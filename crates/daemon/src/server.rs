//! The local IPC server.
//!
//! The connection handler is generic over any byte stream, so the protocol is
//! tested with no filesystem at all and the same code serves a Unix domain
//! socket today and a Windows named pipe later (PROJECT.md §13).
//!
//! **There is no TCP anywhere in this module, and there must never be.** On
//! Windows any local process can connect to a listening localhost port, so a
//! loopback socket is not an access control (PROJECT.md §5, §15.6).

use crate::{
    bridge::Bridge,
    cancel::{cancel_pair, CancelHandle},
    error::DaemonError,
    transport::FragmentTransport,
};
use ipc::{ClientMessage, DaemonMessage, Envelope, ErrorCode, IpcError};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::mpsc,
};

/// The longest transaction a client may ask for.
///
/// A client that asks for an hour would pin the device against every other
/// adapter for an hour. Real user-presence waits are well under a minute.
pub const MAX_TIMEOUT: Duration = Duration::from_secs(300);

/// Outbound frames, serialised by a single writer task.
type Outbox = mpsc::UnboundedSender<Vec<u8>>;

fn send<T: serde::Serialize>(out: &Outbox, message: &Envelope<T>) {
    match ipc::encode(message) {
        Ok(frame) => {
            let _ = out.send(frame);
        }
        // Encoding our own message failing means a bug, not a client problem.
        // Dropping the frame is better than tearing down a healthy connection.
        Err(_) => debug_assert!(false, "failed to encode an outbound IPC message"),
    }
}

fn send_error(out: &Outbox, id: &str, code: ErrorCode, message: &str) {
    send(
        out,
        &Envelope::new(
            id,
            DaemonMessage::Error {
                code,
                // Never carries payload contents, PINs, or key material
                // (PROJECT.md §15.5).
                message: message.to_owned(),
            },
        ),
    );
}

/// The transaction this connection currently has in flight, if any.
type InFlight = Arc<Mutex<Option<(String, CancelHandle)>>>;

/// Serves one client connection until it closes or misbehaves.
pub async fn serve_connection<S, T>(stream: S, bridge: Arc<Bridge<T>>)
where
    S: AsyncRead + AsyncWrite + Send + 'static,
    T: FragmentTransport + Clone + Send + Sync + 'static,
{
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (out, mut out_rx) = mpsc::unbounded_channel::<Vec<u8>>();

    let writer_task = tokio::spawn(async move {
        while let Some(frame) = out_rx.recv().await {
            if writer.write_all(&frame).await.is_err() {
                break;
            }
        }
    });

    let in_flight: InFlight = Arc::new(Mutex::new(None));
    let mut decoder = ipc::FrameDecoder::new();
    let mut buf = [0u8; 8192];

    'read: loop {
        let n = match reader.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        decoder.push(&buf[..n]);

        loop {
            match decoder.next_frame() {
                Ok(Some(frame)) => {
                    handle_frame(&frame, &out, &bridge, &in_flight);
                }
                Ok(None) => break,
                Err(err) => {
                    // A bad length prefix is unrecoverable: it is how we find
                    // the next boundary, so the stream cannot be resynchronised.
                    send_error(&out, "", ErrorCode::BadRequest, &err.to_string());
                    break 'read;
                }
            }
        }
    }

    // The client is gone; nothing can satisfy a pending user-presence prompt.
    if let Some((_, handle)) = in_flight.lock().expect("in-flight lock").take() {
        handle.cancel();
    }
    drop(out);
    let _ = writer_task.await;
}

fn handle_frame<T>(frame: &[u8], out: &Outbox, bridge: &Arc<Bridge<T>>, in_flight: &InFlight)
where
    T: FragmentTransport + Clone + Send + Sync + 'static,
{
    let envelope = match ipc::decode_client(frame) {
        Ok(envelope) => envelope,
        Err(err) => {
            let code = match err {
                IpcError::UnsupportedVersion { .. } => ErrorCode::UnsupportedVersion,
                _ => ErrorCode::BadRequest,
            };
            // The id is unavailable when the frame would not parse, so this
            // reply cannot be correlated. That is unavoidable and is why the
            // version check happens before the body (PROJECT.md §14).
            send_error(out, "", code, &err.to_string());
            return;
        }
    };

    let id = envelope.id;

    match envelope.body {
        ClientMessage::DeviceStatus => {
            let link = bridge.link();
            send(
                out,
                &Envelope::new(
                    id,
                    DaemonMessage::DeviceRange {
                        in_range: link.connected,
                        // Reports usability, not merely that some bond record
                        // exists: a Just Works bond has no MITM protection and
                        // cannot carry CTAP (PROJECT.md §15.2).
                        bonded: link.is_usable(),
                    },
                ),
            );
        }

        ClientMessage::CtapCancel => {
            let taken = in_flight.lock().expect("in-flight lock").take();
            match taken {
                Some((_, handle)) => handle.cancel(),
                None => send_error(
                    out,
                    &id,
                    ErrorCode::BadRequest,
                    "no transaction is in flight",
                ),
            }
        }

        ClientMessage::CtapRequest { cbor, timeout_ms } => {
            let request = match ctap::Request::decode(&cbor) {
                Ok(request) => request,
                Err(err) => {
                    send_error(out, &id, ErrorCode::BadRequest, &err.to_string());
                    return;
                }
            };

            let (handle, token) = cancel_pair();
            {
                let mut slot = in_flight.lock().expect("in-flight lock");
                if slot.is_some() {
                    send_error(
                        out,
                        &id,
                        ErrorCode::Busy,
                        "a transaction is already in flight on this connection",
                    );
                    return;
                }
                *slot = Some((id.clone(), handle));
            }

            let timeout = Duration::from_millis(timeout_ms).min(MAX_TIMEOUT);
            tokio::spawn(run_transaction(
                Arc::clone(bridge),
                Arc::clone(in_flight),
                out.clone(),
                id,
                request,
                timeout,
                token,
            ));
        }
    }
}

async fn run_transaction<T>(
    bridge: Arc<Bridge<T>>,
    in_flight: InFlight,
    out: Outbox,
    id: String,
    request: ctap::Request,
    timeout: Duration,
    mut cancel: crate::cancel::CancelToken,
) where
    T: FragmentTransport + Clone + Send + Sync + 'static,
{
    let (keepalives, mut keepalive_rx) = mpsc::unbounded_channel();

    // Keepalives must reach the client as they happen, not batched at the end:
    // a `up` keepalive is the device asking the user to touch the sensor, and a
    // prompt that arrives after the timeout is no prompt at all.
    let pump = {
        let out = out.clone();
        let id = id.clone();
        tokio::spawn(async move {
            while let Some(reason) = keepalive_rx.recv().await {
                send(
                    &out,
                    &Envelope::new(id.clone(), DaemonMessage::CtapKeepalive { reason }),
                );
            }
        })
    };

    let result = bridge
        .transact(&request, timeout, &keepalives, &mut cancel)
        .await;

    // Ends the pump, and guarantees every keepalive is written before the
    // response that follows it.
    drop(keepalives);
    let _ = pump.await;

    match result {
        Ok(response) => send(
            &out,
            &Envelope::new(
                id.clone(),
                DaemonMessage::CtapResponse {
                    status: response.status.as_u8(),
                    cbor: response.data,
                },
            ),
        ),
        Err(err) => send_error(&out, &id, err.ipc_code(), &err.to_string()),
    }

    // Only clear the slot if it is still ours: a cancel may already have taken
    // it, and a later request may already have claimed it.
    let mut slot = in_flight.lock().expect("in-flight lock");
    if slot.as_ref().is_some_and(|(slot_id, _)| slot_id == &id) {
        *slot = None;
    }
}

/// Maps a daemon error onto the code a client sees.
///
/// Re-exported for adapters that talk to the bridge directly rather than over
/// the socket.
pub fn ipc_code(err: &DaemonError) -> ErrorCode {
    err.ipc_code()
}

#[cfg(unix)]
pub mod unix {
    //! Binding the IPC endpoint to a Unix domain socket.

    use std::{
        fs, io,
        os::unix::fs::{MetadataExt, PermissionsExt},
        path::{Path, PathBuf},
    };
    use tokio::net::{UnixListener, UnixStream};

    use ipc::MAX_SOCKET_PATH;

    /// An owner-only listening socket.
    #[derive(Debug)]
    pub struct IpcListener {
        listener: UnixListener,
        path: PathBuf,
        owner_uid: u32,
    }

    impl IpcListener {
        /// Binds the socket, creating its directory if needed.
        ///
        /// The directory is created `0700` *before* the socket is bound, so the
        /// socket is unreachable by other users even during the window between
        /// `bind` and the `0600` below (PROJECT.md §15.7).
        pub fn bind(path: impl AsRef<Path>) -> io::Result<Self> {
            let path = path.as_ref().to_path_buf();
            if path.as_os_str().len() > MAX_SOCKET_PATH {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "socket path is {} bytes, over the {MAX_SOCKET_PATH}-byte limit: {}",
                        path.as_os_str().len(),
                        path.display()
                    ),
                ));
            }

            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
            }

            // A socket left behind by a crashed daemon would make bind fail.
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                Err(err) => return Err(err),
            }

            let listener = UnixListener::bind(&path)?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
            let owner_uid = fs::metadata(&path)?.uid();

            Ok(Self {
                listener,
                path,
                owner_uid,
            })
        }

        /// The path the socket is bound to.
        pub fn path(&self) -> &Path {
            &self.path
        }

        /// Accepts a connection, rejecting any peer that is not the owner.
        ///
        /// Returns `Ok(None)` when a connection was refused, so the caller can
        /// keep serving. The filesystem permissions should already prevent this;
        /// checking the peer's credentials as well means a misconfigured
        /// directory is not enough on its own (PROJECT.md §15.7).
        pub async fn accept(&self) -> io::Result<Option<UnixStream>> {
            let stream = match self.listener.accept().await {
                Ok((s, _)) => s,
                Err(e)
                    if e.kind() == io::ErrorKind::NotConnected
                        || e.kind() == io::ErrorKind::ConnectionReset =>
                {
                    return Ok(None);
                }
                Err(e) => return Err(e),
            };
            let uid = match stream.peer_cred() {
                Ok(cred) => cred.uid(),
                Err(e)
                    if e.kind() == io::ErrorKind::NotConnected
                        || e.kind() == io::ErrorKind::ConnectionReset =>
                {
                    return Ok(None);
                }
                Err(e) => return Err(e),
            };
            if uid != self.owner_uid {
                return Ok(None);
            }
            Ok(Some(stream))
        }
    }

    impl Drop for IpcListener {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    pub use ipc::default_socket_path;
}
