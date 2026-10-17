//! The local IPC server.
//!
//! The connection handler is generic over any byte stream, so the protocol is
//! tested with no filesystem at all and the same code serves a Unix domain
//! socket (`unix::IpcListener`) and a Windows named pipe (`windows::IpcListener`)
//! alike (PROJECT.md §13).
//!
//! **There is no TCP anywhere in this module, and there must never be.** On
//! Windows any local process can connect to a listening localhost port, so a
//! loopback socket is not an access control (PROJECT.md §5, §15.6).

use crate::{
    bridge::Bridge,
    cancel::{cancel_pair, CancelHandle},
    devices::DeviceStore,
    error::DaemonError,
    transport::{FragmentTransport, LiveRetarget},
};
use ipc::{ClientMessage, DaemonMessage, DeviceInfo, Envelope, ErrorCode, IpcError};
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
    // Local log of record for "why did a transaction fail" — PROJECT.md
    // §15.5: detail belongs here, not only in the (already coarse-coded)
    // reply handed to whatever process opened the socket. `message` is
    // already guaranteed never to carry payload contents, PINs, or key
    // material at every call site below, so logging it is no less safe than
    // sending it.
    eprintln!("cryptick-daemon: [{id}] {code:?}: {message}");
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
///
/// `retarget` is `None` for a transport with no [`LiveRetarget`]
/// implementation (the `fake-transport` build, or any future transport that
/// hasn't implemented it yet) — `devices.select` still updates `devices`
/// immediately in that case, but has no live effect until the next
/// reconnect or restart, exactly as before hot-retargeting existed.
pub async fn serve_connection<S, T>(
    stream: S,
    bridge: Arc<Bridge<T>>,
    devices: Arc<Mutex<DeviceStore>>,
    retarget: Option<Arc<dyn LiveRetarget>>,
) where
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
                    handle_frame(&frame, &out, &bridge, &in_flight, &devices, &retarget);
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
    if let Some((_, handle)) = in_flight.lock().unwrap_or_else(|e| e.into_inner()).take() {
        handle.cancel();
    }
    drop(out);
    let _ = writer_task.await;
}

fn handle_frame<T>(
    frame: &[u8],
    out: &Outbox,
    bridge: &Arc<Bridge<T>>,
    in_flight: &InFlight,
    devices: &Arc<Mutex<DeviceStore>>,
    retarget: &Option<Arc<dyn LiveRetarget>>,
) where
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

        ClientMessage::ListDevices => {
            // Bookkeeping, not a CTAP transaction — answered straight from
            // the store, never queued behind `in_flight`. Piggybacks a real
            // `last_seen` bump onto this read: if the link is connected
            // right now and the store already has an active entry, that is
            // real evidence the active device is still reachable, not
            // merely assumed.
            let mut store = devices.lock().unwrap_or_else(|e| e.into_inner());
            if bridge.link().connected {
                if let Some(active_id) = store.active_id().map(str::to_string) {
                    store.record_seen(&active_id, None, "ble");
                }
            }
            let list = store
                .list()
                .into_iter()
                .map(|d| DeviceInfo {
                    id: d.id,
                    name: d.name,
                    transport: d.transport,
                    last_seen: d.last_seen,
                    active: d.active,
                })
                .collect();
            send(
                out,
                &Envelope::new(id, DaemonMessage::DeviceList { devices: list }),
            );
        }

        ClientMessage::SelectDevice { id: device_id } => {
            // May need a bounded BLE scan (when a live-retarget capability
            // exists), so this runs off the read loop exactly like
            // `CtapRequest` does, rather than blocking this connection from
            // handling anything else meanwhile.
            tokio::spawn(run_retarget(
                Arc::clone(devices),
                retarget.clone(),
                Arc::clone(bridge),
                out.clone(),
                id,
                device_id,
            ));
        }

        ClientMessage::CtapCancel => {
            let taken = in_flight.lock().unwrap_or_else(|e| e.into_inner()).take();
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
                let mut slot = in_flight.lock().unwrap_or_else(|e| e.into_inner());
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
    let mut slot = in_flight.lock().unwrap_or_else(|e| e.into_inner());
    if slot.as_ref().is_some_and(|(slot_id, _)| slot_id == &id) {
        *slot = None;
    }
}

/// Handles one `devices.select` request: validates the id, hot-retargets
/// the live transport when one is available, and only then commits the
/// bookkeeping change.
///
/// The ordering matters. If a live-retarget capability exists and the
/// attempt fails, `devices` is left exactly as it was — PROJECT.md §15.8
/// ("fail closed") read against this bookkeeping means `active_id` and the
/// live connection must never be allowed to disagree about which device is
/// actually in use. When there is no live-retarget capability at all (the
/// `fake-transport` build, or a future transport that hasn't implemented
/// it), there is nothing to verify reachability against, so the bookkeeping
/// commits immediately and takes effect on the next reconnect or restart —
/// the pre-existing behaviour, unchanged.
async fn run_retarget<T>(
    devices: Arc<Mutex<DeviceStore>>,
    retarget: Option<Arc<dyn LiveRetarget>>,
    bridge: Arc<Bridge<T>>,
    out: Outbox,
    id: String,
    device_id: String,
) where
    T: FragmentTransport + Clone + Send + Sync + 'static,
{
    {
        let store = devices.lock().unwrap_or_else(|e| e.into_inner());
        if !store.is_known(&device_id) {
            send_error(
                &out,
                &id,
                ErrorCode::BadRequest,
                &format!("no known device with id {device_id:?}"),
            );
            return;
        }
    }

    let Some(retarget) = retarget else {
        // No live-retarget capability on this transport — bookkeeping only,
        // takes effect on the next reconnect/restart.
        let mut store = devices.lock().unwrap_or_else(|e| e.into_inner());
        match store.set_active(&device_id) {
            Ok(()) => send(&out, &Envelope::new(id, DaemonMessage::Ack)),
            Err(err) => send_error(&out, &id, ErrorCode::BadRequest, &err.to_string()),
        }
        return;
    };

    // `Bridge` rejects rather than queues a second transaction (its own doc
    // comment); retargeting under an in-flight CTAP transaction is refused
    // the same way rather than racing the swap against it. This is a
    // best-effort check, not a lock held for the whole retarget attempt —
    // real hardware with a transaction landing in that window is one of the
    // things NOTES.md flags as unverified here.
    if bridge.is_busy() {
        send_error(
            &out,
            &id,
            ErrorCode::Busy,
            "a transaction is in flight; retry once it finishes",
        );
        return;
    }

    match retarget.retarget(&device_id).await {
        Ok(()) => {
            let mut store = devices.lock().unwrap_or_else(|e| e.into_inner());
            // The id was already confirmed known above, and nothing else
            // mutates `devices` between then and now on this task — but
            // `set_active` is cheap and its own fail-closed check is the
            // authoritative one, so re-running it costs nothing.
            match store.set_active(&device_id) {
                Ok(()) => send(&out, &Envelope::new(id, DaemonMessage::Ack)),
                Err(err) => send_error(&out, &id, ErrorCode::BadRequest, &err.to_string()),
            }
        }
        Err(err) => {
            // The live connection was left untouched by `retarget` on
            // failure (see `LiveRetarget`'s contract) — do not update
            // `active_id` either, so bookkeeping and the live connection
            // never disagree about which device is actually in use.
            send_error(&out, &id, ErrorCode::NotConnected, &err.to_string());
        }
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

#[cfg(windows)]
pub mod windows {
    //! Binding the IPC endpoint to a Windows named pipe (PROJECT.md §13).
    //!
    //! `NamedPipeServer` already implements `AsyncRead + AsyncWrite`, so
    //! [`serve_connection`](super::serve_connection) runs unmodified once a
    //! client has connected — the whole point of keeping that function generic
    //! over the stream type.
    //!
    //! **Known gap, not yet hardware-verified (PROJECT.md §17 applies in
    //! spirit even though this isn't `[HW]`):** §15.7 asks for a restrictive
    //! DACL and peer-credential validation equivalent to Unix's
    //! `SO_PEERCRED`/`peer_cred()` check (there, "validate the connecting
    //! UID equals the socket owner"; here, the Windows analogue is
    //! `GetNamedPipeClientProcessId` plus a token/SID comparison). Neither is
    //! implemented yet — this listener currently relies only on
    //! [`reject_remote_clients`](ServerOptions::reject_remote_clients), which
    //! blocks the pipe from being reached over SMB from another host but does
    //! **not** restrict which *local* user can open a client handle. Do not
    //! assume parity with the Unix listener's owner-only guarantee until this
    //! is closed and verified against a real Windows session.
    use std::{
        io,
        path::{Path, PathBuf},
    };
    use tokio::net::windows::named_pipe::{NamedPipeServer, PipeMode, ServerOptions};

    /// A listener bound to a Windows named pipe.
    #[derive(Debug)]
    pub struct IpcListener {
        pipe_name: String,
        display_path: PathBuf,
        // The next waiting instance, created ahead of time so a second client
        // is never refused while the first is being handed off to a task.
        next: Option<NamedPipeServer>,
    }

    fn new_instance(pipe_name: &str, first: bool) -> io::Result<NamedPipeServer> {
        ServerOptions::new()
            .pipe_mode(PipeMode::Byte)
            .first_pipe_instance(first)
            // Named pipes are reachable over SMB from a remote host unless
            // this is set; PROJECT.md §5/§15.6 forbid any non-local reach.
            .reject_remote_clients(true)
            .create(pipe_name)
    }

    impl IpcListener {
        /// Creates the first instance of the named pipe at `path` (typically
        /// `ipc::WINDOWS_NAMED_PIPE`, e.g. `\\.\pipe\cryptick-daemon`).
        ///
        /// `first_pipe_instance(true)` makes this fail if another process
        /// already owns the name, which is the Windows equivalent of the
        /// Unix listener refusing to bind over another live daemon. Unlike a
        /// Unix socket file, a named pipe leaves nothing behind for a crashed
        /// daemon to clean up: the kernel destroys the object once every
        /// handle to it is closed, so there is no stale-path removal step.
        pub fn bind(path: impl AsRef<Path>) -> io::Result<Self> {
            let display_path = path.as_ref().to_path_buf();
            let pipe_name = display_path.to_string_lossy().into_owned();
            let server = new_instance(&pipe_name, true)?;
            Ok(Self {
                pipe_name,
                display_path,
                next: Some(server),
            })
        }

        /// The pipe path this listener is bound to.
        pub fn path(&self) -> &Path {
            &self.display_path
        }

        /// Waits for one client to connect and returns the connected instance.
        ///
        /// Returns `Ok(None)` for a transient accept failure so the caller can
        /// keep serving, mirroring `unix::IpcListener::accept`'s shape even
        /// though named pipes have no peer-credential check to fail here yet.
        pub async fn accept(&mut self) -> io::Result<Option<NamedPipeServer>> {
            let server = match self.next.take() {
                Some(server) => server,
                None => new_instance(&self.pipe_name, false)?,
            };

            if let Err(err) = server.connect().await {
                // Queue a fresh instance before surfacing the error so one
                // bad connection attempt cannot wedge every later one.
                self.next = new_instance(&self.pipe_name, false).ok();
                return Err(err);
            }

            self.next = Some(new_instance(&self.pipe_name, false)?);
            Ok(Some(server))
        }
    }

    pub use ipc::default_socket_path;
}
