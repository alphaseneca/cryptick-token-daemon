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
                // Prefer the live connection's own hardware-verified
                // identity (`LiveRetarget::verified_identity` — `None` for
                // older firmware, the `fake-transport` build, or any
                // transport that hasn't implemented it) over the
                // pre-existing best-effort key. `record_seen` upserts under
                // whichever id this turns out to be; `set_active` then
                // carries "active" over to it even when that means a brand
                // new row superseding the old best-effort one — see
                // `devices.rs::record_seen`'s doc comment for why these stay
                // two distinct rows rather than being merged in place.
                match retarget.as_ref().and_then(|r| r.verified_identity()) {
                    Some(serial) => {
                        store.record_seen(&serial, None, "ble", true);
                        // `record_seen` just made `serial` known, so this
                        // cannot fail with `UnknownDeviceError` — but it is
                        // still bookkeeping, not a CTAP transaction, so a
                        // defensive `let _` costs nothing if that ever stops
                        // being true.
                        let _ = store.set_active(&serial);
                    }
                    None => {
                        if let Some(active_id) = store.active_id().map(str::to_string) {
                            store.record_seen(&active_id, None, "ble", false);
                        }
                    }
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
                    verified: d.verified,
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
#[allow(unsafe_code)]
pub mod windows {
    //! Binding the IPC endpoint to a Windows named pipe (PROJECT.md §13).
    //!
    //! `NamedPipeServer` already implements `AsyncRead + AsyncWrite`, so
    //! [`serve_connection`](super::serve_connection) runs unmodified once a
    //! client has connected — the whole point of keeping that function generic
    //! over the stream type.
    //!
    //! # §15.7 on this platform
    //!
    //! §15.7 asks for an owner-only endpoint *and* a peer check where the
    //! platform allows one. Both are implemented here, in the same
    //! defence-in-depth shape as [`unix`](super::unix) — bind permissions
    //! first, peer identity second, neither standing in for the other:
    //!
    //! 1. **A restrictive DACL, applied at pipe creation.** Every instance is
    //!    created through tokio's
    //!    [`create_with_security_attributes_raw`](ServerOptions::create_with_security_attributes_raw)
    //!    with a `SECURITY_ATTRIBUTES` carrying the security descriptor built
    //!    by [`owner_only_sddl`] — `D:P(A;;GA;;;<our SID>)`, one
    //!    access-allowed ACE granting `GENERIC_ALL` to the SID of the user
    //!    this process runs as, on a protected (non-inheriting) DACL, and
    //!    nothing else. This replaces the default, which is the whole bug:
    //!    Microsoft documents the default named-pipe descriptor as granting
    //!    "full control to the LocalSystem account, administrators, and the
    //!    creator owner. They also grant **read access to members of the
    //!    Everyone group and the anonymous account**" (CreateNamedPipeW,
    //!    `lpSecurityAttributes`). Every local user could read this daemon's
    //!    IPC traffic; now none but its owner can open the pipe at all.
    //!
    //! 2. **A peer-identity check after `connect()`**, the analogue of the
    //!    Unix listener's `peer_cred()`/UID comparison:
    //!    `GetNamedPipeClientProcessId` → `OpenProcess` →
    //!    `OpenProcessToken` → `GetTokenInformation(TokenUser)` → compare the
    //!    client's user SID against our own. Mismatch rejects, and so does
    //!    *any* failure to establish either SID (§15.8 — the connection is
    //!    refused rather than served on an unproven identity).
    //!
    //! `reject_remote_clients(true)` stays, and is a third, orthogonal axis:
    //! it blocks SMB reach from another host, which the DACL does not
    //! (Microsoft's `PIPE_ACCEPT_REMOTE_CLIENTS` is documented as accepting
    //! remote connections and *then* checking them "against the security
    //! descriptor for the pipe" — so a remote principal holding our SID would
    //! otherwise pass). PROJECT.md §5/§15.6.
    //!
    //! ## Why SDDL rather than a hand-built ACL
    //!
    //! The descriptor is assembled as an SDDL string and handed to
    //! `ConvertStringSecurityDescriptorToSecurityDescriptorW` rather than
    //! built with `InitializeAcl`/`AddAccessAllowedAce`. Both are supported
    //! Win32; the string form keeps the unsafe surface to one call and no
    //! hand-laid ACL memory, and the only variable in it — the SID — comes
    //! from `ConvertSidToStringSidW` rather than from us assembling SID bytes
    //! by hand. Field meanings are from Microsoft's "Security Descriptor
    //! String Format" and "ACE Strings": `D:` sets `SE_DACL_PRESENT`, `P` is
    //! `SDDL_PROTECTED` (`SE_DACL_PROTECTED`, so no inherited ACE can widen
    //! it), `A` is `SDDL_ACCESS_ALLOWED` and `GA` is `SDDL_GENERIC_ALL`. A
    //! DACL that is *present* but lists nobody else denies everybody else; it
    //! is the **absent/NULL** DACL that grants all access, and SDDL cannot
    //! express one, which is a useful property here.
    //!
    //! `GENERIC_ALL` and not something narrower, deliberately: creating the
    //! second and later instances of an existing pipe needs
    //! `FILE_CREATE_PIPE_INSTANCE` on the pipe object ("the user must have
    //! FILE_CREATE_PIPE_INSTANCE access to the named pipe object" —
    //! CreateNamedPipeW Remarks), which a read/write-only grant would not
    //! carry, and this listener creates a fresh instance per connection.
    //!
    //! Only the daemon's own user is granted. LocalSystem and Administrators
    //! are deliberately *not* in the ACE: nothing in this project needs them,
    //! and their omission is not a security claim either way, since an
    //! administrator can take ownership of the object and rewrite the DACL
    //! regardless. The boundary this buys is against *peer* local users, which
    //! is exactly the one the default descriptor gave away.
    //!
    //! # What is verified, and what is not
    //!
    //! Written 2026-10-18, and **compile-time verified only**. This module was
    //! developed on macOS and checked by cross-compiling to
    //! `x86_64-pc-windows-msvc`; no line of it has ever run on Windows, and
    //! `tests/windows_pipe.rs` has never been executed. The Win32 contracts
    //! above are quoted from Microsoft's current documentation (read
    //! 2026-10-18) and every signature was checked against the exact crate
    //! versions in this workspace's `Cargo.lock` — `windows-sys` 0.61.2 and
    //! tokio 1.53.1, whose `create_with_security_attributes_raw` is
    //! `unsafe fn(&self, impl AsRef<OsStr>, *mut c_void)`.
    //!
    //! Still wanted from a human on a real Windows session, before §15.7 is
    //! called closed here:
    //!
    //! - **The DACL as the kernel actually stored it.** `tests/windows_pipe.rs`
    //!   reads it back with `GetSecurityInfo` and asserts Everyone is gone;
    //!   that assertion has never run.
    //! - **A genuine cross-user rejection.** Both halves can only be proved by
    //!   a second local account connecting. Note the expected failure mode is
    //!   not a SID mismatch but an `OpenProcess` denial: Microsoft documents
    //!   that inspecting a process started by a different account needs
    //!   `SE_DEBUG_NAME`, which this daemon neither has nor wants — so the
    //!   peer check rejects such a client by *failing to identify it*, which
    //!   is the §15.8 path and should be confirmed to behave that way rather
    //!   than erroring the accept loop.
    //! - **Whether the descriptor on later instances behaves as assumed.** The
    //!   documentation defines the DACL for the case where "a new named pipe
    //!   is being created" and is silent on instances two and up; this code
    //!   passes the same descriptor on every instance, which is correct under
    //!   either reading, but only a readback on a live second instance shows
    //!   which reading is true.
    //! - **Service-context operation.** If this daemon is ever run under a
    //!   service account rather than as the logged-in user, the SID it grants
    //!   is the service's, and every client is then a different user. That is
    //!   a packaging decision (§16 step 9) this module cannot check.
    //!
    //! ## The PID lookup has a race the Unix side does not
    //!
    //! `peer_cred()` reads credentials the kernel captured at connect time.
    //! `GetNamedPipeClientProcessId` returns a PID, and a PID is a reusable
    //! name: between the client's connect and our `OpenProcess`, that client
    //! could exit and its PID be reissued to a process of ours, which would
    //! then pass the comparison. It is a narrow window and the attacker does
    //! not choose PIDs, but it is a real difference and is recorded here
    //! rather than papered over.
    //!
    //! `ImpersonateNamedPipeClient` has no such race — the kernel hands over
    //! the client's own token — and was rejected anyway: it swaps the *calling
    //! thread's* token, and this is a shared tokio worker thread. A panic, or
    //! any yield, between impersonate and `RevertToSelf` would leave unrelated
    //! tasks running under a borrowed identity. Trading a PID-reuse race for a
    //! thread-identity hazard in an authenticator path is not a trade worth
    //! making, and the DACL — which has no such race — is the primary control
    //! regardless. §15.7 names `GetNamedPipeClientProcessId` for this reason.
    use std::{
        ffi::{c_void, OsStr},
        io,
        os::windows::{ffi::OsStrExt, io::AsRawHandle},
        path::{Path, PathBuf},
    };
    use tokio::net::windows::named_pipe::{NamedPipeServer, PipeMode, ServerOptions};
    use windows_sys::{
        core::PWSTR,
        Win32::{
            Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL},
            Security::{
                Authorization::{
                    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
                    SDDL_REVISION_1,
                },
                GetTokenInformation, TokenUser, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
                TOKEN_QUERY, TOKEN_USER,
            },
            System::{
                Pipes::GetNamedPipeClientProcessId,
                Threading::{
                    GetCurrentProcess, OpenProcess, OpenProcessToken,
                    PROCESS_QUERY_LIMITED_INFORMATION,
                },
            },
        },
    };

    /// A `HANDLE` closed exactly once, on drop.
    struct ScopedHandle(HANDLE);

    impl Drop for ScopedHandle {
        fn drop(&mut self) {
            // SAFETY: the only constructors of this type are the two call
            // sites below, each wrapping a handle a successful `OpenProcess`
            // or `OpenProcessToken` just produced. The type is not `Clone`,
            // so the handle is closed here and nowhere else.
            unsafe { CloseHandle(self.0) };
        }
    }

    /// A security descriptor allocated by Win32 and released with `LocalFree`.
    struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

    impl Drop for LocalSecurityDescriptor {
        fn drop(&mut self) {
            // SAFETY: `self.0` was allocated by
            // `ConvertStringSecurityDescriptorToSecurityDescriptorW`, which
            // documents `LocalFree` as its matching deallocator. Not `Clone`,
            // so this runs once.
            unsafe { LocalFree(self.0 as HLOCAL) };
        }
    }

    /// A NUL-terminated UTF-16 copy of `s`, for the `W` entry points.
    fn wide(s: &str) -> Vec<u16> {
        OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    /// Copies a NUL-terminated UTF-16 string out of Win32-owned memory.
    ///
    /// # Safety
    ///
    /// `raw` must be non-null and point at a NUL-terminated UTF-16 string that
    /// stays valid for the duration of the call.
    unsafe fn pwstr_to_string(raw: PWSTR) -> String {
        let mut len = 0usize;
        while *raw.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(raw, len))
    }

    /// The textual (`S-1-5-…`) form of a SID.
    ///
    /// Comparing these strings is equivalent to `EqualSid`, because
    /// `ConvertSidToStringSidW` is a deterministic, injective rendering of the
    /// SID's bytes. Strings are used instead so that nothing in this module
    /// has to keep a raw `PSID` alive across a call boundary.
    ///
    /// # Safety
    ///
    /// `sid` must point at a valid SID that stays valid for the call.
    unsafe fn sid_to_string(sid: PSID) -> io::Result<String> {
        let mut raw: PWSTR = std::ptr::null_mut();
        if ConvertSidToStringSidW(sid, &mut raw) == 0 {
            return Err(io::Error::last_os_error());
        }
        let owned = pwstr_to_string(raw);
        LocalFree(raw as HLOCAL);
        Ok(owned)
    }

    /// The user SID of the token `token`, as a string.
    fn token_user_sid(token: HANDLE) -> io::Result<String> {
        let mut needed: u32 = 0;
        // SAFETY: the documented size probe — a null buffer of length 0 makes
        // `GetTokenInformation` fail with ERROR_INSUFFICIENT_BUFFER and write
        // the required byte count to `needed`. The failure is expected, so
        // the return value is ignored in favour of checking `needed`.
        unsafe { GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed) };
        if needed == 0 {
            return Err(io::Error::last_os_error());
        }

        // A `TOKEN_USER` is pointer-aligned and this buffer is cast to one, so
        // it is allocated as `u64`s rather than bytes — `Vec<u8>` guarantees
        // only byte alignment.
        let words = (needed as usize).div_ceil(std::mem::size_of::<u64>());
        let mut buf = vec![0u64; words];
        let capacity = (words * std::mem::size_of::<u64>()) as u32;

        // SAFETY: `buf` is `capacity` writable bytes, `capacity >= needed`,
        // and the pointer is 8-byte aligned by construction.
        let ok = unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                buf.as_mut_ptr().cast::<c_void>(),
                capacity,
                &mut needed,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }

        // SAFETY: on success the buffer holds a `TOKEN_USER` whose `User.Sid`
        // points into that same buffer, which outlives this block.
        unsafe {
            let user = &*buf.as_ptr().cast::<TOKEN_USER>();
            sid_to_string(user.User.Sid)
        }
    }

    /// The SID of the user this process is running as.
    fn current_user_sid() -> io::Result<String> {
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: `GetCurrentProcess` returns a pseudo-handle that needs no
        // close and is always valid; `token` is a live out-param.
        let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let token = ScopedHandle(token);
        token_user_sid(token.0)
    }

    /// The SID of the user owning the process at the far end of `pipe`.
    ///
    /// Every step can fail, and every failure is the caller's cue to refuse
    /// the connection (§15.8) — in particular `OpenProcess` is expected to be
    /// denied for a client owned by another account, which is the case this
    /// check exists to catch.
    fn client_user_sid(pipe: HANDLE) -> io::Result<String> {
        let mut pid: u32 = 0;
        // SAFETY: `pipe` is a live server-end named-pipe handle owned by the
        // caller, which is what this entry point requires.
        if unsafe { GetNamedPipeClientProcessId(pipe, &mut pid) } == 0 {
            return Err(io::Error::last_os_error());
        }

        // PROCESS_QUERY_LIMITED_INFORMATION and nothing more: it is exactly
        // what `OpenProcessToken` documents as its requirement, and unlike
        // PROCESS_QUERY_INFORMATION it does not need the target to be at or
        // below our integrity level.
        // SAFETY: a plain scalar call; the returned handle is checked below.
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if process.is_null() {
            return Err(io::Error::last_os_error());
        }
        let process = ScopedHandle(process);

        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: `process.0` is the live handle just opened; `token` is a
        // live out-param.
        let ok = unsafe { OpenProcessToken(process.0, TOKEN_QUERY, &mut token) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let token = ScopedHandle(token);
        token_user_sid(token.0)
    }

    /// The SDDL for "this SID, and nobody else".
    ///
    /// Split out from the descriptor it builds so the string itself can be
    /// asserted on without a live pipe — see this module's tests. Field
    /// meanings are cited in the module documentation.
    fn owner_only_sddl(owner_sid: &str) -> String {
        format!("D:P(A;;GA;;;{owner_sid})")
    }

    /// Builds the owner-only security descriptor for `owner_sid`.
    fn owner_only_descriptor(owner_sid: &str) -> io::Result<LocalSecurityDescriptor> {
        let sddl = wide(&owner_only_sddl(owner_sid));
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: `sddl` is NUL-terminated UTF-16 and outlives the call;
        // `descriptor` is a live out-param; a null size out-param is
        // documented as "don't report the size".
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(LocalSecurityDescriptor(descriptor))
    }

    /// A listener bound to a Windows named pipe.
    #[derive(Debug)]
    pub struct IpcListener {
        pipe_name: String,
        display_path: PathBuf,
        /// The SID every client is checked against, read once at bind time.
        owner_sid: String,
        // The next waiting instance, created ahead of time so a second client
        // is never refused while the first is being handed off to a task.
        next: Option<NamedPipeServer>,
    }

    fn new_instance(pipe_name: &str, first: bool, owner_sid: &str) -> io::Result<NamedPipeServer> {
        let descriptor = owner_only_descriptor(owner_sid)?;
        let mut attrs = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            // The daemon spawns no children, and an inheritable pipe handle
            // would hand one a connection it never opened.
            bInheritHandle: 0,
        };

        // SAFETY: `attrs` is a fully initialised `SECURITY_ATTRIBUTES` whose
        // `lpSecurityDescriptor` points at `descriptor`, still owned and alive
        // here. `CreateNamedPipeW` copies the descriptor into the kernel
        // object, so the explicit `drop` below — after the call returns — is
        // not a use-after-free for the created pipe.
        let server = unsafe {
            ServerOptions::new()
                .pipe_mode(PipeMode::Byte)
                .first_pipe_instance(first)
                // Named pipes are reachable over SMB from a remote host unless
                // this is set; PROJECT.md §5/§15.6 forbid any non-local reach.
                // Orthogonal to the DACL — see the module documentation.
                .reject_remote_clients(true)
                .create_with_security_attributes_raw(
                    pipe_name,
                    std::ptr::addr_of_mut!(attrs).cast::<c_void>(),
                )
        };
        drop(descriptor);
        server
    }

    impl IpcListener {
        /// Creates the first instance of the named pipe at `path` (typically
        /// `ipc::WINDOWS_NAMED_PIPE`, e.g. `\\.\pipe\cryptick-daemon`).
        ///
        /// The owner-only DACL is applied by the creating call itself, so
        /// there is no window in which the pipe exists under the permissive
        /// default descriptor — the Windows counterpart of the Unix listener
        /// creating its directory `0700` *before* binding.
        ///
        /// `first_pipe_instance(true)` makes this fail if another process
        /// already owns the name, which is the Windows equivalent of the
        /// Unix listener refusing to bind over another live daemon. Unlike a
        /// Unix socket file, a named pipe leaves nothing behind for a crashed
        /// daemon to clean up: the kernel destroys the object once every
        /// handle to it is closed, so there is no stale-path removal step.
        ///
        /// Fails if the daemon's own user SID cannot be read, rather than
        /// falling back to a weaker descriptor (§15.8).
        pub fn bind(path: impl AsRef<Path>) -> io::Result<Self> {
            let display_path = path.as_ref().to_path_buf();
            let pipe_name = display_path.to_string_lossy().into_owned();
            let owner_sid = current_user_sid()?;
            let server = new_instance(&pipe_name, true, &owner_sid)?;
            Ok(Self {
                pipe_name,
                display_path,
                owner_sid,
                next: Some(server),
            })
        }

        /// The pipe path this listener is bound to.
        pub fn path(&self) -> &Path {
            &self.display_path
        }

        /// The SID this listener grants access to and checks clients against.
        pub fn owner_sid(&self) -> &str {
            &self.owner_sid
        }

        /// Waits for one client to connect and returns the connected instance,
        /// rejecting any peer that is not owned by the same user as this
        /// process.
        ///
        /// Returns `Ok(None)` when a connection was refused or an accept
        /// failed transiently, so the caller can keep serving — the same shape
        /// as `unix::IpcListener::accept`. A refusal covers both a SID
        /// mismatch and any failure to establish either SID: an unidentifiable
        /// peer is not served (§15.8).
        ///
        /// The DACL should already make a foreign client unable to open the
        /// pipe at all; this check means a descriptor that was wrong, or an
        /// instance created without one, is still not enough on its own —
        /// exactly the reasoning behind the Unix listener doing `0600` *and*
        /// `peer_cred()`.
        pub async fn accept(&mut self) -> io::Result<Option<NamedPipeServer>> {
            let server = match self.next.take() {
                Some(server) => server,
                None => new_instance(&self.pipe_name, false, &self.owner_sid)?,
            };

            if let Err(err) = server.connect().await {
                // Queue a fresh instance before surfacing the error so one
                // bad connection attempt cannot wedge every later one.
                self.next = new_instance(&self.pipe_name, false, &self.owner_sid).ok();
                return Err(err);
            }

            let verdict = client_user_sid(server.as_raw_handle() as HANDLE);
            self.next = Some(new_instance(&self.pipe_name, false, &self.owner_sid)?);

            match verdict {
                Ok(sid) if sid == self.owner_sid => Ok(Some(server)),
                Ok(_) => {
                    // A SID, but not ours. Nothing identifying is logged;
                    // that the refusal happened is the useful part.
                    eprintln!("cryptick-daemon: refused a pipe client owned by another user");
                    let _ = server.disconnect();
                    Ok(None)
                }
                Err(err) => {
                    // Could not establish who the peer is — refuse rather
                    // than serve an unproven identity (§15.8). Expected for a
                    // client owned by another account, whose process this
                    // daemon has no right to inspect.
                    eprintln!(
                        "cryptick-daemon: refused a pipe client of unverifiable identity: {err}"
                    );
                    let _ = server.disconnect();
                    Ok(None)
                }
            }
        }
    }

    pub use ipc::default_socket_path;

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Never executed in the sandbox this was written in (macOS); see the
        /// module documentation.
        #[test]
        fn the_dacl_names_our_own_sid_and_nobody_else() {
            let sid = current_user_sid().expect("our own SID must be readable");
            assert!(sid.starts_with("S-1-"), "not a SID string: {sid}");

            let sddl = owner_only_sddl(&sid);
            assert_eq!(sddl, format!("D:P(A;;GA;;;{sid})"));

            // One ACE, and it is ours.
            assert_eq!(sddl.matches('(').count(), 1, "{sddl}");
            assert!(sddl.contains(&sid), "{sddl}");

            // None of the SDDL aliases that would widen this past our user.
            // `WD` is Everyone, `AU` Authenticated Users, `BU` Users, `BA`
            // Administrators, `AN` Anonymous, `S-1-1-0` Everyone spelled out.
            for wide_open in [";WD)", ";AU)", ";BU)", ";BA)", ";AN)", "S-1-1-0"] {
                assert!(
                    !sddl.contains(wide_open),
                    "DACL grants {wide_open}, which defeats the point: {sddl}"
                );
            }
        }

        /// Proves the SDDL is well-formed against the OS parser rather than
        /// against our own expectations of the syntax (PROJECT.md §20:
        /// verify against the specification, not against the other side).
        #[test]
        fn the_generated_descriptor_is_accepted_by_win32() {
            let sid = current_user_sid().expect("our own SID must be readable");
            let descriptor = owner_only_descriptor(&sid).expect("Win32 must parse our SDDL");
            assert!(!descriptor.0.is_null());
        }

        /// The comparison the peer check rests on is a string equality, so a
        /// SID must render identically every time it is read.
        #[test]
        fn our_sid_renders_stably() {
            let first = current_user_sid().expect("SID");
            let second = current_user_sid().expect("SID");
            assert_eq!(first, second);
        }
    }
}
