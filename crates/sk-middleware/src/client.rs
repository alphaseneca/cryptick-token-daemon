//! A blocking IPC client for the daemon.
//!
//! Blocking on purpose. This runs inside `ssh-sk-helper`, which knows nothing
//! about async runtimes, and starting one inside a host process is how you get
//! a hang at exit (PROJECT.md §10). The whole conversation is one request and
//! one reply, so there is nothing an executor would buy.

use ipc::{ClientMessage, DaemonMessage, Envelope, ErrorCode, FrameDecoder, IpcError};
use std::{
    io::{ErrorKind, Write},
    path::Path,
    time::{Duration, Instant},
};
use thiserror::Error;

#[cfg(unix)]
use std::{io::Read, os::unix::net::UnixStream};

#[cfg(windows)]
use windows_pipe::PipeStream;

/// How long a single socket read may block before the overall deadline is
/// rechecked. Keepalives arrive far more often than this while the device is
/// waiting for a fingerprint, so it only bites when the daemon has gone quiet.
const READ_SLICE: Duration = Duration::from_millis(500);

/// A blocking client connection to a Windows named pipe.
///
/// `std::fs::File` has no read-timeout API, unlike `UnixStream`, so a
/// background thread owns the actual `ReadFile` calls and hands chunks back
/// over a channel — `recv_timeout` on that channel is what lets
/// [`DaemonClient::recv`] honour its deadline even while the pipe is silent.
/// Identical to the module of the same name in `crates/webauthn-host/src/daemon.rs`
/// and `crates/token-manager/src/transport/daemon.rs`; this one must stay
/// free-standing because §10 forbids `sk-middleware` from depending on
/// anything not already audited for running inside `ssh-sk-helper`.
#[cfg(windows)]
mod windows_pipe {
    use std::fs::{File, OpenOptions};
    use std::io::{self, Write};
    use std::path::Path;
    use std::sync::mpsc;
    use std::time::Duration;

    pub struct PipeStream {
        writer: File,
        rx: mpsc::Receiver<io::Result<Vec<u8>>>,
    }

    impl PipeStream {
        /// Connects to an existing named pipe server instance (see
        /// `crates/daemon/src/server.rs`'s `windows::IpcListener`).
        pub fn connect(path: &Path) -> io::Result<Self> {
            let file = OpenOptions::new().read(true).write(true).open(path)?;
            let reader = file.try_clone()?;
            let (tx, rx) = mpsc::channel();
            std::thread::spawn(move || {
                use std::io::Read;
                let mut reader = reader;
                let mut buf = [0u8; 8192];
                loop {
                    let result = reader.read(&mut buf).map(|n| buf[..n].to_vec());
                    let is_eof_or_err =
                        matches!(&result, Ok(chunk) if chunk.is_empty()) || result.is_err();
                    if tx.send(result).is_err() || is_eof_or_err {
                        break;
                    }
                }
            });
            Ok(Self { writer: file, rx })
        }

        pub fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
            self.writer.write_all(buf)
        }

        pub fn flush(&mut self) -> io::Result<()> {
            self.writer.flush()
        }

        /// Waits up to `timeout` for the next chunk read from the pipe. An
        /// empty `Vec` means the peer closed the connection, matching what a
        /// `0`-byte `read()` means on the Unix path.
        pub fn read_chunk(&mut self, timeout: Duration) -> io::Result<Vec<u8>> {
            match self.rx.recv_timeout(timeout) {
                Ok(Ok(chunk)) => Ok(chunk),
                Ok(Err(e)) => Err(e),
                Err(mpsc::RecvTimeoutError::Timeout) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "named pipe read timed out",
                )),
                Err(mpsc::RecvTimeoutError::Disconnected) => Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "named pipe reader thread ended unexpectedly",
                )),
            }
        }
    }
}

/// Talking to the daemon failed.
#[derive(Debug, Error)]
pub enum ClientError {
    /// The daemon socket could not be reached. It is probably not running.
    #[error("cannot reach the daemon: {0}")]
    NotRunning(#[source] std::io::Error),

    /// The socket path could not be determined.
    #[error("no daemon socket path is available for this user")]
    NoSocketPath,

    /// The connection failed mid-conversation.
    #[error("IPC failed: {0}")]
    Io(#[source] std::io::Error),

    /// The daemon sent something we could not parse.
    #[error("malformed reply from the daemon: {0}")]
    Protocol(#[from] IpcError),

    /// The daemon refused the request.
    #[error("daemon returned {code:?}")]
    Refused {
        /// The code the daemon reported.
        code: ErrorCode,
    },

    /// The operation ran past its deadline.
    #[error("the operation timed out")]
    Timeout,
}

/// Whether the token is reachable and usable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceStatus {
    /// A device is in range.
    pub in_range: bool,
    /// The link is bonded with MITM protection, so CTAP may proceed. A bond
    /// without it reports `false` (PROJECT.md §15.2).
    pub bonded: bool,
}

/// A blocking connection to the daemon.
#[derive(Debug)]
pub struct DaemonClient {
    #[cfg(unix)]
    stream: UnixStream,
    #[cfg(windows)]
    stream: PipeStream,
    decoder: FrameDecoder,
    next_id: u64,
}

impl DaemonClient {
    /// Connects to the daemon's default socket.
    pub fn connect(timeout: Duration) -> Result<Self, ClientError> {
        let path = ipc::default_socket_path().ok_or(ClientError::NoSocketPath)?;
        Self::connect_to(&path, timeout)
    }

    /// Connects to a specific socket (Unix) or named pipe (Windows) path.
    #[cfg(unix)]
    pub fn connect_to(path: &Path, timeout: Duration) -> Result<Self, ClientError> {
        let stream = UnixStream::connect(path).map_err(ClientError::NotRunning)?;
        stream
            .set_read_timeout(Some(READ_SLICE.min(timeout)))
            .map_err(ClientError::Io)?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(ClientError::Io)?;
        Ok(Self {
            stream,
            decoder: FrameDecoder::new(),
            next_id: 1,
        })
    }

    /// Connects over the daemon's Windows named pipe.
    ///
    /// **Known caveat, not yet hardware-verified:** the background reader
    /// thread inside [`PipeStream`] can still be blocked in `ReadFile` when
    /// this connection (and the FFI call that owns it) finishes, because
    /// Windows gives no portable way to cancel a blocking read without raw
    /// `OVERLAPPED` I/O. §10 asks for no background thread to outlive a
    /// call; this falls short of that in the strict sense, but the thread
    /// exits as soon as the daemon's next write or the pipe's close arrives,
    /// and `ssh-sk-helper` itself is a short-lived, per-operation process
    /// (PROJECT.md §10) that tears the whole thing down moments later either
    /// way. Replacing this with real overlapped I/O would remove the gap;
    /// flagged here rather than guessed at because it needs a Windows
    /// session to verify, which this sandbox does not have.
    #[cfg(windows)]
    pub fn connect_to(path: &Path, _timeout: Duration) -> Result<Self, ClientError> {
        let stream = PipeStream::connect(path).map_err(ClientError::NotRunning)?;
        Ok(Self {
            stream,
            decoder: FrameDecoder::new(),
            next_id: 1,
        })
    }

    #[cfg(not(any(unix, windows)))]
    pub fn connect_to(_path: &Path, _timeout: Duration) -> Result<Self, ClientError> {
        Err(ClientError::NotRunning(std::io::Error::new(
            ErrorKind::Unsupported,
            "local IPC is not supported on this platform",
        )))
    }

    fn take_id(&mut self) -> String {
        let id = self.next_id;
        // Per-connection, not process-global: §10 forbids global state, and a
        // counter shared between concurrent ssh-sk-helper processes would be
        // meaningless anyway.
        self.next_id = self.next_id.wrapping_add(1);
        format!("sk-{id}")
    }

    #[cfg(any(unix, windows))]
    fn send(&mut self, id: &str, body: ClientMessage) -> Result<(), ClientError> {
        let frame = ipc::encode(&Envelope::new(id, body))?;
        self.stream.write_all(&frame).map_err(ClientError::Io)?;
        self.stream.flush().map_err(ClientError::Io)
    }

    #[cfg(not(any(unix, windows)))]
    fn send(&mut self, _id: &str, _body: ClientMessage) -> Result<(), ClientError> {
        Err(ClientError::NotRunning(std::io::Error::new(
            ErrorKind::Unsupported,
            "local IPC is not supported on this platform",
        )))
    }

    /// Reads replies until one matching `id` arrives, or the deadline passes.
    ///
    /// Keepalives are consumed and discarded. They mean the device is waiting
    /// for a fingerprint, which the middleware cannot act on — `ssh-keygen`
    /// has already printed its own "you may need to touch your authenticator"
    /// prompt, and §10 forbids writing anything to stdout or stderr from here.
    /// They deliberately do **not** extend the deadline.
    #[cfg(unix)]
    fn recv(&mut self, id: &str, deadline: Instant) -> Result<DaemonMessage, ClientError> {
        let mut buf = [0u8; 8192];
        loop {
            while let Some(frame) = self.decoder.next_frame()? {
                let envelope = ipc::decode_daemon(&frame)?;
                if envelope.id != id {
                    continue;
                }
                match envelope.body {
                    DaemonMessage::CtapKeepalive { .. } => continue,
                    body => return Ok(body),
                }
            }

            if Instant::now() >= deadline {
                return Err(ClientError::Timeout);
            }

            match self.stream.read(&mut buf) {
                Ok(0) => {
                    return Err(ClientError::Io(std::io::Error::new(
                        ErrorKind::UnexpectedEof,
                        "the daemon closed the connection",
                    )))
                }
                Ok(n) => self.decoder.push(&buf[..n]),
                // A read slice expiring is expected: the loop above rechecks
                // the real deadline.
                Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => return Err(ClientError::Io(e)),
            }
        }
    }

    /// Same contract as the Unix `recv`, but reads come from
    /// `PipeStream::read_chunk`'s background-thread channel instead of a
    /// socket with its own read timeout (PROJECT.md §13).
    #[cfg(windows)]
    fn recv(&mut self, id: &str, deadline: Instant) -> Result<DaemonMessage, ClientError> {
        loop {
            while let Some(frame) = self.decoder.next_frame()? {
                let envelope = ipc::decode_daemon(&frame)?;
                if envelope.id != id {
                    continue;
                }
                match envelope.body {
                    DaemonMessage::CtapKeepalive { .. } => continue,
                    body => return Ok(body),
                }
            }

            let now = Instant::now();
            if now >= deadline {
                return Err(ClientError::Timeout);
            }
            let slice = (deadline - now).min(READ_SLICE);

            match self.stream.read_chunk(slice) {
                Ok(chunk) if chunk.is_empty() => {
                    return Err(ClientError::Io(std::io::Error::new(
                        ErrorKind::UnexpectedEof,
                        "the daemon closed the connection",
                    )))
                }
                Ok(chunk) => self.decoder.push(&chunk),
                Err(e) if e.kind() == ErrorKind::TimedOut => {}
                Err(e) => return Err(ClientError::Io(e)),
            }
        }
    }

    #[cfg(not(any(unix, windows)))]
    fn recv(&mut self, _id: &str, _deadline: Instant) -> Result<DaemonMessage, ClientError> {
        Err(ClientError::NotRunning(std::io::Error::new(
            ErrorKind::Unsupported,
            "local IPC is not supported on this platform",
        )))
    }

    /// Asks whether the token is reachable.
    pub fn device_status(&mut self) -> Result<DeviceStatus, ClientError> {
        let id = self.take_id();
        self.send(&id, ClientMessage::DeviceStatus)?;
        match self.recv(&id, Instant::now() + READ_SLICE * 4)? {
            DaemonMessage::DeviceRange { in_range, bonded } => {
                Ok(DeviceStatus { in_range, bonded })
            }
            DaemonMessage::Error { code, .. } => Err(ClientError::Refused { code }),
            _ => Err(ClientError::Protocol(IpcError::UnsupportedVersion {
                got: 0,
                expected: ipc::PROTOCOL_VERSION,
            })),
        }
    }

    /// Relays one CTAP transaction and waits for the answer.
    pub fn transact(
        &mut self,
        request: &ctap::Request,
        timeout: Duration,
    ) -> Result<ctap::Response, ClientError> {
        let id = self.take_id();
        self.send(
            &id,
            ClientMessage::CtapRequest {
                cbor: request.encode(),
                timeout_ms: timeout.as_millis().min(u64::MAX as u128) as u64,
            },
        )?;

        match self.recv(&id, Instant::now() + timeout)? {
            DaemonMessage::CtapResponse { status, cbor } => {
                Ok(ctap::Response::new(ctap::StatusCode(status), cbor))
            }
            DaemonMessage::Error { code, .. } => Err(ClientError::Refused { code }),
            _ => Err(ClientError::Refused {
                code: ErrorCode::ProtocolError,
            }),
        }
    }
}

impl ClientError {
    /// The `SSH_SK_ERR_*` code to hand back to OpenSSH.
    ///
    /// Coarse on purpose. `ssh-keygen` prints these to a user who cannot act on
    /// the difference between a protocol error and a malformed frame, but
    /// "device not found" versus "general failure" does change what they try
    /// next.
    pub fn sk_error(&self) -> i32 {
        match self {
            ClientError::NotRunning(_)
            | ClientError::NoSocketPath
            | ClientError::Timeout
            | ClientError::Refused {
                code: ErrorCode::NotConnected | ErrorCode::NotBonded,
            } => crate::SSH_SK_ERR_DEVICE_NOT_FOUND,

            _ => crate::SSH_SK_ERR_GENERAL,
        }
    }
}
