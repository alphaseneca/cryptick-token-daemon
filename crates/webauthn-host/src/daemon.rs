use ctap::{Request, Response, StatusCode};
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

const READ_SLICE: Duration = Duration::from_millis(500);

/// A blocking client connection to a Windows named pipe.
///
/// `std::fs::File` has no read-timeout API, unlike `UnixStream`, so a
/// background thread owns the actual `ReadFile` calls and hands chunks back
/// over a channel — `recv_timeout` on that channel is what lets
/// [`DaemonClient::recv`] honour its deadline even while the pipe is silent.
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
        /// Connects to an existing named pipe server instance.
        ///
        /// Windows named pipes are opened with the ordinary file APIs: once a
        /// server has called `ConnectNamedPipe` (see
        /// `crates/daemon/src/server.rs`'s `windows::IpcListener`), a client
        /// opens the same path with `CreateFileW` to complete the connection.
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

        /// Waits up to `timeout` for the next chunk read from the pipe.
        ///
        /// An empty `Vec` means the peer closed the connection (clean EOF),
        /// matching what a `0`-byte `read()` means on the Unix path.
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

#[derive(Debug, Error)]
pub enum HostError {
    #[error("cannot connect to cryptick-daemon: {0}")]
    NotRunning(#[source] std::io::Error),
    #[error("no daemon socket path found")]
    NoSocketPath,
    #[error("IPC communication error: {0}")]
    Io(#[source] std::io::Error),
    #[error("IPC protocol error: {0}")]
    Protocol(#[from] IpcError),
    #[error("daemon refused request: {code:?}")]
    Refused { code: ErrorCode },
    #[error("operation timed out")]
    Timeout,
    #[error("CTAP error {status:?} ({code:#x})")]
    Ctap { status: StatusCode, code: u8 },
}

pub struct DaemonClient {
    #[cfg(unix)]
    stream: UnixStream,
    #[cfg(windows)]
    stream: PipeStream,
    decoder: FrameDecoder,
    next_id: u64,
}

impl DaemonClient {
    pub fn connect(timeout: Duration) -> Result<Self, HostError> {
        let path = ipc::default_socket_path().ok_or(HostError::NoSocketPath)?;
        Self::connect_to(&path, timeout)
    }

    #[cfg(unix)]
    pub fn connect_to(path: &Path, timeout: Duration) -> Result<Self, HostError> {
        let stream = UnixStream::connect(path).map_err(HostError::NotRunning)?;
        stream
            .set_read_timeout(Some(READ_SLICE.min(timeout)))
            .map_err(HostError::Io)?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(HostError::Io)?;
        Ok(Self {
            stream,
            decoder: FrameDecoder::new(),
            next_id: 1,
        })
    }

    /// Connects over the daemon's Windows named pipe.
    ///
    /// There is no per-call write timeout here: `recv`'s deadline check
    /// covers the round trip, and a write to a pipe the daemon is actively
    /// reading does not block the way a stalled read can (PROJECT.md §13).
    #[cfg(windows)]
    pub fn connect_to(path: &Path, _timeout: Duration) -> Result<Self, HostError> {
        let stream = PipeStream::connect(path).map_err(HostError::NotRunning)?;
        Ok(Self {
            stream,
            decoder: FrameDecoder::new(),
            next_id: 1,
        })
    }

    #[cfg(not(any(unix, windows)))]
    pub fn connect_to(_path: &Path, _timeout: Duration) -> Result<Self, HostError> {
        Err(HostError::NotRunning(std::io::Error::new(
            ErrorKind::Unsupported,
            "local IPC is not supported on this platform",
        )))
    }

    fn take_id(&mut self) -> String {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        format!("webauthn-{id}")
    }

    #[cfg(any(unix, windows))]
    fn send(&mut self, id: &str, body: ClientMessage) -> Result<(), HostError> {
        let frame = ipc::encode(&Envelope::new(id, body))?;
        self.stream.write_all(&frame).map_err(HostError::Io)?;
        self.stream.flush().map_err(HostError::Io)
    }

    #[cfg(not(any(unix, windows)))]
    fn send(&mut self, _id: &str, _body: ClientMessage) -> Result<(), HostError> {
        Err(HostError::NotRunning(std::io::Error::new(
            ErrorKind::Unsupported,
            "local IPC is not supported on this platform",
        )))
    }

    #[cfg(unix)]
    fn recv(&mut self, id: &str, deadline: Instant) -> Result<DaemonMessage, HostError> {
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
                return Err(HostError::Timeout);
            }

            match self.stream.read(&mut buf) {
                Ok(0) => {
                    return Err(HostError::Io(std::io::Error::new(
                        ErrorKind::UnexpectedEof,
                        "daemon closed connection",
                    )))
                }
                Ok(n) => self.decoder.push(&buf[..n]),
                Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => return Err(HostError::Io(e)),
            }
        }
    }

    /// Same contract as the Unix `recv`, but reads arrive from
    /// `PipeStream::read_chunk`'s background-thread channel instead of a
    /// socket with its own `SO_RCVTIMEO`-style timeout (PROJECT.md §13).
    #[cfg(windows)]
    fn recv(&mut self, id: &str, deadline: Instant) -> Result<DaemonMessage, HostError> {
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
                return Err(HostError::Timeout);
            }
            let slice = (deadline - now).min(READ_SLICE);

            match self.stream.read_chunk(slice) {
                Ok(chunk) if chunk.is_empty() => {
                    return Err(HostError::Io(std::io::Error::new(
                        ErrorKind::UnexpectedEof,
                        "daemon closed connection",
                    )))
                }
                Ok(chunk) => self.decoder.push(&chunk),
                Err(e) if e.kind() == ErrorKind::TimedOut => {}
                Err(e) => return Err(HostError::Io(e)),
            }
        }
    }

    #[cfg(not(any(unix, windows)))]
    fn recv(&mut self, _id: &str, _deadline: Instant) -> Result<DaemonMessage, HostError> {
        Err(HostError::NotRunning(std::io::Error::new(
            ErrorKind::Unsupported,
            "local IPC is not supported on this platform",
        )))
    }

    pub fn device_status(&mut self) -> Result<(bool, bool), HostError> {
        let id = self.take_id();
        self.send(&id, ClientMessage::DeviceStatus)?;
        match self.recv(&id, Instant::now() + Duration::from_millis(300))? {
            DaemonMessage::DeviceRange { in_range, bonded } => Ok((in_range, bonded)),
            DaemonMessage::Error { code, .. } => Err(HostError::Refused { code }),
            _ => Err(HostError::Protocol(IpcError::Malformed(
                serde_json::Error::io(std::io::Error::other("unexpected reply")),
            ))),
        }
    }

    /// Every device the daemon knows about (PROJECT.md §13's shape,
    /// extended for item 2 of `docs/research/multi-device-and-credential-sync.md`).
    /// Answered instantly by the daemon regardless of any in-flight CTAP
    /// transaction — see `crates/daemon/src/server.rs`'s `ListDevices` arm.
    pub fn list_devices(&mut self) -> Result<Vec<ipc::DeviceInfo>, HostError> {
        let id = self.take_id();
        self.send(&id, ClientMessage::ListDevices)?;
        match self.recv(&id, Instant::now() + Duration::from_millis(500))? {
            DaemonMessage::DeviceList { devices } => Ok(devices),
            DaemonMessage::Error { code, .. } => Err(HostError::Refused { code }),
            _ => Err(HostError::Protocol(IpcError::Malformed(
                serde_json::Error::io(std::io::Error::other("unexpected reply")),
            ))),
        }
    }

    /// Makes `id` the daemon's active device. See
    /// `crates/daemon/src/devices.rs`'s module doc for what "active"
    /// currently guarantees — today this is bookkeeping plus (for a BLE id)
    /// retargeting the daemon's persisted reconnect address, not necessarily
    /// an instantaneous live hand-off of an already-open connection.
    pub fn select_device(&mut self, id: &str) -> Result<(), HostError> {
        let request_id = self.take_id();
        self.send(
            &request_id,
            ClientMessage::SelectDevice { id: id.to_string() },
        )?;
        match self.recv(&request_id, Instant::now() + Duration::from_millis(500))? {
            DaemonMessage::Ack => Ok(()),
            DaemonMessage::Error { code, .. } => Err(HostError::Refused { code }),
            _ => Err(HostError::Protocol(IpcError::Malformed(
                serde_json::Error::io(std::io::Error::other("unexpected reply")),
            ))),
        }
    }

    pub fn transact(
        &mut self,
        request: &Request,
        timeout: Duration,
    ) -> Result<Response, HostError> {
        let response = self.transact_preserving_status(request, timeout)?;
        if !response.status.is_ok() {
            return Err(HostError::Ctap {
                status: response.status,
                code: response.status.as_u8(),
            });
        }
        Ok(response)
    }

    /// Same as [`Self::transact`], but a non-OK CTAP status is returned as
    /// `Ok` rather than collapsed into `Err(HostError::Ctap)`.
    ///
    /// `transact` is right for most callers (`create`/`get`/`totp_code`): a
    /// non-OK status is simply a failure, and the error message is enough.
    /// Credential management is different — `touch_required`/`timeout`/
    /// `cancelled` are first-class, distinguishable outcomes the extension
    /// needs the real status byte for (PROJECT.md §15.8's "fail closed" cuts
    /// both ways: a caller that needs to tell two failure *kinds* apart must
    /// not have them pre-merged into one string).
    pub fn transact_preserving_status(
        &mut self,
        request: &Request,
        timeout: Duration,
    ) -> Result<Response, HostError> {
        let mut attempts = 0;
        loop {
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
                    return Ok(Response::new(StatusCode(status), cbor));
                }
                DaemonMessage::Error {
                    code: ErrorCode::NotConnected,
                    ..
                } if attempts < 3 => {
                    attempts += 1;
                    std::thread::sleep(Duration::from_millis(800));
                    continue;
                }
                DaemonMessage::Error { code, .. } => return Err(HostError::Refused { code }),
                _ => {
                    return Err(HostError::Refused {
                        code: ErrorCode::ProtocolError,
                    })
                }
            }
        }
    }
}
