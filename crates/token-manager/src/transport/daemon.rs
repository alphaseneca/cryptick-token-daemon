//! BLE Daemon Fallback transport client via local IPC socket.
//!
//! Connects to `cryptick-daemon` over the local domain socket (or Windows named pipe)
//! to relay APDUs and vendor OATH commands across the dedicated Bluetooth Daemon Bridge.

use super::TokenTransport;
use crate::error::ManagerError;
use ctap::{Command, Request, StatusCode};
use ipc::{ClientMessage, DaemonMessage, Envelope, FrameDecoder};
use std::{
    io::{ErrorKind, Write},
    path::Path,
    time::{Duration, Instant},
};

#[cfg(unix)]
use std::{io::Read, os::unix::net::UnixStream};

#[cfg(windows)]
use windows_pipe::PipeStream;

const READ_SLICE: Duration = Duration::from_millis(500);

/// A blocking client connection to a Windows named pipe.
///
/// See the identical module in `crates/webauthn-host/src/daemon.rs` for why
/// a background reader thread is needed: `std::fs::File` has no read-timeout
/// API, unlike `UnixStream`, so this is what lets `recv`'s deadline fire even
/// while the pipe is silent.
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

/// A connection to `cryptick-daemon` over local IPC.
pub struct DaemonTransport {
    #[cfg(unix)]
    stream: UnixStream,
    #[cfg(windows)]
    stream: PipeStream,
    decoder: FrameDecoder,
    next_id: u64,
}

impl DaemonTransport {
    /// Connects to the daemon using the default platform socket path.
    pub fn connect(timeout: Duration) -> Result<Self, ManagerError> {
        let path = ipc::default_socket_path().ok_or_else(|| {
            ManagerError::Transport("Could not determine local IPC socket path".to_string())
        })?;
        Self::connect_to(&path, timeout)
    }

    /// Connects to the daemon at an explicit filesystem path (Unix domain
    /// socket) or named pipe path (Windows).
    pub fn connect_to(path: &Path, timeout: Duration) -> Result<Self, ManagerError> {
        #[cfg(unix)]
        {
            let stream = UnixStream::connect(path).map_err(|e| {
                ManagerError::Transport(format!(
                    "Cannot connect to cryptick-daemon socket at '{}': {e}",
                    path.display()
                ))
            })?;
            stream
                .set_read_timeout(Some(READ_SLICE.min(timeout)))
                .map_err(|e| {
                    ManagerError::Transport(format!("Failed to set socket read timeout: {e}"))
                })?;
            stream.set_write_timeout(Some(timeout)).map_err(|e| {
                ManagerError::Transport(format!("Failed to set socket write timeout: {e}"))
            })?;

            Ok(Self {
                stream,
                decoder: FrameDecoder::new(),
                next_id: 1,
            })
        }
        #[cfg(windows)]
        {
            let stream = PipeStream::connect(path).map_err(|e| {
                ManagerError::Transport(format!(
                    "Cannot connect to cryptick-daemon named pipe at '{}': {e}",
                    path.display()
                ))
            })?;
            Ok(Self {
                stream,
                decoder: FrameDecoder::new(),
                next_id: 1,
            })
        }
        #[cfg(not(any(unix, windows)))]
        {
            Err(ManagerError::Transport(
                "Daemon IPC transport is not supported on this platform".to_string(),
            ))
        }
    }

    fn take_id(&mut self) -> String {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        format!("cryptick-manager-{id}")
    }

    #[cfg(any(unix, windows))]
    fn send(&mut self, id: &str, body: ClientMessage) -> Result<(), ManagerError> {
        let frame = ipc::encode(&Envelope::new(id, body))
            .map_err(|e| ManagerError::Transport(format!("IPC encoding error: {e}")))?;
        self.stream
            .write_all(&frame)
            .map_err(|e| ManagerError::Transport(format!("IPC write error: {e}")))?;
        self.stream
            .flush()
            .map_err(|e| ManagerError::Transport(format!("IPC flush error: {e}")))?;
        Ok(())
    }

    #[cfg(unix)]
    fn recv(&mut self, id: &str, deadline: Instant) -> Result<DaemonMessage, ManagerError> {
        let mut buf = [0u8; 8192];
        loop {
            while let Some(frame) = self
                .decoder
                .next_frame()
                .map_err(|e| ManagerError::Transport(e.to_string()))?
            {
                let envelope = ipc::decode_daemon(&frame)
                    .map_err(|e| ManagerError::Transport(e.to_string()))?;
                if envelope.id != id {
                    continue;
                }
                match envelope.body {
                    DaemonMessage::CtapKeepalive { .. } => {
                        // Token is processing or awaiting biometric touch sensor interaction
                        continue;
                    }
                    body => return Ok(body),
                }
            }

            if Instant::now() >= deadline {
                return Err(ManagerError::Transport(
                    "Daemon transceive timed out".to_string(),
                ));
            }

            match self.stream.read(&mut buf) {
                Ok(0) => {
                    return Err(ManagerError::Transport(
                        "Daemon closed IPC connection unexpectedly".to_string(),
                    ));
                }
                Ok(n) => self.decoder.push(&buf[..n]),
                Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => return Err(ManagerError::Transport(format!("Socket read error: {e}"))),
            }
        }
    }

    /// Same contract as the Unix `recv`, but reads come from
    /// `PipeStream::read_chunk`'s background-thread channel (PROJECT.md §13).
    #[cfg(windows)]
    fn recv(&mut self, id: &str, deadline: Instant) -> Result<DaemonMessage, ManagerError> {
        loop {
            while let Some(frame) = self
                .decoder
                .next_frame()
                .map_err(|e| ManagerError::Transport(e.to_string()))?
            {
                let envelope = ipc::decode_daemon(&frame)
                    .map_err(|e| ManagerError::Transport(e.to_string()))?;
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
                return Err(ManagerError::Transport(
                    "Daemon transceive timed out".to_string(),
                ));
            }
            let slice = (deadline - now).min(READ_SLICE);

            match self.stream.read_chunk(slice) {
                Ok(chunk) if chunk.is_empty() => {
                    return Err(ManagerError::Transport(
                        "Daemon closed IPC connection unexpectedly".to_string(),
                    ));
                }
                Ok(chunk) => self.decoder.push(&chunk),
                Err(e) if e.kind() == ErrorKind::TimedOut => {}
                Err(e) => return Err(ManagerError::Transport(format!("Named pipe read error: {e}"))),
            }
        }
    }

    #[cfg(not(any(unix, windows)))]
    fn recv(&mut self, _id: &str, _deadline: Instant) -> Result<DaemonMessage, ManagerError> {
        Err(ManagerError::Transport(
            "Daemon IPC transport is not supported on this platform".to_string(),
        ))
    }

    /// Every device the daemon knows about. See
    /// `crates/daemon/src/devices.rs`'s module doc for what identity means
    /// here (no firmware-populated serial number exists for this hardware,
    /// so this is a best-effort recognition key, not a guaranteed-stable
    /// one) and why the daemon only ever reports BLE devices.
    #[cfg(any(unix, windows))]
    pub fn list_devices(&mut self) -> Result<Vec<ipc::DeviceInfo>, ManagerError> {
        let id = self.take_id();
        self.send(&id, ClientMessage::ListDevices)?;
        match self.recv(&id, Instant::now() + Duration::from_millis(500))? {
            DaemonMessage::DeviceList { devices } => Ok(devices),
            DaemonMessage::Error { message, .. } => {
                Err(ManagerError::Transport(format!("Daemon error: {message}")))
            }
            _ => Err(ManagerError::Transport(
                "Unexpected reply to ListDevices".to_string(),
            )),
        }
    }

    /// Makes `id` the daemon's active device.
    #[cfg(any(unix, windows))]
    pub fn select_device(&mut self, id: &str) -> Result<(), ManagerError> {
        let request_id = self.take_id();
        self.send(
            &request_id,
            ClientMessage::SelectDevice { id: id.to_string() },
        )?;
        match self.recv(&request_id, Instant::now() + Duration::from_millis(500))? {
            DaemonMessage::Ack => Ok(()),
            DaemonMessage::Error { message, .. } => {
                Err(ManagerError::Transport(format!("Daemon error: {message}")))
            }
            _ => Err(ManagerError::Transport(
                "Unexpected reply to SelectDevice".to_string(),
            )),
        }
    }

    #[cfg(not(any(unix, windows)))]
    pub fn list_devices(&mut self) -> Result<Vec<ipc::DeviceInfo>, ManagerError> {
        Err(ManagerError::Transport(
            "Daemon IPC transport is not supported on this platform".to_string(),
        ))
    }

    #[cfg(not(any(unix, windows)))]
    pub fn select_device(&mut self, _id: &str) -> Result<(), ManagerError> {
        Err(ManagerError::Transport(
            "Daemon IPC transport is not supported on this platform".to_string(),
        ))
    }

    /// Queries the daemon for connected token link status (in_range, bonded).
    #[cfg(any(unix, windows))]
    pub fn device_status(&mut self) -> Result<(bool, bool), ManagerError> {
        let id = self.take_id();
        self.send(&id, ClientMessage::DeviceStatus)?;
        match self.recv(&id, Instant::now() + Duration::from_secs(2))? {
            DaemonMessage::DeviceRange { in_range, bonded } => Ok((in_range, bonded)),
            DaemonMessage::Error { message, .. } => {
                Err(ManagerError::Transport(format!("Daemon error: {message}")))
            }
            _ => Err(ManagerError::Transport(
                "Unexpected reply to DeviceStatus".to_string(),
            )),
        }
    }

    #[cfg(not(any(unix, windows)))]
    pub fn device_status(&mut self) -> Result<(bool, bool), ManagerError> {
        Err(ManagerError::Transport(
            "Daemon IPC transport is not supported on this platform".to_string(),
        ))
    }
}

impl TokenTransport for DaemonTransport {
    #[cfg(any(unix, windows))]
    fn transceive(
        &mut self,
        cmd: u8,
        payload: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, ManagerError> {
        let cmd_byte = cmd | 0x80;
        let ctap_req = Request::new(Command(cmd_byte), payload.to_vec());
        let id = self.take_id();

        self.send(
            &id,
            ClientMessage::CtapRequest {
                cbor: ctap_req.encode(),
                timeout_ms: timeout.as_millis().min(u64::MAX as u128) as u64,
            },
        )?;

        match self.recv(&id, Instant::now() + timeout)? {
            DaemonMessage::CtapResponse { status, cbor } => {
                let status_code = StatusCode(status);
                if !status_code.is_ok() && cbor.is_empty() {
                    return Err(ManagerError::Transport(format!(
                        "CTAP error from token: {status_code:?} ({status:#04X})"
                    )));
                }
                Ok(cbor)
            }
            DaemonMessage::Error { code, message } => Err(ManagerError::Transport(format!(
                "Daemon reported error ({code:?}): {message}"
            ))),
            _ => Err(ManagerError::Transport(
                "Unexpected message response from daemon".to_string(),
            )),
        }
    }

    #[cfg(not(any(unix, windows)))]
    fn transceive(
        &mut self,
        _cmd: u8,
        _payload: &[u8],
        _timeout: Duration,
    ) -> Result<Vec<u8>, ManagerError> {
        Err(ManagerError::Transport(
            "Daemon transport not supported on this platform".to_string(),
        ))
    }

    fn transport_name(&self) -> &'static str {
        "BLE Daemon Fallback"
    }

    fn serial(&self) -> Option<String> {
        None
    }
}
