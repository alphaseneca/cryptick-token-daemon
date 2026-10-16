//! BLE Daemon Fallback transport client via local IPC socket.
//!
//! Connects to `cryptick-daemon` over the local domain socket (or Windows named pipe)
//! to relay APDUs and vendor OATH commands across the dedicated Bluetooth Daemon Bridge.

use super::TokenTransport;
use ctap::{Command, Request, StatusCode};
use ipc::{ClientMessage, DaemonMessage, Envelope, FrameDecoder};
use std::{
    io::{ErrorKind, Read, Write},
    path::Path,
    time::{Duration, Instant},
};

#[cfg(unix)]
use std::os::unix::net::UnixStream;

const READ_SLICE: Duration = Duration::from_millis(500);

/// A connection to `cryptick-daemon` over local IPC.
pub struct DaemonTransport {
    #[cfg(unix)]
    stream: UnixStream,
    decoder: FrameDecoder,
    next_id: u64,
}

impl DaemonTransport {
    /// Connects to the daemon using the default platform socket path.
    pub fn connect(timeout: Duration) -> Result<Self, String> {
        let path = ipc::default_socket_path()
            .ok_or_else(|| "Could not determine local IPC socket path".to_string())?;
        Self::connect_to(&path, timeout)
    }

    /// Connects to the daemon at an explicit filesystem path.
    pub fn connect_to(path: &Path, timeout: Duration) -> Result<Self, String> {
        #[cfg(unix)]
        {
            let stream = UnixStream::connect(path).map_err(|e| {
                format!(
                    "Cannot connect to cryptick-daemon socket at '{}': {e}",
                    path.display()
                )
            })?;
            stream
                .set_read_timeout(Some(READ_SLICE.min(timeout)))
                .map_err(|e| format!("Failed to set socket read timeout: {e}"))?;
            stream
                .set_write_timeout(Some(timeout))
                .map_err(|e| format!("Failed to set socket write timeout: {e}"))?;

            Ok(Self {
                stream,
                decoder: FrameDecoder::new(),
                next_id: 1,
            })
        }
        #[cfg(not(unix))]
        {
            Err("Named pipe IPC transport for Windows not implemented".to_string())
        }
    }

    fn take_id(&mut self) -> String {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        format!("ykman-{id}")
    }

    #[cfg(unix)]
    fn send(&mut self, id: &str, body: ClientMessage) -> Result<(), String> {
        let frame = ipc::encode(&Envelope::new(id, body))
            .map_err(|e| format!("IPC encoding error: {e}"))?;
        self.stream
            .write_all(&frame)
            .map_err(|e| format!("Socket write error: {e}"))?;
        self.stream
            .flush()
            .map_err(|e| format!("Socket flush error: {e}"))?;
        Ok(())
    }

    #[cfg(unix)]
    fn recv(&mut self, id: &str, deadline: Instant) -> Result<DaemonMessage, String> {
        let mut buf = [0u8; 8192];
        loop {
            while let Some(frame) = self.decoder.next_frame().map_err(|e| e.to_string())? {
                let envelope = ipc::decode_daemon(&frame).map_err(|e| e.to_string())?;
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
                return Err("Daemon transceive timed out".to_string());
            }

            match self.stream.read(&mut buf) {
                Ok(0) => {
                    return Err("Daemon closed IPC connection unexpectedly".to_string());
                }
                Ok(n) => self.decoder.push(&buf[..n]),
                Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => return Err(format!("Socket read error: {e}")),
            }
        }
    }

    /// Queries the daemon for connected token link status (in_range, bonded).
    #[cfg(unix)]
    pub fn device_status(&mut self) -> Result<(bool, bool), String> {
        let id = self.take_id();
        self.send(&id, ClientMessage::DeviceStatus)?;
        match self.recv(&id, Instant::now() + Duration::from_secs(2))? {
            DaemonMessage::DeviceRange { in_range, bonded } => Ok((in_range, bonded)),
            DaemonMessage::Error { message, .. } => Err(format!("Daemon error: {message}")),
            _ => Err("Unexpected reply to DeviceStatus".to_string()),
        }
    }
}

impl TokenTransport for DaemonTransport {
    #[cfg(unix)]
    fn transceive(
        &mut self,
        cmd: u8,
        payload: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, String> {
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
                    return Err(format!(
                        "CTAP error from token: {status_code:?} ({status:#04X})"
                    ));
                }
                Ok(cbor)
            }
            DaemonMessage::Error { code, message } => {
                Err(format!("Daemon reported error ({code:?}): {message}"))
            }
            _ => Err("Unexpected message response from daemon".to_string()),
        }
    }

    #[cfg(not(unix))]
    fn transceive(
        &mut self,
        _cmd: u8,
        _payload: &[u8],
        _timeout: Duration,
    ) -> Result<Vec<u8>, String> {
        Err("Daemon transport not supported on non-unix".to_string())
    }

    fn transport_name(&self) -> &'static str {
        "BLE Daemon Fallback"
    }

    fn serial(&self) -> Option<String> {
        None
    }
}
