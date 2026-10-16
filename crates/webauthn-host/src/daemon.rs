use ctap::{Request, Response, StatusCode};
use ipc::{ClientMessage, DaemonMessage, Envelope, ErrorCode, FrameDecoder, IpcError};
use std::{
    io::{ErrorKind, Read, Write},
    os::unix::net::UnixStream,
    path::Path,
    time::{Duration, Instant},
};
use thiserror::Error;

const READ_SLICE: Duration = Duration::from_millis(500);

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
    stream: UnixStream,
    decoder: FrameDecoder,
    next_id: u64,
}

impl DaemonClient {
    pub fn connect(timeout: Duration) -> Result<Self, HostError> {
        let path = ipc::default_socket_path().ok_or(HostError::NoSocketPath)?;
        Self::connect_to(&path, timeout)
    }

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

    fn take_id(&mut self) -> String {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        format!("webauthn-{id}")
    }

    fn send(&mut self, id: &str, body: ClientMessage) -> Result<(), HostError> {
        let frame = ipc::encode(&Envelope::new(id, body))?;
        self.stream.write_all(&frame).map_err(HostError::Io)?;
        self.stream.flush().map_err(HostError::Io)
    }

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

    pub fn transact(
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
                    let status_code = StatusCode(status);
                    if !status_code.is_ok() {
                        return Err(HostError::Ctap {
                            status: status_code,
                            code: status,
                        });
                    }
                    return Ok(Response::new(status_code, cbor));
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
