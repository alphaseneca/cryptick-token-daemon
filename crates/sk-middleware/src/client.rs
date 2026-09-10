//! A blocking IPC client for the daemon.
//!
//! Blocking on purpose. This runs inside `ssh-sk-helper`, which knows nothing
//! about async runtimes, and starting one inside a host process is how you get
//! a hang at exit (PROJECT.md §10). The whole conversation is one request and
//! one reply, so there is nothing an executor would buy.

use ipc::{ClientMessage, DaemonMessage, Envelope, ErrorCode, FrameDecoder, IpcError};
use std::{
    io::{ErrorKind, Read, Write},
    os::unix::net::UnixStream,
    path::Path,
    time::{Duration, Instant},
};
use thiserror::Error;

/// How long a single socket read may block before the overall deadline is
/// rechecked. Keepalives arrive far more often than this while the device is
/// waiting for a fingerprint, so it only bites when the daemon has gone quiet.
const READ_SLICE: Duration = Duration::from_millis(500);

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
    stream: UnixStream,
    decoder: FrameDecoder,
    next_id: u64,
}

impl DaemonClient {
    /// Connects to the daemon's default socket.
    pub fn connect(timeout: Duration) -> Result<Self, ClientError> {
        let path = ipc::default_socket_path().ok_or(ClientError::NoSocketPath)?;
        Self::connect_to(&path, timeout)
    }

    /// Connects to a specific socket path.
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

    fn take_id(&mut self) -> String {
        let id = self.next_id;
        // Per-connection, not process-global: §10 forbids global state, and a
        // counter shared between concurrent ssh-sk-helper processes would be
        // meaningless anyway.
        self.next_id = self.next_id.wrapping_add(1);
        format!("sk-{id}")
    }

    fn send(&mut self, id: &str, body: ClientMessage) -> Result<(), ClientError> {
        let frame = ipc::encode(&Envelope::new(id, body))?;
        self.stream.write_all(&frame).map_err(ClientError::Io)?;
        self.stream.flush().map_err(ClientError::Io)
    }

    /// Reads replies until one matching `id` arrives, or the deadline passes.
    ///
    /// Keepalives are consumed and discarded. They mean the device is waiting
    /// for a fingerprint, which the middleware cannot act on — `ssh-keygen`
    /// has already printed its own "you may need to touch your authenticator"
    /// prompt, and §10 forbids writing anything to stdout or stderr from here.
    /// They deliberately do **not** extend the deadline.
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
