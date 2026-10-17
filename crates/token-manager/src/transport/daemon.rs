//! BLE Daemon Fallback transport client via local IPC socket.
//!
//! Connects to `cryptick-daemon` over the local domain socket (or Windows named pipe)
//! to relay APDUs and vendor OATH commands across the dedicated Bluetooth Daemon Bridge.

use super::TokenTransport;
use crate::error::ManagerError;
use ctap::StatusCode;
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

/// `CTAPHID_CRYPTICK_OATH`, the vendor command `oath.rs` sends as `cmd`.
///
/// The one CTAPHID command whose relayed payload needs an extra
/// discriminator byte in front of it on this wire — see `transceive`'s doc
/// for why.
const VENDOR_OATH_CMD: u8 = 0x63;

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
    /// Relays one CTAPHID-shaped command over the Daemon Bridge.
    ///
    /// **Framing note — read before changing the `cmd == VENDOR_OATH_CMD`
    /// split below.** `ClientMessage::CtapRequest` carries one flat byte
    /// string (`cbor`), with no separate field for *which* CTAPHID command
    /// (`0x10` CBOR, `0x63` vendor OATH, `0x03` raw MSG/APDU) this is. Over
    /// USB, that distinction lives in the CTAPHID packet header (`pkt[4]` in
    /// `UsbTransport::transceive`) — a field entirely separate from the
    /// payload bytes, which `UsbTransport` therefore sends completely
    /// unmodified, already starting with the real CTAP2 command / APDU `CLA`
    /// byte `payload` itself carries.
    ///
    /// The firmware's daemon-bridge dispatcher
    /// (`core/fido2/hal_esp32.cpp`'s `ble_dispatch`) has exactly **one**
    /// special case for an extra discriminator byte in front of a relayed
    /// payload: `ctap_cmd == 0xE3 || ctap_cmd == 0x63` routes to the vendor
    /// OATH applet and strips it first. Every other command — CTAP2 CBOR
    /// included — falls through to `ctap_request()`, which reads its *own*
    /// first byte as the real CTAP2 command with no such stripping. Sending
    /// a CBOR request wrapped the same way OATH needs (as this code
    /// previously did unconditionally) puts the wrong byte in front of
    /// `ctap_request()`'s input on every non-OATH command relayed over this
    /// transport, which is CTAP2-shaped and corrupted for every caller of
    /// it — some of it later swallowed into
    /// `error.response not valid CBOR`-style messages that gave no hint
    /// this was a framing bug rather than a device or firmware problem.
    #[cfg(any(unix, windows))]
    fn transceive(
        &mut self,
        cmd: u8,
        payload: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, ManagerError> {
        let id = self.take_id();

        self.send(
            &id,
            ClientMessage::CtapRequest {
                cbor: encode_daemon_request(cmd, payload),
                timeout_ms: timeout.as_millis().min(u64::MAX as u128) as u64,
            },
        )?;

        match self.recv(&id, Instant::now() + timeout)? {
            DaemonMessage::CtapResponse { status, cbor } => decode_daemon_response(cmd, status, cbor),
            DaemonMessage::Error { code, message } => {
                eprintln!("cryptick-manager: daemon reported error ({code:?}): {message}");
                Err(ManagerError::Transport(format!(
                    "Daemon reported error ({code:?}): {message}"
                )))
            }
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

/// Builds the bytes sent as `ClientMessage::CtapRequest`'s `cbor` field for
/// one `cmd`/`payload` pair. See `transceive`'s doc comment for why only
/// vendor OATH gets an extra discriminator byte in front of it.
fn encode_daemon_request(cmd: u8, payload: &[u8]) -> Vec<u8> {
    if cmd == VENDOR_OATH_CMD {
        let mut v = Vec::with_capacity(1 + payload.len());
        v.push(cmd | 0x80);
        v.extend_from_slice(payload);
        v
    } else {
        payload.to_vec()
    }
}

/// Turns one `DaemonMessage::CtapResponse { status, cbor }` into the bytes
/// `transceive` hands back to its caller for this `cmd`. See `transceive`'s
/// doc comment for why only vendor OATH strips the status byte away.
fn decode_daemon_response(cmd: u8, status: u8, cbor: Vec<u8>) -> Result<Vec<u8>, ManagerError> {
    if cmd == VENDOR_OATH_CMD {
        let status_code = StatusCode(status);
        if !status_code.is_ok() && cbor.is_empty() {
            return Err(ManagerError::Transport(format!(
                "CTAP error from token: {status_code:?} ({status:#04X})"
            )));
        }
        Ok(cbor)
    } else {
        let mut raw = Vec::with_capacity(1 + cbor.len());
        raw.push(status);
        raw.extend_from_slice(&cbor);
        Ok(raw)
    }
}

#[cfg(test)]
mod framing_tests {
    use super::*;

    const CBOR_CMD: u8 = 0x10;
    const MSG_CMD: u8 = 0x03;

    #[test]
    fn cbor_requests_are_sent_unprefixed_like_usb_sends_them() {
        // The real CTAP2 command byte (0x04 = authenticatorGetInfo) must end
        // up first on the wire, with nothing in front of it — the firmware's
        // generic `ctap_request()` has no discriminator-stripping step,
        // unlike the vendor OATH special case.
        let payload = [0x04u8];
        assert_eq!(encode_daemon_request(CBOR_CMD, &payload), vec![0x04]);
    }

    #[test]
    fn msg_requests_are_sent_unprefixed_too() {
        let apdu = [0x00u8, 0xA4, 0x04, 0x00];
        assert_eq!(encode_daemon_request(MSG_CMD, &apdu), apdu.to_vec());
    }

    #[test]
    fn vendor_oath_requests_keep_their_discriminator_byte() {
        // Firmware's `ble_dispatch` specifically detects and strips this
        // byte (`ctap_cmd == 0xE3`) before routing to the OATH applet.
        let apdu = [0x00u8, 0xA4, 0x04, 0x00];
        let mut expected = vec![VENDOR_OATH_CMD | 0x80];
        expected.extend_from_slice(&apdu);
        assert_eq!(encode_daemon_request(VENDOR_OATH_CMD, &apdu), expected);
    }

    #[test]
    fn a_successful_cbor_response_comes_back_with_its_status_byte_attached() {
        // Matches exactly what `UsbTransport` returns for the same command:
        // a leading status byte, then the CBOR body — so a caller decoding
        // via `ctap::Response::decode` sees identical bytes either way.
        let cbor_body = vec![0xa1, 0x01, 0x18, 0x20];
        let raw = decode_daemon_response(CBOR_CMD, 0x00, cbor_body.clone()).unwrap();
        assert_eq!(raw[0], 0x00);
        assert_eq!(&raw[1..], &cbor_body[..]);
    }

    #[test]
    fn a_failed_cbor_response_still_comes_back_with_its_status_byte_so_the_caller_can_see_it() {
        // Unlike OATH, a non-OK CBOR status must reach the caller rather than
        // short-circuiting into a generic transport error — `fido_cli.rs`
        // needs the real CTAP2 status code to report what actually happened.
        let raw = decode_daemon_response(CBOR_CMD, 0x01, Vec::new()).unwrap();
        assert_eq!(raw, vec![0x01]);
    }

    #[test]
    fn a_successful_oath_response_has_its_synthetic_status_byte_stripped() {
        // `oath.rs`'s parsers expect the raw APDU-style response directly,
        // with no extra leading byte — matching what `UsbTransport` gives
        // them, since the real OATH wire protocol has no such byte at all.
        let oath_body = vec![0x71, 0x02, 0xAB, 0xCD, 0x90, 0x00];
        let raw = decode_daemon_response(VENDOR_OATH_CMD, 0x00, oath_body.clone()).unwrap();
        assert_eq!(raw, oath_body);
    }

    #[test]
    fn a_failed_oath_response_with_no_body_is_a_transport_error() {
        assert!(decode_daemon_response(VENDOR_OATH_CMD, 0x01, Vec::new()).is_err());
    }
}
