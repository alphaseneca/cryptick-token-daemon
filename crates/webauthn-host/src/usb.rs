use ctaphid::{ChannelId, PACKET_SIZE};
use hidapi::{HidApi, HidDevice};
use std::time::{Duration, Instant};
use thiserror::Error;

const CRYPTICK_VID: u16 = 0x1209;
const CRYPTICK_PID: u16 = 0xBEEE;
const FIDO_USAGE_PAGE: u16 = 0xF1D0;

/// One Cryptick Token found on the USB bus, before any connection is opened.
pub struct UsbDeviceId {
    /// The device descriptor's `iSerialNumber` string
    /// (`"CT-XXXXXXXXXXXX"`), when the connected firmware exposes one — see
    /// `cryptick-token-code`'s NOTES.md, "Real USB serial number (eFuse
    /// MAC)". `None` on older firmware (or the USB Serial/JTAG lab
    /// fallback build, which never owns this descriptor at all).
    pub serial: Option<String>,
}

/// Enumerates every Cryptick Token presently on the USB bus, without
/// connecting to any of them — a plain `hidapi::HidApi::device_list()` scan,
/// the same non-connecting identity source
/// `crates/token-manager/src/transport/usb.rs`'s `UsbTransport::list_devices`
/// already uses, so `handle_list_devices` can tell two distinct physical
/// units apart instead of reporting a single synthetic `"usb"` row
/// regardless of how many are actually plugged in.
pub fn list_devices() -> Vec<UsbDeviceId> {
    let Ok(api) = HidApi::new() else {
        return Vec::new();
    };
    api.device_list()
        .filter(|d| d.vendor_id() == CRYPTICK_VID && d.product_id() == CRYPTICK_PID)
        .filter(|d| !matches!(d.bus_type(), hidapi::BusType::Bluetooth))
        .map(|d| UsbDeviceId {
            serial: d.serial_number().map(str::to_string),
        })
        .collect()
}

/// Mirrors [`crate::daemon::HostError`]'s shape for the USB side of
/// [`crate::usb`] (PROJECT.md §20: typed errors, no stringly-typed failures
/// across crate lines). `UsbClient::transact`/`transact_preserving_status`
/// implement the identical interface `DaemonClient`'s do — see the doc
/// comment on [`UsbClient::transact_preserving_status`] — so the two error
/// types line up variant-for-variant where the shape is the same
/// (`Timeout`, `Ctap { status, code }`) and diverge only where the
/// transports genuinely differ: USB has no daemon to refuse a request or an
/// `IpcError` to wrap, but it does have a raw HID I/O layer and a
/// CTAPHID_INIT handshake that can fail before any transaction starts.
#[derive(Debug, Error)]
pub enum UsbError {
    /// A raw HID write or read failed at the `hidapi` layer.
    #[error("USB HID I/O error: {0}")]
    Io(#[source] hidapi::HidError),

    /// `CTAPHID_INIT` did not complete: the device timed out or answered
    /// with something that doesn't look like an init response. Mirrors
    /// `HostError::NotRunning` in spirit — the connection never reached a
    /// usable state.
    #[error("USB CTAPHID handshake failed: {0}")]
    Handshake(String),

    /// The caller's payload is larger than the CTAPHID sequence framing can
    /// carry (7609 bytes: a 64-byte init packet plus 128 continuation
    /// packets of 59 bytes each).
    #[error("payload exceeds maximum CTAPHID sequence capacity (7609 bytes)")]
    PayloadTooLarge,

    /// The device sent a `CTAPHID_ERROR` packet.
    #[error("device reported CTAPHID error {0:#04x}")]
    DeviceError(u8),

    /// No complete response arrived before the caller's deadline.
    #[error("operation timed out waiting for a complete response")]
    Timeout,

    /// A CTAP2 transaction completed but the authenticator returned a
    /// non-OK status. Mirrors `HostError::Ctap` exactly: same two fields,
    /// same reason (PROJECT.md §15.8 — a caller that needs to tell failure
    /// *kinds* apart, such as credential management, must get the real
    /// status byte instead of a pre-merged string).
    #[error("CTAP error {status:?} ({code:#x})")]
    Ctap {
        /// The CTAP status code the authenticator returned.
        status: ctap::StatusCode,
        /// The same status, as the raw byte, for display.
        code: u8,
    },

    /// A response did not have the shape the caller expected (too short, a
    /// non-success OATH status word, an unrecognized TLV layout).
    #[error("malformed response: {0}")]
    Protocol(String),
}

pub struct UsbClient {
    device: HidDevice,
    channel_id: ChannelId,
}

impl UsbClient {
    pub fn try_connect() -> Option<Self> {
        let api = HidApi::new().ok()?;

        // Find all candidate HID devices matching Cryptick VID/PID on USB bus.
        let mut candidates: Vec<_> = api
            .device_list()
            .filter(|d| d.vendor_id() == CRYPTICK_VID && d.product_id() == CRYPTICK_PID)
            .filter(|d| !matches!(d.bus_type(), hidapi::BusType::Bluetooth))
            .collect();

        // Sort candidates so true FIDO usage page (0xF1D0) or interface 0 come first
        candidates.sort_by_key(|d| {
            if d.usage_page() == FIDO_USAGE_PAGE {
                0
            } else if d.interface_number() == 0 {
                1
            } else if d.usage_page() != 0x0001 {
                2
            } else {
                3
            }
        });

        for candidate in candidates {
            if let Ok(device) = api.open_path(candidate.path()) {
                let mut client = Self {
                    device,
                    channel_id: ChannelId::BROADCAST,
                };

                // Handshake via CTAPHID_INIT: verifies device speaks CTAPHID protocol
                if client.init_channel().is_ok() {
                    return Some(client);
                }
            }
        }

        None
    }

    pub fn init_channel(&mut self) -> Result<(), UsbError> {
        let mut nonce = [0u8; 8];
        for (i, b) in nonce.iter_mut().enumerate() {
            *b = (0x42 + i * 7) as u8;
        }

        let mut pkt = [0u8; PACKET_SIZE];
        pkt[..4].copy_from_slice(&ChannelId::BROADCAST.to_bytes());
        pkt[4] = 0x86; // CTAPHID_INIT
        pkt[5] = 0x00; // BCNT high
        pkt[6] = 0x08; // BCNT low
        pkt[7..15].copy_from_slice(&nonce);

        self.write_packet(&pkt)?;
        let resp = match self.read_slice(Duration::from_millis(100))? {
            Some(r) => r,
            None => {
                return Err(UsbError::Handshake(
                    "timeout waiting for CTAPHID_INIT".into(),
                ))
            }
        };
        if resp.len() < 19 || resp[4] != 0x86 || resp[7..15] != nonce {
            return Err(UsbError::Handshake("invalid CTAPHID_INIT response".into()));
        }

        let mut cid = [0u8; 4];
        cid.copy_from_slice(&resp[15..19]);
        self.channel_id = ChannelId::from_bytes(cid);
        Ok(())
    }

    fn write_packet(&self, pkt: &[u8; PACKET_SIZE]) -> Result<(), UsbError> {
        let mut buf = [0u8; PACKET_SIZE + 1];
        buf[0] = 0x00;
        buf[1..].copy_from_slice(pkt);
        self.device.write(&buf).map_err(UsbError::Io)?;
        Ok(())
    }

    fn read_slice(&self, timeout: Duration) -> Result<Option<[u8; PACKET_SIZE]>, UsbError> {
        let mut buf = [0u8; PACKET_SIZE];
        let timeout_ms = timeout.as_millis().max(1) as i32;
        match self.device.read_timeout(&mut buf, timeout_ms) {
            Ok(n) if n == PACKET_SIZE => Ok(Some(buf)),
            Ok(0) => Ok(None),
            Ok(n) => Err(UsbError::Protocol(format!(
                "unexpected USB packet length: {n}"
            ))),
            Err(e) => Err(UsbError::Io(e)),
        }
    }

    pub fn transact_raw(
        &mut self,
        cmd: u8,
        payload: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, UsbError> {
        if payload.len() > 7609 {
            return Err(UsbError::PayloadTooLarge);
        }

        // Init packet
        let mut pkt = [0u8; PACKET_SIZE];
        pkt[..4].copy_from_slice(&self.channel_id.to_bytes());
        pkt[4] = cmd | 0x80;
        pkt[5] = ((payload.len() >> 8) & 0xFF) as u8;
        pkt[6] = (payload.len() & 0xFF) as u8;
        let take = payload.len().min(PACKET_SIZE - 7);
        pkt[7..7 + take].copy_from_slice(&payload[..take]);
        self.write_packet(&pkt)?;

        // Continuation packets
        let mut remaining = &payload[take..];
        let mut seq = 0u8;
        while !remaining.is_empty() {
            let mut cont_pkt = [0u8; PACKET_SIZE];
            cont_pkt[..4].copy_from_slice(&self.channel_id.to_bytes());
            cont_pkt[4] = seq & 0x7F;
            seq += 1;
            let c_take = remaining.len().min(PACKET_SIZE - 5);
            cont_pkt[5..5 + c_take].copy_from_slice(&remaining[..c_take]);
            remaining = &remaining[c_take..];
            self.write_packet(&cont_pkt)?;
        }

        // Response assembly
        let deadline = Instant::now() + timeout;
        let mut total_len: Option<usize> = None;
        let mut out = Vec::new();

        while Instant::now() < deadline {
            let remaining_time = deadline.saturating_duration_since(Instant::now());
            let slice = remaining_time.min(Duration::from_millis(500));
            let raw = match self.read_slice(slice)? {
                Some(buf) => buf,
                None => continue,
            };

            let cid = ChannelId::from_bytes([raw[0], raw[1], raw[2], raw[3]]);
            if cid != self.channel_id && cid != ChannelId::BROADCAST {
                continue;
            }

            let rcmd = raw[4];
            let opcode = rcmd & 0x7F;

            // 0x3B = CTAPHID_KEEPALIVE
            if opcode == 0x3B {
                continue;
            }
            // 0x3F = CTAPHID_ERROR
            if opcode == 0x3F {
                let err = raw.get(7).copied().unwrap_or(0);
                return Err(UsbError::DeviceError(err));
            }

            if let Some(total) = total_len {
                if rcmd & 0x80 != 0 {
                    continue;
                }
                let needed = total.saturating_sub(out.len());
                let chunk_len = needed.min(PACKET_SIZE - 5);
                out.extend_from_slice(&raw[5..5 + chunk_len]);
            } else {
                if opcode != (cmd & 0x7F) {
                    continue;
                }
                let len = ((raw[5] as usize) << 8) | (raw[6] as usize);
                total_len = Some(len);
                let chunk_len = len.min(PACKET_SIZE - 7);
                out.extend_from_slice(&raw[7..7 + chunk_len]);
            }

            if let Some(total) = total_len {
                if out.len() >= total {
                    out.truncate(total);
                    return Ok(out);
                }
            }
        }

        Err(UsbError::Timeout)
    }

    pub fn transact(
        &mut self,
        request: &ctap::Request,
        timeout: Duration,
    ) -> Result<ctap::Response, UsbError> {
        let response = self.transact_preserving_status(request, timeout)?;
        if !response.status.is_ok() {
            return Err(UsbError::Ctap {
                status: response.status,
                code: response.status.as_u8(),
            });
        }
        Ok(response)
    }

    /// Same as [`Self::transact`], but a non-OK CTAP status is returned as
    /// `Ok` rather than collapsed into `Err(UsbError::Ctap)`, which would
    /// throw the status byte away as a mere message. See the identical note
    /// on `DaemonClient::transact_preserving_status`
    /// (`crates/webauthn-host/src/daemon.rs`) for why credential management
    /// needs this and `create`/`get`/`totp_code` do not.
    pub fn transact_preserving_status(
        &mut self,
        request: &ctap::Request,
        timeout: Duration,
    ) -> Result<ctap::Response, UsbError> {
        let payload = request.encode();
        let body = self.transact_raw(0x10, &payload, timeout)?;
        if body.is_empty() {
            return Err(UsbError::Protocol("empty CTAP response".into()));
        }
        let status = ctap::StatusCode(body[0]);
        Ok(ctap::Response::new(status, body[1..].to_vec()))
    }

    pub fn oath_list(&mut self, timeout: Duration) -> Result<Vec<String>, UsbError> {
        // INS_LIST = 0xA1
        let apdu = [0x00, 0xA1, 0x00, 0x00, 0x00];
        let resp = self.transact_raw(0x63, &apdu, timeout)?;
        if resp.len() < 2 {
            return Err(UsbError::Protocol("short OATH response".into()));
        }
        let sw = u16::from_be_bytes([resp[resp.len() - 2], resp[resp.len() - 1]]);
        if sw != 0x9000 {
            return Err(UsbError::Protocol(format!(
                "OATH LIST returned error {sw:#06x}"
            )));
        }

        let mut names = Vec::new();
        let mut i = 0;
        let data = &resp[..resp.len() - 2];
        while i + 2 <= data.len() {
            let tag = data[i];
            let len = data[i + 1] as usize;
            i += 2;
            if i + len > data.len() {
                break;
            }
            if tag == 0x71 && len > 1 {
                // First byte is algo (0x21), remainder is name string
                if let Ok(name) = std::str::from_utf8(&data[i + 1..i + len]) {
                    names.push(name.to_string());
                }
            }
            i += len;
        }
        Ok(names)
    }

    pub fn oath_calculate(
        &mut self,
        name: &str,
        counter: u64,
        timeout: Duration,
    ) -> Result<String, UsbError> {
        // INS_CALCULATE = 0xA2
        let name_bytes = name.as_bytes();
        let chal_bytes = counter.to_be_bytes();
        let mut data = Vec::with_capacity(2 + name_bytes.len() + 2 + 8);
        // TAG_NAME = 0x71
        data.push(0x71);
        data.push(name_bytes.len() as u8);
        data.extend_from_slice(name_bytes);
        // TAG_CHALLENGE = 0x74
        data.push(0x74);
        data.push(8);
        data.extend_from_slice(&chal_bytes);

        let mut apdu = vec![0x00, 0xA2, 0x00, 0x00, data.len() as u8];
        apdu.extend_from_slice(&data);

        let resp = self.transact_raw(0x63, &apdu, timeout)?;
        if resp.len() < 2 {
            return Err(UsbError::Protocol("short OATH response".into()));
        }
        let sw = u16::from_be_bytes([resp[resp.len() - 2], resp[resp.len() - 1]]);
        if sw != 0x9000 {
            if sw == 0x6985 {
                return Err(UsbError::Protocol(
                    "user verification failed or timed out (touch sensor)".into(),
                ));
            }
            if sw == 0x6A82 {
                return Err(UsbError::Protocol("account not found on token".into()));
            }
            return Err(UsbError::Protocol(format!(
                "OATH CALCULATE returned {sw:#06x}"
            )));
        }

        // Response format: TAG_RESPONSE (0x75) | len (5) | digits (6) | code_be (4) | 90 00
        let data = &resp[..resp.len() - 2];
        if data.len() >= 7 && data[0] == 0x75 && data[1] == 5 {
            let code_num = u32::from_be_bytes([data[3], data[4], data[5], data[6]]);
            return Ok(format!("{:06}", code_num));
        }

        Err(UsbError::Protocol(
            "invalid OATH CALCULATE response format".into(),
        ))
    }

    /// Enrolls a new TOTP account (`INS 0x01` / `OATH_INS_PUT`).
    ///
    /// `secret` is the raw, already-decoded seed -- base32 decoding is the
    /// caller's job, same layering `oath_calculate` already has for its own
    /// challenge bytes. Verified directly against this device's firmware
    /// (`src/host/cryptick_oath_hid.cpp`'s `OATH_INS_PUT` handler), not
    /// against the OATH_SPEC.md doc this disagreed with before being
    /// checked on real hardware:
    ///
    /// - The key TLV's value is `[type_algo][digits][secret bytes...]` --
    ///   three leading structural bytes, not one. `type_algo` must satisfy
    ///   `& 0x0F == 0x01` (SHA1) and `& 0xF0 == 0x20` (TOTP): `0x21` is the
    ///   only accepted value, so it is hardcoded here rather than exposed
    ///   as a parameter nothing can meaningfully vary. `digits` must be
    ///   exactly `6`; anything else is `SW_CONDITIONS` (0x6985).
    /// - The secret itself has no documented minimum -- the firmware only
    ///   rejects empty (0) or over `OATH_MAX_SECRET` (64) bytes.
    /// - There is no per-account UV/touch-required flag at enrollment: the
    ///   firmware's `OATH_INS_PUT` handler never reads a TAG_PROPERTY at
    ///   all. UV gating is the global `CRYPTICK_OATH_REQUIRE_FP` policy
    ///   (SECURITY_ROADMAP.md) -- on whenever any fingerprint is enrolled,
    ///   for every account alike -- not something a caller can set per
    ///   account, so this function takes no such parameter either.
    pub fn oath_enroll(
        &mut self,
        name: &str,
        secret: &[u8],
        timeout: Duration,
    ) -> Result<(), UsbError> {
        let name_bytes = name.as_bytes();
        if name_bytes.is_empty() || name_bytes.len() > 64 {
            return Err(UsbError::Protocol("account name must be 1-64 bytes".into()));
        }
        if secret.is_empty() || secret.len() > 64 {
            return Err(UsbError::Protocol(
                "secret seed must be 1-64 bytes once decoded".into(),
            ));
        }

        let mut data = Vec::with_capacity(2 + name_bytes.len() + 2 + 2 + secret.len());
        // TAG_NAME = 0x71
        data.push(0x71);
        data.push(name_bytes.len() as u8);
        data.extend_from_slice(name_bytes);
        // TAG_KEY = 0x73: type_algo (TOTP|SHA1 = 0x21), digits (6), seed.
        data.push(0x73);
        data.push((2 + secret.len()) as u8);
        data.push(0x21);
        data.push(6);
        data.extend_from_slice(secret);

        let mut apdu = vec![0x00, 0x01, 0x00, 0x00, data.len() as u8];
        apdu.extend_from_slice(&data);

        let resp = self.transact_raw(0x63, &apdu, timeout)?;
        if resp.len() < 2 {
            return Err(UsbError::Protocol("short OATH response".into()));
        }
        let sw = u16::from_be_bytes([resp[resp.len() - 2], resp[resp.len() - 1]]);
        if sw != 0x9000 {
            if sw == 0x6A84 {
                return Err(UsbError::Protocol("no space for another account".into()));
            }
            return Err(UsbError::Protocol(format!(
                "OATH ENROLL returned error {sw:#06x}"
            )));
        }
        Ok(())
    }

    /// Deletes an account (`INS 0x02` / `OATH_INS_DELETE`): just TAG_NAME,
    /// no key material -- the firmware's handler takes nothing else.
    pub fn oath_delete(&mut self, name: &str, timeout: Duration) -> Result<(), UsbError> {
        let name_bytes = name.as_bytes();
        if name_bytes.is_empty() || name_bytes.len() > 64 {
            return Err(UsbError::Protocol("account name must be 1-64 bytes".into()));
        }
        let mut data = vec![0x71, name_bytes.len() as u8];
        data.extend_from_slice(name_bytes);

        let mut apdu = vec![0x00, 0x02, 0x00, 0x00, data.len() as u8];
        apdu.extend_from_slice(&data);

        let resp = self.transact_raw(0x63, &apdu, timeout)?;
        if resp.len() < 2 {
            return Err(UsbError::Protocol("short OATH response".into()));
        }
        let sw = u16::from_be_bytes([resp[resp.len() - 2], resp[resp.len() - 1]]);
        if sw != 0x9000 {
            if sw == 0x6A82 {
                return Err(UsbError::Protocol("account not found on token".into()));
            }
            return Err(UsbError::Protocol(format!(
                "OATH DELETE returned error {sw:#06x}"
            )));
        }
        Ok(())
    }

    pub fn oath_set_time(&mut self, utc_secs: u64, timeout: Duration) -> Result<(), UsbError> {
        let ts = (utc_secs as u32).to_be_bytes();
        let mut apdu = vec![0x00, 0x04, 0x00, 0x00, 0x04];
        apdu.extend_from_slice(&ts);

        let resp = self.transact_raw(0x63, &apdu, timeout)?;
        if resp.len() < 2 {
            return Err(UsbError::Protocol("short OATH response".into()));
        }
        let sw = u16::from_be_bytes([resp[resp.len() - 2], resp[resp.len() - 1]]);
        if sw != 0x9000 {
            return Err(UsbError::Protocol(format!(
                "OATH SET_TIME returned error {sw:#06x}"
            )));
        }
        Ok(())
    }
}
