use ctaphid::{ChannelId, PACKET_SIZE};
use hidapi::{HidApi, HidDevice};
use std::time::{Duration, Instant};

const CRYPTICK_VID: u16 = 0x1209;
const CRYPTICK_PID: u16 = 0xBEEE;
const FIDO_USAGE_PAGE: u16 = 0xF1D0;

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

    pub fn init_channel(&mut self) -> Result<(), String> {
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
            None => return Err("Timeout waiting for CTAPHID_INIT".into()),
        };
        if resp.len() < 19 || resp[4] != 0x86 || resp[7..15] != nonce {
            return Err("Invalid CTAPHID_INIT response".into());
        }

        let mut cid = [0u8; 4];
        cid.copy_from_slice(&resp[15..19]);
        self.channel_id = ChannelId::from_bytes(cid);
        Ok(())
    }

    fn write_packet(&self, pkt: &[u8; PACKET_SIZE]) -> Result<(), String> {
        let mut buf = [0u8; PACKET_SIZE + 1];
        buf[0] = 0x00;
        buf[1..].copy_from_slice(pkt);
        self.device
            .write(&buf)
            .map_err(|e| format!("USB write failed: {e}"))?;
        Ok(())
    }

    fn read_slice(&self, timeout: Duration) -> Result<Option<[u8; PACKET_SIZE]>, String> {
        let mut buf = [0u8; PACKET_SIZE];
        let timeout_ms = timeout.as_millis().max(1) as i32;
        match self.device.read_timeout(&mut buf, timeout_ms) {
            Ok(n) if n == PACKET_SIZE => Ok(Some(buf)),
            Ok(0) => Ok(None),
            Ok(n) => Err(format!("Unexpected USB packet length: {n}")),
            Err(e) => Err(format!("USB read error: {e}")),
        }
    }

    pub fn transact_raw(
        &mut self,
        cmd: u8,
        payload: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, String> {
        if payload.len() > 7609 {
            return Err("Payload too large".into());
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
                return Err(format!("Device reported CTAPHID error {:#04x}", err));
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

        Err("Device read timed out".into())
    }

    pub fn transact(
        &mut self,
        request: &ctap::Request,
        timeout: Duration,
    ) -> Result<ctap::Response, String> {
        let response = self.transact_preserving_status(request, timeout)?;
        if !response.status.is_ok() {
            return Err(format!(
                "CTAP error {:?} ({:#x})",
                response.status,
                response.status.as_u8()
            ));
        }
        Ok(response)
    }

    /// Same as [`Self::transact`], but a non-OK CTAP status is returned as
    /// `Ok` rather than collapsed into a formatted `Err(String)` that throws
    /// the status byte away. See the identical note on
    /// `DaemonClient::transact_preserving_status` (`crates/webauthn-host/src/daemon.rs`)
    /// for why credential management needs this and `create`/`get`/`totp_code`
    /// do not.
    pub fn transact_preserving_status(
        &mut self,
        request: &ctap::Request,
        timeout: Duration,
    ) -> Result<ctap::Response, String> {
        let payload = request.encode();
        let body = self.transact_raw(0x10, &payload, timeout)?;
        if body.is_empty() {
            return Err("Empty CTAP response".into());
        }
        let status = ctap::StatusCode(body[0]);
        Ok(ctap::Response::new(status, body[1..].to_vec()))
    }

    pub fn oath_list(&mut self, timeout: Duration) -> Result<Vec<String>, String> {
        // INS_LIST = 0xA1
        let apdu = [0x00, 0xA1, 0x00, 0x00, 0x00];
        let resp = self.transact_raw(0x63, &apdu, timeout)?;
        if resp.len() < 2 {
            return Err("Short OATH response".into());
        }
        let sw = u16::from_be_bytes([resp[resp.len() - 2], resp[resp.len() - 1]]);
        if sw != 0x9000 {
            return Err(format!("OATH LIST returned error {sw:#06x}"));
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
    ) -> Result<String, String> {
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
            return Err("Short OATH response".into());
        }
        let sw = u16::from_be_bytes([resp[resp.len() - 2], resp[resp.len() - 1]]);
        if sw != 0x9000 {
            if sw == 0x6985 {
                return Err("User verification failed or timed out (touch sensor)".into());
            }
            if sw == 0x6A82 {
                return Err("Account not found on token".into());
            }
            return Err(format!("OATH CALCULATE returned {sw:#06x}"));
        }

        // Response format: TAG_RESPONSE (0x75) | len (5) | digits (6) | code_be (4) | 90 00
        let data = &resp[..resp.len() - 2];
        if data.len() >= 7 && data[0] == 0x75 && data[1] == 5 {
            let code_num = u32::from_be_bytes([data[3], data[4], data[5], data[6]]);
            return Ok(format!("{:06}", code_num));
        }

        Err("Invalid OATH CALCULATE response format".into())
    }

    pub fn oath_set_time(&mut self, utc_secs: u64, timeout: Duration) -> Result<(), String> {
        let ts = (utc_secs as u32).to_be_bytes();
        let mut apdu = vec![0x00, 0x04, 0x00, 0x00, 0x04];
        apdu.extend_from_slice(&ts);

        let resp = self.transact_raw(0x63, &apdu, timeout)?;
        if resp.len() < 2 {
            return Err("Short OATH response".into());
        }
        let sw = u16::from_be_bytes([resp[resp.len() - 2], resp[resp.len() - 1]]);
        if sw != 0x9000 {
            return Err(format!("OATH SET_TIME returned error {sw:#06x}"));
        }
        Ok(())
    }
}
