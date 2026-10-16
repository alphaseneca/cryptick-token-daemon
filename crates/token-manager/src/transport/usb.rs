//! Direct USB CTAPHID transport implementation for Cryptick Token (`0x1209:0xBEEE`).
//!
//! Directly interacts with the token over raw 64-byte CTAPHID frames via `hidapi`.

use super::TokenTransport;
use ctaphid::{ChannelId, PACKET_SIZE};
use hidapi::{HidApi, HidDevice};
use std::time::{Duration, Instant};

const CRYPTICK_VID: u16 = 0x1209;
const CRYPTICK_PID: u16 = 0xBEEE;
const FIDO_USAGE_PAGE: u16 = 0xF1D0;

/// USB device descriptor summary.
#[derive(Debug, Clone)]
pub struct UsbDeviceInfo {
    /// Serial number string if reported by device.
    pub serial: Option<String>,
    /// Product description string.
    pub product: Option<String>,
    /// Manufacturer string.
    pub manufacturer: Option<String>,
    /// OS path to the device node.
    pub path: String,
}

/// A direct USB HID connection to a Cryptick Token.
pub struct UsbTransport {
    device: HidDevice,
    channel_id: ChannelId,
    serial_number: Option<String>,
}

impl UsbTransport {
    /// Lists all detected Cryptick Token USB devices.
    pub fn list_devices() -> Result<Vec<UsbDeviceInfo>, String> {
        let api = HidApi::new().map_err(|e| format!("Failed to initialize HID subsystem: {e}"))?;
        let mut list = Vec::new();
        for dev in api.device_list() {
            if dev.vendor_id() == CRYPTICK_VID && dev.product_id() == CRYPTICK_PID {
                list.push(UsbDeviceInfo {
                    serial: dev.serial_number().map(str::to_string),
                    product: dev.product_string().map(str::to_string),
                    manufacturer: dev.manufacturer_string().map(str::to_string),
                    path: dev.path().to_string_lossy().to_string(),
                });
            }
        }
        Ok(list)
    }

    /// Attempts to locate and connect to a Cryptick Token on USB.
    pub fn try_connect(device_filter: Option<&str>) -> Result<Option<Self>, String> {
        let api = match HidApi::new() {
            Ok(api) => api,
            Err(_) => return Ok(None),
        };

        let mut candidates: Vec<_> = api
            .device_list()
            .filter(|d| d.vendor_id() == CRYPTICK_VID && d.product_id() == CRYPTICK_PID)
            .filter(|d| !matches!(d.bus_type(), hidapi::BusType::Bluetooth))
            .collect();

        if candidates.is_empty() {
            return Ok(None);
        }

        // Apply device filter if provided (matching serial number or path)
        if let Some(filter) = device_filter {
            candidates.retain(|d| {
                if let Some(sn) = d.serial_number() {
                    if sn.eq_ignore_ascii_case(filter) {
                        return true;
                    }
                }
                d.path().to_string_lossy().contains(filter)
            });
            if candidates.is_empty() {
                return Ok(None);
            }
        }

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
            let serial = candidate.serial_number().map(str::to_string);
            if let Ok(device) = api.open_path(candidate.path()) {
                let mut transport = Self {
                    device,
                    channel_id: ChannelId::BROADCAST,
                    serial_number: serial,
                };

                if transport.init_channel().is_ok() {
                    return Ok(Some(transport));
                }
            }
        }

        Ok(None)
    }

    /// Negotiates a dedicated CTAPHID channel via `CTAPHID_INIT` (0x86).
    pub fn init_channel(&mut self) -> Result<(), String> {
        let mut nonce = [0u8; 8];
        for (i, b) in nonce.iter_mut().enumerate() {
            *b = (0x59 + i * 11) as u8;
        }

        let mut pkt = [0u8; PACKET_SIZE];
        pkt[..4].copy_from_slice(&ChannelId::BROADCAST.to_bytes());
        pkt[4] = 0x86; // CTAPHID_INIT
        pkt[5] = 0x00; // BCNT high
        pkt[6] = 0x08; // BCNT low
        pkt[7..15].copy_from_slice(&nonce);

        self.write_packet(&pkt)?;
        let resp = match self.read_slice(Duration::from_millis(250))? {
            Some(r) => r,
            None => return Err("Timeout waiting for CTAPHID_INIT response from USB token".into()),
        };

        if resp.len() < 19 || resp[4] != 0x86 || &resp[7..15] != &nonce {
            return Err("Invalid CTAPHID_INIT response from token".into());
        }

        let mut cid = [0u8; 4];
        cid.copy_from_slice(&resp[15..19]);
        self.channel_id = ChannelId::from_bytes(cid);
        Ok(())
    }

    fn write_packet(&self, pkt: &[u8; PACKET_SIZE]) -> Result<(), String> {
        // macOS and Windows HID drivers expect a report ID byte (0x00) prefix
        let mut buf = [0u8; PACKET_SIZE + 1];
        buf[0] = 0x00;
        buf[1..].copy_from_slice(pkt);
        self.device
            .write(&buf)
            .map_err(|e| format!("USB HID packet write failed: {e}"))?;
        Ok(())
    }

    fn read_slice(&self, timeout: Duration) -> Result<Option<[u8; PACKET_SIZE]>, String> {
        let mut buf = [0u8; PACKET_SIZE];
        let timeout_ms = timeout.as_millis().max(1) as i32;
        match self.device.read_timeout(&mut buf, timeout_ms) {
            Ok(n) if n == PACKET_SIZE => Ok(Some(buf)),
            Ok(0) => Ok(None),
            Ok(n) => Err(format!(
                "Unexpected USB packet length: {n} (expected {PACKET_SIZE})"
            )),
            Err(e) => Err(format!("USB packet read error: {e}")),
        }
    }
}

impl TokenTransport for UsbTransport {
    fn transceive(
        &mut self,
        cmd: u8,
        payload: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, String> {
        if payload.len() > 7609 {
            return Err("Payload exceeds maximum CTAPHID sequence capacity (7609 bytes)".into());
        }

        // 1. Send Initialization Packet
        let mut pkt = [0u8; PACKET_SIZE];
        pkt[..4].copy_from_slice(&self.channel_id.to_bytes());
        pkt[4] = cmd | 0x80;
        pkt[5] = ((payload.len() >> 8) & 0xFF) as u8;
        pkt[6] = (payload.len() & 0xFF) as u8;
        let take = payload.len().min(PACKET_SIZE - 7);
        pkt[7..7 + take].copy_from_slice(&payload[..take]);
        self.write_packet(&pkt)?;

        // 2. Send Continuation Packets
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

        // 3. Receive and Assemble Response
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

            // 0x3B = CTAPHID_KEEPALIVE (Hardware is processing or awaiting biometric touch)
            if opcode == 0x3B {
                continue;
            }

            // 0x3F = CTAPHID_ERROR
            if opcode == 0x3F {
                let err_code = raw.get(7).copied().unwrap_or(0);
                return Err(format!(
                    "Device reported CTAPHID protocol error {err_code:#04X}"
                ));
            }

            if total_len.is_none() {
                // Must be an initialization packet (high bit set) matching command opcode
                if (rcmd & 0x80 == 0) || (opcode != (cmd & 0x7F)) {
                    continue;
                }
                let len = ((raw[5] as usize) << 8) | (raw[6] as usize);
                total_len = Some(len);
                let chunk_len = len.min(PACKET_SIZE - 7);
                out.extend_from_slice(&raw[7..7 + chunk_len]);
            } else {
                // Continuation packet (high bit clear)
                if rcmd & 0x80 != 0 {
                    continue;
                }
                let needed = total_len.unwrap().saturating_sub(out.len());
                let chunk_len = needed.min(PACKET_SIZE - 5);
                out.extend_from_slice(&raw[5..5 + chunk_len]);
            }

            if let Some(total) = total_len {
                if out.len() >= total {
                    out.truncate(total);
                    return Ok(out);
                }
            }
        }

        Err("Device read timed out waiting for complete response".into())
    }

    fn transport_name(&self) -> &'static str {
        "Direct USB CTAPHID"
    }

    fn serial(&self) -> Option<String> {
        self.serial_number.clone()
    }
}
