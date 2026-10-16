//! Direct USB CTAPHID client for the Cryptick token.
//!
//! When the token is plugged in via USB, OpenSSH security key operations
//! should communicate directly over USB HID rather than going through BLE.
//! If USB is absent or unplugged, the caller falls back to the BLE daemon bridge.

use ctaphid::{ChannelId, Cmd, Message, PACKET_SIZE};
use hidapi::{HidApi, HidDevice};
use std::time::{Duration, Instant};

const CRYPTICK_VID: u16 = 0x1209;
const CRYPTICK_PID: u16 = 0xBEEE;
const FIDO_USAGE_PAGE: u16 = 0xF1D0;

/// A direct USB HID connection to the token.
pub struct UsbClient {
    device: HidDevice,
    channel_id: ChannelId,
}

impl UsbClient {
    /// Attempts to locate and connect to a Cryptick Token on USB.
    pub fn try_connect() -> Option<Self> {
        let api = HidApi::new().ok()?;
        let mut candidates: Vec<_> = api
            .device_list()
            .filter(|d| d.vendor_id() == CRYPTICK_VID && d.product_id() == CRYPTICK_PID)
            .filter(|d| !matches!(d.bus_type(), hidapi::BusType::Bluetooth))
            .collect();

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

                if client.init_channel().is_ok() {
                    return Some(client);
                }
            }
        }

        None
    }

    /// Negotiates a dedicated CTAPHID channel via CTAPHID_INIT.
    fn init_channel(&mut self) -> Result<(), i32> {
        let mut nonce = [0u8; 8];
        for (i, b) in nonce.iter_mut().enumerate() {
            *b = (0x42 + i * 7) as u8;
        }

        let mut pkt = [0u8; PACKET_SIZE];
        pkt[..4].copy_from_slice(&ChannelId::BROADCAST.to_bytes());
        pkt[4] = 0x86; // CTAPHID_INIT
        pkt[5] = 0x00; // BCNT high
        pkt[6] = 0x08; // BCNT low (8 bytes nonce)
        pkt[7..15].copy_from_slice(&nonce);

        let resp = match self.read_slice(Duration::from_millis(100))? {
            Some(r) => r,
            None => return Err(crate::SSH_SK_ERR_DEVICE_NOT_FOUND),
        };
        if resp.len() < 19 || resp[4] != 0x86 || resp[7..15] != nonce {
            return Err(crate::SSH_SK_ERR_GENERAL);
        }

        let mut cid = [0u8; 4];
        cid.copy_from_slice(&resp[15..19]);
        self.channel_id = ChannelId::from_bytes(cid);
        Ok(())
    }

    fn write_packet(&self, pkt: &[u8; PACKET_SIZE]) -> Result<(), i32> {
        // hidapi on macOS/Windows expects a 0x00 report-id prefix byte
        let mut buf = [0u8; PACKET_SIZE + 1];
        buf[0] = 0x00;
        buf[1..].copy_from_slice(pkt);
        self.device
            .write(&buf)
            .map_err(|_| crate::SSH_SK_ERR_GENERAL)?;
        Ok(())
    }

    fn read_slice(&self, timeout: Duration) -> Result<Option<[u8; PACKET_SIZE]>, i32> {
        let mut buf = [0u8; PACKET_SIZE];
        let timeout_ms = timeout.as_millis().max(1) as i32;
        match self.device.read_timeout(&mut buf, timeout_ms) {
            Ok(n) if n == PACKET_SIZE => Ok(Some(buf)),
            Ok(0) => Ok(None),
            Ok(_) => Err(crate::SSH_SK_ERR_GENERAL),
            Err(_) => Err(crate::SSH_SK_ERR_GENERAL),
        }
    }

    /// Transacts a CTAP request directly over USB HID.
    pub fn transact(
        &mut self,
        request: &ctap::Request,
        timeout: Duration,
    ) -> Result<ctap::Response, i32> {
        let cbor = request.encode();
        let msg = Message::new(self.channel_id, Cmd::Cbor, cbor);
        let packets = msg.packets().map_err(|_| crate::SSH_SK_ERR_GENERAL)?;

        for pkt in packets {
            self.write_packet(pkt.as_bytes())?;
        }

        let mut assembler = ctaphid::Assembler::new();
        let deadline = Instant::now() + timeout;

        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let slice = remaining.min(Duration::from_millis(500));
            let raw = match self.read_slice(slice)? {
                Some(buf) => buf,
                None => continue,
            };

            let pkt = match ctaphid::Packet::parse(&raw) {
                Ok(p) => p,
                Err(_) => continue,
            };

            if pkt.channel() != self.channel_id {
                continue;
            }

            match assembler.push(&pkt) {
                Ok(Some(msg)) => {
                    if msg.command == Cmd::Cbor {
                        let payload = msg.payload;
                        if payload.is_empty() {
                            return Err(crate::SSH_SK_ERR_GENERAL);
                        }
                        let status = ctap::StatusCode(payload[0]);
                        let data = payload[1..].to_vec();
                        return Ok(ctap::Response::new(status, data));
                    } else if msg.command == Cmd::Error {
                        return Err(crate::SSH_SK_ERR_GENERAL);
                    }
                }
                Ok(None) => continue, // Keepalive or partial packet: keep waiting!
                Err(_) => return Err(crate::SSH_SK_ERR_GENERAL),
            }
        }

        Err(crate::SSH_SK_ERR_GENERAL)
    }
}
