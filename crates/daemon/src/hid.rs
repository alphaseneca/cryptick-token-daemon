//! The CTAPHID side of the bridge: OS-facing envelope in, BLE envelope out.
//!
//! A virtual HID device makes the browser see an ordinary security key. What
//! arrives on it is CTAPHID; what the token speaks is the CTAP BLE transport.
//! This is where the two meet, and it is the same code for all three virtual
//! HID adapters — Linux `uhid`, macOS CoreHID, Windows USB/IP — because only
//! the device node differs, never the protocol (PROJECT.md §9).
//!
//! # What is handled here rather than relayed
//!
//! Channels do not exist on the BLE side at all, so `CTAPHID_INIT` is answered
//! locally: the daemon allocates the channel and the token never hears about
//! it. `PING` is likewise answered here. Only `CBOR` payloads cross to the
//! device, and they cross untouched.

use crate::{
    bridge::Bridge,
    cancel::{cancel_pair, CancelHandle},
    error::DaemonError,
    transport::FragmentTransport,
};
use ctaphid::{
    Assembler, ChannelAllocator, ChannelId, Cmd, ErrorCode, KeepaliveStatus, Message, Packet,
    CAPABILITY_CBOR, CAPABILITY_WINK,
};
use ipc::KeepaliveReason;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::mpsc;

/// Where outbound packets go — in production, the writer half of the device
/// node.
pub type PacketSink = mpsc::UnboundedSender<Packet>;

/// How long a CTAPHID transaction may run.
///
/// The host has its own timeout; this exists so a wedged device cannot hold a
/// channel open forever.
pub const TRANSACTION_TIMEOUT: Duration = Duration::from_secs(120);

/// The nonce in a `CTAPHID_INIT` request.
const INIT_NONCE_LEN: usize = 8;

fn send(out: &PacketSink, packet: Packet) {
    let _ = out.send(packet);
}

fn send_message(out: &PacketSink, message: &Message) {
    match message.packets() {
        Ok(packets) => {
            for packet in packets {
                send(out, packet);
            }
        }
        // Only reachable if we built a message longer than CTAPHID can carry,
        // which would be our bug, not the host's.
        Err(_) => send(out, Packet::error(message.channel, ErrorCode::Other)),
    }
}

/// Translates CTAPHID on one device node onto one BLE device.
pub struct HidBridge<T> {
    bridge: Arc<Bridge<T>>,
    assembler: Assembler,
    allocator: ChannelAllocator,
    in_flight: Arc<Mutex<HashMap<ChannelId, CancelHandle>>>,
    version: (u8, u8, u8),
}

impl<T: FragmentTransport + Clone + Send + Sync + 'static> HidBridge<T> {
    /// Wraps a bridge, reporting `version` in `CTAPHID_INIT` responses.
    pub fn new(bridge: Arc<Bridge<T>>, version: (u8, u8, u8)) -> Self {
        Self {
            bridge,
            assembler: Assembler::new(),
            allocator: ChannelAllocator::new(),
            in_flight: Arc::new(Mutex::new(HashMap::new())),
            version,
        }
    }

    /// The capabilities reported to the host.
    ///
    /// `CBOR` because CTAP2 is the whole point, and `WINK` to satisfy macOS/Chrome
    /// probes. `NMSG` is omitted so browsers don't refuse the key.
    pub const fn capabilities(&self) -> u8 {
        CAPABILITY_CBOR | CAPABILITY_WINK
    }

    /// Feeds one report from the device node, writing any replies to `out`.
    ///
    /// Returns as soon as the packet is dealt with. A `CBOR` transaction runs
    /// in the background so that later packets — `CTAPHID_CANCEL` above all —
    /// are still processed while the device waits for a fingerprint.
    pub fn handle_packet(&mut self, packet: &Packet, out: &PacketSink) {
        let message = match self.assembler.push(packet) {
            Ok(Some(message)) => message,
            Ok(None) => return,
            Err(err) => {
                send(out, err.packet());
                return;
            }
        };
        self.dispatch(message, out);
    }

    fn dispatch(&mut self, message: Message, out: &PacketSink) {
        let channel = message.channel;

        match message.command {
            Cmd::Init => {
                if message.payload.len() != INIT_NONCE_LEN {
                    send(out, Packet::error(channel, ErrorCode::InvalidLen));
                    return;
                }
                let mut nonce = [0u8; INIT_NONCE_LEN];
                nonce.copy_from_slice(&message.payload);

                // On the broadcast channel the host is asking for a channel; on
                // an assigned one it is resynchronising and keeps the one it
                // has. Either way anything in flight there is abandoned.
                let allocated = if channel == ChannelId::BROADCAST {
                    self.allocator.allocate()
                } else {
                    self.cancel_channel(channel);
                    channel
                };

                send_message(
                    out,
                    &Message::init_response(
                        channel,
                        nonce,
                        allocated,
                        self.version,
                        self.capabilities(),
                    ),
                );
            }

            Cmd::Ping => {
                // Answered here: the token has nothing to do with it.
                send_message(out, &Message::new(channel, Cmd::Ping, message.payload));
            }

            Cmd::Wink => {
                // Answered here with empty payload
                send_message(out, &Message::new(channel, Cmd::Wink, Vec::new()));
            }

            Cmd::Cancel => {
                // No response, per the transport. The pending transaction's own
                // reply carries the cancellation.
                self.assembler.reset(channel);
                self.cancel_channel(channel);
            }

            Cmd::Cbor => self.start_transaction(channel, message.payload, out),

            // MSG and LOCK are refused.
            Cmd::Msg | Cmd::Lock => {
                send(out, Packet::error(channel, ErrorCode::InvalidCmd));
            }

            // The assembler rejects these before they reach here.
            Cmd::Keepalive | Cmd::Error => {
                send(out, Packet::error(channel, ErrorCode::InvalidCmd));
            }
        }
    }

    fn cancel_channel(&self, channel: ChannelId) {
        if let Some(handle) = self
            .in_flight
            .lock()
            .expect("in-flight lock")
            .remove(&channel)
        {
            handle.cancel();
        }
    }

    fn start_transaction(&mut self, channel: ChannelId, payload: Vec<u8>, out: &PacketSink) {
        let request = match ctap::Request::decode(&payload) {
            Ok(request) => request,
            Err(_) => {
                send(out, Packet::error(channel, ErrorCode::InvalidLen));
                return;
            }
        };

        let (handle, mut token) = cancel_pair();
        {
            let mut slots = self.in_flight.lock().expect("in-flight lock");
            if slots.contains_key(&channel) {
                send(out, Packet::error(channel, ErrorCode::ChannelBusy));
                return;
            }
            slots.insert(channel, handle);
        }

        let bridge = Arc::clone(&self.bridge);
        let in_flight = Arc::clone(&self.in_flight);
        let out = out.clone();

        tokio::spawn(async move {
            let (keepalives, mut keepalive_rx) = mpsc::unbounded_channel();

            // Keepalives must reach the host while the device waits, not after.
            // Without them the browser gives up long before a user has found
            // the fingerprint sensor (PROJECT.md §15.3).
            let pump = {
                let out = out.clone();
                tokio::spawn(async move {
                    while let Some(reason) = keepalive_rx.recv().await {
                        let status = match reason {
                            KeepaliveReason::Processing => KeepaliveStatus::Processing,
                            KeepaliveReason::Up => KeepaliveStatus::UpNeeded,
                        };
                        send(&out, Packet::keepalive(channel, status));
                    }
                })
            };

            let result = bridge
                .transact(&request, TRANSACTION_TIMEOUT, &keepalives, &mut token)
                .await;

            drop(keepalives);
            let _ = pump.await;

            match result {
                Ok(response) => {
                    send_message(&out, &Message::new(channel, Cmd::Cbor, response.encode()))
                }

                // A CTAP-level outcome is a CBOR response carrying the status,
                // which is what a real authenticator returns after a cancel.
                Err(DaemonError::Cancelled) => send_message(
                    &out,
                    &Message::new(
                        channel,
                        Cmd::Cbor,
                        ctap::Response::error(ctap::StatusCode::KEEPALIVE_CANCEL).encode(),
                    ),
                ),

                // Transport-level failures belong on the transport's own error
                // channel, not dressed up as an authenticator answer.
                Err(DaemonError::Timeout) => {
                    send(&out, Packet::error(channel, ErrorCode::MsgTimeout))
                }
                Err(DaemonError::Busy) => {
                    send(&out, Packet::error(channel, ErrorCode::ChannelBusy))
                }
                Err(_) => send(&out, Packet::error(channel, ErrorCode::Other)),
            }

            in_flight.lock().expect("in-flight lock").remove(&channel);
        });
    }
}
