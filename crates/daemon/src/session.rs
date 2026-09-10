//! One CTAP transaction, end to end, over a fragment transport.

use crate::{
    cancel::CancelToken,
    error::DaemonError,
    transport::{FragmentTransport, LinkState},
};
use ble_framing::{fragments, BleErrorCode, Command, KeepAliveStatus, Message, Reassembler};
use ipc::KeepaliveReason;
use std::time::Duration;
use tokio::{sync::mpsc, time::Instant};

/// Where keepalives are forwarded to.
pub type KeepaliveSink = mpsc::UnboundedSender<KeepaliveReason>;

/// Runs CTAP transactions over one transport.
///
/// Holds no key material and caches nothing between transactions
/// (PROJECT.md §15.1).
#[derive(Debug)]
pub struct Session<T> {
    transport: T,
    max_message_len: usize,
}

impl<T: FragmentTransport> Session<T> {
    /// Wraps a transport.
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            max_message_len: ble_framing::MAX_PAYLOAD_LEN,
        }
    }

    /// Refuses any response declaring more than `max` bytes.
    ///
    /// Worth tightening to the device's real ceiling once it is known — the
    /// firmware's `CTAP_MAX_MESSAGE_SIZE` is 1200 — so an over-large declaration
    /// is rejected at the first fragment instead of being buffered. Left wide by
    /// default because the value is still an open `[HW]` item (PROJECT.md §17).
    pub fn with_max_message_len(mut self, max: usize) -> Self {
        self.max_message_len = max;
        self
    }

    /// The current link state.
    pub fn link(&self) -> LinkState {
        self.transport.link()
    }

    /// Sends a CTAP request and waits for the response.
    ///
    /// Keepalives are forwarded to `keepalives` as they arrive and are never
    /// swallowed; a `Up` keepalive is the device asking for a physical touch,
    /// which only the user can satisfy (PROJECT.md §15.3).
    ///
    /// The timeout is an absolute deadline from entry. Keepalives do **not**
    /// extend it: a device that keeps saying "still working" must not be able to
    /// hold a transaction open indefinitely.
    pub async fn transact(
        &mut self,
        request: &ctap::Request,
        timeout: Duration,
        keepalives: &KeepaliveSink,
        cancel: &mut CancelToken,
    ) -> Result<ctap::Response, DaemonError> {
        // Fail closed before anything touches the wire (PROJECT.md §15.2, §15.8).
        let link = self.transport.link();
        if !link.connected {
            return Err(DaemonError::NotConnected);
        }
        if !link.is_usable() {
            return Err(DaemonError::NotBonded);
        }
        if cancel.is_cancelled() {
            return Err(DaemonError::Cancelled);
        }

        let deadline = Instant::now() + timeout;
        let size = self.transport.fragment_size().await?;

        let outbound = Message::new(Command::Msg, request.encode());
        for fragment in fragments(&outbound, size)? {
            self.transport.write_fragment(&fragment).await?;
        }

        let mut rx = Reassembler::with_max_message_len(self.max_message_len);

        loop {
            let notification = tokio::select! {
                biased;

                _ = cancel.cancelled() => {
                    self.send_cancel(size).await;
                    return Err(DaemonError::Cancelled);
                }
                _ = tokio::time::sleep_until(deadline) => {
                    self.send_cancel(size).await;
                    return Err(DaemonError::Timeout);
                }
                result = self.transport.next_notification() => result?,
            };

            let Some(message) = rx.push(&notification)? else {
                continue;
            };

            match message.command {
                Command::KeepAlive => {
                    let &byte = message
                        .payload
                        .first()
                        .ok_or(DaemonError::UnexpectedResponse {
                            expected: "a keepalive status byte",
                            got: "an empty keepalive",
                        })?;
                    let reason = match KeepAliveStatus::from_u8(byte)? {
                        KeepAliveStatus::Processing => KeepaliveReason::Processing,
                        KeepAliveStatus::UpNeeded => KeepaliveReason::Up,
                    };
                    // If nobody is listening, the user will never be told to
                    // touch the sensor, so the transaction cannot succeed and
                    // must not be left hanging.
                    if keepalives.send(reason).is_err() {
                        self.send_cancel(size).await;
                        return Err(DaemonError::Cancelled);
                    }
                }

                Command::Msg => return Ok(ctap::Response::decode(&message.payload)?),

                Command::Error => {
                    // The spec calls this "a variable-length, big-endian
                    // integer", not a byte, so a zero-padded code still parses.
                    let code = BleErrorCode::from_payload(&message.payload);
                    return Err(DaemonError::DeviceError(code));
                }

                Command::Ping => {
                    return Err(DaemonError::UnexpectedResponse {
                        expected: "MSG",
                        got: "PING",
                    })
                }
                Command::Cancel => {
                    return Err(DaemonError::UnexpectedResponse {
                        expected: "MSG",
                        got: "CANCEL",
                    })
                }
            }
        }
    }

    /// Tells the device to abandon the transaction. Best effort.
    ///
    /// Deliberately swallows its own failure: the caller is already returning a
    /// timeout or a cancellation, and replacing that with a transport error
    /// would hide why the transaction actually ended.
    async fn send_cancel(&mut self, size: ble_framing::FragmentSize) {
        let message = Message::new(Command::Cancel, Vec::new());
        let Ok(frags) = fragments(&message, size) else {
            return;
        };
        for fragment in frags {
            if self.transport.write_fragment(&fragment).await.is_err() {
                return;
            }
        }
    }
}
