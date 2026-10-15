//! CTAP BLE transport framing.
//!
//! The FIDO BLE transport (GATT service `0xFFFD`) carries CTAP messages as a
//! sequence of fragments written to `fidoControlPoint` and notified on
//! `fidoStatus`. This crate turns messages into fragments and fragments back
//! into messages. It is pure: no I/O, no platform APIs, no radio.
//!
//! It is deliberately *not* CTAPHID. CTAPHID is the USB HID transport — 64-byte
//! reports, 4-byte channel IDs, a 7-byte initialization header. The BLE
//! transport has none of that: no channels, a 3-byte initialization header, and
//! a fragment size negotiated per connection. See PROJECT.md §12.
//!
//! # Framing
//!
//! - Initialization fragment: `CMD` (1 byte, high bit set) ‖ `HLEN` (2 bytes,
//!   big-endian, the length of the *whole* payload) ‖ data
//! - Continuation fragment: `SEQ` (1 byte, high bit clear, wrapping
//!   `0x00`..=`0x7f`) ‖ data
//!
//! The fragment size is whatever the authenticator published in
//! `fidoControlPointLength`, between [`MIN_FRAGMENT_SIZE`] and
//! [`MAX_FRAGMENT_SIZE`]. Read it from the characteristic; never assume a value
//! (PROJECT.md §17 keeps the real one open as an `[HW]` item).
//!
//! # Example
//!
//! ```
//! use ble_framing::{fragments, Command, FragmentSize, Message, Reassembler};
//!
//! let size = FragmentSize::new(20)?;
//! let sent = Message::new(Command::Msg, b"a CTAP2 CBOR request".to_vec());
//!
//! let mut rx = Reassembler::new();
//! let mut received = None;
//! for fragment in fragments(&sent, size)? {
//!     received = rx.push(&fragment)?;
//! }
//!
//! assert_eq!(received, Some(sent));
//! # Ok::<(), ble_framing::FramingError>(())
//! ```
//!
//! # Hostile input
//!
//! Reassembly is the least protected surface in the project (PROJECT.md §14):
//! fragments arrive from our own firmware, which may be half-flashed or running
//! a mismatched build, and pre-bond paths are unauthenticated by nature. Every
//! malformed input is rejected with a typed error carrying the
//! [`BleErrorCode`](crate::BleErrorCode) to report on the wire, and **any error
//! aborts the transaction** — the reassembler returns to idle rather than
//! leaving a half-built message that a later fragment could complete.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod command;
mod error;
mod fragment;
mod reassemble;
mod transport;

pub use command::{Command, KeepAliveStatus};
pub use error::{BleErrorCode, FramingError};
pub use fragment::{fragments, FragmentSize, Fragments, MAX_FRAGMENT_SIZE, MIN_FRAGMENT_SIZE};
pub use reassemble::Reassembler;
pub use transport::{FragmentTransport, LinkState, TransportError};

/// The largest payload a single message can carry.
///
/// `HLEN` is two bytes, so the transport cannot describe more than this.
pub const MAX_PAYLOAD_LEN: usize = u16::MAX as usize;

/// A complete CTAP BLE message: one command and its reassembled payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// The command from the initialization fragment.
    pub command: Command,
    /// The payload, concatenated across every fragment of the message.
    pub payload: Vec<u8>,
}

impl Message {
    /// Builds a message.
    pub fn new(command: Command, payload: Vec<u8>) -> Self {
        Self { command, payload }
    }

    /// The number of fragments this message needs at the given fragment size.
    ///
    /// Errors if the payload is longer than [`MAX_PAYLOAD_LEN`], or if this is
    /// a `CANCEL` carrying a payload — reassembly discards that payload, so
    /// emitting one would produce bytes this crate cannot read back.
    pub fn fragment_count(&self, size: FragmentSize) -> Result<usize, FramingError> {
        if self.command == Command::Cancel && !self.payload.is_empty() {
            return Err(FramingError::CancelWithPayload {
                len: self.payload.len(),
            });
        }
        fragment::fragment_count(self.payload.len(), size)
    }
}
