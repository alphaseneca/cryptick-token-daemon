//! CTAPHID framing: 64-byte packets, channels, and message reassembly.
//!
//! This is the OS-facing half of the daemon's job. A virtual HID device makes
//! the browser see an ordinary security key; what arrives on it is CTAPHID, and
//! what goes to the token is the CTAP BLE transport. Translating between those
//! two envelopes — and nothing else — is the whole of it (PROJECT.md §4, §9).
//!
//! # This is the least protected surface in the project
//!
//! Bonding protects the radio. Nothing protects this: the virtual HID node is
//! writable by any local process that passes the permission check, and it hands
//! us packets directly (PROJECT.md §14, fuzz source 3). Every parser here is
//! written to be total — malformed input produces a typed error carrying the
//! [`ErrorCode`] to answer with, never a panic and never a partial message that
//! a later packet could complete.
//!
//! # How it differs from the BLE transport
//!
//! Same idea, different envelope, and the differences are the bugs waiting to
//! happen:
//!
//! | | CTAPHID (here) | CTAP BLE (`ble-framing`) |
//! |---|---|---|
//! | Unit | always 64 bytes, zero-padded | sized by `fidoControlPointLength` |
//! | Init header | CID(4) ‖ CMD(1) ‖ BCNT(2) = 7 | CMD(1) ‖ HLEN(2) = 3 |
//! | Continuation header | CID(4) ‖ SEQ(1) = 5 | SEQ(1) = 1 |
//! | `SEQ` | `0x00`..=`0x7f`, **does not wrap** | wraps at `0x7f` |
//! | Channels | yes, allocated by `CTAPHID_INIT` | none at all |
//! | Max message | [`MAX_MESSAGE_LEN`] = 7609 bytes | 65535 bytes |
//!
//! Because `SEQ` does not wrap, a CTAPHID message cannot exceed one initial
//! packet plus 128 continuations. That is where 7609 comes from, and it is a
//! hard bound rather than a tuning choice.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod assembler;
mod command;
mod message;
mod packet;

pub use assembler::{Assembler, ChannelAllocator, ChannelError, MAX_PENDING_CHANNELS};
pub use command::{Cmd, ErrorCode, KeepaliveStatus};
pub use message::{Message, Packets, CAPABILITY_CBOR, CAPABILITY_NMSG, CAPABILITY_WINK};
pub use packet::{ChannelId, Packet, PacketKind};

use thiserror::Error;

/// Every CTAPHID packet is exactly this many bytes, padded if need be.
pub const PACKET_SIZE: usize = 64;

/// Payload bytes an initialization packet carries, after CID, CMD and BCNT.
pub const INIT_PAYLOAD_SIZE: usize = PACKET_SIZE - 7;

/// Payload bytes a continuation packet carries, after CID and SEQ.
pub const CONT_PAYLOAD_SIZE: usize = PACKET_SIZE - 5;

/// The highest sequence number. Unlike the BLE transport, this does not wrap.
pub const MAX_SEQ: u8 = 0x7f;

/// The largest message CTAPHID can carry: one init packet plus 128
/// continuations, since `SEQ` runs out at `0x7f` and does not wrap.
pub const MAX_MESSAGE_LEN: usize = INIT_PAYLOAD_SIZE + (MAX_SEQ as usize + 1) * CONT_PAYLOAD_SIZE;

/// A malformed packet or message.
///
/// Every variant maps to the [`ErrorCode`] to answer the host with.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CtaphidError {
    /// A packet that was not exactly [`PACKET_SIZE`] bytes.
    #[error("packet is {len} bytes; CTAPHID packets are always {PACKET_SIZE}")]
    WrongPacketSize {
        /// The length received.
        len: usize,
    },

    /// A command byte that is not one this transport defines.
    #[error("unknown CTAPHID command {0:#04x}")]
    UnknownCommand(u8),

    /// A message longer than [`MAX_MESSAGE_LEN`].
    #[error("message of {len} bytes exceeds the CTAPHID maximum of {MAX_MESSAGE_LEN}")]
    MessageTooLong {
        /// The declared or supplied length.
        len: usize,
    },

    /// A keepalive status byte that is neither `PROCESSING` nor `UP_NEEDED`.
    #[error("unknown keepalive status {0:#04x}")]
    UnknownKeepaliveStatus(u8),
}

impl CtaphidError {
    /// The error code to report to the host.
    pub const fn error_code(&self) -> ErrorCode {
        match self {
            CtaphidError::UnknownCommand(_) => ErrorCode::InvalidCmd,
            CtaphidError::WrongPacketSize { .. } | CtaphidError::MessageTooLong { .. } => {
                ErrorCode::InvalidLen
            }
            CtaphidError::UnknownKeepaliveStatus(_) => ErrorCode::InvalidPar,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_maximum_message_matches_the_sequence_space() {
        // 57 + 128 * 59. The Cryptick token firmware uses the same constant for
        // its CTAPHID buffer, which is a useful independent confirmation.
        assert_eq!(MAX_MESSAGE_LEN, 7609);
    }

    #[test]
    fn payload_capacities_account_for_their_headers() {
        assert_eq!(INIT_PAYLOAD_SIZE, 57);
        assert_eq!(CONT_PAYLOAD_SIZE, 59);
    }
}
