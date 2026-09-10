//! Framing errors, and the wire error codes they map to.

use thiserror::Error;

/// An error code from the CTAP BLE transport, carried as the one-byte payload
/// of an [`Error`](crate::Command::Error) command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BleErrorCode {
    /// The command in the request is invalid.
    InvalidCmd,
    /// A parameter in the request is invalid.
    InvalidPar,
    /// The length of the request is invalid.
    InvalidLen,
    /// The sequence number is invalid.
    InvalidSeq,
    /// The request timed out.
    ReqTimeout,
    /// The device is busy and cannot accept commands at this time.
    ///
    /// The spec says a client SHOULD retry after a short delay. We do not:
    /// PROJECT.md §21 forbids retrying a failed CTAP transaction
    /// automatically, so this is surfaced and the caller decides.
    Busy,
    /// Unspecified error.
    Other,
}

impl BleErrorCode {
    /// The error code's wire byte.
    pub const fn as_u8(self) -> u8 {
        match self {
            BleErrorCode::InvalidCmd => 0x01,
            BleErrorCode::InvalidPar => 0x02,
            BleErrorCode::InvalidLen => 0x03,
            BleErrorCode::InvalidSeq => 0x04,
            BleErrorCode::ReqTimeout => 0x05,
            BleErrorCode::Busy => 0x06,
            BleErrorCode::Other => 0x7f,
        }
    }

    /// Parses an error code byte.
    ///
    /// `0x0a` and `0x0b` are reserved for CTAPHID, and anything else undefined
    /// maps to [`BleErrorCode::Other`] rather than failing: an error response
    /// we cannot parse is still an error response, and turning that into a
    /// second error would lose the original failure.
    pub const fn from_u8(byte: u8) -> Self {
        match byte {
            0x01 => BleErrorCode::InvalidCmd,
            0x02 => BleErrorCode::InvalidPar,
            0x03 => BleErrorCode::InvalidLen,
            0x04 => BleErrorCode::InvalidSeq,
            0x05 => BleErrorCode::ReqTimeout,
            0x06 => BleErrorCode::Busy,
            _ => BleErrorCode::Other,
        }
    }

    /// Parses the payload of an `ERROR` command.
    ///
    /// The spec describes this as "an error code as a variable-length,
    /// big-endian integer", not as a single byte. Every defined code fits in
    /// one, but a peer is entitled to send `00 06`, and taking the first byte
    /// of that would read the padding and lose the error.
    pub fn from_payload(payload: &[u8]) -> Self {
        // Skip leading zero padding, then take the least significant byte. A
        // value too large for u8 is not a code we know, which is Other anyway.
        match payload.iter().copied().find(|&b| b != 0) {
            Some(byte) if payload.iter().filter(|&&b| b != 0).count() == 1 => {
                BleErrorCode::from_u8(byte)
            }
            // All-zero or multi-byte: undefined either way.
            _ => BleErrorCode::Other,
        }
    }
}

/// Something was wrong with a fragment, a message, or a fragment size.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FramingError {
    /// A fragment size outside the range the transport permits.
    #[error("fragment size {0} is outside the permitted range {min}..={max}", min = crate::MIN_FRAGMENT_SIZE, max = crate::MAX_FRAGMENT_SIZE)]
    InvalidFragmentSize(u16),

    /// A `CANCEL` built with a payload.
    ///
    /// Rejected at the source because reassembly delivers `CANCEL` on its
    /// first fragment and discards the rest, so a multi-fragment `CANCEL`
    /// would be something this crate emits and cannot read back. `CANCEL` has
    /// no payload defined; build it empty.
    #[error("CANCEL must carry no payload, but {len} bytes were supplied")]
    CancelWithPayload {
        /// The payload length supplied.
        len: usize,
    },

    /// A payload too long for a 16-bit `HLEN` to describe.
    #[error("payload of {len} bytes exceeds the maximum of {max}")]
    PayloadTooLong {
        /// The payload's length.
        len: usize,
        /// The largest payload the transport can describe.
        max: usize,
    },

    /// A fragment with no bytes at all.
    #[error("received an empty fragment")]
    EmptyFragment,

    /// A fragment longer than the negotiated fragment size.
    #[error("fragment of {len} bytes exceeds the negotiated fragment size of {max}")]
    FragmentTooLong {
        /// The fragment's length.
        len: usize,
        /// The negotiated fragment size.
        max: u16,
    },

    /// An initialization fragment too short to hold `CMD` and `HLEN`.
    #[error("initialization fragment of {len} bytes is too short for CMD and HLEN")]
    TruncatedInitFragment {
        /// The fragment's length.
        len: usize,
    },

    /// A command byte that is not one of the transport's five commands.
    #[error("unknown command byte {0:#04x}")]
    UnknownCommand(u8),

    /// A keepalive status byte that is neither `PROCESSING` nor `UP_NEEDED`.
    #[error("unknown keepalive status byte {0:#04x}")]
    UnknownKeepAliveStatus(u8),

    /// An initialization fragment arrived mid-transaction. The transport has no
    /// channels, so there is no way to interleave two messages.
    #[error("initialization fragment arrived while a transaction was in progress")]
    UnexpectedInitFragment,

    /// A continuation fragment arrived with nothing to continue.
    #[error("continuation fragment arrived with no transaction in progress")]
    ContinuationWithoutInit,

    /// A continuation fragment out of order, or a dropped fragment.
    #[error("expected sequence number {expected:#04x}, got {got:#04x}")]
    UnexpectedSequence {
        /// The sequence number the next fragment should have carried.
        expected: u8,
        /// The sequence number it actually carried.
        got: u8,
    },

    /// A continuation fragment carrying a sequence number and nothing else.
    ///
    /// Rejected because it makes no progress: a peer sending these forever
    /// would keep a transaction open indefinitely without ever completing it.
    #[error("continuation fragment carried no data")]
    EmptyContinuation,

    /// More data arrived than the initialization fragment declared.
    #[error("fragment stream carries more than the declared {declared} bytes")]
    DeclaredLengthExceeded {
        /// The length declared in `HLEN`.
        declared: usize,
    },

    /// An initialization fragment declared a message larger than the configured
    /// ceiling.
    #[error("declared length {declared} exceeds the configured maximum of {max} bytes")]
    DeclaredLengthTooLarge {
        /// The length declared in `HLEN`.
        declared: usize,
        /// The configured maximum.
        max: usize,
    },
}

impl FramingError {
    /// The wire error code to report for this failure.
    ///
    /// Used when we are the authenticator half answering a malformed request;
    /// as the client half, the error is surfaced to the caller instead
    /// (PROJECT.md §21 — never retry a failed transaction automatically).
    pub const fn ble_error_code(&self) -> BleErrorCode {
        match self {
            FramingError::UnknownCommand(_) => BleErrorCode::InvalidCmd,

            FramingError::UnknownKeepAliveStatus(_) => BleErrorCode::InvalidPar,

            FramingError::InvalidFragmentSize(_)
            | FramingError::PayloadTooLong { .. }
            | FramingError::EmptyFragment
            | FramingError::FragmentTooLong { .. }
            | FramingError::TruncatedInitFragment { .. }
            | FramingError::EmptyContinuation
            | FramingError::DeclaredLengthExceeded { .. }
            | FramingError::DeclaredLengthTooLarge { .. }
            | FramingError::CancelWithPayload { .. } => BleErrorCode::InvalidLen,

            FramingError::UnexpectedSequence { .. }
            | FramingError::ContinuationWithoutInit
            | FramingError::UnexpectedInitFragment => BleErrorCode::InvalidSeq,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_round_trip() {
        for code in [
            BleErrorCode::InvalidCmd,
            BleErrorCode::InvalidPar,
            BleErrorCode::InvalidLen,
            BleErrorCode::InvalidSeq,
            BleErrorCode::ReqTimeout,
            BleErrorCode::Other,
        ] {
            assert_eq!(BleErrorCode::from_u8(code.as_u8()), code);
        }
    }

    #[test]
    fn ctaphid_reserved_codes_become_other() {
        // Only 0x0a and 0x0b are reserved for CTAPHID. 0x06 is ERR_BUSY, a
        // real BLE code — an earlier version of this file wrongly listed it
        // as reserved, which is why the spec text is quoted in from_u8.
        for byte in [0x0a, 0x0b, 0x00, 0x30, 0xff] {
            assert_eq!(BleErrorCode::from_u8(byte), BleErrorCode::Other);
        }
        assert_eq!(BleErrorCode::from_u8(0x06), BleErrorCode::Busy);
    }

    #[test]
    fn an_error_payload_is_a_big_endian_integer_not_a_byte() {
        assert_eq!(BleErrorCode::from_payload(&[0x06]), BleErrorCode::Busy);
        // Zero-padded, which the "variable-length big-endian integer" wording
        // permits and a first-byte read would get wrong.
        assert_eq!(
            BleErrorCode::from_payload(&[0x00, 0x06]),
            BleErrorCode::Busy
        );
        assert_eq!(
            BleErrorCode::from_payload(&[0x00, 0x00, 0x7f]),
            BleErrorCode::Other
        );
        // Nothing usable.
        assert_eq!(BleErrorCode::from_payload(&[]), BleErrorCode::Other);
        assert_eq!(BleErrorCode::from_payload(&[0x00]), BleErrorCode::Other);
        assert_eq!(
            BleErrorCode::from_payload(&[0x01, 0x02]),
            BleErrorCode::Other
        );
    }

    #[test]
    fn sequence_failures_report_invalid_seq() {
        let err = FramingError::UnexpectedSequence {
            expected: 0x03,
            got: 0x05,
        };
        assert_eq!(err.ble_error_code(), BleErrorCode::InvalidSeq);
    }

    #[test]
    fn length_failures_report_invalid_len() {
        assert_eq!(
            FramingError::EmptyFragment.ble_error_code(),
            BleErrorCode::InvalidLen
        );
        assert_eq!(
            FramingError::DeclaredLengthTooLarge {
                declared: 5000,
                max: 1200
            }
            .ble_error_code(),
            BleErrorCode::InvalidLen
        );
    }
}
