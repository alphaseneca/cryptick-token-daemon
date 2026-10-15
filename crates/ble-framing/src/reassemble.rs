//! Turning fragments back into a message.

use crate::{error::FramingError, Command, Message, MAX_FRAGMENT_SIZE, MAX_PAYLOAD_LEN};

#[derive(Debug, Clone)]
enum State {
    Idle,
    Collecting {
        command: Command,
        declared: usize,
        buf: Vec<u8>,
        next_seq: u8,
    },
}

/// Reassembles fragments from `fidoControlPoint` or `fidoStatus` into messages.
///
/// One reassembler handles one fragment stream. The transport has no channels,
/// so exactly one transaction is in flight at a time (PROJECT.md §13); an
/// initialization fragment arriving mid-transaction is a protocol violation,
/// not a second conversation.
///
/// **Any error aborts the transaction.** After a failed [`push`](Self::push)
/// the reassembler is idle, so an attacker cannot poison a partially built
/// message and then complete it. Callers should surface the error rather than
/// retrying (PROJECT.md §21).
#[derive(Debug, Clone)]
pub struct Reassembler {
    max_message_len: usize,
    state: State,
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Reassembler {
    /// A reassembler accepting messages up to [`MAX_PAYLOAD_LEN`].
    ///
    /// Deliberately takes no fragment size. `fidoControlPointLength` bounds
    /// *writes to the control point*; inbound fragments arrive as notifications
    /// on `fidoStatus`, whose size follows the negotiated ATT MTU and may be
    /// larger. Bounding reassembly by the write limit would reject a device
    /// that advertises 20 and notifies at MTU-3 — legal, and something a vendor
    /// can plausibly ship. Fragments are instead capped at
    /// [`MAX_FRAGMENT_SIZE`], which still bounds memory.
    pub fn new() -> Self {
        Self {
            max_message_len: MAX_PAYLOAD_LEN,
            state: State::Idle,
        }
    }

    /// A reassembler that rejects any message declaring more than
    /// `max_message_len` bytes.
    ///
    /// `HLEN` is 16 bits, so a peer can declare 65535 bytes whatever the
    /// authenticator can actually handle. Setting this to the device's real
    /// ceiling rejects an over-large message at its first fragment, before
    /// anything is buffered. The Cryptick token firmware caps CTAP
    /// messages at 1200 bytes (`CTAP_MAX_MESSAGE_SIZE`), so that is the value
    /// to use against this device.
    pub fn with_max_message_len(max_message_len: usize) -> Self {
        Self {
            max_message_len: max_message_len.min(MAX_PAYLOAD_LEN),
            state: State::Idle,
        }
    }

    /// Whether a transaction is partly reassembled.
    pub fn in_progress(&self) -> bool {
        matches!(self.state, State::Collecting { .. })
    }

    /// Discards any transaction in progress.
    ///
    /// Call this on disconnect, on `CANCEL`, and on transaction timeout: a
    /// reconnecting peer must not be able to finish a message the previous one
    /// started.
    pub fn reset(&mut self) {
        self.state = State::Idle;
    }

    /// Feeds one fragment.
    ///
    /// Returns the message once the last fragment of it arrives, `None` while
    /// more are expected, and an error for anything malformed — in which case
    /// the transaction is abandoned and the reassembler is left idle.
    pub fn push(&mut self, fragment: &[u8]) -> Result<Option<Message>, FramingError> {
        match self.push_inner(fragment) {
            Ok(message) => Ok(message),
            Err(err) => {
                // Fail closed: never leave half a message behind an error.
                self.state = State::Idle;
                Err(err)
            }
        }
    }

    fn push_inner(&mut self, fragment: &[u8]) -> Result<Option<Message>, FramingError> {
        let (&first, rest) = fragment.split_first().ok_or(FramingError::EmptyFragment)?;

        // CANCEL is handled before every check that could produce an error,
        // and that ordering is the whole point.
        //
        // CTAP 2.1 §11.4.8 requires the outstanding request to be cancelled and
        // forbids replying to the cancel itself — "whether a request was
        // cancelled or not, the authenticator MUST NOT reply to the cancel
        // message itself". So there is no way to tell a peer its CANCEL was
        // malformed. A command that cannot be rejected has to be acted on:
        // waiting for continuations of an over-declared CANCEL, or erroring on
        // a truncated one, both amount to ignoring it, and ignoring a CANCEL
        // violates the MUST.
        //
        // Therefore any fragment beginning with the CANCEL byte delivers
        // `(Cancel, [])` at once, whatever its length or declared HLEN, and
        // abandons whatever was in flight. The declared length is ignored
        // rather than validated, and any payload is discarded — CANCEL has
        // none defined.
        if first == Command::Cancel.as_u8() {
            self.state = State::Idle;
            return Ok(Some(Message::new(Command::Cancel, Vec::new())));
        }

        if fragment.len() > MAX_FRAGMENT_SIZE as usize {
            return Err(FramingError::FragmentTooLong {
                len: fragment.len(),
                max: MAX_FRAGMENT_SIZE,
            });
        }

        // The high bit is the only thing distinguishing the two fragment kinds.
        if first & 0x80 != 0 {
            self.push_init(first, rest, fragment.len())
        } else {
            self.push_continuation(first, rest)
        }
    }

    fn push_init(
        &mut self,
        command_byte: u8,
        rest: &[u8],
        fragment_len: usize,
    ) -> Result<Option<Message>, FramingError> {
        if rest.len() < 2 {
            return Err(FramingError::TruncatedInitFragment { len: fragment_len });
        }

        let command = Command::from_u8(command_byte)?;

        if self.in_progress() {
            // CANCEL never reaches here — push_inner intercepts it before any
            // check that could fail. Every other command starting a message
            // before the last one finished means the stream is out of order.
            debug_assert_ne!(command, Command::Cancel);
            return Err(FramingError::UnexpectedInitFragment);
        }
        let declared = u16::from_be_bytes([rest[0], rest[1]]) as usize;
        let data = &rest[2..];

        if declared > self.max_message_len {
            return Err(FramingError::DeclaredLengthTooLarge {
                declared,
                max: self.max_message_len,
            });
        }
        if data.len() > declared {
            return Err(FramingError::DeclaredLengthExceeded { declared });
        }

        if data.len() == declared {
            return Ok(Some(Message::new(command, data.to_vec())));
        }

        // Bounded by max_message_len, which was checked above.
        let mut buf = Vec::with_capacity(declared);
        buf.extend_from_slice(data);
        self.state = State::Collecting {
            command,
            declared,
            buf,
            next_seq: 0,
        };
        Ok(None)
    }

    fn push_continuation(&mut self, seq: u8, data: &[u8]) -> Result<Option<Message>, FramingError> {
        let State::Collecting {
            command,
            declared,
            buf,
            next_seq,
        } = &mut self.state
        else {
            return Err(FramingError::ContinuationWithoutInit);
        };

        if seq != *next_seq {
            return Err(FramingError::UnexpectedSequence {
                expected: *next_seq,
                got: seq,
            });
        }
        if data.is_empty() {
            // Makes no progress, so a peer could hold the transaction open
            // forever sending these.
            return Err(FramingError::EmptyContinuation);
        }
        if buf.len() + data.len() > *declared {
            return Err(FramingError::DeclaredLengthExceeded {
                declared: *declared,
            });
        }

        buf.extend_from_slice(data);
        *next_seq = (seq + 1) & 0x7f;

        if buf.len() == *declared {
            let message = Message::new(*command, std::mem::take(buf));
            self.state = State::Idle;
            return Ok(Some(message));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{fragments, FragmentSize};

    fn size(n: u16) -> FragmentSize {
        FragmentSize::new(n).expect("test uses a legal fragment size")
    }

    fn round_trip(message: &Message, n: u16) -> Message {
        let s = size(n);
        let mut rx = Reassembler::new();
        let mut out = None;
        for fragment in fragments(message, s).expect("payload fits") {
            out = rx.push(&fragment).expect("fragment is well formed");
        }
        assert!(!rx.in_progress(), "reassembler should be idle when done");
        out.expect("last fragment completes the message")
    }

    #[test]
    fn round_trips_at_every_boundary_size() {
        for n in [20u16, 21, 22, 23, 64, 255, 511, 512] {
            for len in [0usize, 1, 16, 17, 18, 19, 20, 512, 1200, 9000] {
                let msg = Message::new(Command::Msg, (0..len).map(|i| i as u8).collect());
                assert_eq!(round_trip(&msg, n), msg, "size {n}, len {len}");
            }
        }
    }

    #[test]
    fn round_trips_across_a_sequence_wrap() {
        let msg = Message::new(Command::Msg, (0..19 * 400).map(|i| i as u8).collect());
        assert_eq!(round_trip(&msg, 20), msg);
    }

    #[test]
    fn empty_fragment_is_rejected() {
        let mut rx = Reassembler::new();
        assert_eq!(rx.push(&[]), Err(FramingError::EmptyFragment));
    }

    #[test]
    fn oversized_fragment_is_rejected() {
        let mut rx = Reassembler::new();
        // Bounded by the transport ceiling, not by fidoControlPointLength:
        // notifications are sized by the ATT MTU, not by the write limit.
        let fragment = vec![0x83; MAX_FRAGMENT_SIZE as usize + 1];
        assert_eq!(
            rx.push(&fragment),
            Err(FramingError::FragmentTooLong {
                len: MAX_FRAGMENT_SIZE as usize + 1,
                max: MAX_FRAGMENT_SIZE
            })
        );
    }

    #[test]
    fn a_notification_larger_than_the_control_point_length_is_accepted() {
        // fidoControlPointLength bounds writes to fidoControlPoint. A device
        // may advertise 20 and still notify at the negotiated ATT MTU.
        let mut rx = Reassembler::new();
        let mut fragment = vec![0x83, 0x00, 0xc8];
        fragment.extend(std::iter::repeat_n(0xaa, 200));
        assert_eq!(
            rx.push(&fragment).unwrap(),
            Some(Message::new(Command::Msg, vec![0xaa; 200]))
        );
    }

    #[test]
    fn truncated_init_fragment_is_rejected() {
        let mut rx = Reassembler::new();
        assert_eq!(
            rx.push(&[0x83]),
            Err(FramingError::TruncatedInitFragment { len: 1 })
        );
        assert_eq!(
            rx.push(&[0x83, 0x00]),
            Err(FramingError::TruncatedInitFragment { len: 2 })
        );
    }

    #[test]
    fn unknown_command_is_rejected() {
        let mut rx = Reassembler::new();
        assert_eq!(
            rx.push(&[0x84, 0x00, 0x00]),
            Err(FramingError::UnknownCommand(0x84))
        );
    }

    #[test]
    fn continuation_without_init_is_rejected() {
        let mut rx = Reassembler::new();
        assert_eq!(
            rx.push(&[0x00, 0xde, 0xad]),
            Err(FramingError::ContinuationWithoutInit)
        );
    }

    #[test]
    fn out_of_order_continuation_is_rejected_and_aborts() {
        let mut rx = Reassembler::new();
        assert_eq!(rx.push(&[0x83, 0x00, 0x40]).unwrap(), None);
        assert!(rx.in_progress());
        // Expecting SEQ 0x00, sending 0x01.
        assert_eq!(
            rx.push(&[0x01, 0xff]),
            Err(FramingError::UnexpectedSequence {
                expected: 0x00,
                got: 0x01,
            })
        );
        assert!(!rx.in_progress(), "an error must abort the transaction");
    }

    #[test]
    fn reordered_continuations_do_not_reassemble() {
        // A hostile peer replaying fragments out of order gets nothing.
        let msg = Message::new(Command::Msg, vec![0x42; 100]);
        let s = size(20);
        let mut frags: Vec<_> = fragments(&msg, s).unwrap().collect();
        frags.swap(2, 3);

        let mut rx = Reassembler::new();
        let mut saw_error = false;
        for f in &frags {
            if rx.push(f).is_err() {
                saw_error = true;
                break;
            }
        }
        assert!(saw_error, "swapped continuations must be caught");
    }

    #[test]
    fn empty_continuation_is_rejected() {
        let mut rx = Reassembler::new();
        assert_eq!(rx.push(&[0x83, 0x00, 0x40]).unwrap(), None);
        assert_eq!(rx.push(&[0x00]), Err(FramingError::EmptyContinuation));
    }

    #[test]
    fn more_data_than_declared_is_rejected() {
        let mut rx = Reassembler::new();
        // Declares 4 bytes, init fragment carries 2.
        assert_eq!(rx.push(&[0x83, 0x00, 0x04, 0xaa, 0xbb]).unwrap(), None);
        assert_eq!(
            rx.push(&[0x00, 0xcc, 0xdd, 0xee]),
            Err(FramingError::DeclaredLengthExceeded { declared: 4 })
        );
    }

    #[test]
    fn init_fragment_carrying_more_than_it_declares_is_rejected() {
        let mut rx = Reassembler::new();
        assert_eq!(
            rx.push(&[0x83, 0x00, 0x01, 0xaa, 0xbb]),
            Err(FramingError::DeclaredLengthExceeded { declared: 1 })
        );
    }

    #[test]
    fn a_cancel_may_interrupt_a_message_in_flight() {
        // CTAP 2.1 §11.4.8 requires the outstanding request to be cancelled
        // and forbids replying to the cancel itself, so this must yield the
        // CANCEL rather than an error.
        let mut rx = Reassembler::new();
        assert_eq!(rx.push(&[0x83, 0x01, 0x00, 0xaa]).unwrap(), None);
        assert!(rx.in_progress());

        assert_eq!(
            rx.push(&[0xbe, 0x00, 0x00]).unwrap(),
            Some(Message::new(Command::Cancel, Vec::new()))
        );
        assert!(!rx.in_progress(), "the interrupted message is abandoned");
    }

    #[test]
    fn every_shape_of_cancel_delivers_immediately_and_silently() {
        // There is no legal way to report a malformed CANCEL, so each of these
        // must yield `(CANCEL, "")` rather than an error or a wait:
        // a bare command byte, a truncated header, a zero-length cancel, one
        // over-declaring its length, and one longer than any control point.
        let mut oversized = vec![0xbe, 0xff, 0xff];
        oversized.resize(600, 0x5a);

        for fragment in [
            &[0xbe][..],
            &[0xbe, 0x00],
            &[0xbe, 0x00, 0x00],
            &[0xbe, 0x01, 0xf4, 0x6a, 0x75, 0x6e, 0x6b], // HLEN 500, "junk"
            &oversized,
        ] {
            let mut rx = Reassembler::new();
            assert_eq!(
                rx.push(fragment).unwrap(),
                Some(Message::new(Command::Cancel, Vec::new())),
                "fragment {fragment:02x?}"
            );
            assert!(!rx.in_progress());
        }
    }

    #[test]
    fn init_fragment_mid_transaction_is_rejected() {
        let mut rx = Reassembler::new();
        assert_eq!(rx.push(&[0x83, 0x00, 0x40]).unwrap(), None);
        assert_eq!(
            rx.push(&[0x83, 0x00, 0x40]),
            Err(FramingError::UnexpectedInitFragment)
        );
        assert!(!rx.in_progress());
    }

    #[test]
    fn declared_length_above_the_configured_ceiling_is_rejected_before_buffering() {
        // The firmware's CTAP_MAX_MESSAGE_SIZE.
        let mut rx = Reassembler::with_max_message_len(1200);
        assert_eq!(
            rx.push(&[0x83, 0x04, 0xb1]),
            Err(FramingError::DeclaredLengthTooLarge {
                declared: 1201,
                max: 1200,
            })
        );
        // Exactly at the ceiling is fine.
        assert_eq!(rx.push(&[0x83, 0x04, 0xb0]).unwrap(), None);
    }

    #[test]
    fn under_filled_fragments_are_tolerated() {
        // We always fill fragments to capacity, but HLEN is authoritative, so a
        // peer that under-fills is unambiguous and harmless. Accepting this
        // costs nothing and avoids a needless interop failure with firmware
        // that fragments differently; the total is still bounded by HLEN.
        let mut rx = Reassembler::new();
        assert_eq!(rx.push(&[0x83, 0x00, 0x04, 0xaa]).unwrap(), None);
        assert_eq!(rx.push(&[0x00, 0xbb]).unwrap(), None);
        assert_eq!(rx.push(&[0x01, 0xcc]).unwrap(), None);
        assert_eq!(
            rx.push(&[0x02, 0xdd]).unwrap(),
            Some(Message::new(Command::Msg, vec![0xaa, 0xbb, 0xcc, 0xdd]))
        );
    }

    #[test]
    fn reset_discards_a_partial_transaction() {
        let mut rx = Reassembler::new();
        assert_eq!(rx.push(&[0x83, 0x00, 0x40]).unwrap(), None);
        assert!(rx.in_progress());
        rx.reset();
        assert!(!rx.in_progress());
        // The continuation that would have completed it is now orphaned.
        assert_eq!(
            rx.push(&[0x00, 0xff]),
            Err(FramingError::ContinuationWithoutInit)
        );
    }

    #[test]
    fn cancel_round_trips_as_an_empty_message() {
        let msg = Message::new(Command::Cancel, Vec::new());
        assert_eq!(round_trip(&msg, 20), msg);
    }

    #[test]
    fn keepalive_up_needed_round_trips() {
        use crate::KeepAliveStatus;
        let msg = Message::new(Command::KeepAlive, vec![KeepAliveStatus::UpNeeded.as_u8()]);
        let out = round_trip(&msg, 20);
        assert_eq!(out.command, Command::KeepAlive);
        assert_eq!(
            KeepAliveStatus::from_u8(out.payload[0]),
            Ok(KeepAliveStatus::UpNeeded)
        );
    }
}
