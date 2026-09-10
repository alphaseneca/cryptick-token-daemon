//! Turning a message into fragments.

use crate::{error::FramingError, Command, Message, MAX_PAYLOAD_LEN};

/// The smallest fragment size the transport permits.
pub const MIN_FRAGMENT_SIZE: u16 = 20;

/// The largest fragment size the transport permits.
pub const MAX_FRAGMENT_SIZE: u16 = 512;

/// A validated fragment size, as published in `fidoControlPointLength`.
///
/// Constructing one is the only way to prove a size is in range, so no other
/// code in this crate has to re-check it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FragmentSize(u16);

impl FragmentSize {
    /// Validates a fragment size read from `fidoControlPointLength`.
    ///
    /// Read the real value from the characteristic. Never hardcode one — the
    /// device's actual value is still an open `[HW]` item (PROJECT.md §17), and
    /// it can differ per connection because it follows the negotiated ATT MTU.
    pub const fn new(size: u16) -> Result<Self, FramingError> {
        if size < MIN_FRAGMENT_SIZE || size > MAX_FRAGMENT_SIZE {
            return Err(FramingError::InvalidFragmentSize(size));
        }
        Ok(Self(size))
    }

    /// The size in bytes.
    pub const fn get(self) -> u16 {
        self.0
    }

    /// How many payload bytes an initialization fragment can carry, after its
    /// one-byte `CMD` and two-byte `HLEN`.
    pub const fn init_capacity(self) -> usize {
        self.0 as usize - 3
    }

    /// How many payload bytes a continuation fragment can carry, after its
    /// one-byte `SEQ`.
    pub const fn continuation_capacity(self) -> usize {
        self.0 as usize - 1
    }
}

/// How many fragments a payload of this length needs.
pub(crate) fn fragment_count(
    payload_len: usize,
    size: FragmentSize,
) -> Result<usize, FramingError> {
    if payload_len > MAX_PAYLOAD_LEN {
        return Err(FramingError::PayloadTooLong {
            len: payload_len,
            max: MAX_PAYLOAD_LEN,
        });
    }
    let init = size.init_capacity();
    if payload_len <= init {
        // A zero-length payload still needs its initialization fragment, which
        // is how CANCEL is sent.
        return Ok(1);
    }
    Ok(1 + (payload_len - init).div_ceil(size.continuation_capacity()))
}

/// Splits a message into fragments for `fidoControlPoint` or `fidoStatus`.
///
/// Fragments are filled to capacity; the last one is whatever remains. Returns
/// an error if the payload is longer than [`MAX_PAYLOAD_LEN`].
pub fn fragments(message: &Message, size: FragmentSize) -> Result<Fragments<'_>, FramingError> {
    let remaining = message.fragment_count(size)?;
    Ok(Fragments {
        command: message.command,
        payload: &message.payload,
        size,
        offset: 0,
        seq: 0,
        sent_init: false,
        remaining,
    })
}

/// An iterator over a message's fragments, in the order they go on the wire.
///
/// Created by [`fragments`].
#[derive(Debug, Clone)]
pub struct Fragments<'a> {
    command: Command,
    payload: &'a [u8],
    size: FragmentSize,
    offset: usize,
    seq: u8,
    sent_init: bool,
    remaining: usize,
}

impl Iterator for Fragments<'_> {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Vec<u8>> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;

        if !self.sent_init {
            self.sent_init = true;
            let take = self.payload.len().min(self.size.init_capacity());
            let mut fragment = Vec::with_capacity(3 + take);
            fragment.push(self.command.as_u8());
            // HLEN is the length of the whole payload, not of this fragment.
            // The cast is safe: fragment_count rejected anything over u16::MAX.
            fragment.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
            fragment.extend_from_slice(&self.payload[..take]);
            self.offset = take;
            return Some(fragment);
        }

        let take = (self.payload.len() - self.offset).min(self.size.continuation_capacity());
        let mut fragment = Vec::with_capacity(1 + take);
        fragment.push(self.seq);
        fragment.extend_from_slice(&self.payload[self.offset..self.offset + take]);
        self.offset += take;
        // SEQ is 7 bits and wraps; a 65535-byte payload at the smallest legal
        // fragment size needs about 3448 continuations, so this happens often.
        self.seq = (self.seq + 1) & 0x7f;
        Some(fragment)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for Fragments<'_> {}

#[cfg(test)]
mod tests {
    use super::*;

    fn size(n: u16) -> FragmentSize {
        FragmentSize::new(n).expect("test uses a legal fragment size")
    }

    #[test]
    fn fragment_sizes_outside_the_range_are_rejected() {
        assert_eq!(
            FragmentSize::new(19),
            Err(FramingError::InvalidFragmentSize(19))
        );
        assert_eq!(
            FragmentSize::new(513),
            Err(FramingError::InvalidFragmentSize(513))
        );
        assert_eq!(
            FragmentSize::new(0),
            Err(FramingError::InvalidFragmentSize(0))
        );
        assert!(FragmentSize::new(20).is_ok());
        assert!(FragmentSize::new(512).is_ok());
    }

    #[test]
    fn empty_payload_is_one_initialization_fragment() {
        // CANCEL carries no payload but still needs a fragment.
        let msg = Message::new(Command::Cancel, Vec::new());
        let out: Vec<_> = fragments(&msg, size(20)).unwrap().collect();
        assert_eq!(out, vec![vec![0xbe, 0x00, 0x00]]);
    }

    #[test]
    fn a_payload_that_exactly_fills_the_init_fragment_needs_no_continuation() {
        let payload = vec![0xaa; size(20).init_capacity()];
        let msg = Message::new(Command::Msg, payload);
        let out: Vec<_> = fragments(&msg, size(20)).unwrap().collect();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].len(), 20);
    }

    #[test]
    fn one_byte_over_the_init_fragment_adds_a_continuation() {
        let payload = vec![0xaa; size(20).init_capacity() + 1];
        let msg = Message::new(Command::Msg, payload);
        let out: Vec<_> = fragments(&msg, size(20)).unwrap().collect();
        assert_eq!(out.len(), 2);
        assert_eq!(out[1], vec![0x00, 0xaa]);
    }

    #[test]
    fn hlen_is_the_whole_payload_not_the_fragment() {
        let payload = vec![0x11; 300];
        let msg = Message::new(Command::Msg, payload);
        let out: Vec<_> = fragments(&msg, size(20)).unwrap().collect();
        assert_eq!(out[0][0], 0x83);
        assert_eq!(u16::from_be_bytes([out[0][1], out[0][2]]), 300);
        assert_eq!(out[0].len(), 20);
    }

    #[test]
    fn sequence_numbers_wrap_after_0x7f() {
        // Enough payload to need well over 128 continuations at size 20.
        let payload = vec![0x5a; 19 * 300];
        let msg = Message::new(Command::Msg, payload);
        let out: Vec<_> = fragments(&msg, size(20)).unwrap().collect();

        let seqs: Vec<u8> = out[1..].iter().map(|f| f[0]).collect();
        assert!(seqs.len() > 200, "expected the sequence space to wrap");
        assert_eq!(seqs[0], 0x00);
        assert_eq!(seqs[0x7f], 0x7f);
        assert_eq!(seqs[0x80], 0x00, "0x7f must wrap to 0x00");
        assert!(seqs.iter().all(|&s| s & 0x80 == 0));
    }

    #[test]
    fn fragments_never_exceed_the_negotiated_size() {
        for n in [20u16, 21, 23, 64, 100, 511, 512] {
            let msg = Message::new(Command::Msg, vec![0x7e; 4096]);
            for fragment in fragments(&msg, size(n)).unwrap() {
                assert!(!fragment.is_empty());
                assert!(fragment.len() <= n as usize, "size {n}");
            }
        }
    }

    #[test]
    fn reported_count_matches_what_is_produced() {
        for n in [20u16, 33, 512] {
            for len in [0usize, 1, 16, 17, 18, 100, 1200, 4096] {
                let msg = Message::new(Command::Msg, vec![0u8; len]);
                let expected = msg.fragment_count(size(n)).unwrap();
                let it = fragments(&msg, size(n)).unwrap();
                assert_eq!(it.len(), expected);
                assert_eq!(it.count(), expected, "size {n}, len {len}");
            }
        }
    }

    #[test]
    fn a_cancel_with_a_payload_is_refused_at_the_source() {
        // Reassembly delivers CANCEL on its first fragment and discards the
        // rest, so emitting a multi-fragment one would produce bytes we cannot
        // read back.
        let msg = Message::new(Command::Cancel, vec![0u8; 4]);
        assert_eq!(
            msg.fragment_count(size(20)),
            Err(FramingError::CancelWithPayload { len: 4 })
        );
        assert!(fragments(&msg, size(20)).is_err());
        // Empty is the only legal shape, and it is one fragment.
        let empty = Message::new(Command::Cancel, Vec::new());
        assert_eq!(empty.fragment_count(size(20)), Ok(1));
    }

    #[test]
    fn payloads_too_long_for_hlen_are_rejected() {
        let msg = Message::new(Command::Msg, vec![0u8; MAX_PAYLOAD_LEN + 1]);
        assert_eq!(
            msg.fragment_count(size(20)),
            Err(FramingError::PayloadTooLong {
                len: MAX_PAYLOAD_LEN + 1,
                max: MAX_PAYLOAD_LEN,
            })
        );
    }
}
