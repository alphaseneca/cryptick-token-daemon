//! The `vpcd` wire protocol, from the `vicc` side.
//!
//! `vpcd` is the vsmartcard project's reader driver: PCSC-Lite and the Windows
//! smart card service load it as a reader, and it relays everything over
//! loopback to a *virtual ICC* — the `vicc`. The daemon plays the `vicc`, so
//! the operating system's own PIV stack talks to our device as if it were a
//! card in a reader (PROJECT.md §11).
//!
//! Over USB none of this exists: the device is a real CCID reader and the OS
//! binds to it directly. This path is how the same applet is reached over BLE.
//!
//! # The protocol
//!
//! Every message, in both directions, is a two-byte big-endian length followed
//! by that many bytes. `vpcd` always speaks first.
//!
//! | Message | Bytes | The `vicc` replies |
//! |---|---|---|
//! | Power off | `00 01 00` | nothing |
//! | Power on | `00 01 01` | nothing |
//! | Reset | `00 01 02` | nothing |
//! | Get ATR | `00 01 04` | a framed ATR |
//! | APDU | `00 LL` + APDU | a framed response APDU |
//!
//! Transcribed from `vpcd.h` (`VPCD_CTRL_OFF` 0, `ON` 1, `RESET` 2, `ATR` 4,
//! `VPCD_CTRL_LEN` 1) and the reference `vicc` loop in `VirtualSmartcard.py`.
//!
//! # No I/O
//!
//! This crate is a codec and a state machine. The socket lives in the daemon,
//! the same way framing lives here and the radio lives in `transport-ble`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use thiserror::Error;

/// Default loopback port for the first `vpcd` slot.
pub const DEFAULT_PORT: u16 = 35963;
/// Default loopback port for the second `vpcd` slot.
pub const SECOND_PORT: u16 = 35964;

/// The length of a control message: one byte.
pub const CTRL_LEN: usize = 1;

/// `VPCD_CTRL_OFF`.
pub const CTRL_OFF: u8 = 0;
/// `VPCD_CTRL_ON`.
pub const CTRL_ON: u8 = 1;
/// `VPCD_CTRL_RESET`.
pub const CTRL_RESET: u8 = 2;
/// `VPCD_CTRL_ATR`.
pub const CTRL_ATR: u8 = 4;

/// The largest body the two-byte length prefix can describe.
pub const MAX_BODY: usize = u16::MAX as usize;

/// One message from `vpcd`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// The reader powered the card down.
    PowerOff,
    /// The reader powered the card up.
    PowerOn,
    /// The reader reset the card.
    Reset,
    /// The reader wants the Answer-to-Reset.
    GetAtr,
    /// A command APDU to pass to the card.
    Apdu(Vec<u8>),
    /// A zero-length message.
    ///
    /// The reference `vicc` logs this and carries on rather than treating it
    /// as a protocol error, so it is named here instead of being dropped
    /// silently — a relay that quietly discards messages is a relay whose logs
    /// do not explain what happened.
    Empty,
    /// A one-byte message that is not one of the four control bytes.
    ///
    /// Any one-byte message is a control message by definition of the
    /// protocol, so this cannot be a short APDU, and passing it to the card
    /// would be inventing a meaning the protocol does not give it.
    UnknownControl(u8),
}

/// The stream did not decode.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum VpcdError {
    /// A body was longer than the daemon is willing to relay.
    #[error("vpcd sent a {len}-byte body; the relay accepts at most {limit}")]
    BodyTooLong {
        /// The declared length.
        len: usize,
        /// The configured ceiling.
        limit: usize,
    },

    /// A reply was longer than the two-byte prefix can describe.
    #[error("reply is {len} bytes, which does not fit the two-byte length prefix")]
    ReplyTooLong {
        /// How long the reply was.
        len: usize,
    },
}

/// Frames a reply for `vpcd`: two-byte big-endian length, then the body.
pub fn frame(body: &[u8]) -> Result<Vec<u8>, VpcdError> {
    if body.len() > MAX_BODY {
        return Err(VpcdError::ReplyTooLong { len: body.len() });
    }
    let mut out = Vec::with_capacity(2 + body.len());
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
    Ok(out)
}

/// Reassembles the byte stream `vpcd` sends into messages.
#[derive(Debug, Clone)]
pub struct Decoder {
    buffer: Vec<u8>,
    limit: usize,
}

impl Default for Decoder {
    fn default() -> Self {
        Decoder::new(MAX_BODY)
    }
}

impl Decoder {
    /// A decoder refusing any body longer than `limit`.
    ///
    /// The ceiling is what the relay is willing to carry, not what the wire
    /// allows. The BLE path caps an APDU exchange at 261 bytes
    /// (`docs/device-protocol.md`), and an APDU that cannot be delivered
    /// should be refused here rather than half-sent.
    pub fn new(limit: usize) -> Self {
        Decoder {
            buffer: Vec::new(),
            limit: limit.min(MAX_BODY),
        }
    }

    /// Adds bytes read from the socket.
    pub fn push(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    /// Takes the next complete message, if one has arrived.
    ///
    /// Returns `Ok(None)` when more bytes are needed. Call it in a loop: one
    /// read can carry several messages.
    pub fn next_message(&mut self) -> Result<Option<Message>, VpcdError> {
        let Some(header) = self.buffer.get(..2) else {
            return Ok(None);
        };
        let len = u16::from_be_bytes([header[0], header[1]]) as usize;

        if len > self.limit {
            return Err(VpcdError::BodyTooLong {
                len,
                limit: self.limit,
            });
        }
        if self.buffer.len() < 2 + len {
            return Ok(None);
        }

        let body: Vec<u8> = self.buffer.drain(..2 + len).skip(2).collect();

        Ok(Some(match body.as_slice() {
            [] => Message::Empty,
            // Length one is a control message by definition, so this arm must
            // come before any APDU handling.
            [CTRL_OFF] => Message::PowerOff,
            [CTRL_ON] => Message::PowerOn,
            [CTRL_RESET] => Message::Reset,
            [CTRL_ATR] => Message::GetAtr,
            [other] => Message::UnknownControl(*other),
            _ => Message::Apdu(body),
        }))
    }

    /// How many bytes are buffered but not yet a complete message.
    pub fn pending(&self) -> usize {
        self.buffer.len()
    }
}

/// Answer-to-Reset values.
pub mod atr {
    /// The ATR the firmware presents: T=1, no historical bytes.
    ///
    /// `3B` is the direct convention; `80` says one interface byte follows and
    /// there are no historical bytes; `01` selects T=1; `81` is the checksum,
    /// mandatory for T=1 and equal to the exclusive-or of everything after
    /// `TS`. Kept identical to what the device reports over USB CCID so a host
    /// sees the same card on either transport.
    pub const T1_MINIMAL: [u8; 4] = [0x3B, 0x80, 0x01, 0x81];

    /// The exclusive-or check byte an ATR must end with when T=1 is offered.
    pub fn checksum(atr: &[u8]) -> u8 {
        atr.iter().skip(1).fold(0u8, |acc, &b| acc ^ b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn framed(body: &[u8]) -> Vec<u8> {
        frame(body).unwrap()
    }

    #[test]
    fn control_messages_decode_to_their_names() {
        // vpcd.h: OFF 0, ON 1, RESET 2, ATR 4. Note the gap at 3.
        let cases = [
            (CTRL_OFF, Message::PowerOff),
            (CTRL_ON, Message::PowerOn),
            (CTRL_RESET, Message::Reset),
            (CTRL_ATR, Message::GetAtr),
        ];
        for (byte, expected) in cases {
            let mut decoder = Decoder::default();
            decoder.push(&framed(&[byte]));
            assert_eq!(decoder.next_message().unwrap(), Some(expected));
        }
    }

    #[test]
    fn an_unassigned_control_byte_is_not_treated_as_an_apdu() {
        // 3 is in the gap. A one-byte message is a control message by
        // definition, so handing it to the card would invent a meaning.
        let mut decoder = Decoder::default();
        decoder.push(&framed(&[3]));
        assert_eq!(
            decoder.next_message().unwrap(),
            Some(Message::UnknownControl(3))
        );
    }

    #[test]
    fn an_apdu_decodes_whole() {
        let apdu = vec![0x00, 0xA4, 0x04, 0x00, 0x09];
        let mut decoder = Decoder::default();
        decoder.push(&framed(&apdu));
        assert_eq!(decoder.next_message().unwrap(), Some(Message::Apdu(apdu)));
    }

    #[test]
    fn a_message_split_across_reads_is_rejoined() {
        // TCP gives no message boundaries, so this is the normal case and not
        // an edge case.
        let apdu = vec![0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x05];
        let wire = framed(&apdu);

        let mut decoder = Decoder::default();
        for chunk in wire.chunks(3) {
            let before = decoder.next_message().unwrap();
            if before.is_some() {
                panic!("decoded before the whole message arrived");
            }
            decoder.push(chunk);
        }
        assert_eq!(decoder.next_message().unwrap(), Some(Message::Apdu(apdu)));
        assert_eq!(decoder.pending(), 0);
    }

    #[test]
    fn several_messages_in_one_read_all_decode() {
        let mut wire = framed(&[CTRL_ON]);
        wire.extend_from_slice(&framed(&[CTRL_ATR]));
        wire.extend_from_slice(&framed(&[0x00, 0xA4, 0x04, 0x00]));

        let mut decoder = Decoder::default();
        decoder.push(&wire);

        let mut seen = Vec::new();
        while let Some(message) = decoder.next_message().unwrap() {
            seen.push(message);
        }
        assert_eq!(
            seen,
            vec![
                Message::PowerOn,
                Message::GetAtr,
                Message::Apdu(vec![0x00, 0xA4, 0x04, 0x00]),
            ]
        );
    }

    #[test]
    fn a_zero_length_message_is_named_rather_than_dropped() {
        let mut decoder = Decoder::default();
        decoder.push(&framed(&[]));
        assert_eq!(decoder.next_message().unwrap(), Some(Message::Empty));
    }

    #[test]
    fn a_body_over_the_relay_ceiling_is_refused_before_it_is_buffered() {
        // The ceiling is what BLE can carry. Refusing at the header means the
        // daemon never buffers a body it has already decided not to relay.
        let mut decoder = Decoder::new(261);
        decoder.push(&[0x01, 0x00]); // declares 256 bytes, header only
        assert!(decoder.next_message().is_ok());

        let mut decoder = Decoder::new(261);
        decoder.push(&[0x02, 0x00]); // declares 512
        assert_eq!(
            decoder.next_message().unwrap_err(),
            VpcdError::BodyTooLong {
                len: 512,
                limit: 261
            }
        );
    }

    #[test]
    fn framing_is_two_bytes_big_endian() {
        assert_eq!(&framed(&[0xAA])[..2], &[0x00, 0x01]);
        assert_eq!(&framed(&vec![0u8; 300])[..2], &[0x01, 0x2C]);
        assert_eq!(framed(&[]), vec![0x00, 0x00]);
    }

    #[test]
    fn a_reply_too_long_for_the_prefix_is_refused() {
        assert_eq!(
            frame(&vec![0u8; 65536]).unwrap_err(),
            VpcdError::ReplyTooLong { len: 65536 }
        );
        assert!(frame(&vec![0u8; 65535]).is_ok());
    }

    #[test]
    fn the_atr_checksum_is_correct() {
        // TCK is mandatory when T=1 is offered, and a wrong one makes the OS
        // reject the card outright — with no useful diagnostic.
        let atr = atr::T1_MINIMAL;
        let (body, tck) = atr.split_at(atr.len() - 1);
        assert_eq!(atr::checksum(body), tck[0]);
    }
}
