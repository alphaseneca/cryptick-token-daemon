//! A whole CTAPHID message, and turning one into packets.

use crate::{
    command::Cmd,
    packet::{ChannelId, Packet},
    CtaphidError, CONT_PAYLOAD_SIZE, INIT_PAYLOAD_SIZE, MAX_MESSAGE_LEN,
};

/// Capability: the device supports `CTAPHID_WINK`.
pub const CAPABILITY_WINK: u8 = 0x01;
/// Capability: the device supports `CTAPHID_CBOR`. Required for CTAP2.
pub const CAPABILITY_CBOR: u8 = 0x04;
/// Capability: the device does **not** support `CTAPHID_MSG` (CTAP1/U2F).
pub const CAPABILITY_NMSG: u8 = 0x08;

/// A reassembled CTAPHID message.
#[derive(Clone, PartialEq, Eq)]
pub struct Message {
    /// The channel it belongs to.
    pub channel: ChannelId,
    /// The command.
    pub command: Cmd,
    /// The payload, concatenated across every packet and with padding removed.
    pub payload: Vec<u8>,
}

impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Length only: payloads carry CBOR (PROJECT.md §15.5).
        f.debug_struct("Message")
            .field("channel", &self.channel)
            .field("command", &self.command)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

impl Message {
    /// Builds a message.
    pub fn new(channel: ChannelId, command: Cmd, payload: Vec<u8>) -> Self {
        Self {
            channel,
            command,
            payload,
        }
    }

    /// Builds the 17-byte `CTAPHID_INIT` response.
    ///
    /// Sent on the channel the request arrived on — the broadcast channel when
    /// the host is asking for an allocation — and carries the newly allocated
    /// channel for it to use from then on.
    pub fn init_response(
        reply_on: ChannelId,
        nonce: [u8; 8],
        allocated: ChannelId,
        version: (u8, u8, u8),
        capabilities: u8,
    ) -> Self {
        let mut payload = Vec::with_capacity(17);
        payload.extend_from_slice(&nonce);
        payload.extend_from_slice(&allocated.to_bytes());
        payload.push(2); // CTAPHID protocol version
        payload.push(version.0);
        payload.push(version.1);
        payload.push(version.2);
        payload.push(capabilities);
        Self::new(reply_on, Cmd::Init, payload)
    }

    /// How many packets this message needs.
    pub fn packet_count(&self) -> Result<usize, CtaphidError> {
        let len = self.payload.len();
        if len > MAX_MESSAGE_LEN {
            return Err(CtaphidError::MessageTooLong { len });
        }
        if len <= INIT_PAYLOAD_SIZE {
            // A zero-length message still needs its initialization packet,
            // which is how CANCEL is sent.
            return Ok(1);
        }
        Ok(1 + (len - INIT_PAYLOAD_SIZE).div_ceil(CONT_PAYLOAD_SIZE))
    }

    /// Splits into packets, ready to write to the HID node.
    pub fn packets(&self) -> Result<Packets<'_>, CtaphidError> {
        let remaining = self.packet_count()?;
        Ok(Packets {
            message: self,
            offset: 0,
            seq: 0,
            sent_init: false,
            remaining,
        })
    }
}

/// An iterator over a message's packets, in wire order.
#[derive(Debug, Clone)]
pub struct Packets<'a> {
    message: &'a Message,
    offset: usize,
    seq: u8,
    sent_init: bool,
    remaining: usize,
}

impl Iterator for Packets<'_> {
    type Item = Packet;

    fn next(&mut self) -> Option<Packet> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        let payload = &self.message.payload;

        if !self.sent_init {
            self.sent_init = true;
            let take = payload.len().min(INIT_PAYLOAD_SIZE);
            self.offset = take;
            // The cast is safe: packet_count rejected anything over
            // MAX_MESSAGE_LEN, which is well under u16::MAX.
            return Some(Packet::init(
                self.message.channel,
                self.message.command,
                payload.len() as u16,
                &payload[..take],
            ));
        }

        let take = (payload.len() - self.offset).min(CONT_PAYLOAD_SIZE);
        let packet = Packet::continuation(
            self.message.channel,
            self.seq,
            &payload[self.offset..self.offset + take],
        );
        self.offset += take;
        // No wrap: SEQ runs out at 0x7f, which is why MAX_MESSAGE_LEN exists.
        self.seq += 1;
        Some(packet)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for Packets<'_> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_message_is_one_packet() {
        let message = Message::new(ChannelId(1), Cmd::Cancel, Vec::new());
        let packets: Vec<_> = message.packets().unwrap().collect();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].as_bytes()[4], Cmd::Cancel.as_init_byte());
    }

    #[test]
    fn a_message_that_exactly_fills_the_init_packet_needs_no_continuation() {
        let message = Message::new(ChannelId(1), Cmd::Cbor, vec![0xaa; INIT_PAYLOAD_SIZE]);
        assert_eq!(message.packet_count().unwrap(), 1);
        assert_eq!(message.packets().unwrap().count(), 1);
    }

    #[test]
    fn one_byte_more_adds_a_continuation() {
        let message = Message::new(ChannelId(1), Cmd::Cbor, vec![0xaa; INIT_PAYLOAD_SIZE + 1]);
        let packets: Vec<_> = message.packets().unwrap().collect();
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[1].as_bytes()[4], 0x00);
        assert_eq!(packets[1].as_bytes()[5], 0xaa);
    }

    #[test]
    fn every_packet_is_64_bytes() {
        let message = Message::new(ChannelId(1), Cmd::Cbor, vec![0x5a; 1000]);
        for packet in message.packets().unwrap() {
            assert_eq!(packet.as_bytes().len(), 64);
        }
    }

    #[test]
    fn the_largest_message_uses_every_sequence_number_exactly_once() {
        let message = Message::new(ChannelId(1), Cmd::Cbor, vec![0x11; MAX_MESSAGE_LEN]);
        let packets: Vec<_> = message.packets().unwrap().collect();
        assert_eq!(packets.len(), 129, "one init plus 128 continuations");

        let seqs: Vec<u8> = packets[1..].iter().map(|p| p.as_bytes()[4]).collect();
        assert_eq!(seqs.first(), Some(&0x00));
        assert_eq!(seqs.last(), Some(&crate::MAX_SEQ));
        // No wrapping, unlike the BLE transport.
        assert!(seqs.windows(2).all(|w| w[1] == w[0] + 1));
    }

    #[test]
    fn a_message_over_the_maximum_is_rejected_rather_than_wrapping_seq() {
        let message = Message::new(ChannelId(1), Cmd::Cbor, vec![0u8; MAX_MESSAGE_LEN + 1]);
        assert_eq!(
            message.packet_count(),
            Err(CtaphidError::MessageTooLong {
                len: MAX_MESSAGE_LEN + 1
            })
        );
        assert!(message.packets().is_err());
    }

    #[test]
    fn the_init_response_has_the_documented_shape() {
        let message = Message::init_response(
            ChannelId::BROADCAST,
            [1, 2, 3, 4, 5, 6, 7, 8],
            ChannelId(0x0a0b_0c0d),
            (1, 2, 3),
            CAPABILITY_CBOR | CAPABILITY_NMSG,
        );
        assert_eq!(message.payload.len(), 17);
        assert_eq!(&message.payload[..8], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(&message.payload[8..12], &[0x0d, 0x0c, 0x0b, 0x0a]);
        assert_eq!(message.payload[12], 2, "CTAPHID protocol version");
        assert_eq!(&message.payload[13..16], &[1, 2, 3]);
        assert_eq!(message.payload[16], 0x0c);
        // It fits in a single packet, which every host relies on.
        assert_eq!(message.packet_count().unwrap(), 1);
    }

    #[test]
    fn debug_does_not_print_the_payload() {
        let message = Message::new(ChannelId(1), Cmd::Cbor, vec![0xde, 0xad, 0xbe, 0xef]);
        let text = format!("{message:?}");
        assert!(text.contains("payload_len: 4"), "{text}");
        assert!(!text.contains("222"), "{text}");
    }
}
