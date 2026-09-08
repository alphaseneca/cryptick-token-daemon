//! The 64-byte packet, in both directions.

use crate::{
    command::{Cmd, ErrorCode, KeepaliveStatus},
    CtaphidError, CONT_PAYLOAD_SIZE, INIT_PAYLOAD_SIZE, PACKET_SIZE,
};

/// A CTAPHID channel identifier.
///
/// Four bytes on the wire. Their interpretation is opaque — the authenticator
/// allocates a value and the host echoes it back — so only self-consistency
/// matters. Little-endian is used throughout to match every implementation that
/// overlays a struct on the packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChannelId(pub u32);

impl ChannelId {
    /// The channel a host uses before it has been allocated one. Only
    /// `CTAPHID_INIT` may be sent on it.
    pub const BROADCAST: ChannelId = ChannelId(0xffff_ffff);

    /// Reserved and never valid.
    pub const RESERVED: ChannelId = ChannelId(0x0000_0000);

    /// Whether this channel may carry a transaction.
    pub const fn is_assignable(self) -> bool {
        self.0 != Self::BROADCAST.0 && self.0 != Self::RESERVED.0
    }

    /// The four wire bytes.
    pub const fn to_bytes(self) -> [u8; 4] {
        self.0.to_le_bytes()
    }

    /// From the four wire bytes.
    pub const fn from_bytes(bytes: [u8; 4]) -> Self {
        Self(u32::from_le_bytes(bytes))
    }
}

/// What a packet is, once its header has been read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketKind {
    /// Starts a message.
    Init {
        /// The command byte, high bit already stripped.
        command: u8,
        /// The length of the whole message, not of this packet.
        message_len: u16,
    },
    /// Continues one.
    Continuation {
        /// The sequence number, `0x00`..=`0x7f`.
        seq: u8,
    },
}

/// One 64-byte CTAPHID packet.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Packet([u8; PACKET_SIZE]);

impl std::fmt::Debug for Packet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Header only. Packet payloads carry CBOR, which may contain PIN
        // protocol material (PROJECT.md §15.5).
        f.debug_struct("Packet")
            .field("channel", &self.channel())
            .field("kind", &self.kind())
            .field("payload_len", &self.payload().len())
            .finish_non_exhaustive()
    }
}

impl Packet {
    /// Parses a report from the HID node.
    ///
    /// Requires exactly [`PACKET_SIZE`] bytes. Reports are always padded to that
    /// length, so anything else is malformed rather than merely short — and
    /// accepting a short one would mean reading past the end of a caller's
    /// buffer conceptually, which is precisely the class of bug this surface
    /// attracts.
    pub fn parse(bytes: &[u8]) -> Result<Self, CtaphidError> {
        let array: [u8; PACKET_SIZE] = bytes
            .try_into()
            .map_err(|_| CtaphidError::WrongPacketSize { len: bytes.len() })?;
        Ok(Self(array))
    }

    /// The raw bytes, ready to write to the HID node.
    pub const fn as_bytes(&self) -> &[u8; PACKET_SIZE] {
        &self.0
    }

    /// The channel this packet belongs to.
    pub const fn channel(&self) -> ChannelId {
        ChannelId::from_bytes([self.0[0], self.0[1], self.0[2], self.0[3]])
    }

    /// Whether this starts a message or continues one.
    pub const fn kind(&self) -> PacketKind {
        let byte = self.0[4];
        if byte & 0x80 != 0 {
            PacketKind::Init {
                command: byte & 0x7f,
                // BCNT is big-endian, unlike the channel id.
                message_len: u16::from_be_bytes([self.0[5], self.0[6]]),
            }
        } else {
            PacketKind::Continuation { seq: byte }
        }
    }

    /// The payload region, still including any padding.
    ///
    /// How much of it is real is decided by the message length in the
    /// initialization packet, never by the packet itself.
    pub fn payload(&self) -> &[u8] {
        match self.kind() {
            PacketKind::Init { .. } => &self.0[7..],
            PacketKind::Continuation { .. } => &self.0[5..],
        }
    }

    fn build(channel: ChannelId, header: &[u8], data: &[u8]) -> Self {
        let mut bytes = [0u8; PACKET_SIZE];
        bytes[..4].copy_from_slice(&channel.to_bytes());
        bytes[4..4 + header.len()].copy_from_slice(header);
        let start = 4 + header.len();
        // Everything after the data stays zero: reports are padded, and the
        // padding must not leak whatever was in the buffer before.
        bytes[start..start + data.len()].copy_from_slice(data);
        Self(bytes)
    }

    /// Builds an initialization packet. `data` is truncated to fit.
    pub fn init(channel: ChannelId, command: Cmd, message_len: u16, data: &[u8]) -> Self {
        let take = data.len().min(INIT_PAYLOAD_SIZE);
        let len = message_len.to_be_bytes();
        Self::build(
            channel,
            &[command.as_init_byte(), len[0], len[1]],
            &data[..take],
        )
    }

    /// Builds a continuation packet. `data` is truncated to fit.
    pub fn continuation(channel: ChannelId, seq: u8, data: &[u8]) -> Self {
        let take = data.len().min(CONT_PAYLOAD_SIZE);
        Self::build(channel, &[seq & 0x7f], &data[..take])
    }

    /// Builds an `ERROR` response.
    pub fn error(channel: ChannelId, code: ErrorCode) -> Self {
        Self::init(channel, Cmd::Error, 1, &[code.as_u8()])
    }

    /// Builds a `KEEPALIVE` response.
    ///
    /// Sent while the device is working — including while it waits for a
    /// fingerprint. Without these the host gives up (PROJECT.md §15.3).
    pub fn keepalive(channel: ChannelId, status: KeepaliveStatus) -> Self {
        Self::init(channel, Cmd::Keepalive, 1, &[status.as_u8()])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_packet_must_be_exactly_64_bytes() {
        assert!(Packet::parse(&[0u8; 64]).is_ok());
        for len in [0usize, 1, 7, 63, 65, 128] {
            assert_eq!(
                Packet::parse(&vec![0u8; len]),
                Err(CtaphidError::WrongPacketSize { len })
            );
        }
    }

    #[test]
    fn an_init_packet_round_trips_its_header() {
        let packet = Packet::init(ChannelId(0x1234_5678), Cmd::Cbor, 300, &[0xaa; 57]);
        assert_eq!(packet.channel(), ChannelId(0x1234_5678));
        assert_eq!(
            packet.kind(),
            PacketKind::Init {
                command: 0x10,
                message_len: 300
            }
        );
        assert_eq!(packet.payload().len(), INIT_PAYLOAD_SIZE);
    }

    #[test]
    fn the_channel_is_little_endian_and_the_length_is_big_endian() {
        // Getting these the same way round is the classic CTAPHID bug.
        let packet = Packet::init(ChannelId(0x0403_0201), Cmd::Ping, 0x1234, &[]);
        let bytes = packet.as_bytes();
        assert_eq!(&bytes[..4], &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(bytes[4], 0x81);
        assert_eq!(&bytes[5..7], &[0x12, 0x34]);
    }

    #[test]
    fn a_continuation_packet_round_trips() {
        let packet = Packet::continuation(ChannelId(9), 0x7f, &[0xbb; 59]);
        assert_eq!(packet.kind(), PacketKind::Continuation { seq: 0x7f });
        assert_eq!(packet.payload().len(), CONT_PAYLOAD_SIZE);
    }

    #[test]
    fn the_high_bit_alone_decides_the_packet_kind() {
        let mut bytes = [0u8; 64];
        bytes[4] = 0x80;
        assert!(matches!(
            Packet::parse(&bytes).unwrap().kind(),
            PacketKind::Init { command: 0, .. }
        ));
        bytes[4] = 0x7f;
        assert!(matches!(
            Packet::parse(&bytes).unwrap().kind(),
            PacketKind::Continuation { seq: 0x7f }
        ));
    }

    #[test]
    fn short_data_is_zero_padded_not_left_uninitialised() {
        let packet = Packet::init(ChannelId(1), Cmd::Cbor, 2, &[0xff, 0xee]);
        assert_eq!(packet.as_bytes()[7], 0xff);
        assert_eq!(packet.as_bytes()[8], 0xee);
        assert!(packet.as_bytes()[9..].iter().all(|&b| b == 0));
    }

    #[test]
    fn oversized_data_is_truncated_rather_than_panicking() {
        let packet = Packet::init(ChannelId(1), Cmd::Cbor, 9999, &[0x11; 200]);
        assert_eq!(packet.payload().len(), INIT_PAYLOAD_SIZE);
        let packet = Packet::continuation(ChannelId(1), 0, &[0x11; 200]);
        assert_eq!(packet.payload().len(), CONT_PAYLOAD_SIZE);
    }

    #[test]
    fn reserved_and_broadcast_channels_are_not_assignable() {
        assert!(!ChannelId::BROADCAST.is_assignable());
        assert!(!ChannelId::RESERVED.is_assignable());
        assert!(ChannelId(1).is_assignable());
    }

    #[test]
    fn error_and_keepalive_packets_carry_one_byte() {
        let packet = Packet::error(ChannelId(7), ErrorCode::InvalidSeq);
        assert_eq!(
            packet.kind(),
            PacketKind::Init {
                command: 0x3f,
                message_len: 1
            }
        );
        assert_eq!(packet.payload()[0], 0x04);

        let packet = Packet::keepalive(ChannelId(7), KeepaliveStatus::UpNeeded);
        assert_eq!(packet.payload()[0], 0x02);
    }

    #[test]
    fn debug_does_not_print_the_payload() {
        // Payloads carry CBOR, which can contain PIN protocol material.
        let packet = Packet::init(ChannelId(1), Cmd::Cbor, 4, &[0xde, 0xad, 0xbe, 0xef]);
        let text = format!("{packet:?}");
        assert!(!text.contains("222"), "{text}");
        assert!(!text.contains("de"), "{text}");
    }
}
