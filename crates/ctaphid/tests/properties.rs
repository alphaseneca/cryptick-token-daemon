//! Property tests for the CTAPHID framing invariants.

use ctaphid::{Assembler, ChannelId, Cmd, Message, Packet, MAX_MESSAGE_LEN, PACKET_SIZE};
use proptest::prelude::*;

fn any_request_cmd() -> impl Strategy<Value = Cmd> {
    prop_oneof![
        Just(Cmd::Ping),
        Just(Cmd::Msg),
        Just(Cmd::Cbor),
        Just(Cmd::Init),
        Just(Cmd::Cancel),
        Just(Cmd::Wink),
        Just(Cmd::Lock),
    ]
}

fn any_channel() -> impl Strategy<Value = ChannelId> {
    (1u32..0xffff_fffe).prop_map(ChannelId)
}

proptest! {
    /// Splitting into packets and reassembling is the identity.
    #[test]
    fn round_trip(
        channel in any_channel(),
        command in any_request_cmd(),
        payload in prop::collection::vec(any::<u8>(), 0..3000),
    ) {
        let sent = Message::new(channel, command, payload);
        let mut assembler = Assembler::new();
        let mut received = None;
        for packet in sent.packets().expect("payload fits") {
            received = assembler.push(&packet).expect("our own packets are valid");
        }
        prop_assert_eq!(received, Some(sent));
        prop_assert_eq!(assembler.pending_channels(), 0);
    }

    /// Every packet we emit is exactly 64 bytes, and only the first sets the
    /// high bit that marks an initialization packet.
    #[test]
    fn emitted_packets_are_well_formed(
        channel in any_channel(),
        payload in prop::collection::vec(any::<u8>(), 0..3000),
    ) {
        let message = Message::new(channel, Cmd::Cbor, payload);
        for (i, packet) in message.packets().expect("fits").enumerate() {
            prop_assert_eq!(packet.as_bytes().len(), PACKET_SIZE);
            prop_assert_eq!(packet.channel(), channel);
            let marker = packet.as_bytes()[4] & 0x80;
            if i == 0 {
                prop_assert_ne!(marker, 0);
            } else {
                prop_assert_eq!(marker, 0);
            }
        }
    }

    /// Arbitrary bytes must never panic the assembler. This is the same surface
    /// the `ctaphid_frames` fuzz target covers, checked on every PR without a
    /// nightly toolchain.
    #[test]
    fn arbitrary_packets_never_panic(
        packets in prop::collection::vec(
            prop::collection::vec(any::<u8>(), PACKET_SIZE..=PACKET_SIZE),
            0..64,
        ),
    ) {
        let mut assembler = Assembler::new();
        for bytes in &packets {
            if let Ok(packet) = Packet::parse(bytes) {
                let _ = assembler.push(&packet);
            }
        }
        // Whatever happened, the cap holds.
        prop_assert!(assembler.pending_channels() <= ctaphid::MAX_PENDING_CHANNELS);
    }

    /// A message declared longer than the sequence space allows is refused
    /// before a single byte is buffered.
    #[test]
    fn over_long_declarations_buffer_nothing(
        declared in (MAX_MESSAGE_LEN as u16 + 1)..=u16::MAX,
    ) {
        let mut bytes = [0u8; PACKET_SIZE];
        bytes[..4].copy_from_slice(&ChannelId(1).to_bytes());
        bytes[4] = Cmd::Cbor.as_init_byte();
        bytes[5..7].copy_from_slice(&declared.to_be_bytes());

        let mut assembler = Assembler::new();
        prop_assert!(assembler.push(&Packet::parse(&bytes).unwrap()).is_err());
        prop_assert_eq!(assembler.pending_channels(), 0);
    }

    /// A truncated packet stream never yields a message.
    #[test]
    fn dropping_the_last_packet_never_completes(
        payload in prop::collection::vec(any::<u8>(), 100..3000),
    ) {
        let message = Message::new(ChannelId(1), Cmd::Cbor, payload);
        let packets: Vec<_> = message.packets().expect("fits").collect();
        prop_assume!(packets.len() > 1);

        let mut assembler = Assembler::new();
        for packet in &packets[..packets.len() - 1] {
            prop_assert_eq!(assembler.push(packet).expect("valid"), None);
        }
        prop_assert!(assembler.is_pending(ChannelId(1)));
    }
}
