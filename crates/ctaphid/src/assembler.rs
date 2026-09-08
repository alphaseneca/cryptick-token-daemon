//! Reassembling packets into messages, per channel.

use crate::{
    command::{Cmd, ErrorCode},
    message::Message,
    packet::{ChannelId, Packet, PacketKind},
    CONT_PAYLOAD_SIZE, INIT_PAYLOAD_SIZE, MAX_MESSAGE_LEN,
};
use std::collections::HashMap;

/// How many channels may have a message part-way through at once.
///
/// Real hosts use one or two. Any local process can write to the HID node
/// (PROJECT.md §14), so without a cap one could open channels until the daemon
/// runs out of memory.
pub const MAX_PENDING_CHANNELS: usize = 32;

/// A packet was rejected, and this is what to tell the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelError {
    /// The channel to send the `ERROR` packet on.
    pub channel: ChannelId,
    /// The code to send.
    pub code: ErrorCode,
}

impl ChannelError {
    /// The `ERROR` packet to write back.
    pub fn packet(self) -> Packet {
        Packet::error(self.channel, self.code)
    }
}

#[derive(Debug)]
struct Partial {
    command: Cmd,
    declared: usize,
    buf: Vec<u8>,
    next_seq: u8,
}

/// Reassembles CTAPHID packets into messages.
#[derive(Debug, Default)]
pub struct Assembler {
    partial: HashMap<ChannelId, Partial>,
}

impl Assembler {
    /// An assembler with no channels in progress.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether a message is part-way through on this channel.
    pub fn is_pending(&self, channel: ChannelId) -> bool {
        self.partial.contains_key(&channel)
    }

    /// How many channels are part-way through.
    pub fn pending_channels(&self) -> usize {
        self.partial.len()
    }

    /// Abandons whatever is in progress on a channel.
    ///
    /// Call this on `CTAPHID_CANCEL` and on transaction timeout, so a later
    /// packet cannot finish a message the host has already given up on.
    pub fn reset(&mut self, channel: ChannelId) {
        self.partial.remove(&channel);
    }

    /// Feeds one packet.
    ///
    /// Returns the message once its last packet arrives, `None` while more are
    /// expected or the packet was ignorable, and a [`ChannelError`] carrying the
    /// code to answer with otherwise. Any error abandons that channel's
    /// transaction (PROJECT.md §15.8).
    pub fn push(&mut self, packet: &Packet) -> Result<Option<Message>, ChannelError> {
        let channel = packet.channel();
        let fail = |code| ChannelError { channel, code };

        if channel == ChannelId::RESERVED {
            return Err(fail(ErrorCode::InvalidChannel));
        }

        match packet.kind() {
            PacketKind::Init {
                command,
                message_len,
            } => {
                let result = self.push_init(channel, command, message_len, packet.payload());
                if result.is_err() {
                    self.partial.remove(&channel);
                }
                result
            }
            PacketKind::Continuation { seq } => {
                let result = self.push_continuation(channel, seq, packet.payload());
                if result.is_err() {
                    self.partial.remove(&channel);
                }
                result
            }
        }
    }

    fn push_init(
        &mut self,
        channel: ChannelId,
        command: u8,
        message_len: u16,
        payload: &[u8],
    ) -> Result<Option<Message>, ChannelError> {
        let fail = |code| ChannelError { channel, code };

        let command = Cmd::from_u8(command).map_err(|_| fail(ErrorCode::InvalidCmd))?;

        // KEEPALIVE and ERROR only travel authenticator-to-host. A host sending
        // one is confused or probing.
        if !command.is_request() {
            return Err(fail(ErrorCode::InvalidCmd));
        }

        // The broadcast channel exists only so a host can ask for a real one.
        if channel == ChannelId::BROADCAST && command != Cmd::Init {
            return Err(fail(ErrorCode::InvalidChannel));
        }

        let declared = message_len as usize;
        if declared > MAX_MESSAGE_LEN {
            return Err(fail(ErrorCode::InvalidLen));
        }

        if command == Cmd::Init {
            // CTAPHID_INIT synchronises a channel: whatever was in flight on it
            // is deliberately discarded. That is the documented way for a host
            // to recover a wedged channel, so it must not be an error.
            self.partial.remove(&channel);
        } else if self.partial.contains_key(&channel) {
            // A new message starting before the last one finished. The packet
            // stream is out of order; fail closed rather than guessing which
            // message the host meant.
            return Err(fail(ErrorCode::InvalidSeq));
        }

        let take = declared.min(INIT_PAYLOAD_SIZE).min(payload.len());
        let data = &payload[..take];

        if declared <= INIT_PAYLOAD_SIZE {
            return Ok(Some(Message::new(channel, command, data.to_vec())));
        }

        if self.partial.len() >= MAX_PENDING_CHANNELS {
            return Err(fail(ErrorCode::ChannelBusy));
        }

        // Bounded by MAX_MESSAGE_LEN, checked above.
        let mut buf = Vec::with_capacity(declared);
        buf.extend_from_slice(data);
        self.partial.insert(
            channel,
            Partial {
                command,
                declared,
                buf,
                next_seq: 0,
            },
        );
        Ok(None)
    }

    fn push_continuation(
        &mut self,
        channel: ChannelId,
        seq: u8,
        payload: &[u8],
    ) -> Result<Option<Message>, ChannelError> {
        let fail = |code| ChannelError { channel, code };

        if channel == ChannelId::BROADCAST {
            return Err(fail(ErrorCode::InvalidChannel));
        }

        let Some(partial) = self.partial.get_mut(&channel) else {
            // The spec says spurious continuations are ignored rather than
            // rejected. Answering with an error would break hosts that send a
            // trailing packet after cancelling, and nothing is allocated here,
            // so ignoring costs nothing.
            return Ok(None);
        };

        if seq != partial.next_seq {
            return Err(fail(ErrorCode::InvalidSeq));
        }

        let remaining = partial.declared - partial.buf.len();
        // Packets are padded to 64 bytes, so the last one carries fewer real
        // bytes than it has room for. The declared length decides, never the
        // packet.
        let take = remaining.min(CONT_PAYLOAD_SIZE).min(payload.len());
        partial.buf.extend_from_slice(&payload[..take]);
        partial.next_seq += 1;

        if partial.buf.len() == partial.declared {
            let partial = self.partial.remove(&channel).expect("just borrowed it");
            return Ok(Some(Message::new(channel, partial.command, partial.buf)));
        }
        Ok(None)
    }
}

/// Hands out channel identifiers for `CTAPHID_INIT`.
#[derive(Debug)]
pub struct ChannelAllocator {
    next: u32,
}

impl Default for ChannelAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl ChannelAllocator {
    /// An allocator starting from the first usable channel.
    pub fn new() -> Self {
        Self { next: 1 }
    }

    /// Allocates the next channel, skipping the reserved and broadcast values.
    pub fn allocate(&mut self) -> ChannelId {
        loop {
            let candidate = ChannelId(self.next);
            self.next = self.next.wrapping_add(1);
            if candidate.is_assignable() {
                return candidate;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assemble(assembler: &mut Assembler, message: &Message) -> Option<Message> {
        let mut out = None;
        for packet in message.packets().expect("message fits") {
            out = assembler.push(&packet).expect("our own packets are valid");
        }
        out
    }

    #[test]
    fn a_message_round_trips_at_every_interesting_length() {
        for len in [
            0usize,
            1,
            INIT_PAYLOAD_SIZE - 1,
            INIT_PAYLOAD_SIZE,
            INIT_PAYLOAD_SIZE + 1,
            INIT_PAYLOAD_SIZE + CONT_PAYLOAD_SIZE,
            1000,
            MAX_MESSAGE_LEN,
        ] {
            let message = Message::new(
                ChannelId(0x1234),
                Cmd::Cbor,
                (0..len).map(|i| i as u8).collect(),
            );
            let mut assembler = Assembler::new();
            assert_eq!(
                assemble(&mut assembler, &message),
                Some(message),
                "len {len}"
            );
            assert_eq!(assembler.pending_channels(), 0);
        }
    }

    #[test]
    fn padding_in_the_last_packet_is_not_treated_as_data() {
        // The declared length decides, not the 64-byte packet.
        let message = Message::new(ChannelId(1), Cmd::Cbor, vec![0x7e; INIT_PAYLOAD_SIZE + 5]);
        let mut assembler = Assembler::new();
        let got = assemble(&mut assembler, &message).expect("completes");
        assert_eq!(got.payload.len(), INIT_PAYLOAD_SIZE + 5);
    }

    #[test]
    fn two_channels_interleave_without_corrupting_each_other() {
        // Browsers really do this.
        let a = Message::new(ChannelId(0xaaaa), Cmd::Cbor, vec![0xa1; 300]);
        let b = Message::new(ChannelId(0xbbbb), Cmd::Cbor, vec![0xb2; 400]);
        let pa: Vec<_> = a.packets().unwrap().collect();
        let pb: Vec<_> = b.packets().unwrap().collect();

        let mut assembler = Assembler::new();
        let mut done_a = None;
        let mut done_b = None;
        for i in 0..pa.len().max(pb.len()) {
            if let Some(p) = pa.get(i) {
                if let Some(m) = assembler.push(p).unwrap() {
                    done_a = Some(m);
                }
            }
            if let Some(p) = pb.get(i) {
                if let Some(m) = assembler.push(p).unwrap() {
                    done_b = Some(m);
                }
            }
        }
        assert_eq!(done_a, Some(a));
        assert_eq!(done_b, Some(b));
    }

    #[test]
    fn the_reserved_channel_is_refused() {
        let mut assembler = Assembler::new();
        let packet = Packet::init(ChannelId::RESERVED, Cmd::Cbor, 0, &[]);
        assert_eq!(
            assembler.push(&packet),
            Err(ChannelError {
                channel: ChannelId::RESERVED,
                code: ErrorCode::InvalidChannel
            })
        );
    }

    #[test]
    fn only_init_may_use_the_broadcast_channel() {
        let mut assembler = Assembler::new();
        let packet = Packet::init(ChannelId::BROADCAST, Cmd::Cbor, 0, &[]);
        assert_eq!(
            assembler.push(&packet).unwrap_err().code,
            ErrorCode::InvalidChannel
        );

        let packet = Packet::init(ChannelId::BROADCAST, Cmd::Init, 8, &[0; 8]);
        assert!(assembler.push(&packet).unwrap().is_some());
    }

    #[test]
    fn a_host_may_not_send_keepalive_or_error() {
        let mut assembler = Assembler::new();
        for cmd in [Cmd::Keepalive, Cmd::Error] {
            let packet = Packet::init(ChannelId(1), cmd, 1, &[0x01]);
            assert_eq!(
                assembler.push(&packet).unwrap_err().code,
                ErrorCode::InvalidCmd,
                "{cmd:?}"
            );
        }
    }

    #[test]
    fn an_unknown_command_is_refused() {
        let mut bytes = [0u8; 64];
        bytes[..4].copy_from_slice(&ChannelId(1).to_bytes());
        bytes[4] = 0x80 | 0x2a;
        let packet = Packet::parse(&bytes).unwrap();
        assert_eq!(
            Assembler::new().push(&packet).unwrap_err().code,
            ErrorCode::InvalidCmd
        );
    }

    #[test]
    fn a_declared_length_over_the_maximum_is_refused_before_buffering() {
        let mut bytes = [0u8; 64];
        bytes[..4].copy_from_slice(&ChannelId(1).to_bytes());
        bytes[4] = Cmd::Cbor.as_init_byte();
        bytes[5..7].copy_from_slice(&u16::MAX.to_be_bytes());
        let packet = Packet::parse(&bytes).unwrap();

        let mut assembler = Assembler::new();
        assert_eq!(
            assembler.push(&packet).unwrap_err().code,
            ErrorCode::InvalidLen
        );
        assert_eq!(assembler.pending_channels(), 0, "nothing may be buffered");
    }

    #[test]
    fn an_out_of_order_continuation_is_refused_and_abandons_the_channel() {
        let message = Message::new(ChannelId(1), Cmd::Cbor, vec![0x33; 300]);
        let packets: Vec<_> = message.packets().unwrap().collect();

        let mut assembler = Assembler::new();
        assembler.push(&packets[0]).unwrap();
        assembler.push(&packets[1]).unwrap();
        assert!(assembler.is_pending(ChannelId(1)));

        // Expecting SEQ 1, sending 3.
        assert_eq!(
            assembler.push(&packets[3]).unwrap_err().code,
            ErrorCode::InvalidSeq
        );
        assert!(
            !assembler.is_pending(ChannelId(1)),
            "the channel must reset"
        );
    }

    #[test]
    fn a_spurious_continuation_is_ignored_not_rejected() {
        // Per spec. Hosts send these after cancelling, and nothing is
        // allocated, so answering with an error would only break interop.
        let mut assembler = Assembler::new();
        let packet = Packet::continuation(ChannelId(1), 0, &[0xff; 59]);
        assert_eq!(assembler.push(&packet), Ok(None));
        assert_eq!(assembler.pending_channels(), 0);
    }

    #[test]
    fn a_new_message_before_the_last_one_finished_is_refused() {
        let mut assembler = Assembler::new();
        let first = Packet::init(ChannelId(1), Cmd::Cbor, 300, &[0x11; 57]);
        assembler.push(&first).unwrap();

        let second = Packet::init(ChannelId(1), Cmd::Cbor, 300, &[0x22; 57]);
        assert_eq!(
            assembler.push(&second).unwrap_err().code,
            ErrorCode::InvalidSeq
        );
        assert!(!assembler.is_pending(ChannelId(1)));
    }

    #[test]
    fn ctaphid_init_resynchronises_a_wedged_channel() {
        // This is the documented recovery path, so it must not be an error.
        let mut assembler = Assembler::new();
        let stuck = Packet::init(ChannelId(1), Cmd::Cbor, 5000, &[0x11; 57]);
        assembler.push(&stuck).unwrap();
        assert!(assembler.is_pending(ChannelId(1)));

        let init = Packet::init(ChannelId(1), Cmd::Init, 8, &[0x42; 8]);
        let message = assembler
            .push(&init)
            .unwrap()
            .expect("INIT completes at once");
        assert_eq!(message.command, Cmd::Init);
        assert_eq!(message.payload, vec![0x42; 8]);
        assert!(!assembler.is_pending(ChannelId(1)));
    }

    #[test]
    fn reset_discards_a_partial_message() {
        let mut assembler = Assembler::new();
        assembler
            .push(&Packet::init(ChannelId(1), Cmd::Cbor, 300, &[0x11; 57]))
            .unwrap();
        assembler.reset(ChannelId(1));
        assert!(!assembler.is_pending(ChannelId(1)));
        // The continuation that would have finished it is now orphaned.
        assert_eq!(
            assembler.push(&Packet::continuation(ChannelId(1), 0, &[0x11; 59])),
            Ok(None)
        );
    }

    #[test]
    fn pending_channels_are_capped() {
        // Otherwise any local process can exhaust memory by opening channels.
        let mut assembler = Assembler::new();
        for cid in 1..=MAX_PENDING_CHANNELS as u32 {
            let packet = Packet::init(ChannelId(cid), Cmd::Cbor, 300, &[0u8; 57]);
            assembler.push(&packet).expect("under the cap");
        }
        assert_eq!(assembler.pending_channels(), MAX_PENDING_CHANNELS);

        let packet = Packet::init(ChannelId(9999), Cmd::Cbor, 300, &[0u8; 57]);
        assert_eq!(
            assembler.push(&packet).unwrap_err().code,
            ErrorCode::ChannelBusy
        );
    }

    #[test]
    fn the_allocator_never_hands_out_a_reserved_channel() {
        let mut allocator = ChannelAllocator::new();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1000 {
            let cid = allocator.allocate();
            assert!(cid.is_assignable(), "{cid:?}");
            assert!(seen.insert(cid), "allocated {cid:?} twice");
        }
    }

    #[test]
    fn the_allocator_skips_the_reserved_values_when_it_wraps() {
        let mut allocator = ChannelAllocator { next: u32::MAX - 1 };
        for _ in 0..4 {
            assert!(allocator.allocate().is_assignable());
        }
    }
}
