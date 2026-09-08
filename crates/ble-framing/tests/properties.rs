//! Property tests for the framing invariants.
//!
//! The example-based tests in the modules pin down specific boundaries; these
//! assert the invariants hold across the whole input space.

use ble_framing::{fragments, Command, FragmentSize, Message, Reassembler, MAX_FRAGMENT_SIZE};
use proptest::prelude::*;

fn any_command() -> impl Strategy<Value = Command> {
    prop_oneof![
        Just(Command::Ping),
        Just(Command::KeepAlive),
        Just(Command::Msg),
        Just(Command::Cancel),
        Just(Command::Error),
    ]
}

fn any_size() -> impl Strategy<Value = FragmentSize> {
    (20u16..=MAX_FRAGMENT_SIZE)
        .prop_map(|n| FragmentSize::new(n).expect("in range by construction"))
}

proptest! {
    /// Fragmenting and reassembling is the identity, at every legal size.
    #[test]
    fn round_trip(
        command in any_command(),
        payload in prop::collection::vec(any::<u8>(), 0..4096),
        size in any_size(),
    ) {
        let sent = Message::new(command, payload);
        let mut rx = Reassembler::new(size);
        let mut received = None;
        for fragment in fragments(&sent, size).expect("payload fits in HLEN") {
            received = rx.push(&fragment).expect("our own fragments are well formed");
        }
        prop_assert_eq!(received, Some(sent));
        prop_assert!(!rx.in_progress());
    }

    /// Every fragment we emit is non-empty and fits the negotiated size, and
    /// every continuation carries a 7-bit sequence number.
    #[test]
    fn emitted_fragments_are_well_formed(
        command in any_command(),
        payload in prop::collection::vec(any::<u8>(), 0..4096),
        size in any_size(),
    ) {
        let msg = Message::new(command, payload);
        for (i, fragment) in fragments(&msg, size).expect("payload fits").enumerate() {
            prop_assert!(!fragment.is_empty());
            prop_assert!(fragment.len() <= size.get() as usize);
            if i == 0 {
                prop_assert_ne!(fragment[0] & 0x80, 0, "init fragment needs the high bit");
            } else {
                prop_assert_eq!(fragment[0] & 0x80, 0, "continuation must not set it");
            }
        }
    }

    /// Arbitrary bytes must never panic the reassembler. This is the same
    /// surface the `ble_reassembly` fuzz target covers; keeping it here means
    /// it is checked on every PR without a nightly toolchain.
    #[test]
    fn arbitrary_fragments_never_panic(
        fragments in prop::collection::vec(
            prop::collection::vec(any::<u8>(), 0..600),
            0..40,
        ),
        size in any_size(),
    ) {
        let mut rx = Reassembler::with_max_message_len(size, 1200);
        for fragment in &fragments {
            let _ = rx.push(fragment);
        }
    }

    /// A truncated stream never yields a message, however far it got.
    #[test]
    fn dropping_the_last_fragment_never_completes(
        payload in prop::collection::vec(any::<u8>(), 40..4096),
        size in any_size(),
    ) {
        let msg = Message::new(Command::Msg, payload);
        let all: Vec<_> = fragments(&msg, size).expect("payload fits").collect();
        prop_assume!(all.len() > 1);

        let mut rx = Reassembler::new(size);
        for fragment in &all[..all.len() - 1] {
            prop_assert_eq!(rx.push(fragment).expect("well formed"), None);
        }
        prop_assert!(rx.in_progress());
    }

    /// An error always leaves the reassembler idle, so a partially built
    /// message can never be completed after one.
    #[test]
    fn errors_always_abort_the_transaction(
        payload in prop::collection::vec(any::<u8>(), 40..2048),
        size in any_size(),
        junk in prop::collection::vec(any::<u8>(), 1..40),
    ) {
        let msg = Message::new(Command::Msg, payload);
        let all: Vec<_> = fragments(&msg, size).expect("payload fits").collect();
        prop_assume!(all.len() > 2);

        let mut rx = Reassembler::new(size);
        rx.push(&all[0]).expect("init fragment is well formed");

        if rx.push(&junk).is_err() {
            prop_assert!(!rx.in_progress(), "an error must leave the reassembler idle");
        }
    }
}
