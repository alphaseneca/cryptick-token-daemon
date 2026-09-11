//! Properties of the vpcd decoder, for any input and any chunking.
//!
//! This decoder reads a loopback socket that PCSC-Lite and the Windows smart
//! card service write to. That is a local, privileged-ish peer rather than a
//! radio, but §14 still puts the framing layer under test rather than trusting
//! it: TCP delivers no message boundaries, so every split is reachable.

use proptest::prelude::*;
use vpcd::{Decoder, Message, MAX_BODY};

/// Drains every message a decoder can produce from `wire`, fed in `chunk`-byte
/// pieces.
fn decode_all(wire: &[u8], chunk: usize) -> Result<Vec<Message>, vpcd::VpcdError> {
    let mut decoder = Decoder::default();
    let mut seen = Vec::new();
    for piece in wire.chunks(chunk.max(1)) {
        decoder.push(piece);
        while let Some(message) = decoder.next_message()? {
            seen.push(message);
        }
    }
    Ok(seen)
}

proptest! {
    #[test]
    fn decoding_arbitrary_bytes_never_panics(
        input in prop::collection::vec(any::<u8>(), 0..1500),
        chunk in 1usize..=64,
    ) {
        let _ = decode_all(&input, chunk);
    }

    #[test]
    fn an_apdu_survives_any_chunking(
        apdu in prop::collection::vec(any::<u8>(), 2..600),
        chunk in 1usize..=64,
    ) {
        // Two bytes minimum: a one-byte body is a control message by
        // definition of the protocol, not a short APDU.
        let wire = vpcd::frame(&apdu).unwrap();
        prop_assert_eq!(decode_all(&wire, chunk).unwrap(), vec![Message::Apdu(apdu)]);
    }

    #[test]
    fn a_run_of_messages_decodes_in_order(
        bodies in prop::collection::vec(prop::collection::vec(any::<u8>(), 2..80), 1..12),
        chunk in 1usize..=32,
    ) {
        let mut wire = Vec::new();
        for body in &bodies {
            wire.extend_from_slice(&vpcd::frame(body).unwrap());
        }
        let expected: Vec<Message> = bodies.into_iter().map(Message::Apdu).collect();
        prop_assert_eq!(decode_all(&wire, chunk).unwrap(), expected);
    }

    #[test]
    fn framing_round_trips_at_every_length(len in 0usize..2000) {
        let body = vec![0xA5u8; len];
        let wire = vpcd::frame(&body).unwrap();
        prop_assert_eq!(wire.len(), len + 2);
        prop_assert_eq!(
            u16::from_be_bytes([wire[0], wire[1]]) as usize,
            len
        );
        prop_assert!(len <= MAX_BODY);
    }
}
