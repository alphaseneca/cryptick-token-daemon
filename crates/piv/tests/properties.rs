//! Properties the card edge must hold for any input.
//!
//! The parser here reads bytes a card sent, and on the BLE path those bytes
//! crossed a radio. L2 in PROJECT.md §14 says the layer that parses untrusted
//! framing is the one that gets attacked in tests, so it is attacked here.

use piv::apdu::{Command, Response};
use piv::tlv::{self, Tag};
use proptest::prelude::*;

/// Tags spelled the way ISO 7816-4 §5.2.2.1 spells them.
///
/// Built rather than filtered: only a small fraction of 24-bit integers are
/// well-formed tags, so a filter rejects almost everything and proves nothing.
fn any_tag() -> impl Strategy<Value = Tag> {
    prop_oneof![
        // One byte: the low five bits must not all be set.
        (0u8..=0xFF)
            .prop_filter("single-byte tags cannot end in 0b11111", |b| b & 0x1F
                != 0x1F)
            .prop_map(|b| Tag::new(b as u32)),
        // Two bytes: continuation marker, then a byte with bit 8 clear.
        (0u8..=0xFF, 0u8..=0x7F)
            .prop_map(|(hi, lo)| { Tag::new(((hi | 0x1F) as u32) << 8 | lo as u32) }),
        // Three bytes: continuation marker, a byte with bit 8 set, then clear.
        (0u8..=0xFF, 0u8..=0xFF, 0u8..=0x7F).prop_map(|(hi, mid, lo)| {
            Tag::new(((hi | 0x1F) as u32) << 16 | ((mid | 0x80) as u32) << 8 | lo as u32)
        }),
    ]
}

proptest! {
    #[test]
    fn any_tlv_round_trips(tag in any_tag(), value in prop::collection::vec(any::<u8>(), 0..2000)) {
        let encoded = tlv::encode_to_vec(tag, &value);
        let decoded = tlv::expect_one(&encoded, tag).unwrap();
        prop_assert_eq!(decoded, &value[..]);
    }

    #[test]
    fn a_parsed_tag_is_the_tag_that_was_encoded(tag in any_tag()) {
        // The encoder and parser must agree about where a tag ends, or a
        // multi-byte tag silently swallows the length byte after it.
        let encoded = tlv::encode_to_vec(tag, &[0xAA]);
        let (parsed, consumed) = tlv::parse_one(&encoded).unwrap();
        prop_assert_eq!(parsed.tag, tag);
        prop_assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn parsing_arbitrary_bytes_never_panics(input in prop::collection::vec(any::<u8>(), 0..600)) {
        // The only acceptable outcomes are a parse and an error.
        let _ = tlv::parse_all(&input);
        let _ = tlv::parse_one(&input);
    }

    #[test]
    fn a_response_always_splits_or_is_refused(input in prop::collection::vec(any::<u8>(), 0..300)) {
        match Response::decode(&input) {
            Ok(response) => {
                prop_assert_eq!(response.data.len() + 2, input.len());
            }
            Err(_) => prop_assert!(input.len() < 2),
        }
    }

    #[test]
    fn chaining_preserves_the_data_field(
        data in prop::collection::vec(any::<u8>(), 0..3000),
        chunk in 1usize..=255,
    ) {
        let command = Command::with_data(0x00, 0xDB, 0x3F, 0xFF, data.clone()).expecting(0x00);
        let links = piv::chain(&command, chunk).unwrap();

        // Every link must fit the short form, or chaining did not do its job.
        for link in &links {
            prop_assert!(link.encode().is_ok());
        }
        // Only the last link ends the chain.
        for link in &links[..links.len() - 1] {
            prop_assert_eq!(link.cla & 0x10, 0x10);
        }
        prop_assert_eq!(links.last().unwrap().cla & 0x10, 0x00);

        let rejoined: Vec<u8> = links.iter().flat_map(|l| l.data.clone()).collect();
        prop_assert_eq!(rejoined, data);
    }
}
