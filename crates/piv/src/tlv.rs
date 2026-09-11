//! BER-TLV, the subset PIV actually uses.
//!
//! Not a general ASN.1 library. PIV needs multi-byte tags (`5FC105`), long-form
//! lengths up to three bytes (a certificate is comfortably over 255 bytes), and
//! nothing else — no indefinite lengths, no constructed/primitive distinction
//! at this layer, no class checking. Everything outside that is rejected rather
//! than guessed at (PROJECT.md §15.8).

use thiserror::Error;

/// A BER-TLV tag, held as the integer its bytes spell.
///
/// PIV tags are one to three bytes and are written in the specification as hex
/// strings (`'5FC105'`), so storing the same integer keeps the code readable
/// against the tables in SP 800-73-5 Part 1 §4.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Tag(u32);

impl Tag {
    /// Builds a tag from the integer its bytes spell.
    ///
    /// # Panics
    ///
    /// Panics on a value wider than three bytes. Tags are constants in this
    /// crate, so a bad one is a bug at compile time, not input.
    pub const fn new(value: u32) -> Self {
        assert!(value <= 0x00FF_FFFF, "PIV tags are at most three bytes");
        Tag(value)
    }

    /// The tag as the integer its bytes spell.
    pub const fn value(self) -> u32 {
        self.0
    }

    /// The tag's encoding, big-endian, without leading zero bytes.
    pub fn to_bytes(self) -> Vec<u8> {
        let bytes = self.0.to_be_bytes();
        let first = bytes.iter().position(|&b| b != 0).unwrap_or(3);
        bytes[first..].to_vec()
    }

    /// How many bytes this tag occupies on the wire.
    pub const fn encoded_len(self) -> usize {
        match self.0 {
            0x0000_0000..=0x0000_00FF => 1,
            0x0000_0100..=0x0000_FFFF => 2,
            _ => 3,
        }
    }
}

/// Something in a TLV structure did not parse.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TlvError {
    /// Input ended in the middle of a tag, length, or value.
    #[error("truncated TLV: needed {needed} more bytes at offset {offset}")]
    Truncated {
        /// How many more bytes the structure called for.
        needed: usize,
        /// Where the parser ran out.
        offset: usize,
    },

    /// A tag ran past the three bytes PIV permits.
    #[error("tag at offset {offset} is longer than the three bytes PIV uses")]
    TagTooLong {
        /// Where the tag started.
        offset: usize,
    },

    /// A length used a form this parser refuses.
    ///
    /// `0x80` is the indefinite form, which BER allows and PIV does not use;
    /// anything above `0x83` would declare a value longer than any APDU
    /// exchange can carry.
    #[error("length form 0x{form:02X} at offset {offset} is not used by PIV")]
    UnsupportedLengthForm {
        /// The first length byte.
        form: u8,
        /// Where it sat.
        offset: usize,
    },

    /// A required tag was not in the structure.
    #[error("expected tag {expected:06X}, found {found:06X}")]
    UnexpectedTag {
        /// What the caller asked for.
        expected: u32,
        /// What was actually there.
        found: u32,
    },

    /// Bytes were left over after the last complete TLV.
    ///
    /// Refused rather than ignored: a trailing fragment means the sender and
    /// this parser disagree about the structure, and guessing which of us is
    /// right is exactly what §15.8 forbids.
    #[error("{count} trailing bytes after the last TLV")]
    TrailingBytes {
        /// How many bytes were left.
        count: usize,
    },
}

/// One tag-length-value element, borrowing its value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tlv<'a> {
    /// The element's tag.
    pub tag: Tag,
    /// The element's value.
    pub value: &'a [u8],
}

/// Encodes a length in the shortest form that fits.
///
/// The shortest form matters: PIV cards in the field are known to be strict
/// about it, and a non-minimal encoding is the kind of thing that works on the
/// bench and fails on somebody else's reader.
pub fn encode_length(len: usize, out: &mut Vec<u8>) {
    match len {
        0..=0x7F => out.push(len as u8),
        0x80..=0xFF => out.extend_from_slice(&[0x81, len as u8]),
        0x0100..=0xFFFF => {
            out.push(0x82);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        }
        _ => {
            out.push(0x83);
            let bytes = (len as u32).to_be_bytes();
            out.extend_from_slice(&bytes[1..]);
        }
    }
}

/// Encodes one TLV element.
pub fn encode(tag: Tag, value: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&tag.to_bytes());
    encode_length(value.len(), out);
    out.extend_from_slice(value);
}

/// Encodes one TLV element into a fresh buffer.
pub fn encode_to_vec(tag: Tag, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(tag.encoded_len() + 3 + value.len());
    encode(tag, value, &mut out);
    out
}

/// Reads one TLV element from the front of `input`.
///
/// Returns the element and how many bytes it consumed.
pub fn parse_one(input: &[u8]) -> Result<(Tlv<'_>, usize), TlvError> {
    let mut cursor = 0;

    let first = *input.first().ok_or(TlvError::Truncated {
        needed: 1,
        offset: 0,
    })?;
    cursor += 1;

    // Low five bits all set means the tag number continues into the following
    // bytes, each of which sets bit 8 while more follow (ISO 7816-4 §5.2.2.1).
    let mut tag = first as u32;
    if first & 0x1F == 0x1F {
        loop {
            if cursor >= 4 {
                return Err(TlvError::TagTooLong { offset: 0 });
            }
            let byte = *input.get(cursor).ok_or(TlvError::Truncated {
                needed: 1,
                offset: cursor,
            })?;
            cursor += 1;
            tag = (tag << 8) | byte as u32;
            if byte & 0x80 == 0 {
                break;
            }
        }
    }

    let length_start = cursor;
    let first_length = *input.get(cursor).ok_or(TlvError::Truncated {
        needed: 1,
        offset: cursor,
    })?;
    cursor += 1;

    let length = if first_length & 0x80 == 0 {
        first_length as usize
    } else {
        let count = (first_length & 0x7F) as usize;
        if !(1..=3).contains(&count) {
            return Err(TlvError::UnsupportedLengthForm {
                form: first_length,
                offset: length_start,
            });
        }
        let bytes = input
            .get(cursor..cursor + count)
            .ok_or_else(|| TlvError::Truncated {
                needed: (cursor + count).saturating_sub(input.len()),
                offset: cursor,
            })?;
        cursor += count;
        bytes.iter().fold(0usize, |acc, &b| (acc << 8) | b as usize)
    };

    let value = input
        .get(cursor..cursor + length)
        .ok_or_else(|| TlvError::Truncated {
            needed: (cursor + length).saturating_sub(input.len()),
            offset: cursor,
        })?;

    Ok((
        Tlv {
            tag: Tag(tag),
            value,
        },
        cursor + length,
    ))
}

/// Reads every TLV element in `input`, refusing trailing bytes.
pub fn parse_all(input: &[u8]) -> Result<Vec<Tlv<'_>>, TlvError> {
    let mut elements = Vec::new();
    let mut rest = input;
    while !rest.is_empty() {
        let (tlv, consumed) = match parse_one(rest) {
            Ok(parsed) => parsed,
            // A short tail is a trailing fragment, not a truncated element we
            // should ask the caller to supply more bytes for.
            Err(TlvError::Truncated { .. }) if !elements.is_empty() => {
                return Err(TlvError::TrailingBytes { count: rest.len() })
            }
            Err(error) => return Err(error),
        };
        elements.push(tlv);
        rest = &rest[consumed..];
    }
    Ok(elements)
}

/// Finds the first element with `tag` in a flat list.
pub fn find<'a>(elements: &[Tlv<'a>], tag: Tag) -> Option<&'a [u8]> {
    elements.iter().find(|e| e.tag == tag).map(|e| e.value)
}

/// Parses `input` as exactly one element and checks its tag.
pub fn expect_one(input: &[u8], tag: Tag) -> Result<&[u8], TlvError> {
    let (tlv, consumed) = parse_one(input)?;
    if tlv.tag != tag {
        return Err(TlvError::UnexpectedTag {
            expected: tag.value(),
            found: tlv.tag.value(),
        });
    }
    if consumed != input.len() {
        return Err(TlvError::TrailingBytes {
            count: input.len() - consumed,
        });
    }
    Ok(tlv.value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_three_byte_tag_round_trips() {
        // '5FC105' is the X.509 Certificate for PIV Authentication
        // (SP 800-73-5 Part 1, Table 3).
        let tag = Tag::new(0x5F_C105);
        assert_eq!(tag.to_bytes(), vec![0x5F, 0xC1, 0x05]);
        assert_eq!(tag.encoded_len(), 3);

        let encoded = encode_to_vec(tag, &[0xAA, 0xBB]);
        assert_eq!(encoded, vec![0x5F, 0xC1, 0x05, 0x02, 0xAA, 0xBB]);

        let (parsed, consumed) = parse_one(&encoded).unwrap();
        assert_eq!(parsed.tag, tag);
        assert_eq!(parsed.value, &[0xAA, 0xBB]);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn lengths_use_the_shortest_form() {
        // Cards in the field reject non-minimal lengths, and the failure shows
        // up on somebody else's reader rather than on the bench.
        let cases: &[(usize, &[u8])] = &[
            (0, &[0x00]),
            (0x7F, &[0x7F]),
            (0x80, &[0x81, 0x80]),
            (0xFF, &[0x81, 0xFF]),
            (0x0100, &[0x82, 0x01, 0x00]),
            (0xFFFF, &[0x82, 0xFF, 0xFF]),
            (0x0001_0000, &[0x83, 0x01, 0x00, 0x00]),
        ];
        for (len, expected) in cases {
            let mut out = Vec::new();
            encode_length(*len, &mut out);
            assert_eq!(&out, expected, "length {len}");
        }
    }

    #[test]
    fn a_certificate_sized_value_parses() {
        // Over 255 bytes, so the 0x82 form, which is the case that matters.
        let value = vec![0x41u8; 1200];
        let encoded = encode_to_vec(Tag::new(0x70), &value);
        assert_eq!(&encoded[..4], &[0x70, 0x82, 0x04, 0xB0]);
        assert_eq!(expect_one(&encoded, Tag::new(0x70)).unwrap(), &value[..]);
    }

    #[test]
    fn the_indefinite_length_form_is_refused() {
        // BER allows it, PIV does not use it, and accepting it would mean
        // scanning for an end-of-contents marker we never emit.
        let error = parse_one(&[0x70, 0x80]).unwrap_err();
        assert_eq!(
            error,
            TlvError::UnsupportedLengthForm {
                form: 0x80,
                offset: 1
            }
        );
    }

    #[test]
    fn a_tag_longer_than_three_bytes_is_refused() {
        // 0x5F then three continuation bytes: legal BER, not PIV.
        let error = parse_one(&[0x5F, 0xC1, 0xC1, 0xC1, 0x05, 0x00]).unwrap_err();
        assert_eq!(error, TlvError::TagTooLong { offset: 0 });
    }

    #[test]
    fn a_truncated_value_is_refused_rather_than_padded() {
        let error = parse_one(&[0x70, 0x04, 0xAA, 0xBB]).unwrap_err();
        assert!(matches!(error, TlvError::Truncated { .. }));
    }

    #[test]
    fn trailing_bytes_after_a_complete_element_are_refused() {
        // The alternative is silently dropping data the card sent, which means
        // disagreeing with it about the structure and not noticing.
        let mut encoded = encode_to_vec(Tag::new(0x70), &[0x01]);
        encoded.push(0x5F);
        assert_eq!(
            parse_all(&encoded).unwrap_err(),
            TlvError::TrailingBytes { count: 1 }
        );
    }

    #[test]
    fn expect_one_checks_the_tag() {
        let encoded = encode_to_vec(Tag::new(0x70), &[0x01]);
        assert_eq!(
            expect_one(&encoded, Tag::new(0x71)).unwrap_err(),
            TlvError::UnexpectedTag {
                expected: 0x71,
                found: 0x70
            }
        );
    }

    #[test]
    fn a_flat_sequence_parses_in_order() {
        // The shape of a certificate container: 70, 71, FE.
        let mut buffer = Vec::new();
        encode(Tag::new(0x70), &[0xDE, 0xAD], &mut buffer);
        encode(Tag::new(0x71), &[0x00], &mut buffer);
        encode(Tag::new(0xFE), &[], &mut buffer);

        let elements = parse_all(&buffer).unwrap();
        assert_eq!(elements.len(), 3);
        assert_eq!(find(&elements, Tag::new(0x70)), Some(&[0xDE, 0xAD][..]));
        assert_eq!(find(&elements, Tag::new(0x71)), Some(&[0x00][..]));
        assert_eq!(find(&elements, Tag::new(0xFE)), Some(&[][..]));
    }
}
