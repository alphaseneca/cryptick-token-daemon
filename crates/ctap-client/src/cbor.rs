//! CBOR, restricted to the CTAP2 canonical encoding form.
//!
//! Hand-rolled rather than pulled from a crate, for two reasons. Canonical
//! encoding is a *correctness* requirement here — CTAP2 §6 fixes map key
//! ordering, and a generic encoder that preserves insertion order will produce
//! bytes an authenticator is entitled to reject — and this parser is a fuzz
//! target that PROJECT.md §14 names explicitly, so owning it is the point.
//!
//! The subset is what CTAP2 actually uses. Floats, tags and indefinite-length
//! items are rejected rather than supported: none appear in CTAP2 messages, and
//! accepting them would mean carrying decoding paths nothing exercises.
//!
//! # Canonical encoding
//!
//! CTAP2 §6 requires:
//!
//! - integers encoded in the shortest form that fits;
//! - lengths expressed in the shortest form that fits;
//! - definite lengths only;
//! - map keys sorted, comparing major type first, then length, then bytewise.
//!
//! That key ordering is exactly lexicographic order over the *encoded* keys, so
//! [`Value::encode`] sorts on encoded bytes and gets all three clauses at once.

use std::{cmp::Ordering, collections::HashSet};
use thiserror::Error;

/// How deeply nested a value may be before decoding gives up.
///
/// A recursive decoder without this is a stack overflow waiting for a fuzzer to
/// find it, and the input here reaches us from a device (PROJECT.md §14).
/// CTAP2 messages nest three or four deep; 16 is generous.
pub const MAX_DEPTH: usize = 16;

/// A CBOR value, restricted to the types CTAP2 uses.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Value {
    /// Major type 0. A non-negative integer.
    Unsigned(u64),
    /// Major type 1. Encodes `-1 - n`, so `Negative(0)` is `-1`.
    Negative(u64),
    /// Major type 2. A byte string.
    Bytes(Vec<u8>),
    /// Major type 3. A UTF-8 text string.
    Text(String),
    /// Major type 4. An array.
    Array(Vec<Value>),
    /// Major type 5. A map.
    ///
    /// Held in wire order, not canonical order: decoding is deliberately
    /// liberal about a peer that sends keys unsorted, since the canonical
    /// requirement in CTAP2 §6 binds the *encoder* and rejecting would only
    /// buy interop failures. Encoding always sorts, so
    /// `encode(decode(encode(v))) == encode(v)` even where
    /// `decode(encode(v)) != v`. Duplicate keys are rejected outright.
    Map(Vec<(Value, Value)>),
    /// Major type 7, simple value 20 or 21.
    Bool(bool),
    /// Major type 7, simple value 22.
    Null,
}

/// A CBOR value would not decode, or is outside the supported subset.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CborError {
    /// The input ended in the middle of a value.
    #[error("input ended after {consumed} bytes, mid-value")]
    UnexpectedEnd {
        /// How much had been consumed.
        consumed: usize,
    },

    /// A major type this subset does not carry.
    #[error("unsupported major type {major} at byte {offset}")]
    UnsupportedMajorType {
        /// The major type.
        major: u8,
        /// Where it appeared.
        offset: usize,
    },

    /// An additional-information value that is reserved or indefinite.
    #[error("unsupported additional information {info} at byte {offset}")]
    UnsupportedAdditionalInfo {
        /// The additional information nibble.
        info: u8,
        /// Where it appeared.
        offset: usize,
    },

    /// A simple value other than `false`, `true` or `null`.
    #[error("unsupported simple value {value} at byte {offset}")]
    UnsupportedSimpleValue {
        /// The simple value.
        value: u8,
        /// Where it appeared.
        offset: usize,
    },

    /// A text string that is not valid UTF-8.
    #[error("text string at byte {offset} is not valid UTF-8")]
    InvalidUtf8 {
        /// Where the string began.
        offset: usize,
    },

    /// Nesting deeper than [`MAX_DEPTH`].
    #[error("nesting deeper than {MAX_DEPTH} at byte {offset}")]
    TooDeep {
        /// Where the limit was hit.
        offset: usize,
    },

    /// A length or count larger than the remaining input could satisfy.
    ///
    /// Checked before allocating: a two-byte header can claim `u64::MAX`
    /// elements, and reserving for that would be the whole attack.
    #[error("declared length {len} exceeds the {remaining} bytes remaining")]
    LengthBeyondInput {
        /// The declared length or element count.
        len: u64,
        /// What was actually left.
        remaining: usize,
    },

    /// Bytes left over after a complete value.
    #[error("{trailing} trailing bytes after the top-level value")]
    TrailingData {
        /// How many bytes were left.
        trailing: usize,
    },

    /// The same key appeared twice in one map.
    ///
    /// Rejected rather than resolved to first-wins or last-wins: which one a
    /// parser picks is exactly the kind of difference that lets two
    /// implementations read the same bytes as different messages, and CTAP2's
    /// canonical form forbids it outright.
    #[error("duplicate map key at byte {offset}")]
    DuplicateKey {
        /// Where the repeat appeared.
        offset: usize,
    },
}

impl Value {
    /// Encodes to CTAP2 canonical CBOR.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Value::Unsigned(n) => encode_head(out, 0, *n),
            Value::Negative(n) => encode_head(out, 1, *n),
            Value::Bytes(b) => {
                encode_head(out, 2, b.len() as u64);
                out.extend_from_slice(b);
            }
            Value::Text(s) => {
                encode_head(out, 3, s.len() as u64);
                out.extend_from_slice(s.as_bytes());
            }
            Value::Array(items) => {
                encode_head(out, 4, items.len() as u64);
                for item in items {
                    item.encode_into(out);
                }
            }
            Value::Map(entries) => {
                encode_head(out, 5, entries.len() as u64);
                // Sorting on encoded keys implements all three clauses of the
                // CTAP2 §6 ordering rule at once: major type is the high bits
                // of the first byte, length is the next thing the head varies
                // by, and the payload compares bytewise after that.
                let mut sorted: Vec<(Vec<u8>, &Value)> =
                    entries.iter().map(|(k, v)| (k.encode(), v)).collect();
                sorted.sort_by(|(a, _), (b, _)| compare_canonical(a, b));
                for (key, value) in sorted {
                    out.extend_from_slice(&key);
                    value.encode_into(out);
                }
            }
            Value::Bool(false) => out.push(0xf4),
            Value::Bool(true) => out.push(0xf5),
            Value::Null => out.push(0xf6),
        }
    }

    /// Decodes one complete value, rejecting trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Value, CborError> {
        let mut d = Decoder { bytes, offset: 0 };
        let value = d.value(0)?;
        if d.offset != bytes.len() {
            return Err(CborError::TrailingData {
                trailing: bytes.len() - d.offset,
            });
        }
        Ok(value)
    }

    /// Decodes one value, returning it with the number of bytes consumed.
    ///
    /// For the attestation object, whose authenticator data is followed by
    /// fields the caller reads separately.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Value, usize), CborError> {
        let mut d = Decoder { bytes, offset: 0 };
        let value = d.value(0)?;
        Ok((value, d.offset))
    }

    /// Looks up a map entry by unsigned key. CTAP2 uses these for parameters.
    pub fn get(&self, key: u64) -> Option<&Value> {
        match self {
            Value::Map(entries) => entries
                .iter()
                .find(|(k, _)| *k == Value::Unsigned(key))
                .map(|(_, v)| v),
            _ => None,
        }
    }

    /// Looks up a map entry by text key. COSE keys and attestation objects use
    /// these.
    pub fn get_str(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Map(entries) => entries
                .iter()
                .find(|(k, _)| matches!(k, Value::Text(t) if t == key))
                .map(|(_, v)| v),
            _ => None,
        }
    }

    /// The byte string inside, if this is one.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// The text inside, if this is text.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Text(t) => Some(t),
            _ => None,
        }
    }

    /// The value as a signed integer, covering both integer major types.
    ///
    /// COSE algorithm identifiers are negative, so this is how `-7` is read.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Unsigned(n) => i64::try_from(*n).ok(),
            // -1 - n. Done through i128 so Negative(i64::MAX as u64) does not
            // overflow on the way.
            Value::Negative(n) => i64::try_from(-1i128 - i128::from(*n)).ok(),
            _ => None,
        }
    }
}

/// Orders encoded map keys per CTAP2 §6: shorter encodings first, then
/// bytewise. Plain lexicographic order would put `0x18 0x20` before `0x19`,
/// which reverses the length rule.
fn compare_canonical(a: &[u8], b: &[u8]) -> Ordering {
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

/// Writes a head with the shortest additional-information form that fits.
fn encode_head(out: &mut Vec<u8>, major: u8, value: u64) {
    let major = major << 5;
    match value {
        0..=23 => out.push(major | value as u8),
        24..=0xff => {
            out.push(major | 24);
            out.push(value as u8);
        }
        0x100..=0xffff => {
            out.push(major | 25);
            out.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(major | 26);
            out.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            out.push(major | 27);
            out.extend_from_slice(&value.to_be_bytes());
        }
    }
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl Decoder<'_> {
    fn remaining(&self) -> usize {
        self.bytes.len() - self.offset
    }

    fn take(&mut self, n: usize) -> Result<&[u8], CborError> {
        if self.remaining() < n {
            return Err(CborError::UnexpectedEnd {
                consumed: self.offset,
            });
        }
        let slice = &self.bytes[self.offset..self.offset + n];
        self.offset += n;
        Ok(slice)
    }

    fn byte(&mut self) -> Result<u8, CborError> {
        Ok(self.take(1)?[0])
    }

    /// Reads the argument following a head byte, shortest-form as written.
    fn argument(&mut self, info: u8, offset: usize) -> Result<u64, CborError> {
        match info {
            0..=23 => Ok(u64::from(info)),
            24 => Ok(u64::from(self.byte()?)),
            25 => {
                let b = self.take(2)?;
                Ok(u64::from(u16::from_be_bytes([b[0], b[1]])))
            }
            26 => {
                let b = self.take(4)?;
                Ok(u64::from(u32::from_be_bytes([b[0], b[1], b[2], b[3]])))
            }
            27 => {
                let b = self.take(8)?;
                Ok(u64::from_be_bytes([
                    b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                ]))
            }
            // 28..=30 are reserved; 31 is indefinite length, which the
            // canonical form forbids.
            info => Err(CborError::UnsupportedAdditionalInfo { info, offset }),
        }
    }

    /// Rejects a declared length the input cannot possibly satisfy.
    ///
    /// The point is to check *before* allocating. A three-byte input can
    /// declare a four-billion-element array, and `Vec::with_capacity` on that
    /// is the whole denial of service.
    fn bounded(&self, len: u64, per_item: usize) -> Result<usize, CborError> {
        let needed = len.saturating_mul(per_item as u64);
        if needed > self.remaining() as u64 {
            return Err(CborError::LengthBeyondInput {
                len,
                remaining: self.remaining(),
            });
        }
        usize::try_from(len).map_err(|_| CborError::LengthBeyondInput {
            len,
            remaining: self.remaining(),
        })
    }

    fn value(&mut self, depth: usize) -> Result<Value, CborError> {
        let offset = self.offset;
        if depth > MAX_DEPTH {
            return Err(CborError::TooDeep { offset });
        }
        let head = self.byte()?;
        let major = head >> 5;
        let info = head & 0x1f;

        match major {
            0 => Ok(Value::Unsigned(self.argument(info, offset)?)),
            1 => Ok(Value::Negative(self.argument(info, offset)?)),
            2 => {
                let len = self.argument(info, offset)?;
                let len = self.bounded(len, 1)?;
                Ok(Value::Bytes(self.take(len)?.to_vec()))
            }
            3 => {
                let len = self.argument(info, offset)?;
                let len = self.bounded(len, 1)?;
                let raw = self.take(len)?;
                let text =
                    std::str::from_utf8(raw).map_err(|_| CborError::InvalidUtf8 { offset })?;
                Ok(Value::Text(text.to_owned()))
            }
            4 => {
                let count = self.argument(info, offset)?;
                // Every element is at least one byte.
                let count = self.bounded(count, 1)?;
                let mut items = Vec::with_capacity(count);
                for _ in 0..count {
                    items.push(self.value(depth + 1)?);
                }
                Ok(Value::Array(items))
            }
            5 => {
                let count = self.argument(info, offset)?;
                // Every entry is at least two bytes: a key and a value.
                let count = self.bounded(count, 2)?;
                let mut entries: Vec<(Value, Value)> = Vec::with_capacity(count);
                let mut seen: HashSet<Vec<u8>> = HashSet::with_capacity(count);
                for _ in 0..count {
                    let key_offset = self.offset;
                    let key = self.value(depth + 1)?;
                    let value = self.value(depth + 1)?;
                    // Compared by canonical encoding, not by `Value`. Two keys
                    // that are maps with the same entries in different wire
                    // order are distinct `Value`s but the *same* key, and
                    // letting both through would make `encode` emit bytes this
                    // very decoder rejects.
                    if !seen.insert(key.encode()) {
                        return Err(CborError::DuplicateKey { offset: key_offset });
                    }
                    entries.push((key, value));
                }
                Ok(Value::Map(entries))
            }
            7 => match info {
                20 => Ok(Value::Bool(false)),
                21 => Ok(Value::Bool(true)),
                22 => Ok(Value::Null),
                value => Err(CborError::UnsupportedSimpleValue { value, offset }),
            },
            // 6 is tags, which CTAP2 does not use.
            major => Err(CborError::UnsupportedMajorType { major, offset }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn integers_use_the_shortest_form() {
        // RFC 8949 appendix A, which CTAP2 canonical form narrows rather than
        // contradicts.
        for (value, expected) in [
            (0u64, "00"),
            (1, "01"),
            (10, "0a"),
            (23, "17"),
            (24, "1818"),
            (25, "1819"),
            (100, "1864"),
            (1000, "1903e8"),
            (1_000_000, "1a000f4240"),
            (1_000_000_000_000, "1b000000e8d4a51000"),
        ] {
            assert_eq!(Value::Unsigned(value).encode(), hex(expected), "{value}");
        }
    }

    #[test]
    fn negative_integers_encode_as_minus_one_minus_n() {
        assert_eq!(Value::Negative(0).encode(), hex("20"));
        assert_eq!(Value::Negative(9).encode(), hex("29"));
        assert_eq!(Value::Negative(99).encode(), hex("3863"));
        assert_eq!(Value::Negative(0).as_i64(), Some(-1));
        // The COSE algorithm identifier for ES256.
        assert_eq!(Value::Negative(6).as_i64(), Some(-7));
        // And for EdDSA.
        assert_eq!(Value::Negative(7).as_i64(), Some(-8));
    }

    #[test]
    fn map_keys_are_sorted_canonically_regardless_of_insertion_order() {
        // CTAP2 §6: major type, then length, then bytewise. Written backwards
        // on purpose.
        let map = Value::Map(vec![
            (Value::Text("b".into()), Value::Unsigned(2)),
            (Value::Unsigned(300), Value::Unsigned(4)),
            (Value::Negative(0), Value::Unsigned(3)),
            (Value::Unsigned(1), Value::Unsigned(1)),
        ]);
        let encoded = map.encode();
        // 1 (0x01), 300 (0x19 012c), -1 (0x20), "b" (0x61 62): unsigned before
        // negative before text, and the one-byte 1 before the three-byte 300.
        assert_eq!(
            encoded,
            hex(concat!(
                "a4", "01", "01", "20", "03", "6162", "02", "19012c", "04"
            ))
        );
    }

    #[test]
    fn shorter_keys_sort_before_longer_ones_not_bytewise() {
        // Plain lexicographic order would put 0x18 0x20 before 0x19, reversing
        // the length rule. This is the case that catches it.
        let map = Value::Map(vec![
            (Value::Unsigned(0x19), Value::Null),
            (Value::Unsigned(0x20), Value::Null),
        ]);
        let encoded = map.encode();
        assert_eq!(encoded, hex(concat!("a2", "1819", "f6", "1820", "f6")));
    }

    #[test]
    fn round_trips_a_ctap_shaped_map() {
        let value = Value::Map(vec![
            (Value::Unsigned(1), Value::Bytes(vec![0xaa; 32])),
            (
                Value::Unsigned(2),
                Value::Map(vec![(Value::Text("id".into()), Value::Text("ssh:".into()))]),
            ),
            (
                Value::Unsigned(4),
                Value::Array(vec![Value::Map(vec![(
                    Value::Text("alg".into()),
                    Value::Negative(6),
                )])]),
            ),
        ]);
        assert_eq!(Value::decode(&value.encode()).unwrap(), value);
    }

    #[test]
    fn lookups_work_by_both_key_kinds() {
        let value = Value::Map(vec![
            (Value::Unsigned(3), Value::Bytes(vec![1, 2])),
            (Value::Text("fmt".into()), Value::Text("packed".into())),
        ]);
        assert_eq!(value.get(3).and_then(Value::as_bytes), Some(&[1u8, 2][..]));
        assert_eq!(value.get_str("fmt").and_then(Value::as_str), Some("packed"));
        assert_eq!(value.get(99), None);
        assert_eq!(value.get_str("nope"), None);
    }

    #[test]
    fn indefinite_lengths_are_rejected() {
        // Forbidden by the canonical form; 0x5f is an indefinite byte string.
        for byte in [0x5fu8, 0x7f, 0x9f, 0xbf] {
            assert!(matches!(
                Value::decode(&[byte]),
                Err(CborError::UnsupportedAdditionalInfo { info: 31, .. })
            ));
        }
    }

    #[test]
    fn tags_and_floats_are_rejected() {
        // Major type 6 is tags.
        assert!(matches!(
            Value::decode(&hex("c074")),
            Err(CborError::UnsupportedMajorType { major: 6, .. })
        ));
        // 0xfa is a single-precision float.
        assert!(matches!(
            Value::decode(&hex("fa47c35000")),
            Err(CborError::UnsupportedSimpleValue { value: 26, .. })
        ));
    }

    #[test]
    fn a_huge_declared_length_is_refused_before_allocating() {
        // 0x5b then a 64-bit length: eight bytes of input claiming to be
        // eighteen exabytes. Vec::with_capacity on that is the attack.
        let bomb = hex("5bffffffffffffffff");
        assert!(matches!(
            Value::decode(&bomb),
            Err(CborError::LengthBeyondInput { .. })
        ));
        // Same for arrays and maps.
        assert!(matches!(
            Value::decode(&hex("9bffffffffffffffff")),
            Err(CborError::LengthBeyondInput { .. })
        ));
        assert!(matches!(
            Value::decode(&hex("bbffffffffffffffff")),
            Err(CborError::LengthBeyondInput { .. })
        ));
    }

    #[test]
    fn deep_nesting_is_refused_rather_than_overflowing_the_stack() {
        // 0x81 is a one-element array; nesting them is the classic recursive
        // parser kill.
        let deep = vec![0x81u8; MAX_DEPTH + 8];
        assert!(matches!(
            Value::decode(&deep),
            Err(CborError::TooDeep { .. })
        ));
    }

    #[test]
    fn trailing_bytes_are_rejected_but_a_prefix_decode_reports_them() {
        let bytes = hex("0101");
        assert_eq!(
            Value::decode(&bytes),
            Err(CborError::TrailingData { trailing: 1 })
        );
        assert_eq!(
            Value::decode_prefix(&bytes).unwrap(),
            (Value::Unsigned(1), 1)
        );
    }

    #[test]
    fn truncated_input_is_an_error_not_a_panic() {
        for prefix in ["", "18", "19", "1a", "1b", "42", "4201", "a1", "a101"] {
            let bytes = hex(prefix);
            assert!(
                Value::decode(&bytes).is_err(),
                "{prefix:?} should not decode"
            );
        }
    }

    #[test]
    fn invalid_utf8_in_a_text_string_is_rejected() {
        // 0x62 is a two-byte text string; 0xff 0xfe is not UTF-8.
        assert!(matches!(
            Value::decode(&hex("62fffe")),
            Err(CborError::InvalidUtf8 { .. })
        ));
    }

    #[test]
    fn duplicate_map_keys_are_rejected() {
        // First-wins versus last-wins is a parser differential: two
        // implementations read the same bytes as different messages.
        assert!(matches!(
            Value::decode(&hex("a201000100")),
            Err(CborError::DuplicateKey { .. })
        ));
        // Distinct keys of different major types are fine: {1: 0, -1: 0}.
        assert!(Value::decode(&hex("a201002000")).is_ok());
    }

    #[test]
    fn keys_equal_only_after_canonicalisation_are_duplicates() {
        // {{9:0, 0:0}: 8, {0:0, 9:0}: 8}. The two map keys differ in wire
        // order but encode identically, so they are one key. Comparing
        // `Value` misses this, and the encoder would then emit a map with a
        // repeated key that this decoder refuses — output we cannot read back.
        assert!(matches!(
            Value::decode(&hex("a2a20900000008a20000090008")),
            Err(CborError::DuplicateKey { .. })
        ));
    }

    #[test]
    fn everything_this_encoder_emits_decodes_again() {
        // The invariant the fuzzer checks, pinned as a unit test.
        let value = Value::Map(vec![
            (
                Value::Map(vec![(Value::Unsigned(9), Value::Null)]),
                Value::Unsigned(1),
            ),
            (Value::Text("a".into()), Value::Unsigned(2)),
            (Value::Unsigned(3), Value::Array(vec![Value::Bool(true)])),
        ]);
        let once = value.encode();
        let twice = Value::decode(&once)
            .expect("our output must decode")
            .encode();
        assert_eq!(once, twice);
    }

    #[test]
    fn unsorted_keys_decode_but_re_encode_canonically() {
        // Liberal on receive, canonical on send. The byte-level invariant is
        // what holds, not Value equality.
        let bytes = hex("a201000000");
        let value = Value::decode(&bytes).expect("unsorted keys still decode");
        let encoded = value.encode();
        assert_eq!(encoded, hex("a200000100"), "re-encoding sorts");
        assert_eq!(
            Value::decode(&encoded).unwrap().encode(),
            encoded,
            "encoding is idempotent at the byte level"
        );
    }

    #[test]
    fn simple_values_round_trip() {
        for value in [Value::Bool(false), Value::Bool(true), Value::Null] {
            assert_eq!(Value::decode(&value.encode()).unwrap(), value);
        }
        assert_eq!(Value::Bool(false).encode(), hex("f4"));
        assert_eq!(Value::Bool(true).encode(), hex("f5"));
        assert_eq!(Value::Null.encode(), hex("f6"));
    }
}
