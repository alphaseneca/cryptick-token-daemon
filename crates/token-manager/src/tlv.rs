//! BER-TLV serialization and deserialization for OATH data payloads.
//!
//! Handles single-byte tags, length framing (1-byte or 2-byte ASN.1 lengths),
//! and tag lookup dictionary.

use crate::error::ManagerError;

/// Standard YKOATH TLV Tags.
pub mod tags {
    /// Account identifier string (UTF-8, e.g. `Issuer:Account`): `0x71`
    pub const TAG_NAME: u8 = 0x71;

    /// Name list / alternate name: `0x72`
    pub const TAG_NAME_LIST: u8 = 0x72;

    /// Secret key material & algorithm byte: `0x73`
    pub const TAG_KEY: u8 = 0x73;

    /// Challenge value (8-byte counter or random salt): `0x74`
    pub const TAG_CHALLENGE: u8 = 0x74;

    /// Full HMAC response or calculated OTP value: `0x75`
    pub const TAG_RESPONSE: u8 = 0x75;

    /// Truncated response (4-byte integer): `0x76`
    pub const TAG_TRUNCATED: u8 = 0x76;

    /// HOTP counter value: `0x77`
    pub const TAG_HOTP: u8 = 0x77;

    /// Property flags (Touch required) or remaining validity seconds: `0x78`
    pub const TAG_PROPERTY: u8 = 0x78;

    /// Token firmware / applet version (3 bytes): `0x79`
    pub const TAG_VERSION: u8 = 0x79;

    /// Initial moving factor (initial HOTP counter, 4 bytes): `0x7A`
    pub const TAG_IMF: u8 = 0x7A;

    /// Algorithm descriptor: `0x7B`
    pub const TAG_ALGORITHM: u8 = 0x7B;

    /// Touch sensor requirement flag: `0x7C`
    pub const TAG_TOUCH: u8 = 0x7C;
}

/// A parsed Tag-Length-Value entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tlv {
    /// 1-byte TLV tag.
    pub tag: u8,
    /// Value payload bytes.
    pub value: Vec<u8>,
}

impl Tlv {
    /// Constructs a new TLV with given tag and value.
    pub fn new(tag: u8, value: Vec<u8>) -> Self {
        Self { tag, value }
    }

    /// Serializes this TLV into BER-TLV bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(3 + self.value.len());
        out.push(self.tag);
        let len = self.value.len();
        if len < 0x80 {
            out.push(len as u8);
        } else if len <= 0xFF {
            out.push(0x81);
            out.push(len as u8);
        } else {
            out.push(0x82);
            out.push(((len >> 8) & 0xFF) as u8);
            out.push((len & 0xFF) as u8);
        }
        out.extend_from_slice(&self.value);
        out
    }

    /// Parses all TLV elements from a buffer.
    pub fn parse_all(mut data: &[u8]) -> Result<Vec<Tlv>, ManagerError> {
        let mut tlvs = Vec::new();
        while !data.is_empty() {
            let tag = data[0];
            data = &data[1..];
            if data.is_empty() {
                return Err(ManagerError::InvalidInput(format!(
                    "Unexpected end of data after tag {tag:#04X}"
                )));
            }

            let first_len = data[0];
            data = &data[1..];
            let len: usize = if first_len < 0x80 {
                first_len as usize
            } else if first_len == 0x81 {
                if data.is_empty() {
                    return Err(ManagerError::InvalidInput(format!(
                        "Unexpected end of data in length field for tag {tag:#04X}"
                    )));
                }
                let l = data[0] as usize;
                data = &data[1..];
                l
            } else if first_len == 0x82 {
                if data.len() < 2 {
                    return Err(ManagerError::InvalidInput(format!(
                        "Unexpected end of data in 2-byte length field for tag {tag:#04X}"
                    )));
                }
                let l = ((data[0] as usize) << 8) | (data[1] as usize);
                data = &data[2..];
                l
            } else {
                return Err(ManagerError::InvalidInput(format!(
                    "Unsupported BER-TLV length prefix {first_len:#04X}"
                )));
            };

            if data.len() < len {
                return Err(ManagerError::InvalidInput(format!(
                    "TLV payload truncated: expected {len} bytes for tag {tag:#04X}, have {}",
                    data.len()
                )));
            }

            let value = data[..len].to_vec();
            data = &data[len..];
            tlvs.push(Tlv { tag, value });
        }
        Ok(tlvs)
    }

    /// Finds the first TLV with matching tag.
    pub fn find(tlvs: &[Tlv], tag: u8) -> Option<&Tlv> {
        tlvs.iter().find(|t| t.tag == tag)
    }

    /// Finds all TLVs with matching tag.
    pub fn find_all(tlvs: &[Tlv], tag: u8) -> Vec<&Tlv> {
        tlvs.iter().filter(|t| t.tag == tag).collect()
    }
}

/// Helper to build a concatenated sequence of TLVs into a single byte buffer.
pub fn encode_tlvs(tlvs: &[Tlv]) -> Vec<u8> {
    let mut out = Vec::new();
    for tlv in tlvs {
        out.extend_from_slice(&tlv.encode());
    }
    out
}
