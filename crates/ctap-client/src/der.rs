//! Splitting a DER `ECDSA-Sig-Value` into the `r` and `s` OpenSSH wants.
//!
//! CTAP2 returns ECDSA signatures DER-encoded. OpenSSH's `sk_sign_response`
//! wants them as two separate big-endian integers, and its own middleware
//! produces them with `BN_num_bytes` / `BN_bn2bin` (`sk-usbhid.c`,
//! `pack_sig_ecdsa`) — which strips leading zeros. So "minimal big-endian" is
//! the contract, not "fixed 32 bytes".
//!
//! Ed25519 does not come through here at all: its 64-byte signature is passed
//! whole in `sig_r`, with `sig_s` left null (`pack_sig_ed25519`).

use thiserror::Error;

/// A DER signature would not parse.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DerError {
    /// The input ended early.
    #[error("DER signature ended unexpectedly at byte {offset}")]
    UnexpectedEnd {
        /// Where it ran out.
        offset: usize,
    },
    /// A tag other than the one expected.
    #[error("expected DER tag {expected:#04x} at byte {offset}, found {found:#04x}")]
    UnexpectedTag {
        /// The tag required.
        expected: u8,
        /// The tag present.
        found: u8,
        /// Where.
        offset: usize,
    },
    /// A length not encoded in the shortest form DER requires.
    #[error("non-minimal DER length at byte {offset}")]
    NonMinimalLength {
        /// Where.
        offset: usize,
    },
    /// A length this parser will not accept.
    #[error("DER length {len} at byte {offset} is unreasonable for a signature")]
    LengthTooLarge {
        /// The declared length.
        len: usize,
        /// Where.
        offset: usize,
    },
    /// An INTEGER encoded as negative. `r` and `s` are positive by definition.
    #[error("DER INTEGER at byte {offset} is negative")]
    NegativeInteger {
        /// Where.
        offset: usize,
    },
    /// An INTEGER with redundant leading zeros, which DER forbids.
    #[error("DER INTEGER at byte {offset} has a redundant leading zero")]
    NonMinimalInteger {
        /// Where.
        offset: usize,
    },
    /// Bytes after the SEQUENCE.
    #[error("{trailing} bytes after the DER SEQUENCE")]
    TrailingData {
        /// How many.
        trailing: usize,
    },
}

const TAG_SEQUENCE: u8 = 0x30;
const TAG_INTEGER: u8 = 0x02;

/// A P-256 signature is ~72 bytes; anything far larger is not one.
const MAX_LEN: usize = 1024;

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn byte(&mut self) -> Result<u8, DerError> {
        let b = *self.bytes.get(self.offset).ok_or(DerError::UnexpectedEnd {
            offset: self.offset,
        })?;
        self.offset += 1;
        Ok(b)
    }

    fn tag(&mut self, expected: u8) -> Result<(), DerError> {
        let offset = self.offset;
        let found = self.byte()?;
        if found != expected {
            return Err(DerError::UnexpectedTag {
                expected,
                found,
                offset,
            });
        }
        Ok(())
    }

    /// Reads a DER length, requiring the shortest form.
    fn length(&mut self) -> Result<usize, DerError> {
        let offset = self.offset;
        let first = self.byte()?;
        if first < 0x80 {
            return Ok(usize::from(first));
        }
        let count = usize::from(first & 0x7f);
        // 0x80 is the indefinite form, forbidden in DER. More than two length
        // bytes cannot describe anything we would accept anyway.
        if count == 0 || count > 2 {
            return Err(DerError::NonMinimalLength { offset });
        }
        let mut len = 0usize;
        for _ in 0..count {
            len = (len << 8) | usize::from(self.byte()?);
        }
        // DER requires the shortest encoding: a value under 0x80 must use the
        // short form, and a multi-byte length must not have a leading zero.
        if len < 0x80 || (count == 2 && len < 0x100) {
            return Err(DerError::NonMinimalLength { offset });
        }
        if len > MAX_LEN {
            return Err(DerError::LengthTooLarge { len, offset });
        }
        Ok(len)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DerError> {
        if self.bytes.len() - self.offset < n {
            return Err(DerError::UnexpectedEnd {
                offset: self.offset,
            });
        }
        let slice = &self.bytes[self.offset..self.offset + n];
        self.offset += n;
        Ok(slice)
    }

    /// Reads one INTEGER and returns it as minimal big-endian bytes.
    fn integer(&mut self) -> Result<Vec<u8>, DerError> {
        self.tag(TAG_INTEGER)?;
        let offset = self.offset;
        let len = self.length()?;
        if len == 0 {
            return Err(DerError::NonMinimalInteger { offset });
        }
        let content = self.take(len)?;

        if content[0] & 0x80 != 0 {
            return Err(DerError::NegativeInteger { offset });
        }
        // DER forbids a leading zero unless it is there to keep the value
        // positive.
        if content.len() > 1 && content[0] == 0x00 && content[1] & 0x80 == 0 {
            return Err(DerError::NonMinimalInteger { offset });
        }

        // BN_bn2bin drops leading zeros, so the padding byte goes.
        let start = content
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(content.len());
        Ok(content[start..].to_vec())
    }
}

/// Splits a DER `ECDSA-Sig-Value` into `(r, s)`, each minimal big-endian.
pub fn split_ecdsa_signature(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), DerError> {
    let mut r = Reader { bytes, offset: 0 };
    r.tag(TAG_SEQUENCE)?;
    let seq_len = r.length()?;
    let body_start = r.offset;

    let sig_r = r.integer()?;
    let sig_s = r.integer()?;

    if r.offset - body_start != seq_len {
        return Err(DerError::TrailingData {
            trailing: (r.offset - body_start).abs_diff(seq_len),
        });
    }
    if r.offset != bytes.len() {
        return Err(DerError::TrailingData {
            trailing: bytes.len() - r.offset,
        });
    }
    Ok((sig_r, sig_s))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn der(r: &[u8], s: &[u8]) -> Vec<u8> {
        let mut body = vec![TAG_INTEGER, r.len() as u8];
        body.extend_from_slice(r);
        body.push(TAG_INTEGER);
        body.push(s.len() as u8);
        body.extend_from_slice(s);
        let mut out = vec![TAG_SEQUENCE, body.len() as u8];
        out.extend_from_slice(&body);
        out
    }

    #[test]
    fn a_plain_signature_splits() {
        let bytes = der(&[0x01; 32], &[0x02; 32]);
        let (r, s) = split_ecdsa_signature(&bytes).unwrap();
        assert_eq!(r, vec![0x01; 32]);
        assert_eq!(s, vec![0x02; 32]);
    }

    #[test]
    fn the_positive_padding_byte_is_stripped() {
        // A 32-byte value with the high bit set is DER-encoded as 33 bytes
        // with a leading zero. BN_num_bytes reports 32, so OpenSSH expects 32.
        let mut padded = vec![0x00];
        padded.extend_from_slice(&[0xff; 32]);
        let bytes = der(&padded, &[0x02; 32]);
        let (r, s) = split_ecdsa_signature(&bytes).unwrap();
        assert_eq!(r.len(), 32, "the padding byte must not survive");
        assert_eq!(r, vec![0xff; 32]);
        assert_eq!(s, vec![0x02; 32]);
    }

    #[test]
    fn a_short_component_stays_short() {
        // BN_num_bytes reports the minimal width, so r and s are not padded
        // out to 32 bytes. Valid DER has no redundant leading zeros to strip
        // here — only the positive-padding case above does.
        let bytes = der(&[0x05], &[0x7f]);
        let (r, s) = split_ecdsa_signature(&bytes).unwrap();
        assert_eq!(r, vec![0x05]);
        assert_eq!(s, vec![0x7f]);
    }

    #[test]
    fn a_zero_component_becomes_empty_matching_bn_num_bytes() {
        // DER encodes zero as a single 0x00 byte, and BN_num_bytes(0) is 0.
        // A zero r or s is a broken signature, but rejecting it is the
        // verifier's job, not the parser's.
        let bytes = der(&[0x00], &[0x01]);
        let (r, s) = split_ecdsa_signature(&bytes).unwrap();
        assert!(r.is_empty());
        assert_eq!(s, vec![0x01]);
    }

    #[test]
    fn a_negative_integer_is_refused() {
        // r and s are positive; a high bit without padding is malformed.
        let bytes = der(&[0x80, 0x01], &[0x01]);
        assert!(matches!(
            split_ecdsa_signature(&bytes),
            Err(DerError::NegativeInteger { .. })
        ));
    }

    #[test]
    fn a_redundant_leading_zero_is_refused() {
        // 0x00 0x05 is not minimal DER: 0x05 has no high bit to guard.
        let bytes = der(&[0x00, 0x00, 0x05], &[0x01]);
        assert!(matches!(
            split_ecdsa_signature(&bytes),
            Err(DerError::NonMinimalInteger { .. })
        ));
    }

    #[test]
    fn a_non_minimal_length_is_refused() {
        // 0x81 0x02 encodes 2 in long form, which DER forbids.
        let bytes = [0x30, 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
        assert!(matches!(
            split_ecdsa_signature(&bytes),
            Err(DerError::NonMinimalLength { .. })
        ));
    }

    #[test]
    fn trailing_bytes_are_refused() {
        let mut bytes = der(&[0x01], &[0x02]);
        bytes.push(0x00);
        assert!(matches!(
            split_ecdsa_signature(&bytes),
            Err(DerError::TrailingData { .. })
        ));
    }

    #[test]
    fn a_wrong_outer_tag_is_refused() {
        let mut bytes = der(&[0x01], &[0x02]);
        bytes[0] = 0x31;
        assert!(matches!(
            split_ecdsa_signature(&bytes),
            Err(DerError::UnexpectedTag { found: 0x31, .. })
        ));
    }

    #[test]
    fn truncation_at_every_length_is_an_error_not_a_panic() {
        let full = der(&[0x01; 32], &[0x02; 32]);
        for n in 0..full.len() {
            assert!(split_ecdsa_signature(&full[..n]).is_err(), "len {n}");
        }
        assert!(split_ecdsa_signature(&full).is_ok());
    }
}
