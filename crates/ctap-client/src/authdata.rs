//! Authenticator data, and the attested credential inside it.
//!
//! Layout is from WebAuthn §6.1: a fixed 37-byte head, then optional attested
//! credential data, then optional extensions. Both optional parts are announced
//! by flag bits, and the credential public key is CBOR of unannounced length —
//! which is why parsing needs [`Value::decode_prefix`](crate::Value::decode_prefix)
//! rather than a byte count.

use crate::{
    cbor::{CborError, Value},
    cose::{CoseError, CoseKey},
};
use thiserror::Error;

/// User present.
pub const FLAG_UP: u8 = 0x01;
/// User verified. The fingerprint on this device satisfies this, not just UP.
pub const FLAG_UV: u8 = 0x04;
/// Attested credential data is present.
pub const FLAG_AT: u8 = 0x40;
/// Extension data is present.
pub const FLAG_ED: u8 = 0x80;

/// The fixed head: 32-byte RP id hash, one flags byte, four-byte counter.
const HEAD_LEN: usize = 37;

/// Authenticator data would not parse.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AuthDataError {
    /// Shorter than the fixed head.
    #[error("authenticator data is {len} bytes, shorter than the {HEAD_LEN}-byte head")]
    TooShort {
        /// The length received.
        len: usize,
    },
    /// The attested credential data was truncated.
    #[error("attested credential data is truncated")]
    TruncatedCredential,
    /// A credential id length that runs past the end.
    #[error("credential id claims {len} bytes but only {remaining} remain")]
    CredentialIdTooLong {
        /// The declared length.
        len: usize,
        /// What was left.
        remaining: usize,
    },
    /// The credential public key would not decode.
    #[error("credential public key: {0}")]
    Cose(#[from] CoseError),
    /// The extensions block would not decode.
    #[error("extensions: {0}")]
    Cbor(#[from] CborError),
    /// Bytes left over after everything the flags announced.
    #[error("{trailing} bytes remain after the announced fields")]
    TrailingData {
        /// How many were left.
        trailing: usize,
    },
}

/// An attested credential, present on a `makeCredential` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestedCredential {
    /// The authenticator model identifier.
    pub aaguid: [u8; 16],
    /// The credential id. This is OpenSSH's `key_handle`.
    pub credential_id: Vec<u8>,
    /// The credential public key.
    pub public_key: CoseKey,
}

/// Parsed authenticator data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatorData {
    /// SHA-256 of the relying party id.
    pub rp_id_hash: [u8; 32],
    /// The flags byte, passed to OpenSSH verbatim.
    pub flags: u8,
    /// The signature counter, big-endian on the wire.
    pub sign_count: u32,
    /// Present when [`FLAG_AT`] is set.
    pub attested_credential: Option<AttestedCredential>,
}

impl AuthenticatorData {
    /// Whether the user was present.
    pub const fn user_present(&self) -> bool {
        self.flags & FLAG_UP != 0
    }

    /// Whether the user was verified — on this device, a fingerprint match
    /// rather than a mere touch.
    pub const fn user_verified(&self) -> bool {
        self.flags & FLAG_UV != 0
    }

    /// Parses authenticator data.
    pub fn parse(bytes: &[u8]) -> Result<Self, AuthDataError> {
        if bytes.len() < HEAD_LEN {
            return Err(AuthDataError::TooShort { len: bytes.len() });
        }
        let mut rp_id_hash = [0u8; 32];
        rp_id_hash.copy_from_slice(&bytes[..32]);
        let flags = bytes[32];
        let sign_count = u32::from_be_bytes([bytes[33], bytes[34], bytes[35], bytes[36]]);

        let mut rest = &bytes[HEAD_LEN..];
        let attested_credential = if flags & FLAG_AT != 0 {
            let (credential, consumed) = parse_attested_credential(rest)?;
            rest = &rest[consumed..];
            Some(credential)
        } else {
            None
        };

        if flags & FLAG_ED != 0 {
            // Extensions are CBOR of unannounced length. We do not interpret
            // them — nothing in the SSH path uses one — but we must consume
            // them to know the data ended where it claimed to.
            let (_, consumed) = Value::decode_prefix(rest)?;
            rest = &rest[consumed..];
        }

        if !rest.is_empty() {
            return Err(AuthDataError::TrailingData {
                trailing: rest.len(),
            });
        }

        Ok(Self {
            rp_id_hash,
            flags,
            sign_count,
            attested_credential,
        })
    }
}

fn parse_attested_credential(bytes: &[u8]) -> Result<(AttestedCredential, usize), AuthDataError> {
    // 16 bytes of AAGUID plus a two-byte length before the id starts.
    if bytes.len() < 18 {
        return Err(AuthDataError::TruncatedCredential);
    }
    let mut aaguid = [0u8; 16];
    aaguid.copy_from_slice(&bytes[..16]);
    let id_len = usize::from(u16::from_be_bytes([bytes[16], bytes[17]]));

    let after_len = &bytes[18..];
    if id_len > after_len.len() {
        return Err(AuthDataError::CredentialIdTooLong {
            len: id_len,
            remaining: after_len.len(),
        });
    }
    let credential_id = after_len[..id_len].to_vec();

    // The public key is CBOR with no length prefix of its own, so decoding is
    // what tells us where it ends.
    let (value, consumed) = Value::decode_prefix(&after_len[id_len..])
        .map_err(|e| AuthDataError::Cose(CoseError::Cbor(e)))?;
    let public_key = CoseKey::from_value(&value)?;

    Ok((
        AttestedCredential {
            aaguid,
            credential_id,
            public_key,
        },
        18 + id_len + consumed,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cose_es256() -> Vec<u8> {
        Value::Map(vec![
            (Value::Unsigned(1), Value::Unsigned(2)),
            (Value::Unsigned(3), Value::Negative(6)),
            (Value::Negative(0), Value::Unsigned(1)),
            (Value::Negative(1), Value::Bytes(vec![0xaa; 32])),
            (Value::Negative(2), Value::Bytes(vec![0xbb; 32])),
        ])
        .encode()
    }

    fn build(flags: u8, count: u32, tail: &[u8]) -> Vec<u8> {
        let mut out = vec![0x11; 32];
        out.push(flags);
        out.extend_from_slice(&count.to_be_bytes());
        out.extend_from_slice(tail);
        out
    }

    fn attested(id: &[u8]) -> Vec<u8> {
        let mut out = vec![0x22; 16];
        out.extend_from_slice(&(id.len() as u16).to_be_bytes());
        out.extend_from_slice(id);
        out.extend_from_slice(&cose_es256());
        out
    }

    #[test]
    fn an_assertion_without_attested_data_parses() {
        let data = AuthenticatorData::parse(&build(FLAG_UP | FLAG_UV, 42, &[])).unwrap();
        assert_eq!(data.rp_id_hash, [0x11; 32]);
        assert_eq!(data.sign_count, 42);
        assert!(data.user_present());
        assert!(data.user_verified());
        assert!(data.attested_credential.is_none());
    }

    #[test]
    fn the_counter_is_big_endian() {
        // Little-endian here would be a silently wrong counter, which OpenSSH
        // passes straight through into the signature blob.
        let data = AuthenticatorData::parse(&build(0, 0x0102_0304, &[])).unwrap();
        assert_eq!(data.sign_count, 0x0102_0304);
    }

    #[test]
    fn a_credential_parses_out_of_attested_data() {
        let bytes = build(FLAG_UP | FLAG_AT, 1, &attested(&[0xde; 64]));
        let data = AuthenticatorData::parse(&bytes).unwrap();
        let credential = data.attested_credential.expect("AT was set");
        assert_eq!(credential.aaguid, [0x22; 16]);
        assert_eq!(credential.credential_id, vec![0xde; 64]);
        assert_eq!(
            credential.public_key,
            CoseKey::Es256 {
                x: [0xaa; 32],
                y: [0xbb; 32]
            }
        );
    }

    #[test]
    fn extensions_after_a_credential_are_consumed_not_treated_as_trailing() {
        // The public key has no length prefix, so getting its end wrong shows
        // up here as spurious trailing data.
        let mut tail = attested(&[0x01; 16]);
        tail.extend_from_slice(
            &Value::Map(vec![(Value::Text("hmac-secret".into()), Value::Bool(true))]).encode(),
        );
        let data = AuthenticatorData::parse(&build(FLAG_AT | FLAG_ED, 7, &tail)).unwrap();
        assert!(data.attested_credential.is_some());
        assert_eq!(data.sign_count, 7);
    }

    #[test]
    fn extensions_without_a_credential_parse() {
        let extensions = Value::Map(vec![(Value::Text("x".into()), Value::Null)]).encode();
        let data = AuthenticatorData::parse(&build(FLAG_ED, 3, &extensions)).unwrap();
        assert!(data.attested_credential.is_none());
    }

    #[test]
    fn trailing_bytes_are_refused() {
        // The flags say what is present; anything more means we misparsed.
        let mut bytes = build(FLAG_UP, 1, &[]);
        bytes.push(0xff);
        assert_eq!(
            AuthenticatorData::parse(&bytes),
            Err(AuthDataError::TrailingData { trailing: 1 })
        );
    }

    #[test]
    fn a_credential_id_length_past_the_end_is_refused() {
        let mut tail = vec![0x22; 16];
        tail.extend_from_slice(&u16::MAX.to_be_bytes());
        tail.extend_from_slice(&[0u8; 4]);
        assert!(matches!(
            AuthenticatorData::parse(&build(FLAG_AT, 1, &tail)),
            Err(AuthDataError::CredentialIdTooLong { len: 65535, .. })
        ));
    }

    #[test]
    fn truncation_at_every_length_is_an_error_not_a_panic() {
        let mut tail = attested(&[0x05; 32]);
        tail.extend_from_slice(&Value::Map(vec![(Value::Text("e".into()), Value::Null)]).encode());
        let full = build(FLAG_AT | FLAG_ED, 1, &tail);
        for n in 0..full.len() {
            let _ = AuthenticatorData::parse(&full[..n]);
        }
        assert!(AuthenticatorData::parse(&full).is_ok());
    }
}
