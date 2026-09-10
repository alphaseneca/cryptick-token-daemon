//! Parsing `authenticatorMakeCredential` and `authenticatorGetAssertion`
//! responses.
//!
//! Member numbering is from CTAP2 §6.1 and §6.2. The raw authenticator data is
//! kept alongside the parsed form because OpenSSH wants the bytes verbatim in
//! `sk_enroll_response.authdata` — re-encoding them would be a different
//! signature input.

use crate::{
    authdata::{AuthDataError, AuthenticatorData},
    cbor::{CborError, Value},
};
use thiserror::Error;

/// A CTAP response would not parse.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ResponseError {
    /// The body was not valid CBOR.
    #[error("response is not valid CBOR: {0}")]
    Cbor(#[from] CborError),
    /// A required member was absent.
    #[error("response is missing member {member}")]
    MissingMember {
        /// The CTAP member number.
        member: u64,
    },
    /// A member had the wrong CBOR type.
    #[error("response member {member} has the wrong type")]
    WrongType {
        /// The CTAP member number.
        member: u64,
    },
    /// The authenticator data would not parse.
    #[error("authenticator data: {0}")]
    AuthData(#[from] AuthDataError),
    /// A credential was created without attested credential data, so there is
    /// no public key or credential id to return.
    #[error("makeCredential response carries no attested credential data")]
    NoAttestedCredential,
}

fn member(value: &Value, n: u64) -> Result<&Value, ResponseError> {
    value
        .get(n)
        .ok_or(ResponseError::MissingMember { member: n })
}

fn bytes(value: &Value, n: u64) -> Result<Vec<u8>, ResponseError> {
    member(value, n)?
        .as_bytes()
        .map(<[u8]>::to_vec)
        .ok_or(ResponseError::WrongType { member: n })
}

/// A parsed `authenticatorMakeCredential` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MakeCredentialResponse {
    /// The attestation statement format, e.g. `packed` or `none`.
    pub fmt: String,
    /// Authenticator data exactly as received. OpenSSH wants these bytes.
    pub auth_data_raw: Vec<u8>,
    /// The same data, parsed.
    pub auth_data: AuthenticatorData,
    /// The attestation signature, empty when the format carries none.
    pub signature: Vec<u8>,
    /// The first certificate of `x5c`, when the format carries one.
    pub attestation_cert: Option<Vec<u8>>,
}

impl MakeCredentialResponse {
    /// Parses a response body.
    pub fn parse(body: &[u8]) -> Result<Self, ResponseError> {
        let value = Value::decode(body)?;

        let fmt = member(&value, 1)?
            .as_str()
            .ok_or(ResponseError::WrongType { member: 1 })?
            .to_owned();
        let auth_data_raw = bytes(&value, 2)?;
        let auth_data = AuthenticatorData::parse(&auth_data_raw)?;

        // `none` attestation is an empty map, so both of these are absent
        // rather than malformed. ssh-keygen accepts a credential without
        // attestation; it just cannot verify one.
        let att_stmt = member(&value, 3)?;
        let signature = att_stmt
            .get_str("sig")
            .and_then(Value::as_bytes)
            .map(<[u8]>::to_vec)
            .unwrap_or_default();
        let attestation_cert = match att_stmt.get_str("x5c") {
            Some(Value::Array(certs)) => {
                certs.first().and_then(Value::as_bytes).map(<[u8]>::to_vec)
            }
            _ => None,
        };

        Ok(Self {
            fmt,
            auth_data_raw,
            auth_data,
            signature,
            attestation_cert,
        })
    }

    /// The credential public key, in the form OpenSSH expects.
    pub fn public_key(&self) -> Result<Vec<u8>, ResponseError> {
        Ok(self
            .auth_data
            .attested_credential
            .as_ref()
            .ok_or(ResponseError::NoAttestedCredential)?
            .public_key
            .to_openssh_public_key())
    }

    /// The credential id, which OpenSSH calls the key handle.
    pub fn credential_id(&self) -> Result<&[u8], ResponseError> {
        Ok(&self
            .auth_data
            .attested_credential
            .as_ref()
            .ok_or(ResponseError::NoAttestedCredential)?
            .credential_id)
    }
}

/// A parsed `authenticatorGetAssertion` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetAssertionResponse {
    /// The credential the assertion is over. Optional when the request's
    /// `allowList` held exactly one entry.
    pub credential_id: Option<Vec<u8>>,
    /// Authenticator data exactly as received.
    pub auth_data_raw: Vec<u8>,
    /// The same data, parsed.
    pub auth_data: AuthenticatorData,
    /// The assertion signature. DER for ES256, raw 64 bytes for Ed25519.
    pub signature: Vec<u8>,
}

impl GetAssertionResponse {
    /// Parses a response body.
    pub fn parse(body: &[u8]) -> Result<Self, ResponseError> {
        let value = Value::decode(body)?;

        // Member 1 may be omitted when the allowList had a single entry, so
        // its absence is not an error.
        let credential_id = value
            .get(1)
            .and_then(|c| c.get_str("id"))
            .and_then(Value::as_bytes)
            .map(<[u8]>::to_vec);

        let auth_data_raw = bytes(&value, 2)?;
        let auth_data = AuthenticatorData::parse(&auth_data_raw)?;
        let signature = bytes(&value, 3)?;

        Ok(Self {
            credential_id,
            auth_data_raw,
            auth_data,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cose::CoseKey;

    fn cose_ed25519() -> Vec<u8> {
        Value::Map(vec![
            (Value::Unsigned(1), Value::Unsigned(1)),
            (Value::Unsigned(3), Value::Negative(7)),
            (Value::Negative(0), Value::Unsigned(6)),
            (Value::Negative(1), Value::Bytes(vec![0xcc; 32])),
        ])
        .encode()
    }

    fn auth_data_with_credential() -> Vec<u8> {
        let mut out = vec![0x11; 32];
        out.push(crate::authdata::FLAG_UP | crate::authdata::FLAG_UV | crate::authdata::FLAG_AT);
        out.extend_from_slice(&7u32.to_be_bytes());
        out.extend_from_slice(&[0x22; 16]); // aaguid
        out.extend_from_slice(&64u16.to_be_bytes());
        out.extend_from_slice(&[0xde; 64]); // credential id
        out.extend_from_slice(&cose_ed25519());
        out
    }

    fn auth_data_plain(count: u32) -> Vec<u8> {
        let mut out = vec![0x11; 32];
        out.push(crate::authdata::FLAG_UP);
        out.extend_from_slice(&count.to_be_bytes());
        out
    }

    #[test]
    fn a_packed_attestation_yields_everything_openssh_needs() {
        let auth = auth_data_with_credential();
        let body = Value::Map(vec![
            (Value::Unsigned(1), Value::Text("packed".into())),
            (Value::Unsigned(2), Value::Bytes(auth.clone())),
            (
                Value::Unsigned(3),
                Value::Map(vec![
                    (Value::Text("alg".into()), Value::Negative(7)),
                    (Value::Text("sig".into()), Value::Bytes(vec![0x5a; 64])),
                    (
                        Value::Text("x5c".into()),
                        Value::Array(vec![Value::Bytes(vec![0x30, 0x82, 0x01])]),
                    ),
                ]),
            ),
        ])
        .encode();

        let response = MakeCredentialResponse::parse(&body).unwrap();
        assert_eq!(response.fmt, "packed");
        assert_eq!(response.signature, vec![0x5a; 64]);
        assert_eq!(response.attestation_cert, Some(vec![0x30, 0x82, 0x01]));
        assert_eq!(response.credential_id().unwrap(), &[0xde; 64]);
        // Ed25519 packs as the raw 32 bytes.
        assert_eq!(response.public_key().unwrap(), vec![0xcc; 32]);
        // The raw bytes must survive untouched: they are a signature input.
        assert_eq!(response.auth_data_raw, auth);
        assert!(response.auth_data.user_verified());
    }

    #[test]
    fn none_attestation_parses_with_no_signature_or_cert() {
        let body = Value::Map(vec![
            (Value::Unsigned(1), Value::Text("none".into())),
            (
                Value::Unsigned(2),
                Value::Bytes(auth_data_with_credential()),
            ),
            (Value::Unsigned(3), Value::Map(vec![])),
        ])
        .encode();

        let response = MakeCredentialResponse::parse(&body).unwrap();
        assert_eq!(response.fmt, "none");
        assert!(response.signature.is_empty());
        assert_eq!(response.attestation_cert, None);
        // The credential itself is still usable.
        assert_eq!(response.credential_id().unwrap().len(), 64);
    }

    #[test]
    fn a_credential_without_attested_data_is_refused_not_defaulted() {
        // Returning an empty public key here would produce a key pair whose
        // public half is wrong, which fails only much later.
        let body = Value::Map(vec![
            (Value::Unsigned(1), Value::Text("none".into())),
            (Value::Unsigned(2), Value::Bytes(auth_data_plain(1))),
            (Value::Unsigned(3), Value::Map(vec![])),
        ])
        .encode();

        let response = MakeCredentialResponse::parse(&body).unwrap();
        assert_eq!(
            response.public_key(),
            Err(ResponseError::NoAttestedCredential)
        );
        assert_eq!(
            response.credential_id(),
            Err(ResponseError::NoAttestedCredential)
        );
    }

    #[test]
    fn an_assertion_parses() {
        let auth = auth_data_plain(99);
        let body = Value::Map(vec![
            (
                Value::Unsigned(1),
                Value::Map(vec![
                    (Value::Text("id".into()), Value::Bytes(vec![0xab; 32])),
                    (Value::Text("type".into()), Value::Text("public-key".into())),
                ]),
            ),
            (Value::Unsigned(2), Value::Bytes(auth.clone())),
            (Value::Unsigned(3), Value::Bytes(vec![0x77; 64])),
        ])
        .encode();

        let response = GetAssertionResponse::parse(&body).unwrap();
        assert_eq!(response.credential_id, Some(vec![0xab; 32]));
        assert_eq!(response.auth_data.sign_count, 99);
        assert_eq!(response.signature, vec![0x77; 64]);
        assert_eq!(response.auth_data_raw, auth);
    }

    #[test]
    fn an_assertion_without_a_credential_member_is_fine() {
        // Omitted when the allowList held exactly one entry, which is always
        // the case for SSH.
        let body = Value::Map(vec![
            (Value::Unsigned(2), Value::Bytes(auth_data_plain(1))),
            (Value::Unsigned(3), Value::Bytes(vec![0x01; 64])),
        ])
        .encode();
        let response = GetAssertionResponse::parse(&body).unwrap();
        assert_eq!(response.credential_id, None);
    }

    #[test]
    fn missing_required_members_name_themselves() {
        let body = Value::Map(vec![(Value::Unsigned(1), Value::Text("none".into()))]).encode();
        assert_eq!(
            MakeCredentialResponse::parse(&body),
            Err(ResponseError::MissingMember { member: 2 })
        );

        let body =
            Value::Map(vec![(Value::Unsigned(2), Value::Bytes(auth_data_plain(1)))]).encode();
        assert_eq!(
            GetAssertionResponse::parse(&body),
            Err(ResponseError::MissingMember { member: 3 })
        );
    }

    #[test]
    fn garbage_is_an_error_not_a_panic() {
        for body in [&b""[..], &[0x00], &[0xa1, 0x01], &[0xff; 16]] {
            assert!(MakeCredentialResponse::parse(body).is_err());
            assert!(GetAssertionResponse::parse(body).is_err());
        }
    }

    #[test]
    fn the_public_key_matches_what_the_cose_layer_produces() {
        let body = Value::Map(vec![
            (Value::Unsigned(1), Value::Text("none".into())),
            (
                Value::Unsigned(2),
                Value::Bytes(auth_data_with_credential()),
            ),
            (Value::Unsigned(3), Value::Map(vec![])),
        ])
        .encode();
        let response = MakeCredentialResponse::parse(&body).unwrap();
        let expected = CoseKey::Ed25519 { x: [0xcc; 32] }.to_openssh_public_key();
        assert_eq!(response.public_key().unwrap(), expected);
    }
}
