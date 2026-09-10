//! Well-formed CTAP responses for testing, built rather than transcribed.
//!
//! These exist because the daemon's fake device has to serve *something*
//! plausible, and a hex constant is the wrong way to hold one. An earlier
//! version of this was a hex string in the daemon binary; reflowing it across
//! source lines silently dropped two characters, and the failure surfaced as
//! `ssh-keygen` reporting "invalid format" with nothing to point at.
//!
//! Built with the same encoder that parses them, so they cannot drift and
//! cannot be mistyped. The tests below assert they round-trip.

use crate::{
    authdata::{FLAG_AT, FLAG_UP, FLAG_UV},
    cbor::Value,
};

/// The RP id hash these fixtures carry. Not a real hash of anything.
pub const RP_ID_HASH: [u8; 32] = [0x11; 32];
/// The credential id these fixtures carry.
pub const CREDENTIAL_ID: [u8; 32] = [0x7c; 32];
/// The Ed25519 public key these fixtures carry.
pub const PUBLIC_KEY: [u8; 32] = [0x9d; 32];

fn cose_ed25519() -> Vec<u8> {
    Value::Map(vec![
        (Value::Unsigned(1), Value::Unsigned(1)), // kty: OKP
        (Value::Unsigned(3), Value::Negative(7)), // alg: EdDSA
        (Value::Negative(0), Value::Unsigned(6)), // crv: Ed25519
        (Value::Negative(1), Value::Bytes(PUBLIC_KEY.to_vec())),
    ])
    .encode()
}

fn authenticator_data(flags: u8, sign_count: u32, attested: bool) -> Vec<u8> {
    let mut out = RP_ID_HASH.to_vec();
    out.push(flags);
    out.extend_from_slice(&sign_count.to_be_bytes());
    if attested {
        out.extend_from_slice(&[0u8; 16]); // aaguid
        out.extend_from_slice(&(CREDENTIAL_ID.len() as u16).to_be_bytes());
        out.extend_from_slice(&CREDENTIAL_ID);
        out.extend_from_slice(&cose_ed25519());
    }
    out
}

/// An `authenticatorMakeCredential` response: `none` attestation over an
/// Ed25519 credential, with user presence and verification both set.
pub fn make_credential_response() -> Vec<u8> {
    Value::Map(vec![
        (Value::Unsigned(1), Value::Text("none".into())),
        (
            Value::Unsigned(2),
            Value::Bytes(authenticator_data(FLAG_UP | FLAG_UV | FLAG_AT, 1, true)),
        ),
        (Value::Unsigned(3), Value::Map(vec![])),
    ])
    .encode()
}

/// An `authenticatorGetAssertion` response over the same credential.
pub fn get_assertion_response() -> Vec<u8> {
    Value::Map(vec![
        (
            Value::Unsigned(2),
            Value::Bytes(authenticator_data(FLAG_UP | FLAG_UV, 2, false)),
        ),
        (Value::Unsigned(3), Value::Bytes(vec![0x42; 64])),
    ])
    .encode()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GetAssertionResponse, MakeCredentialResponse};

    #[test]
    fn the_make_credential_fixture_parses_and_yields_a_usable_credential() {
        let parsed =
            MakeCredentialResponse::parse(&make_credential_response()).expect("fixture must parse");
        assert_eq!(parsed.fmt, "none");
        assert_eq!(parsed.credential_id().unwrap(), &CREDENTIAL_ID);
        // Ed25519 is packed as the raw 32 bytes, so this is what OpenSSH gets.
        assert_eq!(parsed.public_key().unwrap(), PUBLIC_KEY.to_vec());
        assert!(parsed.auth_data.user_verified());
    }

    #[test]
    fn the_get_assertion_fixture_parses() {
        let parsed =
            GetAssertionResponse::parse(&get_assertion_response()).expect("fixture must parse");
        assert_eq!(parsed.auth_data.sign_count, 2);
        assert_eq!(
            parsed.signature.len(),
            64,
            "Ed25519 signatures are 64 bytes"
        );
    }
}
