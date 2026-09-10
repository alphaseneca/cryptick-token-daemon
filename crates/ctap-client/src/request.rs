//! Building `authenticatorMakeCredential` and `authenticatorGetAssertion`.
//!
//! Parameter numbering is from CTAP2 §6.1 and §6.2. The values OpenSSH supplies
//! are from its own middleware (`sk-usbhid.c` at `V_10_3_P1`) rather than
//! inferred — one detail there is easy to get wrong and impossible to notice
//! until a relying party rejects the credential. See [`client_data_hash`].

use crate::cbor::Value;
use sha2::{Digest, Sha256};

/// COSE `alg` for ECDSA P-256 with SHA-256.
pub const COSE_ES256: i64 = -7;
/// COSE `alg` for EdDSA.
pub const COSE_EDDSA: i64 = -8;

/// `authenticatorMakeCredential`.
pub const CMD_MAKE_CREDENTIAL: u8 = 0x01;
/// `authenticatorGetAssertion`.
pub const CMD_GET_ASSERTION: u8 = 0x02;

/// The user handle OpenSSH sends when no `user` option is given.
///
/// Its buffer is 32 bytes and it is only populated from an explicit option, so
/// the default request carries 32 zero bytes rather than omitting the field —
/// CTAP2 requires `user.id` to be present.
pub const DEFAULT_USER_ID: [u8; 32] = [0u8; 32];

/// Hashes a challenge into a `clientDataHash`.
///
/// **The challenge OpenSSH hands the middleware is not already a hash.**
/// `fido_cred_set_clientdata` and `fido_assert_set_clientdata` both run it
/// through SHA-256 before handing it to the authenticator, so passing the
/// challenge straight through would produce a credential that verifies against
/// nothing. There is no failure mode short of a relying party rejecting it.
pub fn client_data_hash(challenge: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(challenge);
    hasher.finalize().into()
}

fn descriptor(credential_id: &[u8]) -> Value {
    Value::Map(vec![
        (
            Value::Text("id".into()),
            Value::Bytes(credential_id.to_vec()),
        ),
        (Value::Text("type".into()), Value::Text("public-key".into())),
    ])
}

/// Parameters for a credential creation.
#[derive(Debug, Clone)]
pub struct MakeCredential<'a> {
    /// The challenge, hashed here rather than by the caller.
    pub challenge: &'a [u8],
    /// The relying party id. OpenSSH passes its `application`, e.g. `ssh:host`.
    pub rp_id: &'a str,
    /// The user handle.
    pub user_id: &'a [u8],
    /// The COSE algorithm to request.
    pub alg: i64,
    /// Ask for a discoverable credential.
    pub resident_key: bool,
    /// Require user verification — a fingerprint on this device, not a touch.
    pub user_verification: bool,
}

impl MakeCredential<'_> {
    /// Encodes to a CTAP request.
    pub fn encode(&self) -> ctap::Request {
        let mut params = vec![
            (
                Value::Unsigned(1),
                Value::Bytes(client_data_hash(self.challenge).to_vec()),
            ),
            (
                Value::Unsigned(2),
                Value::Map(vec![(
                    Value::Text("id".into()),
                    Value::Text(self.rp_id.to_owned()),
                )]),
            ),
            (
                Value::Unsigned(3),
                Value::Map(vec![(
                    Value::Text("id".into()),
                    Value::Bytes(self.user_id.to_vec()),
                )]),
            ),
            (
                Value::Unsigned(4),
                Value::Array(vec![Value::Map(vec![
                    (Value::Text("alg".into()), algorithm(self.alg)),
                    (Value::Text("type".into()), Value::Text("public-key".into())),
                ])]),
            ),
        ];

        // Options are omitted entirely when neither is set: CTAP2 defaults are
        // what we want, and sending `rk: false` is not the same as sending
        // nothing to every authenticator.
        let mut options = Vec::new();
        if self.resident_key {
            options.push((Value::Text("rk".into()), Value::Bool(true)));
        }
        if self.user_verification {
            options.push((Value::Text("uv".into()), Value::Bool(true)));
        }
        if !options.is_empty() {
            params.push((Value::Unsigned(7), Value::Map(options)));
        }

        ctap::Request::new(
            ctap::Command(CMD_MAKE_CREDENTIAL),
            Value::Map(params).encode(),
        )
    }
}

/// Parameters for an assertion.
#[derive(Debug, Clone)]
pub struct GetAssertion<'a> {
    /// The message to sign, hashed here rather than by the caller.
    pub challenge: &'a [u8],
    /// The relying party id.
    pub rp_id: &'a str,
    /// The credential to use. OpenSSH calls this the key handle.
    pub credential_id: &'a [u8],
    /// Require user verification.
    pub user_verification: bool,
}

impl GetAssertion<'_> {
    /// Encodes to a CTAP request.
    pub fn encode(&self) -> ctap::Request {
        let mut params = vec![
            (Value::Unsigned(1), Value::Text(self.rp_id.to_owned())),
            (
                Value::Unsigned(2),
                Value::Bytes(client_data_hash(self.challenge).to_vec()),
            ),
            (
                Value::Unsigned(3),
                Value::Array(vec![descriptor(self.credential_id)]),
            ),
        ];

        // `up` is left at its default of true. User presence is the whole
        // point of the operation, and PROJECT.md §15.3 forbids anything in
        // this path arranging for it to be skipped.
        if self.user_verification {
            let options = vec![(Value::Text("uv".into()), Value::Bool(true))];
            params.push((Value::Unsigned(5), Value::Map(options)));
        }

        ctap::Request::new(
            ctap::Command(CMD_GET_ASSERTION),
            Value::Map(params).encode(),
        )
    }
}

/// Encodes a COSE algorithm identifier, which is negative for both of ours.
fn algorithm(alg: i64) -> Value {
    if alg < 0 {
        // CBOR negative integers encode -1 - n.
        Value::Negative((-1 - alg) as u64)
    } else {
        Value::Unsigned(alg as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::Value;

    fn params(request: &ctap::Request) -> Value {
        Value::decode(&request.params).expect("params are valid CBOR")
    }

    #[test]
    fn the_challenge_is_hashed_not_passed_through() {
        // The bug this whole module exists to avoid: OpenSSH's challenge is
        // not a clientDataHash, and passing it through yields a credential
        // that verifies against nothing.
        let challenge = b"not a hash";
        let request = MakeCredential {
            challenge,
            rp_id: "ssh:",
            user_id: &DEFAULT_USER_ID,
            alg: COSE_EDDSA,
            resident_key: false,
            user_verification: false,
        }
        .encode();

        let p = params(&request);
        let hash = p.get(1).and_then(Value::as_bytes).unwrap();
        assert_eq!(hash.len(), 32);
        assert_ne!(hash, challenge, "the challenge must not be passed through");
        assert_eq!(hash, client_data_hash(challenge));
    }

    #[test]
    fn the_hash_matches_a_known_sha256_vector() {
        // SHA-256("abc"), so a swapped-in hash function would be caught.
        assert_eq!(
            client_data_hash(b"abc"),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad
            ]
        );
    }

    #[test]
    fn make_credential_has_the_documented_shape() {
        let request = MakeCredential {
            challenge: b"c",
            rp_id: "ssh:example",
            user_id: &[0xaa; 32],
            alg: COSE_ES256,
            resident_key: false,
            user_verification: false,
        }
        .encode();

        assert_eq!(request.command, ctap::Command(0x01));
        let p = params(&request);
        assert_eq!(
            p.get(2)
                .and_then(|rp| rp.get_str("id"))
                .and_then(Value::as_str),
            Some("ssh:example")
        );
        assert_eq!(
            p.get(3)
                .and_then(|u| u.get_str("id"))
                .and_then(Value::as_bytes),
            Some(&[0xaa; 32][..])
        );
        // pubKeyCredParams is an array of {alg, type}.
        let Some(Value::Array(algs)) = p.get(4) else {
            panic!("pubKeyCredParams must be an array")
        };
        assert_eq!(algs[0].get_str("alg").and_then(Value::as_i64), Some(-7));
        assert_eq!(
            algs[0].get_str("type").and_then(Value::as_str),
            Some("public-key")
        );
        // No options were asked for, so the key is absent rather than false.
        assert!(p.get(7).is_none());
    }

    #[test]
    fn options_appear_only_when_requested() {
        let request = MakeCredential {
            challenge: b"c",
            rp_id: "ssh:",
            user_id: &DEFAULT_USER_ID,
            alg: COSE_EDDSA,
            resident_key: true,
            user_verification: true,
        }
        .encode();
        let p = params(&request);
        let options = p.get(7).expect("options present");
        assert_eq!(options.get_str("rk"), Some(&Value::Bool(true)));
        assert_eq!(options.get_str("uv"), Some(&Value::Bool(true)));
    }

    #[test]
    fn get_assertion_has_the_documented_shape() {
        let request = GetAssertion {
            challenge: b"message",
            rp_id: "ssh:host",
            credential_id: &[0x11; 64],
            user_verification: false,
        }
        .encode();

        assert_eq!(request.command, ctap::Command(0x02));
        let p = params(&request);
        assert_eq!(p.get(1).and_then(Value::as_str), Some("ssh:host"));
        assert_eq!(
            p.get(2).and_then(Value::as_bytes),
            Some(&client_data_hash(b"message")[..])
        );
        let Some(Value::Array(allow)) = p.get(3) else {
            panic!("allowList must be an array")
        };
        assert_eq!(
            allow[0].get_str("id").and_then(Value::as_bytes),
            Some(&[0x11; 64][..])
        );
        // `up` is never sent false from here: presence is the point, and
        // §15.3 forbids arranging to skip it.
        assert!(p.get(5).is_none());
    }

    #[test]
    fn requests_are_canonical_cbor() {
        // The authenticator is entitled to reject non-canonical input, and
        // re-encoding must be a fixed point.
        for request in [
            MakeCredential {
                challenge: b"c",
                rp_id: "ssh:",
                user_id: &DEFAULT_USER_ID,
                alg: COSE_ES256,
                resident_key: true,
                user_verification: true,
            }
            .encode(),
            GetAssertion {
                challenge: b"m",
                rp_id: "ssh:",
                credential_id: &[1, 2, 3],
                user_verification: true,
            }
            .encode(),
        ] {
            let decoded = Value::decode(&request.params).expect("valid CBOR");
            assert_eq!(decoded.encode(), request.params, "not canonical");
        }
    }

    #[test]
    fn negative_algorithms_encode_as_cbor_negatives() {
        assert_eq!(algorithm(COSE_ES256), Value::Negative(6));
        assert_eq!(algorithm(COSE_EDDSA), Value::Negative(7));
        assert_eq!(algorithm(COSE_ES256).as_i64(), Some(-7));
    }
}
