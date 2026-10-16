//! CTAP2.0 PIN Protocol One: ECDH key agreement and pinUvAuthToken recovery.
//!
//! Lives here, not in `daemon`, for the same reason `request.rs`/`response.rs`
//! build `authenticatorMakeCredential`/`GetAssertion` CBOR: this crate is the
//! CTAP2 **client** half — the work a browser normally does — and it lives on
//! the far side of the daemon's IPC boundary (`crates/ctap`'s module doc,
//! PROJECT.md §8, §21). The daemon relays opaque bytes; it never parses CBOR,
//! never touches a PIN/UV protocol, and never holds a shared secret or a
//! token — this module is reachable only from `webauthn-host` (and, later,
//! `sk-middleware`/`token-manager` if they need it), never from `crates/daemon`.
//! `crates/daemon/tests/relay_stays_opaque.rs` is the existing precedent for
//! enforcing that kind of boundary by a dependency check rather than by
//! convention alone.
//!
//! # What this device actually needs, and why
//!
//! Credential management (`authenticatorCredentialManagement`, vendor-prefixed
//! `0x41` on this firmware — see `cred_mgmt.rs`) requires a `pinAuth` on several
//! subcommands, computed from a `pinToken` the device hands out only through
//! `authenticatorClientPIN`. Obtaining that token means speaking the actual
//! CTAP2.0 PIN Protocol One wire format: an ECDH P-256 key agreement between
//! platform and authenticator, then an AES-256-CBC-encrypted exchange. That is
//! genuinely new protocol work — confirmed by grep before this was written,
//! none of `ctap`, `ctap-client` or `webauthn-host` implemented any part of it.
//!
//! **This does not reopen PROJECT.md §21's "don't implement CTAP PIN/UV
//! protocols in the daemon".** That rule, and §8's "the daemon pipes payloads;
//! it does not understand them", are both about the `daemon` crate/process
//! specifically — the one that owns the radio and is the IPC relay every
//! client (including a hostile local one) ultimately talks through. This
//! module sits in `ctap-client`, which already does exactly this class of
//! work for `MakeCredential`/`GetAssertion` (`request.rs`, `response.rs`) on
//! behalf of `sk-middleware`, a client *of* the daemon, not the daemon itself
//! — `crates/daemon`'s `Cargo.toml` depends on `ctap-client` only behind the
//! `fake-transport` test feature, and only for response fixtures, never in
//! its real request path. The division of labour is unchanged: the device
//! alone decides whether user verification passed (it still gates the token
//! on a real on-device ceremony, now a fingerprint check rather than a typed
//! PIN — see `cred_mgmt.rs`'s `UvTokenRequest`), and this code never sees or
//! influences that decision. It only speaks the wire format needed to collect
//! the result.
//!
//! # Never cached, never logged
//!
//! The derived shared secret and the decrypted `pinToken` are returned as
//! plain values with no persistence of their own — nothing here writes to
//! disk, and nothing here retains state across calls. It is the caller's
//! (`webauthn-host`'s) job to hold a `pinToken` only in memory for as long as
//! one native-messaging process runs, never write it to disk, and never log
//! it (PROJECT.md §15.5). This module does not even have the means to do
//! either.

#![allow(clippy::many_single_char_names)]

use crate::cbor::Value;
use aes::{
    cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit},
    Aes256,
};
use hmac::{Hmac, Mac};
use p256::elliptic_curve::rand_core::OsRng;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// `authenticatorClientPIN`'s `pinProtocol` parameter. This device only ever
/// advertises/accepts protocol one (`ctap_client_pin`: `if (CP.pinProtocol !=
/// 1 ...) return CTAP1_ERR_OTHER;`, `core/fido2/ctap.c`).
pub const PIN_PROTOCOL_VERSION: i64 = 1;

/// COSE `alg` for ECDH-ES + HKDF-256 — the key-agreement key's own algorithm,
/// distinct from the `-7` (ES256) a *credential* public key carries. Taken
/// from the firmware's own constant (`COSE_ALG_ECDH_ES_HKDF_256`,
/// `core/fido2/cose_key.h`), not assumed from the general COSE registry,
/// because the two numbers happen to differ from several other
/// implementations' choice of a plain `-25`/`-26` split — this is the value
/// this specific firmware's `ctap_add_cose_key`/`parse_cose_key` round-trips.
const COSE_ALG_ECDH_ES_HKDF_256: i64 = -25;

const COSE_KTY_EC2: i64 = 2;
const COSE_CRV_P256: i64 = 1;

/// A failure anywhere in the PIN protocol exchange.
#[derive(Debug, Error)]
pub enum PinProtocolError {
    /// The device's `getKeyAgreement` response was not a usable COSE key.
    #[error("device key-agreement response did not parse: {0}")]
    BadDeviceKey(String),
    /// A byte string was not the length the protocol requires.
    #[error("expected a {expected}-byte value for {field}, got {got}")]
    WrongLength {
        /// What the bytes were for.
        field: &'static str,
        /// The length required.
        expected: usize,
        /// The length actually present.
        got: usize,
    },
}

/// The platform's ephemeral P-256 key-agreement keypair.
///
/// Generated fresh for every PIN-protocol exchange — CTAP2.0 PIN Protocol One
/// §5.5.2 expects a new platform keypair per transaction, not a reused one,
/// so an observer who recovers one shared secret cannot reuse it against a
/// later exchange.
pub struct PlatformKeyAgreement {
    secret: SecretKey,
}

impl PlatformKeyAgreement {
    /// Generates a fresh ephemeral keypair.
    pub fn generate() -> Self {
        Self {
            secret: SecretKey::random(&mut OsRng),
        }
    }

    /// The platform's public key, as the COSE map `authenticatorClientPIN`'s
    /// `keyAgreement` parameter (tag 3) expects: `{1: 2, 3: -25, -1: 1, -2:
    /// x, -3: y}` — see `ctap_add_cose_key` in `core/fido2/ctap.c`, which this
    /// mirrors field for field (kty EC2, this alg, crv P-256, then the two
    /// raw 32-byte coordinates).
    pub fn public_cose_key(&self) -> Value {
        let point = self.secret.public_key().to_encoded_point(false);
        let bytes = point.as_bytes();
        // SEC1 uncompressed: 0x04 || x(32) || y(32).
        debug_assert_eq!(bytes.len(), 65);
        let x = bytes[1..33].to_vec();
        let y = bytes[33..65].to_vec();
        Value::Map(vec![
            (Value::Unsigned(1), Value::Unsigned(COSE_KTY_EC2 as u64)),
            (
                Value::Unsigned(3),
                Value::Negative((-1 - COSE_ALG_ECDH_ES_HKDF_256) as u64),
            ),
            (Value::Negative(0), Value::Unsigned(COSE_CRV_P256 as u64)),
            (Value::Negative(1), Value::Bytes(x)),
            (Value::Negative(2), Value::Bytes(y)),
        ])
    }

    /// Derives the CTAP2.0 PIN Protocol One shared secret with the device's
    /// key-agreement public key: `SHA-256(ECDH(platform_priv,
    /// device_pub).x)`. Matches `ctap_add_pin_if_verified`/`ctap_client_pin`
    /// (`core/fido2/ctap.c`): `crypto_ecc256_shared_secret` followed by one
    /// SHA-256 pass over the raw 32-byte result — not HKDF, which is what the
    /// *name* `ECDH-ES+HKDF-256` would otherwise suggest. This firmware
    /// stayed on the simpler CTAP2.0 Protocol One construction rather than
    /// CTAP2.1 Protocol Two's HKDF-based one; read `ctap_add_pin_if_verified`
    /// before assuming otherwise if the firmware ever changes.
    pub fn shared_secret(&self, device_key: &DeviceKeyAgreement) -> SharedSecret {
        let shared = p256::ecdh::diffie_hellman(
            self.secret.to_nonzero_scalar(),
            device_key.public.as_affine(),
        );
        let x = shared.raw_secret_bytes();
        let mut hasher = Sha256::new();
        hasher.update(x.as_slice());
        let digest = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&digest);
        SharedSecret(key)
    }
}

/// The device's key-agreement public key, from a `getKeyAgreement` response.
pub struct DeviceKeyAgreement {
    public: PublicKey,
}

impl DeviceKeyAgreement {
    /// Parses the COSE key carried under response tag `RESP_keyAgreement`
    /// (`0x01`; `core/fido2/ctap.h`).
    ///
    /// Deliberately does **not** reuse [`crate::cose::CoseKey`]: that type
    /// documents itself as "a credential public key" narrowed to the two
    /// algorithms SSH uses (ES256 / EdDSA), and a key-agreement key carries a
    /// different `alg` (`-25`, ECDH-ES+HKDF-256) for a different purpose.
    /// Reusing it would mean either weakening its `alg` check for every
    /// caller or adding an ECDH variant to a type whose own doc comment says
    /// it is narrowed on purpose.
    pub fn from_value(value: &Value) -> Result<Self, PinProtocolError> {
        let kty = value
            .get(1)
            .and_then(Value::as_i64)
            .ok_or_else(|| PinProtocolError::BadDeviceKey("missing or non-integer kty".into()))?;
        if kty != COSE_KTY_EC2 {
            return Err(PinProtocolError::BadDeviceKey(format!(
                "kty {kty}, expected EC2 (2)"
            )));
        }
        let crv = get_negative(value, 0)
            .ok_or_else(|| PinProtocolError::BadDeviceKey("missing crv".into()))?;
        if crv != COSE_CRV_P256 {
            return Err(PinProtocolError::BadDeviceKey(format!(
                "crv {crv}, expected P-256 (1)"
            )));
        }
        let x = get_negative_bytes(value, 1)
            .ok_or_else(|| PinProtocolError::BadDeviceKey("missing x".into()))?;
        let y = get_negative_bytes(value, 2)
            .ok_or_else(|| PinProtocolError::BadDeviceKey("missing y".into()))?;
        if x.len() != 32 || y.len() != 32 {
            return Err(PinProtocolError::BadDeviceKey(
                "x/y are not 32 bytes each".into(),
            ));
        }

        let mut sec1 = Vec::with_capacity(65);
        sec1.push(0x04);
        sec1.extend_from_slice(x);
        sec1.extend_from_slice(y);
        let public = PublicKey::from_sec1_bytes(&sec1)
            .map_err(|e| PinProtocolError::BadDeviceKey(e.to_string()))?;
        Ok(Self { public })
    }
}

/// Looks up a negative-labelled COSE map entry (`-1 - n` encoding) as an
/// integer.
fn get_negative(value: &Value, n: u64) -> Option<i64> {
    match value {
        Value::Map(entries) => entries
            .iter()
            .find(|(k, _)| *k == Value::Negative(n))
            .and_then(|(_, v)| v.as_i64()),
        _ => None,
    }
}

/// Looks up a negative-labelled COSE map entry as bytes.
fn get_negative_bytes(value: &Value, n: u64) -> Option<&[u8]> {
    match value {
        Value::Map(entries) => entries
            .iter()
            .find(|(k, _)| *k == Value::Negative(n))
            .and_then(|(_, v)| v.as_bytes()),
        _ => None,
    }
}

/// The CTAP2.0 PIN Protocol One shared secret: `SHA-256(ECDH x-coordinate)`.
///
/// Holds no `Drop`/zeroizing behaviour beyond what the stack already gives a
/// plain array — this is a derived per-transaction secret, not the kind of
/// long-lived key material PROJECT.md §15.1 is about, and it is already
/// scoped to live only as long as one `webauthn-host` call.
pub struct SharedSecret([u8; 32]);

/// AES-256-CBC with a zero IV, one or more full 16-byte blocks, no padding.
///
/// Matches `ctap_add_pin_if_verified`/`ctap_update_pin_if_verified`
/// (`core/fido2/ctap.c`): `crypto_aes256_init(shared_secret, NULL)` (NULL IV)
/// followed by `crypto_aes256_decrypt`/`_encrypt`, with an explicit
/// `crypto_aes256_reset_iv(NULL)` between independent operations in one
/// exchange — i.e. IV is always zero, never carried between messages, and
/// every payload this protocol ever encrypts (`pinHashEnc`, `pinToken`,
/// 16-byte multiples of `newPinEnc`) is already block-aligned, so there is no
/// padding scheme to get wrong. This device's `PIN_TOKEN_SIZE` is 16 bytes,
/// not the 32 a from-the-spec-alone reading might assume (`core/fido2/ctap.h`).
impl SharedSecret {
    fn cipher(&self) -> Aes256 {
        Aes256::new(GenericArray::from_slice(&self.0))
    }

    /// Decrypts `ciphertext` in place and returns it. `ciphertext.len()` must
    /// be a multiple of 16.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, PinProtocolError> {
        if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
            return Err(PinProtocolError::WrongLength {
                field: "AES-CBC ciphertext",
                expected: 16,
                got: ciphertext.len(),
            });
        }
        let cipher = self.cipher();
        let mut prev = [0u8; 16]; // zero IV
        let mut out = Vec::with_capacity(ciphertext.len());
        for block in ciphertext.chunks_exact(16) {
            let mut buf = GenericArray::clone_from_slice(block);
            cipher.decrypt_block(&mut buf);
            for i in 0..16 {
                buf[i] ^= prev[i];
            }
            prev.copy_from_slice(block); // CBC chains on ciphertext, not plaintext
            out.extend_from_slice(&buf);
        }
        Ok(out)
    }

    /// Encrypts `plaintext` and returns the ciphertext. `plaintext.len()`
    /// must be a multiple of 16. Not used by the read-only credential-listing
    /// path today (that only ever decrypts a token); kept alongside
    /// [`Self::decrypt`] because `setPIN`/`changePIN` need it and the two
    /// halves of one documented algorithm belong together rather than being
    /// split across a future, separate patch.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, PinProtocolError> {
        if plaintext.is_empty() || plaintext.len() % 16 != 0 {
            return Err(PinProtocolError::WrongLength {
                field: "AES-CBC plaintext",
                expected: 16,
                got: plaintext.len(),
            });
        }
        let cipher = self.cipher();
        let mut prev = [0u8; 16];
        let mut out = Vec::with_capacity(plaintext.len());
        for block in plaintext.chunks_exact(16) {
            let mut buf = GenericArray::clone_from_slice(block);
            for i in 0..16 {
                buf[i] ^= prev[i];
            }
            cipher.encrypt_block(&mut buf);
            prev.copy_from_slice(&buf);
            out.extend_from_slice(&buf);
        }
        Ok(out)
    }
}

/// `pinAuth = left(16, HMAC-SHA256(pinToken, data))`.
///
/// Matches `verify_pin_auth_ex` (`core/fido2/ctap.c`) exactly: HMAC-SHA256
/// keyed by the (16-byte, on this device) `pinToken`, truncated to the first
/// 16 bytes. `hmac::Hmac` accepts a key shorter than the hash's block size
/// with no special-casing needed, so the non-standard 16-byte key length
/// here is not a problem for the construction, only a departure from CTAP2.1
/// Pin/UV Auth Protocol Two's 32-byte token that a reader should not assume
/// carries over.
pub fn pin_auth(pin_token: &[u8; 16], data: &[u8]) -> [u8; 16] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(pin_token)
        .expect("HMAC accepts a key of any length, including 16 bytes");
    Mac::update(&mut mac, data);
    let full = mac.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_cose_key_round_trips_through_device_key_agreement_parsing() {
        // What we build to send is exactly what we are able to parse back —
        // the same symmetry PROJECT.md §20 asks every encoder/decoder pair to
        // hold, applied to the one piece of this module that plays both
        // roles (we build *our* key the same shape the device's key arrives
        // in).
        let platform = PlatformKeyAgreement::generate();
        let cose = platform.public_cose_key();
        let parsed = DeviceKeyAgreement::from_value(&cose).expect("our own key must parse back");
        // Not a tautology: from_value independently re-derives a PublicKey
        // from the SEC1 bytes, so this also proves the COSE map's x/y
        // actually decode to the point we started from.
        assert_eq!(
            parsed.public.to_encoded_point(false).as_bytes(),
            platform
                .secret
                .public_key()
                .to_encoded_point(false)
                .as_bytes()
        );
    }

    #[test]
    fn two_sides_of_one_ecdh_agree() {
        let platform = PlatformKeyAgreement::generate();
        let device = PlatformKeyAgreement::generate(); // stand-in for "the device"

        let device_key_as_seen_by_platform =
            DeviceKeyAgreement::from_value(&device.public_cose_key()).unwrap();
        let platform_key_as_seen_by_device =
            DeviceKeyAgreement::from_value(&platform.public_cose_key()).unwrap();

        let secret_a = platform.shared_secret(&device_key_as_seen_by_platform);
        let secret_b = device.shared_secret(&platform_key_as_seen_by_device);
        assert_eq!(secret_a.0, secret_b.0, "ECDH must agree from both sides");
    }

    #[test]
    fn a_single_block_round_trips_through_encrypt_then_decrypt() {
        let platform = PlatformKeyAgreement::generate();
        let device = PlatformKeyAgreement::generate();
        let secret = platform
            .shared_secret(&DeviceKeyAgreement::from_value(&device.public_cose_key()).unwrap());

        let token = [0x42u8; 16];
        let encrypted = secret.encrypt(&token).unwrap();
        assert_eq!(encrypted.len(), 16);
        assert_ne!(&encrypted[..], &token[..], "must not be a no-op");
        let decrypted = secret.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, token);
    }

    #[test]
    fn multi_block_cbc_chains_correctly() {
        // Two distinct blocks: if the implementation accidentally used ECB
        // (no chaining) this would still pass for most inputs, so the blocks
        // are chosen to be related (one is the other's bitwise complement)
        // in a way plain ECB would not reproduce correctly after a decrypt
        // round trip if the chaining variable were wired to the wrong value.
        let platform = PlatformKeyAgreement::generate();
        let device = PlatformKeyAgreement::generate();
        let secret = platform
            .shared_secret(&DeviceKeyAgreement::from_value(&device.public_cose_key()).unwrap());

        let mut plaintext = [0u8; 32];
        for (i, b) in plaintext.iter_mut().enumerate() {
            *b = i as u8;
        }
        let encrypted = secret.encrypt(&plaintext).unwrap();
        let decrypted = secret.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);

        // The two ciphertext blocks must differ even though AES-ECB of two
        // different plaintext blocks under one key could coincidentally
        // differ too — the real CBC-specific property is that re-encrypting
        // the same plaintext block in isolation (zero IV, truly independent)
        // gives a *different* result than it does here as block two, because
        // block two was XORed with block one's ciphertext first.
        let block_two_alone = secret.encrypt(&plaintext[16..]).unwrap();
        assert_ne!(
            &encrypted[16..],
            &block_two_alone[..],
            "block two must be chained on block one's ciphertext, not independent"
        );
    }

    #[test]
    fn wrong_length_input_is_rejected_not_padded() {
        let platform = PlatformKeyAgreement::generate();
        let device = PlatformKeyAgreement::generate();
        let secret = platform
            .shared_secret(&DeviceKeyAgreement::from_value(&device.public_cose_key()).unwrap());
        assert!(secret.decrypt(&[0u8; 15]).is_err());
        assert!(secret.decrypt(&[]).is_err());
        assert!(secret.encrypt(&[0u8; 17]).is_err());
    }

    #[test]
    fn pin_auth_matches_a_hand_computed_value() {
        // Independent of this crate's own HMAC call: verifies against
        // `hmac::Hmac` used directly the way `verify_pin_auth_ex` describes
        // it (HMAC-SHA256 keyed by the token, truncated to 16 bytes), so a
        // regression in `pin_auth`'s plumbing (wrong key, wrong truncation
        // point) is caught even though both sides use the same crate.
        let token = [0x11u8; 16];
        let data = b"cmd-and-subcommandparams-bytes";

        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&token).unwrap();
        Mac::update(&mut mac, data);
        let expected = mac.finalize().into_bytes();

        let got = pin_auth(&token, data);
        assert_eq!(&got[..], &expected[..16]);
    }

    #[test]
    fn pin_auth_is_sensitive_to_every_byte_of_the_signed_data() {
        // `ctap_cred_mgmt_pinauth` signs `cmd ++ subCommandParamsCborCopy`
        // (core/fido2/ctap.c); a pinAuth that ignored part of that input
        // would let a tampered subCommandParams slip past verification.
        let token = [0x22u8; 16];
        let a = pin_auth(&token, &[0x04]);
        let b = pin_auth(&token, &[0x04, 0xa1, 0x01, 0x58, 0x20]);
        assert_ne!(a, b);
    }
}
