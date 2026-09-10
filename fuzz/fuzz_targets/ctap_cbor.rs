//! Fuzz target: CBOR and the structures decoded from it (PROJECT.md §14).
//!
//! Input reaches these parsers from the device, in both directions. Bonding
//! does not make it trustworthy — half-flashed firmware sends garbage that is
//! perfectly authenticated — and the attestation object in particular is
//! attacker-influenced through the relying party id.

#![no_main]

use ctap_client::{AuthenticatorData, CoseKey, Value};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Decoding must never panic, and encoding must be idempotent *at the byte
    // level*. Value equality is the wrong invariant: maps are held in wire
    // order and only sorted on encode, so a peer sending unsorted keys
    // legitimately decodes to a differently-ordered Value that encodes to the
    // same canonical bytes.
    if let Ok(value) = Value::decode(data) {
        let once = value.encode();
        let decoded = Value::decode(&once).expect("our own canonical output must decode");
        let twice = decoded.encode();
        assert_eq!(once, twice, "canonical encoding is not idempotent");

        let _ = CoseKey::from_value(&value);
    }

    let _ = Value::decode_prefix(data);
    let _ = AuthenticatorData::parse(data);
    let _ = ctap_client::split_ecdsa_signature(data);
});
