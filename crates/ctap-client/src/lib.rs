//! The CTAP2 client half: the work a browser normally does.
//!
//! `crates/ctap` deliberately does not parse CBOR, because the daemon is a
//! relay and a relay that interprets payloads it has no business reading only
//! adds attack surface (PROJECT.md §8, §21). But *something* has to build an
//! `authenticatorMakeCredential` request and pull a credential id out of an
//! attestation object — and for SSH there is no browser to do it. That is this
//! crate.
//!
//! It is a **client**, not a relay: it lives in `sk-middleware`, on the far side
//! of the daemon's IPC boundary, and the daemon never links it.
//!
//! Pure: no I/O, no platform APIs, no hardware.
//!
//! # Scope correction
//!
//! PROJECT.md §7 called the SSH middleware "Small". The FFI shim is; this is
//! not. Building requests, decoding attestation objects, extracting COSE keys
//! and splitting DER signatures is the bulk of a WebAuthn client, and it is the
//! real distance between `sk_api_version()` returning and `ssh-keygen -t
//! ed25519-sk` producing a key.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod authdata;
pub mod cbor;
pub mod cose;
pub mod cred_mgmt;
pub mod der;
pub mod fixtures;
pub mod pin_protocol;
pub mod request;
pub mod response;

pub use authdata::{AttestedCredential, AuthDataError, AuthenticatorData};
pub use cbor::{CborError, Value};
pub use cose::{CoseError, CoseKey};
pub use der::{split_ecdsa_signature, DerError};
pub use request::{client_data_hash, GetAssertion, MakeCredential, COSE_EDDSA, COSE_ES256};
pub use response::{GetAssertionResponse, MakeCredentialResponse, ResponseError};
