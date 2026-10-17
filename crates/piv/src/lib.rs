//! The PIV card edge.
//!
//! PIV, not FIDO, is what logs a user into a Mac or a standalone Windows PC
//! (PROJECT.md §11). This crate is the half of that the host speaks: ISO 7816
//! APDUs, the BER-TLV subset PIV uses, and the SP 800-73-5 command set.
//!
//! # What this crate is not
//!
//! It performs **no I/O**. It builds commands and reads answers; a transport
//! carries them. Over USB that transport is the operating system's own CCID
//! stack and nothing here is involved at all; over BLE the daemon relays the
//! same APDUs through `vpcd`. The card edge is identical either way, which is
//! the reason this is a crate and not part of a transport.
//!
//! It holds **no key material** and performs no cryptography. Private keys stay
//! on the device (§15.1); certificates are built by the provisioning tool and
//! handed here as bytes.
//!
//! # Who may use this — the daemon may not
//!
//! PROJECT.md §8 says the daemon relays payloads it does not interpret, and
//! that rule is unchanged. On the relay path an APDU is an opaque `Vec<u8>`
//! from `vpcd` to the radio and back; parsing it there would add a second
//! place for the card edge to be misread, in the process that also owns the
//! link, for no benefit — the OS already built the APDU and will parse the
//! answer.
//!
//! This crate exists for the **host-side client**: the provisioning tool that
//! generates a key in a slot and writes a certificate into it, which has to
//! build those APDUs because nothing else will. `daemon` therefore does not
//! depend on `piv`, and a test in that crate keeps it that way.
//!
//! # Everything is transcribed from the specification
//!
//! Each builder names the section of SP 800-73-5 it comes from, and the tests
//! assert against the command syntax tables rather than against a capture from
//! our own firmware. Two implementations agreeing is not evidence when both
//! were written from the same misreading (PROJECT.md §20).
//!
//! # Sources
//!
//! - NIST SP 800-73-5 Part 1, Data Model and Representation, July 2024
//! - NIST SP 800-73-5 Part 2, Card Command Interface, July 2024

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod apdu;
pub mod cert;
pub mod chaining;
pub mod cli;
pub mod commands;
pub mod objects;
pub mod provision;
pub mod tlv;

pub use apdu::{ApduError, Command, Response, StatusWord};
pub use cert::{CertError, CertificateBuilder, KeyUsage, ParsedCertificate};
pub use chaining::{chain, ChainError, Collector, Next};
pub use cli::{help_text, parse_args, parse_slot, run_provision, CliCommand, CliError};
pub use objects::{ObjectError, Slot};
pub use provision::{
    CardTransceiver, ProvisionError, ProvisionOptions, ProvisionReport, SimulatedCard,
};
pub use tlv::{Tag, Tlv, TlvError};

/// Cryptographic mechanism identifiers, SP 800-78-5 Table 9.
///
/// These go in P1 of `GENERAL AUTHENTICATE` and in the `80` element of a
/// `GENERATE ASYMMETRIC KEY PAIR` control reference template.
pub mod algorithm {
    /// RSA 2048.
    pub const RSA_2048: u8 = 0x07;
    /// ECDSA on Curve P-256.
    pub const ECC_P256: u8 = 0x11;
    /// ECDSA on Curve P-384.
    pub const ECC_P384: u8 = 0x14;
}
