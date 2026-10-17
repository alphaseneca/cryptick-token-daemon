//! Cryptick Hardware Token Manager (`cryptick-manager`) Library.
//!
//! Provides a comprehensive implementation of the Cryptick Manager command suite
//! for Cryptick Token (`0x1209:0xBEEE`), bridging USB CTAPHID and Bluetooth Low Energy
//! to provide hardware OATH-TOTP/HOTP, device configuration, and APDU management.

#![deny(missing_docs)]

pub mod access;
pub mod apdu;
pub mod cli;
pub mod config;
pub mod error;
pub mod oath;
pub mod otpauth;
pub mod script;
pub mod tlv;
pub mod transport;

pub use apdu::{aid, CommandApdu, ResponseApdu, StatusWord};
pub use error::ManagerError;
pub use oath::{
    calculate_code, list_accounts, put_account, select_oath, CalculatedCode, OathAccountSummary,
};
pub use otpauth::{decode_base32, encode_base32, HashAlgorithm, OathType, OtpAuthUri};
pub use transport::{DualTransport, TokenTransport};
