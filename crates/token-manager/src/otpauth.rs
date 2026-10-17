//! RFC 6238 / RFC 4226 `otpauth://` URI parsing and RFC 4648 Base32 decoding.
//!
//! Provides parsing and validation for two-factor authentication URIs
//! imported into Cryptick Token hardware.

use std::fmt;

use crate::error::ManagerError;

/// OATH OTP generation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OathType {
    /// Time-based One-Time Password (RFC 6238).
    Totp,
    /// HMAC-based One-Time Password (RFC 4226).
    Hotp,
}

impl OathType {
    /// Returns the wire protocol algorithm type nibble (0x2 = TOTP, 0x1 = HOTP).
    pub fn type_nibble(self) -> u8 {
        match self {
            Self::Totp => 0x20,
            Self::Hotp => 0x10,
        }
    }
}

impl fmt::Display for OathType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Totp => write!(f, "TOTP"),
            Self::Hotp => write!(f, "HOTP"),
        }
    }
}

/// Supported HMAC hash algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashAlgorithm {
    /// HMAC-SHA-1 (Default).
    Sha1,
    /// HMAC-SHA-256.
    Sha256,
    /// HMAC-SHA-512.
    Sha512,
}

impl HashAlgorithm {
    /// Returns the wire protocol algorithm byte for a given OATH type.
    pub fn to_algo_byte(self, oath_type: OathType) -> u8 {
        let type_code = match oath_type {
            OathType::Totp => 0x20,
            OathType::Hotp => 0x10,
        };
        let hash_code = match self {
            HashAlgorithm::Sha1 => 0x01,
            HashAlgorithm::Sha256 => 0x02,
            HashAlgorithm::Sha512 => 0x03,
        };
        type_code | hash_code
    }

    /// Parses an algorithm byte from token wire format (e.g. 0x21, 0x11, 0x22).
    pub fn from_algo_byte(byte: u8) -> Option<(OathType, HashAlgorithm)> {
        let oath_type = match byte & 0xF0 {
            0x10 => OathType::Hotp,
            0x20 => OathType::Totp,
            _ => return None,
        };
        let hash_alg = match byte & 0x07 {
            0x01 => HashAlgorithm::Sha1,
            0x02 => HashAlgorithm::Sha256,
            0x03 => HashAlgorithm::Sha512,
            _ => return None,
        };
        Some((oath_type, hash_alg))
    }
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sha1 => write!(f, "SHA1"),
            Self::Sha256 => write!(f, "SHA256"),
            Self::Sha512 => write!(f, "SHA512"),
        }
    }
}

/// Decodes an RFC 4648 Base32 string into binary bytes.
///
/// Handles case-insensitivity, ignores spaces and hyphens, and accepts
/// both padded (`=`) and unpadded inputs.
pub fn decode_base32(input: &str) -> Result<Vec<u8>, ManagerError> {
    let mut clean = String::with_capacity(input.len());
    for c in input.chars() {
        if c.is_whitespace() || c == '-' {
            continue;
        }
        if c == '=' {
            break; // Stop at padding
        }
        let upper = c.to_ascii_uppercase();
        clean.push(upper);
    }

    if clean.is_empty() {
        return Err(ManagerError::InvalidInput("Base32 input is empty".to_string()));
    }

    let mut out = Vec::new();
    let mut buffer = 0u64;
    let mut bits_left = 0;

    for c in clean.chars() {
        let val = match c {
            'A'..='Z' => (c as u8 - b'A') as u64,
            '2'..='7' => (c as u8 - b'2' + 26) as u64,
            _ => {
                return Err(ManagerError::InvalidInput(format!(
                    "Invalid Base32 character: '{c}'"
                )))
            }
        };

        buffer = (buffer << 5) | val;
        bits_left += 5;

        if bits_left >= 8 {
            bits_left -= 8;
            out.push(((buffer >> bits_left) & 0xFF) as u8);
        }
    }

    Ok(out)
}

/// Encodes binary bytes into an RFC 4648 Base32 uppercase string without padding.
pub fn encode_base32(data: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let mut buffer = 0u64;
    let mut bits_left = 0;

    for &b in data {
        buffer = (buffer << 8) | (b as u64);
        bits_left += 8;
        while bits_left >= 5 {
            bits_left -= 5;
            let idx = ((buffer >> bits_left) & 0x1F) as usize;
            out.push(ALPHABET[idx] as char);
        }
    }

    if bits_left > 0 {
        let idx = ((buffer << (5 - bits_left)) & 0x1F) as usize;
        out.push(ALPHABET[idx] as char);
    }

    out
}

/// Decodes standard percent-encoded URL sequences (e.g. `%20` -> `' '`).
pub fn url_decode(s: &str) -> String {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(val) = u8::from_str_radix(
                match std::str::from_utf8(&bytes[i + 1..i + 3]) {
                    Ok(v) => v,
                    Err(_) => {
                        out.push(bytes[i]);
                        i += 1;
                        continue;
                    }
                },
                16,
            ) {
                out.push(val);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

/// A parsed `otpauth://` authentication credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtpAuthUri {
    /// OATH type (TOTP or HOTP).
    pub oath_type: OathType,
    /// Account label/name (e.g. `alice@example.com` or `GitHub:alice`).
    pub account: String,
    /// Issuer provider (e.g. `GitHub` or `AWS`).
    pub issuer: Option<String>,
    /// Raw binary secret seed.
    pub secret: Vec<u8>,
    /// Hash algorithm.
    pub algorithm: HashAlgorithm,
    /// Digits in generated code (usually 6 or 8).
    pub digits: u32,
    /// Step duration in seconds for TOTP (default 30).
    pub period: u32,
    /// Initial counter value for HOTP (default 0).
    pub counter: u64,
}

impl OtpAuthUri {
    /// Returns the canonical on-token account name: `Issuer:Account` if issuer is present,
    /// or just `Account` if no issuer is specified or if already prefixed.
    pub fn canonical_name(&self) -> String {
        if let Some(ref iss) = self.issuer {
            if !iss.is_empty() && !self.account.starts_with(&format!("{iss}:")) {
                return format!("{iss}:{}", self.account);
            }
        }
        self.account.clone()
    }

    /// Parses an `otpauth://` URI.
    pub fn parse(uri_str: &str) -> Result<Self, ManagerError> {
        let uri = uri_str.trim();
        if !uri.starts_with("otpauth://") && !uri.starts_with("OTPAUTH://") {
            return Err(ManagerError::InvalidInput(
                "URI scheme must be 'otpauth://'".to_string(),
            ));
        }

        let without_scheme = &uri["otpauth://".len()..];
        let (type_str, rest) = match without_scheme.find('/') {
            Some(idx) => (&without_scheme[..idx], &without_scheme[idx + 1..]),
            None => {
                return Err(ManagerError::InvalidInput(
                    "Malformed otpauth URI: missing path after type".to_string(),
                ))
            }
        };

        let oath_type = match type_str.to_ascii_lowercase().as_str() {
            "totp" => OathType::Totp,
            "hotp" => OathType::Hotp,
            other => {
                return Err(ManagerError::InvalidInput(format!(
                    "Unsupported OTP type '{other}' (expected totp or hotp)"
                )))
            }
        };

        let (raw_label, query_str) = match rest.find('?') {
            Some(idx) => (&rest[..idx], &rest[idx + 1..]),
            None => (rest, ""),
        };

        let decoded_label = url_decode(raw_label);
        let mut account = decoded_label.clone();
        let mut issuer_from_label = None;

        if let Some(colon_idx) = decoded_label.find(':') {
            let iss = decoded_label[..colon_idx].trim();
            let acc = decoded_label[colon_idx + 1..].trim();
            if !iss.is_empty() {
                issuer_from_label = Some(iss.to_string());
            }
            if !acc.is_empty() {
                account = acc.to_string();
            }
        }

        let mut secret = None;
        let mut issuer_from_param = None;
        let mut algorithm = HashAlgorithm::Sha1;
        let mut digits = 6u32;
        let mut period = 30u32;
        let mut counter = 0u64;

        for param in query_str.split('&') {
            if param.is_empty() {
                continue;
            }
            let (key, val) = match param.find('=') {
                Some(idx) => (&param[..idx], &param[idx + 1..]),
                None => (param, ""),
            };
            let decoded_val = url_decode(val);

            match key.to_ascii_lowercase().as_str() {
                "secret" => {
                    secret = Some(
                        decode_base32(&decoded_val)
                            .map_err(|e| format!("Invalid Base32 in secret parameter: {e}"))?,
                    );
                }
                "issuer" => {
                    if !decoded_val.is_empty() {
                        issuer_from_param = Some(decoded_val);
                    }
                }
                "algorithm" => {
                    algorithm = match decoded_val.to_ascii_uppercase().as_str() {
                        "SHA1" => HashAlgorithm::Sha1,
                        "SHA256" => HashAlgorithm::Sha256,
                        "SHA512" => HashAlgorithm::Sha512,
                        other => {
                            return Err(ManagerError::InvalidInput(format!(
                                "Unsupported algorithm '{other}'"
                            )))
                        }
                    };
                }
                "digits" => {
                    digits = decoded_val
                        .parse::<u32>()
                        .map_err(|_| format!("Invalid digits value: '{decoded_val}'"))?;
                    if digits != 6 && digits != 8 {
                        return Err(ManagerError::InvalidInput(format!(
                            "Unsupported digits '{digits}' (expected 6 or 8)"
                        )));
                    }
                }
                "period" => {
                    period = decoded_val
                        .parse::<u32>()
                        .map_err(|_| format!("Invalid period value: '{decoded_val}'"))?;
                    if period == 0 {
                        return Err(ManagerError::InvalidInput(
                            "Period cannot be zero".to_string(),
                        ));
                    }
                }
                "counter" => {
                    counter = decoded_val
                        .parse::<u64>()
                        .map_err(|_| format!("Invalid counter value: '{decoded_val}'"))?;
                }
                _ => {} // Ignore unknown query parameters (e.g. image, lock)
            }
        }

        let secret =
            secret.ok_or_else(|| "Missing required 'secret' parameter in URI".to_string())?;
        let issuer = issuer_from_param.or(issuer_from_label);

        Ok(Self {
            oath_type,
            account,
            issuer,
            secret,
            algorithm,
            digits,
            period,
            counter,
        })
    }
}
