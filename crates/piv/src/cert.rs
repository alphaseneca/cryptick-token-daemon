//! Self-signed X.509 v3 certificate builder and parser for PIV slots.
//!
//! SP 800-73-5 Part 1 §5 specifies that certificate data objects (tags `5FC105`
//! for 9A, `5FC10B` for 9D, etc.) hold an X.509 v3 certificate wrapped in a
//! Tag `70` element.
//!
//! This module constructs standard DER-encoded X.509 v3 certificates conforming
//! strictly to RFC 5280 and RFC 5480:
//! - P-256 elliptic curve public key (`id-ecPublicKey` and `secp256r1`)
//! - Signature algorithm `ecdsa-with-SHA256` (`1.2.840.10045.4.3.2`)
//! - Subject DN with Common Name (`CN=...`)
//! - Serial number and UTCTime validity period
//! - Key Usage extension (marked critical):
//!   - Digital Signature (`0x80`) for Slot 9A (PIV Authentication)
//!   - Key Encipherment (`0x20`) and Key Agreement (`0x08`) for Slot 9D (Key Management)
//!
//! # Sources
//! - RFC 5280: Internet X.509 Public Key Infrastructure Certificate and CRL Profile
//! - RFC 5480: Elliptic Curve Cryptography Subject Public Key Information
//! - NIST SP 800-73-5 Part 1: PIV Data Model and Representation

use crate::objects::Slot;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// An error that occurred while building or parsing an X.509 certificate.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CertError {
    /// Public key had an invalid length (expected 65 bytes for uncompressed P-256).
    #[error("EC public key is {0} bytes; expected 65 bytes (0x04 || X || Y)")]
    InvalidPublicKeyLength(usize),

    /// Public key did not start with 0x04 (uncompressed EC point indicator).
    #[error("EC public key begins with 0x{0:02X}; expected 0x04 (uncompressed)")]
    InvalidPublicKeyFormat(u8),

    /// Signature had an invalid format or length.
    #[error("ECDSA signature has an invalid format or length")]
    InvalidSignatureFormat,

    /// Date string was invalid (must be UTCTime YYMMDDHHMMSSZ, 13 bytes).
    #[error("invalid date string '{0}'; expected UTCTime format YYMMDDHHMMSSZ")]
    InvalidDateFormat(String),

    /// Common Name was empty or whitespace-only (RFC 5280 §4.1.2.4 DirectoryString SIZE 1..MAX).
    #[error("common name must not be empty")]
    InvalidCommonName,

    /// ASN.1 structure was malformed during parsing.
    #[error("malformed ASN.1 DER structure: {0}")]
    MalformedDer(String),

    /// An unexpected ASN.1 tag was found.
    #[error("expected ASN.1 tag 0x{expected:02X}, found 0x{found:02X} at offset {offset}")]
    UnexpectedTag {
        /// Expected tag.
        expected: u8,
        /// Actual tag.
        found: u8,
        /// Offset where it occurred.
        offset: usize,
    },
}

/// ASN.1 DER tags.
const TAG_BOOLEAN: u8 = 0x01;
const TAG_INTEGER: u8 = 0x02;
const TAG_BIT_STRING: u8 = 0x03;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_OID: u8 = 0x06;
const TAG_UTF8_STRING: u8 = 0x0C;
const TAG_PRINTABLE_STRING: u8 = 0x13;
const TAG_UTC_TIME: u8 = 0x17;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_SET: u8 = 0x31;


/// OID 1.2.840.10045.2.1: id-ecPublicKey (RFC 5480 §2.1.1).
const OID_ID_EC_PUBLIC_KEY: [u8; 7] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];

/// OID 1.2.840.10045.3.1.7: secp256r1 / prime256v1 (RFC 5480 §2.1.1.1).
const OID_SECP256R1: [u8; 8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

/// OID 1.2.840.10045.4.3.2: ecdsa-with-SHA256 (RFC 5480 §2.2.3).
const OID_ECDSA_WITH_SHA256: [u8; 8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];

/// OID 2.5.4.3: id-at-commonName (RFC 5280 §4.1.2.4).
const OID_COMMON_NAME: [u8; 3] = [0x55, 0x04, 0x03];

/// OID 2.5.29.15: id-ce-keyUsage (RFC 5280 §4.2.1.2).
const OID_KEY_USAGE: [u8; 3] = [0x55, 0x1D, 0x0F];

/// X.509 Key Usage extension flags (RFC 5280 §4.2.1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyUsage(u16);

impl KeyUsage {
    /// Digital signature (bit 0, MSB of byte 0).
    pub const DIGITAL_SIGNATURE: Self = Self(1 << 0);
    /// Non-repudiation / content commitment (bit 1).
    pub const NON_REPUDIATION: Self = Self(1 << 1);
    /// Key encipherment (bit 2).
    pub const KEY_ENCIPHERMENT: Self = Self(1 << 2);
    /// Data encipherment (bit 3).
    pub const DATA_ENCIPHERMENT: Self = Self(1 << 3);
    /// Key agreement (bit 4).
    pub const KEY_AGREEMENT: Self = Self(1 << 4);
    /// Key certificate signing (bit 5).
    pub const KEY_CERT_SIGN: Self = Self(1 << 5);
    /// CRL signing (bit 6).
    pub const CRL_SIGN: Self = Self(1 << 6);
    /// Encipher only (bit 7).
    pub const ENCIPHER_ONLY: Self = Self(1 << 7);
    /// Decipher only (bit 8).
    pub const DECIPHER_ONLY: Self = Self(1 << 8);

    /// Creates an empty KeyUsage mask.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Combines two KeyUsage masks.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Checks if a flag is set.
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Default KeyUsage for a PIV slot.
    ///
    /// - 9A (PIV Authentication): Digital Signature
    /// - 9D (Key Management): Key Encipherment | Key Agreement
    /// - 9C (Digital Signature): Digital Signature | Non-Repudiation
    /// - 9E (Card Authentication): Digital Signature
    pub const fn for_slot(slot: Slot) -> Self {
        match slot {
            Slot::PivAuthentication => Self::DIGITAL_SIGNATURE,
            Slot::DigitalSignature => Self(Self::DIGITAL_SIGNATURE.0 | Self::NON_REPUDIATION.0),
            Slot::KeyManagement => Self(Self::KEY_ENCIPHERMENT.0 | Self::KEY_AGREEMENT.0),
            Slot::CardAuthentication => Self::DIGITAL_SIGNATURE,
        }
    }

    /// Returns the raw u16 bitmask.
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Encodes to DER BIT STRING content: `(unused_bits, bytes)`.
    pub fn to_der_bits(self) -> (u8, Vec<u8>) {
        if self.0 == 0 {
            return (0, vec![]);
        }
        let mut byte0 = 0u8;
        if self.contains(Self::DIGITAL_SIGNATURE) {
            byte0 |= 0x80;
        }
        if self.contains(Self::NON_REPUDIATION) {
            byte0 |= 0x40;
        }
        if self.contains(Self::KEY_ENCIPHERMENT) {
            byte0 |= 0x20;
        }
        if self.contains(Self::DATA_ENCIPHERMENT) {
            byte0 |= 0x10;
        }
        if self.contains(Self::KEY_AGREEMENT) {
            byte0 |= 0x08;
        }
        if self.contains(Self::KEY_CERT_SIGN) {
            byte0 |= 0x04;
        }
        if self.contains(Self::CRL_SIGN) {
            byte0 |= 0x02;
        }
        if self.contains(Self::ENCIPHER_ONLY) {
            byte0 |= 0x01;
        }

        let mut byte1 = 0u8;
        if self.contains(Self::DECIPHER_ONLY) {
            byte1 |= 0x80;
        }

        if byte1 != 0 {
            let unused = byte1.trailing_zeros() as u8;
            (unused, vec![byte0, byte1])
        } else {
            let unused = byte0.trailing_zeros() as u8;
            (unused, vec![byte0])
        }
    }

    /// Parses from DER BIT STRING content: `unused_bits` and raw bytes.
    pub fn from_der_bits(unused_bits: u8, bytes: &[u8]) -> Self {
        let mut mask = 0u16;
        if let Some(&b0) = bytes.first() {
            let valid_bits = if bytes.len() == 1 { 8 - (unused_bits.min(7) as usize) } else { 8 };
            if valid_bits > 0 && (b0 & 0x80) != 0 { mask |= Self::DIGITAL_SIGNATURE.0; }
            if valid_bits > 1 && (b0 & 0x40) != 0 { mask |= Self::NON_REPUDIATION.0; }
            if valid_bits > 2 && (b0 & 0x20) != 0 { mask |= Self::KEY_ENCIPHERMENT.0; }
            if valid_bits > 3 && (b0 & 0x10) != 0 { mask |= Self::DATA_ENCIPHERMENT.0; }
            if valid_bits > 4 && (b0 & 0x08) != 0 { mask |= Self::KEY_AGREEMENT.0; }
            if valid_bits > 5 && (b0 & 0x04) != 0 { mask |= Self::KEY_CERT_SIGN.0; }
            if valid_bits > 6 && (b0 & 0x02) != 0 { mask |= Self::CRL_SIGN.0; }
            if valid_bits > 7 && (b0 & 0x01) != 0 { mask |= Self::ENCIPHER_ONLY.0; }
        }
        if let Some(&b1) = bytes.get(1) {
            let valid_bits = 8 - (unused_bits.min(7) as usize);
            if valid_bits > 0 && (b1 & 0x80) != 0 { mask |= Self::DECIPHER_ONLY.0; }
        }
        Self(mask)
    }
}

impl std::ops::BitOr for KeyUsage {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        self.union(rhs)
    }
}

/// Appends DER length octets according to ITU-T X.690 §8.1.3 / §10.1.
fn encode_der_length(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xFF {
        out.push(0x81);
        out.push(len as u8);
    } else if len <= 0xFFFF {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    } else {
        out.push(0x83);
        out.push((len >> 16) as u8);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    }
}

/// Encodes one TLV element into a byte buffer.
fn encode_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + value.len());
    out.push(tag);
    encode_der_length(value.len(), &mut out);
    out.extend_from_slice(value);
    out
}

/// Encodes an ASN.1 SEQUENCE (`0x30`).
fn encode_sequence(elements: &[&[u8]]) -> Vec<u8> {
    let total_len: usize = elements.iter().map(|e| e.len()).sum();
    let mut out = Vec::with_capacity(1 + 4 + total_len);
    out.push(TAG_SEQUENCE);
    encode_der_length(total_len, &mut out);
    for e in elements {
        out.extend_from_slice(e);
    }
    out
}

/// Encodes big-endian integer bytes as an ASN.1 INTEGER (`0x02`), trimming redundant
/// leading zeros and prepending `0x00` if the MSB is set to keep it positive.
fn encode_integer_bytes(bytes: &[u8]) -> Vec<u8> {
    let first_non_zero = bytes
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(bytes.len().saturating_sub(1));
    let trimmed = &bytes[first_non_zero..];
    let mut val = Vec::with_capacity(trimmed.len() + 1);
    if trimmed.is_empty() {
        val.push(0x00);
    } else {
        if trimmed[0] & 0x80 != 0 {
            val.push(0x00);
        }
        val.extend_from_slice(trimmed);
    }
    encode_tlv(TAG_INTEGER, &val)
}

/// Encodes a `u64` as an ASN.1 INTEGER (`0x02`).
fn encode_integer_u64(val: u64) -> Vec<u8> {
    encode_integer_bytes(&val.to_be_bytes())
}

/// Encodes an ASN.1 BIT STRING (`0x03`).
fn encode_bit_string(unused_bits: u8, bytes: &[u8]) -> Vec<u8> {
    let mut val = Vec::with_capacity(1 + bytes.len());
    val.push(unused_bits);
    val.extend_from_slice(bytes);
    encode_tlv(TAG_BIT_STRING, &val)
}

/// Encodes an ASN.1 OCTET STRING (`0x04`).
fn encode_octet_string(bytes: &[u8]) -> Vec<u8> {
    encode_tlv(TAG_OCTET_STRING, bytes)
}

/// Encodes an ASN.1 OBJECT IDENTIFIER (`0x06`).
fn encode_oid(oid: &[u8]) -> Vec<u8> {
    encode_tlv(TAG_OID, oid)
}

/// Encodes an ASN.1 UTF8String (`0x0C`).
fn encode_utf8_string(s: &str) -> Vec<u8> {
    encode_tlv(TAG_UTF8_STRING, s.as_bytes())
}

/// Encodes an ASN.1 UTCTime (`0x17`, `YYMMDDHHMMSSZ`).
fn encode_utc_time(s: &str) -> Vec<u8> {
    encode_tlv(TAG_UTC_TIME, s.as_bytes())
}

/// Validates that a string conforms to RFC 5280 UTCTime format (`YYMMDDHHMMSSZ`).
fn validate_utctime(date_str: &str) -> Result<(), CertError> {
    if date_str.len() != 13 || !date_str.ends_with('Z') {
        return Err(CertError::InvalidDateFormat(date_str.to_string()));
    }
    if !date_str[..12].chars().all(|c| c.is_ascii_digit()) {
        return Err(CertError::InvalidDateFormat(date_str.to_string()));
    }
    let mm: u32 = date_str[2..4].parse().unwrap_or(0);
    let dd: u32 = date_str[4..6].parse().unwrap_or(0);
    let hh: u32 = date_str[6..8].parse().unwrap_or(99);
    let min: u32 = date_str[8..10].parse().unwrap_or(99);
    let ss: u32 = date_str[10..12].parse().unwrap_or(99);

    if !(1..=12).contains(&mm) || !(1..=31).contains(&dd) || hh > 23 || min > 59 || ss > 59 {
        return Err(CertError::InvalidDateFormat(date_str.to_string()));
    }
    Ok(())
}

/// Encodes an ASN.1 BOOLEAN (`0x01`).
fn encode_boolean(val: bool) -> Vec<u8> {
    encode_tlv(TAG_BOOLEAN, &[if val { 0xFF } else { 0x00 }])
}

/// Encodes a context-specific explicit tag: `[tag_num] EXPLICIT ...`
fn encode_explicit_tag(tag_num: u8, content: &[u8]) -> Vec<u8> {
    let tag = 0xA0 | (tag_num & 0x1F);
    encode_tlv(tag, content)
}

/// Encodes an X.500 Name containing a single Common Name RDN:
/// `SEQUENCE { SET { SEQUENCE { OID(2.5.4.3), UTF8String(cn) } } }`
fn encode_rdn_name(common_name: &str) -> Vec<u8> {
    let oid_cn = encode_oid(&OID_COMMON_NAME);
    let cn_val = encode_utf8_string(common_name);
    let attr_seq = encode_sequence(&[&oid_cn, &cn_val]);
    let set = encode_tlv(TAG_SET, &attr_seq);
    encode_sequence(&[&set])
}

/// Encodes the AlgorithmIdentifier for `ecdsa-with-SHA256`:
/// `SEQUENCE { OBJECT IDENTIFIER 1.2.840.10045.4.3.2 }` (RFC 5480 §2.2.3: parameters absent).
fn encode_sig_alg() -> Vec<u8> {
    let oid = encode_oid(&OID_ECDSA_WITH_SHA256);
    encode_sequence(&[&oid])
}

/// Encodes SubjectPublicKeyInfo for EC P-256 (RFC 5480 §2.1):
/// `SEQUENCE { SEQUENCE { id-ecPublicKey, secp256r1 }, BIT STRING(0x04 || X || Y) }`
fn encode_subject_public_key_info(public_key: &[u8]) -> Result<Vec<u8>, CertError> {
    if public_key.len() != 65 {
        return Err(CertError::InvalidPublicKeyLength(public_key.len()));
    }
    if public_key[0] != 0x04 {
        return Err(CertError::InvalidPublicKeyFormat(public_key[0]));
    }
    let id_ec_pk = encode_oid(&OID_ID_EC_PUBLIC_KEY);
    let secp = encode_oid(&OID_SECP256R1);
    let alg_id = encode_sequence(&[&id_ec_pk, &secp]);
    let key_bits = encode_bit_string(0x00, public_key);
    Ok(encode_sequence(&[&alg_id, &key_bits]))
}

/// Encodes Key Usage extension (RFC 5280 §4.2.1.2):
/// `SEQUENCE { extnID (2.5.29.15), critical (TRUE), extnValue OCTET STRING(BIT STRING) }`
fn encode_key_usage_extension(key_usage: KeyUsage) -> Vec<u8> {
    let oid = encode_oid(&OID_KEY_USAGE);
    let critical = encode_boolean(true);
    let (unused_bits, bits) = key_usage.to_der_bits();
    let bit_string = encode_bit_string(unused_bits, &bits);
    let extn_value = encode_octet_string(&bit_string);
    encode_sequence(&[&oid, &critical, &extn_value])
}

/// Encodes raw `r` and `s` big-endian scalar bytes into a DER ECDSA signature
/// (`SEQUENCE { r INTEGER, s INTEGER }`).
pub fn encode_ecdsa_signature(r: &[u8], s: &[u8]) -> Vec<u8> {
    let r_int = encode_integer_bytes(r);
    let s_int = encode_integer_bytes(s);
    encode_sequence(&[&r_int, &s_int])
}

/// Builder for self-signed X.509 v3 certificates conforming to SP 800-73-5 and RFC 5280.
#[derive(Debug, Clone)]
pub struct CertificateBuilder {
    slot: Slot,
    common_name: String,
    serial_number: Vec<u8>,
    not_before: String,
    not_after: String,
    key_usage: KeyUsage,
    public_key: Vec<u8>,
}

/// Type alias for [`CertificateBuilder`].
pub type SelfSignedCertBuilder = CertificateBuilder;

impl CertificateBuilder {
    /// Creates a new certificate builder for a slot with its public key.
    ///
    /// The public key must be an uncompressed EC P-256 point (`0x04 || X || Y`, 65 bytes).
    pub fn new(slot: Slot, public_key: &[u8]) -> Result<Self, CertError> {
        if public_key.len() != 65 {
            return Err(CertError::InvalidPublicKeyLength(public_key.len()));
        }
        if public_key[0] != 0x04 {
            return Err(CertError::InvalidPublicKeyFormat(public_key[0]));
        }

        let common_name = match slot {
            Slot::PivAuthentication => "Cryptick PIV Authentication",
            Slot::KeyManagement => "Cryptick PIV Key Management",
            Slot::DigitalSignature => "Cryptick PIV Digital Signature",
            Slot::CardAuthentication => "Cryptick PIV Card Authentication",
        }
        .to_string();

        Ok(Self {
            slot,
            common_name,
            serial_number: vec![0x01],
            not_before: "260101000000Z".to_string(), // 2026-01-01 00:00:00Z
            not_after: "270101000000Z".to_string(),  // 2027-01-01 00:00:00Z (1 year)
            key_usage: KeyUsage::for_slot(slot),
            public_key: public_key.to_vec(),
        })
    }

    /// Sets the Subject and Issuer Common Name (`CN=...`).
    ///
    /// Per RFC 5280 §4.1.2.4 and X.520, DirectoryString requires SIZE (1..MAX).
    /// Returns [`CertError::InvalidCommonName`] if the trimmed name is empty.
    pub fn with_common_name(mut self, name: impl Into<String>) -> Result<Self, CertError> {
        let name = name.into();
        if name.trim().is_empty() {
            return Err(CertError::InvalidCommonName);
        }
        self.common_name = name;
        Ok(self)
    }

    /// Sets the serial number from an integer.
    pub fn with_serial_number(mut self, serial: u64) -> Self {
        self.serial_number = serial.to_be_bytes().to_vec();
        self
    }

    /// Sets the serial number from raw big-endian bytes.
    pub fn with_serial_bytes(mut self, bytes: &[u8]) -> Self {
        self.serial_number = bytes.to_vec();
        self
    }

    /// Sets the validity dates using UTCTime format (`YYMMDDHHMMSSZ`).
    pub fn with_validity(mut self, not_before: &str, not_after: &str) -> Result<Self, CertError> {
        validate_utctime(not_before)?;
        validate_utctime(not_after)?;
        self.not_before = not_before.to_string();
        self.not_after = not_after.to_string();
        Ok(self)
    }

    /// Overrides the Key Usage extension flags.
    pub fn with_key_usage(mut self, key_usage: KeyUsage) -> Self {
        self.key_usage = key_usage;
        self
    }

    /// Returns the slot being provisioned.
    pub fn slot(&self) -> Slot {
        self.slot
    }

    /// Returns the public key bytes.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Builds the DER-encoded `TBSCertificate` bytes.
    pub fn tbs_certificate_der(&self) -> Result<Vec<u8>, CertError> {
        if self.common_name.trim().is_empty() {
            return Err(CertError::InvalidCommonName);
        }

        let version_int = encode_integer_u64(2); // v3 is integer 2
        let explicit_version = encode_explicit_tag(0, &version_int);
        let serial = encode_integer_bytes(&self.serial_number);
        let sig_alg = encode_sig_alg();
        let name = encode_rdn_name(&self.common_name);
        let issuer = &name;
        let subject = &name;

        let not_before = encode_utc_time(&self.not_before);
        let not_after = encode_utc_time(&self.not_after);
        let validity = encode_sequence(&[&not_before, &not_after]);

        let spki = encode_subject_public_key_info(&self.public_key)?;

        let ext_key_usage = encode_key_usage_extension(self.key_usage);
        let extensions_seq = encode_sequence(&[&ext_key_usage]);
        let explicit_extensions = encode_explicit_tag(3, &extensions_seq);

        Ok(encode_sequence(&[
            &explicit_version,
            &serial,
            &sig_alg,
            issuer,
            &validity,
            subject,
            &spki,
            &explicit_extensions,
        ]))
    }

    /// Computes the SHA-256 digest of the `TBSCertificate` (the payload to be signed).
    pub fn tbs_digest(&self) -> Result<[u8; 32], CertError> {
        let tbs = self.tbs_certificate_der()?;
        let hash = Sha256::digest(&tbs);
        let mut out = [0u8; 32];
        out.copy_from_slice(&hash);
        Ok(out)
    }

    /// Builds the complete X.509 v3 certificate with a provided signature.
    ///
    /// `signature` may be either:
    /// - A DER-encoded `SEQUENCE { r INTEGER, s INTEGER }` (e.g. as returned by
    ///   `commands::parse_signature`).
    /// - A 64-byte raw `r || s` big-endian scalar pair.
    pub fn build(&self, signature: &[u8]) -> Result<Vec<u8>, CertError> {
        let tbs = self.tbs_certificate_der()?;
        let sig_alg = encode_sig_alg();

        let sig_der = if signature.starts_with(&[TAG_SEQUENCE]) {
            signature.to_vec()
        } else if signature.len() == 64 {
            encode_ecdsa_signature(&signature[..32], &signature[32..])
        } else {
            return Err(CertError::InvalidSignatureFormat);
        };

        let sig_bits = encode_bit_string(0x00, &sig_der);
        Ok(encode_sequence(&[&tbs, &sig_alg, &sig_bits]))
    }

    /// Builds a self-signed certificate using a deterministic signature derived from the
    /// `TBSCertificate` digest.
    ///
    /// Ideal for offline testing, dry-run provisioning, or slots where signing is not supported.
    pub fn build_self_signed(&self) -> Result<Vec<u8>, CertError> {
        let digest = self.tbs_digest()?;
        let s = Sha256::digest(digest);
        let sig_der = encode_ecdsa_signature(&digest, &s);
        self.build(&sig_der)
    }
}

/// Generates a default self-signed X.509 v3 certificate for a given PIV slot.
pub fn generate_certificate(slot: Slot, public_key: &[u8]) -> Result<Vec<u8>, CertError> {
    CertificateBuilder::new(slot, public_key)?.build_self_signed()
}

/// An inspected X.509 certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCertificate {
    /// X.509 version (2 for v3).
    pub version: u8,
    /// Certificate serial number bytes.
    pub serial_number: Vec<u8>,
    /// Common Name in Subject and Issuer.
    pub common_name: String,
    /// UTCTime `notBefore`.
    pub not_before: String,
    /// UTCTime `notAfter`.
    pub not_after: String,
    /// Uncompressed EC public key (65 bytes).
    pub public_key: Vec<u8>,
    /// Parsed Key Usage flags.
    pub key_usage: KeyUsage,
    /// Raw DER ECDSA signature bytes.
    pub signature: Vec<u8>,
}

/// Helper struct for parsing DER bytes.
struct DerReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> DerReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn peek_tag(&self) -> Result<u8, CertError> {
        self.bytes
            .get(self.offset)
            .copied()
            .ok_or_else(|| CertError::MalformedDer("unexpected end of DER input".into()))
    }

    fn read_tag(&mut self, expected: u8) -> Result<(), CertError> {
        let offset = self.offset;
        let actual = self
            .bytes
            .get(self.offset)
            .copied()
            .ok_or_else(|| CertError::MalformedDer("unexpected end of DER input".into()))?;
        if actual != expected {
            return Err(CertError::UnexpectedTag {
                expected,
                found: actual,
                offset,
            });
        }
        self.offset += 1;
        Ok(())
    }

    fn read_length(&mut self) -> Result<usize, CertError> {
        let offset = self.offset;
        let first = self
            .bytes
            .get(self.offset)
            .copied()
            .ok_or_else(|| CertError::MalformedDer("unexpected end of DER input".into()))?;
        self.offset += 1;
        if first < 0x80 {
            Ok(usize::from(first))
        } else {
            let count = usize::from(first & 0x7F);
            if count == 0 || count > 3 {
                return Err(CertError::MalformedDer(format!(
                    "unsupported length byte count {count} at offset {offset}"
                )));
            }
            let mut len = 0usize;
            for _ in 0..count {
                let b = self.bytes.get(self.offset).copied().ok_or_else(|| {
                    CertError::MalformedDer("unexpected end in length field".into())
                })?;
                self.offset += 1;
                len = (len << 8) | usize::from(b);
            }
            Ok(len)
        }
    }

    fn read_tlv_content(&mut self, tag: u8) -> Result<&'a [u8], CertError> {
        self.read_tag(tag)?;
        let len = self.read_length()?;
        if self.offset + len > self.bytes.len() {
            return Err(CertError::MalformedDer("TLV length exceeds buffer".into()));
        }
        let slice = &self.bytes[self.offset..self.offset + len];
        self.offset += len;
        Ok(slice)
    }

    fn read_sequence(&mut self) -> Result<&'a [u8], CertError> {
        self.read_tlv_content(TAG_SEQUENCE)
    }
}

/// Parses and validates a DER-encoded X.509 v3 certificate.
pub fn parse_certificate(der: &[u8]) -> Result<ParsedCertificate, CertError> {
    let mut top = DerReader::new(der);
    let cert_body = top.read_sequence()?;
    if top.offset != der.len() {
        return Err(CertError::MalformedDer("trailing bytes after outer SEQUENCE".into()));
    }

    let mut cert_reader = DerReader::new(cert_body);
    let tbs_body = cert_reader.read_sequence()?;
    let _sig_alg = cert_reader.read_sequence()?;
    let sig_bit_string = cert_reader.read_tlv_content(TAG_BIT_STRING)?;

    if sig_bit_string.is_empty() {
        return Err(CertError::MalformedDer("empty signature BIT STRING".into()));
    }
    let signature = sig_bit_string[1..].to_vec();

    // Parse TBSCertificate
    let mut tbs = DerReader::new(tbs_body);

    // [0] EXPLICIT Version
    let version_body = tbs.read_tlv_content(0xA0)?;
    let mut v_reader = DerReader::new(version_body);
    let v_int = v_reader.read_tlv_content(TAG_INTEGER)?;
    let version = *v_int.last().unwrap_or(&0);

    // serialNumber INTEGER
    let serial_number = tbs.read_tlv_content(TAG_INTEGER)?.to_vec();

    // signature AlgorithmIdentifier
    let _tbs_sig_alg = tbs.read_sequence()?;

    // issuer Name
    let issuer_seq = tbs.read_sequence()?;
    let issuer_cn = parse_common_name(issuer_seq)?;

    // validity Validity
    let validity_seq = tbs.read_sequence()?;
    let mut val_reader = DerReader::new(validity_seq);
    let nb_tag = val_reader.peek_tag()?;
    let nb_bytes = val_reader.read_tlv_content(nb_tag)?;
    let na_tag = val_reader.peek_tag()?;
    let na_bytes = val_reader.read_tlv_content(na_tag)?;
    let not_before = String::from_utf8_lossy(nb_bytes).to_string();
    let not_after = String::from_utf8_lossy(na_bytes).to_string();

    // subject Name
    let subject_seq = tbs.read_sequence()?;
    let subject_cn = parse_common_name(subject_seq)?;

    // subjectPublicKeyInfo
    let spki_seq = tbs.read_sequence()?;
    let mut spki_reader = DerReader::new(spki_seq);
    let _spki_alg = spki_reader.read_sequence()?;
    let pk_bits = spki_reader.read_tlv_content(TAG_BIT_STRING)?;
    if pk_bits.is_empty() {
        return Err(CertError::MalformedDer("empty public key bit string".into()));
    }
    let public_key = pk_bits[1..].to_vec();

    // [3] EXPLICIT Extensions
    let ext_tag = tbs.peek_tag()?;
    let mut key_usage = KeyUsage::empty();
    if ext_tag == 0xA3 {
        let ext_body = tbs.read_tlv_content(0xA3)?;
        let mut ext_seq_reader = DerReader::new(ext_body);
        let exts = ext_seq_reader.read_sequence()?;
        let mut exts_reader = DerReader::new(exts);
        while exts_reader.offset < exts.len() {
            let single_ext = exts_reader.read_sequence()?;
            let mut s_reader = DerReader::new(single_ext);
            let ext_oid = s_reader.read_tlv_content(TAG_OID)?;
            let _is_critical = if s_reader.peek_tag()? == TAG_BOOLEAN {
                let bool_val = s_reader.read_tlv_content(TAG_BOOLEAN)?;
                bool_val.first().is_some_and(|&b| b != 0)
            } else {
                false
            };
            let ext_val = s_reader.read_tlv_content(TAG_OCTET_STRING)?;

            if ext_oid == OID_KEY_USAGE {
                let mut ku_reader = DerReader::new(ext_val);
                let ku_bits = ku_reader.read_tlv_content(TAG_BIT_STRING)?;
                if !ku_bits.is_empty() {
                    key_usage = KeyUsage::from_der_bits(ku_bits[0], &ku_bits[1..]);
                }
            }
        }
    }

    Ok(ParsedCertificate {
        version,
        serial_number,
        common_name: subject_cn.unwrap_or(issuer_cn.unwrap_or_default()),
        not_before,
        not_after,
        public_key,
        key_usage,
        signature,
    })
}

/// Helper to parse Common Name out of an X.500 Name sequence.
fn parse_common_name(name_seq: &[u8]) -> Result<Option<String>, CertError> {
    let mut reader = DerReader::new(name_seq);
    while reader.offset < name_seq.len() {
        let set_bytes = reader.read_tlv_content(TAG_SET)?;
        let mut set_reader = DerReader::new(set_bytes);
        while set_reader.offset < set_bytes.len() {
            let attr_bytes = set_reader.read_sequence()?;
            let mut attr_reader = DerReader::new(attr_bytes);
            let oid = attr_reader.read_tlv_content(TAG_OID)?;
            let str_tag = attr_reader.peek_tag()?;
            let val = attr_reader.read_tlv_content(str_tag)?;
            if oid == OID_COMMON_NAME && (str_tag == TAG_UTF8_STRING || str_tag == TAG_PRINTABLE_STRING) {
                return Ok(Some(String::from_utf8_lossy(val).to_string()));
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_p256_public_key() -> [u8; 65] {
        let mut key = [0xAAu8; 65];
        key[0] = 0x04;
        key
    }

    #[test]
    fn key_usage_der_bit_string_encoding() {
        // Digital signature (bit 0): byte 0x80, 7 unused bits
        let (unused, bytes) = KeyUsage::DIGITAL_SIGNATURE.to_der_bits();
        assert_eq!(unused, 7);
        assert_eq!(bytes, vec![0x80]);

        // Key encipherment (bit 2 = 0x20) and key agreement (bit 4 = 0x08)
        let ku = KeyUsage::KEY_ENCIPHERMENT | KeyUsage::KEY_AGREEMENT;
        let (unused, bytes) = ku.to_der_bits();
        assert_eq!(unused, 3);
        assert_eq!(bytes, vec![0x28]);

        // Roundtrip parsing
        assert_eq!(KeyUsage::from_der_bits(unused, &bytes), ku);
    }

    #[test]
    fn certificate_builder_builds_and_roundtrips_slot_9a() {
        let pk = dummy_p256_public_key();
        let builder = CertificateBuilder::new(Slot::PivAuthentication, &pk).unwrap();
        let cert_der = builder.build_self_signed().unwrap();

        assert_eq!(cert_der[0], TAG_SEQUENCE);
        let parsed = parse_certificate(&cert_der).unwrap();
        assert_eq!(parsed.version, 2); // v3
        assert_eq!(parsed.common_name, "Cryptick PIV Authentication");
        assert_eq!(parsed.public_key, pk);
        assert!(parsed.key_usage.contains(KeyUsage::DIGITAL_SIGNATURE));
        assert!(!parsed.key_usage.contains(KeyUsage::KEY_ENCIPHERMENT));
        assert_eq!(parsed.not_before, "260101000000Z");
        assert_eq!(parsed.not_after, "270101000000Z");
    }

    #[test]
    fn certificate_builder_builds_and_roundtrips_slot_9d() {
        let pk = dummy_p256_public_key();
        let builder = CertificateBuilder::new(Slot::KeyManagement, &pk).unwrap();
        let cert_der = builder.build_self_signed().unwrap();

        let parsed = parse_certificate(&cert_der).unwrap();
        assert_eq!(parsed.version, 2);
        assert_eq!(parsed.common_name, "Cryptick PIV Key Management");
        assert_eq!(parsed.public_key, pk);
        assert!(parsed.key_usage.contains(KeyUsage::KEY_ENCIPHERMENT));
        assert!(parsed.key_usage.contains(KeyUsage::KEY_AGREEMENT));
        assert!(!parsed.key_usage.contains(KeyUsage::DIGITAL_SIGNATURE));
    }

    #[test]
    fn invalid_public_key_is_rejected() {
        // Not 65 bytes
        let short_key = [0x04u8; 64];
        assert_eq!(
            CertificateBuilder::new(Slot::PivAuthentication, &short_key).unwrap_err(),
            CertError::InvalidPublicKeyLength(64)
        );

        // Not uncompressed (doesn't start with 0x04)
        let bad_format = [0x02u8; 65];
        assert_eq!(

            CertificateBuilder::new(Slot::PivAuthentication, &bad_format).unwrap_err(),
            CertError::InvalidPublicKeyFormat(0x02)
        );
    }

    #[test]
    fn custom_common_name_and_validity() {
        let pk = dummy_p256_public_key();
        let builder = CertificateBuilder::new(Slot::PivAuthentication, &pk)
            .unwrap()
            .with_common_name("Custom Smart Card Auth")
            .unwrap()
            .with_serial_number(123456)
            .with_validity("250101000000Z", "300101000000Z")
            .unwrap();
        let cert_der = builder.build_self_signed().unwrap();

        let parsed = parse_certificate(&cert_der).unwrap();
        assert_eq!(parsed.common_name, "Custom Smart Card Auth");
        assert_eq!(parsed.not_before, "250101000000Z");
        assert_eq!(parsed.not_after, "300101000000Z");
    }

    #[test]
    fn reject_empty_common_name() {
        let pk = dummy_p256_public_key();
        let builder = CertificateBuilder::new(Slot::PivAuthentication, &pk).unwrap();

        assert_eq!(
            builder.clone().with_common_name("").unwrap_err(),
            CertError::InvalidCommonName
        );
        assert_eq!(
            builder.with_common_name("   \t\n").unwrap_err(),
            CertError::InvalidCommonName
        );
    }

    #[test]
    fn reject_invalid_validity_dates() {
        let pk = dummy_p256_public_key();
        let builder = CertificateBuilder::new(Slot::PivAuthentication, &pk).unwrap();

        // Non-digit characters
        assert!(builder.clone().with_validity("INVALIDDATE1Z", "270101000000Z").is_err());
        assert!(builder.clone().with_validity("260101000000Z", "INVALIDDATE1Z").is_err());
        assert!(builder.clone().with_validity("26010100000AZ", "270101000000Z").is_err());

        // Wrong length or missing Z
        assert!(builder.clone().with_validity("260101000000", "270101000000Z").is_err());
        assert!(builder.clone().with_validity("260101000000X", "270101000000Z").is_err());

        // Invalid calendar ranges
        assert!(builder.clone().with_validity("261301000000Z", "270101000000Z").is_err()); // month 13
        assert!(builder.clone().with_validity("260132000000Z", "270101000000Z").is_err()); // day 32
        assert!(builder.clone().with_validity("260101250000Z", "270101000000Z").is_err()); // hour 25
    }

    #[test]
    fn ecdsa_signature_encoding_and_build() {
        let r = [0x11u8; 32];
        let s = [0x22u8; 32];
        let sig = encode_ecdsa_signature(&r, &s);
        assert_eq!(sig[0], TAG_SEQUENCE);

        let pk = dummy_p256_public_key();
        let builder = CertificateBuilder::new(Slot::PivAuthentication, &pk).unwrap();
        let cert_der = builder.build(&sig).unwrap();
        let parsed = parse_certificate(&cert_der).unwrap();
        assert_eq!(parsed.signature, sig);
    }

    #[test]
    fn raw_signature_conversion() {
        let mut raw = [0x33u8; 64];
        raw[0] = 0x7F; // positive
        let pk = dummy_p256_public_key();
        let builder = CertificateBuilder::new(Slot::PivAuthentication, &pk).unwrap();
        let cert_der = builder.build(&raw).unwrap();
        let parsed = parse_certificate(&cert_der).unwrap();
        assert_eq!(parsed.signature[0], TAG_SEQUENCE);
    }
}
