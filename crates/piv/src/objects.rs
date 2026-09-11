//! PIV data objects and key slots, from SP 800-73-5 Part 1.
//!
//! Only the objects the daemon actually reads or writes are named here. The
//! data model has thirty-six; adding the rest would be transcription without a
//! caller, and an untested constant is a liability rather than an asset.

use crate::tlv::{self, Tag, TlvError};
use thiserror::Error;

/// The PIV Card Application AID: the NIST RID, the application, the version.
///
/// SP 800-73-5 Part 1 §2.2.
pub const PIV_AID: [u8; 11] = [
    0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00,
];

/// The AID without its two-byte version.
///
/// A `SELECT` may use either; the card answers both with the full AID in its
/// application property template, so the truncated form is what to send when
/// the version is not known in advance.
pub const PIV_AID_TRUNCATED: [u8; 9] = [0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00];

/// Tag list, the data field of `GET DATA` and the first half of `PUT DATA`.
pub const TAG_TAG_LIST: Tag = Tag::new(0x5C);
/// The `PUT DATA` payload wrapper and the `GET DATA` response wrapper.
pub const TAG_DATA: Tag = Tag::new(0x53);
/// Application property template, returned by `SELECT`.
pub const TAG_APPLICATION_PROPERTY: Tag = Tag::new(0x61);
/// The AID inside an application property template.
pub const TAG_AID: Tag = Tag::new(0x4F);
/// Dynamic authentication template, the data field of `GENERAL AUTHENTICATE`.
pub const TAG_DYNAMIC_AUTH: Tag = Tag::new(0x7C);
/// Control reference template, the data field of `GENERATE ASYMMETRIC KEY PAIR`.
pub const TAG_CONTROL_REFERENCE: Tag = Tag::new(0xAC);
/// Cryptographic mechanism identifier, inside a control reference template.
pub const TAG_MECHANISM: Tag = Tag::new(0x80);
/// Public key template, returned by `GENERATE ASYMMETRIC KEY PAIR`.
pub const TAG_PUBLIC_KEY: Tag = Tag::new(0x7F49);
/// An uncompressed elliptic-curve point inside a public key template.
pub const TAG_EC_POINT: Tag = Tag::new(0x86);
/// An RSA modulus inside a public key template.
pub const TAG_RSA_MODULUS: Tag = Tag::new(0x81);
/// An RSA public exponent inside a public key template.
pub const TAG_RSA_EXPONENT: Tag = Tag::new(0x82);

/// Witness, inside a dynamic authentication template.
pub const TAG_WITNESS: Tag = Tag::new(0x80);
/// Challenge, inside a dynamic authentication template.
pub const TAG_CHALLENGE: Tag = Tag::new(0x81);
/// Response, inside a dynamic authentication template.
pub const TAG_RESPONSE: Tag = Tag::new(0x82);

/// The certificate itself, inside a certificate container.
pub const TAG_CERTIFICATE: Tag = Tag::new(0x70);
/// `CertInfo`, inside a certificate container.
pub const TAG_CERT_INFO: Tag = Tag::new(0x71);
/// Error detection code — an LRC, always empty in PIV.
pub const TAG_ERROR_DETECTION: Tag = Tag::new(0xFE);

/// Card Capability Container.
pub const TAG_CCC: Tag = Tag::new(0x5F_C107);
/// Card Holder Unique Identifier.
pub const TAG_CHUID: Tag = Tag::new(0x5F_C102);

/// The PIV Card Application PIN.
pub const KEY_REFERENCE_PIN: u8 = 0x80;
/// The PIN Unblocking Key.
pub const KEY_REFERENCE_PUK: u8 = 0x81;
/// The PIV Card Application Administrator key, used to authorise `PUT DATA`.
pub const KEY_REFERENCE_MANAGEMENT: u8 = 0x9B;

/// A PIV key slot.
///
/// Each slot pairs a key reference, used on the card command interface, with
/// the data object holding that key's certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Slot {
    /// `9A` — PIV Authentication. What macOS and Windows log in with.
    PivAuthentication,
    /// `9C` — Digital Signature. Always requires a PIN, every time.
    DigitalSignature,
    /// `9D` — Key Management. Wraps keychain and FileVault secrets on macOS.
    KeyManagement,
    /// `9E` — Card Authentication. The one slot with no PIN.
    CardAuthentication,
}

impl Slot {
    /// Every slot, in key-reference order.
    pub const ALL: [Slot; 4] = [
        Slot::PivAuthentication,
        Slot::DigitalSignature,
        Slot::KeyManagement,
        Slot::CardAuthentication,
    ];

    /// The key reference, as it goes in P2.
    pub const fn key_reference(self) -> u8 {
        match self {
            Slot::PivAuthentication => 0x9A,
            Slot::DigitalSignature => 0x9C,
            Slot::KeyManagement => 0x9D,
            Slot::CardAuthentication => 0x9E,
        }
    }

    /// The data object holding this slot's X.509 certificate.
    pub const fn certificate_tag(self) -> Tag {
        match self {
            Slot::PivAuthentication => Tag::new(0x5F_C105),
            Slot::DigitalSignature => Tag::new(0x5F_C10A),
            Slot::KeyManagement => Tag::new(0x5F_C10B),
            Slot::CardAuthentication => Tag::new(0x5F_C101),
        }
    }

    /// The slot for a key reference, if it is one of the four.
    pub const fn from_key_reference(reference: u8) -> Option<Slot> {
        match reference {
            0x9A => Some(Slot::PivAuthentication),
            0x9C => Some(Slot::DigitalSignature),
            0x9D => Some(Slot::KeyManagement),
            0x9E => Some(Slot::CardAuthentication),
            _ => None,
        }
    }
}

/// A certificate container could not be read.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ObjectError {
    /// The container's TLV structure did not parse.
    #[error("certificate container is malformed: {0}")]
    Tlv(#[from] TlvError),

    /// No `70` element, so there is no certificate in the container.
    #[error("certificate container has no certificate (tag 70)")]
    MissingCertificate,

    /// `CertInfo` was absent or not the single byte the spec defines.
    #[error("CertInfo (tag 71) must be exactly one byte, found {len}")]
    BadCertInfo {
        /// How long it was.
        len: usize,
    },

    /// `CertInfo` asked for a compression this crate will not perform.
    ///
    /// GZIP is legal in PIV. It is refused rather than implemented because a
    /// decompressor on the path from a card to a login decision is an attack
    /// surface bought for an encoding nothing in this system emits.
    #[error("CertInfo is 0x{0:02X}; only 0x00, uncompressed, is handled")]
    UnsupportedCertInfo(u8),
}

/// `CertInfo` for a certificate stored uncompressed.
///
/// SP 800-73-5 Part 1 §5: "for a certificate encoded in uncompressed form,
/// CertInfo SHALL be 0x00".
pub const CERT_INFO_UNCOMPRESSED: u8 = 0x00;
/// `CertInfo` for a GZIP-compressed certificate.
pub const CERT_INFO_GZIP: u8 = 0x01;

/// Builds the contents of a certificate data object.
///
/// The result is what goes inside the `53` wrapper of a `PUT DATA`:
///
/// ```text
/// 70 <len> <certificate, DER>
/// 71 01 00
/// FE 00
/// ```
///
/// The error detection code is an LRC that SP 800-73-5 defines with a
/// zero-length value — present because TIG SCEPACS makes it mandatory, and
/// carrying no data. Emitting the empty element is what every PIV card does,
/// and a reader that requires it would otherwise reject the object.
pub fn encode_certificate(certificate: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(certificate.len() + 12);
    tlv::encode(TAG_CERTIFICATE, certificate, &mut out);
    tlv::encode(TAG_CERT_INFO, &[CERT_INFO_UNCOMPRESSED], &mut out);
    tlv::encode(TAG_ERROR_DETECTION, &[], &mut out);
    out
}

/// Reads a certificate out of a certificate data object's contents.
pub fn decode_certificate(contents: &[u8]) -> Result<Vec<u8>, ObjectError> {
    let elements = tlv::parse_all(contents)?;

    let certificate =
        tlv::find(&elements, TAG_CERTIFICATE).ok_or(ObjectError::MissingCertificate)?;

    // Absent CertInfo is not treated as "probably uncompressed": the whole
    // point of the byte is to say how to read the bytes beside it.
    let info = tlv::find(&elements, TAG_CERT_INFO).unwrap_or(&[]);
    let [byte] = info else {
        return Err(ObjectError::BadCertInfo { len: info.len() });
    };
    if *byte != CERT_INFO_UNCOMPRESSED {
        return Err(ObjectError::UnsupportedCertInfo(*byte));
    }

    Ok(certificate.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_aid_is_the_rid_plus_application_plus_version() {
        // SP 800-73-5 Part 1 §2.2: NIST RID 'A0 00 00 03 08'.
        assert_eq!(&PIV_AID[..5], &[0xA0, 0x00, 0x00, 0x03, 0x08]);
        assert_eq!(&PIV_AID[..9], &PIV_AID_TRUNCATED[..]);
        assert_eq!(&PIV_AID[9..], &[0x01, 0x00]);
    }

    #[test]
    fn every_slot_maps_to_the_tag_the_spec_gives_it() {
        // SP 800-73-5 Part 1, Table 3. Transcribed from the specification, not
        // from the firmware.
        let expected = [
            (Slot::PivAuthentication, 0x9A, 0x5F_C105),
            (Slot::DigitalSignature, 0x9C, 0x5F_C10A),
            (Slot::KeyManagement, 0x9D, 0x5F_C10B),
            (Slot::CardAuthentication, 0x9E, 0x5F_C101),
        ];
        for (slot, reference, tag) in expected {
            assert_eq!(slot.key_reference(), reference);
            assert_eq!(slot.certificate_tag().value(), tag);
            assert_eq!(Slot::from_key_reference(reference), Some(slot));
        }
        assert_eq!(Slot::from_key_reference(0x9B), None);
    }

    #[test]
    fn slots_have_distinct_tags_and_references() {
        // A copy-paste in the table above would otherwise route one slot's
        // certificate into another slot's object.
        let mut tags: Vec<u32> = Slot::ALL
            .iter()
            .map(|s| s.certificate_tag().value())
            .collect();
        tags.sort_unstable();
        tags.dedup();
        assert_eq!(tags.len(), Slot::ALL.len());

        let mut refs: Vec<u8> = Slot::ALL.iter().map(|s| s.key_reference()).collect();
        refs.sort_unstable();
        refs.dedup();
        assert_eq!(refs.len(), Slot::ALL.len());
    }

    #[test]
    fn a_certificate_container_has_the_three_elements_in_order() {
        let container = encode_certificate(&[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(
            container,
            vec![
                0x70, 0x04, 0xDE, 0xAD, 0xBE, 0xEF, // certificate
                0x71, 0x01, 0x00, // CertInfo: uncompressed
                0xFE, 0x00, // error detection code, empty
            ]
        );
    }

    #[test]
    fn a_container_round_trips() {
        let certificate = vec![0x30u8; 900];
        let container = encode_certificate(&certificate);
        assert_eq!(decode_certificate(&container).unwrap(), certificate);
    }

    #[test]
    fn a_container_without_a_certificate_is_refused() {
        let mut container = Vec::new();
        tlv::encode(TAG_CERT_INFO, &[0x00], &mut container);
        tlv::encode(TAG_ERROR_DETECTION, &[], &mut container);
        assert_eq!(
            decode_certificate(&container).unwrap_err(),
            ObjectError::MissingCertificate
        );
    }

    #[test]
    fn a_missing_cert_info_is_not_assumed_to_mean_uncompressed() {
        // The byte exists to say how to read the bytes beside it, so its
        // absence is an unanswered question, not a default.
        let container = tlv::encode_to_vec(TAG_CERTIFICATE, &[0x01, 0x02]);
        assert_eq!(
            decode_certificate(&container).unwrap_err(),
            ObjectError::BadCertInfo { len: 0 }
        );
    }

    #[test]
    fn a_gzipped_certificate_is_refused_rather_than_decompressed() {
        // Legal PIV. Refused deliberately: a decompressor between a card and a
        // login decision is attack surface bought for an encoding we never emit.
        let mut container = Vec::new();
        tlv::encode(TAG_CERTIFICATE, &[0x1F, 0x8B], &mut container);
        tlv::encode(TAG_CERT_INFO, &[CERT_INFO_GZIP], &mut container);
        assert_eq!(
            decode_certificate(&container).unwrap_err(),
            ObjectError::UnsupportedCertInfo(CERT_INFO_GZIP)
        );
    }
}
