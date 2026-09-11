//! The PIV card command set, built as APDUs.
//!
//! Every builder here is transcribed from SP 800-73-5 Part 2 §3, and the tests
//! quote the command syntax tables rather than a working capture, so a change
//! that breaks against a real card breaks against the specification first.

use crate::apdu::Command;
use crate::objects::{self, Slot};
use crate::tlv::{self, Tag};
use thiserror::Error;

/// `SELECT`.
pub const INS_SELECT: u8 = 0xA4;
/// `VERIFY`.
pub const INS_VERIFY: u8 = 0x20;
/// `CHANGE REFERENCE DATA`.
pub const INS_CHANGE_REFERENCE_DATA: u8 = 0x24;
/// `GENERAL AUTHENTICATE`.
pub const INS_GENERAL_AUTHENTICATE: u8 = 0x87;
/// `GET DATA`.
pub const INS_GET_DATA: u8 = 0xCB;
/// `PUT DATA`.
pub const INS_PUT_DATA: u8 = 0xDB;
/// `GENERATE ASYMMETRIC KEY PAIR`.
pub const INS_GENERATE_KEY_PAIR: u8 = 0x47;

/// A PIN or PUK did not meet the card's rules.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PinError {
    /// The PIN was outside the permitted length.
    #[error("PIN is {len} bytes; SP 800-73-5 requires 6 to 8")]
    BadLength {
        /// How long it was.
        len: usize,
    },

    /// The PIN held something other than ASCII digits.
    #[error("PIN must be ASCII digits '0'-'9'")]
    NotDigits,
}

/// Pads a PIN to the eight bytes the card command interface expects.
///
/// SP 800-73-5 Part 1 §2.4.3: the PIN is 6 to 8 bytes of ASCII digits, padded
/// to 8 with `FF` **appended**.
///
/// Validated here rather than at the card: a PIN the card will reject as
/// malformed still costs a retry on some implementations, and burning the
/// user's attempts on our own encoding bug is not acceptable.
pub fn pad_pin(pin: &[u8]) -> Result<[u8; 8], PinError> {
    if !(6..=8).contains(&pin.len()) {
        return Err(PinError::BadLength { len: pin.len() });
    }
    if !pin.iter().all(|b| b.is_ascii_digit()) {
        return Err(PinError::NotDigits);
    }
    let mut padded = [0xFFu8; 8];
    padded[..pin.len()].copy_from_slice(pin);
    Ok(padded)
}

/// `SELECT` the PIV Card Application.
///
/// Sends the right-truncated AID: the card answers either form with its full
/// AID in the application property template, so asking without a version is
/// how you learn the version.
pub fn select() -> Command {
    Command::with_data(
        0x00,
        INS_SELECT,
        0x04,
        0x00,
        objects::PIV_AID_TRUNCATED.to_vec(),
    )
    .expecting(0x00)
}

/// `GET DATA` for one data object.
pub fn get_data(tag: Tag) -> Command {
    Command::with_data(
        0x00,
        INS_GET_DATA,
        0x3F,
        0xFF,
        tlv::encode_to_vec(objects::TAG_TAG_LIST, &tag.to_bytes()),
    )
    .expecting(0x00)
}

/// `PUT DATA` replacing one data object's contents.
///
/// `contents` goes inside the `53` wrapper. For a certificate slot, build it
/// with [`objects::encode_certificate`].
///
/// The result routinely exceeds the short form — a certificate is about a
/// kilobyte — so pass it through [`crate::chaining::chain`] before sending.
pub fn put_data(tag: Tag, contents: &[u8]) -> Command {
    let mut data = tlv::encode_to_vec(objects::TAG_TAG_LIST, &tag.to_bytes());
    tlv::encode(objects::TAG_DATA, contents, &mut data);
    Command::with_data(0x00, INS_PUT_DATA, 0x3F, 0xFF, data)
}

/// `VERIFY` the PIV Card Application PIN.
pub fn verify_pin(pin: &[u8]) -> Result<Command, PinError> {
    Ok(Command::with_data(
        0x00,
        INS_VERIFY,
        0x00,
        objects::KEY_REFERENCE_PIN,
        pad_pin(pin)?.to_vec(),
    ))
}

/// `VERIFY` with no data field, which asks how many attempts remain.
///
/// The card answers `63 Cx` with the count, or `90 00` if verification is not
/// currently needed. It does not consume an attempt.
pub fn verify_retries() -> Command {
    Command::case1(0x00, INS_VERIFY, 0x00, objects::KEY_REFERENCE_PIN)
}

/// `VERIFY` with P1 = `FF`, which clears the PIN's security status.
///
/// Worth sending at the end of a transaction: it puts the card back to
/// "PIN not verified" rather than leaving a window in which the next caller
/// inherits this one's authorisation.
pub fn clear_security_status() -> Command {
    Command::case1(0x00, INS_VERIFY, 0xFF, objects::KEY_REFERENCE_PIN)
}

/// `CHANGE REFERENCE DATA`, replacing the PIN.
pub fn change_pin(current: &[u8], new: &[u8]) -> Result<Command, PinError> {
    let mut data = Vec::with_capacity(16);
    data.extend_from_slice(&pad_pin(current)?);
    data.extend_from_slice(&pad_pin(new)?);
    Ok(Command::with_data(
        0x00,
        INS_CHANGE_REFERENCE_DATA,
        0x00,
        objects::KEY_REFERENCE_PIN,
        data,
    ))
}

/// `GENERAL AUTHENTICATE` asking a slot to sign `payload`.
///
/// `algorithm` is the cryptographic mechanism identifier from SP 800-78
/// Table 9, and goes in P1 — `0x11` for ECDSA on P-256, `0x07` for RSA-2048.
///
/// The template is `7C { 82 00, 81 <payload> }`: an empty Response asks the
/// card for one, and the Challenge carries what to operate on. The empty
/// element comes first because the card reads the template in order and the
/// request-for-a-response has to precede what it is a response to.
pub fn sign(slot: Slot, algorithm: u8, payload: &[u8]) -> Command {
    let mut template = Vec::with_capacity(payload.len() + 8);
    tlv::encode(objects::TAG_RESPONSE, &[], &mut template);
    tlv::encode(objects::TAG_CHALLENGE, payload, &mut template);

    Command::with_data(
        0x00,
        INS_GENERAL_AUTHENTICATE,
        algorithm,
        slot.key_reference(),
        tlv::encode_to_vec(objects::TAG_DYNAMIC_AUTH, &template),
    )
    .expecting(0x00)
}

/// `GENERATE ASYMMETRIC KEY PAIR` in a slot.
///
/// The private key never leaves the card; the public key comes back in a `7F49`
/// template. Read it with [`parse_public_key`].
pub fn generate_key_pair(slot: Slot, algorithm: u8) -> Command {
    let mechanism = tlv::encode_to_vec(objects::TAG_MECHANISM, &[algorithm]);
    Command::with_data(
        0x00,
        INS_GENERATE_KEY_PAIR,
        0x00,
        slot.key_reference(),
        tlv::encode_to_vec(objects::TAG_CONTROL_REFERENCE, &mechanism),
    )
    .expecting(0x00)
}

/// A public key as the card returned it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKey {
    /// An uncompressed elliptic-curve point, `04 || X || Y`.
    Ec {
        /// The point, including its leading `04`.
        point: Vec<u8>,
    },
    /// An RSA modulus and public exponent.
    Rsa {
        /// The modulus.
        modulus: Vec<u8>,
        /// The public exponent.
        exponent: Vec<u8>,
    },
}

/// A public key template did not parse.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PublicKeyError {
    /// The template's TLV structure was malformed.
    #[error("public key template is malformed: {0}")]
    Tlv(#[from] tlv::TlvError),

    /// The template held neither an EC point nor an RSA modulus.
    #[error("public key template holds neither an EC point (86) nor an RSA modulus (81)")]
    UnknownKeyType,

    /// An RSA template was missing its exponent.
    #[error("RSA public key template has a modulus but no exponent (82)")]
    MissingExponent,

    /// An EC point did not begin with the uncompressed marker.
    ///
    /// SP 800-73-5 Part 2, Table 13 defines tag `86` as `04 || X || Y`. Point
    /// compression is not part of that encoding, so a leading `02` or `03` is
    /// a different format and is refused rather than decompressed.
    #[error("EC point starts with 0x{0:02X}; SP 800-73-5 Table 13 requires 0x04")]
    NotUncompressed(u8),
}

/// Reads a `7F49` public key template.
pub fn parse_public_key(response: &[u8]) -> Result<PublicKey, PublicKeyError> {
    let template = tlv::expect_one(response, objects::TAG_PUBLIC_KEY)?;
    let elements = tlv::parse_all(template)?;

    if let Some(point) = tlv::find(&elements, objects::TAG_EC_POINT) {
        match point.first() {
            Some(0x04) => {
                return Ok(PublicKey::Ec {
                    point: point.to_vec(),
                })
            }
            Some(&other) => return Err(PublicKeyError::NotUncompressed(other)),
            None => return Err(PublicKeyError::NotUncompressed(0)),
        }
    }

    if let Some(modulus) = tlv::find(&elements, objects::TAG_RSA_MODULUS) {
        let exponent = tlv::find(&elements, objects::TAG_RSA_EXPONENT)
            .ok_or(PublicKeyError::MissingExponent)?;
        return Ok(PublicKey::Rsa {
            modulus: modulus.to_vec(),
            exponent: exponent.to_vec(),
        });
    }

    Err(PublicKeyError::UnknownKeyType)
}

/// Reads the signature out of a `GENERAL AUTHENTICATE` response.
pub fn parse_signature(response: &[u8]) -> Result<Vec<u8>, tlv::TlvError> {
    let template = tlv::expect_one(response, objects::TAG_DYNAMIC_AUTH)?;
    let elements = tlv::parse_all(template)?;
    tlv::find(&elements, objects::TAG_RESPONSE)
        .map(<[u8]>::to_vec)
        .ok_or(tlv::TlvError::UnexpectedTag {
            expected: objects::TAG_RESPONSE.value(),
            found: elements.first().map_or(0, |e| e.tag.value()),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_matches_the_command_syntax_table() {
        // SP 800-73-5 Part 2 §3.1.1: CLA '00', INS 'A4', P1 '04', P2 '00',
        // Le '00'.
        assert_eq!(
            select().encode().unwrap(),
            vec![
                0x00, 0xA4, 0x04, 0x00, 0x09, // header and Lc
                0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, // truncated AID
                0x00, // Le
            ]
        );
    }

    #[test]
    fn get_data_matches_the_command_syntax_table() {
        // §3.1.2: CLA '00', INS 'CB', P1 '3F', P2 'FF', Lc '05' for a
        // three-byte tag, data '5C 03 ...', Le '00'.
        let command = get_data(Slot::PivAuthentication.certificate_tag());
        assert_eq!(
            command.encode().unwrap(),
            vec![0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x05, 0x00]
        );
    }

    #[test]
    fn put_data_wraps_the_tag_list_and_the_contents() {
        // §3.3.1, Table 10: tag list '5C', then data '53'.
        let command = put_data(Tag::new(0x5F_C105), &[0xAA, 0xBB]);
        assert_eq!(command.cla, 0x00);
        assert_eq!(command.ins, 0xDB);
        assert_eq!((command.p1, command.p2), (0x3F, 0xFF));
        assert_eq!(
            command.data,
            vec![0x5C, 0x03, 0x5F, 0xC1, 0x05, 0x53, 0x02, 0xAA, 0xBB]
        );
        // Response data field is "Absent", so no Le.
        assert_eq!(command.le, None);
    }

    #[test]
    fn a_certificate_write_is_a_put_data_that_needs_chaining() {
        // The realistic case, and the one that would break if the short-form
        // ceiling were handled by truncation instead of chaining.
        let certificate = vec![0x30u8; 1000];
        let contents = objects::encode_certificate(&certificate);
        let command = put_data(Slot::PivAuthentication.certificate_tag(), &contents);
        assert!(command.encode().is_err(), "must not fit the short form");

        let links = crate::chaining::chain(&command, 255).unwrap();
        assert!(links.len() > 1);
        for link in &links {
            link.encode().unwrap();
        }

        // What the applet reassembles must be what we built.
        let rejoined: Vec<u8> = links.iter().flat_map(|l| l.data.clone()).collect();
        assert_eq!(rejoined, command.data);

        let stored = tlv::parse_all(&rejoined).unwrap();
        let inner = tlv::find(&stored, objects::TAG_DATA).unwrap();
        assert_eq!(objects::decode_certificate(inner).unwrap(), certificate);
    }

    #[test]
    fn a_pin_is_padded_to_eight_bytes_with_ff_appended() {
        // Part 1 §2.4.3. Appended, not prepended: the other order verifies
        // against the wrong reference data and burns a retry.
        assert_eq!(
            pad_pin(b"123456").unwrap(),
            [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xFF, 0xFF]
        );
        assert_eq!(
            pad_pin(b"12345678").unwrap(),
            [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]
        );
    }

    #[test]
    fn a_malformed_pin_is_caught_before_it_costs_a_retry() {
        assert_eq!(pad_pin(b"12345"), Err(PinError::BadLength { len: 5 }));
        assert_eq!(pad_pin(b"123456789"), Err(PinError::BadLength { len: 9 }));
        assert_eq!(pad_pin(b"12345a"), Err(PinError::NotDigits));
        // The padding byte is not a legal PIN character either.
        assert_eq!(
            pad_pin(&[0x31, 0x32, 0x33, 0x34, 0x35, 0xFF]),
            Err(PinError::NotDigits)
        );
    }

    #[test]
    fn verify_variants_differ_only_where_the_spec_says_they_do() {
        let check = verify_retries().encode().unwrap();
        assert_eq!(check, vec![0x00, 0x20, 0x00, 0x80]);

        // P1 'FF' with no data resets the security status (§3.2.1).
        let clear = clear_security_status().encode().unwrap();
        assert_eq!(clear, vec![0x00, 0x20, 0xFF, 0x80]);

        let verify = verify_pin(b"123456").unwrap().encode().unwrap();
        assert_eq!(&verify[..5], &[0x00, 0x20, 0x00, 0x80, 0x08]);
    }

    #[test]
    fn sign_builds_the_dynamic_authentication_template() {
        // §3.2.4, Table 7. The empty '82' is the request for a response and
        // precedes the '81' challenge it answers.
        let command = sign(Slot::PivAuthentication, 0x11, &[0xAA, 0xBB]);
        assert_eq!(command.ins, 0x87);
        assert_eq!(command.p1, 0x11);
        assert_eq!(command.p2, 0x9A);
        assert_eq!(
            command.data,
            vec![0x7C, 0x06, 0x82, 0x00, 0x81, 0x02, 0xAA, 0xBB]
        );
    }

    #[test]
    fn generate_builds_the_control_reference_template() {
        // §3.3.2, Table 11: 'AC' holding '80' with the mechanism identifier.
        let command = generate_key_pair(Slot::KeyManagement, 0x11);
        assert_eq!(command.ins, 0x47);
        assert_eq!((command.p1, command.p2), (0x00, 0x9D));
        assert_eq!(command.data, vec![0xAC, 0x03, 0x80, 0x01, 0x11]);
    }

    #[test]
    fn an_ec_public_key_parses() {
        // Table 13: '86' holding 04 || X || Y, 65 bytes for P-256.
        let mut point = vec![0x04];
        point.extend_from_slice(&[0x11; 64]);
        let template = tlv::encode_to_vec(objects::TAG_EC_POINT, &point);
        let response = tlv::encode_to_vec(objects::TAG_PUBLIC_KEY, &template);

        assert_eq!(
            parse_public_key(&response).unwrap(),
            PublicKey::Ec { point }
        );
    }

    #[test]
    fn a_compressed_ec_point_is_refused() {
        // Legal SEC1, not the encoding Table 13 defines. Accepting it would
        // mean handing a point to a verifier that expects 65 bytes.
        let mut point = vec![0x02];
        point.extend_from_slice(&[0x11; 32]);
        let template = tlv::encode_to_vec(objects::TAG_EC_POINT, &point);
        let response = tlv::encode_to_vec(objects::TAG_PUBLIC_KEY, &template);

        assert_eq!(
            parse_public_key(&response).unwrap_err(),
            PublicKeyError::NotUncompressed(0x02)
        );
    }

    #[test]
    fn an_rsa_public_key_needs_both_halves() {
        let mut template = Vec::new();
        tlv::encode(objects::TAG_RSA_MODULUS, &[0x00; 256], &mut template);
        let response = tlv::encode_to_vec(objects::TAG_PUBLIC_KEY, &template);
        assert_eq!(
            parse_public_key(&response).unwrap_err(),
            PublicKeyError::MissingExponent
        );

        tlv::encode(
            objects::TAG_RSA_EXPONENT,
            &[0x01, 0x00, 0x01],
            &mut template,
        );
        let response = tlv::encode_to_vec(objects::TAG_PUBLIC_KEY, &template);
        assert_eq!(
            parse_public_key(&response).unwrap(),
            PublicKey::Rsa {
                modulus: vec![0x00; 256],
                exponent: vec![0x01, 0x00, 0x01],
            }
        );
    }

    #[test]
    fn a_signature_comes_out_of_the_response_element() {
        let signature = vec![0x30, 0x44, 0x02, 0x20];
        let inner = tlv::encode_to_vec(objects::TAG_RESPONSE, &signature);
        let response = tlv::encode_to_vec(objects::TAG_DYNAMIC_AUTH, &inner);
        assert_eq!(parse_signature(&response).unwrap(), signature);
    }

    #[test]
    fn a_response_without_the_signature_element_is_refused() {
        // A card answering with only a challenge echoed back must not look
        // like a zero-length signature.
        let inner = tlv::encode_to_vec(objects::TAG_CHALLENGE, &[0x01]);
        let response = tlv::encode_to_vec(objects::TAG_DYNAMIC_AUTH, &inner);
        assert!(parse_signature(&response).is_err());
    }
}
