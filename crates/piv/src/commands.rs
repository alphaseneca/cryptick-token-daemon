//! The PIV card command set, built as APDUs.
//!
//! Every builder here is transcribed from SP 800-73-5 Part 2 §3, and the tests
//! quote the command syntax tables rather than a working capture, so a change
//! that breaks against a real card breaks against the specification first.

use crate::apdu::Command;
use crate::objects::{self, Slot};
use crate::tlv::{self, Tag};
use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes192;
use thiserror::Error;

/// `SELECT`.
pub const INS_SELECT: u8 = 0xA4;
/// `VERIFY`.
pub const INS_VERIFY: u8 = 0x20;
/// `CHANGE REFERENCE DATA`.
pub const INS_CHANGE_REFERENCE_DATA: u8 = 0x24;
/// `RESET RETRY COUNTER` — unblocks the PIN using the PUK, SP 800-73-5
/// Part 2 §3.2.3.
pub const INS_RESET_RETRY_COUNTER: u8 = 0x2C;
/// `GENERAL AUTHENTICATE`.
pub const INS_GENERAL_AUTHENTICATE: u8 = 0x87;
/// `GET DATA`.
pub const INS_GET_DATA: u8 = 0xCB;
/// `PUT DATA`.
pub const INS_PUT_DATA: u8 = 0xDB;
/// `GENERATE ASYMMETRIC KEY PAIR`.
pub const INS_GENERATE_KEY_PAIR: u8 = 0x47;
/// `SET PIN RETRIES` (vendor, not in SP 800-73 — the same byte YubiKey's
/// own PIV implementation uses for this operation; see this module's
/// top-level doc comment on why this applet follows that convention
/// instead of inventing a second one).
pub const INS_SET_PIN_RETRIES: u8 = 0xFA;
/// `RESET APPLICATION` (vendor, same real-world-convention reasoning as
/// `INS_SET_PIN_RETRIES`/`INS_SET_MANAGEMENT_KEY` above — YubiKey's own
/// byte for a full PIV factory reset). See [`reset_application`] for the
/// gate the card enforces before accepting it.
pub const INS_RESET_APPLICATION: u8 = 0xFB;
/// `SET MANAGEMENT KEY` (vendor, same reasoning as `INS_SET_PIN_RETRIES`).
pub const INS_SET_MANAGEMENT_KEY: u8 = 0xFF;
/// AES-192, this applet's one supported management-key algorithm
/// (SP 800-78-4 Table 6-2).
pub const ALG_MANAGEMENT_AES192: u8 = 0x0A;

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

/// A PUK did not meet the card's rules.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PukError {
    /// The PUK was not exactly 8 bytes.
    ///
    /// Unlike the PIN's 6-8 byte range, SP 800-73-5 Part 1 §2.4.3 gives the
    /// PUK exactly one length — there is no padding variability to get
    /// wrong, so a wrong-length PUK is rejected outright rather than padded.
    #[error("PUK is {len} bytes; SP 800-73-5 requires exactly 8")]
    BadLength {
        /// How long it was.
        len: usize,
    },

    /// The PUK held something other than ASCII digits.
    #[error("PUK must be ASCII digits '0'-'9'")]
    NotDigits,
}

/// Validates a PUK against SP 800-73-5's one length, no padding needed.
pub fn pad_puk(puk: &[u8]) -> Result<[u8; 8], PukError> {
    if puk.len() != 8 {
        return Err(PukError::BadLength { len: puk.len() });
    }
    if !puk.iter().all(|b| b.is_ascii_digit()) {
        return Err(PukError::NotDigits);
    }
    let mut out = [0u8; 8];
    out.copy_from_slice(puk);
    Ok(out)
}

/// `CHANGE REFERENCE DATA`, replacing the PUK — the same instruction as
/// [`change_pin`], distinguished only by key reference (SP 800-73-5 Part 2
/// §3.2.2).
pub fn change_puk(current: &[u8], new: &[u8]) -> Result<Command, PukError> {
    let mut data = Vec::with_capacity(16);
    data.extend_from_slice(&pad_puk(current)?);
    data.extend_from_slice(&pad_puk(new)?);
    Ok(Command::with_data(
        0x00,
        INS_CHANGE_REFERENCE_DATA,
        0x00,
        objects::KEY_REFERENCE_PUK,
        data,
    ))
}

/// `VERIFY` with no data field, for the PUK's own retry counter.
///
/// SP 800-73 has no "verify the PUK" operation — the PUK only ever
/// authenticates as half of [`change_puk`] or [`reset_pin`] — so this is
/// the query-only form the applet actually supports for it; sending a PUK
/// here to check it would spend a retry the card has no mechanism for.
pub fn verify_puk_retries() -> Command {
    Command::case1(0x00, INS_VERIFY, 0x00, objects::KEY_REFERENCE_PUK)
}

/// A [`reset_pin`] call's PUK or new PIN did not meet the card's rules.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ResetPinError {
    /// The PUK was malformed.
    #[error("PUK: {0}")]
    Puk(#[from] PukError),
    /// The new PIN was malformed.
    #[error("new PIN: {0}")]
    Pin(#[from] PinError),
}

/// `RESET RETRY COUNTER`: unblocks the PIN using the PUK, SP 800-73-5 Part 2
/// §3.2.3.
///
/// Does **not** verify the new PIN — the card only clears the block and
/// installs it; a caller that wants the session authenticated still has to
/// send [`verify_pin`] afterward. Encoding that any other way here would
/// make this function's return type lie about what actually happened on
/// the card.
pub fn reset_pin(puk: &[u8], new_pin: &[u8]) -> Result<Command, ResetPinError> {
    let mut data = Vec::with_capacity(16);
    data.extend_from_slice(&pad_puk(puk).map_err(ResetPinError::Puk)?);
    data.extend_from_slice(&pad_pin(new_pin).map_err(ResetPinError::Pin)?);
    Ok(Command::with_data(
        0x00,
        INS_RESET_RETRY_COUNTER,
        0x00,
        objects::KEY_REFERENCE_PIN,
        data,
    ))
}

/// `SET PIN RETRIES` (vendor): reconfigures both retry ceilings.
///
/// Resets the PIN and PUK to their SP 800-73 defaults as a documented side
/// effect — see `piv_hal_t::set_pin_puk_retries`' doc comment in the
/// firmware's `piv.h` for why, and warn the operator before sending this
/// the same way `ctctl piv reset` already does for a full reset.
pub fn set_pin_retries(pin_max: u8, puk_max: u8) -> Command {
    Command::case1(0x00, INS_SET_PIN_RETRIES, pin_max, puk_max)
}

/// `SET MANAGEMENT KEY` (vendor): installs a new 24-byte AES-192 management
/// key. Requires the *current* key to already be authenticated via
/// [`mgmt_request_witness`]/[`mgmt_respond`] in this same session.
pub fn set_management_key(new_key: &[u8; 24]) -> Command {
    let mut data = Vec::with_capacity(2 + new_key.len());
    data.push(ALG_MANAGEMENT_AES192);
    data.push(new_key.len() as u8);
    data.extend_from_slice(new_key);
    Command::with_data(0x00, INS_SET_MANAGEMENT_KEY, 0xFF, 0xFF, data)
}

/// `RESET APPLICATION` (vendor): a full factory reset. No data field, no
/// response data.
///
/// The card accepts this once the PIN has already been verified this
/// session ([`verify_pin`], sent first — the same bar
/// [`generate_key_pair`] already accepts for an operation that likewise
/// destroys certificates already issued) and rejects it otherwise. SP
/// 800-73 does not define this operation at all, so there is no spec
/// text for that gate, but an unauthenticated party who merely holds the
/// device still cannot wipe it and install their own keys and
/// certificates without proving something the device itself checks.
/// `ctctl piv reset` always sends [`verify_pin`] first, so the operator
/// gets a specific "wrong PIN" or "N attempts remaining" message rather
/// than a bare `SECURITY_STATUS_NOT_SATISFIED` (`6982`) from this command
/// itself.
///
/// Deliberately has no PIN-free lockout-recovery path (an earlier version
/// of this function also accepted both the PIN and PUK retry counters
/// already being at zero). That path was removed: reaching "both zero"
/// needs no knowledge of either secret, only physical possession and a
/// few deliberate wrong guesses, so it was reachable by anyone holding
/// the device, not only its legitimate owner. The accepted cost: an
/// owner who forgets the PIN *and* the PUK has no way back into this
/// device at all.
pub fn reset_application() -> Command {
    Command::case1(0x00, INS_RESET_APPLICATION, 0x00, 0x00)
}

/// The PIV card application administration ("management") key — AES-192,
/// the one symmetric algorithm this device's firmware supports for
/// `GENERAL AUTHENTICATE` against key reference `9B`.
///
/// This is the *host's* independent implementation of the same algorithm
/// the firmware's `piv_hal_esp32.cpp` (`mgmt_key_crypt_block`) runs against
/// its own copy of the key — the two never exchange the key itself, only
/// prove to each other that they each hold a copy via the witness/
/// challenge/response exchange `mgmt_request_witness`/`mgmt_respond` build.
#[derive(Clone)]
pub struct ManagementKey([u8; 24]);

impl ManagementKey {
    /// Wraps a 24-byte AES-192 key.
    pub const fn new(key: [u8; 24]) -> Self {
        ManagementKey(key)
    }

    /// The raw key bytes, for [`set_management_key`].
    pub const fn as_bytes(&self) -> &[u8; 24] {
        &self.0
    }

    fn cipher(&self) -> Aes192 {
        Aes192::new(GenericArray::from_slice(&self.0))
    }

    /// Decrypts one 16-byte block (ECB — every value this exchange ever
    /// encrypts is already exactly one block, so there is no chaining mode
    /// to pick).
    pub fn decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut buf = GenericArray::clone_from_slice(block);
        self.cipher().decrypt_block(&mut buf);
        buf.into()
    }

    /// Encrypts one 16-byte block.
    pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut buf = GenericArray::clone_from_slice(block);
        self.cipher().encrypt_block(&mut buf);
        buf.into()
    }
}

/// `GENERAL AUTHENTICATE`'s first half against the management key: an
/// empty witness request, SP 800-73-5 Part 2 §3.2.4 Table 7.
///
/// The card answers with its witness, encrypted under the management key —
/// read it back with [`parse_witness`], decrypt it with
/// [`ManagementKey::decrypt_block`], and pass the plaintext to
/// [`mgmt_respond`].
pub fn mgmt_request_witness() -> Command {
    let template = tlv::encode_to_vec(objects::TAG_WITNESS, &[]);
    Command::with_data(
        0x00,
        INS_GENERAL_AUTHENTICATE,
        ALG_MANAGEMENT_AES192,
        objects::KEY_REFERENCE_MANAGEMENT,
        tlv::encode_to_vec(objects::TAG_DYNAMIC_AUTH, &template),
    )
    .expecting(0x00)
}

/// `GENERAL AUTHENTICATE`'s second half: the witness decrypted (proving
/// this caller holds the key) plus a fresh challenge of the caller's own.
///
/// The card answers with the challenge encrypted under the management
/// key — decrypt it with [`ManagementKey::decrypt_block`] and compare
/// against `challenge`; only if that matches has the *card* also proven it
/// holds the key, completing mutual authentication rather than just one
/// direction of it.
pub fn mgmt_respond(witness_plain: &[u8; 16], challenge: &[u8; 16]) -> Command {
    let mut inner = Vec::with_capacity(36);
    tlv::encode(objects::TAG_WITNESS, witness_plain, &mut inner);
    tlv::encode(objects::TAG_CHALLENGE, challenge, &mut inner);
    Command::with_data(
        0x00,
        INS_GENERAL_AUTHENTICATE,
        ALG_MANAGEMENT_AES192,
        objects::KEY_REFERENCE_MANAGEMENT,
        tlv::encode_to_vec(objects::TAG_DYNAMIC_AUTH, &inner),
    )
    .expecting(0x00)
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

/// Finds one element inside a `GENERAL AUTHENTICATE` response's `7C`
/// dynamic authentication template. Shared by every `parse_*` function
/// below — they differ only in which tag they are looking for.
fn find_dynamic_auth_element(response: &[u8], tag: Tag) -> Result<Vec<u8>, tlv::TlvError> {
    let template = tlv::expect_one(response, objects::TAG_DYNAMIC_AUTH)?;
    let elements = tlv::parse_all(template)?;
    tlv::find(&elements, tag)
        .map(<[u8]>::to_vec)
        .ok_or(tlv::TlvError::UnexpectedTag {
            expected: tag.value(),
            found: elements.first().map_or(0, |e| e.tag.value()),
        })
}

/// Reads the signature out of a `GENERAL AUTHENTICATE` response.
pub fn parse_signature(response: &[u8]) -> Result<Vec<u8>, tlv::TlvError> {
    find_dynamic_auth_element(response, objects::TAG_RESPONSE)
}

/// Reads the management key's encrypted witness out of
/// [`mgmt_request_witness`]'s response.
pub fn parse_witness(response: &[u8]) -> Result<Vec<u8>, tlv::TlvError> {
    find_dynamic_auth_element(response, objects::TAG_WITNESS)
}

/// Reads the management key's encrypted challenge-response out of
/// [`mgmt_respond`]'s response.
pub fn parse_mgmt_response(response: &[u8]) -> Result<Vec<u8>, tlv::TlvError> {
    find_dynamic_auth_element(response, objects::TAG_RESPONSE)
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

    #[test]
    fn a_puk_is_exactly_eight_ascii_digits() {
        // Part 1 §2.4.3: unlike the PIN, there is no padding variability.
        assert_eq!(pad_puk(b"12345678").unwrap(), *b"12345678");
        assert_eq!(pad_puk(b"1234567"), Err(PukError::BadLength { len: 7 }));
        assert_eq!(pad_puk(b"123456789"), Err(PukError::BadLength { len: 9 }));
        assert_eq!(pad_puk(b"1234567a"), Err(PukError::NotDigits));
    }

    #[test]
    fn change_puk_matches_the_command_syntax_table() {
        // Same shape as change_pin, key reference 81 instead of 80.
        let command = change_puk(b"12345678", b"87654321")
            .unwrap()
            .encode()
            .unwrap();
        assert_eq!(
            command,
            vec![
                0x00, 0x24, 0x00, 0x81, 0x10, // header and Lc
                0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, // old PUK
                0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, // new PUK
            ]
        );
    }

    #[test]
    fn verify_puk_retries_asks_without_a_data_field() {
        assert_eq!(
            verify_puk_retries().encode().unwrap(),
            vec![0x00, 0x20, 0x00, 0x81]
        );
    }

    #[test]
    fn reset_pin_combines_the_puk_and_the_new_pin() {
        let command = reset_pin(b"12345678", b"654321").unwrap();
        assert_eq!(command.ins, INS_RESET_RETRY_COUNTER);
        assert_eq!((command.p1, command.p2), (0x00, objects::KEY_REFERENCE_PIN));
        assert_eq!(
            command.data,
            vec![
                0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, // PUK
                0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0xFF, 0xFF, // new PIN, padded
            ]
        );
    }

    #[test]
    fn reset_pin_rejects_a_malformed_puk_or_pin() {
        assert!(matches!(
            reset_pin(b"1234", b"123456"),
            Err(ResetPinError::Puk(PukError::BadLength { len: 4 }))
        ));
        assert!(matches!(
            reset_pin(b"12345678", b"12"),
            Err(ResetPinError::Pin(PinError::BadLength { len: 2 }))
        ));
    }

    #[test]
    fn set_pin_retries_carries_both_ceilings_with_no_data_field() {
        let command = set_pin_retries(5, 7);
        assert_eq!(command.encode().unwrap(), vec![0x00, 0xFA, 5, 7]);
    }

    #[test]
    fn set_management_key_wraps_the_algorithm_and_length() {
        let key = [0x11u8; 24];
        let command = set_management_key(&key);
        assert_eq!((command.ins, command.p1, command.p2), (0xFF, 0xFF, 0xFF));
        let mut expected = vec![ALG_MANAGEMENT_AES192, 24];
        expected.extend_from_slice(&key);
        assert_eq!(command.data, expected);
    }

    #[test]
    fn mgmt_request_witness_asks_for_an_empty_witness() {
        // §3.2.4 Table 7: 7C 02 80 00.
        let command = mgmt_request_witness();
        assert_eq!(
            (command.p1, command.p2),
            (ALG_MANAGEMENT_AES192, objects::KEY_REFERENCE_MANAGEMENT)
        );
        assert_eq!(command.data, vec![0x7C, 0x02, 0x80, 0x00]);
    }

    #[test]
    fn mgmt_respond_carries_the_witness_then_the_challenge() {
        let witness = [0xAAu8; 16];
        let challenge = [0xBBu8; 16];
        let command = mgmt_respond(&witness, &challenge);
        let mut expected_inner = vec![0x80, 16];
        expected_inner.extend_from_slice(&witness);
        expected_inner.push(0x81);
        expected_inner.push(16);
        expected_inner.extend_from_slice(&challenge);
        let mut expected = vec![0x7C, expected_inner.len() as u8];
        expected.extend_from_slice(&expected_inner);
        assert_eq!(command.data, expected);
    }

    #[test]
    fn parse_witness_and_parse_mgmt_response_read_their_own_tags() {
        let witness = vec![0x01, 0x02, 0x03];
        let inner = tlv::encode_to_vec(objects::TAG_WITNESS, &witness);
        let response = tlv::encode_to_vec(objects::TAG_DYNAMIC_AUTH, &inner);
        assert_eq!(parse_witness(&response).unwrap(), witness);
        assert!(parse_mgmt_response(&response).is_err(), "no 82 tag present");

        let answer = vec![0x04, 0x05, 0x06];
        let inner = tlv::encode_to_vec(objects::TAG_RESPONSE, &answer);
        let response = tlv::encode_to_vec(objects::TAG_DYNAMIC_AUTH, &inner);
        assert_eq!(parse_mgmt_response(&response).unwrap(), answer);
    }

    #[test]
    fn management_key_round_trips_through_its_own_cipher() {
        let key = ManagementKey::new([0x5Au8; 24]);
        let plaintext = [0x11u8; 16];
        let ciphertext = key.encrypt_block(&plaintext);
        assert_ne!(ciphertext, plaintext, "AES-192 must not be a no-op");
        assert_eq!(key.decrypt_block(&ciphertext), plaintext);
    }

    #[test]
    fn reset_application_is_a_bare_case_one_command() {
        // No data field, no Le — just CLA/INS/P1/P2, the same ISO case 1
        // shape set_pin_retries/mgmt_request_witness above already use for
        // a command with nothing to carry.
        let command = reset_application();
        assert_eq!(
            command.encode().unwrap(),
            vec![0x00, INS_RESET_APPLICATION, 0x00, 0x00]
        );
    }

    #[test]
    fn management_key_is_actually_aes_192_not_a_fixed_test_vector() {
        // Two different keys over the same plaintext must disagree — this
        // is the one property that rules out "always returns the input" or
        // "ignores the key" as an accidental implementation.
        let a = ManagementKey::new([0x01u8; 24]).encrypt_block(&[0x00u8; 16]);
        let b = ManagementKey::new([0x02u8; 24]).encrypt_block(&[0x00u8; 16]);
        assert_ne!(a, b);
    }
}
