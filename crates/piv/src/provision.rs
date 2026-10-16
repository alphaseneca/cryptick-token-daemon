//! PIV provisioning workflow and card transceive abstraction.
//!
//! Handles generating EC P-256 keys in PIV slots, constructing self-signed X.509
//! certificates, encoding them into SP 800-73-5 certificate containers (`0x53`),
//! and writing them to the card via chained `PUT DATA` APDUs.

use std::collections::HashMap;

use crate::apdu::{ApduError, StatusWord, CLA_CHAIN};
use crate::cert::{CertError, CertificateBuilder};
use crate::chaining::{self, ChainError};
use crate::commands::{
    self, parse_public_key, parse_signature, PinError, PublicKey, PublicKeyError,
};
use crate::objects::{self, ObjectError, Slot};
use crate::tlv::{self, TlvError};
use thiserror::Error;

/// An error encountered during PIV provisioning.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProvisionError {
    /// APDU encoding or decoding failure.
    #[error("APDU error: {0}")]
    Apdu(#[from] ApduError),

    /// TLV serialization or parsing failure.
    #[error("TLV error: {0}")]
    Tlv(#[from] TlvError),

    /// Command chaining failure.
    #[error("command chaining error: {0}")]
    Chain(#[from] ChainError),

    /// X.509 certificate generation failure.
    #[error("certificate error: {0}")]
    Cert(#[from] CertError),

    /// Public key parsing failure.
    #[error("public key error: {0}")]
    PublicKey(#[from] PublicKeyError),

    /// Object container error.
    #[error("object container error: {0}")]
    Object(#[from] ObjectError),

    /// Card returned an unsuccessful status word.
    #[error("card returned status word {0}")]
    CardStatus(StatusWord),

    /// Smart card transceive communication failure.
    #[error("card transceive failed: {0}")]
    Transceive(String),

    /// Invalid PIN or PIN verification failure.
    #[error("PIN error: {0}")]
    Pin(#[from] PinError),

    /// Expected EC public key but received RSA or unknown type.
    #[error("expected EC P-256 public key, received another key type")]
    UnexpectedKeyType,
}

/// A transport-agnostic smart card APDU transceiver.
pub trait CardTransceiver {
    /// Transceives one raw APDU command to the card and returns the raw response.
    fn transceive(&mut self, command: &[u8]) -> Result<Vec<u8>, ProvisionError>;
}

/// Options controlling the provisioning process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionOptions {
    /// Slots to provision.
    pub slots: Vec<Slot>,
    /// Whether to run in simulated dry-run mode without a physical card.
    pub dry_run: bool,
    /// Optional PIN for card verification.
    pub pin: Option<String>,
    /// Optional custom Common Name for the certificate.
    pub common_name: Option<String>,
    /// Whether to print all sent and received APDUs in hex.
    pub print_apdus: bool,
}

impl Default for ProvisionOptions {
    fn default() -> Self {
        Self {
            slots: vec![Slot::PivAuthentication, Slot::KeyManagement],
            dry_run: false,
            pin: Some("123456".to_string()),
            common_name: None,
            print_apdus: false,
        }
    }
}

/// Summary report of a single provisioned slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionReport {
    /// The provisioned slot.
    pub slot: Slot,
    /// Uncompressed EC public key (65 bytes: `0x04 || X || Y`).
    pub public_key: Vec<u8>,
    /// Raw DER-encoded X.509 v3 certificate.
    pub certificate_der: Vec<u8>,
    /// SP 800-73-5 container length in bytes.
    pub container_len: usize,
    /// Number of chained `PUT DATA` APDUs emitted.
    pub chained_apdus_count: usize,
}

/// Provisions a single PIV slot on a card:
/// 1. `SELECT` PIV Card Application (AID `A0 00 00 03 08 00 00 10 00`)
/// 2. `VERIFY` PIN (if provided)
/// 3. `GENERATE ASYMMETRIC KEY PAIR` in slot with algorithm P-256 (`0x11`)
/// 4. Parse returned EC public key
/// 5. Construct self-signed X.509 v3 certificate (with slot-specific KeyUsage)
/// 6. Sign certificate (via card `GENERAL AUTHENTICATE` or self-signature)
/// 7. Wrap certificate in SP 800-73-5 container (`0x53`)
/// 8. Write certificate using chained `PUT DATA` (`0xDB`, `Lc <= 255`)
pub fn provision_slot<T: CardTransceiver>(
    card: &mut T,
    slot: Slot,
    pin: Option<&[u8]>,
    common_name: Option<&str>,
) -> Result<ProvisionReport, ProvisionError> {
    // 1. SELECT PIV application
    let select_cmd = commands::select().encode()?;
    let select_resp = card.transceive(&select_cmd)?;
    let sw = check_response_status(&select_resp)?;
    if !sw.is_success() {
        return Err(ProvisionError::CardStatus(sw));
    }

    // 2. VERIFY PIN if supplied
    if let Some(pin_bytes) = pin {
        let verify_cmd = commands::verify_pin(pin_bytes)?.encode()?;
        let verify_resp = card.transceive(&verify_cmd)?;
        let sw = check_response_status(&verify_resp)?;
        if !sw.is_success() {
            return Err(ProvisionError::CardStatus(sw));
        }
    }

    // 3. GENERATE ASYMMETRIC KEY PAIR
    let gen_cmd = commands::generate_key_pair(slot, crate::algorithm::ECC_P256).encode()?;
    let gen_resp = card.transceive(&gen_cmd)?;
    let sw = check_response_status(&gen_resp)?;
    if !sw.is_success() {
        return Err(ProvisionError::CardStatus(sw));
    }

    // 4. Parse returned public key
    let pub_key_data = strip_status_bytes(&gen_resp);
    let public_key = match parse_public_key(pub_key_data)? {
        PublicKey::Ec { point } => point,
        PublicKey::Rsa { .. } => return Err(ProvisionError::UnexpectedKeyType),
    };

    // 5. Construct self-signed X.509 v3 certificate builder
    let mut builder = CertificateBuilder::new(slot, &public_key)?;
    if let Some(cn) = common_name {
        builder = builder.with_common_name(cn)?;
    }

    // 6. Sign certificate
    let tbs_hash = builder.tbs_digest()?;
    let cert_der = match try_card_sign(card, slot, &tbs_hash) {
        Ok(sig_der) => builder.build(&sig_der)?,
        Err(_) => builder.build_self_signed()?,
    };

    // 7. Encode into SP 800-73-5 certificate container (Tag 53)
    let container = objects::encode_certificate(&cert_der);
    let container_len = container.len();

    // 8. Chained PUT DATA APDUs
    let put_cmd = commands::put_data(slot.certificate_tag(), &container);
    let apdus = chaining::chain(&put_cmd, 255)?;
    let chained_count = apdus.len();

    for link in &apdus {
        let apdu_bytes = link.encode()?;
        let resp = card.transceive(&apdu_bytes)?;
        let sw = check_response_status(&resp)?;
        if !sw.is_success() {
            return Err(ProvisionError::CardStatus(sw));
        }
    }

    Ok(ProvisionReport {
        slot,
        public_key,
        certificate_der: cert_der,
        container_len,
        chained_apdus_count: chained_count,
    })
}

/// Tries signing a digest on the card using GENERAL AUTHENTICATE.
fn try_card_sign<T: CardTransceiver>(
    card: &mut T,
    slot: Slot,
    digest: &[u8; 32],
) -> Result<Vec<u8>, ProvisionError> {
    let sign_cmd = commands::sign(slot, crate::algorithm::ECC_P256, digest).encode()?;
    let sign_resp = card.transceive(&sign_cmd)?;
    let sw = check_response_status(&sign_resp)?;
    if !sw.is_success() {
        return Err(ProvisionError::CardStatus(sw));
    }
    let data = strip_status_bytes(&sign_resp);
    Ok(parse_signature(data)?)
}

/// Strips the trailing 2-byte status word from an APDU response.
fn strip_status_bytes(resp: &[u8]) -> &[u8] {
    if resp.len() >= 2 {
        &resp[..resp.len() - 2]
    } else {
        resp
    }
}

/// Checks the trailing status word of an APDU response.
fn check_response_status(resp: &[u8]) -> Result<StatusWord, ProvisionError> {
    if resp.len() < 2 {
        return Err(ProvisionError::Apdu(ApduError::ResponseTooShort {
            len: resp.len(),
        }));
    }
    let sw1 = resp[resp.len() - 2];
    let sw2 = resp[resp.len() - 1];
    Ok(StatusWord::from_bytes(sw1, sw2))
}

/// An in-memory simulated smart card for testing and dry-run provisioning.
#[derive(Debug, Clone)]
pub struct SimulatedCard {
    /// Stored public keys keyed by slot key reference (`0x9A`, `0x9D`, etc.).
    pub keys: HashMap<u8, Vec<u8>>,
    /// Stored PIV data objects keyed by 3-byte tag value (`0x5FC105`, etc.).
    pub objects: HashMap<u32, Vec<u8>>,
    /// Chained PUT DATA reassembly buffer.
    pub put_data_buffer: Vec<u8>,
    /// History of all transceived APDUs.
    pub transceived: Vec<Vec<u8>>,
    /// Simulated PIN attempts.
    pub pin_verified: bool,
}

impl Default for SimulatedCard {
    fn default() -> Self {
        Self::new()
    }
}

impl SimulatedCard {
    /// Creates a new simulated card.
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
            objects: HashMap::new(),
            put_data_buffer: Vec::new(),
            transceived: Vec::new(),
            pin_verified: false,
        }
    }

    /// Returns a stored certificate for a slot, if present.
    pub fn get_certificate(&self, slot: Slot) -> Result<Option<Vec<u8>>, ObjectError> {
        let tag = slot.certificate_tag().value();
        if let Some(container) = self.objects.get(&tag) {
            Ok(Some(objects::decode_certificate(container)?))
        } else {
            Ok(None)
        }
    }

    /// Resets the card state (clears reassembly buffer and un-verifies PIN).
    pub fn reset(&mut self) {
        self.put_data_buffer.clear();
        self.pin_verified = false;
    }
}

impl CardTransceiver for SimulatedCard {
    fn transceive(&mut self, command: &[u8]) -> Result<Vec<u8>, ProvisionError> {
        self.transceived.push(command.to_vec());

        if command.len() < 4 {
            return Ok(vec![0x67, 0x00]); // Wrong length
        }

        let cla = command[0];
        let ins = command[1];
        let p1 = command[2];
        let p2 = command[3];

        if ins != commands::INS_PUT_DATA {
            self.put_data_buffer.clear();
        }

        match ins {
            // SELECT
            commands::INS_SELECT => {
                let mut resp = vec![
                    0x61, 0x11, // Application property template
                    0x4F, 0x0B, 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00,
                    0x79, 0x02, 0x00, 0x00,
                ];
                resp.extend_from_slice(&[0x90, 0x00]);
                Ok(resp)
            }

            // VERIFY
            commands::INS_VERIFY => {
                if p1 == 0xFF {
                    self.pin_verified = false;
                    return Ok(vec![0x90, 0x00]);
                }
                if command.len() >= 13 && command[4] == 0x08 {
                    // Padded pin
                    self.pin_verified = true;
                    Ok(vec![0x90, 0x00])
                } else if command.len() == 4 {
                    // Retries check
                    Ok(vec![0x90, 0x00])
                } else {
                    Ok(vec![0x63, 0xC3]) // 3 attempts remaining
                }
            }

            // GENERATE ASYMMETRIC KEY PAIR
            commands::INS_GENERATE_KEY_PAIR => {
                let slot_ref = p2;
                // Generate a deterministic 65-byte uncompressed P-256 public key for this slot
                let mut point = vec![0x04];
                point.extend_from_slice(&[slot_ref; 32]);
                point.extend_from_slice(&[!slot_ref; 32]);

                self.keys.insert(slot_ref, point.clone());

                let point_tlv = tlv::encode_to_vec(objects::TAG_EC_POINT, &point);
                let template = tlv::encode_to_vec(objects::TAG_PUBLIC_KEY, &point_tlv);

                let mut resp = template;
                resp.extend_from_slice(&[0x90, 0x00]);
                Ok(resp)
            }

            // GENERAL AUTHENTICATE
            commands::INS_GENERAL_AUTHENTICATE => {
                // Generate a synthetic DER signature: SEQUENCE { r INTEGER, s INTEGER }
                let r = [0x55u8; 32];
                let s = [0x66u8; 32];
                let sig_der = crate::cert::encode_ecdsa_signature(&r, &s);
                let resp_elem = tlv::encode_to_vec(objects::TAG_RESPONSE, &sig_der);
                let template = tlv::encode_to_vec(objects::TAG_DYNAMIC_AUTH, &resp_elem);

                let mut resp = template;
                resp.extend_from_slice(&[0x90, 0x00]);
                Ok(resp)
            }

            // PUT DATA
            commands::INS_PUT_DATA => {
                if command.len() < 5 {
                    return Ok(vec![0x67, 0x00]);
                }
                let lc = command[4] as usize;
                if command.len() < 5 + lc {
                    return Ok(vec![0x67, 0x00]);
                }
                let payload = &command[5..5 + lc];
                self.put_data_buffer.extend_from_slice(payload);

                if (cla & CLA_CHAIN) == 0 {
                    // Final block: reassemble complete TLV and store
                    let reassembled = std::mem::take(&mut self.put_data_buffer);
                    let elements = tlv::parse_all(&reassembled).map_err(ProvisionError::Tlv)?;

                    if let (Some(tag_bytes), Some(data_bytes)) = (
                        tlv::find(&elements, objects::TAG_TAG_LIST),
                        tlv::find(&elements, objects::TAG_DATA),
                    ) {
                        let mut tag_val = 0u32;
                        for &b in tag_bytes {
                            tag_val = (tag_val << 8) | u32::from(b);
                        }
                        self.objects.insert(tag_val, data_bytes.to_vec());
                    }
                }
                Ok(vec![0x90, 0x00])
            }

            // GET DATA
            commands::INS_GET_DATA => {
                if command.len() < 10 {
                    return Ok(vec![0x6A, 0x82]); // File not found
                }
                let req_tag = &command[7..10];
                let mut tag_val = 0u32;
                for &b in req_tag {
                    tag_val = (tag_val << 8) | u32::from(b);
                }

                if let Some(obj) = self.objects.get(&tag_val) {
                    let mut resp = tlv::encode_to_vec(objects::TAG_DATA, obj);
                    resp.extend_from_slice(&[0x90, 0x00]);
                    Ok(resp)
                } else {
                    Ok(vec![0x6A, 0x82]) // Object not found
                }
            }

            _ => Ok(vec![0x6D, 0x00]), // Instruction not supported
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::parse_certificate;

    #[test]
    fn provision_slot_9a_end_to_end_simulated() {
        let mut card = SimulatedCard::new();
        let report = provision_slot(
            &mut card,
            Slot::PivAuthentication,
            Some(b"123456"),
            Some("Test Auth"),
        )
        .unwrap();

        assert_eq!(report.slot, Slot::PivAuthentication);
        assert_eq!(report.public_key.len(), 65);
        assert_eq!(report.public_key[0], 0x04);
        assert!(report.chained_apdus_count > 1);

        // Verify stored object in card
        let stored_cert = card
            .get_certificate(Slot::PivAuthentication)
            .unwrap()
            .unwrap();
        assert_eq!(stored_cert, report.certificate_der);

        // Parse and verify stored certificate
        let parsed = parse_certificate(&stored_cert).unwrap();
        assert_eq!(parsed.common_name, "Test Auth");
        assert_eq!(parsed.public_key, report.public_key);
    }

    #[test]
    fn provision_slot_9d_end_to_end_simulated() {
        let mut card = SimulatedCard::new();
        let report = provision_slot(
            &mut card,
            Slot::KeyManagement,
            Some(b"123456"),
            Some("Test KeyMgmt"),
        )
        .unwrap();

        assert_eq!(report.slot, Slot::KeyManagement);
        assert_eq!(report.public_key.len(), 65);

        let stored_cert = card.get_certificate(Slot::KeyManagement).unwrap().unwrap();
        assert_eq!(stored_cert, report.certificate_der);

        let parsed = parse_certificate(&stored_cert).unwrap();
        assert_eq!(parsed.common_name, "Test KeyMgmt");
    }

    #[test]
    fn chained_put_data_wire_format_matches_firmware_test_vectors() {
        let mut card = SimulatedCard::new();
        let report = provision_slot(&mut card, Slot::PivAuthentication, None, None).unwrap();

        // Check the transceived PUT DATA APDUs:
        // CLA 0x10 for all intermediate, CLA 0x00 for the final.
        // INS 0xDB, P1 0x3F, P2 0xFF, Lc <= 255
        let put_data_apdus: Vec<&Vec<u8>> = card
            .transceived
            .iter()
            .filter(|apdu| apdu.len() >= 5 && apdu[1] == commands::INS_PUT_DATA)
            .collect();

        assert_eq!(put_data_apdus.len(), report.chained_apdus_count);
        assert!(put_data_apdus.len() >= 2);

        let last_idx = put_data_apdus.len() - 1;
        for (i, apdu) in put_data_apdus.iter().enumerate() {
            let expected_cla = if i == last_idx { 0x00 } else { 0x10 };
            assert_eq!(apdu[0], expected_cla, "APDU {i} CLA mismatch");
            assert_eq!(apdu[1], 0xDB, "APDU {i} INS mismatch");
            assert_eq!(apdu[2], 0x3F, "APDU {i} P1 mismatch");
            assert_eq!(apdu[3], 0xFF, "APDU {i} P2 mismatch");
            let lc = apdu[4] as usize;
            assert!(lc <= 255);
            assert_eq!(apdu.len(), 5 + lc);
        }
    }

    #[test]
    fn simulated_card_clears_put_data_buffer_on_non_put_data_command_or_reset() {
        let mut card = SimulatedCard::new();
        // Simulate partial PUT DATA chunk (chained with CLA = 0x10)
        let partial_put = vec![
            0x10,
            commands::INS_PUT_DATA,
            0x3F,
            0xFF,
            0x04,
            0x01,
            0x02,
            0x03,
            0x04,
        ];
        card.transceive(&partial_put).unwrap();
        assert_eq!(card.put_data_buffer, vec![0x01, 0x02, 0x03, 0x04]);

        // Send a non-PUT-DATA command (e.g. VERIFY retries check)
        let verify_cmd = vec![0x00, commands::INS_VERIFY, 0x00, 0x80];
        card.transceive(&verify_cmd).unwrap();
        assert!(
            card.put_data_buffer.is_empty(),
            "buffer must be cleared on non-PUT-DATA"
        );

        // Simulate another partial PUT DATA chunk
        card.transceive(&partial_put).unwrap();
        assert_eq!(card.put_data_buffer, vec![0x01, 0x02, 0x03, 0x04]);

        // Call reset()
        card.reset();
        assert!(
            card.put_data_buffer.is_empty(),
            "buffer must be cleared on reset"
        );
    }
}
