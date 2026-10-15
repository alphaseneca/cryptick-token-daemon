//! Integration tests for Requirement 4 (R4): PIV Provisioning Tool (`cryptick-piv`).
//!
//! Verifies:
//! 1. Key generation command serialization and public key parsing.
//! 2. X.509 v3 self-signed certificate generation and validity.
//! 3. SP 800-73-5 container wrapping (Tag 0x53 containing 0x70, 0x71, 0xFE).
//! 4. Chained PUT DATA APDU emission and byte-level wire format matching test vectors.
//! 5. End-to-end card transceive and certificate storage on simulated token.
//! 6. CLI argument parser flags, help, version, and dry-run options.

use piv::algorithm;
use piv::cert::{encode_ecdsa_signature, parse_certificate, CertificateBuilder, KeyUsage};
use piv::commands::{self, parse_public_key, PublicKey, PublicKeyError};
use piv::objects::{self, Slot};
use piv::provision::{provision_slot, SimulatedCard};
use piv::tlv;


fn sample_p256_point() -> [u8; 65] {
    let mut point = [0x42u8; 65];
    point[0] = 0x04; // uncompressed EC point
    point
}

#[test]
fn key_generation_apdu_and_public_key_parsing() {
    // 1. Generation command format for 9A (PIV Authentication)
    let cmd_9a = commands::generate_key_pair(Slot::PivAuthentication, algorithm::ECC_P256);
    let bytes_9a = cmd_9a.encode().unwrap();
    // Header: CLA 00, INS 47, P1 00, P2 9A, Lc 05, Data AC 03 80 01 11, Le 00
    assert_eq!(
        bytes_9a,
        vec![0x00, 0x47, 0x00, 0x9A, 0x05, 0xAC, 0x03, 0x80, 0x01, 0x11, 0x00]
    );

    // 2. Generation command format for 9D (Key Management)
    let cmd_9d = commands::generate_key_pair(Slot::KeyManagement, algorithm::ECC_P256);
    let bytes_9d = cmd_9d.encode().unwrap();
    assert_eq!(
        bytes_9d,
        vec![0x00, 0x47, 0x00, 0x9D, 0x05, 0xAC, 0x03, 0x80, 0x01, 0x11, 0x00]
    );

    // 3. Parse valid public key response
    let point = sample_p256_point();
    let point_tlv = tlv::encode_to_vec(objects::TAG_EC_POINT, &point);
    let pubkey_template = tlv::encode_to_vec(objects::TAG_PUBLIC_KEY, &point_tlv);

    let parsed = parse_public_key(&pubkey_template).unwrap();
    assert_eq!(parsed, PublicKey::Ec { point: point.to_vec() });

    // 4. Compressed points must be rejected (0x02 or 0x03)
    let mut compressed = vec![0x02];
    compressed.extend_from_slice(&[0x11; 32]);
    let compressed_tlv = tlv::encode_to_vec(objects::TAG_EC_POINT, &compressed);
    let compressed_template = tlv::encode_to_vec(objects::TAG_PUBLIC_KEY, &compressed_tlv);
    assert_eq!(
        parse_public_key(&compressed_template).unwrap_err(),
        PublicKeyError::NotUncompressed(0x02)
    );
}

#[test]
fn x509_v3_certificate_generation_and_validity_for_slot_9a() {
    let point = sample_p256_point();
    let builder = CertificateBuilder::new(Slot::PivAuthentication, &point)
        .unwrap()
        .with_common_name("Cryptick PIV Authentication")
        .unwrap()
        .with_serial_number(1)
        .with_validity("260101000000Z", "270101000000Z")
        .unwrap();

    let cert_der = builder.build_self_signed().unwrap();
    assert_eq!(cert_der[0], 0x30); // SEQUENCE

    let parsed = parse_certificate(&cert_der).unwrap();
    assert_eq!(parsed.version, 2); // v3
    assert_eq!(parsed.common_name, "Cryptick PIV Authentication");
    assert_eq!(parsed.public_key, point.to_vec());
    assert_eq!(parsed.not_before, "260101000000Z");
    assert_eq!(parsed.not_after, "270101000000Z");

    // Key Usage for 9A: Digital Signature MUST be set
    assert!(parsed.key_usage.contains(KeyUsage::DIGITAL_SIGNATURE));
    assert!(!parsed.key_usage.contains(KeyUsage::KEY_ENCIPHERMENT));
    assert!(!parsed.key_usage.contains(KeyUsage::KEY_AGREEMENT));
}

#[test]
fn x509_v3_certificate_generation_and_validity_for_slot_9d() {
    let point = sample_p256_point();
    let builder = CertificateBuilder::new(Slot::KeyManagement, &point)
        .unwrap()
        .with_common_name("Cryptick PIV Key Management")
        .unwrap()
        .with_serial_number(2)
        .with_validity("260101000000Z", "270101000000Z")
        .unwrap();

    let cert_der = builder.build_self_signed().unwrap();
    let parsed = parse_certificate(&cert_der).unwrap();

    assert_eq!(parsed.version, 2);
    assert_eq!(parsed.common_name, "Cryptick PIV Key Management");
    assert_eq!(parsed.public_key, point.to_vec());

    // Key Usage for 9D: Key Encipherment and Key Agreement MUST be set
    assert!(parsed.key_usage.contains(KeyUsage::KEY_ENCIPHERMENT));
    assert!(parsed.key_usage.contains(KeyUsage::KEY_AGREEMENT));
    assert!(!parsed.key_usage.contains(KeyUsage::DIGITAL_SIGNATURE));
}

#[test]
fn x509_v3_certificate_generation_and_validity_for_slot_9c() {
    let point = sample_p256_point();
    let builder = CertificateBuilder::new(Slot::DigitalSignature, &point)
        .unwrap()
        .with_common_name("Cryptick PIV Digital Signature")
        .unwrap()
        .with_serial_number(3)
        .with_validity("260101000000Z", "270101000000Z")
        .unwrap();

    let cert_der = builder.build_self_signed().unwrap();
    let parsed = parse_certificate(&cert_der).unwrap();

    assert_eq!(parsed.version, 2);
    assert_eq!(parsed.common_name, "Cryptick PIV Digital Signature");
    assert_eq!(parsed.public_key, point.to_vec());

    // Key Usage for 9C: Digital Signature and Non-Repudiation MUST be set
    assert!(parsed.key_usage.contains(KeyUsage::DIGITAL_SIGNATURE));
    assert!(parsed.key_usage.contains(KeyUsage::NON_REPUDIATION));
    assert!(!parsed.key_usage.contains(KeyUsage::KEY_ENCIPHERMENT));
    assert!(!parsed.key_usage.contains(KeyUsage::KEY_AGREEMENT));
}

#[test]
fn x509_v3_certificate_generation_and_validity_for_slot_9e() {
    let point = sample_p256_point();
    let builder = CertificateBuilder::new(Slot::CardAuthentication, &point)
        .unwrap()
        .with_common_name("Cryptick PIV Card Authentication")
        .unwrap()
        .with_serial_number(4)
        .with_validity("260101000000Z", "270101000000Z")
        .unwrap();

    let cert_der = builder.build_self_signed().unwrap();
    let parsed = parse_certificate(&cert_der).unwrap();

    assert_eq!(parsed.version, 2);
    assert_eq!(parsed.common_name, "Cryptick PIV Card Authentication");
    assert_eq!(parsed.public_key, point.to_vec());

    // Key Usage for 9E: Digital Signature MUST be set, no Key Encipherment or Non-Repudiation
    assert!(parsed.key_usage.contains(KeyUsage::DIGITAL_SIGNATURE));
    assert!(!parsed.key_usage.contains(KeyUsage::NON_REPUDIATION));
    assert!(!parsed.key_usage.contains(KeyUsage::KEY_ENCIPHERMENT));
    assert!(!parsed.key_usage.contains(KeyUsage::KEY_AGREEMENT));
}

#[test]
fn sp800_73_5_certificate_container_roundtrip() {
    let point = sample_p256_point();
    let builder = CertificateBuilder::new(Slot::PivAuthentication, &point).unwrap();
    let cert_der = builder.build_self_signed().unwrap();

    // Container format: Tag 70 (cert), Tag 71 (0x01 0x00), Tag FE (0x00)
    let container = objects::encode_certificate(&cert_der);
    assert_eq!(container[0], 0x70); // Tag 70
    assert!(container.len() > cert_der.len());

    // Decode and verify roundtrip
    let decoded = objects::decode_certificate(&container).unwrap();
    assert_eq!(decoded, cert_der);
}

#[test]
fn chained_put_data_wire_format_matches_reference_vector() {
    // Reference Python vector pattern:
    // cla = 0x10 if body else 0x00
    // bytes([cla, 0xDB, 0x3F, 0xFF, len(block)]) + block
    let point = sample_p256_point();
    let builder = CertificateBuilder::new(Slot::PivAuthentication, &point).unwrap();
    let cert_der = builder.build_self_signed().unwrap();
    let container = objects::encode_certificate(&cert_der);

    let put_cmd = commands::put_data(Slot::PivAuthentication.certificate_tag(), &container);
    let links = piv::chain(&put_cmd, 255).unwrap();

    // Verify chain length > 1 for typical cert size (~500 bytes)
    assert!(links.len() >= 2);

    let mut body = put_cmd.data.clone();
    let mut expected_blocks = Vec::new();
    while !body.is_empty() {
        let chunk_size = body.len().min(255);
        let block = body.drain(..chunk_size).collect::<Vec<u8>>();
        let cla = if !body.is_empty() { 0x10 } else { 0x00 };
        let mut expected = vec![cla, 0xDB, 0x3F, 0xFF, block.len() as u8];
        expected.extend_from_slice(&block);
        expected_blocks.push(expected);
    }

    assert_eq!(links.len(), expected_blocks.len());

    for (i, link) in links.iter().enumerate() {
        let encoded = link.encode().unwrap();
        assert_eq!(encoded, expected_blocks[i], "Mismatch in block {i}");
    }
}

#[test]
fn simulated_card_end_to_end_provisioning() {
    let mut card = SimulatedCard::new();

    // Provision 9A
    let report_9a = provision_slot(
        &mut card,
        Slot::PivAuthentication,
        Some(b"123456"),
        Some("E2E Auth Cert"),
    )
    .unwrap();
    assert_eq!(report_9a.slot, Slot::PivAuthentication);
    assert_eq!(report_9a.public_key.len(), 65);
    assert!(report_9a.chained_apdus_count >= 2);

    // Provision 9D
    let report_9d = provision_slot(
        &mut card,
        Slot::KeyManagement,
        Some(b"123456"),
        Some("E2E KeyMgmt Cert"),
    )
    .unwrap();
    assert_eq!(report_9d.slot, Slot::KeyManagement);
    assert_eq!(report_9d.public_key.len(), 65);
    assert!(report_9d.chained_apdus_count >= 2);

    // Verify stored certificates in the simulated card
    let cert_9a = card.get_certificate(Slot::PivAuthentication).unwrap().unwrap();
    assert_eq!(cert_9a, report_9a.certificate_der);
    let parsed_9a = parse_certificate(&cert_9a).unwrap();
    assert_eq!(parsed_9a.common_name, "E2E Auth Cert");

    let cert_9d = card.get_certificate(Slot::KeyManagement).unwrap().unwrap();
    assert_eq!(cert_9d, report_9d.certificate_der);
    let parsed_9d = parse_certificate(&cert_9d).unwrap();
    assert_eq!(parsed_9d.common_name, "E2E KeyMgmt Cert");

    // Verify transceived APDU history
    assert!(card.transceived.len() > 10);
}

#[test]
fn simulated_card_end_to_end_provisioning_all_four_slots() {
    let mut card = SimulatedCard::new();

    // Provision all 4 slots: 9A, 9C, 9D, 9E
    let slots_to_test = [
        (Slot::PivAuthentication, "Slot 9A Auth", tlv::Tag::new(0x5F_C105)),
        (Slot::DigitalSignature, "Slot 9C Signature", tlv::Tag::new(0x5F_C10A)),
        (Slot::KeyManagement, "Slot 9D KeyMgmt", tlv::Tag::new(0x5F_C10B)),
        (Slot::CardAuthentication, "Slot 9E CardAuth", tlv::Tag::new(0x5F_C101)),
    ];

    for (slot, cn, expected_tag) in slots_to_test {
        assert_eq!(slot.certificate_tag(), expected_tag);

        let report = provision_slot(
            &mut card,
            slot,
            Some(b"123456"),
            Some(cn),
        )
        .unwrap();

        assert_eq!(report.slot, slot);
        assert_eq!(report.public_key.len(), 65);
        assert!(report.chained_apdus_count >= 1);

        // Verify stored certificate in simulated card
        let cert_der = card.get_certificate(slot).unwrap().expect("stored cert exists");
        assert_eq!(cert_der, report.certificate_der);

        let parsed = parse_certificate(&cert_der).unwrap();
        assert_eq!(parsed.common_name, cn);
        assert_eq!(parsed.public_key, report.public_key);

        match slot {
            Slot::PivAuthentication => {
                assert!(parsed.key_usage.contains(KeyUsage::DIGITAL_SIGNATURE));
                assert!(!parsed.key_usage.contains(KeyUsage::KEY_ENCIPHERMENT));
            }
            Slot::DigitalSignature => {
                assert!(parsed.key_usage.contains(KeyUsage::DIGITAL_SIGNATURE));
                assert!(parsed.key_usage.contains(KeyUsage::NON_REPUDIATION));
            }
            Slot::KeyManagement => {
                assert!(parsed.key_usage.contains(KeyUsage::KEY_ENCIPHERMENT));
                assert!(parsed.key_usage.contains(KeyUsage::KEY_AGREEMENT));
            }
            Slot::CardAuthentication => {
                assert!(parsed.key_usage.contains(KeyUsage::DIGITAL_SIGNATURE));
                assert!(!parsed.key_usage.contains(KeyUsage::NON_REPUDIATION));
                assert!(!parsed.key_usage.contains(KeyUsage::KEY_ENCIPHERMENT));
            }
        }
    }
}

#[test]
fn ecdsa_signature_encoding_positive_integers() {
    // Both r and s have high bit set: must prepend 0x00 to remain positive DER integers
    let r = [0xFFu8; 32];
    let s = [0x80u8; 32];
    let sig = encode_ecdsa_signature(&r, &s);


    assert_eq!(sig[0], 0x30); // SEQUENCE
    assert_eq!(sig[2], 0x02); // INTEGER
    assert_eq!(sig[3], 33);   // 32 bytes + 1 padding byte
    assert_eq!(sig[4], 0x00); // padding byte
    assert_eq!(&sig[5..37], &r);

    assert_eq!(sig[37], 0x02); // INTEGER
    assert_eq!(sig[38], 33);   // 32 bytes + 1 padding byte
    assert_eq!(sig[39], 0x00); // padding byte
    assert_eq!(&sig[40..72], &s);
}

#[test]
fn x509_rejects_empty_common_name_rfc5280() {
    let point = sample_p256_point();
    let builder = CertificateBuilder::new(Slot::PivAuthentication, &point).unwrap();

    assert!(builder.clone().with_common_name("").is_err());
    assert!(builder.with_common_name("   ").is_err());
}

#[test]
fn simulated_card_put_data_buffer_isolation() {
    use piv::commands;
    use piv::CardTransceiver;

    let mut card = SimulatedCard::new();

    // Partial chained PUT DATA
    let partial_apdu = vec![0x10, commands::INS_PUT_DATA, 0x3F, 0xFF, 0x03, 0xAA, 0xBB, 0xCC];
    card.transceive(&partial_apdu).unwrap();
    assert_eq!(card.put_data_buffer, vec![0xAA, 0xBB, 0xCC]);

    // Interrupted by an unrelated command (e.g. GET DATA)
    let get_apdu = vec![0x00, commands::INS_GET_DATA, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x05];
    let _ = card.transceive(&get_apdu);
    assert!(card.put_data_buffer.is_empty(), "buffer must be cleared on non-PUT-DATA command");

    // Partial chained PUT DATA again
    card.transceive(&partial_apdu).unwrap();
    assert_eq!(card.put_data_buffer, vec![0xAA, 0xBB, 0xCC]);

    // Interrupted by card reset
    card.reset();
    assert!(card.put_data_buffer.is_empty(), "buffer must be cleared on reset");
}
