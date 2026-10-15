//! OATH protocol unit tests, cryptographic vectors, and simulated token exchanges.

use cryptick_manager::access::{derive_access_key, hmac_sha1, sha1};
use cryptick_manager::apdu::{aid, format_hex, CommandApdu};
use cryptick_manager::oath::{
    calculate_code, delete_account, list_accounts, put_account, reset_oath, select_oath,
    AddAccountOptions,
};
use cryptick_manager::otpauth::{HashAlgorithm, OathType};
use cryptick_manager::tlv::{tags, Tlv};
use cryptick_manager::transport::TokenTransport;
use std::collections::HashMap;
use std::time::Duration;

#[test]
fn test_sha1_and_hmac_sha1_rfc_vectors() {
    // 1. RFC 3174 SHA-1 Test Vector 1 ("abc")
    let hash_abc = sha1(b"abc");
    assert_eq!(
        format_hex(&hash_abc),
        "A9 99 3E 36 47 06 81 6A BA 3E 25 71 78 50 C2 6C 9C D0 D8 9D"
    );

    // 2. RFC 2202 HMAC-SHA1 Test Case 1
    // Key: 20 bytes 0x0b, Data: "Hi There"
    let key1 = [0x0b; 20];
    let data1 = b"Hi There";
    let hmac1 = hmac_sha1(&key1, data1);
    assert_eq!(
        format_hex(&hmac1),
        "B6 17 31 86 55 05 72 64 E2 8B C0 B6 FB 37 8C 8E F1 46 BE 00"
    );

    // 3. PBKDF2-HMAC-SHA1 Key Derivation
    let derived = derive_access_key("test-password", b"device-salt-1234");
    assert_eq!(derived.len(), 16);
    // Deterministic output
    let derived_repeat = derive_access_key("test-password", b"device-salt-1234");
    assert_eq!(derived, derived_repeat);
}

#[test]
fn test_tlv_encoding_and_multi_byte_lengths() {
    // Short length (< 128)
    let tlv1 = Tlv::new(0x71, b"GitHub:alice".to_vec());
    let enc1 = tlv1.encode();
    assert_eq!(enc1[0], 0x71);
    assert_eq!(enc1[1], 12);
    assert_eq!(&enc1[2..], b"GitHub:alice");

    // 1-byte extended length (128..255)
    let val150 = vec![0x42; 150];
    let tlv2 = Tlv::new(0x73, val150.clone());
    let enc2 = tlv2.encode();
    assert_eq!(enc2[0], 0x73);
    assert_eq!(enc2[1], 0x81);
    assert_eq!(enc2[2], 150);
    assert_eq!(&enc2[3..], &val150[..]);

    // Parse back
    let parsed2 = Tlv::parse_all(&enc2).expect("parse 150-byte TLV");
    assert_eq!(parsed2.len(), 1);
    assert_eq!(parsed2[0].tag, 0x73);
    assert_eq!(parsed2[0].value, val150);

    // Multiple concatenated TLVs
    let mut combined = Vec::new();
    combined.extend_from_slice(&tlv1.encode());
    combined.extend_from_slice(&Tlv::new(0x74, vec![0x01, 0x02, 0x03, 0x04]).encode());

    let parsed_multi = Tlv::parse_all(&combined).expect("parse multiple TLVs");
    assert_eq!(parsed_multi.len(), 2);
    assert_eq!(parsed_multi[0].tag, 0x71);
    assert_eq!(parsed_multi[1].tag, 0x74);
    assert_eq!(parsed_multi[1].value, vec![0x01, 0x02, 0x03, 0x04]);
}

/// Simulated TokenTransport that mimics Cryptick Token OATH applet behavior.
struct SimulatedOathToken {
    version: (u8, u8, u8),
    salt: Vec<u8>,
    password_key: Option<[u8; 16]>,
    accounts: HashMap<String, (Vec<u8>, OathType, HashAlgorithm, u32, bool)>,
    authenticated: bool,
    active_challenge: Option<Vec<u8>>,
}

impl SimulatedOathToken {
    fn new() -> Self {
        Self {
            version: (1, 0, 1),
            salt: b"cryptick-salt-token-test".to_vec(),
            password_key: None,
            accounts: HashMap::new(),
            authenticated: true,
            active_challenge: None,
        }
    }

    fn with_password(mut self, password: &str) -> Self {
        let key = derive_access_key(password, &self.salt);
        self.password_key = Some(key);
        self.authenticated = false;
        self
    }
}

impl TokenTransport for SimulatedOathToken {
    fn transceive(
        &mut self,
        _cmd: u8,
        payload: &[u8],
        _timeout: Duration,
    ) -> Result<Vec<u8>, String> {
        let apdu = CommandApdu::parse(payload)?;

        // 1. SELECT AID
        if apdu.cla == 0x00 && apdu.ins == 0xA4 {
            if apdu.data == aid::OATH {
                let mut tlvs = Vec::new();
                // Tag 0x79: Version
                tlvs.push(Tlv::new(
                    tags::TAG_VERSION,
                    vec![self.version.0, self.version.1, self.version.2],
                ));
                // Tag 0x71: Salt / Device ID
                tlvs.push(Tlv::new(tags::TAG_NAME, self.salt.clone()));

                // Tag 0x74: Challenge (if password is set)
                if self.password_key.is_some() {
                    let chal = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
                    self.active_challenge = Some(chal.clone());
                    tlvs.push(Tlv::new(tags::TAG_CHALLENGE, chal));
                    tlvs.push(Tlv::new(tags::TAG_ALGORITHM, vec![0x01]));
                    self.authenticated = false;
                } else {
                    self.authenticated = true;
                }

                let mut out = cryptick_manager::tlv::encode_tlvs(&tlvs);
                out.extend_from_slice(&[0x90, 0x00]);
                return Ok(out);
            } else {
                return Ok(vec![0x6A, 0x82]); // File not found
            }
        }

        // 2. VALIDATE (INS 0x07)
        if apdu.cla == 0x00 && apdu.ins == 0x07 {
            let tlvs = Tlv::parse_all(&apdu.data)?;
            let resp_tlv = Tlv::find(&tlvs, tags::TAG_RESPONSE).ok_or("Missing TAG_RESPONSE")?;
            if let Some(ref pwd_key) = self.password_key {
                let chal = self.active_challenge.as_ref().ok_or("No active challenge")?;
                let expected = hmac_sha1(pwd_key, chal);
                if resp_tlv.value == expected[..resp_tlv.value.len()] {
                    self.authenticated = true;
                    return Ok(vec![0x90, 0x00]);
                } else {
                    return Ok(vec![0x69, 0x82]); // Security status not satisfied
                }
            } else {
                self.authenticated = true;
                return Ok(vec![0x90, 0x00]);
            }
        }

        // RESET (INS 0x04) is always unauthenticated (recovery operation)
        if apdu.cla == 0x00 && apdu.ins == 0x04 {
            self.accounts.clear();
            self.password_key = None;
            self.authenticated = true;
            return Ok(vec![0x90, 0x00]);
        }

        // Check authentication status for sensitive operations
        if !self.authenticated {
            return Ok(vec![0x69, 0x82]);
        }

        // 3. PUT (INS 0x01)
        if apdu.cla == 0x00 && apdu.ins == 0x01 {
            let tlvs = Tlv::parse_all(&apdu.data)?;
            let name_tlv = Tlv::find(&tlvs, tags::TAG_NAME).ok_or("Missing TAG_NAME")?;
            let key_tlv = Tlv::find(&tlvs, tags::TAG_KEY).ok_or("Missing TAG_KEY")?;
            let name = String::from_utf8_lossy(&name_tlv.value).to_string();

            let (oath_type, alg) = if let Some((ot, ha)) = HashAlgorithm::from_algo_byte(key_tlv.value[0]) {
                (ot, ha)
            } else {
                (OathType::Totp, HashAlgorithm::Sha1)
            };

            let digits = if key_tlv.value.len() > 1 && (key_tlv.value[1] == 6 || key_tlv.value[1] == 8) {
                key_tlv.value[1] as u32
            } else {
                6
            };

            let touch = Tlv::find(&tlvs, tags::TAG_PROPERTY)
                .map(|p| p.value.contains(&0x02))
                .unwrap_or(false);

            self.accounts.insert(name, (key_tlv.value.clone(), oath_type, alg, digits, touch));
            return Ok(vec![0x90, 0x00]);
        }

        // 4. LIST (INS 0xA1 or 0x05)
        if apdu.cla == 0x00 && (apdu.ins == 0xA1 || apdu.ins == 0x05) {
            let mut out = Vec::new();
            for (name, (_, ot, alg, _, touch)) in &self.accounts {
                let mut val = Vec::new();
                let mut b = alg.to_algo_byte(*ot);
                if *touch {
                    b |= 0x08;
                }
                val.push(b);
                val.extend_from_slice(name.as_bytes());
                let tlv = Tlv::new(tags::TAG_NAME, val);
                out.extend_from_slice(&tlv.encode());
            }
            out.extend_from_slice(&[0x90, 0x00]);
            return Ok(out);
        }

        // 5. CALCULATE (INS 0xA2 or 0x06)
        if apdu.cla == 0x00 && (apdu.ins == 0xA2 || apdu.ins == 0x06) {
            let tlvs = Tlv::parse_all(&apdu.data)?;
            let name_tlv = Tlv::find(&tlvs, tags::TAG_NAME).ok_or("Missing TAG_NAME")?;
            let name = String::from_utf8_lossy(&name_tlv.value).to_string();

            if let Some((_, _, _, digits, _)) = self.accounts.get(&name) {
                let mut resp_tlvs = Vec::new();
                // Tag 0x75: [digits] [4-byte big-endian OTP code]
                let mut code_payload = Vec::new();
                code_payload.push(*digits as u8);
                // 842195 = 0x000CDDF3
                code_payload.extend_from_slice(&842195u32.to_be_bytes());
                resp_tlvs.push(Tlv::new(tags::TAG_RESPONSE, code_payload));
                // Tag 0x78: remaining validity seconds (22s)
                resp_tlvs.push(Tlv::new(tags::TAG_PROPERTY, vec![22]));

                let mut out = cryptick_manager::tlv::encode_tlvs(&resp_tlvs);
                out.extend_from_slice(&[0x90, 0x00]);
                return Ok(out);
            } else {
                return Ok(vec![0x6A, 0x88]); // Referenced data not found
            }
        }

        // 6. DELETE (INS 0x02 or 0x03)
        if apdu.cla == 0x00 && (apdu.ins == 0x02 || apdu.ins == 0x03) {
            let tlvs = Tlv::parse_all(&apdu.data)?;
            let name_tlv = Tlv::find(&tlvs, tags::TAG_NAME).ok_or("Missing TAG_NAME")?;
            let name = String::from_utf8_lossy(&name_tlv.value).to_string();

            if self.accounts.remove(&name).is_some() {
                return Ok(vec![0x90, 0x00]);
            } else {
                return Ok(vec![0x6A, 0x88]);
            }
        }

        // 7. RESET (INS 0x04)
        if apdu.cla == 0x00 && apdu.ins == 0x04 {
            self.accounts.clear();
            self.password_key = None;
            self.authenticated = true;
            return Ok(vec![0x90, 0x00]);
        }

        // 8. SET CODE (INS 0x03)
        if apdu.cla == 0x00 && apdu.ins == 0x03 {
            let tlvs = Tlv::parse_all(&apdu.data)?;
            if let Some(key_tlv) = Tlv::find(&tlvs, tags::TAG_KEY) {
                if key_tlv.value.is_empty() {
                    self.password_key = None;
                } else if key_tlv.value.len() == 16 {
                    let mut k = [0u8; 16];
                    k.copy_from_slice(&key_tlv.value);
                    self.password_key = Some(k);
                }
                return Ok(vec![0x90, 0x00]);
            }
        }

        Ok(vec![0x6D, 0x00]) // Instruction not supported
    }

    fn transport_name(&self) -> &'static str {
        "Simulated Cryptick Token"
    }

    fn serial(&self) -> Option<String> {
        Some("SIM-CRYPTICK-01".to_string())
    }
}

#[test]
fn test_simulated_oath_lifecycle() {
    let mut token = SimulatedOathToken::new();

    // 1. Select OATH
    let info = select_oath(&mut token).expect("select oath");
    assert_eq!(info.version, (1, 0, 1));
    assert!(!info.password_protected);

    // 2. Add an account
    put_account(
        &mut token,
        AddAccountOptions {
            name: "GitHub:alice".to_string(),
            secret: vec![0x11; 20],
            oath_type: OathType::Totp,
            algorithm: HashAlgorithm::Sha1,
            digits: 6,
            period: 30,
            counter: 0,
            touch: true,
        },
        None,
    )
    .expect("put account");

    // 3. List accounts
    let accounts = list_accounts(&mut token, None).expect("list accounts");
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].name, "GitHub:alice");
    assert_eq!(accounts[0].oath_type, OathType::Totp);
    assert!(accounts[0].touch_required);

    // 4. Calculate code
    let calc = calculate_code(&mut token, "GitHub:alice", Some(1729000000), 30, None)
        .expect("calculate code");
    assert_eq!(calc.name, "GitHub:alice");
    assert_eq!(calc.code, "842195");
    assert_eq!(calc.remaining_seconds, Some(22));

    // 5. Delete account
    delete_account(&mut token, "GitHub:alice", None).expect("delete account");
    let accounts_after = list_accounts(&mut token, None).expect("list after delete");
    assert_eq!(accounts_after.len(), 0);

    // 6. Delete nonexistent account returns error
    assert!(delete_account(&mut token, "GitHub:alice", None).is_err());
}

#[test]
fn test_password_protected_oath_session() {
    let mut token = SimulatedOathToken::new().with_password("secret123");

    // Select should show password protected
    let info = select_oath(&mut token).expect("select oath");
    assert!(info.password_protected);
    assert!(info.challenge.is_some());

    // Listing without password fails
    assert!(list_accounts(&mut token, None).is_err());

    // Listing with wrong password fails
    assert!(list_accounts(&mut token, Some("wrongpass")).is_err());

    // Listing with correct password succeeds
    let accs = list_accounts(&mut token, Some("secret123")).expect("list with correct password");
    assert_eq!(accs.len(), 0);

    // Reset clears password
    reset_oath(&mut token).expect("reset oath");
    let info_after_reset = select_oath(&mut token).expect("select after reset");
    assert!(!info_after_reset.password_protected);
}
