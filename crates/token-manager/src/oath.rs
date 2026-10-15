//! High-level YKOATH applet client for Cryptick Token.
//!
//! Implements YKOATH protocol operations adhering to `docs/OATH_SPEC.md`
//! and standard ISO 7816 OATH specifications.

use crate::access::{derive_access_key, get_remembered_key, hmac_sha1, remember_key};
use crate::apdu::{aid, CommandApdu, ResponseApdu, StatusWord};
use crate::otpauth::{HashAlgorithm, OathType};
use crate::tlv::{tags, Tlv};
use crate::transport::TokenTransport;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const OATH_TIMEOUT: Duration = Duration::from_secs(10);
const OATH_UV_TIMEOUT: Duration = Duration::from_secs(30);

/// OATH Applet state and capability information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OathAppletInfo {
    /// Applet version (major, minor, patch).
    pub version: (u8, u8, u8),
    /// Token salt or device identifier (Tag 0x71).
    pub device_id: Vec<u8>,
    /// Authentication challenge from token if password is set (Tag 0x74).
    pub challenge: Option<Vec<u8>>,
    /// Challenge algorithm byte (Tag 0x7B).
    pub algorithm: Option<u8>,
    /// Whether the OATH application is protected by a password / access code.
    pub password_protected: bool,
}

/// Summary of an enrolled account on the token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OathAccountSummary {
    /// Full account name (e.g. `GitHub:alice`).
    pub name: String,
    /// OATH type (TOTP or HOTP).
    pub oath_type: OathType,
    /// HMAC hash algorithm.
    pub algorithm: HashAlgorithm,
    /// Whether user verification (biometric sensor touch) is required to calculate.
    pub touch_required: bool,
}

/// The result of calculating an OTP code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalculatedCode {
    /// Account label.
    pub name: String,
    /// The formatted decimal OTP code (e.g. "842195").
    pub code: String,
    /// Remaining validity duration in seconds (for TOTP).
    pub remaining_seconds: Option<u32>,
    /// Whether touch was required or requested.
    pub touch_required: bool,
}

/// Selects the OATH applet on the token.
pub fn select_oath(transport: &mut dyn TokenTransport) -> Result<OathAppletInfo, String> {
    let select_apdu = CommandApdu::select_applet(aid::OATH);
    let resp_bytes = transport.transceive(0x63, &select_apdu.to_bytes(), OATH_TIMEOUT)?;
    let resp = ResponseApdu::parse(&resp_bytes)?;
    resp.check_success()?;

    let tlvs = Tlv::parse_all(&resp.data)?;

    let mut version = (1, 0, 0);
    if let Some(t) = Tlv::find(&tlvs, tags::TAG_VERSION) {
        if t.value.len() >= 3 {
            version = (t.value[0], t.value[1], t.value[2]);
        }
    }

    let device_id = Tlv::find(&tlvs, tags::TAG_NAME)
        .map(|t| t.value.clone())
        .unwrap_or_else(|| b"cryptick-oath-default-id".to_vec());

    let challenge = Tlv::find(&tlvs, tags::TAG_CHALLENGE).map(|t| t.value.clone());
    let algorithm = Tlv::find(&tlvs, tags::TAG_ALGORITHM).map(|t| t.value.first().copied().unwrap_or(0x01));
    let password_protected = challenge.is_some();

    Ok(OathAppletInfo {
        version,
        device_id,
        challenge,
        algorithm,
        password_protected,
    })
}

/// Unlocks the OATH applet with password or remembered access key if required.
pub fn authenticate_session(
    transport: &mut dyn TokenTransport,
    applet_info: &OathAppletInfo,
    password_opt: Option<&str>,
) -> Result<(), String> {
    let challenge = match &applet_info.challenge {
        Some(chal) if !chal.is_empty() => chal,
        _ => return Ok(()), // No password required
    };

    let key = if let Some(pwd) = password_opt {
        derive_access_key(pwd, &applet_info.device_id)
    } else if let Some(rem_key) = get_remembered_key(&applet_info.device_id) {
        rem_key
    } else {
        return Err(
            "OATH application is password-protected. Provide the password using '-p, --password <PASS>' or run 'ykman oath access remember'.".to_string(),
        );
    };

    let resp_hash = hmac_sha1(&key, challenge);
    let mut val_tlvs = Vec::new();
    // TAG_RESPONSE (0x75)
    val_tlvs.push(Tlv::new(tags::TAG_RESPONSE, resp_hash[..8.min(resp_hash.len())].to_vec()));
    // TAG_CHALLENGE (0x74): 8 random host bytes for mutual auth
    let host_chal = [0x5A; 8];
    val_tlvs.push(Tlv::new(tags::TAG_CHALLENGE, host_chal.to_vec()));

    let apdu_data = crate::tlv::encode_tlvs(&val_tlvs);
    // INS 0x07 = VALIDATE
    let validate_apdu = CommandApdu::with_data(0x00, 0x07, 0x00, 0x00, apdu_data);
    let resp_bytes = transport.transceive(0x63, &validate_apdu.to_bytes(), OATH_TIMEOUT)?;
    let resp = ResponseApdu::parse(&resp_bytes)?;

    if !resp.is_success() {
        if resp.sw == StatusWord::SECURITY_STATUS_NOT_SATISFIED || resp.sw == StatusWord::DATA_INVALID {
            return Err("Authentication failed: incorrect OATH access password.".to_string());
        }
        return Err(format!("OATH VALIDATE returned error {}", resp.sw));
    }

    Ok(())
}

/// Lists all configured OATH accounts on the token.
pub fn list_accounts(
    transport: &mut dyn TokenTransport,
    password_opt: Option<&str>,
) -> Result<Vec<OathAccountSummary>, String> {
    let applet = select_oath(transport)?;
    authenticate_session(transport, &applet, password_opt)?;

    // Try INS 0xA1 (Cryptick LIST) first
    let list_apdu = CommandApdu::new(0x00, 0xA1, 0x00, 0x00);
    let mut resp_bytes = transport.transceive(0x63, &list_apdu.to_bytes(), OATH_TIMEOUT)?;
    let mut resp = ResponseApdu::parse(&resp_bytes)?;

    // Fallback to YKOATH standard INS 0x05 (LIST) if 0xA1 is not supported
    if resp.sw == StatusWord::INS_NOT_SUPPORTED || resp.sw == StatusWord::FUNCTION_NOT_SUPPORTED {
        let list_v2 = CommandApdu::new(0x00, 0x05, 0x00, 0x00);
        resp_bytes = transport.transceive(0x63, &list_v2.to_bytes(), OATH_TIMEOUT)?;
        resp = ResponseApdu::parse(&resp_bytes)?;
    }

    resp.check_success()?;
    let tlvs = Tlv::parse_all(&resp.data)?;

    let mut accounts = Vec::new();
    for tlv in tlvs {
        if tlv.tag == tags::TAG_NAME {
            if tlv.value.is_empty() {
                continue;
            }
            // First byte may be algorithm descriptor (e.g. 0x21, 0x11, 0x22), remainder is name string
            let first_byte = tlv.value[0];
            let (oath_type, alg, name_str) = if let Some((ot, ha)) = HashAlgorithm::from_algo_byte(first_byte) {
                let name = String::from_utf8_lossy(&tlv.value[1..]).to_string();
                (ot, ha, name)
            } else {
                let name = String::from_utf8_lossy(&tlv.value).to_string();
                (OathType::Totp, HashAlgorithm::Sha1, name)
            };

            // Touch property is indicated if high bits set or separate property tag
            let touch_required = (first_byte & 0x08) != 0;

            accounts.push(OathAccountSummary {
                name: name_str,
                oath_type,
                algorithm: alg,
                touch_required,
            });
        }
    }

    Ok(accounts)
}

/// Calculates the one-time code for a given account.
pub fn calculate_code(
    transport: &mut dyn TokenTransport,
    name: &str,
    timestamp: Option<u64>,
    period: u32,
    password_opt: Option<&str>,
) -> Result<CalculatedCode, String> {
    let applet = select_oath(transport)?;
    authenticate_session(transport, &applet, password_opt)?;

    let now_secs = timestamp.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    });

    let counter = now_secs / (period as u64);
    let chal_bytes = counter.to_be_bytes();

    let mut data_tlvs = Vec::new();
    data_tlvs.push(Tlv::new(tags::TAG_NAME, name.as_bytes().to_vec()));
    data_tlvs.push(Tlv::new(tags::TAG_CHALLENGE, chal_bytes.to_vec()));
    let payload = crate::tlv::encode_tlvs(&data_tlvs);

    // INS 0xA2 (Cryptick CALCULATE)
    let calc_apdu = CommandApdu::with_data(0x00, 0xA2, 0x00, 0x00, payload.clone());
    let mut resp_bytes = transport.transceive(0x63, &calc_apdu.to_bytes(), OATH_UV_TIMEOUT)?;
    let mut resp = ResponseApdu::parse(&resp_bytes)?;

    // Fallback to INS 0x06 (YKOATH standard CALCULATE) if 0xA2 returns INS_NOT_SUPPORTED
    if resp.sw == StatusWord::INS_NOT_SUPPORTED || resp.sw == StatusWord::FUNCTION_NOT_SUPPORTED {
        let calc_v2 = CommandApdu::with_data(0x00, 0x06, 0x00, 0x00, payload);
        resp_bytes = transport.transceive(0x63, &calc_v2.to_bytes(), OATH_UV_TIMEOUT)?;
        resp = ResponseApdu::parse(&resp_bytes)?;
    }

    if resp.sw == StatusWord::CONDITIONS_NOT_SATISFIED {
        return Err("User verification timed out or was cancelled (touch sensor).".to_string());
    }
    if resp.sw == StatusWord::SECURITY_STATUS_NOT_SATISFIED {
        return Err("Touch sensor interaction required to approve calculation.".to_string());
    }
    if resp.sw == StatusWord::NOT_FOUND || resp.sw == StatusWord::REFERENCED_DATA_NOT_FOUND {
        return Err(format!("Account '{name}' not found on token."));
    }

    resp.check_success()?;

    let tlvs = Tlv::parse_all(&resp.data)?;

    let mut code_str = None;
    let mut remaining = None;
    let mut touch_required = false;

    for tlv in tlvs {
        if tlv.tag == tags::TAG_RESPONSE || tlv.tag == tags::TAG_TRUNCATED {
            if tlv.value.len() >= 5 {
                // First byte is digits (e.g. 6 or 8), next 4 bytes is code integer
                let digits = tlv.value[0] as usize;
                let code_int = u32::from_be_bytes([tlv.value[1], tlv.value[2], tlv.value[3], tlv.value[4]]);
                let divisor = 10u32.pow(digits as u32);
                let truncated = code_int % divisor;
                code_str = Some(format!("{:0width$}", truncated, width = digits));
            } else if tlv.value.len() == 4 {
                let code_int = u32::from_be_bytes([tlv.value[0], tlv.value[1], tlv.value[2], tlv.value[3]]);
                let truncated = code_int % 1_000_000;
                code_str = Some(format!("{:06}", truncated));
            }
        } else if tlv.tag == tags::TAG_PROPERTY {
            if let Some(&rem) = tlv.value.first() {
                remaining = Some(rem as u32);
            }
        } else if tlv.tag == tags::TAG_TOUCH {
            touch_required = true;
        }
    }

    let code = code_str.ok_or_else(|| "Token response missing OTP code payload".to_string())?;
    let remaining_seconds = remaining.or_else(|| {
        let elapsed = (now_secs % (period as u64)) as u32;
        Some(period.saturating_sub(elapsed))
    });

    Ok(CalculatedCode {
        name: name.to_string(),
        code,
        remaining_seconds,
        touch_required,
    })
}

/// Options for enrolling a new account on token.
#[derive(Debug, Clone)]
pub struct AddAccountOptions {
    /// Account label (e.g. `GitHub:alice`).
    pub name: String,
    /// Raw binary secret seed.
    pub secret: Vec<u8>,
    /// OATH type (TOTP or HOTP).
    pub oath_type: OathType,
    /// Hash algorithm.
    pub algorithm: HashAlgorithm,
    /// Digits (6 or 8).
    pub digits: u32,
    /// Period in seconds for TOTP (default 30).
    pub period: u32,
    /// Initial counter value for HOTP.
    pub counter: u64,
    /// Require user presence (biometric touch) to calculate codes.
    pub touch: bool,
}

/// Enrolls a new OATH account on the token via `PUT` (`INS 0x01`).
pub fn put_account(
    transport: &mut dyn TokenTransport,
    opts: AddAccountOptions,
    password_opt: Option<&str>,
) -> Result<(), String> {
    let applet = select_oath(transport)?;
    authenticate_session(transport, &applet, password_opt)?;

    let mut tlvs = Vec::new();

    // 1. TAG_NAME (0x71)
    tlvs.push(Tlv::new(tags::TAG_NAME, opts.name.as_bytes().to_vec()));

    // 2. TAG_KEY (0x73): [algo_byte] [digits] [secret...]
    let algo_byte = opts.algorithm.to_algo_byte(opts.oath_type);
    let mut key_val = Vec::with_capacity(2 + opts.secret.len());
    key_val.push(algo_byte);
    key_val.push(opts.digits as u8);
    key_val.extend_from_slice(&opts.secret);
    tlvs.push(Tlv::new(tags::TAG_KEY, key_val));

    // 3. TAG_PROPERTY (0x78): Bit 0 / 0x02 = Touch Required
    if opts.touch {
        tlvs.push(Tlv::new(tags::TAG_PROPERTY, vec![0x02]));
    }

    // 4. TAG_IMF (0x7A): Initial counter for HOTP
    if opts.oath_type == OathType::Hotp {
        let cnt_bytes = (opts.counter as u32).to_be_bytes();
        tlvs.push(Tlv::new(tags::TAG_IMF, cnt_bytes.to_vec()));
    }

    let payload = crate::tlv::encode_tlvs(&tlvs);
    let put_apdu = CommandApdu::with_data(0x00, 0x01, 0x00, 0x00, payload);
    let resp_bytes = transport.transceive(0x63, &put_apdu.to_bytes(), OATH_TIMEOUT)?;
    let resp = ResponseApdu::parse(&resp_bytes)?;

    if resp.sw == StatusWord::MEMORY_FULL {
        return Err("Cannot add account: token flash storage is full.".to_string());
    }
    resp.check_success()?;

    Ok(())
}

/// Deletes an account from the token.
pub fn delete_account(
    transport: &mut dyn TokenTransport,
    name: &str,
    password_opt: Option<&str>,
) -> Result<(), String> {
    let applet = select_oath(transport)?;
    authenticate_session(transport, &applet, password_opt)?;

    let tlv = Tlv::new(tags::TAG_NAME, name.as_bytes().to_vec());
    let payload = tlv.encode();

    // Try INS 0x02 (YKOATH standard DELETE) first
    let del_apdu = CommandApdu::with_data(0x00, 0x02, 0x00, 0x00, payload.clone());
    let mut resp_bytes = transport.transceive(0x63, &del_apdu.to_bytes(), OATH_TIMEOUT)?;
    let mut resp = ResponseApdu::parse(&resp_bytes)?;

    // Fallback to INS 0x03 if 0x02 returns INS_NOT_SUPPORTED (per docs/OATH_SPEC.md §3.4)
    if resp.sw == StatusWord::INS_NOT_SUPPORTED || resp.sw == StatusWord::FUNCTION_NOT_SUPPORTED {
        let del_v2 = CommandApdu::with_data(0x00, 0x03, 0x00, 0x00, payload);
        resp_bytes = transport.transceive(0x63, &del_v2.to_bytes(), OATH_TIMEOUT)?;
        resp = ResponseApdu::parse(&resp_bytes)?;
    }

    if resp.sw == StatusWord::NOT_FOUND || resp.sw == StatusWord::REFERENCED_DATA_NOT_FOUND {
        return Err(format!("Account '{name}' not found on token."));
    }

    resp.check_success()?;
    Ok(())
}

/// Renames an account on the token.
pub fn rename_account(
    transport: &mut dyn TokenTransport,
    old_name: &str,
    new_name: &str,
    password_opt: Option<&str>,
) -> Result<(), String> {
    let applet = select_oath(transport)?;
    authenticate_session(transport, &applet, password_opt)?;

    // Attempt token-side rename instruction (INS 0x0A)
    let mut tlvs = Vec::new();
    tlvs.push(Tlv::new(tags::TAG_NAME, old_name.as_bytes().to_vec()));
    tlvs.push(Tlv::new(tags::TAG_NAME_LIST, new_name.as_bytes().to_vec()));
    let payload = crate::tlv::encode_tlvs(&tlvs);

    let rename_apdu = CommandApdu::with_data(0x00, 0x0A, 0x00, 0x00, payload);
    if let Ok(resp_bytes) = transport.transceive(0x63, &rename_apdu.to_bytes(), OATH_TIMEOUT) {
        if let Ok(resp) = ResponseApdu::parse(&resp_bytes) {
            if resp.is_success() {
                return Ok(());
            }
        }
    }

    // If hardware does not implement in-place rename, inform the user about the Zero-Trust guarantee
    Err(format!(
        "Cryptick Token hardware does not support modifying encrypted seeds in-place without secret seed re-entry.\n\
         Under the Zero-Trust Hardware Guarantee, seeds stored in encrypted LittleFS flash cannot be exported by the host.\n\
         To rename, re-add the credential with the new name using 'ykman oath accounts add' or import from URI."
    ))
}

/// Resets the OATH application, wiping all enrolled accounts and clearing access password.
pub fn reset_oath(transport: &mut dyn TokenTransport) -> Result<(), String> {
    let _ = select_oath(transport)?;

    // INS 0x04 = RESET
    let reset_apdu = CommandApdu::new(0x00, 0x04, 0x00, 0x00);
    let resp_bytes = transport.transceive(0x63, &reset_apdu.to_bytes(), OATH_TIMEOUT)?;
    let resp = ResponseApdu::parse(&resp_bytes)?;
    resp.check_success()?;

    // Forget any remembered access keys
    let _ = crate::access::forget_all_keys();

    Ok(())
}

/// Sets, changes, or clears the OATH application access password.
pub fn set_access_password(
    transport: &mut dyn TokenTransport,
    current_pwd_opt: Option<&str>,
    new_pwd_opt: Option<&str>,
    remember: bool,
) -> Result<(), String> {
    let applet = select_oath(transport)?;
    authenticate_session(transport, &applet, current_pwd_opt)?;

    let mut tlvs = Vec::new();

    if let Some(new_pwd) = new_pwd_opt {
        if new_pwd.is_empty() {
            return Err("New password cannot be empty (use '--clear' to remove password)".to_string());
        }
        let derived_key = derive_access_key(new_pwd, &applet.device_id);
        // TAG_KEY (0x73): 16-byte derived key
        tlvs.push(Tlv::new(tags::TAG_KEY, derived_key.to_vec()));

        if remember {
            remember_key(&applet.device_id, &derived_key)?;
        }
    } else {
        // Clearing password: Tag 0x73 with empty/zero bytes
        tlvs.push(Tlv::new(tags::TAG_KEY, Vec::new()));
        let _ = crate::access::forget_key(&applet.device_id);
    }

    let payload = crate::tlv::encode_tlvs(&tlvs);
    // INS 0x03 = SET CODE
    let set_code_apdu = CommandApdu::with_data(0x00, 0x03, 0x00, 0x00, payload);
    let resp_bytes = transport.transceive(0x63, &set_code_apdu.to_bytes(), OATH_TIMEOUT)?;
    let resp = ResponseApdu::parse(&resp_bytes)?;
    resp.check_success()?;

    Ok(())
}
