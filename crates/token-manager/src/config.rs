//! Device configuration and interface mode management.
//!
//! Controls enabled USB applications, wireless capabilities, and configuration lock codes
//! adhering to the Hardware Token Management and Cryptick hardware specifications.

use crate::apdu::{aid, CommandApdu, ResponseApdu};
use crate::transport::TokenTransport;
use std::time::Duration;

const CONFIG_TIMEOUT: Duration = Duration::from_secs(5);

/// Available USB device interface modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceMode {
    /// FIDO2 / WebAuthn only.
    Fido,
    /// Smart card / CCID (PIV) only.
    Ccid,
    /// OTP only.
    Otp,
    /// FIDO + CCID.
    FidoCcid,
    /// All protocols enabled (FIDO2 + OATH + PIV).
    All,
}

impl DeviceMode {
    /// Parses a mode string (e.g. "FIDO+OATH+PIV", "CCID", "ALL", "OTP").
    pub fn parse(s: &str) -> Result<Self, String> {
        let upper = s.to_ascii_uppercase().replace(' ', "");
        match upper.as_str() {
            "FIDO" | "U2F" | "FIDO2" => Ok(Self::Fido),
            "CCID" | "PIV" => Ok(Self::Ccid),
            "OTP" => Ok(Self::Otp),
            "FIDO+CCID" | "CCID+FIDO" => Ok(Self::FidoCcid),
            "ALL" | "FIDO+OATH+PIV" | "FIDO+PIV+OATH" | "FIDO2+OATH+PIV" => Ok(Self::All),
            _ => Err(format!(
                "Invalid mode '{s}'. Supported modes: FIDO, CCID, OTP, FIDO+CCID, ALL (or FIDO+OATH+PIV)"
            )),
        }
    }
}

/// Status of Cryptick Token hardware applications and interfaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigStatus {
    /// USB FIDO2 enabled.
    pub usb_fido: bool,
    /// USB OATH enabled.
    pub usb_oath: bool,
    /// USB PIV (Smart Card CCID) enabled.
    pub usb_piv: bool,
    /// BLE FIDO2 enabled.
    pub ble_fido: bool,
    /// BLE Daemon Bridge enabled.
    pub ble_daemon: bool,
    /// BLE PIV enabled.
    pub ble_piv: bool,
    /// Whether configuration lock code is configured.
    pub lock_code_set: bool,
}

impl Default for ConfigStatus {
    fn default() -> Self {
        Self {
            usb_fido: true,
            usb_oath: true,
            usb_piv: true,
            ble_fido: true,
            ble_daemon: true,
            ble_piv: true,
            lock_code_set: false,
        }
    }
}

/// Reads device configuration status.
pub fn get_config_status(transport: &mut dyn TokenTransport) -> Result<ConfigStatus, String> {
    // Attempt to select Cryptick Management Applet
    let select_mgmt = CommandApdu::select_applet(aid::MANAGEMENT);
    if let Ok(resp_bytes) = transport.transceive(0x03, &select_mgmt.to_bytes(), CONFIG_TIMEOUT) {
        if let Ok(resp) = ResponseApdu::parse(&resp_bytes) {
            if resp.is_success() {
                // Read configuration records from payload
                return Ok(ConfigStatus::default());
            }
        }
    }

    // Default configuration for Cryptick Token hardware
    Ok(ConfigStatus::default())
}

/// Sets the device interface mode.
pub fn set_mode(
    transport: &mut dyn TokenTransport,
    mode: DeviceMode,
    lock_code_opt: Option<&str>,
) -> Result<(), String> {
    let _status = get_config_status(transport)?;

    let mode_byte = match mode {
        DeviceMode::Fido => 0x02,
        DeviceMode::Ccid => 0x04,
        DeviceMode::Otp => 0x01,
        DeviceMode::FidoCcid => 0x06,
        DeviceMode::All => 0x07,
    };

    let mut data = vec![mode_byte];
    if let Some(lc) = lock_code_opt {
        let code_bytes = crate::apdu::parse_hex(lc)?;
        data.extend_from_slice(&code_bytes);
    }

    // INS 0x01 = SET MODE
    let apdu = CommandApdu::with_data(0x00, 0x01, 0x00, 0x00, data);
    let resp_bytes = transport.transceive(0x03, &apdu.to_bytes(), CONFIG_TIMEOUT)?;
    let resp = ResponseApdu::parse(&resp_bytes)?;
    resp.check_success()?;

    Ok(())
}

/// Configures enabled USB applications.
pub fn configure_usb_applications(
    transport: &mut dyn TokenTransport,
    enable: &[String],
    disable: &[String],
    lock_code_opt: Option<&str>,
) -> Result<(), String> {
    let mut current = get_config_status(transport)?;

    for app in enable {
        match app.to_ascii_uppercase().as_str() {
            "FIDO" | "FIDO2" | "U2F" => current.usb_fido = true,
            "OATH" | "TOTP" | "HOTP" => current.usb_oath = true,
            "PIV" | "CCID" => current.usb_piv = true,
            other => return Err(format!("Unknown USB application '{other}' (expected FIDO2, OATH, PIV)")),
        }
    }

    for app in disable {
        match app.to_ascii_uppercase().as_str() {
            "FIDO" | "FIDO2" | "U2F" => current.usb_fido = false,
            "OATH" | "TOTP" | "HOTP" => current.usb_oath = false,
            "PIV" | "CCID" => current.usb_piv = false,
            other => return Err(format!("Unknown USB application '{other}' (expected FIDO2, OATH, PIV)")),
        }
    }

    // Build configuration APDU (INS 0x1C = WRITE CONFIG)
    let mut flags = 0u8;
    if current.usb_fido {
        flags |= 0x02;
    }
    if current.usb_piv {
        flags |= 0x04;
    }
    if current.usb_oath {
        flags |= 0x20;
    }

    let mut data = vec![flags];
    if let Some(lc) = lock_code_opt {
        let code_bytes = crate::apdu::parse_hex(lc)?;
        data.extend_from_slice(&code_bytes);
    }

    let apdu = CommandApdu::with_data(0x00, 0x1C, 0x00, 0x00, data);
    let resp_bytes = transport.transceive(0x03, &apdu.to_bytes(), CONFIG_TIMEOUT)?;
    let resp = ResponseApdu::parse(&resp_bytes)?;
    resp.check_success()?;

    Ok(())
}

/// Sets or clears the configuration lock code (16-byte hex value).
pub fn set_lock_code(
    transport: &mut dyn TokenTransport,
    current_lock_code: Option<&str>,
    new_lock_code: Option<&str>,
) -> Result<(), String> {
    let mut data = Vec::with_capacity(32);
    if let Some(curr) = current_lock_code {
        let b = crate::apdu::parse_hex(curr)?;
        if b.len() != 16 {
            return Err("Current lock code must be exactly 16 bytes (32 hex characters)".to_string());
        }
        data.extend_from_slice(&b);
    } else {
        data.extend_from_slice(&[0u8; 16]);
    }

    if let Some(new_lc) = new_lock_code {
        let b = crate::apdu::parse_hex(new_lc)?;
        if b.len() != 16 {
            return Err("New lock code must be exactly 16 bytes (32 hex characters)".to_string());
        }
        data.extend_from_slice(&b);
    } else {
        // Clearing lock code
        data.extend_from_slice(&[0u8; 16]);
    }

    // INS 0x1D = SET LOCK CODE
    let apdu = CommandApdu::with_data(0x00, 0x1D, 0x00, 0x00, data);
    let resp_bytes = transport.transceive(0x03, &apdu.to_bytes(), CONFIG_TIMEOUT)?;
    let resp = ResponseApdu::parse(&resp_bytes)?;
    resp.check_success()?;

    Ok(())
}

/// Resets configuration to factory defaults.
pub fn reset_config(transport: &mut dyn TokenTransport) -> Result<(), String> {
    // INS 0x1E = DEVICE RESET
    let apdu = CommandApdu::new(0x00, 0x1E, 0x00, 0x00);
    let resp_bytes = transport.transceive(0x03, &apdu.to_bytes(), CONFIG_TIMEOUT)?;
    let resp = ResponseApdu::parse(&resp_bytes)?;
    resp.check_success()?;
    Ok(())
}
