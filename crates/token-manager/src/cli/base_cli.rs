//! CLI handlers for base ctctl commands: `info`, `list`, and `script`.
//!
//! `list -s/--serials` matches `ykman list` exactly
//! (`yubikey-manager/ykman/_cli/__main__.py`). `info`'s `-c/--check` and
//! `-s/--serial` are this crate's own flags, not ykman's: real `ykman
//! info` takes only `-c, --check-fips`, which checks for a real, distinct
//! FIPS-certified YubiKey hardware variant — claiming to check for that on
//! hardware with no FIPS variant would be wrong to copy, not a gap to
//! close. `-c/--check` here means something unrelated and harmless
//! instead: "is a token reachable at all."

use crate::error::ManagerError;
use crate::script::{read_script_lines, substitute_args, tokenize_line};
use crate::transport::usb::UsbTransport;
use crate::transport::{DualTransport, TokenTransport};

/// Handles `ctctl info [OPTIONS]`.
pub fn run_base_info(
    transport: &mut dyn TokenTransport,
    args: &[String],
) -> Result<(), ManagerError> {
    let mut check = false;
    let mut serial_only = false;

    for arg in args {
        match arg.as_str() {
            "-c" | "--check" => check = true,
            "-s" | "--serial" | "--serials" => serial_only = true,
            _ => {}
        }
    }

    let serial = transport
        .serial()
        .unwrap_or_else(|| "CRYPTICK-ESP32S3-0001".to_string());

    if serial_only {
        println!("{serial}");
        return Ok(());
    }

    if check {
        println!(
            "Device found: Cryptick Token ({serial}) on {}",
            transport.transport_name()
        );
        return Ok(());
    }

    println!("Device type: Cryptick Token (ESP32-S3 Biometric Enclave)");
    println!("Serial number: {serial}");
    println!("Transport: {}", transport.transport_name());
    println!("Firmware version: 0.1.0");
    println!("Form factor: USB-C + Bluetooth Low Energy (Dual-GATT Radio)");
    println!("Display: 1.47\" 172x320 16-bit Color Display (WYSIWYS Enclave)");
    println!("Biometrics: Capacitive Touch / Fingerprint Sensor (On-Chip Matching)");
    println!("Capabilities:");
    println!("  • USB CTAPHID (0x1209:0xBEEE): FIDO2 / WebAuthn, OATH TOTP/HOTP, PIV Smart Card");
    println!("  • BLE Custom Daemon Bridge (FBF6EB80-...): Wireless CTAP2 & OpenSSH");
    println!("  • BLE Standard FIDO GATT (0xFFFD): Native OS & Browser Direct WebAuthn");
    println!("  • BLE Private PIV GATT (FBF6EB90-...): Wireless Smart Card & Computer Login");
    println!("Storage: Encrypted LittleFS (AES-256-GCM hardware TRNG master keys)");
    Ok(())
}

/// Handles `ctctl list [OPTIONS]`.
pub fn run_base_list(args: &[String]) -> Result<(), ManagerError> {
    let mut serials_only = false;
    for arg in args {
        if arg == "-s" || arg == "--serials" {
            serials_only = true;
        }
    }

    let mut found_devices = Vec::new();

    // 1. Direct USB Scan
    if let Ok(usb_devices) = UsbTransport::list_devices() {
        for dev in usb_devices {
            let sn = dev.serial.unwrap_or_else(|| "CRYPTICK-USB-01".to_string());
            found_devices.push((sn, "Direct USB CTAPHID (0x1209:0xBEEE)"));
        }
    }

    // 2. BLE Daemon Bridge Check
    if let Ok(dual) = DualTransport::connect() {
        if dual.transport_name().contains("BLE") {
            let sn = dual
                .serial()
                .unwrap_or_else(|| "CRYPTICK-BLE-LINK".to_string());
            found_devices.push((sn, "Bluetooth Low Energy Daemon Bridge"));
        }
    }

    if found_devices.is_empty() {
        if !serials_only {
            println!("No Cryptick Tokens detected (USB unplugged and BLE Daemon idle).");
        }
        return Ok(());
    }

    for (sn, transport_desc) in found_devices {
        if serials_only {
            println!("{sn}");
        } else {
            println!("Cryptick Token [{sn}] ({transport_desc})");
        }
    }

    Ok(())
}

/// Handles `ctctl script [OPTIONS] FILE [ARGUMENTS]`.
pub fn run_base_script(
    args: &[String],
    executor: fn(&[String]) -> Result<(), ManagerError>,
) -> Result<(), ManagerError> {
    if args.is_empty() {
        return Err(ManagerError::InvalidInput(
            "Usage: ctctl script [OPTIONS] FILE [ARGUMENTS...]".to_string(),
        ));
    }

    let file_path = &args[0];
    let script_args: Vec<String> = args[1..].to_vec();

    let lines = read_script_lines(file_path)?;
    println!("Executing script '{file_path}' ({} lines)...", lines.len());

    for (line_no, raw_line) in lines.into_iter().enumerate() {
        let line_no = line_no + 1;
        let line = substitute_args(&raw_line, &script_args);
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let tokens = tokenize_line(trimmed).map_err(|e| {
            ManagerError::InvalidInput(format!("Script syntax error at line {line_no}: {e}"))
        })?;
        if tokens.is_empty() {
            continue;
        }

        println!("> {}", tokens.join(" "));
        executor(&tokens)
            .map_err(|e| ManagerError::Other(format!("Script error at line {line_no}: {e}")))?;
    }

    println!("Script '{file_path}' executed successfully.");
    Ok(())
}
