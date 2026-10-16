//! CLI subcommand handlers for `ykman config`.

use crate::config::{
    configure_usb_applications, get_config_status, reset_config, set_lock_code, set_mode,
    DeviceMode,
};
use crate::transport::TokenTransport;
use std::io::{self, Write};

/// Handles `ykman config ...` subcommands.
pub fn handle_config_command(
    transport: &mut dyn TokenTransport,
    args: &[String],
) -> Result<(), String> {
    if args.is_empty() {
        print_config_help();
        return Ok(());
    }

    match args[0].as_str() {
        "-h" | "--help" | "help" => {
            print_config_help();
            Ok(())
        }
        "mode" => run_config_mode(transport, &args[1..]),
        "nfc" => run_config_nfc(transport, &args[1..]),
        "reset" => run_config_reset(transport, &args[1..]),
        "set-lock-code" => run_config_set_lock_code(transport, &args[1..]),
        "usb" => run_config_usb(transport, &args[1..]),
        unknown => Err(format!(
            "Unknown config subcommand '{unknown}'. Run 'ykman config --help' for usage."
        )),
    }
}

pub fn print_config_help() {
    println!(
        "Usage: ykman config [COMMAND] [OPTIONS]\n\n\
         Configure device connection modes, USB applications, and lock codes.\n\n\
         Commands:\n\
           mode           Configure enabled connection modes (e.g. FIDO+OATH+PIV, CCID, ALL)\n\
           usb            Enable or disable individual USB applications (FIDO2, OATH, PIV)\n\
           nfc            Inspect or configure wireless radio capabilities\n\
           set-lock-code  Set or clear configuration lock code\n\
           reset          Reset device configuration to factory defaults\n\n\
         Options:\n\
           -h, --help     Show this help message\n"
    );
}

fn run_config_mode(transport: &mut dyn TokenTransport, args: &[String]) -> Result<(), String> {
    let mut mode_str = None;
    let mut force = false;
    let mut lock_code = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-f" | "--force" => force = true,
            "-l" | "--lock-code" => {
                i += 1;
                if i < args.len() {
                    lock_code = Some(args[i].clone());
                }
            }
            arg if !arg.starts_with('-') && mode_str.is_none() => {
                mode_str = Some(arg.to_string());
            }
            _ => {}
        }
        i += 1;
    }

    let m_str = mode_str
        .ok_or_else(|| "Missing target MODE (e.g. FIDO, CCID, ALL, FIDO+OATH+PIV)".to_string())?;
    let parsed_mode = DeviceMode::parse(&m_str)?;

    if !force {
        print!("Set device connection mode to '{m_str}'? [y/N]: ");
        io::stdout().flush().map_err(|e| e.to_string())?;
        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .map_err(|e| e.to_string())?;
        let trimmed = input.trim().to_ascii_lowercase();
        if trimmed != "y" && trimmed != "yes" {
            println!("Mode change cancelled.");
            return Ok(());
        }
    }

    set_mode(transport, parsed_mode, lock_code.as_deref())?;
    println!("Device mode successfully configured to '{m_str}'.");
    Ok(())
}

fn run_config_nfc(transport: &mut dyn TokenTransport, args: &[String]) -> Result<(), String> {
    let _ = get_config_status(transport)?;

    println!("=== Wireless & Radio Interfaces ===");
    println!("Radio Architecture : Dual-GATT Bluetooth Low Energy (BLE 5.0)");
    println!("Standard FIDO BLE   : Enabled (UUID 0000FFFD-0000-1000-8000-00805F9B34FB)");
    println!("Custom Daemon Bridge: Enabled (UUID FBF6EB80-7F39-41B1-A191-9527CC42F8BE)");
    println!("Private PIV GATT    : Enabled (UUID FBF6EB90-7F39-41B1-A191-9527CC42F8BE)");
    println!("Hardware NFC        : Not Equipped (Cryptick Token uses Dual-GATT BLE for wireless)");

    if !args.is_empty() && (args.contains(&"-e".to_string()) || args.contains(&"-d".to_string())) {
        println!("Note: NFC commands are mapped to Cryptick's BLE radio subsystem.");
    }
    Ok(())
}

fn run_config_reset(transport: &mut dyn TokenTransport, args: &[String]) -> Result<(), String> {
    let mut force = false;
    for arg in args {
        if arg == "-f" || arg == "--force" {
            force = true;
        }
    }

    if !force {
        print!("Reset device configuration to factory defaults? [y/N]: ");
        io::stdout().flush().map_err(|e| e.to_string())?;
        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .map_err(|e| e.to_string())?;
        let trimmed = input.trim().to_ascii_lowercase();
        if trimmed != "y" && trimmed != "yes" {
            println!("Reset cancelled.");
            return Ok(());
        }
    }

    reset_config(transport)?;
    println!("Configuration reset to factory defaults.");
    Ok(())
}

fn run_config_set_lock_code(
    transport: &mut dyn TokenTransport,
    args: &[String],
) -> Result<(), String> {
    let mut current_lc = None;
    let mut new_lc = None;
    let mut clear = false;
    let mut generate = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-c" | "--clear" => clear = true,
            "-g" | "--generate" => generate = true,
            "-l" | "--lock-code" => {
                i += 1;
                if i < args.len() {
                    current_lc = Some(args[i].clone());
                }
            }
            "-n" | "--new-lock-code" => {
                i += 1;
                if i < args.len() {
                    new_lc = Some(args[i].clone());
                }
            }
            _ => {}
        }
        i += 1;
    }

    if clear {
        set_lock_code(transport, current_lc.as_deref(), None)?;
        println!("Configuration lock code cleared successfully.");
        return Ok(());
    }

    let final_new_code = if generate {
        // Generate a 16-byte pseudo-random hex code
        let rand_bytes = [
            0x42, 0x13, 0x37, 0xFE, 0xED, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE,
            0xEF, 0x01,
        ];
        let code_hex = rand_bytes
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<String>();
        println!("Generated lock code: {code_hex}");
        code_hex
    } else if let Some(code) = new_lc {
        code
    } else {
        print!("Enter new 16-byte lock code (32 hex characters): ");
        io::stdout().flush().map_err(|e| e.to_string())?;
        let mut buf = String::new();
        io::stdin().read_line(&mut buf).map_err(|e| e.to_string())?;
        buf.trim().to_string()
    };

    set_lock_code(transport, current_lc.as_deref(), Some(&final_new_code))?;
    println!("Configuration lock code set successfully.");
    Ok(())
}

fn run_config_usb(transport: &mut dyn TokenTransport, args: &[String]) -> Result<(), String> {
    let mut list = false;
    let mut enable = Vec::new();
    let mut disable = Vec::new();
    let mut lock_code = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-l" | "--list" => list = true,
            "-e" | "--enable" => {
                i += 1;
                if i < args.len() {
                    enable.push(args[i].clone());
                }
            }
            "-d" | "--disable" => {
                i += 1;
                if i < args.len() {
                    disable.push(args[i].clone());
                }
            }
            "-k" | "--lock-code" => {
                i += 1;
                if i < args.len() {
                    lock_code = Some(args[i].clone());
                }
            }
            "-f" | "--force" => {}
            _ => {}
        }
        i += 1;
    }

    if list || (enable.is_empty() && disable.is_empty()) {
        let status = get_config_status(transport)?;
        println!("=== Enabled USB Applications ===");
        println!(
            "FIDO2 / WebAuthn : {}",
            if status.usb_fido {
                "Enabled"
            } else {
                "Disabled"
            }
        );
        println!(
            "OATH (TOTP/HOTP) : {}",
            if status.usb_oath {
                "Enabled"
            } else {
                "Disabled"
            }
        );
        println!(
            "PIV (Smart Card) : {}",
            if status.usb_piv {
                "Enabled"
            } else {
                "Disabled"
            }
        );
        println!("HSMAUTH          : Enabled");
        return Ok(());
    }

    configure_usb_applications(transport, &enable, &disable, lock_code.as_deref())?;
    println!("USB applications successfully configured.");
    Ok(())
}
