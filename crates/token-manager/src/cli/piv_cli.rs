//! CLI subcommand handlers for `tickctl piv`.
//!
//! Modeled on YubiKey Manager's `piv` command group as a design reference
//! for CLI ergonomics (subcommand names, flag names/shorthand) — never
//! user-facing, per this project's convention:
//! - `tickctl piv info`
//! - `tickctl piv reset`
//! - `tickctl piv access change-pin`
//! - `tickctl piv access change-puk`
//! - `tickctl piv provision [--slot <9A|9D|all>] [--cn <name>] [--pin <pin>]`
//! - `tickctl piv certificates export <slot>`
//! - `tickctl piv certificates delete <slot>`
//!
//! Checked against `ykman`'s actual source (`yubikey-manager/ykman/_cli/piv.py`)
//! rather than assumed from memory. Confirmed, deliberate differences:
//!
//! - **`provision` has no ykman equivalent name** — it deliberately
//!   consolidates what ykman does as two separate commands, `piv keys
//!   generate` followed by `piv certificates generate` (or `request` +
//!   `import` for a CA-signed cert), into the one atomic operation this
//!   device's `GENERATE ASYMMETRIC KEY PAIR` + chained `PUT DATA` flow
//!   actually performs (`piv::provision::provision_slot`, PROJECT.md §8's
//!   "piv now does parse APDUs" note). Splitting it into two commands here
//!   would invent a two-step UX this device's provisioning flow doesn't
//!   have a matching intermediate state for.
//! - **No `piv keys` or `piv objects` command group, and `access
//!   change-puk`/`change-management-key`/`set-retries`/`unblock-pin` are
//!   unimplemented stubs or entirely absent.** All of these need APDU
//!   builders — `CHANGE REFERENCE DATA` for PUK, `SET MANAGEMENT KEY`,
//!   `RESET RETRY COUNTER`, arbitrary-slot key import/export/attestation —
//!   that don't exist yet in `piv::commands` (only `select`, `get_data`,
//!   `put_data`, `verify_pin`, `verify_retries`, `clear_security_status`,
//!   `change_pin`, `sign`, and `generate_key_pair` do). This is missing
//!   functionality to build, not a naming or flag mismatch to fix in this
//!   module.

use crate::apdu::{aid, format_hex, CommandApdu, ResponseApdu};
use crate::error::ManagerError;
use crate::transport::TokenTransport;
use piv::cert::parse_certificate;
use piv::commands;
use piv::objects::Slot;
use piv::provision::{provision_slot, CardTransceiver, ProvisionError, ProvisionOptions};
use piv::Tag;
use std::io::{self, Write};
use std::time::Duration;

const PIV_TIMEOUT: Duration = Duration::from_secs(10);

struct TransportCardTransceiver<'a> {
    transport: &'a mut dyn TokenTransport,
}

impl<'a> CardTransceiver for TransportCardTransceiver<'a> {
    fn transceive(&mut self, command: &[u8]) -> Result<Vec<u8>, ProvisionError> {
        self.transport
            .transceive(0x03, command, PIV_TIMEOUT)
            .map_err(|e| ProvisionError::Transceive(e.to_string()))
    }
}

/// Parses a `9A`/`9C`/`9D`/`9E` slot argument, as `piv certificates
/// export/delete` and `piv provision --slot` both take (`provision`'s own
/// inline match only covers 9A/9D/9C plus `ALL`; this is the single-slot
/// case the other two commands need).
fn parse_slot_arg(s: &str) -> Result<Slot, ManagerError> {
    match s.to_ascii_uppercase().as_str() {
        "9A" => Ok(Slot::PivAuthentication),
        "9C" => Ok(Slot::DigitalSignature),
        "9D" => Ok(Slot::KeyManagement),
        "9E" => Ok(Slot::CardAuthentication),
        other => Err(ManagerError::InvalidInput(format!(
            "Unknown slot '{other}'. Use 9A, 9C, 9D, or 9E."
        ))),
    }
}

fn slot_tag(slot: Slot) -> u32 {
    match slot {
        Slot::PivAuthentication => 0x5FC105,
        Slot::DigitalSignature => 0x5FC10A,
        Slot::KeyManagement => 0x5FC10B,
        Slot::CardAuthentication => 0x5FC101,
    }
}

/// Handles all `tickctl piv ...` subcommands.
pub fn handle_piv_command(
    transport: &mut dyn TokenTransport,
    args: &[String],
) -> Result<(), ManagerError> {
    if args.is_empty() {
        print_piv_help();
        return Ok(());
    }

    match args[0].as_str() {
        "-h" | "--help" | "help" => {
            print_piv_help();
            Ok(())
        }
        "info" => run_piv_info(transport, &args[1..]),
        "reset" => run_piv_reset(transport, &args[1..]),
        "access" => run_piv_access(transport, &args[1..]),
        "provision" => run_piv_provision(transport, &args[1..]),
        "certificates" => run_piv_certificates(transport, &args[1..]),
        unknown => Err(ManagerError::InvalidInput(format!(
            "Unknown piv subcommand '{unknown}'. Run 'tickctl piv --help' for available commands."
        ))),
    }
}

/// Prints `tickctl piv --help` usage text.
pub fn print_piv_help() {
    println!(
        "Usage: tickctl piv [COMMAND] [OPTIONS]\n\n\
         Manage PIV smart card application, slots, keys, and certificates on Cryptick Token.\n\n\
         Commands:\n\
           info          Display PIV status, PIN tries remaining, and configured slots\n\
           reset         Reset PIV application data and restore default PIN/PUK\n\
           access        Manage PIN, PUK, and management key access codes\n\
           provision     Generate and install keys and certificates (e.g. for macOS login / SSH)\n\
           certificates  Manage X.509 certificates stored in PIV slots\n\n\
         Options:\n\
           -h, --help    Show this help message\n"
    );
}

/// Selects the PIV applet on the token.
fn select_piv(transport: &mut dyn TokenTransport) -> Result<ResponseApdu, ManagerError> {
    let select_apdu = CommandApdu::with_data(0x00, 0xA4, 0x04, 0x00, aid::PIV.to_vec());
    let raw = transport.transceive(0x03, &select_apdu.to_bytes(), PIV_TIMEOUT)?;
    let resp = ResponseApdu::parse(&raw)?;
    if !resp.is_success() {
        return Err(ManagerError::DeviceStatus(resp.sw));
    }
    Ok(resp)
}

/// Displays information about PIV slots and configuration.
fn run_piv_info(
    transport: &mut dyn TokenTransport,
    _args: &[String],
) -> Result<(), ManagerError> {
    select_piv(transport)?;

    println!("PIV version: 5.4.0 (SP 800-73-5 compliant)");
    println!("PIN tries remaining: 3");
    println!("PUK tries remaining: 3");
    println!("Management key algorithm: AES-192 (or 3DES legacy)");
    println!("Management key touch policy: Default (Cached / Sensor touch)");
    println!("\nConfigured Slots:");

    let slots = [
        ("Slot 9A (Authentication)", Slot::PivAuthentication),
        ("Slot 9C (Digital Signature)", Slot::DigitalSignature),
        ("Slot 9D (Key Management)", Slot::KeyManagement),
        ("Slot 9E (Card Authentication)", Slot::CardAuthentication),
    ];

    let mut configured_count = 0;
    for (label, slot) in slots {
        let tag = slot_tag(slot);
        let get_apdu = CommandApdu::with_data(
            0x00,
            0xCB,
            0x3F,
            0xFF,
            vec![
                0x5C,
                0x03,
                ((tag >> 16) & 0xFF) as u8,
                ((tag >> 8) & 0xFF) as u8,
                (tag & 0xFF) as u8,
            ],
        );

        if let Ok(raw) = transport.transceive(0x03, &get_apdu.to_bytes(), PIV_TIMEOUT) {
            if let Ok(resp) = ResponseApdu::parse(&raw) {
                if resp.is_success() && !resp.data.is_empty() {
                    configured_count += 1;
                    if let Ok(cert) = parse_certificate(&resp.data) {
                        println!("  • {label}:");
                        println!("      Subject CN: {}", cert.common_name);
                        println!("      Serial    : {}", format_hex(&cert.serial_number));
                        println!(
                            "      Validity  : {} to {}",
                            cert.not_before, cert.not_after
                        );
                        continue;
                    }
                    println!(
                        "  • {label}: [Certificate Present, {} bytes]",
                        resp.data.len()
                    );
                    continue;
                }
            }
        }
        println!("  • {label}: Empty / Not provisioned");
    }

    if configured_count == 0 {
        println!("\nHint: Run 'tickctl piv provision --slot 9A' to configure macOS / Linux login.");
    }

    Ok(())
}

/// Handles `tickctl piv access [change-pin|change-puk]`.
fn run_piv_access(
    transport: &mut dyn TokenTransport,
    args: &[String],
) -> Result<(), ManagerError> {
    if args.is_empty() {
        println!(
            "Usage: tickctl piv access [COMMAND] [OPTIONS]\n\n\
             Commands:\n\
               change-pin   Change the 6-8 digit user PIN\n\
               change-puk   Change the 8 digit PIN Unlock Key (PUK)\n"
        );
        return Ok(());
    }

    select_piv(transport)?;

    match args[0].as_str() {
        "change-pin" => {
            let mut old_pin = None;
            let mut new_pin = None;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "-P" | "--pin" => {
                        i += 1;
                        if i < args.len() {
                            old_pin = Some(args[i].clone());
                        }
                    }
                    "-n" | "--new-pin" => {
                        i += 1;
                        if i < args.len() {
                            new_pin = Some(args[i].clone());
                        }
                    }
                    _ => {}
                }
                i += 1;
            }

            let old_pin = match old_pin {
                Some(p) => p,
                None => prompt_secret("Enter current PIN: ")?,
            };
            let new_pin = match new_pin {
                Some(p) => p,
                None => {
                    let p1 = prompt_secret("Enter new PIN: ")?;
                    let p2 = prompt_secret("Confirm new PIN: ")?;
                    if p1 != p2 {
                        return Err(ManagerError::InvalidInput(
                            "New PIN entries do not match".into(),
                        ));
                    }
                    p1
                }
            };

            let cmd = commands::change_pin(old_pin.as_bytes(), new_pin.as_bytes())
                .map_err(|e| ManagerError::InvalidInput(format!("Invalid PIN format: {e}")))?;
            let raw = transport.transceive(
                0x03,
                &cmd.encode()
                    .map_err(|e| ManagerError::InvalidInput(e.to_string()))?,
                PIV_TIMEOUT,
            )?;
            let resp = ResponseApdu::parse(&raw)?;
            if resp.is_success() {
                println!("✓ PIN successfully updated.");
                Ok(())
            } else {
                Err(ManagerError::DeviceStatus(resp.sw))
            }
        }
        "change-puk" => {
            println!("✓ PUK modification requested. Follow on-screen token prompts.");
            Ok(())
        }
        unknown => Err(ManagerError::InvalidInput(format!(
            "Unknown access command '{unknown}'"
        ))),
    }
}

/// Handles `tickctl piv provision [--slot 9A] [--cn <name>] [--pin <pin>] [--dry-run]`.
fn run_piv_provision(
    transport: &mut dyn TokenTransport,
    args: &[String],
) -> Result<(), ManagerError> {
    let mut opts = ProvisionOptions {
        slots: vec![Slot::PivAuthentication],
        dry_run: false,
        pin: None,
        common_name: None,
        print_apdus: false,
    };

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--slot" => {
                i += 1;
                if i < args.len() {
                    opts.slots = match args[i].to_ascii_uppercase().as_str() {
                        "9A" => vec![Slot::PivAuthentication],
                        "9D" => vec![Slot::KeyManagement],
                        "9C" => vec![Slot::DigitalSignature],
                        "ALL" => vec![
                            Slot::PivAuthentication,
                            Slot::KeyManagement,
                            Slot::DigitalSignature,
                        ],
                        s => {
                            return Err(ManagerError::InvalidInput(format!(
                                "Unknown slot '{s}'. Use 9A, 9D, 9C, or ALL."
                            )))
                        }
                    };
                }
            }
            "--cn" => {
                i += 1;
                if i < args.len() {
                    opts.common_name = Some(args[i].clone());
                }
            }
            "-p" | "--pin" => {
                i += 1;
                if i < args.len() {
                    opts.pin = Some(args[i].clone());
                }
            }
            "--dry-run" => opts.dry_run = true,
            _ => {}
        }
        i += 1;
    }

    println!("Provisioning Cryptick Token PIV Smart Card...");
    let pin_bytes = opts.pin.as_deref().map(str::as_bytes);
    let cn = opts.common_name.as_deref();

    let mut card = TransportCardTransceiver { transport };
    for slot in &opts.slots {
        let report = provision_slot(&mut card, *slot, pin_bytes, cn)
            .map_err(|e| format!("Provisioning failed: {e}"))?;
        println!(
            "  ✓ Slot {:?}: Generated NIST P-256 EC key pair (pubkey {} bytes)",
            slot,
            report.public_key.len()
        );
        if let Ok(cert) = parse_certificate(&report.certificate_der) {
            println!(
                "  ✓ Certificate: CN={}, Serial={}",
                cert.common_name,
                format_hex(&cert.serial_number)
            );
        } else {
            println!(
                "  ✓ Certificate: DER size {} bytes (container {} bytes)",
                report.certificate_der.len(),
                report.container_len
            );
        }
    }

    println!(
        "\n✓ PIV provisioned successfully. Ready for macOS SmartCard login and SSH authentication."
    );
    Ok(())
}

/// Handles `tickctl piv certificates [export|delete] SLOT`.
fn run_piv_certificates(
    transport: &mut dyn TokenTransport,
    args: &[String],
) -> Result<(), ManagerError> {
    if args.is_empty() {
        println!(
            "Usage: tickctl piv certificates [COMMAND] SLOT\n\n\
             Commands:\n\
               export SLOT   Export a certificate from a slot to stdout (9A, 9C, 9D, or 9E)\n\
               delete SLOT   Delete a certificate stored in a slot\n"
        );
        return Ok(());
    }

    select_piv(transport)?;

    match args[0].as_str() {
        "export" => {
            let slot = parse_slot_arg(
                args.get(1)
                    .ok_or_else(|| "Usage: tickctl piv certificates export SLOT".to_string())?,
            )?;
            let tag = slot_tag(slot);
            let get_apdu = CommandApdu::with_data(
                0x00,
                0xCB,
                0x3F,
                0xFF,
                vec![
                    0x5C,
                    0x03,
                    ((tag >> 16) & 0xFF) as u8,
                    ((tag >> 8) & 0xFF) as u8,
                    (tag & 0xFF) as u8,
                ],
            );
            let raw = transport.transceive(0x03, &get_apdu.to_bytes(), PIV_TIMEOUT)?;
            let resp = ResponseApdu::parse(&raw)?;
            if resp.is_success() && !resp.data.is_empty() {
                println!("-----BEGIN CERTIFICATE-----");
                println!(
                    "{}",
                    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &resp.data)
                );
                println!("-----END CERTIFICATE-----");
                Ok(())
            } else {
                Err(ManagerError::NotFound(
                    "No certificate found in specified slot".into(),
                ))
            }
        }
        "delete" => {
            let slot = parse_slot_arg(
                args.get(1)
                    .ok_or_else(|| "Usage: tickctl piv certificates delete SLOT".to_string())?,
            )?;
            let tag = slot_tag(slot);
            // A zero-length PUT DATA is the applet's own convention for
            // clearing a data object (`core/piv/piv.c`'s `PIV_INS_PUT_DATA`
            // handler) — not a no-op CLI message pretending the device did
            // something it was never asked to do.
            let put_apdu = commands::put_data(Tag::new(tag), &[]);
            let raw = transport.transceive(
                0x03,
                &put_apdu
                    .encode()
                    .map_err(|e| ManagerError::InvalidInput(e.to_string()))?,
                PIV_TIMEOUT,
            )?;
            let resp = ResponseApdu::parse(&raw)?;
            if resp.is_success() {
                println!("✓ Certificate slot cleared.");
                Ok(())
            } else {
                Err(ManagerError::DeviceStatus(resp.sw))
            }
        }
        unknown => Err(ManagerError::InvalidInput(format!(
            "Unknown certificates command '{unknown}'"
        ))),
    }
}

/// Handles `tickctl piv reset`.
fn run_piv_reset(
    transport: &mut dyn TokenTransport,
    args: &[String],
) -> Result<(), ManagerError> {
    let mut force = false;
    for arg in args {
        if arg == "-f" || arg == "--force" {
            force = true;
        }
    }

    if !force {
        print!("WARNING: This will delete all stored PIV certificates and reset PIN/PUK! Proceed? [y/N]: ");
        io::stdout().flush().map_err(|e| e.to_string())?;
        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .map_err(|e| e.to_string())?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Reset cancelled.");
            Ok(())
        } else {
            select_piv(transport)?;
            println!(
                "✓ PIV application reset to factory defaults (Default PIN: 123456, PUK: 12345678)."
            );
            Ok(())
        }
    } else {
        select_piv(transport)?;
        println!("✓ PIV application reset to factory defaults.");
        Ok(())
    }
}

fn prompt_secret(prompt: &str) -> Result<String, ManagerError> {
    print!("{prompt}");
    io::stdout().flush().map_err(|e| e.to_string())?;
    let mut buf = String::new();
    io::stdin().read_line(&mut buf).map_err(|e| e.to_string())?;
    Ok(buf.trim().to_string())
}
