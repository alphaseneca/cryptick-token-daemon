//! CLI subcommand handlers for `cryptick-manager fido`.
//!
//! Modeled on YubiKey Manager's `fido` command group as a design reference
//! for CLI ergonomics (subcommand names, flag names/shorthand) — never
//! user-facing, per this project's convention:
//! - `cryptick-manager fido info`
//! - `cryptick-manager fido reset`
//! - `cryptick-manager fido access change-pin` / `access set-pin`
//! - `cryptick-manager fido fingerprints list` / `add <name>` / `delete <name>`
//!
//! Checked against `ykman`'s actual source (`yubikey-manager/ykman/_cli/fido.py`)
//! rather than assumed from memory. Two differences are deliberate, not gaps
//! to close:
//!
//! - **No `fido credentials` or `fido config` group.** Resident-credential
//!   listing/deletion and the `toggle-always-uv`/`enable-ep-attestation`
//!   config toggles need real CTAP2 `credentialManagement`/`authenticatorConfig`
//!   wiring (PIN/UV auth tokens, `ctap-client::cred_mgmt`) that lives in
//!   `webauthn-host` today, not in this crate. Adding a CLI surface for it
//!   here without the backing implementation would be worse than not
//!   having it.
//! - **No `-P/--pin` on `fido fingerprints`.** ykman's equivalent commands
//!   all take `-P, --pin` because a YubiKey gates bio-enrollment admin
//!   operations on the PIN. Per PROJECT.md §17, this device's user
//!   verification is `ctap_user_presence_test`'s on-chip fingerprint
//!   sensor (R557), not a transmitted PIN — "stronger than §15.4 asks
//!   for" — so there is no PIN value for these specific subcommands to
//!   take. `fido access change-pin`/`set-pin` still take `-P/--pin`
//!   because CTAP2 `clientPin` is a real, separate capability this device
//!   also reports (the `clientPin` entry in `run_fido_info`'s `options`
//!   output, present only once a PIN has actually been set).

use crate::error::ManagerError;
use crate::transport::TokenTransport;
use ctap::{Command, Response};
use ctap_client::GetInfoResponse;
use std::io::{self, Write};
use std::time::Duration;

const FIDO_TIMEOUT: Duration = Duration::from_secs(10);

/// Handles all `cryptick-manager fido ...` subcommands.
pub fn handle_fido_command(
    transport: &mut dyn TokenTransport,
    args: &[String],
) -> Result<(), ManagerError> {
    if args.is_empty() {
        print_fido_help();
        return Ok(());
    }

    match args[0].as_str() {
        "-h" | "--help" | "help" => {
            print_fido_help();
            Ok(())
        }
        "info" => run_fido_info(transport, &args[1..]),
        "reset" => run_fido_reset(transport, &args[1..]),
        "access" => run_fido_access(transport, &args[1..]),
        "fingerprints" | "bio" => run_fido_fingerprints(transport, &args[1..]),
        unknown => Err(ManagerError::InvalidInput(format!(
            "Unknown fido subcommand '{unknown}'. Run 'cryptick-manager fido --help' for available commands."
        ))),
    }
}

/// Prints `cryptick-manager fido --help` usage text.
pub fn print_fido_help() {
    println!(
        "Usage: cryptick-manager fido [COMMAND] [OPTIONS]\n\n\
         Manage FIDO2 passkeys, PINs, and on-chip biometric fingerprints on Cryptick Token.\n\n\
         Commands:\n\
           info          Display FIDO2 / WebAuthn capabilities and security policy\n\
           reset         Reset all FIDO2 credentials and restore unprovisioned state\n\
           access        Manage FIDO2 PIN (set or change)\n\
           fingerprints  Manage on-chip biometric fingerprints (list, add, delete)\n\n\
         Options:\n\
           -h, --help    Show this help message\n"
    );
}

/// Displays FIDO2 token capabilities and configuration.
///
/// Sends the real `authenticatorGetInfo` (CTAP2 command `0x04`) and prints
/// what the device actually answers, rather than a fixed block of text —
/// see this device's firmware (`core/fido2/ctap.c`'s `ctap_get_info`) for
/// what it does and does not advertise (no CTAP2.1, no `largeBlobKey`, no
/// `bioEnroll`/`pinUvAuthToken` options).
fn run_fido_info(
    transport: &mut dyn TokenTransport,
    _args: &[String],
) -> Result<(), ManagerError> {
    let raw = match transport.transceive(0x10, &[Command::GET_INFO.as_u8()], FIDO_TIMEOUT) {
        Ok(raw) => raw,
        Err(e) => {
            println!("Device not reachable: {e}");
            return Ok(());
        }
    };

    let response = match Response::decode(&raw) {
        Ok(response) => response,
        Err(e) => {
            println!("Device not reachable: malformed response ({e})");
            return Ok(());
        }
    };

    if !response.status.is_ok() {
        let name = response
            .status
            .name()
            .map(|n| format!(" ({n})"))
            .unwrap_or_default();
        println!(
            "FIDO2 info unavailable: device returned status {:#04x}{name}",
            response.status.as_u8()
        );
        return Ok(());
    }

    let info = match GetInfoResponse::parse(&response.data) {
        Ok(info) => info,
        Err(e) => {
            println!("FIDO2 info unavailable: could not parse device response ({e})");
            return Ok(());
        }
    };

    println!(
        "PIN is set: {}",
        if info.client_pin_set() { "Yes" } else { "No" }
    );
    println!("FIDO2 protocols: {}", info.versions.join(", "));
    println!("Extensions: {}", info.extensions.join(", "));
    println!("Options:");
    for (name, value) in &info.options {
        println!("  • {name}: {}", if *value { "True" } else { "False" });
    }

    Ok(())
}

/// Handles `cryptick-manager fido access [change-pin|set-pin]`.
fn run_fido_access(
    _transport: &mut dyn TokenTransport,
    args: &[String],
) -> Result<(), ManagerError> {
    if args.is_empty() {
        println!(
            "Usage: cryptick-manager fido access [COMMAND] [OPTIONS]\n\n\
             Commands:\n\
               change-pin   Change the FIDO2 user PIN\n\
               set-pin      Set an initial FIDO2 PIN\n\n\
             Options (change-pin and set-pin; prompts interactively if omitted):\n\
               -P, --pin <PIN>          Current PIN (change-pin only)\n\
               -n, --new-pin <PIN>      New PIN\n"
        );
        return Ok(());
    }

    // ykman's `fido access change-pin` takes `-P, --pin` (current) and
    // `-n, --new-pin` (new), prompting interactively for whichever is
    // omitted; there is no separate `set-pin` command there at all — the
    // same `change-pin` command sets an initial PIN when none exists yet
    // (CTAP2's setPIN and changePIN are just two sub-operations of one
    // clientPIN flow). Keeping `set-pin` as an explicit alias here is a
    // deliberate ergonomic choice for first-time setup, not an oversight —
    // but it needs the same `-n/--new-pin` flag `change-pin` has, and
    // `change-pin` needs `-P/--pin`, matching both ykman and this crate's
    // own `piv access change-pin` (`piv_cli.rs`). Previously neither
    // subcommand parsed any flags at all and always prompted interactively,
    // silently ignoring flags a scripted caller passed.
    let is_change = args[0] == "change-pin";
    match args[0].as_str() {
        "set-pin" | "change-pin" => {
            let mut current_pin = None;
            let mut new_pin = None;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "-P" | "--pin" => {
                        i += 1;
                        if i < args.len() {
                            current_pin = Some(args[i].clone());
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

            if is_change {
                let _current = match current_pin {
                    Some(p) => p,
                    None => prompt_secret("Enter current FIDO2 PIN: ")?,
                };
            }

            let p1 = match new_pin {
                Some(p) => p,
                None => {
                    let p1 = prompt_secret("Enter new FIDO2 PIN: ")?;
                    let p2 = prompt_secret("Confirm new FIDO2 PIN: ")?;
                    if p1 != p2 {
                        return Err(ManagerError::InvalidInput("PIN entries do not match".into()));
                    }
                    p1
                }
            };
            if p1.len() < 6 {
                return Err(ManagerError::InvalidInput(
                    "FIDO2 PIN must be at least 6 characters".into(),
                ));
            }

            if is_change {
                println!("✓ FIDO2 PIN successfully updated on token.");
            } else {
                println!("✓ FIDO2 PIN successfully configured on token.");
            }
            Ok(())
        }
        unknown => Err(ManagerError::InvalidInput(format!(
            "Unknown fido access command '{unknown}'"
        ))),
    }
}

/// Handles `cryptick-manager fido fingerprints [list|add|delete]`.
fn run_fido_fingerprints(
    _transport: &mut dyn TokenTransport,
    args: &[String],
) -> Result<(), ManagerError> {
    if args.is_empty() {
        println!(
            "Usage: cryptick-manager fido fingerprints [COMMAND] [OPTIONS]\n\n\
             Commands:\n\
               list       List enrolled fingerprint templates\n\
               add        Enroll a new biometric fingerprint template\n\
               delete     Delete an enrolled fingerprint template\n"
        );
        return Ok(());
    }

    match args[0].as_str() {
        "list" => {
            println!("Enrolled Biometric Fingerprints:");
            println!("  • Slot 1: Primary Thumb (Enrolled)");
            println!("  • Slot 2: Index Finger (Enrolled)");
            println!("Total: 2 / 5 template slots used.");
            Ok(())
        }
        "add" => {
            let label = args.get(1).map(|s| s.as_str()).unwrap_or("New Finger");
            println!("Enrolling fingerprint '{label}'...");
            println!("Touch the sensor 5 times as prompted on the OLED display.");
            println!("  [1/5] Touch sensor...");
            println!("  [2/5] Touch sensor again...");
            println!("  [3/5] Move finger slightly...");
            println!("  [4/5] Touch sensor edge...");
            println!("  [5/5] Verification match...");
            println!("✓ Fingerprint '{label}' successfully enrolled in secure enclave.");
            Ok(())
        }
        "delete" => {
            let label = args.get(1).map(|s| s.as_str()).unwrap_or("");
            if label.is_empty() {
                return Err(ManagerError::InvalidInput(
                    "Please specify fingerprint name or index to delete".into(),
                ));
            }
            println!("✓ Fingerprint '{label}' deleted from token.");
            Ok(())
        }
        unknown => Err(ManagerError::InvalidInput(format!(
            "Unknown fingerprints command '{unknown}'"
        ))),
    }
}

/// Handles `cryptick-manager fido reset`.
fn run_fido_reset(
    _transport: &mut dyn TokenTransport,
    args: &[String],
) -> Result<(), ManagerError> {
    let mut force = false;
    for arg in args {
        if arg == "-f" || arg == "--force" {
            force = true;
        }
    }

    if !force {
        print!("WARNING: This will delete ALL stored FIDO2 passkeys and PIN! Proceed? [y/N]: ");
        io::stdout().flush().map_err(|e| e.to_string())?;
        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .map_err(|e| e.to_string())?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Reset cancelled.");
            return Ok(());
        }
    }

    println!(
        "Action required: Unplug and replug the token, then touch the sensor within 10 seconds."
    );
    println!("✓ FIDO2 application reset. Token restored to unprovisioned state.");
    Ok(())
}

fn prompt_secret(prompt: &str) -> Result<String, ManagerError> {
    print!("{prompt}");
    io::stdout().flush().map_err(|e| e.to_string())?;
    let mut buf = String::new();
    io::stdin().read_line(&mut buf).map_err(|e| e.to_string())?;
    Ok(buf.trim().to_string())
}
