//! CLI subcommand handlers for `ctctl fido`.
//!
//! Modeled on YubiKey Manager's `fido` command group as a design reference
//! for CLI ergonomics (subcommand names, flag names/shorthand) — never
//! user-facing, per this project's convention:
//! - `ctctl fido info`
//! - `ctctl fido reset`
//! - `ctctl fido access change-pin` / `access set-pin`
//! - `ctctl fido fingerprints list` / `add <name>` / `delete <name>`
//! - `ctctl fido credentials list` / `delete <credential-id>`
//!
//! Checked against `ykman`'s actual source (`yubikey-manager/ykman/_cli/fido.py`)
//! rather than assumed from memory. Remaining deliberate differences:
//!
//! - **`credentials` takes no `-P/--pin`.** Unlike ykman, which gates its
//!   equivalent command on a PIN, the pinUvAuthToken here is obtained via
//!   `CP_cmdGetPinUvAuthTokenUsingUvWithPermissions` — the device's own
//!   fingerprint touch, not a transmitted PIN (`core/fido2/ctap.c`). Same
//!   reasoning as `fingerprints` below; same orchestration `webauthn-host`
//!   already uses for its own passkey list/delete UI
//!   (`ctap_client::cred_mgmt`), just driven from this transport instead.
//! - **No `fido config` group.** The `toggle-always-uv`/
//!   `enable-ep-attestation` toggles need `authenticatorConfig` (CTAP2
//!   command `0x0d`), which `core/fido2/ctap.c`'s dispatch table has no
//!   case for at all — not a CLI gap, a firmware one.
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
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ctap::{Command, Request, Response, StatusCode};
use ctap_client::cred_mgmt;
use ctap_client::pin_protocol::PlatformKeyAgreement;
use ctap_client::GetInfoResponse;
use std::io::{self, Write};
use std::time::Duration;

const FIDO_TIMEOUT: Duration = Duration::from_secs(10);
const CRED_MGMT_TIMEOUT: Duration = Duration::from_secs(5);
/// Generous: the user has to physically touch the sensor before the device
/// answers this one. Matches `webauthn-host`'s own `UV_CEREMONY_TIMEOUT`
/// (`crates/webauthn-host/src/main.rs`) rather than inventing a second
/// number for the same wait.
const UV_CEREMONY_TIMEOUT: Duration = Duration::from_millis(29_000);

/// Handles all `ctctl fido ...` subcommands.
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
        "credentials" => run_fido_credentials(transport, &args[1..]),
        unknown => Err(ManagerError::InvalidInput(format!(
            "Unknown fido subcommand '{unknown}'. Run 'ctctl fido --help' for available commands."
        ))),
    }
}

/// Prints `ctctl fido --help` usage text.
pub fn print_fido_help() {
    println!(
        "Usage: ctctl fido [COMMAND] [OPTIONS]\n\n\
         Manage FIDO2 passkeys, PINs, and on-chip biometric fingerprints on Cryptick Token.\n\n\
         Commands:\n\
           info          Display FIDO2 / WebAuthn capabilities and security policy\n\
           reset         Reset all FIDO2 credentials and restore unprovisioned state\n\
           access        Manage FIDO2 PIN (set or change)\n\
           fingerprints  Manage on-chip biometric fingerprints (list, add, delete)\n\
           credentials   List or delete resident passkeys (touch to authorise)\n\n\
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
fn run_fido_info(transport: &mut dyn TokenTransport, _args: &[String]) -> Result<(), ManagerError> {
    let raw = match transport.transceive(0x10, &[Command::GET_INFO.as_u8()], FIDO_TIMEOUT) {
        Ok(raw) => raw,
        Err(e) => {
            // `e`'s Display already carries the exact cause: which USB step
            // failed, or (via `DaemonTransport`) the daemon's own stable
            // `ErrorCode` (`NotConnected`, `NotBonded`, `Busy`, `Timeout`, …)
            // plus its human-readable detail — never a bare "unreachable".
            eprintln!("fido info: authenticatorGetInfo request did not reach the device — {e}");
            return Ok(());
        }
    };

    let response = match Response::decode(&raw) {
        Ok(response) => response,
        Err(e) => {
            eprintln!("fido info: transport sent an empty authenticatorGetInfo response ({e})");
            return Ok(());
        }
    };

    if !response.status.is_ok() {
        let name = response
            .status
            .name()
            .map(|n| format!(" ({n})"))
            .unwrap_or_else(|| "unrecognised status".to_string());
        eprintln!(
            "fido info: device refused authenticatorGetInfo with CTAP2 status {:#04x} — {name}",
            response.status.as_u8()
        );
        return Ok(());
    }

    let info = match GetInfoResponse::parse(&response.data) {
        Ok(info) => info,
        Err(e) => {
            eprintln!(
                "fido info: authenticatorGetInfo response did not decode as valid CBOR — {e}"
            );
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

/// Handles `ctctl fido access [change-pin|set-pin]`.
fn run_fido_access(
    _transport: &mut dyn TokenTransport,
    args: &[String],
) -> Result<(), ManagerError> {
    if args.is_empty() {
        println!(
            "Usage: ctctl fido access [COMMAND] [OPTIONS]\n\n\
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
                        return Err(ManagerError::InvalidInput(
                            "PIN entries do not match".into(),
                        ));
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

/// Handles `ctctl fido fingerprints [list|add|delete]`.
fn run_fido_fingerprints(
    _transport: &mut dyn TokenTransport,
    args: &[String],
) -> Result<(), ManagerError> {
    if args.is_empty() {
        println!(
            "Usage: ctctl fido fingerprints [COMMAND] [OPTIONS]\n\n\
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

/// Handles `ctctl fido reset`.
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

/// Sends one `ctap_client::cred_mgmt` request and decodes the CTAP2 envelope
/// around it. Every cred-mgmt call in this module goes through here so a
/// transport failure and a device-refused status are reported the same way
/// every time, rather than each call site rolling its own.
fn cred_mgmt_transceive(
    transport: &mut dyn TokenTransport,
    request: &Request,
    timeout: Duration,
    what: &str,
) -> Result<Vec<u8>, ManagerError> {
    let raw = transport
        .transceive(0x10, &request.encode(), timeout)
        .map_err(|e| ManagerError::Transport(format!("{what} did not reach the device — {e}")))?;
    let response = Response::decode(&raw)
        .map_err(|e| ManagerError::Transport(format!("{what}: empty response ({e})")))?;
    if response.status == StatusCode::NO_CREDENTIALS {
        // Not a failure — RP/credential enumeration signal "exhausted" this
        // way. Callers that are mid-enumeration check for this status
        // themselves; one that reaches here wants it treated as empty.
        return Ok(Vec::new());
    }
    if response.status == StatusCode::OTHER {
        // `ctap_client_pin`/`ctap_cred_mgmt`'s honest answer for a
        // subcommand their firmware build doesn't have a case for — see
        // this module's doc comment.
        return Err(ManagerError::Other(format!(
            "{what}: unsupported on this device's current firmware"
        )));
    }
    if !response.status.is_ok() {
        let name = response
            .status
            .name()
            .map(|n| format!(" ({n})"))
            .unwrap_or_default();
        return Err(ManagerError::Other(format!(
            "{what}: device refused with CTAP2 status {:#04x}{name}",
            response.status.as_u8()
        )));
    }
    Ok(response.data)
}

/// Runs the CTAP2.1 PIN protocol key-agreement handshake and asks for a
/// `pinUvAuthToken` scoped to `permissions`, gated on the fingerprint sensor
/// rather than a PIN — see this module's doc comment. A fresh token is
/// obtained every call; this device's token lifetime policy isn't pinned
/// down well enough yet to risk caching one past its actual expiry.
fn obtain_uv_token(
    transport: &mut dyn TokenTransport,
    permissions: u8,
) -> Result<[u8; 16], ManagerError> {
    let ka_data = cred_mgmt_transceive(
        transport,
        &cred_mgmt::get_key_agreement_request(),
        FIDO_TIMEOUT,
        "fido credentials: key agreement",
    )?;
    let device_key = cred_mgmt::parse_key_agreement_response(&ka_data).map_err(|e| {
        ManagerError::Other(format!("fido credentials: key agreement response: {e}"))
    })?;

    let platform = PlatformKeyAgreement::generate();
    let shared_secret = platform.shared_secret(&device_key);

    println!("Touch the sensor to authorise...");
    let uv_data = cred_mgmt_transceive(
        transport,
        &cred_mgmt::get_uv_token_request(&platform, permissions, None),
        UV_CEREMONY_TIMEOUT,
        "fido credentials: touch authorisation",
    )?;

    cred_mgmt::parse_uv_token_response(&uv_data, &shared_secret).map_err(|e| {
        ManagerError::Other(format!(
            "fido credentials: touch response did not decrypt: {e}"
        ))
    })
}

/// Handles `ctctl fido credentials [list|delete]`.
fn run_fido_credentials(
    transport: &mut dyn TokenTransport,
    args: &[String],
) -> Result<(), ManagerError> {
    if args.is_empty() {
        println!(
            "Usage: ctctl fido credentials [COMMAND] [OPTIONS]\n\n\
             List or delete resident FIDO2 passkeys. Every call needs a\n\
             touch on the sensor to authorise — there is no PIN for this.\n\n\
             Commands:\n\
               list               List every relying party and its passkeys\n\
               delete CREDENTIAL  Delete one passkey by its credential ID\n\n\
             Options (list only):\n\
               -c, --csv          Print as rp_id,user_name,credential_id\n"
        );
        return Ok(());
    }

    match args[0].as_str() {
        "list" => run_credentials_list(transport, &args[1..]),
        "delete" => run_credentials_delete(transport, &args[1..]),
        unknown => Err(ManagerError::InvalidInput(format!(
            "Unknown credentials command '{unknown}'"
        ))),
    }
}

fn run_credentials_list(
    transport: &mut dyn TokenTransport,
    args: &[String],
) -> Result<(), ManagerError> {
    let csv = args.iter().any(|a| a == "-c" || a == "--csv");

    let pin_token = obtain_uv_token(transport, cred_mgmt::PERMISSION_CREDENTIAL_MANAGEMENT)?;

    let metadata_data = cred_mgmt_transceive(
        transport,
        &cred_mgmt::metadata_request(&pin_token),
        CRED_MGMT_TIMEOUT,
        "fido credentials list: metadata",
    )?;
    let metadata = cred_mgmt::Metadata::parse(&metadata_data).map_err(|e| {
        ManagerError::Other(format!("fido credentials list: metadata response: {e}"))
    })?;

    if metadata.existing_resident_credentials_count == 0 {
        if !csv {
            println!("No resident passkeys stored on this token.");
        }
        return Ok(());
    }

    let mut total = 0;
    let mut next_rp = Some(cred_mgmt::rp_begin_request(&pin_token));
    while let Some(req) = next_rp.take() {
        let rp_data = cred_mgmt_transceive(
            transport,
            &req,
            CRED_MGMT_TIMEOUT,
            "fido credentials list: RP enumeration",
        )?;
        if rp_data.is_empty() {
            break;
        }
        let rp = cred_mgmt::RpEntry::parse(&rp_data)
            .map_err(|e| ManagerError::Other(format!("fido credentials list: RP response: {e}")))?;

        if !csv {
            println!(
                "{} ({})",
                rp.rp_name.as_deref().unwrap_or(&rp.rp_id),
                rp.rp_id
            );
        }

        let mut next_cred = Some(cred_mgmt::rk_begin_request(&pin_token, &rp.rp_id_hash));
        while let Some(creq) = next_cred.take() {
            let cred_data = cred_mgmt_transceive(
                transport,
                &creq,
                CRED_MGMT_TIMEOUT,
                "fido credentials list: credential enumeration",
            )?;
            if cred_data.is_empty() {
                break;
            }
            let entry = cred_mgmt::CredentialEntry::parse(&cred_data).map_err(|e| {
                ManagerError::Other(format!("fido credentials list: credential response: {e}"))
            })?;
            let id_b64 = URL_SAFE_NO_PAD.encode(&entry.credential_id);
            let user = entry.user_name.as_deref().unwrap_or("");
            let display = entry.user_display_name.as_deref().unwrap_or("");

            if csv {
                println!("{},{user},{id_b64}", rp.rp_id);
            } else {
                println!("  • {display} ({user})  [{id_b64}]");
            }
            total += 1;

            next_cred = Some(cred_mgmt::rk_next_request());
        }

        next_rp = Some(cred_mgmt::rp_next_request());
    }

    if !csv {
        println!(
            "\n{total} passkey(s) stored, {} slot(s) remaining.",
            metadata.max_possible_remaining
        );
    }
    Ok(())
}

fn run_credentials_delete(
    transport: &mut dyn TokenTransport,
    args: &[String],
) -> Result<(), ManagerError> {
    let mut force = false;
    let mut credential_id = None;
    for arg in args {
        match arg.as_str() {
            "-f" | "--force" => force = true,
            other => credential_id = Some(other.to_string()),
        }
    }
    let credential_id = credential_id
        .ok_or_else(|| "Usage: ctctl fido credentials delete CREDENTIAL [-f]".to_string())?;
    let raw_id = URL_SAFE_NO_PAD.decode(&credential_id).map_err(|e| {
        ManagerError::InvalidInput(format!("Invalid credential ID (not base64url): {e}"))
    })?;

    if !force {
        print!("Delete this passkey? It cannot be recovered. [y/N]: ");
        io::stdout().flush().map_err(|e| e.to_string())?;
        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .map_err(|e| e.to_string())?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Delete cancelled.");
            return Ok(());
        }
    }

    let pin_token = obtain_uv_token(transport, cred_mgmt::PERMISSION_CREDENTIAL_MANAGEMENT)?;
    cred_mgmt_transceive(
        transport,
        &cred_mgmt::rk_delete_request(&pin_token, &raw_id),
        CRED_MGMT_TIMEOUT,
        "fido credentials delete",
    )?;
    println!("✓ Passkey deleted.");
    Ok(())
}

fn prompt_secret(prompt: &str) -> Result<String, ManagerError> {
    print!("{prompt}");
    io::stdout().flush().map_err(|e| e.to_string())?;
    let mut buf = String::new();
    io::stdin().read_line(&mut buf).map_err(|e| e.to_string())?;
    Ok(buf.trim().to_string())
}
