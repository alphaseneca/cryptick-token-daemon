//! CLI subcommand handlers for `ctctl piv`.
//!
//! Modeled on YubiKey Manager's `piv` command group as a design reference
//! for CLI ergonomics (subcommand names, flag names/shorthand) — never
//! user-facing, per this project's convention:
//! - `ctctl piv info`
//! - `ctctl piv reset`
//! - `ctctl piv access change-pin`
//! - `ctctl piv access change-puk`
//! - `ctctl piv access unblock-pin`
//! - `ctctl piv access set-retries`
//! - `ctctl piv access change-management-key`
//! - `ctctl piv provision [--slot <9A|9D|all>] [--cn <name>] [--pin <pin>]`
//! - `ctctl piv certificates export <slot>`
//! - `ctctl piv certificates delete <slot>`
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
//! - **No `piv keys` or `piv objects` command group.** Those cover
//!   arbitrary-slot key import/export/attestation — importing an
//!   externally-generated private key weakens this device's "private key
//!   never leaves the card" property, which is a product-security
//!   decision for the device's owner to make deliberately, not one to
//!   bundle into a CLI-parity or access-command pass. `access
//!   change-puk`/`set-retries`/`unblock-pin`/`change-management-key`,
//!   previously in this same category (unimplemented stubs or entirely
//!   absent, because `piv::commands` had no `CHANGE REFERENCE DATA` for
//!   PUK, no `RESET RETRY COUNTER`, no `SET PIN RETRIES`, and no
//!   management key or `GENERAL AUTHENTICATE` against key reference `9B`
//!   at all), are now real — see `piv::commands`' own doc comments and
//!   `cryptick-token-code`'s NOTES.md ("PIV PUK and management key
//!   support") for the firmware-side design, including the management
//!   key's default-key policy, which was a genuine product-security
//!   decision made (and written down) rather than defaulted to silently.
//! - **`reset` only ever sent a bare `SELECT` until this pass** — it
//!   printed a "factory reset" success message without the firmware
//!   having any `RESET APPLICATION` APDU to send it at all, so nothing
//!   was ever actually wiped. Now sends `commands::reset_application()`,
//!   gated (by the device, not merely by this CLI) on either a verified
//!   PIN or both the PIN and PUK already being blocked — see that
//!   function's own doc comment and `cryptick-token-code`'s NOTES.md
//!   ("PIV factory reset") for the firmware-side design. The gate started
//!   out stricter (lockout-only) in this same pass and was relaxed to add
//!   the verified-PIN path after the device's owner found the lockout-
//!   only version impractical for ordinary, non-recovery use — recorded
//!   in that same NOTES.md entry as a product decision made deliberately,
//!   not a bug.

use crate::apdu::{aid, format_hex, parse_hex, CommandApdu, ResponseApdu, StatusWord};
use crate::error::ManagerError;
use crate::transport::TokenTransport;
use piv::cert::parse_certificate;
use piv::commands;
use piv::commands::ManagementKey;
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

/// Handles all `ctctl piv ...` subcommands.
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
            "Unknown piv subcommand '{unknown}'. Run 'ctctl piv --help' for available commands."
        ))),
    }
}

/// Prints `ctctl piv --help` usage text.
pub fn print_piv_help() {
    println!(
        "Usage: ctctl piv [COMMAND] [OPTIONS]\n\n\
         Manage PIV smart card application, slots, keys, and certificates on Cryptick Token.\n\n\
         Commands:\n\
           info          Display PIV status, PIN tries remaining, and configured slots\n\
           reset         Factory-reset PIV (enter your PIN, or recover a locked-out device)\n\
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

/// Queries PIN or PUK retries remaining via VERIFY's empty-body form,
/// without spending an attempt. Returns 0 for an already-blocked secret
/// (VERIFY answers `AUTH_METHOD_BLOCKED`, not a `63Cx` count) rather than
/// failing `piv info` outright over a state the operator needs to see.
fn query_retries(transport: &mut dyn TokenTransport, puk: bool) -> Result<u8, ManagerError> {
    let cmd = if puk {
        commands::verify_puk_retries()
    } else {
        commands::verify_retries()
    };
    let raw = transport.transceive(
        0x03,
        &cmd.encode()
            .map_err(|e| ManagerError::InvalidInput(e.to_string()))?,
        PIV_TIMEOUT,
    )?;
    let resp = ResponseApdu::parse(&raw)?;
    if resp.sw == StatusWord::AUTH_METHOD_BLOCKED {
        return Ok(0);
    }
    // `run_piv_info` always calls `select_piv` immediately before this,
    // which resets PIN verification — so the "already verified, plain
    // 9000" branch VERIFY's empty-body form can take is unreachable here.
    // If that invariant ever stops holding, falling through to 0 below
    // undercounts rather than overclaiming retries that may not be there.
    Ok(retries_remaining(resp.sw).unwrap_or(0))
}

/// Displays information about PIV slots and configuration.
fn run_piv_info(
    transport: &mut dyn TokenTransport,
    _args: &[String],
) -> Result<(), ManagerError> {
    select_piv(transport)?;

    println!("PIV version: 5.4.0 (SP 800-73-5 compliant)");
    println!("PIN tries remaining: {}", query_retries(transport, false)?);
    println!("PUK tries remaining: {}", query_retries(transport, true)?);
    // Not "AES-192 (or 3DES legacy)": this firmware supports exactly one
    // management-key algorithm, and claiming a second one it will never
    // accept is the same kind of fabrication a canned success message is.
    println!("Management key algorithm: AES-192");
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
        println!("\nHint: Run 'ctctl piv provision --slot 9A' to configure macOS / Linux login.");
    }

    Ok(())
}

/// Extracts "attempts remaining" from a `63Cx` status word — VERIFY,
/// CHANGE REFERENCE DATA, and RESET RETRY COUNTER all answer a wrong
/// secret this way (`piv::apdu::StatusWord::retries_left` mirrors the same
/// bit pattern on the `piv` crate's own status-word type; duplicated here
/// in one line because `ResponseApdu` carries this crate's `StatusWord`,
/// not that one).
fn retries_remaining(sw: StatusWord) -> Option<u8> {
    let v = sw.value();
    if v & 0xFFF0 == 0x63C0 {
        Some((v & 0x0F) as u8)
    } else {
        None
    }
}

/// A nonce for the management key's mutual-authenticate challenge.
///
/// Does not need to be cryptographically unpredictable — the protocol's
/// security comes from needing the key to produce a *correct* encrypted
/// answer, not from the challenge being unguessable, so there is nothing to
/// gain by pulling in a `rand` dependency (§7/§20: new dependencies are
/// discussed, not added for something this small) for what wall-clock
/// time already gives a single interactive CLI invocation: a value the
/// card could not have precomputed a response for before this exchange
/// began. A process-local counter is mixed in alongside the timestamp —
/// not for unpredictability, but because some clocks' practical resolution
/// is coarser than true nanoseconds, and two calls landing on the same
/// tick must still not hand the card back a repeated value to encrypt.
fn fresh_challenge() -> [u8; 16] {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut out = nanos.to_be_bytes();
    for (i, b) in count.to_be_bytes().iter().enumerate() {
        out[8 + i] ^= b;
    }
    out
}

/// Sends one `GENERAL AUTHENTICATE` link and returns its response data,
/// failing with the real device status rather than a guessed one.
fn send_mgmt_apdu(
    transport: &mut dyn TokenTransport,
    cmd: &piv::apdu::Command,
) -> Result<Vec<u8>, ManagerError> {
    let raw = transport.transceive(
        0x03,
        &cmd.encode()
            .map_err(|e| ManagerError::InvalidInput(e.to_string()))?,
        PIV_TIMEOUT,
    )?;
    let resp = ResponseApdu::parse(&raw)?;
    if !resp.is_success() {
        return Err(ManagerError::DeviceStatus(resp.sw));
    }
    Ok(resp.data)
}

/// Runs the management key's mutual-authenticate exchange (SP 800-73-5 Part
/// 2 §3.2.4 Table 7) and confirms it really was mutual — the card's
/// response must decrypt back to the challenge this call sent, or the key
/// supplied does not actually match the one on the device.
fn authenticate_management_key(
    transport: &mut dyn TokenTransport,
    key: &ManagementKey,
) -> Result<(), ManagerError> {
    let data = send_mgmt_apdu(transport, &commands::mgmt_request_witness())?;
    let enc_witness: [u8; 16] = commands::parse_witness(&data)
        .map_err(|e| ManagerError::InvalidInput(format!("malformed witness: {e}")))?
        .try_into()
        .map_err(|_| ManagerError::InvalidInput("witness was not 16 bytes".into()))?;
    let witness_plain = key.decrypt_block(&enc_witness);

    let challenge = fresh_challenge();
    let data = send_mgmt_apdu(transport, &commands::mgmt_respond(&witness_plain, &challenge))?;
    let enc_response: [u8; 16] = commands::parse_mgmt_response(&data)
        .map_err(|e| ManagerError::InvalidInput(format!("malformed response: {e}")))?
        .try_into()
        .map_err(|_| ManagerError::InvalidInput("response was not 16 bytes".into()))?;

    if key.decrypt_block(&enc_response) != challenge {
        return Err(ManagerError::InvalidInput(
            "management key authentication failed: the device could not prove it holds \
             the same key (wrong management key, or a device that does not trust this one)"
                .into(),
        ));
    }
    Ok(())
}

/// Parses a management key from hex, requiring exactly 24 bytes (AES-192) —
/// the one algorithm this applet's firmware supports.
fn parse_management_key(hex: &str) -> Result<ManagementKey, ManagerError> {
    let bytes = parse_hex(hex)?;
    let key: [u8; 24] = bytes.try_into().map_err(|b: Vec<u8>| {
        ManagerError::InvalidInput(format!(
            "management key must be 24 bytes (48 hex characters) for AES-192; got {}",
            b.len()
        ))
    })?;
    Ok(ManagementKey::new(key))
}

/// Handles `ctctl piv access [change-pin|change-puk|unblock-pin|set-retries|change-management-key]`.
fn run_piv_access(
    transport: &mut dyn TokenTransport,
    args: &[String],
) -> Result<(), ManagerError> {
    if args.is_empty() {
        println!(
            "Usage: ctctl piv access [COMMAND] [OPTIONS]\n\n\
             Commands:\n\
               change-pin             Change the 6-8 digit user PIN\n\
               change-puk             Change the 8 digit PIN Unlock Key (PUK)\n\
               unblock-pin            Reset a blocked PIN using the PUK\n\
               set-retries             Reconfigure PIN/PUK retry limits (resets both to defaults)\n\
               change-management-key  Install a new AES-192 management key\n"
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
            let mut old_puk = None;
            let mut new_puk = None;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "-u" | "--puk" => {
                        i += 1;
                        if i < args.len() {
                            old_puk = Some(args[i].clone());
                        }
                    }
                    "-n" | "--new-puk" => {
                        i += 1;
                        if i < args.len() {
                            new_puk = Some(args[i].clone());
                        }
                    }
                    _ => {}
                }
                i += 1;
            }

            let old_puk = match old_puk {
                Some(p) => p,
                None => prompt_secret("Enter current PUK: ")?,
            };
            let new_puk = match new_puk {
                Some(p) => p,
                None => {
                    let p1 = prompt_secret("Enter new PUK: ")?;
                    let p2 = prompt_secret("Confirm new PUK: ")?;
                    if p1 != p2 {
                        return Err(ManagerError::InvalidInput(
                            "New PUK entries do not match".into(),
                        ));
                    }
                    p1
                }
            };

            let cmd = commands::change_puk(old_puk.as_bytes(), new_puk.as_bytes())
                .map_err(|e| ManagerError::InvalidInput(format!("Invalid PUK format: {e}")))?;
            let raw = transport.transceive(
                0x03,
                &cmd.encode()
                    .map_err(|e| ManagerError::InvalidInput(e.to_string()))?,
                PIV_TIMEOUT,
            )?;
            let resp = ResponseApdu::parse(&raw)?;
            if resp.is_success() {
                println!("✓ PUK successfully updated.");
                Ok(())
            } else if let Some(left) = retries_remaining(resp.sw) {
                Err(ManagerError::InvalidInput(format!(
                    "Wrong current PUK; {left} attempt(s) remaining before it blocks."
                )))
            } else {
                Err(ManagerError::DeviceStatus(resp.sw))
            }
        }
        "unblock-pin" => {
            let mut puk = None;
            let mut new_pin = None;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "-u" | "--puk" => {
                        i += 1;
                        if i < args.len() {
                            puk = Some(args[i].clone());
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

            let puk = match puk {
                Some(p) => p,
                None => prompt_secret("Enter PUK: ")?,
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

            let cmd = commands::reset_pin(puk.as_bytes(), new_pin.as_bytes())
                .map_err(|e| ManagerError::InvalidInput(format!("Invalid PUK or PIN: {e}")))?;
            let raw = transport.transceive(
                0x03,
                &cmd.encode()
                    .map_err(|e| ManagerError::InvalidInput(e.to_string()))?,
                PIV_TIMEOUT,
            )?;
            let resp = ResponseApdu::parse(&raw)?;
            if resp.is_success() {
                // SP 800-73: RESET RETRY COUNTER clears the block, it does
                // not verify the new PIN. Say so honestly rather than
                // implying the session is now authenticated.
                println!(
                    "✓ PIN unblocked and set to the new value. It has not been verified \
                     this session — the next login (or 'ctctl piv access change-pin') will \
                     need it."
                );
                Ok(())
            } else if let Some(left) = retries_remaining(resp.sw) {
                Err(ManagerError::InvalidInput(format!(
                    "Wrong PUK; {left} attempt(s) remaining before it blocks."
                )))
            } else {
                Err(ManagerError::DeviceStatus(resp.sw))
            }
        }
        "change-management-key" => {
            let mut current = None;
            let mut new = None;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "-m" | "--management-key" => {
                        i += 1;
                        if i < args.len() {
                            current = Some(args[i].clone());
                        }
                    }
                    "-n" | "--new-management-key" => {
                        i += 1;
                        if i < args.len() {
                            new = Some(args[i].clone());
                        }
                    }
                    _ => {}
                }
                i += 1;
            }

            let current = match current {
                Some(k) => k,
                None => prompt_secret("Enter current management key (hex): ")?,
            };
            let new = match new {
                Some(k) => k,
                None => {
                    let k1 = prompt_secret("Enter new management key (hex, 48 chars): ")?;
                    let k2 = prompt_secret("Confirm new management key (hex): ")?;
                    if k1 != k2 {
                        return Err(ManagerError::InvalidInput(
                            "New management key entries do not match".into(),
                        ));
                    }
                    k1
                }
            };

            let current_key = parse_management_key(&current)?;
            let new_key = parse_management_key(&new)?;

            authenticate_management_key(transport, &current_key)?;

            let cmd = commands::set_management_key(new_key.as_bytes());
            let raw = transport.transceive(
                0x03,
                &cmd.encode()
                    .map_err(|e| ManagerError::InvalidInput(e.to_string()))?,
                PIV_TIMEOUT,
            )?;
            let resp = ResponseApdu::parse(&raw)?;
            if resp.is_success() {
                println!("✓ Management key successfully updated.");
                Ok(())
            } else {
                Err(ManagerError::DeviceStatus(resp.sw))
            }
        }
        "set-retries" => {
            let mut pin_retries: Option<u8> = None;
            let mut puk_retries: Option<u8> = None;
            let mut pin = None;
            let mut mgmt_key = None;
            let mut force = false;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--pin-retries" => {
                        i += 1;
                        if i < args.len() {
                            pin_retries = args[i].parse().ok();
                        }
                    }
                    "--puk-retries" => {
                        i += 1;
                        if i < args.len() {
                            puk_retries = args[i].parse().ok();
                        }
                    }
                    "-P" | "--pin" => {
                        i += 1;
                        if i < args.len() {
                            pin = Some(args[i].clone());
                        }
                    }
                    "-m" | "--management-key" => {
                        i += 1;
                        if i < args.len() {
                            mgmt_key = Some(args[i].clone());
                        }
                    }
                    "-f" | "--force" => force = true,
                    _ => {}
                }
                i += 1;
            }

            let pin_retries = pin_retries.ok_or_else(|| {
                ManagerError::InvalidInput("--pin-retries <1-15> is required".into())
            })?;
            let puk_retries = puk_retries.ok_or_else(|| {
                ManagerError::InvalidInput("--puk-retries <1-15> is required".into())
            })?;

            if !force {
                println!(
                    "WARNING: this resets the PIN to 123456 and the PUK to 12345678 — the \
                     ceiling and the stored secret share one rewrite on this device, the \
                     same as every other PIV implementation of this command. Proceed? [y/N]: "
                );
                io::stdout().flush().map_err(|e| e.to_string())?;
                let mut input = String::new();
                io::stdin().read_line(&mut input).map_err(|e| e.to_string())?;
                if !input.trim().eq_ignore_ascii_case("y") {
                    println!("Cancelled.");
                    return Ok(());
                }
            }

            let pin = match pin {
                Some(p) => p,
                None => prompt_secret("Enter current PIN: ")?,
            };
            let mgmt_key = match mgmt_key {
                Some(k) => k,
                None => prompt_secret("Enter management key (hex): ")?,
            };
            let mgmt_key = parse_management_key(&mgmt_key)?;

            let verify_cmd = commands::verify_pin(pin.as_bytes())
                .map_err(|e| ManagerError::InvalidInput(format!("Invalid PIN format: {e}")))?;
            let raw = transport.transceive(
                0x03,
                &verify_cmd
                    .encode()
                    .map_err(|e| ManagerError::InvalidInput(e.to_string()))?,
                PIV_TIMEOUT,
            )?;
            let resp = ResponseApdu::parse(&raw)?;
            if !resp.is_success() {
                return Err(ManagerError::DeviceStatus(resp.sw));
            }

            authenticate_management_key(transport, &mgmt_key)?;

            let cmd = commands::set_pin_retries(pin_retries, puk_retries);
            let raw = transport.transceive(
                0x03,
                &cmd.encode()
                    .map_err(|e| ManagerError::InvalidInput(e.to_string()))?,
                PIV_TIMEOUT,
            )?;
            let resp = ResponseApdu::parse(&raw)?;
            if resp.is_success() {
                println!(
                    "✓ Retry limits set (PIN: {pin_retries}, PUK: {puk_retries}). \
                     PIN reset to 123456, PUK reset to 12345678 — change both before use."
                );
                Ok(())
            } else {
                Err(ManagerError::DeviceStatus(resp.sw))
            }
        }
        unknown => Err(ManagerError::InvalidInput(format!(
            "Unknown access command '{unknown}'"
        ))),
    }
}

/// Handles `ctctl piv provision [--slot 9A] [--cn <name>] [--pin <pin>] [--dry-run]`.
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

/// Handles `ctctl piv certificates [export|delete] SLOT`.
fn run_piv_certificates(
    transport: &mut dyn TokenTransport,
    args: &[String],
) -> Result<(), ManagerError> {
    if args.is_empty() {
        println!(
            "Usage: ctctl piv certificates [COMMAND] SLOT\n\n\
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
                    .ok_or_else(|| "Usage: ctctl piv certificates export SLOT".to_string())?,
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
                    .ok_or_else(|| "Usage: ctctl piv certificates delete SLOT".to_string())?,
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

/// Handles `ctctl piv reset`.
///
/// `RESET APPLICATION` (vendor, INS `0xFB`) accepts either of two
/// preconditions — see `commands::reset_application()`'s own doc comment:
/// a verified PIN (the common case — an owner who still knows their PIN
/// resets directly, no need to deliberately lock anything out first), or
/// both the PIN and PUK already blocked (the lockout-recovery case, for
/// an owner who has lost the PIN entirely). This queries both counters
/// first; if neither already reads zero, it verifies the PIN itself
/// before sending the reset, so a wrong PIN is reported the same specific
/// way `access change-pin` already reports one (attempts remaining)
/// rather than surfacing the device's bare status word. `--force` only
/// skips the destructive-action confirmation below, never PIN
/// verification or the device's own retry-counter gate — those are
/// security checks, not prompts this CLI can choose to skip.
fn run_piv_reset(
    transport: &mut dyn TokenTransport,
    args: &[String],
) -> Result<(), ManagerError> {
    let mut force = false;
    let mut pin = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-f" | "--force" => force = true,
            "-P" | "--pin" => {
                i += 1;
                if i < args.len() {
                    pin = Some(args[i].clone());
                }
            }
            _ => {}
        }
        i += 1;
    }

    select_piv(transport)?;

    let pin_retries = query_retries(transport, false)?;
    let puk_retries = query_retries(transport, true)?;
    let already_locked_out = pin_retries == 0 && puk_retries == 0;

    if !already_locked_out {
        let pin = match pin {
            Some(p) => p,
            None => prompt_secret("Enter current PIN: ")?,
        };
        let verify_cmd = commands::verify_pin(pin.as_bytes())
            .map_err(|e| ManagerError::InvalidInput(format!("Invalid PIN format: {e}")))?;
        let raw = transport.transceive(
            0x03,
            &verify_cmd
                .encode()
                .map_err(|e| ManagerError::InvalidInput(e.to_string()))?,
            PIV_TIMEOUT,
        )?;
        let resp = ResponseApdu::parse(&raw)?;
        if !resp.is_success() {
            return if let Some(left) = retries_remaining(resp.sw) {
                Err(ManagerError::InvalidInput(format!(
                    "Wrong PIN; {left} attempt(s) remaining before it blocks. Nothing \
                     was reset."
                )))
            } else {
                Err(ManagerError::DeviceStatus(resp.sw))
            };
        }
    }

    if !force {
        print!(
            "WARNING: this will permanently delete every stored PIV certificate and \
             reset the PIN, PUK, and management key to their factory defaults. This \
             cannot be undone. Proceed? [y/N]: "
        );
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

    let cmd = commands::reset_application();
    let raw = transport.transceive(
        0x03,
        &cmd.encode()
            .map_err(|e| ManagerError::InvalidInput(e.to_string()))?,
        PIV_TIMEOUT,
    )?;
    let resp = ResponseApdu::parse(&raw)?;
    if resp.is_success() {
        println!(
            "✓ PIV application reset to factory defaults (Default PIN: 123456, PUK: 12345678)."
        );
        Ok(())
    } else {
        Err(ManagerError::DeviceStatus(resp.sw))
    }
}

fn prompt_secret(prompt: &str) -> Result<String, ManagerError> {
    print!("{prompt}");
    io::stdout().flush().map_err(|e| e.to_string())?;
    let mut buf = String::new();
    io::stdin().read_line(&mut buf).map_err(|e| e.to_string())?;
    Ok(buf.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // These test the pure glue this module adds around `piv::commands` and
    // `ManagementKey` — parsing, status-word interpretation, nonce shape —
    // not the APDU protocol itself. That protocol is exercised end to end
    // against the *real* firmware C by `tests/host/test_piv_apdu.py` in
    // cryptick-token-code (32 new cases for exactly this pass), which is
    // stronger evidence than a second, parallel simulated-card fake here
    // would be; building one was not worth the duplication for what it
    // would additionally catch over what commands.rs's own APDU-shape
    // tests and that host suite already do.

    #[test]
    fn retries_remaining_reads_the_63cx_pattern_and_nothing_else() {
        assert_eq!(retries_remaining(StatusWord(0x63C3)), Some(3));
        assert_eq!(retries_remaining(StatusWord(0x63C0)), Some(0));
        assert_eq!(retries_remaining(StatusWord(0x9000)), None);
        assert_eq!(retries_remaining(StatusWord::AUTH_METHOD_BLOCKED), None);
        assert_eq!(retries_remaining(StatusWord(0x6A86)), None);
    }

    #[test]
    fn fresh_challenge_is_16_bytes_and_actually_varies() {
        let a = fresh_challenge();
        let b = fresh_challenge();
        assert_eq!(a.len(), 16);
        // Not a strict requirement of the protocol (a fixed challenge
        // would still be secure, per this function's own doc comment) —
        // but if two calls back to back ever produced the same value,
        // the clock source feeding it would be broken in a way worth
        // catching here rather than finding out from a flaky retry.
        assert_ne!(a, b);
    }

    #[test]
    fn parse_management_key_requires_exactly_24_bytes() {
        let key_hex = "00".repeat(24);
        assert!(parse_management_key(&key_hex).is_ok());

        let short_hex = "00".repeat(16);
        assert!(parse_management_key(&short_hex).is_err());

        let long_hex = "00".repeat(32);
        assert!(parse_management_key(&long_hex).is_err());
    }

    #[test]
    fn parse_management_key_rejects_non_hex() {
        assert!(parse_management_key("not hex at all, 24 bytes of it").is_err());
    }
}
