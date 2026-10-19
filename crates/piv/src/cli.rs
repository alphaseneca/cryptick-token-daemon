//! Command-line argument parsing and execution for `cryptick-piv`.
//!
//! Provides CLI parsing and execution for:
//! - `cryptick-piv provision [--slot <9A|9D|all>] [--dry-run] [--pin <pin>] [--cn <name>] [--print-apdus]`
//! - `cryptick-piv [--slot <9A|9D|all>] [--dry-run] ...`
//! - `cryptick-piv help` / `--help` / `-h`
//! - `cryptick-piv version` / `--version` / `-V`

use crate::cert::{parse_certificate, CertError};
use crate::commands;
use crate::objects::Slot;
use crate::provision::{
    provision_slot, ProvisionError, ProvisionOptions, ProvisionReport, SimulatedCard,
};
use thiserror::Error;

/// Parsed CLI commands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliCommand {
    /// Provision one or more slots.
    Provision(ProvisionOptions),
    /// Display help information.
    Help,
    /// Display version information.
    Version,
}

/// An error encountered while parsing `cryptick-piv` CLI arguments or
/// running the provisioning flow they describe.
///
/// PROJECT.md §20 ("typed errors with `thiserror`; no stringly-typed
/// failures across crate lines") — this module was the one place in the
/// `piv` crate that still returned bare `Result<_, String>`, inconsistent
/// with every other module (`ApduError`, `TlvError`, `ChainError`,
/// `CertError`, `PublicKeyError`, `ObjectError`, `ProvisionError`,
/// `PinError`), all of which are real `thiserror` enums.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CliError {
    /// A `--slot` value (or bare positional slot argument) did not name a
    /// known PIV slot.
    #[error(
        "unknown slot '{0}'. Supported slots: 9A (Authentication), 9D (Key Management), 9C, 9E"
    )]
    UnknownSlot(String),

    /// A flag that takes a value (`--slot`, `--pin`, `--cn`/`--common-name`)
    /// was given with no following argument.
    #[error("flag '{flag}' requires a {expected} argument")]
    MissingArgument {
        /// The flag that was missing its value, e.g. `"--slot"`.
        flag: &'static str,
        /// A short description of what the flag expects, for the error text.
        expected: &'static str,
    },

    /// `--cn` / `--common-name` was given an empty or whitespace-only value.
    #[error("flag '--common-name' argument cannot be empty")]
    EmptyCommonName,

    /// An argument that was not a recognized flag or a valid slot name.
    #[error("unknown option '{0}'. Run 'cryptick-piv --help' for usage.")]
    UnknownOption(String),

    /// Provisioning a slot failed.
    #[error("failed provisioning slot {slot:?}: {source}")]
    Provision {
        /// The slot that failed to provision.
        slot: Slot,
        /// The underlying provisioning failure.
        #[source]
        source: ProvisionError,
    },

    /// The certificate just written to a slot could not be parsed back for
    /// the success summary printed to the user.
    #[error("failed to parse certificate: {0}")]
    Cert(#[from] CertError),
}

/// Parses a slot string (`9A`, `9D`, `9C`, `9E`, or names) into a [`Slot`].
pub fn parse_slot(s: &str) -> Result<Slot, CliError> {
    match s.to_ascii_uppercase().as_str() {
        "9A" | "AUTHENTICATION" | "PIV_AUTHENTICATION" => Ok(Slot::PivAuthentication),
        "9D" | "KEY_MANAGEMENT" | "KEYMANAGEMENT" => Ok(Slot::KeyManagement),
        "9C" | "SIGNATURE" | "DIGITAL_SIGNATURE" => Ok(Slot::DigitalSignature),
        "9E" | "CARD_AUTHENTICATION" => Ok(Slot::CardAuthentication),
        _ => Err(CliError::UnknownSlot(s.to_string())),
    }
}

/// Parses command-line arguments.
pub fn parse_args<I, T>(args: I) -> Result<CliCommand, CliError>
where
    I: IntoIterator<Item = T>,
    T: AsRef<str>,
{
    let args: Vec<String> = args.into_iter().map(|s| s.as_ref().to_string()).collect();

    if args.is_empty() {
        let opts = ProvisionOptions {
            slots: vec![Slot::PivAuthentication],
            dry_run: true,
            ..Default::default()
        };
        return Ok(CliCommand::Provision(opts));
    }

    if args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
        return Ok(CliCommand::Help);
    }
    if args[0] == "version" || args[0] == "--version" || args[0] == "-V" {
        return Ok(CliCommand::Version);
    }

    let mut i = 0;
    if args[0] == "provision" {
        i += 1;
    }

    let mut opts = ProvisionOptions {
        slots: Vec::new(),
        dry_run: false,
        pin: Some("123456".to_string()),
        common_name: None,
        print_apdus: false,
    };

    while i < args.len() {
        match args[i].as_str() {
            "--slot" => {
                i += 1;
                if i >= args.len() {
                    return Err(CliError::MissingArgument {
                        flag: "--slot",
                        expected: "slot (e.g. 9A, 9C, 9D, 9E, or all-slots)",
                    });
                }
                for part in args[i].split(',') {
                    let part = part.trim();
                    if part.eq_ignore_ascii_case("all") {
                        for s in [Slot::PivAuthentication, Slot::KeyManagement] {
                            if !opts.slots.contains(&s) {
                                opts.slots.push(s);
                            }
                        }
                    } else if part.eq_ignore_ascii_case("all-slots") {
                        for s in Slot::ALL {
                            if !opts.slots.contains(&s) {
                                opts.slots.push(s);
                            }
                        }
                    } else {
                        let slot = parse_slot(part)?;
                        if !opts.slots.contains(&slot) {
                            opts.slots.push(slot);
                        }
                    }
                }
                i += 1;
            }
            "--all" => {
                opts.slots = vec![Slot::PivAuthentication, Slot::KeyManagement];
                i += 1;
            }
            "--all-slots" => {
                opts.slots = Slot::ALL.to_vec();
                i += 1;
            }
            "--dry-run" => {
                opts.dry_run = true;
                i += 1;
            }
            "--pin" => {
                i += 1;
                if i >= args.len() {
                    return Err(CliError::MissingArgument {
                        flag: "--pin",
                        expected: "PIN (e.g. 123456)",
                    });
                }
                opts.pin = Some(args[i].clone());
                i += 1;
            }
            "--cn" | "--common-name" => {
                i += 1;
                if i >= args.len() {
                    return Err(CliError::MissingArgument {
                        flag: "--common-name",
                        expected: "string",
                    });
                }
                let cn = &args[i];
                if cn.trim().is_empty() {
                    return Err(CliError::EmptyCommonName);
                }
                opts.common_name = Some(cn.clone());
                i += 1;
            }
            "--print-apdus" => {
                opts.print_apdus = true;
                i += 1;
            }
            "-h" | "--help" => return Ok(CliCommand::Help),
            "-V" | "--version" => return Ok(CliCommand::Version),
            slot_arg if !slot_arg.starts_with('-') => {
                if slot_arg.eq_ignore_ascii_case("all") {
                    opts.slots = vec![Slot::PivAuthentication, Slot::KeyManagement];
                } else if slot_arg.eq_ignore_ascii_case("all-slots") {
                    opts.slots = Slot::ALL.to_vec();
                } else {
                    for part in slot_arg.split(',') {
                        let part = part.trim();
                        let slot = parse_slot(part)?;
                        if !opts.slots.contains(&slot) {
                            opts.slots.push(slot);
                        }
                    }
                }
                i += 1;
            }
            unknown => {
                return Err(CliError::UnknownOption(unknown.to_string()));
            }
        }
    }

    if opts.slots.is_empty() {
        opts.slots = vec![Slot::PivAuthentication];
    }

    Ok(CliCommand::Provision(opts))
}

/// Formats the top-level help text.
pub fn help_text() -> &'static str {
    "Usage: cryptick-piv [COMMAND] [OPTIONS]\n\n\
     Cryptick Token PIV Provisioning Tool.\n\
     Generates EC P-256 keys on the token, constructs self-signed X.509 v3\n\
     certificates, and writes them via chained PUT DATA APDUs.\n\n\
     Commands:\n\
       provision               Provision PIV slots (default command)\n\
       help                    Print this help information\n\
       version                 Print version information\n\n\
     Options:\n\
       --slot <9A|9C|9D|9E|all|all-slots> Target slot (default: 9A)\n\
       --all                   Provision both slot 9A and slot 9D\n\
       --all-slots             Provision all four PIV slots (9A, 9C, 9D, 9E)\n\
       --dry-run               Simulate provisioning without touching physical smart card\n\
       --pin <PIN>             Card PIN (default: 123456)\n\
       --cn <COMMON_NAME>      Custom Subject Common Name\n\
       --print-apdus           Print all emitted APDUs in hex format\n\
       -h, --help              Print help\n\
       -V, --version           Print version\n\n\
     Examples:\n\
       cryptick-piv provision --slot 9A --dry-run\n\
       cryptick-piv --all --dry-run --print-apdus\n\
       cryptick-piv provision 9D\n"
}

/// Runs the CLI application logic with given options.
pub fn run_provision(opts: ProvisionOptions) -> Result<(), CliError> {
    println!("=== Cryptick Token PIV Provisioning ===");
    if opts.dry_run {
        println!("Mode: Simulated dry-run");
    } else {
        println!("Mode: Card Transceive (Simulated Fallback)");
    }

    let mut card = SimulatedCard::new();
    let pin_bytes = opts.pin.as_deref().map(str::as_bytes);

    for &slot in &opts.slots {
        println!(
            "\n--> Provisioning slot {:?} (Key Ref: 0x{:02X}, Tag: 0x{:06X})...",
            slot,
            slot.key_reference(),
            slot.certificate_tag().value()
        );

        let report: ProvisionReport =
            provision_slot(&mut card, slot, pin_bytes, opts.common_name.as_deref())
                .map_err(|source| CliError::Provision { slot, source })?;

        println!("  [OK] EC P-256 key pair generated on-token.");
        println!(
            "       Public Key ({} bytes): 04{}",
            report.public_key.len(),
            hex_slice(&report.public_key[1..9.min(report.public_key.len())])
        );

        let parsed = parse_certificate(&report.certificate_der)?;
        println!("  [OK] Self-signed X.509 v3 certificate constructed:");
        println!("       Subject CN: {}", parsed.common_name);
        println!(
            "       Validity:   {} -> {}",
            parsed.not_before, parsed.not_after
        );
        println!("       Key Usage:  {:?}", parsed.key_usage);
        println!(
            "       Certificate DER size: {} bytes",
            report.certificate_der.len()
        );

        println!(
            "  [OK] Wrapped into SP 800-73-5 container (Tag 0x53): {} bytes.",
            report.container_len
        );
        println!(
            "  [OK] Emitted {} chained PUT DATA APDUs (Lc <= 255).",
            report.chained_apdus_count
        );
        println!("  [OK] Slot {:?} provisioned successfully.", slot);
    }

    if opts.print_apdus {
        println!(
            "\n=== APDU Transaction Log ({} APDUs) ===",
            card.transceived.len()
        );
        for (i, apdu) in card.transceived.iter().enumerate() {
            let cla = apdu.first().copied().unwrap_or(0);
            let ins = apdu.get(1).copied().unwrap_or(0);
            let ins_name = match ins {
                commands::INS_SELECT => "SELECT",
                commands::INS_VERIFY => "VERIFY",
                commands::INS_GENERATE_KEY_PAIR => "GENERATE KEY PAIR",
                commands::INS_GENERAL_AUTHENTICATE => "GENERAL AUTHENTICATE",
                commands::INS_PUT_DATA => "PUT DATA",
                commands::INS_GET_DATA => "GET DATA",
                _ => "UNKNOWN",
            };
            println!(
                "  [{:02}] {} (CLA: 0x{:02X}, len: {}): {}",
                i + 1,
                ins_name,
                cla,
                apdu.len(),
                hex_slice(apdu)
            );
        }
    }

    println!("\nProvisioning completed successfully.");
    Ok(())
}

fn hex_slice(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{:02X}", b);
    }
    s
}
