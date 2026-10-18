//! CLI handler for raw APDU commands: `tickctl apdu`.

use crate::apdu::{aid, format_hex, parse_hex, CommandApdu, ResponseApdu};
use crate::error::ManagerError;
use crate::transport::TokenTransport;
use std::io::{self, Write};
use std::time::{Duration, Instant};

const APDU_TIMEOUT: Duration = Duration::from_secs(15);

/// Resolves an applet alias (e.g. "oath", "piv", "mgmt") or parses an AID hex string.
pub fn resolve_aid(alias: &str) -> Result<Vec<u8>, ManagerError> {
    match alias.to_ascii_lowercase().as_str() {
        "oath" | "totp" => Ok(aid::OATH.to_vec()),
        "piv" | "ccid" => Ok(aid::PIV.to_vec()),
        "mgmt" | "management" | "config" => Ok(aid::MANAGEMENT.to_vec()),
        "fido" | "u2f" | "ctap" => Ok(aid::FIDO.to_vec()),
        hex => parse_hex(hex),
    }
}

/// Handles `tickctl apdu [OPTIONS] [APDU]`.
pub fn run_apdu_command(
    transport: &mut dyn TokenTransport,
    args: &[String],
) -> Result<(), ManagerError> {
    let mut applet_aid = None;
    let mut verbose = false;
    let mut apdu_parts = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                println!(
                    "Usage: tickctl apdu [OPTIONS] [APDU]\n\n\
                     Send raw ISO 7816 APDUs to the token.\n\n\
                     Options:\n\
                       -a, --applet <AID>    Select applet before transmitting (e.g. oath, piv, mgmt, or hex AID)\n\
                       -v, --verbose         Display execution timing, sent packets, and SW breakdown\n\
                       -h, --help            Show this help message\n\n\
                     If [APDU] is omitted, launches an interactive APDU transceive session.\n"
                );
                return Ok(());
            }
            "-a" | "--applet" => {
                i += 1;
                if i < args.len() {
                    applet_aid = Some(resolve_aid(&args[i])?);
                }
            }
            "-v" | "--verbose" => verbose = true,
            part if !part.starts_with('-') => {
                apdu_parts.push(part.to_string());
            }
            other => return Err(ManagerError::InvalidInput(format!("Unknown option '{other}'"))),
        }
        i += 1;
    }

    // Select applet first if requested
    if let Some(ref aid_bytes) = applet_aid {
        if verbose {
            println!("Selecting applet AID: {}", format_hex(aid_bytes));
        }
        let sel_apdu = CommandApdu::select_applet(aid_bytes);
        let resp_bytes = transport.transceive(0x63, &sel_apdu.to_bytes(), APDU_TIMEOUT)?;
        let resp = ResponseApdu::parse(&resp_bytes)?;
        if verbose {
            println!("SELECT response: {}", resp.sw);
        }
        resp.check_success()?;
    }

    if apdu_parts.is_empty() {
        // Interactive APDU REPL mode
        println!("=== Cryptick Token Interactive APDU Terminal ===");
        println!("Transport: {}", transport.transport_name());
        println!("Type raw hex APDUs (e.g. '00 A4 04 00 07 A0 00 00 05 27 21 01'). Press Ctrl+D or type 'exit' to quit.\n");

        loop {
            print!("apdu> ");
            io::stdout().flush().map_err(|e| e.to_string())?;
            let mut line = String::new();
            if io::stdin()
                .read_line(&mut line)
                .map_err(|e| e.to_string())?
                == 0
            {
                break;
            }
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if trimmed.eq_ignore_ascii_case("exit") || trimmed.eq_ignore_ascii_case("quit") {
                break;
            }

            match execute_single_apdu(transport, trimmed, verbose) {
                Ok(()) => {}
                Err(e) => eprintln!("Error: {e}"),
            }
        }
        return Ok(());
    }

    let apdu_str = apdu_parts.join(" ");
    execute_single_apdu(transport, &apdu_str, verbose)
}

fn execute_single_apdu(
    transport: &mut dyn TokenTransport,
    apdu_hex: &str,
    verbose: bool,
) -> Result<(), ManagerError> {
    let raw_bytes = parse_hex(apdu_hex)?;
    if raw_bytes.len() < 4 {
        return Err(ManagerError::InvalidInput(
            "APDU must be at least 4 bytes (CLA, INS, P1, P2)".to_string(),
        ));
    }

    if verbose {
        println!("TX [{} bytes]: {}", raw_bytes.len(), format_hex(&raw_bytes));
    }

    let t0 = Instant::now();
    let resp_bytes = transport.transceive(0x63, &raw_bytes, APDU_TIMEOUT)?;
    let elapsed = t0.elapsed();

    let resp = ResponseApdu::parse(&resp_bytes)?;

    if verbose {
        println!("RX [{} bytes] (elapsed: {:.2?})", resp_bytes.len(), elapsed);
        if !resp.data.is_empty() {
            println!(
                "  Data [{} bytes]: {}",
                resp.data.len(),
                format_hex(&resp.data)
            );
        }
        println!("  SW: {}", resp.sw);
    } else {
        println!("{}", format_hex(&resp_bytes));
    }

    if !resp.is_success() && verbose {
        eprintln!("Warning: Status word indicates refusal: {}", resp.sw);
    }

    Ok(())
}
