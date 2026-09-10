//! `ble-probe` — scan for the token, read what the transport needs, say what
//! can and cannot be proven.
//!
//! Referenced by PROJECT.md §14's hardware job. Its job is diagnosis, not
//! transport: it answers "is the device there, does it speak what we expect,
//! and what is the real `fidoControlPointLength`" without any of the daemon
//! being involved.

use std::time::Duration;
use transport_ble::{adapter, find_device, probe, BleError};

const USAGE: &str = "\
ble-probe — scan for a Cryptick token and read its FIDO service

    --timeout <seconds>   how long to scan (default 10)
    --require-bonded      fail unless the link is bonded with MITM protection
    --help                this text
";

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print!("{USAGE}");
        return std::process::ExitCode::SUCCESS;
    }
    let require_bonded = args.iter().any(|a| a == "--require-bonded");
    let timeout = args
        .windows(2)
        .find(|w| w[0] == "--timeout")
        .and_then(|w| w[1].parse().ok())
        .map_or(Duration::from_secs(10), Duration::from_secs);

    match run(timeout, require_bonded).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("ble-probe: {err}");
            if cfg!(target_os = "macos") && matches!(err, BleError::NoAdapter) {
                eprintln!();
                eprintln!("On macOS a process with no Bluetooth grant is usually killed");
                eprintln!("outright rather than reaching this message. The grant is");
                eprintln!("per-application and a CLI tool inherits it from its parent, so");
                eprintln!("grant it to the terminal: System Settings > Privacy & Security");
                eprintln!("> Bluetooth. See PROJECT.md §18.");
            }
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run(timeout: Duration, require_bonded: bool) -> Result<(), BleError> {
    let adapter = adapter().await?;
    eprintln!("scanning for {} ...", transport_ble::fido_service());

    let peripheral = find_device(&adapter, timeout).await?;
    let info = probe(&peripheral).await?;

    println!("device");
    println!(
        "  name                  {}",
        info.name.as_deref().unwrap_or("(none)")
    );
    println!("  address               {}", info.address);
    println!("fido service");
    println!("  controlPointLength    {}", info.control_point_length);
    println!(
        "  serviceRevision       {} ({})",
        info.revision_bitfield
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" "),
        if info.speaks_fido2 {
            "FIDO2"
        } else {
            "FIDO2 bit NOT set"
        }
    );
    println!("link");
    println!("  connected             {}", info.link.connected);
    println!("  bonded                {}", info.link.bonded);
    println!("  authenticated         {}", info.link.authenticated);

    if !info.speaks_fido2 {
        println!();
        println!("warning: fidoServiceRevisionBitfield does not advertise FIDO2 (bit 5).");
    }

    if !info.link.is_usable() {
        println!();
        println!("The bond is unproven. btleplug exposes no pairing state and the");
        println!("platform backend is unwritten, so the daemon will refuse to");
        println!("transact over this link (PROJECT.md §15.2). Everything above is");
        println!("still a real read from real hardware.");
    }

    if require_bonded && !info.link.is_usable() {
        return Err(BleError::BondUnverifiable);
    }
    Ok(())
}
