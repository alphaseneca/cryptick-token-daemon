//! `ble-probe` — scan for the token, read what the transport needs, say what
//! can and cannot be proven.
//!
//! Referenced by PROJECT.md §14's hardware job. Its job is diagnosis, not
//! transport: it answers "is the device there, does it speak what we expect,
//! and what is the real `fidoControlPointLength`" without any of the daemon
//! being involved.

use std::time::Duration;
use transport_ble::btleplug::api::Peripheral as _;
use transport_ble::{adapter, probe, BleError};

const USAGE: &str = "\
ble-probe — scan for a Cryptick token and read its FIDO service

    --timeout <seconds>   how long to scan (default 10)
    --scan, --list        scan and list all visible nearby BLE devices
    --require-bonded      fail unless the link is bonded with MITM protection
    --version, -V         display version
    --help, -h            this text
";

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("ble-probe {}", env!("CARGO_PKG_VERSION"));
        return std::process::ExitCode::SUCCESS;
    }
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print!("{USAGE}");
        return std::process::ExitCode::SUCCESS;
    }
    let is_scan_mode = args.iter().any(|a| a == "--scan" || a == "--list" || a == "scan");
    let require_bonded = args.iter().any(|a| a == "--require-bonded");
    let target = args
        .windows(2)
        .find(|w| w[0] == "--target" || w[0] == "-t")
        .map(|w| w[1].clone());
    let timeout = args
        .windows(2)
        .find(|w| w[0] == "--timeout")
        .and_then(|w| w[1].parse().ok())
        .map_or(Duration::from_secs(if is_scan_mode { 3 } else { 10 }), Duration::from_secs);

    let res = if is_scan_mode {
        scan_all(timeout).await
    } else {
        run(timeout, target, require_bonded).await
    };

    match res {
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

async fn run(timeout: Duration, target: Option<String>, require_bonded: bool) -> Result<(), BleError> {
    let adapter = adapter().await?;
    eprintln!("scanning for {} ...", transport_ble::fido_service());

    let peripheral = transport_ble::find_device_with_target(&adapter, target.as_deref(), timeout).await?;
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
    let services = peripheral.services();
    println!("discovered services ({}):", services.len());
    for s in &services {
        println!("  service uuid: {}", s.uuid);
    }
    let chars = peripheral.characteristics();
    println!("discovered characteristics ({}):", chars.len());
    for c in &chars {
        println!("  uuid: {}", c.uuid);
    }
    let find_char = |u: uuid::Uuid| chars.iter().find(|c| c.uuid == u).cloned();
    if let Some(atr_char) = find_char(transport_ble::PIV_ATR) {
        println!("piv service (private)");
        match peripheral.read(&atr_char).await {
            Ok(atr_bytes) => {
                println!(
                    "  atr                   {}",
                    atr_bytes
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<Vec<_>>()
                        .join(" ")
                );
            }
            Err(e) => println!("  atr                   (read failed: {e})"),
        }
        if let Some(cpl_char) = find_char(transport_ble::PIV_CONTROL_POINT_LENGTH) {
            match peripheral.read(&cpl_char).await {
                Ok(cpl_bytes) if cpl_bytes.len() == 2 => {
                    let len = u16::from_be_bytes([cpl_bytes[0], cpl_bytes[1]]);
                    println!("  controlPointLength    {}", len);
                }
                _ => {}
            }
        }
    }

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

async fn scan_all(timeout: Duration) -> Result<(), BleError> {
    use transport_ble::btleplug::api::{Central as _, ScanFilter};
    let adapter = adapter().await?;
    println!("Scanning for all nearby BLE devices ({}s)...", timeout.as_secs());
    adapter.start_scan(ScanFilter::default()).await?;
    tokio::time::sleep(timeout).await;
    let _ = adapter.stop_scan().await;

    let peripherals = adapter.peripherals().await?;
    println!("\n{:<28} {:<24} {:<6} Services", "NAME", "ADDRESS", "RSSI");
    println!("{:-<28} {:-<24} {:-<6} {:-<20}", "", "", "", "");

    let mut count = 0;
    for p in peripherals {
        if let Ok(Some(props)) = p.properties().await {
            let name = props.local_name.unwrap_or_else(|| "(unnamed)".to_string());
            let addr = {
                let id_str = p.id().to_string();
                let addr_str = p.address().to_string();
                if addr_str != "00:00:00:00:00:00" {
                    addr_str
                } else {
                    id_str
                }
            };
            let rssi = props
                .rssi
                .map(|r| r.to_string())
                .unwrap_or_else(|| "-".to_string());
            let services = props
                .services
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            println!("{:<28} {:<24} {:<6} {}", name, addr, rssi, services);
            count += 1;
        }
    }
    println!("\nTotal visible devices: {}", count);
    Ok(())
}

