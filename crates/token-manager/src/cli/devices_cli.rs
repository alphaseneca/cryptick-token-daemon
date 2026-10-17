//! `cryptick-manager devices [list|select]`.
//!
//! Wires the CLI to the same known-devices concept
//! `crates/webauthn-host/src/main.rs`'s `list_devices`/`select_device`
//! actions use, per the project's "whatever the CLI can do, the GUI can do
//! too" principle: both talk to the same daemon IPC actions
//! (`ClientMessage::ListDevices`/`SelectDevice`,
//! `crates/daemon/src/devices.rs`) and union in the same live USB scan
//! rather than maintaining two separate ideas of "which devices exist."
//!
//! Does not require an active hardware connection the way `oath`/`fido`/
//! `piv`/`info` do — `cli/mod.rs` special-cases this subcommand alongside
//! `list`/`script` for that reason.

use crate::error::ManagerError;
use crate::transport::daemon::DaemonTransport;
use crate::transport::usb::UsbTransport;
use std::time::Duration;

/// One device as this subcommand reports it.
struct DeviceRow {
    id: String,
    name: String,
    transport: String,
    last_seen: u64,
    active: bool,
}

/// Handles `cryptick-manager devices [list|select] [ARGS]`.
pub fn handle_devices_command(args: &[String]) -> Result<(), ManagerError> {
    if args.is_empty() {
        return run_list();
    }

    match args[0].as_str() {
        "-h" | "--help" | "help" => {
            print_devices_help();
            Ok(())
        }
        "list" => run_list(),
        "select" => {
            let id = args
                .get(1)
                .ok_or_else(|| "Usage: cryptick-manager devices select <ID>".to_string())?;
            run_select(id)
        }
        unknown => Err(ManagerError::InvalidInput(format!(
            "Unknown devices subcommand '{unknown}'. Run 'cryptick-manager devices --help' for available commands."
        ))),
    }
}

fn print_devices_help() {
    println!(
        "Usage: cryptick-manager devices [COMMAND] [ARGS]\n\n\
         List or select among known Cryptick Tokens.\n\n\
         Commands:\n\
           list           List every known device (default if no command given)\n\
           select <ID>    Make <ID> the active device\n\n\
         Options:\n\
           -h, --help     Show this help message\n\n\
         Note: this hardware has no firmware-populated serial number, so a\n\
         USB-connected token is always reported as a single 'usb' entry — see\n\
         crates/daemon/src/devices.rs for why. BLE devices are tracked by the\n\
         daemon under a best-effort recognition key, not a guaranteed-stable one."
    );
}

/// Unions a live USB presence check with the daemon's BLE known-devices
/// list — the same union `webauthn-host`'s `handle_list_devices` does, kept
/// deliberately in sync rather than each inventing its own merge rule.
fn collect_devices() -> Vec<DeviceRow> {
    let mut rows = Vec::new();

    if let Ok(usb_devices) = UsbTransport::list_devices() {
        if !usb_devices.is_empty() {
            rows.push(DeviceRow {
                id: "usb".into(),
                name: "Cryptick Token (USB)".into(),
                transport: "usb".into(),
                last_seen: now_unix(),
                active: true,
            });
        }
    }

    if let Ok(mut daemon) = DaemonTransport::connect(Duration::from_millis(500)) {
        if let Ok(ble_devices) = daemon.list_devices() {
            let usb_is_active = rows.iter().any(|r| r.transport == "usb");
            for d in ble_devices {
                rows.push(DeviceRow {
                    id: d.id,
                    name: d.name,
                    transport: d.transport,
                    last_seen: d.last_seen,
                    active: d.active && !usb_is_active,
                });
            }
        }
    }

    rows
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn run_list() -> Result<(), ManagerError> {
    let devices = collect_devices();
    if devices.is_empty() {
        println!("No known Cryptick Tokens (USB unplugged, and none remembered by the daemon).");
        return Ok(());
    }

    println!(
        "{:<24} {:<24} {:<6} {:<8} LAST SEEN",
        "ID", "NAME", "TRANSPORT", "ACTIVE"
    );
    for d in &devices {
        println!(
            "{:<24} {:<24} {:<6} {:<8} {}",
            d.id,
            d.name,
            d.transport,
            if d.active { "yes" } else { "" },
            format_last_seen(d.last_seen),
        );
    }
    Ok(())
}

fn format_last_seen(unix_secs: u64) -> String {
    if unix_secs == 0 {
        return "never".to_string();
    }
    let now = now_unix();
    let age = now.saturating_sub(unix_secs);
    match age {
        0..=59 => "just now".to_string(),
        60..=3599 => format!("{}m ago", age / 60),
        3600..=86399 => format!("{}h ago", age / 3600),
        _ => format!("{}d ago", age / 86400),
    }
}

fn run_select(id: &str) -> Result<(), ManagerError> {
    if id == "usb" {
        println!("'usb' has nothing to select — it is a single synthetic entry for whichever Cryptick Token is plugged in (see 'devices --help').");
        return Ok(());
    }
    let mut daemon = DaemonTransport::connect(Duration::from_secs(2)).map_err(|e| {
        ManagerError::Transport(format!("Cannot reach cryptick-daemon to select a device: {e}"))
    })?;
    daemon.select_device(id)?;
    println!("[OK] '{id}' is now the active device.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_last_seen_buckets_are_sane() {
        assert_eq!(format_last_seen(0), "never");
        let now = now_unix();
        assert_eq!(format_last_seen(now), "just now");
        assert_eq!(format_last_seen(now - 120), "2m ago");
        assert_eq!(format_last_seen(now - 7200), "2h ago");
        assert_eq!(format_last_seen(now - 2 * 86400), "2d ago");
    }

    #[test]
    fn select_with_no_id_argument_is_a_usage_error_not_a_panic() {
        let err = handle_devices_command(&["select".to_string()]).unwrap_err();
        assert!(err.to_string().contains("Usage"));
    }

    #[test]
    fn unknown_subcommand_is_reported_by_name() {
        let err = handle_devices_command(&["bogus".to_string()]).unwrap_err();
        assert!(err.to_string().contains("bogus"));
    }
}
