//! `ctctl devices [list|select]`.
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
use std::collections::HashSet;
use std::time::Duration;

/// One device as this subcommand reports it.
struct DeviceRow {
    id: String,
    name: String,
    transport: String,
    last_seen: u64,
    /// Whether `id` is a hardware-read identity (USB `iSerialNumber`, or
    /// the daemon's BLE-verified identity) rather than the old best-effort
    /// placeholder/key. See `print_devices_help`'s note and
    /// `crates/daemon/src/devices.rs`'s module doc.
    verified: bool,
    active: bool,
}

/// Handles `ctctl devices [list|select] [ARGS]`.
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
                .ok_or_else(|| "Usage: ctctl devices select <ID>".to_string())?;
            run_select(id)
        }
        unknown => Err(ManagerError::InvalidInput(format!(
            "Unknown devices subcommand '{unknown}'. Run 'ctctl devices --help' for available commands."
        ))),
    }
}

fn print_devices_help() {
    println!(
        "Usage: ctctl devices [COMMAND] [ARGS]\n\n\
         List or select among known Cryptick Tokens.\n\n\
         Commands:\n\
           list           List every known device (default if no command given)\n\
           select <ID>    Make <ID> the active device\n\n\
         Options:\n\
           -h, --help     Show this help message\n\n\
         Note: a Cryptick Token's own factory-unique serial number\n\
         ('CT-XXXXXXXXXXXX', read from USB iSerialNumber or the daemon's BLE\n\
         identity characteristic — see crates/daemon/src/devices.rs) is used\n\
         as its ID whenever it can be read, so two distinct physical tokens\n\
         show up as two distinct rows on either transport. Older firmware\n\
         exposes neither: a USB-connected unit on that firmware still shows\n\
         as a single synthetic 'usb' entry, and a BLE one still falls back\n\
         to the daemon's best-effort recognition key — both unable to tell\n\
         two such older units apart, exactly as before this existed."
    );
}

/// Unions a live USB presence check with the daemon's BLE known-devices
/// list — the same union `webauthn-host`'s `handle_list_devices` does, kept
/// deliberately in sync rather than each inventing its own merge rule.
fn collect_devices() -> Vec<DeviceRow> {
    let mut rows = Vec::new();

    if let Ok(usb_devices) = UsbTransport::list_devices() {
        // Firmware's real per-unit identity (cryptick-token-code's
        // NOTES.md, "Real USB serial number (eFuse MAC)") when present —
        // one row per distinct serial, so two physical units plugged in at
        // once are no longer collapsed together. A unit on firmware that
        // predates that fix reports no serial at all and falls back to the
        // single synthetic 'usb' entry this subcommand has always shown in
        // that case, exactly as honestly limited as before: it still can't
        // tell two such units apart.
        let mut serials_seen: HashSet<String> = HashSet::new();
        let mut saw_unidentified = false;
        for d in &usb_devices {
            match &d.serial {
                Some(serial) if serials_seen.insert(serial.clone()) => {
                    rows.push(DeviceRow {
                        id: serial.clone(),
                        name: format!("Cryptick Token ({serial})"),
                        transport: "usb".into(),
                        last_seen: now_unix(),
                        verified: true,
                        // Only the first distinct serial is "active": there
                        // is no real per-device USB selection mechanism
                        // today (`UsbTransport::try_connect`'s own
                        // candidate order picks one implicitly), so this
                        // reports which one a plain `transact` would
                        // actually reach rather than guessing at a
                        // selection that doesn't exist.
                        active: serials_seen.len() == 1,
                    });
                }
                // Same physical unit's other HID interface reporting the
                // same serial again — already added.
                Some(_) => {}
                None => saw_unidentified = true,
            }
        }
        if saw_unidentified {
            rows.push(DeviceRow {
                id: "usb".into(),
                name: "Cryptick Token (USB)".into(),
                transport: "usb".into(),
                last_seen: now_unix(),
                verified: false,
                active: serials_seen.is_empty(),
            });
        }
    }

    if let Ok(mut daemon) = DaemonTransport::connect(Duration::from_millis(500)) {
        if let Ok(ble_devices) = daemon.list_devices() {
            let usb_is_active = rows.iter().any(|r| r.transport == "usb" && r.active);
            for d in ble_devices {
                rows.push(DeviceRow {
                    id: d.id,
                    name: d.name,
                    transport: d.transport,
                    last_seen: d.last_seen,
                    verified: d.verified,
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
        "{:<24} {:<24} {:<6} {:<8} {:<9} LAST SEEN",
        "ID", "NAME", "TRANSPORT", "ACTIVE", "VERIFIED"
    );
    for d in &devices {
        println!(
            "{:<24} {:<24} {:<6} {:<8} {:<9} {}",
            d.id,
            d.name,
            d.transport,
            if d.active { "yes" } else { "" },
            if d.verified { "yes" } else { "" },
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
    // USB needs no daemon by design (PROJECT.md §1, §4) and has no
    // persistent "selected device" to switch at the transport layer —
    // `UsbTransport::try_connect` picks implicitly among whatever is
    // plugged in, every call. `id == "usb"` is the old synthetic
    // placeholder (no serial available); a real serial that `devices list`
    // just reported as a USB row hits the same limitation, so both get the
    // same honest answer rather than a silent no-op success that implies
    // something changed.
    if id == "usb" || is_a_listed_usb_serial(id) {
        println!("'{id}' is a USB-connected token — USB has no persistent \"selected device\" to switch to (see 'devices --help'); whichever Cryptick Token is plugged in is used.");
        return Ok(());
    }
    let mut daemon = DaemonTransport::connect(Duration::from_secs(2)).map_err(|e| {
        ManagerError::Transport(format!(
            "Cannot reach cryptick-daemon to select a device: {e}"
        ))
    })?;
    daemon.select_device(id)?;
    println!("[OK] '{id}' is now the active device.");
    Ok(())
}

/// Whether `id` matches a serial `UsbTransport::list_devices` currently
/// reports — so `run_select` can give the USB-specific answer above for a
/// real serial, not just the old `"usb"` placeholder.
fn is_a_listed_usb_serial(id: &str) -> bool {
    UsbTransport::list_devices()
        .map(|devices| devices.iter().any(|d| d.serial.as_deref() == Some(id)))
        .unwrap_or(false)
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
