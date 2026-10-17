//! A known-devices store the daemon owns, not the extension.
//!
//! Per the research doc this item implements (`docs/research/multi-device-and-credential-sync.md`
//! §1): "None of this is security-sensitive by itself — it's bookkeeping."
//! Nothing here touches key material, PINs, or user presence, so none of
//! PROJECT.md §15's invariants apply the way they do to `session.rs`/
//! `bridge.rs` — this module exists purely so `tools/cryptick` and the
//! extension agree on "which key am I talking to right now" (PROJECT.md §13's
//! shape, extended) instead of each guessing independently the way
//! `UsbClient::try_connect`/`UsbTransport::try_connect` already have to
//! (sort-and-pick-first across every matching HID interface, with no
//! concept of a second physical token).
//!
//! # What identity actually means here — read before trusting a device id
//!
//! **There is no stable, firmware-populated serial number for this
//! hardware.** Checked directly rather than assumed, in `cryptick-token-code`:
//!
//! - USB: no `iSerialNumber` (or any serial-number) descriptor setup exists
//!   anywhere in the firmware (grepped `platformio.ini`, `core/`, `include/`,
//!   `variants/` for `iSerialNumber`/`SERIAL_NUMBER`/`setSerial`/
//!   `usb_serial` — nothing). `hidapi`'s `serial_number()` for this device
//!   returns `None` today, confirmed by `UsbTransport::list_devices`
//!   (`crates/token-manager/src/transport/usb.rs`) and `UsbClient`
//!   (`crates/webauthn-host/src/usb.rs`) both carrying no serial field for
//!   the connection path, and by this crate having no USB code path at all
//!   (see below).
//! - BLE: the advertised address is **not stable either, by design.**
//!   `ble_fido_gatt_init` (`core/ble_fido/ble_gatt_esp32.cpp`) calls
//!   `NimBLEDevice::setOwnAddrType(BLE_OWN_ADDR_RANDOM)` — a random/resolvable
//!   private address, not the controller's real static MAC — and derives the
//!   advertised *name* by XORing part of the real MAC with a stored "epoch"
//!   byte that increments across bonding cycles
//!   (`mac[0] ^= ep; mac[1] ^= (ep << 2)`), specifically so the name differs
//!   next time. `device_read_aaguid` (`core/fido2/hal_esp32.cpp`) is a fixed
//!   constant shared by every unit of this product, so it cannot distinguish
//!   two tokens either.
//!
//! This is a firmware gap, not something to fake around here with an
//! invented identity scheme. What this module tracks instead is the one
//! identity signal the daemon already depends on for reconnection —
//! `transport::paired_device_path()`'s persisted BLE address — kept as a
//! **best-effort recognition key**, explicitly not a claim that it survives
//! every firmware-side epoch rotation. See `NOTES.md` for what a real fix
//! would need on the firmware side.
//!
//! # Why this only ever sees BLE devices
//!
//! The daemon has no USB code path at all — by design (PROJECT.md §1, §4):
//! "If a capability can be delivered by plugging the cable in, the daemon
//! should stay out of the way," and USB needs no daemon
//! (`docs/ARCHITECTURE.md`'s Mechanism 1, "Daemon Required? No"). `UsbClient`/
//! `UsbTransport` exist only in `webauthn-host`/`token-manager`, which talk to
//! USB directly and never tell the daemon about it. A user who only ever
//! plugs in over USB may not be running this daemon at all. So a store that
//! lived only here could never show a USB device, and `webauthn-host`'s
//! `list_devices` handler (`crates/webauthn-host/src/main.rs`) accounts for
//! that by unioning this store's BLE entries with its own live USB scan
//! rather than asking the daemon for something it structurally cannot know.

use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

/// Where the known-devices file lives. Sibling to
/// `transport::paired_device_path()`, same directory, same per-platform
/// rule.
pub fn known_devices_path() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .map(|p| p.join("cryptick").join("known_devices.json"))
    }
    #[cfg(not(windows))]
    {
        std::env::var_os("HOME").map(PathBuf::from).map(|p| {
            p.join(".config")
                .join("cryptick")
                .join("known_devices.json")
        })
    }
}

/// One remembered device, as stored on disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredDevice {
    id: String,
    name: String,
    transport: String,
    #[serde(rename = "lastSeen")]
    last_seen: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct StoreFile {
    #[serde(default)]
    devices: Vec<StoredDevice>,
    #[serde(default, rename = "activeId")]
    active_id: Option<String>,
}

/// One device as `list_devices` reports it: the stored fields plus whether
/// it is the currently-active one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownDevice {
    /// The best-effort recognition key — see this module's doc comment.
    pub id: String,
    /// A friendly name. Defaults to `id` itself until something nicer is
    /// recorded.
    pub name: String,
    /// `"ble"` — the only transport this store ever sees (see module doc).
    pub transport: String,
    /// Unix timestamp of the last time this daemon process confirmed this
    /// device as its reconnect target or saw it connected.
    pub last_seen: u64,
    /// Whether this is the device `select_device` last chose.
    pub active: bool,
}

/// `set_active` was asked for a device this store has never heard of.
#[derive(Debug, thiserror::Error)]
#[error("no known device with id {0:?}")]
pub struct UnknownDeviceError(pub String);

/// The daemon's persisted record of devices it has connected or been asked
/// to connect to.
#[derive(Debug)]
pub struct DeviceStore {
    path: Option<PathBuf>,
    file: StoreFile,
}

impl DeviceStore {
    /// Loads the store from its default path, or starts empty if none
    /// exists yet or it fails to parse — a corrupt or missing bookkeeping
    /// file must never stop the daemon from serving CTAP requests, which is
    /// the thing that actually matters (PROJECT.md §15.8 is about
    /// bonding/identity ambiguity specifically, but the same fail-soft
    /// instinct applies here: this is bookkeeping, not a security gate).
    pub fn load() -> Self {
        match known_devices_path() {
            Some(path) => Self::load_from(path),
            None => Self {
                path: None,
                file: StoreFile::default(),
            },
        }
    }

    /// A store backed by no file at all: every write stays in memory for the
    /// life of this value. For tests that exercise `ListDevices`/
    /// `SelectDevice` over the IPC server (`crates/daemon/tests/`) without
    /// touching the real user's `known_devices.json`.
    pub fn in_memory() -> Self {
        Self {
            path: None,
            file: StoreFile::default(),
        }
    }

    /// Loads from an explicit path — used directly by tests so they do not
    /// touch the real user config directory.
    pub fn load_from(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let file = fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        Self {
            path: Some(path),
            file,
        }
    }

    fn save(&self) {
        let Some(path) = &self.path else { return };
        let Ok(json) = serde_json::to_string_pretty(&self.file) else {
            debug_assert!(false, "DeviceStore's own file shape failed to serialise");
            return;
        };
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        // Best-effort: a failed write here must not fail whatever IPC
        // request triggered it. The caller already has the in-memory state.
        let _ = fs::write(path, json);
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Upserts a device by id: updates its name and transport, and bumps
    /// `last_seen` to now. If no device is active yet, this one becomes it —
    /// the first device the daemon ever sees should not require a separate
    /// `select_device` call just to become usable.
    pub fn record_seen(&mut self, id: &str, name: Option<&str>, transport: &str) {
        let now = Self::now();
        if let Some(existing) = self.file.devices.iter_mut().find(|d| d.id == id) {
            existing.last_seen = now;
            existing.transport = transport.to_string();
            if let Some(name) = name {
                existing.name = name.to_string();
            }
        } else {
            self.file.devices.push(StoredDevice {
                id: id.to_string(),
                name: name.unwrap_or(id).to_string(),
                transport: transport.to_string(),
                last_seen: now,
            });
        }
        if self.file.active_id.is_none() {
            self.file.active_id = Some(id.to_string());
        }
        self.save();
    }

    /// All known devices, newest-seen first.
    pub fn list(&self) -> Vec<KnownDevice> {
        let mut out: Vec<KnownDevice> = self
            .file
            .devices
            .iter()
            .map(|d| KnownDevice {
                id: d.id.clone(),
                name: d.name.clone(),
                transport: d.transport.clone(),
                last_seen: d.last_seen,
                active: self.file.active_id.as_deref() == Some(d.id.as_str()),
            })
            .collect();
        out.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
        out
    }

    /// Whether `id` is a device this store has recorded.
    pub fn is_known(&self, id: &str) -> bool {
        self.file.devices.iter().any(|d| d.id == id)
    }

    /// The id `select_device` last chose, if any.
    pub fn active_id(&self) -> Option<&str> {
        self.file.active_id.as_deref()
    }

    /// Marks `id` active. Fails if the store has never recorded that id —
    /// PROJECT.md §15.8's "fail closed" spirit applied to bookkeeping: a
    /// typo or a stale id from the extension's own cache must not silently
    /// become "no device selected" or "whatever was active before."
    pub fn set_active(&mut self, id: &str) -> Result<(), UnknownDeviceError> {
        if !self.is_known(id) {
            return Err(UnknownDeviceError(id.to_string()));
        }
        self.file.active_id = Some(id.to_string());
        self.save();
        Ok(())
    }

    /// Ensures the daemon's single persisted BLE reconnect target
    /// (`transport::paired_device_path()`) is reflected here, so a device
    /// paired before this store existed — or paired by a daemon version
    /// that does not yet record into it — still shows up in `list_devices`.
    /// Does not overwrite a friendlier name than "the address itself" if one
    /// is already stored.
    pub fn seed_from_paired_target(&mut self, target: Option<&str>) {
        let Some(address) = target else { return };
        if !self.is_known(address) {
            self.record_seen(address, None, "ble");
        } else if self.file.active_id.is_none() {
            self.file.active_id = Some(address.to_string());
            self.save();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "cryptick-device-store-test-{name}-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
        ))
    }

    #[test]
    fn a_missing_file_loads_as_empty_rather_than_failing() {
        let store = DeviceStore::load_from(temp_path("missing"));
        assert_eq!(store.list(), Vec::new());
        assert_eq!(store.active_id(), None);
    }

    #[test]
    fn the_first_device_seen_becomes_active_automatically() {
        let mut store = DeviceStore::load_from(temp_path("first-active"));
        store.record_seen("AA:BB:CC:DD:EE:FF", Some("My Token"), "ble");
        let devices = store.list();
        assert_eq!(devices.len(), 1);
        assert!(devices[0].active);
        assert_eq!(devices[0].name, "My Token");
        assert_eq!(store.active_id(), Some("AA:BB:CC:DD:EE:FF"));
    }

    #[test]
    fn a_second_device_does_not_steal_active_status() {
        let mut store = DeviceStore::load_from(temp_path("second-not-active"));
        store.record_seen("first", Some("First"), "ble");
        store.record_seen("second", Some("Second"), "ble");
        let devices = store.list();
        let first = devices.iter().find(|d| d.id == "first").unwrap();
        let second = devices.iter().find(|d| d.id == "second").unwrap();
        assert!(first.active);
        assert!(!second.active);
    }

    #[test]
    fn set_active_switches_which_device_is_flagged() {
        let mut store = DeviceStore::load_from(temp_path("switch"));
        store.record_seen("first", None, "ble");
        store.record_seen("second", None, "ble");
        store.set_active("second").unwrap();
        let devices = store.list();
        assert!(!devices.iter().find(|d| d.id == "first").unwrap().active);
        assert!(devices.iter().find(|d| d.id == "second").unwrap().active);
        assert_eq!(store.active_id(), Some("second"));
    }

    #[test]
    fn set_active_on_an_unknown_id_fails_closed() {
        let mut store = DeviceStore::load_from(temp_path("unknown"));
        store.record_seen("first", None, "ble");
        let err = store.set_active("never-seen").unwrap_err();
        assert_eq!(err.0, "never-seen");
        // The failed call must not have changed anything.
        assert_eq!(store.active_id(), Some("first"));
    }

    #[test]
    fn seeing_the_same_id_again_updates_name_and_last_seen_not_duplicates() {
        let mut store = DeviceStore::load_from(temp_path("upsert"));
        store.record_seen("id-1", Some("Old Name"), "ble");
        let first_seen = store.list()[0].last_seen;
        std::thread::sleep(std::time::Duration::from_millis(1100));
        store.record_seen("id-1", Some("New Name"), "ble");
        let devices = store.list();
        assert_eq!(devices.len(), 1, "must upsert, not duplicate");
        assert_eq!(devices[0].name, "New Name");
        assert!(devices[0].last_seen >= first_seen);
    }

    #[test]
    fn persists_across_a_reload_from_the_same_path() {
        let path = temp_path("persist");
        {
            let mut store = DeviceStore::load_from(&path);
            store.record_seen("persisted-id", Some("Persisted"), "ble");
        }
        let reloaded = DeviceStore::load_from(&path);
        let devices = reloaded.list();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].id, "persisted-id");
        assert_eq!(devices[0].name, "Persisted");
        assert!(devices[0].active);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn seed_from_paired_target_is_a_noop_with_nothing_persisted() {
        let mut store = DeviceStore::load_from(temp_path("seed-none"));
        store.seed_from_paired_target(None);
        assert_eq!(store.list(), Vec::new());
    }

    #[test]
    fn seed_from_paired_target_adds_the_address_once() {
        let mut store = DeviceStore::load_from(temp_path("seed-some"));
        store.seed_from_paired_target(Some("11:22:33:44:55:66"));
        let devices = store.list();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].id, "11:22:33:44:55:66");
        assert_eq!(devices[0].transport, "ble");
        assert!(devices[0].active);
    }

    #[test]
    fn seeding_does_not_clobber_a_name_already_recorded() {
        let mut store = DeviceStore::load_from(temp_path("seed-no-clobber"));
        store.record_seen("addr", Some("A Nice Name"), "ble");
        store.seed_from_paired_target(Some("addr"));
        assert_eq!(store.list()[0].name, "A Nice Name");
    }

    #[test]
    fn is_known_reflects_what_has_been_recorded() {
        let mut store = DeviceStore::load_from(temp_path("is-known"));
        assert!(!store.is_known("x"));
        store.record_seen("x", None, "ble");
        assert!(store.is_known("x"));
        assert!(!store.is_known("y"));
    }
}
