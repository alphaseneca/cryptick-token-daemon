//! The BLE radio.
//!
//! # What `btleplug` does not give us
//!
//! Checked against 0.13: it exposes **no pairing, no bonding, and no
//! encryption-state API**, and no ATT MTU accessor either
//! (deviceplug/btleplug#246, open since 2022). PROJECT.md §15.2 makes "refuse
//! unbonded links, with MITM protection" a release blocker.
//!
//! # Asking the platform does not work
//!
//! Checked against vendor documentation on 2026-09-11. Windows answers:
//! `DeviceInformationPairing.ProtectionLevel` reads back
//! `EncryptionAndAuthentication` after pairing. BlueZ does not — `Device1` has
//! `Paired` and `Bonded` and no security-level, key-type or encryption
//! property. CoreBluetooth does not either, and has no bonding property at all.
//!
//! # So the device answers instead
//!
//! The peripheral marks `fidoControlPoint` as requiring encrypted **and
//! authenticated** access. A link that is unbonded, or bonded by Just Works,
//! is refused at ATT with `Insufficient Authentication` (0x05) or
//! `Insufficient Encryption` (0x0F); a write the device accepts is proof the
//! link cleared that bar. This crate's job for §15.2 is therefore to preserve
//! **ATT error fidelity** — see [`classify_att`] — not to query pairing state.
//!
//! Until a backend can do that, everything here reports
//! [`LinkState::authenticated`] as `false`, which makes the daemon refuse to
//! transact. That is the correct failure: §15.8 says fail closed, and a
//! transport that cannot prove the bond must not claim one.
//!
//! # macOS
//!
//! A process touching CoreBluetooth without a Bluetooth grant is killed with
//! `SIGABRT` and no output. The grant is per-application and a CLI tool
//! inherits it from whatever launched it, so grant it to the *terminal*
//! (System Settings → Privacy & Security → Bluetooth). See PROJECT.md §18.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use ble_framing::{LinkState, TransportError};
use btleplug::api::{Central as _, Manager as _, Peripheral as _, ScanFilter};
use btleplug::platform::{Adapter, Manager, Peripheral};
use std::time::Duration;
use thiserror::Error;
use uuid::Uuid;

pub use btleplug;
pub use btleplug::api::bleuuid::uuid_from_u16;

pub mod transport;
pub use transport::{
    BleTransport, MockBleHandle, MockWriteError, DEFAULT_FRAGMENT_SIZE, MAX_FRAGMENT_SIZE,
    MIN_FRAGMENT_SIZE,
};

pub mod piv;
pub use piv::{MockPivBleHandle, PivBleTransport, PivTransportError, MAX_APDU_LEN};

/// The FIDO GATT service, `0xFFFD` expanded against the Bluetooth base UUID.
pub fn fido_service() -> Uuid {
    uuid_from_u16(0xFFFD)
}

/// `fidoControlPoint` — host writes CTAP fragments here.
pub const FIDO_CONTROL_POINT: Uuid = Uuid::from_u128(0xF1D0FFF1_DEAA_ECEE_B42F_C9BA7ED623BB);
/// `fidoStatus` — the authenticator notifies fragments here.
pub const FIDO_STATUS: Uuid = Uuid::from_u128(0xF1D0FFF2_DEAA_ECEE_B42F_C9BA7ED623BB);
/// `fidoControlPointLength` — the maximum write, 20–512.
pub const FIDO_CONTROL_POINT_LENGTH: Uuid = Uuid::from_u128(0xF1D0FFF3_DEAA_ECEE_B42F_C9BA7ED623BB);
/// `fidoServiceRevisionBitfield` — bit 5 (`0x20`) means FIDO2.
pub const FIDO_SERVICE_REVISION_BITFIELD: Uuid =
    Uuid::from_u128(0xF1D0FFF4_DEAA_ECEE_B42F_C9BA7ED623BB);

/// The Cryptick PIV Service UUID: FBF6EB90-7F39-41B1-A191-9527CC42F8BE.
pub const PIV_SERVICE: Uuid = Uuid::from_u128(0xFBF6EB90_7F39_41B1_A191_9527CC42F8BE);
/// `pivControlPoint` — host writes APDU fragments here.
pub const PIV_CONTROL_POINT: Uuid = Uuid::from_u128(0xFBF6EB91_7F39_41B1_A191_9527CC42F8BE);
/// `pivStatus` — the token notifies APDU fragments here.
pub const PIV_STATUS: Uuid = Uuid::from_u128(0xFBF6EB92_7F39_41B1_A191_9527CC42F8BE);
/// `pivControlPointLength` — max write size, 20–512.
pub const PIV_CONTROL_POINT_LENGTH: Uuid = Uuid::from_u128(0xFBF6EB93_7F39_41B1_A191_9527CC42F8BE);
/// `pivAtr` — static Answer-to-Reset.
pub const PIV_ATR: Uuid = Uuid::from_u128(0xFBF6EB94_7F39_41B1_A191_9527CC42F8BE);

/// The Cryptick Daemon Bridge Service UUID: FBF6EB80-7F39-41B1-A191-9527CC42F8BE.
pub const DAEMON_SERVICE: Uuid = Uuid::from_u128(0xFBF6EB80_7F39_41B1_A191_9527CC42F8BE);
/// `daemonControlPoint` — daemon writes CTAP fragments here.
pub const DAEMON_CONTROL_POINT: Uuid = Uuid::from_u128(0xFBF6EB81_7F39_41B1_A191_9527CC42F8BE);
/// `daemonStatus` — token notifies CTAP response fragments here.
pub const DAEMON_STATUS: Uuid = Uuid::from_u128(0xFBF6EB82_7F39_41B1_A191_9527CC42F8BE);
/// `daemonControlPointLength` — max write size, 20–512.
pub const DAEMON_CONTROL_POINT_LENGTH: Uuid =
    Uuid::from_u128(0xFBF6EB83_7F39_41B1_A191_9527CC42F8BE);
/// `daemonVersion` — protocol version (1 byte, 0x01).
pub const DAEMON_VERSION: Uuid = Uuid::from_u128(0xFBF6EB84_7F39_41B1_A191_9527CC42F8BE);

/// Bit 5 of `fidoServiceRevisionBitfield`: this authenticator speaks FIDO2.
pub const REVISION_FIDO2: u8 = 0x20;

/// Something went wrong on the radio.
#[derive(Debug, Error)]
pub enum BleError {
    /// The Bluetooth stack itself failed.
    #[error("bluetooth error: {0}")]
    Bluetooth(#[from] btleplug::Error),

    /// No Bluetooth adapter is available.
    #[error("no bluetooth adapter found")]
    NoAdapter,

    /// Nothing advertising the FIDO service turned up.
    #[error("no device advertising the FIDO service {service} was found in {seconds}s")]
    NotFound {
        /// The service scanned for.
        service: Uuid,
        /// How long the scan ran.
        seconds: u64,
    },

    /// The device is missing a characteristic the transport requires.
    #[error("device does not expose characteristic {0}")]
    MissingCharacteristic(Uuid),

    /// `fidoControlPointLength` held something the spec forbids.
    #[error("fidoControlPointLength is {got:?}, which is not a 2-byte value in 20..=512")]
    BadControlPointLength {
        /// What was actually read.
        got: Vec<u8>,
    },

    /// `pivAtr` held an empty or invalid ATR.
    #[error("pivAtr characteristic held invalid ATR bytes: {got:?}")]
    BadAtr {
        /// What was actually read.
        got: Vec<u8>,
    },

    /// The bond could not be proven, and §15.2 forbids assuming one.
    #[error(
        "cannot verify the link is bonded with MITM protection: btleplug exposes no \
         pairing state, and the platform backend for this OS is not written yet"
    )]
    BondUnverifiable,
}

/// What a probe found on a device.
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    /// The advertised local name, if any.
    pub name: Option<String>,
    /// The peripheral's address as the platform reports it.
    pub address: String,
    /// The value of `fidoControlPointLength`.
    pub control_point_length: u16,
    /// The raw `fidoServiceRevisionBitfield`.
    pub revision_bitfield: Vec<u8>,
    /// Whether the revision bitfield advertises FIDO2.
    pub speaks_fido2: bool,
    /// What we can honestly say about the link.
    pub link: LinkState,
}

/// Returns the first Bluetooth adapter.
pub async fn adapter() -> Result<Adapter, BleError> {
    let manager = Manager::new().await?;
    manager
        .adapters()
        .await?
        .into_iter()
        .next()
        .ok_or(BleError::NoAdapter)
}

/// Scans for a device advertising the FIDO service, optionally filtering by target address or UUID.
pub async fn find_device_with_target(
    adapter: &Adapter,
    target: Option<&str>,
    timeout: Duration,
) -> Result<Peripheral, BleError> {
    let service = fido_service();
    adapter.start_scan(ScanFilter::default()).await?;

    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let periphs = adapter.peripherals().await?;
        for peripheral in periphs {
            if let Some(props) = peripheral.properties().await? {
                let name_str = props.local_name.as_deref().unwrap_or("");
                let is_fido = props.services.contains(&service)
                    || props.services.contains(&DAEMON_SERVICE)
                    || props.services.contains(&PIV_SERVICE)
                    || name_str.to_lowercase().contains("cryptick");

                if let Some(t) = target {
                    let addr = display_address(&peripheral);
                    let id_str = peripheral.id().to_string();
                    let mac_str = peripheral.address().to_string();
                    let t_lower = t.to_lowercase();
                    if addr.to_lowercase().contains(&t_lower)
                        || id_str.to_lowercase().contains(&t_lower)
                        || mac_str.to_lowercase().contains(&t_lower)
                        || (!name_str.is_empty() && name_str.to_lowercase().contains(&t_lower))
                    {
                        let _ = adapter.stop_scan().await;
                        return Ok(peripheral);
                    }
                } else if is_fido {
                    let _ = adapter.stop_scan().await;
                    return Ok(peripheral);
                }
            }
        }
        if tokio::time::Instant::now() >= deadline {
            let _ = adapter.stop_scan().await;
            return Err(BleError::NotFound {
                service,
                seconds: timeout.as_secs(),
            });
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Scans for a device advertising the FIDO service.
pub async fn find_device(adapter: &Adapter, timeout: Duration) -> Result<Peripheral, BleError> {
    find_device_with_target(adapter, None, timeout).await
}

/// Scans for all devices advertising the FIDO service within the given timeout window.
pub async fn find_all_devices(
    adapter: &Adapter,
    timeout: Duration,
) -> Result<Vec<Peripheral>, BleError> {
    let service = fido_service();
    adapter.start_scan(ScanFilter::default()).await?;

    tokio::time::sleep(timeout).await;
    let _ = adapter.stop_scan().await;

    let mut found = Vec::new();
    for peripheral in adapter.peripherals().await? {
        if let Some(props) = peripheral.properties().await? {
            let name_str = props.local_name.as_deref().unwrap_or("");
            let is_fido = props.services.contains(&service)
                || props.services.contains(&DAEMON_SERVICE)
                || props.services.contains(&PIV_SERVICE)
                || name_str.to_lowercase().contains("cryptick");
            if is_fido {
                found.push(peripheral);
            }
        }
    }
    Ok(found)
}

/// Returns a formatted address or platform device ID.
///
/// On macOS, CoreBluetooth intentionally conceals MAC addresses and `p.address()` returns
/// `00:00:00:00:00:00`. This helper returns the non-zero MAC address if available,
/// or falls back to the peripheral ID (platform UUID on macOS, BD_ADDR on Linux/Windows).
pub fn display_address(peripheral: &Peripheral) -> String {
    let addr = peripheral.address().to_string();
    if addr != "00:00:00:00:00:00" {
        addr
    } else {
        peripheral.id().to_string()
    }
}

/// Connects, discovers services, and reads what the transport needs.
///
/// Deliberately reports [`LinkState::authenticated`] as `false`. Probing reads
/// `fidoControlPointLength`, which is world-readable; only an operation on
/// `fidoControlPoint` carries the authentication requirement, so a successful
/// probe proves nothing about the bond and §15.2 does not permit assuming one.
pub async fn probe(peripheral: &Peripheral) -> Result<DeviceInfo, BleError> {
    if !peripheral.is_connected().await? {
        peripheral.connect().await?;
    }
    peripheral.discover_services().await?;

    let characteristics = peripheral.characteristics();
    let find = |uuid: Uuid| {
        characteristics
            .iter()
            .find(|c| c.uuid == uuid)
            .cloned()
            .ok_or(BleError::MissingCharacteristic(uuid))
    };

    // Every one of these must exist for the transport to work at all.
    find(FIDO_CONTROL_POINT)?;
    find(FIDO_STATUS)?;

    let raw = peripheral.read(&find(FIDO_CONTROL_POINT_LENGTH)?).await?;
    let control_point_length = match raw.as_slice() {
        // Two bytes, big-endian, and the spec's own 20..=512 clamp.
        [hi, lo] => {
            let value = u16::from_be_bytes([*hi, *lo]);
            if !(20..=512).contains(&value) {
                return Err(BleError::BadControlPointLength { got: raw.clone() });
            }
            value
        }
        _ => return Err(BleError::BadControlPointLength { got: raw.clone() }),
    };

    let revision_bitfield = match find(FIDO_SERVICE_REVISION_BITFIELD) {
        Ok(c) => peripheral.read(&c).await.unwrap_or_default(),
        // Optional in practice; its absence is worth reporting, not fatal.
        Err(_) => Vec::new(),
    };
    let speaks_fido2 = revision_bitfield
        .first()
        .is_some_and(|b| b & REVISION_FIDO2 != 0);

    let properties = peripheral.properties().await?;
    Ok(DeviceInfo {
        name: properties.as_ref().and_then(|p| p.local_name.clone()),
        address: display_address(peripheral),
        control_point_length,
        revision_bitfield,
        speaks_fido2,
        link: LinkState {
            connected: true,
            // btleplug cannot tell us either of these. Claiming them would be
            // the exact failure §15.2 exists to prevent.
            bonded: false,
            authenticated: false,
        },
    })
}

/// Recovers the ATT error behind a `btleplug` failure, where it survives.
///
/// `btleplug` has no typed ATT error: every backend flattens the code into a
/// string before we see it. So this reads the message, matching only phrases
/// each platform's own stack produces:
///
/// - **macOS** — `CBATTErrorDomain` codes 5 and 15, whose `NSError`
///   descriptions are "Insufficient authentication" and "Insufficient
///   encryption".
/// - **Windows** — WinRT reports `GattCommunicationStatus::ProtocolError` and
///   carries the raw ATT byte in `ProtocolError`.
/// - **Linux** — BlueZ maps the ATT codes onto D-Bus errors, so the text
///   arrives as `org.bluez.Error.NotPermitted` / `NotAuthorized`.
///
/// **Failing to classify is safe.** An unrecognised error stays
/// [`TransportError::Gatt`], which still fails the transaction — a miss costs
/// an accurate message, never the invariant (see `TransportError::is_bond_failure`).
/// Guessing the other way would not be safe, so nothing here maps a vague
/// error onto success.
///
/// **[HW]** The exact strings are transcribed from platform documentation and
/// have not yet been observed against hardware (PROJECT.md §17). Widen the
/// matches when a real device produces something else; never narrow the
/// resulting behaviour.
pub fn classify_att(error: &btleplug::Error) -> TransportError {
    let text = error.to_string();
    let lower = text.to_ascii_lowercase();

    let insufficient = |what: &str| {
        lower.contains(&format!("insufficient {what}"))
            || lower.contains(&format!("insufficient{what}"))
    };

    if insufficient("authentication")
        || lower.contains("notauthorized")
        || lower.contains("not authorized")
        || lower.contains("notpermitted")
    {
        return TransportError::InsufficientAuthentication;
    }
    if insufficient("encryption") {
        return TransportError::InsufficientEncryption;
    }

    if lower.contains("disconnected")
        || lower.contains("no longer available")
        || lower.contains("connection was lost")
        || lower.contains("connection timed out")
        || lower.contains("connection has timed out")
        || lower.contains("not connected")
    {
        return TransportError::Disconnected;
    }

    match error {
        btleplug::Error::NotConnected => TransportError::Disconnected,
        other => TransportError::Gatt(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fido_service_uuid_expands_correctly() {
        // 0xFFFD against the Bluetooth base UUID.
        assert_eq!(
            fido_service().to_string(),
            "0000fffd-0000-1000-8000-00805f9b34fb"
        );
    }

    #[test]
    fn characteristic_uuids_match_the_spec_table() {
        // CTAP2 §11.4.5.1, transcribed from the specification.
        assert_eq!(
            FIDO_CONTROL_POINT.to_string(),
            "f1d0fff1-deaa-ecee-b42f-c9ba7ed623bb"
        );
        assert_eq!(
            FIDO_STATUS.to_string(),
            "f1d0fff2-deaa-ecee-b42f-c9ba7ed623bb"
        );
        assert_eq!(
            FIDO_CONTROL_POINT_LENGTH.to_string(),
            "f1d0fff3-deaa-ecee-b42f-c9ba7ed623bb"
        );
        assert_eq!(
            FIDO_SERVICE_REVISION_BITFIELD.to_string(),
            "f1d0fff4-deaa-ecee-b42f-c9ba7ed623bb"
        );
    }

    #[test]
    fn an_att_authentication_refusal_is_recognised() {
        // The only evidence §15.2 gets on macOS and Linux, so losing it here
        // loses the invariant's error message entirely.
        let error = btleplug::Error::Other(Box::new(std::io::Error::other(
            "Insufficient authentication.",
        )));
        assert_eq!(
            classify_att(&error),
            TransportError::InsufficientAuthentication
        );

        let bluez = btleplug::Error::Other(Box::new(std::io::Error::other(
            "org.bluez.Error.NotPermitted: Write not permitted",
        )));
        assert_eq!(
            classify_att(&bluez),
            TransportError::InsufficientAuthentication
        );
    }

    #[test]
    fn an_att_encryption_refusal_is_recognised() {
        let error =
            btleplug::Error::Other(Box::new(std::io::Error::other("Insufficient encryption.")));
        assert_eq!(classify_att(&error), TransportError::InsufficientEncryption);
    }

    #[test]
    fn an_unrecognised_error_is_not_promoted_to_a_bond_failure() {
        // Failing to classify must cost the message and not the guarantee: it
        // still fails the transaction, it just does not claim to know why.
        let error = btleplug::Error::Other(Box::new(std::io::Error::other("write failed")));
        let classified = classify_att(&error);
        assert!(!classified.is_bond_failure());
        assert!(matches!(classified, TransportError::Gatt(_)));
    }

    #[test]
    fn a_probe_never_claims_a_bond_it_cannot_prove() {
        // The type this crate hands the daemon must be unusable until a
        // platform backend exists (§15.2, §15.8).
        let link = LinkState {
            connected: true,
            bonded: false,
            authenticated: false,
        };
        assert!(!link.is_usable());
    }
}
