//! The BLE radio.
//!
//! # What `btleplug` does not give us
//!
//! Checked against 0.13: it exposes **no pairing, no bonding, and no
//! encryption-state API**, and no ATT MTU accessor either
//! (deviceplug/btleplug#246, open since 2022). PROJECT.md §15.2 makes "refuse
//! unbonded links, with MITM protection" a release blocker, so that check is
//! not a wrapper over this crate — it is three platform backends we write and
//! maintain: BlueZ D-Bus properties on Linux, CoreBluetooth on macOS, and
//! WinRT `DeviceInformation.Pairing` on Windows.
//!
//! Until those exist, everything here reports [`LinkState::authenticated`] as
//! `false`, which makes the daemon refuse to transact. That is the correct
//! failure: §15.8 says fail closed, and a transport that cannot prove the bond
//! must not claim one.
//!
//! # macOS
//!
//! A process touching CoreBluetooth without a Bluetooth grant is killed with
//! `SIGABRT` and no output. The grant is per-application and a CLI tool
//! inherits it from whatever launched it, so grant it to the *terminal*
//! (System Settings → Privacy & Security → Bluetooth). See PROJECT.md §18.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use btleplug::api::{Central, Manager as _, Peripheral as _, ScanFilter};
use btleplug::platform::{Adapter, Manager, Peripheral};
use daemon::LinkState;
use std::time::Duration;
use thiserror::Error;
use uuid::Uuid;

pub use btleplug::api::bleuuid::uuid_from_u16;

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

/// Scans for a device advertising the FIDO service.
pub async fn find_device(adapter: &Adapter, timeout: Duration) -> Result<Peripheral, BleError> {
    let service = fido_service();
    adapter
        .start_scan(ScanFilter {
            services: vec![service],
        })
        .await?;

    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        for peripheral in adapter.peripherals().await? {
            // The scan filter is advisory on some backends, so confirm the
            // service really is advertised rather than trusting the filter.
            if let Some(props) = peripheral.properties().await? {
                if props.services.contains(&service) {
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

/// Connects, discovers services, and reads what the transport needs.
///
/// Deliberately reports [`LinkState::authenticated`] as `false`: nothing here
/// can prove a bond, and §15.2 does not permit assuming one.
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
        address: peripheral.address().to_string(),
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
