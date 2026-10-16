//! Multi-transport abstraction for Cryptick Token.
//!
//! Implements the dual-transport routing architecture:
//! 1. Direct USB CTAPHID (`0x1209:0xBEEE`) using 64-byte CTAPHID framing.
//! 2. BLE Daemon Fallback via local UNIX domain socket IPC.

pub mod daemon;
pub mod usb;

pub use daemon::DaemonTransport;
use std::time::Duration;
pub use usb::UsbTransport;

/// A transport connection capable of transceiving CTAPHID / APDU commands to Cryptick Token.
pub trait TokenTransport {
    /// Transceives a command byte and payload to the token, returning the raw response bytes.
    ///
    /// For OATH and vendor commands: `cmd = 0x63` (`CTAPHID_CRYPTICK_OATH = 0xE3`).
    /// For CTAPHID_MSG (standard raw APDU): `cmd = 0x03`.
    /// For CTAPHID_CBOR: `cmd = 0x10`.
    fn transceive(&mut self, cmd: u8, payload: &[u8], timeout: Duration)
        -> Result<Vec<u8>, String>;

    /// Human-readable transport name (e.g. "Direct USB" or "BLE Daemon Bridge").
    fn transport_name(&self) -> &'static str;

    /// Optional device serial number or identifier string.
    fn serial(&self) -> Option<String>;
}

/// Automatic dual-transport manager that prioritizes direct USB and falls back to BLE Daemon.
pub struct DualTransport {
    active: Box<dyn TokenTransport>,
}

impl DualTransport {
    /// Connects to Cryptick Token, attempting Direct USB first, then BLE Daemon fallback.
    pub fn connect() -> Result<Self, String> {
        Self::connect_with_device(None)
    }

    /// Connects with an optional target device / serial filter.
    pub fn connect_with_device(device_filter: Option<&str>) -> Result<Self, String> {
        // 1. Try Direct USB CTAPHID
        match UsbTransport::try_connect(device_filter) {
            Ok(Some(usb)) => {
                return Ok(Self {
                    active: Box::new(usb),
                });
            }
            Ok(None) => {}
            Err(e) => {
                // If an explicit device filter was specified and failed, record or continue
                if let Some(target) = device_filter {
                    return Err(format!("Direct USB connection to '{target}' failed: {e}"));
                }
            }
        }

        // 2. Try BLE Daemon Fallback
        match DaemonTransport::connect(Duration::from_secs(3)) {
            Ok(daemon) => {
                Ok(Self {
                    active: Box::new(daemon),
                })
            }
            Err(e) => {
                Err(format!(
                    "Cryptick Token (0x1209:0xBEEE) was not found on USB, and BLE Daemon is unavailable.\n\
                     - To connect via USB: plug the Cryptick Token into a USB-C port.\n\
                     - To connect via Bluetooth: ensure 'cryptick-daemon' is running and the token is powered on.\n\
                     Details: {e}"
                ))
            }
        }
    }

    /// Returns the active underlying transport.
    pub fn active(&mut self) -> &mut dyn TokenTransport {
        &mut *self.active
    }
}

impl TokenTransport for DualTransport {
    fn transceive(
        &mut self,
        cmd: u8,
        payload: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, String> {
        self.active.transceive(cmd, payload, timeout)
    }

    fn transport_name(&self) -> &'static str {
        self.active.transport_name()
    }

    fn serial(&self) -> Option<String> {
        self.active.serial()
    }
}
