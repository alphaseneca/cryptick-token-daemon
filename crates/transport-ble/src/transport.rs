//! The live BLE fragment transport for CTAP2 / FIDO2.
//!
//! Connects to a physical or simulated token advertising standard GATT service
//! `0xFFFD`. Handles dynamic `fidoControlPointLength` adaptation, ATT error
//! classification, notification streaming (including KeepAlive `0x82` frames),
//! and link state tracking.

use ble_framing::{FragmentSize, FragmentTransport, LinkState, TransportError};
use btleplug::api::{Characteristic, Peripheral as _, WriteType};
use btleplug::platform::{Adapter, Peripheral};
use futures::stream::StreamExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};
use uuid::Uuid;

use crate::{
    classify_att, find_device, BleError, DAEMON_CONTROL_POINT, DAEMON_CONTROL_POINT_LENGTH,
    DAEMON_STATUS, FIDO_CONTROL_POINT, FIDO_CONTROL_POINT_LENGTH, FIDO_STATUS,
};

/// The default fragment size (252 bytes) when `fidoControlPointLength` is absent
/// or invalid. Standard for Cryptick ESP32 token hardware.
pub const DEFAULT_FRAGMENT_SIZE: u16 = 252;

/// The minimum permitted fragment size per CTAP2 specification (20 bytes).
pub const MIN_FRAGMENT_SIZE: u16 = 20;

/// The maximum permitted fragment size per CTAP2 specification (512 bytes).
pub const MAX_FRAGMENT_SIZE: u16 = 512;

/// Simulated ATT and BLE write errors for unit testing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MockWriteError {
    /// Insufficient authentication (ATT 0x05).
    InsufficientAuthentication,
    /// Insufficient encryption (ATT 0x0F).
    InsufficientEncryption,
    /// Link disconnected.
    NotConnected,
    /// BlueZ D-Bus not permitted (maps to ATT 0x05).
    BluezNotPermitted,
    /// Custom error message.
    Custom(String),
}

impl MockWriteError {
    /// Converts this mock error into a `btleplug::Error`.
    pub fn to_btleplug_error(&self) -> btleplug::Error {
        match self {
            Self::InsufficientAuthentication => btleplug::Error::Other(Box::new(
                std::io::Error::other("Insufficient authentication."),
            )),
            Self::InsufficientEncryption => {
                btleplug::Error::Other(Box::new(std::io::Error::other("Insufficient encryption.")))
            }
            Self::NotConnected => btleplug::Error::NotConnected,
            Self::BluezNotPermitted => btleplug::Error::Other(Box::new(std::io::Error::other(
                "org.bluez.Error.NotPermitted: Write not permitted",
            ))),
            Self::Custom(msg) => {
                btleplug::Error::Other(Box::new(std::io::Error::other(msg.clone())))
            }
        }
    }
}

type CplResponse = Arc<Mutex<Option<Result<Vec<u8>, String>>>>;

/// Handle to control simulated BLE device behavior in unit tests.
#[derive(Clone)]
pub struct MockBleHandle {
    notification_tx: mpsc::UnboundedSender<Vec<u8>>,
    written_fragments: Arc<Mutex<Vec<Vec<u8>>>>,
    write_error: Arc<Mutex<Option<MockWriteError>>>,
    cpl_data: CplResponse,
    connected: Arc<AtomicBool>,
}

impl MockBleHandle {
    /// Sends a notification fragment to the transport queue.
    pub fn send_notification(&self, fragment: Vec<u8>) {
        let _ = self.notification_tx.send(fragment);
    }

    /// Retrieves all fragments written to `fidoControlPoint`.
    pub async fn written_fragments(&self) -> Vec<Vec<u8>> {
        self.written_fragments.lock().await.clone()
    }

    /// Sets the error for subsequent writes (e.g. ATT errors).
    pub async fn set_write_error(&self, error: Option<MockWriteError>) {
        *self.write_error.lock().await = error;
    }

    /// Configures the raw bytes or error returned when reading `fidoControlPointLength`.
    pub async fn set_cpl_response(&self, res: Option<Result<Vec<u8>, String>>) {
        *self.cpl_data.lock().await = res;
    }

    /// Simulates device disconnection.
    pub fn disconnect(&self) {
        self.connected.store(false, Ordering::SeqCst);
    }
}

#[async_trait::async_trait]
pub(crate) trait BleIo: Send + Sync {
    async fn write_control_point(&self, fragment: &[u8]) -> Result<(), btleplug::Error>;
    async fn read_control_point_length(&self) -> Result<Vec<u8>, btleplug::Error>;
}

struct LiveBleIo {
    peripheral: Peripheral,
    control_point: Characteristic,
    control_point_length: Option<Characteristic>,
}

#[async_trait::async_trait]
impl BleIo for LiveBleIo {
    async fn write_control_point(&self, fragment: &[u8]) -> Result<(), btleplug::Error> {
        self.peripheral
            .write(&self.control_point, fragment, WriteType::WithResponse)
            .await
    }

    async fn read_control_point_length(&self) -> Result<Vec<u8>, btleplug::Error> {
        match &self.control_point_length {
            Some(c) => self.peripheral.read(c).await,
            None => Err(btleplug::Error::Other(Box::new(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "fidoControlPointLength characteristic not found",
            )))),
        }
    }
}

struct MockBleIo {
    written_fragments: Arc<Mutex<Vec<Vec<u8>>>>,
    write_error: Arc<Mutex<Option<MockWriteError>>>,
    cpl_data: CplResponse,
    connected: Arc<AtomicBool>,
}

#[async_trait::async_trait]
impl BleIo for MockBleIo {
    async fn write_control_point(&self, fragment: &[u8]) -> Result<(), btleplug::Error> {
        if !self.connected.load(Ordering::SeqCst) {
            return Err(btleplug::Error::NotConnected);
        }

        let err = self.write_error.lock().await.clone();
        if let Some(e) = err {
            return Err(e.to_btleplug_error());
        }

        self.written_fragments.lock().await.push(fragment.to_vec());
        Ok(())
    }

    async fn read_control_point_length(&self) -> Result<Vec<u8>, btleplug::Error> {
        if !self.connected.load(Ordering::SeqCst) {
            return Err(btleplug::Error::NotConnected);
        }

        let resp = self.cpl_data.lock().await.clone();
        match resp {
            Some(Ok(bytes)) => Ok(bytes),
            Some(Err(e)) => Err(btleplug::Error::Other(Box::new(std::io::Error::other(e)))),
            None => Err(btleplug::Error::Other(Box::new(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no mock CPL configured",
            )))),
        }
    }
}

struct BleTransportInner {
    io: Arc<dyn BleIo>,
    fragment_size: std::sync::RwLock<FragmentSize>,
    rx: Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
    connected: Arc<AtomicBool>,
    bonded: Arc<AtomicBool>,
    authenticated: Arc<AtomicBool>,
}

/// The BLE CTAP2 fragment transport.
///
/// Implements [`FragmentTransport`] and [`Clone`]. Wraps an `Arc`-backed
/// handle to the BLE connection so that clones share link state and the
/// incoming notification queue.
#[derive(Clone)]
pub struct BleTransport {
    inner: Arc<BleTransportInner>,
}

impl BleTransport {
    /// Connects to a peripheral advertising the FIDO service.
    ///
    /// Discovers characteristics `FIDO_CONTROL_POINT`, `FIDO_STATUS`, and
    /// `FIDO_CONTROL_POINT_LENGTH`. Dynamically queries `fidoControlPointLength`
    /// (defaulting to 252 if absent or out of 20..=512 range), subscribes to
    /// `fidoStatus` notifications, and returns a new transport instance.
    pub async fn connect(peripheral: &Peripheral) -> Result<Self, BleError> {
        Self::connect_with_characteristics(
            peripheral,
            FIDO_CONTROL_POINT,
            FIDO_STATUS,
            Some(FIDO_CONTROL_POINT_LENGTH),
        )
        .await
    }

    /// Connects to a peripheral specifically using the dedicated Daemon Bridge GATT service (`FBF6EB80-...`).
    ///
    /// Exclusively uses the dedicated custom daemon characteristics (`DAEMON_CONTROL_POINT`, `DAEMON_STATUS`)
    /// to avoid colliding with or hijacking standard FIDO BLE GATT (`0xFFFD`), leaving `0xFFFD` unmolested
    /// for native OS / browser Bluetooth security key drivers.
    pub async fn connect_daemon(peripheral: &Peripheral) -> Result<Self, BleError> {
        if !peripheral.is_connected().await? {
            peripheral.connect().await?;
        }
        peripheral.discover_services().await?;

        let characteristics = peripheral.characteristics();
        let has_daemon_cp = characteristics
            .iter()
            .any(|c| c.uuid == DAEMON_CONTROL_POINT);

        if has_daemon_cp {
            Self::connect_with_characteristics(
                peripheral,
                DAEMON_CONTROL_POINT,
                DAEMON_STATUS,
                Some(DAEMON_CONTROL_POINT_LENGTH),
            )
            .await
        } else {
            // Only fall back to standard FIDO GATT if custom daemon GATT service is absent
            Self::connect(peripheral).await
        }
    }

    /// Connects to a peripheral with explicitly specified control point and status characteristic UUIDs.
    pub async fn connect_with_characteristics(
        peripheral: &Peripheral,
        cp_uuid: Uuid,
        status_uuid: Uuid,
        cpl_uuid: Option<Uuid>,
    ) -> Result<Self, BleError> {
        if !peripheral.is_connected().await? {
            peripheral.connect().await?;
        }
        peripheral.discover_services().await?;

        let characteristics = peripheral.characteristics();
        let find = |uuid: Uuid| characteristics.iter().find(|c| c.uuid == uuid).cloned();

        let control_point = find(cp_uuid).ok_or(BleError::MissingCharacteristic(cp_uuid))?;
        let status = find(status_uuid).ok_or(BleError::MissingCharacteristic(status_uuid))?;
        let control_point_length = cpl_uuid.and_then(find);

        // Read control point length dynamically (20..=512, defaulting to 252)
        let frag_len = if let Some(ref cpl) = control_point_length {
            match peripheral.read(cpl).await {
                Ok(raw) if raw.len() == 2 => {
                    let val = u16::from_be_bytes([raw[0], raw[1]]);
                    if (MIN_FRAGMENT_SIZE..=MAX_FRAGMENT_SIZE).contains(&val) {
                        val
                    } else {
                        DEFAULT_FRAGMENT_SIZE
                    }
                }
                _ => DEFAULT_FRAGMENT_SIZE,
            }
        } else {
            DEFAULT_FRAGMENT_SIZE
        };

        let fragment_size = FragmentSize::new(frag_len)
            .unwrap_or_else(|_| FragmentSize::new(DEFAULT_FRAGMENT_SIZE).unwrap());

        // Subscribe to notifications on status
        peripheral.subscribe(&status).await?;
        let mut notifications = peripheral.notifications().await?;

        let (tx, rx) = mpsc::unbounded_channel();
        let notif_status_uuid = status.uuid;
        let connected = Arc::new(AtomicBool::new(true));
        let connected_task = Arc::clone(&connected);

        tokio::spawn(async move {
            while let Some(notif) = notifications.next().await {
                if notif.uuid == notif_status_uuid
                    && !notif.value.is_empty()
                    && tx.send(notif.value).is_err()
                {
                    break;
                }
            }
            connected_task.store(false, Ordering::SeqCst);
        });

        let io = Arc::new(LiveBleIo {
            peripheral: peripheral.clone(),
            control_point,
            control_point_length,
        });

        Ok(Self {
            inner: Arc::new(BleTransportInner {
                io,
                fragment_size: std::sync::RwLock::new(fragment_size),
                rx: Mutex::new(rx),
                connected,
                bonded: Arc::new(AtomicBool::new(true)),
                authenticated: Arc::new(AtomicBool::new(true)),
            }),
        })
    }

    /// Scans for a device advertising FIDO service and connects to it.
    pub async fn find_and_connect(adapter: &Adapter, timeout: Duration) -> Result<Self, BleError> {
        let peripheral = find_device(adapter, timeout).await?;
        Self::connect(&peripheral).await
    }

    /// Creates a simulated `BleTransport` for unit and integration testing.
    pub fn new_mock(initial_cpl: Option<u16>) -> (Self, MockBleHandle) {
        let (tx, rx) = mpsc::unbounded_channel();
        let written_fragments = Arc::new(Mutex::new(Vec::new()));
        let write_error = Arc::new(Mutex::new(None));
        let cpl_data = Arc::new(Mutex::new(None));
        let connected = Arc::new(AtomicBool::new(true));

        let frag_len = initial_cpl
            .filter(|&v| (MIN_FRAGMENT_SIZE..=MAX_FRAGMENT_SIZE).contains(&v))
            .unwrap_or(DEFAULT_FRAGMENT_SIZE);
        let fragment_size = FragmentSize::new(frag_len)
            .unwrap_or_else(|_| FragmentSize::new(DEFAULT_FRAGMENT_SIZE).unwrap());

        let mock_io = Arc::new(MockBleIo {
            written_fragments: Arc::clone(&written_fragments),
            write_error: Arc::clone(&write_error),
            cpl_data: Arc::clone(&cpl_data),
            connected: Arc::clone(&connected),
        });

        let handle = MockBleHandle {
            notification_tx: tx,
            written_fragments,
            write_error,
            cpl_data,
            connected: Arc::clone(&connected),
        };

        let transport = Self {
            inner: Arc::new(BleTransportInner {
                io: mock_io,
                fragment_size: std::sync::RwLock::new(fragment_size),
                rx: Mutex::new(rx),
                connected,
                bonded: Arc::new(AtomicBool::new(true)),
                authenticated: Arc::new(AtomicBool::new(true)),
            }),
        };

        (transport, handle)
    }

    /// Writes one fragment to `FIDO_CONTROL_POINT`.
    ///
    /// Writes with response (`WriteType::WithResponse`). Maps any errors via
    /// [`classify_att`]. If an ATT authentication (0x05) or encryption (0x0F)
    /// error occurs, transitions link state to unauthenticated (`authenticated: false`,
    /// `bonded: false`) so that subsequent transactions fail immediately.
    pub async fn write_fragment(&self, fragment: &[u8]) -> Result<(), TransportError> {
        if !self.inner.connected.load(Ordering::SeqCst) {
            return Err(TransportError::Disconnected);
        }
        if !self.inner.authenticated.load(Ordering::SeqCst) {
            return Err(TransportError::InsufficientAuthentication);
        }

        let max_size = self.fragment_size_value().get() as usize;
        if fragment.len() > max_size {
            return Err(TransportError::Gatt(format!(
                "fragment length {} exceeds maximum fragment size {}",
                fragment.len(),
                max_size
            )));
        }

        match self.inner.io.write_control_point(fragment).await {
            Ok(()) => Ok(()),
            Err(err) => {
                let mapped = classify_att(&err);
                if mapped.is_bond_failure() {
                    self.inner.authenticated.store(false, Ordering::SeqCst);
                    self.inner.bonded.store(false, Ordering::SeqCst);
                } else if matches!(mapped, TransportError::Disconnected) {
                    self.inner.connected.store(false, Ordering::SeqCst);
                    self.inner.authenticated.store(false, Ordering::SeqCst);
                    self.inner.bonded.store(false, Ordering::SeqCst);
                }
                Err(mapped)
            }
        }
    }

    /// Waits for and returns the next fragment from `FIDO_STATUS`.
    ///
    /// Response fragments and KeepAlive packets (`0x82`) are yielded in order
    /// from the FIFO notification queue.
    pub async fn read_fragment(&self) -> Result<Vec<u8>, TransportError> {
        if !self.inner.connected.load(Ordering::SeqCst) {
            return Err(TransportError::Disconnected);
        }

        let mut rx = self.inner.rx.lock().await;
        tokio::select! {
            maybe_frag = rx.recv() => match maybe_frag {
                Some(fragment) => Ok(fragment),
                None => {
                    self.inner.connected.store(false, Ordering::SeqCst);
                    self.inner.authenticated.store(false, Ordering::SeqCst);
                    self.inner.bonded.store(false, Ordering::SeqCst);
                    Err(TransportError::Disconnected)
                }
            },
            _ = async {
                loop {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    if !self.inner.connected.load(Ordering::SeqCst) {
                        break;
                    }
                }
            } => {
                self.inner.authenticated.store(false, Ordering::SeqCst);
                self.inner.bonded.store(false, Ordering::SeqCst);
                Err(TransportError::Disconnected)
            }
        }
    }

    /// The current link state.
    ///
    /// Tentatively reports `authenticated: true` on initial connection so that
    /// the token's hardware ATT gate can be challenged on first operation;
    /// transitions to `authenticated: false` if ATT 0x05 or 0x0F is detected.
    pub fn link_state(&self) -> LinkState {
        let connected = self.inner.connected.load(Ordering::SeqCst);
        let bonded = self.inner.bonded.load(Ordering::SeqCst);
        let authenticated = self.inner.authenticated.load(Ordering::SeqCst);

        LinkState {
            connected,
            bonded: connected && bonded,
            authenticated: connected && authenticated,
        }
    }

    /// Alias for [`Self::link_state`].
    pub fn link(&self) -> LinkState {
        self.link_state()
    }

    /// The currently negotiated/adapted fragment size.
    pub async fn fragment_size(&self) -> Result<FragmentSize, TransportError> {
        if !self.inner.connected.load(Ordering::SeqCst) {
            return Err(TransportError::Disconnected);
        }
        Ok(self.fragment_size_value())
    }

    /// The currently negotiated fragment size, read synchronously.
    pub fn fragment_size_value(&self) -> FragmentSize {
        *self.inner.fragment_size.read().unwrap()
    }

    /// Dynamically re-queries `fidoControlPointLength` from the peripheral
    /// and adapts the internal fragment size.
    pub async fn refresh_fragment_size(&self) -> Result<FragmentSize, TransportError> {
        if !self.inner.connected.load(Ordering::SeqCst) {
            return Err(TransportError::Disconnected);
        }

        let new_size = match self.inner.io.read_control_point_length().await {
            Ok(raw) if raw.len() == 2 => {
                let val = u16::from_be_bytes([raw[0], raw[1]]);
                if (MIN_FRAGMENT_SIZE..=MAX_FRAGMENT_SIZE).contains(&val) {
                    FragmentSize::new(val)
                        .unwrap_or_else(|_| FragmentSize::new(DEFAULT_FRAGMENT_SIZE).unwrap())
                } else {
                    FragmentSize::new(DEFAULT_FRAGMENT_SIZE).unwrap()
                }
            }
            _ => FragmentSize::new(DEFAULT_FRAGMENT_SIZE).unwrap(),
        };

        *self.inner.fragment_size.write().unwrap() = new_size;
        Ok(new_size)
    }
}

impl std::fmt::Debug for BleTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BleTransport")
            .field("link", &self.link_state())
            .field("fragment_size", &self.fragment_size_value())
            .finish()
    }
}

#[async_trait::async_trait]
impl FragmentTransport for BleTransport {
    async fn fragment_size(&mut self) -> Result<FragmentSize, TransportError> {
        BleTransport::fragment_size(self).await
    }

    async fn write_fragment(&mut self, fragment: &[u8]) -> Result<(), TransportError> {
        BleTransport::write_fragment(self, fragment).await
    }

    async fn next_notification(&mut self) -> Result<Vec<u8>, TransportError> {
        BleTransport::read_fragment(self).await
    }

    fn link(&self) -> LinkState {
        self.link_state()
    }
}
