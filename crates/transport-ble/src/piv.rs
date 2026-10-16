//! The private PIV BLE fragment transport.
//!
//! Communicates with the token's private unadvertised GATT service
//! `FBF6EB90-7F39-41B1-A191-9527CC42F8BE` (PROJECT.md §8, `docs/device-protocol.md`).
//!
//! Exposes short APDU transceive (capped at 261 bytes in both directions)
//! using CTAP BLE framing (reusing `0x83` for APDU, supporting `0x82` KeepAlives,
//! `0xBE` Cancel, and `0xBF` Error) across `pivControlPoint` and `pivStatus`.

use ble_framing::{
    fragments, BleErrorCode, Command, FragmentSize, FramingError, KeepAliveStatus, LinkState,
    Message, Reassembler, TransportError, MAX_FRAGMENT_SIZE, MIN_FRAGMENT_SIZE,
};
use btleplug::api::{Characteristic, Peripheral as _, WriteType};
use btleplug::platform::Peripheral;
use futures::stream::StreamExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{mpsc, Mutex};
use uuid::Uuid;

use crate::{
    classify_att, BleError, MockWriteError, PIV_ATR, PIV_CONTROL_POINT, PIV_CONTROL_POINT_LENGTH,
    PIV_STATUS,
};

/// The default fragment size (252 bytes) when `pivControlPointLength` is absent
/// or invalid. Standard for Cryptick ESP32 token hardware.
pub const DEFAULT_FRAGMENT_SIZE: u16 = 252;

/// The maximum length of a short APDU per PIV over BLE specification (261 bytes).
///
/// `CLA INS P1 P2 Lc` (5 bytes) + up to 255 bytes data + `Le` (1 byte) = 261 bytes.
/// Extended APDUs are rejected by the token applet with `0x6700`.
pub const MAX_APDU_LEN: usize = 261;

/// Errors arising from PIV BLE transport operations.
#[derive(Debug, Error)]
pub enum PivTransportError {
    /// An APDU exceeded the 261-byte short APDU ceiling.
    #[error("APDU exceeds 261-byte ceiling: length is {len}")]
    ApduTooLong {
        /// Actual length in bytes.
        len: usize,
    },

    /// An empty APDU was submitted.
    #[error("APDU is empty")]
    EmptyApdu,

    /// Underlying BLE transport error.
    #[error("transport error: {0}")]
    Transport(#[from] TransportError),

    /// CTAP BLE framing error during fragmentation or reassembly.
    #[error("framing error: {0}")]
    Framing(#[from] FramingError),

    /// Token returned a CTAP BLE transport-level ERROR frame.
    #[error("device returned transport error code: {0:?}")]
    DeviceError(BleErrorCode),

    /// Token returned an unexpected CTAP BLE command.
    #[error("unexpected response command: {0:?}")]
    UnexpectedCommand(Command),

    /// Transaction was cancelled.
    #[error("transaction was cancelled")]
    Cancelled,
}

impl From<PivTransportError> for TransportError {
    fn from(err: PivTransportError) -> Self {
        match err {
            PivTransportError::Transport(t) => t,
            PivTransportError::ApduTooLong { len } => {
                TransportError::Gatt(format!("APDU exceeds 261-byte ceiling: {len}"))
            }
            PivTransportError::EmptyApdu => TransportError::Gatt("APDU is empty".into()),
            PivTransportError::Framing(f) => TransportError::Gatt(format!("framing error: {f}")),
            PivTransportError::DeviceError(code) => {
                TransportError::Gatt(format!("device error: {code:?}"))
            }
            PivTransportError::UnexpectedCommand(cmd) => {
                TransportError::Gatt(format!("unexpected command: {cmd:?}"))
            }
            PivTransportError::Cancelled => TransportError::Gatt("transaction cancelled".into()),
        }
    }
}

type CplResponse = Arc<Mutex<Option<Result<Vec<u8>, String>>>>;
type AutoResponder = Arc<Mutex<Option<Arc<dyn Fn(&[u8]) -> Vec<u8> + Send + Sync>>>>;

/// Test handle for controlling a mock [`PivBleTransport`].
#[derive(Clone)]
pub struct MockPivBleHandle {
    notification_tx: mpsc::UnboundedSender<Vec<u8>>,
    written_fragments: Arc<Mutex<Vec<Vec<u8>>>>,
    write_error: Arc<Mutex<Option<MockWriteError>>>,
    cpl_data: CplResponse,
    atr_data: Arc<Mutex<Vec<u8>>>,
    connected: Arc<AtomicBool>,
    auto_responder: AutoResponder,
}

impl MockPivBleHandle {
    /// Sends a raw notification fragment to the transport's inbound queue.
    pub fn send_notification(&self, fragment: Vec<u8>) {
        let _ = self.notification_tx.send(fragment);
    }

    /// Fragments and queues an APDU response message (`Command::Msg`, 0x83).
    pub fn send_apdu_response(
        &self,
        apdu_resp: &[u8],
        fragment_size: FragmentSize,
    ) -> Result<(), FramingError> {
        let msg = Message::new(Command::Msg, apdu_resp.to_vec());
        let frags = fragments(&msg, fragment_size)?;
        for frag in frags {
            let _ = self.notification_tx.send(frag);
        }
        Ok(())
    }

    /// Sends a KeepAlive frame (`0x82`) with the specified status.
    pub fn send_keepalive(&self, status: KeepAliveStatus) {
        let _ =
            self.notification_tx
                .send(vec![Command::KeepAlive.as_u8(), 0x00, 0x01, status.as_u8()]);
    }

    /// Sends an Error frame (`0xBF`) with the specified error code.
    pub fn send_device_error(&self, error: BleErrorCode) {
        let _ = self
            .notification_tx
            .send(vec![Command::Error.as_u8(), 0x00, 0x01, error.as_u8()]);
    }

    /// Retrieves all fragments written to `pivControlPoint`.
    pub async fn written_fragments(&self) -> Vec<Vec<u8>> {
        self.written_fragments.lock().await.clone()
    }

    /// Sets the error for subsequent writes (e.g. ATT errors).
    pub async fn set_write_error(&self, error: Option<MockWriteError>) {
        *self.write_error.lock().await = error;
    }

    /// Configures the raw bytes or error returned when reading `pivControlPointLength`.
    pub async fn set_cpl_response(&self, res: Option<Result<Vec<u8>, String>>) {
        *self.cpl_data.lock().await = res;
    }

    /// Sets the simulated ATR bytes.
    pub async fn set_atr(&self, atr: Vec<u8>) {
        *self.atr_data.lock().await = atr;
    }

    /// Configures an automated APDU responder callback for deterministic testing.
    ///
    /// Whenever a complete command APDU is written across `pivControlPoint`, the
    /// callback is invoked with the command bytes, and its returned response APDU
    /// bytes are fragmented and sent as notifications automatically.
    pub async fn set_auto_responder<F>(&self, responder: F)
    where
        F: Fn(&[u8]) -> Vec<u8> + Send + Sync + 'static,
    {
        *self.auto_responder.lock().await = Some(Arc::new(responder));
    }

    /// Simulates device disconnection.
    pub fn disconnect(&self) {
        self.connected.store(false, Ordering::SeqCst);
    }
}

#[async_trait::async_trait]
pub(crate) trait PivBleIo: Send + Sync {
    async fn write_control_point(&self, fragment: &[u8]) -> Result<(), btleplug::Error>;
    #[allow(dead_code)]
    async fn read_control_point_length(&self) -> Result<Vec<u8>, btleplug::Error>;
    #[allow(dead_code)]
    async fn read_atr(&self) -> Result<Vec<u8>, btleplug::Error>;
}

struct LivePivBleIo {
    peripheral: Peripheral,
    control_point: Characteristic,
    #[allow(dead_code)]
    control_point_length: Option<Characteristic>,
    #[allow(dead_code)]
    atr: Characteristic,
}

#[async_trait::async_trait]
impl PivBleIo for LivePivBleIo {
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
                "pivControlPointLength characteristic not found",
            )))),
        }
    }

    async fn read_atr(&self) -> Result<Vec<u8>, btleplug::Error> {
        self.peripheral.read(&self.atr).await
    }
}

struct MockPivBleIo {
    written_fragments: Arc<Mutex<Vec<Vec<u8>>>>,
    write_error: Arc<Mutex<Option<MockWriteError>>>,
    #[allow(dead_code)]
    cpl_data: CplResponse,
    #[allow(dead_code)]
    atr_data: Arc<Mutex<Vec<u8>>>,
    connected: Arc<AtomicBool>,
    notification_tx: mpsc::UnboundedSender<Vec<u8>>,
    auto_responder: AutoResponder,
    reassembler: Arc<Mutex<Reassembler>>,
    fragment_size: Arc<std::sync::RwLock<FragmentSize>>,
}

#[async_trait::async_trait]
impl PivBleIo for MockPivBleIo {
    async fn write_control_point(&self, fragment: &[u8]) -> Result<(), btleplug::Error> {
        if !self.connected.load(Ordering::SeqCst) {
            return Err(btleplug::Error::NotConnected);
        }

        let err = self.write_error.lock().await.clone();
        if let Some(e) = err {
            return Err(e.to_btleplug_error());
        }

        self.written_fragments.lock().await.push(fragment.to_vec());

        // Check if auto-responder is configured
        let auto = self.auto_responder.lock().await.clone();
        if let Some(responder) = auto {
            let mut rx = self.reassembler.lock().await;
            if let Ok(Some(msg)) = rx.push(fragment) {
                if msg.command == Command::Msg {
                    let reply = responder(&msg.payload);
                    let reply_msg = Message::new(Command::Msg, reply);
                    let frag_size = *self.fragment_size.read().unwrap();
                    if let Ok(frags) = fragments(&reply_msg, frag_size) {
                        for f in frags {
                            let _ = self.notification_tx.send(f);
                        }
                    }
                }
            }
        }

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

    async fn read_atr(&self) -> Result<Vec<u8>, btleplug::Error> {
        if !self.connected.load(Ordering::SeqCst) {
            return Err(btleplug::Error::NotConnected);
        }
        Ok(self.atr_data.lock().await.clone())
    }
}

struct PivBleTransportInner {
    io: Arc<dyn PivBleIo>,
    fragment_size: Arc<std::sync::RwLock<FragmentSize>>,
    rx: Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
    connected: Arc<AtomicBool>,
    bonded: Arc<AtomicBool>,
    authenticated: Arc<AtomicBool>,
    atr: Vec<u8>,
    transceive_lock: Mutex<()>,
}

/// The private PIV BLE transport.
///
/// Communicates with the Cryptick token's private GATT service (`PIV_SERVICE`).
/// Encapsulates short APDUs in CTAP BLE framing (reusing command 0x83), enforces
/// the 261-byte ceiling in both directions, and handles KeepAlives (`0x82`),
/// Cancel (`0xBE`), and Error (`0xBF`) packets.
#[derive(Clone)]
pub struct PivBleTransport {
    inner: Arc<PivBleTransportInner>,
}

impl PivBleTransport {
    /// Connects to a peripheral exposing the private PIV service.
    ///
    /// Discovers characteristics `PIV_CONTROL_POINT`, `PIV_STATUS`, `PIV_ATR`,
    /// and optionally `PIV_CONTROL_POINT_LENGTH`. Reads the token's ATR,
    /// dynamically queries `pivControlPointLength` (defaulting to 252),
    /// subscribes to `pivStatus` notifications, and returns a new transport instance.
    pub async fn connect(peripheral: &Peripheral) -> Result<Self, BleError> {
        if !peripheral.is_connected().await? {
            peripheral.connect().await?;
        }
        let characteristics = peripheral.characteristics();
        let find = |chars: &std::collections::BTreeSet<Characteristic>, uuid: Uuid| {
            chars.iter().find(|c| c.uuid == uuid).cloned()
        };

        let (control_point, status, atr_char, control_point_length) =
            if let (Some(cp), Some(st), Some(atr)) = (
                find(&characteristics, PIV_CONTROL_POINT),
                find(&characteristics, PIV_STATUS),
                find(&characteristics, PIV_ATR),
            ) {
                (
                    cp,
                    st,
                    atr,
                    find(&characteristics, PIV_CONTROL_POINT_LENGTH),
                )
            } else {
                let _ = peripheral.discover_services().await;
                let fresh = peripheral.characteristics();
                let cp = find(&fresh, PIV_CONTROL_POINT)
                    .ok_or(BleError::MissingCharacteristic(PIV_CONTROL_POINT))?;
                let st =
                    find(&fresh, PIV_STATUS).ok_or(BleError::MissingCharacteristic(PIV_STATUS))?;
                let atr = find(&fresh, PIV_ATR).ok_or(BleError::MissingCharacteristic(PIV_ATR))?;
                let cpl = find(&fresh, PIV_CONTROL_POINT_LENGTH);
                (cp, st, atr, cpl)
            };

        // Read token ATR from pivAtr characteristic with graceful fallback
        let atr = match peripheral.read(&atr_char).await {
            Ok(raw) if !raw.is_empty() => raw,
            _ => vec![0x3B, 0x80, 0x01, 0x80],
        };

        // Read pivControlPointLength dynamically (20..=512, defaulting to 252)
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
        let fragment_size = Arc::new(std::sync::RwLock::new(fragment_size));

        // Subscribe to notifications on pivStatus
        peripheral.subscribe(&status).await?;
        let mut notifications = peripheral.notifications().await?;

        let (tx, rx) = mpsc::unbounded_channel();
        let status_uuid = status.uuid;
        let connected = Arc::new(AtomicBool::new(true));
        let connected_task = Arc::clone(&connected);

        tokio::spawn(async move {
            while let Some(notif) = notifications.next().await {
                if notif.uuid == status_uuid
                    && !notif.value.is_empty()
                    && tx.send(notif.value).is_err()
                {
                    break;
                }
            }
            connected_task.store(false, Ordering::SeqCst);
        });

        let io = Arc::new(LivePivBleIo {
            peripheral: peripheral.clone(),
            control_point,
            control_point_length,
            atr: atr_char,
        });

        Ok(Self {
            inner: Arc::new(PivBleTransportInner {
                io,
                fragment_size,
                rx: Mutex::new(rx),
                connected,
                bonded: Arc::new(AtomicBool::new(true)),
                authenticated: Arc::new(AtomicBool::new(true)),
                atr,
                transceive_lock: Mutex::new(()),
            }),
        })
    }

    /// Creates a simulated `PivBleTransport` for deterministic unit and integration tests.
    pub fn new_mock(atr: Vec<u8>, initial_cpl: Option<u16>) -> (Self, MockPivBleHandle) {
        let (tx, rx) = mpsc::unbounded_channel();
        let written_fragments = Arc::new(Mutex::new(Vec::new()));
        let write_error = Arc::new(Mutex::new(None));
        let cpl_data = Arc::new(Mutex::new(None));
        let atr_data = Arc::new(Mutex::new(atr.clone()));
        let connected = Arc::new(AtomicBool::new(true));
        let auto_responder: AutoResponder = Arc::new(Mutex::new(None));

        let frag_len = initial_cpl
            .filter(|&v| (MIN_FRAGMENT_SIZE..=MAX_FRAGMENT_SIZE).contains(&v))
            .unwrap_or(DEFAULT_FRAGMENT_SIZE);
        let fragment_size = FragmentSize::new(frag_len)
            .unwrap_or_else(|_| FragmentSize::new(DEFAULT_FRAGMENT_SIZE).unwrap());
        let fragment_size = Arc::new(std::sync::RwLock::new(fragment_size));

        let reassembler = Arc::new(Mutex::new(Reassembler::with_max_message_len(MAX_APDU_LEN)));

        let mock_io = Arc::new(MockPivBleIo {
            written_fragments: Arc::clone(&written_fragments),
            write_error: Arc::clone(&write_error),
            cpl_data: Arc::clone(&cpl_data),
            atr_data: Arc::clone(&atr_data),
            connected: Arc::clone(&connected),
            notification_tx: tx.clone(),
            auto_responder: Arc::clone(&auto_responder),
            reassembler,
            fragment_size: Arc::clone(&fragment_size),
        });

        let handle = MockPivBleHandle {
            notification_tx: tx,
            written_fragments,
            write_error,
            cpl_data,
            atr_data,
            connected: Arc::clone(&connected),
            auto_responder,
        };

        let transport = Self {
            inner: Arc::new(PivBleTransportInner {
                io: mock_io,
                fragment_size,
                rx: Mutex::new(rx),
                connected,
                bonded: Arc::new(AtomicBool::new(true)),
                authenticated: Arc::new(AtomicBool::new(true)),
                atr,
                transceive_lock: Mutex::new(()),
            }),
        };

        (transport, handle)
    }

    /// Returns the card's cached Answer-to-Reset (ATR) bytes.
    pub fn atr(&self) -> &[u8] {
        &self.inner.atr
    }

    /// The current link state.
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

    /// The currently negotiated fragment size.
    pub fn fragment_size_value(&self) -> FragmentSize {
        *self.inner.fragment_size.read().unwrap()
    }

    /// Writes a Cancel command (`0xBE`) to `pivControlPoint`.
    ///
    /// Per CTAP2 §11.4.8 and `docs/device-protocol.md`, Cancel abandons the
    /// in-flight APDU and is never answered by the token.
    pub async fn cancel(&self) -> Result<(), TransportError> {
        if !self.inner.connected.load(Ordering::SeqCst) {
            return Err(TransportError::Disconnected);
        }
        let cancel_frag = [Command::Cancel.as_u8(), 0x00, 0x00];
        match self.inner.io.write_control_point(&cancel_frag).await {
            Ok(()) => Ok(()),
            Err(err) => Err(classify_att(&err)),
        }
    }

    /// Transceives one short command APDU, returning the response APDU.
    ///
    /// # Short APDU Ceiling
    /// Enforces the strict 261-byte ceiling in both directions (`docs/device-protocol.md`).
    /// APDUs exceeding 261 bytes are refused immediately.
    ///
    /// # Framing & Streaming
    /// Encapsulates the APDU as a CTAP BLE message (`Command::Msg`, `0x83`) and writes
    /// fragments to `pivControlPoint`. Listens on `pivStatus` notifications and reassembles
    /// the response. KeepAlive notifications (`0x82`) sent while the token processes or
    /// awaits user presence (fingerprint match) are safely consumed without aborting
    /// or corrupting the in-flight APDU reassembly.
    pub async fn transceive(&self, apdu: &[u8]) -> Result<Vec<u8>, PivTransportError> {
        if !self.inner.connected.load(Ordering::SeqCst) {
            return Err(PivTransportError::Transport(TransportError::Disconnected));
        }
        if !self.inner.authenticated.load(Ordering::SeqCst) {
            return Err(PivTransportError::Transport(
                TransportError::InsufficientAuthentication,
            ));
        }
        if apdu.is_empty() {
            return Err(PivTransportError::EmptyApdu);
        }
        if apdu.len() > MAX_APDU_LEN {
            return Err(PivTransportError::ApduTooLong { len: apdu.len() });
        }

        // Serialise access: only one APDU in flight at a time
        let _guard = self.inner.transceive_lock.lock().await;

        let frag_size = self.fragment_size_value();
        let msg = Message::new(Command::Msg, apdu.to_vec());
        let frags = fragments(&msg, frag_size)?;

        let mut rx = self.inner.rx.lock().await;

        // Drain any stale fragments from previous cancelled or timed-out transactions
        while rx.try_recv().is_ok() {}

        // Send all fragments to pivControlPoint
        for fragment in frags {
            if let Err(err) = self.inner.io.write_control_point(&fragment).await {
                let mapped = classify_att(&err);
                if mapped.is_bond_failure() {
                    self.inner.authenticated.store(false, Ordering::SeqCst);
                    self.inner.bonded.store(false, Ordering::SeqCst);
                } else if matches!(mapped, TransportError::Disconnected) {
                    self.inner.connected.store(false, Ordering::SeqCst);
                    self.inner.authenticated.store(false, Ordering::SeqCst);
                    self.inner.bonded.store(false, Ordering::SeqCst);
                }
                return Err(PivTransportError::Transport(mapped));
            }
        }

        // Reassemble incoming fragments from pivStatus notifications
        let mut reassembler = Reassembler::with_max_message_len(MAX_APDU_LEN);

        loop {
            let fragment = tokio::select! {
                maybe_frag = rx.recv() => match maybe_frag {
                    Some(f) => f,
                    None => {
                        self.inner.connected.store(false, Ordering::SeqCst);
                        self.inner.authenticated.store(false, Ordering::SeqCst);
                        self.inner.bonded.store(false, Ordering::SeqCst);
                        return Err(PivTransportError::Transport(TransportError::Disconnected));
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
                    return Err(PivTransportError::Transport(TransportError::Disconnected));
                }
            };

            match reassembler.push(&fragment)? {
                Some(resp_msg) => match resp_msg.command {
                    Command::Msg => return Ok(resp_msg.payload),
                    Command::KeepAlive => {
                        // Token is processing or awaiting biometric user presence.
                        // Continue waiting for the actual response APDU.
                        continue;
                    }
                    Command::Error => {
                        let code = BleErrorCode::from_payload(&resp_msg.payload);
                        return Err(PivTransportError::DeviceError(code));
                    }
                    Command::Cancel => return Err(PivTransportError::Cancelled),
                    other => return Err(PivTransportError::UnexpectedCommand(other)),
                },
                None => {
                    // More fragments needed to complete the response message
                    continue;
                }
            }
        }
    }
}

impl std::fmt::Debug for PivBleTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PivBleTransport")
            .field("link", &self.link_state())
            .field("fragment_size", &self.fragment_size_value())
            .field("atr_len", &self.inner.atr.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_ATR: [u8; 4] = [0x3B, 0x80, 0x01, 0x81];

    #[tokio::test]
    async fn short_apdu_transceive_round_trip() {
        let (transport, handle) = PivBleTransport::new_mock(TEST_ATR.to_vec(), Some(252));

        // SELECT PIV applet command
        let select_apdu = vec![
            0x00, 0xA4, 0x04, 0x00, 0x09, 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00,
        ];
        let expected_resp = vec![0x61, 0x11, 0x4F, 0x02, 0x00, 0x00, 0x90, 0x00];

        let resp_clone = expected_resp.clone();
        handle
            .set_auto_responder(move |cmd| {
                if cmd.starts_with(&[0x00, 0xA4]) {
                    resp_clone.clone()
                } else {
                    vec![0x6A, 0x82]
                }
            })
            .await;

        let res = transport.transceive(&select_apdu).await.unwrap();
        assert_eq!(res, expected_resp);

        let written = handle.written_fragments().await;
        assert_eq!(written.len(), 1);
        // CMD byte must be 0x83
        assert_eq!(written[0][0], 0x83);
    }

    #[tokio::test]
    async fn multi_fragment_apdu_transceive() {
        // Force small fragment size 20 bytes
        let (transport, handle) = PivBleTransport::new_mock(TEST_ATR.to_vec(), Some(20));

        // 60-byte APDU
        let long_apdu: Vec<u8> = (0..60).collect();
        let expected_resp: Vec<u8> = (0..45).map(|b| b ^ 0xFF).collect();

        let resp_clone = expected_resp.clone();
        handle.set_auto_responder(move |_| resp_clone.clone()).await;

        let res = transport.transceive(&long_apdu).await.unwrap();
        assert_eq!(res, expected_resp);

        let written = handle.written_fragments().await;
        // 60 bytes / ~19 payload per fragment > 1 fragment
        assert!(written.len() > 1);
    }

    #[tokio::test]
    async fn apdu_longer_than_261_bytes_is_rejected() {
        let (transport, _handle) = PivBleTransport::new_mock(TEST_ATR.to_vec(), None);

        let over_limit = vec![0x00; 262];
        let err = transport.transceive(&over_limit).await.unwrap_err();
        assert!(matches!(err, PivTransportError::ApduTooLong { len: 262 }));
    }

    #[tokio::test]
    async fn empty_apdu_is_rejected() {
        let (transport, _handle) = PivBleTransport::new_mock(TEST_ATR.to_vec(), None);

        let err = transport.transceive(&[]).await.unwrap_err();
        assert!(matches!(err, PivTransportError::EmptyApdu));
    }

    #[tokio::test]
    async fn keepalive_during_transceive_does_not_corrupt_response() {
        let (transport, handle) = PivBleTransport::new_mock(TEST_ATR.to_vec(), Some(252));

        let apdu = vec![0x00, 0x87, 0x07, 0x9A, 0x04];
        let expected_resp = vec![0x90, 0x00];

        // Spawn background task to send KeepAlives before sending the APDU response
        let handle_clone = handle.clone();
        tokio::spawn(async move {
            // Wait until request fragment is written
            while handle_clone.written_fragments().await.is_empty() {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
            // Send KeepAlive UP_NEEDED (waiting for biometric touch)
            handle_clone.send_keepalive(KeepAliveStatus::UpNeeded);
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            // Send KeepAlive PROCESSING
            handle_clone.send_keepalive(KeepAliveStatus::Processing);
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            // Finally send APDU response
            let _ = handle_clone.send_apdu_response(&[0x90, 0x00], FragmentSize::new(252).unwrap());
        });

        let res = transport.transceive(&apdu).await.unwrap();
        assert_eq!(res, expected_resp);
    }

    #[tokio::test]
    async fn device_error_is_surfaced() {
        let (transport, handle) = PivBleTransport::new_mock(TEST_ATR.to_vec(), Some(252));

        let handle_clone = handle.clone();
        tokio::spawn(async move {
            while handle_clone.written_fragments().await.is_empty() {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
            handle_clone.send_device_error(BleErrorCode::InvalidCmd);
        });

        let err = transport.transceive(&[0x00, 0x01]).await.unwrap_err();
        assert!(matches!(
            err,
            PivTransportError::DeviceError(BleErrorCode::InvalidCmd)
        ));
    }

    #[tokio::test]
    async fn att_authentication_failure_marks_link_unauthenticated() {
        let (transport, handle) = PivBleTransport::new_mock(TEST_ATR.to_vec(), Some(252));
        assert!(transport.link_state().is_usable());

        handle
            .set_write_error(Some(MockWriteError::InsufficientAuthentication))
            .await;

        let err = transport.transceive(&[0x00, 0x01]).await.unwrap_err();
        assert!(matches!(
            err,
            PivTransportError::Transport(TransportError::InsufficientAuthentication)
        ));
        assert!(!transport.link_state().is_usable());
        assert!(!transport.link_state().authenticated);
    }

    #[tokio::test]
    async fn disconnection_fails_transceive() {
        let (transport, handle) = PivBleTransport::new_mock(TEST_ATR.to_vec(), Some(252));
        handle.disconnect();

        let err = transport.transceive(&[0x00, 0x01]).await.unwrap_err();
        assert!(matches!(
            err,
            PivTransportError::Transport(TransportError::Disconnected)
        ));
    }

    #[test]
    fn atr_getter_returns_configured_atr() {
        let (transport, _handle) = PivBleTransport::new_mock(TEST_ATR.to_vec(), None);
        assert_eq!(transport.atr(), &TEST_ATR);
    }

    #[tokio::test]
    async fn cancel_writes_cancel_frame() {
        let (transport, handle) = PivBleTransport::new_mock(TEST_ATR.to_vec(), None);
        transport.cancel().await.unwrap();

        let written = handle.written_fragments().await;
        assert_eq!(written.len(), 1);
        assert_eq!(written[0], vec![0xBE, 0x00, 0x00]);
    }
}
