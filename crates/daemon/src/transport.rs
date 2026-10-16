//! The seam between the daemon and whatever is carrying fragments.
//!
//! The trait is deliberately at the **fragment** level, not the message level.
//! Framing is the daemon's job and the part most likely to be got wrong, so it
//! must sit above the seam where the fake transport can attack it. A trait that
//! exchanged whole messages would hide exactly the code that needs testing.

pub use ble_framing::{FragmentTransport, LinkState, TransportError};

use ble_framing::FragmentSize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use transport_ble::btleplug::platform::Adapter;
use transport_ble::BleTransport;

/// Returns the path to the stored paired device configuration file (~/.config/cryptick/paired_device).
pub fn paired_device_path() -> Option<std::path::PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("APPDATA")
            .map(std::path::PathBuf::from)
            .map(|p| p.join("cryptick").join("paired_device"))
    }
    #[cfg(not(windows))]
    {
        std::env::var_os("HOME")
            .map(std::path::PathBuf::from)
            .map(|p| p.join(".config").join("cryptick").join("paired_device"))
    }
}

/// An auto-reconnecting BLE fragment transport.
///
/// Holds an active BLE connection to the Cryptick Token. If the connection drops
/// (e.g. device reboot, temporary power interruption, or signal loss), a background
/// task automatically scans for and reconnects to the token over the dedicated
/// Daemon Bridge GATT service.
#[derive(Clone, Debug)]
pub struct ReconnectingBleTransport {
    inner: Arc<RwLock<Option<BleTransport>>>,
    target_device: Option<String>,
    is_connecting: Arc<AtomicBool>,
    connected: Arc<AtomicBool>,
    bonded: Arc<AtomicBool>,
    authenticated: Arc<AtomicBool>,
}

impl ReconnectingBleTransport {
    /// Spawns an auto-reconnecting transport monitor, lazily acquiring the BLE adapter in background.
    pub async fn spawn(
        adapter: Option<Adapter>,
        target_device: Option<String>,
    ) -> (Self, tokio::task::JoinHandle<()>) {
        let target_device = target_device.or_else(|| {
            paired_device_path()
                .and_then(|p| std::fs::read_to_string(p).ok())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        });

        eprintln!("Auto-reconnect target: {:?}", target_device);

        let inner: Arc<RwLock<Option<BleTransport>>> = Arc::new(RwLock::new(None));
        let is_connecting = Arc::new(AtomicBool::new(false));
        let connected = Arc::new(AtomicBool::new(false));
        let bonded = Arc::new(AtomicBool::new(false));
        let authenticated = Arc::new(AtomicBool::new(false));

        let inner_clone = Arc::clone(&inner);
        let connecting_clone = Arc::clone(&is_connecting);
        let connected_clone = Arc::clone(&connected);
        let bonded_clone = Arc::clone(&bonded);
        let authenticated_clone = Arc::clone(&authenticated);
        let target_clone = target_device.clone();

        let handle = tokio::spawn(async move {
            let mut opt_adapter = adapter;
            let mut current_target = target_clone;
            loop {
                let need_reconnect = {
                    let r = inner_clone.read().await;
                    match r.as_ref() {
                        Some(t) => {
                            let st = t.link();
                            connected_clone.store(st.connected, Ordering::SeqCst);
                            bonded_clone.store(st.bonded, Ordering::SeqCst);
                            authenticated_clone.store(st.authenticated, Ordering::SeqCst);
                            !st.connected
                        }
                        None => {
                            connected_clone.store(false, Ordering::SeqCst);
                            true
                        }
                    }
                };

                if need_reconnect {
                    {
                        let mut w = inner_clone.write().await;
                        *w = None;
                        connected_clone.store(false, Ordering::SeqCst);
                        bonded_clone.store(false, Ordering::SeqCst);
                        authenticated_clone.store(false, Ordering::SeqCst);
                    }
                    if opt_adapter.is_none() {
                        match transport_ble::adapter().await {
                            Ok(a) => opt_adapter = Some(a),
                            Err(e) => {
                                eprintln!("Waiting for Bluetooth radio adapter: {e}");
                                tokio::time::sleep(Duration::from_millis(1500)).await;
                                continue;
                            }
                        }
                    }
                    // `opt_adapter` was just populated above if it was empty, so this
                    // is always `Some` — but §20 forbids `.unwrap()` here even so,
                    // and failing closed by retrying the loop costs nothing.
                    let Some(adapter_ref) = opt_adapter.as_ref() else {
                        tokio::time::sleep(Duration::from_millis(1500)).await;
                        continue;
                    };

                    connecting_clone.store(true, Ordering::SeqCst);
                    let find_res = match transport_ble::find_device_with_target(
                        adapter_ref,
                        current_target.as_deref(),
                        Duration::from_secs(3),
                    )
                    .await
                    {
                        Ok(p) => Ok(p),
                        Err(_) if current_target.is_some() => {
                            // Pinned device not found; fallback to any advertising Cryptick Token
                            transport_ble::find_device(adapter_ref, Duration::from_secs(3)).await
                        }
                        Err(e) => Err(e),
                    };

                    match find_res {
                        Ok(peripheral) => {
                            let addr = transport_ble::display_address(&peripheral);
                            if current_target.as_deref() != Some(&addr) {
                                current_target = Some(addr.clone());
                                if let Some(p) = paired_device_path() {
                                    let _ = std::fs::write(&p, format!("{}\n", addr));
                                }
                            }
                            eprintln!("Discovered Cryptick Token [{addr}], connecting via Daemon Bridge GATT...");
                            match tokio::time::timeout(
                                Duration::from_secs(15),
                                BleTransport::connect_daemon(&peripheral),
                            )
                            .await
                            {
                                Ok(Ok(new_transport)) => {
                                    eprintln!("Connected to Cryptick Token [{addr}]!");
                                    let mut w = inner_clone.write().await;
                                    *w = Some(new_transport);
                                    connected_clone.store(true, Ordering::SeqCst);
                                    bonded_clone.store(true, Ordering::SeqCst);
                                    authenticated_clone.store(true, Ordering::SeqCst);
                                    connecting_clone.store(false, Ordering::SeqCst);

                                    // Attempt PIV connection if exposed
                                    match tokio::time::timeout(
                                        Duration::from_secs(12),
                                        transport_ble::PivBleTransport::connect(&peripheral),
                                    )
                                    .await
                                    {
                                        Ok(Ok(piv_t)) => {
                                            eprintln!("Connected to PIV service (spawning vpcd relay on 127.0.0.1:35963)");
                                            tokio::spawn(async move {
                                                let _ =
                                                    crate::vpcd_relay::run_vpcd_relay(piv_t, None)
                                                        .await;
                                            });
                                        }
                                        Ok(Err(e)) => {
                                            eprintln!("PIV service not available on token: {e}");
                                        }
                                        Err(_) => {
                                            eprintln!("PIV connect timed out on token [{addr}]");
                                        }
                                    }
                                }
                                Ok(Err(e)) => {
                                    eprintln!("Failed to connect to token [{addr}]: {e}");
                                    connecting_clone.store(false, Ordering::SeqCst);
                                }
                                Err(_) => {
                                    eprintln!("Connection to token [{addr}] timed out");
                                    connecting_clone.store(false, Ordering::SeqCst);
                                }
                            }
                        }
                        Err(_e) => {
                            // Token not discovered during this scan window
                            connecting_clone.store(false, Ordering::SeqCst);
                            // Avoid spamming logs every 3s when token is sleeping; log cleanly
                        }
                    }
                }

                tokio::time::sleep(Duration::from_millis(1000)).await;
            }
        });

        (
            Self {
                inner,
                target_device,
                is_connecting,
                connected,
                bonded,
                authenticated,
            },
            handle,
        )
    }

    /// Returns whether the transport is currently connected to the token.
    pub fn is_connected(&self) -> bool {
        self.link().connected
    }

    /// Returns the target device name/address filter, if pinned.
    pub fn target_device(&self) -> Option<&str> {
        self.target_device.as_deref()
    }

    /// Returns whether a reconnect scan is currently in progress.
    pub fn is_reconnecting(&self) -> bool {
        self.is_connecting.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl FragmentTransport for ReconnectingBleTransport {
    async fn fragment_size(&mut self) -> Result<FragmentSize, TransportError> {
        let r = self.inner.read().await;
        match &*r {
            Some(t) => BleTransport::fragment_size(t).await,
            None => Err(TransportError::Disconnected),
        }
    }

    async fn write_fragment(&mut self, fragment: &[u8]) -> Result<(), TransportError> {
        let r = self.inner.read().await;
        match &*r {
            Some(t) => match BleTransport::write_fragment(t, fragment).await {
                Ok(()) => Ok(()),
                Err(err) => {
                    if matches!(err, TransportError::Disconnected) {
                        self.connected.store(false, Ordering::SeqCst);
                    }
                    Err(err)
                }
            },
            None => {
                self.connected.store(false, Ordering::SeqCst);
                Err(TransportError::Disconnected)
            }
        }
    }

    async fn next_notification(&mut self) -> Result<Vec<u8>, TransportError> {
        let r = self.inner.read().await;
        match &*r {
            Some(t) => match BleTransport::read_fragment(t).await {
                Ok(notif) => Ok(notif),
                Err(err) => {
                    if matches!(err, TransportError::Disconnected) {
                        self.connected.store(false, Ordering::SeqCst);
                    }
                    Err(err)
                }
            },
            None => {
                self.connected.store(false, Ordering::SeqCst);
                Err(TransportError::Disconnected)
            }
        }
    }

    fn link(&self) -> LinkState {
        if let Ok(r) = self.inner.try_read() {
            if let Some(t) = &*r {
                let st = t.link();
                self.connected.store(st.connected, Ordering::SeqCst);
                self.bonded.store(st.bonded, Ordering::SeqCst);
                self.authenticated.store(st.authenticated, Ordering::SeqCst);
                return st;
            } else {
                self.connected.store(false, Ordering::SeqCst);
                self.bonded.store(false, Ordering::SeqCst);
                self.authenticated.store(false, Ordering::SeqCst);
                return LinkState {
                    connected: false,
                    bonded: false,
                    authenticated: false,
                };
            }
        }
        LinkState {
            connected: self.connected.load(Ordering::SeqCst),
            bonded: self.bonded.load(Ordering::SeqCst),
            authenticated: self.authenticated.load(Ordering::SeqCst),
        }
    }
}
