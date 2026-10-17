//! The seam between the daemon and whatever is carrying fragments.
//!
//! The trait is deliberately at the **fragment** level, not the message level.
//! Framing is the daemon's job and the part most likely to be got wrong, so it
//! must sit above the seam where the fake transport can attack it. A trait that
//! exchanged whole messages would hide exactly the code that needs testing.

pub use ble_framing::{FragmentTransport, LinkState, TransportError};

use ble_framing::FragmentSize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, RwLock};
use transport_ble::btleplug::platform::{Adapter, Peripheral};
use transport_ble::BleTransport;

/// A transport whose live connection can be pointed at a different physical
/// device while the daemon keeps running — the thing `ClientMessage::
/// SelectDevice` needs in order to take effect immediately rather than on
/// the next reconnect/restart.
///
/// Decoupled from [`crate::bridge::Bridge`]'s generic transport parameter on
/// purpose: a transport that has no notion of "which device" (the
/// `fake-transport` build's single fixed device, or any future transport
/// that hasn't implemented this yet) simply has none, and callers treat
/// `None` as "bookkeeping only, no live effect" — the exact pre-existing
/// behaviour this trait exists to let one transport (`ReconnectingBleTransport`)
/// opt out of.
#[async_trait::async_trait]
pub trait LiveRetarget: Send + Sync {
    /// Points the live connection at `target`, or fails without disturbing
    /// whatever was connected before.
    ///
    /// Implementations must probe reachability before tearing down an
    /// existing connection: PROJECT.md §15.8 ("fail closed... never guess in
    /// the user's favour") means a device that cannot be confirmed reachable
    /// within a bounded time must leave the previous connection exactly as
    /// it was, not fall back to "whatever else is around" and not leave the
    /// daemon with no connection at all.
    async fn retarget(&self, target: &str) -> Result<(), RetargetError>;
}

/// Why a [`LiveRetarget::retarget`] call failed.
#[derive(Debug, thiserror::Error)]
pub enum RetargetError {
    /// `target` could not be confirmed reachable within the probe window —
    /// out of BLE range, powered off, or simply never existed.
    #[error("device {0:?} is not currently reachable")]
    Unreachable(String),
    /// The background task that owns the connection is not running (it
    /// exited or was never started). Distinct from `Unreachable` only for
    /// diagnosis; a caller should treat both the same way.
    #[error("the background reconnect task is not running")]
    TransportGone,
}

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

/// Asks the background reconnect task in [`ReconnectingBleTransport::spawn`]
/// to switch targets, and carries the outcome back.
struct RetargetRequest {
    target: String,
    reply: oneshot::Sender<Result<(), RetargetError>>,
}

/// An auto-reconnecting BLE fragment transport.
///
/// Holds an active BLE connection to the Cryptick Token. If the connection drops
/// (e.g. device reboot, temporary power interruption, or signal loss), a background
/// task automatically scans for and reconnects to the token over the dedicated
/// Daemon Bridge GATT service.
///
/// `target` is shared (`Arc<Mutex<_>>`), not a plain field, because
/// [`Self::retarget`] must be callable on any clone — the IPC server holds
/// one via a `dyn LiveRetarget` while the background task that actually owns
/// the radio holds another — and both must see the same value.
#[derive(Clone, Debug)]
pub struct ReconnectingBleTransport {
    inner: Arc<RwLock<Option<BleTransport>>>,
    target: Arc<Mutex<Option<String>>>,
    retarget_tx: mpsc::UnboundedSender<RetargetRequest>,
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
        let target = Arc::new(Mutex::new(target_device.clone()));
        let (retarget_tx, mut retarget_rx) = mpsc::unbounded_channel::<RetargetRequest>();
        let is_connecting = Arc::new(AtomicBool::new(false));
        let connected = Arc::new(AtomicBool::new(false));
        let bonded = Arc::new(AtomicBool::new(false));
        let authenticated = Arc::new(AtomicBool::new(false));

        let inner_clone = Arc::clone(&inner);
        let target_clone = Arc::clone(&target);
        let connecting_clone = Arc::clone(&is_connecting);
        let connected_clone = Arc::clone(&connected);
        let bonded_clone = Arc::clone(&bonded);
        let authenticated_clone = Arc::clone(&authenticated);
        let initial_target = target_device;

        let handle = tokio::spawn(async move {
            let mut opt_adapter = adapter;
            let mut current_target = initial_target;
            loop {
                tokio::select! {
                    // Biased so a pending retarget request is always drained
                    // before the next periodic reconnect tick, rather than a
                    // coin flip deciding which runs first when both are ready.
                    biased;

                    request = retarget_rx.recv() => {
                        let Some(request) = request else {
                            // Every `ReconnectingBleTransport` clone (and
                            // hence every retarget_tx) has been dropped —
                            // nothing can ask this task to do anything else.
                            // Fall through to the plain reconnect loop rather
                            // than exiting, so an existing connection keeps
                            // being maintained for in-flight CTAP traffic.
                            tokio::time::sleep(Duration::from_millis(1000)).await;
                            continue;
                        };
                        handle_retarget_request(
                            request,
                            &mut opt_adapter,
                            &mut current_target,
                            &inner_clone,
                            &target_clone,
                            &connecting_clone,
                            &connected_clone,
                            &bonded_clone,
                            &authenticated_clone,
                        )
                        .await;
                    }

                    _ = tokio::time::sleep(Duration::from_millis(1000)) => {
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
                                        continue;
                                    }
                                }
                            }
                            // `opt_adapter` was just populated above if it was empty, so
                            // this is always `Some` here — but §20 forbids `.unwrap()` in
                            // daemon/ even so, and failing closed by retrying costs nothing.
                            let Some(adapter_ref) = opt_adapter.as_ref() else {
                                continue;
                            };

                            connecting_clone.store(true, Ordering::SeqCst);
                            let find_res = match transport_ble::find_device_with_target(
                                adapter_ref,
                                current_target.as_deref(),
                                Duration::from_secs(3),
                            )
                            .await {
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
                                        *target_clone.lock().unwrap_or_else(|e| e.into_inner()) = Some(addr.clone());
                                        if let Some(p) = paired_device_path() {
                                            let _ = std::fs::write(&p, format!("{}\n", addr));
                                        }
                                    }
                                    eprintln!("Discovered Cryptick Token [{addr}], connecting via Daemon Bridge GATT...");
                                    connect_and_adopt(
                                        &peripheral,
                                        &addr,
                                        &inner_clone,
                                        &connecting_clone,
                                        &connected_clone,
                                        &bonded_clone,
                                        &authenticated_clone,
                                    )
                                    .await;
                                }
                                Err(_e) => {
                                    // Token not discovered during this scan window
                                    connecting_clone.store(false, Ordering::SeqCst);
                                    // Avoid spamming logs every 3s when token is sleeping; log cleanly
                                }
                            }
                        }
                    }
                }
            }
        });

        (
            Self {
                inner,
                target,
                retarget_tx,
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

    /// Returns the currently pinned target device address, if any.
    ///
    /// Reflects live updates from [`Self::retarget`] and from the background
    /// task's own organic discovery — hence the owned `String` rather than a
    /// borrow: the value lives behind a lock shared with whichever task last
    /// wrote it, not in `self`.
    pub fn target_device(&self) -> Option<String> {
        self.target
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Returns whether a reconnect scan is currently in progress.
    pub fn is_reconnecting(&self) -> bool {
        self.is_connecting.load(Ordering::SeqCst)
    }
}

/// Opens the GATT connection to `peripheral`, with the same timeout the
/// organic reconnect loop has always used. Returns `None` rather than an
/// error type: every failure here (timeout or connect error) is handled
/// identically by both callers, and the message is already logged.
async fn connect_peripheral(peripheral: &Peripheral, addr: &str) -> Option<BleTransport> {
    match tokio::time::timeout(
        Duration::from_secs(15),
        BleTransport::connect_daemon(peripheral),
    )
    .await
    {
        Ok(Ok(new_transport)) => {
            eprintln!("Connected to Cryptick Token [{addr}]!");
            Some(new_transport)
        }
        Ok(Err(e)) => {
            eprintln!("Failed to connect to token [{addr}]: {e}");
            None
        }
        Err(_) => {
            eprintln!("Connection to token [{addr}] timed out");
            None
        }
    }
}

/// Best-effort PIV side channel, spawned once the main FIDO connection is up.
/// Never affects the caller's success/failure — a token with no PIV service
/// exposed is not a connection failure.
async fn attempt_piv_connect(peripheral: &Peripheral, addr: &str) {
    match tokio::time::timeout(
        Duration::from_secs(12),
        transport_ble::PivBleTransport::connect(peripheral),
    )
    .await
    {
        Ok(Ok(piv_t)) => {
            eprintln!("Connected to PIV service (spawning vpcd relay on 127.0.0.1:35963)");
            tokio::spawn(async move {
                let _ = crate::vpcd_relay::run_vpcd_relay(piv_t, None).await;
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

/// Connects to `peripheral` and, on success, adopts it as `inner` and
/// updates every shared flag — the organic reconnect loop's sequence, used
/// where `inner` is already known to be empty (there is nothing to preserve
/// if this fails). [`handle_retarget_request`] does **not** use this: it
/// must not clear an existing connection before the replacement is already
/// up, which this helper's "adopt on success" ordering does not provide.
async fn connect_and_adopt(
    peripheral: &Peripheral,
    addr: &str,
    inner: &Arc<RwLock<Option<BleTransport>>>,
    connecting: &Arc<AtomicBool>,
    connected: &Arc<AtomicBool>,
    bonded: &Arc<AtomicBool>,
    authenticated: &Arc<AtomicBool>,
) -> bool {
    match connect_peripheral(peripheral, addr).await {
        Some(new_transport) => {
            {
                let mut w = inner.write().await;
                *w = Some(new_transport);
            }
            connected.store(true, Ordering::SeqCst);
            bonded.store(true, Ordering::SeqCst);
            authenticated.store(true, Ordering::SeqCst);
            connecting.store(false, Ordering::SeqCst);
            attempt_piv_connect(peripheral, addr).await;
            true
        }
        None => {
            connecting.store(false, Ordering::SeqCst);
            false
        }
    }
}

/// Handles one [`RetargetRequest`] from [`ReconnectingBleTransport::retarget`].
///
/// Scans for the exact requested address only — deliberately not the
/// "fall back to any advertising token" behaviour the organic reconnect loop
/// uses, because a caller that explicitly asked for device B must get a
/// clear failure if B isn't there, never a silent connection to whatever
/// else happens to be around (PROJECT.md §15.8). The existing connection, if
/// any, is left completely untouched until the new target is confirmed
/// reachable.
async fn handle_retarget_request(
    request: RetargetRequest,
    opt_adapter: &mut Option<Adapter>,
    current_target: &mut Option<String>,
    inner: &Arc<RwLock<Option<BleTransport>>>,
    shared_target: &Arc<Mutex<Option<String>>>,
    connecting: &Arc<AtomicBool>,
    connected: &Arc<AtomicBool>,
    bonded: &Arc<AtomicBool>,
    authenticated: &Arc<AtomicBool>,
) {
    // Already there and actually connected — a safe no-op, no airtime spent.
    if current_target.as_deref() == Some(request.target.as_str())
        && connected.load(Ordering::SeqCst)
    {
        let _ = request.reply.send(Ok(()));
        return;
    }

    if opt_adapter.is_none() {
        match transport_ble::adapter().await {
            Ok(a) => *opt_adapter = Some(a),
            Err(_) => {
                let _ = request
                    .reply
                    .send(Err(RetargetError::Unreachable(request.target)));
                return;
            }
        }
    }
    let Some(adapter_ref) = opt_adapter.as_ref() else {
        let _ = request
            .reply
            .send(Err(RetargetError::Unreachable(request.target)));
        return;
    };

    let found = transport_ble::find_device_with_target(
        adapter_ref,
        Some(&request.target),
        Duration::from_secs(3),
    )
    .await;

    let peripheral = match found {
        Ok(p) => p,
        Err(_) => {
            // Not reachable. Nothing above this line touched `inner`, so
            // whatever was connected before (if anything) is undisturbed.
            let _ = request
                .reply
                .send(Err(RetargetError::Unreachable(request.target)));
            return;
        }
    };

    // Found by the scan — but do **not** touch `inner` yet. Opening the new
    // GATT connection can still fail or time out, and only a *confirmed* new
    // connection may replace the old one: PROJECT.md §15.8 ("fail closed")
    // means a half-finished retarget must leave the previous connection
    // serving requests, not leave the daemon connected to nothing.
    let addr = transport_ble::display_address(&peripheral);
    connecting.store(true, Ordering::SeqCst);
    let new_transport = connect_peripheral(&peripheral, &addr).await;

    let Some(new_transport) = new_transport else {
        connecting.store(false, Ordering::SeqCst);
        // The old connection (if any) is still sitting in `inner`, exactly
        // as it was before this request arrived.
        let _ = request.reply.send(Err(RetargetError::Unreachable(addr)));
        return;
    };

    // Confirmed up. Only now is it safe to retire whatever was connected
    // before.
    {
        let mut w = inner.write().await;
        *w = Some(new_transport);
    }
    connected.store(true, Ordering::SeqCst);
    bonded.store(true, Ordering::SeqCst);
    authenticated.store(true, Ordering::SeqCst);
    connecting.store(false, Ordering::SeqCst);
    attempt_piv_connect(&peripheral, &addr).await;

    *current_target = Some(addr.clone());
    *shared_target.lock().unwrap_or_else(|e| e.into_inner()) = Some(addr.clone());
    if let Some(p) = paired_device_path() {
        let _ = std::fs::write(&p, format!("{}\n", addr));
    }
    let _ = request.reply.send(Ok(()));
}

#[async_trait::async_trait]
impl LiveRetarget for ReconnectingBleTransport {
    /// Sends a request across to the background task spawned by
    /// [`Self::spawn`] and waits for its outcome. See
    /// [`handle_retarget_request`] for what actually happens.
    async fn retarget(&self, target: &str) -> Result<(), RetargetError> {
        let (reply, reply_rx) = oneshot::channel();
        self.retarget_tx
            .send(RetargetRequest {
                target: target.to_string(),
                reply,
            })
            .map_err(|_| RetargetError::TransportGone)?;
        reply_rx.await.map_err(|_| RetargetError::TransportGone)?
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
