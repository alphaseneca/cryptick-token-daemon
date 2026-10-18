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
use transport_ble::{BleTransport, ReconnectBackoff};

/// How long one GATT connection attempt (discovery + characteristic lookup +
/// notify subscription) is allowed to run before this attempt gives up.
/// Generous because some BLE stacks (BlueZ in particular, right after a
/// device reappears) are slow to settle; bounded so one bad attempt cannot
/// wedge the reconnect loop indefinitely.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// How long one scan for the token is allowed to run before concluding it
/// is not currently in range. Short relative to [`CONNECT_TIMEOUT`] because
/// a scan that finds nothing is the common case (PROJECT.md §17: the token
/// spends most of its life idle-advertising or asleep), not the exception.
const SCAN_TIMEOUT: Duration = Duration::from_secs(3);

/// How long the best-effort PIV side-channel connect gets. Separate from
/// [`CONNECT_TIMEOUT`] because a token with no PIV service exposed, or one
/// that is slow to answer it, must never block or fail the FIDO connection
/// that has already succeeded — see `attempt_piv_connect`.
const PIV_CONNECT_TIMEOUT: Duration = Duration::from_secs(12);

/// How often the loop polls link state (and drains a pending retarget
/// request) while the connection looks healthy. Equal to
/// [`transport_ble::INITIAL_BACKOFF`] on purpose: detecting a *new*
/// disconnect is never slower than this regardless of backoff state — only
/// the *retries* after one slow down, via [`ReconnectBackoff`].
const IDLE_POLL_INTERVAL: Duration = transport_ble::INITIAL_BACKOFF;

/// --- Device identity (additive; see `crates/daemon/src/devices.rs`'s module
/// doc for the full picture across both transports) ------------------------
///
/// UUID of the Daemon Bridge GATT service's new `daemonSerialNumber`
/// characteristic — `cryptick-token-code`'s `ble_daemon.h`,
/// `BLE_DAEMON_UUID_SERIAL_NUMBER`, one past `daemonVersion`
/// (`transport_ble::DAEMON_VERSION`, `FBF6EB84`) in the same UUID block.
///
/// Not added as a `transport_ble::` constant: that crate is explicitly out
/// of scope for this change (its own BLE power/reconnect work is landing
/// concurrently in the same files), so this compares the characteristic's
/// UUID by its lowercase string form instead of pulling in the `uuid` crate
/// as a new direct dependency of `daemon/` just to name one literal
/// (`uuid::Uuid`'s `Display` always lowercases, so this is exact).
const DAEMON_SERIAL_NUMBER_UUID: &str = "fbf6eb85-7f39-41b1-a191-9527cc42f8be";

/// Whether `s` matches the identity format `cryptick-token-code` documents
/// (NOTES.md, "Real USB serial number (eFuse MAC)"): `CT-` followed by 12
/// uppercase hex digits — the chip's 6-byte eFuse base MAC. Written by hand
/// rather than pulling in a regex crate for one fifteen-character format.
fn is_stable_serial_format(s: &str) -> bool {
    match s.strip_prefix("CT-") {
        Some(hex) => {
            hex.len() == 12
                && hex
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
        }
        None => false,
    }
}

/// Reads the factory-unique identity exposed by newer firmware on the
/// Daemon Bridge service, if present.
///
/// Returns `None` — never an error — when the characteristic is absent
/// (older firmware), when the read fails for any reason (not yet bonded;
/// the encrypted+authenticated ATT gate this characteristic carries, same
/// as `daemonControlPoint`, refusing an unbonded link; a transient GATT
/// error), or when the bytes read back do not match the documented format.
/// PROJECT.md §15.8 ("fail closed... never guess") applies here exactly as
/// it does to bonding: a malformed or partial read must never be *treated*
/// as a real identity, only discarded in favour of the caller's existing
/// best-effort fallback — which is why this returns `Option`, not
/// `Result`, and every failure path collapses to the same `None`.
///
/// `peripheral` must already be past `discover_services()` — true for every
/// caller here, since each only calls this right after
/// [`connect_peripheral`] succeeds on the same `Peripheral` handle, and
/// `BleTransport::connect_daemon` (`crates/transport-ble`) already ran
/// discovery as part of that connection.
async fn read_verified_identity(peripheral: &Peripheral) -> Option<String> {
    use transport_ble::btleplug::api::Peripheral as _;

    let chr = peripheral
        .characteristics()
        .into_iter()
        .find(|c| c.uuid.to_string() == DAEMON_SERIAL_NUMBER_UUID)?;
    let raw = peripheral.read(&chr).await.ok()?;
    let text = std::str::from_utf8(&raw).ok()?.trim();
    is_stable_serial_format(text).then(|| text.to_string())
}

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

    /// The factory-unique identity of the device currently connected, if the
    /// firmware exposes one and the live connection could read it.
    ///
    /// `None` on older firmware, before any connection has been made, right
    /// after a disconnect, or for any transport — `fake-transport`'s single
    /// fixed device, or any future implementor — that has no notion of
    /// hardware identity at all. Defaulted here rather than required so an
    /// existing or future `LiveRetarget` implementor with nothing to report
    /// needs no changes to keep compiling; see
    /// `crates/daemon/src/devices.rs`'s module doc for what this feeds.
    fn verified_identity(&self) -> Option<String> {
        None
    }
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
/// An unexpected disconnect is retried with bounded, jittered backoff
/// (`transport_ble::ReconnectBackoff`) rather than on a flat fixed interval
/// forever — see that module's doc for why. Backoff resets the moment a
/// connection is actually adopted, so a brief outage and a long one both
/// recover at the same pace once the token is reachable again.
///
/// This is deliberately distinct from a *deliberate* disconnect — the user
/// picking a different known device via [`Self::retarget`]. That path is
/// handled on its own channel with its own fixed, short timeout and never
/// consults or waits on the backoff state at all: a user who explicitly
/// asks for device B must not be made to wait out device A's backoff, and
/// a failed retarget to B must not perturb however long the periodic loop
/// has already been trying to get A back (see [`handle_retarget_request`]).
///
/// Every reconnect — periodic or retargeted — opens a brand new
/// [`BleTransport`] via [`connect_peripheral`], which performs full GATT
/// discovery and resubscribes from scratch. There is no fast path that
/// reuses a previous connection's authenticated state: PROJECT.md §15.2
/// requires the device's own ATT gate (the first authenticated
/// control-point write) be challenged again on every single connection,
/// bounded or not.
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
    /// The current connection's hardware-verified identity, if
    /// [`read_verified_identity`] found one — see [`Self::verified_identity`].
    verified_id: Arc<Mutex<Option<String>>>,
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
        let verified_id = Arc::new(Mutex::new(None));

        let inner_clone = Arc::clone(&inner);
        let target_clone = Arc::clone(&target);
        let connecting_clone = Arc::clone(&is_connecting);
        let connected_clone = Arc::clone(&connected);
        let bonded_clone = Arc::clone(&bonded);
        let authenticated_clone = Arc::clone(&authenticated);
        let verified_id_clone = Arc::clone(&verified_id);
        let initial_target = target_device;

        let handle = tokio::spawn(async move {
            let mut opt_adapter = adapter;
            let mut current_target = initial_target;
            // Tracks consecutive *unexpected*-disconnect reconnect attempts
            // only. Reset to the floor the instant a connection is adopted,
            // from either branch below — see the backoff module doc and the
            // struct doc above for why a deliberate retarget never touches
            // this at all.
            let mut backoff = ReconnectBackoff::new();
            loop {
                // While the link looks healthy, poll at the short, fixed
                // interval so an unexpected disconnect is noticed promptly.
                // Only once we are actually not connected does the backoff
                // schedule set the pace of the *retries* — computed here,
                // before the attempt, so a tick that ends up not reconnecting
                // (adapter still missing, scan empty) still paces the next one.
                let currently_connected = {
                    let r = inner_clone.read().await;
                    r.as_ref().is_some_and(|t| t.link().connected)
                };
                let wait = if currently_connected {
                    IDLE_POLL_INTERVAL
                } else {
                    backoff.next_delay()
                };

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
                            tokio::time::sleep(IDLE_POLL_INTERVAL).await;
                            continue;
                        };
                        // Deliberate user action: always attempted immediately,
                        // regardless of `wait` or the periodic branch's backoff
                        // state (see the struct doc above).
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
                            &verified_id_clone,
                            &mut backoff,
                        )
                        .await;
                    }

                    _ = tokio::time::sleep(wait) => {
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
                                // A new connection (below) may be to a
                                // different physical unit than the one this
                                // identity was read from — never carry it
                                // across a disconnect (PROJECT.md §15.8).
                                *verified_id_clone.lock().unwrap_or_else(|e| e.into_inner()) = None;
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
                                SCAN_TIMEOUT,
                            )
                            .await {
                                Ok(p) => Ok(p),
                                Err(_) if current_target.is_some() => {
                                    // Pinned device not found; fallback to any advertising Cryptick Token
                                    transport_ble::find_device(adapter_ref, SCAN_TIMEOUT).await
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
                                    let adopted = connect_and_adopt(
                                        &peripheral,
                                        &addr,
                                        &inner_clone,
                                        &connecting_clone,
                                        &connected_clone,
                                        &bonded_clone,
                                        &authenticated_clone,
                                        &verified_id_clone,
                                    )
                                    .await;
                                    if adopted {
                                        // A fresh, confirmed-good connection is
                                        // up — the next unexpected disconnect
                                        // (if any) starts its own episode from
                                        // the floor, not from wherever this one
                                        // left off.
                                        backoff.reset();
                                    }
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
                verified_id,
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

    /// Returns the current connection's hardware-verified identity, if
    /// [`read_verified_identity`] found one for it. See
    /// [`LiveRetarget::verified_identity`], which this implements.
    pub fn verified_identity(&self) -> Option<String> {
        self.verified_id
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

/// Opens the GATT connection to `peripheral`, with the same timeout the
/// organic reconnect loop has always used. Returns `None` rather than an
/// error type: every failure here (timeout or connect error) is handled
/// identically by both callers, and the message is already logged.
async fn connect_peripheral(peripheral: &Peripheral, addr: &str) -> Option<BleTransport> {
    match tokio::time::timeout(CONNECT_TIMEOUT, BleTransport::connect_daemon(peripheral)).await
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
        PIV_CONNECT_TIMEOUT,
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
    verified_id: &Arc<Mutex<Option<String>>>,
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
            // Best-effort: absent on older firmware, or if the read itself
            // fails — see `read_verified_identity`'s doc comment. Either way
            // this connection is already adopted and usable either way.
            *verified_id.lock().unwrap_or_else(|e| e.into_inner()) =
                read_verified_identity(peripheral).await;
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
    verified_id: &Arc<Mutex<Option<String>>>,
    backoff: &mut ReconnectBackoff,
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

    let found =
        transport_ble::find_device_with_target(adapter_ref, Some(&request.target), SCAN_TIMEOUT)
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
    // Replaces whatever identity (if any) the previous connection reported —
    // this is a different physical unit's connection now.
    *verified_id.lock().unwrap_or_else(|e| e.into_inner()) =
        read_verified_identity(&peripheral).await;
    // A fresh, confirmed-good connection is up under the new target — the
    // periodic branch's next unexpected disconnect starts its own backoff
    // episode from the floor rather than inheriting whatever the old
    // target's failures (if any) had already accumulated.
    backoff.reset();
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

    /// Delegates to [`Self::verified_identity`] — the real, non-trait-object
    /// method, kept so callers that already hold a concrete
    /// `ReconnectingBleTransport` (rather than a `dyn LiveRetarget`) don't
    /// need the trait in scope just to read it.
    fn verified_identity(&self) -> Option<String> {
        Self::verified_identity(self)
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
