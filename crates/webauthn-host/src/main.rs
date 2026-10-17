mod daemon;
mod usb;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ctap::{Command, Request, Response};
use ctap_client::{
    cbor::Value,
    response::{GetAssertionResponse, MakeCredentialResponse},
};
use daemon::DaemonClient;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::{self, Read, Write},
    sync::{Arc, Mutex},
    time::Duration,
};
use usb::UsbClient;

#[derive(Debug, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
enum HostRequest {
    #[serde(rename = "ping")]
    Ping,
    #[serde(rename = "status")]
    Status,
    #[serde(rename = "restart")]
    Restart,
    #[serde(rename = "create")]
    Create(CreateRequest),
    #[serde(rename = "get")]
    Get(GetRequest),
    #[serde(rename = "totp_list")]
    TotpList,
    #[serde(rename = "totp_code")]
    TotpCode(TotpCodeRequest),
    #[serde(rename = "sync_time")]
    SyncTime,
    #[serde(rename = "totp_sync_time")]
    TotpSyncTime,
    #[serde(rename = "list_credentials")]
    ListCredentials,
    #[serde(rename = "delete_credential")]
    DeleteCredential(DeleteCredentialRequest),
    #[serde(rename = "list_devices")]
    ListDevices,
    #[serde(rename = "select_device")]
    SelectDevice(SelectDeviceRequest),
}

#[derive(Debug, Deserialize)]
struct SelectDeviceRequest {
    id: String,
}

#[derive(Debug, Deserialize)]
struct TotpCodeRequest {
    name: String,
}

#[derive(Debug, Deserialize)]
struct DeleteCredentialRequest {
    #[serde(rename = "credentialId")]
    credential_id: String, // base64url
    // Accepted and currently unused on the wire: the device's own
    // CM_cmdRKDelete lookup matches on the full opaque credential ID alone
    // (`credentialId_to_rk_index`, `core/fido2/ctap.c` — the RP is already
    // encoded inside that ID via its embedded rpIdHash), so nothing here
    // needs to resend it. Kept in the request shape because the extension
    // already has it to hand for its own UI and the exact contract says to
    // accept it.
    #[serde(rename = "rpId")]
    #[allow(dead_code)]
    rp_id: String,
}

#[derive(Debug, Deserialize)]
struct RpEntity {
    id: String,
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UserEntity {
    id: String, // base64url
    name: Option<String>,
    #[serde(rename = "displayName")]
    display_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CreateRequest {
    rp: RpEntity,
    user: UserEntity,
    #[serde(rename = "clientDataJSON")]
    client_data_json: String, // base64url
    #[serde(rename = "pubKeyCredParams", default)]
    pub_key_cred_params: Vec<i64>,
    #[serde(rename = "residentKey", default)]
    resident_key: bool,
    #[serde(rename = "userVerification", default)]
    user_verification: bool,
    #[serde(default = "default_timeout")]
    timeout: u64,
}

#[derive(Debug, Deserialize)]
struct GetRequest {
    #[serde(rename = "rpId")]
    rp_id: String,
    #[serde(rename = "clientDataJSON")]
    client_data_json: String, // base64url
    #[serde(rename = "allowCredentials", default)]
    allow_credentials: Vec<String>, // base64url
    #[serde(rename = "userVerification", default)]
    user_verification: bool,
    #[serde(default = "default_timeout")]
    timeout: u64,
}

fn default_timeout() -> u64 {
    60000
}

#[derive(Debug, Serialize)]
struct HostResponse {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "inRange")]
    in_range: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bonded: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    usb: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "rawId")]
    raw_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "type")]
    cred_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    accounts: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    remaining: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "daemonRunning")]
    daemon_running: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    transport: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "latencyMs")]
    latency_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "clockUtc")]
    clock_utc: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "clockSynced")]
    clock_synced: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "timeOffsetSecs")]
    time_offset_secs: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "tzOffsetMins")]
    tz_offset_mins: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "tzOffsetStr")]
    tz_offset_str: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "relyingParties")]
    relying_parties: Option<Vec<RelyingPartyOut>>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "totalCredentials")]
    total_credentials: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "remainingSlots")]
    remaining_slots: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    devices: Option<Vec<DeviceOut>>,
}

/// One device in a `list_devices` response.
#[derive(Debug, Serialize)]
struct DeviceOut {
    id: String,
    name: String,
    transport: String,
    #[serde(rename = "lastSeen")]
    last_seen: u64,
    active: bool,
}

/// One relying party in a `list_credentials` response.
#[derive(Debug, Serialize)]
struct RelyingPartyOut {
    #[serde(rename = "rpId")]
    rp_id: String,
    #[serde(rename = "rpName")]
    rp_name: String,
    credentials: Vec<CredentialOut>,
}

/// One credential within [`RelyingPartyOut`].
#[derive(Debug, Serialize)]
struct CredentialOut {
    #[serde(rename = "credentialId")]
    credential_id: String, // base64url
    #[serde(rename = "userName")]
    user_name: String,
    #[serde(rename = "userDisplayName")]
    user_display_name: String,
}

impl HostResponse {
    fn ok() -> Self {
        Self {
            status: "ok".into(),
            message: None,
            version: None,
            in_range: None,
            bonded: None,
            usb: None,
            id: None,
            raw_id: None,
            cred_type: None,
            response: None,
            accounts: None,
            name: None,
            code: None,
            remaining: None,
            daemon_running: None,
            transport: None,
            latency_ms: None,
            clock_utc: None,
            clock_synced: None,
            time_offset_secs: None,
            tz_offset_mins: None,
            tz_offset_str: None,
            relying_parties: None,
            total_credentials: None,
            remaining_slots: None,
            devices: None,
        }
    }

    /// A response carrying only a status string — for first-class,
    /// distinguishable non-error outcomes like `touch_required` or
    /// `timeout` that are not themselves a failure to report a message for.
    fn status_only(status: impl Into<String>) -> Self {
        let mut r = Self::ok();
        r.status = status.into();
        r
    }

    fn error(msg: impl Into<String>) -> Self {
        Self {
            status: "error".into(),
            message: Some(msg.into()),
            version: None,
            in_range: None,
            bonded: None,
            usb: None,
            id: None,
            raw_id: None,
            cred_type: None,
            response: None,
            accounts: None,
            name: None,
            code: None,
            remaining: None,
            daemon_running: None,
            transport: None,
            latency_ms: None,
            clock_utc: None,
            clock_synced: None,
            time_offset_secs: None,
            tz_offset_mins: None,
            tz_offset_str: None,
            relying_parties: None,
            total_credentials: None,
            remaining_slots: None,
            devices: None,
        }
    }
}

fn get_local_tz_offset() -> (i32, String) {
    // SAFETY: `libc::time` with a null `time_t*` out-pointer has no output
    // parameter to write through; it only returns the current time by
    // value, so there is no buffer for the call to misuse.
    let t = unsafe { libc::time(std::ptr::null_mut()) };
    // SAFETY: `libc::tm` is a plain C struct of integers; the all-zero bit
    // pattern is a valid (if not yet meaningful) value for every field, and
    // `localtime_r` below fully populates it before it's read.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: `&t` and `&mut tm` are both valid, live, non-overlapping
    // pointers to correctly-sized objects (a `time_t` and a `libc::tm`),
    // which is everything `localtime_r` requires of its two out-parameters.
    unsafe { libc::localtime_r(&t, &mut tm) };
    #[cfg(unix)]
    let offset_secs = tm.tm_gmtoff;
    #[cfg(not(unix))]
    let offset_secs = 0;

    let offset_mins = (offset_secs / 60) as i32;
    let sign = if offset_secs >= 0 { '+' } else { '-' };
    let abs_secs = offset_secs.abs();
    let hours = abs_secs / 3600;
    let mins = (abs_secs % 3600) / 60;
    (offset_mins, format!("UTC{}{:02}:{:02}", sign, hours, mins))
}

fn check_usb_device() -> bool {
    #[cfg(unix)]
    {
        if let Ok(entries) = std::fs::read_dir("/dev") {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with("cu.usbmodem") || name.starts_with("ttyACM") {
                    return true;
                }
            }
        }
    }
    false
}

fn decode_b64(input: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(input.trim_end_matches('='))
        .map_err(|e| format!("invalid base64: {e}"))
}

fn encode_b64(input: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(input)
}

fn hash_client_data(client_data_json: &str) -> Result<Vec<u8>, String> {
    let raw = decode_b64(client_data_json)?;
    let mut hasher = Sha256::new();
    hasher.update(&raw);
    Ok(hasher.finalize().to_vec())
}

fn cbor_alg(alg: i64) -> Value {
    if alg >= 0 {
        Value::Unsigned(alg as u64)
    } else {
        Value::Negative((-1 - alg) as u64)
    }
}

fn transact_with_fallback(request: &Request, timeout: Duration) -> Result<Response, String> {
    // 1. Direct USB CTAPHID first: instantaneous, zero BLE latency or pairing needed
    if let Some(mut usb) = UsbClient::try_connect() {
        return usb.transact(request, timeout).map_err(|e| e.to_string());
    }

    // If USB is present on the bus, retry USB with brief backoffs in case of enumeration lag
    if check_usb_device() {
        for _ in 0..3 {
            std::thread::sleep(Duration::from_millis(150));
            if let Some(mut usb) = UsbClient::try_connect() {
                return usb.transact(request, timeout).map_err(|e| e.to_string());
            }
        }
    }

    // 2. BLE daemon fallback
    let mut client = DaemonClient::connect(Duration::from_secs(3))
        .map_err(|e| format!("Token not on USB and Daemon unreachable: {e}"))?;
    client
        .transact(request, timeout)
        .map_err(|e| format!("{e}"))
}

/// Same shape as [`transact_with_fallback`], but a non-OK CTAP status comes
/// back as `Ok(Response)` rather than a formatted `Err(String)` that has
/// already thrown the status byte away. Credential management needs the
/// real status to tell `touch_required`/`timeout`/`cancelled`/"not supported
/// yet" apart as first-class outcomes rather than one generic failure
/// message; nothing else in this file does, which is why this exists
/// alongside `transact_with_fallback` instead of replacing it.
fn transact_with_fallback_preserving_status(
    request: &Request,
    timeout: Duration,
) -> Result<Response, String> {
    if let Some(mut usb) = UsbClient::try_connect() {
        return usb
            .transact_preserving_status(request, timeout)
            .map_err(|e| e.to_string());
    }

    if check_usb_device() {
        for _ in 0..3 {
            std::thread::sleep(Duration::from_millis(150));
            if let Some(mut usb) = UsbClient::try_connect() {
                return usb
                    .transact_preserving_status(request, timeout)
                    .map_err(|e| e.to_string());
            }
        }
    }

    let mut client = DaemonClient::connect(Duration::from_secs(3))
        .map_err(|e| format!("Token not on USB and Daemon unreachable: {e}"))?;
    client
        .transact_preserving_status(request, timeout)
        .map_err(|e| format!("{e}"))
}

/// How long we are willing to wait for the device's own fingerprint ceremony.
/// Matches the firmware's own budget for a user-presence wait
/// (`CTAP2_UP_DELAY_MS`, `core/fido2/ctap.h`) rather than picking an
/// arbitrary client-side number that could time this side out first and
/// report a misleading "no response" where the device would have reported
/// a real timeout of its own a moment later.
const UV_CEREMONY_TIMEOUT: Duration = Duration::from_millis(29_000);

/// Budget for a credential-management exchange once a `pinUvAuthToken` is
/// already in hand — no further touch is required for these (only obtaining
/// the token itself gates on one), so this is a plain I/O timeout, not a
/// human-response one.
const CRED_MGMT_TIMEOUT: Duration = Duration::from_secs(5);

/// A non-success outcome of obtaining a UV-scoped `pinUvAuthToken`, already
/// in its final `HostResponse` form.
///
/// Builds the response rather than a bare error code because every branch
/// here maps onto one of the exact statuses `list_credentials`/
/// `delete_credential`'s contract defines, and keeping that mapping in one
/// place (here) is what stops `list_credentials` and `delete_credential`
/// from quietly drifting apart on how they classify the same device
/// response.
fn uv_token_failure(context: &str, status: ctap::StatusCode) -> HostResponse {
    match status {
        ctap::StatusCode::ACTION_TIMEOUT | ctap::StatusCode::USER_ACTION_TIMEOUT => {
            HostResponse::status_only("timeout")
        }
        ctap::StatusCode::KEEPALIVE_CANCEL => HostResponse::status_only("cancelled"),
        // The firmware's ctap_client_pin() has no case for subcommand 0x06
        // yet (see cred_mgmt::client_pin_subcommand's doc comment) and falls
        // through to its `default`, which answers CTAP1_ERR_OTHER. This is
        // the expected, honest outcome until that firmware work lands — not
        // folded into a generic error, so the extension can show real
        // guidance ("credential management isn't available on this device's
        // firmware yet") instead of a failure message.
        ctap::StatusCode::OTHER => HostResponse::status_only("uv_token_unsupported"),
        other => HostResponse::error(format!(
            "{context}: device returned {other:?} ({:#04x})",
            other.as_u8()
        )),
    }
}

/// Runs the CTAP2.0 PIN Protocol One key-agreement handshake and asks the
/// device for a `pinUvAuthToken` scoped to [`permissions`], gated on the
/// device's own fingerprint ceremony rather than any PIN.
///
/// Writes an immediate `touch_required` message through `stdout_lock` right
/// before the step that blocks on the user's touch, so the extension is not
/// left guessing for up to [`UV_CEREMONY_TIMEOUT`] with no feedback — see
/// `main`'s doc comment for why a single blocking native-messaging call with
/// no interim signal was the root cause tracked down for a related
/// "device appears to disconnect" report.
///
/// A fresh token is obtained for every call; none is cached across calls.
/// The firmware task adding real support for this is still in flight as of
/// this writing (see `cred_mgmt::client_pin_subcommand`'s doc comment) and
/// its token-lifetime/expiry policy is therefore unknown — caching against
/// an undetermined expiry would risk silently reusing a token the device no
/// longer honours. Re-running the ceremony per call is the honest choice
/// until that policy is confirmed, at the cost of one fingerprint touch per
/// `list_credentials`/`delete_credential` call — the same cost every
/// `create`/`get` call already has.
fn obtain_uv_token(stdout_lock: &Mutex<()>, permissions: u8) -> Result<[u8; 16], HostResponse> {
    let ka_request = ctap_client::cred_mgmt::get_key_agreement_request();
    let ka_response = transact_with_fallback(&ka_request, Duration::from_secs(5)).map_err(|e| {
        HostResponse::error(format!("could not reach device for key agreement: {e}"))
    })?;
    let device_key = ctap_client::cred_mgmt::parse_key_agreement_response(&ka_response.data)
        .map_err(|e| HostResponse::error(format!("device key agreement response: {e}")))?;

    let platform = ctap_client::pin_protocol::PlatformKeyAgreement::generate();
    let shared_secret = platform.shared_secret(&device_key);

    // From here on the device will not answer until the user touches the
    // sensor (or the ceremony times out/cancels), so tell the caller now.
    write_response(stdout_lock, &HostResponse::status_only("touch_required"));

    let uv_request = ctap_client::cred_mgmt::get_uv_token_request(&platform, permissions, None);
    let uv_response =
        match transact_with_fallback_preserving_status(&uv_request, UV_CEREMONY_TIMEOUT) {
            Ok(r) => r,
            Err(e) => return Err(HostResponse::error(format!("UV token request failed: {e}"))),
        };
    if !uv_response.status.is_ok() {
        return Err(uv_token_failure("UV token request", uv_response.status));
    }

    ctap_client::cred_mgmt::parse_uv_token_response(&uv_response.data, &shared_secret)
        .map_err(|e| HostResponse::error(format!("UV token response did not decrypt: {e}")))
}

/// Handles `list_credentials`: enumerate every relying party with resident
/// credentials and every credential under each.
fn handle_list_credentials(stdout_lock: &Mutex<()>) -> HostResponse {
    let pin_token = match obtain_uv_token(
        stdout_lock,
        ctap_client::cred_mgmt::PERMISSION_CREDENTIAL_MANAGEMENT,
    ) {
        Ok(token) => token,
        Err(response) => return response,
    };

    let metadata_req = ctap_client::cred_mgmt::metadata_request(&pin_token);
    let metadata_resp =
        match transact_with_fallback_preserving_status(&metadata_req, CRED_MGMT_TIMEOUT) {
            Ok(r) => r,
            Err(e) => {
                return HostResponse::error(format!("credential metadata request failed: {e}"))
            }
        };
    if !metadata_resp.status.is_ok() {
        return uv_token_failure("credential metadata request", metadata_resp.status);
    }
    let metadata = match ctap_client::cred_mgmt::Metadata::parse(&metadata_resp.data) {
        Ok(m) => m,
        Err(e) => return HostResponse::error(format!("credential metadata response: {e}")),
    };

    if metadata.existing_resident_credentials_count == 0 {
        let mut r = HostResponse::ok();
        r.relying_parties = Some(Vec::new());
        r.total_credentials = Some(0);
        r.remaining_slots = Some(metadata.max_possible_remaining);
        return r;
    }

    let mut relying_parties = Vec::new();

    // CM_cmdRPBegin, then CM_cmdRPNext until the device stops answering —
    // ctap_cred_mgmt returns CTAP2_ERR_NO_CREDENTIALS once enumeration is
    // exhausted (core/fido2/ctap.c).
    let rp_begin_req = ctap_client::cred_mgmt::rp_begin_request(&pin_token);
    let mut next_rp_req = Some(rp_begin_req);
    while let Some(req) = next_rp_req.take() {
        let resp = match transact_with_fallback_preserving_status(&req, CRED_MGMT_TIMEOUT) {
            Ok(r) => r,
            Err(e) => return HostResponse::error(format!("RP enumeration failed: {e}")),
        };
        if resp.status == ctap::StatusCode::NO_CREDENTIALS {
            break;
        }
        if !resp.status.is_ok() {
            return uv_token_failure("RP enumeration", resp.status);
        }
        let rp = match ctap_client::cred_mgmt::RpEntry::parse(&resp.data) {
            Ok(rp) => rp,
            Err(e) => return HostResponse::error(format!("RP enumeration response: {e}")),
        };

        let credentials = match collect_credentials(&pin_token, &rp.rp_id_hash) {
            Ok(creds) => creds,
            Err(response) => return response,
        };

        relying_parties.push(RelyingPartyOut {
            rp_id: rp.rp_id,
            rp_name: rp.rp_name.unwrap_or_default(),
            credentials,
        });

        next_rp_req = Some(ctap_client::cred_mgmt::rp_next_request());
    }

    let mut r = HostResponse::ok();
    r.total_credentials = Some(metadata.existing_resident_credentials_count);
    r.remaining_slots = Some(metadata.max_possible_remaining);
    r.relying_parties = Some(relying_parties);
    r
}

/// `CM_cmdRKBegin` then `CM_cmdRKNext` until exhausted, for one RP.
fn collect_credentials(
    pin_token: &[u8; 16],
    rp_id_hash: &[u8; 32],
) -> Result<Vec<CredentialOut>, HostResponse> {
    let mut credentials = Vec::new();
    let mut next_req = Some(ctap_client::cred_mgmt::rk_begin_request(
        pin_token, rp_id_hash,
    ));
    while let Some(req) = next_req.take() {
        let resp = transact_with_fallback_preserving_status(&req, CRED_MGMT_TIMEOUT)
            .map_err(|e| HostResponse::error(format!("credential enumeration failed: {e}")))?;
        if resp.status == ctap::StatusCode::NO_CREDENTIALS {
            break;
        }
        if !resp.status.is_ok() {
            return Err(uv_token_failure("credential enumeration", resp.status));
        }
        let entry = ctap_client::cred_mgmt::CredentialEntry::parse(&resp.data)
            .map_err(|e| HostResponse::error(format!("credential enumeration response: {e}")))?;

        credentials.push(CredentialOut {
            credential_id: URL_SAFE_NO_PAD.encode(&entry.credential_id),
            user_name: entry.user_name.unwrap_or_default(),
            user_display_name: entry.user_display_name.unwrap_or_default(),
        });

        next_req = Some(ctap_client::cred_mgmt::rk_next_request());
    }
    Ok(credentials)
}

/// Handles `delete_credential`.
fn handle_delete_credential(stdout_lock: &Mutex<()>, req: DeleteCredentialRequest) -> HostResponse {
    let pin_token = match obtain_uv_token(
        stdout_lock,
        ctap_client::cred_mgmt::PERMISSION_CREDENTIAL_MANAGEMENT,
    ) {
        Ok(token) => token,
        Err(response) => return response,
    };

    let credential_id = match decode_b64(&req.credential_id) {
        Ok(bytes) => bytes,
        Err(e) => return HostResponse::error(format!("invalid credentialId: {e}")),
    };

    let delete_req = ctap_client::cred_mgmt::rk_delete_request(&pin_token, &credential_id);
    let resp = match transact_with_fallback_preserving_status(&delete_req, CRED_MGMT_TIMEOUT) {
        Ok(r) => r,
        Err(e) => return HostResponse::error(format!("delete request failed: {e}")),
    };
    if resp.status == ctap::StatusCode::NO_CREDENTIALS {
        return HostResponse::error("no credential on the device matches that credentialId");
    }
    if !resp.status.is_ok() {
        return uv_token_failure("delete request", resp.status);
    }
    HostResponse::ok()
}

/// Handles `list_devices`: everything the daemon's known-devices store has
/// recorded (BLE — the daemon's only domain, see
/// `crates/daemon/src/devices.rs`'s module doc), unioned with a live USB
/// scan done right here.
///
/// The union, not a daemon-only answer, is deliberate: USB needs no daemon
/// by design (PROJECT.md §1, §4; `docs/ARCHITECTURE.md` Mechanism 1), so a
/// user who only ever plugs in over USB may not be running the daemon at
/// all, and the daemon has no USB code path to tell it about one anyway. A
/// daemon that is unreachable is therefore not an error here — it just means
/// zero BLE entries, not zero devices.
///
/// USB has no per-unit identity either (same module doc): there is no
/// firmware-populated serial number, so every USB-connected Cryptick Token
/// is reported as the same synthetic id (`"usb"`). This is honest about
/// what can and cannot be told apart today, not a workaround.
fn handle_list_devices() -> HostResponse {
    let mut devices = Vec::new();

    if UsbClient::try_connect().is_some() {
        devices.push(DeviceOut {
            id: "usb".into(),
            name: "Cryptick Token (USB)".into(),
            transport: "usb".into(),
            last_seen: now_unix(),
            active: true,
        });
    }

    if let Ok(mut client) = DaemonClient::connect(Duration::from_millis(500)) {
        if let Ok(ble_devices) = client.list_devices() {
            for d in ble_devices {
                devices.push(DeviceOut {
                    id: d.id,
                    name: d.name,
                    transport: d.transport,
                    last_seen: d.last_seen,
                    // If a USB device just claimed "active" above, a BLE
                    // entry cannot also be active — only one device is
                    // active at a time, and USB (zero-latency, no daemon)
                    // is the one actually in use when both are present.
                    active: d.active && !devices.iter().any(|existing| existing.transport == "usb"),
                });
            }
        }
    }

    let mut r = HostResponse::ok();
    r.devices = Some(devices);
    r
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Handles `select_device`.
///
/// A `"usb"` selection has nothing to actually switch — see
/// `handle_list_devices`'s doc comment on why USB is a single synthetic
/// entry — so it is accepted as a no-op success rather than forwarded to a
/// daemon that may not even be running. A BLE id is forwarded to the daemon,
/// which is the one that owns that bookkeeping.
fn handle_select_device(req: SelectDeviceRequest) -> HostResponse {
    if req.id == "usb" {
        return HostResponse::ok();
    }
    match DaemonClient::connect(Duration::from_secs(2)) {
        Ok(mut client) => match client.select_device(&req.id) {
            Ok(()) => HostResponse::ok(),
            Err(e) => HostResponse::error(format!("could not select device: {e}")),
        },
        Err(e) => HostResponse::error(format!("daemon unreachable: {e}")),
    }
}

fn parse_oath_list(data: &[u8]) -> Result<Vec<String>, String> {
    if data.len() < 2 {
        return Err("Short OATH response".into());
    }
    let sw = u16::from_be_bytes([data[data.len() - 2], data[data.len() - 1]]);
    if sw != 0x9000 {
        return Err(format!("OATH LIST returned error {sw:#06x}"));
    }

    let mut names = Vec::new();
    let mut i = 0;
    let payload = &data[..data.len() - 2];
    while i + 2 <= payload.len() {
        let tag = payload[i];
        let len = payload[i + 1] as usize;
        i += 2;
        if i + len > payload.len() {
            break;
        }
        if tag == 0x71 && len > 1 {
            // First byte is algo (0x21), remainder is name string
            if let Ok(name) = std::str::from_utf8(&payload[i + 1..i + len]) {
                names.push(name.to_string());
            }
        }
        i += len;
    }
    Ok(names)
}

fn build_oath_calculate_apdu(name: &str, counter: u64) -> Vec<u8> {
    let name_bytes = name.as_bytes();
    let chal_bytes = counter.to_be_bytes();
    let mut data = Vec::with_capacity(2 + name_bytes.len() + 2 + 8);
    // TAG_NAME = 0x71
    data.push(0x71);
    data.push(name_bytes.len() as u8);
    data.extend_from_slice(name_bytes);
    // TAG_CHALLENGE = 0x74
    data.push(0x74);
    data.push(8);
    data.extend_from_slice(&chal_bytes);

    let mut apdu = vec![0x00, 0xA2, 0x00, 0x00, data.len() as u8];
    apdu.extend_from_slice(&data);
    apdu
}

fn parse_oath_code(data: &[u8]) -> Result<String, String> {
    if data.len() < 2 {
        return Err("Short OATH response".into());
    }
    let sw = u16::from_be_bytes([data[data.len() - 2], data[data.len() - 1]]);
    if sw != 0x9000 {
        if sw == 0x6985 {
            return Err("User verification failed or timed out (touch sensor)".into());
        }
        if sw == 0x6A82 {
            return Err("Account not found on token".into());
        }
        return Err(format!("OATH CALCULATE returned {sw:#06x}"));
    }

    let payload = &data[..data.len() - 2];
    if payload.len() >= 7 && payload[0] == 0x75 && payload[1] == 5 {
        let code_num = u32::from_be_bytes([payload[3], payload[4], payload[5], payload[6]]);
        return Ok(format!("{:06}", code_num));
    }
    Err("Invalid OATH CALCULATE response format".into())
}

fn handle_totp_list() -> Result<Vec<String>, String> {
    if let Some(mut usb) = UsbClient::try_connect() {
        return usb
            .oath_list(Duration::from_secs(3))
            .map_err(|e| e.to_string());
    }

    let mut client = DaemonClient::connect(Duration::from_millis(500))
        .map_err(|e| format!("Token not on USB and Daemon unreachable: {e}"))?;
    let apdu = vec![0x00, 0xA1, 0x00, 0x00, 0x00];
    let req = ctap::Request::new(ctap::Command(0xE3), apdu);
    let resp = client
        .transact(&req, Duration::from_secs(5))
        .map_err(|e| format!("{e}"))?;
    parse_oath_list(&resp.data)
}

fn handle_totp_code(name: &str, counter: u64) -> Result<String, String> {
    if let Some(mut usb) = UsbClient::try_connect() {
        return usb
            .oath_calculate(name, counter, Duration::from_secs(25))
            .map_err(|e| e.to_string());
    }

    let mut client = DaemonClient::connect(Duration::from_millis(500))
        .map_err(|e| format!("Token not on USB and Daemon unreachable: {e}"))?;
    let apdu = build_oath_calculate_apdu(name, counter);
    let req = ctap::Request::new(ctap::Command(0xE3), apdu);
    let resp = client
        .transact(&req, Duration::from_secs(25))
        .map_err(|e| format!("{e}"))?;
    parse_oath_code(&resp.data)
}

fn build_oath_set_time_apdu(utc_secs: u64) -> Vec<u8> {
    let ts = (utc_secs as u32).to_be_bytes();
    let mut apdu = vec![0x00, 0x04, 0x00, 0x00, 0x04];
    apdu.extend_from_slice(&ts);
    apdu
}

fn parse_oath_sw(data: &[u8]) -> Result<(), String> {
    if data.len() < 2 {
        return Err("OATH response too short".into());
    }
    let sw = u16::from_be_bytes([data[data.len() - 2], data[data.len() - 1]]);
    if sw != 0x9000 {
        return Err(format!("OATH operation returned error {sw:#06x}"));
    }
    Ok(())
}

fn handle_sync_time(utc_secs: u64) -> Result<(), String> {
    if let Some(mut usb) = UsbClient::try_connect() {
        return usb
            .oath_set_time(utc_secs, Duration::from_secs(3))
            .map_err(|e| e.to_string());
    }

    let mut client = DaemonClient::connect(Duration::from_millis(500))
        .map_err(|e| format!("Token not on USB and Daemon unreachable: {e}"))?;
    let apdu = build_oath_set_time_apdu(utc_secs);
    let req = ctap::Request::new(ctap::Command(0xE3), apdu);
    let resp = client
        .transact(&req, Duration::from_secs(5))
        .map_err(|e| format!("{e}"))?;
    parse_oath_sw(&resp.data)
}

fn handle_create(req: CreateRequest) -> Result<HostResponse, String> {
    let client_data_hash = hash_client_data(&req.client_data_json)?;
    let user_id = decode_b64(&req.user.id)?;

    let mut rp_map = vec![(Value::Text("id".into()), Value::Text(req.rp.id))];
    if let Some(name) = req.rp.name {
        rp_map.push((Value::Text("name".into()), Value::Text(name)));
    }

    let mut user_map = vec![(Value::Text("id".into()), Value::Bytes(user_id))];
    if let Some(name) = req.user.name {
        user_map.push((Value::Text("name".into()), Value::Text(name)));
    }
    if let Some(display_name) = req.user.display_name {
        user_map.push((Value::Text("displayName".into()), Value::Text(display_name)));
    }

    let algs = if req.pub_key_cred_params.is_empty() {
        vec![-7, -8]
    } else {
        req.pub_key_cred_params
    };
    let params_array: Vec<Value> = algs
        .into_iter()
        .map(|alg| {
            Value::Map(vec![
                (Value::Text("type".into()), Value::Text("public-key".into())),
                (Value::Text("alg".into()), cbor_alg(alg)),
            ])
        })
        .collect();

    let mut params = vec![
        (Value::Unsigned(1), Value::Bytes(client_data_hash)),
        (Value::Unsigned(2), Value::Map(rp_map)),
        (Value::Unsigned(3), Value::Map(user_map)),
        (Value::Unsigned(4), Value::Array(params_array)),
    ];

    let mut options = Vec::new();
    if req.resident_key {
        options.push((Value::Text("rk".into()), Value::Bool(true)));
    }
    if req.user_verification {
        options.push((Value::Text("uv".into()), Value::Bool(true)));
    }
    if !options.is_empty() {
        params.push((Value::Unsigned(7), Value::Map(options)));
    }

    let ctap_req = Request::new(Command(0x01), Value::Map(params).encode());
    let timeout = Duration::from_millis(req.timeout);
    let resp = transact_with_fallback(&ctap_req, timeout)
        .map_err(|e| format!("MakeCredential failed: {e}"))?;

    let parsed = MakeCredentialResponse::parse(&resp.data)
        .map_err(|e| format!("Failed to parse MakeCredential response: {e}"))?;
    let cred_id = parsed
        .credential_id()
        .map_err(|_| "Response missing credential ID".to_string())?;

    let ctap_cbor = Value::decode(&resp.data)
        .map_err(|e| format!("Failed to decode MakeCredential CBOR: {e}"))?;

    let fmt_val = ctap_cbor
        .get(1)
        .cloned()
        .unwrap_or_else(|| Value::Text(parsed.fmt.clone()));
    let auth_data_val = ctap_cbor
        .get(2)
        .cloned()
        .unwrap_or_else(|| Value::Bytes(parsed.auth_data_raw.clone()));
    let att_stmt_val = ctap_cbor
        .get(3)
        .cloned()
        .unwrap_or_else(|| Value::Map(vec![]));

    // W3C WebAuthn §6.5.1: attestationObject MUST be a CBOR map with text string keys:
    // "fmt" (text), "authData" (bytes), "attStmt" (map)
    let webauthn_map = Value::Map(vec![
        (Value::Text("fmt".into()), fmt_val),
        (Value::Text("authData".into()), auth_data_val),
        (Value::Text("attStmt".into()), att_stmt_val),
    ]);
    let attestation_bytes = webauthn_map.encode();

    let cred_id_b64 = encode_b64(cred_id);
    let attestation_b64 = encode_b64(&attestation_bytes);
    let auth_data_b64 = encode_b64(&parsed.auth_data_raw);

    let mut resp_obj = HostResponse::ok();
    resp_obj.id = Some(cred_id_b64.clone());
    resp_obj.raw_id = Some(cred_id_b64);
    resp_obj.cred_type = Some("public-key".into());
    resp_obj.response = Some(serde_json::json!({
        "clientDataJSON": req.client_data_json,
        "attestationObject": attestation_b64,
        "authenticatorData": auth_data_b64
    }));

    Ok(resp_obj)
}

fn handle_get(req: GetRequest) -> Result<HostResponse, String> {
    let client_data_hash = hash_client_data(&req.client_data_json)?;

    let mut params = vec![
        (Value::Unsigned(1), Value::Text(req.rp_id)),
        (Value::Unsigned(2), Value::Bytes(client_data_hash)),
    ];

    if !req.allow_credentials.is_empty() {
        let mut allow_list = Vec::new();
        for id_b64 in &req.allow_credentials {
            if let Ok(id_bytes) = decode_b64(id_b64) {
                allow_list.push(Value::Map(vec![
                    (Value::Text("id".into()), Value::Bytes(id_bytes)),
                    (Value::Text("type".into()), Value::Text("public-key".into())),
                ]));
            }
        }
        if !allow_list.is_empty() {
            params.push((Value::Unsigned(3), Value::Array(allow_list)));
        }
    }

    let mut options = Vec::new();
    if req.user_verification {
        options.push((Value::Text("uv".into()), Value::Bool(true)));
    }
    options.push((Value::Text("up".into()), Value::Bool(true)));
    params.push((Value::Unsigned(5), Value::Map(options)));

    let ctap_req = Request::new(Command(0x02), Value::Map(params).encode());
    let timeout = Duration::from_millis(req.timeout);
    let resp = transact_with_fallback(&ctap_req, timeout)
        .map_err(|e| format!("GetAssertion failed: {e}"))?;

    let parsed = GetAssertionResponse::parse(&resp.data)
        .map_err(|e| format!("Failed to parse GetAssertion response: {e}"))?;

    let cred_id_bytes = parsed
        .credential_id
        .or_else(|| {
            req.allow_credentials
                .first()
                .and_then(|s| decode_b64(s).ok())
        })
        .unwrap_or_default();

    let ctap_cbor = Value::decode(&resp.data).ok();
    let user_handle_b64 = ctap_cbor
        .as_ref()
        .and_then(|c| c.get(4))
        .and_then(|u| u.get_str("id"))
        .and_then(Value::as_bytes)
        .map(encode_b64);

    let cred_id_b64 = encode_b64(&cred_id_bytes);
    let auth_data_b64 = encode_b64(&parsed.auth_data_raw);
    let signature_b64 = encode_b64(&parsed.signature);

    let mut resp_obj = HostResponse::ok();
    resp_obj.id = Some(cred_id_b64.clone());
    resp_obj.raw_id = Some(cred_id_b64);
    resp_obj.cred_type = Some("public-key".into());
    resp_obj.response = Some(serde_json::json!({
        "clientDataJSON": req.client_data_json,
        "authenticatorData": auth_data_b64,
        "signature": signature_b64,
        "userHandle": user_handle_b64
    }));

    Ok(resp_obj)
}

fn read_native_message<R: Read>(reader: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }

    let len = u32::from_ne_bytes(len_buf) as usize;
    if len > 10 * 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message too large",
        ));
    }

    let mut msg_buf = vec![0u8; len];
    reader.read_exact(&mut msg_buf)?;
    Ok(Some(msg_buf))
}

fn write_native_message<W: Write>(writer: &mut W, data: &[u8]) -> io::Result<()> {
    let len = (data.len() as u32).to_ne_bytes();
    writer.write_all(&len)?;
    writer.write_all(data)?;
    writer.flush()?;
    Ok(())
}

/// Parses and dispatches one native-messaging request, returning its final
/// response.
///
/// Split out of `main` so each request can be handled on its own thread (see
/// `main`'s doc comment for why that matters) without duplicating the big
/// dispatch match.
fn handle_request(msg_bytes: &[u8], stdout_lock: &Mutex<()>) -> HostResponse {
    match serde_json::from_slice::<HostRequest>(msg_bytes) {
        Ok(HostRequest::Ping) => {
            let mut r = HostResponse::ok();
            r.version = Some(env!("CARGO_PKG_VERSION").into());
            r
        }
        Ok(HostRequest::Status) => {
            let t0 = std::time::Instant::now();
            let now_utc = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let usb_ctaphid = UsbClient::try_connect().is_some();
            let usb_serial_present = check_usb_device();

            let (tz_mins, tz_str) = get_local_tz_offset();

            if usb_ctaphid {
                let elapsed = t0.elapsed().as_millis().max(1) as u64;
                let mut r = HostResponse::ok();
                r.in_range = Some(true);
                r.bonded = Some(true);
                r.usb = Some(true);
                r.daemon_running = Some(true);
                r.transport = Some("usb".into());
                r.latency_ms = Some(elapsed);
                r.clock_utc = Some(now_utc);
                r.clock_synced = Some(true);
                r.time_offset_secs = Some(0);
                r.tz_offset_mins = Some(tz_mins);
                r.tz_offset_str = Some(tz_str);
                r
            } else {
                match DaemonClient::connect(Duration::from_millis(300)) {
                    Ok(mut client) => match client.device_status() {
                        Ok((in_range, bonded)) => {
                            let elapsed = t0.elapsed().as_millis().max(1) as u64;
                            let mut r = HostResponse::ok();
                            r.in_range = Some(in_range);
                            r.bonded = Some(bonded);
                            r.usb = Some(false);
                            r.daemon_running = Some(true);
                            r.transport = Some(if in_range {
                                "ble".into()
                            } else {
                                "none".into()
                            });
                            r.latency_ms = if in_range { Some(elapsed) } else { None };
                            r.clock_utc = Some(now_utc);
                            r.clock_synced = Some(in_range);
                            r.time_offset_secs = Some(0);
                            r.tz_offset_mins = Some(tz_mins);
                            r.tz_offset_str = Some(tz_str);
                            if usb_serial_present {
                                r.message = Some(
                                    "USB device detected in bootloader mode (0x303A:0x1001)".into(),
                                );
                            }
                            r
                        }
                        Err(e) => {
                            let mut r = HostResponse::error(format!("Status query failed: {e}"));
                            r.usb = Some(false);
                            r.daemon_running = Some(true);
                            r.transport = Some("none".into());
                            r.clock_utc = Some(now_utc);
                            r.time_offset_secs = Some(0);
                            r.tz_offset_mins = Some(tz_mins);
                            r.tz_offset_str = Some(tz_str);
                            if usb_serial_present {
                                r.message = Some(
                                    "USB device detected in bootloader mode (0x303A:0x1001)".into(),
                                );
                            }
                            r
                        }
                    },
                    Err(e) => {
                        let mut r = HostResponse::error(format!("Daemon unreachable: {e}"));
                        r.usb = Some(false);
                        r.daemon_running = Some(false);
                        r.transport = Some("offline".into());
                        r.clock_utc = Some(now_utc);
                        r.time_offset_secs = Some(0);
                        r.tz_offset_mins = Some(tz_mins);
                        r.tz_offset_str = Some(tz_str);
                        if usb_serial_present {
                            r.message =
                                Some("USB device in bootloader mode and daemon unreachable".into());
                        }
                        r
                    }
                }
            }
        }
        Ok(HostRequest::Restart) => {
            #[cfg(target_os = "macos")]
            {
                // SAFETY: `getuid()` takes no arguments and has no
                // preconditions — it cannot fail or misbehave regardless of
                // process state, so there is nothing for the caller to
                // uphold beyond calling it.
                let uid = unsafe { libc::getuid() };
                let _ = std::process::Command::new("launchctl")
                    .args([
                        "kickstart",
                        "-k",
                        &format!("gui/{uid}/com.cryptick.daemon"),
                    ])
                    .output();
            }
            #[cfg(target_os = "linux")]
            {
                let _ = std::process::Command::new("systemctl")
                    .args(["--user", "restart", "cryptick-daemon"])
                    .output();
            }
            HostResponse::ok()
        }
        Ok(HostRequest::Create(req)) => match handle_create(req) {
            Ok(r) => r,
            Err(e) => HostResponse::error(e),
        },
        Ok(HostRequest::Get(req)) => match handle_get(req) {
            Ok(r) => r,
            Err(e) => HostResponse::error(e),
        },
        Ok(HostRequest::TotpList) => match handle_totp_list() {
            Ok(accs) => {
                let mut r = HostResponse::ok();
                r.accounts = Some(accs);
                r
            }
            Err(e) => HostResponse::error(format!("TOTP list failed: {e}")),
        },
        Ok(HostRequest::TotpCode(req)) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let counter = now / 30;
            let remaining = (30 - (now % 30)) as u32;
            match handle_totp_code(&req.name, counter) {
                Ok(code) => {
                    let mut r = HostResponse::ok();
                    r.name = Some(req.name);
                    r.code = Some(code);
                    r.remaining = Some(remaining);
                    r.clock_utc = Some(now);
                    let (tz_mins, tz_str) = get_local_tz_offset();
                    r.tz_offset_mins = Some(tz_mins);
                    r.tz_offset_str = Some(tz_str);
                    r
                }
                Err(e) => HostResponse::error(format!("TOTP calculate failed: {e}")),
            }
        }
        Ok(HostRequest::SyncTime) | Ok(HostRequest::TotpSyncTime) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let (tz_mins, tz_str) = get_local_tz_offset();
            match handle_sync_time(now) {
                Ok(()) => {
                    let mut r = HostResponse::ok();
                    r.message = Some(format!(
                        "Hardware RTC and soft clock synchronized to UTC {now} ({tz_str})"
                    ));
                    r.clock_utc = Some(now);
                    r.clock_synced = Some(true);
                    r.time_offset_secs = Some(0);
                    r.tz_offset_mins = Some(tz_mins);
                    r.tz_offset_str = Some(tz_str);
                    r
                }
                Err(e) => HostResponse::error(format!("Time sync failed: {e}")),
            }
        }
        Ok(HostRequest::ListCredentials) => handle_list_credentials(stdout_lock),
        Ok(HostRequest::DeleteCredential(req)) => handle_delete_credential(stdout_lock, req),
        Ok(HostRequest::ListDevices) => handle_list_devices(),
        Ok(HostRequest::SelectDevice(req)) => handle_select_device(req),
        Err(e) => HostResponse::error(format!("Malformed request: {e}")),
    }
}

/// Serialises one `HostResponse` and writes it as a framed native message,
/// guarded by `stdout_lock` so two concurrent request-handling threads (see
/// `main`) can never interleave one response's length prefix with another's
/// body.
fn write_response(stdout_lock: &Mutex<()>, resp: &HostResponse) {
    let Ok(json_bytes) = serde_json::to_vec(resp) else {
        return;
    };
    let _guard = stdout_lock.lock().unwrap_or_else(|e| e.into_inner());
    let stdout = io::stdout();
    let mut writer = stdout.lock();
    let _ = write_native_message(&mut writer, &json_bytes);
}

/// Reads and dispatches native-messaging requests from the extension.
///
/// Each request is handled on its own thread so a request that blocks for
/// seconds waiting on the device's own touch/fingerprint ceremony (`create`,
/// `get`, `totp_code`, `list_credentials`, `delete_credential`) never delays
/// a concurrent `status` poll behind it.
///
/// **Why this changed.** Before this, the whole native messaging host was one
/// blocking loop: `read_native_message` was not called again until the
/// in-flight request's handler had already returned, so a `status` request
/// sent by the extension while e.g. a fingerprint-gated `totp_code` call was
/// outstanding just sat unread in the stdin pipe for the entire wait. The
/// extension's own status-poll timeout (seconds, well under the device's
/// touch-wait budget — firmware's `CTAP2_UP_DELAY_MS` is 29s,
/// `core/fido2/ctap.h`) would fire first and read as "device disconnected"
/// while the device was in fact mid-ceremony and perfectly healthy.
///
/// This was tracked down as the root cause of the OATH/TOTP "asking for a
/// code appears to disconnect the device" report: the daemon's own
/// `device.status` IPC handling is already non-blocking and lock-free with
/// respect to an in-flight CTAP transaction — `crates/daemon/src/server.rs`'s
/// `DeviceStatus` arm reads `Bridge::link()` directly and never touches the
/// per-connection `in_flight` guard or the `Bridge`'s transaction `Mutex`
/// (`crates/daemon/src/bridge.rs`) — and every native-messaging request here
/// already opens its own fresh `DaemonClient`/`UsbClient` connection rather
/// than sharing one. Nothing on the daemon or BLE side was serialising a
/// status check behind a slow transaction; this process's own request loop
/// was.
fn main() {
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let stdout_lock = Arc::new(Mutex::new(()));

    while let Ok(Some(msg_bytes)) = read_native_message(&mut reader) {
        let stdout_lock = Arc::clone(&stdout_lock);
        std::thread::spawn(move || {
            let resp = handle_request(&msg_bytes, &stdout_lock);
            write_response(&stdout_lock, &resp);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_roundtrip() {
        let original = b"Cryptick Token WebAuthn Test Bytes 12345";
        let encoded = encode_b64(original);
        let decoded = decode_b64(&encoded).expect("valid base64");
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_client_data_hash() {
        let client_data = r#"{"type":"webauthn.create","challenge":"dGVzdA","origin":"https://webauthn.io","crossOrigin":false}"#;
        let b64 = encode_b64(client_data.as_bytes());
        let hash = hash_client_data(&b64).expect("hash success");
        assert_eq!(hash.len(), 32);

        let mut hasher = Sha256::new();
        hasher.update(client_data.as_bytes());
        let expected = hasher.finalize().to_vec();
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_cbor_alg() {
        assert_eq!(cbor_alg(-7), Value::Negative(6));
        assert_eq!(cbor_alg(-8), Value::Negative(7));
        assert_eq!(cbor_alg(1), Value::Unsigned(1));
    }

    #[test]
    fn test_native_message_framing() {
        let payload = br#"{"action":"ping"}"#;
        let mut buffer = Vec::new();
        write_native_message(&mut buffer, payload).expect("write ok");

        assert_eq!(buffer.len(), 4 + payload.len());
        let read_back = read_native_message(&mut &buffer[..])
            .expect("read ok")
            .expect("some message");
        assert_eq!(read_back, payload);
    }

    #[test]
    fn list_credentials_request_has_no_fields() {
        let req: HostRequest = serde_json::from_str(r#"{"action":"list_credentials"}"#).unwrap();
        assert!(matches!(req, HostRequest::ListCredentials));
    }

    #[test]
    fn list_credentials_request_ignores_a_stray_pin_field() {
        // The contract changed mid-implementation: credential management is
        // gated on the device's own fingerprint ceremony, not a PIN, and the
        // `pin` field this action's request used to carry was dropped
        // entirely — nothing in `HostRequest::ListCredentials` reads it.
        // Neither `HostRequest` nor any of its variants set
        // `#[serde(deny_unknown_fields)]`, so a caller still on the old
        // contract (or mid-rollout) is harmlessly ignored rather than
        // rejected; this pins that down as deliberate rather than
        // accidental.
        let req: HostRequest =
            serde_json::from_str(r#"{"action":"list_credentials","pin":"123456"}"#).unwrap();
        assert!(matches!(req, HostRequest::ListCredentials));
    }

    #[test]
    fn delete_credential_request_parses_both_fields() {
        let req: HostRequest = serde_json::from_str(
            r#"{"action":"delete_credential","credentialId":"abc123","rpId":"example.com"}"#,
        )
        .unwrap();
        match req {
            HostRequest::DeleteCredential(d) => {
                assert_eq!(d.credential_id, "abc123");
                assert_eq!(d.rp_id, "example.com");
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn list_devices_and_select_device_requests_parse() {
        let req: HostRequest = serde_json::from_str(r#"{"action":"list_devices"}"#).unwrap();
        assert!(matches!(req, HostRequest::ListDevices));

        let req: HostRequest =
            serde_json::from_str(r#"{"action":"select_device","id":"AA:BB:CC"}"#).unwrap();
        match req {
            HostRequest::SelectDevice(s) => assert_eq!(s.id, "AA:BB:CC"),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn select_device_usb_is_a_local_no_op_even_with_no_daemon_running() {
        // "usb" has nothing to switch to (handle_list_devices's doc comment)
        // and must not depend on a daemon that may not even be running.
        let resp = handle_select_device(SelectDeviceRequest { id: "usb".into() });
        assert_eq!(resp.status, "ok");
    }

    #[test]
    fn uv_token_failure_maps_each_known_status_to_its_own_outcome() {
        assert_eq!(
            uv_token_failure("x", ctap::StatusCode::ACTION_TIMEOUT).status,
            "timeout"
        );
        assert_eq!(
            uv_token_failure("x", ctap::StatusCode::USER_ACTION_TIMEOUT).status,
            "timeout"
        );
        assert_eq!(
            uv_token_failure("x", ctap::StatusCode::KEEPALIVE_CANCEL).status,
            "cancelled"
        );
        // CTAP1_ERR_OTHER is what this firmware answers today for the
        // not-yet-implemented UV-token subcommand — see
        // ctap_client::cred_mgmt::client_pin_subcommand's doc comment.
        assert_eq!(
            uv_token_failure("x", ctap::StatusCode::OTHER).status,
            "uv_token_unsupported"
        );
        // Anything else is a real, undifferentiated error — not silently
        // folded into one of the three special cases above.
        let generic = uv_token_failure("context", ctap::StatusCode::PIN_NOT_SET);
        assert_eq!(generic.status, "error");
        assert!(generic.message.unwrap().contains("context"));
    }

    #[test]
    fn test_usb_device_oath() {
        if let Some(mut usb) = UsbClient::try_connect() {
            let accounts = usb.oath_list(Duration::from_secs(2)).expect("oath_list ok");
            println!("USB token connected! OATH accounts: {:?}", accounts);
        } else {
            println!("No USB token connected; skipping hardware test");
        }
    }
}
