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
}

#[derive(Debug, Deserialize)]
struct TotpCodeRequest {
    name: String,
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
        }
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
        }
    }
}

fn get_local_tz_offset() -> (i32, String) {
    let t = unsafe { libc::time(std::ptr::null_mut()) };
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
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
        return usb.transact(request, timeout);
    }

    // If USB is present on the bus, retry USB with brief backoffs in case of enumeration lag
    if check_usb_device() {
        for _ in 0..3 {
            std::thread::sleep(Duration::from_millis(150));
            if let Some(mut usb) = UsbClient::try_connect() {
                return usb.transact(request, timeout);
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
        return usb.oath_list(Duration::from_secs(3));
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
        return usb.oath_calculate(name, counter, Duration::from_secs(25));
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
        return usb.oath_set_time(utc_secs, Duration::from_secs(3));
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

fn main() {
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let stdout = io::stdout();
    let mut writer = stdout.lock();

    while let Ok(Some(msg_bytes)) = read_native_message(&mut reader) {
        let resp = match serde_json::from_slice::<HostRequest>(&msg_bytes) {
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
                        Ok(mut client) => {
                            match client.device_status() {
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
                                        r.message = Some("USB device detected in bootloader mode (0x303A:0x1001)".into());
                                    }
                                    r
                                }
                                Err(e) => {
                                    let mut r =
                                        HostResponse::error(format!("Status query failed: {e}"));
                                    r.usb = Some(false);
                                    r.daemon_running = Some(true);
                                    r.transport = Some("none".into());
                                    r.clock_utc = Some(now_utc);
                                    r.time_offset_secs = Some(0);
                                    r.tz_offset_mins = Some(tz_mins);
                                    r.tz_offset_str = Some(tz_str);
                                    if usb_serial_present {
                                        r.message = Some("USB device detected in bootloader mode (0x303A:0x1001)".into());
                                    }
                                    r
                                }
                            }
                        }
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
                                r.message = Some(
                                    "USB device in bootloader mode and daemon unreachable".into(),
                                );
                            }
                            r
                        }
                    }
                }
            }
            Ok(HostRequest::Restart) => {
                #[cfg(target_os = "macos")]
                {
                    let _ = std::process::Command::new("launchctl")
                        .args([
                            "kickstart",
                            "-k",
                            &format!("gui/{}/com.cryptick.daemon", unsafe { libc::getuid() }),
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
            Err(e) => HostResponse::error(format!("Malformed request: {e}")),
        };

        if let Ok(json_bytes) = serde_json::to_vec(&resp) {
            let _ = write_native_message(&mut writer, &json_bytes);
        }
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
    fn test_usb_device_oath() {
        if let Some(mut usb) = UsbClient::try_connect() {
            let accounts = usb.oath_list(Duration::from_secs(2)).expect("oath_list ok");
            println!("USB token connected! OATH accounts: {:?}", accounts);
        } else {
            println!("No USB token connected; skipping hardware test");
        }
    }
}
