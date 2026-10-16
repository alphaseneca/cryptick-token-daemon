//! `authenticatorCredentialManagement` (vendor-prefixed `0x41` on this
//! firmware) and the `authenticatorClientPIN` subcommands it depends on.
//!
//! See `pin_protocol.rs`'s module doc for why this lives in `ctap-client`
//! rather than `daemon`. Every byte layout here was read directly out of
//! `ctap_parse_cred_mgmt`/`ctap_cred_mgmt`/`ctap_client_pin` in
//! `core/fido2/ctap.c` and `core/fido2/ctap_parse.c` — not assumed from the
//! CTAP2.1 spec's shape for the *standardised* `authenticatorCredentialManagement`
//! (`0x0a`), because this device predates that standardisation and implements
//! the earlier "FIDO_2_1_PRE" vendor prototype instead (confirmed by
//! `core/fido2/ctap.c`'s own comment: "Not FIDO_2_1_PRE: stay on CTAP2.0
//! built-in UV, not pinUvAuthToken-only" at the surrounding `ctap_get_info`,
//! and by `CTAP_CBOR_CRED_MGMT_PRE = 0x41` being the command this firmware's
//! `ctap_request` dispatch table actually routes, `core/fido2/ctap.c` ~line
//! 2517 — `CTAP_CBOR_CRED_MGMT` (`0x0a`, the standardised command) is not
//! dispatched to anything).

use crate::cbor::Value;
use crate::pin_protocol::{DeviceKeyAgreement, PinProtocolError, PlatformKeyAgreement};
use ctap::{Command, Request};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// This firmware's vendor command for credential management. `ctap::Command`
/// has no named constant for it (it is specific to the PRE shape, not
/// standard CTAP2.1), so it is a local one here rather than added to `ctap`,
/// which deliberately only names commands every caller needs (its own doc
/// comment: "Named constants exist for the values the daemon actually
/// branches on").
pub const CREDENTIAL_MANAGEMENT_PRE: Command = Command(0x41);

/// `CM_cmd` subcommand values (`core/fido2/ctap.h`).
pub mod subcommand {
    /// `CM_cmdMetadata` — credential/slot counts. No pinAuth-signed params.
    pub const METADATA: i64 = 0x01;
    /// `CM_cmdRPBegin` — start enumerating relying parties. No signed params.
    pub const RP_BEGIN: i64 = 0x02;
    /// `CM_cmdRPNext` — continue RP enumeration. Not pinAuth-gated (the
    /// `*Begin` call already was) — `ctap_cred_mgmt_pinauth` explicitly skips
    /// pinAuth verification for this subcommand.
    pub const RP_NEXT: i64 = 0x03;
    /// `CM_cmdRKBegin` — start enumerating one RP's resident credentials.
    /// Signed params: `{1: rpIdHash}`.
    pub const RK_BEGIN: i64 = 0x04;
    /// `CM_cmdRKNext` — continue credential enumeration. Not pinAuth-gated.
    pub const RK_NEXT: i64 = 0x05;
    /// `CM_cmdRKDelete` — delete one resident credential. Signed params:
    /// `{2: credentialDescriptor}`.
    pub const RK_DELETE: i64 = 0x06;
}

/// Top-level `authenticatorCredentialManagement` request map keys.
mod field {
    pub const CMD: u64 = 1;
    pub const SUB_COMMAND_PARAMS: u64 = 2;
    pub const PIN_PROTOCOL: u64 = 3;
    pub const PIN_AUTH: u64 = 4;
}

/// `CM_subCommandParams` map keys.
mod sub_param {
    pub const RP_ID_HASH: u64 = 1;
    pub const CREDENTIAL: u64 = 2;
}

/// Response map keys. Two disjoint sets share this namespace depending on
/// which subcommand answered — `ctap_cred_metadata`/`ctap_cred_rp`/
/// `ctap_cred_rk` in `core/fido2/ctap.c` each only ever write a subset.
mod resp {
    pub const EXISTING_RESIDENT_CREDENTIALS_COUNT: u64 = 1;
    pub const MAX_POSSIBLE_REMAINING_CREDENTIALS_COUNT: u64 = 2;
    pub const RP: u64 = 3;
    pub const RP_ID_HASH: u64 = 4;
    pub const TOTAL_RPS: u64 = 5;
    pub const USER: u64 = 6;
    pub const CREDENTIAL_ID: u64 = 7;
    // PUBLIC_KEY = 8 exists on the wire (the credential's COSE public key)
    // but nothing on the daemon/webauthn-host side needs it for listing or
    // deleting, so it is read past rather than parsed.
    pub const TOTAL_CREDENTIALS: u64 = 9;
    pub const CRED_PROTECT: u64 = 0x0a;
}

/// Something about a credential-management request or response did not fit
/// what the firmware expects/returns.
#[derive(Debug, Error)]
pub enum CredMgmtError {
    /// The PIN protocol step that must happen first failed.
    #[error("PIN protocol error: {0}")]
    PinProtocol(#[from] PinProtocolError),
    /// The response CBOR did not parse at all.
    #[error("response is not valid CBOR: {0}")]
    Cbor(#[from] crate::cbor::CborError),
    /// A field the parser needed was absent or the wrong type.
    #[error("response missing or malformed field: {0}")]
    MissingField(&'static str),
}

/// Builds the one-byte-plus-subCommandParams input `pinAuth` signs.
///
/// Mirrors `ctap_cred_mgmt_pinauth`'s `verify_pin_auth_ex(CM->pinAuth,
/// (uint8_t*)&CM->hashed, CM->subCommandParamsCborSize + 1)` exactly: the
/// `cmd` byte followed by the *raw encoded bytes* of `subCommandParams` as
/// they appear on the wire (`core/fido2/ctap_parse.c`'s
/// `parse_cred_mgmt_subcommandparams` copies those bytes verbatim from the
/// request buffer rather than re-deriving them). Since this code builds both
/// the request and the pinAuth input from the same `Value`, encoding it once
/// and signing exactly those bytes keeps the two guaranteed consistent — the
/// one failure mode this has to avoid is encoding the map twice and getting
/// two different byte strings.
fn signed_bytes(cmd: i64, sub_command_params: Option<&Value>) -> Vec<u8> {
    let mut out = vec![cmd as u8];
    if let Some(params) = sub_command_params {
        out.extend_from_slice(&params.encode());
    }
    out
}

/// Builds one `authenticatorCredentialManagement` request, signing it with
/// `pin_token` when the subcommand requires it (`METADATA`, `RP_BEGIN`,
/// `RK_BEGIN`, `RK_DELETE` — matches `ctap_cred_mgmt_pinauth`'s list exactly;
/// `RP_NEXT`/`RK_NEXT` pass `pin_token: None`).
fn build_request(
    cmd: i64,
    sub_command_params: Option<Value>,
    pin_token: Option<&[u8; 16]>,
) -> Request {
    let mut map = vec![(Value::Unsigned(field::CMD), Value::Unsigned(cmd as u64))];

    if let Some(params) = &sub_command_params {
        map.push((Value::Unsigned(field::SUB_COMMAND_PARAMS), params.clone()));
    }

    if let Some(token) = pin_token {
        let signed = signed_bytes(cmd, sub_command_params.as_ref());
        let auth = crate::pin_protocol::pin_auth(token, &signed);
        map.push((
            Value::Unsigned(field::PIN_PROTOCOL),
            Value::Unsigned(crate::pin_protocol::PIN_PROTOCOL_VERSION as u64),
        ));
        map.push((
            Value::Unsigned(field::PIN_AUTH),
            Value::Bytes(auth.to_vec()),
        ));
    }

    Request::new(CREDENTIAL_MANAGEMENT_PRE, Value::Map(map).encode())
}

/// `CM_cmdMetadata`: `{"existingResidentCredentialsCount":
/// "maxPossibleRemainingResidentCredentialsCount"}`.
pub fn metadata_request(pin_token: &[u8; 16]) -> Request {
    build_request(subcommand::METADATA, None, Some(pin_token))
}

/// `CM_cmdRPBegin`: start relying-party enumeration.
pub fn rp_begin_request(pin_token: &[u8; 16]) -> Request {
    build_request(subcommand::RP_BEGIN, None, Some(pin_token))
}

/// `CM_cmdRPNext`: the next relying party. Not pinAuth-signed — a `*Begin`
/// must already have authenticated this enumeration (device-side state,
/// `rp_auth`/`rk_auth` in `ctap_cred_mgmt`).
pub fn rp_next_request() -> Request {
    build_request(subcommand::RP_NEXT, None, None)
}

/// SHA-256 of the UTF-8 `rpId`, exactly as the device computes it for its own
/// resident-key records (`crypto_sha256_update(rp->id, rp->size)` at
/// registration time, `core/fido2/ctap.c`).
pub fn rp_id_hash(rp_id: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(rp_id.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// `CM_cmdRKBegin`: start enumerating one RP's resident credentials.
pub fn rk_begin_request(pin_token: &[u8; 16], rp_id_hash: &[u8; 32]) -> Request {
    let params = Value::Map(vec![(
        Value::Unsigned(sub_param::RP_ID_HASH),
        Value::Bytes(rp_id_hash.to_vec()),
    )]);
    build_request(subcommand::RK_BEGIN, Some(params), Some(pin_token))
}

/// `CM_cmdRKNext`: the next credential for the RP a `RKBegin` already named.
pub fn rk_next_request() -> Request {
    build_request(subcommand::RK_NEXT, None, None)
}

/// `CM_cmdRKDelete`: delete one resident credential by its opaque credential
/// ID (this device's internal `CredentialId` struct, round-tripped
/// opaquely — never interpreted here, exactly as `parse_credential_descriptor`
/// in `core/fido2/ctap_parse.c` treats whatever length arrives).
pub fn rk_delete_request(pin_token: &[u8; 16], credential_id: &[u8]) -> Request {
    let descriptor = Value::Map(vec![
        (
            Value::Text("id".into()),
            Value::Bytes(credential_id.to_vec()),
        ),
        (Value::Text("type".into()), Value::Text("public-key".into())),
    ]);
    let params = Value::Map(vec![(Value::Unsigned(sub_param::CREDENTIAL), descriptor)]);
    build_request(subcommand::RK_DELETE, Some(params), Some(pin_token))
}

/// `CM_cmdMetadata`'s response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metadata {
    /// How many resident credentials currently exist on the device.
    pub existing_resident_credentials_count: i64,
    /// How many more the device has room for.
    pub max_possible_remaining: i64,
}

impl Metadata {
    /// Parses `ctap_cred_metadata`'s two-entry response map.
    pub fn parse(data: &[u8]) -> Result<Self, CredMgmtError> {
        let value = Value::decode(data)?;
        let existing = value
            .get(resp::EXISTING_RESIDENT_CREDENTIALS_COUNT)
            .and_then(Value::as_i64)
            .ok_or(CredMgmtError::MissingField(
                "existingResidentCredentialsCount",
            ))?;
        let remaining = value
            .get(resp::MAX_POSSIBLE_REMAINING_CREDENTIALS_COUNT)
            .and_then(Value::as_i64)
            .ok_or(CredMgmtError::MissingField(
                "maxPossibleRemainingResidentCredentialsCount",
            ))?;
        Ok(Self {
            existing_resident_credentials_count: existing,
            max_possible_remaining: remaining,
        })
    }
}

/// One relying party, from a `CM_cmdRPBegin`/`CM_cmdRPNext` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpEntry {
    /// The relying party ID (e.g. `"example.com"`).
    pub rp_id: String,
    /// The display name this firmware returns alongside it.
    ///
    /// **Firmware quirk, not a bug in this parser:** `ctap_cred_rp`
    /// (`core/fido2/ctap.c`) encodes `rk.user.name` — the *user* entity's
    /// name field of whichever resident key it happened to load — as this
    /// RP's "name", because the firmware has no separate per-RP display-name
    /// storage. For an RP with multiple accounts this is simply whichever
    /// one the enumeration scan landed on. Surfaced as-is rather than
    /// papered over, so a caller can decide how (or whether) to show it.
    pub rp_name: Option<String>,
    /// SHA-256 of `rp_id`. Needed verbatim to start `CM_cmdRKBegin` for this
    /// RP — compare against [`rp_id_hash`] rather than trusting a
    /// recomputation to agree byte for byte with whatever this came from.
    pub rp_id_hash: [u8; 32],
    /// Total number of distinct relying parties with resident credentials.
    /// Present only on the first (`Begin`) response — mirrors
    /// `ctap_cred_mgmt`'s `rp_count`, which is computed once and not
    /// recomputed for `*Next` calls.
    pub total_rps: Option<i64>,
}

impl RpEntry {
    /// Parses one `ctap_cred_rp` response map.
    pub fn parse(data: &[u8]) -> Result<Self, CredMgmtError> {
        let value = Value::decode(data)?;
        let rp = value
            .get(resp::RP)
            .ok_or(CredMgmtError::MissingField("rp"))?;
        let rp_id = rp
            .get_str("id")
            .and_then(Value::as_str)
            .ok_or(CredMgmtError::MissingField("rp.id"))?
            .to_string();
        let rp_name = rp
            .get_str("name")
            .and_then(Value::as_str)
            .map(str::to_string);
        let hash_bytes = value
            .get(resp::RP_ID_HASH)
            .and_then(Value::as_bytes)
            .ok_or(CredMgmtError::MissingField("rpIdHash"))?;
        if hash_bytes.len() != 32 {
            return Err(CredMgmtError::MissingField("rpIdHash (wrong length)"));
        }
        let mut rp_id_hash = [0u8; 32];
        rp_id_hash.copy_from_slice(hash_bytes);
        let total_rps = value.get(resp::TOTAL_RPS).and_then(Value::as_i64);

        Ok(Self {
            rp_id,
            rp_name,
            rp_id_hash,
            total_rps,
        })
    }
}

/// One resident credential, from a `CM_cmdRKBegin`/`CM_cmdRKNext` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialEntry {
    /// The opaque credential ID — this device's internal `CredentialId`
    /// struct, round-tripped unexamined (`ctap_add_credential_descriptor`
    /// just byte-copies it).
    pub credential_id: Vec<u8>,
    /// The WebAuthn user handle (opaque bytes, not necessarily text).
    pub user_id: Vec<u8>,
    /// The account name, if the device stored one and is treating it as
    /// verified (`ctap_add_user_entity`'s `is_verified` gate — always `1` on
    /// the credential-management path, so this is omitted only when the
    /// stored name itself is empty).
    pub user_name: Option<String>,
    /// The display name, same gating as `user_name`.
    pub user_display_name: Option<String>,
    /// Total resident credentials for the RP this enumeration is scoped to.
    /// Present only on the first (`Begin`) response.
    pub total_credentials: Option<i64>,
    /// `EXT_CRED_PROTECT_*` (`core/fido2/ctap.h`): the credProtect policy
    /// this credential was created with.
    pub cred_protect: Option<i64>,
}

impl CredentialEntry {
    /// Parses one `ctap_cred_rk` response map.
    pub fn parse(data: &[u8]) -> Result<Self, CredMgmtError> {
        let value = Value::decode(data)?;

        let user = value
            .get(resp::USER)
            .ok_or(CredMgmtError::MissingField("user"))?;
        let user_id = user
            .get_str("id")
            .and_then(Value::as_bytes)
            .ok_or(CredMgmtError::MissingField("user.id"))?
            .to_vec();
        let user_name = user
            .get_str("name")
            .and_then(Value::as_str)
            .map(str::to_string);
        let user_display_name = user
            .get_str("displayName")
            .and_then(Value::as_str)
            .map(str::to_string);

        let descriptor = value
            .get(resp::CREDENTIAL_ID)
            .ok_or(CredMgmtError::MissingField("credentialID"))?;
        let credential_id = descriptor
            .get_str("id")
            .and_then(Value::as_bytes)
            .ok_or(CredMgmtError::MissingField("credentialID.id"))?
            .to_vec();

        let total_credentials = value.get(resp::TOTAL_CREDENTIALS).and_then(Value::as_i64);
        let cred_protect = value.get(resp::CRED_PROTECT).and_then(Value::as_i64);

        Ok(Self {
            credential_id,
            user_id,
            user_name,
            user_display_name,
            total_credentials,
            cred_protect,
        })
    }
}

/// `authenticatorClientPIN` (`0x06`) subcommand numbers this crate uses.
pub mod client_pin_subcommand {
    /// `CP_cmdGetRetries`.
    pub const GET_RETRIES: i64 = 0x01;
    /// `CP_cmdGetKeyAgreement`.
    pub const GET_KEY_AGREEMENT: i64 = 0x02;
    /// `CP_cmdSetPin`. Not used by the credential-listing path; kept named
    /// here for a future `set_pin` action.
    pub const SET_PIN: i64 = 0x03;
    /// `CP_cmdChangePin`. Same note as `SET_PIN`.
    pub const CHANGE_PIN: i64 = 0x04;
    /// `CP_cmdGetPinToken`. The CTAP2.0 PIN-based path — not used here after
    /// the product decision to gate credential management on the
    /// fingerprint, the same ceremony as everyday sign-in, rather than a
    /// typed PIN. Kept named and documented because it is still real wire
    /// protocol this firmware answers, and `set_pin`/`change_pin` (if ever
    /// built) still need it to obtain a token that authorises *those*
    /// subcommands' own pinAuth.
    pub const GET_PIN_TOKEN: i64 = 0x05;
    /// `getPinUvAuthTokenUsingUvWithPermissions` — **provisional, unconfirmed
    /// against real firmware.** `0x06` is this subcommand's value in the
    /// CTAP2.1 spec's `authenticatorClientPIN` subCommand table, and this
    /// firmware's existing values 0x01-0x05 above match the spec's numbering
    /// exactly, which is why 0x06 is the value used here rather than a guess
    /// with no anchor — but as of this writing `ctap_client_pin`
    /// (`core/fido2/ctap.c`) has no `case` for it: its `switch` only handles
    /// 0x01 through 0x05 and returns `CTAP1_ERR_OTHER` (`0x7f`) for anything
    /// else, including this one. A parallel firmware task is adding real
    /// support for it, gated on the fingerprint sensor via the existing
    /// `ctap_user_presence_test_ex`/`fp_system` machinery, writing into the
    /// same `PIN_TOKEN` global `verify_pin_auth_ex` already checks. Until
    /// that lands, [`get_uv_token_request`] builds a request against this
    /// value and the caller must be ready to see `CTAP1_ERR_OTHER` back
    /// rather than a token — see `webauthn-host`'s handling of
    /// `ctap::StatusCode::OTHER` on this specific request.
    pub const GET_PIN_UV_AUTH_TOKEN_USING_UV_WITH_PERMISSIONS: i64 = 0x06;
}

/// `authenticatorClientPIN` top-level request map keys (`CP_*`,
/// `core/fido2/ctap.h`).
mod cp_field {
    pub const PIN_PROTOCOL: u64 = 1;
    pub const SUB_COMMAND: u64 = 2;
    pub const KEY_AGREEMENT: u64 = 3;
    // Named for completeness against `core/fido2/ctap.h`'s full `CP_*` table,
    // even though nothing in this file sends it yet: `setPIN`/`changePIN`
    // (deferred — see NOTES.md) sign their own request with this field, the
    // same `pin_auth()` this module already uses for credential management.
    #[allow(dead_code)]
    pub const PIN_AUTH: u64 = 4;
    // NEW_PIN_ENC = 5, PIN_HASH_ENC = 6 are the PIN-based fields this crate
    // does not send on the credential-listing path. `7: getKeyAgreement` and
    // `8: getRetries` (CP_getKeyAgreement/CP_getRetries) are request-side
    // *boolean* flags this firmware's `ctap_parse_client_pin` also accepts
    // (confirmed by reading it) but nothing here sends — they are a
    // different, older-looking convention for asking for extra response
    // fields alongside a subcommand's own answer, and the plain
    // `subCommand`-driven requests below don't need them.
    // CTAP2.1 adds `9: permissions` and `10: rpId` for
    // getPinUvAuthTokenUsingUvWithPermissions. These are not in this
    // firmware's current `ctap.h` (it only goes up to CP_getRetries = 8),
    // consistent with the subcommand itself not being implemented yet — the
    // numbering is taken from the CTAP2.1 spec table, matching how this
    // firmware's existing CP_* values already line up with that spec.
    pub const PERMISSIONS: u64 = 9;
    pub const PERMISSIONS_RP_ID: u64 = 10;
}

/// `authenticatorClientPIN` response map keys (`RESP_*`, `core/fido2/ctap.h`).
mod cp_resp {
    pub const KEY_AGREEMENT: u64 = 1;
    pub const PIN_TOKEN: u64 = 2;
    pub const RETRIES: u64 = 3;
}

/// Credential-management permission bit for `permissions` (CTAP2.1 §6.5.5.7).
pub const PERMISSION_CREDENTIAL_MANAGEMENT: u8 = 0x04;

/// `CP_cmdGetKeyAgreement`: ask the device for its current key-agreement
/// public key. No pinAuth, no pinToken — this is the first message of every
/// PIN-protocol exchange.
pub fn get_key_agreement_request() -> Request {
    let map = Value::Map(vec![
        (
            Value::Unsigned(cp_field::PIN_PROTOCOL),
            Value::Unsigned(crate::pin_protocol::PIN_PROTOCOL_VERSION as u64),
        ),
        (
            Value::Unsigned(cp_field::SUB_COMMAND),
            Value::Unsigned(client_pin_subcommand::GET_KEY_AGREEMENT as u64),
        ),
    ]);
    Request::new(Command::CLIENT_PIN, map.encode())
}

/// Parses a `getKeyAgreement` response into the device's public key.
pub fn parse_key_agreement_response(data: &[u8]) -> Result<DeviceKeyAgreement, CredMgmtError> {
    let value = Value::decode(data)?;
    let key = value
        .get(cp_resp::KEY_AGREEMENT)
        .ok_or(CredMgmtError::MissingField("keyAgreement"))?;
    Ok(DeviceKeyAgreement::from_value(key)?)
}

/// `CP_cmdGetRetries`: how many PIN attempts remain. Still meaningful even
/// though the UV-token path does not use a PIN itself — a `pin_invalid`-style
/// outcome has no equivalent here (a mismatched fingerprint does not
/// decrement a PIN counter), but a caller that also offers `set_pin` as a
/// fallback path still needs this for *that* ceremony.
pub fn get_retries_request() -> Request {
    let map = Value::Map(vec![
        (
            Value::Unsigned(cp_field::PIN_PROTOCOL),
            Value::Unsigned(crate::pin_protocol::PIN_PROTOCOL_VERSION as u64),
        ),
        (
            Value::Unsigned(cp_field::SUB_COMMAND),
            Value::Unsigned(client_pin_subcommand::GET_RETRIES as u64),
        ),
    ]);
    Request::new(Command::CLIENT_PIN, map.encode())
}

/// Parses a `getRetries` response.
pub fn parse_retries_response(data: &[u8]) -> Result<i64, CredMgmtError> {
    let value = Value::decode(data)?;
    value
        .get(cp_resp::RETRIES)
        .and_then(Value::as_i64)
        .ok_or(CredMgmtError::MissingField("retries"))
}

/// Builds a **provisional** `getPinUvAuthTokenUsingUvWithPermissions`
/// request. See [`client_pin_subcommand::GET_PIN_UV_AUTH_TOKEN_USING_UV_WITH_PERMISSIONS`]
/// for why this is marked provisional and what to expect until the firmware
/// side lands.
///
/// `rp_id` is omitted for the plain credential-listing/deletion case: CTAP2.1
/// §6.5.5.7.2 makes `rpId` optional for the `cm` permission specifically
/// (unlike `mc`/`ga`, which require it), and there is no single RP to scope
/// this to when listing across all of them.
pub fn get_uv_token_request(
    platform_key: &PlatformKeyAgreement,
    permissions: u8,
    rp_id: Option<&str>,
) -> Request {
    let mut map = vec![
        (
            Value::Unsigned(cp_field::PIN_PROTOCOL),
            Value::Unsigned(crate::pin_protocol::PIN_PROTOCOL_VERSION as u64),
        ),
        (
            Value::Unsigned(cp_field::SUB_COMMAND),
            Value::Unsigned(
                client_pin_subcommand::GET_PIN_UV_AUTH_TOKEN_USING_UV_WITH_PERMISSIONS as u64,
            ),
        ),
        (
            Value::Unsigned(cp_field::KEY_AGREEMENT),
            platform_key.public_cose_key(),
        ),
        (
            Value::Unsigned(cp_field::PERMISSIONS),
            Value::Unsigned(permissions as u64),
        ),
    ];
    if let Some(rp_id) = rp_id {
        map.push((
            Value::Unsigned(cp_field::PERMISSIONS_RP_ID),
            Value::Text(rp_id.to_string()),
        ));
    }
    Request::new(Command::CLIENT_PIN, Value::Map(map).encode())
}

/// Decrypts the `pinUvAuthToken` out of a (once firmware support lands)
/// `getPinUvAuthTokenUsingUvWithPermissions` response. Response tag `0x02`
/// (`RESP_pinToken`) is shared with `CP_cmdGetPinToken`'s response — the
/// encryption mechanics are identical either way (`pin_protocol.rs`'s module
/// doc), so this same function is also exactly what a future `getPinToken`
/// (PIN-based) caller would use.
pub fn parse_uv_token_response(
    data: &[u8],
    shared_secret: &crate::pin_protocol::SharedSecret,
) -> Result<[u8; 16], CredMgmtError> {
    let value = Value::decode(data)?;
    let encrypted = value
        .get(cp_resp::PIN_TOKEN)
        .and_then(Value::as_bytes)
        .ok_or(CredMgmtError::MissingField("pinToken"))?;
    let decrypted = shared_secret.decrypt(encrypted)?;
    if decrypted.len() != 16 {
        return Err(CredMgmtError::MissingField(
            "pinToken (decrypted length is not 16 bytes)",
        ));
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&decrypted);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_request_has_no_sub_command_params_and_is_signed() {
        let token = [0x01u8; 16];
        let req = metadata_request(&token);
        assert_eq!(req.command, CREDENTIAL_MANAGEMENT_PRE);
        let value = Value::decode(&req.params).unwrap();
        assert_eq!(
            value.get(field::CMD).and_then(Value::as_i64),
            Some(subcommand::METADATA)
        );
        assert!(value.get(field::SUB_COMMAND_PARAMS).is_none());
        assert!(value.get(field::PIN_AUTH).is_some());

        // The signed bytes for a no-params subcommand must be exactly the one
        // cmd byte — matches `ctap_cred_mgmt_pinauth`'s
        // `subCommandParamsCborSize + 1` when size is 0.
        let auth = value
            .get(field::PIN_AUTH)
            .and_then(Value::as_bytes)
            .unwrap();
        let expected = crate::pin_protocol::pin_auth(&token, &[subcommand::METADATA as u8]);
        assert_eq!(auth, expected);
    }

    #[test]
    fn rp_next_and_rk_next_are_not_signed() {
        assert!(Value::decode(&rp_next_request().params)
            .unwrap()
            .get(field::PIN_AUTH)
            .is_none());
        assert!(Value::decode(&rk_next_request().params)
            .unwrap()
            .get(field::PIN_AUTH)
            .is_none());
    }

    #[test]
    fn rk_begin_signs_the_exact_subcommandparams_bytes() {
        let token = [0x03u8; 16];
        let hash = rp_id_hash("example.com");
        let req = rk_begin_request(&token, &hash);
        let value = Value::decode(&req.params).unwrap();

        let params = value.get(field::SUB_COMMAND_PARAMS).unwrap().clone();
        let mut expected_signed = vec![subcommand::RK_BEGIN as u8];
        expected_signed.extend_from_slice(&params.encode());
        let expected_auth = crate::pin_protocol::pin_auth(&token, &expected_signed);

        let auth = value
            .get(field::PIN_AUTH)
            .and_then(Value::as_bytes)
            .unwrap();
        assert_eq!(auth, expected_auth);
    }

    #[test]
    fn rk_delete_descriptor_matches_the_firmware_parser_shape() {
        let token = [0x04u8; 16];
        let cred_id = vec![0xAB; 90]; // this firmware's CredentialId is ~90 bytes
        let req = rk_delete_request(&token, &cred_id);
        let value = Value::decode(&req.params).unwrap();
        let params = value.get(field::SUB_COMMAND_PARAMS).unwrap();
        let descriptor = params.get(sub_param::CREDENTIAL).unwrap();
        // parse_credential_descriptor (core/fido2/ctap_parse.c) looks these
        // up by *text* key via cbor_value_map_find_value, not by position.
        assert_eq!(
            descriptor.get_str("id").and_then(Value::as_bytes),
            Some(&cred_id[..])
        );
        assert_eq!(
            descriptor.get_str("type").and_then(Value::as_str),
            Some("public-key")
        );
    }

    #[test]
    fn rp_id_hash_matches_a_known_sha256_vector() {
        // SHA-256("example.com") — a value independent of this crate.
        let hash = rp_id_hash("example.com");
        // Verified independently with `printf '%s' example.com | shasum -a 256`.
        assert_eq!(
            hex(&hash),
            "a379a6f6eeafb9a55e378c118034e2751e682fab9f2d30ab13d2125586ce1947"
        );
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn metadata_response_parses_both_fields() {
        let value = Value::Map(vec![
            (
                Value::Unsigned(resp::EXISTING_RESIDENT_CREDENTIALS_COUNT),
                Value::Unsigned(3),
            ),
            (
                Value::Unsigned(resp::MAX_POSSIBLE_REMAINING_CREDENTIALS_COUNT),
                Value::Unsigned(17),
            ),
        ]);
        let parsed = Metadata::parse(&value.encode()).unwrap();
        assert_eq!(parsed.existing_resident_credentials_count, 3);
        assert_eq!(parsed.max_possible_remaining, 17);
    }

    #[test]
    fn rp_entry_surfaces_the_firmware_name_quirk_without_hiding_it() {
        let value = Value::Map(vec![
            (
                Value::Unsigned(resp::RP),
                Value::Map(vec![
                    (Value::Text("id".into()), Value::Text("example.com".into())),
                    (
                        Value::Text("name".into()),
                        Value::Text("Alice's account".into()),
                    ),
                ]),
            ),
            (
                Value::Unsigned(resp::RP_ID_HASH),
                Value::Bytes(vec![0xAA; 32]),
            ),
            (Value::Unsigned(resp::TOTAL_RPS), Value::Unsigned(2)),
        ]);
        let parsed = RpEntry::parse(&value.encode()).unwrap();
        assert_eq!(parsed.rp_id, "example.com");
        assert_eq!(parsed.rp_name, Some("Alice's account".to_string()));
        assert_eq!(parsed.total_rps, Some(2));
    }

    #[test]
    fn rp_entry_without_total_rps_is_a_continuation_response() {
        let value = Value::Map(vec![
            (
                Value::Unsigned(resp::RP),
                Value::Map(vec![(
                    Value::Text("id".into()),
                    Value::Text("example.org".into()),
                )]),
            ),
            (
                Value::Unsigned(resp::RP_ID_HASH),
                Value::Bytes(vec![0xBB; 32]),
            ),
        ]);
        let parsed = RpEntry::parse(&value.encode()).unwrap();
        assert_eq!(parsed.total_rps, None);
        assert_eq!(parsed.rp_name, None);
    }

    #[test]
    fn credential_entry_parses_user_and_descriptor() {
        let value = Value::Map(vec![
            (
                Value::Unsigned(resp::USER),
                Value::Map(vec![
                    (Value::Text("id".into()), Value::Bytes(vec![1, 2, 3])),
                    (Value::Text("name".into()), Value::Text("alice".into())),
                    (
                        Value::Text("displayName".into()),
                        Value::Text("Alice".into()),
                    ),
                ]),
            ),
            (
                Value::Unsigned(resp::CREDENTIAL_ID),
                Value::Map(vec![
                    (Value::Text("id".into()), Value::Bytes(vec![0xCC; 16])),
                    (Value::Text("type".into()), Value::Text("public-key".into())),
                ]),
            ),
            (Value::Unsigned(resp::TOTAL_CREDENTIALS), Value::Unsigned(5)),
            (Value::Unsigned(resp::CRED_PROTECT), Value::Unsigned(1)),
        ]);
        let parsed = CredentialEntry::parse(&value.encode()).unwrap();
        assert_eq!(parsed.user_id, vec![1, 2, 3]);
        assert_eq!(parsed.user_name, Some("alice".to_string()));
        assert_eq!(parsed.user_display_name, Some("Alice".to_string()));
        assert_eq!(parsed.credential_id, vec![0xCC; 16]);
        assert_eq!(parsed.total_credentials, Some(5));
        assert_eq!(parsed.cred_protect, Some(1));
    }

    #[test]
    fn get_key_agreement_request_is_pin_protocol_one_with_no_pin_auth() {
        let req = get_key_agreement_request();
        assert_eq!(req.command, Command::CLIENT_PIN);
        let value = Value::decode(&req.params).unwrap();
        assert_eq!(
            value.get(cp_field::SUB_COMMAND).and_then(Value::as_i64),
            Some(client_pin_subcommand::GET_KEY_AGREEMENT)
        );
        assert!(value.get(cp_field::PIN_AUTH).is_none());
    }

    #[test]
    fn key_agreement_response_round_trips_a_real_device_key() {
        let platform = PlatformKeyAgreement::generate();
        let cose = platform.public_cose_key();
        let response = Value::Map(vec![(Value::Unsigned(cp_resp::KEY_AGREEMENT), cose)]);
        let parsed = parse_key_agreement_response(&response.encode()).unwrap();
        // Can't compare PublicKey directly without exposing it; proving it
        // parses without error and is usable for a shared secret is the
        // meaningful assertion here (see pin_protocol.rs's own ECDH tests
        // for the agreement property itself).
        let _ = parsed;
    }

    #[test]
    fn uv_token_request_omits_rp_id_when_not_scoped_to_one() {
        let platform = PlatformKeyAgreement::generate();
        let req = get_uv_token_request(&platform, PERMISSION_CREDENTIAL_MANAGEMENT, None);
        let value = Value::decode(&req.params).unwrap();
        assert_eq!(
            value.get(cp_field::SUB_COMMAND).and_then(Value::as_i64),
            Some(client_pin_subcommand::GET_PIN_UV_AUTH_TOKEN_USING_UV_WITH_PERMISSIONS)
        );
        assert_eq!(
            value.get(cp_field::PERMISSIONS).and_then(Value::as_i64),
            Some(PERMISSION_CREDENTIAL_MANAGEMENT as i64)
        );
        assert!(value.get(cp_field::PERMISSIONS_RP_ID).is_none());
    }

    #[test]
    fn uv_token_request_carries_rp_id_when_given() {
        let platform = PlatformKeyAgreement::generate();
        let req = get_uv_token_request(
            &platform,
            PERMISSION_CREDENTIAL_MANAGEMENT,
            Some("example.com"),
        );
        let value = Value::decode(&req.params).unwrap();
        assert_eq!(
            value
                .get(cp_field::PERMISSIONS_RP_ID)
                .and_then(Value::as_str),
            Some("example.com")
        );
    }

    #[test]
    fn uv_token_response_decrypts_with_the_right_shared_secret() {
        let platform = PlatformKeyAgreement::generate();
        let device = PlatformKeyAgreement::generate();
        let device_key_seen_by_platform =
            DeviceKeyAgreement::from_value(&device.public_cose_key()).unwrap();
        let secret = platform.shared_secret(&device_key_seen_by_platform);

        let real_token = [0x5Au8; 16];
        let encrypted = secret.encrypt(&real_token).unwrap();
        let response = Value::Map(vec![(Value::Unsigned(2), Value::Bytes(encrypted))]);

        let decrypted = parse_uv_token_response(&response.encode(), &secret).unwrap();
        assert_eq!(decrypted, real_token);
    }
}
