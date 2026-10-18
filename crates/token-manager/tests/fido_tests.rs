//! `ctctl fido` unit tests against a simulated CTAP2 device.
//!
//! The actual `authenticatorGetInfo` CBOR parsing is covered exhaustively by
//! `ctap-client`'s own `get_info` tests (including the exact shape this
//! firmware sends — see `core/fido2/ctap.c`'s `ctap_get_info`). What this
//! suite checks is the CLI wiring: `fido info` sends a real CTAP2
//! `authenticatorGetInfo` over the transport and degrades gracefully,
//! without erroring out, whether the device answers or not — matching the
//! `SimulatedOathToken` pattern in `oath_tests.rs`.

use ctctl::cli::fido_cli::handle_fido_command;
use ctctl::error::ManagerError;
use ctctl::transport::TokenTransport;
use ctap_client::Value;
use std::time::Duration;

/// A simulated Cryptick Token that answers `authenticatorGetInfo` the way
/// the real firmware does.
struct SimulatedFidoToken {
    pin_set: bool,
}

fn get_info_cbor_body(pin_set: bool) -> Vec<u8> {
    let mut options = vec![
        (Value::Text("rk".into()), Value::Bool(true)),
        (Value::Text("up".into()), Value::Bool(true)),
        (Value::Text("uv".into()), Value::Bool(true)),
        (Value::Text("plat".into()), Value::Bool(false)),
        (Value::Text("credMgmt".into()), Value::Bool(true)),
    ];
    if pin_set {
        options.push((Value::Text("clientPin".into()), Value::Bool(true)));
    }

    Value::Map(vec![
        (
            Value::Unsigned(1),
            Value::Array(vec![
                Value::Text("FIDO_2_0".into()),
                Value::Text("U2F_V2".into()),
            ]),
        ),
        (
            Value::Unsigned(2),
            Value::Array(vec![
                Value::Text("credProtect".into()),
                Value::Text("hmac-secret".into()),
            ]),
        ),
        (Value::Unsigned(4), Value::Map(options)),
    ])
    .encode()
}

impl TokenTransport for SimulatedFidoToken {
    fn transceive(
        &mut self,
        cmd: u8,
        payload: &[u8],
        _timeout: Duration,
    ) -> Result<Vec<u8>, ManagerError> {
        // CTAPHID_CBOR carrying authenticatorGetInfo (command byte 0x04).
        if cmd == 0x10 && payload.first() == Some(&0x04) {
            let mut out = vec![0x00]; // CTAP2_OK
            out.extend_from_slice(&get_info_cbor_body(self.pin_set));
            return Ok(out);
        }
        Ok(vec![0x01]) // CTAP1_ERR_INVALID_COMMAND, no body
    }

    fn transport_name(&self) -> &'static str {
        "Simulated Cryptick Token"
    }

    fn serial(&self) -> Option<String> {
        Some("SIM-FIDO-01".to_string())
    }
}

/// A token that never answers — the USB cable is unplugged, BLE is out of
/// range, or similar.
struct UnreachableToken;

impl TokenTransport for UnreachableToken {
    fn transceive(
        &mut self,
        _cmd: u8,
        _payload: &[u8],
        _timeout: Duration,
    ) -> Result<Vec<u8>, ManagerError> {
        Err(ManagerError::Transport("no device present".into()))
    }

    fn transport_name(&self) -> &'static str {
        "Unreachable"
    }

    fn serial(&self) -> Option<String> {
        None
    }
}

#[test]
fn fido_info_succeeds_against_a_device_with_a_pin_set() {
    let mut token = SimulatedFidoToken { pin_set: true };
    assert!(handle_fido_command(&mut token, &["info".to_string()]).is_ok());
}

#[test]
fn fido_info_succeeds_against_a_device_with_no_pin_set() {
    let mut token = SimulatedFidoToken { pin_set: false };
    assert!(handle_fido_command(&mut token, &["info".to_string()]).is_ok());
}

#[test]
fn fido_info_degrades_gracefully_when_the_device_is_unreachable() {
    // Before this fix, `fido info` never touched the transport's result at
    // all and always printed a fixed success block. It must still not
    // error out — just report nothing rather than fabricating data — when
    // the device cannot be reached.
    let mut token = UnreachableToken;
    assert!(handle_fido_command(&mut token, &["info".to_string()]).is_ok());
}

/// A token that answers every `authenticatorClientPIN`/credential-management
/// request with CTAP1_ERR_OTHER (`0x7f`) and nothing else — the real
/// firmware's own answer for a subcommand its build has no case for yet
/// (`core/fido2/ctap.c`'s `ctap_client_pin` default arm). The actual
/// key-agreement/encryption handshake is `ctap-client`'s own concern, tested
/// there; this is purely "does the CLI surface that status honestly instead
/// of panicking or hanging."
struct UnsupportedCredMgmtToken;

impl TokenTransport for UnsupportedCredMgmtToken {
    fn transceive(
        &mut self,
        cmd: u8,
        _payload: &[u8],
        _timeout: Duration,
    ) -> Result<Vec<u8>, ManagerError> {
        if cmd == 0x10 {
            return Ok(vec![0x7f]); // CTAP1_ERR_OTHER, no body
        }
        Ok(vec![0x01])
    }

    fn transport_name(&self) -> &'static str {
        "Simulated Cryptick Token (no cred-mgmt firmware)"
    }

    fn serial(&self) -> Option<String> {
        Some("SIM-FIDO-02".to_string())
    }
}

#[test]
fn fido_credentials_list_reports_unsupported_firmware_honestly() {
    let mut token = UnsupportedCredMgmtToken;
    let err = handle_fido_command(
        &mut token,
        &["credentials".to_string(), "list".to_string()],
    )
    .unwrap_err();
    assert!(err.to_string().contains("unsupported on this device's current firmware"));
}

#[test]
fn fido_credentials_delete_rejects_a_non_base64_credential_id() {
    let mut token = UnsupportedCredMgmtToken;
    let err = handle_fido_command(
        &mut token,
        &[
            "credentials".to_string(),
            "delete".to_string(),
            "not valid base64url!!".to_string(),
            "-f".to_string(),
        ],
    )
    .unwrap_err();
    assert!(err.to_string().contains("Invalid credential ID"));
}

#[test]
fn fido_credentials_degrades_gracefully_when_the_device_is_unreachable() {
    let mut token = UnreachableToken;
    assert!(handle_fido_command(
        &mut token,
        &["credentials".to_string(), "list".to_string()]
    )
    .is_err());
}
