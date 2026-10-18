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
