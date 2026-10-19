//! Parsing `authenticatorGetInfo` responses.
//!
//! Member numbering is from CTAP2 §6.4 (`RESP_*` in this firmware's
//! `core/fido2/ctap.h`). Only `versions`, `extensions`, and `options` are
//! parsed — the fields a caller actually needs to report what the device
//! advertises (`aaguid`, `maxMsgSize`, `pinProtocols`, and everything from
//! `maxCredentialCountInList` on are left unparsed, same principle as
//! `cred_mgmt.rs`'s partial field sets).

use crate::cbor::{CborError, Value};
use thiserror::Error;

mod member {
    pub const VERSIONS: u64 = 1;
    pub const EXTENSIONS: u64 = 2;
    pub const OPTIONS: u64 = 4;
}

/// A `getInfo` response would not parse.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum GetInfoError {
    /// The body was not valid CBOR.
    #[error("response is not valid CBOR: {0}")]
    Cbor(#[from] CborError),
    /// A required member was absent.
    #[error("response is missing member {member}")]
    MissingMember {
        /// The CTAP member number.
        member: u64,
    },
    /// A member had the wrong CBOR type.
    #[error("response member {member} has the wrong type")]
    WrongType {
        /// The CTAP member number.
        member: u64,
    },
}

/// A parsed `authenticatorGetInfo` response: only the capability fields a
/// caller needs to report what the device actually advertises.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetInfoResponse {
    /// CTAP2/U2F version strings the device advertises (`versions`, member 1).
    pub versions: Vec<String>,
    /// Extension identifiers the device advertises (`extensions`, member 2).
    /// Empty when the device omits the member entirely.
    pub extensions: Vec<String>,
    /// `options` (member 4): capability name to its advertised boolean
    /// value, in the order the device sent them. A capability's *absence*
    /// here is meaningfully different from `false` per CTAP2 §6.4 — this
    /// preserves that distinction rather than defaulting missing
    /// capabilities to `false`.
    pub options: Vec<(String, bool)>,
}

impl GetInfoResponse {
    /// Parses an `authenticatorGetInfo` response body (the CBOR following
    /// the CTAP2 status byte).
    pub fn parse(body: &[u8]) -> Result<Self, GetInfoError> {
        let value = Value::decode(body)?;

        let versions =
            text_array(&value, member::VERSIONS)?.ok_or(GetInfoError::MissingMember {
                member: member::VERSIONS,
            })?;
        let extensions = text_array(&value, member::EXTENSIONS)?.unwrap_or_default();
        let options = bool_map(&value, member::OPTIONS)?;

        Ok(Self {
            versions,
            extensions,
            options,
        })
    }

    /// Looks up one `options` entry by name. `None` when the device did not
    /// advertise this capability at all (not the same as advertising it as
    /// `false`).
    pub fn option(&self, name: &str) -> Option<bool> {
        self.options
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| *v)
    }

    /// Whether the device currently has a PIN set. Per this firmware's own
    /// policy (`core/fido2/ctap.c`'s `ctap_get_info`), `clientPin` is
    /// omitted from `options` entirely when no PIN exists — never sent as
    /// `false` — so its absence here means exactly "no PIN set".
    pub fn client_pin_set(&self) -> bool {
        self.option("clientPin").unwrap_or(false)
    }
}

fn text_array(value: &Value, n: u64) -> Result<Option<Vec<String>>, GetInfoError> {
    match value.get(n) {
        None => Ok(None),
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .ok_or(GetInfoError::WrongType { member: n })
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Some),
        Some(_) => Err(GetInfoError::WrongType { member: n }),
    }
}

fn bool_map(value: &Value, n: u64) -> Result<Vec<(String, bool)>, GetInfoError> {
    match value.get(n) {
        None => Ok(Vec::new()),
        Some(Value::Map(entries)) => entries
            .iter()
            .map(|(k, v)| {
                let key = k
                    .as_str()
                    .ok_or(GetInfoError::WrongType { member: n })?
                    .to_owned();
                match v {
                    Value::Bool(b) => Ok((key, *b)),
                    _ => Err(GetInfoError::WrongType { member: n }),
                }
            })
            .collect(),
        Some(_) => Err(GetInfoError::WrongType { member: n }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shape of a real response from this firmware with no PIN set — see
    /// `core/fido2/ctap.c`'s `ctap_get_info` (`versions`: `FIDO_2_0`,
    /// `U2F_V2`; `extensions`: `credProtect`, `hmac-secret`; `options`:
    /// `rk`/`up`/`uv`/`plat`/`credMgmt`, `clientPin` omitted).
    fn firmware_response(pin_set: bool) -> Vec<u8> {
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
                Value::Unsigned(member::VERSIONS),
                Value::Array(vec![
                    Value::Text("FIDO_2_0".into()),
                    Value::Text("U2F_V2".into()),
                ]),
            ),
            (
                Value::Unsigned(member::EXTENSIONS),
                Value::Array(vec![
                    Value::Text("credProtect".into()),
                    Value::Text("hmac-secret".into()),
                ]),
            ),
            (Value::Unsigned(member::OPTIONS), Value::Map(options)),
        ])
        .encode()
    }

    #[test]
    fn parses_real_firmware_shape_without_a_pin_set() {
        let response = GetInfoResponse::parse(&firmware_response(false)).unwrap();
        assert_eq!(response.versions, vec!["FIDO_2_0", "U2F_V2"]);
        assert_eq!(response.extensions, vec!["credProtect", "hmac-secret"]);
        assert_eq!(response.option("rk"), Some(true));
        assert_eq!(response.option("up"), Some(true));
        assert_eq!(response.option("uv"), Some(true));
        assert_eq!(response.option("plat"), Some(false));
        assert_eq!(response.option("credMgmt"), Some(true));
        // Never advertised by this firmware; must not appear as any value.
        assert_eq!(response.option("bioEnroll"), None);
        assert_eq!(response.option("pinUvAuthToken"), None);
        // Omitted entirely rather than sent as `false`.
        assert_eq!(response.option("clientPin"), None);
        assert!(!response.client_pin_set());
    }

    #[test]
    fn client_pin_set_reflects_the_options_entry_when_present() {
        let response = GetInfoResponse::parse(&firmware_response(true)).unwrap();
        assert_eq!(response.option("clientPin"), Some(true));
        assert!(response.client_pin_set());
    }

    #[test]
    fn extensions_default_to_empty_when_the_member_is_absent() {
        let body = Value::Map(vec![(
            Value::Unsigned(member::VERSIONS),
            Value::Array(vec![Value::Text("FIDO_2_0".into())]),
        )])
        .encode();
        let response = GetInfoResponse::parse(&body).unwrap();
        assert!(response.extensions.is_empty());
        assert!(response.options.is_empty());
    }

    #[test]
    fn missing_versions_is_an_error() {
        let body = Value::Map(vec![]).encode();
        assert_eq!(
            GetInfoResponse::parse(&body),
            Err(GetInfoError::MissingMember {
                member: member::VERSIONS
            })
        );
    }

    #[test]
    fn wrong_type_for_versions_is_an_error() {
        let body =
            Value::Map(vec![(Value::Unsigned(member::VERSIONS), Value::Bool(true))]).encode();
        assert_eq!(
            GetInfoResponse::parse(&body),
            Err(GetInfoError::WrongType {
                member: member::VERSIONS
            })
        );
    }

    #[test]
    fn garbage_is_an_error_not_a_panic() {
        for body in [&b""[..], &[0xff; 16]] {
            assert!(GetInfoResponse::parse(body).is_err());
        }
    }
}
