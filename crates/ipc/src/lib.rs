//! Wire types for the local IPC between the daemon and its clients.
//!
//! Length-prefixed JSON over a Unix domain socket (macOS, Linux) or a named pipe
//! (Windows). Never a loopback TCP port: on Windows any local process can
//! connect to a listening localhost port (PROJECT.md §5, §13, §15.6).
//!
//! Every message carries `v`, `id` and `type`. Binary rides as base64url, and
//! only here — internally it stays `Vec<u8>` (PROJECT.md §20).
//!
//! # Versioning
//!
//! [`PROTOCOL_VERSION`] is checked *before* the body is parsed, so a client
//! speaking an older protocol gets [`IpcError::UnsupportedVersion`] rather than a
//! confusing field-level failure. PROJECT.md §14 makes this a release gate: bump
//! the version whenever a message shape changes, and old clients must get a clean
//! error, never a misparse.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod codec;
pub mod platform;

pub use codec::{FrameDecoder, MAX_FRAME_LEN};
pub use platform::{IpcEndpoint, WINDOWS_NAMED_PIPE};

/// `sun_path` is 104 bytes on macOS and 108 on Linux, terminator included.
/// Application Support paths get long, so this is a real limit and not a
/// theoretical one; exceeding it otherwise surfaces as an opaque `EINVAL`.
pub const MAX_SOCKET_PATH: usize = 100;

/// Derives the socket path given explicit environment parameters and OS indicator.
///
/// Ensures `target_os = "macos"` takes precedence over `XDG_RUNTIME_DIR`.
pub fn socket_path_from_env(
    target_os_macos: bool,
    xdg_runtime_dir: Option<&std::ffi::OsStr>,
    home: Option<&std::ffi::OsStr>,
) -> Option<std::path::PathBuf> {
    use std::path::PathBuf;
    if target_os_macos {
        let home = PathBuf::from(home?);
        Some(
            home.join("Library")
                .join("Application Support")
                .join("cryptick")
                .join("daemon.sock"),
        )
    } else if let Some(dir) = xdg_runtime_dir {
        Some(PathBuf::from(dir).join("cryptick").join("daemon.sock"))
    } else {
        let home = PathBuf::from(home?);
        Some(home.join(".cryptick").join("daemon.sock"))
    }
}

/// Where the daemon's socket lives by default.
///
/// Lives here rather than in the daemon because every client needs it, and
/// `sk-middleware` must not depend on the daemon crate — that would pull an
/// async runtime into `ssh-sk-helper` (PROJECT.md §10).
///
/// On macOS, `~/Library/Application Support/cryptick/daemon.sock` is always preferred.
/// On other Unix platforms, `$XDG_RUNTIME_DIR` is preferred when set, falling back to
/// `~/.cryptick/daemon.sock`. On Windows, the named pipe `\\.\pipe\cryptick-daemon` is returned.
#[cfg(unix)]
pub fn default_socket_path() -> Option<std::path::PathBuf> {
    socket_path_from_env(
        cfg!(target_os = "macos"),
        std::env::var_os("XDG_RUNTIME_DIR").as_deref(),
        std::env::var_os("HOME").as_deref(),
    )
}

/// Where the daemon's socket / named pipe lives by default on Windows.
#[cfg(windows)]
pub fn default_socket_path() -> Option<std::path::PathBuf> {
    Some(std::path::PathBuf::from(WINDOWS_NAMED_PIPE))
}

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The IPC protocol version. Bump on any message shape change.
pub const PROTOCOL_VERSION: u32 = 1;

/// Something went wrong encoding, decoding or validating an IPC message.
#[derive(Debug, Error)]
pub enum IpcError {
    /// The peer speaks a protocol version we do not.
    #[error("unsupported IPC protocol version {got}; this daemon speaks {expected}")]
    UnsupportedVersion {
        /// The version the peer sent.
        got: u32,
        /// The version we speak.
        expected: u32,
    },

    /// A frame longer than [`MAX_FRAME_LEN`].
    #[error("frame of {len} bytes exceeds the maximum of {max}")]
    FrameTooLong {
        /// The declared frame length.
        len: usize,
        /// The maximum accepted.
        max: usize,
    },

    /// The frame was not valid JSON, or not a message shape we know.
    #[error("malformed IPC message: {0}")]
    Malformed(#[from] serde_json::Error),

    /// A base64url field that would not decode.
    #[error("invalid base64url in field: {0}")]
    InvalidBase64(#[from] base64::DecodeError),
}

/// Base64url with no padding, as used for every binary field on this boundary.
mod b64 {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        URL_SAFE_NO_PAD.encode(bytes).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        URL_SAFE_NO_PAD
            .decode(text.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

/// The `v` / `id` header carried by every message, wrapping a typed body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope<T> {
    /// Protocol version.
    pub v: u32,
    /// Correlation id. A response carries the id of the request it answers.
    pub id: String,
    /// The message body, tagged by `type`.
    #[serde(flatten)]
    pub body: T,
}

impl<T> Envelope<T> {
    /// Wraps a body at the current protocol version.
    pub fn new(id: impl Into<String>, body: T) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            id: id.into(),
            body,
        }
    }
}

/// A message from a client to the daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ClientMessage {
    /// Relay a CTAP request to the device.
    #[serde(rename = "ctap.request")]
    CtapRequest {
        /// The CTAP message: a command byte followed by CBOR. Opaque to the
        /// daemon, which never interprets it.
        #[serde(with = "b64")]
        cbor: Vec<u8>,
        /// How long the client will wait, in milliseconds.
        #[serde(rename = "timeoutMs")]
        timeout_ms: u64,
    },

    /// Abandon the transaction in flight.
    #[serde(rename = "ctap.cancel")]
    CtapCancel,

    /// Ask for the device's current status.
    #[serde(rename = "device.status")]
    DeviceStatus,
}

/// A message from the daemon to a client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum DaemonMessage {
    /// The device answered.
    #[serde(rename = "ctap.response")]
    CtapResponse {
        /// The CTAP status byte, relayed verbatim.
        status: u8,
        /// The CBOR response body, relayed verbatim.
        #[serde(with = "b64")]
        cbor: Vec<u8>,
    },

    /// The device is still working.
    ///
    /// `reason: "up"` means it wants a physical touch. Forward it; never swallow
    /// it, and never satisfy it on the device's behalf (PROJECT.md §15.3).
    #[serde(rename = "ctap.keepalive")]
    CtapKeepalive {
        /// `"processing"` or `"up"`.
        reason: KeepaliveReason,
    },

    /// The device came into or left range.
    #[serde(rename = "device.range")]
    DeviceRange {
        /// Whether the device is currently reachable.
        #[serde(rename = "inRange")]
        in_range: bool,
        /// Whether the link is bonded. Proximity without a bond is not usable
        /// (PROJECT.md §15.2).
        bonded: bool,
    },

    /// The request failed.
    #[serde(rename = "error")]
    Error {
        /// A stable machine-readable code.
        code: ErrorCode,
        /// A human-readable description. Never contains key material, PINs, or
        /// payload contents (PROJECT.md §15.5).
        message: String,
    },
}

/// Why the device sent a keepalive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeepaliveReason {
    /// Busy.
    Processing,
    /// Waiting for a physical touch.
    Up,
}

/// A stable error code on the IPC boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    /// No device is currently reachable.
    NotConnected,
    /// A device is reachable but the link is not bonded with MITM protection.
    /// There is deliberately no override for this (PROJECT.md §15.2).
    NotBonded,
    /// Another transaction is already in flight (PROJECT.md §13).
    Busy,
    /// The transaction exceeded its timeout.
    Timeout,
    /// The transaction was cancelled.
    Cancelled,
    /// The device sent something that does not parse.
    ProtocolError,
    /// The client sent something that does not parse.
    BadRequest,
    /// The client speaks a protocol version we do not.
    UnsupportedVersion,
    /// Anything else. Deliberately vague on the wire.
    Internal,
}

/// Checks the `v` field before parsing the body.
///
/// Split out so a version mismatch is reported as itself rather than surfacing
/// as whatever field happened to change shape.
fn check_version(json: &[u8]) -> Result<(), IpcError> {
    #[derive(Deserialize)]
    struct VersionProbe {
        v: u32,
    }
    let probe: VersionProbe = serde_json::from_slice(json)?;
    if probe.v != PROTOCOL_VERSION {
        return Err(IpcError::UnsupportedVersion {
            got: probe.v,
            expected: PROTOCOL_VERSION,
        });
    }
    Ok(())
}

/// Serialises a message to a length-prefixed frame.
pub fn encode<T: Serialize>(message: &Envelope<T>) -> Result<Vec<u8>, IpcError> {
    let json = serde_json::to_vec(message)?;
    codec::frame(&json)
}

/// Parses a client message from a frame body, checking the version first.
pub fn decode_client(json: &[u8]) -> Result<Envelope<ClientMessage>, IpcError> {
    check_version(json)?;
    Ok(serde_json::from_slice(json)?)
}

/// Parses a daemon message from a frame body, checking the version first.
pub fn decode_daemon(json: &[u8]) -> Result<Envelope<DaemonMessage>, IpcError> {
    check_version(json)?;
    Ok(serde_json::from_slice(json)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip_client(body: ClientMessage) {
        let env = Envelope::new("abc123", body);
        let frame = encode(&env).unwrap();
        let mut dec = FrameDecoder::new();
        dec.push(&frame);
        let json = dec.next_frame().unwrap().unwrap();
        assert_eq!(decode_client(&json).unwrap(), env);
    }

    #[test]
    fn client_messages_round_trip() {
        round_trip_client(ClientMessage::CtapRequest {
            cbor: vec![0x04],
            timeout_ms: 60_000,
        });
        round_trip_client(ClientMessage::CtapCancel);
        round_trip_client(ClientMessage::DeviceStatus);
    }

    #[test]
    fn daemon_messages_round_trip() {
        for body in [
            DaemonMessage::CtapResponse {
                status: 0,
                cbor: vec![0xa1, 0x01],
            },
            DaemonMessage::CtapKeepalive {
                reason: KeepaliveReason::Up,
            },
            DaemonMessage::DeviceRange {
                in_range: true,
                bonded: true,
            },
            DaemonMessage::Error {
                code: ErrorCode::NotBonded,
                message: "link is not bonded".into(),
            },
        ] {
            let env = Envelope::new("x", body);
            let frame = encode(&env).unwrap();
            let mut dec = FrameDecoder::new();
            dec.push(&frame);
            let json = dec.next_frame().unwrap().unwrap();
            assert_eq!(decode_daemon(&json).unwrap(), env);
        }
    }

    #[test]
    fn wire_shape_matches_the_documented_protocol() {
        // PROJECT.md §13 shows these exact shapes; clients in other languages
        // will be written against them.
        let env = Envelope::new(
            "7f3",
            ClientMessage::CtapRequest {
                cbor: vec![0x04],
                timeout_ms: 60_000,
            },
        );
        let json: serde_json::Value =
            serde_json::from_slice(&serde_json::to_vec(&env).unwrap()).unwrap();
        assert_eq!(json["v"], 1);
        assert_eq!(json["id"], "7f3");
        assert_eq!(json["type"], "ctap.request");
        assert_eq!(json["cbor"], "BA");
        assert_eq!(json["timeoutMs"], 60_000);
    }

    #[test]
    fn keepalive_reason_serialises_as_documented() {
        let env = Envelope::new(
            "1",
            DaemonMessage::CtapKeepalive {
                reason: KeepaliveReason::Up,
            },
        );
        let text = serde_json::to_string(&env).unwrap();
        assert!(text.contains(r#""reason":"up""#), "{text}");
    }

    #[test]
    fn a_future_version_is_reported_as_a_version_error() {
        let json = br#"{"v":2,"id":"x","type":"ctap.cancel"}"#;
        match decode_client(json) {
            Err(IpcError::UnsupportedVersion {
                got: 2,
                expected: 1,
            }) => {}
            other => panic!("expected a version error, got {other:?}"),
        }
    }

    #[test]
    fn a_version_error_wins_over_a_body_that_would_also_fail() {
        // The point of checking the version first: an old client whose fields
        // changed shape must be told the version is wrong, not that some field
        // is missing.
        let json = br#"{"v":99,"id":"x","type":"ctap.request","cborData":"AAAA"}"#;
        assert!(matches!(
            decode_client(json),
            Err(IpcError::UnsupportedVersion { got: 99, .. })
        ));
    }

    #[test]
    fn unknown_message_types_are_rejected() {
        let json = br#"{"v":1,"id":"x","type":"ctap.somethingElse"}"#;
        assert!(matches!(decode_client(json), Err(IpcError::Malformed(_))));
    }

    #[test]
    fn bad_base64_is_rejected() {
        let json = br#"{"v":1,"id":"x","type":"ctap.request","cbor":"!!!!","timeoutMs":1}"#;
        assert!(decode_client(json).is_err());
    }

    #[test]
    fn binary_survives_the_base64url_boundary() {
        // All 256 byte values, including the ones that would break base64 that
        // is not URL-safe.
        let cbor: Vec<u8> = (0u8..=255).collect();
        let env = Envelope::new(
            "bin",
            ClientMessage::CtapRequest {
                cbor: cbor.clone(),
                timeout_ms: 1,
            },
        );
        let frame = encode(&env).unwrap();
        let mut dec = FrameDecoder::new();
        dec.push(&frame);
        let json = dec.next_frame().unwrap().unwrap();
        match decode_client(&json).unwrap().body {
            ClientMessage::CtapRequest { cbor: got, .. } => assert_eq!(got, cbor),
            other => panic!("wrong body: {other:?}"),
        }
    }

    #[test]
    fn socket_path_precedence_rules() {
        use std::ffi::OsStr;
        use std::path::PathBuf;

        // macOS precedence: macOS MUST ignore XDG_RUNTIME_DIR even when set
        let macos_path = socket_path_from_env(
            true,
            Some(OsStr::new("/tmp/xdg_runtime")),
            Some(OsStr::new("/Users/alice")),
        );
        assert_eq!(
            macos_path,
            Some(PathBuf::from(
                "/Users/alice/Library/Application Support/cryptick/daemon.sock"
            ))
        );

        // Linux with XDG_RUNTIME_DIR
        let linux_xdg = socket_path_from_env(
            false,
            Some(OsStr::new("/run/user/1000")),
            Some(OsStr::new("/home/bob")),
        );
        assert_eq!(
            linux_xdg,
            Some(PathBuf::from("/run/user/1000/cryptick/daemon.sock"))
        );

        // Linux without XDG_RUNTIME_DIR
        let linux_fallback = socket_path_from_env(false, None, Some(OsStr::new("/home/bob")));
        assert_eq!(
            linux_fallback,
            Some(PathBuf::from("/home/bob/.cryptick/daemon.sock"))
        );

        // Missing home and xdg
        assert_eq!(socket_path_from_env(false, None, None), None);
        assert_eq!(socket_path_from_env(true, None, None), None);
    }
}
