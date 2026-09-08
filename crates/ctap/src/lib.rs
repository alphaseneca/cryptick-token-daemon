//! CTAP2 command and status codes, and the framing around CBOR bodies.
//!
//! # Scope, and what is deliberately absent
//!
//! This crate does **not** parse CBOR. That is not an omission to fill in later;
//! it is the design. The daemon is a relay: it does not build client data, make
//! origin decisions, or implement the PIN/UV protocols — those belong to the
//! browser on one side and the authenticator on the other (PROJECT.md §13, §21).
//! A relay that parses payloads it has no business interpreting only adds attack
//! surface and a second place for the spec to be misread.
//!
//! So a request here is *a command byte plus opaque bytes*, and a response is *a
//! status byte plus opaque bytes*. That is everything the daemon needs to know.
//!
//! # Transparency
//!
//! [`Command`] and [`StatusCode`] are newtypes over `u8`, not enums, so an
//! unrecognised value round-trips unchanged. This matters more than it looks: a
//! relay that cannot represent a code it does not know would have to invent a
//! substitute, and the host would then act on a status the authenticator never
//! sent. Named constants exist for the values the daemon actually branches on;
//! everything else passes through untouched.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use thiserror::Error;

/// A CTAP2 command, the first byte of a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Command(pub u8);

impl Command {
    /// `authenticatorMakeCredential`
    pub const MAKE_CREDENTIAL: Command = Command(0x01);
    /// `authenticatorGetAssertion`
    pub const GET_ASSERTION: Command = Command(0x02);
    /// `authenticatorGetInfo` — takes no parameters.
    pub const GET_INFO: Command = Command(0x04);
    /// `authenticatorClientPIN`
    pub const CLIENT_PIN: Command = Command(0x06);
    /// `authenticatorReset` — destructive, and takes no parameters.
    pub const RESET: Command = Command(0x07);
    /// `authenticatorGetNextAssertion` — takes no parameters.
    pub const GET_NEXT_ASSERTION: Command = Command(0x08);
    /// `authenticatorBioEnrollment`
    pub const BIO_ENROLLMENT: Command = Command(0x09);
    /// `authenticatorCredentialManagement`
    pub const CREDENTIAL_MANAGEMENT: Command = Command(0x0a);
    /// `authenticatorSelection` — takes no parameters.
    pub const SELECTION: Command = Command(0x0b);
    /// `authenticatorLargeBlobs`
    pub const LARGE_BLOBS: Command = Command(0x0c);
    /// `authenticatorConfig`
    pub const CONFIG: Command = Command(0x0d);

    /// The command byte.
    pub const fn as_u8(self) -> u8 {
        self.0
    }

    /// A name for logging, if this is a command we recognise.
    ///
    /// Never used for control flow — see the transparency note on the crate.
    pub const fn name(self) -> Option<&'static str> {
        Some(match self {
            Command::MAKE_CREDENTIAL => "authenticatorMakeCredential",
            Command::GET_ASSERTION => "authenticatorGetAssertion",
            Command::GET_INFO => "authenticatorGetInfo",
            Command::CLIENT_PIN => "authenticatorClientPIN",
            Command::RESET => "authenticatorReset",
            Command::GET_NEXT_ASSERTION => "authenticatorGetNextAssertion",
            Command::BIO_ENROLLMENT => "authenticatorBioEnrollment",
            Command::CREDENTIAL_MANAGEMENT => "authenticatorCredentialManagement",
            Command::SELECTION => "authenticatorSelection",
            Command::LARGE_BLOBS => "authenticatorLargeBlobs",
            Command::CONFIG => "authenticatorConfig",
            _ => return None,
        })
    }

    /// Whether this command is expected to carry no CBOR parameters.
    ///
    /// Advisory only: a request that disagrees is still relayed unchanged, since
    /// deciding it is malformed is the authenticator's job, not ours.
    pub const fn takes_no_parameters(self) -> bool {
        matches!(
            self,
            Command::GET_INFO | Command::RESET | Command::GET_NEXT_ASSERTION | Command::SELECTION
        )
    }
}

/// A CTAP2 status, the first byte of a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StatusCode(pub u8);

impl StatusCode {
    /// Success.
    pub const OK: StatusCode = StatusCode(0x00);
    /// `CTAP1_ERR_INVALID_COMMAND`
    pub const INVALID_COMMAND: StatusCode = StatusCode(0x01);
    /// `CTAP1_ERR_INVALID_PARAMETER`
    pub const INVALID_PARAMETER: StatusCode = StatusCode(0x02);
    /// `CTAP1_ERR_INVALID_LENGTH`
    pub const INVALID_LENGTH: StatusCode = StatusCode(0x03);
    /// `CTAP2_ERR_OPERATION_DENIED`
    pub const OPERATION_DENIED: StatusCode = StatusCode(0x27);
    /// `CTAP2_ERR_KEEPALIVE_CANCEL` — the transaction was cancelled.
    pub const KEEPALIVE_CANCEL: StatusCode = StatusCode(0x2e);
    /// `CTAP2_ERR_USER_ACTION_TIMEOUT` — the user never touched the sensor.
    pub const USER_ACTION_TIMEOUT: StatusCode = StatusCode(0x30);
    /// `CTAP2_ERR_UP_REQUIRED` — user presence is required and was not given.
    pub const UP_REQUIRED: StatusCode = StatusCode(0x3c);
    /// `CTAP1_ERR_OTHER`
    pub const OTHER: StatusCode = StatusCode(0x7f);

    /// The status byte.
    pub const fn as_u8(self) -> u8 {
        self.0
    }

    /// Whether the operation succeeded.
    pub const fn is_ok(self) -> bool {
        self.0 == 0
    }

    /// A name for logging, if this is a status we recognise.
    pub const fn name(self) -> Option<&'static str> {
        Some(match self {
            StatusCode::OK => "CTAP2_OK",
            StatusCode::INVALID_COMMAND => "CTAP1_ERR_INVALID_COMMAND",
            StatusCode::INVALID_PARAMETER => "CTAP1_ERR_INVALID_PARAMETER",
            StatusCode::INVALID_LENGTH => "CTAP1_ERR_INVALID_LENGTH",
            StatusCode::OPERATION_DENIED => "CTAP2_ERR_OPERATION_DENIED",
            StatusCode::KEEPALIVE_CANCEL => "CTAP2_ERR_KEEPALIVE_CANCEL",
            StatusCode::USER_ACTION_TIMEOUT => "CTAP2_ERR_USER_ACTION_TIMEOUT",
            StatusCode::UP_REQUIRED => "CTAP2_ERR_UP_REQUIRED",
            StatusCode::OTHER => "CTAP1_ERR_OTHER",
            _ => return None,
        })
    }
}

/// A malformed CTAP message.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CtapError {
    /// A request with no command byte.
    #[error("CTAP request is empty; it must carry at least a command byte")]
    EmptyRequest,
    /// A response with no status byte.
    #[error("CTAP response is empty; it must carry at least a status byte")]
    EmptyResponse,
}

/// A CTAP request: one command and its opaque CBOR parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The command.
    pub command: Command,
    /// CBOR parameters, empty for commands that take none. Never interpreted.
    pub params: Vec<u8>,
}

impl Request {
    /// Builds a request.
    pub fn new(command: Command, params: Vec<u8>) -> Self {
        Self { command, params }
    }

    /// Parses the body of a CTAP `MSG`: a command byte followed by parameters.
    pub fn decode(bytes: &[u8]) -> Result<Self, CtapError> {
        let (&command, params) = bytes.split_first().ok_or(CtapError::EmptyRequest)?;
        Ok(Self {
            command: Command(command),
            params: params.to_vec(),
        })
    }

    /// Serialises back to the wire form.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.params.len());
        out.push(self.command.as_u8());
        out.extend_from_slice(&self.params);
        out
    }
}

/// A CTAP response: one status and its opaque CBOR body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// The status.
    pub status: StatusCode,
    /// CBOR response data, empty on errors and on commands that return none.
    pub data: Vec<u8>,
}

impl Response {
    /// Builds a response.
    pub fn new(status: StatusCode, data: Vec<u8>) -> Self {
        Self { status, data }
    }

    /// An error response with no body.
    pub fn error(status: StatusCode) -> Self {
        Self {
            status,
            data: Vec::new(),
        }
    }

    /// Parses a status byte followed by response data.
    pub fn decode(bytes: &[u8]) -> Result<Self, CtapError> {
        let (&status, data) = bytes.split_first().ok_or(CtapError::EmptyResponse)?;
        Ok(Self {
            status: StatusCode(status),
            data: data.to_vec(),
        })
    }

    /// Serialises back to the wire form.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.data.len());
        out.push(self.status.as_u8());
        out.extend_from_slice(&self.data);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_info_request_is_a_bare_command_byte() {
        let req = Request::new(Command::GET_INFO, Vec::new());
        assert_eq!(req.encode(), vec![0x04]);
        assert_eq!(Request::decode(&[0x04]), Ok(req));
    }

    #[test]
    fn request_round_trips_with_opaque_params() {
        let req = Request::new(Command::MAKE_CREDENTIAL, vec![0xa1, 0x01, 0x02]);
        assert_eq!(Request::decode(&req.encode()), Ok(req));
    }

    #[test]
    fn response_round_trips() {
        let resp = Response::new(StatusCode::OK, vec![0xa1, 0x01, 0x18, 0x20]);
        assert_eq!(Response::decode(&resp.encode()), Ok(resp));
    }

    #[test]
    fn empty_messages_are_rejected() {
        assert_eq!(Request::decode(&[]), Err(CtapError::EmptyRequest));
        assert_eq!(Response::decode(&[]), Err(CtapError::EmptyResponse));
    }

    #[test]
    fn unknown_codes_survive_a_round_trip() {
        // A relay must never remap a code it does not recognise: the host would
        // otherwise act on a status the authenticator never sent.
        let resp = Response::decode(&[0xdd, 0x01]).unwrap();
        assert_eq!(resp.status, StatusCode(0xdd));
        assert_eq!(resp.status.name(), None);
        assert_eq!(resp.encode(), vec![0xdd, 0x01]);

        let req = Request::decode(&[0xee]).unwrap();
        assert_eq!(req.command, Command(0xee));
        assert_eq!(req.command.name(), None);
        assert_eq!(req.encode(), vec![0xee]);
    }

    #[test]
    fn only_zero_is_success() {
        assert!(StatusCode::OK.is_ok());
        for byte in [0x01u8, 0x27, 0x2e, 0x30, 0x3c, 0x7f, 0xff] {
            assert!(!StatusCode(byte).is_ok(), "{byte:#04x}");
        }
    }

    #[test]
    fn parameterless_commands_are_flagged() {
        assert!(Command::GET_INFO.takes_no_parameters());
        assert!(Command::RESET.takes_no_parameters());
        assert!(Command::SELECTION.takes_no_parameters());
        assert!(!Command::MAKE_CREDENTIAL.takes_no_parameters());
        assert!(!Command(0xee).takes_no_parameters());
    }
}
