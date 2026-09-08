//! What can go wrong in a transaction, and how it reaches a client.

use crate::transport::TransportError;
use ble_framing::{BleErrorCode, FramingError};
use ipc::ErrorCode;
use thiserror::Error;

/// A transaction failed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DaemonError {
    /// No device is reachable.
    #[error("no device is connected")]
    NotConnected,

    /// A device is reachable but the link is not bonded with MITM protection.
    ///
    /// There is deliberately no override for this anywhere in the codebase
    /// (PROJECT.md §15.2).
    #[error("the link is not bonded with MITM protection")]
    NotBonded,

    /// Another transaction is already in flight (PROJECT.md §13).
    #[error("another CTAP transaction is already in flight")]
    Busy,

    /// The transaction exceeded the client's timeout.
    #[error("the transaction timed out")]
    Timeout,

    /// The client cancelled.
    #[error("the transaction was cancelled")]
    Cancelled,

    /// The device answered with a transport-level `ERROR`.
    #[error("device reported a transport error: {0:?}")]
    DeviceError(BleErrorCode),

    /// The device sent something that does not decode.
    #[error("device sent a malformed fragment: {0}")]
    Framing(#[from] FramingError),

    /// The device sent a well-framed message that is not valid CTAP.
    #[error("device sent a malformed CTAP message: {0}")]
    Ctap(#[from] ctap::CtapError),

    /// The device answered a request with the wrong kind of message.
    #[error("expected a {expected} response, got {got}")]
    UnexpectedResponse {
        /// What the request called for.
        expected: &'static str,
        /// What arrived.
        got: &'static str,
    },

    /// The transport failed.
    #[error("transport failure: {0}")]
    Transport(#[from] TransportError),
}

impl DaemonError {
    /// The stable code a client sees on the IPC boundary.
    ///
    /// Deliberately coarse. Detail about *why* a device is misbehaving belongs
    /// in local logs, not in a message handed to whatever process opened the
    /// socket (PROJECT.md §15.5).
    pub const fn ipc_code(&self) -> ErrorCode {
        match self {
            DaemonError::NotConnected => ErrorCode::NotConnected,
            DaemonError::NotBonded => ErrorCode::NotBonded,
            DaemonError::Busy => ErrorCode::Busy,
            DaemonError::Timeout => ErrorCode::Timeout,
            DaemonError::Cancelled => ErrorCode::Cancelled,
            DaemonError::DeviceError(_)
            | DaemonError::Framing(_)
            | DaemonError::Ctap(_)
            | DaemonError::UnexpectedResponse { .. } => ErrorCode::ProtocolError,
            DaemonError::Transport(_) => ErrorCode::NotConnected,
        }
    }
}
