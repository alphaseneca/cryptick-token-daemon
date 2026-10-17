//! Typed error type for `cryptick-manager`.
//!
//! PROJECT.md §20: "Typed errors with `thiserror`; no stringly-typed
//! failures across crate lines." Every public function in this crate used
//! to return `Result<_, String>` — 126 occurrences across every module, the
//! one place in the workspace that declared `thiserror.workspace = true`
//! (`Cargo.toml`) and never used it. This module gives them all a single
//! real error type instead, so a caller outside this crate (or a test
//! inside it) can match on a variant — a bad status word, an I/O failure,
//! a missing account — instead of pattern-matching message text.
//!
//! Most of the ~130 error construction sites this crate accumulated before
//! this pass were ad hoc validation messages (a bad CLI argument, a
//! malformed hex string, an otpauth URI with a missing field) that don't
//! carry any structure worth a dedicated variant — [`ManagerError::InvalidInput`]
//! and [`ManagerError::Other`] cover those, preserving the exact wording a
//! caller already saw. The variants that *do* carry structure
//! ([`ManagerError::DeviceStatus`], [`ManagerError::Io`],
//! [`ManagerError::Json`]) are the ones worth matching on.
//!
//! [`From<String>`] and [`From<&str>`] are implemented deliberately, so the
//! large number of pre-existing `.map_err(|e| format!(...))?`,
//! `.ok_or_else(|| "...".to_string())?`, and `.ok_or("...")?` call sites
//! keep compiling unchanged: `?` already calls `From::from` on its error
//! operand, so those sites needed no edits at all, only their function
//! signatures did. A bare `Err("...".to_string())` or `Err(format!(...))`
//! (not routed through `?`) does need the conversion spelled out, since
//! `Err`'s payload type must already match exactly.

use crate::apdu::StatusWord;
use thiserror::Error;

/// The error type returned by every fallible operation in `cryptick_manager`.
#[derive(Debug, Error)]
pub enum ManagerError {
    /// A caller-supplied value failed validation or parsing: a CLI
    /// argument, a hex string, an `otpauth://` URI, a Base32 secret, raw
    /// APDU bytes, or similar.
    #[error("{0}")]
    InvalidInput(String),

    /// The requested account, device, slot, applet, or remembered key does
    /// not exist.
    #[error("{0}")]
    NotFound(String),

    /// The on-device applet answered with a non-success ISO 7816 status
    /// word.
    #[error("device returned error {0}")]
    DeviceStatus(StatusWord),

    /// A USB, BLE daemon IPC, or CTAPHID transport-level failure: a
    /// connection could not be made, a read/write failed, a timeout
    /// elapsed, or the peer sent something the transport didn't expect.
    #[error("{0}")]
    Transport(String),

    /// Local host-side configuration (remembered OATH access keys, device
    /// config) could not be determined, read, or written.
    #[error("{0}")]
    Config(String),

    /// Underlying I/O failure with no further context worth adding.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// JSON (de)serialization of the local key-cache file failed.
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// Everything else — authentication failures, CLI usage errors, script
    /// errors — that is genuinely just a message with no further structure
    /// to preserve.
    #[error("{0}")]
    Other(String),
}

impl From<String> for ManagerError {
    fn from(message: String) -> Self {
        Self::Other(message)
    }
}

impl From<&str> for ManagerError {
    fn from(message: &str) -> Self {
        Self::Other(message.to_string())
    }
}
