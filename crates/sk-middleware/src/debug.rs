//! Opt-in diagnostic logging.
//!
//! This library is `dlopen`ed into `ssh-sk-helper`, which owns stdout and
//! stderr (PROJECT.md §10), so diagnostics can only reasonably go to a file.
//! Three rules shape how, and all three are corrections of what this module
//! replaced — an unconditional `/tmp/sk_debug.log`:
//!
//! - **Off unless asked for.** PROJECT.md §15.5 requires debug logging to sit
//!   behind an explicit runtime flag. Nothing here is opened, created or
//!   written unless [`DEBUG_LOG_ENV`] is set, so the default install of a
//!   library that sits on an SSH authentication path writes no file at all.
//!
//! - **The flag names the file.** A *fixed* path in a world-writable directory
//!   is a liability in this particular process. The file was created with the
//!   ambient umask, hence typically world-readable, handing every local user a
//!   log of someone else's SSH key operations; and because the open was
//!   `create(true)` rather than `create_new(true)`, any local user could win
//!   the race, create the path first — as a symlink, if they liked — and have
//!   `ssh-sk-helper` append into a file of their choosing. Having the operator
//!   name the path removes the predictable target along with the default-on
//!   behaviour. `O_NOFOLLOW` and `0600` below close the rest.
//!
//! - **No payload contents, ever.** §15.5 forbids logging key material, PINs,
//!   APDU bodies or CBOR payload contents. Transport choice, CTAP status
//!   words, byte *counts* and error *descriptions* are none of those, and are
//!   what actually helps when a transaction fails; the response body is not.
//!   The code this replaced hex-dumped an entire
//!   `authenticatorMakeCredential` response whenever parsing it failed.
//!
//! The error types logged here were checked rather than assumed: `ResponseError`
//! names a missing or mistyped member, and `CborError` carries offsets, counts
//! and major/additional-info numbers. Neither embeds the input bytes, so
//! formatting one does not reintroduce what the third rule removes.

use std::fs::{File, OpenOptions};
use std::io::Write;

/// The environment variable that both enables logging and names its
/// destination. Unset — the normal case — means no logging.
pub const DEBUG_LOG_ENV: &str = "CRYPTICK_SK_DEBUG_LOG";

/// A diagnostic sink that exists only when the operator asked for one.
///
/// Holds an open file for the duration of one FFI call and nothing longer;
/// PROJECT.md §10 forbids process-global state in this crate.
#[derive(Debug)]
pub struct DebugLog(Option<File>);

impl DebugLog {
    /// Opens the file named by [`DEBUG_LOG_ENV`] for appending, or returns a
    /// sink that discards everything.
    ///
    /// Never fails: a log that cannot be opened is not a reason to fail an SSH
    /// operation, so an unwritable path is indistinguishable here from logging
    /// being switched off.
    pub fn open() -> Self {
        let Some(path) = std::env::var_os(DEBUG_LOG_ENV) else {
            return Self(None);
        };
        if path.is_empty() {
            return Self(None);
        }

        let mut opts = OpenOptions::new();
        opts.create(true).append(true);

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // The log names relying parties and credential sizes. No other
            // local user needs them, and the ambient umask is not trusted to
            // decide that.
            opts.mode(0o600);
            // Refuse a symlink at the final component instead of following it
            // into a file this process has no business appending to.
            opts.custom_flags(libc::O_NOFOLLOW);
        }

        Self(opts.open(path).ok())
    }

    /// Returns `true` when logging is actually on, so a caller can skip
    /// assembling a message nobody will read.
    pub fn is_enabled(&self) -> bool {
        self.0.is_some()
    }

    /// Appends one line, or does nothing when logging is off.
    ///
    /// Write errors are discarded for the same reason [`Self::open`] cannot
    /// fail: a full disk must not break `ssh`.
    pub fn line(&mut self, args: std::fmt::Arguments<'_>) {
        if let Some(file) = &mut self.0 {
            let _ = writeln!(file, "{args}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logging_is_off_when_the_variable_is_unset() {
        // Not `std::env::set_var`: tests share a process, and this asserts the
        // default rather than a manipulated environment.
        if std::env::var_os(DEBUG_LOG_ENV).is_none() {
            assert!(
                !DebugLog::open().is_enabled(),
                "no log may be opened without {DEBUG_LOG_ENV}"
            );
        }
    }

    #[test]
    fn a_disabled_log_accepts_writes_and_drops_them() {
        let mut log = DebugLog(None);
        assert!(!log.is_enabled());
        log.line(format_args!("dropped"));
    }
}
