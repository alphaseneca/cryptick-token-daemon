//! OpenSSH `SecurityKeyProvider` middleware.
//!
//! OpenSSH does not require FIDO tokens to be on USB. From the 8.2 release
//! notes: communication with the token is managed via a middleware library,
//! named by `SecurityKeyProvider` in `ssh_config` or `$SSH_SK_PROVIDER`. That
//! makes SSH the one capability in this project needing no entitlement, no
//! driver and no code signing on any platform (PROJECT.md §10, §16 step 3).
//!
//! ```text
//! SSH_SK_PROVIDER=/usr/local/lib/libsk_blebridge.dylib ssh-keygen -t ed25519-sk
//! ```
//!
//! # This code runs inside someone else's process
//!
//! It is `dlopen`ed into `ssh-sk-helper`, so the rules in PROJECT.md §10 are
//! hard constraints, not style:
//!
//! - **No async runtime.** The IPC client here is blocking, with an explicit
//!   deadline. Starting a reactor inside a host process that knows nothing
//!   about it is how you get a hang at exit.
//! - **No background threads** outliving a call, no process-global state, no
//!   `atexit` handlers, no signal handlers.
//! - **No panics across the FFI boundary.** Unwinding into C is undefined
//!   behaviour, so every entry point is wrapped and returns an error code
//!   instead. This depends on the crate being built with `panic = "unwind"`;
//!   under `panic = "abort"` the barrier cannot work and a panic takes
//!   `ssh-sk-helper` with it.
//! - **Nothing on stdout or stderr.** `ssh-sk-helper` uses both to talk to
//!   `ssh-keygen`; a stray `println!` corrupts that protocol. Diagnostics go
//!   to an opt-in file instead — see [`debug`].
//!
//! # Memory ownership
//!
//! OpenSSH frees our responses with `freezero()`, which is `explicit_bzero()`
//! then `free()`. Everything handed back must therefore come from `malloc`,
//! not from Rust's allocator — see [`alloc`].

#![allow(
    unsafe_code,
    reason = "this crate is an FFI boundary; see PROJECT.md §20"
)]
#![deny(missing_docs)]

pub mod alloc;
pub mod client;
pub mod debug;
pub mod ffi;
pub mod usb;

pub use client::{ClientError, DaemonClient};
pub use debug::DebugLog;
pub use usb::UsbClient;

/// The SK API version this middleware implements, from OpenSSH's `sk-api.h`
/// at `V_10_3_P1`.
///
/// `ssh-sk-helper` refuses to load a provider whose major version does not
/// match its own, so this is the compatibility gate.
pub const SSH_SK_VERSION_MAJOR: u32 = 0x000a_0000;

/// Mask for the significant half of the version.
pub const SSH_SK_VERSION_MAJOR_MASK: u32 = 0xffff_0000;

/// Unspecified failure.
pub const SSH_SK_ERR_GENERAL: i32 = -1;
/// The requested algorithm or option is not supported.
pub const SSH_SK_ERR_UNSUPPORTED: i32 = -2;
/// A PIN is required.
pub const SSH_SK_ERR_PIN_REQUIRED: i32 = -3;
/// No token could be reached.
pub const SSH_SK_ERR_DEVICE_NOT_FOUND: i32 = -4;
/// A credential for this relying party already exists.
pub const SSH_SK_ERR_CREDENTIAL_EXISTS: i32 = -5;

/// ECDSA over NIST P-256.
pub const SSH_SK_ECDSA: u32 = 0x00;
/// Ed25519.
pub const SSH_SK_ED25519: u32 = 0x01;

/// User presence is required for this operation.
pub const SSH_SK_USER_PRESENCE_REQD: u8 = 0x01;
/// User verification is required.
pub const SSH_SK_USER_VERIFICATION_REQD: u8 = 0x04;
/// Perform the operation even if the token would normally decline.
pub const SSH_SK_FORCE_OPERATION: u8 = 0x10;
/// Create a discoverable (resident) credential.
pub const SSH_SK_RESIDENT_KEY: u8 = 0x20;

/// How long an operation may take, end to end.
///
/// Generous because it spans a human finding the fingerprint sensor, but
/// finite: `ssh-sk-helper` has no way to interrupt us, so a hang here is a
/// hung `ssh` (PROJECT.md §10).
pub const OPERATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// How long to wait for the daemon socket itself.
///
/// Short: either the daemon is running or it is not.
pub const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
