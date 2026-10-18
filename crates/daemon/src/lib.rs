//! The bridge daemon: owns the radio, hosts the adapters.
//!
//! Transport and adaptation only. It holds no key material, caches no
//! credentials, builds no client data, makes no origin decisions, and never
//! satisfies user presence on the device's behalf. Those all belong to the
//! authenticator on one side and the browser or OS on the other
//! (PROJECT.md §4, §15, §21).

// Unsafe stays forbidden outright on every target that can manage it. Windows
// is the one that cannot: §15.7's restrictive DACL on the named pipe and the
// `GetNamedPipeClientProcessId` peer check are raw Win32 calls with no safe
// binding anywhere in the ecosystem (see `server::windows`). So on that target
// the lint drops from `forbid` to `deny` — still an error everywhere by
// default — and exactly one module carries a scoped `#[allow(unsafe_code)]`.
// That is PROJECT.md §20's "unsafe is confined to FFI boundaries, with a
// safety comment per block", kept as narrow as the lint system allows:
// `forbid` cannot be relaxed per-module, which is the only reason this line
// is conditional rather than absolute.
#![cfg_attr(not(windows), forbid(unsafe_code))]
#![cfg_attr(windows, deny(unsafe_code))]
#![deny(missing_docs)]

pub mod bridge;
pub mod cancel;
pub mod cli;
pub mod devices;
pub mod error;
pub mod hid;
pub mod login;
pub mod server;
pub mod service;
pub mod session;
pub mod transport;
pub mod vpcd_relay;

#[cfg(feature = "fake-transport")]
pub mod fake;

pub use bridge::Bridge;
pub use cancel::{cancel_pair, CancelHandle, CancelToken};
pub use devices::{DeviceStore, KnownDevice, UnknownDeviceError};
pub use error::DaemonError;
pub use hid::{HidBridge, PacketSink};
pub use login::{check_login_status, print_login_status, run_login_setup, LoginStatusReport};
pub use session::{KeepaliveSink, Session};
pub use transport::{
    FragmentTransport, LinkState, LiveRetarget, ReconnectingBleTransport, RetargetError,
    TransportError,
};
pub use vpcd_relay::{run_vpcd_relay, PivCardTransport, RelayError, VpcdRelay};
