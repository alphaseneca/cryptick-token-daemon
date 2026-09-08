//! The bridge daemon: owns the radio, hosts the adapters.
//!
//! Transport and adaptation only. It holds no key material, caches no
//! credentials, builds no client data, makes no origin decisions, and never
//! satisfies user presence on the device's behalf. Those all belong to the
//! authenticator on one side and the browser or OS on the other
//! (PROJECT.md §4, §15, §21).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod bridge;
pub mod cancel;
pub mod error;
pub mod hid;
pub mod server;
pub mod session;
pub mod transport;

#[cfg(feature = "fake-transport")]
pub mod fake;

pub use bridge::Bridge;
pub use cancel::{cancel_pair, CancelHandle, CancelToken};
pub use error::DaemonError;
pub use hid::{HidBridge, PacketSink};
pub use session::{KeepaliveSink, Session};
pub use transport::{FragmentTransport, LinkState, TransportError};
