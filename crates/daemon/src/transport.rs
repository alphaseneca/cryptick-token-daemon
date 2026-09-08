//! The seam between the daemon and whatever is carrying fragments.
//!
//! The trait is deliberately at the **fragment** level, not the message level.
//! Framing is the daemon's job and the part most likely to be got wrong, so it
//! must sit above the seam where the fake transport can attack it. A trait that
//! exchanged whole messages would hide exactly the code that needs testing.

use ble_framing::FragmentSize;
use thiserror::Error;

/// What the link is currently doing.
///
/// `bonded` and `authenticated` are separate on purpose. A bond formed by Just
/// Works pairing exists but carries no MITM protection, and CTAP requires LE
/// Secure Connections **with** MITM protection — so a transport that reports
/// only "some bond exists" cannot satisfy PROJECT.md §15.2. Any backend that
/// cannot distinguish the two must report `authenticated: false` rather than
/// guessing in the user's favour (§15.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkState {
    /// A device is reachable.
    pub connected: bool,
    /// A bond exists.
    pub bonded: bool,
    /// The bond was formed with MITM protection and the link is encrypted.
    pub authenticated: bool,
}

impl LinkState {
    /// Nothing connected.
    pub const DISCONNECTED: LinkState = LinkState {
        connected: false,
        bonded: false,
        authenticated: false,
    };

    /// Connected, bonded, MITM-protected. The only state we will transact in.
    pub const READY: LinkState = LinkState {
        connected: true,
        bonded: true,
        authenticated: true,
    };

    /// Whether a CTAP transaction may proceed.
    pub const fn is_usable(self) -> bool {
        self.connected && self.bonded && self.authenticated
    }
}

/// The transport failed underneath us.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TransportError {
    /// The link dropped.
    #[error("the link went down")]
    Disconnected,
    /// A GATT operation failed.
    #[error("GATT operation failed: {0}")]
    Gatt(String),
    /// `fidoControlPointLength` held a value outside the permitted range.
    #[error("device published an unusable fidoControlPointLength: {0}")]
    BadControlPointLength(u16),
}

/// A bidirectional pipe for CTAP BLE fragments.
#[async_trait::async_trait]
pub trait FragmentTransport: Send {
    /// The value published in `fidoControlPointLength`.
    ///
    /// Read from the characteristic, never assumed — it follows the negotiated
    /// ATT MTU and so varies per connection (PROJECT.md §12, §17).
    async fn fragment_size(&mut self) -> Result<FragmentSize, TransportError>;

    /// Writes one fragment to `fidoControlPoint`.
    async fn write_fragment(&mut self, fragment: &[u8]) -> Result<(), TransportError>;

    /// Waits for the next notification on `fidoStatus`.
    async fn next_notification(&mut self) -> Result<Vec<u8>, TransportError>;

    /// The current link state.
    fn link(&self) -> LinkState;
}
