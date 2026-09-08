//! One transaction at a time, across every adapter.
//!
//! The device is a single-threaded authenticator, so CTAP transactions must
//! never interleave (PROJECT.md §13). This is where that is enforced — once,
//! centrally, rather than hopefully in each adapter.
//!
//! It rejects rather than queues. A queued transaction would sit waiting and
//! then demand its own fingerprint at a moment the user has stopped expecting
//! one, which is worse than a clean refusal — and on the firmware side a second
//! pending request is exactly the presence-confusion hazard the device has to
//! avoid too.

use crate::{
    cancel::CancelToken,
    error::DaemonError,
    session::{KeepaliveSink, Session},
    transport::{FragmentTransport, LinkState},
};
use std::time::Duration;
use tokio::sync::Mutex;

/// Serialises access to one device.
///
/// `T: Clone` because the bridge keeps a second handle purely to answer status
/// queries while a transaction holds the session. Implementations are expected
/// to be `Arc`-backed handles to one connection, not independent links — the
/// status handle is **read-only** and must never write a fragment.
#[derive(Debug)]
pub struct Bridge<T> {
    session: Mutex<Session<T>>,
    status: T,
}

impl<T: FragmentTransport + Clone> Bridge<T> {
    /// Wraps a transport.
    pub fn new(transport: T) -> Self {
        Self {
            status: transport.clone(),
            session: Mutex::new(Session::new(transport)),
        }
    }

    /// The link state, answerable even mid-transaction.
    pub fn link(&self) -> LinkState {
        self.status.link()
    }

    /// Whether a transaction is currently in flight.
    pub fn is_busy(&self) -> bool {
        self.session.try_lock().is_err()
    }

    /// Runs a transaction, or refuses with [`DaemonError::Busy`].
    pub async fn transact(
        &self,
        request: &ctap::Request,
        timeout: Duration,
        keepalives: &KeepaliveSink,
        cancel: &mut CancelToken,
    ) -> Result<ctap::Response, DaemonError> {
        let mut session = self.session.try_lock().map_err(|_| DaemonError::Busy)?;
        session.transact(request, timeout, keepalives, cancel).await
    }
}
