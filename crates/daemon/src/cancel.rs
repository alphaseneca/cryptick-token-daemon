//! Cancellation, as a pair of handles.

use tokio::sync::watch;

/// Cancels a transaction. Cloneable; any clone can cancel.
#[derive(Debug, Clone)]
pub struct CancelHandle(watch::Sender<bool>);

/// Observes cancellation from inside a transaction.
#[derive(Debug, Clone)]
pub struct CancelToken(watch::Receiver<bool>);

/// A fresh, uncancelled pair.
pub fn cancel_pair() -> (CancelHandle, CancelToken) {
    let (tx, rx) = watch::channel(false);
    (CancelHandle(tx), CancelToken(rx))
}

impl CancelHandle {
    /// Requests cancellation. Idempotent.
    pub fn cancel(&self) {
        let _ = self.0.send(true);
    }
}

impl CancelToken {
    /// Whether cancellation has already been requested.
    pub fn is_cancelled(&self) -> bool {
        *self.0.borrow()
    }

    /// Resolves once cancellation is requested.
    ///
    /// If every handle has been dropped, this never resolves — a dropped handle
    /// means "nobody will cancel", not "cancel now". Resolving on drop would
    /// abort healthy transactions whenever a client stopped holding its handle.
    pub async fn cancelled(&mut self) {
        loop {
            if *self.0.borrow_and_update() {
                return;
            }
            if self.0.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cancelling_is_observed() {
        let (handle, mut token) = cancel_pair();
        assert!(!token.is_cancelled());
        handle.cancel();
        assert!(token.is_cancelled());
        token.cancelled().await;
    }

    #[tokio::test]
    async fn cancelling_twice_is_harmless() {
        let (handle, mut token) = cancel_pair();
        handle.cancel();
        handle.cancel();
        token.cancelled().await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_dropped_handle_does_not_cancel() {
        let (handle, mut token) = cancel_pair();
        drop(handle);
        assert!(!token.is_cancelled());
        tokio::select! {
            _ = token.cancelled() => panic!("a dropped handle must not cancel"),
            _ = tokio::time::sleep(std::time::Duration::from_secs(3600)) => {}
        }
    }
}
