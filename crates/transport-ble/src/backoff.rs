//! Bounded, jittered backoff for BLE reconnection.
//!
//! A dropped BLE link is the common case for a battery-powered device that
//! spends most of its life advertising or holding an idle connection
//! (PROJECT.md §17, "Power and connection behaviour"): it sleeps, walks out
//! of range, or loses the link to interference, routinely and expectedly.
//! Retrying on a flat, fixed interval forever — which is what
//! `ReconnectingBleTransport` did before this module existed — burns radio
//! airtime and host CPU for no benefit once a token has been gone for more
//! than a few seconds, with no ceiling on how long that goes on.
//!
//! This implements "Equal Jitter" from the backoff-with-jitter family
//! (popularized by the AWS Architecture Blog's 2015 post "Exponential
//! Backoff And Jitter"): each attempt's delay is half of a deterministic
//! exponential ceiling, plus a uniformly random extra half. Equal Jitter is
//! chosen deliberately over that same post's "Full Jitter" strategy: Full
//! Jitter can roll a near-zero delay even after many failed attempts, which
//! is the right trade when many independent clients are spreading load off
//! a shared server, but wrong here — there is one daemon and one token, so
//! an unlucky near-zero roll right after several failures would defeat the
//! entire point of backing off. Equal Jitter keeps a guaranteed floor of
//! `ceiling / 2` while still avoiding an exactly periodic retry pattern.
//!
//! No `rand` dependency. PROJECT.md §20 asks that new runtime dependencies
//! in `daemon/` be a deliberate discussion, not a one-line convenience, and
//! this crate is `daemon`'s only BLE radio implementation. A splitmix64
//! generator seeded from the system clock and a process-wide counter is
//! adequate: jitter only needs to avoid exact synchronisation between
//! attempts, not to resist prediction, so nothing here is asked to do a
//! cryptographic RNG's job.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Smallest delay after the first unexpected disconnect. Also the interval
/// `crates/daemon/src/transport.rs` polls at while the link looks healthy,
/// so noticing a *new* disconnect is never slower than this, only the
/// *retries* after one slow down.
pub const INITIAL_BACKOFF: Duration = Duration::from_secs(1);

/// Largest delay this ever reaches, no matter how many attempts fail in a
/// row. Bounded so a token left unreachable for an extended period is
/// retried roughly once a minute, not abandoned or left hammering the radio.
pub const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// Doubling factor between attempts, before jitter and the ceiling above
/// are applied.
const BACKOFF_MULTIPLIER: u32 = 2;

/// Attempts beyond this are clamped: `INITIAL_BACKOFF * 2^6` (64s) already
/// exceeds `MAX_BACKOFF` (60s), so growing the exponent further would only
/// ever be clamped back down anyway.
const MAX_SHIFT: u32 = 6;

/// Process-wide counter mixed into each new backoff's seed, so two
/// [`ReconnectBackoff`]s created in the same nanosecond (unlikely but not
/// impossible on a fast clock) still start from different jitter sequences.
static SEED_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Tracks reconnect attempts for one unexpected-disconnect episode.
///
/// Call [`Self::next_delay`] before each retry and [`Self::reset`] the
/// moment a connection attempt actually succeeds. A *deliberate* retarget
/// (`LiveRetarget::retarget` in `crates/daemon/src/transport.rs`, driven by
/// the user picking a different known device) is intentionally **not**
/// routed through this struct at all — it is handled on its own channel
/// with its own fixed, short timeout, so a user who explicitly asks for a
/// different device is never made to wait out another device's backoff.
#[derive(Debug)]
pub struct ReconnectBackoff {
    attempt: u32,
    rng: u64,
}

impl ReconnectBackoff {
    /// Starts at attempt zero, seeded so that two of these — e.g. across
    /// daemon restarts — do not produce identical jitter sequences.
    pub fn new() -> Self {
        let counter = SEED_COUNTER.fetch_add(1, Ordering::Relaxed);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let seed = now
            ^ counter.wrapping_mul(0x2545_F491_4F6C_DD1D)
            ^ 0x9E37_79B9_7F4A_7C15;
        Self {
            attempt: 0,
            // splitmix64 degenerates for a zero state; guarantee non-zero.
            rng: seed | 1,
        }
    }

    /// Back to attempt zero. Call after a connection attempt actually
    /// succeeds, so the next unexpected disconnect starts a fresh episode
    /// rather than inheriting how long the *previous* one took to recover.
    pub fn reset(&mut self) {
        self.attempt = 0;
    }

    /// The delay to wait before the next attempt. Advances the attempt
    /// counter as a side effect, so each call in a row backs off further
    /// until [`Self::reset`] is called.
    pub fn next_delay(&mut self) -> Duration {
        let shift = self.attempt.min(MAX_SHIFT);
        let scaled = INITIAL_BACKOFF.saturating_mul(BACKOFF_MULTIPLIER.saturating_pow(shift));
        let ceiling = scaled.min(MAX_BACKOFF);
        self.attempt = self.attempt.saturating_add(1);

        // Equal Jitter: a guaranteed floor of half the ceiling, plus a
        // uniformly random extra half.
        let half = ceiling / 2;
        let jitter_span_ns = (ceiling - half).as_nanos() as u64;
        let jitter_ns = if jitter_span_ns == 0 {
            0
        } else {
            self.next_u64() % (jitter_span_ns + 1)
        };
        half + Duration::from_nanos(jitter_ns)
    }

    /// splitmix64 (Vigna, public domain). Statistically well-spread, not
    /// cryptographically secure — exactly what jitter needs and no more;
    /// see the module doc for why `rand` was not pulled in for this.
    fn next_u64(&mut self) -> u64 {
        self.rng = self.rng.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.rng;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

impl Default for ReconnectBackoff {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_delay_respects_the_equal_jitter_floor_and_ceiling() {
        let mut b = ReconnectBackoff::new();
        let d = b.next_delay();
        assert!(
            d >= INITIAL_BACKOFF / 2,
            "equal jitter must keep the floor: got {d:?}"
        );
        assert!(
            d <= INITIAL_BACKOFF,
            "first delay must not exceed the unjittered ceiling: got {d:?}"
        );
    }

    #[test]
    fn delay_grows_but_never_exceeds_the_ceiling() {
        let mut b = ReconnectBackoff::new();
        let mut prev_floor = Duration::ZERO;
        for i in 0..50 {
            let d = b.next_delay();
            assert!(d <= MAX_BACKOFF, "backoff must stay bounded: got {d:?}");
            if i < MAX_SHIFT {
                // Each successive floor (ceiling / 2) must not shrink while
                // still climbing toward the ceiling.
                assert!(d + d >= prev_floor, "equal jitter floor regressed at attempt {i}");
            }
            prev_floor = d;
        }
    }

    #[test]
    fn eventually_clamps_at_the_ceiling() {
        let mut b = ReconnectBackoff::new();
        for _ in 0..(MAX_SHIFT + 5) {
            b.next_delay();
        }
        let d = b.next_delay();
        assert!(d >= MAX_BACKOFF / 2 && d <= MAX_BACKOFF, "got {d:?}");
    }

    #[test]
    fn reset_returns_to_the_initial_floor() {
        let mut b = ReconnectBackoff::new();
        for _ in 0..10 {
            b.next_delay();
        }
        b.reset();
        let d = b.next_delay();
        assert!(
            d <= INITIAL_BACKOFF,
            "a reset attempt must look like the first one: got {d:?}"
        );
    }

    #[test]
    fn jitter_is_not_constant_across_instances() {
        // Not a security property — only confirms the splitmix64 stream is
        // actually being consumed rather than accidentally always the same.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..20 {
            let mut b = ReconnectBackoff::new();
            for _ in 0..5 {
                b.next_delay();
            }
            seen.insert(b.next_delay());
        }
        assert!(seen.len() > 1, "expected varied delays, got {seen:?}");
    }
}
