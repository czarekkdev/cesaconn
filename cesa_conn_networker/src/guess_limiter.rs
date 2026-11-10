//! Limits online password guessing.
//!
//! SPAKE2 allows one password guess per connection and nothing more, so the
//! remaining attack on `a_key` is to simply try many connections. Every
//! failed SPAKE2 confirmation (a wrong password, on either side) is counted
//! per source: one IPv4 address, or one IPv6 /64 (a single host usually owns
//! a whole /64, so per-address counting would be trivial to dodge).
//!
//! After [`MAX_FAILURES`] failures in a row the source is locked out for
//! [`FIRST_LOCKOUT`], doubling with every further lockout up to
//! [`MAX_LOCKOUT`]. A successful handshake resets the source.
//!
//! The table holds [`MAX_TRACKED`] sources. When that many are active, the
//! listener refuses a new source before the handshake ([`GuessLimiter::is_full_for`]):
//! otherwise filling the table from many addresses would give every further
//! address unlimited guesses. A paired device at its known address still
//! gets in while [`RESERVE`] extra slots have room, so its failures are
//! counted too; those slots also take failures of our own outgoing
//! connections. A source is only admitted while its failure can be counted.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use tokio::sync::Mutex;
use tokio::time::{Duration, Instant};
use tracing::warn;

/// wrong passwords in a row before a lockout
pub const MAX_FAILURES: u32 = 5;
/// first lockout, doubled for every further one
pub const FIRST_LOCKOUT: Duration = Duration::from_secs(60);
/// longest lockout
pub const MAX_LOCKOUT: Duration = Duration::from_secs(60 * 60);
/// most sources tracked at once, so the limiter itself can't eat all memory
pub const MAX_TRACKED: usize = 4096;
/// extra slots for failures from paired devices' addresses (admitted while
/// the table is full) and our own outgoing connections
pub const RESERVE: usize = 256;
/// a source without failures for this long is forgotten
const FORGET_AFTER: Duration = Duration::from_secs(2 * 60 * 60);

/// Who a failure is counted against: an IPv4 address or an IPv6 /64.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) struct Source(IpAddr);

impl Source {
    /// The source an address is counted as (also used by `salt_service`).
    pub(crate) fn of(ip: IpAddr) -> Self {
        match ip.to_canonical() {
            IpAddr::V4(v4) => Self(IpAddr::V4(v4)),
            IpAddr::V6(v6) => {
                let s = v6.segments();
                // keep the /64 network prefix, drop the interface id
                Self(IpAddr::V6(Ipv6Addr::new(
                    s[0], s[1], s[2], s[3], 0, 0, 0, 0,
                )))
            }
        }
    }
}

/// Failure history of one source.
struct Entry {
    /// failures since the last lockout or success
    failures: u32,
    /// lockouts so far, decides the next lockout's length
    lockouts: u32,
    /// locked until this moment
    locked_until: Option<Instant>,
    /// when the last failure happened
    last_failure: Instant,
}

impl Entry {
    fn is_locked(&self, now: Instant) -> bool {
        self.locked_until.is_some_and(|until| now < until)
    }

    /// Safe to forget: not locked and quiet for long enough.
    fn is_stale(&self, now: Instant) -> bool {
        !self.is_locked(now) && now.saturating_duration_since(self.last_failure) > FORGET_AFTER
    }
}

/// Length of the `n`-th lockout (1-based): FIRST_LOCKOUT * 2^(n-1), capped.
fn lockout_duration(n: u32) -> Duration {
    let factor = 1u32.checked_shl(n.saturating_sub(1)).unwrap_or(u32::MAX);

    FIRST_LOCKOUT.saturating_mul(factor).min(MAX_LOCKOUT)
}

/// What [`count_failure`] did.
enum Counted {
    /// limiter full of active sources, failure not recorded
    NotTracked,
    /// failure recorded, no lockout yet
    Recorded,
    /// failure recorded and the source is now locked for this long
    LockedOut(Duration),
}

/// Records one failure of `source` in `entries` (see the module docs).
fn count_failure(entries: &mut HashMap<Source, Entry>, source: Source, now: Instant) -> Counted {
    let limit = MAX_TRACKED.saturating_add(RESERVE);
    if !entries.contains_key(&source) && entries.len() >= limit {
        entries.retain(|_, entry| !entry.is_stale(now));

        if entries.len() >= limit {
            // reserve used up too: memory stays bounded
            return Counted::NotTracked;
        }
    }

    let entry = entries.entry(source).or_insert(Entry {
        failures: 0,
        lockouts: 0,
        locked_until: None,
        last_failure: now,
    });

    entry.failures = entry.failures.saturating_add(1);
    entry.last_failure = now;

    if entry.failures < MAX_FAILURES {
        return Counted::Recorded;
    }

    entry.failures = 0;
    entry.lockouts = entry.lockouts.saturating_add(1);

    let duration = lockout_duration(entry.lockouts);

    // an overflowing deadline means "as long as possible"
    entry.locked_until = Some(
        now.checked_add(duration)
            .unwrap_or_else(|| now.checked_add(MAX_LOCKOUT).unwrap_or(now)),
    );

    Counted::LockedOut(duration)
}

/// Shared failure counter for all connections, see the module docs.
#[derive(Default)]
pub struct GuessLimiter {
    // only held for map operations, never across network I/O
    entries: Mutex<HashMap<Source, Entry>>,
}

impl GuessLimiter {
    /// An empty limiter.
    pub fn new() -> Self {
        Self::default()
    }

    /// `true` if `ip` is locked out right now: don't run a handshake with it.
    pub async fn is_locked(&self, ip: IpAddr) -> bool {
        let now = Instant::now();

        self.entries
            .lock()
            .await
            .get(&Source::of(ip))
            .is_some_and(|entry| entry.is_locked(now))
    }

    /// `true` if `ip` isn't tracked and no failure of it could be counted
    /// now: [`MAX_TRACKED`] active sources, or with `known` (a paired
    /// device's address) [`MAX_TRACKED`] + [`RESERVE`]. The listener refuses
    /// such a source (see the module docs). Stale sources are dropped first.
    pub async fn is_full_for(&self, ip: IpAddr, known: bool) -> bool {
        let now = Instant::now();
        let limit = if known {
            MAX_TRACKED.saturating_add(RESERVE)
        } else {
            MAX_TRACKED
        };
        let mut entries = self.entries.lock().await;

        if entries.contains_key(&Source::of(ip)) || entries.len() < limit {
            return false;
        }
        entries.retain(|_, entry| !entry.is_stale(now));
        entries.len() >= limit
    }

    /// Counts a failed SPAKE2 confirmation (wrong password) for `ip`.
    pub async fn record_failure(&self, ip: IpAddr) {
        // the guard is a temporary: the lock is released before logging
        let outcome = count_failure(
            &mut *self.entries.lock().await,
            Source::of(ip),
            Instant::now(),
        );

        match outcome {
            Counted::NotTracked => {
                warn!(%ip, max = MAX_TRACKED.saturating_add(RESERVE), "guess limiter full, failure not tracked");
            }
            Counted::LockedOut(duration) => {
                warn!(%ip, lockout_secs = duration.as_secs(), "too many wrong passwords, locked out");
            }
            Counted::Recorded => {}
        }
    }

    /// A successful handshake with `ip`: forget its failures.
    pub async fn record_success(&self, ip: IpAddr) {
        self.entries.lock().await.remove(&Source::of(ip));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const V4: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 50));

    async fn fail(limiter: &GuessLimiter, ip: IpAddr, times: u32) {
        for _ in 0..times {
            limiter.record_failure(ip).await;
        }
    }

    /// Test that the lockout starts at the fifth failure, not before
    #[tokio::test(start_paused = true)]
    async fn test_locks_after_max_failures() {
        let limiter = GuessLimiter::new();

        fail(&limiter, V4, MAX_FAILURES - 1).await;
        assert!(!limiter.is_locked(V4).await);

        fail(&limiter, V4, 1).await;
        assert!(limiter.is_locked(V4).await);
    }

    /// Test that lockouts last 1 min, then 2 min, ... up to 1 h
    #[tokio::test(start_paused = true)]
    async fn test_lockout_doubles_up_to_max() {
        let limiter = GuessLimiter::new();

        for minutes in [1u64, 2, 4, 8, 16, 32, 60, 60] {
            fail(&limiter, V4, MAX_FAILURES).await;

            tokio::time::advance(Duration::from_secs(minutes * 60 - 1)).await;
            assert!(
                limiter.is_locked(V4).await,
                "still locked before {minutes} min"
            );

            tokio::time::advance(Duration::from_secs(1)).await;
            assert!(!limiter.is_locked(V4).await, "unlocked after {minutes} min");
        }
    }

    /// Test that a success resets the count and the lockout history
    #[tokio::test(start_paused = true)]
    async fn test_success_resets() {
        let limiter = GuessLimiter::new();

        fail(&limiter, V4, MAX_FAILURES).await;
        tokio::time::advance(FIRST_LOCKOUT).await;
        limiter.record_success(V4).await;

        fail(&limiter, V4, MAX_FAILURES - 1).await;
        assert!(!limiter.is_locked(V4).await);

        // next lockout is the first one again (1 min), not 2 min
        fail(&limiter, V4, 1).await;
        tokio::time::advance(FIRST_LOCKOUT).await;
        assert!(!limiter.is_locked(V4).await);
    }

    /// Test that all addresses of one IPv6 /64 share a counter
    #[tokio::test(start_paused = true)]
    async fn test_ipv6_counted_per_64() {
        let limiter = GuessLimiter::new();

        for host in 1..=MAX_FAILURES {
            let ip: IpAddr = format!("2001:db8:1:2::{host:x}").parse().unwrap();
            limiter.record_failure(ip).await;
        }

        assert!(
            limiter
                .is_locked("2001:db8:1:2::ffff".parse().unwrap())
                .await
        );
        assert!(!limiter.is_locked("2001:db8:1:3::1".parse().unwrap()).await);
    }

    /// Test that an IPv4-mapped IPv6 address counts as its IPv4 address
    #[tokio::test(start_paused = true)]
    async fn test_ipv4_mapped_is_canonicalised() {
        let limiter = GuessLimiter::new();

        fail(
            &limiter,
            "::ffff:192.168.1.50".parse().unwrap(),
            MAX_FAILURES,
        )
        .await;
        assert!(limiter.is_locked(V4).await);
    }

    /// Test that other sources are not affected
    #[tokio::test(start_paused = true)]
    async fn test_sources_independent() {
        let limiter = GuessLimiter::new();

        fail(&limiter, V4, MAX_FAILURES).await;
        assert!(!limiter.is_locked("192.168.1.51".parse().unwrap()).await);
    }

    /// Test that the map never grows past MAX_TRACKED + RESERVE
    #[tokio::test(start_paused = true)]
    async fn test_memory_bounded() {
        let limiter = GuessLimiter::new();

        let max = u32::try_from(MAX_TRACKED + RESERVE).unwrap();

        for i in 0..(max + 100) {
            limiter.record_failure(IpAddr::V4(i.into())).await;
        }

        assert_eq!(limiter.entries.lock().await.len(), MAX_TRACKED + RESERVE);

        // stale entries make room again
        tokio::time::advance(FORGET_AFTER + Duration::from_secs(1)).await;
        fail(&limiter, V4, MAX_FAILURES).await;
        assert!(limiter.is_locked(V4).await);
    }

    /// Fills the table with `MAX_TRACKED` sources (10.0.x.y), one failure each.
    async fn fill(limiter: &GuessLimiter) {
        for i in 0..u32::try_from(MAX_TRACKED).unwrap() {
            let ip = IpAddr::V4(std::net::Ipv4Addr::from(0x0A00_0000 | i));
            limiter.record_failure(ip).await;
        }
    }

    /// Test that a full table is full only for new sources, and frees up
    /// once its sources go stale
    #[tokio::test(start_paused = true)]
    async fn test_full_table_refuses_new_sources() {
        let limiter = GuessLimiter::new();
        let tracked = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 7));

        fill(&limiter).await;
        assert!(limiter.is_full_for(V4, false).await);
        assert!(!limiter.is_full_for(tracked, false).await);

        // one source fewer: room again
        limiter.record_success(tracked).await;
        assert!(!limiter.is_full_for(V4, false).await);
        limiter.record_failure(tracked).await;
        assert!(limiter.is_full_for(V4, false).await);

        tokio::time::advance(FORGET_AFTER + Duration::from_secs(1)).await;
        assert!(!limiter.is_full_for(V4, false).await);
    }

    /// Test that a paired device's address is admitted while the reserve
    /// has room, its failures are counted there (it gets locked out), and
    /// once the reserve is full it isn't admitted either
    #[tokio::test(start_paused = true)]
    async fn test_full_table_still_counts_admitted_sources() {
        let limiter = GuessLimiter::new();
        fill(&limiter).await;

        assert!(!limiter.is_full_for(V4, true).await);
        fail(&limiter, V4, MAX_FAILURES).await;
        assert!(limiter.is_locked(V4).await);

        // the rest of the reserve, e.g. outgoing connections that failed
        let other = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 77));
        for i in 0..u32::try_from(RESERVE - 1).unwrap() {
            let ip = IpAddr::V4(std::net::Ipv4Addr::from(0x0B00_0000 | i));
            assert!(!limiter.is_full_for(ip, true).await);
            limiter.record_failure(ip).await;
        }
        assert!(limiter.is_full_for(other, true).await);
        // tracked sources keep their place
        assert!(!limiter.is_full_for(V4, true).await);
    }

    /// Test the lockout length formula, including overflow
    #[test]
    fn test_lockout_duration() {
        assert_eq!(lockout_duration(1), FIRST_LOCKOUT);
        assert_eq!(lockout_duration(2), FIRST_LOCKOUT * 2);
        assert_eq!(lockout_duration(7), MAX_LOCKOUT);
        assert_eq!(lockout_duration(u32::MAX), MAX_LOCKOUT);
    }
}
