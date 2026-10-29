//! The salt query: how a joining device learns the group's `a_salt`.
//!
//! `a_key = Argon2(pw1, a_salt)`, so a new device can't take part in SPAKE2
//! before it has the group's `a_salt`. A member answers a salt query only
//! while its user has the "Add device" invite window open: the listener on
//! [`SALT_PORT`] exists only during the window, so outside it there is no
//! port, no answer and no attack surface.
//!
//! ```text
//! joiner -> member : SALT_QUERY_MAGIC (8) || version (1)
//! member -> joiner : a_salt (32)
//! (close)
//! ```
//!
//! Safe to hand out before authentication: `a_salt` is public by design and
//! gives no offline test of pw1 (SPAKE2 transcripts don't allow offline
//! guesses). A fake salt only makes the joiner derive a wrong `a_key`; the
//! salt is bound into SPAKE2 (`spake2::identity`), so it fails there. Never
//! `d_salt`: that one only travels after authentication (`ActionType::GroupSalt`).
//!
//! Limits: at most [`MAX_SALT_CLIENTS`] connections at once (more are closed
//! at once), one answer per source (IPv4 address / IPv6 /64) every
//! [`ANSWER_INTERVAL`], every read and write bounded by [`TIMEOUT`].
//! The member does no Argon2 and no other work for a query.

use core::fmt;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::select;
use tokio::sync::{Mutex, Semaphore};
use tokio::time::{Duration, Instant, timeout};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

use crate::auth_snow::TIMEOUT;
use crate::guess_limiter::Source;

/// TCP port of the salt query, open only during an invite window.
pub const SALT_PORT: u16 = 3233;

/* query layout */
/// query magic (8)
const SALT_QUERY_MAGIC: &[u8; 8] = b"CESASALT";
/// query version (1)
const SALT_QUERY_VERSION: u8 = 1;
/// magic (8) + version (1)
const SALT_QUERY_LEN: usize = 8 + 1;

/// Salt-query connections handled at the same time; more are closed at once.
pub const MAX_SALT_CLIENTS: usize = 4;
/// One answer per source per this long.
pub const ANSWER_INTERVAL: Duration = Duration::from_secs(5);
/// Most sources remembered for the rate limit.
const MAX_REMEMBERED: usize = 1024;

/// Errors of the salt query.
#[derive(Debug, PartialEq)]
pub enum SaltServiceErrors {
    /// Connecting to the member failed or timed out.
    Unreachable,
    /// Sending the query or the answer failed or timed out.
    SendFailed,
    /// Reading the query or the answer failed, timed out, or the member
    /// closed without answering (no invite window, rate limited).
    NoAnswer,
}

impl fmt::Display for SaltServiceErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SaltServiceErrors::Unreachable => write!(f, "failed to connect for the salt query"),
            SaltServiceErrors::SendFailed => write!(f, "failed to send the salt query"),
            SaltServiceErrors::NoAnswer => {
                write!(f, "no salt answer (no invite window, or rate limited)")
            }
        }
    }
}

/// The query: magic (8) + version (1).
fn query() -> [u8; SALT_QUERY_LEN] {
    let mut packet = [0u8; SALT_QUERY_LEN];

    for (dst, src) in packet
        .iter_mut()
        .zip(SALT_QUERY_MAGIC.iter().chain([SALT_QUERY_VERSION].iter()))
    {
        *dst = *src;
    }

    packet
}

/// When each source was last answered.
#[derive(Default)]
struct Answered(HashMap<Source, Instant>);

impl Answered {
    /// Check-then-record in one step: `true` if `source` may get an answer
    /// now (and it is recorded as answered).
    fn allow(&mut self, source: Source, now: Instant) -> bool {
        if self
            .0
            .get(&source)
            .is_some_and(|last| now.saturating_duration_since(*last) < ANSWER_INTERVAL)
        {
            return false;
        }

        if self.0.len() >= MAX_REMEMBERED {
            // forget whoever is past the interval; still full: refuse new sources
            self.0
                .retain(|_, last| now.saturating_duration_since(*last) < ANSWER_INTERVAL);
            if self.0.len() >= MAX_REMEMBERED {
                return false;
            }
        }

        self.0.insert(source, now);
        true
    }
}

/// Answers one query on `stream`: reads exactly the query, sends `a_salt`.
///
/// 1. <- magic || version
/// 2. -> a_salt
async fn answer(stream: &mut TcpStream, a_salt: &[u8; 32]) -> Result<(), SaltServiceErrors> {
    let mut buf = [0u8; SALT_QUERY_LEN];

    // 1. the query
    timeout(Duration::from_secs(TIMEOUT), stream.read_exact(&mut buf))
        .await
        .map_err(|_| SaltServiceErrors::NoAnswer)?
        .map_err(|_| SaltServiceErrors::NoAnswer)?;

    if buf != query() {
        return Err(SaltServiceErrors::NoAnswer);
    }

    // 2. the salt
    timeout(Duration::from_secs(TIMEOUT), stream.write_all(a_salt))
        .await
        .map_err(|_| SaltServiceErrors::SendFailed)?
        .map_err(|_| SaltServiceErrors::SendFailed)?;

    timeout(Duration::from_secs(TIMEOUT), stream.flush())
        .await
        .map_err(|_| SaltServiceErrors::SendFailed)?
        .map_err(|_| SaltServiceErrors::SendFailed)
}

/// Answers salt queries on `listener` until `token` is cancelled (the end of
/// the invite window). The caller binds the listener only for the window.
pub async fn serve_salt(
    listener: TcpListener,
    a_salt: Zeroizing<[u8; 32]>,
    token: CancellationToken,
) {
    let slots = Arc::new(Semaphore::new(MAX_SALT_CLIENTS));
    let answered = Arc::new(Mutex::new(Answered::default()));
    let a_salt = Arc::new(a_salt);

    info!("salt queries answered until the invite window closes");

    loop {
        let (mut stream, peer_addr) = select! {
            () = token.cancelled() => break,
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(e) => {
                    warn!(error = %e, "accepting a salt query failed");
                    // no busy loop on a failing accept
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
        };

        // no free slot: close at once, never queue
        let Ok(slot) = slots.clone().try_acquire_owned() else {
            debug!(%peer_addr, "too many salt queries, dropping");
            continue;
        };

        // one answer per source per interval, checked and recorded together
        if !answered
            .lock()
            .await
            .allow(Source::of(peer_addr.ip()), Instant::now())
        {
            debug!(%peer_addr, "salt query rate limited, closing");
            continue;
        }

        let a_salt = a_salt.clone();
        let token = token.clone();
        tokio::spawn(async move {
            let _slot = slot;

            select! {
                () = token.cancelled() => {}
                result = answer(&mut stream, &a_salt) => match result {
                    Ok(()) => info!(%peer_addr, "answered a salt query"),
                    Err(e) => debug!(%peer_addr, error = %e, "salt query not answered"),
                },
            }
        });
    }
}

/// Asks the member at `addr` for the group's `a_salt`.
///
/// 1. -> magic || version
/// 2. <- a_salt (exactly 32 bytes)
///
/// The answer is unauthenticated: the caller derives a *candidate* `a_key`
/// from it, which only the SPAKE2 handshake confirms.
pub async fn query_salt(addr: SocketAddr) -> Result<Zeroizing<[u8; 32]>, SaltServiceErrors> {
    let mut stream = timeout(Duration::from_secs(TIMEOUT), TcpStream::connect(addr))
        .await
        .map_err(|_| SaltServiceErrors::Unreachable)?
        .map_err(|_| SaltServiceErrors::Unreachable)?;

    // 1. the query
    timeout(Duration::from_secs(TIMEOUT), stream.write_all(&query()))
        .await
        .map_err(|_| SaltServiceErrors::SendFailed)?
        .map_err(|_| SaltServiceErrors::SendFailed)?;

    // 2. the salt, read straight into a zeroizing buffer
    let mut a_salt = Zeroizing::new([0u8; 32]);
    timeout(
        Duration::from_secs(TIMEOUT),
        stream.read_exact(a_salt.as_mut_slice()),
    )
    .await
    .map_err(|_| SaltServiceErrors::NoAnswer)?
    .map_err(|_| SaltServiceErrors::NoAnswer)?;

    Ok(a_salt)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: [u8; 32] = [0x42; 32];

    /// A salt service on a free localhost port and its cancel token.
    async fn service() -> (SocketAddr, CancellationToken) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let token = CancellationToken::new();

        tokio::spawn(serve_salt(listener, Zeroizing::new(SALT), token.clone()));
        (addr, token)
    }

    /// Test that a query gets exactly the salt
    #[tokio::test]
    async fn test_query_returns_salt() {
        let (addr, token) = service().await;

        assert_eq!(*query_salt(addr).await.unwrap(), SALT);
        token.cancel();
    }

    /// Test that a wrong query gets nothing: the connection just closes
    #[tokio::test]
    async fn test_wrong_query_gets_nothing() {
        let (addr, token) = service().await;
        let mut stream = TcpStream::connect(addr).await.unwrap();

        stream.write_all(b"CESASALX\x01").await.unwrap();
        let mut buf = Vec::new();
        let read = timeout(Duration::from_secs(2), stream.read_to_end(&mut buf))
            .await
            .unwrap()
            .unwrap();

        assert_eq!(read, 0);
        token.cancel();
    }

    /// Test that one source gets one answer per ANSWER_INTERVAL
    #[tokio::test]
    async fn test_rate_limited_per_source() {
        let (addr, token) = service().await;

        assert!(query_salt(addr).await.is_ok());
        assert_eq!(query_salt(addr).await, Err(SaltServiceErrors::NoAnswer));
        token.cancel();
    }

    /// Test that the rate limit forgets a source after the interval and
    /// stays bounded in memory
    #[test]
    fn test_rate_limit_interval_and_bound() {
        let mut answered = Answered::default();
        let now = Instant::now();
        let a = Source::of("10.0.0.1".parse().unwrap());

        assert!(answered.allow(a, now));
        assert!(!answered.allow(a, now));
        assert!(answered.allow(a, now + ANSWER_INTERVAL));

        for i in 0..MAX_REMEMBERED {
            let ip = std::net::Ipv4Addr::from(u32::try_from(i).unwrap() + 0x0B00_0000);
            answered.allow(Source::of(ip.into()), now + ANSWER_INTERVAL);
        }
        assert!(answered.0.len() <= MAX_REMEMBERED);
        let late = Source::of("12.0.0.1".parse().unwrap());
        assert!(!answered.allow(late, now + ANSWER_INTERVAL));
    }

    /// Test that after the window (token cancelled) nobody is answered
    #[tokio::test]
    async fn test_closed_window_answers_nothing() {
        let (addr, token) = service().await;
        token.cancel();
        tokio::time::sleep(Duration::from_millis(50)).await;

        // the port itself is gone, not only the answer
        assert!(TcpStream::connect(addr).await.is_err());
        assert!(query_salt(addr).await.is_err());
    }
}
