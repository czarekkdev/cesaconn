//! Where the paired devices were last seen, and what connecting to them
//! last showed (shown to the user: an incorrect password, unreachable, ...).
//!
//! Addresses are learned only from authenticated connections: the source
//! IP of a paired device that authenticated to us (with the fixed port), or
//! the address we connected to when the device there authenticated. They
//! are hints where to connect for sync; trust is still decided by the
//! handshake. They are saved in the encrypted vault (config entry), so sync
//! works after a restart without an "Add device".
//!
//! A wrong password can't be tied to a device by the handshake (SPAKE2
//! fails before anyone is identified), so it is tied by address: a failed
//! confirmation from or to the address a paired device was last seen at is
//! shown on that device. That is a hint for the user, not a security
//! decision (daemon.md 18).

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use subtle::ConstantTimeEq;
use tokio::sync::{Notify, RwLock};
use tokio::time::Instant;

use cesa_conn_system::ipc::PeerState;

use crate::auth_snow::{MAX_TRUSTED_PEERS, TrustedPeer};

/// How long sync leaves a device alone after its password didn't match
/// (seconds): every try costs both sides a guess-limiter slot. A key change
/// on this device, or the device connecting to us, ends the pause early.
pub const PASSWORD_RETRY: u64 = 5 * 60;

/// address family bytes in the saved form
const FAMILY_V4: u8 = 4;
const FAMILY_V6: u8 = 6;

/// One paired device's entry.
struct Entry {
    /// The device's Noise static public key: its identity (public).
    peer_id: [u8; 32],
    addr: Option<SocketAddr>,
    state: PeerState,
    /// Sync doesn't connect before this moment.
    retry_after: Option<Instant>,
}

/// Every paired device's last address and connection state.
#[derive(Default)]
pub struct PeerBook {
    entries: RwLock<Vec<Entry>>,
    /// Woken when an address changed, so the owner saves the vault.
    pub changed: Notify,
}

/// Constant time, like every key lookup (public keys, but the habit holds).
fn same_key(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.ct_eq(b).into()
}

impl PeerBook {
    /// The entry of `key`, made (empty) if there is none. At most
    /// [`MAX_TRUSTED_PEERS`] entries: the oldest one makes room.
    fn entry<'a>(entries: &'a mut Vec<Entry>, key: &[u8; 32]) -> Option<&'a mut Entry> {
        if !entries.iter().any(|entry| same_key(&entry.peer_id, key)) {
            if entries.len() >= MAX_TRUSTED_PEERS && !entries.is_empty() {
                entries.remove(0);
            }
            entries.push(Entry {
                peer_id: *key,
                addr: None,
                state: PeerState::Unknown,
                retry_after: None,
            });
        }
        entries
            .iter_mut()
            .find(|entry| same_key(&entry.peer_id, key))
    }

    /// `peer` authenticated on a connection with `addr` (where it listens):
    /// remembers the address; the auth password matches. A data password
    /// that differed still does (and its pause holds) until data goes
    /// through again ([`PeerBook::data_ok`]): authenticating says nothing
    /// about `d_key`.
    pub async fn seen(&self, peer: &TrustedPeer, addr: SocketAddr) {
        let moved = {
            let mut entries = self.entries.write().await;
            let Some(entry) = Self::entry(&mut entries, peer.static_key()) else {
                return;
            };
            let moved = entry.addr != Some(addr);
            entry.addr = Some(addr);
            if entry.state != PeerState::DataPasswordDiffers {
                entry.state = PeerState::Ok;
                entry.retry_after = None;
            }
            moved
        };

        if moved {
            self.changed.notify_one();
        }
    }

    /// Data went through `peer`'s `d_key` layer: both passwords match, any
    /// pause ends.
    pub async fn data_ok(&self, peer: &TrustedPeer) {
        let mut entries = self.entries.write().await;
        if let Some(entry) = Self::entry(&mut entries, peer.static_key()) {
            entry.state = PeerState::Ok;
            entry.retry_after = None;
        }
    }

    /// A connection from or to `ip` failed the password confirmation: every
    /// device last seen at `ip` gets [`PeerState::AuthPasswordDiffers`].
    /// Only when we connected there (`we_connected`) is sync to it paused:
    /// anyone can connect to us from some address and fail on purpose, and
    /// that must not stop sync to a paired device. Returns how many devices
    /// that was.
    pub async fn wrong_password_at(&self, ip: IpAddr, we_connected: bool) -> usize {
        let retry_after = Instant::now().checked_add(Duration::from_secs(PASSWORD_RETRY));
        let mut entries = self.entries.write().await;
        let mut count = 0usize;
        for entry in entries
            .iter_mut()
            .filter(|entry| entry.addr.is_some_and(|addr| addr.ip() == ip))
        {
            entry.state = PeerState::AuthPasswordDiffers;
            if we_connected {
                entry.retry_after = retry_after;
            }
            count = count.saturating_add(1);
        }
        drop(entries);
        count
    }

    /// Sets `peer`'s state: a password mismatch pauses sync to it for
    /// [`PASSWORD_RETRY`], anything else doesn't.
    pub async fn set_state(&self, peer: &TrustedPeer, state: PeerState) {
        let retry_after = match state {
            PeerState::AuthPasswordDiffers | PeerState::DataPasswordDiffers => {
                Instant::now().checked_add(Duration::from_secs(PASSWORD_RETRY))
            }
            PeerState::Unknown | PeerState::Ok | PeerState::Unreachable => None,
        };
        let mut entries = self.entries.write().await;
        if let Some(entry) = Self::entry(&mut entries, peer.static_key()) {
            entry.state = state;
            entry.retry_after = retry_after;
        }
    }

    /// `true` if a paired device was last seen at `ip`.
    pub async fn knows_ip(&self, ip: IpAddr) -> bool {
        self.entries
            .read()
            .await
            .iter()
            .any(|entry| entry.addr.is_some_and(|addr| addr.ip() == ip))
    }

    /// `peer`'s state (`Unknown` if it was never contacted).
    pub async fn state(&self, peer: &TrustedPeer) -> PeerState {
        self.entries
            .read()
            .await
            .iter()
            .find(|entry| same_key(&entry.peer_id, peer.static_key()))
            .map_or(PeerState::Unknown, |entry| entry.state)
    }

    /// Where to send sync data: every one of `peers` with a known address
    /// that isn't paused.
    pub async fn targets(&self, peers: &[TrustedPeer]) -> Vec<(TrustedPeer, SocketAddr)> {
        let now = Instant::now();
        let entries = self.entries.read().await;
        peers
            .iter()
            .filter_map(|peer| {
                let entry = entries
                    .iter()
                    .find(|entry| same_key(&entry.peer_id, peer.static_key()))?;
                let paused = entry.retry_after.is_some_and(|after| after > now);
                entry
                    .addr
                    .filter(|_| !paused)
                    .map(|addr| (peer.clone(), addr))
            })
            .collect()
    }

    /// This device's keys changed: what the old ones showed no longer
    /// holds. Password states go back to `Unknown`, pauses end.
    pub async fn keys_changed(&self) {
        let mut entries = self.entries.write().await;
        for entry in entries.iter_mut() {
            if matches!(
                entry.state,
                PeerState::AuthPasswordDiffers | PeerState::DataPasswordDiffers
            ) {
                entry.state = PeerState::Unknown;
            }
            entry.retry_after = None;
        }
    }

    /// Forgets everything about `peer`.
    pub async fn remove(&self, peer: &TrustedPeer) {
        self.entries
            .write()
            .await
            .retain(|entry| !same_key(&entry.peer_id, peer.static_key()));
    }

    /// Forgets everything (reset).
    pub async fn clear(&self) {
        self.entries.write().await.clear();
    }

    /// The saved form of the addresses of `peers` (others are left out):
    /// `count (u16 LE) || count * (x25519 key (32) || family (1, 4 or 6) ||
    /// ip (4 or 16) || port (u16 LE))`.
    pub async fn encode(&self, peers: &[TrustedPeer]) -> Vec<u8> {
        // copied out, so the guard is gone before the buffer is built
        let saved: Vec<([u8; 32], SocketAddr)> = self
            .entries
            .read()
            .await
            .iter()
            .filter(|entry| {
                peers
                    .iter()
                    .any(|peer| same_key(&entry.peer_id, peer.static_key()))
            })
            .filter_map(|entry| entry.addr.map(|addr| (entry.peer_id, addr)))
            .take(MAX_TRUSTED_PEERS)
            .collect();

        let count = u16::try_from(saved.len()).unwrap_or(0);
        // the largest entry: key + family + IPv6 + port
        let mut out = Vec::with_capacity(saved.len().saturating_mul(51).saturating_add(2));
        out.extend_from_slice(&count.to_le_bytes());
        for (key, addr) in saved.iter().take(usize::from(count)) {
            out.extend_from_slice(key.as_slice());
            match addr.ip() {
                IpAddr::V4(ip) => {
                    out.push(FAMILY_V4);
                    out.extend_from_slice(&ip.octets());
                }
                IpAddr::V6(ip) => {
                    out.push(FAMILY_V6);
                    out.extend_from_slice(&ip.octets());
                }
            }
            out.extend_from_slice(&addr.port().to_le_bytes());
        }
        out
    }

    /// Strict inverse of [`PeerBook::encode`]: exact length, known
    /// families, at most [`MAX_TRUSTED_PEERS`], no duplicate keys.
    pub fn decode(bytes: &[u8]) -> Option<Vec<([u8; 32], SocketAddr)>> {
        let (count, mut rest) = bytes.split_first_chunk::<2>()?;
        let count = usize::from(u16::from_le_bytes(*count));
        if count > MAX_TRUSTED_PEERS {
            return None;
        }

        let mut out: Vec<([u8; 32], SocketAddr)> = Vec::with_capacity(count);
        for _ in 0..count {
            let (key, after) = rest.split_first_chunk::<32>()?;
            let (&family, after) = after.split_first()?;
            let (ip, after) = match family {
                FAMILY_V4 => {
                    let (ip, after) = after.split_first_chunk::<4>()?;
                    (IpAddr::from(*ip), after)
                }
                FAMILY_V6 => {
                    let (ip, after) = after.split_first_chunk::<16>()?;
                    (IpAddr::from(*ip), after)
                }
                _ => return None,
            };
            let (port, after) = after.split_first_chunk::<2>()?;

            if out.iter().any(|(saved, _)| same_key(saved, key)) {
                return None;
            }
            out.push((*key, SocketAddr::new(ip, u16::from_le_bytes(*port))));
            rest = after;
        }

        rest.is_empty().then_some(out)
    }

    /// Replaces the book with saved addresses (after unlocking); every
    /// state starts as `Unknown`.
    pub async fn load(&self, saved: Vec<([u8; 32], SocketAddr)>) {
        let mut entries = self.entries.write().await;
        entries.clear();
        entries.extend(
            saved
                .into_iter()
                .take(MAX_TRUSTED_PEERS)
                .map(|(key, addr)| Entry {
                    peer_id: key,
                    addr: Some(addr),
                    state: PeerState::Unknown,
                    retry_after: None,
                }),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(last: u8, port: u16) -> SocketAddr {
        SocketAddr::from(([192, 168, 1, last], port))
    }

    /// Test that an authenticated connection records the address and a fine
    /// state, and only a real move asks for a save
    #[tokio::test]
    async fn test_seen() {
        let book = PeerBook::default();
        let peer = TrustedPeer::for_test(1, "a");

        assert_eq!(book.state(&peer).await, PeerState::Unknown);
        book.seen(&peer, addr(2, 3232)).await;
        assert_eq!(book.state(&peer).await, PeerState::Ok);
        assert_eq!(
            book.targets(std::slice::from_ref(&peer))
                .await
                .first()
                .map(|(_, a)| *a),
            Some(addr(2, 3232))
        );

        // moved: the owner is told (a permit is stored for the next wait)
        tokio::time::timeout(Duration::from_secs(1), book.changed.notified())
            .await
            .unwrap();
        // the same address again: no save needed
        book.seen(&peer, addr(2, 3232)).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(50), book.changed.notified())
                .await
                .is_err()
        );
    }

    /// Test that a wrong password at a device's address marks that device,
    /// pauses sync to it, and a key change or a new connection ends that
    #[tokio::test]
    async fn test_wrong_password_pauses() {
        let book = PeerBook::default();
        let (a, b) = (TrustedPeer::for_test(1, "a"), TrustedPeer::for_test(2, "b"));
        book.seen(&a, addr(2, 3232)).await;
        book.seen(&b, addr(3, 3232)).await;
        let both = [a.clone(), b.clone()];

        // someone connecting to us from a's address and failing: shown, not paused
        assert_eq!(book.wrong_password_at(addr(2, 0).ip(), false).await, 1);
        assert_eq!(book.state(&a).await, PeerState::AuthPasswordDiffers);
        assert_eq!(book.targets(&both).await.len(), 2);

        // we connected there and it failed: paused too
        assert_eq!(book.wrong_password_at(addr(2, 0).ip(), true).await, 1);
        assert_eq!(book.state(&a).await, PeerState::AuthPasswordDiffers);
        assert_eq!(book.state(&b).await, PeerState::Ok);
        // a is paused, b isn't
        let targets = book.targets(&both).await;
        assert_eq!(targets.len(), 1);
        assert_eq!(targets.first().map(|(_, at)| *at), Some(addr(3, 3232)));

        // an address nobody was seen at marks nobody
        assert_eq!(book.wrong_password_at(addr(9, 0).ip(), true).await, 0);

        book.keys_changed().await;
        assert_eq!(book.state(&a).await, PeerState::Unknown);
        assert_eq!(book.targets(&both).await.len(), 2);

        book.set_state(&b, PeerState::DataPasswordDiffers).await;
        assert_eq!(book.targets(&both).await.len(), 1);
        // authenticating again says nothing about the data password
        book.seen(&b, addr(3, 3232)).await;
        assert_eq!(book.state(&b).await, PeerState::DataPasswordDiffers);
        assert_eq!(book.targets(&both).await.len(), 1);
        // data that went through does
        book.data_ok(&b).await;
        assert_eq!(book.state(&b).await, PeerState::Ok);
        assert_eq!(book.targets(&both).await.len(), 2);

        // unreachable is shown, but not paused
        book.set_state(&a, PeerState::Unreachable).await;
        assert_eq!(book.state(&a).await, PeerState::Unreachable);
        assert_eq!(book.targets(&both).await.len(), 2);
    }

    /// Test that devices without an address, and devices not given, are no target
    #[tokio::test]
    async fn test_targets_only_known_and_given() {
        let book = PeerBook::default();
        let (a, b) = (TrustedPeer::for_test(1, "a"), TrustedPeer::for_test(2, "b"));
        book.set_state(&a, PeerState::Unreachable).await;
        book.seen(&b, addr(3, 3232)).await;

        assert!(book.targets(std::slice::from_ref(&a)).await.is_empty());
        assert!(book.targets(&[]).await.is_empty());
        assert_eq!(book.targets(&[a, b]).await.len(), 1);
    }

    /// Test the saved form: round trip (v4 and v6), only the given peers,
    /// and strict decoding
    #[tokio::test]
    async fn test_encode_decode() {
        let book = PeerBook::default();
        let (a, b, c) = (
            TrustedPeer::for_test(1, "a"),
            TrustedPeer::for_test(2, "b"),
            TrustedPeer::for_test(3, "c"),
        );
        let v6 = SocketAddr::new(IpAddr::from([0xfe80, 0, 0, 0, 1, 2, 3, 4]), 4000);
        book.seen(&a, addr(2, 3232)).await;
        book.seen(&b, v6).await;
        book.seen(&c, addr(4, 3232)).await;

        // c was forgotten: not saved
        let bytes = book.encode(&[a.clone(), b.clone()]).await;
        let decoded = PeerBook::decode(&bytes).unwrap();
        assert_eq!(decoded.len(), 2);
        assert!(decoded.contains(&(*a.static_key(), addr(2, 3232))));
        assert!(decoded.contains(&(*b.static_key(), v6)));

        let loaded = PeerBook::default();
        loaded.load(decoded).await;
        assert_eq!(loaded.state(&a).await, PeerState::Unknown);
        assert_eq!(loaded.targets(&[a.clone(), b.clone()]).await.len(), 2);

        // empty list
        assert_eq!(PeerBook::decode(&[0, 0]).unwrap().len(), 0);
        // trailing byte, cut entry, unknown family, duplicate key, too many
        let mut long = bytes.clone();
        long.push(0);
        assert!(PeerBook::decode(&long).is_none());
        assert!(PeerBook::decode(bytes.get(..bytes.len() - 1).unwrap()).is_none());
        let mut family = bytes.clone();
        *family.get_mut(2 + 32).unwrap() = 5;
        assert!(PeerBook::decode(&family).is_none());
        let one = book.encode(std::slice::from_ref(&a)).await;
        let mut twice = vec![2, 0];
        twice.extend_from_slice(one.get(2..).unwrap());
        twice.extend_from_slice(one.get(2..).unwrap());
        assert!(PeerBook::decode(&twice).is_none());
        let too_many = u16::try_from(MAX_TRUSTED_PEERS + 1).unwrap().to_le_bytes();
        assert!(PeerBook::decode(&too_many).is_none());
        assert!(PeerBook::decode(&[]).is_none());
    }

    /// Test that the book never grows beyond the trusted-peer cap
    #[tokio::test]
    async fn test_bounded() {
        let book = PeerBook::default();
        for i in 0..=MAX_TRUSTED_PEERS {
            let mut key = [0u8; 32];
            key[..8].copy_from_slice(&u64::try_from(i).unwrap().to_le_bytes());
            let peer = TrustedPeer::for_test_key(key, "p");
            book.set_state(&peer, PeerState::Unreachable).await;
        }
        assert_eq!(book.entries.read().await.len(), MAX_TRUSTED_PEERS);
    }

    /// Test that forgetting and resetting remove entries
    #[tokio::test]
    async fn test_remove_and_clear() {
        let book = PeerBook::default();
        let (a, b) = (TrustedPeer::for_test(1, "a"), TrustedPeer::for_test(2, "b"));
        book.seen(&a, addr(2, 3232)).await;
        book.seen(&b, addr(3, 3232)).await;
        book.remove(&a).await;
        assert_eq!(book.state(&a).await, PeerState::Unknown);
        assert_eq!(book.state(&b).await, PeerState::Ok);
        book.clear().await;
        assert_eq!(book.state(&b).await, PeerState::Unknown);
    }
}
