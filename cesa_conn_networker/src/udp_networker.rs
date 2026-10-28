//! LAN discovery over UDP broadcast.
//!
//! An announcement only says "a CesaConn device listens at this address".
//! It is deliberately NOT encrypted or authenticated with anything derived
//! from the password: any password-derived value on the wire (e.g. AES-GCM
//! of a known name under `a_key`) lets anyone on the LAN capture one packet
//! and guess the password offline, which defeats SPAKE2. So the result of
//! discovery is only a hint where to connect; whether a device is trusted
//! is decided by the TCP handshake (SPAKE2 + signatures) alone. Replaying or
//! forging announcements can at most make us try a connection that fails.

use core::fmt;
use core::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::time::{Duration, Instant, sleep, timeout_at};
use tracing::{debug, error, info, warn};

use cesa_conn_crypto::crand::random_array;

/// Port announcements are sent to (and listened on).
pub const DISCOVERY_PORT: u16 = 3636;

/// Longest a broadcast or a search may run (seconds).
pub const MAX_BROADCAST_DURATION: u64 = 20;

/* Announcement layout */
/// protocol magic (8)
const MAGIC: &[u8; 8] = b"CESACONN";
/// protocol version (1)
const VERSION: u8 = 1;
/// magic (8) + version (1) + random instance id (16)
const ANNOUNCEMENT_LEN: usize = 8 + 1 + 16;

/// Random id of one running instance, so a device ignores its own broadcasts.
/// Not a secret and not an identity: it changes on every start. Ordered, so
/// two devices that find each other can agree which one connects.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct InstanceId([u8; 16]);

impl InstanceId {
    /// A fresh random id.
    pub fn generate() -> Result<Self, UdpNetworkerErrors> {
        Ok(Self(
            *random_array::<16>().map_err(|_| UdpNetworkerErrors::FailedToGenerateId)?,
        ))
    }
}

/// Errors that can occur during UDP networking operations
#[derive(Debug, PartialEq)]
pub enum UdpNetworkerErrors {
    /// Failed to bind UDP socket to the given address
    FailedToBindSocket,
    /// Failed to enable or disable broadcast mode on the socket
    FailedToSetBroadcastMode,
    /// Failed to send broadcast packet to the network
    FailedToSendBroadcast,
    /// No device announced itself within the given duration
    Timeout,
    /// Failed to receive incoming UDP packet
    FailedToFetchResult,
    /// The OS failed to provide random bytes for the instance id
    FailedToGenerateId,
}

impl fmt::Display for UdpNetworkerErrors {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            UdpNetworkerErrors::FailedToBindSocket => write!(f, "Failed to bind UDP socket"),
            UdpNetworkerErrors::FailedToSetBroadcastMode => {
                write!(f, "Failed to set broadcast mode")
            }
            UdpNetworkerErrors::FailedToSendBroadcast => {
                write!(f, "Failed to send broadcast packet")
            }
            UdpNetworkerErrors::Timeout => write!(f, "Discovery timed out — no device found"),
            UdpNetworkerErrors::FailedToFetchResult => write!(f, "Failed to receive UDP packet"),
            UdpNetworkerErrors::FailedToGenerateId => {
                write!(f, "failed to generate instance id")
            }
        }
    }
}

/// Builds an announcement: magic (8) + version (1) + instance id (16).
fn announcement(id: InstanceId) -> [u8; ANNOUNCEMENT_LEN] {
    let mut packet = [0u8; ANNOUNCEMENT_LEN];

    for (dst, src) in packet
        .iter_mut()
        .zip(MAGIC.iter().chain([VERSION].iter()).chain(id.0.iter()))
    {
        *dst = *src;
    }

    packet
}

/// Parses an announcement. Anything that isn't exactly one is `None`.
fn parse_announcement(packet: &[u8]) -> Option<InstanceId> {
    let packet: &[u8; ANNOUNCEMENT_LEN] = packet.try_into().ok()?;
    let (magic, rest) = packet.split_first_chunk::<8>()?;
    let (version, id) = rest.split_first()?;

    if magic != MAGIC || *version != VERSION {
        return None;
    }

    Some(InstanceId(id.try_into().ok()?))
}

/// Announces this device on the LAN once per second for `duration` seconds
/// (capped at [`MAX_BROADCAST_DURATION`]).
///
/// The announcement carries no secret, see the module docs.
pub async fn udp_broadcast_presence(
    duration: u64,
    id: InstanceId,
) -> Result<(), UdpNetworkerErrors> {
    let duration = duration.min(MAX_BROADCAST_DURATION);
    let packet = announcement(id);
    let destination = SocketAddr::from(([255, 255, 255, 255], DISCOVERY_PORT));

    // Ephemeral port: only the destination port matters for the listener.
    // nosemgrep: cesa.net.bind-all-interfaces
    let socket = UdpSocket::bind("0.0.0.0:0").await.map_err(|e| {
        error!(error = %e, "failed to bind UDP socket for broadcast");
        UdpNetworkerErrors::FailedToBindSocket
    })?;

    // required to send packets to 255.255.255.255
    socket.set_broadcast(true).map_err(|e| {
        error!(error = %e, "failed to enable broadcast mode on UDP socket");
        UdpNetworkerErrors::FailedToSetBroadcastMode
    })?;

    info!(duration, %destination, "broadcasting presence");

    for tick in 0..duration {
        let bytes_sent = socket.send_to(&packet, destination).await.map_err(|e| {
            error!(error = %e, tick, %destination, "failed to send UDP broadcast packet");
            UdpNetworkerErrors::FailedToSendBroadcast
        })?;

        debug!(tick, bytes_sent, "announcement sent");

        sleep(Duration::from_secs(1)).await;
    }

    info!(duration, "broadcast complete");
    Ok(())
}

/// Listens for announcements of OTHER devices for up to `duration` seconds
/// (capped at [`MAX_BROADCAST_DURATION`]) and returns the first sender's address.
///
/// Packets that aren't a valid announcement, and our own (`own_id`), are
/// skipped. The address is only a hint: it is NOT authenticated, the TCP
/// handshake decides trust.
// only the manual test commands use it (the daemon wants every device)
#[cfg(any(test, feature = "test-commands"))]
pub async fn udp_find_broadcaster(
    duration: u64,
    own_id: InstanceId,
) -> Result<SocketAddr, UdpNetworkerErrors> {
    let duration = duration.min(MAX_BROADCAST_DURATION);
    // one deadline for the whole search, junk packets can't extend it
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(duration))
        .ok_or(UdpNetworkerErrors::Timeout)?;

    // Broadcasts only arrive on a wildcard bind.
    // nosemgrep: cesa.net.bind-all-interfaces
    let socket = UdpSocket::bind(("0.0.0.0", DISCOVERY_PORT))
        .await
        .map_err(|e| {
            error!(error = %e, port = DISCOVERY_PORT, "failed to bind UDP socket for discovery");
            UdpNetworkerErrors::FailedToBindSocket
        })?;

    info!(
        timeout_secs = duration,
        "searching for CesaConn devices on network..."
    );

    // one byte bigger than an announcement, so a longer packet is detectable
    let mut buf = [0u8; ANNOUNCEMENT_LEN + 1];

    loop {
        let (len, addr) = timeout_at(deadline, socket.recv_from(&mut buf))
            .await
            .map_err(|_| {
                warn!(
                    timeout_secs = duration,
                    "UDP discovery timed out — no device responded"
                );
                UdpNetworkerErrors::Timeout
            })?
            .map_err(|e| {
                error!(error = %e, "failed to receive UDP packet");
                UdpNetworkerErrors::FailedToFetchResult
            })?;

        match buf.get(..len).and_then(parse_announcement) {
            Some(id) if id == own_id => {
                debug!(%addr, "ignoring our own announcement");
            }
            Some(_) => {
                info!(%addr, "found CesaConn device (unauthenticated hint)");
                return Ok(addr);
            }
            None => {
                debug!(%addr, len, "ignoring packet that isn't an announcement");
            }
        }
    }
}

/// Most devices one [`udp_find_broadcasters`] search reports.
pub const MAX_FOUND_DEVICES: usize = 16;

/// Listens for announcements of OTHER devices for `duration` seconds (capped
/// at [`MAX_BROADCAST_DURATION`]) and returns every distinct instance heard,
/// at most [`MAX_FOUND_DEVICES`]; an empty list if nobody answered.
///
/// Same rules as [`udp_find_broadcaster`]: junk and our own announcements are
/// skipped, one deadline for the whole search, the addresses are only hints.
pub async fn udp_find_broadcasters(
    duration: u64,
    own_id: InstanceId,
) -> Result<Vec<(SocketAddr, InstanceId)>, UdpNetworkerErrors> {
    let duration = duration.min(MAX_BROADCAST_DURATION);
    // one deadline for the whole search, junk packets can't extend it
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(duration))
        .ok_or(UdpNetworkerErrors::Timeout)?;

    // Broadcasts only arrive on a wildcard bind.
    // nosemgrep: cesa.net.bind-all-interfaces
    let socket = UdpSocket::bind(("0.0.0.0", DISCOVERY_PORT))
        .await
        .map_err(|e| {
            error!(error = %e, port = DISCOVERY_PORT, "failed to bind UDP socket for discovery");
            UdpNetworkerErrors::FailedToBindSocket
        })?;

    info!(
        timeout_secs = duration,
        "searching for all CesaConn devices on the network"
    );

    // one byte bigger than an announcement, so a longer packet is detectable
    let mut buf = [0u8; ANNOUNCEMENT_LEN + 1];
    let mut found: Vec<(SocketAddr, InstanceId)> = Vec::new();

    while found.len() < MAX_FOUND_DEVICES {
        let Ok(received) = timeout_at(deadline, socket.recv_from(&mut buf)).await else {
            break;
        };
        let (len, addr) = received.map_err(|e| {
            error!(error = %e, "failed to receive UDP packet");
            UdpNetworkerErrors::FailedToFetchResult
        })?;

        match buf.get(..len).and_then(parse_announcement) {
            Some(id) if id == own_id => debug!(%addr, "ignoring our own announcement"),
            Some(id) if found.iter().any(|(_, known)| *known == id) => {}
            Some(id) => {
                info!(%addr, "found CesaConn device (unauthenticated hint)");
                found.push((addr, id));
            }
            None => debug!(%addr, len, "ignoring packet that isn't an announcement"),
        }
    }

    if found.len() >= MAX_FOUND_DEVICES {
        warn!(
            max = MAX_FOUND_DEVICES,
            "too many devices answered, the search stopped early"
        );
    }

    Ok(found)
}

#[cfg(test)]
// tests bind the fixed discovery port: the guard is held across awaits on
// purpose, so they run one at a time
#[allow(clippy::await_holding_invalid_type)]
mod tests {
    use super::*;

    /// Serialises tests that bind the fixed discovery port.
    fn port_lock() -> &'static tokio::sync::Mutex<()> {
        static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
    }

    /// Sends `packet` to the discovery port on localhost.
    async fn send_local(packet: &[u8]) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket
            .send_to(packet, ("127.0.0.1", DISCOVERY_PORT))
            .await
            .unwrap();
    }

    /// Starts a 2 s search in the background and waits until it is listening.
    async fn search(
        own_id: InstanceId,
    ) -> tokio::task::JoinHandle<Result<SocketAddr, UdpNetworkerErrors>> {
        let handle = tokio::spawn(async move { udp_find_broadcaster(2, own_id).await });
        sleep(Duration::from_millis(100)).await;
        handle
    }

    /// Test that an announcement round-trips through build and parse
    #[test]
    fn test_announcement_roundtrip() {
        let id = InstanceId::generate().unwrap();
        assert_eq!(parse_announcement(&announcement(id)), Some(id));
    }

    /// Test that wrong magic, version or length is rejected
    #[test]
    fn test_parse_rejects_malformed() {
        let id = InstanceId::generate().unwrap();
        let good = announcement(id);

        let mut bad_magic = good;
        bad_magic[0] ^= 0xFF;
        let mut bad_version = good;
        bad_version[8] = VERSION.wrapping_add(1);

        assert_eq!(parse_announcement(&bad_magic), None);
        assert_eq!(parse_announcement(&bad_version), None);
        assert_eq!(parse_announcement(&good[..ANNOUNCEMENT_LEN - 1]), None);
        assert_eq!(parse_announcement(&[good.as_slice(), &[0]].concat()), None);
        assert_eq!(parse_announcement(&[]), None);
    }

    /// Test that the announcement contains nothing but magic, version and id
    #[test]
    fn test_announcement_has_no_secret_material() {
        let packet = announcement(InstanceId([0x42; 16]));

        assert_eq!(&packet[..8], MAGIC);
        assert_eq!(packet[8], VERSION);
        assert_eq!(&packet[9..], &[0x42; 16]);
    }

    /// Test that another device's announcement is found
    #[tokio::test]
    async fn test_finds_other_device() {
        let _guard = port_lock().lock().await;
        let handle = search(InstanceId::generate().unwrap()).await;

        send_local(&announcement(InstanceId::generate().unwrap())).await;

        assert!(handle.await.unwrap().is_ok());
    }

    /// Test that our own announcement and junk are skipped, then a real one found
    #[tokio::test]
    async fn test_skips_own_and_junk() {
        let _guard = port_lock().lock().await;
        let own = InstanceId::generate().unwrap();
        let handle = search(own).await;

        send_local(&announcement(own)).await;
        send_local(b"CesaConn Broadcast").await;
        send_local(&[0u8; 1024]).await;
        sleep(Duration::from_millis(100)).await;
        assert!(!handle.is_finished());

        send_local(&announcement(InstanceId::generate().unwrap())).await;
        assert!(handle.await.unwrap().is_ok());
    }

    /// Test that only junk and our own packets end in Timeout
    #[tokio::test]
    async fn test_only_junk_times_out() {
        let _guard = port_lock().lock().await;
        let own = InstanceId::generate().unwrap();
        let handle = tokio::spawn(async move { udp_find_broadcaster(1, own).await });
        sleep(Duration::from_millis(100)).await;

        send_local(&announcement(own)).await;
        send_local(b"garbage").await;

        assert_eq!(handle.await.unwrap(), Err(UdpNetworkerErrors::Timeout));
    }

    /// Test that a search for all devices reports each other device once and
    /// skips our own announcement and junk
    #[tokio::test]
    async fn test_finds_every_device_once() {
        let _guard = port_lock().lock().await;
        let own = InstanceId::generate().unwrap();
        let handle = tokio::spawn(async move { udp_find_broadcasters(1, own).await });
        sleep(Duration::from_millis(100)).await;

        let (a, b) = (InstanceId([1; 16]), InstanceId([2; 16]));
        for packet in [
            announcement(a),
            announcement(own),
            announcement(a),
            announcement(b),
        ] {
            send_local(&packet).await;
        }
        send_local(b"garbage").await;

        let mut ids: Vec<InstanceId> = handle
            .await
            .unwrap()
            .unwrap()
            .into_iter()
            .map(|(_, id)| id)
            .collect();
        ids.sort();
        assert_eq!(ids, vec![a, b]);
    }

    /// Test that a search nobody answers ends with an empty list, not an error
    #[tokio::test]
    async fn test_find_all_nobody_answers() {
        let _guard = port_lock().lock().await;
        let found = udp_find_broadcasters(1, InstanceId::generate().unwrap()).await;
        assert_eq!(found, Ok(Vec::new()));
    }

    /// Test that every error has a non-empty message
    #[test]
    fn test_error_display() {
        for e in [
            UdpNetworkerErrors::FailedToBindSocket,
            UdpNetworkerErrors::FailedToSetBroadcastMode,
            UdpNetworkerErrors::FailedToSendBroadcast,
            UdpNetworkerErrors::Timeout,
            UdpNetworkerErrors::FailedToFetchResult,
            UdpNetworkerErrors::FailedToGenerateId,
        ] {
            assert!(!e.to_string().is_empty());
        }
    }
}
