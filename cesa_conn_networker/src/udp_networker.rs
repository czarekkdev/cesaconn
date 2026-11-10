//! LAN discovery over UDP broadcast.
//!
//! An announcement goes to `255.255.255.255` and to the broadcast address of
//! every other IPv4 interface that has one: the OS sends `255.255.255.255`
//! out of one interface only (the default route), so a second network on
//! the same machine (a VM's shared network, Ethernet next to Wi-Fi) would
//! never hear it. Point-to-point interfaces (VPN tunnels) have no broadcast:
//! devices behind one are reached by address, not by discovery.
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
use core::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::task::JoinSet;
use tokio::time::{Duration, Instant, sleep, timeout, timeout_at};
use tracing::{debug, error, info, warn};

use cesa_conn_crypto::crand::random_array;

/// Port announcements are sent to (and listened on).
pub const DISCOVERY_PORT: u16 = 3636;

/// Longest a broadcast or a search may run (seconds).
pub const MAX_BROADCAST_DURATION: u64 = 20;

/// Most destinations one announcement goes to: `255.255.255.255` plus one
/// per interface, so a machine with many interfaces can't make it a flood.
const MAX_BROADCAST_TARGETS: usize = 16;

/// Longest one send of an announcement may take (seconds).
const SEND_TIMEOUT: u64 = 1;

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

/// One IPv4 address of an interface, as far as broadcasting cares.
#[derive(Debug, Clone, Copy)]
struct Ipv4Interface {
    /// The interface's address.
    ip: Ipv4Addr,
    /// Its netmask.
    netmask: Ipv4Addr,
    /// The broadcast address the OS reports, if any.
    broadcast: Option<Ipv4Addr>,
    /// Up, broadcast-capable, not loopback, not point-to-point.
    usable: bool,
}

/// Where one announcement goes: `255.255.255.255` first, then the
/// broadcast address of every usable interface (the reported one, or the
/// network's last address), each once, at most [`MAX_BROADCAST_TARGETS`].
/// A network of /31 or /32 has no broadcast; a reported address outside
/// the interface's own network, or one that isn't a plain unicast-range
/// address, is skipped.
fn broadcast_targets(interfaces: &[Ipv4Interface]) -> Vec<SocketAddr> {
    let mut targets = vec![SocketAddr::from((Ipv4Addr::BROADCAST, DISCOVERY_PORT))];

    for interface in interfaces.iter().filter(|interface| interface.usable) {
        let mask = u32::from(interface.netmask);
        if mask.count_ones() >= 31 {
            continue;
        }
        let network = u32::from(interface.ip) & mask;
        let address = interface
            .broadcast
            .unwrap_or_else(|| Ipv4Addr::from(network | !mask));

        // only an address of the interface's own network
        let own_network = u32::from(address) & mask == network;
        if !own_network
            || address.is_loopback()
            || address.is_unspecified()
            || address.is_multicast()
            || address == Ipv4Addr::BROADCAST
        {
            continue;
        }

        let target = SocketAddr::from((address, DISCOVERY_PORT));
        if !targets.contains(&target) {
            targets.push(target);
        }
    }

    targets.truncate(MAX_BROADCAST_TARGETS);
    targets
}

/// This machine's IPv4 interface addresses; empty if the OS won't say.
#[cfg(unix)]
fn ipv4_interfaces() -> Vec<Ipv4Interface> {
    use nix::net::if_::InterfaceFlags;

    let addresses = match nix::ifaddrs::getifaddrs() {
        Ok(addresses) => addresses,
        Err(e) => {
            warn!(error = %e, "can't list the network interfaces: announcing on the default route only");
            return Vec::new();
        }
    };

    let ipv4 = |address: Option<nix::sys::socket::SockaddrStorage>| {
        address.and_then(|address| address.as_sockaddr_in().map(|address| address.ip()))
    };

    addresses
        .filter_map(|address| {
            let flags = address.flags;
            Some(Ipv4Interface {
                ip: ipv4(address.address)?,
                netmask: ipv4(address.netmask)?,
                broadcast: ipv4(address.broadcast),
                usable: flags.contains(InterfaceFlags::IFF_UP)
                    && flags.contains(InterfaceFlags::IFF_BROADCAST)
                    && !flags.contains(InterfaceFlags::IFF_LOOPBACK)
                    && !flags.contains(InterfaceFlags::IFF_POINTOPOINT),
            })
        })
        .collect()
}

/// Whether `ip` is an address of one of this machine's interfaces, so
/// connecting there would reach this device itself. Loopback is never
/// "own" here (the IPC refuses typed loopback addresses before; tests use
/// it for two daemons on one machine). `false` if the OS won't say.
#[cfg(unix)]
pub fn is_own_address(ip: core::net::IpAddr) -> bool {
    if ip.is_loopback() {
        return false;
    }
    let Ok(addresses) = nix::ifaddrs::getifaddrs() else {
        return false;
    };
    addresses
        .filter_map(|address| address.address)
        .filter_map(|address| {
            address
                .as_sockaddr_in()
                .map(|v4| core::net::IpAddr::V4(v4.ip()))
                .or_else(|| {
                    address
                        .as_sockaddr_in6()
                        .map(|v6| core::net::IpAddr::V6(v6.ip()))
                })
        })
        .any(|own| own == ip)
}

/// Not listed elsewhere yet: no address is known to be this machine's.
#[cfg(not(unix))]
pub fn is_own_address(_ip: core::net::IpAddr) -> bool {
    false
}

/// Not listed elsewhere yet: `255.255.255.255` only.
#[cfg(not(unix))]
fn ipv4_interfaces() -> Vec<Ipv4Interface> {
    Vec::new()
}

/// Sends one announcement to `destination`, bounded by [`SEND_TIMEOUT`];
/// `true` if it went out. A failure is only logged: other networks may work.
async fn send_one(
    socket: &UdpSocket,
    packet: [u8; ANNOUNCEMENT_LEN],
    destination: SocketAddr,
    tick: u64,
) -> bool {
    let send = socket.send_to(&packet, destination);
    match timeout(Duration::from_secs(SEND_TIMEOUT), send).await {
        Ok(Ok(_)) => true,
        Ok(Err(e)) => {
            debug!(error = %e, tick, %destination, "announcement not sent there");
            false
        }
        Err(_) => {
            debug!(tick, %destination, "announcement send timed out");
            false
        }
    }
}

/// Announces this device on the LAN once per second for `duration` seconds
/// (capped at [`MAX_BROADCAST_DURATION`]), on every interface (see the
/// module docs). The interfaces are listed again every second, so one
/// that comes up (a VM started, a cable plugged in) is announced on too.
///
/// The announcement carries no secret, see the module docs.
pub async fn udp_broadcast_presence(
    duration: u64,
    id: InstanceId,
) -> Result<(), UdpNetworkerErrors> {
    let duration = duration.min(MAX_BROADCAST_DURATION);
    let packet = announcement(id);

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

    info!(duration, "broadcasting presence");

    // shared by the sends of one tick, which run at once
    let socket = Arc::new(socket);

    for tick in 0..duration {
        let targets = broadcast_targets(&ipv4_interfaces());
        let (first, rest) = targets
            .split_first()
            .ok_or(UdpNetworkerErrors::FailedToSendBroadcast)?;

        // 255.255.255.255 first, then every interface at once: one slow or
        // refusing network (down, no route) neither stops nor delays the
        // others, so a tick takes at most two SEND_TIMEOUTs, not one per target
        let mut sent = usize::from(send_one(&socket, packet, *first, tick).await);
        let mut sends = JoinSet::new();
        for destination in rest.iter().copied() {
            let socket = socket.clone();
            sends.spawn(async move { send_one(&socket, packet, destination, tick).await });
        }
        while let Some(done) = sends.join_next().await {
            if matches!(done, Ok(true)) {
                sent = sent.saturating_add(1);
            }
        }
        if sent == 0 {
            error!(
                tick,
                targets = targets.len(),
                "failed to send the announcement anywhere"
            );
            return Err(UdpNetworkerErrors::FailedToSendBroadcast);
        }

        debug!(tick, targets = targets.len(), sent, "announcement sent");

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
/// at [`MAX_BROADCAST_DURATION`]) and returns one entry per sending IP (the
/// first instance heard from it), at most [`MAX_FOUND_DEVICES`]; an empty
/// list if nobody answered.
///
/// Per IP, because only the IP is used: a flood of made-up ids from one
/// address can't fill the list and push real devices out. It keeps
/// listening until the deadline either way, so the search always takes
/// `duration` (no early end to race for).
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
    let mut full = false;

    loop {
        let Ok(received) = timeout_at(deadline, socket.recv_from(&mut buf)).await else {
            break;
        };
        let (len, addr) = received.map_err(|e| {
            error!(error = %e, "failed to receive UDP packet");
            UdpNetworkerErrors::FailedToFetchResult
        })?;

        match buf.get(..len).and_then(parse_announcement) {
            Some(id) if id == own_id => debug!(%addr, "ignoring our own announcement"),
            Some(_) if found.iter().any(|(known, _)| known.ip() == addr.ip()) => {}
            Some(_) if found.len() >= MAX_FOUND_DEVICES => full = true,
            Some(id) => {
                info!(%addr, "found CesaConn device (unauthenticated hint)");
                found.push((addr, id));
            }
            None => debug!(%addr, len, "ignoring packet that isn't an announcement"),
        }
    }

    if full {
        warn!(
            max = MAX_FOUND_DEVICES,
            "more devices answered than one search keeps, ignored the rest"
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

    /// Test that a search for all devices reports each sending address once
    /// (many ids from one address are one device, so a flood of made-up ids
    /// can't fill the list) and skips our own announcement and junk
    #[tokio::test]
    async fn test_finds_each_address_once() {
        let _guard = port_lock().lock().await;
        let own = InstanceId::generate().unwrap();
        let handle = tokio::spawn(async move { udp_find_broadcasters(1, own).await });
        sleep(Duration::from_millis(100)).await;

        // all from 127.0.0.1: the first real one counts, the flood doesn't
        send_local(&announcement(own)).await;
        send_local(b"garbage").await;
        let first = InstanceId([1; 16]);
        send_local(&announcement(first)).await;
        for byte in 2..=40u8 {
            send_local(&announcement(InstanceId([byte; 16]))).await;
        }

        let found = handle.await.unwrap().unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].1, first);
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

    fn iface(ip: [u8; 4], prefix: u32, broadcast: Option<[u8; 4]>, usable: bool) -> Ipv4Interface {
        Ipv4Interface {
            ip: Ipv4Addr::from(ip),
            netmask: Ipv4Addr::from(
                32u32
                    .checked_sub(prefix)
                    .and_then(|shift| u32::MAX.checked_shl(shift))
                    .unwrap_or(0),
            ),
            broadcast: broadcast.map(Ipv4Addr::from),
            usable,
        }
    }

    fn target(ip: [u8; 4]) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::from(ip), DISCOVERY_PORT))
    }

    /// Test that an announcement goes to 255.255.255.255 and to every
    /// usable interface's broadcast address once (a Mac on Wi-Fi with a
    /// VM's shared network), computed when the OS reports none
    #[test]
    fn test_broadcast_targets_every_interface() {
        let targets = broadcast_targets(&[
            // Wi-Fi /20 with its broadcast reported
            iface([172, 17, 243, 179], 20, Some([172, 17, 255, 255]), true),
            // the VM's shared network /24, none reported: computed
            iface([10, 211, 55, 2], 24, None, true),
            // a second address on the same network: no duplicate
            iface([10, 211, 55, 3], 24, Some([10, 211, 55, 255]), true),
        ]);

        assert_eq!(
            targets,
            vec![
                target([255, 255, 255, 255]),
                target([172, 17, 255, 255]),
                target([10, 211, 55, 255]),
            ]
        );
    }

    /// Test that loopback, down, point-to-point (VPN) interfaces, /31 and
    /// /32 networks and a reported broadcast outside the interface's own
    /// network get nothing beyond 255.255.255.255
    #[test]
    fn test_broadcast_targets_skips_unusable() {
        let targets = broadcast_targets(&[
            iface([127, 0, 0, 1], 8, None, false),
            iface([192, 168, 1, 5], 24, Some([192, 168, 1, 255]), false),
            iface([10, 8, 0, 2], 32, None, true),
            iface([10, 9, 0, 0], 31, None, true),
            iface([192, 168, 2, 5], 24, Some([8, 8, 8, 8]), true),
            iface([192, 168, 3, 5], 24, Some([224, 0, 0, 1]), true),
            // flags the OS got wrong: loopback, multicast or 0.0.0.0 networks
            iface([127, 0, 0, 1], 8, None, true),
            iface([224, 1, 1, 1], 24, None, true),
            iface([0, 0, 0, 1], 24, Some([0, 0, 0, 0]), true),
        ]);

        assert_eq!(targets, vec![target([255, 255, 255, 255])]);
        assert!(broadcast_targets(&[]).len() == 1);
    }

    /// Test that a machine with very many interfaces can't make one
    /// announcement a flood
    #[test]
    fn test_broadcast_targets_bounded() {
        let many: Vec<Ipv4Interface> = (0..=255u8)
            .map(|i| iface([10, i, 0, 1], 24, None, true))
            .collect();

        let targets = broadcast_targets(&many);
        assert_eq!(targets.len(), MAX_BROADCAST_TARGETS);
        assert_eq!(targets.first(), Some(&target([255, 255, 255, 255])));
    }

    /// Test that the OS's interface list is read, with loopback marked not
    /// usable
    #[cfg(unix)]
    #[test]
    fn test_ipv4_interfaces_lists_loopback_unusable() {
        let interfaces = ipv4_interfaces();
        let loopback = interfaces
            .iter()
            .find(|interface| interface.ip == Ipv4Addr::LOCALHOST)
            .unwrap();
        assert!(!loopback.usable);
    }

    /// Test that this machine's own LAN address counts as its own, while
    /// loopback (left to the IPC) and an address of nobody here don't
    #[cfg(unix)]
    #[test]
    fn test_is_own_address() {
        use core::net::IpAddr;

        assert!(!is_own_address(IpAddr::from(Ipv4Addr::LOCALHOST)));
        // TEST-NET-1: never a real interface's address
        assert!(!is_own_address(IpAddr::from([192, 0, 2, 1])));

        let lan = ipv4_interfaces()
            .into_iter()
            .find(|interface| interface.usable && !interface.ip.is_link_local());
        if let Some(lan) = lan {
            assert!(is_own_address(IpAddr::V4(lan.ip)));
        }
    }
}
