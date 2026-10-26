//TODO: add function arg to handle any further actions determined by ActionType in recv_handler
//TODO: remove arc and rwlock for listener and CancellationToken

use core::net::SocketAddr;
use std::fmt;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::select;
use tokio::sync::{RwLock, Semaphore};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use zeroize::Zeroizing;

use crate::auth_snow::{
    AuthSnowErrors, DATA_LAYER_OVERHEAD, DeviceKeypairs, Keys, SecureConnection, Tags, TrustedPeer,
    TrustedPeers, auth_incoming, auth_outgoing,
};

/// Identifies what kind of action/data is being sent in a packet.
/// Encoded as a single byte at position [0] of the init header.
///
/// Using #[repr(u8)] guarantees stable wire discriminants — changing assigned values
/// breaks protocol compatibility with all existing clients and peers.
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum ActionType {
    /// Default/unspecified action — fallback for unknown or generic packets.
    Default = 0x00,
    /// Debug action — used for testing and diagnostics only, not for production data.
    Debug = 0x01,
    /// Pair with the peer (pairing itself happens during authentication).
    /// No data payload is sent for this action.
    ConnectNewDevice = 0x02,
    /// Synchronizes clipboard content between devices.
    ClipboardSync = 0x03,
}

impl ActionType {
    /// Converts a raw u8 wire byte into an ActionType variant.
    ///
    /// Returns None for unknown values rather than panicking — the caller decides
    /// whether to fall back to Default or reject the packet entirely.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::Default),
            0x01 => Some(Self::Debug),
            0x02 => Some(Self::ConnectNewDevice),
            0x03 => Some(Self::ClipboardSync),
            _ => None,
        }
    }
}

/// Init header: action type (1) + payload length as little-endian u64 (8).
const INIT_HEADER_LEN: usize = 9;

/// Upper bound for one data payload declared in the init header (16 MiB).
/// Checked before allocating, the payload itself is sent in chunks.
pub const MAX_DATA_PACKET_LEN: u64 = 16 * 1024 * 1024;

/// How many incoming connections may be handled at the same time.
/// Each one costs SPAKE2 + ML-KEM work before the peer is authenticated,
/// so without a cap a connection flood exhausts CPU, memory and tasks.
pub const MAX_CONCURRENT_CONNECTIONS: usize = 16;

/// A connection that is being authenticated, incoming or outgoing.
pub struct IncomingConnection {
    /// Name shown to the user when pairing (the peer's address until devices
    /// exchange real names).
    pub name: String,
    pub stream: TcpStream,
}

impl IncomingConnection {
    /// Wraps a connected stream; the peer's address doubles as its display name.
    pub fn new(stream: TcpStream, peer_addr: SocketAddr) -> Self {
        Self {
            name: peer_addr.to_string(),
            stream,
        }
    }
}

/// Everything the TCP layer needs to authenticate peers, shared by all connections.
#[derive(Clone)]
pub struct NetworkerContext {
    /// Shared `a_key` / `d_key`.
    pub keys: Arc<RwLock<Keys>>,
    /// This device's long-term identity.
    pub device_keypairs: Arc<DeviceKeypairs>,
    /// Devices we have paired with.
    pub trusted_peers: TrustedPeers,
    /// Asks the user to confirm a new device (name, handshake hash).
    pub pair_fallback: fn(&String, &[u8; 32]) -> bool,
}

/// One packet received from an authenticated peer.
pub struct ReceivedPacket {
    /// The device that sent it.
    pub peer: TrustedPeer,
    /// What the data is for.
    pub action_type: ActionType,
    /// Decrypted payload, wiped on drop.
    pub data: Zeroizing<Vec<u8>>,
}

/// All errors that can occur in the TCP networker layer.
/// Each variant maps to a specific failure point in the connection lifecycle.
#[derive(Debug, PartialEq)]
pub enum TcpNetworkerErrors {
    /// `listener.accept()` failed — OS-level socket error, usually non-recoverable.
    FailedToAcceptConnection,
    /// Reading or decrypting a message from the authenticated peer failed or timed out.
    FailedToReadFromStream,
    /// Authentication failed — wrong a_key, rejected pairing, bad signature or I/O error.
    FailedToAuthenticate,
    /// Could not read local address from the listener — needed for logging.
    FailedToGetLocalAddr,
    /// TcpStream::connect failed — target unreachable, refused, or timed out.
    FailedToConnect,
    /// Encrypting or sending a message to the authenticated peer failed or timed out.
    FailedToWriteToStream,
    /// Data packet larger than `MAX_DATA_PACKET_LEN` — rejected before allocating / sending.
    DataTooLarge,
    /// The payload failed the `d_key` layer: the peer uses a different data password.
    FailedToDecryptData,
}

impl fmt::Display for TcpNetworkerErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TcpNetworkerErrors::FailedToAcceptConnection => {
                write!(f, "failed to accept connection")
            }
            TcpNetworkerErrors::FailedToReadFromStream => write!(f, "failed to read from stream"),
            TcpNetworkerErrors::FailedToAuthenticate => write!(f, "authentication failed"),
            TcpNetworkerErrors::FailedToGetLocalAddr => write!(f, "failed to get local address"),
            TcpNetworkerErrors::FailedToConnect => write!(f, "failed to make a connection request"),
            TcpNetworkerErrors::FailedToWriteToStream => write!(f, "failed to write to stream"),
            TcpNetworkerErrors::DataTooLarge => write!(f, "declared data packet is too large"),
            TcpNetworkerErrors::FailedToDecryptData => {
                write!(f, "failed to decrypt data (different d_key?)")
            }
        }
    }
}

/// Reads one tagged message of exactly `len` payload bytes from the peer.
async fn read_secure(
    secure_connection: &mut SecureConnection,
    len: usize,
    peer_addr: SocketAddr,
) -> Result<Zeroizing<Vec<u8>>, TcpNetworkerErrors> {
    // +1 for the tag byte that read() removes
    let mut buffer = Zeroizing::new(vec![0u8; len.saturating_add(1)]);

    secure_connection
        .read_timeout(&mut buffer, Tags::Regular)
        .await
        .map_err(|e| {
            warn!(%peer_addr, error = %e, "failed to read message from peer");
            TcpNetworkerErrors::FailedToReadFromStream
        })?;

    Ok(buffer)
}

/// Handles a single incoming TCP connection after it has been accepted by `recv`.
///
/// 1. authentication ([`auth_incoming`]): SPAKE2 + hybrid KEX + Noise +
///    ML-DSA signatures; unknown devices are paired only if both users confirm
/// 2. <- init header (9 bytes): [0] = ActionType, [1..9] = encrypted payload
///    length (u64 LE, plaintext + [`DATA_LAYER_OVERHEAD`]), 0 = no payload
/// 3. <- payload, encrypted with a key derived from `d_key`, in chunks
///    ([`SecureConnection::read_encrypted`])
///
/// Everything after step 1 is encrypted and authenticated by the Noise
/// transport; the payload additionally by the `d_key` layer.
///
/// Returns `Ok(None)` if the peer doesn't know `a_key` (closed without data).
pub async fn recv_handler(
    incoming_connection: (TcpStream, SocketAddr),
    context: NetworkerContext,
) -> Result<Option<ReceivedPacket>, TcpNetworkerErrors> {
    let (stream, peer_addr) = incoming_connection;

    debug!(%peer_addr, "recv_handler started, authenticating peer");

    let context_keys = context.keys.clone();

    // 1. authentication
    let Some((mut secure_connection, peer)) = auth_incoming(
        context.keys,
        &context.device_keypairs,
        context.trusted_peers,
        IncomingConnection::new(stream, peer_addr),
        context.pair_fallback,
    )
    .await
    .map_err(|e| {
        warn!(%peer_addr, error = %e, "authentication of incoming connection failed");
        TcpNetworkerErrors::FailedToAuthenticate
    })?
    else {
        warn!(%peer_addr, "peer failed SPAKE2 confirmation (wrong a_key), closing");
        return Ok(None);
    };

    debug!(%peer_addr, peer = %peer.name(), "peer authenticated, reading init header");

    // 2. init header
    let init_buf = read_secure(&mut secure_connection, INIT_HEADER_LEN, peer_addr).await?;

    let (action_byte, size_bytes) = init_buf
        .split_first()
        .ok_or(TcpNetworkerErrors::FailedToReadFromStream)?;

    let size = u64::from_le_bytes(
        size_bytes
            .try_into()
            .map_err(|_| TcpNetworkerErrors::FailedToReadFromStream)?,
    );

    // the size comes from the peer: bound it before allocating
    if size > MAX_DATA_PACKET_LEN.saturating_add(DATA_LAYER_OVERHEAD as u64) {
        warn!(%peer_addr, size, max = MAX_DATA_PACKET_LEN, "declared data packet too large, rejecting");
        return Err(TcpNetworkerErrors::DataTooLarge);
    }

    let size = usize::try_from(size).map_err(|_| TcpNetworkerErrors::DataTooLarge)?;

    // unknown values fall back to Default, so newer peers stay compatible
    let action_type = ActionType::from_u8(*action_byte).unwrap_or(ActionType::Default);

    // 3. payload (size bounded above)
    let data = if size == 0 {
        Zeroizing::new(Vec::new())
    } else {
        // cloned, so the read lock is released before any network I/O
        let d_key = context_keys.read().await.d_key.clone();

        secure_connection
            .read_encrypted(size, &d_key, Tags::Regular)
            .await
            .map_err(|e| {
                warn!(%peer_addr, error = %e, "failed to read data packet from peer");
                match e {
                    AuthSnowErrors::FailedToDecryptData => TcpNetworkerErrors::FailedToDecryptData,
                    _ => TcpNetworkerErrors::FailedToReadFromStream,
                }
            })?
    };

    info!(
        %peer_addr,
        peer = %peer.name(),
        action_type = ?action_type,
        data_len = data.len(),
        "received packet successfully"
    );

    Ok(Some(ReceivedPacket {
        peer,
        action_type,
        data,
    }))
}

/// Accepts incoming connections in a loop, spawning a `recv_handler` task for each one.
/// Stops cleanly when the cancellation token is triggered.
///
/// Each connection runs in its own `tokio::spawn` task — `accept()` returns immediately
/// to service the next connection without waiting for the handler to finish.
/// The `select!` inside each spawned task drops the handler instantly if cancelled.
pub async fn recv(
    listener: &TcpListener,
    context: NetworkerContext,
    cancellation_token: CancellationToken,
) -> Result<(), TcpNetworkerErrors> {
    let local_addr = listener.local_addr().map_err(|e| {
        error!(error = %e, "failed to read local address from TCP listener");
        TcpNetworkerErrors::FailedToGetLocalAddr
    })?;

    info!(%local_addr, "TCP listener started, waiting for incoming connections");

    let connection_slots = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));

    loop {
        let cloned_token = cancellation_token.clone();
        let context_clone = context.clone();

        // select! races accept() against the cancellation signal — whichever fires first wins.
        let incoming_connection = select! {
            _ = cloned_token.cancelled() => {
                info!(%local_addr, "cancellation token fired, shutting down TCP listener");
                break;
            },
            result = listener.accept() => {
                result.map_err(|e| {
                    error!(%local_addr, error = %e, "listener.accept() failed — OS-level socket error");
                    TcpNetworkerErrors::FailedToAcceptConnection
                })?
            }
        };

        let peer_addr = incoming_connection.1;

        // no free slot: close right away instead of queueing, so a flood
        // can't pile up waiting tasks
        let Ok(slot) = connection_slots.clone().try_acquire_owned() else {
            warn!(%local_addr, %peer_addr, max = MAX_CONCURRENT_CONNECTIONS, "too many connections, dropping");
            drop(incoming_connection);
            continue;
        };

        info!(%local_addr, %peer_addr, "accepted incoming TCP connection, spawning recv_handler");

        tokio::spawn(async move {
            // held until the handler finishes, frees the slot on drop
            let _slot = slot;

            select! {
                _ = cloned_token.cancelled() => {
                    info!(%peer_addr, "cancellation token fired mid-handler, dropping recv_handler task");
                },
                result = recv_handler(incoming_connection, context_clone) => {
                    match result {
                        // TODO: hand the packet to the action handler (see TODO at the top)
                        Ok(Some(packet)) => debug!(
                            %peer_addr,
                            peer = %packet.peer.name(),
                            action_type = ?packet.action_type,
                            data_len = packet.data.len(),
                            "recv_handler completed successfully"
                        ),
                        Ok(None) => debug!(%peer_addr, "recv_handler closed without data"),
                        Err(e) => error!(%peer_addr, error = %e, "recv_handler returned an error"),
                    }
                }
            }
        });
    }

    Ok(())
}

/// Handles a single outgoing TCP connection — authenticates with the peer, then
/// sends one packet.
///
/// 1. authentication ([`auth_outgoing`]), pairs the device if needed
/// 2. -> init header (9 bytes): [0] = ActionType, [1..9] = encrypted payload length (u64 LE)
/// 3. -> payload encrypted with the `d_key` layer, in chunks
///    ([`SecureConnection::write_encrypted`]), if not empty
///
/// `ConnectNewDevice` only pairs: it sends a header with length 0 and no payload.
pub async fn connect_handler(
    context: NetworkerContext,
    connect_addr: SocketAddr,
    outgoing_connection: TcpStream,
    action_type: ActionType,
    data: Zeroizing<Vec<u8>>,
) -> Result<(), TcpNetworkerErrors> {
    debug!(%connect_addr, action_type = ?action_type, data_len = data.len(), "connect_handler started");

    let size = u64::try_from(data.len()).map_err(|_| TcpNetworkerErrors::DataTooLarge)?;

    // checked before authenticating, so we don't pair just to fail afterwards
    if size > MAX_DATA_PACKET_LEN {
        warn!(%connect_addr, size, max = MAX_DATA_PACKET_LEN, "data packet too large, not sending");
        return Err(TcpNetworkerErrors::DataTooLarge);
    }

    // cloned, so the read lock is released before any network I/O
    let d_key = context.keys.read().await.d_key.clone();

    // 1. authentication
    let Some((mut secure_connection, peer)) = auth_outgoing(
        context.keys,
        &context.device_keypairs,
        context.trusted_peers,
        IncomingConnection::new(outgoing_connection, connect_addr),
        context.pair_fallback,
    )
    .await
    .map_err(|e| {
        warn!(%connect_addr, error = %e, "authentication of outgoing connection failed");
        TcpNetworkerErrors::FailedToAuthenticate
    })?
    else {
        warn!(%connect_addr, "server failed SPAKE2 confirmation (wrong a_key), closing");
        return Err(TcpNetworkerErrors::FailedToAuthenticate);
    };

    debug!(%connect_addr, peer = %peer.name(), "peer authenticated, sending init header");

    // what goes on the wire: plaintext + nonce + GCM tag, or nothing
    let size = if action_type == ActionType::ConnectNewDevice || size == 0 {
        0
    } else {
        size.saturating_add(DATA_LAYER_OVERHEAD as u64)
    };

    // 2. init header
    let mut init_data = Vec::with_capacity(INIT_HEADER_LEN);

    init_data.push(action_type as u8);
    init_data.extend_from_slice(&size.to_le_bytes());

    secure_connection
        .write_timeout(&init_data, Tags::Regular)
        .await
        .map_err(|e| {
            error!(%connect_addr, error = %e, "failed to send init header");
            TcpNetworkerErrors::FailedToWriteToStream
        })?;

    // 3. payload
    if size > 0 {
        secure_connection
            .write_encrypted(&data, &d_key, Tags::Regular)
            .await
            .map_err(|e| {
                error!(%connect_addr, error = %e, "failed to send data packet");
                TcpNetworkerErrors::FailedToWriteToStream
            })?;
    }

    info!(%connect_addr, peer = %peer.name(), action_type = ?action_type, data_len = size, "connect_handler completed successfully");
    Ok(())
}

/// Initiates an outgoing TCP connection to `connect_addr` and passes it to `connect_handler`.
///
/// Returns immediately after the TCP connect resolves — auth and data transfer happen
/// inside a spawned task concurrently with other work. Cancellation is checked both
/// before the TCP connect and mid-handler inside the spawned task.
pub async fn connect(
    context: NetworkerContext,
    cancellation_token: CancellationToken,
    connect_addr: SocketAddr,
    action_type: ActionType,
    data: Zeroizing<Vec<u8>>,
) -> Result<(), TcpNetworkerErrors> {
    let cloned_token = cancellation_token.clone();

    debug!(%connect_addr, action_type = ?action_type, "connect: initiating TCP connection");

    // Race TcpStream::connect against cancellation — if cancelled before the TCP
    // handshake completes, return immediately without touching the network.
    let outgoing_connection = select! {
        _ = cloned_token.cancelled() => {
            info!(%connect_addr, "cancellation token fired before TCP connect, aborting");
            return Ok(());
        },
        result = TcpStream::connect(connect_addr) => {
            result.map_err(|e| {
                error!(%connect_addr, error = %e, "TcpStream::connect failed — target unreachable, refused, or timed out");
                TcpNetworkerErrors::FailedToConnect
            })?
        }
    };

    info!(%connect_addr, "TCP connection established, spawning connect_handler");

    tokio::spawn(async move {
        select! {
            _ = cloned_token.cancelled() => {
                info!(%connect_addr, "cancellation token fired mid-handler, dropping connect_handler task");
            },
            result = connect_handler(
                context,
                connect_addr,
                outgoing_connection,
                action_type,
                data,
            ) => {
                match result {
                    Ok(()) => debug!(%connect_addr, "connect_handler completed successfully"),
                    Err(e) => error!(%connect_addr, error = %e, "connect_handler returned an error"),
                }
            }
        }
    });

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_snow::{AuthKey, DataKey};

    const TEST_A_KEY: [u8; 32] = [0xAB; 32];
    const TEST_D_KEY: [u8; 32] = [0xCD; 32];

    /// Pairing callback that accepts every device.
    fn accept_all(_name: &String, _hash: &[u8; 32]) -> bool {
        true
    }

    /// Pairing callback that rejects every device.
    fn reject_all(_name: &String, _hash: &[u8; 32]) -> bool {
        false
    }

    /// Fresh device identity + empty trusted list.
    fn make_context(
        a_key: [u8; 32],
        pair_fallback: fn(&String, &[u8; 32]) -> bool,
    ) -> NetworkerContext {
        make_context_d(a_key, TEST_D_KEY, pair_fallback)
    }

    /// Like [`make_context`] with an explicit `d_key`.
    fn make_context_d(
        a_key: [u8; 32],
        d_key: [u8; 32],
        pair_fallback: fn(&String, &[u8; 32]) -> bool,
    ) -> NetworkerContext {
        NetworkerContext {
            keys: Arc::new(RwLock::new(Keys::new(
                AuthKey::from_bytes(&a_key),
                DataKey::from_bytes(&d_key),
            ))),
            device_keypairs: Arc::new(DeviceKeypairs::generate().unwrap()),
            trusted_peers: Arc::new(RwLock::new(Vec::new())),
            pair_fallback,
        }
    }

    /// Runs one client -> server exchange over localhost and returns both results.
    async fn exchange(
        server: NetworkerContext,
        client: NetworkerContext,
        action_type: ActionType,
        data: &[u8],
    ) -> (
        Result<Option<ReceivedPacket>, TcpNetworkerErrors>,
        Result<(), TcpNetworkerErrors>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let incoming = listener.accept().await.unwrap();
            recv_handler(incoming, server).await
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let client_result = connect_handler(
            client,
            addr,
            stream,
            action_type,
            Zeroizing::new(data.to_vec()),
        )
        .await;

        (server_task.await.unwrap(), client_result)
    }

    /// Test that every known wire byte maps to its ActionType
    #[test]
    fn test_action_type_from_u8_all_known() {
        assert_eq!(ActionType::from_u8(0x00), Some(ActionType::Default));
        assert_eq!(ActionType::from_u8(0x01), Some(ActionType::Debug));
        assert_eq!(
            ActionType::from_u8(0x02),
            Some(ActionType::ConnectNewDevice)
        );
        assert_eq!(ActionType::from_u8(0x03), Some(ActionType::ClipboardSync));
    }

    /// Test that unknown wire bytes are rejected instead of panicking
    #[test]
    fn test_action_type_from_u8_unknown() {
        for v in 0x04..=0xFF {
            assert_eq!(ActionType::from_u8(v), None);
        }
    }

    /// Test that every error has a non-empty message
    #[test]
    fn test_all_error_display_non_empty() {
        let errors = [
            TcpNetworkerErrors::FailedToAcceptConnection,
            TcpNetworkerErrors::FailedToReadFromStream,
            TcpNetworkerErrors::FailedToAuthenticate,
            TcpNetworkerErrors::FailedToGetLocalAddr,
            TcpNetworkerErrors::FailedToConnect,
            TcpNetworkerErrors::FailedToWriteToStream,
            TcpNetworkerErrors::DataTooLarge,
            TcpNetworkerErrors::FailedToDecryptData,
        ];

        for e in errors {
            assert!(!e.to_string().is_empty());
        }
    }

    /// Test that two new devices pair and the payload arrives intact
    #[tokio::test]
    async fn test_pair_and_send_debug_packet() {
        let server = make_context(TEST_A_KEY, accept_all);
        let client = make_context(TEST_A_KEY, accept_all);
        let server_peers = server.trusted_peers.clone();
        let client_peers = client.trusted_peers.clone();

        let (server_result, client_result) =
            exchange(server, client, ActionType::Debug, b"Hello CesaSec!").await;

        assert_eq!(client_result, Ok(()));

        let packet = server_result.unwrap().unwrap();

        assert_eq!(packet.action_type, ActionType::Debug);
        assert_eq!(packet.data.as_slice(), b"Hello CesaSec!");
        assert_eq!(server_peers.read().await.len(), 1);
        assert_eq!(client_peers.read().await.len(), 1);
    }

    /// Test that a multi-chunk payload (1 MiB) arrives intact
    #[tokio::test]
    async fn test_large_payload_chunked() {
        let data: Vec<u8> = (0..=250u8).cycle().take(1024 * 1024).collect();

        let (server_result, client_result) = exchange(
            make_context(TEST_A_KEY, accept_all),
            make_context(TEST_A_KEY, accept_all),
            ActionType::ClipboardSync,
            &data,
        )
        .await;

        assert_eq!(client_result, Ok(()));
        assert_eq!(
            server_result.unwrap().unwrap().data.as_slice(),
            data.as_slice()
        );
    }

    /// Test that the client refuses to send more than MAX_DATA_PACKET_LEN
    #[tokio::test]
    async fn test_oversized_payload_rejected_by_sender() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let stream = TcpStream::connect(addr).await.unwrap();

        let result = connect_handler(
            make_context(TEST_A_KEY, accept_all),
            addr,
            stream,
            ActionType::ClipboardSync,
            Zeroizing::new(vec![
                0u8;
                usize::try_from(MAX_DATA_PACKET_LEN)
                    .unwrap()
                    .saturating_add(1)
            ]),
        )
        .await;

        assert_eq!(result, Err(TcpNetworkerErrors::DataTooLarge));
    }

    /// Test that ConnectNewDevice pairs and delivers an empty payload
    #[tokio::test]
    async fn test_connect_new_device_pairs_without_payload() {
        let server = make_context(TEST_A_KEY, accept_all);
        let server_peers = server.trusted_peers.clone();

        let (server_result, client_result) = exchange(
            server,
            make_context(TEST_A_KEY, accept_all),
            ActionType::ConnectNewDevice,
            b"ignored",
        )
        .await;

        assert_eq!(client_result, Ok(()));

        let packet = server_result.unwrap().unwrap();

        assert_eq!(packet.action_type, ActionType::ConnectNewDevice);
        assert!(packet.data.is_empty());
        assert_eq!(server_peers.read().await.len(), 1);
    }

    /// Test that a peer with a different a_key gets nothing and pairs nothing
    #[tokio::test]
    async fn test_wrong_a_key_rejected() {
        let server = make_context(TEST_A_KEY, accept_all);
        let server_peers = server.trusted_peers.clone();

        let (server_result, client_result) = exchange(
            server,
            make_context([0x11; 32], accept_all),
            ActionType::Debug,
            b"secret",
        )
        .await;

        assert!(server_result.unwrap().is_none());
        assert_eq!(client_result, Err(TcpNetworkerErrors::FailedToAuthenticate));
        assert!(server_peers.read().await.is_empty());
    }

    /// Test that a rejected pairing delivers no data and saves no peer on either side
    #[tokio::test]
    async fn test_rejected_pairing_sends_nothing() {
        let server = make_context(TEST_A_KEY, reject_all);
        let client = make_context(TEST_A_KEY, accept_all);
        let server_peers = server.trusted_peers.clone();
        let client_peers = client.trusted_peers.clone();

        let (server_result, client_result) =
            exchange(server, client, ActionType::Debug, b"secret").await;

        assert_eq!(
            server_result.err(),
            Some(TcpNetworkerErrors::FailedToAuthenticate)
        );
        assert_eq!(client_result, Err(TcpNetworkerErrors::FailedToAuthenticate));
        assert!(server_peers.read().await.is_empty());
        assert!(client_peers.read().await.is_empty());
    }

    /// Test that a peer with the right a_key but a different d_key can pair,
    /// but its data is rejected
    #[tokio::test]
    async fn test_different_d_key_data_rejected() {
        let (server_result, client_result) = exchange(
            make_context(TEST_A_KEY, accept_all),
            make_context_d(TEST_A_KEY, [0x22; 32], accept_all),
            ActionType::ClipboardSync,
            b"clipboard",
        )
        .await;

        assert_eq!(client_result, Ok(()));
        assert_eq!(
            server_result.err(),
            Some(TcpNetworkerErrors::FailedToDecryptData)
        );
    }

    /// Test that connections past MAX_CONCURRENT_CONNECTIONS are closed at once
    #[tokio::test]
    async fn test_connection_limit_drops_extra_connections() {
        use tokio::io::AsyncReadExt;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let token = CancellationToken::new();
        let server_token = token.clone();
        let context = make_context(TEST_A_KEY, accept_all);

        let server = tokio::spawn(async move { recv(&listener, context, server_token).await });

        // occupy every slot: each handler is waiting for our SPAKE2 message
        let mut held = Vec::new();

        for _ in 0..MAX_CONCURRENT_CONNECTIONS {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            let mut first = [0u8; 1];

            // the server speaks first (SPAKE2), so this proves the slot is taken
            stream.read_exact(&mut first).await.unwrap();
            held.push(stream);
        }

        // one more: closed without a single byte
        let mut extra = TcpStream::connect(addr).await.unwrap();
        let mut buf = Vec::new();
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            extra.read_to_end(&mut buf),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(read, 0);

        token.cancel();
        assert!(server.await.unwrap().is_ok());
    }

    /// Test that cancelling before connect() returns Ok(()) without connecting
    #[tokio::test]
    async fn test_connect_cancels_before_connecting() {
        let token = CancellationToken::new();

        token.cancel();

        let unreachable: SocketAddr = "127.0.0.1:19999".parse().unwrap();
        let result = connect(
            make_context(TEST_A_KEY, accept_all),
            token,
            unreachable,
            ActionType::Debug,
            Zeroizing::new(Vec::new()),
        )
        .await;

        assert!(result.is_ok());
    }

    /// Test that connecting to a closed port returns FailedToConnect
    #[tokio::test]
    async fn test_connect_to_closed_port_fails() {
        // bind then drop, so the port is closed when connect runs
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let result = connect(
            make_context(TEST_A_KEY, accept_all),
            CancellationToken::new(),
            addr,
            ActionType::Debug,
            Zeroizing::new(Vec::new()),
        )
        .await;

        assert_eq!(result.unwrap_err(), TcpNetworkerErrors::FailedToConnect);
    }
}
