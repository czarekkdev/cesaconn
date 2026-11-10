use core::net::SocketAddr;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::select;
use tokio::sync::{RwLock, Semaphore, mpsc, oneshot};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use zeroize::Zeroizing;

use cesa_conn_system::ipc::PeerState;

use crate::auth_snow::{
    AuthSnowErrors, Authenticated, DATA_LAYER_OVERHEAD, DataKey, DeviceKeypairs, Keys, Pairing,
    SecureConnection, Tags, TrustedPeer, TrustedPeers, auth_incoming, auth_outgoing,
};
use crate::clip_sync::{CLIP_MAX_WIRE_LEN, CLIP_MIN_WIRE_LEN, DataAck};
use crate::guess_limiter::GuessLimiter;
use crate::peer_book::PeerBook;

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
    /// A clipboard update (`clip_sync`) through the `d_key` layer; the
    /// receiver answers one [`DataAck`] byte.
    ClipboardSync = 0x03,
    /// A joining device asks for the group's `d_salt` on the connection
    /// that just paired it; the member answers `d_salt (32)` through Noise
    /// only (the joiner has no `d_key` yet). Header length must be 0.
    GroupSalt = 0x04,
    /// "Still the same passwords?": [`HELLO_PAYLOAD`] through the `d_key`
    /// layer, answered with one [`DataAck`] byte. Sent to the paired devices
    /// when networking starts and after a key change, so a password that
    /// differs shows at once and the devices learn each other's addresses.
    Hello = 0x05,
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
            0x04 => Some(Self::GroupSalt),
            0x05 => Some(Self::Hello),
            _ => None,
        }
    }
}

/// TCP port devices listen on (and connect to; discovery only gives the IP).
pub const TCP_PORT: u16 = 3232;

/// The payload of [`ActionType::Hello`]: fixed, public bytes; only the
/// `d_key` layer around them matters.
pub const HELLO_PAYLOAD: &[u8; 8] = b"CESAHELO";

/// How long the receiver waits for the daemon to apply a clipboard update
/// before it answers `Ignored` (seconds); below [`crate::auth_snow::TIMEOUT`],
/// so the answer reaches a sender that waits that long.
const APPLY_TIMEOUT: u64 = 2;

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
    /// Asks the user to confirm a new device (name, pairing code).
    pub pairing: Pairing,
    /// Counts wrong passwords per source and locks guessers out.
    pub guess_limiter: Arc<GuessLimiter>,
    /// The group's `d_salt` while this member's invite window is open,
    /// `None` otherwise (see [`ActionType::GroupSalt`]).
    pub salt_offer: SaltOffer,
    /// Where the paired devices were last seen and what connecting showed.
    pub peer_book: Arc<PeerBook>,
    /// The port paired devices listen on (an incoming connection's own
    /// port is random): [`TCP_PORT`], other ports in tests.
    pub peer_port: u16,
    /// Where received clipboard updates go (`None`: not taken, `Ignored`).
    pub clipboard: ClipSink,
}

/// A received clipboard update on its way to the daemon, which answers
/// whether it was applied.
pub struct ClipDelivery {
    /// The device that sent it (authenticated).
    pub peer: TrustedPeer,
    /// The decrypted update (`clip_sync` format), wiped on drop.
    pub payload: Zeroizing<Vec<u8>>,
    /// The daemon's answer; dropped unanswered = `Ignored`.
    pub answer: oneshot::Sender<DataAck>,
}

/// The daemon's inbox for clipboard updates (bounded, never waited on).
pub type ClipSink = Option<mpsc::Sender<ClipDelivery>>;

/// The `d_salt` a member hands to devices that join during its invite window.
pub type SaltOffer = Arc<RwLock<Option<Zeroizing<[u8; 32]>>>>;

/// Length of a `GroupSalt` answer: the 32-byte `d_salt`.
const GROUP_SALT_LEN: usize = 32;

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
    /// The peer is locked out after too many wrong passwords ([`GuessLimiter`]).
    LockedOut,
    /// `GroupSalt` outside an invite window, or not on the connection that
    /// just paired the two devices.
    NotInvited,
    /// The password check (SPAKE2 confirmation) failed: this device and the
    /// peer use different auth passwords.
    WrongPassword,
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
            TcpNetworkerErrors::LockedOut => {
                write!(f, "peer is locked out after too many wrong passwords")
            }
            TcpNetworkerErrors::NotInvited => write!(
                f,
                "group salt only goes to a device paired just now, in an invite window"
            ),
            TcpNetworkerErrors::WrongPassword => {
                write!(f, "the password check failed (different auth passwords)")
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

    // locked out for guessing the password: no handshake at all
    if context.guess_limiter.is_locked(peer_addr.ip()).await {
        warn!(%peer_addr, "peer is locked out after wrong passwords, closing");
        return Err(TcpNetworkerErrors::LockedOut);
    }

    debug!(%peer_addr, "recv_handler started, authenticating peer");

    let context_keys = context.keys.clone();
    let salt_offer = context.salt_offer.clone();

    // 1. authentication
    let Some(Authenticated {
        connection: mut secure_connection,
        peer,
        newly_paired,
    }) = auth_incoming(
        context.keys,
        &context.device_keypairs,
        context.trusted_peers,
        IncomingConnection::new(stream, peer_addr),
        &context.pairing,
    )
    .await
    .map_err(|e| {
        warn!(%peer_addr, error = %e, "authentication of incoming connection failed");
        TcpNetworkerErrors::FailedToAuthenticate
    })?
    else {
        // the peer sent a wrong confirmation value: one password guess
        warn!(%peer_addr, "peer failed SPAKE2 confirmation (wrong a_key), closing");
        context.guess_limiter.record_failure(peer_addr.ip()).await;
        // shown on the paired device last seen there (a hint, see peer_book)
        context
            .peer_book
            .wrong_password_at(peer_addr.ip(), false)
            .await;
        return Ok(None);
    };

    context.guess_limiter.record_success(peer_addr.ip()).await;
    // it listens on the fixed port, not on the one it connected from
    context
        .peer_book
        .seen(&peer, SocketAddr::new(peer_addr.ip(), context.peer_port))
        .await;

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

    // data that is answered: a hello, a clipboard update
    if matches!(action_type, ActionType::Hello | ActionType::ClipboardSync) {
        let key = context_keys.read().await.d_key.clone();
        return receive_answered(
            &mut secure_connection,
            DataRequest {
                peer,
                action_type,
                size,
                peer_addr,
            },
            &key,
            &context.peer_book,
            &context.clipboard,
        )
        .await
        .map(Some);
    }

    // a joiner asking for d_salt: no payload, the answer goes back instead
    if action_type == ActionType::GroupSalt {
        if size != 0 {
            warn!(%peer_addr, size, "GroupSalt with a payload, rejecting");
            return Err(TcpNetworkerErrors::DataTooLarge);
        }
        send_group_salt(&mut secure_connection, newly_paired, &salt_offer, peer_addr).await?;

        return Ok(Some(ReceivedPacket {
            peer,
            action_type,
            data: Zeroizing::new(Vec::new()),
        }));
    }

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

/// What [`receive_answered`] is about.
struct DataRequest {
    peer: TrustedPeer,
    action_type: ActionType,
    /// Declared length on the wire, `d_key` layer included (not bounded yet).
    size: usize,
    peer_addr: SocketAddr,
}

/// The wire length a data action must have: `Hello` exactly, a clipboard
/// update within its bounds. Checked before allocating.
fn answered_len_ok(action_type: ActionType, size: usize) -> bool {
    match action_type {
        ActionType::Hello => size == HELLO_PAYLOAD.len().saturating_add(DATA_LAYER_OVERHEAD),
        ActionType::ClipboardSync => (CLIP_MIN_WIRE_LEN..=CLIP_MAX_WIRE_LEN).contains(&size),
        ActionType::Default
        | ActionType::Debug
        | ActionType::ConnectNewDevice
        | ActionType::GroupSalt => false,
    }
}

/// Receiver side of `Hello` / `ClipboardSync`:
/// 1. <- the payload through the `d_key` layer (length bounded first)
/// 2. -> one [`DataAck`] byte through Noise
///
/// A payload that fails the `d_key` layer means the data passwords differ:
/// the peer is marked ([`PeerState::DataPasswordDiffers`]) and told so,
/// instead of a silent close. A clipboard update goes to the daemon, which
/// decides whether it is applied.
async fn receive_answered(
    secure_connection: &mut SecureConnection,
    request: DataRequest,
    d_key: &DataKey,
    peer_book: &PeerBook,
    clipboard: &ClipSink,
) -> Result<ReceivedPacket, TcpNetworkerErrors> {
    let DataRequest {
        peer,
        action_type,
        size,
        peer_addr,
    } = request;

    // 1. the payload, bounded before allocating
    if !answered_len_ok(action_type, size) {
        warn!(%peer_addr, size, action_type = ?action_type, "data packet of a wrong size, rejecting");
        return Err(TcpNetworkerErrors::DataTooLarge);
    }

    let data = match secure_connection
        .read_encrypted(size, d_key, Tags::Regular)
        .await
    {
        Ok(data) => data,
        Err(AuthSnowErrors::FailedToDecryptData) => {
            warn!(%peer_addr, peer = %peer.name(), "data failed the d_key layer: the data passwords differ");
            peer_book
                .set_state(&peer, PeerState::DataPasswordDiffers)
                .await;
            send_ack(secure_connection, DataAck::DataKeyDiffers, peer_addr).await?;
            return Err(TcpNetworkerErrors::FailedToDecryptData);
        }
        Err(e) => {
            warn!(%peer_addr, error = %e, "failed to read data packet from peer");
            return Err(TcpNetworkerErrors::FailedToReadFromStream);
        }
    };

    // it read our d_key layer: the data passwords match
    peer_book.data_ok(&peer).await;

    // 2. the answer
    let (ack, data) = if action_type == ActionType::ClipboardSync {
        // the update moves to the daemon; nothing is kept here
        let ack = deliver_clip(clipboard, &peer, data).await;
        (ack, Zeroizing::new(Vec::new()))
    } else if data.as_slice() == HELLO_PAYLOAD.as_slice() {
        // public constant bytes: nothing for timing to reveal
        (DataAck::Applied, data)
    } else {
        (DataAck::Ignored, data)
    };
    send_ack(secure_connection, ack, peer_addr).await?;

    info!(%peer_addr, peer = %peer.name(), action_type = ?action_type, ack = ?ack, "answered data packet");
    Ok(ReceivedPacket {
        peer,
        action_type,
        data,
    })
}

/// Hands a clipboard update to the daemon and waits (briefly) for its
/// answer. A full or missing inbox, or no answer in time, is `Ignored`.
async fn deliver_clip(
    clipboard: &ClipSink,
    peer: &TrustedPeer,
    payload: Zeroizing<Vec<u8>>,
) -> DataAck {
    let Some(sink) = clipboard else {
        return DataAck::Ignored;
    };
    let (answer, reply) = oneshot::channel();
    let delivery = ClipDelivery {
        peer: peer.clone(),
        payload,
        answer,
    };
    // full: dropped (and wiped) at once, never queued behind others
    if sink.try_send(delivery).is_err() {
        return DataAck::Ignored;
    }
    match timeout(Duration::from_secs(APPLY_TIMEOUT), reply).await {
        Ok(Ok(ack)) => ack,
        _ => DataAck::Ignored,
    }
}

/// Sends the one-byte answer to a data packet.
async fn send_ack(
    secure_connection: &mut SecureConnection,
    ack: DataAck,
    peer_addr: SocketAddr,
) -> Result<(), TcpNetworkerErrors> {
    secure_connection
        .write_timeout(&[ack as u8], Tags::Regular)
        .await
        .map_err(|e| {
            warn!(%peer_addr, error = %e, "failed to answer the data packet");
            TcpNetworkerErrors::FailedToWriteToStream
        })
}

/// Member side of [`ActionType::GroupSalt`]: sends `d_salt` through Noise,
/// only on the connection that just paired the two devices and only while
/// the invite window offers it. Anyone else gets nothing: an already paired
/// peer doesn't need it, and outside the window nobody was invited.
async fn send_group_salt(
    secure_connection: &mut SecureConnection,
    newly_paired: bool,
    salt_offer: &SaltOffer,
    peer_addr: SocketAddr,
) -> Result<(), TcpNetworkerErrors> {
    // copied under the guard, which is dropped before any network I/O
    let offer = salt_offer.read().await.clone();

    let Some(d_salt) = offer.filter(|_| newly_paired) else {
        warn!(%peer_addr, newly_paired, "group salt asked for outside an invite or by a known peer, refusing");
        return Err(TcpNetworkerErrors::NotInvited);
    };

    secure_connection
        .write_chunked(d_salt.as_slice(), Tags::Regular)
        .await
        .map_err(|e| {
            warn!(%peer_addr, error = %e, "failed to send the group salt");
            TcpNetworkerErrors::FailedToWriteToStream
        })?;

    info!(%peer_addr, "sent the group salt to the device paired just now");
    Ok(())
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
    let Authenticated {
        connection: mut secure_connection,
        peer,
        ..
    } = authenticate_outgoing(context, connect_addr, outgoing_connection).await?;

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

/// The client side of authentication with the guess limiter around it:
/// refuses a locked-out server, counts failed confirmations against it.
async fn authenticate_outgoing(
    context: NetworkerContext,
    connect_addr: SocketAddr,
    outgoing_connection: TcpStream,
) -> Result<Authenticated, TcpNetworkerErrors> {
    // a fake server gets one password guess from our confirmation value per
    // connection, so servers that keep failing are locked out as well
    if context.guess_limiter.is_locked(connect_addr.ip()).await {
        warn!(%connect_addr, "server is locked out after failed confirmations, not connecting");
        return Err(TcpNetworkerErrors::LockedOut);
    }

    let guess_limiter = context.guess_limiter.clone();
    let peer_book = context.peer_book.clone();

    // a full handshake: boxed, so the future isn't kept on the caller's stack
    let authenticated = Box::pin(auth_outgoing(
        context.keys,
        &context.device_keypairs,
        context.trusted_peers,
        IncomingConnection::new(outgoing_connection, connect_addr),
        &context.pairing,
    ))
    .await;

    let authenticated = match authenticated {
        Ok(authenticated) => authenticated,
        Err(e) => {
            // after we sent our confirmation value, any failure (wrong value,
            // the server hanging up or stalling) may have been a guess against it
            if matches!(
                e,
                AuthSnowErrors::FailedToConfirmMutualAuthSpake2 | AuthSnowErrors::HandshakeTimeout
            ) {
                guess_limiter.record_failure(connect_addr.ip()).await;
            }
            warn!(%connect_addr, error = %e, "authentication of outgoing connection failed");
            // the server hung up on our confirmation value: it didn't
            // accept our password (an honest server closes right there)
            if e == AuthSnowErrors::FailedToConfirmMutualAuthSpake2 {
                peer_book.wrong_password_at(connect_addr.ip(), true).await;
                return Err(TcpNetworkerErrors::WrongPassword);
            }
            return Err(TcpNetworkerErrors::FailedToAuthenticate);
        }
    };

    let Some(authenticated) = authenticated else {
        warn!(%connect_addr, "server failed SPAKE2 confirmation (wrong a_key), closing");
        guess_limiter.record_failure(connect_addr.ip()).await;
        peer_book.wrong_password_at(connect_addr.ip(), true).await;
        return Err(TcpNetworkerErrors::WrongPassword);
    };

    guess_limiter.record_success(connect_addr.ip()).await;
    peer_book.seen(&authenticated.peer, connect_addr).await;

    Ok(authenticated)
}

/// Sends `Hello` or a clipboard update to a paired device and reads its
/// answer:
/// 1. authentication ([`auth_outgoing`]) that never pairs: only a device
///    both sides know gets data
/// 2. -> init header: action, length (payload + [`DATA_LAYER_OVERHEAD`])
/// 3. -> the payload through the `d_key` layer
/// 4. <- one [`DataAck`] byte through Noise
///
/// Who answered and what: `DataKeyDiffers` marks the peer
/// ([`PeerState::DataPasswordDiffers`]); a failed password check marks the
/// devices last seen at `connect_addr` ([`TcpNetworkerErrors::WrongPassword`]).
pub async fn send_answered(
    context: NetworkerContext,
    connect_addr: SocketAddr,
    outgoing_connection: TcpStream,
    action_type: ActionType,
    payload: &[u8],
) -> Result<(TrustedPeer, DataAck), TcpNetworkerErrors> {
    let size = payload.len().saturating_add(DATA_LAYER_OVERHEAD);
    if !answered_len_ok(action_type, size) {
        warn!(%connect_addr, size, action_type = ?action_type, "data packet of a wrong size, not sending");
        return Err(TcpNetworkerErrors::DataTooLarge);
    }

    let d_key = context.keys.read().await.d_key.clone();
    let peer_book = context.peer_book.clone();
    // sync never pairs: a device that forgot us gets nothing and no prompt
    let context = NetworkerContext {
        pairing: Pairing::refuse_all(),
        ..context
    };

    // 1. authentication
    let Authenticated {
        connection: mut secure_connection,
        peer,
        newly_paired,
    } = authenticate_outgoing(context, connect_addr, outgoing_connection).await?;
    if newly_paired {
        // can't happen: every pairing request is refused above
        return Err(TcpNetworkerErrors::FailedToAuthenticate);
    }

    // 2. init header
    let wire_len = u64::try_from(size).map_err(|_| TcpNetworkerErrors::DataTooLarge)?;
    let mut init_data = Vec::with_capacity(INIT_HEADER_LEN);
    init_data.push(action_type as u8);
    init_data.extend_from_slice(&wire_len.to_le_bytes());

    secure_connection
        .write_timeout(&init_data, Tags::Regular)
        .await
        .map_err(|e| {
            warn!(%connect_addr, error = %e, "failed to send init header");
            TcpNetworkerErrors::FailedToWriteToStream
        })?;

    // 3. payload
    secure_connection
        .write_encrypted(payload, &d_key, Tags::Regular)
        .await
        .map_err(|e| {
            warn!(%connect_addr, error = %e, "failed to send data packet");
            TcpNetworkerErrors::FailedToWriteToStream
        })?;

    // 4. the answer (an older build sends none: a read error)
    let answer = read_secure(&mut secure_connection, 1, connect_addr).await?;
    let ack = answer
        .first()
        .copied()
        .and_then(DataAck::from_u8)
        .filter(|_| answer.len() == 1)
        .ok_or(TcpNetworkerErrors::FailedToReadFromStream)?;

    if ack == DataAck::DataKeyDiffers {
        warn!(%connect_addr, peer = %peer.name(), "the device couldn't read our data: the data passwords differ");
        peer_book
            .set_state(&peer, PeerState::DataPasswordDiffers)
            .await;
    } else {
        // it read our d_key layer: the data passwords match
        peer_book.data_ok(&peer).await;
    }

    debug!(%connect_addr, peer = %peer.name(), action_type = ?action_type, ack = ?ack, "data packet answered");
    Ok((peer, ack))
}

/// Joiner side of [`ActionType::GroupSalt`]: authenticates (the user pairs
/// the devices), asks for the group's `d_salt` and reads it.
///
/// 1. authentication ([`auth_outgoing`]); must pair the devices just now
/// 2. -> init header: `GroupSalt`, length 0
/// 3. <- `d_salt (32)` through Noise
///
/// The salt is only taken from the connection whose pairing the user just
/// confirmed: a peer we knew already could otherwise swap the data salt.
pub async fn join_handler(
    context: NetworkerContext,
    connect_addr: SocketAddr,
    outgoing_connection: TcpStream,
) -> Result<(TrustedPeer, Zeroizing<[u8; 32]>), TcpNetworkerErrors> {
    // 1. authentication
    let Authenticated {
        connection: mut secure_connection,
        peer,
        newly_paired,
    } = authenticate_outgoing(context, connect_addr, outgoing_connection).await?;

    if !newly_paired {
        warn!(%connect_addr, "the device was paired already: not taking a group salt from it");
        return Err(TcpNetworkerErrors::NotInvited);
    }

    // 2. init header, no payload
    let mut init_data = Vec::with_capacity(INIT_HEADER_LEN);
    init_data.push(ActionType::GroupSalt as u8);
    init_data.extend_from_slice(&0u64.to_le_bytes());

    secure_connection
        .write_timeout(&init_data, Tags::Regular)
        .await
        .map_err(|e| {
            warn!(%connect_addr, error = %e, "failed to ask for the group salt");
            TcpNetworkerErrors::FailedToWriteToStream
        })?;

    // 3. exactly 32 bytes
    let received = secure_connection
        .read_chunked(GROUP_SALT_LEN, Tags::Regular)
        .await
        .map_err(|e| {
            warn!(%connect_addr, error = %e, "no group salt from the device");
            TcpNetworkerErrors::FailedToReadFromStream
        })?;

    let mut d_salt = Zeroizing::new([0u8; GROUP_SALT_LEN]);
    let bytes = received
        .get(..GROUP_SALT_LEN)
        .filter(|_| received.len() == GROUP_SALT_LEN)
        .ok_or(TcpNetworkerErrors::FailedToReadFromStream)?;
    d_salt.copy_from_slice(bytes);

    info!(%connect_addr, peer = %peer.name(), "received the group salt");
    Ok((peer, d_salt))
}

/// Initiates an outgoing TCP connection to `connect_addr` and passes it to `connect_handler`.
///
/// Returns immediately after the TCP connect resolves — auth and data transfer happen
/// inside a spawned task concurrently with other work. Cancellation is checked both
/// before the TCP connect and mid-handler inside the spawned task.
// only the manual test commands use it (the daemon waits for each result)
#[cfg(any(test, feature = "test-commands"))]
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
#[allow(clippy::large_futures)] // full handshakes in tests, stack size doesn't matter
mod tests {
    use super::*;
    use crate::auth_snow::{AuthKey, DataKey};

    const TEST_A_KEY: [u8; 32] = [0xAB; 32];
    const TEST_D_KEY: [u8; 32] = [0xCD; 32];

    /// The user accepts every new device.
    const ACCEPT_ALL: bool = true;
    /// The user rejects every new device.
    const REJECT_ALL: bool = false;

    /// Fresh device identity + empty trusted list.
    fn make_context(a_key: [u8; 32], accept: bool) -> NetworkerContext {
        make_context_d(a_key, TEST_D_KEY, accept)
    }

    /// Like [`make_context`] with an explicit `d_key`.
    fn make_context_d(a_key: [u8; 32], d_key: [u8; 32], accept: bool) -> NetworkerContext {
        NetworkerContext {
            keys: Arc::new(RwLock::new(Keys::new(
                AuthKey::from_bytes(&a_key),
                &[0x5A; 32],
                DataKey::from_bytes(&d_key),
            ))),
            device_keypairs: Arc::new(DeviceKeypairs::generate().unwrap()),
            trusted_peers: Arc::new(RwLock::new(Vec::new())),
            pairing: Pairing::answer_all(accept),
            guess_limiter: Arc::new(GuessLimiter::new()),
            salt_offer: SaltOffer::default(),
            peer_book: Arc::default(),
            peer_port: TCP_PORT,
            clipboard: None,
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
        assert_eq!(ActionType::from_u8(0x04), Some(ActionType::GroupSalt));
        assert_eq!(ActionType::from_u8(0x05), Some(ActionType::Hello));
    }

    /// Test that unknown wire bytes are rejected instead of panicking
    #[test]
    fn test_action_type_from_u8_unknown() {
        for v in 0x06..=0xFF {
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
            TcpNetworkerErrors::LockedOut,
            TcpNetworkerErrors::NotInvited,
            TcpNetworkerErrors::WrongPassword,
        ];

        for e in errors {
            assert!(!e.to_string().is_empty());
        }
    }

    /// Test that two new devices pair and the payload arrives intact
    #[tokio::test]
    async fn test_pair_and_send_debug_packet() {
        let server = make_context(TEST_A_KEY, ACCEPT_ALL);
        let client = make_context(TEST_A_KEY, ACCEPT_ALL);
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
            make_context(TEST_A_KEY, ACCEPT_ALL),
            make_context(TEST_A_KEY, ACCEPT_ALL),
            ActionType::Debug,
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
            make_context(TEST_A_KEY, ACCEPT_ALL),
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
        let server = make_context(TEST_A_KEY, ACCEPT_ALL);
        let server_peers = server.trusted_peers.clone();

        let (server_result, client_result) = exchange(
            server,
            make_context(TEST_A_KEY, ACCEPT_ALL),
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

    const D_SALT: [u8; 32] = [0xD5; 32];

    /// Runs one join (client asks for the group salt) against a server and
    /// returns both results.
    async fn join_exchange(
        server: NetworkerContext,
        client: NetworkerContext,
    ) -> (
        Result<Option<ReceivedPacket>, TcpNetworkerErrors>,
        Result<(TrustedPeer, Zeroizing<[u8; 32]>), TcpNetworkerErrors>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let incoming = listener.accept().await.unwrap();
            recv_handler(incoming, server).await
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let client_result = join_handler(client, addr, stream).await;

        (server_task.await.unwrap(), client_result)
    }

    /// Test that a device paired just now during an invite window gets
    /// exactly the offered d_salt
    #[tokio::test]
    async fn test_group_salt_to_new_device_in_invite() {
        let server = make_context(TEST_A_KEY, ACCEPT_ALL);
        *server.salt_offer.write().await = Some(Zeroizing::new(D_SALT));

        let (server_result, client_result) =
            join_exchange(server, make_context(TEST_A_KEY, ACCEPT_ALL)).await;

        assert_eq!(*client_result.unwrap().1, D_SALT);
        let packet = server_result.unwrap().unwrap();
        assert_eq!(packet.action_type, ActionType::GroupSalt);
    }

    /// Test that without an invite window the salt is never sent
    #[tokio::test]
    async fn test_group_salt_refused_without_invite() {
        let (server_result, client_result) = join_exchange(
            make_context(TEST_A_KEY, ACCEPT_ALL),
            make_context(TEST_A_KEY, ACCEPT_ALL),
        )
        .await;

        assert_eq!(server_result.err(), Some(TcpNetworkerErrors::NotInvited));
        assert_eq!(
            client_result.err(),
            Some(TcpNetworkerErrors::FailedToReadFromStream)
        );
    }

    /// Test that a peer paired before gets no salt, even in an invite window,
    /// and that a joiner doesn't ask a peer it already knew
    #[tokio::test]
    async fn test_group_salt_only_on_the_pairing_connection() {
        let server = make_context(TEST_A_KEY, ACCEPT_ALL);
        let client = make_context(TEST_A_KEY, ACCEPT_ALL);
        *server.salt_offer.write().await = Some(Zeroizing::new(D_SALT));

        // pair them first
        let (_, paired) = exchange(
            server.clone(),
            client.clone(),
            ActionType::ConnectNewDevice,
            b"",
        )
        .await;
        assert_eq!(paired, Ok(()));

        // the joiner side refuses to ask a peer it knew already
        let (_, client_result) = join_exchange(server.clone(), client.clone()).await;
        assert_eq!(client_result.err(), Some(TcpNetworkerErrors::NotInvited));

        // and the member side refuses a peer it knew already: a raw request
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let incoming = listener.accept().await.unwrap();
            recv_handler(incoming, server).await
        });
        let stream = TcpStream::connect(addr).await.unwrap();
        let sent = connect_handler(
            client,
            addr,
            stream,
            ActionType::GroupSalt,
            Zeroizing::new(Vec::new()),
        )
        .await;
        assert_eq!(sent, Ok(()));
        assert_eq!(
            server_task.await.unwrap().err(),
            Some(TcpNetworkerErrors::NotInvited)
        );
    }

    /// Test that a GroupSalt request with a payload is refused
    #[tokio::test]
    async fn test_group_salt_with_payload_refused() {
        let server = make_context(TEST_A_KEY, ACCEPT_ALL);
        *server.salt_offer.write().await = Some(Zeroizing::new(D_SALT));

        let (server_result, _) = exchange(
            server,
            make_context(TEST_A_KEY, ACCEPT_ALL),
            ActionType::GroupSalt,
            b"x",
        )
        .await;

        assert_eq!(server_result.err(), Some(TcpNetworkerErrors::DataTooLarge));
    }

    /// Test that a peer with a different a_key gets nothing and pairs nothing
    #[tokio::test]
    async fn test_wrong_a_key_rejected() {
        let server = make_context(TEST_A_KEY, ACCEPT_ALL);
        let server_peers = server.trusted_peers.clone();

        let (server_result, client_result) = exchange(
            server,
            make_context([0x11; 32], ACCEPT_ALL),
            ActionType::Debug,
            b"secret",
        )
        .await;

        assert!(server_result.unwrap().is_none());
        assert_eq!(client_result, Err(TcpNetworkerErrors::WrongPassword));
        assert!(server_peers.read().await.is_empty());
    }

    /// Test that a rejected pairing delivers no data and saves no peer on either side
    #[tokio::test]
    async fn test_rejected_pairing_sends_nothing() {
        let server = make_context(TEST_A_KEY, REJECT_ALL);
        let client = make_context(TEST_A_KEY, ACCEPT_ALL);
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
            make_context(TEST_A_KEY, ACCEPT_ALL),
            make_context_d(TEST_A_KEY, [0x22; 32], ACCEPT_ALL),
            ActionType::Debug,
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
        let context = make_context(TEST_A_KEY, ACCEPT_ALL);

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

    /// Test that a client guessing wrong passwords is locked out after MAX_FAILURES
    #[tokio::test]
    async fn test_wrong_passwords_lock_out_the_source() {
        use crate::guess_limiter::MAX_FAILURES;

        let server = make_context(TEST_A_KEY, ACCEPT_ALL);

        for _ in 0..MAX_FAILURES {
            let (server_result, _) = exchange(
                server.clone(),
                make_context([0x11; 32], ACCEPT_ALL),
                ActionType::Debug,
                b"guess",
            )
            .await;
            assert!(server_result.unwrap().is_none());
        }

        // even the right password is refused now, before any handshake
        let (server_result, client_result) = exchange(
            server.clone(),
            make_context(TEST_A_KEY, ACCEPT_ALL),
            ActionType::Debug,
            b"hi",
        )
        .await;

        assert_eq!(server_result.err(), Some(TcpNetworkerErrors::LockedOut));
        assert!(client_result.is_err());
    }

    /// A full limiter refuses untracked peers on both sides before authentication.
    #[tokio::test]
    async fn test_full_guess_limiter_refuses_handshakes() {
        use crate::guess_limiter::MAX_TRACKED;

        for full_server in [true, false] {
            let server = make_context(TEST_A_KEY, ACCEPT_ALL);
            let client = make_context(TEST_A_KEY, ACCEPT_ALL);
            let full = if full_server { &server } else { &client };
            for i in 0..u32::try_from(MAX_TRACKED).unwrap() {
                full.guess_limiter
                    .record_failure(std::net::IpAddr::V4(i.into()))
                    .await;
            }
            let (server_result, client_result) =
                exchange(server, client, ActionType::Debug, b"hi").await;
            if full_server {
                assert_eq!(server_result.err(), Some(TcpNetworkerErrors::LockedOut));
                assert!(client_result.is_err());
            } else {
                assert_eq!(client_result.err(), Some(TcpNetworkerErrors::LockedOut));
                assert!(server_result.is_err());
            }
        }
    }

    /// Test that a server failing our confirmation is locked out on the client too
    #[tokio::test]
    async fn test_client_locks_out_failing_server() {
        use crate::guess_limiter::MAX_FAILURES;

        let client = make_context([0x11; 32], ACCEPT_ALL);

        for _ in 0..MAX_FAILURES {
            let (_, client_result) = exchange(
                make_context(TEST_A_KEY, ACCEPT_ALL),
                client.clone(),
                ActionType::Debug,
                b"x",
            )
            .await;
            assert!(client_result.is_err());
        }

        assert!(
            client
                .guess_limiter
                .is_locked("127.0.0.1".parse().unwrap())
                .await
        );
    }

    /// Test that cancelling before connect() returns Ok(()) without connecting
    #[tokio::test]
    async fn test_connect_cancels_before_connecting() {
        let token = CancellationToken::new();

        token.cancel();

        let unreachable: SocketAddr = "127.0.0.1:19999".parse().unwrap();
        let result = connect(
            make_context(TEST_A_KEY, ACCEPT_ALL),
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
            make_context(TEST_A_KEY, ACCEPT_ALL),
            CancellationToken::new(),
            addr,
            ActionType::Debug,
            Zeroizing::new(Vec::new()),
        )
        .await;

        assert_eq!(result.unwrap_err(), TcpNetworkerErrors::FailedToConnect);
    }

    /// Pairs `server` and `client` (both accept), so they know each other.
    async fn pair(server: &NetworkerContext, client: &NetworkerContext) {
        let (_, paired) = exchange(
            server.clone(),
            client.clone(),
            ActionType::ConnectNewDevice,
            b"",
        )
        .await;
        assert_eq!(paired, Ok(()));
    }

    /// Runs one answered send (hello / clipboard) and returns both results.
    async fn answered_exchange(
        server: NetworkerContext,
        client: NetworkerContext,
        action_type: ActionType,
        payload: &[u8],
    ) -> (
        Result<Option<ReceivedPacket>, TcpNetworkerErrors>,
        Result<(TrustedPeer, DataAck), TcpNetworkerErrors>,
        SocketAddr,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let incoming = listener.accept().await.unwrap();
            recv_handler(incoming, server).await
        });
        let stream = TcpStream::connect(addr).await.unwrap();
        let client_result = send_answered(client, addr, stream, action_type, payload).await;
        (server_task.await.unwrap(), client_result, addr)
    }

    /// Test that a hello between paired devices is answered and both
    /// remember where the other is
    #[tokio::test]
    async fn test_hello_answered_and_addresses_learned() {
        let server = make_context(TEST_A_KEY, ACCEPT_ALL);
        let client = make_context(TEST_A_KEY, ACCEPT_ALL);
        pair(&server, &client).await;
        // both had seen a data mismatch earlier: data that goes through ends it
        for side in [&client, &server] {
            let known = side.trusted_peers.read().await.clone();
            side.peer_book
                .set_state(known.first().unwrap(), PeerState::DataPasswordDiffers)
                .await;
        }

        let (server_result, client_result, addr) = answered_exchange(
            server.clone(),
            client.clone(),
            ActionType::Hello,
            HELLO_PAYLOAD,
        )
        .await;

        let (peer, ack) = client_result.unwrap();
        assert_eq!(ack, DataAck::Applied);
        assert_eq!(client.peer_book.state(&peer).await, PeerState::Ok);
        // the client knows the server at the address it connected to
        let targets = client.peer_book.targets(std::slice::from_ref(&peer)).await;
        assert_eq!(targets.first().map(|(_, at)| *at), Some(addr));

        let packet = server_result.unwrap().unwrap();
        assert_eq!(packet.action_type, ActionType::Hello);
        // the server knows the client at its IP and the fixed port
        assert_eq!(server.peer_book.state(&packet.peer).await, PeerState::Ok);
        let targets = server
            .peer_book
            .targets(std::slice::from_ref(&packet.peer))
            .await;
        assert_eq!(
            targets.first().map(|(_, at)| *at),
            Some(SocketAddr::new(addr.ip(), TCP_PORT))
        );
    }

    /// Test that a different data password shows on BOTH sides: the
    /// receiver can't read the hello, says so, and nothing is applied
    #[tokio::test]
    async fn test_hello_with_other_data_password() {
        let server = make_context(TEST_A_KEY, ACCEPT_ALL);
        let client = make_context(TEST_A_KEY, ACCEPT_ALL);
        pair(&server, &client).await;
        // the client's user changed the data password
        client.keys.write().await.d_key = DataKey::from_bytes(&[0x22; 32]);

        let (server_result, client_result, _) = answered_exchange(
            server.clone(),
            client.clone(),
            ActionType::Hello,
            HELLO_PAYLOAD,
        )
        .await;

        let (peer, ack) = client_result.unwrap();
        assert_eq!(ack, DataAck::DataKeyDiffers);
        assert_eq!(
            client.peer_book.state(&peer).await,
            PeerState::DataPasswordDiffers
        );
        assert_eq!(
            server_result.err(),
            Some(TcpNetworkerErrors::FailedToDecryptData)
        );
        let peers = server.trusted_peers.read().await.clone();
        assert_eq!(
            server.peer_book.state(peers.first().unwrap()).await,
            PeerState::DataPasswordDiffers
        );
    }

    /// Test that a different auth password shows on both sides, at the
    /// devices last seen at that address, and pairs nothing
    #[tokio::test]
    async fn test_other_auth_password_marks_both_sides() {
        let server = make_context(TEST_A_KEY, ACCEPT_ALL);
        let client = make_context(TEST_A_KEY, ACCEPT_ALL);
        pair(&server, &client).await;
        // a hello first, so each knows the other's address
        let (_, sent, _) = answered_exchange(
            server.clone(),
            client.clone(),
            ActionType::Hello,
            HELLO_PAYLOAD,
        )
        .await;
        let (server_peer, _) = sent.unwrap();

        client.keys.write().await.a_key = AuthKey::from_bytes(&[0x33; 32]);
        let (server_result, client_result, _) = answered_exchange(
            server.clone(),
            client.clone(),
            ActionType::Hello,
            HELLO_PAYLOAD,
        )
        .await;

        assert_eq!(client_result.err(), Some(TcpNetworkerErrors::WrongPassword));
        assert!(server_result.unwrap().is_none());
        assert_eq!(
            client.peer_book.state(&server_peer).await,
            PeerState::AuthPasswordDiffers
        );
        let peers = server.trusted_peers.read().await.clone();
        assert_eq!(
            server.peer_book.state(peers.first().unwrap()).await,
            PeerState::AuthPasswordDiffers
        );
        // paused: sync leaves it alone for a while
        assert!(
            client
                .peer_book
                .targets(std::slice::from_ref(&server_peer))
                .await
                .is_empty()
        );
    }

    /// Test that a sync connection never pairs: a device that doesn't know
    /// us gets no data and nobody is asked, even if it would accept
    #[tokio::test]
    async fn test_answered_send_never_pairs() {
        let server = make_context(TEST_A_KEY, ACCEPT_ALL);
        let client = make_context(TEST_A_KEY, ACCEPT_ALL);

        let (server_result, client_result, _) = answered_exchange(
            server.clone(),
            client.clone(),
            ActionType::Hello,
            HELLO_PAYLOAD,
        )
        .await;

        assert!(client_result.is_err());
        assert!(server_result.is_err());
        assert!(server.trusted_peers.read().await.is_empty());
        assert!(client.trusted_peers.read().await.is_empty());
    }

    /// Test that a clipboard update reaches the daemon's inbox and the
    /// daemon's answer goes back; without an inbox it is Ignored
    #[tokio::test]
    async fn test_clipboard_delivered_and_answered() {
        let (sink, mut inbox) = mpsc::channel(1);
        let server = NetworkerContext {
            clipboard: Some(sink),
            ..make_context(TEST_A_KEY, ACCEPT_ALL)
        };
        let client = make_context(TEST_A_KEY, ACCEPT_ALL);
        pair(&server, &client).await;

        let daemon = tokio::spawn(async move {
            let delivery = inbox.recv().await.unwrap();
            let text = crate::clip_sync::decode(&delivery.payload).unwrap().text;
            delivery.answer.send(DataAck::Applied).unwrap();
            text.to_string()
        });

        let payload = crate::clip_sync::encode(&[4; 8], 1, "copied").unwrap();
        let (server_result, client_result, _) =
            answered_exchange(server, client.clone(), ActionType::ClipboardSync, &payload).await;

        assert_eq!(client_result.unwrap().1, DataAck::Applied);
        assert_eq!(daemon.await.unwrap(), "copied");
        // the content moved to the daemon, nothing is kept by the networker
        assert!(server_result.unwrap().unwrap().data.is_empty());

        // no inbox (no clipboard on that platform): Ignored
        let bare = make_context(TEST_A_KEY, ACCEPT_ALL);
        pair(&bare, &client).await;
        let (_, client_result, _) =
            answered_exchange(bare, client, ActionType::ClipboardSync, &payload).await;
        assert_eq!(client_result.unwrap().1, DataAck::Ignored);
    }

    /// Test that the sizes are bounded on both ends: a hello must be exact,
    /// a clipboard update within its limits
    #[test]
    fn test_answered_sizes() {
        let hello = HELLO_PAYLOAD.len() + DATA_LAYER_OVERHEAD;
        assert!(answered_len_ok(ActionType::Hello, hello));
        assert!(!answered_len_ok(ActionType::Hello, hello + 1));
        assert!(!answered_len_ok(ActionType::Hello, hello - 1));
        assert!(answered_len_ok(
            ActionType::ClipboardSync,
            CLIP_MIN_WIRE_LEN
        ));
        assert!(answered_len_ok(
            ActionType::ClipboardSync,
            CLIP_MAX_WIRE_LEN
        ));
        assert!(!answered_len_ok(
            ActionType::ClipboardSync,
            CLIP_MIN_WIRE_LEN - 1
        ));
        assert!(!answered_len_ok(
            ActionType::ClipboardSync,
            CLIP_MAX_WIRE_LEN + 1
        ));
        for other in [
            ActionType::Default,
            ActionType::Debug,
            ActionType::ConnectNewDevice,
            ActionType::GroupSalt,
        ] {
            assert!(!answered_len_ok(other, hello));
        }
    }

    /// Test that the receiver refuses an oversized clipboard update before
    /// reading it (a raw header from a paired device)
    #[tokio::test]
    async fn test_oversized_clipboard_refused_by_receiver() {
        let server = make_context(TEST_A_KEY, ACCEPT_ALL);
        let client = make_context(TEST_A_KEY, ACCEPT_ALL);
        pair(&server, &client).await;

        // connect_handler sends any size: CLIP_MAX_LEN + header + 1 is too long
        let big =
            vec![b'a'; crate::clip_sync::CLIP_HEADER_LEN + crate::clip_sync::CLIP_MAX_LEN + 1];
        let (server_result, _) = exchange(server, client, ActionType::ClipboardSync, &big).await;
        assert_eq!(server_result.err(), Some(TcpNetworkerErrors::DataTooLarge));
    }
}
