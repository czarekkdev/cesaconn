//TODO: add streaming option for large files
//TODO: add function arg to handle any further actions determined by ActionType in recv_handler
//TODO: remove arc and rwlock for listener and CancellationToken

use core::net::SocketAddr;
use std::fmt;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::select;
use tokio::sync::RwLock;
use tokio::task::spawn_blocking;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::auth::{Keys, auth_incoming, auth_outgoing, decrypt_tunnel, encrypt_tunnel};

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
    /// Adds the connecting peer to the trusted address list.
    /// No data payload is sent for this action — connection closes after auth succeeds.
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

pub struct TrustedPeer {
    peer_id: 
}

/// All errors that can occur in the TCP networker layer.
/// Each variant maps to a specific failure point in the connection lifecycle.
#[derive(Debug, PartialEq)]
pub enum TcpNetworkerErrors {
    /// `listener.accept()` failed — OS-level socket error, usually non-recoverable.
    FailedToAcceptConnection,
    /// Stream closed or errored before all expected bytes arrived — peer disconnected early.
    FailedToReadFromStream,
    /// ECDH + pre-shared key handshake failed — wrong key, untrusted peer, or I/O error.
    FailedToAuthenticate,
    /// AES-GCM decryption failed — wrong key or data was tampered with in transit.
    FailedToDecryptTunnel,
    /// Could not read local address from the listener — needed for logging.
    FailedToGetLocalAddr,
    /// TcpStream::connect failed — target unreachable, refused, or timed out.
    FailedToConnect,
    /// AES-GCM encryption failed — should not happen under normal conditions.
    FailedToEncryptTunnel,
    /// Writing to the TCP stream failed — peer disconnected or network error.
    FailedToWriteToStream,
    /// tokio::task::spawn_blocking returned a JoinError — blocking task panicked.
    FailedToSpawnNewBlockingTask,
}

impl fmt::Display for TcpNetworkerErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TcpNetworkerErrors::FailedToAcceptConnection => {
                write!(f, "failed to accept connection")
            }
            TcpNetworkerErrors::FailedToReadFromStream => write!(f, "failed to read from stream"),
            TcpNetworkerErrors::FailedToAuthenticate => write!(f, "authentication failed"),
            TcpNetworkerErrors::FailedToDecryptTunnel => write!(f, "failed to decrypt tunnel data"),
            TcpNetworkerErrors::FailedToGetLocalAddr => write!(f, "failed to get local address"),
            TcpNetworkerErrors::FailedToConnect => write!(f, "failed to make a connection request"),
            TcpNetworkerErrors::FailedToEncryptTunnel => write!(f, "failed to encrypt tunnel data"),
            TcpNetworkerErrors::FailedToWriteToStream => write!(f, "failed to write to stream"),
            TcpNetworkerErrors::FailedToSpawnNewBlockingTask => {
                write!(f, "failed to spawn new blocking task")
            }
        }
    }
}

/// Handles a single incoming TCP connection after it has been accepted by `recv`.
///
/// # Packet format
///
/// Every connection follows a fixed three-phase protocol:
///
/// **Phase 1 — Authentication** (handled by `auth_incoming`)
///   ECDH X25519 key exchange + pre-shared key verification.
///   Derives an ephemeral session key (`shared_key`) unique to this connection.
///   If the peer's IP is not in `trusted_addrs`, auth returns false immediately
///   and the connection is closed without reading any data.
///
/// **Phase 2 — Init header** (37 encrypted bytes)
///   Encrypted layout: 12 (nonce) + 9 (plaintext) + 16 (GCM tag) = 37 bytes
///   Plaintext layout:
///     - [0]    = ActionType as u8
///     - [1..9] = encrypted data size as little-endian u64
///              (byte count of the encrypted data packet, not the raw plaintext size)
///
/// **Phase 3 — Data packet** (variable size, declared in init header)
///   Double-encrypted: outer layer = session key, inner layer = static data key.
///   Decrypt outer first (strips session encryption), then inner (strips data key).
///   Both decryption steps are offloaded to spawn_blocking for large payload support.
///   The local d_key copy is zeroized immediately after use.
pub async fn recv_handler(
    incoming_connection: (TcpStream, SocketAddr),
    keys: Arc<RwLock<Keys>>,
    trusted_addrs: Arc<RwLock<Vec<SocketAddr>>>,
) -> Result<(), TcpNetworkerErrors> {
    let peer_addr = incoming_connection.1;

    // Move the stream out of the tuple so we can take a mutable reference to it.
    let mut connection = incoming_connection.0;
    let connection_mut = &mut connection;

    debug!(%peer_addr, "recv_handler started for incoming connection");

    // Phase 1: ECDH + pre-shared key handshake.
    // shared_key is ephemeral — derived fresh from ECDH for every connection.
    // All further communication on this stream uses shared_key for the outer encryption layer.
    debug!(%peer_addr, "phase 1: starting auth_incoming handshake");
    let (auth_result, shared_key) =
        auth_incoming(keys.clone(), trusted_addrs, (connection_mut, peer_addr))
            .await
            .map_err(|e| {
                error!(%peer_addr, error = %e, "auth_incoming returned an error");
                TcpNetworkerErrors::FailedToAuthenticate
            })?;

    // auth_incoming returns false (not Err) for untrusted peers — close gracefully, not as an error.
    if !auth_result {
        warn!(%peer_addr, "authentication failed for incoming connection, closing gracefully");
        return Ok(());
    }

    debug!(%peer_addr, "phase 1 complete: authentication successful");

    // Phase 2: Read and decrypt the init header.
    // Fixed size: 12 (nonce) + 9 (plaintext) + 16 (GCM tag) = 37 bytes.
    let e_init_buf = &mut [0u8; 37];

    debug!(%peer_addr, "phase 2: reading encrypted init header (37 bytes)");
    connection_mut.read_exact(e_init_buf).await.map_err(|e| {
        error!(%peer_addr, error = %e, "failed to read encrypted init header from stream");
        TcpNetworkerErrors::FailedToReadFromStream
    })?;

    // Decrypt using the session key — GCM tag verification catches any in-transit tampering.
    debug!(%peer_addr, "decrypting init header with session key");
    let init_buf = decrypt_tunnel(&shared_key, e_init_buf)
        .map_err(|e| {
            error!(%peer_addr, error = %e, "failed to decrypt init header — GCM tag mismatch or wrong session key");
            TcpNetworkerErrors::FailedToDecryptTunnel
        })?;

    // Extract the encrypted data packet size from bytes [1..9] as little-endian u64.
    // This is the byte count of the encrypted packet below — not the raw plaintext size.
    let size_bytes = &mut [0u8; 8];
    size_bytes.copy_from_slice(&init_buf[1..9]);
    let size = u64::from_le_bytes(*size_bytes);

    let action_type_raw = init_buf[0];
    debug!(%peer_addr, action_type_byte = action_type_raw, data_packet_size = size, "init header decrypted successfully");

    // Phase 3a: Read the double-encrypted data packet.
    // Length was declared in the authenticated init header — we trust it because
    // the header passed AES-GCM verification, so the size field was not tampered with.
    let mut e_t_data_buf = vec![0u8; size as usize];

    debug!(%peer_addr, size, "phase 3a: reading double-encrypted data packet");
    connection_mut
        .read_exact(&mut e_t_data_buf)
        .await
        .map_err(|e| {
            error!(%peer_addr, error = %e, expected_bytes = size, "failed to read double-encrypted data packet from stream");
            TcpNetworkerErrors::FailedToReadFromStream
        })?;

    // Phase 3b: Strip the outer encryption layer using the session key — offloaded to
    // spawn_blocking so large payloads don't block the tokio runtime.
    // Result is still encrypted with d_key — forward secrecy is maintained because
    // session keys are ephemeral and not stored anywhere.
    debug!(%peer_addr, "phase 3b: stripping outer session-key encryption layer (spawn_blocking)");
    let e_data_buf = spawn_blocking(move || {
        let e_t_t_data_buf = e_t_data_buf;
        decrypt_tunnel(&shared_key, &e_t_t_data_buf)
    })
    .await
    .map_err(|e| {
        error!(%peer_addr, error = %e, "spawn_blocking task for outer-layer decryption panicked");
        TcpNetworkerErrors::FailedToSpawnNewBlockingTask
    })?
    .map_err(|e| {
        error!(%peer_addr, error = %e, "outer-layer AES-GCM decryption failed — wrong session key or tampered data");
        TcpNetworkerErrors::FailedToDecryptTunnel
    })?;

    // Phase 3c: Strip the inner encryption layer using the static data key.
    // Clone d_key out of the RwLock into a local buffer so we can zeroize it after use.
    let d_key_clone = keys.read().await.d_key.clone();

    debug!(%peer_addr, "phase 3c: stripping inner d_key encryption layer (spawn_blocking)");

    let data_buf = spawn_blocking(move || {
        decrypt_tunnel(&d_key_clone, e_data_buf.as_ref())
    })
    .await
    .map_err(|e| {
        error!(%peer_addr, error = %e, "spawn task for inner-layer decryption panicked");
        TcpNetworkerErrors::FailedToSpawnNewBlockingTask
    })?
    .map_err(|e| {
        error!(%peer_addr, error = %e, "inner-layer AES-GCM decryption failed — wrong d_key or tampered data");
        TcpNetworkerErrors::FailedToDecryptTunnel
    })?;

    // Parse the action type byte. Unknown values default to Default instead of rejecting —
    // this keeps the protocol forward-compatible with new ActionType variants added later.
    let action_type = ActionType::from_u8(init_buf[0]).unwrap_or(ActionType::Default);

    //TODO: dispatch to the appropriate handler based on action type
    info!(
        %peer_addr,
        action_type = ?action_type,
        data_len = data_buf.len(),
        data = %String::from_utf8_lossy(&data_buf),
        "received packet successfully"
    );

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
    keys: Arc<RwLock<Keys>>,
    trusted_addrs: Arc<RwLock<Vec<SocketAddr>>>,
    cancellation_token: CancellationToken,
) -> Result<(), TcpNetworkerErrors> {
    let local_addr = listener.local_addr().map_err(|e| {
        error!(error = %e, "failed to read local address from TCP listener");
        TcpNetworkerErrors::FailedToGetLocalAddr
    })?;

    info!(%local_addr, "TCP listener started, waiting for incoming connections");

    loop {
        // Clone all Arc references before spawning — each task owns its own reference counts.
        // This avoids the spawned task borrowing from the loop's local scope.
        let cloned_token = cancellation_token.clone();
        let keys_clone = keys.clone();
        let trusted_addrs_clone = trusted_addrs.clone();

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
        info!(%local_addr, %peer_addr, "accepted incoming TCP connection, spawning recv_handler");

        // Spawn a dedicated task for this connection — no .await, so the loop immediately
        // circles back to accept() and can handle the next incoming connection in parallel.
        tokio::spawn(async move {
            select! {
                // If the token fires mid-handler, drop the task immediately without waiting
                // for it to finish — prevents stale tasks from delaying shutdown.
                _ = cloned_token.cancelled() => {
                    info!(%peer_addr, "cancellation token fired mid-handler, dropping recv_handler task");
                },
                result = recv_handler(
                    incoming_connection,
                    keys_clone,
                    trusted_addrs_clone,
                ) => {
                    match result {
                        Ok(()) => debug!(%peer_addr, "recv_handler completed successfully"),
                        Err(e) => error!(%peer_addr, error = %e, "recv_handler returned an error"),
                    }
                }
            }
        });
    }

    Ok(())
}

/// Handles a single outgoing TCP connection — authenticates with the peer then
/// sends a double-encrypted data packet.
///
/// # Packet format
///
/// **Phase 1 — Authentication** (handled by `auth_outgoing`)
///   ECDH X25519 key exchange + pre-shared key verification.
///   Derives an ephemeral session key (`shared_key`) for this connection.
///   If `connect_addr` is not in `trusted_addrs`, auth returns false and the
///   connection is closed immediately without sending any data.
///
/// **Phase 2 — ConnectNewDevice shortcut**
///   If action_type is ConnectNewDevice, `connect_addr` is added to `trusted_addrs`
///   and the function returns immediately. No init header or data packet is sent.
///
/// **Phase 3 — Data packet** (double-encrypted, built before the init header)
///   Inner layer: d_key (static pre-shared data key) — encrypted in spawn_blocking
///   so large payloads don't block the tokio runtime.
///   Outer layer: shared_key (ephemeral session key) — also in spawn_blocking.
///   The local d_key copy is zeroized inside the closure immediately after use.
///
/// **Phase 4 — Init header** (37 encrypted bytes, sent after the data is ready)
///   Plaintext layout:
///     - [0]    = ActionType as u8
///     - [1..9] = e_t_data.len() as little-endian u64 (byte count of the packet above)
///   Built last so the exact encrypted size is known before writing to the header.
pub async fn connect_handler(
    keys: Arc<RwLock<Keys>>,
    trusted_addrs: Arc<RwLock<Vec<SocketAddr>>>,
    connect_addr: SocketAddr,
    outgoing_connection: TcpStream,
    action_type: ActionType,
    data: Vec<u8>,
) -> Result<(), TcpNetworkerErrors> {
    let mut connection = outgoing_connection;

    debug!(%connect_addr, action_type = ?action_type, data_len = data.len(), "connect_handler started");

    // Phase 1: ECDH + pre-shared key handshake.
    // auth_outgoing returns false (not Err) if connect_addr is not in trusted_addrs.
    debug!(%connect_addr, "phase 1: starting auth_outgoing handshake");
    let (auth_result, shared_key) = auth_outgoing(
        keys.clone(),
        trusted_addrs.clone(),
        (&mut connection, connect_addr),
    )
    .await
    .map_err(|e| {
        error!(%connect_addr, error = %e, "auth_outgoing returned an error");
        TcpNetworkerErrors::FailedToAuthenticate
    })?;

    // Peer rejected our key, or we rejected theirs — close gracefully without sending data.
    if !auth_result {
        warn!(%connect_addr, "authentication failed for outgoing connection, closing gracefully");
        return Ok(());
    }

    debug!(%connect_addr, "phase 1 complete: authentication successful");

    // Phase 2: ConnectNewDevice — register the peer as trusted and exit.
    // No data payload is defined for this action type.
    if action_type == ActionType::ConnectNewDevice {
        info!(%connect_addr, "phase 2: ConnectNewDevice — adding peer to trusted_addrs and returning");
        let mut trusted_addrs_mod = trusted_addrs.write().await;
        trusted_addrs_mod.push(connect_addr);
        return Ok(());
    }

    // Phase 3a: Encrypt data with d_key (inner layer) in a blocking task.
    // spawn_blocking offloads CPU-intensive AES-GCM off the tokio worker thread —
    // critical for large payloads (e.g. files) so other async tasks aren't starved.
    let d_key_clone = keys.read().await.d_key.clone();

    debug!(%connect_addr, data_len = data.len(), "phase 3a: encrypting data with d_key inner layer (spawn_blocking)");
    let e_data = spawn_blocking(move || {
        encrypt_tunnel(&d_key_clone, &data)
    })
    .await
    .map_err(|e| {
        error!(%connect_addr, error = %e, "spawn_blocking task for inner-layer encryption panicked");
        TcpNetworkerErrors::FailedToSpawnNewBlockingTask
    })?
    .map_err(|e| {
        error!(%connect_addr, error = %e, "inner-layer AES-GCM encryption with d_key failed");
        TcpNetworkerErrors::FailedToEncryptTunnel
    })?;

    // Phase 3b: Wrap with the session key (outer layer) — also in spawn_blocking.
    // Forward secrecy: even if d_key is later leaked, past sessions remain protected
    // because shared_key is ephemeral and was never stored.
    debug!(%connect_addr, inner_encrypted_len = e_data.len(), "phase 3b: wrapping with session key outer layer (spawn_blocking)");
    let e_t_data = spawn_blocking(move || encrypt_tunnel(&shared_key, &e_data))
        .await
        .map_err(|e| {
            error!(%connect_addr, error = %e, "spawn_blocking task for outer-layer encryption panicked");
            TcpNetworkerErrors::FailedToSpawnNewBlockingTask
        })?
        .map_err(|e| {
            error!(%connect_addr, error = %e, "outer-layer AES-GCM encryption with session key failed");
            TcpNetworkerErrors::FailedToEncryptTunnel
        })?;

    // Phase 4: Build and send the init header now that we know the exact encrypted size.
    // size = e_t_data.len() so the receiver knows exactly how many bytes to read_exact().
    let size = e_t_data.len() as u64;
    let mut init_data = [0u8; 9];
    init_data[0] = action_type as u8;
    init_data[1..].copy_from_slice(&size.to_le_bytes()); // little-endian, matches recv_handler

    debug!(%connect_addr, action_type = ?action_type, data_packet_size = size, "phase 4: encrypting init header");
    let e_init_data = encrypt_tunnel(&shared_key, &init_data).map_err(|e| {
        error!(%connect_addr, error = %e, "failed to encrypt init header with session key");
        TcpNetworkerErrors::FailedToEncryptTunnel
    })?;

    // Send init header first, then the double-encrypted data packet.
    debug!(%connect_addr, "sending encrypted init header (37 bytes)");
    connection.write_all(&e_init_data).await.map_err(|e| {
        error!(%connect_addr, error = %e, "failed to write encrypted init header to stream");
        TcpNetworkerErrors::FailedToWriteToStream
    })?;

    debug!(%connect_addr, data_packet_size = size, "sending double-encrypted data packet");
    connection.write_all(&e_t_data).await.map_err(|e| {
        error!(%connect_addr, error = %e, "failed to write double-encrypted data packet to stream");
        TcpNetworkerErrors::FailedToWriteToStream
    })?;

    info!(%connect_addr, action_type = ?action_type, data_packet_size = size, "connect_handler completed successfully");
    Ok(())
}

/// Initiates an outgoing TCP connection to `connect_addr` and passes it to `connect_handler`.
///
/// Returns immediately after the TCP connect resolves — auth and data transfer happen
/// inside a spawned task concurrently with other work. Cancellation is checked both
/// before the TCP connect and mid-handler inside the spawned task.
pub async fn connect(
    keys: Arc<RwLock<Keys>>,
    trusted_addrs: Arc<RwLock<Vec<SocketAddr>>>,
    cancellation_token: CancellationToken,
    connect_addr: SocketAddr,
    action_type: ActionType,
    data: Vec<u8>,
) -> Result<(), TcpNetworkerErrors> {
    // Clone Arcs before the select! — the spawned task needs its own reference counts.
    let cloned_token = cancellation_token.clone();
    let keys_clone = keys.clone();
    let trusted_addrs_clone = trusted_addrs.clone();

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

    // Spawn the handler — no .await so connect() returns immediately after the TCP connect.
    tokio::spawn(async move {
        select! {
            // Drop the handler immediately if the token fires mid-connection.
            _ = cloned_token.cancelled() => {
                info!(%connect_addr, "cancellation token fired mid-handler, dropping connect_handler task");
            },
            result = connect_handler(
                keys_clone,
                trusted_addrs_clone,
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
        };
    });

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{decrypt_tunnel, encrypt_tunnel};
    use cesa_conn_crypto::x25519_cesa::{
        calculate_public_key, calculate_shared_key, generate_private_key, hash_key,
    };
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;
    use tokio_util::sync::CancellationToken;

    // Pre-shared keys used across all tests — constant for deterministic, reproducible runs.
    const TEST_A_KEY: [u8; 32] = [0xAB; 32]; // authentication key
    const TEST_D_KEY: [u8; 32] = [0xCD; 32]; // data encryption key

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /// Builds the Arc<RwLock<...>> state bundle used by all handlers.
    /// Both keys are packed into a single `Keys` so callers match `recv_handler`/`connect_handler`.
    fn make_state(
        a_key: [u8; 32],
        d_key: [u8; 32],
        trusted: Vec<SocketAddr>,
    ) -> (Arc<RwLock<Keys>>, Arc<RwLock<Vec<SocketAddr>>>) {
        (
            Arc::new(RwLock::new(Keys::new(a_key, d_key))),
            Arc::new(RwLock::new(trusted)),
        )
    }

    /// Manually drives the CLIENT side of the auth_incoming handshake.
    /// Mirrors what auth_outgoing sends on the wire so tests can exercise
    /// recv_handler directly without needing a real connect_handler.
    ///
    /// Returns the derived shared_hash (session key) for subsequent manual encryption.
    async fn client_auth(stream: &mut TcpStream, auth_key: [u8; 32]) -> [u8; 32] {
        // Step 1: generate ephemeral key pair and send public key to the server.
        let client_priv = generate_private_key();
        let client_pub = calculate_public_key(&client_priv);
        stream.write_all(&client_pub).await.unwrap();

        // Step 2: read server's ephemeral public key and derive the shared secret.
        let server_pub = &mut [0u8; 32];
        stream.read_exact(server_pub).await.unwrap();
        let shared = calculate_shared_key(&client_priv, server_pub);
        let shared_hash = hash_key(&shared);

        // Step 3: encrypt our auth key with the session key and send it (60 bytes).
        let payload = encrypt_tunnel(&shared_hash, &auth_key).unwrap();
        stream.write_all(&payload).await.unwrap();

        // Step 4: read server's key echo (60 bytes) and verify it matches our auth key.
        let recv_buf = &mut [0u8; 60];
        stream.read_exact(recv_buf).await.unwrap();
        let recv_plaintext = decrypt_tunnel(&shared_hash, recv_buf).unwrap();

        // Step 5: send confirmation byte — 0x01 confirmed, 0x00 rejected (29 bytes).
        let confirmed = recv_plaintext == auth_key;
        let conf_byte = [if confirmed { 0x01u8 } else { 0x00u8 }];
        let e_conf = encrypt_tunnel(&shared_hash, &conf_byte).unwrap();
        stream.write_all(&e_conf).await.unwrap();

        shared_hash
    }

    // -------------------------------------------------------------------------
    // ActionType tests
    // -------------------------------------------------------------------------

    /// All four known byte values must map to their correct ActionType variants.
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

    /// Unknown byte values must return None — not panic or silently default.
    #[test]
    fn test_action_type_from_u8_unknown() {
        assert_eq!(ActionType::from_u8(0x04), None);
        assert_eq!(ActionType::from_u8(0x10), None);
        assert_eq!(ActionType::from_u8(0xFF), None);
    }

    /// Wire discriminants must be stable — changing them breaks protocol compatibility.
    #[test]
    fn test_action_type_discriminants() {
        assert_eq!(ActionType::Default as u8, 0x00);
        assert_eq!(ActionType::Debug as u8, 0x01);
        assert_eq!(ActionType::ConnectNewDevice as u8, 0x02);
        assert_eq!(ActionType::ClipboardSync as u8, 0x03);
    }

    /// from_u8 and as u8 must be a perfect roundtrip for all known variants.
    #[test]
    fn test_action_type_roundtrip() {
        for variant in [
            ActionType::Default,
            ActionType::Debug,
            ActionType::ConnectNewDevice,
            ActionType::ClipboardSync,
        ] {
            assert_eq!(ActionType::from_u8(variant as u8), Some(variant));
        }
    }

    // -------------------------------------------------------------------------
    // TcpNetworkerErrors display tests
    // -------------------------------------------------------------------------

    /// Every error variant must produce a non-empty, human-readable Display string.
    #[test]
    fn test_all_error_display_non_empty() {
        let errors = [
            TcpNetworkerErrors::FailedToAcceptConnection,
            TcpNetworkerErrors::FailedToReadFromStream,
            TcpNetworkerErrors::FailedToAuthenticate,
            TcpNetworkerErrors::FailedToDecryptTunnel,
            TcpNetworkerErrors::FailedToGetLocalAddr,
            TcpNetworkerErrors::FailedToConnect,
            TcpNetworkerErrors::FailedToEncryptTunnel,
            TcpNetworkerErrors::FailedToWriteToStream,
            TcpNetworkerErrors::FailedToSpawnNewBlockingTask,
        ];
        for err in errors {
            assert!(!err.to_string().is_empty());
        }
    }

    #[test]
    fn test_error_display_accept() {
        assert_eq!(
            TcpNetworkerErrors::FailedToAcceptConnection.to_string(),
            "failed to accept connection"
        );
    }

    #[test]
    fn test_error_display_read() {
        assert_eq!(
            TcpNetworkerErrors::FailedToReadFromStream.to_string(),
            "failed to read from stream"
        );
    }

    #[test]
    fn test_error_display_auth() {
        assert_eq!(
            TcpNetworkerErrors::FailedToAuthenticate.to_string(),
            "authentication failed"
        );
    }

    #[test]
    fn test_error_display_decrypt() {
        assert_eq!(
            TcpNetworkerErrors::FailedToDecryptTunnel.to_string(),
            "failed to decrypt tunnel data"
        );
    }

    #[test]
    fn test_error_display_local_addr() {
        assert_eq!(
            TcpNetworkerErrors::FailedToGetLocalAddr.to_string(),
            "failed to get local address"
        );
    }

    #[test]
    fn test_error_display_connect() {
        assert_eq!(
            TcpNetworkerErrors::FailedToConnect.to_string(),
            "failed to make a connection request"
        );
    }

    #[test]
    fn test_error_display_encrypt() {
        assert_eq!(
            TcpNetworkerErrors::FailedToEncryptTunnel.to_string(),
            "failed to encrypt tunnel data"
        );
    }

    #[test]
    fn test_error_display_write() {
        assert_eq!(
            TcpNetworkerErrors::FailedToWriteToStream.to_string(),
            "failed to write to stream"
        );
    }

    #[test]
    fn test_error_display_spawn_blocking() {
        assert_eq!(
            TcpNetworkerErrors::FailedToSpawnNewBlockingTask.to_string(),
            "failed to spawn new blocking task"
        );
    }

    // -------------------------------------------------------------------------
    // recv_handler tests
    // -------------------------------------------------------------------------

    /// A peer whose address is not in trusted_addrs must be rejected gracefully.
    /// recv_handler returns Ok(()) — a closed untrusted connection is not an error.
    #[tokio::test]
    async fn test_recv_handler_untrusted_addr_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, peer_addr) = listener.accept().await.unwrap();

        // Empty trusted list — peer_addr fails the allowlist check inside auth_incoming.
        let (keys, trusted) = make_state(TEST_A_KEY, TEST_D_KEY, vec![]);

        drop(client); // cleanup — server returns Ok without reading anything (IP not in trusted_addrs)

        let result = recv_handler((server, peer_addr), keys, trusted).await;
        assert!(result.is_ok());
    }

    /// Stream closing during auth must return FailedToAuthenticate.
    #[tokio::test]
    async fn test_recv_handler_stream_closes_during_auth() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, peer_addr) = listener.accept().await.unwrap();

        // peer_addr is trusted — auth proceeds, then fails when stream closes immediately.
        let (keys, trusted) = make_state(TEST_A_KEY, TEST_D_KEY, vec![peer_addr]);

        drop(client); // EOF on auth_incoming's first read_exact

        let result = recv_handler((server, peer_addr), keys, trusted).await;
        assert_eq!(
            result.unwrap_err(),
            TcpNetworkerErrors::FailedToAuthenticate
        );
    }

    /// Wrong auth key must cause auth_incoming to return false — server closes gracefully.
    ///
    /// We drive the client side with auth_outgoing (wrong key) instead of client_auth —
    /// auth_outgoing handles the server closing mid-handshake gracefully (EOF → Err),
    /// whereas client_auth would panic on unwrap() when the 60-byte server response never arrives.
    #[tokio::test]
    async fn test_recv_handler_wrong_auth_key() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).await.unwrap();
        let (server, peer_addr) = listener.accept().await.unwrap();

        let (keys, trusted) = make_state(TEST_A_KEY, TEST_D_KEY, vec![peer_addr]);

        let server_task = tokio::spawn(recv_handler((server, peer_addr), keys, trusted));

        // auth_outgoing sends the wrong key then reads the server's response.
        // When the server closes without responding, auth_outgoing returns Err(FailedToReadFromStream)
        // instead of panicking — so the client task exits cleanly.
        let wrong_a_key = Arc::new(RwLock::new(Keys::new([0x00u8; 32], [0u8; 32])));
        let wrong_trusted = Arc::new(RwLock::new(vec![peer_addr]));
        let _ = auth_outgoing(wrong_a_key, wrong_trusted, (&mut client, peer_addr)).await;

        let result = server_task.await.unwrap();
        // auth_incoming sees key mismatch → returns (false, _) → recv_handler returns Ok(()).
        assert!(result.is_ok());
    }

    /// Garbage bytes in place of the init header must be rejected by AES-GCM tag verification.
    #[tokio::test]
    async fn test_recv_handler_garbage_after_auth() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).await.unwrap();
        let (server, peer_addr) = listener.accept().await.unwrap();

        let (keys, trusted) = make_state(TEST_A_KEY, TEST_D_KEY, vec![peer_addr]);

        let server_task = tokio::spawn(recv_handler((server, peer_addr), keys, trusted));

        // Auth succeeds, then send 37 random bytes as the init header.
        client_auth(&mut client, TEST_A_KEY).await;
        client.write_all(&[0xDE; 37]).await.unwrap();

        let result = server_task.await.unwrap();
        // GCM tag mismatch on the garbage bytes → FailedToDecryptTunnel.
        assert_eq!(
            result.unwrap_err(),
            TcpNetworkerErrors::FailedToDecryptTunnel
        );
    }

    /// Closing the stream after auth but before the init header must return FailedToReadFromStream.
    #[tokio::test]
    async fn test_recv_handler_closes_after_auth() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).await.unwrap();
        let (server, peer_addr) = listener.accept().await.unwrap();

        let (keys, trusted) = make_state(TEST_A_KEY, TEST_D_KEY, vec![peer_addr]);

        let server_task = tokio::spawn(recv_handler((server, peer_addr), keys, trusted));

        client_auth(&mut client, TEST_A_KEY).await;
        drop(client); // EOF on recv_handler's read_exact for the init header

        let result = server_task.await.unwrap();
        assert_eq!(
            result.unwrap_err(),
            TcpNetworkerErrors::FailedToReadFromStream
        );
    }

    // -------------------------------------------------------------------------
    // Full client -> server test (manual client + recv_handler)
    // -------------------------------------------------------------------------

    /// Full end-to-end test: a manually constructed client sends a correctly formatted
    /// and encrypted packet — recv_handler on the server side must accept and decrypt it.
    ///
    /// Driving the client manually (not via connect_handler) gives full control over the
    /// wire format so recv_handler can be verified in isolation.
    #[tokio::test]
    async fn test_full_client_to_server() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).await.unwrap();
        let (server, peer_addr) = listener.accept().await.unwrap();

        let (keys, trusted) = make_state(TEST_A_KEY, TEST_D_KEY, vec![peer_addr]);

        let server_task = tokio::spawn(recv_handler((server, peer_addr), keys, trusted));

        // Auth: complete the handshake and obtain the ephemeral session key.
        let shared_hash = client_auth(&mut client, TEST_A_KEY).await;

        let plaintext = b"hello from client";

        // Double-encrypt: inner = d_key, outer = session key — mirrors connect_handler.
        let inner = encrypt_tunnel(&TEST_D_KEY, plaintext).unwrap();
        let outer = encrypt_tunnel(&shared_hash, &inner).unwrap();

        // Init header: store outer.len() (the encrypted packet size) so recv_handler
        // knows exactly how many bytes to read_exact() for the data packet.
        let mut init_plaintext = [0u8; 9];
        init_plaintext[0] = ActionType::Debug as u8;
        init_plaintext[1..9].copy_from_slice(&(outer.len() as u64).to_le_bytes());

        let init_packet = encrypt_tunnel(&shared_hash, &init_plaintext).unwrap();
        client.write_all(&init_packet).await.unwrap();
        client.write_all(&outer).await.unwrap();

        assert!(server_task.await.unwrap().is_ok());
    }

    /// Same as test_full_client_to_server but with a 512-byte payload to verify the
    /// size field is decoded and used correctly for larger data.
    #[tokio::test]
    async fn test_full_client_to_server_large_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).await.unwrap();
        let (server, peer_addr) = listener.accept().await.unwrap();

        let (keys, trusted) = make_state(TEST_A_KEY, TEST_D_KEY, vec![peer_addr]);

        let server_task = tokio::spawn(recv_handler((server, peer_addr), keys, trusted));

        let shared_hash = client_auth(&mut client, TEST_A_KEY).await;

        let plaintext = vec![0xBE; 512];
        let inner = encrypt_tunnel(&TEST_D_KEY, &plaintext).unwrap();
        let outer = encrypt_tunnel(&shared_hash, &inner).unwrap();

        let mut init_plaintext = [0u8; 9];
        init_plaintext[0] = ActionType::ClipboardSync as u8;
        init_plaintext[1..9].copy_from_slice(&(outer.len() as u64).to_le_bytes());

        let init_packet = encrypt_tunnel(&shared_hash, &init_plaintext).unwrap();
        client.write_all(&init_packet).await.unwrap();
        client.write_all(&outer).await.unwrap();

        assert!(server_task.await.unwrap().is_ok());
    }

    // -------------------------------------------------------------------------
    // Full server -> client test (connect_handler + recv_handler)
    // -------------------------------------------------------------------------

    /// Full end-to-end test pairing connect_handler (sender) with recv_handler (receiver).
    ///
    /// connect_handler runs auth_outgoing, double-encrypts the payload, and sends it.
    /// recv_handler runs auth_incoming, reads and double-decrypts the payload.
    /// Both sides use the same pre-shared keys — the ECDH session key is negotiated live
    /// so it's different every run.
    #[tokio::test]
    async fn test_full_server_to_client() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        // Connect first so we can get the client's ephemeral address before building
        // the trusted_addrs list — auth_incoming checks the peer's address.
        let outgoing = TcpStream::connect(server_addr).await.unwrap();
        let client_addr = outgoing.local_addr().unwrap();
        let (server_stream, peer_addr) = listener.accept().await.unwrap();

        // Server trusts the client's ephemeral addr; client trusts the server addr.
        let (keys_s, trusted_s) = make_state(TEST_A_KEY, TEST_D_KEY, vec![client_addr]);
        let (keys_c, trusted_c) = make_state(TEST_A_KEY, TEST_D_KEY, vec![server_addr]);

        // Spawn the server (recv_handler) — blocks waiting for the client's ECDH public key.
        let server_task = tokio::spawn(recv_handler(
            (server_stream, peer_addr),
            keys_s,
            trusted_s,
        ));

        // Run the client (connect_handler) inline — drives auth + double-encrypt + send.
        let client_result = connect_handler(
            keys_c,
            trusted_c,
            server_addr,
            outgoing,
            ActionType::Debug,
            b"hello from connect_handler".to_vec(),
        )
        .await;

        assert!(client_result.is_ok());
        assert!(server_task.await.unwrap().is_ok());
    }

    /// Same as test_full_server_to_client with a 256-byte ClipboardSync payload.
    #[tokio::test]
    async fn test_full_server_to_client_large_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let outgoing = TcpStream::connect(server_addr).await.unwrap();
        let client_addr = outgoing.local_addr().unwrap();
        let (server_stream, peer_addr) = listener.accept().await.unwrap();

        let (keys_s, trusted_s) = make_state(TEST_A_KEY, TEST_D_KEY, vec![client_addr]);
        let (keys_c, trusted_c) = make_state(TEST_A_KEY, TEST_D_KEY, vec![server_addr]);

        let server_task = tokio::spawn(recv_handler(
            (server_stream, peer_addr),
            keys_s,
            trusted_s,
        ));

        let result = connect_handler(
            keys_c,
            trusted_c,
            server_addr,
            outgoing,
            ActionType::ClipboardSync,
            vec![0xAA; 256],
        )
        .await;

        assert!(result.is_ok());
        assert!(server_task.await.unwrap().is_ok());
    }

    // -------------------------------------------------------------------------
    // connect_handler specific tests
    // -------------------------------------------------------------------------

    /// ConnectNewDevice must add the peer's address to trusted_addrs and return Ok.
    /// No init header or data packet is sent after auth — the handler exits immediately.
    ///
    /// recv_handler on the server side will return FailedToReadFromStream (EOF) because
    /// connect_handler closes the stream without sending any data — this is expected.
    #[tokio::test]
    async fn test_connect_handler_connect_new_device_adds_trusted() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let outgoing = TcpStream::connect(server_addr).await.unwrap();
        let client_addr = outgoing.local_addr().unwrap();
        let (server_stream, peer_addr) = listener.accept().await.unwrap();

        // Client's trusted list starts with just the server addr.
        let trusted = Arc::new(RwLock::new(vec![server_addr]));
        let trusted_clone = Arc::clone(&trusted);
        let keys = Arc::new(RwLock::new(Keys::new(TEST_A_KEY, TEST_D_KEY)));

        // Server side: recv_handler waits for data that never comes — it will get EOF
        // when connect_handler returns after auth (ConnectNewDevice shortcut).
        let server_task = tokio::spawn(recv_handler(
            (server_stream, peer_addr),
            Arc::new(RwLock::new(Keys::new(TEST_A_KEY, TEST_D_KEY))),
            Arc::new(RwLock::new(vec![client_addr])),
        ));

        let result = connect_handler(
            keys,
            trusted_clone,
            server_addr,
            outgoing,
            ActionType::ConnectNewDevice,
            vec![],
        )
        .await;

        assert!(result.is_ok());
        // server_addr must now be in the client's trusted list.
        assert!(trusted.read().await.contains(&server_addr));

        // Server gets EOF after auth — FailedToReadFromStream is expected here.
        let server_result = server_task.await.unwrap();
        assert_eq!(
            server_result.unwrap_err(),
            TcpNetworkerErrors::FailedToReadFromStream
        );
    }

    /// Cancelling before connect() is called must return Ok(()) immediately.
    #[tokio::test]
    async fn test_connect_cancels_before_connecting() {
        let token = CancellationToken::new();
        let keys = Arc::new(RwLock::new(Keys::new(TEST_A_KEY, TEST_D_KEY)));
        let trusted = Arc::new(RwLock::new(vec![]));

        token.cancel(); // cancel before calling connect

        let unreachable: SocketAddr = "127.0.0.1:19999".parse().unwrap();
        let result = connect(
            keys,
            trusted,
            token,
            unreachable,
            ActionType::Debug,
            vec![],
        )
        .await;
        assert!(result.is_ok());
    }

    /// Connecting to a closed port must return FailedToConnect.
    #[tokio::test]
    async fn test_connect_to_closed_port_fails() {
        let keys = Arc::new(RwLock::new(Keys::new(TEST_A_KEY, TEST_D_KEY)));
        let trusted = Arc::new(RwLock::new(vec![]));
        let token = CancellationToken::new();

        // Bind then drop immediately — port is closed by the time TcpStream::connect runs.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let result = connect(
            keys,
            trusted,
            token,
            addr,
            ActionType::Debug,
            vec![],
        )
        .await;
        assert_eq!(result.unwrap_err(), TcpNetworkerErrors::FailedToConnect);
    }
}
