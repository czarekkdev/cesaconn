use cesa_conn_crypto::aes::{decrypt, encrypt};
use cesa_conn_crypto::ecdh::{
    calculate_public_key, calculate_shared_key, generate_private_key, hash_key,
};
use core::net::SocketAddr;
use std::fmt;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::{io::AsyncReadExt, net::TcpStream, sync::RwLock};
use tracing::{debug, error, info, warn};
use zeroize::Zeroize;
use zeroize::Zeroizing;

/// All errors that can occur during authentication.
#[derive(Debug, PartialEq)]
pub enum AuthErrors {
    /// The TCP stream ended or errored before we could read all expected bytes.
    FailedToReadFromStream,
    /// AES-GCM decryption failed — wrong shared secret or tampered data.
    FailedToDecrypt,
    /// The TCP stream errored while sending data to the client.
    FailedToWriteToStream,
    /// Failed to encrypt the authentication key.
    FailedToEncrypt,
}

impl fmt::Display for AuthErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthErrors::FailedToReadFromStream => {
                write!(f, "failed to read authentication key from stream")
            }
            AuthErrors::FailedToDecrypt => write!(f, "failed to decrypt authentication key"),
            AuthErrors::FailedToWriteToStream => write!(f, "failed to write to stream"),
            AuthErrors::FailedToEncrypt => write!(f, "failed to encrypt authentication key"),
        }
    }
}

/// Holds the two pre-shared 32-byte keys used by the networker.
///
/// * `a_key` — authentication key, verified during the ECDH handshake.
/// * `d_key` — data key, used for the inner encryption layer on actual payloads.
///
/// Both fields are wrapped in `Zeroizing` so they are wiped from memory on drop.
pub struct Keys {
    pub a_key: Zeroizing<[u8; 32]>,
    pub d_key: Zeroizing<[u8; 32]>,
}

impl Keys {
    // /// Splits a packed 64-byte buffer into the two keys (`a_key` = bytes 0–31, `d_key` = bytes 32–63).
    // pub fn from_ref(data: &[u8; 64]) -> Self {
    //     let mut a_key_bytes = Zeroizing::new([0u8; 32]);
    //     let mut d_key_bytes = Zeroizing::new([0u8; 32]);

    //     a_key_bytes.copy_from_slice(&data[..32]);
    //     d_key_bytes.copy_from_slice(&data[32..]);

    //     Self {
    //         a_key: a_key_bytes,
    //         d_key: d_key_bytes,
    //     }
    // }

    // /// Packs both keys into `data` (`a_key` in bytes 0–31, `d_key` in bytes 32–63). Inverse of `from_ref`.
    // pub fn to_ref(&self, data: &mut [u8; 64]) {
    //     data[..32].copy_from_slice(&*self.a_key);
    //     data[32..].copy_from_slice(&*self.d_key);
    // }

    /// Wraps two raw 32-byte arrays in `Zeroizing` so they are wiped from memory on drop.
    pub fn new(a_key: [u8; 32], d_key: [u8; 32]) -> Self {
        Self {
            a_key: Zeroizing::new(a_key),
            d_key: Zeroizing::new(d_key),
        }
    }
}

/// Decrypts a tunnel message produced by `encrypt_tunnel`.
/// Expects the input to be: nonce (12 bytes) + AES-GCM ciphertext (N bytes).
pub fn decrypt_tunnel(shared_key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, AuthErrors> {
    let nonce = &mut [0u8; 12];
    nonce.copy_from_slice(&ciphertext[..12]);

    decrypt(shared_key, &ciphertext[12..], nonce).map_err(|e| {
        error!(error = %e, ciphertext_len = ciphertext.len(), "AES-256-GCM decryption failed in decrypt_tunnel");
        AuthErrors::FailedToDecrypt
    })
}

/// Encrypts plaintext and returns: nonce (12 bytes) + AES-GCM ciphertext (N+16 bytes).
/// The nonce is randomly generated — output is different every call even for the same input.
pub fn encrypt_tunnel(shared_key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, AuthErrors> {
    let (encrypted_data, nonce) =
        encrypt(shared_key, plaintext).map_err(|e| {
            error!(error = %e, plaintext_len = plaintext.len(), "AES-256-GCM encryption failed in encrypt_tunnel");
            AuthErrors::FailedToEncrypt
        })?;
    Ok([nonce.to_vec(), encrypted_data].concat())
}

/// TODO: add data signing to the handshake for stronger authentication
/// Authenticates an incoming TCP connection using ECDH key exchange + pre-shared key verification.
///
/// Handshake sequence:
///   1. Client → Server: client's X25519 ephemeral public key (32 bytes)
///   2. Server → Client: server's X25519 ephemeral public key (32 bytes)
///   3. Client → Server: nonce (12 bytes) + AES-256-GCM ciphertext (48 bytes) = 60 bytes total
///      - Client encrypts the pre-shared key using SHA-256(ECDH shared secret) as the AES key
///   4. Server → Client: nonce (12 bytes) + AES-256-GCM ciphertext (48 bytes) = 60 bytes total
///      - Server encrypts the same pre-shared key back so the client can verify the server knows it too
///   5. Client → Server: nonce (12 bytes) + AES-256-GCM ciphertext (17 bytes) = 29 bytes total
///      - Client encrypts a single confirmation byte (0x01 = verified) using the session key
///
/// Both sides prove they know the pre-shared key, so neither can impersonate the other.
///
/// Returns (authenticated, shared_key_hash).
/// The caller should use shared_key_hash as the session encryption key for all further communication.
pub async fn auth_incoming(
    keys: Arc<RwLock<Keys>>,
    trusted_addrs: Arc<RwLock<Vec<SocketAddr>>>,
    incoming_connection: (&mut TcpStream, SocketAddr),
) -> Result<(bool, [u8; 32]), AuthErrors> {
    let peer_addr = incoming_connection.1;

    // Step 1: IP allowlist check — reject unknown peers before doing any crypto work
    if !trusted_addrs
        .read()
        .await
        .iter()
        .any(|addr| addr.ip() == peer_addr.ip())
    {
        warn!(%peer_addr, "received connection from untrusted address, rejecting");
        return Ok((false, [0u8; 32]));
    }

    info!(%peer_addr, "received connection from trusted address, starting ECDH handshake");

    // Step 2: Read the client's X25519 ephemeral public key (always exactly 32 bytes)
    let their_pub_key = &mut [0u8; 32];

    debug!(%peer_addr, "reading client ephemeral X25519 public key (32 bytes)");
    incoming_connection
        .0
        .read_exact(their_pub_key)
        .await
        .map_err(|e| {
            error!(%peer_addr, error = %e, "failed to read client's X25519 public key from stream");
            AuthErrors::FailedToReadFromStream
        })?;

    // An all-zero public key is cryptographically invalid — reject it
    if their_pub_key == &[0u8; 32] {
        warn!(%peer_addr, "received all-zero X25519 public key (invalid), rejecting");
        return Ok((false, [0u8; 32]));
    }

    // Step 3: Generate our ephemeral keypair and derive the shared secret
    // private_key is marked &mut so we can zeroize it from memory after use
    debug!(%peer_addr, "generating ephemeral X25519 keypair and deriving shared secret");
    let private_key = &mut generate_private_key();
    let public_key = &mut calculate_public_key(&private_key);
    let shared_key = &mut calculate_shared_key(&private_key, their_pub_key);

    // Hash the raw ECDH output before using it as an AES key — raw shared secrets
    // are not uniformly distributed and must not be used directly
    let shared_key_hash = hash_key(&shared_key);
    debug!(%peer_addr, "ECDH shared secret derived and hashed with SHA-256");

    // Wipe private key and raw shared secret from memory immediately — they're no longer needed
    private_key.zeroize();
    shared_key.zeroize();

    // Step 3b: Send our public key to the client so they can compute the same shared secret
    debug!(%peer_addr, "sending server ephemeral X25519 public key (32 bytes)");
    incoming_connection
        .0
        .write_all(public_key)
        .await
        .map_err(|e| {
            error!(%peer_addr, error = %e, "failed to write server's X25519 public key to stream");
            AuthErrors::FailedToWriteToStream
        })?;

    public_key.zeroize(); // wipe our public key from memory — already sent, not needed anymore

    // Step 4: Read the client's encrypted pre-shared key
    // Layout: [ nonce (12 bytes) | AES-GCM ciphertext (48 bytes) ] = 60 bytes total
    // Ciphertext = encrypt(pre_shared_key[32 bytes]) → 32 + 16 (GCM tag) = 48 bytes
    let e_key_buf = &mut [0u8; 60];

    debug!(%peer_addr, "reading client's encrypted pre-shared key (60 bytes)");
    incoming_connection
        .0
        .read_exact(e_key_buf)
        .await
        .map_err(|e| {
            error!(%peer_addr, error = %e, "failed to read client's encrypted pre-shared key from stream");
            AuthErrors::FailedToReadFromStream
        })?;

    // Step 5: Decrypt using the hashed shared key — GCM also verifies integrity,
    // so any tampering or wrong key causes an error here
    debug!(%peer_addr, "decrypting client's pre-shared key with session key");
    let key_buf = &mut decrypt_tunnel(&shared_key_hash, e_key_buf)
        .map_err(|e| {
            warn!(%peer_addr, error = %e, "failed to decrypt client's pre-shared key — wrong ECDH secret or tampered data");
            AuthErrors::FailedToDecrypt
        })?;

    // Wipe the encrypted buffer and nonce — plaintext key is now in key_buf
    e_key_buf.zeroize();

    // Step 6: Compare decrypted key against the expected pre-shared key
    if key_buf != keys.read().await.a_key.as_ref() {
        warn!(%peer_addr, "pre-shared key mismatch — client sent wrong key, rejecting connection");
        key_buf.zeroize();
        return Ok((false, [0u8; 32]));
    }

    // Wipe the decrypted key now that comparison is done
    key_buf.zeroize();
    debug!(%peer_addr, "client pre-shared key verified successfully");

    // Step 7: Encrypt our pre-shared key and send it back — mutual authentication,
    // client will verify we know the same key
    debug!(%peer_addr, "encrypting server pre-shared key echo (60 bytes)");
    let send_buf = &mut encrypt_tunnel(&shared_key_hash, keys.read().await.a_key.as_ref())
        .map_err(|e| {
            error!(%peer_addr, error = %e, "failed to encrypt server's pre-shared key echo");
            AuthErrors::FailedToEncrypt
        })?;

    debug!(%peer_addr, "sending server pre-shared key echo (60 bytes)");
    incoming_connection
        .0
        .write_all(send_buf)
        .await
        .map_err(|e| {
            error!(%peer_addr, error = %e, "failed to write server's pre-shared key echo to stream");
            AuthErrors::FailedToWriteToStream
        })?;

    // Wipe sensitive data — key material no longer needed
    send_buf.zeroize();

    // Step 8: Read the encrypted confirmation from the client (29 bytes)
    // Layout: [ nonce (12 bytes) | AES-GCM ciphertext (17 bytes) ] — plaintext is 1 byte (0x01 = verified)
    // Client encrypts with shared_key_hash: 1 byte plaintext + 16 GCM tag = 17 bytes ciphertext
    let e_confirmation_byte = &mut [0u8; 29]; // 12 nonce + 1 plaintext + 16 GCM tag = 29 bytes total

    debug!(%peer_addr, "reading client confirmation byte (29 bytes)");
    incoming_connection
        .0
        .read_exact(e_confirmation_byte)
        .await
        .map_err(|e| {
            error!(%peer_addr, error = %e, "failed to read client's confirmation byte from stream");
            AuthErrors::FailedToReadFromStream
        })?;

    let confirmation_byte =
        &mut decrypt_tunnel(&shared_key_hash, e_confirmation_byte).map_err(|e| {
            warn!(%peer_addr, error = %e, "failed to decrypt client's confirmation byte");
            AuthErrors::FailedToDecrypt
        })?;

    e_confirmation_byte.zeroize(); // wipe encrypted confirmation byte

    if confirmation_byte != &[1u8] {
        warn!(%peer_addr, "client rejected our key confirmation (sent 0x00), authentication failed");
        confirmation_byte.zeroize();
        return Ok((false, [0u8; 32]));
    }

    confirmation_byte.zeroize(); // wipe confirmation byte from memory

    info!(%peer_addr, "incoming authentication successful, ephemeral session key established");

    // Return authentication result and the shared_key_hash for use as the session encryption key
    Ok((true, shared_key_hash))
}

/// TODO: add data signing to the handshake for stronger authentication
/// Authenticates an outgoing TCP connection using ECDH key exchange + pre-shared key verification.
/// This is the client-side mirror of `auth_incoming`.
///
/// Handshake sequence:
///   1. Client → Server: client's X25519 ephemeral public key (32 bytes)
///   2. Server → Client: server's X25519 ephemeral public key (32 bytes)
///   3. Client → Server: nonce (12 bytes) + AES-256-GCM ciphertext (48 bytes) = 60 bytes total
///      - Client encrypts the pre-shared key using SHA-256(ECDH shared secret) as the AES key
///   4. Server → Client: nonce (12 bytes) + AES-256-GCM ciphertext (48 bytes) = 60 bytes total
///      - Server encrypts the same pre-shared key back so the client can verify it
///   5. Client → Server: nonce (12 bytes) + AES-256-GCM ciphertext (17 bytes) = 29 bytes total
///      - Client encrypts a single confirmation byte using the session key
///      - 0x01 = verified, 0x00 = rejected (client sends rejection byte before closing)
///
/// Returns (authenticated, shared_key_hash).
/// The caller should use shared_key_hash as the session encryption key for all further communication.
pub async fn auth_outgoing(
    keys: Arc<RwLock<Keys>>,
    trusted_addrs: Arc<RwLock<Vec<SocketAddr>>>,
    outgoing_connection: (&mut TcpStream, SocketAddr),
) -> Result<(bool, [u8; 32]), AuthErrors> {
    let peer_addr = outgoing_connection.1;

    // Step 1: IP allowlist check — don't initiate crypto work with unknown peers
    if !trusted_addrs
        .read()
        .await
        .iter()
        .any(|addr| addr.ip() == peer_addr.ip())
    {
        warn!(%peer_addr, "attempted to connect to untrusted address, rejecting");
        return Ok((false, [0u8; 32]));
    }

    info!(%peer_addr, "initiating outgoing connection to trusted peer, starting ECDH handshake");

    // Step 2: Generate our ephemeral keypair and send our public key to the server
    debug!(%peer_addr, "generating ephemeral X25519 keypair");
    let private_key = &mut generate_private_key();
    let public_key = &mut calculate_public_key(&private_key);

    debug!(%peer_addr, "sending client ephemeral X25519 public key (32 bytes)");
    outgoing_connection
        .0
        .write_all(public_key)
        .await
        .map_err(|e| {
            error!(%peer_addr, error = %e, "failed to write client's X25519 public key to stream");
            AuthErrors::FailedToWriteToStream
        })?;

    public_key.zeroize(); // wipe our public key from memory — already sent, not needed anymore

    // Step 3: Read the server's ephemeral public key (always exactly 32 bytes)
    let their_pub_key = &mut [0u8; 32];

    debug!(%peer_addr, "reading server ephemeral X25519 public key (32 bytes)");
    outgoing_connection
        .0
        .read_exact(their_pub_key)
        .await
        .map_err(|e| {
            error!(%peer_addr, error = %e, "failed to read server's X25519 public key from stream");
            AuthErrors::FailedToReadFromStream
        })?;

    // Step 4: Derive the shared secret and hash it for use as an AES key
    // Hash the raw ECDH output — raw shared secrets are not uniformly distributed
    debug!(%peer_addr, "computing ECDH X25519 shared secret and hashing with SHA-256");
    let shared_key = &mut calculate_shared_key(&private_key, their_pub_key);

    let shared_key_hash = hash_key(&shared_key);

    // Wipe private key and raw shared secret — no longer needed
    private_key.zeroize();
    shared_key.zeroize();

    // Step 5: Encrypt and send our pre-shared key to the server for verification
    debug!(%peer_addr, "encrypting client pre-shared key for server verification");
    let e_key_buf = &mut encrypt_tunnel(&shared_key_hash, keys.read().await.a_key.as_ref())
        .map_err(|e| {
            error!(%peer_addr, error = %e, "failed to encrypt client's pre-shared key");
            AuthErrors::FailedToEncrypt
        })?;

    debug!(%peer_addr, "sending client encrypted pre-shared key (60 bytes)");
    outgoing_connection
        .0
        .write_all(e_key_buf)
        .await
        .map_err(|e| {
            error!(%peer_addr, error = %e, "failed to write client's encrypted pre-shared key to stream");
            AuthErrors::FailedToWriteToStream
        })?;

    e_key_buf.zeroize();

    // Step 6: Read the server's encrypted pre-shared key back (60 bytes)
    // Layout: [ nonce (12 bytes) | AES-GCM ciphertext (48 bytes) ]
    let recv_e_key_buf = &mut [0u8; 60];

    debug!(%peer_addr, "reading server pre-shared key echo (60 bytes)");
    outgoing_connection
        .0
        .read_exact(recv_e_key_buf)
        .await
        .map_err(|e| {
            error!(%peer_addr, error = %e, "failed to read server's pre-shared key echo from stream");
            AuthErrors::FailedToReadFromStream
        })?;

    // Step 7: Decrypt the server's response — GCM verifies integrity, wrong key = error
    debug!(%peer_addr, "decrypting server's pre-shared key echo");
    let recv_key_buf = &mut decrypt_tunnel(&shared_key_hash, recv_e_key_buf)
        .map_err(|e| {
            warn!(%peer_addr, error = %e, "failed to decrypt server's pre-shared key echo — wrong key or tampered data");
            AuthErrors::FailedToDecrypt
        })?;

    recv_e_key_buf.zeroize();

    let confirmation_byte = &mut [1u8];

    // Step 8: Compare the server's key against our expected pre-shared key
    if recv_key_buf != keys.read().await.a_key.as_ref() {
        warn!(%peer_addr, "server returned wrong pre-shared key during outgoing handshake, sending rejection (0x00)");
        confirmation_byte.fill(0u8); // prepare to send rejection byte
    }

    recv_key_buf.zeroize();

    // Step 9: Encrypt the confirmation byte (0x01) with the session key and send it
    // Server reads 29 bytes: [ nonce (12) | AES-GCM ciphertext (17) ]
    debug!(%peer_addr, "encrypting and sending confirmation byte (29 bytes)");
    let e_confirmation_byte =
        &mut encrypt_tunnel(&shared_key_hash, confirmation_byte).map_err(|e| {
            error!(%peer_addr, error = %e, "failed to encrypt confirmation byte");
            AuthErrors::FailedToEncrypt
        })?;

    outgoing_connection
        .0
        .write_all(&e_confirmation_byte)
        .await
        .map_err(|e| {
            error!(%peer_addr, error = %e, "failed to write confirmation byte to stream");
            AuthErrors::FailedToWriteToStream
        })?;

    // Capture result before zeroizing — comparison after zeroize would always read [0u8]
    let rejected = confirmation_byte == &[0u8];

    // Wipe key material regardless of outcome
    e_confirmation_byte.zeroize();
    confirmation_byte.zeroize();

    if rejected {
        warn!(%peer_addr, "outgoing authentication rejected — server key mismatch confirmed, connection closed");
        // Encrypted rejection (0x00) was sent — connection closes after return
        return Ok((false, [0u8; 32]));
    }

    info!(%peer_addr, "outgoing authentication successful, ephemeral session key established");
    Ok((true, shared_key_hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cesa_conn_crypto::aes::encrypt;
    use cesa_conn_crypto::ecdh::{
        calculate_public_key, calculate_shared_key, generate_private_key, hash_key,
    };
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;
    use tokio::time::{Duration, timeout};

    const TEST_KEY: [u8; 32] = [0xAB; 32];

    /// Spins up a TCP listener, connects a client, returns (server_stream, client_stream, peer_addr)
    async fn setup_tcp_pair() -> (TcpStream, TcpStream, SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, peer_addr) = listener.accept().await.unwrap();
        (server, client, peer_addr)
    }

    /// Wraps `key` in a `Keys` struct (with `d_key` zeroed) and `trusted` in `Arc<RwLock<_>>`
    /// to match the signatures of `auth_incoming` and `auth_outgoing`.
    fn make_shared_state(
        key: [u8; 32],
        trusted: Vec<SocketAddr>,
    ) -> (Arc<RwLock<Keys>>, Arc<RwLock<Vec<SocketAddr>>>) {
        (
            Arc::new(RwLock::new(Keys::new(key, [0u8; 32]))),
            Arc::new(RwLock::new(trusted)),
        )
    }

    // -------------------------------------------------------------------------
    // Keys struct unit tests
    // -------------------------------------------------------------------------

    /// Keys::new must store both raw arrays verbatim inside Zeroizing wrappers.
    #[test]
    fn test_keys_new() {
        let a = [0xAAu8; 32];
        let d = [0xDDu8; 32];
        let keys = Keys::new(a, d);
        assert_eq!(*keys.a_key, a);
        assert_eq!(*keys.d_key, d);
    }

    // /// Keys::from_ref must split the 64-byte buffer: bytes 0–31 → a_key, bytes 32–63 → d_key.
    // #[test]
    // fn test_keys_from_ref() {
    //     let mut buf = [0u8; 64];
    //     buf[..32].fill(0xAA);
    //     buf[32..].fill(0xDD);
    //     let keys = Keys::from_ref(&buf);
    //     assert_eq!(*keys.a_key, [0xAAu8; 32]);
    //     assert_eq!(*keys.d_key, [0xDDu8; 32]);
    // }

    // /// Keys::to_ref must write a_key into bytes 0–31 and d_key into bytes 32–63.
    // #[test]
    // fn test_keys_to_ref() {
    //     let keys = Keys::new([0xAAu8; 32], [0xDDu8; 32]);
    //     let mut out = [0u8; 64];
    //     keys.to_ref(&mut out);
    //     assert_eq!(&out[..32], &[0xAAu8; 32]);
    //     assert_eq!(&out[32..], &[0xDDu8; 32]);
    // }

    // /// from_ref then to_ref must reproduce the original 64-byte buffer exactly (round-trip).
    // #[test]
    // fn test_keys_roundtrip() {
    //     let mut original = [0u8; 64];
    //     for (i, b) in original.iter_mut().enumerate() {
    //         *b = i as u8;
    //     }
    //     let keys = Keys::from_ref(&original);
    //     let mut out = [0u8; 64];
    //     keys.to_ref(&mut out);
    //     assert_eq!(out, original);
    // }

    // /// Keys::from_ref with all-zero input must produce two zero keys, not panic.
    // #[test]
    // fn test_keys_from_ref_all_zeros() {
    //     let buf = [0u8; 64];
    //     let keys = Keys::from_ref(&buf);
    //     assert_eq!(*keys.a_key, [0u8; 32]);
    //     assert_eq!(*keys.d_key, [0u8; 32]);
    // }

    /// a_key and d_key may be identical — Keys::new must not deduplicate them.
    #[test]
    fn test_keys_new_same_values() {
        let k = [0x42u8; 32];
        let keys = Keys::new(k, k);
        assert_eq!(*keys.a_key, k);
        assert_eq!(*keys.d_key, k);
    }

    /// Connection from an address not in the trusted list must be rejected immediately.
    #[tokio::test]
    async fn test_untrusted_addr_rejected() {
        let (mut server, _client, peer_addr) = setup_tcp_pair().await;
        let (key, trusted) = make_shared_state(TEST_KEY, vec![]);

        let result = auth_incoming(key, trusted, (&mut server, peer_addr)).await;
        assert_eq!(result.unwrap(), (false, [0u8; 32]));
    }

    /// An all-zero public key is invalid and must be rejected after reading.
    #[tokio::test]
    async fn test_zero_pubkey_rejected() {
        let (mut server, mut client, peer_addr) = setup_tcp_pair().await;
        let (key, trusted) = make_shared_state(TEST_KEY, vec![peer_addr]);

        client.write_all(&[0u8; 32]).await.unwrap();

        let result = auth_incoming(key, trusted, (&mut server, peer_addr)).await;
        assert_eq!(result.unwrap(), (false, [0u8; 32]));
    }

    /// Stream closing before sending a full public key must return FailedToReadFromStream.
    #[tokio::test]
    async fn test_incomplete_pubkey_returns_error() {
        let (mut server, mut client, peer_addr) = setup_tcp_pair().await;
        let (key, trusted) = make_shared_state(TEST_KEY, vec![peer_addr]);

        client.write_all(&[0xAB; 10]).await.unwrap();
        drop(client); // close stream early

        let result = auth_incoming(key, trusted, (&mut server, peer_addr)).await;
        assert_eq!(result.unwrap_err(), AuthErrors::FailedToReadFromStream);
    }

    /// Stream closing after pubkey exchange but before sending the full 60-byte encrypted payload
    /// must return FailedToReadFromStream.
    /// Client reads server pubkey first to avoid a race where the server's write fails instead.
    #[tokio::test]
    async fn test_incomplete_encrypted_payload_returns_error() {
        let (mut server, mut client, peer_addr) = setup_tcp_pair().await;
        let (key, trusted) = make_shared_state(TEST_KEY, vec![peer_addr]);

        let client_task = tokio::spawn(async move {
            let client_priv = generate_private_key();
            let client_pub = calculate_public_key(&client_priv);

            // Send our pubkey so server can proceed to send its own
            client.write_all(&client_pub).await.unwrap();

            // Read server's pubkey so the server's write_all doesn't fail
            client.read_exact(&mut [0u8; 32]).await.unwrap();

            // Send only 20 of the required 60 bytes then close
            client.write_all(&[0xAB; 20]).await.unwrap();
            drop(client);
        });

        let result = auth_incoming(key, trusted, (&mut server, peer_addr)).await;
        client_task.await.unwrap();

        assert_eq!(result.unwrap_err(), AuthErrors::FailedToReadFromStream);
    }

    /// Sending garbage bytes as the encrypted payload must fail decryption (GCM tag mismatch).
    /// Client reads server pubkey first so the server's write doesn't race with the decrypt error.
    #[tokio::test]
    async fn test_invalid_ciphertext_returns_decrypt_error() {
        let (mut server, mut client, peer_addr) = setup_tcp_pair().await;
        let (key, trusted) = make_shared_state(TEST_KEY, vec![peer_addr]);

        let client_task = tokio::spawn(async move {
            let client_priv = generate_private_key();
            let client_pub = calculate_public_key(&client_priv);

            client.write_all(&client_pub).await.unwrap();

            // Read server pubkey so its write_all doesn't error before we send garbage
            client.read_exact(&mut [0u8; 32]).await.unwrap();

            client.write_all(&[0xDE; 60]).await.unwrap(); // garbage — GCM tag will fail
        });

        let result = auth_incoming(key, trusted, (&mut server, peer_addr)).await;
        client_task.await.unwrap();

        assert_eq!(result.unwrap_err(), AuthErrors::FailedToDecrypt);
    }

    /// Simulates the full client side of the handshake.
    /// Returns true if the server's key confirmation matched, false otherwise.
    async fn run_client(mut stream: TcpStream, auth_key: [u8; 32]) -> bool {
        let client_priv = generate_private_key();
        let client_pub = calculate_public_key(&client_priv);

        // Step 1: send our ephemeral public key
        stream.write_all(&client_pub).await.unwrap();

        // Step 2: read server's ephemeral public key
        let server_pub = &mut [0u8; 32];
        stream.read_exact(server_pub).await.unwrap();

        // Step 3: derive shared secret and encrypt our copy of the auth key
        let shared = calculate_shared_key(&client_priv, server_pub);
        let shared_hash = hash_key(&shared);
        let payload = encrypt_tunnel(&shared_hash, &auth_key).unwrap();
        stream.write_all(&payload).await.unwrap();

        // Step 4: read server's encrypted key back — EOF here means server rejected us
        let recv_buf = &mut [0u8; 60];
        if stream.read_exact(recv_buf).await.is_err() {
            return false;
        }

        let recv_plaintext = match decrypt_tunnel(&shared_hash, recv_buf) {
            Ok(p) => p,
            Err(_) => return false, // server sent something we can't decrypt
        };

        // Step 5: encrypt and send the confirmation byte (29 bytes: 12 nonce + 1 byte + 16 GCM tag)
        // 0x01 = verified, 0x00 = rejected — encrypted with session key to match server's read_exact(29)
        let confirmed = recv_plaintext == auth_key;
        let conf_byte = [if confirmed { 0x01u8 } else { 0x00u8 }];
        let e_conf = encrypt_tunnel(&shared_hash, &conf_byte).unwrap();
        stream.write_all(&e_conf).await.unwrap();

        confirmed
    }

    /// encrypt_tunnel output must be decryptable by decrypt_tunnel and produce the original data.
    #[test]
    fn test_tunnel_roundtrip() {
        let key = [0x42u8; 32];
        let plaintext = b"hello tunnel";

        let encrypted = encrypt_tunnel(&key, plaintext).unwrap();
        let decrypted = decrypt_tunnel(&key, &encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    /// decrypt_tunnel with a wrong key must fail (GCM tag mismatch).
    #[test]
    fn test_tunnel_wrong_key_fails() {
        let key = [0x42u8; 32];
        let wrong_key = [0xFFu8; 32];

        let encrypted = encrypt_tunnel(&key, b"secret").unwrap();
        assert!(decrypt_tunnel(&wrong_key, &encrypted).is_err());
    }

    /// encrypt_tunnel must produce different ciphertext each call (random nonce).
    #[test]
    fn test_tunnel_nonce_is_random() {
        let key = [0x42u8; 32];
        let plaintext = b"same data";

        let e1 = encrypt_tunnel(&key, plaintext).unwrap();
        let e2 = encrypt_tunnel(&key, plaintext).unwrap();

        assert_ne!(e1, e2);
    }

    /// Correct pre-shared key and trusted address must result in successful authentication
    /// on both sides — server returns true, client confirms the server's response.
    /// Also verifies the returned shared key hash is valid (non-zero).
    #[tokio::test]
    async fn test_correct_key_auth_success() {
        let (mut server, client, peer_addr) = setup_tcp_pair().await;
        let (key, trusted) = make_shared_state(TEST_KEY, vec![peer_addr]);

        // Server and client must run concurrently — both block waiting for the other
        let client_task = tokio::spawn(run_client(client, TEST_KEY));
        let result = auth_incoming(key, trusted, (&mut server, peer_addr)).await;
        let client_confirmed = client_task.await.unwrap();

        let (authenticated, shared_key_hash) = result.unwrap();
        assert!(authenticated);
        assert!(client_confirmed);
        // Shared key hash must be non-zero — zeroed key means ECDH failed silently
        assert_ne!(shared_key_hash, [0u8; 32]);
    }

    /// Wrong pre-shared key — server rejects during key comparison and returns early.
    /// The server stream (owned by the test) is dropped after auth_incoming returns,
    /// which closes the connection and lets the client detect rejection via read error.
    #[tokio::test]
    async fn test_wrong_key_server_rejects() {
        let (mut server, client, peer_addr) = setup_tcp_pair().await;
        let (key, trusted) = make_shared_state(TEST_KEY, vec![peer_addr]);

        let wrong_key = [0xFFu8; 32];
        let client_task = tokio::spawn(timeout(
            Duration::from_secs(5),
            run_client(client, wrong_key),
        ));
        let result = auth_incoming(key, trusted, (&mut server, peer_addr)).await;

        // Drop server stream explicitly so the client's read_exact gets an EOF
        drop(server);

        let client_confirmed = client_task.await.unwrap().unwrap();

        assert_eq!(result.unwrap(), (false, [0u8; 32]));
        assert!(!client_confirmed);
    }

    /// Client sends the correct key but then rejects the server's confirmation (sends 0x00).
    /// Server should return false after reading the zero confirmation byte.
    #[tokio::test]
    async fn test_client_rejects_server_confirmation() {
        let (mut server, mut client, peer_addr) = setup_tcp_pair().await;
        let (key, trusted) = make_shared_state(TEST_KEY, vec![peer_addr]);

        let client_task = tokio::spawn(async move {
            let client_priv = generate_private_key();
            let client_pub = calculate_public_key(&client_priv);

            client.write_all(&client_pub).await.unwrap();

            let server_pub = &mut [0u8; 32];
            client.read_exact(server_pub).await.unwrap();

            let shared = calculate_shared_key(&client_priv, server_pub);
            let shared_hash = hash_key(&shared);
            let (ciphertext, nonce) = encrypt(&shared_hash, &TEST_KEY).unwrap();
            client.write_all(&nonce).await.unwrap();
            client.write_all(&ciphertext).await.unwrap();

            // Read server's key response (60 bytes) so its write_all doesn't fail
            let _ = client.read_exact(&mut [0u8; 60]).await;

            // Encrypt and send 0x00 confirmation — server reads 29 bytes (nonce + ciphertext)
            let e_conf = encrypt_tunnel(&shared_hash, &[0x00u8]).unwrap();
            client.write_all(&e_conf).await.unwrap();
        });

        let result = auth_incoming(key, trusted, (&mut server, peer_addr)).await;
        client_task.await.unwrap();

        assert_eq!(result.unwrap(), (false, [0u8; 32]));
    }

    /// Client completes the full handshake correctly but closes the connection instead of
    /// sending the confirmation byte — server must return FailedToReadFromStream.
    #[tokio::test]
    async fn test_confirmation_byte_missing() {
        let (mut server, mut client, peer_addr) = setup_tcp_pair().await;
        let (key, trusted) = make_shared_state(TEST_KEY, vec![peer_addr]);

        let client_task = tokio::spawn(async move {
            let client_priv = generate_private_key();
            let client_pub = calculate_public_key(&client_priv);

            client.write_all(&client_pub).await.unwrap();

            let server_pub = &mut [0u8; 32];
            client.read_exact(server_pub).await.unwrap();

            let shared = calculate_shared_key(&client_priv, server_pub);
            let shared_hash = hash_key(&shared);
            let (ciphertext, nonce) = encrypt(&shared_hash, &TEST_KEY).unwrap();
            client.write_all(&nonce).await.unwrap();
            client.write_all(&ciphertext).await.unwrap();

            // Read server's confirmation payload so its write_all doesn't fail
            client.read_exact(&mut [0u8; 60]).await.unwrap();

            // Close without sending the confirmation byte
            drop(client);
        });

        let result = auth_incoming(key, trusted, (&mut server, peer_addr)).await;
        client_task.await.unwrap();

        assert_eq!(result.unwrap_err(), AuthErrors::FailedToReadFromStream);
    }

    /// Each successful auth must produce a different shared key because ephemeral keys are
    /// generated fresh per connection.
    #[tokio::test]
    async fn test_shared_key_unique_per_session() {
        let (mut server1, client1, peer_addr1) = setup_tcp_pair().await;
        let (mut server2, client2, peer_addr2) = setup_tcp_pair().await;
        let (key1, trusted1) = make_shared_state(TEST_KEY, vec![peer_addr1]);
        let (key2, trusted2) = make_shared_state(TEST_KEY, vec![peer_addr2]);

        let t1 = tokio::spawn(run_client(client1, TEST_KEY));
        let t2 = tokio::spawn(run_client(client2, TEST_KEY));

        let r1 = auth_incoming(key1, trusted1, (&mut server1, peer_addr1)).await;
        let r2 = auth_incoming(key2, trusted2, (&mut server2, peer_addr2)).await;

        t1.await.unwrap();
        t2.await.unwrap();

        let (_, hash1) = r1.unwrap();
        let (_, hash2) = r2.unwrap();

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_error_display_read() {
        assert_eq!(
            AuthErrors::FailedToReadFromStream.to_string(),
            "failed to read authentication key from stream"
        );
    }

    #[test]
    fn test_error_display_decrypt() {
        assert_eq!(
            AuthErrors::FailedToDecrypt.to_string(),
            "failed to decrypt authentication key"
        );
    }

    #[test]
    fn test_error_display_write() {
        assert_eq!(
            AuthErrors::FailedToWriteToStream.to_string(),
            "failed to write to stream"
        );
    }

    #[test]
    fn test_error_display_encrypt() {
        assert_eq!(
            AuthErrors::FailedToEncrypt.to_string(),
            "failed to encrypt authentication key"
        );
    }

    // -------------------------------------------------------------------------
    // auth_outgoing tests
    // -------------------------------------------------------------------------

    /// Connecting to an address not in the trusted list must be rejected immediately.
    #[tokio::test]
    async fn test_outgoing_untrusted_addr_rejected() {
        let (mut _server, mut client, peer_addr) = setup_tcp_pair().await;
        let (key, trusted) = make_shared_state(TEST_KEY, vec![]); // empty trusted list

        let result = auth_outgoing(key, trusted, (&mut client, peer_addr)).await;
        assert_eq!(result.unwrap(), (false, [0u8; 32]));
    }

    /// Stream closes before the server sends its public key — must return FailedToReadFromStream.
    #[tokio::test]
    async fn test_outgoing_stream_closes_before_server_pubkey() {
        let (server, mut client, peer_addr) = setup_tcp_pair().await;
        let (key, trusted) = make_shared_state(TEST_KEY, vec![peer_addr]);

        // Drop server immediately — client's read_exact for server pubkey will fail
        drop(server);

        let result = auth_outgoing(key, trusted, (&mut client, peer_addr)).await;
        assert_eq!(result.unwrap_err(), AuthErrors::FailedToReadFromStream);
    }

    /// Server sends garbage as its confirmation payload — decryption must fail.
    #[tokio::test]
    async fn test_outgoing_invalid_server_confirmation_fails_decrypt() {
        let (mut server, mut client, peer_addr) = setup_tcp_pair().await;
        let (key, trusted) = make_shared_state(TEST_KEY, vec![peer_addr]);

        let server_task = tokio::spawn(async move {
            let client_pub = &mut [0u8; 32];
            server.read_exact(client_pub).await.unwrap();

            // Send a valid-looking server pubkey so client can proceed
            let priv_key = generate_private_key();
            let pub_key = calculate_public_key(&priv_key);
            server.write_all(&pub_key).await.unwrap();

            // Read client's encrypted key so its write_all doesn't error
            server.read_exact(&mut [0u8; 60]).await.unwrap();

            // Send 60 bytes of garbage instead of a valid encrypted key
            server.write_all(&[0xDE; 60]).await.unwrap();
        });

        let result = auth_outgoing(key, trusted, (&mut client, peer_addr)).await;
        server_task.await.unwrap();

        assert_eq!(result.unwrap_err(), AuthErrors::FailedToDecrypt);
    }

    /// Server sends a correctly encrypted but wrong key back — client must send 0x00 and return false.
    #[tokio::test]
    async fn test_outgoing_server_returns_wrong_key() {
        let (mut server, mut client, peer_addr) = setup_tcp_pair().await;
        let (key, trusted) = make_shared_state(TEST_KEY, vec![peer_addr]);

        let server_task = tokio::spawn(async move {
            let client_pub = &mut [0u8; 32];
            server.read_exact(client_pub).await.unwrap();

            let server_priv = generate_private_key();
            let server_pub = calculate_public_key(&server_priv);
            server.write_all(&server_pub).await.unwrap();

            // Derive the shared key the same way the client will
            let shared = calculate_shared_key(&server_priv, client_pub);
            let shared_hash = hash_key(&shared);

            // Read and discard the client's encrypted key
            server.read_exact(&mut [0u8; 60]).await.unwrap();

            // Send back a different (wrong) key encrypted with the correct shared key
            let wrong_key = [0xFFu8; 32];
            let payload = encrypt_tunnel(&shared_hash, &wrong_key).unwrap();
            server.write_all(&payload).await.unwrap();

            // auth_outgoing sends encrypted 0x00 on rejection (29 bytes) — read it and ignore
            let _ = server.read_exact(&mut [0u8; 29]).await;
        });

        let result = auth_outgoing(key, trusted, (&mut client, peer_addr)).await;
        drop(client); // ensure stream is closed before awaiting server_task
        server_task.await.unwrap();

        assert_eq!(result.unwrap(), (false, [0u8; 32]));
    }

    // -------------------------------------------------------------------------
    // Full bidirectional integration tests (auth_incoming <-> auth_outgoing)
    // -------------------------------------------------------------------------

    /// Both sides use the same pre-shared key — full handshake must succeed on both ends,
    /// and both must derive the same shared_key_hash for use as the session key.
    #[tokio::test]
    async fn test_full_handshake_success() {
        let (mut server_stream, mut client_stream, peer_addr) = setup_tcp_pair().await;
        let (server_key, server_trusted) = make_shared_state(TEST_KEY, vec![peer_addr]);
        let (client_key, client_trusted) = make_shared_state(TEST_KEY, vec![peer_addr]);

        let server_task = tokio::spawn(async move {
            auth_incoming(server_key, server_trusted, (&mut server_stream, peer_addr)).await
        });

        let client_result =
            auth_outgoing(client_key, client_trusted, (&mut client_stream, peer_addr)).await;
        let server_result = server_task.await.unwrap();

        let (client_auth, client_hash) = client_result.unwrap();
        let (server_auth, server_hash) = server_result.unwrap();

        assert!(client_auth);
        assert!(server_auth);
        // Both sides must derive the same session key from the ECDH exchange
        assert_eq!(client_hash, server_hash);
        assert_ne!(client_hash, [0u8; 32]);
    }

    /// Client uses the wrong pre-shared key — server rejects during key comparison,
    /// client receives a wrong key back and also rejects. Both return false.
    #[tokio::test]
    async fn test_full_handshake_wrong_client_key() {
        let (mut server_stream, mut client_stream, peer_addr) = setup_tcp_pair().await;
        let (server_key, server_trusted) = make_shared_state(TEST_KEY, vec![peer_addr]);

        let wrong_key = [0xFFu8; 32];
        let (client_key, client_trusted) = make_shared_state(wrong_key, vec![peer_addr]);

        let server_task = tokio::spawn(async move {
            auth_incoming(server_key, server_trusted, (&mut server_stream, peer_addr)).await
        });

        let client_result =
            auth_outgoing(client_key, client_trusted, (&mut client_stream, peer_addr)).await;
        let server_result = server_task.await.unwrap();

        // Server rejects — wrong key sent by client
        assert_eq!(server_result.unwrap(), (false, [0u8; 32]));
        // Server drops the connection without sending a response, so client's read_exact
        // for the 60-byte server confirmation gets an EOF → FailedToReadFromStream
        assert_eq!(
            client_result.unwrap_err(),
            AuthErrors::FailedToReadFromStream
        );
    }

    /// Two concurrent full handshakes must each produce a unique shared_key_hash —
    /// ephemeral keys must not be reused across connections.
    #[tokio::test]
    async fn test_full_handshake_keys_unique_across_sessions() {
        let (mut s1, mut c1, addr1) = setup_tcp_pair().await;
        let (mut s2, mut c2, addr2) = setup_tcp_pair().await;

        let (sk1, st1) = make_shared_state(TEST_KEY, vec![addr1]);
        let (ck1, ct1) = make_shared_state(TEST_KEY, vec![addr1]);
        let (sk2, st2) = make_shared_state(TEST_KEY, vec![addr2]);
        let (ck2, ct2) = make_shared_state(TEST_KEY, vec![addr2]);

        let s1_task = tokio::spawn(async move { auth_incoming(sk1, st1, (&mut s1, addr1)).await });
        let s2_task = tokio::spawn(async move { auth_incoming(sk2, st2, (&mut s2, addr2)).await });

        let r_c1 = auth_outgoing(ck1, ct1, (&mut c1, addr1)).await;
        let r_c2 = auth_outgoing(ck2, ct2, (&mut c2, addr2)).await;

        s1_task.await.unwrap().unwrap();
        s2_task.await.unwrap().unwrap();

        let (_, hash1) = r_c1.unwrap();
        let (_, hash2) = r_c2.unwrap();

        assert_ne!(hash1, hash2);
    }
}
