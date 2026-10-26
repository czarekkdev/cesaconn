/*
TODO:
add tests
persist DeviceKeypairs (private keys encrypted / in the OS keychain)
sync the trusted peer list between devices, allow revoking one device
add encrypting/decrypting data with aes256 in SecureConnection with d_key
 */

/* Constant variables for noise protocol */
/* All according to the documentation https://noiseprotocol.org/noise.html */
/// -> e (32) + empty payload tag (16)
/// in PSK mode `e` also calls MixKey, so the first payload is already encrypted
const SNOW_MSG1_LEN: usize = 48;
/// <- e (32), ee, s (32 + 16), es + empty payload tag (16)
const SNOW_MSG2_LEN: usize = 96;
/// -> s (32 + 16), se, psk + empty payload tag (16)
const SNOW_MSG3_LEN: usize = 64;
/// max noise message size
const SNOW_MSG_MAX_LEN: usize = 65535;
/// authentication tag
const SNOW_TAG_LEN: usize = 16;
/// biggest payload one [`SecureConnection`] message can carry:
/// max noise message - AEAD tag - our tag byte
pub const SECURE_MSG_MAX_PAYLOAD: usize = SNOW_MSG_MAX_LEN - SNOW_TAG_LEN - 1;

/// read/write timeout (seconds)
pub const TIMEOUT: u64 = 5;

/// how long the user has to confirm a new device during pairing (seconds)
pub const PAIRING_TIMEOUT: u64 = 60;

use crate::{
    auth_snow::Tags::ServerAcceptTag,
    auth_snow::Tags::{
        ClientAcceptTag, IsSavedTag, MLDSA87SignatureTag, MLDSA87VerificationKeyTag,
    },
    hybrid_kex::{HybridKep, hybrid_kex_client, hybrid_kex_server},
    spake2::{
        spake2_confirm_mutual_auth_client, spake2_confirm_mutual_auth_server,
        spake2_exchange_client, spake2_exchange_server,
    },
    tcp_networker::IncomingConnection,
};
use blake2::Blake2s256;
use cesa_conn_crypto::{
    crand::random_array,
    x25519_cesa::{X25519KeyPair, generate_new_key_pair},
};
use core::fmt;
use hkdf::SimpleHkdf;
use libcrux_ml_dsa::ml_dsa_87::{
    MLDSA87KeyPair, MLDSA87Signature, MLDSA87VerificationKey, generate_key_pair, sign, verify,
};
use snow::{Builder, TransportState};
use std::{sync::Arc, time::Duration};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::RwLock,
    task::spawn_blocking,
    time::timeout,
};
use zeroize::Zeroizing;

/// All errors that can occur during authentication.
#[derive(Debug, PartialEq)]
pub enum AuthSnowErrors {
    /// The TCP stream ended or errored before we could read all expected bytes.
    FailedToReadFromStream,
    /// The TCP stream errored while sending data to the peer.
    FailedToWriteToStream,
    /// Failed to generate cryptographically secure random data
    FailedToGenerateRandomData,
    /// SPAKE2 could not derive the shared key from the peer's message.
    FailedToFinishSpake2Exchange,
    /// HKDF expand failed (requested output length too long).
    FailedToExpandHkdf,
    /// A slice/vector did not have the length required for a fixed-size array.
    FailedToConvertToArray,
    /// The Noise protocol name string could not be parsed.
    FailedToParseText,
    /// Snow rejected our static private key.
    FailedToSetLocalPrivateKey,
    /// Snow rejected the pre-shared key or its position in the pattern.
    FailedToSetPsk,
    /// Snow could not build the handshake state for the responder role.
    FailedToBuildSnowResponder,
    /// A Noise message failed to decrypt/authenticate or was malformed.
    FailedToReadSnowMessage,
    /// A Noise message could not be produced (e.g. output buffer too small).
    FailedToWriteSnowMessage,
    /// The handshake was not finished when switching to transport mode.
    FailedToEnterTransportMode,
    /// The SPAKE2 message exchange with the peer failed.
    FailedToExchangeSpake2,
    /// The SPAKE2 key confirmation step failed.
    FailedToConfirmMutualAuthSpake2,
    /// The peer did not confirm the hybrid key exchange.
    FailedToConfirmKex,
    /// The hybrid (X25519 + ML-KEM) key exchange failed.
    KexFailed,
    /// A decrypted packet did not end with the expected tag byte.
    WrongTag,
    /// The peer did not send data within [`TIMEOUT`] seconds.
    ReadTimeout,
    /// Data could not be sent within [`TIMEOUT`] seconds.
    WriteTimeout,
    /// The peer's static key was not available after the Noise handshake.
    SnowFailedToGetRemoteStatic,
    /// The peer's ML-KEM public key failed the FIPS 203 validity check.
    MlKemInvalidPublicKey,
    /// The X25519 shared secret was non-contributory (peer sent a low-order point).
    FailedToCalculateSharedSecret,
    /// Reading or decrypting a message from a [`SecureConnection`] failed.
    FailedToReadFromSecureConnection,
    /// The user rejected the new device, or confirming it failed.
    FailedToPairNewDevice,
    /// The peer's ML-DSA signature over the handshake hash is invalid.
    FailedToVerifySignature,
    /// Signing the handshake hash with our ML-DSA key failed.
    FailedToSignData,
    /// Encrypting or sending a message over a [`SecureConnection`] failed.
    FailedToWriteToSecureConnection,
    /// The user did not confirm the new device within [`PAIRING_TIMEOUT`] seconds.
    PairingTimeout,
    /// The server didnt get the confirming byte from the client
    NoClientConfirmation,
    /// The client did not get a positive pairing decision from the server.
    NoServerConfirmation,
    /// Snow could not build the handshake state for the initiator role.
    FailedToBuildSnowInitiator,
    /// A known peer sent a different ML-DSA verification key than the one we stored.
    PeerKeyMismatch,
    /// A message is bigger than one [`SecureConnection`] message can carry.
    MessageTooLarge,
}

impl fmt::Display for AuthSnowErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthSnowErrors::FailedToReadFromStream => {
                write!(f, "failed to read from stream")
            }
            AuthSnowErrors::FailedToWriteToStream => write!(f, "failed to write to stream"),
            AuthSnowErrors::FailedToExpandHkdf => write!(f, "failed to expand hkdf"),
            AuthSnowErrors::FailedToFinishSpake2Exchange => {
                write!(f, "failed to finish spake2 exchange")
            }
            AuthSnowErrors::FailedToGenerateRandomData => {
                write!(f, "failed to generate array of random data")
            }
            AuthSnowErrors::FailedToConvertToArray => {
                write!(f, "failed to convert vector to array")
            }
            AuthSnowErrors::FailedToParseText => {
                write!(f, "failed to parse text")
            }
            AuthSnowErrors::FailedToSetLocalPrivateKey => {
                write!(f, "failed to set local private key")
            }
            AuthSnowErrors::FailedToSetPsk => {
                write!(f, "failed to set psk")
            }
            AuthSnowErrors::FailedToBuildSnowResponder => {
                write!(f, "failed to build snow responder")
            }
            AuthSnowErrors::FailedToReadSnowMessage => {
                write!(f, "failed to read snow message")
            }
            AuthSnowErrors::FailedToWriteSnowMessage => {
                write!(f, "failed to write snow message")
            }
            AuthSnowErrors::FailedToEnterTransportMode => {
                write!(f, "failed to enter transport mode")
            }
            AuthSnowErrors::FailedToExchangeSpake2 => {
                write!(f, "failed to make exchange for spake2")
            }
            AuthSnowErrors::FailedToConfirmMutualAuthSpake2 => {
                write!(f, "failed to confirm mutual auth in spake2")
            }
            AuthSnowErrors::FailedToConfirmKex => {
                write!(f, "failed to confirm key exchange")
            }
            AuthSnowErrors::KexFailed => {
                write!(f, "key exchange failed")
            }
            AuthSnowErrors::WrongTag => {
                write!(f, "packet has a wrong tag")
            }
            AuthSnowErrors::ReadTimeout => {
                write!(f, "reading from stream timed out")
            }
            AuthSnowErrors::WriteTimeout => {
                write!(f, "writing to stream timed out")
            }
            AuthSnowErrors::SnowFailedToGetRemoteStatic => {
                write!(f, "failed to get a remote static key from peer in noise")
            }
            AuthSnowErrors::MlKemInvalidPublicKey => {
                write!(f, "invalid public key")
            }
            AuthSnowErrors::FailedToCalculateSharedSecret => {
                write!(f, "failed to calculate shared secret")
            }
            AuthSnowErrors::FailedToReadFromSecureConnection => {
                write!(f, "failed to read from SecureConnection")
            }
            AuthSnowErrors::FailedToPairNewDevice => {
                write!(f, "failed to pair new device")
            }
            AuthSnowErrors::FailedToVerifySignature => {
                write!(f, "failed to verify peer's signature")
            }
            AuthSnowErrors::FailedToSignData => {
                write!(f, "failed to sign the data")
            }
            AuthSnowErrors::FailedToWriteToSecureConnection => {
                write!(f, "failed to write data to secure connection")
            }
            AuthSnowErrors::PairingTimeout => {
                write!(f, "pairing timed out")
            }
            AuthSnowErrors::NoClientConfirmation => {
                write!(f, "server didnt recieve pairing confirmation from client")
            }
            AuthSnowErrors::NoServerConfirmation => {
                write!(f, "client didn't receive pairing confirmation from server")
            }
            AuthSnowErrors::FailedToBuildSnowInitiator => {
                write!(f, "failed to build snow initiator")
            }
            AuthSnowErrors::PeerKeyMismatch => {
                write!(f, "peer's verification key doesn't match the stored one")
            }
            AuthSnowErrors::MessageTooLarge => {
                write!(f, "message is too large for one secure connection message")
            }
        }
    }
}

/// Packet type marker appended as the last byte of every plaintext
/// sent over a [`SecureConnection`].
#[repr(u8)]
#[derive(Clone, Copy)]
pub enum Tags {
    /// Ordinary application data.
    Regular = 0x01,
    /// ML-DSA-87 verification key (2592 bytes).
    MLDSA87VerificationKeyTag = 0x02,
    /// ML-DSA-87 signature over the handshake hash (4627 bytes).
    MLDSA87SignatureTag = 0x03,
    /// Client accepted to pair
    ClientAcceptTag = 0x04,
    /// For checking whether other party has us saved
    IsSavedTag = 0x05,
    /// Server accepted to pair
    ServerAcceptTag = 0x06,
}

impl Tags {
    /// Appends the tag byte to the end of `packet`.
    pub fn tag(self, packet: &mut Vec<u8>) {
        packet.push(self as u8);
    }

    /// Returns `true` if `packet` ends with this tag.
    #[allow(dead_code)] // API for callers outside the PoC binary (daemon, tests)
    pub fn check_tag(self, packet: &[u8]) -> bool {
        packet.ends_with(&[self as u8])
    }

    /// Removes the tag from the end of `packet`.
    /// Returns `false` (and leaves `packet` untouched) if the tag doesn't match.
    pub fn untag(self, packet: &mut Vec<u8>) -> bool {
        if packet.ends_with(&[self as u8]) {
            packet.pop();
            true
        } else {
            false
        }
    }
}

/// Shared list of all devices this device has paired with.
pub type TrustedPeers = Arc<RwLock<Vec<TrustedPeer>>>;

/// An authenticated, encrypted channel to a peer after a completed Noise handshake.
pub struct SecureConnection {
    /// Underlying TCP stream carrying the ciphertext.
    pub connection: IncomingConnection,
    /// Noise transport state holding the send/receive cipher keys and nonces.
    pub ts: TransportState,
}

impl SecureConnection {
    /// Wraps an already-handshaken stream and its transport state.
    pub fn new(connection: IncomingConnection, ts: TransportState) -> Self {
        Self {
            connection: connection,
            ts: ts,
        }
    }

    /// Tags `src`, encrypts it and sends it to the peer.
    ///
    /// Note: `src` is modified (the tag byte is appended).
    /// At most [`SECURE_MSG_MAX_PAYLOAD`] bytes fit into one message.
    pub async fn write(&mut self, src: &mut Vec<u8>, tag: Tags) -> Result<(), AuthSnowErrors> {
        if src.len() > SECURE_MSG_MAX_PAYLOAD {
            return Err(AuthSnowErrors::MessageTooLarge);
        }

        tag.tag(src);

        // ciphertext = plaintext + AEAD tag
        let mut buffer = Zeroizing::new(vec![0u8; src.len().saturating_add(SNOW_TAG_LEN)]);

        self.ts
            .write_message(src, &mut buffer)
            .map_err(|_| AuthSnowErrors::FailedToWriteSnowMessage)?;

        self.connection
            .stream
            .write_all(&buffer)
            .await
            .map_err(|_| AuthSnowErrors::FailedToWriteToStream)?;

        Ok(())
    }

    /// Reads exactly `buffer.len()` bytes of plaintext (+ AEAD tag) from the peer,
    /// decrypts it into `buffer` and verifies/removes the expected `tag`.
    ///
    /// `buffer` must be sized to payload + 1 (for the tag byte). On success it
    /// is shortened by 1, so resize it before reusing it for the next read.
    ///
    /// Returns the payload length (decrypted bytes without the tag byte).
    pub async fn read(&mut self, buffer: &mut Vec<u8>, tag: Tags) -> Result<usize, AuthSnowErrors> {
        // +1 is the tag byte inside the payload
        if buffer.len() > SECURE_MSG_MAX_PAYLOAD + 1 {
            return Err(AuthSnowErrors::MessageTooLarge);
        }

        let mut message = Zeroizing::new(vec![0u8; buffer.len().saturating_add(SNOW_TAG_LEN)]);

        // Every caller wraps `SecureConnection::read` in `timeout(...)` (TIMEOUT /
        // PAIRING_TIMEOUT), so this low-level read deliberately has none of its own.
        // nosemgrep: cesa.net.read-without-timeout
        self.connection
            .stream
            .read_exact(&mut message)
            .await
            .map_err(|_| AuthSnowErrors::FailedToReadFromStream)?;

        let read = self
            .ts
            .read_message(&message, buffer)
            .map_err(|_| AuthSnowErrors::FailedToReadSnowMessage)?;

        if !tag.untag(buffer) {
            return Err(AuthSnowErrors::WrongTag);
        }

        // read >= 1, untag() just removed the tag byte
        Ok(read.saturating_sub(1))
    }

    /// [`Self::write`] bounded by [`TIMEOUT`].
    pub async fn write_timeout(
        &mut self,
        src: &mut Vec<u8>,
        tag: Tags,
    ) -> Result<(), AuthSnowErrors> {
        send_secure(self, src, tag, TIMEOUT).await
    }

    /// [`Self::read`] bounded by [`TIMEOUT`].
    pub async fn read_timeout(
        &mut self,
        buffer: &mut Vec<u8>,
        tag: Tags,
    ) -> Result<usize, AuthSnowErrors> {
        let read = self.read(buffer, tag);

        timeout(Duration::from_secs(TIMEOUT), read)
            .await
            .map_err(|_| AuthSnowErrors::ReadTimeout)?
            .map_err(|_| AuthSnowErrors::FailedToReadFromSecureConnection)
    }

    /// Sends `data` of any length as a series of messages, each carrying at
    /// most [`SECURE_MSG_MAX_PAYLOAD`] bytes and tagged with `tag`.
    ///
    /// The length is NOT sent: the receiver must already know it (e.g. from a
    /// header) and call [`Self::read_chunked`] with the same length. Noise
    /// nonces make the chunks impossible to reorder, drop or replay unnoticed.
    /// Every chunk is bounded by [`TIMEOUT`].
    pub async fn write_chunked(&mut self, data: &[u8], tag: Tags) -> Result<(), AuthSnowErrors> {
        // one reusable buffer, +1 for the tag byte write() appends
        let mut chunk_buf = Zeroizing::new(Vec::with_capacity(SECURE_MSG_MAX_PAYLOAD + 1));

        for chunk in data.chunks(SECURE_MSG_MAX_PAYLOAD) {
            chunk_buf.clear();
            chunk_buf.extend_from_slice(chunk);

            self.write_timeout(&mut chunk_buf, tag).await?;
        }

        Ok(())
    }

    /// Receives exactly `len` bytes sent with [`Self::write_chunked`].
    ///
    /// `len` comes from the peer in the end, so the CALLER must bound it before
    /// calling this; the buffer is allocated once with that capacity.
    /// Every chunk is bounded by [`TIMEOUT`].
    pub async fn read_chunked(
        &mut self,
        len: usize,
        tag: Tags,
    ) -> Result<Zeroizing<Vec<u8>>, AuthSnowErrors> {
        let mut data = Zeroizing::new(Vec::with_capacity(len));
        // +1 for the tag byte read() removes
        let mut chunk_buf = Zeroizing::new(Vec::with_capacity(SECURE_MSG_MAX_PAYLOAD + 1));

        while data.len() < len {
            let chunk_len = len.saturating_sub(data.len()).min(SECURE_MSG_MAX_PAYLOAD);

            chunk_buf.clear();
            chunk_buf.resize(chunk_len.saturating_add(1), 0);

            self.read_timeout(&mut chunk_buf, tag).await?;

            data.extend_from_slice(&chunk_buf);
        }

        Ok(data)
    }
}

/// Holds the two pre-shared 32-byte keys used by the networker.
///
/// * `a_key` — authentication key, used as the SPAKE2 password during pairing/connecting.
/// * `d_key` — data key, used for the inner encryption layer on actual payloads.
///
/// Both fields are wrapped in `Zeroizing` so they are wiped from memory on drop.
pub struct Keys {
    pub a_key: Zeroizing<[u8; 32]>,
    pub d_key: Zeroizing<[u8; 32]>,
}

impl Keys {
    /// Splits a packed 64-byte buffer into the two keys (`a_key` = bytes 0–31, `d_key` = bytes 32–63).
    pub fn from_ref(data: &[u8; 64]) -> Self {
        let mut a_key_bytes = Zeroizing::new([0u8; 32]);
        let mut d_key_bytes = Zeroizing::new([0u8; 32]);

        a_key_bytes.copy_from_slice(&data[..32]);
        d_key_bytes.copy_from_slice(&data[32..]);

        Self {
            a_key: a_key_bytes,
            d_key: d_key_bytes,
        }
    }

    /// Packs both keys into `data` (`a_key` in bytes 0–31, `d_key` in bytes 32–63). Inverse of `from_ref`.
    pub fn to_ref(&self, data: &mut [u8; 64]) {
        data[..32].copy_from_slice(&*self.a_key);
        data[32..].copy_from_slice(&*self.d_key);
    }

    /// Replaces both keys with the ones from `data`.
    pub fn update(&mut self, data: Self) {
        *self.a_key = *data.a_key;
        *self.d_key = *data.d_key;
    }

    /// Copies two 32-byte keys into `Zeroizing` so they are wiped from memory on drop.
    /// Taken by reference so callers don't leave an extra un-wiped copy behind.
    pub fn new(a_key: &[u8; 32], d_key: &[u8; 32]) -> Self {
        Self {
            a_key: Zeroizing::new(*a_key),
            d_key: Zeroizing::new(*d_key),
        }
    }
}

/// Holds the two 32-byte Argon2 salts used to derive `a_key` and `d_key` from
/// their passwords. Salts are not secret, but all devices must use the same ones.
pub struct Salts {
    pub a_salt: Zeroizing<[u8; 32]>,
    pub d_salt: Zeroizing<[u8; 32]>,
}

impl Salts {
    /// Splits a packed 64-byte buffer into the two salts (`a_salt` = bytes 0–31, `d_salt` = bytes 32–63).
    pub fn from_ref(data: &[u8; 64]) -> Self {
        let mut a_salt_bytes = Zeroizing::new([0u8; 32]);
        let mut d_salt_bytes = Zeroizing::new([0u8; 32]);

        a_salt_bytes.copy_from_slice(&data[..32]);
        d_salt_bytes.copy_from_slice(&data[32..]);

        Self {
            a_salt: a_salt_bytes,
            d_salt: d_salt_bytes,
        }
    }

    /// Packs both salts into `data` (`a_salt` in bytes 0–31, `d_salt` in bytes 32–63). Inverse of `from_ref`.
    pub fn to_ref(&self, data: &mut [u8; 64]) {
        data[..32].copy_from_slice(&*self.a_salt);
        data[32..].copy_from_slice(&*self.d_salt);
    }

    /// Replaces both salts with the ones from `data`.
    pub fn update(&mut self, data: Self) {
        *self.a_salt = *data.a_salt;
        *self.d_salt = *data.d_salt;
    }

    /// Wraps two raw 32-byte arrays in `Zeroizing`.
    #[allow(dead_code)] // API for callers outside the PoC binary (daemon, tests)
    pub fn new(a_salt: [u8; 32], d_salt: [u8; 32]) -> Self {
        Self {
            a_salt: Zeroizing::new(a_salt),
            d_salt: Zeroizing::new(d_salt),
        }
    }
}

/// This device's own long-term identity, different on every device.
///
/// Generated once when the device is set up, then stored and reused,
/// otherwise every restart would look like a new, unpaired device.
pub struct DeviceKeypairs {
    /// Noise static key pair, sent (encrypted) during every handshake.
    x25519_kep: X25519KeyPair,
    /// ML-DSA-87 key pair, used to sign the handshake hash.
    mldsa_kep: MLDSA87KeyPair,
}

impl DeviceKeypairs {
    /// Generates a fresh random X25519 and ML-DSA-87 key pair.
    /// Only call this once, when the device is set up.
    pub fn generate() -> Result<Self, AuthSnowErrors> {
        Ok(Self {
            x25519_kep: generate_new_key_pair(
                *random_array::<32>().map_err(|_| AuthSnowErrors::FailedToGenerateRandomData)?,
            ),
            mldsa_kep: generate_key_pair(
                *random_array::<32>().map_err(|_| AuthSnowErrors::FailedToGenerateRandomData)?,
            ),
        })
    }

    /// Wraps already existing key pairs, e.g. loaded from storage.
    #[allow(dead_code)] // API for callers outside the PoC binary (daemon, tests)
    pub fn new(x25519_kep: X25519KeyPair, mldsa_kep: MLDSA87KeyPair) -> Self {
        Self {
            x25519_kep,
            mldsa_kep,
        }
    }
}

/// A device we have paired with, identified by both of its public keys.
#[derive(Clone)]
pub struct TrustedPeer {
    /// The peer's Noise static public key, used to look it up after the handshake.
    x25519_pub_key: [u8; 32],
    /// The peer's ML-DSA-87 verification key, used to check its handshake signature.
    mldsa_verification_key: [u8; 2592],
    /// Human-readable device name shown to the user.
    name: String,
}

impl TrustedPeer {
    /// Creates a trusted peer entry from its two public keys and name.
    #[allow(dead_code)] // API for callers outside the PoC binary (daemon, tests)
    pub fn new(x25519_pub_key: [u8; 32], mldsa_verification_key: [u8; 2592], name: String) -> Self {
        Self {
            x25519_pub_key,
            mldsa_verification_key,
            name,
        }
    }

    /// Human-readable device name shown to the user.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The peer's Noise static public key.
    #[allow(dead_code)] // API for callers outside the PoC binary (daemon, tests)
    pub fn x25519_pub_key(&self) -> &[u8; 32] {
        &self.x25519_pub_key
    }
}

/// Which end of the connection we are. Decides who sends first after the
/// Noise handshake and which ML-DSA signing context belongs to whom.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Role {
    /// We opened the connection (Noise initiator, SPAKE2 side A).
    Client,
    /// We accepted the connection (Noise responder, SPAKE2 side B).
    Server,
}

impl Role {
    /// ML-DSA context of the client's handshake signature.
    const CLIENT_CONTEXT: &'static [u8] = b"CesaConn Client Handshake";
    /// ML-DSA context of the server's handshake signature.
    const SERVER_CONTEXT: &'static [u8] = b"CesaConn Server Handshake";

    /// Context we sign our own handshake signature with.
    fn own_context(self) -> &'static [u8] {
        match self {
            Role::Client => Self::CLIENT_CONTEXT,
            Role::Server => Self::SERVER_CONTEXT,
        }
    }

    /// Context the peer signed its handshake signature with.
    fn peer_context(self) -> &'static [u8] {
        match self {
            Role::Client => Self::SERVER_CONTEXT,
            Role::Server => Self::CLIENT_CONTEXT,
        }
    }
}

/// ML-DSA-87 verification key length (2592 bytes).
const MLDSA87_VK_LEN: usize = MLDSA87VerificationKey::len();
/// ML-DSA-87 signature length (4627 bytes).
const MLDSA87_SIG_LEN: usize = MLDSA87Signature::len();

/// Tags and sends `data` over `secure_connection`, bounded by `secs` seconds.
async fn send_secure(
    secure_connection: &mut SecureConnection,
    data: &mut Vec<u8>,
    tag: Tags,
    secs: u64,
) -> Result<(), AuthSnowErrors> {
    let send = secure_connection.write(data, tag);

    timeout(Duration::from_secs(secs), send)
        .await
        .map_err(|_| AuthSnowErrors::WriteTimeout)?
        .map_err(|_| AuthSnowErrors::FailedToWriteToSecureConnection)
}

/// Reads one message of exactly `len` payload bytes with the expected `tag`,
/// bounded by `secs` seconds. The returned buffer no longer contains the tag.
async fn recv_secure(
    secure_connection: &mut SecureConnection,
    len: usize,
    tag: Tags,
    secs: u64,
) -> Result<Zeroizing<Vec<u8>>, AuthSnowErrors> {
    // +1 for the tag byte that read() removes
    let mut buffer = Zeroizing::new(vec![0u8; len.saturating_add(1)]);

    let read = secure_connection.read(&mut buffer, tag);

    timeout(Duration::from_secs(secs), read)
        .await
        .map_err(|_| AuthSnowErrors::ReadTimeout)?
        .map_err(|_| AuthSnowErrors::FailedToReadFromSecureConnection)?;

    Ok(buffer)
}

/// Tells the peer whether we have it in `trusted_peers` and learns the same
/// about us. The client sends first.
///
/// 1. -> client's "I have you saved" byte
/// 2. <- server's "I have you saved" byte
///
/// Returns `true` only if BOTH sides have each other saved (no pairing needed).
async fn exchange_is_saved(
    secure_connection: &mut SecureConnection,
    role: Role,
    we_have_peer: bool,
) -> Result<bool, AuthSnowErrors> {
    let mut ours = vec![u8::from(we_have_peer)];

    let theirs = match role {
        Role::Client => {
            send_secure(secure_connection, &mut ours, IsSavedTag, TIMEOUT).await?;
            recv_secure(secure_connection, 1, IsSavedTag, TIMEOUT).await?
        }
        Role::Server => {
            let theirs = recv_secure(secure_connection, 1, IsSavedTag, TIMEOUT).await?;
            send_secure(secure_connection, &mut ours, IsSavedTag, TIMEOUT).await?;
            theirs
        }
    };

    Ok(we_have_peer && theirs.first() == Some(&0x01))
}

/// Checks the peer's handshake signature.
///
/// For a known peer the received verification key must match the stored one
/// (constant-time), so a device can't swap its identity key. The signature is
/// always verified with the received key, which proves the peer owns it.
fn verify_peer_signature(
    received_key: &[u8; MLDSA87_VK_LEN],
    signature: &[u8; MLDSA87_SIG_LEN],
    stored_key: Option<&[u8; MLDSA87_VK_LEN]>,
    handshake_hash: &Zeroizing<[u8; 32]>,
    context: &[u8],
) -> Result<(), AuthSnowErrors> {
    if let Some(stored_key) = stored_key {
        if stored_key.ct_eq(received_key).unwrap_u8() != 1 {
            return Err(AuthSnowErrors::PeerKeyMismatch);
        }
    }

    verify(
        &MLDSA87VerificationKey::new(*received_key),
        handshake_hash.as_slice(),
        context,
        &MLDSA87Signature::new(*signature),
    )
    .map_err(|_| AuthSnowErrors::FailedToVerifySignature)
}

/// Mutual ML-DSA-87 authentication over the finished Noise handshake.
///
/// 1. -> client's verification key
/// 2. -> client's signature over `handshake_hash`
/// 3. <- server's verification key
/// 4. <- server's signature over `handshake_hash`
///
/// Both sides ALWAYS send their key, so the message order never depends on
/// whether the peer is known. The server checks the client's signature before
/// sending its own. The handshake hash is unique per connection and identical
/// on both sides, so a valid signature proves the peer took part in this exact
/// handshake. Everything is appended to `transcript` in the order above.
///
/// Returns the peer's (verified) verification key.
async fn exchange_signatures(
    secure_connection: &mut SecureConnection,
    role: Role,
    handshake_hash: &Zeroizing<[u8; 32]>,
    stored_key: Option<&[u8; MLDSA87_VK_LEN]>,
    device_keypairs: &DeviceKeypairs,
    transcript: &mut Zeroizing<Vec<u8>>,
) -> Result<[u8; MLDSA87_VK_LEN], AuthSnowErrors> {
    let mut our_key = device_keypairs
        .mldsa_kep
        .verification_key
        .as_slice()
        .to_vec();

    let mut our_signature = sign(
        &device_keypairs.mldsa_kep.signing_key,
        handshake_hash.as_slice(),
        role.own_context(),
        *random_array::<32>().map_err(|_| AuthSnowErrors::FailedToSignData)?,
    )
    .map_err(|_| AuthSnowErrors::FailedToSignData)?
    .as_slice()
    .to_vec();

    // kept before send_secure() appends the tag byte to our buffers
    let our_key_wire = our_key.clone();
    let our_signature_wire = our_signature.clone();

    let (peer_key, peer_signature) = match role {
        Role::Client => {
            // 1. + 2.
            send_secure(
                secure_connection,
                &mut our_key,
                MLDSA87VerificationKeyTag,
                TIMEOUT,
            )
            .await?;
            send_secure(
                secure_connection,
                &mut our_signature,
                MLDSA87SignatureTag,
                TIMEOUT,
            )
            .await?;

            // 3. + 4.
            let peer_key = recv_secure(
                secure_connection,
                MLDSA87_VK_LEN,
                MLDSA87VerificationKeyTag,
                TIMEOUT,
            )
            .await?;
            let peer_signature = recv_secure(
                secure_connection,
                MLDSA87_SIG_LEN,
                MLDSA87SignatureTag,
                TIMEOUT,
            )
            .await?;

            transcript.extend_from_slice(&our_key_wire);
            transcript.extend_from_slice(&our_signature_wire);
            transcript.extend_from_slice(&peer_key);
            transcript.extend_from_slice(&peer_signature);

            (peer_key, peer_signature)
        }
        Role::Server => {
            // 1. + 2.
            let peer_key = recv_secure(
                secure_connection,
                MLDSA87_VK_LEN,
                MLDSA87VerificationKeyTag,
                TIMEOUT,
            )
            .await?;
            let peer_signature = recv_secure(
                secure_connection,
                MLDSA87_SIG_LEN,
                MLDSA87SignatureTag,
                TIMEOUT,
            )
            .await?;

            transcript.extend_from_slice(&peer_key);
            transcript.extend_from_slice(&peer_signature);
            transcript.extend_from_slice(&our_key_wire);
            transcript.extend_from_slice(&our_signature_wire);

            (peer_key, peer_signature)
        }
    };

    let peer_key: &[u8; MLDSA87_VK_LEN] = peer_key
        .as_slice()
        .try_into()
        .map_err(|_| AuthSnowErrors::FailedToConvertToArray)?;
    let peer_signature: &[u8; MLDSA87_SIG_LEN] = peer_signature
        .as_slice()
        .try_into()
        .map_err(|_| AuthSnowErrors::FailedToConvertToArray)?;

    // checked before we send anything else, and before any user is asked to pair
    verify_peer_signature(
        peer_key,
        peer_signature,
        stored_key,
        handshake_hash,
        role.peer_context(),
    )?;

    if role == Role::Server {
        // 3. + 4. only after the client proved itself
        send_secure(
            secure_connection,
            &mut our_key,
            MLDSA87VerificationKeyTag,
            TIMEOUT,
        )
        .await?;
        send_secure(
            secure_connection,
            &mut our_signature,
            MLDSA87SignatureTag,
            TIMEOUT,
        )
        .await?;
    }

    Ok(*peer_key)
}

/// Pairing confirmation, run only when the two devices don't both know each other.
///
/// Our user compares the words derived from the handshake hash and decides
/// (`pair_fallback`, on a blocking thread, at most [`PAIRING_TIMEOUT`]). Then:
///
/// 1. -> our decision (client: `ClientAcceptTag`, server: `ServerAcceptTag`)
/// 2. <- the peer's decision
///
/// The peer's user may still be deciding, so the read waits up to
/// [`PAIRING_TIMEOUT`] + [`TIMEOUT`]. We always send our decision, even a
/// rejection, so the peer doesn't wait for nothing.
///
/// Returns `Ok(())` only if both users accepted.
async fn confirm_pairing(
    secure_connection: &mut SecureConnection,
    role: Role,
    handshake_hash: &Zeroizing<[u8; 32]>,
    pair_fallback: fn(&String, &[u8; 32]) -> bool,
) -> Result<(), AuthSnowErrors> {
    // ask the user on a blocking thread, so tokio isn't blocked meanwhile
    let name_clone = secure_connection.connection.name.clone();
    let handshake_hash_clone = handshake_hash.clone();

    let accept = timeout(
        Duration::from_secs(PAIRING_TIMEOUT),
        spawn_blocking(move || pair_fallback(&name_clone, &handshake_hash_clone)),
    )
    .await
    .map_err(|_| AuthSnowErrors::PairingTimeout)?
    .map_err(|_| AuthSnowErrors::FailedToPairNewDevice)?;

    let (our_tag, peer_tag, peer_rejected) = match role {
        Role::Client => (
            ClientAcceptTag,
            ServerAcceptTag,
            AuthSnowErrors::NoServerConfirmation,
        ),
        Role::Server => (
            ServerAcceptTag,
            ClientAcceptTag,
            AuthSnowErrors::NoClientConfirmation,
        ),
    };

    // 1. our decision
    let mut decision = vec![u8::from(accept)];

    send_secure(secure_connection, &mut decision, our_tag, TIMEOUT).await?;

    if !accept {
        return Err(AuthSnowErrors::FailedToPairNewDevice);
    }

    // 2. the peer's decision
    let peer_decision =
        recv_secure(secure_connection, 1, peer_tag, PAIRING_TIMEOUT + TIMEOUT).await?;

    if peer_decision.first() != Some(&0x01) {
        return Err(peer_rejected);
    }

    Ok(())
}

/// Adds `peer` to `trusted_peers` unless a device with the same static key is
/// already there. Checked under the write lock, so two parallel pairings of the
/// same device can't both add it.
async fn save_peer(trusted_peers: &TrustedPeers, peer: &TrustedPeer) {
    let mut peers = trusted_peers.write().await;

    if !peers
        .iter()
        .any(|saved| saved.x25519_pub_key.ct_eq(&peer.x25519_pub_key).into())
    {
        peers.push(peer.clone());
    }
}

/// Everything after the Noise handshake, the same for both roles.
///
/// 1. tell each other whether we have the peer saved ([`exchange_is_saved`])
/// 2. mutual ML-DSA signatures over the handshake hash ([`exchange_signatures`])
/// 3. only if the devices don't both know each other: both users confirm
///    ([`confirm_pairing`]), then the peer is saved
///
/// Returns the secure connection and the authenticated peer.
#[allow(clippy::too_many_arguments)] // one call per role, a struct would only move the list
async fn authenticate_peer(
    mut secure_connection: SecureConnection,
    role: Role,
    peer_static: [u8; 32],
    handshake_hash: Zeroizing<[u8; 32]>,
    device_keypairs: &DeviceKeypairs,
    trusted_peers: TrustedPeers,
    pair_fallback: fn(&String, &[u8; 32]) -> bool,
    transcript: &mut Zeroizing<Vec<u8>>,
) -> Result<(SecureConnection, TrustedPeer), AuthSnowErrors> {
    // cloned, so the read lock is released before any network I/O
    let stored_peer = trusted_peers
        .read()
        .await
        .iter()
        .find(|device| device.x25519_pub_key.ct_eq(&peer_static).into())
        .cloned();

    // 1.
    let both_saved = exchange_is_saved(&mut secure_connection, role, stored_peer.is_some()).await?;

    // 2.
    let peer_key = exchange_signatures(
        &mut secure_connection,
        role,
        &handshake_hash,
        stored_peer
            .as_ref()
            .map(|peer| &peer.mldsa_verification_key),
        device_keypairs,
        transcript,
    )
    .await?;

    let peer = TrustedPeer {
        x25519_pub_key: peer_static,
        mldsa_verification_key: peer_key,
        name: match stored_peer {
            Some(stored_peer) => stored_peer.name,
            None => secure_connection.connection.name.clone(),
        },
    };

    // 3.
    if !both_saved {
        confirm_pairing(&mut secure_connection, role, &handshake_hash, pair_fallback).await?;
        save_peer(&trusted_peers, &peer).await;
    }

    Ok((secure_connection, peer))
}

/// Noise protocol used for the final handshake.
const NOISE_PARAMS: &str = "Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s";

/// Runs the responder side of a `Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s` handshake.
///
/// * `secure_psk` - key derived from SPAKE2 + hybrid KEX, mixed in at message 3
/// * `device_keypairs` - our own long-term keys (X25519 static key, ML-DSA key pair)
/// * `trusted_peers` - devices we already paired with
/// * `pair_fallback` - asks the user to confirm an unknown device; gets its name
///   and the handshake hash (to show as words). Runs on a blocking thread.
/// * `transcript` - the signature exchange is appended to it
///
/// After the handshake both sides authenticate each other with ML-DSA
/// signatures; devices that don't both know each other are only accepted after
/// both users confirm ([`authenticate_peer`]).
///
/// Every network read/write is bounded by [`TIMEOUT`].
///
/// Returns the secure connection and the authenticated peer.
async fn snow_handshake_server(
    mut incoming_connection: IncomingConnection,
    secure_psk: Zeroizing<[u8; 32]>,
    device_keypairs: &DeviceKeypairs,
    trusted_peers: TrustedPeers,
    pair_fallback: fn(&String, &[u8; 32]) -> bool,
    transcript: &mut Zeroizing<Vec<u8>>,
) -> Result<(SecureConnection, TrustedPeer), AuthSnowErrors> {
    let stream = &mut incoming_connection.stream;

    // psk3: the PSK is mixed in at the end of the third handshake message
    let mut builder = Builder::new(
        NOISE_PARAMS
            .parse()
            .map_err(|_| AuthSnowErrors::FailedToParseText)?,
    )
    .local_private_key(device_keypairs.x25519_kep.private.as_slice())
    .map_err(|_| AuthSnowErrors::FailedToSetLocalPrivateKey)?
    .psk(3, &secure_psk)
    .map_err(|_| AuthSnowErrors::FailedToSetPsk)?
    .build_responder()
    .map_err(|_| AuthSnowErrors::FailedToBuildSnowResponder)?;

    // `buffer` holds outgoing messages / decrypted payloads,
    // `read_buffer` holds raw bytes received from the peer
    let mut buffer = Zeroizing::new([0u8; SNOW_MSG2_LEN]);
    let mut read_buffer = Zeroizing::new([0u8; SNOW_MSG3_LEN]);

    // -> e
    let read = stream.read_exact(
        read_buffer
            .get_mut(..SNOW_MSG1_LEN)
            .ok_or(AuthSnowErrors::FailedToReadFromStream)?,
    );

    timeout(Duration::from_secs(TIMEOUT), read)
        .await
        .map_err(|_| AuthSnowErrors::ReadTimeout)?
        .map_err(|_| AuthSnowErrors::FailedToReadFromStream)?;

    builder
        .read_message(
            read_buffer
                .get(..SNOW_MSG1_LEN)
                .ok_or(AuthSnowErrors::FailedToReadSnowMessage)?,
            buffer.as_mut_slice(),
        )
        .map_err(|_| AuthSnowErrors::FailedToReadSnowMessage)?;

    // <- e, ee, s, es (empty payload)
    builder
        .write_message(
            &[],
            buffer
                .get_mut(..SNOW_MSG2_LEN)
                .ok_or(AuthSnowErrors::FailedToWriteSnowMessage)?,
        )
        .map_err(|_| AuthSnowErrors::FailedToWriteSnowMessage)?;

    let write = stream.write_all(
        buffer
            .get(..SNOW_MSG2_LEN)
            .ok_or(AuthSnowErrors::FailedToWriteToStream)?,
    );

    timeout(Duration::from_secs(TIMEOUT), write)
        .await
        .map_err(|_| AuthSnowErrors::WriteTimeout)?
        .map_err(|_| AuthSnowErrors::FailedToWriteToStream)?;

    // -> s, se, psk
    let read = stream.read_exact(
        read_buffer
            .get_mut(..SNOW_MSG3_LEN)
            .ok_or(AuthSnowErrors::FailedToReadFromStream)?,
    );

    timeout(Duration::from_secs(TIMEOUT), read)
        .await
        .map_err(|_| AuthSnowErrors::ReadTimeout)?
        .map_err(|_| AuthSnowErrors::FailedToReadFromStream)?;

    builder
        .read_message(
            read_buffer
                .get(..SNOW_MSG3_LEN)
                .ok_or(AuthSnowErrors::FailedToReadSnowMessage)?,
            buffer.as_mut_slice(),
        )
        .map_err(|_| AuthSnowErrors::FailedToReadSnowMessage)?;

    // the peer's static public key identifies the device in `trusted_peers`
    let peer_static: [u8; 32] = builder
        .get_remote_static()
        .ok_or(AuthSnowErrors::SnowFailedToGetRemoteStatic)?
        .try_into()
        .map_err(|_| AuthSnowErrors::FailedToConvertToArray)?;

    // saved now, snow only exposes it before switching to transport mode;
    // used for the signatures and for the words the user compares when pairing
    let mut handshake_hash = Zeroizing::new([0u8; 32]);

    handshake_hash.clone_from_slice(builder.get_handshake_hash());

    // handshake complete, switch to encrypted transport
    let transport = builder
        .into_transport_mode()
        .map_err(|_| AuthSnowErrors::FailedToEnterTransportMode)?;

    let secure_connection = SecureConnection::new(incoming_connection, transport);

    authenticate_peer(
        secure_connection,
        Role::Server,
        peer_static,
        handshake_hash,
        device_keypairs,
        trusted_peers,
        pair_fallback,
        transcript,
    )
    .await
}

/// Runs the initiator side of a `Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s` handshake.
///
/// 1. -> e
/// 2. <- e, ee, s, es
/// 3. -> s, se, psk
///
/// Same arguments and result as [`snow_handshake_server`].
async fn snow_handshake_client(
    mut outgoing_connection: IncomingConnection,
    secure_psk: Zeroizing<[u8; 32]>,
    device_keypairs: &DeviceKeypairs,
    trusted_peers: TrustedPeers,
    pair_fallback: fn(&String, &[u8; 32]) -> bool,
    transcript: &mut Zeroizing<Vec<u8>>,
) -> Result<(SecureConnection, TrustedPeer), AuthSnowErrors> {
    let stream = &mut outgoing_connection.stream;

    let mut noise = Builder::new(
        NOISE_PARAMS
            .parse()
            .map_err(|_| AuthSnowErrors::FailedToParseText)?,
    )
    .local_private_key(device_keypairs.x25519_kep.private.as_slice())
    .map_err(|_| AuthSnowErrors::FailedToSetLocalPrivateKey)?
    .psk(3, &secure_psk)
    .map_err(|_| AuthSnowErrors::FailedToSetPsk)?
    .build_initiator()
    .map_err(|_| AuthSnowErrors::FailedToBuildSnowInitiator)?;

    let mut buffer = Zeroizing::new([0u8; SNOW_MSG2_LEN]);
    let mut read_buffer = Zeroizing::new([0u8; SNOW_MSG2_LEN]);

    // 1. -> e
    let len = noise
        .write_message(&[], buffer.as_mut_slice())
        .map_err(|_| AuthSnowErrors::FailedToWriteSnowMessage)?;

    if len != SNOW_MSG1_LEN {
        return Err(AuthSnowErrors::FailedToWriteSnowMessage);
    }

    let write = stream.write_all(
        buffer
            .get(..SNOW_MSG1_LEN)
            .ok_or(AuthSnowErrors::FailedToWriteToStream)?,
    );

    timeout(Duration::from_secs(TIMEOUT), write)
        .await
        .map_err(|_| AuthSnowErrors::WriteTimeout)?
        .map_err(|_| AuthSnowErrors::FailedToWriteToStream)?;

    // 2. <- e, ee, s, es
    let read = stream.read_exact(
        read_buffer
            .get_mut(..SNOW_MSG2_LEN)
            .ok_or(AuthSnowErrors::FailedToReadFromStream)?,
    );

    timeout(Duration::from_secs(TIMEOUT), read)
        .await
        .map_err(|_| AuthSnowErrors::ReadTimeout)?
        .map_err(|_| AuthSnowErrors::FailedToReadFromStream)?;

    noise
        .read_message(
            read_buffer
                .get(..SNOW_MSG2_LEN)
                .ok_or(AuthSnowErrors::FailedToReadSnowMessage)?,
            buffer.as_mut_slice(),
        )
        .map_err(|_| AuthSnowErrors::FailedToReadSnowMessage)?;

    // 3. -> s, se, psk
    let len = noise
        .write_message(&[], buffer.as_mut_slice())
        .map_err(|_| AuthSnowErrors::FailedToWriteSnowMessage)?;

    if len != SNOW_MSG3_LEN {
        return Err(AuthSnowErrors::FailedToWriteSnowMessage);
    }

    let write = stream.write_all(
        buffer
            .get(..SNOW_MSG3_LEN)
            .ok_or(AuthSnowErrors::FailedToWriteToStream)?,
    );

    timeout(Duration::from_secs(TIMEOUT), write)
        .await
        .map_err(|_| AuthSnowErrors::WriteTimeout)?
        .map_err(|_| AuthSnowErrors::FailedToWriteToStream)?;

    let peer_static: [u8; 32] = noise
        .get_remote_static()
        .ok_or(AuthSnowErrors::SnowFailedToGetRemoteStatic)?
        .try_into()
        .map_err(|_| AuthSnowErrors::FailedToConvertToArray)?;

    let mut handshake_hash = Zeroizing::new([0u8; 32]);

    handshake_hash.clone_from_slice(noise.get_handshake_hash());

    let transport = noise
        .into_transport_mode()
        .map_err(|_| AuthSnowErrors::FailedToEnterTransportMode)?;

    let secure_connection = SecureConnection::new(outgoing_connection, transport);

    authenticate_peer(
        secure_connection,
        Role::Client,
        peer_static,
        handshake_hash,
        device_keypairs,
        trusted_peers,
        pair_fallback,
        transcript,
    )
    .await
}

/// PSK = HKDF(key1 || x25519_ss || mlkem_ss || HKDF(transcript)), label `CPQHA-psk`.
///
/// key1 binds the KEX to SPAKE2, so a MITM that only relays SPAKE2 can't derive it.
/// Both sides must have built `transcript` in the same order.
fn derive_secure_psk(
    key1: &Zeroizing<Vec<u8>>,
    hybrid_kep: &HybridKep,
    transcript: &Zeroizing<Vec<u8>>,
) -> Result<Zeroizing<[u8; 32]>, AuthSnowErrors> {
    let mut transcript_hash = Zeroizing::new([0u8; 32]);

    SimpleHkdf::<Blake2s256>::new(None, transcript)
        .expand(&[], transcript_hash.as_mut_slice())
        .map_err(|_| AuthSnowErrors::FailedToExpandHkdf)?;

    // sized up front, so the secret buffer never reallocates (old copies aren't wiped)
    let mut psk = Zeroizing::new(Vec::with_capacity(key1.len().saturating_add(3 * 32)));

    psk.extend_from_slice(key1);
    psk.extend_from_slice(hybrid_kep.x25519_ss.as_slice());
    psk.extend_from_slice(hybrid_kep.mlkem_ss.as_slice());
    psk.extend_from_slice(transcript_hash.as_slice());

    let mut secure_psk = Zeroizing::new([0u8; 32]);

    SimpleHkdf::<Blake2s256>::new(None, &psk)
        .expand(b"CPQHA-psk", secure_psk.as_mut_slice())
        .map_err(|_| AuthSnowErrors::FailedToExpandHkdf)?;

    Ok(secure_psk)
}

/// Authenticates an incoming connection (server side).
///
/// Steps:
/// 1. SPAKE2 exchange + mutual key confirmation using the shared `a_key`
/// 2. hybrid X25519 + ML-KEM key exchange
/// 3. derive a PSK from the SPAKE2 key, both KEX shared secrets and the transcript hash
/// 4. Noise XXpsk3 handshake using that PSK and our device's static key
/// 5. mutual ML-DSA signatures over the handshake hash; devices that don't both
///    know each other are only accepted after both users confirm (pairing)
///
/// Returns `Ok(None)` if the peer failed SPAKE2 confirmation
/// (i.e. doesn't know the shared key), `Ok(Some(_))` with the secure
/// connection and the authenticated peer on success.
pub async fn auth_incoming(
    keys: Arc<RwLock<Keys>>,
    device_keypairs: &DeviceKeypairs,
    trusted_peers: TrustedPeers,
    mut incoming_connection: IncomingConnection,
    pair_fallback: fn(&String, &[u8; 32]) -> bool,
) -> Result<Option<(SecureConnection, TrustedPeer)>, AuthSnowErrors> {
    let mut stream = &mut incoming_connection.stream;
    let a_key = keys.read().await.a_key.clone();
    // every message exchanged before Noise is appended here so the
    // derived PSK is bound to the whole pre-handshake conversation;
    // the signature exchange after Noise is appended too
    let mut transcript = Zeroizing::new(Vec::new());

    // 1. SPAKE2
    let key1 = spake2_exchange_server(&mut stream, &a_key, &mut transcript)
        .await
        .map_err(|_| AuthSnowErrors::FailedToExchangeSpake2)?;

    if !spake2_confirm_mutual_auth_server(&mut stream, &key1, &mut transcript)
        .await
        .map_err(|_| AuthSnowErrors::FailedToConfirmMutualAuthSpake2)?
    {
        return Ok(None);
    }

    // 2. hybrid KEX (classic + post-quantum)
    let hybrid_kep = hybrid_kex_server(&mut stream, &mut transcript)
        .await
        .map_err(|_| AuthSnowErrors::KexFailed)?;

    // 3. PSK
    let secure_psk = derive_secure_psk(&key1, &hybrid_kep, &transcript)?;

    // 4. + 5. Noise handshake, then signatures / pairing
    snow_handshake_server(
        incoming_connection,
        secure_psk,
        device_keypairs,
        trusted_peers,
        pair_fallback,
        &mut transcript,
    )
    .await
    .map(Some)
}

/// Authenticates an outgoing connection (client side). Mirrors [`auth_incoming`]
/// step by step, with the client sending first wherever both sides send.
///
/// Returns `Ok(None)` if the server's SPAKE2 confirmation was wrong (it doesn't
/// know the shared key), `Ok(Some(_))` with the secure connection and the
/// authenticated peer on success.
pub async fn auth_outgoing(
    keys: Arc<RwLock<Keys>>,
    device_keypairs: &DeviceKeypairs,
    trusted_peers: TrustedPeers,
    mut outgoing_connection: IncomingConnection,
    pair_fallback: fn(&String, &[u8; 32]) -> bool,
) -> Result<Option<(SecureConnection, TrustedPeer)>, AuthSnowErrors> {
    let mut stream = &mut outgoing_connection.stream;
    let a_key = keys.read().await.a_key.clone();
    let mut transcript = Zeroizing::new(Vec::new());

    // 1. SPAKE2
    let key1 = spake2_exchange_client(&mut stream, &a_key, &mut transcript)
        .await
        .map_err(|_| AuthSnowErrors::FailedToExchangeSpake2)?;

    if !spake2_confirm_mutual_auth_client(&mut stream, &key1, &mut transcript)
        .await
        .map_err(|_| AuthSnowErrors::FailedToConfirmMutualAuthSpake2)?
    {
        return Ok(None);
    }

    // 2. hybrid KEX (classic + post-quantum)
    let hybrid_kep = hybrid_kex_client(&mut stream, &mut transcript)
        .await
        .map_err(|_| AuthSnowErrors::KexFailed)?;

    // 3. PSK
    let secure_psk = derive_secure_psk(&key1, &hybrid_kep, &transcript)?;

    // 4. + 5. Noise handshake, then signatures / pairing
    snow_handshake_client(
        outgoing_connection,
        secure_psk,
        device_keypairs,
        trusted_peers,
        pair_fallback,
        &mut transcript,
    )
    .await
    .map(Some)
}

#[cfg(test)]
#[allow(clippy::large_futures)] // full handshakes in tests, stack size doesn't matter
mod tests {

    use super::*;
    use tokio::net::{TcpListener, TcpStream};

    const TEST_A_KEY: [u8; 32] = [0xAB; 32];

    /// Pairing callback that accepts every device.
    fn accept_all(_name: &String, _hash: &[u8; 32]) -> bool {
        true
    }

    /// Pairing callback for peers that must already be known: fails the test
    /// path by rejecting, so an unexpected prompt shows up as an error.
    fn must_not_prompt(_name: &String, _hash: &[u8; 32]) -> bool {
        false
    }

    /// One side of a test connection: keys, identity and trusted list.
    struct Device {
        keys: Arc<RwLock<Keys>>,
        keypairs: DeviceKeypairs,
        peers: TrustedPeers,
    }

    impl Device {
        fn new(a_key: [u8; 32]) -> Self {
            Self {
                keys: Arc::new(RwLock::new(Keys::new(&a_key, &[0xCD; 32]))),
                keypairs: DeviceKeypairs::generate().unwrap(),
                peers: Arc::new(RwLock::new(Vec::new())),
            }
        }
    }

    type AuthResult = Result<Option<(SecureConnection, TrustedPeer)>, AuthSnowErrors>;

    /// Runs auth_incoming / auth_outgoing against each other over localhost.
    async fn handshake(
        server: &Device,
        client: &Device,
        server_pair: fn(&String, &[u8; 32]) -> bool,
        client_pair: fn(&String, &[u8; 32]) -> bool,
    ) -> (AuthResult, AuthResult) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_side = async {
            let (stream, peer_addr) = listener.accept().await.unwrap();
            auth_incoming(
                server.keys.clone(),
                &server.keypairs,
                server.peers.clone(),
                IncomingConnection::new(stream, peer_addr),
                server_pair,
            )
            .await
        };

        let client_side = async {
            let stream = TcpStream::connect(addr).await.unwrap();
            auth_outgoing(
                client.keys.clone(),
                &client.keypairs,
                client.peers.clone(),
                IncomingConnection::new(stream, addr),
                client_pair,
            )
            .await
        };

        tokio::join!(server_side, client_side)
    }

    /// Test that two new devices pair, save each other and get a working channel
    #[tokio::test]
    async fn test_first_pairing_saves_both_peers() {
        let server = Device::new(TEST_A_KEY);
        let client = Device::new(TEST_A_KEY);

        let (server_result, client_result) =
            handshake(&server, &client, accept_all, accept_all).await;

        let (mut server_conn, client_as_seen) = server_result.unwrap().unwrap();
        let (mut client_conn, server_as_seen) = client_result.unwrap().unwrap();

        // each side identified the other by its real static key
        assert_eq!(
            client_as_seen.x25519_pub_key(),
            &*client.keypairs.x25519_kep.public
        );
        assert_eq!(
            server_as_seen.x25519_pub_key(),
            &*server.keypairs.x25519_kep.public
        );
        assert_eq!(server.peers.read().await.len(), 1);
        assert_eq!(client.peers.read().await.len(), 1);

        // the transport works in both directions
        let mut msg = b"ping".to_vec();
        client_conn
            .write_timeout(&mut msg, Tags::Regular)
            .await
            .unwrap();

        let mut buf = vec![0u8; 4 + 1];
        server_conn
            .read_timeout(&mut buf, Tags::Regular)
            .await
            .unwrap();
        assert_eq!(buf, b"ping");

        let mut msg = b"pong".to_vec();
        server_conn
            .write_timeout(&mut msg, Tags::Regular)
            .await
            .unwrap();

        let mut buf = vec![0u8; 4 + 1];
        client_conn
            .read_timeout(&mut buf, Tags::Regular)
            .await
            .unwrap();
        assert_eq!(buf, b"pong");
    }

    /// Test that known devices reconnect without asking the user again
    #[tokio::test]
    async fn test_known_peers_reconnect_without_prompt() {
        let server = Device::new(TEST_A_KEY);
        let client = Device::new(TEST_A_KEY);

        let (s, c) = handshake(&server, &client, accept_all, accept_all).await;
        assert!(s.unwrap().is_some() && c.unwrap().is_some());

        // must_not_prompt rejects, so this only succeeds if nobody is asked
        let (s, c) = handshake(&server, &client, must_not_prompt, must_not_prompt).await;

        assert!(s.unwrap().is_some());
        assert!(c.unwrap().is_some());
        assert_eq!(server.peers.read().await.len(), 1);
        assert_eq!(client.peers.read().await.len(), 1);
    }

    /// Test that a device which forgot its peer re-pairs instead of failing
    #[tokio::test]
    async fn test_one_sided_forget_repairs() {
        let server = Device::new(TEST_A_KEY);
        let client = Device::new(TEST_A_KEY);

        let (s, c) = handshake(&server, &client, accept_all, accept_all).await;
        assert!(s.unwrap().is_some() && c.unwrap().is_some());

        client.peers.write().await.clear();

        // the server still knows the client, but both must confirm again
        let (s, c) = handshake(&server, &client, must_not_prompt, accept_all).await;
        assert!(s.is_err() && c.is_err());

        let (s, c) = handshake(&server, &client, accept_all, accept_all).await;
        assert!(s.unwrap().is_some() && c.unwrap().is_some());

        // no duplicate entry on the side that never forgot
        assert_eq!(server.peers.read().await.len(), 1);
        assert_eq!(client.peers.read().await.len(), 1);
    }

    /// Test that a known peer presenting a different ML-DSA key is rejected
    #[tokio::test]
    async fn test_known_peer_with_swapped_mldsa_key_rejected() {
        let server = Device::new(TEST_A_KEY);
        let mut client = Device::new(TEST_A_KEY);

        let (s, c) = handshake(&server, &client, accept_all, accept_all).await;
        assert!(s.unwrap().is_some() && c.unwrap().is_some());

        // same Noise static key, new ML-DSA identity
        client.keypairs = DeviceKeypairs::new(
            generate_new_key_pair(*client.keypairs.x25519_kep.private),
            generate_key_pair(*random_array::<32>().unwrap()),
        );

        let (s, c) = handshake(&server, &client, accept_all, accept_all).await;

        assert_eq!(s.err(), Some(AuthSnowErrors::PeerKeyMismatch));
        assert!(c.is_err());
    }

    /// Test that a peer without the shared a_key is turned away before Noise
    #[tokio::test]
    async fn test_wrong_a_key_returns_none() {
        let server = Device::new(TEST_A_KEY);
        let client = Device::new([0x11; 32]);

        let (s, c) = handshake(&server, &client, accept_all, accept_all).await;

        assert!(s.unwrap().is_none());
        // the server closes instead of sending its confirmation
        assert!(c.is_err());
        assert!(server.peers.read().await.is_empty());
        assert!(client.peers.read().await.is_empty());
    }

    /// Test that a rejection on either side means nobody saves anybody
    #[tokio::test]
    async fn test_client_rejects_pairing() {
        let server = Device::new(TEST_A_KEY);
        let client = Device::new(TEST_A_KEY);

        let (s, c) = handshake(&server, &client, accept_all, must_not_prompt).await;

        assert_eq!(s.err(), Some(AuthSnowErrors::NoClientConfirmation));
        assert_eq!(c.err(), Some(AuthSnowErrors::FailedToPairNewDevice));
        assert!(server.peers.read().await.is_empty());
        assert!(client.peers.read().await.is_empty());
    }

    /// Test that SecureConnection refuses messages bigger than one Noise message
    #[tokio::test]
    async fn test_secure_connection_message_too_large() {
        let server = Device::new(TEST_A_KEY);
        let client = Device::new(TEST_A_KEY);

        let (_s, c) = handshake(&server, &client, accept_all, accept_all).await;
        let (mut conn, _) = c.unwrap().unwrap();

        let mut too_big = vec![0u8; SECURE_MSG_MAX_PAYLOAD + 1];
        assert_eq!(
            conn.write(&mut too_big, Tags::Regular).await.err(),
            Some(AuthSnowErrors::MessageTooLarge)
        );

        let mut too_big = vec![0u8; SECURE_MSG_MAX_PAYLOAD + 2];
        assert_eq!(
            conn.read(&mut too_big, Tags::Regular).await.err(),
            Some(AuthSnowErrors::MessageTooLarge)
        );
    }

    /// Test that a message with the wrong tag is rejected
    #[tokio::test]
    async fn test_wrong_tag_rejected() {
        let server = Device::new(TEST_A_KEY);
        let client = Device::new(TEST_A_KEY);

        let (s, c) = handshake(&server, &client, accept_all, accept_all).await;
        let (mut server_conn, _) = s.unwrap().unwrap();
        let (mut client_conn, _) = c.unwrap().unwrap();

        let mut msg = b"x".to_vec();
        client_conn.write(&mut msg, Tags::IsSavedTag).await.unwrap();

        let mut buf = vec![0u8; 1 + 1];
        assert_eq!(
            server_conn.read(&mut buf, Tags::Regular).await.err(),
            Some(AuthSnowErrors::WrongTag)
        );
    }

    /// Test that payloads of every size around the chunk boundary arrive intact
    #[tokio::test]
    async fn test_chunked_roundtrip_sizes() {
        let server = Device::new(TEST_A_KEY);
        let client = Device::new(TEST_A_KEY);

        let (s, c) = handshake(&server, &client, accept_all, accept_all).await;
        let (mut server_conn, _) = s.unwrap().unwrap();
        let (mut client_conn, _) = c.unwrap().unwrap();

        for len in [
            0,
            1,
            SECURE_MSG_MAX_PAYLOAD - 1,
            SECURE_MSG_MAX_PAYLOAD,
            SECURE_MSG_MAX_PAYLOAD + 1,
            3 * SECURE_MSG_MAX_PAYLOAD + 7,
        ] {
            let data: Vec<u8> = (0..=250u8).cycle().take(len).collect();

            let send = client_conn.write_chunked(&data, Tags::Regular);
            let recv = server_conn.read_chunked(len, Tags::Regular);
            let (sent, received) = tokio::join!(send, recv);

            sent.unwrap();
            assert_eq!(received.unwrap().as_slice(), data.as_slice(), "len {len}");
        }
    }

    /// Test that a chunk with the wrong tag stops the transfer
    #[tokio::test]
    async fn test_chunked_wrong_tag_rejected() {
        let server = Device::new(TEST_A_KEY);
        let client = Device::new(TEST_A_KEY);

        let (s, c) = handshake(&server, &client, accept_all, accept_all).await;
        let (mut server_conn, _) = s.unwrap().unwrap();
        let (mut client_conn, _) = c.unwrap().unwrap();

        let data = vec![1u8; SECURE_MSG_MAX_PAYLOAD + 10];

        let send = client_conn.write_chunked(&data, Tags::IsSavedTag);
        let recv = server_conn.read_chunked(data.len(), Tags::Regular);
        let (_, received) = tokio::join!(send, recv);

        assert_eq!(
            received.err(),
            Some(AuthSnowErrors::FailedToReadFromSecureConnection)
        );
    }

    /// Test that a sender stopping early makes read_chunked fail instead of hang
    #[tokio::test]
    async fn test_chunked_truncated_transfer_fails() {
        let server = Device::new(TEST_A_KEY);
        let client = Device::new(TEST_A_KEY);

        let (s, c) = handshake(&server, &client, accept_all, accept_all).await;
        let (mut server_conn, _) = s.unwrap().unwrap();
        let (mut client_conn, _) = c.unwrap().unwrap();

        // announce more than we send, then hang up
        client_conn
            .write_chunked(&[7u8; 100], Tags::Regular)
            .await
            .unwrap();
        drop(client_conn);

        assert!(server_conn.read_chunked(200, Tags::Regular).await.is_err());
    }

    /// Test that both roles derive the same PSK from the same inputs
    #[test]
    fn test_derive_secure_psk_deterministic() {
        let key1 = Zeroizing::new(vec![1u8; 32]);
        let kep = HybridKep {
            x25519_ss: Zeroizing::new([2u8; 32]),
            mlkem_ss: Zeroizing::new([3u8; 32]),
        };
        let transcript = Zeroizing::new(vec![4u8; 100]);

        let a = derive_secure_psk(&key1, &kep, &transcript).unwrap();
        let b = derive_secure_psk(&key1, &kep, &transcript).unwrap();
        assert_eq!(*a, *b);

        // any transcript change changes the PSK
        let other = Zeroizing::new(vec![5u8; 100]);
        let c = derive_secure_psk(&key1, &kep, &other).unwrap();
        assert_ne!(*a, *c);
    }

    /// Test that every error has a non-empty message
    #[test]
    fn test_error_display_non_empty() {
        for e in [
            AuthSnowErrors::PeerKeyMismatch,
            AuthSnowErrors::NoServerConfirmation,
            AuthSnowErrors::FailedToBuildSnowInitiator,
            AuthSnowErrors::MessageTooLarge,
            AuthSnowErrors::NoClientConfirmation,
        ] {
            assert!(!e.to_string().is_empty());
        }
    }
}
