/*
TODO:
persist DeviceKeypairs (private keys encrypted / in the OS keychain)
sync the trusted peer list between devices, allow revoking one device
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

/// pairings that may wait for the user at the same time; one more is
/// rejected at once instead of queueing (a peer that knows the auth
/// password must not be able to stack up prompts)
pub const MAX_PENDING_PAIRINGS: usize = 4;

/// HKDF label of the pairing code
const PAIRING_CODE_LABEL: &[u8] = b"CesaConn-pairing-code";

/// deadline for the whole handshake up to the verified signatures (seconds);
/// per-message timeouts alone would let a peer drip one message every
/// TIMEOUT - 1 seconds and hold the connection for minutes
pub const HANDSHAKE_DEADLINE: u64 = 20;

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
    aes::{decrypt, encrypt},
    crand::random_array,
    x25519_cesa::{X25519KeyPair, generate_new_key_pair},
};
use cesa_conn_system::pairing_code::{PAIRING_CODE_LEN, PairingCode};
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
    sync::{Notify, RwLock, mpsc, oneshot},
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
    /// Encrypting a payload with the `d_key` data layer failed.
    FailedToEncryptData,
    /// The `d_key` data layer failed to decrypt: wrong `d_key` or tampered data.
    FailedToDecryptData,
    /// The handshake didn't finish within [`HANDSHAKE_DEADLINE`] seconds.
    HandshakeTimeout,
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
            AuthSnowErrors::FailedToEncryptData => {
                write!(f, "failed to encrypt data with d_key")
            }
            AuthSnowErrors::HandshakeTimeout => {
                write!(f, "handshake did not finish in time")
            }
            AuthSnowErrors::FailedToDecryptData => {
                write!(
                    f,
                    "failed to decrypt data with d_key (wrong d_key or tampered data)"
                )
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
///
/// Only the timed, tagged operations are public: the raw stream and the Noise
/// state stay private, so nothing can bypass tags, size limits or timeouts.
pub struct SecureConnection {
    /// Underlying TCP stream carrying the ciphertext.
    connection: IncomingConnection,
    /// Noise transport state holding the send/receive cipher keys and nonces.
    ts: TransportState,
    /// Noise handshake hash, unique per connection; salts the `d_key` data keys.
    handshake_hash: Zeroizing<[u8; 32]>,
    /// `true` if we opened the connection (client), picks the data key direction.
    is_initiator: bool,
}

/// Bytes the `d_key` data layer adds to a payload: AES-GCM nonce (12) + tag (16).
pub const DATA_LAYER_OVERHEAD: usize = 12 + 16;

impl SecureConnection {
    /// Wraps an already-handshaken stream and its transport state.
    fn new(
        connection: IncomingConnection,
        ts: TransportState,
        handshake_hash: Zeroizing<[u8; 32]>,
        is_initiator: bool,
    ) -> Self {
        Self {
            connection,
            ts,
            handshake_hash,
            is_initiator,
        }
    }

    /// Per-connection, per-direction key for the `d_key` data layer:
    /// HKDF(ikm = d_key, salt = handshake hash, info = direction label).
    ///
    /// Bound to this connection, so a payload can't be replayed into another
    /// one, and each direction has its own key.
    fn data_key(
        &self,
        d_key: &DataKey,
        sending: bool,
    ) -> Result<Zeroizing<[u8; 32]>, AuthSnowErrors> {
        let label: &[u8] = if sending == self.is_initiator {
            b"CPQHA-data-client-to-server"
        } else {
            b"CPQHA-data-server-to-client"
        };

        let mut key = Zeroizing::new([0u8; 32]);

        SimpleHkdf::<Blake2s256>::new(
            Some(self.handshake_hash.as_slice()),
            d_key.expose().as_slice(),
        )
        .expand(label, key.as_mut_slice())
        .map_err(|_| AuthSnowErrors::FailedToExpandHkdf)?;

        Ok(key)
    }

    /// Encrypts `data` with AES-256-GCM under a key derived from `d_key`
    /// ([`Self::data_key`]) and sends `nonce (12) || ciphertext` in chunks.
    ///
    /// This is the inner layer: even with the Noise session broken, the data
    /// stays unreadable without the second password (`d_key`).
    /// The receiver needs the length, i.e. `data.len() + DATA_LAYER_OVERHEAD`.
    pub async fn write_encrypted(
        &mut self,
        data: &[u8],
        d_key: &DataKey,
        tag: Tags,
    ) -> Result<(), AuthSnowErrors> {
        let key = self.data_key(d_key, true)?;

        let (ciphertext, nonce) =
            encrypt(&key, data).map_err(|_| AuthSnowErrors::FailedToEncryptData)?;

        let mut packet = Zeroizing::new(Vec::with_capacity(
            ciphertext.len().saturating_add(nonce.len()),
        ));

        packet.extend_from_slice(&nonce);
        packet.extend_from_slice(&ciphertext);

        self.write_chunked(&packet, tag).await
    }

    /// Receives `len` bytes sent with [`Self::write_encrypted`] and decrypts them.
    ///
    /// `len` includes [`DATA_LAYER_OVERHEAD`]; the caller must bound it first.
    pub async fn read_encrypted(
        &mut self,
        len: usize,
        d_key: &DataKey,
        tag: Tags,
    ) -> Result<Zeroizing<Vec<u8>>, AuthSnowErrors> {
        if len < DATA_LAYER_OVERHEAD {
            return Err(AuthSnowErrors::FailedToDecryptData);
        }

        let packet = self.read_chunked(len, tag).await?;
        let key = self.data_key(d_key, false)?;

        let (nonce, ciphertext) = packet.split_at(12);
        let nonce: &[u8; 12] = nonce
            .try_into()
            .map_err(|_| AuthSnowErrors::FailedToConvertToArray)?;

        // GCM tag check: wrong d_key or tampered data fails here
        decrypt(&key, ciphertext, nonce).map_err(|_| AuthSnowErrors::FailedToDecryptData)
    }

    /// Tags a copy of `src`, encrypts it and sends it to the peer.
    /// At most [`SECURE_MSG_MAX_PAYLOAD`] bytes fit into one message.
    ///
    /// No timeout of its own: only called through [`Self::write_timeout`].
    async fn write(&mut self, src: &[u8], tag: Tags) -> Result<(), AuthSnowErrors> {
        if src.len() > SECURE_MSG_MAX_PAYLOAD {
            return Err(AuthSnowErrors::MessageTooLarge);
        }

        // own buffer sized for the tag up front: the caller's data is never
        // modified and the push can't reallocate (old copies aren't wiped)
        let mut plaintext = Zeroizing::new(Vec::with_capacity(src.len().saturating_add(1)));

        plaintext.extend_from_slice(src);
        tag.tag(&mut plaintext);

        // ciphertext = plaintext + AEAD tag
        let mut buffer = Zeroizing::new(vec![0u8; plaintext.len().saturating_add(SNOW_TAG_LEN)]);

        self.ts
            .write_message(&plaintext, &mut buffer)
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
    ///
    /// No timeout of its own: only called through [`Self::read_timeout`] /
    /// [`recv_secure`], which bound it.
    async fn read(&mut self, buffer: &mut Vec<u8>, tag: Tags) -> Result<usize, AuthSnowErrors> {
        // +1 is the tag byte inside the payload
        if buffer.len() > SECURE_MSG_MAX_PAYLOAD + 1 {
            return Err(AuthSnowErrors::MessageTooLarge);
        }

        let mut message = Zeroizing::new(vec![0u8; buffer.len().saturating_add(SNOW_TAG_LEN)]);

        // private, every caller bounds it with timeout(...) (TIMEOUT / PAIRING_TIMEOUT)
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
    pub async fn write_timeout(&mut self, src: &[u8], tag: Tags) -> Result<(), AuthSnowErrors> {
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
        for chunk in data.chunks(SECURE_MSG_MAX_PAYLOAD) {
            self.write_timeout(chunk, tag).await?;
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

/// Authentication key (`a_key`): the SPAKE2 password every device shares.
///
/// A newtype, so it can't be passed where the data key is expected (or the
/// other way round). No `Debug`/`Copy`; read it only through [`Self::expose`].
#[derive(Clone)]
pub struct AuthKey(Zeroizing<[u8; 32]>);

/// Data key (`d_key`): input of the inner AES-256-GCM data layer.
/// Same rules as [`AuthKey`].
#[derive(Clone)]
pub struct DataKey(Zeroizing<[u8; 32]>);

impl AuthKey {
    /// Takes ownership of an already zeroizing key (e.g. from `derive_key`).
    pub fn new(key: Zeroizing<[u8; 32]>) -> Self {
        Self(key)
    }

    /// Copies a key from a borrowed array.
    pub fn from_bytes(key: &[u8; 32]) -> Self {
        Self(Zeroizing::new(*key))
    }

    /// The raw key bytes.
    pub fn expose(&self) -> &Zeroizing<[u8; 32]> {
        &self.0
    }
}

impl DataKey {
    /// Takes ownership of an already zeroizing key (e.g. from `derive_key`).
    pub fn new(key: Zeroizing<[u8; 32]>) -> Self {
        Self(key)
    }

    /// Copies a key from a borrowed array.
    pub fn from_bytes(key: &[u8; 32]) -> Self {
        Self(Zeroizing::new(*key))
    }

    /// The raw key bytes.
    pub fn expose(&self) -> &Zeroizing<[u8; 32]> {
        &self.0
    }
}

/// Holds the two pre-shared 32-byte keys used by the networker.
///
/// * `a_key` — authentication key, used as the SPAKE2 password during pairing/connecting.
/// * `d_key` — data key, used for the inner encryption layer on actual payloads.
///
/// Both fields are wrapped in `Zeroizing` so they are wiped from memory on drop.
pub struct Keys {
    pub a_key: AuthKey,
    /// The group's `a_salt` (public, but bound into SPAKE2, see `spake2`).
    pub a_salt: Zeroizing<[u8; 32]>,
    pub d_key: DataKey,
}

impl Keys {
    /// Bundles both keys and the auth salt; the types make it impossible to
    /// swap the keys.
    pub fn new(a_key: AuthKey, a_salt: &[u8; 32], d_key: DataKey) -> Self {
        Self {
            a_key,
            a_salt: Zeroizing::new(*a_salt),
            d_key,
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

/// Length of an identity seed: X25519 private key (32) || ML-DSA-87 seed (32).
pub const IDENTITY_SEED_LEN: usize = 64;

impl DeviceKeypairs {
    /// A fresh random identity seed. Made once, when the device is set up,
    /// then kept in the encrypted vault: the same seed is the same device.
    pub fn new_seed() -> Result<Zeroizing<[u8; IDENTITY_SEED_LEN]>, AuthSnowErrors> {
        random_array::<IDENTITY_SEED_LEN>().map_err(|_| AuthSnowErrors::FailedToGenerateRandomData)
    }

    /// The key pairs of a seed (deterministic).
    ///
    /// The ML-DSA seed is passed by value because libcrux takes it that way;
    /// that stack copy is not wiped (libcrux limitation, upstream issue).
    pub fn from_seed(seed: &Zeroizing<[u8; IDENTITY_SEED_LEN]>) -> Self {
        let mut x25519_private = Zeroizing::new([0u8; 32]);
        let mut mldsa_seed = Zeroizing::new([0u8; 32]);
        let (x, m) = seed.split_at(32);
        x25519_private.copy_from_slice(x);
        mldsa_seed.copy_from_slice(m);

        Self {
            x25519_kep: generate_new_key_pair(&x25519_private),
            mldsa_kep: generate_key_pair(*mldsa_seed),
        }
    }

    /// A fresh random identity that is never saved (tests, manual test commands).
    #[cfg(any(test, feature = "test-commands"))]
    pub fn generate() -> Result<Self, AuthSnowErrors> {
        Ok(Self::from_seed(&Self::new_seed()?))
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

/// Most trusted peers kept (each is about 2.7 KB in the vault).
pub const MAX_TRUSTED_PEERS: usize = 256;
/// Longest saved peer name (bytes, UTF-8).
pub const MAX_PEER_NAME_LEN: usize = 255;
/// One encoded peer without its name: x25519 key, ML-DSA key, name length.
const ENCODED_PEER_FIXED_LEN: usize = 32 + MLDSA87_VK_LEN + 1;

/// A peer name that is safe to keep and show: at most [`MAX_PEER_NAME_LEN`]
/// bytes and no control characters (no terminal escape sequences in the TUI).
fn valid_peer_name(name: &str) -> bool {
    name.len() <= MAX_PEER_NAME_LEN && !name.chars().any(char::is_control)
}

/// Encodes the trusted peers for the vault:
/// `count (u16 LE) || (x25519 (32) || ML-DSA vk || name len (u8) || name)*`.
/// `None` if there are too many or a name isn't valid ([`valid_peer_name`]).
pub fn encode_peers(peers: &[TrustedPeer]) -> Option<Vec<u8>> {
    if peers.len() > MAX_TRUSTED_PEERS || !peers.iter().all(|p| valid_peer_name(&p.name)) {
        return None;
    }

    let count = u16::try_from(peers.len()).ok()?;
    let len = peers.iter().try_fold(2usize, |len, peer| {
        len.checked_add(ENCODED_PEER_FIXED_LEN)?
            .checked_add(peer.name.len())
    })?;
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(&count.to_le_bytes());

    for peer in peers {
        let name_len = u8::try_from(peer.name.len()).ok()?;
        out.extend_from_slice(&peer.x25519_pub_key);
        out.extend_from_slice(&peer.mldsa_verification_key);
        out.push(name_len);
        out.extend_from_slice(peer.name.as_bytes());
    }

    Some(out)
}

/// Strict inverse of [`encode_peers`]: exact length, valid names, no
/// duplicate keys. `None` on anything else.
pub fn decode_peers(bytes: &[u8]) -> Option<Vec<TrustedPeer>> {
    let (count, mut rest) = bytes.split_first_chunk::<2>()?;
    let count = usize::from(u16::from_le_bytes(*count));
    if count > MAX_TRUSTED_PEERS {
        return None;
    }

    let mut peers: Vec<TrustedPeer> = Vec::with_capacity(count);
    for _ in 0..count {
        let (x25519_pub_key, after) = rest.split_first_chunk::<32>()?;
        let (mldsa_verification_key, after) = after.split_first_chunk::<MLDSA87_VK_LEN>()?;
        let (&name_len, after) = after.split_first()?;
        let (name, after) = after.split_at_checked(usize::from(name_len))?;
        let name = std::str::from_utf8(name).ok()?;
        if !valid_peer_name(name) {
            return None;
        }
        let name = name.to_owned();

        if peers
            .iter()
            .any(|p| p.x25519_pub_key.ct_eq(x25519_pub_key).into())
        {
            return None;
        }

        peers.push(TrustedPeer {
            x25519_pub_key: *x25519_pub_key,
            mldsa_verification_key: *mldsa_verification_key,
            name,
        });
        rest = after;
    }

    rest.is_empty().then_some(peers)
}

impl TrustedPeer {
    /// A made-up peer for tests: every key byte is `byte`.
    #[cfg(test)]
    pub fn for_test(byte: u8, name: &str) -> Self {
        Self {
            x25519_pub_key: [byte; 32],
            mldsa_verification_key: [byte; MLDSA87_VK_LEN],
            name: name.to_owned(),
        }
    }

    /// Human-readable device name shown to the user.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// First 8 bytes of the Noise static public key, shown to tell devices apart.
    pub fn fingerprint(&self) -> [u8; 8] {
        let mut fingerprint = [0u8; 8];

        for (dst, src) in fingerprint.iter_mut().zip(self.x25519_pub_key.iter()) {
            *dst = *src;
        }

        fingerprint
    }
}

/// A new device waiting for our user's decision: shown with its name and
/// the pairing code, answered with [`PairingRequest::answer`]. Dropping it
/// unanswered is a rejection.
pub struct PairingRequest {
    /// The peer's display name (its address until devices exchange names).
    pub name: String,
    /// The code both devices show, see [`pairing_code`].
    pub code: PairingCode,
    /// Where the decision goes; the handshake waits on the other end.
    decision: oneshot::Sender<bool>,
}

impl PairingRequest {
    /// Sends the user's decision (`true` = the codes match, pair).
    pub fn answer(self, accept: bool) {
        if self.decision.send(accept).is_err() {
            tracing::debug!(name = %self.name, "pairing answered after it had expired");
        }
    }

    /// The handshake stopped waiting (timeout, connection closed).
    pub fn is_expired(&self) -> bool {
        self.decision.is_closed()
    }

    /// A request with a fixed code whose answer goes to `decision` (tests).
    #[cfg(test)]
    pub fn for_test(name: &str, decision: oneshot::Sender<bool>) -> Self {
        Self {
            name: name.to_owned(),
            code: [0; PAIRING_CODE_LEN],
            decision,
        }
    }
}

/// How the handshake asks the user about a new device, and tells the owner
/// that a new peer was saved (so it can be written to the vault).
#[derive(Clone)]
pub struct Pairing {
    /// Bounded by [`MAX_PENDING_PAIRINGS`]; a full queue rejects at once.
    requests: mpsc::Sender<PairingRequest>,
    /// Woken after a peer was added to the trusted list.
    saved: Arc<Notify>,
}

/// The receiving end of a [`Pairing`]: requests for the user, and the
/// "a peer was saved" signal.
pub struct PairingInbox {
    pub requests: mpsc::Receiver<PairingRequest>,
    pub saved: Arc<Notify>,
}

impl Pairing {
    /// A new pairing channel and its receiving end.
    pub fn channel() -> (Self, PairingInbox) {
        let (requests, receiver) = mpsc::channel(MAX_PENDING_PAIRINGS);
        let saved = Arc::new(Notify::new());

        (
            Self {
                requests,
                saved: saved.clone(),
            },
            PairingInbox {
                requests: receiver,
                saved,
            },
        )
    }

    /// A pairing channel whose every request gets the same answer (tests).
    #[cfg(test)]
    pub fn answer_all(accept: bool) -> Self {
        let (pairing, mut inbox) = Self::channel();

        tokio::spawn(async move {
            // an in-process channel, not the network: ends with the senders
            // nosemgrep: cesa.net.read-without-timeout
            while let Some(request) = inbox.requests.recv().await {
                request.answer(accept);
            }
        });

        pairing
    }
}

/// The pairing code of a connection: `HKDF-BLAKE2s(ikm = handshake hash)`
/// expanded to 6 bytes = 48 bits, cut into 8 symbols of 6 bits (big endian,
/// first symbol = highest bits). Both devices have the same handshake hash
/// only without a MITM, so only then do they show the same code.
pub fn pairing_code(handshake_hash: &[u8; 32]) -> Result<PairingCode, AuthSnowErrors> {
    // not secret (it is shown on screen), so no Zeroizing here
    let mut okm = [0u8; 8];

    // the top 2 bytes stay zero, the 6 expanded bytes are the 48 code bits
    let (_, bits) = okm.split_at_mut(2);
    SimpleHkdf::<Blake2s256>::new(None, handshake_hash)
        .expand(PAIRING_CODE_LABEL, bits)
        .map_err(|_| AuthSnowErrors::FailedToExpandHkdf)?;

    let bits = u64::from_be_bytes(okm);
    let mut code = [0u8; PAIRING_CODE_LEN];

    for (symbol, shift) in code.iter_mut().zip([42u32, 36, 30, 24, 18, 12, 6, 0]) {
        // 6 bits: always below PAIRING_SYMBOLS
        *symbol = u8::try_from(bits.checked_shr(shift).unwrap_or(0) & 0x3F)
            .map_err(|_| AuthSnowErrors::FailedToConvertToArray)?;
    }

    Ok(code)
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
    data: &[u8],
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
    let ours = [u8::from(we_have_peer)];

    let theirs = match role {
        Role::Client => {
            send_secure(secure_connection, &ours, IsSavedTag, TIMEOUT).await?;
            recv_secure(secure_connection, 1, IsSavedTag, TIMEOUT).await?
        }
        Role::Server => {
            let theirs = recv_secure(secure_connection, 1, IsSavedTag, TIMEOUT).await?;
            send_secure(secure_connection, &ours, IsSavedTag, TIMEOUT).await?;
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
    if let Some(stored_key) = stored_key
        && stored_key.ct_eq(received_key).unwrap_u8() != 1
    {
        return Err(AuthSnowErrors::PeerKeyMismatch);
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
    let our_key = device_keypairs.mldsa_kep.verification_key.as_slice();

    let our_signature = sign(
        &device_keypairs.mldsa_kep.signing_key,
        handshake_hash.as_slice(),
        role.own_context(),
        *random_array::<32>().map_err(|_| AuthSnowErrors::FailedToSignData)?,
    )
    .map_err(|_| AuthSnowErrors::FailedToSignData)?;
    let our_signature = our_signature.as_slice();

    let (peer_key, peer_signature) = match role {
        Role::Client => {
            // 1. + 2.
            send_secure(
                secure_connection,
                our_key,
                MLDSA87VerificationKeyTag,
                TIMEOUT,
            )
            .await?;
            send_secure(
                secure_connection,
                our_signature,
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

            transcript.extend_from_slice(our_key);
            transcript.extend_from_slice(our_signature);
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
            transcript.extend_from_slice(our_key);
            transcript.extend_from_slice(our_signature);

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
            our_key,
            MLDSA87VerificationKeyTag,
            TIMEOUT,
        )
        .await?;
        send_secure(
            secure_connection,
            our_signature,
            MLDSA87SignatureTag,
            TIMEOUT,
        )
        .await?;
    }

    Ok(*peer_key)
}

/// Asks our user about the peer: the name and the pairing code go to the
/// [`Pairing`] channel, the answer comes back within [`PAIRING_TIMEOUT`].
/// A full queue or a dropped request is a rejection; no answer in time is
/// `Err(PairingTimeout)`.
async fn ask_user(
    pairing: &Pairing,
    name: String,
    handshake_hash: &[u8; 32],
) -> Result<bool, AuthSnowErrors> {
    let code = pairing_code(handshake_hash)?;
    let (decision, answer) = oneshot::channel();

    // full: rejected at once, never queued behind other prompts
    if pairing
        .requests
        .try_send(PairingRequest {
            name,
            code,
            decision,
        })
        .is_err()
    {
        tracing::warn!("too many pairings waiting for the user, rejecting");
        return Ok(false);
    }

    match timeout(Duration::from_secs(PAIRING_TIMEOUT), answer).await {
        Ok(Ok(accept)) => Ok(accept),
        // dropped without an answer (UI gone, networking stopped)
        Ok(Err(_)) => Ok(false),
        Err(_) => Err(AuthSnowErrors::PairingTimeout),
    }
}

/// Pairing confirmation, run only when the two devices don't both know each other.
///
/// Our user compares the pairing code derived from the handshake hash with
/// the other device and decides ([`ask_user`], at most [`PAIRING_TIMEOUT`]).
/// Then:
///
/// 1. -> our decision (client: `ClientAcceptTag`, server: `ServerAcceptTag`)
/// 2. <- the peer's decision
///
/// The peer's user may still be deciding, so the read waits up to
/// [`PAIRING_TIMEOUT`] + [`TIMEOUT`]. We always send our decision, even a
/// rejection or a timeout, so the peer doesn't wait for nothing.
///
/// Returns `Ok(())` only if both users accepted.
async fn confirm_pairing(
    secure_connection: &mut SecureConnection,
    role: Role,
    handshake_hash: &Zeroizing<[u8; 32]>,
    pairing: &Pairing,
) -> Result<(), AuthSnowErrors> {
    let asked = ask_user(
        pairing,
        secure_connection.connection.name.clone(),
        handshake_hash,
    )
    .await;
    let accept = matches!(asked, Ok(true));

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
    let decision = [u8::from(accept)];

    send_secure(secure_connection, &decision, our_tag, TIMEOUT).await?;

    if !accept {
        // a timeout stays visible as such, everything else is a rejection
        return Err(asked.err().unwrap_or(AuthSnowErrors::FailedToPairNewDevice));
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
/// same device can't both add it. Fails when [`MAX_TRUSTED_PEERS`] are saved
/// (more wouldn't fit in the vault).
async fn save_peer(trusted_peers: &TrustedPeers, peer: &TrustedPeer) -> Result<(), AuthSnowErrors> {
    let mut peers = trusted_peers.write().await;

    let known = peers
        .iter()
        .any(|saved| saved.x25519_pub_key.ct_eq(&peer.x25519_pub_key).into());
    let result = if known {
        Ok(())
    } else if peers.len() >= MAX_TRUSTED_PEERS {
        Err(AuthSnowErrors::FailedToPairNewDevice)
    } else {
        peers.push(peer.clone());
        Ok(())
    };
    drop(peers);

    result
}

/// Identifies the peer after the Noise handshake, the same for both roles.
///
/// 1. tell each other whether we have the peer saved ([`exchange_is_saved`])
/// 2. mutual ML-DSA signatures over the handshake hash ([`exchange_signatures`])
///
/// Returns the authenticated peer and whether BOTH devices already know each
/// other; if not, the caller must run [`confirm_pairing`] before trusting it.
async fn identify_peer(
    secure_connection: &mut SecureConnection,
    role: Role,
    peer_static: [u8; 32],
    handshake_hash: &Zeroizing<[u8; 32]>,
    device_keypairs: &DeviceKeypairs,
    trusted_peers: &TrustedPeers,
    transcript: &mut Zeroizing<Vec<u8>>,
) -> Result<(TrustedPeer, bool), AuthSnowErrors> {
    // cloned, so the read lock is released before any network I/O
    let stored_peer = trusted_peers
        .read()
        .await
        .iter()
        .find(|device| device.x25519_pub_key.ct_eq(&peer_static).into())
        .cloned();

    // 1.
    let both_saved = exchange_is_saved(secure_connection, role, stored_peer.is_some()).await?;

    // 2.
    let peer_key = exchange_signatures(
        secure_connection,
        role,
        handshake_hash,
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

    Ok((peer, both_saved))
}

/// Result of a Noise handshake: the transport, the peer's static key and the
/// handshake hash (snow only exposes it before switching to transport mode).
type NoiseResult = (SecureConnection, [u8; 32], Zeroizing<[u8; 32]>);

/// Noise protocol used for the final handshake.
const NOISE_PARAMS: &str = "Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s";

/// Runs the responder side of a `Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s` handshake.
///
/// * `secure_psk` - key derived from SPAKE2 + hybrid KEX, mixed in at message 3
/// * `device_keypairs` - our own long-term keys (X25519 static key)
///
/// Every network read/write is bounded by [`TIMEOUT`].
///
/// Returns the transport, the peer's static key and the handshake hash; the
/// peer is NOT authenticated yet ([`identify_peer`]).
async fn snow_handshake_server(
    mut incoming_connection: IncomingConnection,
    secure_psk: Zeroizing<[u8; 32]>,
    device_keypairs: &DeviceKeypairs,
) -> Result<NoiseResult, AuthSnowErrors> {
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

    let secure_connection = SecureConnection::new(
        incoming_connection,
        transport,
        handshake_hash.clone(),
        false,
    );

    Ok((secure_connection, peer_static, handshake_hash))
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
) -> Result<NoiseResult, AuthSnowErrors> {
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

    let secure_connection =
        SecureConnection::new(outgoing_connection, transport, handshake_hash.clone(), true);

    Ok((secure_connection, peer_static, handshake_hash))
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

/// A connection that finished every automatic step: SPAKE2, KEX, Noise and
/// the verified signatures. `bool` = both devices already know each other.
type Identified = (SecureConnection, TrustedPeer, Zeroizing<[u8; 32]>, bool);

/// Server side of everything up to the verified signatures.
///
/// 1. SPAKE2 exchange + mutual key confirmation using the shared `a_key`
/// 2. hybrid X25519 + ML-KEM key exchange
/// 3. derive a PSK from the SPAKE2 key, both KEX shared secrets and the transcript hash
/// 4. Noise XXpsk3 handshake using that PSK and our device's static key
/// 5. mutual ML-DSA signatures over the handshake hash ([`identify_peer`])
///
/// Returns `Ok(None)` if the peer failed SPAKE2 confirmation.
async fn handshake_server(
    mut incoming_connection: IncomingConnection,
    a_key: &AuthKey,
    a_salt: &[u8; 32],
    device_keypairs: &DeviceKeypairs,
    trusted_peers: &TrustedPeers,
) -> Result<Option<Identified>, AuthSnowErrors> {
    let stream = &mut incoming_connection.stream;
    // every message exchanged before Noise is appended here so the
    // derived PSK is bound to the whole pre-handshake conversation;
    // the signature exchange after Noise is appended too
    let mut transcript = Zeroizing::new(Vec::new());

    // 1. SPAKE2
    let key1 = spake2_exchange_server(stream, a_key, a_salt, &mut transcript)
        .await
        .map_err(|_| AuthSnowErrors::FailedToExchangeSpake2)?;

    if !spake2_confirm_mutual_auth_server(stream, &key1, &mut transcript)
        .await
        .map_err(|_| AuthSnowErrors::FailedToConfirmMutualAuthSpake2)?
    {
        return Ok(None);
    }

    // 2. hybrid KEX (classic + post-quantum)
    let hybrid_kep = hybrid_kex_server(stream, &mut transcript)
        .await
        .map_err(|_| AuthSnowErrors::KexFailed)?;

    // 3. PSK
    let secure_psk = derive_secure_psk(&key1, &hybrid_kep, &transcript)?;

    // 4. Noise
    let (mut secure_connection, peer_static, handshake_hash) =
        snow_handshake_server(incoming_connection, secure_psk, device_keypairs).await?;

    // 5. signatures
    let (peer, both_saved) = identify_peer(
        &mut secure_connection,
        Role::Server,
        peer_static,
        &handshake_hash,
        device_keypairs,
        trusted_peers,
        &mut transcript,
    )
    .await?;

    Ok(Some((secure_connection, peer, handshake_hash, both_saved)))
}

/// Client side of everything up to the verified signatures. Mirrors
/// [`handshake_server`] step by step, the client sends first wherever both do.
///
/// Returns `Ok(None)` if the server's SPAKE2 confirmation was wrong.
async fn handshake_client(
    mut outgoing_connection: IncomingConnection,
    a_key: &AuthKey,
    a_salt: &[u8; 32],
    device_keypairs: &DeviceKeypairs,
    trusted_peers: &TrustedPeers,
) -> Result<Option<Identified>, AuthSnowErrors> {
    let stream = &mut outgoing_connection.stream;
    let mut transcript = Zeroizing::new(Vec::new());

    // 1. SPAKE2
    let key1 = spake2_exchange_client(stream, a_key, a_salt, &mut transcript)
        .await
        .map_err(|_| AuthSnowErrors::FailedToExchangeSpake2)?;

    if !spake2_confirm_mutual_auth_client(stream, &key1, &mut transcript)
        .await
        .map_err(|_| AuthSnowErrors::FailedToConfirmMutualAuthSpake2)?
    {
        return Ok(None);
    }

    // 2. hybrid KEX (classic + post-quantum)
    let hybrid_kep = hybrid_kex_client(stream, &mut transcript)
        .await
        .map_err(|_| AuthSnowErrors::KexFailed)?;

    // 3. PSK
    let secure_psk = derive_secure_psk(&key1, &hybrid_kep, &transcript)?;

    // 4. Noise
    let (mut secure_connection, peer_static, handshake_hash) =
        snow_handshake_client(outgoing_connection, secure_psk, device_keypairs).await?;

    // 5. signatures
    let (peer, both_saved) = identify_peer(
        &mut secure_connection,
        Role::Client,
        peer_static,
        &handshake_hash,
        device_keypairs,
        trusted_peers,
        &mut transcript,
    )
    .await?;

    Ok(Some((secure_connection, peer, handshake_hash, both_saved)))
}

/// An authenticated connection: the channel, who is on the other end, and
/// whether this very connection paired them (the user confirmed the code).
pub struct Authenticated {
    pub connection: SecureConnection,
    pub peer: TrustedPeer,
    /// `true` only if the devices didn't know each other and were paired
    /// on this connection; the join's `GroupSalt` exchange requires it.
    pub newly_paired: bool,
}

/// Runs the automatic part under [`HANDSHAKE_DEADLINE`], then pairing if needed.
///
/// Pairing waits for a human ([`PAIRING_TIMEOUT`]), so it runs after the
/// deadline, and only for a peer whose signature is already verified.
async fn finish_auth(
    identified: Result<Result<Option<Identified>, AuthSnowErrors>, tokio::time::error::Elapsed>,
    role: Role,
    trusted_peers: &TrustedPeers,
    pairing: &Pairing,
) -> Result<Option<Authenticated>, AuthSnowErrors> {
    let Some((mut secure_connection, peer, handshake_hash, both_saved)) =
        identified.map_err(|_| AuthSnowErrors::HandshakeTimeout)??
    else {
        return Ok(None);
    };

    if !both_saved {
        // full: refuse before asking the user, not after they said yes
        if trusted_peers.read().await.len() >= MAX_TRUSTED_PEERS {
            tracing::warn!("too many trusted devices: remove one before pairing another");
            return Err(AuthSnowErrors::FailedToPairNewDevice);
        }

        confirm_pairing(&mut secure_connection, role, &handshake_hash, pairing).await?;
        save_peer(trusted_peers, &peer).await?;

        // the owner writes the new list to the vault
        pairing.saved.notify_one();
    }

    Ok(Some(Authenticated {
        connection: secure_connection,
        peer,
        newly_paired: !both_saved,
    }))
}

/// Authenticates an incoming connection (server side).
///
/// SPAKE2, hybrid KEX, Noise and the ML-DSA signatures ([`handshake_server`])
/// must finish within [`HANDSHAKE_DEADLINE`]; devices that don't both know
/// each other are only accepted after both users confirm (pairing).
///
/// Returns `Ok(None)` if the peer failed SPAKE2 confirmation
/// (i.e. doesn't know the shared key), `Ok(Some(_))` with the secure
/// connection and the authenticated peer on success.
pub async fn auth_incoming(
    keys: Arc<RwLock<Keys>>,
    device_keypairs: &DeviceKeypairs,
    trusted_peers: TrustedPeers,
    incoming_connection: IncomingConnection,
    pairing: &Pairing,
) -> Result<Option<Authenticated>, AuthSnowErrors> {
    // cloned, so the read lock is released before any network I/O
    let (a_key, a_salt) = {
        let keys = keys.read().await;
        (keys.a_key.clone(), keys.a_salt.clone())
    };

    // one deadline for all automatic steps, see HANDSHAKE_DEADLINE
    let identified = timeout(
        Duration::from_secs(HANDSHAKE_DEADLINE),
        handshake_server(
            incoming_connection,
            &a_key,
            &a_salt,
            device_keypairs,
            &trusted_peers,
        ),
    )
    .await;

    finish_auth(identified, Role::Server, &trusted_peers, pairing).await
}

/// Authenticates an outgoing connection (client side). Mirrors [`auth_incoming`].
///
/// Returns `Ok(None)` if the server's SPAKE2 confirmation was wrong (it doesn't
/// know the shared key), `Ok(Some(_))` with the secure connection and the
/// authenticated peer on success.
pub async fn auth_outgoing(
    keys: Arc<RwLock<Keys>>,
    device_keypairs: &DeviceKeypairs,
    trusted_peers: TrustedPeers,
    outgoing_connection: IncomingConnection,
    pairing: &Pairing,
) -> Result<Option<Authenticated>, AuthSnowErrors> {
    let (a_key, a_salt) = {
        let keys = keys.read().await;
        (keys.a_key.clone(), keys.a_salt.clone())
    };

    // one deadline for all automatic steps, see HANDSHAKE_DEADLINE
    let identified = timeout(
        Duration::from_secs(HANDSHAKE_DEADLINE),
        handshake_client(
            outgoing_connection,
            &a_key,
            &a_salt,
            device_keypairs,
            &trusted_peers,
        ),
    )
    .await;

    finish_auth(identified, Role::Client, &trusted_peers, pairing).await
}

#[cfg(test)]
#[allow(clippy::large_futures)] // full handshakes in tests, stack size doesn't matter
mod tests {

    use super::*;
    use tokio::net::{TcpListener, TcpStream};

    const TEST_A_KEY: [u8; 32] = [0xAB; 32];
    const TEST_A_SALT: [u8; 32] = [0x5A; 32];

    /// Pairing that accepts every device.
    fn accept_all() -> Pairing {
        Pairing::answer_all(true)
    }

    /// Pairing for peers that must already be known: rejects, so an
    /// unexpected prompt shows up as an error.
    fn must_not_prompt() -> Pairing {
        Pairing::answer_all(false)
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
                keys: Arc::new(RwLock::new(Keys::new(
                    AuthKey::from_bytes(&a_key),
                    &TEST_A_SALT,
                    DataKey::from_bytes(&[0xCD; 32]),
                ))),
                keypairs: DeviceKeypairs::generate().unwrap(),
                peers: Arc::new(RwLock::new(Vec::new())),
            }
        }
    }

    type AuthResult = Result<Option<Authenticated>, AuthSnowErrors>;

    /// Runs auth_incoming / auth_outgoing against each other over localhost.
    async fn handshake(
        server: &Device,
        client: &Device,
        server_pair: Pairing,
        client_pair: Pairing,
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
                &server_pair,
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
                &client_pair,
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
            handshake(&server, &client, accept_all(), accept_all()).await;

        let Authenticated {
            connection: mut server_conn,
            peer: client_as_seen,
            ..
        } = server_result.unwrap().unwrap();
        let Authenticated {
            connection: mut client_conn,
            peer: server_as_seen,
            ..
        } = client_result.unwrap().unwrap();

        // each side identified the other by its real static key
        assert_eq!(
            &client_as_seen.x25519_pub_key,
            &*client.keypairs.x25519_kep.public
        );
        assert_eq!(
            &server_as_seen.x25519_pub_key,
            &*server.keypairs.x25519_kep.public
        );
        assert_eq!(server.peers.read().await.len(), 1);
        assert_eq!(client.peers.read().await.len(), 1);

        // the transport works in both directions
        let msg = b"ping".to_vec();
        client_conn
            .write_timeout(&msg, Tags::Regular)
            .await
            .unwrap();

        let mut buf = vec![0u8; 4 + 1];
        server_conn
            .read_timeout(&mut buf, Tags::Regular)
            .await
            .unwrap();
        assert_eq!(buf, b"ping");

        let msg = b"pong".to_vec();
        server_conn
            .write_timeout(&msg, Tags::Regular)
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

        let (s, c) = handshake(&server, &client, accept_all(), accept_all()).await;
        assert!(s.unwrap().is_some() && c.unwrap().is_some());

        // must_not_prompt rejects, so this only succeeds if nobody is asked
        let (s, c) = handshake(&server, &client, must_not_prompt(), must_not_prompt()).await;

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

        let (s, c) = handshake(&server, &client, accept_all(), accept_all()).await;
        assert!(s.unwrap().is_some() && c.unwrap().is_some());

        client.peers.write().await.clear();

        // the server still knows the client, but both must confirm again
        let (s, c) = handshake(&server, &client, must_not_prompt(), accept_all()).await;
        assert!(s.is_err() && c.is_err());

        let (s, c) = handshake(&server, &client, accept_all(), accept_all()).await;
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

        let (s, c) = handshake(&server, &client, accept_all(), accept_all()).await;
        assert!(s.unwrap().is_some() && c.unwrap().is_some());

        // same Noise static key, new ML-DSA identity
        client.keypairs = DeviceKeypairs {
            x25519_kep: generate_new_key_pair(&client.keypairs.x25519_kep.private),
            mldsa_kep: generate_key_pair(*random_array::<32>().unwrap()),
        };

        let (s, c) = handshake(&server, &client, accept_all(), accept_all()).await;

        assert_eq!(s.err(), Some(AuthSnowErrors::PeerKeyMismatch));
        assert!(c.is_err());
    }

    /// Test that a peer without the shared a_key is turned away before Noise
    #[tokio::test]
    async fn test_wrong_a_key_returns_none() {
        let server = Device::new(TEST_A_KEY);
        let client = Device::new([0x11; 32]);

        let (s, c) = handshake(&server, &client, accept_all(), accept_all()).await;

        assert!(s.unwrap().is_none());
        // the server closes instead of sending its confirmation
        assert!(c.is_err());
        assert!(server.peers.read().await.is_empty());
        assert!(client.peers.read().await.is_empty());
    }

    /// A pairing channel that answers `accept` and hands every request's
    /// code back to the test.
    fn recording(accept: bool) -> (Pairing, mpsc::UnboundedReceiver<PairingCode>, Arc<Notify>) {
        let (pairing, mut inbox) = Pairing::channel();
        let (codes, seen) = mpsc::unbounded_channel();
        let saved = inbox.saved.clone();

        tokio::spawn(async move {
            while let Some(request) = inbox.requests.recv().await {
                codes.send(request.code).unwrap();
                request.answer(accept);
            }
        });

        (pairing, seen, saved)
    }

    /// Test that both devices are shown the same pairing code, every symbol
    /// is in the table, and another connection gets another code
    #[tokio::test]
    async fn test_pairing_code_same_on_both_sides() {
        use cesa_conn_system::pairing_code::is_valid;

        let server = Device::new(TEST_A_KEY);
        let client = Device::new(TEST_A_KEY);
        let (server_pair, mut server_codes, _) = recording(false);
        let (client_pair, mut client_codes, _) = recording(false);

        // rejected, so the next connection asks again
        let _ = handshake(&server, &client, server_pair.clone(), client_pair.clone()).await;
        let _ = handshake(&server, &client, server_pair, client_pair).await;

        let (first_s, first_c) = (
            server_codes.recv().await.unwrap(),
            client_codes.recv().await.unwrap(),
        );
        let (second_s, second_c) = (
            server_codes.recv().await.unwrap(),
            client_codes.recv().await.unwrap(),
        );

        assert_eq!(first_s, first_c);
        assert_eq!(second_s, second_c);
        assert!(is_valid(&first_s) && is_valid(&second_s));
        // 48 bits: two handshakes colliding would be a 1 in 2^48 accident
        assert_ne!(first_s, second_s);
    }

    /// Test that the code is exactly the 48 HKDF bits, 6 per symbol, first
    /// symbol = highest bits, and that it depends on the handshake hash
    #[test]
    fn test_pairing_code_derivation() {
        let hash = [7u8; 32];
        let mut okm = [0u8; 6];
        SimpleHkdf::<Blake2s256>::new(None, &hash)
            .expand(PAIRING_CODE_LABEL, &mut okm)
            .unwrap();

        let bits: Vec<char> = okm
            .iter()
            .flat_map(|b| format!("{b:08b}").chars().collect::<Vec<_>>())
            .collect();
        let expected: Vec<u8> = bits
            .chunks(6)
            .map(|symbol| u8::from_str_radix(&symbol.iter().collect::<String>(), 2).unwrap())
            .collect();

        assert_eq!(pairing_code(&hash).unwrap().to_vec(), expected);
        assert_eq!(pairing_code(&hash).unwrap(), pairing_code(&hash).unwrap());
        assert_ne!(
            pairing_code(&hash).unwrap(),
            pairing_code(&[8u8; 32]).unwrap()
        );
    }

    /// Test that a request dropped without an answer (UI gone, networking
    /// stopped) rejects at once and tells the peer, instead of waiting out
    /// PAIRING_TIMEOUT
    #[tokio::test]
    async fn test_dropped_request_rejects_at_once() {
        let server = Device::new(TEST_A_KEY);
        let client = Device::new(TEST_A_KEY);
        let (server_pair, mut inbox) = Pairing::channel();

        tokio::spawn(async move {
            while let Some(request) = inbox.requests.recv().await {
                drop(request);
            }
        });

        let started = tokio::time::Instant::now();
        let (s, c) = handshake(&server, &client, server_pair, accept_all()).await;

        assert_eq!(s.err(), Some(AuthSnowErrors::FailedToPairNewDevice));
        assert_eq!(c.err(), Some(AuthSnowErrors::NoServerConfirmation));
        assert!(started.elapsed() < Duration::from_secs(PAIRING_TIMEOUT));
        assert!(server.peers.read().await.is_empty());
        assert!(client.peers.read().await.is_empty());
    }

    /// Test that with MAX_PENDING_PAIRINGS prompts already waiting, the next
    /// one is rejected at once instead of queued
    #[tokio::test]
    async fn test_full_pairing_queue_rejects_at_once() {
        let server = Device::new(TEST_A_KEY);
        let client = Device::new(TEST_A_KEY);
        // never read: the queue stays full
        let (server_pair, _inbox) = Pairing::channel();
        let mut waiting = Vec::new();

        for _ in 0..MAX_PENDING_PAIRINGS {
            let (decision, answer) = oneshot::channel();
            waiting.push(answer);
            server_pair
                .requests
                .try_send(PairingRequest {
                    name: "queued".into(),
                    code: [0; PAIRING_CODE_LEN],
                    decision,
                })
                .unwrap_or_else(|_| panic!("queue full too early"));
        }

        let started = tokio::time::Instant::now();
        let (s, c) = handshake(&server, &client, server_pair, accept_all()).await;

        assert_eq!(s.err(), Some(AuthSnowErrors::FailedToPairNewDevice));
        assert_eq!(c.err(), Some(AuthSnowErrors::NoServerConfirmation));
        assert!(started.elapsed() < Duration::from_secs(PAIRING_TIMEOUT));
        assert!(server.peers.read().await.is_empty());
    }

    /// Test that the owner is told after a new peer was saved (so it can
    /// write the vault), and not when nothing was paired
    #[tokio::test]
    async fn test_saved_peer_is_announced() {
        let server = Device::new(TEST_A_KEY);
        let client = Device::new(TEST_A_KEY);
        let (server_pair, _codes, saved) = recording(true);

        let (s, c) = handshake(&server, &client, server_pair.clone(), accept_all()).await;
        assert!(s.is_ok() && c.is_ok());
        timeout(Duration::from_secs(1), saved.notified())
            .await
            .expect("no saved signal after pairing");

        // known to each other now: no pairing, no signal
        let (s, c) = handshake(&server, &client, server_pair, must_not_prompt()).await;
        assert!(s.is_ok() && c.is_ok());
        assert!(
            timeout(Duration::from_millis(200), saved.notified())
                .await
                .is_err()
        );
    }

    /// Test that a rejection on either side means nobody saves anybody
    #[tokio::test]
    async fn test_client_rejects_pairing() {
        let server = Device::new(TEST_A_KEY);
        let client = Device::new(TEST_A_KEY);

        let (s, c) = handshake(&server, &client, accept_all(), must_not_prompt()).await;

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

        let (_s, c) = handshake(&server, &client, accept_all(), accept_all()).await;
        let Authenticated {
            connection: mut conn,
            ..
        } = c.unwrap().unwrap();

        let too_big = vec![0u8; SECURE_MSG_MAX_PAYLOAD + 1];
        assert_eq!(
            conn.write(&too_big, Tags::Regular).await.err(),
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

        let (s, c) = handshake(&server, &client, accept_all(), accept_all()).await;
        let Authenticated {
            connection: mut server_conn,
            ..
        } = s.unwrap().unwrap();
        let Authenticated {
            connection: mut client_conn,
            ..
        } = c.unwrap().unwrap();

        let msg = b"x".to_vec();
        client_conn.write(&msg, Tags::IsSavedTag).await.unwrap();

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

        let (s, c) = handshake(&server, &client, accept_all(), accept_all()).await;
        let Authenticated {
            connection: mut server_conn,
            ..
        } = s.unwrap().unwrap();
        let Authenticated {
            connection: mut client_conn,
            ..
        } = c.unwrap().unwrap();

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

        let (s, c) = handshake(&server, &client, accept_all(), accept_all()).await;
        let Authenticated {
            connection: mut server_conn,
            ..
        } = s.unwrap().unwrap();
        let Authenticated {
            connection: mut client_conn,
            ..
        } = c.unwrap().unwrap();

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

        let (s, c) = handshake(&server, &client, accept_all(), accept_all()).await;
        let Authenticated {
            connection: mut server_conn,
            ..
        } = s.unwrap().unwrap();
        let Authenticated {
            connection: mut client_conn,
            ..
        } = c.unwrap().unwrap();

        // announce more than we send, then hang up
        client_conn
            .write_chunked(&[7u8; 100], Tags::Regular)
            .await
            .unwrap();
        drop(client_conn);

        assert!(server_conn.read_chunked(200, Tags::Regular).await.is_err());
    }

    /// Test that the d_key layer round-trips in both directions
    #[tokio::test]
    async fn test_encrypted_roundtrip_both_directions() {
        let server = Device::new(TEST_A_KEY);
        let client = Device::new(TEST_A_KEY);

        let (s, c) = handshake(&server, &client, accept_all(), accept_all()).await;
        let Authenticated {
            connection: mut server_conn,
            ..
        } = s.unwrap().unwrap();
        let Authenticated {
            connection: mut client_conn,
            ..
        } = c.unwrap().unwrap();

        let d_key = server.keys.read().await.d_key.clone();
        let data: Vec<u8> = (0..=250u8).cycle().take(200_000).collect();
        let len = data.len() + DATA_LAYER_OVERHEAD;

        let send = client_conn.write_encrypted(&data, &d_key, Tags::Regular);
        let recv = server_conn.read_encrypted(len, &d_key, Tags::Regular);
        let (sent, received) = tokio::join!(send, recv);
        sent.unwrap();
        assert_eq!(received.unwrap().as_slice(), data.as_slice());

        let send = server_conn.write_encrypted(b"back", &d_key, Tags::Regular);
        let recv = client_conn.read_encrypted(4 + DATA_LAYER_OVERHEAD, &d_key, Tags::Regular);
        let (sent, received) = tokio::join!(send, recv);
        sent.unwrap();
        assert_eq!(received.unwrap().as_slice(), b"back");
    }

    /// Test that a different d_key on the receiver fails decryption
    #[tokio::test]
    async fn test_encrypted_wrong_d_key_fails() {
        let server = Device::new(TEST_A_KEY);
        let client = Device::new(TEST_A_KEY);

        let (s, c) = handshake(&server, &client, accept_all(), accept_all()).await;
        let Authenticated {
            connection: mut server_conn,
            ..
        } = s.unwrap().unwrap();
        let Authenticated {
            connection: mut client_conn,
            ..
        } = c.unwrap().unwrap();

        let send_key = DataKey::from_bytes(&[1u8; 32]);
        let recv_key = DataKey::from_bytes(&[2u8; 32]);

        let send = client_conn.write_encrypted(b"clipboard", &send_key, Tags::Regular);
        let recv = server_conn.read_encrypted(9 + DATA_LAYER_OVERHEAD, &recv_key, Tags::Regular);
        let (_, received) = tokio::join!(send, recv);

        assert_eq!(received.err(), Some(AuthSnowErrors::FailedToDecryptData));
    }

    /// Test that the data keys differ per direction and per connection
    #[tokio::test]
    async fn test_data_keys_bound_to_direction_and_connection() {
        let server = Device::new(TEST_A_KEY);
        let client = Device::new(TEST_A_KEY);
        let d_key = DataKey::from_bytes(&[9u8; 32]);

        let (s, c) = handshake(&server, &client, accept_all(), accept_all()).await;
        let Authenticated {
            connection: server_conn,
            ..
        } = s.unwrap().unwrap();
        let Authenticated {
            connection: client_conn,
            newly_paired: first_paired,
            ..
        } = c.unwrap().unwrap();
        // the first connection paired them
        assert!(first_paired);

        let c2s_client = client_conn.data_key(&d_key, true).unwrap();
        let c2s_server = server_conn.data_key(&d_key, false).unwrap();
        let s2c_client = client_conn.data_key(&d_key, false).unwrap();

        // both ends agree per direction, directions differ
        assert_eq!(*c2s_client, *c2s_server);
        assert_ne!(*c2s_client, *s2c_client);

        // a new connection gets new keys (new handshake hash)
        let (_s2, c2) = handshake(&server, &client, accept_all(), accept_all()).await;
        let Authenticated {
            connection: client_conn2,
            newly_paired: second_paired,
            ..
        } = c2.unwrap().unwrap();
        // the second one only reconnected, both already trusted each other
        assert!(!second_paired);
        assert_ne!(*client_conn2.data_key(&d_key, true).unwrap(), *c2s_client);
    }

    /// Test that a handshake past HANDSHAKE_DEADLINE is reported as HandshakeTimeout
    #[tokio::test]
    async fn test_handshake_deadline_maps_to_timeout() {
        let elapsed = timeout(Duration::ZERO, std::future::pending::<()>())
            .await
            .unwrap_err();
        let peers: TrustedPeers = Arc::new(RwLock::new(Vec::new()));

        let result = finish_auth(Err(elapsed), Role::Server, &peers, &accept_all()).await;

        assert_eq!(result.err(), Some(AuthSnowErrors::HandshakeTimeout));
        assert!(peers.read().await.is_empty());
    }

    /// Test that a peer which connects and goes silent is dropped, not held forever
    #[tokio::test]
    async fn test_silent_peer_times_out() {
        let server = Device::new(TEST_A_KEY);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // connected, but never sends anything
        let _silent = TcpStream::connect(addr).await.unwrap();
        let (stream, peer_addr) = listener.accept().await.unwrap();

        let started = tokio::time::Instant::now();
        let result = auth_incoming(
            server.keys.clone(),
            &server.keypairs,
            server.peers.clone(),
            IncomingConnection::new(stream, peer_addr),
            &accept_all(),
        )
        .await;

        assert!(result.is_err());
        assert!(started.elapsed() <= Duration::from_secs(HANDSHAKE_DEADLINE));
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

    /// Test that the same identity seed gives the same keys, a different seed
    /// different ones (a restart must look like the same device)
    #[test]
    fn test_identity_from_seed() {
        let seed = DeviceKeypairs::new_seed().unwrap();
        let a = DeviceKeypairs::from_seed(&seed);
        let b = DeviceKeypairs::from_seed(&seed);
        let other = DeviceKeypairs::from_seed(&DeviceKeypairs::new_seed().unwrap());

        assert_eq!(*a.x25519_kep.public, *b.x25519_kep.public);
        assert_eq!(
            a.mldsa_kep.verification_key.as_slice(),
            b.mldsa_kep.verification_key.as_slice()
        );
        assert_ne!(*a.x25519_kep.public, *other.x25519_kep.public);
        assert_ne!(
            a.mldsa_kep.verification_key.as_slice(),
            other.mldsa_kep.verification_key.as_slice()
        );
    }

    /// Test that trusted peers encode and decode back unchanged
    #[test]
    fn test_peers_roundtrip() {
        let peers = vec![
            TrustedPeer::for_test(1, "laptop"),
            TrustedPeer::for_test(2, "zażółć"),
            TrustedPeer::for_test(3, ""),
        ];
        let decoded = decode_peers(&encode_peers(&peers).unwrap()).unwrap();

        assert_eq!(decoded.len(), 3);
        for (a, b) in peers.iter().zip(&decoded) {
            assert_eq!(a.x25519_pub_key, b.x25519_pub_key);
            assert_eq!(a.mldsa_verification_key, b.mldsa_verification_key);
            assert_eq!(a.name, b.name);
        }
        assert_eq!(decode_peers(&encode_peers(&[]).unwrap()).unwrap().len(), 0);
    }

    /// Test that the peer list decoding is strict
    #[test]
    fn test_peers_decode_strict() {
        let good = encode_peers(&[TrustedPeer::for_test(1, "ab")]).unwrap();

        // truncated anywhere, or extra bytes
        for cut in 0..good.len() {
            assert!(decode_peers(&good[..cut]).is_none(), "cut at {cut}");
        }
        let mut longer = good.clone();
        longer.push(0);
        assert!(decode_peers(&longer).is_none());

        // name not UTF-8
        let mut bad_name = good.clone();
        let last = bad_name.len() - 1;
        bad_name[last] = 0xFF;
        assert!(decode_peers(&bad_name).is_none());

        // a terminal escape sequence in a name
        let escape = encode_peers(&[TrustedPeer::for_test(1, "ab")]).unwrap();
        let mut escape = escape.clone();
        let last = escape.len() - 2;
        escape[last] = 0x1B;
        assert!(decode_peers(&escape).is_none());

        // the same key twice
        let twice =
            encode_peers(&[TrustedPeer::for_test(1, "a"), TrustedPeer::for_test(1, "b")]).unwrap();
        assert!(decode_peers(&twice).is_none());

        // count above the limit
        let mut too_many = good.clone();
        too_many[..2].copy_from_slice(&u16::try_from(MAX_TRUSTED_PEERS + 1).unwrap().to_le_bytes());
        assert!(decode_peers(&too_many).is_none());
    }

    /// Test that too many peers or too long a name can't be encoded
    #[test]
    fn test_peers_encode_limits() {
        let many: Vec<_> = (0..=MAX_TRUSTED_PEERS)
            .map(|i| TrustedPeer::for_test(u8::try_from(i % 256).unwrap(), ""))
            .collect();
        assert!(encode_peers(&many).is_none());
        assert!(encode_peers(&many[..MAX_TRUSTED_PEERS]).is_some());

        let long = "x".repeat(MAX_PEER_NAME_LEN + 1);
        assert!(encode_peers(&[TrustedPeer::for_test(1, &long)]).is_none());
        let longest = "x".repeat(MAX_PEER_NAME_LEN);
        assert!(encode_peers(&[TrustedPeer::for_test(1, &longest)]).is_some());

        for bad in ["a\u{1b}[2J", "new\nline", "\u{7f}", "\u{9b}"] {
            assert!(
                encode_peers(&[TrustedPeer::for_test(1, bad)]).is_none(),
                "{bad:?}"
            );
        }
        assert!(encode_peers(&[TrustedPeer::for_test(1, "Laptop Czarka 💻")]).is_some());
    }

    /// Test that saving a peer is idempotent and stops at the limit
    #[tokio::test]
    async fn test_save_peer_limit() {
        let peers: TrustedPeers = Arc::default();
        save_peer(&peers, &TrustedPeer::for_test(1, "a"))
            .await
            .unwrap();
        save_peer(&peers, &TrustedPeer::for_test(1, "a"))
            .await
            .unwrap();
        assert_eq!(peers.read().await.len(), 1);

        {
            let mut list = peers.write().await;
            list.clear();
            for i in 0..MAX_TRUSTED_PEERS {
                let mut peer = TrustedPeer::for_test(0, "");
                peer.x25519_pub_key[..8].copy_from_slice(&u64::try_from(i).unwrap().to_le_bytes());
                list.push(peer);
            }
        }
        assert!(
            save_peer(&peers, &TrustedPeer::for_test(0xEE, "new"))
                .await
                .is_err()
        );
        // one already saved is still fine when full
        let first = peers.read().await[0].clone();
        save_peer(&peers, &first).await.unwrap();
    }
}
