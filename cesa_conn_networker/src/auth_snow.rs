/*
TODO:
add visual comparison if peer is not saved in trusted_addrs
add tests
add client-side
add chunking to SecureConnection read/write
add per-device static key pairs: exchange public keys during pairing (SPAKE2),
  keep a synced list of trusted device public keys, check the Noise remote
  static against it (instead of the shared d_key), allow revoking one device
add encrypting/decrypting data with aes256 in Secure Connection with d_key
replace noise static key with a random keypair
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

/// read/write timeout (seconds)
pub const TIMEOUT: u64 = 5;

pub const PARING_TIMEOUT: u64 = 60;

use crate::{
    auth_snow::Tags::{MLDSA87SignatureTag, MLDSA87VerificationKeyTag},
    hybrid_kex::hybrid_kex_server,
    spake2::{spake2_confirm_mutual_auth_server, spake2_exchange_server},
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
    FaledToExpandHkdf,
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
    FailedToEnterTansportMode,
    /// The SPAKE2 message exchange with the peer failed.
    FailedToExchangeSpake2,
    /// The SPAKE2 key confirmation step failed.
    FailedToConfirmMutualAuthSpake2,
    /// The peer did not confirm the hybrid key exchange.
    FailedToConfirmKex,
    /// The hybrid (X25519 + ML-KEM) key exchange failed.
    KexFailed,
    /// Any step of the Noise handshake failed.
    FailedToCompleteSnowHandshake,
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
    FailedToReadFromSecureConnection,
    FailedToPairNewDevice,
    FailedToVerifySignature,
    FailedToSignData,
    FailedToWriteToSecureConnection,
    ParingTimeout,
}

impl fmt::Display for AuthSnowErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthSnowErrors::FailedToReadFromStream => {
                write!(f, "failed to read from stream")
            }
            AuthSnowErrors::FailedToWriteToStream => write!(f, "failed to write to stream"),
            AuthSnowErrors::FaledToExpandHkdf => write!(f, "failed to expand hkdf"),
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
            AuthSnowErrors::FailedToEnterTansportMode => {
                write!(f, "failed to enter transport mode")
            }
            AuthSnowErrors::FailedToExchangeSpake2 => {
                write!(f, "failed to make exchange for spake2")
            }
            AuthSnowErrors::FailedToConfirmMutualAuthSpake2 => {
                write!(f, "failed to confirm mutual auth in spake2")
            }
            AuthSnowErrors::FailedToConfirmKex => {
                write!(f, "failed to cofirm key exchange")
            }
            AuthSnowErrors::KexFailed => {
                write!(f, "key exchange failed")
            }
            AuthSnowErrors::FailedToCompleteSnowHandshake => {
                write!(f, "failed to complete snow handshake")
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
                write!(f, "failed to verify peers signature")
            }
            AuthSnowErrors::FailedToSignData => {
                write!(f, "failed to sign the data")
            }
            AuthSnowErrors::FailedToWriteToSecureConnection => {
                write!(f, "failed to write data to secure connection")
            }
            AuthSnowErrors::ParingTimeout => {
                write!(f, "pairing timed out")
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
    MLDSA87VerificationKeyTag = 0x02,
    MLDSA87SignatureTag = 0x03,
}

impl Tags {
    /// Appends the tag byte to the end of `packet`.
    pub fn tag(self, packet: &mut Vec<u8>) {
        packet.push(self as u8);
    }

    /// Returns `true` if `packet` ends with this tag.
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
    pub async fn write(&mut self, src: &mut Vec<u8>, tag: Tags) -> Result<(), AuthSnowErrors> {
        tag.tag(src);

        // ciphertext = plaintext + AEAD tag
        let mut buffer = Zeroizing::new(vec![0u8; src.len() + SNOW_TAG_LEN]);

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
        let mut message = Zeroizing::new(vec![0u8; buffer.len() + SNOW_TAG_LEN]);

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

        Ok(read - 1)
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

    pub fn update(&mut self, data: Self) {
        *self.a_key = *data.a_key;
        *self.d_key = *data.d_key;
    }

    /// Wraps two raw 32-byte arrays in `Zeroizing` so they are wiped from memory on drop.
    pub fn new(a_key: [u8; 32], d_key: [u8; 32]) -> Self {
        Self {
            a_key: Zeroizing::new(a_key),
            d_key: Zeroizing::new(d_key),
        }
    }
}

pub struct Salts {
    pub a_salt: Zeroizing<[u8; 32]>,
    pub d_salt: Zeroizing<[u8; 32]>,
}

impl Salts {
    /// Splits a packed 64-byte buffer into the two keys (`a_key` = bytes 0–31, `d_key` = bytes 32–63).
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

    /// Packs both keys into `data` (`a_key` in bytes 0–31, `d_key` in bytes 32–63). Inverse of `from_ref`.
    pub fn to_ref(&self, data: &mut [u8; 64]) {
        data[..32].copy_from_slice(&*self.a_salt);
        data[32..].copy_from_slice(&*self.d_salt);
    }

    pub fn update(&mut self, data: Self) {
        *self.a_salt = *data.a_salt;
        *self.d_salt = *data.d_salt;
    }

    pub fn new(a_salt: [u8; 32], d_salt: [u8; 32]) -> Self {
        Self {
            a_salt: Zeroizing::new(a_salt),
            d_salt: Zeroizing::new(d_salt),
        }
    }
}

pub struct DeviceKeypairs {
    x25519_kep: X25519KeyPair,
    mldsa_kep: MLDSA87KeyPair,
}

impl DeviceKeypairs {
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

    pub fn new(x25519_kep: X25519KeyPair, mldsa_kep: MLDSA87KeyPair) -> Self {
        Self {
            x25519_kep,
            mldsa_kep,
        }
    }
}

#[derive(Clone)]
pub struct TrustedPeer {
    x25519_pub_key: [u8; 32],
    mldsa_verification_key: [u8; 2592],
    name: String,
}

impl TrustedPeer {
    pub fn new(x25519_pub_key: [u8; 32], mldsa_verification_key: [u8; 2592], name: String) -> Self {
        Self {
            x25519_pub_key,
            mldsa_verification_key,
            name,
        }
    }
}

async fn verify_sig_server(
    secure_connection: &mut SecureConnection,
    handshake_hash: Zeroizing<[u8; 32]>,
    trusted_peer: Option<&TrustedPeer>,
    device_keypairs: &DeviceKeypairs,
) -> Result<[u8; MLDSA87VerificationKey::len()], AuthSnowErrors> {
    match trusted_peer {
        Some(peer) => {
            let mut sig_buffer = vec![0u8; MLDSA87Signature::len() + 1];

            let read = secure_connection.read(&mut sig_buffer, MLDSA87SignatureTag);

            timeout(Duration::from_secs(TIMEOUT), read)
                .await
                .map_err(|_| AuthSnowErrors::ReadTimeout)?
                .map_err(|_| AuthSnowErrors::FailedToReadFromSecureConnection)?;

            let signature = MLDSA87Signature::new(
                *sig_buffer
                    .as_array()
                    .ok_or(AuthSnowErrors::FailedToConvertToArray)?,
            );

            verify(
                &MLDSA87VerificationKey::new(peer.mldsa_verification_key.clone()),
                handshake_hash.as_slice(),
                b"CesaConn Handshake",
                &signature,
            )
            .map_err(|_| AuthSnowErrors::FailedToVerifySignature)?;

            let ver_key = &mut device_keypairs
                .mldsa_kep
                .verification_key
                .clone()
                .as_mut_slice()
                .to_vec();

            let mut signature = sign(
                &device_keypairs.mldsa_kep.signing_key,
                handshake_hash.as_slice(),
                b"CesaConn Handshake",
                *random_array::<32>().map_err(|_| AuthSnowErrors::FailedToSignData)?,
            )
            .map_err(|_| AuthSnowErrors::FailedToSignData)?
            .as_mut_slice()
            .to_vec();

            let send = secure_connection.write(ver_key, MLDSA87VerificationKeyTag);

            timeout(Duration::from_secs(TIMEOUT), send)
                .await
                .map_err(|_| AuthSnowErrors::WriteTimeout)?
                .map_err(|_| AuthSnowErrors::FailedToWriteToSecureConnection)?;

            let send = secure_connection.write(&mut signature, MLDSA87SignatureTag);

            timeout(Duration::from_secs(TIMEOUT), send)
                .await
                .map_err(|_| AuthSnowErrors::WriteTimeout)?
                .map_err(|_| AuthSnowErrors::FailedToWriteToSecureConnection)?;

            Ok(peer.mldsa_verification_key.clone())
        }
        None => {
            let mut ver_buffer = vec![0u8; MLDSA87VerificationKey::len() + 1];
            let mut sig_buffer = vec![0u8; MLDSA87Signature::len() + 1];

            let read = secure_connection.read(&mut ver_buffer, MLDSA87VerificationKeyTag);

            timeout(Duration::from_secs(TIMEOUT), read)
                .await
                .map_err(|_| AuthSnowErrors::ReadTimeout)?
                .map_err(|_| AuthSnowErrors::FailedToReadFromSecureConnection)?;

            let read = secure_connection.read(&mut sig_buffer, MLDSA87SignatureTag);

            timeout(Duration::from_secs(TIMEOUT), read)
                .await
                .map_err(|_| AuthSnowErrors::ReadTimeout)?
                .map_err(|_| AuthSnowErrors::FailedToReadFromSecureConnection)?;

            let verification_key = MLDSA87VerificationKey::new(
                *ver_buffer
                    .as_array()
                    .ok_or(AuthSnowErrors::FailedToConvertToArray)?,
            );

            let signature = MLDSA87Signature::new(
                *sig_buffer
                    .as_array()
                    .ok_or(AuthSnowErrors::FailedToConvertToArray)?,
            );

            verify(
                &verification_key,
                handshake_hash.as_slice(),
                b"CesaConn Handshake",
                &signature,
            )
            .map_err(|_| AuthSnowErrors::FailedToVerifySignature)?;

            let ver_key = &mut device_keypairs
                .mldsa_kep
                .verification_key
                .clone()
                .as_mut_slice()
                .to_vec();

            let mut signature = sign(
                &device_keypairs.mldsa_kep.signing_key,
                handshake_hash.as_slice(),
                b"CesaConn Handshake",
                *random_array::<32>().map_err(|_| AuthSnowErrors::FailedToSignData)?,
            )
            .map_err(|_| AuthSnowErrors::FailedToSignData)?
            .as_mut_slice()
            .to_vec();

            let send = secure_connection.write(ver_key, MLDSA87VerificationKeyTag);

            timeout(Duration::from_secs(TIMEOUT), send)
                .await
                .map_err(|_| AuthSnowErrors::WriteTimeout)?
                .map_err(|_| AuthSnowErrors::FailedToWriteToSecureConnection)?;

            let send = secure_connection.write(&mut signature, MLDSA87SignatureTag);

            timeout(Duration::from_secs(TIMEOUT), send)
                .await
                .map_err(|_| AuthSnowErrors::WriteTimeout)?
                .map_err(|_| AuthSnowErrors::FailedToWriteToSecureConnection)?;

            Ok(*ver_buffer
                .as_array()
                .ok_or(AuthSnowErrors::FailedToConvertToArray)?)
        }
    }
}

/// Runs the responder side of a `Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s` handshake.
///
/// * `secure_psk` - key derived from SPAKE2 + hybrid KEX, mixed in at message 3
/// * `d_key` - our static X25519 private key (the same on both peers)
///
/// Every network read/write is bounded by [`TIMEOUT`].
///
/// Returns `Ok(None)` if the peer's static key doesn't match ours.
async fn snow_handshake_server(
    mut incoming_connection: IncomingConnection,
    secure_psk: Zeroizing<[u8; 32]>,
    device_keypairs: &DeviceKeypairs,
    trusted_peers: TrustedPeers,
    pair_fallback: fn(&String, &[u8; 32]) -> bool,
) -> Result<Option<(SecureConnection, TrustedPeer)>, AuthSnowErrors> {
    let stream = &mut incoming_connection.stream;

    // psk3: the PSK is mixed in at the end of the third handshake message
    let mut builder = Builder::new(
        "Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s"
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
    let read = stream.read_exact(&mut read_buffer[..SNOW_MSG1_LEN]);

    timeout(Duration::from_secs(TIMEOUT), read)
        .await
        .map_err(|_| AuthSnowErrors::ReadTimeout)?
        .map_err(|_| AuthSnowErrors::FailedToReadFromStream)?;

    builder
        .read_message(&read_buffer[..SNOW_MSG1_LEN], buffer.as_mut_slice())
        .map_err(|_| AuthSnowErrors::FailedToReadSnowMessage)?;

    // <- e, ee, s, es (empty payload)
    builder
        .write_message(&[], &mut buffer[..SNOW_MSG2_LEN])
        .map_err(|_| AuthSnowErrors::FailedToWriteSnowMessage)?;

    let write = stream.write_all(&buffer[..SNOW_MSG2_LEN]);

    timeout(Duration::from_secs(TIMEOUT), write)
        .await
        .map_err(|_| AuthSnowErrors::WriteTimeout)?
        .map_err(|_| AuthSnowErrors::FailedToWriteToStream)?;

    // -> s, se, psk
    let read = stream.read_exact(&mut read_buffer[..SNOW_MSG3_LEN]);

    timeout(Duration::from_secs(TIMEOUT), read)
        .await
        .map_err(|_| AuthSnowErrors::ReadTimeout)?
        .map_err(|_| AuthSnowErrors::FailedToReadFromStream)?;

    builder
        .read_message(&read_buffer[..SNOW_MSG3_LEN], buffer.as_mut_slice())
        .map_err(|_| AuthSnowErrors::FailedToReadSnowMessage)?;

    // both peers use the same `d_key`, so the peer's static public key
    // must equal the one derived from ours, otherwise reject the connection
    let peer_static: [u8; 32] = builder
        .get_remote_static()
        .ok_or(AuthSnowErrors::SnowFailedToGetRemoteStatic)?
        .try_into()
        .map_err(|_| AuthSnowErrors::FailedToConvertToArray)?;

    let mut handshake_hash = Zeroizing::new([0u8; 32]);

    handshake_hash.clone_from_slice(builder.get_handshake_hash());

    // handshake complete, switch to encrypted transport
    let transport = builder
        .into_transport_mode()
        .map_err(|_| AuthSnowErrors::FailedToEnterTansportMode)?;

    let mut secure_connection = SecureConnection::new(incoming_connection, transport);

    let new_device = trusted_peers
        .read()
        .await
        .iter()
        .find(|device| device.x25519_pub_key.ct_eq(&peer_static).into())
        .cloned();

    let trusted_peer = match new_device {
        Some(device) => {
            verify_sig_server(
                &mut secure_connection,
                handshake_hash,
                Some(&device),
                device_keypairs,
            )
            .await
            .map_err(|_| AuthSnowErrors::FailedToVerifySignature)?;
            device
        }
        None => {
            let name_clone = secure_connection.connection.name.clone();
            let handshake_hash_clone = handshake_hash.clone();

            let accept = timeout(
                Duration::from_secs(PARING_TIMEOUT),
                spawn_blocking(move || pair_fallback(&name_clone, &handshake_hash_clone)),
            )
            .await
            .map_err(|_| AuthSnowErrors::ParingTimeout)?
            .map_err(|_| AuthSnowErrors::FailedToPairNewDevice)?;

            if !accept {
                return Err(AuthSnowErrors::FailedToPairNewDevice);
            }

            let ver_key = verify_sig_server(
                &mut secure_connection,
                handshake_hash,
                None,
                device_keypairs,
            )
            .await
            .map_err(|_| AuthSnowErrors::FailedToVerifySignature)?;

            let trusted_peer = TrustedPeer {
                x25519_pub_key: peer_static,
                mldsa_verification_key: ver_key,
                name: secure_connection.connection.name.clone(),
            };

            let mut peer = trusted_peers.write().await;

            if !peer
                .iter()
                .any(|peer| peer.x25519_pub_key.ct_eq(&peer_static).into())
            {
                peer.push(trusted_peer.clone());
            }

            trusted_peer
        }
    };

    Ok(Some((secure_connection, trusted_peer)))
}

/// Authenticates an incoming connection (server side).
///
/// Steps:
/// 1. SPAKE2 exchange + mutual key confirmation using the shared `a_key`
/// 2. hybrid X25519 + ML-KEM key exchange
/// 3. derive a PSK from the SPAKE2 key, both KEX shared secrets and the transcript hash
/// 4. Noise XXpsk3 handshake using that PSK and our static `d_key`
///
/// Returns `Ok(None)` if the peer failed SPAKE2 confirmation
/// (i.e. doesn't know the shared key) or its Noise static key doesn't match,
/// `Ok(Some(_))` on success.
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
    // derived PSK is bound to the whole pre-handshake conversation
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

    // 3. PSK = HKDF(key1 || x25519_ss || mlkem_ss || HKDF(transcript))
    // key1 binds the KEX to SPAKE2, so a MITM that only relays SPAKE2 can't derive it
    let mut transcript_hash = Zeroizing::new([0u8; 32]);

    SimpleHkdf::<Blake2s256>::new(None, &transcript)
        .expand(&[], transcript_hash.as_mut_slice())
        .map_err(|_| AuthSnowErrors::FaledToExpandHkdf)?;

    let mut psk = Zeroizing::new(Vec::new());

    psk.extend_from_slice(&key1);
    psk.extend_from_slice(hybrid_kep.x25519_ss.as_slice());
    psk.extend_from_slice(hybrid_kep.mlkem_ss.as_slice());
    psk.extend_from_slice(transcript_hash.as_slice());

    let psk_hk = SimpleHkdf::<Blake2s256>::new(None, &psk);

    let mut secure_psk = Zeroizing::new([0u8; 32]);

    psk_hk
        .expand(b"CPQHA-psk", secure_psk.as_mut_slice())
        .map_err(|_| AuthSnowErrors::FaledToExpandHkdf)?;

    // 4. Noise handshake
    snow_handshake_server(
        incoming_connection,
        secure_psk,
        device_keypairs,
        trusted_peers,
        pair_fallback,
    )
    .await
    .map_err(|_| AuthSnowErrors::FailedToCompleteSnowHandshake)
}
