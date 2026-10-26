/*
TODO:

add tests
*/

use std::time::Duration;

use crate::{
    auth_snow::{AuthSnowErrors, TIMEOUT},
    hybrid_kex::Tags::{ConfirmByte, MlKeyPub, X25519Pub},
};
use cesa_conn_crypto::{
    crand::random_array,
    x25519_cesa::{self, calculate_shared_key},
};
use libcrux_ml_kem::mlkem1024::{MlKem1024Ciphertext, decapsulate, encapsulate, generate_key_pair};
use libcrux_ml_kem::mlkem1024::{MlKem1024PublicKey, validate_private_key, validate_public_key};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};
use zeroize::{Zeroize, Zeroizing};

/// ML-KEM-1024 ciphertext length (1568 bytes).
const MLKEM1024_CIPHERTEXT_LEN: usize = MlKem1024Ciphertext::len();

/// 32-byte shared secret, zeroized on drop.
pub type SsKey = Zeroizing<[u8; 32]>;

/// Result of the hybrid key exchange: one shared secret from the classic
/// X25519 exchange and one from the post-quantum ML-KEM-1024 exchange.
pub struct HybridKep {
    /// X25519 ECDH shared secret.
    pub x25519_ss: SsKey,
    /// ML-KEM-1024 encapsulated shared secret.
    pub mlkem_ss: SsKey,
}

/// Packet type marker appended as the last byte of every KEX message.
#[repr(u8)]
#[derive(Clone, Copy)]
pub enum Tags {
    /// X25519 public key.
    X25519Pub = 0x01,
    /// Confirmation that the peer accepted the previous step.
    ConfirmByte = 0x02,
    /// ML-KEM public key (client -> server) or ciphertext (server -> client).
    MlKeyPub = 0x03,
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

/// Server side of the X25519 exchange.
///
/// 1. <- client's public key
/// 2. -> our ephemeral public key
/// 3. <- client's confirm byte
///
/// All messages (tags included) are appended to `transcript`.
async fn x25519_kex_server(
    stream: &mut TcpStream,
    transcript: &mut Zeroizing<Vec<u8>>,
) -> Result<SsKey, AuthSnowErrors> {
    // fresh ephemeral key pair for this connection
    let x25519_pair = x25519_cesa::generate_new_key_pair(
        *random_array::<32>().map_err(|_| AuthSnowErrors::FailedToGenerateRandomData)?,
    );

    let mut x25519_pub = Zeroizing::new(x25519_pair.public.to_vec());

    X25519Pub.tag(&mut x25519_pub);

    // 1. client's public key
    let mut x25519_recv = Zeroizing::new(vec![0u8; 32 + 1]); // + tag

    let read = stream.read_exact(&mut x25519_recv);

    timeout(Duration::from_secs(TIMEOUT), read)
        .await
        .map_err(|_| AuthSnowErrors::ReadTimeout)?
        .map_err(|_| AuthSnowErrors::FailedToReadFromStream)?;

    transcript.extend_from_slice(&x25519_recv);
    transcript.extend_from_slice(&x25519_pub);

    if !X25519Pub.untag(&mut x25519_recv) {
        return Err(AuthSnowErrors::WrongTag);
    }

    // fails if the client sent a low-order point (all-zero shared secret)
    let x25519_ss = Zeroizing::new(
        calculate_shared_key(
            &x25519_pair.private,
            x25519_recv
                .as_array()
                .ok_or(AuthSnowErrors::FailedToConvertToArray)?,
        )
        .ok_or(AuthSnowErrors::FailedToCalculateSharedSecret)?,
    );

    // 2. our public key
    let write = stream.write_all(&x25519_pub);

    timeout(Duration::from_secs(TIMEOUT), write)
        .await
        .map_err(|_| AuthSnowErrors::WriteTimeout)?
        .map_err(|_| AuthSnowErrors::FailedToWriteToStream)?;

    // 3. client's confirmation, 0x00 means it rejected the exchange
    let mut confirm_buffer = vec![0u8; 2];

    let read = stream.read_exact(&mut confirm_buffer);

    timeout(Duration::from_secs(TIMEOUT), read)
        .await
        .map_err(|_| AuthSnowErrors::ReadTimeout)?
        .map_err(|_| AuthSnowErrors::FailedToReadFromStream)?;

    transcript.extend_from_slice(&confirm_buffer);

    if !ConfirmByte.untag(&mut confirm_buffer) {
        return Err(AuthSnowErrors::WrongTag);
    }

    if confirm_buffer[0].eq(&0x00) {
        return Err(AuthSnowErrors::FailedToConfirmKex);
    }

    Ok(x25519_ss)
}

/// Server side of the ML-KEM-1024 exchange.
///
/// 1. <- client's ML-KEM public key
/// 2. -> ciphertext encapsulated to that key
/// 3. <- client's confirm byte
///
/// All messages (tags included) are appended to `transcript`.
async fn mlkem_kex_server(
    stream: &mut TcpStream,
    transcript: &mut Zeroizing<Vec<u8>>,
) -> Result<SsKey, AuthSnowErrors> {
    // 1. client's public key (1568 bytes for ML-KEM-1024)
    let mut ml_key_recv = Zeroizing::new(vec![0u8; 1568 + 1]); // + tag

    let read = stream.read_exact(&mut ml_key_recv);

    timeout(Duration::from_secs(TIMEOUT), read)
        .await
        .map_err(|_| AuthSnowErrors::ReadTimeout)?
        .map_err(|_| AuthSnowErrors::FailedToReadFromStream)?;

    transcript.extend_from_slice(&ml_key_recv);

    if !MlKeyPub.untag(&mut ml_key_recv) {
        return Err(AuthSnowErrors::WrongTag);
    }

    let public_key = MlKem1024PublicKey::from(
        ml_key_recv
            .as_array()
            .ok_or(AuthSnowErrors::FailedToConvertToArray)?,
    );

    // FIPS 203 encapsulation key check: rejects keys whose coefficients
    // are not properly reduced mod q
    if !validate_public_key(&public_key) {
        return Err(AuthSnowErrors::MlKemInvalidPublicKey);
    }

    // encapsulate a fresh shared secret to the client's key
    let (ciphertext, mut ml_key_ss) = encapsulate(
        &public_key,
        *random_array::<32>().map_err(|_| AuthSnowErrors::FailedToGenerateRandomData)?,
    );

    let mut ciphertext = ciphertext.as_slice().to_vec();

    MlKeyPub.tag(&mut ciphertext);
    transcript.extend_from_slice(&ciphertext);

    // move the secret into a zeroizing wrapper and wipe the plain copy
    let ml_key_ss_secure = Zeroizing::new(ml_key_ss);
    ml_key_ss.zeroize();

    // 2. ciphertext
    let write = stream.write_all(&ciphertext);

    timeout(Duration::from_secs(TIMEOUT), write)
        .await
        .map_err(|_| AuthSnowErrors::WriteTimeout)?
        .map_err(|_| AuthSnowErrors::FailedToWriteToStream)?;

    // 3. client's confirmation, 0x00 means it rejected the exchange
    let mut confirm_buffer = vec![0u8; 2];

    let read = stream.read_exact(&mut confirm_buffer);

    timeout(Duration::from_secs(TIMEOUT), read)
        .await
        .map_err(|_| AuthSnowErrors::ReadTimeout)?
        .map_err(|_| AuthSnowErrors::FailedToReadFromStream)?;

    transcript.extend_from_slice(&confirm_buffer);

    if !ConfirmByte.untag(&mut confirm_buffer) {
        return Err(AuthSnowErrors::WrongTag);
    }

    if confirm_buffer[0].eq(&0x00) {
        return Err(AuthSnowErrors::FailedToConfirmKex);
    }

    Ok(ml_key_ss_secure)
}

/// Runs the server side of the hybrid key exchange:
/// X25519 first, then ML-KEM-1024.
///
/// Both shared secrets are returned separately so the caller can combine
/// them (together with the transcript) into the final key.
pub async fn hybrid_kex_server(
    stream: &mut TcpStream,
    transcript: &mut Zeroizing<Vec<u8>>,
) -> Result<HybridKep, AuthSnowErrors> {
    let x25519_ss = x25519_kex_server(stream, transcript)
        .await
        .map_err(|_| AuthSnowErrors::KexFailed)?;
    let mlkem_ss = mlkem_kex_server(stream, transcript)
        .await
        .map_err(|_| AuthSnowErrors::KexFailed)?;

    Ok(HybridKep {
        x25519_ss,
        mlkem_ss,
    })
}

/// Sends a tagged one-byte confirmation (`0x01` = accepted, `0x00` = rejected)
/// and appends it to `transcript`.
async fn send_confirm(
    stream: &mut TcpStream,
    accepted: bool,
    transcript: &mut Zeroizing<Vec<u8>>,
) -> Result<(), AuthSnowErrors> {
    let mut confirm = vec![u8::from(accepted)];

    ConfirmByte.tag(&mut confirm);
    transcript.extend_from_slice(&confirm);

    let write = stream.write_all(&confirm);

    timeout(Duration::from_secs(TIMEOUT), write)
        .await
        .map_err(|_| AuthSnowErrors::WriteTimeout)?
        .map_err(|_| AuthSnowErrors::FailedToWriteToStream)?;

    Ok(())
}

/// Client side of the X25519 exchange.
///
/// 1. -> our ephemeral public key
/// 2. <- server's ephemeral public key
/// 3. -> our confirm byte (`0x00` if the server sent a low-order point)
///
/// All messages (tags included) are appended to `transcript` in the same
/// order as on the server.
async fn x25519_kex_client(
    stream: &mut TcpStream,
    transcript: &mut Zeroizing<Vec<u8>>,
) -> Result<SsKey, AuthSnowErrors> {
    // fresh ephemeral key pair for this connection
    let x25519_pair = x25519_cesa::generate_new_key_pair(
        *random_array::<32>().map_err(|_| AuthSnowErrors::FailedToGenerateRandomData)?,
    );

    let mut x25519_pub = Zeroizing::new(x25519_pair.public.to_vec());

    X25519Pub.tag(&mut x25519_pub);

    // 1. our public key
    let write = stream.write_all(&x25519_pub);

    timeout(Duration::from_secs(TIMEOUT), write)
        .await
        .map_err(|_| AuthSnowErrors::WriteTimeout)?
        .map_err(|_| AuthSnowErrors::FailedToWriteToStream)?;

    // 2. server's public key
    let mut x25519_recv = Zeroizing::new(vec![0u8; 32 + 1]); // + tag

    let read = stream.read_exact(&mut x25519_recv);

    timeout(Duration::from_secs(TIMEOUT), read)
        .await
        .map_err(|_| AuthSnowErrors::ReadTimeout)?
        .map_err(|_| AuthSnowErrors::FailedToReadFromStream)?;

    transcript.extend_from_slice(&x25519_pub);
    transcript.extend_from_slice(&x25519_recv);

    if !X25519Pub.untag(&mut x25519_recv) {
        return Err(AuthSnowErrors::WrongTag);
    }

    // None if the server sent a low-order point (all-zero shared secret)
    let shared = calculate_shared_key(
        &x25519_pair.private,
        x25519_recv
            .as_array()
            .ok_or(AuthSnowErrors::FailedToConvertToArray)?,
    )
    .map(Zeroizing::new);

    // 3. our confirmation, tell the server why we stop instead of just closing
    send_confirm(stream, shared.is_some(), transcript).await?;

    shared.ok_or(AuthSnowErrors::FailedToCalculateSharedSecret)
}

/// Client side of the ML-KEM-1024 exchange.
///
/// 1. -> our ML-KEM public key (fresh key pair per connection)
/// 2. <- ciphertext encapsulated to that key
/// 3. -> our confirm byte
///
/// All messages (tags included) are appended to `transcript` in the same
/// order as on the server.
async fn mlkem_kex_client(
    stream: &mut TcpStream,
    transcript: &mut Zeroizing<Vec<u8>>,
) -> Result<SsKey, AuthSnowErrors> {
    let key_pair = generate_key_pair(
        *random_array::<64>().map_err(|_| AuthSnowErrors::FailedToGenerateRandomData)?,
    );

    let mut ml_key_pub = key_pair.public_key().as_slice().to_vec();

    MlKeyPub.tag(&mut ml_key_pub);
    transcript.extend_from_slice(&ml_key_pub);

    // 1. our public key
    let write = stream.write_all(&ml_key_pub);

    timeout(Duration::from_secs(TIMEOUT), write)
        .await
        .map_err(|_| AuthSnowErrors::WriteTimeout)?
        .map_err(|_| AuthSnowErrors::FailedToWriteToStream)?;

    // 2. ciphertext (1568 bytes for ML-KEM-1024)
    let mut ciphertext_recv = vec![0u8; MLKEM1024_CIPHERTEXT_LEN + 1]; // + tag

    let read = stream.read_exact(&mut ciphertext_recv);

    timeout(Duration::from_secs(TIMEOUT), read)
        .await
        .map_err(|_| AuthSnowErrors::ReadTimeout)?
        .map_err(|_| AuthSnowErrors::FailedToReadFromStream)?;

    transcript.extend_from_slice(&ciphertext_recv);

    if !MlKeyPub.untag(&mut ciphertext_recv) {
        return Err(AuthSnowErrors::WrongTag);
    }

    let ciphertext = MlKem1024Ciphertext::from(
        ciphertext_recv
            .as_array()
            .ok_or(AuthSnowErrors::FailedToConvertToArray)?,
    );

    // implicit rejection: a tampered ciphertext gives a random key, which
    // then fails the Noise PSK step instead of leaking anything here
    let mut ml_key_ss = decapsulate(key_pair.private_key(), &ciphertext);
    let ml_key_ss_secure = Zeroizing::new(ml_key_ss);
    ml_key_ss.zeroize();

    // 3. our confirmation
    send_confirm(stream, true, transcript).await?;

    Ok(ml_key_ss_secure)
}

/// Runs the client side of the hybrid key exchange:
/// X25519 first, then ML-KEM-1024 (same order as [`hybrid_kex_server`]).
pub async fn hybrid_kex_client(
    stream: &mut TcpStream,
    transcript: &mut Zeroizing<Vec<u8>>,
) -> Result<HybridKep, AuthSnowErrors> {
    let x25519_ss = x25519_kex_client(stream, transcript)
        .await
        .map_err(|_| AuthSnowErrors::KexFailed)?;
    let mlkem_ss = mlkem_kex_client(stream, transcript)
        .await
        .map_err(|_| AuthSnowErrors::KexFailed)?;

    Ok(HybridKep {
        x25519_ss,
        mlkem_ss,
    })
}
