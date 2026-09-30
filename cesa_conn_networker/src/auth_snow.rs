/*
TODO:
tag packets
wrap read_messages in timeout
 */

const SNOW_MSG1_LEN: usize = 32;
const SNOW_MSG2_LEN: usize = 80;
const SNOW_MSG3_LEN: usize = 48;
const SNOW_MSG_MAX_LEN: usize = 65535;

use crate::{
    auth::Keys,
    hybrid_kex::{HybridKep, SsKey, hybrid_kex_server},
    spake2::{spake2_confirm_mutual_auth_server, spake2_exchange_server},
};
use blake2::Blake2s256;
use cesa_conn_crypto::{
    crand::random_array,
    x25519_cesa::{self, calculate_shared_key},
};
use core::fmt;
use hkdf::SimpleHkdf;
#[cfg(target_arch = "x86_64")]
use libcrux_ml_kem::mlkem1024::avx2::{decapsulate, encapsulate};
#[cfg(target_arch = "aarch64")]
use libcrux_ml_kem::mlkem1024::neon::{decapsulate, encapsulate};
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
use libcrux_ml_kem::mlkem1024::portable::{decapsulate, encapsulate};
use libcrux_ml_kem::mlkem1024::{self, MlKem1024KeyPair, MlKem1024PublicKey};
use snow::{Builder, params::NoiseParams};
use std::{
    net::SocketAddr,
    sync::{Arc, LazyLock},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::RwLock,
};
use zeroize::{Zeroize, Zeroizing};

static SNOW_CONNECTION_PARAMS: LazyLock<NoiseParams> =
    LazyLock::new(|| "Noise_XXpsk2_25519_AESGCM_BLAKE2b".parse().unwrap());

/// All errors that can occur during authentication.
#[derive(Debug, PartialEq)]
pub enum AuthSnowErrors {
    /// The TCP stream ended or errored before we could read all expected bytes.
    FailedToReadFromStream,
    /// AES-GCM decryption failed — wrong shared secret or tampered data.
    FailedToDecrypt,
    /// The TCP stream errored while sending data to the client.
    FailedToWriteToStream,
    /// Failed to encrypt the authentication key.
    FailedToEncrypt,
    FailedToBindPrivateKey,
    FailedToInitSnowBuilder,
    FailedToGenerateRandomData,
    FailedToFinishSpake2Exchange,
    FaledToExpandHkdf,
    FailedToConvertToArray,
    FailedToParseText,
    FailedToSetLocalPrivateKey,
    FailedToSetPsk,
    FailedToBuildSnowResponder,
    FailedToReadSnowMessage,
    FailedToWriteSnowMessage,
    FailedToEnterTansportMode,
    FailedToExchangeSpake2,
    FailedToConfirmMutualAuthSpake2,
    FailedToConfirmKex,
    KexFailed,
}

impl fmt::Display for AuthSnowErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthSnowErrors::FailedToReadFromStream => {
                write!(f, "failed to read authentication key from stream")
            }
            AuthSnowErrors::FailedToDecrypt => write!(f, "failed to decrypt authentication key"),
            AuthSnowErrors::FailedToWriteToStream => write!(f, "failed to write to stream"),
            AuthSnowErrors::FailedToEncrypt => write!(f, "failed to encrypt authentication key"),
            AuthSnowErrors::FaledToExpandHkdf => write!(f, "failed to expand hkdf"),
            AuthSnowErrors::FailedToFinishSpake2Exchange => {
                write!(f, "failed to finish spake2 exchange")
            }
            AuthSnowErrors::FailedToBindPrivateKey => {
                write!(f, "failed to bind private key to noise")
            }
            AuthSnowErrors::FailedToInitSnowBuilder => {
                write!(f, "failed to initialize snow builder")
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
        }
    }
}

pub async fn auth_incoming(
    keys: Arc<RwLock<Keys>>,
    tusted_addrs: Arc<RwLock<Vec<SocketAddr>>>,
    incoming_connection: (&mut TcpStream, SocketAddr),
) -> Result<bool, AuthSnowErrors> {
    let a_key = keys.read().await.a_key.clone();

    let key1 = spake2_exchange_server(incoming_connection.0, &a_key)
        .await
        .map_err(|_| AuthSnowErrors::FailedToExchangeSpake2)?;

    if (spake2_confirm_mutual_auth_server(incoming_connection.0, &key1)
        .await
        .map_err(|_| AuthSnowErrors::FailedToConfirmMutualAuthSpake2)?)
        != true
    {
        return Ok(false);
    }

    let hybrid_kep = hybrid_kex_server(incoming_connection.0)
        .await
        .map_err(|_| AuthSnowErrors::KexFailed)?;

    let mut psk = Zeroizing::new(Vec::new());

    psk.extend_from_slice(hybrid_kep.x25519_ss.as_slice());
    psk.extend_from_slice(hybrid_kep.mlkem_ss.as_slice());

    let psk_hk = SimpleHkdf::<Blake2s256>::new(None, &psk);

    let mut secure_psk = Zeroizing::new([0u8; 32]);

    psk_hk
        .expand(b"CPQHA-psk", secure_psk.as_mut_slice())
        .map_err(|_| AuthSnowErrors::FaledToExpandHkdf)?;

    let d_key = keys.read().await.d_key.clone();

    let mut builder = Builder::new(
        "Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s"
            .parse()
            .map_err(|_| AuthSnowErrors::FailedToParseText)?,
    )
    .local_private_key(d_key.as_slice())
    .map_err(|_| AuthSnowErrors::FailedToSetLocalPrivateKey)?
    .psk(3, &secure_psk)
    .map_err(|_| AuthSnowErrors::FailedToSetPsk)?
    .build_responder()
    .map_err(|_| AuthSnowErrors::FailedToBuildSnowResponder)?;

    let mut buffer = Zeroizing::new([0u8; SNOW_MSG2_LEN]);
    let mut read_buffer = Zeroizing::new([0u8; SNOW_MSG_MAX_LEN]);

    incoming_connection
        .0
        .read_exact(&mut read_buffer[..SNOW_MSG1_LEN])
        .await
        .map_err(|_| AuthSnowErrors::FailedToReadFromStream)?;

    builder
        .read_message(&read_buffer[..SNOW_MSG1_LEN], buffer.as_mut_slice())
        .map_err(|_| AuthSnowErrors::FailedToReadSnowMessage)?;

    builder
        .write_message(&[], &mut buffer[..SNOW_MSG2_LEN])
        .map_err(|_| AuthSnowErrors::FailedToWriteSnowMessage)?;

    incoming_connection
        .0
        .write_all(&buffer[..SNOW_MSG2_LEN])
        .await
        .map_err(|_| AuthSnowErrors::FailedToWriteToStream)?;

    incoming_connection
        .0
        .read_exact(&mut read_buffer[..SNOW_MSG3_LEN])
        .await
        .map_err(|_| AuthSnowErrors::FailedToReadFromStream)?;

    builder
        .read_message(&read_buffer[..SNOW_MSG3_LEN], buffer.as_mut_slice())
        .map_err(|_| AuthSnowErrors::FailedToReadSnowMessage)?;

    let mut transport = builder
        .into_transport_mode()
        .map_err(|_| AuthSnowErrors::FailedToEnterTansportMode)?;

    Ok(true)
}
