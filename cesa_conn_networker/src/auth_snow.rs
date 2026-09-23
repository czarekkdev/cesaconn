/*
TODO:
tag packets
 */

use crate::auth::Keys;
use blake2::{Blake2s256, Blake2sMac256};
use cesa_conn_crypto::{
    crand::random_array,
    x25519_cesa::{self, calculate_shared_key, generate_new_key_pair},
};
use core::fmt;
use hkdf::{Hkdf, SimpleHkdf};
use libcrux_ml_kem::mlkem1024::{self, MlKem1024KeyPair, MlKem1024PublicKey};
#[cfg(target_arch = "x86_64")]
use libcrux_ml_kem::mlkem1024::avx2::{encapsulate, decapsulate};
#[cfg(target_arch = "aarch64")]
use libcrux_ml_kem::mlkem1024::neon::{encapsulate, decapsulate};
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
use libcrux_ml_kem::mlkem1024::portable::{encapsulate, decapsulate};
use rand::{make_rng, rngs::StdRng};
use snow::{Builder, params::NoiseParams};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use std::{
    net::SocketAddr,
    sync::{Arc, LazyLock},
};
use subtle::ConstantTimeEq;
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
        }
    }
}

pub async fn auth_incoming(
    keys: Arc<RwLock<Keys>>,
    tusted_addrs: Arc<RwLock<Vec<SocketAddr>>>,
    incoming_connection: (&mut TcpStream, SocketAddr),
) -> Result<bool, AuthSnowErrors> {
    let a_key = keys.read().await.a_key.clone();

    let (s1, outbound_msg) = Spake2::<Ed25519Group>::start_b(
        &Password::new(a_key),
        &Identity::new(b"client"),
        &Identity::new(b"server"),
    );

    let mut inbound_msg = Zeroizing::new(vec![0u8; outbound_msg.len()]);

    incoming_connection
        .0
        .write_all(&outbound_msg)
        .await
        .map_err(|_| AuthSnowErrors::FailedToWriteToStream)?;

    incoming_connection
        .0
        .read_exact(&mut inbound_msg)
        .await
        .map_err(|_| AuthSnowErrors::FailedToReadFromStream)?;

    let key1 = Zeroizing::new(
        s1.finish(&inbound_msg)
            .map_err(|_| AuthSnowErrors::FailedToFinishSpake2Exchange)?,
    );

    let hk = SimpleHkdf::<Blake2s256>::new(None, &key1);

    let mut confirm_expect = Zeroizing::new(vec![0u8; 32]);

    hk.expand(b"CPQHA-confirm-client-to-server", &mut confirm_expect)
        .map_err(|_| AuthSnowErrors::FaledToExpandHkdf)?;

    let mut confirm_recieved = Zeroizing::new(vec![0u8; 32]);

    incoming_connection
        .0
        .read_exact(&mut confirm_recieved)
        .await
        .map_err(|_| AuthSnowErrors::FailedToReadFromStream)?;

    if confirm_expect.ct_eq(&confirm_recieved).unwrap_u8() != 1 {
        return Ok(false);
    }

    let mut confirm_send = Zeroizing::new(vec![0u8; 32]);

    hk.expand(b"CPQHA-confirm-server-to-client", &mut confirm_send)
        .map_err(|_| AuthSnowErrors::FaledToExpandHkdf)?;

    incoming_connection
        .0
        .write_all(&confirm_send)
        .await
        .map_err(|_| AuthSnowErrors::FailedToWriteToStream)?;

    let x25519_pair = x25519_cesa::generate_new_key_pair(
        *random_array::<32>().map_err(|_| AuthSnowErrors::FailedToGenerateRandomData)?,
    );

    let x25519_pub = Zeroizing::new(x25519_pair.public.to_vec());

    let mut x25519_recv = Zeroizing::new(vec![0u8; 32]);
    let mut ml_key_recv = Zeroizing::new(vec![0u8; 1568]);

    incoming_connection
        .0
        .read_exact(&mut x25519_recv)
        .await
        .map_err(|_| AuthSnowErrors::FailedToReadFromStream)?;

    incoming_connection
        .0
        .read_exact(&mut ml_key_recv)
        .await
        .map_err(|_| AuthSnowErrors::FailedToReadFromStream)?;

    let x25519_ss = Zeroizing::new(calculate_shared_key(
        &x25519_pair.private,
        &x25519_recv.as_array().unwrap(),
    ));

    let (ciphertext, mut ml_key_ss) = encapsulate(
        &MlKem1024PublicKey::from(ml_key_recv.as_array().unwrap()),
        *random_array::<32>().map_err(|_| AuthSnowErrors::FailedToGenerateRandomData)?,
    );

    let ml_key_ss_secure = Zeroizing::new(ml_key_ss);
    ml_key_ss.zeroize();

    incoming_connection
        .0
        .write_all(&x25519_pub)
        .await
        .map_err(|_| AuthSnowErrors::FailedToWriteToStream)?;

    incoming_connection
        .0
        .write_all(ciphertext.as_slice())
        .await
        .map_err(|_| AuthSnowErrors::FailedToWriteToStream)?;

    let mut psk = Zeroizing::new(Vec::new());

    psk.extend_from_slice(x25519_ss.as_slice());
    psk.extend_from_slice(ml_key_ss_secure.as_slice());

    let psk_hk = SimpleHkdf::<Blake2s256>::new(None, &psk);

    let mut secure_psk = Zeroizing::new([0u8; 32]);

    psk_hk
        .expand(b"CPQHA-psk", secure_psk.as_mut_slice())
        .map_err(|_| AuthSnowErrors::FaledToExpandHkdf)?;

    let d_key = keys.read().await.d_key.clone();

    let builder = Builder::new(
        "Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s"
            .parse()
            .map_err(|_| AuthSnowErrors::FailedToParseText)?,
    )
    .local_private_key(d_key.as_slice())
    .map_err(|_| AuthSnowErrors::FailedToSetLocalPrivateKey)?
    .psk(3, &secure_psk)
    .map_err(|_| AuthSnowErrors::FailedToSetPsk)?;

    Ok(true)
}
