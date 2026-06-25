use crate::auth::Keys;
use cesa_conn_crypto::{
    crand::random_array,
    x25519_cesa::{self, generate_new_key_pair},
};
use core::fmt;
use libcrux_ml_kem::mlkem1024::{self, MlKem1024KeyPair};
use rand::{make_rng, rngs::StdRng};
use snow::{Builder, params::NoiseParams};
use std::{
    net::SocketAddr,
    sync::{Arc, LazyLock},
};
use tokio::{net::TcpStream, sync::RwLock};
use zeroize::Zeroizing;

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
            AuthSnowErrors::FailedToBindPrivateKey => {
                write!(f, "failed to bind private key to noise")
            }
            AuthSnowErrors::FailedToInitSnowBuilder => {
                write!(f, "failed to initialize snow builder")
            }
            AuthSnowErrors::FailedToGenerateRandomData => {
                write!(f, "failed to generate array of random data")
            }
        }
    }
}

pub async fn auth_incoming(
    keys: Arc<RwLock<Keys>>,
    tusted_addrs: Arc<RwLock<Vec<SocketAddr>>>,
    incoming_connection: (&mut TcpStream, SocketAddr),
) -> Result<bool, AuthSnowErrors> {
    let ml_key_pair = mlkem1024::generate_key_pair(
        *random_array::<64>().map_err(|_| AuthSnowErrors::FailedToGenerateRandomData)?,
    );
    let x25519_pair = x25519_cesa::generate_new_key_pair(
        *random_array::<32>().map_err(|_| AuthSnowErrors::FailedToGenerateRandomData)?,
    );

    

    Ok(true)
}
