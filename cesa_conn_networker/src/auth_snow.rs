use crate::auth::Keys;
use cesa_conn_crypto::crand::random_array;
use core::fmt;
use libcrux_ml_kem::mlkem1024::{self, MlKem1024KeyPair};
use rand::{make_rng, rngs::StdRng};
use snow::{Builder, params::NoiseParams};
use std::{
    net::SocketAddr,
    sync::{Arc, LazyLock},
};
use tokio::{net::TcpStream, sync::RwLock};

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
        }
    }
}

pub async fn auth_incoming(
    keys: Arc<RwLock<Keys>>,
    tusted_addrs: Arc<RwLock<Vec<SocketAddr>>>,
    incoming_connection: (&mut TcpStream, SocketAddr),
    ml_key_pair: MlKem1024KeyPair,
) -> Result<bool, AuthSnowErrors> {
    let builder = Builder::new(SNOW_CONNECTION_PARAMS.clone());
    // let mut noise = builder.local_private_key(keys.read().await.a_key.as_ref()).map_err(|_| AuthSnowErrors::FailedToBindPrivateKey)?.psk(2, key)
    Ok(true)
}
