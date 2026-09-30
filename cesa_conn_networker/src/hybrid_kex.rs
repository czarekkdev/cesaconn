use crate::auth_snow::AuthSnowErrors;
use cesa_conn_crypto::{
    crand::random_array,
    x25519_cesa::{self, calculate_shared_key},
};
#[cfg(target_arch = "x86_64")]
use libcrux_ml_kem::mlkem1024::avx2::{decapsulate, encapsulate};
#[cfg(target_arch = "aarch64")]
use libcrux_ml_kem::mlkem1024::neon::{decapsulate, encapsulate};
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
use libcrux_ml_kem::mlkem1024::portable::{decapsulate, encapsulate};
use libcrux_ml_kem::mlkem1024::{self, MlKem1024KeyPair, MlKem1024PublicKey};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use zeroize::{Zeroize, Zeroizing};

pub type SsKey = Zeroizing<[u8; 32]>;

pub struct HybridKep {
    pub x25519_ss: SsKey,
    pub mlkem_ss: SsKey,
}

async fn x25519_kex_server(stream: &mut TcpStream) -> Result<SsKey, AuthSnowErrors> {
    let x25519_pair = x25519_cesa::generate_new_key_pair(
        *random_array::<32>().map_err(|_| AuthSnowErrors::FailedToGenerateRandomData)?,
    );

    let x25519_pub = Zeroizing::new(x25519_pair.public.to_vec());

    let mut x25519_recv = Zeroizing::new(vec![0u8; 32]);

    stream
        .read_exact(&mut x25519_recv)
        .await
        .map_err(|_| AuthSnowErrors::FailedToReadFromStream)?;

    let x25519_ss = Zeroizing::new(calculate_shared_key(
        &x25519_pair.private,
        x25519_recv
            .as_array()
            .ok_or(AuthSnowErrors::FailedToConvertToArray)?,
    ));

    stream
        .write_all(&x25519_pub)
        .await
        .map_err(|_| AuthSnowErrors::FailedToWriteToStream)?;

    let mut confirm_buffer = vec![0x00];

    stream
        .read_exact(&mut confirm_buffer)
        .await
        .map_err(|_| AuthSnowErrors::FailedToReadFromStream)?;

    if confirm_buffer[0].eq(&0x00) {
        return Err(AuthSnowErrors::FailedToConfirmKex);
    }

    Ok(x25519_ss)
}

async fn mlkem_kex_server(stream: &mut TcpStream) -> Result<SsKey, AuthSnowErrors> {
    let mut ml_key_recv = Zeroizing::new(vec![0u8; 1568]);

    stream
        .read_exact(&mut ml_key_recv)
        .await
        .map_err(|_| AuthSnowErrors::FailedToReadFromStream)?;

    let (ciphertext, mut ml_key_ss) = encapsulate(
        &MlKem1024PublicKey::from(
            ml_key_recv
                .as_array()
                .ok_or(AuthSnowErrors::FailedToConvertToArray)?,
        ),
        *random_array::<32>().map_err(|_| AuthSnowErrors::FailedToGenerateRandomData)?,
    );

    let ml_key_ss_secure = Zeroizing::new(ml_key_ss);
    ml_key_ss.zeroize();

    stream
        .write_all(ciphertext.as_slice())
        .await
        .map_err(|_| AuthSnowErrors::FailedToWriteToStream)?;

    let mut confirm_buffer = vec![0x00];

    stream
        .read_exact(&mut confirm_buffer)
        .await
        .map_err(|_| AuthSnowErrors::FailedToReadFromStream)?;

    if confirm_buffer[0].eq(&0x00) {
        return Err(AuthSnowErrors::FailedToConfirmKex);
    }

    Ok(ml_key_ss_secure)
}

pub async fn hybrid_kex_server(stream: &mut TcpStream) -> Result<HybridKep, AuthSnowErrors> {
    let x25519_ss = x25519_kex_server(stream)
        .await
        .map_err(|_| AuthSnowErrors::KexFailed)?;
    let mlkem_ss = mlkem_kex_server(stream)
        .await
        .map_err(|_| AuthSnowErrors::KexFailed)?;

    Ok(HybridKep { x25519_ss, mlkem_ss })
}
