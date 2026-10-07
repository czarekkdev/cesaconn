/*
TODO:

add tests
add comments
wrap read_messages in timeout
*/

use crate::{
    auth_snow::AuthSnowErrors::{self, WrongTag},
    hybrid_kex::Tags::{ConfirmByte, MlKeyPub, X25519Pub},
};
use cesa_conn_crypto::{
    crand::random_array,
    x25519_cesa::{self, calculate_shared_key},
};
use libcrux_ml_kem::mlkem1024::MlKem1024PublicKey;
#[cfg(target_arch = "x86_64")]
use libcrux_ml_kem::mlkem1024::avx2::{decapsulate, encapsulate};
#[cfg(target_arch = "aarch64")]
use libcrux_ml_kem::mlkem1024::neon::{decapsulate, encapsulate};
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
use libcrux_ml_kem::mlkem1024::portable::{decapsulate, encapsulate};
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

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum Tags {
    X25519Pub = 0x01,
    ConfirmByte = 0x02,
    MlKeyPub = 0x03,
}

impl Tags {
    pub fn tag(self, packet: &mut Vec<u8>) {
        packet.push(self as u8);
    }

    pub fn check_tag(self, packet: &Vec<u8>) -> bool {
        packet.ends_with(&[self as u8])
    }

    pub fn untag(self, packet: &mut Vec<u8>) -> bool {
        if packet.last().eq(&Some(&(self as u8))) {
            packet.pop();
            true
        } else {
            false
        }
    }
}

async fn x25519_kex_server(stream: &mut TcpStream) -> Result<SsKey, AuthSnowErrors> {
    let x25519_pair = x25519_cesa::generate_new_key_pair(
        *random_array::<32>().map_err(|_| AuthSnowErrors::FailedToGenerateRandomData)?,
    );

    let mut x25519_pub = Zeroizing::new(x25519_pair.public.to_vec());

    X25519Pub.tag(&mut x25519_pub);

    let mut x25519_recv = Zeroizing::new(vec![0u8; 32 + 1]); // + tag

    stream
        .read_exact(&mut x25519_recv)
        .await
        .map_err(|_| AuthSnowErrors::FailedToReadFromStream)?;

    if !X25519Pub.untag(&mut x25519_recv) {
        return Err(AuthSnowErrors::WrongTag);
    }

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

    if !ConfirmByte.untag(&mut confirm_buffer) {
        return Err(AuthSnowErrors::WrongTag);
    }

    if confirm_buffer[0].eq(&0x00) {
        return Err(AuthSnowErrors::FailedToConfirmKex);
    }

    Ok(x25519_ss)
}

async fn mlkem_kex_server(stream: &mut TcpStream) -> Result<SsKey, AuthSnowErrors> {
    let mut ml_key_recv = Zeroizing::new(vec![0u8; 1568 + 1]); // + tag

    stream
        .read_exact(&mut ml_key_recv)
        .await
        .map_err(|_| AuthSnowErrors::FailedToReadFromStream)?;

    if !MlKeyPub.untag(&mut ml_key_recv) {
        return Err(WrongTag);
    }

    let (ciphertext, mut ml_key_ss) = encapsulate(
        &MlKem1024PublicKey::from(
            ml_key_recv
                .as_array()
                .ok_or(AuthSnowErrors::FailedToConvertToArray)?,
        ),
        *random_array::<32>().map_err(|_| AuthSnowErrors::FailedToGenerateRandomData)?,
    );

    let mut ciphertext = ciphertext.as_slice().to_vec();

    MlKeyPub.tag(&mut ciphertext);

    let ml_key_ss_secure = Zeroizing::new(ml_key_ss);
    ml_key_ss.zeroize();

    stream
        .write_all(&ciphertext)
        .await
        .map_err(|_| AuthSnowErrors::FailedToWriteToStream)?;

    let mut confirm_buffer = vec![0x00];

    stream
        .read_exact(&mut confirm_buffer)
        .await
        .map_err(|_| AuthSnowErrors::FailedToReadFromStream)?;

    if !ConfirmByte.untag(&mut confirm_buffer) {
        return Err(AuthSnowErrors::WrongTag);
    }

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

    Ok(HybridKep {
        x25519_ss,
        mlkem_ss,
    })
}
