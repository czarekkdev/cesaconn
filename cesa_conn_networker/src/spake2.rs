/*
TODO:

add tests
add comments
*/

use crate::{auth_snow::AuthSnowErrors, spake2::Tags::OutboundMsg};
use blake2::Blake2s256;
use hkdf::SimpleHkdf;
use spake2::{Ed25519Group, Identity, Password, Spake2};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use zeroize::Zeroizing;

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum Tags {
    OutboundMsg = 0x01,
}

impl Tags {
    pub fn tag(self, packet: &mut Vec<u8>) {
        packet.push(self as u8);
    }

    pub fn check_tag(self, packet: &Vec<u8>) -> bool {
        packet.ends_with(&[self as u8])
    }

    pub fn untag(self, packet: &mut Vec<u8>) -> bool {
        if packet.ends_with(&[self as u8]) {
            packet.pop();
            true
        } else {
            false
        }
    }
}

pub async fn spake2_exchange_server(
    stream: &mut TcpStream,
    a_key: &Zeroizing<[u8; 32]>,
) -> Result<Zeroizing<Vec<u8>>, AuthSnowErrors> {
    let (s1, mut outbound_msg) = Spake2::<Ed25519Group>::start_b(
        &Password::new(a_key),
        &Identity::new(b"client"),
        &Identity::new(b"server"),
    );

    OutboundMsg.tag(&mut outbound_msg);

    let mut inbound_msg = Zeroizing::new(vec![0u8; outbound_msg.len()]);

    stream
        .write_all(&outbound_msg)
        .await
        .map_err(|_| AuthSnowErrors::FailedToWriteToStream)?;

    stream
        .read_exact(&mut inbound_msg)
        .await
        .map_err(|_| AuthSnowErrors::FailedToReadFromStream)?;

    if !OutboundMsg.untag(&mut inbound_msg) {
        return Err(AuthSnowErrors::WrongTag);
    }

    Ok(Zeroizing::new(s1.finish(&inbound_msg).map_err(|_| {
        AuthSnowErrors::FailedToFinishSpake2Exchange
    })?))
}

pub async fn spake2_confirm_mutual_auth_server(
    stream: &mut TcpStream,
    key1: &Zeroizing<Vec<u8>>,
) -> Result<bool, AuthSnowErrors> {
    let hk = SimpleHkdf::<Blake2s256>::new(None, key1);

    let mut confirm_expect = Zeroizing::new(vec![0u8; 32]);

    hk.expand(b"CPQHA-confirm-client-to-server", &mut confirm_expect)
        .map_err(|_| AuthSnowErrors::FaledToExpandHkdf)?;

    let mut confirm_recieved = Zeroizing::new(vec![0u8; 32]);

    stream
        .read_exact(&mut confirm_recieved)
        .await
        .map_err(|_| AuthSnowErrors::FailedToReadFromStream)?;

    if confirm_expect.ct_eq(&confirm_recieved).unwrap_u8() != 1 {
        return Ok(false);
    }

    let mut confirm_send = Zeroizing::new(vec![0u8; 32]);

    hk.expand(b"CPQHA-confirm-server-to-client", &mut confirm_send)
        .map_err(|_| AuthSnowErrors::FaledToExpandHkdf)?;

    stream
        .write_all(&confirm_send)
        .await
        .map_err(|_| AuthSnowErrors::FailedToWriteToStream)?;

    Ok(true)
}
