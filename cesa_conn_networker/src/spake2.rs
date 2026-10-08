/*
TODO:

add tests
add client-side
*/

use std::time::Duration;

use crate::{
    auth_snow::{AuthSnowErrors, TIMEOUT},
    spake2::Tags::OutboundMsg,
};
use blake2::Blake2s256;
use hkdf::SimpleHkdf;
use spake2::{Ed25519Group, Identity, Password, Spake2};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};
use zeroize::Zeroizing;

/// Packet type marker appended as the last byte of every SPAKE2 message.
#[repr(u8)]
#[derive(Clone, Copy)]
pub enum Tags {
    /// SPAKE2 exchange message (same tag in both directions).
    OutboundMsg = 0x01,
}

impl Tags {
    /// Appends the tag byte to the end of `packet`.
    pub fn tag(self, packet: &mut Vec<u8>) {
        packet.push(self as u8);
    }

    /// Returns `true` if `packet` ends with this tag.
    pub fn check_tag(self, packet: &Vec<u8>) -> bool {
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

/// Server side of the SPAKE2 exchange (role B) using `a_key` as the password.
///
/// 1. -> our SPAKE2 message
/// 2. <- client's SPAKE2 message
///
/// Both messages (tags included) are appended to `transcript`.
/// Returns the SPAKE2 session key (`key1`), which is still unconfirmed,
/// see [`spake2_confirm_mutual_auth_server`].
pub async fn spake2_exchange_server(
    stream: &mut TcpStream,
    a_key: &Zeroizing<[u8; 32]>,
    transcript: &mut Zeroizing<Vec<u8>>,
) -> Result<Zeroizing<Vec<u8>>, AuthSnowErrors> {
    // identities must match the client's `start_a` call exactly
    let (s1, mut outbound_msg) = Spake2::<Ed25519Group>::start_b(
        &Password::new(a_key),
        &Identity::new(b"client"),
        &Identity::new(b"server"),
    );

    OutboundMsg.tag(&mut outbound_msg);

    // both sides' messages have the same length (side byte + point + tag)
    let mut inbound_msg = Zeroizing::new(vec![0u8; outbound_msg.len()]);

    // 1. our message
    let write = stream.write_all(&outbound_msg);

    timeout(Duration::from_secs(TIMEOUT), write)
        .await
        .map_err(|_| AuthSnowErrors::WriteTimeout)?
        .map_err(|_| AuthSnowErrors::FailedToWriteToStream)?;

    // 2. client's message
    let read = stream.read_exact(&mut inbound_msg);

    timeout(Duration::from_secs(TIMEOUT), read)
        .await
        .map_err(|_| AuthSnowErrors::ReadTimeout)?
        .map_err(|_| AuthSnowErrors::FailedToReadFromStream)?;

    // order: client's message, then ours (the client must use the same order)
    transcript.extend_from_slice(&inbound_msg);
    transcript.extend_from_slice(&outbound_msg);

    if !OutboundMsg.untag(&mut inbound_msg) {
        return Err(AuthSnowErrors::WrongTag);
    }

    // finish() checks the message length and side byte, then derives the key
    // from the password, both identities and both messages
    Ok(Zeroizing::new(s1.finish(&inbound_msg).map_err(|_| {
        AuthSnowErrors::FailedToFinishSpake2Exchange
    })?))
}

/// Key confirmation for SPAKE2: proves that both sides derived the same `key1`
/// (i.e. both know `a_key`).
///
/// 1. <- client's confirmation value
/// 2. -> our confirmation value (only sent if the client's one was correct)
///
/// The client proves first, so a peer without the password learns nothing
/// from us. Both values are appended to `transcript` on success.
///
/// Returns `Ok(false)` if the client's confirmation value is wrong.
pub async fn spake2_confirm_mutual_auth_server(
    stream: &mut TcpStream,
    key1: &Zeroizing<Vec<u8>>,
    transcript: &mut Zeroizing<Vec<u8>>,
) -> Result<bool, AuthSnowErrors> {
    let hk = SimpleHkdf::<Blake2s256>::new(None, key1);

    // separate labels per direction, so one side's value can't be
    // reflected back as the other's
    let mut confirm_expect = Zeroizing::new(vec![0u8; 32]);

    hk.expand(b"CPQHA-confirm-client-to-server", &mut confirm_expect)
        .map_err(|_| AuthSnowErrors::FaledToExpandHkdf)?;

    // 1. client's confirmation
    let mut confirm_recieved = Zeroizing::new(vec![0u8; 32]);

    let read = stream.read_exact(&mut confirm_recieved);

    timeout(Duration::from_secs(TIMEOUT), read)
        .await
        .map_err(|_| AuthSnowErrors::ReadTimeout)?
        .map_err(|_| AuthSnowErrors::FailedToReadFromStream)?;

    // constant-time compare, so timing doesn't leak how many bytes matched
    if confirm_expect.ct_eq(&confirm_recieved).unwrap_u8() != 1 {
        return Ok(false);
    }

    let mut confirm_send = Zeroizing::new(vec![0u8; 32]);

    hk.expand(b"CPQHA-confirm-server-to-client", &mut confirm_send)
        .map_err(|_| AuthSnowErrors::FaledToExpandHkdf)?;

    // 2. our confirmation
    let write = stream.write_all(&confirm_send);

    timeout(Duration::from_secs(TIMEOUT), write)
        .await
        .map_err(|_| AuthSnowErrors::WriteTimeout)?
        .map_err(|_| AuthSnowErrors::FailedToWriteToStream)?;

    transcript.extend_from_slice(&confirm_recieved);
    transcript.extend_from_slice(&confirm_send);

    Ok(true)
}
