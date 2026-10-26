use std::time::Duration;

use crate::{
    auth_snow::{AuthKey, AuthSnowErrors, TIMEOUT},
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
    a_key: &AuthKey,
    transcript: &mut Zeroizing<Vec<u8>>,
) -> Result<Zeroizing<Vec<u8>>, AuthSnowErrors> {
    // identities must match the client's `start_a` call exactly
    let (s1, mut outbound_msg) = Spake2::<Ed25519Group>::start_b(
        &Password::new(a_key.expose().as_slice()),
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
        .map_err(|_| AuthSnowErrors::FailedToExpandHkdf)?;

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
        .map_err(|_| AuthSnowErrors::FailedToExpandHkdf)?;

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

/// Client side of the SPAKE2 exchange (role A) using `a_key` as the password.
///
/// 1. -> our SPAKE2 message
/// 2. <- server's SPAKE2 message
///
/// Both messages (tags included) are appended to `transcript` in the same
/// order as on the server: client's message, then the server's.
/// Returns the SPAKE2 session key (`key1`), which is still unconfirmed,
/// see [`spake2_confirm_mutual_auth_client`].
pub async fn spake2_exchange_client(
    stream: &mut TcpStream,
    a_key: &AuthKey,
    transcript: &mut Zeroizing<Vec<u8>>,
) -> Result<Zeroizing<Vec<u8>>, AuthSnowErrors> {
    // identities must match the server's `start_b` call exactly
    let (s1, mut outbound_msg) = Spake2::<Ed25519Group>::start_a(
        &Password::new(a_key.expose().as_slice()),
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

    // 2. server's message
    let read = stream.read_exact(&mut inbound_msg);

    timeout(Duration::from_secs(TIMEOUT), read)
        .await
        .map_err(|_| AuthSnowErrors::ReadTimeout)?
        .map_err(|_| AuthSnowErrors::FailedToReadFromStream)?;

    // order: our message, then the server's (same as on the server)
    transcript.extend_from_slice(&outbound_msg);
    transcript.extend_from_slice(&inbound_msg);

    if !OutboundMsg.untag(&mut inbound_msg) {
        return Err(AuthSnowErrors::WrongTag);
    }

    Ok(Zeroizing::new(s1.finish(&inbound_msg).map_err(|_| {
        AuthSnowErrors::FailedToFinishSpake2Exchange
    })?))
}

/// Key confirmation for SPAKE2, client side.
///
/// 1. -> our confirmation value
/// 2. <- server's confirmation value
///
/// The client proves first (see [`spake2_confirm_mutual_auth_server`]).
/// Both values are appended to `transcript` on success.
///
/// Returns `Ok(false)` if the server's confirmation value is wrong.
pub async fn spake2_confirm_mutual_auth_client(
    stream: &mut TcpStream,
    key1: &Zeroizing<Vec<u8>>,
    transcript: &mut Zeroizing<Vec<u8>>,
) -> Result<bool, AuthSnowErrors> {
    let hk = SimpleHkdf::<Blake2s256>::new(None, key1);

    let mut confirm_send = Zeroizing::new(vec![0u8; 32]);

    hk.expand(b"CPQHA-confirm-client-to-server", &mut confirm_send)
        .map_err(|_| AuthSnowErrors::FailedToExpandHkdf)?;

    let mut confirm_expect = Zeroizing::new(vec![0u8; 32]);

    hk.expand(b"CPQHA-confirm-server-to-client", &mut confirm_expect)
        .map_err(|_| AuthSnowErrors::FailedToExpandHkdf)?;

    // 1. our confirmation
    let write = stream.write_all(&confirm_send);

    timeout(Duration::from_secs(TIMEOUT), write)
        .await
        .map_err(|_| AuthSnowErrors::WriteTimeout)?
        .map_err(|_| AuthSnowErrors::FailedToWriteToStream)?;

    // 2. server's confirmation (the server closes instead if ours was wrong)
    let mut confirm_received = Zeroizing::new(vec![0u8; 32]);

    let read = stream.read_exact(&mut confirm_received);

    timeout(Duration::from_secs(TIMEOUT), read)
        .await
        .map_err(|_| AuthSnowErrors::ReadTimeout)?
        .map_err(|_| AuthSnowErrors::FailedToReadFromStream)?;

    // constant-time compare, so timing doesn't leak how many bytes matched
    if confirm_expect.ct_eq(&confirm_received).unwrap_u8() != 1 {
        return Ok(false);
    }

    transcript.extend_from_slice(&confirm_send);
    transcript.extend_from_slice(&confirm_received);

    Ok(true)
}

#[cfg(test)]
mod tests {

    use super::*;
    use tokio::net::TcpListener;

    /// Connected localhost pair: (server side, client side).
    async fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (client, server) = tokio::join!(TcpStream::connect(addr), listener.accept());

        (server.unwrap().0, client.unwrap())
    }

    /// Runs exchange + confirmation on both sides with the given passwords.
    async fn run(
        server_key: [u8; 32],
        client_key: [u8; 32],
    ) -> (
        Result<bool, AuthSnowErrors>,
        Result<bool, AuthSnowErrors>,
        Zeroizing<Vec<u8>>,
        Zeroizing<Vec<u8>>,
    ) {
        let (mut s, mut c) = pair().await;
        let (sk, ck) = (
            AuthKey::from_bytes(&server_key),
            AuthKey::from_bytes(&client_key),
        );
        let mut st = Zeroizing::new(Vec::new());
        let mut ct = Zeroizing::new(Vec::new());

        let server = async {
            let key1 = spake2_exchange_server(&mut s, &sk, &mut st).await?;
            spake2_confirm_mutual_auth_server(&mut s, &key1, &mut st).await
        };
        let client = async {
            let key1 = spake2_exchange_client(&mut c, &ck, &mut ct).await?;
            spake2_confirm_mutual_auth_client(&mut c, &key1, &mut ct).await
        };
        let (sr, cr) = tokio::join!(server, client);

        (sr, cr, st, ct)
    }

    /// Test that the same password confirms on both sides with equal transcripts
    #[tokio::test]
    async fn test_same_password_confirms() {
        let (sr, cr, st, ct) = run([7u8; 32], [7u8; 32]).await;

        assert_eq!(sr, Ok(true));
        assert_eq!(cr, Ok(true));
        assert_eq!(*st, *ct);
        assert!(!st.is_empty());
    }

    /// Test that a different password is caught by the server before it confirms
    #[tokio::test]
    async fn test_wrong_password_rejected_by_server() {
        let (sr, cr, _, _) = run([7u8; 32], [8u8; 32]).await;

        assert_eq!(sr, Ok(false));
        // the server never sends its value, the client sees EOF / error
        assert_ne!(cr, Ok(true));
    }

    /// Test that the exchange gives a fresh key1 every run (ephemeral scalars)
    #[tokio::test]
    async fn test_session_keys_are_fresh() {
        let mut keys = Vec::new();

        for _ in 0..2 {
            let (mut s, mut c) = pair().await;
            let k = AuthKey::from_bytes(&[7u8; 32]);
            let mut st = Zeroizing::new(Vec::new());
            let mut ct = Zeroizing::new(Vec::new());

            let (sk1, ck1) = tokio::join!(
                spake2_exchange_server(&mut s, &k, &mut st),
                spake2_exchange_client(&mut c, &k, &mut ct)
            );
            let (sk1, ck1) = (sk1.unwrap(), ck1.unwrap());

            assert_eq!(*sk1, *ck1);
            keys.push(sk1);
        }

        assert_ne!(*keys[0], *keys[1]);
    }
}
