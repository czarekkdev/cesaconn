//! `servertest` / `clienttest`: manual end-to-end test of discovery, pairing
//! and one data packet between two machines.
//!
//! Only compiled with `--features test-commands`, so release builds don't
//! ship them. Each run uses fresh random salts (printed by `servertest`,
//! passed to `clienttest`) and derives two different keys from the password.

use std::{
    io::{self, BufRead, Write},
    net::SocketAddr,
    sync::Arc,
};
use tokio::{net::TcpListener, sync::RwLock};
use tokio_util::sync::CancellationToken;
use tracing::error;
use zeroize::Zeroizing;

use cesa_conn_crypto::{crand::random_array, pswd_manager::derive_key};
use cesa_conn_system::pairing_code::{PairingCode, symbol};

use crate::{
    auth_snow::{AuthKey, DataKey, DeviceKeypairs, Keys, Pairing},
    guess_limiter::GuessLimiter,
    tcp_networker::{ActionType, NetworkerContext, SaltOffer, TCP_PORT, connect, recv},
    udp_networker::{InstanceId, UdpNetworkerErrors, udp_broadcast_presence, udp_find_broadcaster},
};

/// a_salt (32) + d_salt (32), hex encoded on the command line
const SALTS_LEN: usize = 64;

/// The pairing code as `emoji name` pairs, the way the UI shows it.
fn describe_code(code: &PairingCode) -> String {
    code.iter()
        .filter_map(|&index| symbol(index))
        .map(|(emoji, name)| format!("{emoji} {name}"))
        .collect::<Vec<_>>()
        .join("  ")
}

/// Asks on the terminal whether to pair with a new device. The user
/// compares the pairing code with the other device before accepting (the
/// codes only match without a MITM).
fn pair_prompt(prompt: &str) -> bool {
    print!("{prompt}");

    if io::stdout().flush().is_err() {
        return false;
    }

    let mut answer = String::new();

    if io::stdin().lock().read_line(&mut answer).is_err() {
        return false;
    }

    matches!(answer.trim(), "y" | "Y" | "yes")
}

/// Asks on the terminal about every new device, one at a time.
fn terminal_pairing() -> Pairing {
    let (pairing, mut inbox) = Pairing::channel();

    tokio::spawn(async move {
        // an in-process channel, not the network: ends with the senders
        // nosemgrep: cesa.net.read-without-timeout
        while let Some(request) = inbox.requests.recv().await {
            let prompt = format!(
                "Pair with {}? Check that the other device shows:\n  {}\n[y/N] ",
                request.name,
                describe_code(&request.code)
            );
            // stdin blocks: off the async workers
            let accept = tokio::task::spawn_blocking(move || pair_prompt(&prompt))
                .await
                .unwrap_or(false);

            request.answer(accept);
        }
    });

    pairing
}

/// Shared networker state for the test subcommands.
/// TODO: load the device identity from storage instead of generating it per run.
fn make_context(keys: Arc<RwLock<Keys>>) -> Option<NetworkerContext> {
    let device_keypairs = match DeviceKeypairs::generate() {
        Ok(device_keypairs) => device_keypairs,
        Err(e) => {
            error!(error = %e, "failed to generate device keys");
            return None;
        }
    };

    Some(NetworkerContext {
        keys,
        device_keypairs: Arc::new(device_keypairs),
        trusted_peers: Arc::new(RwLock::new(Vec::new())),
        pairing: terminal_pairing(),
        guess_limiter: Arc::new(GuessLimiter::new()),
        salt_offer: SaltOffer::default(),
    })
}

/// Lowercase hex of `bytes`.
fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parses exactly `SALTS_LEN` bytes of hex, `None` for anything else.
fn salts_from_hex(hex: &str) -> Option<[u8; SALTS_LEN]> {
    if hex.len() != SALTS_LEN.checked_mul(2)? {
        return None;
    }

    let mut out = [0u8; SALTS_LEN];

    // the length is checked above, so there is no remainder
    let (pairs, _) = hex.as_bytes().as_chunks::<2>();

    for (byte, pair) in out.iter_mut().zip(pairs) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }

    Some(out)
}

/// Derives `a_key` and `d_key` from one password with two different salts.
fn test_keys(password: &str, salts: &[u8; SALTS_LEN]) -> Option<Arc<RwLock<Keys>>> {
    let (a_salt, d_salt) = salts.split_first_chunk::<32>()?;
    let d_salt: &[u8; 32] = d_salt.try_into().ok()?;

    let derived = derive_key(password.as_bytes(), a_salt)
        .and_then(|a_key| Ok((a_key, derive_key(password.as_bytes(), d_salt)?)));

    match derived {
        Ok((a_key, d_key)) => Some(Arc::new(RwLock::new(Keys::new(
            AuthKey::new(a_key),
            a_salt,
            DataKey::new(d_key),
        )))),
        Err(e) => {
            error!(error = %e, "failed to derive the test keys");
            None
        }
    }
}

/// UDP discovery for servertest: alternates between broadcasting presence and
/// listening, so both sides find each other regardless of who starts first.
async fn server_discovery(id: InstanceId) {
    loop {
        if let Err(e) = udp_broadcast_presence(1, id).await {
            error!(error = %e, "UDP broadcast failed, stopping discovery");
            return;
        }

        match udp_find_broadcaster(3, id).await {
            Ok(_) => return,
            Err(UdpNetworkerErrors::Timeout) => {}
            Err(e) => {
                error!(error = %e, "UDP discovery failed, stopping discovery");
                return;
            }
        }
    }
}

/// UDP discovery for clienttest: listen for a broadcaster, then announce ourselves.
async fn client_discovery(id: InstanceId) -> Option<SocketAddr> {
    loop {
        match udp_find_broadcaster(1, id).await {
            Ok(addr) => {
                if let Err(e) = udp_broadcast_presence(3, id).await {
                    error!(error = %e, "UDP broadcast failed");
                    return None;
                }

                return Some(addr);
            }
            Err(UdpNetworkerErrors::Timeout) => {}
            Err(e) => {
                error!(error = %e, "UDP discovery failed");
                return None;
            }
        }
    }
}

/// `servertest <password>`: prints fresh salts, listens for one test client.
async fn servertest(password: &str) {
    let salts = match (random_array::<32>(), random_array::<32>()) {
        (Ok(a_salt), Ok(d_salt)) => {
            let mut salts = Zeroizing::new([0u8; SALTS_LEN]);

            for (dst, src) in salts.iter_mut().zip(a_salt.iter().chain(d_salt.iter())) {
                *dst = *src;
            }

            salts
        }
        _ => {
            error!("failed to generate salts");
            return;
        }
    };

    // salts aren't secret, the client needs them to derive the same keys
    println!("salts: {}", to_hex(salts.as_slice()));

    let Some(keys) = test_keys(password, &salts) else {
        return;
    };

    // Test server: peers on the LAN must reach it; every connection is
    // authenticated before any data is processed.
    // nosemgrep: cesa.net.bind-all-interfaces
    let listener = match TcpListener::bind(("0.0.0.0", TCP_PORT)).await {
        Ok(listener) => listener,
        Err(e) => {
            error!(error = %e, port = TCP_PORT, "failed to bind TCP listener");
            return;
        }
    };

    let Ok(id) = InstanceId::generate() else {
        error!("failed to generate instance id");
        return;
    };

    tokio::spawn(server_discovery(id));

    let Some(context) = make_context(keys) else {
        return;
    };

    if let Err(e) = recv(&listener, context, CancellationToken::new()).await {
        error!(error = %e, "TCP listener stopped");
    }
}

/// `clienttest <message> <password> <salts>`: finds the server, sends `message`.
async fn clienttest(message: &str, password: &str, salts_hex: &str) {
    let Some(salts) = salts_from_hex(salts_hex) else {
        error!(
            "salts must be the {} hex characters servertest printed",
            SALTS_LEN * 2
        );
        return;
    };

    let Some(keys) = test_keys(password, &salts) else {
        return;
    };

    let Ok(id) = InstanceId::generate() else {
        error!("failed to generate instance id");
        return;
    };

    let Some(server_addr) = client_discovery(id).await else {
        return;
    };

    // only the IP comes from discovery (an unauthenticated hint), the port is fixed
    let connect_addr = SocketAddr::new(server_addr.ip(), TCP_PORT);

    let Some(context) = make_context(keys) else {
        return;
    };

    if let Err(e) = connect(
        context,
        CancellationToken::new(),
        connect_addr,
        ActionType::Debug,
        Zeroizing::new(message.as_bytes().to_vec()),
    )
    .await
    {
        error!(error = %e, "failed to connect");
        return;
    }

    // keep the process alive long enough for the spawned connect_handler
    // task to finish, including a first-time pairing prompt
    tokio::time::sleep(tokio::time::Duration::from_secs(70)).await;
}

/// Runs a test subcommand from `args` (args[0] = binary).
pub async fn run(args: &[String]) {
    let bin = args.first().map_or("cesa_conn_networker", String::as_str);
    let usage = format!(
        "Usage:\n  {bin} servertest <password>\n  {bin} clienttest <message> <password> <salts>"
    );

    match (
        args.get(1).map(String::as_str),
        args.get(2),
        args.get(3),
        args.get(4),
    ) {
        (Some("servertest"), Some(password), _, _) => servertest(password).await,
        (Some("clienttest"), Some(message), Some(password), Some(salts)) => {
            clienttest(message, password, salts).await;
        }
        (Some(sub @ ("servertest" | "clienttest")), ..) => {
            error!("Missing argument for '{sub}'.\n{usage}");
        }
        (Some(unknown), ..) => error!("Unknown subcommand: '{unknown}'.\n{usage}"),
        (None, ..) => error!("No subcommand provided.\n{usage}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that salts round-trip through hex
    #[test]
    fn test_salts_hex_roundtrip() {
        let salts: [u8; SALTS_LEN] = core::array::from_fn(|i| u8::try_from(i).unwrap());
        assert_eq!(salts_from_hex(&to_hex(&salts)), Some(salts));
    }

    /// Test that wrong length or non-hex input is rejected
    #[test]
    fn test_salts_hex_rejects_bad_input() {
        let good = to_hex(&[0xAB; SALTS_LEN]);

        assert_eq!(salts_from_hex(good.get(..good.len() - 2).unwrap()), None);
        assert_eq!(salts_from_hex(&format!("{good}00")), None);
        assert_eq!(salts_from_hex(&good.replacen('a', "g", 1)), None);
        assert_eq!(salts_from_hex(""), None);
    }

    /// Test that the two keys come from different salts, so they differ
    #[tokio::test]
    async fn test_a_key_and_d_key_differ() {
        let salts: [u8; SALTS_LEN] = core::array::from_fn(|i| u8::try_from(i).unwrap());
        let keys = test_keys("pw", &salts).unwrap();
        let keys = keys.read().await;

        assert_ne!(**keys.a_key.expose(), **keys.d_key.expose());
    }
}
