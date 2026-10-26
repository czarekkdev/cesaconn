#![forbid(unsafe_code)]

/* TODO NOW:


---------------

ADD SALT SYNCING
CLIPBOARD SYNC
FOLDER SYNC

*/

/* TODO AFTER POC:

IMPORTANT:

GET RID OF STORING KEYS IN RAM

---------------

 */

mod auth_snow;
mod hybrid_kex;
mod ipc_unix;
mod spake2;
mod tcp_networker;
mod udp_networker;
use std::{
    env,
    io::{self, BufRead, Write},
    net::SocketAddr,
    sync::Arc,
};
use tracing::{error, warn};
use tracing_subscriber::EnvFilter;

use cesa_conn_crypto::pswd_manager::derive_key;
use tokio::{net::TcpListener, sync::RwLock};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::{
    auth_snow::{AuthKey, DataKey, DeviceKeypairs, Keys},
    tcp_networker::{ActionType, NetworkerContext, connect, recv},
    udp_networker::{
        BROADCAST_NAME, UdpNetworkerErrors, udp_broadcast_presence, udp_find_broadcaster,
    },
};

/// Asks on the terminal whether to pair with a new device.
///
/// Shows the first 8 bytes of the handshake hash, the user compares them with
/// the other device before accepting (they only match without a MITM).
fn pair_prompt(name: &String, handshake_hash: &[u8; 32]) -> bool {
    let code: String = handshake_hash
        .iter()
        .take(8)
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ");

    print!("Pair with {name}? Check that the other device shows: {code}  [y/N] ");

    if io::stdout().flush().is_err() {
        return false;
    }

    let mut answer = String::new();

    if io::stdin().lock().read_line(&mut answer).is_err() {
        return false;
    }

    matches!(answer.trim(), "y" | "Y" | "yes")
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
        pair_fallback: pair_prompt,
    })
}

/// Derives the test `Keys` from a password (same key for auth and data, test only).
fn test_keys(password: &str) -> Option<Arc<RwLock<Keys>>> {
    let test_psw = password.as_bytes();

    // Salt derived from the password itself — acceptable for testing only
    let mut salt = [0u8; 32];

    for (s, p) in salt.iter_mut().zip(test_psw) {
        *s = *p;
    }

    match derive_key(test_psw, &salt) {
        // Zeroizing: wiped on drop
        Ok(raw_key) => Some(Arc::new(RwLock::new(Keys::new(
            AuthKey::from_bytes(&raw_key),
            DataKey::new(raw_key),
        )))),
        Err(e) => {
            error!(error = %e, "failed to derive the test key");
            None
        }
    }
}

/// UDP discovery for servertest: alternates between broadcasting presence and
/// listening, so both sides find each other regardless of who starts first.
async fn server_discovery(keys: Arc<RwLock<Keys>>) {
    loop {
        if let Err(e) = udp_broadcast_presence(BROADCAST_NAME.as_bytes(), 1, keys.clone()).await {
            error!(error = %e, "UDP broadcast failed, stopping discovery");
            return;
        }

        match udp_find_broadcaster(3, BROADCAST_NAME.as_bytes(), keys.clone()).await {
            Ok(_) => return,
            Err(UdpNetworkerErrors::Timeout) => {}
            Err(UdpNetworkerErrors::FailedToDecryptTunnel) => {
                warn!("Someone tried to connect with wrong key");
            }
            Err(e) => {
                error!(error = %e, "UDP discovery failed, stopping discovery");
                return;
            }
        }
    }
}

/// UDP discovery for clienttest: listen for a broadcaster, then announce ourselves.
async fn client_discovery(keys: Arc<RwLock<Keys>>) -> Option<SocketAddr> {
    loop {
        match udp_find_broadcaster(1, BROADCAST_NAME.as_bytes(), keys.clone()).await {
            Ok(addr) => {
                if let Err(e) =
                    udp_broadcast_presence(BROADCAST_NAME.as_bytes(), 3, keys.clone()).await
                {
                    error!(error = %e, "UDP broadcast failed");
                    return None;
                }

                return Some(addr);
            }
            Err(UdpNetworkerErrors::Timeout) => {}
            Err(UdpNetworkerErrors::FailedToDecryptTunnel) => {
                warn!("Someone tried to connect with wrong key");
            }
            Err(e) => {
                error!(error = %e, "UDP discovery failed");
                return None;
            }
        }
    }
}

#[tokio::main]
async fn main() {
    // debug in dev builds, info in release — RUST_LOG overrides both at runtime
    let default_level = if cfg!(debug_assertions) {
        "cesa_conn=debug"
    } else {
        "cesa_conn=info"
    };

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level)),
        )
        .init();

    // args[0] = binary path, args[1] = subcommand, args[2..] = subcommand-specific params
    let args: Vec<String> = env::args().collect();
    let bin = args.first().map_or("cesa_conn_networker", String::as_str);
    let usage =
        format!("Usage:\n  {bin} servertest <password>\n  {bin} clienttest <message> <password>");

    match (args.get(1).map(String::as_str), args.get(2), args.get(3)) {
        // servertest <password>
        // Starts a TCP listener and discovers clients via UDP.
        (Some("servertest"), Some(password), _) => {
            let Some(keys) = test_keys(password) else {
                return;
            };

            // Test server: peers on the LAN must reach it; every connection is
            // authenticated before any data is processed.
            // nosemgrep: cesa.net.bind-all-interfaces
            let listener = match TcpListener::bind("0.0.0.0:3232").await {
                Ok(listener) => listener,
                Err(e) => {
                    error!(error = %e, "failed to bind TCP listener on port 3232");
                    return;
                }
            };

            tokio::spawn(server_discovery(keys.clone()));

            let Some(context) = make_context(keys) else {
                return;
            };

            if let Err(e) = recv(&listener, context, CancellationToken::new()).await {
                error!(error = %e, "TCP listener stopped");
            }
        }

        // clienttest <message> <password>
        // Discovers a servertest peer via UDP, then sends <message> over TCP.
        (Some("clienttest"), Some(message), Some(password)) => {
            let Some(keys) = test_keys(password) else {
                return;
            };

            let Some(incoming_addr) = client_discovery(keys.clone()).await else {
                return;
            };

            let message = Zeroizing::new(message.as_bytes().to_vec());

            // Server always listens on port 3232 — only the IP comes from UDP discovery
            let connect_addr = SocketAddr::new(incoming_addr.ip(), 3232);

            let Some(context) = make_context(keys) else {
                return;
            };

            if let Err(e) = connect(
                context,
                CancellationToken::new(),
                connect_addr,
                ActionType::Debug,
                message,
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

        (Some(sub @ ("servertest" | "clienttest")), _, _) => {
            error!("Missing argument for '{sub}'.\n{usage}");
        }
        (Some(unknown), _, _) => {
            error!("Unknown subcommand: '{unknown}'.\n{usage}");
        }
        (None, _, _) => {
            error!("No subcommand provided.\n{usage}");
        }
    }
}
