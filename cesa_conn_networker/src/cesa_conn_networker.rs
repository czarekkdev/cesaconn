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

mod auth;
mod ipc;
mod tcp_networker;
mod udp_networker;
use std::{env, net::SocketAddr, sync::Arc};
use tracing::{error, warn};
use tracing_subscriber::EnvFilter;

use cesa_conn_crypto::pswd_manager::derive_key;
use tokio::{net::TcpListener, sync::RwLock};
use tokio_util::sync::CancellationToken;

use crate::{
    auth::Keys,
    tcp_networker::{ActionType, connect, recv},
    udp_networker::{
        BROADCAST_NAME, UdpNetworkerErrors, udp_broadcast_presence, udp_find_broadcaster,
    },
};

#[tokio::main]
async fn main() {
    // debug in dev builds, info in release — RUST_LOG overrides both at runtime
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env().add_directive(
                if cfg!(debug_assertions) {
                    "cesa_conn=debug"
                } else {
                    "cesa_conn=info"
                }
                .parse()
                .unwrap(),
            ),
        )
        .init();

    // args[0] = binary path, args[1] = subcommand, args[2..] = subcommand-specific params
    let args: Vec<String> = env::args().collect();

    let bin = &args[0];

    if args.len() > 1 {
        match args[1].as_str() {
            // servertest <password>
            // Starts a TCP listener and discovers clients via UDP.
            // Uses the same key for both auth and data encryption — test only.
            "servertest" => {
                if args.len() < 3 {
                    error!("Missing argument.\nUsage: {bin} servertest <password>");
                    return;
                }

                let test_psw = args[2].as_bytes();
                // Salt derived from the password itself — acceptable for testing only
                let mut salt = [0u8; 32];
                let len = test_psw.len().min(32);
                salt[0..len].copy_from_slice(&test_psw[..len]);
                let raw_key: [u8; 32] = derive_key(test_psw, salt).unwrap();
                let keys = Arc::new(RwLock::new(Keys::new(raw_key, raw_key)));

                let listener = TcpListener::bind("0.0.0.0:3232").await.unwrap();
                let trusted_addrs: Arc<RwLock<Vec<SocketAddr>>> = Arc::new(RwLock::new(Vec::new()));
                let cancellation_token = CancellationToken::new();
                let keys_clone = keys.clone();

                // Background task: UDP peer discovery loop.
                // Alternates between broadcasting presence and listening for responses
                // so both sides can find each other regardless of who starts first.
                tokio::spawn(async move {
                    // Inner loop retries until a valid peer is found, skipping timeouts
                    // and wrong-key peers without propagating those as fatal errors.
                    loop {
                        udp_broadcast_presence(BROADCAST_NAME.as_bytes(), 1, keys_clone.clone())
                            .await
                            .unwrap();
                        break match udp_find_broadcaster(
                            3,
                            BROADCAST_NAME.as_bytes(),
                            keys_clone.clone(),
                        )
                        .await
                        {
                            Ok(addr) => Ok(addr),
                            Err(e) if e == UdpNetworkerErrors::Timeout => continue,
                            Err(e) if e == UdpNetworkerErrors::FailedToDecryptTunnel => {
                                warn!("Someone tired to connect with wrong key");
                                continue;
                            }
                            Err(e) => Err(e),
                        }
                        .unwrap();
                    }
                });

                recv(
                    &listener,
                    keys,
                    trusted_addrs.clone(),
                    cancellation_token.clone(),
                )
                .await
                .unwrap();
            }

            // clienttest <message> <password>
            // Discovers a servertest peer via UDP, then sends <message> over TCP.
            "clienttest" => {
                if args.len() < 4 {
                    error!("Missing argument.\nUsage: {bin} clienttest <message> <password>");
                    return;
                }

                let test_psw = args[2].as_bytes();
                // Salt derived from the password itself — acceptable for testing only
                let mut salt = [0u8; 32];
                let len = test_psw.len().min(32);
                salt[0..len].copy_from_slice(&test_psw[..len]);

                let raw_key: [u8; 32] = derive_key(test_psw, salt).unwrap();
                let keys = Arc::new(RwLock::new(Keys::new(raw_key, raw_key)));

                let trusted_addrs = Arc::new(RwLock::new(Vec::new()));

                // UDP discovery: listen for a broadcaster first, then announce ourselves
                // so the server adds us to its trusted list before we attempt TCP.
                let incoming_addr = loop {
                    let incoming_addr =
                        match udp_find_broadcaster(1, BROADCAST_NAME.as_bytes(), keys.clone())
                            .await
                        {
                            Ok(addr) => Ok(addr),
                            Err(e) if e == UdpNetworkerErrors::Timeout => continue,
                            Err(e) if e == UdpNetworkerErrors::FailedToDecryptTunnel => {
                                warn!("Someone tired to connect with wrong key");
                                continue;
                            }
                            Err(e) => Err(e),
                        }
                        .unwrap();

                    udp_broadcast_presence(BROADCAST_NAME.as_bytes(), 3, keys.clone())
                        .await
                        .unwrap();

                    break incoming_addr;
                };

                let write_g = trusted_addrs.write();
                write_g.await.push(incoming_addr);

                let cancellation_token = CancellationToken::new();

                let message = args[2].as_bytes().to_vec();

                // Server always listens on port 3232 — only the IP comes from UDP discovery
                let connect_addr = SocketAddr::new(incoming_addr.ip(), 3232);

                let action_type = ActionType::Debug;

                connect(
                    keys,
                    trusted_addrs,
                    cancellation_token,
                    connect_addr,
                    action_type,
                    message,
                )
                .await
                .unwrap();

                // Keep the process alive long enough for the spawned connect_handler task to finish
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            }
            unknown => {
                error!(
                    "Unknown subcommand: '{unknown}'.\nUsage:\n  {bin} servertest <password>\n  {bin} clienttest <message> <password>"
                );
            }
        }
    } else {
        error!(
            "No subcommand provided.\nUsage:\n  {bin} servertest <password>\n  {bin} clienttest <message> <password>"
        );
    }
}
