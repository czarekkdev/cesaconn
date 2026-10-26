/*
TODO:
start the networker once both keys are set (needs persisted DeviceKeypairs, see auth_snow)
pairing prompt over IPC (UI command set is defined together with the UI)
 */

//! The daemon: owns `a_key` / `d_key` and answers UI requests over IPC.
//!
//! Keys only ever enter the daemon as passwords (derived here with Argon2)
//! and never leave it; the UI gets status and public peer info only.

use std::sync::Arc;
use tokio::sync::{RwLock, Semaphore};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use zeroize::Zeroizing;

use cesa_conn_crypto::pswd_manager::derive_key;
use cesa_conn_system::ipc::{
    DaemonError, MAX_LISTED_PEERS, PasswordUpdate, PeerInfo, Request, Response, Status, socket_path,
};

use crate::{
    auth_snow::{AuthKey, DataKey, TrustedPeer},
    ipc_server::{self, ClientPolicy},
};

/// The keys the user has set so far (each one is set separately).
#[derive(Default)]
struct KeySlots {
    a_key: Option<AuthKey>,
    d_key: Option<DataKey>,
}

/// Everything the daemon owns. Shared between IPC handlers.
pub struct Daemon {
    keys: RwLock<KeySlots>,
    trusted_peers: Arc<RwLock<Vec<TrustedPeer>>>,
    // one Argon2 run (64 MiB) at a time, so clients can't stack up memory
    derive_slot: Arc<Semaphore>,
}

/// Which key a password is for.
#[derive(Clone, Copy)]
enum KeyKind {
    Auth,
    Data,
}

impl Default for Daemon {
    fn default() -> Self {
        Self {
            keys: RwLock::default(),
            trusted_peers: Arc::default(),
            derive_slot: Arc::new(Semaphore::new(1)),
        }
    }
}

impl Daemon {
    /// Answers one request with an encoded response body.
    pub async fn handle(&self, request: Request) -> Vec<u8> {
        match request {
            Request::Status => Response::Status(self.status().await).encode(),
            Request::SetAuthPassword(update) => self.set_password(KeyKind::Auth, update).await,
            Request::SetDataPassword(update) => self.set_password(KeyKind::Data, update).await,
            Request::ListPeers => Response::Peers(self.peers().await).encode(),
        }
    }

    async fn status(&self) -> Status {
        let (auth_key_set, data_key_set) = {
            let keys = self.keys.read().await;
            (keys.a_key.is_some(), keys.d_key.is_some())
        };
        let trusted_peers = self.trusted_peers.read().await.len();

        Status {
            auth_key_set,
            data_key_set,
            network_running: false,
            trusted_peers: u32::try_from(trusted_peers).unwrap_or(u32::MAX),
        }
    }

    async fn peers(&self) -> Vec<PeerInfo> {
        self.trusted_peers
            .read()
            .await
            .iter()
            .take(MAX_LISTED_PEERS)
            .map(|peer| PeerInfo {
                fingerprint: peer.fingerprint(),
                name: peer.name().to_owned(),
            })
            .collect()
    }

    /// Derives the key from the password (off the async workers) and stores it.
    async fn set_password(&self, kind: KeyKind, update: PasswordUpdate) -> Vec<u8> {
        let Ok(slot) = self.derive_slot.clone().acquire_owned().await else {
            return Response::encode_error(DaemonError::Internal);
        };

        // the slot moves into the blocking task: if this request hits its
        // deadline, the slot stays taken until Argon2 really finished.
        // `update` (and with it the password) is dropped and wiped inside
        let derived = tokio::task::spawn_blocking(move || {
            let key = derive_key(&update.password, &update.salt);
            drop(slot);
            key
        })
        .await;

        let key: Zeroizing<[u8; 32]> = match derived {
            Ok(Ok(key)) => key,
            Ok(Err(e)) => {
                warn!(error = %e, "key derivation failed");
                return Response::encode_error(DaemonError::KeyDerivationFailed);
            }
            Err(e) => {
                error!(error = %e, "key derivation task failed");
                return Response::encode_error(DaemonError::Internal);
            }
        };

        // one write guard, no await while holding it
        {
            let mut keys = self.keys.write().await;

            match kind {
                KeyKind::Auth => keys.a_key = Some(AuthKey::new(key)),
                KeyKind::Data => keys.d_key = Some(DataKey::new(key)),
            }
        }

        match kind {
            KeyKind::Auth => info!("auth key set"),
            KeyKind::Data => info!("data key set"),
        }

        Response::Done.encode()
    }
}

/// Runs the daemon until Ctrl-C.
pub async fn run() {
    let policy = match ClientPolicy::from_build() {
        Ok(policy) => policy,
        Err(e) => {
            error!(error = %e, "refusing to start with this IPC client policy");
            return;
        }
    };

    let path = match socket_path() {
        Ok(path) => path,
        Err(e) => {
            error!(error = %e, "no safe place for the IPC socket");
            return;
        }
    };

    let listener = match ipc_server::bind(&path) {
        Ok(listener) => listener,
        Err(e) => {
            error!(error = %e, path = %path.display(), "failed to start the IPC server");
            return;
        }
    };

    info!(path = %path.display(), "daemon listening for the UI");

    let daemon = Arc::new(Daemon::default());
    let token = CancellationToken::new();
    let handler = move |request: Request| {
        let daemon = daemon.clone();
        async move { daemon.handle(request).await }
    };

    let server = tokio::spawn(ipc_server::serve(listener, policy, handler, token.clone()));

    if tokio::signal::ctrl_c().await.is_err() {
        error!("failed to listen for Ctrl-C, shutting down");
    }

    token.cancel();

    if server.await.is_err() {
        error!("IPC server task failed");
    }

    // best effort: a stale socket is replaced on the next start anyway
    if std::fs::remove_file(&path).is_err() {
        warn!(path = %path.display(), "failed to remove the IPC socket");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cesa_conn_system::ipc::{IpcErrors, SALT_LEN, prepare_socket_dir, request_at};

    fn update(password: &[u8]) -> PasswordUpdate {
        PasswordUpdate {
            salt: [3; SALT_LEN],
            password: Zeroizing::new(password.to_vec()),
        }
    }

    /// Test that a fresh daemon reports no keys and no peers
    #[tokio::test]
    async fn test_fresh_status() {
        let daemon = Daemon::default();

        assert_eq!(
            daemon.status().await,
            Status {
                auth_key_set: false,
                data_key_set: false,
                network_running: false,
                trusted_peers: 0,
            }
        );
    }

    /// Test that setting each password derives exactly that key with Argon2
    #[tokio::test]
    async fn test_set_passwords_derives_keys() {
        let daemon = Daemon::default();

        assert_eq!(
            daemon
                .handle(Request::SetAuthPassword(update(b"auth pw")))
                .await,
            Response::Done.encode()
        );

        let status = daemon.status().await;
        assert!(status.auth_key_set && !status.data_key_set);

        assert_eq!(
            daemon
                .handle(Request::SetDataPassword(update(b"data pw")))
                .await,
            Response::Done.encode()
        );

        let keys = daemon.keys.read().await;
        let expected = derive_key(b"auth pw", &[3; SALT_LEN]).unwrap();
        assert_eq!(**keys.a_key.as_ref().unwrap().expose(), *expected);
        assert_ne!(
            **keys.a_key.as_ref().unwrap().expose(),
            **keys.d_key.as_ref().unwrap().expose()
        );
    }

    /// Test that no response ever contains key bytes (end to end over the socket)
    #[tokio::test]
    async fn test_responses_never_contain_keys() {
        let base = std::env::temp_dir().join(format!("cesa-daemon-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        let path = prepare_socket_dir(&base).unwrap();

        let daemon = Arc::new(Daemon::default());
        let state = daemon.clone();
        let token = CancellationToken::new();
        let handler = move |request: Request| {
            let daemon = state.clone();
            async move { daemon.handle(request).await }
        };

        tokio::spawn(ipc_server::serve(
            ipc_server::bind(&path).unwrap(),
            ClientPolicy::new(None).unwrap(),
            handler,
            token.clone(),
        ));

        request_at(&path, &Request::SetAuthPassword(update(b"pw")))
            .await
            .unwrap();
        request_at(&path, &Request::SetDataPassword(update(b"pw2")))
            .await
            .unwrap();

        let key = **daemon.keys.read().await.a_key.as_ref().unwrap().expose();

        for request in [Request::Status, Request::ListPeers] {
            let body = daemon.handle(request).await;
            assert!(!body.windows(32).any(|w| w == key));
        }

        // a malformed password request changes nothing
        assert_eq!(
            request_at(&path, &Request::SetAuthPassword(update(b""))).await,
            Err(IpcErrors::Daemon(DaemonError::BadRequest))
        );

        token.cancel();
    }
}
