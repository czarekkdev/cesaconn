/*
TODO:
start the networker once the vault is open (device identity + trusted peers go into the vault first)
pairing prompt over IPC (UI command set is defined together with the UI)
salt syncing between devices (docs/design/daemon.md, section 11)
Linux keychain backend (Secret Service): until then Linux keeps the keys in RAM only
data-protection keychain (WhenUnlockedThisDeviceOnly) together with release signing
 */

//! The daemon: owns `a_key` / `d_key` and answers UI requests over IPC.
//!
//! Keys only ever enter the daemon as passwords (derived here with Argon2)
//! and never leave it; the UI gets status and public peer info only.
//! The salts are the daemon's too: generated here, kept in zeroizing memory,
//! never sent to the UI.
//!
//! Saved state (see `vault`): nothing is stored unencrypted.
//! * `a_key`, `a_salt`, config: the encrypted vault file
//! * `d_salt` + storage salt: the OS keychain
//! * `d_key`: RAM only; after a restart the vault is **locked** until the user
//!   enters the data password. With automatic login, `d_key` is also kept in
//!   the OS keychain and the daemon unlocks itself.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{RwLock, Semaphore};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use zeroize::Zeroizing;

use cesa_conn_crypto::{crand::random_array, pswd_manager::derive_key};
use cesa_conn_system::{
    ipc::{
        DaemonError, MAX_LISTED_PEERS, MIN_NEW_PASSWORD_LEN, PasswordUpdate, PeerInfo, Request,
        Response, Status, socket_path,
    },
    keychain::{Item, OsKeychain, SecretStore},
};

use crate::{
    auth_snow::{
        AuthKey, DataKey, DeviceKeypairs, IDENTITY_SEED_LEN, TrustedPeer, decode_peers,
        encode_peers,
    },
    ipc_server::{self, ClientPolicy},
    vault::{self, Salts, VaultContents, VaultErrors, WrappedDek},
};

/// Argon2 salt, owned by the daemon; wiped on drop like the keys.
type Salt = Zeroizing<[u8; 32]>;

/// Where the daemon saves its state. Without it the keys stay in RAM only.
pub struct Storage {
    /// The OS keychain (salts, and `d_key` with automatic login).
    pub store: Arc<dyn SecretStore>,
    /// The encrypted vault file.
    pub path: PathBuf,
}

/// The open vault, kept so changes can be re-sealed without the password.
struct OpenVault {
    dek: Zeroizing<[u8; 32]>,
    wrapped: WrappedDek,
    storage_salt: Salt,
    config: Zeroizing<Vec<u8>>,
    /// This device's identity seed: made with the vault, kept for good.
    identity: Zeroizing<[u8; IDENTITY_SEED_LEN]>,
}

/// The keys the user has set so far, their salts, and the vault state.
#[derive(Default)]
struct KeySlots {
    a_key: Option<AuthKey>,
    d_key: Option<DataKey>,
    a_salt: Option<Salt>,
    d_salt: Option<Salt>,
    /// `Some` once the keys are saved (and the vault is open).
    vault: Option<OpenVault>,
    /// A saved vault exists but isn't open yet.
    locked: bool,
    /// `d_key` is in the OS keychain.
    auto_login: bool,
    /// Wrong unlock passwords since the last success (see [`unlock_delay`]).
    unlock_failures: u32,
    /// No unlock attempt is accepted before this moment.
    unlock_not_before: Option<Instant>,
}

/* unlock guessing */
/// Wrong unlock passwords allowed before every attempt is delayed.
const FREE_UNLOCK_ATTEMPTS: u32 = 5;
/// Longest delay before an unlock attempt (seconds).
const MAX_UNLOCK_DELAY: u64 = 60;

/// How long after the `failures`-th wrong password the next unlock attempt
/// is refused: not at all for the first [`FREE_UNLOCK_ATTEMPTS`], then 1 s
/// doubling up to [`MAX_UNLOCK_DELAY`]. On top of Argon2's own cost, this
/// slows a local process guessing through the IPC.
///
/// Attempts inside the delay are refused at once ([`DaemonError::UnlockDelayed`])
/// instead of waiting: a wait would outlast the IPC deadline, and the UI
/// would get a timeout even for the right password.
fn unlock_delay(failures: u32) -> Duration {
    let over = failures.saturating_sub(FREE_UNLOCK_ATTEMPTS);
    if failures < FREE_UNLOCK_ATTEMPTS {
        return Duration::ZERO;
    }

    let secs = 1u64
        .checked_shl(over)
        .unwrap_or(u64::MAX)
        .min(MAX_UNLOCK_DELAY);
    Duration::from_secs(secs)
}

/// Whole seconds left until `not_before` (rounded up, so 0 really means now).
fn wait_secs(not_before: Option<Instant>, now: Instant) -> u16 {
    let left = not_before.map_or(Duration::ZERO, |t| t.saturating_duration_since(now));
    let secs = left
        .as_secs()
        .saturating_add(u64::from(left.subsec_nanos() > 0));

    u16::try_from(secs).unwrap_or(u16::MAX)
}

/// Everything the daemon owns. Shared between IPC handlers.
pub struct Daemon {
    keys: RwLock<KeySlots>,
    trusted_peers: Arc<RwLock<Vec<TrustedPeer>>>,
    // one Argon2 run (64 MiB) at a time, so clients can't stack up memory
    derive_slot: Arc<Semaphore>,
    // one state change (set password / unlock / auto-login) at a time, end to end
    change_slot: Arc<Semaphore>,
    storage: Option<Storage>,
}

/// Which key a password is for.
#[derive(Clone, Copy)]
enum KeyKind {
    Auth,
    Data,
}

impl Default for Daemon {
    fn default() -> Self {
        Self::new(None)
    }
}

/// Runs blocking work (Argon2 aside: keychain, files) off the async workers.
async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T, DaemonError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|_| DaemonError::Internal)
}

/// Length of a password in characters (bytes if it isn't UTF-8), so a
/// password with multi-byte letters isn't counted longer than it is.
fn password_chars(password: &[u8]) -> usize {
    std::str::from_utf8(password).map_or(password.len(), |p| p.chars().count())
}

/// Maps vault errors to what the UI is told; details stay in the daemon log.
fn storage_error(e: VaultErrors) -> DaemonError {
    match e {
        VaultErrors::WrongKey => DaemonError::WrongPassword,
        other => {
            error!(error = %other, "vault operation failed");
            DaemonError::StorageFailed
        }
    }
}

impl Daemon {
    /// A daemon saving to `storage` (`None`: RAM only).
    pub fn new(storage: Option<Storage>) -> Self {
        Self {
            keys: RwLock::default(),
            trusted_peers: Arc::default(),
            derive_slot: Arc::new(Semaphore::new(1)),
            change_slot: Arc::new(Semaphore::new(1)),
            storage,
        }
    }

    /// Answers one request with an encoded response body.
    ///
    /// State changes wait for their turn here (so at most one runs and the
    /// waiting ones are bounded by the IPC client cap), then run as their own
    /// task: if the IPC deadline cancels this future, the change still
    /// finishes as a whole (never half-saved).
    pub async fn handle(self: &Arc<Self>, request: Request) -> Vec<u8> {
        match request {
            Request::Status => Response::Status(self.status().await).encode(),
            Request::ListPeers => Response::Peers(self.peers().await).encode(),
            change => {
                let Ok(turn) = self.change_slot.clone().acquire_owned().await else {
                    return Response::encode_error(DaemonError::Internal);
                };

                let daemon = self.clone();
                let task = tokio::spawn(async move {
                    let result = daemon.change(change).await;
                    drop(turn);
                    result
                });

                match task.await {
                    Ok(Ok(())) => Response::Done.encode(),
                    Ok(Err(e)) => Response::encode_error(e),
                    Err(_) => Response::encode_error(DaemonError::Internal),
                }
            }
        }
    }

    /// One state change; the caller holds the change slot.
    async fn change(&self, request: Request) -> Result<(), DaemonError> {
        match request {
            Request::SetAuthPassword(update) => self.set_password(KeyKind::Auth, update).await,
            Request::SetDataPassword(update) => self.set_password(KeyKind::Data, update).await,
            Request::Unlock(update) => self.unlock(update).await,
            Request::SetAutoLogin(on) => self.set_auto_login(on).await,
            Request::Status | Request::ListPeers => Err(DaemonError::BadRequest),
        }
    }

    /// Looks for a saved vault: if there is one the daemon starts locked, and
    /// with automatic login it unlocks itself from the keychain.
    pub async fn start(&self) {
        let Some(storage) = &self.storage else {
            warn!("no storage: keys stay in RAM only and are gone after a restart");
            return;
        };

        let path = storage.path.clone();
        match blocking(move || vault::read_file(&path)).await {
            Ok(Ok(Some(_))) => {}
            Ok(Ok(None)) => {
                info!("no saved vault yet");
                return;
            }
            Ok(Err(e)) => {
                // stays locked: unlocking will report the same problem
                error!(error = %e, "the saved vault can't be read");
            }
            Err(_) => error!("reading the saved vault failed"),
        }

        self.keys.write().await.locked = true;
        info!("saved vault found: locked until the data password is entered");

        let store = storage.store.clone();
        let d_key = match blocking(move || store.get(Item::DataKey)).await {
            Ok(Ok(Some(d_key))) => d_key,
            Ok(Ok(None)) => return,
            Ok(Err(e)) => {
                warn!(error = %e, "keychain unavailable: no automatic login");
                return;
            }
            Err(_) => return,
        };

        self.keys.write().await.auto_login = true;

        if d_key.len() != 32 {
            warn!("automatic login key has the wrong size: enter the data password");
            return;
        }
        // copied straight into a zeroizing buffer, no plain array in between
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&d_key);
        drop(d_key);

        match self.unlock_with(DataKey::new(key)).await {
            Ok(()) => info!("vault unlocked by automatic login"),
            Err(DaemonError::WrongPassword) => {
                // a stale key that no longer opens the vault: remove it
                let store = storage.store.clone();
                let removed = blocking(move || store.delete(Item::DataKey)).await;
                if matches!(removed, Ok(Ok(()))) {
                    self.keys.write().await.auto_login = false;
                }
                warn!(
                    "automatic login key no longer opens the vault: removed, enter the data password"
                );
            }
            Err(e) => warn!(error = %e, "automatic login failed: enter the data password"),
        }
    }

    async fn status(&self) -> Status {
        let status = {
            let keys = self.keys.read().await;
            Status {
                auth_key_set: keys.a_key.is_some(),
                data_key_set: keys.d_key.is_some(),
                network_running: false,
                trusted_peers: 0,
                locked: keys.locked,
                saved: keys.vault.is_some(),
                auto_login: keys.auto_login,
                unlock_wait_secs: wait_secs(keys.unlock_not_before, Instant::now()),
            }
        };
        let trusted_peers = self.trusted_peers.read().await.len();

        Status {
            trusted_peers: u32::try_from(trusted_peers).unwrap_or(u32::MAX),
            ..status
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

    /// The salt for `kind`, made (and kept) on first use.
    async fn salt_for(&self, kind: KeyKind) -> Result<Salt, DaemonError> {
        // one write guard for check-then-create, no await while holding it
        let mut keys = self.keys.write().await;

        let slot = match kind {
            KeyKind::Auth => &mut keys.a_salt,
            KeyKind::Data => &mut keys.d_salt,
        };

        if slot.is_none() {
            // filled in place inside a zeroizing buffer
            *slot = Some(random_array::<32>().map_err(|e| {
                error!(error = %e, "failed to generate a salt");
                DaemonError::Internal
            })?);
        }

        let salt = slot.clone().ok_or(DaemonError::Internal)?;
        drop(keys);

        Ok(salt)
    }

    /// Argon2 off the async workers, one at a time. The password and the
    /// salt are moved in and wiped there.
    async fn derive(
        &self,
        update: PasswordUpdate,
        salt: Salt,
    ) -> Result<Zeroizing<[u8; 32]>, DaemonError> {
        let slot = self
            .derive_slot
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| DaemonError::Internal)?;

        // the slot moves into the blocking task: it stays taken until Argon2
        // really finished, even if this future is dropped
        match blocking(move || {
            let key = derive_key(&update.password, &salt);
            drop(slot);
            key
        })
        .await?
        {
            Ok(key) => Ok(key),
            Err(e) => {
                warn!(error = %e, "key derivation failed");
                Err(DaemonError::KeyDerivationFailed)
            }
        }
    }

    /// Sets a new password: derive, save (if the vault is open), then keep.
    async fn set_password(&self, kind: KeyKind, update: PasswordUpdate) -> Result<(), DaemonError> {
        if password_chars(&update.password) < MIN_NEW_PASSWORD_LEN {
            return Err(DaemonError::WeakPassword);
        }
        if self.keys.read().await.locked {
            return Err(DaemonError::Locked);
        }

        let salt = self.salt_for(kind).await?;
        let key = self.derive(update, salt).await?;

        // saved first, kept second: a failed save changes nothing
        if self.keys.read().await.vault.is_some() {
            self.save_changed_key(kind, &key).await?;
        }

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

        // first time both keys exist: create the vault
        if self.keys.read().await.vault.is_none() {
            self.create_vault().await;
        }

        Ok(())
    }

    /// The trusted peers, encoded for the vault. Read before the key lock is
    /// taken, so the two locks are never held together.
    async fn encoded_peers(&self) -> Result<Zeroizing<Vec<u8>>, DaemonError> {
        let peers = self.trusted_peers.read().await;
        let encoded = encode_peers(&peers).ok_or_else(|| {
            error!("trusted peers don't fit in the vault");
            DaemonError::StorageFailed
        })?;
        drop(peers);

        Ok(Zeroizing::new(encoded))
    }

    /// Re-saves the open vault with a changed key. A new `d_key` re-wraps the
    /// DEK (and replaces the automatic-login key); a new `a_key` re-seals.
    async fn save_changed_key(&self, kind: KeyKind, key: &[u8; 32]) -> Result<(), DaemonError> {
        let Some(storage) = &self.storage else {
            return Ok(());
        };

        let peers = self.encoded_peers().await?;

        let (file, new_wrap, auto_login) = {
            let keys = self.keys.read().await;
            let (Some(open), Some(a_key), Some(a_salt)) = (&keys.vault, &keys.a_key, &keys.a_salt)
            else {
                return Err(DaemonError::Internal);
            };

            let (a_key, wrapped) = match kind {
                KeyKind::Auth => (AuthKey::from_bytes(key), open.wrapped.clone()),
                KeyKind::Data => {
                    let kek = vault::derive_kek(&DataKey::from_bytes(key), &open.storage_salt)
                        .map_err(storage_error)?;
                    (
                        a_key.clone(),
                        vault::wrap_dek(&kek, &open.dek).map_err(storage_error)?,
                    )
                }
            };

            let contents = VaultContents {
                a_key,
                a_salt: a_salt.clone(),
                config: open.config.clone(),
                identity: open.identity.clone(),
                peers,
            };
            let file = vault::seal(&wrapped, &open.dek, &contents).map_err(storage_error)?;

            (file, wrapped, keys.auto_login)
        };

        let path = storage.path.clone();
        blocking(move || vault::write_file_atomic(&path, &file))
            .await?
            .map_err(storage_error)?;

        if let KeyKind::Data = kind {
            {
                let mut keys = self.keys.write().await;
                if let Some(open) = keys.vault.as_mut() {
                    open.wrapped = new_wrap;
                }
            }

            if auto_login {
                let store = storage.store.clone();
                let d_key = Zeroizing::new(*key);
                let saved = blocking(move || store.set(Item::DataKey, d_key.as_slice())).await;

                if !matches!(saved, Ok(Ok(()))) {
                    // the old keychain key no longer opens the vault: remove it
                    let store = storage.store.clone();
                    let _ = blocking(move || store.delete(Item::DataKey)).await;
                    self.keys.write().await.auto_login = false;
                    warn!("automatic login turned off: the keychain refused the new key");
                }
            }
        }

        info!("vault saved");
        Ok(())
    }

    /// Creates the vault once both keys are set. On failure the keys stay in
    /// RAM only (the status says `saved = false`) and nothing is half-written.
    async fn create_vault(&self) {
        let Some(storage) = &self.storage else {
            return;
        };

        // copies (zeroizing) taken under the guard, which is dropped right away
        let copies = {
            let keys = self.keys.read().await;
            (
                keys.a_key.clone(),
                keys.a_salt.clone(),
                keys.d_key.clone(),
                keys.d_salt.clone(),
            )
        };

        let (Some(a_key), Some(a_salt), Some(d_key), Some(d_salt)) = copies else {
            return;
        };

        let Ok(peers) = self.encoded_peers().await else {
            return;
        };

        let prepared = {
            (|| {
                let storage_salt = random_array::<32>().map_err(|_| VaultErrors::Crypto)?;
                let salts = Salts {
                    d_salt: d_salt.clone(),
                    storage_salt: storage_salt.clone(),
                };
                let dek = vault::generate_dek()?;
                let kek = vault::derive_kek(&d_key, &storage_salt)?;
                let wrapped = vault::wrap_dek(&kek, &dek)?;
                let config = Zeroizing::new(Vec::new());
                // the device identity is born with the vault
                let identity = DeviceKeypairs::new_seed().map_err(|_| VaultErrors::Crypto)?;
                let contents = VaultContents {
                    a_key: a_key.clone(),
                    a_salt: a_salt.clone(),
                    config: config.clone(),
                    identity: identity.clone(),
                    peers,
                };
                let file = vault::seal(&wrapped, &dek, &contents)?;

                Ok::<_, VaultErrors>((
                    salts,
                    file,
                    OpenVault {
                        dek,
                        wrapped,
                        storage_salt,
                        config,
                        identity,
                    },
                ))
            })()
        };

        let (salts, file, open) = match prepared {
            Ok(prepared) => prepared,
            Err(e) => {
                error!(error = %e, "preparing the vault failed: keys stay in RAM only");
                return;
            }
        };

        // 1. salts into the keychain (without them the file can't be opened)
        let store = storage.store.clone();
        let salt_bytes = salts.to_bytes();
        match blocking(move || store.set(Item::Salts, salt_bytes.as_slice())).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                warn!(error = %e, "keychain refused the salts: keys stay in RAM only");
                return;
            }
            Err(_) => return,
        }

        // 2. the vault file
        let path = storage.path.clone();
        match blocking(move || vault::write_file_atomic(&path, &file)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                error!(error = %e, "writing the vault failed: keys stay in RAM only");
                return;
            }
            Err(_) => return,
        }

        self.keys.write().await.vault = Some(open);
        info!("keys saved in the encrypted vault");
    }

    /// Opens the saved vault with the data password.
    async fn unlock(&self, update: PasswordUpdate) -> Result<(), DaemonError> {
        let Some(storage) = &self.storage else {
            return Err(DaemonError::NotSaved);
        };

        {
            let keys = self.keys.read().await;
            if !keys.locked {
                return Err(if keys.vault.is_some() {
                    DaemonError::BadRequest
                } else {
                    DaemonError::NotSaved
                });
            }

            // too soon after wrong passwords: refused at once, before any
            // keychain access or Argon2, and not counted as another guess
            if wait_secs(keys.unlock_not_before, Instant::now()) > 0 {
                return Err(DaemonError::UnlockDelayed);
            }
        }

        let store = storage.store.clone();
        let salts = match blocking(move || store.get(Item::Salts)).await? {
            Ok(Some(bytes)) => Salts::from_bytes(&bytes).ok_or(DaemonError::StorageFailed)?,
            Ok(None) => {
                error!("the vault's salts are missing from the keychain");
                return Err(DaemonError::StorageFailed);
            }
            Err(e) => {
                error!(error = %e, "keychain unavailable");
                return Err(DaemonError::StorageFailed);
            }
        };

        let d_key = self.derive(update, salts.d_salt.clone()).await?;

        let result = self.unlock_with(DataKey::new(d_key)).await;

        {
            let mut keys = self.keys.write().await;
            match result {
                Ok(()) => {
                    keys.unlock_failures = 0;
                    keys.unlock_not_before = None;
                }
                Err(DaemonError::WrongPassword) => {
                    keys.unlock_failures = keys.unlock_failures.saturating_add(1);
                    let delay = unlock_delay(keys.unlock_failures);
                    // an overflowing deadline means "as long as possible"
                    let now = Instant::now();
                    keys.unlock_not_before = Some(
                        now.checked_add(delay)
                            .or_else(|| now.checked_add(Duration::from_secs(MAX_UNLOCK_DELAY)))
                            .unwrap_or(now),
                    );
                    warn!(
                        failures = keys.unlock_failures,
                        delay_secs = delay.as_secs(),
                        "wrong data password"
                    );
                }
                Err(_) => {}
            }
        }

        result
    }

    /// Opens the vault with `d_key` (typed password or automatic login).
    async fn unlock_with(&self, d_key: DataKey) -> Result<(), DaemonError> {
        let Some(storage) = &self.storage else {
            return Err(DaemonError::NotSaved);
        };

        let store = storage.store.clone();
        let salts = match blocking(move || store.get(Item::Salts)).await? {
            Ok(Some(bytes)) => Salts::from_bytes(&bytes).ok_or(DaemonError::StorageFailed)?,
            _ => return Err(DaemonError::StorageFailed),
        };

        let path = storage.path.clone();
        let file = blocking(move || vault::read_file(&path))
            .await?
            .map_err(storage_error)?
            .ok_or(DaemonError::NotSaved)?;

        let kek = vault::derive_kek(&d_key, &salts.storage_salt).map_err(storage_error)?;
        let opened = vault::open(&kek, &file).map_err(storage_error)?;
        let peers = decode_peers(&opened.contents.peers).ok_or_else(|| {
            error!("saved trusted peers are damaged");
            DaemonError::StorageFailed
        })?;

        *self.trusted_peers.write().await = peers;

        let mut keys = self.keys.write().await;
        keys.a_key = Some(opened.contents.a_key);
        keys.a_salt = Some(opened.contents.a_salt);
        keys.d_key = Some(d_key);
        keys.d_salt = Some(salts.d_salt);
        keys.vault = Some(OpenVault {
            dek: opened.dek,
            wrapped: opened.wrapped,
            storage_salt: salts.storage_salt,
            config: opened.contents.config,
            identity: opened.contents.identity,
        });
        keys.locked = false;
        drop(keys);

        info!("vault unlocked");
        Ok(())
    }

    /// Keeps `d_key` in the OS keychain (or removes it from there).
    async fn set_auto_login(&self, on: bool) -> Result<(), DaemonError> {
        let Some(storage) = &self.storage else {
            return Err(DaemonError::NotSaved);
        };

        let d_key = {
            let keys = self.keys.read().await;
            if keys.locked {
                return Err(DaemonError::Locked);
            }
            if keys.vault.is_none() {
                return Err(DaemonError::NotSaved);
            }
            keys.d_key
                .as_ref()
                .map(|k| k.expose().clone())
                .ok_or(DaemonError::NotSaved)?
        };

        let store = storage.store.clone();
        let result = if on {
            blocking(move || store.set(Item::DataKey, d_key.as_slice())).await?
        } else {
            drop(d_key);
            blocking(move || store.delete(Item::DataKey)).await?
        };

        result.map_err(|e| {
            error!(error = %e, "keychain refused the automatic-login change");
            DaemonError::StorageFailed
        })?;

        self.keys.write().await.auto_login = on;

        if on {
            warn!("automatic login on: d_key is in the OS keychain, its security rests on the OS");
        } else {
            info!("automatic login off: d_key removed from the OS keychain");
        }

        Ok(())
    }
}

/// The storage this platform supports: the vault in the private data
/// directory plus the OS keychain. `None` (RAM only) where there is no
/// keychain backend yet.
fn platform_storage() -> Option<Storage> {
    if !cfg!(target_os = "macos") {
        warn!("no OS keychain backend on this platform yet: keys stay in RAM only");
        return None;
    }

    match vault::data_dir() {
        Ok(dir) => Some(Storage {
            store: Arc::new(OsKeychain),
            path: vault::vault_path(&dir),
        }),
        Err(e) => {
            error!(error = %e, "no safe data directory: keys stay in RAM only");
            None
        }
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

    let daemon = Arc::new(Daemon::new(platform_storage()));
    daemon.start().await;

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
    use cesa_conn_system::ipc::{IpcErrors, prepare_socket_dir, request_at};
    use cesa_conn_system::keychain::KeychainErrors;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::sync::Mutex;

    const AUTH_PW: &[u8] = b"auth password 1";
    const DATA_PW: &[u8] = b"data password 22";

    fn update(password: &[u8]) -> PasswordUpdate {
        PasswordUpdate {
            password: Zeroizing::new(password.to_vec()),
        }
    }

    /// In-memory keychain; `fail` makes every call fail like a locked keychain.
    /// The daemon calls it only from blocking tasks (`blocking_lock` is fine
    /// there); the async tests read it with `lock().await`.
    #[derive(Default)]
    struct MemStore {
        items: Mutex<HashMap<Item, Zeroizing<Vec<u8>>>>,
        fail: AtomicBool,
    }

    impl MemStore {
        async fn has(&self, item: Item) -> bool {
            self.items.lock().await.contains_key(&item)
        }
    }

    impl SecretStore for MemStore {
        fn get(&self, item: Item) -> Result<Option<Zeroizing<Vec<u8>>>, KeychainErrors> {
            if self.fail.load(Ordering::SeqCst) {
                return Err(KeychainErrors::Failed);
            }
            Ok(self.items.blocking_lock().get(&item).cloned())
        }

        fn set(&self, item: Item, secret: &[u8]) -> Result<(), KeychainErrors> {
            if self.fail.load(Ordering::SeqCst) {
                return Err(KeychainErrors::Failed);
            }
            self.items
                .blocking_lock()
                .insert(item, Zeroizing::new(secret.to_vec()));
            Ok(())
        }

        fn delete(&self, item: Item) -> Result<(), KeychainErrors> {
            if self.fail.load(Ordering::SeqCst) {
                return Err(KeychainErrors::Failed);
            }
            self.items.blocking_lock().remove(&item);
            Ok(())
        }
    }

    /// A storage in a fresh private test directory, sharing `store`.
    struct TestStorage {
        store: Arc<MemStore>,
        dir: PathBuf,
    }

    impl TestStorage {
        fn new(name: &str) -> Self {
            let base =
                std::env::temp_dir().join(format!("cesa-daemon-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&base);
            std::fs::create_dir_all(&base).unwrap();
            let dir = vault::prepare_dir(&base.join("data")).unwrap();

            Self {
                store: Arc::default(),
                dir,
            }
        }

        fn path(&self) -> PathBuf {
            vault::vault_path(&self.dir)
        }

        /// A daemon as after a (re)start with this storage.
        async fn daemon(&self) -> Arc<Daemon> {
            let daemon = Arc::new(Daemon::new(Some(Storage {
                store: self.store.clone(),
                path: self.path(),
            })));
            daemon.start().await;
            daemon
        }
    }

    impl Drop for TestStorage {
        fn drop(&mut self) {
            if let Some(base) = self.dir.parent() {
                let _ = std::fs::remove_dir_all(base);
            }
        }
    }

    async fn ask(daemon: &Arc<Daemon>, request: Request) -> Result<(), DaemonError> {
        let body = daemon.handle(request).await;
        if body == Response::Done.encode() {
            Ok(())
        } else {
            match body.as_slice() {
                [0x01, code] => Err(match *code {
                    0x01 => DaemonError::BadRequest,
                    0x02 => DaemonError::KeyDerivationFailed,
                    0x04 => DaemonError::WrongPassword,
                    0x05 => DaemonError::Locked,
                    0x06 => DaemonError::StorageFailed,
                    0x07 => DaemonError::NotSaved,
                    0x08 => DaemonError::WeakPassword,
                    0x09 => DaemonError::UnlockDelayed,
                    _ => DaemonError::Internal,
                }),
                _ => panic!("unexpected response"),
            }
        }
    }

    async fn setup(daemon: &Arc<Daemon>) {
        ask(daemon, Request::SetAuthPassword(update(AUTH_PW)))
            .await
            .unwrap();
        ask(daemon, Request::SetDataPassword(update(DATA_PW)))
            .await
            .unwrap();
    }

    async fn key_bytes(daemon: &Daemon) -> ([u8; 32], [u8; 32]) {
        let keys = daemon.keys.read().await;
        (
            **keys.a_key.as_ref().unwrap().expose(),
            **keys.d_key.as_ref().unwrap().expose(),
        )
    }

    /// Test that a fresh daemon reports no keys and no peers
    #[tokio::test]
    async fn test_fresh_status() {
        assert_eq!(Daemon::default().status().await, Status::default());
    }

    /// Test that setting each password derives exactly that key with Argon2
    #[tokio::test]
    async fn test_set_passwords_derives_keys() {
        let daemon = Arc::new(Daemon::default());

        ask(&daemon, Request::SetAuthPassword(update(AUTH_PW)))
            .await
            .unwrap();
        let status = daemon.status().await;
        assert!(status.auth_key_set && !status.data_key_set);

        ask(&daemon, Request::SetDataPassword(update(DATA_PW)))
            .await
            .unwrap();

        let keys = daemon.keys.read().await;
        let expected = derive_key(AUTH_PW, keys.a_salt.as_ref().unwrap()).unwrap();
        assert_eq!(**keys.a_key.as_ref().unwrap().expose(), *expected);
        assert_ne!(
            **keys.a_key.as_ref().unwrap().expose(),
            **keys.d_key.as_ref().unwrap().expose()
        );
    }

    /// Test that the daemon makes one salt per key and keeps it: the same
    /// password set twice gives the same key, and auth / data salts differ
    #[tokio::test]
    async fn test_salts_owned_and_stable() {
        let daemon = Arc::new(Daemon::default());
        let pw = b"same password!!";

        assert!(daemon.keys.read().await.a_salt.is_none());

        ask(&daemon, Request::SetAuthPassword(update(pw)))
            .await
            .unwrap();
        let (first_salt, first_key) = {
            let keys = daemon.keys.read().await;
            (
                keys.a_salt.clone().unwrap(),
                **keys.a_key.as_ref().unwrap().expose(),
            )
        };

        ask(&daemon, Request::SetAuthPassword(update(pw)))
            .await
            .unwrap();
        ask(&daemon, Request::SetDataPassword(update(pw)))
            .await
            .unwrap();

        let keys = daemon.keys.read().await;
        assert_eq!(*keys.a_salt.clone().unwrap(), *first_salt);
        assert_eq!(**keys.a_key.as_ref().unwrap().expose(), first_key);
        assert_ne!(*keys.d_salt.clone().unwrap(), *first_salt);
        // same password, different salt: different key
        assert_ne!(**keys.d_key.as_ref().unwrap().expose(), first_key);
    }

    /// Test that the password is used exactly as sent (no trimming)
    #[tokio::test]
    async fn test_password_not_trimmed() {
        let daemon = Arc::new(Daemon::default());

        ask(
            &daemon,
            Request::SetAuthPassword(update(b" pw with spaces ")),
        )
        .await
        .unwrap();

        let keys = daemon.keys.read().await;
        let salt = keys.a_salt.as_ref().unwrap();
        assert_eq!(
            **keys.a_key.as_ref().unwrap().expose(),
            *derive_key(b" pw with spaces ", salt).unwrap()
        );
        assert_ne!(
            **keys.a_key.as_ref().unwrap().expose(),
            *derive_key(b"pw with spaces", salt).unwrap()
        );
    }

    /// Test that new passwords shorter than the minimum are refused
    #[tokio::test]
    async fn test_weak_password_refused() {
        let daemon = Arc::new(Daemon::default());
        let short = vec![b'a'; MIN_NEW_PASSWORD_LEN - 1];

        for request in [
            Request::SetAuthPassword(update(&short)),
            Request::SetDataPassword(update(&short)),
        ] {
            assert_eq!(ask(&daemon, request).await, Err(DaemonError::WeakPassword));
        }
        assert_eq!(daemon.status().await, Status::default());
    }

    /// Test the full saved lifecycle: setup saves an encrypted vault, a
    /// restart starts locked, a wrong password is refused, the right one
    /// brings back exactly the same keys
    #[tokio::test]
    async fn test_save_restart_unlock() {
        let storage = TestStorage::new("cycle");
        let daemon = storage.daemon().await;
        setup(&daemon).await;

        let status = daemon.status().await;
        assert!(status.saved && !status.locked && !status.auto_login);
        let before = key_bytes(&daemon).await;
        drop(daemon);

        // restart
        let daemon = storage.daemon().await;
        let status = daemon.status().await;
        assert!(status.locked && !status.auth_key_set && !status.data_key_set);

        // nothing can be changed while locked
        assert_eq!(
            ask(&daemon, Request::SetAuthPassword(update(AUTH_PW))).await,
            Err(DaemonError::Locked)
        );
        assert_eq!(
            ask(&daemon, Request::SetAutoLogin(true)).await,
            Err(DaemonError::Locked)
        );

        assert_eq!(
            ask(&daemon, Request::Unlock(update(b"wrong data password"))).await,
            Err(DaemonError::WrongPassword)
        );
        assert!(daemon.status().await.locked);

        ask(&daemon, Request::Unlock(update(DATA_PW)))
            .await
            .unwrap();
        let status = daemon.status().await;
        assert!(!status.locked && status.saved && status.auth_key_set && status.data_key_set);
        assert_eq!(key_bytes(&daemon).await, before);

        // already open
        assert_eq!(
            ask(&daemon, Request::Unlock(update(DATA_PW))).await,
            Err(DaemonError::BadRequest)
        );
    }

    /// Test that nothing secret is on disk in plaintext, and the keychain
    /// holds only the salts (no d_key without automatic login)
    #[tokio::test]
    async fn test_nothing_plaintext_on_disk() {
        let storage = TestStorage::new("plain");
        let daemon = storage.daemon().await;
        setup(&daemon).await;

        let (a_key, d_key) = key_bytes(&daemon).await;
        let (a_salt, d_salt) = {
            let keys = daemon.keys.read().await;
            (*keys.a_salt.clone().unwrap(), *keys.d_salt.clone().unwrap())
        };
        let file = std::fs::read(storage.path()).unwrap();

        for secret in [a_key, d_key, a_salt, d_salt] {
            assert!(!file.windows(32).any(|w| w == secret));
        }
        for password in [AUTH_PW, DATA_PW] {
            assert!(!file.windows(password.len()).any(|w| w == password));
        }

        assert!(storage.store.has(Item::Salts).await);
        assert!(!storage.store.has(Item::DataKey).await);
        let items = storage.store.items.lock().await;
        assert_eq!(items.get(&Item::Salts).unwrap().get(..32).unwrap(), d_salt);
    }

    /// Test automatic login: on stores d_key in the keychain and a restart
    /// unlocks by itself; off removes it and a restart is locked again
    #[tokio::test]
    async fn test_auto_login() {
        let storage = TestStorage::new("auto");
        let daemon = storage.daemon().await;

        // nothing saved yet
        assert_eq!(
            ask(&daemon, Request::SetAutoLogin(true)).await,
            Err(DaemonError::NotSaved)
        );

        setup(&daemon).await;
        let before = key_bytes(&daemon).await;
        ask(&daemon, Request::SetAutoLogin(true)).await.unwrap();
        assert!(daemon.status().await.auto_login);
        drop(daemon);

        let daemon = storage.daemon().await;
        let status = daemon.status().await;
        assert!(!status.locked && status.auto_login);
        assert_eq!(key_bytes(&daemon).await, before);

        ask(&daemon, Request::SetAutoLogin(false)).await.unwrap();
        assert!(!storage.store.has(Item::DataKey).await);
        drop(daemon);

        let daemon = storage.daemon().await;
        assert!(daemon.status().await.locked);
    }

    /// Test changing the data password: the vault is re-wrapped, so after a
    /// restart only the new password opens it (and the automatic-login key
    /// in the keychain follows the change)
    #[tokio::test]
    async fn test_change_data_password() {
        let storage = TestStorage::new("change");
        let daemon = storage.daemon().await;
        setup(&daemon).await;
        ask(&daemon, Request::SetAutoLogin(true)).await.unwrap();

        let new_pw = b"a new data password";
        ask(&daemon, Request::SetDataPassword(update(new_pw)))
            .await
            .unwrap();
        let after = key_bytes(&daemon).await;
        drop(daemon);

        // automatic login uses the new key
        let daemon = storage.daemon().await;
        assert!(!daemon.status().await.locked);
        assert_eq!(key_bytes(&daemon).await, after);
        ask(&daemon, Request::SetAutoLogin(false)).await.unwrap();
        drop(daemon);

        let daemon = storage.daemon().await;
        assert_eq!(
            ask(&daemon, Request::Unlock(update(DATA_PW))).await,
            Err(DaemonError::WrongPassword)
        );
        ask(&daemon, Request::Unlock(update(new_pw))).await.unwrap();
        assert_eq!(key_bytes(&daemon).await, after);
    }

    /// Test changing the auth password is saved too
    #[tokio::test]
    async fn test_change_auth_password_saved() {
        let storage = TestStorage::new("auth");
        let daemon = storage.daemon().await;
        setup(&daemon).await;

        ask(
            &daemon,
            Request::SetAuthPassword(update(b"another auth pw")),
        )
        .await
        .unwrap();
        let after = key_bytes(&daemon).await;
        drop(daemon);

        let daemon = storage.daemon().await;
        ask(&daemon, Request::Unlock(update(DATA_PW)))
            .await
            .unwrap();
        assert_eq!(key_bytes(&daemon).await, after);
    }

    /// Test that a refusing keychain leaves the keys in RAM only: no file,
    /// status says not saved, nothing half-written
    #[tokio::test]
    async fn test_keychain_failure_stays_in_ram() {
        let storage = TestStorage::new("fail");
        storage.store.fail.store(true, Ordering::SeqCst);
        let daemon = storage.daemon().await;
        setup(&daemon).await;

        let status = daemon.status().await;
        assert!(status.auth_key_set && status.data_key_set && !status.saved);
        assert!(!storage.path().exists());
    }

    /// Test that a damaged vault is reported as a storage failure, not as a
    /// wrong password, and the daemon stays locked
    #[tokio::test]
    async fn test_damaged_vault() {
        let storage = TestStorage::new("damaged");
        let daemon = storage.daemon().await;
        setup(&daemon).await;
        drop(daemon);

        let mut file = std::fs::read(storage.path()).unwrap();
        let last = file.len() - 1;
        file[last] ^= 1;
        vault::write_file_atomic(&storage.path(), &file).unwrap();

        let daemon = storage.daemon().await;
        assert_eq!(
            ask(&daemon, Request::Unlock(update(DATA_PW))).await,
            Err(DaemonError::StorageFailed)
        );
        assert!(daemon.status().await.locked);
    }

    /// Test the unlock delay: free attempts first, then doubling, capped
    #[test]
    fn test_unlock_delay() {
        use std::time::Duration;

        for f in 0..FREE_UNLOCK_ATTEMPTS {
            assert_eq!(unlock_delay(f), Duration::ZERO);
        }
        assert_eq!(unlock_delay(FREE_UNLOCK_ATTEMPTS), Duration::from_secs(1));
        assert_eq!(
            unlock_delay(FREE_UNLOCK_ATTEMPTS + 1),
            Duration::from_secs(2)
        );
        assert_eq!(
            unlock_delay(FREE_UNLOCK_ATTEMPTS + 10),
            Duration::from_secs(MAX_UNLOCK_DELAY)
        );
        assert_eq!(
            unlock_delay(u32::MAX),
            Duration::from_secs(MAX_UNLOCK_DELAY)
        );
    }

    /// Test that wrong unlock passwords are counted and a success resets them
    #[tokio::test]
    async fn test_unlock_failures_counted() {
        let storage = TestStorage::new("count");
        let daemon = storage.daemon().await;
        setup(&daemon).await;
        drop(daemon);

        let daemon = storage.daemon().await;
        for _ in 0..2 {
            assert_eq!(
                ask(&daemon, Request::Unlock(update(b"wrong password!"))).await,
                Err(DaemonError::WrongPassword)
            );
        }
        assert_eq!(daemon.keys.read().await.unlock_failures, 2);

        ask(&daemon, Request::Unlock(update(DATA_PW)))
            .await
            .unwrap();
        assert_eq!(daemon.keys.read().await.unlock_failures, 0);
    }

    /// Test that inside the delay an unlock is refused at once, even with the
    /// right password: no Argon2, not counted as another guess, still locked;
    /// the status says how long to wait, and after it the password works
    #[tokio::test]
    async fn test_unlock_inside_delay_refused_at_once() {
        let storage = TestStorage::new("delayed");
        let daemon = storage.daemon().await;
        setup(&daemon).await;
        drop(daemon);

        let daemon = storage.daemon().await;
        // one wrong password away from the first delay (1 s)
        daemon.keys.write().await.unlock_failures = FREE_UNLOCK_ATTEMPTS - 1;
        assert_eq!(
            ask(&daemon, Request::Unlock(update(b"wrong password!"))).await,
            Err(DaemonError::WrongPassword)
        );
        assert_eq!(daemon.status().await.unlock_wait_secs, 1);

        // the Argon2 slot is taken: an unlock that tried to derive would hang
        let busy = daemon.derive_slot.clone().acquire_owned().await.unwrap();
        let answer = tokio::time::timeout(
            Duration::from_millis(500),
            ask(&daemon, Request::Unlock(update(DATA_PW))),
        )
        .await;
        assert_eq!(answer, Ok(Err(DaemonError::UnlockDelayed)));
        drop(busy);

        assert!(daemon.status().await.locked);
        assert_eq!(
            daemon.keys.read().await.unlock_failures,
            FREE_UNLOCK_ATTEMPTS
        );

        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert_eq!(daemon.status().await.unlock_wait_secs, 0);
        ask(&daemon, Request::Unlock(update(DATA_PW)))
            .await
            .unwrap();

        let status = daemon.status().await;
        assert!(!status.locked && status.unlock_wait_secs == 0);
        assert_eq!(daemon.keys.read().await.unlock_failures, 0);
    }

    /// Test that the longest delay (longer than the IPC deadline) is still
    /// answered well within the deadline, over a real socket
    #[tokio::test]
    async fn test_long_delay_answered_within_ipc_deadline() {
        let storage = TestStorage::new("longdelay");
        let daemon = storage.daemon().await;
        setup(&daemon).await;
        drop(daemon);

        let daemon = storage.daemon().await;
        // the next wrong password starts the longest delay
        daemon.keys.write().await.unlock_failures = FREE_UNLOCK_ATTEMPTS + 9;
        assert_eq!(
            ask(&daemon, Request::Unlock(update(b"wrong password!"))).await,
            Err(DaemonError::WrongPassword)
        );
        let wait = daemon.status().await.unlock_wait_secs;
        assert_eq!(u64::from(wait), MAX_UNLOCK_DELAY);
        assert!(Duration::from_secs(u64::from(wait)) > ipc_server::REQUEST_DEADLINE);

        let base = std::env::temp_dir().join(format!("cesa-daemon-ld-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        let path = prepare_socket_dir(&base).unwrap();
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

        let answer = tokio::time::timeout(
            Duration::from_secs(2),
            request_at(&path, &Request::Unlock(update(DATA_PW))),
        )
        .await;
        assert_eq!(
            answer,
            Ok(Err(IpcErrors::Daemon(DaemonError::UnlockDelayed)))
        );

        token.cancel();
    }

    /// Test that the minimum counts characters, not bytes (12 bytes of
    /// two-byte letters are only 6 characters)
    #[tokio::test]
    async fn test_min_length_counts_characters() {
        let daemon = Arc::new(Daemon::default());

        assert_eq!(
            ask(
                &daemon,
                Request::SetAuthPassword(update("ąęśćżź".as_bytes()))
            )
            .await,
            Err(DaemonError::WeakPassword)
        );
        ask(
            &daemon,
            Request::SetAuthPassword(update("zażółć gęślą".as_bytes())),
        )
        .await
        .unwrap();
    }

    /// Test that a stale automatic-login key is removed instead of kept
    #[tokio::test]
    async fn test_stale_auto_login_key_removed() {
        let storage = TestStorage::new("stale");
        let daemon = storage.daemon().await;
        setup(&daemon).await;
        drop(daemon);

        storage
            .store
            .items
            .lock()
            .await
            .insert(Item::DataKey, Zeroizing::new(vec![0x42; 32]));

        let daemon = storage.daemon().await;
        let status = daemon.status().await;
        assert!(status.locked && !status.auto_login);
        assert!(!storage.store.has(Item::DataKey).await);
    }

    /// Test that a change waiting for its turn holds no task: dropping the
    /// waiting request (IPC deadline) leaves nothing queued behind it
    #[tokio::test]
    async fn test_waiting_change_not_spawned() {
        let daemon = Arc::new(Daemon::default());
        let busy = daemon.change_slot.clone().acquire_owned().await.unwrap();

        let waiting = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            daemon.handle(Request::SetAuthPassword(update(AUTH_PW))),
        )
        .await;
        assert!(waiting.is_err());

        drop(busy);
        // the dropped request never ran
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(!daemon.status().await.auth_key_set);
    }

    /// The identity seed of an open vault.
    async fn identity_seed(daemon: &Daemon) -> [u8; IDENTITY_SEED_LEN] {
        **daemon
            .keys
            .read()
            .await
            .vault
            .as_ref()
            .map(|open| &open.identity)
            .unwrap()
    }

    /// Test that the device identity is made with the vault and is the same
    /// after a restart (no re-pairing), and differs between devices
    #[tokio::test]
    async fn test_identity_survives_restart() {
        let storage = TestStorage::new("identity");
        let daemon = storage.daemon().await;
        setup(&daemon).await;
        let before = identity_seed(&daemon).await;
        assert_ne!(before, [0u8; IDENTITY_SEED_LEN]);
        drop(daemon);

        let daemon = storage.daemon().await;
        ask(&daemon, Request::Unlock(update(DATA_PW)))
            .await
            .unwrap();
        assert_eq!(identity_seed(&daemon).await, before);

        // a re-save (password change) keeps it too
        ask(
            &daemon,
            Request::SetDataPassword(update(b"new data password")),
        )
        .await
        .unwrap();
        drop(daemon);
        let daemon = storage.daemon().await;
        ask(&daemon, Request::Unlock(update(b"new data password")))
            .await
            .unwrap();
        assert_eq!(identity_seed(&daemon).await, before);

        let other = TestStorage::new("identity-other");
        let other_daemon = other.daemon().await;
        setup(&other_daemon).await;
        assert_ne!(identity_seed(&other_daemon).await, before);
    }

    /// Test that trusted peers are saved in the vault and come back on unlock
    #[tokio::test]
    async fn test_peers_survive_restart() {
        let storage = TestStorage::new("peers");
        let daemon = storage.daemon().await;
        daemon
            .trusted_peers
            .write()
            .await
            .push(TrustedPeer::for_test(7, "phone"));
        setup(&daemon).await;
        drop(daemon);

        let daemon = storage.daemon().await;
        assert!(daemon.peers().await.is_empty());
        ask(&daemon, Request::Unlock(update(DATA_PW)))
            .await
            .unwrap();

        let peers = daemon.peers().await;
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].name, "phone");
        assert_eq!(peers[0].fingerprint, [7; 8]);

        // a re-save (password change) keeps them
        ask(
            &daemon,
            Request::SetAuthPassword(update(b"other auth password")),
        )
        .await
        .unwrap();
        drop(daemon);
        let daemon = storage.daemon().await;
        ask(&daemon, Request::Unlock(update(DATA_PW)))
            .await
            .unwrap();
        assert_eq!(daemon.peers().await.len(), 1);
    }

    /// Test that without storage nothing can be unlocked or auto-logged
    #[tokio::test]
    async fn test_ram_only() {
        let daemon = Arc::new(Daemon::default());
        setup(&daemon).await;

        assert!(!daemon.status().await.saved);
        assert_eq!(
            ask(&daemon, Request::Unlock(update(DATA_PW))).await,
            Err(DaemonError::NotSaved)
        );
        assert_eq!(
            ask(&daemon, Request::SetAutoLogin(true)).await,
            Err(DaemonError::NotSaved)
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

        request_at(&path, &Request::SetAuthPassword(update(AUTH_PW)))
            .await
            .unwrap();
        request_at(&path, &Request::SetDataPassword(update(DATA_PW)))
            .await
            .unwrap();

        let (key, a_salt, d_salt) = {
            let keys = daemon.keys.read().await;
            (
                **keys.a_key.as_ref().unwrap().expose(),
                *keys.a_salt.clone().unwrap(),
                *keys.d_salt.clone().unwrap(),
            )
        };

        // neither keys nor salts ever leave the daemon
        for request in [Request::Status, Request::ListPeers] {
            let body = daemon.handle(request).await;
            for secret in [key, a_salt, d_salt] {
                assert!(!body.windows(32).any(|w| w == secret));
            }
        }

        // a malformed password request changes nothing
        assert_eq!(
            request_at(&path, &Request::SetAuthPassword(update(b""))).await,
            Err(IpcErrors::Daemon(DaemonError::BadRequest))
        );

        token.cancel();
    }
}
