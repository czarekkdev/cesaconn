/*
TODO:
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
//!
//! Networking (off by default): with the Sync switch on and the vault open,
//! the daemon listens for paired devices. New devices are only paired from
//! the "Add device" window, and only after the user compared the pairing
//! code (`PendingPairing` / `AnswerPairing` over IPC).
//!
//! Clipboard sync (off by default, its own switch): while networking runs,
//! a new clipboard text goes to every paired device at its last address,
//! and updates from paired devices are applied (daemon.md 12). What the
//! connections show (an incorrect password, unreachable) is kept per device
//! for the UI (`peer_book`).

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::time::Duration;
use subtle::ConstantTimeEq;
use tokio::net::{TcpListener, TcpStream};
use tokio::select;
use tokio::sync::{Mutex, RwLock, Semaphore, mpsc};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{Instant, sleep, timeout};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use zeroize::Zeroizing;

use cesa_conn_crypto::{crand::random_array, pswd_manager::derive_key};
use cesa_conn_system::{
    clipboard::{ClipRead, Clipboard},
    ipc::{
        DaemonError, FINGERPRINT_LEN, JoinPasswords, MAX_LISTED_PEERS, MIN_NEW_PASSWORD_LEN,
        PairingPrompt, PasswordUpdate, PeerInfo, PeerState, Request, Response, Status, socket_path,
    },
    keychain::{Item, OsKeychain, SecretStore},
    pairing_code::PairingCode,
};

use crate::{
    auth_snow::{
        AuthKey, DataKey, DeviceKeypairs, HANDSHAKE_DEADLINE, IDENTITY_SEED_LEN, Keys,
        MAX_PENDING_PAIRINGS, Pairing, PairingInbox, PairingRequest, TIMEOUT, TrustedPeer,
        decode_peers, encode_peers,
    },
    clip_sync::{self, CLIP_MAX_LEN, DataAck},
    guess_limiter::GuessLimiter,
    ipc_server::{self, ClientPolicy},
    peer_book::PeerBook,
    salt_service::{SALT_PORT, query_salt, serve_salt},
    tcp_networker::{
        self, ActionType, ClipDelivery, HELLO_PAYLOAD, NetworkerContext, SaltOffer, TCP_PORT,
        TcpNetworkerErrors,
    },
    udp_networker::{
        InstanceId, MAX_BROADCAST_DURATION, is_own_address, udp_broadcast_presence,
        udp_find_broadcasters,
    },
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

/* settings: the vault's config entry */
/// config format version 1: `flags` only (read, never written any more)
const CONFIG_VERSION_1: u8 = 0x01;
/// config format version 2: `flags || peer addresses`
const CONFIG_VERSION: u8 = 0x02;
/// config flag: the Sync switch
const CONFIG_SYNC: u8 = 0b1;
/// config flag: the clipboard sync switch
const CONFIG_CLIPBOARD: u8 = 0b10;
/// every config flag this version knows
const CONFIG_FLAGS: u8 = CONFIG_SYNC | CONFIG_CLIPBOARD;

/// The paired devices' last addresses as saved (see [`PeerBook::decode`]).
type SavedAddrs = Vec<([u8; 32], SocketAddr)>;

/// The daemon's settings, saved in the vault. Every one is off by default.
#[derive(Clone, Copy, Default, PartialEq, Debug)]
struct Config {
    /// Networking on: listen for paired devices, allow "Add device".
    sync: bool,
    /// Clipboard sync on (works while networking runs).
    clipboard: bool,
}

impl Config {
    /// `version (1) || flags (1) || addresses` (the peer book's saved form).
    fn encode(self, addresses: &[u8]) -> Zeroizing<Vec<u8>> {
        let flags = if self.sync { CONFIG_SYNC } else { 0 }
            | if self.clipboard { CONFIG_CLIPBOARD } else { 0 };
        let mut out = Zeroizing::new(Vec::with_capacity(addresses.len().saturating_add(2)));
        out.push(CONFIG_VERSION);
        out.push(flags);
        out.extend_from_slice(addresses);
        out
    }

    /// Strict: an empty entry (vaults from before there were settings) is
    /// the defaults, version 1 is `version || Sync flag`, version 2 is
    /// `version || known flags || valid addresses`; anything else is `None`.
    fn decode(bytes: &[u8]) -> Option<(Self, SavedAddrs)> {
        match bytes {
            [] => Some((Self::default(), Vec::new())),
            [CONFIG_VERSION_1, flags] if flags & !CONFIG_SYNC == 0 => Some((
                Self {
                    sync: flags & CONFIG_SYNC != 0,
                    clipboard: false,
                },
                Vec::new(),
            )),
            [CONFIG_VERSION, flags, addresses @ ..] if flags & !CONFIG_FLAGS == 0 => Some((
                Self {
                    sync: flags & CONFIG_SYNC != 0,
                    clipboard: flags & CONFIG_CLIPBOARD != 0,
                },
                PeerBook::decode(addresses)?,
            )),
            _ => None,
        }
    }
}

/* networking */
/// How long "Add device" searches the LAN for other members (seconds).
const ADD_DEVICE_SEARCH: u64 = MAX_BROADCAST_DURATION;
/// How long "Add device" keeps the invite window open: this device is
/// announced, answers salt queries and asks about new devices (seconds).
const INVITE_WINDOW: u64 = 120;

/* joining */
/// Longest a join may run; its passwords are wiped after it (seconds).
const JOIN_WINDOW: u64 = 5 * 60;
/// Salt attempts per join: each one costs an Argon2 run, so a fake member
/// can't make the joiner derive keys endlessly.
const JOIN_MAX_ATTEMPTS: u32 = 5;
/// Most devices one invite window connects to (each costs a handshake).
const MAX_TRIED_PER_WINDOW: usize = 16;
/// Pause between join searches that found nobody to try (seconds); also
/// keeps the joiner within the members' salt-query rate limit.
const JOIN_RETRY_PAUSE: u64 = 5;
/// How long the bridge may take to save the peers at shutdown (seconds).
const SHUTDOWN_SAVE_TIMEOUT: u64 = 5;

/* clipboard sync */
/// How often the clipboard's change counter is read (milliseconds). A
/// change is sent once the counter stayed the same for one more poll, so
/// fast repeated copies send only the last one.
const CLIP_POLL_MS: u64 = 300;
/// Most received clipboard updates waiting for the daemon; more are
/// answered `Ignored` at once.
const CLIP_INBOX: usize = 8;
/// Longest one send to one device may take: the handshake, the data and
/// the answer (seconds).
const SEND_DEADLINE: u64 = HANDSHAKE_DEADLINE + 3 * TIMEOUT;

/// Networking while it runs; cancelling the token stops all of it.
struct Network {
    token: CancellationToken,
    /// What every connection shares: keys, identity, peers, pairing.
    context: NetworkerContext,
    /// The pairing bridge; it saves the peers once more when it stops.
    bridge: JoinHandle<()>,
}

impl Network {
    /// Running: not cancelled (Sync off, shutdown, or the listener failed).
    fn running(&self) -> bool {
        !self.token.is_cancelled()
    }
}

/// Pairings waiting for the user's answer over IPC.
#[derive(Default)]
struct PendingPairings {
    /// Id of the next request; ids only tell answers apart, they aren't secret.
    next_id: u32,
    waiting: Vec<(u32, PairingRequest)>,
}

impl PendingPairings {
    /// Drops the requests the handshake stopped waiting for (timeout, closed).
    fn prune(&mut self) {
        self.waiting.retain(|(_, request)| !request.is_expired());
    }
}

/// A running join: cancelling the token ends it and wipes its passwords
/// (they live only inside the join's task).
struct JoinSlot {
    /// Tells this join apart from a later one.
    generation: u64,
    token: CancellationToken,
}

/// An open invite window: cancelling `window` ends it; `offer` is the
/// `d_salt` offer it set.
struct InviteSlot {
    /// Tells this window apart from a later one.
    generation: u64,
    window: CancellationToken,
    offer: SaltOffer,
    /// What this window found, was given and connected to.
    addrs: Arc<WindowAddrs>,
}

/// The addresses of one invite window, each list at most
/// [`MAX_TRIED_PER_WINDOW`]. Kept apart: a device the LAN search found but
/// leaves to the other side (lower-id rule) may never be connected to by
/// it (the broadcast only went one way), and the user typing its address
/// must still make this side connect.
#[derive(Default)]
struct WindowAddrs {
    /// Found by the LAN search (each is checked once).
    searched: Tried,
    /// Typed by the user (each is waited for once).
    typed: Tried,
    /// Connected to by this side, found or typed: one connection per
    /// device and window.
    connected: Tried,
}

/// A list of addresses that each count once.
#[derive(Default)]
struct Tried(Mutex<Vec<IpAddr>>);

impl Tried {
    /// `true` (and remembered) if `ip` wasn't tried yet and there is room.
    async fn claim(&self, ip: IpAddr) -> bool {
        let mut tried = self.0.lock().await;
        if tried.contains(&ip) || tried.len() >= MAX_TRIED_PER_WINDOW {
            return false;
        }
        tried.push(ip);
        true
    }
}

/// Where a join looks for the member: its salt query and its listener.
#[derive(Clone, Copy, Debug)]
struct MemberAddrs {
    salt: SocketAddr,
    tcp: SocketAddr,
}

/// What a join attempt brought: everything a joined device keeps.
struct Joined {
    a_key: AuthKey,
    a_salt: Salt,
    d_key: DataKey,
    d_salt: Salt,
    peer: TrustedPeer,
    /// Where the member listens (its first saved address).
    addr: SocketAddr,
}

/// The open vault, kept so changes can be re-sealed without the password.
struct OpenVault {
    dek: Zeroizing<[u8; 32]>,
    wrapped: WrappedDek,
    storage_salt: Salt,
    config: Config,
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
/// Unlock attempts that run back to back; after this many wrong passwords
/// every further attempt has to wait.
const FREE_UNLOCK_ATTEMPTS: u32 = 5;
/// Longest time unlocks are refused after a wrong password (seconds).
const MAX_UNLOCK_DELAY: u64 = 60;

/// How long after the `failures`-th wrong password the next unlock attempt
/// is refused: not at all below [`FREE_UNLOCK_ATTEMPTS`] (those attempts run
/// back to back), then 1 s doubling up to [`MAX_UNLOCK_DELAY`]. On top of
/// Argon2's own cost, this slows a local process guessing through the IPC.
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
    /// The paired devices. The handle itself is replaced by a reset, so a
    /// handshake of the old network that finishes late pairs into the old,
    /// dropped list, never into the fresh device's.
    trusted_peers: RwLock<Arc<RwLock<Vec<TrustedPeer>>>>,
    /// Counts resets: a join that started before one never commits after it.
    resets: std::sync::atomic::AtomicU64,
    // one Argon2 run (64 MiB) at a time, so clients can't stack up memory
    derive_slot: Arc<Semaphore>,
    // one state change (set password / unlock / auto-login / sync) at a time, end to end
    change_slot: Arc<Semaphore>,
    storage: Option<Storage>,
    /// `Some` while networking runs.
    network: RwLock<Option<Network>>,
    /// New devices waiting for the user.
    pairings: RwLock<PendingPairings>,
    /// The "Add device" window is open: only then are new devices asked about.
    adding: AtomicBool,
    /// The open invite window, so the user can end it early.
    invite: RwLock<Option<InviteSlot>>,
    /// The open window found a device of another group (reset per window).
    other_group: Arc<AtomicBool>,
    /// Generation of the next invite window.
    next_invite: std::sync::atomic::AtomicU64,
    /// The running join, if any (its pairing is asked about too).
    join: RwLock<Option<JoinSlot>>,
    /// Generation of the next join.
    next_join: std::sync::atomic::AtomicU64,
    /// One guess limiter for the daemon's lifetime, so a Sync off / on
    /// doesn't forgive a guesser.
    guess_limiter: Arc<GuessLimiter>,
    /// Where the listener binds: every interface on [`TCP_PORT`] (tests: localhost).
    listen_addr: SocketAddr,
    /// Where the salt query binds during an invite window: every interface
    /// on [`SALT_PORT`] (tests: localhost).
    salt_addr: SocketAddr,
    /// Where the paired devices were last seen and what connecting showed.
    /// Cleared by a reset; entries of devices that aren't trusted any more
    /// are never listed, saved or connected to.
    peer_book: Arc<PeerBook>,
    /// The port paired devices listen on: [`TCP_PORT`] (tests: theirs).
    peer_port: AtomicU16,
    /// The port of the salt query on a device at a typed address:
    /// [`SALT_PORT`] (tests: theirs).
    peer_salt_port: AtomicU16,
    /// The OS clipboard, `None` where it isn't supported (and in tests
    /// that don't give one).
    clipboard: Option<Arc<dyn Clipboard>>,
    /// Tests only: the members a join tries instead of searching the LAN.
    #[cfg(test)]
    test_members: RwLock<Vec<MemberAddrs>>,
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
        // paired devices on the LAN must reach it; every connection is
        // authenticated (SPAKE2 + signatures) before anything is processed
        Self::with_addrs(
            storage,
            SocketAddr::from(([0, 0, 0, 0], TCP_PORT)),
            SocketAddr::from(([0, 0, 0, 0], SALT_PORT)),
        )
    }

    /// A daemon whose listener binds `listen_addr` and whose salt query
    /// (during an invite window) binds `salt_addr`.
    fn with_addrs(
        storage: Option<Storage>,
        listen_addr: SocketAddr,
        salt_addr: SocketAddr,
    ) -> Self {
        Self {
            keys: RwLock::default(),
            trusted_peers: RwLock::default(),
            resets: std::sync::atomic::AtomicU64::new(0),
            derive_slot: Arc::new(Semaphore::new(1)),
            change_slot: Arc::new(Semaphore::new(1)),
            storage,
            network: RwLock::default(),
            pairings: RwLock::default(),
            adding: AtomicBool::new(false),
            invite: RwLock::default(),
            other_group: Arc::default(),
            next_invite: std::sync::atomic::AtomicU64::new(0),
            join: RwLock::default(),
            next_join: std::sync::atomic::AtomicU64::new(0),
            guess_limiter: Arc::new(GuessLimiter::new()),
            listen_addr,
            salt_addr,
            peer_book: Arc::default(),
            peer_port: AtomicU16::new(TCP_PORT),
            peer_salt_port: AtomicU16::new(SALT_PORT),
            clipboard: None,
            #[cfg(test)]
            test_members: RwLock::default(),
        }
    }

    /// This daemon with the OS clipboard `clipboard` (clipboard sync).
    pub fn with_clipboard(mut self, clipboard: Option<Arc<dyn Clipboard>>) -> Self {
        self.clipboard = clipboard;
        self
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
            // quick and storage-free: never wait behind an Argon2 run, the
            // pairing timeout is running
            Request::PendingPairing => Response::Pairing(self.pending_pairing().await).encode(),
            Request::AnswerPairing { id, code, accept } => {
                match self.answer_pairing(id, &code, accept).await {
                    Ok(()) => Response::Done.encode(),
                    Err(e) => Response::encode_error(e),
                }
            }
            Request::AddDevice => match self.add_device(None).await {
                Ok(()) => Response::Done.encode(),
                Err(e) => Response::encode_error(e),
            },
            Request::AddDeviceAt(at) => match self.add_device(Some(at.ip())).await {
                Ok(()) => Response::Done.encode(),
                Err(e) => Response::encode_error(e),
            },
            // starts the join and returns: it runs (and waits for the user)
            // in its own task, taking the change slot only to commit
            Request::JoinGroup(passwords) => match self.join_group(passwords, None).await {
                Ok(()) => Response::Done.encode(),
                Err(e) => Response::encode_error(e),
            },
            Request::JoinGroupAt(at, passwords) => {
                match self.join_group(passwords, Some(at.ip())).await {
                    Ok(()) => Response::Done.encode(),
                    Err(e) => Response::encode_error(e),
                }
            }
            Request::CancelJoin => {
                self.cancel_join().await;
                Response::Done.encode()
            }
            Request::StopAddDevice => {
                self.stop_add_device().await;
                Response::Done.encode()
            }
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
    async fn change(self: &Arc<Self>, request: Request) -> Result<(), DaemonError> {
        let result = match request {
            Request::SetAuthPassword(update) => self.set_password(KeyKind::Auth, update).await,
            Request::SetDataPassword(update) => self.set_password(KeyKind::Data, update).await,
            Request::Unlock(update) => self.unlock(update).await,
            Request::SetAutoLogin(on) => self.set_auto_login(on).await,
            Request::SetSync(on) => self.set_sync(on).await,
            Request::SetClipboard(on) => self.set_clipboard(on).await,
            Request::ForgetPeer(fingerprint) => self.forget_peer(&fingerprint).await,
            Request::ResetDevice => self.reset_device().await,
            Request::Status
            | Request::ListPeers
            | Request::PendingPairing
            | Request::AnswerPairing { .. }
            | Request::AddDevice
            | Request::AddDeviceAt(_)
            | Request::JoinGroup(_)
            | Request::JoinGroupAt(..)
            | Request::CancelJoin
            | Request::StopAddDevice => Err(DaemonError::BadRequest),
        };

        // networking follows the state: keys, lock and the Sync switch
        self.apply_network().await;

        result
    }

    /// Looks for a saved vault: if there is one the daemon starts locked, and
    /// with automatic login it unlocks itself from the keychain (and starts
    /// networking if Sync is on).
    pub async fn start(self: &Arc<Self>) {
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
            Ok(()) => {
                info!("vault unlocked by automatic login");
                self.apply_network().await;
            }
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
        // one lock after the other, never two at once
        let status = {
            let keys = self.keys.read().await;
            Status {
                auth_key_set: keys.a_key.is_some(),
                data_key_set: keys.d_key.is_some(),
                locked: keys.locked,
                saved: keys.vault.is_some(),
                auto_login: keys.auto_login,
                unlock_wait_secs: wait_secs(keys.unlock_not_before, Instant::now()),
                sync_enabled: keys.vault.as_ref().is_some_and(|open| open.config.sync),
                clipboard_enabled: keys
                    .vault
                    .as_ref()
                    .is_some_and(|open| open.config.clipboard),
                clipboard_unavailable: self.clipboard.is_none(),
                ..Status::default()
            }
        };
        let trusted_peers = self.peer_list().await.read().await.len();
        let network_running = self
            .network
            .read()
            .await
            .as_ref()
            .is_some_and(Network::running);
        let pending_pairings = {
            let mut pairings = self.pairings.write().await;
            pairings.prune();
            pairings.waiting.len()
        };
        let joining = self.join_running().await;

        Status {
            trusted_peers: u32::try_from(trusted_peers).unwrap_or(u32::MAX),
            network_running,
            adding_device: network_running && self.adding.load(Ordering::SeqCst),
            other_group_nearby: network_running
                && self.adding.load(Ordering::SeqCst)
                && self.other_group.load(Ordering::SeqCst),
            pending_pairings: u8::try_from(pending_pairings).unwrap_or(u8::MAX),
            joining,
            ..status
        }
    }

    /// The current paired-devices list (the handle; see `trusted_peers`).
    async fn peer_list(&self) -> Arc<RwLock<Vec<TrustedPeer>>> {
        self.trusted_peers.read().await.clone()
    }

    async fn peers(&self) -> Vec<PeerInfo> {
        // copied first: the list and the book are never locked together
        let peers = self.trusted_copy().await;
        let mut listed = Vec::with_capacity(peers.len().min(MAX_LISTED_PEERS));
        for peer in peers.iter().take(MAX_LISTED_PEERS) {
            listed.push(PeerInfo {
                fingerprint: peer.fingerprint(),
                name: peer.name().to_owned(),
                state: self.peer_book.state(peer).await,
            });
        }
        listed
    }

    /// A copy of the paired devices (public keys and names only), so the
    /// list's lock isn't held while another one is taken.
    async fn trusted_copy(&self) -> Vec<TrustedPeer> {
        self.peer_list().await.read().await.clone()
    }

    /// The saved form of the paired devices' last addresses.
    async fn encoded_addresses(&self) -> Vec<u8> {
        let peers = self.trusted_copy().await;
        self.peer_book.encode(&peers).await
    }

    /// The clipboard sync switch is on (and the vault open).
    async fn clipboard_on(&self) -> bool {
        self.keys
            .read()
            .await
            .vault
            .as_ref()
            .is_some_and(|open| open.config.clipboard)
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
    async fn set_password(
        self: &Arc<Self>,
        kind: KeyKind,
        update: PasswordUpdate,
    ) -> Result<(), DaemonError> {
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

        // running connections use the new key from now on
        self.update_network_keys().await;

        // first time both keys exist: create the vault (and the group)
        if self.keys.read().await.vault.is_none() {
            self.create_vault(None, Config::default()).await;
        }

        Ok(())
    }

    /// The trusted peers, encoded for the vault. Read before the key lock is
    /// taken, so the two locks are never held together.
    async fn encoded_peers(&self) -> Result<Zeroizing<Vec<u8>>, DaemonError> {
        let list = self.peer_list().await;
        let peers = list.read().await;
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
        let addresses = self.encoded_addresses().await;

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
                config: open.config.encode(&addresses),
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

    /// Creates the vault once both keys are set, with this device's
    /// `identity` (a new one if `None`) and `config`. On failure the keys
    /// stay in RAM only (the status says `saved = false`) and nothing is
    /// half-written.
    async fn create_vault(
        &self,
        identity: Option<Zeroizing<[u8; IDENTITY_SEED_LEN]>>,
        config: Config,
    ) {
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
        let addresses = self.encoded_addresses().await;

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
                // the device identity is born with the vault (a joining
                // device made it for the join already)
                let identity = match identity {
                    Some(identity) => identity,
                    None => DeviceKeypairs::new_seed().map_err(|_| VaultErrors::Crypto)?,
                };
                let contents = VaultContents {
                    a_key: a_key.clone(),
                    a_salt: a_salt.clone(),
                    config: config.encode(&addresses),
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
                    // can't overflow: the delay is at most MAX_UNLOCK_DELAY and an
                    // Instant a minute from now always fits
                    let now = Instant::now();
                    keys.unlock_not_before = Some(now.checked_add(delay).unwrap_or(now));
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
        let (config, addresses) = Config::decode(&opened.contents.config).ok_or_else(|| {
            error!("saved settings are damaged");
            DaemonError::StorageFailed
        })?;

        *self.peer_list().await.write().await = peers;
        self.peer_book.load(addresses).await;

        let mut keys = self.keys.write().await;
        keys.a_key = Some(opened.contents.a_key);
        keys.a_salt = Some(opened.contents.a_salt);
        keys.d_key = Some(d_key);
        keys.d_salt = Some(salts.d_salt);
        keys.vault = Some(OpenVault {
            dek: opened.dek,
            wrapped: opened.wrapped,
            storage_salt: salts.storage_salt,
            config,
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

    /// Turns the Sync switch on or off: saved in the vault first, then
    /// networking follows ([`Daemon::apply_network`], run by `change`).
    async fn set_sync(&self, on: bool) -> Result<(), DaemonError> {
        let config = Config {
            sync: on,
            ..self.saved_config().await?
        };
        self.save_config(config).await?;

        if on {
            info!("sync on");
        } else {
            info!("sync off");
        }

        Ok(())
    }

    /// Turns clipboard sync on or off: saved in the vault first. It works
    /// while networking runs (Sync on); off, nothing is read or applied.
    async fn set_clipboard(&self, on: bool) -> Result<(), DaemonError> {
        if on && self.clipboard.is_none() {
            return Err(DaemonError::ClipboardUnavailable);
        }

        let config = Config {
            clipboard: on,
            ..self.saved_config().await?
        };
        self.save_config(config).await?;

        if on {
            info!("clipboard sync on");
        } else {
            info!("clipboard sync off");
        }

        Ok(())
    }

    /// The settings of the open vault: `Locked` / `NotSaved` without one (a
    /// setting must survive a restart: none without a vault).
    async fn saved_config(&self) -> Result<Config, DaemonError> {
        let keys = self.keys.read().await;
        if keys.locked {
            return Err(DaemonError::Locked);
        }
        keys.vault
            .as_ref()
            .map(|open| open.config)
            .ok_or(DaemonError::NotSaved)
    }

    /// Saves `config` (saved first, kept second: a failed save changes
    /// nothing). The caller holds the change slot.
    async fn save_config(&self, config: Config) -> Result<(), DaemonError> {
        self.reseal(Some(config)).await?;

        let mut keys = self.keys.write().await;
        if let Some(open) = keys.vault.as_mut() {
            open.config = config;
        }
        drop(keys);
        Ok(())
    }

    /// Removes the paired device(s) with this fingerprint from this device:
    /// from memory first (new handshakes treat it as unknown at once), then
    /// from the vault; a failed save puts them back and changes nothing.
    ///
    /// Local only: the device still knows the group passwords and this
    /// device, and may pair again through "Add device" if the user accepts.
    /// Keeping it out for good needs new group passwords (daemon.md 14.1).
    async fn forget_peer(&self, fingerprint: &[u8; FINGERPRINT_LEN]) -> Result<(), DaemonError> {
        {
            let keys = self.keys.read().await;
            if keys.locked {
                return Err(DaemonError::Locked);
            }
        }

        let list = self.peer_list().await;
        let is_it = |peer: &TrustedPeer| bool::from(peer.fingerprint().ct_eq(fingerprint));
        // every match: two keys with one 64-bit fingerprint are one device
        // in practice, and the user picked it by that fingerprint
        let removed: Vec<(usize, TrustedPeer)> = {
            let mut peers = list.write().await;
            let removed = peers
                .iter()
                .enumerate()
                .filter(|(_, peer)| is_it(peer))
                .map(|(index, peer)| (index, peer.clone()))
                .collect();
            peers.retain(|peer| !is_it(peer));
            drop(peers);
            removed
        };

        if removed.is_empty() {
            return Err(DaemonError::UnknownPeer);
        }

        // RAM only (no storage, nothing saved yet): nothing more to do
        if self.keys.read().await.vault.is_some()
            && let Err(e) = self.reseal(None).await
        {
            // saved first, kept second: put them back where they were
            let mut peers = list.write().await;
            for (index, peer) in removed {
                let at = index.min(peers.len());
                peers.insert(at, peer);
            }
            drop(peers);
            return Err(e);
        }

        for (_, peer) in &removed {
            self.peer_book.remove(peer).await;
        }

        info!(count = removed.len(), "forgot a paired device");
        Ok(())
    }

    /// Wipes this device back to fresh, as if CesaConn never ran: it leaves
    /// its group. Allowed while locked (the way out of a forgotten data
    /// password: the vault is lost anyway) and without any password: the
    /// same user can delete these files by hand, a reset reveals nothing.
    ///
    /// Order: networking, invite and join end first (nothing new pairs);
    /// the vault file goes next, the decisive step (no vault, no group:
    /// the keychain items mean nothing without it, the daemon starts fresh);
    /// then memory; the keychain items last. A failed vault delete changes
    /// nothing else; a failed keychain delete still leaves a fresh device
    /// and is reported, a second reset removes the leftovers.
    async fn reset_device(self: &Arc<Self>) -> Result<(), DaemonError> {
        // a join that started before never commits after this
        self.resets.fetch_add(1, Ordering::SeqCst);
        self.cancel_join().await;
        // the bridge finishes on its own (its save sees no vault)
        drop(self.stop_network().await);

        if let Some(storage) = &self.storage {
            let path = storage.path.clone();
            blocking(move || vault::delete_file(&path))
                .await?
                .map_err(storage_error)?;
        }

        // the keys are wiped (zeroized) with the old slots
        *self.keys.write().await = KeySlots::default();
        // a new list: a late handshake of the old network can't add to it
        *self.trusted_peers.write().await = Arc::default();
        self.peer_book.clear().await;
        self.pairings.write().await.waiting.clear();
        self.other_group.store(false, Ordering::SeqCst);
        warn!("this device was reset: keys, vault and paired devices are gone");

        if let Some(storage) = &self.storage {
            for item in [Item::Salts, Item::DataKey] {
                let store = storage.store.clone();
                match blocking(move || store.delete(item)).await {
                    Ok(Ok(())) => {}
                    _ => {
                        error!(
                            ?item,
                            "removing a keychain item failed: reset again to remove it"
                        );
                        return Err(DaemonError::StorageFailed);
                    }
                }
            }
        }

        Ok(())
    }

    /// Re-seals the open vault as it is, with `config` if given. The caller
    /// holds the change slot.
    async fn reseal(&self, config: Option<Config>) -> Result<(), DaemonError> {
        let Some(storage) = &self.storage else {
            return Err(DaemonError::NotSaved);
        };

        let peers = self.encoded_peers().await?;
        let addresses = self.encoded_addresses().await;

        let file = {
            let keys = self.keys.read().await;
            let (Some(open), Some(a_key), Some(a_salt)) = (&keys.vault, &keys.a_key, &keys.a_salt)
            else {
                return Err(DaemonError::NotSaved);
            };

            let contents = VaultContents {
                a_key: a_key.clone(),
                a_salt: a_salt.clone(),
                config: config.unwrap_or(open.config).encode(&addresses),
                identity: open.identity.clone(),
                peers,
            };
            let file = vault::seal(&open.wrapped, &open.dek, &contents);
            drop(keys);
            file.map_err(storage_error)?
        };

        let path = storage.path.clone();
        blocking(move || vault::write_file_atomic(&path, &file))
            .await?
            .map_err(storage_error)?;

        info!("vault saved");
        Ok(())
    }

    /// Writes the trusted peers to the vault after a pairing, as its own
    /// state change (waits for the change slot).
    async fn save_peers(&self) {
        let Ok(_turn) = self.change_slot.clone().acquire_owned().await else {
            return;
        };

        if self.keys.read().await.vault.is_none() {
            return;
        }

        if let Err(e) = self.reseal(None).await {
            error!(error = %e, "saving the trusted devices failed: they are kept in memory, the next change saves them");
        }
    }

    /// Starts or stops networking to match the state: it runs exactly while
    /// the vault is open with both keys and the Sync switch is on.
    async fn apply_network(self: &Arc<Self>) {
        let wanted = {
            let keys = self.keys.read().await;
            match &keys.vault {
                Some(open)
                    if open.config.sync
                        && !keys.locked
                        && keys.a_key.is_some()
                        && keys.d_key.is_some() =>
                {
                    Some(open.identity.clone())
                }
                _ => None,
            }
        };

        let running = self
            .network
            .read()
            .await
            .as_ref()
            .is_some_and(Network::running);

        match (wanted, running) {
            (Some(identity), false) => self.start_network(identity).await,
            // the bridge finishes on its own, nobody needs to wait here
            (None, true) => drop(self.stop_network().await),
            _ => {}
        }
    }

    /// Starts the TCP listener and the pairing bridge with this device's
    /// identity, the shared keys and trusted peers.
    async fn start_network(self: &Arc<Self>, identity: Zeroizing<[u8; IDENTITY_SEED_LEN]>) {
        // copies (zeroizing) under the guard, which is dropped right away
        let keys = {
            let keys = self.keys.read().await;
            match (&keys.a_key, &keys.a_salt, &keys.d_key) {
                (Some(a_key), Some(a_salt), Some(d_key)) => {
                    Keys::new(a_key.clone(), a_salt, d_key.clone())
                }
                _ => return,
            }
        };

        let listener = match TcpListener::bind(self.listen_addr).await {
            Ok(listener) => listener,
            Err(e) => {
                error!(error = %e, addr = %self.listen_addr, "failed to start the TCP listener: networking stays off");
                return;
            }
        };
        let local_addr = match listener.local_addr() {
            Ok(addr) => addr,
            Err(e) => {
                error!(error = %e, "failed to read the TCP listener's address: networking stays off");
                return;
            }
        };

        let (pairing, inbox) = Pairing::channel();
        let token = CancellationToken::new();
        let (clip_sender, clip_inbox) = mpsc::channel(CLIP_INBOX);
        let context = NetworkerContext {
            keys: Arc::new(RwLock::new(keys)),
            device_keypairs: Arc::new(DeviceKeypairs::from_seed(&identity)),
            trusted_peers: self.peer_list().await,
            pairing,
            guess_limiter: self.guess_limiter.clone(),
            // offered only while an invite window is open
            salt_offer: Arc::default(),
            peer_book: self.peer_book.clone(),
            peer_port: self.peer_port.load(Ordering::SeqCst),
            clipboard: Some(clip_sender),
        };
        drop(identity);

        listen(listener, context.clone(), token.clone());
        let bridge = tokio::spawn(self.clone().pairing_bridge(inbox, token.clone()));
        // without an OS clipboard the inbox is dropped: updates are `Ignored`
        if let Some(clipboard) = self.clipboard.clone() {
            tokio::spawn(self.clone().clipboard_task(
                clipboard,
                clip_inbox,
                context.clone(),
                token.clone(),
            ));
        }
        // the paired devices hear from us: a password that differs shows at once
        tokio::spawn(self.clone().hello_round(context.clone(), token.clone()));

        // check-then-act under one write guard; nothing is awaited while held
        let mut network = self.network.write().await;
        if network.as_ref().is_some_and(Network::running) {
            drop(network);
            // started twice (can't happen under the change slot): undo this one
            token.cancel();
            return;
        }
        *network = Some(Network {
            token,
            context,
            bridge,
        });
        // a new network has no "Add device" window, whatever the last one
        // had (a listener that failed on its own never closed its window)
        self.adding.store(false, Ordering::SeqCst);
        drop(network);

        info!(%local_addr, "networking on: listening for paired devices");
    }

    /// Stops networking; returns the bridge, which saves the peers once
    /// more and ends (awaited at shutdown only: it needs the change slot).
    async fn stop_network(&self) -> Option<JoinHandle<()>> {
        let network = self.network.write().await.take()?;

        network.token.cancel();
        // the invite window ends with networking (salt port, offer)
        self.end_invite(None).await;
        self.adding.store(false, Ordering::SeqCst);
        // dropped = rejected; the handshakes tell their peers
        self.pairings.write().await.waiting.clear();
        info!("networking off");

        Some(network.bridge)
    }

    /// Hands changed keys to the running connections.
    async fn update_network_keys(self: &Arc<Self>) {
        let keys = {
            let keys = self.keys.read().await;
            match (&keys.a_key, &keys.a_salt, &keys.d_key) {
                (Some(a_key), Some(a_salt), Some(d_key)) => {
                    Keys::new(a_key.clone(), a_salt, d_key.clone())
                }
                _ => return,
            }
        };

        // the networker's own lock, taken after the daemon's is released
        let running = self
            .network
            .read()
            .await
            .as_ref()
            .filter(|network| network.running())
            .map(|network| (network.context.clone(), network.token.clone()));

        // what the old keys showed no longer holds (and pauses end)
        self.peer_book.keys_changed().await;

        if let Some((context, token)) = running {
            *context.keys.write().await = keys;
            // the paired devices are asked again with the new keys at once
            tokio::spawn(self.clone().hello_round(context, token));
        }
    }

    /// Between the handshakes and the UI: queues pairing requests for the
    /// user and saves the peers after a pairing. Ends with networking.
    async fn pairing_bridge(self: Arc<Self>, mut inbox: PairingInbox, token: CancellationToken) {
        loop {
            select! {
                () = token.cancelled() => break,
                request = inbox.requests.recv() => match request {
                    Some(request) => self.queue_pairing(request).await,
                    None => break,
                },
                // its own task: the bridge keeps taking requests while the
                // save waits for the change slot
                () = inbox.saved.notified() => {
                    let daemon = self.clone();
                    tokio::spawn(async move { daemon.save_peers().await });
                }
                // a paired device moved: its new address is saved too
                () = self.peer_book.changed.notified() => {
                    let daemon = self.clone();
                    tokio::spawn(async move { daemon.save_peers().await });
                }
            }
        }

        // (waiting requests were dropped by stop_network: rejected)

        // a pairing that finished just as networking stopped is saved too
        self.save_peers().await;
    }

    /// Keeps `request` for the user, or rejects it: outside the
    /// "Add device" window or a join nobody asked to pair, and the queue is
    /// bounded.
    async fn queue_pairing(&self, request: PairingRequest) {
        if !self.adding.load(Ordering::SeqCst) && !self.join_running().await {
            warn!(name = %request.name, "pairing request outside \"Add device\", rejected");
            request.answer(false);
            return;
        }

        let mut pairings = self.pairings.write().await;
        pairings.prune();

        if pairings.waiting.len() >= MAX_PENDING_PAIRINGS {
            drop(pairings);
            warn!(name = %request.name, "too many pairings waiting, rejected");
            request.answer(false);
            return;
        }

        let id = pairings.next_id;
        pairings.next_id = id.wrapping_add(1);
        info!(id, name = %request.name, "new device wants to pair: waiting for the user");
        pairings.waiting.push((id, request));
    }

    /// The oldest pairing still waiting for the user.
    async fn pending_pairing(&self) -> Option<PairingPrompt> {
        let mut pairings = self.pairings.write().await;
        pairings.prune();

        pairings.waiting.first().map(|(id, request)| PairingPrompt {
            id: *id,
            name: request.name.clone(),
            code: request.code,
        })
    }

    /// The user's answer to pairing `id`. The answer names the code the
    /// user saw: ids start again after a restart, so an id alone could
    /// accept a pairing nobody compared.
    async fn answer_pairing(
        &self,
        id: u32,
        code: &PairingCode,
        accept: bool,
    ) -> Result<(), DaemonError> {
        let request = {
            let mut pairings = self.pairings.write().await;
            pairings.prune();
            let index = pairings
                .waiting
                .iter()
                .position(|(waiting, request)| *waiting == id && request.code == *code)
                .ok_or(DaemonError::PairingExpired)?;
            pairings.waiting.remove(index).1
        };

        info!(id, name = %request.name, accept, "pairing answered");
        request.answer(accept);
        Ok(())
    }

    /// Clipboard sync while networking runs: applies updates from paired
    /// devices (`inbox`) and sends this device's new clipboard text to them.
    ///
    /// The clipboard's change counter is polled every [`CLIP_POLL_MS`]; a
    /// change is sent once the counter held still for one more poll (fast
    /// repeated copies send the last one), and only while no earlier send
    /// round runs (the latest text goes when it ends). An update applied
    /// here moves the counter too: that counter is taken as seen, so it is
    /// never sent back. Content marked concealed / transient by a password
    /// manager is never read. Nothing is read or applied while the switch
    /// is off.
    async fn clipboard_task(
        self: Arc<Self>,
        clipboard: Arc<dyn Clipboard>,
        mut inbox: mpsc::Receiver<ClipDelivery>,
        context: NetworkerContext,
        token: CancellationToken,
    ) {
        // random per run: the receivers' ordering starts over with it
        let Ok(epoch) = random_array::<8>() else {
            error!("failed to generate a clipboard epoch: clipboard sync stays off");
            return;
        };
        let mut seq = 0u64;
        let mut ordering = clip_sync::UpdateOrder::default();
        // what is on the clipboard now was copied before: never sent
        let Some(start) = self.clip_count(&clipboard).await else {
            error!("the clipboard can't be read: clipboard sync stays off");
            return;
        };
        let mut watch = ClipWatch::new(start);
        let mut round: Option<JoinHandle<()>> = None;

        loop {
            select! {
                () = token.cancelled() => break,
                delivery = inbox.recv() => {
                    let Some(delivery) = delivery else { break };
                    let ack = self
                        .apply_clip(&clipboard, &mut ordering, &delivery, &mut watch)
                        .await;
                    // the connection may have given up waiting: nothing to do then
                    let _ = delivery.answer.send(ack);
                }
                () = sleep(Duration::from_millis(CLIP_POLL_MS)) => {
                    let on = self.clipboard_on().await;
                    // a failed read is no change (a made-up counter would be one)
                    let Some(count) = self.clip_count(&clipboard).await else {
                        continue;
                    };
                    let busy = round.as_ref().is_some_and(|round| !round.is_finished());
                    if watch.tick(on, count, busy) == ClipTick::Wait {
                        continue;
                    }

                    let Some(payload) = self.read_clip(&clipboard, &epoch, &mut seq).await else {
                        continue;
                    };
                    round = Some(tokio::spawn(self.clone().send_round(
                        context.clone(),
                        token.clone(),
                        ActionType::ClipboardSync,
                        payload,
                    )));
                }
            }
        }
    }

    /// The clipboard's change counter (read off the async workers); `None`
    /// if the read failed.
    async fn clip_count(&self, clipboard: &Arc<dyn Clipboard>) -> Option<i64> {
        let clipboard = clipboard.clone();
        blocking(move || clipboard.change_count()).await.ok()
    }

    /// Reads the clipboard text and encodes the next update; `None` for
    /// nothing to send (no text, concealed, too long).
    async fn read_clip(
        &self,
        clipboard: &Arc<dyn Clipboard>,
        epoch: &[u8; 8],
        seq: &mut u64,
    ) -> Option<Arc<Zeroizing<Vec<u8>>>> {
        let clipboard = clipboard.clone();
        let text = match blocking(move || clipboard.read_text(CLIP_MAX_LEN)).await {
            Ok(ClipRead::Text(text)) => text,
            Ok(ClipRead::Concealed) => {
                debug!("clipboard content marked concealed: not synced");
                return None;
            }
            Ok(ClipRead::TooLarge) => {
                info!(max = CLIP_MAX_LEN, "clipboard text too long: not synced");
                return None;
            }
            Ok(ClipRead::NoText) | Err(_) => return None,
        };

        *seq = seq.saturating_add(1);
        let payload = clip_sync::encode(epoch, *seq, &text)?;
        debug!(len = text.len(), seq = *seq, "clipboard changed: sending");
        Some(Arc::new(payload))
    }

    /// Applies an update from a paired device: only with the switch on,
    /// only a well-formed one, only newer than the last one from that
    /// device. The counter of our own write is taken as seen.
    async fn apply_clip(
        &self,
        clipboard: &Arc<dyn Clipboard>,
        ordering: &mut clip_sync::UpdateOrder,
        delivery: &ClipDelivery,
        watch: &mut ClipWatch,
    ) -> DataAck {
        if !self.clipboard_on().await {
            return DataAck::Ignored;
        }
        let Some(message) = clip_sync::decode(&delivery.payload) else {
            warn!(peer = %delivery.peer.name(), "malformed clipboard update, ignored");
            return DataAck::Ignored;
        };
        if !ordering.accept(delivery.peer.static_key(), &message.epoch, message.seq) {
            debug!(peer = %delivery.peer.name(), seq = message.seq, "older clipboard update, ignored");
            return DataAck::Ignored;
        }

        let (clipboard, text) = (clipboard.clone(), message.text);
        let len = text.len();
        match blocking(move || clipboard.write_text(&text)).await {
            Ok(Some(count)) => {
                watch.written(count);
                info!(peer = %delivery.peer.name(), len, seq = message.seq, "clipboard updated from a paired device");
                DataAck::Applied
            }
            _ => {
                warn!(peer = %delivery.peer.name(), "the OS refused the clipboard update");
                DataAck::Ignored
            }
        }
    }

    /// Sends `Hello` to every paired device at its last address.
    async fn hello_round(self: Arc<Self>, context: NetworkerContext, token: CancellationToken) {
        let payload = Arc::new(Zeroizing::new(HELLO_PAYLOAD.to_vec()));
        self.send_round(context, token, ActionType::Hello, payload)
            .await;
    }

    /// Sends `payload` to every paired device at its last address that
    /// isn't paused, all at once, each bounded by [`SEND_DEADLINE`]; ends
    /// when every send did, or with networking.
    async fn send_round(
        self: Arc<Self>,
        context: NetworkerContext,
        token: CancellationToken,
        action_type: ActionType,
        payload: Arc<Zeroizing<Vec<u8>>>,
    ) {
        let peers = self.trusted_copy().await;
        let targets = self.peer_book.targets(&peers).await;
        let mut sends = JoinSet::new();
        for (peer, addr) in targets {
            sends.spawn(send_to(
                context.clone(),
                peer,
                addr,
                action_type,
                payload.clone(),
            ));
        }

        select! {
            () = token.cancelled() => sends.abort_all(),
            () = async { while sends.join_next().await.is_some() {} } => {}
        }
    }

    /// Opens the "Add device" window for [`INVITE_WINDOW`] seconds: this
    /// device is announced on the LAN, answers salt queries (a new device
    /// joining, see [`crate::salt_service`]), hands `d_salt` to a device it
    /// pairs with just now, and asks the user about new devices. For the
    /// whole window it also searches (in [`ADD_DEVICE_SEARCH`] rounds) for
    /// other members with a window open and connects to them (re-pairing two
    /// devices that are both in the group already).
    ///
    /// `at`: a typed address (another network, a VPN) to connect to as
    /// well, also when the window is open already ([`connect_at`]).
    async fn add_device(self: &Arc<Self>, at: Option<IpAddr>) -> Result<(), DaemonError> {
        if at.is_some_and(is_own_address) {
            return Err(DaemonError::OwnAddress);
        }

        // already open: one window at a time, an address joins that one
        if let Some(invite) = self.open_invite().await? {
            self.run_invite(invite);
        }
        if let Some(ip) = at {
            self.connect_at_in_window(ip).await;
        }

        Ok(())
    }

    /// The LAN part of a window just opened, in its own task: announce,
    /// search and connect until the window ends, then close it.
    fn run_invite(self: &Arc<Self>, invite: Invite) {
        info!(seconds = INVITE_WINDOW, "add device: invite window open");

        let daemon = self.clone();
        tokio::spawn(async move {
            let Invite {
                context,
                token,
                id,
                window,
                generation,
                addrs,
            } = invite;

            select! {
                () = token.cancelled() => {},
                () = invite_window(context, id, window.clone(), daemon.other_group.clone(), addrs) => {},
            }
            // the salt goes away with the window, whatever ended it; a
            // window the user stopped (or a newer one) isn't touched here
            if daemon.end_invite(Some(generation)).await {
                info!("add device: invite window closed");
            }
        });
    }

    /// The invite part of [`Daemon::add_device`] without the LAN: marks the
    /// window open, offers `d_salt` to devices paired just now and starts
    /// the salt query (closed when `Invite::window` is cancelled, at the
    /// latest after [`INVITE_WINDOW`]). `None` if a window is open already.
    async fn open_invite(&self) -> Result<Option<Invite>, DaemonError> {
        let (context, token) = {
            let network = self.network.read().await;
            match network.as_ref() {
                Some(network) if network.running() => {
                    (network.context.clone(), network.token.clone())
                }
                _ => return Err(DaemonError::NetworkOff),
            }
        };

        // copies (zeroizing) under the guard, which is dropped right away
        let (a_salt, d_salt) = {
            let keys = self.keys.read().await;
            match (&keys.a_salt, &keys.d_salt) {
                (Some(a_salt), Some(d_salt)) => (a_salt.clone(), d_salt.clone()),
                _ => return Err(DaemonError::NetworkOff),
            }
        };

        let id = InstanceId::generate().map_err(|e| {
            error!(error = %e, "failed to generate a discovery id");
            DaemonError::Internal
        })?;

        if self.adding.swap(true, Ordering::SeqCst) {
            return Ok(None);
        }
        // a new window starts without the last one's findings
        self.other_group.store(false, Ordering::SeqCst);

        let window = CancellationToken::new();
        let generation = self.next_invite.fetch_add(1, Ordering::SeqCst);
        let addrs = Arc::new(WindowAddrs::default());
        *self.invite.write().await = Some(InviteSlot {
            generation,
            window: window.clone(),
            offer: context.salt_offer.clone(),
            addrs: addrs.clone(),
        });

        // the salt query exists only during the window: no port outside it
        match TcpListener::bind(self.salt_addr).await {
            Ok(listener) => {
                tokio::spawn(serve_salt(listener, a_salt, window.clone()));
            }
            Err(e) => {
                warn!(error = %e, addr = %self.salt_addr, "salt query unavailable: new devices can't join, members can still pair");
            }
        }

        *context.salt_offer.write().await = Some(d_salt);

        // the window's own end, whatever else runs in it
        let closing = window.clone();
        tokio::spawn(async move {
            select! {
                () = closing.cancelled() => {},
                () = sleep(Duration::from_secs(INVITE_WINDOW)) => closing.cancel(),
            }
        });

        Ok(Some(Invite {
            context,
            token,
            id,
            window,
            generation,
            addrs,
        }))
    }

    /// Where a device at a typed address listens: its salt query and its
    /// listener, on the fixed ports.
    fn member_at(&self, ip: IpAddr) -> MemberAddrs {
        MemberAddrs {
            salt: SocketAddr::new(ip, self.peer_salt_port.load(Ordering::SeqCst)),
            tcp: SocketAddr::new(ip, self.peer_port.load(Ordering::SeqCst)),
        }
    }

    /// The typed address of `AddDeviceAt` is connected to within the open
    /// window (just opened, or open already).
    async fn connect_at_in_window(self: &Arc<Self>, ip: IpAddr) {
        let slot = self
            .invite
            .read()
            .await
            .as_ref()
            .map(|slot| (slot.window.clone(), slot.addrs.clone()));
        let running = self
            .network
            .read()
            .await
            .as_ref()
            .filter(|network| network.running())
            .map(|network| (network.context.clone(), network.token.clone()));

        match (slot, running) {
            (Some((window, addrs)), Some((context, token))) => {
                self.spawn_connect_at(context, token, window, addrs, ip);
            }
            // the window ended (or networking stopped) right in between: the
            // user presses again
            _ => warn!(%ip, "add device: no open window to connect to the address from"),
        }
    }

    /// Runs [`connect_at`] for `ip` in its own task, until it is done or
    /// networking ends.
    fn spawn_connect_at(
        self: &Arc<Self>,
        context: NetworkerContext,
        token: CancellationToken,
        window: CancellationToken,
        addrs: Arc<WindowAddrs>,
        ip: IpAddr,
    ) {
        let (member, other_group) = (self.member_at(ip), self.other_group.clone());
        tokio::spawn(async move {
            select! {
                () = token.cancelled() => {},
                () = connect_at(context, member, window, addrs, other_group) => {},
            }
        });
    }

    /// Ends the invite window `generation` (`None`: whichever is open):
    /// announcing, searching and the salt query stop, `d_salt` is no longer
    /// offered, no new device is asked about. `false` if that window isn't
    /// open (ended already, or a newer one is open).
    async fn end_invite(&self, generation: Option<u64>) -> bool {
        let slot = {
            let mut invite = self.invite.write().await;
            let current = invite.as_ref().map(|slot| slot.generation);
            if generation.is_some_and(|wanted| current != Some(wanted)) {
                return false;
            }
            invite.take()
        };
        let Some(slot) = slot else {
            return false;
        };

        close_invite(&slot.window, &slot.offer).await;
        self.adding.store(false, Ordering::SeqCst);
        true
    }

    /// The user stops "Add device" before its 2 min are over. Pairings it
    /// was asking about are rejected (unless a join still asks about them).
    async fn stop_add_device(&self) {
        if self.end_invite(None).await {
            info!("add device: stopped by the user");
            if !self.join_running().await {
                self.pairings.write().await.waiting.clear();
            }
        }
    }

    /// Starts joining the group of a device whose user opened "Add
    /// device": only on a fresh device (no keys, no vault) that can save
    /// what it gets. The passwords move into the join's task and are wiped
    /// when it ends: success, [`JOIN_WINDOW`], [`JOIN_MAX_ATTEMPTS`],
    /// `CancelJoin` or shutdown.
    ///
    /// `at`: a typed address (another network, a VPN): the join goes through
    /// the device there instead of searching the LAN.
    async fn join_group(
        self: &Arc<Self>,
        passwords: JoinPasswords,
        at: Option<IpAddr>,
    ) -> Result<(), DaemonError> {
        // a joined device must survive a restart
        if self.storage.is_none() {
            return Err(DaemonError::NotSaved);
        }
        if at.is_some_and(is_own_address) {
            return Err(DaemonError::OwnAddress);
        }
        let at = at.map(|ip| self.member_at(ip));
        if !self.is_fresh().await {
            return Err(DaemonError::AlreadyInGroup);
        }
        // a reset from here on makes this join void
        let resets = self.resets.load(Ordering::SeqCst);

        // this device's identity, kept by the vault once the join commits
        let identity = DeviceKeypairs::new_seed().map_err(|e| {
            error!(error = %e, "failed to generate the device identity");
            DaemonError::Internal
        })?;

        let token = CancellationToken::new();
        let generation = self.next_join.fetch_add(1, Ordering::SeqCst);
        {
            // check-then-set under one write guard; nothing awaited inside
            let mut join = self.join.write().await;
            if join.as_ref().is_some_and(|slot| !slot.token.is_cancelled()) {
                return Err(DaemonError::JoinRunning);
            }
            *join = Some(JoinSlot {
                generation,
                token: token.clone(),
            });
            drop(join);
        }

        match at {
            Some(member) => {
                info!(addr = %member.tcp, "joining a group through the device at the address")
            }
            None => info!("joining a group: looking for a device with \"Add device\" open"),
        }

        let daemon = self.clone();
        tokio::spawn(async move {
            select! {
                () = token.cancelled() => info!("join cancelled"),
                result = timeout(
                    Duration::from_secs(JOIN_WINDOW),
                    daemon.run_join(passwords, identity, resets, at),
                ) => match result {
                    Ok(Ok(())) => info!("joined the group"),
                    Ok(Err(e)) => warn!(error = %e, "join failed"),
                    Err(_) => warn!("join timed out"),
                },
            }
            // (the passwords were dropped with the join future: wiped)
            daemon.end_join(generation).await;
        });

        Ok(())
    }

    /// No keys, no vault, nothing locked: a device that may join.
    async fn is_fresh(&self) -> bool {
        let keys = self.keys.read().await;
        !keys.locked
            && keys.vault.is_none()
            && keys.a_key.is_none()
            && keys.d_key.is_none()
            && keys.a_salt.is_none()
            && keys.d_salt.is_none()
    }

    /// Ends the running join (its passwords are wiped with its task).
    async fn cancel_join(&self) {
        let slot = self.join.write().await.take();
        if let Some(slot) = slot {
            slot.token.cancel();
            self.finish_join().await;
        }
    }

    /// Clears the join `generation` if it is still the current one.
    async fn end_join(&self, generation: u64) {
        {
            let mut join = self.join.write().await;
            if join
                .as_ref()
                .is_none_or(|slot| slot.generation != generation)
            {
                return;
            }
            *join = None;
        }
        self.finish_join().await;
    }

    /// A join runs: one whose slot is set and not cancelled. Read from the
    /// slot itself, so an old join ending can't switch off a newer one.
    async fn join_running(&self) -> bool {
        self.join
            .read()
            .await
            .as_ref()
            .is_some_and(|slot| !slot.token.is_cancelled())
    }

    /// No join any more: its waiting prompts are rejected (unless an
    /// "Add device" window or a new join still asks about devices).
    async fn finish_join(&self) {
        if !self.adding.load(Ordering::SeqCst) && !self.join_running().await {
            self.pairings.write().await.waiting.clear();
        }
    }

    /// The join itself: search for members (or take the one at `at`), try
    /// each until one succeeds or [`JOIN_MAX_ATTEMPTS`] salt attempts are
    /// used up. A device that gives no salt (its window isn't open yet)
    /// costs no attempt: it is asked again after [`JOIN_RETRY_PAUSE`].
    async fn run_join(
        self: &Arc<Self>,
        passwords: JoinPasswords,
        identity: Zeroizing<[u8; IDENTITY_SEED_LEN]>,
        resets: u64,
        at: Option<MemberAddrs>,
    ) -> Result<(), DaemonError> {
        let mut attempts = 0u32;

        while attempts < JOIN_MAX_ATTEMPTS {
            let members = match at {
                Some(member) => vec![member],
                None => self.find_members().await,
            };
            for member in members {
                if attempts >= JOIN_MAX_ATTEMPTS {
                    break;
                }
                let before = attempts;
                match self
                    .join_attempt(&passwords, &identity, member, &mut attempts)
                    .await
                {
                    Ok(joined) => {
                        // its own task: a timeout or CancelJoin from here on
                        // can't cut the commit half-way (keychain without vault)
                        let daemon = self.clone();
                        return tokio::spawn(async move {
                            daemon.commit_join(joined, identity, resets).await
                        })
                        .await
                        .map_err(|_| DaemonError::Internal)?;
                    }
                    // no salt there (its window isn't open yet): no attempt used,
                    // quiet, since a typed address is asked every few seconds
                    Err(e) if attempts == before => {
                        debug!(addr = %member.tcp, error = %e, "no join through the device yet");
                    }
                    Err(e) => warn!(addr = %member.tcp, error = %e, "join attempt failed"),
                }
            }

            sleep(Duration::from_secs(JOIN_RETRY_PAUSE)).await;
        }

        warn!(
            attempts = JOIN_MAX_ATTEMPTS,
            "join: every salt attempt used up without joining"
        );
        Err(DaemonError::NetworkOff)
    }

    /// Devices announcing an open "Add device" window on the LAN.
    async fn find_members(&self) -> Vec<MemberAddrs> {
        #[cfg(test)]
        {
            let members = self.test_members.read().await.clone();
            if !members.is_empty() {
                return members;
            }
        }

        let Ok(own) = InstanceId::generate() else {
            return Vec::new();
        };

        match udp_find_broadcasters(ADD_DEVICE_SEARCH, own).await {
            // only the IP comes from discovery (an unauthenticated hint)
            Ok(found) => found
                .into_iter()
                .map(|(addr, _)| MemberAddrs {
                    salt: SocketAddr::new(addr.ip(), SALT_PORT),
                    tcp: SocketAddr::new(addr.ip(), TCP_PORT),
                })
                .collect(),
            Err(e) => {
                warn!(error = %e, "searching for a device to join failed");
                Vec::new()
            }
        }
    }

    /// One try with one member:
    /// 1. the salt query: `a_salt` (unauthenticated, see `salt_service`);
    /// 2. a candidate `a_key` from pw1 and that salt (counts as an attempt);
    /// 3. the handshake, the user pairs the devices, `d_salt` comes over
    ///    that same connection ([`tcp_networker::join_handler`]);
    /// 4. `d_key` from pw2 and `d_salt`.
    ///
    /// A fake salt fails in step 3: it is bound into SPAKE2.
    async fn join_attempt(
        self: &Arc<Self>,
        passwords: &JoinPasswords,
        identity: &Zeroizing<[u8; IDENTITY_SEED_LEN]>,
        member: MemberAddrs,
        attempts: &mut u32,
    ) -> Result<Joined, DaemonError> {
        // 1. the salt
        let a_salt = query_salt(member.salt).await.map_err(|e| {
            debug!(addr = %member.salt, error = %e, "no salt from the device");
            DaemonError::NetworkOff
        })?;

        // 2. the candidate auth key
        *attempts = attempts.saturating_add(1);
        let a_key = AuthKey::new(
            self.derive(
                PasswordUpdate {
                    password: passwords.auth.password.clone(),
                },
                a_salt.clone(),
            )
            .await?,
        );

        // 3. handshake, pairing, d_salt; d_key isn't known yet and the
        // GroupSalt exchange doesn't use it: a random one that opens nothing
        let unused_d_key = random_array::<32>().map_err(|_| DaemonError::Internal)?;
        let (pairing, inbox) = Pairing::channel();
        let context = NetworkerContext {
            keys: Arc::new(RwLock::new(Keys::new(
                a_key.clone(),
                &a_salt,
                DataKey::new(unused_d_key),
            ))),
            device_keypairs: Arc::new(DeviceKeypairs::from_seed(identity)),
            // nobody is trusted yet: the member must be paired just now
            trusted_peers: Arc::default(),
            pairing,
            guess_limiter: self.guess_limiter.clone(),
            salt_offer: Arc::default(),
            // the join's own: the commit keeps the member's address
            peer_book: Arc::default(),
            peer_port: self.peer_port.load(Ordering::SeqCst),
            clipboard: None,
        };
        // ends when the context (and with it the pairing sender) is dropped
        tokio::spawn(self.clone().join_bridge(inbox));

        let stream = timeout(Duration::from_secs(TIMEOUT), TcpStream::connect(member.tcp))
            .await
            .map_err(|_| DaemonError::NetworkOff)?
            .map_err(|_| DaemonError::NetworkOff)?;

        // a full handshake: boxed, so the future isn't kept on the stack
        let (peer, d_salt) = Box::pin(tcp_networker::join_handler(context, member.tcp, stream))
            .await
            .map_err(|e| {
                debug!(addr = %member.tcp, error = %e, "joining through the device failed");
                DaemonError::NetworkOff
            })?;

        // 4. the data key
        let d_key = DataKey::new(
            self.derive(
                PasswordUpdate {
                    password: passwords.data.password.clone(),
                },
                d_salt.clone(),
            )
            .await?,
        );

        Ok(Joined {
            a_key,
            a_salt,
            d_key,
            d_salt,
            peer,
            addr: member.tcp,
        })
    }

    /// Hands the join's pairing requests to the user (no saving: the commit
    /// saves everything at once).
    async fn join_bridge(self: Arc<Self>, mut inbox: PairingInbox) {
        // ends when the join attempt drops its context (the sender): the
        // attempt itself is bounded by the handshake deadline, the pairing
        // timeout and JOIN_WINDOW; an in-process channel, not the network
        // nosemgrep: cesa.net.read-without-timeout
        while let Some(request) = inbox.requests.recv().await {
            self.queue_pairing(request).await;
        }
    }

    /// Keeps what the join brought: keys, salts, the member as a trusted
    /// peer, a new vault with Sync on (joining means syncing), networking.
    async fn commit_join(
        self: &Arc<Self>,
        joined: Joined,
        identity: Zeroizing<[u8; IDENTITY_SEED_LEN]>,
        resets: u64,
    ) -> Result<(), DaemonError> {
        let turn = self
            .change_slot
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| DaemonError::Internal)?;

        // the user reset this device meanwhile: the join belongs to before
        if self.resets.load(Ordering::SeqCst) != resets {
            warn!("a join from before the reset finished: dropped, nothing kept");
            return Err(DaemonError::Internal);
        }
        // the state may have changed while the user was pairing
        if !self.is_fresh().await {
            return Err(DaemonError::AlreadyInGroup);
        }

        {
            let mut keys = self.keys.write().await;
            keys.a_key = Some(joined.a_key);
            keys.a_salt = Some(joined.a_salt);
            keys.d_key = Some(joined.d_key);
            keys.d_salt = Some(joined.d_salt);
        }
        self.peer_book.seen(&joined.peer, joined.addr).await;
        self.peer_list().await.write().await.push(joined.peer);

        // clipboard stays off: every feature is off until the user turns it on
        self.create_vault(
            Some(identity),
            Config {
                sync: true,
                clipboard: false,
            },
        )
        .await;
        let saved = self.keys.read().await.vault.is_some();

        drop(turn);
        self.apply_network().await;

        if saved {
            Ok(())
        } else {
            // the keys stay in RAM, like a first device whose save failed
            Err(DaemonError::StorageFailed)
        }
    }
}

/// What one clipboard poll decided.
#[derive(Debug, PartialEq)]
enum ClipTick {
    /// Nothing to send now.
    Wait,
    /// Read the clipboard and send it.
    Send,
}

/// The clipboard task's view of the clipboard's change counter (12.3).
struct ClipWatch {
    /// The counter last seen (or written by us).
    last_count: i64,
    /// A change made while the switch was on waits to be sent.
    pending: bool,
}

impl ClipWatch {
    fn new(count: i64) -> Self {
        Self {
            last_count: count,
            pending: false,
        }
    }

    /// One poll: `count` is the counter now, `on` the switch, `busy` a send
    /// round still running. A change is sent once the counter held still
    /// for one more poll and no round runs; a change made while the switch
    /// is off, or the switch going off before it was sent, is never sent.
    fn tick(&mut self, on: bool, count: i64, busy: bool) -> ClipTick {
        if count != self.last_count {
            self.last_count = count;
            self.pending = on;
            return ClipTick::Wait;
        }
        if !on {
            self.pending = false;
            return ClipTick::Wait;
        }
        if !self.pending || busy {
            return ClipTick::Wait;
        }
        self.pending = false;
        ClipTick::Send
    }

    /// We wrote `count` (an update from a paired device): taken as seen,
    /// so it is never sent back.
    fn written(&mut self, count: i64) {
        self.last_count = count;
    }
}

/// Ends an invite window: the salt query stops and `d_salt` is no longer
/// offered to anyone.
async fn close_invite(window: &CancellationToken, offer: &SaltOffer) {
    window.cancel();
    *offer.write().await = None;
}

/// An open invite window ([`Daemon::open_invite`]).
struct Invite {
    context: NetworkerContext,
    /// The network's token: the window ends with networking.
    token: CancellationToken,
    /// This window's discovery id.
    id: InstanceId,
    /// Cancelled when the window ends; stops the salt query.
    window: CancellationToken,
    /// This window's generation (see [`Daemon::end_invite`]).
    generation: u64,
    /// The addresses this window works with (see [`WindowAddrs`]).
    addrs: Arc<WindowAddrs>,
}

/// Runs the accept loop in its own task until the token is cancelled. If
/// it fails on its own, it cancels the token, so all of networking stops.
fn listen(listener: TcpListener, context: NetworkerContext, token: CancellationToken) {
    tokio::spawn(async move {
        // the accept loop runs until the token is cancelled; every
        // connection in it has its own timeouts and handshake deadline
        // nosemgrep: cesa.net.read-without-timeout
        let result = tcp_networker::recv(&listener, context, token.clone()).await;

        if let Err(e) = result {
            error!(error = %e, "TCP listener stopped: networking off");
            token.cancel();
        }
    });
}

/// The LAN part of the invite window ([`Daemon::add_device`]): announce
/// this device until `window` ends, and meanwhile search for other members
/// and connect to every one found; waits for those connections.
async fn invite_window(
    context: NetworkerContext,
    id: InstanceId,
    window: CancellationToken,
    other_group: Arc<AtomicBool>,
    addrs: Arc<WindowAddrs>,
) {
    tokio::join!(
        announce_until(id, window.clone()),
        search_and_connect(context, id, window.clone(), other_group, addrs),
    );
}

/// "Add device" with a typed address (a device on another network, e.g.
/// behind a VPN, that discovery can't reach): asks the device there for
/// its group salt every [`JOIN_RETRY_PAUSE`] until its own window is open
/// (the salt query only exists then), then connects once. A device of
/// another group is reported instead (as in [`on_found`]). Unlike a found
/// device it doesn't wait for the other side to connect: the user named
/// it, and the other side may not see this one at all.
async fn connect_at(
    context: NetworkerContext,
    member: MemberAddrs,
    window: CancellationToken,
    addrs: Arc<WindowAddrs>,
    other_group: Arc<AtomicBool>,
) {
    if !addrs.typed.claim(member.tcp.ip()).await {
        debug!(addr = %member.tcp, "add device: that address is waited for in this window already");
        return;
    }
    let own_a_salt = context.keys.read().await.a_salt.clone();
    info!(addr = %member.tcp, "add device: waiting for the device at the address to open Add device");

    loop {
        let check = select! {
            () = window.cancelled() => return,
            check = check_group(&own_a_salt, member.salt) => check,
        };
        match check {
            GroupCheck::Same => {
                if addrs.connected.claim(member.tcp.ip()).await {
                    // a full handshake: boxed, so the future isn't kept on the stack
                    let _ = Box::pin(connect_to(context, member.tcp)).await;
                } else {
                    debug!(addr = %member.tcp, "add device: connected to that device in this window already");
                }
                return;
            }
            GroupCheck::Different => {
                warn!(addr = %member.tcp, "the device at the address is in a different group (other salts): not connecting; to add it, reset it and use Join on it");
                other_group.store(true, Ordering::SeqCst);
                return;
            }
            GroupCheck::Unknown => {
                debug!(addr = %member.tcp, "no Add device window at the address yet");
                select! {
                    () = window.cancelled() => return,
                    () = sleep(Duration::from_secs(JOIN_RETRY_PAUSE)) => {},
                }
            }
        }
    }
}

/// What a found device's salt says about its group.
#[derive(Debug, PartialEq)]
enum GroupCheck {
    /// Same `a_salt`: a device of this group.
    Same,
    /// Another `a_salt`: a device of another group. SPAKE2 would fail for
    /// sure (the salt is bound into it), so connecting only costs both
    /// sides a guess-limiter slot.
    Different,
    /// No answer (no salt query there, rate limited, an older build).
    Unknown,
}

/// What the invite window does with one device it found.
#[derive(Debug, PartialEq)]
enum Found {
    /// This side connects (lower id).
    Connect,
    /// The other side connects (it has the lower id).
    TheyConnect,
    /// Another group: nobody connects, the user is told.
    OtherGroup,
}

/// Decides about a device found during "Add device": a device of another
/// group is reported (`other_group`) instead of a doomed handshake, on both
/// sides whichever would connect; otherwise only the lower id connects, so
/// a pair makes one connection (and one prompt each), not two.
async fn on_found(
    own_a_salt: &[u8; 32],
    salt_addr: SocketAddr,
    id: InstanceId,
    their_id: InstanceId,
    other_group: &AtomicBool,
) -> Found {
    if check_group(own_a_salt, salt_addr).await == GroupCheck::Different {
        warn!(%salt_addr, "found a device of a different group (other salts): not connecting; to add it, reset it and use Join on it");
        other_group.store(true, Ordering::SeqCst);
        return Found::OtherGroup;
    }

    if id < their_id {
        Found::Connect
    } else {
        Found::TheyConnect
    }
}

/// Asks the device at `salt_addr` for its group salt and compares it with
/// `own_a_salt`. Unauthenticated, like every salt answer: a forged answer
/// can at most make this device skip a real member (a DoS, like forged
/// announcements), never pair with the wrong one.
async fn check_group(own_a_salt: &[u8; 32], salt_addr: SocketAddr) -> GroupCheck {
    match query_salt(salt_addr).await {
        Ok(theirs) if bool::from(theirs.as_slice().ct_eq(own_a_salt.as_slice())) => {
            GroupCheck::Same
        }
        Ok(_) => GroupCheck::Different,
        Err(_) => GroupCheck::Unknown,
    }
}

/// Announces this device in [`MAX_BROADCAST_DURATION`] rounds until `window`
/// is cancelled.
async fn announce_until(id: InstanceId, window: CancellationToken) {
    while !window.is_cancelled() {
        select! {
            () = window.cancelled() => break,
            announced = udp_broadcast_presence(MAX_BROADCAST_DURATION, id) => {
                if let Err(e) = announced {
                    warn!(error = %e, "announcing this device failed");
                    // no busy loop on a failing socket
                    select! {
                        () = window.cancelled() => break,
                        () = sleep(Duration::from_secs(JOIN_RETRY_PAUSE)) => {},
                    }
                }
            },
        }
    }
}

/// Searches in [`ADD_DEVICE_SEARCH`] rounds until `window` ends for other
/// members with the window open, connects once to every new one this side
/// should connect to, then waits for those connections. Searching the whole
/// window (not only its start) matters: the two users rarely press "Add
/// device" at the same moment, and only the lower id connects.
async fn search_and_connect(
    context: NetworkerContext,
    id: InstanceId,
    window: CancellationToken,
    other_group: Arc<AtomicBool>,
    addrs: Arc<WindowAddrs>,
) {
    let own_a_salt = context.keys.read().await.a_salt.clone();
    let mut connects = JoinSet::new();

    while !window.is_cancelled() {
        let found = select! {
            () = window.cancelled() => break,
            found = udp_find_broadcasters(ADD_DEVICE_SEARCH, id) => found,
        };
        let found = match found {
            Ok(found) => found,
            Err(e) => {
                warn!(error = %e, "searching for devices failed");
                // no busy loop on a failing socket
                select! {
                    () = window.cancelled() => break,
                    () = sleep(Duration::from_secs(JOIN_RETRY_PAUSE)) => {},
                }
                continue;
            }
        };

        for (addr, their_id) in found {
            // each found device is checked once per window
            if !addrs.searched.claim(addr.ip()).await {
                continue;
            }

            // its own task: a device that doesn't answer the group check
            // (up to the timeouts) never holds up the search or the others
            let (context, own_a_salt, other_group, addrs) = (
                context.clone(),
                own_a_salt.clone(),
                other_group.clone(),
                addrs.clone(),
            );
            connects.spawn(async move {
                // only the IP comes from discovery (an unauthenticated hint)
                let salt_addr = SocketAddr::new(addr.ip(), SALT_PORT);
                match on_found(&own_a_salt, salt_addr, id, their_id, &other_group).await {
                    // one connection per device and window (typed ones included)
                    Found::Connect if addrs.connected.claim(addr.ip()).await => {
                        // a full handshake: boxed, so the future isn't kept on the stack
                        Box::pin(connect_to(context, SocketAddr::new(addr.ip(), TCP_PORT))).await
                    }
                    Found::Connect => {
                        debug!(%addr, "connected to that device in this window already");
                        Ok(())
                    }
                    Found::TheyConnect => {
                        debug!(%addr, "found device connects to us");
                        Ok(())
                    }
                    Found::OtherGroup => Ok(()),
                }
            });
        }
    }

    while connects.join_next().await.is_some() {}
}

/// One outgoing `ConnectNewDevice` connection: authenticates, and pairs if
/// the two devices don't know each other yet (the user is asked).
async fn connect_to(context: NetworkerContext, addr: SocketAddr) -> Result<(), TcpNetworkerErrors> {
    let stream = timeout(Duration::from_secs(TIMEOUT), TcpStream::connect(addr))
        .await
        .map_err(|_| TcpNetworkerErrors::FailedToConnect)?
        .map_err(|_| TcpNetworkerErrors::FailedToConnect)?;

    // a full handshake: boxed, so the future isn't kept on the stack
    let result = Box::pin(tcp_networker::connect_handler(
        context,
        addr,
        stream,
        ActionType::ConnectNewDevice,
        Zeroizing::new(Vec::new()),
    ))
    .await;

    match &result {
        Ok(()) => info!(%addr, "connected to the device"),
        Err(e) => warn!(%addr, error = %e, "connecting to the device failed"),
    }

    result
}

/// One `Hello` or clipboard update to one paired device at `addr`: a
/// device that doesn't answer is shown as unreachable; a password that
/// differs is marked by the networker (`send_answered`).
async fn send_to(
    context: NetworkerContext,
    peer: TrustedPeer,
    addr: SocketAddr,
    action_type: ActionType,
    payload: Arc<Zeroizing<Vec<u8>>>,
) {
    let peer_book = context.peer_book.clone();
    let stream = match timeout(Duration::from_secs(TIMEOUT), TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => stream,
        _ => {
            debug!(%addr, peer = %peer.name(), "paired device not reachable");
            peer_book.set_state(&peer, PeerState::Unreachable).await;
            return;
        }
    };

    // a full handshake: boxed, so the future isn't kept on the stack
    let sent = timeout(
        Duration::from_secs(SEND_DEADLINE),
        Box::pin(tcp_networker::send_answered(
            context,
            addr,
            stream,
            action_type,
            &payload,
        )),
    )
    .await;

    match sent {
        Ok(Ok((answered, ack))) => {
            debug!(%addr, peer = %answered.name(), action_type = ?action_type, ack = ?ack, "sent to a paired device");
        }
        Ok(Err(TcpNetworkerErrors::WrongPassword)) => {
            warn!(%addr, peer = %peer.name(), "the paired device uses a different auth password");
        }
        Ok(Err(e)) => {
            warn!(%addr, peer = %peer.name(), error = %e, "sending to a paired device failed")
        }
        Err(_) => warn!(%addr, peer = %peer.name(), "sending to a paired device timed out"),
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

    let clipboard = cesa_conn_system::clipboard::platform_clipboard();
    if clipboard.is_none() {
        warn!("no clipboard support on this platform yet: clipboard sync stays off");
    }
    let daemon = Arc::new(Daemon::new(platform_storage()).with_clipboard(clipboard));
    daemon.start().await;

    let token = CancellationToken::new();
    let handler_daemon = daemon.clone();
    let handler = move |request: Request| {
        let daemon = handler_daemon.clone();
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

    // networking off; the bridge saves a pairing that just finished
    if let Some(bridge) = daemon.stop_network().await
        && timeout(Duration::from_secs(SHUTDOWN_SAVE_TIMEOUT), bridge)
            .await
            .is_err()
    {
        warn!("saving the trusted devices at shutdown timed out");
    }

    // best effort: a stale socket is replaced on the next start anyway
    if std::fs::remove_file(&path).is_err() {
        warn!(path = %path.display(), "failed to remove the IPC socket");
    }
}

#[cfg(test)]
#[allow(clippy::large_futures)] // full handshakes in tests, stack size doesn't matter
mod tests {
    use super::*;
    use crate::auth_snow::HANDSHAKE_DEADLINE;
    use cesa_conn_system::ipc::{DeviceAddress, IpcErrors, prepare_socket_dir, request_at};
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
                    0x0A => DaemonError::NetworkOff,
                    0x0B => DaemonError::PairingExpired,
                    0x0C => DaemonError::AlreadyInGroup,
                    0x0D => DaemonError::JoinRunning,
                    0x0E => DaemonError::UnknownPeer,
                    0x0F => DaemonError::ClipboardUnavailable,
                    0x10 => DaemonError::OwnAddress,
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
        // no clipboard given: the daemon says so, it doesn't pretend
        assert_eq!(
            Daemon::default().status().await,
            Status {
                clipboard_unavailable: true,
                ..Status::default()
            }
        );
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
        assert_eq!(
            daemon.status().await,
            Status {
                clipboard_unavailable: true,
                ..Status::default()
            }
        );
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
        let _ = std::fs::remove_dir_all(&base);
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
            .peer_list()
            .await
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

    // ── networking and pairing ───────────────────────────────────────────

    impl TestStorage {
        /// A (re)started daemon whose listener binds a free localhost port.
        async fn daemon_on_localhost(&self) -> Arc<Daemon> {
            self.daemon_with_clipboard(None).await
        }

        /// Like [`TestStorage::daemon_on_localhost`], with a clipboard.
        async fn daemon_with_clipboard(
            &self,
            clipboard: Option<Arc<dyn Clipboard>>,
        ) -> Arc<Daemon> {
            let daemon = Arc::new(
                Daemon::with_addrs(
                    Some(Storage {
                        store: self.store.clone(),
                        path: self.path(),
                    }),
                    free_local_addr(),
                    free_local_addr(),
                )
                .with_clipboard(clipboard),
            );
            // port 1 on localhost: nothing listens, so hellos to a saved
            // address fail at once instead of reaching a real daemon on
            // TCP_PORT (tests that need it set the other daemon's port)
            daemon.peer_port.store(1, Ordering::SeqCst);
            daemon.start().await;
            daemon
        }
    }

    /// A free localhost port: bound, read, released (the daemon binds it again).
    fn free_local_addr() -> SocketAddr {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    /// The shared context of a running network.
    async fn context(daemon: &Daemon) -> NetworkerContext {
        daemon
            .network
            .read()
            .await
            .as_ref()
            .expect("networking isn't running")
            .context
            .clone()
    }

    /// Two devices of one group: the second one gets the first one's salts
    /// before its passwords are set (test only: real devices will get them
    /// from salt sync), so both derive the same keys.
    async fn group_of_two(a: &TestStorage, b: &TestStorage) -> (Arc<Daemon>, Arc<Daemon>) {
        group_of_two_with(a, b, None, None).await
    }

    /// [`group_of_two`] with a clipboard for each.
    async fn group_of_two_with(
        a: &TestStorage,
        b: &TestStorage,
        clipboard_a: Option<Arc<dyn Clipboard>>,
        clipboard_b: Option<Arc<dyn Clipboard>>,
    ) -> (Arc<Daemon>, Arc<Daemon>) {
        let first = a.daemon_with_clipboard(clipboard_a).await;
        setup(&first).await;

        let second = b.daemon_with_clipboard(clipboard_b).await;
        let (a_salt, d_salt) = {
            let salts = first.keys.read().await;
            (salts.a_salt.clone(), salts.d_salt.clone())
        };
        {
            let mut keys = second.keys.write().await;
            keys.a_salt = a_salt;
            keys.d_salt = d_salt;
        }
        setup(&second).await;
        assert_eq!(key_bytes(&first).await, key_bytes(&second).await);
        // each one finds the other where it really listens
        first
            .peer_port
            .store(second.listen_addr.port(), Ordering::SeqCst);
        second
            .peer_port
            .store(first.listen_addr.port(), Ordering::SeqCst);

        for daemon in [&first, &second] {
            ask(daemon, Request::SetSync(true)).await.unwrap();
            assert!(daemon.status().await.network_running);
        }

        (first, second)
    }

    /// Waits (bounded) until `daemon` has a pairing waiting for its user.
    async fn wait_for_prompt(daemon: &Daemon) -> PairingPrompt {
        for _ in 0..1000 {
            if let Some(prompt) = daemon.pending_pairing().await {
                return prompt;
            }
            sleep(Duration::from_millis(10)).await;
        }
        panic!("no pairing prompt within 10 s");
    }

    /// Waits (bounded) until `daemon`'s vault holds `count` trusted peers.
    async fn wait_for_saved_peers(storage: &TestStorage, count: usize) {
        for _ in 0..500 {
            let restarted = storage.daemon_on_localhost().await;
            restarted.unlock(update(DATA_PW)).await.unwrap();
            if restarted.peer_list().await.read().await.len() == count {
                return;
            }
            sleep(Duration::from_millis(20)).await;
        }
        panic!("the vault never held {count} peers");
    }

    /// A pairing request as a handshake would send it, and the end that
    /// receives the user's answer.
    fn fake_request() -> (PairingRequest, tokio::sync::oneshot::Receiver<bool>) {
        let (decision, answer) = tokio::sync::oneshot::channel();
        (PairingRequest::for_test("peer", decision), answer)
    }

    /// Test that the daemon keeps at most MAX_PENDING_PAIRINGS prompts and
    /// rejects the next one at once, and that answered ones are gone
    #[tokio::test]
    async fn test_pending_pairings_bounded() {
        let daemon = Daemon::default();
        daemon.adding.store(true, Ordering::SeqCst);
        let mut answers = Vec::new();

        for _ in 0..MAX_PENDING_PAIRINGS {
            let (request, answer) = fake_request();
            daemon.queue_pairing(request).await;
            answers.push(answer);
        }
        assert_eq!(
            usize::from(daemon.status().await.pending_pairings),
            MAX_PENDING_PAIRINGS
        );

        let (extra, extra_answer) = fake_request();
        daemon.queue_pairing(extra).await;
        assert_eq!(
            timeout(Duration::from_secs(1), extra_answer).await,
            Ok(Ok(false))
        );
        assert_eq!(
            usize::from(daemon.status().await.pending_pairings),
            MAX_PENDING_PAIRINGS
        );

        // the oldest first; an answer reaches its handshake and frees a place
        let first = daemon.pending_pairing().await.unwrap();
        daemon
            .answer_pairing(first.id, &first.code, true)
            .await
            .unwrap();
        assert_eq!(answers.remove(0).await, Ok(true));
        assert_ne!(daemon.pending_pairing().await.unwrap().id, first.id);

        // a handshake that stopped waiting drops out by itself
        drop(answers);
        assert_eq!(daemon.status().await.pending_pairings, 0);
        assert!(daemon.pending_pairing().await.is_none());
    }

    /// Test that the settings encoding is strict and empty means defaults
    #[test]
    fn test_config_encoding() {
        assert_eq!(Config::decode(&[]), Some((Config::default(), Vec::new())));
        assert!(!Config::default().sync);
        assert!(!Config::default().clipboard);
        let no_addresses = [0u8, 0];
        for (sync, clipboard) in [(false, false), (true, false), (false, true), (true, true)] {
            let config = Config { sync, clipboard };
            assert_eq!(
                Config::decode(&config.encode(&no_addresses)),
                Some((config, Vec::new()))
            );
        }
        // version 1 (Sync only) is still read
        assert_eq!(
            Config::decode(&[CONFIG_VERSION_1, 0x01]),
            Some((
                Config {
                    sync: true,
                    clipboard: false
                },
                Vec::new()
            ))
        );
        // version 1 never had the clipboard flag; unknown version and flags,
        // wrong lengths, damaged addresses
        assert_eq!(Config::decode(&[CONFIG_VERSION_1, 0b10]), None);
        assert_eq!(Config::decode(&[CONFIG_VERSION_1, 0x01, 0x00]), None);
        assert_eq!(Config::decode(&[0x03, 0x01, 0, 0]), None);
        assert_eq!(Config::decode(&[CONFIG_VERSION, 0b100, 0, 0]), None);
        assert_eq!(Config::decode(&[CONFIG_VERSION]), None);
        assert_eq!(Config::decode(&[CONFIG_VERSION, 0x01]), None);
        assert_eq!(Config::decode(&[CONFIG_VERSION, 0x01, 0, 0, 0]), None);
        assert_eq!(Config::decode(&[CONFIG_VERSION, 0x01, 1, 0]), None);
    }

    /// Test that Sync is off by default, starts networking when switched on,
    /// survives a restart (networking comes back with the unlock) and turns
    /// everything off again
    #[tokio::test]
    async fn test_sync_switch_saved_and_drives_networking() {
        let storage = TestStorage::new("sync");
        let daemon = storage.daemon_on_localhost().await;
        setup(&daemon).await;

        let status = daemon.status().await;
        assert!(!status.sync_enabled && !status.network_running);
        assert_eq!(
            ask(&daemon, Request::AddDevice).await,
            Err(DaemonError::NetworkOff)
        );

        ask(&daemon, Request::SetSync(true)).await.unwrap();
        let status = daemon.status().await;
        assert!(status.sync_enabled && status.network_running);
        drop(daemon.stop_network().await);
        drop(daemon);

        // restart: locked, so off; the unlock brings it back
        let daemon = storage.daemon_on_localhost().await;
        let status = daemon.status().await;
        assert!(status.locked && !status.sync_enabled && !status.network_running);
        ask(&daemon, Request::Unlock(update(DATA_PW)))
            .await
            .unwrap();
        let status = daemon.status().await;
        assert!(status.sync_enabled && status.network_running);

        ask(&daemon, Request::SetSync(false)).await.unwrap();
        let status = daemon.status().await;
        assert!(!status.sync_enabled && !status.network_running);
        drop(daemon);

        let daemon = storage.daemon_on_localhost().await;
        ask(&daemon, Request::Unlock(update(DATA_PW)))
            .await
            .unwrap();
        assert!(!daemon.status().await.network_running);
    }

    /// Test that automatic login starts networking too when Sync is on
    #[tokio::test]
    async fn test_auto_login_starts_networking() {
        let storage = TestStorage::new("sync-auto");
        let daemon = storage.daemon_on_localhost().await;
        setup(&daemon).await;
        ask(&daemon, Request::SetAutoLogin(true)).await.unwrap();
        ask(&daemon, Request::SetSync(true)).await.unwrap();
        drop(daemon.stop_network().await);
        drop(daemon);

        let daemon = storage.daemon_on_localhost().await;
        let status = daemon.status().await;
        assert!(!status.locked && status.network_running);
    }

    /// Test that Sync needs an open, saved vault
    #[tokio::test]
    async fn test_sync_needs_saved_unlocked_keys() {
        let ram_only = Arc::new(Daemon::default());
        setup(&ram_only).await;
        assert_eq!(
            ask(&ram_only, Request::SetSync(true)).await,
            Err(DaemonError::NotSaved)
        );
        assert!(!ram_only.status().await.network_running);

        let storage = TestStorage::new("sync-locked");
        let daemon = storage.daemon_on_localhost().await;
        assert_eq!(
            ask(&daemon, Request::SetSync(true)).await,
            Err(DaemonError::NotSaved)
        );
        setup(&daemon).await;
        drop(daemon);

        let daemon = storage.daemon_on_localhost().await;
        assert_eq!(
            ask(&daemon, Request::SetSync(true)).await,
            Err(DaemonError::Locked)
        );
    }

    /// Test the whole pairing flow between two daemons: both users see the
    /// same code over IPC and accept, both vaults save the other device, and
    /// after a restart they reconnect without being asked again
    #[tokio::test]
    async fn test_two_daemons_pair_once_and_reconnect_after_restart() {
        let (storage_a, storage_b) = (TestStorage::new("pair-a"), TestStorage::new("pair-b"));
        let (a, b) = group_of_two(&storage_a, &storage_b).await;

        // both users pressed "Add device" (the UDP part is tested in udp_networker)
        a.adding.store(true, Ordering::SeqCst);
        b.adding.store(true, Ordering::SeqCst);

        let b_addr = b.listen_addr;
        let connect = tokio::spawn(connect_to(context(&a).await, b_addr));

        let prompt_a = wait_for_prompt(&a).await;
        let prompt_b = wait_for_prompt(&b).await;
        assert_eq!(prompt_a.code, prompt_b.code);
        assert_eq!(a.status().await.pending_pairings, 1);

        // the daemon's IPC answers both
        for (daemon, prompt) in [(&a, &prompt_a), (&b, &prompt_b)] {
            ask(
                daemon,
                Request::AnswerPairing {
                    id: prompt.id,
                    code: prompt.code,
                    accept: true,
                },
            )
            .await
            .unwrap();
        }

        assert_eq!(connect.await.unwrap(), Ok(()));
        assert_eq!(a.status().await.trusted_peers, 1);
        assert_eq!(b.status().await.trusted_peers, 1);
        assert_eq!(a.status().await.pending_pairings, 0);

        // the new peer reaches the vault on its own (re-sealed after pairing)
        wait_for_saved_peers(&storage_a, 1).await;
        wait_for_saved_peers(&storage_b, 1).await;

        for daemon in [a, b] {
            drop(daemon.stop_network().await);
        }

        // restart both; Sync was saved, the unlock starts networking
        let a = storage_a.daemon_on_localhost().await;
        let b = storage_b.daemon_on_localhost().await;
        for daemon in [&a, &b] {
            ask(daemon, Request::Unlock(update(DATA_PW))).await.unwrap();
            assert!(daemon.status().await.network_running);
        }

        // no "Add device" window anywhere: known devices still connect,
        // and nobody is asked
        assert_eq!(connect_to(context(&a).await, b.listen_addr).await, Ok(()));
        assert!(a.pending_pairing().await.is_none());
        assert!(b.pending_pairing().await.is_none());
        assert_eq!(a.status().await.trusted_peers, 1);
        assert_eq!(b.status().await.trusted_peers, 1);
    }

    /// Test that a new device is rejected without a prompt when this device
    /// has no "Add device" window open, and nothing is saved on either side
    #[tokio::test]
    async fn test_pairing_outside_add_window_rejected() {
        let (storage_a, storage_b) = (TestStorage::new("gate-a"), TestStorage::new("gate-b"));
        let (a, b) = group_of_two(&storage_a, &storage_b).await;

        // only A wants to add a device
        a.adding.store(true, Ordering::SeqCst);

        let connect = tokio::spawn(connect_to(context(&a).await, b.listen_addr));

        // A's user is asked and accepts; B rejected without asking anybody
        let prompt = wait_for_prompt(&a).await;
        assert!(b.pending_pairing().await.is_none());
        a.answer_pairing(prompt.id, &prompt.code, true)
            .await
            .unwrap();

        assert_eq!(
            connect.await.unwrap(),
            Err(TcpNetworkerErrors::FailedToAuthenticate)
        );
        assert!(b.pending_pairing().await.is_none());
        assert_eq!(a.status().await.trusted_peers, 0);
        assert_eq!(b.status().await.trusted_peers, 0);
    }

    /// Test that a rejection by one user pairs nobody, and an answer for an
    /// unknown or already answered pairing is refused
    #[tokio::test]
    async fn test_rejected_pairing_and_stale_answers() {
        let (storage_a, storage_b) = (TestStorage::new("reject-a"), TestStorage::new("reject-b"));
        let (a, b) = group_of_two(&storage_a, &storage_b).await;
        a.adding.store(true, Ordering::SeqCst);
        b.adding.store(true, Ordering::SeqCst);

        let connect = tokio::spawn(connect_to(context(&a).await, b.listen_addr));
        let prompt_a = wait_for_prompt(&a).await;
        let prompt_b = wait_for_prompt(&b).await;

        assert_eq!(
            ask(
                &b,
                Request::AnswerPairing {
                    id: prompt_b.id.wrapping_add(1),
                    code: prompt_b.code,
                    accept: true
                }
            )
            .await,
            Err(DaemonError::PairingExpired)
        );
        // the right id with another code (a different pairing after a
        // restart reuses ids) is refused too, and the prompt stays
        let mut other_code = prompt_b.code;
        other_code[0] = (other_code[0] + 1) % 64;
        assert_eq!(
            ask(
                &b,
                Request::AnswerPairing {
                    id: prompt_b.id,
                    code: other_code,
                    accept: true
                }
            )
            .await,
            Err(DaemonError::PairingExpired)
        );
        assert_eq!(b.pending_pairing().await, Some(prompt_b.clone()));

        ask(
            &b,
            Request::AnswerPairing {
                id: prompt_b.id,
                code: prompt_b.code,
                accept: false,
            },
        )
        .await
        .unwrap();
        // answered: gone
        assert_eq!(
            ask(
                &b,
                Request::AnswerPairing {
                    id: prompt_b.id,
                    code: prompt_b.code,
                    accept: true
                }
            )
            .await,
            Err(DaemonError::PairingExpired)
        );
        a.answer_pairing(prompt_a.id, &prompt_a.code, true)
            .await
            .unwrap();

        assert!(connect.await.unwrap().is_err());
        assert_eq!(a.status().await.trusted_peers, 0);
        assert_eq!(b.status().await.trusted_peers, 0);
    }

    /// Test that switching Sync off stops networking and rejects a pairing
    /// that is still waiting for the user
    #[tokio::test]
    async fn test_sync_off_rejects_waiting_pairing() {
        let (storage_a, storage_b) = (TestStorage::new("off-a"), TestStorage::new("off-b"));
        let (a, b) = group_of_two(&storage_a, &storage_b).await;
        a.adding.store(true, Ordering::SeqCst);
        b.adding.store(true, Ordering::SeqCst);

        let connect = tokio::spawn(connect_to(context(&a).await, b.listen_addr));
        let prompt_a = wait_for_prompt(&a).await;
        wait_for_prompt(&b).await;

        ask(&b, Request::SetSync(false)).await.unwrap();
        // rejected by the stop itself, not only once the handshake noticed
        assert!(b.pairings.read().await.waiting.is_empty());
        let status = b.status().await;
        assert!(!status.network_running && !status.adding_device);
        assert_eq!(status.pending_pairings, 0);
        a.answer_pairing(prompt_a.id, &prompt_a.code, true)
            .await
            .unwrap();

        assert!(connect.await.unwrap().is_err());
        assert_eq!(a.status().await.trusted_peers, 0);
        assert_eq!(b.status().await.trusted_peers, 0);
    }

    /// Test that a network that stopped on its own (listener failure) and is
    /// started again doesn't inherit an open "Add device" window
    #[tokio::test]
    async fn test_restarted_network_has_no_add_window() {
        let storage = TestStorage::new("restart-window");
        let daemon = storage.daemon_on_localhost().await;
        setup(&daemon).await;
        ask(&daemon, Request::SetSync(true)).await.unwrap();

        daemon.adding.store(true, Ordering::SeqCst);
        assert!(daemon.status().await.adding_device);

        // what the listener task does when accept fails
        daemon.network.read().await.as_ref().unwrap().token.cancel();
        let status = daemon.status().await;
        assert!(!status.network_running && !status.adding_device);

        // the next state change starts networking again: no window
        ask(&daemon, Request::SetSync(true)).await.unwrap();
        let status = daemon.status().await;
        assert!(status.network_running && !status.adding_device);
        assert!(!daemon.adding.load(Ordering::SeqCst));
    }

    /// Test that a password change reaches the running connections: after a
    /// new auth password on one side only, the two no longer authenticate
    #[tokio::test]
    async fn test_password_change_reaches_network() {
        let (storage_a, storage_b) = (TestStorage::new("keys-a"), TestStorage::new("keys-b"));
        let (a, b) = group_of_two(&storage_a, &storage_b).await;

        ask(
            &b,
            Request::SetAuthPassword(update(b"another auth password")),
        )
        .await
        .unwrap();

        // the networker holds exactly the daemon's new keys
        let (a_key, d_key) = key_bytes(&b).await;
        {
            let shared = context(&b).await.keys;
            let shared = shared.read().await;
            assert_eq!(**shared.a_key.expose(), a_key);
            assert_eq!(**shared.d_key.expose(), d_key);
        }

        a.adding.store(true, Ordering::SeqCst);
        b.adding.store(true, Ordering::SeqCst);

        // different a_key: SPAKE2 fails before anybody is asked
        let started = Instant::now();
        assert_eq!(
            connect_to(context(&a).await, b.listen_addr).await,
            Err(TcpNetworkerErrors::WrongPassword)
        );
        assert!(started.elapsed() < Duration::from_secs(HANDSHAKE_DEADLINE));
        assert!(a.pending_pairing().await.is_none());
        assert!(b.pending_pairing().await.is_none());
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

    // ── joining a group (salt sync) ──────────────────────────────────────

    fn join_request(auth: &[u8], data: &[u8]) -> Request {
        Request::JoinGroup(JoinPasswords {
            auth: update(auth),
            data: update(data),
        })
    }

    /// Where a join should find `member` (instead of searching the LAN).
    async fn join_through(joiner: &Daemon, member: &Daemon) {
        *joiner.test_members.write().await = vec![MemberAddrs {
            salt: member.salt_addr,
            tcp: member.listen_addr,
        }];
    }

    /// A member with networking on and an open invite window.
    async fn member_with_invite(storage: &TestStorage) -> (Arc<Daemon>, Invite) {
        let member = storage.daemon_on_localhost().await;
        setup(&member).await;
        ask(&member, Request::SetSync(true)).await.unwrap();
        let invite = member.open_invite().await.unwrap().unwrap();
        (member, invite)
    }

    /// Waits (bounded) until `check` holds for `daemon`'s status.
    async fn wait_for_status(daemon: &Daemon, check: impl Fn(&Status) -> bool) -> Status {
        for _ in 0..3000 {
            let status = daemon.status().await;
            if check(&status) {
                return status;
            }
            sleep(Duration::from_millis(10)).await;
        }
        panic!("status never got there: {:?}", daemon.status().await);
    }

    /// Test the whole join: a fresh device with the group's two passwords
    /// gets the salts from a member with "Add device" open, both users see
    /// the same code and accept, the joiner ends up with the member's keys,
    /// a saved vault and Sync on, and after a restart they reconnect
    /// without being asked again
    #[tokio::test]
    async fn test_join_group_end_to_end() {
        let (storage_a, storage_b) = (TestStorage::new("join-a"), TestStorage::new("join-b"));
        let (member, invite) = member_with_invite(&storage_a).await;

        let joiner = storage_b.daemon_on_localhost().await;
        join_through(&joiner, &member).await;
        ask(&joiner, join_request(AUTH_PW, DATA_PW)).await.unwrap();
        assert!(joiner.status().await.joining);

        let prompt_member = wait_for_prompt(&member).await;
        let prompt_joiner = wait_for_prompt(&joiner).await;
        assert_eq!(prompt_member.code, prompt_joiner.code);

        for (daemon, prompt) in [(&member, &prompt_member), (&joiner, &prompt_joiner)] {
            ask(
                daemon,
                Request::AnswerPairing {
                    id: prompt.id,
                    code: prompt.code,
                    accept: true,
                },
            )
            .await
            .unwrap();
        }

        let status = wait_for_status(&joiner, |s| s.saved && s.network_running).await;
        assert!(status.sync_enabled && !status.joining && !status.locked);
        assert_eq!(status.trusted_peers, 1);
        assert_eq!(key_bytes(&member).await, key_bytes(&joiner).await);
        let salts =
            |keys: &KeySlots| (*keys.a_salt.clone().unwrap(), *keys.d_salt.clone().unwrap());
        let member_salts = salts(&*member.keys.read().await);
        let joiner_salts = salts(&*joiner.keys.read().await);
        assert_eq!(member_salts, joiner_salts);
        assert_eq!(member.status().await.trusted_peers, 1);
        wait_for_saved_peers(&storage_a, 1).await;

        // the window closes; the joined device restarts and reconnects
        invite.window.cancel();
        member.adding.store(false, Ordering::SeqCst);
        drop(joiner.stop_network().await);
        drop(joiner);

        let joiner = storage_b.daemon_on_localhost().await;
        ask(&joiner, Request::Unlock(update(DATA_PW)))
            .await
            .unwrap();
        assert!(joiner.status().await.network_running);
        assert_eq!(
            connect_to(context(&member).await, joiner.listen_addr).await,
            Ok(())
        );
        assert!(member.pending_pairing().await.is_none());
        assert!(joiner.pending_pairing().await.is_none());
    }

    /// Test that a joiner with a wrong auth password fails SPAKE2 at once:
    /// nobody is asked, the joiner stays fresh, and CancelJoin ends it
    #[tokio::test]
    async fn test_join_wrong_password_never_prompts() {
        let (storage_a, storage_b) = (TestStorage::new("joinpw-a"), TestStorage::new("joinpw-b"));
        let (member, _invite) = member_with_invite(&storage_a).await;

        let joiner = storage_b.daemon_on_localhost().await;
        join_through(&joiner, &member).await;
        ask(&joiner, join_request(b"wrong auth password", DATA_PW))
            .await
            .unwrap();

        // the attempt runs and fails (Argon2, then SPAKE2 confirmation)
        for _ in 0..500 {
            if member
                .guess_limiter
                .is_locked(joiner.listen_addr.ip())
                .await
                || !member.pairings.read().await.waiting.is_empty()
            {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
        sleep(Duration::from_secs(2)).await;

        assert!(member.pending_pairing().await.is_none());
        assert!(joiner.pending_pairing().await.is_none());
        assert!(joiner.is_fresh().await);
        assert_eq!(member.status().await.trusted_peers, 0);

        ask(&joiner, Request::CancelJoin).await.unwrap();
        assert!(!joiner.status().await.joining);
        assert!(joiner.join.read().await.is_none());
    }

    /// Test that a fake salt (a rogue salt service in front of a real
    /// member) only makes the join fail: the salt is bound into SPAKE2, so
    /// nobody is asked and nothing is kept
    #[tokio::test]
    async fn test_join_fake_salt_fails() {
        let (storage_a, storage_b) = (
            TestStorage::new("joinfake-a"),
            TestStorage::new("joinfake-b"),
        );
        let (member, invite) = member_with_invite(&storage_a).await;
        // the real salt service is gone, a rogue one answers instead
        invite.window.cancel();
        let rogue = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rogue_addr = rogue.local_addr().unwrap();
        let rogue_token = CancellationToken::new();
        tokio::spawn(serve_salt(
            rogue,
            Zeroizing::new([0x66; 32]),
            rogue_token.clone(),
        ));

        let joiner = storage_b.daemon_on_localhost().await;
        let mut attempts = 0;
        let passwords = JoinPasswords {
            auth: update(AUTH_PW),
            data: update(DATA_PW),
        };
        // a join is running, so the joiner would show a prompt
        *joiner.join.write().await = Some(JoinSlot {
            generation: 0,
            token: CancellationToken::new(),
        });
        let result = joiner
            .join_attempt(
                &passwords,
                &DeviceKeypairs::new_seed().unwrap(),
                MemberAddrs {
                    salt: rogue_addr,
                    tcp: member.listen_addr,
                },
                &mut attempts,
            )
            .await;

        assert!(result.is_err());
        assert_eq!(attempts, 1);
        assert!(member.pending_pairing().await.is_none());
        assert!(joiner.pending_pairing().await.is_none());
        assert_eq!(member.status().await.trusted_peers, 0);
        rogue_token.cancel();
    }

    /// Test that the salt query exists only during the invite window, and
    /// the d_salt offer goes away with it
    #[tokio::test]
    async fn test_salt_only_during_invite() {
        let storage = TestStorage::new("invite");
        let member = storage.daemon_on_localhost().await;
        setup(&member).await;
        ask(&member, Request::SetSync(true)).await.unwrap();

        assert!(query_salt(member.salt_addr).await.is_err());

        let invite = member.open_invite().await.unwrap().unwrap();
        let a_salt = member.keys.read().await.a_salt.clone().unwrap();
        assert_eq!(*query_salt(member.salt_addr).await.unwrap(), *a_salt);
        assert!(context(&member).await.salt_offer.read().await.is_some());
        // one window at a time
        assert!(member.open_invite().await.unwrap().is_none());

        // the end of the window, as add_device's task ends it
        close_invite(&invite.window, &invite.context.salt_offer).await;
        sleep(Duration::from_millis(50)).await;
        assert!(query_salt(member.salt_addr).await.is_err());
        assert!(context(&member).await.salt_offer.read().await.is_none());
    }

    /// Test that the user can stop "Add device" early: the salt port and
    /// the d_salt offer go away, waiting prompts are rejected, no new
    /// device is asked about, and a new window can open that the old one's
    /// end doesn't close
    #[tokio::test]
    async fn test_stop_add_device() {
        let storage = TestStorage::new("stop-invite");
        let member = storage.daemon_on_localhost().await;
        setup(&member).await;
        ask(&member, Request::SetSync(true)).await.unwrap();

        let first = member.open_invite().await.unwrap().unwrap();
        assert!(member.status().await.adding_device);
        assert!(query_salt(member.salt_addr).await.is_ok());
        let (request, answer) = fake_request();
        member.queue_pairing(request).await;
        assert!(member.pending_pairing().await.is_some());

        ask(&member, Request::StopAddDevice).await.unwrap();

        assert!(!member.status().await.adding_device);
        assert!(first.window.is_cancelled());
        assert!(context(&member).await.salt_offer.read().await.is_none());
        assert!(member.pending_pairing().await.is_none());
        // dropped: the handshake reads that as a rejection
        assert_ne!(answer.await, Ok(true));
        sleep(Duration::from_millis(50)).await;
        assert!(TcpStream::connect(member.salt_addr).await.is_err());
        // nobody new is asked about any more
        let (request, answer) = fake_request();
        member.queue_pairing(request).await;
        assert_eq!(answer.await, Ok(false));
        // stopping again is harmless
        ask(&member, Request::StopAddDevice).await.unwrap();

        // a new window; the first one's late end doesn't close it
        let second = member.open_invite().await.unwrap().unwrap();
        assert!(!member.end_invite(Some(first.generation)).await);
        assert!(member.status().await.adding_device);
        assert!(!second.window.is_cancelled());
        assert!(context(&member).await.salt_offer.read().await.is_some());
        assert!(member.end_invite(Some(second.generation)).await);
        assert!(!member.status().await.adding_device);

        // Sync off ends an open window too: the salt port goes at once
        let third = member.open_invite().await.unwrap().unwrap();
        ask(&member, Request::SetSync(false)).await.unwrap();
        assert!(third.window.is_cancelled());
        sleep(Duration::from_millis(50)).await;
        assert!(TcpStream::connect(member.salt_addr).await.is_err());
    }

    /// Test that the group check tells a device of this group, a device of
    /// another group and a device that doesn't answer apart, and that the
    /// status reports another group only during the window that found it
    #[tokio::test]
    async fn test_check_group() {
        let (storage_a, storage_b, storage_c) = (
            TestStorage::new("group-a"),
            TestStorage::new("group-b"),
            TestStorage::new("group-c"),
        );
        // A and B: one group (B got A's salts); C: its own group
        let (a, b) = group_of_two(&storage_a, &storage_b).await;
        let c = storage_c.daemon_on_localhost().await;
        setup(&c).await;
        ask(&c, Request::SetSync(true)).await.unwrap();

        let own = a.keys.read().await.a_salt.clone().unwrap();
        let _b_window = b.open_invite().await.unwrap().unwrap();
        let _c_window = c.open_invite().await.unwrap().unwrap();

        assert_eq!(check_group(&own, b.salt_addr).await, GroupCheck::Same);
        assert_eq!(check_group(&own, c.salt_addr).await, GroupCheck::Different);
        // no salt query there (no window, an older build)
        assert_eq!(
            check_group(&own, free_local_addr()).await,
            GroupCheck::Unknown
        );

        // a found device: another group is skipped and reported, whatever
        // the ids; this group (or no answer) follows the lower-id rule
        let (x, y) = (
            InstanceId::generate().unwrap(),
            InstanceId::generate().unwrap(),
        );
        let (low, high) = (x.min(y), x.max(y));
        // C answered the check above: wait out its per-source rate limit
        sleep(crate::salt_service::ANSWER_INTERVAL).await;
        let seen = AtomicBool::new(false);
        assert_eq!(
            on_found(&own, c.salt_addr, low, high, &seen).await,
            Found::OtherGroup
        );
        assert!(seen.load(Ordering::SeqCst));
        // this group (B, waited out too) and no answer follow the ids
        let seen = AtomicBool::new(false);
        assert_eq!(
            on_found(&own, b.salt_addr, low, high, &seen).await,
            Found::Connect
        );
        assert_eq!(
            on_found(&own, free_local_addr(), high, low, &seen).await,
            Found::TheyConnect
        );
        assert!(!seen.load(Ordering::SeqCst));

        // the status shows it only while the window that found it is open
        let _a_window = a.open_invite().await.unwrap().unwrap();
        a.other_group.store(true, Ordering::SeqCst);
        assert!(a.status().await.other_group_nearby);
        ask(&a, Request::StopAddDevice).await.unwrap();
        assert!(!a.status().await.other_group_nearby);
        // and a new window starts clean
        let _again = a.open_invite().await.unwrap().unwrap();
        assert!(!a.status().await.other_group_nearby);
    }

    // ── devices on another network: a typed address ───────────────────────

    const LOCALHOST: IpAddr = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

    /// Where `daemon` finds the device at a typed address: `other`'s ports.
    fn reach_at(daemon: &Daemon, other: &Daemon) {
        daemon
            .peer_salt_port
            .store(other.salt_addr.port(), Ordering::SeqCst);
        daemon
            .peer_port
            .store(other.listen_addr.port(), Ordering::SeqCst);
    }

    /// Answers `daemon`'s waiting pairing with yes.
    async fn accept_prompt(daemon: &Arc<Daemon>, prompt: &PairingPrompt) {
        ask(
            daemon,
            Request::AnswerPairing {
                id: prompt.id,
                code: prompt.code,
                accept: true,
            },
        )
        .await
        .unwrap();
    }

    /// Test that a join at a typed address goes to that device only (no
    /// LAN search), waits without using attempts until its "Add device"
    /// window opens, then joins as usual
    #[tokio::test]
    async fn test_join_at_address() {
        let (storage_a, storage_b) = (TestStorage::new("joinat-a"), TestStorage::new("joinat-b"));
        let member = storage_a.daemon_on_localhost().await;
        setup(&member).await;
        ask(&member, Request::SetSync(true)).await.unwrap();

        let joiner = storage_b.daemon_on_localhost().await;
        reach_at(&joiner, &member);
        let passwords = JoinPasswords {
            auth: update(AUTH_PW),
            data: update(DATA_PW),
        };
        joiner.join_group(passwords, Some(LOCALHOST)).await.unwrap();

        // no window there yet: it keeps asking, nobody is prompted
        sleep(Duration::from_secs(1)).await;
        assert!(joiner.status().await.joining);
        assert!(member.pending_pairing().await.is_none());

        let _invite = member.open_invite().await.unwrap().unwrap();
        let prompt_member = wait_for_prompt(&member).await;
        let prompt_joiner = wait_for_prompt(&joiner).await;
        assert_eq!(prompt_member.code, prompt_joiner.code);
        accept_prompt(&member, &prompt_member).await;
        accept_prompt(&joiner, &prompt_joiner).await;

        let status = wait_for_status(&joiner, |s| s.saved && s.network_running).await;
        assert_eq!(status.trusted_peers, 1);
        assert_eq!(key_bytes(&member).await, key_bytes(&joiner).await);
    }

    /// Test that "Add device" at a typed address connects to a member of
    /// the group there once its window opens (the other side never has to
    /// find this one), both users are asked, and both end up paired
    #[tokio::test]
    async fn test_add_device_at_address() {
        let (storage_a, storage_b) = (TestStorage::new("addat-a"), TestStorage::new("addat-b"));
        let (a, b) = group_of_two(&storage_a, &storage_b).await;
        reach_at(&a, &b);
        assert_eq!(a.status().await.trusted_peers, 0);

        // the window without the LAN part (no broadcast, no UDP port): the
        // address goes into it the way AddDeviceAt does with a window open
        let _a_window = a.open_invite().await.unwrap().unwrap();
        a.add_device(Some(LOCALHOST)).await.unwrap();
        // the same address again in the same window: still one connection
        a.add_device(Some(LOCALHOST)).await.unwrap();
        sleep(Duration::from_secs(1)).await;
        assert!(b.pending_pairing().await.is_none());

        let _b_window = b.open_invite().await.unwrap().unwrap();
        let prompt_a = wait_for_prompt(&a).await;
        let prompt_b = wait_for_prompt(&b).await;
        assert_eq!(prompt_a.code, prompt_b.code);
        accept_prompt(&a, &prompt_a).await;
        accept_prompt(&b, &prompt_b).await;

        wait_for_status(&a, |s| s.trusted_peers == 1).await;
        wait_for_status(&b, |s| s.trusted_peers == 1).await;
        sleep(Duration::from_secs(1)).await;
        assert!(a.pending_pairing().await.is_none());
        assert!(b.pending_pairing().await.is_none());
    }

    /// Test that a typed address already waited for in this window, or a
    /// device this window connected to already (e.g. found by the search),
    /// gets no second connection
    #[tokio::test]
    async fn test_connect_at_once_per_window() {
        let (storage_a, storage_b) = (TestStorage::new("once-a"), TestStorage::new("once-b"));
        let (a, b) = group_of_two(&storage_a, &storage_b).await;
        let _b_window = b.open_invite().await.unwrap().unwrap();
        reach_at(&a, &b);
        let (context_a, window) = (context(&a).await, CancellationToken::new());

        // typed twice: the second one ends at once
        let typed = Arc::new(WindowAddrs::default());
        assert!(typed.typed.claim(LOCALHOST).await);
        timeout(
            Duration::from_secs(1),
            connect_at(
                context_a.clone(),
                a.member_at(LOCALHOST),
                window.clone(),
                typed,
                Arc::default(),
            ),
        )
        .await
        .unwrap();

        // connected already: the window is open there, still no connection
        let connected = Arc::new(WindowAddrs::default());
        assert!(connected.connected.claim(LOCALHOST).await);
        timeout(
            Duration::from_secs(10),
            connect_at(
                context_a,
                a.member_at(LOCALHOST),
                window,
                connected,
                Arc::default(),
            ),
        )
        .await
        .unwrap();

        sleep(Duration::from_secs(1)).await;
        assert!(b.pending_pairing().await.is_none());
        assert!(a.pending_pairing().await.is_none());
    }

    /// Test that a typed address of a device of another group is reported
    /// and never connected to (no prompt, no guess-limiter slot)
    #[tokio::test]
    async fn test_add_device_at_other_group() {
        let (storage_a, storage_c) = (TestStorage::new("addat-o-a"), TestStorage::new("addat-o-c"));
        let a = storage_a.daemon_on_localhost().await;
        setup(&a).await;
        ask(&a, Request::SetSync(true)).await.unwrap();
        let c = storage_c.daemon_on_localhost().await;
        setup(&c).await;
        ask(&c, Request::SetSync(true)).await.unwrap();
        let _c_window = c.open_invite().await.unwrap().unwrap();
        reach_at(&a, &c);

        // the window without the LAN part (see test_add_device_at_address)
        let _a_window = a.open_invite().await.unwrap().unwrap();
        a.add_device(Some(LOCALHOST)).await.unwrap();
        wait_for_status(&a, |s| s.other_group_nearby).await;
        sleep(Duration::from_secs(1)).await;
        assert!(c.pending_pairing().await.is_none());
        assert!(!c.guess_limiter.is_locked(LOCALHOST).await);
    }

    /// Test that this device's own address is refused for both requests
    #[tokio::test]
    async fn test_own_address_refused() {
        let Some(own) = own_lan_ip() else {
            // a machine with loopback only: nothing to test
            return;
        };
        let at = DeviceAddress::new(own).unwrap();

        let storage = TestStorage::new("own-addr");
        let member = storage.daemon_on_localhost().await;
        setup(&member).await;
        ask(&member, Request::SetSync(true)).await.unwrap();
        assert_eq!(
            ask(&member, Request::AddDeviceAt(at)).await,
            Err(DaemonError::OwnAddress)
        );
        // refused before any window opens
        assert!(!member.status().await.adding_device);

        let fresh_storage = TestStorage::new("own-addr-fresh");
        let fresh = fresh_storage.daemon_on_localhost().await;
        let passwords = JoinPasswords {
            auth: update(AUTH_PW),
            data: update(DATA_PW),
        };
        assert_eq!(
            ask(&fresh, Request::JoinGroupAt(at, passwords)).await,
            Err(DaemonError::OwnAddress)
        );
        assert!(!fresh.status().await.joining);
    }

    /// A non-loopback address of this machine, if it has one.
    fn own_lan_ip() -> Option<IpAddr> {
        nix::ifaddrs::getifaddrs()
            .ok()?
            .filter_map(|address| address.address?.as_sockaddr_in().map(|v4| v4.ip()))
            .find(|ip| !ip.is_loopback() && !ip.is_link_local())
            .map(IpAddr::V4)
    }

    /// Test that each address counts once per list, at most
    /// MAX_TRIED_PER_WINDOW, and that the lists are apart: a device the
    /// search left to the other side can still be typed and connected to
    #[tokio::test]
    async fn test_tried_claim() {
        let addrs = WindowAddrs::default();
        assert!(addrs.searched.claim(LOCALHOST).await);
        assert!(addrs.typed.claim(LOCALHOST).await);
        assert!(addrs.connected.claim(LOCALHOST).await);
        assert!(!addrs.connected.claim(LOCALHOST).await);

        let tried = Tried::default();
        assert!(tried.claim(LOCALHOST).await);
        assert!(!tried.claim(LOCALHOST).await);
        for i in 1..MAX_TRIED_PER_WINDOW {
            let ip = IpAddr::from([10, 0, 0, u8::try_from(i).unwrap()]);
            assert!(tried.claim(ip).await);
        }
        assert!(!tried.claim(IpAddr::from([10, 0, 1, 1])).await);
    }

    /// Test that only a fresh device with storage may join, and one join
    /// runs at a time
    #[tokio::test]
    async fn test_join_refused_unless_fresh() {
        // RAM only: a joined device wouldn't survive a restart
        let ram = Arc::new(Daemon::default());
        assert_eq!(
            ask(&ram, join_request(AUTH_PW, DATA_PW)).await,
            Err(DaemonError::NotSaved)
        );

        // a device with keys is in a group already
        let storage = TestStorage::new("join-member");
        let member = storage.daemon().await;
        setup(&member).await;
        assert_eq!(
            ask(&member, join_request(AUTH_PW, DATA_PW)).await,
            Err(DaemonError::AlreadyInGroup)
        );
        // a locked one too
        drop(member);
        let locked = storage.daemon().await;
        assert_eq!(
            ask(&locked, join_request(AUTH_PW, DATA_PW)).await,
            Err(DaemonError::AlreadyInGroup)
        );

        // one join at a time; nobody to join here (no member answers)
        let fresh_storage = TestStorage::new("join-fresh");
        let fresh = fresh_storage.daemon_on_localhost().await;
        *fresh.test_members.write().await = vec![MemberAddrs {
            salt: free_local_addr(),
            tcp: free_local_addr(),
        }];
        ask(&fresh, join_request(AUTH_PW, DATA_PW)).await.unwrap();
        assert_eq!(
            ask(&fresh, join_request(AUTH_PW, DATA_PW)).await,
            Err(DaemonError::JoinRunning)
        );
        ask(&fresh, Request::CancelJoin).await.unwrap();
        assert!(!fresh.status().await.joining);
        // cancelled: a new one may start
        ask(&fresh, join_request(AUTH_PW, DATA_PW)).await.unwrap();
        ask(&fresh, Request::CancelJoin).await.unwrap();
    }

    /// The fingerprints of `daemon`'s paired devices, in order.
    async fn fingerprints(daemon: &Arc<Daemon>) -> Vec<[u8; FINGERPRINT_LEN]> {
        daemon.peers().await.iter().map(|p| p.fingerprint).collect()
    }

    /// Makes the vault directory read-only (writes and deletes fail) or
    /// owner-only again.
    fn vault_dir_writable(storage: &TestStorage, writable: bool) {
        use std::os::unix::fs::PermissionsExt;
        let mode = if writable { 0o700 } else { 0o500 };
        std::fs::set_permissions(&storage.dir, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// Test that forgetting a device removes it from memory and the vault,
    /// refuses an unknown fingerprint and a locked vault, and that a failed
    /// save puts it back in its place
    #[tokio::test]
    async fn test_forget_peer() {
        let storage = TestStorage::new("forget");
        let daemon = storage.daemon().await;
        setup(&daemon).await;
        let (phone, laptop, tablet) = (
            TrustedPeer::for_test(7, "phone"),
            TrustedPeer::for_test(8, "laptop"),
            TrustedPeer::for_test(9, "tablet"),
        );
        let (fp_phone, fp_laptop, fp_tablet) = (
            phone.fingerprint(),
            laptop.fingerprint(),
            tablet.fingerprint(),
        );
        daemon
            .peer_list()
            .await
            .write()
            .await
            .extend([phone, laptop, tablet]);
        daemon.save_peers().await;

        assert_eq!(
            ask(&daemon, Request::ForgetPeer([0xEE; 8])).await,
            Err(DaemonError::UnknownPeer)
        );

        // a failed save changes nothing: the device is back in its place
        vault_dir_writable(&storage, false);
        assert_eq!(
            ask(&daemon, Request::ForgetPeer(fp_laptop)).await,
            Err(DaemonError::StorageFailed)
        );
        vault_dir_writable(&storage, true);
        assert_eq!(
            fingerprints(&daemon).await,
            [fp_phone, fp_laptop, fp_tablet]
        );

        ask(&daemon, Request::ForgetPeer(fp_laptop)).await.unwrap();
        assert_eq!(fingerprints(&daemon).await, [fp_phone, fp_tablet]);
        assert_eq!(daemon.status().await.trusted_peers, 2);

        // saved: gone after a restart too; locked, nothing can be forgotten
        let restarted = storage.daemon().await;
        assert_eq!(
            ask(&restarted, Request::ForgetPeer(fp_phone)).await,
            Err(DaemonError::Locked)
        );
        ask(&restarted, Request::Unlock(update(DATA_PW)))
            .await
            .unwrap();
        assert_eq!(fingerprints(&restarted).await, [fp_phone, fp_tablet]);
    }

    /// Test that a reset wipes everything (vault file, keychain items, keys,
    /// paired devices, networking), works while locked, and leaves a device
    /// that starts fresh and may join
    #[tokio::test]
    async fn test_reset_device() {
        let storage = TestStorage::new("reset");
        let daemon = storage.daemon_on_localhost().await;
        setup(&daemon).await;
        ask(&daemon, Request::SetAutoLogin(true)).await.unwrap();
        ask(&daemon, Request::SetSync(true)).await.unwrap();
        daemon
            .peer_list()
            .await
            .write()
            .await
            .push(TrustedPeer::for_test(7, "phone"));
        daemon.save_peers().await;
        assert!(daemon.status().await.network_running);
        assert!(storage.store.has(Item::Salts).await && storage.store.has(Item::DataKey).await);

        ask(&daemon, Request::ResetDevice).await.unwrap();

        let fresh = Status::default();
        let status = daemon.status().await;
        assert_eq!(
            (
                status.auth_key_set,
                status.data_key_set,
                status.saved,
                status.locked
            ),
            (false, false, false, false)
        );
        assert_eq!(
            (
                status.network_running,
                status.sync_enabled,
                status.trusted_peers
            ),
            (fresh.network_running, fresh.sync_enabled, 0)
        );
        assert!(daemon.is_fresh().await);
        assert!(!storage.path().exists());
        assert!(!storage.store.has(Item::Salts).await);
        assert!(!storage.store.has(Item::DataKey).await);

        // a restart finds nothing either
        let restarted = storage.daemon_on_localhost().await;
        assert!(restarted.is_fresh().await);

        // locked (a forgotten data password): reset is the way out
        setup(&restarted).await;
        let locked = storage.daemon_on_localhost().await;
        assert!(locked.status().await.locked);
        ask(&locked, Request::ResetDevice).await.unwrap();
        assert!(locked.is_fresh().await);
        assert!(!storage.path().exists());
    }

    /// Test that a failed vault delete changes nothing, and that a failed
    /// keychain delete still leaves a fresh device and a second reset
    /// removes the leftovers
    #[tokio::test]
    async fn test_reset_device_failures() {
        let storage = TestStorage::new("reset-fail");
        let daemon = storage.daemon().await;
        setup(&daemon).await;

        vault_dir_writable(&storage, false);
        assert_eq!(
            ask(&daemon, Request::ResetDevice).await,
            Err(DaemonError::StorageFailed)
        );
        vault_dir_writable(&storage, true);
        assert!(daemon.status().await.saved);
        assert!(storage.path().exists());

        storage.store.fail.store(true, Ordering::SeqCst);
        assert_eq!(
            ask(&daemon, Request::ResetDevice).await,
            Err(DaemonError::StorageFailed)
        );
        storage.store.fail.store(false, Ordering::SeqCst);
        assert!(daemon.is_fresh().await);
        assert!(!storage.path().exists());
        assert!(storage.store.has(Item::Salts).await);

        ask(&daemon, Request::ResetDevice).await.unwrap();
        assert!(!storage.store.has(Item::Salts).await);
    }

    /// Test that nothing from before a reset comes back: a handshake of the
    /// old network that finishes late adds to the old list, and a join that
    /// started before never commits
    #[tokio::test]
    async fn test_reset_device_late_arrivals() {
        let storage = TestStorage::new("reset-late");
        let daemon = storage.daemon_on_localhost().await;
        setup(&daemon).await;

        let old_list = daemon.peer_list().await;
        ask(&daemon, Request::ResetDevice).await.unwrap();
        old_list
            .write()
            .await
            .push(TrustedPeer::for_test(7, "late"));
        assert_eq!(daemon.status().await.trusted_peers, 0);

        // a join that began before the reset (resets was 0 then)
        let joined = Joined {
            a_key: AuthKey::from_bytes(&[1; 32]),
            a_salt: Zeroizing::new([2; 32]),
            d_key: DataKey::from_bytes(&[3; 32]),
            d_salt: Zeroizing::new([4; 32]),
            peer: TrustedPeer::for_test(9, "member"),
            addr: SocketAddr::from(([127, 0, 0, 1], TCP_PORT)),
        };
        assert!(
            daemon
                .commit_join(joined, DeviceKeypairs::new_seed().unwrap(), 0)
                .await
                .is_err()
        );
        assert!(daemon.is_fresh().await);
        assert!(!storage.path().exists());
    }

    /// Test that a join's commit refuses a device that got keys while the
    /// user was pairing, and changes nothing
    #[tokio::test]
    async fn test_commit_join_rechecks_fresh() {
        let storage = TestStorage::new("join-commit");
        let daemon = storage.daemon_on_localhost().await;
        setup(&daemon).await;
        let before = key_bytes(&daemon).await;

        let joined = Joined {
            a_key: AuthKey::from_bytes(&[1; 32]),
            a_salt: Zeroizing::new([2; 32]),
            d_key: DataKey::from_bytes(&[3; 32]),
            d_salt: Zeroizing::new([4; 32]),
            peer: TrustedPeer::for_test(9, "member"),
            addr: SocketAddr::from(([127, 0, 0, 1], TCP_PORT)),
        };
        let result = daemon
            .commit_join(joined, DeviceKeypairs::new_seed().unwrap(), 0)
            .await;

        assert_eq!(result, Err(DaemonError::AlreadyInGroup));
        assert_eq!(key_bytes(&daemon).await, before);
        assert!(daemon.peers().await.is_empty());
    }

    /// Test that a join's pairing prompts go away when the join is
    /// cancelled, and a stale join task can't end a newer join
    #[tokio::test]
    async fn test_cancel_join_clears_prompts_and_generation() {
        let daemon = TestStorage::new("join-gen").daemon_on_localhost().await;
        *daemon.join.write().await = Some(JoinSlot {
            generation: 7,
            token: CancellationToken::new(),
        });
        let (request, _answer) = fake_request();
        daemon.queue_pairing(request).await;
        assert!(daemon.pending_pairing().await.is_some());

        // an older join ending doesn't touch the current one
        daemon.end_join(6).await;
        assert!(daemon.status().await.joining);
        assert!(daemon.pending_pairing().await.is_some());

        ask(&daemon, Request::CancelJoin).await.unwrap();
        assert!(!daemon.status().await.joining);
        assert!(daemon.pending_pairing().await.is_none());

        // outside a join (and outside "Add device") nobody is asked
        let (request, answer) = fake_request();
        daemon.queue_pairing(request).await;
        assert!(daemon.pending_pairing().await.is_none());
        assert_eq!(answer.await, Ok(false));
    }

    /// The clipboard in memory: a counter, a text, and whether it is marked
    /// concealed (as a password manager would). No lock of its own: the
    /// counter is atomic, the content a `watch` value replaced as a whole.
    struct MemClipboard {
        count: std::sync::atomic::AtomicI64,
        content: tokio::sync::watch::Sender<(Option<String>, bool)>,
    }

    impl Default for MemClipboard {
        fn default() -> Self {
            Self {
                count: std::sync::atomic::AtomicI64::new(0),
                content: tokio::sync::watch::Sender::new((None, false)),
            }
        }
    }

    impl MemClipboard {
        /// What a user copying `text` does (`concealed`: a password manager).
        fn copy(&self, text: &str, concealed: bool) {
            self.content
                .send_replace((Some(text.to_owned()), concealed));
            self.count.fetch_add(1, Ordering::SeqCst);
        }

        fn text(&self) -> Option<String> {
            self.content.borrow().0.clone()
        }
    }

    impl Clipboard for MemClipboard {
        fn change_count(&self) -> i64 {
            self.count.load(Ordering::SeqCst)
        }

        fn read_text(&self, max_len: usize) -> ClipRead {
            let (text, concealed) = self.content.borrow().clone();
            match text {
                _ if concealed => ClipRead::Concealed,
                Some(text) if text.len() > max_len => ClipRead::TooLarge,
                Some(text) => ClipRead::Text(Zeroizing::new(text)),
                None => ClipRead::NoText,
            }
        }

        fn write_text(&self, text: &str) -> Option<i64> {
            self.content.send_replace((Some(text.to_owned()), false));
            Some(self.count.fetch_add(1, Ordering::SeqCst).saturating_add(1))
        }
    }

    /// Two paired devices (the user compared the code on both), each with
    /// its own clipboard; both have the other's address.
    async fn paired_two(
        a: &TestStorage,
        b: &TestStorage,
        clipboard_a: Option<Arc<dyn Clipboard>>,
        clipboard_b: Option<Arc<dyn Clipboard>>,
    ) -> (Arc<Daemon>, Arc<Daemon>) {
        let (first, second) = group_of_two_with(a, b, clipboard_a, clipboard_b).await;
        first.adding.store(true, Ordering::SeqCst);
        second.adding.store(true, Ordering::SeqCst);

        let connect = tokio::spawn(connect_to(context(&first).await, second.listen_addr));
        let (prompt_a, prompt_b) = (
            wait_for_prompt(&first).await,
            wait_for_prompt(&second).await,
        );
        for (daemon, prompt) in [(&first, &prompt_a), (&second, &prompt_b)] {
            ask(
                daemon,
                Request::AnswerPairing {
                    id: prompt.id,
                    code: prompt.code,
                    accept: true,
                },
            )
            .await
            .unwrap();
        }
        assert_eq!(connect.await.unwrap(), Ok(()));
        first.adding.store(false, Ordering::SeqCst);
        second.adding.store(false, Ordering::SeqCst);

        (first, second)
    }

    /// The state `daemon` shows for its only paired device.
    async fn only_peer_state(daemon: &Daemon) -> PeerState {
        let peers = daemon.peers().await;
        assert_eq!(peers.len(), 1);
        peers.first().map_or(PeerState::Unknown, |peer| peer.state)
    }

    /// Waits (bounded) until `daemon` shows `state` for its paired device.
    async fn wait_for_peer_state(daemon: &Daemon, state: PeerState) {
        for _ in 0..1500 {
            if only_peer_state(daemon).await == state {
                return;
            }
            sleep(Duration::from_millis(10)).await;
        }
        panic!(
            "the paired device never showed {state:?} (it shows {:?})",
            only_peer_state(daemon).await
        );
    }

    /// Test that after pairing both devices show the other as fine and know
    /// where it listens
    #[tokio::test]
    async fn test_paired_devices_know_each_other() {
        let (storage_a, storage_b) = (TestStorage::new("book-a"), TestStorage::new("book-b"));
        let (a, b) = paired_two(&storage_a, &storage_b, None, None).await;

        assert_eq!(only_peer_state(&a).await, PeerState::Ok);
        assert_eq!(only_peer_state(&b).await, PeerState::Ok);
        let peers = b.trusted_copy().await;
        let targets = b.peer_book.targets(&peers).await;
        assert_eq!(targets.first().map(|(_, addr)| *addr), Some(a.listen_addr));

        // the addresses survive a restart (saved in the vault)
        drop(b.stop_network().await);
        let mut saved = None;
        for _ in 0..500 {
            let restarted = storage_b.daemon_on_localhost().await;
            restarted.unlock(update(DATA_PW)).await.unwrap();
            let peers = restarted.trusted_copy().await;
            saved = restarted
                .peer_book
                .targets(&peers)
                .await
                .first()
                .map(|(_, addr)| *addr);
            if saved.is_some() {
                break;
            }
            sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(saved, Some(a.listen_addr));
    }

    /// Test that changing the auth password on one device makes BOTH show
    /// "incorrect password" for the other at once (the hello after the
    /// change), nobody is asked to pair, and setting the same password
    /// again makes both fine
    #[tokio::test]
    async fn test_auth_password_change_shows_incorrect_password() {
        let (storage_a, storage_b) = (TestStorage::new("pw1-a"), TestStorage::new("pw1-b"));
        let (a, b) = paired_two(&storage_a, &storage_b, None, None).await;

        ask(
            &b,
            Request::SetAuthPassword(update(b"another auth password")),
        )
        .await
        .unwrap();
        wait_for_peer_state(&b, PeerState::AuthPasswordDiffers).await;
        wait_for_peer_state(&a, PeerState::AuthPasswordDiffers).await;
        assert!(a.pending_pairing().await.is_none());
        assert!(b.pending_pairing().await.is_none());

        // the same password as the other device again
        ask(&b, Request::SetAuthPassword(update(AUTH_PW)))
            .await
            .unwrap();
        wait_for_peer_state(&b, PeerState::Ok).await;
        wait_for_peer_state(&a, PeerState::Ok).await;
    }

    /// Test that changing the data password on one device makes both show
    /// "incorrect password" (data) for the other, through the hello's
    /// answer, and the same password again makes both fine
    #[tokio::test]
    async fn test_data_password_change_shows_incorrect_password() {
        let (storage_a, storage_b) = (TestStorage::new("pw2-a"), TestStorage::new("pw2-b"));
        let (a, b) = paired_two(&storage_a, &storage_b, None, None).await;

        ask(
            &b,
            Request::SetDataPassword(update(b"another data password")),
        )
        .await
        .unwrap();
        wait_for_peer_state(&a, PeerState::DataPasswordDiffers).await;
        wait_for_peer_state(&b, PeerState::DataPasswordDiffers).await;

        ask(&b, Request::SetDataPassword(update(DATA_PW)))
            .await
            .unwrap();
        wait_for_peer_state(&b, PeerState::Ok).await;
        wait_for_peer_state(&a, PeerState::Ok).await;
    }

    /// Test that a device whose last address doesn't answer is shown as
    /// unreachable
    #[tokio::test]
    async fn test_unreachable_peer_shown() {
        let (storage_a, storage_b) = (TestStorage::new("gone-a"), TestStorage::new("gone-b"));
        let (a, b) = paired_two(&storage_a, &storage_b, None, None).await;

        // A goes away; B's next hello (after a key change) finds nobody
        drop(a.stop_network().await);
        ask(&b, Request::SetAuthPassword(update(AUTH_PW)))
            .await
            .unwrap();
        wait_for_peer_state(&b, PeerState::Unreachable).await;
    }

    /// Waits (bounded) until `clipboard` holds `text`.
    async fn wait_for_clip(clipboard: &MemClipboard, text: &str) {
        for _ in 0..1500 {
            if clipboard.text().as_deref() == Some(text) {
                return;
            }
            sleep(Duration::from_millis(10)).await;
        }
        panic!(
            "the clipboard never got {text:?} (it has {:?})",
            clipboard.text()
        );
    }

    /// Test clipboard sync end to end between two paired daemons: a copy on
    /// one appears on the other, both ways, without being sent back; text
    /// a password manager marked concealed is never sent; the switch is
    /// off by default and off means nothing is sent or applied
    #[tokio::test]
    async fn test_clipboard_sync_end_to_end() {
        let (storage_a, storage_b) = (TestStorage::new("clip-a"), TestStorage::new("clip-b"));
        let (clip_a, clip_b) = (
            Arc::new(MemClipboard::default()),
            Arc::new(MemClipboard::default()),
        );
        let (a, b) = paired_two(
            &storage_a,
            &storage_b,
            Some(clip_a.clone()),
            Some(clip_b.clone()),
        )
        .await;

        // off by default: nothing goes anywhere
        assert!(!a.status().await.clipboard_enabled);
        clip_a.copy("before the switch", false);
        sleep(Duration::from_millis(5 * CLIP_POLL_MS)).await;
        assert_eq!(clip_b.text(), None);

        for daemon in [&a, &b] {
            ask(daemon, Request::SetClipboard(true)).await.unwrap();
            let status = daemon.status().await;
            assert!(status.clipboard_enabled && !status.clipboard_unavailable);
        }
        // turning it on doesn't send what was copied before
        sleep(Duration::from_millis(5 * CLIP_POLL_MS)).await;
        assert_eq!(clip_b.text(), None);

        clip_a.copy("zażółć gęślą jaźń", false);
        wait_for_clip(&clip_b, "zażółć gęślą jaźń").await;

        // applied on B: B doesn't send it back (A's clipboard stays as it was)
        let count_a = clip_a.change_count();
        sleep(Duration::from_millis(10 * CLIP_POLL_MS)).await;
        assert_eq!(clip_a.change_count(), count_a);

        // and the other way round
        clip_b.copy("from b", false);
        wait_for_clip(&clip_a, "from b").await;

        // concealed (a password manager): never read, never sent
        clip_a.copy("hunter2 password", true);
        sleep(Duration::from_millis(10 * CLIP_POLL_MS)).await;
        assert_eq!(clip_b.text().as_deref(), Some("from b"));

        // B switched off: A's copy isn't applied there
        ask(&b, Request::SetClipboard(false)).await.unwrap();
        clip_a.copy("after b switched off", false);
        sleep(Duration::from_millis(10 * CLIP_POLL_MS)).await;
        assert_eq!(clip_b.text().as_deref(), Some("from b"));

        // the switch is saved
        assert!(!b.status().await.clipboard_enabled);
        assert!(a.status().await.clipboard_enabled);
    }

    /// Test that clipboard sync needs a saved vault, and a platform without
    /// a clipboard refuses to turn it on
    #[tokio::test]
    async fn test_clipboard_switch_refusals() {
        let storage = TestStorage::new("clip-switch");
        let daemon = storage.daemon_on_localhost().await;
        assert_eq!(
            ask(&daemon, Request::SetClipboard(true)).await,
            Err(DaemonError::ClipboardUnavailable)
        );
        // off is always fine to ask, but needs a vault to save it in
        assert_eq!(
            ask(&daemon, Request::SetClipboard(false)).await,
            Err(DaemonError::NotSaved)
        );

        let storage = TestStorage::new("clip-switch-2");
        let daemon = storage
            .daemon_with_clipboard(Some(Arc::new(MemClipboard::default())))
            .await;
        assert_eq!(
            ask(&daemon, Request::SetClipboard(true)).await,
            Err(DaemonError::NotSaved)
        );
        setup(&daemon).await;
        ask(&daemon, Request::SetClipboard(true)).await.unwrap();
        assert!(daemon.status().await.clipboard_enabled);

        // locked after a restart: refused until unlocked, then still on
        let restarted = storage
            .daemon_with_clipboard(Some(Arc::new(MemClipboard::default())))
            .await;
        assert_eq!(
            ask(&restarted, Request::SetClipboard(false)).await,
            Err(DaemonError::Locked)
        );
        ask(&restarted, Request::Unlock(update(DATA_PW)))
            .await
            .unwrap();
        assert!(restarted.status().await.clipboard_enabled);
    }

    /// Test that an update from a paired device is applied only when it is
    /// well formed and newer, and only with the switch on
    #[tokio::test]
    async fn test_apply_clip_checks() {
        let storage = TestStorage::new("clip-apply");
        let clip = Arc::new(MemClipboard::default());
        let daemon = storage.daemon_with_clipboard(Some(clip.clone())).await;
        setup(&daemon).await;
        let clipboard: Arc<dyn Clipboard> = clip.clone();
        let mut ordering = clip_sync::UpdateOrder::default();
        let mut watch = ClipWatch::new(0);
        let peer = TrustedPeer::for_test(3, "peer");

        let deliver = |payload: Zeroizing<Vec<u8>>| {
            let (answer, _reply) = tokio::sync::oneshot::channel();
            ClipDelivery {
                peer: peer.clone(),
                payload,
                answer,
            }
        };
        let message = |seq: u64, text: &str| clip_sync::encode(&[1; 8], seq, text).unwrap();

        // switch off: ignored
        let off = deliver(message(1, "off"));
        assert_eq!(
            daemon
                .apply_clip(&clipboard, &mut ordering, &off, &mut watch)
                .await,
            DataAck::Ignored
        );
        assert_eq!(clip.text(), None);

        ask(&daemon, Request::SetClipboard(true)).await.unwrap();

        let first = deliver(message(5, "first"));
        assert_eq!(
            daemon
                .apply_clip(&clipboard, &mut ordering, &first, &mut watch)
                .await,
            DataAck::Applied
        );
        assert_eq!(clip.text().as_deref(), Some("first"));
        // our own write is taken as seen, so it is never sent back
        assert_eq!(watch.tick(true, clip.change_count(), false), ClipTick::Wait);
        assert_eq!(watch.tick(true, clip.change_count(), false), ClipTick::Wait);

        // older or the same again: ignored
        for seq in [5, 4] {
            let old = deliver(message(seq, "old"));
            assert_eq!(
                daemon
                    .apply_clip(&clipboard, &mut ordering, &old, &mut watch)
                    .await,
                DataAck::Ignored
            );
        }
        // malformed: ignored
        let bad = deliver(Zeroizing::new(vec![0x01, 0x01, 0x00]));
        assert_eq!(
            daemon
                .apply_clip(&clipboard, &mut ordering, &bad, &mut watch)
                .await,
            DataAck::Ignored
        );
        assert_eq!(clip.text().as_deref(), Some("first"));
    }

    /// Test the clipboard poll decision: a change goes once it held still,
    /// not while a round runs, never when made with the switch off or when
    /// the switch went off before it was sent, never our own write
    #[test]
    fn test_clip_watch() {
        use ClipTick::{Send, Wait};
        let mut watch = ClipWatch::new(10);

        // nothing changed
        assert_eq!(watch.tick(true, 10, false), Wait);
        // a copy: sent at the next poll if it held still
        assert_eq!(watch.tick(true, 11, false), Wait);
        assert_eq!(watch.tick(true, 11, false), Send);
        assert_eq!(watch.tick(true, 11, false), Wait);

        // fast copies: only the last one, once it held still
        assert_eq!(watch.tick(true, 12, false), Wait);
        assert_eq!(watch.tick(true, 13, false), Wait);
        assert_eq!(watch.tick(true, 13, false), Send);

        // a round still runs: it waits, then goes
        assert_eq!(watch.tick(true, 14, true), Wait);
        assert_eq!(watch.tick(true, 14, true), Wait);
        assert_eq!(watch.tick(true, 14, false), Send);

        // copied while off: never sent, also not after turning on
        assert_eq!(watch.tick(false, 15, false), Wait);
        assert_eq!(watch.tick(false, 15, false), Wait);
        assert_eq!(watch.tick(true, 15, false), Wait);

        // copied while off, switched on right at the next poll: still never sent
        assert_eq!(watch.tick(false, 18, false), Wait);
        assert_eq!(watch.tick(true, 18, false), Wait);
        assert_eq!(watch.tick(true, 18, false), Wait);

        // copied while on, switched off before it went: never sent
        assert_eq!(watch.tick(true, 19, false), Wait);
        assert_eq!(watch.tick(false, 19, false), Wait);
        assert_eq!(watch.tick(true, 19, false), Wait);

        // our own write (an update from a paired device): never sent back
        watch.written(20);
        assert_eq!(watch.tick(true, 20, false), Wait);
        assert_eq!(watch.tick(true, 20, false), Wait);
    }
}
