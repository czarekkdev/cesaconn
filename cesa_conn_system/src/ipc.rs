//! UI <-> daemon IPC: wire protocol, socket location and the client side.
//!
//! Security model
//! * The daemon owns `a_key` / `d_key` and their salts and NEVER sends them
//!   out. The UI only sends passwords (once, to set them) and gets status back;
//!   it holds nothing to keep.
//! * The socket lives in a private directory (owner only, `0700`) that is
//!   checked on every use, and is itself `0600`.
//! * The daemon accepts a connection only from a process of the same user
//!   (kernel peer credentials), and on macOS only from code whose signature
//!   satisfies a requirement fixed at build time (see the networker).
//! * The other way round too: the UI only talks to (and sends a password to)
//!   a daemon of the same user, and on macOS only to one whose signature
//!   satisfies [`DAEMON_CODE_REQUIREMENT`].
//!
//! Wire format (version 4), one request and one response per connection:
//! `frame = length (u32 LE, 1..=MAX_FRAME_LEN) || body`
//!
//! Request body: `kind (1) || payload`
//! * `0x01` Status
//! * `0x04` ListPeers
//! * `0x05` SetAuthPassword: `password (1..=MAX_PASSWORD_LEN)`; the daemon
//!   picks the salt
//! * `0x06` SetDataPassword: same
//! * `0x07` Unlock: `password (1..=MAX_PASSWORD_LEN)`, the data password that
//!   opens the encrypted vault after a restart
//! * `0x08` SetAutoLogin: `on (1)`, exactly `0x00` or `0x01`
//! * `0x09` SetSync: `on (1)`, exactly `0x00` or `0x01`; networking on/off,
//!   saved in the vault
//! * `0x0A` AddDevice: none; opens the "Add device" window (search the LAN,
//!   pair with what answers)
//! * `0x0B` PendingPairing: none; the pairing waiting for the user, if any
//! * `0x0C` AnswerPairing: `id (u32 LE) || accept (1)`, accept exactly
//!   `0x00` or `0x01`
//! * `0x02` / `0x03` are retired (version 1 sent `salt || password` there).
//!   They are refused, so a mismatched UI and daemon fail loudly instead of
//!   deriving a key from the wrong bytes.
//!
//! Response body: `0x00 || payload` on success, `0x01 || error code (1)` on error
//! * Status: `flags (1) || trusted peers (u32 LE) || unlock wait (u16 LE) ||
//!   pending pairings (u8)`; flags bit 0 = auth key set, bit 1 = data key set,
//!   bit 2 = network running, bit 3 = vault locked, bit 4 = keys saved
//!   (encrypted vault), bit 5 = automatic login on, bit 6 = Sync switched on,
//!   bit 7 = "Add device" window open; unlock wait = seconds until `Unlock` is
//!   accepted again after too many wrong data passwords (0 = now). Versions 2
//!   and 3 were shorter, so a mismatched UI and daemon fail with `Malformed`.
//! * SetAuthPassword / SetDataPassword / Unlock / SetAutoLogin / SetSync /
//!   AddDevice / AnswerPairing: empty
//! * ListPeers: `count (u16 LE) || count * (fingerprint (8) || name len (1) || name)`
//! * PendingPairing: `0x00` (none) or `0x01 || id (u32 LE) || code (8) ||
//!   name len (1) || name`; every code byte is below
//!   [`crate::pairing_code::PAIRING_SYMBOLS`], the name has no control characters

use core::fmt;
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;
use zeroize::Zeroizing;

use crate::pairing_code::{self, PAIRING_CODE_LEN, PairingCode};

/// Largest frame body accepted in either direction (bytes); fits the
/// biggest message, a full `ListPeers` answer (checked below).
pub const MAX_FRAME_LEN: u32 = 72 * 1024;
/// Longest password accepted (bytes).
pub const MAX_PASSWORD_LEN: usize = 1024;
/// Most peers returned by `ListPeers`.
pub const MAX_LISTED_PEERS: usize = 256;
/// Timeout for every single read / write (seconds).
pub const IO_TIMEOUT: Duration = Duration::from_secs(5);
/// Bytes of a peer's key shown as its fingerprint.
pub const FINGERPRINT_LEN: usize = 8;

/// longest `ListPeers` body: status + count + every peer at full name length
const MAX_PEERS_BODY: usize = 1 + 2 + MAX_LISTED_PEERS * (FINGERPRINT_LEN + 1 + 255);
/// longest request body: kind + password
const MAX_REQUEST_BODY: usize = 1 + MAX_PASSWORD_LEN;

const _: () = assert!(MAX_PEERS_BODY <= MAX_FRAME_LEN as usize);
const _: () = assert!(MAX_REQUEST_BODY <= MAX_FRAME_LEN as usize);

/// Code requirement the daemon must satisfy (macOS), fixed when the UI is built:
/// `CESA_IPC_DAEMON_CODE_REQUIREMENT='anchor apple generic and certificate
/// leaf[subject.OU] = "TEAMID" and identifier "dev.czarekk.cesaconn.daemon"'`
///
/// Only meaningful with a Developer ID signature and the hardened runtime on
/// the daemon. Unset: the daemon is checked by uid only, and the UI says so.
pub const DAEMON_CODE_REQUIREMENT: Option<&str> = option_env!("CESA_IPC_DAEMON_CODE_REQUIREMENT");

/// Whether the daemon's code signature is checked before anything is sent.
pub fn daemon_signature_checked() -> bool {
    DAEMON_CODE_REQUIREMENT.is_some()
}

/// `false` if a requirement was built in but doesn't parse (or this platform
/// has no code signing): then every daemon is refused, which fails closed.
pub fn daemon_requirement_valid() -> bool {
    DAEMON_CODE_REQUIREMENT
        .is_none_or(|requirement| crate::code_signature::validate_requirement(requirement).is_ok())
}

/// Socket file name inside the private directory.
const SOCKET_NAME: &str = "daemon.sock";
/// Private directory name inside the per-user runtime/temp directory.
const DIR_NAME: &str = "cesaconn";

/* request kinds */
const REQ_STATUS: u8 = 0x01;
const REQ_LIST_PEERS: u8 = 0x04;
const REQ_SET_AUTH_PASSWORD: u8 = 0x05;
const REQ_SET_DATA_PASSWORD: u8 = 0x06;
const REQ_UNLOCK: u8 = 0x07;
const REQ_SET_AUTO_LOGIN: u8 = 0x08;
const REQ_SET_SYNC: u8 = 0x09;
const REQ_ADD_DEVICE: u8 = 0x0A;
const REQ_PENDING_PAIRING: u8 = 0x0B;
const REQ_ANSWER_PAIRING: u8 = 0x0C;

/// Shortest new password the daemon accepts (characters; bytes if not UTF-8). Anyone holding the vault
/// file and the keychain salts can guess the data password offline, so short
/// passwords are refused when they are set (not when unlocking).
pub const MIN_NEW_PASSWORD_LEN: usize = 12;

/* response status */
const RESP_OK: u8 = 0x00;
const RESP_ERR: u8 = 0x01;

/// All errors of the IPC layer.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum IpcErrors {
    /// Local IPC isn't implemented on this platform yet (Windows).
    Unsupported,
    /// No per-user runtime directory (`XDG_RUNTIME_DIR`) to put the socket in.
    NoRuntimeDir,
    /// The socket directory is not ours, not private (`0700`) or a symlink.
    InsecureDirectory,
    /// Creating or inspecting the socket directory / file failed.
    FailedToPrepareSocket,
    /// The daemon isn't running (nothing listens on the socket).
    FailedToConnect,
    /// The process behind the socket runs as a different user, or (macOS)
    /// its code signature doesn't satisfy [`DAEMON_CODE_REQUIREMENT`].
    UntrustedDaemon,
    /// Reading from the socket failed or the peer closed it early.
    FailedToRead,
    /// Writing to the socket failed.
    FailedToWrite,
    /// A read or write didn't finish within [`IO_TIMEOUT`].
    Timeout,
    /// A frame length was 0 or larger than [`MAX_FRAME_LEN`].
    FrameTooLarge,
    /// A message doesn't follow the wire format.
    Malformed,
    /// The daemon answered with an error.
    Daemon(DaemonError),
}

impl fmt::Display for IpcErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpcErrors::Unsupported => write!(f, "local IPC is not supported on this platform yet"),
            IpcErrors::NoRuntimeDir => write!(f, "no per-user runtime directory for the socket"),
            IpcErrors::InsecureDirectory => {
                write!(f, "socket directory is not private to this user")
            }
            IpcErrors::FailedToPrepareSocket => write!(f, "failed to prepare the socket"),
            IpcErrors::FailedToConnect => write!(f, "failed to connect to the daemon"),
            IpcErrors::UntrustedDaemon => write!(f, "daemon runs as a different user"),
            IpcErrors::FailedToRead => write!(f, "failed to read from the socket"),
            IpcErrors::FailedToWrite => write!(f, "failed to write to the socket"),
            IpcErrors::Timeout => write!(f, "IPC timed out"),
            IpcErrors::FrameTooLarge => write!(f, "IPC frame is empty or too large"),
            IpcErrors::Malformed => write!(f, "malformed IPC message"),
            IpcErrors::Daemon(e) => write!(f, "daemon error: {e}"),
        }
    }
}

/// Errors the daemon reports back (one byte on the wire).
#[derive(Debug, PartialEq, Clone, Copy)]
#[repr(u8)]
pub enum DaemonError {
    /// The request was malformed.
    BadRequest = 0x01,
    /// Deriving a key from the password failed.
    KeyDerivationFailed = 0x02,
    /// Anything else went wrong inside the daemon.
    Internal = 0x03,
    /// Unlock: the data password doesn't open the vault.
    WrongPassword = 0x04,
    /// The vault is locked: unlock it first.
    Locked = 0x05,
    /// The keychain or the vault file failed; the change was not saved.
    StorageFailed = 0x06,
    /// Nothing is saved yet (no vault), so there is nothing to unlock or log into.
    NotSaved = 0x07,
    /// A new password is shorter than [`MIN_NEW_PASSWORD_LEN`].
    WeakPassword = 0x08,
    /// Unlock: too many wrong data passwords, try again later (refused before
    /// any key derivation; `Status` says how long to wait).
    UnlockDelayed = 0x09,
    /// AddDevice: networking isn't running (Sync off, or the keys aren't
    /// saved and unlocked).
    NetworkOff = 0x0A,
    /// AnswerPairing: no pairing with this id is waiting (answered already,
    /// or it timed out).
    PairingExpired = 0x0B,
}

impl DaemonError {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::BadRequest),
            0x02 => Some(Self::KeyDerivationFailed),
            0x03 => Some(Self::Internal),
            0x04 => Some(Self::WrongPassword),
            0x05 => Some(Self::Locked),
            0x06 => Some(Self::StorageFailed),
            0x07 => Some(Self::NotSaved),
            0x08 => Some(Self::WeakPassword),
            0x09 => Some(Self::UnlockDelayed),
            0x0A => Some(Self::NetworkOff),
            0x0B => Some(Self::PairingExpired),
            _ => None,
        }
    }
}

impl fmt::Display for DaemonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DaemonError::BadRequest => write!(f, "bad request"),
            DaemonError::KeyDerivationFailed => write!(f, "key derivation failed"),
            DaemonError::Internal => write!(f, "internal error"),
            DaemonError::WrongPassword => write!(f, "wrong data password"),
            DaemonError::Locked => write!(f, "locked: enter the data password first"),
            DaemonError::StorageFailed => write!(f, "saving to the keychain / vault failed"),
            DaemonError::NotSaved => write!(f, "nothing is saved yet"),
            DaemonError::WeakPassword => write!(
                f,
                "password too short (at least {MIN_NEW_PASSWORD_LEN} characters)"
            ),
            DaemonError::UnlockDelayed => {
                write!(f, "too many wrong data passwords, try again later")
            }
            DaemonError::NetworkOff => {
                write!(
                    f,
                    "networking is off: turn Sync on (needs saved, unlocked keys)"
                )
            }
            DaemonError::PairingExpired => write!(f, "that pairing request is no longer waiting"),
        }
    }
}

/// A password for the daemon to derive a key from. Wiped on drop.
/// No `Debug` / `Clone`: it must not end up in logs or in a second copy.
pub struct PasswordUpdate {
    /// The password, exactly as typed (never trimmed), wiped on drop.
    pub password: Zeroizing<Vec<u8>>,
}

/// A request from the UI to the daemon.
pub enum Request {
    /// What is configured / running.
    Status,
    /// Derive and set `a_key`.
    SetAuthPassword(PasswordUpdate),
    /// Derive and set `d_key`.
    SetDataPassword(PasswordUpdate),
    /// Paired devices.
    ListPeers,
    /// Open the saved vault with the data password (after a restart).
    Unlock(PasswordUpdate),
    /// Keep `d_key` in the OS keychain (`true`) or delete it from there.
    SetAutoLogin(bool),
    /// Turn networking on (`true`: listener, "Add device") or off; saved.
    SetSync(bool),
    /// Open the "Add device" window: search the LAN and pair.
    AddDevice,
    /// The pairing waiting for the user's answer, if any.
    PendingPairing,
    /// The user's answer to the pairing `id` (`true` = the codes match).
    AnswerPairing { id: u32, accept: bool },
}

/// Daemon status (contains no key material).
#[derive(Debug, PartialEq, Clone, Copy, Default)]
pub struct Status {
    pub auth_key_set: bool,
    pub data_key_set: bool,
    pub network_running: bool,
    pub trusted_peers: u32,
    /// A saved vault exists but isn't open yet.
    pub locked: bool,
    /// The keys are saved in the encrypted vault.
    pub saved: bool,
    /// `d_key` is kept in the OS keychain (automatic login).
    pub auto_login: bool,
    /// Seconds until `Unlock` is accepted again (0 = now).
    pub unlock_wait_secs: u16,
    /// The Sync switch is on (networking wanted; see `network_running`).
    pub sync_enabled: bool,
    /// The "Add device" window is open.
    pub adding_device: bool,
    /// Pairings waiting for the user's answer.
    pub pending_pairings: u8,
}

/// A pairing waiting for the user (public data only: the handshake hash
/// it comes from stays in the daemon).
#[derive(Debug, PartialEq, Clone)]
pub struct PairingPrompt {
    /// Which pairing an answer is for.
    pub id: u32,
    /// The other device's display name (its address for now).
    pub name: String,
    /// The code to compare with the other device, see [`pairing_code`].
    pub code: PairingCode,
}

/// A paired device as shown to the user (public data only).
#[derive(Debug, PartialEq, Clone)]
pub struct PeerInfo {
    /// First [`FINGERPRINT_LEN`] bytes of the peer's static public key.
    pub fingerprint: [u8; FINGERPRINT_LEN],
    /// Display name (at most 255 bytes of UTF-8).
    pub name: String,
}

/// A successful answer from the daemon.
#[derive(Debug, PartialEq, Clone)]
pub enum Response {
    /// Answer to [`Request::Status`].
    Status(Status),
    /// Answer to `SetAuthPassword` / `SetDataPassword`.
    Done,
    /// Answer to [`Request::ListPeers`].
    Peers(Vec<PeerInfo>),
    /// Answer to [`Request::PendingPairing`].
    Pairing(Option<PairingPrompt>),
}

/// Parses a one-byte on/off payload: exactly `0x00` or `0x01`.
fn parse_flag(payload: &[u8]) -> Option<bool> {
    match payload {
        [0x00] => Some(false),
        [0x01] => Some(true),
        _ => None,
    }
}

/// `name` cut to at most 255 bytes, on a char boundary.
fn short_name(name: &str) -> &[u8] {
    let mut end = name.len().min(255);
    while !name.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    name.as_bytes().get(..end).unwrap_or_default()
}

/// Parses a `password` payload.
fn parse_password_update(password: &[u8]) -> Option<PasswordUpdate> {
    if password.is_empty() || password.len() > MAX_PASSWORD_LEN {
        return None;
    }

    Some(PasswordUpdate {
        password: Zeroizing::new(password.to_vec()),
    })
}

impl Request {
    /// Encodes the request body. Zeroizing: it may contain a password.
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let (kind, update) = match self {
            Request::Status => (REQ_STATUS, None),
            Request::SetAuthPassword(u) => (REQ_SET_AUTH_PASSWORD, Some(u)),
            Request::SetDataPassword(u) => (REQ_SET_DATA_PASSWORD, Some(u)),
            Request::ListPeers => (REQ_LIST_PEERS, None),
            Request::Unlock(u) => (REQ_UNLOCK, Some(u)),
            Request::SetAutoLogin(on) => {
                return Zeroizing::new(vec![REQ_SET_AUTO_LOGIN, u8::from(*on)]);
            }
            Request::SetSync(on) => return Zeroizing::new(vec![REQ_SET_SYNC, u8::from(*on)]),
            Request::AddDevice => (REQ_ADD_DEVICE, None),
            Request::PendingPairing => (REQ_PENDING_PAIRING, None),
            Request::AnswerPairing { id, accept } => {
                let mut body = Zeroizing::new(Vec::with_capacity(6));
                body.push(REQ_ANSWER_PAIRING);
                body.extend_from_slice(&id.to_le_bytes());
                body.push(u8::from(*accept));
                return body;
            }
        };

        // sized up front so the buffer holding the password never reallocates
        let len = update.map_or(0, |u| u.password.len());
        let mut body = Zeroizing::new(Vec::with_capacity(len.saturating_add(1)));

        body.push(kind);

        if let Some(update) = update {
            body.extend_from_slice(&update.password);
        }

        body
    }

    /// Decodes a request body; anything not exactly well-formed is `None`.
    pub fn decode(body: &[u8]) -> Option<Self> {
        let (&kind, payload) = body.split_first()?;

        match kind {
            REQ_STATUS if payload.is_empty() => Some(Request::Status),
            REQ_LIST_PEERS if payload.is_empty() => Some(Request::ListPeers),
            REQ_SET_AUTH_PASSWORD => parse_password_update(payload).map(Request::SetAuthPassword),
            REQ_SET_DATA_PASSWORD => parse_password_update(payload).map(Request::SetDataPassword),
            REQ_UNLOCK => parse_password_update(payload).map(Request::Unlock),
            REQ_SET_AUTO_LOGIN => parse_flag(payload).map(Request::SetAutoLogin),
            REQ_SET_SYNC => parse_flag(payload).map(Request::SetSync),
            REQ_ADD_DEVICE if payload.is_empty() => Some(Request::AddDevice),
            REQ_PENDING_PAIRING if payload.is_empty() => Some(Request::PendingPairing),
            REQ_ANSWER_PAIRING => match payload {
                [a, b, c, d, accept] => Some(Request::AnswerPairing {
                    id: u32::from_le_bytes([*a, *b, *c, *d]),
                    accept: parse_flag(&[*accept])?,
                }),
                _ => None,
            },
            _ => None,
        }
    }
}

impl Response {
    /// Encodes a successful response body.
    pub fn encode(&self) -> Vec<u8> {
        let mut body = vec![RESP_OK];

        match self {
            Response::Status(s) => {
                let flags = u8::from(s.auth_key_set)
                    | u8::from(s.data_key_set) << 1
                    | u8::from(s.network_running) << 2
                    | u8::from(s.locked) << 3
                    | u8::from(s.saved) << 4
                    | u8::from(s.auto_login) << 5
                    | u8::from(s.sync_enabled) << 6
                    | u8::from(s.adding_device) << 7;

                body.push(flags);
                body.extend_from_slice(&s.trusted_peers.to_le_bytes());
                body.extend_from_slice(&s.unlock_wait_secs.to_le_bytes());
                body.push(s.pending_pairings);
            }
            Response::Done => {}
            Response::Pairing(None) => body.push(0x00),
            Response::Pairing(Some(prompt)) => {
                let name = short_name(&prompt.name);
                body.push(0x01);
                body.extend_from_slice(&prompt.id.to_le_bytes());
                body.extend_from_slice(&prompt.code);
                body.push(u8::try_from(name.len()).unwrap_or(0));
                body.extend_from_slice(name);
            }
            Response::Peers(peers) => {
                let peers = peers.get(..MAX_LISTED_PEERS).unwrap_or(peers);
                let count = u16::try_from(peers.len()).unwrap_or(u16::MAX);

                body.extend_from_slice(&count.to_le_bytes());

                for peer in peers.iter().take(usize::from(count)) {
                    // names are cut at 255 bytes, on a char boundary
                    let name = short_name(&peer.name);

                    body.extend_from_slice(&peer.fingerprint);
                    body.push(u8::try_from(name.len()).unwrap_or(0));
                    body.extend_from_slice(name);
                }
            }
        }

        body
    }

    /// Encodes an error response body.
    pub fn encode_error(error: DaemonError) -> Vec<u8> {
        vec![RESP_ERR, error as u8]
    }

    /// Decodes a response body for the request `kind` it answers.
    fn decode(request: &Request, body: &[u8]) -> Result<Self, IpcErrors> {
        let (&status, payload) = body.split_first().ok_or(IpcErrors::Malformed)?;

        if status == RESP_ERR {
            let code = match payload {
                [code] => *code,
                _ => return Err(IpcErrors::Malformed),
            };
            return Err(IpcErrors::Daemon(
                DaemonError::from_u8(code).ok_or(IpcErrors::Malformed)?,
            ));
        }

        if status != RESP_OK {
            return Err(IpcErrors::Malformed);
        }

        match request {
            Request::Status => {
                let (flags, peers, unlock_wait_secs, pending_pairings) = match payload {
                    [flags, a, b, c, d, w0, w1, pending] => (
                        *flags,
                        u32::from_le_bytes([*a, *b, *c, *d]),
                        u16::from_le_bytes([*w0, *w1]),
                        *pending,
                    ),
                    _ => return Err(IpcErrors::Malformed),
                };

                Ok(Response::Status(Status {
                    auth_key_set: flags & 0b001 != 0,
                    data_key_set: flags & 0b010 != 0,
                    network_running: flags & 0b100 != 0,
                    locked: flags & 0b1000 != 0,
                    saved: flags & 0b1_0000 != 0,
                    auto_login: flags & 0b10_0000 != 0,
                    sync_enabled: flags & 0b100_0000 != 0,
                    adding_device: flags & 0b1000_0000 != 0,
                    trusted_peers: peers,
                    unlock_wait_secs,
                    pending_pairings,
                }))
            }
            Request::SetAuthPassword(_)
            | Request::SetDataPassword(_)
            | Request::Unlock(_)
            | Request::SetAutoLogin(_)
            | Request::SetSync(_)
            | Request::AddDevice
            | Request::AnswerPairing { .. }
                if payload.is_empty() =>
            {
                Ok(Response::Done)
            }
            Request::SetAuthPassword(_)
            | Request::SetDataPassword(_)
            | Request::Unlock(_)
            | Request::SetAutoLogin(_)
            | Request::SetSync(_)
            | Request::AddDevice
            | Request::AnswerPairing { .. } => Err(IpcErrors::Malformed),
            Request::ListPeers => decode_peers(payload).ok_or(IpcErrors::Malformed),
            Request::PendingPairing => decode_pairing(payload).ok_or(IpcErrors::Malformed),
        }
    }
}

/// Parses the `ListPeers` payload; `None` unless it is consumed exactly.
fn decode_peers(payload: &[u8]) -> Option<Response> {
    let (count, mut rest) = payload.split_first_chunk::<2>()?;
    let count = usize::from(u16::from_le_bytes(*count));

    if count > MAX_LISTED_PEERS {
        return None;
    }

    let mut peers = Vec::with_capacity(count);

    for _ in 0..count {
        let (fingerprint, after) = rest.split_first_chunk::<FINGERPRINT_LEN>()?;
        let (&name_len, after) = after.split_first()?;
        let name = after.get(..usize::from(name_len))?;

        peers.push(PeerInfo {
            fingerprint: *fingerprint,
            name: String::from_utf8(name.to_vec()).ok()?,
        });

        rest = after.get(usize::from(name_len)..)?;
    }

    rest.is_empty().then_some(Response::Peers(peers))
}

/// Parses the `PendingPairing` payload; `None` unless it is consumed exactly,
/// the code is in the table and the name is printable (it goes to a terminal).
fn decode_pairing(payload: &[u8]) -> Option<Response> {
    let (&present, rest) = payload.split_first()?;

    match present {
        0x00 if rest.is_empty() => Some(Response::Pairing(None)),
        0x01 => {
            let (id, rest) = rest.split_first_chunk::<4>()?;
            let (code, rest) = rest.split_first_chunk::<PAIRING_CODE_LEN>()?;
            let (&name_len, name) = rest.split_first()?;

            if name.len() != usize::from(name_len) || !pairing_code::is_valid(code) {
                return None;
            }

            let name = std::str::from_utf8(name).ok()?;
            if name.chars().any(char::is_control) {
                return None;
            }

            Some(Response::Pairing(Some(PairingPrompt {
                id: u32::from_le_bytes(*id),
                name: name.to_owned(),
                code: *code,
            })))
        }
        _ => None,
    }
}

/// Writes one frame (`length || body`), each write bounded by [`IO_TIMEOUT`].
pub async fn write_frame<S: AsyncWrite + Unpin>(
    stream: &mut S,
    body: &[u8],
) -> Result<(), IpcErrors> {
    let len = u32::try_from(body.len()).map_err(|_| IpcErrors::FrameTooLarge)?;

    if len == 0 || len > MAX_FRAME_LEN {
        return Err(IpcErrors::FrameTooLarge);
    }

    timeout(IO_TIMEOUT, stream.write_all(&len.to_le_bytes()))
        .await
        .map_err(|_| IpcErrors::Timeout)?
        .map_err(|_| IpcErrors::FailedToWrite)?;

    timeout(IO_TIMEOUT, stream.write_all(body))
        .await
        .map_err(|_| IpcErrors::Timeout)?
        .map_err(|_| IpcErrors::FailedToWrite)?;

    timeout(IO_TIMEOUT, stream.flush())
        .await
        .map_err(|_| IpcErrors::Timeout)?
        .map_err(|_| IpcErrors::FailedToWrite)
}

/// Reads one frame. The length is checked before allocating; the body is
/// zeroizing because a request may carry a password.
pub async fn read_frame<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<Zeroizing<Vec<u8>>, IpcErrors> {
    let mut len = [0u8; 4];

    timeout(IO_TIMEOUT, stream.read_exact(&mut len))
        .await
        .map_err(|_| IpcErrors::Timeout)?
        .map_err(|_| IpcErrors::FailedToRead)?;

    let len = u32::from_le_bytes(len);

    if len == 0 || len > MAX_FRAME_LEN {
        return Err(IpcErrors::FrameTooLarge);
    }

    let len = usize::try_from(len).map_err(|_| IpcErrors::FrameTooLarge)?;
    let mut body = Zeroizing::new(vec![0u8; len]);

    timeout(IO_TIMEOUT, stream.read_exact(&mut body))
        .await
        .map_err(|_| IpcErrors::Timeout)?
        .map_err(|_| IpcErrors::FailedToRead)?;

    Ok(body)
}

/// Checks that `dir` is a real directory (not a symlink), owned by us and not
/// accessible by anyone else (`0700`).
#[cfg(unix)]
pub fn check_private_dir(dir: &Path) -> Result<(), IpcErrors> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let meta = std::fs::symlink_metadata(dir).map_err(|_| IpcErrors::FailedToPrepareSocket)?;

    if !meta.file_type().is_dir()
        || meta.uid() != nix::unistd::geteuid().as_raw()
        || meta.permissions().mode() & 0o077 != 0
    {
        return Err(IpcErrors::InsecureDirectory);
    }

    Ok(())
}

/// The per-user base directory the private socket directory goes into.
#[cfg(unix)]
fn base_dir() -> Result<PathBuf, IpcErrors> {
    if cfg!(target_os = "macos") {
        // per-user /var/folders/.../T/, private to the user
        Ok(std::env::temp_dir())
    } else {
        // /run/user/<uid>, private to the user; no fallback to a shared /tmp
        std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .ok_or(IpcErrors::NoRuntimeDir)
    }
}

/// Creates (if needed) and checks the private socket directory under `base`
/// and returns the socket path inside it.
#[cfg(unix)]
pub fn prepare_socket_dir(base: &Path) -> Result<PathBuf, IpcErrors> {
    use std::os::unix::fs::DirBuilderExt;

    let dir = base.join(DIR_NAME);

    match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(IpcErrors::FailedToPrepareSocket),
    }

    // also catches a directory someone else created before us
    check_private_dir(&dir)?;

    Ok(dir.join(SOCKET_NAME))
}

/// Path of the daemon socket (the directory is created and checked).
#[cfg(unix)]
pub fn socket_path() -> Result<PathBuf, IpcErrors> {
    prepare_socket_dir(&base_dir()?)
}

/// Path of the daemon socket: not supported on this platform yet.
#[cfg(not(unix))]
pub fn socket_path() -> Result<PathBuf, IpcErrors> {
    Err(IpcErrors::Unsupported)
}

/// Sends `request` to the daemon at `path` and returns its answer.
#[cfg(unix)]
pub async fn request_at(path: &Path, request: &Request) -> Result<Response, IpcErrors> {
    request_at_checked(path, request, DAEMON_CODE_REQUIREMENT).await
}

/// [`request_at`] with an explicit daemon code requirement (tests).
#[cfg(unix)]
async fn request_at_checked(
    path: &Path,
    request: &Request,
    daemon_requirement: Option<&'static str>,
) -> Result<Response, IpcErrors> {
    // the directory must still be private, or the socket could be someone else's
    check_private_dir(path.parent().ok_or(IpcErrors::FailedToPrepareSocket)?)?;

    let mut stream = timeout(IO_TIMEOUT, tokio::net::UnixStream::connect(path))
        .await
        .map_err(|_| IpcErrors::Timeout)?
        .map_err(|_| IpcErrors::FailedToConnect)?;

    // the password only goes to a daemon of our own user
    let daemon = stream.peer_cred().map_err(|_| IpcErrors::UntrustedDaemon)?;

    if daemon.uid() != nix::unistd::geteuid().as_raw() {
        return Err(IpcErrors::UntrustedDaemon);
    }

    // macOS: ...and only to a daemon signed as required (fails closed elsewhere)
    if let Some(requirement) = daemon_requirement {
        crate::code_signature::verify_peer(&stream, requirement)
            .await
            .map_err(|_| IpcErrors::UntrustedDaemon)?;
    }

    write_frame(&mut stream, &request.encode()).await?;

    let body = read_frame(&mut stream).await?;

    Response::decode(request, &body)
}

/// Sends `request` to the local daemon and returns its answer.
#[cfg(unix)]
pub async fn request(request: &Request) -> Result<Response, IpcErrors> {
    request_at(&socket_path()?, request).await
}

/// Sends `request` to the local daemon: not supported on this platform yet.
#[cfg(not(unix))]
pub async fn request(_request: &Request) -> Result<Response, IpcErrors> {
    Err(IpcErrors::Unsupported)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn update(password: &[u8]) -> PasswordUpdate {
        PasswordUpdate {
            password: Zeroizing::new(password.to_vec()),
        }
    }

    /// Test that every request kind round-trips
    #[test]
    fn test_request_roundtrip() {
        for req in [
            Request::Status,
            Request::ListPeers,
            Request::SetAuthPassword(update(b"hunter2")),
            Request::SetDataPassword(update(b"x")),
            // spaces are part of the password, never trimmed
            Request::SetAuthPassword(update(b" pass word ")),
            Request::Unlock(update(b"data password")),
            Request::SetAutoLogin(true),
            Request::SetAutoLogin(false),
            Request::SetSync(true),
            Request::SetSync(false),
            Request::AddDevice,
            Request::PendingPairing,
            Request::AnswerPairing {
                id: 0xDEAD_BEEF,
                accept: true,
            },
            Request::AnswerPairing {
                id: 0,
                accept: false,
            },
        ] {
            let decoded = Request::decode(&req.encode()).unwrap();
            assert_eq!(decoded.encode().as_slice(), req.encode().as_slice());
        }
    }

    /// Test that malformed requests are rejected
    #[test]
    fn test_request_rejects_malformed() {
        assert!(Request::decode(&[]).is_none());
        assert!(Request::decode(&[0x99]).is_none());
        assert!(Request::decode(&[REQ_STATUS, 0]).is_none());
        // empty password
        assert!(Request::decode(&[REQ_SET_AUTH_PASSWORD]).is_none());
        // retired version-1 kinds (salt || password) are refused, not misread
        for retired in [0x02u8, 0x03] {
            let v1 = [&[retired][..], &[7; 32], b"password"].concat();
            assert!(Request::decode(&v1).is_none());
        }
        // password too long
        let long = [
            &[REQ_SET_DATA_PASSWORD][..],
            &vec![b'a'; MAX_PASSWORD_LEN + 1],
        ]
        .concat();
        assert!(Request::decode(&long).is_none());
        // auto-login flag: exactly one byte, 0 or 1
        assert!(Request::decode(&[REQ_SET_AUTO_LOGIN]).is_none());
        assert!(Request::decode(&[REQ_SET_AUTO_LOGIN, 2]).is_none());
        assert!(Request::decode(&[REQ_SET_AUTO_LOGIN, 1, 0]).is_none());
        // empty unlock password
        assert!(Request::decode(&[REQ_UNLOCK]).is_none());
        // sync flag: exactly one byte, 0 or 1
        assert!(Request::decode(&[REQ_SET_SYNC]).is_none());
        assert!(Request::decode(&[REQ_SET_SYNC, 2]).is_none());
        assert!(Request::decode(&[REQ_SET_SYNC, 0, 0]).is_none());
        // payload-less requests take no payload
        assert!(Request::decode(&[REQ_ADD_DEVICE, 0]).is_none());
        assert!(Request::decode(&[REQ_PENDING_PAIRING, 0]).is_none());
        // answer: id (4) + exactly 0 or 1
        assert!(Request::decode(&[REQ_ANSWER_PAIRING, 1, 0, 0, 0]).is_none());
        assert!(Request::decode(&[REQ_ANSWER_PAIRING, 1, 0, 0, 0, 2]).is_none());
        assert!(Request::decode(&[REQ_ANSWER_PAIRING, 1, 0, 0, 0, 1, 0]).is_none());
        // longest allowed password still fits
        let max = [&[REQ_SET_DATA_PASSWORD][..], &vec![b'a'; MAX_PASSWORD_LEN]].concat();
        assert!(Request::decode(&max).is_some());
    }

    /// Test that every daemon error code round-trips, and unknown status bits are refused
    #[test]
    fn test_error_codes_and_status_bits() {
        for e in [
            DaemonError::BadRequest,
            DaemonError::KeyDerivationFailed,
            DaemonError::Internal,
            DaemonError::WrongPassword,
            DaemonError::Locked,
            DaemonError::StorageFailed,
            DaemonError::NotSaved,
            DaemonError::WeakPassword,
            DaemonError::UnlockDelayed,
            DaemonError::NetworkOff,
            DaemonError::PairingExpired,
        ] {
            assert_eq!(
                Response::decode(&Request::Status, &Response::encode_error(e)),
                Err(IpcErrors::Daemon(e))
            );
        }

        // unknown error codes are refused
        assert_eq!(
            Response::decode(&Request::Status, &[RESP_ERR, 0x0C]),
            Err(IpcErrors::Malformed)
        );

        // a version 2 (no unlock wait) or version 3 (no pending pairings)
        // status is refused, not misread
        assert_eq!(
            Response::decode(&Request::Status, &[RESP_OK, 0, 0, 0, 0, 0]),
            Err(IpcErrors::Malformed)
        );
        assert_eq!(
            Response::decode(&Request::Status, &[RESP_OK, 0, 0, 0, 0, 0, 0, 0]),
            Err(IpcErrors::Malformed)
        );
    }

    /// Test that the pairing answer round-trips and its decoding is strict
    #[test]
    fn test_pairing_prompt_roundtrip_and_strict() {
        for prompt in [
            None,
            Some(PairingPrompt {
                id: 7,
                name: "192.168.1.20:51234".into(),
                code: [0, 1, 2, 3, 60, 61, 62, 63],
            }),
        ] {
            let response = Response::Pairing(prompt);
            assert_eq!(
                Response::decode(&Request::PendingPairing, &response.encode()),
                Ok(response)
            );
        }

        let good = Response::Pairing(Some(PairingPrompt {
            id: 1,
            name: "ab".into(),
            code: [5; PAIRING_CODE_LEN],
        }))
        .encode();

        // truncated anywhere, or extra bytes
        for cut in 1..good.len() {
            assert_eq!(
                Response::decode(&Request::PendingPairing, &good[..cut]),
                Err(IpcErrors::Malformed),
                "cut at {cut}"
            );
        }
        let longer = [&good[..], &[0]].concat();
        assert_eq!(
            Response::decode(&Request::PendingPairing, &longer),
            Err(IpcErrors::Malformed)
        );

        // "none" with trailing bytes, an unknown marker
        for body in [&[RESP_OK, 0x00, 0x00][..], &[RESP_OK, 0x02]] {
            assert_eq!(
                Response::decode(&Request::PendingPairing, body),
                Err(IpcErrors::Malformed)
            );
        }

        // a symbol outside the table
        let mut bad_code = good.clone();
        bad_code[6] = 64;
        assert_eq!(
            Response::decode(&Request::PendingPairing, &bad_code),
            Err(IpcErrors::Malformed)
        );

        // a control character (terminal escape) in the name
        let mut escape = good.clone();
        let last = escape.len() - 1;
        escape[last] = 0x1b;
        assert_eq!(
            Response::decode(&Request::PendingPairing, &escape),
            Err(IpcErrors::Malformed)
        );

        // not UTF-8
        let mut not_utf8 = good;
        let last = not_utf8.len() - 1;
        not_utf8[last] = 0xff;
        assert_eq!(
            Response::decode(&Request::PendingPairing, &not_utf8),
            Err(IpcErrors::Malformed)
        );
    }

    /// Test that every response kind round-trips
    #[test]
    fn test_response_roundtrip() {
        let status = Response::Status(Status {
            auth_key_set: true,
            data_key_set: false,
            network_running: true,
            trusted_peers: 3,
            locked: false,
            saved: true,
            auto_login: true,
            unlock_wait_secs: 0x1234,
            sync_enabled: true,
            adding_device: true,
            pending_pairings: 3,
        });
        assert_eq!(
            Response::decode(&Request::Status, &status.encode()),
            Ok(status)
        );

        assert_eq!(
            Response::decode(
                &Request::SetAuthPassword(update(b"p")),
                &Response::Done.encode()
            ),
            Ok(Response::Done)
        );

        let peers = Response::Peers(vec![
            PeerInfo {
                fingerprint: [1; 8],
                name: "laptop".into(),
            },
            PeerInfo {
                fingerprint: [2; 8],
                name: String::new(),
            },
        ]);
        assert_eq!(
            Response::decode(&Request::ListPeers, &peers.encode()),
            Ok(peers)
        );
    }

    /// Test that long names are cut at a char boundary, not mid-character
    #[test]
    fn test_long_peer_name_cut_on_char_boundary() {
        let peers = Response::Peers(vec![PeerInfo {
            fingerprint: [0; 8],
            name: "ą".repeat(200),
        }]);

        let Ok(Response::Peers(decoded)) = Response::decode(&Request::ListPeers, &peers.encode())
        else {
            panic!("peers didn't decode");
        };
        assert_eq!(decoded[0].name, "ą".repeat(127));
    }

    /// Test that the biggest possible ListPeers answer fits in one frame
    #[tokio::test]
    async fn test_full_peer_list_fits_frame() {
        let peers = Response::Peers(vec![
            PeerInfo {
                fingerprint: [9; 8],
                name: "x".repeat(255)
            };
            MAX_LISTED_PEERS
        ]);
        let body = peers.encode();
        let (mut a, mut b) = tokio::io::duplex(1 << 20);

        write_frame(&mut a, &body).await.unwrap();
        let read = read_frame(&mut b).await.unwrap();

        assert_eq!(Response::decode(&Request::ListPeers, &read), Ok(peers));
    }

    /// Test that error responses map to DaemonError
    #[test]
    fn test_error_response() {
        let body = Response::encode_error(DaemonError::KeyDerivationFailed);
        assert_eq!(
            Response::decode(&Request::Status, &body),
            Err(IpcErrors::Daemon(DaemonError::KeyDerivationFailed))
        );
    }

    /// Test that random bytes never panic the decoders (cheap fuzzing)
    #[test]
    fn test_decoders_never_panic_on_random_input() {
        let mut seed = 0x2545_F491_4F6C_DD1Du64;

        for _ in 0..20_000 {
            // xorshift, deterministic
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let len = usize::try_from(seed % 64).unwrap();
            let bytes: Vec<u8> = (0..len)
                .map(|i| seed.rotate_left(u32::try_from(i).unwrap()).to_le_bytes()[0])
                .collect();

            let _ = Request::decode(&bytes);
            let _ = Response::decode(&Request::Status, &bytes);
            let _ = Response::decode(&Request::ListPeers, &bytes);
            let _ = Response::decode(&Request::PendingPairing, &bytes);
        }
    }

    /// Test that frames past MAX_FRAME_LEN are refused before allocating
    #[tokio::test]
    async fn test_oversized_frame_rejected() {
        let (mut a, mut b) = tokio::io::duplex(64);

        let header = (MAX_FRAME_LEN + 1).to_le_bytes();
        a.write_all(&header).await.unwrap();

        assert_eq!(
            read_frame(&mut b).await.err(),
            Some(IpcErrors::FrameTooLarge)
        );
        assert_eq!(
            write_frame(&mut a, &[]).await.err(),
            Some(IpcErrors::FrameTooLarge)
        );
    }

    /// Test that a peer that never sends times out
    #[tokio::test(start_paused = true)]
    async fn test_silent_peer_times_out() {
        let (_a, mut b) = tokio::io::duplex(64);
        assert_eq!(read_frame(&mut b).await.err(), Some(IpcErrors::Timeout));
    }

    /// Test that the UI checks the daemon's code signature before sending
    /// anything (macOS; the test binary is not Apple-signed)
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn test_daemon_code_requirement_checked() {
        let base = std::env::temp_dir().join(format!("cesa-ipc-sig-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        let path = prepare_socket_dir(&base).unwrap();
        let listener = tokio::net::UnixListener::bind(&path).unwrap();

        // fake daemon: answers Status, records whether it got any bytes
        let server = tokio::spawn(async move {
            let mut got_bytes = Vec::new();
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let body = read_frame(&mut stream).await;
                got_bytes.push(body.is_ok());
                if body.is_ok() {
                    let status = Response::Status(Status {
                        auth_key_set: false,
                        data_key_set: false,
                        network_running: false,
                        trusted_peers: 0,
                        ..Status::default()
                    });
                    write_frame(&mut stream, &status.encode()).await.unwrap();
                }
            }
            got_bytes
        });

        let password = Request::SetAuthPassword(update(b"secret"));

        // requirement not met: refused before a single byte is sent
        assert_eq!(
            request_at_checked(&path, &password, Some("anchor apple"))
                .await
                .err(),
            Some(IpcErrors::UntrustedDaemon)
        );
        // requirement met: served
        assert!(
            request_at_checked(&path, &Request::Status, Some("! anchor apple"))
                .await
                .is_ok()
        );

        assert_eq!(server.await.unwrap(), vec![false, true]);
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// Test that the socket directory is created private and checked
    #[cfg(unix)]
    #[test]
    fn test_socket_dir_private() {
        use std::os::unix::fs::PermissionsExt;

        let base = std::env::temp_dir().join(format!("cesa-ipc-test-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();

        let path = prepare_socket_dir(&base).unwrap();
        let dir = path.parent().unwrap();
        assert_eq!(
            std::fs::metadata(dir).unwrap().permissions().mode() & 0o777,
            0o700
        );

        // someone opened it up: refuse
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            prepare_socket_dir(&base).err(),
            Some(IpcErrors::InsecureDirectory)
        );

        // a symlink in its place: refuse
        std::fs::remove_dir(dir).unwrap();
        std::os::unix::fs::symlink(&base, dir).unwrap();
        assert_eq!(
            prepare_socket_dir(&base).err(),
            Some(IpcErrors::InsecureDirectory)
        );

        std::fs::remove_file(dir).unwrap();
        std::fs::remove_dir(&base).unwrap();
    }
}
