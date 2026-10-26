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
//!
//! Wire format (version 1), one request and one response per connection:
//! `frame = length (u32 LE, 1..=MAX_FRAME_LEN) || body`
//!
//! Request body: `kind (1) || payload`
//! * `0x01` Status
//! * `0x02` SetAuthPassword: `password (1..=MAX_PASSWORD_LEN)`; the daemon
//!   picks the salt
//! * `0x03` SetDataPassword: same
//! * `0x04` ListPeers
//!
//! Response body: `0x00 || payload` on success, `0x01 || error code (1)` on error
//! * Status: `flags (1) || trusted peers (u32 LE)`; flags bit 0 = auth key set,
//!   bit 1 = data key set, bit 2 = network running
//! * SetAuthPassword / SetDataPassword: empty
//! * ListPeers: `count (u16 LE) || count * (fingerprint (8) || name len (1) || name)`

use core::fmt;
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;
use zeroize::Zeroizing;

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

/// Socket file name inside the private directory.
const SOCKET_NAME: &str = "daemon.sock";
/// Private directory name inside the per-user runtime/temp directory.
const DIR_NAME: &str = "cesaconn";

/* request kinds */
const REQ_STATUS: u8 = 0x01;
const REQ_SET_AUTH_PASSWORD: u8 = 0x02;
const REQ_SET_DATA_PASSWORD: u8 = 0x03;
const REQ_LIST_PEERS: u8 = 0x04;

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
    /// The process behind the socket runs as a different user.
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
}

impl DaemonError {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::BadRequest),
            0x02 => Some(Self::KeyDerivationFailed),
            0x03 => Some(Self::Internal),
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
}

/// Daemon status (contains no key material).
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct Status {
    pub auth_key_set: bool,
    pub data_key_set: bool,
    pub network_running: bool,
    pub trusted_peers: u32,
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
                    | u8::from(s.network_running) << 2;

                body.push(flags);
                body.extend_from_slice(&s.trusted_peers.to_le_bytes());
            }
            Response::Done => {}
            Response::Peers(peers) => {
                let peers = peers.get(..MAX_LISTED_PEERS).unwrap_or(peers);
                let count = u16::try_from(peers.len()).unwrap_or(u16::MAX);

                body.extend_from_slice(&count.to_le_bytes());

                for peer in peers.iter().take(usize::from(count)) {
                    // names are cut at 255 bytes, on a char boundary
                    let mut end = peer.name.len().min(255);
                    while !peer.name.is_char_boundary(end) {
                        end = end.saturating_sub(1);
                    }
                    let name = peer.name.as_bytes().get(..end).unwrap_or_default();

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
                let (flags, peers) = match payload {
                    [flags, a, b, c, d] => (*flags, u32::from_le_bytes([*a, *b, *c, *d])),
                    _ => return Err(IpcErrors::Malformed),
                };

                if flags & !0b111 != 0 {
                    return Err(IpcErrors::Malformed);
                }

                Ok(Response::Status(Status {
                    auth_key_set: flags & 0b001 != 0,
                    data_key_set: flags & 0b010 != 0,
                    network_running: flags & 0b100 != 0,
                    trusted_peers: peers,
                }))
            }
            Request::SetAuthPassword(_) | Request::SetDataPassword(_) if payload.is_empty() => {
                Ok(Response::Done)
            }
            Request::SetAuthPassword(_) | Request::SetDataPassword(_) => Err(IpcErrors::Malformed),
            Request::ListPeers => decode_peers(payload).ok_or(IpcErrors::Malformed),
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
        // password too long
        let long = [
            &[REQ_SET_DATA_PASSWORD][..],
            &vec![b'a'; MAX_PASSWORD_LEN + 1],
        ]
        .concat();
        assert!(Request::decode(&long).is_none());
        // longest allowed password still fits
        let max = [&[REQ_SET_DATA_PASSWORD][..], &vec![b'a'; MAX_PASSWORD_LEN]].concat();
        assert!(Request::decode(&max).is_some());
    }

    /// Test that every response kind round-trips
    #[test]
    fn test_response_roundtrip() {
        let status = Response::Status(Status {
            auth_key_set: true,
            data_key_set: false,
            network_running: true,
            trusted_peers: 3,
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
