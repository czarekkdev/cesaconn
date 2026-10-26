//! The daemon's end of the UI IPC (protocol and client: `cesa_conn_system::ipc`).
//!
//! Every connection must pass, in this order, before a single byte is read:
//! 1. the peer is a process of the same user (kernel peer credentials)
//! 2. macOS: the peer's code signature satisfies [`CODE_REQUIREMENT`]
//!    (looked up by audit token, so a recycled pid can't be confused with it)
//!
//! Then one request is read (bounded, zeroizing), handled and answered.
//! At most [`MAX_CONCURRENT_CLIENTS`] connections are served at once and each
//! one has [`REQUEST_DEADLINE`] in total.

use std::future::Future;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{UnixListener, UnixStream};
use tokio::select;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use cesa_conn_system::{
    code_signature,
    ipc::{DaemonError, Request, Response, read_frame, write_frame},
};

/// Most UI connections handled at the same time (password derivation is
/// expensive, so this stays small).
pub const MAX_CONCURRENT_CLIENTS: usize = 4;

/// Total time one connection may take, verification included.
pub const REQUEST_DEADLINE: Duration = Duration::from_secs(10);

/// Pause after a failed `accept` (e.g. no file descriptors left).
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// Code requirement every macOS client must satisfy, fixed at build time:
/// `CESA_IPC_CODE_REQUIREMENT='anchor apple generic and certificate
/// leaf[subject.OU] = "TEAMID" and identifier "dev.czarekk.cesaconn.tui"' cargo build`
///
/// Only meaningful with a Developer ID signature and the hardened runtime on
/// the client (otherwise code can be injected into it). Unset: the uid check
/// is the only gate and the daemon says so loudly at startup.
pub const CODE_REQUIREMENT: Option<&str> = option_env!("CESA_IPC_CODE_REQUIREMENT");

/// All errors of the IPC server.
#[derive(Debug, PartialEq)]
pub enum IpcServerErrors {
    /// Something that isn't our socket sits at the socket path.
    SocketPathTaken,
    /// Another daemon already listens on the socket.
    AlreadyRunning,
    /// Removing a stale socket, binding or setting permissions failed.
    FailedToBind,
    /// The peer's credentials couldn't be read.
    FailedToGetPeerCred,
    /// The peer runs as a different user.
    WrongUser,
    /// The peer's code signature couldn't be checked or doesn't satisfy the requirement.
    UntrustedCode,
    /// The build-time code requirement doesn't parse.
    InvalidCodeRequirement,
}

impl std::fmt::Display for IpcServerErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpcServerErrors::SocketPathTaken => write!(f, "socket path is taken by something else"),
            IpcServerErrors::AlreadyRunning => write!(f, "another daemon is already running"),
            IpcServerErrors::FailedToBind => write!(f, "failed to bind the IPC socket"),
            IpcServerErrors::FailedToGetPeerCred => write!(f, "failed to read peer credentials"),
            IpcServerErrors::WrongUser => write!(f, "peer runs as a different user"),
            IpcServerErrors::UntrustedCode => {
                write!(f, "peer's code signature doesn't satisfy the requirement")
            }
            IpcServerErrors::InvalidCodeRequirement => {
                write!(f, "CESA_IPC_CODE_REQUIREMENT doesn't parse")
            }
        }
    }
}

/// Who may talk to the daemon.
#[derive(Clone, Copy)]
pub struct ClientPolicy {
    /// macOS code requirement; `None` = uid check only.
    requirement: Option<&'static str>,
}

impl ClientPolicy {
    /// The policy this binary was built with, validated once at startup.
    pub fn from_build() -> Result<Self, IpcServerErrors> {
        Self::new(CODE_REQUIREMENT)
    }

    /// A policy with an explicit requirement (tests, or [`Self::from_build`]).
    pub fn new(requirement: Option<&'static str>) -> Result<Self, IpcServerErrors> {
        match requirement {
            Some(requirement) => {
                code_signature::validate_requirement(requirement)
                    .map_err(|_| IpcServerErrors::InvalidCodeRequirement)?;
                info!(
                    requirement,
                    "IPC clients must satisfy this code requirement"
                );
            }
            None if cfg!(target_os = "macos") => {
                // loud on purpose: a release build should never look like this
                error!(
                    "IPC CLIENT SIGNATURE CHECK DISABLED: built without \
                     CESA_IPC_CODE_REQUIREMENT, any process of this user can control the daemon"
                );
            }
            None => {
                warn!("no OS code signing on this platform: IPC clients are checked by uid only");
            }
        }

        Ok(Self { requirement })
    }

    /// Runs every check on a new connection.
    async fn verify(&self, stream: &UnixStream) -> Result<(), IpcServerErrors> {
        let cred = stream
            .peer_cred()
            .map_err(|_| IpcServerErrors::FailedToGetPeerCred)?;

        if cred.uid() != nix::unistd::geteuid().as_raw() {
            return Err(IpcServerErrors::WrongUser);
        }

        if let Some(requirement) = self.requirement {
            code_signature::verify_peer(stream, requirement)
                .await
                .map_err(|_| IpcServerErrors::UntrustedCode)?;
        }

        Ok(())
    }
}

/// Binds the daemon socket at `path` (its directory must already be private).
///
/// An old socket file is only removed if it is a socket owned by us that
/// nobody listens on; anything else at the path is an error.
pub fn bind(path: &Path) -> Result<UnixListener, IpcServerErrors> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};

    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if !meta.file_type().is_socket() || meta.uid() != nix::unistd::geteuid().as_raw() {
            return Err(IpcServerErrors::SocketPathTaken);
        }

        if std::os::unix::net::UnixStream::connect(path).is_ok() {
            return Err(IpcServerErrors::AlreadyRunning);
        }

        std::fs::remove_file(path).map_err(|_| IpcServerErrors::FailedToBind)?;
    }

    let listener = UnixListener::bind(path).map_err(|_| IpcServerErrors::FailedToBind)?;

    // the directory is 0700 already, this is defence in depth
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|_| IpcServerErrors::FailedToBind)?;

    Ok(listener)
}

/// Verifies the peer, reads one request, answers it.
async fn serve_client<H, F>(
    mut stream: UnixStream,
    policy: ClientPolicy,
    handler: H,
) -> Result<(), IpcServerErrors>
where
    H: Fn(Request) -> F,
    F: Future<Output = Vec<u8>>,
{
    // 1. + 2. before reading anything from the peer
    policy.verify(&stream).await?;

    let Ok(body) = read_frame(&mut stream).await else {
        debug!("IPC client sent no valid frame");
        return Ok(());
    };

    let response = match Request::decode(&body) {
        Some(request) => handler(request).await,
        None => Response::encode_error(DaemonError::BadRequest),
    };

    if write_frame(&mut stream, &response).await.is_err() {
        debug!("IPC client went away before the answer");
    }

    Ok(())
}

/// Accepts UI connections until `cancellation_token` fires.
///
/// `handler` answers one decoded request with an encoded response body.
pub async fn serve<H, F>(
    listener: UnixListener,
    policy: ClientPolicy,
    handler: H,
    cancellation_token: CancellationToken,
) where
    H: Fn(Request) -> F + Clone + Send + Sync + 'static,
    F: Future<Output = Vec<u8>> + Send,
{
    let slots = Arc::new(Semaphore::new(MAX_CONCURRENT_CLIENTS));

    loop {
        let stream = select! {
            _ = cancellation_token.cancelled() => {
                info!("IPC server shutting down");
                return;
            }
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => stream,
                Err(e) => {
                    // e.g. out of file descriptors: back off instead of spinning
                    error!(error = %e, "IPC accept failed");
                    tokio::time::sleep(ACCEPT_BACKOFF).await;
                    continue;
                }
            }
        };

        // full: close at once instead of queueing
        let Ok(slot) = slots.clone().try_acquire_owned() else {
            warn!(
                max = MAX_CONCURRENT_CLIENTS,
                "too many IPC clients, dropping one"
            );
            drop(stream);
            continue;
        };

        let handler = handler.clone();

        tokio::spawn(async move {
            let _slot = slot;

            match timeout(REQUEST_DEADLINE, serve_client(stream, policy, handler)).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => warn!(error = %e, "IPC client rejected"),
                Err(_) => warn!("IPC client hit the request deadline"),
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cesa_conn_system::ipc::{IpcErrors, Status, prepare_socket_dir, request_at};
    use std::path::PathBuf;

    /// A private socket directory unique to one test.
    fn test_socket(name: &str) -> PathBuf {
        let base = std::env::temp_dir().join(format!("cesa-ipcd-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        prepare_socket_dir(&base).unwrap()
    }

    /// Answers every request with a fixed status.
    async fn status_handler(_request: Request) -> Vec<u8> {
        Response::Status(Status {
            auth_key_set: true,
            data_key_set: false,
            network_running: false,
            trusted_peers: 2,
        })
        .encode()
    }

    /// Starts a server with `policy` at a fresh socket.
    fn start(name: &str, policy: ClientPolicy) -> (PathBuf, CancellationToken) {
        let path = test_socket(name);
        let listener = bind(&path).unwrap();
        let token = CancellationToken::new();

        tokio::spawn(serve(listener, policy, status_handler, token.clone()));
        (path, token)
    }

    /// Test that a same-user client gets an answer
    #[tokio::test]
    async fn test_same_user_client_served() {
        let (path, token) = start("ok", ClientPolicy::new(None).unwrap());

        let response = request_at(&path, &Request::Status).await.unwrap();
        assert!(matches!(response, Response::Status(s) if s.trusted_peers == 2));

        token.cancel();
    }

    /// Test that a malformed request gets BadRequest, not a crash
    #[tokio::test]
    async fn test_malformed_request_answered_with_error() {
        let (path, token) = start("bad", ClientPolicy::new(None).unwrap());

        let mut stream = UnixStream::connect(&path).await.unwrap();
        write_frame(&mut stream, &[0x99, 1, 2]).await.unwrap();
        let body = read_frame(&mut stream).await.unwrap();

        assert_eq!(
            body.as_slice(),
            Response::encode_error(DaemonError::BadRequest)
        );
        token.cancel();
    }

    /// Test that the socket is created 0600
    #[tokio::test]
    async fn test_socket_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let (path, token) = start("perm", ClientPolicy::new(None).unwrap());
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();

        assert_eq!(mode & 0o777, 0o600);
        token.cancel();
    }

    /// Test that a second daemon refuses to steal a live socket
    #[tokio::test]
    async fn test_second_daemon_refused() {
        let (path, token) = start("twice", ClientPolicy::new(None).unwrap());

        assert_eq!(bind(&path).err(), Some(IpcServerErrors::AlreadyRunning));
        token.cancel();
    }

    /// Test that a regular file at the socket path is never deleted
    #[test]
    fn test_foreign_file_at_path_refused() {
        let path = test_socket("file");
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, b"not a socket").unwrap();

        assert_eq!(bind(&path).err(), Some(IpcServerErrors::SocketPathTaken));
        assert!(path.exists());
        std::fs::remove_file(&path).unwrap();
    }

    /// Test that a stale socket (no daemon behind it) is replaced
    #[tokio::test]
    async fn test_stale_socket_replaced() {
        let path = test_socket("stale");
        drop(bind(&path).unwrap());

        assert!(bind(&path).is_ok());
    }

    /// Test that a client whose signature misses the requirement gets nothing
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn test_unsigned_client_rejected_by_requirement() {
        // the test binary is not Apple-signed
        let (path, token) = start("req-no", ClientPolicy::new(Some("anchor apple")).unwrap());

        let result = request_at(&path, &Request::Status).await;
        assert!(matches!(
            result,
            Err(IpcErrors::FailedToRead | IpcErrors::FailedToWrite)
        ));
        token.cancel();
    }

    /// Test that a client satisfying the requirement is served
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn test_client_satisfying_requirement_served() {
        let (path, token) = start(
            "req-yes",
            ClientPolicy::new(Some("! anchor apple")).unwrap(),
        );

        assert!(request_at(&path, &Request::Status).await.is_ok());
        token.cancel();
    }

    /// Test that an unparsable requirement is refused at startup
    #[test]
    fn test_invalid_requirement_refused() {
        assert_eq!(
            ClientPolicy::new(Some("this is ( not a requirement")).err(),
            Some(IpcServerErrors::InvalidCodeRequirement)
        );
    }
}
