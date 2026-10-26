/*
TODO:
pairing prompt ("pair with X? code") once the daemon runs the networker
*/

//! The TUI's link to the daemon over IPC (`cesa_conn_system::ipc`).
//!
//! The UI loop is synchronous and Argon2 in the daemon takes a while, so
//! requests run on one worker thread with its own small tokio runtime:
//! 1. UI -> worker: a [`Command`] over a channel (never blocks the UI)
//! 2. worker -> daemon: one IPC request per command (bounded, timed)
//! 3. worker -> UI: the outcome as a [`LinkEvent`], polled every frame
//!
//! Passwords only pass through here inside [`PasswordUpdate`] (zeroizing);
//! the worker drops the request, and with it the password, right after sending.

use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::thread;

use cesa_conn_system::ipc::{
    self, IpcErrors, PasswordUpdate, PeerInfo, Request, Response, SALT_LEN, Status,
};

/// Which of the two keys a password is for.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KeyKind {
    /// Password 1: authentication and discovery.
    Auth,
    /// Password 2: data transfer.
    Data,
}

/// Work for the worker thread.
pub enum Command {
    /// Ask for the daemon's status and its paired devices.
    Refresh,
    /// Send a password; the daemon derives and keeps the key.
    SetPassword {
        kind: KeyKind,
        update: PasswordUpdate,
    },
}

/// What the worker reports back.
#[derive(Debug, PartialEq)]
pub enum LinkEvent {
    /// Answer to [`Command::Refresh`].
    Refreshed(Result<(Status, Vec<PeerInfo>), IpcErrors>),
    /// Answer to [`Command::SetPassword`].
    PasswordSet {
        kind: KeyKind,
        result: Result<(), IpcErrors>,
    },
    /// The worker is gone (its runtime couldn't start, or it panicked).
    WorkerStopped,
}

/// The UI's handle on the worker. Dropping it stops the worker.
pub struct DaemonLink {
    commands: Sender<Command>,
    events: Receiver<LinkEvent>,
}

impl DaemonLink {
    /// Starts the worker, talking to the daemon at the default socket.
    pub fn spawn() -> std::io::Result<Self> {
        Self::spawn_with(None)
    }

    /// Starts the worker; `socket` overrides the default path (tests).
    fn spawn_with(socket: Option<PathBuf>) -> std::io::Result<Self> {
        let (commands, command_rx) = mpsc::channel::<Command>();
        let (event_tx, events) = mpsc::channel::<LinkEvent>();

        thread::Builder::new()
            .name("cesa-daemon-link".into())
            .spawn(move || worker(socket, &command_rx, &event_tx))?;

        Ok(Self { commands, events })
    }

    /// Queues a command. `false` if the worker is gone.
    pub fn send(&self, command: Command) -> bool {
        self.commands.send(command).is_ok()
    }

    /// The next finished event, without blocking.
    pub fn try_recv(&self) -> Option<LinkEvent> {
        match self.events.try_recv() {
            Ok(event) => Some(event),
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => Some(LinkEvent::WorkerStopped),
        }
    }
}

/// The worker loop: one command at a time until the UI drops its sender.
fn worker(socket: Option<PathBuf>, commands: &Receiver<Command>, events: &Sender<LinkEvent>) {
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
    else {
        // dropping `events` also tells the UI, this just says it first
        let _ = events.send(LinkEvent::WorkerStopped);
        return;
    };

    while let Ok(command) = commands.recv() {
        let event = runtime.block_on(run_command(socket.as_ref(), command));

        if events.send(event).is_err() {
            return;
        }
    }
}

/// Runs one command against the daemon.
async fn run_command(socket: Option<&PathBuf>, command: Command) -> LinkEvent {
    match command {
        Command::Refresh => LinkEvent::Refreshed(refresh(socket).await),
        Command::SetPassword { kind, update } => {
            let request = match kind {
                KeyKind::Auth => Request::SetAuthPassword(update),
                KeyKind::Data => Request::SetDataPassword(update),
            };

            let result = match send(socket, &request).await {
                Ok(Response::Done) => Ok(()),
                Ok(_) => Err(IpcErrors::Malformed),
                Err(e) => Err(e),
            };

            // `request` (and the password in it) is wiped here, not later
            drop(request);

            LinkEvent::PasswordSet { kind, result }
        }
    }
}

/// Status first, then the paired devices.
async fn refresh(socket: Option<&PathBuf>) -> Result<(Status, Vec<PeerInfo>), IpcErrors> {
    let Response::Status(status) = send(socket, &Request::Status).await? else {
        return Err(IpcErrors::Malformed);
    };

    let Response::Peers(peers) = send(socket, &Request::ListPeers).await? else {
        return Err(IpcErrors::Malformed);
    };

    Ok((status, peers))
}

async fn send(socket: Option<&PathBuf>, request: &Request) -> Result<Response, IpcErrors> {
    match socket {
        #[cfg(unix)]
        Some(path) => ipc::request_at(path, request).await,
        #[cfg(not(unix))]
        Some(_) => Err(IpcErrors::Unsupported),
        None => ipc::request(request).await,
    }
}

/* salts (public, shown to the user so other devices can use the same one) */

/// Lower-case hex of a salt.
pub fn salt_to_hex(salt: &[u8; SALT_LEN]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";

    let mut out = String::with_capacity(SALT_LEN.saturating_mul(2));

    for byte in salt {
        for nibble in [byte >> 4, byte & 0x0f] {
            if let Some(&digit) = DIGITS.get(usize::from(nibble)) {
                out.push(char::from(digit));
            }
        }
    }

    out
}

/// Parses exactly `2 * SALT_LEN` hex digits (either case); anything else is `None`.
pub fn salt_from_hex(text: &str) -> Option<[u8; SALT_LEN]> {
    let digits = text.as_bytes();

    if digits.len() != SALT_LEN.saturating_mul(2) {
        return None;
    }

    let mut salt = [0u8; SALT_LEN];

    let (pairs, _) = digits.as_chunks::<2>();

    for (byte, [hi, lo]) in salt.iter_mut().zip(pairs) {
        *byte = hex_value(*hi)? << 4 | hex_value(*lo)?;
    }

    Some(salt)
}

fn hex_value(digit: u8) -> Option<u8> {
    char::from(digit)
        .to_digit(16)
        .and_then(|v| u8::try_from(v).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    /// Test that salts survive a hex round trip
    #[test]
    fn test_salt_hex_roundtrip() {
        let salt: [u8; SALT_LEN] = core::array::from_fn(|i| u8::try_from(i * 7).unwrap());
        let hex = salt_to_hex(&salt);

        assert_eq!(hex.len(), SALT_LEN * 2);
        assert_eq!(salt_from_hex(&hex), Some(salt));
        assert_eq!(salt_from_hex(&hex.to_uppercase()), Some(salt));
    }

    /// Test that anything but exactly 64 hex digits is refused
    #[test]
    fn test_salt_hex_rejects_bad_input() {
        let good = "ab".repeat(SALT_LEN);

        assert_eq!(salt_from_hex(""), None);
        assert_eq!(salt_from_hex(good.get(1..).unwrap()), None);
        assert_eq!(salt_from_hex(&format!("{good}00")), None);
        assert_eq!(salt_from_hex(&good.replacen('a', "g", 1)), None);
        assert_eq!(salt_from_hex(&good.replacen("ab", "ą", 1)), None);
        assert_eq!(salt_from_hex(&good.replacen('a', " ", 1)), None);
    }

    /// Test that a missing daemon is reported, not hung on
    #[cfg(unix)]
    #[test]
    fn test_no_daemon_reports_error() {
        let dir = std::env::temp_dir().join(format!("cesa-tui-nodaemon-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = ipc::prepare_socket_dir(&dir).unwrap();

        let link = DaemonLink::spawn_with(Some(path.clone())).unwrap();
        assert!(link.send(Command::Refresh));

        let event = wait_for_event(&link);
        assert_eq!(event, LinkEvent::Refreshed(Err(IpcErrors::FailedToConnect)));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Test the link end to end against a fake daemon on a real socket:
    /// refresh returns status + peers, and a password arrives intact
    #[cfg(unix)]
    #[test]
    fn test_link_against_fake_daemon() {
        use tokio::net::UnixListener;

        let dir = std::env::temp_dir().join(format!("cesa-tui-link-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = ipc::prepare_socket_dir(&dir).unwrap();

        let status = Status {
            auth_key_set: true,
            data_key_set: false,
            network_running: false,
            trusted_peers: 1,
        };
        let peer = PeerInfo {
            fingerprint: [0xab; ipc::FINGERPRINT_LEN],
            name: "laptop".into(),
        };

        // fake daemon: answers 3 requests, hands the 3rd one back to the test
        let (seen_tx, seen_rx) = mpsc::channel::<Vec<u8>>();
        let server_path = path.clone();
        let answer_peer = peer.clone();
        let server = thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            rt.block_on(async move {
                let listener = UnixListener::bind(&server_path).unwrap();

                for _ in 0..3 {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let body = ipc::read_frame(&mut stream).await.unwrap();

                    let answer = match Request::decode(&body).unwrap() {
                        Request::Status => Response::Status(status).encode(),
                        Request::ListPeers => Response::Peers(vec![answer_peer.clone()]).encode(),
                        Request::SetAuthPassword(_) | Request::SetDataPassword(_) => {
                            seen_tx.send(body.to_vec()).unwrap();
                            Response::Done.encode()
                        }
                    };

                    ipc::write_frame(&mut stream, &answer).await.unwrap();
                }
            });
        });

        // the listener must exist before the first connect
        while !path.exists() {
            thread::sleep(std::time::Duration::from_millis(5));
        }

        let link = DaemonLink::spawn_with(Some(path)).unwrap();

        assert!(link.send(Command::Refresh));
        assert_eq!(
            wait_for_event(&link),
            LinkEvent::Refreshed(Ok((status, vec![peer])))
        );

        assert!(link.send(Command::SetPassword {
            kind: KeyKind::Data,
            update: PasswordUpdate {
                salt: [5; SALT_LEN],
                password: Zeroizing::new(b"hunter2".to_vec()),
            },
        }));
        assert_eq!(
            wait_for_event(&link),
            LinkEvent::PasswordSet {
                kind: KeyKind::Data,
                result: Ok(()),
            }
        );

        let Request::SetDataPassword(sent) = Request::decode(&seen_rx.recv().unwrap()).unwrap()
        else {
            panic!("expected a data password request");
        };
        assert_eq!(sent.salt, [5; SALT_LEN]);
        assert_eq!(sent.password.as_slice(), b"hunter2");

        server.join().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn wait_for_event(link: &DaemonLink) -> LinkEvent {
        for _ in 0..1000 {
            if let Some(event) = link.try_recv() {
                return event;
            }
            thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("no event from the link worker within 10 s");
    }
}
