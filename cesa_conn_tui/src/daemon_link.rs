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
//! Nothing key-related is kept here: no keys, no salts (both are the daemon's).

use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::thread;

use cesa_conn_system::{
    ipc::{self, IpcErrors, PairingPrompt, PasswordUpdate, PeerInfo, Request, Response, Status},
    pairing_code::PairingCode,
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
    /// Open the saved vault with the data password.
    Unlock(PasswordUpdate),
    /// Turn automatic login on (d_key into the OS keychain) or off.
    SetAutoLogin(bool),
    /// Turn networking on or off (saved by the daemon).
    SetSync(bool),
    /// Open the daemon's "Add device" window.
    AddDevice,
    /// The user's answer to a pairing prompt.
    AnswerPairing {
        id: u32,
        code: PairingCode,
        accept: bool,
    },
}

/// What a refresh brings back: status, paired devices and the pairing
/// waiting for the user (asked for only when the status says one waits).
pub type Refresh = (Status, Vec<PeerInfo>, Option<PairingPrompt>);

/// What the worker reports back.
#[derive(Debug, PartialEq)]
pub enum LinkEvent {
    /// Answer to [`Command::Refresh`].
    Refreshed(Result<Refresh, IpcErrors>),
    /// Answer to [`Command::SetPassword`].
    PasswordSet {
        kind: KeyKind,
        result: Result<(), IpcErrors>,
    },
    /// Answer to [`Command::Unlock`].
    Unlocked(Result<(), IpcErrors>),
    /// Answer to [`Command::SetAutoLogin`].
    AutoLoginSet {
        on: bool,
        result: Result<(), IpcErrors>,
    },
    /// Answer to [`Command::SetSync`].
    SyncSet {
        on: bool,
        result: Result<(), IpcErrors>,
    },
    /// Answer to [`Command::AddDevice`].
    AddDeviceStarted(Result<(), IpcErrors>),
    /// Answer to [`Command::AnswerPairing`].
    PairingAnswered {
        accept: bool,
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

            LinkEvent::PasswordSet {
                kind,
                result: send_done(socket, request).await,
            }
        }
        Command::Unlock(update) => {
            LinkEvent::Unlocked(send_done(socket, Request::Unlock(update)).await)
        }
        Command::SetAutoLogin(on) => LinkEvent::AutoLoginSet {
            on,
            result: send_done(socket, Request::SetAutoLogin(on)).await,
        },
        Command::SetSync(on) => LinkEvent::SyncSet {
            on,
            result: send_done(socket, Request::SetSync(on)).await,
        },
        Command::AddDevice => {
            LinkEvent::AddDeviceStarted(send_done(socket, Request::AddDevice).await)
        }
        Command::AnswerPairing { id, code, accept } => LinkEvent::PairingAnswered {
            accept,
            result: send_done(socket, Request::AnswerPairing { id, code, accept }).await,
        },
    }
}

/// Sends a request answered with `Done`. Takes the request by value so a
/// password in it is wiped right after sending, not later.
async fn send_done(socket: Option<&PathBuf>, request: Request) -> Result<(), IpcErrors> {
    let result = match send(socket, &request).await {
        Ok(Response::Done) => Ok(()),
        Ok(_) => Err(IpcErrors::Malformed),
        Err(e) => Err(e),
    };

    drop(request);

    result
}

/// Status first, then the paired devices, then the waiting pairing (if
/// the status says there is one).
async fn refresh(socket: Option<&PathBuf>) -> Result<Refresh, IpcErrors> {
    let Response::Status(status) = send(socket, &Request::Status).await? else {
        return Err(IpcErrors::Malformed);
    };

    let Response::Peers(peers) = send(socket, &Request::ListPeers).await? else {
        return Err(IpcErrors::Malformed);
    };

    let pairing = if status.pending_pairings > 0 {
        let Response::Pairing(pairing) = send(socket, &Request::PendingPairing).await? else {
            return Err(IpcErrors::Malformed);
        };
        pairing
    } else {
        None
    };

    Ok((status, peers, pairing))
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

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

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
            network_running: true,
            trusted_peers: 1,
            pending_pairings: 1,
            ..Status::default()
        };
        let peer = PeerInfo {
            fingerprint: [0xab; ipc::FINGERPRINT_LEN],
            name: "laptop".into(),
        };
        let prompt = PairingPrompt {
            id: 9,
            name: "10.0.0.2:50000".into(),
            code: [1, 2, 3, 4, 5, 6, 7, 8],
        };

        // fake daemon: answers every request, hands the changes back to the test
        let (seen_tx, seen_rx) = mpsc::channel::<Vec<u8>>();
        let server_path = path.clone();
        let answer_peer = peer.clone();
        let answer_prompt = prompt.clone();
        let server = thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            rt.block_on(async move {
                let listener = UnixListener::bind(&server_path).unwrap();

                for _ in 0..9 {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let body = ipc::read_frame(&mut stream).await.unwrap();

                    let answer = match Request::decode(&body).unwrap() {
                        Request::Status => Response::Status(status).encode(),
                        Request::ListPeers => Response::Peers(vec![answer_peer.clone()]).encode(),
                        Request::PendingPairing => {
                            Response::Pairing(Some(answer_prompt.clone())).encode()
                        }
                        Request::SetAuthPassword(_)
                        | Request::SetDataPassword(_)
                        | Request::Unlock(_)
                        | Request::SetAutoLogin(_)
                        | Request::SetSync(_)
                        | Request::AddDevice
                        | Request::AnswerPairing { .. } => {
                            seen_tx.send(body.to_vec()).unwrap();
                            Response::Done.encode()
                        }
                    };

                    ipc::write_frame(&mut stream, &answer).await.unwrap();
                }
            });
        });

        // the listener must exist before the first connect
        // bounded, so a failed server thread can't hang the test
        for _ in 0..2000 {
            if path.exists() {
                break;
            }
            thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(path.exists(), "fake daemon didn't start");

        let link = DaemonLink::spawn_with(Some(path)).unwrap();

        // the status says a pairing waits, so the refresh brings it along
        assert!(link.send(Command::Refresh));
        assert_eq!(
            wait_for_event(&link),
            LinkEvent::Refreshed(Ok((status, vec![peer], Some(prompt))))
        );

        assert!(link.send(Command::SetPassword {
            kind: KeyKind::Data,
            update: PasswordUpdate {
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
        assert_eq!(sent.password.as_slice(), b"hunter2");

        // unlock and automatic login reach the daemon as such
        assert!(link.send(Command::Unlock(PasswordUpdate {
            password: Zeroizing::new(b"data password!".to_vec()),
        })));
        assert_eq!(wait_for_event(&link), LinkEvent::Unlocked(Ok(())));
        let Request::Unlock(sent) = Request::decode(&seen_rx.recv().unwrap()).unwrap() else {
            panic!("expected an unlock request");
        };
        assert_eq!(sent.password.as_slice(), b"data password!");

        assert!(link.send(Command::SetAutoLogin(true)));
        assert_eq!(
            wait_for_event(&link),
            LinkEvent::AutoLoginSet {
                on: true,
                result: Ok(())
            }
        );
        assert!(matches!(
            Request::decode(&seen_rx.recv().unwrap()).unwrap(),
            Request::SetAutoLogin(true)
        ));

        // sync, add device and the pairing answer reach the daemon as such
        assert!(link.send(Command::SetSync(true)));
        assert_eq!(
            wait_for_event(&link),
            LinkEvent::SyncSet {
                on: true,
                result: Ok(())
            }
        );
        assert!(matches!(
            Request::decode(&seen_rx.recv().unwrap()).unwrap(),
            Request::SetSync(true)
        ));

        assert!(link.send(Command::AddDevice));
        assert_eq!(wait_for_event(&link), LinkEvent::AddDeviceStarted(Ok(())));
        assert!(matches!(
            Request::decode(&seen_rx.recv().unwrap()).unwrap(),
            Request::AddDevice
        ));

        assert!(link.send(Command::AnswerPairing {
            id: 9,
            code: [1, 2, 3, 4, 5, 6, 7, 8],
            accept: true
        }));
        assert_eq!(
            wait_for_event(&link),
            LinkEvent::PairingAnswered {
                accept: true,
                result: Ok(())
            }
        );
        assert!(matches!(
            Request::decode(&seen_rx.recv().unwrap()).unwrap(),
            Request::AnswerPairing {
                id: 9,
                code: [1, 2, 3, 4, 5, 6, 7, 8],
                accept: true
            }
        ));

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
