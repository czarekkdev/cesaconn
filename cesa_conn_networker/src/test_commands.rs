//! `servertest` / `clienttest`: manual end-to-end test of discovery, pairing
//! and one data packet between two machines.
//!
//! Only compiled with `--features test-commands`, so release builds don't
//! ship them. Each run uses fresh random salts (printed by `servertest`,
//! passed to `clienttest`) and derives two different keys from the password.
//! The password is typed at a prompt with echo off, never passed as an
//! argument (that would land in the shell history and in `ps`).

use std::{
    io::{self, BufRead, Write},
    net::SocketAddr,
    sync::Arc,
};
use tokio::{net::TcpListener, sync::RwLock};
use tokio_util::sync::CancellationToken;
use tracing::error;
use zeroize::Zeroizing;

use cesa_conn_crypto::{crand::random_array, pswd_manager::derive_key};
use cesa_conn_system::{
    ipc::MAX_PASSWORD_LEN,
    pairing_code::{PairingCode, symbol},
};

use crate::{
    auth_snow::{AuthKey, DataKey, DeviceKeypairs, Keys, Pairing},
    guess_limiter::GuessLimiter,
    tcp_networker::{ActionType, NetworkerContext, SaltOffer, TCP_PORT, connect, recv},
    udp_networker::{InstanceId, UdpNetworkerErrors, udp_broadcast_presence, udp_find_broadcaster},
};

/// a_salt (32) + d_salt (32), hex encoded on the command line
const SALTS_LEN: usize = 64;

/// The pairing code as `emoji name` pairs, the way the UI shows it.
fn describe_code(code: &PairingCode) -> String {
    code.iter()
        .filter_map(|&index| symbol(index))
        .map(|(emoji, name)| format!("{emoji} {name}"))
        .collect::<Vec<_>>()
        .join("  ")
}

/// Asks on the terminal whether to pair with a new device. The user
/// compares the pairing code with the other device before accepting (the
/// codes only match without a MITM).
fn pair_prompt(prompt: &str) -> bool {
    print!("{prompt}");

    if io::stdout().flush().is_err() {
        return false;
    }

    let mut answer = String::new();

    if io::stdin().lock().read_line(&mut answer).is_err() {
        return false;
    }

    matches!(answer.trim(), "y" | "Y" | "yes")
}

/// Asks on the terminal about every new device, one at a time.
fn terminal_pairing() -> Pairing {
    let (pairing, mut inbox) = Pairing::channel();

    tokio::spawn(async move {
        // an in-process channel, not the network: ends with the senders
        // nosemgrep: cesa.net.read-without-timeout
        while let Some(request) = inbox.requests.recv().await {
            let prompt = format!(
                "Pair with {}? Check that the other device shows:\n  {}\n[y/N] ",
                request.name,
                describe_code(&request.code)
            );
            // stdin blocks: off the async workers
            let accept = tokio::task::spawn_blocking(move || pair_prompt(&prompt))
                .await
                .unwrap_or(false);

            request.answer(accept);
        }
    });

    pairing
}

/// Shared networker state for the test subcommands. A fresh identity per
/// run on purpose: the manual test always pairs (the daemon keeps its
/// identity in the vault).
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
        pairing: terminal_pairing(),
        guess_limiter: Arc::new(GuessLimiter::new()),
        salt_offer: SaltOffer::default(),
        peer_book: Arc::default(),
        peer_port: TCP_PORT,
        clipboard: None,
    })
}

/// Lowercase hex of `bytes`.
fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parses exactly `SALTS_LEN` bytes of hex, `None` for anything else.
fn salts_from_hex(hex: &str) -> Option<[u8; SALTS_LEN]> {
    if hex.len() != SALTS_LEN.checked_mul(2)? {
        return None;
    }

    let mut out = [0u8; SALTS_LEN];

    // the length is checked above, so there is no remainder
    let (pairs, _) = hex.as_bytes().as_chunks::<2>();

    for (byte, pair) in out.iter_mut().zip(pairs) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }

    Some(out)
}

/// Reads the test password from the terminal with echo off (blocking: run
/// it on a blocking thread). `None` if stdin isn't a terminal, the read
/// fails, the line is empty or longer than [`MAX_PASSWORD_LEN`].
#[cfg(unix)]
fn read_password_hidden() -> Option<Zeroizing<String>> {
    use nix::sys::termios::{LocalFlags, SetArg, tcgetattr, tcsetattr};
    use std::{io::Read, os::fd::AsFd};

    let stdin = io::stdin();
    let Ok(old) = tcgetattr(stdin.as_fd()) else {
        error!("the password needs a terminal (stdin isn't one)");
        return None;
    };
    // room for the longest password and its newline; computed before echo
    // goes off, so no early return can leave the terminal silent
    let limit = MAX_PASSWORD_LEN.saturating_add(2);
    let limit_u64 = u64::try_from(limit).ok()?;

    let mut hidden = old.clone();
    hidden.local_flags.remove(LocalFlags::ECHO);
    // the Enter still moves to a new line
    hidden.local_flags.insert(LocalFlags::ECHONL);

    print!("Test-session password: ");
    io::stdout().flush().ok()?;
    if tcsetattr(stdin.as_fd(), SetArg::TCSANOW, &hidden).is_err() {
        error!("couldn't turn terminal echo off");
        return None;
    }

    // read through `take`: the String never reallocates and leaves no
    // unwiped copy behind
    let mut line = Zeroizing::new(String::with_capacity(limit));
    let read = stdin.lock().take(limit_u64).read_line(&mut line);

    // echo back on before anything else, whatever the read did
    if tcsetattr(stdin.as_fd(), SetArg::TCSANOW, &old).is_err() {
        error!("couldn't turn terminal echo back on (run `stty echo`)");
    }

    if let Err(e) = read {
        error!(error = %e, "failed to read the password");
        return None;
    }
    if !line.ends_with('\n') {
        error!(max = MAX_PASSWORD_LEN, "password too long or input ended");
        return None;
    }
    let len = line.trim_end_matches(['\r', '\n']).len();
    line.truncate(len);
    if line.is_empty() {
        error!("empty password");
        return None;
    }
    Some(line)
}

/// No hidden terminal input here: refuse instead of echoing the password.
#[cfg(not(unix))]
fn read_password_hidden() -> Option<Zeroizing<String>> {
    error!("hidden password input is only built for Unix terminals");
    None
}

/// Asks for the password (echo off, on a blocking thread), then derives
/// the test keys; the password is wiped when this returns.
async fn prompt_test_keys(salts: &[u8; SALTS_LEN]) -> Option<Arc<RwLock<Keys>>> {
    let password = tokio::task::spawn_blocking(read_password_hidden)
        .await
        .ok()
        .flatten()?;

    test_keys(&password, salts)
}

/// Derives `a_key` and `d_key` from one password with two different salts.
fn test_keys(password: &str, salts: &[u8; SALTS_LEN]) -> Option<Arc<RwLock<Keys>>> {
    let (a_salt, d_salt) = salts.split_first_chunk::<32>()?;
    let d_salt: &[u8; 32] = d_salt.try_into().ok()?;

    let derived = derive_key(password.as_bytes(), a_salt)
        .and_then(|a_key| Ok((a_key, derive_key(password.as_bytes(), d_salt)?)));

    match derived {
        Ok((a_key, d_key)) => Some(Arc::new(RwLock::new(Keys::new(
            AuthKey::new(a_key),
            a_salt,
            DataKey::new(d_key),
        )))),
        Err(e) => {
            error!(error = %e, "failed to derive the test keys");
            None
        }
    }
}

/// UDP discovery for servertest: alternates between broadcasting presence and
/// listening, so both sides find each other regardless of who starts first.
async fn server_discovery(id: InstanceId) {
    loop {
        if let Err(e) = udp_broadcast_presence(1, id).await {
            error!(error = %e, "UDP broadcast failed, stopping discovery");
            return;
        }

        match udp_find_broadcaster(3, id).await {
            Ok(_) => return,
            Err(UdpNetworkerErrors::Timeout) => {}
            Err(e) => {
                error!(error = %e, "UDP discovery failed, stopping discovery");
                return;
            }
        }
    }
}

/// UDP discovery for clienttest: listen for a broadcaster, then announce ourselves.
async fn client_discovery(id: InstanceId) -> Option<SocketAddr> {
    loop {
        match udp_find_broadcaster(1, id).await {
            Ok(addr) => {
                if let Err(e) = udp_broadcast_presence(3, id).await {
                    error!(error = %e, "UDP broadcast failed");
                    return None;
                }

                return Some(addr);
            }
            Err(UdpNetworkerErrors::Timeout) => {}
            Err(e) => {
                error!(error = %e, "UDP discovery failed");
                return None;
            }
        }
    }
}

/// `servertest <password>`: prints fresh salts, listens for one test client.
async fn servertest() {
    let salts = match (random_array::<32>(), random_array::<32>()) {
        (Ok(a_salt), Ok(d_salt)) => {
            let mut salts = Zeroizing::new([0u8; SALTS_LEN]);

            for (dst, src) in salts.iter_mut().zip(a_salt.iter().chain(d_salt.iter())) {
                *dst = *src;
            }

            salts
        }
        _ => {
            error!("failed to generate salts");
            return;
        }
    };

    // salts aren't secret, the client needs them to derive the same keys
    println!("salts: {}", to_hex(salts.as_slice()));

    let Some(keys) = prompt_test_keys(&salts).await else {
        return;
    };

    // Test server: peers on the LAN must reach it; every connection is
    // authenticated before any data is processed.
    // nosemgrep: cesa.net.bind-all-interfaces
    let listener = match TcpListener::bind(("0.0.0.0", TCP_PORT)).await {
        Ok(listener) => listener,
        Err(e) => {
            error!(error = %e, port = TCP_PORT, "failed to bind TCP listener");
            return;
        }
    };

    let Ok(id) = InstanceId::generate() else {
        error!("failed to generate instance id");
        return;
    };

    tokio::spawn(server_discovery(id));

    let Some(context) = make_context(keys) else {
        return;
    };

    if let Err(e) = recv(&listener, context, CancellationToken::new()).await {
        error!(error = %e, "TCP listener stopped");
    }
}

/// `clienttest <message> <password> <salts>`: finds the server, sends `message`.
async fn clienttest(message: &str, salts_hex: &str) {
    let Some(salts) = salts_from_hex(salts_hex) else {
        error!(
            "salts must be the {} hex characters servertest printed",
            SALTS_LEN * 2
        );
        return;
    };

    let Some(keys) = prompt_test_keys(&salts).await else {
        return;
    };

    let Ok(id) = InstanceId::generate() else {
        error!("failed to generate instance id");
        return;
    };

    let Some(server_addr) = client_discovery(id).await else {
        return;
    };

    // only the IP comes from discovery (an unauthenticated hint), the port is fixed
    let connect_addr = SocketAddr::new(server_addr.ip(), TCP_PORT);

    let Some(context) = make_context(keys) else {
        return;
    };

    if let Err(e) = connect(
        context,
        CancellationToken::new(),
        connect_addr,
        ActionType::Debug,
        Zeroizing::new(message.as_bytes().to_vec()),
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

/// A test subcommand, parsed from the command line.
#[derive(Debug, PartialEq)]
enum Command<'a> {
    /// `servertest`
    Server,
    /// `clienttest <message> <salts>`
    Client {
        /// what to send
        message: &'a str,
        /// salts printed by `servertest`, hex
        salts: &'a str,
    },
}

/// Parses `args` (args[0] = binary). Extra arguments are refused: the old
/// forms took the password there, and it must not be taken that way.
fn parse(args: &[String]) -> Result<Command<'_>, &'static str> {
    match args.get(1..).unwrap_or_default() {
        [sub] if sub == "servertest" => Ok(Command::Server),
        [sub, message, salts] if sub == "clienttest" => Ok(Command::Client { message, salts }),
        [sub, ..] if sub == "servertest" || sub == "clienttest" => {
            Err("Wrong arguments (the password is no longer an argument: it's asked for, hidden).")
        }
        [_, ..] => Err("Unknown subcommand."),
        [] => Err("No subcommand provided."),
    }
}

/// Runs a test subcommand from `args` (args[0] = binary).
pub async fn run(args: &[String]) {
    let bin = args.first().map_or("cesa_conn_networker", String::as_str);
    let usage = format!(
        "Usage:\n  {bin} servertest\n  {bin} clienttest <message> <salts>\n\
         The password is asked for on the terminal (input hidden)."
    );

    match parse(args) {
        Ok(Command::Server) => servertest().await,
        Ok(Command::Client { message, salts }) => clienttest(message, salts).await,
        Err(e) => error!("{e}\n{usage}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that the subcommands parse, and that the old forms with the
    /// password as an argument are refused
    #[test]
    fn test_parse_refuses_password_arguments() {
        let args = |list: &[&str]| list.iter().map(|s| s.to_string()).collect::<Vec<_>>();

        assert_eq!(parse(&args(&["bin", "servertest"])), Ok(Command::Server));
        assert_eq!(
            parse(&args(&["bin", "clienttest", "hi", "ab"])),
            Ok(Command::Client {
                message: "hi",
                salts: "ab"
            })
        );

        for old in [
            &["bin", "servertest", "secret"][..],
            &["bin", "clienttest", "hi", "secret", "ab"][..],
            &["bin", "clienttest", "hi"][..],
            &["bin", "other"][..],
            &["bin"][..],
        ] {
            assert!(parse(&args(old)).is_err(), "{old:?}");
        }
    }

    /// Test that salts round-trip through hex
    #[test]
    fn test_salts_hex_roundtrip() {
        let salts: [u8; SALTS_LEN] = core::array::from_fn(|i| u8::try_from(i).unwrap());
        assert_eq!(salts_from_hex(&to_hex(&salts)), Some(salts));
    }

    /// Test that wrong length or non-hex input is rejected
    #[test]
    fn test_salts_hex_rejects_bad_input() {
        let good = to_hex(&[0xAB; SALTS_LEN]);

        assert_eq!(salts_from_hex(good.get(..good.len() - 2).unwrap()), None);
        assert_eq!(salts_from_hex(&format!("{good}00")), None);
        assert_eq!(salts_from_hex(&good.replacen('a', "g", 1)), None);
        assert_eq!(salts_from_hex(""), None);
    }

    /// Test that the two keys come from different salts, so they differ
    #[tokio::test]
    async fn test_a_key_and_d_key_differ() {
        let salts: [u8; SALTS_LEN] = core::array::from_fn(|i| u8::try_from(i).unwrap());
        let keys = test_keys("pw", &salts).unwrap();
        let keys = keys.read().await;

        assert_ne!(**keys.a_key.expose(), **keys.d_key.expose());
    }
}
