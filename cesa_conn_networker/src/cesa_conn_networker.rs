#![forbid(unsafe_code)]
// an un-awaited future or an ignored Result is always a bug here
#![deny(unused_must_use)]

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

mod auth_snow;
#[cfg(unix)]
mod daemon;
mod guess_limiter;
mod hybrid_kex;
#[cfg(unix)]
mod ipc_server;
mod salt_service;
mod spake2;
mod tcp_networker;
#[cfg(feature = "test-commands")]
mod test_commands;
mod udp_networker;
#[cfg(unix)]
mod vault;

use std::env;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    // debug in dev builds, info in release — RUST_LOG overrides both at runtime
    let default_level = if cfg!(debug_assertions) {
        "cesa_conn=debug"
    } else {
        "cesa_conn=info"
    };

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level)),
        )
        .init();

    let args: Vec<String> = env::args().collect();

    // a subcommand runs the manual tests, no subcommand runs the daemon
    #[cfg(feature = "test-commands")]
    if args.len() > 1 {
        test_commands::run(&args).await;
        return;
    }

    if let Some(arg) = args.get(1) {
        tracing::error!(%arg, "unknown argument (test commands need `--features test-commands`)");
        return;
    }

    #[cfg(unix)]
    daemon::run().await;

    #[cfg(not(unix))]
    tracing::error!("the daemon is not supported on this platform yet");
}
