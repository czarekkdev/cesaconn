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
mod guess_limiter;
mod hybrid_kex;
mod ipc_unix;
mod spake2;
mod tcp_networker;
#[cfg(feature = "test-commands")]
mod test_commands;
mod udp_networker;

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

    #[cfg(feature = "test-commands")]
    test_commands::run(&args).await;

    #[cfg(not(feature = "test-commands"))]
    {
        let _ = args;
        tracing::error!("no daemon yet; the test commands need `--features test-commands`");
    }
}
