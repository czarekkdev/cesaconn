# Security gate

Every push and pull request runs `.github/workflows/security.yml`; locally the
`pre-push` hook runs the static part before anything leaves your machine.
Only **critical** findings block (red check / refused push). Everything else
lands in the report: job summary, `security-report-*` artifact, and GitHub
code scanning (Security -> Code scanning).

## What is checked

| Area | Tool | Critical (blocks) | Reported |
|---|---|---|---|
| Zeroize | semgrep `zeroize.yml` | secret in plain `[u8;N]`/`Vec<u8>` local or struct field, key copied out of `Zeroizing`/lock (`*keys.read().await.a_key`), secret in `println!`/`tracing`/`format!`, `mem::forget`/`Box::leak` | `.to_vec()` of a secret, secret params by value, `Debug` derive on key structs, `ManuallyDrop` |
| RwLock / guards | semgrep `locks.yml` + clippy | same lock re-acquired while its guard is alive (tokio RwLock is not re-entrant -> deadlock), `blocking_read/write` in async, `std::sync` locks in the networker, std guard across `.await` | tokio guard held across `.await` (+ `clippy::await_holding_invalid_type` via `clippy.toml`), two different locks nested (lock ordering), guard alive through a whole `match`/`if let`/`for`, `try_*().unwrap()`, guard lives longer than needed (`significant_drop_*`) |
| Races | semgrep + ThreadSanitizer | `static mut`, `unsafe impl Send/Sync`, any TSan data race | check-then-act / lost update (read guard, then separate write guard), `Ordering::Relaxed`, test hang under TSan |
| UB | Miri (`cesa_conn_crypto`) | Undefined Behavior | tests failing under Miri |
| Dependencies | cargo-audit, cargo-deny | RustSec vulnerability or *unsound* advisory, non-crates.io source | unmaintained/yanked, duplicate versions, licenses |
| Secrets in git | gitleaks | any detected secret in history / pushed commits | |
| Panics | clippy | | `unwrap`/`expect`/`panic`/indexing/arithmetic overflow/truncating casts outside tests |

Code that does not compile cannot be linted by clippy or race-tested; that is
reported as a note (it does not block - semgrep still covers it).

## Run locally

```sh
brew install semgrep cargo-audit cargo-deny gitleaks   # once
security/install-hooks.sh                              # once per clone
python3 security/run.py --fast                         # same as the hook
python3 security/run.py                                # + Miri (+ TSan on Linux)
semgrep --test --metrics=off security/semgrep          # rule self-tests
```

Report: `target/security/report.md`. Emergency bypass: `git push --no-verify`
(CI still runs).

## False positives

Suppress one line after review, with a reason:

```rust
// nosemgrep: cesa.lock.guard-held-across-await -- guard must cover the write to keep peers consistent
```

or `#[allow(clippy::<lint>)] // reason`. New rule? Add it to `security/semgrep/*.yml`
with a `// ruleid:` / `// ok:` case in the matching `.rs` fixture.
