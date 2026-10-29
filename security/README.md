# Security gate

Every push and pull request runs `.github/workflows/security.yml`; locally the
`pre-push` hook runs the static part before anything leaves your machine.
**Every critical finding, every warning and every coverage gap blocks** (red
check / refused push): the code has to be perfect. Only notes pass: reviewed
upstream dependency exceptions (below) and unused code (`dead_code`,
`unused_*`: the networking code isn't started by the daemon yet, and
`allow(dead_code)` is forbidden, so it stays visible as a note). Everything
lands in the report: job summary, `security-report-*` artifact, and GitHub
code scanning (Security -> Code scanning).

## What is checked

| Area | Tool | Critical (blocks) | Warning (blocks too) |
|---|---|---|---|
| Zeroize | semgrep `zeroize.yml` | secret in plain `[u8;N]`/`Vec<u8>` local or struct field, key copied out of `Zeroizing`/lock (`*keys.read().await.a_key`), secret in `println!`/`tracing`/`format!`, `mem::forget`/`Box::leak` | `.to_vec()` of a secret, secret params by value, `Debug` derive on key structs, `ManuallyDrop` |
| RwLock / guards | semgrep `locks.yml` + clippy | same lock re-acquired while its guard is alive (tokio RwLock is not re-entrant -> deadlock), `blocking_read/write` in async, `std::sync` locks in the networker, std guard across `.await` | tokio guard held across `.await` (+ `clippy::await_holding_invalid_type` via `clippy.toml`), two different locks nested (lock ordering), guard alive through a whole `match`/`if let`/`for`, `try_*().unwrap()`, guard lives longer than needed (`significant_drop_*`) |
| Network / protocol | semgrep `network.yml` | length read from the wire used as an allocation size without an upper bound (remote memory DoS), secret/MAC/confirmation compared with `==` instead of constant-time `ct_eq`, fixed/zero AEAD nonce | socket reads awaited without `timeout(...)` (slowloris), sockets bound to `0.0.0.0`/`[::]`, u64 wire length cast `as usize`, `unwrap`/`expect` on network/crypto results |
| Races | semgrep + ThreadSanitizer | `static mut`, `unsafe impl Send/Sync`, any TSan data race | check-then-act / lost update (read guard, then separate write guard), `Ordering::Relaxed`, test hang under TSan |
| UB | Miri (`cesa_conn_crypto`) | Undefined Behavior | tests failing under Miri |
| Failing tests | ThreadSanitizer run (CI's only full test run, `--no-fail-fast`) | | a `test ... FAILED`, a test binary that died (abort, signal) although every other `test result` says ok, any cargo exit code nothing else explains |
| The gate itself | `selftest` (every run, also `--fast` and `--only`) | its test-result parsing gives a wrong answer on recorded real cargo output | |
| Dependencies | cargo-audit, cargo-deny | RustSec vulnerability or *unsound* advisory, non-crates.io source | unmaintained/yanked, duplicate versions, licenses |
| Secrets in git | gitleaks | any detected secret in history / pushed commits | |
| Panics | clippy + semgrep `hygiene.yml` | `unwrap`/`expect` outside tests, and `allow(clippy::unwrap_used / expect_used)` anywhere | `panic`/indexing/arithmetic overflow/truncating casts outside tests |
| Everything else | rustc + clippy (default groups) | | any other compiler or clippy warning, in both feature sets, tests included; a broken `clippy.toml` entry |

Code that does not compile cannot be linted by clippy or race-tested. Then
the gate reports **BLOCKED - PARTIAL COVERAGE**: a banner at the top of the
report, a red `::error` annotation on the run/PR, and a `NOT ANALYSED` line in
the log listing exactly what was skipped (crates that did not build, tools
that were not installed, crashed or timed out, Miri tests it couldn't run,
broken semgrep rule fixtures). A gap always fails. A full local run on macOS
fails for that reason too: ThreadSanitizer only runs on Linux (CI).

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

## Dependency exceptions (`security/accepted.json`)

Some dependency warnings can't be fixed in this repo: duplicate versions that
come from upstream crates (btleplug, libcrux, snow, RustCrypto) and
unmaintained-but-not-vulnerable advisories with no fixed version. After review
they go into `security/accepted.json`, with a reason for each:

- an accepted finding is shown as a **note** with its reason, never hidden
- matching is exact: a duplicate only while `Cargo.lock` has exactly the listed
  versions, an advisory only for the listed `package@version`; any change
  makes it a warning again
- entries that no longer match are reported as `stale-exception` (a warning,
  so it blocks): remove them
- only `Cargo.lock` warnings can be accepted; critical findings
  (vulnerabilities, unsound crates, foreign sources) and first-party code can't

Re-check the list whenever dependencies change.
