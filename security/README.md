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
| Network / protocol | semgrep `network.yml` | length read from the wire used as an allocation size without an upper bound (remote memory DoS), secret/MAC/confirmation compared with `==` instead of constant-time `ct_eq`, fixed/zero AEAD nonce | socket reads awaited without `timeout(...)` (slowloris), sockets bound to `0.0.0.0`/`[::]`, u64 wire length cast `as usize`, `unwrap`/`expect` on network/crypto results |
| Races | semgrep + ThreadSanitizer | `static mut`, `unsafe impl Send/Sync`, any TSan data race | check-then-act / lost update (read guard, then separate write guard), `Ordering::Relaxed`, test hang under TSan |
| UB | Miri (`cesa_conn_crypto`) | Undefined Behavior | tests failing under Miri |
| Dependencies | cargo-audit, cargo-deny | RustSec vulnerability or *unsound* advisory, non-crates.io source | unmaintained/yanked, duplicate versions, licenses |
| Secrets in git | gitleaks | any detected secret in history / pushed commits | |
| Panics | clippy | | `unwrap`/`expect`/`panic`/indexing/arithmetic overflow/truncating casts outside tests |

Code that does not compile cannot be linted by clippy or race-tested. The gate
then reports **PASSED - PARTIAL COVERAGE**: a warning banner at the top of the
report, a yellow `::warning` annotation on the run/PR, and a `NOT ANALYSED`
line in the log listing exactly what was skipped (crates that did not build,
tools that were not installed, crashed or timed out). It does not block by
default; set `CESA_REQUIRE_FULL_COVERAGE=1` (env or workflow) to make any gap
fail the run.

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
- entries that no longer match are reported as `stale-exception`, remove them
- only `Cargo.lock` warnings can be accepted; critical findings
  (vulnerabilities, unsound crates, foreign sources) and first-party code can't

Re-check the list whenever dependencies change.
