#!/usr/bin/env python3
"""
CesaConn security gate.

Runs every security check, writes a Markdown report + a SARIF file, and exits
non-zero ONLY when a CRITICAL finding exists. Everything else is reported.

    python3 security/run.py              # full run (CI): + Miri + ThreadSanitizer
    python3 security/run.py --fast       # pre-push hook: static checks only
    python3 security/run.py --range A..B # limit secret scanning to these commits

Checks
  semgrep   security/semgrep/*.yml  - zeroize, lock/guard misuse, races
  clippy    per crate, security lint set (+ clippy.toml tokio guard config)
  audit     cargo-audit (RustSec)     - vulnerabilities / unsound crates
  deny      cargo-deny                - registry sources, licenses, bans
  gitleaks  committed secrets
  miri      (full) UB in cesa_conn_crypto tests
  tsan      (full, Linux nightly) data races in tests

Severity
  critical  -> blocks (exit 1)
  warning   -> reported only
  info      -> a tool could not run / partial analysis, or a reviewed dependency
               exception from security/accepted.json (reported, never blocks)
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "target" / "security"

CRATES = ["cesa_conn_crypto", "cesa_conn_networker", "cesa_conn_system", "cesa_conn_tui"]
MIRI_CRATES = ["cesa_conn_crypto"]
# Tests too slow for the Miri interpreter (Argon2 with 64 MiB memory cost, MB-sized buffers).
# Their code paths are pure safe Rust in audited dependencies.
MIRI_SKIP = ["pswd_manager::", "test_large_data"]

# ---- clippy lint policy -----------------------------------------------------
# Denied lints -> critical. Everything listed in WARN -> warning.
CLIPPY_DENY = [
    "clippy::await_holding_lock",          # std/parking_lot guard across .await
    "clippy::await_holding_refcell_ref",
    "clippy::mem_forget",                  # skips Drop -> no zeroize
    "clippy::undocumented_unsafe_blocks",
    "clippy::multiple_unsafe_ops_per_block",
    "unsafe_op_in_unsafe_fn",
    "clippy::correctness",
]
CLIPPY_WARN = [
    "clippy::await_holding_invalid_type",  # tokio guards across .await (clippy.toml)
    "clippy::significant_drop_tightening", # guard lives longer than needed
    "clippy::significant_drop_in_scrutinee",
    "clippy::large_futures",
    "clippy::let_underscore_future",
    "clippy::mutex_atomic",
    "clippy::mutex_integer",
    "clippy::rc_mutex",
    "clippy::unwrap_used",
    "clippy::expect_used",
    "clippy::panic",
    "clippy::indexing_slicing",
    "clippy::arithmetic_side_effects",
    "clippy::cast_possible_truncation",
    "clippy::cast_sign_loss",
    "clippy::large_stack_arrays",
    "clippy::string_slice",
    "clippy::todo",
    "clippy::unimplemented",
    "clippy::dbg_macro",
    "clippy::suspicious",
    "unsafe_code",
]
CLIPPY_REPORTED = {l.split("::")[-1] for l in CLIPPY_DENY + CLIPPY_WARN}

SEV_ORDER = {"critical": 0, "warning": 1, "info": 2}


@dataclass
class Finding:
    tool: str
    rule: str
    severity: str  # critical | warning | info
    message: str
    path: str = ""
    line: int = 0
    snippet: str = ""


@dataclass
class ToolResult:
    name: str
    status: str = "ok"  # ok | findings | skipped | failed
    note: str = ""
    seconds: float = 0.0
    findings: list[Finding] = field(default_factory=list)


def run(cmd, timeout=1800, env=None, cwd=ROOT):
    e = os.environ.copy()
    if env:
        e.update(env)
    try:
        p = subprocess.run(cmd, cwd=cwd, env=e, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired as ex:
        return 124, (ex.stdout or b"").decode() if isinstance(ex.stdout, bytes) else (ex.stdout or ""), \
            f"TIMEOUT after {timeout}s"
    except FileNotFoundError:
        return 127, "", f"not found: {cmd[0]}"


def have(binary: str) -> bool:
    return shutil.which(binary) is not None


def have_cargo_sub(sub: str) -> bool:
    return have(f"cargo-{sub}")


def rel(p: str) -> str:
    try:
        return str(Path(p).resolve().relative_to(ROOT))
    except Exception:
        return p


def source_line(path: str, line: int) -> str:
    try:
        return (ROOT / path).read_text(errors="replace").splitlines()[line - 1].strip()[:200]
    except Exception:
        return ""


# ---- semgrep ----------------------------------------------------------------
def check_semgrep() -> ToolResult:
    r = ToolResult("semgrep")
    if not have("semgrep"):
        r.status, r.note = "skipped", "semgrep not installed (pip install semgrep / brew install semgrep)"
        return r
    # 1. rule self-test: rules that silently stop matching are worse than none
    code, out, err = run(["semgrep", "--test", "--metrics=off", "security/semgrep"], timeout=600)
    if code != 0 or "All tests passed" not in out + err:
        r.findings.append(Finding("semgrep", "rule-self-test", "info",
                                  "Semgrep rule fixtures failed - rules may be broken:\n" + (out + err)[-1500:]))
    code, out, err = run(["semgrep", "scan", "--metrics=off", "--disable-version-check", "--json", "-q",
                          "--config", "security/semgrep",
                          "--exclude", "security", "--exclude", "target", "."], timeout=1200)
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        r.status, r.note = "failed", (err or out)[-800:]
        return r
    for e in data.get("errors", []):
        r.findings.append(Finding("semgrep", "parse-error", "info", e.get("message", "")[:400],
                                  rel(e.get("path", "") or "")))
    for res in data.get("results", []):
        sev = {"ERROR": "critical", "WARNING": "warning"}.get(res["extra"]["severity"], "info")
        rid = res["check_id"].split("cesa.", 1)[-1]
        r.findings.append(Finding("semgrep", rid, sev, " ".join(res["extra"]["message"].split()),
                                  rel(res["path"]), res["start"]["line"],
                                  source_line(res["path"], res["start"]["line"])))
    return r


# ---- clippy -----------------------------------------------------------------
def check_clippy() -> ToolResult:
    r = ToolResult("clippy")
    flags = ["-A", "clippy::style", "-A", "clippy::complexity", "-A", "clippy::perf"]
    for l in CLIPPY_WARN:
        flags += ["-W", l]
    for l in CLIPPY_DENY:
        flags += ["-D", l]
    broken = []
    for crate in CRATES:
        code, out, err = run(["cargo", "clippy", "-p", crate, "--all-targets", "--message-format=json",
                              "--", *flags], timeout=1800)
        build_errors = 0
        seen = set()
        for line in out.splitlines():
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if msg.get("reason") != "compiler-message":
                continue
            m = msg["message"]
            lint = (m.get("code") or {}).get("code") or ""
            short = lint.split("::")[-1]
            span = next((s for s in m.get("spans", []) if s.get("is_primary")), None)
            if not span:
                continue
            path = span["file_name"]
            if not path.startswith(crate + "/") and not path.startswith(crate):
                # dependency or another crate's file compiled as part of this one
                if not any(path.startswith(c) for c in CRATES):
                    continue
            key = (lint, path, span["line_start"], m["message"])
            if key in seen:
                continue
            seen.add(key)
            if m["level"] == "error" and (not lint or lint.startswith("E")):
                build_errors += 1
                continue
            if short not in CLIPPY_REPORTED and not lint.startswith("clippy::"):
                continue
            if short not in CLIPPY_REPORTED:
                continue  # default style lints - not security
            sev = "critical" if m["level"] == "error" else "warning"
            r.findings.append(Finding("clippy", lint or "error", sev, m["message"],
                                      path, span["line_start"], (span.get("text") or [{}])[0].get("text", "").strip()[:200]))
        if build_errors:
            broken.append(f"{crate} ({build_errors} compile errors)")
    if broken:
        r.findings.append(Finding("clippy", "does-not-compile", "info",
                                  "Clippy could not fully analyse: " + ", ".join(broken) +
                                  ". Lints for code that does not compile are MISSING from this report."))
    return r


# ---- cargo audit ------------------------------------------------------------
def check_audit() -> ToolResult:
    r = ToolResult("cargo-audit")
    if not have_cargo_sub("audit"):
        r.status, r.note = "skipped", "cargo-audit not installed (cargo install cargo-audit --locked)"
        return r
    code, out, err = run(["cargo", "audit", "--json"], timeout=600)
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        r.status, r.note = "failed", (err or out)[-800:]
        return r
    for v in data.get("vulnerabilities", {}).get("list", []):
        a, pkg = v["advisory"], v["package"]
        r.findings.append(Finding("cargo-audit", a["id"], "critical",
                                  f"{pkg['name']} {pkg['version']}: {a['title']} "
                                  f"(fix: {', '.join(v.get('versions', {}).get('patched', [])) or 'none'})",
                                  "Cargo.lock"))
    for kind, items in (data.get("warnings") or {}).items():
        for w in items:
            a = w.get("advisory") or {}
            pkg = w.get("package", {})
            sev = "critical" if kind == "unsound" else "warning"
            fix = ", ".join((w.get("versions") or {}).get("patched", []) or []) or "none"
            r.findings.append(Finding("cargo-audit", f"{kind}:{a.get('id', '')}", sev,
                                      f"{pkg.get('name')} {pkg.get('version')}: {a.get('title', kind)} (fix: {fix})",
                                      "Cargo.lock"))
    return r


# ---- cargo deny -------------------------------------------------------------
def check_deny() -> ToolResult:
    r = ToolResult("cargo-deny")
    if not have_cargo_sub("deny"):
        r.status, r.note = "skipped", "cargo-deny not installed (cargo install cargo-deny --locked)"
        return r
    for check, sev in (("sources", "critical"), ("bans", "warning"), ("licenses", "warning")):
        code, out, err = run(["cargo", "deny", "--format", "json", "check", check], timeout=600)
        for line in err.splitlines():
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            if d.get("type") != "diagnostic":
                continue
            f = d["fields"]
            if f.get("severity") not in ("error", "warning"):
                continue
            s = sev if f["severity"] == "error" else "warning"
            r.findings.append(Finding("cargo-deny", f"{check}:{f.get('code', '')}", s,
                                      f.get("message", ""), "Cargo.lock"))
        if code not in (0, 1) and not r.findings:
            r.findings.append(Finding("cargo-deny", check, "info", f"cargo deny check {check} failed: {err[-400:]}"))
    return r


# ---- gitleaks ---------------------------------------------------------------
def check_gitleaks(git_range: str | None) -> ToolResult:
    r = ToolResult("gitleaks")
    if not have("gitleaks"):
        r.status, r.note = "skipped", "gitleaks not installed"
        return r
    report = OUT / "gitleaks.json"
    cmd = ["gitleaks", "git", "--no-banner", "--redact", "--exit-code", "0",
           "--report-format", "json", "--report-path", str(report)]
    if git_range:
        cmd += ["--log-opts", git_range]
    cmd.append(".")
    code, out, err = run(cmd, timeout=600)
    if not report.exists():
        r.status, r.note = "failed", (err or out)[-600:]
        return r
    for leak in json.loads(report.read_text() or "[]"):
        r.findings.append(Finding("gitleaks", leak.get("RuleID", "secret"), "critical",
                                  f"Possible secret committed in {leak.get('Commit', '')[:10]}: "
                                  f"{leak.get('Description', '')}",
                                  leak.get("File", ""), leak.get("StartLine", 0)))
    return r


# ---- miri -------------------------------------------------------------------
PASSED_RE = re.compile(r"test result: \w+\. (\d+) passed; (\d+) failed")


def count_tests(text: str) -> str:
    p = f = 0
    for m in PASSED_RE.finditer(text):
        p, f = p + int(m.group(1)), f + int(m.group(2))
    return f"{p} tests passed, {f} failed"


UB_RE = re.compile(r"error: (Undefined Behavior|unsupported operation)[^\n]*", re.I)


def check_miri() -> ToolResult:
    r = ToolResult("miri")
    code, out, err = run(["rustup", "run", "nightly", "cargo", "miri", "--version"], timeout=60)
    if code != 0:
        r.status, r.note = "skipped", "nightly + miri not installed (rustup +nightly component add miri)"
        return r
    for crate in MIRI_CRATES:
        skip = [a for t in MIRI_SKIP for a in ("--skip", t)]
        code, out, err = run(["cargo", "+nightly", "miri", "test", "-p", crate, "--", *skip],
                             env={"MIRIFLAGS": "-Zmiri-strict-provenance -Zmiri-symbolic-alignment-check"},
                             timeout=int(os.environ.get("CESA_MIRI_TIMEOUT", "2400")))
        text = out + err
        r.note = (r.note + "; " if r.note else "") + f"{crate}: {count_tests(text)}"
        for m in UB_RE.finditer(text):
            sev = "critical" if m.group(1).lower().startswith("undefined") else "info"
            loc = re.search(r"--> ([^\s:]+):(\d+)", text[m.end():m.end() + 2000])
            r.findings.append(Finding("miri", m.group(1), sev, m.group(0)[:300],
                                      loc.group(1) if loc else crate, int(loc.group(2)) if loc else 0))
        if code == 124:
            r.findings.append(Finding("miri", "timeout", "info", f"Miri timed out on {crate} (partial coverage)"))
        elif code != 0 and not r.findings:
            r.findings.append(Finding("miri", "tests-failed", "warning",
                                      f"Tests fail under Miri for {crate}:\n{text[-1200:]}"))
    return r


# ---- ThreadSanitizer --------------------------------------------------------
TSAN_RE = re.compile(r"WARNING: ThreadSanitizer: ([a-z\- ]+)")


def check_tsan() -> ToolResult:
    r = ToolResult("tsan")
    if platform.system() != "Linux" or platform.machine() not in ("x86_64", "aarch64"):
        r.status, r.note = "skipped", "ThreadSanitizer runs in CI (Linux) only"
        return r
    target = f"{platform.machine()}-unknown-linux-gnu"
    env = {"RUSTFLAGS": "-Zsanitizer=thread -Cforce-frame-pointers=yes",
           "RUSTDOCFLAGS": "-Zsanitizer=thread",
           "TSAN_OPTIONS": "halt_on_error=0 second_deadlock_stack=1 report_signal_unsafe=0",
           "CARGO_TARGET_DIR": str(ROOT / "target" / "tsan")}
    broken = []
    for crate in CRATES:
        code, out, err = run(["cargo", "+nightly", "test", "-Zbuild-std", "--target", target, "-p", crate,
                              "--all-targets"], env=env,
                             timeout=int(os.environ.get("CESA_TSAN_TIMEOUT", "1800")))
        text = out + err
        if code != 0 and not PASSED_RE.search(text):
            # nothing ran: build failure (e.g. crate does not compile) or toolchain problem
            broken.append(crate)
            tail = "\n".join(l for l in text.splitlines() if l.startswith("error"))[-600:] or text[-600:]
            r.findings.append(Finding("tsan", "not-tested", "info",
                                      f"{crate} was NOT race-tested (exit {code}):\n{tail}"))
            continue
        r.note = (r.note + "; " if r.note else "") + f"{crate}: {count_tests(text)}"
        seen = set()
        for m in TSAN_RE.finditer(text):
            kind = m.group(1).strip()
            block = text[m.start():m.start() + 4000]
            loc = re.search(r"(\S+\.rs):(\d+)", block)
            key = (kind, loc.group(0) if loc else "")
            if key in seen:
                continue
            seen.add(key)
            r.findings.append(Finding("tsan", kind, "critical",
                                      f"ThreadSanitizer: {kind} in {crate} tests",
                                      rel(loc.group(1)) if loc else crate, int(loc.group(2)) if loc else 0,
                                      block[:600]))
        if code == 124:
            r.findings.append(Finding("tsan", "timeout", "warning",
                                      f"{crate} tests timed out under TSan - possible deadlock or hang"))
    if broken:
        r.note = (r.note + "; " if r.note else "") + "NOT tested: " + ", ".join(broken)
    return r


# ---- reviewed dependency exceptions -----------------------------------------
ACCEPTED = ROOT / "security" / "accepted.json"


def lock_versions() -> dict[str, set[str]]:
    """crate name -> every version of it in Cargo.lock"""
    out: dict[str, set[str]] = {}
    lock = (ROOT / "Cargo.lock").read_text()
    for m in re.finditer(r'^name = "([^"]+)"\nversion = "([^"]+)"', lock, re.M):
        out.setdefault(m.group(1), set()).add(m.group(2))
    return out


def apply_accepted(results: list[ToolResult]) -> None:
    """Downgrades reviewed, unfixable dependency findings (security/accepted.json)
    to notes. Exact match only - a new version or package makes it a warning
    again. Never applies to critical findings or first-party code. Stale entries
    are reported so the list can't silently rot."""
    if not ACCEPTED.exists():
        return
    acc = json.loads(ACCEPTED.read_text())
    dups, advs = acc.get("duplicates", {}), acc.get("advisories", {})
    versions = lock_versions()
    used: set[str] = set()

    for r in results:
        for f in r.findings:
            if f.severity != "warning" or f.path != "Cargo.lock":
                continue
            m = re.search(r"duplicate entries for crate '([^']+)'", f.message)
            if r.name == "cargo-deny" and f.rule == "bans:duplicate" and m:
                name = m.group(1)
                e = dups.get(name)
                if e and set(e["versions"]) == versions.get(name, set()):
                    f.severity, f.rule = "info", "accepted:duplicate"
                    f.message = f"{name} {', '.join(sorted(versions[name]))} - {e['reason']}"
                    used.add(f"dup:{name}")
            elif r.name == "cargo-audit":
                adv_id = f.rule.split(":")[-1]
                e = advs.get(adv_id)
                pkg = f.message.split(":")[0].replace(" ", "@")
                if e and e["package"] == pkg:
                    f.severity, f.rule = "info", f"accepted:{adv_id}"
                    f.message = f"{pkg} - {e['reason']}"
                    used.add(f"adv:{adv_id}")

    stale = [f"duplicate {n}" for n in dups if f"dup:{n}" not in used] + \
            [f"advisory {i}" for i in advs if f"adv:{i}" not in used]
    ran = {r.name for r in results}
    if stale and {"cargo-deny", "cargo-audit"} <= ran:
        results.append(ToolResult("accepted", "findings", findings=[
            Finding("accepted", "stale-exception", "info",
                    f"{x} in security/accepted.json no longer matches (fixed or version changed) - remove it",
                    "security/accepted.json") for x in stale]))


# ---- report -----------------------------------------------------------------
GAP_RULES = {"does-not-compile", "not-tested", "tool-failed", "timeout"}


def coverage_gaps(results: list[ToolResult]) -> list[str]:
    """Everything that was NOT actually analysed: skipped tools, crates that did not
    build, checkers that crashed or timed out. A green result must not hide these."""
    gaps = []
    for r in results:
        if r.status == "skipped":
            gaps.append(f"{r.name}: skipped ({r.note})")
        for f in r.findings:
            if f.rule in GAP_RULES and f.severity == "info":
                gaps.append(f"{r.name}: {f.message.splitlines()[0]}")
    return gaps


def write_report(results: list[ToolResult], mode: str) -> tuple[int, str]:
    allf = [f for r in results for f in r.findings]
    allf.sort(key=lambda f: (SEV_ORDER[f.severity], f.tool, f.path, f.line))
    crit = sum(f.severity == "critical" for f in allf)
    warn = sum(f.severity == "warning" for f in allf)
    info = sum(f.severity == "info" for f in allf)

    sha = run(["git", "rev-parse", "--short", "HEAD"])[1].strip()
    gaps = coverage_gaps(results)
    verdict = "❌ BLOCKED" if crit else ("⚠️ PASSED - PARTIAL COVERAGE" if gaps else "✅ PASSED")
    lines = [f"# CesaConn security report ({mode}) - `{sha}`", "",
             f"**{verdict}** - {crit} critical, {warn} warnings, {info} notes", ""]
    if gaps:
        lines += ["> [!WARNING]",
                  "> **Not everything was analysed.** A pass only covers what actually ran:",
                  *[f"> - {g}" for g in gaps], ""]
    lines += [
             "| Tool | Status | Critical | Warnings | Time |", "|---|---|---|---|---|"]
    for r in results:
        c = sum(f.severity == "critical" for f in r.findings)
        w = sum(f.severity == "warning" for f in r.findings)
        st = r.status if r.status in ("skipped", "failed") else ("findings" if r.findings else "clean")
        lines.append(f"| {r.name} | {st}{(' - ' + r.note) if r.note else ''} | {c} | {w} | {r.seconds:.0f}s |")
    for sev, title in (("critical", "🔴 Critical (blocking)"), ("warning", "🟡 Warnings"), ("info", "ℹ️ Notes")):
        group = [f for f in allf if f.severity == sev]
        if not group:
            continue
        lines += ["", f"## {title}", ""]
        if sev == "warning":
            # summary by rule first - warnings can be many
            from collections import Counter
            cnt = Counter(f"{f.tool}: {f.rule}" for f in group)
            lines += ["| Rule | Count |", "|---|---|"] + [f"| `{k}` | {v} |" for k, v in cnt.most_common()] + [""]
            lines.append("<details><summary>All warnings</summary>\n")
        for f in group:
            loc = f"`{f.path}:{f.line}`" if f.line else (f"`{f.path}`" if f.path else "")
            lines.append(f"- **{f.tool} / {f.rule}** {loc}  \n  {f.message}")
            if f.snippet and sev == "critical":
                lines.append(f"  ```\n  {f.snippet}\n  ```")
        if sev == "warning":
            lines.append("\n</details>")
    lines += ["", "Suppress a reviewed false positive with `// nosemgrep: <rule-id>` or "
              "`#[allow(clippy::<lint>)]` + a comment explaining why."]
    md = "\n".join(lines) + "\n"
    (OUT / "report.md").write_text(md)

    # SARIF (GitHub code scanning)
    runs = []
    for r in results:
        res = []
        for f in r.findings:
            if not f.path or f.severity == "info":
                continue
            res.append({"ruleId": f"{r.name}/{f.rule}",
                        "level": "error" if f.severity == "critical" else "warning",
                        "message": {"text": f.message},
                        "locations": [{"physicalLocation": {
                            "artifactLocation": {"uri": f.path},
                            "region": {"startLine": max(f.line, 1)}}}]})
        runs.append({"tool": {"driver": {"name": f"cesa-{r.name}", "informationUri":
                                         "https://github.com/czarekkdev/cesaconn",
                                         "rules": [{"id": i} for i in sorted({x["ruleId"] for x in res})]}},
                     "results": res})
    (OUT / "security.sarif").write_text(json.dumps(
        {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": runs}, indent=1))
    return crit, md


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fast", action="store_true", help="static checks only (pre-push hook)")
    ap.add_argument("--range", default=os.environ.get("CESA_GIT_RANGE"),
                    help="git log range for secret scanning, e.g. origin/main..HEAD")
    ap.add_argument("--only", help="comma-separated subset: semgrep,clippy,audit,deny,gitleaks,miri,tsan")
    a = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)

    checks = [("semgrep", check_semgrep), ("clippy", check_clippy), ("audit", check_audit),
              ("deny", check_deny), ("gitleaks", lambda: check_gitleaks(a.range))]
    if not a.fast:
        checks += [("miri", check_miri), ("tsan", check_tsan)]
    if a.only:
        want = set(a.only.split(","))
        checks = [c for c in checks if c[0] in want]

    results = []
    for name, fn in checks:
        print(f"[security] {name} ...", flush=True)
        t = time.time()
        try:
            res = fn()
        except Exception as ex:  # a crashing checker must never pass silently
            res = ToolResult(name, "failed", f"checker crashed: {ex!r}")
        res.seconds = time.time() - t
        if res.status == "failed":
            res.findings.append(Finding(name, "tool-failed", "info", res.note))
        c = sum(f.severity == "critical" for f in res.findings)
        print(f"[security] {name}: {res.status}, {len(res.findings)} findings ({c} critical) "
              f"in {res.seconds:.0f}s", flush=True)
        results.append(res)

    apply_accepted(results)
    crit, md = write_report(results, "fast" if a.fast else "full")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as fh:
            fh.write(md)
    print()
    for f in [f for r in results for f in r.findings if f.severity == "critical"]:
        loc = f"{f.path}:{f.line}" if f.line else f.path
        print(f"  CRITICAL  {f.tool}/{f.rule}  {loc}\n            {f.message[:220]}")
    gaps = coverage_gaps(results)
    for g in gaps:
        print(f"  NOT ANALYSED  {g}")
        if os.environ.get("GITHUB_ACTIONS"):
            # shows up as a yellow annotation on the run and in the PR checks
            msg = g.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
            print(f"::warning title=Security gate - partial coverage::{msg}")
    strict = os.environ.get("CESA_REQUIRE_FULL_COVERAGE") == "1"
    print(f"\nReport: {OUT / 'report.md'}")
    if crit:
        print("RESULT: BLOCKED", f"({crit} critical)")
        return 1
    if gaps:
        print("RESULT: PASSED - PARTIAL COVERAGE", f"({len(gaps)} gaps{', strict mode -> failing' if strict else ''})")
        return 1 if strict else 0
    print("RESULT: PASSED (0 critical, full coverage)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
