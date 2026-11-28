# Daemon states

daemon.md 6.1 and 13. Networking is not a state of its own: it runs exactly
while the vault is open, both keys are set and Sync is on, and every state
change checks that again.

```mermaid
stateDiagram-v2
    [*] --> Fresh: no vault file
    [*] --> Locked: vault file found (its header gives the mode, or shows an older version)
    Fresh --> Joining: JoinGroup / JoinGroupAt (pw1, pw2)
    Joining --> Fresh: cancel, 5 min, 5 attempts used up, before a commit started (passwords wiped)
    Joining --> Open: paired, both salts received, vault created with Sync on (a cancel or the 5 min after the commit started don't stop it)
    Joining --> RamOnly: commit ran, but the vault couldn't be saved (keys and the member kept in RAM)
    Fresh --> Partial: SetAuth or SetData
    Partial --> Open: second key set, vault created
    Partial --> RamOnly: second key set, no storage or the save failed
    RamOnly --> Open: next successful key change creates the vault
    Locked --> Open: Unlock(pw2), UnlockBoth(pw1, pw2) in Enhanced mode, or automatic login (Standard only)
    Locked --> Locked: wrong password (delay after 5 failures)
    Open --> Open: SetAuth / SetData (re-seal) / SetAutoLogin / SetEnhanced / SetClipboard
    Open --> Fresh: ResetDevice
    Locked --> Fresh: ResetDevice
    Open --> [*]: Ctrl-C (RAM wiped)
    Locked --> [*]: Ctrl-C
```

## When networking runs

```mermaid
flowchart LR
    change["any state change<br/>(or auto-login at start)"] --> check{"vault open<br/>and both keys<br/>and Sync on?"}
    check -- yes --> bind{"listener binds<br/>TCP 3232?"}
    bind -- yes --> on["networking on:<br/>listener 3232, pairing bridge,<br/>clipboard task, hello round"]
    bind -- no --> failed["stays off: Status shows Sync on but<br/>network_running false (see the daemon log)"]
    check -- no --> off["networking off:<br/>token cancelled, connections end,<br/>Add device window closes,<br/>waiting pairings rejected"]
```

## Unlock

```mermaid
flowchart TB
    u["Unlock(pw2) / UnlockBoth(pw1, pw2)"] --> old{"outdated<br/>vault?"}
    old -- yes --> outdated["VaultOutdated at once<br/>(no Argon2, not counted; only a reset helps)"]
    old -- no --> wait{"inside the<br/>delay?"}
    wait -- yes --> delayed["UnlockDelayed at once<br/>(no file read, no Argon2, not counted)"]
    wait -- no --> mode{"request fits the<br/>header's mode?"}
    mode -- no --> wrongreq["Unlock on Enhanced: NeedsBothPasswords<br/>UnlockBoth on Standard: BadRequest<br/>(no Argon2, not counted)"]
    mode -- yes --> derive["d_key = Argon2id(pw2, d_salt)<br/>Enhanced: also a_key = Argon2id(pw1, a_salt)<br/>Standard: KEK = HKDF(d_key, storage salt)<br/>Enhanced: KEK = HKDF(Argon2id(d_key || a_key))"]
    derive --> open{"DEK unwraps?"}
    open -- yes --> ok["Open: counter and delay reset"]
    open -- no --> wrong["WrongPassword, failures + 1 (one per attempt,<br/>never says which password)<br/>after 5: next not before 1 s,<br/>doubling up to 60 s"]
```
