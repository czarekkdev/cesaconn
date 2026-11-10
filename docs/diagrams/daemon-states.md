# Daemon states

daemon.md 6.1 and 13. Networking is not a state of its own: it runs exactly
while the vault is open, both keys are set and Sync is on, and every state
change checks that again.

```mermaid
stateDiagram-v2
    [*] --> Fresh: no vault file
    [*] --> Locked: vault file found
    Fresh --> Joining: JoinGroup / JoinGroupAt (pw1, pw2)
    Joining --> Fresh: cancel, 5 min, 5 attempts used up, before a commit started (passwords wiped)
    Joining --> Open: paired, both salts received, vault created with Sync on (a cancel or the 5 min after the commit started don't stop it)
    Joining --> RamOnly: commit ran, but the vault couldn't be saved (keys and the member kept in RAM)
    Fresh --> Partial: SetAuth or SetData
    Partial --> Open: second key set, vault created
    Partial --> RamOnly: second key set, no storage or the save failed
    RamOnly --> Open: next successful key change creates the vault
    Locked --> Open: Unlock(pw2) or automatic login
    Locked --> Locked: wrong pw2 (delay after 5 failures)
    Open --> Open: SetAuth / SetData (re-seal) / SetAutoLogin / SetClipboard
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

## Unlock delay

```mermaid
flowchart TB
    u["Unlock(pw2)"] --> wait{"inside the<br/>delay?"}
    wait -- yes --> delayed["UnlockDelayed at once<br/>(no keychain, no Argon2, not counted)"]
    wait -- no --> derive["d_key = Argon2id(pw2, d_salt)<br/>KEK = HKDF(d_key, storage salt)"]
    derive --> open{"DEK unwraps?"}
    open -- yes --> ok["Open: counter and delay reset"]
    open -- no --> wrong["WrongPassword, failures + 1<br/>after 5: next not before 1 s,<br/>doubling up to 60 s"]
```
