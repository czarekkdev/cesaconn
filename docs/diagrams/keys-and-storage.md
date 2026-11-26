# Keys and storage

daemon.md 4, 6.3-6.7 and 8. Two passwords, two independent keys; the salts
belong to the group (section 11) and sit in the vault's header in plain.
The vault needs nothing from the OS; the keychain only holds `d_key` for
the opt-in automatic login.

```mermaid
flowchart LR
    pw1["pw1<br/>(auth password)"] --> a_argon["Argon2id<br/>64 MiB"]
    a_salt["a_salt<br/>(group, public)"] --> a_argon
    a_argon --> a_key["a_key<br/>SPAKE2 password"]

    pw2["pw2<br/>(data password)"] --> d_argon["Argon2id<br/>64 MiB"]
    d_salt["d_salt<br/>(group, sent only after auth)"] --> d_argon
    d_argon --> d_key["d_key<br/>data layer + vault"]

    d_key --> hkdf["HKDF-BLAKE2s"]
    a_key -. "Enhanced mode only:<br/>ikm = d_key || a_key" .-> hkdf
    s_salt["storage salt<br/>(this device)"] --> hkdf
    hkdf --> kek["KEK"]
    kek -- "AES-256-GCM wraps" --> dek["DEK (random)"]
    dek -- "AES-256-GCM seals" --> contents["vault contents"]
```

Standard mode: `KEK = HKDF(d_key, storage salt, "cesaconn-storage-v1")`.
Enhanced mode: `KEK = HKDF(d_key || a_key, storage salt,
"cesaconn-storage-both-v1")`, so only both passwords together open it.

## What is stored where

```mermaid
flowchart TB
    subgraph ram["daemon RAM (Zeroizing)"]
        r1["a_key, d_key, a_salt, d_salt,<br/>DEK, identity seed, peers"]
    end
    subgraph kc["OS keychain (macOS, device only, never synced)"]
        k2["data-key: d_key (32)<br/>only with automatic login,<br/>never in Enhanced mode"]
    end
    subgraph file["vault.bin (0600, private dir)"]
        f0["header (plain, authenticated):<br/>CESAVLT\0 || 0x03 || mode ||<br/>a_salt || d_salt || storage salt"]
        f1["wrap nonce || AES-GCM(KEK, DEK)"]
        f2["data nonce || AES-GCM(DEK, padded contents)"]
        f2 --> c["contents (TLV, fixed order):<br/>a_key (Standard mode only), config<br/>(Sync, clipboard, last addresses),<br/>identity seed, peers"]
    end
```

The file alone is enough for an offline guess (its salts are in it), at a
full Argon2 run per guess: that is why new passwords need 12 characters.
Standard mode: cracking `pw2` also gives `a_key` (it is inside, 18.2).
Enhanced mode: `a_key` isn't in the file and a guess must get both
passwords right at once.

## First setup: creating the vault

```mermaid
sequenceDiagram
    participant UI
    participant D as Daemon
    participant F as vault.bin
    UI->>D: SetAuthPassword(pw1)
    Note over D: a_salt made (first use), a_key = Argon2(pw1, a_salt)
    UI->>D: SetDataPassword(pw2)
    Note over D: d_salt made, d_key = Argon2(pw2, d_salt)
    Note over D: both keys, no vault: create_vault() in Standard mode<br/>storage salt, DEK, identity seed, KEK, seal
    D->>F: write atomically (temp file, fsync, rename): one file, salts in its header
    Note over D: only now keep the open vault in RAM<br/>any failure: keys stay RAM only, nothing half-written
```

## Changing a password

```mermaid
flowchart LR
    new["new password<br/>(UI asked 'are you sure?')"] --> kind{"which?"}
    kind -- pw1 --> a["a_key from the same a_salt<br/>Standard: re-seal with the new a_key<br/>Enhanced: re-wrap the DEK (KEK uses a_key), re-seal"]
    kind -- pw2 --> d["d_key from the same d_salt<br/>re-wrap DEK, re-seal;<br/>auto-login: replace data-key"]
    a --> saved["saved first, kept second"]
    d --> saved
    saved --> net{"networking running<br/>(Sync on)?"}
    net -- yes --> hello["hello to every paired device with a<br/>known address that isn't paused: those<br/>with the old password show<br/>'incorrect password' (13.1)"]
    net -- no --> later["no hello now: shown when<br/>the devices next connect"]
```

## Enhanced security on / off

```mermaid
flowchart LR
    req["SetEnhanced(on)"] --> open{"vault open<br/>and unlocked?"}
    open -- no --> refused["Locked / NotSaved"]
    open -- yes --> same{"already<br/>that mode?"}
    same -- yes --> done["Done, nothing written"]
    same -- no --> auto{"turning on and<br/>automatic login on?"}
    auto -- yes --> conflict["AutoLoginConflict<br/>(the TUI turns automatic login off first)"]
    auto -- no --> rewrap["new header (mode byte), KEK for the new mode,<br/>re-wrap the same DEK, re-seal with / without a_key"]
    rewrap --> write["write atomically, then keep<br/>(saved first, kept second)"]
```
