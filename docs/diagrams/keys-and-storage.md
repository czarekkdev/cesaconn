# Keys and storage

daemon.md 4, 6.3-6.5 and 8. Two passwords, two independent keys; the salts
belong to the group (section 11).

```mermaid
flowchart LR
    pw1["pw1<br/>(auth password)"] --> a_argon["Argon2id<br/>64 MiB"]
    a_salt["a_salt<br/>(group, public)"] --> a_argon
    a_argon --> a_key["a_key<br/>SPAKE2 password"]

    pw2["pw2<br/>(data password)"] --> d_argon["Argon2id<br/>64 MiB"]
    d_salt["d_salt<br/>(group, sent only after auth)"] --> d_argon
    d_argon --> d_key["d_key<br/>data layer + vault"]

    d_key --> hkdf["HKDF"]
    s_salt["storage salt<br/>(this device)"] --> hkdf
    hkdf --> kek["KEK"]
    kek -- "AES-256-GCM wraps" --> dek["DEK (random)"]
    dek -- "AES-256-GCM seals" --> contents["vault contents"]
```

## What is stored where

```mermaid
flowchart TB
    subgraph ram["daemon RAM (Zeroizing)"]
        r1["a_key, d_key, a_salt, d_salt,<br/>DEK, identity seed, peers"]
    end
    subgraph kc["OS keychain (device only, never synced)"]
        k1["salts: d_salt (32) || storage salt (32)"]
        k2["data-key: d_key (32)<br/>only with automatic login"]
    end
    subgraph file["vault.bin (0600, private dir)"]
        f0["header: CESAVLT\0 || 0x02"]
        f1["wrap nonce || AES-GCM(KEK, DEK)"]
        f2["data nonce || AES-GCM(DEK, padded contents)"]
        f2 --> c["contents (TLV, fixed order):<br/>a_key, a_salt, config (Sync, clipboard,<br/>last addresses), identity seed, peers"]
    end
```

Cracking `pw2` needs the vault file **and** the keychain salts; it then also
gives `a_key` (18). That is why new passwords need 12 characters.

## First setup: creating the vault

```mermaid
sequenceDiagram
    participant UI
    participant D as Daemon
    participant KC as Keychain
    participant F as vault.bin
    UI->>D: SetAuthPassword(pw1)
    Note over D: a_salt made (first use), a_key = Argon2(pw1, a_salt)
    UI->>D: SetDataPassword(pw2)
    Note over D: d_salt made, d_key = Argon2(pw2, d_salt)
    Note over D: both keys, no vault: create_vault()<br/>storage salt, DEK, identity seed, KEK, seal
    D->>KC: write d_salt || storage salt
    D->>F: write atomically (temp file, fsync, rename)
    Note over D: only now keep the open vault in RAM<br/>any failure: keys stay RAM only, nothing half-written
```

## Changing a password

```mermaid
flowchart LR
    new["new password<br/>(UI asked 'are you sure?')"] --> kind{"which?"}
    kind -- pw1 --> a["a_key from the same a_salt<br/>re-seal the vault"]
    kind -- pw2 --> d["d_key from the same d_salt<br/>re-wrap DEK, re-seal;<br/>auto-login: replace data-key"]
    a --> saved["saved first, kept second"]
    d --> saved
    saved --> hello["hello to every paired device:<br/>those with the old password show<br/>'incorrect password' (13.1)"]
```
