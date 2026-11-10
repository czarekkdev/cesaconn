# Forgetting a device, resetting this one

daemon.md 14. Both are local: neither is a revocation.

## Forget (`d`, then `y`)

```mermaid
flowchart TB
    f["ForgetPeer(fingerprint)"] --> locked{"vault locked?"}
    locked -- yes --> lk["Locked"]
    locked -- no --> known{"a peer with that<br/>fingerprint?"}
    known -- no --> unk["UnknownPeer"]
    known -- yes --> mem["remove every such peer from memory<br/>(new handshakes: unknown at once)"]
    mem --> save{"vault re-sealed?"}
    save -- yes --> done["forgotten here"]
    save -- no --> back["put the entries back in place,<br/>StorageFailed"]
    done -. "it still knows both passwords" .-> again["it can pair again in an<br/>Add device window, if the user says y"]
```

## Reset (Settings > Reset this device, type `RESET`)

Works while locked and asks for no password (a forgotten pw2 or lost
keychain salts are the reason to use it).

```mermaid
flowchart TB
    r["ResetDevice (CN-RESET bytes)"] --> s1["1. reset counter + 1, cancel a join,<br/>stop networking (window, salt port, prompts)"]
    s1 --> s2{"2. delete vault.bin<br/>(the decisive step)"}
    s2 -- failed --> keep["StorageFailed: keys, vault and peers unchanged;<br/>the join and the window stay cancelled;<br/>networking starts again if the saved state says so"]
    s2 -- deleted --> s3["3. drop the key slots (zeroized),<br/>replace the trusted-peer list with a new one,<br/>clear prompts"]
    s3 --> s4{"4. delete keychain<br/>salts + data-key"}
    s4 -- ok --> fresh["Fresh: n joins a group again"]
    s4 -- failed --> fresh2["Fresh anyway (no vault = keychain ignored),<br/>StorageFailed: a second reset removes them"]
```

```mermaid
sequenceDiagram
    participant Old as handshake of the old network
    participant D as Daemon
    participant J as join started before the reset
    Note over D: reset: new trusted-peer list, reset counter + 1
    Old->>D: finishes late, pairs
    Note over D: it pairs into the old, dropped list: nothing comes back
    J->>D: commit
    Note over D: reset counter changed: commit refused
```
