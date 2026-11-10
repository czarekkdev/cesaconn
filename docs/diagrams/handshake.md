# auth_snow: the handshake

daemon.md 10. Phases 1-5 run under one 20 s deadline; pairing (6) waits for
humans, after the signatures verified.

```mermaid
sequenceDiagram
    participant C as Client (connects)
    participant S as Server (listens)
    Note over C,S: Phase 1: SPAKE2 with a_key, identities bound to a_salt
    C->>S: SPAKE2 msg A
    S->>C: SPAKE2 msg B
    C->>S: confirm C->S (client proves first)
    Note over S: wrong: close, count a guess
    S->>C: confirm S->C
    Note over C,S: Phase 2: hybrid key exchange
    C->>S: X25519 public key
    S->>C: X25519 public key
    C->>S: confirm byte
    C->>S: ML-KEM-1024 encapsulation key
    Note over S: FIPS 203 key check
    S->>C: ML-KEM ciphertext
    C->>S: confirm byte
    Note over C,S: Phase 3: PSK = HKDF(key1, x25519_ss, mlkem_ss, transcript hash)
    Note over C,S: Phase 4: Noise XXpsk3 with the device identity key
    C->>S: msg1: e
    S->>C: msg2: e, ee, s, es
    C->>S: msg3: s, se, psk
    Note over C,S: Noise transport from here
    Note over C,S: Phase 5: who is it
    C->>S: IsSaved
    S->>C: IsSaved
    C->>S: ML-DSA-87 key + signature over the handshake hash
    Note over S: verify first (known peer: key must match)
    S->>C: ML-DSA-87 key + signature
    opt Phase 6: not both saved (new device)
        Note over C,S: both users compare 8 emoji + names, y / n (60 s)
        C->>S: decision
        S->>C: decision
        Note over C,S: both yes: save the peer, re-seal the vault
    end
```

## Why each layer

```mermaid
flowchart TB
    p1["SPAKE2 (pw1)"] -->|"one online guess per connection,<br/>nothing to test offline"| p2
    p2["X25519 + ML-KEM-1024"] -->|"fresh secrets, one post-quantum"| p3
    p3["PSK = HKDF(key1, both secrets, transcript)"] -->|"binds everything before Noise:<br/>a relay or a changed message fails msg3"| p4
    p4["Noise XXpsk3"] -->|"encrypted transport, peer's static key,<br/>handshake hash"| p5
    p5["ML-DSA-87 signatures"] -->|"peer owns its identity, keys pinned"| p6
    p6["pairing code (humans)"] -->|"a MITM with pw1 shows<br/>different codes"| data
    data["d_key data layer (pw2)<br/>AES-256-GCM per connection + direction"]
```

## One data packet (after the handshake)

```mermaid
sequenceDiagram
    participant C as Sender
    participant S as Receiver
    alt Hello / ClipboardSync (answered)
        C->>S: init header: ActionType || length (payload + 28), tag 0x01
        Note over S: length bounded before allocating
        C->>S: payload through the d_key layer, chunked
        S->>C: one byte through Noise only:<br/>0x00 applied, 0x01 ignored, 0x02 data passwords differ
    else GroupSalt (join only)
        C->>S: init header: GroupSalt || length 0 (no payload)
        S->>C: d_salt (32) through Noise, only to a device paired just now
    end
```
