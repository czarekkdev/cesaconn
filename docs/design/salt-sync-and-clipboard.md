# Design: salt syncing + clipboard sync protocol

Status: **draft for review** (no code yet). Builds on PR #19, where the
daemon owns the salts.

Sections marked **DECISION** need your call; everything else is a proposal
you can change.

---

## 0. Ground rules this design keeps

- Secrets (keys, salts, passwords, clipboard content) live only in daemon
  memory (`Zeroizing`), the OS keychain, or an encrypted file. The UI holds
  nothing.
- A password lives in the daemon only as long as it must, and always in a
  zeroizing buffer.
- UDP discovery carries nothing derived from a password or a salt.
- SPAKE2 stays the only trust decision. Nothing here adds an offline
  guessing oracle.
- Every feature is off by default.
- Every network read has a timeout, every length is bounded before
  allocating, and every handshake has a deadline.

---

## Part A: salt syncing

### A.1 The problem

`a_key = Argon2(pw1, a_salt)` is the SPAKE2 password, so two devices only
authenticate if they share the same `a_salt`. The same goes for
`d_key = Argon2(pw2, d_salt)`, which encrypts the data layer.

Today (#19) every daemon picks its own random salts, so no two devices can
agree on keys.

### A.2 Options considered

| Option | Verdict |
|---|---|
| Salt derived from the password (`salt = H(pw)`) or one fixed app-wide salt | **Rejected.** Every CesaConn user shares the salt, so one precomputed table cracks everyone. This defeats the purpose of a salt. |
| A fresh salt per connection, Argon2 on every connect | **Rejected.** The daemon would have to keep the password forever (breaks rule 0.2), and it costs 64 MiB plus ~0.3 s per connection on both sides. |
| User types the salt on each device (the first #19 commit) | **Rejected** by you. The salt belongs in the daemon, not the UI. |
| **A group salt plus a "join" flow** (below) | **Proposed.** |

### A.3 Proposal: a device group with group salts

A *group* is all the devices sharing one password pair. It has two public,
random group parameters, `a_salt` and `d_salt`, each 32 bytes from the OS
RNG. They are created once by the first device.

**Creating a group** (first device):
1. The UI sends `CreateGroup`.
2. The user enters pw1 and pw2.
3. The daemon generates `a_salt` and `d_salt`, then derives `a_key` and
   `d_key`.
4. The passwords are wiped right after derivation, as today.

**Joining a group** (every other device):
1. The UI sends `JoinGroup`.
2. The user enters pw1 and pw2.
3. The daemon can't derive anything yet, because it has no salts. It keeps
   pw1 and pw2 in `Zeroizing` buffers in a **join slot**, for at most
   `JOIN_WINDOW` (proposal: 5 min) or until the join finishes. On timeout,
   cancel, or daemon exit, the slot is wiped.
4. **Salt fetch** (A.4): the joiner gets `a_salt` from a group member, then
   derives `a_key` and wipes pw1.
5. The normal handshake runs: SPAKE2, hybrid KEX, Noise, ML-DSA, and the
   **pairing confirmation** (both users compare the code).
6. After the handshake succeeds, the member sends `d_salt` over the secure
   channel (A.5). The joiner derives `d_key` and wipes pw2.
7. The salts are **committed** only after steps 5 and 6 both succeed.
   Otherwise they are thrown away and the device stays in join mode.

After that the device behaves like any member: salts and keys sit in daemon
memory, or in the keychain or encrypted file once storage is decided.

### A.4 Salt fetch (pre-auth, `a_salt` only)

This is a separate short TCP exchange on the same port, *before* the real
handshake, because Argon2 can't run inside the 20 s handshake deadline.

```
joiner -> member : SALT_QUERY_MAGIC (8) || version (1)
member -> joiner : a_salt (32)
(close)
```

- The member answers only if it has a group, and only within the existing
  connection cap and `guess_limiter` lockout. Each IP gets at most one
  answer per N seconds.
- The query itself is not a password guess, so the guess counter is not
  touched.
- **`d_salt` is never sent before authentication.**

Why this is safe:
- `a_salt` is public by design. Knowing it gives no offline test of pw1,
  because SPAKE2 transcripts don't let anyone verify a guess offline. An
  attacker can only make online guesses, and `guess_limiter` already limits
  those.
- **A man in the middle sends a fake salt.** The joiner derives a wrong
  `a_key`:
  - with a real member, SPAKE2 just fails;
  - with the attacker, the attacker gets one *online* guess, which is
    rate-limited on the joiner's side too;
  - nothing is committed, because step 7 only commits after a confirmed
    pairing. The worst case is a failed join (DoS), never a wrong group.
- **The salt is bound into the handshake.** `a_salt` is appended to the
  SPAKE2 transcript, in the same order on both sides. A salt mismatch is
  then caught by the SPAKE2 confirmation, not only implicitly through
  differing keys.

Privacy cost (**DECISION 1**):
- Anyone on the LAN who connects can read `a_salt`, and it is stable, so it
  works as a group identifier that can link your devices across networks.
- Mitigation options:
  - (a) accept it, and answer salt queries only while a member's user has
    opened "Add device" (a time-limited **invite window**, e.g. 2 min);
  - (b) always answer.
- I recommend **(a)**: no window, no answer, so a closed group reveals
  nothing.

### A.5 `d_salt` sync (post-auth)

A new `ActionType::GroupSalt = 0x04`, sent only inside an authenticated
`SecureConnection`:
- payload: `d_salt (32)`;
- it goes through the Noise transport only, not the `d_key` layer, because
  the joiner has no `d_key` yet;
- it is sent only when the peer was just paired with us, *and* that pairing
  happened while our invite window was open.

### A.6 Group membership, rotation, revocation

These are out of scope here; they belong to "trusted-peer sync and
revocation", which is open decision 3 on the roadmap. Note for later: a
password change or a revocation means a new group, with new salts and new
keys, re-distributed to the remaining devices.

### A.7 IPC changes (UI <-> daemon)

| Request | Payload | Note |
|---|---|---|
| `CreateGroup` | `pw1_len (2) \|\| pw1 \|\| pw2` | replaces SetAuth/SetDataPassword when there is no group |
| `JoinGroup` | `pw1_len (2) \|\| pw1 \|\| pw2` | opens the join slot |
| `CancelJoin` | none | wipes the join slot |
| `OpenInvite` | `seconds (2)` (capped) | opens the invite window (A.4 option a) |
| `Status` | adds `group: none / joining / member`, `invite_open` | still no salts or keys |

The `SetAuthPassword` / `SetDataPassword` requests stay for re-entering the
passwords on an existing member, for example after a restart while storage
is still RAM-only. The salt is the group salt.

---

## Part B: clipboard sync protocol

### B.1 Scope (v1)

- Text only (UTF-8), up to `CLIP_MAX_LEN` (proposal: 1 MiB).
- Images and files come later, with folder sync.
- Off by default. When on, it is per peer, with two flags: *send to this
  peer* and *accept from this peer*.

### B.2 Message (inside the existing transport)

It uses the current `connect_handler` / `recv_handler` path:
1. auth (SPAKE2, KEX, Noise, ML-DSA);
2. the init header: `ActionType::ClipboardSync = 0x03 || len (u64 LE)`;
3. the payload, under the `d_key` AES-256-GCM layer (per-connection,
   per-direction key, HKDF bound to the handshake hash).

The payload (plaintext inside the `d_key` layer) is versioned:

```
version     (1)   = 0x01
kind        (1)   = 0x01 text/utf-8
origin_seq  (8)   u64 LE, per-origin counter, strictly increasing
content_len (4)   u32 LE, 1..=CLIP_MAX_LEN, must equal the remaining length
content     (content_len)
```

- The origin device is **not** in the payload: the receiver already knows
  the authenticated peer (its ML-DSA key or fingerprint).
- **Receiver checks**, in this order, each failure dropping the message with
  a uniform error:
  1. the peer is allowed to send ("accept from");
  2. `len` is at most `14 + CLIP_MAX_LEN + DATA_LAYER_OVERHEAD`, checked
     before allocating (14 = version + kind + seq + content_len);
  3. the version and kind are known;
  4. `content_len` matches exactly;
  5. the content is valid UTF-8;
  6. `origin_seq` is greater than the last value seen from that peer, so
     stale or reordered updates are ignored. Replay is already impossible:
     the keys are bound to the connection, and Noise uses nonces.
- **Ack** (proposal): the receiver answers with one encrypted byte, `0x00`
  for applied or `0x01` for ignored, so the sender can log delivery. Without
  it the protocol stays fire-and-forget.

### B.3 Loops, ordering, concurrency

- **Echo loop:** applying a remote clipboard fires the local clipboard
  listener. The daemon keeps `last_applied = BLAKE2s-keyed(local_secret,
  content)`. The key is per daemon run and lives only in daemon `Zeroizing`
  memory. A local change matching `last_applied` is not sent.
  - The hash is **keyed** so that a leaked hash can't be used to brute-force
    whatever was in the clipboard (passwords end up there).
- **Ordering:** the last writer wins by `(origin_seq, peer fingerprint)`. A
  simple per-origin counter is enough for clipboards; there are no vector
  clocks in v1.
- **Debounce:** wait about 300 ms after a local change and send only the
  latest value.

### B.4 What is never synced

The daemon checks the content's markers before reading it:
- macOS: `org.nspasteboard.ConcealedType` and `org.nspasteboard.TransientType`,
  which password managers set;
- Windows (later): `ExcludeClipboardContentFromMonitorProcessing`;
- KDE/Wayland: `x-kde-passwordManagerHint`.

Marked content is never read into memory and never sent.

### B.5 Memory and logging

- Content only exists in `Zeroizing<Vec<u8>>`, pre-sized from `content_len`
  so it never reallocates. It is wiped right after it has been sent or
  applied.
- Logs show lengths, peers and seq numbers, never the content or its hash.
- The OS clipboard itself is outside our control. That is documented, not
  hidden.

### B.6 Delivery

v1:
- one connection per update, to each reachable trusted peer that is allowed
  to receive. It does the full handshake every time; post-quantum is
  expensive, which is why updates are debounced;
- peers are found through UDP discovery, the plain announcement.

Later (**DECISION 3**): keep one persistent session per peer, to avoid a
full ML-KEM/ML-DSA handshake for every copy.

### B.7 Clipboard access (**DECISION 2**)

The daemon runs as the user, so it can read and write the clipboard:
- macOS: NSPasteboard;
- X11/Wayland: a data-control protocol.

Options:
- (a) the `arboard` crate: one dependency, all platforms, but it needs
  auditing and doesn't expose the concealed-type markers on every platform;
- (b) small platform modules of our own: no dependency, but more code. On
  macOS this means `objc2-app-kit`, and probably unsafe code, which goes
  against `forbid(unsafe_code)`.

I recommend (a) for reading and writing, plus our own marker check where
`arboard` falls short. Whether it's acceptable should be decided after an
audit.

---

## C. Decisions needed from you

1. Salt query privacy: (a) answer only during an invite window
   (recommended), or (b) always answer.
2. Clipboard access: (a) `arboard` (recommended, after an audit), or
   (b) our own platform code.
3. Delivery: (a) a new connection per update in v1 (recommended), or (b) a
   persistent session now.
4. Defaults:
   - `JOIN_WINDOW` 5 min, invite window 2 min;
   - `CLIP_MAX_LEN` 1 MiB, debounce 300 ms;
   - Ack on.
5. Still open from the roadmap, and unblocking all of this: where keys and
   salts are stored (OS keychain or encrypted file). Until then a daemon
   restart forgets the group, and you have to re-enter the passwords.

## D. Implementation plan (after review), one stacked PR each

1. Group state and the IPC changes (`CreateGroup`, `JoinGroup`,
   `CancelJoin`, `OpenInvite`, `Status`), plus the join slot with its
   timeout and wipe.
2. The salt query (A.4), the invite window, and `a_salt` in the SPAKE2
   transcript.
3. `GroupSalt` after auth (A.5), plus the commit-only-after-pairing rule.
4. The daemon starts the networker. This needs storage decision 1 and the
   pairing prompt over IPC.
5. Clipboard v1 (Part B).

Every step gets tests for its failure paths (fake salt, expired window,
replayed or old seq, oversize, sensitive marker), each shown to fail
without its protection, plus the security gate.
