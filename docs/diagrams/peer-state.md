# A paired device's state

daemon.md 13.1. What the last connection with a paired device showed; a hint
for the user, the handshake still decides trust.

```mermaid
stateDiagram-v2
    direction LR
    [*] --> NotContacted: daemon start
    NotContacted --> Fine: authenticated
    Fine --> AuthDiffers: password check failed
    Fine --> DataDiffers: d_key layer failed
    Fine --> Unreachable: address didn't accept
    AuthDiffers --> Fine: authenticated
    DataDiffers --> Fine: data went through
    Unreachable --> Fine: authenticated
    AuthDiffers --> NotContacted: key changed here
    DataDiffers --> NotContacted: key changed here
```

The main path only. From **any** state:

| Event | New state |
|---|---|
| the password check failed on a connection from or to its last address | auth differs |
| its last address didn't accept the connection | not reachable |
| a connection authenticated | fine, **except** from "data differs": that one needs data to go through |
| a key changed on this device | "auth differs" and "data differs" go back to not contacted (the next hello asks again); the others stay |

| State on the wire | TUI |
|---|---|
| `0x00` not contacted | grey |
| `0x01` fine | green |
| `0x02` auth password differs | "incorrect password (auth password differs)" |
| `0x03` data password differs | "incorrect password (data password differs)" |
| `0x04` not reachable | not reachable at its last address |

## The pause

```mermaid
flowchart TB
    fail["password check failed"] --> who{"who connected?"}
    who -- "we connected to it" --> pause["mark + pause sync to it for 5 min<br/>(each try costs both a guess slot)"]
    who -- "it connected to us" --> mark["mark only, never pause<br/>(anyone can connect from that<br/>address and fail on purpose)"]
    pause --> ends["ends: it authenticates (auth pause),<br/>data goes through (data pause),<br/>a key change here (both)"]
```

## The hello

```mermaid
sequenceDiagram
    participant A as This device
    participant B as Paired device (at its last address)
    Note over A: networking starts, or a password changed here
    A->>B: handshake (never pairs)
    alt pw1 differs
        Note over A,B: SPAKE2 confirmation fails: both mark "auth differs"
    else pw1 same
        A->>B: Hello: "CESAHELO" through the d_key layer
        alt pw2 differs
            B->>A: 0x02: both mark "data differs"
        else both same
            B->>A: 0x00: both "fine", both learn the other's address
        end
    end
```

Addresses come only from authenticated connections: the address we
connected to, or the source IP of a paired device that authenticated to us
(port 3232). They are saved in the vault config, so sync finds the devices
after a restart.
