# The "Add device" window

daemon.md 9.1, 13 and 13.2. Outgoing connections to new devices happen only
in this window (2 min), never on every announcement.

```mermaid
flowchart TB
    n["n on Devices (AddDevice)<br/>needs networking"] --> open["open one window: 2 min, new instance id,<br/>new generation, three address lists"]
    open --> salt["salt query on 3233<br/>(only during the window)"]
    open --> offer["offer d_salt to a device<br/>paired just now"]
    open --> announce["announce every second:<br/>255.255.255.255, then every interface at once"]
    open --> search["search in 20 s rounds<br/>for other members' windows"]
    open --> prompts["pairing prompts allowed<br/>(outside a window: rejected)"]
    search --> found["a device found"]
    found --> once{"checked in this<br/>window already?"}
    once -- yes --> skip["skip"]
    once -- no --> check{"its a_salt<br/>(salt query)"}
    check -- "other group" --> other["report 'another group',<br/>never connect"]
    check -- "same / no answer" --> id{"lower instance id?"}
    id -- "we are lower" --> connected{"connected to it in<br/>this window already?"}
    connected -- no --> connect["connect: ConnectNewDevice<br/>(handshake, pairing)"]
    connected -- yes --> skip
    id -- "they are lower" --> wait["they connect to us"]
    close["2 min, x (StopAddDevice), Sync off"] --> closed["salt port closed, d_salt offer cleared,<br/>waiting pairings rejected"]
```

## A typed address (`a`, 13.2)

For a device discovery can't reach: another subnet, a VPN.

```mermaid
flowchart TB
    a["a on Devices: IPv4 address"] --> valid{"usable?<br/>(not loopback, multicast,<br/>broadcast, IPv6; not own)"}
    valid -- no --> red["popup stays open, red reason<br/>(daemon: BadRequest / OwnAddress)"]
    valid -- "yes, member" --> win["AddDeviceAt: window opens<br/>(or the open one is used)"]
    valid -- "yes, fresh device" --> joinat["JoinGroupAt (see join.md)"]
    win --> typed{"waited for in this<br/>window already?"}
    typed -- yes --> done["nothing more"]
    typed -- no --> poll["ask its salt query"]
    poll --> grp{"answer"}
    grp -- "no answer:<br/>its window isn't open" --> sleep["wait 5 s"] --> poll
    grp -- "other group" --> other2["report, never connect"]
    grp -- "same group" --> conn{"connected to it in<br/>this window already?"}
    conn -- no --> go["connect once (no id rule:<br/>it may not see us at all)"]
    conn -- yes --> done
    poll -. "window ends" .-> done
```

## Why three lists

```mermaid
sequenceDiagram
    participant A as A (Mac, lower id)
    participant B as B (VM)
    Note over A,B: B's broadcast reaches A, A's never reaches B
    B-->>A: announcement
    Note over A: found B, but B has the higher id:<br/>"B connects to us" (searched list)
    Note over B: never heard A: never connects
    Note over A: user types B's address (typed list)
    A->>B: salt query, then connect (connected list)
    Note over A,B: one list for all would have skipped B
```
