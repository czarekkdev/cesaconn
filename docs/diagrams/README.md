# Diagrams

Pictures of how CesaConn works. The text that decides is
`docs/design/daemon.md`; each diagram names the section it shows. They are
Mermaid, so GitHub draws them and a change to one is a normal text diff.

| Diagram | Shows | daemon.md |
|---|---|---|
| [architecture.md](architecture.md) | crates, processes, what talks to what | 1, 5 |
| [daemon-states.md](daemon-states.md) | the daemon's states, when networking runs | 6, 13 |
| [keys-and-storage.md](keys-and-storage.md) | passwords to keys, what is stored where, the vault | 4, 6, 8 |
| [ipc.md](ipc.md) | one UI request, the checks on both ends | 7 |
| [handshake.md](handshake.md) | `auth_snow` phases 1-6 and the data layer | 10 |
| [add-device.md](add-device.md) | the "Add device" window: announce, search, group check, typed address | 9.1, 13, 13.2 |
| [join.md](join.md) | a fresh device joining a group | 11, 13.2 |
| [clipboard-sync.md](clipboard-sync.md) | a copy reaching the other devices, no echo | 12 |
| [peer-state.md](peer-state.md) | a paired device's state, "incorrect password", the hello | 13.1 |
| [forget-reset.md](forget-reset.md) | forgetting a device, resetting this one | 14 |

When the code changes what a diagram shows, change the diagram in the same
PR (like the design doc).
