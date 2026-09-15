# radiata chat example

A decentralized chat room built on the radiata library: five independent
chat nodes form a cluster, and every chat feature is either a metadata
resource (roster, groups, announcements) or customer-owned traffic over
the routed data channel (DMs, group fan-out, read receipts).

## How the features map onto radiata

| Chat feature | radiata mechanism |
| --- | --- |
| User identity | One resource per user (`resources/user-<name>`) whose `node-id` label pins the identity to exactly one node. The record rides the ordinary resource plane so the roster converges everywhere; the identity itself (keys, local store) never leaves the node. |
| Group chat | One resource per group (`resources/group-<name>`); the member roster is a comma-joined label. Joins are conditional read-modify-writes (`PutResource::with_expected`): a raced join surfaces as an explicit conflict and retries, so concurrent joins converge instead of losing updates. |
| Dissolve | `RemoveResource` with the observed version: the removal tombstone converges, every member's group view reads as gone, and further sends fail closed. |
| Announcements | Regular resources (`resources/announce-<title>`); resource sync delivers them to every node. |
| DMs, group messages, receipts | The data channel: one direct-routed stream per message over a registered chat protocol. Messages are never metadata. |
| Read receipts | Strictly user-driven: a node marks a message seen only when the user executes `list messages`, and that is the moment the receipt is emitted. Delivery alone never produces a receipt. |
| Offline recipients | A send to an unreachable node queues in the sender's store as `pending`; `POST /flush` retries. Read receipts queue and heal the same way. |

## How to integrate with the library

The task-oriented integration guide lives in the crate root docs:
`radiata::guide` (run `cargo doc --open` on the library crate). It
walks through the version-tuple round trip behind conditional writes,
the any-one-route connectivity contract, and the three extension
points this example consumes: `RouteNextHop` (the default relay
policy), `PacketConsumer` (the chat wire protocol), and `KeyProvider`
(the `FileKeyProvider` in `src/keys.rs`).

## Networking and failure recovery

The business surface is exactly three operations: **join** (one HTTP
call that merges through any single cluster member), **send** (target a
user; the library delivers over a direct session when one exists and
relays through a live peer when it does not — the next-hop policy is
the library's built-in `DefaultNextHop`), and **leave**. There is no
business-side meshing: the library's recovery plane retries every member
in the table while the node is fully isolated, reconnects through any
member that answers, and quiesces the moment any one route exists (the
"any one route" contract). Messages sent during an outage queue as
`pending` in the customer's store and flush when connectivity returns.

## Run

```bash
./up.sh                      # 5 chat nodes (u1..u5), http 19081..19085
python3 test_chat.py         # the full scenario matrix, writes chat-report.json
./down.sh
```

The node binary speaks the same command set over HTTP: `/whoami`,
`/identities`, `/announce`, `/announcements`, `/dm`, `/flush`,
`/messages`, `/read`, `/groups`, `/groups/{name}/join|send|dissolve`,
`/disconnect`, `/mesh`.

## Deliberate example limitations

- Concurrent joins to one group retry on explicit conflicts (the join
  rides a `PutResource::with_expected` precondition, so a raced
  read-modify-write is visible and retried — never silently lost).
  A hotly-contended roster can still exhaust the bounded retry budget.
- Message delivery is at-most-once per attempt with a customer-owned
  retry queue; the library's sync plane is deliberately not used for
  chat traffic.
- Group rosters are bounded by the 256-byte label value budget.
