# node-handle API plan — the client-go-shaped surface

**Scoped:** replace the public command/query struct dispatch on
`NodeHandle` with a Kubernetes client-go shaped surface: resource-scoped
accessors carrying the standard verb set (`get`/`list`/`create`/`delete`),
domain operation verbs on the handle (`join`/`leave`/`revoke`/`sync`/
`shutdown`), and `watch` for event subscription. The runtime's internal
`Control` bus, wire formats, and storage contracts are untouched.

**Status:** W1, W3, and W4 are complete on the `node-handle-api` branch
(the full quality gates and the 758-test suite pass locally). W2's
examples work is done; its chat acceptance lane is the CI container job.
This document deletes itself per the lifecycle rules once that lane is
green on the merge commit.

**Breaking, deliberately:** the crate is `0.0.2`, unreleased. No
compatibility surface is kept for the command/query layer.

**Deleted when done**, per [`README.md`](README.md): the acceptance
evidence lands in the commit history of the `node-handle-api` branch.

## Motivation (evidence)

1. **Six plumbing traits, zero generic consumers.** `Command`, `Query`,
   `CommandControl`, `QueryControl`, `DispatchCommand`, `DispatchQuery`
   exist solely to route sealed crate-internal types through one bus.
   `rg "C: Command|Q: Query|dyn Command" src/` finds no consumer outside
   their definitions and impls; every one of the 640+ `.command(`/`.query(`
   call sites under `tests/` names a concrete command type. The
   extensibility that justifies message-struct dispatch (third parties
   defining messages) is structurally absent: both traits are sealed.
2. **The uniform shape is already being fought.** `src/node/handle.rs`
   carries four "lifecycle specials" (`Shutdown`, `GetNodeStatus`,
   `WaitForShutdown`, `GetRoute`) with dedicated dispatch impls because the
   uniform `Result<Output>` bus does not fit them, and
   `NodeHandle::run_sync_round` already escaped as a dedicated method. The
   pattern has precedent inside this crate; the plan finishes it.
3. **Signature falsehoods.** `GetNodeStatus` is a synchronous local read
   wrapped in `Result`; `WaitForShutdown` never fails. A generic dispatch
   layer cannot express sync or infallible operations; per-verb methods
   can and do.
4. **Discoverability.** IDE completion on `node.` currently shows seven
   entries; the ~36 operations are invisible without reading rustdoc. A
   resource-scoped surface turns completion into the equivalent of
   `kubectl api-resources` followed by the resource's verb list.
5. **Prior art.** openraft ships the same internal architecture (spawned
   actor, typed messages, oneshot replies) behind a pure verb-method
   `Raft` handle (`add_learner`, `change_membership`, `client_write`).
   iroh, libp2p (`listen_on`/`dial`), quinn, and etcd-client are verb
   APIs. Message-struct dispatch pays off where the message is data
   (sqlx statements, Kafka records) or third-party-extensible (actor
   frameworks); radiata's commands are neither.

## Design (decided)

The reference is client-go, kubernetes' own library API, not the CLI
syntax: a small uniform verb set hanging off resource-scoped accessor
objects, plus domain verbs for operations. Rust precedents for the verb
names themselves: `HashMap::get`, `Extend`-era `list`-style plural
readers.

Three layers on `NodeHandle`:

1. **Resource accessors.** `node.members()`, `node.resources()`, … return
   a cheap borrowing accessor struct over the runtime client. Each
   accessor carries exactly the verbs that resource supports — a
   read-only resource gets `get`/`list`, a mutable one gets
   `create`/`delete`, and nowhere does an unsupported verb compile.
2. **Node operation verbs.** Cluster lifecycle and operator actions stay
   directly on the handle, named as domain verbs — the
   kubectl/kubeadm operation vocabulary (`join`, `leave`, `revoke`,
   `cleanup`, `sync`, `shutdown`), not CRUD.
3. **Observation.** `watch::<E>` replaces `events::<E>` (the k8s API
   verb); status reads become cheap, honest signatures.

Accessor structs are cheap single-use values holding a cloned runtime
client (`node.members()`); every verb consumes the accessor and returns
an owned future, so a write intent built now can be held and driven
later exactly like any other value. The `RuntimeClient` clone is a few
channel handles; the borrowing form (`Members<'a>`) was rejected
because it made deferred futures un-returnable (verified by the
`resources.version` guide chapter's enqueue pattern).

### Layer 1 — resource accessors

| Accessor | Verbs | Replaces |
|---|---|---|
| `node.members()` | `get(node)`, `list(page)` | `GetMember`, `PageMembers` |
| `node.resources()` | `get(name)`, `list(page)`, `select(selector, page)`, `put(write)`, `put_expected(write, expected)`, `delete(name, expected)` | `GetResource`, `PageResources`, `SelectResources`, `PutResource`, `RemoveResource` |
| `node.listeners()` | `list(page)`, `create(endpoint)`, `delete(listener)` | `PageListeners`, `Listen`, `StopListener` |
| `node.sessions()` | `list(page)` | `PageSessions` |
| `node.topology()` | `list(page)` | `PageTopology` |
| `node.trust()` | `list(page)` | `PageTrust` |
| `node.credentials()` | `issue()`, `rotate()` | `IssueMergeCredential`, `RotateMergeCredential` |
| `node.routes()` | `get(handle)` | `GetRoute` |

Accessor struct names: `Members`, `Resources`, `Listeners`, `Sessions`,
`Topology`, `Trust`, `Credentials`, `Routes` — plain plural nouns, no
`Api` suffix, none collides with an existing export.

### Layer 2 — node operation verbs

| Method | Replaces | Signature | k8s grounding |
|---|---|---|---|
| `node.status()` | `GetNodeStatus` | sync, infallible → `NodeStatus` | the node phase read |
| `node.local_node()` | `GetLocalNode` | `Result<LocalNodeView>` | the self node object |
| `node.join(receiver, credential)` | `MergeCluster` | `Result<MergeView>` | `kubeadm join`; the credential is the join token |
| `node.leave(ack)` | `LeaveCluster` | `Result<LeaveOutcome>` | `kubeadm reset` family |
| `node.connect(receiver, peer)` | `ConnectMember` | `Result<NodeId>` | typed dial |
| `node.disconnect(peer)` | `DisconnectPeer` | `Result<()>` | — |
| `node.patch_metadata(expected_revision, patch)` | `UpdateNodeMetadata` | `Result<MemberView>` | `kubectl patch`; expected revision is `resourceVersion` CAS |
| `node.revoke(subject, expected_key)` | `RevokeNode` | `Result<RevokeOutcome>` | `certificate deny` |
| `node.cleanup(subject)` | `CleanupNode` | `Result<()>` | delete with finalizer completion |
| `node.purge_revocation(subject)` | `PurgeRevocation` | `Result<()>` | — |
| `node.issue_cleanup_checkpoint()` | `IssueCleanupCheckpoint` | `Result<u64>` | GC epoch watermark |
| `node.apply_receipt_retention()` | `ApplyReceiptRetention` | `Result<ReceiptRetentionReport>` | GC sweep |
| `node.resolve_frozen_journal(ack)` | `ResolveFrozenJournal` | `Result<()>` | operator-confirmed override |
| `node.start_recovery()` | `StartRecovery` | `Result<RecoveryView>` | forced reconcile cycle |
| `node.recovery()` | `GetRecovery` | `Result<RecoveryView>` | status subresource read |
| `node.connection_degree()` | `GetConnectionDegree` | `Result<ConnectionDegreeView>` | — |
| `node.metrics()` | `GetObservability` | `Result<ObservabilitySnapshot>` | `metrics.k8s.io` |
| `node.sync()` | `RunSyncRound` | `impl Future<Output = Result<()>>` | anti-entropy round; the crate's own domain term |
| `node.shutdown()` | `Shutdown` | `Result<ShutdownOutcome>` | — |
| `node.wait_for_shutdown()` | `WaitForShutdown` | async, infallible → `ShutdownReason` | drain --wait |

### Layer 3 — data plane and observation

| Entry | Change |
|---|---|
| `node.watch::<E>(options)` | renames `events::<E>`; `EventOptions`, `EventSubscription`, `EventReceive` keep their names this cycle |
| `node.open_stream(target, protocol, policy, metadata)` | unchanged — the full-form entry for streaming bodies |
| `node.send(target, protocol, policy, body)` | new one-shot sugar: `open_stream` with empty metadata + `send_sync`, returning `BoxFuture<'static, Result<DeliveryAck>>`; covers the probe/message pattern that dominates the examples |
| `node.member_revision()` | unchanged |

### Signature truthfulness

`status()` is sync and infallible; `wait_for_shutdown()` is async and
infallible; `sync()` keeps the `impl Future` shape `run_sync_round` has
today. Everything else is `async` + `Result`. This is the contract
correction the generic layer could not make.

### Target example story

```rust
use radiata::{Endpoint, NodeBuilder, PageSpec, ResourceChanged};

let node = NodeBuilder::new(storage).start().await?;

// kubectl create / apply
let listener = node.listeners().create(Endpoint::parse("tls://node1.example.net:9443")?).await?;
node.join(receiver, credential).await?;

// kubectl get / describe
let me = node.local_node().await?;
for member in node.members().list(PageSpec::first(64)?).await?.items() {
  // …
}

// conditional write: raced updates surface as ErrorKind::Conflict
node.resources().put_expected(write, observed_version).await?;

// kubectl get --watch
let mut changes = node.watch::<ResourceChanged>(radiata::EventOptions::new())?;

// operations
node.sync().await?;
node.shutdown().await?;
let reason = node.wait_for_shutdown().await;
```

## Full mapping table

Commands: `Shutdown` → `shutdown()`; `WaitForShutdown` →
`wait_for_shutdown()`; `RunSyncRound` → `sync()`; `Listen` →
`listeners().create()`; `StopListener` → `listeners().delete()`;
`MergeCluster` → `join()`; `ConnectMember` → `connect()`;
`DisconnectPeer` → `disconnect()`; `LeaveCluster` → `leave()`;
`ResolveFrozenJournal` → `resolve_frozen_journal()`; `UpdateNodeMetadata`
→ `patch_metadata()`; `PutResource` → `resources().put()` /
`resources().put_expected()`; `RemoveResource` → `resources().delete()`;
`RevokeNode` → `revoke()`; `CleanupNode` → `cleanup()`;
`PurgeRevocation` → `purge_revocation()`; `IssueMergeCredential` →
`credentials().issue()`; `RotateMergeCredential` → `credentials().rotate()`;
`StartRecovery` → `start_recovery()`; `IssueCleanupCheckpoint` →
`issue_cleanup_checkpoint()`; `ApplyReceiptRetention` →
`apply_receipt_retention()`.

Queries: `GetNodeStatus` → `status()`; `GetLocalNode` → `local_node()`;
`GetObservability` → `metrics()`; `GetRecovery` → `recovery()`;
`GetConnectionDegree` → `connection_degree()`; `GetMember` →
`members().get()`; `PageMembers` → `members().list()`; `GetResource` →
`resources().get()`; `PageResources` → `resources().list()`;
`SelectResources` → `resources().select()`; `PageListeners` →
`listeners().list()`; `PageSessions` → `sessions().list()`;
`PageTopology` → `topology().list()`; `PageTrust` → `trust().list()`;
`GetRoute` → `routes().get()`.

## Kept and deleted

**Kept (value and semantic types):** `Endpoint`, `PageSpec`, `Selector`,
`ResourceWrite`, `ResourceVersion`, `ResourceName`, `MergeCredential`,
`StreamTarget`/`StreamPolicy`/`StreamMetadata`, `NodeMetadataPatch`, both
acknowledgement types (`ReplaceIdentityAndDeleteOldCoreMetadata`,
`DeclareInterruptedTransactionUncommitted` — the no-`Default` friction
for destructive ops is independent of dispatch style), every `*View` /
`*Page` output, the `Event` trait and event structs,
`EventOptions`/`EventSubscription`/`EventReceive`, `OutboundStream`.

**Deleted:** the six plumbing traits; the 33 command/query structs in
`src/operation.rs`; `NodeHandle::command`/`NodeHandle::query`; the
`CommandControl`/`QueryControl` impl blocks in `src/node/handle.rs`; the
~40 matching re-exports at the crate root. `src/operation.rs` keeps the
`Event` trait and event structs.

## Recorded naming decisions (do not relitigate)

- **`join`, not `merge`** — `kubeadm join` is the exact operation shape
  (endpoint + join token); the internal `Control::MergeCluster` variant
  and merge-credential domain language stay as they are.
- **`watch`, not `events`/`subscribe`** — the k8s API verb.
- **`put` / `put_expected`** — the LWW unconditional write and the
  precondition write are separate verbs so the semantic choice is visible
  at the call site; `delete` always carries its precondition (today's
  `RemoveResource` contract). Grounding: k8s `resourceVersion`
  preconditions on update/delete.
- **`metrics`, not `observability`** — `metrics.k8s.io`; the snapshot
  type keeps its name.
- **`sync`, not `reconcile`** — the crate's own domain term for the
  anti-entropy round; `reconcile` is controller-runtime jargon with no
  internal anchor here.
- **`patch_metadata`** — `kubectl patch` with expected revision as the
  resourceVersion CAS.
- **`select` stays a distinct verb** — k8s folds label selectors into
  `ListOptions`; folding `PageSpec` + `Selector` into a resources-only
  options struct is a possible later simplification, out of this cycle.
- **`send` sugar carries no metadata parameter** — metadata defaults to
  empty; callers needing metadata use `open_stream`.

**Rejected shapes:** flat `get_*`/`list_*` prefixes (dumps ~35 methods on
one type and reads worse in Rust); keeping the sealed `Command`/`Query`
traits as public markers (zero generic consumers — evidence above);
message structs as the public API (sealed + single-use at call sites).

## Work items

### W1 — the verb surface (additive)

Add `src/node/api/` with the eight accessor structs and the Layer-2
methods on `NodeHandle`. Every method's rustdoc is the migrated contract
text of the command it replaces — no contract paragraph is lost. Rewrite
`tests/public_api.rs` onto the new surface while the old one still exists.

- **Acceptance:** the full mapping table compiles and passes through
  `radiata::*` from an external consumer; every method's doc carries the
  migrated contract.
- **Gate:** `tests/public_api.rs` (the external-crate proof — a missing
  or mis-shaped verb breaks its build) plus the full workspace test run.

### W2 — data-plane sugar and watch rename

Add `node.send(...)`; rename `events` to `watch`; migrate the probe paths
in `examples/cluster` and `examples/chat` to `send`.

- **Acceptance:** both examples build and run; no example constructs a
  stream-and-send-sync pair for a one-shot body.
- **Gate:** the chat acceptance lane (CI container job) and the example
  builds.

### W3 — migrate every internal consumer

All of `tests/` (640+ sites), `examples/`, `src/guide.rs` doc examples,
and the root `README.md` snippets.

- **Acceptance:** `rg "\.command\(|\.query\(|events::<" src tests
  examples README.md` returns nothing.
- **Gate:** that grep run at review time, plus the full quality-gate
  list from `AGENTS.md`.

### W4 — delete the command layer

Remove the six traits, the 33 structs, `command`/`query`, the impl
blocks in `handle.rs`, and the crate-root re-exports.

- **Acceptance:** zero clippy/rustfmt/taplo warnings; the public API
  diff (this file's mapping table is the expected diff) reviewed line by
  line; `cargo doc` renders with every migrated contract visible on its
  method.
- **Gate:** the full quality gates:
  `taplo fmt --check`, `cargo +nightly fmt --all -- --check`,
  `cargo check --workspace --all-targets --all-features --locked`,
  `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`,
  `cargo test --workspace --all-features --locked`.

## Sequencing

Branch `node-handle-api`; four commits mapped to W1–W4, gitmoji
convention, e.g. `:sparkles: expose the node handle verb surface`,
`:recycle: migrate consumers to the verb surface`,
`:fire: delete the command dispatch layer`.

## Non-goals

- No runtime, `Control`-bus, wire-format, or storage changes; dispatch
  internals move, semantics do not.
- No new operations, no semantic changes to any existing operation.
- No renames of view/value/event types beyond the tables above
  (`EventOptions` and friends keep their names this cycle).
- No batching or command-serialization surface; if a future admin
  protocol needs commands-as-data, it gets an explicit design then.
