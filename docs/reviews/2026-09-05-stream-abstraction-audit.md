---
title: Stream Abstraction Audit — radiata vs futures/tokio idioms
status: review-record
date: 2026-09-05
scope: read-only audit; no code change
---

# Stream Abstraction Audit

## Question

Several public and SPI surfaces hand-roll incremental async abstractions. Are they redundant
reinventions of the mature `futures::Stream` / `tokio::io::AsyncRead` / `AsyncWrite` designs, or
deliberate trade-offs justified by the frozen ABI contract?

Method: inventory every hand-rolled incremental/pull abstraction in `src/`, classify each against its
ecosystem counterpart, and record the verdict plus follow-up measures. This document records findings
only; it does not amend the API manifest or any ADR.

## Governing Constraint

The API manifest (`docs/api-manifest.md`) freezes one ABI rule that decides most of this audit:

> No public signature contains Tokio channels/tasks, TLS implementation types, CBOR implementation
> types, redb types, JSON values, wire envelopes, private-key bytes, or an upper-layer object model.

Public signatures therefore use only `std` types and crate types. `futures::Stream` lives in
`futures-core`; `AsyncRead`/`AsyncWrite` live in `tokio::io` (or `futures::io`). Exposing any of them
makes that crate part of radiata's public semver surface. The hand-rolled shapes below are the price
of that rule — the audit asks whether the price buys enough.

**Amendment (decided 2026-09-05):** Tokio is the crate's sole supported async ecosystem. Re-exporting
Tokio or using its standard interfaces/traits in public signatures is therefore acceptable, and the
manifest's ABI rule is to be amended accordingly (recorded as measure R3): `futures-core` and Tokio
traits/interfaces (e.g. `Stream`, `tokio-stream` adapters, `tokio::io` traits where they fit) may
enter the public ABI; Tokio **channel and task handles** (mpsc/broadcast senders, `JoinHandle`, …)
remain excluded — they are runtime internals, not interfaces. The verdicts below were re-audited
under this amended premise; where the original reasoning cited the Tokio prohibition, the remaining
merits are stated explicitly.

## Inventory and Verdicts

| Abstraction | Site | Ecosystem counterpart | Verdict |
| --- | --- | --- | --- |
| `PacketBody` | `src/packet/mod.rs` (public) | `Stream<Item = Result<Arc<[u8]>>>` | Reinvented shape, ABI-justified; resolved by R1 |
| `ChannelBody` | `src/packet/mod.rs` (internal) | `tokio_stream::wrappers::ReceiverStream` | Internal reinvention; optional cleanup R4 |
| `StoreScan` | `src/provider.rs` (public SPI) | `BoxStream<'a, Result<StoreEntry>>` | Defensible as written |
| `EventSubscription` / `EventReceive` | `src/node/event.rs` (public) | `BroadcastStream` | Justified; keep |
| `Discovery::discover` | `src/transport/registry.rs` (public SPI) | cursor-paged RPC, not a stream | Correct as written |
| `CandidateNodeReader` | `src/routing.rs` (public, sealed) | paged pull | Correct as written |
| `LoadBalancingPolicy`, `RouteNextHop`, `KeyProvider`, `Storage*`, `PacketConsumer` | public SPIs | single async method traits | Not reinvention; see "BoxFuture style" |
| Public paged views (`PageSpec`/`PageCursor`, `Page*` queries) | `src/paging.rs`, `src/view.rs` | cursor pages | Correct as written |
| Transport internals | `src/transport/connection.rs` | already `SplitSink`/`SplitStream` | No reinvention |

### `PacketBody` — the one real finding

```rust
pub trait PacketBody: fmt::Debug + Send + 'static {
  fn next_chunk<'a>(&'a mut self) -> BoxFuture<'a, Result<Option<Arc<[u8]>>>>;
}
```

This is isomorphic to `Stream<Item = Result<Arc<[u8]>>>`. Two facts sharpen the finding:

- Chunk boundaries are **not** preserved on the wire: core re-chunks any caller chunk above
  `MAX_CHUNK_BYTES` (32 KiB) to stay constant-memory. The interface is therefore "yield bytes in
  order", which is exactly the textbook `Stream`/`AsyncRead` shape — the custom trait buys no extra
  expressiveness.
- Ergonomics cost is real: a one-shot body needs a struct + impl + `Box::pin` (see `PubBody` in
  `tests/public_api.rs`).

Why it still exists: object safety with explicit `Send + 'static`, unified `radiata::Error`, and the
std-only ABI rule above. Precedent exists in the ecosystem (hyper/tonic `Body`), so the direction is
defensible — but the current form is bare: there is no public convenience constructor, so even the
trivial "send these bytes" case pays the full trait ceremony.

Why **not** `AsyncRead`/`AsyncWrite` specifically:

- `AsyncWrite` does not fit the outbound body: packet streams have explicit end/interrupted semantics
  that do not map onto `flush`/`close`, and core — not the caller — owns the 32 KiB chunk quantum.
- `AsyncRead` superficially fits the incoming read side, but its error channel is `io::Error`
  (loses typed `ErrorKind`), its poll-based buffer ownership fights the `Arc<[u8]>` zero-copy
  forwarding path, and it is markedly harder to implement correctly than an async `next()`.
  (Re-audit: the Tokio admission removes the public-dependency objection; the three remaining
  reasons still decide against it. `Stream` is the better fit for an ordered, error-typed,
  chunk-yielding source.)

Verdict: keep the trait and the two-phase `create_packet` → `send_*` flow (the `TraceId`-before-body
contract requires the split); fix the ergonomics, not the semantics.

### `StoreScan`

```rust
pub trait StoreScan: fmt::Debug + Send {
  fn next<'a>(&'a mut self) -> BoxFuture<'a, Result<Option<StoreEntry>>>;
}
```

Also stream-shaped, but the implementors are storage adapters writing cursor loops over redb/JSON/
external backends. For implementors, an explicit async `next()` is the mature pattern (SQL drivers
and embedded stores commonly expose exactly this); a `BoxStream` return would force providers to
hand-write `poll_next` state machines or depend on a stream-construction crate. (Re-audit: with
`futures-core` admitted to the public ABI by R1, "pushing futures-core into provider signatures" is
no longer an objection; the implementor-ergonomics argument still decides. The R2 converter gives
consumers a `BoxStream` view without changing what providers implement.) Verdict: keep.

### `EventSubscription` / `EventReceive`

Backed by `tokio::sync::broadcast`. `tokio_stream::wrappers::BroadcastStream` exists, but it folds
lag into an opaque error and has no `try_recv`/`Empty` surface. The explicit
`Item / Empty / Lagged { missed } / Closed` enum is the deliberate contract: lag must be visible so
subscribers re-read through the paged queries. (Re-audit: under the Tokio admission the additive
`Stream` impl may build on `tokio_stream` wrappers; the enum stays the primary contract because lag
must remain explicit.) Verdict: keep; an additive `Stream` impl ships with
R2.

### Cursor-paged surfaces

`Discovery::discover`, `CandidateNodeReader::next_matching_nodes`, and the public `Page*` queries are
**not** streams: the cursor is opaque, caller-owned, and resumable across calls and failures. A
`Stream` would fuse the cursor into hidden iterator state and defeat resumability. Correct as
written.

### BoxFuture style on single-method traits

Rust 1.98 (the MSRV) supports native `async fn` in traits, but every trait here is consumed as
`Box<dyn …>` / `Arc<dyn …>`, where native async fns are not dyn-compatible. Hand-written
`BoxFuture<'a, …>` is the zero-dependency form of what the `async-trait` macro generates; adopting
`async-trait` would add a proc-macro dependency for syntax only, against the dependency policy in
`AGENTS.md`. (Re-audit: the Tokio admission does not change this — `async-trait` is orthogonal to
Tokio, and dyn-compatibility is unchanged.) Verdict: keep.

## Follow-up Measures

All measures land in the `0.1.0` cycle; nothing from this audit is deferred past the publish.

| ID | Measure | Nature | Timing |
| --- | --- | --- | --- |
| R1 | Rename the packet family to stream terminology **and adopt the standard `futures::Stream` trait for stream bodies in the same change**: `create_packet → open_stream`, `OutboundPacket → OutboundStream`, `IncomingPacket → IncomingStream`, `PacketBody` is replaced by `Stream` (futures-core enters the public ABI here), and the `Packet*` support types likewise (`PacketTarget → StreamTarget`, `PacketPolicy → StreamPolicy`, `PacketMetadata → StreamMetadata`). Terminology model: a *packet* is the individual data unit processed within a stream (wire/internal vocabulary — `PacketConsumer`, wire kinds, schema tags, and internal modules keep their names unchanged); a *stream* is the ordered flow the public API exposes, so documentation "packet stream" and API "stream" denote the same thing. Requires an API-manifest amendment, an api-inventory digest update, and a public-api proof re-run; wire formats and golden vectors are unaffected. Do not use "connection" or "channel" in any new name. | API rename + public-ABI dependency admission | `0.1.0` cycle (decided 2026-09-05) |
| R2 | `Stream` impl for `EventSubscription` (may build on `tokio_stream` wrappers) and a `StoreScan → BoxStream` converter for the surfaces not covered by R1 (futures-core and Tokio traits are already in the public ABI via R1/R3, so no feature gate is needed) | Additive | `0.1.0` cycle, with R1 |
| R3 | Amend the API manifest's ABI rule and record the rationale in an ADR (or a manifest note): Tokio is the sole supported async ecosystem; `futures-core` and Tokio traits/interfaces may appear in public signatures, while Tokio channel/task handles, TLS/CBOR/redb/JSON implementation types, wire envelopes, and private-key bytes stay excluded | Documentation + manifest amendment | `0.1.0` cycle, with R1 |
| R4 | Internal cleanup: replace `ChannelBody`'s hand-rolled receiver loop with `ReceiverStream` + explicit end sentinel | Internal only; no API impact | `0.1.0` cycle; low priority |

## Non-Goals of This Audit

- No change to the two-phase packet creation flow; the `TraceId`-before-body contract stands.
- No change to cursor-paged reads; resumability is a feature, not an accident.
- No admission of Tokio channel or task handles into public signatures; Tokio *traits/interfaces*
  are admitted by the amended ABI rule (R3).
