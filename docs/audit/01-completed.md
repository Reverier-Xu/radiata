# Completed Work

Branch `audit-followups`, 22 commits, `a9bc717..44f29ec`. 149 files, +13639 / -5662.

Baseline before this work: `a9bc717` — 1037 passed / 0 failed / 24 ignored.
Current: `44f29ec` — 1123 passed / 0 failed / 26 ignored.

## Commit log

| Commit | Work package | Summary |
|---|---|---|
| `b704fa5` | WP1 | Remove the test-only discovery surface and dead error variants (`ProviderErrorContext::Discovery`, `NeighborPolicy`) |
| `4c71fb2` | WP2a | Drop the test-only `transactional_migration` capability bit |
| `4acbad7` | WP2b | Drop `NodeDescriptorV1.removed`, renumber CBOR fields, refresh descriptor golden vectors |
| `dc15c65` | WP3 | Describe current behavior instead of development history (62 files, comments only) |
| `2c1a3a4` | WP4a | Keep the active-leave signal through a concurrent leave; refuse a second leave; `LeaveSignal`; idempotent teardown |
| `b16b638` | WP4b | Report dead sessions consistently; release dropped queue frames; `connected_peers()` alive filter; `unreachable!` → `Closed` |
| `15c3be6` | WP4c | Log settled freezes; narrow descriptor notifications to own writes; move identity GC to recovery retention sweeps |
| `d9cfb15` | WP5a | Persist revocations outside the authorization section; one `storage_corrupt()` constructor; redb open read-check before write; single-buffer `encode_frame_into` |
| `89aff53` | WP5b | `RecoveryConfig::new` rejects sub-second; typed `SyncKind`; `ack_error` doc fix; descriptor docs → "strictly greater revision" |
| `4d9e9bc` | WP7 | Freeze the 0.1.0 public API surface: `ReceiptRetentionReport` → `view.rs` with accessors, `OperationId::from_bytes`/`as_bytes`, private `ReconcileContext` fields, `Task::status() -> Option<TaskStatus>`, `MemberStatus` non-exhaustive, ABI baseline regenerated |
| `7ed136b` | WP5c | Session stamps on Pong (delete `pong_last_seen`); TLS log after handshake; accept backoff `saturating_sub(1)`; typed audit dial initiator always settled; `with_task_reconcile_extension_slots` |
| `c92737e` | WP13 | Trust resource rows through the delivering session — remove per-resource signatures and the whole writer-trust deferral machinery (net −1110 lines) |
| `5dc7f73` | WP6 | Single-source remaining shared constants: `canonical_id!` for `KeyOperationId`, inline purpose validation per durable record module, one checkpoint key, table-driven reserved labels, fuzz crate edition 2024, schema family coverage |
| `435856f` | WP8 | Make task kinds and outputs domain-contained tags: `TaskKind(QualifiedTag)` with 19 core constants, `TaskOutput { kind, bytes }` with canonical CBOR core encodings, `SucceededWithOutput` |
| `50c95c9` | WP14 | Deliver local targets without a session: shared admission body, local pump, provider `Io` classification for handshake and upgrade |
| `08089d5` | WP9 | Select routing policies by tag and give every lane its own module: `RoutingPolicy(QualifiedTag)` + registry, `PendingAdmissions` session API, `Lane` trait with impls next to owning modules |
| `665eacf` | WP10 | Register official transports and protocols explicitly: empty-by-construction registries, `register_default()`, `TransportAdmission`/`TransportCapabilities` provider capability, `RuntimeClient::get_task`/`page_tasks` |
| `9c13c4f` | WP11 | Route packets along an explicit or learned path: `RouteContext`/`HopState` carry the remaining path, `StreamTarget::Path`, `RouteNextHop::plan`, `src/routing/graph.rs` learned topology, `NextHopView::remaining_hops` |
| `bfc5ef8` | WP12 | Persist a resource change feed with resumable versions: feed append inside the record commit transaction, `ResourceWatch` replay + live follow, bounded retention with typed compaction |
| `9f75a82` | WP15a | Inventory built-in tags and pin their version convention: `src/protocol/builtin.rs` catalog, category constants, three-way test (inventory ↔ live registries ↔ owner sources) |
| `c42ef6e` | WP15b | Measure revocation and reconnect catch-up SLOs: `tests/slo.rs`, two `#[ignore]` strata with derived bounds |
| `44f29ec` | WP16 | Keep the feed window bounded and route outcomes honest: batch eviction, periodic watch re-check + `Reset`, hop budget aligned with the walk, graph outcomes only for queued opens, refused tombstone rows, shared reclaim predicate, domain-neutral metadata notify, derived family locality, exhaustive TLS-class predicate, reserved domain for protocols, override-order doc |

## Verification facilities added

- `tests/slo.rs` — 588 lines, two measured strata. Revocation propagation: 104 ms measured vs 8200 ms bound. Reconnect catch-up: 94 ms measured vs 48200 ms whole bound / 8200 ms convergence bound. Catalog size 256 (converges to 288 after 32 further writes).
- `tests/local_delivery.rs` — 259 lines, three regression tests for isolated-node self-delivery, above-chunk-bound reassembly, and non-local exact target still failing on the session path.
- `tests/routed_packets.rs` — +264 lines for caller paths, learned paths, invalid-path rejection, graph planning.

## Incidents during the work

- WP12's worker timed out at the 60-minute limit after finishing; the patch was complete and passed all gates, so it was applied and merged manually.
- WP15's first worker hit a network failure mid-run; the tag-inventory half was recovered and merged as `9f75a82`, the SLO half was re-dispatched as WP15b.
- WP16's worker was terminated mid-run; its patch was complete and green except for a missing ABI baseline regeneration, which was done manually (`ResourceFeedError::Reset` was the only delta).
- The first reviewer batch (3 agents) all hit the default 30-minute timeout with no report produced; they were re-dispatched with a hard tool-call budget and 60-minute limits.
