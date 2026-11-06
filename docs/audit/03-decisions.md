# Confirmed Decisions

Dispositions confirmed by the project owner during the audit. **DECIDED** items are awaiting implementation; they are not a task list or a schedule.

## Task surface

| ID | Finding | Disposition |
|---|---|---|
| A1 | Task output payload overflows its CBOR bound after the write landed | **DECIDED** — derive the body bound from `LABEL_SET_MAX_ENTRIES × (MAX_TAG_LEN + LABEL_VALUE_MAX_BYTES)` with framing headroom; add a round-trip test at the bound (max labels, max-length keys and values) |
| A2 | `ReconcileDecision` has no terminal-failure variant | **DECIDED** — add `Failed` **and remove the automatic retry on `Err`**: only an explicit `Retry` re-arms the schedule; `Err` terminalizes |
| B3 | No official load balancer; label-addressed data plane undocumented | **DECIDED** — install a `DefaultLoadBalancer` (first matching candidate, the implementation three tests hand-wrote) through `register_default()`, add a guide section, then delete the three duplicate `FirstMatch` impls |
| B4 | `CoreTaskKind` lets core-ness select task policy | **DECIDED** — move slot class and shutdown-drain onto the reconciler registration; official core verbs declare through the same channel in `register_default()` |
| D7 (part) | `TaskOutput.kind` duplicates `TaskEntry.kind` | **DECIDED** — delete `TaskOutput.kind`; `TaskOutput` becomes `{ bytes }`; remove the `resolve_terminal` kind comparison |

## Extension surface

| ID | Finding | Disposition |
|---|---|---|
| B1 | TLS trust class reachable only through the built-in enum | **DECIDED** — **delete `TransportTrust` entirely**. Official TLS transports use `merge_client_config()` unconditionally (identity is carried by the application-layer session handshake + exporter binding). Caller transports own their own TLS stack; the library makes no trust claim about them. Simplify `Transport::connect(endpoint, trust)` to `connect(endpoint)`; delete `accepts_tls_intents` and the `registry.rs:452` double check; `TransportCapabilities` keeps only `admission` |
| B2 | Event seam sealed in both directions | **DECIDED** — add a tag-keyed event channel (`EventTag`-qualified publish/subscribe); the nine sealed crate types stay untouched |
| B5 | `LaneId` centralisation | **DECIDED** — do **not** use `inventory`/`linkme`; provide one managed registration entry point in the registry. `const CODE: u8` is carried **by the lane**; the registry lists lane objects only, and `code()`/`from_code()`/`ALL` derive from that list |
| B6 | `TransportScheme` centralisation | **DECIDED** — refactor to table-driven. The enum stays as URL-syntax constants; `register_default()` and `official_transport()` derive from one `(name, tag, ctor)` table, so adding an official transport is one table row |
| B7 | `TombstoneKind` centralisation | **DECIDED** — refactor to table-driven |
| B9 | Reserved-domain rule on 4 of 8 seams | **DECIDED** — apply `require_caller_domain` to **all eight** seams. This breaks the ability of a caller to claim `DefaultNextHop::TAG` before the default path runs (the `.entry().or_insert_with()` override mechanism stops working for that tag). Tests using caller-domain tags are unaffected |
| B10 | Five public enums lack `#[non_exhaustive]` | **DECIDED** — add to all five |
| B11 | Built-in `DIRECT` tag privileged in the data plane | **DECIDED** — introduce an explicit defer signal in `RouteNextHop::plan` (e.g. `Defer` / `Ok(None)`) so `DirectRouting` becomes an ordinary registered implementation and the tag comparison disappears |
| B12 | `register_routing_policy` has no end-to-end test | **DECIDED** — add one: register a caller routing policy, send with `StreamPolicy::new(RoutingPolicy::from(tag), hops)`, assert delivery along the chain plus a typed failure for an empty-table policy |
| B8 | Per-lane inputs unioned into shared structs | **PENDING** — see `04-pending.md` |

## Routing

| ID | Finding | Disposition |
|---|---|---|
| A7 | Graph re-planning can route back through the visited chain | **DECIDED (doc-only)** — do **not** force acyclic paths. Rationale: a sparse mesh with extra connections is an undirected cyclic graph; only shortest-path matters. Excluding visited nodes from re-planning would make a package die at a node when the next leg breaks mid-route, since the only escape is to backtrack via another route. Reword `src/routing.rs:24-32` to describe the actual guarantee: bounded by the hop budget, with mid-route re-planning permitted to revisit the chain when the next leg fails |
| A8 | Routing security doc overstates the guarantee | **DECIDED** — reword to "each hop authenticates its immediate predecessor; the origin identity is hop-attested, not end-to-end", and align `IncomingStream`'s endpoint doc |

## Retention and disk data

| ID | Finding | Disposition |
|---|---|---|
| A12 | `RESOURCE_FEED_RETENTION` is a library-imposed deletion schedule | **DECIDED** — **delete the window entirely.** Keep the full feed history; cleanup is the operator's mechanism. Removes `RESOURCE_FEED_RETENTION`, `oldest_retained()`, the eviction arithmetic, `ResourceFeedError::Compacted`, and the `first_evicted` loop. `ResourceFeedError::Reset` is **kept** — it handles a leave wipe resetting the head below the cursor, which is unrelated to compaction |
| A11 | `RESOURCE_REGISTER_CAP` cannot be disabled | **DECIDED** — accept `cap == 0` in `NodeConfig::with_resource_removal_retention` and document it as "no population cap". The sweep already implements it |
| A14 | `RESOURCE_REMOVAL_RETENTION` documented as a storage knob | **DECIDED** — reword `src/config.rs:242-257` to state it is a cluster-wide convergence parameter, not GC |
| A13 | `FORWARDING_ROUTE_CAPACITY_DEFAULT` hardcoded | **DECIDED** — derive from the same configured `TraceMetadataLimits` the route table uses |
| (audit) | Feed retention window "24 MB is acceptable" | **SUPERSEDED** — the owner's later principle (disk data belongs to the user) overrides the size argument; the window is deleted (see A12) |

## Verification facilities

| ID | Finding | Disposition |
|---|---|---|
| C1 | `compatibility.rs` is mostly a gentleman's agreement | **DECIDED** — strip it down. Keep `descriptor-v1` with `PreviousReader` (pins that an old wire shape still decodes) and keep behavioral assertions that do not depend on frozen bytes (`unsupported_format_versions_fail_closed`, `trace_vectors_decode_to_exact_phases`). Delete the 22 current-shape vectors, `FROZEN_FAMILY_COUNTS`, and the self-referential tests. Also delete the duplicate `GOLDEN_RESOURCE_RECORD_V1` in `src/resource/mod.rs:685` |
| C2 | Six of seven `static_invariants` tests are source greps | **DECIDED** — delete five: `compatibility_manifest_enumerates_every_family`, `redb_adapter_stays_feature_gated`, `removal_commit_has_a_single_production_writer`, `cluster_identifiers_stay_excised`, `packet_body_vocabulary_stays_retired`, `wall_clock_surface_stays_out_of_the_facade`. **Keep `metadata_namespace_literals_are_single_sourced`** — it caught a real duplicated-data regression during this work |
| C3 | `families.rs` hand-rolled source scanner | **DECIDED** — delete it |
| C4 | SLO strata never run in CI | **NO-FIX** — accepted as operator-only verification |
| C5 | Offline resource writes unproven in CI | **NO-FIX** — falls under C4 |
| C8 | SLO bound constants hand-re-declared | **NO-FIX** |

## Naming and format

| ID | Finding | Disposition |
|---|---|---|
| D17 | `g7`/`g9` vector names are development-era code names | **DECIDED** — rename strictly by semantics, no version numbers stuffed into names; delete whatever can be deleted |
| D18 | Two version numbers in one domain | **DECIDED** — tag version follows `record_version` |
| D8 | `TimeWire` vs millis | **DECIDED** — unify on millis, delete `TimeWire`. `src/time.rs` needs a pre-epoch-safe conversion (the existing `to_millis` returns 0 for pre-epoch) |
| D9 | `ErrorKind ⇄ u8` two hand-written tables | **DECIDED** — merge into one table **and renumber contiguously**. Pre-0.1.0 has no persisted data, so renumbering is free. The `record-routing-v1` and `record-delivered-v1` golden vectors are non-Failed phases and carry no `kind_code` bytes |
| D10 | `HopState` parallel to `RouteContext` | **DECIDED** — compose: `RouteContext` embeds `HopState`; the projection becomes a move |
| D11 | Four parallel lifecycle enums | **DECIDED** — merge all into one. `RouteState` becomes the single public type; `TracePhase` and `TraceTransition` are deleted; `TraceTransition::Streaming` disappears with them and the golden vector is constructed via `RouteState::Streaming`. `Selecting` is never persisted, so the wire code maps it out of band |
| D12 | Per-lane redundant `namespaces()` bodies | **DECIDED** — trait associated constant with a default `namespaces()` implementation |
| D13 | `ResourceChange::is_removal` duplicates `kind()` | **DECIDED** — delete it (`ResourceVersion::is_removal` stays) |
| D14 | `PageApply.applied` duplicates `installed.len()` | **DECIDED** — delete the field; the test-only `apply_page_ctx` uses `.installed.len()` |
| D15 | `SessionPolicy.pending_admissions` cannot vary | **DECIDED** — delete the field, use the constant at the one read site |

## Local delivery

| ID | Finding | Disposition |
|---|---|---|
| (design) | `run_local` is a special-cased path with dead branches | **DECIDED** — express local delivery as **a hop**: introduce `DeliveryLeg { Session(SessionEntry), Local(LocalLeg) }` carrying `pending_acks`/`clock`/`alive`/`deliver_open`/`deliver_chunk`/`deliver_end`. The only divergence is `deliver_*`. `PumpHandoff::Local` becomes `PumpHandoff::Leg(DeliveryLeg::Local(..))`; `destination == local` constructs a Local leg as the next hop rather than returning a different enum; `run_local` is deleted; `admit_stream` becomes the Local leg's `deliver_open`. The incoming table is **node-level and shared** (mirroring "one table per session, lifetime = session"), which makes duplicate detection and the queue bound live again on the local path. Local delivery **does** go through `PendingAdmissions`. The dead branches exist because `run_local` violated the one-table-per-session model, not because the model needs a special case |

## Documentation

| ID | Finding | Disposition |
|---|---|---|
| E1 | Development history in docs and public rustdoc | **DECIDED** — rewrite all of it as present-tense descriptions of current behavior; drop phase and migration framing |
| E2 | `send_sync` does not document the absence of a timeout | **DECIDED** — add a sentence mirroring `Tasks::wait` |
| E3 | `send_async` does not document route-record timing | **DECIDED** — state that the record appears once admission completes |
| E4 | `ResourceHook` runs on the caller's admission future | **DECIDED** — state that hooks run on the caller's admission future and must not block |
| E5 | Extension-slot reentrancy is a documented trap | **DECIDED** — add nested-submit detection at admission, returning a typed refusal instead of a deadlock |
| A10 | Poisoned registry reads silently degrade | **DECIDED** — unify the read accessors on returning `Result` with a typed `Error::extension_registry`, matching the write paths |

## Feed watch

| ID | Finding | Disposition |
|---|---|---|
| (design) | `fill` reads the whole window in one pass and can lose changes mid-scan | **DECIDED** — separate `scan_cursor` from `cursor`: `fill` advances only the scan position, `cursor` advances only when an entry is popped. A mid-scan decode failure then loses nothing |
| A4 | Watch can stall forever | **DECIDED** — periodic re-check at **5 s** (raised from 100 ms); `notified` remains the latency path |
| (design) | `Compacted`/`Reset` cannot be recovered in place | **DECIDED** — `Compacted` disappears with the window; `Reset` stays |

## Kept as-is (NO-FIX)

Findings raised during the audit and explicitly decided to keep. **These were decided under the criteria in `05-principles.md`; several predate the criteria's final form and may deserve re-evaluation under principle P7 (verification facilities must earn their keep) and the general no-duplication rule.**

| ID | Finding | Disposition |
|---|---|---|
| P3-1 | `limit.clamp(1, MAX_VIEW_PAGE_ITEMS)` repeated 9× (`runtime/lifecycle.rs:220`, `runtime/views.rs:85,162,189,312,346`, `resource/select.rs:69`, `task/mod.rs:569`, `routing.rs:781`) | **NO-FIX** — accepted duplication |
| P3-4 | `CHANGELOG.md` is empty | **NO-FIX** — accepted doc gap |
| P3-7 | No minimal send example | **NO-FIX** — accepted doc gap |
| P3-8 | 175 `sleep` calls in tests | **NO-FIX** — accepted test style. **Re-evaluate under P7**: sleeps as synchronization are exactly the kind of verification facility that can silently pass |
| P3-14 | `check_ranges` / `check_bounds` duplication | **NO-FIX** — accepted |
| P3-15 | membership / resource batch-commit duplication | **NO-FIX** — accepted |
| P3-16 | winner-contest duplication | **NO-FIX** — accepted |
| P3-17 | tombstone decode/apply ×4 | **NO-FIX** — accepted |
| P3-24 | `read_hint` allocates 65 KiB before validating 17 bytes (`transport/framing.rs:207-218`) | **NO-FIX** — bounded, non-malicious, robustness only |
| P3-25 | json adapter: `load_chain` ignores configured limits (`json/store.rs:362,640`), flush does not wait for in-flight commit (`:935-938`), `native.rs:50` uses `println!` | **NO-FIX** — test-only adapter, though `json` is a public feature |
| E20 | `member()` recomputes status inline and reads the store twice (`runtime/views.rs:53-57`) | **MERGED** — folded into WP4b (`b16b638`), which unified the connectivity view |
| E21 | `published_endpoints` snapshot block duplicated 4× (`task_effects.rs:905-909,968-972`, `anti_entropy.rs:69-72,88-91`) | **NO-FIX** — accepted duplication. **Re-evaluate under the no-duplication rule** |
| E42 | `membership/sync.rs:431-442` tolerated-conflict over-counts: compares only `revision >=`, so a different endpoint/label still counts as installed and still fires `member_changed` → two revision bumps for one install | **NO-FIX** — accepted over-counting. **This is a real behavior defect** (the revision is an observable counter); re-evaluate |
| E43 | membership tick owned identity GC | **MERGED** — WP4c (`15c3be6`) moved identity GC into the recovery retention sweeps |
| E47 | `RetryClass::Extension` retries non-convergent operations | **NO-FIX** — accepted. Note this interacts with A2: once `Err` stops auto-retrying, the extension retry schedule only applies to an explicit `Retry` |
| D1 | Deterministic transaction id duplication | **NO-FIX** — downgraded to P3, accepted |
| E27 | Transport split-block duplication (×6) | **NO-FIX** — downgraded to P3, accepted |
| E28 | `Connection::send` duplication | **NO-FIX** — downgraded to P3, accepted |

## Merged but not previously recorded

Decisions taken informally during the audit and implemented in a work package, recorded here so the record is complete.

| ID | Finding | Disposition |
|---|---|---|
| C9 | `NextHopView` did not expose `remaining_hops` | **MERGED** — WP11 (`9c13c4f`) added `NextHopView::remaining_hops` |
| A2 (original) | WebSocket upgrade IO classified as `InvalidInput` instead of `Io` | **MERGED** — folded into WP14 (`50c95c9`); `ws_io_error` is the shared mapper and `receive_error` reuses it |
| A3 | TLS-class override channel-binding downgrade | **MERGED (capability model)** — WP10 (`665eacf`) replaced the hardcoded `attributable` state with a declared `TransportCapabilities`. Whether the override path still downgrades channel binding is **not verified**; see `04-pending.md` |
| P3-3 (partial) | Provider domain naming unified to `radiata.woooo.tech` | **MERGED (partial)** — WP15a (`9f75a82`) inventoried the built-in tags and pinned the `<category>/v1/<name>` convention. The separate `/v1/xxx` vs `/xxx/v1` vs `/xxx-v1` consistency sweep was **not done**; see `04-pending.md` |
