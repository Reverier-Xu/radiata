# Findings

Every valid finding from all four review rounds, grouped by theme. Severity is the reviewer's, adjusted after spot-checking against source.

Items marked **✗** were rejected as out of scope under `05-principles.md` (threat model or library-scope) and are recorded so they are not re-raised.

---

## A. Correctness defects (verified)

### A1 — Task output payload can overflow its CBOR bound after the write landed
**P1, verified.** `src/task/output.rs:33` sets `OUTPUT_LIMITS = CborLimits::new(8, 256, 16 * 1024)`. A `MemberView` may carry `LABEL_SET_MAX_ENTRIES = 64` labels (`src/label.rs:34`) whose keys reach `MAX_TAG_LEN = 128` (`src/protocol/tag.rs:6`) and values `LABEL_VALUE_MAX_BYTES = 256` (`src/label.rs:19`) — 64 × (128 + 256) = 24576 bytes of label text alone, exceeding 16384.

Call site: `src/runtime/task_effects.rs:1319-1323` commits the descriptor (`store_descriptor_ctx`), emits the event, bumps the revision, and **then** calls `encode_member(&view)?`. A record that legitimately exists in the register therefore turns `PATCH_NODE_METADATA` into an `Internal` failure, and `Task::wait` surfaces an error for a write that landed. The same shape applies to `encode_resource_mutation` on the put/delete path.

Why it matters: a landed write reported as failed is the one failure mode a user cannot recover from by retrying — a retry is a duplicate write, and the caller's model of the register is now wrong.

### A2 — `ReconcileDecision` has no terminal-failure variant
**P1, verified.** `src/task/mod.rs:1337-1347` has only `Succeeded`, `SucceededWithOutput(Vec<u8>)`, `Retry`. The `submit` effect (`src/node/api.rs:483-500`) maps `Retry` to `Error::overloaded("custom task retry")` and any `Err` into the same bounded-retry path. A reconciler that detects a permanently invalid business input is silently re-executed before the caller ever sees the error.

Why it matters: business retry belongs to the user's logic (principle P2). This is the only surface where the crate reaches into the user's retry policy.

### A3 — Feed retention window is not enforced for batched appends *(fixed in 44f29ec)*
**P1, verified, fixed.** `src/resource/feed.rs:148-157` evicted only one key for a batch of n records, leaving n−1 stale entries per batch. Fixed to evict the whole expired range.

### A4 — A parked feed watch can stall forever
**P1, verified, fixed in 44f29ec** by a periodic re-check and a typed `Reset`. Two reachable triggers: an indeterminate commit that later resolves to installed (the wake only fires on the `Committed` arm, `src/resource/store.rs:314`), and a leave wipe that resets the head below the cursor (`src/identity/leave.rs:434-438` wipes `MetadataDomain::Resource`).

### A5 — Hop budget was validated one stricter than the walk
**P1, verified, fixed in 44f29ec.** The walk consumes no budget at origin dispatch, one per relay, and checks arrival before the budget, so a path of `relays + 1` entries is valid for `max_hops = relays`. The three validators used `path.len() <= max_hops`, rejecting a legal single-relay path.

### A6 — The learned graph recorded failures for attempts that never left the node
**P1, verified, fixed in 44f29ec.** `terminal!` charged the whole planned path before the open was queued: dead session, saturated pending map, envelope/encode errors, and caller body-stream errors all charged every edge.

### A7 — Graph re-planning can route back through the visited chain
**P2, verified.** `src/routing/graph.rs:171-190` builds adjacency from all learned edges; `:208-220` relaxation skips only `settled`, not `visited`/`source`/`current`. `src/routing/forward.rs:238-253` constrains only the *first* hop via `loop_free_candidates`. A mid-route re-plan can therefore contain a node already in `visited`, while `src/routing.rs:24-32` claims the walk is loop-free "by the plan's own construction".

Bounded by the hop budget, so not an infinite loop, but it wastes budget and can re-send a frame through a node that already relayed it.

### A8 — The routing security doc overstates the guarantee
**P2, verified.** `src/routing.rs:11-19` claims mutation of the trace, endpoints, protocol, metadata, or any route field fails closed. What `receive` actually checks is `current == peer` — the immediate predecessor. There is no MAC over the envelope. Any authenticated relay can rewrite `source`, `destination`, `protocol`, `metadata`, `visited`, `remaining_hops`. `IncomingStream` (`src/packet/mod.rs:432-433`) documents endpoints as session-authenticated while `source` comes straight from the wire.

Under the post-admission mutual-trust model this is a documentation defect, not a security defect.

### A9 — Tombstone lane never fills `refused`
**P2, verified, fixed in 44f29ec.** `apply_tombstone_rows` returned an empty refused list, so decided-refusal rows entered the derived view and were gossiped to every primed sibling.

### A10 — Poisoned registry reads silently degrade
**P2, verified.** Registration paths use `.map_err(Error::extension_registry)?`; read accessors use `.ok()` / `.unwrap_or_default()` (`src/extension_registry.rs:161, 171, 297, 419, 431, 443, 489, 498`). A poisoned `features` lock makes handshake offer nothing; hooks silently stop running; protocol resolution returns nothing.

### A11 — `RESOURCE_REGISTER_CAP` cannot be disabled even though the sweep supports it
**P1, verified.** `src/resource/retention.rs:37` + `src/config.rs:264` rejects `cap == 0`, but the sweep itself implements `cap == 0` as "never evict" and tests already exercise it (`retention.rs:542`, `:566`).

### A12 — `RESOURCE_FEED_RETENTION` is a library-imposed deletion schedule
**P1, verified.** `src/resource/feed.rs:60`, deletion at `:163-181` inside the register commit transaction, no `NodeConfig` setter exists.

### A13 — `FORWARDING_ROUTE_CAPACITY_DEFAULT` is hardcoded while its sibling is caller-derived
**P2, verified.** `src/routing/forward.rs:197` passed literally at `src/runtime/supervisor.rs:1082`, whereas the route-table capacity at `:1162` comes from `config.trace_metadata_limits().active()`.

### A14 — `RESOURCE_REMOVAL_RETENTION` is documented as a storage knob but is a cluster contract
**P2, verified.** `src/config.rs:242-257` describes it as retention policy; `src/reconcile/plane.rs:474-480` and `src/guide.rs:70-81` show it is the reclaimed-knowledge basis. An operator "tuning" it resurrects or drops evidence cluster-wide.

---

## B. Extension surface (principle P4 / P5)

### B1 — TLS trust class is reachable only through the built-in enum
**P1, verified.** `TransportTrust::for_dial` (`src/transport/registry.rs:120-126`) returns `Merge` only for `Builtin(scheme) if scheme.is_tls_class()`; `Custom(_)` is always `Plaintext`. Custom registrations hard-code `accepts_tls_intents: false` (`:388`), and `:452` makes a `Plaintext` intent fail typed on a TLS transport.

Consequence: **a caller who implements a TLS transport with identical framing cannot connect at all.** `TransportTrust` selects which rustls `ClientConfig` to build (`src/transport/tls.rs`: `Merge => merge_client_config()`), so the intent is not cosmetic.

### B2 — The event seam is sealed in both directions
**P1, verified.** `Event: private::Sealed` (`src/operation.rs:8`); `subscribe`/`emit` are `pub(crate)` (`src/node/event.rs:222`, `:235`); the only public entry is `watch::<E: Event>` (`src/node/handle.rs:511`), which cannot be instantiated for a user type. Users can attach logic to crate events (plus `ResourceHook::observed`, `ActionHook::on_transition`) but cannot publish a typed event of their own.

### B3 — No official load balancer, and the label-addressed data plane is undocumented
**P1, verified.** `register_default()` (`src/extension_registry.rs:110-117`) installs transports, routing policies, and features only. `StreamTarget::MatchingNodes` without a registered LB is refused (`src/node/handle.rs:64-66`). `load_balancer` / `MatchingNodes` / `LoadBalancingPolicy` appear **zero times** in `src/guide.rs`.

Evidence that this is a real gap: three test files each hand-wrote the same 12-line `FirstMatch` policy (`tests/facade.rs:59`, `tests/mixed_versions.rs:87`, `tests/public_api.rs:528`).

### B4 — `CoreTaskKind` lets core-ness select task policy
**P2, verified.** `slot_class` (`src/task/mod.rs:140`) and `drains_on_shutdown` (`:125`) dispatch through `CoreTaskKind::from_tag`. A caller task kind is always `SlotClass::Extension` and never drains, while official core verbs get their own slot class and drain behavior.

### B5 — `LaneId` centralisation: adding a lane edits other modules' files
**P2, verified.** Adding a lane requires `reconcile/wire.rs` (enum variant, `code()`, `from_code()`, `ALL`) plus `reconcile/lane.rs` (`policy()`) — 5 mandatory sites in 2 files, none of which belongs to the lane. The reviewer's suggested tuple `REGISTRY` reduces it to 2 sites, still in other modules' files.

Measured: `LaneId::Variant` referenced 142 times across 10 files. `LaneId` carries double duty: wire code **and** behavior dispatch.

### B6 — `TransportScheme` centralisation: adding an official transport edits 9 sites
**P2, verified.** `src/transport/endpoint.rs` has `enum`, `ALL`, `name`, `canonical`, `default_port`, `is_tls_class`, `from_prefix`; `src/transport/registry.rs` has `builtin_transport_tag` and `official_transport` (a hand-written exhaustive match). Adding an official transport (e.g. QUIC) touches 9 sites in 3 files, while a caller adding a transport makes one `register_transport` call.

### B7 — `TombstoneKind` centralisation
**P2, verified.** The enum plus `namespace_tag` in `src/reconcile/wire.rs` must be edited to add a tombstone family.

### B8 — Per-lane inputs are unioned into two shared structs
**P2, verified.** `ScanFilters` (`src/reconcile/lane.rs:42-45`) carries the tombstones-only `checkpoint` and the resources-only `swept_at`/`removal_retention`; `LaneContext` (`:60-68`) carries the tombstones-only `sessions`/`authorization`. The plane must still know which lane needs which input (`src/reconcile/plane.rs:693-710`). Adding a lane with a new input edits the seam structs **and** the plane.

### B9 — Reserved-domain rule enforced on 4 of 8 registration seams
**P2, verified.** Enforced: features (`extension_registry.rs:137`), protocols (`:455`), task reconcilers (`:395`), routing policies (`routing.rs:1080`). Not enforced: load balancers (`:277`), resource hooks (`:357`), action hooks (`:373`), next hops (`routing.rs:1063`).

The predicate's own doc (`src/protocol/tag.rs:20-26`) lists exactly the four surfaces that do enforce it, so the doc does not lie — the doc simply does not claim the other four.

### B10 — Five public enums lack `#[non_exhaustive]`
**P1, verified.** `TaskPhase` (`src/task/mod.rs:296`), `ReconcileDecision` (`:1336`), `ResourceOrigin` (`src/operation.rs:218`), `TransportScheme` (`src/transport/endpoint.rs:135`), `TransportSelector` (`:219`). Siblings all carry the attribute (`StreamTarget`, `RouteState`, `TrustStatus`, `ReconcileOutcome`, `MemberStatus`, `ResourceChangeKind`, `ResourceFeedError`) — drift, not policy.

### B11 — Built-in `DIRECT` tag is functionally privileged in the data plane
**P2, verified.** `src/runtime/packets.rs:340`: `if routing_policy.tag() == crate::RoutingPolicy::DIRECT.tag()` selects the node-level policy. `DirectRouting` (`src/routing.rs:990-1001`) implements `RouteNextHop` but always returns `Err(route_unavailable)` — the registered implementation is never consulted; the tag literal is the behavior switch.

### B12 — `register_routing_policy` has no end-to-end test
**P2, verified.** Zero uses in `tests/`. The only coverage is `src/extension_registry.rs:892-911`, a unit test asserting `routing_policy(&caller).is_some()`.

### B13 — Custom protocol registration forces feature-fingerprint boilerplate
**P2, verified.** `ProtocolDefinition::new(tag, owning_feature)` requires an owning feature in the negotiated offer, so users either invent an arbitrary 32-byte digest (`tests/secure_join.rs:2016`) or borrow a builtin feature tag (`tests/facade.rs:107` borrows `radiata.woooo.tech/features/session-core`).

### B14 — `tls://` occupancy is a timing privilege
**P2, verified.** `override_builtin_transport` must precede `register_default()`; afterwards it is a `Conflict` (`src/transport/registry.rs:596`, test at `:1377`).

---

## C. Verification facilities (principle P7)

### C1 — `src/compatibility.rs` is mostly a gentleman's agreement
**P2, verified.** 930 lines, 23 vectors, 16 hex constants, 2516 bytes of hex, 8 families. `VECTOR_MANIFEST` is consumed only by its own test module. `FROZEN_FAMILY_COUNTS` (`:434`) is read only by `family_inventory_is_closed`, i.e. the file asserts its own constants match its own manifest. `manifest_vectors_reproduce_byte_for_byte` (`:486`) is hex → decode → re-encode → compare, which is circular.

Duplicate data confirmed: `src/resource/mod.rs:685`'s 216-byte `GOLDEN_RESOURCE_RECORD_V1` is byte-identical to `RESOURCE_RECORD_G7_HEX` (`compatibility.rs:417`).

The parts that do earn their keep:
- `descriptor-v1` with `VectorShape::PreviousReader` — pins that an old 143-byte wire shape still decodes.
- `unsupported_format_versions_fail_closed` (`:634`) — rejects unknown versions; does not depend on frozen bytes.

### C2 — Six of seven `tests/static_invariants.rs` tests are source greps
**P2, verified.** 342 lines. `compatibility_manifest_enumerates_every_family` (`:205`) greps `src/compatibility.rs` for the string `"CompatibilityFamily::Packet"` — a comment satisfies it. Same category: `redb_adapter_stays_feature_gated`, `removal_commit_has_a_single_production_writer`, `cluster_identifiers_stay_excised`, `packet_body_vocabulary_stays_retired`, `wall_clock_surface_stays_out_of_the_facade`.

The exception that does earn its keep: `metadata_namespace_literals_are_single_sourced` (`:78`) **caught a real regression during this work** — WP15 wrote 19 metadata namespace literals into `src/protocol/builtin.rs`, and the test refused them. That is duplicated-data detection, not contract pinning.

### C3 — `families.rs` hand-rolled source scanner
**P2, verified.** `src/storage/families.rs:313` strips whitespace and needle-matches `_NAMESPACE:&str="`. It silently stops at the first constant written with `concat!`, a raw string, or a different type ascription — the guard would pass vacuously.

### C4 — SLO strata never run in CI
**P1, verified.** `tests/slo.rs:392` and `:478` are both `#[ignore]`. `.github/workflows/quality_check.yml` runs `--ignored` only for the simulation fault matrix (`:396`, `:491`) and `public_abi` (`:792`). The two headline guarantees — revocation reaches every live node, a reconnected member catches up — can regress with the pipeline green.

### C5 — Offline resource writes landing after reconnect is unproven in CI
**P1, verified.** The only non-ignored partition proof is `tests/membership_sync.rs:1320-1513`, which bumps **descriptor labels** (`bump_descriptor_label`, `:1378`), never `resources().put`. A regression dropping offline resource records on the reconcile lane would pass CI.

### C6 — `membership_sync_slo_trend_stays_below_bound` asserts nothing by default
**P2, verified.** `tests/membership_sync.rs:1543-1572`: the 10 s bound is asserted only when `RADIATA_SLO_PROFILE_STRICT=1`; otherwise the sample is merely logged. No workflow sets that flag.

### C7 — `soak.rs` is CI-invisible
**P2, verified.** `tests/soak.rs:290-291` is `#[ignore]`; no workflow references `scripts/verify-soak.sh`.

### C8 — SLO bound constants are hand-re-declared
**P2, verified.** `tests/slo.rs:100-116` copies `DETECTION_CADENCE_TICKS = 32` and `SEND_ACK_WAIT = 5 s` with the comment "Re-declared here because the constant is `pub(crate)`". A change to the production constant leaves the asserted bound stale with no failing test.

### C9 — Endpoint-change recovery is only partially proven
**P2, verified.** `tests/membership_sync.rs:1830` proves peers *observe* new endpoints; `tests/transport_chaos.rs:1274` restarts a tail with new listeners but reconnects **explicitly**; `tests/leave.rs:691-782` proves passive reconnect to an *unchanged* endpoint. Nothing proves recovery's dial follows a *changed* published address on its own.

---

## D. Duplication and factoring

### D1 — Feed retention eviction (see A3)
### D2 — Resource lane re-derives the reclaim predicate
**P2, verified, fixed in 44f29ec.** `src/resource/lane.rs:82-88` duplicated `retention::reclaimed` inline and sampled `SystemTime::now()` instead of the pass instant, so prune and receive could disagree on a row sitting exactly on the deadline.

### D3 — Three lanes hand-roll the same scan and apply prologue
**P2, verified.** `scan`: `membership/lane.rs:39-48`, `identity/lane.rs:39-48`, `resource/lane.rs:42-51` are identical except the decode predicate. `apply` prologue: the same "decode → key must equal the record's own identity → else refuse" loop three times.

### D4 — Path-shape validation duplicated with duplicated hop arithmetic
**P2, verified.** `src/routing.rs:727-745` `validate_planned_path` and `src/packet/mod.rs:174-200` `validate_caller_path` independently implement non-empty / duplicate-free / `len <= hops+1`, and both repeat `usize::try_from(max_hops).unwrap_or(usize::MAX).saturating_add(1)`.

### D5 — "Duplicate-free bounded path" implemented four times
**P2, verified.** `src/routing.rs:735-742`, `src/packet/mod.rs:157-166`, `src/packet/wire.rs:263-273` (visited chain), `src/packet/wire.rs:285-295` (remaining path) — the same `BTreeSet` insert loop with a different error context.

### D6 — `ReconcilePlane::deliver` is a ~200-line god function
**P2, verified.** `src/reconcile/plane.rs:741-960`: row extraction → receive filter → apply + refusal → force-rescan → message rewrite → lock #1 → lock #2 → dispatch. The `?` on `engine.drive(...)` at `:919` would discard accumulated `outbound`.

### D7 — Twelve structurally identical `TaskResult` impls
**P3, verified.** `src/task/mod.rs:729-851`: every body is `match CoreTaskKind::from_tag(output.kind()) { Some(<kind set>) => output::decode_x(output.bytes()), _ => Err(...) }`. ~120 lines where only the kind set and decode fn vary.

### D8 — Time codec duplicated
**P3, verified.** `TimeWire { secs: i64, nanos: u32 }` (`src/task/output.rs:415-455`) versus the crate-wide millis convention (`resource` records, `identity/cleanup`, `time::from_millis`). The resource-mutation path is millis → `SystemTime` → nanos, so it gains no precision.

### D9 — `ErrorKind ⇄ u8` maintained as two hand-written tables
**P3, verified.** `src/routing/trace.rs:92-122` (encode) and `:124-190` (decode), 24 arms each. Codes are non-sequential (`FrameTooLarge = 24` sits between 13 and 14; `CallerError = 23` before 22) — historical append order.

### D10 — `HopState` is a field-for-field parallel of `RouteContext`
**P3, verified.** `src/routing.rs:503-510` vs `:529-538`, with hand-written projection both ways (`hop_state()` `:601`, `from_frame()` `:621`), plus a third parallel shape in `RouteWire` (`src/packet/wire.rs:150-168`).

### D11 — Four parallel lifecycle enums
**P3, verified.** `RouteState` (`src/packet/mod.rs:666-672`, public, 5 variants incl. `Selecting`), `TracePhase` (`src/routing/trace.rs:50-55`, internal, 4), `TraceTransition` (`:235-242`, internal, `Streaming` is `#[cfg(test)]`), plus the conversion match at `src/routing/outbound.rs:389-394`. `Selecting` is never persisted.

### D12 — Per-lane redundant `namespaces()` bodies
**P3, verified.** Each lane declares a private `const NAMESPACES` and then a `fn namespaces()` that only returns it: `membership/lane.rs:35`, `identity/lane.rs:35`, `resource/lane.rs:38`, `membership/tombstone.rs:571`. The four method bodies are byte-identical.

### D13 — `ResourceChange::is_removal` duplicates `kind()`
**P3, verified.** `src/resource/feed.rs:305` is `matches!(self.change, ResourceChangeKind::Removed)`; `kind()` (`:298`) already returns the enum. (`ResourceVersion::is_removal` at `mod.rs:259` is a *different* thing — the LWW removal rank — and must stay.)

### D14 — `PageApply.applied` duplicates `installed.len()`
**P3, verified.** `src/resource/page.rs:118-124`, set at `:143-148`; two fields that can never disagree.

### D15 — `SessionPolicy.pending_admissions` is a field that cannot vary
**P3, verified.** `src/session/stream.rs:68` is set to `MAX_PENDING_ADMISSIONS` in the only constructor (`:87`), read once (`:527`). It reads as a knob and is a constant.

### D16 — Lane scan/apply duplication is the same as D3
### D17 — `g7` / `g9` vector names are development-era code names
**P3, verified.** `record-g7-previous`, `record-g9-live`, `record-g9-removal` (`src/compatibility.rs:311, 319, 327`). `rg "g7|g9"` over the whole repo hits only `compatibility.rs`; `git log -S "record-g7"` points at `f7da72a` "freeze the wire and metadata formats for 0.1.0". Sibling vectors in the trace family use `<shape>-v<version>`, so the naming is inconsistent as well as undocumented.

### D18 — Two version numbers in one domain
**P3, verified.** Schema tags are `radiata.woooo.tech/schemas/v1/<name>` (schema version); records carry an independent `record_version: u16`. `descriptor` has `record_version = 2` while its tag still says `v1` (`src/membership/page.rs:206` accepts 1 or 2). The vector names `descriptor-v1`/`descriptor-v2` refer to `record_version`, not the tag version.

### D19 — `TaskOutput.kind` duplicates `TaskEntry.kind`
**P3, verified.** `src/task/mod.rs:470` `TaskEntry { kind, status, output, secret }`; `TaskOutput` carries its own `kind`. `resolve_terminal` (`:950-957`) compares them and returns an internal error on mismatch — a branch unreachable in normal flow.

---

## E. Documentation

### E1 — Development history in module docs and public rustdoc
**P2, verified.** `src/node/handle.rs:106` (public rustdoc) "Each method's contract is the migrated contract of the command or query type it replaces"; `src/reconcile/mod.rs:3` "The plane replaced the push watermark anti-entropy with", `:11` "phase 1"; `src/runtime/task_effects.rs:1` "The migrated mutating verbs", `:55`, `:124`; `src/runtime/task_manager.rs:1048` "caller-migrated effect", `:2130` "used to suppress".

### E2 — `send_sync` does not document that it has no timeout
**P3, verified.** `src/packet/mod.rs:342-347` says "waits only for the destination's current-process admission acknowledgement"; the future awaits an oneshot with no timeout. `Tasks::wait` (`src/node/api.rs:428-435`) already says "No timeout is built in: callers compose `tokio::time::timeout`".

### E3 — `send_async` does not document the route-record timing
**P3, verified.** `src/packet/mod.rs:367-369` says delivery progress is observable through `GetRoute`; the `RouteRecord` is inserted later in the admission task (`src/runtime/packets.rs:130-138`) while `try_send_packet` only queues (`src/runtime/lifecycle.rs:298-305`). An immediate query returns `NotFound`.

### E4 — `ResourceHook` runs on the caller's admission future
**P3, verified.** `src/runtime/task_effects.rs:786` applies `validate`/`mutate` before `tasks.submit`, so a blocking hook stalls the caller's `put().await`. Documented as "before any IO runs", which is true of core's IO but not the hook's.

### E5 — Extension-slot reentrancy is a documented trap, not a prevented one
**P3, verified.** A reconciler awaiting another extension-kind task self-deadlocks against the default 2 extension slots (`src/config.rs:503`, `src/runtime/task_manager.rs:57-75`). Nothing at admission detects the reentrant submit.

### E6 — `register_default` ordering doc misstates the rule
**P2, verified.** `src/extension_registry.rs:204-206` says an override "installed before the node starts" wins; once `register_default()` has run the official tag is occupied and `override_builtin_transport` fails `Conflict`. The sibling registry words it correctly: "a caller may claim before the default path runs" (`src/routing.rs:1002-1004`).

### E7 — `metadata_namespace_literals` test is the exception that proves the rule
See C2.

---

## F. Rejected as out of scope

These were raised and are recorded as **rejected**, not as backlog.

- **Route `source` forgery** — post-admission mutual trust; no non-malicious path produces it.
- **Checkpoint validation on the receive side** — the operator owns the deployment contract; demanding proof of the operator's assertion is infinite regress.
- **Duplicate `Open` handling** — no honest radiata retransmits an `Open` to the same destination.
- **Route policy before envelope validation** — unreachable under honest operation.
- **`read_hint` allocating 65 KiB before validating 17 bytes** — bounded, not malicious, robustness only.
- **`planned_namespace` defense-in-depth** — a decoded journal with a foreign namespace requires a corrupted store.
- **At-rest encryption documentation** — the user's responsibility, already stated.
- **Library-level retry removal** — the library retries cluster communication by design; the finding was about *error classification*, which is kept as A-none (see B1 for the transport case).

## G. Corrections made during the audit

Reviewer claims that contradicted the source, and were corrected:

1. **`src/identity/lifecycle.rs:633` `RETENTION`** is a test fixture inside `#[cfg(test)] mod tests`, not a retention mechanism.
2. **`src/storage/receipt.rs:42` `RETENTION_SWEEP_BOUND`** is a scan/latency bound driving cursor rotation, not a retention trigger; the trigger is `receipt_retention`.
3. **`src/routing/table.rs` route-table capacity** is caller-derived from `TraceMetadataLimits::active()`, not hardcoded.
4. **`TransportSelector::Builtin | Custom`** — I initially framed the addressing split as an official/user asymmetry. It is not: `Endpoint::host()` is `pub(crate)` but `validate_opaque` (`endpoint.rs:457-472`) accepts any printable ASCII except `?` and `#`, so a custom provider's opaque address **can** carry `host:port`. The split is URL-authority versus opaque grammar, which is a real syntactic difference. The actual asymmetry is the **trust class** (B1).
5. **`TransportTrust` is not cosmetic** — it selects which rustls `ClientConfig` is built (`src/transport/tls.rs`: `Merge => merge_client_config()`).
6. **`Lane` is correctly closed as a *set*** — the lane code is a wire field both nodes must agree on, and every lane's rows live in crate-owned store namespaces. The defect is the *factoring*, not the closedness.
7. **`LaneId` tuple-registry suggestion is insufficient** — it reduces 5 sites to 2 but leaves both in other modules' files. The owner rejected it.
8. **`is_removal` on `ResourceChange` vs `ResourceVersion`** — different semantics; only the former is redundant.
