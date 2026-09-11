# radiata Verified Findings (G3-era review, 2026-08)

> **G9 review 2026-09-02 (main @ 8135662, four fresh reviewer lanes):
> resources/selector, identity custody, runtime facade, cross-cutting +
> tests.** G9 verdict **PASS-WITH-GAPS** → remediated to **PASS** (same
> day; all seven lanes re-run PASS, Q 550/0 clean tree ×5). All seven
> resource/authorization/leave/facade verify lanes PASS;
> full Q green on a clean tree (550 passed, 0 failed). Every SC-G09
> acceptance phrase mapped to a proving test except the gaps below; no P0.
>
> ### P1 (fix before attestation)
> 1. revocation.rs:88-116 — the revoke transaction pins only the
>    revocation key, not the trusted binding's digest: a concurrent
>    binding change between snapshot and commit lets the revoke commit
>    against a stale key and silently miss. Fix: add `Check …
>    Exact(binding digest)` as deletion.rs:93-101 does.
> 2. revocation.rs crash matrix + leave.rs crash matrix are JSON-only;
>    SC-G09-P0-14 says "JSON/redb" and P0-21 says "both backends". redb's
>    select_crash_point exists (storage/redb/store.rs:39) and is used by
>    the migration/mixed lanes — add the redb arms.
> 3. supervisor.rs:571 — `forwarding_capacity` is wired to
>    `trace_metadata_limits().active()`: two subsystem bounds keyed off one
>    unrelated config knob. Give forwarding its own config knob.
>
> ### P2 (evidence gaps + should-fix)
> - No isolating test for revoked-issuer raw-grant rejection
>   (session/driver.rs:489) or responder-side join-admission revocation
>   (driver.rs:245); tests/revocation.rs rejoin assertion accepts three
>   kinds and cannot attribute the failure.
> - Snapshot binding adoption of a revoked issuer's member (the
>   "independently trusted binding" half of P0-14) unasserted.
> - trust.rs adopt_binding_ctx never consults local revocation — the
>   never-re-adopt property is structural, not enforced.
> - leave::execute refuses a pending intent; a mid-phase live-process
>   failure leaves the node serving with no way to re-drive (restart only).
> - supervisor.rs:1600 — `removal_rank + 1` unchecked add (a synced
>   u64::MAX rank panics debug / wraps release).
> - commit_record_ctx / commit_removal_ctx share an identical prepare/
>   commit tail (store.rs); put_resource/remove_resource repeat the
>   sign-then-seal pipeline (supervisor) with a double body encode.
> - Selector::parse / parse_predicates loop written twice (routing.rs).
> - namespace() helper duplicated 8×; three copies omit the
>   CATEGORY_METADATA check the canonical records::metadata_namespace does.
> - lifecycle.rs:518-661 test harness duplicates identity::testing
>   (FaultingFactory/CommitFault already shared).
> - Integration harness duplication: join_with_retry 3×, delete-capable
>   key providers 2× (LeaveKeys/LeaveCapableKeys ~150 lines each because
>   common::ScriptedKeys::delete hard-fails), Node/start_node/listen 7×,
>   open_store 10×, resource sign fixture 5×, trust helper 2×,
>   PutResource helper 4×. One `common::NodeHarness` + `ScriptedKeys::
>   deleting()` collapses most of it.
> - E2E-08 key-intent clause attested only jointly across tests/leave.rs
>   (deleted_count) and tests/facade.rs; add the deleted_count assert to
>   e2e08 itself.
>
> ### P3 (hygiene)
> ResourceUri duplicates LabelValue's bound (share a bounded-text
> constructor); two distinct `ResourcePage` types (rename the internal one
> ResourceRecordPage); crash-matrix LAST_POINT=13 pinned despite its own
> comment; cursor-tail `next.map(PageCursor::new)` repeated 4× (paging
> helper); pending-acks drain written twice (run_session end + retire);
> DispatchCommand/DispatchQuery impl boilerplate (macro optional);
> page_sessions silently drops unresolvable feature digests; lib.rs and
> extension_registry.rs stale module docs; record_rejection magic
> usize::MAX capacity; leave_cluster retires sessions without
> SessionChanged (document the asymmetry); tests/leave.rs
> `former_handle_bytes` holds a NodeId; fixed-sleep absence windows;
> verify-resource-selectors label naming; retention tombstone-GC resurrection window
> deserves one doc sentence; ResourceVersion::from_record/CommitReceipt
> dead_code payloads are a declared G10 wiring obligation.
>
> ### Remediated 2026-09-02 (same day)
> - P1 revoke TOCTOU: the revoke transaction now pins the trusted
>   binding's digest (58b5041); fresh trust-binding adoption for a
>   locally revoked identity is refused while re-delivery stays
>   idempotent; removal-rank increment fails closed on saturation.
> - P1 JSON-only matrices: both revocation and leave subprocess matrices
>   are backend-parameterized and run against JSON (13 boundaries) and
>   redb (6) (cffeb34).
> - P1 forwarding miswire: the forwarded-route bound is its own
>   decision-register constant (forwarding.route-capacity-default),
>   independent of the trace metadata budget (c3b5851).
> - P2: leave::execute re-drives a pending intent to completion;
>   E2E-08 asserts the key-custody clause in-file; the delayed-content
>   lane asserts the revoked writer's binding adoption on the third
>   member; join_with_retry single-sourced in tests/common;
>   sign-and-seal single path (sign_with_provider/seal_prepared);
>   shared conditional-put tail; selector parse loop factored;
>   namespace construction single-sourced through
>   records::metadata_namespace (category check restored).
> - Still open (recorded, own tickets): common::ScriptedKeys::deleting
>   + NodeHarness consolidation (test-only), raw-grant rejection
>   isolation test (needs a post-leave rejoin path), runtime_seed
>   consumption, lib.rs/extension_registry doc refresh, dispatch-impl
>   macro, retention tombstone-GC doc note.
>
> ### What is healthy
> EventHub design (per-subscription channels, poison-recovering lock,
> prune semantics) matches its no-replay tests; the removal
> precondition/tuple-win layering is correct under one snapshot; the
> selector parser bounds and escape round-trips were hand-traced and are
> property-pinned; the revocation/leave crash matrices reconcile
> decisively at every point; the verify-authorization-revocation namespace-catalog diff
> guard is a strong single-source check; no unsafe, no unwrap/expect in
> production, no stringly-typed registries found in any lane.
>
> **G8 review 2026-08-30 (main @ a6f9b3e, four fresh reviewer lanes +
> orchestrator):** G8 verdict **PASS**. All five storage verify lanes PASS;
> every SC-G08 acceptance phrase mapped to a concrete test (no unmapped
> phrases). Zero P0, zero P1 across all four lanes. All cited P2s
> spot-checked.
>
> **Remediated 2026-08-30 (same-day pass, all batches + full gates):**
> fixed: trust-cursor fail-open (strict parse, typed InvalidInput) +
> clamp(1,64)→MAX_VIEW_PAGE_ITEMS; receipt.rs reference-state read +
> audit preamble ×4 → load_reference_state; migration domain strings
> + modern-v1 literal ×5 → consts, stamp_base/edge_transaction_id
> share migration_transaction_value; txn-id helper ×6 → test_util;
> complete_capabilities → helpers::required_capabilities;
> StoreNamespace::new made infallible (api-manifest amended + hashes
> re-pinned by explicit decision); CleanupPlan enum → (bool, ops);
> json needs_commit_barrier precomputed + hex::decode_array;
> resource record/live alias collapse + async factory;
> alive-peers ×4 → sync_common::alive_peers; join/member session-
> registration tail → keep_outbound_session; _runtime_seed kept (the
> G1 lifecycle test pins the startup entropy budget — deliberate, not
> dead); packet channel built at the builder (no Option/unreachable);
> SessionPacketContext built via one supervisor helper;
> apply_metadata_patch moved to membership.rs; PatchParts struct;
> PageSpec::build; fixed_bytes shared in error.rs; golden() → hex::decode;
> OFFER_CBOR_LIMITS/ADR0002_BODY_BYTES → protocol::CONTROL_CBOR_LIMITS
> + protocol::ADR0002_BODY_BYTES; TagText trait deleted; FeatureTag::domain()
> replaces tag_domain text-splitting; builtin_definitions hoisted out of
> the reserved-namespace loop; extension test fixtures shared via
> offer::fixtures; trust snapshot key width single-sourced
> (REVISION_KEY_DIGITS + strict length check); decode_grant_payload →
> decode_canonical_strict; GenerationId::from_bytes; registry dup cfg
> removed + BUILTIN_TRANSPORT_WSS const; retire_session doc fragment
> fixed; read_descriptor_ctx delegates; ack_error catch-all → internal
> fail-closed.
>
> Deferred (architectural, own tickets): session/stream.rs file split
> (TODO M6 routing), RouteState/TracePhase merge, dual-shape decode
> helper, builder WSS→NodeConfig selection, driver clock injection,
> ws.rs Option SPKI, Discovery trait gating, engine.rs test split,
> membership/sync trust logic move, trace.rs code tables, trust keyset
> cursor, records.rs canonical_record! macro.
>
> **Delivered in G8 (verified from evidence, not commits):** all-family
> metadata storage contract driven unchanged across JSON/redb/reference
> providers (`contract/reference.rs::run_storage_contract`); namespace
> literals single-sourced in `families.rs` and statically enforced by
> verify-storage-contract's rg+diff guard; redb adapter feature-gated with static
> isolation checks (cfg gate, api-manifest redb-type grep, powerset via
> pinned cargo-hack 0.6.45); redb crash matrix at 6 commit-path points
> (begin→conditions→mutations→revision→receipt→durable-commit) with
> parent reopen asserting exact old-or-new; migration graph validation
> + JSON/redb interruption + replay idempotence + older-reader/digest
> fail-closed lanes; mixed JSON/redb convergence + graceful/killed
> restart E2E (mixed_e2e.rs) = E2E-07.
>
> ### G8 P2 hotspots (verified, none block the gate)
> - storage/receipt.rs:212-224/280-292/341-352/592-612 — live-marker +
>   head/edge/anchor read + audit preamble repeated 4×; extract one
>   load_reference_state helper.
> - Test txn-id helper `txn_{index:021}` duplicated 6× (test_util.rs:26,
>   contract/helpers.rs:99 AND :128 same-module, tests.rs:538,
>   redb/crash.rs:44, redb/tests.rs:112); complete_capabilities
>   byte-duplicates contract/helpers required_capabilities.
> - storage/migration.rs:199/:299 inline `migration-transaction-v1`
>   domain string ×2 and `migration/modern-v1` literal ×5 in tests —
>   must stay byte-identical forever; promote consts.
> - provider.rs:364 `StoreNamespace::new` returns Result that can never
>   fail — vestigial `?` at every caller.
> - MetadataStore god-type across mod.rs/receipt.rs/pending.rs sibling
>   impl blocks reaching each other's private helpers; split state.rs
>   next time storage grows.
> - json vs redb adapters necessarily duplicate commit check ordering
>   (receipt replay→digest→base→conditions→apply→bump); parity held
>   only by shared contract + crash matrices — document the order in
>   the Storage trait docs.
> - runtime/supervisor.rs:1131 `clamp(1, 64)` ignores
>   paging::MAX_VIEW_PAGE_ITEMS (drift already happened); :1135-1139
>   trust cursor `unwrap_or(0)` fails OPEN (silently restarts page at
>   offset 0 on a malformed cursor — public-behavior item, fix first).
> - supervisor.rs:84 `_runtime_seed` — RESOLVED as deliberate: the G1
>   lifecycle test pins the 32-byte startup seed draw; packet_tx Option
>   fixed by building the channel in the builder.
> - LESSON: storage read order is OBSERVABLE (fault-injecting providers
>   pin exact per-site read sequences, incl. interleavings). Read-path
>   dedup must preserve per-site order: load_reference_state takes an
>   edge-token mode; the read_descriptor_ctx delegation was reverted.
> - Carried from earlier gates, still open: OFFER_CBOR_LIMITS is the
>   de-facto crate-wide control CBOR limit but lives in offer.rs
>   (identity/trust.rs + 6 more modules reach into protocol::offer);
>   fixed_bytes::<N> helper triplicated (handshake.rs:839,
>   records.rs:126, storage/pending.rs:775); identity/records.rs
>   (2228 ln) nine record types repeat Wire/encode/decode scaffolding
>   (canonical_record! macro candidate); node/builder.rs:52-71 WSS
>   hardcoded as sole transport (registry decorative at node level);
>   session/stream.rs (2068 ln) queue/lifecycle/pump/route in one file
>   with TODO(M6) routing debt; alive-peer enumeration 4× (sync_common
>   :37 declared single-source, forward.rs:298, supervisor :941/:1268);
>   trace.rs:70-139 hand-maintained 22-entry ErrorKind↔code tables
>   with lying `Option<u8>` signature; membership/sync.rs holds trust
>   refresh/anchor logic; supervisor.rs:1185-1236 descriptor patch
>   merge rules inline instead of membership.rs.
>
> ### G8 gate record
> - verify-storage-contract, verify-redb-adapter, verify-redb-integrity,
>   verify-storage-migration, verify-mixed-storage: PASS (ran locally 2026-08-30).
> - SC mapping: P0-01/02 contract+unknown.rs tests; P1-03 capability
>   refusal (contract unknown.rs:80 + redb tests.rs:43); P0-04 redb
>   contract parity; P0-05 static isolation checks in script; P1-06
>   cargo-hack each-feature pinned 0.6.45 (also CI); P0-07 crash
>   matrix 6 points; P0-08 concurrent-commit-once + digest fail-closed;
>   P0-09 receipt_refs.rs owner/intent/cleanup lanes; P0-10..12
>   migration registry/interruption/replay/reader lanes; P0-13/14
>   mixed_e2e convergence + graceful/killed restarts; P1-15 powerset
>   + CI lanes in verify-mixed-storage; E2E-07 = mixed_e2e lanes.
>

> **G7 re-review 2026-08-25 (main, four fresh reviewer lanes +
> orchestrator):** G7 verdict **PASS-WITH-GAPS**; all six wall-clock/resource verify
> lanes PASS; Q suite green on rerun (first run had one parallel-load
> flake: routed_packets handshake `AuthenticationFailed: handshake
> closed`, 3/3 green in isolation — harness lacks connect retry).
> All P0/P1 findings spot-checked against source.
>
> **Remediated 2026-08-28 (branch fix-g7-review-findings, 10 commits):**
> both P1s, all P2 hotspots below, and the evidence gaps (P0-18 sample
> + P0-11 restart/readdress lane, wired into verify-resource-sync/verify-merge-scale-slo).
> Residual decisions: E2E-06 real-session resource writes need the G9
> facade (no pre-G9 write path exists); stream.rs clock_second/millis
> aliases kept (single-file readability, no longer duplicated); member
> first-seen descriptor must be revision 1 — the SLO sample waits for
> rev1 convergence before bumping.
>
> ### P1 — verified
> 1. session/stream.rs:1118 unbounded `pending_acks` HashMap; entries
>    removed only on ack/session end; liveness_observer (:613) exempts
>    sessions with pending work from idle close → a peer that accepts
>    opens but never acks keeps sessions alive while origin memory grows
>    linearly with sends. Cap concurrent pending admissions per session
>    (typed Overloaded) and/or deadline-bound the has-work hold-off.
> 2. Cursor-pagination loop ×5 with ALREADY-DIVERGENT end-of-stream:
>    routing.rs:377-417 peeks one extra entry (honest has_more);
>    supervisor.rs page_members/page_topology use `items.len() < limit`
>    heuristic that can emit a trailing cursor whose next page is empty;
>    membership/page.rs + resource/page.rs emit_page_ctx are two more
>    copies. Extract one shared scan_paged helper.
>
> ### P2 hotspots (top of backlog)
> - membership/sync.rs ↔ resource/sync.rs systemic duplication:
>   drain_body+MAX_SYNC_BYTES, alive_peers/peers_fingerprint,
>   send_payload — security-relevant validation paths fixed twice.
> - Page envelope codec duplicated membership/page.rs:46-146 vs
>   resource/page.rs:50-121 (capacity/canonical/fingerprint).
> - Subprocess crash-matrix scaffolding triplicated (json/crash.rs,
>   resource/crash.rs ×2 lanes, json/native.rs) with hardcoded
>   crash-point numbering.
> - resource/retention.rs sweep_removed_ctx materializes every removal
>   record then applies cap post-hoc, O(n·m) freshness filter, full
>   namespace scan every 2s unconditional — violates boundedness rule
>   at the 262,144-record cap (contrast trace lane's counter gate).
> - transport→session domain cycle: registry.rs:206,236 calls
>   session::handshake_frame_rules; frame rules belong in protocol.
> - node/builder.rs:48-59 WSS hardcoded as dial/listen transport;
>   registry extensibility decorative at node level.
> - supervisor.rs recovery_tick N+1 snapshot per unreachable member.
> - simulation/* incl. artifact fs capture compiles into non-test builds.
> - storage/receipt.rs:412 outcome classified by operations.len()==2.
> - Magic literal 64 in supervisor paging + neighbor degree vs named
>   consts; "limits" category literal compared in 3 places; tag.rs:139
>   hardcoded reserved (domain,category) pair duplicating feature.rs
>   policy; records.rs record_digest duplicates signature::body_digest;
>   handshake decode_wire reimplements decode_canonical_strict.
>
> ### Evidence gaps for the G7 gate record
> - SC-G07-P0-18 (revised 16-node SLO workload covering admission+
>   packets+node revisions+resources ≤10000 ms): NO test exists;
>   resource/e2e.rs:386 comment defers it to a dedicated G10 harness.
>   Either write the G7 sample or amend the catalog/plan row.
> - E2E-06 covered at store+sync layer only (resource::e2e); no real-
>   session/public-facade resource convergence integration test exists
>   in tests/ (membership_sync covers metadata but not resources).
> - SC-G07-P0-11 restart/readdress mid-resource-repair exercised only
>   indirectly via partition-healing e2e; no dedicated case.

> **G6 re-review 2026-08-25 (main @ b9cd349, five fresh reviewer lanes +
> orchestrator):** G6 verdict **PASS-WITH-GAPS**; Q suite and all five
> routing verify lanes (verify-route-authorization, verify-routing-trace,
> verify-packet-forwarding, verify-stream-admission, verify-route-completion)
> green; planning validator green (69/226/10/29).
> All P0/P1 findings below spot-checked against source. Hotspots:
>
> ### P0 — leftover debug output in the G6 hot path
> - `eprintln!("DEBUG …")` ×10: session/forward.rs:70-81,101,197;
>   runtime/supervisor.rs:771,840,871; session/stream.rs:1084.
>   Prints NodeIds/routes to stderr on every routed open/pump. Delete or
>   convert to `tracing::trace!` before gate closure evidence freeze.
>
> ### P1 — should-fix (all verified)
> 1. membership/page.rs:74 `descriptor.encode().unwrap_or_default()` —
>     swallowed encode failure ships an empty descriptor that fails remote
>     decode; propagate the error.
> 2. identity/trust.rs:585 silent `continue` on malformed binding rows +
>     magic binary format (`len<33 || bytes[0]!=1`) + stringly snapshot key
>     parsed back with `rsplit('/')…unwrap_or(0)` (trust.rs:472,512) —
>     violates fail-closed rule 8; use a schema-tagged CBOR record and a
>     binary composite key.
> 3. Canonical decode re-encode check inconsistently applied: present in
>     identity/records.rs:98, protocol/handshake.rs:841, routing/trace.rs:285,
>     protocol/offer.rs:134, storage/pending.rs:379; ABSENT in
>     membership/sync.rs:89 and page.rs:86. Security-adjacent divergence —
>     add one `decode_canonical_strict` in protocol/cbor.rs.
> 4. transport/connection.rs receive loop duplicated verbatim between
>     Connection::receive (:223) and ConnectionReader::receive (:366), send
>     likewise (:197 vs :329); already drifted (trace logging only in one).
> 5. Forwarding-table take/across-await/restore race: session/forward.rs
>     relay_chunk (:113-130) removes the hop during unbounded backpressure
>     await; close_for_peer (:160-180) misses it and restore can resurrect a
>     terminated route (leak; downstream never gets end).
> 6. runtime/supervisor.rs member()/page_members() hand-roll descriptor→
>     MemberView mapping twice (carried over from 2026-08-24 backlog — still
>     unfixed at G6).
>
> ### Evidence gaps for the gate record
> - SC-G06-P0-18: trace retention tested with monotonic forward clock only;
>     no rollback/freeze case in routing/trace.rs (candidates.rs/recovery.rs
>     have the pattern to copy).
> - SC-G06-P0-13/14: no wire-level duplicate-open consumer-twice test; ACK
>     "admission-only" semantics asserted only implicitly via E2E ordering.
>
> ### Recurring cross-gate patterns (fix once, everywhere)
> - epoch-millis conversions duplicated ≥4 sites; CommitOutcome four-arm
>     mapping ×3-4; AckStatus↔ErrorKind mapping ×3 with catch-all
>     StreamInterrupted in packet/mod.rs:573; trace kind_from_code silently
>     maps unknown codes → Internal (trace.rs:136) contradicting its own
>     fail-closed doc; host-clock `now_millis` bypasses injected WallClock
>     (stream.rs:1363); god-functions run_outbound (~200 ln), sync_tick,
>     Supervisor::new, send_packet.

> **Post-closure spot review 2026-08-25 (main @ cc984d8, two fresh
> reviewer agents + supervisor-run verify lanes):** evidence chain
> COMPLETE — all five routing verify scripts (verify-route-authorization,
> verify-routing-trace, verify-packet-forwarding, verify-stream-admission,
> verify-route-completion) PASS locally; task/scenario/
> impact registration consistent; all nine development-gates G6 Verify
> bullets covered. Code verdict NEEDS-WORK → remediated same day:
>
> ### Fixed in the remediation pass
> 1. relay_chunk dropped the hop's relay lock before its backpressure
>    await (contradicting its own comment), letting a concurrent
>    close_for_peer enqueue End ahead of an in-flight chunk — strict
>    chunk-then-end order (SC-G06-P0-09) could break under load. The
>    guard now spans encode + send_waiting; regression test
>    closing_session_end_queues_after_the_last_in_flight_chunk pins it.
> 2. ForwardingTable had no concurrent-route cap: any authenticated peer
>    could open unbounded trace_ids. New routes beyond
>    TraceMetadataLimits::active() now fail closed with AckStatus::Overloaded.
> 3. MemberView construction de-duplicated: membership::member_view now
>    takes the ConnectivityStatus directly and routing.rs candidate reads
>    plus supervisor label mutation flow through it (was three inline
>    constructions contradicting the "single mapper" doc).
> 4. ParserLimits TODO(G6) resolved: NodeConfig::parser_cbor_limits feeds
>    every packet-frame decode (decode_open/chunk/end/ack take limits);
>    public knob is no longer write-only.
> 5. Terminal trace persistence bounded by a 16-permit semaphore inside
>    TraceSink; retention-sweep skip-gate counter now tracks successful
>    persists minus sweep removals instead of counting total packets ever.
>    take_existing alias folded into take.
>
> ### Still open (carried)
> - Policy invoked before envelope validation in forward::open (minor).
> - SC-G06-P0-18 rollback/freeze clock cases and wire-level
>   duplicate-open consumer-twice test remain unwritten.
> - Fresh backlog (2026-08-24) P1 items unchanged.

> **Re-review 2026-08-24 (main @ post-ADR-0008, four fresh agents +
> orchestrator):** G5 verdict PASS-WITH-GAPS; Q suite and all twelve
> g04/g05 lanes green. Session-trust migration (ADR-0008) verified
> consistent code-to-doc. New backlog below supersedes the remediation
> order at the bottom of this file.
>
> ## Fresh backlog (2026-08-24)
>
> ### P1 — should-fix
> 1. Revision-gap convergence contradiction: the store accepts only
>    exact-next revisions, so a peer that misses one descriptor revision
>    diverges permanently while page.rs:6-8 / SC-G05-P0-07 claim repair.
>    Fix: relay intermediate revisions, accept strictly-greater remote
>    applies (tombstone rule still blocks downgrades), or amend the
>    scenario text.
> 2. `RecoveryPolicy.neighbors` dead field; `plan_neighbors` has no
>    runtime caller; file-level `allow(dead_code)` masks both. Wire or
>    delete, and narrow the allow.
> 3. SC-G05-P0-22 counting-transport observation absent (dial path
>    bypasses the transport registry); P0-29 SLO sampled at eight nodes
>    vs sixteen-node catalog text — sample a sixteen-node run or amend
>    the catalog.
>
> ### P2 — nice-to-have
> - Supervisor recovery tick still scans the full binding namespace once
>   (needs the member set; acceptable) — sync.rs sites resolved 2026-08-24
>   (early-exit count + count short-circuit).
> - RESOLVED 2026-08-24: snapshot revisions pruned on persist;
>   paged_trust_ctx streamed without whole-population materialization.
> - Page sends now fingerprint-gated (content + peer set) with a 32-tick
>   resend backstop; steady-state anti-entropy traffic is zero.
> - Multi-thread packet race: NOT reproducible after the wait_for harness
>   fix (17/17 green x5 under multi_thread); closed as harness bug.
> - Supervisor `member()`/`page_members()` hand-roll descriptor paging;
>   expose a bounded paged read on the membership store instead.
> - `sync_tick` two-regime god-function with duplicated peer-dispatch
>   blocks; split around the membership-regime check.
> - Test-only factory-handle wrappers behind allow(dead_code)
>   (read_descriptor/store_descriptor/emit_page/apply_page/trust
>   wrappers) — move to test support; drop the 10s magic timeout.
> - Binding raw-byte format sniffed in persist_binding_ctx vs decoded
>   IdentityBindingV1 in adopt_binding_ctx — decode both.
> - Snapshot key `{issuer}/{revision:020}` written/formatted in one
>   place, reverse-parsed in another — extract an encode/decode pair.
> - Multi-thread-runtime packet-delivery race was worked around by
>   keeping join lanes current_thread (2bc3b38); the underlying race is
>   UNINVESTIGATED — reproduce with multi_thread attributes before G6.

Verified against the codebase on 2026-08-22 (main @ c8f0394). P1 = should-fix,
P2 = nice-to-have. All line numbers are from that revision and drift.

## Resolution status (updated after the P1+P2 fix pass, 2026-08-22)

- **All seven P1 findings are fixed** (base62/hex/condition sharing, error
  projection, test harness consolidation, typed-bus dispatch, constant
  single-sourcing).
- **All twenty P2 findings are fixed**, including two that grew beyond the
  original plan: `connect_member` now pins member reconnects to the
  join-time leaf SPKI (the join hint carries it; documented as a wire
  format addition), and hostname/IP grammar is delegated to `domain` 0.11
  and `std::net` with lowercase normalization for storage/comparison.
- `docs/implementation-plan.md` records the `domain` dependency amendment;
  `docs/roadmap.md` lists which gate consumes each reserved config field.
- Remaining known follow-ups: M6 moves the routing-domain code out of
  `session/stream.rs` (marked `TODO(M6)`); M9 wires `NodeHandle::events`
  (marked `TODO(M9)`); G5 wires the anti-entropy config fields (marked
  `TODO(G5)`).

## G4 status (2026-08, gate in progress)

- T-G04-01..06 all registered with verify lanes (`verify-transport-*`,
  `verify-session-*`, `verify-identity-trust`, `verify-reconnect`), all
  lanes PASS on the working tree; full suite 392 tests, zero warnings.
- Delivered: transport/discovery registries with the built-in WSS registered
  by default; identity-scoped endpoint candidates with wall-clock expiry;
  deterministic crossed-dial session ownership with drain; bounded session
  queues (count+bytes) and wall-clock liveness (idle + keepalive); signed
  trust snapshots with fail-closed verification, durable persistence, and
  paged observations; credential-free member reconnect (E2E-01/02/03).
- Handoff to G5: the member-to-member trust propagation protocol (SC-G04-P0-17/18
  dissemination and offline catch-up) needs the membership sync/anti-entropy
  channel that G5 builds; the G4 components it consumes (trust store,
  binding persistence, member-mode reconnect) are in place and unit-verified.
- TODO markers added for G4-06 wiring that the reconnect E2E consumes:
  `WssConnection::into_split/inner/join_hint`, `WssTransport::with_hint`,
  `Connection::ping/pong_last_seen` pre-split forms.

## G4 fresh re-review (2026-08, four independent reviewer agents)

Fresh-context reviewers confirmed the G4 evidence (392 tests, six verify lanes)
and surfaced four P1 bugs, all fixed and committed (364c564):

1. **Dead session entries blocked reconnection** — the crossed-dial
   replacement decision ignored `previous.alive()` and teardown never removed
   the table entry, so a reconnect from the non-winning direction was dropped
   at both endpoints forever. Fix: only live entries compete under the
   ownership rule; teardown removes the registered dead entry.
2. **Bounded queue admission was racy under concurrent senders** —
   check-then-act on count/bytes could exceed the byte budget. Fix: one
   mutex-protected critical section for admission+reservation.
3. **`latest_snapshot` ignored the issuer** — it scanned the whole namespace
   and picked the max revision across all issuers, so another issuer's higher
   revision shadowed the trusted one. Fix: scan with the issuer key prefix.
4. **Keepalive never observed the pong** — the timeout measured time since
   the locally-sent ping, closing a peer that answers every ping but sends no
   binary traffic. Fix: reflect peer pongs into the injected clock's activity
   mark and require no response for the full deadline.

P2 fixes (3e11e46): PageCursor/EndpointCandidate manifest accessor names,
single-parse typed transport tag, SessionPolicy::from_config single-sourcing,
writer-failure session teardown, snapshot_digest delegation.

Deferred with TODO markers (G4-06 wiring / G7): `WssListener::close` is a
no-op until the supervisor consumes the registry listener (needs a shared
cancel signal); `Supervisor::new` keeps four `unreachable!` invariants;
`WallClock` still lives in `storage::receipt` (move to node when G7 lands);
transport pong timestamps use host seconds while session liveness uses the
injected clock (reconcile units when G4-06 wires keepalive for real).

Health check outcome: the G4 transport/session/trust additions are
structurally sound — open registries per manifest, injected wall clock, no
production unwrap/expect/unsafe, and the crossed-dial ownership rule is a
total order verified by unit and integration tests.

## G5 status (2026-08, gate in progress)

- T-G05-01..05 (descriptors, pages, neighbors, recovery, seeded sim) all
  registered with verify lanes (`verify-membership-*`), all lanes PASS; full
  suite 399 tests, zero warnings.
- Delivered: owner-signed node descriptors with strict-next revisions and
  signed removal markers; bounded anti-entropy pages (emit/apply with
  fail-closed dishonest-page rejection); deterministic sparse neighbor
  planning with a maintenance limiter; the continuous recovery state
  machine (activation/backoff/fan-out/quiesce/reactivate/immediate); a
  seeded recovery simulation that replays exact decisions.
- Handoff for the remaining batch: T-G05-05's 16-node facade E2E
  (SC-G05-P0-21/22) and T-G05-06 readiness/scale closure (SC-G05-P0-23..29:
  15+1 readiness, exact 32-session/degree-4/diameter-3 topology, membership
  failure matrix, 10s metadata SLO, 1,024-node trend) need a 16-node
  facade harness and public topology/membership views; the controller,
  planning, and page components they consume are in place and unit-verified.
- Wired from NodeConfig: `anti_entropy_interval` (page ticks) and
  `RecoveryConfig` (recovery policy) remain TODO(G5) until the facade
  harness consumes them.

## G5 batch 2 (public views + 16-node core, 2026-08)

- Public membership/topology views shipped per the api manifest:
  `PageSpec`, `MemberView`, `MemberPage`, `TopologyEdgeView`,
  `TopologyPage`, `ConnectivityStatus`; `GetMember`/`PageMembers`/
  `PageTopology` queries through the typed bus.
- A node lazily publishes its own signed descriptor (revision 1); views
  read the descriptor store through the metadata store and annotate
  connectivity from the session table without re-opening storage.
- A sixteen-node join harness proves all fifteen authenticated edges are
  visible through the public topology view.
- G5 is complete: the session-carried membership sync protocol streams
  signed descriptor pages and the issuer-signed trust snapshot over
  authenticated sessions; members relay the highest verified snapshot so
  the grant set propagates across the sparse topology; the recovery
  controller heals edge loss among ever-connected members, never dials
  intentionally disconnected peers until a deliberate reconnect, and
  quiesces at connected-path connectivity.
- Sixteen-node E2E passes: reciprocal trust (15 and 16), exact 28-edge
  induced CQ4 and exact 32-session/degree-4/diameter-3 topology, node 15's
  grant on all members, descriptor readiness, partition healing, and the
  metadata SLO lane (8-node: <10s). A 1,024-node functional/trend unit
  lane covers the seed.
- Fresh three-reviewer pass (2026-08-22): P1 recovery-pending monotonic
  counter fixed (atomic in-flight bound released by the detached dial);
  core protocol registration moved before ready (typed conflict, no
  spawned-task panic); SLO lane times the full admission window and the
  harness cross-checks exact NodeId-to-key and descriptor-digest agreement;
  failure-matrix header/scenario citations narrowed to what is tested;
  single canonical descriptor decoder; shared trusted-anchor resolver;
  snapshot version and binding key substitution fail closed; the driver
  threads the page cursor across ticks so descriptor sync converges beyond
  sixteen members; plan_neighbors walks the cycle without a whole-
  population allocation; the recovery simulation is cfg(test)-gated.
- Residual gaps recorded: the counting-transport observation (SC-G05-P0-22)
  is unit-only (the dial path does not consume the transport registry);
  the failure matrix exercises duplicate delivery and partition healing
  (reorder/endpoint-change/restart covered by descriptor-store unit tests
  and the secure-join restart lane).

## Historical findings (pre-fix baseline)

## P1 — should-fix (verified in real code)

1. **TypeId if-else "typed bus" dispatch** — `src/node/handle.rs:64-120`:
   `command()` has 7 sequential `if id == TypeId::of::<X>()` branches and
   `query()` has 4, using `downcast_input`/`cast_output` `Any` machinery
   (handle.rs:132-150). `Command`/`Query` are sealed marker traits with zero
   methods (`src/operation.rs:9-16`), so the compiler cannot enforce
   exhaustiveness: a new command compiles and silently becomes `Unsupported`.
   Fix: add `async fn run(self, runtime: &RuntimeClient) -> Result<Self::Output>`
   to the sealed traits (impl per command), or a closed enum bus.
2. **Hex encoding duplicated in production** — `src/identity/deletion.rs:285-296`
   (`deletion_purpose` hand-rolls nibble→hex) vs `src/storage/json/document.rs:241`
   (`hex_encode` lookup table). Same lowercase-hex of a byte slice. Test-only
   copies in 8+ files (identity/testing.rs:583, lifecycle.rs:861,
   protocol/{credential,feature,handshake,selection}.rs, storage/pending.rs:840).
   Fix: one `crate::hex` codec (encode+decode); `Digest` could render its own hex.
3. **base62 ID validation duplicated** — `src/identity/id.rs:149-166`
   (`validate_id` + `is_base62`) vs `src/provider.rs:654-670`
   (`validate_key_operation_id` + identical `is_base62`). Fix: one shared
   `validate_prefixed_base62(value, prefix, context)`.
4. **Oracle-dup hazard: condition evaluation twice** —
   `condition_matches`/`expectation_matches` byte-identical in
   `src/storage/contract.rs:368-406` (reference oracle) and
   `src/storage/json/store.rs:487-526` (adapter under test). A bug in both
   copies cancels out and the contract can no longer catch condition
   regressions. Fix: share one `pub(crate)` definition.
5. **Mirror error enums with hand-written table** — `ErrorKind`
   (`src/error.rs:6-28`) vs `ProviderErrorKind` (`error.rs:33-49`) mapped by a
   12-arm `provider_error_kind` table (`error.rs:217-233`); each variant maps
   1:1. `ErrorKind::Revoked` has no constructor/producer anywhere. Fix: derive
   the mapping from data or collapse; remove `Revoked` until a gate produces it.
6. **Test harness duplicated** — `src/identity/lifecycle.rs:484-727`
   re-implements `SequenceEntropy`/`KeyCall`/`ScriptedKeys` from
   `src/identity/testing.rs:38-191` (drift already: lifecycle's entropy
   rejects non-16-byte fills; `KeyCall::Sign` lacks the message payload).
   Fix: parameterize `identity/testing.rs` and delete the lifecycle copy.
7. **Constant triplication** — `PENDING_NAMESPACE`
   ("radiata.woooo.tech/metadata/pending-transaction-v1") in
   `identity/testing.rs:32`, `identity/lifecycle.rs:503`,
   `storage/pending.rs:40`; built-in feature tag strings in
   `protocol/feature.rs:45-49` (private consts), `protocol/offer.rs:320-326`
   (`BUILTIN_FEATURES: [&str; 5]`), `protocol/selection.rs` tests; and
   `storage/pending.rs:789-790` re-declares `LOCAL_IDENTITY_NAMESPACE`/
   `CLUSTER_GENESIS_NAMESPACE` from `identity/records.rs:30,33`. Fix: export
   from the owner module (`feature.rs` consts `pub(crate)`; `records.rs`
   namespaces) and import everywhere.

## P2 — notable (verified)

- **`src/storage/contract.rs` is a 4124-line god file** mixing reference
  provider (32-407), contract runner (410-890), engine tests (894-1787),
  unknown-fault tests (1789-2400), receipt-ref tests (2448-3357), journal
  tests (3359-4124). Split along those seams. The reference provider is
  `pub(crate)` test-support living in production `src/` (imported by
  identity/{admission,deletion,genesis,lifecycle}.rs tests) — the
  `test-support` crate is the intended home.
- **Routing-domain logic parked in `src/session/stream.rs:421-625`**
  (`run_outbound`, `RouteTable`, `insert_route`) — roadmap assigns routing to
  its own module (M6). Mark for the move.
- **Handshake kind tables duplicated** — `probe`/`position_sender`/
  `position_arity` (`protocol/handshake.rs:802-840`) hardcode kind→position,
  position→role, position→arity that `protocol/wire.rs:33-58`
  (`HandshakeKind` registry) should own. Also `MAGIC "MRLY"` twice
  (envelope.rs:3 bytes, handshake.rs:67 text) and `BASE_SCHEMA_ID` in two
  types (wire.rs:18 u16, handshake.rs:68 u64).
- **Duplicate commit/reconcile control flow (7 copies)** —
  identity/{lifecycle,genesis,deletion,admission}.rs all repeat the
  `match store.commit() { Committed | Unknown => reconcile … | Aborted }`
  shape; `commit_admission`/`adopt_admission` (admission.rs:72-256, 272-397)
  are ~150-line god-functions sharing a skeleton. Extract a
  `commit_with_reconcile` helper.
- **String-concatenated durable purpose strings** — `purpose: String` in
  `KeyCreationIntentV1`/`KeyDeletionIntentV1` (records.rs:299-311, 372-384)
  built by concatenation at 6 call sites ("key-delete-" + hex, "admission-" +
  hex, "local-identity", "cluster-genesis"). Typed `JournalPurpose` enum
  would make them exhaustive; they become durable storage values.
- **Dead/speculative public surface** — `NodeHandle::events` returns
  `Err(Error::unsupported("node events"))` unconditionally (handle.rs:123-128)
  while `node/event.rs` ships full `EventOptions`/`EventSubscription`
  machinery; `member_client_config` (`transport/tls.rs:70-79`) is
  `#[allow(dead_code)]` with a stale "production wiring arrives with G3-04"
  comment although `connect_member` already exists; ~18 `#[allow(dead_code)]`
  accessors (Selection::features/limits, FeatureOffer::limits,
  FeatureDefinition::fingerprint, LimitWidth::U64, …) await G3-04 consumers.
- **Unwired config defaults** — `anti_entropy_interval`, `RecoveryConfig`,
  `session_queue_bytes`, `ParserLimits`, `TraceMetadataLimits.terminal/
  retention` are validated-but-unconsumed; `ParserLimits` (config.rs:101-122)
  duplicates `CborLimits` (protocol/cbor.rs:11-27) semantics. Wire them or
  delete until their gates land.
- **Stringly routing policy** — `DIRECT_ROUTING_POLICY: &str` (packet/
  mod.rs:30) compared by string at node/handle.rs:48; every other registry
  keys on typed tags. Typed `RoutingPolicy` enum or `QualifiedTag` const.
- **`hex` purpose-key loops in production** — `adoption_purpose`/
  `admission_purpose` (admission.rs:450-457, 542-549), `deletion_purpose`
  (deletion.rs:285-296), `generation_hex` (transport/ws.rs:71-77) — four
  copies of the same nibble loop with different prefixes.
- **Scenario topology defined twice** — `run_fault_matrix_seed`
  (simulation/network.rs:530-560) and `ScenarioFixture::network_fault_matrix`
  (simulation/fixture.rs:29-52) register the same 4-node/8-link matrix
  independently; renaming desynchronizes failure-artifact aliases.
- **`EventKey` redundant fields** — `ordinal`/`reorder_rank`
  (simulation/event.rs:42-57) are pure functions of `frame`; `EventPhase` has
  3 of 4 variants constructed only in tests.
- **`condition` also duplicated in receipt→pending outcome mapping (4 sites)**
  — `CommitOutcome` four-arm matches in storage/mod.rs:150-175,
  receipt.rs:496-505, receipt.rs:415-428, pending.rs:656-664.

## Healthy (do not "fix" these)

- Facade: `lib.rs` re-exports deliberately, `compile_fail` privacy doc-tests
  enforce the boundary; `extension`/`adapters` submodules are coherent.
- `extension_registry.rs` and `protocol/feature.rs` both key on typed tags —
  the approved extension pattern; the stringly `DIRECT_ROUTING_POLICY` is the
  only inconsistency.
- `protocol/cbor.rs` canonical encoding (shortest-arg, map order, depth caps,
  bounded writer) is exemplary; secrets are zeroized/redacted; constant-time
  HMAC; golden-byte fixtures pin transcripts and records.
- `#[cfg_attr(not(test), deny(clippy::unwrap_used, expect_used))]` in
  `src/lib.rs` is why production unwraps stay out; the `unwrap()`s found by
  naive greps in storage/contract.rs etc. are all test-double/test-module code.

## Remediation order

1. Shared hex codec + shared `condition_matches` + shared base62 validator +
   constant exports (kills the highest-divergence duplicates).
2. Replace the TypeId bus with per-command `run` methods.
3. Split `storage/contract.rs` along its six seams.
4. Export namespace/feature constants; de-duplicate lifecycle test harness.
5. Wire or gate the speculative public surface (events, member_client_config,
   config defaults) before 0.1.0.

---

# Round 3 — Delta audit of the post-fix segment (2026-09-11, main @ 8bee21f)

> Scope: full regression of the 2026-09-09 audit fixes (all STILL-FIXED,
> see docs/audit-findings.md §9) + deep review of the never-audited segment
> `9b23ce3..HEAD` (per-peer sync cursors, recovery seeding/forgetting,
> MemberStatus, wildcard bind, resource stamp monotonic clock, loopback
> benchmark). 4 reviewer lanes; supervisor re-verified every P1/P2 against
> HEAD source. Q suite green (614/0). Verdict for the new segment: **BLOCK**
> (3×P1, all one-line-class fixes + regression tests).

### P1 (verified against HEAD source)

1. **resource/sync.rs:229 — page fingerprint recorded on continuation
   rounds.** `state.page_fingerprint = page_fp;` runs every round; catalogs
   >1 page (16 records) record a tail-range fingerprint, so the next
   from-scratch round never matches → quiet never true → full catalog
   resend per peer per 250ms tick, forever. membership/sync.rs:720-724 does
   it correctly (record only in the `starting_round` arm) — the divergence
   is the proof. Fix: mirror membership; add a >16-record steady-state
   zero-send regression test (the existing quiet test uses 1 record).
2. **runtime/supervisor.rs:1320-1324 — issued stamp never folded back into
   `resource_write_clock`.** `fetch_max(observed)` returns `previous` but
   only stores `observed`: write#2 in one millisecond issues
   `previous+1` while the clock stays at `observed`, so write#3+ repeat the
   same stamp → digest tie-break → the writer's own later put can lose to
   its earlier one (exactly what 8bee21f promised to prevent; only covers
   the first pair per millisecond). Fix: after computing `timestamp_millis`,
   `fetch_max(timestamp_millis, Relaxed)`; add a 3-writes-same-ms strictly
   increasing test.
3. **runtime/recovery.rs:164-165 + :220 — recovery_excluded peers counted
   pending forever.** The direct-peer backfill inserts every alive-session
   peer into `recovery_history` without checking `recovery_excluded`; an
   intentionally-disconnected peer that reconnects *inbound* then loses its
   session is pending (counted) but never dialable (:220 skips it) →
   controller never quiesces, backoff pegged at max — same trap shape as
   example-findings #11. Exclusion is only lifted on outbound
   `connect_member` (supervisor.rs:1014). Fix: skip excluded peers in the
   backfill, or clear exclusion on inbound session registration.

### P2 hotspots (verified)

- supervisor.rs:1410 — remove_resource uses raw `now_millis()`, bypassing
  the monotonic issue clock (put-only invariant; rollback → removals
  fail-conflict / later puts silently Superseded).
- identity trust.rs:730,905 + records.rs:243 + cleanup.rs:363 —
  `let _ = store.commit(..)` discards CommitOutcome (Conflict/Aborted/
  Unknown treated as success) at four identity-side persist points.
- recovery.rs:174-175 + views.rs:83-84 — every 2s tick / PageMembers runs
  `usize::MAX`-cap full scans of all cleanup+leave tombstones (unbounded,
  permanent).
- views.rs:27,62 → membership/sync.rs ensure_local_descriptor — query path
  mutates the member set without MemberChanged/revision bump (revision
  contract breach + "no state transition here" doc breach + ghost doc
  param at :477-479).
- transport/registry.rs:33-34/305-310 + supervisor.rs:951-953 — close()
  contract claims it releases the bound address; the real release is the
  supervisor's abort dropping the task; both comments state the causality
  backwards. No close→rebind regression test exists.
- transport/registry.rs:183-196 — wildcard bind family chosen by *first
  resolved address*; on Windows (IPV6_V6ONLY=1) an AAAA-first resolution
  yields [::] that refuses all IPv4 dials.
- examples/cluster/src/keys.rs:95-99 — reference FileKeyProvider writes
  the secret (umask 0644) *then* chmods 0600; crash between = permanently
  wide-open key file, chmod errors swallowed. Use OpenOptions mode(0o600).
- Duplication cluster from the per-peer cursor landing (parallel state
  machines membership/sync.rs:556-601 vs resource/sync.rs:142-169, same
  32/128 cadence constants; halving ladders membership/page.rs:151-186 vs
  resource/page.rs:87-125) — extract shared PeerPageCursor into
  sync_common.rs / ladder into paging.rs.
- purpose validation remains dual (pending.rs:753-761 vs records.rs:69-78)
  and deterministic txn-id derivation is hand-rolled twice in storage
  (receipt.rs:510-523, migration.rs:230-238).

### False positive to remember

- "fmt gate red at supervisor.rs:518 (`}      Control::RemoveResource {`)"
  — rustfmt +nightly *preserves* that arm as-is (known complex-arm
  behavior); `cargo +nightly fmt --all -- --check` exits 0. Cosmetic P3,
  not a gate violation. Don't report fmt-red without running the gate.

### Healthy (new segment)

- 2026-09-09 audit fixes: all 3×P1 + sampled P2s verified STILL-FIXED with
  HEAD line evidence (retention single-transaction multi-delete; trust
  policy in identity::trust; NotTrusted propagation; Aborted→Err; rate
  limiter check-before-record; TRUST_BINDING family gone; WIPE derived
  from families; snapshot overflow isolation; liveness setter).
- LimitedWriter rewrite (cbor.rs) correct: try_reserve_exact, atomic
  reject-or-append, prefix-preserving, fully pinned by tests.
- Wildcard bind + with_port publishing shape correct (advertised host +
  bound port); teardown retry bounded; recovery seeding exclusions correct
  at seed time; MemberStatus derived from terminal records at the view
  layer only.
- Fail-closed, bounded-queue, secret-redaction and tracing disciplines all
  held across the new segment; no unsafe / prod unwrap / println anywhere.

### Lesson for the next review

- The two worst P1s (fingerprint overwrite, stamp fold-back) are *same-mechanism-two-lanes*
  drift: one lane landed the correct shape, the other a near-miss. When a
  mechanism exists in two lanes, diff the two implementations — the
  divergence is the finding.
- give each reviewer explicit "answer this question" items (lane B was
  asked to compare against the membership-side shape and found it).
