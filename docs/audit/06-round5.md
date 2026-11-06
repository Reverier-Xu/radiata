# Round 5 — Pre-0.1.0 Release Audit

Date: audit run on branch `audit-followups` at `35041c0`.
Method: quality gates + 6 parallel read-only reviewer lanes (5 module partitions with the 7-dimension rubric + 1 decisions/vision verification lane). Every high-severity finding spot-checked against source.

## Gate status

| Gate | Result |
|---|---|
| `taplo fmt --check` | PASS |
| nightly `cargo fmt --all -- --check` | **FAIL** — 9 diffs in `src/membership/sync.rs` (1) and `src/protocol/builtin.rs` (8), introduced by WP5b/WP15a. Root cause confirmed: `cargo fmt` resolves `rustfmt` from PATH (stable), so unstable options are silently ignored locally. Use `RUSTFMT="$(rustup run nightly rustc --print sysroot)/bin/rustfmt" rustup run nightly cargo fmt --all -- --check` locally; CI nightly is authoritative. |
| `cargo check --workspace --all-targets --all-features --locked` | PASS |
| `cargo clippy ... -- -D warnings` | PASS |
| `cargo test --workspace --all-features --locked` | 1123 passed / 0 failed / 26 ignored |
| ABI freeze | baseline present (`fixtures/public-api/baseline-0.1.txt`), CI `abi` job active |

## Verdict

**PASS-WITH-GAPS.** No new P0. No new correctness defect beyond what the decision record already tracks. The gap is execution: of the DECIDED dispositions in `03-decisions.md`, only A8, A14, D18 (+ E1 spot-check) are DONE; 4 are PARTIAL; ~34 are NOT implemented. Several unimplemented decisions are user-visible semantics or data-correctness items that become debt the moment 0.1.0 tags.

## Pre-0.1.0 must-land (P1, all are recorded decisions, verified unimplemented)

1. **A1 — task-output CBOR bound can overflow after the write landed.** `src/task/output.rs:33` hand-sets 16 KiB; a maximal `MemberView`/`ResourceView` (64 labels × ~384 B ≈ 25 KB) exceeds it, turning a landed write into an `Internal` failure. Implement the derived bound + round-trip test at the bound.
2. **D8 — pre-epoch wall time silently truncates to 0.** `src/time.rs:50-56` `to_millis` saturates pre-epoch to 0 and a test pins it. Merge order is timestamp-tuple-based; pre-epoch timestamps collapse onto the epoch. Unify on millis per the decision, with a pre-epoch-safe conversion.
3. **E5 — hook/reconciler nested-submit deadlock ships without the decided typed refusal.** `src/task/mod.rs:1324` documents the trap; no detection exists. A reentrant hook submit hangs the caller's write with no diagnostic.
4. **B10 — `TaskPhase` still lacks `#[non_exhaustive]`** (`src/task/mod.rs:297`). The ABI baseline is already frozen; adding the attribute after the tag is a visible ABI diff. Cheapest now, most expensive later. (B10's other four enums were partially fixed; `TransportScheme`/`TransportSelector` still miss it — recheck against the decision list.)
5. **A2 — `ReconcileDecision` has no terminal-failure variant** (`src/task/mod.rs:1337-1347`); `Err` still auto-retries (bounded), contradicting P2 (business retry belongs to the user). Also update the doc at `:1329-1331`.
6. **B1 — custom TLS-class transports still cannot dial.** `TransportTrust` (`src/transport/registry.rs:100-111`), `accepts_tls_intents` (`:361`, `:452`) alive; `Custom(_)` is always `Plaintext`. PARTIAL: `TransportCapabilities` already collapsed to `admission` and `TransportProvider::connect(endpoint)` already drops the trust param.
7. **B3 — no official load balancer.** `StreamTarget::MatchingNodes` is refused without one (`src/node/handle.rs:69`); tests still hand-write the policy. The guide sells the label-addressed data plane.

## New findings this round (not in the prior record)

### P1

- **B9 scope is wider than recorded.** `require_caller_domain` is missing on **five** seams, not four: `register_transport` (`extension_registry.rs:192`), `register_load_balancer` (`:277`), `register_next_hop` (`:314`), `register_resource_hook` (`:357`), `register_action_hook` (`:373`).

### P2

- **protocol ↔ identity conceptual cycle.** `protocol/handshake.rs:67` and `protocol/credential.rs:21` import identity-owned items, while every identity record depends on protocol CBOR plumbing. Move `identity/signature.rs`'s three domain-agnostic helpers (`body_digest`, `signature_message`, `verify_strict`) to a neutral home; identity re-exports. No wire-byte change.
- **Error-remapping discards contexts (P8).** `From<HandshakeError> for Error` (`protocol/handshake.rs:156-190`) and `SelectionError` mapping (`protocol/selection.rs:46-64`) collapse `Malformed { context }` payloads to fixed strings; the carefully threaded contexts become test-only.
- **MergeSlot::Drop leaks counters on poisoned mutex.** `identity/merge_rate.rs:325` uses `if let Ok(lock)` while the sibling stores recover with `PoisonError::into_inner` (`keys/ephemeral.rs:78`, `keys/metadata.rs:128`). One panic while held permanently inflates admission pending counts.
- **TLS composition duplicated on dial and accept sides.** `transport/tls_transport.rs:82-113` re-rolls `Connection::connect_tls_ws` (`connection.rs:182-212`); `:141-171` re-rolls `accept_tls_ws` (`:145-179`). This is the exact sequence where channel-binding drift hides.
- **Session read loop owns routing-plane policy.** The ~110-line `PacketKind::Ack` arm in `session/inbound.rs:356-460` does late-ack attribution, re-dispatch, and route-table terminal flips — contradicting the session layer's own stated boundary (`session/stream.rs:16-18`). `read_loop_frames` is ~250 lines (`:214-470`).
- **`WallClock` seam bypassed at ~15 production sites.** `time.rs:16-24` declares "every layer reads time through this trait", yet `SystemTime::now()` is read directly in `reconcile/plane.rs` (×7), `packet/mod.rs` (×4), `routing/graph.rs` (×4), `runtime/task_effects.rs`, `runtime/task_manager.rs`, `runtime/views.rs`, `session/driver.rs`, `membership/*`, `sync_common.rs`. At least one is semantic: `swept_at` (`reconcile/plane.rs:773`) feeds the reclaim predicate.
- **`alive_peers` lives in the wrong module.** `sync_common.rs:146-160`, consumed by routing (`forward.rs:223`), runtime (`packets.rs:282,339`), reconcile (`plane.rs:626`), membership (`sync.rs:252`). Move to `session::stream`.
- **Identity schema tags hand-copied in three files.** Owners `identity/records.rs:66-72`; copies `compatibility.rs:90-95,394` and `protocol/builtin.rs:129-146`. The namespace-literals guard (`tests/static_invariants.rs:78`) covers metadata namespaces only, not schema tags.
- **Storage carries reconcile-plane change detection.** `storage/mod.rs:188-241` epoch bookkeeping names "the sync driver" and per-lane watermarks. Extract a `ChangeTracker` the store composes.
- **`supervisor.rs` is a 2,637-line god-module** (dial helpers, shutdown sequencing, control loop, ~900 test lines). Split `runtime/dial.rs` / `runtime/shutdown.rs`. Related: `resolve_frozen_journal_uncommitted` is ~170 lines (`storage/mod.rs:799-968`).
- **Migration machinery is production-unreachable.** `storage/migration.rs:137-330`: zero edges, `MigrationEdge::new` is `#[cfg(test)]`, ~200 lines of edge machinery with crash-matrix tests. Honest header, but it is the one place paying the "speculative extensibility" cost. Keep-or-delete is a maintainer call.
- **A13 record now contradicts the code comment.** `routing/forward.rs:197-199` asserts "deliberately independent of the trace metadata budget" while the decision says derive it. Resolve one way.
- **C3 decision contradicts `04-pending.md` §12.** C3 says delete the `families.rs` source scanner; §12 praises the same scanner as the good precedent for the `LaneId` refactor. Resolve before B5 work copies the wrong shape.
- **A7 residual.** Mid-route re-planning can still traverse the visited chain (`graph.rs:212` skips only `settled`; `validate_planned_path` `routing.rs:736-752` ignores the visited chain), and `routing.rs:24-32` still claims loop-free "by the plan's own construction". The decision was doc-only; the doc reword has not landed.
- **Identity-internal duplication set:** adopted-binding probe ×2 (`membership.rs:371-379` vs `:514-524`); GC sweep bodies (`leave.rs:316-342` vs `cleanup.rs:481-505`); max-wins checkpoint commit ×2 in one file (`cleanup.rs:340-377`, `:410-432`); `CreatedKey` construction ×5 across `keys/*`; merge validation blocks (`merge.rs:514-569` vs `:571-660`).
- **Transport small duplication set:** trust-intent rejection ×3 (`tls.rs:84-87`, `plain.rs:88-90`, `registry.rs:447-453`); listener `close()` ×3; builtin transport tag literals scattered across three transport files instead of one `TransportScheme::builtin_tag()`.
- **Prior §D findings still open at HEAD** (verified): D4/D5 path validation ×2, D6 `deliver` god function (`reconcile/plane.rs:741`), D7 twelve `TaskResult` impls, D9 ErrorKind tables, D10 HopState/RouteContext, D11 lifecycle enums, D12 `namespaces()` ×4 (PARTIAL), D13, D14, D15, D17 g7/g9 names, C1, C2, C3. Fixed since the record: D1, D2, D3 (scan side), A3, A4, A5, A6, A9. The findings doc should be annotated accordingly.

### P3 (representative, not exhaustive)

`PageCursor::from_provider_bytes` byte-identical alias of `new` (`paging.rs:178-186`); `_permit` parameter naming lie in `identity/lifecycle.rs`/`leave.rs`/`deletion.rs`; flat-record CBOR limits restated in 4 families instead of one `FLAT_RECORD_LIMITS`; `LEAVE_ACK_WAIT` vs `SEND_ACK_WAIT` both 5 s with independent rationales; `membership/page.rs:104-131` test-only `sync` mod whose doc claims to be the production apply path; seven identical `{items,next}` page types in `view.rs`; `Error::poisoned` mapper ×8 in `error.rs:176-249`; config zero-refusal contract repeated ~20 sites; journal purpose strings in `audit.rs:75-95` should be a typed enum; `PageApply.applied` (D14) consumed by a test-only wrapper.

## Prior-audit dispositions verified DONE at HEAD

A8 (hop-attestation doc), A14 (cluster-contract doc), D18 (single record_version), E1 (present-tense docs; minor internal remnants only), plus WP16's fixes (A3, A4, A5, A6, A9, D1, D2, D3-scan-side).

## Vision coverage (P11)

| Guarantee | Status |
|---|---|
| Local write never blocks when cluster unreachable | PARTIAL — proven for descriptors (`tests/membership_sync.rs` partition matrix); no live-cluster test writes a **resource** while partitioned (C5, NO-FIX by decision) |
| Offline resource metadata converges after reconnect | PARTIAL/GAP — store-level paging proofs only (`resource/e2e.rs`); no end-to-end live-node proof |
| Revocation propagation | COVERED — `tests/revocation*.rs` + measured SLO (operator-only) |
| Custom transport with little code | COVERED — `tests/transport_provider.rs:197` full secure merge over one in-memory provider; docs in `transport/registry.rs:290-336` |
| Attach user logic to metadata events | COVERED for crate-typed events + hooks (`tests/tasks.rs`, `tests/event_parity.rs`); **user-published events remain impossible** until B2 (tag-keyed channel) lands |

## CI

`quality_check.yml` runs fmt/check/clippy/test/doc/MSRV/feature-powerset/starvation/ABI/deny/simulator-gate. Not in CI: `tests/slo.rs` strata, `tests/soak.rs`, all benchmarks (operator-only lanes; consistent with C4 NO-FIX).

## Recommended sequence for 0.1.0

1. Land the seven must-land items above (A1, D8, E5, B10 remainder, A2, B1, B3) — each is small, decided, and becomes ABI/correctness debt after the tag.
2. Fix the nightly-fmt gate (2 files) and add a local pre-commit path that cannot silently use stable rustfmt.
3. Resolve the two record contradictions (A13 comment vs decision; C3 vs pending §12) before starting the B5/B6/B7 table refactors.
4. Batch the P2 structural refactors (signature-helper rehoming, session Ack-arm extraction, supervisor split, WallClock seam, schema-tag single-sourcing) as one post-decision-implementation sweep, since the B5/B6/B7 refactors touch the same files.
