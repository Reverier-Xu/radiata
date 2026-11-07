# Code Quality & Architecture Audit — radiata pre-0.1.0

Date: 2026-11-07. Method: 8 parallel read-only review agents (5 module
partitions across 7 quality dimensions, plus a cross-module duplication
scan, a vision-alignment audit, a security-scope audit, and an
extensibility/ergonomics audit) over all 164 source files (~112k lines).
Every P1/P2 finding was spot-checked against the source before inclusion;
line numbers refer to the tree at audit time.

---

## 1. Quality gates (baseline)

| Gate | Result |
| --- | --- |
| `taplo fmt --check` | PASS |
| `cargo +nightly fmt --all -- --check` | PASS (0 diffs; note: the Homebrew rustup shim mishandles `+nightly fmt` — invoke the toolchain binary directly) |
| `cargo check --workspace --all-targets --all-features --locked` | PASS |
| `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | PASS (zero warnings) |
| `cargo test --workspace --all-features --locked` | PASS |

Overall verdict: **PASS**. Zero P0 findings, zero compile/lint/test issues.
All substantive findings below are maintainability debt, scoped
documentation gaps, or agreed architectural work.

## 2. What is healthy (verified, not asserted)

- **Single-sourced encoding discipline.** `canonical_record!` plus
  byte-stable golden vectors for every identity record;
  `protocol::encode_canonical` is the only CBOR primitive; `hex.rs` the
  only hex codec; all wall-clock reads funnel through `time.rs` (12+
  `SystemTime::now()` sites checked — every production read goes through
  the seam).
- **Fail-closed everywhere, pinned by tests.** Non-canonical wire
  encodings rejected by re-encode byte-compare; unknown kinds/reasons/tags
  fail closed; torn key artifacts resolve to `Unknown` and are never
  overwritten; no `unwrap`/`expect` reaches production paths (crate-root
  deny).
- **The feared sync-path duplication does not exist.**
  `contest_descriptors`, `descriptor_skip_reason`, `apply_descriptor_batch_ctx`,
  the reconcile `Lane` trait, and `sync_common`'s pump/ack helpers are
  single-sourced across membership/reconcile/resource; redb and json share
  `commit_precheck`/`condition_matches`/`classify_receipt`.
- **The extension registry is genuinely the single map.** Transports,
  routing policies, hooks, protocols, and reconcilers all resolve through
  `ExtensionRegistry` with a uniformly enforced reserved domain and one
  insertion-once helper; concurrency is test-covered.
- **Security seams are explicit and tested.** Channel binding is locally
  derived (RFC 9266 exporter or versioned class constants), never a wire
  field, never logged; handshake signing order enforced in code; SLO bounds
  derived from documented cadence constants.
- **Scope discipline is real.** Payload bytes are opaque (no AEAD/payload
  crypto anywhere), metadata storage is deliberately plaintext, `tcp://` is
  a first-class scheme, feature negotiation is channel-level only — the
  crate stops exactly where the owner's responsibility boundary was drawn.

## 3. Agreed architecture direction (from the audit discussion)

Two decisions were reached during review of the findings; later findings
are marked with how they are affected.

1. **Unified row model.** Storage rows unify to `name + labels + version +
   payload`. Core identity records become private-domain resources; the
   public write API refuses reserved domains (read stays open). Contest /
   admission semantics are declared per family (generalizing the existing
   `decides: fn` precedent); payload interpretation stays split by domain
   (user payloads opaque, core payloads typed). Rationale: core becomes the
   hardest user of its own resource machinery; the parallel private
   machinery that caused several drift-risk findings disappears.
2. **Cleanup policy is row data, not a compile-time constant.** Cleanup
   policy is carried on rows as a reserved, core-verb-writable label with a
   typed vocabulary validated at registration. Rationale: in a decentralized
   cluster without synchronized binary upgrades, data-carried policy
   converges through the existing reconcile plane; compile-time policy
   would require fleet-wide upgrade coordination. Users never write these
   labels directly; business-semantic changes go through encapsulated core
   verbs/tasks.

## 4. P1 findings

### 4.1 Default key-custody seed file permissions — **approved, fix immediately (Track 0)**

`src/keys/metadata.rs` (default store-backed custody) writes the raw
32-byte identity seed into the metadata store; `src/storage/redb/store.rs:363`
(`Database::create`) and the json store set no file permissions, so the seed
lands world-readable under a typical umask. `FileKeyStore` carefully enforces
0600-from-first-byte plus tightening on load (`keys/file.rs:150-160`) — two
custody adapters, same threat model, two standards.

**Fix:** create with 0600 (directory 0700) and tighten on open with a
`tracing::warn` for stores hosting the `Custody` domain, mirroring
`file.rs` hygiene. No public API change.

### 4.2 Storage backend authoring is a dead end for external authors — **partially subsumed by the unification**

`commit_precheck` / `condition_matches` are `pub(crate)` (`provider.rs:842, 893`)
and the contract runner is `#[cfg(test)] pub(crate)`
(`storage/contract/mod.rs`): a third-party `Storage` author can neither reuse
the commit-semantics derivation nor validate their backend against the
reference oracle; there is no in-memory demo factory either. The unified row
model (§3) restructures this surface; when it lands, expose the derivation
helpers and an opt-in contract runner, and consider `adapters::memory_store()`.

## 5. P2 findings

### 5.1 Silent-drift duplications — **dropped as standalone fixes; subsumed by the unification**

- `membership/tombstone.rs:224-240` hand-copies the local revoke effect
  sequence from `runtime/task_effects.rs:603-616` (persist → section →
  retire → `SessionChanged` → `NodeRevoked`); only a docstring promises the
  order. Original fix (extract `close_authorization` into
  `identity::revocation`) is superseded: under the unified model both arms
  become one declared family behavior.
- `identity/leave.rs:312-341` ≈ `identity/cleanup.rs:490-514`: identical
  checkpoint-sweep bodies. Subsumed by the generic cleanup engine (Phase C).
- `identity/merge.rs:514-560` `re_admission` re-implements `merge_state`
  validation. Subsumed by per-family admission declarations.
- `membership.rs:372-380` ≈ `:516-524`: adopted-binding evidence probe
  copied verbatim, feeding one skip decision. Subsumed.
- `identity/records.rs:573-603`: the family-agnostic sweep hardcodes
  revocation's permanent-exclusion rule (`revoked_key_ctx`). Superseded by
  cleanup policy as declared family behavior (Phase C).

### 5.2 Core task-kind policy split across five match tables — **Track 0**

`CoreTaskKind::slot_class` (`task/mod.rs:239`), `drains_on_shutdown`
(`task/mod.rs:232`), `retry_policy` (`task_manager.rs:199`), `check_shape`
(`task_manager.rs:336`), `coalesce_key` (`task_manager.rs:357`): wildcard
arms make a newly added verb silently degrade (ONCE retry, no coalescing,
no shape check). Consolidate into the `TaskReconcilePolicy` registration
record and derive the five tables from it. New core verbs will land during
the unification, so this goes first.

### 5.3 `SessionPacketContext` fuses the routing plane — **Track 0**

`session/stream.rs:239-336`: seven routing-domain fields and a
17-positional-argument constructor on a session-named type; the session read
loop calls routing internals directly (`inbound.rs:337-357, 439-456, 612`).
Extract a `RoutingPlaneContext` held as one field. This is separation (not
convergence): the two planes evolve independently.

### 5.4 Security posture notes (in-scope)

- **Routed-stream `source` attribution is an unauthenticated claim**
  (`routing.rs:695-703` accepts the frame's `source`; only the current
  holder is validated against the session peer). If origin attribution is
  deliberately user-business, document the trust stance at
  `RouteContext::from_frame`/`receive`. *Deferred to the documentation
  track.*
- **One leaked join credential admits unlimited distinct subjects for its
  600 s lifetime** (bearer secret, per-subject single use,
  `identity/merge.rs:1-16`, `merge_rate.rs:12-30`). State the blast radius
  on the `MergeCredential` surface. *Deferred to the documentation track.*
- **`tcp://` listeners bind with no runtime signal** (`plain.rs:31-56`).
  Add one `tracing::warn!` at bind. *Track 0.*
- **Revocation enforcement is convergence-bound** (accepted design; the
  in-flight publication race is closed at `stream.rs:577-586`). State the
  latency contract in operator docs. *Deferred to the documentation track.*

### 5.5 Cross-module placement (the inverse problem: family semantics in shared scaffolding)

- `config.rs:414-420` `NodeConfig::route_policy` reaches into
  `routing::DefaultNextHop::tag()` to fabricate a default the caller never
  configured. Resolve the default where the default policy is registered;
  keep `route_policy()` a plain `Option` read. *Track 0 (small,
  independent).*

## 6. P3 findings (~40, by category)

### 6.1 Mechanical same-family convergences (small, safe)

| Location | Item |
| --- | --- |
| `session/inbound.rs:365-370` ≈ `:739-743` | `EndReason → StreamItem` mapping duplicated; one `From` impl |
| `transport/connection.rs:151-161` ≈ `:216-226` | admission → attributable-address mapping duplicated; one helper |
| `connection.rs:412/419/505-511` ≈ `framing.rs:184-190` | wire sent/received trace events duplicated across stream classes; log at one seam |
| `session/inbound.rs:1338/1648/2071/2534/3038` | five copies of the 17-arg test-context builder; one test helper (shrinks automatically after §5.3) |
| `routing.rs` (`resolve_plan` ≈ `plan_of`) | same body minus one lookup |
| `membership/tombstone.rs:50-76` | `collected` ≈ `collected_row` watermark predicate at two shapes |
| `membership/tombstone.rs:417-479` | refusal-policy wrapper duplicated across cleanup/revocation rows |
| `membership.rs:33-35` ≈ `:295-297` | namespace constructor duplicated against its own doc claim |
| `routing.rs:518` ≈ `:992` | byte-identical `OnceLock` builtin-tag blocks; one generic helper |
| `error.rs:203-250` | eight poisoned-lock mappers differing only in context string; one `poisoned(context)` |
| `config.rs:8-12` | `reject_zero` pure forward to `zero_checked`; inline or drop |
| `keys/metadata.rs:128-215` | lock-poison recovery expression repeated where `ephemeral.rs:76-82` factors it |
| `task_manager.rs:242-258` | `credential_issued` ≡ `credential_rotated` bodies; event distinction lives at call sites |
| `protocol/envelope.rs:88,102` | generic over a registry predicate with one production `fn` caller; fn-pointer parameter suffices |
| `protocol/wire.rs:50-88` | `position` duplicates `kind_id` data (0x0001↔1 …); derive one from the other |
| `supervisor.rs:888-948,1041-1070` | `TickState` re-declares 10 `EffectPlanes` fields; hold one `Arc` handle |
| `fuzz_adapters.rs:136` | dead statement (`let _ = FeatureTag::parse(...)`); delete. *Track 0* |
| `driver.rs:570-573` | stale doc line on `send` (leftover from a deleted helper) — in an auth-critical file. *Track 0* |

### 6.2 Readability extractions (god-functions, single-purpose splits)

| Location | Item |
| --- | --- |
| `identity/merge.rs:119-310` | `commit_merge` ~190 lines, linear and commented; optional split at `classify_existing_state` / `build_caller_operations` |
| `session/stream.rs:528-700` | `run_session` ~170 lines; crossed-dial and teardown blocks extract cleanly |
| `task_effects.rs:1496-1655` | `reconcile_listen` mixes bind, accept-loop construction, publication; extract `spawn_accept_loop` |
| `storage/mod.rs:799-930` | `resolve_frozen_journal_uncommitted` seven chained phases; extract outcome-classification tail |
| `membership/tombstone.rs:300-395` | `decode_tombstone_row` four parallel match arms (arms genuinely differ — leave or light macro) |
| `routing/forward.rs:209-222, 407-421` | 11- and 9-parameter entry points with `too_many_arguments`; a `ForwardContext` bundle mirrors the existing `SessionAckContext` pattern |

### 6.3 Structural / file organization

| Location | Item |
| --- | --- |
| `session/inbound.rs` | 3294 lines, ~70% tests; move test modules to `inbound/tests.rs` (crate already has this pattern) |
| `view.rs` | seven structurally identical page types (~150 duplicated lines); a private macro keeps nominal types at zero API cost |
| `identity/lane.rs:55-61` | `Lane::apply` forces the trust lane to name session types it ignores; upstream fix is a lane-context struct (aligns with §5.3) |
| `extension_registry.rs:66-68, 460-500` | registry stores a task-module-specific record shape and calls `task::core_task_policies()`; factor a generic `Registration` value type if a second domain needs one |
| `error.rs:362-369` | `fixed_bytes` codec helper lives in the error module; relocate beside `hex.rs` |
| `receipt.rs:1612-1624` | `encode_wall_time`/`decode_wall_time` is a second `SystemTime`-vs-`UNIX_EPOCH` split site while `time.rs` claims single ownership; it is a distinct 13-byte wire format — soften the `time.rs` doc claim (or relocate), do not force-merge |
| `storage/receipt.rs:594-740` | `scan_due_anchors` ≈ `scan_retention_candidates` duplicate the bounded-scan skeleton (cursor/bound/advance); one generic helper. *Track 0 item 7* |
| `receipt.rs:908-949` ≈ `:1259-1300` | self-reference operation shape rebuilt for crash recovery; recovery must equal build byte-for-byte — extract the pure shape function. *Track 0 item 7* |
| `json/store.rs ~485` | `map_commit_io_error` maps every write failure to `CommitUnknown` including provably-not-applied pre-rename failures; align to redb's evidence-based classification (semantics, not code sharing) |
| `routing.rs:233-237` | reserved-selector-key pair hardcoded in the selector grammar; a `RESERVED_RESOURCE_LABEL_KEYS` const in `resource/mod.rs` iterated here |
| `routing.rs:1050-1130` | `routing_policies` is a second map of the same trait with one defer-only builtin; one map plus a domain flag would halve the surface (future simplification) |
| `membership/page.rs:111-140` | test-only three-name wrapper chain around `apply_descriptor_batch_ctx`; collapse |
| test fixtures | `stamped_leave_record`/`stamped_tombstone`/`signed_record` exist three times across leave/cleanup/revocation; `lifecycle.rs` duplicates `identity/testing.rs` helpers; `arm_admission` copied 3× in `routing/outbound.rs:511/688/873` |
| `endpoint.rs:198-206` | builtin transport tags repeat the domain prefix as three literals (test-pinned); one `const` from the shared prefix |
| `endpoint.rs:169-206`-adjacent | `Selector::parse_predicate_stream(parser, enforce_predicate_bound: bool)` — boolean entry flag; two named constructors read better |

### 6.4 Report-only — deliberate, do not converge

These look like duplication but are intentional under the agreed
abstraction principle (converge only same-semantic-family logic):

- `reconcile/budget.rs` mirrors `plane.rs` serialization discipline — the
  acceptance harness derives its value from independence; documented.
- redb/json `commit_inner`/`commit_blocking` critical sections — same
  contract, different failure evidence; the semantic layer is already
  shared via `provider.rs`.
- Three doubling-backoff schedules in different units/domains (wall-clock,
  tick counter, lane budget) — different time semantics.
- `clock_seconds`/`clock_millis` pair — fine as-is.
- Status tag literals in `view.rs:250-270` and `builtin.rs:226-236` —
  different purposes (published API vs wire inventory), drift pinned by a
  cross-check test.
- `packet/wire.rs:25` importing `routing::HopState` — one shared type in
  one direction is acceptable.
- `resource/mod.rs:487-528` hand-rolled encode/decode triple beside the
  `canonical_record!` macro — justified by the resource digest-verification
  step the macro does not support.
- `SyncKind::LeaveApplied` plumbing — best-effort one-shot notify through a
  full wire kind; documented as bounded-degrading.

## 7. Vision-alignment audit (summary)

| Vision item | Verdict |
| --- | --- |
| Offline-first metadata (mutations never wait on connectivity) | **Delivered.** Admission gates only on node lifecycle (`runtime/lifecycle.rs:186`); the sole write precondition is the frozen-store gate, not connectivity; offline writes commit locally and ride anti-entropy on reconnect |
| Offline data-plane (packet outbox) | **Deliberately delegated to applications** (guide ch. 4/9: fail-fast at origin, "queue locally, re-drive"). Decision recorded: optionally provide an official durable-outbox recipe later |
| Eventual consistency + reconnect recovery | **Delivered** (LWW tuple ordering, CAS conflicts surfaced, receiver-evidenced range reconciliation, fail-closed frozen-journal loop). Documented trade-offs: tombstone retention window is convention not enforcement; wall-clock LWW/checkpoints assume clock agreement |
| Fault recovery / roaming | **Delivered** (pure state machine, jittered backoff, candidate rotation, 2 s member-table rescan, full endpoint-list rotation, hub-free bridge probes with star preservation) |
| NAT reachability | **Owner decision: out of scope.** Transports are directed; sessions undirected; mobile devices dial out and need no publishable endpoint; VPN-based reachability (tailscale/openvpn) is the operator's composition choice. *Documentation of the dial-only deployment form deferred to the documentation track* |
| Intelligent channel selection | **Owner decision: explicit endpoint choice is the design position for 0.1.0** (guide.rs:191-192); a preference seam is roadmap-only. The `LinkProfile` EWMA already exists for future use |
| Event/task extensibility | **Delivered** (`watch_resources` durable replay with version resume, hooks, custom tasks) — discoverability gaps deferred to the documentation track |
| SLO evidence | Two measured strata (revocation propagation, reconnect catch-up) with bounds derived from documented cadences. Gaps (isolated-redial, bridge-probe, frozen-journal recovery strata; strict-profile runs) **deferred to the SLO special project** |

## 8. Remediation plan (agreed)

### Track 0 — immediate, independent (approved to start)

1. Seed-file permissions for Custody-domain stores (§4.1)
2. Delete stale doc on `driver.rs::send` (§6.1)
3. Delete dead statement `fuzz_adapters.rs:136` (§6.1)
4. `tracing::warn` on `tcp://` bind (§5.4)
5. Task-kind policy consolidation into `TaskReconcilePolicy` (§5.2)
6. `SessionPacketContext` → `RoutingPlaneContext` split (§5.3)
7. `receipt.rs` bounded-scan skeleton + self-reference op-shape extraction (§6.3)
8. `config.rs::route_policy` default resolution moved out of config (§5.5)

### Track 1 — unified row model (phased; every phase all-gates-green)

- **Phase A — row envelope.** Unify rows to `name + labels + version +
  payload`; migrate identity families onto the envelope (typed payloads,
  golden vectors updated); extend `families.rs` with per-family policy
  records (contest / admission / visibility / cleanup vocabulary).
  Purely structural; no behavior change. Acceptance: all gates + all-family
  contract suite + decoder/state fuzz replay + regenerated ABI baseline.
- **Phase B — resource machine unification.** Resource module onto the
  unified envelope; reserved-domain write gating; single reconcile lane.
  Acceptance: gates + event-parity + soak + mixed-versions.
- **Phase C — cleanup as controllers.** Generic sweep engine consuming
  declared cleanup policies (label projection of row data; typed
  vocabulary); leave/cleanup/revocation/key-seed declare policies; policy
  mutation via semantic core verbs; delete the old sweep scaffolding.
  Acceptance: gates + tombstone scenario tests (revoked-subject binding
  retention preserved as policy behavior).
- **Phase D — task wake unification.** Core sweeps/retirements run as
  core-owned controllers on the same `CustomTaskSpec`/`TaskReconciler`
  machinery; operation events generated from the unified change stream.
  Acceptance: gates + existing event/parity/task suites.

Cross-cutting: wire amendments follow the CHANGELOG pre-release precedent;
ABI baseline regenerated at defined phase boundaries; no new core verbs
during Phases A/B (feature freeze to reduce conflict).

### Deferred tracks (excluded from this effort by owner decision)

- Documentation track: guide chapters for dial-only members / custom
  transports / hooks / `watch_resources`; security-contract wording
  (routed `source`, credential blast radius, revocation latency).
- SLO track: additional strata (isolated redial, bridge probe,
  frozen-journal recovery; strict-profile runs).
