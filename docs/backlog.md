# backlog — open work

Time-scoped ledger of work that is scoped but not done. Rules follow
[`README.md`](README.md): every item traces its motivation to concrete
evidence, names its acceptance criteria, and names the gate that will
catch its regression later. Items leave this file when their acceptance
evidence lands in the commit history.

## Decisions already made (do not relitigate)

- **One timing profile.** Peer-visible timing constants are a
  cluster-wide contract; there are no per-device timing profiles, and
  the shipped defaults are the deployment.
- **Revocation reachability is the operator's job.** The library does
  not backstop a mesh that cannot reach an evicted node; eviction plus
  unreachable peers is the operator's problem to solve.
- **A join that dies with its hub is an expected failure.** The joining
  leaf re-merges as an independent node; other leaves re-establish
  through nearby members.
- **Recovery liveness comes from connection-degree maintenance**, not
  from a new handshake-evidence protocol (landed, see below).
- **Sync planes pipeline.** Both the descriptor and trust planes carry
  bounded in-flight windows; the committed cursor advances only across
  the consecutive-delivered prefix (shipped, commit history of PR #49).
- **A member dial against an unspread binding is a typed `NotFound`.**
  The retryable convergence state is distinct from the non-retryable
  authentication failures (contradicted or revoked bindings); the
  dial path stays an immediate refusal and the healing planes plus
  caller retry policies absorb it (decided with the operator, landed
  with the connection-degree cycle).
- **The sync plane converges on range-fingerprint reconciliation.**
  Decided 2026-10 with the research cycle (`docs/research/`, decision
  record in `research/06-architecture-proposal.md`): the push
  watermark anti-entropy is structurally redundant (per-edge payload
  duplication ≈ 1−1/k at degree k; the 2026-10 loopback observation
  measured ~95%) and is replaced — not tuned — by receiver-evidenced
  range reconciliation over `(count, xor)` fingerprints, with payload
  bytes only crossing a session for ranges the receiver proves it
  lacks. Landed (the cycle's summary is in the landed section below).
- **The public handle API is the client-go-shaped verb surface.**
  `node.command(...)`/`node.query(...)` over sealed command structs are
  replaced by resource-scoped accessors (`members()`, `resources()`, …
  with `get`/`list`/`put`/`delete`) plus domain operation verbs
  (`join`, `leave`, `revoke`, `sync`, `shutdown`, `watch`, `send`).
  Landed 2026-09-29 (PR #54, rebase history with the full plan; the
  chat acceptance lane green on the merge commit closed the cycle).

## Landed in the connection-degree cycle (2026-09-27, no action)

- The connection-degree maintenance plane: the exact-formula
  `degree_target(n)` (integer fixed point, CI-asserted against the
  formula), `NodeConfig::with_connection_degree` override, the 30 s
  deficit-bounded maintenance tick over the active member universe,
  the `GetConnectionDegree` status query (`Healthy`/`Unhealthy` with
  the session count and the target), the zero-session deferral to the
  recovery plane, and additive-only semantics (maintenance never
  prunes, never gates functionality). Guide chapters 2 and 7 updated
  with the maintenance contract and the degree ceiling. The former
  design-input document's table contained formula errors; the shipped
  truth is the CI assertion binding `degree_target` to an independent
  evaluation of the exact formula.
- The typed member-dial contract: an absent trusted binding fails with
  `ErrorKind::NotFound` (retryable), while decode failures, contradicted
  bindings, and revocations keep their non-retryable kinds. Pinned by
  the binding-race lane in `tests/connection_degree.rs`.
- The chat acceptance lane in CI: image build, scenario matrix,
  boundary suite, and a four-attempt must-pass hub-loss soak, with the
  expected duration recorded in the workflow. The example scripts take
  `CONTAINER_ENGINE` (podman locally, docker in CI). The suite's
  sensitivity was verified by a deliberately injected large-payload
  truncation (suite fails) that was reverted (suite passes). The chat
  example's suite was updated from its old full-mesh/spanning-tree
  expectations to the degree contract (the steady mesh is a k-out
  graph; every node converges to its derived target).
- The receiver-side leave-persist log: a persist failure at the
  `SyncPayload::Leave` apply site logs its typed kind at debug level
  and propagates, so the next roster stall is attributable; pinned by
  the divergent-record unit lane in `membership/sync.rs`.
- The transport-chaos lane gained the mode-1 hub-loss phase: center
  lost before convergence, survivors re-mesh (recovery for the isolated
  spokes, degree maintenance for the below-target bus members), a
  spoke-to-bus relay crosses the bridged mesh, and the center restarts
  and rejoins through its own healing planes.
- The anti-entropy planes bound each round's dispatch to a small fair
  window of the live sessions, so per-round cost is independent of the
  connection degree. This is the degree plane's load consequence made
  explicit: the unbounded round starved the runtime's shared task on a
  single core at the reference scale (the starvation lane wedged at
  1661 s where `main` passes in 230 s); with the bound the same lane
  passes in 217 s.

## Landed in the watermark anti-entropy cycle (2026-10, no action)

- The membership sync planes (descriptors, issuer trust bindings,
  tombstones) converged on the shared per-peer watermark walk
  (`sync_common::WatermarkWalk`, the resource lane's proven model):
  every plane tracks the digest of each row it has delivered to a peer
  and emits only mismatched rows, so redundancy scales with the change
  set — never with the catalog size. This retired the whole-catalog
  fingerprint rounds whose cascade the 2026-10 audit measured at 98%
  redundant descriptor traffic under churn (a one-row join re-sent the
  whole catalog per peer per hop). The from-scratch liveness bound is
  the periodic watermark refresh (every 64 completed passes per peer,
  pinned by the `sync_common` walk tests); the one-tick-per-hop push is
  the register-write epoch, now noted by every membership store write
  path (`note_local_write`).
- The trust plane's binding pages are diff-shaped on the same walk
  (append-only bindings make a missing row never a removal — pinned by
  `the_trust_walk_dispatches_only_the_binding_diff`); the tombstone
  plane forwards only a peer's unconfirmed records, and its
  confirmations expire both when binding evidence reaches the peer
  (the admitted-but-not-applied heal: a revocation skipped because its
  subject's binding had not converged yet — pinned by
  `delayed_content_converges_after_revoke` and the 64-node chaos lane)
  and on a bounded tick refresh (`TOMBSTONE_CONFIRM_REFRESH_TICKS`) as
  the backstop for a binding learned from a third party. Tombstones are
  the one plane without a zero-traffic steady state: admission-only
  acknowledgements cannot prove application, so the bounded refresh
  stands in for the receiver-side receipt the leave plane has.
- The zero-emission steady state of the descriptor and trust planes,
  and the one-row join push, are pinned by
  `a_converged_mesh_emits_nothing_until_a_real_change`: over forty
  ticks the descriptor plane sends exactly one page (one row) and the
  converged binding walk sends exactly one page, an armed quiet scan
  sends zero rows, and one committed descriptor change sends exactly
  one row. The tombstone plane keeps a bounded confirmation refresh
  (see below) as its only steady traffic. The audit-feature counters
  (`membership_page_emitted` vs `descriptor_installed`) carry the same
  ratio for harness-level measurement.
- Deleted with the design: `PeerPageCursor` (the fingerprint and
  page-window machinery), the trust page window, and the per-tick
  whole-catalog fingerprint fold — the membership and resource lanes
  now share one walk implementation (`walk_namespace_filtered`) and
  one state machine.

## Landed in the reconciliation plane cycle (2026-10, no action)

- The reconciliation plane: all four lanes (descriptors, trust,
  resources, tombstones) converge by receiver-evidenced range
  reconciliation — `(count, xor)` fingerprints over each lane's
  item-digest space, the six-message `reconcile-v1` wire contract
  (ROOT/HINT/OFFER/NEED/ROWS/DONE, canonical CBOR, fail-closed
  decode, golden vectors), the frozen digest function (truncated
  SHA-256 over the canonical `[key, content]` pair), the `b = 4`
  multi-way negotiation, one in-flight round per session-lane, the
  per-node per-lane pull serialization (held hints bounded at eight
  per lane), and `(count, xor)`-ordered root initiation. The
  `WatermarkWalk`, the per-peer watermark tables, the refresh passes,
  and the tombstone resend cadence are deleted; the cleanup checkpoint
  GC and every lane's merge semantics are untouched (the primitive
  `c54382d`, the engine and wire `14b780d`/`b055a31`/`028fcdf`, the
  lane migration `b49c787`…`a359379`).
- The trigger and adaptation layer: local writes debounce into one
  coalesced HINT per tick through namespace-granular epoch indexing (a
  quiet steady state scans nothing), the 32-tick quiet ROOT detection
  cadence (8 ticks on weak links), the 4 KiB eager-delta piggyback on
  healthy links, and the per-session link profile (EWMA RTT and loss;
  weak = loss ≥ 10% or RTT ≥ 1.5 s) driving exactly three knobs — the
  cadence multiplier, the hint retry on a 1/2/4/8-tick backoff, and
  the eager-delta toggle — with the payload path never a knob
  (`5d240d9`, pinned by `654cd64`).
- The budget evidence (`scripts/verify-sync-budget.sh`, the
  engine-level matrix over n ∈ {8, 64, 256} × single-row / batch /
  reconnect): payload delivery redundancy measured 1.000–1.040×
  against the 1.05× bound (1.143/3.381/2.630/1.471 before the
  per-lane serialization), hint traffic held within changes × degree ×
  200 B, and the 20%-loss cell converging in 64 ticks against the
  eager-off baseline's 192 at n=8 (`30c6b5c`, `697eb15`).
- Defect classes the budget lane and the dual-perspective audit
  caught and fixed in-cycle: the cross-lane repair retry (a
  policy-skipped revocation waiting out a cadence window, `0d67596`),
  the wedged apply batch on refused rows (`900641c`), the root-side
  serialization gaps, the retention resurrection of swept removal
  rows, the hint-retry re-arming loop, and the narrow-scan plan
  erasing other lanes' repair marks (`e3891de`).
- The equivalence proof is the pre-existing suite: the membership,
  trust, resource, crash, and chaos lanes pass unchanged over the new
  plane — 804 tests green at the R3/R4 acceptance points, 805 after
  R5's guide doctest — and the `radiata::guide` sync
  chapters now describe the reconciliation contract (chapter 3 and the
  deployment chapter's background-load sizing).

## Landed earlier (2026-09-27 audit cycle, no action)

- The sync planes pipeline (descriptor and trust), round settlements are
  never dropped, a failed page keeps its barrier entry, and the
  acknowledgement bound is calibrated to a starved-runner admission
  (PR #49).
- Every crash-matrix child retries the store lock window its parent just
  released — the container gate's `crash boundary must be monotonic`
  failure (PR #50).
- Four drifted evidence lanes repaired: two session lanes whose filters
  pointed at renamed modules, the removal lane's caller pin, and the
  public-API baseline (18 deliberate additions, no removals).
- The chaos-lane convergence diagnostics now report the member-page row
  count and the absent identities, which is how every roster stall in
  this cycle was attributed.

## 1. Evidence-lane budgets and known environmental limits (record, not fix)

- The feature-matrix lanes (`verify-mixed-storage`,
  `verify-json-adapter`, `verify-redb-adapter`) sweep every feature
  combination and re-run the full suite per combination: 20–40 minutes
  each by design. Audits must budget for that; they are not CI lanes.
- The json-feature chaos lane's phase budgets are tight under
  concurrent host load (two audit-time failures, not reproducible in
  controlled repetition: pre-merge 4/4 pass, current 3/3 pass).
- The `container` job can hang for reasons outside the code: a 2026-09-27
  run sat 23 minutes in `tests/lifecycle.rs` (which passes in 0.02 s
  elsewhere) and was cancelled at the 30-minute job timeout; the same
  gate passes locally in 6m30s and passed on re-run. Treat a silent
  container hang as runner-side until a local container run reproduces it.
- The chat boundary suite asserted DM viewability straight off the wire
  admission ack, which proves current-process admission only: the chunk
  pump and the recipient's store write land after it. A single
  non-retrying inbox poll therefore lost a millisecond-scale race that a
  loaded runner reliably loses — the lane was red on `main` from
  2026-09-27 while the identical flow completed locally inside the
  poll's own round trip (300 KiB / 10 chunks, 13–49 ms measured). The
  suite now waits for viewability (`wait_viewable`, cumulative burst
  polling) and the library gained the missing above-chunk-bound delivery
  test (`a_body_above_the_chunk_bound_crosses_three_hops_byte_exact`);
  the data plane itself was never at fault.
