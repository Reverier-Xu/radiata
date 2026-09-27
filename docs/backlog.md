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

## 2. Conditional: receiver-side cursor evidence for sync planes

**Recorded, not scheduled.** The acknowledgement bound is now five
seconds and the planes pipeline, so a lost acknowledgement delays one
window slot instead of truncating a pass. If admission latency ever
grows with scale beyond that bound, the structural answer is
receiver-side cursor evidence (a pull-based repair) — a bigger timer is
explicitly not the answer (it uniformly slows every sync-bound phase;
measured during the 2026-09-27 cycle).
