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
  from a new handshake-evidence protocol (see item 1).
- **Sync planes pipeline.** Both the descriptor and trust planes carry
  bounded in-flight windows; the committed cursor advances only across
  the consecutive-delivered prefix (shipped, commit history of PR #49).

## Landed in the 2026-09-27 cycle (no action)

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

## 1. Connection-degree maintenance (largest item)

**Motivation.** When a hub dies before bindings converge, member
reconnects between leaves fail with `session binding` — the dialer has
no binding for its peer, and bindings only spread over sessions. The
json-feature chaos lanes hit this twice during the 2026-09-27 audit
(`member reconnect failed persistently: session binding`).

**Design input.** [`connectivity-degree-design.md`](connectivity-degree-design.md):
per-node target degree `k(n)` from the Poisson/isolated-vertex formula,
clamped to `[1, n-1]`; 90% connectivity target (+2 for 99%); operator
override for topologies the library cannot know (a single public-IP
relay where one link is enough).

**Scope.**
1. `NodeConfig::with_connection_degree(usize)` — operator override;
   unset or zero means the derived value.
2. `degree_target(n)` — the exact-formula const fn (smallest `k` with
   `n·(1 − k/(n−1))^(n−1) ≤ −ln 0.9`), with the constant table asserted
   in tests.
3. Maintenance loop: every 30 s, while active sessions < target, dial a
   uniformly random unconnected member from the member page (excluding
   terminal and already-connected peers).
4. Status exposure: the status query reports `connection state:
   healthy|unhealthy` with the current session count and the target, so
   an operator can see and fix network problems.
5. Below target but at least one session: everything keeps working —
   the degree gates only status and the maintenance cadence, never
   functionality. Only a fully offline node (zero sessions, cluster
   size > 1) uses the existing high-frequency recovery backoff.

**Acceptance.** Degree-table tests; a maintenance-tick unit lane (member
page + session table fakes); an integration lane proving an unhealthy
node dials its way back to target; the mode-1 scenario (hub lost before
convergence, leaves re-connect leaf-to-leaf) converging in the chaos
lane; `examples/chat/soak_hub_loss.sh` promoted from observation to a
must-pass lane. The `guide` chapter that states the practical ceiling
must be updated with the new maintenance contract.

**Gate.** The starvation lane plus the promoted soak lane; add a CI
assertion that the degree table's constant values match the formula.

## 2. Member-dial tolerance for not-yet-converged bindings

**Motivation.** Same evidence as item 1: a member dial is rejected
immediately (`session binding`) when the dialer's binding for the target
has not spread yet. Degree maintenance makes this rare; the dial path
still converts a transient topology state into a typed failure.

**Open question (needs a decision before work).** Is "target binding not
yet known" a retryable state (queue/bounded retry inside the dial, with
the same budgets as other dial work) or should it stay an immediate
typed refusal that the caller's retry policy handles? The recovery
plane already retries; the question is whether the request path should
also absorb it.

**Acceptance.** A lane where a dial races the binding spread succeeds
within its budget; no unbounded waits; the typed-error contract stays
documented either way.

## 3. Chat acceptance in CI

**Motivation.** `examples/chat`'s matrix, boundary suite, fuzz harness,
and hub-loss soak run locally only. The boundary suite found a real
32 KiB chunk-bound loss before it shipped.

**Scope.** A CI lane that builds the chat image and runs at least the
boundary suite (and the soak when its budget allows), plus a recorded
expected duration. The runner has docker; the example already ships
`up.sh`/`down.sh`/`run_acceptance.sh`.

**Acceptance.** The lane runs in CI, fails on a deliberately injected
boundary regression, and stays inside a bounded job timeout.

## 4. Receiver-side leave-persist observability

**Motivation.** During the audit a json-feature lane stalled with the
leaver still `Active` everywhere while the sender kept forwarding; the
receiver's persist outcome left no trace, so the stall could not be
attributed from the log.

**Scope.** Log the persist failure with its typed kind at the
`SyncPayload::Leave` apply site (debug level, matching the lane's other
diagnostics), so the next occurrence is attributable.

**Acceptance.** The log line exists and is exercised by the existing
leave lanes' failure paths.

## 5. Evidence-lane budgets and known environmental limits (record, not fix)

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

## 6. Conditional: receiver-side cursor evidence for sync planes

**Recorded, not scheduled.** The acknowledgement bound is now five
seconds and the planes pipeline, so a lost acknowledgement delays one
window slot instead of truncating a pass. If admission latency ever
grows with scale beyond that bound, the structural answer is
receiver-side cursor evidence (a pull-based repair) — a bigger timer is
explicitly not the answer (it uniformly slows every sync-bound phase;
measured during the 2026-09-27 cycle).
