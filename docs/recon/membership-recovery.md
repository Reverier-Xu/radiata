# Recon: membership recovery / connectivity claims

Repo: `/home/reverier/Code/Rust/radiata`, branch `fix/connectivity-liveness-integrity`, HEAD `cb831f4`.
Read-only recon; no source file modified, no docs/audit or docs/plan file read.

Important context: the tree has already absorbed the 2026-10-09 audit fixes (tick workers
moved off the supervisor loop, task-manager migration of the mutating verbs, rotating
recovery fan-out window, endpoint-level failover). Claims 2, 4, and 6 describe the
pre-fix state and are refuted by the current code. Claim 1 is refuted for its stated
scenario by the connection-degree maintenance plane. Claim 19's mechanism is real but
bounded.

---

## Claim 1 — Two internally-connected partitions never auto-reconnect

**Verdict: refuted** (for the stated 4-node 2+2 scenario), with one real boundary case
recorded as residual risk.

### Evidence

The claim's mechanism exists in the recovery plane — it quiesces on *any one route*:

- `src/membership/recovery.rs:129-165` (`RecoveryController::observe`): when
  `reachable` is non-empty the controller transitions to `RecoveryState::Connected`,
  resets attempts, and never dials again until fully isolated:
  ```rust
  // At least one authenticated path exists: the "any one route"
  // deployment contract is satisfied, so recovery quiesces instead of
  // expanding the topology.
  self.pending = unreachable;
  if self.state != RecoveryState::Connected {
    self.state = RecoveryState::Connected;
    self.attempts = 0;
  ```
  So the recovery plane alone indeed never heals a 2+2 partition.

But a budgeted periodic probe *does* exist — the connection-degree maintenance plane,
which is exactly the link-selection layer the claim asks about:

- `src/runtime/degree.rs:38-40` — `DEGREE_MAINTENANCE_TICK_PERIOD = 30s`, one
  long-lived worker (`run_maintenance_worker`, lines 56-76, `MissedTickBehavior::Skip`).
- `src/runtime/degree.rs:85-153` (`TickState::maintenance_tick`): recomputes the plan
  from the full member universe and live sessions, then dials the deficit:
  ```rust
  let plan = crate::membership::degree::degree_plan(
    members.len().saturating_add(1),
    self.config.connection_degree(),
    connected.len(),
  );
  ...
  let dials = crate::membership::degree::select_degree_dials(
    plan.dial_budget, &local, &members, &connected, self.entropy.as_ref())?;
  ```
- `src/membership/degree.rs:76-110` (`degree_plan`): `dial_budget = target − sessions`
  while at least one session exists (only the zero-session case defers to recovery).
- `src/membership/degree.rs:117-144` (`select_degree_dials`): uniform random selection
  among *unconnected* members carrying all their endpoints.
- `src/membership/degree.rs:47-75` (`degree_target`): for n=4, k(4)=3 (pinned by the
  shipped table and the exact-formula CI test).

Walk-through of the claim's scenario (nodes A-B and C-D, pairwise connected, n=4):
each node has `sessions=1`, target `k(4)=3`, so `dial_budget=2`; the only unconnected
members are the two nodes of the other partition, so the very first maintenance tick
(≤30 s) dials both cross-partition members. The partitions bridge.

Edge-trim logic cannot undo this: `src/runtime/recovery.rs:427-505`
(`maybe_prune_recovery_edges`) prunes at most one *recovery-dialed* edge per 4-tick
cooldown and only while a non-recovery (caller/inbound/maintenance) edge remains;
maintenance dials land as caller-class edges (`recovery_dialed=false`,
`src/runtime/degree.rs:193-199`), so pruning never fights them and can never
re-isolate a node.

`src/membership.rs` (listed in the claim) contains only the descriptor schema; no
link-selection logic lives there. `src/config.rs:313-315,380` — `connection_degree`
defaults to 0 = derived k(n), so the probe is on by default.

### Root cause of the (historical) observation

The "any one route" recovery contract alone would strand partitions; that is still
true of the recovery controller in isolation. The reconnect pressure comes from the
newer degree plane, which the claim predates or overlooks.

### Residual risk (boundary case, not the claim's scenario)

Degree is a connectivity-threshold target, not a mesh-restoration goal. If each
sub-partition already satisfies k(n) internally (e.g. n=16, k=5, two internally
8-meshed halves with 7 sessions each) or the operator sets
`with_connection_degree(1)`, every node is `Healthy`, `dial_budget=0`, and no plane
ever dials across: the partitions never re-bridge while members remain in each
other's tables. Anti-entropy sync runs only over existing sessions, so even
membership data stops flowing. If whole-cluster healing at/above target degree is a
requirement, that is a deliberate design gap to close explicitly (smallest change:
a low-frequency bridge probe in the degree plane, or documenting the boundary) — it
is not a defect in the stated 4-node case.

### Minimal fix direction

None for the stated scenario — behavior is already correct. If the boundary case
matters, the smallest in-pattern change is extending `degree_plan`/`maintenance_tick`
with a slow cross-partition probe cadence; do not touch the recovery controller's
quiescence contract (it is load-bearing for "connected node never dials").

### Coupling / risks

Degree dials share `known_online_member_endpoints` (`src/runtime/recovery.rs:209-243`)
with the recovery plane and the public views; any change there moves all three.
`RecoveryView.connected` means "any one route", not "whole cluster" — public-API
semantics to keep in mind before strengthening guarantees.

### Test surface

- Existing: `tests/connection_degree.rs:128-215` (`an_unhealthy_node_dials_its_way_back_to_target`);
  `tests/transport_chaos.rs:1068-1107` (hub loss splits the cluster into components and
  "the components bridge as soon as one cross-component dial lands" via the maintenance
  plane — already the partition-bridge regression lane);
  unit tests in `src/membership/degree.rs` and `src/runtime/degree.rs`.
- Regression test that would pin the claim's exact shape: a 4-node test that joins all
  four, disconnects into two pairs (e.g. via `disconnect` on the cross edges after a
  star, or two pairs joined through a shared roster), then asserts full pairwise
  reachability within ~2 maintenance ticks with no explicit `connect`. Belongs in
  `tests/connection_degree.rs`.

---

## Claim 2 — Fan-out became fixed-prefix retry (first member by node id always dialed)

**Verdict: refuted.** The candidate window rotates; the audit lines cited (~158, ~314)
no longer match the file's current shape.

### Evidence

- `src/membership/recovery.rs:78-88` — the rotating cursor:
  ```rust
  /// The rotating candidate window: each step takes the next `fan_out`
  /// candidates starting at this offset (modulo the candidate count), so
  /// an isolated node sweeps its whole member table across successive
  /// attempts instead of retrying the same dictionary-order prefix
  /// forever (audit 2026-10-09 item 7).
  cursor: usize,
  ```
- `src/membership/recovery.rs:175-205` (`next_step`):
  ```rust
  let start = if count == 0 { 0 } else { self.cursor % count };
  let targets: Vec<NodeId> = (0..take)
    .map(|offset| ordered[(start + offset) % count].clone())
    .collect();
  if count > 0 {
    self.cursor = self.cursor.wrapping_add(take);
  }
  ```
  With `fan_out=1` and candidates {m1,m2,m3}, successive attempts dial m1, m2, m3,
  m1, … — a down first member is retried only once per sweep, never starves the rest.

### Ordering, budget, reset behaviour

- Ordering: deterministic `BTreeSet` (node-id) order; the cursor rotates over it.
- Retry budget: none on attempts *count* (isolated retry is unbounded but rate-limited);
  the backoff doubles `initial << min(attempts,16)` capped at `maximum_backoff`
  (`src/membership/recovery.rs:207-215`), ±25% jitter (217-245).
- Reset: `attempts` and `scheduled_backoff` reset on any state transition in `observe`
  (lines 148-152, 160-164); the `cursor` deliberately is *not* reset, so reactivation
  continues the sweep where it stopped rather than restarting at the prefix.
- Per-peer/per-address attempt state: **does not exist** — one controller-global
  `attempts` serial (incremented once per step, line 189-190) also drives endpoint
  rotation (`src/runtime/recovery.rs:509-513`). Consequence: with `fan_out>1`, every
  target of one step dials the *same* endpoint index of its own list, and a member
  re-selected after a sweep may skip an endpoint. Benign for failover (the next
  schedule starts at index 0 again after `attempts` resets), but it is a shared-serial
  design, not per-member state.

### Minimal fix direction

None needed. If per-member endpoint fidelity is ever wanted, the smallest change is
keying `recovery_endpoint` on a per-member counter in `TickState` instead of the
global serial — not currently justified.

### Test surface

Existing unit tests in `src/membership/recovery.rs`: `recovery_rotates_the_candidate_window_across_steps`
(~lines 480-511), `the_rotating_window_survives_a_changing_candidate_set` (~514-543),
`recovery_expands_through_bounded_fan_out` (~455-465). The fan_out=1 down-first-member
shape is *not* pinned explicitly; a one-line variant of the rotation test with
`RecoveryPolicy::new(1, …)` asserting `m1, m2, m3, m1` across four steps would close
that gap, same file.

---

## Claim 6 — Recovery dials only the first declared endpoint of each node

**Verdict: refuted.** All published endpoints are candidates; one is dialed per attempt,
rotated by the attempt serial.

### Evidence

- `src/runtime/recovery.rs:194-243` (`known_online_member_endpoints`): the recovery
  universe maps each member to `descriptor.endpoints().to_vec()` — **every** published
  endpoint, with the doc comment "a multi-homed member's later endpoints stay dial
  candidates … (audit 2026-10-09 item 7)" (lines 189-197).
- `src/runtime/recovery.rs:355-366` (in `recovery_tick_inner`):
  ```rust
  let Some(endpoint) = recovery_endpoint(endpoints, step.attempt) else { continue; };
  ```
- `src/runtime/recovery.rs:509-513`:
  ```rust
  pub(super) fn recovery_endpoint(endpoints: &[Endpoint], attempt: u64) -> Option<&Endpoint> {
    let index = attempt.saturating_sub(1) as usize % endpoints.len().max(1);
    endpoints.get(index)
  }
  ```
  Attempt 1 dials endpoint[0], attempt 2 endpoint[1], …, wrapping. The same helper is
  shared by the degree plane with its own `degree_attempt` serial
  (`src/runtime/degree.rs:140-152`).
- `src/transport/endpoint.rs:211+`: `Endpoint` is a single parsed address; there is no
  first-only projection anywhere on this path. The descriptor carries
  `endpoints: Vec<Endpoint>` (`src/membership.rs:34-40`).

Caveat (design, not bug): within one attempt only one endpoint per member is dialed,
not all concurrently; failover is across attempts. For an isolated node the recovery
schedule's attempt counter resets on reactivation, so each isolation episode starts
again at the first endpoint — correct, since descriptors may have changed.

### Test surface

- Existing: `src/runtime/recovery.rs:585-602` (`recovery_endpoints_rotate_with_the_attempt_serial`);
  `src/runtime/degree.rs:325-401` (`maintenance_dials_rotate_to_the_second_endpoint_when_the_first_stalls`,
  a live two-listener integration-style unit test).
- Missing: the equivalent live test for the *recovery* plane (isolated node, multi-homed
  member, first endpoint dead, assert the second endpoint receives the dial on the next
  attempt). Belongs in `src/runtime/recovery.rs`'s `#[cfg(test)] mod tests`, reusing the
  `silent_peer` test-support pattern from `src/runtime/degree.rs` tests.

---

## Claim 4 — Explicit network commands still run inline on the supervisor loop

**Verdict: refuted.** The mutating network verbs are task-manager effects; the
supervisor's control enum carries no network command at all.

### Evidence

- `src/runtime/lifecycle.rs:61-119`: `enum Control` = `Shutdown` plus read-only queries
  (`GetLocalNode`, `GetMember`, `GetRecovery`, `GetConnectionDegree`, `PageMembers`,
  `SelectResources`, `GetResource`, `PageResources`, `PageListeners`, `PageSessions`,
  `PageTopology`, `PageTrust`, `Observability`). No Connect/Listen/Join/Disconnect
  variant exists.
- `src/runtime/task_effects.rs:209-318`: `join`, `connect`, `disconnect` are admissions
  that submit `TaskEffect` closures to the task manager (`tasks.submit(TaskSpec::new(
  TaskKind::Connect, …), effect)`); `listen`/`stop_listener` likewise (1193-1330). The
  effect bodies (`reconcile_connect` at 340-360, `reconcile_listen` at 1370+) run on the
  manager's workers.
- `src/runtime/task_manager.rs`: each attempt body runs as its own spawned task
  (`AbortOnDrop(tokio::spawn(Attempt{…}.run()))`, line 1079), gated by per-class
  semaphores (`ReconcileChannels`, lines 47-77; local vs network slots from
  `NodeConfig::with_task_reconcile_slots`), with bounded retry (`NETWORK_RETRY`: 4
  attempts, 100 ms → 10 s, lines 138-143). A panicking effect surfaces as the task's
  typed failure, never on the supervisor.
- `src/runtime/supervisor.rs:410-545`: the select loop awaits only read queries; the
  single inline non-trivial arm is `send_packet` (lines 483-497), which is
  *deliberately* inline as the admission backpressure point with an in-code rationale
  ("Deliberately INLINE (audit 2026-10-09 item 3, partial)…"), bounded storage IO, and
  record-before-pump ordering. That arm is packet admission, not a network command.

### Minimal fix direction

None. The isolation the claim asks for (the standalone-dial-task shape) is exactly the
manager's spawned-attempt pattern, already applied.

### Test surface

`tests/starvation.rs` (slot split: wedged dials must not starve local kinds),
`tests/tasks.rs`, and the `task_manager.rs` unit tests (hook containment, coalescing,
cancel). No new test needed for the claim; a regression pinning "no `Control` variant
performs IO" would be a structural test in `src/runtime/lifecycle.rs` — low value.

---

## Claim 19 — Recovery dials are not owned by the shutdown/task manager

**Verdict: partially confirmed.** The mechanism is real (detached, unowned, not
cancelled, not awaited), but the exposure is bounded by the dial/authentication
deadlines and the shutdown signal reaches the session half.

### Evidence

- `src/runtime/recovery.rs:355-402`: each recovery dial is a bare `tokio::spawn`
  (line 382) whose `JoinHandle` is dropped on the spot; the task is registered
  *nowhere* — not in `connection_tasks`, not in the task manager. Only the
  `recovery_pending` atomic bounds in-flight count (incremented line 360, decremented
  at 401). Same shape for degree-maintenance dials: `src/runtime/degree.rs:160-204`
  (spawn at 188).
- `src/runtime/supervisor.rs:875-905` (`into_dependencies`, the shutdown path): sends
  the shutdown watch, then aborts and returns for awaiting only `sync_driver`,
  `tick_workers`, and `connection_tasks`. Detached recovery/maintenance dials are in
  none of those. `finish_shutdown` (lines 548-590) awaits only that `drained` list.
- What *does* bound them:
  - the dial phase is wrapped in `connect_with_deadline` (dial_deadline, default 10 s,
    `src/config.rs:347`) and the handshake in `authentication_deadline` (default 30 s);
  - the task passes a `shutdown` watch receiver into `dial_member` →
    `keep_outbound_session` → `run_session` (`src/runtime/recovery.rs:371`,
    `src/runtime/supervisor.rs:956-1040`), so a session that *completes* during
    shutdown closes cooperatively;
  - `retire_all_sessions` in `into_dependencies` (supervisor.rs:899-903) drops each
    session entry's frame sender so detached writers exit.
- What does *not* happen: the in-flight dial phase (TCP/TLS/WS connect + member
  handshake) never selects on the shutdown watch — `connect_with_deadline`
  (supervisor.rs:933-953) is timeout-only — so shutdown neither cancels nor waits for
  it. The detached task keeps `Arc` clones of `SessionDriver` (→ identity context →
  store), `SessionTable`, and the packet context alive until it settles.

### Root cause

The recovery/degree dial spawn sites predate or bypass the crate's own bounded-accounting
rule ("exactly N tasks, aborted and awaited by the shutdown path" — the rule the tick
workers and join session tasks follow). The in-flight counter replaced task ownership
instead of complementing it.

### Concrete impact

Worst case is a restart race: `finish_shutdown` can return while a recovery dial still
holds the old store/context Arcs (≤ dial_deadline + auth_deadline, ~40 s at defaults),
and a node restarted on the same storage factory in that window can race the lingering
capture — the exact hazard `into_dependencies`'s await of accept-side tasks was built
to avoid (comment at supervisor.rs:561-566). The window is small and the dial does no
storage IO until handshake-admission, hence "partially".

### Minimal fix direction (smallest in-pattern change)

Push each dial's `JoinHandle` into the existing `connection_tasks` vec (the recovery
tick already reaps finished handles there every tick — `src/runtime/recovery.rs:283-290`
— and `into_dependencies` already aborts + `finish_shutdown` awaits that vec). That is
a two-line change per spawn site (`recovery.rs:382`, `degree.rs:188`) reusing the
existing ownership channel — no new task manager, no new abstraction. Optionally also
select on `shutdown.changed()` inside the dial body for prompt cancel; the handle
registration alone already fixes ownership/await.

### Coupling / risks

- `connection_tasks` is shared with the observability counts and the tick reaper;
  adding recovery handles makes the counts include short-lived dials (arguably more
  correct).
- Aborting a dial mid-handshake is safe (errors already logged as "recovery dial
  failed"; the `pending.fetch_sub` release must stay on every exit path — keep the
  decrement after the `dial_member` await as it is).
- No public-API change; `RecoveryView` semantics untouched.

### Test surface

- Existing: none assert shutdown interaction of recovery dials; the closest is
  `src/runtime/recovery.rs:681-730` (tick boundedness under a stalled store) and the
  `dial_deadline_tests` in `src/runtime/supervisor.rs:1063-1125`.
- Regression test proving the fix: in `src/runtime/recovery.rs` tests — arm a silent
  peer (the existing `SnapshotGate`/`silent_peer` pattern), let a recovery tick spawn a
  dial that parks in the handshake, shut the supervisor down, and assert (a) shutdown
  completes promptly and (b) the dial task is finished/aborted before the shutdown
  reply resolves (observable via the handle now living in `connection_tasks`, or via a
  dropped-Arc probe on the store factory). Under the current code (b) fails: the dial
  outlives the reply until the deadline.

---

## Adjacent bugs noticed (not fixed)

1. **Member-mode session pumps are detached and untracked.** `dial_member` hardcodes
   `|session_task| { tokio::spawn(session_task); }` (`src/runtime/supervisor.rs:1024`),
   while `reconcile_join` routes its session pump through `track_connection_task`
   (`src/runtime/task_effects.rs:330-333`, `376-389`). So sessions established by
   explicit `connect` and by recovery/degree dials are never reaped by the recovery
   tick, never counted in connection-task observability, and never abort-awaited at
   shutdown (they do observe the shutdown watch and `retire_all_sessions`, so they exit
   — just unobserved and unawaited). Same ownership gap as claim 19, one layer later in
   the same call chain; the same `connection_tasks` registration fixes both.
2. **Recovery in-flight gate admits overshoot.** `recovery_tick_inner` checks
   `recovery_pending >= fan_out` once before the batch (`src/runtime/recovery.rs:313-320`)
   and then spawns up to `fan_out` dials, so in-flight dials can transiently reach
   `2·fan_out − 1`. Bounded and self-correcting, but the documented bound ("the counter
   bounds in-flight dials") is looser than written. The degree plane's equivalent gate
   (`src/runtime/degree.rs:107-124`) has the same shape vs `dial_budget`.
3. **Duplicated doc sentence** on `RecoveryController::immediate`
   (`src/membership/recovery.rs:266-269`): "Forces one immediate recovery cycle
   (immediate-recovery command). Forces one immediate recovery cycle without storms: …"
   — leftover merge of two doc edits; cosmetic only.

## Files retrieved (key ranges)

1. `src/membership/recovery.rs:78-88, 129-245, 266-276` — controller quiescence, rotating cursor, backoff/jitter, immediate.
2. `src/runtime/recovery.rs:189-243, 281-407, 427-513` — endpoint universe, tick + detached dial spawn, prune guard, `recovery_endpoint`.
3. `src/membership/degree.rs:47-144` — k(n) target, plan, uniform selection.
4. `src/runtime/degree.rs:38-204` — 30 s maintenance worker, deficit dials, detached spawn.
5. `src/runtime/supervisor.rs:410-545, 548-590, 875-953, 956-1040` — select loop, shutdown drain, abort/await list, `connect_with_deadline`, `dial_member`, `keep_outbound_session`.
6. `src/runtime/task_effects.rs:209-318, 340-360, 1193-1330, 1562-1580` — verb admissions → task manager; effect bodies.
7. `src/runtime/task_manager.rs:47-77, 138-160, 186-190, 380-395, 1040-1130, 1193-1210` — slot semaphores, retry policies, cancellable kinds, drain, spawned attempt bodies.
8. `src/runtime/lifecycle.rs:61-119` — `Control` enum (read-only + shutdown).
9. `src/config.rs:313-315, 347, 380, 545-608` — degree default (derived), dial deadline 10 s, `RecoveryConfig` defaults (fan-out 16, 2 s → 5 min).
10. `tests/connection_degree.rs:128-215`, `tests/transport_chaos.rs:1068-1107` — existing acceptance lanes for degree healing and partition bridging.
