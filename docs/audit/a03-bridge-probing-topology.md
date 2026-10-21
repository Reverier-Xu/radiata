# A03: Bridge probing eligibility bound and cluster-wide topology awareness

- Verdict: PARTIALLY CONFIRMED

## Evidence

1. The literal bound exists. `src/runtime/degree.rs:68`:
   `pub(super) const BRIDGE_PROBE_SLACK: usize = 1;`
   `src/runtime/degree.rs:232-234` (`bridge_probe_tick`):
   ```
   let eligible = plan.state == crate::ConnectionDegreeState::Healthy
     && connected.len() < plan.target + BRIDGE_PROBE_SLACK
     && members.keys().any(|node| !connected.contains(node));
   ```
   So "session count < target+1" is a real, necessary condition.

2. The gloss "below its connection target" is refuted. `Healthy` is defined in
   `src/membership/degree.rs:107-109` as `sessions >= target`. The probe is
   reachable only from `maintenance_tick` when the deficit budget is zero
   (`src/runtime/degree.rs:136-138`: `if plan.dial_budget == 0 { ... return
   self.bridge_probe_tick(...) }`), and `degree_plan` (`src/membership/degree.rs:112-118`)
   gives `dial_budget = target - sessions` for any node with 1..target-1 sessions.
   Eligible set is therefore exactly `sessions == target` ("at target", not below).
   A below-target node dials the deficit every 30s tick; a zero-session node is
   owned by the recovery plane (`runtime/recovery.rs` backoff; comment at
   `membership/degree.rs:112-117`).

3. The proposed duty is already implemented. Module doc `src/runtime/degree.rs:22-33`:
   "a healthy node at its target that still has unconnected members ... At most
   once per probe interval the tick dials ONE uniformly random unconnected member"
   (`BRIDGE_PROBE_INTERVAL_TICKS = 10` × 30s = 5 min, `runtime/degree.rs:55-61`,
   pinned by `bridge_probe_interval_is_five_minutes` at line 656). The code
   explicitly cites this as a prior "audit finding #1's residual boundary".
   Proven by test `bridge_probe_dials_a_cross_partition_member_within_two_intervals`
   (`runtime/degree.rs:673`): two halves of an 8-node cluster meshed at k(8)=4
   re-bridge within two intervals; negative space pinned by
   `a_fully_connected_healthy_node_never_probes` (line 795).

4. Topology dissemination today (all session-borne, additive):
   - `src/membership/sync.rs:1-13`: authenticated sessions carry `MembershipPage`s
     of node descriptors plus issuer trust bindings.
   - `src/reconcile/plane.rs:132-138`: four anti-entropy lanes (descriptors, trust,
     resources, tombstones) run on the reconcile plane; descriptors batch into
     `MembershipPage` commits (`plane.rs:92-93`).
   - The probe's universe is recomputed every tick from the durable store:
     `known_online_member_endpoints` (`src/runtime/recovery.rs:209-257`) = every
     member with trusted binding, live descriptor, published endpoint.
   - No lane carries other nodes' liveness/online state. Online/offline is purely
     local (per-session keepalive, `session/liveness.rs`; local session table at
     `runtime/degree.rs:119-126`).

## Root cause (actual mechanism)

The audit misreads one conjunct as the whole predicate. Eligibility =
Healthy(sessions ≥ target) ∧ sessions < target+1 ∧ unconnected member exists ∧
cadence bracket elapsed ∧ no maintenance dial in flight. Net effect: exactly one
probe edge above target per node, deliberately capped (`runtime/degree.rs:63-68`:
"one landed probe edge disables further probes until a session drop re-opens the
deficit path"). Concrete residual gaps vs. the audit's proposal:
- A node holding app-initiated sessions above `target+1` never probes — the
  maintenance plane is additive-only (`runtime/degree.rs:6-7`) and recovery prunes
  only recovery-class edges (`maybe_prune_recovery_edges`, `runtime/recovery.rs:459`),
  so such a node stays above the bound indefinitely.
- A landed bridge edge also raises the *receiver* above target, disabling the
  receiver's own probe until a session drop.
- Members that join the far side of a partition are invisible until re-merge
  (dissemination rides the severed sessions); the durable pre-partition member
  table is what the probe dials from.

## Impact

Library users running long-lived clusters: the canonical partition shape (halves
meshed exactly at target) is healed within ~5-10 min by the existing probe, so the
audit's core scenario is already covered. The over-target node gap delays healing
only when one side holds surplus app-initiated edges; severity P2 (report-only),
self-healing once surplus sessions drop. No functional gate is involved (degree is
"never a functional gate", `membership/degree.rs:9-11`). Not permanent: any session
drop re-opens eligibility.

## Suggested fix direction

Minimal, if the over-target gap matters: relax `bridge_probe_tick` eligibility
(`src/runtime/degree.rs:232-234`) to `Healthy && has unconnected members`, keeping
the 1-probe-per-interval bracket as the sole storm bound (dial cost stays ≤ 1
probe/node/5 min even if degrees inflate above target+1). Do NOT build the proposed
cluster-wide online/offline gossip: a new sync lane (touching `membership/sync.rs`
payload kinds, `reconcile/plane.rs` `ACTIVE_LANES`, `membership/page.rs`) cannot
propagate across the partition it is meant to heal — dissemination rides the same
authenticated sessions that were severed — and the probe already fails cheap
against offline members at its cadence. Local `debug!`/`warn!` tracing already
covers the paths; keep any change free of unwrap/unsafe per AGENTS.md.

## Validation ideas

- Extend `bridge_probe_dials_a_cross_partition_member_within_two_intervals`
  (`runtime/degree.rs:673`): seed one node at target+2 sessions with unconnected
  members; assert the chosen policy (probe fires, or documented negative).
- New test: bridge edge lands on the receiver, pushing it to target+1; assert its
  probe eligibility flips off and re-arms after a session drop.
- New test: node above target with zero unconnected members never spends the
  cadence bracket (mirrors `a_fully_connected_healthy_node_never_probes`).
- Simulation/integration test under `simulation/`: two halves, one side seeded with
  surplus app edges; assert reconnect within a bounded number of intervals.

---

Note: the audit's file pointers were slightly off — the eligibility check lives in `src/runtime/degree.rs` (not `src/membership/degree.rs`, which holds only the plan formula), `src/membership/recovery.rs` is the pure recovery state machine (never dials), and `src/routing/` is packet forwarding/relay with no connection-bridging role.
