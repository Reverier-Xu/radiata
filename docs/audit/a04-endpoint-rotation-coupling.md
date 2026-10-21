# A04: Recovery endpoint rotation shares the schedule serial with member rotation, pinning each multi-homed member to one endpoint

- Verdict: CONFIRMED

- Evidence:
  - `src/membership/recovery.rs:182-190` (`RecoveryController::next_step`): member window and the attempt serial advance together every step:
    ```rust
    let start = if count == 0 { 0 } else { self.cursor % count };
    let targets: Vec<NodeId> = (0..take)
      .map(|offset| ordered[(start + offset) % count].clone())
      .collect();
    ...
    self.cursor = self.cursor.wrapping_add(take);
    self.attempts = self.attempts.saturating_add(1);
    let attempt = self.attempts;
    ```
  - `src/runtime/recovery.rs:371` (recovery tick dial loop): `let Some(endpoint) = recovery_endpoint(endpoints, step.attempt) else {`
  - `src/runtime/recovery.rs:555-557`: the shared serial indexes each member's list by modulo:
    ```rust
    pub(super) fn recovery_endpoint(endpoints: &[Endpoint], attempt: u64) -> Option<&Endpoint> {
      let index = attempt.saturating_sub(1) as usize % endpoints.len().max(1);
      endpoints.get(index)
    }
    ```
  - Candidate order is deterministic (`BTreeSet` iteration, `src/membership/recovery.rs:180`: `let ordered: Vec<NodeId> = candidates.iter().cloned().collect();`); candidates carry ALL published endpoints (`src/runtime/recovery.rs:118-124`, `known_online_member_endpoints`).
  - Degree plane: member selection is uniform-random Fisher–Yates, not counter-based (`src/membership/degree.rs:140-167`, `select_degree_dials`), but endpoint choice uses the same shared-batch-serial modulo (`src/runtime/degree.rs:178-181` and `:199`: `let attempt = self.degree_attempt.fetch_add(1, …) + 1;` … `recovery_endpoint(&endpoints, attempt)`), a second, independent global counter (`src/runtime/supervisor.rs:698`).
  - No other automatic dial path selects among endpoints: the connect/reconnect task effect dials one explicit endpoint (`src/runtime/task_effects.rs:346-363`), and `NodeHandle::connect` takes the caller's endpoint.
  - The "sweep" claim the design relies on, `src/runtime/recovery.rs:541-546`: "the serial advances once per step and wraps per member, so each member still sweeps every published endpoint across successive attempts" — unproven and, as shown below, false in common shapes.

- Root cause: Within one continuous isolation, both counters are pure functions of the step number, so member position and endpoint index are deterministically aliased. With fan_out = 1 and c candidates in sorted order, the member at position p is selected exactly at attempts a ≡ p+1 (mod c), and its endpoint index is (a−1) mod len = (p + j·c) mod len. Concrete interleaving (the audit's scenario: fresh controller, c = 2 members A,B each with 2 endpoints, fan_out = 1):
  - step 1: start 0%2=0 → A, cursor 1, attempt 1 → index 0 → A.ep[0]
  - step 2: start 1%2=1 → B, cursor 2, attempt 2 → index 1 → B.ep[1]
  - step 3: start 2%2=0 → A, attempt 3 → index 0 → A.ep[0]
  - step 4: start 3%2=1 → B, attempt 4 → index 1 → B.ep[1] … forever.
  A is dialed only on odd attempts and always hits endpoint 0; B only on even attempts and always endpoint 1 — each member tries the same single endpoint forever, exactly as claimed. Generally, member p's index set is {(p + j·c) mod len}: fully pinned when c ≡ 0 (mod len), sweeping only a len/gcd(c,len) subset otherwise; full sweep requires gcd(c,len) = 1. With fan_out = f > 1 the same aliasing generalizes (window start f·(k−1) mod c vs index (k−1) mod len); e.g. c=4, f=2, len=2 pins every member (even positions → index 0, odd → index 1). The doc comment's per-step independence argument ("a shared index correlates nothing") is correct within one step but misses this cross-step correlation.

- Impact: A fully isolated node (zero sessions) is the only state in which recovery dials, and the degree plane deliberately dials nothing there (`src/membership/degree.rs:112-116`: `let dial_budget = if sessions == 0 && n > 1 { 0 }`), so there is no backstop: if each member's pinned endpoint is dead while another published endpoint of the same member is live, the node stays partitioned indefinitely — recovery never quiesces, the backoff pegs at `maximum_backoff`, and the "any one route suffices" contract fails despite reachable endpoints. The smallest broken shape (2 members × 2 endpoints, fan_out 1) is also the most common multi-homed deployment. Mitigations: the coupling is only fixed within one isolation period — `attempts` resets to 0 on re-arm (`src/membership/recovery.rs:144`, `:158`) while `cursor` persists, so transient connectivity re-randomizes the phase; the degree plane's random reselection gives probabilistic failover once any one session exists. Severity: high for multi-homed clusters under sustained partition; permanent until membership or endpoint counts change the phase.

- Suggested fix direction: Decouple endpoint failover from the shared schedule serial: keep a per-member endpoint cursor (e.g. `BTreeMap<NodeId, usize>` alongside the candidate set, advanced once per dial of that member and wrapping per member) in `RecoveryController` or `TickState`, and pass that per-member serial to `recovery_endpoint` instead of `step.attempt` (and to the degree plane instead of `degree_attempt`). This guarantees every member sweeps all endpoints for any (c, len, f) with no new dependencies, no unsafe, no unwrap; log the chosen index via `tracing::debug!` for diagnosability. Minimally, also correct the false sweep claim in the `recovery_endpoint` doc comment and extend `one_step_dials_the_same_index_of_every_targets_own_list` or replace it with the cross-step contract test below.

- Validation ideas:
  - Unit test: drive `RecoveryController::next_step` + endpoint indexing for c = 2, len = 2, fan_out = 1 over 2c steps; assert each member's dialed-index set equals all its endpoints (fails today: A → {0}, B → {1}).
  - Exhaustive table test: for c ∈ 1..=8, len ∈ 1..=4, fan_out ∈ {1,2,3}, run c·len steps and assert every member dials every endpoint at least once (the failover liveness contract).
  - Integration test modeled on `recovery_steps_hold_in_flight_dials_at_the_fan_out_bound`: two multi-homed members whose first endpoints refuse and second endpoints are live silent peers, node fully isolated; assert both members connect through their second endpoints within bounded steps.
  - Re-run the seeded recovery simulation (`membership/recovery.rs` `simulation::run_seed`) extended with per-member endpoint counters to replay traces after the fix.
