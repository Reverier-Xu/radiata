//! The connection-degree contract: the cluster-size → target-degree
//! formula, the maintenance plan, and the uniform dial selection.
//!
//! A connected node is no longer left at whatever topology chance gave
//! it: while its authenticated session count sits below the target
//! degree, a periodic maintenance tick dials uniformly random unconnected
//! members until the target is reached. The formula is the exact
//! Poisson/isolated-vertex threshold `k(n)` = smallest `k` with
//! `n·(1 − k/(n−1))^(n−1) ≤ −ln 0.9 ≈ 0.10536`, clamped to `[1, n−1]`
//! (see `docs/connectivity-degree-design.md`): near the connectivity
//! threshold, disconnection is dominated by isolated vertices, so
//! holding the expected isolated-vertex count under `−ln(0.9)` keeps the
//! one-vertex-loss probability at or below ten percent. The design doc's
//! rationale records why the exact finite-`n` form ships instead of the
//! `⌈ln n + 2.25⌉` asymptote: the exact form never over-provisions at
//! small `n`.
//!
//! Degree is a maintenance target, never a functional gate: below
//! target with at least one session everything keeps working, and only
//! a fully offline node (zero sessions, cluster size > 1) falls back to
//! the recovery plane's high-frequency backoff — maintenance never
//! duplicates that plane's work.

use std::collections::{BTreeMap, BTreeSet};

use crate::{Endpoint, NodeId, Result, api::Entropy};

/// The fixed-point scale of the degree formula's probability arithmetic:
/// `−ln(0.9)` and the isolated-vertex product are represented as
/// integers over 2^40, which resolves every `k(n)` decision for cluster
/// sizes into the tens of thousands with five orders of magnitude of
/// margin to the nearest decision boundary (pinned by
/// `degree_table_matches_the_exact_formula`).
const DEGREE_SCALE: u128 = 1 << 40;

/// `−ln(0.9)` scaled by [`DEGREE_SCALE`], rounded down so the integer
/// comparison can only make connectivity marginally *harder* to
/// declare, never easier.
const DEGREE_THRESHOLD_SCALED: u128 = 115_845_112_074;

/// The target peer degree for a cluster of `n` nodes: the smallest `k`
/// with `n·(1 − k/(n−1))^(n−1) ≤ −ln(0.9)` (integer fixed-point
/// arithmetic over [`DEGREE_SCALE`]), clamped to `[1, n−1]`. A
/// single-node cluster has no peers and reports `0` — always healthy.
///
/// The iteration is exact arithmetic, so the table below is a contract,
/// not documentation: the test lane asserts it against an independent
/// floating-point evaluation of the same formula.
///
/// | n    | 2 | 3 | 4 | 5 | 6 | 8 | 16 | 32 | 64 | 128 | 256 | 512 | 1024 | 2048 | 4096 |
/// |------|---|---|---|---|---|---|----|----|----|-----|-----|-----|------|------|------|
/// | k(n) | 1 | 2 | 3 | 3 | 3 | 4 | 5  | 6  | 7  | 7   | 8   | 9   | 10   | 10   | 11   |
pub(crate) const fn degree_target(n: usize) -> usize {
  // A cluster of one has no peers: degree zero is the only reachable
  // state and the healthy predicate must agree.
  if n <= 1 {
    return 0;
  }
  let n = n as u128;
  let peers = n - 1;
  let mut k: u128 = 1;
  loop {
    // q = (1 − k/(n−1))^(n−1) in fixed point: one factor per node,
    // each multiplication rounds down, so q only under-estimates —
    // compensated by the threshold's outward rounding.
    let mut q: u128 = DEGREE_SCALE;
    let mut round: u128 = 0;
    while round < peers {
      q = q * (peers - k) / peers;
      round += 1;
    }
    if n * q <= DEGREE_THRESHOLD_SCALED {
      return k as usize;
    }
    k += 1;
    // k = n−1 zeroes the product: the clamp terminates the loop.
    if k >= peers {
      return peers as usize;
    }
  }
}

/// One maintenance decision: the target in force, the resulting health,
/// and how many dials the tick should spend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DegreePlan {
  /// The effective target: the operator override when nonzero, the
  /// derived `k(n)` otherwise.
  pub(crate) target: usize,
  pub(crate) state: crate::ConnectionDegreeState,
  /// The dial budget for this tick: the session deficit, except that a
  /// fully offline node (zero sessions, cluster size > 1) dials nothing
  /// — the recovery plane's high-frequency backoff owns that case.
  pub(crate) dial_budget: usize,
}

/// Computes one maintenance decision from the observed state: `n` is
/// the active member count including this node, `override_target` the
/// configured degree (`0` = derived), `sessions` the live authenticated
/// session count.
pub(crate) const fn degree_plan(n: usize, override_target: usize, sessions: usize) -> DegreePlan {
  let target = if override_target == 0 {
    degree_target(n)
  } else {
    override_target
  };
  let state = if sessions >= target {
    crate::ConnectionDegreeState::Healthy
  } else {
    crate::ConnectionDegreeState::Unhealthy
  };
  let dial_budget = if sessions == 0 && n > 1 {
    // Fully offline: the recovery plane is already retrying the member
    // table at its high-frequency cadence; maintenance stays out of the
    // way until at least one route exists.
    0
  } else {
    target.saturating_sub(sessions)
  };
  DegreePlan {
    target,
    state,
    dial_budget,
  }
}

/// Picks up to `dial_budget` distinct dial candidates: uniformly random
/// members outside the connected set and never the local node, by
/// partial Fisher–Yates over the eligible members with entropy-sourced
/// indices. Every candidate carries ALL of its published endpoints —
/// the caller rotates through them across attempts (endpoint-level
/// failover aligned with the recovery plane, remaining-items list
/// P2-5) — so a multi-homed member's later endpoints stay dial
/// candidates instead of being projected away at selection time.
/// Returns fewer than the budget only when fewer members are
/// eligible. The index draw reduces one entropy word modulo the
/// remaining candidate count — the modulo bias is below `2^-32` for any
/// real cluster size and is deliberately accepted over an unbounded
/// rejection loop on the tick path.
pub(crate) fn select_degree_dials(
  dial_budget: usize, local: &NodeId, members: &BTreeMap<NodeId, Vec<Endpoint>>,
  connected: &BTreeSet<NodeId>, entropy: &dyn Entropy,
) -> Result<Vec<(NodeId, Vec<Endpoint>)>> {
  if dial_budget == 0 {
    return Ok(Vec::new());
  }
  let candidates: Vec<(NodeId, Vec<Endpoint>)> = members
    .iter()
    .filter(|(node, _)| *node != local && !connected.contains(*node))
    .map(|(node, endpoints)| (node.clone(), endpoints.clone()))
    .collect();
  let take = dial_budget.min(candidates.len());
  let mut candidates = candidates;
  let mut chosen = Vec::with_capacity(take);
  for index in 0..take {
    let remaining = candidates.len() - index;
    let swap = index + uniform_below(entropy, remaining)?;
    candidates.swap(index, swap);
    chosen.push(candidates[index].clone());
  }
  Ok(chosen)
}

/// One uniform index below `bound` from the injected entropy.
fn uniform_below(entropy: &dyn Entropy, bound: usize) -> Result<usize> {
  debug_assert!(bound > 0);
  let mut word = [0_u8; 8];
  entropy.fill(&mut word)?;
  Ok((u64::from_le_bytes(word) % bound as u64) as usize)
}

#[cfg(test)]
mod tests {
  use std::collections::{BTreeMap, BTreeSet};

  use super::{degree_plan, degree_target, select_degree_dials};
  use crate::{
    ConnectionDegreeState, Endpoint, NodeId, api::Entropy, identity::testing::SequenceEntropy,
  };

  /// The shipped degree table: every constant below is asserted against
  /// an independent floating-point evaluation of the exact formula in
  /// `degree_table_matches_the_exact_formula`, so this test pins the
  /// shipped values and that one proves they are the formula's.
  #[test]
  fn degree_table_is_the_shipped_contract() {
    let table = [
      (1, 0),
      (2, 1),
      (3, 2),
      (4, 3),
      (5, 3),
      (6, 3),
      (7, 4),
      (8, 4),
      (9, 4),
      (10, 4),
      (16, 5),
      (32, 6),
      (64, 7),
      (128, 7),
      (256, 8),
      (512, 9),
      (1024, 10),
      (2048, 10),
      (4096, 11),
    ];
    for (n, k) in table {
      assert_eq!(degree_target(n), k, "degree_target({n})");
    }
  }

  /// The CI assertion binding the constant table to the formula: an
  /// independent f64 evaluation of
  /// `n·(1 − k/(n−1))^(n−1) ≤ −ln(0.9)` must agree with the integer
  /// implementation for every cluster size in the supported range.
  #[test]
  fn degree_table_matches_the_exact_formula() {
    let threshold = -(0.9_f64).ln();
    let expected = |n: usize| -> usize {
      if n <= 1 {
        return 0;
      }
      let peers = (n - 1) as f64;
      for k in 1..n {
        let lambda = n as f64 * (1.0 - k as f64 / peers).powf(peers);
        if lambda <= threshold {
          return k;
        }
      }
      n - 1
    };
    for n in 1..=4_096 {
      assert_eq!(degree_target(n), expected(n), "degree_target({n})");
    }
    for n in [8_192, 16_384, 32_768, 65_536] {
      assert_eq!(degree_target(n), expected(n), "degree_target({n})");
    }
  }

  /// The plan derives the target when no override is set, honors the
  /// override when it is, and reserves the zero-session case for the
  /// recovery plane.
  #[test]
  fn degree_plan_derives_overrides_and_defers_to_recovery() {
    // Derived: five nodes, one session, k(5) = 3 → unhealthy, budget 2.
    let plan = degree_plan(5, 0, 1);
    assert_eq!(plan.target, 3);
    assert_eq!(plan.state, ConnectionDegreeState::Unhealthy);
    assert_eq!(plan.dial_budget, 2);

    // Override: the operator's value replaces the derivation outright.
    let plan = degree_plan(5, 1, 1);
    assert_eq!(plan.target, 1);
    assert_eq!(plan.state, ConnectionDegreeState::Healthy);
    assert_eq!(plan.dial_budget, 0);

    // Zero means derived, per the setter's contract.
    assert_eq!(degree_plan(5, 0, 1).target, degree_plan(5, 0, 1).target);

    // Healthy: at target the budget is empty.
    let plan = degree_plan(64, 0, 7);
    assert_eq!(plan.target, 7);
    assert_eq!(plan.state, ConnectionDegreeState::Healthy);
    assert_eq!(plan.dial_budget, 0);

    // Fully offline with a real cluster: the recovery plane owns it.
    let plan = degree_plan(64, 0, 0);
    assert_eq!(plan.state, ConnectionDegreeState::Unhealthy);
    assert_eq!(plan.dial_budget, 0);

    // A single-node cluster is always healthy with no budget.
    let plan = degree_plan(1, 0, 0);
    assert_eq!(plan.target, 0);
    assert_eq!(plan.state, ConnectionDegreeState::Healthy);
    assert_eq!(plan.dial_budget, 0);

    // Single node with an operator override above zero: the state
    // reports the operator's target and the budget is the deficit; the
    // selection then finds no members and dials nothing.
    let plan = degree_plan(1, 3, 0);
    assert_eq!(plan.target, 3);
    assert_eq!(plan.state, ConnectionDegreeState::Unhealthy);
    assert_eq!(plan.dial_budget, 3);
  }

  fn member_map(entries: &[(u8, &[&str])]) -> BTreeMap<NodeId, Vec<Endpoint>> {
    entries
      .iter()
      .map(|(seed, addresses)| {
        (
          NodeId::parse(&format!("node-{seed:021}")).unwrap(),
          addresses
            .iter()
            .map(|address| Endpoint::parse(address).unwrap())
            .collect::<Vec<_>>(),
        )
      })
      .collect()
  }

  fn node(seed: u8) -> NodeId {
    NodeId::parse(&format!("node-{seed:021}")).unwrap()
  }

  /// A deterministic xorshift entropy for selection assertions.
  struct Xorshift(std::sync::Mutex<u64>);

  impl Xorshift {
    fn new(seed: u64) -> Self {
      Self(std::sync::Mutex::new(seed))
    }
  }

  impl std::fmt::Debug for Xorshift {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
      formatter.write_str("Xorshift")
    }
  }

  impl Entropy for Xorshift {
    fn fill(&self, buffer: &mut [u8]) -> crate::Result<()> {
      let mut state = *self.0.lock().unwrap();
      for chunk in buffer.chunks_mut(8) {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        *self.0.lock().unwrap() = state;
        let word = state.wrapping_mul(0x2545_F491_4F6C_DD1D).to_le_bytes();
        let take = chunk.len();
        chunk.copy_from_slice(&word[..take]);
      }
      Ok(())
    }
  }

  /// Selection never dials the local node, never dials a connected
  /// peer, stays inside the budget, returns distinct members, and
  /// carries EVERY published endpoint of a selected multi-homed member
  /// (the caller rotates through them across attempts —
  /// remaining-items list P2-5).
  #[test]
  fn selection_respects_budget_exclusions_distinctness_and_endpoints() {
    let local = node(0);
    let members = member_map(&[
      (1, &["wss://127.0.0.1:9001"]),
      (2, &["wss://127.0.0.1:9002"]),
      (3, &["wss://127.0.0.1:9003", "wss://10.0.0.3:9003"]),
      (4, &["wss://127.0.0.1:9004"]),
      (5, &["wss://127.0.0.1:9005"]),
    ]);
    let connected: BTreeSet<NodeId> = [node(1), node(2)].into_iter().collect();
    let entropy = Xorshift::new(0x5EED);

    let dials = select_degree_dials(2, &local, &members, &connected, &entropy).unwrap();
    assert_eq!(dials.len(), 2);
    let mut seen = BTreeSet::new();
    for (peer, endpoints) in &dials {
      assert_ne!(peer, &local, "selection must never dial the local node");
      assert!(
        !connected.contains(peer),
        "selection must never dial a connected peer"
      );
      assert!(
        seen.insert(peer.clone()),
        "selection must not repeat a peer"
      );
      let published = members
        .get(peer)
        .map(|expected| expected.as_slice())
        .unwrap_or(&[]);
      assert_eq!(
        endpoints, published,
        "selection must carry every published endpoint of the member"
      );
    }
  }

  /// With fewer eligible members than the budget, every eligible member
  /// is dialed exactly once; a zero budget dials nothing; the sequence
  /// is deterministic under a fixed entropy seed.
  #[test]
  fn selection_covers_every_candidate_and_is_deterministic() {
    let local = node(0);
    let members = member_map(&[
      (1, &["wss://127.0.0.1:9001"]),
      (2, &["wss://127.0.0.1:9002", "wss://10.0.0.2:9002"]),
      (3, &["wss://127.0.0.1:9003"]),
    ]);
    let connected = BTreeSet::new();

    let first = select_degree_dials(9, &local, &members, &connected, &Xorshift::new(0xAB)).unwrap();
    assert_eq!(first.len(), 3, "budget above the candidate count saturates");
    let second =
      select_degree_dials(9, &local, &members, &connected, &Xorshift::new(0xAB)).unwrap();
    assert_eq!(first, second, "the same seed must reproduce the same dials");

    let empty = select_degree_dials(0, &local, &members, &connected, &Xorshift::new(0xAB)).unwrap();
    assert!(empty.is_empty());

    // The local node is never its own candidate even when unconnected.
    let solo = select_degree_dials(4, &local, &members, &connected, &Xorshift::new(0xAB)).unwrap();
    assert!(solo.iter().all(|(peer, _)| peer != &local));
  }

  /// An entropy fault fails the tick's selection instead of silently
  /// dialing a skewed subset (the tick logs and retries next round).
  #[test]
  fn selection_propagates_entropy_faults() {
    let local = node(0);
    let members = member_map(&[(1, &["wss://127.0.0.1:9001"])]);
    struct Faulting;

    impl std::fmt::Debug for Faulting {
      fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Faulting")
      }
    }

    impl Entropy for Faulting {
      fn fill(&self, _buffer: &mut [u8]) -> crate::Result<()> {
        Err(crate::Error::provider(
          crate::ProviderErrorKind::Io,
          crate::ProviderErrorContext::Entropy,
        ))
      }
    }
    let error = select_degree_dials(1, &local, &members, &BTreeSet::new(), &Faulting).unwrap_err();
    assert_eq!(error.kind(), crate::ErrorKind::Io);
    assert_eq!(error.context(), "entropy");
    // The sequence-based entropy still selects.
    let dials = select_degree_dials(
      1,
      &local,
      &members,
      &BTreeSet::new(),
      &SequenceEntropy::default(),
    )
    .unwrap();
    assert_eq!(dials.len(), 1);
  }
}
