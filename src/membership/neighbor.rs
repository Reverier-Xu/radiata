//! Deterministic sparse neighbor planning.
//!
//! The planner and maintenance limiter are unit-verified; the surface is
//! intentionally dead in non-test builds.
#![cfg_attr(not(test), allow(dead_code))]
//!
//! Equal membership inputs produce the same bounded neighbor plan
//! with no self-edge or duplicate peer; reachability stays distinct from
//! the active topology (directly reachable non-policy endpoints remain
//! candidates only); churn restores the configured sparse cycle without
//! exceeding the peer bound; and slow candidates cannot exceed the bounded
//! maintenance concurrency.

use std::collections::BTreeSet;

use crate::{NodeId, Result};

/// One deterministic sparse neighbor plan for a local node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NeighborPlan {
  neighbors: Vec<NodeId>,
}

impl NeighborPlan {
  pub(crate) fn neighbors(&self) -> &[NodeId] {
    &self.neighbors
  }

  pub(crate) fn len(&self) -> usize {
    self.neighbors.len()
  }

  pub(crate) fn is_empty(&self) -> bool {
    self.neighbors.is_empty()
  }
}

/// Plans the sparse neighbor set for `local` over the membership.
/// The plan is a pure function of the inputs: the same membership always
/// yields the same bounded plan. The neighbors are the
/// `degree` next members in canonical order (wrapping), skipping self and
/// deduplicating, so the result is a sparse cycle with no self-edge.
pub(crate) fn plan_neighbors(
  local: &NodeId, members: &BTreeSet<NodeId>, degree: usize,
) -> Result<NeighborPlan> {
  let degree = degree.clamp(1, 64);
  if !members.contains(local) {
    // The local node is not part of the membership; it plans no neighbors.
    return Ok(NeighborPlan {
      neighbors: Vec::new(),
    });
  }
  // The number of possible neighbors excludes the local node itself. The
  // plan size is bounded by this availability, so a requested degree larger
  // than the membership cannot spin the cycle forever: the walk stops once
  // every possible neighbor is collected, keeping the plan a bounded,
  // deterministic function of the owner-marked inputs.
  let available = members.len().saturating_sub(1);
  let target = degree.min(available);
  let mut neighbors = Vec::with_capacity(target);
  if target == 0 {
    // A singleton membership has no possible neighbors.
    return Ok(NeighborPlan { neighbors });
  }
  // Walk the canonical cycle in place (no whole-population allocation):
  // the next `target` members after the local node, wrapping, skipping the
  // local node itself.
  let position = members
    .iter()
    .position(|member| member == local)
    .unwrap_or(0);
  let mut cursor = members.iter().cycle();
  for _ in 0..=position {
    cursor.next();
  }
  for next in cursor {
    if next == local {
      continue;
    }
    if !neighbors.contains(next) {
      neighbors.push(next.clone());
      if neighbors.len() >= target {
        break;
      }
    }
  }
  Ok(NeighborPlan { neighbors })
}

/// The bounded maintenance concurrency of one node: how many candidate
/// connects may be pending or active at once, and how many may be queued.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MaintenanceBounds {
  pub(crate) max_pending: usize,
  pub(crate) max_queue: usize,
}

impl MaintenanceBounds {
  pub(crate) fn new(max_pending: usize, max_queue: usize) -> Self {
    Self {
      max_pending,
      max_queue,
    }
  }
}

/// One slot tracked by the neighbor maintenance limiter: pending (in
/// flight) or queued. The limiter refuses work beyond the configured
/// bounds so slow or nonresponsive candidates cannot exceed the
/// pending-connect or queue limits.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct MaintenanceLoad {
  pending: usize,
  queued: usize,
}

impl MaintenanceLoad {
  /// Whether one more queued candidate would exceed the queue bound.
  pub(crate) fn can_queue(&self, bounds: MaintenanceBounds) -> bool {
    self.queued < bounds.max_queue
  }

  /// Starts one candidate connect (moves a queued slot to pending).
  pub(crate) fn start_connect(&mut self, bounds: MaintenanceBounds) -> Result<()> {
    if self.pending >= bounds.max_pending {
      return Err(crate::Error::overloaded("neighbor maintenance"));
    }
    self.pending += 1;
    if self.queued > 0 {
      self.queued -= 1;
    }
    Ok(())
  }

  /// Completes or fails one candidate connect.
  pub(crate) fn finish_connect(&mut self) {
    self.pending = self.pending.saturating_sub(1);
  }

  /// Queues one candidate; refuses when both bounds are exhausted.
  pub(crate) fn enqueue(&mut self, bounds: MaintenanceBounds) -> Result<()> {
    if !self.can_queue(bounds) {
      return Err(crate::Error::overloaded("neighbor maintenance"));
    }
    self.queued += 1;
    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use std::collections::BTreeSet;

  use super::{MaintenanceBounds, MaintenanceLoad, plan_neighbors};
  use crate::{ErrorKind, NodeId};

  fn node(value: u8) -> NodeId {
    NodeId::parse(&format!("node_{value:021}")).unwrap()
  }

  fn members(values: &[u8]) -> BTreeSet<NodeId> {
    values.iter().map(|value| node(*value)).collect()
  }

  /// Equal inputs produce the same bounded plan with no self-edge or
  /// duplicate peer.
  #[test]
  fn neighbor_plan_is_deterministic_and_clean() {
    let membership = members(&[1, 2, 3, 4, 5]);
    let first = plan_neighbors(&node(2), &membership, 3).unwrap();
    let second = plan_neighbors(&node(2), &membership, 3).unwrap();
    assert_eq!(first, second);

    let neighbors = first.neighbors();
    assert_eq!(neighbors.len(), 3);
    assert!(!neighbors.contains(&node(2)), "no self-edge");
    let unique: BTreeSet<&NodeId> = neighbors.iter().collect();
    assert_eq!(unique.len(), neighbors.len(), "no duplicates");
    // The sparse cycle wraps: node 2's next three are 3, 4, 5.
    assert_eq!(neighbors[0], node(3));
    assert_eq!(neighbors[2], node(5));
  }

  /// Churn (join/leave) restores the configured sparse cycle without
  /// exceeding the peer bound.
  #[test]
  fn neighbor_plan_recovers_under_churn_within_bound() {
    let mut membership = members(&[1, 2, 3, 4]);
    let before = plan_neighbors(&node(4), &membership, 2).unwrap();
    assert_eq!(before.neighbors(), &[node(1), node(2)]);

    // A new member joins; the plan re-derives deterministically.
    membership.insert(node(5));
    let after = plan_neighbors(&node(4), &membership, 2).unwrap();
    assert_eq!(after.neighbors().len(), 2);
    assert!(!after.neighbors().contains(&node(4)));

    // A member leaves; the cycle closes without exceeding the bound.
    membership.remove(&node(5));
    membership.remove(&node(1));
    let recovered = plan_neighbors(&node(4), &membership, 2).unwrap();
    assert_eq!(recovered.neighbors().len(), 2);
  }

  /// Slow candidates cannot exceed pending/queue limits.
  #[test]
  fn maintenance_limiter_bounds_pending_and_queue() {
    let bounds = MaintenanceBounds::new(2, 2);
    let mut load = MaintenanceLoad::default();

    // Queue up to the bound.
    load.enqueue(bounds).unwrap();
    load.enqueue(bounds).unwrap();
    assert!(load.enqueue(bounds).is_err());
    assert_eq!(
      load.enqueue(bounds).unwrap_err().kind(),
      ErrorKind::Overloaded
    );

    // Two in flight; a third pending is refused.
    load.start_connect(bounds).unwrap();
    load.start_connect(bounds).unwrap();
    assert_eq!(
      load.start_connect(bounds).unwrap_err().kind(),
      ErrorKind::Overloaded
    );

    // Completion frees a pending slot.
    load.finish_connect();
    load.start_connect(bounds).unwrap();
  }

  /// Reachability is distinct from active topology — a local node outside
  /// the membership plans no neighbors (candidates only).
  #[test]
  fn neighbor_plan_keeps_reachability_distinct() {
    let membership = members(&[1, 2, 3]);
    // Node 9 is reachable (has candidates) but not in the
    // membership; it must not create hidden sessions or edges.
    let plan = plan_neighbors(&node(9), &membership, 4).unwrap();
    assert!(plan.is_empty());
  }

  /// A requested degree that exceeds the membership must terminate with
  /// every available neighbor instead of spinning the canonical cycle.
  #[test]
  fn neighbor_plan_degree_beyond_membership_terminates_with_all_neighbors() {
    // Three members: the max possible plan size is two, but five are
    // requested. The plan must return both available neighbors and end.
    let membership = members(&[1, 2, 3]);
    let plan = plan_neighbors(&node(2), &membership, 5).unwrap();
    assert_eq!(plan.len(), 2);
    assert!(!plan.neighbors().contains(&node(2)), "no self-edge");
    let unique: BTreeSet<&NodeId> = plan.neighbors().iter().collect();
    assert_eq!(unique.len(), plan.len(), "no duplicates");
  }

  /// A singleton membership must terminate with an empty plan: there is no
  /// profile member to plan as a neighbor and the cycle has no exit.
  #[test]
  fn neighbor_plan_singleton_membership_terminates_empty() {
    let membership = members(&[7]);
    let plan = plan_neighbors(&node(7), &membership, 4).unwrap();
    assert!(plan.is_empty());
  }

  /// The exact-boundary degree (population minus one) still returns every
  /// possible neighbor and terminates.
  #[test]
  fn neighbor_plan_exact_available_degree_terminates() {
    let membership = members(&[1, 2, 3, 4]);
    let plan = plan_neighbors(&node(2), &membership, 3).unwrap();
    assert_eq!(plan.len(), 3);
    assert!(!plan.neighbors().contains(&node(2)));
  }
}

#[cfg(test)]
mod scale_tests {
  use std::collections::BTreeSet;

  use super::{MaintenanceBounds, MaintenanceLoad, plan_neighbors};
  use crate::NodeId;

  fn node_at(index: usize) -> NodeId {
    NodeId::parse(&format!("node_{index:021}")).unwrap()
  }

  /// The 1,024-node functional trend: the sparse planner and the
  /// maintenance limiter operate at cluster scale without a
  /// whole-population allocation or a rejection boundary.
  #[test]
  fn neighbor_plan_and_limiter_scale_to_1024_nodes() {
    let membership: BTreeSet<NodeId> = (0..1_024).map(node_at).collect();
    // The plan for a mid-cluster node is bounded and clean at scale.
    for local in [0_usize, 511, 1023] {
      let plan = plan_neighbors(&node_at(local), &membership, 4).unwrap();
      assert_eq!(plan.len(), 4, "degree four at scale for node {local}");
      assert!(!plan.neighbors().contains(&node_at(local)), "no self-edge");
      let unique: BTreeSet<&NodeId> = plan.neighbors().iter().collect();
      assert_eq!(unique.len(), 4, "no duplicate peer");
    }
    // The maintenance limiter bounds independent of the population.
    let bounds = MaintenanceBounds::new(4, 4);
    let mut load = MaintenanceLoad::default();
    for _ in 0..4 {
      load.enqueue(bounds).unwrap();
    }
    assert!(load.enqueue(bounds).is_err(), "queue bound holds at scale");
    for _ in 0..4 {
      load.start_connect(bounds).unwrap();
    }
    assert!(
      load.start_connect(bounds).is_err(),
      "pending bound holds at scale"
    );
  }
}
