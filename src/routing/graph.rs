//! The node-local learned topology graph.
//!
//! Every routed delivery attempt the origin observes ends in one terminal
//! fact, and that fact is an observation about the path the attempt took:
//! either the path carried the stream to its destination, or it did not.
//! The graph keeps those observations per destination as directed edge
//! statistics — `(destination, from, to) -> (successes, failures,
//! last_seen)` — and answers one question: the cheapest known path from
//! this node to a destination, where an edge costs
//! `(failures + 1) / (successes + 1)`. An edge never observed costs one,
//! a reliably succeeding edge costs less, and an edge that keeps failing
//! grows arbitrarily expensive, so the default policy prefers the paths
//! that have been working and routes around the ones that have not.
//!
//! The graph is node-local and bounded: observations expire after
//! [`TOPOLOGY_EDGE_TTL`] and the population never exceeds
//! [`TOPOLOGY_MAX_ENTRIES`] edges (the least recently observed leaves
//! first). Paths are simple by construction (Dijkstra over non-negative
//! weights never revisits a settled node), which is what makes the plan
//! the origin computes loop-free: every hop of a planned path moves
//! strictly forward along it.
//!
//! The graph is deliberately not a reachability oracle: it only knows
//! paths some earlier attempt actually walked, and only from this node's
//! point of view. A destination it has never reached falls back to the
//! caller policy's own heuristic (for the built-in policy, the
//! trace-keyed single relay), so delivery works before anything has been
//! learned.

use std::{
  collections::{BTreeMap, BTreeSet},
  sync::Mutex,
  time::{Duration, SystemTime},
};

use crate::NodeId;

/// The maximum number of observed edges the graph retains. A node with a
/// large membership keeps bounded routing state: the least recently
/// observed edge leaves first.
pub(crate) const TOPOLOGY_MAX_ENTRIES: usize = 1_024;

/// How long one observation stays usable. Older edges are dropped so a
/// healed topology is re-learned instead of being avoided forever.
pub(crate) const TOPOLOGY_EDGE_TTL: Duration = Duration::from_secs(600);

/// The observed outcome of one routed delivery attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RouteOutcome {
  /// The attempt reached the destination's admission.
  Delivered,
  /// The attempt ended in a typed failure before admission.
  Failed,
}

/// The observation counters of one directed edge toward one destination.
#[derive(Clone, Copy, Debug)]
struct EdgeStats {
  successes: u32,
  failures: u32,
  last_seen: SystemTime,
}

impl EdgeStats {
  fn new(at: SystemTime) -> Self {
    Self {
      successes: 0,
      failures: 0,
      last_seen: at,
    }
  }

  /// The edge cost: one for a never-observed edge, less as successes
  /// accumulate, more as failures do.
  fn weight(&self) -> f64 {
    (f64::from(self.failures) + 1.0) / (f64::from(self.successes) + 1.0)
  }

  fn expired(&self, now: SystemTime) -> bool {
    now
      .duration_since(self.last_seen)
      .is_ok_and(|age| age >= TOPOLOGY_EDGE_TTL)
  }
}

/// One directed edge keyed by the destination it was observed toward.
type EdgeKey = (NodeId, NodeId, NodeId);

/// The guarded edge population.
#[derive(Default)]
struct GraphState {
  edges: BTreeMap<EdgeKey, EdgeStats>,
}

/// The node-local learned topology: bounded, pruned, and shared between
/// the routing plane (which records outcomes) and the default next-hop
/// policy (which plans over it).
#[derive(Default)]
pub(crate) struct TopologyGraph {
  state: Mutex<GraphState>,
}

impl TopologyGraph {
  pub(crate) fn new() -> Self {
    Self::default()
  }

  /// Records one attempt's outcome along `path`, which starts at `origin`
  /// (exclusive) and ends at `destination` (inclusive). Every edge of the
  /// attempt carries the same verdict: the attempt as a whole either
  /// delivered or did not, and the origin cannot attribute a failure to a
  /// single hop.
  pub(crate) fn record(
    &self, destination: &NodeId, origin: &NodeId, path: &[NodeId], outcome: RouteOutcome,
  ) {
    let Ok(mut state) = self.state.lock() else {
      // A poisoned graph loses observations, never routing: the policy
      // falls back to its unlearned heuristic.
      return;
    };
    let now = SystemTime::now();
    let mut previous = origin.clone();
    for hop in path {
      let stats = state
        .edges
        .entry((destination.clone(), previous.clone(), hop.clone()))
        .or_insert_with(|| EdgeStats::new(now));
      match outcome {
        RouteOutcome::Delivered => {
          stats.successes = stats.successes.saturating_add(1);
        }
        RouteOutcome::Failed => {
          stats.failures = stats.failures.saturating_add(1);
        }
      }
      stats.last_seen = now;
      previous = hop.clone();
    }
    prune(&mut state, now);
  }

  /// The cheapest known path from `origin` to `destination` over the
  /// learned edges, or `None` when nothing has been learned. The path
  /// excludes `origin`, ends at `destination`, and is simple; its first
  /// hop is always one of the live `peers` (a plan may only leave this
  /// node along a session it actually holds) and its length never exceeds
  /// `remaining_hops + 1` entries — the relays the budget pays for plus
  /// the destination, which the walk reaches before the budget is
  /// checked.
  pub(crate) fn path(
    &self, origin: &NodeId, destination: &NodeId, peers: &[NodeId], remaining_hops: u32,
  ) -> Option<Vec<NodeId>> {
    let budget = usize::try_from(remaining_hops).ok()?;
    if budget == 0 {
      return None;
    }
    let state = self.state.lock().ok()?;
    let now = SystemTime::now();
    // The adjacency of this destination's learned edges, expired
    // observations excluded.
    let mut adjacency: BTreeMap<NodeId, Vec<(NodeId, f64)>> = BTreeMap::new();
    for ((edge_destination, from, to), stats) in &state.edges {
      if edge_destination != destination || stats.expired(now) {
        continue;
      }
      adjacency
        .entry(from.clone())
        .or_default()
        .push((to.clone(), stats.weight()));
    }
    // Seed the search with the live peers this node holds an edge toward:
    // the first hop of any usable plan is a session this node can use.
    let mut distance: BTreeMap<NodeId, f64> = BTreeMap::new();
    let mut previous: BTreeMap<NodeId, NodeId> = BTreeMap::new();
    let mut frontier: BTreeSet<NodeId> = BTreeSet::new();
    for (peer, weight) in adjacency.get(origin).into_iter().flatten() {
      if !peers.contains(peer) {
        continue;
      }
      let better = distance.get(peer).is_none_or(|known| *weight < *known);
      if better {
        distance.insert(peer.clone(), *weight);
        previous.insert(peer.clone(), origin.clone());
        frontier.insert(peer.clone());
      }
    }
    // Dijkstra over non-negative weights. Ties resolve by canonical node
    // order, so the same observations always plan the same path.
    let mut settled: BTreeSet<NodeId> = BTreeSet::new();
    loop {
      let next = frontier
        .iter()
        .min_by(|left, right| {
          distance[*left]
            .total_cmp(&distance[*right])
            .then_with(|| left.cmp(right))
        })
        .cloned();
      let Some(current) = next else {
        break;
      };
      frontier.remove(&current);
      settled.insert(current.clone());
      if current == *destination {
        break;
      }
      let Some(edges) = adjacency.get(&current) else {
        continue;
      };
      let reached = distance[&current];
      for (to, weight) in edges {
        if settled.contains(to) {
          continue;
        }
        let candidate = reached + weight;
        let better = distance.get(to).is_none_or(|known| candidate < *known);
        if better {
          distance.insert(to.clone(), candidate);
          previous.insert(to.clone(), current.clone());
          frontier.insert(to.clone());
        }
      }
    }
    if !distance.contains_key(destination) {
      return None;
    }
    // Walk the predecessor chain back to the origin.
    let mut path = vec![destination.clone()];
    let mut cursor = destination.clone();
    while let Some(step) = previous.get(&cursor) {
      if *step == *origin {
        break;
      }
      path.push(step.clone());
      cursor = step.clone();
    }
    path.reverse();
    if path.len() > budget.saturating_add(1)
      || !path.first().is_some_and(|first| peers.contains(first))
    {
      return None;
    }
    Some(path)
  }

  /// The number of retained observations (diagnostics and tests).
  #[cfg(test)]
  pub(crate) fn len(&self) -> usize {
    self
      .state
      .lock()
      .map(|state| state.edges.len())
      .unwrap_or(0)
  }

  /// The observed cost of one edge (tests): the input the planner weighs.
  #[cfg(test)]
  pub(crate) fn edge_weight(
    &self, destination: &NodeId, from: &NodeId, to: &NodeId,
  ) -> Option<f64> {
    self
      .state
      .lock()
      .ok()?
      .edges
      .get(&(destination.clone(), from.clone(), to.clone()))
      .map(EdgeStats::weight)
  }
}

impl std::fmt::Debug for TopologyGraph {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter
      .debug_struct("TopologyGraph")
      .field(
        "edges",
        &self.state.lock().map(|state| state.edges.len()).ok(),
      )
      .finish()
  }
}

/// Drops expired observations, then the least recently observed edges
/// beyond the entry cap.
fn prune(state: &mut GraphState, now: SystemTime) {
  state.edges.retain(|_, stats| !stats.expired(now));
  while state.edges.len() > TOPOLOGY_MAX_ENTRIES {
    let oldest = state
      .edges
      .iter()
      .min_by(|(left_key, left), (right_key, right)| {
        left
          .last_seen
          .cmp(&right.last_seen)
          .then_with(|| left_key.cmp(right_key))
      })
      .map(|(key, _)| key.clone());
    match oldest {
      Some(key) => {
        state.edges.remove(&key);
      }
      None => break,
    }
  }
}

#[cfg(test)]
mod tests {
  use std::time::{Duration, SystemTime};

  use super::{EdgeStats, TOPOLOGY_EDGE_TTL, TOPOLOGY_MAX_ENTRIES, TopologyGraph};
  use crate::{NodeId, routing::graph::RouteOutcome};

  fn node(value: u8) -> NodeId {
    NodeId::parse(&format!("node-{value:021}")).unwrap()
  }

  fn path(values: &[u8]) -> Vec<NodeId> {
    values.iter().map(|value| node(*value)).collect()
  }

  // ---- success-rate weighted path selection ----

  /// The policy prefers the path whose edges have been delivering: a
  /// cheaper (better success rate) two-hop path beats a more expensive
  /// one, and a failed edge steers the plan away from the path that
  /// carries it.
  #[test]
  fn the_better_success_rate_wins_and_a_failed_edge_is_avoided() {
    let graph = TopologyGraph::new();
    let peers = path(&[2, 3]);
    // Path 1 -> 2 -> 9 delivered twice; path 1 -> 3 -> 9 failed twice.
    for _ in 0..2 {
      graph.record(&node(9), &node(1), &path(&[2, 9]), RouteOutcome::Delivered);
      graph.record(&node(9), &node(1), &path(&[3, 9]), RouteOutcome::Failed);
    }
    assert_eq!(
      graph.path(&node(1), &node(9), &peers, 4),
      Some(path(&[2, 9])),
      "the delivering path must win"
    );

    // Once the failing path starts working and the good one starts
    // failing, the plan follows the evidence instead of the history.
    for _ in 0..4 {
      graph.record(&node(9), &node(1), &path(&[2, 9]), RouteOutcome::Failed);
      graph.record(&node(9), &node(1), &path(&[3, 9]), RouteOutcome::Delivered);
    }
    assert_eq!(
      graph.path(&node(1), &node(9), &peers, 4),
      Some(path(&[3, 9])),
      "the plan must follow the current evidence"
    );
  }

  /// A learned multi-hop path is returned whole, and one longer than the
  /// remaining budget can carry is refused instead of dispatched into a
  /// doomed walk. The budget counts relays: a path of `relays + 1` entries
  /// (the relays plus the destination) fits a `relays` budget, because the
  /// origin's dispatch consumes none and arrival is checked before it.
  #[test]
  fn a_learned_path_is_returned_whole_and_respects_the_budget() {
    let graph = TopologyGraph::new();
    let peers = path(&[2, 4]);
    graph.record(
      &node(9),
      &node(1),
      &path(&[2, 5, 9]),
      RouteOutcome::Delivered,
    );
    assert_eq!(
      graph.path(&node(1), &node(9), &peers, 3),
      Some(path(&[2, 5, 9]))
    );
    assert_eq!(
      graph.path(&node(1), &node(9), &peers, 2),
      Some(path(&[2, 5, 9])),
      "a two-relay path fits a two-relay budget"
    );
    assert_eq!(
      graph.path(&node(1), &node(9), &peers, 1),
      None,
      "a two-relay path does not fit a one-relay budget"
    );
    assert_eq!(
      graph.path(&node(1), &node(9), &peers, 0),
      None,
      "an exhausted budget plans nothing"
    );
  }

  /// A plan may only leave along a live session: an edge whose first hop
  /// is not a current peer is unusable, and the search then finds the
  /// alternative that does start at a peer.
  #[test]
  fn a_plan_only_starts_at_a_live_peer() {
    let graph = TopologyGraph::new();
    graph.record(&node(9), &node(1), &path(&[2, 9]), RouteOutcome::Delivered);
    graph.record(&node(9), &node(1), &path(&[3, 9]), RouteOutcome::Delivered);
    // Node 2 is not a live peer any more (its session died).
    assert_eq!(
      graph.path(&node(1), &node(9), &path(&[3]), 4),
      Some(path(&[3, 9]))
    );
    assert_eq!(graph.path(&node(1), &node(9), &[], 4), None);
  }

  /// Nothing learned means no plan: the caller policy's own fallback
  /// decides, so delivery works before any evidence exists.
  #[test]
  fn an_unlearned_destination_has_no_plan() {
    let graph = TopologyGraph::new();
    assert_eq!(graph.path(&node(1), &node(9), &path(&[2, 3]), 4), None);
    // Observations toward another destination never leak into this one.
    graph.record(&node(8), &node(1), &path(&[2, 8]), RouteOutcome::Delivered);
    assert_eq!(graph.path(&node(1), &node(9), &path(&[2, 3]), 4), None);
  }

  // ---- bounded, pruned observations ----

  /// Expired observations stop steering the plan, and the entry cap keeps
  /// the population bounded by dropping the least recently observed edge.
  #[test]
  fn observations_expire_and_the_population_stays_bounded() {
    let graph = TopologyGraph::new();
    let now = SystemTime::now();
    // One observation that is already past its time to live.
    {
      let mut state = graph.state.lock().unwrap();
      state.edges.insert(
        (node(9), node(1), node(2)),
        EdgeStats {
          successes: 5,
          failures: 0,
          last_seen: now - TOPOLOGY_EDGE_TTL - Duration::from_secs(1),
        },
      );
    }
    assert_eq!(
      graph.path(&node(1), &node(9), &path(&[2]), 4),
      None,
      "an expired observation must not steer the plan"
    );
    // The next recorded observation prunes the expired row.
    graph.record(&node(9), &node(1), &path(&[3, 9]), RouteOutcome::Delivered);
    assert_eq!(graph.len(), 2, "the expired row left, the fresh one stayed");

    // Overflow the cap: the population stays at the cap.
    for index in 0..TOPOLOGY_MAX_ENTRIES + 16 {
      let hop = NodeId::parse(&format!("node-{:021}", index + 1)).unwrap();
      graph.record(&node(9), &node(1), &[hop], RouteOutcome::Delivered);
    }
    assert_eq!(graph.len(), TOPOLOGY_MAX_ENTRIES);
  }

  /// The edge cost is the documented ratio: one for an unobserved edge,
  /// smaller as successes accumulate, larger as failures do.
  #[test]
  fn the_edge_cost_follows_the_observed_ratio() {
    let at = SystemTime::now();
    let mut stats = EdgeStats::new(at);
    assert_eq!(stats.weight(), 1.0);
    stats.successes = 3;
    assert!(stats.weight() < 1.0);
    stats.failures = 5;
    assert!(stats.weight() > 1.0);
  }
}
