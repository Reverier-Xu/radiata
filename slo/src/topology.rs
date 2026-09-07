//! The deterministic sixteen-node sparse topology (ADR-0005, SC-G10-P0-32).
//!
//! The final authenticated graph is a ring plus quarter-span chords: every
//! member keeps its two ring neighbours and two chord neighbours, giving a
//! sparse connected graph of exactly 32 undirected edges — the 64 final
//! directed directions the profile preflight verifies. The generation is
//! closed-form and seed-free, so the candidate ledger can freeze the exact
//! direction list, one exact three-hop path, and four designated
//! throughput edges without running any node.

use std::collections::BTreeMap;

/// The exact final population of the quantified profile.
pub const PROFILE_MEMBERS: usize = 16;

/// One undirected final-topology edge between two member indexes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Edge(pub usize, pub usize);

/// The exact 32 undirected edges of the final topology: the ring
/// `(i, i+1 mod n)` plus every quarter-span chord `(i, i+4 mod n)`.
///
/// # Panics
/// Never: the profile member count is a compile-time constant.
#[must_use]
pub fn profile_edges() -> Vec<Edge> {
  edges_for(PROFILE_MEMBERS)
}

/// The directed direction table: both orientations of every undirected
/// edge, exactly 64 final directions for the profile population.
#[must_use]
pub fn directed_directions() -> Vec<(usize, usize)> {
  let mut directions = Vec::new();
  for Edge(from, to) in profile_edges() {
    directions.push((from, to));
    directions.push((to, from));
  }
  directions
}

/// One exact three-hop path of the final topology, proven by breadth-first
/// search: the endpoints are three ring/chord hops apart and no shorter
/// path exists.
///
/// # Panics
/// Never: the profile topology always contains an exact three-hop pair.
#[must_use]
pub fn exact_three_hop() -> (usize, usize) {
  let from = 0;
  for to in 1..PROFILE_MEMBERS {
    if distance(from, to) == Some(3) {
      return (from, to);
    }
  }
  unreachable!("the profile topology always contains an exact three-hop pair");
}

/// The four designated throughput edges of the profile: one final edge in
/// every octant of the frozen edge list, used by the preflight throughput
/// probes.
#[must_use]
pub fn throughput_edges() -> [Edge; 4] {
  let edges = profile_edges();
  let octant = edges.len() / 4;
  [
    edges[0],
    edges[octant],
    edges[octant * 2],
    edges[octant * 3],
  ]
}

/// The breadth-first-search distance of one directed pair, or `None` when
/// the member index is out of range.
#[must_use]
pub fn distance(from: usize, to: usize) -> Option<usize> {
  if from >= PROFILE_MEMBERS || to >= PROFILE_MEMBERS {
    return None;
  }
  let mut neighbours = [const { Vec::new() }; PROFILE_MEMBERS];
  for Edge(a, b) in profile_edges() {
    neighbours[a].push(b);
    neighbours[b].push(a);
  }
  let mut distances = [usize::MAX; PROFILE_MEMBERS];
  distances[from] = 0;
  let mut frontier = std::collections::VecDeque::new();
  frontier.push_back(from);
  while let Some(node) = frontier.pop_front() {
    for &neighbour in &neighbours[node] {
      if distances[neighbour] == usize::MAX {
        distances[neighbour] = distances[node] + 1;
        frontier.push_back(neighbour);
      }
    }
  }
  match distances[to] {
    usize::MAX => None,
    found => Some(found),
  }
}

/// The deterministic per-source next-hop table over the frozen topology:
/// for every source, the first hop on a shortest path to every other
/// member. The harness distributes each source's row to that node so the
/// registered routing policy can resolve multi-hop routes.
#[must_use]
pub fn next_hop_table() -> BTreeMap<usize, BTreeMap<usize, usize>> {
  let mut neighbours = [const { Vec::new() }; PROFILE_MEMBERS];
  for Edge(a, b) in profile_edges() {
    neighbours[a].push(b);
    neighbours[b].push(a);
  }
  let mut table = BTreeMap::new();
  for source in 0..PROFILE_MEMBERS {
    let mut first_hop: BTreeMap<usize, usize> = BTreeMap::new();
    let mut distances = [usize::MAX; PROFILE_MEMBERS];
    distances[source] = 0;
    let mut frontier = std::collections::VecDeque::new();
    // Direct neighbours are their own first hop.
    for &neighbour in &neighbours[source] {
      distances[neighbour] = 1;
      first_hop.insert(neighbour, neighbour);
      frontier.push_back(neighbour);
    }
    while let Some(node) = frontier.pop_front() {
      let hop = first_hop[&node];
      for &neighbour in &neighbours[node] {
        if distances[neighbour] == usize::MAX {
          distances[neighbour] = distances[node] + 1;
          first_hop.insert(neighbour, hop);
          frontier.push_back(neighbour);
        }
      }
    }
    first_hop.remove(&source);
    table.insert(source, first_hop);
  }
  table
}

/// The closed-form edge list for a population of at least eight members:
/// the ring plus every quarter-span chord, exactly `2n` undirected edges.
fn edges_for(members: usize) -> Vec<Edge> {
  assert!(
    members >= 8,
    "the ring-plus-chord family is defined for at least eight members"
  );
  let chord = members / 4;
  let mut edges = Vec::with_capacity(members * 2);
  for node in 0..members {
    edges.push(Edge(node, (node + 1) % members));
  }
  for node in 0..members {
    edges.push(Edge(node, (node + chord) % members));
  }
  edges
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::collections::BTreeSet;

  // SC-G10-P0-32: the frozen direction table is exactly 64 directions —
  // 32 unique undirected edges, no self-loops, both orientations present.
  #[test]
  fn direction_table_is_exactly_sixty_four_directions() {
    let edges = profile_edges();
    assert_eq!(edges.len(), 32);
    let unique: BTreeSet<(usize, usize)> = edges
      .iter()
      .map(|Edge(a, b)| (*a.min(b), *b.max(a)))
      .collect();
    assert_eq!(unique.len(), 32);
    assert!(edges.iter().all(|Edge(a, b)| a != b));
    let directions = directed_directions();
    assert_eq!(directions.len(), 64);
    for Edge(a, b) in &edges {
      assert!(directions.contains(&(*a, *b)));
      assert!(directions.contains(&(*b, *a)));
    }
  }

  // The profile graph is connected, every member holds exactly four
  // neighbours, and no endpoint exceeds the population.
  #[test]
  fn profile_graph_is_connected_and_four_regular() {
    let mut degrees = vec![0_usize; PROFILE_MEMBERS];
    for Edge(a, b) in profile_edges() {
      assert!(a < PROFILE_MEMBERS && b < PROFILE_MEMBERS);
      degrees[a] += 1;
      degrees[b] += 1;
    }
    assert!(degrees.iter().all(|degree| *degree == 4));
    // Connected: every member is reachable from member zero.
    for member in 0..PROFILE_MEMBERS {
      assert!(
        distance(0, member).is_some(),
        "member {member} is unreachable"
      );
    }
  }

  // SC-G10-P0-32: one exact three-hop path exists — the endpoints are
  // three hops apart with no two-hop or one-hop shortcut.
  #[test]
  fn exact_three_hop_pair_has_breadth_first_distance_three() {
    let (from, to) = exact_three_hop();
    assert_eq!(distance(from, to), Some(3));
    let mut two_hops = BTreeSet::new();
    for Edge(a, b) in profile_edges() {
      if a == from {
        two_hops.insert(b);
      }
      if b == from {
        two_hops.insert(a);
      }
    }
    let mut neighbourhood = two_hops.clone();
    neighbourhood.insert(from);
    for middle in &two_hops {
      for Edge(a, b) in profile_edges() {
        if a == *middle && !neighbourhood.contains(&b) {
          assert_ne!(b, to, "a two-hop shortcut reached the three-hop endpoint");
        }
        if b == *middle && !neighbourhood.contains(&a) {
          assert_ne!(a, to, "a two-hop shortcut reached the three-hop endpoint");
        }
      }
    }
  }

  // The four throughput edges are distinct frozen final edges.
  #[test]
  fn throughput_edges_are_four_distinct_final_edges() {
    let throughput = throughput_edges();
    assert_eq!(throughput.len(), 4);
    let final_edges: BTreeSet<(usize, usize)> = profile_edges()
      .iter()
      .map(|Edge(a, b)| (*a.min(b), *b.max(a)))
      .collect();
    for Edge(a, b) in throughput {
      assert!(final_edges.contains(&(a.min(b), b.max(a))));
    }
    let unique: BTreeSet<(usize, usize)> = throughput
      .iter()
      .map(|Edge(a, b)| (*a.min(b), *b.max(a)))
      .collect();
    assert_eq!(unique.len(), 4);
  }

  // The distance helper rejects out-of-range members.
  #[test]
  fn distance_rejects_out_of_range_members() {
    assert_eq!(distance(0, PROFILE_MEMBERS), None);
    assert_eq!(distance(PROFILE_MEMBERS, 0), None);
    assert_eq!(distance(0, 0), Some(0));
  }

  // Every next hop lies on a shortest path: it is a live neighbour of the
  // source and the distance from the hop to the destination is exactly
  // one less than the source-to-destination distance.
  #[test]
  fn next_hop_table_rows_lie_on_shortest_paths() {
    let table = next_hop_table();
    assert_eq!(table.len(), PROFILE_MEMBERS);
    for (source, row) in &table {
      assert_eq!(row.len(), PROFILE_MEMBERS - 1);
      for (destination, hop) in row {
        assert_ne!(destination, source);
        assert_eq!(
          distance(*hop, *destination),
          distance(*source, *destination).map(|value| value - 1),
        );
        assert!(
          profile_edges()
            .iter()
            .any(|Edge(a, b)| (*a == *source && *b == *hop) || (*b == *source && *a == *hop)),
        );
      }
    }
  }
}
