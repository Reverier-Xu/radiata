//! Node-owned endpoint candidate sets.
//!
//! An observed address becomes a candidate **for one authenticated
//! `NodeId`** and can never create, replace, or rebind an identity record:
//! candidates are identity-scoped routing hints, not identity. Duplicate
//! and reordered observations merge into one deterministic candidate set
//! per node, and candidates expire on host wall time so a readdressed peer
//! reconnects at its fresh candidates while stale or attacker-supplied
//! addresses cannot authorize a session (authentication always happens at
//! the handshake).

// The table is currently exercised only by its unit suite.
#![allow(dead_code)]

use std::{
  collections::BTreeMap,
  sync::Arc,
  time::{Duration, SystemTime},
};

use crate::{Endpoint, NodeId, Result};

/// One observed candidate endpoint for a node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CandidateEntry {
  endpoint: Endpoint,
  priority: i32,
  observed_at: SystemTime,
}

impl CandidateEntry {
  pub(crate) const fn new(endpoint: Endpoint, priority: i32, observed_at: SystemTime) -> Self {
    Self {
      endpoint,
      priority,
      observed_at,
    }
  }

  pub(crate) const fn endpoint(&self) -> &Endpoint {
    &self.endpoint
  }

  pub(crate) const fn priority(&self) -> i32 {
    self.priority
  }

  pub(crate) const fn observed_at(&self) -> SystemTime {
    self.observed_at
  }
}

/// The identity-scoped candidate set for one node: at most one entry per
/// endpoint, sorted deterministically by priority then canonical endpoint
/// text, so duplicate observations converge.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct CandidateSet {
  entries: BTreeMap<Endpoint, CandidateEntry>,
}

impl CandidateSet {
  /// Records one observation. An already-present endpoint keeps its
  /// canonical identity-scoped entry (same node) and refreshes provenance
  /// only if the observation is not stale; a candidate never crosses
  /// between peers because the set is keyed under one node.
  pub(crate) fn observe(&mut self, entry: CandidateEntry) {
    let endpoint = entry.endpoint().clone();
    match self.entries.get(&endpoint) {
      Some(existing) if existing.observed_at() > entry.observed_at() => {}
      _ => {
        self.entries.insert(endpoint, entry);
      }
    }
  }

  /// Removes candidates observed at or before `now` minus `ttl`.
  pub(crate) fn expire(&mut self, now: SystemTime, ttl: Duration) {
    let before = now.checked_sub(ttl).unwrap_or(SystemTime::UNIX_EPOCH);
    self
      .entries
      .retain(|_, entry| entry.observed_at() >= before);
  }

  /// The deterministic ordered candidate list: priority ascending, then
  /// canonical endpoint text.
  pub(crate) fn ordered(&self) -> Vec<CandidateEntry> {
    let mut entries: Vec<CandidateEntry> = self.entries.values().cloned().collect();
    entries.sort_by(|left, right| {
      left
        .priority()
        .cmp(&right.priority())
        .then_with(|| left.endpoint().as_str().cmp(right.endpoint().as_str()))
    });
    entries
  }

  pub(crate) fn len(&self) -> usize {
    self.entries.len()
  }

  pub(crate) fn is_empty(&self) -> bool {
    self.entries.is_empty()
  }
}

/// The node-scoped endpoint table.
#[derive(Clone, Debug, Default)]
pub(crate) struct EndpointTable {
  by_node: BTreeMap<NodeId, CandidateSet>,
}

impl EndpointTable {
  /// Records one observation for the authenticated `node`. The table never
  /// creates or mutates identity records: it only routes hints.
  pub(crate) fn observe(&mut self, node: NodeId, entry: CandidateEntry) {
    self.by_node.entry(node).or_default().observe(entry);
  }

  /// Expires candidates across all nodes at the injected wall-clock `now`.
  pub(crate) fn expire(&mut self, now: SystemTime, ttl: Duration) {
    for set in self.by_node.values_mut() {
      set.expire(now, ttl);
    }
    self.by_node.retain(|_, set| !set.is_empty());
  }

  /// The ordered candidates for one node, or an empty set when none are
  /// known or all have expired.
  pub(crate) fn candidates(&self, node: &NodeId) -> Vec<CandidateEntry> {
    self
      .by_node
      .get(node)
      .map(|set| set.ordered())
      .unwrap_or_default()
  }

  pub(crate) fn node_count(&self) -> usize {
    self.by_node.len()
  }
}

/// The shared table plus its configured candidate time-to-live.
#[derive(Clone)]
pub(crate) struct EndpointCandidates {
  table: Arc<std::sync::Mutex<EndpointTable>>,
  ttl: Duration,
}

impl EndpointCandidates {
  pub(crate) fn new(ttl: Duration) -> Self {
    Self {
      table: Arc::new(std::sync::Mutex::new(EndpointTable::default())),
      ttl,
    }
  }

  /// Records one authenticated observation.
  pub(crate) fn observe(&self, node: NodeId, endpoint: Endpoint, priority: i32, now: SystemTime) {
    if let Ok(mut table) = self.table.lock() {
      table.observe(node, CandidateEntry::new(endpoint, priority, now));
    }
  }

  /// Expires candidates at the injected wall-clock `now`.
  pub(crate) fn expire(&self, now: SystemTime) {
    if let Ok(mut table) = self.table.lock() {
      table.expire(now, self.ttl);
    }
  }

  /// The ordered candidates for one node at the injected wall-clock `now`,
  /// with expired entries already removed.
  pub(crate) fn candidates(&self, node: &NodeId, now: SystemTime) -> Result<Vec<CandidateEntry>> {
    let mut table = self
      .table
      .lock()
      .map_err(|_| crate::Error::internal("endpoint candidates"))?;
    table.expire(now, self.ttl);
    Ok(table.candidates(node))
  }

  pub(crate) fn ttl(&self) -> Duration {
    self.ttl
  }
}

#[cfg(test)]
mod tests {
  use std::time::{Duration, UNIX_EPOCH};

  use super::{CandidateEntry, CandidateSet, EndpointCandidates, EndpointTable};
  use crate::{Endpoint, NodeId};

  fn endpoint(host: &str) -> Endpoint {
    Endpoint::parse(&format!("wss://{host}:9000")).unwrap()
  }

  fn node(value: u8) -> NodeId {
    NodeId::parse(&format!("node_{value:021}")).unwrap()
  }

  fn at(seconds: u64) -> std::time::SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds)
  }

  // ---- Candidates bind to the authenticated identity ----

  #[test]
  fn endpoint_table_scopes_candidates_by_node_and_never_touches_identity() {
    let mut table = EndpointTable::default();
    table.observe(
      node(1),
      CandidateEntry::new(endpoint("one.example"), 0, at(100)),
    );
    table.observe(
      node(2),
      CandidateEntry::new(endpoint("two.example"), 0, at(100)),
    );

    // Candidates are identity-scoped: node 1 sees only its own.
    let one = table.candidates(&node(1));
    assert_eq!(one.len(), 1);
    assert_eq!(one[0].endpoint().host(), "one.example");
    assert_eq!(
      table.candidates(&node(2))[0].endpoint().host(),
      "two.example"
    );

    // The table is routing hints only; identity records are untouched (the
    // table has no identity mutation surface by construction).
    assert_eq!(table.node_count(), 2);
  }

  // ---- Deterministic candidate merging ----

  #[test]
  fn candidate_set_merges_duplicates_and_reorders_deterministically() {
    let mut set = CandidateSet::default();
    // Reordered and duplicate observations converge to one entry each.
    set.observe(CandidateEntry::new(endpoint("zeta"), 5, at(110)));
    set.observe(CandidateEntry::new(endpoint("alpha"), 1, at(100)));
    set.observe(CandidateEntry::new(endpoint("zeta"), 5, at(120)));
    set.observe(CandidateEntry::new(endpoint("middle"), 3, at(90)));

    let ordered = set.ordered();
    let hosts: Vec<&str> = ordered
      .iter()
      .map(|entry| entry.endpoint().host())
      .collect();
    // Priority ascending, then canonical text; duplicate "zeta" collapsed.
    assert_eq!(hosts, ["alpha", "middle", "zeta"]);
    assert_eq!(set.len(), 3);
  }

  // ---- Host wall-clock expiry ----

  #[test]
  fn candidates_expire_at_the_host_wall_clock_boundary() {
    let mut set = CandidateSet::default();
    set.observe(CandidateEntry::new(endpoint("fresh"), 0, at(200)));
    set.observe(CandidateEntry::new(endpoint("old"), 0, at(50)));

    // Normal expiry: at now=300 with ttl=100, "old" (observed at 50) is
    // gone, "fresh" (200) stays.
    set.expire(at(300), Duration::from_secs(100));
    let ordered = set.ordered();
    let hosts: Vec<&str> = ordered.iter().map(|e| e.endpoint().host()).collect();
    assert_eq!(hosts, ["fresh"]);

    // Wall-clock rollback/freeze delays expiry: at now=149 nothing expires.
    let mut set = CandidateSet::default();
    set.observe(CandidateEntry::new(endpoint("old"), 0, at(50)));
    set.expire(at(149), Duration::from_secs(100));
    assert_eq!(set.len(), 1);
    // A forward jump makes it immediately due.
    set.expire(at(151), Duration::from_secs(100));
    assert_eq!(set.len(), 0);
  }

  #[test]
  fn shared_candidates_expire_and_query_with_injected_clock() {
    let candidates = EndpointCandidates::new(Duration::from_secs(100));
    candidates.observe(node(7), endpoint("seven.example"), 0, at(1000));
    assert_eq!(candidates.candidates(&node(7), at(1099)).unwrap().len(), 1);
    // Forward jump past the boundary expires the only candidate.
    assert_eq!(candidates.candidates(&node(7), at(1101)).unwrap().len(), 0);
  }

  // ---- Readdress keeps the exact trusted key ----

  #[test]
  fn readdress_replaces_the_candidate_while_identity_stays_bound() {
    let candidates = EndpointCandidates::new(Duration::from_secs(300));
    candidates.observe(node(9), endpoint("old.example"), 0, at(100));
    // The node readdresses to a fresh endpoint.
    candidates.observe(node(9), endpoint("new.example"), 0, at(200));

    let ordered = candidates.candidates(&node(9), at(250)).unwrap();
    let hosts: Vec<&str> = ordered.iter().map(|e| e.endpoint().host()).collect();
    // Both are valid until the old one expires; the fresh one is present.
    assert!(hosts.contains(&"new.example"));
    assert!(hosts.contains(&"old.example"));

    // After the stale candidate expires, only the new address remains; the
    // peer still reconnects under the same node identity (key trust is
    // decided by the handshake, never by the address).
    let ordered = candidates.candidates(&node(9), at(410)).unwrap();
    let hosts: Vec<&str> = ordered.iter().map(|e| e.endpoint().host()).collect();
    assert_eq!(hosts, ["new.example"]);
  }
}
