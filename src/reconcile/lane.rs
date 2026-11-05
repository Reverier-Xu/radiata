//! The lane seam of the reconciliation plane: one [`Lane`] implementation
//! per reconciled key space, owned next to the module whose rows it
//! carries.
//!
//! The plane stays lane-agnostic: it plans the scan, drives the engines,
//! applies inbound rows, prunes the derived view, and emits the lane's
//! audit events. Everything lane-specific lives behind this trait — the
//! store namespaces, the row projection, the reclaimed-evidence
//! predicate, the receive filter, and the merge semantics — so a lane
//! change never edits the plane.
//!
//! The lane↔namespace map is [`LaneId::namespaces`]: the incremental scan
//! plan derives a dirty namespace's lane from it, and each lane's scan
//! derives its namespaces from the same list.

use std::{
  sync::Arc,
  time::{Duration, SystemTime},
};

use super::wire::LaneId;
use crate::{
  NodeId, Result,
  api::{BoxFuture, Entropy},
  identity::lifecycle::LocalIdentityContext,
  node::{EventHub, MemberRevisionSignal},
  provider::StoreSnapshot,
  runtime::RuntimeClient,
  session::stream::{AuthorizationBoundary, SessionTable},
};

/// One lane's canonical rows: `(key, content)` pairs in scan order.
pub(crate) type LaneRows = Vec<(Vec<u8>, Vec<u8>)>;

/// The per-scan filter inputs every row-judging phase reads: the tombstone
/// lane's collected-row watermark, the resources lane's swept-predicate
/// host-clock sample, and the configured removal retention window. One
/// value per scan keeps every row of a pass judged against one instant,
/// and naming the fields keeps the lane implementations from having to
/// agree on an argument order.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ScanFilters {
  pub(crate) checkpoint: Option<u64>,
  pub(crate) swept_at: SystemTime,
  pub(crate) removal_retention: Duration,
}

/// One lane apply's outcome: the rows the store **refused** — decided
/// evidence it will refuse on every re-delivery, so they never enter an
/// engine.
pub(crate) struct LaneOutcome {
  pub(crate) refused: LaneRows,
}

/// The lane-agnostic collaborators one apply or receive filter needs: the
/// node's identity context (upgraded from the plane's weak handle), the
/// entropy source, the event/revision/session/authorization handles the
/// row application reports through, and the two inputs the resources lane
/// judges reclaimed evidence against — one host-clock instant per call
/// plus the configured removal retention window, the same pair the scan
/// filters carry, so the prune and the receive filter read one predicate
/// against one instant.
pub(crate) struct LaneContext<'a> {
  pub(crate) context: &'a Arc<LocalIdentityContext>,
  pub(crate) entropy: &'a Arc<dyn Entropy>,
  pub(crate) events: &'a Arc<EventHub>,
  pub(crate) revision: &'a MemberRevisionSignal,
  pub(crate) sessions: &'a SessionTable,
  pub(crate) authorization: &'a AuthorizationBoundary,
  pub(crate) swept_at: SystemTime,
  pub(crate) removal_retention: Duration,
}

/// One reconciliation lane's policy, implemented next to the module that
/// owns its rows. The plane calls exactly these hooks; no lane is
/// special-cased there.
pub(crate) trait Lane: std::fmt::Debug + Send + Sync + 'static {
  /// The lane this policy reconciles.
  fn id(&self) -> LaneId;

  /// The store namespaces this lane reconciles: the single lane↔namespace
  /// map ([`LaneId::namespaces`] delegates here).
  fn namespaces(&self) -> &'static [&'static str];

  /// The lane's canonical rows from one snapshot: every owned namespace
  /// scanned in key order, the lane's decode gate applied, and the
  /// lane's reclaimed evidence skipped at the scan boundary (so it never
  /// primes a peer either).
  fn scan<'a>(
    &self, snapshot: &'a dyn StoreSnapshot, filters: &'a ScanFilters,
  ) -> BoxFuture<'a, Result<LaneRows>>;

  /// Whether one engine row is reclaimed evidence the store will never
  /// hold again (a collected tombstone, a retention-swept removal): the
  /// prune and the derived-view repair both read it. `key_present` is
  /// whether the store scan listed the row's key at all.
  fn reclaimed(
    &self, _key_present: bool, _key: &[u8], _content: &[u8], _filters: &ScanFilters,
  ) -> bool {
    false
  }

  /// Whether the lane's scan judges rows against the collected-tombstone
  /// watermark: the plane reads it once per scan, and only when a planned
  /// lane needs it.
  fn reads_checkpoint(&self) -> bool {
    false
  }

  /// The receive filter: drops the rows of one inbound message that must
  /// never enter an engine (reclaimed evidence a peer re-delivered).
  fn receive<'a>(
    &self, _ctx: &'a LaneContext<'a>, _rows: &'a mut LaneRows,
  ) -> BoxFuture<'a, Result<()>> {
    Box::pin(async { Ok(()) })
  }

  /// Applies one batch of rows through the lane's merge semantics and
  /// returns the rows the lane refused (see [`LaneOutcome`]).
  fn apply<'a>(
    &self, ctx: &'a LaneContext<'a>, rows: &'a LaneRows, source: Option<&'a NodeId>,
    runtime: Option<&'a RuntimeClient>,
  ) -> BoxFuture<'a, Result<LaneOutcome>>;

  /// The lane's audit event for a settled quiet pass (the peer's
  /// last-seen whole-lane fingerprint equals ours).
  fn pass_settled(&self, _peer: &NodeId) {}

  /// The lane's audit event for `rows` rows it put on the wire.
  fn rows_emitted(&self, _rows: usize) {}
}

impl LaneId {
  /// The lane's policy implementation.
  pub(crate) fn policy(self) -> &'static dyn Lane {
    let policy: &'static dyn Lane = match self {
      LaneId::Descriptors => &crate::membership::lane::DescriptorsLane,
      LaneId::Trust => &crate::identity::lane::TrustLane,
      LaneId::Resources => &crate::resource::lane::ResourcesLane,
      LaneId::Tombstones => &crate::membership::tombstone::TombstonesLane,
    };
    debug_assert_eq!(policy.id(), self, "lane policy registry mismatch");
    policy
  }

  /// The store namespaces this lane reconciles: the single lane↔namespace
  /// map the incremental scan plan and every lane scan derive from.
  pub(crate) fn namespaces(self) -> &'static [&'static str] {
    self.policy().namespaces()
  }
}

/// Scans every namespace the lane owns into rows, keeping the raw store
/// key and skipping rows the lane cannot decode. Corrupt rows are skipped
/// with a diagnostic — one bad row must not kill egress for every other
/// row (the page lanes' corrupt-row policy).
pub(crate) async fn scan_namespaces(
  snapshot: &(dyn StoreSnapshot + '_), namespaces: &'static [&'static str],
  decodable: impl Fn(&[u8], &[u8]) -> bool,
) -> Result<LaneRows> {
  let mut rows = LaneRows::new();
  for tag in namespaces {
    let namespace = crate::storage::families::namespace(tag)?;
    let mut scan = snapshot.scan(&namespace, &[]).await?;
    while let Some(entry) = scan.next().await? {
      let key = entry.key().as_bytes().to_vec();
      let value = entry.value().as_bytes().to_vec();
      if !decodable(&key, &value) {
        tracing::debug!(
          namespace = %tag,
          key = %String::from_utf8_lossy(&key),
          "reconcile lane scan skipped an undecodable row"
        );
        continue;
      }
      rows.push((key, value));
    }
  }
  Ok(rows)
}

#[cfg(test)]
mod tests {
  use std::time::SystemTime;

  use super::{LaneId, ScanFilters};

  /// The lane registry is total and self-consistent: every wire lane has a
  /// policy that names the same lane, and every policy owns at least one
  /// store namespace.
  #[test]
  fn the_lane_registry_covers_every_wire_lane() {
    for lane in LaneId::ALL {
      let policy = lane.policy();
      assert_eq!(policy.id(), lane);
      assert!(
        !policy.namespaces().is_empty(),
        "lane {lane:?} owns no namespace"
      );
      assert_eq!(lane.namespaces(), policy.namespaces());
    }
  }

  /// The tombstone lane's namespace map is the wire contract's kind table:
  /// the four terminal record families, in kind order.
  #[test]
  fn the_tombstone_lane_namespaces_follow_the_kind_table() {
    let expected: Vec<&str> = crate::reconcile::wire::TombstoneKind::ALL
      .into_iter()
      .map(|kind| kind.namespace_tag())
      .collect();
    assert_eq!(LaneId::Tombstones.namespaces(), expected.as_slice());
  }

  /// The reclaim predicates are the owning modules' exports, not plane
  /// copies: the resources lane reads the retention contract, the
  /// tombstones lane reads the collected-row watermark, and the two
  /// append-only lanes never reclaim a row.
  #[test]
  fn each_lane_reports_its_owning_modules_reclaim_predicate() {
    let now = SystemTime::now();
    let retention = crate::resource::retention::RESOURCE_REMOVAL_RETENTION;
    let name = crate::ResourceName::parse("radiata.woooo.tech/resources/lane").unwrap();
    let expired = crate::resource::ResourceRecordV1::new(
      name,
      crate::LabelValue::parse("document").unwrap(),
      crate::ResourceUri::parse("u://lane").unwrap(),
      crate::LabelSet::new(),
      1_000,
      crate::NodeId::parse("node-000000000000000000007").unwrap(),
      1,
      true,
    )
    .unwrap()
    .encode()
    .unwrap();
    let filters = ScanFilters {
      checkpoint: None,
      swept_at: now,
      removal_retention: retention,
    };
    assert_eq!(
      LaneId::Resources
        .policy()
        .reclaimed(false, b"key", &expired, &filters),
      crate::resource::retention::reclaimed(false, &expired, now, retention)
    );
    assert!(
      LaneId::Resources
        .policy()
        .reclaimed(false, b"key", &expired, &filters),
      "an expired removal with the key gone is reclaimed evidence"
    );
    assert!(
      !LaneId::Resources
        .policy()
        .reclaimed(true, b"key", &expired, &filters)
    );

    // A collected leave row: the checkpoint watermark sits past the
    // record's stamp.
    let stamp = 1_000_u64;
    let mut key = vec![1_u8];
    key.extend_from_slice(b"node-000000000000000000007");
    let content = vec![0_u8];
    let filters = ScanFilters {
      checkpoint: Some(stamp),
      swept_at: now,
      removal_retention: retention,
    };
    assert_eq!(
      LaneId::Tombstones
        .policy()
        .reclaimed(false, &key, &content, &filters),
      crate::membership::tombstone::collected_row(Some(stamp), &key, &content)
    );
    // An undecodable row is never collected evidence.
    assert!(
      !LaneId::Tombstones
        .policy()
        .reclaimed(false, &key, &content, &filters)
    );

    // The append-only lanes never reclaim a row.
    for lane in [LaneId::Descriptors, LaneId::Trust] {
      assert!(!lane.policy().reclaimed(false, b"key", &expired, &filters));
    }
  }

  /// The scan filter inputs are read only for the lanes that judge rows
  /// against the collected-tombstone watermark.
  #[test]
  fn only_the_tombstone_lane_reads_the_checkpoint() {
    for lane in LaneId::ALL {
      assert_eq!(
        lane.policy().reads_checkpoint(),
        lane == LaneId::Tombstones,
        "lane {lane:?}"
      );
    }
  }

  /// The default receive filter and audit hooks are no-ops for the lanes
  /// that do not override them: the plane calls them unconditionally.
  #[test]
  fn the_default_lane_hooks_are_no_ops() {
    let peer = crate::NodeId::parse("node-000000000000000000007").unwrap();
    for lane in [LaneId::Descriptors, LaneId::Trust] {
      lane.policy().pass_settled(&peer);
      lane.policy().rows_emitted(3);
    }
  }
}
