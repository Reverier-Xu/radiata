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

/// The resources lane's swept-predicate basis: one host-clock instant per
/// pass plus the configured removal-retention window — the sweep's own
/// contract and the one basis on which a gone store key reads as
/// reclaimed knowledge. One value per pass keeps every row the pass
/// judges (the scan boundary, the receive filter, the prune, and the
/// repair set) pinned to one instant, so the sweep's mirrors cannot
/// disagree with the sweep.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SweptBasis {
  pub(crate) swept_at: SystemTime,
  pub(crate) removal_retention: Duration,
}

/// One lane apply's outcome: the rows the store **refused** — decided
/// evidence it will refuse on every re-delivery, so they never enter an
/// engine.
pub(crate) struct LaneOutcome {
  pub(crate) refused: LaneRows,
}

/// The lane-agnostic collaborators one apply or receive filter needs:
/// the node's identity context (upgraded from the plane's weak handle),
/// the entropy source, and the event/revision handles the row
/// application reports through. Per-lane inputs are deliberately not
/// unioned in here: the session/authorization pair rides the apply hook
/// as explicit parameters, the resources lane's swept basis rides
/// [`SweptBasis`], and the tombstones lane self-serves its checkpoint
/// watermark from its own scan snapshot.
pub(crate) struct LaneContext<'a> {
  pub(crate) context: &'a Arc<LocalIdentityContext>,
  pub(crate) entropy: &'a Arc<dyn Entropy>,
  pub(crate) events: &'a Arc<EventHub>,
  pub(crate) revision: &'a MemberRevisionSignal,
}

/// One reconciliation lane's policy, implemented next to the module that
/// owns its rows. The plane calls exactly these hooks; no lane is
/// special-cased there.
pub(crate) trait Lane: std::fmt::Debug + Send + Sync + 'static {
  /// The lane this policy reconciles.
  fn id(&self) -> LaneId;

  /// The lane's canonical rows from one snapshot: every owned namespace
  /// scanned in key order and the lane's decode gate applied. The lane's
  /// per-scan inputs are its own: the tombstones lane self-serves its
  /// collected-row watermark from the same snapshot (so the scan and its
  /// filter judge one store instant), and the lane's reclaimed evidence
  /// is skipped at the scan boundary — it never primes a peer either.
  fn scan<'a>(&self, snapshot: &'a dyn StoreSnapshot) -> BoxFuture<'a, Result<LaneRows>>;

  /// Whether one engine row is reclaimed evidence the store will never
  /// hold again (a collected tombstone, a retention-swept removal): the
  /// prune and the derived-view repair both read it. `key_present` is
  /// whether the store scan listed the row's key at all. The two bases a
  /// reclaim predicate can judge against ride the call — the swept
  /// basis and the cleanup-checkpoint watermark — and each lane reads
  /// only its own ([`SweptBasis`] is no union of per-lane inputs; the
  /// defaults ignore both).
  fn reclaimed(
    &self, _key_present: bool, _key: &[u8], _content: &[u8], _basis: &SweptBasis,
    _checkpoint: Option<u64>,
  ) -> bool {
    false
  }

  /// Whether the lane's reclaim predicate judges rows against the
  /// collected-tombstone watermark: the plane reads the watermark once
  /// per pass for the prune and the repair set, and only when a planned
  /// lane needs it (the scan side self-serves from its own snapshot).
  fn reads_checkpoint(&self) -> bool {
    false
  }

  /// The receive filter: drops the rows of one inbound message that must
  /// never enter an engine (reclaimed evidence a peer re-delivered).
  /// `basis` is the pass's swept-predicate basis, one instant for every
  /// row the filter judges.
  fn receive<'a>(
    &self, _ctx: &'a LaneContext<'a>, _basis: &'a SweptBasis, _rows: &'a mut LaneRows,
  ) -> BoxFuture<'a, Result<()>> {
    Box::pin(async { Ok(()) })
  }

  /// Applies one batch of rows through the lane's merge semantics and
  /// returns the rows the lane refused (see [`LaneOutcome`]). The
  /// session table and the authorization boundary ride the hook as
  /// explicit parameters: only the lanes whose trust decisions serialize
  /// against them name them, so adding a lane input never widens this
  /// seam for every other lane.
  fn apply<'a>(
    &self, ctx: &'a LaneContext<'a>, rows: &'a LaneRows, source: Option<&'a NodeId>,
    runtime: Option<&'a RuntimeClient>, sessions: &'a SessionTable,
    authorization: &'a AuthorizationBoundary,
  ) -> BoxFuture<'a, Result<LaneOutcome>>;

  /// The lane's audit event for a settled quiet pass (the peer's
  /// last-seen whole-lane fingerprint equals ours).
  fn pass_settled(&self, _peer: &NodeId) {}

  /// The lane's audit event for `rows` rows it put on the wire.
  fn rows_emitted(&self, _rows: usize) {}
}

/// One lane registry row: the lane's policy object plus the wire code and
/// store namespaces the lane's own module owns. The values are the lane's
/// own constants — a row only projects them — so the single source of a
/// lane's identity stays in the lane's module and the registry stays the
/// one listing place.
pub(crate) struct LaneEntry {
  pub(crate) policy: &'static dyn Lane,
  pub(crate) code: u8,
  pub(crate) namespaces: &'static [&'static str],
}

/// The lane registry: the one managed registration entry point listing the
/// lane objects. Every lane projection ([`LaneId::all`], [`LaneId::code`],
/// [`LaneId::from_code`], [`LaneId::policy`], [`LaneId::namespaces`])
/// derives from these rows, so adding a lane is one row here plus the
/// lane's own module. The rows are
/// in [`LaneId`] variant order — the discriminant-indexed projections read
/// them through it, and the registry-alignment test pins the alignment.
pub(crate) const LANES: [LaneEntry; 4] = [
  LaneEntry {
    policy: &crate::membership::lane::DescriptorsLane,
    code: crate::membership::lane::DescriptorsLane::CODE,
    namespaces: &crate::membership::lane::DescriptorsLane::NAMESPACES,
  },
  LaneEntry {
    policy: &crate::identity::lane::TrustLane,
    code: crate::identity::lane::TrustLane::CODE,
    namespaces: &crate::identity::lane::TrustLane::NAMESPACES,
  },
  LaneEntry {
    policy: &crate::resource::lane::ResourcesLane,
    code: crate::resource::lane::ResourcesLane::CODE,
    namespaces: &crate::resource::lane::ResourcesLane::NAMESPACES,
  },
  LaneEntry {
    policy: &crate::membership::tombstone::TombstonesLane,
    code: crate::membership::tombstone::TombstonesLane::CODE,
    namespaces: &crate::membership::tombstone::TombstonesLane::NAMESPACES,
  },
];

impl LaneId {
  /// The lane's registry row. The discriminant indexes the registry
  /// directly, so the projections are total without fallibility — the
  /// registry-alignment test pins the row↔variant order this relies on.
  fn entry(self) -> &'static LaneEntry {
    &LANES[self as usize]
  }

  /// Every lane, in registry order: the single closed lane set the
  /// plane's active-lane passes derive from.
  pub(crate) fn all() -> impl Iterator<Item = LaneId> {
    LANES.iter().map(|entry| entry.policy.id())
  }

  /// The lane's immutable wire code: the `CODE` constant the lane's own
  /// module owns, read through the registry.
  pub(crate) fn code(self) -> u8 {
    self.entry().code
  }

  /// Resolves a wire code to a lane; unknown codes are `None` and fail
  /// closed at the decode boundary.
  pub(crate) fn from_code(code: u8) -> Option<Self> {
    LANES
      .iter()
      .find(|entry| entry.code == code)
      .map(|entry| entry.policy.id())
  }

  /// The lane's policy implementation: the registry object the plane
  /// dispatches the lane's hooks through.
  pub(crate) fn policy(self) -> &'static dyn Lane {
    self.entry().policy
  }

  /// The store namespaces this lane reconciles: the single lane↔namespace
  /// map the incremental scan plan and every lane scan derive from — the
  /// registry row's projection of the lane's own `NAMESPACES` constant.
  pub(crate) fn namespaces(self) -> &'static [&'static str] {
    self.entry().namespaces
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

/// The shared apply prologue: decodes each row and refuses — as decided
/// evidence the receive boundary keeps out of the engines — every row
/// that cannot decode or whose key does not equal the record's own
/// identity. Returns the decoded records with their row positions, plus
/// the refused rows in their original wire shape. One undecodable or
/// misattributed row skips with a diagnostic instead of failing the
/// batch: a whole-batch error would wedge the derived-view repair on the
/// same poison row forever (the scan side's corrupt-row policy, applied
/// at the apply boundary).
pub(crate) fn decode_identified<T>(
  rows: &LaneRows, row_kind: &str, decode: impl Fn(&[u8]) -> Result<T>,
  identity: impl Fn(&T) -> &[u8],
) -> (Vec<(usize, T)>, LaneRows) {
  let mut decoded: Vec<(usize, T)> = Vec::with_capacity(rows.len());
  let mut refused = LaneRows::new();
  for (index, (row_key, content)) in rows.iter().enumerate() {
    match decode(content) {
      Ok(record) if row_key.as_slice() == identity(&record) => {
        decoded.push((index, record));
      }
      Ok(_) => {
        tracing::debug!(row_kind = row_kind, "reconcile row skipped: key mismatch");
        refused.push((row_key.clone(), content.clone()));
      }
      Err(error) => {
        tracing::debug!(
          row_kind = row_kind,
          kind = ?error.kind(),
          "reconcile row skipped: undecodable"
        );
        refused.push((row_key.clone(), content.clone()));
      }
    }
  }
  (decoded, refused)
}

#[cfg(test)]
mod tests {
  use std::time::SystemTime;

  use super::{LANES, LaneId, SweptBasis};

  /// The lane registry rows align with the [`LaneId`] discriminants: the
  /// row order is the variant order — the total-indexing contract the
  /// discriminant projections ([`LaneId::entry`]) rely on.
  #[test]
  fn the_lane_registry_rows_align_with_the_lane_discriminants() {
    for (index, entry) in LANES.iter().enumerate() {
      assert_eq!(
        entry.policy.id() as usize,
        index,
        "registry row {index} is out of variant order"
      );
    }
  }

  /// The lane registry is closed and self-consistent: every wire lane
  /// has a policy that names the same lane, a unique wire code that
  /// round-trips through `from_code`, and at least one store namespace
  /// the registry projects from the lane's own constant.
  #[test]
  fn the_lane_registry_covers_every_wire_lane() {
    for lane in LaneId::all() {
      let policy = lane.policy();
      assert_eq!(policy.id(), lane);
      assert_eq!(LaneId::from_code(lane.code()), Some(lane));
      assert!(
        LaneId::all()
          .filter(|other| *other != lane)
          .all(|other| other.code() != lane.code()),
        "duplicate lane code for {lane:?}"
      );
      assert!(
        !lane.namespaces().is_empty(),
        "lane {lane:?} owns no namespace"
      );
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
    let basis = SweptBasis {
      swept_at: now,
      removal_retention: retention,
    };
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
    assert_eq!(
      LaneId::Resources
        .policy()
        .reclaimed(false, b"key", &expired, &basis, None),
      crate::resource::retention::reclaimed(false, &expired, now, retention)
    );
    assert!(
      LaneId::Resources
        .policy()
        .reclaimed(false, b"key", &expired, &basis, None),
      "an expired removal with the key gone is reclaimed evidence"
    );
    assert!(
      !LaneId::Resources
        .policy()
        .reclaimed(true, b"key", &expired, &basis, None)
    );

    // A collected leave row: the checkpoint watermark sits past the
    // record's stamp.
    let stamp = 1_000_u64;
    let mut key = vec![1_u8];
    key.extend_from_slice(b"node-000000000000000000007");
    let content = vec![0_u8];
    assert_eq!(
      LaneId::Tombstones
        .policy()
        .reclaimed(false, &key, &content, &basis, Some(stamp)),
      crate::membership::tombstone::collected_row(Some(stamp), &key, &content)
    );
    // An undecodable row is never collected evidence.
    assert!(
      !LaneId::Tombstones
        .policy()
        .reclaimed(false, &key, &content, &basis, Some(stamp))
    );

    // The append-only lanes never reclaim a row.
    for lane in [LaneId::Descriptors, LaneId::Trust] {
      assert!(
        !lane
          .policy()
          .reclaimed(false, b"key", &expired, &basis, None)
      );
    }
  }

  /// The scan filter inputs are read only for the lanes that judge rows
  /// against the collected-tombstone watermark.
  #[test]
  fn only_the_tombstone_lane_reads_the_checkpoint() {
    for lane in LaneId::all() {
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
    for lane in LaneId::all() {
      lane.policy().pass_settled(&peer);
      lane.policy().rows_emitted(3);
    }
  }
}
