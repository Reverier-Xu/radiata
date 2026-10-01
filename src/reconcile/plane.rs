//! The session-carried reconciliation plane: the phase-3 lane migration.
//!
//! One [`Engine`] per session and per lane lives behind this plane, fed
//! through the five attachment points of the engine's lane seam:
//!
//! 1. **local writes** — the driver's tick watches the store's register epoch
//!    (the `note_local_write` path); any advance rescans the lane namespaces
//!    and feeds every peer engine through [`Engine::insert_row`], then drives
//!    [`Drive::LocalChange`];
//! 2. **session frames** — the [`ReconcileConsumer`] receives admitted streams
//!    on the reconcile-v1 protocol, decodes one [`super::wire::Message`] per
//!    frame, and drives the sender's engine with [`Drive::Message`];
//! 3. **establishment and cadence** — a peer newly present in the alive set (or
//!    one whose engines an inbound frame created before the driver saw the
//!    session) is primed with the full lane row set and driven with
//!    [`Drive::RootExchange`]; every
//!    [`crate::sync_common::DETECTION_CADENCE_TICKS`] ticks a bounded rotation
//!    window of the alive set exchanges ROOTs — the quiet fallback that heals
//!    any loss the message-driven exchange never observed;
//! 4. **outbound** — every drive's returned messages encode through
//!    [`super::wire`] onto the session as one bounded body each, carried by the
//!    shared pump and admission-ack discipline
//!    ([`crate::sync_common::send_payload`]);
//! 5. **applied-rows fan-out** — rows a consumer applies propagate to every
//!    sibling session's engine of the same lane with `insert_row` plus
//!    [`Drive::LocalChange`] (the epidemic wave is hints between sessions;
//!    payload crosses each edge once).
//!
//! The engine set is append-only, so the plane enforces the
//! derived-view invariant in both directions on every epoch pass:
//! store rows flow into the engines (store → engine), and engine rows
//! missing from the store re-apply through the lane's merge semantics
//! (engine → store). The second direction is the row-shaped equivalent
//! of the watermark model's resend cadence: a tombstone skipped because
//! its binding had not converged yet retries on the next store write
//! (the binding's arrival is one), instead of on a fixed tick roll.
//!
//! Rows carry each lane's merge state in their content and apply through
//! the lane's existing semantics — descriptors batch into one
//! [`crate::membership::page::MembershipPage`] commit, trust bindings
//! adopt per record, resource records ride one
//! [`crate::resource::page::ResourcePage`] (preserving the per-writer
//! bounded wait), and tombstones verify against the trusted-binding set
//! exactly as the announcement plane does. The cleanup checkpoint GC is
//! untouched; collected tombstones fail open at the apply boundary
//! (a record at or before the local checkpoint watermark was collected
//! on purpose — re-persisting it would resurrect collected evidence).

use std::{
  collections::{BTreeMap, BTreeSet},
  sync::{Arc, Mutex},
};

use minicbor::bytes::ByteVec;

use super::{
  engine::{Drive, Engine},
  wire::{self, LaneId, Message},
};
use crate::{
  Error, IncomingStream, NodeId, ProtocolTag, Result,
  api::{BoxFuture, Entropy},
  extension_registry::{PacketConsumer, ProtocolDefinition},
  identity::lifecycle::LocalIdentityContext,
  node::{EventHub, MemberRevisionSignal},
  runtime::RuntimeClient,
  session::stream::SessionTable,
  sync_common::alive_peers,
};

/// The canonical protocol tag of the reconciliation stream.
pub(crate) const RECONCILE_PROTOCOL: &str = "radiata.woooo.tech/protocols/reconcile-v1";

/// The wire schema of one reconciliation frame: one encoded
/// [`super::wire::Message`] per body.
pub(crate) const RECONCILE_SCHEMA: &str = "radiata.woooo.tech/schemas/reconcile-v1";

/// The lanes this build carries on the engine. The migration walks the
/// lanes one commit at a time (descriptors, trust, resources,
/// tombstones); a lane joins this list only by migrating onto the
/// engine, and a lane not in it still rides the watermark walks.
const ACTIVE_LANES: [LaneId; 2] = [LaneId::Descriptors, LaneId::Trust];

/// The peers one tick drives with a cadence ROOT exchange: the bounded
/// fair window over the alive set — the old push-round bound repurposed
/// for the only steady traffic the plane has. ROOT bodies are tens of
/// bytes, so the bound is about per-tick dispatch discipline, not
/// bandwidth.
const ROOT_EXCHANGE_WINDOW: usize = 2;

/// The row identity for derived-view comparisons: the exact
/// `(key, content)` pair bytes.
fn row_identity(key: &[u8], content: &[u8]) -> Vec<u8> {
  let mut identity = Vec::with_capacity(key.len() + content.len() + 1);
  identity.extend_from_slice(key);
  identity.push(0);
  identity.extend_from_slice(content);
  identity
}

/// One lane's canonical rows: `(key, content)` pairs in scan order.
pub(crate) type LaneRows = Vec<(Vec<u8>, Vec<u8>)>;

/// The per-lane row sets of one scan pass.
type LaneScan = Vec<(LaneId, LaneRows)>;

/// The repair set's index: row identity to row, per lane.
type RepairIndex = BTreeMap<LaneId, BTreeMap<Vec<u8>, (Vec<u8>, Vec<u8>)>>;

/// One peer's plane state: one engine per active lane plus the cadence
/// counter. An unprimed entry exists but holds no rows yet (an inbound
/// frame created it before the driver saw the session); the next tick
/// primes it and opens with a root exchange.
struct PeerState {
  engines: BTreeMap<LaneId, Engine>,
  primed: bool,
  ticks_since_exchange: u32,
}

impl PeerState {
  fn fresh() -> Self {
    Self {
      engines: BTreeMap::new(),
      primed: false,
      ticks_since_exchange: 0,
    }
  }

  /// The peer's engine of one lane, created empty on first touch.
  fn engine(&mut self, lane: LaneId) -> &mut Engine {
    self
      .engines
      .entry(lane)
      .or_insert_with(|| Engine::new(lane))
  }
}

/// The driver-owned plane state behind one mutex: the per-peer engines
/// plus the rescan epoch and the cadence rotation point.
struct PlaneState {
  peers: BTreeMap<NodeId, PeerState>,
  /// The register epoch at the driver's last rescan pass.
  install_epoch: u64,
  /// The rotation continuation point for the cadence window.
  rotation: Option<NodeId>,
}

/// The plane's shared state: the per-peer engines plus the node-scoped
/// collaborators the lane apply paths run against. Both the consumer
/// (inbound frames) and the driver (the tick) go through the state
/// mutex; store-touching apply work always runs outside it.
pub(crate) struct PlaneShared {
  // Held weakly so the registry shared with a live node handle never
  // pins the node's metadata store after shutdown (the same rule the
  // membership sync consumer follows); a frame or tick arriving after
  // the runtime dropped is rejected as shutting down.
  context: std::sync::Weak<LocalIdentityContext>,
  entropy: Arc<dyn Entropy>,
  events: Arc<EventHub>,
  revision: MemberRevisionSignal,
  sessions: SessionTable,
  state: Mutex<PlaneState>,
}

impl PlaneShared {
  /// Locks the plane state; poisoning only follows a panic inside a
  /// drive, which is a bug, not an input condition.
  fn lock(&self) -> Result<std::sync::MutexGuard<'_, PlaneState>> {
    self
      .state
      .lock()
      .map_err(|_| Error::internal("reconcile plane"))
  }

  /// Upgrades the identity context: `None` means the runtime dropped
  /// while a frame or tick was still in flight.
  fn context(&self) -> Result<Arc<LocalIdentityContext>> {
    self
      .context
      .upgrade()
      .ok_or_else(|| Error::shutting_down("reconcile plane"))
  }
}

/// The node-scoped reconciliation plane: register the consumer, drive
/// the tick. Cheap to clone (one `Arc`).
#[derive(Clone)]
pub(crate) struct ReconcilePlane {
  shared: Arc<PlaneShared>,
}

impl ReconcilePlane {
  pub(crate) fn new(
    context: Arc<LocalIdentityContext>, entropy: Arc<dyn Entropy>, events: Arc<EventHub>,
    revision: MemberRevisionSignal, sessions: SessionTable,
  ) -> Self {
    Self {
      shared: Arc::new(PlaneShared {
        context: Arc::downgrade(&context),
        entropy,
        events,
        revision,
        sessions,
        state: Mutex::new(PlaneState {
          peers: BTreeMap::new(),
          install_epoch: 0,
          rotation: None,
        }),
      }),
    }
  }

  pub(crate) fn shared(&self) -> Arc<PlaneShared> {
    Arc::clone(&self.shared)
  }

  /// The protocol definition that gates the reconciliation stream on
  /// authenticated sessions: owned by the data-messages feature both
  /// sides select.
  pub(crate) fn protocol_definition() -> Result<ProtocolDefinition> {
    Ok(ProtocolDefinition::new(
      ProtocolTag::parse(RECONCILE_PROTOCOL)?,
      crate::FeatureTag::parse(crate::protocol::feature::DATA_MESSAGES)?,
    ))
  }

  /// One anti-entropy tick of the plane: prime fresh peers (full row
  /// set plus a root exchange), rescan the lane namespaces on every
  /// register-epoch advance and drive local changes, exchange ROOTs
  /// with the cadence window, and drain every engine's backlog. The
  /// epoch pass also collects the derived-view repair set — engine rows
  /// the store still lacks — and re-applies it outside the lock.
  pub(crate) async fn tick(&self, runtime: &RuntimeClient) -> Result<()> {
    let context = self.shared.context()?;
    let store = context.store();
    // The same quiescence probe the membership tick uses: before any
    // member is admitted the node's store writes are quiescent, keeping
    // the admission commit sequence deterministic for fault-injecting
    // providers.
    if !crate::identity::trust::store::has_more_than_bindings(store, 1).await? {
      return Ok(());
    }
    let peers = alive_peers(&self.shared.sessions)?;
    if peers.is_empty() {
      // Nothing can be delivered with no live sessions. Dropping the
      // per-peer engines means a returning peer is caught up in full —
      // including everything written while it was unreachable.
      let mut guard = self.shared.lock()?;
      guard.peers.clear();
      guard.rotation = None;
      return Ok(());
    }
    let epoch = store.register_epoch();
    // Fresh peers prime with a full row set even on a quiet epoch, so
    // the scan runs whenever any peer needs its first fill.
    let has_unprimed = {
      let mut guard = self.shared.lock()?;
      guard.peers.retain(|peer, _| peers.contains(peer));
      peers
        .iter()
        .any(|peer| guard.peers.get(peer).is_none_or(|state| !state.primed))
    };
    let rescan = has_unprimed || epoch != self.shared.lock()?.install_epoch;
    let rows: LaneScan = if rescan {
      scan_lanes(store).await?
    } else {
      Vec::new()
    };
    let mut outbound: Vec<(NodeId, Message)> = Vec::new();
    let mut repair: LaneScan = Vec::new();
    {
      let mut guard = self.shared.lock()?;
      if rescan {
        guard.install_epoch = epoch;
      }
      for peer in &peers {
        let state = guard
          .peers
          .entry(peer.clone())
          .or_insert_with(PeerState::fresh);
        for (lane, lane_rows) in &rows {
          let engine = state.engine(*lane);
          for (key, content) in lane_rows {
            if let Err(error) = engine.insert_row(key, content) {
              tracing::debug!(
                lane = ?lane,
                kind = ?error.kind(),
                "reconcile row skipped at the local-write boundary"
              );
            }
          }
        }
        if !state.primed {
          // Session establishment: the full row set is in, the root
          // exchange opens the first negotiation.
          state.primed = true;
          state.ticks_since_exchange = 0;
          for lane in ACTIVE_LANES {
            match state.engine(lane).drive(Drive::RootExchange) {
              Ok(messages) => {
                outbound.extend(messages.into_iter().map(|message| (peer.clone(), message)));
              }
              Err(error) => {
                tracing::debug!(lane = ?lane, kind = ?error.kind(), "reconcile prime failed");
              }
            }
          }
        } else if rescan {
          for lane in ACTIVE_LANES {
            match state.engine(lane).drive(Drive::LocalChange) {
              Ok(messages) => {
                outbound.extend(messages.into_iter().map(|message| (peer.clone(), message)));
              }
              Err(error) => {
                tracing::debug!(lane = ?lane, kind = ?error.kind(), "reconcile change failed");
              }
            }
          }
        }
      }
      if rescan {
        // The derived-view repair set: engine rows the store scan did
        // not list, deduplicated across peers.
        let listed: BTreeMap<LaneId, BTreeSet<Vec<u8>>> = rows
          .iter()
          .map(|(lane, lane_rows)| {
            (
              *lane,
              lane_rows
                .iter()
                .map(|(key, content)| row_identity(key, content))
                .collect(),
            )
          })
          .collect();
        let mut seen: BTreeMap<LaneId, BTreeSet<Vec<u8>>> = BTreeMap::new();
        let mut pending: RepairIndex = BTreeMap::new();
        for state in guard.peers.values() {
          for (lane, engine) in &state.engines {
            let Some(known) = listed.get(lane) else {
              continue;
            };
            for (key, content) in engine.rows() {
              let identity = row_identity(key, content);
              if known.contains(&identity) {
                continue;
              }
              if seen.entry(*lane).or_default().insert(identity.clone()) {
                pending
                  .entry(*lane)
                  .or_default()
                  .insert(identity, (key.to_vec(), content.to_vec()));
              }
            }
          }
        }
        repair = pending
          .into_iter()
          .map(|(lane, rows)| (lane, rows.into_values().collect()))
          .collect();
      }
      // The cadence window: ROOT exchanges for the due peers a bounded
      // fair window of the alive set serves this tick.
      let due: Vec<NodeId> = guard
        .peers
        .iter()
        .filter(|(_, state)| state.primed)
        .filter(|(_, state)| {
          state.ticks_since_exchange >= crate::sync_common::DETECTION_CADENCE_TICKS
        })
        .map(|(peer, _)| peer.clone())
        .collect();
      for state in guard.peers.values_mut() {
        state.ticks_since_exchange = state.ticks_since_exchange.saturating_add(1);
      }
      let (window, rotation) =
        crate::sync_common::rotation_window(&due, guard.rotation.as_ref(), ROOT_EXCHANGE_WINDOW);
      guard.rotation = rotation.cloned();
      for peer in window.iter().copied() {
        if let Some(state) = guard.peers.get_mut(peer) {
          state.ticks_since_exchange = 0;
          for lane in ACTIVE_LANES {
            match state.engine(lane).drive(Drive::RootExchange) {
              Ok(messages) => {
                outbound.extend(messages.into_iter().map(|message| (peer.clone(), message)));
              }
              Err(error) => {
                tracing::debug!(lane = ?lane, kind = ?error.kind(), "reconcile cadence failed");
              }
            }
          }
        }
      }
      // Drain every engine's backlog behind the triggered drives.
      for peer in &peers {
        if let Some(state) = guard.peers.get_mut(peer) {
          for lane in ACTIVE_LANES {
            if let Some(engine) = state.engines.get_mut(&lane) {
              match engine.drive(Drive::Drain) {
                Ok(messages) => {
                  outbound.extend(messages.into_iter().map(|message| (peer.clone(), message)));
                }
                Err(error) => {
                  tracing::debug!(lane = ?lane, kind = ?error.kind(), "reconcile drain failed");
                }
              }
            }
          }
        }
      }
    }
    // The repair pass runs outside the peers lock: it touches the store.
    for (lane, lane_rows) in &repair {
      if lane_rows.is_empty() {
        continue;
      }
      tracing::debug!(lane = ?lane, rows = lane_rows.len(), "reconcile derived-view repair");
      if let Err(error) = apply_rows(&self.shared, lane, lane_rows, None, Some(runtime)).await {
        tracing::debug!(
          lane = ?lane,
          kind = ?error.kind(),
          "reconcile derived-view repair skipped rows"
        );
      }
    }
    for (peer, message) in outbound {
      send_message(&self.shared, runtime, &peer, message);
    }
    Ok(())
  }

  /// Delivers one decoded inbound message from `source`: drives the
  /// sender's engine, applies carried rows through the lane's merge
  /// semantics, fans the rows out to the sibling sessions' engines, and
  /// sends the results (responses to the source, hints to the
  /// siblings).
  pub(crate) async fn deliver(
    &self, runtime: &RuntimeClient, source: &NodeId, message: Message,
  ) -> Result<()> {
    let lane = message.lane();
    if !ACTIVE_LANES.contains(&lane) {
      // Fail closed exactly like a lane mismatch at the engine: the
      // registry carries one closed lane set, so an inactive lane on
      // the wire is foreign input.
      return Err(Error::invalid_input("reconcile lane"));
    }
    let rows: Vec<(Vec<u8>, Vec<u8>)> = match &message {
      Message::Rows { rows, .. } => rows
        .iter()
        .map(|row| (row.key.clone(), row.content.clone()))
        .collect(),
      _ => Vec::new(),
    };
    let mut outbound: Vec<(NodeId, Message)> = Vec::new();
    {
      let mut guard = self.shared.lock()?;
      let engine = guard
        .peers
        .entry(source.clone())
        .or_insert_with(PeerState::fresh)
        .engine(lane);
      let messages = engine.drive(Drive::Message(message))?;
      outbound.extend(
        messages
          .into_iter()
          .map(|message| (source.clone(), message)),
      );
    }
    if !rows.is_empty() {
      // Rows apply through the lane's merge semantics before any
      // fan-out observes them; a failed application still fans out —
      // propagation and application are decoupled (the derived-view
      // repair retries the application side on the next epoch pass).
      if let Err(error) = apply_rows(&self.shared, &lane, &rows, Some(source), Some(runtime)).await
      {
        tracing::debug!(lane = ?lane, kind = ?error.kind(), "reconcile rows apply failed");
      }
      let mut guard = self.shared.lock()?;
      for (peer, state) in guard.peers.iter_mut() {
        if peer == source || !state.primed {
          continue;
        }
        let engine = state.engine(lane);
        for (key, content) in &rows {
          if let Err(error) = engine.insert_row(key, content) {
            tracing::debug!(kind = ?error.kind(), "reconcile fan-out row skipped");
          }
        }
        match engine.drive(Drive::LocalChange) {
          Ok(messages) => {
            outbound.extend(messages.into_iter().map(|message| (peer.clone(), message)));
          }
          Err(error) => {
            tracing::debug!(kind = ?error.kind(), "reconcile fan-out drive failed");
          }
        }
      }
    }
    for (peer, message) in outbound {
      send_message(&self.shared, runtime, &peer, message);
    }
    Ok(())
  }
}

/// The core receiver of reconciliation streams over authenticated
/// sessions: one frame, one message, one drive.
pub(crate) struct ReconcileConsumer {
  shared: Arc<PlaneShared>,
}

impl ReconcileConsumer {
  pub(crate) fn new(shared: Arc<PlaneShared>) -> Self {
    Self { shared }
  }
}

impl std::fmt::Debug for ReconcileConsumer {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter.write_str("ReconcileConsumer(..)")
  }
}

impl PacketConsumer for ReconcileConsumer {
  fn accept<'a>(&'a self, mut packet: IncomingStream) -> BoxFuture<'a, Result<()>> {
    Box::pin(async move {
      let source = packet.source().clone();
      let runtime = packet.reply_runtime();
      let bytes = crate::sync_common::drain_body(packet.body(), "reconcile body").await?;
      let payload = crate::sync_common::decode_plain_sync_envelope(
        &bytes,
        RECONCILE_SCHEMA,
        "reconcile frame canonical form",
        "reconcile frame schema",
      )?;
      let message = wire::decode(payload.as_ref())?;
      let plane = ReconcilePlane {
        shared: Arc::clone(&self.shared),
      };
      plane.deliver(&runtime, &source, message).await
    })
  }
}

/// Sends one message to one peer: encode, envelope, one bounded body on
/// the shared pump with the admission-ack discipline. A dispatch
/// failure is diagnostics only — loss heals at the next root exchange.
fn send_message(shared: &PlaneShared, runtime: &RuntimeClient, peer: &NodeId, message: Message) {
  let lane = message.lane();
  let rows = match &message {
    Message::Rows { rows, .. } => rows.len(),
    _ => 0,
  };
  let Ok(encoded) = wire::encode(&message).and_then(|body| {
    crate::sync_common::encode_sync_envelope(RECONCILE_SCHEMA, None, ByteVec::from(body))
  }) else {
    tracing::debug!(lane = ?lane, "reconcile message encode failed");
    return;
  };
  // The redundancy ledger's sent side: the audit stream's
  // rows-to-installed ratio is the reconcile plane's equivalent of the
  // page counter it replaces.
  if rows > 0 && lane == LaneId::Descriptors {
    crate::audit::membership_page_emitted(rows);
  }
  let entropy = Arc::clone(&shared.entropy);
  let Ok(protocol) = ProtocolTag::parse(RECONCILE_PROTOCOL) else {
    return;
  };
  let runtime = runtime.clone();
  let peer = peer.clone();
  tokio::spawn(async move {
    match crate::sync_common::send_payload(&runtime, &entropy, &peer, &protocol, &encoded).await {
      Ok(ack) => {
        if !crate::sync_common::delivered_within_bound(ack).await {
          tracing::debug!(peer = %peer.as_str(), "reconcile message not admitted");
        }
      }
      Err(error) => {
        tracing::debug!(peer = %peer.as_str(), kind = ?error.kind(), "reconcile dispatch failed");
      }
    }
  });
}

/// Scans every active lane's namespaces into canonical
/// `(key, content)` rows. Corrupt rows are skipped with a diagnostic —
/// one bad row must not kill egress for every other row (the page
/// lanes' corrupt-row policy, carried over).
async fn scan_lanes(store: &crate::storage::MetadataStore) -> Result<LaneScan> {
  let snapshot = store.snapshot().await?;
  let mut lanes = Vec::new();
  for lane in ACTIVE_LANES {
    lanes.push((lane, scan_lane(snapshot.as_ref(), lane).await?));
  }
  Ok(lanes)
}

/// One lane's rows from a snapshot.
async fn scan_lane(
  snapshot: &(dyn crate::provider::StoreSnapshot + '_), lane: LaneId,
) -> Result<LaneRows> {
  let mut rows = Vec::new();
  match lane {
    LaneId::Descriptors => {
      scan_namespace(
        snapshot,
        crate::storage::families::namespace(crate::membership::NODE_DESCRIPTOR_NAMESPACE)?,
        |_key, value| crate::membership::page::decode_descriptor(value).is_ok(),
        &mut rows,
      )
      .await?;
    }
    LaneId::Trust => {
      scan_namespace(
        snapshot,
        crate::storage::families::namespace(crate::identity::records::IDENTITY_BINDING_NAMESPACE)?,
        |_key, value| crate::identity::records::IdentityBindingV1::decode(value).is_ok(),
        &mut rows,
      )
      .await?;
    }
    LaneId::Resources => {
      scan_namespace(
        snapshot,
        crate::resource::store::namespace()?,
        |_key, value| crate::resource::ResourceRecordV1::decode(value).is_ok(),
        &mut rows,
      )
      .await?;
    }
    LaneId::Tombstones => {
      for kind in [
        TombstoneKind::Leave,
        TombstoneKind::Cleanup,
        TombstoneKind::Revocation,
      ] {
        let mut raw = Vec::new();
        scan_namespace(
          snapshot,
          crate::storage::families::namespace(kind.namespace_tag())?,
          move |key, value| kind.decodable(key, value),
          &mut raw,
        )
        .await?;
        for (key, content) in raw {
          rows.push((kind.row_key(&key), content));
        }
      }
      // The cleanup checkpoint singleton: one row, max-wins at apply.
      let checkpoint = TombstoneKind::Checkpoint;
      let namespace =
        crate::storage::families::namespace(crate::storage::families::CHECKPOINT_NAMESPACE)?;
      let key = crate::StoreKey::new(std::sync::Arc::from(b"checkpoint".to_vec()));
      if let Some(value) = snapshot.get(&namespace, &key).await? {
        rows.push((checkpoint.row_key(b"checkpoint"), value.as_bytes().to_vec()));
      }
    }
  }
  Ok(rows)
}

/// Scans one namespace into rows, keeping the raw store key as the row
/// key and skipping rows the lane cannot decode.
async fn scan_namespace(
  snapshot: &(dyn crate::provider::StoreSnapshot + '_), namespace: crate::StoreNamespace,
  decodable: impl Fn(&[u8], &[u8]) -> bool, rows: &mut LaneRows,
) -> Result<()> {
  let mut scan = snapshot.scan_from(&namespace, &[], None).await?;
  while let Some(entry) = scan.next().await? {
    let key = entry.key().as_bytes().to_vec();
    let value = entry.value().as_bytes().to_vec();
    if !decodable(&key, &value) {
      tracing::debug!(
        key = %String::from_utf8_lossy(&key),
        "reconcile lane scan skipped an undecodable row"
      );
      continue;
    }
    rows.push((key, value));
  }
  Ok(())
}

/// The tombstone lane's kind byte: one key space for the four terminal
/// record families (a subject can carry more than one kind).
#[derive(Clone, Copy)]
enum TombstoneKind {
  Leave,
  Cleanup,
  Revocation,
  Checkpoint,
}

impl TombstoneKind {
  fn prefix(&self) -> u8 {
    match self {
      Self::Leave => 1,
      Self::Cleanup => 2,
      Self::Revocation => 3,
      Self::Checkpoint => 4,
    }
  }

  fn namespace_tag(&self) -> &'static str {
    match self {
      Self::Leave => crate::storage::families::LEAVE_NAMESPACE,
      Self::Cleanup => crate::storage::families::CLEANUP_NAMESPACE,
      Self::Revocation => crate::storage::families::REVOCATION_NAMESPACE,
      Self::Checkpoint => crate::storage::families::CHECKPOINT_NAMESPACE,
    }
  }

  fn row_key(&self, subject: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(subject.len() + 1);
    key.push(self.prefix());
    key.extend_from_slice(subject);
    key
  }

  /// Whether a scanned row belongs to this kind (and decodes): the
  /// leave family's intent singleton is not a record and is skipped.
  fn decodable(&self, key: &[u8], value: &[u8]) -> bool {
    match self {
      Self::Leave => {
        !crate::identity::leave::is_intent_key(key)
          && crate::identity::leave::LeaveRecordV1::decode(value).is_ok()
      }
      Self::Cleanup => crate::identity::cleanup::CleanupRecordV1::decode(value).is_ok(),
      Self::Revocation => crate::identity::revocation::RevocationRecordV1::decode(value).is_ok(),
      Self::Checkpoint => crate::identity::cleanup::CleanupCheckpointV1::decode(value).is_ok(),
    }
  }
}

/// Applies one message batch of rows through the lane's merge
/// semantics. `source` is the sending peer when the rows arrived on the
/// wire (the leave receipt addresses it); the derived-view repair path
/// passes `None`.
async fn apply_rows(
  shared: &PlaneShared, lane: &LaneId, rows: &[(Vec<u8>, Vec<u8>)], source: Option<&NodeId>,
  runtime: Option<&RuntimeClient>,
) -> Result<()> {
  let context = shared.context()?;
  let store = context.store();
  match lane {
    LaneId::Descriptors => {
      let mut descriptors = Vec::with_capacity(rows.len());
      for (key, content) in rows {
        let descriptor = crate::membership::page::decode_descriptor(content)
          .map_err(|_| Error::invalid_input("reconcile descriptor row"))?;
        if key.as_slice() != descriptor.node().as_str().as_bytes() {
          return Err(Error::invalid_input("reconcile descriptor key"));
        }
        descriptors.push(descriptor);
      }
      for chunk in descriptors.chunks(crate::paging::PAGE_MAX_ITEMS) {
        let page = crate::membership::page::MembershipPage::new(chunk.to_vec(), None)?;
        let installed = crate::membership::store::apply_descriptor_batch_ctx(
          store,
          shared.entropy.as_ref(),
          &page,
        )
        .await?;
        for descriptor in chunk {
          if installed.contains(descriptor.node()) {
            // The audit event is the propagation path proof: a
            // descriptor exists on this peer only because these rows
            // carried it.
            crate::audit::descriptor_installed(descriptor.node().as_str(), descriptor.revision());
            crate::membership::sync::member_changed(
              &shared.events,
              &shared.revision,
              descriptor.node().clone(),
            );
          }
        }
      }
      Ok(())
    }
    LaneId::Trust => {
      for (key, content) in rows {
        let binding = crate::identity::records::IdentityBindingV1::decode(content)
          .map_err(|_| Error::invalid_input("reconcile binding row"))?;
        if key.as_slice() != binding.node().as_str().as_bytes() {
          return Err(Error::invalid_input("reconcile binding key"));
        }
        // The snapshot-accept policy, per record: transient contention
        // skips one binding (the repair retries it); everything else —
        // key substitution above all — fails closed.
        if let Err(error) = crate::identity::trust::store::adopt_binding_ctx(
          store,
          shared.entropy.as_ref(),
          binding.node(),
          binding.public_key(),
        )
        .await
        {
          if matches!(
            error.kind(),
            crate::ErrorKind::Conflict | crate::ErrorKind::NotReady
          ) {
            tracing::debug!(node = %binding.node(), "trust binding adoption skipped");
            continue;
          }
          return Err(error);
        }
      }
      Ok(())
    }
    LaneId::Resources => {
      let mut records = Vec::with_capacity(rows.len());
      for (key, content) in rows {
        let record = crate::resource::ResourceRecordV1::decode(content)
          .map_err(|_| Error::invalid_input("reconcile resource row"))?;
        if key.as_slice() != record.name().as_str().as_bytes() {
          return Err(Error::invalid_input("reconcile resource key"));
        }
        records.push(record);
      }
      for chunk in records.chunks(crate::paging::PAGE_MAX_ITEMS) {
        let page = crate::resource::page::ResourcePage::new(chunk.to_vec(), None)?;
        let installed =
          crate::resource::page::sync::apply_page_ctx(store, shared.entropy.as_ref(), &page)
            .await?;
        tracing::debug!(installed, "reconcile resource rows applied");
      }
      Ok(())
    }
    LaneId::Tombstones => {
      crate::membership::sync::apply_tombstone_rows(
        &context,
        &shared.entropy,
        &shared.events,
        &shared.revision,
        &shared.sessions,
        rows,
        source,
        runtime,
      )
      .await
    }
  }
}

#[cfg(test)]
mod tests {
  use std::sync::Arc;

  use super::scan_lanes;
  use crate::identity::lifecycle::LocalIdentityContext;

  fn node(value: u64) -> crate::NodeId {
    crate::NodeId::parse(&format!("node-{value:021}")).unwrap()
  }

  fn key(value: u64) -> crate::PublicKey {
    let signing = crate::identity::testing::scripted_signing(value);
    crate::PublicKey::from_bytes(signing.verifying_key().to_bytes())
  }

  async fn context_with_bindings(bindings: &[u64]) -> Arc<LocalIdentityContext> {
    let (_reference, factory) = crate::identity::testing::fresh_reference();
    let keys = crate::identity::testing::ScriptedKeys::full_at(9_100);
    let entropy = Arc::new(crate::identity::testing::SequenceEntropy::default());
    let context = Arc::new(
      crate::identity::testing::open_context(&factory, &keys, &entropy)
        .await
        .unwrap(),
    );
    for value in bindings {
      let (namespace, store_key) =
        crate::identity::records::identity_binding_key(&node(*value)).unwrap();
      let binding = crate::identity::records::IdentityBindingV1::new(node(*value), key(*value));
      crate::identity::trust::store::adopt_binding_ctx(
        context.store(),
        entropy.as_ref(),
        &node(*value),
        &key(*value),
      )
      .await
      .unwrap();
      let _ = (namespace, store_key, binding);
    }
    context
  }

  /// The trust lane's row projection: the binding namespace scans into
  /// one row per binding, keyed by the node id — the append-only key
  /// space the plane reconciles.
  #[tokio::test]
  async fn the_trust_lane_scans_one_row_per_binding() {
    let context = context_with_bindings(&[101, 102]).await;
    let lanes = scan_lanes(context.store()).await.unwrap();
    let trust = lanes
      .iter()
      .find(|(lane, _)| matches!(lane, super::super::wire::LaneId::Trust))
      .unwrap();
    assert_eq!(trust.1.len(), 2, "one row per adopted binding");
    for (row_key, _) in &trust.1 {
      let text = std::str::from_utf8(row_key).unwrap();
      assert!(text.starts_with("node-"), "keys are node ids: {text}");
    }
  }
}
