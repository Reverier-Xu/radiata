//! The session-carried reconciliation plane: the phase-3 lane migration
//! plus the phase-4 trigger and adaptation layer.
//!
//! One [`Engine`] per session and per lane lives behind this plane, fed
//! through the five attachment points of the engine's lane seam:
//!
//! 1. **local writes** — the driver's tick reads the store's namespace-granular
//!    write epochs (the `note_local_write*` paths): only the lanes whose key
//!    spaces actually changed are rescanned, every other lane is zero-scan in
//!    the steady state (the incremental successor of the whole-catalog rescan;
//!    an un-namespaced note degrades to the full rescan so no write can hide);
//! 2. **session frames** — the [`ReconcileConsumer`] receives admitted streams
//!    on the reconcile v1 protocol, decodes one [`super::wire::Message`] per
//!    frame, and drives the sender's engine with [`Drive::Message`];
//! 3. **establishment and cadence** — a peer newly present in the alive set (or
//!    one whose engines an inbound frame created before the driver saw the
//!    session) is primed with the full lane row set and driven with
//!    [`Drive::RootExchange`]; every
//!    [`crate::sync_common::DETECTION_CADENCE_TICKS`] ticks (divided by the
//!    link profile's cadence multiplier on weak links) a bounded rotation
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
//! The per-lane pull serialization closes the payload-once invariant:
//! a node holds a sibling session's hint (rows still applying) while
//! any engine of the same lane but the source session's own has an
//! open round (a hint from the round's own session walks the engine's
//! pending-hint discipline instead), and the engine's root initiation
//! is ordered (`root_precedes`: the data-poorer side of an edge
//! initiates, so the richer side never pushes from a stale whole-lane
//! claim). One node, one negotiation per lane — two
//! parallel answerers can never race the same rows onto the wire
//! twice. Responses are never held: a peer's initiation must always
//! answer, or two nodes holding each other's hints would deadlock.
//!
//! The trigger layer rides the same five seams: a local write debounces
//! into the next tick's lane scan and leaves the engine as one coalesced
//! HINT (plus, on a healthy link, the eager-delta row piggyback — the
//! originator's bounded push head); a received HINT that matches the
//! local fingerprints is silence, and one that does not initiates the
//! negotiation; the quiet ROOT cadence is the loss-recovery backstop.
//! The per-session [`LinkProfile`] observes admission-ack latency and
//! loss and drives exactly three knobs — the cadence multiplier, the
//! hint retry budget, and the eager-delta toggle. The payload path is
//! untouched by all of them: rows cross a session only under
//! receiver-evidenced lack (or the bounded 4 KiB eager piggyback), never
//! as a loss premium.
//!
//! The engine set is append-only in *content* but not in *identity*: the
//! epoch pass enforces the derived-view invariant in both directions —
//! store rows flow into the engines (store → engine), and engine rows
//! missing from the store re-apply through the lane's merge semantics
//! (engine → store) — and the pass *prunes* engine rows the store scan
//! superseded (a descriptor revision bump or a resource-tuple loser left
//! an old `(key, content)` identity behind) or collected (a tombstone at
//! or before the cleanup-checkpoint watermark). Without the prune the
//! engine row set grows monotonically: superseded identities never leave
//! (lifetime memory growth), the repair set never empties (the store can
//! never take the old row back), and every newly primed peer re-receives
//! the whole historical row set. Collected tombstone rows are filtered
//! at the scan and the receive boundary alike (collected evidence never
//! enters an engine), so the checkpoint GC stops propagating reclaimed
//! rows. The same receive-boundary discipline gates the rows the lane's
//! apply *refuses* — a stale descriptor revision, a binding for a revoked
//! subject, an unhealable first install: a refused row never enters an
//! engine, because the store will refuse it again on every re-delivery
//! while the peers whose stores list it keep answering the resulting
//! fingerprint divergence with the same bytes — an unbounded
//! re-negotiation loop (the leave/restart livelock the transport-chaos
//! lane caught on a starved core). The apply still runs first and its
//! outcome decides the gate, so the lane's merge semantics stay the one
//! source of truth; the transient deferrals (a tombstone whose subject
//! binding has not converged, a contended binding adoption) keep their
//! engine rows — their retry is the cross-lane repair, exactly as before.
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
  time::Duration,
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
pub(crate) const RECONCILE_PROTOCOL: &str = "radiata.woooo.tech/protocols/v1/reconcile";

/// The wire schema of one reconciliation frame: one encoded
/// [`super::wire::Message`] per body.
pub(crate) const RECONCILE_SCHEMA: &str = "radiata.woooo.tech/schemas/v1/reconcile";

/// The lanes this build carries on the engine: all four (descriptors,
/// trust, resources, tombstones) migrated onto the plane, retiring the
/// watermark walks entirely.
const ACTIVE_LANES: [LaneId; 4] = [
  LaneId::Descriptors,
  LaneId::Trust,
  LaneId::Resources,
  LaneId::Tombstones,
];

/// The peers one tick drives with a cadence ROOT exchange: the bounded
/// fair window over the alive set — the old push-round bound repurposed
/// for the only steady traffic the plane has. ROOT bodies are tens of
/// bytes, so the bound is about per-tick dispatch discipline, not
/// bandwidth.
const ROOT_EXCHANGE_WINDOW: usize = 2;

/// The scan's derived view, both projections per lane: the exact row
/// identities (identity → row for the repair index) and the lane keys
/// under them (the prune's supersession oracle).
type LaneListed = BTreeMap<LaneId, (BTreeSet<Vec<u8>>, BTreeSet<Vec<u8>>)>;

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

/// One peer's plane state: one engine per active lane, the cadence
/// counter, the session's link profile, and the bounded hint-retry slot.
/// An unprimed entry exists but holds no rows yet (an inbound frame
/// created it before the driver saw the session); the next tick primes
/// it and opens with a root exchange.
struct PeerState {
  engines: BTreeMap<LaneId, Engine>,
  primed: bool,
  ticks_since_exchange: u32,
  profile: LinkProfile,
  hint_retry: Option<PendingHint>,
}

impl PeerState {
  fn fresh() -> Self {
    Self {
      engines: BTreeMap::new(),
      primed: false,
      ticks_since_exchange: 0,
      profile: LinkProfile::default(),
      hint_retry: None,
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

/// One undelivered hint awaiting its backoff on a weak link: the
/// message, the remaining retry budget, and the tick it may re-send at.
/// The slot arms once: a session already holding a retry keeps its
/// remaining attempts (a later undelivered hint does not replace it),
/// a recovered link drops its pending hint, and the budget's
/// exhaustion drops it (the detection cadence is the backstop, and
/// hints are advisory by contract).
struct PendingHint {
  message: Message,
  attempts_left: u8,
  resume_at_tick: u64,
}

/// The hint-retry budget on a weak link: four attempts with a doubling
/// backoff (1, 2, 4, 8 ticks), after which the cadence ROOT exchange
/// absorbs the loss — the hint is a summary, and its information never
/// expires, only its urgency does.
const HINT_RETRY_MAX: u8 = 4;

/// One session's link profile: the EWMA admission-ack latency (the
/// session's observable round trip) and the EWMA dispatch-loss rate,
/// observed on every message the plane sends the peer. The knobs the
/// profile drives are deliberately exactly three, all on the summary
/// side of the plane — the cadence multiplier, the hint retry budget,
/// and the eager-delta toggle. The payload path is never a knob: rows
/// cross a session only under receiver-evidenced lack, whatever the
/// link quality.
///
/// # The knob curve
///
/// The profile's weakness signal is one boolean with the thresholds
/// below; a session is **weak** when the loss EWMA is at least 10% or
/// the RTT EWMA is at least 1.5 s (a loopback or LAN session sits four
/// orders of magnitude below both; a WAN session under churn crosses
/// them), and healthy otherwise (including a fresh session with no
/// samples yet — knobs default open so a quiet but healthy link pays no
/// premium). The curve is a step, not a ramp, on purpose: two bands are
/// enough for the two failure shapes the audit measured (ack-starved
/// saturation and lossy long links), and every extra band is another
/// threshold to calibrate against the same evidence. The steps:
///
/// | knob | healthy | weak |
/// | --- | --- | --- |
/// | cadence multiplier | 1× (32 ticks) | 4× (8 ticks) |
/// | hint redundancy | one send, no retry | bounded backoff retry ([`HINT_RETRY_MAX`]) |
/// | eager-delta | on | off (a lost 4 KiB piggyback buys nothing) |
#[derive(Default)]
struct LinkProfile {
  /// The EWMA admission latency in milliseconds; `None` until the
  /// first delivered sample.
  rtt_ewma_ms: Option<f64>,
  /// The EWMA dispatch-loss rate in `[0, 1]` (1 = everything undelivered).
  loss_ewma: f64,
}

/// The RTT EWMA weight: one sample moves a quarter of the distance, so
/// the profile follows a real degradation within a few messages without
/// tracking single-message jitter.
const RTT_EWMA_ALPHA: f64 = 0.25;
/// The loss EWMA weight: slower than the RTT weight so a burst of drops
/// in one busy tick does not flap the knobs.
const LOSS_EWMA_ALPHA: f64 = 0.125;
/// The weakness thresholds: a loss EWMA at or above 10%, or an RTT EWMA
/// at or above 1.5 s.
const WEAK_LOSS: f64 = 0.10;
const WEAK_RTT_MS: f64 = 1_500.0;

impl LinkProfile {
  /// Records one dispatched message's outcome: `Some(latency)` for a
  /// message the peer admitted, `None` for a dispatch failure or an
  /// admission-ack timeout.
  fn observe(&mut self, delivered: Option<Duration>) {
    match delivered {
      Some(elapsed) => {
        let sample = elapsed.as_secs_f64() * 1_000.0;
        self.rtt_ewma_ms = Some(match self.rtt_ewma_ms {
          Some(ewma) => ewma + RTT_EWMA_ALPHA * (sample - ewma),
          None => sample,
        });
        self.loss_ewma *= 1.0 - LOSS_EWMA_ALPHA;
      }
      None => self.loss_ewma += LOSS_EWMA_ALPHA * (1.0 - self.loss_ewma),
    }
  }

  /// The weakness verdict (see the knob-curve table).
  fn weak(&self) -> bool {
    self.loss_ewma >= WEAK_LOSS || self.rtt_ewma_ms.is_some_and(|ms| ms >= WEAK_RTT_MS)
  }

  /// The cadence divisor: weak links exchange ROOTs four times as
  /// often, so a lost change heals in a quarter of the quiet window.
  fn cadence_divisor(&self) -> u32 {
    if self.weak() { 4 } else { 1 }
  }

  /// The eager-delta toggle: off on weak links.
  fn eager_delta(&self) -> bool {
    !self.weak()
  }
}

/// The driver-owned plane state behind one mutex: the per-peer engines
/// plus the rescan epoch, the cadence rotation point, and the
/// forced-rescan lanes.
struct PlaneState {
  peers: BTreeMap<NodeId, PeerState>,
  /// The register epoch at the driver's last namespace-dirty query: the
  /// watermark the incremental scan consumes dirty namespaces against.
  install_epoch: u64,
  /// The rotation continuation point for the cadence window.
  rotation: Option<NodeId>,
  /// Lanes whose next tick rescans regardless of namespace dirt: an
  /// apply fault left rows in the engines that the store never took, so
  /// the derived-view repair must retry even though no new write armed
  /// the lane.
  force_rescan: BTreeSet<LaneId>,
  /// Lanes with an outstanding derived-view repair set at the last
  /// pass: a policy-skipped row (a tombstone whose subject binding has
  /// not converged yet) heals when *another* lane's write advances the
  /// epoch, so these lanes rescan on every epoch advance — the
  /// pre-incremental retry semantics — while a clean steady state
  /// (empty repair set everywhere) still scans nothing.
  repair_pending: BTreeSet<LaneId>,
  /// The per-lane pull serialization: hints held while any engine of
  /// the lane has an open round (their rows applied, their ranges
  /// waiting), and root-exchange drives (the prime and the cadence
  /// re-drive are initiations too) held under the same rule. One node
  /// never runs two negotiations of one lane at once, so two parallel
  /// answerers can never race the same rows onto the wire twice — the
  /// payload-once discipline of the proposal §8, extended from "one
  /// round per session" to "one round per node". Responses are never
  /// held (a peer's initiation must always answer, or two nodes holding
  /// each other's hints would deadlock).
  held_hints: BTreeMap<LaneId, Vec<(NodeId, Vec<crate::reconcile::wire::RangeFingerprint>)>>,
  /// Root-exchange drives waiting out their lane's open round: the
  /// prime's and the cadence's initiations, re-driven at the release
  /// point when the lane goes quiet (a fresh whole-lane claim then
  /// replaces the stale one the wait would have acted on).
  held_roots: BTreeMap<LaneId, Vec<NodeId>>,
  /// The monotonic tick counter (the hint-retry backoff clock).
  tick_count: u64,
}

/// The per-lane hold on held hints: one round's worth of concurrent
/// notices, the same discipline as the engine's pending set.
const HELD_HINTS_PER_LANE: usize = 8;

impl PlaneState {
  /// Whether any engine of one lane has an open round, optionally
  /// excluding one session's engine (a message from that session walks
  /// the engine's own round discipline — its `pending_hints` — not the
  /// node-level hold; a different session's round is what serializes).
  fn lane_in_round(&self, lane: LaneId, except: Option<&NodeId>) -> bool {
    self.peers.iter().any(|(peer, state)| {
      Some(peer) != except && state.engines.get(&lane).is_some_and(|e| e.round_open())
    })
  }

  /// Whether one more held entry fits the lane's bounded hold.
  fn hold_room(&self, lane: LaneId) -> bool {
    self
      .held_hints
      .get(&lane)
      .is_none_or(|held| held.len() < HELD_HINTS_PER_LANE)
      && self
        .held_roots
        .get(&lane)
        .is_none_or(|held| held.len() < HELD_HINTS_PER_LANE)
  }

  /// Holds one root-exchange drive (the prime's or the cadence's
  /// initiation) until the lane goes quiet.
  fn hold_root_exchange(&mut self, lane: LaneId, peer: NodeId) {
    self.held_roots.entry(lane).or_default().push(peer);
  }

  /// Releases every held hint and root-exchange drive whose lane went
  /// quiet, driving each into its source engine; returns the outbound
  /// messages the releases generated.
  fn release_held_hints(&mut self) -> Vec<(NodeId, Message)> {
    let mut outbound = Vec::new();
    let lanes: Vec<LaneId> = self
      .held_hints
      .keys()
      .chain(self.held_roots.keys())
      .copied()
      .collect();
    for lane in lanes {
      if self.lane_in_round(lane, None) {
        continue;
      }
      if let Some(held) = self.held_hints.remove(&lane) {
        for (source, ranges) in held {
          let Some(state) = self.peers.get_mut(&source) else {
            continue;
          };
          let hint = Message::Hint {
            lane,
            ranges,
            rows: Vec::new(),
          };
          match state.engine(lane).drive(Drive::Message(hint)) {
            Ok(messages) => {
              outbound.extend(
                messages
                  .into_iter()
                  .map(|message| (source.clone(), message)),
              );
            }
            Err(error) => {
              tracing::debug!(lane = ?lane, kind = ?error.kind(), "reconcile held hint failed");
            }
          }
        }
      }
      if let Some(held) = self.held_roots.remove(&lane) {
        for peer in held {
          let Some(state) = self.peers.get_mut(&peer) else {
            continue;
          };
          match state.engine(lane).drive(Drive::RootExchange) {
            Ok(messages) => {
              // The same quiet-pass audit event the direct cadence
              // drive emits: a released re-drive that observes
              // agreement is a settled pass like any other.
              if lane == LaneId::Resources && state.engine(lane).peer_agrees() {
                crate::audit::resource_pass_settled(peer.as_str(), false);
              }
              outbound.extend(messages.into_iter().map(|message| (peer.clone(), message)));
            }
            Err(error) => {
              tracing::debug!(lane = ?lane, kind = ?error.kind(), "reconcile held root failed");
            }
          }
        }
      }
    }
    outbound
  }
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
          force_rescan: BTreeSet::new(),
          repair_pending: BTreeSet::new(),
          tick_count: 0,
          held_hints: BTreeMap::new(),
          held_roots: BTreeMap::new(),
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
    // The scan plan: which lanes does this tick rescan? Fresh peers
    // need the full set (the prime fill), a forced lane needs itself (an
    // apply fault retries its repair), and everything else is
    // namespace-granular — the store reports the families written past
    // the plane's watermark, each maps to at most one lane, and an
    // untracked note degrades the plan to the full set (the
    // pre-incremental semantics, so a write path the namespaces do not
    // cover can never hide a change).
    let plan: BTreeSet<LaneId> = {
      let mut guard = self.shared.lock()?;
      // One set-membership test per live peer, not a linear scan per
      // peer (the retain was O(peers²) at connection-degree scale).
      let alive: BTreeSet<&NodeId> = peers.iter().collect();
      guard.peers.retain(|peer, _| alive.contains(peer));
      guard.tick_count = guard.tick_count.saturating_add(1);
      let has_unprimed = peers
        .iter()
        .any(|peer| guard.peers.get(peer).is_none_or(|state| !state.primed));
      let forced = std::mem::take(&mut guard.force_rescan);
      // The cross-lane repair retry: an epoch advance with any lane
      // still carrying a repair set rescans those lanes (a refused
      // tombstone heals on the binding lane's write, never its own).
      let epoch_advanced = epoch != guard.install_epoch;
      let repair_lanes = if epoch_advanced {
        std::mem::take(&mut guard.repair_pending)
      } else {
        BTreeSet::new()
      };
      if has_unprimed {
        ACTIVE_LANES.into_iter().collect()
      } else {
        let (dirty, untracked) = store.dirty_namespaces_since(guard.install_epoch);
        if untracked.is_some() {
          ACTIVE_LANES.into_iter().collect()
        } else {
          let mut lanes = forced;
          lanes.extend(repair_lanes);
          for namespace in dirty {
            if let Some(lane) = lane_of_namespace(&namespace) {
              lanes.insert(lane);
            }
          }
          lanes
        }
      }
    };
    // The tombstone lane's collected-row filter reads the local
    // checkpoint watermark once per scan (the same predicate the apply
    // boundary fails open on).
    let checkpoint = if plan.contains(&LaneId::Tombstones) {
      crate::identity::cleanup::latest_checkpoint_millis_ctx(store).await?
    } else {
      None
    };
    let rows: LaneScan = if plan.is_empty() {
      Vec::new()
    } else {
      scan_lanes(store, &plan, checkpoint).await?
    };
    let mut outbound: Vec<(NodeId, Message)> = Vec::new();
    let mut repair: LaneScan = Vec::new();
    {
      let mut guard = self.shared.lock()?;
      if !plan.is_empty() {
        guard.install_epoch = epoch;
      }
      // The scan's derived view, both projections: the exact row
      // identities and the lane keys under them (the prune's
      // supersession oracle).
      let listed: LaneListed = rows
        .iter()
        .map(|(lane, lane_rows)| {
          (
            *lane,
            (
              lane_rows
                .iter()
                .map(|(key, content)| row_identity(key, content))
                .collect(),
              lane_rows.iter().map(|(key, _)| key.clone()).collect(),
            ),
          )
        })
        .collect();
      // The prime's held root exchanges accumulate here (the state
      // borrow outlives each peer's body) and land in the hold set
      // after the loop.
      let mut prime_holds: Vec<(LaneId, NodeId)> = Vec::new();
      for peer in &peers {
        // The per-lane gating computed ahead of the state borrow:
        // which lanes' root exchanges hold out the rounds of other
        // sessions.
        let held_prime_lanes: Vec<LaneId> = ACTIVE_LANES
          .iter()
          .copied()
          .filter(|lane| guard.lane_in_round(*lane, Some(peer)) && guard.hold_room(*lane))
          .collect();
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
          // exchange opens the first negotiation — gated by the
          // per-lane serialization like every initiation.
          state.primed = true;
          state.ticks_since_exchange = 0;
          for lane in ACTIVE_LANES {
            if held_prime_lanes.contains(&lane) {
              continue;
            }
            match state.engine(lane).drive(Drive::RootExchange) {
              Ok(messages) => {
                outbound.extend(messages.into_iter().map(|message| (peer.clone(), message)));
              }
              Err(error) => {
                tracing::debug!(lane = ?lane, kind = ?error.kind(), "reconcile prime failed");
              }
            }
          }
          for lane in held_prime_lanes {
            prime_holds.push((lane, peer.clone()));
          }
        } else {
          // The local-write drive over the scanned lanes: the eager
          // piggyback rides only on this path (the originator's push
          // head) and only while the session profile allows it.
          let eager = state.profile.eager_delta();
          for lane in ACTIVE_LANES {
            if !plan.contains(&lane) {
              continue;
            }
            let drive = if eager {
              Drive::LocalChangeEager
            } else {
              Drive::LocalChange
            };
            match state.engine(lane).drive(drive) {
              Ok(messages) => {
                outbound.extend(messages.into_iter().map(|message| (peer.clone(), message)));
              }
              Err(error) => {
                tracing::debug!(lane = ?lane, kind = ?error.kind(), "reconcile change failed");
              }
            }
          }
        }
        // The prune pass over the scanned lanes: engine rows the store
        // no longer lists leave the index — superseded identities (the
        // key survived under new content: a revision bump, a tuple
        // loser) and collected tombstones (the checkpoint watermark's
        // reclaim). Rows whose key the store does not hold at all stay:
        // they are the derived-view repair set.
        for lane in ACTIVE_LANES {
          if !plan.contains(&lane) {
            continue;
          }
          let Some((identities, keys)) = listed.get(&lane) else {
            continue;
          };
          let engine = state.engine(lane);
          let mut prune: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
          for (key, content) in engine.rows() {
            if identities.contains(&row_identity(key, content)) {
              continue;
            }
            let collected_row =
              lane == LaneId::Tombstones && tombstone_collected(checkpoint, key, content);
            let swept_row = lane == LaneId::Resources && resource_swept(keys, key, content);
            if collected_row || swept_row || keys.contains(key) {
              prune.push((key.to_vec(), content.to_vec()));
            }
          }
          for (key, content) in prune {
            if engine.remove_row(&key, &content).unwrap_or(false) {
              tracing::debug!(
                lane = ?lane,
                "reconcile pruned a superseded or collected engine row"
              );
            }
          }
        }
      }
      // The prime's held root exchanges land now that the state
      // borrows are spent.
      for (lane, peer) in prime_holds {
        guard.hold_root_exchange(lane, peer);
      }
      if !plan.is_empty() {
        // The derived-view repair set — engine rows the store scan did
        // not list and the prune kept (their key is absent from the
        // store entirely), deduplicated across peers.
        let mut seen: BTreeMap<LaneId, BTreeSet<Vec<u8>>> = BTreeMap::new();
        let mut pending: RepairIndex = BTreeMap::new();
        for state in guard.peers.values() {
          for lane in &plan {
            let Some(engine) = state.engines.get(lane) else {
              continue;
            };
            let Some((known, keys)) = listed.get(lane) else {
              continue;
            };
            for (key, content) in engine.rows() {
              let identity = row_identity(key, content);
              if known.contains(&identity) {
                continue;
              }
              if *lane == LaneId::Tombstones && tombstone_collected(checkpoint, key, content) {
                continue;
              }
              // The retention-reclaimed exemption: a swept removal row
              // is not repair work — re-applying it is the resurrection.
              if *lane == LaneId::Resources && resource_swept(keys, key, content) {
                continue;
              }
              if keys.contains(key) {
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
        // The outstanding-repair lanes: every epoch advance rescans
        // them until their repair set empties (the cross-lane retry).
        // Lanes outside this pass's plan keep their marks — a narrow
        // plan (one dirty namespace) must not erase another lane's
        // pending repair, or its cross-lane retry waits for its own
        // namespace to dirty again.
        let recomputed: BTreeSet<LaneId> = repair.iter().map(|(lane, _)| *lane).collect();
        guard.repair_pending.retain(|lane| !plan.contains(lane));
        guard.repair_pending.extend(recomputed);
      }
      // The cadence window: ROOT exchanges for the due peers a bounded
      // fair window of the alive set serves this tick. The per-session
      // cadence divisor is the weak-link knob: a lossy link exchanges
      // roots four times as often, so a lost change heals in a quarter
      // of the quiet window.
      let due: Vec<NodeId> = guard
        .peers
        .iter()
        .filter(|(_, state)| state.primed)
        .filter(|(_, state)| {
          let cadence =
            crate::sync_common::DETECTION_CADENCE_TICKS / state.profile.cadence_divisor().max(1);
          state.ticks_since_exchange >= cadence.max(1)
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
        // The cadence's per-lane gating, computed ahead of the state
        // borrow.
        let held_cadence_lanes: Vec<LaneId> = ACTIVE_LANES
          .iter()
          .copied()
          .filter(|lane| guard.lane_in_round(*lane, Some(peer)) && guard.hold_room(*lane))
          .collect();
        if let Some(state) = guard.peers.get_mut(peer) {
          state.ticks_since_exchange = 0;
          for lane in ACTIVE_LANES {
            // The cadence initiation is gated like every other: a lane
            // still negotiating elsewhere re-drives at the release
            // point with a fresh claim.
            if held_cadence_lanes.contains(&lane) {
              continue;
            }
            match state.engine(lane).drive(Drive::RootExchange) {
              Ok(messages) => {
                // The resources lane's quiet-pass audit event: the SLO
                // harness asserts its presence as the resource plane's
                // settled-pass proof. It fires only on observed
                // agreement — the peer's last-seen whole-lane
                // fingerprint equals ours after the exchange — so the
                // event means the same thing the walk's changeless scan
                // meant (`continued = false`: a settled whole lane),
                // never a bare dispatch.
                if lane == LaneId::Resources && state.engine(lane).peer_agrees() {
                  crate::audit::resource_pass_settled(peer.as_str(), false);
                }
                outbound.extend(messages.into_iter().map(|message| (peer.clone(), message)));
              }
              Err(error) => {
                tracing::debug!(lane = ?lane, kind = ?error.kind(), "reconcile cadence failed");
              }
            }
          }
        }
        for lane in held_cadence_lanes {
          guard.hold_root_exchange(lane, peer.clone());
        }
      }
      // Rounds the cadence closed release their held hints and root
      // re-drives too.
      outbound.extend(guard.release_held_hints());
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
      // The hint-retry budget: an undelivered hint on a link the
      // profile still reads as weak re-sends once its backoff expires,
      // up to the bounded attempt count. A recovered link drops its
      // pending hint — the cadence is the backstop, and hints are
      // advisory by contract.
      let tick_now = guard.tick_count;
      let mut retries: Vec<(NodeId, Message)> = Vec::new();
      for (peer, state) in guard.peers.iter_mut() {
        let Some(pending) = state.hint_retry.take() else {
          continue;
        };
        if !state.profile.weak() || pending.attempts_left == 0 || pending.resume_at_tick > tick_now
        {
          continue;
        }
        let backoff = 1_u64 << (HINT_RETRY_MAX - pending.attempts_left);
        state.hint_retry = Some(PendingHint {
          message: pending.message.clone(),
          attempts_left: pending.attempts_left - 1,
          resume_at_tick: tick_now.saturating_add(backoff),
        });
        retries.push((peer.clone(), pending.message));
      }
      outbound.extend(retries);
    }
    // The repair pass runs outside the peers lock: it touches the store.
    for (lane, lane_rows) in &repair {
      if lane_rows.is_empty() {
        continue;
      }
      tracing::debug!(lane = ?lane, rows = lane_rows.len(), "reconcile derived-view repair");
      // Row-level refusals (undecodable, misattributed, policy-skipped)
      // never reach here — the arms skip them in-line. An error at this
      // boundary is a batch-level fault (a store write failure): the
      // rows stay pending and the next epoch pass retries them — the
      // forced rescan below keeps that promise even when the failed
      // apply was the last write the lane sees for a while.
      if let Err(error) = apply_rows(&self.shared, lane, lane_rows, None, Some(runtime)).await {
        tracing::warn!(
          lane = ?lane,
          kind = ?error.kind(),
          "reconcile derived-view repair aborted by a store fault; retrying next epoch pass"
        );
        if let Ok(mut guard) = self.shared.lock() {
          guard.force_rescan.insert(*lane);
        }
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
    let mut message = message;
    let mut rows: Vec<(Vec<u8>, Vec<u8>)> = match &message {
      Message::Rows { rows, .. } | Message::Hint { rows, .. } => rows
        .iter()
        .map(|row| (row.key.clone(), row.content.clone()))
        .collect(),
      _ => Vec::new(),
    };
    let carried = rows.len();
    if !rows.is_empty() && lane == LaneId::Tombstones {
      // The collected-row receive filter: a leave or cleanup record at
      // or before the local checkpoint watermark never enters an
      // engine (its fingerprints, its fan-out, and its repair-set
      // candidacy alike) — re-admitting collected evidence is what
      // made the GC rows re-propagate forever.
      let checkpoint =
        crate::identity::cleanup::latest_checkpoint_millis_ctx(self.shared.context()?.store())
          .await?;
      rows.retain(|(key, content)| !tombstone_collected(checkpoint, key, content));
    }
    if !rows.is_empty() && lane == LaneId::Resources {
      // The retention-reclaimed receive filter, the tombstone mirror:
      // a removal row whose subject the local store does not hold
      // never enters an engine. Its subject is already gone here —
      // admitting the row would only materialize a tombstone that the
      // next sweep deletes again (the resurrection churn), and a newly
      // primed peer would receive the whole historical removal set.
      let context = self.shared.context()?;
      let store = context.store();
      let namespace = crate::resource::store::namespace()?;
      let snapshot = store.snapshot().await?;
      let mut retained = Vec::with_capacity(rows.len());
      for (key, content) in rows {
        let swept = crate::resource::ResourceRecordV1::decode(&content)
          .ok()
          .is_some_and(|record| record.removed())
          && snapshot
            .get(
              &namespace,
              &crate::StoreKey::new(std::sync::Arc::from(key.clone())),
            )
            .await?
            .is_none();
        if !swept {
          retained.push((key, content));
        }
      }
      rows = retained;
    }
    if !rows.is_empty() {
      // The store decides before any engine does: rows apply through
      // the lane's merge semantics FIRST, and the rows the lane
      // deterministically refused never reach the derived view — the
      // same receive-boundary discipline the collected-tombstone and
      // swept-resource filters enforce above. Without this gate a
      // refused row (a stale descriptor revision, a binding for a
      // revoked subject) enters the engine anyway, the epoch pass
      // prunes it as superseded, the prune's hint re-announces the
      // change, and the peers that still list the row re-deliver it —
      // an unbounded re-negotiation loop between the refusing node and
      // every fingerprint it exchanges (the leave/restart livelock:
      // one starved core never drains it and the data plane starves).
      // A batch-level store fault keeps every row in the message: the
      // engines hold them and the derived-view repair retries, exactly
      // as before.
      match apply_rows(&self.shared, &lane, &rows, Some(source), Some(runtime)).await {
        Ok(refused) => {
          if !refused.is_empty() {
            rows.retain(|(key, content)| {
              !refused.iter().any(|(refused_key, refused_content)| {
                refused_key == key && refused_content == content
              })
            });
            tracing::debug!(
              lane = ?lane,
              refused = refused.len(),
              "reconcile receive refused rows; they never enter the engines"
            );
          }
        }
        Err(error) => {
          // Row-level refusals are skipped in-line by the arms; an error
          // here is a batch-level store fault — the rows stay in the
          // engines and the derived-view repair retries them.
          tracing::warn!(
            lane = ?lane,
            kind = ?error.kind(),
            "reconcile rows apply aborted by a store fault; the repair retries"
          );
        }
      }
      if !rows.is_empty() {
        // The lane schedules one confirmation scan: the apply may have
        // deferred rows the store cannot take yet (a tombstone whose
        // subject binding has not converged), and those rows' retry
        // lives in the next repair pass — without the scan the pass
        // never recomputes (the delayed-content regression: the
        // revocation arrived before its binding and never retried).
        // A fully-refused batch needs no scan: nothing entered the
        // store or the engines.
        if let Ok(mut guard) = self.shared.lock() {
          guard.force_rescan.insert(lane);
        }
      }
    }
    if rows.len() != carried {
      // A receive filter or the apply refusal dropped rows: the
      // engine's message must carry the retained set only — driving
      // the original body would re-admit exactly what was refused (the
      // engine applies piggybacked and carried rows alike before any
      // comparison).
      let retained_rows = rows
        .iter()
        .map(|(key, content)| crate::reconcile::wire::Row {
          key: key.clone(),
          content: content.clone(),
        })
        .collect();
      message = match message {
        Message::Rows { lane, .. } => Message::Rows {
          lane,
          rows: retained_rows,
        },
        Message::Hint { lane, ranges, .. } => Message::Hint {
          lane,
          ranges,
          rows: retained_rows,
        },
        other => other,
      };
    }
    let mut outbound: Vec<(NodeId, Message)> = Vec::new();
    {
      let mut guard = self.shared.lock()?;
      // An inbound root whose lane still negotiates elsewhere at this
      // node drops: its whole-lane claim is a then-snapshot, and
      // initiating from a stale claim re-delivers what the open round
      // is already bringing over the same edge. Roots are cheap and
      // cadence-refreshed, so the drop costs one quiet window of
      // peer-view latency, never correctness — the fresh claim comes
      // back with the next exchange. A root from the round's own
      // session still processes (the engine suppresses its initiation
      // against its own open round; its agreement close must run).
      if matches!(message, Message::Root { .. }) && guard.lane_in_round(lane, Some(source)) {
        drop(guard);
        return Ok(());
      }
      // The per-lane pull serialization: a hint arriving while a
      // *different* session's engine of the lane still negotiates
      // holds its ranges (the piggyback rows below still apply —
      // payload is never held) and releases when the lane goes quiet,
      // where a fingerprint comparison usually resolves it to silence.
      // A hint from the round's own session walks the engine's pending
      // set instead (its own discipline). Responses are never held: a
      // peer's initiation must always answer, or two nodes holding
      // each other's hints would deadlock.
      let hold = match &message {
        Message::Hint { ranges, .. }
          if guard.lane_in_round(lane, Some(source)) && guard.hold_room(lane) =>
        {
          Some(ranges.clone())
        }
        _ => None,
      };
      if let Some(ranges) = hold {
        guard
          .held_hints
          .entry(lane)
          .or_default()
          .push((source.clone(), ranges));
        // The piggyback rows still enter the source engine: payload is
        // never held, only the negotiation candidacy — and without
        // eager candidacy (a receive path is not the originator's
        // local write; its rows never ride a later piggyback).
        let engine = guard
          .peers
          .entry(source.clone())
          .or_insert_with(PeerState::fresh)
          .engine(lane);
        for (key, content) in &rows {
          if let Err(error) = engine.insert_row_quiet(key, content) {
            tracing::debug!(kind = ?error.kind(), "reconcile held-hint row skipped");
          }
        }
      } else {
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
      // A round the delivery just closed releases whatever it was
      // holding — the released hint compares against the settled state
      // and stays silent when its divergence was the round's own.
      outbound.extend(guard.release_held_hints());
    }
    if !rows.is_empty() {
      // The kept rows — installed or deferred — fan out to the
      // sibling engines: propagation and application are decoupled
      // (the derived-view repair retries the application side on the
      // next epoch pass), and a refused row never propagates from a
      // node that will not hold it.
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

/// The reconcile protocol tag, parsed once: the tag grammar is a pure
/// function of the constant string, so per-message re-parsing was pure
/// latency on the send path. `None` is unreachable (the constant is
/// well-formed); a failure there skips the dispatch exactly like an
/// encode failure.
fn reconcile_protocol_tag() -> Option<&'static ProtocolTag> {
  static TAG: std::sync::OnceLock<Option<ProtocolTag>> = std::sync::OnceLock::new();
  TAG
    .get_or_init(|| ProtocolTag::parse(RECONCILE_PROTOCOL).ok())
    .as_ref()
}

/// Sends one message to one peer: encode, envelope, one bounded body on
/// the shared pump with the admission-ack discipline. A dispatch
/// failure is diagnostics only — loss heals at the next root exchange
/// (or, on a link the profile reads as weak, the bounded hint retry).
/// The dispatch outcome feeds the session's link profile: the
/// admission latency is the session's observable round trip, and an
/// undelivered dispatch is a loss sample.
fn send_message(
  shared: &Arc<PlaneShared>, runtime: &RuntimeClient, peer: &NodeId, message: Message,
) {
  let lane = message.lane();
  let rows = match &message {
    Message::Rows { rows, .. } | Message::Hint { rows, .. } => rows.len(),
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
  // page counter it replaces. The eager-delta piggyback is payload
  // crossing a session, so it counts exactly like a ROWS message.
  if rows > 0 && lane == LaneId::Descriptors {
    crate::audit::membership_page_emitted(rows);
  }
  let entropy = Arc::clone(&shared.entropy);
  let Some(protocol) = reconcile_protocol_tag() else {
    tracing::debug!(lane = ?lane, "reconcile protocol tag unavailable");
    return;
  };
  let protocol = protocol.clone();
  let runtime = runtime.clone();
  let peer = peer.clone();
  let shared = Arc::clone(shared);
  let is_hint = matches!(message, Message::Hint { .. });
  let retry_message = (is_hint && rows == 0).then(|| message.clone());
  let sent_at = std::time::Instant::now();
  tokio::spawn(async move {
    let delivered = match crate::sync_common::send_payload(
      &runtime, &entropy, &peer, &protocol, &encoded,
    )
    .await
    {
      Ok(ack) => crate::sync_common::delivered_within_bound(ack).await,
      Err(error) => {
        tracing::debug!(peer = %peer.as_str(), kind = ?error.kind(), "reconcile dispatch failed");
        false
      }
    };
    let elapsed = sent_at.elapsed();
    if !delivered {
      tracing::debug!(peer = %peer.as_str(), "reconcile message not admitted");
    }
    // The profile sample: an admission is a round-trip observation, a
    // failure is a loss observation. The retry slot takes only plain
    // hints (a piggybacked hint re-sent blind would spend the eager
    // budget on a link the profile already distrusts) and only while
    // the profile still reads weak — the knob, not the sender, decides.
    // The budget arms once: a slot already holding a retry keeps its
    // remaining attempts, so a persistently failing session exhausts
    // the bounded budget and the detection cadence absorbs the loss
    // instead of the retry loop running forever.
    if let Ok(mut guard) = shared.state.lock() {
      let tick_now = guard.tick_count;
      if let Some(state) = guard.peers.get_mut(&peer) {
        state.profile.observe(delivered.then_some(elapsed));
        if !delivered
          && let Some(message) = retry_message
          && state.profile.weak()
          && state.hint_retry.is_none()
        {
          state.hint_retry = Some(PendingHint {
            message,
            attempts_left: HINT_RETRY_MAX,
            resume_at_tick: tick_now.saturating_add(1),
          });
        }
      }
    }
  });
}

/// Maps one store namespace to the lane that reconciles it: the
/// incremental scan's namespace→lane dictionary. A namespace outside
/// every lane's key space maps to nothing (its writes cannot change any
/// lane's row set, so no scan is armed for them).
fn lane_of_namespace(namespace: &crate::StoreNamespace) -> Option<LaneId> {
  let tag = namespace.as_str();
  if tag == crate::membership::NODE_DESCRIPTOR_NAMESPACE {
    return Some(LaneId::Descriptors);
  }
  if tag == crate::storage::families::IDENTITY_BINDING_NAMESPACE {
    return Some(LaneId::Trust);
  }
  if tag == crate::resource::store::NAMESPACE_TAG {
    return Some(LaneId::Resources);
  }
  if matches!(
    tag,
    crate::storage::families::LEAVE_NAMESPACE
      | crate::storage::families::CLEANUP_NAMESPACE
      | crate::storage::families::REVOCATION_NAMESPACE
      | crate::storage::families::CHECKPOINT_NAMESPACE
  ) {
    return Some(LaneId::Tombstones);
  }
  None
}

/// Whether one tombstone-lane row is collected evidence: a leave or
/// cleanup record stamped at or before the local checkpoint watermark
/// (the same predicate the apply boundary fails open on). Revocations
/// are never collected, and the checkpoint singleton itself never is.
fn tombstone_collected(checkpoint: Option<u64>, key: &[u8], content: &[u8]) -> bool {
  let collected = |stamp: Option<u64>| {
    checkpoint.is_some_and(|watermark| stamp.is_some_and(|stamp| stamp <= watermark))
  };
  match key.first() {
    Some(1) => collected(
      crate::identity::leave::LeaveRecordV1::decode(content)
        .ok()
        .map(|record| record.timestamp_millis()),
    ),
    Some(2) => collected(
      crate::identity::cleanup::CleanupRecordV1::decode(content)
        .ok()
        .map(|record| record.timestamp_millis()),
    ),
    _ => false,
  }
}

/// Whether one resources-lane row is retention-reclaimed evidence: a
/// `removed()` record whose key the local store no longer holds (the
/// sweep deleted it, or the node never held the resource — either way
/// the terminal row's subject is absent and re-admitting it would only
/// materialize a tombstone for nothing). The tombstone lane's
/// collected-mode mirror: swept rows leave the engines (the prune
/// below), never re-enter them (the receive filter), and a newly
/// primed peer does not receive the historical removal set back.
fn resource_swept(keys: &BTreeSet<Vec<u8>>, key: &[u8], content: &[u8]) -> bool {
  crate::resource::ResourceRecordV1::decode(content)
    .ok()
    .is_some_and(|record| record.removed())
    && !keys.contains(key)
}

/// Scans the planned lanes' namespaces into canonical
/// `(key, content)` rows. Corrupt rows are skipped with a diagnostic —
/// one bad row must not kill egress for every other row (the page
/// lanes' corrupt-row policy, carried over). The tombstone lane skips
/// collected rows at the scan boundary: collected evidence never
/// enters the derived view, so it never primes a new peer either.
async fn scan_lanes(
  store: &crate::storage::MetadataStore, plan: &BTreeSet<LaneId>, checkpoint: Option<u64>,
) -> Result<LaneScan> {
  let snapshot = store.snapshot().await?;
  let mut lanes = Vec::new();
  for lane in ACTIVE_LANES {
    if !plan.contains(&lane) {
      continue;
    }
    lanes.push((lane, scan_lane(snapshot.as_ref(), lane, checkpoint).await?));
  }
  Ok(lanes)
}

/// One lane's rows from a snapshot.
async fn scan_lane(
  snapshot: &(dyn crate::provider::StoreSnapshot + '_), lane: LaneId, checkpoint: Option<u64>,
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
          let row_key = kind.row_key(&key);
          if tombstone_collected(checkpoint, &row_key, &content) {
            continue;
          }
          rows.push((row_key, content));
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
/// passes `None`. Returns the rows the lane **refused** — the
/// deterministic policy skips (a stale descriptor revision, an
/// unhealable first install, a revoked or substituted binding, a
/// corrupt or misattributed row) whose outcome no retry can change.
/// The receive boundary gates engine admission on this list: a refused
/// row must never enter the derived view, because the row would then
/// diverge every fingerprint exchange against the peers whose stores
/// do list it, and the prune/hint/re-push cycle would re-deliver the
/// refusal forever (the leave/restart livelock). Deferred classes —
/// the transient contention and not-yet-converged-binding skips — do
/// NOT appear here: their retry lives in the engine (the cross-lane
/// repair), exactly as before.
async fn apply_rows(
  shared: &PlaneShared, lane: &LaneId, rows: &[(Vec<u8>, Vec<u8>)], source: Option<&NodeId>,
  runtime: Option<&RuntimeClient>,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
  let context = shared.context()?;
  let store = context.store();
  match lane {
    LaneId::Descriptors => {
      // Row-level fault tolerance, the scan side's corrupt-row policy:
      // one undecodable or misattributed row skips with a typed reason
      // instead of failing the batch — a whole-batch error would wedge
      // the derived-view repair on the same poison row forever (the
      // engines hold it, so the fingerprints look converged while the
      // store never receives the good rows behind it). Store failures
      // below still propagate: they are real write faults, not corrupt
      // input. The refused list carries the rows in their original
      // wire shape, so the receive boundary can keep them out of the
      // engines — including the same-key duplicates the page-order
      // contest below drops (their loser is stale-or-equal by
      // construction, the same refusal the store would make).
      let mut descriptors: Vec<(Vec<u8>, Vec<u8>, crate::membership::NodeDescriptorV1)> =
        Vec::with_capacity(rows.len());
      let mut refused = Vec::new();
      let mut index_by_node: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
      for (row_key, content) in rows {
        match crate::membership::page::decode_descriptor(content) {
          Ok(descriptor) if row_key.as_slice() == descriptor.node().as_str().as_bytes() => {
            let node = descriptor.node().as_str().to_owned();
            match index_by_node.get(&node) {
              Some(&index) if descriptors[index].2.revision() >= descriptor.revision() => {
                refused.push((row_key.clone(), content.clone()));
              }
              Some(&index) => {
                let superseded_content =
                  std::mem::replace(&mut descriptors[index].1, content.clone());
                refused.push((row_key.clone(), superseded_content));
                descriptors[index].2 = descriptor;
              }
              None => {
                index_by_node.insert(node, descriptors.len());
                descriptors.push((row_key.clone(), content.clone(), descriptor));
              }
            }
          }
          Ok(descriptor) => {
            tracing::debug!(
              node = %descriptor.node(),
              "reconcile descriptor row skipped: key mismatch"
            );
            refused.push((row_key.clone(), content.clone()));
          }
          Err(error) => {
            tracing::debug!(
              kind = ?error.kind(),
              "reconcile descriptor row skipped: undecodable"
            );
            refused.push((row_key.clone(), content.clone()));
          }
        }
      }
      let mut skipped_ids = Vec::new();
      for chunk in descriptors.chunks(crate::paging::PAGE_MAX_ITEMS) {
        let page = crate::membership::page::MembershipPage::new(
          chunk
            .iter()
            .map(|(_, _, descriptor)| descriptor.clone())
            .collect(),
          None,
        )?;
        let (installed, skipped) = crate::membership::store::apply_descriptor_batch_ctx(
          store,
          shared.entropy.as_ref(),
          &page,
        )
        .await?;
        skipped_ids.extend(skipped);
        for (_, _, descriptor) in chunk {
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
      // The batch's refused node ids map back onto exactly the rows
      // that carried them (the dedup above left one row per node id).
      for (row_key, content, _) in &descriptors {
        if skipped_ids
          .iter()
          .any(|node| node.as_str().as_bytes() == row_key.as_slice())
        {
          refused.push((row_key.clone(), content.clone()));
        }
      }
      Ok(refused)
    }
    LaneId::Trust => {
      // The same row-level policy as the descriptors arm: a corrupt or
      // misattributed binding row skips; adoption failures keep the
      // snapshot-accept semantics (transient contention skips one
      // binding — the repair retries it — and everything else, key
      // substitution above all, fails closed and propagates).
      let mut refused = Vec::new();
      for (row_key, content) in rows {
        let binding = match crate::identity::records::IdentityBindingV1::decode(content) {
          Ok(binding) if row_key.as_slice() == binding.node().as_str().as_bytes() => binding,
          Ok(binding) => {
            tracing::debug!(
              node = %binding.node(),
              "reconcile binding row skipped: key mismatch"
            );
            refused.push((row_key.clone(), content.clone()));
            continue;
          }
          Err(error) => {
            tracing::debug!(
              kind = ?error.kind(),
              "reconcile binding row skipped: undecodable"
            );
            refused.push((row_key.clone(), content.clone()));
            continue;
          }
        };
        // The per-record adoption policy, row-scoped: transient
        // contention skips one binding (the repair retries it); a
        // revoked subject (revocation tombstones out-rank late binding
        // rows — the delayed-content mirror order) and a substituted
        // key are refused evidence — the row is skipped, not stored,
        // and the batch continues (skipping IS the correct outcome;
        // these fire on honest input, so an abort here would wedge the
        // repair on every re-delivery). Everything else — provider
        // faults above all — is a real write fault and propagates.
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
            crate::ErrorKind::Conflict
              | crate::ErrorKind::NotReady
              | crate::ErrorKind::Revoked
              | crate::ErrorKind::NotTrusted
          ) {
            tracing::warn!(
              node = %binding.node(),
              kind = ?error.kind(),
              "reconcile binding row refused by policy; skipping"
            );
            // Revoked and substituted-key rows are refused evidence
            // whose outcome no retry changes: they join the refused
            // list so the receive boundary keeps them out of the
            // engines. Contention and not-ready are transient — the
            // row stays a repair candidate exactly as before.
            if matches!(
              error.kind(),
              crate::ErrorKind::Revoked | crate::ErrorKind::NotTrusted
            ) {
              refused.push((row_key.clone(), content.clone()));
            }
            continue;
          }
          return Err(error);
        }
      }
      Ok(refused)
    }
    LaneId::Resources => {
      // The same row-level policy as the descriptors arm: a corrupt or
      // misattributed record row skips; the page apply below keeps its
      // per-writer bounded wait and fail-closed skip for unknown
      // writers, and its store faults propagate.
      let mut records = Vec::with_capacity(rows.len());
      let mut refused = Vec::new();
      for (row_key, content) in rows {
        match crate::resource::ResourceRecordV1::decode(content) {
          Ok(record) if row_key.as_slice() == record.name().as_str().as_bytes() => {
            records.push(record);
          }
          Ok(record) => {
            tracing::debug!(
              name = %record.name().as_str(),
              "reconcile resource row skipped: key mismatch"
            );
            refused.push((row_key.clone(), content.clone()));
          }
          Err(error) => {
            tracing::debug!(
              kind = ?error.kind(),
              "reconcile resource row skipped: undecodable"
            );
            refused.push((row_key.clone(), content.clone()));
          }
        }
      }
      for chunk in records.chunks(crate::paging::PAGE_MAX_ITEMS) {
        let page = crate::resource::page::ResourcePage::new(chunk.to_vec(), None)?;
        let installed =
          crate::resource::page::sync::apply_page_ctx(store, shared.entropy.as_ref(), &page)
            .await?;
        tracing::debug!(installed, "reconcile resource rows applied");
      }
      Ok(refused)
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
      .await?;
      // No refused rows on this lane: the policy skips (a subject
      // binding that has not converged) are the designed transient
      // retries — every tombstone row the collected filter passed
      // stays a repair candidate until its binding lands.
      Ok(Vec::new())
    }
  }
}

#[cfg(test)]
mod tests {
  use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
  };

  use super::{super::wire::LaneId, scan_lanes};
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
    let plan: BTreeSet<LaneId> = [LaneId::Trust].into_iter().collect();
    let lanes = scan_lanes(context.store(), &plan, None).await.unwrap();
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

  /// The resources lane's per-writer bounded wait keeps its liveness in
  /// the row shape: a row batch whose writer is not (and never becomes)
  /// trusted applies within the page's own bounded window — one wait
  /// shared by the batch's records from that writer, then a fail-closed
  /// skip — never a dead wait. This is the page-lane contract carried
  /// over unchanged: the plane batches its rows into the same page
  /// apply, so the wait bound cannot regress by row-ization.
  #[tokio::test]
  async fn the_resources_lane_skips_unknown_writers_within_the_bounded_wait() {
    use crate::resource::ResourceRecordV1;

    let context = context_with_bindings(&[]).await;
    let writer = node(7);
    let signing = crate::identity::testing::scripted_signing(7);
    let mut rows = Vec::new();
    for index in 0..4_u64 {
      let name =
        crate::ResourceName::parse(&format!("example.org/resources/unknown-{index}")).unwrap();
      let record = ResourceRecordV1::sign(
        name.clone(),
        crate::LabelValue::parse("document").unwrap(),
        crate::ResourceUri::parse("u://unknown").unwrap(),
        crate::LabelSet::new(),
        1_000 + index,
        writer.clone(),
        0,
        false,
        &signing,
      )
      .unwrap();
      rows.push((name.as_str().as_bytes().to_vec(), record.encode().unwrap()));
    }
    let started = std::time::Instant::now();
    let shared = plane_shared(&context).await;
    super::apply_rows(
      shared.as_ref(),
      &super::super::wire::LaneId::Resources,
      &rows,
      None,
      None,
    )
    .await
    .unwrap();
    let elapsed = started.elapsed();
    assert!(
      elapsed < std::time::Duration::from_secs(6),
      "the batch bounded-waited once, not once per row: {elapsed:?}"
    );
    // Nothing installed: the writer never became trusted, so every
    // record skipped fail-closed.
    for (row_key, _) in &rows {
      let name = crate::ResourceName::parse(std::str::from_utf8(row_key).unwrap()).unwrap();
      assert!(
        crate::resource::store::read_record_ctx(context.store(), &name)
          .await
          .unwrap()
          .is_none(),
        "an unknown writer's record must not install"
      );
    }
  }

  /// The poison-row contract, descriptors and trust arms: a batch
  /// carrying undecodable or key-misattributed rows applies its good
  /// rows and skips the poison with a typed reason — and a second pass
  /// over the same batch (the derived-view repair's shape) succeeds
  /// instead of wedging on the same row forever.
  #[tokio::test]
  async fn poison_rows_skip_and_good_rows_apply() {
    use super::super::wire::LaneId;

    let context = context_with_bindings(&[]).await;
    let shared = plane_shared(&context).await;

    // Descriptors: one good row, one undecodable, one misattributed key.
    let good = crate::membership::NodeDescriptorV1::new(
      node(51),
      key(51),
      vec![crate::Endpoint::parse("wss://good:9000").unwrap()],
      1,
      false,
      1,
    );
    let good_key = node(51).as_str().as_bytes().to_vec();
    let stale_key = node(52).as_str().as_bytes().to_vec();
    let descriptor_rows = vec![
      (good_key, good.encode().unwrap()),
      (node(53).as_str().as_bytes().to_vec(), vec![0xFF, 0x00]),
      (stale_key, good.encode().unwrap()),
    ];
    super::apply_rows(
      shared.as_ref(),
      &LaneId::Descriptors,
      &descriptor_rows,
      None,
      None,
    )
    .await
    .unwrap();
    assert!(
      crate::membership::store::read_descriptor_ctx(context.store(), &node(51))
        .await
        .unwrap()
        .is_some(),
      "the good descriptor row applied"
    );
    // The repair channel's shape: the same batch applies again without
    // wedging on its poison rows.
    super::apply_rows(
      shared.as_ref(),
      &LaneId::Descriptors,
      &descriptor_rows,
      None,
      None,
    )
    .await
    .unwrap();

    // Trust: one good binding, one undecodable, one misattributed key.
    let binding = crate::identity::records::IdentityBindingV1::new(node(54), key(54));
    let binding_rows = vec![
      (
        node(54).as_str().as_bytes().to_vec(),
        binding.encode().unwrap(),
      ),
      (node(55).as_str().as_bytes().to_vec(), vec![0xFF, 0x00]),
      (
        node(56).as_str().as_bytes().to_vec(),
        binding.encode().unwrap(),
      ),
    ];
    super::apply_rows(shared.as_ref(), &LaneId::Trust, &binding_rows, None, None)
      .await
      .unwrap();
    super::apply_rows(shared.as_ref(), &LaneId::Trust, &binding_rows, None, None)
      .await
      .unwrap();
    let bindings = crate::identity::trust::store::trusted_bindings(context.store())
      .await
      .unwrap();
    assert_eq!(
      bindings.get(&node(54)),
      Some(&key(54)),
      "the good binding row applied"
    );
    assert!(
      !bindings.contains_key(&node(56)),
      "the misattributed row did not adopt under a foreign key"
    );
  }

  /// The poison-row contract, resources arm: the same skip policy with
  /// the per-writer trust intact — a good record from a trusted writer
  /// lands, poison rows skip, and the repair shape does not wedge.
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn poison_rows_skip_and_good_resource_rows_apply() {
    use crate::resource::ResourceRecordV1;

    let context = context_with_bindings(&[]).await;
    let shared = plane_shared(&context).await;
    // The writer is trusted: its descriptor is in the local store.
    let writer = node(57);
    let descriptor = crate::membership::NodeDescriptorV1::new(
      writer.clone(),
      key(57),
      vec![crate::Endpoint::parse("wss://writer:9000").unwrap()],
      1,
      false,
      1,
    );
    crate::membership::store::store_descriptor_ctx(
      context.store(),
      &crate::api::SystemEntropy,
      &descriptor,
    )
    .await
    .unwrap();
    let name = crate::ResourceName::parse("example.org/resources/good").unwrap();
    let record = ResourceRecordV1::sign(
      name.clone(),
      crate::LabelValue::parse("document").unwrap(),
      crate::ResourceUri::parse("u://good").unwrap(),
      crate::LabelSet::new(),
      1_000,
      writer,
      0,
      false,
      &crate::identity::testing::scripted_signing(57),
    )
    .unwrap();
    let rows = vec![
      (name.as_str().as_bytes().to_vec(), record.encode().unwrap()),
      (b"example.org/resources/poison".to_vec(), vec![0xFF, 0x00]),
    ];
    super::apply_rows(
      shared.as_ref(),
      &super::super::wire::LaneId::Resources,
      &rows,
      None,
      None,
    )
    .await
    .unwrap();
    super::apply_rows(
      shared.as_ref(),
      &super::super::wire::LaneId::Resources,
      &rows,
      None,
      None,
    )
    .await
    .unwrap();
    assert!(
      crate::resource::store::read_record_ctx(context.store(), &name)
        .await
        .unwrap()
        .is_some(),
      "the good resource row applied behind the poison row"
    );
  }

  /// The poison-row contract, tombstone dispatch: undecodable
  /// leave/cleanup/revocation/checkpoint rows and unknown-kind rows
  /// skip; a good signed leave row in the same batch persists; the
  /// repair shape re-applies the batch without wedging.
  #[tokio::test]
  async fn poison_rows_skip_and_good_tombstone_rows_apply() {
    let context = context_with_bindings(&[]).await;
    let shared = plane_shared(&context).await;
    // A properly signed leave for the context's own node; its binding
    // is adopted into the trusted set first, so the evidence gate
    // passes and the signature verifies.
    crate::identity::trust::store::adopt_binding_ctx(
      context.store(),
      &crate::api::SystemEntropy,
      context.identity().node(),
      context.identity().public_key(),
    )
    .await
    .unwrap();
    let record = crate::identity::leave::sign_leave_record(&context, context.keys())
      .await
      .unwrap();
    let leaver = context.identity().node().clone();
    let mut key = vec![1_u8];
    key.extend_from_slice(leaver.as_str().as_bytes());
    let rows = vec![
      // Undecodable leave row.
      (vec![1_u8, 0xFF], vec![0xFF, 0x00]),
      // The good leave row.
      (key, record.encode().unwrap()),
      // Undecodable cleanup, revocation, and checkpoint rows.
      (vec![2_u8, 0xFF], vec![0xFF, 0x00]),
      (vec![3_u8, 0xFF], vec![0xFF, 0x00]),
      (vec![4_u8], vec![0xFF, 0x00]),
      // An unknown kind byte.
      (vec![9_u8], record.encode().unwrap()),
    ];
    let apply = |rows: Vec<_>| {
      let shared = std::sync::Arc::clone(&shared);
      async move {
        super::apply_rows(
          shared.as_ref(),
          &super::super::wire::LaneId::Tombstones,
          &rows,
          None,
          None,
        )
        .await
      }
    };
    apply(rows.clone()).await.unwrap();
    apply(rows).await.unwrap();
    assert!(
      crate::identity::leave::is_left_ctx(context.store(), &leaver)
        .await
        .unwrap(),
      "the good leave row applied behind the poison rows"
    );
  }

  /// The revoked-subject ordering (the delayed-content mirror): a node
  /// that received the revocation tombstone first refuses the subject's
  /// later binding row — the refusal skips the row instead of aborting
  /// the batch, so good bindings behind it still land and the repair
  /// shape re-applies without wedging.
  #[tokio::test]
  async fn a_revoked_subjects_binding_row_skips_without_wedging_the_batch() {
    let (reference, factory) = crate::identity::testing::fresh_reference();
    let keys = crate::identity::testing::ScriptedKeys::full_at(9_700);
    let entropy = std::sync::Arc::new(crate::identity::testing::SequenceEntropy::default());
    let context = std::sync::Arc::new(
      crate::identity::testing::open_context(&factory, &keys, &entropy)
        .await
        .unwrap(),
    );
    let shared = plane_shared(&context).await;
    // The revocation tombstone for node(61) arrives first: a stored
    // revocation record outranks any later binding row.
    let revoked = node(61);
    let revocation = crate::identity::revocation::RevocationRecordV1::new(
      revoked.clone(),
      key(61),
      context.identity().node().clone(),
      crate::Signature::from_bytes([0_u8; 64]),
    );
    let (namespace, store_key) = (
      crate::storage::families::namespace(crate::storage::families::REVOCATION_NAMESPACE).unwrap(),
      crate::StoreKey::new(std::sync::Arc::from(revoked.as_str().as_bytes().to_vec())),
    );
    crate::identity::testing::inject_entry(
      &reference,
      (namespace, store_key),
      revocation.encode().unwrap(),
    );
    // The batch: the revoked subject's binding row, then a good row.
    let revoked_binding =
      crate::identity::records::IdentityBindingV1::new(revoked.clone(), key(61));
    let good_binding = crate::identity::records::IdentityBindingV1::new(node(62), key(62));
    let rows = vec![
      (
        revoked.as_str().as_bytes().to_vec(),
        revoked_binding.encode().unwrap(),
      ),
      (
        node(62).as_str().as_bytes().to_vec(),
        good_binding.encode().unwrap(),
      ),
    ];
    super::apply_rows(
      shared.as_ref(),
      &super::super::wire::LaneId::Trust,
      &rows,
      None,
      None,
    )
    .await
    .unwrap();
    super::apply_rows(
      shared.as_ref(),
      &super::super::wire::LaneId::Trust,
      &rows,
      None,
      None,
    )
    .await
    .unwrap();
    let bindings = crate::identity::trust::store::trusted_bindings(context.store())
      .await
      .unwrap();
    assert!(
      !bindings.contains_key(&revoked),
      "the revoked subject's binding row was refused"
    );
    assert_eq!(
      bindings.get(&node(62)),
      Some(&key(62)),
      "the good binding behind the refused row still applied"
    );
  }

  /// One plane-shared fixture around a context.
  async fn plane_shared(context: &Arc<LocalIdentityContext>) -> Arc<super::PlaneShared> {
    let entropy = std::sync::Arc::new(crate::identity::testing::SequenceEntropy::default());
    let events = Arc::new(crate::node::EventHub::new());
    let (revision_tx, _revision_rx) = tokio::sync::watch::channel(0_u64);
    let sessions: crate::session::stream::SessionTable =
      Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::new()));
    super::ReconcilePlane::new(
      Arc::clone(context),
      entropy,
      events,
      crate::node::MemberRevisionSignal::new(revision_tx),
      sessions,
    )
    .shared()
  }

  /// A live single-peer session fixture: the session table holds one
  /// alive peer, and the runtime's packet channel drains (and acks) in
  /// the background so the plane's fire-and-forget dispatches never
  /// wedge the tick.
  fn live_peer(shared: &Arc<super::PlaneShared>) -> (crate::NodeId, crate::runtime::RuntimeClient) {
    let peer = node(900);
    let (entry, _rx) = crate::session::stream::test_entry(shared.entropy.as_ref());
    shared.sessions.lock().unwrap().insert(peer.clone(), entry);
    let (packet_tx, mut packet_rx) = tokio::sync::mpsc::channel(64);
    let routes: crate::routing::RouteTable =
      Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::new()));
    let runtime = crate::runtime::RuntimeClient::routing_only(packet_tx, routes);
    tokio::spawn(async move {
      while let Some(request) = packet_rx.recv().await {
        let _ = request.ack_notify.send(Ok(crate::packet::RoutedAck {
          by: crate::NodeId::parse("node-000000000000000000090").unwrap(),
          admitted_at: std::time::SystemTime::now(),
        }));
      }
    });
    (peer, runtime)
  }

  /// The peer's engine row count for one lane.
  fn engine_rows(
    shared: &Arc<super::PlaneShared>, peer: &crate::NodeId, lane: LaneId,
  ) -> Vec<(Vec<u8>, Vec<u8>)> {
    let guard = shared.state.lock().unwrap();
    guard
      .peers
      .get(peer)
      .and_then(|state| state.engines.get(&lane))
      .map(|engine| {
        engine
          .rows()
          .map(|(key, content)| (key.to_vec(), content.to_vec()))
          .collect()
      })
      .unwrap_or_default()
  }

  /// B-P2: a narrow scan plan keeps the other lanes' repair marks.
  /// The repair-pending set is what makes a policy-skipped row retry on
  /// any epoch advance (the cross-lane retry); a pass whose plan covers
  /// only one lane must not erase a different lane's mark, or that
  /// lane's retry stalls until its own namespace dirties again.
  #[test]
  fn a_narrow_plan_keeps_other_lanes_repair_marks() {
    let mut state = super::PlaneState {
      peers: BTreeMap::new(),
      install_epoch: 0,
      rotation: None,
      force_rescan: BTreeSet::new(),
      repair_pending: BTreeSet::new(),
      tick_count: 0,
      held_hints: BTreeMap::new(),
      held_roots: BTreeMap::new(),
    };
    state.repair_pending.insert(LaneId::Tombstones);
    state.repair_pending.insert(LaneId::Trust);
    // One narrow pass over the descriptors lane: its repair set is
    // empty (the store scan and the engines agree), the tombstones
    // mark stays.
    let plan: BTreeSet<LaneId> = [LaneId::Descriptors].into_iter().collect();
    let repair: super::LaneScan = Vec::new();
    let recomputed: BTreeSet<LaneId> = repair.iter().map(|(lane, _)| *lane).collect();
    state.repair_pending.retain(|lane| !plan.contains(lane));
    state.repair_pending.extend(recomputed);
    assert!(
      state.repair_pending.contains(&LaneId::Tombstones),
      "a lane outside the plan keeps its repair mark"
    );
    assert!(state.repair_pending.contains(&LaneId::Trust));
  }

  /// B-P2: the hint-retry budget exhausts. A weak link's pending hint
  /// spends its attempts one backoff at a time, the exhausted slot
  /// drops (the detection cadence is the backstop), and the budget
  /// never re-arms while a retry is still pending — a persistently
  /// failing session cannot loop forever.
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn the_hint_retry_budget_exhausts_to_the_cadence() {
    let context = context_with_bindings(&[101, 102]).await;
    let shared = plane_shared(&context).await;
    let (peer, runtime) = live_peer(&shared);
    let plane = super::ReconcilePlane {
      shared: Arc::clone(&shared),
    };
    {
      let mut guard = shared.state.lock().unwrap();
      let state = guard
        .peers
        .entry(peer.clone())
        .or_insert_with(super::PeerState::fresh);
      // A weak link (sustained loss) with one retry attempt left.
      for _ in 0..12 {
        state.profile.observe(None);
      }
      state.hint_retry = Some(super::PendingHint {
        message: crate::reconcile::wire::Message::Hint {
          lane: LaneId::Trust,
          ranges: Vec::new(),
          rows: Vec::new(),
        },
        attempts_left: 2,
        resume_at_tick: 1,
      });
    }
    plane.tick(&runtime).await.unwrap();
    {
      let guard = shared.state.lock().unwrap();
      let state = guard.peers.get(&peer).unwrap();
      let pending = state.hint_retry.as_ref().unwrap();
      assert_eq!(
        pending.attempts_left, 1,
        "the due retry spent one attempt and kept its remaining budget"
      );
    }
    // Burn the last attempt: the next due tick spends it and drops the
    // exhausted slot; a further tick never resurrects it.
    plane.tick(&runtime).await.unwrap();
    plane.tick(&runtime).await.unwrap();
    plane.tick(&runtime).await.unwrap();
    let guard = shared.state.lock().unwrap();
    let state = guard.peers.get(&peer).unwrap();
    assert!(
      state.hint_retry.is_none(),
      "the exhausted retry slot dropped to the detection cadence"
    );
  }

  /// A1/B-P1: the retention resurrection — a swept removal row leaves
  /// the engines on the sweep-noted epoch pass, a re-primed peer never
  /// receives the historical removal set back, and a peer re-delivering
  /// the swept row is filtered at the receive boundary (the tombstone
  /// collected-mode mirror for resources).
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn a_swept_removal_row_never_resurrects() {
    use crate::resource::{ResourceName, ResourceRecordV1};

    let context = context_with_bindings(&[101, 102]).await;
    let shared = plane_shared(&context).await;
    let (peer, runtime) = live_peer(&shared);
    let plane = super::ReconcilePlane {
      shared: Arc::clone(&shared),
    };
    // A removal record the writer signs directly into the store (the
    // writer's descriptor is trusted so the page apply accepts it).
    let writer = node(701);
    let signing = crate::identity::testing::scripted_signing(701);
    let descriptor = crate::membership::NodeDescriptorV1::new(
      writer.clone(),
      key(701),
      vec![crate::Endpoint::parse("wss://127.0.0.1:3").unwrap()],
      1,
      false,
      1,
    );
    crate::membership::store::store_descriptor_ctx(
      context.store(),
      &crate::api::SystemEntropy,
      &descriptor,
    )
    .await
    .unwrap();
    let name = ResourceName::parse("radiata.woooo.tech/resources/swept").unwrap();
    let removal = ResourceRecordV1::sign(
      name.clone(),
      crate::LabelValue::parse("document").unwrap(),
      crate::ResourceUri::parse("file:///swept").unwrap(),
      crate::LabelSet::new(),
      1_000,
      writer,
      1,
      true,
      &signing,
    )
    .unwrap();
    let encoded = removal.encode().unwrap();
    crate::resource::store::commit_record_ctx(
      context.store(),
      &crate::api::SystemEntropy,
      &removal,
    )
    .await
    .unwrap();
    // The plane primes: the removal row is live data (within any
    // retention window) and enters the engines.
    plane.tick(&runtime).await.unwrap();
    let primed = engine_rows(&shared, &peer, LaneId::Resources);
    assert_eq!(
      primed.len(),
      1,
      "the removal row enters the engine while the store holds it"
    );

    // The retention sweep reclaims it (zero window, immediate).
    let swept = crate::resource::retention::sweep_removed_ctx(
      context.store(),
      &crate::time::HostWallClock,
      std::time::Duration::ZERO,
      0,
    )
    .await
    .unwrap();
    assert_eq!(swept, 1, "the removal swept");
    // The sweep-noted epoch pass prunes the row out of the engines
    // instead of feeding it to the repair set.
    plane.tick(&runtime).await.unwrap();
    let pruned = engine_rows(&shared, &peer, LaneId::Resources);
    assert!(
      pruned.is_empty(),
      "the swept removal row left the engines, not the repair set"
    );
    assert!(
      crate::resource::store::read_record_ctx(context.store(), &name)
        .await
        .unwrap()
        .is_none(),
      "the repair did not resurrect the swept row"
    );

    // A peer re-delivering the swept row is filtered at the receive
    // boundary: no engine admission, no store write.
    plane
      .deliver(
        &runtime,
        &peer,
        crate::reconcile::wire::Message::Rows {
          lane: LaneId::Resources,
          rows: vec![crate::reconcile::wire::Row {
            key: name.as_str().as_bytes().to_vec(),
            content: encoded.clone(),
          }],
        },
      )
      .await
      .unwrap();
    assert!(
      engine_rows(&shared, &peer, LaneId::Resources).is_empty(),
      "the swept row never re-enters the engine"
    );
    assert!(
      crate::resource::store::read_record_ctx(context.store(), &name)
        .await
        .unwrap()
        .is_none(),
      "the swept row never re-materializes in the store"
    );

    // The re-prime contract: a returning session receives only the
    // current row set — the historical removal is gone with the sweep.
    shared.sessions.lock().unwrap().clear();
    plane.tick(&runtime).await.unwrap();
    shared.sessions.lock().unwrap().insert(
      peer.clone(),
      crate::session::stream::test_entry(shared.entropy.as_ref()).0,
    );
    plane.tick(&runtime).await.unwrap();
    assert!(
      engine_rows(&shared, &peer, LaneId::Resources).is_empty(),
      "a re-primed peer receives no historical removal set"
    );
  }

  /// A1: a superseded identity (a descriptor revision bump) leaves the
  /// engine row set on the epoch pass — the engine tracks the store's
  /// current row per key instead of growing monotonically — and a peer
  /// re-primed afterwards receives only the current identity (no
  /// historical rows).
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn a_revision_bump_prunes_the_superseded_engine_row() {
    let context = context_with_bindings(&[101, 102]).await;
    let shared = plane_shared(&context).await;
    let (peer, runtime) = live_peer(&shared);
    let plane = super::ReconcilePlane {
      shared: Arc::clone(&shared),
    };
    let descriptor = crate::membership::NodeDescriptorV1::new(
      node(700),
      key(700),
      vec![crate::Endpoint::parse("wss://127.0.0.1:1").unwrap()],
      1,
      false,
      1,
    );
    crate::membership::store::store_descriptor_ctx(
      context.store(),
      &crate::api::SystemEntropy,
      &descriptor,
    )
    .await
    .unwrap();
    plane.tick(&runtime).await.unwrap();
    let primed = engine_rows(&shared, &peer, LaneId::Descriptors);
    assert_eq!(primed.len(), 1, "the engine holds the one descriptor row");
    let old_identity = primed[0].clone();

    // The revision bump: the same key under new content supersedes the
    // primed identity.
    let bumped = crate::membership::NodeDescriptorV1::new(
      node(700),
      key(700),
      vec![crate::Endpoint::parse("wss://127.0.0.1:2").unwrap()],
      2,
      false,
      1,
    );
    crate::membership::store::store_descriptor_ctx(
      context.store(),
      &crate::api::SystemEntropy,
      &bumped,
    )
    .await
    .unwrap();
    plane.tick(&runtime).await.unwrap();
    let pruned = engine_rows(&shared, &peer, LaneId::Descriptors);
    assert_eq!(
      pruned.len(),
      1,
      "the engine row set did not grow on a revision bump"
    );
    assert_eq!(
      pruned[0].1,
      bumped.encode().unwrap(),
      "the current identity"
    );
    assert_ne!(pruned[0], old_identity, "the superseded identity left");

    // The re-prime contract: the session drops and returns, the fresh
    // engine fills with exactly the current row set — the historical
    // identity never re-crosses.
    shared.sessions.lock().unwrap().clear();
    plane.tick(&runtime).await.unwrap();
    shared.sessions.lock().unwrap().insert(
      peer.clone(),
      crate::session::stream::test_entry(shared.entropy.as_ref()).0,
    );
    plane.tick(&runtime).await.unwrap();
    let reprimed = engine_rows(&shared, &peer, LaneId::Descriptors);
    assert_eq!(
      reprimed.len(),
      1,
      "a re-primed peer receives only the current row set"
    );
    assert_eq!(reprimed[0].1, bumped.encode().unwrap());
  }

  /// A2 (the leave/restart livelock): a descriptor row the store
  /// deterministically refuses — a stale revision here — never enters
  /// the engines at the receive boundary. Admitting it made every
  /// fingerprint exchange re-detect the divergence: the epoch pass
  /// pruned the row, the prune's hint re-announced the change, and the
  /// peers that still listed the stale revision pushed it back — an
  /// unbounded re-negotiation loop that starved a single core's data
  /// plane (the transport-chaos relay wedges).
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn a_stale_descriptor_row_never_enters_the_engines() {
    let context = context_with_bindings(&[101, 102]).await;
    let shared = plane_shared(&context).await;
    let (peer, runtime) = live_peer(&shared);
    let plane = super::ReconcilePlane {
      shared: Arc::clone(&shared),
    };
    // The store holds node(700) at revision 2 (its binding is adopted,
    // so the first install at revision 1 was healable and applied).
    let stale = crate::membership::NodeDescriptorV1::new(
      node(700),
      key(700),
      vec![crate::Endpoint::parse("wss://127.0.0.1:1").unwrap()],
      1,
      false,
      1,
    );
    let current = crate::membership::NodeDescriptorV1::new(
      node(700),
      key(700),
      vec![crate::Endpoint::parse("wss://127.0.0.1:2").unwrap()],
      2,
      false,
      1,
    );
    for descriptor in [&stale, &current] {
      crate::membership::store::store_descriptor_ctx(
        context.store(),
        &crate::api::SystemEntropy,
        descriptor,
      )
      .await
      .unwrap();
    }
    plane.tick(&runtime).await.unwrap();
    assert_eq!(
      engine_rows(&shared, &peer, LaneId::Descriptors).len(),
      1,
      "the engine holds the one current descriptor row"
    );

    // A lagging peer re-delivers the superseded revision.
    plane
      .deliver(
        &runtime,
        &peer,
        crate::reconcile::wire::Message::Rows {
          lane: LaneId::Descriptors,
          rows: vec![crate::reconcile::wire::Row {
            key: node(700).as_str().as_bytes().to_vec(),
            content: stale.encode().unwrap(),
          }],
        },
      )
      .await
      .unwrap();
    let rows = engine_rows(&shared, &peer, LaneId::Descriptors);
    assert_eq!(
      rows.len(),
      1,
      "the refused row never entered the engine, even transiently"
    );
    assert_eq!(rows[0].1, current.encode().unwrap(), "the current row only");
    assert_eq!(
      crate::membership::store::read_descriptor_ctx(context.store(), &node(700))
        .await
        .unwrap()
        .as_ref()
        .map(crate::membership::NodeDescriptorV1::revision),
      Some(2),
      "the store kept the newer revision"
    );
    // The follow-up epoch pass stays quiet: nothing to prune, nothing
    // to repair, no hint about a change that was never news.
    plane.tick(&runtime).await.unwrap();
    assert_eq!(
      engine_rows(&shared, &peer, LaneId::Descriptors).len(),
      1,
      "the pass found no superseded row to prune"
    );
  }

  /// A2's leaver shape: a wiped store holds no binding for the row's
  /// subject, so a first descriptor install above revision 1 is refused
  /// forever. The row must not sit in the engines as repair evidence —
  /// the repair can never succeed, and every exchange would re-deliver
  /// the same refused bytes (the leave/rejoin livelock carrier).
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn an_unhealable_first_install_stays_out_of_the_engines() {
    let context = context_with_bindings(&[101, 102]).await;
    let shared = plane_shared(&context).await;
    let (peer, runtime) = live_peer(&shared);
    let plane = super::ReconcilePlane {
      shared: Arc::clone(&shared),
    };
    plane.tick(&runtime).await.unwrap();
    // node(700) has no binding here and no stored descriptor: revision 3
    // is an unhealable first install.
    let orphan = crate::membership::NodeDescriptorV1::new(
      node(700),
      key(700),
      vec![crate::Endpoint::parse("wss://127.0.0.1:1").unwrap()],
      3,
      false,
      1,
    );
    plane
      .deliver(
        &runtime,
        &peer,
        crate::reconcile::wire::Message::Rows {
          lane: LaneId::Descriptors,
          rows: vec![crate::reconcile::wire::Row {
            key: node(700).as_str().as_bytes().to_vec(),
            content: orphan.encode().unwrap(),
          }],
        },
      )
      .await
      .unwrap();
    assert!(
      engine_rows(&shared, &peer, LaneId::Descriptors).is_empty(),
      "the unhealable first install never entered the engine"
    );
    assert!(
      crate::membership::store::read_descriptor_ctx(context.store(), &node(700))
        .await
        .unwrap()
        .is_none(),
      "the store refused the first install, as designed"
    );
    // The epoch pass does not adopt it as repair work: the repair set
    // stays empty and the row never re-crosses to a peer.
    plane.tick(&runtime).await.unwrap();
    assert!(
      engine_rows(&shared, &peer, LaneId::Descriptors).is_empty(),
      "no repair candidate appeared for the refused row"
    );
  }

  /// The trust-lane mirror of the same gate: a revoked subject's
  /// binding row is refused evidence — it applies never, so it must not
  /// enter the engines and answer later exchanges with bytes the store
  /// will refuse again.
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn a_revoked_binding_row_never_enters_the_engines() {
    let (reference, factory) = crate::identity::testing::fresh_reference();
    let keys = crate::identity::testing::ScriptedKeys::full_at(9_700);
    let entropy = Arc::new(crate::identity::testing::SequenceEntropy::default());
    let context = Arc::new(
      crate::identity::testing::open_context(&factory, &keys, &entropy)
        .await
        .unwrap(),
    );
    let shared = plane_shared(&context).await;
    let (peer, runtime) = live_peer(&shared);
    let plane = super::ReconcilePlane {
      shared: Arc::clone(&shared),
    };
    let revoked = node(61);
    let revocation = crate::identity::revocation::RevocationRecordV1::new(
      revoked.clone(),
      key(61),
      context.identity().node().clone(),
      crate::Signature::from_bytes([0_u8; 64]),
    );
    let (namespace, store_key) = (
      crate::storage::families::namespace(crate::storage::families::REVOCATION_NAMESPACE).unwrap(),
      crate::StoreKey::new(Arc::from(revoked.as_str().as_bytes().to_vec())),
    );
    crate::identity::testing::inject_entry(
      &reference,
      (namespace, store_key),
      revocation.encode().unwrap(),
    );
    plane.tick(&runtime).await.unwrap();
    let binding = crate::identity::records::IdentityBindingV1::new(revoked.clone(), key(61));
    plane
      .deliver(
        &runtime,
        &peer,
        crate::reconcile::wire::Message::Rows {
          lane: LaneId::Trust,
          rows: vec![crate::reconcile::wire::Row {
            key: revoked.as_str().as_bytes().to_vec(),
            content: binding.encode().unwrap(),
          }],
        },
      )
      .await
      .unwrap();
    assert!(
      engine_rows(&shared, &peer, LaneId::Trust)
        .iter()
        .all(|(key, _)| key.as_slice() != revoked.as_str().as_bytes()),
      "the revoked subject's binding row never entered the engine"
    );
  }

  /// A1: collected tombstone rows never enter the derived view on
  /// either side — the scan filters them (so a prime cannot carry them)
  /// and the receive-side predicate is exactly the apply boundary's
  /// collected test.
  #[tokio::test]
  async fn collected_tombstone_rows_stay_out_of_the_scan() {
    let context = context_with_bindings(&[101, 102]).await;
    let record = crate::identity::leave::sign_leave_record(&context, context.keys())
      .await
      .unwrap();
    let stamp = record.timestamp_millis();
    let leaver = context.identity().node().clone();
    let mut key = vec![1_u8];
    key.extend_from_slice(leaver.as_str().as_bytes());
    let content = record.encode().unwrap();
    // The checkpoint sits past the record's stamp: the row is collected.
    let collected = super::tombstone_collected(Some(stamp), &key, &content);
    assert!(collected, "a record at the watermark is collected");
    assert!(
      !super::tombstone_collected(Some(stamp - 1), &key, &content),
      "a record after the watermark is live"
    );
    assert!(
      !super::tombstone_collected(None, &key, &content),
      "no checkpoint means nothing is collected"
    );
    // The revocation and checkpoint rows are never collected evidence.
    let revocation_key = vec![3_u8];
    assert!(!super::tombstone_collected(
      Some(u64::MAX),
      &revocation_key,
      &content
    ));
  }

  /// B2/B4: the link profile's knob curve. A fresh session (no
  /// samples) is healthy with every knob open; sustained undelivered
  /// dispatches cross the loss threshold and flip all three knobs; a
  /// slow-but-delivered session crosses on the RTT threshold alone;
  /// recovery (delivered traffic decaying the loss EWMA) restores the
  /// healthy band. The knobs never touch the payload path.
  #[test]
  fn the_link_profile_curve_drives_exactly_three_knobs() {
    let mut profile = super::LinkProfile::default();
    assert!(!profile.weak(), "a fresh session is healthy");
    assert_eq!(profile.cadence_divisor(), 1, "the base cadence");
    assert!(profile.eager_delta(), "eager-delta defaults on");

    // Sustained loss: twelve undelivered dispatches push the loss EWMA
    // (≈ 1 − 0.875¹² ≈ 0.80) far past the 10% threshold.
    for _ in 0..12 {
      profile.observe(None);
    }
    assert!(profile.weak(), "a lossy link is weak");
    assert_eq!(profile.cadence_divisor(), 4, "the weak-link cadence ¼");
    assert!(!profile.eager_delta(), "eager-delta off on a weak link");

    // Recovery: delivered traffic decays the loss EWMA below the
    // threshold (0.8 × 0.875ⁿ < 0.10 needs n ≥ 15).
    for _ in 0..16 {
      profile.observe(Some(std::time::Duration::from_micros(400)));
    }
    assert!(!profile.weak(), "a recovered link is healthy again");
    assert!(profile.eager_delta());

    // The RTT band: a delivered but slow session is weak on latency
    // alone — a 3 s admission latency crosses the 1.5 s threshold even
    // with zero loss.
    let mut slow = super::LinkProfile::default();
    slow.observe(Some(std::time::Duration::from_secs(3)));
    assert!(slow.weak(), "a slow link is weak");
    assert_eq!(slow.cadence_divisor(), 4);
    assert!(!slow.eager_delta());
  }
}
