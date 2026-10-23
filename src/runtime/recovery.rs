//! The recovery plane: the known-online healing policy over the
//! authenticated session set, forward-entry selection for packet relay,
//! and the recovery-observation worker that drives the bounded recovery
//! tick and the retention sweeps off the supervisor's select loop.

use std::sync::Arc;

use tracing::debug;

use super::supervisor::{Supervisor, TickState, dial_member};
use crate::{Endpoint, Error, NodeId, Result, session::stream::SessionEntry};

/// The recovery controller's observation period (unnamed literal kept
/// every other period out of `NodeConfig`).
pub(super) const RECOVERY_TICK_PERIOD: std::time::Duration = std::time::Duration::from_secs(2);

/// Runs the recovery-observation worker: one long-lived task that owns
/// the recovery cadence and, per tick, runs the recovery tick followed
/// by the three retention sweeps — the exact work the supervisor's
/// select loop used to await inline (audit 2026-10-09 item 3), so slow
/// storage no longer parks control-plane reads and packet admission
/// behind a tick.
///
/// Overlap policy — SKIP, never queue: the worker is a single task and
/// runs each tick inline in its own loop, and the timer's
/// `MissedTickBehavior::Skip` drops every deadline that fires while a
/// tick is still running. A tick is an observation of current state
/// (session table, member table, retention deadlines), not an event to
/// process, so a skipped tick loses nothing the next one would not
/// recompute — while queueing or merging would only stack stale
/// observations behind a slow store. Bounded accounting (audit item 4's
/// lesson): exactly one task for the node's lifetime, aborted and
/// awaited by the shutdown path — never one spawned task per tick.
pub(super) async fn run_recovery_worker(state: Arc<TickState>) {
  let mut shutdown = state.shutdown.clone();
  let mut timer = tokio::time::interval(RECOVERY_TICK_PERIOD);
  timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
  loop {
    tokio::select! {
      changed = shutdown.changed() => {
        let _ = changed;
        break;
      }
      _ = timer.tick() => {
        // A failed tick (store outage, tombstone scan failure) must stay
        // visible: silent drops would starve recovery diagnostics.
        if let Err(error) = state.recovery_tick().await {
          tracing::warn!(kind = ?error.kind(), "recovery tick failed");
        }
        state.trace_retention_sweep().await;
        state.resource_removal_sweep().await;
        state.receipt_retention_sweep().await;
      }
    }
  }
}

/// The cleaned and left node sets behind the recovery exclusions and the
/// member status annotations, kept distinct so a cleaned member still
/// annotates as [`crate::MemberStatus::Cleaned`] rather than left.
#[derive(Clone, Default)]
pub(super) struct Departed {
  cleaned: std::collections::BTreeSet<NodeId>,
  left: std::collections::BTreeSet<NodeId>,
}

impl Departed {
  async fn compute(store: &crate::storage::MetadataStore) -> Result<Self> {
    Ok(Self {
      cleaned: crate::identity::cleanup::cleaned_nodes_ctx(store).await?,
      left: crate::identity::leave::left_nodes_ctx(store).await?,
    })
  }

  /// The union exclusion set for the recovery plane.
  pub(super) fn union(&self) -> std::collections::BTreeSet<NodeId> {
    self
      .cleaned
      .iter()
      .chain(self.left.iter())
      .cloned()
      .collect()
  }

  /// The member status annotation for one node.
  pub(super) fn status(&self, node: &NodeId) -> crate::MemberStatus {
    crate::membership::member_status(self.cleaned.contains(node), self.left.contains(node))
  }
}

/// Recovery-tick cooldown between pruning two recovery-dialed redundant
/// edges: one cut per four 2s ticks (8s) drains a post-partition mesh
/// gradually enough to observe stability between cuts while still
/// converging in seconds-to-a-minute on small clusters.
const RECOVERY_PRUNE_COOLDOWN_TICKS: u32 = 4;

impl Supervisor {
  /// Resolves one live downstream session for a routed first hop through
  /// the node's effective next-hop policy (the caller selection, or the
  /// built-in default policy). `Ok(None)` means no eligible hop exists and
  /// the caller fails the route explicitly.
  pub(super) async fn select_forward_entry(
    &self, trace: &crate::TraceId, destination: &NodeId,
  ) -> Result<Option<SessionEntry>> {
    let tag = self.dependencies.config.route_policy()?;
    let local = self.packet.local().clone();
    let peers = crate::sync_common::alive_peers(&self.dependencies.sessions)?;
    let hop = match crate::routing::resolve_next_hop(
      &self.dependencies.extensions,
      &tag,
      trace,
      destination,
      &local,
      &peers,
    )
    .await
    {
      Ok(Some(hop)) => hop,
      Ok(None) => {
        tracing::warn!(tag = %tag, "configured route policy is not registered");
        return Ok(None);
      }
      Err(error) => return Err(error),
    };
    let entry = self
      .dependencies
      .sessions
      .lock()
      .map_err(Error::session_table)?
      .get(&hop)
      .filter(|entry| entry.alive())
      .cloned();
    debug!(hop = %hop, selected = entry.is_some(), "forward candidate resolved");
    Ok(entry)
  }
  /// Resolves one matching-node target to exactly one eligible
  /// destination: the registered load-balancing policy selects among the
  /// incrementally streamed candidates, and core independently validates
  /// the pick against the authoritative descriptors — an unknown, removed,
  /// or nonmatching node fails closed before any frame moves.
  pub(super) async fn select_matching_destination(
    &self, selector: &crate::Selector, load_balancer: Option<&crate::QualifiedTag>,
  ) -> Result<NodeId> {
    let Some(load_balancer) = load_balancer else {
      return Err(Error::invalid_input("packet load balancer"));
    };
    let policy = self
      .dependencies
      .extensions
      .load_balancer(load_balancer)
      .ok_or_else(|| Error::invalid_input("packet load balancer"))?;
    let snapshot = self.context()?.store().snapshot().await?;
    let reader = crate::routing::StoreCandidateReader::new(snapshot);
    let selected = policy.select(selector, &reader).await?;
    // Authoritative re-validation of the selected destination.
    let descriptor =
      crate::membership::store::read_descriptor_ctx(self.context()?.store(), &selected).await?;
    let Some(descriptor) = descriptor else {
      return Err(Error::not_found("packet destination"));
    };
    if descriptor.removed() || !selector.matches(descriptor.labels()) {
      return Err(Error::not_trusted("packet destination"));
    }
    Ok(selected)
  }

  /// The public recovery observation: whether every known online member
  /// has an authenticated path, how many members remain unreachable, and
  /// the next scheduled attempt.
  pub(super) fn recovery_view(&self) -> crate::RecoveryView {
    controller_view(&self.recovery)
  }
  /// The departed-members exclusion state (cleaned + left), memoized per
  /// store revision: rescanning and decoding every accumulated tombstone
  /// on every two-second tick (and every member page) is unbounded work
  /// for an answer that only changes when a tombstone commit moves the
  /// revision. A poisoned cache only costs a recompute.
  pub(super) async fn departed_exclusions(
    &self, store: &crate::storage::MetadataStore,
  ) -> Result<Departed> {
    departed_exclusions(&self.exclusion_cache, store).await
  }
}

/// The public recovery observation over the shared controller, with the
/// poisoned-lock fallback shared by the supervisor's read view and the
/// recovery worker's before/after emission check: a poisoned lock only
/// costs the observation — the view reports the recovering fallback
/// instead of failing the read.
fn controller_view(
  recovery: &std::sync::Arc<std::sync::Mutex<crate::membership::recovery::RecoveryController>>,
) -> crate::RecoveryView {
  match recovery.lock() {
    Ok(controller) => recovery_view(&controller),
    Err(_) => crate::RecoveryView::new(false, 0, None),
  }
}

/// The full recovery universe with EVERY published endpoint per
/// member: a multi-homed member's later endpoints stay dial candidates,
/// and both dial planes rotate through them per member — one serial per
/// member, advanced once per dial of that member (endpoint-level
/// failover), so a member whose first endpoint is unreachable is still
/// reached on the others (audit 2026-10-09 item 7). The degree plane
/// consumes the SAME full endpoint lists and the SAME per-member
/// rotation (see `runtime/degree.rs`), so the first-endpoint projection
/// the degree dialer used to carry is gone (remaining-items list P2-5).
pub(super) async fn known_online_member_endpoints(
  cache: &ExclusionCache, store: &crate::storage::MetadataStore, local: &NodeId,
) -> Result<std::collections::BTreeMap<NodeId, Vec<Endpoint>>> {
  // Departed identities (left or cleaned) are no longer cluster
  // members: they never enter the member table, so the recovery plane
  // cannot count one as pending — that would keep the controller
  // Recovering forever, never quiescent, attempts unbounded, and peg
  // the dial backoff at its maximum for every future partition.
  let excluded = departed_exclusions(cache, store).await?.union();
  // The member table IS the recovery universe: every member with a
  // trusted binding, a live descriptor, and a published endpoint is a
  // retry candidate while the node is isolated. Scanning it every tick
  // (not once at startup) is what lets a first-join leaf — whose
  // descriptor table filled only after its first recovery tick —
  // still dial a different member after its bootstrap dies.
  let bindings = crate::identity::trust::store::trusted_bindings(store).await?;
  let snapshot = store.snapshot().await?;
  let namespace = crate::membership::descriptor_namespace()?;
  let mut scan = snapshot.scan_from(&namespace, &[], None).await?;
  let mut known_members: std::collections::BTreeMap<NodeId, Vec<Endpoint>> =
    std::collections::BTreeMap::new();
  while let Some(entry) = scan.next().await? {
    let decoded = crate::membership::page::decode_descriptor(entry.value().as_bytes());
    let descriptor = match decoded {
      Ok(descriptor) => descriptor,
      // The table scan is best-effort over durable evidence; a corrupt
      // entry skips this round, but never silently.
      Err(error) => {
        tracing::debug!(kind = ?error.kind(), "recovery skipped an undecodable descriptor");
        continue;
      }
    };
    let node = descriptor.node().clone();
    if descriptor.removed()
      || &node == local
      || excluded.contains(&node)
      || !bindings.contains_key(&node)
    {
      continue;
    }
    if descriptor.endpoints().is_empty() {
      // No published endpoint: recovery stays best-effort, but the
      // skip is visible in diagnostics instead of silent.
      tracing::debug!(member = %node.as_str(), "no published endpoint; skipped");
      continue;
    }
    known_members.insert(node, descriptor.endpoints().to_vec());
  }
  Ok(known_members)
}

impl TickState {
  /// One recovery observation tick: feed the controller the member-table
  /// set (the recovery universe) and the current direct sessions, prune
  /// one redundant recovery-dialed edge per cooldown while connected,
  /// then — while fully isolated — dial unreachable members whose
  /// endpoints are published, through the configured bounded fan-out
  /// (recovery restores authenticated path connectivity to known members
  /// and quiesces; it never dials strangers or the local node, so it
  /// cannot add edges beyond the configured topology). Runs on the
  /// recovery worker (see [`run_recovery_worker`]), never inline in the
  /// supervisor's select loop.
  pub(super) async fn recovery_tick(&self) -> Result<()> {
    let before = controller_view(&self.recovery);
    let result = self.recovery_tick_inner().await;
    let after = controller_view(&self.recovery);
    if after != before {
      self.events.emit(crate::RecoveryChanged::new(after));
    }
    result
  }

  pub(super) async fn recovery_tick_inner(&self) -> Result<()> {
    // Finished connection tasks keep their JoinHandles until reaped, so a
    // long-lived listener would otherwise grow one dead handle per ever
    // accepted connection and inflate the observability counts. Reaping
    // each tick keeps the vec and the counts live-work only; abort() on a
    // finished handle is a no-op, so shutdown semantics are unchanged.
    if let Ok(mut handles) = self.connection_tasks.lock() {
      handles.retain(|handle| !handle.is_finished());
    }
    let direct: std::collections::BTreeSet<NodeId> = self
      .sessions
      .lock()
      .map_err(Error::session_table)?
      .iter()
      .filter(|(_, entry)| entry.alive())
      .map(|(peer, _)| peer.clone())
      .collect();
    let store = self.context.store();
    let local = self.context.identity().node().clone();
    let known_members = known_online_member_endpoints(&self.exclusion_cache, store, &local).await?;
    let known: std::collections::BTreeSet<NodeId> = known_members.keys().cloned().collect();
    // Bounded endpoint-rotation state: a serial for a member that left
    // the member table is dead rotation phase. Drop such entries each
    // tick so the per-member serial map tracks the live member
    // universe, not the node's dial history (the maintenance worker
    // advances serials under the same lock for members of this same
    // universe).
    if let Ok(mut attempts) = self.endpoint_attempts.lock() {
      attempts.retain(|member, _| known_members.contains_key(member));
    }
    let now = crate::time::now_seconds();
    let dial_due = {
      let mut controller = self
        .recovery
        .lock()
        .map_err(|_| crate::Error::internal("recovery controller"))?;
      controller.observe(&known, &direct);
      controller.state() == crate::membership::recovery::RecoveryState::Recovering
        && controller.due(now)
    };
    self.maybe_prune_recovery_edges(&direct)?;
    // The documented in-flight bound (the counter bounds in-flight
    // dials, not lifetime volume): checked here to skip the whole step
    // when already full, and re-checked before EVERY spawn below —
    // slots held by previous ticks' dials free up between ticks, so a
    // pre-batch check alone would admit up to `2*fan_out - 1`
    // concurrent dials (audit finding #5).
    let fan_out = self.config.recovery().fan_out().max(1);
    if !dial_due
      || self
        .recovery_pending
        .load(std::sync::atomic::Ordering::Relaxed)
        >= fan_out
    {
      return Ok(());
    }
    // The node is fully isolated: retry every table member it is not
    // directly connected to, one bounded fan-out step at a time, until
    // any one connects (the "any one route" deployment contract). The
    // candidate set carries every published endpoint per member.
    let mut candidates: std::collections::BTreeMap<NodeId, Vec<Endpoint>> =
      std::collections::BTreeMap::new();
    for member in known.difference(&direct) {
      if let Some(endpoints) = known_members.get(member) {
        candidates.insert(member.clone(), endpoints.clone());
      }
    }
    let step = {
      let mut controller = self
        .recovery
        .lock()
        .map_err(|_| crate::Error::internal("recovery controller"))?;
      controller.next_step(
        now,
        &candidates.keys().cloned().collect(),
        self.entropy.as_ref(),
      )
    };
    for member in step.targets {
      // Bound re-check per spawn (audit finding #5): the counter only
      // ever decrements when a dial completes, so the check immediately
      // before the spawn below (which acquires the slot) holds the
      // in-flight count at the bound; the truncated targets stay
      // candidates for the controller's rotating cursor on a later step.
      if self
        .recovery_pending
        .load(std::sync::atomic::Ordering::Relaxed)
        >= fan_out
      {
        debug!("recovery step truncated at the in-flight fan-out bound");
        break;
      }
      let Some(endpoints) = candidates.get(&member) else {
        continue;
      };
      // Endpoint-level failover with a PER-MEMBER serial: every dial of
      // this member advances its own rotation, wrapping per member, so
      // each member sweeps ALL its published endpoints no matter which
      // members the schedule picks (audit 2026-10-09 item 7; a shared
      // schedule serial aliased member position with endpoint index and
      // could pin a member to one endpoint forever).
      let Some(serial) = self.member_dial_serial(&member) else {
        continue;
      };
      let Some(endpoint) = recovery_endpoint(endpoints, serial) else {
        continue;
      };
      // Recovery dials run in their own task so the tick worker never
      // blocks on a handshake (each holds its in-flight slot no longer
      // than the configured dial deadline plus the authentication
      // deadline); the shared dial lifecycle below owns the execution
      // and tracking mechanics, and the result is reconciled by the next
      // observation tick.
      spawn_member_dial(
        self,
        Arc::clone(&self.recovery_pending),
        member.clone(),
        endpoint.clone(),
        true,
        report_recovery_dial_failure,
      );
    }
    Ok(())
  }

  /// Consumes one per-member endpoint serial for the dial about to
  /// start — shared by both dial planes (recovery and degree
  /// maintenance): the serial is the member's dial count, so
  /// [`recovery_endpoint`] lands a member's first dial on its first
  /// published endpoint and every further dial of that member on its
  /// next one, wrapping per member. That is the failover liveness
  /// contract: every member sweeps all its published endpoints for any
  /// candidate count, endpoint count, or fan-out.
  ///
  /// A poisoned lock only costs this dial's rotation advance: the dial
  /// is skipped this tick and the member stays a candidate for the
  /// next step (the map's critical sections are panic-free, so poison
  /// is unreachable in practice).
  pub(super) fn member_dial_serial(&self, member: &NodeId) -> Option<u64> {
    let mut attempts = self.endpoint_attempts.lock().ok()?;
    Some(advance_member_serial(&mut attempts, member))
  }

  /// Bounded pruning of recovery-accumulated redundant edges.
  /// While connected, retires at most one recovery-dialed session per
  /// cooldown, choosing the highest peer id deterministically. An edge is
  /// pruned only while at least one caller-configured or inbound session
  /// remains: a node holding only recovery-dialed sessions never prunes
  /// (those edges are its lifeline), so pruning can never re-isolate the
  /// node, and a restored primary edge (inbound on this side) gradually
  /// displaces the recovery mesh. Caller-configured and inbound sessions
  /// are never reclaimed here.
  ///
  /// The cooldown is an atomic because the tick state is Arc-shared
  /// between the two workers; only the recovery worker mutates it, so a
  /// racing read at worst shifts one cut by one tick.
  pub(super) fn maybe_prune_recovery_edges(
    &self, direct: &std::collections::BTreeSet<NodeId>,
  ) -> Result<()> {
    let connected = match self.recovery.lock() {
      Ok(controller) => controller.state() == crate::membership::recovery::RecoveryState::Connected,
      // A poisoned lock only costs this tick's prune: the edge set
      // stays as it is.
      Err(_) => false,
    };
    if !connected {
      return Ok(());
    }
    let cooldown = self
      .prune_cooldown
      .load(std::sync::atomic::Ordering::Relaxed);
    self.prune_cooldown.store(
      cooldown.saturating_sub(1),
      std::sync::atomic::Ordering::Relaxed,
    );
    if cooldown > 1 {
      return Ok(());
    }
    // The scan and the removal share ONE session-table lock span: the
    // victim is removed by the exact entry identity the scan observed
    // (re-verified as an alive, direct, recovery-dialed edge), so a
    // reconnect that replaces the map entry in any window can never be
    // retired as the old redundant edge (audit 2026-10-09 item 13
    // addendum:
    // the recovery-dialed flag belongs to the entry, not the key).
    let victim: Option<(NodeId, crate::session::stream::SessionEntry)> = {
      let mut sessions = self.sessions.lock().map_err(Error::session_table)?;
      let mut marked = Vec::new();
      let mut unmarked = Vec::new();
      for (peer, entry) in sessions.iter() {
        if !direct.contains(peer) || !entry.alive() {
          continue;
        }
        if entry.recovery_dialed() {
          marked.push(peer.clone());
        } else {
          unmarked.push(peer.clone());
        }
      }
      // The star-preservation rule: pruning requires a non-recovery edge
      // to keep this node connected, so the fallback route survives the
      // cut. The highest peer id remains the deterministic victim.
      let Some(victim) = marked.iter().max().cloned() else {
        return Ok(());
      };
      if unmarked.is_empty() {
        return Ok(());
      }
      let removable = sessions
        .get(&victim)
        .is_some_and(|entry| entry.alive() && entry.recovery_dialed());
      removable
        .then(|| sessions.remove(&victim).map(|entry| (victim, entry)))
        .flatten()
    };
    // Retire the exact observed entry outside the table lock; the entry
    // is already removed, so the key is free for a concurrent dial.
    let Some((victim, entry)) = victim else {
      return Ok(());
    };
    crate::session::stream::retire(&entry);
    self.events.emit(crate::SessionChanged::new(victim.clone()));
    self.prune_cooldown.store(
      RECOVERY_PRUNE_COOLDOWN_TICKS,
      std::sync::atomic::Ordering::Relaxed,
    );
    tracing::debug!(peer = %victim.as_str(), "pruned a redundant recovery-dialed edge");
    Ok(())
  }
}

/// One scoped in-flight dial slot: [`DialPermit::acquire`] increments
/// the plane's pending counter and the permit's `Drop` decrements it
/// exactly once. The permit is a live local across the dial's await, so
/// every exit path of the dial task — successful completion, the dial's
/// error return, a panic unwinding through a caller-supplied transport's
/// future, or the shutdown path's abort — runs the drop and releases the
/// slot. The manual `fetch_add`/`fetch_sub` pairs this replaces decremented
/// only after the await, so any panic or cancellation skipped it and the
/// stranded slot suppressed later maintenance/probe ticks or consumed a
/// recovery fan-out budget for the incarnation's remainder.
pub(super) struct DialPermit {
  pending: Arc<std::sync::atomic::AtomicUsize>,
}

impl DialPermit {
  /// Acquires one slot against the plane's pending counter.
  pub(super) fn acquire(pending: Arc<std::sync::atomic::AtomicUsize>) -> Self {
    pending.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    Self { pending }
  }
}

impl Drop for DialPermit {
  fn drop(&mut self) {
    // Exactly one decrement per `acquire`, so the pair cannot underflow.
    self
      .pending
      .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
  }
}

/// The plane-owned failure diagnostics the shared dial lifecycle calls
/// when a member dial resolves to an error: each plane keeps its own
/// log target, level, and message — a recovery failure is expected while
/// a peer restarts and surfaces at warn for the controller's next
/// observation tick; a maintenance failure is best-effort by contract
/// and stays at debug.
pub(super) type DialFailureReport = fn(&NodeId, &Error);

/// The dial lifecycle both dial planes share (recovery fan-out and
/// degree maintenance): resolve the endpoint's transport, spawn
/// [`dial_member`] in its own task under a scoped [`DialPermit`] (the
/// slot releases on completion, panic unwind, or cancellation), and
/// register the JoinHandle with the tracked connection-task set the
/// recovery tick reaps and the shutdown path drains. The planes keep
/// their own selection policies and budgets — the caller picks the
/// counter the permit bounds, the `recovery_dialed` edge class, and the
/// failure diagnostics; the helper owns only the execution and tracking
/// mechanics both planes repeated.
pub(super) fn spawn_member_dial(
  state: &TickState, pending: Arc<std::sync::atomic::AtomicUsize>, peer: NodeId,
  receiver: Endpoint, recovery_dialed: bool, report: DialFailureReport,
) {
  let transport = match state.extensions.resolve_transport(&receiver.selector()) {
    Ok(transport) => transport,
    // No transport for the endpoint: the dial cannot even start, so no
    // in-flight slot is taken, and the next tick picks again (possibly
    // the same member).
    Err(error) => {
      debug!(
        peer = %peer.as_str(),
        endpoint = %receiver.as_str(),
        kind = ?error.kind(),
        "member dial unresolvable"
      );
      return;
    }
  };
  let permit = DialPermit::acquire(pending);
  let driver = state.driver.clone();
  let sessions = state.sessions.clone();
  let packet = state.packet.clone();
  let shutdown = state.shutdown.clone();
  let connection_tasks = state.connection_tasks.clone();
  let dial_deadline = state.config.dial_deadline();
  let dial = tokio::spawn(async move {
    let _slot = permit;
    if let Err(error) = dial_member(
      transport,
      driver,
      sessions,
      packet,
      shutdown,
      connection_tasks,
      receiver,
      &peer,
      recovery_dialed,
      dial_deadline,
    )
    .await
    {
      report(&peer, &error);
    }
  });
  // The dial's JoinHandle joins the tracked connection-task set the
  // recovery tick reaps (finished handles) and the shutdown path drains
  // inside its bounded cooperative window, aborting only the stragglers
  // (audit finding #19): an in-flight dial is owned and torn down with
  // the node instead of outliving it.
  if let Ok(mut handles) = state.connection_tasks.lock() {
    handles.push(dial);
  }
}

/// The recovery plane's failure diagnostics for the shared dial
/// lifecycle: a refused dial is expected while a peer restarts; the
/// failure surfaces at warn for the recovery controller's next
/// observation tick instead of vanishing here.
fn report_recovery_dial_failure(peer: &NodeId, error: &Error) {
  tracing::warn!(
    peer = %peer.as_str(),
    kind = ?error.kind(),
    "recovery dial failed"
  );
}

/// Advances a per-member endpoint serial map for `member`'s next dial
/// and returns the 1-based serial that dial consumes: a member's first
/// dial is serial 1 (its first published endpoint), and every further
/// dial of that member advances its OWN serial, wrapping per member.
/// The pure half of the rotation [`TickState::member_dial_serial`]
/// applies across both dial planes — keyed per member, never by a
/// schedule-level serial.
pub(super) fn advance_member_serial(
  serials: &mut std::collections::BTreeMap<NodeId, u64>, member: &NodeId,
) -> u64 {
  let serial = serials.entry(member.clone()).or_insert(0);
  *serial = serial.wrapping_add(1);
  *serial
}

/// The endpoint one dial of a multi-homed member lands on: the serial
/// is the member's OWN dial count (see [`advance_member_serial`]), so a
/// member whose current endpoint is unreachable is retried on the
/// others across successive dials of that member (audit 2026-10-09
/// item 7). A member's first dial lands on its first published
/// endpoint.
///
/// The serial must be PER MEMBER, never a schedule-level attempt
/// serial: member selection and a shared serial are both pure functions
/// of the step number, so they alias — with `c` candidates in sorted
/// order and fan-out one, member `p` is dialed exactly at attempts
/// `a ≡ p+1 (mod c)` and its endpoint index `(a−1) mod len =
/// (p + j·c) mod len` visits only a `len/gcd(c, len)` subset, fully
/// pinned whenever `c ≡ 0 (mod len)`. Per-member serials decouple the
/// two and guarantee every member sweeps every endpoint for any
/// (candidates, endpoints, fan-out).
///
/// Shared FUNCTION with the degree maintenance plane, which feeds the
/// member's serial from the same per-member rotation — the two planes
/// rotate one member's endpoints together (remaining-items list P2-5).
pub(super) fn recovery_endpoint(endpoints: &[Endpoint], serial: u64) -> Option<&Endpoint> {
  let index = serial.saturating_sub(1) as usize % endpoints.len().max(1);
  endpoints.get(index)
}

/// The memoized departed-members exclusion set, keyed by the store
/// revision it was computed at. Shared between the supervisor's own
/// pages/ticks and the identity effects (the checkpoint guard), so the
/// memo serves one truth per incarnation.
pub(super) type ExclusionCache =
  std::sync::Arc<std::sync::Mutex<Option<(crate::StoreRevision, Departed)>>>;

/// The public recovery observation over one controller snapshot:
/// whether every known online member has an authenticated path, how
/// many members remain unreachable, and the next scheduled attempt.
/// Shared by the supervisor's read and the start-recovery effect, so
/// both report the one controller truth.
pub(super) fn recovery_view(
  controller: &crate::membership::recovery::RecoveryController,
) -> crate::RecoveryView {
  let now = crate::time::now_seconds();
  crate::RecoveryView::new(
    controller.state() == crate::membership::recovery::RecoveryState::Connected,
    controller.pending_count(),
    controller
      .next_attempt_seconds(now)
      .map(crate::time::from_seconds),
  )
}

/// The departed-members exclusion state (cleaned + left), memoized per
/// store revision in the shared cache: rescanning and decoding every
/// accumulated tombstone on every two-second tick (and every member
/// page) is unbounded work for an answer that only changes when a
/// tombstone commit moves the revision. A poisoned cache only costs a
/// recompute.
pub(super) async fn departed_exclusions(
  cache: &ExclusionCache, store: &crate::storage::MetadataStore,
) -> Result<Departed> {
  let revision = store.snapshot().await?.revision().clone();
  if let Ok(guard) = cache.lock()
    && let Some((cached_revision, cached)) = guard.as_ref()
    && cached_revision == &revision
  {
    return Ok(cached.clone());
  }
  let departed = Departed::compute(store).await?;
  if let Ok(mut guard) = cache.lock() {
    *guard = Some((revision, departed.clone()));
  }
  Ok(departed)
}

#[cfg(test)]
mod tests {
  use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
      Arc,
      atomic::{AtomicUsize, Ordering},
    },
  };

  use tokio::sync::watch;

  use super::{
    DialPermit, RECOVERY_TICK_PERIOD, advance_member_serial, recovery_endpoint, run_recovery_worker,
  };
  use crate::{
    BoxFuture, Endpoint, NodeConfig,
    membership::recovery::{RecoveryController, RecoveryPolicy},
    provider::{
      CommitOutcome, ReconcileOutcome, Storage, StorageFactory, StoreCapabilities,
      StoreRequirements, StoreSnapshot, StoreTransaction,
    },
    runtime::supervisor::test_support::{
      install_member, member_id, member_key, refusing_peer, silent_peer, supervisor_over,
    },
  };

  fn endpoint(port: u16) -> Endpoint {
    Endpoint::parse(&format!("wss://10.0.0.1:{port}")).unwrap()
  }

  fn node(value: u8) -> crate::NodeId {
    crate::NodeId::parse(&format!("node-{value:021}")).unwrap()
  }

  /// Endpoint-level failover (audit 2026-10-09 item 7): a member's
  /// per-member serial rotates it through its published endpoints — the
  /// member's first dial lands on its first endpoint, later dials the
  /// others, and the sweep wraps.
  #[test]
  fn recovery_endpoints_rotate_with_the_per_member_serial() {
    let endpoints = vec![endpoint(1), endpoint(2), endpoint(3)];
    assert_eq!(recovery_endpoint(&endpoints, 1), Some(&endpoints[0]));
    assert_eq!(recovery_endpoint(&endpoints, 2), Some(&endpoints[1]));
    assert_eq!(recovery_endpoint(&endpoints, 3), Some(&endpoints[2]));
    assert_eq!(recovery_endpoint(&endpoints, 4), Some(&endpoints[0]));

    // A single-endpoint member always dials it...
    let single = vec![endpoint(9)];
    assert_eq!(recovery_endpoint(&single, 7), Some(&single[0]));
    // ...and an endpointless member (never a candidate) dials nothing.
    assert_eq!(recovery_endpoint(&[], 7), None);
  }

  /// A04 (endpoint-rotation coupling): the audit's smallest pinned
  /// shape — two multi-homed members with two endpoints each, fan-out
  /// one. Under the shared schedule serial, member A was dialed only on
  /// odd attempts and always its first endpoint, member B only on even
  /// attempts and always its second — each pinned to ONE endpoint
  /// forever (c = 2 pins fully because 2 ≡ 0 mod 2). Per-member serials
  /// decouple endpoint rotation from the member window: across 2c
  /// steps each member's dialed set is ALL of its own endpoints.
  #[test]
  fn two_multi_homed_members_each_sweep_both_endpoints() {
    let entropy = crate::identity::testing::SequenceEntropy::default();
    let candidates: BTreeSet<crate::NodeId> = [node(0), node(1)].into_iter().collect();
    let endpoints: BTreeMap<crate::NodeId, Vec<Endpoint>> = candidates
      .iter()
      .map(|member| (member.clone(), vec![endpoint(1), endpoint(2)]))
      .collect();
    let mut controller = RecoveryController::new(RecoveryPolicy::new(1, 1, 60));
    controller.observe(&candidates, &BTreeSet::new());
    let mut serials = BTreeMap::new();
    let mut dialed: BTreeMap<crate::NodeId, BTreeSet<usize>> = BTreeMap::new();
    for step in 0..2 * candidates.len() {
      let decision = controller.next_step(step as u64, &candidates, &entropy);
      for target in decision.targets {
        let serial = advance_member_serial(&mut serials, &target);
        let index = recovery_endpoint(&endpoints[&target], serial)
          .and_then(|endpoint| {
            endpoints[&target]
              .iter()
              .position(|other| other == endpoint)
          })
          .unwrap();
        dialed.entry(target).or_default().insert(index);
      }
    }
    for (member, indexes) in dialed {
      assert_eq!(
        indexes,
        (0..2).collect::<BTreeSet<_>>(),
        "member {member:?} must sweep both of its endpoints, not {indexes:?}"
      );
    }
  }

  /// A04's failover liveness contract, exhaustively: for every
  /// candidate count (1..=8), endpoint count (1..=4), and fan-out
  /// (1, 2, 3), driving `candidates * endpoints` recovery steps must
  /// dial every endpoint of every member at least once. A shared
  /// schedule-level serial fails this whenever
  /// gcd(candidate_count, endpoint_count) > 1 (the audit's aliasing);
  /// per-member serials sweep unconditionally.
  #[test]
  fn every_member_sweeps_every_endpoint_for_any_schedule_shape() {
    for candidate_count in 1..=8_usize {
      for endpoint_count in 1..=4_usize {
        for fan_out in [1_usize, 2, 3] {
          let entropy = crate::identity::testing::SequenceEntropy::default();
          let candidates: BTreeSet<crate::NodeId> = (0..u8::try_from(candidate_count).unwrap())
            .map(node)
            .collect();
          let endpoints: BTreeMap<crate::NodeId, Vec<Endpoint>> = candidates
            .iter()
            .map(|member| {
              (
                member.clone(),
                (1..=u16::try_from(endpoint_count).unwrap())
                  .map(endpoint)
                  .collect::<Vec<_>>(),
              )
            })
            .collect();
          let mut controller = RecoveryController::new(RecoveryPolicy::new(fan_out, 1, 60));
          controller.observe(&candidates, &BTreeSet::new());
          let mut serials = BTreeMap::new();
          let mut dialed: BTreeMap<crate::NodeId, BTreeSet<usize>> = BTreeMap::new();
          for step in 0..candidate_count * endpoint_count {
            let decision = controller.next_step(step as u64, &candidates, &entropy);
            for target in decision.targets {
              let serial = advance_member_serial(&mut serials, &target);
              let index = recovery_endpoint(&endpoints[&target], serial)
                .and_then(|endpoint| {
                  endpoints[&target]
                    .iter()
                    .position(|other| other == endpoint)
                })
                .unwrap();
              dialed.entry(target).or_default().insert(index);
            }
          }
          for member in &candidates {
            let indexes = dialed.get(member).cloned().unwrap_or_default();
            assert_eq!(
              indexes,
              (0..endpoint_count).collect::<BTreeSet<_>>(),
              "candidates={candidate_count} endpoints={endpoint_count} fan_out={fan_out}: \
               member {member:?} must sweep all its endpoints"
            );
          }
        }
      }
    }
  }

  /// The gated-snapshot injection: once armed, every `snapshot` call
  /// parks forever (and counts itself), so the test holds one tick's
  /// storage IO open for as long as it wants. Every read path of a tick
  /// enters the store through one snapshot, so gating here gates the
  /// tick.
  #[derive(Debug)]
  struct SnapshotGate {
    hold: std::sync::atomic::AtomicBool,
    entered: std::sync::atomic::AtomicUsize,
    entries: watch::Sender<usize>,
  }

  #[derive(Debug)]
  struct GatedFactory {
    inner: Arc<dyn StorageFactory>,
    gate: Arc<SnapshotGate>,
  }

  impl StorageFactory for GatedFactory {
    fn open<'a>(
      &'a self, requirements: StoreRequirements,
    ) -> BoxFuture<'a, crate::Result<Box<dyn Storage>>> {
      let inner = &self.inner;
      let gate = Arc::clone(&self.gate);
      Box::pin(async move {
        let storage = inner.open(requirements).await?;
        Ok(Box::new(GatedStorage { storage, gate }) as Box<dyn Storage>)
      })
    }
  }

  #[derive(Debug)]
  struct GatedStorage {
    storage: Box<dyn Storage>,
    gate: Arc<SnapshotGate>,
  }

  impl Storage for GatedStorage {
    fn capabilities(&self) -> StoreCapabilities {
      self.storage.capabilities()
    }

    fn snapshot<'a>(&'a self) -> BoxFuture<'a, crate::Result<Box<dyn StoreSnapshot>>> {
      let gate = Arc::clone(&self.gate);
      let storage = &self.storage;
      Box::pin(async move {
        if gate.hold.load(std::sync::atomic::Ordering::Relaxed) {
          gate
            .entered
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
          gate
            .entries
            .send_replace(gate.entered.load(std::sync::atomic::Ordering::Relaxed));
          // Park until the test ends: a tick whose storage IO never
          // resolves is the slow-store shape under test.
          std::future::pending::<()>().await;
        }
        storage.snapshot().await
      })
    }

    fn commit<'a>(
      &'a self, transaction: StoreTransaction,
    ) -> BoxFuture<'a, crate::Result<CommitOutcome>> {
      self.storage.commit(transaction)
    }

    fn reconcile<'a>(
      &'a self, transaction: &'a crate::TransactionId, digest: &'a crate::Digest,
    ) -> BoxFuture<'a, crate::Result<ReconcileOutcome>> {
      self.storage.reconcile(transaction, digest)
    }

    fn flush<'a>(&'a self) -> BoxFuture<'a, crate::Result<()>> {
      self.storage.flush()
    }
  }

  /// Boundedness of the derived recovery tick (audit 2026-10-09 item 3):
  /// while one tick's storage IO never resolves, NO further tick work
  /// piles up behind it — after two more tick deadlines fire, exactly
  /// one gated snapshot has been entered. A spawn-per-tick or queued
  /// design would have started one tick per deadline and grown the
  /// counter; the single worker with `MissedTickBehavior::Skip` holds
  /// the in-flight work at one tick.
  #[tokio::test(start_paused = true)]
  async fn recovery_worker_holds_one_tick_in_flight_under_a_stalled_store() {
    let reference = Arc::new(crate::storage::contract::ReferenceFactory::new(
      crate::storage::contract::required_capabilities(),
    ));
    let gate = Arc::new(SnapshotGate {
      hold: std::sync::atomic::AtomicBool::new(false),
      entered: std::sync::atomic::AtomicUsize::new(0),
      entries: watch::channel(0).0,
    });
    let factory: Arc<dyn StorageFactory> = Arc::new(GatedFactory {
      inner: reference as Arc<dyn StorageFactory>,
      gate: Arc::clone(&gate),
    });
    // A slow anti-entropy cadence keeps the sync driver (spawned by
    // `Supervisor::new` with an immediate first tick) out of the armed
    // window: its next cadence root is far past every advance below.
    let config = NodeConfig::new()
      .with_anti_entropy_interval(std::time::Duration::from_secs(3_600))
      .unwrap();
    let (supervisor, _entropy, _sessions) = supervisor_over(factory, config).await;
    // Let the driver's immediate first tick drain before arming, so the
    // gate observes tick work only.
    for _ in 0..16 {
      tokio::task::yield_now().await;
    }
    assert_eq!(
      gate.entered.load(std::sync::atomic::Ordering::Relaxed),
      0,
      "no snapshot may be gated before the gate is armed"
    );

    let ticks = supervisor.tick_state().unwrap();
    let mut entries = gate.entries.subscribe();
    gate.hold.store(true, std::sync::atomic::Ordering::Relaxed);
    let worker = tokio::spawn(run_recovery_worker(Arc::new(ticks)));

    // The worker's first interval tick fires immediately: await its
    // entry into the gated snapshot (a watch value, so no wakeup is
    // lost). The box is a hang guard, not a latency claim.
    tokio::time::timeout(std::time::Duration::from_secs(30), entries.changed())
      .await
      .expect("the first tick must reach the store")
      .unwrap();
    assert_eq!(*entries.borrow_and_update(), 1);

    // Two more tick deadlines fire while the first tick is still
    // parked on the store: no second tick may start.
    tokio::time::advance(RECOVERY_TICK_PERIOD * 2 + std::time::Duration::from_millis(500)).await;
    assert_eq!(
      gate.entered.load(std::sync::atomic::Ordering::Relaxed),
      1,
      "overlapping ticks must be skipped, never queued"
    );

    worker.abort();
  }

  /// A silent peer that reports BOTH acceptance and close: it accepts
  /// every connection, swallows the client's bytes without ever
  /// answering (a wss dial parks in the TLS handshake until its
  /// deadline), and counts the connection closed the moment the dial
  /// side drops the socket. The close count is the observable the
  /// shutdown-ordering assertion needs: an aborted dial drops its
  /// transport immediately, while a dial nobody owns holds it until
  /// the deadline.
  async fn closing_silent_peer() -> (
    u16,
    Arc<std::sync::atomic::AtomicUsize>,
    Arc<std::sync::atomic::AtomicUsize>,
    tokio::task::JoinHandle<()>,
  ) {
    use tokio::io::AsyncReadExt;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let closed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (peer_accepted, peer_closed) = (Arc::clone(&accepted), Arc::clone(&closed));
    let handle = tokio::spawn(async move {
      let mut readers = tokio::task::JoinSet::new();
      while let Ok((stream, _)) = listener.accept().await {
        peer_accepted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let closed = Arc::clone(&peer_closed);
        readers.spawn(async move {
          let mut stream = stream;
          let mut sink = [0_u8; 256];
          // Swallow every byte and never answer: the client's handshake
          // waits forever, and the first EOF or error marks the dial
          // side gone.
          loop {
            match stream.read(&mut sink).await {
              Ok(0) | Err(_) => break,
              Ok(_) => {}
            }
          }
          closed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        });
      }
    });
    (port, accepted, closed, handle)
  }

  /// A caller-registered transport whose connect future counts the
  /// attempt and then panics mid-dial: P2-12's exact shape — a custom
  /// transport future unwinding through the dial task. The attempt
  /// counter is the observable: it rising again after the panic proves a
  /// later dial still launched, which the leaked in-flight counter made
  /// impossible.
  #[derive(Debug)]
  struct PanickingWire {
    attempts: Arc<AtomicUsize>,
  }

  impl crate::TransportProvider for PanickingWire {
    fn bind(
      &self, _endpoint: Endpoint,
    ) -> crate::BoxFuture<'static, crate::Result<Box<dyn crate::ProviderListener>>> {
      Box::pin(async { Err(crate::Error::not_found("listener")) })
    }

    fn connect(
      &self, _endpoint: Endpoint,
    ) -> crate::BoxFuture<'static, crate::Result<Box<dyn crate::TransportStream>>> {
      let attempts = Arc::clone(&self.attempts);
      Box::pin(async move {
        attempts.fetch_add(1, Ordering::Relaxed);
        panic!("the custom transport's connect future panics mid-dial");
      })
    }
  }

  /// Installs one dialable member (descriptor plus trusted binding)
  /// straight into the reference factory's state — the same pair
  /// `test_support::install_member` lays through the supervisor's store,
  /// injected here before the runtime opens the factory: the real
  /// supervision path owns the store from `spawn_runtime` on, and the
  /// reference factory refuses a second open while the node holds it.
  fn install_dialable_member(
    reference: &Arc<crate::storage::contract::ReferenceFactory>, seed: u64, endpoint: Endpoint,
  ) {
    let node = member_id(seed);
    let descriptor = crate::membership::NodeDescriptorV1::new(
      node.clone(),
      member_key(seed),
      vec![endpoint],
      1,
      false,
      1,
    );
    let namespace =
      crate::storage::families::namespace(crate::storage::families::NODE_DESCRIPTOR_NAMESPACE)
        .unwrap();
    let key = crate::StoreKey::new(Arc::from(node.as_str().as_bytes().to_vec()));
    crate::identity::testing::inject_entry(
      reference,
      (namespace, key),
      descriptor.encode().unwrap(),
    );
    let (binding_namespace, binding_key) =
      crate::identity::records::identity_binding_key(&node).unwrap();
    let binding = crate::identity::records::IdentityBindingV1::new(node, member_key(seed));
    crate::identity::testing::inject_entry(
      reference,
      (binding_namespace, binding_key),
      binding.encode().unwrap(),
    );
  }

  /// Boots a node through the REAL supervision path — `spawn_runtime` →
  /// `supervise`, the same construction `NodeBuilder::start` performs —
  /// and hands the test the tracked connection-task registry the
  /// shutdown path drains, so the test observes exactly the handles
  /// `into_dependencies` aborts and `finish_shutdown` awaits.
  async fn supervised_runtime(
    reference: Arc<crate::storage::contract::ReferenceFactory>, config: NodeConfig,
  ) -> (
    crate::runtime::RuntimeClient,
    Arc<std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>>,
    Arc<AtomicUsize>,
  ) {
    let keys = crate::identity::testing::ScriptedKeys::full();
    let entropy: Arc<dyn crate::api::Entropy> =
      Arc::new(crate::identity::testing::SequenceEntropy::default());
    let mut extensions = crate::extension_registry::ExtensionRegistry::new();
    for (tag, transport) in [
      (
        crate::transport::registry::builtin_transport_tag(crate::TransportScheme::Tls).unwrap(),
        Arc::new(crate::transport::tls_transport::TlsTransport::new())
          as Arc<dyn crate::transport::registry::Transport>,
      ),
      (
        crate::transport::registry::builtin_transport_tag(crate::TransportScheme::Wss).unwrap(),
        Arc::new(crate::transport::wss::WssTransport::new())
          as Arc<dyn crate::transport::registry::Transport>,
      ),
      (
        crate::transport::registry::builtin_transport_tag(crate::TransportScheme::Tcp).unwrap(),
        Arc::new(crate::transport::plain::PlainTransport::new())
          as Arc<dyn crate::transport::registry::Transport>,
      ),
    ] {
      extensions
        .register_builtin_transport(tag, transport)
        .unwrap();
    }
    // The panicking custom transport the P2-12 regression dials through,
    // under its own scheme name: only endpoints that advertise it
    // resolve here, so the other fixtures never touch it.
    let attempts = Arc::new(AtomicUsize::new(0));
    extensions
      .register_transport(
        crate::TransportName::parse("panicwire").unwrap(),
        Arc::new(PanickingWire {
          attempts: Arc::clone(&attempts),
        }),
      )
      .unwrap();
    let (revision_tx, _revision_rx) = tokio::sync::watch::channel(0_u64);
    let (round_tx, round_rx) =
      tokio::sync::mpsc::channel(crate::runtime::SYNC_ROUND_CHANNEL_CAPACITY);
    let (packet_tx, packet_rx) =
      tokio::sync::mpsc::channel(crate::runtime::PACKET_CHANNEL_CAPACITY);
    let connection_tasks: Arc<std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>> =
      Arc::new(std::sync::Mutex::new(Vec::new()));
    let client = crate::runtime::spawn_runtime(
      crate::runtime::RuntimeDependencies {
        storage_factory: reference as Arc<dyn crate::provider::StorageFactory>,
        context: None,
        keys: Some(keys.as_provider()),
        config,
        entropy,
        extensions: Arc::new(extensions),
        sessions: Default::default(),
        routes: Default::default(),
        events: Arc::new(crate::node::EventHub::new()),
        member_revision: crate::node::MemberRevisionSignal::new(revision_tx),
        leave_applied: crate::membership::sync::LeaveAppliedSignal::new(),
        reconcile: None,
        sync_round_requests: round_tx,
        connection_tasks: Arc::clone(&connection_tasks),
        listeners: Default::default(),
        task_manager: None,
        operations: None,
        runtime_seed: None,
      },
      (packet_tx, packet_rx),
      round_rx,
    )
    .await
    .unwrap();
    (client, connection_tasks, attempts)
  }

  /// Audit finding #19: a recovery dial is a spawned task whose
  /// JoinHandle must be registered in the tracked connection-task set,
  /// or shutdown neither cancels nor awaits it. This drives the real
  /// shutdown path end to end: the node's recovery worker dials a
  /// member whose endpoint parks in the TLS handshake against a silent
  /// peer (a 30s dial deadline holds it there), then
  /// `RuntimeClient::shutdown` — control message → `into_dependencies`
  /// → `finish_shutdown` → reply — must (a) resolve far inside that
  /// deadline because the dial is aborted, and (b) leave the dial task
  /// finished by then: `finish_shutdown` awaits every drained handle
  /// before the reply resolves, so the dial's transport drops with it
  /// and the silent peer observes the connection close with the reply.
  /// A detached dial (the finding's shape) holds the socket until the
  /// deadline: the registration poll and the close poll both time out.
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn shutdown_aborts_and_awaits_an_in_flight_recovery_dial() {
    let reference = Arc::new(crate::storage::contract::ReferenceFactory::new(
      crate::storage::contract::required_capabilities(),
    ));
    // A dial deadline far beyond every box below — a parked dial must be
    // observable as parked, not as briefly slow — and a fan-out of one,
    // so exactly one dial is ever in flight for the one member.
    let config = NodeConfig::new()
      .with_dial_deadline(std::time::Duration::from_secs(30))
      .unwrap()
      .with_recovery_policy(
        crate::RecoveryConfig::new(
          1,
          std::time::Duration::from_secs(1),
          std::time::Duration::from_secs(2),
        )
        .unwrap(),
      )
      .unwrap();
    let (port, accepted, closed, holder) = closing_silent_peer().await;
    install_dialable_member(
      &reference,
      101,
      Endpoint::parse(&format!("wss://127.0.0.1:{port}")).unwrap(),
    );

    let (client, connection_tasks, _attempts) = supervised_runtime(reference, config).await;

    // The recovery worker's first tick fires immediately and dials the
    // only member: the peer accepts the connection and the dial parks
    // in the TLS handshake for its 30s deadline.
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
      loop {
        if accepted.load(std::sync::atomic::Ordering::Relaxed) >= 1 {
          break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
      }
    })
    .await
    .expect("the recovery tick must dial the silent member");

    // The parked dial's JoinHandle must sit in the tracked set the
    // shutdown path drains — an empty set is the finding's detached
    // shape.
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
      loop {
        if !connection_tasks.lock().unwrap().is_empty() {
          break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
      }
    })
    .await
    .expect("the recovery dial must register its JoinHandle");

    // (a) The shutdown reply resolves far inside the parked dial's
    // deadline: the dial is aborted with the node, not awaited alive.
    tokio::time::timeout(std::time::Duration::from_secs(5), client.shutdown())
      .await
      .expect("shutdown must not wait out the parked dial's deadline")
      .expect("the shutdown reply must resolve");

    // (b) The dial task was aborted and awaited BEFORE the reply
    // resolved (finish_shutdown awaits every drained handle first), so
    // its transport is gone and the silent peer sees the connection
    // close immediately — the box only tolerates the peer-side read
    // wakeup, never a lingering dial.
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
      loop {
        if closed.load(std::sync::atomic::Ordering::Relaxed) >= 1 {
          break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
      }
    })
    .await
    .expect("the parked dial must close with the shutdown reply");
    holder.abort();
  }

  /// Audit finding #5's bound, through the real recovery tick: while a
  /// previous step's dial stays parked against a silent peer, the next
  /// step must hold the in-flight count AT the fan-out bound instead of
  /// overshooting to `2*fan_out - 1` — the pre-batch gate alone admits
  /// the overshoot because a slot frees between the steps. Member 101's
  /// first endpoint refuses connections (its slot frees inside the poll
  /// below), so the second step starts with one held slot and a fan-out
  /// of two: exactly one further dial may launch.
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn recovery_steps_hold_in_flight_dials_at_the_fan_out_bound() {
    let reference = Arc::new(crate::storage::contract::ReferenceFactory::new(
      crate::storage::contract::required_capabilities(),
    ));
    let config = NodeConfig::new()
      .with_dial_deadline(std::time::Duration::from_secs(30))
      .unwrap()
      .with_recovery_policy(
        crate::RecoveryConfig::new(
          2,
          std::time::Duration::from_secs(1),
          std::time::Duration::from_secs(2),
        )
        .unwrap(),
      )
      .unwrap();
    let (supervisor, _entropy, _sessions) = supervisor_over(
      reference.clone() as Arc<dyn crate::provider::StorageFactory>,
      config,
    )
    .await;
    let ticks = supervisor.tick_state().unwrap();
    // A refusing peer: the dial fails fast and deterministically at the
    // handshake, releasing its in-flight slot and giving the second step
    // exactly one held slot to start from. The silent peer parks for the
    // long dial deadline, so the window it leaves is wide on every
    // platform.
    let (refused_port, refused_holder) = refusing_peer().await;
    let (first_port, first_connections, first_holder) = silent_peer().await;
    let (second_port, second_connections, second_holder) = silent_peer().await;
    install_member(&supervisor, &reference, 101, &[refused_port, first_port]).await;
    install_member(&supervisor, &reference, 102, &[second_port]).await;

    // Step 1 (attempt 1): 101 dials its refused first endpoint and 102
    // parks against the silent peer — two slots taken, then one. The
    // poll also awaits the parked dial's accept, since the connection
    // lands asynchronously.
    ticks.recovery_tick().await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(60), async {
      loop {
        if ticks
          .recovery_pending
          .load(std::sync::atomic::Ordering::Relaxed)
          == 1
          && second_connections.load(std::sync::atomic::Ordering::Relaxed) >= 1
        {
          break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
      }
    })
    .await
    .expect("the refused dial must release its in-flight slot");
    assert_eq!(
      second_connections.load(std::sync::atomic::Ordering::Relaxed),
      1,
      "the parked dial must hold against the counted silent peer"
    );

    // Step 2 (attempt 2, once the backoff comes due): one held slot,
    // fan-out two — the step must stop at the bound instead of spawning
    // both targets, which would park three dials in flight.
    tokio::time::timeout(std::time::Duration::from_secs(6), async {
      loop {
        if ticks
          .recovery
          .lock()
          .unwrap()
          .due(crate::time::now_seconds())
        {
          break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
      }
    })
    .await
    .expect("the second recovery attempt must come due");
    ticks.recovery_tick().await.unwrap();
    assert_eq!(
      ticks
        .recovery_pending
        .load(std::sync::atomic::Ordering::Relaxed),
      2,
      "the step must hold in-flight dials at the fan-out bound, never 2*fan_out - 1"
    );
    // The re-dial connects asynchronously: await its accept before
    // counting, then check the bound left the second target alone.
    tokio::time::timeout(std::time::Duration::from_secs(60), async {
      loop {
        if first_connections.load(std::sync::atomic::Ordering::Relaxed) >= 1 {
          break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
      }
    })
    .await
    .expect("attempt 2 must rotate 101 to its second endpoint");
    assert_eq!(
      second_connections.load(std::sync::atomic::Ordering::Relaxed),
      1,
      "the bound must leave the second target to a later step"
    );
    first_holder.abort();
    second_holder.abort();
    refused_holder.abort();
  }

  /// The scoped permit is P2-12's mechanism: whichever way the dial
  /// task's future ends — completion, a panic unwinding through it, or
  /// the shutdown path's cancellation — the drop runs and the counter
  /// returns to its pre-acquisition value. (The completion path is the
  /// ordinary dial tests above.)
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn dial_permit_releases_the_slot_on_panic_and_cancellation() {
    let pending = Arc::new(AtomicUsize::new(0));
    let panicking = {
      let permit = DialPermit::acquire(Arc::clone(&pending));
      assert_eq!(pending.load(Ordering::Relaxed), 1, "acquire takes the slot");
      tokio::spawn(async move {
        let _slot = permit;
        panic!("the dial future panics");
      })
    };
    assert!(
      panicking.await.is_err(),
      "the dial task must actually panic"
    );
    assert_eq!(
      pending.load(Ordering::Relaxed),
      0,
      "the panic unwind must release the slot"
    );

    let cancelled = {
      let permit = DialPermit::acquire(Arc::clone(&pending));
      tokio::spawn(async move {
        let _slot = permit;
        std::future::pending::<()>().await;
      })
    };
    cancelled.abort();
    let _ = cancelled.await;
    assert_eq!(
      pending.load(Ordering::Relaxed),
      0,
      "the cancellation must release the slot"
    );
  }

  /// P2-12's recovery shape, through the real supervision path: a
  /// caller-supplied transport whose connect future panics mid-dial must
  /// not strand its fan-out slot. The manual `fetch_add`/`fetch_sub`
  /// pair decremented after the await, so the panic skipped it; the
  /// fan-out gate then deferred every later recovery step for the
  /// incarnation and the attempt counter froze at one. The scoped
  /// permit releases on the unwind, so the plane keeps dialing.
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn a_panicking_transport_future_releases_its_recovery_slot() {
    let reference = Arc::new(crate::storage::contract::ReferenceFactory::new(
      crate::storage::contract::required_capabilities(),
    ));
    // Fan-out one, so the single slot the panic must release is the
    // plane's whole budget; the initial backoff schedules the second
    // attempt within seconds (the base doubles to 2s, which has no
    // whole-second jitter spread to sample).
    let config = NodeConfig::new()
      .with_dial_deadline(std::time::Duration::from_secs(5))
      .unwrap()
      .with_recovery_policy(
        crate::RecoveryConfig::new(
          1,
          std::time::Duration::from_secs(1),
          std::time::Duration::from_secs(2),
        )
        .unwrap(),
      )
      .unwrap();
    install_dialable_member(
      &reference,
      101,
      Endpoint::parse("panicwire://unreachable").unwrap(),
    );

    let (_client, _connection_tasks, attempts) = supervised_runtime(reference, config).await;

    // Attempt 1 fires on the worker's first tick and panics inside the
    // custom transport's future.
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
      loop {
        if attempts.load(Ordering::Relaxed) >= 1 {
          break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
      }
    })
    .await
    .expect("the recovery worker must dial the panicking transport");

    // The slot must come back: the second attempt is due after the
    // doubled initial backoff, and only a released slot lets the
    // fan-out-of-one gate admit it.
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
      loop {
        if attempts.load(Ordering::Relaxed) >= 2 {
          break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
      }
    })
    .await
    .expect("recovery must keep dialing after a panicking transport");
  }
}
