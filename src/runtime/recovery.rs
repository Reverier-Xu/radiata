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
/// and the recovery tick rotates through them across attempts
/// (endpoint-level failover), so a member whose first endpoint is
/// unreachable is still reached on the others (audit 2026-10-09
/// item 7). The degree plane consumes the SAME full endpoint lists —
/// its maintenance dials rotate a multi-homed member's endpoints by
/// their own batch serial (see `runtime/degree.rs`), so the
/// first-endpoint projection the degree dialer used to carry is gone
/// (remaining-items list P2-5).
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
    if !dial_due || {
      self
        .recovery_pending
        .load(std::sync::atomic::Ordering::Relaxed)
        >= self.config.recovery().fan_out().max(1)
    } {
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
      let Some(endpoints) = candidates.get(&member) else {
        continue;
      };
      // Endpoint-level failover: successive attempts for one member
      // rotate through its published endpoints (audit 2026-10-09
      // item 7), so a multi-homed member whose current endpoint is
      // unreachable is retried on the others.
      let Some(endpoint) = recovery_endpoint(endpoints, step.attempt) else {
        continue;
      };
      // Recovery dials run in a detached task so the supervisor select
      // loop never blocks on a handshake (each holds its in-flight
      // slot no longer than the configured dial deadline plus the
      // authentication deadline); the result is reconciled by the next
      // observation tick.
      self
        .recovery_pending
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
      let receiver = endpoint.clone();
      let peer = member.clone();
      let driver = self.driver.clone();
      let sessions = self.sessions.clone();
      let packet = self.packet.clone();
      let shutdown = self.shutdown.clone();
      let pending = Arc::clone(&self.recovery_pending);
      let transport = match self.extensions.resolve_transport(&endpoint.selector()) {
        Ok(transport) => transport,
        // No transport for the endpoint: the detached dial fails and
        // releases its in-flight slot through the normal error path.
        Err(error) => {
          let _ = self
            .recovery_pending
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
          tracing::debug!(endpoint = %endpoint.as_str(), kind = ?error.kind(), "recovery dial unresolvable");
          continue;
        }
      };
      let dial_deadline = self.config.dial_deadline();
      tokio::spawn(async move {
        if let Err(error) = dial_member(
          transport,
          driver,
          sessions,
          packet,
          shutdown,
          receiver,
          &peer,
          true,
          dial_deadline,
        )
        .await
        {
          // A refused dial is expected while a peer restarts; the
          // failure surfaces for the recovery controller's next
          // observation tick instead of vanishing here.
          tracing::warn!(
            peer = %peer.as_str(),
            kind = ?error.kind(),
            "recovery dial failed"
          );
        }
        // Release the in-flight slot when the dial resolves, so recovery
        // stays alive across repeated partition waves (the counter bounds
        // in-flight dials, not lifetime volume).
        pending.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
      });
    }
    Ok(())
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

/// The endpoint one recovery attempt dials for a multi-homed member:
/// the attempt serial rotates through the member's published endpoints,
/// so a member whose current endpoint is unreachable is retried on the
/// others across successive attempts (audit 2026-10-09 item 7). The
/// first attempt of every schedule dials the first published endpoint.
/// Shared with the degree maintenance plane, which rotates a member's
/// endpoints by its own dial-batch serial (remaining-items list P2-5).
pub(super) fn recovery_endpoint(endpoints: &[Endpoint], attempt: u64) -> Option<&Endpoint> {
  let index = attempt.saturating_sub(1) as usize % endpoints.len().max(1);
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
  use std::sync::Arc;

  use tokio::sync::watch;

  use super::{RECOVERY_TICK_PERIOD, recovery_endpoint, run_recovery_worker};
  use crate::{
    BoxFuture, Endpoint, NodeConfig,
    provider::{
      CommitOutcome, ReconcileOutcome, Storage, StorageFactory, StoreCapabilities,
      StoreRequirements, StoreSnapshot, StoreTransaction,
    },
    runtime::supervisor::test_support::supervisor_over,
  };

  fn endpoint(port: u16) -> Endpoint {
    Endpoint::parse(&format!("wss://10.0.0.1:{port}")).unwrap()
  }

  /// Endpoint-level failover (audit 2026-10-09 item 7): the attempt
  /// serial rotates a multi-homed member through its published endpoints
  /// — the first attempt of every schedule dials the first endpoint,
  /// later attempts the others, and the sweep wraps.
  #[test]
  fn recovery_endpoints_rotate_with_the_attempt_serial() {
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
}
