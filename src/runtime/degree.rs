//! The connection-degree maintenance plane: while the node's live
//! authenticated session count sits below its target degree, a periodic
//! tick dials uniformly random unconnected members from the active
//! member universe until the target is reached.
//!
//! Plane separation, deliberately narrow: the maintenance plane is
//! additive-only — it never prunes sessions, never gates functionality,
//! and never touches the zero-session case (the recovery plane's
//! high-frequency backoff owns a fully offline node). Its deficit dials
//! land as ordinary caller-class edges, so the recovery plane's
//! redundancy pruning never fights the maintenance target. The degree gates
//! only the status query and this cadence; below target with at least one
//! session everything keeps working.
//!
//! The tick runs on the dedicated maintenance worker, never inline in
//! the supervisor's select loop, and every selected member carries ALL of
//! its published endpoints: each dial of a member rotates that member to
//! its next endpoint with the same
//! per-member endpoint-level failover the recovery plane applies, so a
//! multi-homed member whose first endpoint is unreachable is retried on
//! the others.
//!
//! The one deliberate exception to "healthy means dial nothing" is the
//! bridge probe: EVERY healthy node that still has unconnected members —
//! two sub-partitions each internally meshed at or above the degree
//! target, including nodes holding surplus app-initiated sessions above
//! the target — would otherwise never re-bridge, because the deficit
//! budget is zero (`degree_plan`) and the recovery controller quiesces on
//! any one route. At most once per probe interval the tick dials ONE
//! uniformly random unconnected member through the ordinary maintenance
//! dial path. The interval bracket alone bounds the dial rate — one dial
//! per node per five minutes, whatever the session count — and a failed
//! probe dial is recorded at debug level only: a refused or stalled
//! peer is the probe's expected outcome while a partition persists,
//! never an error condition.
//!
//! The probe is a one-shot bridge attempt, not a densification loop: the
//! plane probes only while the node holds NO live probe edge, so a landed
//! bridge caps the node at one probe edge — `k(n) + 1` sessions plus the
//! caller's own topology, never a full mesh. That edge is never reclaimed
//! by the recovery plane's redundancy pruning (a cut would re-split the
//! partition it healed); it retires with its session — peer offline,
//! teardown, or shutdown — and the next interval's tick probes again.
//!
//! The one-edge cap is bounded in TIME, not forever
//! ([`BRIDGE_PROBE_EDGE_LIFETIME_TICKS`]). The probe picks uniformly
//! among unconnected members, so a pick that lands on the same side of a
//! partition bridges nothing while still consuming the node's single
//! edge — and because probe edges are never pruned, that one unlucky pick
//! would spend the probe for the node's whole lifetime. After the
//! lifetime the plane reclaims its own edge and re-probes in the same
//! tick, skipping the peer it just released so the rotation advances.
//!
//! Reclaiming a real bridge is safe by construction: while the probe edge
//! is the node's only cross-partition link, every remaining unconnected
//! member is on the far side, so the replacement probe lands on one of
//! them. Only a same-side edge can be followed by another same-side pick,
//! and that is exactly the case the rotation exists to escape. The steady
//! state stays `k(n) + 1`.

use std::{
  collections::{BTreeMap, BTreeSet},
  sync::Arc,
};

use tracing::debug;

use super::{
  recovery::spawn_member_dial,
  supervisor::{Supervisor, TickState},
};
use crate::{Error, NodeId, Result};

/// The maintenance cadence: nothing while healthy; while below target,
/// one deficit-bounded batch of random dials per tick. Purely local
/// behavior — peers observe dials, never the cadence — so unlike the
/// peer-visible timing constants this period is not a cluster-wide
/// contract.
pub(super) const DEGREE_MAINTENANCE_TICK_PERIOD: std::time::Duration =
  std::time::Duration::from_secs(30);

/// The bridge-probe cadence, in maintenance ticks: a healthy node with
/// unconnected members may dial one of them at most once per this many
/// eligible ticks (10 × 30s = 5 minutes — pinned by
/// `bridge_probe_interval_is_five_minutes`). The bracket is the sole
/// storm bound: even a permanently partitioned cluster issues one
/// probe per node per five minutes, whatever the session count.
pub(super) const BRIDGE_PROBE_INTERVAL_TICKS: u32 = 10;

/// The bounded lifetime of one bridge-probe edge, in maintenance ticks
/// (120 × 30 s = one hour). The probe plane reclaims its own edge after
/// this long so a landing on the same side of a partition cannot spend
/// the node's only probe for the rest of its life; because the
/// replacement probe is issued in the same tick, a real bridge is
/// re-reached within one dial rather than one interval (see the module
/// doc for why the replacement is guaranteed to cross).
///
/// The unit is ticks, not intervals: while a probe edge is live the
/// cadence bracket stays at its firing value (the probe is suppressed
/// before the bracket is re-armed, which is what makes the plane probe
/// again on the very first tick after the edge retires), so the gate —
/// and this age — advances once per maintenance tick.
pub(super) const BRIDGE_PROBE_EDGE_LIFETIME_TICKS: u32 = 120;

/// The bridge-probe plane's own bookkeeping: the edge it is currently
/// holding (with its age in probe intervals) and the peer it just
/// released, which the replacement probe skips so the rotation advances
/// instead of re-picking the edge it just cut.
#[derive(Debug, Default)]
pub(super) struct ProbeLedger {
  edge: Option<(NodeId, u32)>,
  retired: Option<NodeId>,
}

/// Runs the degree-maintenance worker: one long-lived task that owns the
/// maintenance cadence, so a slow member-table scan or a stalled dial
/// batch never parks control-plane reads and
/// packet admission behind it.
///
/// Overlap policy — SKIP, never queue: the worker is a single task that
/// runs each tick inline in its own loop, and the timer's
/// `MissedTickBehavior::Skip` drops every deadline that fires while a
/// tick is still running. A tick recomputes the dial plan from current
/// state (and its dials are already bounded by the in-flight counter),
/// so a skipped tick only delays the next deficit batch — queueing
/// would stack stale plans behind a slow store for no gain. Bounded
/// accounting: exactly one task for the node's lifetime, aborted and
/// awaited by the shutdown path.
pub(super) async fn run_maintenance_worker(state: Arc<TickState>) {
  let mut shutdown = state.shutdown.clone();
  let mut timer = tokio::time::interval(DEGREE_MAINTENANCE_TICK_PERIOD);
  timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
  loop {
    tokio::select! {
      changed = shutdown.changed() => {
        let _ = changed;
        break;
      }
      _ = timer.tick() => {
        // Best-effort by contract: a failed tick (store outage) waits
        // for the next one, but never silently — the same attribution
        // rule as the recovery tick.
        if let Err(error) = state.maintenance_tick().await {
          tracing::warn!(kind = ?error.kind(), "degree maintenance tick failed");
        }
      }
    }
  }
}

impl TickState {
  /// One maintenance tick: recompute the degree plan from the active
  /// member universe and the live session table, and dial the deficit
  /// in tracked tasks (each bounded by the configured dial deadline
  /// plus the authentication deadline, reconciled by the next tick).
  /// A skipped or failed dial simply waits for the next tick — the
  /// plane is best-effort by contract.
  pub(super) async fn maintenance_tick(&self) -> Result<()> {
    let store = self.context().store();
    let local = self.context().identity().node().clone();
    let members =
      super::recovery::known_online_member_endpoints(self.exclusion_cache(), store, &local).await?;
    let connected: BTreeSet<NodeId> = self
      .sessions()
      .lock()
      .map_err(|_| Error::poisoned("session table"))?
      .iter()
      .filter(|(_, entry)| entry.alive())
      .map(|(peer, _)| peer.clone())
      .collect();
    // The cluster size includes this node; the universe map excludes it.
    let plan = crate::membership::degree::degree_plan(
      members.len().saturating_add(1),
      self.config().connection_degree(),
      connected.len(),
    );
    if plan.dial_budget == 0 {
      // Healthy at target, fully offline (recovery owns it), or nothing
      // left to reach. The healthy-at-target case with unconnected
      // members left is the plane's residual boundary — neither
      // plane dials — so the low-frequency bridge probe takes over.
      return self.bridge_probe_tick(&local, &members, &connected, &plan);
    }
    // Previous tick's dials may still be in flight (dial deadline plus
    // authentication deadline exceeds one cadence): never exceed the
    // deficit with concurrent dials, or a slow mesh doubles its own
    // dial load every tick. This gate skips the whole tick when the
    // budget is already exhausted; the spawn loop below re-checks per
    // spawn, because a PARTIALLY free budget must not overshoot either.
    if self
      .maintenance_pending
      .load(std::sync::atomic::Ordering::Relaxed)
      >= plan.dial_budget
    {
      debug!(
        pending = self
          .maintenance_pending
          .load(std::sync::atomic::Ordering::Relaxed),
        budget = plan.dial_budget,
        "degree maintenance tick deferred: dials in flight"
      );
      return Ok(());
    }
    let dials = crate::membership::degree::select_degree_dials(
      plan.dial_budget,
      &local,
      &members,
      &connected,
      self.entropy().as_ref(),
    )?;
    // Per-member endpoint rotation: every dial of a member advances that
    // member's OWN serial, wrapping per member — the same per-member
    // rotation the recovery plane applies, through the shared endpoint
    // selector's serial map. A member
    // whose dialed endpoint is unreachable is retried on its next
    // endpoint by the next tick that selects it, regardless of which
    // members any one tick happens to select.
    for (peer, endpoints) in dials {
      // In-flight bound re-check per spawn: the
      // pre-batch gate compares the counter to the budget once, but
      // previous ticks' dials can still hold slots when this batch
      // starts, so spawning the whole batch would admit up to
      // `2*dial_budget - 1` concurrent dials. The check right before
      // each spawn holds the batch at the budget; unserved members
      // wait for the next tick's plan.
      if self
        .maintenance_pending
        .load(std::sync::atomic::Ordering::Relaxed)
        >= plan.dial_budget
      {
        debug!("degree maintenance batch truncated at the in-flight budget");
        break;
      }
      let Some(endpoint) = self.endpoint_selector().next_endpoint(&peer, &endpoints) else {
        continue;
      };
      self.spawn_maintenance_dial(
        peer,
        endpoint.clone(),
        crate::session::stream::DialClass::Caller,
      );
    }
    Ok(())
  }

  /// One bridge-probe decision for an otherwise quiescent maintenance
  /// plane (the dial budget is zero): the residual boundary — two
  /// sub-partitions each internally meshed at/above the degree target —
  /// never re-bridges on its own, because the deficit
  /// budget is zero and the recovery controller quiesces on any one
  /// authenticated route. The probe is deliberately slow and bounded:
  /// it fires for EVERY healthy node with at least one unconnected
  /// member — including nodes already above the target, whose surplus
  /// app-initiated sessions must not blind them to the far side of a
  /// partition — at most once per [`BRIDGE_PROBE_INTERVAL_TICKS`]
  /// eligible maintenance ticks (the interval bracket bounds the dial
  /// rate), and dials exactly ONE uniformly random unconnected member
  /// through the SAME deficit machinery (`select_degree_dials`,
  /// endpoint rotation, `spawn_maintenance_dial`). The edge lands as a
  /// probe-class maintenance edge, never caller- or recovery-class: the
  /// recovery plane's redundancy pruning never reclaims it — the bridge
  /// that healed a partition must outlive any cut — and the plane stops
  /// probing while it lives, so a node holds at most one probe edge. A
  /// failed probe dial is recorded at debug level only: a refused peer
  /// is the probe's expected outcome while the partition persists, never
  /// an error.
  fn bridge_probe_tick(
    &self, local: &NodeId, members: &BTreeMap<NodeId, Vec<crate::Endpoint>>,
    connected: &BTreeSet<NodeId>, plan: &crate::membership::degree::DegreePlan,
  ) -> Result<()> {
    // Eligibility is the whole gate: healthy (the deficit path owns
    // below-target states, the recovery plane owns zero sessions) and
    // at least one unconnected member to reach — a fully connected
    // node never even spends the cadence bracket. Every healthy node
    // qualifies regardless of how far above the target its session
    // count sits: the interval bracket alone bounds the dial rate, so
    // surplus app-initiated sessions cannot blind a node to the far
    // side of a partition.
    let eligible = plan.state == crate::ConnectionDegreeState::Healthy
      && members.keys().any(|node| !connected.contains(node));
    if !eligible {
      return Ok(());
    }
    // One bridge dial in flight at a time — the same in-flight bound
    // the deficit path applies to its batch, so a stalled probe dial
    // defers the next probe instead of stacking concurrent ones.
    if self
      .maintenance_pending
      .load(std::sync::atomic::Ordering::Relaxed)
      >= 1
    {
      debug!("bridge probe deferred: a maintenance dial is in flight");
      return Ok(());
    }
    // The cadence bracket: only eligible ticks advance it, and the
    // probe fires on the tick it reaches one. Solely the maintenance
    // worker mutates the atomic, so load/store cannot race here.
    let countdown = self
      .bridge_probe_ticks
      .load(std::sync::atomic::Ordering::Relaxed);
    if countdown > 1 {
      self
        .bridge_probe_ticks
        .store(countdown - 1, std::sync::atomic::Ordering::Relaxed);
      return Ok(());
    }
    // The one-live-probe-edge cap, bounded in time: a landed probe edge
    // IS this node's bridge, so no further probe may fire while it lives
    // — otherwise every interval that succeeds would add one more
    // permanent edge and a healthy node would densify toward a full mesh.
    // The check sits after the bracket on purpose: the bracket keeps
    // advancing, so the first eligible tick after the probe edge retires
    // probes again instead of waiting out a fresh interval.
    match self.probe_edge_peer() {
      // A poisoned session table suppresses the probe: densifying the
      // mesh is the unsafe direction, and the edge's age simply stops
      // advancing.
      Err(error) => {
        debug!(kind = ?error.kind(), "bridge probe deferred: the session table is poisoned");
        return Ok(());
      }
      Ok(Some(peer)) => {
        // The edge's bounded lifetime: a same-side landing must not spend
        // the node's only probe forever, so an edge older than the
        // lifetime is reclaimed here and the replacement probe runs in
        // this same tick.
        if !self.reclaim_aged_probe_edge(&peer)? {
          debug!("bridge probe deferred: a probe edge is already live");
          return Ok(());
        }
      }
      Ok(None) => self.forget_probe_edge(),
    }
    self.bridge_probe_ticks.store(
      BRIDGE_PROBE_INTERVAL_TICKS,
      std::sync::atomic::Ordering::Relaxed,
    );
    // The replacement probe skips the peer whose edge was just reclaimed,
    // so the rotation advances instead of re-picking the edge it cut. The
    // exclusion is single-slot and falls back to the full pool when it
    // would leave nothing to dial.
    let pool = self
      .take_retired_probe_peer()
      .as_ref()
      .and_then(|retired| probe_pool(members, retired));
    let mut dials = match &pool {
      Some(pool) => crate::membership::degree::select_degree_dials(
        1,
        local,
        pool,
        connected,
        self.entropy().as_ref(),
      )?,
      None => Vec::new(),
    };
    if dials.is_empty() {
      dials = crate::membership::degree::select_degree_dials(
        1,
        local,
        members,
        connected,
        self.entropy().as_ref(),
      )?;
    }
    // Per-member endpoint rotation, the same serial map the deficit
    // path and the recovery plane share: a multi-homed member's
    // endpoints rotate across successive probes of that member,
    // wrapping per member.
    for (peer, endpoints) in dials {
      let Some(endpoint) = self.endpoint_selector().next_endpoint(&peer, &endpoints) else {
        continue;
      };
      debug!(
        peer = %peer.as_str(),
        endpoint = %endpoint.as_str(),
        interval_ticks = BRIDGE_PROBE_INTERVAL_TICKS,
        "degree bridge probe dial"
      );
      self.spawn_maintenance_dial(
        peer,
        endpoint.clone(),
        crate::session::stream::DialClass::Probe,
      );
    }
    Ok(())
  }

  /// The live bridge-probe edge's peer, if the node holds one. A poisoned
  /// session-table lock is an error: the caller suppresses the probe
  /// rather than densify on a table it cannot read.
  fn probe_edge_peer(&self) -> Result<Option<NodeId>> {
    let sessions = self
      .sessions()
      .lock()
      .map_err(|_| Error::poisoned("session table"))?;
    Ok(sessions.iter().find_map(|(peer, entry)| {
      (entry.alive() && entry.dial_class() == crate::session::stream::DialClass::Probe)
        .then(|| peer.clone())
    }))
  }

  /// Ages the live probe edge by one probe interval and reclaims it once
  /// its bounded lifetime elapses. Returns whether the plane may probe
  /// now; a reclaimed edge records its peer for the replacement probe to
  /// skip.
  ///
  /// The cut re-verifies the exact observed entry under the session-table
  /// lock (alive and probe-class) before removing it, the redundancy
  /// prune's exact-identity rule: a reconnect that replaced the map entry
  /// in any window is never retired as the old edge.
  fn reclaim_aged_probe_edge(&self, peer: &NodeId) -> Result<bool> {
    let due = {
      let mut ledger = self
        .probe_ledger
        .lock()
        .map_err(|_| Error::internal("probe ledger"))?;
      let age = match &ledger.edge {
        Some((tracked, age)) if tracked == peer => age.saturating_add(1),
        // First observation: the edge has already lived one interval.
        _ => 1,
      };
      if age < BRIDGE_PROBE_EDGE_LIFETIME_TICKS {
        ledger.edge = Some((peer.clone(), age));
        return Ok(false);
      }
      ledger.edge = None;
      true
    };
    debug_assert!(due);
    let removed = {
      let mut sessions = self
        .sessions()
        .lock()
        .map_err(|_| Error::poisoned("session table"))?;
      match sessions.get(peer) {
        Some(entry)
          if entry.alive() && entry.dial_class() == crate::session::stream::DialClass::Probe =>
        {
          sessions.remove(peer)
        }
        // The edge retired on its own between the scan and the cut: the
        // rotation state is stale, the probe is not.
        _ => None,
      }
    };
    let Some(entry) = removed else {
      return Ok(true);
    };
    crate::session::stream::retire(&entry);
    self.events.emit(crate::SessionChanged::new(peer.clone()));
    self
      .probe_ledger
      .lock()
      .map_err(|_| Error::internal("probe ledger"))?
      .retired = Some(peer.clone());
    tracing::debug!(
      peer = %peer.as_str(),
      intervals = BRIDGE_PROBE_EDGE_LIFETIME_TICKS,
      "reclaimed the aged bridge-probe edge to rotate the probe"
    );
    Ok(true)
  }

  /// Forgets the tracked probe edge: the node holds none, so the next
  /// landing starts a fresh lifetime.
  fn forget_probe_edge(&self) {
    if let Ok(mut ledger) = self.probe_ledger.lock() {
      ledger.edge = None;
    }
  }

  /// Consumes the peer whose probe edge the plane just reclaimed.
  fn take_retired_probe_peer(&self) -> Option<NodeId> {
    self
      .probe_ledger
      .lock()
      .ok()
      .and_then(|mut ledger| ledger.retired.take())
  }

  /// Spawns one maintenance dial through the shared member dial
  /// lifecycle (see `runtime/recovery.rs`): the maintenance worker never
  /// blocks on a handshake, the scoped permit releases the in-flight
  /// slot on completion, panic, or cancellation, and the JoinHandle
  /// joins the tracked connection-task set — the probe dials through
  /// this exact path. The edge class travels with the dial: a deficit
  /// dial is caller-class (never reclaimed), a probe dial is probe-class
  /// (never reclaimed either, and capped at one live edge).
  fn spawn_maintenance_dial(
    &self, peer: NodeId, receiver: crate::Endpoint, class: crate::session::stream::DialClass,
  ) {
    spawn_member_dial(
      self,
      Arc::clone(&self.maintenance_pending),
      peer,
      receiver,
      class,
      report_maintenance_dial_failure,
    );
  }
}

/// The replacement probe's candidate pool: the member universe minus the
/// peer whose probe edge the plane just reclaimed, so the rotation
/// advances instead of re-picking the edge it cut. `None` when the
/// exclusion would leave nothing to dial — the caller then probes the
/// full universe, because a rotation that starves the probe is worse than
/// re-picking one peer.
fn probe_pool(
  members: &BTreeMap<NodeId, Vec<crate::Endpoint>>, retired: &NodeId,
) -> Option<BTreeMap<NodeId, Vec<crate::Endpoint>>> {
  let pool: BTreeMap<NodeId, Vec<crate::Endpoint>> = members
    .iter()
    .filter(|(node, _)| *node != retired)
    .map(|(node, endpoints)| (node.clone(), endpoints.clone()))
    .collect();
  (!pool.is_empty()).then_some(pool)
}

/// The maintenance plane's failure diagnostics for the shared dial
/// lifecycle: a failed deficit or probe dial is the expected outcome
/// while a partition or outage persists — recorded at debug only, never
/// an error condition.
fn report_maintenance_dial_failure(peer: &NodeId, error: &Error) {
  debug!(
    peer = %peer.as_str(),
    kind = ?error.kind(),
    "degree maintenance dial failed"
  );
}

impl Supervisor {
  /// The public connection-degree observation: the effective target,
  /// the live session count, and the resulting health. Recomputed from
  /// the stores per query (the same bounded scan the recovery tick
  /// runs every two seconds), so an operator's read never trails a
  /// membership change by more than the store itself.
  pub(super) async fn connection_degree_view(&self) -> Result<crate::ConnectionDegreeView> {
    let context = self.context()?;
    let local = context.identity().node().clone();
    let members = super::recovery::known_online_member_endpoints(
      &self.exclusion_cache,
      context.store(),
      &local,
    )
    .await?;
    let sessions = self
      .dependencies
      .sessions
      .lock()
      .map_err(|_| Error::poisoned("session table"))?
      .values()
      .filter(|entry| entry.alive())
      .count();
    let plan = crate::membership::degree::degree_plan(
      members.len().saturating_add(1),
      self.dependencies.config.connection_degree(),
      sessions,
    );
    Ok(crate::ConnectionDegreeView::new(
      plan.state,
      sessions,
      plan.target,
    ))
  }
}

#[cfg(test)]
mod tests {
  use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
  };

  use crate::{
    runtime::supervisor::test_support::{
      self, insert_live_session, install_member, member_id, member_key, refusing_peer, silent_peer,
      supervisor_over,
    },
    session::stream::DialClass,
  };

  /// Installs one active member whose only endpoint addresses the
  /// panicking custom transport: descriptor through the supervisor's
  /// store plus the trusted binding injected into the reference factory
  /// — the same pair `test_support::install_member` lays down for a wss
  /// endpoint.
  async fn install_panicking_member(
    supervisor: &crate::runtime::supervisor::Supervisor,
    reference: &Arc<crate::storage::contract::ReferenceFactory>, seed: u64, endpoint: &str,
  ) {
    let node = member_id(seed);
    let endpoints = vec![crate::Endpoint::parse(endpoint).unwrap()];
    let descriptor =
      crate::membership::NodeDescriptorV1::new(node.clone(), member_key(seed), endpoints, 1, 1);
    crate::membership::store::store_descriptor_ctx(
      supervisor.context().unwrap().store(),
      supervisor.dependencies.entropy.as_ref(),
      &descriptor,
    )
    .await
    .unwrap();
    let (namespace, key) = crate::identity::records::identity_binding_key(&node).unwrap();
    let binding = crate::identity::records::IdentityBindingV1::new(node, member_key(seed));
    crate::identity::testing::inject_enveloped_entry(
      reference,
      &namespace,
      &key,
      binding.encode().unwrap(),
    );
  }

  /// A caller-registered transport whose connect future counts the
  /// attempt and then panics mid-dial — a custom transport future
  /// unwinding through the dial task. The attempt
  /// counter is the observable: it rising again after the panic proves a
  /// later dial still launched, which the leaked in-flight counter made
  /// impossible.
  #[derive(Debug)]
  struct PanickingWire {
    attempts: Arc<AtomicUsize>,
  }

  impl crate::TransportProvider for PanickingWire {
    fn bind(
      &self, _endpoint: crate::Endpoint,
    ) -> crate::BoxFuture<'static, crate::Result<Box<dyn crate::ProviderListener>>> {
      Box::pin(async { Err(crate::Error::not_found("listener")) })
    }

    fn connect(
      &self, _endpoint: crate::Endpoint,
    ) -> crate::BoxFuture<'static, crate::Result<Box<dyn crate::TransportStream>>> {
      let attempts = Arc::clone(&self.attempts);
      Box::pin(async move {
        attempts.fetch_add(1, Ordering::Relaxed);
        panic!("the custom transport's connect future panics mid-dial");
      })
    }
  }

  /// The maintenance tick's wiring: with one live session and four
  /// dialable members, the derived plan for five nodes is k(5) = 3, so
  /// the tick dials the deficit of two in detached tasks (observed as
  /// in-flight slots), the status view reports the same plan, and the
  /// slots release once the dials hit their deadline. With zero sessions
  /// the tick must defer to the recovery plane.
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn maintenance_tick_dials_the_deficit_and_defers_when_offline() {
    let (reference, config) = test_support::reference_and_config();
    let (supervisor, _entropy, sessions) = supervisor_over(
      reference.clone() as Arc<dyn crate::provider::StorageFactory>,
      config,
    )
    .await;
    let ticks = supervisor.tick_state().unwrap();
    let (port, _connections, holder) = silent_peer().await;

    // Four active members (seeds offset above the supervisor's own
    // deterministic identity space): the cluster size is five
    // including self.
    for seed in 101..=104 {
      install_member(&supervisor, &reference, seed, &[port]).await;
    }

    // Fully offline: the recovery plane owns the zero-session case.
    ticks.maintenance_tick().await.unwrap();
    assert_eq!(
      ticks
        .maintenance_pending
        .load(std::sync::atomic::Ordering::Relaxed),
      0,
      "a fully offline node must defer to the recovery plane"
    );
    let view = supervisor.connection_degree_view().await.unwrap();
    assert_eq!(view.sessions(), 0);
    assert_eq!(view.target(), 3, "k(5) = 3 from the shipped degree table");
    assert_eq!(view.state(), crate::ConnectionDegreeState::Unhealthy);

    // One live session: the deficit is two, dialed immediately and kept
    // in flight by the silent peer, so the slot count is deterministic.
    insert_live_session(
      &sessions,
      member_id(101),
      ticks.entropy().as_ref(),
      DialClass::Caller,
    );
    ticks.maintenance_tick().await.unwrap();
    let pending = ticks
      .maintenance_pending
      .load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(pending, 2, "the tick dials exactly the deficit");
    let view = supervisor.connection_degree_view().await.unwrap();
    assert_eq!(view.sessions(), 1);
    assert_eq!(view.state(), crate::ConnectionDegreeState::Unhealthy);

    // The slots release when the dials hit their deadline, so a later
    // tick can dial again instead of piling up in-flight work.
    tokio::time::timeout(std::time::Duration::from_secs(6), async {
      loop {
        if ticks
          .maintenance_pending
          .load(std::sync::atomic::Ordering::Relaxed)
          == 0
        {
          break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
      }
    })
    .await
    .expect("the expired dials must release their in-flight slots");
    holder.abort();
  }

  /// Endpoint-level failover for the degree plane: a multi-homed member
  /// whose first endpoint is unreachable is dialed on its SECOND endpoint
  /// by the next maintenance tick —
  /// the same per-member rotation the recovery plane applies, so maintenance dials never hammer a dead first endpoint forever. A
  /// single-endpoint projection would dial the first endpoint again and
  /// the second listener would never see a connection.
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn maintenance_dials_rotate_to_the_second_endpoint_when_the_first_stalls() {
    let (reference, config) = test_support::reference_and_config();
    let (supervisor, _entropy, sessions) = supervisor_over(
      reference.clone() as Arc<dyn crate::provider::StorageFactory>,
      config,
    )
    .await;
    let ticks = supervisor.tick_state().unwrap();
    let (first_port, first_connections, first_holder) = silent_peer().await;
    let (second_port, second_connections, second_holder) = silent_peer().await;

    // A three-node cluster: one connected member leaves exactly one
    // dial candidate — the multi-homed member with both silent
    // endpoints — so the observed connection counts are deterministic.
    install_member(&supervisor, &reference, 101, &[first_port]).await;
    install_member(&supervisor, &reference, 102, &[first_port, second_port]).await;
    insert_live_session(
      &sessions,
      member_id(101),
      ticks.entropy().as_ref(),
      DialClass::Caller,
    );

    // First tick: attempt 1 dials the member's FIRST endpoint...
    ticks.maintenance_tick().await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(6), async {
      loop {
        if ticks
          .maintenance_pending
          .load(std::sync::atomic::Ordering::Relaxed)
          == 0
        {
          break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
      }
    })
    .await
    .expect("the first maintenance dial must release its in-flight slot");
    assert_eq!(
      first_connections.load(std::sync::atomic::Ordering::Relaxed),
      1,
      "attempt 1 dials the first published endpoint"
    );
    assert_eq!(
      second_connections.load(std::sync::atomic::Ordering::Relaxed),
      0,
      "attempt 1 must not touch the second endpoint"
    );

    // ...and the next tick rotates to the SECOND endpoint.
    ticks.maintenance_tick().await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(6), async {
      loop {
        if second_connections.load(std::sync::atomic::Ordering::Relaxed) >= 1 {
          break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
      }
    })
    .await
    .expect("attempt 2 must dial the second published endpoint");
    assert_eq!(
      first_connections.load(std::sync::atomic::Ordering::Relaxed),
      1,
      "attempt 2 leaves the first endpoint alone"
    );
    first_holder.abort();
    second_holder.abort();
  }

  /// The same in-flight bound for the deficit path:
  /// with one dial still parked from the previous tick, the next tick
  /// must hold the batch AT the dial budget instead of overshooting to
  /// `2*dial_budget - 1` — the pre-batch gate alone admits the
  /// overshoot because a slot frees between the ticks. A four-node
  /// cluster (k(4) = 3) with one live session leaves a deficit of two
  /// and exactly two dial candidates; member 101's first endpoint
  /// refuses connections (its slot frees inside the poll below) and
  /// its second endpoint is the silent first listener, so the second
  /// tick starts with one held slot: exactly one further dial may
  /// launch, whichever member the uniform pick serves first.
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn maintenance_tick_holds_in_flight_dials_at_the_dial_budget() {
    let (reference, config) = test_support::reference_and_config();
    // A long dial deadline keeps the parked dial in flight for the whole
    // test, so the one-held-slot window the second tick needs is wide on
    // every platform.
    let config = config
      .with_dial_deadline(std::time::Duration::from_secs(30))
      .unwrap();
    let (supervisor, _entropy, sessions) = supervisor_over(
      reference.clone() as Arc<dyn crate::provider::StorageFactory>,
      config,
    )
    .await;
    let ticks = supervisor.tick_state().unwrap();
    // A refusing peer: the dial fails fast and deterministically at the
    // handshake, releasing its in-flight slot and giving the second tick
    // exactly one held slot to start from.
    let (refused_port, refused_holder) = refusing_peer().await;
    let (first_port, first_connections, first_holder) = silent_peer().await;
    let (second_port, second_connections, second_holder) = silent_peer().await;

    install_member(&supervisor, &reference, 101, &[refused_port, first_port]).await;
    install_member(&supervisor, &reference, 102, &[second_port]).await;
    // The connected member completes the k(4) = 3 arithmetic: one live
    // session leaves the deficit at two with 101/102 as the only
    // candidates, so the batch and the connection counts are
    // deterministic.
    install_member(&supervisor, &reference, 103, &[first_port]).await;
    insert_live_session(
      &sessions,
      member_id(103),
      ticks.entropy().as_ref(),
      DialClass::Caller,
    );

    // First tick: the budget of two dials 101's refused first endpoint
    // and parks 102 against the silent peer — two slots taken, then
    // one. The poll also awaits the parked dial's accept, since the
    // connection lands asynchronously.
    ticks.maintenance_tick().await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(60), async {
      loop {
        if ticks
          .maintenance_pending
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

    // Second tick: one held slot, budget two — the batch must stop at
    // the bound instead of spawning both candidates, which would park
    // three dials in flight.
    ticks.maintenance_tick().await.unwrap();
    assert_eq!(
      ticks
        .maintenance_pending
        .load(std::sync::atomic::Ordering::Relaxed),
      2,
      "the tick must hold in-flight dials at the dial budget, never 2*dial_budget - 1"
    );
    // The re-dial connects asynchronously: await its accept before
    // counting, then check the bound stopped the remaining candidate.
    tokio::time::timeout(std::time::Duration::from_secs(60), async {
      loop {
        let dialed = first_connections.load(std::sync::atomic::Ordering::Relaxed)
          + second_connections.load(std::sync::atomic::Ordering::Relaxed);
        if dialed >= 2 {
          break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
      }
    })
    .await
    .expect("the second tick must launch exactly one re-dial");
    let dialed = first_connections.load(std::sync::atomic::Ordering::Relaxed)
      + second_connections.load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
      dialed, 2,
      "exactly one re-dial may join the parked first dial; the bound stops the rest"
    );
    first_holder.abort();
    second_holder.abort();
    refused_holder.abort();
  }

  /// The bridge-probe cadence stays on the order of five minutes
  /// (like the tick period, purely local — never a cluster-wide
  /// contract): pinned so a future recalibration is a deliberate act.
  #[test]
  fn bridge_probe_interval_is_five_minutes() {
    assert_eq!(
      u64::from(super::BRIDGE_PROBE_INTERVAL_TICKS)
        * super::DEGREE_MAINTENANCE_TICK_PERIOD.as_secs(),
      300
    );
  }

  /// The replacement probe's pool excludes exactly the released peer, and
  /// never empties: with the released peer as the only remaining
  /// candidate the pool is `None`, so the caller falls back to the full
  /// universe instead of leaving the plane silent.
  #[test]
  fn the_probe_pool_excludes_the_released_peer_without_emptying() {
    let endpoint = crate::Endpoint::parse("wss://127.0.0.1:9").unwrap();
    let members: std::collections::BTreeMap<_, _> = [member_id(105), member_id(106)]
      .into_iter()
      .map(|node| (node, vec![endpoint.clone()]))
      .collect();

    let pool = super::probe_pool(&members, &member_id(105)).expect("106 remains");
    assert_eq!(
      pool.keys().cloned().collect::<Vec<_>>(),
      vec![member_id(106)]
    );
    let pool = super::probe_pool(&members, &member_id(106)).expect("105 remains");
    assert_eq!(
      pool.keys().cloned().collect::<Vec<_>>(),
      vec![member_id(105)]
    );

    // The released peer is the only member left: no pool, so the caller
    // probes the full universe rather than skipping the probe.
    let only: std::collections::BTreeMap<_, _> = [member_id(105)]
      .into_iter()
      .map(|node| (node, vec![endpoint.clone()]))
      .collect();
    assert!(super::probe_pool(&only, &member_id(105)).is_none());
  }

  /// The probe edge's bounded lifetime stays on the order of an hour
  /// (purely local, never a cluster-wide contract): pinned so a future
  /// recalibration is a deliberate act, and so the rotation's cost — one
  /// reclaim-and-reprobe per lifetime — stays visible next to the
  /// cadence it multiplies.
  #[test]
  fn bridge_probe_edge_lifetime_is_one_hour() {
    assert_eq!(
      u64::from(super::BRIDGE_PROBE_EDGE_LIFETIME_TICKS)
        * super::DEGREE_MAINTENANCE_TICK_PERIOD.as_secs(),
      3_600
    );
  }

  /// The bridge probe's residual boundary: two sub-partitions each
  /// internally meshed at/above the degree target never re-bridge —
  /// the deficit budget is zero and the recovery controller quiesces
  /// on any one route. The bridge probe heals it: a healthy node with
  /// unconnected members issues ONE cross-partition maintenance dial
  /// per probe interval — never before the interval elapses, never
  /// through the recovery plane — and the interval bracket alone
  /// bounds the dial rate.
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn bridge_probe_dials_a_cross_partition_member_within_two_intervals() {
    let (reference, config) = test_support::reference_and_config();
    let (supervisor, _entropy, sessions) = supervisor_over(
      reference.clone() as Arc<dyn crate::provider::StorageFactory>,
      config,
    )
    .await;
    let ticks = supervisor.tick_state().unwrap();
    let (port, connections, holder) = silent_peer().await;

    // Two halves of an eight-node cluster (k(8) = 4): this node's half
    // — members 101..104 — is fully meshed from here (four live
    // sessions, exactly the target), and the only unconnected members
    // are the other half (105..107). Every member shares one silent
    // listener, so whichever member the uniform pick chooses, the dial
    // lands on the counted endpoint.
    for seed in 101..=104 {
      insert_live_session(
        &sessions,
        member_id(seed),
        ticks.entropy().as_ref(),
        DialClass::Caller,
      );
    }
    for seed in 101..=107 {
      install_member(&supervisor, &reference, seed, &[port]).await;
    }
    let view = supervisor.connection_degree_view().await.unwrap();
    assert_eq!(view.target(), 4, "k(8) = 4 from the shipped degree table");
    assert_eq!(view.sessions(), 4);
    assert_eq!(view.state(), crate::ConnectionDegreeState::Healthy);

    // The finding's exact shape, one interval long: healthy at target
    // with a zero dial budget and unconnected members — the ordinary
    // tick dials nothing, and the cadence bracket holds every tick of
    // the interval back.
    for _ in 0..super::BRIDGE_PROBE_INTERVAL_TICKS - 1 {
      ticks.maintenance_tick().await.unwrap();
      let view = supervisor.connection_degree_view().await.unwrap();
      assert_eq!(view.state(), crate::ConnectionDegreeState::Healthy);
      assert_eq!(
        connections.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "the cadence bracket holds the interval's first ticks back"
      );
    }
    assert_eq!(
      ticks
        .bridge_probe_ticks
        .load(std::sync::atomic::Ordering::Relaxed),
      1,
      "eligible ticks spend the bracket one at a time"
    );

    // The interval's tick: exactly one cross-half dial, through the
    // maintenance path (its in-flight slot), never the recovery plane.
    ticks.maintenance_tick().await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(6), async {
      loop {
        if connections.load(std::sync::atomic::Ordering::Relaxed) >= 1 {
          break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
      }
    })
    .await
    .expect("the bridge probe must issue its cross-half dial");
    assert_eq!(
      ticks
        .maintenance_pending
        .load(std::sync::atomic::Ordering::Relaxed),
      1,
      "the probe dial runs as an ordinary maintenance dial"
    );
    assert_eq!(
      ticks
        .recovery_pending
        .load(std::sync::atomic::Ordering::Relaxed),
      0,
      "the bridge edge must never be recovery-class"
    );
    assert_eq!(
      ticks
        .bridge_probe_ticks
        .load(std::sync::atomic::Ordering::Relaxed),
      super::BRIDGE_PROBE_INTERVAL_TICKS,
      "the bracket re-arms for the next interval"
    );

    // The stalled dial releases its slot at the deadline; the re-armed
    // bracket then holds further probes back until the next interval
    // elapses — at most one probe dial per interval, whatever the
    // session count.
    tokio::time::timeout(std::time::Duration::from_secs(6), async {
      loop {
        if ticks
          .maintenance_pending
          .load(std::sync::atomic::Ordering::Relaxed)
          == 0
        {
          break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
      }
    })
    .await
    .expect("the stalled probe dial must release its in-flight slot");
    for _ in 0..3 {
      ticks.maintenance_tick().await.unwrap();
    }
    assert_eq!(
      connections.load(std::sync::atomic::Ordering::Relaxed),
      1,
      "the re-armed bracket holds the next interval's first ticks back"
    );
    holder.abort();
  }

  /// Every healthy node with
  /// unconnected members probes — a node holding surplus app-initiated
  /// sessions above `target + 1` never stays blind to the far side
  /// of a partition until a session drop: the probe fires at its
  /// interval even at six sessions over a target of four, and the
  /// interval bracket stays the sole storm bound.
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn a_node_above_the_target_with_unconnected_members_still_probes() {
    let (reference, config) = test_support::reference_and_config();
    let (supervisor, _entropy, sessions) = supervisor_over(
      reference.clone() as Arc<dyn crate::provider::StorageFactory>,
      config,
    )
    .await;
    let ticks = supervisor.tick_state().unwrap();
    let (port, connections, holder) = silent_peer().await;

    // An eight-node cluster (k(8) = 4) with SIX live sessions — two
    // above the probe's `target + slack` bound — and one unconnected member
    // (107), so the probe's uniform pick is deterministic and the
    // silent listener counts the dial.
    for seed in 101..=106 {
      insert_live_session(
        &sessions,
        member_id(seed),
        ticks.entropy().as_ref(),
        DialClass::Caller,
      );
    }
    for seed in 101..=107 {
      install_member(&supervisor, &reference, seed, &[port]).await;
    }
    let view = supervisor.connection_degree_view().await.unwrap();
    assert_eq!(view.target(), 4, "k(8) = 4 from the shipped degree table");
    assert_eq!(
      view.sessions(),
      6,
      "the surplus sessions sit above the target + slack bound"
    );
    assert_eq!(view.state(), crate::ConnectionDegreeState::Healthy);

    // The bracket still holds the interval's first ticks back...
    for _ in 0..super::BRIDGE_PROBE_INTERVAL_TICKS - 1 {
      ticks.maintenance_tick().await.unwrap();
    }
    assert_eq!(
      connections.load(std::sync::atomic::Ordering::Relaxed),
      0,
      "the cadence bracket holds the interval's first ticks back"
    );

    // ...and the interval's tick probes the unconnected member even
    // though the session count sits far above the target.
    ticks.maintenance_tick().await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(6), async {
      loop {
        if connections.load(std::sync::atomic::Ordering::Relaxed) >= 1 {
          break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
      }
    })
    .await
    .expect("a node above the target must still probe its unconnected member");
    assert_eq!(
      ticks
        .recovery_pending
        .load(std::sync::atomic::Ordering::Relaxed),
      0,
      "the bridge edge must never be recovery-class"
    );
    holder.abort();
  }

  /// The probe is a one-shot bridge attempt, not a densification loop: a
  /// landed probe edge is the node's one bridge, so the plane probes no
  /// further while it lives — otherwise every five-minute bracket that
  /// succeeds would add another permanent edge and a healthy node would
  /// densify toward a full mesh. The edge retires with its session (peer
  /// offline, teardown), and the next eligible tick probes again. The
  /// suppression is bounded in time, not forever — see
  /// `an_aged_probe_edge_is_reclaimed_and_the_probe_rotates`.
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn a_live_probe_edge_suppresses_the_next_probe_until_it_retires() {
    let (reference, config) = test_support::reference_and_config();
    let (supervisor, _entropy, sessions) = supervisor_over(
      reference.clone() as Arc<dyn crate::provider::StorageFactory>,
      config,
    )
    .await;
    let ticks = supervisor.tick_state().unwrap();
    let (port, connections, holder) = silent_peer().await;

    // An eight-node cluster (k(8) = 4): four live caller sessions put
    // this node exactly at target, members 106 and 107 stay unconnected
    // — so the probe is eligible — and the live probe edge to 105 is the
    // bridge the previous probe landed.
    for seed in 101..=104 {
      insert_live_session(
        &sessions,
        member_id(seed),
        ticks.entropy().as_ref(),
        DialClass::Caller,
      );
    }
    for seed in 101..=107 {
      install_member(&supervisor, &reference, seed, &[port]).await;
    }
    insert_live_session(
      &sessions,
      member_id(105),
      ticks.entropy().as_ref(),
      DialClass::Probe,
    );
    let view = supervisor.connection_degree_view().await.unwrap();
    assert_eq!(view.target(), 4, "k(8) = 4 from the shipped degree table");
    assert_eq!(view.state(), crate::ConnectionDegreeState::Healthy);

    // Two whole brackets: while the probe edge lives, no probe dial may
    // leave the plane — a second one would make the bridge permanent
    // surplus on top of the first. The negative observation needs a
    // settle window: a probe dial that (wrongly) left the plane would
    // land on the counted listener inside it.
    for _ in 0..(2 * super::BRIDGE_PROBE_INTERVAL_TICKS) {
      ticks.maintenance_tick().await.unwrap();
    }
    let dialed = tokio::time::timeout(std::time::Duration::from_millis(500), async {
      loop {
        if connections.load(std::sync::atomic::Ordering::Relaxed) >= 1 {
          return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
      }
    })
    .await;
    assert!(
      dialed.is_err(),
      "a live probe edge must suppress every further probe dial"
    );
    assert_eq!(
      ticks
        .maintenance_pending
        .load(std::sync::atomic::Ordering::Relaxed),
      0,
      "a suppressed probe takes no in-flight slot"
    );

    // The edge retires with its session: the bracket kept advancing while
    // the probe was suppressed, so the very next eligible tick probes
    // again instead of waiting out a fresh interval.
    crate::session::stream::retire_session(&sessions, &member_id(105)).unwrap();
    ticks.maintenance_tick().await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(6), async {
      loop {
        if connections.load(std::sync::atomic::Ordering::Relaxed) >= 1 {
          break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
      }
    })
    .await
    .expect("the plane must probe again once the probe edge retires");
    holder.abort();
  }

  /// The one-edge cap is bounded in time: a probe edge that has lived
  /// its whole lifetime is reclaimed by the probe plane itself and the
  /// replacement probe runs in the same tick, skipping the peer it just
  /// released. Without the rotation a single landing on the same side of
  /// a partition — which bridges nothing but still holds the node's only
  /// probe edge — would spend the probe for the node's whole lifetime.
  ///
  /// The exclusion is observable through the listeners: two unconnected
  /// members, one on each port, and the reclaimed peer's port must stay
  /// silent while the other is dialed.
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn an_aged_probe_edge_is_reclaimed_and_the_probe_rotates() {
    let (reference, config) = test_support::reference_and_config();
    let (supervisor, _entropy, sessions) = supervisor_over(
      reference.clone() as Arc<dyn crate::provider::StorageFactory>,
      config,
    )
    .await;
    let ticks = supervisor.tick_state().unwrap();
    let (probed_port, probed_connections, probed_holder) = silent_peer().await;
    let (other_port, other_connections, other_holder) = silent_peer().await;

    // A seven-node cluster (k(7) = 4): four live caller sessions put this
    // node exactly at target, so the deficit budget is zero and the probe
    // owns the dial. Member 105 is the live probe edge (the landing the
    // rotation must eventually release); member 106 is the only other
    // unconnected member, on its own port.
    for seed in 101..=104 {
      insert_live_session(
        &sessions,
        member_id(seed),
        ticks.entropy().as_ref(),
        DialClass::Caller,
      );
    }
    for seed in 101..=104 {
      install_member(&supervisor, &reference, seed, &[probed_port]).await;
    }
    install_member(&supervisor, &reference, 105, &[probed_port]).await;
    install_member(&supervisor, &reference, 106, &[other_port]).await;
    insert_live_session(
      &sessions,
      member_id(105),
      ticks.entropy().as_ref(),
      DialClass::Probe,
    );
    let view = supervisor.connection_degree_view().await.unwrap();
    assert_eq!(view.target(), 4, "k(7) = 4 from the shipped degree table");
    assert_eq!(view.state(), crate::ConnectionDegreeState::Healthy);

    // The age starts on the bracket's first firing tick and advances one
    // tick at a time from there (the bracket stays armed while the probe
    // is suppressed), so the reclaim lands on tick
    // `INTERVAL + LIFETIME - 1`. One tick short of it the edge is still
    // the node's bridge and no probe may leave the plane.
    let reclaim_tick =
      super::BRIDGE_PROBE_INTERVAL_TICKS + super::BRIDGE_PROBE_EDGE_LIFETIME_TICKS - 1;
    for _ in 0..reclaim_tick - 1 {
      ticks.maintenance_tick().await.unwrap();
    }
    assert_eq!(
      other_connections.load(std::sync::atomic::Ordering::Relaxed),
      0,
      "a live probe edge suppresses the probe until its lifetime elapses"
    );
    assert!(
      sessions.lock().unwrap().contains_key(&member_id(105)),
      "the edge is still held one tick short of its lifetime"
    );

    // The lifetime's tick: the plane reclaims its own edge and probes a
    // different member in the same tick.
    ticks.maintenance_tick().await.unwrap();
    assert!(
      !sessions.lock().unwrap().contains_key(&member_id(105)),
      "the aged probe edge left the session table"
    );
    tokio::time::timeout(std::time::Duration::from_secs(6), async {
      loop {
        if other_connections.load(std::sync::atomic::Ordering::Relaxed) >= 1 {
          break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
      }
    })
    .await
    .expect("the replacement probe must dial the other unconnected member");
    assert_eq!(
      probed_connections.load(std::sync::atomic::Ordering::Relaxed),
      0,
      "the replacement probe must skip the peer whose edge it just released"
    );
    probed_holder.abort();
    other_holder.abort();
  }

  /// The exclusion is single-slot and never starves the probe: when the
  /// reclaimed peer is the ONLY unconnected member left, the replacement
  /// probe falls back to the full pool and dials it again rather than
  /// leaving the plane silent.
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn the_replacement_probe_falls_back_when_the_retired_peer_is_the_only_target() {
    let (reference, config) = test_support::reference_and_config();
    let (supervisor, _entropy, sessions) = supervisor_over(
      reference.clone() as Arc<dyn crate::provider::StorageFactory>,
      config,
    )
    .await;
    let ticks = supervisor.tick_state().unwrap();
    let (port, connections, holder) = silent_peer().await;

    // Six nodes (k(6) = 3): three caller sessions at target, and member
    // 105 — the live probe edge — is the only member left unconnected
    // once its edge is reclaimed.
    for seed in 101..=103 {
      insert_live_session(
        &sessions,
        member_id(seed),
        ticks.entropy().as_ref(),
        DialClass::Caller,
      );
    }
    for seed in 101..=105 {
      install_member(&supervisor, &reference, seed, &[port]).await;
    }
    insert_live_session(
      &sessions,
      member_id(105),
      ticks.entropy().as_ref(),
      DialClass::Probe,
    );
    let view = supervisor.connection_degree_view().await.unwrap();
    assert_eq!(view.target(), 3, "k(6) = 3 from the shipped degree table");
    assert_eq!(view.state(), crate::ConnectionDegreeState::Healthy);

    for _ in 0..super::BRIDGE_PROBE_INTERVAL_TICKS + super::BRIDGE_PROBE_EDGE_LIFETIME_TICKS {
      ticks.maintenance_tick().await.unwrap();
    }
    tokio::time::timeout(std::time::Duration::from_secs(6), async {
      loop {
        if connections.load(std::sync::atomic::Ordering::Relaxed) >= 1 {
          break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
      }
    })
    .await
    .expect("the replacement probe must fall back to the released peer");
    holder.abort();
  }

  /// A gated tracing capture for the probe-failure test: a global
  /// registry layer whose recording an atomic gates, so only the armed
  /// test observes events and every other test pays nothing. Library
  /// tests install no subscriber otherwise, so the global default is
  /// free to take.
  mod captured_events {
    use std::sync::{Arc, Mutex, OnceLock};

    /// One recorded event: (level, target, message).
    pub(super) type CapturedEvent = (tracing::Level, String, String);

    #[derive(Debug, Default)]
    struct Shared {
      gate: std::sync::atomic::AtomicBool,
      events: Mutex<Vec<CapturedEvent>>,
    }

    /// The armed capture handle: events flow until [`Capture::disarm`].
    pub(super) struct Capture(Arc<Shared>);

    impl Capture {
      /// Clears the recorded events and starts recording.
      pub(super) fn arm(&self) {
        if let Ok(mut events) = self.0.events.lock() {
          events.clear();
        }
        self
          .0
          .gate
          .store(true, std::sync::atomic::Ordering::Relaxed);
      }

      /// Stops recording; the recorded events stay readable.
      pub(super) fn disarm(&self) {
        self
          .0
          .gate
          .store(false, std::sync::atomic::Ordering::Relaxed);
      }

      /// The events recorded so far (other tests' concurrent events
      /// may appear too: the gate is process-wide).
      pub(super) fn events(&self) -> Vec<CapturedEvent> {
        self
          .0
          .events
          .lock()
          .map(|events| events.clone())
          .unwrap_or_default()
      }
    }

    /// Extracts an event's `message` field (the human-readable text of
    /// `tracing::debug!("...")`).
    struct Message(String);

    impl tracing::field::Visit for Message {
      fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
          self.0 = format!("{value:?}");
        }
      }
    }

    struct Layer {
      shared: Arc<Shared>,
    }

    impl<S: tracing::Subscriber> tracing_subscriber::layer::Layer<S> for Layer {
      fn on_event(
        &self, event: &tracing::Event<'_>, _ctx: tracing_subscriber::layer::Context<'_, S>,
      ) {
        if !self.shared.gate.load(std::sync::atomic::Ordering::Relaxed) {
          return;
        }
        let mut message = Message(String::new());
        event.record(&mut message);
        if let Ok(mut events) = self.shared.events.lock() {
          events.push((
            *event.metadata().level(),
            event.metadata().target().to_string(),
            message.0,
          ));
        }
      }
    }

    /// Installs the capturing layer once per process and hands back the
    /// capture handle.
    pub(super) fn install() -> Capture {
      static SHARED: OnceLock<Arc<Shared>> = OnceLock::new();
      Capture(
        SHARED
          .get_or_init(|| {
            use tracing_subscriber::layer::SubscriberExt;
            let shared = Arc::new(Shared::default());
            let _ =
              tracing::subscriber::set_global_default(tracing_subscriber::registry().with(Layer {
                shared: Arc::clone(&shared),
              }));
            shared
          })
          .clone(),
      )
    }
  }

  /// A failed probe dial is an expected outcome, never an error:
  /// the refusal is recorded at debug level only (no warn/error
  /// escalation anywhere on the degree plane), the tick itself stays
  /// `Ok`, the in-flight slot releases, and the re-armed bracket probes
  /// again at the next interval.
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn a_failed_probe_dial_stays_at_debug_level_and_never_escalates() {
    let capture = captured_events::install();
    let (reference, config) = test_support::reference_and_config();
    let (supervisor, _entropy, sessions) = supervisor_over(
      reference.clone() as Arc<dyn crate::provider::StorageFactory>,
      config,
    )
    .await;
    let ticks = supervisor.tick_state().unwrap();
    // A refusing peer: the probe dial fails fast and deterministically
    // at the handshake on every platform.
    let (refused_port, refused_holder) = refusing_peer().await;

    // A five-node cluster (k(5) = 3) healthy at target with exactly one
    // unconnected member (104), whose only endpoint refuses.
    for seed in 101..=103 {
      insert_live_session(
        &sessions,
        member_id(seed),
        ticks.entropy().as_ref(),
        DialClass::Caller,
      );
    }
    for seed in 101..=104 {
      install_member(&supervisor, &reference, seed, &[refused_port]).await;
    }
    let view = supervisor.connection_degree_view().await.unwrap();
    assert_eq!(view.target(), 3, "k(5) = 3 from the shipped degree table");
    assert_eq!(view.sessions(), 3);
    assert_eq!(view.state(), crate::ConnectionDegreeState::Healthy);

    capture.arm();
    // The interval's first ticks hold the bracket back, then the firing
    // tick probes the refusing member: the dial starts, fails fast, and
    // the failure is recorded as a debug event of the degree plane.
    for _ in 0..super::BRIDGE_PROBE_INTERVAL_TICKS - 1 {
      ticks.maintenance_tick().await.unwrap();
    }
    ticks.maintenance_tick().await.unwrap();
    let refused_debug_records = |capture: &captured_events::Capture| {
      capture
        .events()
        .iter()
        .filter(|(level, target, message)| {
          *level == tracing::Level::DEBUG
            && target.as_str() == "radiata::runtime::degree"
            && message.contains("degree maintenance dial failed")
        })
        .count()
    };
    tokio::time::timeout(std::time::Duration::from_secs(6), async {
      loop {
        if refused_debug_records(&capture) >= 1 {
          break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
      }
    })
    .await
    .expect("the refused probe dial must be recorded at debug level");

    // The failed dial releases its in-flight slot and the plane keeps
    // probing: the re-armed bracket fires again at the next interval —
    // the failure is non-fatal, never an error condition.
    tokio::time::timeout(std::time::Duration::from_secs(6), async {
      loop {
        if ticks
          .maintenance_pending
          .load(std::sync::atomic::Ordering::Relaxed)
          == 0
        {
          break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
      }
    })
    .await
    .expect("the refused dial must release its in-flight slot");
    for _ in 0..super::BRIDGE_PROBE_INTERVAL_TICKS {
      ticks.maintenance_tick().await.unwrap();
    }
    tokio::time::timeout(std::time::Duration::from_secs(6), async {
      loop {
        if refused_debug_records(&capture) >= 2 {
          break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
      }
    })
    .await
    .expect("the re-armed bracket must probe again after the failure");

    // No escalation anywhere on the degree plane while armed: every
    // event it emitted stayed at trace/debug/info.
    assert!(
      capture.events().iter().all(|(level, target, _)| {
        target.as_str() != "radiata::runtime::degree"
          || !matches!(*level, tracing::Level::WARN | tracing::Level::ERROR)
      }),
      "a failed probe dial must never escalate past debug"
    );
    capture.disarm();
    refused_holder.abort();
  }

  /// The probe's negative space: a healthy node with NO unconnected
  /// members never probes — no dial leaves the plane, and the cadence
  /// bracket is never even spent.
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn a_fully_connected_healthy_node_never_probes() {
    let (reference, config) = test_support::reference_and_config();
    let (supervisor, _entropy, sessions) = supervisor_over(
      reference.clone() as Arc<dyn crate::provider::StorageFactory>,
      config,
    )
    .await;
    let ticks = supervisor.tick_state().unwrap();
    let (port, connections, holder) = silent_peer().await;

    // A five-node cluster (k(5) = 3) fully meshed from here: every
    // member connected and the target exceeded — nothing left to
    // reach, so no probe may ever fire.
    for seed in 101..=104 {
      insert_live_session(
        &sessions,
        member_id(seed),
        ticks.entropy().as_ref(),
        DialClass::Caller,
      );
    }
    for seed in 101..=104 {
      install_member(&supervisor, &reference, seed, &[port]).await;
    }

    for _ in 0..(3 * super::BRIDGE_PROBE_INTERVAL_TICKS) {
      ticks.maintenance_tick().await.unwrap();
    }
    assert_eq!(
      connections.load(std::sync::atomic::Ordering::Relaxed),
      0,
      "a fully connected node must never issue a probe dial"
    );
    assert_eq!(
      ticks
        .maintenance_pending
        .load(std::sync::atomic::Ordering::Relaxed),
      0
    );
    assert_eq!(
      ticks
        .bridge_probe_ticks
        .load(std::sync::atomic::Ordering::Relaxed),
      super::BRIDGE_PROBE_INTERVAL_TICKS,
      "a fully connected node never spends the cadence bracket"
    );
    holder.abort();
  }

  /// The maintenance cadence stays purely local (never a cluster-wide
  /// contract): pinned so a future recalibration is a deliberate act.
  #[test]
  fn maintenance_cadence_is_thirty_seconds() {
    assert_eq!(
      super::DEGREE_MAINTENANCE_TICK_PERIOD,
      std::time::Duration::from_secs(30)
    );
  }

  /// The maintenance shape: a caller-supplied transport whose
  /// connect future panics mid-dial must not strand its in-flight slot.
  /// The manual `fetch_add`/`fetch_sub` pair decremented after the
  /// await, so the panic skipped the decrement — and both the deficit
  /// gate and the bridge-probe gate read this counter, so every later
  /// tick deferred ("truncated at the in-flight budget") until restart.
  /// With the scoped permit the slot releases on the unwind and the next
  /// tick dials again; the probe shares this exact dial path.
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn a_panicking_transport_future_releases_its_maintenance_slot() {
    let (reference, config) = test_support::reference_and_config();
    let (supervisor, _entropy, sessions) = supervisor_over(
      reference.clone() as Arc<dyn crate::provider::StorageFactory>,
      config,
    )
    .await;
    let mut ticks = supervisor.tick_state().unwrap();
    // Point the plane's transport resolution at the panicking custom
    // transport: the ticks resolve endpoints through this registry.
    let attempts = Arc::new(AtomicUsize::new(0));
    let mut extensions = crate::ExtensionRegistry::new();
    extensions
      .register_transport(
        crate::TransportName::parse("panicwire").unwrap(),
        Arc::new(PanickingWire {
          attempts: Arc::clone(&attempts),
        }),
      )
      .unwrap();
    ticks.extensions = Arc::new(extensions);

    // A three-node cluster (k(3) = 2): member 101 is connected through
    // a live session, member 102 is unconnected and only dialable
    // through the panicking transport — the deficit of one is exactly
    // one dial of 102, deterministically.
    let (connected_port, _connected_connections, connected_holder) = silent_peer().await;
    install_member(&supervisor, &reference, 101, &[connected_port]).await;
    install_panicking_member(&supervisor, &reference, 102, "panicwire://unreachable").await;
    insert_live_session(
      &sessions,
      member_id(101),
      ticks.entropy().as_ref(),
      DialClass::Caller,
    );

    // First tick: the deficit dial starts and the custom transport's
    // future panics mid-dial.
    ticks.maintenance_tick().await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
      loop {
        if attempts.load(Ordering::Relaxed) >= 1 {
          break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
      }
    })
    .await
    .expect("the maintenance tick must dial the panicking transport");
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
      loop {
        if ticks
          .maintenance_pending
          .load(std::sync::atomic::Ordering::Relaxed)
          == 0
        {
          break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
      }
    })
    .await
    .expect("the panicking dial must release its in-flight slot");

    // The gate reads the released counter: the next tick dials again.
    // Under the leaked counter this tick truncated at the budget gate
    // forever and the attempt count froze at one.
    ticks.maintenance_tick().await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
      loop {
        if attempts.load(Ordering::Relaxed) >= 2 {
          break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
      }
    })
    .await
    .expect("the next tick must still dial after the panic");
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
      loop {
        if ticks
          .maintenance_pending
          .load(std::sync::atomic::Ordering::Relaxed)
          == 0
        {
          break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
      }
    })
    .await
    .expect("the second panicking dial must release its in-flight slot too");
    connected_holder.abort();
  }
}
