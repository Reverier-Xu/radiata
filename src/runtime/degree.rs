//! The connection-degree maintenance plane: while the node's live
//! authenticated session count sits below its target degree, a periodic
//! tick dials uniformly random unconnected members from the active
//! member universe until the target is reached.
//!
//! Plane separation, deliberately narrow: the maintenance plane is
//! additive-only — it never prunes sessions, never gates functionality,
//! and never touches the zero-session case (the recovery plane's
//! high-frequency backoff owns a fully offline node). Its dials land as
//! ordinary caller-class edges, so the recovery plane's redundancy
//! pruning never fights the maintenance target. The degree gates only
//! the status query and this cadence; below target with at least one
//! session everything keeps working.
//!
//! The tick runs on the dedicated maintenance worker (audit 2026-10-09
//! item 3), never inline in the supervisor's select loop, and every
//! selected member carries ALL of its published endpoints: each dial of
//! a member rotates that member to its next endpoint with the same
//! per-member endpoint-level failover the recovery plane applies
//! (remaining-items list P2-5), so a multi-homed member whose first
//! endpoint is unreachable is retried on the others.
//!
//! The one deliberate exception to "healthy means dial nothing" is the
//! bridge probe (audit finding #1's residual boundary): EVERY healthy
//! node that still has unconnected members — two sub-partitions each
//! internally meshed at or above the degree target, including nodes
//! holding surplus app-initiated sessions above the target — would
//! otherwise never re-bridge, because the deficit budget is zero
//! (`degree_plan`) and the recovery controller quiesces on any one
//! route. At most once per probe interval the tick dials ONE uniformly
//! random unconnected member through the ordinary maintenance dial
//! path. The interval bracket alone bounds the probe — one dial per
//! node per five minutes, whatever the session count — and a failed
//! probe dial is recorded at debug level only: a refused or stalled
//! peer is the probe's expected outcome while a partition persists,
//! never an error condition.

use std::{
  collections::{BTreeMap, BTreeSet},
  sync::Arc,
};

use tracing::debug;

use super::{
  recovery::recovery_endpoint,
  supervisor::{Supervisor, TickState, dial_member},
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

/// Runs the degree-maintenance worker: one long-lived task that owns the
/// maintenance cadence — the tick the supervisor's select loop used to
/// await inline (audit 2026-10-09 item 3), so a slow member-table scan
/// or a stalled dial batch no longer parks control-plane reads and
/// packet admission behind it.
///
/// Overlap policy — SKIP, never queue: the worker is a single task that
/// runs each tick inline in its own loop, and the timer's
/// `MissedTickBehavior::Skip` drops every deadline that fires while a
/// tick is still running. A tick recomputes the dial plan from current
/// state (and its dials are already bounded by the in-flight counter),
/// so a skipped tick only delays the next deficit batch — queueing
/// would stack stale plans behind a slow store for no gain. Bounded
/// accounting (audit item 4's lesson): exactly one task for the node's
/// lifetime, aborted and awaited by the shutdown path.
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
    let store = self.context.store();
    let local = self.context.identity().node().clone();
    let members =
      super::recovery::known_online_member_endpoints(&self.exclusion_cache, store, &local).await?;
    let connected: BTreeSet<NodeId> = self
      .sessions
      .lock()
      .map_err(Error::session_table)?
      .iter()
      .filter(|(_, entry)| entry.alive())
      .map(|(peer, _)| peer.clone())
      .collect();
    // The cluster size includes this node; the universe map excludes it.
    let plan = crate::membership::degree::degree_plan(
      members.len().saturating_add(1),
      self.config.connection_degree(),
      connected.len(),
    );
    if plan.dial_budget == 0 {
      // Healthy at target, fully offline (recovery owns it), or nothing
      // left to reach. The healthy-at-target case with unconnected
      // members left is audit finding #1's residual boundary — neither
      // plane dials — so the low-frequency bridge probe takes over.
      return self.bridge_probe_tick(&local, &members, &connected, &plan);
    }
    // Previous tick's dials may still be in flight (dial deadline plus
    // authentication deadline exceeds one cadence): never exceed the
    // deficit with concurrent dials, or a slow mesh doubles its own
    // dial load every tick. This gate skips the whole tick when the
    // budget is already exhausted; the spawn loop below re-checks per
    // spawn, because a PARTIALLY free budget must not overshoot either
    // (audit finding #5).
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
      self.entropy.as_ref(),
    )?;
    // Per-member endpoint rotation (remaining-items list P2-5): every
    // dial of a member advances that member's OWN serial, wrapping per
    // member — the same per-member `recovery_endpoint` rotation the
    // recovery plane applies, through one shared serial map. A member
    // whose dialed endpoint is unreachable is retried on its next
    // endpoint by the next tick that selects it, regardless of which
    // members any one tick happens to select.
    for (peer, endpoints) in dials {
      // In-flight bound re-check per spawn (audit finding #5): the
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
      let Some(serial) = self.member_dial_serial(&peer) else {
        continue;
      };
      let Some(endpoint) = recovery_endpoint(&endpoints, serial) else {
        continue;
      };
      self.spawn_maintenance_dial(peer, endpoint.clone());
    }
    Ok(())
  }

  /// One bridge-probe decision for an otherwise quiescent maintenance
  /// plane (the dial budget is zero): audit finding #1's residual
  /// boundary — two sub-partitions each internally meshed at/above the
  /// degree target — never re-bridges on its own, because the deficit
  /// budget is zero and the recovery controller quiesces on any one
  /// authenticated route. The probe is deliberately slow and bounded:
  /// it fires for EVERY healthy node with at least one unconnected
  /// member — including nodes already above the target, whose surplus
  /// app-initiated sessions must not blind them to the far side of a
  /// partition — at most once per [`BRIDGE_PROBE_INTERVAL_TICKS`]
  /// eligible maintenance ticks (the interval bracket is the sole
  /// storm bound), and dials exactly ONE uniformly random unconnected
  /// member through the SAME deficit machinery (`select_degree_dials`,
  /// endpoint rotation, `spawn_maintenance_dial`). The edge lands as an
  /// ordinary caller-class maintenance edge — never recovery-class — so
  /// the recovery plane's redundant-edge pruning
  /// (`maybe_prune_recovery_edges`) never reclaims the bridge and
  /// re-splits the partition it just healed. A failed probe dial is
  /// recorded at debug level only: a refused peer is the probe's
  /// expected outcome while the partition persists, never an error.
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
    self.bridge_probe_ticks.store(
      BRIDGE_PROBE_INTERVAL_TICKS,
      std::sync::atomic::Ordering::Relaxed,
    );
    let dials = crate::membership::degree::select_degree_dials(
      1,
      local,
      members,
      connected,
      self.entropy.as_ref(),
    )?;
    // Per-member endpoint rotation, the same serial map the deficit
    // path and the recovery plane share: a multi-homed member's
    // endpoints rotate across successive probes of that member,
    // wrapping per member.
    for (peer, endpoints) in dials {
      let Some(serial) = self.member_dial_serial(&peer) else {
        continue;
      };
      let Some(endpoint) = recovery_endpoint(&endpoints, serial) else {
        continue;
      };
      debug!(
        peer = %peer.as_str(),
        endpoint = %endpoint.as_str(),
        interval_ticks = BRIDGE_PROBE_INTERVAL_TICKS,
        "degree bridge probe dial"
      );
      self.spawn_maintenance_dial(peer, endpoint.clone());
    }
    Ok(())
  }

  /// Spawns one maintenance dial in its own task: the maintenance
  /// worker never blocks on a handshake, and the in-flight slot releases
  /// when the dial resolves (success, refusal, or deadline).
  fn spawn_maintenance_dial(&self, peer: NodeId, receiver: crate::Endpoint) {
    let transport = match self.extensions.resolve_transport(&receiver.selector()) {
      Ok(transport) => transport,
      // No transport for the endpoint: the dial cannot even start; the
      // next tick picks again (possibly the same member).
      Err(error) => {
        debug!(
          peer = %peer.as_str(),
          endpoint = %receiver.as_str(),
          kind = ?error.kind(),
          "degree maintenance dial unresolvable"
        );
        return;
      }
    };
    self
      .maintenance_pending
      .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let pending = Arc::clone(&self.maintenance_pending);
    let driver = self.driver.clone();
    let sessions = self.sessions.clone();
    let packet = self.packet.clone();
    let shutdown = self.shutdown.clone();
    let connection_tasks = self.connection_tasks.clone();
    let dial_deadline = self.config.dial_deadline();
    let dial = tokio::spawn(async move {
      if let Err(error) = dial_member(
        transport,
        driver,
        sessions,
        packet,
        shutdown,
        connection_tasks,
        receiver,
        &peer,
        // Ordinary caller-class edge: the recovery plane's redundancy
        // pruning never reclaims a maintenance edge (additive-only).
        false,
        dial_deadline,
      )
      .await
      {
        debug!(
          peer = %peer.as_str(),
          kind = ?error.kind(),
          "degree maintenance dial failed"
        );
      }
      pending.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    });
    // The maintenance dial's JoinHandle joins the same tracked
    // connection-task set as the recovery dials (audit finding #19): the
    // recovery tick reaps finished handles and the shutdown path drains
    // the rest inside its bounded cooperative window, aborting only the
    // stragglers, so an in-flight maintenance handshake is owned and
    // torn down with the node instead of outliving it.
    if let Ok(mut handles) = self.connection_tasks.lock() {
      handles.push(dial);
    }
  }
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
      .map_err(Error::session_table)?
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
  use std::sync::Arc;

  use crate::runtime::supervisor::test_support::{
    self, insert_live_session, install_member, member_id, refusing_peer, silent_peer,
    supervisor_over,
  };

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
    insert_live_session(&sessions, member_id(101), ticks.entropy.as_ref());
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

  /// Endpoint-level failover for the degree plane (remaining-items list
  /// P2-5): a multi-homed member whose first endpoint is unreachable
  /// is dialed on its SECOND endpoint by the next maintenance tick —
  /// the same `recovery_endpoint` rotation the recovery plane applies,
  /// so maintenance dials no longer hammer a dead first endpoint
  /// forever. Under the old single-endpoint projection the second tick
  /// dialed the first endpoint again and the second listener never saw
  /// a connection.
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
    insert_live_session(&sessions, member_id(101), ticks.entropy.as_ref());

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

  /// The same in-flight bound for the deficit path (audit finding #5):
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
    insert_live_session(&sessions, member_id(103), ticks.entropy.as_ref());

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

  /// Audit finding #1's residual boundary: two sub-partitions each
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
      insert_live_session(&sessions, member_id(seed), ticks.entropy.as_ref());
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

  /// A03: the over-target restriction is gone. Every healthy node with
  /// unconnected members probes — a node holding surplus app-initiated
  /// sessions above `target + 1` no longer stays blind to the far side
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
    // above the old `target + slack` bound — and one unconnected member
    // (107), so the probe's uniform pick is deterministic and the
    // silent listener counts the dial.
    for seed in 101..=106 {
      insert_live_session(&sessions, member_id(seed), ticks.entropy.as_ref());
    }
    for seed in 101..=107 {
      install_member(&supervisor, &reference, seed, &[port]).await;
    }
    let view = supervisor.connection_degree_view().await.unwrap();
    assert_eq!(view.target(), 4, "k(8) = 4 from the shipped degree table");
    assert_eq!(
      view.sessions(),
      6,
      "the surplus sessions sit above the retired target + slack bound"
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

  /// A03: a failed probe dial is an expected outcome, never an error:
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
      insert_live_session(&sessions, member_id(seed), ticks.entropy.as_ref());
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
      insert_live_session(&sessions, member_id(seed), ticks.entropy.as_ref());
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
}
