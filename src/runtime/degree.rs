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
//! selected member carries ALL of its published endpoints: the dial
//! rotates through them across successive ticks with the same
//! endpoint-level failover the recovery plane applies (remaining-items
//! list P2-5), so a multi-homed member whose first endpoint is
//! unreachable is retried on the others.

use std::{collections::BTreeSet, sync::Arc};

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
  /// in detached tasks (each bounded by the configured dial deadline
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
      // Healthy, fully offline (recovery owns it), or nothing to reach.
      return Ok(());
    }
    // Previous tick's dials may still be in flight (dial deadline plus
    // authentication deadline exceeds one cadence): never exceed the
    // deficit with concurrent dials, or a slow mesh doubles its own
    // dial load every tick.
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
    // One attempt serial per dialing tick: every selected member's
    // published endpoints rotate by it (remaining-items list P2-5), the
    // same `recovery_endpoint` rotation the recovery plane applies to
    // its own dials. Like recovery, the rotation advances across
    // ATTEMPTS (ticks), not within one batch: a member whose dialed
    // endpoint is unreachable is retried on its next endpoint by the
    // next tick that selects it. A member skipped for a few ticks may
    // land past an endpoint when reselected — acceptable for this
    // best-effort plane, whose only contract is covering the deficit,
    // while the recovery plane's per-schedule rotation stays the
    // guaranteed failover for an isolated node.
    let attempt = self
      .degree_attempt
      .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
      + 1;
    for (peer, endpoints) in dials {
      let Some(endpoint) = recovery_endpoint(&endpoints, attempt) else {
        continue;
      };
      self.spawn_maintenance_dial(peer, endpoint.clone());
    }
    Ok(())
  }

  /// Spawns one detached maintenance dial: the maintenance worker never
  /// blocks on a handshake, and the in-flight slot releases when the
  /// dial resolves (success, refusal, or deadline).
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
    self, insert_live_session, install_member, member_id, silent_peer, supervisor_over,
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
