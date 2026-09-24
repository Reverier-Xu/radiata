//! The anti-entropy subsystem: the self-contained sync driver that pages
//! membership descriptors and resource records over every authenticated
//! session on the configured interval, plus the on-demand round requests
//! that run the identical round for deterministic convergence checks.

use std::sync::Arc;

use crate::{Endpoint, identity::lifecycle::LocalIdentityContext};

/// Spawns the anti-entropy membership-sync driver: it pages descriptors
/// and the issuer trust snapshot over every authenticated session on the
/// configured interval and stops on the shutdown signal (streams metadata
/// pages; bounded work per tick).
#[allow(clippy::too_many_arguments)]
pub(super) fn spawn_sync_driver(
  context: &Arc<LocalIdentityContext>, entropy: Arc<dyn crate::api::Entropy>,
  sessions: crate::session::stream::SessionTable, runtime: crate::runtime::RuntimeClient,
  published_endpoints: Arc<std::sync::Mutex<Vec<Endpoint>>>, interval: std::time::Duration,
  shutdown: tokio::sync::watch::Receiver<()>,
  mut round_requests: tokio::sync::mpsc::Receiver<tokio::sync::oneshot::Sender<()>>,
  events: Arc<crate::node::EventHub>, revision: crate::node::MemberRevisionSignal,
) -> tokio::task::JoinHandle<()> {
  let driver_context = Arc::clone(context);
  let driver_entropy = entropy;
  let driver_sessions = sessions;
  let driver_runtime = runtime;
  let driver_endpoints = published_endpoints;
  let mut driver_shutdown = shutdown;
  let driver_events = events;
  let driver_revision = revision;
  tokio::spawn(async move {
    let mut timer = tokio::time::interval(interval);
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut sync_cursor = crate::membership::sync::MembershipSyncCursors::default();
    let mut resource_cursor = crate::resource::sync::ResourceSyncCursors::default();
    // The previous round's unsettled delivery verdicts, per plane, with
    // the peers whose planes they hold in flight. The periodic tick
    // settles them opportunistically: resolved effects apply before the
    // next dispatch, unresolved planes skip their peers this round
    // (their cursors are neither committed nor rewound yet). This keeps
    // the tick's hold-down at the dispatch cost instead of the slowest
    // peer's ack bound, which is what made a large-mesh hub's effective
    // cadence a multiple of the ack wait.
    type SyncPending = (
      tokio::task::JoinHandle<crate::membership::sync::MembershipRoundEffects>,
      crate::membership::sync::InFlightRounds,
    );
    type ResourcePending = (
      tokio::task::JoinHandle<crate::resource::sync::ResourceRoundEffects>,
      std::collections::BTreeSet<crate::NodeId>,
    );
    let mut pending_sync: Option<SyncPending> = None;
    let mut pending_resource: Option<ResourcePending> = None;
    // Applies the previous round's verdict effects once they resolved.
    // With `settle_all` the wait blocks until they do (the deterministic
    // seam: a requested round must leave settled cursor state).
    async fn harvest_sync(
      pending: &mut Option<SyncPending>,
      cursors: &mut crate::membership::sync::MembershipSyncCursors, settle_all: bool,
    ) {
      let Some((handle, _)) = pending else { return };
      if !settle_all && !handle.is_finished() {
        return;
      }
      match handle.await {
        Ok(effects) => crate::membership::sync::apply_round_effects(cursors, effects),
        Err(error) => {
          tracing::warn!(error = %error, "membership round settlement failed");
        }
      }
      *pending = None;
    }
    async fn harvest_resource(
      pending: &mut Option<ResourcePending>,
      cursors: &mut crate::resource::sync::ResourceSyncCursors, settle_all: bool,
    ) {
      let Some((handle, _)) = pending else { return };
      if !settle_all && !handle.is_finished() {
        return;
      }
      match handle.await {
        Ok(effects) => crate::resource::sync::apply_resource_round_effects(cursors, effects),
        Err(error) => {
          tracing::warn!(error = %error, "resource round settlement failed");
        }
      }
      *pending = None;
    }
    // Dispatches one full round for both planes against the current
    // cursors and in-flight sets, and stores each plane's unsettled
    // verdicts (spawned, so the next tick harvests them without
    // blocking this one).
    #[allow(clippy::too_many_arguments)]
    async fn dispatch_rounds(
      context: &Arc<LocalIdentityContext>, entropy: &Arc<dyn crate::api::Entropy>,
      sessions: &crate::session::stream::SessionTable, runtime: &crate::runtime::RuntimeClient,
      endpoints: &[Endpoint], sync_cursor: &mut crate::membership::sync::MembershipSyncCursors,
      resource_cursor: &mut crate::resource::sync::ResourceSyncCursors,
      pending_sync: &mut Option<SyncPending>, pending_resource: &mut Option<ResourcePending>,
      events: &Arc<crate::node::EventHub>, revision: &crate::node::MemberRevisionSignal,
    ) {
      let sync_in_flight = pending_sync
        .as_ref()
        .map(|(_, in_flight)| in_flight.clone())
        .unwrap_or_default();
      let resource_in_flight = pending_resource
        .as_ref()
        .map(|(_, in_flight)| in_flight.clone())
        .unwrap_or_default();
      match crate::membership::sync::sync_tick(
        context,
        entropy,
        sessions,
        runtime,
        endpoints,
        sync_cursor,
        &sync_in_flight,
        events,
        revision,
      )
      .await
      {
        Ok(Some(pending)) => {
          let in_flight = pending.in_flight();
          *pending_sync = Some((tokio::spawn(pending.settle()), in_flight));
        }
        Ok(None) => {}
        // Persistent anti-entropy failure must stay visible in
        // diagnostics; the next tick retries regardless.
        Err(error) => tracing::warn!(kind = ?error.kind(), "membership sync tick failed"),
      }
      match crate::resource::sync::resource_sync_tick(
        context,
        entropy,
        sessions,
        runtime,
        resource_cursor,
        &resource_in_flight,
      )
      .await
      {
        Ok(Some(pending)) => {
          let in_flight = pending.in_flight();
          *pending_resource = Some((tokio::spawn(pending.settle()), in_flight));
        }
        Ok(None) => {}
        Err(error) => tracing::warn!(kind = ?error.kind(), "resource sync tick failed"),
      }
    }
    loop {
      tokio::select! {
        changed = driver_shutdown.changed() => {
          let _ = changed;
          break;
        }
        _ = timer.tick() => {
          // Opportunistic harvest: resolved verdicts apply, unresolved
          // planes skip their peers in this round's dispatch.
          harvest_sync(&mut pending_sync, &mut sync_cursor, false).await;
          harvest_resource(&mut pending_resource, &mut resource_cursor, false).await;
          let endpoints: Vec<Endpoint> = driver_endpoints
            .lock()
            .map(|endpoints| endpoints.clone())
            .unwrap_or_default();
          dispatch_rounds(
            &driver_context,
            &driver_entropy,
            &driver_sessions,
            &driver_runtime,
            &endpoints,
            &mut sync_cursor,
            &mut resource_cursor,
            &mut pending_sync,
            &mut pending_resource,
            &driver_events,
            &driver_revision,
          )
          .await;
        }
        // The RunSyncRound command's deterministic round: identical work
        // to a wall-clock tick, but the caller awaits its completion, so
        // convergence checks need no interval-cadence sleeps. Every
        // detached round settles before the reply, so the caller
        // observes settled cursor state.
        Some(round) = round_requests.recv() => {
          harvest_sync(&mut pending_sync, &mut sync_cursor, true).await;
          harvest_resource(&mut pending_resource, &mut resource_cursor, true).await;
          let endpoints: Vec<Endpoint> = driver_endpoints
            .lock()
            .map(|endpoints| endpoints.clone())
            .unwrap_or_default();
          dispatch_rounds(
            &driver_context,
            &driver_entropy,
            &driver_sessions,
            &driver_runtime,
            &endpoints,
            &mut sync_cursor,
            &mut resource_cursor,
            &mut pending_sync,
            &mut pending_resource,
            &driver_events,
            &driver_revision,
          )
          .await;
          // Settle this round's verdicts inline: the requested round's
          // effects must be visible when the command returns.
          harvest_sync(&mut pending_sync, &mut sync_cursor, true).await;
          harvest_resource(&mut pending_resource, &mut resource_cursor, true).await;
          let _ = round.send(());
        }
      }
    }
  })
}
