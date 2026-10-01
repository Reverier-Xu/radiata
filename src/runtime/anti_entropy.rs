//! The anti-entropy subsystem: the self-contained sync driver that
//! carries the membership tombstone plane and the reconciliation lanes
//! over every authenticated session on the configured interval, plus
//! the on-demand round requests that run the identical round for
//! deterministic convergence checks.

use std::sync::Arc;

use crate::{Endpoint, identity::lifecycle::LocalIdentityContext};

/// Spawns the anti-entropy membership-sync driver: it forwards the
/// removal tombstones over every authenticated session on the
/// configured interval, drives the reconciliation plane's lanes, and
/// stops on the shutdown signal (bounded work per tick).
#[allow(clippy::too_many_arguments)]
pub(super) fn spawn_sync_driver(
  context: &Arc<LocalIdentityContext>, entropy: Arc<dyn crate::api::Entropy>,
  sessions: crate::session::stream::SessionTable, runtime: crate::runtime::RuntimeClient,
  published_endpoints: Arc<std::sync::Mutex<Vec<Endpoint>>>, interval: std::time::Duration,
  shutdown: tokio::sync::watch::Receiver<()>,
  mut round_requests: tokio::sync::mpsc::Receiver<tokio::sync::oneshot::Sender<()>>,
  events: Arc<crate::node::EventHub>, revision: crate::node::MemberRevisionSignal,
  reconcile: Option<crate::reconcile::plane::ReconcilePlane>,
) -> tokio::task::JoinHandle<()> {
  let driver_context = Arc::clone(context);
  let driver_entropy = entropy;
  let driver_sessions = sessions;
  let driver_runtime = runtime;
  let driver_endpoints = published_endpoints;
  let mut driver_shutdown = shutdown;
  let driver_events = events;
  let driver_revision = revision;
  let driver_reconcile = reconcile;
  tokio::spawn(async move {
    let mut timer = tokio::time::interval(interval);
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut sync_cursor = crate::membership::sync::MembershipSyncCursors::default();
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
    let mut pending_sync: Vec<SyncPending> = Vec::new();
    // Applies every round's verdict effects whose settlement resolved.
    // With `settle_all` the wait blocks until each does (the
    // deterministic seam: a requested round must leave settled cursor
    // state). Unsettled rounds stay queued: a later dispatch NEVER
    // overwrites them — a dropped settlement would strand its window
    // entries at `delivered = None` forever, permanently stalling those
    // peers.
    async fn harvest_sync(
      pending: &mut Vec<SyncPending>, cursors: &mut crate::membership::sync::MembershipSyncCursors,
      settle_all: bool,
    ) {
      let mut remaining = Vec::new();
      for (handle, in_flight) in pending.drain(..) {
        if !settle_all && !handle.is_finished() {
          remaining.push((handle, in_flight));
          continue;
        }
        match handle.await {
          Ok(effects) => crate::membership::sync::apply_round_effects(cursors, effects),
          Err(error) => {
            tracing::warn!(error = %error, "membership round settlement failed");
          }
        }
      }
      *pending = remaining;
    }
    // Dispatches one full round for both planes against the current
    // cursors and in-flight sets, and queues each plane's unsettled
    // verdicts (spawned, so the next tick harvests them without
    // blocking this one).
    #[allow(clippy::too_many_arguments)]
    async fn dispatch_rounds(
      context: &Arc<LocalIdentityContext>, entropy: &Arc<dyn crate::api::Entropy>,
      sessions: &crate::session::stream::SessionTable, runtime: &crate::runtime::RuntimeClient,
      endpoints: &[Endpoint], sync_cursor: &mut crate::membership::sync::MembershipSyncCursors,
      pending_sync: &mut Vec<SyncPending>, events: &Arc<crate::node::EventHub>,
      revision: &crate::node::MemberRevisionSignal,
      reconcile: Option<&crate::reconcile::plane::ReconcilePlane>,
    ) {
      // The skip set is the union over every unsettled round: a peer
      // with an in-flight tombstone dispatch skips its round regardless
      // of which round dispatched it.
      let mut sync_in_flight = crate::membership::sync::InFlightRounds::new();
      for (_, in_flight) in pending_sync.iter() {
        sync_in_flight.extend(in_flight.iter().cloned());
      }
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
          pending_sync.push((tokio::spawn(pending.settle()), in_flight));
        }
        Ok(None) => {}
        // Persistent anti-entropy failure must stay visible in
        // diagnostics; the next tick retries regardless.
        Err(error) => tracing::warn!(kind = ?error.kind(), "membership sync tick failed"),
      }
      // The reconciliation plane's tick: the migrated lanes ride it
      // (priming, epoch-driven local changes, the cadence root
      // exchange, and the backlog drain). Its dispatches are
      // fire-and-forget under the admission-ack discipline, so a
      // failure is diagnostics only — the next root exchange re-drives.
      // A driver spawned without a plane (the supervisor always passes
      // one) simply runs the watermark lanes alone.
      if let Some(reconcile) = reconcile
        && let Err(error) = reconcile.tick(runtime).await
      {
        tracing::warn!(kind = ?error.kind(), "reconcile tick failed");
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
            &mut pending_sync,
            &driver_events,
            &driver_revision,
            driver_reconcile.as_ref(),
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
            &mut pending_sync,
            &driver_events,
            &driver_revision,
            driver_reconcile.as_ref(),
          )
          .await;
          // Settle this round's verdicts inline: the requested round's
          // effects must be visible when the command returns.
          harvest_sync(&mut pending_sync, &mut sync_cursor, true).await;
          let _ = round.send(());
        }
      }
    }
  })
}
