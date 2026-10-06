//! The anti-entropy subsystem: the sync driver that runs the membership
//! maintenance tick and the reconciliation plane over every authenticated
//! session on the configured interval, plus the on-demand round requests
//! that run the identical round for deterministic convergence checks.

use std::sync::Arc;

use crate::{Endpoint, identity::lifecycle::LocalIdentityContext};

/// Spawns the anti-entropy sync driver: every tick runs the membership
/// maintenance (local descriptor publication, issuer snapshot refresh,
/// checkpoint GC) and drives the reconciliation plane (priming,
/// epoch-driven local changes, the cadence root exchange, and the
/// backlog drain across every reconciled lane). The plane's dispatches
/// are fire-and-forget under the admission-ack discipline, so a failure
/// is diagnostics only — the next root exchange re-drives.
#[allow(clippy::too_many_arguments)]
pub(super) fn spawn_sync_driver(
  context: &Arc<LocalIdentityContext>, entropy: Arc<dyn crate::api::Entropy>,
  runtime: crate::runtime::RuntimeClient,
  published_endpoints: Arc<std::sync::Mutex<Vec<Endpoint>>>, interval: std::time::Duration,
  shutdown: tokio::sync::watch::Receiver<()>,
  mut round_requests: tokio::sync::mpsc::Receiver<tokio::sync::oneshot::Sender<()>>,
  events: Arc<crate::node::EventHub>, revision: crate::node::MemberRevisionSignal,
  reconcile: Option<crate::reconcile::plane::ReconcilePlane>,
) -> tokio::task::JoinHandle<()> {
  let driver_context = Arc::clone(context);
  let driver_entropy = entropy;
  let driver_runtime = runtime;
  let driver_endpoints = published_endpoints;
  let mut driver_shutdown = shutdown;
  let driver_events = events;
  let driver_revision = revision;
  let driver_reconcile = reconcile;
  tokio::spawn(async move {
    let mut timer = tokio::time::interval(interval);
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Dispatches one full round: the membership maintenance tick, then
    // the reconciliation plane's tick.
    #[allow(clippy::too_many_arguments)]
    async fn dispatch_round(
      context: &Arc<LocalIdentityContext>, entropy: &Arc<dyn crate::api::Entropy>,
      runtime: &crate::runtime::RuntimeClient, endpoints: &[Endpoint],
      events: &Arc<crate::node::EventHub>, revision: &crate::node::MemberRevisionSignal,
      reconcile: Option<&crate::reconcile::plane::ReconcilePlane>,
    ) {
      if let Err(error) = crate::membership::sync::membership_maintenance_tick(
        context, entropy, endpoints, events, revision,
      )
      .await
      {
        tracing::warn!(kind = ?error.kind(), "membership maintenance tick failed");
      }
      // A driver spawned without a plane (the supervisor always passes
      // one) runs the maintenance alone.
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
          let endpoints: Vec<Endpoint> = driver_endpoints
            .lock()
            .map(|endpoints| endpoints.clone())
            .unwrap_or_default();
          dispatch_round(
            &driver_context,
            &driver_entropy,
            &driver_runtime,
            &endpoints,
            &driver_events,
            &driver_revision,
            driver_reconcile.as_ref(),
          )
          .await;
        }
        // The RunSyncRound command's deterministic round: identical work
        // to a wall-clock tick, but the caller awaits its completion, so
        // convergence checks need no interval-cadence sleeps.
        Some(round) = round_requests.recv() => {
          let endpoints: Vec<Endpoint> = driver_endpoints
            .lock()
            .map(|endpoints| endpoints.clone())
            .unwrap_or_default();
          dispatch_round(
            &driver_context,
            &driver_entropy,
            &driver_runtime,
            &endpoints,
            &driver_events,
            &driver_revision,
            driver_reconcile.as_ref(),
          )
          .await;
          let _ = round.send(());
        }
      }
    }
  })
}
