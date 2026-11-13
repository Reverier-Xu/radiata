//! The anti-entropy subsystem: the sync driver that runs the membership
//! maintenance tick and the reconciliation plane over every authenticated
//! session on the configured `sched` cadence, plus the on-demand round
//! requests that run the identical round for deterministic convergence
//! checks.

use std::sync::Arc;

use crate::{Endpoint, identity::lifecycle::LocalIdentityContext};

/// Spawns the anti-entropy sync driver: every scheduled tick runs the
/// membership maintenance (local descriptor publication) and drives the
/// reconciliation plane (priming, epoch-driven local changes, the
/// cadence root exchange, and the backlog drain across every reconciled
/// lane). The plane's dispatches are fire-and-forget under the
/// admission-ack discipline, so a failure is diagnostics only — the next
/// root exchange re-drives.
///
/// The cadence is the caller's `sched` expression (forwarded as
/// written); a tick whose previous body is still in flight is skipped,
/// and a stale tick is skipped, never replayed. On-demand rounds share
/// the same single loop, so a scheduled round and a requested round never
/// run concurrently.
#[allow(clippy::too_many_arguments)]
pub(super) fn spawn_sync_driver(
  context: &Arc<LocalIdentityContext>, entropy: Arc<dyn crate::api::Entropy>,
  runtime: crate::runtime::RuntimeClient,
  published_endpoints: Arc<std::sync::Mutex<Vec<Endpoint>>>, schedule: &str,
  shutdown: tokio::sync::watch::Receiver<()>,
  mut round_requests: tokio::sync::mpsc::Receiver<tokio::sync::oneshot::Sender<()>>,
  events: Arc<crate::node::EventHub>, revision: crate::node::MemberRevisionSignal,
  reconcile: Option<crate::reconcile::plane::ReconcilePlane>,
) -> tokio::task::JoinHandle<()> {
  let driver_context = Arc::clone(context);
  let driver_entropy = entropy;
  let driver_runtime = runtime;
  let driver_endpoints = published_endpoints;
  let driver_events = events;
  let driver_revision = revision;
  let driver_reconcile = reconcile;
  let driver_schedule = schedule.to_owned();
  let mut driver_shutdown = shutdown;
  tokio::spawn(async move {
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

    // The scheduled body: clone the shared handles per run, snapshot the
    // published endpoints, and dispatch one round.
    let body_context = Arc::clone(&driver_context);
    let body_entropy = Arc::clone(&driver_entropy);
    let body_runtime = driver_runtime.clone();
    let body_endpoints = Arc::clone(&driver_endpoints);
    let body_events = Arc::clone(&driver_events);
    let body_revision = driver_revision.clone();
    let body_reconcile = driver_reconcile.clone();
    let body = move || {
      let context = Arc::clone(&body_context);
      let entropy = Arc::clone(&body_entropy);
      let runtime = body_runtime.clone();
      let endpoints = Arc::clone(&body_endpoints);
      let events = Arc::clone(&body_events);
      let revision = body_revision.clone();
      let reconcile = body_reconcile.clone();
      async move {
        let endpoints: Vec<Endpoint> = endpoints
          .lock()
          .map(|endpoints| endpoints.clone())
          .unwrap_or_default();
        dispatch_round(
          &context,
          &entropy,
          &runtime,
          &endpoints,
          &events,
          &revision,
          reconcile.as_ref(),
        )
        .await;
      }
    };
    let mut trigger = sched::Trigger::new();
    if let Err(error) = trigger.register_at(
      crate::trigger::timestamp_now(),
      &driver_schedule,
      move |_scheduled_at| body(),
    ) {
      tracing::error!(
        %error,
        schedule = %driver_schedule,
        "the anti-entropy cadence registration failed"
      );
      return;
    }
    loop {
      let now = crate::trigger::timestamp_now();
      let next = trigger.next(now);
      let wait = next.map(|at| crate::trigger::wait_until(now, at));
      tokio::select! {
        changed = driver_shutdown.changed() => {
          let _ = changed;
          break;
        }
        _ = tokio::time::sleep(wait.unwrap_or(std::time::Duration::ZERO)), if next.is_some() => {
          let Some(scheduled_at) = next else {
            continue;
          };
          let started_at = crate::trigger::timestamp_now();
          // Run the scheduled round inline: the on-demand round and the
          // scheduled round share one serialized loop, never overlap.
          for run in trigger.fire_due(scheduled_at, started_at) {
            run.await;
          }
        }
        // The RunSyncRound command's deterministic round: identical work
        // to a wall-clock tick, but the caller awaits its completion, so
        // convergence checks need no cadence sleeps.
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
