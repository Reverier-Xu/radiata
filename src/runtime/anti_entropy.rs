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
    async fn run_round(
      context: &Arc<LocalIdentityContext>, entropy: &Arc<dyn crate::api::Entropy>,
      sessions: &crate::session::stream::SessionTable, runtime: &crate::runtime::RuntimeClient,
      endpoints: &[Endpoint], sync_cursor: &mut crate::membership::sync::MembershipSyncCursors,
      resource_cursor: &mut crate::resource::sync::ResourceSyncCursors,
      events: &Arc<crate::node::EventHub>, revision: &crate::node::MemberRevisionSignal,
    ) {
      if let Err(error) = crate::membership::sync::sync_tick(
        context,
        entropy,
        sessions,
        runtime,
        endpoints,
        sync_cursor,
        events,
        revision,
      )
      .await
      {
        // Persistent anti-entropy failure must stay visible in
        // diagnostics; the next tick retries regardless.
        tracing::warn!(kind = ?error.kind(), "membership sync tick failed");
      }
      if let Err(error) = crate::resource::sync::resource_sync_tick(
        context,
        entropy,
        sessions,
        runtime,
        resource_cursor,
      )
      .await
      {
        tracing::warn!(kind = ?error.kind(), "resource sync tick failed");
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
          run_round(
            &driver_context,
            &driver_entropy,
            &driver_sessions,
            &driver_runtime,
            &endpoints,
            &mut sync_cursor,
            &mut resource_cursor,
            &driver_events,
            &driver_revision,
          )
          .await;
        }
        // The RunSyncRound command's deterministic round: identical work
        // to a wall-clock tick, but the caller awaits its completion, so
        // convergence checks need no interval-cadence sleeps.
        round = round_requests.recv() => {
          let reply = round;
          let endpoints: Vec<Endpoint> = driver_endpoints
            .lock()
            .map(|endpoints| endpoints.clone())
            .unwrap_or_default();
          run_round(
            &driver_context,
            &driver_entropy,
            &driver_sessions,
            &driver_runtime,
            &endpoints,
            &mut sync_cursor,
            &mut resource_cursor,
            &driver_events,
            &driver_revision,
          )
          .await;
          if let Some(reply) = reply {
            let _ = reply.send(());
          }
        }
      }
    }
  })
}
