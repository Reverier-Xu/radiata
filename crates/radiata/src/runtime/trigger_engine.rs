//! The trigger dispatch engine: one long-lived task that is the single
//! dispatch point for trigger fires. It drives the shared `sched` task
//! table (sleeping until the soonest registered time-trigger window,
//! then firing the due tick), drains the bounded fire queue the table's
//! callbacks enqueue into, and matches the live resource-change stream
//! against the event-trigger cache the evaluation pass refreshes —
//! reusing the W2-2 emit-side predicate evaluation (one matching path,
//! never a second one). Each fire admits its target through the
//! ordinary public task surface (`node.tasks().submit`), with the
//! declared overlap policy: a fire whose target already has a live
//! (non-terminal) run for the same trigger is skipped, never queued.
//!
//! Shutdown: the engine observes the incarnation's shutdown signal and
//! exits; it is one task for the node's lifetime (bounded accounting),
//! never one per fire. The `sched` runs it spawned (empty callback
//! futures) are aborted and awaited with it.
//!
//! Event-trigger delivery follows the transient change-stream contract:
//! a lagged engine warns and moves on (the predicate is a pure function
//! of the event, so there is nothing to replay), while time triggers'
//! durability rides the declaration rows — the `sched` table is rebuilt
//! from them on every incarnation, and a window missed while the node
//! was down is skipped, never replayed.

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use tokio::{sync::mpsc, task::JoinSet};

use super::task_effects::OperationDeps;
use crate::{
  LabelSet, TaskId,
  node::{EventOptions, EventReceive},
};

/// The engine's overlap bookkeeping: one live target run per trigger.
type InFlight = BTreeMap<String, TaskId>;

/// Runs the engine until the incarnation shuts down (or the fire
/// queue's senders are all gone). Before the loop, one evaluation pass
/// loads the event-trigger cache and the `sched` time-trigger table
/// immediately (the table's callbacks enqueue into the queue this loop
/// drains); a startup failure is a warn — the next controller pass
/// refreshes both halves anyway.
pub(super) async fn run_trigger_engine(
  deps: Arc<OperationDeps>, tasks: super::task_manager::TaskClient, handle: crate::NodeHandle,
  mut fires: mpsc::Receiver<crate::trigger::TriggerFire>,
  mut shutdown: tokio::sync::watch::Receiver<()>,
) {
  if let Err(error) =
    crate::trigger::evaluate_pass(deps.planes().context.store(), deps.triggers()).await
  {
    tracing::warn!(kind = ?error.kind(), "the trigger engine's startup pass failed");
  }
  let mut events = deps
    .events()
    .subscribe::<crate::ResourceChanged>(EventOptions::new());
  let mut in_flight = InFlight::new();
  let mut runs = JoinSet::new();
  loop {
    // Reap finished sched runs so the set stays bounded, then compute
    // the soonest pending window from the current table.
    while let Some(result) = runs.try_join_next() {
      if let Err(error) = result {
        tracing::warn!(%error, "a scheduled trigger run failed");
      }
    }
    let now = crate::trigger::timestamp_now();
    let next = deps.triggers().next_fire(now);
    let wait = next.map(|at| crate::trigger::wait_until(now, at));
    tokio::select! {
      _ = shutdown.changed() => break,
      // The evaluation pass changed the table: recompute the next
      // instant instead of sleeping on a stale one.
      _ = deps.triggers().changed() => {}
      _ = tokio::time::sleep(wait.unwrap_or(Duration::ZERO)), if next.is_some() => {
        let Some(scheduled_at) = next else {
          continue;
        };
        let started_at = crate::trigger::timestamp_now();
        for run in deps.triggers().fire_due(scheduled_at, started_at) {
          runs.spawn(run);
        }
      }
      fire = fires.recv() => {
        let Some(fire) = fire else {
          break;
        };
        dispatch_fire(&deps, &tasks, &handle, &mut in_flight, fire).await;
      }
      received = events.recv() => {
        match received {
          Ok(EventReceive::Item(event)) => {
            dispatch_event(&deps, &tasks, &handle, &mut in_flight, &event).await;
          }
          Ok(EventReceive::Lagged { missed }) => {
            tracing::warn!(missed, "the trigger engine lagged the change stream");
          }
          // recv never yields Empty (that is try_recv's poll-level
          // pending); the arm documents the contract instead of
          // pretending the type cannot grow.
          Ok(EventReceive::Empty) => {}
          // The engine holds an operation-deps clone (an event-hub
          // owner) for its whole lifetime, so the subscription only
          // closes with the incarnation.
          Ok(EventReceive::Closed) => break,
          Err(error) => {
            tracing::warn!(kind = ?error.kind(), "the trigger engine's subscription failed");
            break;
          }
        }
      }
    }
  }
  // The scheduled runs are empty callback futures; shutting the set
  // down only clears the table's in-flight flags.
  runs.shutdown().await;
}

/// Matches one live resource change against the cached event triggers:
/// the emit-side evaluation (`SubscriptionPredicate::admits_resource`),
/// the same conjunction the hub applies to watch subscribers.
async fn dispatch_event(
  deps: &Arc<OperationDeps>, tasks: &super::task_manager::TaskClient, handle: &crate::NodeHandle,
  in_flight: &mut InFlight, event: &crate::ResourceChanged,
) {
  for (name, trigger) in deps.triggers().event_rows() {
    if trigger
      .predicate
      .admits_resource(event.resource(), event.labels())
    {
      dispatch_fire(
        deps,
        tasks,
        handle,
        in_flight,
        crate::trigger::TriggerFire {
          trigger: name,
          source: crate::TriggerSourceKind::Event,
          target: trigger.target,
        },
      )
      .await;
    }
  }
}

/// Dispatches one fire: the overlap policy is skip (a live run for the
/// same trigger skips the fire), and the target admits through the
/// ordinary public task surface. `TriggerFired` is emitted once per
/// admitted run — a skipped or refused fire emits nothing.
async fn dispatch_fire(
  deps: &Arc<OperationDeps>, tasks: &super::task_manager::TaskClient, handle: &crate::NodeHandle,
  in_flight: &mut InFlight, fire: crate::trigger::TriggerFire,
) {
  if let Some(id) = in_flight.get(&fire.trigger) {
    match tasks.observer.table.status(id) {
      Some((_, status)) if !status.phase().is_terminal() => {
        tracing::debug!(
          trigger = %fire.trigger,
          "trigger fire skipped: the target is already in flight"
        );
        return;
      }
      _ => {
        in_flight.remove(&fire.trigger);
      }
    }
  }
  match handle
    .tasks()
    .submit(crate::CustomTaskSpec::new(
      fire.target.clone(),
      LabelSet::new(),
    ))
    .await
  {
    Ok(task) => {
      in_flight.insert(fire.trigger.clone(), task.id().clone());
      deps
        .events()
        .emit(crate::TriggerFired::new(fire.trigger, fire.source));
    }
    Err(error) => {
      tracing::warn!(
        trigger = %fire.trigger,
        kind = ?error.kind(),
        "trigger target admission failed"
      );
    }
  }
}
