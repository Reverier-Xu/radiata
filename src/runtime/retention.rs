//! The tick-driven retention sweeps: durable route-trace records,
//! resource removal evidence, anchored receipts, the collected identity
//! tombstones, and the trigger evaluation pass. Every pass is bounded by
//! the host wall clock (or by its own record batch), tolerates failure as
//! a warning (the next tick retries), and touches core metadata only.
//!
//! On an incarnation with a task manager (production always), each pass
//! runs as a core-owned controller task on the
//! `CustomTaskSpec`/`TaskReconciler` machinery: its own slot class (see
//! [`crate::task::SlotClass::Controller`]), a bounded observable task record
//! per pass, and the shutdown drain honors the declared policy (the controllers
//! are idempotent observations, so they declare cancellable and the next tick
//! retries). The engines themselves are unchanged — the same functions, the
//! same gate, so the swept and retained sets are identical to the inline
//! predecessor. A fixture-built supervisor without a manager runs the
//! same bodies inline.

use std::sync::atomic::{AtomicUsize, Ordering};

use super::supervisor::TickState;
use crate::{Error, Result, TaskKind, api::Entropy, storage::MetadataStore, task::TaskPhase};

/// Runs one controller pass through the task machinery: skip while the
/// previous pass of the kind still holds a slot (the overlap policy —
/// skip, never queue), admit the controller task, and await its terminal
/// phase so the tick's own sequencing matches the inline predecessor. A
/// failed pass is a warn; the next tick retries.
async fn run_controller_task(tasks: &super::task_manager::TaskClient, kind: TaskKind) {
  if tasks.observer.table.has_non_terminal(&kind) {
    return;
  }
  let admission = super::task_effects::admit_core_controller(tasks, kind.clone()).await;
  let task = match admission {
    Ok(task) => task,
    Err(error) => {
      log_controller_error(&kind, "admission failed", &error);
      return;
    }
  };
  let record = tasks.observer.await_terminal(task.id()).await;
  match record {
    Ok(record) if record.phase == TaskPhase::Failed => {
      let context = record
        .error
        .map(|error| error.as_str().to_owned())
        .unwrap_or_default();
      tracing::warn!(task = %kind, context, "controller pass failed");
    }
    Ok(_) => {}
    Err(error) => log_controller_error(&kind, "controller wait failed", &error),
  }
}

fn log_controller_error(kind: &TaskKind, message: &'static str, error: &Error) {
  if error.kind() == crate::ErrorKind::ShuttingDown {
    tracing::debug!(task = %kind, kind = ?error.kind(), message);
  } else {
    tracing::warn!(task = %kind, kind = ?error.kind(), message);
  }
}

/// One host-wall-clock retention pass over the durable route-trace
/// records: terminal records expire at their configured deadline and the
/// terminal population stays within the caller-selected cap; active
/// records are never removed. Skipped while no durable record exists.
impl TickState {
  pub(super) async fn trace_retention_sweep(&self) {
    if let Some(tasks) = self.tasks() {
      run_controller_task(tasks, TaskKind::TRACE_RETENTION).await;
      return;
    }
    let live = self.trace_records.clone();
    let limits = self.config().trace_metadata_limits();
    if let Err(error) = sweep_trace_records(
      self.context().store(),
      self.entropy().as_ref(),
      &live,
      limits.terminal(),
      limits.retention(),
    )
    .await
    {
      tracing::warn!(kind = ?error.kind(), "trace retention sweep failed");
    }
  }

  /// One host-wall-clock retention pass over the resource removal
  /// evidence: expired and excess signed removal records leave
  /// by exact conditional deletes that never dereference a resource URI
  /// or touch caller data; live resource metadata is never evicted. The
  /// window and cap are the caller's configured policy — the same window
  /// the reconcile plane reads as its reclaimed-knowledge basis.
  pub(super) async fn resource_removal_sweep(&self) {
    if let Some(tasks) = self.tasks() {
      run_controller_task(tasks, TaskKind::RESOURCE_REMOVAL_RETENTION).await;
      return;
    }
    if let Err(error) = sweep_resource_removals(
      self.context().store(),
      self.config().resource_removal_retention(),
      self.config().resource_removal_cap(),
    )
    .await
    {
      tracing::warn!(kind = ?error.kind(), "resource removal sweep failed");
    }
  }

  /// One host-wall-clock retention pass over the anchored receipts: every
  /// receipt past its configured retention deadline is forgotten through
  /// the cleanup state machine, so the `receipt_retention` knob has an
  /// automatic driver alongside the explicit command. A failure (store
  /// outage, frozen reconciliation) never panics the tick: it surfaces as
  /// a warning and the next bounded pass retries.
  pub(super) async fn receipt_retention_sweep(&self) {
    if let Some(tasks) = self.tasks() {
      run_controller_task(tasks, TaskKind::RECEIPT_RETENTION).await;
      return;
    }
    if let Err(error) = sweep_receipts(self.context().store()).await {
      tracing::warn!(kind = ?error.kind(), "receipt retention sweep failed");
    }
  }

  /// One bounded identity-tombstone GC pass, run by the generic sweep
  /// engine: every row the catalog declares checkpoint-collected (the
  /// leave and cleanup tombstones) at or before the local
  /// cleanup-checkpoint watermark leaves, together with the bindings it
  /// pins where the families declare the retirement. The checkpoint is
  /// the pass's gate — a node that never issued or received one has no
  /// eligible watermark, so the sweep stays off the tick entirely instead
  /// of running empty scans. The pass itself is bounded by its record
  /// batch; a failure (store outage, frozen slot) surfaces as a warning
  /// and the next tick retries.
  pub(super) async fn collected_tombstone_sweep(&self) {
    if let Some(tasks) = self.tasks() {
      run_controller_task(tasks, TaskKind::TOMBSTONE_COLLECTION).await;
      return;
    }
    if let Err(error) =
      sweep_collected_tombstones(self.context().store(), self.entropy().as_ref()).await
    {
      tracing::warn!(kind = ?error.kind(), "tombstone gc sweep failed");
    }
  }

  /// One trigger evaluation pass: the durable trigger rows are scanned,
  /// due time triggers coalesce to one fire each, and the event-trigger
  /// cache is refreshed. The pass's engine lives in `crate::trigger`;
  /// the routing here is the same controller-vs-inline split as the
  /// retention sweeps.
  pub(super) async fn trigger_evaluation_sweep(&self) {
    if let Some(tasks) = self.tasks() {
      run_controller_task(tasks, TaskKind::TRIGGER_EVALUATION).await;
      return;
    }
    if let Err(error) = crate::trigger::evaluate_pass(
      self.context().store(),
      self.entropy().as_ref(),
      &self.operations.triggers().clone(),
    )
    .await
    {
      tracing::warn!(kind = ?error.kind(), "trigger evaluation pass failed");
    }
  }
}

/// The trace-retention engine, shared by the controller effect and the
/// inline fixture path: one bounded sweep over the durable route-trace
/// records, decrementing the sink's live-record counter by the removed
/// population. Skipped while no durable record exists.
pub(super) async fn sweep_trace_records(
  store: &MetadataStore, entropy: &dyn Entropy, live: &AtomicUsize, terminal: usize,
  retention: std::time::Duration,
) -> Result<()> {
  if live.load(Ordering::Relaxed) == 0 {
    return Ok(());
  }
  match crate::routing::trace::sweep(
    store,
    entropy,
    &crate::time::HostWallClock,
    terminal,
    retention,
  )
  .await
  {
    Ok(removed) => {
      let _ = live.try_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
        Some(count.saturating_sub(removed))
      });
      Ok(())
    }
    Err(error) => Err(error),
  }
}

/// The resource-removal-retention engine, shared by the controller effect
/// and the inline fixture path.
pub(super) async fn sweep_resource_removals(
  store: &MetadataStore, retention: std::time::Duration, cap: usize,
) -> Result<()> {
  crate::resource::retention::sweep_removed_ctx(store, &crate::time::HostWallClock, retention, cap)
    .await
    .map(|_| ())
}

/// The receipt-retention engine, shared by the controller effect and the
/// inline fixture path.
pub(super) async fn sweep_receipts(store: &MetadataStore) -> Result<()> {
  store.apply_receipt_retention().await.map(|_| ())
}

/// The checkpoint-gated tombstone-collection engine, shared by the
/// controller effect and the inline fixture path: without an eligible
/// watermark the pass is a no-op (the gate), with one the bounded sweep
/// engine collects.
pub(super) async fn sweep_collected_tombstones(
  store: &MetadataStore, entropy: &dyn Entropy,
) -> Result<()> {
  match crate::identity::cleanup::latest_checkpoint_millis_ctx(store).await {
    Ok(Some(watermark)) => {
      crate::identity::sweep::collect_checkpoint_watermark_ctx(store, entropy, watermark)
        .await
        .map(|_| ())
    }
    Ok(None) => Ok(()),
    Err(error) => Err(error),
  }
}
