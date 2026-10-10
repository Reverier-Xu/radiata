//! The tick-driven retention sweeps: durable route-trace records,
//! resource removal evidence, and anchored receipts. Every pass is
//! bounded by the host wall clock, tolerates failure as a warning (the
//! next tick retries), and touches core metadata only. The passes run
//! on the recovery worker after each recovery tick (see
//! `runtime/recovery.rs`), never inline in the supervisor's select
//! loop (audit 2026-10-09 item 3).

use super::supervisor::TickState;

impl TickState {
  /// One host-wall-clock retention pass over the durable route-trace
  /// records: terminal records expire at their configured deadline and the
  /// terminal population stays within the caller-selected cap; active
  /// records are never removed. Skipped while no durable record exists.
  pub(super) async fn trace_retention_sweep(&self) {
    if self
      .trace_records
      .load(std::sync::atomic::Ordering::Relaxed)
      == 0
    {
      return;
    }
    let limits = self.config.trace_metadata_limits();
    match crate::routing::trace::sweep(
      self.context.store(),
      self.entropy.as_ref(),
      &crate::time::HostWallClock,
      limits.terminal(),
      limits.retention(),
    )
    .await
    {
      Ok(removed) => {
        self
          .trace_records
          .try_update(
            std::sync::atomic::Ordering::Relaxed,
            std::sync::atomic::Ordering::Relaxed,
            |live| Some(live.saturating_sub(removed)),
          )
          .ok();
      }
      Err(error) => {
        tracing::warn!(kind = ?error.kind(), "trace retention sweep failed");
      }
    }
  }

  /// One host-wall-clock retention pass over the resource removal
  /// evidence: expired and excess signed removal records leave
  /// by exact conditional deletes that never dereference a resource URI
  /// or touch caller data; live resource metadata is never evicted.
  pub(super) async fn resource_removal_sweep(&self) {
    if let Err(error) = crate::resource::retention::sweep_removed_ctx(
      self.context.store(),
      &crate::time::HostWallClock,
      crate::resource::retention::RESOURCE_REMOVAL_RETENTION,
      crate::resource::retention::RESOURCE_REGISTER_CAP,
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
    if let Err(error) = self.context.store().apply_receipt_retention().await {
      tracing::warn!(kind = ?error.kind(), "receipt retention sweep failed");
    }
  }
}
