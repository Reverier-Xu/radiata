//! The runtime's internal sched-driven cadences.
//!
//! One `sched::Trigger` table per worker, driven by the host wall clock.
//! The crate's stance is unconditional trust in that clock, so the
//! driver reads [`crate::trigger::timestamp_now`] and hands the
//! expression to `sched` as written; no interval conversion happens in
//! radiata.
//!
//! The worker body runs inline in the driver loop (the old interval
//! workers' shape): a slow pass delays the next tick, and a tick that is
//! already stale at dispatch time is skipped, never replayed — the same
//! policy the user time triggers get. The first pass is the next
//! scheduled tick, never an extra startup run.

use std::{future::Future, time::Duration};

use tokio::sync::watch;

/// Runs `body` on the `expression` schedule until `shutdown` fires.
///
/// The first occurrence is computed at registration from the host wall
/// clock. A registration failure (an unparsable expression or an
/// unresolvable zone) is an error log and disables the worker: internal
/// expressions are constants or validated config, so this is a
/// programming/configuration failure, never a transient one.
pub(super) async fn run<F, Fut>(expression: &str, mut shutdown: watch::Receiver<()>, mut body: F)
where
  F: FnMut() -> Fut + Send + 'static,
  Fut: Future<Output = ()> + Send + 'static, {
  let mut trigger = sched::Trigger::new();
  if let Err(error) = trigger.register_at(
    crate::trigger::timestamp_now(),
    expression,
    move |_scheduled_at| body(),
  ) {
    tracing::error!(
      %error,
      schedule = expression,
      "internal cadence registration failed"
    );
    return;
  }
  loop {
    let now = crate::trigger::timestamp_now();
    let next = trigger.next(now);
    let wait = next.map(|at| crate::trigger::wait_until(now, at));
    tokio::select! {
      _ = shutdown.changed() => break,
      _ = tokio::time::sleep(wait.unwrap_or(Duration::ZERO)), if next.is_some() => {
        let Some(scheduled_at) = next else {
          continue;
        };
        let started_at = crate::trigger::timestamp_now();
        // Run the body inline: the old interval workers serialized the
        // pass with their loop, and a slow pass must delay (and let
        // `sched` skip) the next tick, never overlap it.
        for run in trigger.fire_due(scheduled_at, started_at) {
          run.await;
        }
      }
    }
  }
}
