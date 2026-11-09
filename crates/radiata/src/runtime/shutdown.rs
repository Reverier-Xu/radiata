//! The node's one shutdown sequence: the shared teardown every exit
//! path (explicit, fatal, and active-leave) runs after the supervisor's
//! control loop stops serving arms.

use tokio::{
  sync::{mpsc, oneshot},
  task::JoinSet,
};

use super::supervisor::{CONTROL_CAPACITY, LifecyclePublisher, RuntimeDependencies};
use crate::{
  ShutdownOutcome, ShutdownReason,
  runtime::{Control, LifecycleSnapshot},
};

/// The bounded cooperative window the drained connection tasks get at
/// shutdown before only the stragglers are aborted: the graceful
/// signal was already broadcast, so an in-flight consumer drain (a
/// fully received control payload mid persist-and-emit) completes
/// instead of being aborted mid-apply, while a task that never settles
/// can hold the shutdown reply no longer than this bound. Handles
/// already aborted upstream (the anti-entropy driver, the tick
/// workers, the accept loops) resolve immediately, so a quiet node's
/// shutdown stays as prompt as before.
pub(super) const CONNECTION_TASK_SHUTDOWN_GRACE: std::time::Duration =
  std::time::Duration::from_secs(3);

/// The shutdown sequence shared by the explicit, fatal, and active-leave
/// exits: the control channel closes, the task manager drains (the
/// journaled kinds run to their terminal phase), the runtime's own task
/// set tears down, and every queued shutdown reply answers with the one
/// reason.
pub(super) async fn finish_shutdown(
  mut control: mpsc::Receiver<Control>, mut tasks: JoinSet<()>,
  mut dependencies: RuntimeDependencies, drained: Vec<tokio::task::JoinHandle<()>>,
  lifecycle: &mut LifecyclePublisher, first_reply: Option<oneshot::Sender<ShutdownOutcome>>,
  reason: ShutdownReason,
) {
  lifecycle.publish(LifecycleSnapshot::shutting_down());
  control.close();

  // The task manager goes first: it stops admitting, releases every
  // cancellable effect, and awaits the journaled kinds (leave,
  // frozen-journal resolution) to their terminal phase. Only then does the
  // node's own task set shut down — the effects still need the storage and
  // session machinery this teardown releases.
  if let Some(manager) = dependencies.task_manager.take() {
    manager.begin_shutdown();
    manager.drain().await;
  }

  let mut queued_replies = Vec::with_capacity(CONTROL_CAPACITY);
  while let Ok(Control::Shutdown { reply }) = control.try_recv() {
    queued_replies.push(reply);
  }
  tasks.shutdown().await;
  // Drain the returned task teardown so every storage capture is dropped
  // before the shutdown reply returns (a restarted node on the same
  // factory must not race the release). The handles aborted upstream (the
  // anti-entropy driver, the tick workers, the accept loops) resolve
  // immediately; the live connection tasks get one shared, bounded
  // cooperative window — the graceful signal was already broadcast — so
  // an in-flight consumer drain finishes its apply, and only a task still
  // unfinished at the window's edge is aborted and reaped: a wedged task
  // can never hang the reply past the bound.
  let deadline = tokio::time::Instant::now() + CONNECTION_TASK_SHUTDOWN_GRACE;
  for mut handle in drained {
    if tokio::time::timeout_at(deadline, &mut handle)
      .await
      .is_err()
    {
      // Straggler: abort it, then reap the aborted join so its captures
      // still drop before the reply. (A handle that settled inside the
      // window was already joined by the timed poll — re-polling a
      // completed `JoinHandle` panics, so only this arm awaits again.)
      handle.abort();
      let _ = handle.await;
    }
  }
  // The storage execution completion barrier:
  // every runtime plane is torn down above, so no new execution can
  // start; the storage flush now resolves only when every detached
  // execution the node spawned has ended (committed, failed, or rolled
  // back) and every snapshot execution has released its handle — commit
  // and read alike — so the shutdown reply returns only once no
  // in-flight execution still holds the database. A still-live read
  // would otherwise pin the file lock past
  // the reply and restarts would race it. Like the task manager's journaled
  // drain, the wait is deliberately unbounded: it awaits durability
  // obligations, not cancellable effects. A flush failure is diagnosed
  // and teardown continues, because the reply itself must still answer.
  if let Some(context) = dependencies.context.as_ref()
    && let Err(error) = context.store().provider().flush().await
  {
    tracing::warn!(
      kind = ?error.kind(),
      "storage execution completion barrier failed at shutdown"
    );
  }
  drop(control);
  drop(dependencies);

  lifecycle.stop(reason);
  if let Some(reply) = first_reply {
    let _ = reply.send(ShutdownOutcome::new(reason));
  }
  for reply in queued_replies {
    let _ = reply.send(ShutdownOutcome::new(reason));
  }
}
