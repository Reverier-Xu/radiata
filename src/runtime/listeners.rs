//! The listener plane: binding advertised endpoints, the bounded-backoff
//! accept loop's backoff constants, and the shared teardown used by the
//! stop-listener effect and the leave teardown. The listen effect itself
//! lives in [`super::task_effects`] (`reconcile_listen`); both mutate the
//! one shared listener registry.

use super::supervisor::ListenerRegistry;
use crate::{Endpoint, Error, Result};

/// The accept-loop backoff: every consecutive failed upgrade delays the
/// next accept by one step, capped at `ACCEPT_BACKOFF_MAX_STEPS` steps,
/// so a persistently broken accept cannot spin hot; one success clears
/// the backoff. A single failed upgrade still costs nothing (the delay
/// applies only from the second consecutive failure on).
pub(super) const ACCEPT_BACKOFF_STEP: std::time::Duration = std::time::Duration::from_millis(100);
pub(super) const ACCEPT_BACKOFF_MAX_STEPS: u32 = 5;

/// Tears one bound listener down: removes the registry entry, wakes and
/// aborts the accept loop, and unpublishes the advertised endpoint.
/// Shared by the stop-listener effect and the leave effect's network
/// teardown, so both mutate the one registry.
pub(super) async fn stop_listener(
  listeners: &ListenerRegistry,
  published_endpoints: &std::sync::Arc<std::sync::Mutex<Vec<Endpoint>>>,
  listener: &crate::identity::ListenerId,
) -> Result<()> {
  let removed = listeners
    .lock()
    .map_err(|_| Error::internal("listener registry"))?
    .remove(listener);
  let Some((endpoint, listener_handle, abort)) = removed else {
    return Err(Error::not_found("listener"));
  };
  // Close only wakes the pending accept so it observes the shutdown;
  // the address is released by dropping the listener — the removal
  // above and the aborted accept task drop the last owners, so a
  // later rebind on the same port works.
  let _ = listener_handle.close().await;
  abort.abort();
  if let Ok(mut endpoints) = published_endpoints.lock() {
    endpoints.retain(|candidate| candidate != &endpoint);
  }
  Ok(())
}
