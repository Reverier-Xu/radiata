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

/// The delay after the `failures`-th consecutive failed accept: the
/// first failure does not sleep (a single bad upgrade must not delay the
/// next accept), and every further failure adds one step up to the cap.
pub(super) fn accept_backoff(failures: u32) -> std::time::Duration {
  let steps = failures.saturating_sub(1).min(ACCEPT_BACKOFF_MAX_STEPS);
  ACCEPT_BACKOFF_STEP.saturating_mul(steps)
}

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
    .map_err(Error::listener_registry)?
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

#[cfg(test)]
mod accept_backoff_tests {
  use super::{ACCEPT_BACKOFF_MAX_STEPS, ACCEPT_BACKOFF_STEP, accept_backoff};

  /// The first failed accept does not sleep; the second sleeps one step
  /// and every further failure adds one step until the cap.
  #[test]
  fn the_first_failure_does_not_sleep_and_later_failures_grow_to_the_cap() {
    assert_eq!(accept_backoff(0), std::time::Duration::ZERO);
    assert_eq!(accept_backoff(1), std::time::Duration::ZERO);
    assert_eq!(accept_backoff(2), ACCEPT_BACKOFF_STEP);
    assert_eq!(accept_backoff(3), ACCEPT_BACKOFF_STEP * 2);
    assert_eq!(
      accept_backoff(ACCEPT_BACKOFF_MAX_STEPS + 1),
      ACCEPT_BACKOFF_STEP * ACCEPT_BACKOFF_MAX_STEPS
    );
    assert_eq!(
      accept_backoff(u32::MAX),
      ACCEPT_BACKOFF_STEP * ACCEPT_BACKOFF_MAX_STEPS,
      "the saturated failure count still caps"
    );
  }
}

#[cfg(test)]
mod stop_listener_tests {
  use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
  };

  use super::stop_listener;
  use crate::{ErrorKind, identity::ListenerId, runtime::supervisor::ListenerRegistry};

  /// A poisoned listener registry reports the registry's named internal
  /// error instead of a generic one: the lock-poison diagnostic stays
  /// uniform with the other shared tables.
  #[tokio::test]
  async fn stop_listener_reports_the_named_listener_registry_error_on_a_poisoned_registry() {
    let listeners: ListenerRegistry = Arc::new(Mutex::new(BTreeMap::new()));
    let poisoner = Arc::clone(&listeners);
    let _ = std::thread::spawn(move || {
      let _guard = poisoner.lock().expect("listener registry guard");
      panic!("poison the listener registry");
    })
    .join();
    let published = Arc::new(Mutex::new(Vec::new()));
    let listener = ListenerId::parse("listener-000000000000000000001").unwrap();

    let error = stop_listener(&listeners, &published, &listener)
      .await
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Internal);
    assert_eq!(error.context(), "listener registry");
  }
}
