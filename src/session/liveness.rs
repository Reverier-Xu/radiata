//! The session liveness policy: idle and keepalive deadlines evaluated
//! against the injected wall clock, with owned in-flight admissions
//! holding the session open up to their own deadline.

use std::{
  sync::{Arc, atomic::Ordering},
  time::Duration,
};

use tokio::sync::watch;

use super::stream::clock_seconds;
use crate::routing::forward::{PendingAck, PendingAcks};

/// Enforces the session liveness policy on host wall time:
/// a session with no authenticated traffic or owned in-flight work for the
/// idle deadline closes; a peer missing a keepalive result for the
/// keepalive deadline closes. Wall-clock rollback or freeze delays both
/// deadlines and a forward jump makes them immediately due.
pub(super) async fn liveness_observer(
  last_activity: &Arc<std::sync::atomic::AtomicU64>, pending_acks: &PendingAcks,
  clock: Arc<dyn crate::storage::receipt::WallClock>, idle_timeout: Duration,
  keepalive_interval: Duration, keepalive_timeout: Duration, ping_tx: &watch::Sender<()>,
) {
  if idle_timeout.is_zero() && keepalive_interval.is_zero() {
    // No liveness policy configured; never resolves.
    std::future::pending::<()>().await;
    return;
  }
  let tick = std::cmp::min(
    if idle_timeout.is_zero() {
      Duration::MAX
    } else {
      idle_timeout
    },
    if keepalive_interval.is_zero() {
      Duration::MAX
    } else {
      keepalive_interval
    },
  )
  .min(Duration::from_secs(1))
  .max(Duration::from_millis(10));
  let mut last_ping = 0_u64;
  loop {
    tokio::time::sleep(tick).await;
    let now = clock_seconds(clock.as_ref());
    let last = last_activity.load(Ordering::Relaxed);
    // Owned in-flight work holds the session open, but the hold-off is
    // itself deadline-bounded: once the oldest waiting admission has been
    // outstanding for a full idle deadline, a silent peer no longer
    // exempts the session from the idle close (which then fails every
    // pending admission explicitly with StreamInterrupted).
    let holds_session = pending_acks
      .lock()
      .map(|pending| {
        if pending.is_empty() {
          return false;
        }
        let oldest_wait = pending
          .values()
          .filter_map(|entry| match entry {
            PendingAck::Wait { queued_at, .. } => Some(*queued_at),
            PendingAck::Relay { .. } => None,
          })
          .min();
        match oldest_wait {
          Some(oldest) => now.saturating_sub(oldest) < idle_timeout.as_secs(),
          // Pure forwarding hops are bounded transitively by the liveness
          // policies of the sessions on both ends of the relay.
          None => true,
        }
      })
      .unwrap_or(false);
    // Idle close only when no owned in-flight work remains (or it went stale).
    if !idle_timeout.is_zero()
      && !holds_session
      && now.saturating_sub(last) >= idle_timeout.as_secs()
    {
      return;
    }
    if !keepalive_interval.is_zero()
      && last_ping != 0
      && now.saturating_sub(last_ping) >= keepalive_timeout.as_secs()
      && now.saturating_sub(last) >= keepalive_timeout.as_secs()
    {
      // The peer missed the keepalive result (no pong or traffic since the
      // ping was sent); close.
      return;
    }
    if !keepalive_interval.is_zero()
      && now.saturating_sub(last_ping) >= keepalive_interval.as_secs()
    {
      last_ping = now;
      let _ = ping_tx.send(());
    }
  }
}

#[cfg(test)]
mod liveness_tests {
  use std::{
    collections::HashMap,
    sync::{Arc, Mutex, atomic::AtomicU64},
    time::{Duration, UNIX_EPOCH},
  };

  use tokio::sync::{oneshot, watch};

  use super::{PendingAcks, liveness_observer};
  use crate::storage::contract::helpers::ManualClock;

  fn no_pending() -> PendingAcks {
    Arc::new(Mutex::new(HashMap::new()))
  }

  /// While host wall time advances normally, only sessions without
  /// authenticated traffic or owned in-flight work close after the
  /// configured idle deadline.
  #[tokio::test(start_paused = true)]
  async fn idle_closes_at_the_deadline_only_without_owned_work() {
    let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(100)));
    let last_activity = Arc::new(AtomicU64::new(100));
    let pending = no_pending();
    let (ping_tx, _) = watch::channel(());
    let handle = tokio::spawn({
      let last_activity = Arc::clone(&last_activity);
      let pending = Arc::clone(&pending);
      let clock = clock.clone();
      let ping_tx = ping_tx.clone();
      async move {
        liveness_observer(
          &last_activity,
          &pending,
          clock,
          Duration::from_secs(10),
          Duration::ZERO,
          Duration::ZERO,
          &ping_tx,
        )
        .await
      }
    });

    // Before the deadline the observer stays alive.
    clock.set(UNIX_EPOCH + Duration::from_secs(109));
    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(!handle.is_finished());

    // Owned in-flight work holds the session past the deadline.
    let held = no_pending();
    let held_handle = tokio::spawn({
      let last_activity = Arc::clone(&last_activity);
      let held = Arc::clone(&held);
      let clock = clock.clone();
      let ping_tx = ping_tx.clone();
      async move {
        liveness_observer(
          &last_activity,
          &held,
          clock,
          Duration::from_secs(10),
          Duration::ZERO,
          Duration::ZERO,
          &ping_tx,
        )
        .await
      }
    });
    clock.set(UNIX_EPOCH + Duration::from_secs(200));
    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(!held_handle.is_finished());

    // At the deadline with no work the observer resolves.
    clock.set(UNIX_EPOCH + Duration::from_secs(110));
    tokio::time::advance(Duration::from_secs(2)).await;
    handle.await.unwrap();
  }

  /// Clock rollback or freeze delays closure and a forward jump makes it
  /// immediately due.
  #[tokio::test(start_paused = true)]
  async fn idle_respects_clock_rollback_and_forward_jumps() {
    let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(100)));
    let last_activity = Arc::new(AtomicU64::new(100));
    let (ping_tx, _) = watch::channel(());
    let pending = no_pending();
    let handle = tokio::spawn({
      let last_activity = Arc::clone(&last_activity);
      let pending = Arc::clone(&pending);
      let clock = clock.clone();
      let ping_tx = ping_tx.clone();
      async move {
        liveness_observer(
          &last_activity,
          &pending,
          clock,
          Duration::from_secs(10),
          Duration::ZERO,
          Duration::ZERO,
          &ping_tx,
        )
        .await
      }
    });

    // Rollback keeps the session alive (deadline recedes).
    clock.set(UNIX_EPOCH + Duration::from_secs(50));
    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(!handle.is_finished());

    // A forward jump makes the deadline immediately due.
    clock.set(UNIX_EPOCH + Duration::from_secs(500));
    tokio::time::advance(Duration::from_secs(2)).await;
    handle.await.unwrap();
  }

  /// A peer missing the keepalive result is closed after the keepalive
  /// deadline.
  #[tokio::test(start_paused = true)]
  async fn keepalive_closes_a_peer_missing_the_result() {
    let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(1_000)));
    let last_activity = Arc::new(AtomicU64::new(1_000));
    let (ping_tx, mut ping_rx) = watch::channel(());
    let pending = no_pending();
    let handle = tokio::spawn({
      let last_activity = Arc::clone(&last_activity);
      let pending = Arc::clone(&pending);
      let clock = clock.clone();
      let ping_tx = ping_tx.clone();
      async move {
        liveness_observer(
          &last_activity,
          &pending,
          clock,
          Duration::ZERO,
          Duration::from_secs(5),
          Duration::from_secs(10),
          &ping_tx,
        )
        .await
      }
    });

    // After the keepalive interval a ping fires.
    clock.set(UNIX_EPOCH + Duration::from_secs(1_005));
    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(ping_rx.changed().await.is_ok());

    // The peer never answers: after the keepalive timeout the observer
    // resolves (session closes).
    clock.set(UNIX_EPOCH + Duration::from_secs(1_015));
    tokio::time::advance(Duration::from_secs(2)).await;
    handle.await.unwrap();
  }

  /// The owned-work hold-off is itself deadline-bounded — a waiting
  /// admission older than the idle deadline no longer exempts the
  /// session, so a peer that never acknowledges cannot hold it open
  /// forever.
  #[tokio::test(start_paused = true)]
  async fn stale_owned_work_no_longer_blocks_the_idle_close() {
    let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(100)));
    let last_activity = Arc::new(AtomicU64::new(100));
    let pending = no_pending();
    {
      let (notify, _wait) = oneshot::channel();
      pending.lock().unwrap().insert(
        crate::TraceId::parse("trace-000000000000000000001").unwrap(),
        super::PendingAck::Wait {
          notify,
          queued_at: 100,
        },
      );
    }
    let (ping_tx, _) = watch::channel(());
    let handle = tokio::spawn({
      let last_activity = Arc::clone(&last_activity);
      let pending = Arc::clone(&pending);
      let clock = clock.clone();
      let ping_tx = ping_tx.clone();
      async move {
        liveness_observer(
          &last_activity,
          &pending,
          clock,
          Duration::from_secs(10),
          Duration::ZERO,
          Duration::ZERO,
          &ping_tx,
        )
        .await
      }
    });

    // Fresh owned work still holds the session open.
    clock.set(UNIX_EPOCH + Duration::from_secs(109));
    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(!handle.is_finished());

    // Once the oldest waiting admission is a full idle deadline old, the
    // hold-off expires and the idle close proceeds.
    clock.set(UNIX_EPOCH + Duration::from_secs(110));
    tokio::time::advance(Duration::from_secs(2)).await;
    handle.await.unwrap();
  }
}
