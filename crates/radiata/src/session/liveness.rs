//! The session liveness policy: idle and keepalive deadlines evaluated
//! against the injected wall clock, with owned in-flight admissions
//! holding the session open up to their own deadline.

use std::{
  sync::{Arc, atomic::Ordering},
  time::Duration,
};

use tokio::sync::watch;

use super::{pending::PendingAdmissions, stream::clock_seconds};

/// Enforces the session liveness policy on host wall time:
/// a session with no authenticated traffic or owned in-flight work for the
/// idle deadline closes; a peer that leaves the earliest outstanding
/// keepalive probe unanswered for the keepalive deadline closes. The
/// keepalive cadence is a bound `sched` schedule: a ping is due at each
/// scheduled wall-clock instant. Wall-clock rollback or freeze delays
/// both deadlines and a forward jump makes them immediately due.
pub(super) async fn liveness_observer(
  last_activity: &Arc<std::sync::atomic::AtomicU64>, pending_acks: &PendingAdmissions,
  clock: Arc<dyn crate::time::WallClock>, idle_timeout: Duration,
  keepalive_schedule: Option<Arc<sched::BoundSchedule>>, keepalive_timeout: Duration,
  ping_tx: &watch::Sender<()>,
) {
  if idle_timeout.is_zero() && keepalive_schedule.is_none() {
    // No liveness policy configured; never resolves.
    std::future::pending::<()>().await;
    return;
  }
  let tick = if idle_timeout.is_zero() {
    Duration::from_secs(1)
  } else {
    idle_timeout.min(Duration::from_secs(1))
  }
  .max(Duration::from_millis(10));
  // The next scheduled ping instant, in UNIX seconds. A schedule that
  // never fires again leaves this `None`: only the idle deadline can
  // close the session.
  let mut next_ping = keepalive_schedule
    .as_ref()
    .and_then(|schedule| schedule.next_after(timestamp_at(clock_seconds(clock.as_ref()))))
    .map(|zoned| timestamp_seconds(zoned.timestamp()));
  // Stamp of the earliest keepalive ping still awaiting a result. It must
  // stay separate from the send cadence: keying the deadline on the last
  // send could never leave a gap of `keepalive_timeout` between
  // consecutive stamps (the send branch runs at each scheduled instant).
  let mut probe_since: Option<u64> = None;
  loop {
    tokio::time::sleep(tick).await;
    let now = clock_seconds(clock.as_ref());
    let last = last_activity.load(Ordering::Relaxed);
    // Owned in-flight work holds the session open, but the hold-off is
    // itself deadline-bounded: once the oldest waiting admission has been
    // outstanding for a full idle deadline, a silent peer no longer
    // exempts the session from the idle close (which then fails every
    // pending admission explicitly with StreamInterrupted).
    let holds_session = if pending_acks.is_empty() {
      false
    } else {
      match pending_acks.oldest_wait() {
        Some(oldest) => now.saturating_sub(oldest) < idle_timeout.as_secs(),
        // Pure forwarding hops are bounded transitively by the liveness
        // policies of the sessions on both ends of the relay.
        None => true,
      }
    };
    // Idle close only when no owned in-flight work remains (or it went stale).
    if !idle_timeout.is_zero()
      && !holds_session
      && now.saturating_sub(last) >= idle_timeout.as_secs()
    {
      return;
    }
    // A pong or any traffic at or after the probe stamp answered it: the
    // deadline fully resets, and the next ping opens a fresh probe.
    if probe_since.is_some_and(|sent| last >= sent) {
      probe_since = None;
    }
    if probe_since.is_some_and(|sent| now.saturating_sub(sent) >= keepalive_timeout.as_secs()) {
      // The peer left the outstanding probe unanswered (no pong or traffic
      // at or after its ping) for the full keepalive deadline; close even
      // though pings keep being sent.
      return;
    }
    if next_ping.is_some_and(|due| now >= due) {
      next_ping = keepalive_schedule
        .as_ref()
        .and_then(|schedule| schedule.next_after(timestamp_at(now)))
        .map(|zoned| timestamp_seconds(zoned.timestamp()));
      // Only the first ping of an unanswered run opens a probe; later
      // pings keep the deadline anchored to that run's earliest stamp.
      probe_since.get_or_insert(now);
      let _ = ping_tx.send(());
    }
  }
}

/// The `sched` instant for one UNIX-second reading; the conversion
/// saturates at the epoch for pre-epoch readings.
fn timestamp_at(seconds: u64) -> sched::Timestamp {
  sched::Timestamp::from_second(i64::try_from(seconds).unwrap_or(i64::MAX))
    .unwrap_or(sched::Timestamp::UNIX_EPOCH)
}

/// The UNIX-second reading of a `sched` instant, saturating at the epoch.
fn timestamp_seconds(at: sched::Timestamp) -> u64 {
  u64::try_from(at.as_second()).unwrap_or(0)
}

#[cfg(test)]
mod liveness_tests {
  use std::{
    sync::{
      Arc,
      atomic::{AtomicU64, Ordering},
    },
    time::{Duration, UNIX_EPOCH},
  };

  use tokio::sync::{oneshot, watch};

  use super::liveness_observer;
  use crate::{session::pending::PendingAdmissions, storage::contract::helpers::ManualClock};

  fn no_pending() -> PendingAdmissions {
    PendingAdmissions::new(crate::session::stream::MAX_PENDING_ADMISSIONS)
  }

  /// A bound keepalive schedule firing every `step` seconds at the
  /// matching second values of every minute.
  fn keepalive_every(step: u64) -> Option<Arc<sched::BoundSchedule>> {
    let values = (0..60)
      .step_by(step as usize)
      .map(|second| format!("{second:02}"))
      .collect::<Vec<_>>()
      .join(",");
    let expression = format!("{{*}}-{{*}}-{{*}}T{{*}}:{{*}}:{{{values}}}Z");
    let schedule = sched::Schedule::parse(&expression).expect("schedule");
    Some(Arc::new(schedule.bind().expect("bind")))
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
      let pending = pending.clone();
      let clock = clock.clone();
      let ping_tx = ping_tx.clone();
      async move {
        liveness_observer(
          &last_activity,
          &pending,
          clock,
          Duration::from_secs(10),
          None,
          Duration::ZERO,
          &ping_tx,
        )
        .await
      }
    });
    tokio::task::yield_now().await;

    // Before the deadline the observer stays alive.
    clock.set(UNIX_EPOCH + Duration::from_secs(109));
    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(!handle.is_finished());

    // Owned in-flight work holds the session past the deadline.
    let held = no_pending();
    let held_handle = tokio::spawn({
      let last_activity = Arc::clone(&last_activity);
      let held = held.clone();
      let clock = clock.clone();
      let ping_tx = ping_tx.clone();
      async move {
        liveness_observer(
          &last_activity,
          &held,
          clock,
          Duration::from_secs(10),
          None,
          Duration::ZERO,
          &ping_tx,
        )
        .await
      }
    });
    tokio::task::yield_now().await;
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
      let pending = pending.clone();
      let clock = clock.clone();
      let ping_tx = ping_tx.clone();
      async move {
        liveness_observer(
          &last_activity,
          &pending,
          clock,
          Duration::from_secs(10),
          None,
          Duration::ZERO,
          &ping_tx,
        )
        .await
      }
    });
    tokio::task::yield_now().await;

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
      let pending = pending.clone();
      let clock = clock.clone();
      let ping_tx = ping_tx.clone();
      async move {
        liveness_observer(
          &last_activity,
          &pending,
          clock,
          Duration::ZERO,
          keepalive_every(5),
          Duration::from_secs(10),
          &ping_tx,
        )
        .await
      }
    });
    tokio::task::yield_now().await;

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

  /// Regression: the close deadline must key on an
  /// outstanding probe, not on the ping send cadence. With the wall clock
  /// advancing one tick at a time — no jump the send branch could hide
  /// behind — a peer that never answers must still be closed by the
  /// keepalive policy even though pings keep being sent.
  #[tokio::test(start_paused = true)]
  async fn keepalive_closes_a_silent_peer_under_continuously_advancing_time() {
    let start = UNIX_EPOCH + Duration::from_secs(1_000);
    let clock = Arc::new(ManualClock::new(start));
    let last_activity = Arc::new(AtomicU64::new(1_000));
    let (ping_tx, mut ping_rx) = watch::channel(());
    let pending = no_pending();
    let handle = tokio::spawn({
      let last_activity = Arc::clone(&last_activity);
      let pending = pending.clone();
      let clock = clock.clone();
      let ping_tx = ping_tx.clone();
      async move {
        liveness_observer(
          &last_activity,
          &pending,
          clock,
          Duration::ZERO,
          keepalive_every(5),
          Duration::from_secs(10),
          &ping_tx,
        )
        .await
      }
    });
    tokio::task::yield_now().await;

    // One-second steps with no activity at all: several full keepalive
    // intervals and timeouts pass without a single clock jump.
    let mut pings = 0_u32;
    let mut closed_at = None;
    for second in 1..=40_u64 {
      clock.set(start + Duration::from_secs(second));
      tokio::time::advance(Duration::from_secs(1)).await;
      if ping_rx.has_changed().unwrap_or(false) {
        pings += 1;
        let _ = ping_rx.borrow_and_update();
      }
      if handle.is_finished() {
        closed_at = Some(second);
        break;
      }
    }
    let closed_at = closed_at.expect("a never-answering peer must be closed");
    // The first ping fires at the first tick (second 1), so the probe
    // deadline cannot elapse before second 11.
    assert!(closed_at >= 11, "closed_at = {closed_at}");
    // The send cadence kept firing while the probe went unanswered: at
    // least the second ping (second 6) preceded the close.
    assert!(pings >= 2, "pings = {pings}");
    handle.await.unwrap();
  }

  /// An answered probe fully resets the keepalive deadline: the peer
  /// answers the first ping, then goes silent, and the close keys on the
  /// next unanswered probe — not on the first ping's stamp.
  #[tokio::test(start_paused = true)]
  async fn an_answered_probe_fully_resets_the_keepalive_deadline() {
    let start = UNIX_EPOCH + Duration::from_secs(1_000);
    let clock = Arc::new(ManualClock::new(start));
    let last_activity = Arc::new(AtomicU64::new(1_000));
    let (ping_tx, mut ping_rx) = watch::channel(());
    let pending = no_pending();
    let handle = tokio::spawn({
      let last_activity = Arc::clone(&last_activity);
      let pending = pending.clone();
      let clock = clock.clone();
      let ping_tx = ping_tx.clone();
      async move {
        liveness_observer(
          &last_activity,
          &pending,
          clock,
          Duration::ZERO,
          keepalive_every(5),
          Duration::from_secs(10),
          &ping_tx,
        )
        .await
      }
    });
    tokio::task::yield_now().await;

    // Answer only the first ping, then stay silent forever.
    let mut answered = false;
    let mut closed_at = None;
    for second in 1..=20_u64 {
      clock.set(start + Duration::from_secs(second));
      tokio::time::advance(Duration::from_secs(1)).await;
      if !answered && ping_rx.has_changed().unwrap_or(false) {
        let _ = ping_rx.borrow_and_update();
        answered = true;
        last_activity.store(1_000 + second, Ordering::Relaxed);
      }
      if handle.is_finished() {
        closed_at = Some(second);
        break;
      }
    }
    let closed_at = closed_at.expect("a peer that stops answering must close");
    // Past the first probe's deadline (second 11): the answer reset it.
    assert!(closed_at > 11, "closed_at = {closed_at}");
    // The next probe opens at the second ping (second 6), so its deadline
    // is due at second 16.
    assert!(closed_at >= 16, "closed_at = {closed_at}");
    handle.await.unwrap();
  }

  /// A peer that keeps answering every probe stays alive well past several
  /// keepalive timeouts.
  #[tokio::test(start_paused = true)]
  async fn answering_every_probe_keeps_a_responsive_peer_alive() {
    let start = UNIX_EPOCH + Duration::from_secs(1_000);
    let clock = Arc::new(ManualClock::new(start));
    let last_activity = Arc::new(AtomicU64::new(1_000));
    let (ping_tx, mut ping_rx) = watch::channel(());
    let pending = no_pending();
    let handle = tokio::spawn({
      let last_activity = Arc::clone(&last_activity);
      let pending = pending.clone();
      let clock = clock.clone();
      let ping_tx = ping_tx.clone();
      async move {
        liveness_observer(
          &last_activity,
          &pending,
          clock,
          Duration::ZERO,
          keepalive_every(5),
          Duration::from_secs(10),
          &ping_tx,
        )
        .await
      }
    });
    tokio::task::yield_now().await;

    // Every ping is answered by traffic at the current stamp: four full
    // keepalive timeouts pass and the session stays open.
    for second in 1..=40_u64 {
      clock.set(start + Duration::from_secs(second));
      tokio::time::advance(Duration::from_secs(1)).await;
      if ping_rx.has_changed().unwrap_or(false) {
        let _ = ping_rx.borrow_and_update();
        last_activity.store(1_000 + second, Ordering::Relaxed);
      }
      assert!(!handle.is_finished(), "closed at second {second}");
    }
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
      pending
        .try_reserve_admission(
          &crate::TraceId::parse("trace-000000000000000000001").unwrap(),
          crate::routing::forward::PendingAck::Wait {
            notify,
            queued_at: 100,
          },
        )
        .unwrap();
    }
    let (ping_tx, _) = watch::channel(());
    let handle = tokio::spawn({
      let last_activity = Arc::clone(&last_activity);
      let pending = pending.clone();
      let clock = clock.clone();
      let ping_tx = ping_tx.clone();
      async move {
        liveness_observer(
          &last_activity,
          &pending,
          clock,
          Duration::from_secs(10),
          None,
          Duration::ZERO,
          &ping_tx,
        )
        .await
      }
    });
    tokio::task::yield_now().await;

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
