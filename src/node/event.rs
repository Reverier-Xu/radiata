use std::{
  pin::Pin,
  task::{Context, Poll},
};

use tokio::sync::broadcast;

use crate::{Error, Event, Result};

const DEFAULT_EVENT_CAPACITY: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventOptions {
  capacity: usize,
}

impl EventOptions {
  pub fn new() -> Self {
    Self::default()
  }

  pub fn capacity(mut self, value: usize) -> Result<Self> {
    validate_capacity(value)?;
    self.capacity = value;
    Ok(self)
  }
}

impl Default for EventOptions {
  fn default() -> Self {
    Self {
      capacity: DEFAULT_EVENT_CAPACITY,
    }
  }
}

pub struct EventSubscription<E: Event> {
  state: SubscriptionState<E>,
}

/// The subscription's receive state: the channel receiver either sits
/// idle, or is checked out into one in-flight receive future while a
/// `Stream` poll is pending. Checking the receiver out keeps the
/// `Stream` impl free of any additional dependency while `recv`,
/// `try_recv`, and `poll_next` share one channel position.
enum SubscriptionState<E: Event> {
  Idle(broadcast::Receiver<E>),
  InFlight(PendingReceive<E>),
  Terminated,
}

type RawReceive<E> = std::result::Result<E, broadcast::error::RecvError>;

/// One parked receive future and the receiver it hands back on
/// resolution.
type PendingReceive<E> = crate::BoxFuture<'static, (RawReceive<E>, broadcast::Receiver<E>)>;

/// Maps one raw broadcast receive to the contract item plus the terminal
/// flag: `Closed` is terminal (yielded once, then the stream ends).
fn map_receive<E: Event>(raw: RawReceive<E>) -> (EventReceive<E>, bool) {
  match raw {
    Ok(event) => (EventReceive::Item(event), false),
    Err(broadcast::error::RecvError::Lagged(missed)) => (EventReceive::Lagged { missed }, false),
    Err(broadcast::error::RecvError::Closed) => (EventReceive::Closed, true),
  }
}

impl<E: Event> EventSubscription<E> {
  /// Parks the receive future on the subscription and hands it out: an
  /// idle receiver is checked out into a fresh receive future, and an
  /// already-parked one stays where it is, so a cancelled caller leaves
  /// the receiver owned by the subscription instead of dropping it with
  /// the caller's frame. `None` once the subscription is terminal.
  fn park(&mut self) -> Option<&mut PendingReceive<E>> {
    let state = std::mem::replace(&mut self.state, SubscriptionState::Terminated);
    self.state = match state {
      SubscriptionState::Terminated => return None,
      SubscriptionState::Idle(mut receiver) => {
        SubscriptionState::InFlight(Box::pin(async move { (receiver.recv().await, receiver) }))
      }
      SubscriptionState::InFlight(pending) => SubscriptionState::InFlight(pending),
    };
    match &mut self.state {
      SubscriptionState::InFlight(pending) => Some(pending),
      // The state was just parked as `InFlight`; a terminal subscription
      // has no future to hand out.
      _ => None,
    }
  }

  pub async fn recv(&mut self) -> Result<EventReceive<E>> {
    // The receive future is parked on `self` before awaiting, so a
    // cancelled `recv` leaves the receiver owned by the subscription
    // instead of dropping it with this future's frame, which would
    // silently terminate every later receive.
    let (raw, receiver) = {
      let Some(pending) = self.park() else {
        return Ok(EventReceive::Closed);
      };
      pending.as_mut().await
    };
    let (item, terminated) = map_receive(raw);
    self.state = if terminated {
      SubscriptionState::Terminated
    } else {
      SubscriptionState::Idle(receiver)
    };
    Ok(item)
  }

  /// The non-blocking receive. `Empty` is poll-level pending: while a
  /// `Stream` poll owns the channel position, this reports `Empty` and
  /// leaves the parked receive (and the waker it registered) untouched,
  /// so the stream's owner still wakes on the next event.
  pub fn try_recv(&mut self) -> Result<EventReceive<E>> {
    let state = std::mem::replace(&mut self.state, SubscriptionState::Terminated);
    match state {
      SubscriptionState::Terminated => Ok(EventReceive::Closed),
      SubscriptionState::Idle(mut receiver) => {
        let (item, terminated) = match receiver.try_recv() {
          Ok(event) => (EventReceive::Item(event), false),
          Err(broadcast::error::TryRecvError::Empty) => (EventReceive::Empty, false),
          Err(broadcast::error::TryRecvError::Lagged(missed)) => {
            (EventReceive::Lagged { missed }, false)
          }
          Err(broadcast::error::TryRecvError::Closed) => (EventReceive::Closed, true),
        };
        self.state = if terminated {
          SubscriptionState::Terminated
        } else {
          SubscriptionState::Idle(receiver)
        };
        Ok(item)
      }
      SubscriptionState::InFlight(pending) => {
        // A pending stream poll owns the channel position AND the waker
        // it registered: polling the parked future here would re-register
        // this call's waker and the stream's owner would never be woken.
        // Report the poll-level empty and leave the parked future alone;
        // the next `poll_next` (or `recv`) delivers whatever arrived.
        self.state = SubscriptionState::InFlight(pending);
        Ok(EventReceive::Empty)
      }
    }
  }
}

#[non_exhaustive]
pub enum EventReceive<E> {
  Item(E),
  Empty,
  Lagged { missed: u64 },
  Closed,
}

/// The additive standard-stream view: the same items `recv` yields,
/// in the same order. Lag stays explicit as `EventReceive::Lagged`; the
/// terminal `EventReceive::Closed` item is yielded once, then the stream
/// ends. `try_recv`'s `Empty` is poll-level pending and never appears as
/// an item.
impl<E: Event> futures_core::Stream for EventSubscription<E> {
  type Item = EventReceive<E>;

  fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
    let Some(pending) = self.park() else {
      return Poll::Ready(None);
    };
    match pending.as_mut().poll(cx) {
      Poll::Pending => Poll::Pending,
      Poll::Ready((raw, receiver)) => {
        let (item, terminated) = map_receive(raw);
        self.state = if terminated {
          SubscriptionState::Terminated
        } else {
          SubscriptionState::Idle(receiver)
        };
        Poll::Ready(Some(item))
      }
    }
  }
}

/// The runtime event hub: one typed subscriber set per event
/// type. Events are transient — an emission with no live subscriber is
/// dropped, a lagging subscriber observes `Lagged` and must re-read
/// through the paged queries, and nothing is retained for replay after
/// restart.
///
/// The hub holds each subscription's sender strongly so the channel stays
/// open for the subscriber's receiver; a sender whose receiver count
/// drops to zero is pruned on the next emission or subscription.
#[derive(Debug, Default)]
pub(crate) struct EventHub {
  subscribers: std::sync::Mutex<
    std::collections::HashMap<std::any::TypeId, Vec<Box<dyn std::any::Any + Send + Sync>>>,
  >,
}

impl EventHub {
  pub(crate) fn new() -> Self {
    Self::default()
  }

  /// Locks the subscriber map, recovering from a poisoned lock: the map
  /// holds only plain subscriber vectors, so a panicking emitter cannot
  /// leave it inconsistent.
  fn lock(
    &self,
  ) -> std::sync::MutexGuard<
    '_,
    std::collections::HashMap<std::any::TypeId, Vec<Box<dyn std::any::Any + Send + Sync>>>,
  > {
    self
      .subscribers
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner())
  }

  /// Subscribes with an independent bounded channel per subscription, so
  /// one slow subscriber's lag never backpressures emitters or other
  /// subscribers.
  pub(crate) fn subscribe<E: Event>(&self, options: EventOptions) -> EventSubscription<E> {
    let (sender, receiver) = broadcast::channel(options.capacity);
    let mut subscribers = self.lock();
    let entries = subscribers.entry(std::any::TypeId::of::<E>()).or_default();
    Self::prune::<E>(entries);
    entries.push(Box::new(std::sync::Arc::new(sender)));
    EventSubscription {
      state: SubscriptionState::Idle(receiver),
    }
  }

  /// Emits one event to every live subscriber of its type; a subscriber
  /// whose channel is full lags instead of blocking the emitter.
  pub(crate) fn emit<E: Event>(&self, event: E) {
    let mut subscribers = self.lock();
    let Some(entries) = subscribers.get_mut(&std::any::TypeId::of::<E>()) else {
      return;
    };
    for entry in entries.iter() {
      if let Some(sender) = entry.downcast_ref::<std::sync::Arc<broadcast::Sender<E>>>() {
        // A send error means this channel has no active receivers; the
        // transient event is gone and the next retain prunes the sender.
        let _ = sender.send(event.clone());
      }
    }
    Self::prune::<E>(entries);
  }

  /// Drops senders whose subscribers have all gone away.
  fn prune<E: Event>(entries: &mut Vec<Box<dyn std::any::Any + Send + Sync>>) {
    entries.retain(|entry| {
      entry
        .downcast_ref::<std::sync::Arc<broadcast::Sender<E>>>()
        .is_some_and(|sender| sender.receiver_count() > 0)
    });
  }
}

fn validate_capacity(value: usize) -> Result<()> {
  if value == 0 {
    return Err(Error::invalid_input("event subscription capacity"));
  }
  let represented = value
    .checked_next_power_of_two()
    .ok_or_else(|| Error::invalid_input("event subscription capacity"))?;
  let mut allocation_probe = Vec::<u8>::new();
  allocation_probe
    .try_reserve_exact(represented)
    .map_err(|_| Error::resource_exhausted("event subscription capacity"))?;
  Ok(())
}

#[cfg(test)]
fn event_channel<E: Event>(options: EventOptions) -> (broadcast::Sender<E>, EventSubscription<E>) {
  let (sender, receiver) = broadcast::channel(options.capacity);
  (
    sender,
    EventSubscription {
      state: SubscriptionState::Idle(receiver),
    },
  )
}

#[cfg(test)]
mod tests {
  use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
  };

  use super::event_channel;
  use crate::{ErrorKind, Event, EventOptions, EventReceive, operation::private};

  #[derive(Clone, Debug, Eq, PartialEq)]
  struct TestEvent(u8);

  impl private::Sealed for TestEvent {}
  impl Event for TestEvent {}

  #[test]
  fn lifecycle_event_capacity_accepts_values_without_a_fixed_maximum() {
    EventOptions::new().capacity(1_025).unwrap();
    EventOptions::new().capacity(4_097).unwrap();
    assert_eq!(
      EventOptions::new().capacity(0).unwrap_err().kind(),
      ErrorKind::InvalidInput,
    );
    assert_eq!(
      EventOptions::new().capacity(usize::MAX).unwrap_err().kind(),
      ErrorKind::InvalidInput,
    );
    assert_eq!(
      EventOptions::new()
        .capacity(isize::MAX as usize)
        .unwrap_err()
        .kind(),
      ErrorKind::ResourceExhausted,
    );
  }

  #[tokio::test]
  async fn lifecycle_event_subscription_reports_empty_lagged_and_closed() {
    let options = EventOptions::new().capacity(2).unwrap();
    let (sender, mut subscription) = event_channel::<TestEvent>(options);

    assert!(matches!(
      subscription.try_recv().unwrap(),
      EventReceive::Empty
    ));
    sender.send(TestEvent(1)).unwrap();
    sender.send(TestEvent(2)).unwrap();
    sender.send(TestEvent(3)).unwrap();

    assert!(matches!(
      subscription.try_recv().unwrap(),
      EventReceive::Lagged { missed: 1 }
    ));
    assert!(matches!(
      subscription.recv().await.unwrap(),
      EventReceive::Item(TestEvent(2))
    ));
    assert!(matches!(
      subscription.recv().await.unwrap(),
      EventReceive::Item(TestEvent(3))
    ));

    drop(sender);
    assert!(matches!(
      subscription.recv().await.unwrap(),
      EventReceive::Closed
    ));
  }

  /// Cancelling a pending `recv` must not destroy the subscription: the
  /// receiver stays parked on the subscription, a later `recv` observes events
  /// sent after the cancellation, and the terminal close is still delivered
  /// exactly once.
  #[tokio::test]
  async fn event_subscription_recv_survives_cancellation() {
    let options = EventOptions::new().capacity(2).unwrap();
    let (sender, mut subscription) = event_channel::<TestEvent>(options);

    // No event yet: the receive parks, and the timeout cancels it.
    let cancelled =
      tokio::time::timeout(std::time::Duration::from_millis(20), subscription.recv()).await;
    assert!(cancelled.is_err(), "recv completed without any event");

    // The cancelled receive must not have consumed or dropped the
    // receiver: events sent afterwards are still observed.
    sender.send(TestEvent(7)).unwrap();
    assert!(matches!(
      subscription.recv().await.unwrap(),
      EventReceive::Item(TestEvent(7))
    ));

    // A second cancelled receive parks again; the stream view then keeps
    // working from the same channel position.
    let cancelled =
      tokio::time::timeout(std::time::Duration::from_millis(20), subscription.recv()).await;
    assert!(cancelled.is_err(), "recv completed without any event");
    sender.send(TestEvent(9)).unwrap();
    assert!(matches!(
      subscription.recv().await.unwrap(),
      EventReceive::Item(TestEvent(9))
    ));

    drop(sender);
    assert!(matches!(
      subscription.recv().await.unwrap(),
      EventReceive::Closed
    ));
  }

  /// The additive `Stream` view yields exactly the items
  /// `recv`/`try_recv` report, keeps lag explicit, and terminates after
  /// one `Closed` item.
  #[tokio::test]
  async fn event_subscription_stream_matches_recv_parity() {
    use futures_util::StreamExt;

    let options = EventOptions::new().capacity(2).unwrap();
    let (sender, subscription) = event_channel::<TestEvent>(options);
    tokio::pin!(subscription);

    // Pending is poll-level, never an Empty item.
    futures_util::future::poll_fn(|cx| {
      assert!(futures_core::Stream::poll_next(subscription.as_mut(), cx).is_pending());
      std::task::Poll::Ready(())
    })
    .await;

    sender.send(TestEvent(1)).unwrap();
    sender.send(TestEvent(2)).unwrap();
    sender.send(TestEvent(3)).unwrap();

    assert!(matches!(
      subscription.as_mut().next().await,
      Some(EventReceive::Lagged { missed: 1 })
    ));
    assert!(matches!(
      subscription.as_mut().next().await,
      Some(EventReceive::Item(TestEvent(2)))
    ));
    assert!(matches!(
      subscription.as_mut().next().await,
      Some(EventReceive::Item(TestEvent(3)))
    ));

    drop(sender);
    assert!(matches!(
      subscription.as_mut().next().await,
      Some(EventReceive::Closed)
    ));
    assert!(subscription.as_mut().next().await.is_none());
    assert!(subscription.as_mut().next().await.is_none());
  }

  /// A waker that only records whether it was woken.
  struct RecordingWaker(AtomicBool);

  impl futures_util::task::ArcWake for RecordingWaker {
    fn wake_by_ref(arc_self: &Arc<Self>) {
      arc_self.0.store(true, Ordering::SeqCst);
    }
  }

  /// `try_recv` must leave the waker a pending stream poll registered in
  /// place: polling the parked future with its own waker would replace it
  /// and the stream's owner would never be woken again.
  #[tokio::test]
  async fn try_recv_leaves_the_stream_poll_waker_registered() {
    let (sender, subscription) = event_channel::<TestEvent>(EventOptions::new());
    tokio::pin!(subscription);
    let recorder = Arc::new(RecordingWaker(AtomicBool::new(false)));
    let waker = futures_util::task::waker(Arc::clone(&recorder));
    let mut context = std::task::Context::from_waker(&waker);

    assert!(
      futures_core::Stream::poll_next(subscription.as_mut(), &mut context).is_pending(),
      "an empty subscription parked instead of yielding an item"
    );
    assert!(matches!(
      subscription.try_recv().unwrap(),
      EventReceive::Empty
    ));

    sender.send(TestEvent(1)).unwrap();
    assert!(
      recorder.0.load(Ordering::SeqCst),
      "try_recv replaced the waker the pending stream poll registered"
    );
    assert!(matches!(
      futures_core::Stream::poll_next(subscription.as_mut(), &mut context),
      std::task::Poll::Ready(Some(EventReceive::Item(TestEvent(1))))
    ));
  }

  /// The terminal state is idempotent across every receive shape: after
  /// the channel closes, `recv`, `try_recv`, and the stream each report
  /// the terminal instead of panicking on the parked state.
  #[tokio::test]
  async fn a_closed_subscription_reports_the_terminal_from_every_receive_shape() {
    use futures_util::StreamExt;

    let (sender, mut subscription) = event_channel::<TestEvent>(EventOptions::new());
    drop(sender);
    assert!(matches!(
      subscription.recv().await.unwrap(),
      EventReceive::Closed
    ));
    assert!(matches!(
      subscription.recv().await.unwrap(),
      EventReceive::Closed
    ));
    assert!(matches!(
      subscription.try_recv().unwrap(),
      EventReceive::Closed
    ));
    assert!(subscription.next().await.is_none());
  }
}
