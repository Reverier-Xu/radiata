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
  InFlight(crate::BoxFuture<'static, (RawReceive<E>, broadcast::Receiver<E>)>),
  Terminated,
}

type RawReceive<E> = std::result::Result<E, broadcast::error::RecvError>;

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
  pub async fn recv(&mut self) -> Result<EventReceive<E>> {
    let state = std::mem::replace(&mut self.state, SubscriptionState::Terminated);
    let (raw, receiver) = match state {
      SubscriptionState::Terminated => return Ok(EventReceive::Closed),
      SubscriptionState::Idle(mut receiver) => {
        let raw = receiver.recv().await;
        (raw, receiver)
      }
      SubscriptionState::InFlight(pending) => pending.await,
    };
    let (item, terminated) = map_receive(raw);
    self.state = if terminated {
      SubscriptionState::Terminated
    } else {
      SubscriptionState::Idle(receiver)
    };
    Ok(item)
  }

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
      SubscriptionState::InFlight(mut pending) => {
        // A pending stream poll owns the channel position: observe its
        // current readiness without consuming the caller's waker.
        let waker = futures_util::task::noop_waker();
        let mut context = Context::from_waker(&waker);
        match pending.as_mut().poll(&mut context) {
          Poll::Pending => {
            self.state = SubscriptionState::InFlight(pending);
            Ok(EventReceive::Empty)
          }
          Poll::Ready((raw, receiver)) => {
            let (item, terminated) = map_receive(raw);
            self.state = if terminated {
              SubscriptionState::Terminated
            } else {
              SubscriptionState::Idle(receiver)
            };
            Ok(item)
          }
        }
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

/// The additive standard-stream view (R2): the same items `recv` yields,
/// in the same order. Lag stays explicit as `EventReceive::Lagged`; the
/// terminal `EventReceive::Closed` item is yielded once, then the stream
/// ends. `try_recv`'s `Empty` is poll-level pending and never appears as
/// an item.
impl<E: Event> futures_core::Stream for EventSubscription<E> {
  type Item = EventReceive<E>;

  fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
    loop {
      match &mut self.state {
        SubscriptionState::Terminated => return Poll::Ready(None),
        SubscriptionState::Idle(_) => {
          let SubscriptionState::Idle(mut receiver) =
            std::mem::replace(&mut self.state, SubscriptionState::Terminated)
          else {
            unreachable!("matched idle state")
          };
          self.state =
            SubscriptionState::InFlight(Box::pin(async move { (receiver.recv().await, receiver) }));
        }
        SubscriptionState::InFlight(pending) => match pending.as_mut().poll(cx) {
          Poll::Pending => return Poll::Pending,
          Poll::Ready((raw, receiver)) => {
            let (item, terminated) = map_receive(raw);
            self.state = if terminated {
              SubscriptionState::Terminated
            } else {
              SubscriptionState::Idle(receiver)
            };
            return Poll::Ready(Some(item));
          }
        },
      }
    }
  }
}

/// The runtime event hub (T-G09-03): one typed subscriber set per event
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
  use super::event_channel;
  use crate::{ErrorKind, Event, EventOptions, EventReceive, operation::private};

  #[derive(Clone, Debug, Eq, PartialEq)]
  struct TestEvent(u8);

  impl private::Sealed for TestEvent {}
  impl Event for TestEvent {}

  #[test]
  fn g1_lifecycle_event_capacity_accepts_values_above_old_maximum() {
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
  async fn g1_lifecycle_event_subscription_reports_empty_lagged_and_closed() {
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

  /// SC-G11-P1-04: the additive `Stream` view yields exactly the items
  /// `recv`/`try_recv` report, keeps lag explicit, and terminates after
  /// one `Closed` item.
  #[tokio::test]
  async fn g11_event_subscription_stream_matches_recv_parity() {
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
}
