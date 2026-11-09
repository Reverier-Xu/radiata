//! The tag-keyed event channel's public surface: a caller publishes
//! opaque bytes under an `EventTag` and subscribers receive them as
//! `TaggedEvent` items over the same bounded subscription plumbing as
//! the typed event hub. The built-in domain stays reserved (the crate's
//! official events are the sealed types), and a publish with no live
//! subscriber is dropped.

use std::{sync::Arc, time::Duration};

use radiata::{EventOptions, EventReceive, EventTag, NodeBuilder, NodeHandle};

mod common;

use common::{MemoryStorageFactory, ScriptedKeys, required_capabilities};
use radiata::extension::{KeyProvider, StorageFactory};

async fn start() -> NodeHandle {
  let storage: Arc<dyn StorageFactory> =
    Arc::new(MemoryStorageFactory::new(required_capabilities()));
  let keys: Arc<dyn KeyProvider> = Arc::new(ScriptedKeys::full());
  NodeBuilder::new(storage).keys(keys).start().await.unwrap()
}

/// A publish under a caller-owned tag round-trips to that tag's
/// subscribers with the publishing tag and payload; another tag's
/// subscriber observes nothing, and a subscription created later is not
/// replayed the earlier publishes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn publish_reaches_the_tag_subscribers_with_the_payload() {
  let node = start().await;
  let alpha = EventTag::parse("example.com/events/alpha").unwrap();
  let beta = EventTag::parse("example.com/events/beta").unwrap();

  // A publish with no subscriber is dropped, never buffered.
  node.publish(alpha.clone(), Arc::from([1_u8])).unwrap();

  let mut alpha_events = node.subscribe(alpha.clone(), EventOptions::new()).unwrap();
  let mut beta_events = node.subscribe(beta.clone(), EventOptions::new()).unwrap();

  node.publish(alpha.clone(), Arc::from([2_u8])).unwrap();
  node.publish(beta.clone(), Arc::from([9_u8])).unwrap();

  let received = tokio::time::timeout(Duration::from_secs(5), alpha_events.recv())
    .await
    .unwrap()
    .unwrap();
  assert!(
    matches!(&received, EventReceive::Item(event)
      if event.tag() == &alpha && event.payload().as_ref() == [2_u8]),
    "the subscriber receives the publishing tag and payload"
  );
  assert!(
    tokio::time::timeout(Duration::from_millis(50), alpha_events.recv())
      .await
      .is_err(),
    "one tag's publishes never land on another tag's subscribers"
  );
  let received = tokio::time::timeout(Duration::from_secs(5), beta_events.recv())
    .await
    .unwrap()
    .unwrap();
  assert!(
    matches!(&received, EventReceive::Item(event)
      if event.tag() == &beta && event.payload().as_ref() == [9_u8]),
    "the beta subscriber receives exactly the beta publish"
  );

  node.shutdown().await.unwrap();
}

/// The bounded subscription: a subscriber whose channel is full lags
/// (with the exact missed count) instead of blocking the publisher, and
/// the delivered payload order is preserved.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_slow_subscriber_lags_instead_of_blocking_the_publisher() {
  let node = start().await;
  let tag = EventTag::parse("example.com/events/bounded").unwrap();
  let mut events = node
    .subscribe(tag.clone(), EventOptions::new().capacity(2).unwrap())
    .unwrap();

  for byte in 0..4_u8 {
    node.publish(tag.clone(), Arc::from([byte])).unwrap();
  }

  assert!(
    matches!(
      events.try_recv().unwrap(),
      EventReceive::Lagged { missed: 2 }
    ),
    "a capacity-2 subscriber misses the first two of four publishes"
  );
  for byte in [2_u8, 3] {
    let item = events.recv().await.unwrap();
    assert!(
      matches!(&item, EventReceive::Item(event) if event.payload().as_ref() == [byte]),
      "the post-lag deliveries keep the payload order"
    );
  }

  node.shutdown().await.unwrap();
}

/// The built-in domain is reserved for the crate's sealed event types: a
/// publish or a subscription under it is refused typed, on both the
/// reserved-domain and the not-running gates.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_builtin_domain_stays_reserved_on_the_event_channel() {
  let node = start().await;
  let reserved = EventTag::parse("radiata.woooo.tech/events/official").unwrap();
  let caller = EventTag::parse("example.com/events/caller").unwrap();

  let refused = node
    .publish(reserved.clone(), Arc::from([1_u8]))
    .unwrap_err();
  assert_eq!(refused.kind(), radiata::ErrorKind::InvalidInput);
  assert_eq!(refused.context(), "tag-keyed event channel");
  let refused = match node.subscribe(reserved, EventOptions::new()) {
    Err(error) => error,
    Ok(_) => panic!("the reserved-domain subscription is refused"),
  };
  assert_eq!(refused.kind(), radiata::ErrorKind::InvalidInput);
  assert_eq!(refused.context(), "tag-keyed event channel");

  // The caller-owned domain is unaffected by the reservation.
  node.publish(caller, Arc::from([1_u8])).unwrap();
  node.shutdown().await.unwrap();

  // A stopped node refuses the channel like the typed watch.
  let stopped = EventTag::parse("example.com/events/stopped").unwrap();
  let refused = node
    .publish(stopped.clone(), Arc::from([1_u8]))
    .unwrap_err();
  assert_eq!(refused.kind(), radiata::ErrorKind::ShuttingDown);
  assert!(node.subscribe(stopped, EventOptions::new()).is_err());
}
