//! Event-parity invariant: the pre-existing event set fires exactly as
//! the declarative refactor found it, for one scripted
//! join/leave/resource sequence.
//!
//! The pins below are per node, per event type. A total cross-type
//! order was never deterministic (concurrent effects interleave under
//! the scheduler, exactly as they did before the refactor); the parity
//! contract is *which* events fire, *how often*, with *which payloads*,
//! and in which order within one type. `TaskChanged` is the refactor's
//! one deliberate addition and is pinned in `tests/tasks.rs`, not here.

use std::{
  future::Future,
  sync::Arc,
  time::{Duration, Instant},
};

use radiata::{
  Endpoint, Event, EventOptions, EventReceive, EventSubscription, IdentityReplaced, MemberChanged,
  MemberStatus, NodeBuilder, NodeConfig, NodeHandle, NodeId, NodeRevoked, PageSpec,
  RecoveryChanged, ResourceChanged, ResourceLabels, ResourceName, ResourceUri, ResourceWrite,
  RouteChanged, SessionChanged,
  extension::{KeyProvider, StorageFactory},
};

mod common;

use common::{MemoryStorageFactory, ScriptedKeys};

/// A deterministic key provider with working deletion (the shared
/// scripted providers intentionally fail deletes, so the member's
/// leave custody lane needs its own; the per-suite fixture precedent
/// is `tests/leave.rs`'s `LeaveKeys`).
#[derive(Debug, Default)]
struct LeaveCapableKeys {
  records: std::sync::Mutex<std::collections::BTreeMap<Vec<u8>, ed25519_dalek::SigningKey>>,
  operations: std::sync::Mutex<std::collections::BTreeMap<Vec<u8>, Vec<u8>>>,
  next: std::sync::Mutex<u64>,
}

impl LeaveCapableKeys {
  /// Generated keys start from `base`, so two providers in one test
  /// never collide on an identity.
  fn with_base(base: u64) -> Self {
    let provider = Self::default();
    *provider.next.lock().unwrap() = base;
    provider
  }

  fn seed_for(base: u64) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&base.to_le_bytes().repeat(4)[..32].try_into().unwrap())
  }

  fn create_at(&self, operation: &radiata::KeyOperationId) -> radiata::KeyCreateState {
    let mut operations = self.operations.lock().unwrap();
    if let Some(handle) = operations.get(operation.as_str().as_bytes()) {
      let records = self.records.lock().unwrap();
      let signing = &records[handle];
      return radiata::KeyCreateState::Present(radiata::CreatedKey::new(
        radiata::KeyHandle::from_provider_bytes(Arc::from(handle.clone())).unwrap(),
        radiata::PublicKey::from_bytes(signing.verifying_key().to_bytes()),
      ));
    }
    let mut next = self.next.lock().unwrap();
    let index = *next;
    *next += 1;
    let signing = Self::seed_for(index + 1);
    let handle = format!("parity-handle-{index}").into_bytes();
    let created = radiata::CreatedKey::new(
      radiata::KeyHandle::from_provider_bytes(Arc::from(handle.clone())).unwrap(),
      radiata::PublicKey::from_bytes(signing.verifying_key().to_bytes()),
    );
    operations.insert(operation.as_str().as_bytes().to_vec(), handle.clone());
    self.records.lock().unwrap().insert(handle, signing);
    radiata::KeyCreateState::Present(created)
  }
}

impl radiata::extension::KeyProvider for LeaveCapableKeys {
  fn capabilities(&self) -> radiata::KeyCapabilities {
    radiata::KeyCapabilities::new()
      .ed25519(true)
      .reconciliation(true)
      .deletion(true)
  }

  fn create_ed25519<'a>(
    &'a self, operation: &'a radiata::KeyOperationId,
  ) -> radiata::BoxFuture<'a, radiata::Result<radiata::KeyCreateState>> {
    Box::pin(async move { Ok(self.create_at(operation)) })
  }

  fn reconcile_create<'a>(
    &'a self, operation: &'a radiata::KeyOperationId,
  ) -> radiata::BoxFuture<'a, radiata::Result<radiata::KeyCreateState>> {
    Box::pin(async move {
      let operations = self.operations.lock().unwrap();
      let Some(handle) = operations.get(operation.as_str().as_bytes()) else {
        return Ok(radiata::KeyCreateState::Absent);
      };
      let records = self.records.lock().unwrap();
      let Some(signing) = records.get(handle) else {
        return Ok(radiata::KeyCreateState::Absent);
      };
      Ok(radiata::KeyCreateState::Present(radiata::CreatedKey::new(
        radiata::KeyHandle::from_provider_bytes(Arc::from(handle.clone())).unwrap(),
        radiata::PublicKey::from_bytes(signing.verifying_key().to_bytes()),
      )))
    })
  }

  fn public_key<'a>(
    &'a self, handle: &'a radiata::KeyHandle,
  ) -> radiata::BoxFuture<'a, radiata::Result<radiata::PublicKey>> {
    let result = self
      .records
      .lock()
      .unwrap()
      .get(handle.expose_provider_handle())
      .map(|signing| radiata::PublicKey::from_bytes(signing.verifying_key().to_bytes()))
      .ok_or_else(|| {
        radiata::Error::provider(
          radiata::ProviderErrorKind::Internal,
          radiata::ProviderErrorContext::KeyPublicKey,
        )
      });
    Box::pin(async move { result })
  }

  fn sign<'a>(
    &'a self, handle: &'a radiata::KeyHandle, message: &'a [u8],
  ) -> radiata::BoxFuture<'a, radiata::Result<radiata::Signature>> {
    use ed25519_dalek::Signer as _;
    let result = self
      .records
      .lock()
      .unwrap()
      .get(handle.expose_provider_handle())
      .map(|signing| radiata::Signature::from_bytes(signing.sign(message).to_bytes()))
      .ok_or_else(|| {
        radiata::Error::provider(
          radiata::ProviderErrorKind::Internal,
          radiata::ProviderErrorContext::KeySign,
        )
      });
    Box::pin(async move { result })
  }

  fn delete<'a>(
    &'a self, _operation: &'a radiata::KeyOperationId, handle: &'a radiata::KeyHandle,
  ) -> radiata::BoxFuture<'a, radiata::Result<radiata::KeyDeleteState>> {
    let removed = self
      .records
      .lock()
      .unwrap()
      .remove(handle.expose_provider_handle())
      .is_some();
    Box::pin(async move {
      Ok(if removed {
        radiata::KeyDeleteState::Present
      } else {
        radiata::KeyDeleteState::Absent
      })
    })
  }

  fn reconcile_delete<'a>(
    &'a self, _operation: &'a radiata::KeyOperationId, handle: &'a radiata::KeyHandle,
  ) -> radiata::BoxFuture<'a, radiata::Result<radiata::KeyDeleteState>> {
    let present = self
      .records
      .lock()
      .unwrap()
      .contains_key(handle.expose_provider_handle());
    Box::pin(async move {
      Ok(if present {
        radiata::KeyDeleteState::Present
      } else {
        radiata::KeyDeleteState::Absent
      })
    })
  }
}

/// Long enough that no background anti-entropy tick fires during the
/// script: convergence is driven by the manual `sync()` round alone, so
/// the event streams stay deterministic.
const QUIET_INTERVAL: Duration = Duration::from_secs(600);
const CONVERGENCE_DEADLINE: Duration = Duration::from_secs(30);

async fn start(seed: u64) -> NodeHandle {
  let storage: Arc<dyn StorageFactory> =
    Arc::new(MemoryStorageFactory::new(common::required_capabilities()));
  let keys: Arc<dyn KeyProvider> = Arc::new(ScriptedKeys::full_at(8_000_000 + seed * 1_000));
  NodeBuilder::new(storage)
    .keys(keys)
    .config(
      NodeConfig::new()
        .with_anti_entropy_interval(QUIET_INTERVAL)
        .unwrap(),
    )
    .start()
    .await
    .unwrap()
}

/// The leaving member's variant: deletion-capable keys, so the leave
/// custody lane completes.
async fn start_leaver(seed: u64) -> NodeHandle {
  let storage: Arc<dyn StorageFactory> =
    Arc::new(MemoryStorageFactory::new(common::required_capabilities()));
  let keys: Arc<dyn KeyProvider> = Arc::new(LeaveCapableKeys::with_base(9_000_000 + seed));
  NodeBuilder::new(storage)
    .keys(keys)
    .config(
      NodeConfig::new()
        .with_anti_entropy_interval(QUIET_INTERVAL)
        .unwrap(),
    )
    .start()
    .await
    .unwrap()
}

/// Drains one subscription's buffered items, failing on lag: parity is
/// an exact-sequence pin, so a dropped item is a broken invariant, not
/// a retryable condition.
fn drain<E: Event>(subscription: &mut EventSubscription<E>) -> Vec<E> {
  let mut items = Vec::new();
  loop {
    match subscription.try_recv().unwrap() {
      EventReceive::Item(item) => items.push(item),
      EventReceive::Lagged { missed } => panic!("parity subscription lagged by {missed}"),
      EventReceive::Empty | EventReceive::Closed => return items,
      _ => return items,
    }
  }
}

/// The seven subscriptions covering one node's pre-existing event set.
struct ExistingEvents {
  member: EventSubscription<MemberChanged>,
  session: EventSubscription<SessionChanged>,
  resource: EventSubscription<ResourceChanged>,
  route: EventSubscription<RouteChanged>,
  recovery: EventSubscription<RecoveryChanged>,
  revoked: EventSubscription<NodeRevoked>,
  identity: EventSubscription<IdentityReplaced>,
}

fn subscribe(node: &NodeHandle) -> ExistingEvents {
  ExistingEvents {
    member: node.watch::<MemberChanged>(EventOptions::new()).unwrap(),
    session: node.watch::<SessionChanged>(EventOptions::new()).unwrap(),
    resource: node.watch::<ResourceChanged>(EventOptions::new()).unwrap(),
    route: node.watch::<RouteChanged>(EventOptions::new()).unwrap(),
    recovery: node.watch::<RecoveryChanged>(EventOptions::new()).unwrap(),
    revoked: node.watch::<NodeRevoked>(EventOptions::new()).unwrap(),
    identity: node.watch::<IdentityReplaced>(EventOptions::new()).unwrap(),
  }
}

fn resource_write(seed: u8) -> ResourceWrite {
  ResourceWrite::new(
    ResourceName::parse(&format!("example.org/resources/parity-{seed:03}")).unwrap(),
    ResourceLabels::new(
      radiata::LabelValue::parse("document").unwrap(),
      ResourceUri::parse(&format!("file:///parity/{seed:03}")).unwrap(),
    ),
  )
}

/// The deadline-bounded convergence poll (the suite's standing shape
/// for observability that has no watch surface of its own).
async fn until<P, F>(what: &'static str, mut probe: P)
where
  P: FnMut() -> F,
  F: Future<Output = bool>, {
  let deadline = Instant::now() + CONVERGENCE_DEADLINE;
  while !probe().await {
    assert!(Instant::now() < deadline, "{what}");
    tokio::time::sleep(Duration::from_millis(5)).await;
  }
}

async fn member_visible(node: &NodeHandle, peer: &NodeId) -> bool {
  let page = node
    .members()
    .list(PageSpec::first(16).unwrap())
    .await
    .unwrap();
  page.items().iter().any(|view| view.node_id() == peer)
}

async fn member_left(node: &NodeHandle, peer: &NodeId) -> bool {
  node
    .members()
    .get(peer.clone())
    .await
    .unwrap()
    .is_some_and(|view| view.status() == MemberStatus::Left)
}

async fn session_gone(node: &NodeHandle, peer: &NodeId) -> bool {
  let page = node
    .sessions()
    .list(PageSpec::first(16).unwrap())
    .await
    .unwrap();
  page.items().iter().all(|view| view.peer() != peer)
}

/// The scripted sequence: credential rotation, listener, join, one
/// resource write, one manual convergence round, one leave. Every step
/// is driven to completion (task waits, convergence polls) before the
/// next, so each node's per-type emission order is causal and pinnable.
///
/// Derived pins (per node, per type):
/// - issuer `MemberChanged`: self at listen (first descriptor), member at the
///   sync round (descriptor install), member again at the leave record
///   (removal);
/// - issuer `SessionChanged`: member twice (join registration, teardown when
///   the leaver closes the socket);
/// - issuer `ResourceChanged`: none — a synced row is writer-local by design,
///   only the writing node emits;
/// - member `MemberChanged`: self at the resource write (its first descriptor
///   install precedes the commit) — the one member-initiated round carries the
///   member's rows to the issuer; the issuer's own rows flow back on the
///   issuer's rounds, which never run in this script, so no issuer-side install
///   fires on the member;
/// - member `SessionChanged`: issuer once (join registration — the leave's
///   local teardown retires the table entry without a second event, exactly as
///   before the refactor);
/// - member `ResourceChanged`: the one written name;
/// - member `IdentityReplaced`: exactly once (the leave);
/// - `RouteChanged`/`RecoveryChanged`/`NodeRevoked`: none on either side (no
///   relayed packets, no recovery, no revocation).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn existing_events_fire_exactly_once_for_the_scripted_sequence() {
  common::init_tracing();
  let issuer = start(1).await;
  let member = start_leaver(2).await;
  let issuer_id = issuer.local_node().await.unwrap().node_id().clone();
  let member_id = member.local_node().await.unwrap().node_id().clone();

  let mut issuer_events = subscribe(&issuer);
  let mut member_events = subscribe(&member);

  // Credential rotation: pure key-custody state, no member-set event.
  let issued = issuer
    .credentials()
    .rotate()
    .await
    .unwrap()
    .wait()
    .await
    .unwrap();
  let secret = issued.credential().expose_secret().to_owned();

  // Listener: the first publication of the local descriptor (with the
  // listener's endpoint) is one member-set change on the issuer.
  let listener = issuer
    .listeners()
    .create(Endpoint::parse("wss://127.0.0.1:0").unwrap())
    .await
    .unwrap()
    .wait()
    .await
    .unwrap();

  // Join: one authenticated session on each side.
  common::merge_with_retry(&member, &issuer, listener.endpoint().clone()).await;

  // One local resource write: the writer's first descriptor install
  // (the member never listens) then exactly one committed-candidate
  // event on the writer.
  member
    .resources()
    .put(resource_write(1))
    .await
    .unwrap()
    .wait()
    .await
    .unwrap();

  // One manual convergence round: the issuer installs the member's
  // descriptor (one member-set change); the member installs the
  // issuer's (one member-set change). The synced resource row emits
  // nothing on the issuer.
  member.sync().await.unwrap();
  let probe_issuer = issuer.clone();
  let probe_member_id = member_id.clone();
  until("issuer never observed the member", || {
    let issuer = probe_issuer.clone();
    let member_id = probe_member_id.clone();
    async move { member_visible(&issuer, &member_id).await }
  })
  .await;

  // Leave: the member's identity is replaced (one event on the
  // member), the issuer applies the leave record (one member-set
  // removal) and observes the session teardown (one session event).
  let outcome = member
    .leave(radiata::ReplaceIdentityAndDeleteOldCoreMetadata::new())
    .await
    .unwrap()
    .wait()
    .await
    .unwrap();
  assert_eq!(*outcome.former_identity(), member_id);
  let probe_issuer = issuer.clone();
  let probe_member_id = member_id.clone();
  until("issuer never observed the leave record", || {
    let issuer = probe_issuer.clone();
    let member_id = probe_member_id.clone();
    async move { member_left(&issuer, &member_id).await }
  })
  .await;
  let probe_issuer = issuer.clone();
  let probe_member_id = member_id.clone();
  until("issuer never tore the member session down", || {
    let issuer = probe_issuer.clone();
    let member_id = probe_member_id.clone();
    async move { session_gone(&issuer, &member_id).await }
  })
  .await;

  // One final quiet round on the issuer: with the member departed it
  // carries nothing new, so anything it emits breaks parity.
  issuer.sync().await.unwrap();

  // ---- The pins ----
  let issuer_member = drain(&mut issuer_events.member);
  assert_eq!(
    issuer_member
      .iter()
      .map(|event| event.node_id().clone())
      .collect::<Vec<_>>(),
    vec![issuer_id.clone(), member_id.clone(), member_id.clone()],
    "issuer member-set: self at listen, member at sync, member at leave"
  );
  let issuer_session = drain(&mut issuer_events.session);
  assert_eq!(
    issuer_session
      .iter()
      .map(|event| event.peer().clone())
      .collect::<Vec<_>>(),
    vec![member_id.clone(), member_id.clone()],
    "issuer sessions: member at join, member at teardown"
  );
  assert!(
    drain(&mut issuer_events.resource).is_empty(),
    "a synced resource row emits nothing on the receiver"
  );
  // Route events ride the untouched data plane (sync-round payloads,
  // the leave receipt): their count is a function of sync-plane paging
  // and best-effort delivery, never of any migrated verb, so the parity
  // pin is structural — packets flowed, nothing lagged — while the six
  // semantic types above and below are exact.
  let issuer_routes = drain(&mut issuer_events.route);
  assert!(
    !issuer_routes.is_empty(),
    "the issuer's sync responses must route"
  );
  let member_routes = drain(&mut member_events.route);
  assert!(
    !member_routes.is_empty(),
    "the member's round and announcement must route"
  );
  assert!(drain(&mut issuer_events.recovery).is_empty());
  assert!(drain(&mut issuer_events.revoked).is_empty());
  assert!(drain(&mut issuer_events.identity).is_empty());

  let member_member = drain(&mut member_events.member);
  assert_eq!(
    member_member
      .iter()
      .map(|event| event.node_id().clone())
      .collect::<Vec<_>>(),
    vec![member_id.clone()],
    "member member-set: self at the write; the issuer's rows return on issuer rounds"
  );
  let member_session = drain(&mut member_events.session);
  assert_eq!(
    member_session
      .iter()
      .map(|event| event.peer().clone())
      .collect::<Vec<_>>(),
    vec![issuer_id.clone()],
    "member sessions: issuer at join; the leave teardown retires silently"
  );
  assert_eq!(
    drain(&mut member_events.resource)
      .iter()
      .map(|event| event.resource().clone())
      .collect::<Vec<_>>(),
    vec![ResourceName::parse("example.org/resources/parity-001").unwrap()],
    "exactly one committed-candidate event, on the writer"
  );
  assert!(drain(&mut member_events.recovery).is_empty());
  assert!(drain(&mut member_events.revoked).is_empty());
  let member_identity = drain(&mut member_events.identity);
  assert_eq!(member_identity.len(), 1, "one identity replacement");
  assert_eq!(member_identity[0].former_identity(), &member_id);
  assert_ne!(*member_identity[0].replacement_identity(), member_id);
  assert_eq!(
    member_identity[0].replacement_identity(),
    outcome.replacement_identity(),
    "the event carries the outcome's replacement identity"
  );

  issuer.shutdown().await.unwrap();
  let _ = secret;
}
