//! Public-API integration test for the revocation/publication
//! authorization boundary (audit 2026-10-23, P1-11).
//!
//! A member handshake is admitted against the durable trusted binding
//! and then spends its round trips completing. The revocation that
//! commits inside that window must still decide the outcome: the
//! finishing handshake either never publishes or is retired
//! immediately. The interleave is made deterministic by parking the
//! issuer's responder exactly at its identity-proof signature — strictly
//! after the binding checks that admitted the handshake — and committing
//! the revoke while it is parked.

use std::{
  sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
  },
  time::Duration,
};

use radiata::{
  BoxFuture, Endpoint, ErrorKind, EventOptions, EventReceive, KeyCapabilities, KeyCreateState,
  KeyDeleteState, KeyHandle, KeyOperationId, NodeBuilder, NodeConfig, NodeHandle, NodeId, PageSpec,
  PublicKey, Result, SessionChanged, Signature, TrustStatus, extension::KeyProvider,
};

mod common;

use common::{MemoryStorageFactory, ScriptedKeys};

const SYNC_INTERVAL: Duration = Duration::from_millis(50);

/// A `KeyProvider` wrapper whose next `sign` after `arm()` parks until
/// `open()`: the deterministic "handshake completing while a revocation
/// lands" interleave. The park point is the responder's identity-proof
/// signature, which sits strictly after the binding checks that admit
/// the handshake, so an observed park is proof the handshake passed its
/// authorization and is mid-flight. The gate is one-shot, so the revoke
/// tombstone's own signature (signed later, by the test's ordering)
/// passes straight through.
#[derive(Debug)]
struct GatedKeys {
  inner: ScriptedKeys,
  armed: AtomicBool,
  parked: AtomicBool,
  open_tx: tokio::sync::watch::Sender<bool>,
}

impl GatedKeys {
  /// Wraps `inner` and returns the control handle beside the provider
  /// view the node builder consumes.
  fn wrap(inner: ScriptedKeys) -> (Arc<Self>, Arc<dyn KeyProvider>) {
    let (open_tx, _) = tokio::sync::watch::channel(false);
    let keys = Arc::new(Self {
      inner,
      armed: AtomicBool::new(false),
      parked: AtomicBool::new(false),
      open_tx,
    });
    let provider: Arc<dyn KeyProvider> = Arc::clone(&keys) as Arc<dyn KeyProvider>;
    (keys, provider)
  }

  /// Parks exactly the next `sign` call.
  fn arm(&self) {
    self.armed.store(true, Ordering::SeqCst);
  }

  /// Whether the armed sign call is parked mid-handshake.
  fn is_parked(&self) -> bool {
    self.parked.load(Ordering::SeqCst)
  }

  /// Releases the parked sign call.
  fn open(&self) {
    let _ = self.open_tx.send(true);
  }

  /// Consumes the one-shot arm and parks until `open`. The watch pair
  /// closes the notify race: a release that lands before the park simply
  /// leaves the observed flag true.
  async fn gate(&self) {
    if !self.armed.swap(false, Ordering::SeqCst) {
      return;
    }
    self.parked.store(true, Ordering::SeqCst);
    let mut open = self.open_tx.subscribe();
    while !*open.borrow_and_update() {
      if open.changed().await.is_err() {
        break;
      }
    }
  }
}

impl KeyProvider for GatedKeys {
  fn capabilities(&self) -> KeyCapabilities {
    self.inner.capabilities()
  }

  fn create_ed25519<'a>(
    &'a self, operation: &'a KeyOperationId,
  ) -> BoxFuture<'a, Result<KeyCreateState>> {
    self.inner.create_ed25519(operation)
  }

  fn reconcile_create<'a>(
    &'a self, operation: &'a KeyOperationId,
  ) -> BoxFuture<'a, Result<KeyCreateState>> {
    self.inner.reconcile_create(operation)
  }

  fn public_key<'a>(&'a self, handle: &'a KeyHandle) -> BoxFuture<'a, Result<PublicKey>> {
    self.inner.public_key(handle)
  }

  fn sign<'a>(
    &'a self, handle: &'a KeyHandle, message: &'a [u8],
  ) -> BoxFuture<'a, Result<Signature>> {
    Box::pin(async move {
      self.gate().await;
      self.inner.sign(handle, message).await
    })
  }

  fn delete<'a>(
    &'a self, operation: &'a KeyOperationId, handle: &'a KeyHandle,
  ) -> BoxFuture<'a, Result<KeyDeleteState>> {
    self.inner.delete(operation, handle)
  }

  fn reconcile_delete<'a>(
    &'a self, operation: &'a KeyOperationId, handle: &'a KeyHandle,
  ) -> BoxFuture<'a, Result<KeyDeleteState>> {
    self.inner.reconcile_delete(operation, handle)
  }
}

struct Node {
  handle: NodeHandle,
  endpoint: Endpoint,
  id: NodeId,
}

async fn start_node(keys: Arc<dyn KeyProvider>) -> Node {
  let storage = Arc::new(MemoryStorageFactory::new(common::required_capabilities()));
  let config = NodeConfig::new()
    .with_anti_entropy_interval(SYNC_INTERVAL)
    .unwrap();
  let handle = NodeBuilder::new(storage)
    .keys(keys)
    .config(config)
    .start()
    .await
    .unwrap();
  Node {
    handle,
    endpoint: Endpoint::parse("wss://127.0.0.1:0").unwrap(),
    id: NodeId::parse("node-000000000000000000000").unwrap(), // replaced by local_id()
  }
}

async fn listen(node: &Node) -> Endpoint {
  let listener = node
    .handle
    .listeners()
    .create(node.endpoint.clone())
    .await
    .unwrap()
    .wait()
    .await
    .unwrap();
  listener.endpoint().clone()
}

async fn local_id(node: &NodeHandle) -> NodeId {
  node.local_node().await.unwrap().node_id().clone()
}

/// The member's trusted public key as the issuer observes it (bindings
/// arrive with the admission commit; the observation is polled with a
/// bound like the revocation suite's).
async fn trusted_key(issuer: &NodeHandle, member: &NodeId) -> PublicKey {
  let deadline = std::time::Instant::now() + Duration::from_secs(30);
  loop {
    issuer.sync().await.unwrap();
    let page = issuer
      .trust()
      .list(PageSpec::first(64).unwrap())
      .await
      .unwrap();
    if let Some(view) = page.items().iter().find(|view| view.node_id() == member) {
      return view.public_key().clone();
    }
    assert!(
      std::time::Instant::now() < deadline,
      "member {member} must be trusted"
    );
    tokio::time::sleep(Duration::from_millis(5)).await;
  }
}

/// The member's trust status as the issuer observes it.
async fn trust_status(issuer: &NodeHandle, member: &NodeId) -> Option<TrustStatus> {
  issuer
    .trust()
    .list(PageSpec::first(64).unwrap())
    .await
    .unwrap()
    .items()
    .iter()
    .find(|view| view.node_id() == member)
    .map(|view| view.status())
}

/// Audit P1-11's interleaving, driven end to end: the handshake passes
/// its binding checks, the revocation commits while the handshake is
/// mid-flight, the handshake then completes — and the session it would
/// publish never survives under the revoked identity (publication is
/// refused at the shared authorization boundary, and the durable state
/// keeps denying every fresh dial).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revocation_landing_mid_handshake_refuses_final_session_publication() {
  common::init_tracing();

  let (issuer_keys, issuer_provider) = GatedKeys::wrap(ScriptedKeys::full_at(800_000));
  let issuer = start_node(issuer_provider).await;
  let issuer_endpoint = listen(&issuer).await;
  let issuer_id = local_id(&issuer.handle).await;

  let mut member = start_node(Arc::new(ScriptedKeys::full_at(801_000))).await;
  member.endpoint = listen(&member).await;
  common::merge_with_retry(&member.handle, &issuer.handle, issuer_endpoint.clone()).await;
  member.id = local_id(&member.handle).await;

  let member_key = trusted_key(&issuer.handle, &member.id).await;
  assert_eq!(
    trust_status(&issuer.handle, &member.id).await,
    Some(TrustStatus::Trusted),
    "the pre-revoke baseline must be a trusted, connected member"
  );

  // The interleave: arm the one-shot sign gate, then start the member's
  // reconnect dial. The issuer's responder parks at its identity-proof
  // signature — strictly after the binding checks admitted the handshake
  // — so at the observed park the handshake is authorized and mid-flight
  // exactly as the finding describes.
  issuer_keys.arm();
  let dial = {
    let handle = member.handle.clone();
    let endpoint = issuer_endpoint.clone();
    let peer = issuer_id.clone();
    tokio::spawn(async move { handle.connect(endpoint, peer).await.unwrap().wait().await })
  };
  let deadline = std::time::Instant::now() + Duration::from_secs(10);
  while !issuer_keys.is_parked() {
    assert!(
      std::time::Instant::now() < deadline,
      "the in-flight handshake never reached its identity-proof signature"
    );
    tokio::time::sleep(Duration::from_millis(10)).await;
  }

  // The revocation commits while the handshake is parked: it retires the
  // member's existing session and records the revoked subject inside the
  // shared authorization boundary.
  let mut events = issuer
    .handle
    .watch::<SessionChanged>(EventOptions::new())
    .unwrap();
  let outcome = issuer
    .handle
    .revoke(member.id.clone(), member_key.clone())
    .await
    .unwrap()
    .wait()
    .await
    .unwrap();
  assert!(!outcome.was_already_revoked());

  // Release the parked handshake: it completes on both sides (the member
  // publishes its own half), and the issuer's publication must be
  // refused — the revoked identity never survives as a fresh session.
  issuer_keys.open();
  let authenticated = tokio::time::timeout(Duration::from_secs(10), dial)
    .await
    .expect("the released handshake must complete")
    .expect("the dial task must not panic")
    .expect("the member's own half publishes");
  assert_eq!(authenticated, issuer_id);

  // The retirement announced exactly one session change (the revoked
  // identity's existing session); the refused publication must add none.
  let retired = tokio::time::timeout(Duration::from_secs(5), events.recv())
    .await
    .expect("the retirement must announce its session change")
    .expect("the event channel must stay open");
  match retired {
    EventReceive::Item(changed) => assert_eq!(changed.peer(), &member.id),
    _ => panic!("expected the retirement's session change"),
  }

  // Quiet window: without the shared boundary the completed handshake
  // would publish a fresh session for the revoked identity here,
  // announcing a second session change on the issuer.
  tokio::time::sleep(Duration::from_secs(2)).await;
  assert!(
    matches!(
      events.try_recv().unwrap(),
      EventReceive::Empty | EventReceive::Closed
    ),
    "no session may be published for the revoked identity"
  );

  // The durable state denies every fresh dial with the typed revocation
  // (guards against the test passing vacuously on a dial that never
  // reached publication for an unrelated reason).
  let error = issuer
    .handle
    .connect(member.endpoint.clone(), member.id.clone())
    .await
    .unwrap()
    .wait()
    .await
    .unwrap_err();
  assert_eq!(error.kind(), ErrorKind::Revoked);
  assert_eq!(
    trust_status(&issuer.handle, &member.id).await,
    Some(TrustStatus::Revoked)
  );

  issuer.handle.shutdown().await.unwrap();
  member.handle.shutdown().await.unwrap();
}
