//! Public-API integration test for the sync-delivered half of the
//! revocation/publication authorization boundary (audit 2026-10-23,
//! P1-11 follow-up).
//!
//! The local revoke effect already serializes its [commit → retire]
//! against session publication through the shared boundary. A revocation
//! tombstone that a peer applies from the reconciliation plane used to
//! bypass that boundary: it persisted the row and retired the subject's
//! current sessions while a handshake admitted before the tombstone was
//! still completing — and that handshake then published a fresh session
//! for the revoked identity. The interleave is made deterministic the
//! same way the local-path suite makes it: the peer's responder is
//! parked exactly at its identity-proof signature — strictly after the
//! binding checks that admitted the handshake — and the issuer's
//! revocation tombstone lands on the peer through ordinary sync while
//! it is parked.

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
/// authorization and is mid-flight. The gate is one-shot, so any later
/// signature (the node's own traffic after the release) passes straight
/// through.
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

/// The subject's trust status as `observer` sees it (None until the
/// binding converges).
async fn trust_status(observer: &NodeHandle, subject: &NodeId) -> Option<TrustStatus> {
  observer
    .trust()
    .list(PageSpec::first(64).unwrap())
    .await
    .unwrap()
    .items()
    .iter()
    .find(|view| view.node_id() == subject)
    .map(|view| view.status())
}

/// Polls until `observer` sees `subject` at `expected`, nudging the
/// observer's anti-entropy round each pass like the revocation suite's
/// convergence polls.
async fn await_trust(observer: &NodeHandle, subject: &NodeId, expected: TrustStatus, what: &str) {
  let deadline = std::time::Instant::now() + Duration::from_secs(30);
  loop {
    if trust_status(observer, subject).await == Some(expected) {
      return;
    }
    assert!(
      std::time::Instant::now() < deadline,
      "{what}: {subject} never reached {expected:?}"
    );
    observer.sync().await.unwrap();
    tokio::time::sleep(Duration::from_millis(5)).await;
  }
}

/// Drains every currently queued session change on the subscription.
fn drain_session_changes(events: &mut radiata::EventSubscription<SessionChanged>) {
  loop {
    match events.try_recv().unwrap() {
      EventReceive::Item(_) => continue,
      EventReceive::Empty | EventReceive::Closed => return,
      EventReceive::Lagged { .. } => panic!("test subscription lagged"),
      _ => panic!("unexpected event receive state"),
    }
  }
}

/// Audit P1-11's interleaving on the sync-delivered path, driven end to
/// end: the member's handshake with the peer passes its binding checks,
/// the issuer's revocation tombstone lands on the peer through ordinary
/// sync while the handshake is mid-flight, the handshake then completes
/// — and the session it would publish never survives under the revoked
/// identity (the tombstone lane and session publication serialize on the
/// same authorization boundary as the local revoke effect).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sync_delivered_revocation_landing_mid_handshake_refuses_session_publication() {
  common::init_tracing();

  // The issuer owns the member's binding and revokes it; the peer is the
  // node where the tombstone lands through sync while its handshake with
  // the member is mid-flight.
  let issuer = start_node(Arc::new(ScriptedKeys::full_at(800_000))).await;
  let issuer_endpoint = listen(&issuer).await;

  let (peer_keys, peer_provider) = GatedKeys::wrap(ScriptedKeys::full_at(801_000));
  let peer = start_node(peer_provider).await;
  let peer_endpoint = listen(&peer).await;
  let peer_id = local_id(&peer.handle).await;

  let mut member = start_node(Arc::new(ScriptedKeys::full_at(802_000))).await;
  member.endpoint = listen(&member).await;
  common::merge_with_retry(&member.handle, &issuer.handle, issuer_endpoint.clone()).await;
  member.id = local_id(&member.handle).await;
  common::merge_with_retry(&peer.handle, &issuer.handle, issuer_endpoint.clone()).await;

  // Cluster convergence before the interleave: the peer must trust the
  // member (its inbound handshake admission reads the binding) and the
  // member must trust the peer (its dial authenticates the responder).
  await_trust(&peer.handle, &member.id, TrustStatus::Trusted, "peer trust").await;
  await_trust(
    &member.handle,
    &peer_id,
    TrustStatus::Trusted,
    "member trust",
  )
  .await;

  // The member's trusted public key as the issuer observes it: the exact
  // binding the revoke commits against.
  let member_key = {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
      let page = issuer
        .handle
        .trust()
        .list(PageSpec::first(64).unwrap())
        .await
        .unwrap();
      if let Some(view) = page
        .items()
        .iter()
        .find(|view| view.node_id() == &member.id)
      {
        break view.public_key().clone();
      }
      assert!(
        std::time::Instant::now() < deadline,
        "the issuer must trust the member before the revoke"
      );
      issuer.handle.sync().await.unwrap();
      tokio::time::sleep(Duration::from_millis(5)).await;
    }
  };

  // The interleave: arm the one-shot sign gate, then start the member's
  // dial. The peer's responder parks at its identity-proof signature —
  // strictly after the binding checks admitted the handshake — so at the
  // observed park the handshake is authorized and mid-flight exactly as
  // the finding describes.
  let mut peer_sessions = peer
    .handle
    .watch::<SessionChanged>(EventOptions::new())
    .unwrap();
  peer_keys.arm();
  let dial = {
    let handle = member.handle.clone();
    let endpoint = peer_endpoint.clone();
    let expected = peer_id.clone();
    tokio::spawn(async move {
      handle
        .connect(endpoint, expected)
        .await
        .unwrap()
        .wait()
        .await
    })
  };
  let deadline = std::time::Instant::now() + Duration::from_secs(10);
  while !peer_keys.is_parked() {
    assert!(
      std::time::Instant::now() < deadline,
      "the in-flight handshake never reached its identity-proof signature"
    );
    tokio::time::sleep(Duration::from_millis(10)).await;
  }

  // The revocation commits on the issuer (the local lane), then its
  // tombstone lands on the peer through ordinary sync — durable
  // revocation observed while the handshake is still parked.
  let outcome = issuer
    .handle
    .revoke(member.id.clone(), member_key)
    .await
    .unwrap()
    .wait()
    .await
    .unwrap();
  assert!(!outcome.was_already_revoked());
  await_trust(
    &peer.handle,
    &member.id,
    TrustStatus::Revoked,
    "tombstone landing",
  )
  .await;
  assert!(
    peer_keys.is_parked(),
    "the handshake must still be mid-flight when the tombstone lands"
  );

  // Everything the peer published or retired before the tombstone (the
  // recovery lane may have raced a session in) is pre-revocation
  // history: drain it, because the assertion below is about sessions
  // that would arrive after the boundary closed.
  drain_session_changes(&mut peer_sessions);

  // Release the parked handshake: it completes on both sides (the member
  // publishes its own half), and the peer's publication must be refused
  // — the revoked identity never survives as a fresh session.
  peer_keys.open();
  let authenticated = tokio::time::timeout(Duration::from_secs(10), dial)
    .await
    .expect("the released handshake must complete")
    .expect("the dial task must not panic")
    .expect("the member's own half publishes");
  assert_eq!(authenticated, peer_id);

  // Quiet window: without the shared boundary the completed handshake
  // would publish a fresh session for the revoked identity here,
  // announcing a session change on the peer.
  tokio::time::sleep(Duration::from_secs(2)).await;
  assert!(
    matches!(
      peer_sessions.try_recv().unwrap(),
      EventReceive::Empty | EventReceive::Closed
    ),
    "no session may be published for the revoked identity"
  );

  // The durable state denies every fresh dial with the typed revocation
  // (guards against the test passing vacuously on a dial that never
  // reached publication for an unrelated reason).
  let error = peer
    .handle
    .connect(member.endpoint.clone(), member.id.clone())
    .await
    .unwrap()
    .wait()
    .await
    .unwrap_err();
  assert_eq!(error.kind(), ErrorKind::Revoked);
  assert_eq!(
    trust_status(&peer.handle, &member.id).await,
    Some(TrustStatus::Revoked)
  );

  issuer.handle.shutdown().await.unwrap();
  peer.handle.shutdown().await.unwrap();
  member.handle.shutdown().await.unwrap();
}
