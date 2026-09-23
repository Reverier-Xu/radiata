//! The transport chaos lane: a 64-node cluster assembled over a mixed
//! star-plus-bus topology where every dial picks one of the four
//! transports at random, then a seeded fuzz churn drives the mesh
//! through disconnects, cross-protocol extra links, graceful restarts,
//! and the leave-and-return contract: a node that leaves the cluster
//! comes back through a *different* protocol than the edge it used
//! before, reconnecting to either the same member or a different one.
//!
//! The four transports in play: the built-in direct `tls://`, the
//! WebSocket `wss://`, the plaintext `tcp://`, and a test-owned
//! `unix://` custom transport registered through the public
//! [`radiata::CustomTransport`] surface (a Unix domain socket medium,
//! the same recipe the chat example ships). Every node listens on all
//! four, so every member advertises one dialable endpoint per scheme,
//! and the recovery plane's first-endpoint dials themselves cross
//! protocols as a side effect of the seeded listener order.
//!
//! Convergence contract under churn: exactly the surviving members plus
//! rejoiners stay `Active` everywhere, the left identities stay
//! tombstoned as `Left`, and relayed packets still cross the star into
//! a bus line multi-hop after the churn window. The relay gates are
//! deliberately a few hops, not the full seventeen-hop tail: a starved
//! runner's per-hop latency accumulates with hop count, and the lane
//! must fail fast (every await is bounded) instead of wedging a CI job
//! past its timeout.
//
// Unix-only: the fourth transport is a Unix domain socket medium. The
// whole lane compiles to nothing elsewhere, so the cross-platform
// gates stay green.
#![cfg(unix)]

use std::{
  os::unix::fs::FileTypeExt,
  path::{Path, PathBuf},
  sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
  },
  time::Duration,
};

use radiata::{
  BoxFuture, ConnectMember, CustomListener, CustomTransport, DisconnectPeer, Endpoint, Error,
  FeatureTag, GetLocalNode, GetRecovery, IssueMergeCredential, LeaveCluster, Listen, MemberStatus,
  MergeCluster, MergeCredential, NodeBuilder, NodeConfig, NodeHandle, NodeId, PacketConsumer,
  PageMembers, PageSpec, ProtocolDefinition, ProtocolTag, Result, RoutingPolicy, ShutdownReason,
  StreamMetadata, StreamPolicy, StreamTarget, TransportName, TransportStream, WaitForShutdown,
};
mod common;

use common::MemoryStorageFactory;

/// Cluster size: one center, twelve star spokes, three bus lines of
/// seventeen. 1 + 12 + 3 * 17 = 64.
const NODES: usize = 64;
const STAR_SPOKES: usize = 12;
const BUS_LINES: usize = 3;
/// The per-phase budgets assume a contended machine, not a quiet one:
/// 63 joins, 256 listeners, and the churn window share one runtime.
const CONVERGE_TIMEOUT: Duration = Duration::from_secs(240);
const MERGE_TIMEOUT: Duration = Duration::from_secs(300);
/// The per-command ceiling: a wedged runtime must fail the lane loudly
/// instead of hanging the CI job past its timeout. Generous enough that
/// a merely starved runner never trips it.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(120);
/// Bounded retry budget for a restart racing the previous runtime's
/// storage release (the store unlocks when the old runtime's task
/// drops it, which can land a tick after the shutdown observation).
const RESTART_TIMEOUT: Duration = Duration::from_secs(15);

/// The protocol tag of the relay-check consumer.
const ECHO_PROTOCOL: &str = "radiata.woooo.tech/protocols/chaos-echo";
const ECHO_OWNING_FEATURE: &str = "radiata.woooo.tech/features/session-core";

/// The four transports every node advertises, in canonical order. The
/// index doubles as the seeded dial selector.
const SCHEMES: [&str; 4] = ["tls", "wss", "tcp", "unix"];

/// A deterministic xorshift64* generator: the chaos is seeded, so a
/// failing seed reproduces exactly.
#[derive(Debug)]
struct Chaos(u64);

impl Chaos {
  fn new(seed: u64) -> Self {
    Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).max(1))
  }

  fn next_u64(&mut self) -> u64 {
    self.0 ^= self.0 >> 12;
    self.0 ^= self.0 << 25;
    self.0 ^= self.0 >> 27;
    self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
  }

  /// A scheme index for the next dial.
  fn scheme(&mut self) -> usize {
    (self.next_u64() % SCHEMES.len() as u64) as usize
  }

  /// A member index below `bound`.
  fn below(&mut self, bound: usize) -> usize {
    (self.next_u64() % bound as u64) as usize
  }
}

// ---- The test-owned unix:// transport -------------------------------------
//
// A Unix domain socket medium over the public custom-transport surface.
// The kernel routes by socket path, so the transport itself is
// stateless; the listener owns its path, wakes a pending accept on
// close, and unlinks the socket on drop so a restart rebinds cleanly.

/// Extracts the socket path from a `unix://` endpoint's opaque
/// remainder (the transport's own address grammar).
fn socket_path(endpoint: &Endpoint) -> Result<PathBuf> {
  let opaque = endpoint
    .opaque()
    .ok_or_else(|| Error::caller("unix endpoint without a socket path"))?;
  Ok(PathBuf::from(opaque))
}

/// One established Unix socket connection. The newtype exists because
/// [`TransportStream`] is a foreign trait over a foreign type.
#[derive(Debug)]
struct UnixStream(tokio::net::UnixStream);

impl TransportStream for UnixStream {}

impl tokio::io::AsyncRead for UnixStream {
  fn poll_read(
    mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>,
    buf: &mut tokio::io::ReadBuf<'_>,
  ) -> std::task::Poll<std::io::Result<()>> {
    std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
  }
}

impl tokio::io::AsyncWrite for UnixStream {
  fn poll_write(
    mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8],
  ) -> std::task::Poll<std::io::Result<usize>> {
    std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
  }

  fn poll_flush(
    mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>,
  ) -> std::task::Poll<std::io::Result<()>> {
    std::pin::Pin::new(&mut self.0).poll_flush(cx)
  }

  fn poll_shutdown(
    mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>,
  ) -> std::task::Poll<std::io::Result<()>> {
    std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
  }
}

/// The stateless custom transport: bind and connect by socket path.
#[derive(Debug, Default)]
struct UnixTransport;

impl CustomTransport for UnixTransport {
  fn bind(&self, endpoint: Endpoint) -> BoxFuture<'static, Result<Box<dyn CustomListener>>> {
    Box::pin(async move {
      let path = socket_path(&endpoint)?;
      let listener =
        tokio::net::UnixListener::bind(&path).map_err(|_| Error::caller("unix socket bind"))?;
      Ok(Box::new(UnixListener {
        path,
        endpoint,
        listener,
        shutdown: Arc::new(tokio::sync::Notify::new()),
      }) as Box<dyn CustomListener>)
    })
  }

  fn connect(&self, endpoint: Endpoint) -> BoxFuture<'static, Result<Box<dyn TransportStream>>> {
    Box::pin(async move {
      let path = socket_path(&endpoint)?;
      let stream = tokio::net::UnixStream::connect(&path)
        .await
        .map_err(|_| Error::caller("unix socket connect"))?;
      Ok(Box::new(UnixStream(stream)) as Box<dyn TransportStream>)
    })
  }
}

#[derive(Debug)]
struct UnixListener {
  path: PathBuf,
  endpoint: Endpoint,
  listener: tokio::net::UnixListener,
  shutdown: Arc<tokio::sync::Notify>,
}

impl Drop for UnixListener {
  fn drop(&mut self) {
    // Release the filesystem name with the socket so a restart on the
    // same path rebinds; ignore the race where a successor already
    // rebound the same path.
    if self
      .path
      .metadata()
      .is_ok_and(|metadata| metadata.file_type().is_socket())
    {
      let _ = std::fs::remove_file(&self.path);
    }
  }
}

impl CustomListener for UnixListener {
  fn local_endpoint(&self) -> Endpoint {
    self.endpoint.clone()
  }

  fn accept(&self) -> BoxFuture<'_, Result<Box<dyn TransportStream>>> {
    Box::pin(async move {
      loop {
        let accepted = tokio::select! {
          _ = self.shutdown.notified() => {
            return Err(Error::caller("unix listener closed"));
          }
          accepted = self.listener.accept() => accepted,
        };
        match accepted {
          Ok((stream, _peer)) => {
            return Ok(Box::new(UnixStream(stream)) as Box<dyn TransportStream>);
          }
          Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
          Err(_) => return Err(Error::caller("unix socket accept")),
        }
      }
    })
  }

  fn close(&self) -> BoxFuture<'_, Result<()>> {
    self.shutdown.notify_waiters();
    Box::pin(async { Ok(()) })
  }
}

// ---- Keys with working deletion -------------------------------------------
//
// The leave flow's custody lane replaces the identity and deletes the
// old key, so the provider here keeps working deletion and idempotent
// create (the same custody contract tests/leave.rs models).

/// One node slot's key custody: deterministic seeds, working deletion.
#[derive(Debug, Default)]
struct ChaosKeys {
  records: Mutex<std::collections::BTreeMap<Vec<u8>, ed25519_dalek::SigningKey>>,
  operations: Mutex<std::collections::BTreeMap<Vec<u8>, Vec<u8>>>,
  deleted: Mutex<Vec<Vec<u8>>>,
  next: AtomicUsize,
}

impl ChaosKeys {
  /// A provider whose generated keys start from `base`, so two slots
  /// never collide on an identity.
  fn with_base(base: u64) -> Self {
    let keys = Self::default();
    keys.next.store(base as usize, Ordering::SeqCst);
    keys
  }

  fn seed_for(index: usize) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(
      &(index as u64).to_le_bytes().repeat(4)[..32]
        .try_into()
        .expect("fixed size"),
    )
  }

  fn created(handle: &[u8], signing: &ed25519_dalek::SigningKey) -> radiata::KeyCreateState {
    radiata::KeyCreateState::Present(radiata::CreatedKey::new(
      radiata::KeyHandle::from_provider_bytes(Arc::from(handle.to_vec())).expect("valid handle"),
      radiata::PublicKey::from_bytes(signing.verifying_key().to_bytes()),
    ))
  }

  fn create_at(&self, operation: &radiata::KeyOperationId) -> radiata::KeyCreateState {
    let mut operations = self.operations.lock().unwrap();
    if let Some(handle) = operations.get(operation.as_str().as_bytes()) {
      let records = self.records.lock().unwrap();
      let signing = &records[handle];
      return Self::created(handle, signing);
    }
    let index = self.next.fetch_add(1, Ordering::SeqCst);
    let signing = Self::seed_for(index);
    let handle = format!("chaos-handle-{index}").into_bytes();
    let created = Self::created(&handle, &signing);
    operations.insert(operation.as_str().as_bytes().to_vec(), handle.clone());
    self.records.lock().unwrap().insert(handle, signing);
    created
  }
}

impl radiata::extension::KeyProvider for ChaosKeys {
  fn capabilities(&self) -> radiata::KeyCapabilities {
    radiata::KeyCapabilities::new()
      .ed25519(true)
      .reconciliation(true)
      .deletion(true)
  }

  fn create_ed25519<'a>(
    &'a self, operation: &'a radiata::KeyOperationId,
  ) -> BoxFuture<'a, Result<radiata::KeyCreateState>> {
    Box::pin(async move { Ok(self.create_at(operation)) })
  }

  fn reconcile_create<'a>(
    &'a self, operation: &'a radiata::KeyOperationId,
  ) -> BoxFuture<'a, Result<radiata::KeyCreateState>> {
    Box::pin(async move {
      let operations = self.operations.lock().unwrap();
      let Some(handle) = operations.get(operation.as_str().as_bytes()) else {
        return Ok(radiata::KeyCreateState::Absent);
      };
      let records = self.records.lock().unwrap();
      let Some(signing) = records.get(handle) else {
        return Ok(radiata::KeyCreateState::Absent);
      };
      Ok(Self::created(handle, signing))
    })
  }

  fn public_key<'a>(
    &'a self, handle: &'a radiata::KeyHandle,
  ) -> BoxFuture<'a, Result<radiata::PublicKey>> {
    let result = self
      .records
      .lock()
      .unwrap()
      .get(handle.expose_provider_handle())
      .map(|signing| radiata::PublicKey::from_bytes(signing.verifying_key().to_bytes()))
      .ok_or_else(|| {
        Error::provider(
          radiata::ProviderErrorKind::Internal,
          radiata::ProviderErrorContext::KeyPublicKey,
        )
      });
    Box::pin(async move { result })
  }

  fn sign<'a>(
    &'a self, handle: &'a radiata::KeyHandle, message: &'a [u8],
  ) -> BoxFuture<'a, Result<radiata::Signature>> {
    use ed25519_dalek::Signer as _;
    let result = self
      .records
      .lock()
      .unwrap()
      .get(handle.expose_provider_handle())
      .map(|signing| radiata::Signature::from_bytes(signing.sign(message).to_bytes()))
      .ok_or_else(|| {
        Error::provider(
          radiata::ProviderErrorKind::Internal,
          radiata::ProviderErrorContext::KeySign,
        )
      });
    Box::pin(async move { result })
  }

  fn delete<'a>(
    &'a self, _operation: &'a radiata::KeyOperationId, handle: &'a radiata::KeyHandle,
  ) -> BoxFuture<'a, Result<radiata::KeyDeleteState>> {
    let deleted = self
      .records
      .lock()
      .unwrap()
      .remove(handle.expose_provider_handle())
      .is_some();
    if deleted {
      self
        .deleted
        .lock()
        .unwrap()
        .push(handle.expose_provider_handle().to_vec());
    }
    let state = if deleted {
      radiata::KeyDeleteState::Present
    } else {
      radiata::KeyDeleteState::Absent
    };
    Box::pin(async move { Ok(state) })
  }

  fn reconcile_delete<'a>(
    &'a self, _operation: &'a radiata::KeyOperationId, handle: &'a radiata::KeyHandle,
  ) -> BoxFuture<'a, Result<radiata::KeyDeleteState>> {
    let state = if self
      .deleted
      .lock()
      .unwrap()
      .iter()
      .any(|record| record.as_slice() == handle.expose_provider_handle())
    {
      radiata::KeyDeleteState::Present
    } else {
      radiata::KeyDeleteState::Absent
    };
    Box::pin(async move { Ok(state) })
  }
}

// ---- The cluster harness ---------------------------------------------------

/// Counts fully drained relay-check packets.
#[derive(Debug, Default)]
struct EchoCollector {
  packets: Mutex<usize>,
}

impl PacketConsumer for EchoCollector {
  fn accept<'a>(
    &'a self, mut packet: radiata::IncomingStream,
  ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
    Box::pin(async move {
      let mut body = packet.body();
      while std::future::poll_fn(|cx| body.as_mut().poll_next(cx))
        .await
        .transpose()?
        .is_some()
      {}
      *self.packets.lock().unwrap() += 1;
      Ok(())
    })
  }
}

fn echo_body(chunk: Arc<[u8]>) -> impl futures_core::Stream<Item = Result<Arc<[u8]>>> + Send {
  futures_util::stream::once(async move { Ok(chunk) })
}

/// One node slot: the handle plus everything a restart or rejoin needs.
/// The storage factory and the key provider are per-slot and reused
/// across lifetimes, so a restart resumes the same identity (and a
/// post-leave restart boots the replacement identity).
struct Slot {
  handle: Option<NodeHandle>,
  storage: Arc<MemoryStorageFactory>,
  keys: Arc<ChaosKeys>,
  collector: Arc<EchoCollector>,
  id: Option<NodeId>,
  /// One dialable endpoint per scheme, in [`SCHEMES`] order.
  endpoints: Vec<Endpoint>,
}

impl Slot {
  fn handle(&self) -> &NodeHandle {
    self.handle.as_ref().expect("slot is running")
  }

  fn id(&self) -> &NodeId {
    self.id.as_ref().expect("slot identity resolved")
  }

  /// The dialable endpoint for one scheme index.
  fn endpoint(&self, scheme: usize) -> &Endpoint {
    &self.endpoints[scheme]
  }
}

fn init_tracing() {
  use std::sync::Once;
  static INIT: Once = Once::new();
  INIT.call_once(|| {
    tracing_subscriber::fmt()
      .with_env_filter(tracing_subscriber::EnvFilter::new("radiata=debug"))
      .with_test_writer()
      .init();
  });
}

fn node_config() -> NodeConfig {
  // The shipped defaults, unpinned: the chaos lane is the evidence that
  // the single timing profile (one anti-entropy tick per second,
  // recovery fan-out sixteen with a two-second initial backoff, 30 s
  // authentication deadline) survives a starved two-vcpu-class runner.
  NodeConfig::new()
}

fn runtime_extensions(collector: &Arc<EchoCollector>) -> radiata::ExtensionRegistry {
  let mut extensions = radiata::ExtensionRegistry::new();
  extensions
    .register_transport(
      TransportName::parse("unix").expect("static scheme name"),
      Arc::new(UnixTransport),
    )
    .expect("register unix transport");
  extensions
    .register_protocol(
      ProtocolDefinition::new(
        ProtocolTag::parse(ECHO_PROTOCOL).expect("static protocol tag"),
        FeatureTag::parse(ECHO_OWNING_FEATURE).expect("static feature tag"),
      ),
      Arc::clone(collector) as Arc<dyn PacketConsumer>,
    )
    .expect("register echo protocol");
  extensions
}

fn unix_endpoint(sockets: &Path, index: usize) -> Endpoint {
  Endpoint::parse(&format!(
    "unix://{}",
    sockets.join(format!("node-{index}.sock")).display()
  ))
  .expect("unix endpoint")
}

/// Binds the four listeners of one node, one per scheme.
async fn listen_all(handle: &NodeHandle, sockets: &Path, index: usize) -> Vec<Endpoint> {
  let mut endpoints = Vec::with_capacity(SCHEMES.len());
  for scheme in SCHEMES {
    let requested = match scheme {
      "unix" => unix_endpoint(sockets, index),
      _ => Endpoint::parse(&format!("{scheme}://127.0.0.1:0")).expect("builtin endpoint"),
    };
    // A restart may race the previous runtime's listener teardown for
    // the same unix path; the bind retries briefly and bounded.
    let deadline = std::time::Instant::now() + RESTART_TIMEOUT;
    let listener = loop {
      match bounded(
        handle.command(Listen::new(requested.clone())),
        "listen {scheme}",
      )
      .await
      {
        Ok(listener) => break listener,
        Err(_) if std::time::Instant::now() < deadline => {
          tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Err(error) => panic!("listen {scheme} failed persistently: {error:?}"),
      }
    };
    endpoints.push(listener.endpoint().clone());
  }
  endpoints
}

async fn start_slot(index: usize, sockets: &Path) -> Slot {
  let storage: Arc<MemoryStorageFactory> =
    Arc::new(MemoryStorageFactory::new(common::required_capabilities()));
  let keys = Arc::new(ChaosKeys::with_base(700_000 + (index as u64) * 1_000));
  let collector = Arc::new(EchoCollector::default());
  let handle =
    NodeBuilder::new(Arc::clone(&storage) as Arc<dyn radiata::extension::StorageFactory>)
      .keys(Arc::clone(&keys) as Arc<dyn radiata::extension::KeyProvider>)
      .config(node_config())
      .extensions(runtime_extensions(&collector))
      .start()
      .await
      .expect("node start");
  let endpoints = listen_all(&handle, sockets, index).await;
  Slot {
    handle: Some(handle),
    storage,
    keys,
    collector,
    id: None,
    endpoints,
  }
}

/// Restarts a slot on its own storage and keys. After a graceful
/// [`radiata::Shutdown`] the identity is the same one; after a
/// [`LeaveCluster`] the replacement identity boots instead.
async fn restart_slot(slot: &mut Slot, sockets: &Path, index: usize) {
  let storage = Arc::clone(&slot.storage);
  let keys = Arc::clone(&slot.keys);
  let collector = Arc::clone(&slot.collector);
  // The old runtime releases its store when its task drops it, which
  // can land a tick after the shutdown observation; retry bounded.
  let deadline = std::time::Instant::now() + RESTART_TIMEOUT;
  let handle = loop {
    match NodeBuilder::new(Arc::clone(&storage) as Arc<dyn radiata::extension::StorageFactory>)
      .keys(Arc::clone(&keys) as Arc<dyn radiata::extension::KeyProvider>)
      .config(node_config())
      .extensions(runtime_extensions(&collector))
      .start()
      .await
    {
      Ok(handle) => break handle,
      Err(_) if std::time::Instant::now() < deadline => {
        tokio::time::sleep(Duration::from_millis(50)).await;
      }
      Err(error) => panic!("node restart failed persistently: {error:?}"),
    }
  };
  slot.endpoints = listen_all(&handle, sockets, index).await;
  slot.handle = Some(handle);
}

/// Retry backoff for admission-sensitive commands: doubles from 250 ms,
/// caps at 4 s (the fixed merge policy caps one source at sixteen
/// attempts per minute; a tighter storm would trip it).
fn retry_backoff(attempts: u32) -> Duration {
  let shift = attempts.min(5);
  Duration::from_millis(250_u64.saturating_mul(1_u64 << shift)).min(Duration::from_secs(4))
}

/// Bounds every runtime interaction: a wedged supervisor (dead control
/// loop, poisoned internal channel) must fail the lane with a named
/// call instead of hanging the CI job past its timeout. The wrapper is
/// deliberately applied at every `handle` call site — the in-test
/// convergence timeouts below cannot fire while a single await inside
/// them never resolves.
async fn bounded<F: std::future::Future>(future: F, what: &str) -> F::Output {
  match tokio::time::timeout(COMMAND_TIMEOUT, future).await {
    Ok(output) => output,
    Err(_) => panic!("wedged runtime: {what} did not answer within {COMMAND_TIMEOUT:?}"),
  }
}

/// The live join credential of one node (any number of joins until
/// rotation or expiry, so receivers need no per-join rotation).
async fn issue_credential(slot: &Slot) -> String {
  let issued = bounded(
    slot.handle().command(IssueMergeCredential::new()),
    "issue merge credential",
  )
  .await
  .expect("issue merge credential");
  issued.credential().expose_secret().to_owned()
}

/// One join with bounded retries; a transient refusal consumes no
/// credential, so the same secret retries.
async fn merge_with_retry(
  joiner: &Slot, endpoint: &Endpoint, secret: &str, what: &str,
) -> radiata::MergeView {
  let deadline = std::time::Instant::now() + MERGE_TIMEOUT;
  let mut attempts = 0_u32;
  loop {
    attempts = attempts.wrapping_add(1);
    match bounded(
      joiner.handle().command(MergeCluster::new(
        endpoint.clone(),
        MergeCredential::parse(secret).expect("valid credential"),
      )),
      "merge join",
    )
    .await
    {
      Ok(view) => return view,
      Err(_) if std::time::Instant::now() < deadline => {
        tokio::time::sleep(retry_backoff(attempts)).await;
      }
      Err(error) => panic!("{what}: merge failed persistently: {error:?}"),
    }
  }
}

/// One member reconnect with bounded retries.
async fn connect_member_with_retry(
  node: &Slot, endpoint: &Endpoint, peer: &NodeId, what: &str,
) -> NodeId {
  let deadline = std::time::Instant::now() + MERGE_TIMEOUT;
  let mut attempts = 0_u32;
  loop {
    attempts = attempts.wrapping_add(1);
    match bounded(
      node
        .handle()
        .command(ConnectMember::new(endpoint.clone(), peer.clone())),
      "member reconnect",
    )
    .await
    {
      Ok(authenticated) => return authenticated,
      Err(_) if std::time::Instant::now() < deadline => {
        tokio::time::sleep(retry_backoff(attempts)).await;
      }
      Err(error) => panic!("{what}: member reconnect failed persistently: {error:?}"),
    }
  }
}

/// Every member view one node currently holds, paged through cursors.
async fn member_views(slot: &Slot) -> Vec<radiata::MemberView> {
  let mut views = Vec::new();
  let mut cursor = None;
  loop {
    let page = match cursor {
      None => slot
        .handle()
        .query(PageMembers::new(PageSpec::first(NODES).expect("page size")))
        .await
        .expect("member page"),
      Some(cursor) => slot
        .handle()
        .query(PageMembers::new(
          PageSpec::after(cursor, NODES).expect("page size"),
        ))
        .await
        .expect("member page"),
    };
    let next = page.next().cloned();
    views.extend_from_slice(page.items());
    match next {
      Some(next_cursor) => cursor = Some(next_cursor),
      None => return views,
    }
  }
}

/// The number of `Active` members one node currently sees.
async fn active_members(slot: &Slot) -> usize {
  member_views(slot)
    .await
    .iter()
    .filter(|member| member.status() == MemberStatus::Active)
    .count()
}

/// The left tombstones one node still carries.
async fn left_members(slot: &Slot) -> Vec<NodeId> {
  member_views(slot)
    .await
    .iter()
    .filter(|member| member.status() == MemberStatus::Left)
    .map(|member| member.node_id().clone())
    .collect()
}

/// Drives deterministic sync rounds and waits until every listed node
/// reports `expected` active members and a connected recovery plane.
async fn wait_converged(slots: &[Slot], expected: usize, what: &str) {
  let indices: Vec<usize> = (0..slots.len()).collect();
  wait_converged_indices(slots, &indices, expected, what).await;
}

async fn wait_converged_indices(slots: &[Slot], indices: &[usize], expected: usize, what: &str) {
  let deadline = std::time::Instant::now() + CONVERGE_TIMEOUT;
  let mut last_report = std::time::Instant::now() - CONVERGE_TIMEOUT;
  loop {
    for index in indices {
      bounded(
        slots[*index].handle().command(radiata::RunSyncRound::new()),
        "sync round",
      )
      .await
      .expect("sync round");
    }
    let mut ready = true;
    for index in indices {
      let slot = &slots[*index];
      if active_members(slot).await != expected {
        ready = false;
        break;
      }
      let recovery = bounded(slot.handle().query(GetRecovery::new()), "recovery view")
        .await
        .expect("recovery view");
      if !recovery.is_connected() {
        ready = false;
        break;
      }
    }
    if ready {
      return;
    }
    // Diagnose the stragglers every ten seconds so a timeout names the
    // stuck nodes instead of leaving an anonymous hole.
    if last_report.elapsed() >= Duration::from_secs(10) {
      last_report = std::time::Instant::now();
      for index in indices {
        let slot = &slots[*index];
        let recovery = bounded(
          slot.handle().query(GetRecovery::new()),
          "recovery view diag",
        )
        .await
        .expect("recovery view");
        if !recovery.is_connected() || active_members(slot).await != expected {
          let sessions = slot
            .handle()
            .query(radiata::PageSessions::new(
              PageSpec::first(NODES).expect("page size"),
            ))
            .await
            .map(|page| page.items().len())
            .unwrap_or(0);
          eprintln!(
            "CONVERGE {what}: node {index} active={} expected={expected} recovery_connected={} sessions={sessions}",
            active_members(slot).await,
            recovery.is_connected(),
          );
        }
      }
    }
    assert!(
      std::time::Instant::now() < deadline,
      "{what}: convergence timeout after {CONVERGE_TIMEOUT:?}"
    );
    tokio::time::sleep(Duration::from_millis(150)).await;
  }
}

/// Sends one relay-check packet `from` to `to` and waits for it to land
/// in `to`'s collector. Routed over the current mesh: distant pairs
/// traverse the star or the bus through the default next-hop policy. A
/// send that races a churn wave surfaces as StreamInterrupted (delivery
/// is at-most-once per attempt, by contract); the retry loop re-sends
/// until the packet lands, which is the same customer-side pattern the
/// library documents for real traffic.
async fn relay_packet(from: &Slot, to: &Slot, what: &str) {
  let before = *to.collector.packets.lock().unwrap();
  // A long relay (bus tail to center crosses seventeen hops) on a
  // starved two-vcpu runner legitimately takes tens of seconds per
  // attempt; the retry budget outlives that, not the other way round.
  let deadline = std::time::Instant::now() + CONVERGE_TIMEOUT;
  let mut attempts = 0_u32;
  loop {
    attempts = attempts.wrapping_add(1);
    let packet = from
      .handle()
      .open_stream(
        StreamTarget::Exact(to.id().clone()),
        ProtocolTag::parse(ECHO_PROTOCOL).expect("static protocol tag"),
        StreamPolicy::new(RoutingPolicy::Direct, NODES as u32).expect("valid policy"),
        StreamMetadata::new(),
      )
      .expect("open relay stream");
    let sent = bounded(
      packet.send_sync(echo_body(Arc::from(what.as_bytes()))),
      "relay send",
    )
    .await;
    match sent {
      Ok(_ack) => {}
      // The churn may interrupt the carrying session mid-send; a fresh
      // attempt rides the healed mesh.
      Err(_) if std::time::Instant::now() < deadline => {
        tokio::time::sleep(retry_backoff(attempts)).await;
        continue;
      }
      Err(error) => panic!("{what}: relay send failed persistently: {error:?}"),
    }
    if *to.collector.packets.lock().unwrap() > before {
      return;
    }
    assert!(
      std::time::Instant::now() < deadline,
      "{what}: relayed packet never arrived"
    );
    tokio::time::sleep(Duration::from_millis(20)).await;
  }
}

/// Shuts one slot down (the shutdown must already have been requested)
/// and waits for the reported reason.
async fn await_shutdown(slot: &mut Slot) -> ShutdownReason {
  let reason = bounded(slot.handle().query(WaitForShutdown::new()), "shutdown wait")
    .await
    .expect("shutdown wait");
  slot.handle = None;
  reason
}

/// The designed mixed topology: node 0 is the star center; nodes
/// 1..=STAR_SPOKES are its spokes; the rest form BUS_LINES chains whose
/// heads dial the center and whose bodies dial their predecessor. Each
/// tuple is (dialer, receiver); the assembly processes them in order,
/// so every receiver is already a member when its dialer joins.
fn designed_edges() -> Vec<(usize, usize)> {
  let mut edges = Vec::new();
  for spoke in 1..=STAR_SPOKES {
    edges.push((spoke, 0));
  }
  let line_length = (NODES - 1 - STAR_SPOKES) / BUS_LINES;
  for line in 0..BUS_LINES {
    let head = STAR_SPOKES + 1 + line * line_length;
    edges.push((head, 0));
    for member in head + 1..head + line_length {
      edges.push((member, member - 1));
    }
  }
  edges
}

/// The parent (designed receiver) of every non-center node.
fn designed_parent() -> Vec<usize> {
  let mut parent = vec![0; NODES];
  for (dialer, receiver) in designed_edges() {
    parent[dialer] = receiver;
  }
  parent
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn sixty_four_node_mixed_transport_chaos() {
  init_tracing();
  let sockets = tempfile::tempdir().expect("socket dir");
  let mut rng = Chaos::new(0xC400_0000_0040_0001);

  // ---- Assembly: 64 nodes, 4 transports each, mixed star+bus -------
  let mut slots: Vec<Slot> = Vec::with_capacity(NODES);
  for index in 0..NODES {
    slots.push(start_slot(index, sockets.path()).await);
  }
  for slot in &mut slots {
    let id = bounded(slot.handle().query(GetLocalNode::new()), "local node")
      .await
      .expect("local node")
      .node_id()
      .clone();
    slot.id = Some(id);
  }
  let ids: Vec<NodeId> = slots.iter().map(|slot| slot.id().clone()).collect();

  // Every edge dials a seeded-random scheme of the receiver's four.
  let mut edge_scheme: Vec<Option<usize>> = vec![None; NODES];
  for (dialer, receiver) in designed_edges() {
    let scheme = rng.scheme();
    let secret = issue_credential(&slots[receiver]).await;
    let view = merge_with_retry(
      &slots[dialer],
      slots[receiver].endpoint(scheme),
      &secret,
      &format!("edge {dialer}->{receiver} over {}", SCHEMES[scheme]),
    )
    .await;
    assert_eq!(view.node(), &ids[dialer], "edge {dialer}->{receiver}");
    assert_eq!(view.peer(), &ids[receiver], "edge {dialer}->{receiver}");
    edge_scheme[dialer] = Some(scheme);
  }
  // The seeded assembly must actually span the transport space.
  let mut used_schemes: Vec<usize> = edge_scheme.iter().filter_map(|scheme| *scheme).collect();
  used_schemes.sort_unstable();
  used_schemes.dedup();
  assert!(
    used_schemes.len() >= 2,
    "the seeded assembly only used one transport scheme"
  );

  wait_converged(&slots, NODES, "assembly").await;
  for slot in &slots {
    assert!(
      left_members(slot).await.is_empty(),
      "no tombstones exist after assembly"
    );
  }
  relay_packet(&slots[13], &slots[0], "assembly relay").await;

  // ---- Fuzz churn ---------------------------------------------------
  //
  // A seeded operation schedule over the converged cluster. The leave
  // rounds cover the required reconnect shapes: same-member return and
  // different-member return, each through a different protocol than
  // the departed edge used.

  // (1) Kicks: disconnect a designed edge. A tail whose only edge dies
  // heals through the recovery plane (crossing protocols, because heal
  // dials target the first published endpoint of whichever member wins
  // the race); a cut with surviving edges must not disturb membership.
  let kicks: [(usize, usize); 6] = [(1, 0), (30, 0), (40, 39), (60, 59), (5, 0), (20, 19)];
  for (step, (from, to)) in kicks.into_iter().enumerate() {
    let what = format!("kick {step} ({from}->{to})");
    // Absence after a concurrent prune is benign; a real failure
    // surfaces through the convergence check below.
    let _ = bounded(
      slots[from]
        .handle()
        .command(DisconnectPeer::new(ids[to].clone())),
      "disconnect peer",
    )
    .await;
    wait_converged(&slots, NODES, &what).await;
  }

  // (2) Extra cross-protocol links: ConnectMember dials an explicit
  // scheme of an explicit member, growing the mesh beyond the design.
  for step in 0..6 {
    let from = rng.below(NODES);
    let mut to = rng.below(NODES);
    while to == from {
      to = rng.below(NODES);
    }
    let scheme = rng.scheme();
    let what = format!("extra link {step} ({from}->{to} over {})", SCHEMES[scheme]);
    let authenticated =
      connect_member_with_retry(&slots[from], slots[to].endpoint(scheme), &ids[to], &what).await;
    assert_eq!(authenticated, ids[to], "{what}");
  }
  wait_converged(&slots, NODES, "extra links").await;

  // (3) Leave and return. The leaver is a non-structural member (a
  // spoke or a bus body, never the center or a line head) so the
  // survivors stay connected while it is gone.
  for (round, leaver) in [3usize, 35].into_iter().enumerate() {
    let same_member = round == 0;
    let former = slots[leaver].id().clone();
    let original_receiver = designed_parent()[leaver];
    let original_scheme = edge_scheme[leaver].expect("designed edge");

    // Leave: acknowledged replacement, old identity tombstoned, node
    // shuts down with the active-leave reason.
    let outcome = bounded(
      slots[leaver].handle().command(LeaveCluster::new(
        radiata::ReplaceIdentityAndDeleteOldCoreMetadata::new(),
      )),
      "leave cluster",
    )
    .await
    .unwrap_or_else(|error| panic!("leave round {round}: {error:?}"));
    assert_eq!(outcome.former_identity(), &former);
    assert_ne!(outcome.former_identity(), outcome.replacement_identity());
    assert_eq!(
      await_shutdown(&mut slots[leaver]).await,
      ShutdownReason::ActiveLeave,
      "leave must shut the slot down"
    );
    // The replacement identity boots on the same slot (same storage
    // and keys): a fresh outsider, per the leave custody contract.
    restart_slot(&mut slots[leaver], sockets.path(), leaver).await;
    let replacement = bounded(
      slots[leaver].handle().query(GetLocalNode::new()),
      "local node after leave",
    )
    .await
    .expect("local node")
    .node_id()
    .clone();
    assert_ne!(replacement, former, "the leave replaced the identity");

    // The survivors converge on 63 actives with the former identity
    // tombstoned everywhere the leave record has landed.
    let survivors: Vec<usize> = (0..NODES).filter(|index| *index != leaver).collect();
    wait_converged_indices(&slots, &survivors, NODES - 1, "after leave").await;
    for index in &survivors {
      assert!(
        left_members(&slots[*index]).await.contains(&former),
        "the former identity must be tombstoned everywhere"
      );
    }

    // Return through a *different* protocol than the original edge.
    // The target is the same member it used to dial (round 0) or a
    // different one (round 1); the scheme is seeded and never the
    // original one.
    let (target, scheme) = loop {
      let candidate = if same_member {
        original_receiver
      } else {
        rng.below(NODES)
      };
      if candidate == leaver {
        continue;
      }
      let scheme = rng.scheme();
      if candidate == original_receiver && scheme == original_scheme {
        continue;
      }
      break (candidate, scheme);
    };
    let what = format!(
      "rejoin {leaver} -> {target} over {} (was {original_receiver} over {})",
      SCHEMES[scheme], SCHEMES[original_scheme],
    );
    let secret = issue_credential(&slots[target]).await;
    let view = merge_with_retry(
      &slots[leaver],
      slots[target].endpoint(scheme),
      &secret,
      &what,
    )
    .await;
    assert_eq!(view.node(), &replacement, "{what}");
    assert_eq!(view.peer(), &ids[target], "{what}");
    wait_converged(&slots, NODES, "after rejoin").await;
    assert_eq!(active_members(&slots[leaver]).await, NODES, "{what}");
    assert!(left_members(&slots[leaver]).await.contains(&former));
    relay_packet(&slots[leaver], &slots[target], "post-rejoin relay").await;
  }

  // (4) Graceful restart of a bus tail: same identity, new listeners.
  // The tail reconnects through a seeded scheme (an explicit member
  // reconnect; its own recovery plane would also heal it, which the
  // kicks lane already exercised).
  let tail = NODES - 1;
  let restarted_id = slots[tail].id().clone();
  bounded(
    slots[tail].handle().command(radiata::Shutdown::new()),
    "graceful shutdown",
  )
  .await
  .expect("graceful shutdown");
  assert_eq!(
    await_shutdown(&mut slots[tail]).await,
    ShutdownReason::Explicit
  );
  restart_slot(&mut slots[tail], sockets.path(), tail).await;
  let booted = bounded(
    slots[tail].handle().query(GetLocalNode::new()),
    "local node after restart",
  )
  .await
  .expect("local node")
  .node_id()
  .clone();
  assert_eq!(booted, restarted_id, "a restart resumes the same identity");
  let scheme = rng.scheme();
  let peer = if tail > STAR_SPOKES + 1 { tail - 1 } else { 0 };
  let what = format!("restart reconnect over {}", SCHEMES[scheme]);
  let authenticated = connect_member_with_retry(
    &slots[tail],
    slots[peer].endpoint(scheme),
    &ids[peer],
    &what,
  )
  .await;
  assert_eq!(authenticated, ids[peer], "{what}");
  wait_converged(&slots, NODES, "after restart").await;

  // ---- Post-churn invariants ----------------------------------------
  //
  // Membership is exactly the 64 identities (the leavers' replacements
  // included), the two left tombstones persist, recovery is connected
  // everywhere, and relays cross the star and both bus lines.
  wait_converged(&slots, NODES, "post-churn").await;
  for (index, slot) in slots.iter().enumerate() {
    assert_eq!(
      active_members(slot).await,
      NODES,
      "node {index} lost members under churn"
    );
    let recovery = bounded(
      slot.handle().query(GetRecovery::new()),
      "recovery view post-churn",
    )
    .await
    .expect("recovery view");
    assert!(recovery.is_connected(), "node {index} never reconnected");
  }
  for former in [&ids[3], &ids[35]] {
    for slot in &slots {
      assert!(
        left_members(slot).await.contains(former),
        "the tombstone of {} must survive the churn everywhere",
        former.as_str()
      );
    }
  }
  // Multi-hop relay checks that cross the star and a bus line, kept
  // short enough that a starved runner's per-hop latency cannot
  // exhaust the relay acks: center to a mid-bus body crosses center ->
  // head -> six bodies and back.
  for slot in &slots {
    bounded(
      slot.handle().command(radiata::RunSyncRound::new()),
      "settle sync round",
    )
    .await
    .expect("settle sync round");
  }
  tokio::time::sleep(Duration::from_secs(2)).await;
  relay_packet(&slots[0], &slots[STAR_SPOKES + 7], "center-to-bus relay").await;
  relay_packet(&slots[STAR_SPOKES + 7], &slots[0], "bus-to-center relay").await;

  // ---- Teardown ------------------------------------------------------
  for slot in &mut slots {
    if let Some(handle) = slot.handle.take() {
      let _ = bounded(
        handle.command(radiata::Shutdown::new()),
        "teardown shutdown",
      )
      .await;
      let _ = bounded(handle.query(WaitForShutdown::new()), "teardown wait").await;
    }
  }
}

#[test]
fn designed_topology_shape_holds() {
  // The mixed topology is a spanning tree: 64 nodes, 63 edges, every
  // non-center node has exactly one designed parent, the center has
  // STAR_SPOKES + BUS_LINES children, and every node reaches the
  // center through its parent chain.
  let edges = designed_edges();
  assert_eq!(edges.len(), NODES - 1);
  let parent = designed_parent();
  let mut dialed = [false; NODES];
  for (dialer, _) in &edges {
    assert!(!dialed[*dialer], "node {dialer} dials twice");
    dialed[*dialer] = true;
  }
  assert!(!dialed[0], "the center dials nobody");
  let center_children = edges.iter().filter(|(_, receiver)| *receiver == 0).count();
  assert_eq!(center_children, STAR_SPOKES + BUS_LINES);
  for node in 1..NODES {
    let mut hop = node;
    let mut steps = 0;
    while hop != 0 {
      hop = parent[hop];
      steps += 1;
      assert!(steps < NODES, "cycle in the designed topology");
    }
  }
}
