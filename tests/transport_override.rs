//! Built-in transport override integration lane.
//!
//! Exercises the explicit built-in override surface exactly as a caller
//! would: an in-memory hub medium implements [`radiata::TransportProvider`]
//! and replaces the built-in WSS transport through
//! [`radiata::ExtensionRegistry::override_builtin_transport`] on every
//! node, so the `wss://` selector is served end to end by the caller's
//! implementation — an in-memory bus no built-in transport could ever
//! reach — and two real nodes complete a full secure merge addressed by
//! the built-in URL form. The control case proves the opposite
//! direction: with no override installed, the same flow over `tls://`
//! is carried by the built-in transport.

use std::{
  collections::HashMap,
  sync::{Arc, Mutex},
};

use radiata::{
  Endpoint, Error, MergeCredential, NodeBuilder, NodeHandle, ProviderListener, TransportProvider,
  TransportScheme, TransportStream,
};
use tokio::sync::mpsc;

mod common;

use common::{MemoryStorageFactory, ScriptedKeys};

/// Routes inbound streams from dialers to bound listeners by canonical
/// endpoint text. A built-in override receives the built-in URL form
/// (`wss://host:port`), so the medium keys its routing table on the
/// canonical text and interprets the host and port itself — here the
/// address names a hub destination instead of a network socket.
#[derive(Debug, Default)]
struct Hub {
  listeners: Mutex<HashMap<String, mpsc::Sender<Box<dyn TransportStream>>>>,
}

impl Hub {
  fn register(&self, address: &str, sender: mpsc::Sender<Box<dyn TransportStream>>) {
    self
      .listeners
      .lock()
      .unwrap()
      .insert(address.to_owned(), sender);
  }

  fn deliver(&self, address: &str, stream: Box<dyn TransportStream>) -> radiata::Result<()> {
    let sender = self
      .listeners
      .lock()
      .unwrap()
      .get(address)
      .cloned()
      .ok_or_else(|| Error::caller("hub listener not bound"))?;
    sender
      .try_send(stream)
      .map_err(|_| Error::caller("hub listener queue full"))
  }
}

/// The stream type of the hub medium: one half of an in-memory duplex
/// pipe behind a caller-owned newtype, the same shape a real medium's
/// device handle takes.
#[derive(Debug)]
struct HubStream {
  inner: tokio::io::DuplexStream,
}

impl TransportStream for HubStream {}

impl tokio::io::AsyncRead for HubStream {
  fn poll_read(
    mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>,
    buf: &mut tokio::io::ReadBuf<'_>,
  ) -> std::task::Poll<std::io::Result<()>> {
    std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
  }
}

impl tokio::io::AsyncWrite for HubStream {
  fn poll_write(
    mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8],
  ) -> std::task::Poll<std::result::Result<usize, std::io::Error>> {
    std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
  }

  fn poll_flush(
    mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>,
  ) -> std::task::Poll<std::result::Result<(), std::io::Error>> {
    std::pin::Pin::new(&mut self.inner).poll_flush(cx)
  }

  fn poll_shutdown(
    mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>,
  ) -> std::task::Poll<std::result::Result<(), std::io::Error>> {
    std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
  }
}

#[derive(Debug)]
struct HubTransport(Arc<Hub>);

impl TransportProvider for HubTransport {
  fn bind(
    &self, endpoint: Endpoint,
  ) -> radiata::BoxFuture<'static, radiata::Result<Box<dyn ProviderListener>>> {
    let hub = Arc::clone(&self.0);
    Box::pin(async move {
      let address = endpoint.as_str().to_owned();
      let (sender, receiver) = mpsc::channel(1);
      hub.register(&address, sender);
      Ok(Box::new(HubListener {
        endpoint,
        receiver: tokio::sync::Mutex::new(receiver),
      }) as Box<dyn ProviderListener>)
    })
  }

  fn connect(
    &self, endpoint: Endpoint,
  ) -> radiata::BoxFuture<'static, radiata::Result<Box<dyn TransportStream>>> {
    let hub = Arc::clone(&self.0);
    Box::pin(async move {
      let address = endpoint.as_str().to_owned();
      let (client_side, server_side) = tokio::io::duplex(64 * 1024);
      hub.deliver(&address, Box::new(HubStream { inner: server_side }))?;
      Ok(Box::new(HubStream { inner: client_side }) as Box<dyn TransportStream>)
    })
  }
}

#[derive(Debug)]
struct HubListener {
  endpoint: Endpoint,
  receiver: tokio::sync::Mutex<mpsc::Receiver<Box<dyn TransportStream>>>,
}

impl ProviderListener for HubListener {
  fn local_endpoint(&self) -> Endpoint {
    self.endpoint.clone()
  }

  fn accept(&self) -> radiata::BoxFuture<'_, radiata::Result<Box<dyn TransportStream>>> {
    Box::pin(async {
      let mut receiver = self.receiver.lock().await;
      receiver
        .recv()
        .await
        .ok_or_else(|| Error::caller("hub listener closed"))
    })
  }

  fn close(&self) -> radiata::BoxFuture<'static, radiata::Result<()>> {
    Box::pin(async { Ok(()) })
  }
}

/// Routes crate diagnostics into the libtest capture for the calling
/// test, so failures print their own session traces.
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

/// Starts one node whose `wss` selector is served by the hub medium: the
/// override is installed before start, so the builder's seeding skips the
/// built-in WSS transport for that node.
async fn start_override_node(hub: &Arc<Hub>, seed: u64) -> NodeHandle {
  init_tracing();
  let factory: Arc<dyn radiata::extension::StorageFactory> =
    Arc::new(MemoryStorageFactory::new(common::required_capabilities()));
  let mut extensions = radiata::ExtensionRegistry::new();
  extensions
    .override_builtin_transport(
      TransportScheme::Wss,
      Arc::new(HubTransport(Arc::clone(hub))),
    )
    .unwrap();
  NodeBuilder::new(factory)
    .keys(Arc::new(ScriptedKeys::full_at(seed)))
    .extensions(extensions)
    .start()
    .await
    .unwrap()
}

/// Runs the receiver-rotates, joiner-merges flow against `endpoint` and
/// returns the two node identifiers: the joiner's own and the merged
/// receiver's.
async fn merge_over(
  receiver: &NodeHandle, joiner: &NodeHandle, endpoint: Endpoint,
) -> (radiata::NodeId, radiata::NodeId) {
  let listener = receiver
    .listeners()
    .create(endpoint.clone())
    .await
    .unwrap()
    .wait()
    .await
    .unwrap();
  // The override reports the requested address verbatim; the built-in
  // TLS listener resolves port zero to the OS-assigned port, so the
  // dial targets the listener's own resolved form.
  let dial = listener.endpoint().clone();
  assert_eq!(dial.selector(), endpoint.selector());

  let issued = receiver
    .credentials()
    .rotate()
    .await
    .unwrap()
    .wait()
    .await
    .unwrap();
  let secret = issued.credential().expose_secret().to_owned();

  let merge = joiner
    .join(dial, MergeCredential::parse(&secret).unwrap())
    .await
    .unwrap()
    .wait()
    .await
    .unwrap();
  (
    joiner.local_node().await.unwrap().node_id().clone(),
    merge.peer().clone(),
  )
}

/// An overridden built-in selector is served by the caller's
/// implementation: both nodes replace `wss` with the in-memory hub before
/// start, and a full secure merge over the built-in `wss://` address form
/// completes. The hub has no sockets, so the built-in WSS transport could
/// not have carried any part of the session — the dial and the listen
/// both resolved to the override.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn overridden_builtin_carries_the_full_merge_over_the_caller_medium() {
  let hub = Arc::new(Hub::default());
  let receiver = start_override_node(&hub, 30_000).await;
  let joiner = start_override_node(&hub, 40_000).await;

  let endpoint = Endpoint::parse("wss://override-hub:443").unwrap();
  let (joiner_id, receiver_id) = merge_over(&receiver, &joiner, endpoint).await;

  // The joiner adopted the receiver's identity view over the override.
  let receiver_local = receiver.local_node().await.unwrap();
  assert_eq!(receiver_local.node_id(), &receiver_id);
  assert_ne!(joiner_id, receiver_id);

  receiver.shutdown().await.unwrap();
  joiner.shutdown().await.unwrap();
}

/// The control direction: with no override installed, the same flow over
/// the built-in `tls://` form is carried by the built-in TLS transport.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn builtins_serve_their_selectors_when_not_overridden() {
  init_tracing();
  let receiver = NodeBuilder::new(Arc::new(MemoryStorageFactory::new(
    common::required_capabilities(),
  )))
  .keys(Arc::new(ScriptedKeys::full_at(50_000)))
  .start()
  .await
  .unwrap();
  let joiner = NodeBuilder::new(Arc::new(MemoryStorageFactory::new(
    common::required_capabilities(),
  )))
  .keys(Arc::new(ScriptedKeys::full_at(60_000)))
  .start()
  .await
  .unwrap();

  let endpoint = Endpoint::parse("tls://127.0.0.1:0").unwrap();
  let (joiner_id, receiver_id) = merge_over(&receiver, &joiner, endpoint).await;

  let receiver_local = receiver.local_node().await.unwrap();
  assert_eq!(receiver_local.node_id(), &receiver_id);
  assert_ne!(joiner_id, receiver_id);

  receiver.shutdown().await.unwrap();
  joiner.shutdown().await.unwrap();
}
