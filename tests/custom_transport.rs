//! Custom-transport integration lane.
//!
//! Exercises the public transport extension surface exactly as a caller
//! would: one in-memory hub medium implements [`radiata::CustomTransport`]
//! (a stream type implementing [`radiata::TransportStream`] plus a
//! listener implementing [`radiata::CustomListener`]), registers under a
//! caller-owned scheme name, and two real nodes complete a full secure
//! merge across it, addressed by the canonical custom form
//! `<name>://<opaque>`. No built-in transport participates.

use std::{
  collections::HashMap,
  sync::{Arc, Mutex},
};

use radiata::{
  CustomListener, CustomTransport, Endpoint, GetLocalNode, Listen, MergeCluster, MergeCredential,
  NodeBuilder, NodeHandle, RotateMergeCredential, Shutdown, TransportName, TransportStream,
};
use tokio::sync::mpsc;

mod common;

use common::{MemoryStorageFactory, ScriptedKeys};

/// The caller-owned tag of the demonstration medium.
/// The protocol prefix (scheme) the demonstration medium registers.
const HUB_SCHEME: &str = "hub";

/// The stream type of the hub medium: one half of an in-memory duplex
/// pipe, wrapped in a caller-owned newtype (a real medium wraps its own
/// device handle the same way) implementing the crate's stream contract.
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

/// Routes inbound streams from dialers to bound listeners by opaque
/// address, exactly like a real medium's addressing layer.
#[derive(Debug, Default)]
struct Hub {
  listeners: Mutex<HashMap<String, mpsc::Sender<Box<dyn TransportStream>>>>,
}

impl Hub {
  fn register(&self, opaque: &str, sender: mpsc::Sender<Box<dyn TransportStream>>) {
    self
      .listeners
      .lock()
      .unwrap()
      .insert(opaque.to_owned(), sender);
  }

  fn deliver(&self, opaque: &str, stream: Box<dyn TransportStream>) -> radiata::Result<()> {
    let sender = self
      .listeners
      .lock()
      .unwrap()
      .get(opaque)
      .cloned()
      .ok_or_else(|| radiata::Error::caller("hub listener not bound"))?;
    sender
      .try_send(stream)
      .map_err(|_| radiata::Error::caller("hub listener queue full"))
  }
}

#[derive(Debug)]
struct HubTransport(Arc<Hub>);

impl CustomTransport for HubTransport {
  fn bind(
    &self, endpoint: Endpoint,
  ) -> radiata::BoxFuture<'static, radiata::Result<Box<dyn CustomListener>>> {
    let hub = Arc::clone(&self.0);
    Box::pin(async move {
      let opaque = endpoint
        .opaque()
        .ok_or_else(|| radiata::Error::caller("hub endpoint without opaque address"))?
        .to_owned();
      let (sender, receiver) = mpsc::channel(1);
      hub.register(&opaque, sender);
      Ok(Box::new(HubListener {
        endpoint,
        receiver: tokio::sync::Mutex::new(receiver),
      }) as Box<dyn CustomListener>)
    })
  }

  fn connect(
    &self, endpoint: Endpoint,
  ) -> radiata::BoxFuture<'static, radiata::Result<Box<dyn TransportStream>>> {
    let hub = Arc::clone(&self.0);
    Box::pin(async move {
      let opaque = endpoint
        .opaque()
        .ok_or_else(|| radiata::Error::caller("hub endpoint without opaque address"))?
        .to_owned();
      let (client_side, server_side) = tokio::io::duplex(64 * 1024);
      hub.deliver(&opaque, Box::new(HubStream { inner: server_side }))?;
      Ok(Box::new(HubStream { inner: client_side }) as Box<dyn TransportStream>)
    })
  }
}

#[derive(Debug)]
struct HubListener {
  endpoint: Endpoint,
  receiver: tokio::sync::Mutex<mpsc::Receiver<Box<dyn TransportStream>>>,
}

impl CustomListener for HubListener {
  fn local_endpoint(&self) -> Endpoint {
    self.endpoint.clone()
  }

  fn accept(&self) -> radiata::BoxFuture<'_, radiata::Result<Box<dyn TransportStream>>> {
    Box::pin(async move {
      let mut receiver = self.receiver.lock().await;
      receiver
        .recv()
        .await
        .ok_or_else(|| radiata::Error::caller("hub listener closed"))
    })
  }

  fn close(&self) -> radiata::BoxFuture<'_, radiata::Result<()>> {
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

async fn start_node(hub: &Arc<Hub>, seed: u64) -> NodeHandle {
  init_tracing();
  let factory: Arc<dyn radiata::extension::StorageFactory> =
    Arc::new(MemoryStorageFactory::new(common::required_capabilities()));
  let mut extensions = radiata::ExtensionRegistry::new();
  extensions
    .register_transport(
      TransportName::parse(HUB_SCHEME).unwrap(),
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn custom_transport_carries_a_full_secure_merge() {
  let hub = Arc::new(Hub::default());
  let receiver = start_node(&hub, 10_000).await;
  let joiner = start_node(&hub, 20_000).await;

  let endpoint = Endpoint::parse(&format!("{HUB_SCHEME}://receiver")).unwrap();
  let listener = receiver
    .command(Listen::new(endpoint.clone()))
    .await
    .unwrap();
  assert_eq!(listener.endpoint(), &endpoint);

  let issued = receiver
    .command(RotateMergeCredential::new())
    .await
    .unwrap();
  let secret = issued.credential().expose_secret().to_owned();

  let merge = joiner
    .command(MergeCluster::new(
      endpoint.clone(),
      MergeCredential::parse(&secret).unwrap(),
    ))
    .await
    .unwrap();
  let _ = listener;

  // Both sides observe the adopted binding through their local views.
  let joiner_local = joiner.query(GetLocalNode::new()).await.unwrap();
  assert_eq!(joiner_local.node_id(), merge.node());
  let receiver_local = receiver.query(GetLocalNode::new()).await.unwrap();
  assert_eq!(receiver_local.node_id(), merge.peer());

  receiver.command(Shutdown::new()).await.unwrap();
  joiner.command(Shutdown::new()).await.unwrap();
}
