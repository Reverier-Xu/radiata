//! Transport performance benchmark.
//!
//! Measures the CPU-tick cost per delivered chunk of the full radiata
//! stream pipeline (CBOR packet frames + session multiplexing + WS
//! prelude + TLS) against bare TLS chunk transport, under an enforced
//! send rate. Both lanes deliver identical 1 KiB chunks over one
//! loopback connection at an identical pace; the tick delta isolates the
//! encapsulation overhead.
//!
//! Run explicitly (ignored by default, Linux only):
//!
//! ```text
//! cargo test --test transport_benchmark -- --ignored --nocapture
//! ```

#![cfg(target_os = "linux")]

use std::{
  sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
  },
  time::Duration,
};

use radiata::{
  Endpoint, GetLocalNode, Listen, NodeBuilder, NodeConfig, NodeHandle, NodeId, ProtocolDefinition,
  ProtocolTag, RoutingPolicy, StreamMetadata, StreamPolicy, StreamTarget,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

mod common;

use common::{MemoryStorageFactory, ScriptedKeys};

/// The chunk count per measured lane.
const CHUNKS: usize = 20_000;
/// The enforced send rate (chunks per second): the rate limiter keeps
/// both lanes under identical load so the CPU comparison is like for
/// like.
const RATE_PER_SEC: u32 = 10_000;
/// The payload size of one chunk.
const PAYLOAD_BYTES: usize = 1024;
/// Warmup chunks before the measured section (excludes handshake and
/// first-touch costs from the measurement).
const WARMUP: usize = 500;

/// Process CPU ticks (utime + stime) from procfs; CLK_TCK is 100 on
/// stock Linux, so one tick is 10 ms of CPU.
fn cpu_ticks() -> u64 {
  let stat = std::fs::read_to_string("/proc/self/stat").expect("procfs stat");
  let after = stat.rsplit_once(')').expect("stat comm").1;
  let fields: Vec<&str> = after.split_whitespace().collect();
  let utime: u64 = fields[11].parse().expect("utime");
  let stime: u64 = fields[12].parse().expect("stime");
  utime + stime
}

/// The rate limiter: one fixed share of a second per chunk.
async fn pace() {
  tokio::time::sleep(Duration::from_nanos(
    1_000_000_000 / u64::from(RATE_PER_SEC),
  ))
  .await;
}

/// The receiver's stream consumer: counts delivered chunks and bytes.
#[derive(Debug, Default)]
struct Sink {
  chunks: AtomicUsize,
  bytes: AtomicUsize,
}

impl radiata::PacketConsumer for Sink {
  fn accept<'a>(
    &'a self, mut packet: radiata::IncomingStream,
  ) -> radiata::BoxFuture<'a, radiata::Result<()>> {
    Box::pin(async move {
      let mut chunks = packet.body();
      while let Some(chunk) = std::future::poll_fn(|cx| chunks.as_mut().poll_next(cx))
        .await
        .transpose()?
      {
        self.bytes.fetch_add(chunk.len(), Ordering::Relaxed);
        if chunk.len() == PAYLOAD_BYTES {
          self.chunks.fetch_add(1, Ordering::Relaxed);
        }
      }
      Ok(())
    })
  }
}

async fn start_node(seed: u64, sink: Arc<Sink>) -> (NodeHandle, Endpoint) {
  let storage = Arc::new(MemoryStorageFactory::new(common::required_capabilities()));
  let keys: Arc<dyn radiata::extension::KeyProvider> =
    Arc::new(ScriptedKeys::full_at(1_500_000 + seed * 1_000));
  let config = NodeConfig::new()
    .with_anti_entropy_interval(Duration::from_millis(500))
    .unwrap();
  let mut extensions = radiata::ExtensionRegistry::new();
  extensions
    .register_protocol(
      ProtocolDefinition::new(
        ProtocolTag::parse("radiata.woooo.tech/protocols/bench").unwrap(),
        radiata::FeatureTag::parse("radiata.woooo.tech/features/session-core").unwrap(),
      ),
      sink,
    )
    .unwrap();
  let handle = NodeBuilder::new(storage, keys)
    .config(config)
    .extensions(extensions)
    .start()
    .await
    .unwrap();
  let listener = handle
    .command(Listen::new(Endpoint::parse("wss://127.0.0.1:0").unwrap()))
    .await
    .unwrap();
  (handle, listener.endpoint().clone())
}

/// A merged pair, the receiver's node id, and the receiver's sink.
async fn merged_pair(receiver_sink: Arc<Sink>) -> (NodeHandle, NodeHandle, NodeId, Arc<Sink>) {
  let sender_sink = Arc::new(Sink::default());
  let (receiver, receiver_endpoint) = start_node(1, Arc::clone(&receiver_sink)).await;
  let (sender, _) = start_node(2, sender_sink).await;
  common::merge_with_retry(&sender, &receiver, receiver_endpoint).await;
  let peer = receiver
    .query(GetLocalNode::new())
    .await
    .unwrap()
    .node_id()
    .clone();
  (receiver, sender, peer, receiver_sink)
}

/// A paced body stream of `count` 1 KiB chunks.
fn paced_chunks(
  payload: Arc<[u8]>, count: usize,
) -> impl futures_core::Stream<Item = radiata::Result<Arc<[u8]>>> {
  futures_util::stream::unfold(
    (0_usize, count, payload),
    |(sent, count, payload)| async move {
      if sent >= count {
        None
      } else {
        pace().await;
        Some((Ok(Arc::clone(&payload)), (sent + 1, count, payload)))
      }
    },
  )
}

/// Opens one stream to `peer` and feeds it `count` paced chunks.
async fn send_chunks(sender: &NodeHandle, peer: &NodeId, count: usize, payload: &Arc<[u8]>) {
  let stream = sender
    .open_stream(
      StreamTarget::Exact(peer.clone()),
      ProtocolTag::parse("radiata.woooo.tech/protocols/bench").unwrap(),
      StreamPolicy::new(RoutingPolicy::Direct, 8).unwrap(),
      StreamMetadata::new(),
    )
    .unwrap();
  stream
    .send_sync(paced_chunks(Arc::clone(payload), count))
    .await
    .unwrap();
}

/// Waits until the sink observed `count` delivered chunks.
async fn await_delivery(sink: &Sink, count: usize) {
  let deadline = std::time::Instant::now() + Duration::from_secs(120);
  while sink.chunks.load(Ordering::Relaxed) < count {
    assert!(
      deadline.elapsed() < Duration::from_secs(120),
      "a benchmark lane never delivered every chunk"
    );
    tokio::time::sleep(Duration::from_millis(2)).await;
  }
}

/// The self-signed certificate and matching key for the bare-TLS server.
fn self_signed() -> (
  rustls::pki_types::CertificateDer<'static>,
  rustls::pki_types::PrivateKeyDer<'static>,
) {
  let issued = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
  let cert = rustls::pki_types::CertificateDer::from(issued.cert);
  let key = rustls::pki_types::PrivateKeyDer::Pkcs8(issued.signing_key.serialize_der().into());
  (cert, key)
}

/// Lane B: bare TLS — the same paced 1 KiB chunks length-prefixed over a
/// raw tokio-rustls TCP connection. No CBOR, no packet frames, no session
/// layer, no WebSocket.
async fn lane_bare_tls() -> (u64, Duration, usize) {
  let (cert, key) = self_signed();
  let server_config = rustls::ServerConfig::builder()
    .with_no_client_auth()
    .with_single_cert(vec![cert.clone()], key)
    .unwrap();
  let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

  let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let addr = listener.local_addr().unwrap();

  let server = tokio::spawn(async move {
    let (tcp, _) = listener.accept().await.unwrap();
    let mut tls = acceptor.accept(tcp).await.unwrap();
    let mut buf = vec![0u8; PAYLOAD_BYTES];
    let mut chunks = 0_usize;
    let mut bytes = 0_usize;
    while chunks < CHUNKS + WARMUP {
      tls.read_exact(&mut buf).await.unwrap();
      chunks += 1;
      bytes += buf.len();
    }
    (chunks, bytes)
  });

  // The client pins the exact self-signed certificate as its only trust
  // anchor: no insecure verifier needed.
  let mut roots = rustls::RootCertStore::empty();
  roots.add(cert).unwrap();
  let client_config = rustls::ClientConfig::builder()
    .with_root_certificates(roots)
    .with_no_client_auth();
  let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));

  let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
  let mut tls = connector
    .connect("localhost".try_into().unwrap(), tcp)
    .await
    .unwrap();

  let payload = vec![0xA5u8; PAYLOAD_BYTES];
  for _ in 0..WARMUP {
    tls.write_all(&payload).await.unwrap();
    pace().await;
  }
  tls.flush().await.unwrap();
  tokio::time::sleep(Duration::from_millis(50)).await;

  let start_ticks = cpu_ticks();
  let start_wall = std::time::Instant::now();
  for _ in 0..CHUNKS {
    tls.write_all(&payload).await.unwrap();
    pace().await;
  }
  tls.flush().await.unwrap();
  let delivered = server.await.unwrap();
  let wall = start_wall.elapsed();
  let ticks = cpu_ticks() - start_ticks;
  assert_eq!(delivered.0, CHUNKS + WARMUP);
  (ticks, wall, delivered.1 - WARMUP * PAYLOAD_BYTES)
}

/// The benchmark: identical paced delivery through both lanes; the tick
/// delta is the CBOR/framing/session encapsulation overhead.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "explicit benchmark: cargo test --test transport_benchmark -- --ignored --nocapture"]
async fn transport_cpu_ticks_full_pipeline_vs_bare_tls() {
  println!(
    "transport benchmark: {CHUNKS} chunks x {PAYLOAD_BYTES} B at {RATE_PER_SEC} chunks/s (paced, one stream per lane)"
  );

  let receiver_sink = Arc::new(Sink::default());
  let (receiver, sender, peer, sink) = merged_pair(receiver_sink).await;
  let payload: Arc<[u8]> = Arc::from(vec![0xA5u8; PAYLOAD_BYTES]);

  // Warmup both lanes' connection setup out of the measurement.
  send_chunks(&sender, &peer, WARMUP, &payload).await;
  await_delivery(&sink, WARMUP).await;
  sink.chunks.store(0, Ordering::Relaxed);

  let start_ticks = cpu_ticks();
  let start_wall = std::time::Instant::now();
  send_chunks(&sender, &peer, CHUNKS, &payload).await;
  await_delivery(&sink, CHUNKS).await;
  let a_wall = start_wall.elapsed();
  let a_ticks = cpu_ticks() - start_ticks;
  let a_bytes = sink.bytes.load(Ordering::Relaxed);

  sender.command(radiata::Shutdown::new()).await.unwrap();
  receiver.command(radiata::Shutdown::new()).await.unwrap();
  println!(
    "lane A full pipeline : {a_ticks:>6} cpu ticks | {:>9.2} ms wall | {a_bytes} B delivered",
    a_wall.as_secs_f64() * 1e3
  );

  let (b_ticks, b_wall, b_bytes) = lane_bare_tls().await;
  println!(
    "lane B bare TLS      : {b_ticks:>6} cpu ticks | {:>9.2} ms wall | {b_bytes} B delivered",
    b_wall.as_secs_f64() * 1e3
  );

  let overhead = if b_ticks > 0 {
    (a_ticks as f64 - b_ticks as f64) / b_ticks as f64 * 100.0
  } else {
    f64::NAN
  };
  println!("encapsulation overhead: {overhead:.1}% extra cpu ticks");
}
