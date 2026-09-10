//! Latency and throughput benchmark: bare TLS 1.3 versus the full radiata
//! channel, both over loopback.
//!
//! Three measurements per lane, like for like:
//!
//! 1. **round trip** — bare TLS echoes one 1 KiB message back; radiata opens a
//!    stream and awaits the destination's synchronous admission acknowledgement
//!    (`send_sync`). Both are one wire round trip under the lane's own protocol
//!    machinery.
//! 2. **end to end delivery** — radiata only: send instant to the receiver's
//!    stream-consumer arrival, per probe stream.
//! 3. **throughput** — 32 MiB as unpaced 32 KiB chunks (the wire chunk bound),
//!    end to end into the receiver, in MiB/s.
//!
//! Connection establishment is printed for context: TLS handshake versus
//! a full merge (TLS + WebSocket + five-position authentication +
//! admission), single sample each.
//!
//! Run explicitly (release build recommended):
//!
//! ```text
//! cargo test --release --test latency_benchmark -- --ignored --nocapture
//! ```

use std::{
  sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
  },
  time::{Duration, Instant},
};

use radiata::{
  Endpoint, GetLocalNode, Listen, NodeBuilder, NodeConfig, NodeHandle, NodeId, ProtocolDefinition,
  ProtocolTag, QualifiedTag, RoutingPolicy, StreamMetadata, StreamPolicy, StreamTarget,
};
use tokio::{
  io::{AsyncReadExt as _, AsyncWriteExt as _},
  sync::mpsc,
};

mod common;

use common::{MemoryStorageFactory, ScriptedKeys};

/// Round-trip probe count per lane.
const PROBES: usize = 500;
/// Probes discarded before the measured section.
const WARMUP_PROBES: usize = 50;
/// The round-trip payload size.
const RTT_BYTES: usize = 1_024;
/// The throughput payload size: one full wire chunk.
const BULK_BYTES: usize = 32 * 1_024;
/// Bulk chunks per throughput lane (32 MiB total).
const BULK_CHUNKS: usize = 1_024;

fn percentile(samples: &mut [Duration], p: f64) -> Duration {
  samples.sort();
  let index = (((samples.len() as f64) * p).ceil() as usize).saturating_sub(1);
  samples[index.min(samples.len() - 1)]
}

fn print_latency(name: &str, mut samples: Vec<Duration>) {
  let mean = samples.iter().sum::<Duration>() / samples.len() as u32;
  let p50 = percentile(&mut samples, 0.50);
  let p90 = percentile(&mut samples, 0.90);
  let p99 = percentile(&mut samples, 0.99);
  let max = *samples.last().unwrap();
  println!(
    "  {name:<38} mean {mean:>9.1?} | p50 {:>9.1?} | p90 {:>9.1?} | p99 {:>9.1?} | max {:>9.1?}  (n={})",
    p50,
    p90,
    p99,
    max,
    samples.len()
  );
}

fn probe_tag() -> QualifiedTag {
  QualifiedTag::parse("radiata.woooo.tech/bench/probe").unwrap()
}

// ---------------------------------------------------------------------------
// radiata lanes
// ---------------------------------------------------------------------------

/// The probe protocol's consumer: records the arrival instant of every
/// single-chunk probe stream, keyed by the probe id carried in metadata.
#[derive(Debug)]
struct ProbeSink {
  arrivals: mpsc::UnboundedSender<(u64, Instant)>,
}

impl radiata::PacketConsumer for ProbeSink {
  fn accept<'a>(
    &'a self, mut packet: radiata::IncomingStream,
  ) -> radiata::BoxFuture<'a, radiata::Result<()>> {
    Box::pin(async move {
      let id = packet
        .metadata()
        .get(&probe_tag())
        .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
        .map(u64::from_le_bytes)
        .unwrap_or(u64::MAX);
      let mut body = packet.body();
      while let Some(chunk) = std::future::poll_fn(|cx| body.as_mut().poll_next(cx))
        .await
        .transpose()?
      {
        let _ = chunk.len();
      }
      let _ = self.arrivals.send((id, Instant::now()));
      Ok(())
    })
  }
}

/// The bulk protocol's consumer: counts delivered bytes.
#[derive(Debug, Default)]
struct BulkSink {
  bytes: AtomicUsize,
}

impl radiata::PacketConsumer for BulkSink {
  fn accept<'a>(
    &'a self, mut packet: radiata::IncomingStream,
  ) -> radiata::BoxFuture<'a, radiata::Result<()>> {
    Box::pin(async move {
      let mut body = packet.body();
      while let Some(chunk) = std::future::poll_fn(|cx| body.as_mut().poll_next(cx))
        .await
        .transpose()?
      {
        self.bytes.fetch_add(chunk.len(), Ordering::Relaxed);
      }
      Ok(())
    })
  }
}

fn receiver_protocols(
  arrivals: mpsc::UnboundedSender<(u64, Instant)>, bulk: Arc<BulkSink>,
) -> radiata::ExtensionRegistry {
  let mut extensions = radiata::ExtensionRegistry::new();
  extensions
    .register_protocol(
      ProtocolDefinition::new(
        ProtocolTag::parse("radiata.woooo.tech/protocols/bench-probe").unwrap(),
        radiata::FeatureTag::parse("radiata.woooo.tech/features/session-core").unwrap(),
      ),
      Arc::new(ProbeSink { arrivals }),
    )
    .unwrap();
  extensions
    .register_protocol(
      ProtocolDefinition::new(
        ProtocolTag::parse("radiata.woooo.tech/protocols/bench-bulk").unwrap(),
        radiata::FeatureTag::parse("radiata.woooo.tech/features/session-core").unwrap(),
      ),
      bulk,
    )
    .unwrap();
  extensions
}

fn sender_protocols(bulk: Arc<BulkSink>) -> radiata::ExtensionRegistry {
  let mut extensions = radiata::ExtensionRegistry::new();
  // The probe protocol must be registered on the sender too: open_stream
  // validates the tag against the local registry. Its consumer is unused
  // (the sender never receives probe streams); the channel is discarded.
  let (dead_arrivals, _) = mpsc::unbounded_channel();
  extensions
    .register_protocol(
      ProtocolDefinition::new(
        ProtocolTag::parse("radiata.woooo.tech/protocols/bench-probe").unwrap(),
        radiata::FeatureTag::parse("radiata.woooo.tech/features/session-core").unwrap(),
      ),
      Arc::new(ProbeSink {
        arrivals: dead_arrivals,
      }),
    )
    .unwrap();
  extensions
    .register_protocol(
      ProtocolDefinition::new(
        ProtocolTag::parse("radiata.woooo.tech/protocols/bench-bulk").unwrap(),
        radiata::FeatureTag::parse("radiata.woooo.tech/features/session-core").unwrap(),
      ),
      bulk,
    )
    .unwrap();
  extensions
}

async fn start_node(
  extensions: radiata::ExtensionRegistry, key_seed: u64,
) -> (NodeHandle, Endpoint) {
  let storage = Arc::new(MemoryStorageFactory::new(common::required_capabilities()));
  let keys: Arc<dyn radiata::extension::KeyProvider> = Arc::new(ScriptedKeys::full_at(key_seed));
  let handle = NodeBuilder::new(storage, keys)
    .config(NodeConfig::new())
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

/// One synchronous-send probe: open a single-chunk stream and await the
/// destination's admission acknowledgement. Returns (ack instant, send
/// started instant).
async fn sync_probe(
  sender: &NodeHandle, peer: &NodeId, id: u64, payload: &Arc<[u8]>,
) -> (Instant, Instant) {
  let started = Instant::now();
  let stream = sender
    .open_stream(
      StreamTarget::Exact(peer.clone()),
      ProtocolTag::parse("radiata.woooo.tech/protocols/bench-probe").unwrap(),
      StreamPolicy::new(RoutingPolicy::Direct, 8).unwrap(),
      StreamMetadata::new()
        .insert(probe_tag(), Arc::from(id.to_le_bytes().as_slice()))
        .unwrap(),
    )
    .unwrap();
  stream
    .send_sync(futures_util::stream::iter([Ok(Arc::clone(payload))]))
    .await
    .unwrap();
  (Instant::now(), started)
}

/// Warmup + measured probe rounds, sequentially over one session.
async fn run_probes(
  sender: &NodeHandle, peer: &NodeId, payload: &Arc<[u8]>,
  arrivals_rx: &mut mpsc::UnboundedReceiver<(u64, Instant)>,
) -> (Vec<Duration>, Vec<Duration>) {
  let mut ack_rtts = Vec::with_capacity(PROBES);
  let mut e2e = Vec::with_capacity(PROBES);
  for id in 0..PROBES {
    let id = u64::try_from(id).unwrap();
    let (acked, started) = sync_probe(sender, peer, id, payload).await;
    ack_rtts.push(acked.duration_since(started));
    let (arrived_id, arrived) = arrivals_rx.recv().await.unwrap();
    assert_eq!(arrived_id, id);
    e2e.push(arrived.duration_since(started));
  }
  (ack_rtts, e2e)
}

/// The radiata lanes: admission round trip and end-to-end delivery per
/// probe stream, sequentially over one established session.
async fn lane_radiata() {
  let (arrivals_tx, mut arrivals_rx) = mpsc::unbounded_channel();
  let bulk = Arc::new(BulkSink::default());
  let (receiver, receiver_endpoint) = start_node(
    receiver_protocols(arrivals_tx, Arc::clone(&bulk)),
    2_500_001,
  )
  .await;
  let (sender, _) = start_node(sender_protocols(Arc::new(BulkSink::default())), 2_500_002).await;

  let merge_started = Instant::now();
  common::merge_with_retry(&sender, &receiver, receiver_endpoint).await;
  let merge = merge_started.elapsed();
  println!(
    "  [radiata] establishment (full merge): {merge:.1?}  (single sample; TLS+WS+5-position auth+admission)"
  );

  let peer = receiver
    .query(GetLocalNode::new())
    .await
    .unwrap()
    .node_id()
    .clone();
  let payload: Arc<[u8]> = Arc::from(vec![0xA5u8; RTT_BYTES]);

  // Warmup (results discarded).
  run_probes(&sender, &peer, &payload, &mut arrivals_rx).await;

  let (ack_rtts, e2e) = run_probes(&sender, &peer, &payload, &mut arrivals_rx).await;

  println!("  [radiata] synchronous admission round trip (open_stream + send_sync -> ack):");
  print_latency("send_sync ack round trip", ack_rtts);
  println!("  [radiata] end-to-end delivery (send -> consumer arrival):");
  print_latency("one-probe-stream delivery", e2e);

  sender.command(radiata::Shutdown::new()).await.unwrap();
  receiver.command(radiata::Shutdown::new()).await.unwrap();
}

/// The radiata throughput lane: 32 sequential streams of 1 MiB each.
/// The session queue is a bounded flow-control window (16 MiB): one
/// single stream bursting past it ends with `StreamInterrupted` by
/// design, so sustainable throughput is measured stream by stream.
async fn lane_radiata_throughput() {
  let (arrivals_tx, _arrivals_rx) = mpsc::unbounded_channel();
  let bulk = Arc::new(BulkSink::default());
  let (receiver, receiver_endpoint) = start_node(
    receiver_protocols(arrivals_tx, Arc::clone(&bulk)),
    2_500_003,
  )
  .await;
  let (sender, _) = start_node(sender_protocols(Arc::clone(&bulk)), 2_500_004).await;
  common::merge_with_retry(&sender, &receiver, receiver_endpoint).await;
  let peer = receiver
    .query(GetLocalNode::new())
    .await
    .unwrap()
    .node_id()
    .clone();

  const STREAMS: usize = 32;
  const CHUNKS_PER_STREAM: usize = 32; // 32 x 32 KiB = 1 MiB per stream
  let payload: Arc<[u8]> = Arc::from(vec![0xA5u8; BULK_BYTES]);
  let expected = STREAMS * CHUNKS_PER_STREAM * BULK_BYTES;

  let started = Instant::now();
  for _ in 0..STREAMS {
    let before = bulk.bytes.load(Ordering::Relaxed);
    let stream = sender
      .open_stream(
        StreamTarget::Exact(peer.clone()),
        ProtocolTag::parse("radiata.woooo.tech/protocols/bench-bulk").unwrap(),
        StreamPolicy::new(RoutingPolicy::Direct, 8).unwrap(),
        StreamMetadata::new(),
      )
      .unwrap();
    let stream_payload = Arc::clone(&payload);
    let body = futures_util::stream::iter(
      (0..CHUNKS_PER_STREAM).map(move |_| Ok(Arc::clone(&stream_payload))),
    );
    stream.send_sync(body).await.unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    while bulk.bytes.load(Ordering::Relaxed) - before < CHUNKS_PER_STREAM * BULK_BYTES {
      assert!(Instant::now() < deadline, "a bulk stream never delivered");
      tokio::time::sleep(Duration::from_millis(1)).await;
    }
  }
  let wall = started.elapsed();
  let bytes = bulk.bytes.load(Ordering::Relaxed);
  assert_eq!(bytes, expected);
  println!(
    "  [radiata] throughput: {:.0} MiB in {:.2?} = {:.0} MiB/s (32 x 1 MiB streams, end to end, sustainable)",
    bytes as f64 / (1 << 20) as f64,
    wall,
    bytes as f64 / (1 << 20) as f64 / wall.as_secs_f64()
  );

  sender.command(radiata::Shutdown::new()).await.unwrap();
  receiver.command(radiata::Shutdown::new()).await.unwrap();
}

// ---------------------------------------------------------------------------
// bare TLS lanes
// ---------------------------------------------------------------------------

fn self_signed() -> (
  rustls::pki_types::CertificateDer<'static>,
  rustls::pki_types::PrivateKeyDer<'static>,
) {
  let issued = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
  let cert = rustls::pki_types::CertificateDer::from(issued.cert);
  let key = rustls::pki_types::PrivateKeyDer::Pkcs8(issued.signing_key.serialize_der().into());
  (cert, key)
}

fn tls_connector(cert: &rustls::pki_types::CertificateDer<'static>) -> tokio_rustls::TlsConnector {
  let mut roots = rustls::RootCertStore::empty();
  roots.add(cert.clone()).unwrap();
  let config = rustls::ClientConfig::builder()
    .with_root_certificates(roots)
    .with_no_client_auth();
  tokio_rustls::TlsConnector::from(Arc::new(config))
}

async fn lane_bare_tls() {
  let (cert, key) = self_signed();
  let server_config = rustls::ServerConfig::builder()
    .with_no_client_auth()
    .with_single_cert(vec![cert.clone()], key)
    .unwrap();
  let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
  let connector = tls_connector(&cert);

  // Handshake cost, 20 samples.
  let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let addr = listener.local_addr().unwrap();
  let handshake_acceptor = acceptor.clone();
  tokio::spawn(async move {
    while let Ok((tcp, _)) = listener.accept().await {
      let _ = handshake_acceptor.accept(tcp).await;
    }
  });
  let mut handshakes = Vec::new();
  for _ in 0..20 {
    let started = Instant::now();
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let _tls = connector
      .connect("localhost".try_into().unwrap(), tcp)
      .await
      .unwrap();
    handshakes.push(started.elapsed());
  }
  println!("  [bare tls] establishment (TLS 1.3 handshake):");
  print_latency("connect", handshakes);

  // Round trip: echo server + 1 KiB probes.
  let echo_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let echo_addr = echo_listener.local_addr().unwrap();
  let echo_acceptor = acceptor.clone();
  tokio::spawn(async move {
    let (tcp, _) = echo_listener.accept().await.unwrap();
    let mut tls = echo_acceptor.accept(tcp).await.unwrap();
    let mut buf = vec![0u8; RTT_BYTES];
    loop {
      if tls.read_exact(&mut buf).await.is_err() {
        break;
      }
      if tls.write_all(&buf).await.is_err() || tls.flush().await.is_err() {
        break;
      }
    }
  });
  let tcp = tokio::net::TcpStream::connect(echo_addr).await.unwrap();
  let mut tls = connector
    .connect("localhost".try_into().unwrap(), tcp)
    .await
    .unwrap();

  let rtt_payload = vec![0xA5u8; RTT_BYTES];
  let mut ack_rtts = Vec::with_capacity(PROBES);
  for _ in 0..WARMUP_PROBES {
    tls.write_all(&rtt_payload).await.unwrap();
    tls.flush().await.unwrap();
    let mut echo = [0u8; RTT_BYTES];
    tls.read_exact(&mut echo).await.unwrap();
  }
  for _ in 0..PROBES {
    let started = Instant::now();
    tls.write_all(&rtt_payload).await.unwrap();
    tls.flush().await.unwrap();
    let mut echo = [0u8; RTT_BYTES];
    tls.read_exact(&mut echo).await.unwrap();
    ack_rtts.push(started.elapsed());
  }
  println!("  [bare tls] echo round trip (same 1 KiB):");
  print_latency("write -> echo back", ack_rtts);

  // Throughput: 32 MiB as 32 KiB writes; the server counts bytes.
  let bulk_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let bulk_addr = bulk_listener.local_addr().unwrap();
  let expected = BULK_CHUNKS * BULK_BYTES;
  let bulk_acceptor = acceptor.clone();
  let bulk_server = tokio::spawn(async move {
    let (tcp, _) = bulk_listener.accept().await.unwrap();
    let mut tls = bulk_acceptor.accept(tcp).await.unwrap();
    let mut buf = vec![0u8; BULK_BYTES];
    let mut total = 0_usize;
    while total < expected {
      let read = tls.read(&mut buf).await.unwrap();
      assert!(read > 0);
      total += read;
    }
    total
  });
  let tcp = tokio::net::TcpStream::connect(bulk_addr).await.unwrap();
  let mut tls = connector
    .connect("localhost".try_into().unwrap(), tcp)
    .await
    .unwrap();

  let bulk_payload = vec![0xA5u8; BULK_BYTES];
  let started = Instant::now();
  for _ in 0..BULK_CHUNKS {
    tls.write_all(&bulk_payload).await.unwrap();
  }
  tls.flush().await.unwrap();
  let delivered = bulk_server.await.unwrap();
  let wall = started.elapsed();
  println!(
    "  [bare tls] throughput: {:.1} MiB in {:.2?} = {:.0} MiB/s (32 KiB writes, end to end)",
    delivered as f64 / (1 << 20) as f64,
    wall,
    delivered as f64 / (1 << 20) as f64 / wall.as_secs_f64()
  );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "explicit benchmark: cargo test --release --test latency_benchmark -- --ignored --nocapture"]
async fn sync_latency_and_throughput_bare_tls_vs_radiata() {
  let _ = tracing_subscriber::fmt()
    .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
    .with_test_writer()
    .try_init();
  println!("=== lane: bare TLS 1.3 over loopback ===");
  lane_bare_tls().await;
  println!("=== lane: full radiata channel over loopback ===");
  lane_radiata().await;
  lane_radiata_throughput().await;
}
