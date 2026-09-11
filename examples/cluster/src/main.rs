//! radiata-cluster-node: a customer-style service over the radiata
//! library. Each instance exposes an HTTP resource getter/setter, joins
//! a sparse cluster through a bootstrap peer, and reports observation
//! counters — without touching any radiata internals. Joining is
//! operator-driven (POST /join): credential rotation invalidates
//! previously issued tokens, so concurrent self-joins would race.

mod http;
mod http_client;
mod keys;

use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use radiata::{GetLocalNode, Listen, NodeBuilder, ProtocolDefinition, ProtocolTag};
use serde_json::json;

/// The self-probe protocol: one chunk looped back through the local
/// admission path, counted by this consumer.
#[derive(Debug)]
struct ProbeConsumer {
  delivered: Arc<std::sync::atomic::AtomicUsize>,
}

impl radiata::PacketConsumer for ProbeConsumer {
  fn accept<'a>(
    &'a self, mut packet: radiata::IncomingStream,
  ) -> radiata::BoxFuture<'a, radiata::Result<()>> {
    use futures_util::StreamExt as _;
    Box::pin(async move {
      let mut body = packet.body();
      while let Some(chunk) = body.next().await {
        let _ = chunk?;
      }
      self
        .delivered
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
      Ok(())
    })
  }
}

struct Config {
  listen: String,
  http_listen: String,
  data: PathBuf,
}

fn env_or(key: &str, default: &str) -> String {
  std::env::var(key).unwrap_or_else(|_| default.to_owned())
}

fn load_config() -> Config {
  Config {
    listen: env_or("LISTEN", "wss://127.0.0.1:9443"),
    http_listen: env_or("HTTP_LISTEN", "0.0.0.0:8080"),
    data: PathBuf::from(env_or("DATA", "/data")),
  }
}

#[tokio::main]
async fn main() {
  tracing_subscriber::fmt()
    .with_env_filter(
      tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
    )
    .init();
  let config = load_config();

  let storage = radiata::adapters::redb_store(config.data.join("store.redb"));
  let keys = keys::FileKeyProvider::new(&config.data).expect("key directory");

  // The self-probe consumer must be registered before the node starts:
  // ExtensionRegistry is frozen at build time by design.
  let probe_delivered = Arc::new(std::sync::atomic::AtomicUsize::new(0));
  let probe = ProbeConsumer {
    delivered: Arc::clone(&probe_delivered),
  };
  let mut extensions = radiata::ExtensionRegistry::new();
  extensions
    .register_protocol(
      ProtocolDefinition::new(
        ProtocolTag::parse("radiata.woooo.tech/protocols/probe").unwrap(),
        radiata::FeatureTag::parse("radiata.woooo.tech/features/session-core").unwrap(),
      ),
      Arc::new(probe),
    )
    .expect("register probe protocol");

  let node = NodeBuilder::new(storage, Arc::new(keys))
    .config(
      radiata::NodeConfig::new()
        .with_session_liveness(
          Duration::from_secs(30),
          Duration::from_secs(5),
          Duration::from_secs(15),
        )
        .expect("liveness policy"),
    )
    .extensions(extensions)
    .start()
    .await
    .expect("radiata node start");
  node
    .command(Listen::new(
      radiata::Endpoint::parse(&config.listen).expect("LISTEN endpoint"),
    ))
    .await
    .expect("listen");
  let node_id = node
    .query(GetLocalNode::new())
    .await
    .expect("local node")
    .node_id()
    .clone();
  tracing::info!(node = %node_id.as_str(), "radiata node up");

  let state = Arc::new(http::AppState {
    node,
    node_id,
    probe_delivered,
    started: std::time::Instant::now(),
  });

  let app = http::router(Arc::clone(&state));
  let addr: SocketAddr = config.http_listen.parse().expect("HTTP_LISTEN");
  let listener = tokio::net::TcpListener::bind(addr)
    .await
    .expect("http bind");
  tracing::info!(%addr, "http api up");
  axum::serve(listener, app)
    .with_graceful_shutdown(async {
      let _ = tokio::signal::ctrl_c().await;
      let _ = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("sigterm handler")
        .recv()
        .await;
      tracing::info!("shutting down");
    })
    .await
    .expect("http serve");
  state.node.command(radiata::Shutdown::new()).await.ok();
  let _ = json!({}); // serde_json stays referenced from this crate root too
}
