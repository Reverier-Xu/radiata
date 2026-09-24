//! radiata-chat-node: a decentralized chat room over the radiata
//! library. Identities, group chats, and announcements are resources on
//! the metadata plane; direct messages, group fan-out, and read
//! receipts travel over the routed data channel and live in the
//! customer's own store. No radiata internals are touched.

mod chat;
mod http;
mod http_client;
mod store;
#[cfg(unix)]
mod unix_transport;

use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use radiata::{
  ExtensionRegistry, GetLocalNode, Listen, NodeBuilder, ProtocolDefinition, ProtocolTag,
};

use crate::{chat::ChatConsumer, http::SharedState, store::ChatStore};

struct Config {
  listen: String,
  http_listen: String,
  data: PathBuf,
  /// The chat user this node speaks as; the identity resource pins the
  /// user to this node's NodeId.
  user: String,
}

fn env_or(key: &str, default: &str) -> String {
  std::env::var(key).unwrap_or_else(|_| default.to_owned())
}

fn load_config() -> Config {
  Config {
    // tls:// (default) for the open internet, wss:// behind
    // web-traffic-only firewalls, tcp:// on closed intranets with
    // constrained devices, and unix:///path/to/socket for same-host
    // IPC between co-located nodes (see src/unix_transport.rs).
    listen: env_or("LISTEN", "tls://127.0.0.1:9443"),
    http_listen: env_or("HTTP_LISTEN", "0.0.0.0:8080"),
    data: PathBuf::from(env_or("DATA", "/data")),
    user: env_or("CHAT_USER", "anonymous"),
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
  let store = Arc::new(
    ChatStore::open(config.data.join("messages.json"))
      .await
      .expect("chat store"),
  );

  // The chat protocol must be registered before the node starts:
  // ExtensionRegistry is frozen at build time by design.
  let mut extensions = ExtensionRegistry::new();
  extensions
    .register_next_hop(
      radiata::QualifiedTag::parse(chat::ROUTE_POLICY).expect("static route policy tag"),
      Arc::new(radiata::DefaultNextHop),
    )
    .expect("register route policy");
  extensions
    .register_protocol(
      ProtocolDefinition::new(
        ProtocolTag::parse(chat::CHAT_PROTOCOL).expect("static protocol tag"),
        radiata::FeatureTag::parse("radiata.woooo.tech/features/session-core")
          .expect("static feature tag"),
      ),
      Arc::new(ChatConsumer::new(Arc::clone(&store))),
    )
    .expect("register chat protocol");

  // The unix:// transport is one extra registration: once the scheme
  // name is bound, LISTEN=unix:///run/chat.sock and every merge target
  // of the form unix://... dial through it. Unix sockets are same-host
  // only; nodes behind that address scheme must share the filesystem.
  #[cfg(unix)]
  extensions
    .register_transport(
      radiata::TransportName::parse(unix_transport::UNIX_SCHEME).expect("static scheme name"),
      Arc::new(unix_transport::UnixTransport),
    )
    .expect("register unix transport");

  // Diagnostic switch for the acceptance bisect: restores the
  // pre-recalibration timing defaults when set.
  let mut node_config = radiata::NodeConfig::new();
  if std::env::var_os("LEGACY_TIMING").is_some() {
    use std::time::Duration;
    node_config = node_config
      .with_anti_entropy_interval(Duration::from_millis(250))
      .expect("nonzero interval")
      .with_session_liveness(
        Duration::from_secs(30),
        Duration::from_secs(10),
        Duration::from_secs(30),
      )
      .expect("valid liveness")
      .with_authentication_deadline(Duration::from_secs(10))
      .expect("nonzero deadline")
      .with_recovery_policy(
        radiata::RecoveryConfig::new(64, Duration::from_secs(1), Duration::from_secs(300))
          .expect("valid recovery"),
      )
      .expect("valid config");
  }

  let node = NodeBuilder::new(storage)
    .config(node_config.with_route_policy(
      radiata::QualifiedTag::parse(chat::ROUTE_POLICY).expect("static route policy tag"),
    ))
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
  tracing::info!(node = %node_id.as_str(), user = %config.user, "chat node up");

  let state: SharedState = Arc::new(http::AppState {
    node,
    node_id,
    user: config.user,
    store,
  });

  // Re-assert the identity resource (idempotent on restart), then keep
  // the authenticated mesh complete for direct-routed chat traffic.
  if let Err(error) = http::publish_identity(&state).await {
    tracing::error!(%error, "identity publish failed");
  }

  let addr: SocketAddr = config.http_listen.parse().expect("HTTP_LISTEN");
  let listener = tokio::net::TcpListener::bind(addr)
    .await
    .expect("http bind");
  tracing::info!(%addr, "chat http api up");
  axum::serve(listener, http::router(Arc::clone(&state)))
    .with_graceful_shutdown(async {
      let _ = tokio::signal::ctrl_c().await;
      if let Ok(mut term) =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
      {
        let _ = term.recv().await;
      }
      tracing::info!("shutting down");
    })
    .await
    .expect("http serve");
}
