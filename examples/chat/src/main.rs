//! radiata-chat-node: a decentralized chat room over the radiata
//! library. Identities, group chats, and announcements are resources on
//! the metadata plane; direct messages, group fan-out, and read
//! receipts travel over the routed data channel and live in the
//! customer's own store. No radiata internals are touched.

mod chat;
mod http;
mod http_client;
mod keys;
mod store;

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
    listen: env_or("LISTEN", "wss://127.0.0.1:9443"),
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
  let chat_keys = keys::FileKeyProvider::new(&config.data).expect("key directory");
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
      Arc::new(chat::DefaultNextHop),
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

  let node = NodeBuilder::new(storage, Arc::new(chat_keys))
    .config(radiata::NodeConfig::new().with_route_policy(
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
