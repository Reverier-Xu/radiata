use std::sync::Arc;

use crate::{
  ExtensionRegistry, NodeConfig, NodeHandle, Result,
  api::{Entropy, SystemEntropy},
  provider::{KeyProvider, StorageFactory},
  runtime::{RuntimeDependencies, spawn_runtime},
};

pub struct NodeBuilder {
  storage: Arc<dyn StorageFactory>,
  /// The caller's custody injection; `None` lets the runtime assemble the
  /// default store-backed key custody over the opened metadata store.
  keys: Option<Arc<dyn KeyProvider>>,
  config: NodeConfig,
  entropy: Arc<dyn Entropy>,
  extensions: ExtensionRegistry,
}

impl NodeBuilder {
  /// Creates a builder over one storage factory. Key custody defaults to
  /// the store-backed provider over the same storage; pass
  /// [`NodeBuilder::keys`] to inject a custom [`KeyProvider`] (a file
  /// store on another volume, an HSM, a cloud KMS).
  pub fn new(storage: Arc<dyn StorageFactory>) -> Self {
    Self {
      storage,
      keys: None,
      config: NodeConfig::new(),
      entropy: Arc::new(SystemEntropy),
      extensions: ExtensionRegistry::new(),
    }
  }

  /// Injects the key custody provider for this node. The same provider
  /// must back every restart of the node, or the persisted identity can
  /// no longer sign; without an injection, custody lives in the metadata
  /// store itself and follows it across restarts and moves.
  pub fn keys(mut self, keys: Arc<dyn KeyProvider>) -> Self {
    self.keys = Some(keys);
    self
  }

  pub fn config(mut self, value: NodeConfig) -> Self {
    self.config = value;
    self
  }

  pub fn extensions(mut self, value: ExtensionRegistry) -> Self {
    self.extensions = value;
    self
  }

  pub fn entropy(mut self, value: Arc<dyn Entropy>) -> Self {
    self.entropy = value;
    self
  }

  pub async fn start(self) -> Result<NodeHandle> {
    let mut extensions = self.extensions;
    // The built-in WSS transport is always available; a caller registration
    // for the same tag is a conflict, so only add it when absent. WSS is
    // currently the only dial/listen transport the runtime resolves: the
    // open registry accepts further transports for future milestones, but
    // `spawn_runtime` is wired to the WSS tag until a config-selected
    // transport tag exists (roadmap: transports open behind traits).
    let wss_tag = crate::transport::registry::WssTransport::tag()?;
    if extensions.transport(&wss_tag).is_none() {
      extensions.register_transport(
        wss_tag,
        std::sync::Arc::new(crate::transport::registry::WssTransport::new()),
      )?;
    }
    // The built-in next-hop policy is the default route policy: a node
    // without a caller-selected tag relays through it, so multi-hop
    // routes work out of the box. As with the transport, a caller
    // registration for the same tag is a conflict, so only add it when
    // absent.
    let next_hop_tag = crate::routing::DefaultNextHop::tag()?;
    if extensions.next_hop_policy(&next_hop_tag).is_none() {
      extensions.register_next_hop(
        next_hop_tag,
        std::sync::Arc::new(crate::routing::DefaultNextHop),
      )?;
    }
    let extensions = Arc::new(extensions);
    let events = Arc::new(crate::node::EventHub::new());
    let (revision_tx, revision_rx) = tokio::sync::watch::channel(0_u64);
    let (round_tx, round_rx) =
      tokio::sync::mpsc::channel(crate::runtime::SYNC_ROUND_CHANNEL_CAPACITY);
    let client = {
      let (packet_tx, packet_rx) =
        tokio::sync::mpsc::channel(crate::runtime::PACKET_CHANNEL_CAPACITY);
      spawn_runtime(
        RuntimeDependencies {
          transport: extensions
            .transport(&crate::transport::registry::WssTransport::tag()?)
            .cloned()
            .ok_or_else(|| crate::Error::internal("built-in transport"))?,
          storage_factory: self.storage,
          context: None,
          keys: self.keys,
          config: self.config,
          entropy: self.entropy.clone(),
          extensions: extensions.clone(),
          sessions: Default::default(),
          routes: Default::default(),
          events: Arc::clone(&events),
          member_revision: crate::node::MemberRevisionSignal::new(revision_tx),
          leave_applied: crate::membership::sync::LeaveAppliedSignal::new(),
          sync_round_requests: round_tx,
          connection_tasks: Arc::new(std::sync::Mutex::new(Vec::new())),
          runtime_seed: None,
        },
        (packet_tx, packet_rx),
        round_rx,
      )
      .await?
    };
    Ok(NodeHandle::new(
      client,
      self.entropy,
      extensions,
      events,
      crate::node::MemberRevision::new(revision_rx),
    ))
  }
}
