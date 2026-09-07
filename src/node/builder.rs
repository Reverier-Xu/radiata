use std::sync::Arc;

use crate::{
  ExtensionRegistry, NodeConfig, NodeHandle, Result,
  api::{Entropy, SystemEntropy},
  provider::{KeyProvider, StorageFactory},
  runtime::{RuntimeDependencies, spawn_runtime},
};

pub struct NodeBuilder {
  storage: Arc<dyn StorageFactory>,
  keys: Arc<dyn KeyProvider>,
  config: NodeConfig,
  entropy: Arc<dyn Entropy>,
  extensions: ExtensionRegistry,
}

impl NodeBuilder {
  pub fn new(storage: Arc<dyn StorageFactory>, keys: Arc<dyn KeyProvider>) -> Self {
    Self {
      storage,
      keys,
      config: NodeConfig::new(),
      entropy: Arc::new(SystemEntropy),
      extensions: ExtensionRegistry::new(),
    }
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
    let extensions = Arc::new(extensions);
    let events = Arc::new(crate::node::EventHub::new());
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
          connection_tasks: Arc::new(std::sync::Mutex::new(Vec::new())),
          runtime_seed: None,
        },
        (packet_tx, packet_rx),
      )
      .await?
    };
    Ok(NodeHandle::new(client, self.entropy, extensions, events))
  }
}
