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
    // The official transports, core routing policies, the built-in load
    // balancer, and the core feature definitions are installed explicitly.
    // The transports keep their own insertion rule (an explicit
    // registration survives the default pass); a caller claim on a core
    // routing entry conflicts, so a caller names its own tag instead.
    // Dial and listen resolve their transport from the endpoint's
    // selector through the registry at runtime.
    extensions.register_default()?;
    // The effective route policy resolves in the registration channel,
    // right after the default pass installs the built-in policy: the
    // caller's selection if configured, else the default's tag. A
    // registry missing the default fails the start typed here instead of
    // surfacing at the first routed frame.
    let route_policy = extensions.effective_route_policy(self.config.route_policy())?;
    // The effective endpoint-selection policy resolves on the same
    // channel, the same way: the caller's selection (or preference-list
    // shape) if configured, else the built-in published-order rotation.
    // A registry missing the resolution target fails the start typed
    // here instead of surfacing at the first member dial.
    let endpoint_policy = extensions.effective_endpoint_policy(
      self.config.endpoint_policy(),
      self.config.endpoint_preference(),
    )?;
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
          storage_factory: self.storage,
          context: None,
          keys: self.keys,
          config: self.config,
          route_policy,
          endpoint_policy,
          entropy: self.entropy.clone(),
          extensions: extensions.clone(),
          sessions: Default::default(),
          routes: Default::default(),
          events: Arc::clone(&events),
          member_revision: crate::node::MemberRevisionSignal::new(revision_tx),
          leave_applied: crate::membership::sync::LeaveAppliedSignal::new(),
          reconcile: None,
          sync_round_requests: round_tx,
          connection_tasks: Arc::new(std::sync::Mutex::new(Vec::new())),
          listeners: Default::default(),
          task_manager: None,
          tasks: None,
          triggers: None,
          operations: None,
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
