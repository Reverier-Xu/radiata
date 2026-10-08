//! The node-local extension registry.
//!
//! [`ExtensionRegistry::register_protocol`] binds a [`ProtocolDefinition`]
//! to the [`PacketConsumer`] that receives admitted incoming streams for
//! that protocol tag, alongside caller registration of feature
//! definitions, load-balancing policies, and next-hop routing policies,
//! and caller registration of transport providers. The runtime seeds the
//! built-in transports and core protocols at startup through the same
//! registry: it is the single map from endpoint selector to transport.

use std::{collections::BTreeMap, fmt, sync::Arc};

// The discovery extension surface is test-only until a discovery wiring
// exists (see `transport::registry`).
#[cfg(test)]
use crate::{DiscoveryTag, transport::registry::Discovery};
use crate::{
  Error, FeatureTag, IncomingStream, ProtocolTag, Result, TransportTag,
  api::BoxFuture,
  transport::{
    TransportSelector,
    registry::{Transport, TransportProvider, TransportProviderAdapter, builtin_transport_tag},
  },
};

/// The immutable definition of one domain-qualified packet protocol: its
/// tag and the feature that owns it. The owning feature must be selected
/// on a session before the destination admits the protocol's streams.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolDefinition {
  tag: ProtocolTag,
  owning_feature: FeatureTag,
}

impl ProtocolDefinition {
  pub fn new(tag: ProtocolTag, owning_feature: FeatureTag) -> Self {
    Self {
      tag,
      owning_feature,
    }
  }

  pub(crate) const fn owning_feature(&self) -> &FeatureTag {
    &self.owning_feature
  }
}

/// The caller-owned receiver of admitted incoming packet streams.
///
/// `accept` is invoked once per admitted stream, after authentication and
/// admission; it owns all application meaning of the packet.
pub trait PacketConsumer: fmt::Debug + Send + Sync + 'static {
  fn accept<'a>(&'a self, packet: IncomingStream) -> BoxFuture<'a, Result<()>>;
}

/// One registered protocol: its definition plus the receiving consumer.
pub(crate) struct ProtocolRegistration {
  pub(crate) definition: ProtocolDefinition,
  pub(crate) consumer: Arc<dyn PacketConsumer>,
}

/// The node-local extension registry. Caller registrations are immutable
/// for the node's lifetime and are installed through
/// [`crate::NodeBuilder::extensions`]; core protocols are registered by
/// the runtime at startup through
/// `ExtensionRegistry::register_core_protocol`.
#[derive(Default)]
pub struct ExtensionRegistry {
  features: std::sync::Mutex<BTreeMap<crate::FeatureTag, crate::FeatureDefinition>>,
  protocols: std::sync::Mutex<BTreeMap<ProtocolTag, Arc<ProtocolRegistration>>>,
  transports: BTreeMap<TransportTag, Arc<dyn Transport>>,
  /// The caller-registered transport providers, keyed by the scheme name
  /// (protocol prefix) each one owns.
  schemes: BTreeMap<crate::transport::TransportName, Arc<dyn Transport>>,
  #[cfg(test)]
  discoveries: BTreeMap<DiscoveryTag, Arc<dyn Discovery>>,
  load_balancers:
    std::sync::Mutex<BTreeMap<crate::QualifiedTag, Arc<dyn crate::LoadBalancingPolicy>>>,
  next_hops: std::sync::Mutex<BTreeMap<crate::QualifiedTag, Arc<dyn crate::RouteNextHop>>>,
  resource_hooks: std::sync::Mutex<BTreeMap<crate::QualifiedTag, Arc<dyn crate::ResourceHook>>>,
  action_hooks: std::sync::Mutex<BTreeMap<crate::QualifiedTag, Arc<dyn crate::ActionHook>>>,
  task_reconcilers: std::sync::Mutex<BTreeMap<crate::QualifiedTag, Arc<dyn crate::TaskReconciler>>>,
}

impl ExtensionRegistry {
  pub fn new() -> Self {
    Self::default()
  }

  /// Registers one caller-defined feature: the definition's
  /// contract fingerprint joins the node's negotiation registry, so its
  /// exact digest is offered and intersected at handshake time. A
  /// duplicate tag is a conflict; the built-in domain is reserved (the
  /// definition constructor already refuses it).
  pub fn register_feature(&mut self, value: crate::FeatureDefinition) -> Result<&mut Self> {
    {
      let mut features = self.features.lock().map_err(Error::extension_registry)?;
      insert_once(
        &mut features,
        value.tag().clone(),
        value,
        "feature registration",
      )?;
    }
    Ok(self)
  }

  /// The caller-registered feature definitions in canonical tag order.
  pub(crate) fn feature_definitions(&self) -> Vec<crate::FeatureDefinition> {
    self
      .features
      .lock()
      .map(|features| features.values().cloned().collect())
      .unwrap_or_default()
  }

  /// The exact negotiation digest of one feature tag (the digest offered
  /// and intersected at handshake time): the caller-registered definition
  /// wins, then the built-in registry.
  pub(crate) fn feature_digest(&self, tag: &crate::FeatureTag) -> Option<crate::Digest> {
    let definition = self
      .features
      .lock()
      .ok()
      .and_then(|features| features.get(tag).cloned())
      .or_else(|| {
        crate::protocol::feature::FeatureRegistry::builtin()
          .ok()?
          .get(tag)
          .cloned()
      });
    definition.and_then(|definition| definition.definition_digest().ok())
  }

  /// Registers one caller-defined transport under its addressing scheme
  /// name (the protocol prefix of the custom endpoint form
  /// `<name>://<opaque>`). The name is unique per node: a duplicate, a
  /// reserved name, or any other conflict is rejected before use. The
  /// built-in transports are seeded by the runtime under their own
  /// schemes and cannot be shadowed from here.
  ///
  /// This is the public extension surface of the transport layer: the
  /// registry is the single map from endpoint selector to transport,
  /// and a registered name becomes dialable through the canonical
  /// custom form `<name>://<opaque-address>`. The binding is node-local:
  /// endpoints exchanged across nodes assume both sides bound the name
  /// identically, and a mismatch fails at the session handshake's
  /// identity proofs rather than silently.
  pub fn register_transport(
    &mut self, name: crate::transport::TransportName, transport: Arc<dyn TransportProvider>,
  ) -> Result<&mut Self> {
    let adapter = Arc::new(TransportProviderAdapter::new(
      Arc::clone(&transport),
      name.clone(),
    )?);
    insert_once(&mut self.schemes, name, adapter, "transport registration")?;
    Ok(self)
  }

  /// Registers one built-in transport implementation under its canonical
  /// tag. Crate-private: only the runtime seeds built-ins, and only when
  /// the tag is still free.
  pub(crate) fn register_builtin_transport(
    &mut self, tag: TransportTag, value: Arc<dyn Transport>,
  ) -> Result<&mut Self> {
    insert_once(&mut self.transports, tag, value, "transport registration")?;
    Ok(self)
  }

  /// Resolves one endpoint's transport selector through the map: the
  /// built-in transports and every caller-registered transport provider
  /// merge into one resolution namespace, and a selector that resolves
  /// to nothing fails typed here — at dial or listen time, never at
  /// parse time (endpoint parsing is purely syntactic and
  /// registry-free).
  pub(crate) fn resolve_transport(
    &self, selector: &TransportSelector,
  ) -> Result<Arc<dyn Transport>> {
    match selector {
      TransportSelector::Builtin(scheme) => {
        let tag = builtin_transport_tag(*scheme)?;
        self
          .transport(&tag)
          .cloned()
          .ok_or_else(|| Error::not_found("transport"))
      }
      TransportSelector::Custom(name) => self
        .schemes
        .get(name)
        .cloned()
        .ok_or_else(|| Error::not_found("transport")),
    }
  }

  /// Registers one discovery implementation under its canonical tag, with
  /// the same duplicate/reserved/conflict rules as transports.
  #[cfg(test)]
  pub(crate) fn register_discovery(
    &mut self, tag: DiscoveryTag, value: Arc<dyn Discovery>,
  ) -> Result<&mut Self> {
    insert_once(&mut self.discoveries, tag, value, "discovery registration")?;
    Ok(self)
  }

  /// The registered transport for one tag.
  pub(crate) fn transport(&self, tag: &TransportTag) -> Option<&Arc<dyn Transport>> {
    self.transports.get(tag)
  }

  /// The registered discovery for one tag.
  #[cfg(test)]
  pub(crate) fn discovery(&self, tag: &DiscoveryTag) -> Option<&Arc<dyn Discovery>> {
    self.discoveries.get(tag)
  }

  /// Registers one load-balancing policy under a canonical tag. A
  /// duplicate tag is a conflict; registration never
  /// replaces an existing entry. Matching-node stream targets resolve
  /// their `StreamPolicy` load-balancer tag here at send time.
  pub fn register_load_balancer(
    &mut self, tag: crate::QualifiedTag, value: Arc<dyn crate::LoadBalancingPolicy>,
  ) -> Result<&mut Self> {
    {
      let mut balancers = self
        .load_balancers
        .lock()
        .map_err(Error::extension_registry)?;
      insert_once(&mut balancers, tag, value, "load balancer registration")?;
    }
    Ok(self)
  }

  /// The registered load-balancing policy for one tag, when present.
  pub(crate) fn load_balancer(
    &self, tag: &crate::QualifiedTag,
  ) -> Option<Arc<dyn crate::LoadBalancingPolicy>> {
    self
      .load_balancers
      .lock()
      .ok()
      .and_then(|balancers| balancers.get(tag).cloned())
  }

  /// Whether the load-balancer tag is registered locally.
  pub(crate) fn has_load_balancer(&self, tag: &crate::QualifiedTag) -> bool {
    self
      .load_balancers
      .lock()
      .map(|balancers| balancers.contains_key(tag))
      .unwrap_or(false)
  }

  /// Registers one next-hop routing policy under a canonical tag. A
  /// duplicate tag is a conflict; registration never
  /// replaces an existing entry. A node's configured route-policy tag
  /// resolves here when a routed packet must hop through this node.
  pub fn register_next_hop(
    &mut self, tag: crate::QualifiedTag, value: Arc<dyn crate::RouteNextHop>,
  ) -> Result<&mut Self> {
    {
      let mut policies = self.next_hops.lock().map_err(Error::extension_registry)?;
      insert_once(&mut policies, tag, value, "next-hop registration")?;
    }
    Ok(self)
  }

  /// The registered next-hop policy for one tag, when present.
  pub(crate) fn next_hop_policy(
    &self, tag: &crate::QualifiedTag,
  ) -> Option<Arc<dyn crate::RouteNextHop>> {
    self
      .next_hops
      .lock()
      .ok()
      .and_then(|policies| policies.get(tag).cloned())
  }

  /// Registers one resource-write hook under a canonical tag. All hooks
  /// registered here run in canonical tag order; a duplicate tag is a
  /// conflict and registration never replaces an existing entry.
  pub fn register_resource_hook(
    &mut self, tag: crate::QualifiedTag, hook: Arc<dyn crate::ResourceHook>,
  ) -> Result<&mut Self> {
    {
      let mut hooks = self
        .resource_hooks
        .lock()
        .map_err(Error::extension_registry)?;
      insert_once(&mut hooks, tag, hook, "resource hook registration")?;
    }
    Ok(self)
  }

  /// Registers one task phase-transition observer under a canonical tag.
  /// All hooks registered here run in canonical tag order; a duplicate
  /// tag is a conflict and registration never replaces an existing entry.
  pub fn register_action_hook(
    &mut self, tag: crate::QualifiedTag, hook: Arc<dyn crate::ActionHook>,
  ) -> Result<&mut Self> {
    {
      let mut hooks = self
        .action_hooks
        .lock()
        .map_err(Error::extension_registry)?;
      insert_once(&mut hooks, tag, hook, "action hook registration")?;
    }
    Ok(self)
  }

  /// Registers one custom task kind's reconciler under the kind tag.
  /// A duplicate tag is a conflict. The built-in `radiata.woooo.tech`
  /// domain is reserved: the core kinds are the [`crate::TaskKind`] set,
  /// never tags, so a reconciler registered under that domain is refused
  /// (the same reserved-domain rule the tag grammar applies to crypto
  /// tags).
  pub fn register_task_reconciler(
    &mut self, kind: crate::QualifiedTag, reconciler: Arc<dyn crate::TaskReconciler>,
  ) -> Result<&mut Self> {
    if kind.domain() == crate::protocol::tag::BUILTIN_DOMAIN {
      return Err(Error::invalid_input("task reconciler kind"));
    }
    {
      let mut reconcilers = self
        .task_reconcilers
        .lock()
        .map_err(Error::extension_registry)?;
      insert_once(
        &mut reconcilers,
        kind,
        reconciler,
        "task reconciler registration",
      )?;
    }
    Ok(self)
  }

  /// The registered action hooks in canonical tag order (the order they
  /// observe a transition in). Cloned per transition: the hook map is a
  /// `std` mutex and must not be held across the hooks' awaits.
  pub(crate) fn action_hooks(&self) -> Vec<Arc<dyn crate::ActionHook>> {
    self
      .action_hooks
      .lock()
      .map(|hooks| hooks.values().cloned().collect())
      .unwrap_or_default()
  }

  /// Registers one packet protocol and its consumer. A duplicate protocol
  /// tag is a conflict; registration never replaces an existing entry.
  pub fn register_protocol(
    &mut self, value: ProtocolDefinition, consumer: Arc<dyn PacketConsumer>,
  ) -> Result<&mut Self> {
    self.register_protocol_inner(value, consumer)?;
    Ok(self)
  }

  /// Registers a core (runtime-owned) packet protocol after the node's
  /// identity is provisioned; the same duplicate/conflict rules apply.
  pub(crate) fn register_core_protocol(
    &self, value: ProtocolDefinition, consumer: Arc<dyn PacketConsumer>,
  ) -> Result<()> {
    self.register_protocol_inner(value, consumer)
  }

  fn register_protocol_inner(
    &self, value: ProtocolDefinition, consumer: Arc<dyn PacketConsumer>,
  ) -> Result<()> {
    let mut protocols = self.protocols.lock().map_err(Error::extension_registry)?;
    insert_once(
      &mut protocols,
      value.tag.clone(),
      Arc::new(ProtocolRegistration {
        definition: value,
        consumer,
      }),
      "protocol registration",
    )?;
    Ok(())
  }

  /// The registration for one protocol tag, when present.
  pub(crate) fn protocol(&self, tag: &ProtocolTag) -> Option<Arc<ProtocolRegistration>> {
    self
      .protocols
      .lock()
      .ok()
      .and_then(|protocols| protocols.get(tag).cloned())
  }

  /// Whether the protocol tag is registered locally.
  pub(crate) fn has_protocol(&self, tag: &ProtocolTag) -> bool {
    self
      .protocols
      .lock()
      .ok()
      .is_some_and(|protocols| protocols.contains_key(tag))
  }
}

impl fmt::Debug for ExtensionRegistry {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    let mut builder = formatter.debug_struct("ExtensionRegistry");
    builder.field(
      "protocols",
      &self
        .protocols
        .lock()
        .map(|protocols| protocols.len())
        .unwrap_or(0),
    );
    builder.field("transports", &self.transports.len());
    #[cfg(test)]
    builder.field("discoveries", &self.discoveries.len());
    builder
      .field(
        "load_balancers",
        &self
          .load_balancers
          .lock()
          .map(|balancers| balancers.len())
          .unwrap_or(0),
      )
      .field(
        "next_hops",
        &self
          .next_hops
          .lock()
          .map(|policies| policies.len())
          .unwrap_or(0),
      )
      .field(
        "resource_hooks",
        &self
          .resource_hooks
          .lock()
          .map(|hooks| hooks.len())
          .unwrap_or(0),
      )
      .field(
        "action_hooks",
        &self
          .action_hooks
          .lock()
          .map(|hooks| hooks.len())
          .unwrap_or(0),
      )
      .field(
        "task_reconcilers",
        &self
          .task_reconcilers
          .lock()
          .map(|reconcilers| reconcilers.len())
          .unwrap_or(0),
      )
      .finish()
  }
}

/// Inserts `value` only when `tag` is absent; a duplicate is a typed
/// conflict. The single insertion-once rule for every registry map.
fn insert_once<K: Ord, V>(
  map: &mut std::collections::BTreeMap<K, V>, tag: K, value: V, context: &'static str,
) -> Result<()> {
  use std::collections::btree_map::Entry;
  match map.entry(tag) {
    Entry::Occupied(_) => Err(Error::conflict(context)),
    Entry::Vacant(slot) => {
      slot.insert(value);
      Ok(())
    }
  }
}

#[cfg(test)]
mod tests {
  use std::sync::Arc;

  use super::{ExtensionRegistry, PacketConsumer, ProtocolDefinition};
  use crate::{ErrorKind, FeatureTag, IncomingStream, ProtocolTag, Result, api::BoxFuture};

  #[derive(Debug)]
  struct NoopConsumer;

  impl PacketConsumer for NoopConsumer {
    fn accept<'a>(&'a self, _packet: IncomingStream) -> BoxFuture<'a, Result<()>> {
      Box::pin(async { Ok(()) })
    }
  }

  #[derive(Debug)]
  struct NoopResourceHook;

  impl crate::ResourceHook for NoopResourceHook {}

  #[derive(Debug)]
  struct NoopActionHook;

  impl crate::ActionHook for NoopActionHook {}

  #[derive(Debug)]
  struct NoopReconciler;

  impl crate::TaskReconciler for NoopReconciler {
    fn reconcile<'a>(
      &'a self, _ctx: crate::ReconcileContext,
    ) -> crate::BoxFuture<'a, Result<crate::ReconcileDecision>> {
      Box::pin(async { Ok(crate::ReconcileDecision::Succeeded) })
    }
  }

  fn definition(name: &str) -> ProtocolDefinition {
    ProtocolDefinition::new(
      ProtocolTag::parse(&format!("radiata.woooo.tech/protocols/{name}")).unwrap(),
      FeatureTag::parse("radiata.woooo.tech/features/data-messages").unwrap(),
    )
  }

  #[test]
  fn tls_transport_extension_registry_registers_and_rejects_duplicates() {
    let mut registry = ExtensionRegistry::new();
    registry
      .register_protocol(definition("alpha"), Arc::new(NoopConsumer))
      .unwrap();
    assert!(
      registry.has_protocol(&ProtocolTag::parse("radiata.woooo.tech/protocols/alpha").unwrap())
    );

    let error = registry
      .register_protocol(definition("alpha"), Arc::new(NoopConsumer))
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Conflict);

    // A distinct tag still registers after the failed duplicate.
    registry
      .register_protocol(definition("beta"), Arc::new(NoopConsumer))
      .unwrap();
    assert!(
      registry.has_protocol(&ProtocolTag::parse("radiata.woooo.tech/protocols/beta").unwrap())
    );
    assert!(
      !registry.has_protocol(&ProtocolTag::parse("radiata.woooo.tech/protocols/gamma").unwrap())
    );
  }

  /// The three hook maps follow the same insertion-once rule as every
  /// other registry map, and the registry's `Debug` keeps summarizing
  /// them as counts.
  #[test]
  fn hook_registrations_are_insertion_once() {
    let mut registry = ExtensionRegistry::new();
    let alpha = crate::QualifiedTag::parse("example.com/hooks/alpha").unwrap();
    let zeta = crate::QualifiedTag::parse("example.com/hooks/zeta").unwrap();
    registry
      .register_action_hook(zeta, Arc::new(NoopActionHook))
      .unwrap();
    registry
      .register_action_hook(alpha.clone(), Arc::new(NoopActionHook))
      .unwrap();
    let duplicate = registry
      .register_action_hook(alpha, Arc::new(NoopActionHook))
      .unwrap_err();
    assert_eq!(duplicate.kind(), ErrorKind::Conflict);

    let guard = crate::QualifiedTag::parse("example.com/hooks/guard").unwrap();
    registry
      .register_resource_hook(guard.clone(), Arc::new(NoopResourceHook))
      .unwrap();
    let duplicate = registry
      .register_resource_hook(guard, Arc::new(NoopResourceHook))
      .unwrap_err();
    assert_eq!(duplicate.kind(), ErrorKind::Conflict);

    // The hook order the manager runs is the registry's own tag order.
    assert_eq!(registry.action_hooks().len(), 2);
    let summary = format!("{registry:?}");
    assert!(summary.contains("action_hooks: 2"), "{summary}");
    assert!(summary.contains("resource_hooks: 1"), "{summary}");
  }

  /// Core kinds are the `TaskKind` set, never tags: the built-in domain
  /// is reserved for task-reconciler registrations, and caller domains
  /// register under the ordinary duplicate rule.
  #[test]
  fn task_reconciler_registration_reserves_the_builtin_domain() {
    let mut registry = ExtensionRegistry::new();
    let builtin = crate::QualifiedTag::parse("radiata.woooo.tech/tasks/rotate").unwrap();
    let refused = registry
      .register_task_reconciler(builtin, Arc::new(NoopReconciler))
      .unwrap_err();
    assert_eq!(refused.kind(), ErrorKind::InvalidInput);
    assert_eq!(refused.context(), "task reconciler kind");

    let caller = crate::QualifiedTag::parse("example.com/tasks/rotate-secret").unwrap();
    registry
      .register_task_reconciler(caller.clone(), Arc::new(NoopReconciler))
      .unwrap();
    let duplicate = registry
      .register_task_reconciler(caller, Arc::new(NoopReconciler))
      .unwrap_err();
    assert_eq!(duplicate.kind(), ErrorKind::Conflict);
    assert!(format!("{registry:?}").contains("task_reconcilers: 1"));
  }

  /// The built-in next-hop policy's well-known tag is an ordinary
  /// registry tag: a caller may claim it (the builder only auto-registers
  /// when absent), but a duplicate registration for it stays a conflict —
  /// the same insertion-once rule the built-in transport tag follows.
  #[test]
  fn next_hop_registry_rejects_duplicate_builtin_tag_registrations() {
    let mut registry = ExtensionRegistry::new();
    let tag = crate::routing::DefaultNextHop::tag().unwrap();
    registry
      .register_next_hop(tag.clone(), Arc::new(crate::routing::DefaultNextHop))
      .unwrap();
    let error = registry
      .register_next_hop(tag, Arc::new(crate::routing::DefaultNextHop))
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Conflict);
  }
}
