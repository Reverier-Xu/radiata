//! The node-local extension registry.
//!
//! [`ExtensionRegistry::register_protocol`] binds a [`ProtocolDefinition`]
//! to the [`PacketConsumer`] that receives admitted incoming streams for
//! that protocol tag, alongside caller registration of feature
//! definitions, load-balancing policies, and next-hop routing policies,
//! and caller registration of transport providers. The registry is born
//! empty: [`ExtensionRegistry::register_default`] installs the official
//! transports, the core routing policies, the built-in load balancer, and
//! the core feature definitions explicitly, and the node builder calls it
//! by default. Core protocol
//! consumers register at runtime through `register_core_protocol` once the
//! runtime context exists.

use std::{collections::BTreeMap, fmt, sync::Arc};

use crate::{
  Error, FeatureTag, IncomingStream, ProtocolTag, Result,
  api::{BoxFuture, insert_once},
  routing::RoutingRegistry,
  transport::{
    TransportName, TransportProvider,
    registry::{Transport, TransportRegistry},
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
pub struct ExtensionRegistry {
  features: std::sync::Mutex<BTreeMap<crate::FeatureTag, crate::FeatureDefinition>>,
  protocols: std::sync::RwLock<BTreeMap<ProtocolTag, Arc<ProtocolRegistration>>>,
  /// The transport map: its own registry owns selector resolution,
  /// official defaults, and caller registrations.
  transports: TransportRegistry,
  /// The routing map: its own registry owns the next-hop and stream
  /// routing policies, including the core defaults.
  routing: RoutingRegistry,
  load_balancers:
    std::sync::RwLock<BTreeMap<crate::QualifiedTag, Arc<dyn crate::LoadBalancingPolicy>>>,
  resource_hooks: std::sync::Mutex<BTreeMap<crate::QualifiedTag, Arc<dyn crate::ResourceHook>>>,
  action_hooks: std::sync::Mutex<BTreeMap<crate::QualifiedTag, Arc<dyn crate::ActionHook>>>,
  task_reconcilers:
    std::sync::Mutex<BTreeMap<crate::QualifiedTag, super::task::TaskReconcilerRegistration>>,
}

impl Default for ExtensionRegistry {
  /// The empty registry: every official and caller entry is registered
  /// explicitly. [`ExtensionRegistry::register_default`] installs the
  /// official transports, the core routing policies, the built-in load
  /// balancer, and the core feature definitions; the node builder calls
  /// it by default.
  fn default() -> Self {
    Self {
      features: std::sync::Mutex::new(BTreeMap::new()),
      protocols: std::sync::RwLock::new(BTreeMap::new()),
      transports: TransportRegistry::new(),
      routing: RoutingRegistry::new(),
      load_balancers: std::sync::RwLock::new(BTreeMap::new()),
      resource_hooks: std::sync::Mutex::new(BTreeMap::new()),
      action_hooks: std::sync::Mutex::new(BTreeMap::new()),
      task_reconcilers: std::sync::Mutex::new(BTreeMap::new()),
    }
  }
}

impl ExtensionRegistry {
  pub fn new() -> Self {
    Self::default()
  }

  /// Installs the official transports, the core routing policies, the
  /// built-in load balancer, the core feature definitions, and the core
  /// verbs' execution policies explicitly. The node builder calls this
  /// by default, so an ordinary node keeps resolving every official
  /// scheme and feature; a caller that builds its own registry sees
  /// exactly what it registered. The transports keep their own insertion
  /// rule (an explicit registration survives the default pass); every
  /// core routing entry and the built-in load balancer are installed
  /// through the ordinary insertion-once registration, so a second
  /// default pass over one registry conflicts instead of overriding.
  pub fn register_default(&mut self) -> Result<&mut Self> {
    self.transports.register_default()?;
    self.routing.register_default()?;
    {
      let mut balancers = self
        .load_balancers
        .write()
        .map_err(|_| Error::poisoned("extension registry"))?;
      crate::api::insert_once(
        &mut balancers,
        crate::routing::DefaultLoadBalancer::tag()?,
        Arc::new(crate::routing::DefaultLoadBalancer),
        "load balancer registration",
      )?;
    }
    for definition in crate::protocol::feature::builtin_definitions()? {
      self.register_core_feature(definition)?;
    }
    self.register_core_task_policies()?;
    Ok(self)
  }

  /// Registers one core (runtime-owned) feature definition. Crate-private:
  /// the default path owns the official definitions, and a caller
  /// registration under the built-in domain stays refused.
  pub(crate) fn register_core_feature(&mut self, value: crate::FeatureDefinition) -> Result<()> {
    let mut features = self
      .features
      .lock()
      .map_err(|_| Error::poisoned("extension registry"))?;
    features.entry(value.tag().clone()).or_insert(value);
    Ok(())
  }

  /// Registers one caller-defined feature: the definition's
  /// contract fingerprint joins the node's negotiation registry, so its
  /// exact digest is offered and intersected at handshake time. A
  /// duplicate tag is a conflict; the built-in domain stays reserved for
  /// the official definitions the default path installs.
  pub fn register_feature(&mut self, value: crate::FeatureDefinition) -> Result<&mut Self> {
    crate::protocol::tag::require_caller_domain(
      value.tag().domain(),
      "feature definition reserved namespace",
    )?;
    {
      let mut features = self
        .features
        .lock()
        .map_err(|_| Error::poisoned("extension registry"))?;
      insert_once(
        &mut features,
        value.tag().clone(),
        value,
        "feature registration",
      )?;
    }
    Ok(self)
  }

  /// The registered feature definitions in canonical tag order: the
  /// official definitions installed by [`ExtensionRegistry::register_default`]
  /// and every caller registration.
  pub(crate) fn feature_definitions(&self) -> Vec<crate::FeatureDefinition> {
    self
      .features
      .lock()
      .map(|features| features.values().cloned().collect())
      .unwrap_or_default()
  }

  /// The exact negotiation digest of one feature tag (the digest offered
  /// and intersected at handshake time): the registered definition, with
  /// no hidden official fallback.
  pub(crate) fn feature_digest(&self, tag: &crate::FeatureTag) -> Option<crate::Digest> {
    self
      .features
      .lock()
      .ok()
      .and_then(|features| features.get(tag).cloned())
      .and_then(|definition| definition.definition_digest().ok())
  }

  /// Registers one caller-defined transport under its addressing scheme
  /// name (the protocol prefix of the endpoint form `<name>://<opaque>`).
  /// The name is unique per node: a duplicate, a reserved name, or any
  /// other conflict is rejected before use. The official scheme names are
  /// ordinary registry names: a name claimed here before
  /// [`ExtensionRegistry::register_default`] runs occupies it, and the
  /// default path skips that scheme — the claimant's implementation serves
  /// the official URL form with no specialization. After the default path
  /// has run the name is taken, so the same claim is a `Conflict`.
  ///
  /// This seam carries no reserved-domain check by design: a transport
  /// name is a bare scheme name, not a domain-qualified tag, and the
  /// official scheme names are ordinary claimable registry names (the
  /// reserved-name rule lives in [`TransportName::parse`]).
  ///
  /// This is the public extension surface of the transport layer: the
  /// registry is the single map from scheme name to transport, and a
  /// registered name becomes dialable through the canonical form
  /// `<name>://<opaque-address>`. The binding is node-local: endpoints
  /// exchanged across nodes assume both sides bound the name identically,
  /// and a mismatch fails at the session handshake's identity proofs
  /// rather than silently.
  pub fn register_transport(
    &mut self, name: TransportName, transport: Arc<dyn TransportProvider>,
  ) -> Result<&mut Self> {
    self.transports.register_transport(name, transport)?;
    Ok(self)
  }

  /// Registers one transport implementation under a scheme name.
  /// Test-only: the default path owns the official registrations in
  /// production.
  #[cfg(test)]
  pub(crate) fn register_named_transport(
    &mut self, name: TransportName, value: Arc<dyn Transport>,
  ) -> Result<&mut Self> {
    self.transports.register_named_transport(name, value)?;
    Ok(self)
  }

  /// Resolves one endpoint's scheme name through the map: the official
  /// transports and every caller-registered transport provider merge
  /// into one resolution namespace, and a name that resolves to nothing
  /// fails typed here — at dial or listen time, never at parse time
  /// (endpoint parsing is purely syntactic and registry-free).
  pub(crate) fn resolve_transport(&self, name: &TransportName) -> Result<Arc<dyn Transport>> {
    self.transports.resolve_transport(name)
  }

  /// The registered transport for one scheme name. Test-only: production
  /// resolves through [`Self::resolve_transport`].
  #[cfg(test)]
  pub(crate) fn transport(&self, name: &TransportName) -> Option<&Arc<dyn Transport>> {
    self.transports.transport(name)
  }

  /// The routing map: next-hop and stream routing policy resolution.
  pub(crate) fn routing(&self) -> &RoutingRegistry {
    &self.routing
  }

  /// Registers one load-balancing policy under a canonical tag. The
  /// built-in `radiata.woooo.tech` domain is reserved — the built-in
  /// load balancer is installed there by the default path — so a caller
  /// policy registers under a caller-owned domain. A duplicate tag is a
  /// conflict; registration never
  /// replaces an existing entry. Matching-node stream targets resolve
  /// their `StreamPolicy` load-balancer tag here at send time.
  pub fn register_load_balancer(
    &mut self, tag: crate::QualifiedTag, value: Arc<dyn crate::LoadBalancingPolicy>,
  ) -> Result<&mut Self> {
    crate::protocol::tag::require_caller_domain(tag.domain(), "load balancer tag")?;
    {
      let mut balancers = self
        .load_balancers
        .write()
        .map_err(|_| Error::poisoned("extension registry"))?;
      insert_once(&mut balancers, tag, value, "load balancer registration")?;
    }
    Ok(self)
  }

  /// The registered load-balancing policy for one tag, when present. A
  /// poisoned registry lock surfaces as the typed registry error instead
  /// of degrading to "no policy".
  pub(crate) fn load_balancer(
    &self, tag: &crate::QualifiedTag,
  ) -> Result<Option<Arc<dyn crate::LoadBalancingPolicy>>> {
    Ok(
      self
        .load_balancers
        .read()
        .map_err(|_| Error::poisoned("extension registry"))?
        .get(tag)
        .cloned(),
    )
  }

  /// Whether the load-balancer tag is registered locally. A poisoned
  /// registry lock surfaces as the typed registry error instead of
  /// reading as an unregistered tag.
  pub(crate) fn has_load_balancer(&self, tag: &crate::QualifiedTag) -> Result<bool> {
    Ok(
      self
        .load_balancers
        .read()
        .map_err(|_| Error::poisoned("extension registry"))?
        .contains_key(tag),
    )
  }

  /// Registers one next-hop routing policy under a canonical tag. The
  /// built-in `radiata.woooo.tech` domain is reserved — the default
  /// next-hop policy is installed there by the default path — so a
  /// caller policy registers under a caller-owned domain. A duplicate
  /// tag is a conflict; registration never
  /// replaces an existing entry. A node's configured route-policy tag
  /// resolves here when a routed packet must hop through this node.
  pub fn register_next_hop(
    &mut self, tag: crate::QualifiedTag, value: Arc<dyn crate::RouteNextHop>,
  ) -> Result<&mut Self> {
    crate::protocol::tag::require_caller_domain(tag.domain(), "next-hop tag")?;
    self.routing.register_next_hop(tag, value)?;
    Ok(self)
  }

  /// The registered next-hop policy for one tag, when present. A
  /// poisoned registry lock surfaces as the typed registry error instead
  /// of degrading to "no policy". Test-only: production resolution goes
  /// through [`Self::routing`].
  #[cfg(test)]
  pub(crate) fn next_hop_policy(
    &self, tag: &crate::QualifiedTag,
  ) -> Result<Option<Arc<dyn crate::RouteNextHop>>> {
    self.routing.next_hop_policy(tag)
  }

  /// Registers one stream-level routing policy under the stream's
  /// [`crate::RoutingPolicy`] tag: the registered [`crate::RouteNextHop`]
  /// implementation plans the route for every stream carrying that
  /// policy. A duplicate tag is a conflict; registration never replaces
  /// an existing entry. The built-in `radiata.woooo.tech` domain is
  /// reserved — the core direct policy is installed there by the default
  /// path and cannot be shadowed — so a caller policy registers under a
  /// caller-owned domain.
  pub fn register_routing_policy(
    &mut self, tag: crate::QualifiedTag, value: Arc<dyn crate::RouteNextHop>,
  ) -> Result<&mut Self> {
    self.routing.register_routing_policy(tag, value)?;
    Ok(self)
  }

  /// The registered routing policy for one stream tag, when present. The
  /// admission plane resolves a stream's [`crate::RoutingPolicy`] here
  /// before the node-level route policy plans the route. A poisoned
  /// registry lock surfaces as the typed registry error instead of
  /// degrading to "no policy".
  pub(crate) fn routing_policy(
    &self, tag: &crate::QualifiedTag,
  ) -> Result<Option<Arc<dyn crate::RouteNextHop>>> {
    self.routing.routing_policy(tag)
  }

  /// The node's effective next-hop route policy tag: the caller's
  /// selection when configured, else the built-in default policy's tag.
  /// The builder resolves this once in the registration channel — right
  /// after the default registry pass installs the default policy — and
  /// the runtime reads only the resolved tag. Fail-closed: a registry
  /// without the built-in default fails typed here instead of handing
  /// the runtime a tag nothing resolves.
  pub(crate) fn effective_route_policy(
    &self, configured: Option<&crate::QualifiedTag>,
  ) -> Result<crate::QualifiedTag> {
    match configured {
      Some(tag) => Ok(tag.clone()),
      None => {
        let tag = crate::routing::DefaultNextHop::tag()?;
        if self.routing_policy(&tag)?.is_none() {
          return Err(Error::internal("default next-hop policy"));
        }
        Ok(tag)
      }
    }
  }

  /// Registers one resource-write hook under a canonical tag. The built-in
  /// `radiata.woooo.tech` domain is reserved — the crate defines no built-in
  /// resource hooks, and the namespace stays closed for them — so a caller
  /// hook registers under a caller-owned domain. All hooks
  /// registered here run in canonical tag order; a duplicate tag is a
  /// conflict and registration never replaces an existing entry.
  pub fn register_resource_hook(
    &mut self, tag: crate::QualifiedTag, hook: Arc<dyn crate::ResourceHook>,
  ) -> Result<&mut Self> {
    crate::protocol::tag::require_caller_domain(tag.domain(), "resource hook tag")?;
    {
      let mut hooks = self
        .resource_hooks
        .lock()
        .map_err(|_| Error::poisoned("extension registry"))?;
      insert_once(&mut hooks, tag, hook, "resource hook registration")?;
    }
    Ok(self)
  }

  /// Registers one task phase-transition observer under a canonical tag.
  /// The built-in `radiata.woooo.tech` domain is reserved — the crate
  /// defines no built-in action hooks, and the namespace stays closed
  /// for them — so a caller hook registers under a caller-owned domain.
  /// All hooks registered here run in canonical tag order; a duplicate
  /// tag is a conflict and registration never replaces an existing entry.
  pub fn register_action_hook(
    &mut self, tag: crate::QualifiedTag, hook: Arc<dyn crate::ActionHook>,
  ) -> Result<&mut Self> {
    crate::protocol::tag::require_caller_domain(tag.domain(), "action hook tag")?;
    {
      let mut hooks = self
        .action_hooks
        .lock()
        .map_err(|_| Error::poisoned("extension registry"))?;
      insert_once(&mut hooks, tag, hook, "action hook registration")?;
    }
    Ok(self)
  }

  /// Registers one custom task kind's reconciler under the kind tag.
  /// A duplicate tag is a conflict. The built-in `radiata.woooo.tech`
  /// domain is reserved: the core verbs are the [`crate::TaskKind`]
  /// constants under that domain, so a reconciler registered there is
  /// refused (the same reserved-domain rule the tag grammar applies to
  /// crypto tags).
  ///
  /// The registration declares the kind's execution policy: a
  /// caller-registered kind always draws from the extension slot
  /// channel and is cancelled on shutdown
  /// (`TaskReconcilePolicy::EXTENSION`) — the core verbs declare their
  /// own policies through the same channel in
  /// [`ExtensionRegistry::register_default`](Self::register_default).
  pub fn register_task_reconciler(
    &mut self, kind: crate::QualifiedTag, reconciler: Arc<dyn crate::TaskReconciler>,
  ) -> Result<&mut Self> {
    crate::protocol::tag::require_caller_domain(kind.domain(), "task reconciler kind")?;
    {
      let mut reconcilers = self
        .task_reconcilers
        .lock()
        .map_err(|_| Error::poisoned("extension registry"))?;
      insert_once(
        &mut reconcilers,
        kind,
        super::task::TaskReconcilerRegistration {
          reconciler: Some(reconciler),
          policy: super::task::TaskReconcilePolicy::EXTENSION,
        },
        "task reconciler registration",
      )?;
    }
    Ok(self)
  }

  /// Declares the core verbs' execution policies onto the reconciler
  /// registration channel (see
  /// [`crate::task::core_task_policies`]): policy-only records — the
  /// core effects are the runtime's own closures, never registered
  /// reconcilers — and never replacing an existing entry, like every
  /// other default.
  pub(crate) fn register_core_task_policies(&mut self) -> Result<()> {
    let mut reconcilers = self
      .task_reconcilers
      .lock()
      .map_err(|_| Error::poisoned("extension registry"))?;
    for (kind, policy) in crate::task::core_task_policies() {
      reconcilers
        .entry(kind.tag().clone())
        .or_insert(super::task::TaskReconcilerRegistration {
          reconciler: None,
          policy,
        });
    }
    Ok(())
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

  /// The registered resource hooks in canonical tag order (the order
  /// they validate, mutate, and observe one write in). Cloned per use:
  /// the hook map is a `std` mutex and must not be held across the
  /// hooks' awaits.
  pub(crate) fn resource_hooks(&self) -> Vec<Arc<dyn crate::ResourceHook>> {
    self
      .resource_hooks
      .lock()
      .map(|hooks| hooks.values().cloned().collect())
      .unwrap_or_default()
  }

  /// The reconciler registered for one custom task kind tag, when
  /// present (the `tasks().submit` admission resolves the kind's
  /// effect through this lookup). Core verbs have policy-only records
  /// and never carry one.
  pub(crate) fn task_reconciler(
    &self, kind: &crate::QualifiedTag,
  ) -> Option<Arc<dyn crate::TaskReconciler>> {
    self
      .task_reconcilers
      .lock()
      .ok()
      .and_then(|reconcilers| reconcilers.get(kind).and_then(|r| r.reconciler.clone()))
  }

  /// The execution policy registered for one task kind, when present:
  /// the slot class its effect draws from and whether the shutdown
  /// drain awaits it. The task manager's admission resolves it once and
  /// stores it on the admitted entry.
  pub(crate) fn task_reconciler_policy(
    &self, kind: &crate::TaskKind,
  ) -> Option<super::task::TaskReconcilePolicy> {
    self
      .task_reconcilers
      .lock()
      .ok()
      .and_then(|reconcilers| reconcilers.get(kind.tag()).map(|r| r.policy))
  }

  /// Registers one packet protocol and its consumer. A duplicate protocol
  /// tag is a conflict; registration never replaces an existing entry. The
  /// built-in `radiata.woooo.tech` domain is reserved — the core protocols
  /// are installed there by the runtime — so a caller protocol registers
  /// under a caller-owned domain instead of failing later at `start()`.
  pub fn register_protocol(
    &mut self, value: ProtocolDefinition, consumer: Arc<dyn PacketConsumer>,
  ) -> Result<&mut Self> {
    crate::protocol::tag::require_caller_domain(value.tag.domain(), "protocol registration")?;
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
    let mut protocols = self
      .protocols
      .write()
      .map_err(|_| Error::poisoned("extension registry"))?;
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

  /// The registration for one protocol tag, when present. A poisoned
  /// registry lock surfaces as the typed registry error instead of
  /// degrading to "no registration".
  pub(crate) fn protocol(&self, tag: &ProtocolTag) -> Result<Option<Arc<ProtocolRegistration>>> {
    Ok(
      self
        .protocols
        .read()
        .map_err(|_| Error::poisoned("extension registry"))?
        .get(tag)
        .cloned(),
    )
  }

  /// Whether the protocol tag is registered locally. A poisoned registry
  /// lock surfaces as the typed registry error instead of reading as an
  /// unregistered protocol.
  pub(crate) fn has_protocol(&self, tag: &ProtocolTag) -> Result<bool> {
    Ok(
      self
        .protocols
        .read()
        .map_err(|_| Error::poisoned("extension registry"))?
        .contains_key(tag),
    )
  }
}

impl fmt::Debug for ExtensionRegistry {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    let mut builder = formatter.debug_struct("ExtensionRegistry");
    builder.field(
      "protocols",
      &self
        .protocols
        .read()
        .map(|protocols| protocols.len())
        .unwrap_or(0),
    );
    builder.field("transports", &self.transports.len());
    builder
      .field(
        "load_balancers",
        &self
          .load_balancers
          .read()
          .map(|balancers| balancers.len())
          .unwrap_or(0),
      )
      .field("next_hops", &self.routing.next_hop_count())
      .field("routing_policies", &self.routing.routing_policy_count())
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

#[cfg(test)]
mod tests {
  use std::sync::Arc;

  use super::{ExtensionRegistry, PacketConsumer, ProtocolDefinition};
  use crate::{
    Digest, ErrorKind, FeatureDefinition, FeatureTag, IncomingStream, ProtocolTag, Result,
    api::BoxFuture,
  };

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
  struct NoopLoadBalancer;

  impl crate::LoadBalancingPolicy for NoopLoadBalancer {
    fn select<'a>(
      &'a self, _selector: &'a crate::routing::Selector,
      _candidates: &'a dyn crate::CandidateNodeReader,
    ) -> crate::api::BoxFuture<'a, Result<crate::NodeId>> {
      Box::pin(async { Err(crate::Error::route_unavailable("packet candidates")) })
    }
  }

  #[derive(Debug)]
  struct NoopReconciler;

  impl crate::TaskReconciler for NoopReconciler {
    fn reconcile<'a>(
      &'a self, _ctx: crate::ReconcileContext,
    ) -> crate::BoxFuture<'a, Result<crate::ReconcileDecision>> {
      Box::pin(async { Ok(crate::ReconcileDecision::Succeeded) })
    }
  }

  /// A caller protocol definition under a caller-owned domain: the
  /// built-in domain is reserved for the core registrations.
  fn definition(name: &str) -> ProtocolDefinition {
    ProtocolDefinition::new(
      ProtocolTag::parse(&format!("example.org/protocols/{name}")).unwrap(),
      FeatureTag::parse("radiata.woooo.tech/features/data-messages").unwrap(),
    )
  }

  #[test]
  fn register_default_installs_official_features_and_refuses_caller_builtin_definitions() {
    let mut registry = ExtensionRegistry::new();
    assert!(registry.feature_definitions().is_empty());
    registry.register_default().unwrap();
    assert_eq!(
      registry.feature_definitions().len(),
      crate::protocol::feature::builtin_definitions()
        .unwrap()
        .len(),
      "the default path installs every official feature definition"
    );

    let builtin = FeatureDefinition::new(
      FeatureTag::parse("radiata.woooo.tech/features/session-core").unwrap(),
      Digest::from_bytes([7; 32]),
    )
    .unwrap();
    let refused = registry.register_feature(builtin).unwrap_err();
    assert_eq!(refused.kind(), ErrorKind::InvalidInput);
    assert_eq!(refused.context(), "feature definition reserved namespace");
  }

  #[test]
  fn tls_transport_extension_registry_registers_and_rejects_duplicates() {
    let mut registry = ExtensionRegistry::new();
    registry
      .register_protocol(definition("alpha"), Arc::new(NoopConsumer))
      .unwrap();
    assert!(
      registry
        .has_protocol(&ProtocolTag::parse("example.org/protocols/alpha").unwrap())
        .unwrap()
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
      registry
        .has_protocol(&ProtocolTag::parse("example.org/protocols/beta").unwrap())
        .unwrap()
    );
    assert!(
      !registry
        .has_protocol(&ProtocolTag::parse("example.org/protocols/gamma").unwrap())
        .unwrap()
    );
  }

  /// The built-in domain is reserved for the core registrations: a caller
  /// protocol under it is refused at registration instead of failing later
  /// at `start()` with a `Conflict`. The core path still installs the same
  /// tag.
  #[test]
  fn caller_protocols_under_the_builtin_domain_are_refused() {
    let mut registry = ExtensionRegistry::new();
    let builtin = || {
      ProtocolDefinition::new(
        ProtocolTag::parse("radiata.woooo.tech/protocols/v1/reconcile").unwrap(),
        FeatureTag::parse("radiata.woooo.tech/features/data-messages").unwrap(),
      )
    };
    let refused = registry
      .register_protocol(builtin(), Arc::new(NoopConsumer))
      .unwrap_err();
    assert_eq!(refused.kind(), ErrorKind::InvalidInput);
    assert_eq!(refused.context(), "protocol registration");

    registry
      .register_core_protocol(builtin(), Arc::new(NoopConsumer))
      .unwrap();
    assert!(
      registry
        .has_protocol(&ProtocolTag::parse("radiata.woooo.tech/protocols/v1/reconcile").unwrap())
        .unwrap()
    );
  }

  /// The read-mostly maps guard lookups with a shared lock and only
  /// registration takes the exclusive lock: concurrent protocol,
  /// load-balancer, and next-hop lookups coexist with a thread exercising
  /// the late `&self` core-registration path — duplicate registrations
  /// stay conflicts, the one new tag registers, and every lookup keeps
  /// resolving exactly the registered entries. Completion is the
  /// no-deadlock proof.
  #[test]
  fn concurrent_lookups_coexist_with_late_core_registration() {
    use std::sync::Barrier;

    let mut registry = ExtensionRegistry::new();
    let alpha = definition("alpha");
    let alpha_tag = alpha.tag.clone();
    registry
      .register_protocol(alpha, Arc::new(NoopConsumer))
      .unwrap();
    let expected_registration = registry.protocol(&alpha_tag).unwrap().unwrap();

    let balancer_tag = crate::QualifiedTag::parse("example.com/policies/pinned").unwrap();
    registry
      .register_load_balancer(balancer_tag.clone(), Arc::new(NoopLoadBalancer))
      .unwrap();
    let expected_balancer = registry.load_balancer(&balancer_tag).unwrap().unwrap();

    let hop_tag = crate::QualifiedTag::parse("example.com/next-hops/hop").unwrap();
    registry
      .register_next_hop(
        hop_tag.clone(),
        Arc::new(crate::routing::DefaultNextHop::default()),
      )
      .unwrap();
    let expected_hop = registry.next_hop_policy(&hop_tag).unwrap().unwrap();

    let registry = std::sync::Arc::new(registry);

    let readers = 4;
    let iterations = 1_000;
    let barrier = Arc::new(Barrier::new(readers + 1));
    let mut reader_handles = Vec::new();
    for _ in 0..readers {
      let registry = Arc::clone(&registry);
      let alpha_tag = alpha_tag.clone();
      let expected_registration = Arc::clone(&expected_registration);
      let balancer_tag = balancer_tag.clone();
      let expected_balancer = Arc::clone(&expected_balancer);
      let hop_tag = hop_tag.clone();
      let expected_hop = Arc::clone(&expected_hop);
      let barrier = Arc::clone(&barrier);
      reader_handles.push(std::thread::spawn(move || {
        barrier.wait();
        for _ in 0..iterations {
          let registration = registry.protocol(&alpha_tag).unwrap().unwrap();
          assert!(Arc::ptr_eq(&registration, &expected_registration));
          assert!(registry.has_protocol(&alpha_tag).unwrap());
          let balancer = registry.load_balancer(&balancer_tag).unwrap().unwrap();
          assert!(Arc::ptr_eq(&balancer, &expected_balancer));
          let hop = registry.next_hop_policy(&hop_tag).unwrap().unwrap();
          assert!(Arc::ptr_eq(&hop, &expected_hop));
        }
      }));
    }

    let writer = {
      let registry = Arc::clone(&registry);
      let barrier = Arc::clone(&barrier);
      std::thread::spawn(move || {
        barrier.wait();
        for _ in 0..256 {
          let error = registry
            .register_core_protocol(definition("alpha"), Arc::new(NoopConsumer))
            .unwrap_err();
          assert_eq!(error.kind(), ErrorKind::Conflict);
        }
        registry
          .register_core_protocol(definition("beta"), Arc::new(NoopConsumer))
          .unwrap();
      })
    };

    for handle in reader_handles {
      handle.join().unwrap();
    }
    writer.join().unwrap();

    let beta = definition("beta");
    assert!(registry.has_protocol(&beta.tag).unwrap());
    assert!(registry.has_protocol(&alpha_tag).unwrap());
    assert!(Arc::ptr_eq(
      &registry.protocol(&alpha_tag).unwrap().unwrap(),
      &expected_registration
    ));
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

  /// Core verbs are the `TaskKind` constants under the built-in domain:
  /// that domain is reserved for task-reconciler registrations, and
  /// caller domains register under the ordinary duplicate rule.
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

  /// The execution policy rides the registration, not the tag being a
  /// core verb: `register_default` declares the core verbs' policies as
  /// policy-only records (a core kind carries no reconciler), a caller
  /// registration declares the extension policy, and a second default
  /// pass changes nothing.
  #[test]
  fn task_policies_are_declared_on_the_registration_channel() {
    let mut registry = ExtensionRegistry::new();
    assert!(
      registry
        .task_reconciler_policy(&crate::TaskKind::JOIN)
        .is_none()
    );
    registry.register_default().unwrap();
    let join = registry
      .task_reconciler_policy(&crate::TaskKind::JOIN)
      .expect("register_default declares every core verb");
    assert_eq!(join.slot_class, crate::task::SlotClass::Network);
    assert!(!join.drains_on_shutdown);
    let leave = registry
      .task_reconciler_policy(&crate::TaskKind::LEAVE)
      .expect("register_default declares every core verb");
    assert_eq!(leave.slot_class, crate::task::SlotClass::Local);
    assert!(leave.drains_on_shutdown);
    // Core verbs are policy-only: no reconciler resolves for them.
    assert!(
      registry
        .task_reconciler(crate::TaskKind::JOIN.tag())
        .is_none()
    );

    let caller = crate::QualifiedTag::parse("example.com/tasks/rotate-secret").unwrap();
    registry
      .register_task_reconciler(caller.clone(), Arc::new(NoopReconciler))
      .unwrap();
    let policy = registry
      .task_reconciler_policy(&crate::TaskKind::from(caller))
      .expect("the registration declares the kind's policy");
    assert_eq!(policy.slot_class, crate::task::SlotClass::Extension);
    assert!(!policy.drains_on_shutdown);

    // Core registration is insertion-once: a second default pass over
    // the same registry conflicts instead of overriding or silently
    // keeping a claim (the same rule the built-in next-hop follows).
    let second_pass = registry.register_default().unwrap_err();
    assert_eq!(second_pass.kind(), ErrorKind::Conflict);
    assert_eq!(
      registry
        .task_reconciler_policy(&crate::TaskKind::JOIN)
        .unwrap()
        .slot_class,
      crate::task::SlotClass::Network
    );
  }

  /// The built-in domain is reserved on every tag-keyed caller seam: a
  /// load-balancer, next-hop, resource-hook, or action-hook registration
  /// under it is refused at registration (the built-in load balancer and
  /// next-hop policy are installed there by the default path), while the
  /// caller-owned domains follow the ordinary duplicate rule.
  #[test]
  fn the_builtin_domain_is_reserved_on_every_tag_keyed_registration_seam() {
    let mut registry = ExtensionRegistry::new();
    let builtin = [
      "radiata.woooo.tech/policies/default-load-balance",
      "radiata.woooo.tech/route-policies/default-next-hop",
      "radiata.woooo.tech/hooks/resource",
      "radiata.woooo.tech/hooks/action",
    ];
    let expected_context = [
      "load balancer tag",
      "next-hop tag",
      "resource hook tag",
      "action hook tag",
    ];
    let refused_balancer = registry
      .register_load_balancer(
        crate::QualifiedTag::parse(builtin[0]).unwrap(),
        Arc::new(NoopLoadBalancer),
      )
      .unwrap_err();
    assert_eq!(refused_balancer.kind(), ErrorKind::InvalidInput);
    let refused_hop = registry
      .register_next_hop(
        crate::QualifiedTag::parse(builtin[1]).unwrap(),
        Arc::new(crate::routing::DefaultNextHop::default()),
      )
      .unwrap_err();
    assert_eq!(refused_hop.kind(), ErrorKind::InvalidInput);
    let refused_resource = registry
      .register_resource_hook(
        crate::QualifiedTag::parse(builtin[2]).unwrap(),
        Arc::new(NoopResourceHook),
      )
      .unwrap_err();
    assert_eq!(refused_resource.kind(), ErrorKind::InvalidInput);
    let refused_action = registry
      .register_action_hook(
        crate::QualifiedTag::parse(builtin[3]).unwrap(),
        Arc::new(NoopActionHook),
      )
      .unwrap_err();
    assert_eq!(refused_action.kind(), ErrorKind::InvalidInput);
    for (error, context) in [
      refused_balancer,
      refused_hop,
      refused_resource,
      refused_action,
    ]
    .into_iter()
    .zip(expected_context)
    {
      assert_eq!(error.context(), context);
    }

    // The same four seams accept caller-owned domains and keep the
    // insertion-once duplicate rule there.
    let caller_tags = [
      "example.com/policies/pinned",
      "example.com/next-hops/hop",
      "example.com/hooks/resource",
      "example.com/hooks/action",
    ];
    registry
      .register_load_balancer(
        crate::QualifiedTag::parse(caller_tags[0]).unwrap(),
        Arc::new(NoopLoadBalancer),
      )
      .unwrap();
    registry
      .register_next_hop(
        crate::QualifiedTag::parse(caller_tags[1]).unwrap(),
        Arc::new(crate::routing::DefaultNextHop::default()),
      )
      .unwrap();
    registry
      .register_resource_hook(
        crate::QualifiedTag::parse(caller_tags[2]).unwrap(),
        Arc::new(NoopResourceHook),
      )
      .unwrap();
    registry
      .register_action_hook(
        crate::QualifiedTag::parse(caller_tags[3]).unwrap(),
        Arc::new(NoopActionHook),
      )
      .unwrap();
    let duplicate = registry
      .register_load_balancer(
        crate::QualifiedTag::parse(caller_tags[0]).unwrap(),
        Arc::new(NoopLoadBalancer),
      )
      .unwrap_err();
    assert_eq!(duplicate.kind(), ErrorKind::Conflict);
  }

  /// The default next-hop policy's well-known tag is installed by the
  /// default path through insertion-once: a caller registration for it
  /// is refused as a reserved-domain claim, and after the default pass
  /// the same claim is refused the same way (the reservation precedes
  /// the conflict check).
  #[test]
  fn next_hop_registry_rejects_duplicate_builtin_tag_registrations() {
    let mut registry = ExtensionRegistry::new();
    registry.register_default().unwrap();
    let tag = crate::routing::DefaultNextHop::tag().unwrap();
    let error = registry
      .register_next_hop(tag, Arc::new(crate::routing::DefaultNextHop::default()))
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert_eq!(error.context(), "next-hop tag");
  }

  /// The routing-policy registry starts empty, the explicit default path
  /// installs the core direct policy, and the other rules hold: the
  /// built-in domain is reserved (the direct tag cannot be shadowed), a
  /// caller policy registers under a caller-owned domain, and a duplicate
  /// tag stays a conflict.
  #[test]
  fn routing_policy_registry_defaults_direct_and_reserves_the_builtin_domain() {
    let mut registry = ExtensionRegistry::new();
    assert!(
      registry
        .routing_policy(crate::RoutingPolicy::DIRECT.tag())
        .unwrap()
        .is_none(),
      "a fresh registry holds no hidden direct policy"
    );
    registry.register_default().unwrap();
    assert!(
      registry
        .routing_policy(crate::RoutingPolicy::DIRECT.tag())
        .unwrap()
        .is_some(),
      "the default path installs the direct policy"
    );

    let reserved = registry
      .register_routing_policy(
        crate::RoutingPolicy::DIRECT.tag().clone(),
        Arc::new(crate::routing::DefaultNextHop::default()),
      )
      .unwrap_err();
    assert_eq!(reserved.kind(), ErrorKind::InvalidInput);
    assert_eq!(reserved.context(), "routing policy tag");

    let caller = crate::QualifiedTag::parse("example.com/route-policies/shortest").unwrap();
    registry
      .register_routing_policy(
        caller.clone(),
        Arc::new(crate::routing::DefaultNextHop::default()),
      )
      .unwrap();
    assert!(registry.routing_policy(&caller).unwrap().is_some());
    let duplicate = registry
      .register_routing_policy(caller, Arc::new(crate::routing::DefaultNextHop::default()))
      .unwrap_err();
    assert_eq!(duplicate.kind(), ErrorKind::Conflict);
    assert!(
      format!("{registry:?}").contains("routing_policies: 2"),
      "the debug summary counts the default and caller policies"
    );
  }

  /// The default next-hop policy is an ordinary registry entry the
  /// default path installs through insertion-once: a fresh registry
  /// resolves it after the default pass, and a second default pass
  /// conflicts instead of overriding or silently keeping a claim.
  #[test]
  fn register_default_installs_the_default_next_hop_through_insertion_once() {
    let mut registry = ExtensionRegistry::new();
    let tag = crate::routing::DefaultNextHop::tag().unwrap();
    assert!(
      registry.next_hop_policy(&tag).unwrap().is_none(),
      "a fresh registry holds no hidden default next-hop policy"
    );
    registry.register_default().unwrap();
    assert!(registry.next_hop_policy(&tag).unwrap().is_some());
    let second_pass = registry.register_default().unwrap_err();
    assert_eq!(second_pass.kind(), ErrorKind::Conflict);
  }
}
