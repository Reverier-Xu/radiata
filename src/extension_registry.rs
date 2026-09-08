//! The caller-supplied extension registry (ADR-0007).
//!
//! This gate implements exactly one registration point:
//! [`ExtensionRegistry::register_protocol`] binds a [`ProtocolDefinition`]
//! to the [`PacketConsumer`] that receives admitted incoming streams for
//! that protocol tag. The remaining manifest registration points arrive
//! with their owning gates (transports and discovery G4-01, policies
//! G5/G6).

use std::{collections::BTreeMap, fmt, sync::Arc};

use crate::{
  DiscoveryTag, Error, FeatureTag, IncomingStream, ProtocolTag, Result, TransportTag,
  api::BoxFuture,
  transport::registry::{Discovery, Transport},
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
  discoveries: BTreeMap<DiscoveryTag, Arc<dyn Discovery>>,
  load_balancers:
    std::sync::Mutex<BTreeMap<crate::QualifiedTag, Arc<dyn crate::LoadBalancingPolicy>>>,
  next_hops: std::sync::Mutex<BTreeMap<crate::QualifiedTag, Arc<dyn crate::RouteNextHop>>>,
}

impl ExtensionRegistry {
  pub fn new() -> Self {
    Self::default()
  }

  /// Registers one caller-defined feature (T-G09-07): the definition's
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
  /// wins, then the built-in registry (T-G09-07).
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

  /// Registers one transport implementation under its canonical tag. A
  /// duplicate tag, a malformed or reserved tag, or a registration that
  /// conflicts with an existing entry is rejected before use; the built-in
  /// WSS transport is always present.
  pub(crate) fn register_transport(
    &mut self, tag: TransportTag, value: Arc<dyn Transport>,
  ) -> Result<&mut Self> {
    insert_once(&mut self.transports, tag, value, "transport registration")?;
    Ok(self)
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

  /// Registers one load-balancing policy under a canonical tag
  /// (T-G06-01). A duplicate tag is a conflict; registration never
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

  /// Registers one next-hop routing policy under a canonical tag
  /// (T-G06-03). A duplicate tag is a conflict; registration never
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
    formatter
      .debug_struct("ExtensionRegistry")
      .field(
        "protocols",
        &self
          .protocols
          .lock()
          .map(|protocols| protocols.len())
          .unwrap_or(0),
      )
      .field("transports", &self.transports.len())
      .field("discoveries", &self.discoveries.len())
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
}
