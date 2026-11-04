//! Domain-qualified feature label definitions and the closed validation
//! registry.
//!
//! A [`FeatureDefinition`] is the immutable contract behind one feature
//! label. Its definition digest is SHA-256 over the deterministic-CBOR
//! encoding of the full canonical record: tag, contract fingerprint, sorted
//! dependencies, sorted conflicts, and sorted protocol handlers.
//!
//! Built-in contract fingerprints are fixed 32-byte values derived as
//! SHA-256 of one exact frozen seed string per feature:
//!
//! ```text
//! seed = "radiata.woooo.tech/crypto/v1/feature-fingerprint/" ++ <full feature tag>
//! ```
//!
//! The five frozen seeds are:
//!
//! - `radiata.woooo.tech/crypto/v1/feature-fingerprint/radiata.woooo.tech/
//!   features/ auth-ed25519-session`
//! - `radiata.woooo.tech/crypto/v1/feature-fingerprint/radiata.woooo.tech/
//!   features/ session-core`
//! - `radiata.woooo.tech/crypto/v1/feature-fingerprint/radiata.woooo.tech/
//!   features/ data-messages`
//! - `radiata.woooo.tech/crypto/v1/feature-fingerprint/radiata.woooo.tech/
//!   features/ direct-request`
//! - `radiata.woooo.tech/crypto/v1/feature-fingerprint/radiata.woooo.tech/
//!   features/ routed-delivery`
//!
//! `handshake_feature_registry_golden_fixture_is_frozen` pins the exact
//! fingerprints and definition digests those seeds produce.

use std::collections::BTreeMap;

use minicbor::Encode;

use super::{
  CborLimits, FeatureTag, MAX_BODY_BYTES, ProtocolTag, encode_canonical, tag::BUILTIN_DOMAIN,
};
use crate::{Digest, Error, Result, identity::signature::body_digest};
const FINGERPRINT_SEED_PREFIX: &str = "radiata.woooo.tech/crypto/v1/feature-fingerprint/";

pub(crate) const AUTH_ED25519_SESSION: &str = "radiata.woooo.tech/features/auth-ed25519-session";
pub(crate) const SESSION_CORE: &str = "radiata.woooo.tech/features/session-core";
pub(crate) const DATA_MESSAGES: &str = "radiata.woooo.tech/features/data-messages";
pub(crate) const DIRECT_REQUEST: &str = "radiata.woooo.tech/features/direct-request";
pub(crate) const ROUTED_DELIVERY: &str = "radiata.woooo.tech/features/routed-delivery";

/// The five built-in feature labels in declaration order. Fixtures and
/// tests reuse this single list so adding a built-in feature cannot
/// silently desynchronize the offer and selection fixtures.
#[cfg(test)]
pub(crate) const BUILTIN_FEATURE_LABELS: [&str; 5] = [
  AUTH_ED25519_SESSION,
  SESSION_CORE,
  DATA_MESSAGES,
  DIRECT_REQUEST,
  ROUTED_DELIVERY,
];
const DIRECT_REQUEST_PROTOCOL: &str = "radiata.woooo.tech/protocols/direct-request";

const DEFINITION_LIMITS: CborLimits = CborLimits::new(16, 1_024, MAX_BODY_BYTES);

/// The canonical immutable contract behind one negotiated feature label.
#[derive(Clone, Debug)]
pub struct FeatureDefinition {
  tag: FeatureTag,
  fingerprint: Digest,
  dependencies: Vec<FeatureTag>,
  conflicts: Vec<FeatureTag>,
  protocols: Vec<ProtocolTag>,
}

impl FeatureDefinition {
  /// Starts a definition for an extension feature label with its immutable
  /// 32-byte contract fingerprint.
  ///
  /// The built-in `radiata.woooo.tech` domain is reserved for the frozen
  /// built-in definitions and is rejected here.
  pub fn new(tag: FeatureTag, fingerprint: Digest) -> Result<Self> {
    if tag.domain() == BUILTIN_DOMAIN {
      return Err(Error::invalid_input(
        "feature definition reserved namespace",
      ));
    }
    Ok(Self::unchecked(tag, fingerprint))
  }

  /// Adds an immutable required feature label.
  pub fn dependency(mut self, tag: FeatureTag) -> Result<Self> {
    if tag == self.tag {
      return Err(Error::invalid_input("feature dependency self"));
    }
    if self.dependencies.contains(&tag) {
      return Err(Error::invalid_input("feature dependency duplicate"));
    }
    self.dependencies.push(tag);
    Ok(self)
  }

  /// Adds a symmetric, irreflexive conflicting feature label.
  pub fn conflict(mut self, tag: FeatureTag) -> Result<Self> {
    if tag == self.tag {
      return Err(Error::invalid_input("feature conflict self"));
    }
    if self.conflicts.contains(&tag) {
      return Err(Error::invalid_input("feature conflict duplicate"));
    }
    self.conflicts.push(tag);
    Ok(self)
  }

  /// Claims ownership of a domain-qualified protocol handler tag.
  pub fn protocol(mut self, tag: ProtocolTag) -> Result<Self> {
    if self.protocols.contains(&tag) {
      return Err(Error::invalid_input("feature protocol duplicate"));
    }
    self.protocols.push(tag);
    Ok(self)
  }

  fn unchecked(tag: FeatureTag, fingerprint: Digest) -> Self {
    Self {
      tag,
      fingerprint,
      dependencies: Vec::new(),
      conflicts: Vec::new(),
      protocols: Vec::new(),
    }
  }

  pub(crate) const fn tag(&self) -> &FeatureTag {
    &self.tag
  }

  /// The immutable contract fingerprint included in the definition digest
  /// input.
  #[cfg(test)]
  pub(crate) const fn fingerprint(&self) -> &Digest {
    &self.fingerprint
  }

  pub(crate) fn dependencies(&self) -> &[FeatureTag] {
    &self.dependencies
  }

  pub(crate) fn conflicts(&self) -> &[FeatureTag] {
    &self.conflicts
  }

  pub(crate) fn protocols(&self) -> &[ProtocolTag] {
    &self.protocols
  }

  /// Computes SHA-256 over the deterministic-CBOR canonical definition.
  pub(crate) fn definition_digest(&self) -> Result<Digest> {
    let bytes = encode_canonical(&self.wire(), DEFINITION_LIMITS)?;
    Ok(body_digest(&bytes))
  }

  fn wire(&self) -> DefinitionWire {
    let mut dependencies: Vec<String> = self
      .dependencies
      .iter()
      .map(|tag| tag.as_str().to_owned())
      .collect();
    dependencies.sort();
    let mut conflicts: Vec<String> = self
      .conflicts
      .iter()
      .map(|tag| tag.as_str().to_owned())
      .collect();
    conflicts.sort();
    let mut protocols: Vec<String> = self
      .protocols
      .iter()
      .map(|tag| tag.as_str().to_owned())
      .collect();
    protocols.sort();
    DefinitionWire {
      tag: self.tag.as_str().to_owned(),
      fingerprint: self.fingerprint.as_bytes().to_vec(),
      dependencies,
      conflicts,
      protocols,
    }
  }
}

#[derive(Encode)]
#[cbor(array)]
struct DefinitionWire {
  #[n(0)]
  tag: String,
  #[n(1)]
  #[cbor(with = "minicbor::bytes")]
  fingerprint: Vec<u8>,
  #[n(2)]
  dependencies: Vec<String>,
  #[n(3)]
  conflicts: Vec<String>,
  #[n(4)]
  protocols: Vec<String>,
}

/// The closed, validated set of locally implemented feature definitions.
#[derive(Debug)]
pub(crate) struct FeatureRegistry {
  definitions: BTreeMap<FeatureTag, FeatureDefinition>,
}

impl FeatureRegistry {
  /// Builds a registry, rejecting duplicate labels, reserved-namespace
  /// misuse, missing dependencies, dependency cycles, asymmetric or self
  /// conflicts, and duplicate protocol handler ownership.
  pub(crate) fn build(definitions: Vec<FeatureDefinition>) -> Result<Self> {
    let mut map: BTreeMap<FeatureTag, FeatureDefinition> = BTreeMap::new();
    for definition in definitions {
      if map.insert(definition.tag().clone(), definition).is_some() {
        return Err(Error::invalid_input("feature registry duplicate label"));
      }
    }
    let builtins = builtin_definitions()?;
    for definition in map.values() {
      check_reserved_namespace(definition, &builtins)?;
    }
    check_dependencies(&map)?;
    check_conflicts(&map)?;
    check_unique_ownership(&map)?;
    Ok(Self { definitions: map })
  }

  /// Builds the frozen built-in registry.
  pub(crate) fn builtin() -> Result<Self> {
    Self::build(builtin_definitions()?)
  }

  pub(crate) fn get(&self, tag: &FeatureTag) -> Option<&FeatureDefinition> {
    self.definitions.get(tag)
  }

  /// Iterates every registered definition in canonical tag order.
  pub(crate) fn iter(&self) -> impl Iterator<Item = (&FeatureTag, &FeatureDefinition)> {
    self.definitions.iter()
  }
}

/// The built-in features every session requires: the Ed25519 session
/// authentication and the session core it anchors.
pub(crate) fn required_session_features() -> Result<[FeatureTag; 2]> {
  Ok([
    FeatureTag::parse(AUTH_ED25519_SESSION)?,
    FeatureTag::parse(SESSION_CORE)?,
  ])
}

fn check_reserved_namespace(
  definition: &FeatureDefinition, builtins: &[FeatureDefinition],
) -> Result<()> {
  if definition.tag().domain() != BUILTIN_DOMAIN {
    return Ok(());
  }
  let actual = definition.definition_digest()?;
  for candidate in builtins {
    if candidate.tag() == definition.tag() && candidate.definition_digest()? == actual {
      return Ok(());
    }
  }
  Err(Error::invalid_input("feature registry reserved namespace"))
}

fn check_dependencies(definitions: &BTreeMap<FeatureTag, FeatureDefinition>) -> Result<()> {
  #[derive(Clone, Copy, Eq, PartialEq)]
  enum Mark {
    Visiting,
    Done,
  }

  fn visit<'registry>(
    tag: &'registry FeatureTag, definitions: &'registry BTreeMap<FeatureTag, FeatureDefinition>,
    marks: &mut BTreeMap<&'registry FeatureTag, Mark>,
  ) -> Result<()> {
    match marks.get(tag) {
      Some(Mark::Done) => return Ok(()),
      Some(Mark::Visiting) => {
        return Err(Error::invalid_input("feature registry dependency cycle"));
      }
      None => {}
    }
    marks.insert(tag, Mark::Visiting);
    let definition = definitions
      .get(tag)
      .ok_or_else(|| Error::invalid_input("feature registry missing dependency"))?;
    for dependency in definition.dependencies() {
      visit(dependency, definitions, marks)?;
    }
    marks.insert(tag, Mark::Done);
    Ok(())
  }

  let mut marks = BTreeMap::new();
  for tag in definitions.keys() {
    visit(tag, definitions, &mut marks)?;
  }
  Ok(())
}

fn check_conflicts(definitions: &BTreeMap<FeatureTag, FeatureDefinition>) -> Result<()> {
  for definition in definitions.values() {
    for conflict in definition.conflicts() {
      if conflict == definition.tag() {
        return Err(Error::invalid_input("feature registry self conflict"));
      }
      let Some(other) = definitions.get(conflict) else {
        return Err(Error::invalid_input("feature registry asymmetric conflict"));
      };
      if !other.conflicts().contains(definition.tag()) {
        return Err(Error::invalid_input("feature registry asymmetric conflict"));
      }
    }
  }
  Ok(())
}

fn check_unique_ownership(definitions: &BTreeMap<FeatureTag, FeatureDefinition>) -> Result<()> {
  let mut protocols: BTreeMap<&ProtocolTag, ()> = BTreeMap::new();
  for definition in definitions.values() {
    for protocol in definition.protocols() {
      if protocols.insert(protocol, ()).is_some() {
        return Err(Error::invalid_input(
          "feature registry duplicate protocol owner",
        ));
      }
    }
  }
  Ok(())
}

pub(crate) fn builtin_definitions() -> Result<Vec<FeatureDefinition>> {
  let auth = builtin(AUTH_ED25519_SESSION)?;
  let session = builtin(SESSION_CORE)?.dependency(FeatureTag::parse(AUTH_ED25519_SESSION)?)?;
  let data = builtin(DATA_MESSAGES)?.dependency(FeatureTag::parse(SESSION_CORE)?)?;
  let direct = builtin(DIRECT_REQUEST)?
    .dependency(FeatureTag::parse(DATA_MESSAGES)?)?
    .protocol(ProtocolTag::parse(DIRECT_REQUEST_PROTOCOL)?)?;
  let routed = builtin(ROUTED_DELIVERY)?.dependency(FeatureTag::parse(DATA_MESSAGES)?)?;
  Ok(vec![auth, session, data, direct, routed])
}

fn builtin(tag: &str) -> Result<FeatureDefinition> {
  let tag = FeatureTag::parse(tag)?;
  let fingerprint = builtin_fingerprint(&tag);
  Ok(FeatureDefinition::unchecked(tag, fingerprint))
}

fn builtin_fingerprint(tag: &FeatureTag) -> Digest {
  let mut seed = String::with_capacity(FINGERPRINT_SEED_PREFIX.len() + tag.as_str().len());
  seed.push_str(FINGERPRINT_SEED_PREFIX);
  seed.push_str(tag.as_str());
  body_digest(seed.as_bytes())
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{
    QualifiedTag,
    hex::encode as hex,
    protocol::offer::fixtures::{extension_feature, extension_tag},
  };

  fn builtin_definition(name: &str) -> FeatureDefinition {
    builtin_definitions()
      .unwrap()
      .into_iter()
      .find(|definition| definition.tag().as_str() == name)
      .unwrap()
  }

  #[test]
  fn handshake_feature_registry_golden_fixture_is_frozen() {
    let registry = FeatureRegistry::builtin().unwrap();
    let cases = [
      (
        AUTH_ED25519_SESSION,
        "8f83df98c958318ec3d96e4b0d16fa0e49550244a56c3e62580248a499b3ad43",
        "3df87b424b76c2b0e73284e877679a07aeb1688c150bf90a99c6bc667f0b8aae",
      ),
      (
        SESSION_CORE,
        "c1e856e3ba8381bb6fbead84dfff0f28aaee5b77e4a54efd47293e2357091edd",
        "22373a9809f3ec58a1becf45acb4dfae3da54151973534fcfc18aeab57f0f874",
      ),
      (
        DATA_MESSAGES,
        "c5145330004d71f5bc628652ff94689c944ff21a288cb8230d732cbd3ff6a62f",
        "b65136c721b44eb602c70788a372644af3b738ccfe0437c2ba33060a89ff9d2f",
      ),
      (
        DIRECT_REQUEST,
        "f267e89141b80aab766cd167502a55e5662567a7ca5ac02c091f1ec5c5003d8b",
        "7dfa9f0d5f24bf399f1ff3dd7f3354f09a7448d0a48b8e0b6e98c5b56e4e0a27",
      ),
      (
        ROUTED_DELIVERY,
        "6ba9b5e1ff674801f0fcb9f91c58971bec5fb085cf9f6d61674d028655f66db7",
        "57dfd16e43af9dbf7a4e47bdbeb40cb50d2f031d0355bb126dc3c16134f859a5",
      ),
    ];
    for (name, fingerprint, digest) in cases {
      let definition = registry.get(&FeatureTag::parse(name).unwrap()).unwrap();
      assert_eq!(
        hex(definition.fingerprint().as_bytes()),
        fingerprint,
        "{name}"
      );
      assert_eq!(
        hex(definition.definition_digest().unwrap().as_bytes()),
        digest,
        "{name}"
      );
    }
  }

  #[test]
  fn handshake_feature_registry_rejects_invalid_graphs() {
    let duplicate = FeatureRegistry::build(vec![
      extension_feature("alpha", 1),
      extension_feature("alpha", 2),
    ])
    .unwrap_err();
    assert_eq!(duplicate.context(), "feature registry duplicate label");

    let missing = FeatureRegistry::build(vec![
      extension_feature("alpha", 1)
        .dependency(extension_tag("beta"))
        .unwrap(),
    ])
    .unwrap_err();
    assert_eq!(missing.context(), "feature registry missing dependency");

    let cycle = FeatureRegistry::build(vec![
      extension_feature("alpha", 1)
        .dependency(extension_tag("beta"))
        .unwrap(),
      extension_feature("beta", 2)
        .dependency(extension_tag("alpha"))
        .unwrap(),
    ])
    .unwrap_err();
    assert_eq!(cycle.context(), "feature registry dependency cycle");

    let self_dependency = extension_feature("alpha", 1).dependency(extension_tag("alpha"));
    assert_eq!(
      self_dependency.unwrap_err().context(),
      "feature dependency self"
    );

    let asymmetric = FeatureRegistry::build(vec![
      extension_feature("alpha", 1)
        .conflict(extension_tag("beta"))
        .unwrap(),
      extension_feature("beta", 2),
    ])
    .unwrap_err();
    assert_eq!(asymmetric.context(), "feature registry asymmetric conflict");

    let unknown_conflict = FeatureRegistry::build(vec![
      extension_feature("alpha", 1)
        .conflict(extension_tag("gamma"))
        .unwrap(),
    ])
    .unwrap_err();
    assert_eq!(
      unknown_conflict.context(),
      "feature registry asymmetric conflict"
    );

    let self_conflict = extension_feature("alpha", 1).conflict(extension_tag("alpha"));
    assert_eq!(
      self_conflict.unwrap_err().context(),
      "feature conflict self"
    );

    let protocol = ProtocolTag::parse("testing.example/protocols/shared").unwrap();
    let duplicate_protocol = FeatureRegistry::build(vec![
      extension_feature("alpha", 1)
        .protocol(protocol.clone())
        .unwrap(),
      extension_feature("beta", 2).protocol(protocol).unwrap(),
    ])
    .unwrap_err();
    assert_eq!(
      duplicate_protocol.context(),
      "feature registry duplicate protocol owner"
    );

    let reserved = FeatureDefinition::new(
      FeatureTag::parse(AUTH_ED25519_SESSION).unwrap(),
      Digest::from_bytes([7; 32]),
    );
    assert_eq!(
      reserved.unwrap_err().context(),
      "feature definition reserved namespace"
    );

    let crypto = QualifiedTag::parse("radiata.woooo.tech/crypto/v1/session");
    assert!(crypto.is_err());

    let valid = FeatureRegistry::build(vec![
      extension_feature("alpha", 1),
      extension_feature("beta", 2)
        .dependency(extension_tag("alpha"))
        .unwrap()
        .conflict(extension_tag("gamma"))
        .unwrap(),
      extension_feature("gamma", 3)
        .conflict(extension_tag("beta"))
        .unwrap(),
    ]);
    assert!(valid.is_ok());
  }

  #[test]
  fn handshake_mutated_builtin_definitions_are_detected() {
    let names = [
      AUTH_ED25519_SESSION,
      SESSION_CORE,
      DATA_MESSAGES,
      DIRECT_REQUEST,
      ROUTED_DELIVERY,
    ];
    for name in names {
      let definition = builtin_definition(name);
      let digest = definition.definition_digest().unwrap();
      assert_eq!(digest, definition.definition_digest().unwrap(), "{name}");
    }

    assert_mutation_detected(AUTH_ED25519_SESSION, |definition| {
      definition.fingerprint = Digest::from_bytes([0xFF; 32]);
    });
    assert_mutation_detected(SESSION_CORE, |definition| {
      definition
        .dependencies
        .push(FeatureTag::parse(ROUTED_DELIVERY).unwrap());
    });
    assert_mutation_detected(ROUTED_DELIVERY, |definition| {
      definition
        .conflicts
        .push(FeatureTag::parse(SESSION_CORE).unwrap());
    });
    assert_mutation_detected(DATA_MESSAGES, |definition| {
      definition
        .protocols
        .push(ProtocolTag::parse("radiata.woooo.tech/protocols/data-messages").unwrap());
    });
    assert_mutation_detected(DIRECT_REQUEST, |definition| {
      definition
        .protocols
        .push(ProtocolTag::parse("radiata.woooo.tech/protocols/routed-delivery").unwrap());
    });
  }

  fn assert_mutation_detected(name: &str, mutate: impl FnOnce(&mut FeatureDefinition)) {
    let mut definitions = builtin_definitions().unwrap();
    let index = definitions
      .iter()
      .position(|definition| definition.tag().as_str() == name)
      .unwrap();
    let frozen = definitions[index].definition_digest().unwrap();
    mutate(&mut definitions[index]);
    assert_ne!(
      definitions[index].definition_digest().unwrap(),
      frozen,
      "{name}"
    );
    let error = FeatureRegistry::build(definitions).unwrap_err();
    assert_eq!(
      error.context(),
      "feature registry reserved namespace",
      "{name}"
    );
  }
}
