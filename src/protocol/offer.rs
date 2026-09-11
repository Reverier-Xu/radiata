//! Canonical authenticated feature offer encoding and validation.
//!
//! An offer carries sorted, unique collections: `(feature label,
//! definition digest)` supported pairs, required labels, and the mandatory
//! numeric limits owned by the offered labels. Decoding enforces the
//! handshake control CBOR bounds (64 KiB body, depth 16, 1,024 collection
//! items), the 128-entry offer caps, canonical ordering, `required` as a
//! subset of `supported`, and the exact mandatory limit set with every
//! value inside its legal registry range.

use std::collections::{BTreeMap, BTreeSet};

use minicbor::{Decode, Encode};

use super::{
  CONTROL_CBOR_LIMITS, FeatureTag, QualifiedTag, decode_canonical_strict, encode_canonical,
  feature::{FeatureRegistry, LimitDefinition, required_session_features},
};
use crate::{Digest, Error, Result};

pub(crate) const MAX_SUPPORTED_LABELS: usize = 128;
pub(crate) const MAX_REQUIRED_LABELS: usize = 128;
pub(crate) const MAX_NEGOTIATED_LIMITS: usize = 128;
/// The fixed authentication role of one handshake endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Role {
  Initiator,
  Responder,
}

impl Role {
  pub(crate) const fn as_str(self) -> &'static str {
    match self {
      Self::Initiator => "initiator",
      Self::Responder => "responder",
    }
  }
}

/// A sorted collection holds no adjacent duplicates (single source for
/// the canonical-form duplicate rule).
fn ensure_unique_sorted<T>(
  sorted: &[T], key: impl Fn(&T) -> &str, context: &'static str,
) -> Result<()> {
  if sorted.windows(2).any(|pair| key(&pair[0]) == key(&pair[1])) {
    return Err(Error::invalid_input(context));
  }
  Ok(())
}

/// Validates strict ascending wire ordering while transforming entries:
/// duplicates and out-of-order entries fail closed (canonical form).
fn map_ordered<'a, E: 'a, T>(
  entries: impl IntoIterator<Item = &'a E>, key: impl Fn(&'a E) -> &'a str, context: &'static str,
  mut map: impl FnMut(&'a E) -> Result<T>,
) -> Result<Vec<T>> {
  let mut out = Vec::new();
  let mut previous: Option<&'a str> = None;
  for entry in entries {
    let current = key(entry);
    if previous >= Some(current) {
      return Err(Error::invalid_input(context));
    }
    previous = Some(current);
    out.push(map(entry)?);
  }
  Ok(out)
}

/// One canonical, validated feature offer from a single endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FeatureOffer {
  supported: Vec<(FeatureTag, Digest)>,
  required: Vec<FeatureTag>,
  limits: Vec<(QualifiedTag, u64)>,
}

impl FeatureOffer {
  /// Builds a canonical offer, sorting every collection and rejecting
  /// duplicates, capacity overflow, non-`limits` limit tags, and required
  /// labels outside the supported set.
  pub(crate) fn new(
    mut supported: Vec<(FeatureTag, Digest)>, mut required: Vec<FeatureTag>,
    mut limits: Vec<(QualifiedTag, u64)>,
  ) -> Result<Self> {
    if supported.len() > MAX_SUPPORTED_LABELS {
      return Err(Error::invalid_input("feature offer supported capacity"));
    }
    if required.len() > MAX_REQUIRED_LABELS {
      return Err(Error::invalid_input("feature offer required capacity"));
    }
    if limits.len() > MAX_NEGOTIATED_LIMITS {
      return Err(Error::invalid_input("feature offer limits capacity"));
    }
    supported.sort_by(|first, second| first.0.as_str().cmp(second.0.as_str()));
    required.sort_by(|first, second| first.as_str().cmp(second.as_str()));
    limits.sort_by(|first, second| first.0.as_str().cmp(second.0.as_str()));
    ensure_unique_sorted(
      &supported,
      |(tag, _)| tag.as_str(),
      "feature offer supported duplicate",
    )?;
    ensure_unique_sorted(
      &required,
      |tag| tag.as_str(),
      "feature offer required duplicate",
    )?;
    ensure_unique_sorted(
      &limits,
      |(tag, _)| tag.as_str(),
      "feature offer limits duplicate",
    )?;
    for (tag, _) in &limits {
      if tag.category() != crate::protocol::tag::CATEGORY_LIMITS {
        return Err(Error::invalid_input("feature offer limit category"));
      }
    }
    for tag in &required {
      if !supported.iter().any(|(candidate, _)| candidate == tag) {
        return Err(Error::invalid_input("feature offer required unsupported"));
      }
    }
    Ok(Self {
      supported,
      required,
      limits,
    })
  }

  pub(crate) fn supported(&self) -> &[(FeatureTag, Digest)] {
    &self.supported
  }

  pub(crate) fn required(&self) -> &[FeatureTag] {
    &self.required
  }

  /// The offered numeric limit map.
  #[cfg(test)]
  pub(crate) fn limits(&self) -> &[(QualifiedTag, u64)] {
    &self.limits
  }

  pub(crate) fn supported_digest(&self, tag: &FeatureTag) -> Option<&Digest> {
    self
      .supported
      .iter()
      .find(|(candidate, _)| candidate == tag)
      .map(|(_, digest)| digest)
  }

  pub(crate) fn limit_value(&self, tag: &QualifiedTag) -> Option<u64> {
    self
      .limits
      .iter()
      .find(|(candidate, _)| candidate == tag)
      .map(|(_, value)| *value)
  }

  pub(crate) fn encode(&self) -> Result<Vec<u8>> {
    encode_canonical(&self.wire(), CONTROL_CBOR_LIMITS)
  }

  /// Decodes canonical offer bytes and validates them against the local
  /// registry, including the exact mandatory limit set and legal ranges.
  pub(crate) fn decode(bytes: &[u8], registry: &FeatureRegistry) -> Result<Self> {
    let wire: FeatureOfferWire =
      decode_canonical_strict(bytes, CONTROL_CBOR_LIMITS, "feature offer canonical form")?;
    let offer = Self::from_wire(wire)?;
    offer.validate_limits(registry)?;
    Ok(offer)
  }

  /// Requires the offered limits to be exactly the mandatory limits owned
  /// by the offered labels, each inside its legal registry range.
  pub(crate) fn validate_limits(&self, registry: &FeatureRegistry) -> Result<()> {
    let mut expected: BTreeMap<&QualifiedTag, &LimitDefinition> = BTreeMap::new();
    for (tag, _) in &self.supported {
      if let Some(definition) = registry.get(tag) {
        for limit in definition.limits() {
          if limit.mandatory() {
            expected.insert(limit.tag(), limit);
          }
        }
      }
    }
    if self.limits.len() != expected.len() {
      return Err(Error::invalid_input("feature offer mandatory limits"));
    }
    for (tag, value) in &self.limits {
      let Some(definition) = expected.get(tag) else {
        return Err(Error::invalid_input("feature offer unknown limit"));
      };
      if !definition.contains(*value) {
        return Err(Error::invalid_input("feature offer limit range"));
      }
    }
    Ok(())
  }

  fn from_wire(wire: FeatureOfferWire) -> Result<Self> {
    if wire.supported.len() > MAX_SUPPORTED_LABELS {
      return Err(Error::invalid_input("feature offer supported capacity"));
    }
    if wire.required.len() > MAX_REQUIRED_LABELS {
      return Err(Error::invalid_input("feature offer required capacity"));
    }
    if wire.limits.len() > MAX_NEGOTIATED_LIMITS {
      return Err(Error::invalid_input("feature offer limits capacity"));
    }

    let supported = map_ordered(
      &wire.supported,
      |entry| entry.label.as_str(),
      "feature offer supported ordering",
      |entry| {
        let digest = <[u8; 32]>::try_from(entry.digest.as_slice())
          .map_err(|_| Error::invalid_input("feature offer digest"))?;
        Ok((FeatureTag::parse(&entry.label)?, Digest::from_bytes(digest)))
      },
    )?;

    let required = map_ordered(
      &wire.required,
      |label| label.as_str(),
      "feature offer required ordering",
      |label| FeatureTag::parse(label),
    )?;

    let limits = map_ordered(
      &wire.limits,
      |entry| entry.tag.as_str(),
      "feature offer limits ordering",
      |entry| {
        let tag = QualifiedTag::parse(&entry.tag)?;
        if tag.category() != crate::protocol::tag::CATEGORY_LIMITS {
          return Err(Error::invalid_input("feature offer limit category"));
        }
        Ok((tag, entry.value))
      },
    )?;

    for tag in &required {
      if !supported.iter().any(|(candidate, _)| candidate == tag) {
        return Err(Error::invalid_input("feature offer required unsupported"));
      }
    }
    Ok(Self {
      supported,
      required,
      limits,
    })
  }

  fn wire(&self) -> FeatureOfferWire {
    FeatureOfferWire {
      supported: self
        .supported
        .iter()
        .map(|(tag, digest)| SupportedEntryWire {
          label: tag.as_str().to_owned(),
          digest: digest.as_bytes().to_vec(),
        })
        .collect(),
      required: self
        .required
        .iter()
        .map(|tag| tag.as_str().to_owned())
        .collect(),
      limits: self
        .limits
        .iter()
        .map(|(tag, value)| LimitEntryWire {
          tag: tag.as_str().to_owned(),
          value: *value,
        })
        .collect(),
    }
  }
}

#[derive(Clone, Encode, Decode)]
#[cbor(array)]
struct SupportedEntryWire {
  #[n(0)]
  label: String,
  #[n(1)]
  #[cbor(with = "minicbor::bytes")]
  digest: Vec<u8>,
}

#[derive(Clone, Encode, Decode)]
#[cbor(array)]
pub(super) struct LimitEntryWire {
  #[n(0)]
  pub(super) tag: String,
  #[n(1)]
  pub(super) value: u64,
}

#[derive(Encode, Decode)]
#[cbor(array)]
struct FeatureOfferWire {
  #[n(0)]
  supported: Vec<SupportedEntryWire>,
  #[n(1)]
  required: Vec<String>,
  #[n(2)]
  limits: Vec<LimitEntryWire>,
}

/// Builds the node's production offer: every registry feature supported at
/// its exact definition digest, the mandatory session features plus every
/// caller-required feature required, and every mandatory limit at its
/// registry default value. Caller-required labels outside the registry are
/// rejected before any offer exists.
pub(crate) fn node_offer(
  registry: &FeatureRegistry, caller_required: &BTreeSet<FeatureTag>,
) -> Result<FeatureOffer> {
  let mut supported = Vec::new();
  let mut limits = Vec::new();
  for (tag, definition) in registry.iter() {
    supported.push((tag.clone(), definition.definition_digest()?));
    for limit in definition.limits() {
      if limit.mandatory() {
        limits.push((limit.tag().clone(), limit.default()));
      }
    }
  }
  let mut required = caller_required.clone();
  for tag in required_session_features()? {
    required.insert(tag);
  }
  for tag in &required {
    if !supported.iter().any(|(candidate, _)| candidate == tag) {
      return Err(Error::invalid_input("required feature"));
    }
  }
  FeatureOffer::new(supported, required.into_iter().collect(), limits)
}

#[cfg(test)]
pub(crate) mod fixtures {
  use super::{super::feature::FeatureRegistry, FeatureOffer, FeatureTag, QualifiedTag};
  use crate::Digest;

  pub(crate) const BUILTIN_FEATURES: [&str; 5] = crate::protocol::feature::BUILTIN_FEATURE_LABELS;

  pub(crate) fn feature(name: &str) -> FeatureTag {
    FeatureTag::parse(&format!("radiata.woooo.tech/features/{name}")).unwrap()
  }

  pub(crate) fn limit(name: &str) -> QualifiedTag {
    QualifiedTag::parse(&format!("radiata.woooo.tech/limits/{name}")).unwrap()
  }

  /// An extension-domain feature tag (`testing.example/features/…`) for
  /// tests that register non-built-in definitions.
  pub(crate) fn extension_tag(name: &str) -> FeatureTag {
    FeatureTag::parse(&format!("testing.example/features/{name}")).unwrap()
  }

  /// One registered extension feature with a fixed fingerprint byte.
  pub(crate) fn extension_feature(
    name: &str, fingerprint_byte: u8,
  ) -> crate::protocol::feature::FeatureDefinition {
    crate::protocol::feature::FeatureDefinition::new(
      extension_tag(name),
      Digest::from_bytes([fingerprint_byte; 32]),
    )
    .unwrap()
  }

  fn supported(registry: &FeatureRegistry, names: &[&str]) -> Vec<(FeatureTag, Digest)> {
    names
      .iter()
      .map(|name| {
        let tag = FeatureTag::parse(name).unwrap();
        let digest = registry.get(&tag).unwrap().definition_digest().unwrap();
        (tag, digest)
      })
      .collect()
  }

  /// The fixed initiator golden offer: all built-ins supported, the direct
  /// request chain required, default limit values.
  pub(crate) fn initiator_offer(registry: &FeatureRegistry) -> FeatureOffer {
    FeatureOffer::new(
      supported(registry, &BUILTIN_FEATURES),
      vec![
        feature("auth-ed25519-session"),
        feature("session-core"),
        feature("data-messages"),
        feature("direct-request"),
      ],
      vec![
        (limit("data-body-bytes"), 1_048_576),
        (limit("in-flight-requests"), 256),
      ],
    )
    .unwrap()
  }

  /// The fixed responder golden offer: all built-ins supported and
  /// required, raised in-range limit values.
  pub(crate) fn responder_offer(registry: &FeatureRegistry) -> FeatureOffer {
    FeatureOffer::new(
      supported(registry, &BUILTIN_FEATURES),
      BUILTIN_FEATURES
        .iter()
        .map(|name| FeatureTag::parse(name).unwrap())
        .collect(),
      vec![
        (limit("data-body-bytes"), 8_388_608),
        (limit("in-flight-requests"), 512),
      ],
    )
    .unwrap()
  }
}

#[cfg(test)]
mod tests {
  use super::{
    super::{feature::FeatureRegistry, selection::select},
    fixtures::{initiator_offer, responder_offer},
    *,
  };

  fn registry() -> FeatureRegistry {
    FeatureRegistry::builtin().unwrap()
  }

  /// Returns true only when the offer decodes, selects against `peer`, and
  /// reproduces the exact golden selection bytes for the unmutated pair.
  fn verifies(offer: &FeatureOffer, peer: &FeatureOffer, registry: &FeatureRegistry) -> bool {
    let bytes = offer.encode().unwrap();
    let Ok(decoded) = FeatureOffer::decode(&bytes, registry) else {
      return false;
    };
    let Ok(selection) = select(
      registry,
      &decoded,
      peer,
      decoded.required(),
      peer.required(),
    ) else {
      return false;
    };
    let golden_offer = initiator_offer(registry);
    let golden = select(
      registry,
      &golden_offer,
      peer,
      golden_offer.required(),
      peer.required(),
    )
    .unwrap();
    selection.bytes() == golden.bytes()
  }

  #[test]
  fn handshake_offer_round_trip_preserves_canonical_bytes() {
    let registry = registry();
    for offer in [initiator_offer(&registry), responder_offer(&registry)] {
      let bytes = offer.encode().unwrap();
      let decoded = FeatureOffer::decode(&bytes, &registry).unwrap();
      assert_eq!(decoded, offer);
      assert_eq!(decoded.encode().unwrap(), bytes);
    }
  }

  #[test]
  fn handshake_offer_caps_and_membership_are_enforced() {
    let registry = registry();
    let tag = fixtures::feature("auth-ed25519-session");
    let digest = registry.get(&tag).unwrap().fingerprint().clone();

    let over_supported = vec![(tag.clone(), digest.clone()); 2];
    assert!(
      FeatureOffer::new(over_supported, Vec::new(), Vec::new())
        .unwrap_err()
        .context()
        == "feature offer supported duplicate"
    );

    let distinct_supported: Vec<(FeatureTag, Digest)> = (0..=MAX_SUPPORTED_LABELS)
      .map(|index| {
        (
          FeatureTag::parse(&format!("testing.example/features/label-{index:04}")).unwrap(),
          digest.clone(),
        )
      })
      .collect();
    assert!(
      FeatureOffer::new(distinct_supported, Vec::new(), Vec::new())
        .unwrap_err()
        .context()
        == "feature offer supported capacity"
    );

    let over_required: Vec<FeatureTag> = (0..=MAX_REQUIRED_LABELS)
      .map(|index| {
        FeatureTag::parse(&format!("testing.example/features/label-{index:04}")).unwrap()
      })
      .collect();
    assert!(
      FeatureOffer::new(Vec::new(), over_required, Vec::new())
        .unwrap_err()
        .context()
        == "feature offer required capacity"
    );

    let over_limits: Vec<(QualifiedTag, u64)> = (0..=MAX_NEGOTIATED_LIMITS)
      .map(|index| {
        (
          QualifiedTag::parse(&format!("testing.example/limits/limit-{index:04}")).unwrap(),
          1,
        )
      })
      .collect();
    assert!(
      FeatureOffer::new(Vec::new(), Vec::new(), over_limits)
        .unwrap_err()
        .context()
        == "feature offer limits capacity"
    );

    let unsupported_required = FeatureOffer::new(Vec::new(), vec![tag], Vec::new()).unwrap_err();
    assert_eq!(
      unsupported_required.context(),
      "feature offer required unsupported"
    );
  }

  #[test]
  fn handshake_any_offer_field_or_ordering_mutation_fails() {
    let registry = registry();
    let initiator = initiator_offer(&registry);
    let responder = responder_offer(&registry);
    assert!(verifies(&initiator, &responder, &registry));

    // Mutated supported digest of a common label.
    let mut mutated = initiator.clone();
    mutated.supported[0].1 = Digest::from_bytes([0xAB; 32]);
    assert!(!verifies(&mutated, &responder, &registry));

    // Renamed supported label (kept sorted) drops a required label.
    let mut mutated = initiator.clone();
    mutated.supported[0].0 = fixtures::feature("routed-delivery");
    mutated.supported.remove(3);
    mutated
      .supported
      .sort_by(|first, second| first.0.as_str().cmp(second.0.as_str()));
    assert!(!verifies(&mutated, &responder, &registry));

    // Out-of-range limit value.
    let mut mutated = initiator.clone();
    mutated.limits[0].1 = 63 * 1_024;
    assert!(!verifies(&mutated, &responder, &registry));

    // In-range but changed limit value changes the selection bytes.
    let mut mutated = initiator.clone();
    mutated.limits[0].1 = 2 * 1_024 * 1_024;
    assert!(!verifies(&mutated, &responder, &registry));

    // Missing mandatory limit.
    let mut mutated = initiator.clone();
    mutated.limits.remove(0);
    assert!(!verifies(&mutated, &responder, &registry));

    // Unknown limit tag.
    let mut mutated = initiator.clone();
    mutated.limits.push((
      QualifiedTag::parse("testing.example/limits/unknown").unwrap(),
      1,
    ));
    assert!(!verifies(&mutated, &responder, &registry));

    // Required label outside the supported set.
    let mut mutated = initiator.clone();
    mutated
      .required
      .push(FeatureTag::parse("testing.example/features/zz-policy").unwrap());
    assert!(!verifies(&mutated, &responder, &registry));

    // Out-of-order supported entries on the wire.
    let mut wire = initiator.wire();
    wire.supported.swap(0, 1);
    let bytes = encode_canonical(&wire, CONTROL_CBOR_LIMITS).unwrap();
    assert!(FeatureOffer::decode(&bytes, &registry).is_err());

    // Duplicated supported entry on the wire.
    let mut wire = initiator.wire();
    let entry = wire.supported[0].clone();
    wire.supported.insert(1, entry);
    let bytes = encode_canonical(&wire, CONTROL_CBOR_LIMITS).unwrap();
    assert!(FeatureOffer::decode(&bytes, &registry).is_err());

    // Truncated and trailing wire bytes.
    let bytes = initiator.encode().unwrap();
    assert!(FeatureOffer::decode(&bytes[..bytes.len() - 1], &registry).is_err());
    let mut trailing = bytes.clone();
    trailing.push(0x00);
    assert!(FeatureOffer::decode(&trailing, &registry).is_err());

    // Non-canonical container header.
    let mut noncanonical = bytes;
    noncanonical[0] = 0x9F;
    assert!(FeatureOffer::decode(&noncanonical, &registry).is_err());
  }

  #[test]
  fn handshake_offer_duplicate_limit_entries_reject_at_decode() {
    let registry = FeatureRegistry::builtin().unwrap();
    let initiator = fixtures::initiator_offer(&registry);
    let mut wire = initiator.wire();
    let entry = wire.limits[0].clone();
    wire.limits.push(entry);
    let bytes = encode_canonical(&wire, CONTROL_CBOR_LIMITS).unwrap();
    assert!(FeatureOffer::decode(&bytes, &registry).is_err());

    let mut unsorted = initiator.wire();
    unsorted.limits.reverse();
    let bytes = encode_canonical(&unsorted, CONTROL_CBOR_LIMITS).unwrap();
    assert!(FeatureOffer::decode(&bytes, &registry).is_err());
  }
}
