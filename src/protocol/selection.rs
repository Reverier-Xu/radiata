//! Exact authenticated feature selection.
//!
//! Both peers independently compute the same effective feature set:
//!
//! 1. every common label must carry an exactly equal definition digest;
//! 2. `C0` is the equality intersection of both `supported` sets;
//! 3. labels whose immutable dependencies are absent are removed until a fixed
//!    point `C*` (labels without a local registry definition cannot be
//!    selected);
//! 4. any remaining conflict pair rejects the session;
//! 5. the union of both required sets must be a subset of `C*`;
//! 6. an unknown required label rejects the session;
//! 7. `C*` is canonically sorted, effective limits are the per-limit minimum of
//!    both offers, and the deterministic-CBOR selection bytes must match
//!    exactly on both peers before either signs the transcript.

use std::collections::{BTreeMap, BTreeSet};

use minicbor::Encode;

use super::{
  CONTROL_CBOR_LIMITS, FeatureTag, QualifiedTag, encode_canonical,
  feature::FeatureRegistry,
  offer::{FeatureOffer, LimitEntryWire},
};
use crate::Error;

/// The typed reason an authenticated feature selection failed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SelectionError {
  /// One common label carried different definition digests.
  DigestMismatch { label: String },
  /// A symmetric conflict pair survived the dependency fixed point.
  Conflict { first: String, second: String },
  /// A known required label is not in the selected set.
  MissingRequired { label: String },
  /// A required label has no local registry definition.
  UnknownRequired { label: String },
  /// A structurally valid offer violated the negotiation contract.
  Malformed { context: &'static str },
}

impl From<SelectionError> for Error {
  fn from(error: SelectionError) -> Self {
    match error {
      SelectionError::DigestMismatch { .. } => {
        Error::authentication_failed("feature definition digest mismatch")
      }
      SelectionError::Conflict { .. } => Error::authentication_failed("feature selection conflict"),
      SelectionError::MissingRequired { .. } => {
        Error::authentication_failed("feature selection missing required")
      }
      SelectionError::UnknownRequired { .. } => {
        Error::authentication_failed("feature selection unknown required")
      }
      SelectionError::Malformed { .. } => {
        Error::authentication_failed("feature selection malformed")
      }
    }
  }
}

/// The exact pairwise selection both peers must reproduce byte-for-byte.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Selection {
  features: Vec<FeatureTag>,
  limits: Vec<(QualifiedTag, u64)>,
  bytes: Vec<u8>,
}

impl Selection {
  /// The selected feature set.
  #[allow(dead_code)]
  pub(crate) fn features(&self) -> &[FeatureTag] {
    &self.features
  }

  /// The effective negotiated limits.
  #[allow(dead_code)]
  pub(crate) fn limits(&self) -> &[(QualifiedTag, u64)] {
    &self.limits
  }

  /// The deterministic-CBOR selection bytes exchanged for exact match.
  pub(crate) fn bytes(&self) -> &[u8] {
    &self.bytes
  }

  /// One effective limit by tag.
  #[allow(dead_code)]
  pub(crate) fn limit(&self, tag: &QualifiedTag) -> Option<u64> {
    self
      .limits
      .iter()
      .find(|(candidate, _)| candidate == tag)
      .map(|(_, value)| *value)
  }
}

/// Computes the exact effective feature set for one authenticated pair.
pub(crate) fn select(
  registry: &FeatureRegistry, local_offer: &FeatureOffer, remote_offer: &FeatureOffer,
  local_required: &[FeatureTag], remote_required: &[FeatureTag],
) -> std::result::Result<Selection, SelectionError> {
  // Steps 1 and 2: digest equality on every common label, then intersect.
  let mut selected: BTreeSet<&FeatureTag> = BTreeSet::new();
  for (tag, digest) in local_offer.supported() {
    if let Some(remote_digest) = remote_offer.supported_digest(tag) {
      if remote_digest != digest {
        return Err(SelectionError::DigestMismatch {
          label: tag.as_str().to_owned(),
        });
      }
      // Defense in depth: a label known to the local registry must carry the
      // registry's exact definition digest, so two mutually consistent but
      // wrong offers can never select it.
      if let Some(definition) = registry.get(tag) {
        let registry_digest =
          definition
            .definition_digest()
            .map_err(|_| SelectionError::Malformed {
              context: "selection definition digest",
            })?;
        if &registry_digest != digest {
          return Err(SelectionError::DigestMismatch {
            label: tag.as_str().to_owned(),
          });
        }
      }
      selected.insert(tag);
    }
  }

  // Step 3: dependency fixed point. Unknown local definitions are dropped.
  loop {
    let retained: BTreeSet<&FeatureTag> = selected
      .iter()
      .filter(|tag| match registry.get(tag) {
        Some(definition) => definition
          .dependencies()
          .iter()
          .all(|dependency| selected.contains(dependency)),
        None => false,
      })
      .copied()
      .collect();
    if retained.len() == selected.len() {
      break;
    }
    selected = retained;
  }

  // Step 4: conflict-pair rejection; lexical order never chooses a winner.
  for &tag in &selected {
    let definition = registry.get(tag).ok_or(SelectionError::Malformed {
      context: "selection definition",
    })?;
    for conflict in definition.conflicts() {
      if selected.contains(conflict) {
        let (first, second) = if tag.as_str() < conflict.as_str() {
          (tag, conflict)
        } else {
          (conflict, tag)
        };
        return Err(SelectionError::Conflict {
          first: first.as_str().to_owned(),
          second: second.as_str().to_owned(),
        });
      }
    }
  }

  // Steps 5 and 6: the required union must be known and selected.
  let mut required: BTreeSet<&FeatureTag> = BTreeSet::new();
  required.extend(local_required);
  required.extend(remote_required);
  for tag in required {
    if registry.get(tag).is_none() {
      return Err(SelectionError::UnknownRequired {
        label: tag.as_str().to_owned(),
      });
    }
    if !selected.contains(tag) {
      return Err(SelectionError::MissingRequired {
        label: tag.as_str().to_owned(),
      });
    }
  }

  // Step 7: canonical sort, per-limit minimum, and selection bytes.
  let mut effective: BTreeMap<&QualifiedTag, u64> = BTreeMap::new();
  for &tag in &selected {
    let definition = registry.get(tag).ok_or(SelectionError::Malformed {
      context: "selection definition",
    })?;
    for limit in definition.limits() {
      if !limit.mandatory() {
        continue;
      }
      let local = local_offer
        .limit_value(limit.tag())
        .ok_or(SelectionError::Malformed {
          context: "selection local limit",
        })?;
      let remote = remote_offer
        .limit_value(limit.tag())
        .ok_or(SelectionError::Malformed {
          context: "selection remote limit",
        })?;
      effective.insert(limit.tag(), local.min(remote));
    }
  }

  let features: Vec<FeatureTag> = selected.iter().map(|tag| (*tag).clone()).collect();
  let limits: Vec<(QualifiedTag, u64)> = effective
    .iter()
    .map(|(tag, value)| ((*tag).clone(), *value))
    .collect();
  let wire = SelectionWire {
    features: features.iter().map(|tag| tag.as_str().to_owned()).collect(),
    limits: limits
      .iter()
      .map(|(tag, value)| LimitEntryWire {
        tag: tag.as_str().to_owned(),
        value: *value,
      })
      .collect(),
  };
  let bytes =
    encode_canonical(&wire, CONTROL_CBOR_LIMITS).map_err(|_| SelectionError::Malformed {
      context: "selection encode",
    })?;
  Ok(Selection {
    features,
    limits,
    bytes,
  })
}

#[derive(Encode)]
#[cbor(array)]
struct SelectionWire {
  #[n(0)]
  features: Vec<String>,
  #[n(1)]
  limits: Vec<LimitEntryWire>,
}

#[cfg(test)]
mod tests {
  use super::{
    super::{
      feature::{
        AUTH_ED25519_SESSION, DATA_MESSAGES, DIRECT_REQUEST, FeatureRegistry, ROUTED_DELIVERY,
        SESSION_CORE,
      },
      offer::fixtures::{self, initiator_offer, responder_offer},
    },
    *,
  };
  use crate::{Digest, hex::encode as hex};

  const INITIATOR_OFFER_HEX: &str = "8385827830726164696174612e776f6f6f6f2e746563682f66656174757265732f617574682d656432353531392d73657373696f6e58207e1cd8b5da6a7073ecf8bcc214f3bc23fd0e8aa5d039df81d051aebc6261dbb2827829726164696174612e776f6f6f6f2e746563682f66656174757265732f646174612d6d657373616765735820594268233e6759361cfe2a5ddb5fe318375670bd6d3c74a9dfd7970378328ba882782a726164696174612e776f6f6f6f2e746563682f66656174757265732f6469726563742d7265717565737458209b6e0d583656d859650b5b2f983772d13f37f0ddcb800cb5ae73b92d521d1f0882782b726164696174612e776f6f6f6f2e746563682f66656174757265732f726f757465642d64656c69766572795820348d89297781958b76a3b261ef9a9a1c47d5231102afad3f1a30fbce07a37537827828726164696174612e776f6f6f6f2e746563682f66656174757265732f73657373696f6e2d636f72655820c7d97780c1919caa52efbf957e11a6ed3e894724558bf0e80497996536e2fa6e847830726164696174612e776f6f6f6f2e746563682f66656174757265732f617574682d656432353531392d73657373696f6e7829726164696174612e776f6f6f6f2e746563682f66656174757265732f646174612d6d65737361676573782a726164696174612e776f6f6f6f2e746563682f66656174757265732f6469726563742d726571756573747828726164696174612e776f6f6f6f2e746563682f66656174757265732f73657373696f6e2d636f726582827829726164696174612e776f6f6f6f2e746563682f6c696d6974732f646174612d626f64792d62797465731a0010000082782c726164696174612e776f6f6f6f2e746563682f6c696d6974732f696e2d666c696768742d7265717565737473190100";
  const RESPONDER_OFFER_HEX: &str = "8385827830726164696174612e776f6f6f6f2e746563682f66656174757265732f617574682d656432353531392d73657373696f6e58207e1cd8b5da6a7073ecf8bcc214f3bc23fd0e8aa5d039df81d051aebc6261dbb2827829726164696174612e776f6f6f6f2e746563682f66656174757265732f646174612d6d657373616765735820594268233e6759361cfe2a5ddb5fe318375670bd6d3c74a9dfd7970378328ba882782a726164696174612e776f6f6f6f2e746563682f66656174757265732f6469726563742d7265717565737458209b6e0d583656d859650b5b2f983772d13f37f0ddcb800cb5ae73b92d521d1f0882782b726164696174612e776f6f6f6f2e746563682f66656174757265732f726f757465642d64656c69766572795820348d89297781958b76a3b261ef9a9a1c47d5231102afad3f1a30fbce07a37537827828726164696174612e776f6f6f6f2e746563682f66656174757265732f73657373696f6e2d636f72655820c7d97780c1919caa52efbf957e11a6ed3e894724558bf0e80497996536e2fa6e857830726164696174612e776f6f6f6f2e746563682f66656174757265732f617574682d656432353531392d73657373696f6e7829726164696174612e776f6f6f6f2e746563682f66656174757265732f646174612d6d65737361676573782a726164696174612e776f6f6f6f2e746563682f66656174757265732f6469726563742d72657175657374782b726164696174612e776f6f6f6f2e746563682f66656174757265732f726f757465642d64656c69766572797828726164696174612e776f6f6f6f2e746563682f66656174757265732f73657373696f6e2d636f726582827829726164696174612e776f6f6f6f2e746563682f6c696d6974732f646174612d626f64792d62797465731a0080000082782c726164696174612e776f6f6f6f2e746563682f6c696d6974732f696e2d666c696768742d7265717565737473190200";
  const SELECTION_HEX: &str = "82857830726164696174612e776f6f6f6f2e746563682f66656174757265732f617574682d656432353531392d73657373696f6e7829726164696174612e776f6f6f6f2e746563682f66656174757265732f646174612d6d65737361676573782a726164696174612e776f6f6f6f2e746563682f66656174757265732f6469726563742d72657175657374782b726164696174612e776f6f6f6f2e746563682f66656174757265732f726f757465642d64656c69766572797828726164696174612e776f6f6f6f2e746563682f66656174757265732f73657373696f6e2d636f726582827829726164696174612e776f6f6f6f2e746563682f6c696d6974732f646174612d626f64792d62797465731a0010000082782c726164696174612e776f6f6f6f2e746563682f6c696d6974732f696e2d666c696768742d7265717565737473190100";

  #[test]
  fn handshake_canonical_offers_produce_exact_selection_bytes() {
    let registry = FeatureRegistry::builtin().unwrap();
    let initiator = initiator_offer(&registry);
    let responder = responder_offer(&registry);
    assert_eq!(hex(&initiator.encode().unwrap()), INITIATOR_OFFER_HEX);
    assert_eq!(hex(&responder.encode().unwrap()), RESPONDER_OFFER_HEX);

    let as_initiator = select(
      &registry,
      &initiator,
      &responder,
      initiator.required(),
      responder.required(),
    )
    .unwrap();
    let as_responder = select(
      &registry,
      &responder,
      &initiator,
      responder.required(),
      initiator.required(),
    )
    .unwrap();
    assert_eq!(as_initiator.bytes(), as_responder.bytes());
    assert_eq!(hex(as_initiator.bytes()), SELECTION_HEX);

    assert_eq!(
      as_initiator
        .features()
        .iter()
        .map(|tag| tag.as_str())
        .collect::<Vec<_>>(),
      [
        AUTH_ED25519_SESSION,
        DATA_MESSAGES,
        DIRECT_REQUEST,
        ROUTED_DELIVERY,
        SESSION_CORE,
      ]
    );
    assert_eq!(
      as_initiator.limit(&fixtures::limit("data-body-bytes")),
      Some(1_048_576)
    );
    assert_eq!(
      as_initiator.limit(&fixtures::limit("in-flight-requests")),
      Some(256)
    );

    // Offer input ordering never changes the canonical bytes.
    let mut shuffled_supported = initiator.supported().to_vec();
    shuffled_supported.reverse();
    let mut shuffled_limits = initiator.limits().to_vec();
    shuffled_limits.reverse();
    let shuffled = FeatureOffer::new(
      shuffled_supported,
      initiator.required().to_vec(),
      shuffled_limits,
    )
    .unwrap();
    assert_eq!(shuffled.encode().unwrap(), initiator.encode().unwrap());
    let reselected = select(
      &registry,
      &shuffled,
      &responder,
      shuffled.required(),
      responder.required(),
    )
    .unwrap();
    assert_eq!(reselected.bytes(), as_initiator.bytes());
  }

  #[test]
  fn handshake_limit_negotiation_uses_minimum_and_rejects_out_of_range() {
    let registry = FeatureRegistry::builtin().unwrap();
    let data_body = fixtures::limit("data-body-bytes");
    let in_flight = fixtures::limit("in-flight-requests");

    for (local_value, remote_value, expected) in [
      (65_536, 65_536, 65_536),
      (65_536, 8_388_608, 65_536),
      (8_388_608, 8_388_608, 8_388_608),
      (1_048_576, 8_388_608, 1_048_576),
    ] {
      let local = offer_with_limits(&registry, local_value, 256);
      let remote = offer_with_limits(&registry, remote_value, 1_024);
      let selection = select(
        &registry,
        &local,
        &remote,
        local.required(),
        remote.required(),
      )
      .unwrap();
      assert_eq!(selection.limit(&data_body), Some(expected));
      assert_eq!(selection.limit(&in_flight), Some(256));
    }

    for value in [0, 65_535, 8_388_609, u64::from(u32::MAX) + 1] {
      let offer = offer_with_limits(&registry, value, 256);
      let error = offer.validate_limits(&registry).unwrap_err();
      assert_eq!(error.context(), "feature offer limit range", "{value}");
    }
    for value in [0, 1_025, u64::from(u16::MAX) + 1] {
      let offer = offer_with_limits(&registry, 1_048_576, value);
      let error = offer.validate_limits(&registry).unwrap_err();
      assert_eq!(error.context(), "feature offer limit range", "{value}");
    }

    // Decoding an out-of-range offer fails before any selection work.
    let encoded = offer_with_limits(&registry, 65_535, 256).encode().unwrap();
    assert!(FeatureOffer::decode(&encoded, &registry).is_err());
  }

  #[test]
  fn handshake_selection_rejects_digest_mismatch_conflict_and_required() {
    let registry = FeatureRegistry::builtin().unwrap();
    let initiator = initiator_offer(&registry);
    let responder = responder_offer(&registry);

    // Step 1: a changed digest on a common label rejects.
    let mut forged_supported = responder.supported().to_vec();
    forged_supported[0].1 = Digest::from_bytes([0xCD; 32]);
    let forged = FeatureOffer::new(
      forged_supported,
      responder.required().to_vec(),
      responder.limits().to_vec(),
    )
    .unwrap();
    let error = select(
      &registry,
      &initiator,
      &forged,
      initiator.required(),
      forged.required(),
    )
    .unwrap_err();
    assert_eq!(
      error,
      SelectionError::DigestMismatch {
        label: AUTH_ED25519_SESSION.to_owned(),
      }
    );

    // Defense in depth: both offers carrying the same wrong digest for a
    // registry-known label still rejects against the local registry.
    let mut wrong_supported = responder.supported().to_vec();
    wrong_supported[0].1 = Digest::from_bytes([0xCD; 32]);
    let wrong_responder = FeatureOffer::new(
      wrong_supported,
      responder.required().to_vec(),
      responder.limits().to_vec(),
    )
    .unwrap();
    let mut wrong_initiator_supported = initiator.supported().to_vec();
    wrong_initiator_supported[0].1 = Digest::from_bytes([0xCD; 32]);
    let wrong_initiator = FeatureOffer::new(
      wrong_initiator_supported,
      initiator.required().to_vec(),
      initiator.limits().to_vec(),
    )
    .unwrap();
    let error = select(
      &registry,
      &wrong_initiator,
      &wrong_responder,
      wrong_initiator.required(),
      wrong_responder.required(),
    )
    .unwrap_err();
    assert_eq!(
      error,
      SelectionError::DigestMismatch {
        label: AUTH_ED25519_SESSION.to_owned(),
      }
    );

    // Step 3: dependency fixed point prunes unsatisfiable labels.
    let partial = FeatureOffer::new(
      vec![
        supported_entry(&registry, AUTH_ED25519_SESSION),
        supported_entry(&registry, SESSION_CORE),
        supported_entry(&registry, DIRECT_REQUEST),
      ],
      vec![fixtures::feature("auth-ed25519-session")],
      vec![(fixtures::limit("in-flight-requests"), 256)],
    )
    .unwrap();
    let error = select(
      &registry,
      &initiator,
      &partial,
      initiator.required(),
      partial.required(),
    )
    .unwrap_err();
    assert_eq!(
      error,
      SelectionError::MissingRequired {
        label: DATA_MESSAGES.to_owned(),
      }
    );

    // Steps 4-6 use an extension registry with a symmetric conflict pair.
    let alpha = extension_feature("alpha", 1)
      .conflict(extension_tag("beta"))
      .unwrap();
    let beta = extension_feature("beta", 2)
      .conflict(extension_tag("alpha"))
      .unwrap();
    let gamma = extension_feature("gamma", 3);
    let extension_registry = FeatureRegistry::build(vec![alpha, beta, gamma]).unwrap();
    let conflict_offer = extension_offer(&extension_registry, &["alpha", "beta"], &[]);
    let error = select(
      &extension_registry,
      &conflict_offer,
      &conflict_offer,
      &[],
      &[],
    )
    .unwrap_err();
    assert_eq!(
      error,
      SelectionError::Conflict {
        first: "testing.example/features/alpha".to_owned(),
        second: "testing.example/features/beta".to_owned(),
      }
    );

    let local = extension_offer(&extension_registry, &["gamma"], &["gamma"]);
    let remote = extension_offer(&extension_registry, &[], &[]);
    let error = select(&extension_registry, &local, &remote, local.required(), &[]).unwrap_err();
    assert_eq!(
      error,
      SelectionError::MissingRequired {
        label: "testing.example/features/gamma".to_owned(),
      }
    );

    let unknown = extension_tag("delta");
    let error = select(
      &extension_registry,
      &local,
      &local,
      &[],
      std::slice::from_ref(&unknown),
    )
    .unwrap_err();
    assert_eq!(
      error,
      SelectionError::UnknownRequired {
        label: "testing.example/features/delta".to_owned(),
      }
    );

    // The `From` mapping keeps every failure an authentication failure.
    let error: Error = SelectionError::UnknownRequired {
      label: "x".to_owned(),
    }
    .into();
    assert_eq!(error.kind(), crate::ErrorKind::AuthenticationFailed);
  }

  fn offer_with_limits(
    registry: &FeatureRegistry, data_body_bytes: u64, in_flight_requests: u64,
  ) -> FeatureOffer {
    let initiator = initiator_offer(registry);
    FeatureOffer::new(
      initiator.supported().to_vec(),
      initiator.required().to_vec(),
      vec![
        (fixtures::limit("data-body-bytes"), data_body_bytes),
        (fixtures::limit("in-flight-requests"), in_flight_requests),
      ],
    )
    .unwrap()
  }

  fn supported_entry(registry: &FeatureRegistry, name: &str) -> (FeatureTag, Digest) {
    let tag = FeatureTag::parse(name).unwrap();
    let digest = registry.get(&tag).unwrap().definition_digest().unwrap();
    (tag, digest)
  }

  use crate::protocol::offer::fixtures::{extension_feature, extension_tag};

  fn extension_offer(
    registry: &FeatureRegistry, supported: &[&str], required: &[&str],
  ) -> FeatureOffer {
    FeatureOffer::new(
      supported
        .iter()
        .map(|name| supported_entry(registry, &format!("testing.example/features/{name}")))
        .collect(),
      required.iter().map(|name| extension_tag(name)).collect(),
      Vec::new(),
    )
    .unwrap()
  }

  #[test]
  fn handshake_selection_required_order_permutations_are_identical() {
    let registry = FeatureRegistry::builtin().unwrap();
    let initiator = initiator_offer(&registry);
    let responder = responder_offer(&registry);

    // Every ordering of the required union yields the same selection bytes.
    let mut required = initiator.required().to_vec();
    let baseline = select(
      &registry,
      &initiator,
      &responder,
      initiator.required(),
      responder.required(),
    )
    .unwrap();
    for _ in 0..required.len() {
      required.rotate_left(1);
      let permuted = FeatureOffer::new(
        initiator.supported().to_vec(),
        required.clone(),
        initiator.limits().to_vec(),
      )
      .unwrap();
      let selection = select(
        &registry,
        &permuted,
        &responder,
        permuted.required(),
        responder.required(),
      )
      .unwrap();
      assert_eq!(selection.bytes(), baseline.bytes());
    }
  }

  #[test]
  fn handshake_selection_unknown_optional_label_stays_transcript_bound_and_unselected() {
    let registry = FeatureRegistry::builtin().unwrap();
    let initiator = initiator_offer(&registry);
    // An unknown optional label in one offer: not in the registry, so it can
    // never be selected, but it remains part of this peer's transcript bytes.
    let unknown = FeatureTag::parse("testing.example/features/future-optional").unwrap();
    let unknown_digest = Digest::from_bytes([0xEE; 32]);
    let mut supported = initiator.supported().to_vec();
    supported.push((unknown.clone(), unknown_digest));
    let with_unknown = FeatureOffer::new(
      supported,
      initiator.required().to_vec(),
      initiator.limits().to_vec(),
    )
    .unwrap();

    let selection = select(
      &registry,
      &with_unknown,
      &responder_offer(&registry),
      with_unknown.required(),
      responder_offer(&registry).required(),
    )
    .unwrap();
    assert!(
      !selection.features().iter().any(|tag| tag == &unknown),
      "unknown optional must never be selected"
    );
    assert!(
      with_unknown
        .encode()
        .unwrap()
        .windows(unknown.as_str().len())
        .any(|window| window == unknown.as_str().as_bytes()),
      "unknown optional must remain in the transcript offer"
    );
  }

  #[test]
  fn handshake_offer_rejects_missing_duplicate_and_unknown_mandatory_limits() {
    let registry = FeatureRegistry::builtin().unwrap();
    let initiator = initiator_offer(&registry);

    // Missing a mandatory limit.
    let missing = FeatureOffer::new(
      initiator.supported().to_vec(),
      initiator.required().to_vec(),
      vec![(fixtures::limit("data-body-bytes"), 1_048_576)],
    )
    .unwrap();
    let error = missing.validate_limits(&registry).unwrap_err();
    assert_eq!(error.context(), "feature offer mandatory limits");

    // Duplicate limit entries reject at decode (ordering) and validation.
    let mut duplicates = initiator.limits().to_vec();
    duplicates.push(duplicates[0].clone());
    let duplicate_offer = FeatureOffer::new(
      initiator.supported().to_vec(),
      initiator.required().to_vec(),
      duplicates,
    );
    assert!(duplicate_offer.is_err());
    // Unknown mandatory limit: not owned by any offered label.
    let unknown = FeatureOffer::new(
      initiator.supported().to_vec(),
      initiator.required().to_vec(),
      vec![
        (fixtures::limit("data-body-bytes"), 1_048_576),
        (
          QualifiedTag::parse("radiata.woooo.tech/limits/not-owned").unwrap(),
          1,
        ),
      ],
    )
    .unwrap();
    let error = unknown.validate_limits(&registry).unwrap_err();
    assert_eq!(error.context(), "feature offer unknown limit");
  }
}
