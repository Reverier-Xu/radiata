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
//! 7. `C*` is canonically sorted and the deterministic-CBOR selection bytes
//!    must match exactly on both peers before either signs the transcript.

use std::collections::BTreeSet;

use minicbor::Encode;

use super::{
  CONTROL_CBOR_LIMITS, FeatureTag, encode_canonical, feature::FeatureRegistry, offer::FeatureOffer,
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
  bytes: Vec<u8>,
}

impl Selection {
  /// The selected feature set.
  pub(crate) fn features(&self) -> &[FeatureTag] {
    &self.features
  }

  /// The deterministic-CBOR selection bytes exchanged for exact match.
  pub(crate) fn bytes(&self) -> &[u8] {
    &self.bytes
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

  // Step 7: canonical sort and selection bytes.
  let features: Vec<FeatureTag> = selected.iter().map(|tag| (*tag).clone()).collect();
  let wire = SelectionWire {
    features: features.iter().map(|tag| tag.as_str().to_owned()).collect(),
  };
  let bytes =
    encode_canonical(&wire, CONTROL_CBOR_LIMITS).map_err(|_| SelectionError::Malformed {
      context: "selection encode",
    })?;
  Ok(Selection { features, bytes })
}

#[derive(Encode)]
#[cbor(array)]
struct SelectionWire {
  #[n(0)]
  features: Vec<String>,
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

  const INITIATOR_OFFER_HEX: &str = "8285827830726164696174612e776f6f6f6f2e746563682f66656174757265732f617574682d656432353531392d73657373696f6e58203df87b424b76c2b0e73284e877679a07aeb1688c150bf90a99c6bc667f0b8aae827829726164696174612e776f6f6f6f2e746563682f66656174757265732f646174612d6d657373616765735820b65136c721b44eb602c70788a372644af3b738ccfe0437c2ba33060a89ff9d2f82782a726164696174612e776f6f6f6f2e746563682f66656174757265732f6469726563742d726571756573745820469160fe1e5ddfa06da9874fffd0fbac0582beaea670991697f809df6813e3e082782b726164696174612e776f6f6f6f2e746563682f66656174757265732f726f757465642d64656c6976657279582057dfd16e43af9dbf7a4e47bdbeb40cb50d2f031d0355bb126dc3c16134f859a5827828726164696174612e776f6f6f6f2e746563682f66656174757265732f73657373696f6e2d636f7265582022373a9809f3ec58a1becf45acb4dfae3da54151973534fcfc18aeab57f0f874847830726164696174612e776f6f6f6f2e746563682f66656174757265732f617574682d656432353531392d73657373696f6e7829726164696174612e776f6f6f6f2e746563682f66656174757265732f646174612d6d65737361676573782a726164696174612e776f6f6f6f2e746563682f66656174757265732f6469726563742d726571756573747828726164696174612e776f6f6f6f2e746563682f66656174757265732f73657373696f6e2d636f7265";
  const RESPONDER_OFFER_HEX: &str = "8285827830726164696174612e776f6f6f6f2e746563682f66656174757265732f617574682d656432353531392d73657373696f6e58203df87b424b76c2b0e73284e877679a07aeb1688c150bf90a99c6bc667f0b8aae827829726164696174612e776f6f6f6f2e746563682f66656174757265732f646174612d6d657373616765735820b65136c721b44eb602c70788a372644af3b738ccfe0437c2ba33060a89ff9d2f82782a726164696174612e776f6f6f6f2e746563682f66656174757265732f6469726563742d726571756573745820469160fe1e5ddfa06da9874fffd0fbac0582beaea670991697f809df6813e3e082782b726164696174612e776f6f6f6f2e746563682f66656174757265732f726f757465642d64656c6976657279582057dfd16e43af9dbf7a4e47bdbeb40cb50d2f031d0355bb126dc3c16134f859a5827828726164696174612e776f6f6f6f2e746563682f66656174757265732f73657373696f6e2d636f7265582022373a9809f3ec58a1becf45acb4dfae3da54151973534fcfc18aeab57f0f874857830726164696174612e776f6f6f6f2e746563682f66656174757265732f617574682d656432353531392d73657373696f6e7829726164696174612e776f6f6f6f2e746563682f66656174757265732f646174612d6d65737361676573782a726164696174612e776f6f6f6f2e746563682f66656174757265732f6469726563742d72657175657374782b726164696174612e776f6f6f6f2e746563682f66656174757265732f726f757465642d64656c69766572797828726164696174612e776f6f6f6f2e746563682f66656174757265732f73657373696f6e2d636f7265";
  const SELECTION_HEX: &str = "81857830726164696174612e776f6f6f6f2e746563682f66656174757265732f617574682d656432353531392d73657373696f6e7829726164696174612e776f6f6f6f2e746563682f66656174757265732f646174612d6d65737361676573782a726164696174612e776f6f6f6f2e746563682f66656174757265732f6469726563742d72657175657374782b726164696174612e776f6f6f6f2e746563682f66656174757265732f726f757465642d64656c69766572797828726164696174612e776f6f6f6f2e746563682f66656174757265732f73657373696f6e2d636f7265";

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

    // Offer input ordering never changes the canonical bytes.
    let mut shuffled_supported = initiator.supported().to_vec();
    shuffled_supported.reverse();
    let shuffled = FeatureOffer::new(shuffled_supported, initiator.required().to_vec()).unwrap();
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
  fn handshake_selection_rejects_digest_mismatch_conflict_and_required() {
    let registry = FeatureRegistry::builtin().unwrap();
    let initiator = initiator_offer(&registry);
    let responder = responder_offer(&registry);

    // Step 1: a changed digest on a common label rejects.
    let mut forged_supported = responder.supported().to_vec();
    forged_supported[0].1 = Digest::from_bytes([0xCD; 32]);
    let forged = FeatureOffer::new(forged_supported, responder.required().to_vec()).unwrap();
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
    let wrong_responder =
      FeatureOffer::new(wrong_supported, responder.required().to_vec()).unwrap();
    let mut wrong_initiator_supported = initiator.supported().to_vec();
    wrong_initiator_supported[0].1 = Digest::from_bytes([0xCD; 32]);
    let wrong_initiator =
      FeatureOffer::new(wrong_initiator_supported, initiator.required().to_vec()).unwrap();
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
      let permuted = FeatureOffer::new(initiator.supported().to_vec(), required.clone()).unwrap();
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
    let with_unknown = FeatureOffer::new(supported, initiator.required().to_vec()).unwrap();

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

  /// The selection wire carries exactly one element, the selected feature
  /// set: the deleted per-limit array must never come back. Re-adding a
  /// `limits` field to `SelectionWire` makes this arity check fail.
  #[test]
  fn handshake_selection_wire_carries_only_the_feature_set() {
    let registry = FeatureRegistry::builtin().unwrap();
    let initiator = initiator_offer(&registry);
    let responder = responder_offer(&registry);
    let selection = select(
      &registry,
      &initiator,
      &responder,
      initiator.required(),
      responder.required(),
    )
    .unwrap();
    let bytes = selection.bytes();
    let mut decoder = minicbor::Decoder::new(bytes);
    assert_eq!(decoder.array().unwrap(), Some(1), "one wire element");
    let features = decoder.array().unwrap().expect("feature array");
    for _ in 0..features {
      decoder.str().unwrap();
    }
    assert_eq!(decoder.position(), bytes.len(), "no trailing wire element");
  }
}
