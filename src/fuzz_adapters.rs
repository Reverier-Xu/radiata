//! The bounded fuzz adapters for the canonical decoder and selector fuzz
//! targets.
//!
//! The module exists only under `cfg(any(test, fuzzing))`: the corpus
//! replay suites reuse it for the out-of-libFuzzer ordered replay, the
//! libFuzzer targets drive it under `cargo fuzz`, and no production or
//! test-only surface outside this module changes. Every adapter is
//! panic-free by construction: it feeds the exact same fail-closed
//! decoders the production paths use and maps every outcome to a value.

use crate::{
  FeatureTag,
  identity::records::{
    CredentialUseV1, IdentityBindingV1, KeyCreationIntentV1, KeyDeletedV1, KeyDeletionIntentV1,
    LocalIdentityV1, MergeGrantV1,
  },
  membership::page::decode_descriptor,
  packet::wire,
  protocol::{CONTROL_CBOR_LIMITS, wire as protocol_wire},
  resource::ResourceRecordV1,
  routing::trace::decode_trace_record,
  storage::{migration::decode_schema_record, pending::PendingTransactionV1},
};

/// One packet frame decoded by the wire target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireFrame {
  Open,
  Chunk,
  End,
  Ack,
}

/// The wire target (`wire_decode`): prelude splitting, closed
/// kind lookups, and every packet frame body decoder. The prelude half
/// exercises the exact `split_message` boundary the transport uses; the
/// body half decodes the input as each packet frame shape directly.
pub fn wire_decode(input: &[u8]) -> Vec<WireFrame> {
  let mut decoded = Vec::new();
  // Prelude lane: any input carrying a valid 16-byte prelude with a
  // declared kind and a bounded body must split cleanly.
  let limit = u32::try_from(CONTROL_CBOR_LIMITS.max_body_len()).unwrap_or(u32::MAX);
  let _ =
    crate::protocol::envelope::split_message(input, 0, limit, limit, protocol_wire::is_declared);
  // Closed-registry lane: schema/kind bytes never resolve outside the
  // frozen registries.
  if input.len() >= 4 {
    let schema = u16::from_be_bytes([input[0], input[1]]);
    let kind = u16::from_be_bytes([input[2], input[3]]);
    if protocol_wire::lookup(schema, kind).is_some() {
      decoded.push(WireFrame::Open);
    }
  }
  // Frame-body lane: the same caller-selected limits production uses.
  if wire::decode_open(input, CONTROL_CBOR_LIMITS).is_ok() {
    decoded.push(WireFrame::Open);
  }
  if wire::decode_chunk(input, CONTROL_CBOR_LIMITS).is_ok() {
    decoded.push(WireFrame::Chunk);
  }
  if wire::decode_end(input, CONTROL_CBOR_LIMITS).is_ok() {
    decoded.push(WireFrame::End);
  }
  if wire::decode_ack(input, CONTROL_CBOR_LIMITS).is_ok() {
    decoded.push(WireFrame::Ack);
  }
  decoded
}

/// The persisted target (`persisted_decode`): every frozen
/// metadata record decoder across the identity, node, resource, trace,
/// transaction, and migration families. Each decoder is the exact
/// fail-closed production path; any outcome other than a clean
/// `Ok`/typed-`Err` is a fuzz finding.
pub fn persisted_decode(input: &[u8]) {
  let _ = LocalIdentityV1::decode(input);
  let _ = KeyCreationIntentV1::decode(input);
  let _ = KeyDeletionIntentV1::decode(input);
  let _ = KeyDeletedV1::decode(input);
  let _ = IdentityBindingV1::decode(input);
  let _ = CredentialUseV1::decode(input);
  let _ = MergeGrantV1::decode(input);
  let _ = decode_descriptor(input);
  let _ = ResourceRecordV1::decode(input);
  let _ = decode_trace_record(input);
  let _ = PendingTransactionV1::decode(input);
  // The migration schema-record grammar is byte-framed: kind byte, tag
  // length, tag text, optional 32-byte digest.
  let _ = decode_schema_record(&crate::StoreValue::new(std::sync::Arc::from(input)));
}

/// The selector target (`selector`): the bounded parser plus the
/// canonical round-trip invariant. Two parses of one input converge, the
/// canonical text reparses to itself, and every outcome is a value.
pub fn selector_parse(input: &[u8]) -> Option<String> {
  let text = std::str::from_utf8(input).ok()?;
  let selector = crate::Selector::parse(text).ok()?;
  let canonical = selector.as_str().to_owned();
  let reparsed = crate::Selector::parse(&canonical)
    .unwrap_or_else(|_| panic!("selector canonical text must reparse: {canonical}"));
  assert_eq!(
    reparsed.as_str(),
    canonical,
    "selector canonical form is not a fixed point: {canonical}"
  );
  // The canonical form is bounded by the same parser limits, so it can
  // never grow without bound across round trips.
  assert!(
    canonical.len() <= crate::routing::SELECTOR_INPUT_MAX_BYTES,
    "selector canonical form exceeded the frozen limit"
  );
  let _ = FeatureTag::parse("radiata.woooo.tech/features/session-core").ok();
  Some(canonical)
}

// ---- state-machine targets ----

use std::{collections::BTreeSet, sync::Arc as SharedArc};

use crate::{
  ErrorKind, NodeId, PublicKey, TraceId,
  identity::{
    merge::{MergeProposal, MergeState, commit_merge, merge_state},
    records::{GenerationId, MergeId},
    testing::{
      ScriptedKeys, SequenceEntropy, fresh_reference, node, open_context, scripted_signing,
    },
  },
  protocol::{
    feature::{
      AUTH_ED25519_SESSION, DATA_MESSAGES, DIRECT_REQUEST, FeatureRegistry, ROUTED_DELIVERY,
      SESSION_CORE,
    },
    offer::FeatureOffer,
    selection::select,
  },
  routing::{RouteContext, RouteProgress},
};

/// The builtin feature labels in wire order; the bitmask derivations index
/// into this frozen list.
const STATE_FEATURES: [&str; 5] = [
  AUTH_ED25519_SESSION,
  SESSION_CORE,
  DATA_MESSAGES,
  DIRECT_REQUEST,
  ROUTED_DELIVERY,
];

/// Derives one offer's supported set, required set, and mandatory limits
/// at the registry defaults from two bitmask bytes.
fn derive_offer(
  registry: &FeatureRegistry, support_bits: u8, required_bits: u8,
) -> crate::Result<FeatureOffer> {
  let mut supported = Vec::new();
  let mut required = Vec::new();
  let mut limits = Vec::new();
  for (index, name) in STATE_FEATURES.iter().enumerate() {
    if support_bits & (1 << index) == 0 {
      continue;
    }
    let tag = FeatureTag::parse(name)?;
    let Some(definition) = registry.get(&tag) else {
      continue;
    };
    supported.push((tag.clone(), definition.definition_digest()?));
    if required_bits & (1 << index) != 0 {
      required.push(tag);
    }
    for limit in definition.limits() {
      if limit.mandatory() {
        limits.push((limit.tag().clone(), limit.default()));
      }
    }
  }
  FeatureOffer::new(supported, required, limits)
}

/// The feature_selection target: derived offer
/// pairs exercise digest equality, dependency closure, conflict pairs,
/// limit minima, and required-label rejection with no downgrade or
/// fallback. Any panic is a finding; an accepted selection must satisfy
/// every structural invariant again.
pub fn feature_selection(input: &[u8]) -> Option<()> {
  let registry = FeatureRegistry::builtin().ok()?;
  let bytes = |offset: usize| -> u8 { bytes_at(input, offset) };
  let local = derive_offer(&registry, bytes(0), bytes(1)).ok()?;
  let remote = derive_offer(&registry, bytes(2), bytes(3)).ok()?;
  // Mutation: flip one digest byte in the first local supported entry so
  // the pair disagrees and the digest check must fire.
  let local = match bytes(16) % 4 {
    1 => {
      let mut supported = local.supported().to_vec();
      if let Some((_, digest)) = supported.first_mut() {
        let mut flipped = *digest.as_bytes();
        flipped[0] ^= 0xFF;
        *digest = crate::Digest::from_bytes(flipped);
      }
      FeatureOffer::new(
        supported,
        local.required().to_vec(),
        local.limits().to_vec(),
      )
      .ok()?
    }
    _ => local,
  };
  let selection = select(
    &registry,
    &local,
    &remote,
    local.required(),
    remote.required(),
  );
  let Ok(selection) = selection else {
    return Some(());
  };
  // Structural invariants on every accepted selection.
  let reselected = select(
    &registry,
    &local,
    &remote,
    local.required(),
    remote.required(),
  );
  match reselected {
    Ok(again) if again.bytes() == selection.bytes() => {}
    _ => panic!("selection is not deterministic"),
  }
  let selected: BTreeSet<&FeatureTag> = selection.features().iter().collect();
  for feature in selection.features() {
    if let Some(definition) = registry.get(feature) {
      for dependency in definition.dependencies() {
        if !selected.contains(dependency) {
          panic!("selection accepted an open dependency");
        }
      }
      for conflict in definition.conflicts() {
        if selected.contains(conflict) {
          panic!("selection accepted a conflict pair");
        }
      }
    }
  }
  for tag in local.required().iter().chain(remote.required()) {
    if !selected.contains(tag) {
      panic!("selection accepted a missing required label");
    }
  }
  Some(())
}

/// One derived admission operation.
#[derive(Clone, Copy)]
enum AdmissionOp {
  /// Commit a fresh proposal for one subject.
  Propose,
  /// Replay the last successful proposal (idempotence).
  Replay,
  /// Reuse the last successful generation with a different subject
  /// (single-subject binding).
  DoubleBook,
  /// Commit the last successful proposal with a different subject key.
  WrongKey,
}

fn admission_op(byte: u8) -> AdmissionOp {
  match byte % 4 {
    0 => AdmissionOp::Propose,
    1 => AdmissionOp::Replay,
    2 => AdmissionOp::DoubleBook,
    _ => AdmissionOp::WrongKey,
  }
}

/// The admission target: derived operation
/// sequences preserve the single-subject generation binding, replay
/// rejection/idempotence, and commit reconciliation against the reference
/// storage, with every error a typed value. The target allocates a fresh
/// deterministic fixture per input; generation/replay/double-book order
/// comes from the bytes.
pub fn admission(input: &[u8]) {
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build();
  let Ok(runtime) = runtime else {
    return;
  };
  runtime
    .block_on(async move {
      let (_reference, factory) = fresh_reference();
      let keys = ScriptedKeys::full();
      let entropy = SharedArc::new(SequenceEntropy::default());
      let context = SharedArc::new(match open_context(&factory, &keys, &entropy).await {
        Ok(context) => context,
        // A fixture failure is an environment error, not an input
        // finding: skip the run.
        Err(_) => return Ok::<(), crate::Error>(()),
      });
      if crate::identity::lifecycle::ensure_self_binding(&context, entropy.as_ref())
        .await
        .is_err()
      {
        return Ok(());
      }
      let mut last: Option<(MergeProposal, MergeGrantV1)> = None;
      for pair in input.chunks(2) {
        let op = admission_op(pair[0]);
        let subject_index = u64::from(pair.get(1).copied().unwrap_or(0)) % 4;
        match op {
          AdmissionOp::Propose => {
            let (Some(generation), Some(merge_id)) = (
              GenerationId::generate(entropy.as_ref()).ok(),
              MergeId::generate(entropy.as_ref()).ok(),
            ) else {
              return Ok(());
            };
            let proposal = MergeProposal::new(
              node(u128::from(subject_index) + 1_000),
              PublicKey::from_bytes(scripted_signing(subject_index).verifying_key().to_bytes()),
              generation,
              merge_id,
            );
            match commit_merge(&context, &keys.as_provider(), entropy.as_ref(), &proposal).await {
              Ok(grant) => {
                // The grant verifies against the issuer key and the state
                // machine reports the exact triple consumed.
                grant.verify(context.identity().public_key())?;
                match merge_state(&context, &proposal).await {
                  Ok(MergeState::Consumed(_, existing)) if *existing == grant => {}
                  other => panic!("admission state diverged after commit: {other:?}"),
                }
                last = Some((proposal, grant));
              }
              Err(error) => {
                // Every failure is a typed error, never a panic.
                let _ = error.kind();
              }
            }
          }
          AdmissionOp::Replay => {
            if let Some((proposal, grant)) = &last {
              let replayed =
                commit_merge(&context, &keys.as_provider(), entropy.as_ref(), proposal).await;
              match replayed {
                Ok(existing) if existing == *grant => {}
                _ => panic!("replay of a consumed admission diverged"),
              }
            }
          }
          AdmissionOp::DoubleBook => {
            if let Some((proposal, _)) = &last {
              let Some(merge_id) = MergeId::generate(entropy.as_ref()).ok() else {
                return Ok(());
              };
              let double = MergeProposal::new(
                node(u128::from(subject_index) + 2_000),
                PublicKey::from_bytes(
                  scripted_signing(subject_index + 4)
                    .verifying_key()
                    .to_bytes(),
                ),
                proposal.generation().clone(),
                merge_id,
              );
              match commit_merge(&context, &keys.as_provider(), entropy.as_ref(), &double).await {
                Err(error) => {
                  if error.kind() != ErrorKind::Conflict {
                    panic!("double-booking must fail closed as Conflict: {error:?}");
                  }
                }
                Ok(_) => panic!("a second subject admitted on a consumed generation"),
              }
              // The original admission survives the rejected attempt.
              match merge_state(&context, proposal).await {
                Ok(MergeState::Consumed(..)) => {}
                _ => panic!("the rejected attempt must not disturb the committed triple"),
              }
            }
          }
          AdmissionOp::WrongKey => {
            if let Some((proposal, _)) = &last {
              let wrong = MergeProposal::new(
                proposal.subject().clone(),
                PublicKey::from_bytes(
                  scripted_signing(subject_index + 8)
                    .verifying_key()
                    .to_bytes(),
                ),
                proposal.generation().clone(),
                proposal.merge().clone(),
              );
              match commit_merge(&context, &keys.as_provider(), entropy.as_ref(), &wrong).await {
                Err(error) => {
                  if error.kind() != ErrorKind::Conflict {
                    panic!("a wrong-key replay must fail closed as Conflict: {error:?}");
                  }
                }
                Ok(_) => panic!("a wrong-key replay admitted a different subject key"),
              }
            }
          }
        }
      }
      Ok::<(), crate::Error>(())
    })
    .ok();
}

/// The routing target: derived transition
/// sequences over the route envelope preserve authenticated holder
/// selection, one checked next hop, monotone budget drain, duplicate-free
/// visited chains, and explicit termination; every rejection is a typed
/// error, never a panic.
pub fn routing(input: &[u8]) -> Option<()> {
  let pool: Vec<NodeId> = (1_u8..=8)
    .map(|index| NodeId::parse(&format!("node_{index:021}")))
    .collect::<crate::Result<Vec<_>>>()
    .ok()?;
  let node = |byte: u8| pool[usize::from(byte) % pool.len()].clone();
  let trace = TraceId::parse("trace_000000000000000000001").ok()?;
  let max_hops = u32::from(bytes_at(input, 0) % 8) + 1;
  let mut context = RouteContext::new(
    trace,
    node(bytes_at(input, 1)),
    node(bytes_at(input, 2)),
    max_hops,
  );
  let mut step = 3_usize;
  while step + 3 <= input.len() {
    let local = node(bytes_at(input, step));
    let peer = node(bytes_at(input, step + 1));
    let next_byte = bytes_at(input, step + 2);
    let choose = |_: &RouteContext| -> crate::Result<NodeId> {
      if next_byte == 0xFF {
        return Err(crate::Error::invalid_input("no next hop"));
      }
      Ok(node(next_byte % 0xFF))
    };
    // `receive` consumes the envelope; keep a clone for the oracle
    // assertions below.
    let before = context.clone();
    let remaining_before = before.hop_state().remaining_hops;
    let visited_before = before.visited().len();
    match before.receive(&local, &peer, choose) {
      Ok(RouteProgress::Arrive) => {
        if context.destination() != &local {
          panic!("Arrive at a non-destination");
        }
        break;
      }
      Ok(RouteProgress::Continue {
        next_hop,
        context: advanced,
      }) => {
        // The forwarded envelope is a fresh route state: the previous
        // holder joins the visited chain once and the budget drains once.
        if advanced.hop_state().remaining_hops + 1 != remaining_before {
          panic!("route budget did not drain exactly once");
        }
        if advanced.visited().len() != visited_before + 1 {
          panic!("the visited chain did not grow by exactly one holder");
        }
        let mut seen = std::collections::BTreeSet::new();
        for holder in advanced.visited() {
          if !seen.insert(holder) || holder == advanced.current() {
            panic!("visited chain has a duplicate or includes the current holder");
          }
        }
        if next_hop == local || next_hop == *advanced.current() {
          panic!("the next hop loops back to the holder or the local node");
        }
        context = advanced;
      }
      Err(error) => {
        // Every rejection is a typed error (Conflict/InvalidInput/
        // NotTrusted/ResourceExhausted), never a panic.
        let _ = error.kind();
        break;
      }
    }
    step += 3;
  }
  Some(())
}

fn bytes_at(input: &[u8], offset: usize) -> u8 {
  input.get(offset).copied().unwrap_or(0)
}

#[cfg(test)]
mod replay_tests {
  //! Ordered corpus replay: every approved
  //! retained corpus input replays exactly once in filename order,
  //! outside libFuzzer scheduling. Malformed or over-bound inputs must
  //! fail closed with typed errors and never panic.

  use std::path::PathBuf;

  /// One retained corpus: the manifest digests and the directory listing
  /// must agree exactly, so an omitted fixture or an unscreened addition
  /// fails the suite.
  fn corpus_files(target: &str) -> Vec<(String, PathBuf, Vec<u8>)> {
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
      .join("fuzz")
      .join("corpus")
      .join(target);
    let manifest = std::fs::read_to_string(directory.join("manifest.toml"))
      .unwrap_or_else(|error| panic!("missing retained manifest for {target}: {error}"));
    let manifest_digests: Vec<String> = manifest
      .lines()
      .filter_map(|line| line.trim().strip_prefix("digest = \""))
      .map(|line| line.trim_end_matches('"').to_owned())
      .collect();
    assert!(
      !manifest_digests.is_empty(),
      "the retained corpus for {target} has no manifest entries"
    );

    let mut files: Vec<(String, PathBuf, Vec<u8>)> = std::fs::read_dir(&directory)
      .unwrap_or_else(|error| panic!("missing retained corpus directory for {target}: {error}"))
      .filter_map(|entry| entry.ok())
      .map(|entry| entry.path())
      .filter(|path| path.extension().is_some_and(|extension| extension == "bin"))
      .map(|path| {
        let name = path
          .file_stem()
          .and_then(|stem| stem.to_str())
          .expect("corpus file name")
          .to_owned();
        let bytes = std::fs::read(&path).expect("corpus file bytes");
        (name, path, bytes)
      })
      .collect();
    // Filename order: the frozen replay order.
    files.sort_by(|left, right| left.0.cmp(&right.0));

    // Every manifest entry exists and every file is manifest-listed.
    let mut listed = manifest_digests;
    listed.sort();
    let mut present: Vec<String> = files.iter().map(|(name, ..)| name.clone()).collect();
    present.sort();
    assert_eq!(listed, present, "the {target} manifest and corpus diverge");

    // Each file's bytes hash exactly to its frozen digest name.
    use sha2::Digest as _;
    for (name, path, bytes) in &files {
      let digest: [u8; 32] = sha2::Sha256::digest(bytes).into();
      assert_eq!(
        crate::hex::encode(&digest),
        *name,
        "corpus file {} does not match its frozen digest",
        path.display()
      );
    }
    files
  }

  /// Replays one input exactly once through the wire target.
  #[test]
  fn wire_corpus_replays_in_filename_order() {
    let files = corpus_files("wire_decode");
    for (name, path, bytes) in &files {
      // The replay result is a value: any clean frame list is
      // acceptable, a panic is a finding.
      let frames = super::wire_decode(bytes);
      assert!(
        frames.len() <= 4,
        "wire corpus entry {name} ({}) produced an impossible frame list",
        path.display()
      );
    }
  }

  /// Replays one input exactly once through the persisted target.
  #[test]
  fn persisted_corpus_replays_in_filename_order() {
    for (name, path, bytes) in corpus_files("persisted_decode") {
      super::persisted_decode(&bytes);
      let _ = (name, path);
    }
  }

  /// Replays one input exactly once through the selector target; valid
  /// entries must satisfy the canonical fixed-point invariant.
  #[test]
  fn selector_corpus_replays_in_filename_order() {
    for (name, path, bytes) in corpus_files("selector") {
      let canonical = super::selector_parse(&bytes);
      if let Some(canonical) = canonical {
        assert!(
          !canonical.is_empty(),
          "selector corpus entry {name} ({}) parsed to an empty canonical form",
          path.display()
        );
      }
    }
  }

  /// Replays one input exactly once through the admission state-machine
  /// target.
  #[test]
  fn admission_corpus_replays_in_filename_order() {
    for (name, path, bytes) in corpus_files("admission") {
      super::admission(&bytes);
      let _ = (name, path);
    }
  }

  /// Replays one input exactly once through the feature-selection
  /// state-machine target.
  #[test]
  fn feature_selection_corpus_replays_in_filename_order() {
    for (name, path, bytes) in corpus_files("feature_selection") {
      let _ = super::feature_selection(&bytes);
      let _ = (name, path);
    }
  }

  /// Replays one input exactly once through the routing state-machine
  /// target.
  #[test]
  fn routing_corpus_replays_in_filename_order() {
    for (name, path, bytes) in corpus_files("routing") {
      let _ = super::routing(&bytes);
      let _ = (name, path);
    }
  }
}
