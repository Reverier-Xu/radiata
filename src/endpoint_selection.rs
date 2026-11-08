//! The endpoint-selection seam: one policy interface that decides which
//! published endpoint a member dial lands on, with the three official
//! built-ins installed by the extension registry's default pass and the
//! per-member rotation state every dial plane shares.
//!
//! The seam is pull-shaped: every dial of a member asks the selector once.
//! The caller hands over the member's candidate set exactly as the
//! authoritative member-table descriptor published it (see
//! `runtime/recovery.rs::known_online_member_endpoints` — the recovery
//! scan, the degree maintenance tick, and the bridge probe all read the
//! same descriptor lists), and the selector returns the one endpoint that
//! dial consumes. The dial planes keep their own budgets, schedules, and
//! classes; only endpoint choice is policy.
//!
//! # Fail-closed candidate validation
//!
//! A policy never speaks in endpoint values: it orders the validated
//! candidate set by returning a permutation (possibly a filtered subset)
//! of candidate *indices*. The selector drops any index outside the
//! candidate set before use, so a custom policy — buggy, hostile, or
//! merely confused — can never make the node dial an endpoint the member's
//! descriptor did not publish. With no dialable ordering left the dial is
//! skipped and the member stays a candidate for a later tick, exactly like
//! the pre-seem rotation's empty-endpoint skip.
//!
//! # Per-member rotation handle
//!
//! [`EndpointSelector`] owns the per-member dial serials the three dial
//! loops previously hand-copied (recovery fan-out, degree deficit batch,
//! bridge probe): each dial of a member advances that member's own serial,
//! wrapping per member, and the dial lands on the serial's position in the
//! policy-ordered candidates. Per-member serials decouple member selection
//! from endpoint rotation — the failover liveness contract pinned by the
//! recovery suite's exhaustive sweep test — and one shared serial map
//! keeps the two runtime dial planes rotating a member's endpoints
//! together, exactly as before the seam existed. Under the default
//! [`PublishedOrderPolicy`] the ordering is the identity over the
//! published list, so every dial outcome is bit-identical to the
//! hand-copied rotation.

use std::{fmt, sync::Arc};

use crate::{Endpoint, Error, NodeId, QualifiedTag, Result, TransportName};

/// One dial outcome an observant policy can learn from: the dial
/// established its session (carrying the connect-plus-bootstrap elapsed
/// time) or it failed (refused, timed out, reset). Strictly observational
/// input — the policies below reorder candidates from these marks and
/// never invent quality for a scheme they have not observed.
#[derive(Clone, Copy, Debug)]
pub enum DialObservation {
  /// The dial completed and the session was established.
  Delivered(std::time::Duration),
  /// The dial failed before an authenticated session existed.
  Failed,
}

/// The endpoint-selection policy: orders one member's validated candidate
/// set for its next dial. Registered implementations live in the node's
/// extension registry (the built-ins under their reserved tags through
/// [`crate::ExtensionRegistry::register_default`], caller policies under
/// caller-owned domains through
/// [`crate::ExtensionRegistry::register_endpoint_policy`]), and the node's
/// effective instance resolves once in the registration channel — the
/// same discipline as the next-hop route policy.
///
/// The returned ordering is an index sequence over `candidates` in
/// dial-preference order — typically a permutation (possibly a filtered
/// subset); the selector drops out-of-range indices fail-closed and
/// does not deduplicate, so a policy that repeats an index pins that
/// member's dial to one endpoint (reordering is the maximum damage a
/// policy can do, and repetition is its own risk to own). Stateful
/// policies (the outcome-weighted built-in, a caller's own learner)
/// keep their observation tables inside themselves; the trait methods
/// take `&self` so one instance serves the node's lifetime.
pub trait EndpointSelectionPolicy: fmt::Debug + Send + Sync + 'static {
  /// Orders one member's validated candidate set for its next dial.
  fn rank_candidates(&self, member: &NodeId, candidates: &[Endpoint]) -> Vec<usize>;

  /// Records one dial outcome for the endpoint's scheme. Observant
  /// policies override this; the default ignores the mark.
  fn observe_outcome(&self, _scheme: &TransportName, _outcome: DialObservation) {}
}

/// Parses one built-in policy's well-known tag literal once; the
/// impossible parse failure of a fixed canonical constant surfaces as an
/// internal error instead of a panic (the same shape as the routing
/// registry's built-in tags).
fn builtin_tag(
  slot: &'static std::sync::OnceLock<std::result::Result<QualifiedTag, ()>>, literal: &'static str,
) -> Result<QualifiedTag> {
  slot
    .get_or_init(|| QualifiedTag::parse(literal).map_err(|_| ()))
    .clone()
    .map_err(|_| Error::internal("built-in endpoint-selection policy tag"))
}

/// The default built-in: today's published-order rotation. The ordering
/// is the identity over the candidate list, so the selector's per-member
/// serial lands each dial on `(serial − 1) mod len` — byte-identical to
/// the rotation the recovery and degree dial loops hand-copied before the
/// seam existed. Registered under [`Self::TAG`] by the default pass and
/// resolved as the effective policy whenever the node configures no
/// preference list and no explicit policy tag.
#[derive(Debug, Default)]
pub struct PublishedOrderPolicy;

impl PublishedOrderPolicy {
  /// The well-known tag the built-in policy is registered under. The
  /// built-in domain is insertion-once reserved: a caller policy can
  /// never claim or replace it.
  pub const TAG: &'static str = "radiata.woooo.tech/endpoint-policies/published-order";

  /// The built-in policy's canonical tag, parsed once.
  pub fn tag() -> Result<QualifiedTag> {
    static TAG: std::sync::OnceLock<std::result::Result<QualifiedTag, ()>> =
      std::sync::OnceLock::new();
    builtin_tag(&TAG, Self::TAG)
  }
}

impl EndpointSelectionPolicy for PublishedOrderPolicy {
  fn rank_candidates(&self, _member: &NodeId, candidates: &[Endpoint]) -> Vec<usize> {
    (0..candidates.len()).collect()
  }
}

/// The preference-order built-in: reorders each member's candidates by a
/// NodeConfig-declared scheme preference list (e.g. `wss` before `tcp`).
/// A candidate whose scheme sits in the list ranks by list position; a
/// candidate with an unknown (or unpreferred) scheme keeps its published
/// position after every preferred one — the per-candidate fallback is the
/// fail-safe, so no registration or reachability knowledge is needed to
/// stay correct. With no observations and no list the ordering is exactly
/// published order.
///
/// The node builder resolves the config's preference list into an
/// instance of this policy in the registration channel; the registry's
/// default-pass instance carries the empty list, which is the published-
/// order fallback shape.
#[derive(Debug, Default)]
pub struct PreferenceOrderPolicy {
  preference: Vec<TransportName>,
}

impl PreferenceOrderPolicy {
  /// The well-known tag the built-in policy is registered under. The
  /// built-in domain is insertion-once reserved: a caller policy can
  /// never claim or replace it.
  pub const TAG: &'static str = "radiata.woooo.tech/endpoint-policies/preference-order";

  /// The built-in policy's canonical tag, parsed once.
  pub fn tag() -> Result<QualifiedTag> {
    static TAG: std::sync::OnceLock<std::result::Result<QualifiedTag, ()>> =
      std::sync::OnceLock::new();
    builtin_tag(&TAG, Self::TAG)
  }

  /// Builds the policy over one scheme preference list. An empty list is
  /// the no-preference shape: every candidate falls back to published
  /// order. (The config surface validates the caller's list — nonempty
  /// and duplicate-free — before it reaches here.)
  pub fn new(preference: Vec<TransportName>) -> Self {
    Self { preference }
  }
}

impl EndpointSelectionPolicy for PreferenceOrderPolicy {
  fn rank_candidates(&self, _member: &NodeId, candidates: &[Endpoint]) -> Vec<usize> {
    // A stable sort over the published indices: candidates whose scheme
    // is preferred rank by list position, everything else keeps its
    // published order behind them. (An explicit group key, not
    // `Option`'s own ordering — `None` sorts *before* `Some`.)
    let mut ranked: Vec<usize> = (0..candidates.len()).collect();
    ranked.sort_by_key(|&index| {
      match self
        .preference
        .iter()
        .position(|name| *name == candidates[index].selector())
      {
        Some(position) => (0, position),
        None => (1, 0),
      }
    });
    ranked
  }
}

/// The RTT EWMA weight: one sample moves a quarter of the distance, so
/// the scheme score follows a real degradation within a few dials without
/// tracking single-dial jitter. Mirrors the sync plane's `LinkProfile`
/// curve so all outcome observations in the crate weigh evidence alike.
const RTT_EWMA_ALPHA: f64 = 0.25;
/// The loss EWMA weight: slower than the RTT weight so one burst of
/// failures does not flip the ordering on its own. Mirrors `LinkProfile`.
const LOSS_EWMA_ALPHA: f64 = 0.125;

/// One transport scheme's recent dial outcomes: the EWMA dial latency in
/// milliseconds (`None` until the first delivered dial) and the EWMA
/// failure rate in `[0, 1]`. The same two statistics the sync plane's
/// per-session `LinkProfile` keeps, observed node-wide per scheme here.
#[derive(Debug, Default)]
struct SchemeOutcome {
  rtt_ewma_ms: Option<f64>,
  loss_ewma: f64,
}

/// The outcome-weighted built-in: orders candidates by each scheme's
/// recent dial outcomes, observed node-wide through
/// [`EndpointSelector::observe_outcome`] (the shared dial lifecycle feeds
/// every member dial's result). Strictly observant, never creative — the
/// ordering is a stable sort by each scheme's outcome key:
///
/// - **failure EWMA ascending**, then **latency EWMA ascending**;
/// - an **unobserved** scheme scores zero failures and unknown latency, so it
///   keeps its published position ahead of a scheme with observed failures and
///   behind a scheme with observed deliveries — no scheme is ever assumed good
///   or bad without evidence;
/// - with **no** observations at all (cold start) every key is equal and the
///   ordering is exactly published order.
///
/// The observation table is owned here, keyed by scheme — not by the sync
/// plane's per-session `LinkProfile` — so the seam's evidence stays
/// node-wide and the sync plane's session struct stays private to its own
/// knobs. A poisoned table degrades to published order (a ranking
/// heuristic never blocks a dial).
#[derive(Debug, Default)]
pub struct OutcomeWeightedPolicy {
  outcomes: std::sync::Mutex<std::collections::BTreeMap<TransportName, SchemeOutcome>>,
}

impl OutcomeWeightedPolicy {
  /// The well-known tag the built-in policy is registered under. The
  /// built-in domain is insertion-once reserved: a caller policy can
  /// never claim or replace it.
  pub const TAG: &'static str = "radiata.woooo.tech/endpoint-policies/outcome-weighted";

  /// The built-in policy's canonical tag, parsed once.
  pub fn tag() -> Result<QualifiedTag> {
    static TAG: std::sync::OnceLock<std::result::Result<QualifiedTag, ()>> =
      std::sync::OnceLock::new();
    builtin_tag(&TAG, Self::TAG)
  }

  /// The dial-preference key of one scheme: failure EWMA first, latency
  /// EWMA second. An unobserved scheme scores zero failures and unknown
  /// latency; equal keys keep published order (stable sort).
  fn rank_key(outcomes: &SchemeOutcome) -> (f64, f64) {
    (
      outcomes.loss_ewma,
      outcomes.rtt_ewma_ms.unwrap_or(f64::INFINITY),
    )
  }
}

/// The outcome key of an unobserved scheme: zero failures, unknown
/// latency (see [`OutcomeWeightedPolicy::rank_key`]).
const UNOBSERVED_SCHEME_KEY: (f64, f64) = (0.0, f64::INFINITY);

impl EndpointSelectionPolicy for OutcomeWeightedPolicy {
  fn rank_candidates(&self, _member: &NodeId, candidates: &[Endpoint]) -> Vec<usize> {
    let Ok(outcomes) = self.outcomes.lock() else {
      // Poisoned table: degrade to published order, never block a dial.
      return (0..candidates.len()).collect();
    };
    let mut ranked: Vec<usize> = (0..candidates.len()).collect();
    ranked.sort_by(|&a, &b| {
      let key = |index: usize| {
        outcomes
          .get(&candidates[index].selector())
          .map_or(UNOBSERVED_SCHEME_KEY, Self::rank_key)
      };
      let (left, right) = (key(a), key(b));
      left
        .0
        .total_cmp(&right.0)
        .then_with(|| left.1.total_cmp(&right.1))
    });
    ranked
  }

  fn observe_outcome(&self, scheme: &TransportName, outcome: DialObservation) {
    let Ok(mut outcomes) = self.outcomes.lock() else {
      return;
    };
    let stats = outcomes.entry(scheme.clone()).or_default();
    match outcome {
      DialObservation::Delivered(elapsed) => {
        let sample = elapsed.as_secs_f64() * 1_000.0;
        stats.rtt_ewma_ms = Some(match stats.rtt_ewma_ms {
          Some(ewma) => ewma + RTT_EWMA_ALPHA * (sample - ewma),
          None => sample,
        });
        stats.loss_ewma *= 1.0 - LOSS_EWMA_ALPHA;
      }
      DialObservation::Failed => {
        stats.loss_ewma += LOSS_EWMA_ALPHA * (1.0 - stats.loss_ewma);
      }
    }
  }
}

/// The node's endpoint selector: the resolved policy plus the per-member
/// rotation serials the dial planes share. One instance lives on the
/// node's operation planes; every dial of a member — recovery fan-out,
/// degree deficit batch, bridge probe — resolves through
/// [`EndpointSelector::next_endpoint`], which advances that member's own
/// serial and lands on the serial's position in the policy-ordered
/// candidates.
pub struct EndpointSelector {
  policy: Arc<dyn EndpointSelectionPolicy>,
  serials: std::sync::Mutex<std::collections::BTreeMap<NodeId, u64>>,
}

impl fmt::Debug for EndpointSelector {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("EndpointSelector")
      .field("policy", &self.policy)
      .finish()
  }
}

impl EndpointSelector {
  /// Builds one selector over the resolved effective policy.
  pub fn new(policy: Arc<dyn EndpointSelectionPolicy>) -> Self {
    Self {
      policy,
      serials: std::sync::Mutex::new(std::collections::BTreeMap::new()),
    }
  }

  /// The endpoint one dial of `member` lands on: advances the member's
  /// own rotation serial (first dial = serial 1 = the policy's first
  /// candidate), ranks the validated candidates through the policy, and
  /// selects the serial's position in that order, wrapping per member.
  ///
  /// `candidates` must be the member's published endpoints exactly as the
  /// authoritative descriptor carries them; the fail-closed index filter
  /// below makes any policy output outside that set undialable. A
  /// poisoned serial table or an empty (or fully filtered-out) ordering
  /// skips the dial: the member stays a candidate for a later tick.
  pub fn next_endpoint(&self, member: &NodeId, candidates: &[Endpoint]) -> Option<Endpoint> {
    let serial = {
      let mut serials = self.serials.lock().ok()?;
      let serial = serials.entry(member.clone()).or_insert(0);
      *serial = serial.wrapping_add(1);
      *serial
    };
    if candidates.is_empty() {
      return None;
    }
    // Fail-closed candidate validation: a policy ordering may only name
    // candidates the caller validated against the member's descriptor.
    let mut ranked = self.policy.rank_candidates(member, candidates);
    ranked.retain(|index| *index < candidates.len());
    if ranked.is_empty() {
      return None;
    }
    let index = (serial.saturating_sub(1) as usize) % ranked.len();
    Some(candidates[ranked[index]].clone())
  }

  /// Feeds one dial outcome to the policy (an observant policy learns
  /// per scheme; the default ignores the mark). Called by the shared dial
  /// lifecycle when a member dial settles.
  pub fn observe_outcome(&self, endpoint: &Endpoint, outcome: DialObservation) {
    self.policy.observe_outcome(&endpoint.selector(), outcome);
  }

  /// Drops the rotation serials of members that no longer satisfy
  /// `keep`: a serial for a member that left the member table is dead
  /// rotation phase. The recovery tick retains the live member universe
  /// through this each tick (the same bounded-state rule the hand-copied
  /// map followed).
  pub(crate) fn retain_members(&self, keep: impl Fn(&NodeId) -> bool) {
    if let Ok(mut serials) = self.serials.lock() {
      serials.retain(|member, _| keep(member));
    }
  }
}

#[cfg(test)]
mod tests {
  use super::{
    DialObservation, EndpointSelectionPolicy, EndpointSelector, OutcomeWeightedPolicy,
    PreferenceOrderPolicy, PublishedOrderPolicy,
  };
  use crate::{Endpoint, NodeId, TransportName};

  fn endpoint(url: &str) -> Endpoint {
    Endpoint::parse(url).unwrap()
  }

  fn node(value: u8) -> NodeId {
    NodeId::parse(&format!("node-{value:021}")).unwrap()
  }

  /// A custom policy that names a fixed index ordering, including
  /// out-of-range garbage, to pin the fail-closed filter.
  #[derive(Debug)]
  struct FixedOrder(Vec<usize>);

  impl EndpointSelectionPolicy for FixedOrder {
    fn rank_candidates(&self, _member: &NodeId, _candidates: &[Endpoint]) -> Vec<usize> {
      self.0.clone()
    }
  }

  /// The default policy is today's rotation: the first dial of a member
  /// lands on its first published endpoint, every further dial advances
  /// that member's own serial, and the rotation wraps per member —
  /// independent of every other member's cursor.
  #[test]
  fn published_order_rotates_per_member_and_wraps() {
    let selector = EndpointSelector::new(std::sync::Arc::new(PublishedOrderPolicy));
    let member = node(1);
    let candidates = vec![
      endpoint("wss://10.0.0.1:9001"),
      endpoint("tls://10.0.0.1:9002"),
      endpoint("tcp://10.0.0.1:9003"),
    ];
    let landed: Vec<String> = (0..5)
      .map(|_| {
        selector
          .next_endpoint(&member, &candidates)
          .unwrap()
          .to_string()
      })
      .collect();
    assert_eq!(
      landed,
      [
        "wss://10.0.0.1:9001",
        "tls://10.0.0.1:9002",
        "tcp://10.0.0.1:9003",
        "wss://10.0.0.1:9001",
        "tls://10.0.0.1:9002",
      ]
    );

    // A second member's cursor is its own: its first dial lands on its
    // first endpoint even though the first member already rotated.
    let other = node(2);
    let single = vec![endpoint("wss://10.0.0.2:9001")];
    assert_eq!(
      selector.next_endpoint(&other, &single).unwrap().to_string(),
      "wss://10.0.0.2:9001"
    );

    // An empty candidate set advances nothing dialable: the dial is
    // skipped, and the member's next real dial continues its rotation
    // (five dials in, the sixth real dial wraps to the first endpoint).
    assert!(selector.next_endpoint(&member, &[]).is_none());
    assert_eq!(
      selector
        .next_endpoint(&member, &candidates)
        .unwrap()
        .to_string(),
      "wss://10.0.0.1:9001"
    );
  }

  /// Preference-order reorders per the configured scheme list, falls back
  /// to published order per candidate for unknown schemes, and is exactly
  /// published order with no preference declared.
  #[test]
  fn preference_order_reorders_per_the_configured_list() {
    let candidates = vec![
      endpoint("wss://10.0.0.1:1"),
      endpoint("tls://10.0.0.1:2"),
      endpoint("tcp://10.0.0.1:3"),
      endpoint("custom://10.0.0.1:4"),
    ];
    let order_of = |policy: &dyn EndpointSelectionPolicy| -> Vec<String> {
      policy
        .rank_candidates(&node(1), &candidates)
        .into_iter()
        .map(|index| candidates[index].selector().as_str().to_owned())
        .collect()
    };

    // tcp before tls before everything unpreferred (published order).
    let preference = PreferenceOrderPolicy::new(vec![
      TransportName::parse("tcp").unwrap(),
      TransportName::parse("tls").unwrap(),
    ]);
    assert_eq!(
      order_of(&preference),
      ["tcp", "tls", "wss", "custom"],
      "preferred schemes rank by list position; unpreferred keep published order"
    );

    // No preference: exactly published order (the cold shape).
    assert_eq!(
      order_of(&PreferenceOrderPolicy::default()),
      ["wss", "tls", "tcp", "custom"]
    );

    // Through the selector: the rotation follows the ranked order.
    let selector = EndpointSelector::new(std::sync::Arc::new(preference));
    let landed: Vec<String> = (0..4)
      .map(|_| {
        selector
          .next_endpoint(&node(1), &candidates)
          .unwrap()
          .to_string()
      })
      .collect();
    assert_eq!(
      landed,
      [
        "tcp://10.0.0.1:3",
        "tls://10.0.0.1:2",
        "wss://10.0.0.1:1",
        "custom://10.0.0.1:4",
      ]
    );
  }

  /// Outcome-weighted is published order cold, reorders after observed
  /// failures (a failing scheme sinks below every unobserved one), and
  /// recovers as delivered dials decay the failure EWMA.
  #[test]
  fn outcome_weighted_falls_back_cold_then_reorders_after_observations() {
    let policy = OutcomeWeightedPolicy::default();
    let candidates = vec![endpoint("wss://10.0.0.1:1"), endpoint("tcp://10.0.0.1:2")];
    let order_of = |policy: &dyn EndpointSelectionPolicy| -> Vec<String> {
      policy
        .rank_candidates(&node(1), &candidates)
        .into_iter()
        .map(|index| candidates[index].selector().as_str().to_owned())
        .collect()
    };

    // Cold start: no observations, exactly published order.
    assert_eq!(order_of(&policy), ["wss", "tcp"]);

    // Sustained wss failures sink it below the unobserved tcp scheme.
    for _ in 0..12 {
      policy.observe_outcome(
        &TransportName::parse("wss").unwrap(),
        DialObservation::Failed,
      );
    }
    assert_eq!(order_of(&policy), ["tcp", "wss"]);

    // Delivered dials decay the failure EWMA back down; the scheme stays
    // observed, and once a tcp failure joins the observed set the two
    // sort by outcome: healthier wss first, failing tcp second.
    for _ in 0..20 {
      policy.observe_outcome(
        &TransportName::parse("wss").unwrap(),
        DialObservation::Delivered(std::time::Duration::from_micros(400)),
      );
    }
    policy.observe_outcome(
      &TransportName::parse("tcp").unwrap(),
      DialObservation::Failed,
    );
    assert_eq!(order_of(&policy), ["wss", "tcp"]);
  }

  /// The fail-closed filter: an ordering that names indices outside the
  /// validated candidate set never surfaces an unvalidated endpoint — the
  /// garbage index is dropped, and an ordering with nothing valid left
  /// skips the dial entirely.
  #[test]
  fn invalid_candidate_indices_are_never_selected() {
    let candidates = vec![endpoint("wss://10.0.0.1:1"), endpoint("tcp://10.0.0.1:2")];
    let member = node(1);

    // Out-of-range index dropped, valid ordering preserved: the first
    // dial lands on index 1 (the valid head of the ordering).
    let selector = EndpointSelector::new(std::sync::Arc::new(FixedOrder(vec![7, 1, 0])));
    assert_eq!(
      selector
        .next_endpoint(&member, &candidates)
        .unwrap()
        .to_string(),
      "tcp://10.0.0.1:2"
    );
    assert_eq!(
      selector
        .next_endpoint(&member, &candidates)
        .unwrap()
        .to_string(),
      "wss://10.0.0.1:1"
    );

    // Nothing valid left: no dial.
    let empty = EndpointSelector::new(std::sync::Arc::new(FixedOrder(vec![9, 42])));
    assert!(empty.next_endpoint(&member, &candidates).is_none());
  }
}
