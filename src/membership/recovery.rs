//! Continuous recovery state machine.
//!
//! Recovery guards the deployment contract "any one route suffices": a
//! node with at least one authenticated path is connected and never
//! expands its topology, while a fully isolated node retries every
//! member in its table (bounded fan-out, caller-configured wall-clock
//! backoff re-read from `SystemTime` after every wake, including
//! rollback/freeze/forward-jump) until any one connects. Each taken step
//! samples a ±25% uniform jitter around the base backoff from the
//! injected entropy, so devices recovering from one shared event do not
//! retry in lockstep. A `NodeId` is authenticated before a session is
//! accepted, and the single controller re-arms after any later isolation
//! without storms.

use std::collections::BTreeSet;

use crate::{NodeId, api::Entropy};

/// The jitter granularity: the sampled wait deviates from the base
/// backoff by at most one quarter in either direction (±25% uniform).
const JITTER_QUARTER: u64 = 4;

/// The caller-configured recovery policy (wired from `NodeConfig`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RecoveryPolicy {
  pub(crate) fan_out: usize,
  pub(crate) initial_backoff: u64,
  pub(crate) maximum_backoff: u64,
}

impl RecoveryPolicy {
  pub(crate) const fn new(fan_out: usize, initial_backoff: u64, maximum_backoff: u64) -> Self {
    Self {
      fan_out,
      initial_backoff,
      maximum_backoff,
    }
  }
}

/// The recovery state machine state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecoveryState {
  /// Everything reachable; no recovery scheduled.
  Idle,
  /// Recovery is active and retrying unreachable components.
  Recovering,
  /// Every known online member has an authenticated path.
  Connected,
}

/// One recovery cycle decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RecoveryStep {
  pub(crate) targets: Vec<NodeId>,
  /// The wall-clock wait the just-taken attempt scheduled (the jittered
  /// next doubling's base), and `0` when the deadline is already due
  /// (the caller wakes immediately).
  pub(crate) backoff_seconds: u64,
}

/// The continuous recovery controller. Pure state logic: the caller
/// feeds membership/connectivity observations, wall-clock seconds, and
/// the entropy the jitter samples; the controller decides activation,
/// backoff, fan-out, quiescence, and reactivation.
#[derive(Clone, Debug)]
pub(crate) struct RecoveryController {
  policy: RecoveryPolicy,
  state: RecoveryState,
  attempts: u64,
  last_attempt_at: u64,
  /// The jittered wait the just-taken step sampled, stable between
  /// wakes: every due-check inside one schedule compares against the
  /// same sampled value. `None` before the first step of a schedule.
  scheduled_backoff: Option<u64>,
  pending: BTreeSet<NodeId>,
}

impl RecoveryController {
  pub(crate) fn new(policy: RecoveryPolicy) -> Self {
    Self {
      policy,
      state: RecoveryState::Idle,
      attempts: 0,
      last_attempt_at: 0,
      scheduled_backoff: None,
      pending: BTreeSet::new(),
    }
  }

  pub(crate) const fn state(&self) -> RecoveryState {
    self.state
  }

  /// The count of known online members still pending an authenticated
  /// path (the unreachable set the controller is healing).
  pub(crate) fn pending_count(&self) -> usize {
    self.pending.len()
  }

  /// The wall-clock seconds of the next scheduled attempt, when recovery
  /// is active; `None` when idle or connected.
  pub(crate) fn next_attempt_seconds(&self, now: u64) -> Option<u64> {
    if self.state != RecoveryState::Recovering {
      return None;
    }
    Some(
      self
        .last_attempt_at
        .saturating_add(self.backoff_seconds(now)),
    )
  }

  /// Feeds one observation of which members are reachable and which are
  /// known online. Recovery activates when known online members remain
  /// unreachable; it quiesces when all are connected through some
  /// authenticated path.
  pub(crate) fn observe(&mut self, known_members: &BTreeSet<NodeId>, reachable: &BTreeSet<NodeId>) {
    let unreachable: BTreeSet<NodeId> = known_members.difference(reachable).cloned().collect();
    if reachable.is_empty() {
      if known_members.is_empty() {
        // No members known yet: nothing to recover toward.
        self.state = RecoveryState::Idle;
        self.pending.clear();
        self.scheduled_backoff = None;
        return;
      }
      // Fully isolated: every table member is a retry candidate, and the
      // controller retries until any one connects.
      self.pending = unreachable;
      if self.state != RecoveryState::Recovering {
        self.state = RecoveryState::Recovering;
        self.attempts = 0;
        self.scheduled_backoff = None;
      }
      // Reactivation while isolated re-arms the controller without a
      // storm (single controller, bounded attempts).
      return;
    }
    // At least one authenticated path exists: the "any one route"
    // deployment contract is satisfied, so recovery quiesces instead of
    // expanding the topology. The unreachable remainder stays visible as
    // the pending diagnostic count.
    self.pending = unreachable;
    if self.state != RecoveryState::Connected {
      self.state = RecoveryState::Connected;
      self.attempts = 0;
      self.scheduled_backoff = None;
    }
  }

  /// Computes the next recovery step: a bounded set of targets within the
  /// configured fan-out, plus the wall-clock wait this attempt schedules —
  /// the next doubling's base with the sampled ±25% jitter applied
  /// (rollback/freeze delays it, a forward jump makes it due and the
  /// returned wait collapses to zero). The first attempt runs immediately
  /// upon activation, so the first retry waits the doubled initial.
  pub(crate) fn next_step(
    &mut self, now: u64, candidates: &BTreeSet<NodeId>, entropy: &dyn Entropy,
  ) -> RecoveryStep {
    let targets: Vec<NodeId> = candidates
      .iter()
      .take(self.policy.fan_out.max(1))
      .cloned()
      .collect();
    self.attempts = self.attempts.saturating_add(1);
    let sampled = self.sample_jitter(self.base_seconds(), entropy);
    let due_already = now >= self.last_attempt_at.saturating_add(sampled);
    self.last_attempt_at = now;
    self.scheduled_backoff = Some(sampled);
    RecoveryStep {
      targets,
      backoff_seconds: if due_already { 0 } else { sampled },
    }
  }

  /// The deterministic base backoff: doubles from the initial value up
  /// to the maximum.
  fn base_seconds(&self) -> u64 {
    let exponent = self.attempts.min(16);
    self
      .policy
      .initial_backoff
      .saturating_mul(1_u64 << exponent)
      .min(self.policy.maximum_backoff)
  }

  /// Samples the ±25% uniform jitter around `base` from the injected
  /// entropy: devices recovering from one power or network event share
  /// identical base sequences and would otherwise slam the far end's
  /// admission limits in lockstep. An entropy fault degrades to the
  /// unjittered base — recovery stays best-effort, and the fault is
  /// already visible wherever the entropy surfaces it.
  fn sample_jitter(&self, base: u64, entropy: &dyn Entropy) -> u64 {
    let spread = base / JITTER_QUARTER;
    if spread == 0 {
      // Sub-second bases have no whole-second spread to sample.
      return base;
    }
    let mut word = [0_u8; 8];
    if entropy.fill(&mut word).is_err() {
      return base;
    }
    let range = 2 * spread;
    let offset = if range == u64::MAX {
      u64::from_be_bytes(word)
    } else {
      ((u128::from(u64::from_be_bytes(word)) * u128::from(range + 1)) >> 64) as u64
    };
    (base - spread).saturating_add(offset)
  }

  /// The wall-clock seconds of the currently scheduled wait: the jittered
  /// value the just-taken step sampled, or the deterministic base before
  /// the first step of a schedule. A deadline already due under `now`
  /// collapses to zero.
  pub(crate) fn backoff_seconds(&self, now: u64) -> u64 {
    let scheduled = self
      .scheduled_backoff
      .unwrap_or_else(|| self.base_seconds());
    if now >= self.last_attempt_at.saturating_add(scheduled) {
      // The deadline is already due; wake immediately.
      return 0;
    }
    scheduled
  }

  /// Whether the controller should run a cycle now (deadline due under the
  /// current wall time; a forward jump makes it immediately due).
  pub(crate) fn due(&self, now: u64) -> bool {
    if self.state != RecoveryState::Recovering {
      return false;
    }
    now
      >= self
        .last_attempt_at
        .saturating_add(self.backoff_seconds(now))
  }

  /// Forces one immediate recovery cycle (immediate-recovery command).
  /// Forces one immediate recovery cycle without storms: only an active
  /// recovery is pulled forward. A connected node satisfies the "any one
  /// route" contract already, so forcing a cycle there would expand the
  /// topology — exactly what recovery must not do.
  pub(crate) fn immediate(&mut self, now: u64) {
    if self.state != RecoveryState::Recovering {
      return;
    }
    self.last_attempt_at = now.saturating_sub(1);
  }
}

/// A deterministic entropy whose every fill yields the same word: the
/// jitter sample is pinned, so backoff assertions and seeded replays
/// stay exact.
#[cfg(test)]
#[derive(Debug)]
struct WordEntropy(u64);

#[cfg(test)]
impl Entropy for WordEntropy {
  fn fill(&self, output: &mut [u8]) -> crate::Result<()> {
    let len = output.len();
    let word = self.0.to_be_bytes();
    output.copy_from_slice(&word[(word.len() - len)..]);
    Ok(())
  }
}

/// An entropy that fails like a faulty provider: the jitter must
/// degrade to the unjittered base instead of failing recovery.
#[cfg(test)]
#[derive(Debug)]
struct FailingEntropy;

#[cfg(test)]
impl Entropy for FailingEntropy {
  fn fill(&self, _output: &mut [u8]) -> crate::Result<()> {
    Err(crate::Error::provider(
      crate::ProviderErrorKind::Io,
      crate::ProviderErrorContext::Entropy,
    ))
  }
}

#[cfg(test)]
mod tests {
  use std::collections::BTreeSet;

  use super::{FailingEntropy, RecoveryController, RecoveryPolicy, RecoveryState, WordEntropy};
  use crate::NodeId;

  fn node(value: u8) -> NodeId {
    NodeId::parse(&format!("node-{value:021}")).unwrap()
  }

  fn set(values: &[u8]) -> BTreeSet<NodeId> {
    values.iter().map(|value| node(*value)).collect()
  }

  fn policy() -> RecoveryPolicy {
    RecoveryPolicy::new(64, 1, 5 * 60)
  }

  /// Recovery activates only on full isolation (no authenticated path
  /// at all); partial unreachability stays connected — the "any one
  /// route" contract — with the unreachable remainder as diagnostics.
  #[test]
  fn recovery_activates_only_on_full_isolation() {
    let mut controller = RecoveryController::new(policy());
    assert_eq!(controller.state(), RecoveryState::Idle);

    let online = set(&[1, 2, 3]);
    // A known table but no sessions at all: recovery activates.
    controller.observe(&online, &set(&[]));
    assert_eq!(controller.state(), RecoveryState::Recovering);

    // Any one route connects: recovery quiesces without a full mesh.
    controller.observe(&online, &set(&[1]));
    assert_eq!(controller.state(), RecoveryState::Connected);
    assert_eq!(
      controller.pending_count(),
      2,
      "the unreachable remainder stays visible"
    );

    // Isolated again: the controller re-arms.
    controller.observe(&online, &set(&[]));
    assert_eq!(controller.state(), RecoveryState::Recovering);

    // An empty member table is idle, never recovering.
    controller.observe(&set(&[]), &set(&[]));
    assert_eq!(controller.state(), RecoveryState::Idle);
  }

  /// Recovery quiesces the moment any one authenticated path exists,
  /// and re-activates when that last path is lost.
  #[test]
  fn recovery_quiesces_at_any_one_path() {
    let mut controller = RecoveryController::new(policy());
    let online = set(&[1, 2, 3]);
    controller.observe(&online, &set(&[]));
    assert_eq!(controller.state(), RecoveryState::Recovering);

    // One path connects: recovery stops (never a full mesh).
    controller.observe(&online, &set(&[1]));
    assert_eq!(controller.state(), RecoveryState::Connected);

    // The last path is lost: one bounded controller re-arms.
    controller.observe(&online, &set(&[]));
    assert_eq!(controller.state(), RecoveryState::Recovering);
  }

  /// Backoff doubles from the initial value up to the maximum and
  /// re-reads wall time; a forward jump makes it immediately due,
  /// rollback/freeze delays it. The pinned jitter word samples the base
  /// exactly, so the doubling stays observable at the fourth-second step.
  #[test]
  fn recovery_backoff_follows_wall_clock() {
    // Samples offset one out of the [0, 2] range: the jittered wait
    // equals the unjittered base whenever the spread is a whole second.
    let entropy = WordEntropy(0xAAAA_AAAA_AAAA_AAAA);
    let mut controller = RecoveryController::new(policy());
    let online = set(&[1, 2]);
    controller.observe(&online, &set(&[]));
    let _ = controller.next_step(100, &set(&[2]), &entropy);

    // Not due yet: 101 < 100 + 2 (initial backoff 1, doubled after attempt).
    assert!(!controller.due(101));
    // At the doubled deadline it is due.
    assert!(controller.due(102));
    // A forward jump makes it immediately due.
    assert!(controller.due(10_000));

    // The next backoff doubles again (attempt 2: 1 << 2 = 4).
    let step = controller.next_step(10_000, &set(&[2]), &entropy);
    assert_eq!(step.backoff_seconds, 0); // immediately due after the jump
    assert!(!controller.due(10_003));
    assert!(controller.due(10_004));
  }

  /// The sampled jitter stays inside ±25% of the base and decorrelates
  /// two devices that share one base sequence: different entropy words
  /// produce different waits for the same state.
  #[test]
  fn jitter_stays_bounded_and_decorrelates_identical_sequences() {
    let base_policy = RecoveryPolicy::new(4, 8, 8);
    let online = set(&[1, 2]);
    let sampled = |word: u64| {
      let mut controller = RecoveryController::new(base_policy);
      controller.observe(&online, &set(&[]));
      let step = controller.next_step(0, &online, &WordEntropy(word));
      (step.backoff_seconds, controller)
    };

    // Word 0 samples the low end (8 - 2), u64::MAX the high end (8 + 2).
    let (low, controller_low) = sampled(0);
    let (high, _) = sampled(u64::MAX);
    assert_eq!(low, 6);
    assert_eq!(high, 10);

    // Every sampled word stays within one quarter of the base.
    for word in [1, 7, 123, 0xDEAD_BEEF, u64::MAX - 1] {
      let (value, _) = sampled(word);
      assert!(
        (6..=10).contains(&value),
        "jitter word {word} sampled {value}, outside ±25% of 8"
      );
    }

    // The sampled schedule is stable across due checks: the wait the
    // step announced is the wait the controller enforces.
    assert!(!controller_low.due(low - 1));
    assert!(controller_low.due(low));
  }

  /// An entropy fault degrades to the unjittered base instead of
  /// failing the recovery step.
  #[test]
  fn an_entropy_fault_degrades_to_the_unjittered_base() {
    let mut controller = RecoveryController::new(RecoveryPolicy::new(4, 8, 8));
    let online = set(&[1, 2]);
    controller.observe(&online, &set(&[]));
    let step = controller.next_step(0, &online, &FailingEntropy);
    assert_eq!(step.backoff_seconds, 8);
  }

  /// Each cycle expands only through the configured bounded fan-out.
  #[test]
  fn recovery_expands_through_bounded_fan_out() {
    let entropy = WordEntropy(0);
    let mut controller = RecoveryController::new(RecoveryPolicy::new(2, 1, 60));
    let online = set(&[1, 2, 3, 4]);
    controller.observe(&online, &set(&[]));
    let step = controller.next_step(0, &set(&[2, 3, 4, 5, 6]), &entropy);
    assert_eq!(step.targets.len(), 2, "fan-out bounds each cycle");
  }

  /// An immediate-recovery command forces one cycle without storms.
  #[test]
  fn recovery_immediate_forces_one_cycle() {
    let entropy = WordEntropy(0);
    let mut controller = RecoveryController::new(policy());
    let online = set(&[1, 2]);
    controller.observe(&online, &set(&[]));
    controller.immediate(50);
    assert!(controller.due(50));
    // One step consumes the immediate trigger.
    let _ = controller.next_step(50, &set(&[2]), &entropy);
    assert!(!controller.due(50));
  }
}

/// Seeded recovery simulation: drives the recovery controller over
/// a deterministic membership/connectivity scenario and replays the exact
/// decisions for a seed, matching the configured fan-out and
/// wall-clock backoff.
#[cfg(test)]
pub(crate) mod simulation {
  use std::collections::BTreeSet;

  use super::{RecoveryController, RecoveryPolicy, RecoveryState, WordEntropy};
  use crate::NodeId;

  /// The deterministic scenario script: (wall seconds, reachable set).
  pub(crate) struct RecoveryScenario {
    pub(crate) online: BTreeSet<NodeId>,
    pub(crate) steps: Vec<(u64, Vec<u8>)>,
  }

  /// One replayable recovery decision.
  #[derive(Clone, Debug, Eq, PartialEq)]
  pub(crate) struct RecoveryDecision {
    pub(crate) at_seconds: u64,
    pub(crate) targets: Vec<NodeId>,
    pub(crate) state: RecoveryState,
  }

  /// Runs one seeded scenario and returns the exact decision trace. The
  /// seed selects the deterministic order of the *unreachable* members
  /// only; reachable members are never dialed.
  pub(crate) fn run_seed(seed: u64, scenario: &RecoveryScenario) -> Vec<RecoveryDecision> {
    let mut controller = RecoveryController::new(RecoveryPolicy::new(64, 1, 60));
    let mut trace = Vec::new();
    for (now, reachable) in &scenario.steps {
      let reachable: BTreeSet<NodeId> = reachable
        .iter()
        .map(|value| {
          NodeId::parse(&format!("node-{value:021}"))
            .unwrap_or_else(|_| unreachable!("scenario node text"))
        })
        .collect();
      controller.observe(&scenario.online, &reachable);
      if controller.state() == RecoveryState::Recovering && controller.due(*now) {
        // The candidate order is a pure function of the seed and the
        // current unreachable set, so replays are exact.
        let unreachable: Vec<NodeId> = scenario.online.difference(&reachable).cloned().collect();
        let offset = (seed % unreachable.len().max(1) as u64) as usize;
        let mut ordered = unreachable.clone();
        ordered.sort();
        ordered.rotate_left(offset);
        let step = controller.next_step(*now, &ordered.into_iter().collect(), &WordEntropy(seed));
        trace.push(RecoveryDecision {
          at_seconds: *now,
          targets: step.targets,
          state: controller.state(),
        });
      }
    }
    trace
  }

  #[cfg(test)]
  mod tests {
    use std::collections::BTreeSet;

    use super::{RecoveryScenario, run_seed};
    use crate::NodeId;

    fn node(value: u8) -> NodeId {
      NodeId::parse(&format!("node-{value:021}")).unwrap()
    }

    fn online() -> BTreeSet<NodeId> {
      [1_u8, 2, 3, 4].into_iter().map(node).collect()
    }

    /// A seeded simulation replays the same decisions for the same seed and
    /// reaches connected-path connectivity; recovery stops at
    /// reachability, not a full mesh.
    #[test]
    fn seeded_recovery_replays_and_quiesces() {
      let scenario = RecoveryScenario {
        online: online(),
        steps: vec![
          (0, vec![]),        // fully isolated: dial
          (2, vec![]),        // still isolated: next backoff step
          (5, vec![1, 2, 3]), // any one route: quiesce
          (8, vec![]),        // isolated again: re-arm
        ],
      };
      let first = run_seed(7, &scenario);
      let second = run_seed(7, &scenario);
      assert_eq!(first, second, "same seed replays exactly");

      assert!(!first.is_empty(), "recovery emitted bounded attempts");
      for decision in &first {
        assert!(!decision.targets.is_empty(), "bounded fan-out targets");
        assert!(
          decision
            .targets
            .iter()
            .all(|target| scenario.online.contains(target)),
          "only table members are dialled"
        );
      }
    }

    #[test]
    fn different_seeds_choose_deterministically() {
      let scenario = RecoveryScenario {
        online: online(),
        steps: vec![(0, vec![])],
      };
      let a = run_seed(3, &scenario);
      let b = run_seed(3, &scenario);
      assert_eq!(a, b);
    }
  }
}

#[cfg(test)]
mod scale_tests {
  use std::collections::BTreeSet;

  use super::{RecoveryController, RecoveryPolicy, RecoveryState, WordEntropy};
  use crate::NodeId;

  fn node_at(index: usize) -> NodeId {
    NodeId::parse(&format!("node-{index:021}")).unwrap()
  }

  fn set(values: &[usize]) -> BTreeSet<NodeId> {
    values.iter().map(|value| node_at(*value)).collect()
  }

  /// The 1,024-node recovery trend: the controller makes bounded
  /// decisions over a cluster-scale membership without a whole-population
  /// graph or a rejection boundary.
  #[test]
  fn recovery_controller_scales_to_1024_nodes() {
    let online: BTreeSet<NodeId> = (0..1_024).map(node_at).collect();
    let mut controller = RecoveryController::new(RecoveryPolicy::new(16, 1, 60));
    // Full isolation at cluster scale: every member is a retry candidate.
    controller.observe(&online, &set(&[]));
    assert_eq!(controller.state(), RecoveryState::Recovering);

    let step = controller.next_step(0, &online, &WordEntropy(0));
    assert!(
      step.targets.len() <= 16,
      "each cycle expands only through the bounded fan-out"
    );

    // Quiescence at scale: any one route connects the controller.
    controller.observe(&online, &set(&[1]));
    assert_eq!(controller.state(), RecoveryState::Connected);
  }
}
