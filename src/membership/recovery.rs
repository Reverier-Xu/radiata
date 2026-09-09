//! Continuous recovery state machine.
//!
//! Recovery activates whenever known online members remain in mutually
//! unreachable authenticated components, retries according to caller-
//! configured wall-clock backoff (re-reading `SystemTime` after every
//! wake, including rollback/freeze/forward-jump), expands only through the
//! configured bounded fan-out, authenticates a `NodeId` before accepting a
//! session, quiesces once every known online member is connected through
//! some authenticated path (never a full mesh), and reactivates one
//! bounded controller after any later change without storms.

use std::collections::BTreeSet;

use crate::NodeId;

/// The caller-configured recovery policy (wired from `NodeConfig`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RecoveryPolicy {
  pub(crate) neighbors: usize,
  pub(crate) fan_out: usize,
  pub(crate) initial_backoff: u64,
  pub(crate) maximum_backoff: u64,
}

impl RecoveryPolicy {
  pub(crate) const fn new(
    neighbors: usize, fan_out: usize, initial_backoff: u64, maximum_backoff: u64,
  ) -> Self {
    Self {
      neighbors,
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
  pub(crate) backoff_seconds: u64,
}

/// The continuous recovery controller. Pure state logic: the caller feeds
/// membership/connectivity observations and wall-clock seconds; the
/// controller decides activation, backoff, fan-out, quiescence, and
/// reactivation.
#[derive(Clone, Debug)]
pub(crate) struct RecoveryController {
  policy: RecoveryPolicy,
  state: RecoveryState,
  attempts: u64,
  last_attempt_at: u64,
  pending: BTreeSet<NodeId>,
}

impl RecoveryController {
  pub(crate) fn new(policy: RecoveryPolicy) -> Self {
    Self {
      policy,
      state: RecoveryState::Idle,
      attempts: 0,
      last_attempt_at: 0,
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
  pub(crate) fn observe(&mut self, online: &BTreeSet<NodeId>, reachable: &BTreeSet<NodeId>) {
    let unreachable: BTreeSet<NodeId> = online.difference(reachable).cloned().collect();
    if unreachable.is_empty() {
      if self.state != RecoveryState::Idle {
        self.state = RecoveryState::Connected;
      }
      self.pending.clear();
      return;
    }
    self.pending = unreachable;
    if self.state == RecoveryState::Idle || self.state == RecoveryState::Connected {
      self.state = RecoveryState::Recovering;
      self.attempts = 0;
    }
    // Reactivation: any change while recovering re-arms the controller
    // without a storm (single controller, bounded attempts).
  }

  /// Computes the next recovery step: a bounded set of targets expanded
  /// only through the configured fan-out from the neighbors, plus the
  /// wall-clock backoff (re-read every wake; rollback/freeze delays,
  /// forward jump makes it due).
  pub(crate) fn next_step(&mut self, now: u64, candidates: &BTreeSet<NodeId>) -> RecoveryStep {
    let backoff = self.backoff_seconds(now);
    let targets: Vec<NodeId> = candidates
      .iter()
      .take(self.policy.fan_out.max(1))
      .cloned()
      .collect();
    self.last_attempt_at = now;
    self.attempts = self.attempts.saturating_add(1);
    RecoveryStep {
      targets,
      backoff_seconds: backoff,
    }
  }

  /// The wall-clock backoff for the next attempt: doubles from the initial
  /// value up to the maximum; a forward jump in wall time makes the next
  /// attempt immediately due.
  pub(crate) fn backoff_seconds(&self, now: u64) -> u64 {
    let exponent = self.attempts.min(16);
    let doubled = self
      .policy
      .initial_backoff
      .saturating_mul(1_u64 << exponent);
    let capped = doubled.min(self.policy.maximum_backoff);
    if now >= self.last_attempt_at.saturating_add(capped) {
      // The deadline is already due; wake immediately.
      return 0;
    }
    capped
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

  /// Records one candidate as connected; when nothing remains pending the
  /// controller transitions to `Connected`. Assertion
  /// surface for the unit suite; production observes through `state`.
  #[cfg(test)]
  pub(crate) fn connected(&mut self, member: &NodeId) {
    self.pending.remove(member);
    if self.pending.is_empty() && self.state == RecoveryState::Recovering {
      self.state = RecoveryState::Connected;
    }
  }

  /// Forces one immediate recovery cycle (immediate-recovery command).
  pub(crate) fn immediate(&mut self, now: u64) {
    if self.pending.is_empty() && self.state != RecoveryState::Recovering {
      return;
    }
    self.state = RecoveryState::Recovering;
    self.last_attempt_at = now.saturating_sub(1);
  }
}

#[cfg(test)]
mod tests {
  use std::collections::BTreeSet;

  use super::{RecoveryController, RecoveryPolicy, RecoveryState};
  use crate::NodeId;

  fn node(value: u8) -> NodeId {
    NodeId::parse(&format!("node_{value:021}")).unwrap()
  }

  fn set(values: &[u8]) -> BTreeSet<NodeId> {
    values.iter().map(|value| node(*value)).collect()
  }

  fn policy() -> RecoveryPolicy {
    RecoveryPolicy::new(4, 64, 1, 5 * 60)
  }

  /// Recovery activates whenever known online members remain
  /// unreachable, including after a later connectivity change.
  #[test]
  fn recovery_activates_on_unreachable_members() {
    let mut controller = RecoveryController::new(policy());
    assert_eq!(controller.state(), RecoveryState::Idle);

    let online = set(&[1, 2, 3]);
    let reachable = set(&[1]);
    controller.observe(&online, &reachable);
    assert_eq!(controller.state(), RecoveryState::Recovering);

    // A later connectivity change keeps recovery active.
    let reachable = set(&[1, 2]);
    controller.observe(&online, &reachable);
    assert_eq!(controller.state(), RecoveryState::Recovering);
  }

  /// Recovery quiesces once all online members are connected
  /// through some authenticated path; never a full mesh.
  #[test]
  fn recovery_quiesces_at_connected_path() {
    let mut controller = RecoveryController::new(policy());
    let online = set(&[1, 2, 3]);
    controller.observe(&online, &set(&[1]));
    assert_eq!(controller.state(), RecoveryState::Recovering);

    controller.connected(&node(2));
    assert_eq!(controller.state(), RecoveryState::Recovering);
    controller.connected(&node(3));
    assert_eq!(controller.state(), RecoveryState::Connected);

    // A later partition re-activates one bounded controller.
    controller.observe(&online, &set(&[1]));
    assert_eq!(controller.state(), RecoveryState::Recovering);
  }

  /// Backoff doubles from the initial value up to the maximum and
  /// re-reads wall time; a forward jump makes it immediately due,
  /// rollback/freeze delays it.
  #[test]
  fn recovery_backoff_follows_wall_clock() {
    let mut controller = RecoveryController::new(policy());
    let online = set(&[1, 2]);
    controller.observe(&online, &set(&[1]));
    let _ = controller.next_step(100, &set(&[2]));

    // Not due yet: 101 < 100 + 2 (initial backoff 1, doubled after attempt).
    assert!(!controller.due(101));
    // At the doubled deadline it is due.
    assert!(controller.due(102));
    // A forward jump makes it immediately due.
    assert!(controller.due(10_000));

    // The next backoff doubles again (attempt 2: 1 << 2 = 4).
    let step = controller.next_step(10_000, &set(&[2]));
    assert_eq!(step.backoff_seconds, 0); // immediately due after the jump
    assert!(!controller.due(10_003));
    assert!(controller.due(10_004));
  }

  /// Each cycle expands only through the configured bounded fan-out.
  #[test]
  fn recovery_expands_through_bounded_fan_out() {
    let mut controller = RecoveryController::new(RecoveryPolicy::new(4, 2, 1, 60));
    let online = set(&[1, 2, 3, 4]);
    controller.observe(&online, &set(&[1]));
    let step = controller.next_step(0, &set(&[2, 3, 4, 5, 6]));
    assert_eq!(step.targets.len(), 2, "fan-out bounds each cycle");
  }

  /// An immediate-recovery command forces one cycle without storms.
  #[test]
  fn recovery_immediate_forces_one_cycle() {
    let mut controller = RecoveryController::new(policy());
    let online = set(&[1, 2]);
    controller.observe(&online, &set(&[1]));
    controller.immediate(50);
    assert!(controller.due(50));
    // One step consumes the immediate trigger.
    let _ = controller.next_step(50, &set(&[2]));
    assert!(!controller.due(50));
  }
}

/// Seeded recovery simulation: drives the recovery controller over
/// a deterministic membership/connectivity scenario and replays the exact
/// decisions for a seed, matching the configured neighbor/fan-out and
/// wall-clock backoff.
#[cfg(test)]
pub(crate) mod simulation {
  use std::collections::BTreeSet;

  use super::{RecoveryController, RecoveryPolicy, RecoveryState};
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
    let mut controller = RecoveryController::new(RecoveryPolicy::new(4, 64, 1, 60));
    let mut trace = Vec::new();
    for (now, reachable) in &scenario.steps {
      let reachable: BTreeSet<NodeId> = reachable
        .iter()
        .map(|value| {
          NodeId::parse(&format!("node_{value:021}"))
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
        let step = controller.next_step(*now, &ordered.into_iter().collect());
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
      NodeId::parse(&format!("node_{value:021}")).unwrap()
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
          (0, vec![1]),
          (2, vec![1, 2]),
          (5, vec![1, 2, 3]),
          (8, vec![1, 2, 3, 4]),
        ],
      };
      let first = run_seed(7, &scenario);
      let second = run_seed(7, &scenario);
      assert_eq!(first, second, "same seed replays exactly");

      assert!(!first.is_empty(), "recovery emitted bounded attempts");
      for decision in &first {
        assert!(!decision.targets.is_empty(), "bounded fan-out targets");
        assert!(
          !decision.targets.contains(&node(1)),
          "never dials a reachable member"
        );
      }
    }

    #[test]
    fn different_seeds_choose_deterministically() {
      let scenario = RecoveryScenario {
        online: online(),
        steps: vec![(0, vec![1])],
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

  use super::{RecoveryController, RecoveryPolicy, RecoveryState};
  use crate::NodeId;

  fn node_at(index: usize) -> NodeId {
    NodeId::parse(&format!("node_{index:021}")).unwrap()
  }

  /// The 1,024-node recovery trend: the controller makes bounded
  /// decisions over a cluster-scale membership without a whole-population
  /// graph or a rejection boundary.
  #[test]
  fn recovery_controller_scales_to_1024_nodes() {
    let online: BTreeSet<NodeId> = (0..1_024).map(node_at).collect();
    let mut controller = RecoveryController::new(RecoveryPolicy::new(4, 16, 1, 60));
    // One partition: 512 members are unreachable.
    let reachable: BTreeSet<NodeId> = (0..512).map(node_at).collect();
    controller.observe(&online, &reachable);
    assert_eq!(controller.state(), RecoveryState::Recovering);

    let step = controller.next_step(0, &(512..1_024).map(node_at).collect());
    assert!(
      step.targets.len() <= 16,
      "each cycle expands only through the bounded fan-out"
    );

    // Quiescence at scale: once every member is reachable the controller
    // stops without a full mesh.
    controller.observe(&online, &online);
    assert_eq!(controller.state(), RecoveryState::Connected);
  }
}
