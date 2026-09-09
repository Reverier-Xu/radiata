use std::{collections::BTreeSet, time::Duration};

use crate::{Error, FeatureTag, Result};

#[derive(Debug)]
pub struct NodeConfig {
  anti_entropy_interval: Duration,
  recovery: RecoveryConfig,
  session_queue_messages: usize,
  // The summed encoded-byte budget of one session's outbound frame
  // queue.
  session_queue_bytes: usize,
  // A session with no authenticated traffic or owned in-flight work for
  // this long closes on host wall time. Zero disables.
  session_idle_timeout: Duration,
  // The keepalive interval and the deadline after which a peer missing a
  // keepalive result is closed. Zero disables keepalive.
  keepalive_interval: Duration,
  keepalive_timeout: Duration,
  // Caller-selected packet parser limits: depth, collection items,
  // and frame bytes bound every packet-body decode allocation.
  parser_limits: ParserLimits,
  trace_metadata_limits: TraceMetadataLimits,
  route_policy: Option<crate::QualifiedTag>,
  receipt_retention: Duration,
  required_features: BTreeSet<FeatureTag>,
}

impl NodeConfig {
  pub fn new() -> Self {
    Self::default()
  }

  pub fn with_anti_entropy_interval(mut self, value: Duration) -> Result<Self> {
    ensure_nonzero_duration(value, "anti-entropy interval")?;
    self.anti_entropy_interval = value;
    Ok(self)
  }

  pub fn with_recovery_policy(mut self, value: RecoveryConfig) -> Result<Self> {
    self.recovery = value;
    Ok(self)
  }

  pub fn with_session_queue_limits(mut self, messages: usize, bytes: usize) -> Result<Self> {
    ensure_nonzero(messages, "session queue messages")?;
    ensure_nonzero(bytes, "session queue bytes")?;
    self.session_queue_messages = messages;
    self.session_queue_bytes = bytes;
    Ok(self)
  }

  /// Sets the session liveness policy. A session with no authenticated
  /// traffic or owned in-flight work for `idle_timeout` closes, and a peer
  /// missing a keepalive result for `keepalive_timeout` closes. All three
  /// values zero disable the policy; otherwise `idle_timeout` or
  /// `keepalive_interval` must be nonzero, and a configured keepalive
  /// requires `keepalive_interval > 0` with
  /// `keepalive_timeout > keepalive_interval`.
  pub fn with_session_liveness(
    mut self, idle_timeout: Duration, keepalive_interval: Duration, keepalive_timeout: Duration,
  ) -> Result<Self> {
    // A configured keepalive is always the ordered pair interval <
    // timeout: an interval without a deadline, a deadline without an
    // interval, or a deadline inside the interval would silently disable
    // or immediately fire the peer-missed close.
    let keepalive_configured = !keepalive_interval.is_zero() || !keepalive_timeout.is_zero();
    if keepalive_configured
      && (keepalive_interval.is_zero()
        || keepalive_timeout.is_zero()
        || keepalive_timeout <= keepalive_interval)
    {
      return Err(Error::invalid_input("session liveness policy"));
    }
    self.session_idle_timeout = idle_timeout;
    self.keepalive_interval = keepalive_interval;
    self.keepalive_timeout = keepalive_timeout;
    Ok(self)
  }

  /// Sets the parser limits: every packet-frame decode enforces them.
  pub fn with_parser_limits(mut self, value: ParserLimits) -> Result<Self> {
    self.parser_limits = value;
    Ok(self)
  }

  pub fn with_trace_metadata_limits(mut self, value: TraceMetadataLimits) -> Result<Self> {
    self.trace_metadata_limits = value;
    Ok(self)
  }

  /// Selects the node's next-hop routing policy tag: when a
  /// routed packet's destination is not directly connected, the tag
  /// resolves in the extension registry and the registered policy picks
  /// the single next hop. Without a tag the node forwards only to a
  /// directly connected destination and fails closed otherwise.
  pub fn with_route_policy(mut self, tag: crate::QualifiedTag) -> Self {
    self.route_policy = Some(tag);
    self
  }

  pub fn with_receipt_retention(mut self, value: Duration) -> Result<Self> {
    ensure_nonzero_duration(value, "receipt retention")?;
    self.receipt_retention = value;
    Ok(self)
  }

  pub(crate) const fn receipt_retention(&self) -> Duration {
    self.receipt_retention
  }

  /// The anti-entropy tick interval (consumed by the membership sync
  /// driver; nonzero by construction).
  pub(crate) const fn anti_entropy_interval(&self) -> Duration {
    self.anti_entropy_interval
  }

  /// The recovery policy (consumed by the recovery controller).
  pub(crate) const fn recovery(&self) -> RecoveryConfig {
    self.recovery
  }

  pub(crate) const fn session_queue_messages(&self) -> usize {
    self.session_queue_messages
  }

  /// The summed encoded-byte budget of one session's outbound frame queue.
  pub(crate) const fn session_queue_bytes(&self) -> usize {
    self.session_queue_bytes
  }

  /// The idle deadline after which a session with no authenticated traffic
  /// or owned in-flight work closes.
  pub(crate) const fn session_idle_timeout(&self) -> Duration {
    self.session_idle_timeout
  }

  /// The keepalive interval (zero disables).
  pub(crate) const fn keepalive_interval(&self) -> Duration {
    self.keepalive_interval
  }

  /// The keepalive result deadline.
  pub(crate) const fn keepalive_timeout(&self) -> Duration {
    self.keepalive_timeout
  }

  pub(crate) const fn trace_metadata_limits(&self) -> &TraceMetadataLimits {
    &self.trace_metadata_limits
  }

  /// The packet parser limits as canonical-decoder bounds: depth, item
  /// count, and frame bytes map one-to-one onto the CBOR layer's checks.
  pub(crate) const fn parser_cbor_limits(&self) -> crate::protocol::CborLimits {
    crate::protocol::CborLimits::new(
      self.parser_limits.depth,
      self.parser_limits.collection_items as u64,
      self.parser_limits.frame_bytes,
    )
  }
  /// The node's configured next-hop routing policy tag, if any.
  pub(crate) const fn route_policy(&self) -> Option<&crate::QualifiedTag> {
    self.route_policy.as_ref()
  }

  pub(crate) const fn required_features(&self) -> &BTreeSet<FeatureTag> {
    &self.required_features
  }

  pub fn require_feature(mut self, value: FeatureTag) -> Result<Self> {
    if !self.required_features.insert(value) {
      return Err(Error::conflict("required feature"));
    }
    Ok(self)
  }
}

impl Default for NodeConfig {
  fn default() -> Self {
    Self {
      anti_entropy_interval: Duration::from_millis(250),
      recovery: RecoveryConfig::default(),
      session_queue_messages: 256,
      session_queue_bytes: 8 * 1024 * 1024,
      session_idle_timeout: Duration::from_secs(0),
      keepalive_interval: Duration::from_secs(0),
      keepalive_timeout: Duration::from_secs(0),
      parser_limits: ParserLimits::default(),
      trace_metadata_limits: TraceMetadataLimits::default(),
      route_policy: None,
      receipt_retention: Duration::from_secs(30 * 24 * 60 * 60),
      required_features: BTreeSet::new(),
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParserLimits {
  frame_bytes: usize,
  depth: usize,
  collection_items: usize,
}

impl ParserLimits {
  pub fn new(frame_bytes: usize, depth: usize, collection_items: usize) -> Result<Self> {
    ensure_nonzero(frame_bytes, "parser frame bytes")?;
    ensure_nonzero(depth, "parser depth")?;
    ensure_nonzero(collection_items, "parser collection items")?;
    Ok(Self {
      frame_bytes,
      depth,
      collection_items,
    })
  }
}

impl Default for ParserLimits {
  fn default() -> Self {
    Self {
      frame_bytes: crate::protocol::ADR0002_BODY_BYTES,
      depth: 16,
      collection_items: 1_024,
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraceMetadataLimits {
  active: usize,
  terminal: usize,
  retention: Duration,
}

impl TraceMetadataLimits {
  pub fn new(active: usize, terminal: usize, retention: Duration) -> Result<Self> {
    ensure_nonzero(active, "active trace metadata")?;
    ensure_nonzero(terminal, "terminal trace metadata")?;
    ensure_nonzero_duration(retention, "trace metadata retention")?;
    Ok(Self {
      active,
      terminal,
      retention,
    })
  }

  pub(crate) const fn active(&self) -> usize {
    self.active
  }

  /// The caller-selected terminal-record population cap, enforced by the
  /// trace retention sweep.
  pub(crate) const fn terminal(&self) -> usize {
    self.terminal
  }

  /// The caller-selected host-wall-clock retention window for terminal
  /// records.
  pub(crate) const fn retention(&self) -> Duration {
    self.retention
  }
}

impl Default for TraceMetadataLimits {
  fn default() -> Self {
    Self {
      active: 8_192,
      terminal: 262_144,
      retention: Duration::from_secs(24 * 60 * 60),
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryConfig {
  neighbors: usize,
  fan_out: usize,
  initial_backoff: Duration,
  maximum_backoff: Duration,
}

impl RecoveryConfig {
  pub fn new(
    neighbors: usize, fan_out: usize, initial_backoff: Duration, maximum_backoff: Duration,
  ) -> Result<Self> {
    ensure_nonzero(neighbors, "recovery neighbors")?;
    ensure_nonzero(fan_out, "recovery fan-out")?;
    ensure_nonzero_duration(initial_backoff, "initial recovery backoff")?;
    ensure_nonzero_duration(maximum_backoff, "maximum recovery backoff")?;
    if neighbors > fan_out || initial_backoff > maximum_backoff {
      return Err(Error::invalid_input("recovery policy"));
    }
    Ok(Self {
      neighbors,
      fan_out,
      initial_backoff,
      maximum_backoff,
    })
  }

  pub(crate) const fn neighbors(&self) -> usize {
    self.neighbors
  }

  pub(crate) const fn fan_out(&self) -> usize {
    self.fan_out
  }

  pub(crate) fn initial_backoff_seconds(&self) -> u64 {
    self.initial_backoff.as_secs().max(1)
  }

  pub(crate) fn maximum_backoff_seconds(&self) -> u64 {
    self.maximum_backoff.as_secs().max(1)
  }
}

impl Default for RecoveryConfig {
  fn default() -> Self {
    Self {
      neighbors: 4,
      fan_out: 64,
      initial_backoff: Duration::from_secs(1),
      maximum_backoff: Duration::from_secs(5 * 60),
    }
  }
}

fn ensure_nonzero(value: usize, context: &'static str) -> Result<()> {
  if value == 0 {
    return Err(Error::invalid_input(context));
  }
  Ok(())
}

fn ensure_nonzero_duration(value: Duration, context: &'static str) -> Result<()> {
  if value.is_zero() {
    return Err(Error::invalid_input(context));
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use std::time::Duration;

  use super::NodeConfig;
  use crate::ErrorKind;

  /// The liveness setter stores every accepted policy shape: fully
  /// disabled, idle-only, keepalive-only, and the idle plus ordered
  /// keepalive pair.
  #[test]
  fn session_liveness_accepts_disabled_and_valid_policies() {
    // All-zero disables the policy and matches the default.
    let disabled = NodeConfig::new()
      .with_session_liveness(Duration::ZERO, Duration::ZERO, Duration::ZERO)
      .unwrap();
    assert!(disabled.session_idle_timeout().is_zero());
    assert!(disabled.keepalive_interval().is_zero());
    assert!(disabled.keepalive_timeout().is_zero());
    assert_eq!(
      disabled.session_idle_timeout(),
      NodeConfig::new().session_idle_timeout()
    );

    let idle_only = NodeConfig::new()
      .with_session_liveness(Duration::from_secs(30), Duration::ZERO, Duration::ZERO)
      .unwrap();
    assert_eq!(idle_only.session_idle_timeout(), Duration::from_secs(30));
    assert!(idle_only.keepalive_interval().is_zero());
    assert!(idle_only.keepalive_timeout().is_zero());

    let keepalive_only = NodeConfig::new()
      .with_session_liveness(
        Duration::ZERO,
        Duration::from_secs(5),
        Duration::from_secs(15),
      )
      .unwrap();
    assert!(keepalive_only.session_idle_timeout().is_zero());
    assert_eq!(keepalive_only.keepalive_interval(), Duration::from_secs(5));
    assert_eq!(keepalive_only.keepalive_timeout(), Duration::from_secs(15));

    let both = NodeConfig::new()
      .with_session_liveness(
        Duration::from_secs(30),
        Duration::from_secs(5),
        Duration::from_secs(15),
      )
      .unwrap();
    assert_eq!(both.session_idle_timeout(), Duration::from_secs(30));
    assert_eq!(both.keepalive_interval(), Duration::from_secs(5));
    assert_eq!(both.keepalive_timeout(), Duration::from_secs(15));
  }

  /// A deadline without either driver, a keepalive without a deadline,
  /// and a deadline inside the interval are all invalid input.
  #[test]
  fn session_liveness_rejects_broken_policies() {
    let broken = [
      (Duration::ZERO, Duration::ZERO, Duration::from_secs(15)),
      (
        Duration::from_secs(30),
        Duration::ZERO,
        Duration::from_secs(15),
      ),
      (Duration::ZERO, Duration::from_secs(5), Duration::ZERO),
      (
        Duration::from_secs(30),
        Duration::from_secs(5),
        Duration::from_secs(5),
      ),
      (
        Duration::from_secs(30),
        Duration::from_secs(5),
        Duration::from_secs(4),
      ),
    ];
    for (idle_timeout, keepalive_interval, keepalive_timeout) in broken {
      let error = NodeConfig::new()
        .with_session_liveness(idle_timeout, keepalive_interval, keepalive_timeout)
        .unwrap_err();
      assert_eq!(error.kind(), ErrorKind::InvalidInput);
    }
  }
}
