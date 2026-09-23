use std::{collections::BTreeSet, time::Duration};

use crate::{Error, FeatureTag, Result};

/// The node configuration: every knob is a plain value, clonable so one
/// construction site can share a calibrated config across nodes or retry
/// a start without rebuilding it.
#[derive(Clone, Debug)]
pub struct NodeConfig {
  anti_entropy_interval: Duration,
  recovery: RecoveryConfig,
  session_queue_messages: usize,
  // The summed encoded-byte budget of one session's outbound frame
  // queue.
  session_queue_bytes: usize,
  // The wall-clock bound for one outbound transport connect (TCP dial,
  // TLS handshake, and WebSocket upgrade). Distinct from the
  // authentication deadline, which starts only after the connect
  // returns.
  dial_deadline: Duration,
  // The wall-clock bound for the full session bootstrap exchange
  // (handshake positions one through six, including the join-mode
  // admission commit and grant adoption). One cluster-wide timing
  // contract: recalibrated so a burst of joins paying slow-flash commit
  // latencies still admits its tail, and tightened only downward by
  // fast deployments (see `with_authentication_deadline`).
  authentication_deadline: Duration,
  // The acknowledgment budget one forwarded-open hop gets before the
  // attempt fails locally and the typed failure propagates (see
  // `with_relay_hop_deadline`).
  relay_hop_deadline: Duration,
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
  merge_admission: MergeAdmissionLimits,
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
  /// the single next hop. Without a tag the node relays through the
  /// built-in [`crate::routing::DefaultNextHop`] policy, so multi-hop
  /// routes work out of the box; setting a tag overrides the default.
  pub fn with_route_policy(mut self, tag: crate::QualifiedTag) -> Self {
    self.route_policy = Some(tag);
    self
  }

  /// Replaces the merge admission limits (see
  /// [`MergeAdmissionLimits`]): the limits are validated at
  /// construction, so this only stores them.
  pub fn with_merge_admission(mut self, value: MergeAdmissionLimits) -> Self {
    self.merge_admission = value;
    self
  }

  pub fn with_receipt_retention(mut self, value: Duration) -> Result<Self> {
    ensure_nonzero_duration(value, "receipt retention")?;
    self.receipt_retention = value;
    Ok(self)
  }

  /// Sets the outbound dial deadline: the bound for one transport
  /// connect (TCP dial, TLS handshake, and WebSocket upgrade). Distinct
  /// from the authentication deadline, which starts only after the
  /// connect returns.
  pub fn with_dial_deadline(mut self, value: Duration) -> Result<Self> {
    ensure_nonzero_duration(value, "dial deadline")?;
    self.dial_deadline = value;
    Ok(self)
  }

  /// Sets the authentication deadline: the wall-clock bound for the full
  /// session bootstrap exchange, including the join-mode admission
  /// commit and grant adoption (a durable fsync may cost hundreds of
  /// milliseconds on slow flash, and concurrent joins queue behind it).
  /// This constant is peer-visible — it bounds the other side's
  /// handshake too — so it is part of the cluster-wide timing contract:
  /// keep it uniform across a cluster and tighten it only for
  /// uniformly fast deployments.
  pub fn with_authentication_deadline(mut self, value: Duration) -> Result<Self> {
    ensure_nonzero_duration(value, "authentication deadline")?;
    self.authentication_deadline = value;
    Ok(self)
  }

  /// Sets the per-hop relay budget: how long one forwarded-open hop
  /// waits for its downstream acknowledgment before the attempt fails
  /// locally (the branch search continues, or the typed `Failed`
  /// surfaces upstream). Without this budget a k-hop attempt's latency
  /// is bounded only transitively, by the liveness policies of the
  /// sessions on both ends of every hop, so one hiccup at any hop
  /// stranded the whole attempt for the longest bound in the chain.
  /// With it, a k-hop attempt is bounded by `k ×` this budget.
  pub fn with_relay_hop_deadline(mut self, value: Duration) -> Result<Self> {
    ensure_nonzero_duration(value, "relay hop deadline")?;
    self.relay_hop_deadline = value;
    Ok(self)
  }

  /// The dial deadline after which one outbound transport connect fails
  /// (consumed by the supervisor's dial paths; nonzero by construction).
  pub(crate) const fn dial_deadline(&self) -> Duration {
    self.dial_deadline
  }

  /// The authentication deadline for the full session bootstrap exchange
  /// (consumed by the session driver's three timeout sites; nonzero by
  /// construction).
  pub(crate) const fn authentication_deadline(&self) -> Duration {
    self.authentication_deadline
  }

  /// The acknowledgment budget one forwarded-open hop gets (consumed by
  /// the forwarding plane's deadline tasks; nonzero by construction).
  pub(crate) const fn relay_hop_deadline(&self) -> Duration {
    self.relay_hop_deadline
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
  /// The node's effective next-hop routing policy tag: the caller-selected
  /// tag, or the built-in default policy's tag when unset (the builder
  /// registers that policy out of the box).
  pub(crate) fn route_policy(&self) -> Result<crate::QualifiedTag> {
    match &self.route_policy {
      Some(tag) => Ok(tag.clone()),
      None => crate::routing::DefaultNextHop::tag(),
    }
  }

  pub(crate) const fn required_features(&self) -> &BTreeSet<FeatureTag> {
    &self.required_features
  }

  /// The configured merge admission limits (consumed by the session
  /// driver's limiter).
  pub(crate) const fn merge_admission(&self) -> MergeAdmissionLimits {
    self.merge_admission
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
      // One second, not 250 ms: the anti-entropy cadence is a fixed
      // per-node cost paid N-wide every tick, and 64 nodes × 4 ticks/s
      // saturated a two-vcpu runner until the data plane's relay acks
      // starved (incident C). Convergence at one tick/s stays far
      // inside the sync SLOs; fast deployments may tighten it.
      anti_entropy_interval: Duration::from_secs(1),
      dial_deadline: Duration::from_secs(10),
      // 30 s, not 10 s: the deadline covers the join-mode admission
      // commit, and on slow flash one commit costs hundreds of
      // milliseconds — a few concurrent joins pushed the tail of a
      // burst past 10 s so joins failed persistently (the incident-B
      // shape). The default must be safe on the slowest supported
      // device; fast deployments tighten it, never the reverse.
      authentication_deadline: Duration::from_secs(30),
      // Five seconds per hop: long enough for a slow hop to answer,
      // short enough that a long relay attempt fails its stuck branch
      // and moves on instead of hanging to the transitive liveness
      // bound (the incident-C shape).
      relay_hop_deadline: Duration::from_secs(5),
      recovery: RecoveryConfig::default(),
      session_queue_messages: 256,
      session_queue_bytes: 8 * 1024 * 1024,
      // Enabled by default: a silently dead peer (lost partition, frozen
      // process, starved scheduler) must fail in-flight streams within a
      // bounded window instead of hanging until TCP's own retransmit
      // timeouts. A live peer's keepalive results keep both deadlines
      // refreshing, so only real silence closes. The values are the
      // cluster-wide liveness contract, calibrated for duty-cycled and
      // slow devices: a 90 s idle and a 20 s/60 s keepalive pair let a
      // deep-sleeping peer skip several pings without its sessions
      // being torn down by the faster side of a mixed cluster.
      session_idle_timeout: Duration::from_secs(90),
      keepalive_interval: Duration::from_secs(20),
      keepalive_timeout: Duration::from_secs(60),
      parser_limits: ParserLimits::default(),
      trace_metadata_limits: TraceMetadataLimits::default(),
      route_policy: None,
      receipt_retention: Duration::from_secs(30 * 24 * 60 * 60),
      required_features: BTreeSet::new(),
      merge_admission: MergeAdmissionLimits::default(),
    }
  }
}

/// The per-pool admission budgets the limiter reads out of
/// [`MergeAdmissionLimits`]: one per-source and one global token bucket
/// each.
#[derive(Clone, Copy, Debug)]
pub(crate) struct AdmissionPoolLimits {
  pub(crate) source: (u32, Duration),
  pub(crate) global: (u32, Duration),
}

/// The merge admission limits: two pools of token buckets metering the
/// authenticated session admission. **Joins** (untrusted strangers
/// carrying a credential) keep the strictest budget — a burst of 16 per
/// source per minute, 256 per node per minute. **Member reconnects**
/// (holders of a trusted binding — the self-healing path) are budgeted
/// by the cluster scale: `max(16, 4 × expected_members)` per source and
/// `max(256, 4 × expected_members)` per node per minute, so a whole
/// site reconnecting behind one address never starves its tail (the
/// incident-B shape). Tokens refill continuously at `burst / window`
/// per second.
#[derive(Clone, Copy, Debug)]
pub struct MergeAdmissionLimits {
  join_source: (u32, Duration),
  join_global: (u32, Duration),
  member_source: (u32, Duration),
  member_global: (u32, Duration),
}

impl MergeAdmissionLimits {
  /// Derives the limits for a cluster of `expected_members` nodes. The
  /// join pool stays fixed (strangers do not scale with the cluster);
  /// only the member pool grows with the expected member count.
  pub fn for_cluster(expected_members: usize) -> Result<Self> {
    ensure_nonzero(expected_members, "expected members")?;
    Ok(Self::scaled(expected_members))
  }

  fn scaled(expected_members: usize) -> Self {
    let member_burst = |floor: u32| {
      u32::try_from(expected_members.saturating_mul(4))
        .unwrap_or(u32::MAX)
        .max(floor)
    };
    let minute = Duration::from_secs(60);
    Self {
      join_source: (16, minute),
      join_global: (256, minute),
      member_source: (member_burst(16), minute),
      member_global: (member_burst(256), minute),
    }
  }

  /// Replaces the join pool's per-source and global budgets (burst
  /// tokens per window). Strangers carrying credentials: keep this the
  /// tightest budget in the node.
  pub fn with_join_pool(
    mut self, source_burst: u32, source_window: Duration, global_burst: u32,
    global_window: Duration,
  ) -> Result<Self> {
    ensure_nonzero(source_burst as usize, "join source burst")?;
    ensure_nonzero(global_burst as usize, "join global burst")?;
    ensure_nonzero_duration(source_window, "join source window")?;
    ensure_nonzero_duration(global_window, "join global window")?;
    self.join_source = (source_burst, source_window);
    self.join_global = (global_burst, global_window);
    Ok(self)
  }

  /// Replaces the member pool's per-source and global budgets (burst
  /// tokens per window). Holders of a trusted binding: this is the
  /// self-healing path and must stay the more generous pool.
  pub fn with_member_pool(
    mut self, source_burst: u32, source_window: Duration, global_burst: u32,
    global_window: Duration,
  ) -> Result<Self> {
    ensure_nonzero(source_burst as usize, "member source burst")?;
    ensure_nonzero(global_burst as usize, "member global burst")?;
    ensure_nonzero_duration(source_window, "member source window")?;
    ensure_nonzero_duration(global_window, "member global window")?;
    self.member_source = (source_burst, source_window);
    self.member_global = (global_burst, global_window);
    Ok(self)
  }

  pub(crate) fn join_pool(&self) -> AdmissionPoolLimits {
    AdmissionPoolLimits {
      source: self.join_source,
      global: self.join_global,
    }
  }

  pub(crate) fn member_pool(&self) -> AdmissionPoolLimits {
    AdmissionPoolLimits {
      source: self.member_source,
      global: self.member_global,
    }
  }
}

impl Default for MergeAdmissionLimits {
  fn default() -> Self {
    // The reference cluster scale: the defaults ship safe for the
    // 64-node deployments the chaos lane exercises, and every value is
    // overridable through `for_cluster` or the pool setters.
    Self::scaled(64)
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
      frame_bytes: crate::protocol::MAX_BODY_BYTES,
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

/// The recovery policy: bounds and cadence for the any-one-route
/// recovery plane. While fully isolated, a node retries members from its
/// table with wall-clock backoff (initial → maximum, doubling); a
/// connected node never dials. `fan_out` caps how many members one
/// recovery round dials in parallel, and the backoff pair bounds the
/// retry cadence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryConfig {
  fan_out: usize,
  initial_backoff: Duration,
  maximum_backoff: Duration,
}

impl RecoveryConfig {
  pub fn new(fan_out: usize, initial_backoff: Duration, maximum_backoff: Duration) -> Result<Self> {
    ensure_nonzero(fan_out, "recovery fan-out")?;
    ensure_nonzero_duration(initial_backoff, "initial recovery backoff")?;
    ensure_nonzero_duration(maximum_backoff, "maximum recovery backoff")?;
    if initial_backoff > maximum_backoff {
      return Err(Error::invalid_input("recovery policy"));
    }
    Ok(Self {
      fan_out,
      initial_backoff,
      maximum_backoff,
    })
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
      // Sixteen, not sixty-four: the any-one-route contract needs exactly
      // one route, and on two slow cores a sixty-four-dial burst starved
      // its own tail past the authentication deadline so every dial in
      // the burst failed and the isolated member never healed (incident
      // B). Sixteen converges in a step or two under the same
      // starvation.
      fan_out: 16,
      // Two seconds, not one: with identical backoff sequences many
      // devices recovering from one shared event retry in lockstep and
      // slam the far end's admission limits together; the sampled jitter
      // (±25%, seeded from the injected entropy) decorrelates them from
      // the first doubling on.
      initial_backoff: Duration::from_secs(2),
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
    // All-zero explicitly disables the policy.
    let disabled = NodeConfig::new()
      .with_session_liveness(Duration::ZERO, Duration::ZERO, Duration::ZERO)
      .unwrap();
    assert!(disabled.session_idle_timeout().is_zero());
    assert!(disabled.keepalive_interval().is_zero());
    assert!(disabled.keepalive_timeout().is_zero());

    // The default policy is enabled: a silently dead peer must be
    // detected within a bounded window, not TCP's own retransmit
    // timeouts, so the defaults satisfy the keepalive ordering invariant
    // and stay nonzero. The values are the slow-device-safe liveness
    // contract (90 s idle, 20 s ping, 60 s timeout — see
    // `liveness_defaults_are_the_slow_device_calibration`).
    let default = NodeConfig::new();
    assert_eq!(default.session_idle_timeout(), Duration::from_secs(90));
    assert_eq!(default.keepalive_interval(), Duration::from_secs(20));
    assert_eq!(default.keepalive_timeout(), Duration::from_secs(60));
    assert_ne!(
      disabled.session_idle_timeout(),
      default.session_idle_timeout()
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

  /// The dial deadline accepts any nonzero duration and rejects zero: a
  /// zero deadline would cancel every dial before the OS connect
  /// resolves. The authentication deadline behaves the same, and its
  /// default is the slow-device-safe 30 s calibration.
  #[test]
  fn dial_deadline_accepts_nonzero_and_rejects_zero() {
    let configured = NodeConfig::new()
      .with_dial_deadline(Duration::from_millis(250))
      .unwrap();
    assert_eq!(configured.dial_deadline(), Duration::from_millis(250));
    assert_eq!(NodeConfig::new().dial_deadline(), Duration::from_secs(10));
    let error = NodeConfig::new()
      .with_dial_deadline(Duration::ZERO)
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
  }

  /// The authentication deadline accepts any nonzero duration, rejects
  /// zero, and defaults to the 30 s calibration: the join-mode
  /// admission commit sits inside the deadline, and slow-flash commits
  /// pushed concurrent join bursts past the old 10 s value. The relay
  /// hop deadline behaves the same and defaults to 5 s per hop.
  #[test]
  fn authentication_deadline_accepts_nonzero_and_rejects_zero() {
    let configured = NodeConfig::new()
      .with_authentication_deadline(Duration::from_secs(45))
      .unwrap();
    assert_eq!(
      configured.authentication_deadline(),
      Duration::from_secs(45)
    );
    assert_eq!(
      NodeConfig::new().authentication_deadline(),
      Duration::from_secs(30)
    );
    let error = NodeConfig::new()
      .with_authentication_deadline(Duration::ZERO)
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
  }

  /// The relay hop deadline accepts any nonzero duration, rejects zero,
  /// and defaults to 5 s per hop.
  #[test]
  fn relay_hop_deadline_accepts_nonzero_and_rejects_zero() {
    let configured = NodeConfig::new()
      .with_relay_hop_deadline(Duration::from_secs(9))
      .unwrap();
    assert_eq!(configured.relay_hop_deadline(), Duration::from_secs(9));
    assert_eq!(
      NodeConfig::new().relay_hop_deadline(),
      Duration::from_secs(5)
    );
    let error = NodeConfig::new()
      .with_relay_hop_deadline(Duration::ZERO)
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
  }

  /// The library ships exactly one profile — the defaults — and it must
  /// be safe on the slowest supported device (the mixed-cluster rule:
  /// timing constants are peer-visible, so there is no second, named
  /// low-power profile). Every recalibrated value traces to a
  /// transport-chaos incident or a slow-device bound.
  #[test]
  fn liveness_defaults_are_the_slow_device_calibration() {
    let config = NodeConfig::new();
    // Incident C: 64 nodes x 4 anti-entropy ticks/s starved a two-vcpu
    // runner's data plane; one tick/s keeps the O(N x interval) load
    // bounded while converging far inside the sync SLOs.
    assert_eq!(config.anti_entropy_interval(), Duration::from_secs(1));
    // Incident B, deadline half: slow-flash admission commits pushed
    // concurrent join tails past the old 10 s deadline into persistent
    // join failure.
    assert_eq!(config.authentication_deadline(), Duration::from_secs(30));
    // Duty-cycled peers skip several 20 s pings before the 60 s
    // keepalive timeout closes them, and a 90 s idle tolerates a slow
    // scheduling environment without tearing down live sessions.
    assert_eq!(config.session_idle_timeout(), Duration::from_secs(90));
    assert_eq!(config.keepalive_interval(), Duration::from_secs(20));
    assert_eq!(config.keepalive_timeout(), Duration::from_secs(60));
    // Incident B: the recovery plane's own defaults (fan-out sixteen,
    // two-second initial backoff) are asserted in the recovery
    // controller's tests; here only the ordering invariant repeats:
    assert!(config.recovery().fan_out() >= 1);
    assert!(config.recovery().maximum_backoff >= config.recovery().initial_backoff);
    // A k-hop relay attempt is bounded by k x the per-hop budget.
    assert_eq!(config.relay_hop_deadline(), Duration::from_secs(5));
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
