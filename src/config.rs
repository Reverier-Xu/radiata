use std::{collections::BTreeSet, time::Duration};

use crate::{Error, FeatureTag, Result};

/// The zero-refusal contract for every configured bound: a zero value
/// is a caller mistake, not a "disable" spelling, so every setter fails
/// typed with the value's own name. The seal covers the two bound
/// shapes a config knob takes: a plain count and a duration.
trait ZeroCheck {
  fn zero_checked(&self, name: &'static str) -> Result<()>;
}

impl ZeroCheck for usize {
  fn zero_checked(&self, name: &'static str) -> Result<()> {
    if *self == 0 {
      return Err(Error::invalid_input(name));
    }
    Ok(())
  }
}

impl ZeroCheck for u32 {
  fn zero_checked(&self, name: &'static str) -> Result<()> {
    if *self == 0 {
      return Err(Error::invalid_input(name));
    }
    Ok(())
  }
}

impl ZeroCheck for Duration {
  fn zero_checked(&self, name: &'static str) -> Result<()> {
    if self.is_zero() {
      return Err(Error::invalid_input(name));
    }
    Ok(())
  }
}

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
  trace_metadata_limits: TraceMetadataLimits,
  route_policy: Option<crate::QualifiedTag>,
  // The caller-selected endpoint-selection policy tag, if any. Resolved
  // against the extension registry once in the registration channel (the
  // effective_route_policy discipline).
  endpoint_policy: Option<crate::QualifiedTag>,
  // The caller-declared transport scheme preference list, if any. Its
  // presence selects the built-in preference-order policy at resolution
  // time; unmatched candidate schemes fall back to published order.
  endpoint_preference: Option<Vec<crate::TransportName>>,
  receipt_retention: Duration,
  // The resource removal-evidence policy: how long a signed removal
  // record stays convergence-eligible after its own timestamp, and the
  // stored-removal population cap the sweep enforces oldest-first. Both
  // halves are one policy because the reconcile plane's "reclaimed
  // knowledge" predicate must read the same window the sweep deletes
  // on — a window that drifted between them would either resurrect
  // swept rows or drop live evidence.
  resource_removal_retention: Duration,
  resource_removal_cap: usize,
  required_features: BTreeSet<FeatureTag>,
  merge_admission: MergeAdmissionLimits,
  connection_degree: usize,
  // The task manager's local-class execution-slot budget: the resource
  // writes, credentials, and maintenance kinds draw from their own
  // admission channel so their latency never queues behind a dial.
  task_reconcile_local_slots: usize,
  // The task manager's network-class execution-slot budget: the join and
  // connect dials, which can each hold a slot for a whole dial deadline.
  task_reconcile_network_slots: usize,
  // The task manager's extension-class execution-slot budget: the
  // caller-registered extension kinds, which routinely await other
  // admitted tasks through their public handle.
  task_reconcile_extension_slots: usize,
  // The task manager's controller-class execution-slot budget: the
  // core's own controllers (the retention sweeps, the checkpoint-gated
  // tombstone collection, the trigger evaluation pass).
  task_reconcile_controller_slots: usize,
}

impl NodeConfig {
  pub fn new() -> Self {
    Self::default()
  }

  /// Sets the anti-entropy tick interval. The tick's cost scales with
  /// the member table (N × interval per round cluster-wide); a cluster
  /// keeping one interval keeps its load predictable (nonzero).
  pub fn with_anti_entropy_interval(mut self, value: Duration) -> Result<Self> {
    value.zero_checked("anti-entropy interval")?;
    self.anti_entropy_interval = value;
    Ok(self)
  }

  /// Sets the recovery policy: fan-out, initial backoff, and maximum
  /// backoff for the any-one-route healing plane. A purely self-side
  /// cadence — peers observe dials, never the policy.
  pub fn with_recovery_policy(mut self, value: RecoveryConfig) -> Result<Self> {
    self.recovery = value;
    Ok(self)
  }

  /// Sets the session queue limits: the outbound frame queue's message
  /// count (also the per-session concurrent admission bound) and byte
  /// budget. Local memory and backpressure only — it never crosses the
  /// wire, so per-device scaling is safe (both nonzero).
  pub fn with_session_queue_limits(mut self, messages: usize, bytes: usize) -> Result<Self> {
    messages.zero_checked("session queue messages")?;
    bytes.zero_checked("session queue bytes")?;
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
  /// `keepalive_timeout > keepalive_interval`. These deadlines are
  /// peer-visible: keep them uniform across a cluster, or the tighter
  /// side closes sessions the looser side still holds alive.
  ///
  /// The policy is **second-granular**: the liveness observer compares
  /// second-resolution activity stamps, so a sub-second component would
  /// be silently truncated. A nonzero value below one second truncates
  /// to zero and would close every session on the observer's first tick;
  /// a fractional value (1500 ms) would silently become a different
  /// deadline. Both are rejected here instead of misbehaving later.
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
    for value in [idle_timeout, keepalive_interval, keepalive_timeout] {
      if value.subsec_nanos() != 0 {
        return Err(Error::invalid_input("session liveness policy"));
      }
    }
    self.session_idle_timeout = idle_timeout;
    self.keepalive_interval = keepalive_interval;
    self.keepalive_timeout = keepalive_timeout;
    Ok(self)
  }

  /// Sets the trace metadata budget: the bounded population of in-flight
  /// route traces, terminal records, and their retention. Purely local
  /// diagnostics — it never crosses the wire, so shrinking it per
  /// device is safe (the cost is only diagnostic depth).
  pub fn with_trace_metadata_limits(mut self, value: TraceMetadataLimits) -> Result<Self> {
    self.trace_metadata_limits = value;
    Ok(self)
  }

  /// Selects the node's next-hop routing policy tag: when a routed
  /// packet's destination is not directly connected, the tag resolves in
  /// the extension registry and the registered policy plans the route
  /// (the ordered path the packet follows). Without a tag the node plans
  /// through the built-in [`crate::routing::DefaultNextHop`] policy, so
  /// multi-hop routes work out of the box; setting a tag overrides the
  /// default.
  pub fn with_route_policy(mut self, tag: crate::QualifiedTag) -> Self {
    self.route_policy = Some(tag);
    self
  }

  /// Selects the node's endpoint-selection policy tag: the registered
  /// policy decides which of a member's published endpoints each dial
  /// lands on (recovery, degree maintenance, and bridge-probe dials
  /// alike). The tag resolves in the extension registry; without a tag
  /// the node runs the built-in published-order rotation, or the built-in
  /// preference-order policy when a scheme preference list is declared
  /// with [`NodeConfig::with_endpoint_preference`].
  pub fn with_endpoint_policy(mut self, tag: crate::QualifiedTag) -> Self {
    self.endpoint_policy = Some(tag);
    self
  }

  /// Declares the node's transport scheme preference list (e.g. `wss`
  /// before `tcp`) and selects the built-in preference-order policy for
  /// every dial plane: candidates on a preferred scheme dial first, by
  /// list position; candidates on unknown or unpreferred schemes keep
  /// their published order behind the preferred ones — the per-candidate
  /// fallback is the fail-safe, so an entry no member publishes is
  /// harmless (it simply never matches) and needs no registration
  /// knowledge here. The list must be nonempty and duplicate-free.
  /// Setting an explicit policy tag with
  /// [`NodeConfig::with_endpoint_policy`] other than the built-in
  /// preference-order policy rejects a declared list at node start (the
  /// list would silently do nothing); declaring the built-in
  /// preference-order tag carries the list.
  pub fn with_endpoint_preference(mut self, preference: Vec<crate::TransportName>) -> Result<Self> {
    if preference.is_empty() {
      return Err(Error::invalid_input("endpoint preference list"));
    }
    let mut seen = BTreeSet::new();
    for name in &preference {
      if !seen.insert(name.as_str()) {
        return Err(Error::conflict("endpoint preference entry"));
      }
    }
    self.endpoint_preference = Some(preference);
    Ok(self)
  }

  /// Replaces the merge admission limits (see
  /// [`MergeAdmissionLimits`]): the limits are validated at
  /// construction, so this only stores them.
  pub fn with_merge_admission(mut self, value: MergeAdmissionLimits) -> Self {
    self.merge_admission = value;
    self
  }

  /// Sets the connection-degree maintenance target: while the node's
  /// live authenticated session count sits below this value, a periodic
  /// maintenance tick dials uniformly random unconnected members until
  /// the target is reached. This is a maintenance target, never a hard
  /// limit — sessions above the target are never pruned by it, and
  /// below-target operation never restricts functionality (the degree
  /// gates only the status query and the maintenance cadence).
  ///
  /// Zero (the default) derives the target from the cluster size with
  /// the exact isolated-vertex connectivity formula
  /// `k(n)` = smallest `k` with `n·(1 − k/(n−1))^(n−1) ≤ −ln 0.9`,
  /// tracking the live member count as the cluster grows and shrinks.
  /// Set an explicit value for topologies the library cannot know: a
  /// single public-IP relay where one link is enough stays at `1`.
  pub fn with_connection_degree(mut self, target: usize) -> Self {
    self.connection_degree = target;
    self
  }

  /// Sets the task manager's execution-slot budgets, split by class:
  /// `local` admits the resource writes, credentials, leave, and
  /// maintenance kinds; `network` admits the join and connect dials,
  /// each of which can hold its slot for a whole dial deadline. The two
  /// channels are independent, so a fleet of wedged dials cannot starve
  /// local operations (and vice versa). Purely local admission, never
  /// peer-visible; both values must be nonzero (the local channel is
  /// the caller's latency floor, so a deployment that never dials may
  /// shrink `network` to `1` but never zero).
  ///
  /// The extension channel's budget is configured separately with
  /// [`NodeConfig::with_task_reconcile_extension_slots`].
  pub fn with_task_reconcile_slots(mut self, local: usize, network: usize) -> Result<Self> {
    local.zero_checked("local task reconcile slots")?;
    network.zero_checked("network task reconcile slots")?;
    self.task_reconcile_local_slots = local;
    self.task_reconcile_network_slots = network;
    Ok(self)
  }

  /// Sets the task manager's extension-class execution-slot budget: the
  /// caller-registered extension kinds draw from their own channel so a
  /// workflow awaiting core verbs through its handle never occupies the
  /// local capacity its own child operations need. Purely local
  /// admission, never peer-visible; the value must be nonzero.
  pub fn with_task_reconcile_extension_slots(mut self, extension: usize) -> Result<Self> {
    extension.zero_checked("extension task reconcile slots")?;
    self.task_reconcile_extension_slots = extension;
    Ok(self)
  }

  /// Sets the task manager's controller-class execution-slot budget:
  /// the core's own controllers (the retention sweeps, the
  /// checkpoint-gated tombstone collection, the trigger evaluation
  /// pass) draw from their own channel, so a backed-up controller never
  /// consumes the caller-owned local, dial, or extension budgets.
  /// Purely local admission, never peer-visible; the value must be
  /// nonzero. Completed controller passes stay observable through the
  /// task surface's bounded terminal history.
  pub fn with_task_reconcile_controller_slots(mut self, controller: usize) -> Result<Self> {
    controller.zero_checked("controller task reconcile slots")?;
    self.task_reconcile_controller_slots = controller;
    Ok(self)
  }

  pub fn with_receipt_retention(mut self, value: Duration) -> Result<Self> {
    value.zero_checked("receipt retention")?;
    self.receipt_retention = value;
    Ok(self)
  }

  /// Sets the resource removal-evidence policy: `retention` is how long
  /// a signed removal record survives after its own timestamp before the
  /// periodic sweep may drop it, and `cap` bounds the stored removal
  /// population (the oldest evict first). Live resource metadata is
  /// never evicted by either half.
  ///
  /// The window is a **cluster-wide data contract**, not a local tuning
  /// knob: it is also the basis on which a node treats a gone register
  /// key as reclaimed knowledge, so a peer running a shorter window
  /// deletes evidence a peer running a longer one still honours. Keep it
  /// uniform across a cluster; raise it when peers may be offline
  /// longer than the window (an offline peer that misses a removal
  /// inside the window can still resurrect the older live record).
  /// The window must be nonzero: a zero window would drop every removal
  /// on the first sweep. A zero `cap` means **no population cap** — the
  /// sweep keeps every removal until its own window expires.
  pub fn with_resource_removal_retention(
    mut self, retention: Duration, cap: usize,
  ) -> Result<Self> {
    retention.zero_checked("resource removal retention")?;
    self.resource_removal_retention = retention;
    self.resource_removal_cap = cap;
    Ok(self)
  }

  /// Sets the outbound dial deadline: the bound for one transport
  /// connect (TCP dial, TLS handshake, and WebSocket upgrade). The
  /// dialed peer never observes it, so per-device tuning is safe — but
  /// keep it above this device's worst-case connect plus handshake
  /// time, or every dial expires before it can succeed. Distinct from
  /// the authentication deadline, which starts only after the connect
  /// returns.
  pub fn with_dial_deadline(mut self, value: Duration) -> Result<Self> {
    value.zero_checked("dial deadline")?;
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
    value.zero_checked("authentication deadline")?;
    self.authentication_deadline = value;
    Ok(self)
  }

  /// Sets the per-hop relay budget: how long one forwarded-open hop
  /// waits for its downstream acknowledgment before the attempt fails
  /// locally (the branch search continues, or the typed `Failed`
  /// surfaces upstream). Each hop bounds its own branch and the value
  /// never crosses the wire, but uniform values keep a k-hop attempt's
  /// latency predictable at `k ×` this budget. Without a budget at all
  /// a stuck hop would hang to the transitive liveness bound of the
  /// sessions on the path.
  pub fn with_relay_hop_deadline(mut self, value: Duration) -> Result<Self> {
    value.zero_checked("relay hop deadline")?;
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

  /// The caller-selected removal-evidence retention window (consumed by
  /// the periodic sweep and by the reconcile plane's reclaimed-knowledge
  /// predicate; nonzero by construction).
  pub(crate) const fn resource_removal_retention(&self) -> Duration {
    self.resource_removal_retention
  }

  /// The caller-selected stored-removal population cap (consumed by the
  /// periodic sweep; nonzero by construction).
  pub(crate) const fn resource_removal_cap(&self) -> usize {
    self.resource_removal_cap
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
  /// The caller-selected next-hop routing policy tag, if any. This is a
  /// plain configuration read: the effective tag — this selection, or the
  /// built-in default policy's tag when unset — resolves in the
  /// registration channel (the node builder, right after the default
  /// registry pass) and the runtime reads only the resolved tag.
  pub(crate) const fn route_policy(&self) -> Option<&crate::QualifiedTag> {
    self.route_policy.as_ref()
  }

  /// The caller-selected endpoint-selection policy tag, if any. This is a
  /// plain configuration read: the effective policy — this selection, or
  /// the built-in preference-order policy when a preference list is
  /// declared, or the built-in published-order rotation otherwise —
  /// resolves in the registration channel (the node builder, right after
  /// the default registry pass) and the runtime reads only the resolved
  /// instance.
  pub(crate) const fn endpoint_policy(&self) -> Option<&crate::QualifiedTag> {
    self.endpoint_policy.as_ref()
  }

  /// The caller-declared transport scheme preference list, if any.
  /// Consumed by the registration channel's policy resolution.
  pub(crate) fn endpoint_preference(&self) -> Option<&[crate::TransportName]> {
    self.endpoint_preference.as_deref()
  }

  pub(crate) const fn required_features(&self) -> &BTreeSet<FeatureTag> {
    &self.required_features
  }

  /// The configured merge admission limits (consumed by the session
  /// driver's limiter).
  pub(crate) const fn merge_admission(&self) -> MergeAdmissionLimits {
    self.merge_admission
  }

  /// The connection-degree maintenance target (`0` = derived from the
  /// cluster size; consumed by the degree maintenance tick).
  pub(crate) const fn connection_degree(&self) -> usize {
    self.connection_degree
  }

  /// The local-class execution-slot budget consumed by the task
  /// manager's admission channel (nonzero by construction).
  pub(crate) const fn task_reconcile_local_slots(&self) -> usize {
    self.task_reconcile_local_slots
  }

  /// The network-class (join/connect dial) execution-slot budget
  /// consumed by the task manager's admission channel (nonzero by
  /// construction).
  pub(crate) const fn task_reconcile_network_slots(&self) -> usize {
    self.task_reconcile_network_slots
  }

  /// The extension-class execution-slot budget consumed by the task
  /// manager's admission channel (nonzero by construction).
  pub(crate) const fn task_reconcile_extension_slots(&self) -> usize {
    self.task_reconcile_extension_slots
  }

  /// The controller-class execution-slot budget consumed by the task
  /// manager's admission channel (nonzero by construction).
  pub(crate) const fn task_reconcile_controller_slots(&self) -> usize {
    self.task_reconcile_controller_slots
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
      // starved. Convergence at one tick/s stays far inside the sync
      // SLOs; fast deployments may tighten it.
      anti_entropy_interval: Duration::from_secs(1),
      dial_deadline: Duration::from_secs(10),
      // 30 s, not 10 s: the deadline covers the join-mode admission
      // commit, and on slow flash one commit costs hundreds of
      // milliseconds — a few concurrent joins pushed the tail of a
      // burst past 10 s so joins failed persistently. The default must
      // be safe on the slowest supported device; fast deployments tighten
      // it, never the reverse.
      authentication_deadline: Duration::from_secs(30),
      // Five seconds per hop: long enough for a slow hop to answer,
      // short enough that a long relay attempt fails its stuck branch
      // and moves on instead of hanging to the transitive liveness
      // bound.
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
      trace_metadata_limits: TraceMetadataLimits::default(),
      route_policy: None,
      endpoint_policy: None,
      endpoint_preference: None,
      receipt_retention: Duration::from_secs(30 * 24 * 60 * 60),
      // The shipped removal-evidence policy: one month of retention and
      // a quarter-million removal rows per node, the same defaults the
      // sweep carried before they became configurable.
      resource_removal_retention: crate::resource::retention::RESOURCE_REMOVAL_RETENTION,
      resource_removal_cap: crate::resource::retention::RESOURCE_REGISTER_CAP,
      required_features: BTreeSet::new(),
      merge_admission: MergeAdmissionLimits::default(),
      connection_degree: 0,
      // Two plus two: one shared semaphore of four permits would let a
      // dial hold every slot, so the split keeps that total while giving each
      // class its own channel — local work keeps a two-slot floor even while
      // every network slot sits inside a dial deadline. Deployments that dial
      // heavily may grow `network`; a deployment that never dials may shrink
      // it.
      task_reconcile_local_slots: 2,
      task_reconcile_network_slots: 2,
      task_reconcile_extension_slots: 2,
      // Four controller permits: the shipped retention set is four
      // sweeps plus the trigger evaluation pass, so a full controller
      // pass runs without stacking behind a slow sweep, while the
      // budget still bounds a pathological controller population.
      task_reconcile_controller_slots: 4,
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
/// site reconnecting behind one address never starves its tail. Tokens
/// refill continuously at `burst / window`
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
    expected_members.zero_checked("expected members")?;
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
    source_burst.zero_checked("join source burst")?;
    global_burst.zero_checked("join global burst")?;
    source_window.zero_checked("join source window")?;
    global_window.zero_checked("join global window")?;
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
    source_burst.zero_checked("member source burst")?;
    global_burst.zero_checked("member global burst")?;
    source_window.zero_checked("member source window")?;
    global_window.zero_checked("member global window")?;
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
pub struct TraceMetadataLimits {
  active: usize,
  terminal: usize,
  retention: Duration,
}

impl TraceMetadataLimits {
  pub fn new(active: usize, terminal: usize, retention: Duration) -> Result<Self> {
    active.zero_checked("active trace metadata")?;
    terminal.zero_checked("terminal trace metadata")?;
    retention.zero_checked("trace metadata retention")?;
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
///
/// The backoff pair is **second-granular**: the controller's schedule is
/// whole seconds, so a sub-second component would be silently truncated
/// (500 ms → 1 s, 1.5 s → 1 s). A fractional value is rejected at
/// construction instead of becoming a different cadence at runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryConfig {
  fan_out: usize,
  initial_backoff: Duration,
  maximum_backoff: Duration,
}

impl RecoveryConfig {
  /// Builds one recovery policy: a nonzero fan-out, a nonzero initial
  /// backoff no greater than the maximum, and both backoffs in whole
  /// seconds.
  pub fn new(fan_out: usize, initial_backoff: Duration, maximum_backoff: Duration) -> Result<Self> {
    if fan_out == 0 {
      return Err(Error::invalid_input("recovery fan-out"));
    }
    initial_backoff.zero_checked("initial recovery backoff")?;
    maximum_backoff.zero_checked("maximum recovery backoff")?;
    if initial_backoff > maximum_backoff {
      return Err(Error::invalid_input("recovery policy"));
    }
    for value in [initial_backoff, maximum_backoff] {
      if value.subsec_nanos() != 0 {
        return Err(Error::invalid_input("recovery backoff granularity"));
      }
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
      // the burst failed and the isolated member never healed. Sixteen
      // converges in a step or two under the same starvation.
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

#[cfg(test)]
mod tests {
  use std::time::Duration;

  use super::{NodeConfig, RecoveryConfig};
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

  /// The liveness policy is second-granular: a sub-second value would
  /// truncate to zero in the observer and close every session on its
  /// first tick, and a fractional value would silently become a
  /// different deadline. Both are rejected at the constructor instead of
  /// misbehaving at runtime.
  #[test]
  fn session_liveness_rejects_sub_second_granularity() {
    for value in [
      Duration::from_millis(500),
      Duration::from_millis(1_500),
      Duration::from_nanos(1),
    ] {
      let error = NodeConfig::new()
        .with_session_liveness(value, Duration::ZERO, Duration::ZERO)
        .unwrap_err();
      assert_eq!(error.kind(), ErrorKind::InvalidInput);
    }
    // The keepalive pair is validated the same way: a fractional
    // interval would truncate and change the meaning of the ordering
    // invariant the setter enforces.
    let error = NodeConfig::new()
      .with_session_liveness(
        Duration::ZERO,
        Duration::from_millis(1_500),
        Duration::from_secs(15),
      )
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    // The smallest whole-second policy stays valid.
    assert!(
      NodeConfig::new()
        .with_session_liveness(Duration::from_secs(1), Duration::ZERO, Duration::ZERO)
        .is_ok()
    );
  }

  /// Every nonzero-duration and nonzero-count knob shares one setter
  /// contract: a configured value is stored verbatim and zero is
  /// refused (a zero deadline cancels every operation before it starts,
  /// a zero budget never admits anything). The shipped defaults are
  /// pinned separately by
  /// `liveness_defaults_are_the_slow_device_calibration`.
  #[test]
  fn nonzero_knobs_store_their_value_and_refuse_zero() {
    let configured = NodeConfig::new()
      .with_dial_deadline(Duration::from_millis(250))
      .unwrap()
      .with_authentication_deadline(Duration::from_secs(45))
      .unwrap()
      .with_relay_hop_deadline(Duration::from_secs(9))
      .unwrap()
      .with_receipt_retention(Duration::from_secs(7))
      .unwrap()
      .with_resource_removal_retention(Duration::from_secs(3_600), 1_024)
      .unwrap()
      .with_task_reconcile_slots(4, 8)
      .unwrap()
      .with_task_reconcile_extension_slots(3)
      .unwrap();
    assert_eq!(configured.dial_deadline(), Duration::from_millis(250));
    assert_eq!(
      configured.authentication_deadline(),
      Duration::from_secs(45)
    );
    assert_eq!(configured.relay_hop_deadline(), Duration::from_secs(9));
    assert_eq!(configured.receipt_retention(), Duration::from_secs(7));
    assert_eq!(
      configured.resource_removal_retention(),
      Duration::from_secs(3_600)
    );
    assert_eq!(configured.resource_removal_cap(), 1_024);
    assert_eq!(configured.task_reconcile_local_slots(), 4);
    assert_eq!(configured.task_reconcile_network_slots(), 8);
    assert_eq!(configured.task_reconcile_extension_slots(), 3);

    for error in [
      NodeConfig::new()
        .with_dial_deadline(Duration::ZERO)
        .unwrap_err(),
      NodeConfig::new()
        .with_authentication_deadline(Duration::ZERO)
        .unwrap_err(),
      NodeConfig::new()
        .with_relay_hop_deadline(Duration::ZERO)
        .unwrap_err(),
      NodeConfig::new()
        .with_receipt_retention(Duration::ZERO)
        .unwrap_err(),
      NodeConfig::new()
        .with_resource_removal_retention(Duration::ZERO, 1)
        .unwrap_err(),
      NodeConfig::new()
        .with_task_reconcile_slots(0, 2)
        .unwrap_err(),
      NodeConfig::new()
        .with_task_reconcile_slots(2, 0)
        .unwrap_err(),
      NodeConfig::new()
        .with_task_reconcile_extension_slots(0)
        .unwrap_err(),
    ] {
      assert_eq!(error.kind(), ErrorKind::InvalidInput);
    }
  }

  /// The three execution-slot channels ship the same two-slot default:
  /// the historical four-permit total split across the core classes plus
  /// the extension channel's own two lanes.
  #[test]
  fn task_reconcile_slots_default_to_two_per_class() {
    let config = NodeConfig::new();
    assert_eq!(config.task_reconcile_local_slots(), 2);
    assert_eq!(config.task_reconcile_network_slots(), 2);
    assert_eq!(config.task_reconcile_extension_slots(), 2);
  }

  /// A zero removal cap is the documented "no population cap" shape:
  /// the sweep's candidate heap stays empty and the removal population
  /// is bounded only by each record's own window.
  #[test]
  fn a_zero_removal_cap_means_no_population_cap() {
    let config = NodeConfig::new()
      .with_resource_removal_retention(Duration::from_secs(3_600), 0)
      .unwrap();
    assert_eq!(config.resource_removal_cap(), 0);
    assert_eq!(
      config.resource_removal_retention(),
      Duration::from_secs(3_600)
    );
  }

  /// The library ships exactly one profile — the defaults — and it must
  /// be safe on the slowest supported device (the mixed-cluster rule:
  /// timing constants are peer-visible, so there is no second, named
  /// low-power profile). Every recalibrated value traces to a
  /// transport-chaos scenario or a slow-device bound.
  #[test]
  fn liveness_defaults_are_the_slow_device_calibration() {
    let config = NodeConfig::new();
    // 64 nodes x 4 anti-entropy ticks/s starve a two-vcpu
    // runner's data plane; one tick/s keeps the O(N x interval) load
    // bounded while converging far inside the sync SLOs.
    assert_eq!(config.anti_entropy_interval(), Duration::from_secs(1));
    // Deadline half: slow-flash admission commits push
    // concurrent join tails past a 10 s deadline into persistent
    // join failure, so the default covers the slowest supported device.
    assert_eq!(config.authentication_deadline(), Duration::from_secs(30));
    // Duty-cycled peers skip several 20 s pings before the 60 s
    // keepalive timeout closes them, and a 90 s idle tolerates a slow
    // scheduling environment without tearing down live sessions.
    assert_eq!(config.session_idle_timeout(), Duration::from_secs(90));
    assert_eq!(config.keepalive_interval(), Duration::from_secs(20));
    assert_eq!(config.keepalive_timeout(), Duration::from_secs(60));
    // The recovery plane's own defaults (fan-out sixteen,
    // two-second initial backoff) are asserted in the recovery
    // controller's tests; here only the ordering invariant repeats:
    assert!(config.recovery().fan_out() >= 1);
    assert!(config.recovery().maximum_backoff >= config.recovery().initial_backoff);
    // A k-hop relay attempt is bounded by k x the per-hop budget.
    assert_eq!(config.relay_hop_deadline(), Duration::from_secs(5));
  }

  /// The liveness setter accepts every disabled/ordered shape and the
  /// degree override defaults to the derived value (zero).
  #[test]
  fn connection_degree_defaults_to_derived_and_accepts_overrides() {
    // Unset: zero, meaning the derived k(n) at tick time.
    assert_eq!(NodeConfig::new().connection_degree(), 0);
    // The operator override stores any value, including zero (derived).
    let configured = NodeConfig::new().with_connection_degree(1);
    assert_eq!(configured.connection_degree(), 1);
    let relay = NodeConfig::new().with_connection_degree(3);
    assert_eq!(relay.connection_degree(), 3);
    let derived = NodeConfig::new().with_connection_degree(0);
    assert_eq!(derived.connection_degree(), 0);
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

  /// The recovery backoff pair is second-granular: the controller's
  /// schedule is whole seconds, so a sub-second value would silently
  /// truncate to a different cadence (500 ms → 1 s, 1.5 s → 1 s). Both
  /// halves are rejected at the constructor; the smallest whole-second
  /// policy stays valid and reads back exactly.
  #[test]
  fn recovery_backoff_rejects_sub_second_granularity() {
    for (initial_backoff, maximum_backoff) in [
      (Duration::from_millis(500), Duration::from_secs(5)),
      (Duration::from_millis(1_500), Duration::from_secs(5)),
      (Duration::from_secs(1), Duration::from_millis(1_500)),
      (Duration::from_nanos(1), Duration::from_secs(1)),
    ] {
      let error = RecoveryConfig::new(1, initial_backoff, maximum_backoff).unwrap_err();
      assert_eq!(error.kind(), ErrorKind::InvalidInput);
    }
    let whole = RecoveryConfig::new(1, Duration::from_secs(1), Duration::from_secs(2)).unwrap();
    assert_eq!(whole.initial_backoff_seconds(), 1);
    assert_eq!(whole.maximum_backoff_seconds(), 2);
  }

  /// The endpoint-selection surface: both accessors default to unset
  /// (plain `Option` reads; the effective policy resolves in the
  /// registration channel), the policy tag stores verbatim, and the
  /// preference list refuses an empty list and duplicate entries while
  /// keeping its declared order.
  #[test]
  fn endpoint_selection_surface_stores_and_validates() {
    // Unset: both reads are `None`.
    let default = NodeConfig::new();
    assert!(default.endpoint_policy().is_none());
    assert!(default.endpoint_preference().is_none());

    // The policy tag stores verbatim (the with_route_policy shape).
    let tag = crate::QualifiedTag::parse("example.com/endpoint-policies/pinned").unwrap();
    let configured = NodeConfig::new().with_endpoint_policy(tag.clone());
    assert_eq!(configured.endpoint_policy(), Some(&tag));
    assert!(configured.endpoint_preference().is_none());

    // The preference list keeps its declared order and reads back.
    let preference = vec![
      crate::TransportName::parse("wss").unwrap(),
      crate::TransportName::parse("tcp").unwrap(),
    ];
    let configured = NodeConfig::new()
      .with_endpoint_preference(preference.clone())
      .unwrap();
    assert_eq!(configured.endpoint_preference(), Some(&preference[..]));
    assert!(configured.endpoint_policy().is_none());

    // An empty list is a caller mistake, not a "no preference" spelling.
    let error = NodeConfig::new()
      .with_endpoint_preference(Vec::new())
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert_eq!(error.context(), "endpoint preference list");

    // A duplicate entry is a conflict.
    let duplicated = vec![
      crate::TransportName::parse("wss").unwrap(),
      crate::TransportName::parse("wss").unwrap(),
    ];
    let error = NodeConfig::new()
      .with_endpoint_preference(duplicated)
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Conflict);
    assert_eq!(error.context(), "endpoint preference entry");
  }
}
