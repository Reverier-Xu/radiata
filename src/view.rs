use crate::{
  Endpoint, Error, ErrorKind, NodeId, PublicKey, QualifiedTag, Result,
  identity::{ListenerId, SessionId},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum NodeStatus {
  Starting,
  Running,
  ShuttingDown,
  Stopped,
  Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ShutdownReason {
  Explicit,
  ActiveLeave,
  Fatal(ErrorKind),
}

/// The completed merge returned by `MergeCluster`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MergeView {
  node: NodeId,
  peer: NodeId,
}

impl MergeView {
  /// The local node that adopted the issuer's binding.
  pub fn node(&self) -> &NodeId {
    &self.node
  }

  /// The authenticated merge peer whose binding was adopted.
  pub fn peer(&self) -> &NodeId {
    &self.peer
  }

  pub(crate) const fn new(node: NodeId, peer: NodeId) -> Self {
    Self { node, peer }
  }
}

/// One bound listener returned by `Listen`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListenerView {
  id: ListenerId,
  endpoint: Endpoint,
}

impl ListenerView {
  pub fn id(&self) -> &ListenerId {
    &self.id
  }

  pub fn endpoint(&self) -> &Endpoint {
    &self.endpoint
  }

  pub(crate) const fn new(id: ListenerId, endpoint: Endpoint) -> Self {
    Self { id, endpoint }
  }
}

/// One bounded page of listener observations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListenerPage {
  items: Vec<ListenerView>,
  next: Option<crate::PageCursor>,
}

impl ListenerPage {
  pub fn items(&self) -> &[ListenerView] {
    &self.items
  }

  pub fn next(&self) -> Option<&crate::PageCursor> {
    self.next.as_ref()
  }

  pub(crate) fn new(items: Vec<ListenerView>, next: Option<crate::PageCursor>) -> Self {
    Self { items, next }
  }
}

/// One session-scoped selected feature: the negotiated tag and its exact
/// definition digest from the authenticated intersection.
/// The pair is session metadata: it disappears with the session and never
/// becomes a node-wide authorization claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionFeatureView {
  feature: crate::FeatureTag,
  definition_digest: crate::Digest,
}

impl SessionFeatureView {
  pub fn feature(&self) -> &crate::FeatureTag {
    &self.feature
  }

  pub fn definition_digest(&self) -> &crate::Digest {
    &self.definition_digest
  }

  pub(crate) const fn new(feature: crate::FeatureTag, definition_digest: crate::Digest) -> Self {
    Self {
      feature,
      definition_digest,
    }
  }
}

/// One live authenticated session's public observation: its
/// server-allocated id, the per-peer replacement generation, the peer, the
/// attachment endpoint (the dial target for outbound sessions, the
/// accepting listener for inbound ones), and the session-scoped feature
/// intersection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionView {
  id: SessionId,
  generation: u64,
  peer: NodeId,
  endpoint: Endpoint,
  selected_features: Vec<SessionFeatureView>,
}

impl SessionView {
  pub fn id(&self) -> &SessionId {
    &self.id
  }

  pub fn generation(&self) -> u64 {
    self.generation
  }

  pub fn peer(&self) -> &NodeId {
    &self.peer
  }

  pub fn endpoint(&self) -> &Endpoint {
    &self.endpoint
  }

  pub fn selected_features(&self) -> &[SessionFeatureView] {
    &self.selected_features
  }

  pub(crate) fn new(
    id: SessionId, generation: u64, peer: NodeId, endpoint: Endpoint,
    selected_features: Vec<SessionFeatureView>,
  ) -> Self {
    Self {
      id,
      generation,
      peer,
      endpoint,
      selected_features,
    }
  }
}

/// One bounded page of session observations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionPage {
  items: Vec<SessionView>,
  next: Option<crate::PageCursor>,
}

impl SessionPage {
  pub fn items(&self) -> &[SessionView] {
    &self.items
  }

  pub fn next(&self) -> Option<&crate::PageCursor> {
    self.next.as_ref()
  }

  pub(crate) fn new(items: Vec<SessionView>, next: Option<crate::PageCursor>) -> Self {
    Self { items, next }
  }
}

/// The bounded observability snapshot of one node: counters keyed by
/// well-known tags covering sessions,
/// listeners, background tasks, queue totals, open routes, retained trace
/// metadata plus its dropped-record counter, pending transactions, and
/// metadata-store availability,
/// captured at the local host wall clock. Counters and flags only; the
/// snapshot carries no identity, address, path, selector, body, or
/// credential material and never enumerates a whole population.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ObservabilitySnapshot {
  captured_at: std::time::SystemTime,
  counters: std::collections::BTreeMap<QualifiedTag, u64>,
}

impl ObservabilitySnapshot {
  /// Well-known counter tag: live authenticated sessions.
  pub const SESSIONS: &str = "radiata.woooo.tech/status/sessions";
  /// Well-known counter tag: live listeners.
  pub const LISTENERS: &str = "radiata.woooo.tech/status/listeners";
  /// Well-known counter tag: live background tasks.
  pub const BACKGROUND_TASKS: &str = "radiata.woooo.tech/status/background-tasks";
  /// Well-known counter tag: total queued outbound session frames.
  pub const QUEUED_SESSION_MESSAGES: &str = "radiata.woooo.tech/status/queued-session-messages";
  /// Well-known counter tag: total queued outbound session bytes.
  pub const QUEUED_SESSION_BYTES: &str = "radiata.woooo.tech/status/queued-session-bytes";
  /// Well-known counter tag: open outbound routes.
  pub const OPEN_ROUTES: &str = "radiata.woooo.tech/status/open-routes";
  /// Well-known counter tag: retained trace metadata records.
  pub const TRACE_RECORDS: &str = "radiata.woooo.tech/status/trace-records";
  /// Well-known counter tag: terminal trace records dropped because the
  /// persistence queue was full (best-effort lane, never a data loss).
  pub const TRACE_RECORDS_DROPPED: &str = "radiata.woooo.tech/status/trace-records-dropped";
  /// Well-known counter tag: pending metadata transactions.
  pub const PENDING_TRANSACTIONS: &str = "radiata.woooo.tech/status/pending-transactions";
  /// Well-known counter tag: metadata store availability (1 = available).
  pub const METADATA_STORE_AVAILABLE: &str = "radiata.woooo.tech/status/metadata-store-available";

  /// The value of one well-known counter, if the snapshot carries it.
  pub fn counter(&self, tag: &QualifiedTag) -> Option<u64> {
    self.counters.get(tag).copied()
  }

  /// The local host wall-clock instant of the capture.
  pub fn captured_at(&self) -> std::time::SystemTime {
    self.captured_at
  }

  /// Builds the snapshot from the runtime collectors; every well-known
  /// tag is present exactly once, in canonical order.
  #[allow(clippy::too_many_arguments)]
  pub(crate) fn new(
    captured_at: std::time::SystemTime, sessions: usize, listeners: usize, background_tasks: usize,
    queued_session_messages: usize, queued_session_bytes: u64, open_routes: usize,
    trace_records: usize, trace_records_dropped: usize, pending_transactions: usize,
    storage_available: bool,
  ) -> Result<Self> {
    let internal = || Error::internal("observability counter");
    let counters: [(&str, u64); 10] = [
      (
        Self::SESSIONS,
        u64::try_from(sessions).map_err(|_| internal())?,
      ),
      (
        Self::LISTENERS,
        u64::try_from(listeners).map_err(|_| internal())?,
      ),
      (
        Self::BACKGROUND_TASKS,
        u64::try_from(background_tasks).map_err(|_| internal())?,
      ),
      (
        Self::QUEUED_SESSION_MESSAGES,
        u64::try_from(queued_session_messages).map_err(|_| internal())?,
      ),
      (Self::QUEUED_SESSION_BYTES, queued_session_bytes),
      (
        Self::OPEN_ROUTES,
        u64::try_from(open_routes).map_err(|_| internal())?,
      ),
      (
        Self::TRACE_RECORDS,
        u64::try_from(trace_records).map_err(|_| internal())?,
      ),
      (
        Self::TRACE_RECORDS_DROPPED,
        u64::try_from(trace_records_dropped).map_err(|_| internal())?,
      ),
      (
        Self::PENDING_TRANSACTIONS,
        u64::try_from(pending_transactions).map_err(|_| internal())?,
      ),
      (Self::METADATA_STORE_AVAILABLE, u64::from(storage_available)),
    ];
    let mut map = std::collections::BTreeMap::new();
    for (tag, value) in counters {
      let parsed = QualifiedTag::parse(tag)?;
      if map.insert(parsed, value).is_some() {
        return Err(Error::internal("observability duplicate counter"));
      }
    }
    Ok(Self {
      captured_at,
      counters: map,
    })
  }
}

/// The local node's identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalNodeView {
  node_id: NodeId,
  public_key: PublicKey,
}

impl LocalNodeView {
  pub fn node_id(&self) -> &NodeId {
    &self.node_id
  }

  pub fn public_key(&self) -> &PublicKey {
    &self.public_key
  }

  pub(crate) const fn new(node_id: NodeId, public_key: PublicKey) -> Self {
    Self {
      node_id,
      public_key,
    }
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShutdownOutcome {
  reason: ShutdownReason,
}

impl ShutdownOutcome {
  pub fn reason(&self) -> &ShutdownReason {
    &self.reason
  }

  pub(crate) const fn new(reason: ShutdownReason) -> Self {
    Self { reason }
  }
}

// ---- Public membership and topology views ----

/// The connectivity of one member as observed locally.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ConnectivityStatus {
  /// No observation yet.
  Unknown,
  /// Known but no session and not a neighbor candidate.
  Offline,
  /// Has candidate endpoints but no authenticated session.
  Reachable,
  /// Has an authenticated session.
  Connected,
}

/// One public member observation: the exact owner-marked descriptor plus the
/// local connectivity view.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemberView {
  node_id: NodeId,
  public_key: PublicKey,
  owner_revision: u64,
  digest: crate::Digest,
  connectivity: ConnectivityStatus,
  status: MemberStatus,
  endpoints: Vec<Endpoint>,
  labels: crate::LabelSet,
}

/// The node's membership-removal state as observed from the local
/// terminal records. A signed leave or cleanup record marks a member as no
/// longer part of the cluster even though its descriptor remains stored as
/// verification evidence, so the status — not the page membership — is the
/// authoritative liveness signal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemberStatus {
  /// No terminal removal record exists for the node.
  Active,
  /// The node owns a signed leave record.
  Left,
  /// An issuer-signed cleanup record removes the node.
  Cleaned,
}

impl MemberView {
  pub fn node_id(&self) -> &NodeId {
    &self.node_id
  }

  pub fn public_key(&self) -> &PublicKey {
    &self.public_key
  }

  pub fn owner_revision(&self) -> u64 {
    self.owner_revision
  }

  pub fn digest(&self) -> &crate::Digest {
    &self.digest
  }

  pub fn connectivity(&self) -> ConnectivityStatus {
    self.connectivity
  }

  pub fn endpoints(&self) -> &[Endpoint] {
    &self.endpoints
  }

  /// The member's node-owned capability labels.
  pub fn labels(&self) -> &crate::LabelSet {
    &self.labels
  }

  /// The node's membership-removal state. Left and cleaned members keep
  /// their descriptor as verification evidence but are no longer cluster
  /// members; count only [`MemberStatus::Active`] entries when computing
  /// live membership from a member page.
  pub fn status(&self) -> MemberStatus {
    self.status
  }

  pub(crate) fn new(
    node_id: NodeId, public_key: PublicKey, owner_revision: u64, digest: crate::Digest,
    connectivity: ConnectivityStatus, endpoints: Vec<Endpoint>, labels: crate::LabelSet,
  ) -> Self {
    Self {
      node_id,
      public_key,
      owner_revision,
      digest,
      connectivity,
      status: MemberStatus::Active,
      endpoints,
      labels,
    }
  }

  /// Annotates the view with the node's removal state; the observation
  /// layer derives it from the terminal-record stores.
  pub(crate) fn with_status(mut self, status: MemberStatus) -> Self {
    self.status = status;
    self
  }
}

/// The caller-built patch behind the `UpdateNodeMetadata` command: the
/// owning node's bounded edits to its own descriptor, applied at a strictly
/// higher revision.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NodeMetadataPatch {
  add_endpoints: Vec<Endpoint>,
  remove_endpoints: Vec<Endpoint>,
  set_labels: Vec<(crate::LabelKey, crate::LabelValue)>,
  remove_labels: Vec<crate::LabelKey>,
}

/// The validated edits carried by one [`NodeMetadataPatch`].
pub(crate) struct PatchParts {
  pub(crate) add_endpoints: Vec<Endpoint>,
  pub(crate) remove_endpoints: Vec<Endpoint>,
  pub(crate) set_labels: Vec<(crate::LabelKey, crate::LabelValue)>,
  pub(crate) remove_labels: Vec<crate::LabelKey>,
}

impl NodeMetadataPatch {
  pub fn new() -> Self {
    Self::default()
  }

  /// Adds one endpoint candidate. Duplicates within one patch are
  /// rejected.
  pub fn add_endpoint(mut self, endpoint: Endpoint) -> crate::Result<Self> {
    if self.add_endpoints.contains(&endpoint) {
      return Err(Error::conflict("node metadata endpoint"));
    }
    self.add_endpoints.push(endpoint);
    Ok(self)
  }

  /// Removes one endpoint candidate; removing an unknown endpoint fails.
  /// Removals apply to the record as it exists after the additions.
  pub fn remove_endpoint(mut self, endpoint: Endpoint) -> crate::Result<Self> {
    self.remove_endpoints.push(endpoint);
    Ok(self)
  }

  /// Sets one capability label. Setting the same key twice in one patch
  /// is rejected.
  pub fn set_capability(
    mut self, key: crate::LabelKey, value: crate::LabelValue,
  ) -> crate::Result<Self> {
    if self.set_labels.iter().any(|(existing, _)| existing == &key) {
      return Err(Error::conflict("node metadata label"));
    }
    self.set_labels.push((key, value));
    Ok(self)
  }

  /// Removes one capability label; removing an unknown key fails at
  /// apply time against the current record.
  pub fn remove_capability(mut self, key: crate::LabelKey) -> crate::Result<Self> {
    self.remove_labels.push(key);
    Ok(self)
  }

  pub(crate) fn into_parts(self) -> PatchParts {
    PatchParts {
      add_endpoints: self.add_endpoints,
      remove_endpoints: self.remove_endpoints,
      set_labels: self.set_labels,
      remove_labels: self.remove_labels,
    }
  }
}

/// One bounded page of member observations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemberPage {
  items: Vec<MemberView>,
  next: Option<crate::PageCursor>,
}

impl MemberPage {
  pub fn items(&self) -> &[MemberView] {
    &self.items
  }

  pub fn next(&self) -> Option<&crate::PageCursor> {
    self.next.as_ref()
  }

  pub(crate) fn new(items: Vec<MemberView>, next: Option<crate::PageCursor>) -> Self {
    Self { items, next }
  }
}

/// One public resource observation: the winning record's stable name,
/// its reserved-plus-custom labels, and its exact tuple version.
///
/// A resource whose current winner is a signed removal is not observed:
/// removal evidence stays internal, and a removed name reads as absent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceView {
  name: crate::ResourceName,
  labels: crate::ResourceLabels,
  version: crate::ResourceVersion,
}

impl ResourceView {
  pub fn name(&self) -> &crate::ResourceName {
    &self.name
  }

  pub fn labels(&self) -> &crate::ResourceLabels {
    &self.labels
  }

  pub fn version(&self) -> &crate::ResourceVersion {
    &self.version
  }

  pub(crate) fn new(
    name: crate::ResourceName, labels: crate::ResourceLabels, version: crate::ResourceVersion,
  ) -> Self {
    Self {
      name,
      labels,
      version,
    }
  }
}

/// One bounded page of resource observations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourcePage {
  items: Vec<ResourceView>,
  next: Option<crate::PageCursor>,
}

impl ResourcePage {
  pub fn items(&self) -> &[ResourceView] {
    &self.items
  }

  pub fn next(&self) -> Option<&crate::PageCursor> {
    self.next.as_ref()
  }

  pub(crate) fn new(items: Vec<ResourceView>, next: Option<crate::PageCursor>) -> Self {
    Self { items, next }
  }
}

/// The outcome of one local resource mutation: the accepted
/// signed candidate plus whether that candidate is the register's current
/// tuple winner. Acceptance is not a promise of winning or staying
/// current; a losing candidate stays harmless.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceMutationView {
  accepted: ResourceView,
  current_winner: bool,
}

impl ResourceMutationView {
  /// The accepted candidate as committed (or offered) locally.
  pub fn accepted(&self) -> &ResourceView {
    &self.accepted
  }

  /// Whether the accepted candidate is the register's current winner.
  pub fn is_current_winner(&self) -> bool {
    self.current_winner
  }

  pub(crate) fn new(accepted: ResourceView, current_winner: bool) -> Self {
    Self {
      accepted,
      current_winner,
    }
  }
}

/// The explicit acknowledgement required by [`crate::LeaveCluster`]:
/// constructing it is the caller's deliberate confirmation
/// that the leave replaces the node's identity and deletes the old
/// identity's local core metadata. It has no `Default`, so the
/// acknowledgement cannot be produced accidentally.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplaceIdentityAndDeleteOldCoreMetadata {
  acknowledged: bool,
}

impl ReplaceIdentityAndDeleteOldCoreMetadata {
  /// Constructs the acknowledgement; there is deliberately no `Default`
  /// so the acknowledgement cannot be produced accidentally.
  #[allow(clippy::new_without_default)]
  pub fn new() -> Self {
    Self { acknowledged: true }
  }

  pub(crate) const fn is_acknowledged(&self) -> bool {
    self.acknowledged
  }
}

/// The outcome of one active leave: the exact former and
/// replacement identities, bound together.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeaveOutcome {
  former_identity: NodeId,
  replacement_identity: NodeId,
}

impl LeaveOutcome {
  pub fn former_identity(&self) -> &NodeId {
    &self.former_identity
  }

  pub fn replacement_identity(&self) -> &NodeId {
    &self.replacement_identity
  }

  pub(crate) const fn new(former_identity: NodeId, replacement_identity: NodeId) -> Self {
    Self {
      former_identity,
      replacement_identity,
    }
  }
}

/// The outcome of one authorization revoke: the exact subject
/// and whether this call performed the revocation transition (an
/// idempotent repeated revoke reports `true` for `was_already_revoked`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevokeOutcome {
  subject: NodeId,
  was_already_revoked: bool,
}

impl RevokeOutcome {
  pub fn subject(&self) -> &NodeId {
    &self.subject
  }

  pub fn was_already_revoked(&self) -> bool {
    self.was_already_revoked
  }

  pub(crate) const fn new(subject: NodeId, was_already_revoked: bool) -> Self {
    Self {
      subject,
      was_already_revoked,
    }
  }
}

/// One public topology edge: a directed session between two members.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TopologyEdgeView {
  source: NodeId,
  destination: NodeId,
  connected: bool,
  observed_at: std::time::SystemTime,
}

impl TopologyEdgeView {
  pub fn source(&self) -> &NodeId {
    &self.source
  }

  pub fn destination(&self) -> &NodeId {
    &self.destination
  }

  pub fn connected(&self) -> bool {
    self.connected
  }

  pub fn observed_at(&self) -> std::time::SystemTime {
    self.observed_at
  }

  pub(crate) fn new(
    source: NodeId, destination: NodeId, connected: bool, observed_at: std::time::SystemTime,
  ) -> Self {
    Self {
      source,
      destination,
      connected,
      observed_at,
    }
  }
}

/// One bounded page of topology edges.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TopologyPage {
  items: Vec<TopologyEdgeView>,
  next: Option<crate::PageCursor>,
}

impl TopologyPage {
  pub fn items(&self) -> &[TopologyEdgeView] {
    &self.items
  }

  pub fn next(&self) -> Option<&crate::PageCursor> {
    self.next.as_ref()
  }

  pub(crate) fn new(items: Vec<TopologyEdgeView>, next: Option<crate::PageCursor>) -> Self {
    Self { items, next }
  }
}

/// One paged query spec: a bounded first page or a continuation after a
/// cursor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PageSpec {
  cursor: Option<crate::PageCursor>,
  limit: usize,
}

impl PageSpec {
  pub fn first(limit: usize) -> crate::Result<Self> {
    Self::build(None, limit)
  }

  pub fn after(cursor: crate::PageCursor, limit: usize) -> crate::Result<Self> {
    Self::build(Some(cursor), limit)
  }

  /// The single limit check behind both constructors: a first page and a
  /// continuation differ only in their cursor.
  fn build(cursor: Option<crate::PageCursor>, limit: usize) -> crate::Result<Self> {
    if limit == 0 {
      return Err(crate::Error::invalid_input("page limit"));
    }
    Ok(Self { cursor, limit })
  }

  pub(crate) const fn cursor(&self) -> Option<&crate::PageCursor> {
    self.cursor.as_ref()
  }

  pub(crate) const fn limit(&self) -> usize {
    self.limit
  }
}

// ---- Trust and recovery views ----

/// The trust status of one observed identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TrustStatus {
  /// The binding is trusted (verified from an admission grant or an
  /// issuer snapshot).
  Trusted,
  /// The binding was revoked.
  Revoked,
}

/// One public trust observation: an exact NodeId-to-key binding with its
/// status.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedIdentityView {
  node_id: NodeId,
  public_key: PublicKey,
  status: TrustStatus,
}

impl TrustedIdentityView {
  pub fn node_id(&self) -> &NodeId {
    &self.node_id
  }

  pub fn public_key(&self) -> &PublicKey {
    &self.public_key
  }

  pub const fn status(&self) -> TrustStatus {
    self.status
  }

  pub(crate) const fn new(node_id: NodeId, public_key: PublicKey, status: TrustStatus) -> Self {
    Self {
      node_id,
      public_key,
      status,
    }
  }
}

/// One bounded page of trust observations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustPage {
  items: Vec<TrustedIdentityView>,
  next: Option<crate::PageCursor>,
}

impl TrustPage {
  pub fn items(&self) -> &[TrustedIdentityView] {
    &self.items
  }

  pub fn next(&self) -> Option<&crate::PageCursor> {
    self.next.as_ref()
  }

  pub(crate) fn new(items: Vec<TrustedIdentityView>, next: Option<crate::PageCursor>) -> Self {
    Self { items, next }
  }
}

/// The outcome of one explicit receipt-retention pass: how many anchored
/// receipts past their deadline were forgotten, and whether anchored
/// receipts remain beyond the pass bound (call again to continue).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiptRetentionReport {
  /// Anchored receipts whose retention deadline had elapsed and whose
  /// forget transaction committed.
  pub forgotten: u64,
  /// The pass stopped at its internal bound with anchored receipts left;
  /// issue the command again to continue.
  pub remaining: bool,
}

/// The public view of one immediate recovery observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryView {
  is_connected: bool,
  unreachable_members: usize,
  next_attempt_at: Option<std::time::SystemTime>,
}

impl RecoveryView {
  pub const fn is_connected(&self) -> bool {
    self.is_connected
  }

  /// How many known members the controller still counts as unreachable.
  pub const fn unreachable_members(&self) -> usize {
    self.unreachable_members
  }

  pub const fn next_attempt_at(&self) -> Option<std::time::SystemTime> {
    self.next_attempt_at
  }

  pub(crate) const fn new(
    is_connected: bool, unreachable_members: usize, next_attempt_at: Option<std::time::SystemTime>,
  ) -> Self {
    Self {
      is_connected,
      unreachable_members,
      next_attempt_at,
    }
  }
}
