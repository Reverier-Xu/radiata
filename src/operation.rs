pub(crate) mod private {
  pub trait Sealed {}
}

use crate::{Endpoint, MergeCredential, NodeId, identity::ListenerId, packet::RouteHandle};

#[allow(private_bounds)]
pub trait Command: private::Sealed + Send + 'static {
  type Output: Send + 'static;
}

#[allow(private_bounds)]
pub trait Query: private::Sealed + Send + 'static {
  type Output: Send + 'static;
}

#[allow(private_bounds)]
pub trait Event: private::Sealed + Clone + Send + Sync + 'static {}

pub struct Shutdown {
  _private: (),
}

#[allow(clippy::new_without_default)]
impl Shutdown {
  pub fn new() -> Self {
    Self { _private: () }
  }
}

impl private::Sealed for Shutdown {}

impl Command for Shutdown {
  type Output = crate::ShutdownOutcome;
}

pub struct RotateMergeCredential {
  _private: (),
}

#[allow(clippy::new_without_default)]
impl RotateMergeCredential {
  pub fn new() -> Self {
    Self { _private: () }
  }
}

impl private::Sealed for RotateMergeCredential {}

impl Command for RotateMergeCredential {
  type Output = crate::IssuedMergeCredential;
}

pub struct Listen {
  endpoint: Endpoint,
}

impl Listen {
  pub fn new(endpoint: Endpoint) -> Self {
    Self { endpoint }
  }

  pub(crate) fn into_endpoint(self) -> Endpoint {
    self.endpoint
  }
}

impl private::Sealed for Listen {}

impl Command for Listen {
  type Output = crate::ListenerView;
}

pub struct StopListener {
  listener: ListenerId,
}

impl StopListener {
  pub fn new(listener: ListenerId) -> Self {
    Self { listener }
  }

  pub(crate) fn into_listener(self) -> ListenerId {
    self.listener
  }
}

impl private::Sealed for StopListener {}

impl Command for StopListener {
  type Output = ();
}

pub struct MergeCluster {
  receiver: Endpoint,
  credential: MergeCredential,
}

impl MergeCluster {
  pub fn new(receiver: Endpoint, credential: MergeCredential) -> Self {
    Self {
      receiver,
      credential,
    }
  }

  pub(crate) fn into_parts(self) -> (Endpoint, MergeCredential) {
    (self.receiver, self.credential)
  }
}

impl private::Sealed for MergeCluster {}

impl Command for MergeCluster {
  type Output = crate::MergeView;
}

/// Connects to an already-admitted peer using key trust only (G3-04): no
/// join credential is consulted or required, the expected peer's trusted
/// identity binding gates the handshake, and the negotiated feature policy
/// is the same exact offer/selection machinery as a join.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectMember {
  receiver: Endpoint,
  peer: NodeId,
}

impl ConnectMember {
  /// `receiver` is the peer's listen endpoint; `peer` is the expected
  /// node identity whose trusted binding must already exist.
  pub fn new(receiver: Endpoint, peer: NodeId) -> Self {
    Self { receiver, peer }
  }

  pub(crate) fn into_parts(self) -> (Endpoint, NodeId) {
    (self.receiver, self.peer)
  }
}

impl private::Sealed for ConnectMember {}

impl Command for ConnectMember {
  type Output = crate::NodeId;
}

pub struct GetNodeStatus {
  _private: (),
}

#[allow(clippy::new_without_default)]
impl GetNodeStatus {
  pub fn new() -> Self {
    Self { _private: () }
  }
}

impl private::Sealed for GetNodeStatus {}

impl Query for GetNodeStatus {
  type Output = crate::NodeStatus;
}

/// The bounded observability snapshot query (T-G10-05): one snapshot of
/// counters and flags, never an enumeration.
pub struct GetObservability {
  _private: (),
}

#[allow(clippy::new_without_default)]
impl GetObservability {
  pub fn new() -> Self {
    Self { _private: () }
  }
}

impl private::Sealed for GetObservability {}

impl Query for GetObservability {
  type Output = crate::ObservabilitySnapshot;
}

pub struct GetLocalNode {
  _private: (),
}

#[allow(clippy::new_without_default)]
impl GetLocalNode {
  pub fn new() -> Self {
    Self { _private: () }
  }
}

impl private::Sealed for GetLocalNode {}

impl Query for GetLocalNode {
  type Output = crate::LocalNodeView;
}

pub struct WaitForShutdown {
  _private: (),
}

#[allow(clippy::new_without_default)]
impl WaitForShutdown {
  pub fn new() -> Self {
    Self { _private: () }
  }
}

impl private::Sealed for WaitForShutdown {}

impl Query for WaitForShutdown {
  type Output = crate::ShutdownReason;
}

/// Queries one member's public observation (G5-06).
pub struct GetMember {
  node: NodeId,
}

impl GetMember {
  pub fn new(node: NodeId) -> Self {
    Self { node }
  }

  pub(crate) const fn node(&self) -> &NodeId {
    &self.node
  }
}

impl private::Sealed for GetMember {}

impl Query for GetMember {
  type Output = Option<crate::MemberView>;
}

/// Pages the public membership observations (G5-06).
pub struct PageMembers {
  page: crate::PageSpec,
}

impl PageMembers {
  pub fn new(page: crate::PageSpec) -> Self {
    Self { page }
  }

  pub(crate) const fn page(&self) -> &crate::PageSpec {
    &self.page
  }
}

impl private::Sealed for PageMembers {}

impl Query for PageMembers {
  type Output = crate::MemberPage;
}

/// Pages the live resource winners matching one selector (T-G09-02).
pub struct SelectResources {
  selector: crate::Selector,
  page: crate::PageSpec,
}

impl SelectResources {
  pub fn new(selector: crate::Selector, page: crate::PageSpec) -> Self {
    Self { selector, page }
  }

  pub(crate) const fn selector(&self) -> &crate::Selector {
    &self.selector
  }

  pub(crate) const fn page(&self) -> &crate::PageSpec {
    &self.page
  }
}

impl private::Sealed for SelectResources {}

impl Query for SelectResources {
  type Output = crate::ResourcePage;
}

/// Pages the node's bound listeners (G9-07).
pub struct PageListeners {
  page: crate::PageSpec,
}

impl PageListeners {
  pub fn new(page: crate::PageSpec) -> Self {
    Self { page }
  }

  pub(crate) const fn page(&self) -> &crate::PageSpec {
    &self.page
  }
}

impl private::Sealed for PageListeners {}

impl Query for PageListeners {
  type Output = crate::ListenerPage;
}

/// Pages the live authenticated sessions (G9-07).
pub struct PageSessions {
  page: crate::PageSpec,
}

impl PageSessions {
  pub fn new(page: crate::PageSpec) -> Self {
    Self { page }
  }

  pub(crate) const fn page(&self) -> &crate::PageSpec {
    &self.page
  }
}

impl private::Sealed for PageSessions {}

impl Query for PageSessions {
  type Output = crate::SessionPage;
}

/// Reads the live winner of one named resource, when present (G9-07).
pub struct GetResource {
  name: crate::ResourceName,
}

impl GetResource {
  pub fn new(name: crate::ResourceName) -> Self {
    Self { name }
  }

  pub(crate) const fn name(&self) -> &crate::ResourceName {
    &self.name
  }
}

impl private::Sealed for GetResource {}

impl Query for GetResource {
  type Output = Option<crate::ResourceView>;
}

/// Pages the live resource winners in canonical name order (G9-07).
pub struct PageResources {
  page: crate::PageSpec,
}

impl PageResources {
  pub fn new(page: crate::PageSpec) -> Self {
    Self { page }
  }

  pub(crate) const fn page(&self) -> &crate::PageSpec {
    &self.page
  }
}

impl private::Sealed for PageResources {}

impl Query for PageResources {
  type Output = crate::ResourcePage;
}

/// One caller-authored resource write intent (T-G09-03): the stable name
/// plus its reserved and custom labels. Core stamps the wall-clock tuple
/// and signs the candidate record when the command executes; the caller
/// never supplies a timestamp, writer, or signature.
pub struct ResourceWrite {
  name: crate::ResourceName,
  labels: crate::ResourceLabels,
}

impl ResourceWrite {
  pub fn new(name: crate::ResourceName, labels: crate::ResourceLabels) -> Self {
    Self { name, labels }
  }

  pub(crate) const fn name(&self) -> &crate::ResourceName {
    &self.name
  }

  pub(crate) const fn labels(&self) -> &crate::ResourceLabels {
    &self.labels
  }
}

/// Commits one resource write intent as a signed candidate record
/// (T-G09-03). Acceptance never promises the candidate becomes or stays
/// the tuple winner; the outcome view reports the accepted record and
/// whether it is the current winner.
pub struct PutResource {
  write: ResourceWrite,
}

impl PutResource {
  /// Validates the write's encoded shape before it reaches the runtime:
  /// a candidate that can never fit the canonical record envelope is
  /// rejected here, before any signing or storage work.
  pub fn new(record: ResourceWrite) -> crate::Result<Self> {
    crate::resource::check_write_shape(record.name(), record.labels())?;
    Ok(Self { write: record })
  }

  pub(crate) fn into_write(self) -> ResourceWrite {
    self.write
  }
}

impl private::Sealed for PutResource {}

impl Command for PutResource {
  type Output = crate::ResourceMutationView;
}

/// Revokes one exact subject binding's connection and admission authority
/// (T-G09-04, ADR-0006): a durable local authorization boundary that
/// closes the identity's sessions and rejects its new sessions, raw
/// grants, and admissions — without deleting or reinterpreting any stored
/// metadata. `expected_key` pins the exact trusted binding so a stale or
/// substituted revocation fails closed.
pub struct RevokeNode {
  subject: NodeId,
  expected_key: crate::PublicKey,
}

impl RevokeNode {
  pub fn new(subject: NodeId, expected_key: crate::PublicKey) -> Self {
    Self {
      subject,
      expected_key,
    }
  }

  pub(crate) fn into_parts(self) -> (NodeId, crate::PublicKey) {
    (self.subject, self.expected_key)
  }
}

impl private::Sealed for RevokeNode {}

impl Command for RevokeNode {
  type Output = crate::RevokeOutcome;
}

/// Issues a convergent issuer-signed cleanup tombstone for one
/// decommissioned node (ADR-0009 decision 4). Terminal: there is no
/// resurrection path. The caller is responsible for never cleaning a node
/// that is merely offline.
pub struct CleanupNode {
  subject: NodeId,
}

impl CleanupNode {
  pub fn new(subject: NodeId) -> Self {
    Self { subject }
  }

  pub(crate) fn into_subject(self) -> NodeId {
    self.subject
  }
}

impl private::Sealed for CleanupNode {}

impl Command for CleanupNode {
  type Output = ();
}

/// Explicitly clears the local revocation record for one subject
/// (ADR-0009 decision 6). Local-only and idempotent.
pub struct PurgeRevocation {
  subject: NodeId,
}

impl PurgeRevocation {
  pub fn new(subject: NodeId) -> Self {
    Self { subject }
  }

  pub(crate) fn into_subject(self) -> NodeId {
    self.subject
  }
}

impl private::Sealed for PurgeRevocation {}

impl Command for PurgeRevocation {
  type Output = ();
}

/// Creates signed removal evidence for one resource (T-G09-05): the
/// removal commits only when the locally stored winner still equals
/// `expected` exactly and the removal strictly wins the tuple, so a stale
/// request never removes newer metadata and never poses as a newer
/// wall-clock winner. Removal is limited to core metadata; core never
/// follows the resource URI or touches the caller's object.
pub struct RemoveResource {
  name: crate::ResourceName,
  expected: crate::ResourceVersion,
}

impl RemoveResource {
  pub fn new(name: crate::ResourceName, expected: crate::ResourceVersion) -> Self {
    Self { name, expected }
  }

  pub(crate) fn into_parts(self) -> (crate::ResourceName, crate::ResourceVersion) {
    (self.name, self.expected)
  }
}

impl private::Sealed for RemoveResource {}

impl Command for RemoveResource {
  type Output = crate::ResourceMutationView;
}

/// Actively leaves the cluster (T-G09-06): replaces the node's identity
/// with a fresh node id and key, deletes the old identity's local core
/// metadata and key through the journaled custody protocols, and shuts the
/// node down with [`crate::ShutdownReason::ActiveLeave`]. The explicit
/// acknowledgement makes the identity replacement and metadata deletion
/// a deliberate caller decision.
pub struct LeaveCluster {
  acknowledgement: crate::ReplaceIdentityAndDeleteOldCoreMetadata,
}

impl LeaveCluster {
  pub fn new(acknowledgement: crate::ReplaceIdentityAndDeleteOldCoreMetadata) -> Self {
    Self { acknowledgement }
  }

  pub(crate) const fn acknowledgement(&self) -> &crate::ReplaceIdentityAndDeleteOldCoreMetadata {
    &self.acknowledgement
  }
}

impl private::Sealed for LeaveCluster {}

impl Command for LeaveCluster {
  type Output = crate::LeaveOutcome;
}

/// The node's identity was replaced by an active leave (T-G09-06).
/// Emitted once, after the identity swap is durable and before the node
/// shuts down with [`crate::ShutdownReason::ActiveLeave`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityReplaced {
  former_identity: NodeId,
  replacement_identity: NodeId,
}

impl IdentityReplaced {
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

impl private::Sealed for IdentityReplaced {}

impl Event for IdentityReplaced {}

/// One authenticated session to the peer was established, replaced, or
/// retired (T-G09-07). Transient: subscribers re-read the session page
/// for the current set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionChanged {
  peer: NodeId,
}

impl SessionChanged {
  pub fn peer(&self) -> &NodeId {
    &self.peer
  }

  pub(crate) const fn new(peer: NodeId) -> Self {
    Self { peer }
  }
}

impl private::Sealed for SessionChanged {}

impl Event for SessionChanged {}

/// A member's owner-revision descriptor changed (T-G09-07): a local
/// update or a converged sync install. Transient: subscribers re-read the
/// member views for the current state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemberChanged {
  node_id: NodeId,
}

impl MemberChanged {
  pub fn node_id(&self) -> &NodeId {
    &self.node_id
  }

  pub(crate) const fn new(node_id: NodeId) -> Self {
    Self { node_id }
  }
}

impl private::Sealed for MemberChanged {}

impl Event for MemberChanged {}

/// One route's state changed (T-G09-07). Transient: subscribers re-read
/// `GetRoute` for the current status.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteChanged {
  handle: crate::RouteHandle,
}

impl RouteChanged {
  pub fn handle(&self) -> &crate::RouteHandle {
    &self.handle
  }

  pub(crate) const fn new(handle: crate::RouteHandle) -> Self {
    Self { handle }
  }
}

impl private::Sealed for RouteChanged {}

impl Event for RouteChanged {}

/// The recovery state changed (T-G09-07): connectivity restored, a
/// component became unreachable, or an immediate recovery started.
/// Transient: subscribers re-read the recovery view.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryChanged {
  recovery: crate::RecoveryView,
}

impl RecoveryChanged {
  pub fn recovery(&self) -> &crate::RecoveryView {
    &self.recovery
  }

  pub(crate) const fn new(recovery: crate::RecoveryView) -> Self {
    Self { recovery }
  }
}

impl private::Sealed for RecoveryChanged {}

impl Event for RecoveryChanged {}

/// A locally revoked identity lost connection and admission authority
/// (T-G09-04). Emitted once per revocation transition, after the durable
/// commit; an idempotent repeated revoke emits nothing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeRevoked {
  subject: NodeId,
}

impl NodeRevoked {
  pub fn subject(&self) -> &NodeId {
    &self.subject
  }

  pub(crate) const fn new(subject: NodeId) -> Self {
    Self { subject }
  }
}

impl private::Sealed for NodeRevoked {}

impl Event for NodeRevoked {}

/// One committed local resource candidate became visible in the catalog
/// (T-G09-03). Emitted exactly once after the candidate's durable commit;
/// the command's [`crate::ResourceMutationView`] reports whether that
/// candidate is the current winner. Aborted and indeterminate candidates
/// emit nothing, and restart or maintenance never replays the event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceChanged {
  resource: crate::ResourceName,
}

impl ResourceChanged {
  pub fn resource(&self) -> &crate::ResourceName {
    &self.resource
  }

  pub(crate) const fn new(resource: crate::ResourceName) -> Self {
    Self { resource }
  }
}

impl private::Sealed for ResourceChanged {}

impl Event for ResourceChanged {}

/// Pages the public topology edges (G5-06).
pub struct PageTopology {
  page: crate::PageSpec,
}

impl PageTopology {
  pub fn new(page: crate::PageSpec) -> Self {
    Self { page }
  }

  pub(crate) const fn page(&self) -> &crate::PageSpec {
    &self.page
  }
}

impl private::Sealed for PageTopology {}

impl Query for PageTopology {
  type Output = crate::TopologyPage;
}

/// Pages the public trust observations (G5-06).
pub struct PageTrust {
  page: crate::PageSpec,
}

impl PageTrust {
  pub fn new(page: crate::PageSpec) -> Self {
    Self { page }
  }

  pub(crate) const fn page(&self) -> &crate::PageSpec {
    &self.page
  }
}

impl private::Sealed for PageTrust {}

impl Query for PageTrust {
  type Output = crate::TrustPage;
}

/// Forces one bounded immediate recovery cycle and returns its view
/// (G5-06).
pub struct StartRecovery {
  _private: (),
}

#[allow(clippy::new_without_default)]
impl StartRecovery {
  pub fn new() -> Self {
    Self { _private: () }
  }
}

impl private::Sealed for StartRecovery {}

impl Command for StartRecovery {
  type Output = crate::RecoveryView;
}

/// Closes the authenticated session to one peer (G5-06, partition
/// simulation and failure matrix).
pub struct DisconnectPeer {
  peer: NodeId,
}

impl DisconnectPeer {
  pub fn new(peer: NodeId) -> Self {
    Self { peer }
  }

  pub(crate) const fn peer(&self) -> &NodeId {
    &self.peer
  }
}

impl private::Sealed for DisconnectPeer {}

impl Command for DisconnectPeer {
  type Output = ();
}

/// Updates the local node's own descriptor (owner-only node metadata,
/// ADR-0007): endpoint candidates and capability labels are applied at a
/// strictly higher revision than `expected_revision`, and the updated
/// member view is returned. Same-revision or stale expectations conflict.
pub struct UpdateNodeMetadata {
  expected_revision: u64,
  patch: crate::NodeMetadataPatch,
}

impl UpdateNodeMetadata {
  pub fn new(expected_revision: u64, patch: crate::NodeMetadataPatch) -> Self {
    Self {
      expected_revision,
      patch,
    }
  }

  pub(crate) fn into_parts(self) -> (u64, crate::NodeMetadataPatch) {
    (self.expected_revision, self.patch)
  }
}

impl private::Sealed for UpdateNodeMetadata {}

impl Command for UpdateNodeMetadata {
  type Output = crate::MemberView;
}

/// Queries the in-memory route status of one packet route handle
/// (ADR-0007: bounded trace metadata only, no durability claim).
pub struct GetRoute {
  handle: RouteHandle,
}

impl GetRoute {
  pub fn new(handle: RouteHandle) -> Self {
    Self { handle }
  }

  pub(crate) const fn handle(&self) -> &RouteHandle {
    &self.handle
  }
}

impl private::Sealed for GetRoute {}

impl Query for GetRoute {
  type Output = crate::RouteStatusView;
}
