pub(crate) mod private {
  pub trait Sealed {}
}

use crate::{NodeId, packet::RouteHandle};

#[allow(private_bounds)]
pub trait Event: private::Sealed + Clone + Send + Sync + 'static {}

/// One caller-authored resource write intent: the stable name
/// plus its reserved and custom labels. Core stamps the wall-clock tuple
/// and signs the candidate record when the write executes; the caller
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

/// The node's identity was replaced by an active leave.
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
/// retired. Transient: subscribers re-read the session page
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

/// A member's owner-revision descriptor changed: a local
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

/// One route's state changed. Transient: subscribers re-read
/// the route status for the current state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteChanged {
  handle: RouteHandle,
}

impl RouteChanged {
  pub fn handle(&self) -> &RouteHandle {
    &self.handle
  }

  pub(crate) const fn new(handle: RouteHandle) -> Self {
    Self { handle }
  }
}

impl private::Sealed for RouteChanged {}

impl Event for RouteChanged {}

/// The recovery state changed: connectivity restored, a
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

/// A locally revoked identity lost connection and admission authority.
/// Emitted once per revocation transition, after the durable
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

/// One committed local resource candidate became visible in the catalog.
/// Emitted exactly once after the candidate's durable commit;
/// the write's [`crate::ResourceMutationView`] reports whether that
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
