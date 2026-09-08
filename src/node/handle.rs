use std::sync::Arc;

use tokio::sync::oneshot;

use crate::{
  Command, ConnectMember, DisconnectPeer, Error, Event, EventOptions, EventSubscription,
  GetLocalNode, GetMember, GetNodeStatus, GetObservability, GetRoute, IssuedMergeCredential,
  Listen, MergeCluster, NodeId, NodeStatus, OutboundStream, PageMembers, PageTopology, PageTrust,
  ProtocolTag, Query, Result, RotateMergeCredential, RouteStatusView, SelectResources, Shutdown,
  ShutdownOutcome, ShutdownReason, StartRecovery, StopListener, StreamMetadata, StreamPolicy,
  StreamTarget, TraceId, UpdateNodeMetadata, WaitForShutdown,
  api::{BoxFuture, Entropy},
  extension_registry::ExtensionRegistry,
  runtime::{Control, RuntimeClient},
  view::{ListenerView, LocalNodeView, MergeView},
};

#[derive(Clone)]
pub struct NodeHandle {
  runtime: RuntimeClient,
  entropy: Arc<dyn Entropy>,
  extensions: Arc<ExtensionRegistry>,
  events: Arc<crate::node::EventHub>,
  member_revision: crate::node::MemberRevision,
}

/// Arms one command into its control-bus message. Implementing this is
/// what wires a command into the runtime: the generic dispatcher owns the
/// send-and-await, and the compiler rejects a command that forgets the
/// arm.
pub(crate) trait CommandControl: Command {
  fn control(self, reply: oneshot::Sender<Result<Self::Output>>) -> Control;
}

/// Executes one typed command against the runtime. Every command arms
/// itself into one [`Control`] message via [`CommandControl`]; the
/// generic dispatcher owns the send-and-await.
pub(crate) trait DispatchCommand: Command {
  fn dispatch(self, runtime: &RuntimeClient) -> BoxFuture<'static, Result<Self::Output>>;
}

impl<C: CommandControl> DispatchCommand for C {
  fn dispatch(self, runtime: &RuntimeClient) -> BoxFuture<'static, Result<C::Output>> {
    let runtime = runtime.clone();
    Box::pin(async move { runtime.send_command(|reply| C::control(self, reply)).await })
  }
}

/// Arms one query into its control-bus message; see [`CommandControl`].
pub(crate) trait QueryControl: Query {
  fn control(self, reply: oneshot::Sender<Result<Self::Output>>) -> Control;
}

/// Executes one typed query against the runtime; see [`CommandControl`].
pub(crate) trait DispatchQuery: Query {
  fn dispatch(self, runtime: &RuntimeClient) -> BoxFuture<'static, Result<Self::Output>>;
}

impl<Q: QueryControl> DispatchQuery for Q {
  fn dispatch(self, runtime: &RuntimeClient) -> BoxFuture<'static, Result<Q::Output>> {
    let runtime = runtime.clone();
    Box::pin(async move { runtime.send_command(|reply| Q::control(self, reply)).await })
  }
}

// Lifecycle specials that do not ride the Result-wrapped control bus: an
// outcome-typed shutdown, a local status read, a shutdown wait, and a
// route-table read. Each keeps its dedicated dispatch.

impl DispatchCommand for Shutdown {
  fn dispatch(self, runtime: &RuntimeClient) -> BoxFuture<'static, Result<ShutdownOutcome>> {
    let runtime = runtime.clone();
    Box::pin(async move { runtime.shutdown().await })
  }
}

impl DispatchQuery for GetNodeStatus {
  fn dispatch(self, runtime: &RuntimeClient) -> BoxFuture<'static, Result<NodeStatus>> {
    let runtime = runtime.clone();
    Box::pin(async move { Ok(runtime.status()) })
  }
}

impl DispatchQuery for WaitForShutdown {
  fn dispatch(self, runtime: &RuntimeClient) -> BoxFuture<'static, Result<ShutdownReason>> {
    let runtime = runtime.clone();
    Box::pin(async move { runtime.wait_for_shutdown().await })
  }
}

impl DispatchQuery for GetRoute {
  fn dispatch(self, runtime: &RuntimeClient) -> BoxFuture<'static, Result<RouteStatusView>> {
    let handle = self.handle().clone();
    let runtime = runtime.clone();
    Box::pin(async move { runtime.route_status(&handle) })
  }
}

// Commands.

impl CommandControl for RotateMergeCredential {
  fn control(self, reply: oneshot::Sender<Result<IssuedMergeCredential>>) -> Control {
    Control::RotateMergeCredential { reply }
  }
}

impl CommandControl for Listen {
  fn control(self, reply: oneshot::Sender<Result<ListenerView>>) -> Control {
    let endpoint = self.into_endpoint();
    Control::Listen { endpoint, reply }
  }
}

impl CommandControl for StopListener {
  fn control(self, reply: oneshot::Sender<Result<()>>) -> Control {
    let listener = self.into_listener();
    Control::StopListener { listener, reply }
  }
}

impl CommandControl for MergeCluster {
  fn control(self, reply: oneshot::Sender<Result<MergeView>>) -> Control {
    let (receiver, credential) = self.into_parts();
    Control::MergeCluster {
      receiver,
      credential,
      reply,
    }
  }
}

impl CommandControl for ConnectMember {
  fn control(self, reply: oneshot::Sender<Result<NodeId>>) -> Control {
    let (receiver, peer) = self.into_parts();
    Control::ConnectMember {
      receiver,
      peer,
      reply,
    }
  }
}

impl CommandControl for StartRecovery {
  fn control(self, reply: oneshot::Sender<Result<crate::RecoveryView>>) -> Control {
    Control::StartRecovery { reply }
  }
}

impl CommandControl for DisconnectPeer {
  fn control(self, reply: oneshot::Sender<Result<()>>) -> Control {
    let peer = self.peer().clone();
    Control::DisconnectPeer { peer, reply }
  }
}

impl CommandControl for UpdateNodeMetadata {
  fn control(self, reply: oneshot::Sender<Result<crate::MemberView>>) -> Control {
    let (expected_revision, patch) = self.into_parts();
    Control::UpdateNodeMetadata {
      expected_revision,
      patch,
      reply,
    }
  }
}

impl CommandControl for crate::PutResource {
  fn control(self, reply: oneshot::Sender<Result<crate::ResourceMutationView>>) -> Control {
    let write = crate::PutResource::into_write(self);
    Control::PutResource { write, reply }
  }
}

impl CommandControl for crate::RevokeNode {
  fn control(self, reply: oneshot::Sender<Result<crate::RevokeOutcome>>) -> Control {
    let (subject, expected_key) = self.into_parts();
    Control::RevokeNode {
      subject,
      expected_key,
      reply,
    }
  }
}

impl CommandControl for crate::CleanupNode {
  fn control(self, reply: oneshot::Sender<Result<()>>) -> Control {
    let subject = self.into_subject();
    Control::CleanupNode { subject, reply }
  }
}

impl CommandControl for crate::IssueCleanupCheckpoint {
  fn control(self, reply: oneshot::Sender<Result<u64>>) -> Control {
    Control::IssueCleanupCheckpoint { reply }
  }
}

impl CommandControl for crate::ApplyReceiptRetention {
  fn control(self, reply: oneshot::Sender<Result<crate::view::ReceiptRetentionReport>>) -> Control {
    Control::ApplyReceiptRetention { reply }
  }
}

impl CommandControl for crate::RunSyncRound {
  fn control(self, reply: oneshot::Sender<Result<()>>) -> Control {
    Control::RunSyncRound { reply }
  }
}

impl CommandControl for crate::PurgeRevocation {
  fn control(self, reply: oneshot::Sender<Result<()>>) -> Control {
    let subject = self.into_subject();
    Control::PurgeRevocation { subject, reply }
  }
}

impl CommandControl for crate::RemoveResource {
  fn control(self, reply: oneshot::Sender<Result<crate::ResourceMutationView>>) -> Control {
    let (name, expected) = self.into_parts();
    Control::RemoveResource {
      name,
      expected,
      reply,
    }
  }
}

impl CommandControl for crate::LeaveCluster {
  fn control(self, reply: oneshot::Sender<Result<crate::LeaveOutcome>>) -> Control {
    let acknowledgement = *self.acknowledgement();
    Control::LeaveCluster {
      acknowledgement,
      reply,
    }
  }
}

// Queries.

impl QueryControl for GetObservability {
  fn control(self, reply: oneshot::Sender<Result<crate::ObservabilitySnapshot>>) -> Control {
    Control::Observability { reply }
  }
}

impl QueryControl for GetLocalNode {
  fn control(self, reply: oneshot::Sender<Result<LocalNodeView>>) -> Control {
    Control::GetLocalNode { reply }
  }
}

impl QueryControl for GetMember {
  fn control(self, reply: oneshot::Sender<Result<Option<crate::MemberView>>>) -> Control {
    let node = self.node().clone();
    Control::GetMember { node, reply }
  }
}

impl QueryControl for PageMembers {
  fn control(self, reply: oneshot::Sender<Result<crate::MemberPage>>) -> Control {
    let page = self.page();
    let cursor = page.cursor().cloned();
    let limit = page.limit();
    Control::PageMembers {
      cursor,
      limit,
      reply,
    }
  }
}

impl QueryControl for SelectResources {
  fn control(self, reply: oneshot::Sender<Result<crate::ResourcePage>>) -> Control {
    let selector = self.selector().clone();
    let page = self.page();
    let cursor = page.cursor().cloned();
    let limit = page.limit();
    Control::SelectResources {
      selector,
      cursor,
      limit,
      reply,
    }
  }
}

impl QueryControl for crate::GetResource {
  fn control(self, reply: oneshot::Sender<Result<Option<crate::ResourceView>>>) -> Control {
    let name = self.name().clone();
    Control::GetResource { name, reply }
  }
}

impl QueryControl for crate::PageResources {
  fn control(self, reply: oneshot::Sender<Result<crate::ResourcePage>>) -> Control {
    let page = self.page();
    let cursor = page.cursor().cloned();
    let limit = page.limit();
    Control::PageResources {
      cursor,
      limit,
      reply,
    }
  }
}

impl QueryControl for crate::PageListeners {
  fn control(self, reply: oneshot::Sender<Result<crate::ListenerPage>>) -> Control {
    let page = self.page();
    let cursor = page.cursor().cloned();
    let limit = page.limit();
    Control::PageListeners {
      cursor,
      limit,
      reply,
    }
  }
}

impl QueryControl for crate::PageSessions {
  fn control(self, reply: oneshot::Sender<Result<crate::SessionPage>>) -> Control {
    let page = self.page();
    let cursor = page.cursor().cloned();
    let limit = page.limit();
    Control::PageSessions {
      cursor,
      limit,
      reply,
    }
  }
}

impl QueryControl for PageTopology {
  fn control(self, reply: oneshot::Sender<Result<crate::TopologyPage>>) -> Control {
    let page = self.page();
    let cursor = page.cursor().cloned();
    let limit = page.limit();
    Control::PageTopology {
      cursor,
      limit,
      reply,
    }
  }
}

impl QueryControl for PageTrust {
  fn control(self, reply: oneshot::Sender<Result<crate::TrustPage>>) -> Control {
    let page = self.page();
    let cursor = page.cursor().cloned();
    let limit = page.limit();
    Control::PageTrust {
      cursor,
      limit,
      reply,
    }
  }
}

impl NodeHandle {
  pub(crate) fn new(
    runtime: RuntimeClient, entropy: Arc<dyn Entropy>, extensions: Arc<ExtensionRegistry>,
    events: Arc<crate::node::EventHub>, member_revision: crate::node::MemberRevision,
  ) -> Self {
    Self {
      runtime,
      entropy,
      extensions,
      events,
      member_revision,
    }
  }

  /// Opens an outbound stream, allocating its core-generated [`TraceId`]
  /// synchronously from the injected entropy. No body delivery starts
  /// until [`OutboundStream::send_sync`] or [`OutboundStream::send_async`]
  /// consumes the body.
  ///
  /// An exact-node target rejects a load-balancer selection; a
  /// matching-node target requires one whose tag resolves in the node's
  /// [`ExtensionRegistry`] (T-G06-01). The routing policy must resolve to
  /// the built-in direct policy, and the protocol tag must be registered.
  pub fn open_stream(
    &self, target: StreamTarget, protocol: ProtocolTag, policy: StreamPolicy,
    metadata: StreamMetadata,
  ) -> Result<OutboundStream> {
    let load_balancer = match (&target, policy.load_balancing_policy()) {
      (StreamTarget::Exact(_), Some(_)) => {
        return Err(Error::invalid_input("packet load balancer"));
      }
      (StreamTarget::Exact(_), None) => None,
      (StreamTarget::MatchingNodes(_), None) => {
        return Err(Error::invalid_input("packet load balancer"));
      }
      (StreamTarget::MatchingNodes(_), Some(tag)) => {
        // Every referenced policy tag must resolve in the registry.
        if !self.extensions.has_load_balancer(tag) {
          return Err(Error::invalid_input("packet load balancer"));
        }
        Some(tag.clone())
      }
    };
    if !self.extensions.has_protocol(&protocol) {
      return Err(Error::unsupported("packet protocol"));
    }
    let trace_id = TraceId::generate(self.entropy.as_ref())?;
    Ok(OutboundStream::new(
      trace_id,
      target,
      load_balancer,
      policy.max_hops(),
      protocol,
      metadata,
      self.runtime.clone(),
    ))
  }

  /// Dispatches one typed command to the runtime. The bound is satisfied by
  /// every crate-defined command; callers only name the concrete command
  /// type.
  #[allow(private_bounds)]
  pub async fn command<C: Command + DispatchCommand>(&self, command: C) -> Result<C::Output> {
    command.dispatch(&self.runtime).await
  }

  #[allow(private_bounds)]
  pub async fn query<Q: Query + DispatchQuery>(&self, query: Q) -> Result<Q::Output> {
    query.dispatch(&self.runtime).await
  }

  /// Subscribes to node events (T-G09-03). Subscriptions are bounded and
  /// transient: a lagging subscriber observes `EventReceive::Lagged` and
  /// must re-read through the paged queries.
  pub fn events<E: Event>(&self, options: EventOptions) -> Result<EventSubscription<E>> {
    if self.runtime.status() != NodeStatus::Running {
      return Err(Error::shutting_down("node events"));
    }
    Ok(self.events.subscribe::<E>(options))
  }

  /// Subscribes to this node's member-set revision. Unlike the transient
  /// event stream, the revision is value-based state: a watcher created
  /// before an action observes every later change, and a watcher created
  /// after it reads the current revision immediately. Await
  /// `MemberRevision::changed` after driving an operation instead of
  /// polling the member pages with wall-clock sleeps.
  pub fn member_revision(&self) -> crate::node::MemberRevision {
    self.member_revision.clone()
  }

  /// Runs one full anti-entropy round now (membership pages, the issuer
  /// trust snapshot, and resource pages over every authenticated session)
  /// and completes when the round finishes. The convergence check
  /// becomes deterministic: drive a round, await it, then read the
  /// pages — no interval-cadence sleeps.
  pub fn run_sync_round(&self) -> impl Future<Output = Result<()>> + Send {
    crate::RunSyncRound::new().dispatch(&self.runtime)
  }
}
