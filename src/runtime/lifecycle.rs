use tokio::sync::{mpsc, oneshot, watch};

use crate::{
  Endpoint, Error, IssuedMergeCredential, ListenerView, LocalNodeView, MergeView, NodeId,
  NodeStatus, Result, RouteStatusView, ShutdownOutcome, ShutdownReason,
  identity::{ListenerId, credential::MergeCredential},
  packet::{OutboundRequest, RouteHandle},
  routing::RouteTable,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LifecycleSnapshot {
  status: NodeStatus,
  reason: Option<ShutdownReason>,
}

impl LifecycleSnapshot {
  pub(crate) const fn starting() -> Self {
    Self {
      status: NodeStatus::Starting,
      reason: None,
    }
  }

  pub(crate) const fn running() -> Self {
    Self {
      status: NodeStatus::Running,
      reason: None,
    }
  }

  pub(crate) const fn shutting_down() -> Self {
    Self {
      status: NodeStatus::ShuttingDown,
      reason: None,
    }
  }

  pub(crate) const fn stopped(reason: ShutdownReason) -> Self {
    Self {
      status: NodeStatus::Stopped,
      reason: Some(reason),
    }
  }

  pub(crate) const fn failed() -> Self {
    Self {
      status: NodeStatus::Failed,
      reason: Some(ShutdownReason::Fatal(crate::ErrorKind::Internal)),
    }
  }

  pub(crate) const fn status(self) -> NodeStatus {
    self.status
  }

  pub(crate) const fn reason(self) -> Option<ShutdownReason> {
    self.reason
  }
}

pub(crate) enum Control {
  Shutdown {
    reply: oneshot::Sender<ShutdownOutcome>,
  },
  RotateMergeCredential {
    reply: oneshot::Sender<Result<IssuedMergeCredential>>,
  },
  Listen {
    endpoint: Endpoint,
    reply: oneshot::Sender<Result<ListenerView>>,
  },
  StopListener {
    listener: ListenerId,
    reply: oneshot::Sender<Result<()>>,
  },
  MergeCluster {
    receiver: Endpoint,
    credential: MergeCredential,
    reply: oneshot::Sender<Result<MergeView>>,
  },
  ConnectMember {
    receiver: Endpoint,
    peer: NodeId,
    reply: oneshot::Sender<Result<NodeId>>,
  },
  GetLocalNode {
    reply: oneshot::Sender<Result<LocalNodeView>>,
  },
  GetMember {
    node: NodeId,
    reply: oneshot::Sender<Result<Option<crate::MemberView>>>,
  },
  PageMembers {
    cursor: Option<crate::PageCursor>,
    limit: usize,
    reply: oneshot::Sender<Result<crate::MemberPage>>,
  },
  SelectResources {
    selector: crate::Selector,
    cursor: Option<crate::PageCursor>,
    limit: usize,
    reply: oneshot::Sender<Result<crate::ResourcePage>>,
  },
  GetResource {
    name: crate::ResourceName,
    reply: oneshot::Sender<Result<Option<crate::ResourceView>>>,
  },
  PageResources {
    cursor: Option<crate::PageCursor>,
    limit: usize,
    reply: oneshot::Sender<Result<crate::ResourcePage>>,
  },
  PageListeners {
    cursor: Option<crate::PageCursor>,
    limit: usize,
    reply: oneshot::Sender<Result<crate::ListenerPage>>,
  },
  PageSessions {
    cursor: Option<crate::PageCursor>,
    limit: usize,
    reply: oneshot::Sender<Result<crate::SessionPage>>,
  },
  PageTopology {
    cursor: Option<crate::PageCursor>,
    limit: usize,
    reply: oneshot::Sender<Result<crate::TopologyPage>>,
  },
  PageTrust {
    cursor: Option<crate::PageCursor>,
    limit: usize,
    reply: oneshot::Sender<Result<crate::TrustPage>>,
  },
  StartRecovery {
    reply: oneshot::Sender<Result<crate::RecoveryView>>,
  },
  DisconnectPeer {
    peer: NodeId,
    reply: oneshot::Sender<Result<()>>,
  },
  UpdateNodeMetadata {
    expected_revision: u64,
    patch: crate::NodeMetadataPatch,
    reply: oneshot::Sender<Result<crate::MemberView>>,
  },
  PutResource {
    write: crate::ResourceWrite,
    reply: oneshot::Sender<Result<crate::ResourceMutationView>>,
  },
  RevokeNode {
    subject: NodeId,
    expected_key: crate::PublicKey,
    reply: oneshot::Sender<Result<crate::RevokeOutcome>>,
  },
  PurgeRevocation {
    subject: NodeId,
    reply: oneshot::Sender<Result<()>>,
  },
  CleanupNode {
    subject: NodeId,
    reply: oneshot::Sender<Result<()>>,
  },
  IssueCleanupCheckpoint {
    reply: oneshot::Sender<Result<u64>>,
  },
  ApplyReceiptRetention {
    reply: oneshot::Sender<Result<crate::view::ReceiptRetentionReport>>,
  },
  RunSyncRound {
    reply: oneshot::Sender<Result<()>>,
  },
  RemoveResource {
    name: crate::ResourceName,
    expected: crate::ResourceVersion,
    reply: oneshot::Sender<Result<crate::ResourceMutationView>>,
  },
  LeaveCluster {
    acknowledgement: crate::ReplaceIdentityAndDeleteOldCoreMetadata,
    reply: oneshot::Sender<Result<crate::LeaveOutcome>>,
  },
  Observability {
    reply: oneshot::Sender<Result<crate::ObservabilitySnapshot>>,
  },
}

#[derive(Clone)]
pub(crate) struct RuntimeClient {
  control: Option<mpsc::Sender<Control>>,
  state: watch::Receiver<LifecycleSnapshot>,
  routes: RouteTable,
  packet: mpsc::Sender<OutboundRequest>,
}

impl RuntimeClient {
  pub(crate) fn new(
    control: mpsc::Sender<Control>, state: watch::Receiver<LifecycleSnapshot>, routes: RouteTable,
    packet: mpsc::Sender<OutboundRequest>,
  ) -> Self {
    Self {
      control: Some(control),
      state,
      routes,
      packet,
    }
  }

  /// A routing-only client for the packet session context: it can route
  /// outbound packets but holds no node-command sender, so an admitted
  /// packet's reply capability never keeps the supervisor's command
  /// channel open after the last `NodeHandle` drops.
  pub(crate) fn routing_only(packet: mpsc::Sender<OutboundRequest>, routes: RouteTable) -> Self {
    Self {
      control: None,
      state: watch::channel(LifecycleSnapshot::running()).1,
      routes,
      packet,
    }
  }

  pub(crate) fn status(&self) -> NodeStatus {
    self.state.borrow().status()
  }

  pub(crate) async fn shutdown(&self) -> Result<ShutdownOutcome> {
    if let Some(reason) = self.state.borrow().reason() {
      return Ok(ShutdownOutcome::new(reason));
    }

    let (reply, response) = oneshot::channel();
    let Some(control) = self.control.as_ref() else {
      return Err(Error::not_ready("node command channel"));
    };
    if control.send(Control::Shutdown { reply }).await.is_err() {
      return self.wait_for_shutdown().await.map(ShutdownOutcome::new);
    }

    match response.await {
      Ok(outcome) => Ok(outcome),
      Err(_) => self.wait_for_shutdown().await.map(ShutdownOutcome::new),
    }
  }

  pub(crate) async fn send_command<Output, Build>(&self, build: Build) -> Result<Output>
  where
    Build: FnOnce(oneshot::Sender<Result<Output>>) -> Control,
    Output: Send + 'static, {
    let (reply, response) = oneshot::channel();
    let control = self
      .control
      .as_ref()
      .ok_or_else(|| Error::not_ready("node command channel"))?;
    control
      .send(build(reply))
      .await
      .map_err(|_| Error::shutting_down("node control"))?;
    response
      .await
      .map_err(|_| Error::internal("node control reply"))?
  }

  /// Hands one outbound packet to the supervisor over the dedicated packet
  /// routing channel; routing outcomes flow back through the request's
  /// acknowledgement channel and route records, never through the node
  /// command bus.
  pub(crate) async fn send_packet(&self, request: OutboundRequest) -> Result<()> {
    self
      .packet
      .send(request)
      .await
      .map_err(|_| Error::shutting_down("node routing"))
  }

  /// The non-blocking variant behind `send_async`: queue saturation is a
  /// typed overload, never an unbounded queue.
  pub(crate) fn try_send_packet(&self, request: OutboundRequest) -> Result<()> {
    self.packet.try_send(request).map_err(|error| match error {
      mpsc::error::TrySendError::Full(_) => Error::overloaded("node routing"),
      mpsc::error::TrySendError::Closed(_) => Error::shutting_down("node routing"),
    })
  }

  /// Reads one in-memory route record (ADR-0007: bounded trace metadata
  /// only, no durability claim).
  pub(crate) fn route_status(&self, handle: &RouteHandle) -> Result<RouteStatusView> {
    let routes = self
      .routes
      .lock()
      .map_err(|_| Error::internal("route records"))?;
    let record = routes
      .get(handle.trace_id())
      .ok_or_else(|| Error::not_found("route"))?;
    Ok(record.view())
  }

  pub(crate) async fn wait_for_shutdown(&self) -> Result<ShutdownReason> {
    let mut state = self.state.clone();
    loop {
      if let Some(reason) = state.borrow().reason() {
        return Ok(reason);
      }
      state
        .changed()
        .await
        .map_err(|_| Error::internal("node shutdown state"))?;
    }
  }
}
