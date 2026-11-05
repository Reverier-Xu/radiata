//! Paged reads and point views on the node's observed state: members,
//! resources, listeners, sessions, topology, trust, and observability.
//! Pure observation over the signed descriptor stores and the session
//! table. One deliberate nuance: a member query SCHEDULES the local
//! descriptor's lazy publication (single flight, off the supervisor's
//! select loop) instead of awaiting
//! it, so a slow descriptor commit can never park the control plane
//! behind a member read. The query answers from committed state only:
//! the single kicking read on a node that never bound a listener may
//! not yet include the local node, while the scheduled publication
//! lands with its paired [`crate::MemberChanged`] event and revision
//! bump (the one-to-one promise lives in the ensure itself). Listener
//! transitions publish synchronously in the listen effect, so a read
//! after a bound listener still observes the local node
//! deterministically.

use tokio::task::JoinSet;

use super::supervisor::Supervisor;
use crate::{Error, LocalNodeView, NodeId, Result};

/// The connected-peer set of one view read: a session whose reader loop
/// ended (`alive == false`, entry not yet removed) is not a connected
/// peer. The exact member lookup, the member page, and the session page
/// all read connectivity through this one filter so they cannot
/// disagree about the same session table.
fn connected_peers(
  sessions: &crate::session::stream::SessionTable,
) -> Result<std::collections::BTreeSet<NodeId>> {
  Ok(
    sessions
      .lock()
      .map_err(Error::session_table)?
      .iter()
      .filter(|(_, entry)| entry.alive())
      .map(|(peer, _)| peer.clone())
      .collect(),
  )
}

impl Supervisor {
  /// Schedules the local descriptor's lazy publication without awaiting
  /// it: the member read views stay
  /// pure reads, and the publication's storage IO — which
  /// awaited inline in this loop would park every control-plane operation
  /// behind a slow descriptor commit — runs in the single-flight task
  /// the kick schedules (at most one alive; none in steady state). The
  /// listener transition publishes synchronously in the listen effect,
  /// so a read that follows a bound listener observes the local node
  /// deterministically.
  fn kick_self_descriptor(&self) {
    if let Some(operations) = self.dependencies.operations.as_ref() {
      super::task_effects::kick_self_descriptor_publication(operations);
    }
  }

  /// One member's public observation from the signed descriptor store and
  /// the session table. The removal status comes from the same memoized
  /// departed set the member page annotates with, so the exact lookup and
  /// the page agree.
  pub(super) async fn member(&mut self, node: NodeId) -> Result<Option<crate::MemberView>> {
    self.kick_self_descriptor();
    let connected = connected_peers(&self.dependencies.sessions)?.contains(&node);
    let Some(descriptor) =
      crate::membership::store::read_descriptor_ctx(self.context()?.store(), &node).await?
    else {
      return Ok(None);
    };
    let context = self.context()?;
    let status = self
      .departed_exclusions(context.store())
      .await?
      .status(&node);
    let connectivity = crate::membership::member_connectivity(connected);
    Ok(Some(
      crate::membership::member_view(&descriptor, connectivity)?.with_status(status),
    ))
  }
  /// Pages the signed descriptors, annotating connectivity from the
  /// session table.
  pub(super) async fn page_members(
    &mut self, cursor: Option<crate::PageCursor>, limit: usize,
  ) -> Result<crate::MemberPage> {
    self.kick_self_descriptor();
    let limit = limit.clamp(1, crate::paging::MAX_VIEW_PAGE_ITEMS);
    // Snapshot the connected set under the lock, then release it before
    // any await so the supervisor future stays `Send`.
    let connected = connected_peers(&self.dependencies.sessions)?;
    let namespace = crate::membership::descriptor_namespace()?;
    // The removal state comes from the terminal-record stores, collected
    // once per page: the descriptor store deliberately retains left and
    // cleaned members as verification evidence, so the page annotates
    // their status instead of filtering them.
    let context = self.context()?;
    let store = context.store();
    let departed = self.departed_exclusions(store).await?;
    let snapshot = store.snapshot().await?;
    let paged = crate::paging::scan_paged(
      snapshot.as_ref(),
      &namespace,
      &[],
      cursor.as_ref().map(|cursor| cursor.as_bytes()),
      limit,
      |_key, bytes| {
        let descriptor = crate::membership::page::decode_descriptor(bytes)?;
        let status = departed.status(descriptor.node());
        let connectivity =
          crate::membership::member_connectivity(connected.contains(descriptor.node()));
        crate::membership::member_view(&descriptor, connectivity)
          .map(|view| Some(view.with_status(status)))
      },
    )
    .await?;
    crate::paging::finish_page(paged, crate::MemberPage::new)
  }
  /// Pages the live resource winners matching one selector.
  pub(super) async fn select_resources(
    &mut self, selector: &crate::Selector, cursor: Option<crate::PageCursor>, limit: usize,
  ) -> Result<crate::ResourcePage> {
    crate::resource::select::select_page_ctx(
      self.context()?.store(),
      selector,
      cursor.as_ref(),
      limit,
    )
    .await
  }
  /// Pages every live resource winner in canonical name order:
  /// the reserved type label is always present, so its existence selector
  /// is exactly the unfiltered catalog.
  pub(super) async fn page_resources(
    &mut self, cursor: Option<crate::PageCursor>, limit: usize,
  ) -> Result<crate::ResourcePage> {
    let all = crate::Selector::parse(crate::resource::RESERVED_TYPE_LABEL_KEY)?;
    self.select_resources(&all, cursor, limit).await
  }
  /// Reads the live winner of one named resource; a removed or
  /// unknown name reads as absent.
  pub(super) async fn get_resource(
    &mut self, name: &crate::ResourceName,
  ) -> Result<Option<crate::ResourceView>> {
    let record = crate::resource::store::read_record_ctx(self.context()?.store(), name).await?;
    Ok(match record {
      Some(record) if !record.removed() => Some(crate::resource::select::resource_view(&record)),
      _ => None,
    })
  }
  /// Creates one watch over the durable resource change feed: `None`
  /// starts at the current head, `Some(version)` replays the entries after
  /// that version and then follows live commits. The watch holds the
  /// store, so it reads the persisted feed rather than a process-local
  /// buffer and survives a restart.
  pub(super) async fn watch_resources(
    &mut self, from: Option<u64>,
  ) -> Result<crate::ResourceWatch> {
    crate::ResourceWatch::subscribe(self.context()?.store_handle(), from).await
  }
  /// Pages the node's bound listeners in canonical id order.
  pub(super) async fn page_listeners(
    &mut self, cursor: Option<crate::PageCursor>, limit: usize,
  ) -> Result<crate::ListenerPage> {
    let limit = limit.clamp(1, crate::paging::MAX_VIEW_PAGE_ITEMS);
    let entries = self
      .dependencies
      .listeners
      .lock()
      .map_err(Error::listener_registry)?
      .iter()
      .map(|(id, (endpoint, ..))| {
        (
          id.as_str().as_bytes().to_vec(),
          crate::ListenerView::new(id.clone(), endpoint.clone()),
        )
      })
      .collect::<Vec<_>>();
    let paged = crate::paging::page_keys(
      entries,
      cursor.as_ref().map(|cursor| cursor.as_bytes()),
      limit,
    );
    crate::paging::finish_page(paged, crate::ListenerPage::new)
  }
  /// Pages the live authenticated sessions in canonical peer order;
  /// selected features resolve their exact definition digests at query
  /// time.
  pub(super) async fn page_sessions(
    &mut self, cursor: Option<crate::PageCursor>, limit: usize,
  ) -> Result<crate::SessionPage> {
    let limit = limit.clamp(1, crate::paging::MAX_VIEW_PAGE_ITEMS);
    let connected = connected_peers(&self.dependencies.sessions)?;
    let entries: Vec<(Vec<u8>, crate::SessionView)> = {
      let sessions = self
        .dependencies
        .sessions
        .lock()
        .map_err(Error::session_table)?;
      sessions
        .iter()
        .filter(|(peer, _)| connected.contains(*peer))
        .map(|(peer, entry)| {
          let features = entry
            .meta
            .features
            .iter()
            .filter_map(|tag| {
              self
                .dependencies
                .extensions
                .feature_digest(tag)
                .map(|digest| crate::SessionFeatureView::new(tag.clone(), digest))
            })
            .collect();
          (
            peer.as_str().as_bytes().to_vec(),
            crate::SessionView::new(
              entry.meta.id.clone(),
              entry.meta.generation,
              peer.clone(),
              entry.meta.endpoint.clone(),
              features,
            ),
          )
        })
        .collect()
    };
    let paged = crate::paging::page_keys(
      entries,
      cursor.as_ref().map(|cursor| cursor.as_bytes()),
      limit,
    );
    crate::paging::finish_page(paged, crate::SessionPage::new)
  }
  /// The bounded observability snapshot:
  /// session/listener/task counters, queue totals, route and trace
  /// counters, the pending-transaction count, and metadata-store
  /// availability, captured at the local host wall clock. Counters and
  /// flags only; the snapshot never enumerates a whole population and
  /// carries no identity, address, path, selector, body, or credential
  /// material.
  pub(super) async fn observability_snapshot(
    &mut self, tasks: &JoinSet<()>,
  ) -> Result<crate::ObservabilitySnapshot> {
    let Some(context) = self.dependencies.context.clone() else {
      return Err(Error::not_ready("observability snapshot"));
    };
    let (sessions, queued_messages, queued_bytes, audit_delta) = {
      let table = self
        .dependencies
        .sessions
        .lock()
        .map_err(Error::session_table)?;
      let messages = table.values().map(|entry| entry.queued_messages()).sum();
      let bytes = table.values().map(|entry| entry.queued_bytes()).sum();
      let audit: usize = table.values().map(|entry| entry.queue_audit_delta()).sum();
      (table.len(), messages, bytes, audit)
    };
    let open_routes = {
      let routes = self
        .dependencies
        .routes
        .lock()
        .map_err(Error::route_records)?;
      routes.len()
    };
    let connection_tasks = self
      .dependencies
      .connection_tasks
      .lock()
      .map_err(Error::connection_tasks)?
      .len();
    let background_tasks = tasks.len() + connection_tasks + usize::from(self.sync_driver.is_some());
    let trace_records = self
      .trace_records
      .load(std::sync::atomic::Ordering::Relaxed);
    let trace_records_dropped = self.trace_sink.dropped();
    let pending_transactions =
      crate::storage::pending::pending_transaction_count(context.store()).await?;
    let storage_available = !context.store().is_blocked()?;
    if queued_messages > 0 || audit_delta != queued_messages {
      tracing::warn!(
        queued_messages,
        queued_bytes,
        audit_reserved_minus_removed = audit_delta,
        "runtime status: queued session frames"
      );
    }
    crate::ObservabilitySnapshot::new(
      std::time::SystemTime::now(),
      crate::view::ObservabilityCounts {
        sessions,
        listeners: self
          .dependencies
          .listeners
          .lock()
          .map(|listeners| listeners.len())
          .unwrap_or(0),
        background_tasks,
        queued_session_messages: queued_messages,
        queued_session_bytes: queued_bytes,
        open_routes,
        trace_records,
        trace_records_dropped,
        pending_transactions,
        storage_available,
      },
    )
  }
  /// Pages the authenticated sessions as directed topology edges.
  pub(super) async fn page_topology(
    &mut self, cursor: Option<crate::PageCursor>, limit: usize,
  ) -> Result<crate::TopologyPage> {
    let limit = limit.clamp(1, crate::paging::MAX_VIEW_PAGE_ITEMS);
    // Build the edge list entirely under the lock (no await inside), so the
    // guard drops before the future completes.
    let context_node = self.context()?.identity().node().clone();
    let paged = crate::paging::page_keys(
      self
        .dependencies
        .sessions
        .lock()
        .map_err(Error::session_table)?
        .iter()
        .map(|(peer, entry)| {
          (
            peer.as_str().as_bytes().to_vec(),
            crate::TopologyEdgeView::new(
              context_node.clone(),
              peer.clone(),
              entry.alive(),
              std::time::SystemTime::now(),
            ),
          )
        })
        .collect::<Vec<_>>(),
      cursor.as_ref().map(|cursor| cursor.as_bytes()),
      limit,
    );
    crate::paging::finish_page(paged, crate::TopologyPage::new)
  }
  /// Pages the public trust observations: the exact
  /// NodeId-to-key bindings verified locally, deterministically ordered
  /// and bounded (keyset-paginated like every other view).
  pub(super) async fn page_trust(
    &mut self, cursor: Option<crate::PageCursor>, limit: usize,
  ) -> Result<crate::TrustPage> {
    let limit = limit.clamp(1, crate::paging::MAX_VIEW_PAGE_ITEMS);
    let context = self.context()?;
    let paged = crate::identity::trust::store::paged_trust_ctx(
      context.store(),
      cursor.as_ref().map(|cursor| cursor.as_bytes()),
      limit,
    )
    .await?;
    let mut items = Vec::with_capacity(paged.items.len());
    for binding in &paged.items {
      // A locally revoked binding reports its exact status; the binding
      // itself is never erased (revoke is an authorization boundary, not
      // content erasure).
      let status = match crate::identity::revocation::revoked_key_ctx(
        context.store(),
        binding.node(),
      )
      .await?
      {
        Some(revoked) if &revoked == binding.key() => crate::TrustStatus::Revoked,
        _ => crate::TrustStatus::Trusted,
      };
      items.push(crate::TrustedIdentityView::new(
        binding.node().clone(),
        binding.key().clone(),
        status,
      ));
    }
    crate::paging::finish_page(
      crate::paging::Paged {
        items,
        next: paged.next,
      },
      crate::TrustPage::new,
    )
  }
  pub(super) async fn local_node(&mut self) -> Result<LocalNodeView> {
    let context = self.context()?;
    Ok(LocalNodeView::new(
      context.identity().node().clone(),
      context.identity().public_key().clone(),
    ))
  }
}

#[cfg(test)]
mod connectivity_tests {
  use std::sync::Arc;

  use crate::{
    ConnectivityStatus,
    runtime::supervisor::test_support::{
      install_member, member_id, reference_and_config, supervisor_over,
    },
  };

  /// A session entry whose reader loop ended (`alive == false`, entry not
  /// yet removed) is not a connected peer: the exact member lookup and
  /// the member page report the same `Reachable` connectivity for it.
  #[tokio::test]
  async fn a_dead_session_entry_is_not_reported_connected() {
    let (reference, config) = reference_and_config();
    let (mut supervisor, entropy, sessions) = supervisor_over(
      Arc::clone(&reference) as Arc<dyn crate::provider::StorageFactory>,
      config,
    )
    .await;
    let peer = member_id(7);
    install_member(&supervisor, &reference, 7, &[9_443]).await;

    // The session's reader loop ended: the entry stays in the table until
    // its teardown removes it, but it no longer serves the connection.
    let entry = crate::session::stream::SessionEntry::synthetic_entry(
      entropy.as_ref(),
      crate::Endpoint::parse("wss://127.0.0.1:9").expect("test endpoint"),
      crate::session::stream::DialClass::Caller,
    )
    .expect("synthetic session entry");
    crate::session::stream::retire(&entry);
    assert!(!entry.alive(), "the fixture entry must be dead");
    sessions
      .lock()
      .expect("session table")
      .insert(peer.clone(), entry);

    let view = supervisor
      .member(peer.clone())
      .await
      .expect("member lookup")
      .expect("the installed member has a descriptor");
    assert_eq!(view.connectivity(), ConnectivityStatus::Reachable);

    let page = supervisor.page_members(None, 8).await.expect("member page");
    let paged = page
      .items()
      .iter()
      .find(|view| view.node_id() == &peer)
      .expect("the installed member is on the page");
    assert_eq!(paged.connectivity(), ConnectivityStatus::Reachable);
  }
}

#[cfg(test)]
mod shared_table_poison_tests {
  use std::sync::Arc;

  use tokio::task::JoinSet;

  use crate::{ErrorKind, NodeConfig, runtime::supervisor::test_support::supervisor_over};

  /// A poisoned connection-task list reports the list's named internal
  /// error instead of a generic one: the lock-poison diagnostic stays
  /// uniform with the other shared tables.
  #[tokio::test]
  async fn observability_snapshot_reports_the_named_connection_tasks_error_on_a_poisoned_list() {
    let reference = Arc::new(crate::storage::contract::ReferenceFactory::new(
      crate::storage::contract::required_capabilities(),
    ));
    let (mut supervisor, _entropy, _sessions) = supervisor_over(
      reference as Arc<dyn crate::provider::StorageFactory>,
      NodeConfig::new(),
    )
    .await;
    let poisoner = Arc::clone(&supervisor.dependencies.connection_tasks);
    let _ = std::thread::spawn(move || {
      let _guard = poisoner.lock().expect("connection tasks guard");
      panic!("poison the connection tasks");
    })
    .join();

    let error = supervisor
      .observability_snapshot(&JoinSet::new())
      .await
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Internal);
    assert_eq!(error.context(), "connection tasks");
  }
}
