//! Paged reads and point views on the node's observed state: members,
//! resources, listeners, sessions, topology, trust, and observability.
//! Pure observation over the signed descriptor stores and the session
//! table; no state transition lives here.

use tokio::task::JoinSet;

use super::supervisor::Supervisor;
use crate::{Error, LocalNodeView, NodeId, Result};

/// The shared tail of the keyset-paged views: wraps the scan's next key
/// into the opaque page cursor and assembles the page through the
/// caller's page constructor.
fn finish_page<T, P>(
  paged: crate::paging::Paged<T>, page: impl FnOnce(Vec<T>, Option<crate::PageCursor>) -> P,
) -> P {
  let next = paged
    .next
    .map(|key| crate::PageCursor::new(std::sync::Arc::from(key)));
  page(paged.items, next)
}

impl Supervisor {
  /// One member's public observation from the signed descriptor store and
  /// the session table.
  pub(super) async fn member(&mut self, node: NodeId) -> Result<Option<crate::MemberView>> {
    self.ensure_self_descriptor().await?;
    let connected = self
      .dependencies
      .sessions
      .lock()
      .map_err(Error::session_table)?
      .contains_key(&node);
    let Some(descriptor) =
      crate::membership::store::read_descriptor_ctx(self.context()?.store(), &node).await?
    else {
      return Ok(None);
    };
    Ok(Some(crate::membership::member_view(
      &descriptor,
      if connected {
        crate::ConnectivityStatus::Connected
      } else {
        crate::ConnectivityStatus::Reachable
      },
    )?))
  }
  /// Pages the signed descriptors, annotating connectivity from the
  /// session table.
  pub(super) async fn page_members(
    &mut self, cursor: Option<crate::PageCursor>, limit: usize,
  ) -> Result<crate::MemberPage> {
    self.ensure_self_descriptor().await?;
    let limit = limit.clamp(1, crate::paging::MAX_VIEW_PAGE_ITEMS);
    // Snapshot the connected set under the lock, then release it before
    // any await so the supervisor future stays `Send`.
    let connected: std::collections::BTreeSet<NodeId> = self
      .dependencies
      .sessions
      .lock()
      .map_err(Error::session_table)?
      .keys()
      .cloned()
      .collect();
    let namespace = crate::StoreNamespace::new(crate::QualifiedTag::parse(
      crate::membership::NODE_DESCRIPTOR_NAMESPACE,
    )?);
    let snapshot = self.context()?.store().snapshot().await?;
    let mut scan = snapshot.scan(&namespace, &[]).await?;
    let paged = crate::paging::scan_paged(
      scan.as_mut(),
      cursor.as_ref().map(|cursor| cursor.as_bytes()),
      limit,
      |_key, bytes| {
        let descriptor = crate::membership::page::decode_descriptor(bytes)?;
        crate::membership::member_view(
          &descriptor,
          if connected.contains(descriptor.node()) {
            crate::ConnectivityStatus::Connected
          } else {
            crate::ConnectivityStatus::Reachable
          },
        )
        .map(Some)
      },
    )
    .await?;
    Ok(finish_page(paged, crate::MemberPage::new))
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
  /// Pages the node's bound listeners in canonical id order.
  pub(super) async fn page_listeners(
    &mut self, cursor: Option<crate::PageCursor>, limit: usize,
  ) -> Result<crate::ListenerPage> {
    let limit = limit.clamp(1, crate::paging::MAX_VIEW_PAGE_ITEMS);
    let entries = self
      .listeners
      .iter()
      .map(|(id, (endpoint, ..))| {
        (
          id.as_str().as_bytes().to_vec(),
          crate::ListenerView::new(id.clone(), endpoint.clone()),
        )
      })
      .collect::<Vec<_>>();
    let paged = crate::paging::page_keys(
      entries.into_iter(),
      cursor.as_ref().map(|cursor| cursor.as_bytes()),
      limit,
    );
    Ok(finish_page(paged, crate::ListenerPage::new))
  }
  /// Pages the live authenticated sessions in canonical peer order;
  /// selected features resolve their exact definition digests at query
  /// time.
  pub(super) async fn page_sessions(
    &mut self, cursor: Option<crate::PageCursor>, limit: usize,
  ) -> Result<crate::SessionPage> {
    let limit = limit.clamp(1, crate::paging::MAX_VIEW_PAGE_ITEMS);
    let entries: Vec<(Vec<u8>, crate::SessionView)> = {
      let sessions = self
        .dependencies
        .sessions
        .lock()
        .map_err(Error::session_table)?;
      sessions
        .iter()
        .filter(|(_, entry)| entry.alive())
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
      entries.into_iter(),
      cursor.as_ref().map(|cursor| cursor.as_bytes()),
      limit,
    );
    Ok(finish_page(paged, crate::SessionPage::new))
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
        .map_err(|_| Error::internal("route records"))?;
      routes.len()
    };
    let connection_tasks = self
      .dependencies
      .connection_tasks
      .lock()
      .map_err(|_| Error::internal("connection tasks"))?
      .len();
    let background_tasks = tasks.len() + connection_tasks + usize::from(self.sync_driver.is_some());
    let trace_records = self
      .trace_records
      .load(std::sync::atomic::Ordering::Relaxed);
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
      sessions,
      self.listeners.len(),
      background_tasks,
      queued_messages,
      queued_bytes,
      open_routes,
      trace_records,
      pending_transactions,
      storage_available,
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
        }),
      cursor.as_ref().map(|cursor| cursor.as_bytes()),
      limit,
    );
    Ok(finish_page(paged, crate::TopologyPage::new))
  }
  /// Pages the public trust observations: the exact
  /// NodeId-to-key bindings verified locally, deterministically ordered
  /// and bounded.
  pub(super) async fn page_trust(
    &mut self, cursor: Option<crate::PageCursor>, limit: usize,
  ) -> Result<crate::TrustPage> {
    let limit = limit.clamp(1, crate::paging::MAX_VIEW_PAGE_ITEMS);
    // Trust paging is offset-based (the trust store scans an ordered
    // namespace in slices) while the other views keyset-paginate. The
    // encoding still lives behind the opaque `PageCursor`, and a cursor
    // that does not decode exactly fails closed instead of restarting
    // the page at offset zero.
    let offset = match cursor.as_ref() {
      None => 0,
      Some(cursor) => std::str::from_utf8(cursor.as_bytes())
        .map_err(|_| Error::invalid_input("trust page cursor"))?
        .parse::<usize>()
        .map_err(|_| Error::invalid_input("trust page cursor"))?,
    };
    let context = self.context()?;
    let observations =
      crate::identity::trust::store::paged_trust_ctx(context.store(), offset, limit).await?;
    let mut items = Vec::with_capacity(observations.bindings().len());
    for binding in observations.bindings() {
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
    let next = observations
      .next()
      .map(|next| crate::PageCursor::new(std::sync::Arc::from(next.to_string().into_bytes())));
    Ok(crate::TrustPage::new(items, next))
  }
  pub(super) async fn local_node(&mut self) -> Result<LocalNodeView> {
    let context = self.context()?;
    Ok(LocalNodeView::new(
      context.identity().node().clone(),
      context.identity().public_key().clone(),
    ))
  }
}
