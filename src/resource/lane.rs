//! The resources lane's reconciliation policy: the resource-record
//! namespace, its row projection, its retention-reclaimed evidence, and
//! its page-batch apply.
//!
//! The lane carries one row per resource record, keyed by the resource
//! name. A row is trusted through the authenticated session that delivered
//! it (the register's own stance), so no writer descriptor is resolved and
//! no row is deferred behind one. The retention deadline is the reclaim
//! basis the sweep itself enforces: an expired removal whose key the store
//! no longer holds is reclaimed knowledge, while a fresh deletion stays
//! legitimate evidence on a node that never held the resource.

use crate::{
  NodeId, Result,
  api::BoxFuture,
  provider::StoreSnapshot,
  reconcile::{
    lane::{Lane, LaneContext, LaneOutcome, LaneRows, ScanFilters, scan_namespaces},
    wire::LaneId,
  },
  runtime::RuntimeClient,
};

/// The resource-metadata lane.
#[derive(Debug)]
pub(crate) struct ResourcesLane;

impl ResourcesLane {
  /// The lane's store namespaces: the lane↔namespace map.
  const NAMESPACES: [&str; 1] = [crate::storage::families::RESOURCE_RECORD_NAMESPACE];
}

impl Lane for ResourcesLane {
  fn id(&self) -> LaneId {
    LaneId::Resources
  }

  fn namespaces(&self) -> &'static [&'static str] {
    &Self::NAMESPACES
  }

  fn scan<'a>(
    &self, snapshot: &'a dyn StoreSnapshot, _filters: &'a ScanFilters,
  ) -> BoxFuture<'a, Result<LaneRows>> {
    Box::pin(async move {
      scan_namespaces(snapshot, &Self::NAMESPACES, |_key, value| {
        crate::resource::ResourceRecordV1::decode(value).is_ok()
      })
      .await
    })
  }

  fn reclaimed(
    &self, key_present: bool, _key: &[u8], content: &[u8], filters: &ScanFilters,
  ) -> bool {
    crate::resource::retention::reclaimed(
      key_present,
      content,
      filters.swept_at,
      filters.removal_retention,
    )
  }

  fn receive<'a>(
    &self, ctx: &'a LaneContext<'a>, rows: &'a mut LaneRows,
  ) -> BoxFuture<'a, Result<()>> {
    Box::pin(async move {
      // The retention-reclaimed receive filter, the tombstone mirror: a
      // removal row past its retention deadline whose subject the local
      // store no longer holds never enters an engine. The predicate is
      // the scan side's own (`retention::reclaimed`) judged against the
      // context's one instant, so the prune and this filter cannot
      // disagree on what reclaimed evidence is. The deadline is the
      // sweep's own contract — the real basis a gone key needs before it
      // reads as reclaimed knowledge. A fresh deletion is legitimate
      // evidence even on a node that never held the resource (an older
      // live value may still arrive later and must lose to it), so key
      // absence alone never drops it: its subject is absent here either
      // way, and admitting the row installs the tombstone that beats the
      // late live value, while the local sweep reclaims the record at its
      // own deadline.
      let store = ctx.context.store();
      let namespace = crate::resource::store::namespace()?;
      let snapshot = store.snapshot().await?;
      let mut retained = LaneRows::with_capacity(rows.len());
      for (key, content) in rows.drain(..) {
        let key_present = snapshot
          .get(
            &namespace,
            &crate::StoreKey::new(std::sync::Arc::from(key.clone())),
          )
          .await?
          .is_some();
        if !crate::resource::retention::reclaimed(
          key_present,
          &content,
          ctx.swept_at,
          ctx.removal_retention,
        ) {
          retained.push((key, content));
        }
      }
      *rows = retained;
      Ok(())
    })
  }

  fn apply<'a>(
    &self, ctx: &'a LaneContext<'a>, rows: &'a LaneRows, _source: Option<&'a NodeId>,
    _runtime: Option<&'a RuntimeClient>,
  ) -> BoxFuture<'a, Result<LaneOutcome>> {
    Box::pin(async move {
      let store = ctx.context.store();
      // The same row-level policy as the descriptors lane: a corrupt or
      // misattributed record row skips, and the page apply's store
      // faults propagate.
      let mut staged: Vec<crate::resource::ResourceRecordV1> = Vec::with_capacity(rows.len());
      let mut refused = Vec::new();
      for (row_key, content) in rows {
        match crate::resource::ResourceRecordV1::decode(content) {
          Ok(record) if row_key.as_slice() == record.name().as_str().as_bytes() => {
            staged.push(record);
          }
          Ok(record) => {
            tracing::debug!(
              name = %record.name().as_str(),
              "reconcile resource row skipped: key mismatch"
            );
            refused.push((row_key.clone(), content.clone()));
          }
          Err(error) => {
            tracing::debug!(
              kind = ?error.kind(),
              "reconcile resource row skipped: undecodable"
            );
            refused.push((row_key.clone(), content.clone()));
          }
        }
      }
      for chunk in staged.chunks(crate::paging::PAGE_MAX_ITEMS) {
        let page = crate::resource::page::ResourcePage::new(chunk.to_vec(), None)?;
        let outcome =
          crate::resource::page::sync::apply_page_reported_ctx(store, ctx.entropy.as_ref(), &page)
            .await?;
        tracing::debug!(
          applied = outcome.installed.len(),
          "reconcile resource rows applied"
        );
        // Each committed record is a peer-converged resource change:
        // report it through the same event local writes emit, tagged
        // `Remote` so a hook can tell the two apart. The removal flag
        // follows the winning record.
        for record in &outcome.installed {
          ctx.events.emit(crate::ResourceChanged::new(
            record.name().clone(),
            crate::ResourceOrigin::Remote,
            record.removed(),
          ));
        }
      }
      Ok(LaneOutcome { refused })
    })
  }

  fn pass_settled(&self, peer: &NodeId) {
    // The resources lane's quiet-pass audit event: the SLO harness
    // asserts its presence as the resource plane's settled-pass proof. It
    // fires only on observed agreement, so the event means a settled
    // whole lane, never a bare dispatch.
    crate::audit::resource_pass_settled(peer.as_str(), false);
  }
}
