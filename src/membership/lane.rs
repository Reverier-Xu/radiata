//! The descriptors lane's reconciliation policy: the member-descriptor
//! namespace, its row projection, and its page-batch apply.
//!
//! The lane carries one row per member descriptor, keyed by the node id.
//! Rows are trusted through the authenticated session that delivered them
//! (the register's own stance), so the apply is the register's page batch
//! with its page-order contest; every row it refuses is decided evidence
//! the receive boundary keeps out of the engines.

use crate::{
  NodeId, Result,
  api::BoxFuture,
  provider::StoreSnapshot,
  reconcile::{
    lane::{Lane, LaneContext, LaneOutcome, LaneRows, decode_identified, scan_namespaces},
    wire::LaneId,
  },
  runtime::RuntimeClient,
  session::stream::{AuthorizationBoundary, SessionTable},
};

/// The member-descriptor lane.
#[derive(Debug)]
pub(crate) struct DescriptorsLane;

impl DescriptorsLane {
  /// The lane's store namespaces: the lane↔namespace map (the lane
  /// registry projects it).
  pub(crate) const NAMESPACES: [&str; 1] = [crate::membership::NODE_DESCRIPTOR_NAMESPACE];

  /// The lane's immutable wire code: the frozen reconcile-wire v1 contract
  /// the registry's wire projections read.
  pub(crate) const CODE: u8 = 1;
}

impl Lane for DescriptorsLane {
  fn id(&self) -> LaneId {
    LaneId::Descriptors
  }

  fn scan<'a>(&self, snapshot: &'a dyn StoreSnapshot) -> BoxFuture<'a, Result<LaneRows>> {
    Box::pin(async move {
      scan_namespaces(snapshot, &Self::NAMESPACES, |_key, value| {
        // The descriptor family stores the row envelope; the lane carries
        // the envelope's payload element, the canonical descriptor record
        // bytes.
        crate::storage::RowEnvelope::open(value)
          .ok()
          .filter(|payload| crate::membership::page::decode_descriptor(payload).is_ok())
      })
      .await
    })
  }

  fn apply<'a>(
    &self, ctx: &'a LaneContext<'a>, rows: &'a LaneRows, _source: Option<&'a NodeId>,
    _runtime: Option<&'a RuntimeClient>, _sessions: &'a SessionTable,
    _authorization: &'a AuthorizationBoundary,
  ) -> BoxFuture<'a, Result<LaneOutcome>> {
    Box::pin(async move {
      let store = ctx.context.store();
      // Row-level fault tolerance, the scan side's corrupt-row policy:
      // one undecodable or misattributed row skips with a typed reason
      // instead of failing the batch — a whole-batch error would wedge
      // the derived-view repair on the same poison row forever (the
      // engines hold it, so the fingerprints look converged while the
      // store never receives the good rows behind it). Store failures
      // below still propagate: they are real write faults, not corrupt
      // input. The refused list carries the rows in their original
      // wire shape, so the receive boundary can keep them out of the
      // engines.
      let (decoded, mut refused) = decode_identified(
        rows,
        "descriptor",
        crate::membership::page::decode_descriptor,
        |descriptor| descriptor.node().as_str().as_bytes(),
      );
      // The same-key page-order contest, single-sourced with the
      // register's page batch (`contest_descriptors`): the decided
      // contest losers — stale-or-equal by construction, the same
      // refusal the store would make — join the refused list in their
      // original wire shape, and the winners apply in first-seen order.
      let records: Vec<&crate::membership::NodeDescriptorV1> =
        decoded.iter().map(|(_, descriptor)| descriptor).collect();
      let (winner_rows, loser_rows) = crate::membership::store::contest_descriptors(&records);
      for index in loser_rows {
        refused.push(rows[decoded[index].0].clone());
      }
      let mut skipped_ids = Vec::new();
      for chunk in winner_rows.chunks(crate::paging::PAGE_MAX_ITEMS) {
        let page = crate::membership::page::MembershipPage::new(
          chunk
            .iter()
            .map(|index| decoded[*index].1.clone())
            .collect(),
          None,
        )?;
        let (installed, skipped) =
          crate::membership::store::apply_descriptor_batch_ctx(store, ctx.entropy.as_ref(), &page)
            .await?;
        skipped_ids.extend(skipped);
        for index in chunk {
          let descriptor = &decoded[*index].1;
          if installed.contains(descriptor.node()) {
            // The audit event is the propagation path proof: a
            // descriptor exists on this peer only because these rows
            // carried it.
            crate::audit::descriptor_installed(descriptor.node().as_str(), descriptor.revision());
            crate::membership::sync::member_changed(
              ctx.events,
              ctx.revision,
              descriptor.node().clone(),
            );
          }
        }
      }
      // The batch's refused node ids map back onto exactly the rows
      // that carried them (the dedup above left one row per node id).
      for index in winner_rows {
        let (row_key, content) = &rows[decoded[index].0];
        if skipped_ids
          .iter()
          .any(|node| node.as_str().as_bytes() == row_key.as_slice())
        {
          refused.push((row_key.clone(), content.clone()));
        }
      }
      Ok(LaneOutcome { refused })
    })
  }

  fn rows_emitted(&self, rows: usize) {
    // The redundancy ledger's sent side: the audit stream's
    // rows-to-installed ratio is the reconcile plane's equivalent of the
    // page counter it replaces. The eager-delta piggyback is payload
    // crossing a session, so it counts exactly like a ROWS message.
    crate::audit::membership_page_emitted(rows);
  }
}
