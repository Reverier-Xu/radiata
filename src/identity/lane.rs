//! The trust lane's reconciliation policy: the identity-binding
//! namespace, its row projection, and its per-record adoption apply.
//!
//! The lane carries one row per issuer binding, keyed by the node id. The
//! apply is the per-record adoption policy: transient contention skips one
//! binding (the derived-view repair retries it), while a revoked subject
//! or a substituted key is refused evidence the receive boundary keeps out
//! of the engines.

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

/// The issuer-trust lane.
#[derive(Debug)]
pub(crate) struct TrustLane;

impl TrustLane {
  /// The lane's store namespaces: the lane↔namespace map.
  const NAMESPACES: [&str; 1] = [crate::storage::families::IDENTITY_BINDING_NAMESPACE];
}

impl Lane for TrustLane {
  fn id(&self) -> LaneId {
    LaneId::Trust
  }

  fn namespaces(&self) -> &'static [&'static str] {
    &Self::NAMESPACES
  }

  fn scan<'a>(
    &self, snapshot: &'a dyn StoreSnapshot, _filters: &'a ScanFilters,
  ) -> BoxFuture<'a, Result<LaneRows>> {
    Box::pin(async move {
      scan_namespaces(snapshot, &Self::NAMESPACES, |_key, value| {
        crate::identity::records::IdentityBindingV1::decode(value).is_ok()
      })
      .await
    })
  }

  fn apply<'a>(
    &self, ctx: &'a LaneContext<'a>, rows: &'a LaneRows, _source: Option<&'a NodeId>,
    _runtime: Option<&'a RuntimeClient>,
  ) -> BoxFuture<'a, Result<LaneOutcome>> {
    Box::pin(async move {
      let store = ctx.context.store();
      // The same row-level policy as the descriptors lane: a corrupt or
      // misattributed binding row skips; adoption failures keep the
      // snapshot-accept semantics (transient contention skips one
      // binding — the repair retries it — and everything else, key
      // substitution above all, fails closed and propagates).
      let mut refused = Vec::new();
      for (row_key, content) in rows {
        let binding = match crate::identity::records::IdentityBindingV1::decode(content) {
          Ok(binding) if row_key.as_slice() == binding.node().as_str().as_bytes() => binding,
          Ok(binding) => {
            tracing::debug!(
              node = %binding.node(),
              "reconcile binding row skipped: key mismatch"
            );
            refused.push((row_key.clone(), content.clone()));
            continue;
          }
          Err(error) => {
            tracing::debug!(
              kind = ?error.kind(),
              "reconcile binding row skipped: undecodable"
            );
            refused.push((row_key.clone(), content.clone()));
            continue;
          }
        };
        // The per-record adoption policy, row-scoped: transient
        // contention skips one binding (the repair retries it); a
        // revoked subject (revocation tombstones out-rank late binding
        // rows — the delayed-content mirror order) and a substituted
        // key are refused evidence — the row is skipped, not stored,
        // and the batch continues (skipping IS the correct outcome;
        // these fire on honest input, so an abort here would wedge the
        // repair on every re-delivery). Everything else — provider
        // faults above all — is a real write fault and propagates.
        if let Err(error) = crate::identity::trust::store::adopt_binding_ctx(
          store,
          ctx.entropy.as_ref(),
          binding.node(),
          binding.public_key(),
        )
        .await
        {
          if matches!(
            error.kind(),
            crate::ErrorKind::Conflict
              | crate::ErrorKind::NotReady
              | crate::ErrorKind::Revoked
              | crate::ErrorKind::NotTrusted
          ) {
            tracing::warn!(
              node = %binding.node(),
              kind = ?error.kind(),
              "reconcile binding row refused by policy; skipping"
            );
            // Revoked and substituted-key rows are refused evidence
            // whose outcome no retry changes: they join the refused
            // list so the receive boundary keeps them out of the
            // engines. Contention and not-ready are transient — the
            // row stays a repair candidate exactly as before.
            if matches!(
              error.kind(),
              crate::ErrorKind::Revoked | crate::ErrorKind::NotTrusted
            ) {
              refused.push((row_key.clone(), content.clone()));
            }
            continue;
          }
          return Err(error);
        }
      }
      Ok(LaneOutcome { refused })
    })
  }
}
