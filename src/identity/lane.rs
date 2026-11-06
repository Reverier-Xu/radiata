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
    lane::{Lane, LaneContext, LaneOutcome, LaneRows, decode_identified, scan_namespaces},
    wire::LaneId,
  },
  runtime::RuntimeClient,
  session::stream::{AuthorizationBoundary, SessionTable},
};

/// The issuer-trust lane.
#[derive(Debug)]
pub(crate) struct TrustLane;

impl TrustLane {
  /// The lane's store namespaces: the lane↔namespace map (the lane
  /// registry projects it).
  pub(crate) const NAMESPACES: [&str; 1] = [crate::storage::families::IDENTITY_BINDING_NAMESPACE];

  /// The lane's immutable wire code: the frozen reconcile-wire v1 contract
  /// the registry's wire projections read.
  pub(crate) const CODE: u8 = 2;
}

impl Lane for TrustLane {
  fn id(&self) -> LaneId {
    LaneId::Trust
  }

  fn scan<'a>(&self, snapshot: &'a dyn StoreSnapshot) -> BoxFuture<'a, Result<LaneRows>> {
    Box::pin(async move {
      scan_namespaces(snapshot, &Self::NAMESPACES, |_key, value| {
        crate::identity::records::IdentityBindingV1::decode(value).is_ok()
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
      // The same row-level policy as the descriptors lane: a corrupt or
      // misattributed binding row skips; adoption failures keep the
      // snapshot-accept semantics (transient contention skips one
      // binding — the repair retries it — and everything else, key
      // substitution above all, fails closed and propagates).
      let (decoded, mut refused) = decode_identified(
        rows,
        "binding",
        crate::identity::records::IdentityBindingV1::decode,
        |binding| binding.node().as_str().as_bytes(),
      );
      for (binding_row, binding) in &decoded {
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
              refused.push(rows[*binding_row].clone());
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
