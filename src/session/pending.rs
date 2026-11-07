//! The per-session pending-admission map and its one lock discipline.
//!
//! Both data-plane directions register here: the origin pump reserves a
//! one-shot waiter for its open, and a forwarding hop reserves a relay
//! entry whose acknowledgement it carries upstream. The session's read
//! loop resolves one entry per acknowledgement, the hop deadline expires
//! a still-pending relay, and the session teardown drains whatever is
//! left. Every entry has one lifetime: a resolved, withdrawn, expired, or
//! torn-down entry leaves the map exactly once.
//!
//! The map is bounded per session by the session policy's
//! `pending_admissions`: beyond it a reservation fails closed with typed
//! `Overloaded` backpressure instead of growing the map without limit.
//! The entry type itself is the routing domain's ([`PendingAck`]): this
//! module owns only the map's ownership rules, so no caller locks the map
//! directly.

use std::{
  collections::HashMap,
  sync::{Arc, Mutex},
};

use crate::{ErrorKind, TraceId, routing::forward::PendingAck};

/// One session's pending-admission map, shared between the session entry
/// and every pump, hop, and read loop that resolves an entry.
#[derive(Clone)]
pub(crate) struct PendingAdmissions {
  entries: Arc<Mutex<HashMap<TraceId, PendingAck>>>,
  /// The concurrent-admission bound (see the module docs).
  bound: usize,
}

impl PendingAdmissions {
  pub(crate) fn new(bound: usize) -> Self {
    Self {
      entries: Arc::new(Mutex::new(HashMap::new())),
      bound,
    }
  }

  /// Reserves one pending entry for `trace_id`. `Overloaded` is the typed
  /// backpressure at the per-session bound; `Conflict` means the trace
  /// already holds an entry (a duplicate open for one trace is a
  /// protocol violation, never an overwrite that would drop the standing
  /// waiter); `Internal` is the poisoned map.
  pub(crate) fn try_reserve_admission(
    &self, trace_id: &TraceId, ack: PendingAck,
  ) -> Result<(), ErrorKind> {
    let mut entries = self.entries.lock().map_err(|_| ErrorKind::Internal)?;
    if entries.contains_key(trace_id) {
      return Err(ErrorKind::Conflict);
    }
    if entries.len() >= self.bound {
      return Err(ErrorKind::Overloaded);
    }
    entries.insert(trace_id.clone(), ack);
    Ok(())
  }

  /// Removes one entry unconditionally: a reservation whose open never
  /// reached the wire, or an attempt the caller abandoned.
  pub(crate) fn withdraw(&self, trace_id: &TraceId) {
    if let Ok(mut entries) = self.entries.lock() {
      entries.remove(trace_id);
    }
  }

  /// Removes one entry only if it is still a relay: an acknowledged
  /// attempt already resolved its entry, and the deadline task's removal
  /// then reports nothing to expire. A local waiter is never an expiring
  /// relay, and a poisoned map conservatively reports nothing — the
  /// session teardown owns the entries in that case.
  pub(crate) fn take_expired(&self, trace_id: &TraceId) -> bool {
    let Ok(mut entries) = self.entries.lock() else {
      return false;
    };
    if matches!(entries.get(trace_id), Some(PendingAck::Relay { .. })) {
      entries.remove(trace_id);
      return true;
    }
    false
  }

  /// Takes the entry one acknowledgement resolves, if it is still
  /// pending.
  pub(crate) fn take(&self, trace_id: &TraceId) -> Option<PendingAck> {
    self
      .entries
      .lock()
      .ok()
      .and_then(|mut entries| entries.remove(trace_id))
  }

  /// Whether the trace's pending entry is a relay: the attribution test a
  /// discovering hop's live attempt must pass.
  pub(crate) fn holds_relay(&self, trace_id: &TraceId) -> bool {
    self
      .entries
      .lock()
      .ok()
      .and_then(|entries| {
        entries
          .get(trace_id)
          .map(|entry| matches!(entry, PendingAck::Relay { .. }))
      })
      .unwrap_or(false)
  }

  /// The oldest queued local waiter's wall-clock stamp, or `None` when the
  /// map holds no waiter: the liveness policy's owned-work exemption
  /// reads it (a relay-only map is bounded transitively by the sessions
  /// on both ends of the hop).
  pub(crate) fn oldest_wait(&self) -> Option<u64> {
    self.entries.lock().ok().and_then(|entries| {
      entries
        .values()
        .filter_map(|entry| match entry {
          PendingAck::Wait { queued_at, .. } => Some(*queued_at),
          PendingAck::Relay { .. } => None,
        })
        .min()
    })
  }

  /// Whether the map holds no entry at all.
  pub(crate) fn is_empty(&self) -> bool {
    self
      .entries
      .lock()
      .map(|entries| entries.is_empty())
      .unwrap_or(false)
  }

  /// Drains every pending entry (session teardown): the caller fails the
  /// local waiters and relays the forwarded hops upstream.
  pub(crate) fn drain(&self) -> Vec<(TraceId, PendingAck)> {
    match self.entries.lock() {
      Ok(mut entries) => std::mem::take(&mut *entries).into_iter().collect(),
      Err(_) => Vec::new(),
    }
  }

  /// Whether two handles name the same session's map: forwarded-hop
  /// attribution requires the exact map the attempt registered in, so a
  /// superseded branch's map never steers the live hop.
  pub(crate) fn is_same_map(&self, other: &Self) -> bool {
    Arc::ptr_eq(&self.entries, &other.entries)
  }

  #[cfg(test)]
  pub(crate) fn contains(&self, trace_id: &TraceId) -> bool {
    self
      .entries
      .lock()
      .map(|entries| entries.contains_key(trace_id))
      .unwrap_or(false)
  }
}

#[cfg(test)]
mod tests {
  use super::PendingAdmissions;
  use crate::{
    ErrorKind, TraceId,
    routing::forward::PendingAck,
    session::stream::{BoundedSender, MAX_PENDING_ADMISSIONS, test_queue},
  };

  fn trace(seed: u32) -> TraceId {
    TraceId::parse(&format!("trace-{seed:021}")).unwrap()
  }

  fn relay() -> (PendingAck, BoundedSender) {
    let (upstream, _receiver) = test_queue(4, 1024);
    (
      PendingAck::Relay {
        upstream: upstream.clone(),
      },
      upstream,
    )
  }

  /// The reservation bound is the typed backpressure, and a duplicate
  /// reservation for one trace is a conflict instead of an overwrite that
  /// would drop the standing waiter.
  #[test]
  fn reserve_enforces_the_bound_and_refuses_duplicates() {
    let pending = PendingAdmissions::new(2);
    let (ack, _keep) = relay();
    pending.try_reserve_admission(&trace(1), ack).unwrap();
    let (ack, _keep) = relay();
    pending.try_reserve_admission(&trace(2), ack).unwrap();

    let (ack, _keep) = relay();
    assert_eq!(
      pending.try_reserve_admission(&trace(3), ack),
      Err(ErrorKind::Overloaded)
    );
    let (ack, _keep) = relay();
    assert_eq!(
      pending.try_reserve_admission(&trace(1), ack),
      Err(ErrorKind::Conflict)
    );

    // A withdrawal frees the slot for the next reservation.
    pending.withdraw(&trace(1));
    let (ack, _keep) = relay();
    pending.try_reserve_admission(&trace(3), ack).unwrap();
    assert!(pending.contains(&trace(2)) && pending.contains(&trace(3)));
  }

  /// Withdrawal removes a reservation that never reached the wire; the
  /// expiry path removes only a still-pending relay, so an attempt the
  /// acknowledgement already resolved reports nothing to expire.
  #[test]
  fn withdraw_and_expiry_remove_exactly_their_own_entry() {
    let pending = PendingAdmissions::new(MAX_PENDING_ADMISSIONS);
    let (ack, _keep) = relay();
    pending.try_reserve_admission(&trace(1), ack).unwrap();
    pending.withdraw(&trace(1));
    assert!(!pending.contains(&trace(1)));
    assert!(!pending.take_expired(&trace(1)));

    let (ack, _keep) = relay();
    pending.try_reserve_admission(&trace(2), ack).unwrap();
    assert!(pending.take_expired(&trace(2)));
    assert!(!pending.contains(&trace(2)));
    // The second expiry of the same attempt finds nothing.
    assert!(!pending.take_expired(&trace(2)));

    // A local waiter is not an expiring relay: the hop deadline never
    // consumes an origin's admission wait.
    let (notify, _ack_rx) = tokio::sync::oneshot::channel();
    pending
      .try_reserve_admission(
        &trace(3),
        PendingAck::Wait {
          notify,
          queued_at: 1,
        },
      )
      .unwrap();
    assert!(!pending.take_expired(&trace(3)));
    assert!(pending.contains(&trace(3)));
    assert!(!pending.holds_relay(&trace(3)));
  }

  /// Resolution takes one entry exactly once, and the teardown drain
  /// leaves the map empty: the two terminal paths never double-resolve an
  /// entry.
  #[test]
  fn resolution_and_drain_take_each_entry_once() {
    let pending = PendingAdmissions::new(MAX_PENDING_ADMISSIONS);
    let (ack, _keep) = relay();
    pending.try_reserve_admission(&trace(1), ack).unwrap();
    assert!(pending.take(&trace(1)).is_some());
    assert!(pending.take(&trace(1)).is_none());

    let (ack, _keep) = relay();
    pending.try_reserve_admission(&trace(2), ack).unwrap();
    let (ack, _keep) = relay();
    pending.try_reserve_admission(&trace(3), ack).unwrap();
    let drained = pending.drain();
    assert_eq!(drained.len(), 2);
    assert!(pending.is_empty());
    assert!(pending.drain().is_empty());
  }

  /// Two handles of one map compare equal and independent maps do not:
  /// the forwarded-hop attribution test relies on that identity.
  #[test]
  fn map_identity_follows_the_shared_handle() {
    let pending = PendingAdmissions::new(MAX_PENDING_ADMISSIONS);
    let clone = pending.clone();
    assert!(pending.is_same_map(&clone));
    assert!(!pending.is_same_map(&PendingAdmissions::new(MAX_PENDING_ADMISSIONS)));
  }
}
