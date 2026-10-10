//! The node-local route table: bounded in-memory trace
//! metadata only — identity, selected node, progress, terminal state.
//! Never payload bytes, no durability claim; the durable twin lives in
//! [`crate::routing::trace`].

use std::{
  collections::BTreeMap,
  sync::{Arc, Mutex},
};

use crate::{
  Error, ErrorKind, Result, TraceId,
  packet::{RouteRecord, RouteState},
};

/// The shared node-local route table: bounded in-memory trace metadata
/// (identity, selected node, progress, terminal state — never
/// payload bytes, no durability claim). Routing-domain state: session
/// framing only borrows it while demultiplexing frames.
pub(crate) type RouteTable = Arc<Mutex<BTreeMap<TraceId, RouteRecord>>>;

/// Inserts one route record under the configured capacity, evicting the
/// oldest terminal record when full. Active records are never evicted.
/// A recorded failure is final: an insert never replaces an existing
/// `Failed` record — the same stickiness [`update_route`] enforces on
/// updates — so no route progress can overwrite a terminal fact.
pub(crate) fn insert_route(
  routes: &RouteTable, capacity: usize, record: RouteRecord,
) -> Result<()> {
  let mut table = routes
    .lock()
    .map_err(|_| Error::internal("route records"))?;
  insert_locked(&mut table, capacity, record)
}

/// The shared insert body for callers already holding the table lock:
/// presence decisions (capacity eviction, `Failed` stickiness) and the
/// write land in one lock span, so [`record_terminal_failure`] can decide
/// a trace is untracked and insert its terminal record without an
/// untracked gap a concurrent write could slip into.
fn insert_locked(
  table: &mut BTreeMap<TraceId, RouteRecord>, capacity: usize, record: RouteRecord,
) -> Result<()> {
  if !table.contains_key(&record.trace_id) && table.len() >= capacity {
    let oldest = table
      .iter()
      .filter(|(_, entry)| matches!(entry.state, RouteState::Delivered | RouteState::Failed(_)))
      .min_by_key(|(_, entry)| entry.updated_at)
      .map(|(trace_id, _)| trace_id.clone());
    match oldest {
      Some(trace_id) => {
        table.remove(&trace_id);
      }
      None => return Err(Error::resource_exhausted("route records")),
    }
  }
  // A recorded failure is final at insert time too: a late insert for an
  // already-failed trace is a no-op, exactly like [`update_route`] on the
  // same state, so fresh route progress can never overwrite the first
  // terminal fact.
  if let Some(existing) = table.get(&record.trace_id)
    && matches!(existing.state, RouteState::Failed(_))
  {
    return Ok(());
  }
  table.insert(record.trace_id.clone(), record);
  Ok(())
}

/// Applies one update to a route record, when present.
pub(crate) fn update_route(
  routes: &RouteTable, trace_id: &TraceId, update: impl FnOnce(&mut RouteRecord),
) {
  // A failed route is final: an interruption discovered after the local
  // enqueue completed still terminates the observation as failed, while no
  // later success can overwrite a recorded failure.
  if let Ok(mut table) = routes.lock()
    && let Some(record) = table.get_mut(trace_id)
    && !matches!(record.state, RouteState::Failed(_))
  {
    update(record);
  }
}

/// Records one bounded terminal route failure: an already-tracked route
/// keeps its real selected node and forwarded bytes while only the state
/// moves to the typed failure (a recorded failure stays final); an
/// untracked trace gets a fresh bounded terminal record within the
/// node's configured route-record capacity. Never payload bytes.
pub(crate) fn record_terminal_failure(
  routes: &RouteTable, capacity: usize, trace_id: &TraceId, kind: ErrorKind,
) {
  let mut table = match routes.lock() {
    Ok(table) => table,
    // A poisoned table can no longer record bounded trace facts.
    Err(_) => return,
  };
  if let Some(record) = table.get_mut(trace_id) {
    // The observed destination and progress survive the failure; a
    // recorded failure is final, so a later terminal fact never
    // overwrites the first one.
    if !matches!(record.state, RouteState::Failed(_)) {
      record.update(RouteState::Failed(kind));
    }
    return;
  }
  // Presence was decided and the insert lands inside the same lock span:
  // no concurrent write can slip a record between the absent check and
  // the terminal insert (the drop-then-relock gap once let the fresh
  // terminal `failing()` record overwrite a racing active insert,
  // losing its real selected node).
  let mut record = RouteRecord::failing(trace_id.clone());
  record.update(RouteState::Failed(kind));
  let _ = insert_locked(&mut table, capacity, record);
}

#[cfg(test)]
mod terminal_failure_tests {
  use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
  };

  use super::*;
  use crate::NodeId;

  fn node(value: u8) -> NodeId {
    NodeId::parse(&format!("node-{value:021}")).unwrap()
  }

  fn trace(seed: u32) -> TraceId {
    TraceId::parse(&format!("trace-{seed:021}")).unwrap()
  }

  /// A terminal failure on an already-tracked route moves only the state
  /// to the typed failure: the real selected node and the forwarded
  /// bytes survive so `GetRoute` still answers with the true
  /// destination instead of a fabricated empty record.
  #[test]
  fn terminal_failure_keeps_the_selected_node() {
    let routes: RouteTable = Arc::new(Mutex::new(BTreeMap::new()));
    insert_route(&routes, 8, RouteRecord::new(trace(1), node(7))).unwrap();
    if let Ok(mut table) = routes.lock()
      && let Some(record) = table.get_mut(&trace(1))
    {
      record.forward(128);
    }

    record_terminal_failure(&routes, 8, &trace(1), ErrorKind::StreamInterrupted);

    let table = routes.lock().unwrap();
    assert_eq!(table.len(), 1);
    let record = table.get(&trace(1)).unwrap();
    assert_eq!(record.selected_node.as_ref(), Some(&node(7)));
    assert!(matches!(
      record.state,
      RouteState::Failed(ErrorKind::StreamInterrupted)
    ));
    assert_eq!(record.bytes_forwarded, 128);
  }

  /// A recorded failure is final: a later terminal fact for the same
  /// trace neither overwrites the first typed failure nor resurrects a
  /// cleared selected node.
  #[test]
  fn terminal_failure_is_final() {
    let routes: RouteTable = Arc::new(Mutex::new(BTreeMap::new()));
    insert_route(&routes, 8, RouteRecord::new(trace(1), node(7))).unwrap();
    record_terminal_failure(&routes, 8, &trace(1), ErrorKind::StreamInterrupted);

    record_terminal_failure(&routes, 8, &trace(1), ErrorKind::Unsupported);

    let table = routes.lock().unwrap();
    let record = table.get(&trace(1)).unwrap();
    assert!(matches!(
      record.state,
      RouteState::Failed(ErrorKind::StreamInterrupted)
    ));
    assert_eq!(record.selected_node.as_ref(), Some(&node(7)));
  }

  /// A terminal failure on an untracked trace inserts exactly one
  /// bounded terminal record with no fabricated selected node, and a
  /// repeated failure never grows the table.
  #[test]
  fn untracked_terminal_failures_record_one_bounded_fact() {
    let routes: RouteTable = Arc::new(Mutex::new(BTreeMap::new()));
    record_terminal_failure(&routes, 8, &trace(2), ErrorKind::Unsupported);
    record_terminal_failure(&routes, 8, &trace(2), ErrorKind::Unsupported);

    let table = routes.lock().unwrap();
    assert_eq!(table.len(), 1);
    let record = table.get(&trace(2)).unwrap();
    assert!(record.selected_node.is_none());
    assert!(matches!(
      record.state,
      RouteState::Failed(ErrorKind::Unsupported)
    ));
  }
}

#[cfg(test)]
mod insert_route_tests {
  use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
  };

  use super::*;
  use crate::NodeId;

  fn node(value: u8) -> NodeId {
    NodeId::parse(&format!("node-{value:021}")).unwrap()
  }

  fn trace(seed: u32) -> TraceId {
    TraceId::parse(&format!("trace-{seed:021}")).unwrap()
  }

  /// A recorded failure is final at insert time too: a late insert for an
  /// already-failed trace succeeds as a no-op and never replaces the
  /// terminal fact — the same stickiness `update_route` enforces, now
  /// covering the route table's one unguarded write point.
  #[test]
  fn insert_route_never_overwrites_a_recorded_failure() {
    let routes: RouteTable = Arc::new(Mutex::new(BTreeMap::new()));
    insert_route(&routes, 8, RouteRecord::new(trace(1), node(7))).unwrap();
    record_terminal_failure(&routes, 8, &trace(1), ErrorKind::StreamInterrupted);

    insert_route(&routes, 8, RouteRecord::new(trace(1), node(9))).unwrap();

    let table = routes.lock().unwrap();
    assert_eq!(table.len(), 1);
    let record = table.get(&trace(1)).unwrap();
    assert_eq!(
      record.state,
      RouteState::Failed(ErrorKind::StreamInterrupted)
    );
    assert_eq!(record.selected_node.as_ref(), Some(&node(7)));
  }

  /// The normal new-route path is untouched: an untracked trace gets its
  /// fresh routing record carrying the resolved selected node.
  #[test]
  fn insert_route_tracks_a_new_route() {
    let routes: RouteTable = Arc::new(Mutex::new(BTreeMap::new()));

    insert_route(&routes, 8, RouteRecord::new(trace(1), node(7))).unwrap();

    let table = routes.lock().unwrap();
    assert_eq!(table.len(), 1);
    let record = table.get(&trace(1)).unwrap();
    assert_eq!(record.state, RouteState::Routing);
    assert_eq!(record.selected_node.as_ref(), Some(&node(7)));
  }
}
