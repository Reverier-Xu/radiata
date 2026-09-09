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
pub(crate) fn insert_route(
  routes: &RouteTable, capacity: usize, record: RouteRecord,
) -> Result<()> {
  let mut table = routes
    .lock()
    .map_err(|_| Error::internal("route records"))?;
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
  drop(table);
  let mut record = RouteRecord::failing(trace_id.clone());
  record.update(RouteState::Failed(kind));
  let _ = insert_route(routes, capacity, record);
}

/// Records one bounded terminal route fact for an admission rejection:
/// identity and typed failure only, never payload bytes, always within
/// the node's configured route-record capacity.
pub(crate) fn record_rejection(
  routes: &RouteTable, capacity: usize, trace_id: &TraceId, kind: ErrorKind,
) {
  record_terminal_failure(routes, capacity, trace_id, kind);
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
    NodeId::parse(&format!("node_{value:021}")).unwrap()
  }

  fn trace(seed: u32) -> TraceId {
    TraceId::parse(&format!("trace_{seed:021}")).unwrap()
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
