//! The node-local route table (ADR-0007): bounded in-memory trace
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
/// (ADR-0007: identity, selected node, progress, terminal state — never
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

/// Records one bounded terminal route fact for an admission rejection:
/// identity and typed failure only, never payload bytes, always within
/// the node's configured route-record capacity.
pub(crate) fn record_rejection(
  routes: &RouteTable, capacity: usize, trace_id: &TraceId, kind: ErrorKind,
) {
  // A trace already carrying a terminal fact never grows the table.
  if routes
    .lock()
    .map(|table| table.contains_key(trace_id))
    .unwrap_or(true)
  {
    return;
  }
  let mut record = RouteRecord::failing(trace_id.clone());
  record.update(RouteState::Failed(kind));
  let _ = insert_route(routes, capacity, record);
}
