//! The HTTP surface: a resource getter/setter plus cluster operations
//! (join, connect, status), all backed by radiata's public facade.

use std::sync::Arc;

use axum::{
  Json, Router,
  extract::{Path as AxumPath, Query, State},
  http::StatusCode,
  routing::{get, post},
};
use radiata::{
  CleanupNode, ConnectMember, Digest, GetObservability, GetResource, IssueCleanupCheckpoint,
  IssueMergeCredential, LabelKey, LabelValue, LeaveCluster, MemberPage, MergeCluster,
  MergeCredential, NodeHandle, NodeId, PageCursor, PageMembers, PageResources, PageSessions,
  PageSpec, PageTrust, ProtocolTag, PutResource, QualifiedTag, RemoveResource,
  ReplaceIdentityAndDeleteOldCoreMetadata, ResourceLabels, ResourceName, ResourceUri,
  ResourceVersion, ResourceWrite, RevokeNode, RoutingPolicy, SelectResources, Selector,
  StreamMetadata, StreamPolicy, StreamTarget,
};
use serde_json::{Value, json};

use crate::http_client;

pub struct AppState {
  pub node: NodeHandle,
  pub node_id: NodeId,
  pub probe_delivered: Arc<std::sync::atomic::AtomicUsize>,
  pub started: std::time::Instant,
}

pub type SharedState = Arc<AppState>;

fn status_tag(name: &str) -> QualifiedTag {
  QualifiedTag::parse(&format!("radiata.woooo.tech/status/{name}")).unwrap()
}

/// The page bound every demo list lane shares: one caller-visible page
/// never exceeds the store's own page capacity, so a cursor walk
/// exercises the exact continuation contract the sync lanes use.
const PAGE_LIMIT: usize = 64;

fn to_hex(bytes: &[u8]) -> String {
  bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn from_hex(value: &str) -> Option<Vec<u8>> {
  if !value.len().is_multiple_of(2) {
    return None;
  }
  (0..value.len())
    .step_by(2)
    .map(|offset| u8::from_str_radix(&value[offset..offset + 2], 16).ok())
    .collect()
}

fn bad_request(error: radiata::Error) -> (StatusCode, Json<Value>) {
  (
    StatusCode::BAD_REQUEST,
    Json(json!({"error": error.to_string()})),
  )
}

/// Builds one page spec from the demo's query parameters: the cursor is
/// the hex encoding of the opaque continuation bytes the previous page
/// returned, and the limit stays inside the shared page bound.
fn page_spec(
  limit: Option<usize>, cursor: Option<String>,
) -> Result<PageSpec, (StatusCode, Json<Value>)> {
  let limit = limit.unwrap_or(PAGE_LIMIT).clamp(1, PAGE_LIMIT);
  match cursor {
    Some(text) if !text.is_empty() => {
      let bytes = from_hex(&text)
        .filter(|bytes| !bytes.is_empty())
        .ok_or_else(|| {
          (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "malformed cursor"})),
          )
        })?;
      let cursor =
        PageCursor::from_provider_bytes(bytes.into_boxed_slice().into()).map_err(bad_request)?;
      PageSpec::after(cursor, limit).map_err(bad_request)
    }
    _ => PageSpec::first(limit).map_err(bad_request),
  }
}

async fn status(state: State<SharedState>) -> Json<Value> {
  let node = &state.node;
  let observability = node.query(GetObservability::new()).await;
  let members: Option<MemberPage> = node
    .query(PageMembers::new(PageSpec::first(64).unwrap()))
    .await
    .ok();
  let member_count = members.as_ref().map_or(0, |page| page.items().len());
  // The library annotates every member page entry with its lifecycle
  // status (active / left / cleaned), so an operator — and the scenario
  // tests — can tell live members from departed evidence (finding #9).
  let member_statuses: std::collections::BTreeMap<String, String> = members
    .as_ref()
    .map(|page| {
      page
        .items()
        .iter()
        .map(|view| {
          (
            view.node_id().as_str().to_owned(),
            format!("{:?}", view.status()).to_lowercase(),
          )
        })
        .collect()
    })
    .unwrap_or_default();
  let counter = |name: &str| {
    observability
      .as_ref()
      .ok()
      .and_then(|snapshot| snapshot.counter(&status_tag(name)))
  };
  Json(json!({
    "node_id": state.node_id.as_str(),
    "uptime_secs": state.started.elapsed().as_secs(),
    "members": member_count,
    "member_statuses": member_statuses,
    "sessions": counter("sessions"),
    "listeners": counter("listeners"),
    "store_available": counter("metadata-store-available"),
    "queued_session_messages": counter("queued-session-messages"),
    "trace_records": counter("trace-records"),
    "trace_records_dropped": counter("trace-records-dropped"),
    "probe_chunks_received": state.probe_delivered.load(std::sync::atomic::Ordering::Relaxed),
  }))
}

async fn join_token(state: State<SharedState>) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
  let issued = state
    .node
    .command(IssueMergeCredential::new())
    .await
    .map_err(internal_error)?;
  Ok(Json(json!({
    "credential": issued.credential().expose_secret(),
    "node_id": state.node_id.as_str(),
  })))
}

#[derive(serde::Deserialize)]
pub struct JoinRequest {
  /// Bootstrap node's HTTP address, e.g. "n1:8080".
  pub bootstrap_http: String,
  /// Bootstrap node's wss endpoint, e.g. "wss://n1:9443".
  pub bootstrap_wss: String,
}

async fn join(
  state: State<SharedState>, Json(request): Json<JoinRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
  let mut attempt = 0_u32;
  loop {
    attempt += 1;
    let token = http_client::get_json(&request.bootstrap_http, "/join-token")
      .await
      .map_err(|error| {
        (
          StatusCode::BAD_GATEWAY,
          Json(json!({"error": error.to_string()})),
        )
      })?;
    let secret = token["credential"].as_str().ok_or_else(|| {
      (
        StatusCode::BAD_GATEWAY,
        Json(json!({"error": "no credential"})),
      )
    })?;
    let credential = MergeCredential::parse(secret).map_err(|error| {
      (
        StatusCode::BAD_GATEWAY,
        Json(json!({"error": error.to_string()})),
      )
    })?;
    match state
      .node
      .command(MergeCluster::new(
        radiata::Endpoint::parse(&request.bootstrap_wss).map_err(|error| {
          (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": error.to_string()})),
          )
        })?,
        credential,
      ))
      .await
    {
      Ok(view) => {
        return Ok(Json(json!({
          "merged": true,
          "peer": view.peer().as_str(),
        })));
      }
      Err(error) => {
        if attempt >= 10 {
          return Err((
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": format!("merge failed after {attempt} attempts: {error:?}")})),
          ));
        }
        tracing::warn!(attempt, ?error, "merge attempt failed; retrying");
        tokio::time::sleep(std::time::Duration::from_millis(250 * u64::from(attempt))).await;
      }
    }
  }
}

#[derive(serde::Deserialize)]
pub struct ConnectRequest {
  pub endpoint: String,
  pub node_id: String,
}

async fn connect(
  state: State<SharedState>, Json(request): Json<ConnectRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
  let endpoint = radiata::Endpoint::parse(&request.endpoint).map_err(|error| {
    (
      StatusCode::BAD_REQUEST,
      Json(json!({"error": error.to_string()})),
    )
  })?;
  let node_id = NodeId::parse(&request.node_id).map_err(|error| {
    (
      StatusCode::BAD_REQUEST,
      Json(json!({"error": error.to_string()})),
    )
  })?;
  let connected = state
    .node
    .command(ConnectMember::new(endpoint, node_id))
    .await
    .map_err(|error| {
      (
        StatusCode::BAD_GATEWAY,
        Json(json!({"error": error.to_string()})),
      )
    })?;
  Ok(Json(json!({"connected": connected.as_str()})))
}

#[derive(serde::Deserialize)]
pub struct DisconnectRequest {
  pub node_id: String,
}
/// Tears down the session to one peer: the topology shaper uses it to
/// drop the join-phase legs through the bootstrap once the sparse graph
/// is dialed.
async fn disconnect(
  state: State<SharedState>, Json(request): Json<DisconnectRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
  let node_id = NodeId::parse(&request.node_id).map_err(|error| {
    (
      StatusCode::BAD_REQUEST,
      Json(json!({"error": error.to_string()})),
    )
  })?;
  state
    .node
    .command(radiata::DisconnectPeer::new(node_id))
    .await
    .map_err(|error| {
      (
        StatusCode::BAD_GATEWAY,
        Json(json!({"error": error.to_string()})),
      )
    })?;
  Ok(Json(json!({"disconnected": true})))
}

/// Leaves the cluster: the node's identity is replaced and the old
/// identity's local core metadata is wiped (the operator acknowledges
/// this deliberately). The runtime shuts down after the outcome is
/// returned; the process stays up only long enough to serve it.
async fn leave(state: State<SharedState>) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
  let outcome = state
    .node
    .command(LeaveCluster::new(
      ReplaceIdentityAndDeleteOldCoreMetadata::new(),
    ))
    .await
    .map_err(|error| {
      (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": error.to_string()})),
      )
    })?;
  Ok(Json(json!({
    "left": true,
    "former_identity": outcome.former_identity().as_str(),
    "replacement_identity": outcome.replacement_identity().as_str(),
  })))
}

fn version_json(view: &radiata::ResourceView) -> Value {
  let version = view.version();
  let digest: String = version
    .digest()
    .as_bytes()
    .iter()
    .map(|byte| format!("{byte:02x}"))
    .collect();
  json!({
    "timestamp_millis": version
      .timestamp()
      .duration_since(std::time::UNIX_EPOCH)
      .map(|age| age.as_millis() as u64)
      .unwrap_or(0),
    "writer": version.writer().as_str(),
    "digest": digest,
    "removal": version.is_removal(),
  })
}

fn labels_json(view: &radiata::ResourceView) -> Value {
  let labels = view.labels();
  let custom: serde_json::Map<String, Value> = labels
    .custom_labels()
    .entries()
    .map(|(key, value)| (key.as_str().to_owned(), json!(value.as_str())))
    .collect();
  json!({
    "type": labels.resource_type().as_str(),
    "uri": labels.uri().as_str(),
    "custom": custom,
  })
}

async fn get_resource(
  state: State<SharedState>, AxumPath(name): AxumPath<String>,
) -> Result<Json<Value>, StatusCode> {
  let name = ResourceName::parse(&name).map_err(|_| StatusCode::NOT_FOUND)?;
  match state.node.query(GetResource::new(name)).await {
    Ok(Some(view)) => Ok(Json(json!({
      "name": view.name().as_str(),
      "labels": labels_json(&view),
      "version": version_json(&view),
    }))),
    Ok(None) => Err(StatusCode::NOT_FOUND),
    Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
  }
}

#[derive(serde::Deserialize)]
pub struct ResourcePut {
  #[serde(rename = "type")]
  pub resource_type: String,
  pub uri: String,
  #[serde(default)]
  pub labels: std::collections::BTreeMap<String, String>,
}

async fn put_resource(
  state: State<SharedState>, AxumPath(name): AxumPath<String>, Json(request): Json<ResourcePut>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
  let name = ResourceName::parse(&name).map_err(|error| {
    (
      StatusCode::BAD_REQUEST,
      Json(json!({"error": error.to_string()})),
    )
  })?;
  let resource_type = LabelValue::parse(&request.resource_type).map_err(|error| {
    (
      StatusCode::BAD_REQUEST,
      Json(json!({"error": error.to_string()})),
    )
  })?;
  let uri = ResourceUri::parse(&request.uri).map_err(|error| {
    (
      StatusCode::BAD_REQUEST,
      Json(json!({"error": error.to_string()})),
    )
  })?;
  let mut labels = ResourceLabels::new(resource_type, uri);
  for (key, value) in request.labels {
    let key = LabelKey::parse(&key).map_err(|error| {
      (
        StatusCode::BAD_REQUEST,
        Json(json!({"error": error.to_string()})),
      )
    })?;
    let value = LabelValue::parse(&value).map_err(|error| {
      (
        StatusCode::BAD_REQUEST,
        Json(json!({"error": error.to_string()})),
      )
    })?;
    labels = labels.custom(key, value).map_err(|error| {
      (
        StatusCode::BAD_REQUEST,
        Json(json!({"error": error.to_string()})),
      )
    })?;
  }
  let put = PutResource::new(ResourceWrite::new(name, labels)).map_err(|error| {
    (
      StatusCode::BAD_REQUEST,
      Json(json!({"error": error.to_string()})),
    )
  })?;
  let outcome = state.node.command(put).await.map_err(|error| {
    (
      StatusCode::CONFLICT,
      Json(json!({"error": error.to_string()})),
    )
  })?;
  Ok(Json(json!({
    "accepted": true,
    "is_winner": outcome.is_current_winner(),
    "version": version_json(outcome.accepted()),
  })))
}

#[derive(serde::Deserialize)]
pub struct ListQuery {
  pub limit: Option<usize>,
  /// Hex-encoded continuation cursor from the previous page.
  pub cursor: Option<String>,
}

async fn list_resources(
  state: State<SharedState>, Query(query): Query<ListQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
  let spec = page_spec(query.limit, query.cursor)?;
  let page = state
    .node
    .query(PageResources::new(spec))
    .await
    .map_err(internal_error)?;
  let items: Vec<Value> = page
    .items()
    .iter()
    .map(|view| {
      json!({
        "name": view.name().as_str(),
        "version": version_json(view),
      })
    })
    .collect();
  Ok(Json(json!({
    "items": items,
    "count": items.len(),
    "next": page.next().map(|cursor| to_hex(cursor.as_bytes())),
  })))
}

/// The selector surface: one canonical label-selector expression over
/// the live resource winners, paged exactly like the full listing.
#[derive(serde::Deserialize)]
pub struct SelectRequest {
  pub selector: String,
  pub limit: Option<usize>,
  pub cursor: Option<String>,
}

async fn select_resources(
  state: State<SharedState>, Json(request): Json<SelectRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
  let selector = Selector::parse(&request.selector).map_err(bad_request)?;
  let spec = page_spec(request.limit, request.cursor)?;
  let page = state
    .node
    .query(SelectResources::new(selector, spec))
    .await
    .map_err(internal_error)?;
  let items: Vec<Value> = page
    .items()
    .iter()
    .map(|view| {
      json!({
        "name": view.name().as_str(),
        "labels": labels_json(view),
        "version": version_json(view),
      })
    })
    .collect();
  Ok(Json(json!({
    "items": items,
    "count": items.len(),
    "next": page.next().map(|cursor| to_hex(cursor.as_bytes())),
  })))
}

/// Conditional removal: the caller echoes the exact version tuple it
/// observed, and the removal commits only while that tuple is still the
/// local winner — a stale request never removes newer metadata.
#[derive(serde::Deserialize)]
pub struct RemoveRequest {
  pub expected: ExpectedVersion,
}

#[derive(serde::Deserialize)]
pub struct ExpectedVersion {
  pub timestamp_millis: u64,
  pub writer: String,
  pub digest: String,
  #[serde(default)]
  pub removal: bool,
}

async fn remove_resource(
  state: State<SharedState>, AxumPath(name): AxumPath<String>, Json(request): Json<RemoveRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
  let name = ResourceName::parse(&name).map_err(bad_request)?;
  let writer = NodeId::parse(&request.expected.writer).map_err(bad_request)?;
  let bytes = from_hex(&request.expected.digest).ok_or_else(|| {
    (
      StatusCode::BAD_REQUEST,
      Json(json!({"error": "malformed digest"})),
    )
  })?;
  let digest: [u8; 32] = bytes.try_into().map_err(|_| {
    (
      StatusCode::BAD_REQUEST,
      Json(json!({"error": "digest must be 32 bytes"})),
    )
  })?;
  let expected = ResourceVersion::from_parts(
    std::time::SystemTime::UNIX_EPOCH
      + std::time::Duration::from_millis(request.expected.timestamp_millis),
    writer,
    request.expected.removal,
    Digest::from_bytes(digest),
  );
  let outcome = state
    .node
    .command(RemoveResource::new(name, expected))
    .await
    .map_err(|error| {
      // A stale expectation is a conflict, not a server fault: the
      // caller must re-observe and retry.
      (
        StatusCode::CONFLICT,
        Json(json!({"error": error.to_string()})),
      )
    })?;
  Ok(Json(json!({
    "removed": true,
    "is_winner": outcome.is_current_winner(),
    "version": version_json(outcome.accepted()),
  })))
}

/// The trust plane view: the exact node-to-key bindings this node
/// verifies signatures against, with each binding's status.
async fn trust(state: State<SharedState>) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
  let page = state
    .node
    .query(PageTrust::new(
      PageSpec::first(PAGE_LIMIT).map_err(bad_request)?,
    ))
    .await
    .map_err(internal_error)?;
  let items: Vec<Value> = page
    .items()
    .iter()
    .map(|view| {
      json!({
        "node_id": view.node_id().as_str(),
        "status": format!("{:?}", view.status()).to_lowercase(),
      })
    })
    .collect();
  Ok(Json(json!({"items": items, "count": items.len()})))
}

#[derive(serde::Deserialize)]
pub struct SubjectRequest {
  pub node_id: String,
}

/// Revokes one identity's exact binding: its sessions close and its
/// new sessions, admissions, and dials fail closed. Stored metadata
/// stays eligible for ordinary sync (an authorization boundary, not
/// content erasure).
async fn revoke(
  state: State<SharedState>, Json(request): Json<SubjectRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
  let subject = NodeId::parse(&request.node_id).map_err(bad_request)?;
  let page = state
    .node
    .query(PageTrust::new(
      PageSpec::first(PAGE_LIMIT).map_err(bad_request)?,
    ))
    .await
    .map_err(internal_error)?;
  let binding = page
    .items()
    .iter()
    .find(|view| view.node_id() == &subject)
    .ok_or_else(|| {
      (
        StatusCode::NOT_FOUND,
        Json(json!({"error": "no trust binding observed for subject"})),
      )
    })?;
  let outcome = state
    .node
    .command(RevokeNode::new(subject, binding.public_key().clone()))
    .await
    .map_err(internal_error)?;
  Ok(Json(json!({
    "revoked": true,
    "already": outcome.was_already_revoked(),
    "subject": outcome.subject().as_str(),
  })))
}

/// Issues the convergent issuer-signed cleanup tombstone for one
/// decommissioned node. Terminal — the deployment owns the decision to
/// never clean a merely offline node.
async fn cleanup(
  state: State<SharedState>, Json(request): Json<SubjectRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
  let subject = NodeId::parse(&request.node_id).map_err(bad_request)?;
  state
    .node
    .command(CleanupNode::new(subject))
    .await
    .map_err(internal_error)?;
  Ok(Json(json!({"cleaned": true})))
}

/// Starts a cleanup checkpoint GC epoch at the current wall clock
/// (max-wins across nodes). Issued only against a converged cluster.
async fn cleanup_checkpoint(
  state: State<SharedState>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
  let watermark = state
    .node
    .command(IssueCleanupCheckpoint::new())
    .await
    .map_err(internal_error)?;
  Ok(Json(json!({"watermark": watermark})))
}

/// Opens a one-chunk stream to the first other cluster member and waits
/// for the consumer's delivery: an on-demand data-plane health probe.
/// Self-directed streams are not a routing concept (a relay data plane
/// has no route to itself), so the probe always targets a peer.
async fn stream_probe(state: State<SharedState>) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
  // Direct routing reaches session neighbors only, so the probe picks
  // its target from the live session table.
  let sessions = state
    .node
    .query(PageSessions::new(
      PageSpec::first(64).map_err(internal_error)?,
    ))
    .await
    .map_err(internal_error)?;
  let peer = sessions
    .items()
    .first()
    .map(|session| session.peer().clone())
    .ok_or_else(|| {
      (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({"error": "no established session to probe"})),
      )
    })?;
  let started = std::time::Instant::now();
  let stream = state
    .node
    .open_stream(
      StreamTarget::Exact(peer),
      ProtocolTag::parse("radiata.woooo.tech/protocols/probe").unwrap(),
      StreamPolicy::new(RoutingPolicy::Direct, 8).unwrap(),
      StreamMetadata::new(),
    )
    .map_err(|error| {
      (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": error.to_string()})),
      )
    })?;
  let body = futures_util::stream::iter([Ok(Arc::from(vec![0xA5u8; 1024].into_boxed_slice()))]);
  stream.send_sync(body).await.map_err(|error| {
    (
      StatusCode::INTERNAL_SERVER_ERROR,
      Json(json!({"error": error.to_string()})),
    )
  })?;
  let acked = started.elapsed();
  Ok(Json(json!({"ack_us": acked.as_micros() as u64})))
}

pub fn internal_error(error: radiata::Error) -> (StatusCode, Json<Value>) {
  (
    StatusCode::INTERNAL_SERVER_ERROR,
    Json(json!({"error": error.to_string()})),
  )
}

/// The public recovery-plane view: whether every known online member has
/// an authenticated path, how many members remain unreachable, and the
/// next scheduled attempt (operator debugging for partition healing).
async fn recovery(state: State<SharedState>) -> Json<Value> {
  match state.node.query(radiata::GetRecovery::new()).await {
    Ok(view) => Json(json!({
      "connected": view.is_connected(),
      "unreachable_members": view.unreachable_members(),
      "next_attempt_at": view.next_attempt_at()
        .and_then(|at| at.duration_since(std::time::SystemTime::UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs()),
    })),
    Err(error) => Json(json!({"error": error.to_string()})),
  }
}

pub fn router(state: SharedState) -> Router {
  Router::new()
    .route("/status", get(status))
    .route("/join-token", get(join_token))
    .route("/join", post(join))
    .route("/connect", post(connect))
    .route("/disconnect", post(disconnect))
    .route("/leave", post(leave))
    .route("/resources", get(list_resources))
    .route(
      "/resources/{*name}",
      get(get_resource).put(put_resource).delete(remove_resource),
    )
    .route("/resources/select", post(select_resources))
    .route("/trust", get(trust))
    .route("/revoke", post(revoke))
    .route("/cleanup", post(cleanup))
    .route("/cleanup-checkpoint", post(cleanup_checkpoint))
    .route("/recovery", get(recovery))
    .route("/stream-probe", post(stream_probe))
    .with_state(state)
}
