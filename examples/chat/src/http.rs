//! The chat surface: every user command is a thin mapping from HTTP
//! onto either the metadata plane (identities, groups, announcements as
//! resources) or the data channel (DMs, group fan-out, read receipts).
//! All group fan-out and receipt logic is business-owned on purpose —
//! radiata carries the bytes, the chat room owns the semantics.

use std::sync::Arc;

use axum::{
  Json, Router,
  extract::{Path as AxumPath, Query, State},
  http::StatusCode,
  routing::{get, post},
};
use radiata::{
  GetResource, LabelKey, LabelValue, NodeHandle, NodeId, PageSessions, PageSpec, PutResource,
  RemoveResource, ResourceLabels, ResourceName, ResourceUri, ResourceWrite, RoutingPolicy,
  SelectResources, Selector, StreamMetadata, StreamPolicy, StreamTarget,
};
use serde_json::{Value, json};

use crate::{chat::WireMessage, store::ChatStore};

/// The metadata-plane naming scheme. Three resource kinds live under one
/// domain; the reserved `type` label separates them for selectors.
const DOMAIN: &str = "chat.example.org";
const TYPE_USER: &str = "chat-user";
const TYPE_GROUP: &str = "chat-group";
const TYPE_ANNOUNCE: &str = "chat-announce";
/// One comma-joined member list per group: label values are bounded, so
/// the example caps group rosters instead of inventing a second record kind.
const MAX_MEMBERS: usize = 16;

/// The bounded retry for a raced group-join read-modify-write: one
/// attempt per observed concurrent joiner is more than enough headroom
/// for the 5-node matrix, and a hot roster still fails closed.
const JOIN_RETRIES: usize = 16;

pub struct AppState {
  pub node: NodeHandle,
  pub node_id: NodeId,
  pub user: String,
  pub store: Arc<ChatStore>,
}

pub type SharedState = Arc<AppState>;

fn domain_tag(category: &str, name: &str) -> String {
  format!("{DOMAIN}/{category}/{name}")
}

fn name_error(error: radiata::Error) -> (StatusCode, Json<Value>) {
  (
    StatusCode::BAD_REQUEST,
    Json(json!({"error": error.to_string()})),
  )
}

fn not_found(message: &'static str) -> (StatusCode, Json<Value>) {
  (StatusCode::NOT_FOUND, Json(json!({"error": message})))
}

fn bad_request(message: &'static str) -> (StatusCode, Json<Value>) {
  (StatusCode::BAD_REQUEST, Json(json!({"error": message})))
}

fn conflict_msg(message: &'static str) -> (StatusCode, Json<Value>) {
  (StatusCode::CONFLICT, Json(json!({"error": message})))
}

fn conflict_error(error: radiata::Error) -> (StatusCode, Json<Value>) {
  (
    StatusCode::CONFLICT,
    Json(json!({"error": error.to_string()})),
  )
}

fn internal(error: impl std::fmt::Display) -> (StatusCode, Json<Value>) {
  (
    StatusCode::INTERNAL_SERVER_ERROR,
    Json(json!({"error": error.to_string()})),
  )
}

/// User and group name components: deliberately stricter than the tag
/// grammar, so the example never teaches customers to depend on quirks.
fn valid_component(value: &str) -> bool {
  !value.is_empty()
    && value.len() <= 32
    && value
      .chars()
      .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

fn now_millis() -> u64 {
  std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .map(|age| age.as_millis() as u64)
    .unwrap_or(0)
}

// ------------------------------------------------------------- metadata

/// Publishes (or re-asserts on restart) this node's chat identity: one
/// resource whose `node-id` label pins the user to exactly one node. The
/// record rides the ordinary resource plane so the roster converges; the
/// identity itself (keys, secrets) never leaves the node.
pub async fn publish_identity(state: &SharedState) -> Result<(), String> {
  let name = ResourceName::parse(&domain_tag("resources", &format!("user-{}", state.user)))
    .map_err(|error| error.to_string())?;
  let labels = ResourceLabels::new(
    LabelValue::parse(TYPE_USER).map_err(|error| error.to_string())?,
    ResourceUri::parse(&format!("chat://user/{}", state.user))
      .map_err(|error| error.to_string())?,
  )
  .custom(
    LabelKey::parse(&domain_tag("labels", "node-id")).map_err(|error| error.to_string())?,
    LabelValue::parse(state.node_id.as_str()).map_err(|error| error.to_string())?,
  )
  .map_err(|error| error.to_string())?;
  let put =
    PutResource::new(ResourceWrite::new(name, labels)).map_err(|error| error.to_string())?;
  state
    .node
    .command(put)
    .await
    .map_err(|error| error.to_string())?;
  Ok(())
}

/// Resolves one user to their pinned node through the locally converged
/// roster. A missing identity reads as an unknown user.
async fn resolve_user(state: &SharedState, user: &str) -> Option<NodeId> {
  let name = ResourceName::parse(&domain_tag("resources", &format!("user-{user}"))).ok()?;
  let view = state.node.query(GetResource::new(name)).await.ok()??;
  let node_id = view
    .labels()
    .custom_labels()
    .get(&LabelKey::parse(&domain_tag("labels", "node-id")).ok()?)
    .map(|value| value.as_str().to_owned())?;
  NodeId::parse(&node_id).ok()
}

/// Reads one locally converged resource view as JSON, `None` when the
/// name reads as absent (never written, or a removal tombstone won).
async fn get_resource_json(
  state: &SharedState, name: &str,
) -> Result<Option<(Value, radiata::ResourceVersion)>, (StatusCode, Json<Value>)> {
  let name = ResourceName::parse(name).map_err(name_error)?;
  match state.node.query(GetResource::new(name)).await {
    Ok(Some(view)) => {
      let custom: serde_json::Map<String, Value> = view
        .labels()
        .custom_labels()
        .entries()
        .map(|(key, value)| (key.as_str().to_owned(), json!(value.as_str())))
        .collect();
      let version = view.version().clone();
      let digest: String = version
        .digest()
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
      Ok(Some((
        json!({
          "name": view.name().as_str(),
          "labels": custom,
          "timestamp_millis": version
            .timestamp()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|age| age.as_millis() as u64)
            .unwrap_or(0),
          "digest": digest,
        }),
        version,
      )))
    }
    Ok(None) => Ok(None),
    Err(error) => Err(internal(error)),
  }
}

/// Lists one resource kind by its reserved type label.
async fn list_kind(
  state: &SharedState, kind: &str,
) -> Result<Vec<(Value, radiata::ResourceVersion)>, (StatusCode, Json<Value>)> {
  let selector =
    Selector::parse(&format!("radiata.woooo.tech/resources/type={kind}")).map_err(name_error)?;
  // Page through the whole selection: a single first page caps the
  // listing at one page's worth of entries, which silently truncated
  // every roster at the page bound (the star-128 "never converges"
  // measurement artifact).
  let mut out = Vec::new();
  let mut next = Some(PageSpec::first(64).map_err(name_error)?);
  while let Some(spec) = next {
    let page = state
      .node
      .query(SelectResources::new(selector.clone(), spec))
      .await
      .map_err(internal)?;
    for view in page.items() {
      let custom: serde_json::Map<String, Value> = view
        .labels()
        .custom_labels()
        .entries()
        .map(|(key, value)| (key.as_str().to_owned(), json!(value.as_str())))
        .collect();
      let version = view.version();
      let timestamp = version
        .timestamp()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|age| age.as_millis() as u64)
        .unwrap_or(0);
      out.push((
        json!({
          "name": view.name().as_str(),
          "labels": custom,
          "timestamp_millis": timestamp,
        }),
        version.clone(),
      ));
    }
    next = page
      .next()
      .cloned()
      .map(|cursor| PageSpec::after(cursor, 64))
      .transpose()
      .map_err(name_error)?;
  }
  out.sort_by_key(|(view, _)| view["timestamp_millis"].as_u64().unwrap_or(0));
  Ok(out)
}

// ------------------------------------------------------------ data plane

/// Sends one wire message over the data channel. The message is a
/// stream, not a resource: no metadata is written, and delivery reaches
/// exactly the addressed node or nobody. The boolean is the business
/// verdict; the error string is diagnostics only.
async fn send_wire(
  state: &SharedState, peer: &NodeId, message: &WireMessage,
) -> Result<(), String> {
  let payload = serde_json::to_vec(message).map_err(|error| error.to_string())?;
  let protocol =
    radiata::ProtocolTag::parse(crate::chat::CHAT_PROTOCOL).map_err(|error| error.to_string())?;
  // The hop budget must cover the mesh's longest simple path, not a
  // typical depth: a 32-node chain relay needs 31 hops (an 8-hop budget
  // never delivered across it), and routes are loop-free by validation,
  // so a generous budget costs nothing beyond one check per hop.
  let policy = StreamPolicy::new(RoutingPolicy::Direct, 128).map_err(|error| error.to_string())?;
  let stream = state
    .node
    .open_stream(
      StreamTarget::Exact(peer.clone()),
      protocol,
      policy,
      StreamMetadata::new(),
    )
    .map_err(|error| error.to_string())?;
  let chunk: Arc<[u8]> = Arc::from(payload.into_boxed_slice());
  let body = futures_util::stream::iter([Ok(chunk)]);
  stream
    .send_sync(body)
    .await
    .map(|_ack| ())
    .map_err(|error| error.to_string())
}

// --------------------------------------------------------------- handlers

async fn whoami(state: State<SharedState>) -> Json<Value> {
  Json(json!({
    "user": state.user,
    "node_id": state.node_id.as_str(),
  }))
}

#[derive(serde::Deserialize)]
pub struct AnnounceRequest {
  pub title: String,
  pub body: String,
}

/// Creates one announcement resource: it rides the resource sync plane
/// and therefore converges on every node.
async fn announce(
  state: State<SharedState>, Json(request): Json<AnnounceRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
  if !valid_component(&request.title) {
    return Err(bad_request("invalid announcement title"));
  }
  if request.body.is_empty() || request.body.len() > 200 {
    return Err(bad_request("announcement body must be 1..=200 bytes"));
  }
  let name = format!("announce-{}-{}", request.title, now_millis());
  let base = ResourceLabels::new(
    LabelValue::parse(TYPE_ANNOUNCE).map_err(name_error)?,
    ResourceUri::parse(&format!("chat://announce/{}", request.title)).map_err(name_error)?,
  );
  let labels = base
    .custom(
      LabelKey::parse(&domain_tag("labels", "body")).map_err(name_error)?,
      LabelValue::parse(&request.body).map_err(name_error)?,
    )
    .map_err(name_error)?;
  let labels = labels
    .custom(
      LabelKey::parse(&domain_tag("labels", "author")).map_err(name_error)?,
      LabelValue::parse(&state.user).map_err(name_error)?,
    )
    .map_err(name_error)?;
  let resource = format!("resources/{name}");
  let resource_name = ResourceName::parse(&domain_tag("resources", &name)).map_err(name_error)?;
  let put = PutResource::new(ResourceWrite::new(resource_name, labels)).map_err(name_error)?;
  state.node.command(put).await.map_err(conflict_error)?;
  Ok(Json(
    json!({"created": true, "name": domain_tag("resources", &name), "resource": resource}),
  ))
}

async fn announcements(
  state: State<SharedState>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
  let items = list_kind(&state, TYPE_ANNOUNCE).await?;
  let announcements: Vec<Value> = items
    .into_iter()
    .map(|(view, _)| {
      json!({
        "name": view["name"],
        "author": view["labels"].get(format!("{DOMAIN}/labels/author")),
        "body": view["labels"].get(format!("{DOMAIN}/labels/body")),
        "at_millis": view["timestamp_millis"],
      })
    })
    .collect();
  Ok(Json(json!({"announcements": announcements})))
}

async fn identities(state: State<SharedState>) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
  let items = list_kind(&state, TYPE_USER).await?;
  let users: Vec<Value> = items
    .into_iter()
    .map(|(view, _)| {
      json!({
        "user": view["name"].as_str().and_then(|name| name.rsplit('/').next().and_then(|tail| tail.strip_prefix("user-"))),
        "node_id": view["labels"].get(format!("{DOMAIN}/labels/node-id")),
      })
    })
    .collect();
  Ok(Json(json!({"identities": users})))
}

#[derive(serde::Deserialize)]
pub struct DmRequest {
  pub to: String,
  pub body: String,
}

/// Sends one direct message over the data channel. An unreachable peer
/// does NOT fail the command: the message lands in `pending` and a
/// later flush retries it — the customer owns the offline queue.
async fn send_dm(
  state: State<SharedState>, Json(request): Json<DmRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
  if !valid_component(&request.to) {
    return Err(bad_request("invalid user name"));
  }
  let peer = resolve_user(&state, &request.to)
    .await
    .ok_or_else(|| not_found("unknown user"))?;
  let msg_id = state
    .store
    .record_outbox(
      "dm",
      None,
      request.to.clone(),
      peer.as_str().to_owned(),
      Some(request.body.clone()),
    )
    .await
    .map_err(internal)?;
  let message = WireMessage {
    kind: "dm".to_owned(),
    msg_id: msg_id.clone(),
    group: None,
    from_user: state.user.clone(),
    to_user: Some(request.to),
    body: Some(request.body),
    at_millis: now_millis(),
  };
  let delivered = send_wire(&state, &peer, &message).await.is_ok();
  if delivered {
    state.store.mark_sent(&msg_id).await.map_err(internal)?;
  }
  Ok(Json(json!({
    "msg_id": msg_id,
    "state": if delivered { "sent" } else { "pending" },
  })))
}

/// Retries every pending outbound message, read receipts included: the
/// receiver's `mark_read` is idempotent, so a replayed receipt is
/// harmless and a receipt that finally lands heals the sender's state.
async fn flush(state: State<SharedState>) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
  let pending = state.store.pending_outbound().await.map_err(internal)?;
  let mut delivered = 0_usize;
  let mut still_pending = 0_usize;
  for message in pending {
    let peer = NodeId::parse(&message.to_node).map_err(internal)?;
    let wire = WireMessage {
      kind: message.kind.clone(),
      msg_id: message.msg_id.clone(),
      group: message.group.clone(),
      from_user: state.user.clone(),
      to_user: Some(message.to_user.clone()),
      body: message.body.clone(),
      at_millis: message.created_at_millis,
    };
    if send_wire(&state, &peer, &wire).await.is_ok() {
      state
        .store
        .mark_sent(&message.msg_id)
        .await
        .map_err(internal)?;
      delivered += 1;
    } else {
      still_pending += 1;
    }
  }
  Ok(Json(
    json!({"delivered": delivered, "still_pending": still_pending}),
  ))
}

#[derive(serde::Deserialize)]
pub struct ListQuery {
  /// `inbox` (default) or `outbox`.
  pub r#box: Option<String>,
  /// Inbox only: list only unseen messages.
  pub unread: Option<bool>,
}

/// Lists messages. Viewing the inbox is the read event: every message
/// shown for the first time is marked seen and a read receipt is sent to
/// its sender — receipts are user-driven by design, never automatic on
/// delivery.
async fn list_messages(
  state: State<SharedState>, Query(query): Query<ListQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
  match query.r#box.as_deref().unwrap_or("inbox") {
    "inbox" => {
      let (messages, newly_seen) = state
        .store
        .list_inbox(query.unread.unwrap_or(false))
        .await
        .map_err(internal)?;
      let mut receipts_sent = 0_usize;
      for message in &newly_seen {
        // The receipt targets the MESSAGE AUTHOR, resolved through the
        // roster: on a multi-hop relay the wire-level source is the last
        // hop node, not the author, so from_node cannot address it.
        let peer = resolve_user(&state, &message.from_user)
          .await
          .ok_or_else(|| not_found("author node unknown"))?;
        let receipt = WireMessage {
          kind: "read".to_owned(),
          msg_id: message.msg_id.clone(),
          group: message.group.clone(),
          from_user: state.user.clone(),
          to_user: Some(message.from_user.clone()),
          body: None,
          at_millis: now_millis(),
        };
        let receipt_id = state
          .store
          .record_outbox(
            "read",
            message.group.clone(),
            message.from_user.clone(),
            message.from_node.clone(),
            None,
          )
          .await
          .map_err(internal)?;
        if send_wire(&state, &peer, &receipt).await.is_ok() {
          state.store.mark_sent(&receipt_id).await.map_err(internal)?;
          receipts_sent += 1;
        }
      }
      Ok(Json(
        json!({"messages": messages, "receipts_sent": receipts_sent}),
      ))
    }
    "outbox" => {
      let messages = state.store.list_outbox(false).await.map_err(internal)?;
      Ok(Json(json!({"messages": messages})))
    }
    _ => Err(not_found("unknown box")),
  }
}

#[derive(serde::Deserialize)]
pub struct ReadRequest {
  pub msg_id: String,
}

/// Explicitly reads one inbox message and emits its receipt.
async fn mark_read(
  state: State<SharedState>, Json(request): Json<ReadRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
  let Some(message) = state
    .store
    .mark_inbox_seen(&request.msg_id)
    .await
    .map_err(internal)?
  else {
    return Ok(Json(
      json!({"receipt_sent": false, "reason": "already seen or unknown"}),
    ));
  };
  // Same author-targeting rule as the inbox listing: from_node is the
  // last relay hop on a multi-hop route, not the author.
  let peer = resolve_user(&state, &message.from_user)
    .await
    .ok_or_else(|| not_found("author node unknown"))?;
  let receipt = WireMessage {
    kind: "read".to_owned(),
    msg_id: message.msg_id.clone(),
    group: message.group.clone(),
    from_user: state.user.clone(),
    to_user: Some(message.from_user.clone()),
    body: None,
    at_millis: now_millis(),
  };
  let receipt_id = state
    .store
    .record_outbox(
      "read",
      message.group.clone(),
      message.from_user.clone(),
      message.from_node.clone(),
      None,
    )
    .await
    .map_err(internal)?;
  let sent = send_wire(&state, &peer, &receipt).await.is_ok();
  if sent {
    state.store.mark_sent(&receipt_id).await.map_err(internal)?;
  }
  Ok(Json(json!({"receipt_sent": sent})))
}

fn members_of(labels: &Value) -> Vec<String> {
  labels
    .get(format!("{DOMAIN}/labels/member"))
    .and_then(Value::as_str)
    .map(|members| {
      members
        .split(',')
        .filter(|member| !member.is_empty())
        .map(str::to_owned)
        .collect()
    })
    .unwrap_or_default()
}

#[derive(serde::Deserialize)]
pub struct GroupRequest {
  pub name: String,
}

/// Builds one group resource's labels: the comma-joined member roster
/// plus the immutable owner. One helper keeps create and join on the
/// exact same label shape, so a join can never silently re-shape the
/// record.
fn group_labels(members: &str, owner: &str, name: &str) -> Result<ResourceLabels, radiata::Error> {
  let base = ResourceLabels::new(
    LabelValue::parse(TYPE_GROUP)?,
    ResourceUri::parse(&format!("chat://group/{name}"))?,
  );
  let labels = base.custom(
    LabelKey::parse(&domain_tag("labels", "member"))?,
    LabelValue::parse(members)?,
  )?;
  labels.custom(
    LabelKey::parse(&domain_tag("labels", "owner"))?,
    LabelValue::parse(owner)?,
  )
}

/// Creates one group chat: a resource whose member label lists the
/// roster. The creator is the first member.
async fn create_group(
  state: State<SharedState>, Json(request): Json<GroupRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
  if !valid_component(&request.name) {
    return Err(bad_request("invalid group name"));
  }
  let name = domain_tag("resources", &format!("group-{}", request.name));
  if get_resource_json(&state, &name).await?.is_some() {
    return Err(conflict_msg("group already exists"));
  }
  let labels = group_labels(&state.user, &state.user, &request.name).map_err(name_error)?;
  let put = PutResource::new(ResourceWrite::new(
    ResourceName::parse(&name).map_err(name_error)?,
    labels,
  ))
  .map_err(name_error)?;
  state.node.command(put).await.map_err(conflict_error)?;
  Ok(Json(
    json!({"created": true, "group": request.name, "members": [state.user]}),
  ))
}

/// Joins one group: a read-modify-write over the member label under an
/// exact-version precondition. A raced join conflicts explicitly and
/// retries with a fresh read, so concurrent joins no longer lose
/// updates; the retry bound keeps a hotly-contended roster from
/// spinning forever.
async fn join_group(
  state: State<SharedState>, AxumPath(name): AxumPath<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
  if !valid_component(&name) {
    return Err(bad_request("invalid group name"));
  }
  let full = domain_tag("resources", &format!("group-{name}"));
  for _attempt in 0..JOIN_RETRIES {
    let Some((view, version)) = get_resource_json(&state, &full).await? else {
      return Err(not_found("unknown group"));
    };
    let mut members = members_of(&view["labels"]);
    if members.contains(&state.user) {
      return Ok(Json(
        json!({"joined": true, "members": members, "already": true}),
      ));
    }
    if members.len() >= MAX_MEMBERS {
      return Err(not_found("group is full"));
    }
    members.push(state.user.clone());
    let roster = members.join(",");
    let owner = view["labels"]
      .get(format!("{DOMAIN}/labels/owner"))
      .and_then(Value::as_str)
      .unwrap_or(&state.user)
      .to_owned();
    let labels = group_labels(&roster, &owner, &name).map_err(name_error)?;
    let put = PutResource::with_expected(
      ResourceWrite::new(ResourceName::parse(&full).map_err(name_error)?, labels),
      version,
    )
    .map_err(name_error)?;
    match state.node.command(put).await {
      Ok(_) => return Ok(Json(json!({"joined": true, "members": members}))),
      // The precondition lost a race: re-read and rebuild.
      Err(error) if error.kind() == radiata::ErrorKind::Conflict => continue,
      Err(error) => return Err(conflict_error(error)),
    }
  }
  Err(conflict_msg("group join raced past the retry bound"))
}

async fn list_groups(state: State<SharedState>) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
  let items = list_kind(&state, TYPE_GROUP).await?;
  let groups: Vec<Value> = items
    .into_iter()
    .map(|(view, _)| {
      json!({
        "name": view["name"].as_str().and_then(|name| name.rsplit('/').next().and_then(|tail| tail.strip_prefix("group-"))),
        "members": members_of(&view["labels"]),
        "owner": view["labels"].get(format!("{DOMAIN}/labels/owner")),
      })
    })
    .collect();
  Ok(Json(json!({"groups": groups})))
}

/// Dissolves one group: a conditional removal of the group resource.
/// The removal tombstone converges, so every member's group view reads
/// as gone — further sends fail closed.
async fn dissolve_group(
  state: State<SharedState>, AxumPath(name): AxumPath<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
  if !valid_component(&name) {
    return Err(bad_request("invalid group name"));
  }
  let full = domain_tag("resources", &format!("group-{name}"));
  let Some((view, version)) = get_resource_json(&state, &full).await? else {
    return Ok(Json(json!({"dissolved": true, "already": true})));
  };
  if view["labels"].is_null() {
    return Ok(Json(json!({"dissolved": true, "already": true})));
  }
  state
    .node
    .command(RemoveResource::new(
      ResourceName::parse(&full).map_err(name_error)?,
      version,
    ))
    .await
    .map_err(conflict_error)?;
  Ok(Json(json!({"dissolved": true})))
}

#[derive(serde::Deserialize)]
pub struct GroupMessageRequest {
  pub body: String,
}

/// Sends one group message: the sender reads the locally converged
/// group resource, derives the recipient set, and fans the message out
/// over the data channel — one receipt per recipient eventually comes
/// back through the same channel.
async fn send_group_message(
  state: State<SharedState>, AxumPath(name): AxumPath<String>,
  Json(request): Json<GroupMessageRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
  if !valid_component(&name) {
    return Err(bad_request("invalid group name"));
  }
  let full = domain_tag("resources", &format!("group-{name}"));
  let Some((view, _)) = get_resource_json(&state, &full).await? else {
    return Err(not_found("unknown or dissolved group"));
  };
  let members = members_of(&view["labels"]);
  let recipients: Vec<&String> = members
    .iter()
    .filter(|member| *member != &state.user)
    .collect();
  let mut results = serde_json::Map::new();
  let at_millis = now_millis();
  for member in recipients {
    let Some(peer) = resolve_user(&state, member).await else {
      results.insert(member.clone(), json!({"state": "unknown-user"}));
      continue;
    };
    let msg_id = state
      .store
      .record_outbox(
        "group",
        Some(name.clone()),
        member.clone(),
        peer.as_str().to_owned(),
        Some(request.body.clone()),
      )
      .await
      .map_err(internal)?;
    let wire = WireMessage {
      kind: "group".to_owned(),
      msg_id: msg_id.clone(),
      group: Some(name.clone()),
      from_user: state.user.clone(),
      to_user: Some(member.clone()),
      body: Some(request.body.clone()),
      at_millis,
    };
    let delivered = send_wire(&state, &peer, &wire).await.is_ok();
    if delivered {
      state.store.mark_sent(&msg_id).await.map_err(internal)?;
    }
    results.insert(
      member.clone(),
      json!({"state": if delivered { "sent" } else { "pending" }, "msg_id": msg_id}),
    );
  }
  Ok(Json(json!({"group": name, "recipients": results})))
}

/// Issues one merge credential. Issuing is non-rotating: the same live
/// generation admits any number of concurrent joins until it is rotated
/// (explicit revocation) or expires.
async fn join_token(state: State<SharedState>) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
  let issued = state
    .node
    .command(radiata::IssueMergeCredential::new())
    .await
    .map_err(internal)?;
  Ok(Json(json!({
    "credential": issued.credential().expose_secret(),
    "node_id": state.node_id.as_str(),
  })))
}

#[derive(serde::Deserialize)]
pub struct JoinRequest {
  /// Bootstrap node's HTTP address, e.g. "c1:8080".
  pub bootstrap_http: String,
  /// Bootstrap node's wss endpoint, e.g. "wss://c1:9443".
  pub bootstrap_wss: String,
}

/// Merges this node into the chat cluster through the bootstrap peer:
/// the token is fetched live (issuing is non-rotating, so concurrent
/// joins share the generation), then the merge command runs with
/// bounded retries.
async fn join_chat(
  state: State<SharedState>, Json(request): Json<JoinRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
  let mut attempt = 0_u32;
  loop {
    attempt += 1;
    let token = crate::http_client::get_json(&request.bootstrap_http, "/join-token")
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
    let credential = radiata::MergeCredential::parse(secret).map_err(|error| {
      (
        StatusCode::BAD_GATEWAY,
        Json(json!({"error": error.to_string()})),
      )
    })?;
    let endpoint = radiata::Endpoint::parse(&request.bootstrap_wss).map_err(name_error)?;
    match state
      .node
      .command(radiata::MergeCluster::new(endpoint, credential))
      .await
    {
      Ok(_) => return Ok(Json(json!({"joined": true}))),
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

/// The node's full session table, for the harness's mesh waits and the
/// redundant-edge verification: walks every page so the count and the
/// peer edge set stay exact at any cluster size, not just the first 64
/// sessions. `sessions` is the raw live-session count and `distinct` the
/// deduplicated peer count — a gap between the two is a parallel
/// duplicate edge.
async fn mesh_sessions(
  state: State<SharedState>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
  let mut raw = 0_usize;
  let mut peers: Vec<String> = Vec::new();
  let mut next = Some(PageSpec::first(64).map_err(name_error)?);
  while let Some(page) = next {
    let view = state
      .node
      .query(PageSessions::new(page))
      .await
      .map_err(internal)?;
    raw += view.items().len();
    peers.extend(
      view
        .items()
        .iter()
        .map(|session| session.peer().as_str().to_owned()),
    );
    next = view
      .next()
      .cloned()
      .map(|cursor| PageSpec::after(cursor, 64))
      .transpose()
      .map_err(name_error)?;
  }
  peers.sort();
  peers.dedup();
  Ok(Json(
    json!({"sessions": raw, "distinct": peers.len(), "peers": peers}),
  ))
}

fn label_map_json(view: &radiata::MemberView) -> serde_json::Map<String, Value> {
  view
    .labels()
    .entries()
    .map(|(key, value)| (key.as_str().to_owned(), json!(value.as_str())))
    .collect()
}

/// Reads the node's own owner metadata: the capability label map plus
/// the revision a conditional update must expect. The scenario fuzz
/// harness drives node labeling through this surface.
async fn get_metadata(state: State<SharedState>) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
  let view = state
    .node
    .query(radiata::GetMember::new(state.node_id.clone()))
    .await
    .map_err(internal)?
    .ok_or_else(|| not_found("local member view"))?;
  Ok(Json(json!({
    "labels": label_map_json(&view),
    "revision": view.owner_revision(),
  })))
}

/// Reads any member's converged capability labels plus the owner
/// revision: the descriptor page plane carries owner metadata to every
/// peer, so the same read on different nodes converges to the same
/// value. The scenario fuzz harness asserts label convergence through
/// this surface.
async fn member_labels(
  state: State<SharedState>, AxumPath(user): AxumPath<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
  if !valid_component(&user) {
    return Err(bad_request("invalid user"));
  }
  let Some(node_id) = resolve_user(&state, &user).await else {
    return Err(not_found("unknown user"));
  };
  let view = state
    .node
    .query(radiata::GetMember::new(node_id))
    .await
    .map_err(internal)?
    .ok_or_else(|| not_found("member view not converged"))?;
  Ok(Json(json!({
    "user": user,
    "revision": view.owner_revision(),
    "labels": label_map_json(&view),
  })))
}

#[derive(serde::Deserialize)]
pub struct MetadataUpdateRequest {
  /// Capability labels to set (domain-qualified keys are derived from
  /// these bare names, matching every other chat-surface label).
  pub set_labels: std::collections::HashMap<String, String>,
  /// Capability labels to remove.
  #[serde(default)]
  pub remove_labels: Vec<String>,
  /// The owner revision the update applies on top of; a stale value
  /// conflicts (409) and the caller retries from a fresh read.
  pub expected_revision: u64,
}

/// Conditionally updates the node's own owner metadata: strictly higher
/// revision, capability labels set and removed as one transaction, the
/// updated view returned. A raced update conflicts (409).
async fn update_metadata(
  state: State<SharedState>, Json(request): Json<MetadataUpdateRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
  let mut patch = radiata::NodeMetadataPatch::new();
  for (name, value) in &request.set_labels {
    let key = LabelKey::parse(&domain_tag("labels", name)).map_err(name_error)?;
    let value = LabelValue::parse(value).map_err(name_error)?;
    patch = patch.set_capability(key, value).map_err(conflict_error)?;
  }
  for name in &request.remove_labels {
    let key = LabelKey::parse(&domain_tag("labels", name)).map_err(name_error)?;
    patch = patch.remove_capability(key).map_err(conflict_error)?;
  }
  let view = state
    .node
    .command(radiata::UpdateNodeMetadata::new(
      request.expected_revision,
      patch,
    ))
    .await
    .map_err(conflict_error)?;
  Ok(Json(json!({
    "labels": label_map_json(&view),
    "revision": view.owner_revision(),
  })))
}

#[derive(serde::Deserialize)]
pub struct DisconnectRequest {
  pub node_id: String,
}

/// Tears one session down on purpose. The recovery plane re-dials the
/// peer while the node is otherwise isolated, so this is a temporary
/// break, never a departure.
async fn disconnect(
  state: State<SharedState>, Json(request): Json<DisconnectRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
  let peer = NodeId::parse(&request.node_id).map_err(name_error)?;
  state
    .node
    .command(radiata::DisconnectPeer::new(peer))
    .await
    .map_err(internal)?;
  Ok(Json(json!({"disconnected": true})))
}

#[derive(serde::Deserialize)]
pub struct ConnectRequest {
  pub endpoint: String,
  pub node_id: String,
}

/// Dials one peer explicitly: the topology shaper uses it to add the
/// non-tree edges of a shaped graph after the roster converges. A
/// caller-directed dial is a configured edge — the recovery pruner
/// never reclaims it.
async fn connect(
  state: State<SharedState>, Json(request): Json<ConnectRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
  let endpoint = radiata::Endpoint::parse(&request.endpoint).map_err(name_error)?;
  let node_id = NodeId::parse(&request.node_id).map_err(name_error)?;
  let connected = state
    .node
    .command(radiata::ConnectMember::new(endpoint, node_id))
    .await
    .map_err(internal)?;
  Ok(Json(json!({"connected": connected.as_str()})))
}

/// Leaves the cluster: the identity is replaced and the old identity's
/// core metadata is deleted (the operator acknowledges deliberately).
/// The former user's chat identity resource stays behind as departed
/// evidence until the deployment cleans it.
async fn leave(state: State<SharedState>) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
  let outcome = state
    .node
    .command(radiata::LeaveCluster::new(
      radiata::ReplaceIdentityAndDeleteOldCoreMetadata::new(),
    ))
    .await
    .map_err(internal)?;
  Ok(Json(json!({
    "left": true,
    "former_identity": outcome.former_identity().as_str(),
    "replacement_identity": outcome.replacement_identity().as_str(),
  })))
}

pub fn router(state: SharedState) -> Router {
  Router::new()
    .route("/whoami", get(whoami))
    .route("/identities", get(identities))
    .route("/announce", post(announce))
    .route("/announcements", get(announcements))
    .route("/dm", post(send_dm))
    .route("/flush", post(flush))
    .route("/messages", get(list_messages))
    .route("/read", post(mark_read))
    .route("/groups", post(create_group).get(list_groups))
    .route("/groups/{name}/join", post(join_group))
    .route("/groups/{name}/send", post(send_group_message))
    .route("/groups/{name}/dissolve", post(dissolve_group))
    .route("/join-token", get(join_token))
    .route("/join-chat", post(join_chat))
    .route("/metadata", get(get_metadata).post(update_metadata))
    .route("/labels/{user}", get(member_labels))
    .route("/mesh-sessions", get(mesh_sessions))
    .route("/disconnect", post(disconnect))
    .route("/connect", post(connect))
    .route("/leave", post(leave))
    .with_state(state)
}
