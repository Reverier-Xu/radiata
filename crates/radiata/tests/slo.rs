//! The service-level-objective (SLO) harness: two measured convergence
//! strata, each `#[ignore]`-gated so it runs explicitly in CI and on the
//! nightly lane.
//!
//! Run: `cargo test --release --test slo -- --ignored --nocapture`
//!
//! Every stratum builds a three-node cluster over the shared in-memory
//! storage provider and the scripted key provider (`tests/common`),
//! drives one disturbance through the public facade only, and measures
//! the wall-clock interval until the cluster's *observable* state
//! reflects the disturbance. The bounds are derived from cadences the
//! library already documents, never from a number tuned to one machine:
//!
//! - the anti-entropy tick ([`SYNC_TICK`], set through
//!   `NodeConfig::with_anti_entropy_schedule`) is the reconciliation plane's
//!   local-write debounce and the unit of the quiet detection cadence;
//! - the quiet detection cadence ([`DETECTION_CADENCE_TICKS`], 32 ticks in
//!   `src/sync_common.rs`) is the documented loss-recovery backstop that heals
//!   any drift no message ever observed;
//! - the per-payload admission budget ([`SEND_ACK_WAIT`], 5 s in
//!   `src/sync_common.rs`) bounds one round's payload, because the receiver's
//!   admission is a durable commit;
//! - the outbound dial and session-bootstrap deadlines ([`DIAL_DEADLINE`],
//!   [`AUTHENTICATION_DEADLINE`]) bound the transport half of a reconnect. The
//!   harness configures both explicitly, so the documented bound is derived
//!   from the same values the nodes run.
//!
//! ## SLO 1 — revocation propagation
//!
//! **Measured**: from the instant the issuer's `revoke` commit resolves
//! until *every live node* observes the revocation — the issuer holds no
//! session to the subject, every live node reports the subject's binding
//! as `TrustStatus::Revoked`, and every live node refuses a dial to it
//! with `ErrorKind::Revoked`. The revoked subject is not a live node: the
//! revoke closes its sessions and it is no longer authorized in the
//! cluster, so it never learns the tombstone (by design).
//!
//! **Bound**: [`CONVERGENCE_BOUND`] = `DETECTION_CADENCE_TICKS ×
//! SYNC_TICK + SEND_ACK_WAIT` (37 s at this harness's 1 s tick).
//!
//! **Why the bound is defensible**: the revocation tombstone is one row
//! in the revocation lane. Its commit notes the store namespace, so the
//! next sync tick rescans only that lane and leaves each peer one
//! coalesced HINT carrying the row on the eager-delta piggyback; a peer
//! that applies it is done in one tick plus one round trip. If the HINT
//! or its payload is lost, the hint retry ladder (1, 2, 4, 8 ticks)
//! re-sends it, and the quiet detection cadence — 32 ticks — is the
//! documented backstop for drift no message ever observed. One payload's
//! admission is bounded by `SEND_ACK_WAIT`. No propagation can therefore
//! exceed one cadence period plus one admission budget, whatever the loss
//! pattern.
//!
//! ## SLO 2 — reconnect catch-up
//!
//! **Measured**: a three-node cluster holds a converged catalog of
//! [`CATALOG_SIZE`] (256) resources. One member is disconnected from the
//! hub, the hub writes [`RECONNECT_CHANGE_COUNT`] (32) further resources
//! while that member is away, the hub reconnects it, and the harness
//! measures from the reconnect dial until the reconnected member's paged
//! catalog equals the hub's.
//!
//! **Bound**: [`RECONNECT_CATCHUP_BOUND`] = `DIAL_DEADLINE +
//! AUTHENTICATION_DEADLINE + CONVERGENCE_BOUND` (48.2 s at this harness's
//! settings), and the convergence stage alone is asserted against
//! [`CONVERGENCE_BOUND`] (8.2 s).
//!
//! **Why the bound is defensible**: the reconnect pays exactly three
//! documented stages. The outbound dial is bounded by `DIAL_DEADLINE` and
//! the session bootstrap by `AUTHENTICATION_DEADLINE` (both are the
//! shipped defaults, configured explicitly here so the bound and the
//! nodes agree). The rejoined session then opens with a whole-lane
//! summary exchange that primes the peer with the lane's full row set, so
//! the catalog catch-up is one reconciliation round rather than a
//! per-record replay — bounded, exactly like SLO 1, by one quiet
//! detection cadence plus one payload admission budget. The harness
//! reports the two stages separately and asserts both bounds, so a
//! regression in the convergence half cannot hide behind the transport
//! half.
//!
//! [`CATALOG_SIZE`] is 256 because that is the smallest power-of-two
//! catalog spanning five 64-record pages: the catch-up then exercises
//! multi-page paging and a multi-round prime instead of the single-page
//! special case, while the whole stratum still runs in seconds.

use std::{
  collections::BTreeSet,
  sync::Arc,
  time::{Duration, Instant},
};

use radiata::{
  Endpoint, ErrorKind, NodeBuilder, NodeConfig, NodeHandle, NodeId, PageSpec, ResourceLabels,
  ResourceName, ResourceUri, ResourceWrite, TrustStatus, extension::KeyProvider,
};

mod common;

use common::{MemoryStorageFactory, ScriptedKeys};

/// The anti-entropy cadence every node in this harness runs: every
/// second. The shipped default; the SLO bounds scale with the tick.
const SYNC_SCHEDULE: &str = "{*}-{*}-{*}T{*}:{*}:{*}Z";
const SYNC_TICK: Duration = Duration::from_secs(1);

/// The reconciliation plane's quiet detection cadence, in sync ticks
/// (`DETECTION_CADENCE_TICKS` in `src/sync_common.rs`). Re-declared here
/// because the constant is `pub(crate)`; the module doc explains why
/// every bound below is expressed against it.
const DETECTION_CADENCE_TICKS: u32 = 32;

/// The bounded admission wait for one sync payload (`SEND_ACK_WAIT` in
/// `src/sync_common.rs`). Re-declared for the same reason.
const SEND_ACK_WAIT: Duration = Duration::from_secs(5);

/// The outbound dial bound the harness configures (the shipped
/// `NodeConfig` default).
const DIAL_DEADLINE: Duration = Duration::from_secs(10);

/// The session-bootstrap bound the harness configures (the shipped
/// `NodeConfig` default).
const AUTHENTICATION_DEADLINE: Duration = Duration::from_secs(30);

/// The converged catalog every node holds before the reconnect stratum
/// disconnects a member.
const CATALOG_SIZE: u32 = 256;

/// The resources the hub writes while the member is disconnected: a
/// bounded change set whose catch-up the stratum measures.
const RECONNECT_CHANGE_COUNT: u32 = 32;

/// The disturbance attempts before the stratum gives up. An isolated
/// member's recovery plane redials on its own cadence, so a recovery dial
/// can land inside the change phase and re-establish the session the
/// stratum is trying to hold open. Each attempt uses a fresh change-set
/// seed range, so a retried change set is still a change the member
/// missed; a successful recovery dial also pushes the next one a full
/// backoff away, which is what makes the retry reliable.
const DISTURBANCE_ATTEMPTS: u32 = 3;

/// The convergence stage's bound, shared by both strata: one quiet
/// detection cadence (the loss-recovery backstop that heals any drift no
/// message ever observed) plus one payload admission budget. SLO 1's
/// whole measurement is this bound; SLO 2's catch-up stage is.
const CONVERGENCE_BOUND: Duration = SYNC_TICK
  .saturating_mul(DETECTION_CADENCE_TICKS)
  .saturating_add(SEND_ACK_WAIT);

/// SLO 2's whole-measurement bound: the bounded dial, the bounded
/// session bootstrap, then the convergence stage.
const RECONNECT_CATCHUP_BOUND: Duration = DIAL_DEADLINE
  .saturating_add(AUTHENTICATION_DEADLINE)
  .saturating_add(CONVERGENCE_BOUND);

/// The untimed-setup wait: convergence before a stratum starts measuring
/// is asserted, never measured, so it gets a generous bound.
const SETUP_TIMEOUT: Duration = Duration::from_secs(120);

/// The measurement poll interval: reads the local store only, so it never
/// perturbs the cadence it measures.
const POLL: Duration = Duration::from_millis(10);

/// The page size every paged read in this harness uses (the public view's
/// page limit).
const PAGE_LIMIT: usize = 64;

/// The resource name prefix of this harness's catalog.
const CATALOG_PREFIX: &str = "radiata.woooo.tech/resources/slo";

/// Installs the harness's subscriber once: the harness's own `info`
/// measurements always show, the crate stays at its warning level, and
/// `RUST_LOG` overrides both (raise it to `radiata=debug` for a
/// convergence diagnosis).
fn init_tracing() {
  use std::sync::Once;
  static INIT: Once = Once::new();
  INIT.call_once(|| {
    let _ = tracing_subscriber::fmt()
      .with_env_filter(
        tracing_subscriber::EnvFilter::try_from_default_env()
          .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,radiata=warn")),
      )
      .with_test_writer()
      .try_init();
  });
}

struct Node {
  handle: NodeHandle,
  endpoint: Endpoint,
  id: NodeId,
}

async fn start_node(seed: u64) -> Node {
  let storage = Arc::new(MemoryStorageFactory::new(common::required_capabilities()));
  let keys: Arc<dyn KeyProvider> = Arc::new(ScriptedKeys::full_at(900_000 + seed * 1_000));
  let config = NodeConfig::new()
    .with_anti_entropy_schedule(SYNC_SCHEDULE)
    .unwrap()
    .with_dial_deadline(DIAL_DEADLINE)
    .unwrap()
    .with_authentication_deadline(AUTHENTICATION_DEADLINE)
    .unwrap();
  let handle = NodeBuilder::new(storage)
    .keys(keys)
    .config(config)
    .start()
    .await
    .unwrap();
  let id = handle.local_node().await.unwrap().node_id().clone();
  let endpoint = handle
    .listeners()
    .create(Endpoint::parse("wss://127.0.0.1:0").unwrap())
    .await
    .unwrap()
    .wait()
    .await
    .unwrap()
    .endpoint()
    .clone();
  Node {
    handle,
    endpoint,
    id,
  }
}

/// Builds the harness's three-node star: one hub and two members merged
/// onto it.
async fn cluster() -> (Node, Node, Node) {
  let hub = start_node(0).await;
  let member_a = start_node(1).await;
  let member_b = start_node(2).await;
  common::merge_with_retry(&member_a.handle, &hub.handle, hub.endpoint.clone()).await;
  common::merge_with_retry(&member_b.handle, &hub.handle, hub.endpoint.clone()).await;
  (hub, member_a, member_b)
}

fn resource(seed: u32) -> (ResourceName, ResourceLabels) {
  (
    ResourceName::parse(&format!("{CATALOG_PREFIX}-{seed:05}")).unwrap(),
    ResourceLabels::new(
      radiata::LabelValue::parse("slo").unwrap(),
      ResourceUri::parse(&format!("file:///slo/{seed:05}")).unwrap(),
    ),
  )
}

fn resource_name(seed: u32) -> String {
  format!("{CATALOG_PREFIX}-{seed:05}")
}

/// Writes `count` catalog resources on `node`, starting at `first_seed`.
async fn write_catalog(node: &NodeHandle, first_seed: u32, count: u32) {
  for seed in first_seed..first_seed + count {
    let (name, labels) = resource(seed);
    common::put_resource_with_retry(node, || ResourceWrite::new(name.clone(), labels.clone()))
      .await;
  }
}

/// The node's locally visible resource names, paged through the public
/// view in canonical order.
async fn catalog(handle: &NodeHandle) -> BTreeSet<String> {
  let mut names = BTreeSet::new();
  let mut spec = PageSpec::first(PAGE_LIMIT).unwrap();
  loop {
    let page = handle.resources().list(spec).await.unwrap();
    names.extend(
      page
        .items()
        .iter()
        .map(|view| view.name().as_str().to_owned()),
    );
    let Some(cursor) = page.next() else { break };
    spec = PageSpec::after(cursor.clone(), PAGE_LIMIT).unwrap();
  }
  names
}

/// Polls the node's catalog (without nudging any cadence) until it equals
/// `expected`, returning the elapsed interval. Panics past `bound`.
async fn await_catalog_within(
  handle: &NodeHandle, expected: &BTreeSet<String>, bound: Duration, what: &str,
) -> Duration {
  let started = Instant::now();
  loop {
    let seen = catalog(handle).await;
    if seen == *expected {
      return started.elapsed();
    }
    assert!(
      started.elapsed() < bound,
      "{what}: catalog never matched ({} of {} records visible) after {:?}",
      seen.len(),
      expected.len(),
      started.elapsed()
    );
    tokio::time::sleep(POLL).await;
  }
}

/// The subject's trust status as `observer` sees it (`None` until the
/// binding converges).
async fn trust_status(observer: &NodeHandle, subject: &NodeId) -> Option<TrustStatus> {
  observer
    .trust()
    .list(PageSpec::first(PAGE_LIMIT).unwrap())
    .await
    .unwrap()
    .items()
    .iter()
    .find(|view| view.node_id() == subject)
    .map(|view| view.status())
}

/// Polls (nudging one deterministic anti-entropy round per pass) until
/// `observer` trusts `expected` bindings: the untimed setup half of both
/// strata.
async fn await_trust_count(observer: &NodeHandle, expected: usize, what: &str) {
  let deadline = Instant::now() + SETUP_TIMEOUT;
  loop {
    let page = observer
      .trust()
      .list(PageSpec::first(PAGE_LIMIT).unwrap())
      .await
      .unwrap();
    if page.items().len() == expected {
      return;
    }
    assert!(
      Instant::now() < deadline,
      "{what}: trust never reached {expected} bindings ({} visible)",
      page.items().len()
    );
    observer.sync().await.unwrap();
    tokio::time::sleep(POLL).await;
  }
}

/// The subject's trusted public key as `issuer` observes it: the exact
/// binding a revoke commits against.
async fn trusted_key(issuer: &NodeHandle, subject: &NodeId) -> radiata::PublicKey {
  let deadline = Instant::now() + SETUP_TIMEOUT;
  loop {
    let page = issuer
      .trust()
      .list(PageSpec::first(PAGE_LIMIT).unwrap())
      .await
      .unwrap();
    if let Some(view) = page.items().iter().find(|view| view.node_id() == subject) {
      return view.public_key().clone();
    }
    assert!(
      Instant::now() < deadline,
      "{subject} must become trusted before the stratum starts"
    );
    issuer.sync().await.unwrap();
    tokio::time::sleep(POLL).await;
  }
}

/// Whether the node holds a live session to `peer`.
async fn has_session(node: &NodeHandle, peer: &NodeId) -> bool {
  node
    .sessions()
    .list(PageSpec::first(PAGE_LIMIT).unwrap())
    .await
    .unwrap()
    .items()
    .iter()
    .any(|view| view.peer() == peer)
}

/// Polls (nudging one deterministic anti-entropy round per pass) until
/// the node holds no session to `peer`: the untimed setup half of the
/// reconnect stratum.
async fn await_no_session(node: &NodeHandle, peer: &NodeId) {
  let deadline = Instant::now() + SETUP_TIMEOUT;
  while has_session(node, peer).await {
    assert!(
      Instant::now() < deadline,
      "the session to {peer} never retired"
    );
    node.sync().await.unwrap();
    tokio::time::sleep(POLL).await;
  }
}

/// SLO 1: a revoke commits on the issuer and every live node observes the
/// revocation inside one quiet detection cadence plus one payload
/// admission.
#[ignore = "explicit SLO harness: cargo test --release --test slo -- --ignored --nocapture"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revocation_propagates_to_every_live_node_within_the_detection_cadence() {
  init_tracing();
  let (hub, member_a, member_b) = cluster().await;

  // Untimed setup: every node's trust view holds all three bindings, so
  // the surviving member can observe the tombstone's arrival.
  for (node, what) in [
    (&hub, "hub trust"),
    (&member_a, "surviving member trust"),
    (&member_b, "subject trust"),
  ] {
    await_trust_count(&node.handle, 3, what).await;
  }
  let subject_key = trusted_key(&hub.handle, &member_b.id).await;

  // The measured disturbance: the issuer's exact-binding revoke.
  let outcome = hub
    .handle
    .revoke(member_b.id.clone(), subject_key)
    .await
    .unwrap()
    .wait()
    .await
    .unwrap();
  assert!(!outcome.was_already_revoked(), "the revoke must be new");
  let started = Instant::now();

  // The observation poll reads local state only: no `sync()` nudge, so the
  // sample measures the production cadence, not the harness.
  let deadline = started + CONVERGENCE_BOUND;
  loop {
    let hub_revoked = trust_status(&hub.handle, &member_b.id).await == Some(TrustStatus::Revoked);
    let hub_session_gone = !has_session(&hub.handle, &member_b.id).await;
    let survivor_revoked =
      trust_status(&member_a.handle, &member_b.id).await == Some(TrustStatus::Revoked);
    if hub_revoked && hub_session_gone && survivor_revoked {
      break;
    }
    assert!(
      Instant::now() < deadline,
      "revocation never reached every live node within {CONVERGENCE_BOUND:?} \
       (hub_revoked={hub_revoked}, hub_session_gone={hub_session_gone}, \
       survivor_revoked={survivor_revoked})"
    );
    tokio::time::sleep(POLL).await;
  }
  let observed = started.elapsed();

  // The key is refused on every live node: the durable authorization
  // boundary, not just the derived view.
  for node in [&hub, &member_a] {
    let error = node
      .handle
      .connect(member_b.endpoint.clone(), member_b.id.clone())
      .await
      .unwrap()
      .wait()
      .await
      .unwrap_err();
    assert_eq!(
      error.kind(),
      ErrorKind::Revoked,
      "a dial to the revoked subject must fail closed"
    );
  }

  tracing::info!(
    observed_ms = observed.as_millis(),
    bound_ms = CONVERGENCE_BOUND.as_millis(),
    "SLO revocation_propagation: measured"
  );
  assert!(
    observed <= CONVERGENCE_BOUND,
    "revocation propagation took {observed:?}, over the {CONVERGENCE_BOUND:?} bound"
  );

  for node in [hub, member_a, member_b] {
    node.handle.shutdown().await.unwrap();
  }
}

/// SLO 2: a member that missed a bounded catalog change set catches up
/// within the bounded reconnect plus one quiet detection cadence and one
/// payload admission.
#[ignore = "explicit SLO harness: cargo test --release --test slo -- --ignored --nocapture"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reconnected_member_catches_up_within_the_detection_cadence() {
  init_tracing();
  let (hub, member_a, member_b) = cluster().await;

  // Untimed setup: the base catalog converges on every node.
  write_catalog(&hub.handle, 0, CATALOG_SIZE).await;
  let base: BTreeSet<String> = (0..CATALOG_SIZE).map(resource_name).collect();
  for (node, what) in [
    (&member_a, "surviving member base catalog"),
    (&member_b, "reconnecting member base catalog"),
  ] {
    await_catalog_within(&node.handle, &base, SETUP_TIMEOUT, what).await;
  }

  // The disturbance: the member leaves the hub's session table, the hub
  // writes the change set, and the harness confirms the member was still
  // away when the reconnect starts. A recovery dial that re-establishes
  // the session inside the change phase would make the catch-up vacuous,
  // so the phase is re-run with a fresh change set instead.
  let mut expected = base.clone();
  let mut change_seed = CATALOG_SIZE;
  let mut disturbed = false;
  for _ in 0..DISTURBANCE_ATTEMPTS {
    hub
      .handle
      .disconnect(member_b.id.clone())
      .await
      .unwrap()
      .wait()
      .await
      .unwrap();
    member_b
      .handle
      .disconnect(hub.id.clone())
      .await
      .unwrap()
      .wait()
      .await
      .unwrap();
    await_no_session(&hub.handle, &member_b.id).await;

    write_catalog(&hub.handle, change_seed, RECONNECT_CHANGE_COUNT).await;
    expected.extend((change_seed..change_seed + RECONNECT_CHANGE_COUNT).map(resource_name));
    if !has_session(&hub.handle, &member_b.id).await {
      disturbed = true;
      break;
    }
    tracing::info!(
      change_seed,
      "the member's own recovery dial re-established its session inside the change phase; \
       re-running the disturbance with a fresh change set"
    );
    change_seed += RECONNECT_CHANGE_COUNT;
  }
  assert!(
    disturbed,
    "the member's recovery plane re-established its session inside every change phase, so the \
     reconnect catch-up cannot be measured"
  );

  // The measured reconnect and catch-up.
  let started = Instant::now();
  hub
    .handle
    .connect(member_b.endpoint.clone(), member_b.id.clone())
    .await
    .unwrap()
    .wait()
    .await
    .unwrap();
  let reconnect = started.elapsed();
  let catchup = await_catalog_within(
    &member_b.handle,
    &expected,
    CONVERGENCE_BOUND,
    "reconnected member catch-up",
  )
  .await;
  let observed = started.elapsed();

  // The hub's own catalog is the reference the member converged on.
  assert_eq!(
    catalog(&hub.handle).await,
    expected,
    "the hub's catalog is the catch-up reference"
  );

  tracing::info!(
    catalog = expected.len(),
    reconnect_ms = reconnect.as_millis(),
    catchup_ms = catchup.as_millis(),
    observed_ms = observed.as_millis(),
    convergence_bound_ms = CONVERGENCE_BOUND.as_millis(),
    bound_ms = RECONNECT_CATCHUP_BOUND.as_millis(),
    "SLO reconnect_catchup: measured"
  );
  assert!(
    catchup <= CONVERGENCE_BOUND,
    "the convergence stage took {catchup:?}, over the {CONVERGENCE_BOUND:?} bound"
  );
  assert!(
    observed <= RECONNECT_CATCHUP_BOUND,
    "reconnect catch-up took {observed:?}, over the {RECONNECT_CATCHUP_BOUND:?} bound"
  );

  for node in [hub, member_a, member_b] {
    node.handle.shutdown().await.unwrap();
  }
}
