#![allow(dead_code)]
//! The exact ADR-0005 workload (T-G10-11, SC-G10-P0-34..37): five runs of
//! five samples per stratum — fixed admission, direct packets, routed
//! label-selected packets, owner-revision node metadata, and resource
//! metadata writes — observed only through the public facade.
//!
//! The helper executes one sample per command and reports the raw start
//! and end host wall-clock observations. Nothing is excluded, replaced,
//! or reclassified after start: the controller records every result.

use std::{
  sync::Arc,
  time::{Duration, Instant, SystemTime},
};

use radiata::{
  BoxFuture, Endpoint, LabelKey, LabelValue, LoadBalancingPolicy, NodeHandle, NodeId,
  NodeMetadataPatch, PageMembers, PageSpec, ProtocolTag, PutResource, ResourceLabels,
  ResourceName, ResourceUri, ResourceWrite, RoutingPolicy, Selector, StreamMetadata, StreamPolicy,
  StreamTarget, UpdateNodeMetadata,
};

/// The protocol tag the workload packets ride (registered on every node).
pub const WORKLOAD_PROTOCOL: &str = "radiata.woooo.tech/protocols/workload-echo";
/// The owning feature of the workload protocol.
pub const WORKLOAD_FEATURE: &str = "radiata.woooo.tech/features/session-core";
/// The load-balancer tag used by the routed stratum.
pub const WORKLOAD_BALANCER: &str = "example.org/balancers/first-match";
/// The member label the routed stratum selects on.
pub const WORKLOAD_SELECTOR: &str = "example.org/labels/zone=edge";
/// The SLO sample deadline (the decision-register constant).
pub const SAMPLE_DEADLINE_MS: u128 = 10_000;

/// A completed raw sample.
#[derive(Clone, Debug)]
pub struct RawSample {
  pub run: u32,
  pub index: u32,
  pub stratum: &'static str,
  pub started_at_ms: u128,
  pub ended_at_ms: u128,
  pub outcome: String,
}

impl RawSample {
  /// The exact pass rule: the predicate was observed and the raw latency
  /// is within the deadline.
  #[must_use]
  pub fn passes(&self) -> bool {
    self.outcome == "ok"
      && self.ended_at_ms >= self.started_at_ms
      && self.ended_at_ms - self.started_at_ms <= SAMPLE_DEADLINE_MS
  }

  /// The raw ledger line (canonical JSON, no secret values).
  #[must_use]
  pub fn ledger_line(&self) -> String {
    format!(
      "{{\"schema\":\"radiata.woooo.tech/schemas/slo-ledger-v1\",\"sample_id\":\"run-{}/sample-{}\",\"stratum\":\"{}\",\"started_at_ms\":{},\"ended_at_ms\":{},\"outcome\":\"{}\"}}",
      self.run, self.index, self.stratum, self.started_at_ms, self.ended_at_ms, self.outcome
    )
  }
}

fn now_ms() -> u128 {
  SystemTime::now()
    .duration_since(SystemTime::UNIX_EPOCH)
    .map(|value| value.as_millis())
    .unwrap_or(0)
}

fn finish(mut sample: RawSample, result: Result<(), radiata::Error>) -> RawSample {
  if let Err(error) = result {
    sample.outcome = format!("failed: {:?} {}", error.kind(), error.context());
  }
  sample.ended_at_ms = now_ms();
  sample
}

/// A minimal opaque stream body: the bounded 4,096-byte benchmark payload
/// (a benchmark value, not an API maximum).
fn workload_body() -> impl futures_core::Stream<Item = radiata::Result<Arc<[u8]>>> + Send + 'static
{
  futures_util::stream::once(async move { Ok(Arc::from(vec![0_u8; 4096]) as Arc<[u8]>) })
}

/// Selects the first matching candidate in canonical order.
#[derive(Debug)]
pub struct FirstMatch;

impl LoadBalancingPolicy for FirstMatch {
  fn select<'a>(
    &'a self, selector: &'a Selector, candidates: &'a dyn radiata::CandidateNodeReader,
  ) -> BoxFuture<'a, radiata::Result<NodeId>> {
    Box::pin(async move {
      let page = candidates.next_matching_nodes(selector, None, 1).await?;
      page
        .items()
        .first()
        .map(|member| member.node_id().clone())
        .ok_or_else(|| {
          radiata::Error::provider(
            radiata::ProviderErrorKind::Unsupported,
            radiata::ProviderErrorContext::LoadBalancingPolicy,
          )
        })
    })
  }
}

/// Executes one direct-packet sample: send one 4,096-byte stream to the
/// exact node and wait for the current-process delivery acknowledgement.
pub async fn sample_direct_packet(handle: &NodeHandle, target: &NodeId) -> RawSample {
  let sample = RawSample {
    run: 0,
    index: 0,
    stratum: "direct-packet",
    started_at_ms: now_ms(),
    ended_at_ms: 0,
    outcome: "ok".to_owned(),
  };
  let result = async {
    let packet = handle.open_stream(
      StreamTarget::Exact(target.clone()),
      ProtocolTag::parse(WORKLOAD_PROTOCOL)?,
      StreamPolicy::new(RoutingPolicy::Direct, 1)?,
      StreamMetadata::new(),
    )?;
    packet.send_sync(workload_body()).await?;
    Ok(())
  }
  .await;
  finish(sample, result)
}

/// Executes one routed-packet sample: label selection and the frozen
/// load-balancing policy select the destination.
pub async fn sample_routed_packet(handle: &NodeHandle) -> RawSample {
  let sample = RawSample {
    run: 0,
    index: 0,
    stratum: "routed-packet",
    started_at_ms: now_ms(),
    ended_at_ms: 0,
    outcome: "ok".to_owned(),
  };
  let result = async {
    let selector = Selector::parse(WORKLOAD_SELECTOR)?;
    let packet = handle.open_stream(
      StreamTarget::MatchingNodes(selector),
      ProtocolTag::parse(WORKLOAD_PROTOCOL)?,
      StreamPolicy::new(RoutingPolicy::Direct, 3)?
        .load_balancer(radiata::QualifiedTag::parse(WORKLOAD_BALANCER)?),
      StreamMetadata::new(),
    )?;
    packet.send_sync(workload_body()).await?;
    Ok(())
  }
  .await;
  finish(sample, result)
}

/// Executes one node-metadata sample: one owner-revision capability
/// revision observed at the exact new revision.
pub async fn sample_node_metadata(
  handle: &NodeHandle, requested_revision: u64, zone_value: &str,
) -> RawSample {
  let sample = RawSample {
    run: 0,
    index: 0,
    stratum: "node-metadata",
    started_at_ms: now_ms(),
    ended_at_ms: 0,
    outcome: "ok".to_owned(),
  };
  let result = async {
    // The caller passes 0 to mean "my current revision": the exact
    // expected revision is observed through the public member page. A
    // concurrent descriptor ensure can bump the revision between the
    // observation and the command, so the conflict re-observes and
    // retries within a bound.
    let key = LabelKey::parse("example.org/labels/zone")?;
    let value = LabelValue::parse(zone_value)?;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
      let revision = if requested_revision == 0 {
        let local = handle.query(radiata::GetLocalNode::new()).await?;
        let page = handle
          .query(PageMembers::new(PageSpec::first(64).unwrap()))
          .await?;
        page
          .items()
          .iter()
          .find(|view| view.node_id() == local.node_id())
          .map(|view| view.owner_revision())
          .unwrap_or(1)
      } else {
        requested_revision
      };
      let patch = NodeMetadataPatch::new().set_capability(key.clone(), value.clone())?;
      match handle.command(UpdateNodeMetadata::new(revision, patch)).await {
        Ok(updated) => {
          let _ = updated.owner_revision();
          return Ok(());
        }
        Err(error) if error.kind() == radiata::ErrorKind::Conflict => {
          if Instant::now() > deadline {
            return Err(error);
          }
          tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Err(error) => return Err(error),
      }
    }
  }
  .await;
  finish(sample, result)
}

/// Executes one resource-metadata sample: one named resource candidate
/// with reserved type and URI labels plus one custom label. The URI is
/// never dereferenced.
pub async fn sample_resource_metadata(handle: &NodeHandle, name_seed: u32) -> RawSample {
  let sample = RawSample {
    run: 0,
    index: 0,
    stratum: "resource-metadata",
    started_at_ms: now_ms(),
    ended_at_ms: 0,
    outcome: "ok".to_owned(),
  };
  let result = async {
    let labels = ResourceLabels::new(
      LabelValue::parse("workload")?,
      ResourceUri::parse("file:///workload")?,
    )
    .custom(
      LabelKey::parse("example.org/labels/zone")?,
      LabelValue::parse("workload")?,
    )?;
    let write = PutResource::new(ResourceWrite::new(
      ResourceName::parse(&format!(
        "radiata.woooo.tech/resources/workload-{name_seed:03}"
      ))?,
      labels,
    ))?;
    let mutation = handle.command(write).await?;
    let _ = mutation.is_current_winner();
    Ok(())
  }
  .await;
  finish(sample, result)
}

/// Polls the public member page until `predicate` holds, bounded.
pub async fn wait_for_predicate(
  handle: &NodeHandle, deadline: Duration,
  mut predicate: impl FnMut(&[radiata::MemberView]) -> bool,
) -> Result<(), radiata::Error> {
  let started = Instant::now();
  loop {
    let members = handle
      .query(PageMembers::new(PageSpec::first(64).unwrap()))
      .await?;
    if predicate(members.items()) {
      return Ok(());
    }
    if started.elapsed() > deadline {
      return Err(radiata::Error::provider(
        radiata::ProviderErrorKind::Unsupported,
        radiata::ProviderErrorContext::NeighborPolicy,
      ));
    }
    tokio::time::sleep(Duration::from_millis(25)).await;
  }
}

/// Executes one admission sample against a pre-started fresh member
/// helper: rotate one single-use credential, complete the authenticated
/// join, and observe the new member through public pages.
pub async fn sample_admission(
  issuer: &NodeHandle, member: &NodeHandle, endpoint: &Endpoint,
) -> RawSample {
  let sample = RawSample {
    run: 0,
    index: 0,
    stratum: "admission",
    started_at_ms: now_ms(),
    ended_at_ms: 0,
    outcome: "ok".to_owned(),
  };
  let result = async {
    let issued = issuer.command(radiata::RotateMergeCredential::new()).await?;
    let secret = issued.credential().expose_secret().to_owned();
    member
      .command(radiata::MergeCluster::new(
        endpoint.clone(),
        radiata::MergeCredential::parse(&secret)?,
      ))
      .await?;
    let expected = member.query(radiata::GetLocalNode::new()).await?;
    wait_for_predicate(issuer, Duration::from_secs(30), |members| {
      members
        .iter()
        .any(|view| view.node_id() == expected.node_id())
    })
    .await
  }
  .await;
  finish(sample, result)
}
