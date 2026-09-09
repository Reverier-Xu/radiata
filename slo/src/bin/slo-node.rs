//! One SLO harness node helper (`slo-node`).
//!
//! The helper mounts one production redb store and drives a single
//! radiata node purely through the public facade. It never touches
//! private modules, storage internals, or test-only features.
//!
//! Stdin protocol (no secret ever rides the environment or argv):
//! - creator: prints `credential <secret>` (initial rotation) then
//!   `ready <node-id> <endpoint>`, then answers commands until `shutdown`
//!   or EOF: `rotate`, `myrevision`, `workload ...`, `members`.
//! - member: expects `join <secret>` as the first line, prints
//!   `ready <node-id> <endpoint>`, then answers `setzone <value>` and
//!   `id` commands until `shutdown` or EOF.

use std::{
  io::{BufRead, Write},
  process::ExitCode,
  time::{Duration, Instant},
};

use radiata::{
  Endpoint, GetLocalNode, Listen, MergeCluster, NodeBuilder, NodeConfig, PageMembers,
  PageSpec, RotateMergeCredential, adapters::redb_store,
};

#[path = "../common_impl.rs"]
mod common;
#[path = "../workload.rs"]
mod workload;

/// Counts delivered workload packets (the consumer every node registers).
#[derive(Debug, Default)]
struct EchoConsumer;

impl radiata::PacketConsumer for EchoConsumer {
  fn accept<'a>(
    &'a self, mut packet: radiata::IncomingStream,
  ) -> radiata::BoxFuture<'a, radiata::Result<()>> {
    Box::pin(async move {
      let mut body = packet.body();
      while std::future::poll_fn(|cx| body.as_mut().poll_next(cx))
        .await
        .transpose()?
        .is_some()
      {}
      Ok(())
    })
  }
}

fn main() -> ExitCode {
  eprintln!(
    "slo-node starting; log={}",
    std::env::var("RADIATA_SLO_LOG").is_ok()
  );
  if std::env::var("RADIATA_SLO_LOG").is_ok() {
    tracing_subscriber::fmt()
      .with_env_filter(tracing_subscriber::EnvFilter::new("radiata=debug"))
      .with_writer(std::io::stderr)
      .init();
  }
  let runtime = match tokio::runtime::Builder::new_multi_thread()
    .worker_threads(2)
    .enable_all()
    .build()
  {
    Ok(runtime) => runtime,
    Err(error) => {
      eprintln!("slo-node runtime failed: {error}");
      return ExitCode::FAILURE;
    }
  };
  match runtime.block_on(run()) {
    Ok(()) => ExitCode::SUCCESS,
    Err(error) => {
      eprintln!("slo-node failed: {error}");
      ExitCode::FAILURE
    }
  }
}

async fn run() -> Result<(), String> {
  let role = std::env::var(common::ENV_ROLE).map_err(|_| "role unset".to_owned())?;
  let directory = std::env::var(common::ENV_DIR).map_err(|_| "dir unset".to_owned())?;
  let endpoint_text =
    std::env::var(common::ENV_ENDPOINT).map_err(|_| "endpoint unset".to_owned())?;
  let endpoint = Endpoint::parse(&endpoint_text).map_err(|error| error.to_string())?;

  std::fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
  let keys = common::keys(std::path::Path::new(&directory));
  let factory = redb_store(std::path::Path::new(&directory).join("store.redb"));

  let config = NodeConfig::new()
    .with_anti_entropy_interval(Duration::from_millis(250))
    .map_err(|error| error.to_string())?;
  let config = config.with_route_policy(
    radiata::QualifiedTag::parse(workload::NEXT_HOP_POLICY).map_err(|error| error.to_string())?,
  );
  // The workload protocol rides the core session feature with an echo
  // consumer owned by the helper; every node registers the same surface
  // so packets deliver at any member.
  let mut extensions = radiata::ExtensionRegistry::new();
  let protocol_tag = radiata::ProtocolTag::parse(workload::WORKLOAD_PROTOCOL)
    .map_err(|error| error.to_string())?;
  let feature_tag = radiata::FeatureTag::parse(workload::WORKLOAD_FEATURE)
    .map_err(|error| error.to_string())?;
  extensions
    .register_protocol(
      radiata::ProtocolDefinition::new(protocol_tag, feature_tag),
      std::sync::Arc::new(EchoConsumer),
    )
    .map_err(|error| error.to_string())?;
  let balancer_tag = radiata::QualifiedTag::parse(workload::WORKLOAD_BALANCER)
    .map_err(|error| error.to_string())?;
  extensions
    .register_load_balancer(balancer_tag, std::sync::Arc::new(workload::FirstMatch))
    .map_err(|error| error.to_string())?;
  let route_table: RouteTable = std::sync::Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::new()));
  extensions
    .register_next_hop(
      radiata::QualifiedTag::parse(workload::NEXT_HOP_POLICY).map_err(|error| error.to_string())?,
      std::sync::Arc::new(SloNextHopPolicy {
        table: std::sync::Arc::clone(&route_table),
      }),
    )
    .map_err(|error| error.to_string())?;
  let handle = NodeBuilder::new(factory, keys)
    .config(config)
    .extensions(extensions)
    .start()
    .await
    .map_err(|error| error.to_string())?;

  let mut stdin = std::io::stdin().lock();
  let mut stdout = std::io::stdout().lock();

  match role.as_str() {
    "creator" => {
      creator(handle, endpoint, &mut stdin, &mut stdout, route_table)
        .await
    }
    "member" => {
      member(handle, endpoint, &mut stdin, &mut stdout, route_table)
        .await
    }
    other => Err(format!("unknown role {other}")),
  }
}

/// The harness-distributed routing table: destination node id text to
/// next-hop node id text over the frozen sparse topology.
type RouteTable = std::sync::Arc<
  std::sync::Mutex<std::collections::BTreeMap<String, String>>,
>;

/// The topology-aware next-hop policy: one frozen first-hop row per node,
/// distributed by the controller over the helpers' stdin protocol.
/// Unknown destinations fail closed with the provider-visible
/// unsupported error.
#[derive(Debug)]
struct SloNextHopPolicy {
  table: RouteTable,
}

impl radiata::RouteNextHop for SloNextHopPolicy {
  fn next_hop<'a>(
    &'a self, view: radiata::NextHopView<'a>,
  ) -> radiata::BoxFuture<'a, radiata::Result<radiata::NodeId>> {
    Box::pin(async move {
      let next = self
        .table
        .lock()
        .unwrap()
        .get(view.destination().as_str())
        .cloned()
        .ok_or_else(|| {
          radiata::Error::provider(
            radiata::ProviderErrorKind::Unsupported,
            radiata::ProviderErrorContext::RoutingPolicy,
          )
        })?;
      radiata::NodeId::parse(&next)
    })
  }
}

/// Handles one `route <destination> <next-hop>` table row.
fn handle_route(table: &RouteTable, parts: impl Iterator<Item = String>) -> &'static str {
  let mut fields = parts;
  let (Some(destination), Some(next_hop)) = (fields.next(), fields.next()) else {
    return "error route row needs destination and next hop";
  };
  if radiata::NodeId::parse(&destination).is_err() || radiata::NodeId::parse(&next_hop).is_err() {
    return "error route row ids are invalid";
  }
  table
    .lock()
    .unwrap()
    .insert(destination, next_hop);
  "route ok"
}

async fn creator(
  handle: radiata::NodeHandle, endpoint: Endpoint, stdin: &mut std::io::StdinLock<'static>,
  stdout: &mut std::io::StdoutLock<'static>, table: RouteTable,
) -> Result<(), String> {
  // Born-with-cluster: no genesis step. The initial credential
  // rotates BEFORE the listener starts, so the accept loop's first computed
  // hint already carries an active generation (a hint computed before any
  // credential exists refuses every early merger).
  let issued = handle
    .command(RotateMergeCredential::new())
    .await
    .map_err(|error| error.to_string())?;
  let listener = handle
    .command(Listen::new(endpoint))
    .await
    .map_err(|error| error.to_string())?;
  let local = handle
    .query(GetLocalNode::new())
    .await
    .map_err(|error| error.to_string())?;
  println!("credential {}", issued.credential().expose_secret());
  println!("ready {} {}", local.node_id(), listener.endpoint().as_str());
  stdout.flush().map_err(|error| error.to_string())?;

  #[allow(unused_mut)]
  let mut line = String::new();
  loop {
    line.clear();
    match stdin.read_line(&mut line) {
      Ok(0) => {
        eprintln!("slo-node: creator stdin closed; exiting");
        break;
      }
      Ok(_) => {
        let command = line.trim().to_owned();
        let mut parts = command.split_whitespace();
        match parts.next().unwrap_or("") {
          "shutdown" => {
            eprintln!("slo-node: creator received shutdown");
            break;
          }
          "rotate" => {
            let issued = handle
              .command(RotateMergeCredential::new())
              .await
              .map_err(|error| error.to_string())?;
            println!("credential {}", issued.credential().expose_secret());
          }
          "myrevision" => {
            let local = handle
              .query(GetLocalNode::new())
              .await
              .map_err(|error| error.to_string())?;
            let page = handle
              .query(PageMembers::new(PageSpec::first(64).unwrap()))
              .await
              .map_err(|error| error.to_string())?;
            let revision = page
              .items()
              .iter()
              .find(|view| view.node_id() == local.node_id())
              .map(|view| view.owner_revision())
              .unwrap_or(0);
            println!("revision {revision}");
          }
          "members" => {
            let page = handle
              .query(PageMembers::new(PageSpec::first(64).unwrap()))
              .await
              .map_err(|error| error.to_string())?;
            let ids = page
              .items()
              .iter()
              .map(|view| view.node_id().as_str())
              .collect::<Vec<_>>()
              .join(",");
            println!("members {ids}");
          }
          "zones" => {
            let page = handle
              .query(PageMembers::new(PageSpec::first(64).unwrap()))
              .await
              .map_err(|error| error.to_string())?;
            let zone_key = radiata::LabelKey::parse("example.org/labels/zone")
              .map_err(|error| error.to_string())?;
            let count = page
              .items()
              .iter()
              .filter(|view| {
                view.labels().get(&zone_key).is_some()
              })
              .count();
            println!("zones {count}");
          }
          "disconnect" => {
            // Drop one member session: the harness prunes the star merge
            // sessions down to the sparse final topology.
            // Intentionally disconnected peers are never re-dialled by
            // recovery until a deliberate reconnect.
            let Some(id_text) = parts.next() else {
              println!("error missing node id");
              continue;
            };
            let target = match radiata::NodeId::parse(id_text) {
              Ok(node_id) => radiata::DisconnectPeer::new(node_id),
              Err(_) => {
                println!("error invalid node id");
                continue;
              }
            };
            match handle.command(target).await {
              Ok(_) => println!("disconnect ok"),
              Err(error) => println!("disconnect error {error}"),
            }
          }
          "route" => {
            let fields = parts.map(str::to_owned);
            println!("{}", handle_route(&table, fields));
          }
          "workload" => {
            let reply = run_workload_command(&handle, parts).await;
            println!("{reply}");
          }
          _ => println!("error unknown command"),
        }
        stdout.flush().map_err(|error| error.to_string())?;
      }
      Err(error) => return Err(error.to_string()),
    }
  }
  handle
    .command(radiata::Shutdown::new())
    .await
    .map_err(|error| error.to_string())?;
  Ok(())
}

async fn member(
  handle: radiata::NodeHandle, endpoint: Endpoint, stdin: &mut std::io::StdinLock<'static>,
  stdout: &mut std::io::StdoutLock<'static>, table: RouteTable,
) -> Result<(), String> {
  // The first line carries the single-use credential; the member listens
  // before it joins so the accept loop holds its precomputed join hint.
  let listener = handle
    .command(Listen::new(endpoint))
    .await
    .map_err(|error| error.to_string())?;
  let listen_endpoint = listener.endpoint().clone();
  let mut line = String::new();
  stdin
    .read_line(&mut line)
    .map_err(|error| error.to_string())?;
  let mut parts = line.split_whitespace();
  if parts.next().unwrap_or("") != "join" {
    return Err("expected join line".to_owned());
  }
  let secret = parts.next().ok_or("expected credential".to_owned())?;
  let issuer_text = std::env::var(common::ENV_ISSUER).map_err(|_| "issuer unset".to_owned())?;
  let issuer = Endpoint::parse(&issuer_text).map_err(|error| error.to_string())?;
  let credential = radiata::MergeCredential::parse(secret).map_err(|error| error.to_string())?;
  let joined = tokio::time::timeout(
    Duration::from_secs(30),
    handle.command(MergeCluster::new(issuer, credential)),
  )
  .await;
  match joined {
    Ok(Ok(_)) => {}
    Ok(Err(error)) => return Err(format!("join failed: {error}")),
    Err(_) => return Err("join timed out after 30s".to_owned()),
  }
  let local = handle
    .query(GetLocalNode::new())
    .await
    .map_err(|error| error.to_string())?;
  let node_id = local.node_id().clone();
  let _page = handle
    .query(PageMembers::new(PageSpec::first(64).unwrap()))
    .await
    .map_err(|error| error.to_string())?;
  println!("ready {node_id} {}", listen_endpoint.as_str());
  stdout.flush().map_err(|error| error.to_string())?;

  loop {
    line.clear();
    match stdin.read_line(&mut line) {
      Ok(0) => break,
      Ok(_) => {
        let command = line.trim().to_owned();
        let mut parts = command.split_whitespace();
        match parts.next().unwrap_or("") {
          "shutdown" => break,
          "id" => println!("id {node_id}"),
          "revision" => {
            let reply = own_revision(&handle, &node_id).await;
            println!("{reply}");
          }
          "haszone" => {
            let Some(value) = parts.next() else {
              println!("error missing zone value");
              continue;
            };
            let reply = any_zone_is(&handle, value).await;
            println!("{reply}");
          }
          "has" => {
            let Some(name_text) = parts.next() else {
              println!("error missing resource name");
              continue;
            };
            let reply = has_resource(&handle, name_text).await;
            println!("{reply}");
          }
          "setzone" => {
            let value = parts.next().unwrap_or("edge").to_owned();
            let reply = set_own_zone(&handle, &node_id, &value).await;
            println!("{reply}");
          }
          "connect" => {
            // Dial a fellow cluster member: credential-free after the
            // pairwise merge, used by the harness to build the sparse
            // final topology.
            let Some(endpoint_text) = parts.next() else {
              println!("error missing endpoint");
              continue;
            };
            let Some(id_text) = parts.next() else {
              println!("error missing node id");
              continue;
            };
            let target = match (radiata::Endpoint::parse(endpoint_text), radiata::NodeId::parse(id_text)) {
              (Ok(endpoint), Ok(node_id)) => radiata::ConnectMember::new(endpoint, node_id),
              _ => {
                println!("error invalid connect target");
                continue;
              }
            };
            match handle.command(target).await {
              Ok(_) => println!("connect ok"),
              Err(error) => println!("connect error {error}"),
            }
          }
          "route" => {
            let fields = parts.map(str::to_owned);
            println!("{}", handle_route(&table, fields));
          }
          _ => println!("error unknown command"),
        }
        stdout.flush().map_err(|error| error.to_string())?;
      }
      Err(error) => return Err(error.to_string()),
    }
  }
  handle
    .command(radiata::Shutdown::new())
    .await
    .map_err(|error| error.to_string())?;
  Ok(())
}

/// Whether the member's own public view exposes the exact zone label.
async fn any_zone_is(handle: &radiata::NodeHandle, value: &str) -> String {
  match handle
    .query(PageMembers::new(PageSpec::first(64).unwrap()))
    .await
  {
    Ok(page) => {
      let zone_key = radiata::LabelKey::parse("example.org/labels/zone");
      let observed = page.items().iter().any(|view| {
        zone_key
          .as_ref()
          .ok()
          .and_then(|key| view.labels().get(key))
          .is_some_and(|label| label.as_str() == value)
      });
      if observed {
        "haszone yes".to_owned()
      } else {
        "haszone no".to_owned()
      }
    }
    Err(_) => "error member page".to_owned(),
  }
}

/// The member's own owner revision through the public member page.
async fn own_revision(handle: &radiata::NodeHandle, node_id: &radiata::NodeId) -> String {
  match handle
    .query(PageMembers::new(PageSpec::first(64).unwrap()))
    .await
  {
    Ok(page) => format!(
      "revision {}",
      page
        .items()
        .iter()
        .find(|view| view.node_id() == node_id)
        .map(|view| view.owner_revision())
        .unwrap_or(0)
    ),
    Err(_) => "error member page".to_owned(),
  }
}

/// Whether the exact named resource is observable through the public
/// resource query.
async fn has_resource(handle: &radiata::NodeHandle, name_text: &str) -> String {
  let name = match radiata::ResourceName::parse(name_text) {
    Ok(name) => name,
    Err(_) => return "error bad name".to_owned(),
  };
  match handle.query(radiata::GetResource::new(name)).await {
    Ok(Some(_)) => "has yes".to_owned(),
    Ok(None) => "has no".to_owned(),
    Err(_) => "error resource query".to_owned(),
  }
}

/// Sets the member's own zone capability label: the owner revision is
/// observed through the public member page (the descriptor ensure may
/// legitimately bump revisions concurrently).
async fn set_own_zone(
  handle: &radiata::NodeHandle, node_id: &radiata::NodeId, value: &str,
) -> String {
  let deadline = Instant::now() + Duration::from_secs(30);
  let mut attempts = 0_u32;
  loop {
    attempts += 1;
    let revision = match handle
      .query(PageMembers::new(PageSpec::first(64).unwrap()))
      .await
    {
      Ok(page) => page
        .items()
        .iter()
        .find(|view| view.node_id() == node_id)
        .map(|view| view.owner_revision())
        .unwrap_or(1),
      Err(_) => return "error member page".to_owned(),
    };
    let patch = (|| {
      let key = radiata::LabelKey::parse("example.org/labels/zone")?;
      let value = radiata::LabelValue::parse(value)?;
      radiata::NodeMetadataPatch::new().set_capability(key, value)
    })();
    let patch = match patch {
      Ok(patch) => patch,
      Err(error) => return format!("error {error}"),
    };
    match handle
      .command(radiata::UpdateNodeMetadata::new(revision, patch))
      .await
    {
      Ok(_) => return "zone ok".to_owned(),
      Err(error) if error.kind() == radiata::ErrorKind::Conflict => {
        // A concurrent descriptor ensure may have bumped the revision;
        // re-observe and retry within the bound.
        if Instant::now() > deadline || attempts > 20 {
          return format!("error {error}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
      }
      Err(error) => return format!("error {error}"),
    }
  }
}

/// Executes one workload command and returns the reply line.
async fn run_workload_command(
  handle: &radiata::NodeHandle, mut parts: std::str::SplitWhitespace<'_>,
) -> String {
  let Some(kind) = parts.next() else {
    return "error missing workload kind".to_owned();
  };
  let sample = match kind {
    "direct" => {
      let Some(target) = parts
        .next()
        .and_then(|value| radiata::NodeId::parse(value).ok())
      else {
        return "error bad target".to_owned();
      };
      workload::sample_direct_packet(handle, &target).await
    }
    "routed" => workload::sample_routed_packet(handle).await,
    "node-meta" => {
      let Some(revision) = parts.next().and_then(|value| value.parse::<u64>().ok()) else {
        return "error bad revision".to_owned();
      };
      let value = parts.next().unwrap_or("edge").to_owned();
      workload::sample_node_metadata(handle, revision, &value).await
    }
    "resource" => {
      let Some(seed) = parts.next().and_then(|value| value.parse::<u32>().ok()) else {
        return "error bad seed".to_owned();
      };
      workload::sample_resource_metadata(handle, seed).await
    }
    other => return format!("error unknown workload kind {other}"),
  };
  if !sample.passes() {
    eprintln!("workload sample failed: {} {}", sample.stratum, sample.outcome);
  }
  let _ = sample.passes();
  sample.ledger_line()
}
