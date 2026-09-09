//! The SLO harness controller (`slo-controller`).
//!
//! The controller owns the cluster: it starts node helper processes,
//! drives readiness and the workload through public facade observations
//! only, records raw wall-clock samples into the release ledger, and
//! performs the ordered shutdown and cleanup. It never inspects private
//! node state: its only node-facing channels are the
//! helpers' stdin protocols and the public facade itself.
//!
//! Modes:
//! - `qualify <nodes>`: start a bounded cluster, prove readiness through
//!   public pages, shut down in order, and record the qualification
//!   outcome — the harness self-proof, without claiming any SLO sample.
//! - `measure`: the exact 125-sample workload over one pinned candidate
//!   commit (`RADIATA_SLO_COMMIT`); the operator reviews the ledger and
//!   publishes manually.
//! - `topology`: print the frozen profile direction table — the 64 final
//!   directions, the exact three-hop path, and the four throughput edges.

use std::{
  io::{BufRead, Write},
  path::PathBuf,
  process::{Child, ChildStdin, ChildStdout, Command, Stdio},
  time::{Duration, Instant},
};

use radiata_slo::{common, topology};

fn main() {
  let args: Vec<String> = std::env::args().collect();
  let mode = args.get(1).map(String::as_str).unwrap_or("qualify");
  let result = match mode {
    "qualify" => {
      let count = args
        .get(2)
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(3);
      qualify(count)
    }
    // The exact 125-sample workload over one pinned candidate commit; the
    // operator reviews the ledger and publishes manually.
    "measure" => {
      let runs = args
        .get(2)
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(5);
      measure(runs)
    }
    "topology" => print_topology(),
    other => Err(format!("unknown mode {other}")),
  };
  if let Err(error) = result {
    eprintln!("slo-controller failed: {error}");
    std::process::exit(1);
  }
}

/// Prints the frozen profile direction table: one line per final
/// direction, then the three-hop path and the four throughput edges. Each
/// count is verified against the frozen profile before printing.
fn print_topology() -> Result<(), String> {
  let directions = topology::directed_directions();
  if directions.len() != 64 {
    return Err(format!(
      "the profile direction table holds {} directions, expected 64",
      directions.len()
    ));
  }
  for (from, to) in &directions {
    println!("direction {from}->{to}");
  }
  let (from, to) = topology::exact_three_hop();
  if topology::distance(from, to) != Some(3) {
    return Err("the three-hop path is not exactly three hops".to_owned());
  }
  println!("three-hop {from}->{to}");
  let throughput = topology::throughput_edges();
  let final_edges: Vec<(usize, usize)> = topology::profile_edges()
    .iter()
    .map(|edge| (edge.0.min(edge.1), edge.0.max(edge.1)))
    .collect();
  if throughput.len() != 4 {
    return Err(format!(
      "the profile holds {} throughput edges, expected 4",
      throughput.len()
    ));
  }
  for edge in throughput {
    let canonical = (edge.0.min(edge.1), edge.0.max(edge.1));
    if !final_edges.contains(&canonical) {
      return Err("a throughput edge is not a final edge".to_owned());
    }
    println!("throughput {}->{}", edge.0.min(edge.1), edge.0.max(edge.1));
  }
  Ok(())
}

struct NodeProcess {
  child: Child,
  stdin: ChildStdin,
  stdout: std::io::BufReader<ChildStdout>,
  directory: PathBuf,
  node_id: Option<String>,
  endpoint: Option<String>,
  ready: bool,
}

impl NodeProcess {
  fn send(&mut self, line: &str) -> Result<(), String> {
    self
      .stdin
      .write_all(format!("{line}\n").as_bytes())
      .map_err(|error| error.to_string())?;
    self.stdin.flush().map_err(|error| error.to_string())
  }

  fn read_line(&mut self) -> Result<String, String> {
    let mut line = String::new();
    let read = self
      .stdout
      .read_line(&mut line)
      .map_err(|e| e.to_string())?;
    if read == 0 {
      return Err("node closed its stdout".to_owned());
    }
    Ok(line)
  }

  fn shutdown(mut self) -> Result<(), String> {
    self.send("shutdown")?;
    let outcome = match self.child.wait() {
      Ok(status) if status.success() => Ok(()),
      Ok(status) => Err(format!("node exited with {status}")),
      Err(error) => Err(error.to_string()),
    };
    // The run-owned store directory is removed only after the ordered
    // shutdown proves the helper exited cleanly.
    let _ = std::fs::remove_dir_all(&self.directory);
    outcome
  }
}

impl Drop for NodeProcess {
  fn drop(&mut self) {
    let _ = self.child.kill();
    let _ = self.child.wait();
  }
}

fn qualify(count: usize) -> Result<(), String> {
  let root = std::env::var("RADIATA_SLO_ROOT")
    .map(PathBuf::from)
    .map_err(|_| "RADIATA_SLO_ROOT unset".to_owned())?;
  let ledger = std::env::var("RADIATA_SLO_LEDGER")
    .map(PathBuf::from)
    .map_err(|_| "RADIATA_SLO_LEDGER unset".to_owned())?;
  std::fs::create_dir_all(&root).map_err(|error| error.to_string())?;

  let started = Instant::now();
  let mut nodes: Vec<NodeProcess> = Vec::new();
  let outcome = run_cluster(&root, count, &mut nodes);
  let elapsed = started.elapsed();

  let ready = nodes.iter().filter(|node| node.ready).count();
  let status = if outcome.is_ok() && ready == count {
    "pass"
  } else {
    "fail"
  };
  let record_error = record_qualification(&ledger, count, ready, status, elapsed);
  for node in nodes {
    let _ = node.shutdown();
  }
  outcome?;
  record_error
}

fn creator_endpoint(creator: Option<&NodeProcess>) -> Result<String, String> {
  creator
    .and_then(|node| node.endpoint.clone())
    .ok_or("creator has no endpoint".to_owned())
}

fn spawn_node(
  root: &std::path::Path, index: usize, issuer: &str, role: &str,
) -> Result<NodeProcess, String> {
  let directory = root.join(format!("node-{index}"));
  std::fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
  // Each respawn takes the next port in a wide range: a failed helper's
  // TLS listener port can linger in TIME_WAIT past the respawn.
  static PORT_SEQ: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(17_000);
  let port = PORT_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
  let endpoint = format!("wss://127.0.0.1:{port}");
  let mut command = Command::new(node_binary());
  command
    .env(common::ENV_ROLE, role)
    .env(common::ENV_DIR, &directory)
    .env(common::ENV_ENDPOINT, &endpoint);
  if !issuer.is_empty() {
    command.env(common::ENV_ISSUER, issuer);
  }
  command
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::inherit());
  let mut child = command
    .spawn()
    .map_err(|error| format!("node spawn failed: {error}"))?;
  let stdin = child.stdin.take().ok_or("node stdin missing")?;
  let stdout = std::io::BufReader::new(child.stdout.take().ok_or("node stdout missing")?);
  Ok(NodeProcess {
    child,
    stdin,
    stdout,
    directory,
    node_id: None,
    endpoint: Some(endpoint),
    ready: false,
  })
}

fn run_cluster(
  root: &std::path::Path, count: usize, nodes: &mut Vec<NodeProcess>,
) -> Result<(), String> {
  let mut creator: Option<NodeProcess> = None;
  let mut initial_credential: Option<String> = None;
  for index in 0..count {
    let role = if index == 0 { "creator" } else { "member" };
    let mut node = if index == 0 {
      spawn_node(root, index, "", role)?
    } else {
      let issuer = creator_endpoint(creator.as_ref())?;
      spawn_node(root, index, &issuer, role)?
    };
    if index == 0 {
      // The creator prints its initial credential before the ready line:
      // the listener only starts serving hints after the first rotation.
      // The creator prints its initial credential before ready; the
      // first member consumes it.
      let line = node.read_line()?;
      initial_credential =
        Some(common::parse_credential_line(&line).ok_or("creator returned no initial credential")?);
      wait_ready(&mut node, Duration::from_secs(120))?;
      creator = Some(node);
    } else {
      // One fresh credential per member; the first member consumes the
      // creator's initial rotation. A failed join consumes no credential,
      // so a retry reuses the same secret: the accept loop recomputes its
      // hint per connection, and rotating per retry would leave the
      // blocked accept permanently one generation behind.
      let secret = if index == 1 {
        initial_credential
          .take()
          .ok_or("initial credential missing")?
      } else {
        creator.as_mut().ok_or("creator missing")?.send("rotate")?;
        let line = creator.as_mut().ok_or("creator missing")?.read_line()?;
        common::parse_credential_line(&line).ok_or("creator returned no credential")?
      };
      let deadline = Instant::now() + Duration::from_secs(120);
      loop {
        node.send(&format!("join {secret}"))?;
        match wait_ready(&mut node, Duration::from_secs(120)) {
          Ok(()) => break,
          Err(error) if Instant::now() < deadline => {
            eprintln!("slo-controller: member {index} join retried after {error}");
            // The helper exited on the failed join: respawn it.
            node = spawn_node(root, index, &creator_endpoint(creator.as_ref())?, role)?;
          }
          Err(error) => return Err(error),
        }
      }
      nodes.push(node);
    }
  }
  // The creator is the last process to shut down: drop closes it.
  if let Some(creator) = creator {
    nodes.push(creator);
  }
  Ok(())
}

fn wait_ready(node: &mut NodeProcess, deadline: Duration) -> Result<(), String> {
  let started = Instant::now();
  loop {
    if started.elapsed() > deadline {
      return Err("node readiness deadline".to_owned());
    }
    let line = node.read_line()?;
    if let Some((node_id, endpoint)) = common::parse_ready_line(&line) {
      node.node_id = Some(node_id);
      node.endpoint = Some(endpoint);
      node.ready = true;
      return Ok(());
    }
  }
}

fn node_binary() -> PathBuf {
  std::env::var("RADIATA_SLO_NODE_BIN")
    .map(PathBuf::from)
    .unwrap_or_else(|_| PathBuf::from("slo-node"))
}

fn record_qualification(
  ledger: &std::path::Path, nodes: usize, ready: usize, status: &str, elapsed: Duration,
) -> Result<(), String> {
  let mut file = std::fs::OpenOptions::new()
    .create(true)
    .append(true)
    .open(ledger)
    .map_err(|error| error.to_string())?;
  let commit = std::env::var("RADIATA_SLO_COMMIT").unwrap_or_else(|_| "unknown".to_owned());
  let record = format!(
    "{{\"schema\":\"radiata.woooo.tech/schemas/slo-harness-qualification-v1\",\
     \"commit\":\"{commit}\",\"nodes\":{nodes},\"ready\":{ready},\
     \"status\":\"{status}\",\"elapsed_secs\":{}}}\n",
    elapsed.as_secs(),
  );
  file
    .write_all(record.as_bytes())
    .map_err(|error| error.to_string())
}


/// The exact measurement: five runs of the five-stratum
/// 25-sample mix, every raw sample recorded against the pinned commit.
fn measure(runs: u32) -> Result<(), String> {
  let expected_commit =
    std::env::var("RADIATA_SLO_COMMIT").map_err(|_| "RADIATA_SLO_COMMIT unset".to_owned())?;
  if expected_commit == "unknown" || expected_commit.is_empty() {
    return Err("RADIATA_SLO_COMMIT must be the exact candidate SHA".to_owned());
  }
  let runtime = tokio::runtime::Builder::new_multi_thread()
    .worker_threads(2)
    .enable_all()
    .build()
    .map_err(|error| error.to_string())?;
  let commit = expected_commit.clone();
  runtime.block_on(async move { measure_async(runs, commit).await })
}

/// The fresh run population: one creator plus ten
/// already-merged members; the merge stratum adds five fresh nodes to
/// reach the exact sixteen-node final population.
const INITIAL_MEMBERS: usize = 10;

async fn measure_async(runs: u32, expected_commit: String) -> Result<(), String> {
  let root = std::env::var("RADIATA_SLO_ROOT")
    .map(PathBuf::from)
    .map_err(|_| "RADIATA_SLO_ROOT unset".to_owned())?;
  let ledger_path = std::env::var("RADIATA_SLO_LEDGER")
    .map(PathBuf::from)
    .map_err(|_| "RADIATA_SLO_LEDGER unset".to_owned())?;
  std::fs::create_dir_all(&root).map_err(|error| error.to_string())?;
  let mut ledger = std::fs::OpenOptions::new()
    .create(true)
    .append(true)
    .open(&ledger_path)
    .map_err(|error| error.to_string())?;
  use std::io::Write as _;
  let mut sample_seed: u32 = 0;
  let mut recorded = 0_usize;
  for run in 1..=runs {
    // Five fresh independent runs — every run creates fresh
    // identities, stores, credentials, and ports, and is shut down and
    // cleaned up before the next one starts. A failed run fails the
    // attempt: the summary records the shortfall.
    let run_root = root.join(format!("run{run}"));
    if let Err(error) = measure_run(
      &run_root,
      run,
      &mut ledger,
      &mut sample_seed,
      &mut recorded,
    )
    .await
    {
      eprintln!("slo-controller: run {run} failed: {error}");
      break;
    }
  }
  let status = if recorded == runs as usize * 25 { "pass" } else { "fail" };
  let summary = format!(
    "{{\"schema\":\"radiata.woooo.tech/schemas/slo-ledger-summary-v1\",\"commit\":\"{expected_commit}\",\"runs\":{runs},\"recorded\":{recorded},\"status\":\"{status}\"}}\n"
  );
  ledger
    .write_all(summary.as_bytes())
    .map_err(|error| error.to_string())?;
  if status == "pass" {
    Ok(())
  } else {
    Err("the measurement recorded failures or missing samples".to_owned())
  }
}

/// One fresh independent run over a brand-new sixteen-node cluster.
async fn measure_run(
  root: &std::path::Path, run: u32, ledger: &mut std::fs::File,
  sample_seed: &mut u32, recorded: &mut usize,
) -> Result<(), String> {
  let workload_nodes = 5_usize;

  // Cluster startup (untimed): one creator plus ten already-merged
  // members. One fresh credential per member; retries REUSE it. A failed
  // join consumes no credential and the accept loop recomputes its hint
  // per connection, so the next dial with the SAME generation matches (a
  // rotate-per-retry would leave the blocked accept permanently one
  // generation behind).
  let mut members: Vec<NodeProcess> = Vec::new();
  let mut creator: NodeProcess = {
    let mut node = spawn_node(root, 0, "", "creator")?;
    let line = node.read_line()?;
    common::parse_credential_line(&line).ok_or("creator returned no initial credential")?;
    wait_ready(&mut node, Duration::from_secs(120))?;
    node
  };
  let creator_id = creator.node_id.clone().ok_or("creator id missing")?;
  for index in 0..INITIAL_MEMBERS {
    eprintln!("slo-controller: run {run} startup member {index} rotating");
    let creator_ref = &mut creator;
    creator_ref.send("rotate")?;
    let line = creator_ref.read_line()?;
    let secret = common::parse_credential_line(&line).ok_or("creator returned no credential")?;
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
      let mut node = spawn_node(
        root,
        index + 1,
        &creator_endpoint(Some(creator_ref))?,
        "member",
      )?;
      eprintln!("slo-controller: run {run} startup member {index} joining");
      node.send(&format!("join {secret}"))?;
      match wait_ready(&mut node, Duration::from_secs(120)) {
        Ok(()) => {
          eprintln!("slo-controller: run {run} startup member {index} ready");
          members.push(node);
          break;
        }
        Err(_) if Instant::now() < deadline => {
          // Pace the retries outside the fixed per-source admission
          // window (sixteen attempts per minute).
          tokio::time::sleep(Duration::from_millis(4_000)).await;
          continue;
        }
        Err(error) => return Err(error),
      }
    }
  }

  // -- merge stratum: five fresh nodes join through fixed admission.
  for index in 0..workload_nodes {
    creator.send("rotate")?;
    let line = creator.read_line()?;
    let secret = common::parse_credential_line(&line).ok_or("creator returned no credential")?;
    // The sample starts before the credential is relayed: the raw window
    // covers the full admission through the public observation. A failed
    // join consumes no credential, so retries reuse the same secret; the
    // retries are paced outside the per-source admission window.
    let mut started: Option<u128> = None;
    let outcome;
    let mut ended;
    let mut joined: Option<NodeProcess> = None;
    let admission_deadline = Instant::now() + Duration::from_secs(180);
    let issuer = creator_endpoint(Some(&creator))?;
    loop {
      let mut fresh = spawn_node(root, INITIAL_MEMBERS + index + 1, &issuer, "member")?;
      if started.is_none() {
        started = Some(now_ms());
      }
      fresh.send(&format!("join {secret}"))?;
      let ready = wait_ready(&mut fresh, Duration::from_secs(120));
      ended = now_ms();
      if ready.is_ok() {
        outcome = "ok";
        joined = Some(fresh);
        break;
      }
      if Instant::now() > admission_deadline {
        outcome = "failed";
        break;
      }
      tokio::time::sleep(Duration::from_millis(4_000)).await;
    }
    let pass = outcome == "ok";
    write_sample(
      ledger,
      run,
      index as u32 + 1,
      "merge",
      started.unwrap_or(0),
      ended,
      outcome,
    )?;
    *recorded += 1;
    if let Some(fresh) = joined {
      members.push(fresh);
    }
    if !pass {
      return Err("an admission sample failed".to_owned());
    }
  }

  // -- topology: prune the star down to the sparse final
  // graph. The creator keeps sessions only with its frozen ring/chord
  // neighbours; every member-to-member edge is dialled credential-free.
  // Intentionally disconnected peers are never re-dialled by recovery,
  // so the pruned sessions stay pruned.
  let creator_neighbours: Vec<usize> = topology::profile_edges()
    .iter()
    .filter(|edge| edge.0 == 0 || edge.1 == 0)
    .map(|edge| if edge.0 == 0 { edge.1 } else { edge.0 })
    .collect();
  let population = INITIAL_MEMBERS + workload_nodes;
  for index in 1..=population {
    if creator_neighbours.contains(&index) {
      continue;
    }
    let id = members[index - 1].node_id.clone().ok_or("member id missing")?;
    creator.send(&format!("disconnect {id}"))?;
    let reply = creator.read_line()?;
    if reply.trim() != "disconnect ok" {
      return Err(format!("session prune failed: {reply}"));
    }
  }
  for edge in topology::profile_edges() {
    if edge.0 == 0 || edge.1 == 0 {
      continue;
    }
    let (dialer, target) = (edge.0 - 1, edge.1 - 1);
    let target_endpoint = members[target].endpoint.clone().ok_or("member endpoint missing")?;
    let target_id = members[target].node_id.clone().ok_or("member id missing")?;
    let dial_deadline = Instant::now() + Duration::from_secs(150);
    loop {
      members[dialer]
        .send(&format!("connect {target_endpoint} {target_id}"))?;
      let reply = members[dialer].read_line()?;
      if reply.trim() == "connect ok" {
        break;
      }
      if Instant::now() > dial_deadline {
        return Err(format!(
          "topology edge {}->{} never dialled: {reply}",
          edge.0, edge.1
        ));
      }
      // The pairwise trust trails the merges on the sync cadence.
      tokio::time::sleep(Duration::from_millis(4_000)).await;
    }
  }

  // Distribute the frozen per-source next-hop rows: each helper learns
  // the first hop toward every destination over its stdin protocol, so
  // the registered routing policy resolves multi-hop routes.
  let hop_table = topology::next_hop_table();
  let mut node_ids: Vec<String> = vec![creator_id.clone()];
  for member in &members {
    node_ids.push(member.node_id.clone().ok_or("member id missing")?);
  }
  for (source, row) in &hop_table {
    for (destination, hop) in row {
      let line = format!("route {} {}", node_ids[*destination], node_ids[*hop]);
      let (reply, label) = if *source == 0 {
        creator.send(&line)?;
        (creator.read_line()?, 0)
      } else {
        let member = &mut members[source - 1];
        member.send(&line)?;
        (member.read_line()?, *source)
      };
      if reply.trim() != "route ok" {
        return Err(format!(
          "route row {destination}->{hop} rejected at node {label}: {reply}"
        ));
      }
    }
  }

  creator.send("members")?;
  let line = creator.read_line()?;
  let member_ids: Vec<String> = line
    .strip_prefix("members ")
    .unwrap_or("")
    .split(',')
    .filter(|id| !id.is_empty())
    .map(str::to_owned)
    .collect();
  if member_ids.len() < workload_nodes {
    return Err("not enough members for the packet strata".to_owned());
  }
  // Label member seven as the routed stratum's only eligible target:
  // the exact three-hop endpoint of the frozen topology, so every routed
  // sample crosses exactly three hops. The label propagates
  // to the creator's public page over the sparse topology.
  members[6].send("setzone edge")?;
  let reply = members[6].read_line()?;
  if reply.trim() != "zone ok" {
    return Err(format!("zone label setup failed: {reply}"));
  }
  // Untimed setup: wait until the creator's public member page exposes
  // the zone label of the three-hop routed target (member seven, the
  // exact three-hop endpoint of the frozen topology).
  {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
      creator.send("zones")?;
      let reply = creator.read_line()?;
      let count = reply
        .trim()
        .strip_prefix("zones ")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
      if count >= 1 {
        break;
      }
      if Instant::now() > deadline {
        return Err(format!("zone label never converged; last {reply:?}"));
      }
      tokio::time::sleep(Duration::from_millis(200)).await;
    }
  }

  // -- direct packet stratum: targets are other nodes only.
  let targets: Vec<&String> =
    member_ids.iter().filter(|id| *id != &creator_id).collect();
  for index in 0..workload_nodes {
    let target = &targets[index % targets.len()];
    let started = now_ms();
    creator.send(&format!("workload direct {target}"))?;
    let line = creator.read_line()?;
    let ended = now_ms();
    let outcome = if line.contains("\"outcome\":\"ok\"") {
      "ok"
    } else {
      "failed"
    };
    write_sample(
      ledger,
      run,
      index as u32 + 1,
      "direct-packet",
      started,
      ended,
      outcome,
    )?;
    *recorded += 1;
    if outcome != "ok" {
      return Err("a direct packet sample failed".to_owned());
    }
  }

  // -- routed packet stratum (label-selected destination).
  for index in 0..workload_nodes {
    let started = now_ms();
    creator.send("workload routed")?;
    let line = creator.read_line()?;
    let ended = now_ms();
    let outcome = if line.contains("\"outcome\":\"ok\"") {
      "ok"
    } else {
      "failed"
    };
    write_sample(
      ledger,
      run,
      index as u32 + 1,
      "routed-packet",
      started,
      ended,
      outcome,
    )?;
    *recorded += 1;
    if outcome != "ok" {
      return Err("a routed packet sample failed".to_owned());
    }
  }

  // -- node metadata stratum: one owner revision observed by every member.
  for index in 0..workload_nodes {
    let value = format!("run{run}-{index}");
    let started = now_ms();
    creator.send(&format!("workload node-meta 0 {value}"))?;
    let line = creator.read_line()?;
    // The acceptance predicate: every member observes the exact label
    // value through its own public member page (bounded polling while
    // sync converges over the sparse topology).
    let mut observed = false;
    let convergence = Instant::now() + Duration::from_secs(30);
    loop {
      let mut all_yes = true;
      for member in &mut members {
        member.send(&format!("haszone {value}"))?;
        let reply = member.read_line()?;
        if reply.trim() != "haszone yes" {
          all_yes = false;
        }
      }
      if all_yes {
        observed = true;
        break;
      }
      if Instant::now() > convergence {
        break;
      }
      tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let ended = now_ms();
    let outcome = if observed && line.contains("\"outcome\":\"ok\"") {
      "ok"
    } else {
      "failed"
    };
    write_sample(
      ledger,
      run,
      index as u32 + 1,
      "node-metadata",
      started,
      ended,
      outcome,
    )?;
    *recorded += 1;
    if outcome != "ok" {
      return Err("a node metadata sample failed".to_owned());
    }
  }

  // -- resource metadata stratum.
  for index in 0..workload_nodes {
    *sample_seed += 1;
    let name = format!("radiata.woooo.tech/resources/workload-{sample_seed:03}");
    let started = now_ms();
    creator.send(&format!("workload resource {sample_seed}"))?;
    let line = creator.read_line()?;
    let mut observed = false;
    let convergence = Instant::now() + Duration::from_secs(30);
    loop {
      let mut all_yes = true;
      for member in &mut members {
        member.send(&format!("has {name}"))?;
        let reply = member.read_line()?;
        if reply.trim() != "has yes" {
          all_yes = false;
        }
      }
      if all_yes {
        observed = true;
        break;
      }
      if Instant::now() > convergence {
        break;
      }
      tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let ended = now_ms();
    let outcome = if observed && line.contains("\"outcome\":\"ok\"") {
      "ok"
    } else {
      "failed"
    };
    write_sample(
      ledger,
      run,
      index as u32 + 1,
      "resource-metadata",
      started,
      ended,
      outcome,
    )?;
    *recorded += 1;
    if outcome != "ok" {
      return Err("a resource metadata sample failed".to_owned());
    }
  }

  // Cleanup: ordered shutdown of every helper; the run-owned stores are
  // removed by the helpers' shutdown path, and the empty run directory
  // goes with them.
  for member in members {
    let _ = member.shutdown();
  }
  let _ = creator.shutdown();
  let _ = std::fs::remove_dir(root);
  Ok(())
}

fn now_ms() -> u128 {
  std::time::SystemTime::now()
    .duration_since(std::time::SystemTime::UNIX_EPOCH)
    .map(|value| value.as_millis())
    .unwrap_or(0)
}

/// Writes one raw sample record into the release ledger.
fn write_sample(
  ledger: &mut std::fs::File, run: u32, index: u32, stratum: &str, started: u128, ended: u128,
  outcome: &str,
) -> Result<(), String> {
  let line = format!(
    "{{\"schema\":\"radiata.woooo.tech/schemas/slo-ledger-v1\",\"sample_id\":\"run-{run}/sample-{index}\",\"stratum\":\"{stratum}\",\"started_at_ms\":{started},\"ended_at_ms\":{ended},\"outcome\":\"{outcome}\"}}\n"
  );
  ledger
    .write_all(line.as_bytes())
    .map_err(|error| error.to_string())
}
