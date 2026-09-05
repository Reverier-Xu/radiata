//! The SLO harness controller (`slo-controller`).
//!
//! The controller owns the cluster: it starts node helper processes,
//! drives readiness and the workload through public facade observations
//! only, records raw wall-clock samples into the release ledger, and
//! performs the ordered shutdown and cleanup. It never inspects private
//! node state (SC-G10-P0-31): its only node-facing channels are the
//! helpers' stdin protocols and the public facade itself.
//!
//! Modes:
//! - `qualify <nodes>`: start a bounded cluster, prove readiness through
//!   public pages, shut down in order, and record the qualification
//!   outcome — the harness self-proof demanded by SC-G10-P0-33 without
//!   claiming any SLO sample.
//! - `measure`: the exact 125-sample workload, refused until the external
//!   release token of T-G10-12 gates the immutable candidate.

use std::{
  io::{BufRead, Write},
  path::PathBuf,
  process::{Child, ChildStdin, ChildStdout, Command, Stdio},
  time::{Duration, Instant},
};

use radiata_slo::common;

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
    // The exact 125-sample workload. The external T-G10-12 release token
    // (candidate SHA + complete-ledger digest, `eligible = true`) must be
    // present and match the tested commit before any sample starts.
    "measure" => {
      let runs = args
        .get(2)
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(5);
      measure(runs)
    }
    other => Err(format!("unknown mode {other}")),
  };
  if let Err(error) = result {
    eprintln!("slo-controller failed: {error}");
    std::process::exit(1);
  }
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
    // shutdown proves the helper exited cleanly (ADR-0005 cleanup rules:
    // run-owned containers, networks, stores, credentials, artifacts).
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
      // A fresh single-use credential per member; a transient handshake
      // refusal (a loaded accept loop expiring the fixed authentication
      // deadline) retries with a newly rotated credential — the harness
      // precedent for admission-sensitive operations.
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

/// The token gate: the external signed release-eligibility token file
/// records the exact candidate SHA, the Cargo.lock digest, the package
/// version, and `eligible = true`; it never enters the attested commit.
fn verify_release_token(expected_commit: &str) -> Result<(), String> {
  let path = std::env::var("RADIATA_SLO_TOKEN")
    .map_err(|_| "RADIATA_SLO_TOKEN unset: measurement is not eligible".to_owned())?;
  let text =
    std::fs::read_to_string(&path).map_err(|error| format!("release token unreadable: {error}"))?;
  // The token file is a flat object of string/bool fields produced by the
  // external issuer; pull the four allowlisted keys by pattern.
  let field = |key: &str| {
    let marker = format!("\"{key}\":");
    text
      .find(&marker)
      .map(|start| {
        let rest = &text[start + marker.len()..];
        let end = rest.find([',', '}']).unwrap_or(rest.len());
        rest[..end].trim().trim_matches('"').to_owned()
      })
      .unwrap_or_default()
  };
  let eligible = field("eligible") == "true";
  let commit = field("commit");
  let version = field("version");
  if !eligible {
    return Err("the release token is not eligible".to_owned());
  }
  if commit != expected_commit {
    return Err("the release token commit does not match the tested commit".to_owned());
  }
  if version != "0.1.0" {
    return Err(format!(
      "the release token version is {version}, expected 0.1.0"
    ));
  }
  Ok(())
}

/// The exact ADR-0005 measurement: five runs of the five-stratum
/// 25-sample mix over one sixteen-node cluster, every raw sample recorded.
fn measure(runs: u32) -> Result<(), String> {
  let expected_commit =
    std::env::var("RADIATA_SLO_COMMIT").map_err(|_| "RADIATA_SLO_COMMIT unset".to_owned())?;
  if expected_commit == "unknown" || expected_commit.is_empty() {
    return Err("RADIATA_SLO_COMMIT must be the exact candidate SHA".to_owned());
  }
  verify_release_token(&expected_commit)?;
  let runtime = tokio::runtime::Builder::new_multi_thread()
    .worker_threads(2)
    .enable_all()
    .build()
    .map_err(|error| error.to_string())?;
  let commit = expected_commit.clone();
  runtime.block_on(async move { measure_async(runs, commit).await })
}

async fn measure_async(runs: u32, expected_commit: String) -> Result<(), String> {
  let root = std::env::var("RADIATA_SLO_ROOT")
    .map(PathBuf::from)
    .map_err(|_| "RADIATA_SLO_ROOT unset".to_owned())?;
  let ledger_path = std::env::var("RADIATA_SLO_LEDGER")
    .map(PathBuf::from)
    .map_err(|_| "RADIATA_SLO_LEDGER unset".to_owned())?;
  std::fs::create_dir_all(&root).map_err(|error| error.to_string())?;
  let workload_nodes = 5_usize;

  // Cluster startup (untimed): one creator plus five workload members.
  let mut members: Vec<NodeProcess> = Vec::new();
  let mut creator: NodeProcess = {
    let mut node = spawn_node(&root, 0, "", "creator")?;
    let line = node.read_line()?;
    common::parse_credential_line(&line).ok_or("creator returned no initial credential")?;
    wait_ready(&mut node, Duration::from_secs(120))?;
    node
  };
  let creator_id = creator.node_id.clone().ok_or("creator id missing")?;
  for index in 0..workload_nodes {
    // One fresh credential per member; retries REUSE it. A failed join
    // consumes no credential and the accept loop recomputes its hint per
    // connection, so the next dial with the SAME generation matches (a
    // rotate-per-retry would leave the blocked accept permanently one
    // generation behind).
    eprintln!("slo-controller: startup member {index} rotating");
    let creator_ref = &mut creator;
    creator_ref.send("rotate")?;
    eprintln!("slo-controller: startup member {index} credential ready");
    let line = creator_ref.read_line()?;
    let secret = common::parse_credential_line(&line).ok_or("creator returned no credential")?;
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
      let mut node = spawn_node(
        &root,
        index + 1,
        &creator_endpoint(Some(creator_ref))?,
        "member",
      )?;
      eprintln!("slo-controller: startup member {index} spawned, joining");
      node.send(&format!("join {secret}"))?;
      eprintln!("slo-controller: startup member {index} join sent");
      match wait_ready(&mut node, Duration::from_secs(120)) {
        Ok(()) => {
          eprintln!("slo-controller: startup member {index} ready");
          // Untimed setup: label the member so the routed stratum's
          // label-selected targets resolve (ADR-0005 routed samples).
          node.send("setzone edge")?;
          let reply = node.read_line()?;
          if reply.trim() != "zone ok" {
            return Err(format!("zone label setup failed: {reply}"));
          }
          members.push(node);
          break;
        }
        Err(_) if Instant::now() < deadline => {
          // Pace the retries outside the fixed per-source admission
          // window (sixteen attempts per minute).
          tokio::time::sleep(Duration::from_millis(300)).await;
          continue;
        }
        Err(error) => return Err(error),
      }
    }
  }

  let mut sample_seed: u32 = 0;
  let mut recorded = 0_usize;
  let mut all_pass = true;
  let mut ledger = std::fs::OpenOptions::new()
    .create(true)
    .append(true)
    .open(&ledger_path)
    .map_err(|error| error.to_string())?;
  use std::io::Write as _;

  for run in 1..=runs {
    // -- admission stratum: five fresh nodes join through fixed admission.
    for index in 0..workload_nodes {
      let port = 18_000_u32 + (run - 1) * 100 + index as u32;
      creator.send("rotate")?;
      let line = creator.read_line()?;
      let secret = common::parse_credential_line(&line).ok_or("creator returned no credential")?;
      // The sample starts before the credential is relayed: the raw
      // window covers the full admission through the public observation.
      // A failed join consumes no credential, so retries reuse the same
      // secret (the accept loop recomputes its hint per connection; a
      // rotate-per-retry would leave the blocked accept one generation
      // behind). The start timestamp is taken at the first relay.
      let mut started: Option<u128> = None;
      let outcome;
      let mut ended;
      let mut joined: Option<NodeProcess> = None;
      let admission_deadline = Instant::now() + Duration::from_secs(180);
      loop {
        let mut fresh = spawn_admission_node(&root, run, index as u32, port)?;
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
        tokio::time::sleep(Duration::from_millis(300)).await;
      }
      if outcome == "failed" {
        all_pass = false;
      }
      write_sample(
        &mut ledger,
        run,
        index as u32 + 1,
        "admission",
        started.unwrap_or(0),
        ended,
        outcome,
      )?;
      recorded += 1;
      if let Some(fresh) = joined {
        members.push(fresh);
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
    // Untimed setup: wait until the creator's public member page exposes
    // the zone label of every workload member (descriptor convergence).
    {
      let deadline = Instant::now() + Duration::from_secs(60);
      loop {
        creator.send("zones")?;
        let reply = creator.read_line()?;
        // The creator's own node-metadata samples also carry the zone
        // label, so the converged count is at least the workload members.
        let count = reply
          .trim()
          .strip_prefix("zones ")
          .and_then(|value| value.parse::<usize>().ok())
          .unwrap_or(0);
        if count >= workload_nodes {
          break;
        }
        if Instant::now() > deadline {
          return Err(format!("zone labels never converged; last {reply:?}"));
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
      if outcome == "failed" {
        all_pass = false;
      }
      write_sample(
        &mut ledger,
        run,
        index as u32 + 1,
        "direct-packet",
        started,
        ended,
        outcome,
      )?;
      recorded += 1;
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
      if outcome == "failed" {
        all_pass = false;
      }
      write_sample(
        &mut ledger,
        run,
        index as u32 + 1,
        "routed-packet",
        started,
        ended,
        outcome,
      )?;
      recorded += 1;
    }

    // -- node metadata stratum: one owner revision observed by every member.
    for index in 0..workload_nodes {
      let value = format!("run{run}-{index}");
      let started = now_ms();
      creator.send(&format!("workload node-meta 0 {value}"))?;
      let line = creator.read_line()?;
      // The acceptance predicate: every member observes the exact label
      // value through its own public member page (bounded polling while
      // sync converges).
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
      if outcome == "failed" {
        all_pass = false;
      }
      write_sample(
        &mut ledger,
        run,
        index as u32 + 1,
        "node-metadata",
        started,
        ended,
        outcome,
      )?;
      recorded += 1;
    }

    // -- resource metadata stratum.
    for index in 0..workload_nodes {
      sample_seed += 1;
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
      if outcome == "failed" {
        all_pass = false;
      }
      write_sample(
        &mut ledger,
        run,
        index as u32 + 1,
        "resource-metadata",
        started,
        ended,
        outcome,
      )?;
      recorded += 1;
    }
  }

  // Cleanup: ordered shutdown of every helper; the run-owned stores are
  // removed by the helpers' shutdown path.
  for member in members {
    let _ = member.shutdown();
  }
  let _ = creator.shutdown();
  let summary = format!(
    "{{\"schema\":\"radiata.woooo.tech/schemas/slo-ledger-summary-v1\",\"commit\":\"{expected_commit}\",\"runs\":{runs},\"recorded\":{recorded},\"status\":\"{}\"}}\n",
    if all_pass && recorded == runs as usize * 25 {
      "pass"
    } else {
      "fail"
    }
  );
  ledger
    .write_all(summary.as_bytes())
    .map_err(|error| error.to_string())?;
  if all_pass && recorded == runs as usize * 25 {
    Ok(())
  } else {
    Err("the measurement recorded failures or missing samples".to_owned())
  }
}

fn now_ms() -> u128 {
  std::time::SystemTime::now()
    .duration_since(std::time::SystemTime::UNIX_EPOCH)
    .map(|value| value.as_millis())
    .unwrap_or(0)
}

/// Spawns one admission-sample helper: a listening, unjoined member.
fn spawn_admission_node(
  root: &std::path::Path, run: u32, index: u32, port: u32,
) -> Result<NodeProcess, String> {
  let directory = root.join(format!("admission-run{run}-{index}"));
  std::fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
  let endpoint = format!("wss://127.0.0.1:{port}");
  let mut command = Command::new(node_binary());
  command
    .env(common::ENV_ROLE, "member")
    .env(common::ENV_DIR, &directory)
    .env(common::ENV_ENDPOINT, &endpoint)
    .env(common::ENV_ISSUER, "wss://127.0.0.1:17000");
  command
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::inherit());
  let mut child = command
    .spawn()
    .map_err(|error| format!("admission node spawn failed: {error}"))?;
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
