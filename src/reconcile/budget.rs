//! The sync-budget lane: the R4 acceptance harness.
//!
//! A deterministic engine-level mesh that mirrors the plane's five
//! attachment points (prime, debounced local change, fan-out, cadence
//! ROOT rotation, drain) over one lane and measures the three budget
//! invariants the proposal §9 V1 gate names:
//!
//! 1. **payload delivery redundancy** — row bytes that actually crossed an edge
//!    over the row bytes a full-convergence run strictly needed (each row ×
//!    each node that lacked it, exactly once): ≤ 1.05× on the no-loss
//!    steady-state matrices;
//! 2. **hint traffic** — the summary bytes of HINT messages (the piggyback's
//!    row bytes are payload, so they count on the ledger above, not here)
//!    within `changes × degree × HINT_BUDGET_BYTES`;
//! 3. **loss convergence** — with a deterministic 20% message drop, the full
//!    trigger layer converges no slower than the baseline with the eager-delta
//!    knob off (the pre-R4 engine behavior).
//!
//! The harness is engine-level on purpose: the redundancy and hint
//! budgets are properties of the negotiation discipline itself, and the
//! full-suite equivalence lanes (membership, chaos, scale) carry the
//! plane/session/store layers above it. n = 256 is one matrix cell
//! here, not a forty-minute lane.

#![cfg(test)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use super::{
  engine::{Drive, Engine},
  wire::{LaneId, Message},
};

/// The mesh degree k: a ring plus the half-turn chord — every node
/// reaches the whole mesh in at most two hops, the shape the
/// connection-degree plane maintains at small n.
const DEGREE: usize = 2;

/// The steady-state hint budget: one debounced hint per change per edge,
/// at most this many summary bytes. A single-range hint is ~40 bytes on
/// the wire; the bound allows a coalesced multi-range hint (~17 bytes
/// per range) with generous headroom while still catching the failure
/// this gate exists for — a hint per row (or per tick per edge of an
/// unchanged catalog) blows it by an order of magnitude.
const HINT_BUDGET_BYTES: usize = 200;

/// The redundancy tolerance: delivered row bytes over necessary row
/// bytes. Payload crosses an edge exactly once per lacking receiver, so
/// the honest floor is 1.0; the 5% headroom absorbs the DONE/repair
/// boundary cases without licensing re-sends.
const REDUNDANCY_BOUND: f64 = 1.05;

/// The loss rate of the loss matrix: every fifth message drops.
const LOSS_INTERVAL: u64 = 5;

/// The cadence of the quiet ROOT rotation (ticks), shared with the
/// plane.
const CADENCE_TICKS: u32 = 32;

/// The per-node hold on held hints (one round's worth of concurrent
/// notices per peer, matching the engine's pending set discipline).
const HELD_HINTS_PER_NODE: usize = 8;

/// The ROOT exchange window per tick per node, shared with the plane.
const ROOT_WINDOW: usize = 2;

/// A deterministic xorshift64* generator: the matrix is reproducible
/// bit-for-bit.
struct Rng(u64);

impl Rng {
  fn new(seed: u64) -> Self {
    Self(seed | 1)
  }

  fn next(&mut self) -> u64 {
    let mut x = self.0;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    self.0 = x;
    x.wrapping_mul(0x2545_F491_4F6C_DD1D)
  }
}

/// One directed edge message.
struct Frame {
  from: usize,
  to: usize,
  message: Message,
}

/// The measurement ledger of one run.
#[derive(Default)]
struct Ledger {
  /// Row bytes that actually crossed an edge and landed (ROWS payloads
  /// plus eager-delta piggybacks): counted at delivery only — a frame
  /// a dead session swallowed (the reconnect partition window) is
  /// emission, not delivery, and the redundancy numerator counts what
  /// the receiver took.
  row_bytes_delivered: usize,
  /// The summary bytes of hint messages (message size minus the
  /// piggyback's row bytes, re-encoded without rows), counted at
  /// emission: hints are fire-and-forget notices, so the hint budget
  /// is what went on the wire whether or not it landed.
  hint_summary_bytes: usize,
  hints: usize,
  roots: usize,
  /// The delivery-shape breakdown for diagnostics: negotiated ROWS
  /// bytes with message counts, and the eager piggyback hint count
  /// (its row bytes are inside `row_bytes_delivered`).
  rows_bytes: usize,
  rows_messages: usize,
  eager_hints: usize,
  /// The duplicate-delivery oracle: each delivered row's sender→receiver
  /// edge, counted per (row, edge) — a count above one is redundant
  /// delivery the redundancy bound must absorb or the design must fix.
  row_deliveries: BTreeMap<(usize, usize, Vec<u8>), usize>,
}

impl Ledger {
  /// Accounts one crossing frame's summary traffic at emission (hints
  /// are fire-and-forget notices: what went on the wire is the hint
  /// budget, whether it landed).
  fn record(&mut self, message: &Message) {
    match message {
      Message::Rows { .. } => {}
      Message::Hint { ranges, rows, lane } => {
        let summary = Message::Hint {
          lane: *lane,
          ranges: ranges.clone(),
          rows: Vec::new(),
        };
        self.hint_summary_bytes += super::wire::encode(&summary)
          .map(|bytes| bytes.len())
          .unwrap_or_default();
        self.hints += 1;
        self.eager_hints += !rows.is_empty() as usize;
      }
      Message::Root { .. } => self.roots += 1,
      _ => {}
    }
  }

  /// Accounts one delivered (not dropped) frame's rows on its edge:
  /// payload redundancy counts what actually crossed, so a frame the
  /// dead session swallowed (the reconnect partition window) is not
  /// delivery.
  fn record_delivery(&mut self, from: usize, to: usize, rows: &[super::wire::Row]) {
    let bytes: usize = rows
      .iter()
      .map(|row| row.key.len() + row.content.len())
      .sum();
    self.row_bytes_delivered += bytes;
    self.rows_messages += 1;
    self.rows_bytes += bytes;
    for row in rows {
      *self
        .row_deliveries
        .entry((from, to, row.key.clone()))
        .or_default() += 1;
    }
  }

  /// The diagnostic summary for a failing assertion.
  fn breakdown(&self) -> String {
    let duplicates: usize = self
      .row_deliveries
      .values()
      .filter(|count| **count > 1)
      .copied()
      .sum();
    let unique = self.row_deliveries.len();
    // One exemplar row's full delivery trace (edges as from→to).
    let exemplar = self
      .row_deliveries
      .keys()
      .map(|(_, _, key)| key.clone())
      .min()
      .unwrap_or_default();
    let trace: Vec<String> = self
      .row_deliveries
      .iter()
      .filter(|((_, _, key), _)| *key == exemplar)
      .map(|((from, to, _), count)| format!("{from}->{to}x{count}"))
      .collect();
    format!(
      "rows_messages={} rows_bytes={} eager_hints={} hints={} roots={} \
       unique_row_node_deliveries={} duplicate_deliveries={} exemplar=[{}]",
      self.rows_messages,
      self.rows_bytes,
      self.eager_hints,
      self.hints,
      self.roots,
      unique,
      duplicates,
      trace.join(", ")
    )
  }
}

/// One simulated node: its applied store, one engine per directed
/// session, and the per-lane held sets (the pull-serialization
/// discipline the plane enforces — one negotiation per lane per node:
/// held hints and held root-exchange drives release when the lane goes
/// quiet).
struct Node {
  store: BTreeMap<Vec<u8>, Vec<u8>>,
  engines: BTreeMap<usize, Engine>,
  /// Held inbound hints (rows stripped and applied) whose lane still
  /// negotiates elsewhere at the node; inbound roots in the same window
  /// drop instead (a stale whole-lane claim must never initiate).
  held: BTreeMap<usize, Vec<Message>>,
  /// Peers whose root-exchange drive waits out the lane's open round
  /// (the prime and the cadence re-drive are initiations too).
  held_roots: Vec<usize>,
}

impl Node {
  fn new() -> Self {
    Self {
      store: BTreeMap::new(),
      engines: BTreeMap::new(),
      held: BTreeMap::new(),
      held_roots: Vec::new(),
    }
  }

  fn engine(&mut self, peer: usize) -> &mut Engine {
    self
      .engines
      .entry(peer)
      .or_insert_with(|| Engine::new(LaneId::Resources))
  }

  /// Whether any session engine of the (single) lane has an open
  /// round, optionally excluding one engine (its own round never gates
  /// its root re-drive, which replaces it).
  fn lane_in_round(&self, except: Option<usize>) -> bool {
    self
      .engines
      .iter()
      .filter(|(peer, _)| Some(**peer) != except)
      .any(|(_, engine)| engine.round_open())
  }
}

/// The mesh: n nodes over the degree-k topology, the shared frame
/// queues, the drop counter, and the ledger.
struct Mesh {
  nodes: Vec<Node>,
  edges: Vec<Vec<usize>>,
  frames: VecDeque<Frame>,
  dropped: u64,
  ledger: Ledger,
  /// The R4 trigger knobs: eager-delta on (the full layer) or off (the
  /// pre-R4 baseline the loss matrix compares against).
  eager: bool,
  tick: u64,
  /// The diagnostic label of the cell (mesh size and shape).
  label: String,
}

impl Mesh {
  fn new(nodes: usize, eager: bool) -> Self {
    // The symmetric degree-2 ring: an undirected edge set (both ring
    // directions), so every session the mesh simulates is mutual —
    // a directed edge list would leave the receiver's engine-for-peer
    // empty and it would pull the row back from its own propagation.
    let edges: Vec<Vec<usize>> = (0..nodes)
      .map(|index| {
        vec![(index + 1) % nodes, (index + nodes - 1) % nodes]
          .into_iter()
          .collect::<BTreeSet<_>>()
          .into_iter()
          .collect()
      })
      .collect();
    Self {
      nodes: (0..nodes).map(|_| Node::new()).collect(),
      edges,
      frames: VecDeque::new(),
      dropped: 0,
      ledger: Ledger::default(),
      eager,
      tick: 0,
      label: format!("{nodes}-node"),
    }
  }

  /// One plane turn for one node: the debounced local change over its
  /// engines (the originator's eager piggyback rides here), then the
  /// cadence ROOT rotation.
  fn drive_node(&mut self, index: usize) {
    let peers = self.edges[index].clone();
    for peer in peers {
      let drive = if self.eager {
        Drive::LocalChangeEager
      } else {
        Drive::LocalChange
      };
      let out = self.nodes[index].engine(peer).drive(drive);
      self.emit(index, peer, out);
    }
  }

  /// The cadence ROOT rotation for one node (the bounded fair window),
  /// gated by the per-lane serialization: an exchange whose lane still
  /// negotiates elsewhere at the node waits in the held set.
  fn cadence_node(&mut self, index: usize) {
    let peers = self.edges[index].clone();
    let offset = (self.tick / u64::from(CADENCE_TICKS)) as usize;
    let window: Vec<usize> = peers
      .iter()
      .cycle()
      .skip(offset % peers.len().max(1))
      .take(ROOT_WINDOW.min(peers.len()))
      .copied()
      .collect();
    for peer in window {
      self.root_exchange_gated(index, peer);
    }
  }

  /// Drives one root exchange unless the lane is busy elsewhere at the
  /// node (the held re-drive releases with the lane's quiet).
  fn root_exchange_gated(&mut self, index: usize, peer: usize) {
    if self.nodes[index].lane_in_round(Some(peer))
      && self.nodes[index].held_roots.len() < HELD_HINTS_PER_NODE
    {
      self.nodes[index].held_roots.push(peer);
      return;
    }
    let out = self.nodes[index].engine(peer).drive(Drive::RootExchange);
    self.emit(index, peer, out);
  }

  /// Applies one node's local writes: the store row feeds every
  /// session engine (the epoch pass's insert), then the debounced
  /// change drive.
  fn write_rows(&mut self, index: usize, rows: &[(Vec<u8>, Vec<u8>)]) {
    let peers = self.edges[index].clone();
    for (key, content) in rows {
      self.nodes[index].store.insert(key.clone(), content.clone());
      for peer in &peers {
        let _ = self.nodes[index].engine(*peer).insert_row(key, content);
      }
    }
    self.drive_node(index);
  }

  /// Queues one engine's output frames (a drive error is a harness
  /// bug: the engine is driven with well-formed input only).
  fn emit(&mut self, from: usize, to: usize, out: crate::Result<Vec<Message>>) {
    for message in out.unwrap() {
      self.ledger.record(&message);
      self.frames.push_back(Frame { from, to, message });
    }
  }

  /// Pumps every queued frame to its destination (applying carried rows
  /// through the fan-out discipline) until the mesh is quiet. `loss`
  /// drops every `LOSS_INTERVAL`-th frame, deterministically.
  fn pump(&mut self, loss: bool, rng: &mut Rng) {
    let mut guard = 0_u64;
    while let Some(frame) = self.frames.pop_front() {
      guard += 1;
      assert!(
        guard < 2_000_000,
        "the {} mesh did not quiesce at tick {} ({} frames, {} dropped)",
        self.label,
        self.tick,
        guard,
        self.dropped
      );
      if self.nodes[frame.to].engines.contains_key(&frame.from) {
        // The session exists: deliver.
      } else {
        // The session is gone (an offline node's engines were cleared):
        // the frame is dropped at the session boundary.
        continue;
      }
      if loss && rng.next().is_multiple_of(LOSS_INTERVAL) {
        self.dropped += 1;
        continue;
      }
      let Frame { from, to, message } = frame;
      let rows: Vec<(Vec<u8>, Vec<u8>)> = match &message {
        Message::Rows { rows, .. } | Message::Hint { rows, .. } => rows
          .iter()
          .map(|row| (row.key.clone(), row.content.clone()))
          .collect(),
        _ => Vec::new(),
      };
      match &message {
        Message::Rows { rows, .. } | Message::Hint { rows, .. } => {
          self.ledger.record_delivery(from, to, rows);
        }
        _ => {}
      }
      // The per-lane pull serialization, mirrored from the plane: a
      // hint arriving while a *different* engine of the node's lane
      // negotiates holds (its rows still apply; the release compares
      // its claimed ranges against the settled state and usually stays
      // silent). An inbound root in the same window drops instead: its
      // whole-lane claim is stale the moment it waits, and initiating
      // from a stale claim re-delivers what the round it waited for
      // already delivered (the reconnect double-pull). Roots are cheap
      // and cadence-refreshed, so the drop costs one quiet window of
      // peer-view latency, never correctness. Responses (offer, need,
      // rows, done) always process — a peer's negotiation must never
      // wait on ours, or two nodes holding each other deadlock.
      let hold = match &message {
        Message::Hint { lane, ranges, .. }
          if self.nodes[to].lane_in_round(Some(from))
            && self.nodes[to].held.values().map(Vec::len).sum::<usize>() < HELD_HINTS_PER_NODE =>
        {
          Some(Message::Hint {
            lane: *lane,
            ranges: ranges.clone(),
            rows: Vec::new(),
          })
        }
        _ => None,
      };
      let drop_root =
        matches!(message, Message::Root { .. }) && self.nodes[to].lane_in_round(Some(from));
      if drop_root {
        self.dropped += 1;
        continue;
      }
      if let Some(held_message) = hold {
        for (key, content) in &rows {
          let _ = self.nodes[to].engine(from).insert_row(key, content);
        }
        self.nodes[to]
          .held
          .entry(from)
          .or_default()
          .push(held_message);
      } else {
        let out = self.nodes[to].engine(from).drive(Drive::Message(message));
        self.emit(to, from, out);
      }
      // The applied-rows fan-out: the row enters the store and every
      // sibling engine, then the plain (row-less) change drive.
      if !rows.is_empty() {
        for (key, content) in &rows {
          self.nodes[to].store.insert(key.clone(), content.clone());
        }
        let siblings: Vec<usize> = self.edges[to]
          .iter()
          .copied()
          .filter(|peer| *peer != from)
          .collect();
        for sibling in siblings {
          for (key, content) in &rows {
            let _ = self.nodes[to].engine(sibling).insert_row(key, content);
          }
          let out = self.nodes[to].engine(sibling).drive(Drive::LocalChange);
          self.emit(to, sibling, out);
        }
      }
      // The drain behind every delivery: backlogs surface, and a lane
      // that just went quiet releases its held hints (they usually
      // compare equal against the settled state and stay silent).
      self.drain_node(to);
      self.drain_node(from);
      self.release_held(to);
    }
  }

  /// Releases one node's held messages and root exchanges when no
  /// engine of the lane has an open round, driving each into its source
  /// engine.
  fn release_held(&mut self, index: usize) {
    if self.nodes[index].lane_in_round(None) {
      return;
    }
    let held = std::mem::take(&mut self.nodes[index].held);
    let roots = std::mem::take(&mut self.nodes[index].held_roots);
    for (from, messages) in held {
      for message in messages {
        let out = self.nodes[index]
          .engine(from)
          .drive(Drive::Message(message));
        self.emit(index, from, out);
      }
    }
    for peer in roots {
      let out = self.nodes[index].engine(peer).drive(Drive::RootExchange);
      self.emit(index, peer, out);
    }
  }

  /// Drains one node's every engine backlog into frames.
  fn drain_node(&mut self, index: usize) {
    let peers = self.nodes[index]
      .engines
      .keys()
      .copied()
      .collect::<Vec<_>>();
    for peer in peers {
      let out = self.nodes[index].engine(peer).drive(Drive::Drain);
      self.emit(index, peer, out);
    }
  }

  /// One full mesh tick: the cadence rotation on the cadence boundary,
  /// every node's drain, and the pump.
  fn tick(&mut self, loss: bool, rng: &mut Rng) {
    self.tick += 1;
    if self.tick.is_multiple_of(u64::from(CADENCE_TICKS)) {
      for index in 0..self.nodes.len() {
        self.cadence_node(index);
      }
    }
    for index in 0..self.nodes.len() {
      self.drain_node(index);
    }
    self.pump(loss, rng);
  }

  /// Takes one node offline: both directions' engines clear (the
  /// session teardown) and its frames drop at the boundary until it
  /// returns.
  fn partition(&mut self, index: usize) {
    self.nodes[index].engines.clear();
    for node in self.nodes.iter_mut() {
      node.engines.remove(&index);
    }
  }

  /// Brings one node back: the next tick's prime fills both directions'
  /// engines with the full row sets and opens with ROOT exchanges — the
  /// session-establishment contract.
  /// Brings one node back: the next tick's prime fills both directions'
  /// engines with the full row sets and opens with gated ROOT exchanges
  /// — the session-establishment contract under the per-lane
  /// serialization.
  fn heal(&mut self, index: usize) {
    for peer in self.edges[index].clone() {
      let rows: Vec<(Vec<u8>, Vec<u8>)> = self.nodes[index]
        .store
        .iter()
        .map(|(key, content)| (key.clone(), content.clone()))
        .collect();
      for (key, content) in &rows {
        let _ = self.nodes[index].engine(peer).insert_row(key, content);
      }
      self.root_exchange_gated(index, peer);
      let theirs: Vec<(Vec<u8>, Vec<u8>)> = self.nodes[peer]
        .store
        .iter()
        .map(|(key, content)| (key.clone(), content.clone()))
        .collect();
      for (key, content) in &theirs {
        let _ = self.nodes[peer].engine(index).insert_row(key, content);
      }
      self.root_exchange_gated(peer, index);
    }
  }

  /// Whether every node's store is identical.
  fn converged(&self) -> bool {
    let reference = &self.nodes[0].store;
    self.nodes.iter().all(|node| &node.store == reference)
  }

  /// The necessary row bytes of the run: every distinct row, once per
  /// node that lacked it (all nodes but its writer), at the row's
  /// actual wire size.
  fn necessary_row_bytes(&self, written: usize, row_bytes: usize) -> usize {
    written * (self.nodes.len() - 1) * row_bytes
  }
}

/// One steady-state cell: `nodes` nodes, the write shape, no loss.
/// Returns (redundancy, hint bytes per change per edge, diagnostics).
fn steady_cell(nodes: usize, batch: usize, ticks: usize, reconnect: bool) -> (f64, f64, String) {
  let mut rng = Rng::new(0xB00D_2026);
  let mut mesh = Mesh::new(nodes, true);
  let _ = &mesh.label;
  // Prime: every session fills and opens with ROOT exchanges.
  for index in 0..nodes {
    mesh.heal(index);
  }
  mesh.pump(false, &mut rng);
  let row_len = 48_usize;
  // The row's actual wire footprint (key + content bytes): the
  // necessary-delivery denominator must count real bytes, not the
  // nominal length.
  let row_bytes = "budget-0000-00000".len() + (row_len - 21);
  let mut written = 0_usize;
  let mut changes = 0_usize;
  let offline = reconnect.then_some(nodes - 1);
  if let Some(offline) = offline {
    mesh.partition(offline);
  }
  for tick in 0..ticks {
    // The steady write: one batch of fresh rows from the hub each tick.
    let rows: Vec<(Vec<u8>, Vec<u8>)> = (0..batch)
      .map(|index| {
        (
          format!("budget-{tick:04}-{index:05}").into_bytes(),
          vec![0x42; row_len - 21],
        )
      })
      .collect();
    changes += batch;
    written += batch;
    mesh.write_rows(0, &rows);
    mesh.tick(false, &mut rng);
    // The offline window: sixteen ticks of churn, then the heal.
    if let Some(offline) = offline
      && tick == 15
    {
      mesh.heal(offline);
    }
  }
  // Settle: pump until quiet and converged (bounded).
  let mut settled = 0_u64;
  while !mesh.converged() && settled < 256 {
    settled += 1;
    for index in 0..nodes {
      mesh.drive_node(index);
    }
    mesh.tick(false, &mut rng);
  }
  assert!(mesh.converged(), "the {} cell must converge", mesh.label);
  let necessary = mesh.necessary_row_bytes(written, row_bytes);
  let redundancy = mesh.ledger.row_bytes_delivered as f64 / necessary as f64;
  // The hint budget normalizes per change per session edge (the
  // proposal's O(changes × k × ~40 B): an epidemic change crosses every
  // node's k sessions once, so the denominator is changes × nodes ×
  // degree, not the writer's degree alone).
  let hint_per_change_edge =
    mesh.ledger.hint_summary_bytes as f64 / (changes * nodes * DEGREE) as f64;
  (redundancy, hint_per_change_edge, mesh.ledger.breakdown())
}

/// One loss cell: 20% deterministic drop, convergence measured in mesh
/// ticks for the full layer and the eager-off baseline.
fn loss_cell(nodes: usize, batch: usize) -> (u64, u64) {
  let run = |eager: bool| -> u64 {
    let mut rng = Rng::new(0x1055_2026);
    let mut mesh = Mesh::new(nodes, eager);
    for index in 0..nodes {
      mesh.heal(index);
    }
    mesh.pump(true, &mut rng);
    let rows: Vec<(Vec<u8>, Vec<u8>)> = (0..batch)
      .map(|index| (format!("loss-{index:05}").into_bytes(), vec![0x42; 48 - 11]))
      .collect();
    mesh.write_rows(0, &rows);
    let mut ticks = 0_u64;
    while !mesh.converged() {
      mesh.tick(true, &mut rng);
      ticks += 1;
      assert!(ticks < 4_000, "the loss cell wedged");
    }
    ticks
  };
  (run(true), run(false))
}

/// The budget matrix: n ∈ {8, 64, 256} × single-row / batch /
/// reconnect. The redundancy and hint budgets hold on every cell.
#[test]
fn sync_budget_matrix_payload_redundancy_and_hint_traffic() {
  // (nodes, batch per tick, ticks, reconnect)
  let cells: [(usize, usize, usize, bool); 6] = [
    (8, 1, 12, false),
    (8, 16, 6, false),
    (8, 1, 20, true),
    (64, 1, 12, false),
    (64, 16, 6, false),
    (256, 1, 12, false),
  ];
  let mut report = String::new();
  let mut failures = Vec::new();
  for (nodes, batch, ticks, reconnect) in cells {
    let (redundancy, hint_per_change_edge, breakdown) = steady_cell(nodes, batch, ticks, reconnect);
    report.push_str(&format!(
      "n={nodes} batch={batch} reconnect={reconnect}: redundancy={redundancy:.3} \
       hint_per_change_edge={hint_per_change_edge:.1}B ({breakdown}); "
    ));
    if redundancy > REDUNDANCY_BOUND {
      failures.push(format!(
        "n={nodes} batch={batch} reconnect={reconnect}: payload redundancy {redundancy:.3} \
         exceeds {REDUNDANCY_BOUND}"
      ));
    }
    if hint_per_change_edge > HINT_BUDGET_BYTES as f64 {
      failures.push(format!(
        "n={nodes} batch={batch}: hint traffic {hint_per_change_edge:.1} bytes per change \
         per edge exceeds {HINT_BUDGET_BYTES}"
      ));
    }
  }
  assert!(
    failures.is_empty(),
    "sync budget matrix failures: {}; measurements: {report}",
    failures.join("; ")
  );
  // The lane's own measurement record: one line per run, matching the
  // benchmark lanes' reporting convention.
  eprintln!("sync budget matrix: {report}");
}

/// The loss matrix: under a deterministic 20% drop the full trigger
/// layer converges no slower than the eager-off baseline (the pre-R4
/// engine behavior) — eager-delta only ever adds a delivery
/// opportunity, never a dependency.
#[test]
fn sync_budget_loss_convergence_not_worse_than_baseline() {
  for (nodes, batch) in [(8_usize, 4_usize), (64, 16)] {
    let (full, baseline) = loss_cell(nodes, batch);
    eprintln!(
      "sync budget loss cell n={nodes} batch={batch}: full={full} ticks baseline={baseline} ticks"
    );
    assert!(
      full <= baseline,
      "n={nodes}: the full layer took {full} ticks against the baseline's {baseline}"
    );
  }
}
