//! The connection-degree maintenance plane: while the node's live
//! authenticated session count sits below its target degree, a periodic
//! tick dials uniformly random unconnected members from the active
//! member universe until the target is reached.
//!
//! Plane separation, deliberately narrow: the maintenance plane is
//! additive-only — it never prunes sessions, never gates functionality,
//! and never touches the zero-session case (the recovery plane's
//! high-frequency backoff owns a fully offline node). Its dials land as
//! ordinary caller-class edges, so the recovery plane's redundancy
//! pruning never fights the maintenance target. The degree gates only
//! the status query and this cadence; below target with at least one
//! session everything keeps working.

use std::collections::BTreeSet;

use tracing::debug;

use super::supervisor::{Supervisor, dial_member};
use crate::{Endpoint, Error, NodeId, Result};

/// The maintenance cadence: nothing while healthy; while below target,
/// one deficit-bounded batch of random dials per tick. Purely local
/// behavior — peers observe dials, never the cadence — so unlike the
/// peer-visible timing constants this period is not a cluster-wide
/// contract.
pub(super) const DEGREE_MAINTENANCE_TICK_PERIOD: std::time::Duration =
  std::time::Duration::from_secs(30);

impl Supervisor {
  /// One maintenance tick: recompute the degree plan from the active
  /// member universe and the live session table, and dial the deficit
  /// in detached tasks (each bounded by the configured dial deadline
  /// plus the authentication deadline, reconciled by the next tick).
  /// A skipped or failed dial simply waits for the next tick — the
  /// plane is best-effort by contract.
  pub(super) async fn maintenance_tick(&mut self) -> Result<()> {
    let context = self.context()?;
    let store = context.store();
    let members = self.known_online_members(store).await?;
    let connected: BTreeSet<NodeId> = self
      .dependencies
      .sessions
      .lock()
      .map_err(Error::session_table)?
      .iter()
      .filter(|(_, entry)| entry.alive())
      .map(|(peer, _)| peer.clone())
      .collect();
    // The cluster size includes this node; the universe map excludes it.
    let plan = crate::membership::degree::degree_plan(
      members.len().saturating_add(1),
      self.dependencies.config.connection_degree(),
      connected.len(),
    );
    if plan.dial_budget == 0 {
      // Healthy, fully offline (recovery owns it), or nothing to reach.
      return Ok(());
    }
    // Previous tick's dials may still be in flight (dial deadline plus
    // authentication deadline exceeds one cadence): never exceed the
    // deficit with concurrent dials, or a slow mesh doubles its own
    // dial load every tick.
    if self
      .maintenance_pending
      .load(std::sync::atomic::Ordering::Relaxed)
      >= plan.dial_budget
    {
      debug!(
        pending = self
          .maintenance_pending
          .load(std::sync::atomic::Ordering::Relaxed),
        budget = plan.dial_budget,
        "degree maintenance tick deferred: dials in flight"
      );
      return Ok(());
    }
    let local = context.identity().node().clone();
    let dials = crate::membership::degree::select_degree_dials(
      plan.dial_budget,
      &local,
      &members,
      &connected,
      self.dependencies.entropy.as_ref(),
    )?;
    for (peer, endpoint) in dials {
      self.spawn_maintenance_dial(peer, endpoint);
    }
    Ok(())
  }

  /// Spawns one detached maintenance dial: the supervisor select loop
  /// never blocks on a handshake, and the in-flight slot releases when
  /// the dial resolves (success, refusal, or deadline).
  fn spawn_maintenance_dial(&mut self, peer: NodeId, receiver: Endpoint) {
    let transport = match self
      .dependencies
      .extensions
      .resolve_transport(&receiver.selector())
    {
      Ok(transport) => transport,
      // No transport for the endpoint: the dial cannot even start; the
      // next tick picks again (possibly the same member).
      Err(error) => {
        debug!(
          peer = %peer.as_str(),
          endpoint = %receiver.as_str(),
          kind = ?error.kind(),
          "degree maintenance dial unresolvable"
        );
        return;
      }
    };
    self
      .maintenance_pending
      .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let pending = std::sync::Arc::clone(&self.maintenance_pending);
    let driver = self.driver.clone();
    let sessions = self.dependencies.sessions.clone();
    let packet = self.packet.clone();
    let shutdown = self.shutdown_tx.subscribe();
    let dial_deadline = self.dependencies.config.dial_deadline();
    tokio::spawn(async move {
      if let Err(error) = dial_member(
        transport,
        driver,
        sessions,
        packet,
        shutdown,
        receiver,
        &peer,
        // Ordinary caller-class edge: the recovery plane's redundancy
        // pruning never reclaims a maintenance edge (additive-only).
        false,
        dial_deadline,
      )
      .await
      {
        debug!(
          peer = %peer.as_str(),
          kind = ?error.kind(),
          "degree maintenance dial failed"
        );
      }
      pending.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    });
  }

  /// The public connection-degree observation: the effective target,
  /// the live session count, and the resulting health. Recomputed from
  /// the stores per query (the same bounded scan the recovery tick
  /// runs every two seconds), so an operator's read never trails a
  /// membership change by more than the store itself.
  pub(super) async fn connection_degree_view(&self) -> Result<crate::ConnectionDegreeView> {
    let context = self.context()?;
    let members = self.known_online_members(context.store()).await?;
    let sessions = self
      .dependencies
      .sessions
      .lock()
      .map_err(Error::session_table)?
      .values()
      .filter(|entry| entry.alive())
      .count();
    let plan = crate::membership::degree::degree_plan(
      members.len().saturating_add(1),
      self.dependencies.config.connection_degree(),
      sessions,
    );
    Ok(crate::ConnectionDegreeView::new(
      plan.state,
      sessions,
      plan.target,
    ))
  }
}

#[cfg(test)]
mod tests {
  use std::sync::Arc;

  use tokio::sync::{mpsc, watch};

  use super::{DEGREE_MAINTENANCE_TICK_PERIOD, Supervisor};
  use crate::{
    NodeConfig,
    extension_registry::ExtensionRegistry,
    identity::{
      lifecycle::open_local_identity,
      records::{IdentityBindingV1, identity_binding_key},
      testing::{ScriptedKeys, SequenceEntropy, inject_entry},
    },
    protocol::{feature, offer::node_offer},
    provider::StorageFactory,
    runtime::RuntimeDependencies,
    session::stream::{SessionEntry, SessionTable},
    storage::contract::{ReferenceFactory, required_capabilities},
  };

  /// Builds a supervisor over a fresh in-memory identity: no sessions,
  /// no listeners — the maintenance tick runs against a real store.
  async fn maintenance_supervisor() -> (
    Supervisor,
    Arc<ReferenceFactory>,
    Arc<dyn crate::api::Entropy>,
    SessionTable,
  ) {
    let reference = Arc::new(ReferenceFactory::new(required_capabilities()));
    let factory: Arc<dyn StorageFactory> = reference.clone();
    let keys = ScriptedKeys::full();
    let entropy: Arc<dyn crate::api::Entropy> = Arc::new(SequenceEntropy::default());
    let context = Arc::new(
      open_local_identity(
        &factory,
        Some(&keys.as_provider()),
        entropy.as_ref(),
        std::time::Duration::from_secs(3_600),
      )
      .await
      .unwrap(),
    );
    // A dial deadline long enough that the tick's detached dials stay in
    // flight while the test observes them: they stall in the TLS
    // handshake against the held silent listener below.
    let config = NodeConfig::new()
      .with_dial_deadline(std::time::Duration::from_secs(2))
      .unwrap();
    let mut extensions = ExtensionRegistry::new();
    // The built-in transports the node builder installs: the tick
    // resolves the members' wss endpoints through this registry.
    for (tag, transport) in [
      (
        crate::transport::tls_transport::TlsTransport::tag().unwrap(),
        Arc::new(crate::transport::tls_transport::TlsTransport::new())
          as Arc<dyn crate::transport::registry::Transport>,
      ),
      (
        crate::transport::wss::WssTransport::tag().unwrap(),
        Arc::new(crate::transport::wss::WssTransport::new())
          as Arc<dyn crate::transport::registry::Transport>,
      ),
      (
        crate::transport::plain::PlainTransport::tag().unwrap(),
        Arc::new(crate::transport::plain::PlainTransport::new())
          as Arc<dyn crate::transport::registry::Transport>,
      ),
    ] {
      extensions
        .register_builtin_transport(tag, transport)
        .unwrap();
    }
    let mut definitions = feature::builtin_definitions().unwrap();
    definitions.extend(extensions.feature_definitions());
    let registry = feature::FeatureRegistry::build(definitions).unwrap();
    let offer = node_offer(&registry, config.required_features()).unwrap();
    let (round_tx, round_rx) = mpsc::channel(crate::runtime::SYNC_ROUND_CHANNEL_CAPACITY);
    let (revision_tx, _revision_rx) = watch::channel(0_u64);
    let (packet_tx, _packet_rx) = mpsc::channel(crate::runtime::PACKET_CHANNEL_CAPACITY);
    let sessions: SessionTable = Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::new()));
    let dependencies = RuntimeDependencies {
      storage_factory: factory,
      context: Some(context),
      keys: Some(keys),
      config,
      entropy: entropy.clone(),
      extensions: Arc::new(extensions),
      sessions: sessions.clone(),
      routes: Default::default(),
      events: Arc::new(crate::node::EventHub::new()),
      member_revision: crate::node::MemberRevisionSignal::new(revision_tx),
      leave_applied: crate::membership::sync::LeaveAppliedSignal::new(),
      sync_round_requests: round_tx,
      connection_tasks: Arc::new(std::sync::Mutex::new(Vec::new())),
      runtime_seed: None,
    };
    let supervisor = match Supervisor::new(dependencies, packet_tx, round_rx, offer) {
      Ok(supervisor) => supervisor,
      Err(boxed) => panic!("supervisor construction failed: {}", boxed.0),
    };
    (supervisor, reference, entropy, sessions)
  }

  fn member_id(seed: u64) -> crate::NodeId {
    crate::NodeId::parse(&format!("node-{seed:021}")).unwrap()
  }

  fn member_key(seed: u64) -> crate::PublicKey {
    let signing = crate::identity::testing::scripted_signing(seed);
    crate::PublicKey::from_bytes(signing.verifying_key().to_bytes())
  }

  /// Installs one active member: trusted binding (injected) plus
  /// descriptor (committed through the store path) with one silently
  /// held endpoint, so the member universe counts it and any dial to it
  /// stalls in flight instead of failing before the test can observe it.
  async fn install_member(
    supervisor: &Supervisor, reference: &Arc<ReferenceFactory>, seed: u64, port: u16,
  ) {
    let node = member_id(seed);
    let descriptor = crate::membership::NodeDescriptorV1::new(
      node.clone(),
      member_key(seed),
      vec![crate::Endpoint::parse(&format!("wss://127.0.0.1:{port}")).unwrap()],
      1,
      false,
      1,
    );
    crate::membership::store::store_descriptor_ctx(
      supervisor.context().unwrap().store(),
      supervisor.dependencies.entropy.as_ref(),
      &descriptor,
    )
    .await
    .unwrap();
    let (namespace, key) = identity_binding_key(&node).unwrap();
    let binding = IdentityBindingV1::new(node, member_key(seed));
    inject_entry(reference, (namespace, key), binding.encode().unwrap());
  }

  /// Inserts one live session entry for `peer` into the table: a
  /// synthetic entry is enough — the tick only reads liveness.
  fn insert_live_session(
    sessions: &SessionTable, peer: crate::NodeId, entropy: &dyn crate::api::Entropy,
  ) {
    let entry = SessionEntry::synthetic_entry(
      entropy,
      crate::Endpoint::parse("wss://127.0.0.1:1").unwrap(),
    )
    .unwrap();
    sessions.lock().unwrap().insert(peer, entry);
  }

  /// A silent TCP peer: accepts every connection and holds it open, so a
  /// wss dial stalls in the TLS handshake until its deadline. The tick's
  /// in-flight slots are then observable deterministically instead of
  /// racing a connection-refused failure.
  async fn silent_peer() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let held: Arc<std::sync::Mutex<Vec<tokio::net::TcpStream>>> =
      Arc::new(std::sync::Mutex::new(Vec::new()));
    let handle = tokio::spawn(async move {
      while let Ok((stream, _)) = listener.accept().await {
        // Holding the socket is the point: dropping it would reset the
        // connection and fail the dial early.
        held.lock().unwrap().push(stream);
      }
    });
    (port, handle)
  }

  /// The maintenance tick's wiring: with one live session and four
  /// dialable members, the derived plan for five nodes is k(5) = 3, so
  /// the tick dials the deficit of two in detached tasks (observed as
  /// in-flight slots), the status view reports the same plan, and the
  /// slots release once the dials hit their deadline. With zero sessions
  /// the tick must defer to the recovery plane.
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn maintenance_tick_dials_the_deficit_and_defers_when_offline() {
    let (mut supervisor, reference, entropy, sessions) = maintenance_supervisor().await;
    let (port, holder) = silent_peer().await;

    // Four active members (seeds offset above the supervisor's own
    // deterministic identity space): the cluster size is five
    // including self.
    for seed in 101..=104 {
      install_member(&supervisor, &reference, seed, port).await;
    }

    // Fully offline: the recovery plane owns the zero-session case.
    supervisor.maintenance_tick().await.unwrap();
    assert_eq!(
      supervisor
        .maintenance_pending
        .load(std::sync::atomic::Ordering::Relaxed),
      0,
      "a fully offline node must defer to the recovery plane"
    );
    let view = supervisor.connection_degree_view().await.unwrap();
    assert_eq!(view.sessions(), 0);
    assert_eq!(view.target(), 3, "k(5) = 3 from the shipped degree table");
    assert_eq!(view.state(), crate::ConnectionDegreeState::Unhealthy);

    // One live session: the deficit is two, dialed immediately and kept
    // in flight by the silent peer, so the slot count is deterministic.
    insert_live_session(&sessions, member_id(101), entropy.as_ref());
    supervisor.maintenance_tick().await.unwrap();
    let pending = supervisor
      .maintenance_pending
      .load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(pending, 2, "the tick dials exactly the deficit");
    let view = supervisor.connection_degree_view().await.unwrap();
    assert_eq!(view.sessions(), 1);
    assert_eq!(view.state(), crate::ConnectionDegreeState::Unhealthy);

    // The slots release when the dials hit their deadline, so a later
    // tick can dial again instead of piling up in-flight work.
    tokio::time::timeout(std::time::Duration::from_secs(6), async {
      loop {
        if supervisor
          .maintenance_pending
          .load(std::sync::atomic::Ordering::Relaxed)
          == 0
        {
          break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
      }
    })
    .await
    .expect("the expired dials must release their in-flight slots");
    holder.abort();
  }

  /// The maintenance cadence stays purely local (never a cluster-wide
  /// contract): pinned so a future recalibration is a deliberate act.
  #[test]
  fn maintenance_cadence_is_thirty_seconds() {
    assert_eq!(
      DEGREE_MAINTENANCE_TICK_PERIOD,
      std::time::Duration::from_secs(30)
    );
  }
}
