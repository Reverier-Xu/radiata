//! The declarative operation surface: task lifecycle phases, retries,
//! coalescing, shutdown cancellation, the `tasks()` accessor semantics,
//! `TaskChanged` events, custom kinds with a registered reconciler, the
//! resource-hook seam (ordering, error semantics, panic isolation), and
//! the once-only credential delivery.

use std::{
  collections::VecDeque,
  sync::{Arc, Mutex},
  time::Duration,
};

use radiata::{
  ActionHook, BoxFuture, CustomTaskSpec, Endpoint, Error, ErrorKind, EventOptions, EventReceive,
  ExtensionRegistry, LabelKey, LabelSet, LabelValue, NodeBuilder, NodeConfig, NodeHandle, PageSpec,
  QualifiedTag, ReconcileContext, ReconcileDecision, ResourceHook, ResourceLabels, ResourceName,
  ResourceUri, ResourceWrite, Result, TaskChanged, TaskKind, TaskOutput, TaskPhase, TaskReconciler,
  TaskTransition,
  extension::{KeyProvider, StorageFactory},
};
use tokio::sync::watch;

mod common;

use common::{MemoryStorageFactory, ScriptedKeys};

const PROBE_KIND: &str = "example.org/tasks/v1/probe";
/// One scripted step of the probe reconciler.
#[derive(Clone, Copy, Debug)]
enum Step {
  /// Fails the attempt with the typed error.
  Fail,
  /// Parks the attempt until the shared release flips true.
  Park,
  /// Panics inside the reconcile attempt.
  Panic,
  /// Completes the attempt.
  Succeed,
}

/// Everything the tests observe of one probe reconciler: the attempt
/// contexts it received, in order.
#[derive(Debug, Default)]
struct ReconcilerLog {
  contexts: Mutex<Vec<(u32, Option<ErrorKind>)>>,
}

/// The scripted custom-kind reconciler: every attempt pops its step.
#[derive(Debug)]
struct ProbeReconciler {
  log: Arc<ReconcilerLog>,
  script: Mutex<VecDeque<Step>>,
  release: watch::Receiver<bool>,
}

impl ProbeReconciler {
  fn new(log: Arc<ReconcilerLog>, script: Vec<Step>, release: watch::Receiver<bool>) -> Arc<Self> {
    Arc::new(Self {
      log,
      script: Mutex::new(script.into()),
      release,
    })
  }
}

impl TaskReconciler for ProbeReconciler {
  fn reconcile<'a>(&'a self, ctx: ReconcileContext) -> BoxFuture<'a, Result<ReconcileDecision>> {
    let log = Arc::clone(&self.log);
    let step = self
      .script
      .lock()
      .unwrap()
      .pop_front()
      .unwrap_or(Step::Succeed);
    let mut release = self.release.clone();
    Box::pin(async move {
      log
        .contexts
        .lock()
        .unwrap()
        .push((ctx.attempt, ctx.last_error.map(|error| error.kind())));
      match step {
        // The extension schedule retries every error kind, so one
        // public constructor exercises the whole ladder.
        Step::Fail => Err(Error::caller("probe step")),
        Step::Park => {
          loop {
            if *release.borrow_and_update() {
              break;
            }
            if release.changed().await.is_err() {
              return Err(Error::caller("probe gate"));
            }
          }
          Ok(ReconcileDecision::Succeeded)
        }
        Step::Panic => panic!("scripted reconcile panic"),
        Step::Succeed => Ok(ReconcileDecision::Succeeded),
      }
    })
  }
}

/// Starts one isolated node with the given extension registry.
async fn start_node(seed: u64, extensions: ExtensionRegistry, config: NodeConfig) -> NodeHandle {
  let keys: Arc<dyn KeyProvider> = Arc::new(ScriptedKeys::full_at(7_000_000 + seed * 1_000));
  start_node_with_keys(keys, extensions, config).await
}

/// Starts one isolated node with the caller's key custody: the leave
/// regression below needs a provider whose delete actually applies
/// (`ScriptedKeys::delete` is deliberately the typed failure path).
async fn start_node_with_keys(
  keys: Arc<dyn KeyProvider>, extensions: ExtensionRegistry, config: NodeConfig,
) -> NodeHandle {
  let storage: Arc<dyn StorageFactory> =
    Arc::new(MemoryStorageFactory::new(common::required_capabilities()));
  NodeBuilder::new(storage)
    .keys(keys)
    .extensions(extensions)
    .config(config)
    .start()
    .await
    .unwrap()
}

fn probe_spec() -> CustomTaskSpec {
  CustomTaskSpec::new(
    QualifiedTag::parse(PROBE_KIND).unwrap(),
    LabelSet::new()
      .insert(
        LabelKey::parse("example.org/labels/lane").unwrap(),
        LabelValue::parse("tasks").unwrap(),
      )
      .unwrap(),
  )
}

/// Registers the scripted probe reconciler and returns its log plus the
/// release gate.
fn probe_extensions(
  script: Vec<Step>,
) -> (ExtensionRegistry, Arc<ReconcilerLog>, watch::Sender<bool>) {
  let (release, receiver) = watch::channel(false);
  let log = Arc::new(ReconcilerLog::default());
  let mut extensions = ExtensionRegistry::new();
  extensions
    .register_task_reconciler(
      QualifiedTag::parse(PROBE_KIND).unwrap(),
      ProbeReconciler::new(Arc::clone(&log), script, receiver),
    )
    .unwrap();
  (extensions, log, release)
}

/// Receives one event item with a bound, failing the test on lag or a
/// miss (the subscriptions are sized for the pinned sequences).
async fn next_changed(events: &mut radiata::EventSubscription<TaskChanged>) -> TaskChanged {
  match tokio::time::timeout(Duration::from_secs(30), events.recv())
    .await
    .unwrap()
    .unwrap()
  {
    EventReceive::Item(item) => item,
    EventReceive::Lagged { missed } => panic!("task event subscription lagged by {missed}"),
    EventReceive::Empty => panic!("task event stream returned empty from a pending recv"),
    EventReceive::Closed => panic!("task event stream closed before the pinned sequence"),
    _ => panic!("unexpected task event stream state"),
  }
}

/// The task phase machine over the public surface: admission publishes
/// `Pending` and the first spawn `Running`, the accessor observes the
/// live phases, and both wait forms are value-based once terminal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lifecycle_phases_and_value_based_waits() {
  common::init_tracing();
  let (extensions, _log, release) = probe_extensions(vec![Step::Park]);
  let node = start_node(1, extensions, NodeConfig::new()).await;
  let mut events = node.watch::<TaskChanged>(EventOptions::new()).unwrap();

  let task = node.tasks().submit(probe_spec()).await.unwrap();
  assert_eq!(
    task.kind(),
    &TaskKind::Extension(QualifiedTag::parse(PROBE_KIND).unwrap())
  );

  // Admission then the first spawn: exactly one event per transition.
  let pending = next_changed(&mut events).await;
  assert_eq!(pending.task(), task.id());
  assert_eq!(pending.phase(), TaskPhase::Pending);
  let running = next_changed(&mut events).await;
  assert_eq!(running.phase(), TaskPhase::Running);

  // The live snapshot through the accessor: one attempt spent, started
  // but not finished, no error, no output.
  let view = node.tasks().get(task.id().clone()).await.unwrap().unwrap();
  assert_eq!(view.phase(), TaskPhase::Running);
  assert_eq!(view.attempts(), 1);
  assert!(view.started().is_some());
  assert!(view.finished().is_none());
  assert!(view.error().is_none());
  assert!(view.output().is_none());
  let status = task.status();
  assert_eq!(status.phase(), TaskPhase::Running);
  assert_eq!(status.attempts(), 1);

  // Release the effect; the terminal publication lands before any wait.
  release.send(true).unwrap();
  let done = next_changed(&mut events).await;
  assert_eq!(done.phase(), TaskPhase::Succeeded);

  // Both wait forms resolve from an already-terminal state: the typed
  // handle delivers the verb output and the accessor the terminal view.
  let view = node.tasks().wait(task.id().clone()).await.unwrap();
  assert_eq!(view.phase(), TaskPhase::Succeeded);
  assert_eq!(view.output(), Some(&TaskOutput::Extension(())));
  assert!(view.finished().is_some());
  let clone = task.clone();
  clone.wait().await.unwrap();
  // The handle's local snapshot stays readable after the wait consumed
  // it: the phase and attempts are table state, not wait state.
  assert_eq!(task.status().phase(), TaskPhase::Succeeded);

  // Unknown ids: `get` distinguishes absence, `wait` is typed not-found.
  let unknown = radiata::TaskId::parse("task-00000000000000000009z").unwrap();
  assert!(node.tasks().get(unknown.clone()).await.unwrap().is_none());
  let missing = node.tasks().wait(unknown).await.unwrap_err();
  assert_eq!(missing.kind(), ErrorKind::NotFound);
  node.shutdown().await.unwrap();
}

/// A second admission while the first runs lists after it, in admission
/// (id) order, and the page cursor walks the same order.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn list_reports_admission_order_with_keyset_pages() {
  common::init_tracing();
  let (extensions, _log, _release) = probe_extensions(vec![Step::Succeed]);
  let node = start_node(2, extensions, NodeConfig::new()).await;
  let first = node.tasks().submit(probe_spec()).await.unwrap();
  first.clone().wait().await.unwrap();
  let second = node.tasks().submit(probe_spec()).await.unwrap();
  second.clone().wait().await.unwrap();
  assert!(second.id() > first.id(), "admission order must be id order");

  let page = node
    .tasks()
    .list(PageSpec::first(1).unwrap())
    .await
    .unwrap();
  assert_eq!(page.items().len(), 1);
  assert_eq!(page.items()[0].id(), first.id());
  let cursor = page.next().unwrap().clone();
  let rest = node
    .tasks()
    .list(PageSpec::after(cursor, 8).unwrap())
    .await
    .unwrap();
  assert_eq!(rest.items().len(), 1);
  assert_eq!(rest.items()[0].id(), second.id());
  assert!(rest.next().is_none());
  node.shutdown().await.unwrap();
}

/// The bounded retry schedule drives a failed attempt again: every wake
/// re-publishes `Running`, the attempt index climbs, and the previous
/// attempt's typed error rides the context.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn extension_retries_republish_running_with_the_last_error() {
  common::init_tracing();
  let (extensions, log, _release) = probe_extensions(vec![Step::Fail, Step::Fail, Step::Succeed]);
  let node = start_node(3, extensions, NodeConfig::new()).await;
  let mut events = node.watch::<TaskChanged>(EventOptions::new()).unwrap();

  let task = node.tasks().submit(probe_spec()).await.unwrap();
  task.clone().wait().await.unwrap();

  // Pending, three running wakes (one per attempt), then the terminal.
  let phases = [
    next_changed(&mut events).await,
    next_changed(&mut events).await,
    next_changed(&mut events).await,
    next_changed(&mut events).await,
    next_changed(&mut events).await,
  ]
  .map(|event| event.phase());
  assert_eq!(
    phases,
    [
      TaskPhase::Pending,
      TaskPhase::Running,
      TaskPhase::Running,
      TaskPhase::Running,
      TaskPhase::Succeeded
    ]
  );
  // The contexts: the first attempt has no predecessor error, every
  // later attempt carries the previous typed failure.
  assert_eq!(
    *log.contexts.lock().unwrap(),
    vec![
      (1, None),
      (2, Some(ErrorKind::CallerError)),
      (3, Some(ErrorKind::CallerError))
    ]
  );
  let view = node.tasks().get(task.id().clone()).await.unwrap().unwrap();
  assert_eq!(view.attempts(), 3);
  node.shutdown().await.unwrap();
}

/// Exhausting the bounded schedule terminalizes the task with the last
/// typed error; nothing retries past the bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn extension_exhaustion_fails_with_the_last_error() {
  common::init_tracing();
  let (extensions, _log, _release) =
    probe_extensions(vec![Step::Fail, Step::Fail, Step::Fail, Step::Fail]);
  let node = start_node(4, extensions, NodeConfig::new()).await;
  let task = node.tasks().submit(probe_spec()).await.unwrap();
  let error = task.clone().wait().await.unwrap_err();
  assert_eq!(error.kind(), ErrorKind::CallerError);
  let view = node.tasks().get(task.id().clone()).await.unwrap().unwrap();
  assert_eq!(view.phase(), TaskPhase::Failed);
  assert_eq!(view.attempts(), 4);
  assert_eq!(view.error().unwrap().kind(), ErrorKind::CallerError);
  node.shutdown().await.unwrap();
}

/// A panic inside one reconcile attempt terminalizes the task typed and
/// leaves the node serving.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reconciler_panic_fails_the_task_and_keeps_the_node_serving() {
  common::init_tracing();
  let (extensions, _log, _release) = probe_extensions(vec![Step::Panic]);
  let node = start_node(5, extensions, NodeConfig::new()).await;
  let task = node.tasks().submit(probe_spec()).await.unwrap();
  let error = task.clone().wait().await.unwrap_err();
  assert_eq!(error.kind(), ErrorKind::Internal);
  assert_eq!(error.context(), "reconciler panicked");
  let view = node.tasks().get(task.id().clone()).await.unwrap().unwrap();
  assert_eq!(view.phase(), TaskPhase::Failed);
  assert_eq!(view.error().unwrap().as_str(), "reconciler panicked");
  // The node itself is unaffected: reads keep answering.
  node
    .members()
    .list(PageSpec::first(8).unwrap())
    .await
    .unwrap();
  node.shutdown().await.unwrap();
}

/// Shutdown cancels in-flight tasks: the cancellable extension kind
/// exits mid-flight, its waits fail typed, and the shutdown completes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shutdown_cancels_in_flight_tasks_and_fails_waits_typed() {
  common::init_tracing();
  let (extensions, _log, _release) = probe_extensions(vec![Step::Park]);
  let node = start_node(6, extensions, NodeConfig::new()).await;
  let task = node.tasks().submit(probe_spec()).await.unwrap();

  // Two waiters: the typed handle and the accessor.
  let handle_wait = {
    let task = task.clone();
    tokio::spawn(async move { task.wait().await })
  };
  let accessor_wait = {
    let tasks = node.tasks();
    let id = task.id().clone();
    tokio::spawn(async move { tasks.wait(id).await })
  };
  // Let both waiters register before the shutdown race starts.
  tokio::time::sleep(Duration::from_millis(50)).await;

  let outcome = node.shutdown().await.unwrap();
  assert_eq!(*outcome.reason(), radiata::ShutdownReason::Explicit);
  let error = handle_wait.await.unwrap().unwrap_err();
  assert_eq!(error.kind(), ErrorKind::ShuttingDown);
  let error = accessor_wait.await.unwrap().unwrap_err();
  assert_eq!(error.kind(), ErrorKind::ShuttingDown);
  // Post-shutdown accessor reads refuse typed (the table's state after
  // the stop is not part of the contract).
  let refused = node.tasks().get(task.id().clone()).await.unwrap_err();
  assert_eq!(refused.kind(), ErrorKind::ShuttingDown);
}

/// The bounded terminal history evicts oldest-terminal first: an evicted
/// id reads absent through `get`, typed not-found through `wait`, and as
/// a fresh admission snapshot through the handle's `status`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn terminal_history_eviction_shapes_get_wait_and_status() {
  common::init_tracing();
  let (extensions, _log, _release) = probe_extensions(vec![Step::Succeed]);
  let node = start_node(7, extensions, NodeConfig::new()).await;
  // The retained bound is 256 terminal tasks; 300 admissions push the
  // first 44 past it.
  let first = node.tasks().submit(probe_spec()).await.unwrap();
  first.clone().wait().await.unwrap();
  for _ in 1..300 {
    node.tasks().submit(probe_spec()).await.unwrap();
  }
  let last = node.tasks().submit(probe_spec()).await.unwrap();
  last.clone().wait().await.unwrap();

  assert!(
    node
      .tasks()
      .get(first.id().clone())
      .await
      .unwrap()
      .is_none()
  );
  let evicted = node.tasks().wait(first.id().clone()).await.unwrap_err();
  assert_eq!(evicted.kind(), ErrorKind::NotFound);
  let status = first.status();
  assert_eq!(status.phase(), TaskPhase::Pending);
  assert_eq!(status.attempts(), 0);
  let view = node.tasks().get(last.id().clone()).await.unwrap().unwrap();
  assert_eq!(view.phase(), TaskPhase::Succeeded);
  node.shutdown().await.unwrap();
}

/// The issued credential secret is delivered exactly once: the typed
/// handle is the only carrier of the secret (a credential task is
/// deliberately not cloneable — the amendment's once-only slot), the
/// accessor's wait and views observe only the expiry, and the handle's
/// local snapshot stays readable after the delivery. The typed
/// second-wait refusal is pinned next to the task model itself
/// (`src/task/mod.rs`, `credential_secret_is_collected_exactly_once`)
/// because a second handle cannot exist for this kind.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn credential_secret_is_delivered_exactly_once() {
  common::init_tracing();
  let node = start_node(8, ExtensionRegistry::new(), NodeConfig::new()).await;

  let task = node.credentials().issue().await.unwrap();
  // The accessor wait never touches the secret slot: it resolves with
  // the terminal view carrying the expiry observation only.
  let view = node.tasks().wait(task.id().clone()).await.unwrap();
  assert_eq!(view.phase(), TaskPhase::Succeeded);
  let TaskOutput::IssueCredential(observed) = view.output().unwrap() else {
    panic!("credential task must carry the expiry observation");
  };
  assert!(observed.expires_at() > std::time::SystemTime::now());

  // The single typed wait collects the secret; the table keeps only the
  // observation afterwards.
  let task_id = task.id().clone();
  let issued = task.wait().await.unwrap();
  assert_eq!(issued.expires_at(), observed.expires_at());
  assert!(!issued.credential().expose_secret().is_empty());
  let view = node.tasks().get(task_id).await.unwrap().unwrap();
  assert!(matches!(
    view.output(),
    Some(TaskOutput::IssueCredential(later)) if later.expires_at() == observed.expires_at()
  ));
  node.shutdown().await.unwrap();
}

/// A silent peer wedges the connect dial: identical in-flight
/// submissions coalesce onto the one task, and a different intent
/// conflicts at admission.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_coalesces_identical_in_flight_submissions() {
  common::init_tracing();
  let silent = silent_peer().await;
  let config = NodeConfig::new()
    .with_dial_deadline(Duration::from_secs(8))
    .unwrap();
  let node = start_node(9, ExtensionRegistry::new(), config).await;
  let endpoint = Endpoint::parse(&format!("wss://127.0.0.1:{}", silent.port)).unwrap();
  let peer = node.local_node().await.unwrap().node_id().clone();

  let first = node.connect(endpoint.clone(), peer.clone()).await.unwrap();
  // The dial cannot settle within the scheduling slice, so the task is
  // still in flight: the identical intent joins it, a different one
  // conflicts at admission.
  let view = node.tasks().get(first.id().clone()).await.unwrap().unwrap();
  assert!(
    !view.phase().is_terminal(),
    "the dial must still be in flight"
  );
  let joined = node.connect(endpoint.clone(), peer.clone()).await.unwrap();
  assert_eq!(joined.id(), first.id());
  assert_eq!(joined.kind(), &TaskKind::Connect);
  // A distinct endpoint is a different intent for the same subject:
  // admission refuses it instead of smuggling it onto the dial.
  let other = Endpoint::parse(&format!("wss://127.0.0.1:{}", silent.port + 1)).unwrap();
  let conflict = node.connect(other, peer).await.unwrap_err();
  assert_eq!(conflict.kind(), ErrorKind::Conflict);
  assert_eq!(conflict.context(), "task in flight");

  // Shutdown cancels the wedged dial instead of waiting it out.
  node.shutdown().await.unwrap();
  silent.holder.abort();
}

/// One in-flight pair: the silent listener plus the task holding it.
struct SilentPeer {
  port: u16,
  holder: tokio::task::JoinHandle<()>,
}

/// The silent-peer fixture from the supervisor's dial-deadline tests:
/// accepts the TCP connection and then never speaks, so the TLS
/// handshake stalls until the configured deadline.
async fn silent_peer() -> SilentPeer {
  let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let port = listener.local_addr().unwrap().port();
  let holder = tokio::spawn(async move {
    let (_held, _) = listener.accept().await.unwrap();
    // Hold the socket open without ever speaking TLS.
    tokio::time::sleep(Duration::from_secs(30)).await;
  });
  SilentPeer { port, holder }
}

/// A builtin network kind retries on the retryable not-found: a connect
/// to a bound listener for a peer whose binding has not spread spends
/// the whole four-attempt schedule and fails typed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn builtin_connect_retries_the_unspread_binding_then_fails_typed() {
  common::init_tracing();
  let issuer = start_node(10, ExtensionRegistry::new(), NodeConfig::new()).await;
  let stranger = start_node(11, ExtensionRegistry::new(), NodeConfig::new()).await;
  let member = start_node(12, ExtensionRegistry::new(), NodeConfig::new()).await;

  let issued = issuer
    .credentials()
    .rotate()
    .await
    .unwrap()
    .wait()
    .await
    .unwrap();
  let _secret = issued.credential().expose_secret().to_owned();
  let listener = issuer
    .listeners()
    .create(Endpoint::parse("wss://127.0.0.1:0").unwrap())
    .await
    .unwrap()
    .wait()
    .await
    .unwrap();
  common::merge_with_retry(&member, &issuer, listener.endpoint().clone()).await;

  // The stranger never merged, so its binding never spread to the
  // member: every attempt finds not-found against the live listener.
  let stranger_id = stranger.local_node().await.unwrap().node_id().clone();
  let task = member
    .connect(listener.endpoint().clone(), stranger_id)
    .await
    .unwrap();
  let error = task.clone().wait().await.unwrap_err();
  assert_eq!(error.kind(), ErrorKind::NotFound);
  let view = member
    .tasks()
    .get(task.id().clone())
    .await
    .unwrap()
    .unwrap();
  assert_eq!(view.attempts(), 4, "the whole network schedule is spent");

  member.shutdown().await.unwrap();
  stranger.shutdown().await.unwrap();
  issuer.shutdown().await.unwrap();
}

/// A probe hook recording its calls: the shared log every hook flavor
/// writes into.
#[derive(Debug, Default)]
struct HookLog {
  calls: Mutex<Vec<&'static str>>,
}

impl HookLog {
  fn record(&self, call: &'static str) {
    self.calls.lock().unwrap().push(call);
  }

  fn calls(&self) -> Vec<&'static str> {
    self.calls.lock().unwrap().clone()
  }
}

/// One resource hook flavor per behavior under test, all keyed by their
/// registration tag (the tag order is the hook order).
#[derive(Debug)]
enum ProbeResourceHook {
  /// Records `validate`/`mutate`/`observed` calls in the shared log.
  Recording { log: Arc<HookLog> },
  /// Rejects at admission with the typed error.
  Rejecting,
  /// Panics inside `validate`.
  Panicking,
  /// Fails `observed` (the diagnostic path).
  FailingObserved { log: Arc<HookLog> },
}

impl ResourceHook for ProbeResourceHook {
  fn validate(&self, write: &ResourceWrite) -> Result<()> {
    match self {
      Self::Recording { log } => {
        log.record("validate");
        // Validate observes the caller's intent before any mutation.
        assert!(!write.name().as_str().is_empty());
        Ok(())
      }
      Self::Rejecting => Err(Error::caller("probe hook rejected")),
      Self::Panicking => panic!("scripted validate panic"),
      Self::FailingObserved { .. } => Ok(()),
    }
  }

  fn mutate(&self, write: ResourceWrite) -> Result<ResourceWrite> {
    match self {
      Self::Recording { log } => {
        log.record("mutate");
        Ok(write)
      }
      _ => Ok(write),
    }
  }

  fn observed<'a>(&'a self, view: &'a radiata::ResourceView) -> BoxFuture<'a, Result<()>> {
    match self {
      Self::Recording { log } => {
        log.record("observed");
        let _ = view.name();
        Box::pin(async { Ok(()) })
      }
      Self::FailingObserved { log } => {
        log.record("observed-error");
        Box::pin(async { Err(Error::caller("probe observation")) })
      }
      _ => Box::pin(async { Ok(()) }),
    }
  }
}

fn resource_write(seed: u8) -> ResourceWrite {
  ResourceWrite::new(
    ResourceName::parse(&format!("example.org/resources/tasks-{seed:03}")).unwrap(),
    ResourceLabels::new(
      LabelValue::parse("document").unwrap(),
      ResourceUri::parse(&format!("file:///tasks/{seed:03}")).unwrap(),
    ),
  )
}

/// Hooks compose at admission in canonical tag order — every `validate`
/// before any `mutate` — and `observed` fires after the local commit,
/// in the same order, from its own spawned observation task (so the
/// recorded observations are polled to their final shape: the task's
/// terminal publication deliberately precedes them).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resource_hooks_compose_in_tag_order_and_observe_after_commit() {
  common::init_tracing();
  let log = Arc::new(HookLog::default());
  let mut extensions = ExtensionRegistry::new();
  extensions
    .register_resource_hook(
      QualifiedTag::parse("a.example.org/hooks/v1/first").unwrap(),
      Arc::new(ProbeResourceHook::Recording {
        log: Arc::clone(&log),
      }),
    )
    .unwrap()
    .register_resource_hook(
      QualifiedTag::parse("b.example.org/hooks/v1/second").unwrap(),
      Arc::new(ProbeResourceHook::Recording {
        log: Arc::clone(&log),
      }),
    )
    .unwrap();
  let node = start_node(13, extensions, NodeConfig::new()).await;

  let task = node.resources().put(resource_write(1)).await.unwrap();
  task.wait().await.unwrap();

  let expected = [
    "validate", "validate", "mutate", "mutate", "observed", "observed",
  ];
  let deadline = std::time::Instant::now() + Duration::from_secs(5);
  loop {
    let calls = log.calls();
    if calls == expected {
      break;
    }
    assert!(
      std::time::Instant::now() < deadline,
      "hook calls never reached {expected:?}: {calls:?}"
    );
    tokio::time::sleep(Duration::from_millis(5)).await;
  }
  // The committed record is the catalog's winner.
  let view = node
    .resources()
    .get(ResourceName::parse("example.org/resources/tasks-001").unwrap())
    .await
    .unwrap()
    .unwrap();
  assert_eq!(view.labels().resource_type().as_str(), "document");
  node.shutdown().await.unwrap();
}

/// A hook rejection fails the verb at admission — synchronously, before
/// any task exists — and nothing reaches the catalog.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resource_hook_rejection_fails_admission_typed() {
  common::init_tracing();
  let mut extensions = ExtensionRegistry::new();
  extensions
    .register_resource_hook(
      QualifiedTag::parse("a.example.org/hooks/v1/guard").unwrap(),
      Arc::new(ProbeResourceHook::Rejecting),
    )
    .unwrap();
  let node = start_node(14, extensions, NodeConfig::new()).await;

  let error = node.resources().put(resource_write(2)).await.unwrap_err();
  assert_eq!(error.kind(), ErrorKind::CallerError);
  assert_eq!(error.context(), "probe hook rejected");
  // Nothing was admitted: the task table holds no put task and the
  // catalog holds no record.
  let page = node
    .tasks()
    .list(PageSpec::first(8).unwrap())
    .await
    .unwrap();
  assert!(page.items().is_empty());
  let catalog = node
    .resources()
    .get(ResourceName::parse("example.org/resources/tasks-002").unwrap())
    .await
    .unwrap();
  assert!(catalog.is_none());
  node.shutdown().await.unwrap();
}

/// An `observed` error is a diagnostic only: the task still succeeds
/// and the commit stands, because observers can never fail a task.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resource_hook_observed_error_is_diagnostic_only() {
  common::init_tracing();
  let log = Arc::new(HookLog::default());
  let mut extensions = ExtensionRegistry::new();
  extensions
    .register_resource_hook(
      QualifiedTag::parse("a.example.org/hooks/v1/observer").unwrap(),
      Arc::new(ProbeResourceHook::FailingObserved {
        log: Arc::clone(&log),
      }),
    )
    .unwrap();
  let node = start_node(15, extensions, NodeConfig::new()).await;

  let task = node.resources().put(resource_write(3)).await.unwrap();
  task.wait().await.unwrap();
  // The observation runs in its own spawned task after the terminal
  // publication, so its diagnostic is polled for, never assumed.
  let deadline = std::time::Instant::now() + Duration::from_secs(5);
  while log.calls().is_empty() {
    assert!(
      std::time::Instant::now() < deadline,
      "the observer never ran"
    );
    tokio::time::sleep(Duration::from_millis(5)).await;
  }
  assert_eq!(log.calls(), ["observed-error"]);
  let view = node
    .resources()
    .get(ResourceName::parse("example.org/resources/tasks-003").unwrap())
    .await
    .unwrap();
  assert!(
    view.is_some(),
    "the commit stands despite the observer error"
  );
  node.shutdown().await.unwrap();
}

/// A panicking admission hook aborts the caller's future only: the node
/// keeps serving reads and the catalog stays empty.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn panicking_admission_hook_isolates_to_the_caller() {
  common::init_tracing();
  let mut extensions = ExtensionRegistry::new();
  extensions
    .register_resource_hook(
      QualifiedTag::parse("a.example.org/hooks/v1/panic").unwrap(),
      Arc::new(ProbeResourceHook::Panicking),
    )
    .unwrap();
  let node = start_node(16, extensions, NodeConfig::new()).await;
  let reader = node.clone();

  let put = tokio::spawn(async move {
    node
      .resources()
      .put(resource_write(4))
      .await
      .unwrap()
      .wait()
      .await
  });
  let panicked = put.await.unwrap_err();
  assert!(
    panicked.is_panic(),
    "the admission hook must abort the caller"
  );

  // The node survives the caller's panic: reads answer, the catalog has
  // no record, and the task table has no half-admitted task.
  reader
    .members()
    .list(PageSpec::first(8).unwrap())
    .await
    .unwrap();
  let catalog = reader
    .resources()
    .get(ResourceName::parse("example.org/resources/tasks-004").unwrap())
    .await
    .unwrap();
  assert!(catalog.is_none());
  reader.shutdown().await.unwrap();
}

/// One action-hook probe with selectable behavior per transition.
#[derive(Debug)]
enum ProbeActionHook {
  /// Fails every observation (the diagnostic path).
  Failing,
  /// Panics on the given target phase.
  Panicking { on: TaskPhase },
}

impl ActionHook for ProbeActionHook {
  fn on_transition<'a>(&'a self, transition: &'a TaskTransition) -> BoxFuture<'a, Result<()>> {
    match self {
      Self::Failing => Box::pin(async { Err(Error::caller("probe action")) }),
      Self::Panicking { on } => {
        if transition.to() == *on {
          panic!("scripted action hook panic");
        }
        Box::pin(async { Ok(()) })
      }
    }
  }
}

fn action_extensions(hook: ProbeActionHook) -> ExtensionRegistry {
  let mut extensions = ExtensionRegistry::new();
  extensions
    .register_action_hook(
      QualifiedTag::parse("a.example.org/hooks/v1/action").unwrap(),
      Arc::new(hook),
    )
    .unwrap();
  extensions
}

/// Action-hook errors are diagnostics: every transition is observed,
/// the task still succeeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn action_hook_error_is_diagnostic_only() {
  common::init_tracing();
  let extensions = action_extensions(ProbeActionHook::Failing);
  let (extensions, _log, _release) = with_probe_reconciler(extensions, vec![Step::Succeed]);
  let node = start_node(17, extensions, NodeConfig::new()).await;
  let task = node.tasks().submit(probe_spec()).await.unwrap();
  task.wait().await.unwrap();
  node.shutdown().await.unwrap();
}

/// An action hook panicking at the running transition is contained in
/// the observation task: the task still runs its effect to success, and
/// the node keeps serving. (The observation runs off the attempt body,
/// so an observer panic is a diagnostic, never the task's failure.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn action_hook_panic_at_running_is_contained_and_the_task_succeeds() {
  common::init_tracing();
  let extensions = action_extensions(ProbeActionHook::Panicking {
    on: TaskPhase::Running,
  });
  let (extensions, _log, _release) = with_probe_reconciler(extensions, vec![Step::Succeed]);
  let node = start_node(18, extensions, NodeConfig::new()).await;
  let task = node.tasks().submit(probe_spec()).await.unwrap();
  task.clone().wait().await.unwrap();
  let view = node.tasks().get(task.id().clone()).await.unwrap().unwrap();
  assert_eq!(view.phase(), TaskPhase::Succeeded);
  node
    .members()
    .list(PageSpec::first(8).unwrap())
    .await
    .unwrap();
  node.shutdown().await.unwrap();
}

/// An action hook panicking at the terminal observation cannot unseat
/// the terminal phase: the task stays succeeded (terminality is
/// monotone across a panicking hook).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn action_hook_panic_at_succeeded_keeps_the_terminal_phase() {
  common::init_tracing();
  let extensions = action_extensions(ProbeActionHook::Panicking {
    on: TaskPhase::Succeeded,
  });
  let (extensions, _log, _release) = with_probe_reconciler(extensions, vec![Step::Succeed]);
  let node = start_node(19, extensions, NodeConfig::new()).await;
  let task = node.tasks().submit(probe_spec()).await.unwrap();
  task.clone().wait().await.unwrap();
  let view = node.tasks().get(task.id().clone()).await.unwrap().unwrap();
  assert_eq!(view.phase(), TaskPhase::Succeeded);
  node.shutdown().await.unwrap();
}

/// An action hook that never settles: a wedged observer under test.
#[derive(Debug)]
struct WedgingActionHook;

impl ActionHook for WedgingActionHook {
  fn on_transition<'a>(&'a self, _transition: &'a TaskTransition) -> BoxFuture<'a, Result<()>> {
    Box::pin(std::future::pending())
  }
}

/// A deterministic key provider with working deletion, after the
/// facade's `LeaveCapableKeys` shape: the leave regression below runs a
/// full identity replacement, whose custody lane deletes the former
/// identity keys.
#[derive(Debug, Default)]
struct LeaveCapableKeys {
  records: std::sync::Mutex<std::collections::BTreeMap<Vec<u8>, ed25519_dalek::SigningKey>>,
  operations: std::sync::Mutex<std::collections::BTreeMap<Vec<u8>, Vec<u8>>>,
  next: std::sync::Mutex<u64>,
}

impl LeaveCapableKeys {
  fn seed_for(base: u64) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&base.to_le_bytes().repeat(4)[..32].try_into().unwrap())
  }

  fn create_at(&self, operation: &radiata::KeyOperationId) -> radiata::KeyCreateState {
    let mut operations = self.operations.lock().unwrap();
    if let Some(handle) = operations.get(operation.as_str().as_bytes()).cloned()
      && let Some(signing) = self.records.lock().unwrap().get(&handle).cloned()
    {
      return radiata::KeyCreateState::Present(radiata::CreatedKey::new(
        radiata::KeyHandle::from_provider_bytes(Arc::from(handle)).unwrap(),
        radiata::PublicKey::from_bytes(signing.verifying_key().to_bytes()),
      ));
    }
    let mut next = self.next.lock().unwrap();
    let index = *next;
    *next += 1;
    let signing = Self::seed_for(index + 1);
    let handle = format!("tasks-leave-handle-{index}").into_bytes();
    let created = radiata::CreatedKey::new(
      radiata::KeyHandle::from_provider_bytes(Arc::from(handle.clone())).unwrap(),
      radiata::PublicKey::from_bytes(signing.verifying_key().to_bytes()),
    );
    operations.insert(operation.as_str().as_bytes().to_vec(), handle.clone());
    self.records.lock().unwrap().insert(handle, signing);
    radiata::KeyCreateState::Present(created)
  }

  fn lookup(&self, operation: &radiata::KeyOperationId) -> Option<radiata::KeyCreateState> {
    let handle = self
      .operations
      .lock()
      .unwrap()
      .get(operation.as_str().as_bytes())?
      .clone();
    let signing = self.records.lock().unwrap().get(&handle).cloned()?;
    Some(radiata::KeyCreateState::Present(radiata::CreatedKey::new(
      radiata::KeyHandle::from_provider_bytes(Arc::from(handle)).unwrap(),
      radiata::PublicKey::from_bytes(signing.verifying_key().to_bytes()),
    )))
  }
}

impl KeyProvider for LeaveCapableKeys {
  fn capabilities(&self) -> radiata::KeyCapabilities {
    radiata::KeyCapabilities::new()
      .ed25519(true)
      .reconciliation(true)
      .deletion(true)
  }

  fn create_ed25519<'a>(
    &'a self, operation: &'a radiata::KeyOperationId,
  ) -> BoxFuture<'a, Result<radiata::KeyCreateState>> {
    let created = self.create_at(operation);
    Box::pin(async move { Ok(created) })
  }

  fn reconcile_create<'a>(
    &'a self, operation: &'a radiata::KeyOperationId,
  ) -> BoxFuture<'a, Result<radiata::KeyCreateState>> {
    let created = self.lookup(operation);
    Box::pin(async move { Ok(created.unwrap_or(radiata::KeyCreateState::Absent)) })
  }

  fn public_key<'a>(
    &'a self, handle: &'a radiata::KeyHandle,
  ) -> BoxFuture<'a, Result<radiata::PublicKey>> {
    let result = self
      .records
      .lock()
      .unwrap()
      .get(handle.expose_provider_handle())
      .map(|signing| radiata::PublicKey::from_bytes(signing.verifying_key().to_bytes()))
      .ok_or_else(|| {
        radiata::Error::provider(
          radiata::ProviderErrorKind::Internal,
          radiata::ProviderErrorContext::KeyPublicKey,
        )
      });
    Box::pin(async move { result })
  }

  fn sign<'a>(
    &'a self, handle: &'a radiata::KeyHandle, message: &'a [u8],
  ) -> BoxFuture<'a, Result<radiata::Signature>> {
    use ed25519_dalek::Signer as _;
    let result = self
      .records
      .lock()
      .unwrap()
      .get(handle.expose_provider_handle())
      .map(|signing| radiata::Signature::from_bytes(signing.sign(message).to_bytes()))
      .ok_or_else(|| {
        radiata::Error::provider(
          radiata::ProviderErrorKind::Internal,
          radiata::ProviderErrorContext::KeySign,
        )
      });
    Box::pin(async move { result })
  }

  fn delete<'a>(
    &'a self, _operation: &'a radiata::KeyOperationId, handle: &'a radiata::KeyHandle,
  ) -> BoxFuture<'a, Result<radiata::KeyDeleteState>> {
    self
      .records
      .lock()
      .unwrap()
      .remove(handle.expose_provider_handle());
    Box::pin(async move { Ok(radiata::KeyDeleteState::Absent) })
  }

  fn reconcile_delete<'a>(
    &'a self, _operation: &'a radiata::KeyOperationId, handle: &'a radiata::KeyHandle,
  ) -> BoxFuture<'a, Result<radiata::KeyDeleteState>> {
    let present = self
      .records
      .lock()
      .unwrap()
      .contains_key(handle.expose_provider_handle());
    Box::pin(async move {
      Ok(if present {
        radiata::KeyDeleteState::Present
      } else {
        radiata::KeyDeleteState::Absent
      })
    })
  }
}

/// A never-returning action hook neither occupies an execution slot nor
/// delays the leave shutdown. The node runs with a single local slot:
/// the task after the wedged observation must still run (under the old
/// in-body observation, the wedged hook pinned the slot forever), and a
/// leave whose observation wedges must still replace the identity and
/// stop the node with the ActiveLeave reason (the signal is driven by
/// the task table's terminal phase, not by the hook chain).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wedged_action_hook_holds_no_slot_and_never_delays_leave_shutdown() {
  common::init_tracing();
  let mut extensions = ExtensionRegistry::new();
  extensions
    .register_action_hook(
      QualifiedTag::parse("a.example.org/hooks/v1/wedged").unwrap(),
      Arc::new(WedgingActionHook),
    )
    .unwrap();
  let (extensions, _log, _release) = with_probe_reconciler(extensions, vec![Step::Succeed]);
  let config = NodeConfig::new().with_task_reconcile_slots(1, 1).unwrap();
  let node = start_node_with_keys(Arc::new(LeaveCapableKeys::default()), extensions, config).await;

  // The first task completes while its first transition observation
  // wedges forever — the boxed wait fails fast on a regression instead
  // of hanging the harness.
  let first = node.tasks().submit(probe_spec()).await.unwrap();
  tokio::time::timeout(Duration::from_secs(5), first.clone().wait())
    .await
    .expect("the terminal publication must land without the observation")
    .unwrap();

  // The one local slot is free: the next task runs to completion inside
  // the box instead of queueing behind the wedged observer.
  let second = node.tasks().submit(probe_spec()).await.unwrap();
  tokio::time::timeout(Duration::from_secs(5), second.wait())
    .await
    .expect("the wedged observation must not hold the execution slot")
    .unwrap();

  // The leave shutdown is not delayed either: the leave terminalizes,
  // the ActiveLeave signal fires from the task table's terminal phase,
  // and the node stops without ever waiting on the observation.
  let outcome = node
    .leave(radiata::ReplaceIdentityAndDeleteOldCoreMetadata::new())
    .await
    .unwrap();
  tokio::time::timeout(Duration::from_secs(30), outcome.wait())
    .await
    .expect("the leave completes despite the wedged observer")
    .unwrap();
  let reason = tokio::time::timeout(Duration::from_secs(30), node.wait_for_shutdown())
    .await
    .expect("the node stops despite the wedged observer")
    .unwrap();
  assert_eq!(reason, radiata::ShutdownReason::ActiveLeave);
}

/// Adds the probe reconciler to an existing registry.
fn with_probe_reconciler(
  mut extensions: ExtensionRegistry, script: Vec<Step>,
) -> (ExtensionRegistry, Arc<ReconcilerLog>, watch::Sender<bool>) {
  let (release, receiver) = watch::channel(false);
  let log = Arc::new(ReconcilerLog::default());
  extensions
    .register_task_reconciler(
      QualifiedTag::parse(PROBE_KIND).unwrap(),
      ProbeReconciler::new(Arc::clone(&log), script, receiver),
    )
    .unwrap();
  (extensions, log, release)
}
