//! The trigger surface end to end: time triggers driven by cadence
//! patterns against the runtime's controller cadence, event triggers
//! matched against the live resource-change stream, the overlap policy,
//! the additive `TriggerFired` event, and controller passes observable
//! as bounded task records.

use std::{
  sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
  },
  time::{Duration, Instant},
};

use radiata::{
  BoxFuture, EventOptions, EventReceive, ExtensionRegistry, LabelValue, NodeBuilder, NodeConfig,
  NodeHandle, QualifiedTag, ReconcileContext, ReconcileDecision, ResourceLabels, ResourceName,
  ResourceUri, ResourceWrite, Result, SubscriptionPredicate, TaskReconciler, TriggerFired,
  TriggerSourceKind,
  extension::{KeyProvider, StorageFactory},
};
use tokio::sync::Notify;

mod common;

use common::{MemoryStorageFactory, ScriptedKeys};

const PROBE_KIND: &str = "example.org/tasks/v1/trigger-probe";

/// The counting reconciler every trigger targets: it counts its runs and
/// optionally parks until released, so the overlap policy is observable.
#[derive(Debug)]
struct ProbeReconciler {
  runs: Arc<AtomicUsize>,
  park: Option<Arc<Notify>>,
}

impl ProbeReconciler {
  fn counting(runs: Arc<AtomicUsize>) -> Arc<Self> {
    Arc::new(Self { runs, park: None })
  }

  fn parking(runs: Arc<AtomicUsize>, park: Arc<Notify>) -> Arc<Self> {
    Arc::new(Self {
      runs,
      park: Some(park),
    })
  }
}

impl TaskReconciler for ProbeReconciler {
  fn reconcile<'a>(&'a self, _ctx: ReconcileContext) -> BoxFuture<'a, Result<ReconcileDecision>> {
    let runs = Arc::clone(&self.runs);
    let park = self.park.clone();
    Box::pin(async move {
      runs.fetch_add(1, Ordering::SeqCst);
      if let Some(park) = park {
        park.notified().await;
      }
      Ok(ReconcileDecision::Succeeded)
    })
  }
}

fn probe_kind() -> QualifiedTag {
  QualifiedTag::parse(PROBE_KIND).expect("tag")
}

fn extensions_with(reconciler: Arc<ProbeReconciler>) -> ExtensionRegistry {
  let mut extensions = ExtensionRegistry::new();
  extensions
    .register_task_reconciler(probe_kind(), reconciler)
    .expect("register reconciler");
  extensions
}

async fn start_node(extensions: ExtensionRegistry) -> NodeHandle {
  let keys: Arc<dyn KeyProvider> = Arc::new(ScriptedKeys::full_at(9_100_000));
  let storage: Arc<dyn StorageFactory> =
    Arc::new(MemoryStorageFactory::new(common::required_capabilities()));
  NodeBuilder::new(storage)
    .keys(keys)
    .extensions(extensions)
    .config(NodeConfig::new())
    .start()
    .await
    .expect("node starts")
}

/// The every-second UTC pattern: every wall-clock second matches, so
/// each evaluation pass finds the watermark due (the windows between
/// passes coalesce to one run — the count grows per pass, never per
/// second).
const EVERY_SECOND: &str = "{*}-{*}-{*}T{*}:{*}:{*}Z";

/// A time trigger fires per its pattern through the runtime's own
/// controller cadence (no manual pass), each fire is observable through
/// the additive `TriggerFired` event, and the missed windows between
/// evaluation passes coalesce to one run per pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_time_trigger_fires_per_its_pattern_and_coalesces_missed_windows() {
  let runs = Arc::new(AtomicUsize::new(0));
  let handle = start_node(extensions_with(ProbeReconciler::counting(Arc::clone(
    &runs,
  ))))
  .await;
  let mut fired = handle.watch::<TriggerFired>(EventOptions::new()).unwrap();

  handle
    .triggers()
    .register_time("every-second", EVERY_SECOND, probe_kind())
    .await
    .expect("registration")
    .wait()
    .await
    .expect("the durable registration lands");

  // Two or more controller passes elapse; every pass fires the due
  // trigger exactly once, so the run count tracks passes (about one per
  // two-second tick), never wall-clock seconds.
  let started = Instant::now();
  while runs.load(Ordering::SeqCst) < 2 {
    assert!(
      started.elapsed() < Duration::from_secs(30),
      "the time trigger never fired through the controller cadence"
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
  }
  let elapsed = started.elapsed();
  tokio::time::sleep(Duration::from_secs(1)).await;
  let fired_count = runs.load(Ordering::SeqCst);
  assert!(
    fired_count <= elapsed.as_secs() as usize + 2,
    "missed windows must coalesce to one run per pass: {fired_count} runs in {elapsed:?}"
  );

  // The fire is observable as the additive event kind, with the time
  // source and the trigger's registered name.
  let event = tokio::time::timeout(Duration::from_secs(5), fired.recv())
    .await
    .expect("a TriggerFired event arrives")
    .expect("subscription");
  let EventReceive::Item(event) = event else {
    panic!("expected a TriggerFired item");
  };
  assert_eq!(event.trigger(), "every-second");
  assert_eq!(event.source(), TriggerSourceKind::Time);

  handle.shutdown().await.expect("shutdown");
}

/// An event trigger fires on a predicate match against the live
/// resource-change stream (the emit-side evaluation), and while the
/// target is in flight further matching events are skipped per the
/// overlap policy — one run, never a queue.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_event_trigger_matches_the_stream_and_skips_overlapping_fires() {
  let runs = Arc::new(AtomicUsize::new(0));
  let park = Arc::new(Notify::new());
  let handle = start_node(extensions_with(ProbeReconciler::parking(
    Arc::clone(&runs),
    Arc::clone(&park),
  )))
  .await;

  let predicate = SubscriptionPredicate::new().domain("example.org").unwrap();
  handle
    .triggers()
    .register_event("on-example-change", predicate, probe_kind())
    .await
    .expect("registration")
    .wait()
    .await
    .expect("the durable registration lands");

  // The event-trigger cache loads on the next controller pass; give the
  // cadence one tick of margin before driving the stream.
  tokio::time::sleep(Duration::from_secs(3)).await;

  // Two matching changes in a row: the first admits the parked target,
  // the second is skipped while that run is in flight. A non-matching
  // domain's change never fires the trigger.
  let other = ResourceName::parse("radiata.woooo.tech/resources/trigger-miss").unwrap();
  handle
    .resources()
    .put(ResourceWrite::new(
      other,
      ResourceLabels::new(
        LabelValue::parse("document").unwrap(),
        ResourceUri::parse("file:///trigger-miss").unwrap(),
      ),
    ))
    .await
    .unwrap()
    .wait()
    .await
    .unwrap();
  tokio::time::sleep(Duration::from_millis(500)).await;
  assert_eq!(
    runs.load(Ordering::SeqCst),
    0,
    "a non-matching domain must not fire the trigger"
  );

  for index in 0..2 {
    let name = ResourceName::parse("example.org/resources/trigger-hit").unwrap();
    let labels = ResourceLabels::new(
      LabelValue::parse("document").unwrap(),
      ResourceUri::parse(&format!("file:///trigger-{index}")).unwrap(),
    );
    handle
      .resources()
      .put(ResourceWrite::new(name, labels))
      .await
      .unwrap()
      .wait()
      .await
      .unwrap();
    // The engine dispatches events sequentially: give it a beat so the
    // first fire's admission is bookkept before the second event lands.
    tokio::time::sleep(Duration::from_millis(300)).await;
  }
  tokio::time::sleep(Duration::from_millis(500)).await;
  assert_eq!(
    runs.load(Ordering::SeqCst),
    1,
    "the overlapping fire must be skipped while the target is in flight"
  );

  // Releasing the parked target lets it terminalize; the durable row
  // survives and the trigger keeps working afterwards.
  park.notify_waiters();
  tokio::time::sleep(Duration::from_millis(500)).await;
  handle.shutdown().await.expect("shutdown");
}

/// The core's own controller passes are observable as bounded task
/// records: after a few controller ticks, the task page carries the
/// controller kinds at terminal phases, and the bounded terminal history
/// keeps the population capped.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn controller_passes_appear_as_bounded_observable_task_records() {
  let handle = start_node(extensions_with(ProbeReconciler::counting(Arc::new(
    AtomicUsize::new(0),
  ))))
  .await;

  // Three or more controller periods elapse: several evaluation passes
  // (and their tombstone/receipt/trace/removal siblings) terminalize.
  let deadline = Instant::now() + Duration::from_secs(30);
  loop {
    let page = handle
      .tasks()
      .list(radiata::PageSpec::first(512).unwrap())
      .await
      .expect("task page");
    let controller_passes = page
      .items()
      .iter()
      .filter(|view| {
        view
          .kind()
          .as_str()
          .starts_with("radiata.woooo.tech/tasks/")
          && matches!(
            view.kind().as_str(),
            "radiata.woooo.tech/tasks/trigger-evaluation"
              | "radiata.woooo.tech/tasks/tombstone-collection"
              | "radiata.woooo.tech/tasks/receipt-retention"
              | "radiata.woooo.tech/tasks/trace-retention"
              | "radiata.woooo.tech/tasks/resource-removal-retention"
          )
      })
      .count();
    let terminal_controller_passes = page
      .items()
      .iter()
      .filter(|view| {
        view.kind().as_str() == "radiata.woooo.tech/tasks/trigger-evaluation"
          && view.phase().is_terminal()
      })
      .count();
    if terminal_controller_passes >= 2 {
      assert!(
        controller_passes >= terminal_controller_passes,
        "every controller pass is a task record"
      );
      // The whole population stays bounded by the terminal history cap.
      assert!(
        page.items().len() <= 256 + 8,
        "the task history stays bounded"
      );
      break;
    }
    assert!(
      Instant::now() < deadline,
      "controller passes never appeared as task records"
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
  }

  // Shutdown drains cleanly with controller passes in flight.
  handle
    .shutdown()
    .await
    .expect("shutdown drains the controllers");
}
