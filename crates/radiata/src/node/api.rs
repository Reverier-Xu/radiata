//! The resource-scoped accessor surface: the client-go-shaped half of
//! the [`NodeHandle`](crate::NodeHandle) verb API. Each accessor hangs
//! off one resource (`node.members()`, `node.resources()`, …) and
//! carries exactly the verbs that resource supports — a read-only
//! resource gets `get`/`list`, a mutable one gets `create`/`delete`.
//!
//! Accessors are cheap single-use values: every verb consumes the
//! accessor and returns an owned future, so a write intent built now
//! can be held and driven later exactly like any other value.

use std::sync::Arc;

use crate::{
  Endpoint, IssuedMergeCredential, ListenerId, NodeId, PageSpec, Result, RouteHandle,
  RouteStatusView, Selector, Task, TaskKind, TaskOutput,
  extension_registry::ExtensionRegistry,
  runtime::{Control, EffectOutcome, RuntimeClient, TaskClient, TaskEffect, TaskPayload, TaskSpec},
  view::{ListenerPage, ListenerView, MemberPage, MemberView, ResourcePage, ResourceView},
};

/// The public membership observations.
///
/// The local node's own descriptor publishes lazily: binding a
/// listener publishes it synchronously with the listen task, but on a
/// node that never bound one, the first member query only SCHEDULES
/// that publication (so a slow store can never stall the query behind
/// the descriptor's commit) and answers from committed state — that
/// single first query may not yet list the local node. The scheduled
/// publication lands with its paired
/// [`MemberChanged`](crate::MemberChanged) event and member-revision
/// bump, and every later query observes the local node.
pub struct Members {
  runtime: RuntimeClient,
}

impl Members {
  pub(crate) fn new(runtime: &RuntimeClient) -> Self {
    Self {
      runtime: runtime.clone(),
    }
  }

  /// Queries one member's public observation.
  pub async fn get(self, node: NodeId) -> Result<Option<MemberView>> {
    self
      .runtime
      .send_command(move |reply| Control::GetMember { node, reply })
      .await
  }

  /// Pages the public membership observations.
  pub async fn list(self, page: PageSpec) -> Result<MemberPage> {
    let cursor = page.cursor().cloned();
    let limit = page.limit();
    self
      .runtime
      .send_command(move |reply| Control::PageMembers {
        cursor,
        limit,
        reply,
      })
      .await
  }
}

/// The node's resource register.
pub struct Resources {
  runtime: RuntimeClient,
  /// The node-local extension registry: the resource hooks' admission
  /// source (validate and mutate run on the caller's task before any
  /// IO).
  extensions: std::sync::Arc<ExtensionRegistry>,
}

impl Resources {
  pub(crate) fn new(
    runtime: &RuntimeClient, extensions: &std::sync::Arc<ExtensionRegistry>,
  ) -> Self {
    Self {
      runtime: runtime.clone(),
      extensions: extensions.clone(),
    }
  }

  /// Reads the live winner of one named resource, when present.
  pub async fn get(self, name: crate::ResourceName) -> Result<Option<ResourceView>> {
    self
      .runtime
      .send_command(move |reply| Control::GetResource { name, reply })
      .await
  }

  /// Pages the live resource winners in canonical name order.
  pub async fn list(self, page: PageSpec) -> Result<ResourcePage> {
    let cursor = page.cursor().cloned();
    let limit = page.limit();
    self
      .runtime
      .send_command(move |reply| Control::PageResources {
        cursor,
        limit,
        reply,
      })
      .await
  }

  /// Pages the live resource winners matching one selector.
  pub async fn select(self, selector: Selector, page: PageSpec) -> Result<ResourcePage> {
    let cursor = page.cursor().cloned();
    let limit = page.limit();
    self
      .runtime
      .send_command(move |reply| Control::SelectResources {
        selector,
        cursor,
        limit,
        reply,
      })
      .await
  }

  /// Commits one resource write intent as a signed candidate record,
  /// unconditionally (last-writer-wins). Acceptance never promises the
  /// candidate becomes or stays the tuple winner; the outcome view
  /// reports the accepted record and whether it is the current winner.
  /// For the conditional (compare-and-swap) form, see
  /// [`Resources::put_expected`](Resources::put_expected).
  ///
  /// Admission-time failures are the pure shape checks (a stopped node,
  /// a malformed write, a resource hook's rejection); the frozen-store
  /// refusal and every commit failure are effect-time and surface on
  /// the returned task's [`Task::wait`].
  pub async fn put(
    self, write: crate::ResourceWrite,
  ) -> Result<Task<crate::view::ResourceMutationView>> {
    crate::runtime::put_resource(&self.extensions, self.runtime.admit()?, write, None).await
  }

  /// Commits one resource write intent as a signed candidate record
  /// with a precondition (compare-and-swap): the candidate commits only
  /// when the stored winner still equals `expected` exactly, so a raced
  /// read-modify-write surfaces as an explicit
  /// [`crate::ErrorKind::Conflict`] instead of a silently lost update.
  ///
  /// Admission-time failures are the pure shape checks (a stopped node,
  /// a malformed write, a resource hook's rejection); the CAS outcome is
  /// effect-time and surfaces on the returned task's [`Task::wait`] (a
  /// lost race as [`crate::ErrorKind::Conflict`]).
  pub async fn put_expected(
    self, write: crate::ResourceWrite, expected: crate::ResourceVersion,
  ) -> Result<Task<crate::view::ResourceMutationView>> {
    crate::runtime::put_resource(
      &self.extensions,
      self.runtime.admit()?,
      write,
      Some(expected),
    )
    .await
  }

  /// Creates signed removal evidence for one resource: the removal
  /// commits only when the locally stored winner still equals `expected`
  /// exactly and the removal strictly wins the tuple, so a stale request
  /// never removes newer metadata and never poses as a newer wall-clock
  /// winner. Removal is limited to core metadata; core never follows the
  /// resource URI or touches the caller's object.
  ///
  /// Admission-time failures are the pure shape checks only (a stopped
  /// node); the stale-observation conflict and every commit failure are
  /// effect-time and surface on the returned task's [`Task::wait`].
  pub async fn delete(
    self, name: crate::ResourceName, expected: crate::ResourceVersion,
  ) -> Result<Task<crate::view::ResourceMutationView>> {
    crate::runtime::delete_resource(self.runtime.admit()?, name, expected).await
  }
}

/// The node's bound listeners.
pub struct Listeners {
  runtime: RuntimeClient,
  /// The node-local extension registry: the listen admission resolves
  /// the endpoint's transport selector (a pure registry lookup).
  extensions: std::sync::Arc<ExtensionRegistry>,
}

impl Listeners {
  pub(crate) fn new(
    runtime: &RuntimeClient, extensions: &std::sync::Arc<ExtensionRegistry>,
  ) -> Self {
    Self {
      runtime: runtime.clone(),
      extensions: extensions.clone(),
    }
  }

  /// Binds one new listener on the endpoint and returns the admitted
  /// [`Task`], whose `wait` resolves with the listener's live view.
  ///
  /// Admission-time failures are the pure shape checks (a stopped node,
  /// an endpoint whose transport selector does not resolve in the
  /// registry); the bind syscall and the frozen-store refusal are
  /// effect-time and surface on the task's `wait`.
  pub async fn create(self, endpoint: Endpoint) -> Result<Task<ListenerView>> {
    crate::runtime::listen(&self.extensions, self.runtime.admit()?, endpoint).await
  }

  /// Unbinds one listener by id through the admitted [`Task`], whose
  /// `wait` resolves once the listener is down.
  ///
  /// Admission-time failures are the pure shape checks only (a stopped
  /// node); an unknown listener id is effect-time and surfaces on the
  /// task's `wait` as [`crate::ErrorKind::NotFound`].
  pub async fn delete(self, listener: ListenerId) -> Result<Task<()>> {
    crate::runtime::stop_listener(self.runtime.admit()?, listener).await
  }

  /// Pages the node's bound listeners.
  pub async fn list(self, page: PageSpec) -> Result<ListenerPage> {
    let cursor = page.cursor().cloned();
    let limit = page.limit();
    self
      .runtime
      .send_command(move |reply| Control::PageListeners {
        cursor,
        limit,
        reply,
      })
      .await
  }
}

/// The live authenticated sessions.
pub struct Sessions {
  runtime: RuntimeClient,
}

impl Sessions {
  pub(crate) fn new(runtime: &RuntimeClient) -> Self {
    Self {
      runtime: runtime.clone(),
    }
  }

  /// Pages the live authenticated sessions.
  pub async fn list(self, page: PageSpec) -> Result<crate::SessionPage> {
    let cursor = page.cursor().cloned();
    let limit = page.limit();
    self
      .runtime
      .send_command(move |reply| Control::PageSessions {
        cursor,
        limit,
        reply,
      })
      .await
  }
}

/// The public topology edges.
pub struct Topology {
  runtime: RuntimeClient,
}

impl Topology {
  pub(crate) fn new(runtime: &RuntimeClient) -> Self {
    Self {
      runtime: runtime.clone(),
    }
  }

  /// Pages the public topology edges.
  pub async fn list(self, page: PageSpec) -> Result<crate::TopologyPage> {
    let cursor = page.cursor().cloned();
    let limit = page.limit();
    self
      .runtime
      .send_command(move |reply| Control::PageTopology {
        cursor,
        limit,
        reply,
      })
      .await
  }
}

/// The public trust observations.
pub struct Trust {
  runtime: RuntimeClient,
}

impl Trust {
  pub(crate) fn new(runtime: &RuntimeClient) -> Self {
    Self {
      runtime: runtime.clone(),
    }
  }

  /// Pages the public trust observations.
  pub async fn list(self, page: PageSpec) -> Result<crate::TrustPage> {
    let cursor = page.cursor().cloned();
    let limit = page.limit();
    self
      .runtime
      .send_command(move |reply| Control::PageTrust {
        cursor,
        limit,
        reply,
      })
      .await
  }
}

/// The cluster's live join credentials.
pub struct Credentials {
  runtime: RuntimeClient,
}

impl Credentials {
  pub(crate) fn new(runtime: &RuntimeClient) -> Self {
    Self {
      runtime: runtime.clone(),
    }
  }

  /// Issues the current live join credential generation without rotating
  /// it: the issued credential admits any number of joins until the
  /// generation is rotated or expires (ten minutes), so concurrent joins
  /// share one generation. With no live generation, one is created.
  /// [`Credentials::rotate`](Credentials::rotate) remains the
  /// revocation/upgrade step.
  ///
  /// The credential is deliberately once-only: exactly the *first*
  /// [`Task::wait`] on the returned task collects the secret, any later
  /// `wait` fails with [`crate::ErrorKind::InvalidInput`] ("task output
  /// already collected"), and every status view exposes only the
  /// generation's expiry — an issued credential is a value to hand out
  /// once, never an observation to keep re-reading. Admission-time
  /// failures are the pure shape checks only (a stopped node); the
  /// frozen-store refusal is effect-time and surfaces on the task's
  /// `wait`.
  pub async fn issue(self) -> Result<Task<IssuedMergeCredential>> {
    crate::runtime::issue_merge_credential(self.runtime.admit()?).await
  }

  /// Replaces the live join credential generation: the issued
  /// replacement admits joins from now on and the former generation
  /// admits none — the revocation/upgrade step next to
  /// [`Credentials::issue`](Credentials::issue).
  ///
  /// The replacement is deliberately once-only: exactly the *first*
  /// [`Task::wait`] on the returned task collects the secret, any later
  /// `wait` fails with [`crate::ErrorKind::InvalidInput`] ("task output
  /// already collected"), and every status view exposes only the
  /// generation's expiry. Admission-time failures are the pure shape
  /// checks only (a stopped node); the frozen-store refusal is
  /// effect-time and surfaces on the task's `wait`.
  pub async fn rotate(self) -> Result<Task<IssuedMergeCredential>> {
    crate::runtime::rotate_merge_credential(self.runtime.admit()?).await
  }
}

/// The in-memory packet route records.
pub struct Routes {
  runtime: RuntimeClient,
}

impl Routes {
  pub(crate) fn new(runtime: &RuntimeClient) -> Self {
    Self {
      runtime: runtime.clone(),
    }
  }

  /// Reads the in-memory route status of one packet route handle
  /// (bounded trace metadata only, no durability claim).
  pub fn get(self, handle: &RouteHandle) -> Result<RouteStatusView> {
    self.runtime.route_status(handle)
  }
}

/// The node's admitted operation tasks: `get`/`list`/`wait` over the
/// bounded live+terminal task table, and `submit` for caller-registered
/// extension kinds.
pub struct Tasks {
  runtime: RuntimeClient,
  /// The node-local extension registry: the custom-kind reconciler
  /// lookup behind `submit`.
  extensions: std::sync::Arc<ExtensionRegistry>,
  /// The ordinary public handle the custom-kind reconcilers receive in
  /// their [`crate::ReconcileContext`]: a caller workflow over the
  /// public surface, never privileged core access.
  handle: crate::NodeHandle,
}

impl Tasks {
  pub(crate) fn new(
    runtime: &RuntimeClient, extensions: &std::sync::Arc<ExtensionRegistry>,
    handle: &crate::NodeHandle,
  ) -> Self {
    Self {
      runtime: runtime.clone(),
      extensions: extensions.clone(),
      handle: handle.clone(),
    }
  }

  /// One task's current status, when live or inside the bounded
  /// terminal history. `Ok(None)` for an unknown or evicted id.
  ///
  /// The read is local (no supervisor round trip) and refuses typed once
  /// the node stopped: the table's post-shutdown state is not part of
  /// the public contract.
  pub async fn get(&self, id: crate::TaskId) -> Result<Option<crate::view::TaskView>> {
    self.runtime.get_task(id)
  }

  /// Tasks in canonical id order (= admission order, newest last).
  /// Local read like [`Tasks::get`]; see its shutdown note.
  pub async fn list(&self, page: PageSpec) -> Result<crate::view::TaskPage> {
    let cursor = page.cursor().cloned();
    self.runtime.page_tasks(cursor.as_ref(), page.limit())
  }

  /// Awaits one task's terminal phase and resolves with its terminal
  /// view (value-based: an already-terminal task resolves immediately,
  /// so there is no missed-transition race). [`crate::ErrorKind::NotFound`]
  /// for an unknown or evicted id; [`crate::ErrorKind::ShuttingDown`] if
  /// the node stops before the effect settles (a kind the shutdown drain
  /// awaits to terminality still resolves with its real outcome, exactly
  /// like [`crate::Task::wait`]). No timeout is built in: callers compose
  /// `tokio::time::timeout` over the runtime's own bounded retry
  /// schedules.
  pub async fn wait(&self, id: crate::TaskId) -> Result<crate::view::TaskView> {
    self.require_running()?;
    let client = self.client()?;
    // The watch/shutdown arbitration is the observer's own (shared
    // with [`crate::Task::wait`]); only the terminal read differs —
    // this wait resolves with the view, not the typed output.
    client.observer.await_terminal(&id).await?;
    client
      .observer
      .table
      .view(&id)
      .ok_or_else(|| crate::Error::not_found("task"))
  }

  /// Submits one custom-kind task. The kind tag must live under a
  /// caller-owned domain (never the builtin `radiata.woooo.tech`
  /// domain) and must have a registered
  /// [`TaskReconciler`](crate::TaskReconciler); anything else is
  /// [`crate::ErrorKind::Unsupported`]. The admitted [`Task`] resolves
  /// with `()` on the reconciler's success — the workflow's observations
  /// ride the handle the reconciler itself received, and its optional
  /// output bytes ride the task's
  /// [`TaskOutput`](crate::TaskOutput) payload.
  ///
  /// Admission-time failures are the pure shape checks (a stopped node,
  /// the reserved domain, an unregistered kind); every reconciler error
  /// is effect-time and surfaces on the task's `wait`. Only the
  /// reconciler's explicit
  /// [`ReconcileDecision::Retry`](crate::ReconcileDecision::Retry)
  /// decision re-arms the bounded extension retry schedule; a returned
  /// `Err` or an explicit
  /// [`ReconcileDecision::Failed`](crate::ReconcileDecision::Failed)
  /// decision terminalizes the task as failed with that error, never
  /// retried — re-driving a failed workflow is the caller's own
  /// re-submission.
  pub async fn submit(&self, spec: crate::CustomTaskSpec) -> Result<Task<()>> {
    let client = self.client()?.clone();
    if spec.kind().domain() == crate::protocol::tag::BUILTIN_DOMAIN {
      // Both refusals name the offending kind: the error context
      // carries the offending value (see `Error`'s full-detail stance).
      return Err(crate::Error::unsupported(format!(
        "task kind {}",
        spec.kind()
      )));
    }
    let Some(reconciler) = self.extensions.task_reconciler(spec.kind()) else {
      return Err(crate::Error::unsupported(format!(
        "task kind {}",
        spec.kind()
      )));
    };
    self.require_running()?;
    let kind = TaskKind::from(spec.kind().clone());
    let handle = self.handle.clone();
    let effect: TaskEffect = Arc::new(move |_deps, attempt| {
      let reconciler = Arc::clone(&reconciler);
      let handle = handle.clone();
      let spec = spec.clone();
      Box::pin(async move {
        let context =
          crate::ReconcileContext::new(handle, spec, attempt.attempt, attempt.last_error);
        match reconciler.reconcile(context).await {
          Ok(crate::ReconcileDecision::Succeeded) => {
            Ok(EffectOutcome::new(TaskOutput::new(Arc::from([]))))
          }
          Ok(crate::ReconcileDecision::SucceededWithOutput(bytes)) => {
            Ok(EffectOutcome::new(TaskOutput::new(bytes.into())))
          }
          // The explicit no-progress decision is the only re-arm path:
          // it rides the bounded extension schedule as the typed
          // overload marker the next attempt's context reads.
          Ok(crate::ReconcileDecision::Retry) => Ok(EffectOutcome::Retry(
            crate::Error::overloaded("custom task retry"),
          )),
          // The explicit terminal-failure decision and a returned error
          // both terminalize the task with their error; nothing retries
          // either.
          Ok(crate::ReconcileDecision::Failed(error)) => Err(error.into_error()),
          Err(error) => Err(error),
        }
      })
    });
    let id = client
      .submit(TaskSpec::new(kind.clone(), TaskPayload::None), effect)
      .await?;
    Ok(Task::from_parts(id, kind, client.observer.clone()))
  }

  /// The local shutdown gate shared by every accessor verb.
  fn require_running(&self) -> Result<()> {
    if self.runtime.status() != crate::NodeStatus::Running {
      return Err(crate::Error::shutting_down("node tasks"));
    }
    Ok(())
  }

  fn client(&self) -> Result<&TaskClient> {
    self.runtime.task_client()
  }
}

/// The node's trigger declarations: durable, node-local rows whose
/// source is a `sched` schedule expression (time triggers) or a
/// [`crate::SubscriptionPredicate`] (event triggers), and whose target
/// is a registered caller-owned task reconciler kind — the same rule
/// the `tasks().submit` admission enforces.
///
/// Registration is an admitted task (see the returned [`Task`]): the
/// durable row write lands through the task machinery's own store
/// entry, so `wait()` resolves after the declaration is durable. The
/// trigger evaluation worker rebuilds the runtime `sched` table from the
/// rows every second: a time trigger's first fire is the next schedule
/// window after the pass that registered it, and an event trigger is
/// matched against the live change stream once the next pass has loaded
/// it (bounded by the one-second evaluation cadence). A window missed
/// while the node was down is skipped, not replayed — the `sched`
/// stale-tick policy.
///
/// Schedule expressions are forwarded to `sched` as written: `Z`, a
/// fixed offset, an IANA zone, and the device-local frame all resolve
/// through the library's timezone handling.
pub struct Triggers {
  runtime: RuntimeClient,
  /// The node-local extension registry: the target reconciler lookup
  /// behind registration.
  extensions: std::sync::Arc<ExtensionRegistry>,
}

impl Triggers {
  pub(crate) fn new(
    runtime: &RuntimeClient, extensions: &std::sync::Arc<ExtensionRegistry>,
  ) -> Self {
    Self {
      runtime: runtime.clone(),
      extensions: extensions.clone(),
    }
  }

  /// Registers one time trigger: `pattern` is the `sched` schedule text,
  /// `target` the qualified tag of a registered caller-owned task
  /// reconciler. Re-registering an existing name REPLACES its
  /// declaration outright (a documented overwrite — the new pattern and
  /// target take over at the next evaluation pass; callers never need
  /// `remove` to change a declaration). `wait()` resolves only after the
  /// durable write landed; a registration that keeps losing commit races
  /// fails typed.
  pub async fn register_time(
    self, name: &str, pattern: &str, target: crate::QualifiedTag,
  ) -> Result<Task<()>> {
    crate::trigger::validate_trigger_target(&self.extensions, &target)?;
    // Parsing and zone binding are CPU work plus a possible first
    // timezone-database read: keep them off the async worker.
    let name = name.to_owned();
    let pattern = pattern.to_owned();
    let prepared = tokio::task::spawn_blocking(move || {
      crate::trigger::prepare_time_trigger(&name, &pattern, target)
    })
    .await
    .map_err(|_| crate::Error::internal("trigger preparation"))??;
    let client = self.admit_client().await?;
    crate::runtime::register_trigger(&client, prepared).await
  }

  /// Registers one event trigger: `predicate` filters the live resource
  /// change stream (the same emit-side evaluation the watch
  /// subscriptions use), `target` the qualified tag of a registered
  /// caller-owned task reconciler. Re-registering an existing name
  /// REPLACES its declaration (a documented overwrite); `wait()`
  /// resolves only after the durable write landed, and a registration
  /// that keeps losing commit races fails typed.
  pub async fn register_event(
    self, name: &str, predicate: crate::SubscriptionPredicate, target: crate::QualifiedTag,
  ) -> Result<Task<()>> {
    let row = crate::trigger::prepare_event_trigger(name, predicate, target.clone())?;
    crate::trigger::validate_trigger_target(&self.extensions, &target)?;
    let client = self.admit_client().await?;
    crate::runtime::register_trigger(&client, row).await
  }

  /// Removes one trigger declaration by name. Idempotent: an absent
  /// name succeeds, and so does a removal whose conditional commit
  /// loses a race to a concurrent removal (the name is absent
  /// afterwards, which is the contract). A name that keeps being
  /// re-registered under the removal re-drives bounded and then fails
  /// typed — the caller learns a live declaration still carries the
  /// name instead of a silent false success.
  pub async fn remove(self, name: &str) -> Result<Task<()>> {
    let client = self.admit_client().await?;
    crate::runtime::remove_trigger(&client, name.to_owned()).await
  }

  /// The running-gated admission client (the same gate every mutating
  /// verb applies).
  async fn admit_client(&self) -> Result<TaskClient> {
    if self.runtime.status() != crate::NodeStatus::Running {
      return Err(crate::Error::shutting_down("node triggers"));
    }
    Ok(self.runtime.task_client()?.clone())
  }
}
