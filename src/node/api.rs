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
    self.require_running()?;
    Ok(self.client()?.observer.table.view(&id))
  }

  /// Tasks in canonical id order (= admission order, newest last).
  /// Local read like [`Tasks::get`]; see its shutdown note.
  pub async fn list(&self, page: PageSpec) -> Result<crate::view::TaskPage> {
    self.require_running()?;
    let cursor = page.cursor().cloned();
    let limit = page.limit().clamp(1, crate::paging::MAX_VIEW_PAGE_ITEMS);
    Ok(
      self
        .client()?
        .observer
        .table
        .page_views(cursor.as_ref().map(|cursor| cursor.as_bytes()), limit),
    )
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
    let Some((kind, _)) = client.observer.table.status(&id) else {
      return Err(crate::Error::not_found("task"));
    };
    let Some(mut status) = client.observer.table.watch(&id) else {
      return Err(crate::Error::not_found("task"));
    };
    let mut stop = client.observer.stop.clone();
    loop {
      if status.borrow().phase.is_terminal() {
        return client
          .observer
          .table
          .view(&id)
          .ok_or_else(|| crate::Error::not_found("task"));
      }
      let stopped = tokio::select! {
        changed = status.changed() => changed.is_err(),
        changed = stop.changed() => changed.is_err() || !kind.drains_on_shutdown(),
      };
      if stopped {
        // The terminal publication can land in the same wake as the stop
        // signal (the manager publishes before it stops), so the view is
        // still read before the typed shutdown failure.
        if status.borrow().phase.is_terminal() {
          return client
            .observer
            .table
            .view(&id)
            .ok_or_else(|| crate::Error::not_found("task"));
        }
        return Err(crate::Error::shutting_down("task wait"));
      }
    }
  }

  /// Submits one custom-kind task. The kind tag must live under a
  /// caller-owned domain (never the builtin `radiata.woooo.tech`
  /// domain) and must have a registered
  /// [`TaskReconciler`](crate::TaskReconciler); anything else is
  /// [`crate::ErrorKind::Unsupported`]. The admitted [`Task`] resolves
  /// with `()` on the reconciler's success — the workflow's observations
  /// ride the handle the reconciler itself received.
  ///
  /// Admission-time failures are the pure shape checks (a stopped node,
  /// the reserved domain, an unregistered kind); every reconciler error
  /// is effect-time, retried within the bounded extension schedule, and
  /// surfaces on the task's `wait`.
  pub async fn submit(&self, spec: crate::CustomTaskSpec) -> Result<Task<()>> {
    let client = self.client()?.clone();
    if spec.kind().domain() == crate::protocol::tag::BUILTIN_DOMAIN {
      return Err(crate::Error::unsupported("task kind"));
    }
    let Some(reconciler) = self.extensions.task_reconciler(spec.kind()) else {
      return Err(crate::Error::unsupported("task kind"));
    };
    self.require_running()?;
    let kind = TaskKind::Extension(spec.kind().clone());
    let handle = self.handle.clone();
    let effect: TaskEffect = Arc::new(move |_deps, attempt| {
      let reconciler = Arc::clone(&reconciler);
      let handle = handle.clone();
      let spec = spec.clone();
      Box::pin(async move {
        let context = crate::ReconcileContext {
          handle,
          spec,
          attempt: attempt.attempt,
          last_error: attempt.last_error,
        };
        match reconciler.reconcile(context).await {
          Ok(crate::ReconcileDecision::Succeeded) => {
            Ok(EffectOutcome::new(TaskOutput::Extension(())))
          }
          // The explicit no-progress decision re-arms the same bounded
          // extension schedule an error rides, as the typed overload.
          Ok(crate::ReconcileDecision::Retry) => Err(crate::Error::overloaded("custom task retry")),
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
