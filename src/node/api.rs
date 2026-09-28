//! The resource-scoped accessor surface: the client-go-shaped half of
//! the [`NodeHandle`](crate::NodeHandle) verb API. Each accessor hangs
//! off one resource (`node.members()`, `node.resources()`, …) and
//! carries exactly the verbs that resource supports — a read-only
//! resource gets `get`/`list`, a mutable one gets `create`/`delete`.
//!
//! Accessors are cheap single-use values: every verb consumes the
//! accessor and returns an owned future, so a write intent built now
//! can be held and driven later exactly like any other value.

use crate::{
  Endpoint, IssuedMergeCredential, ListenerId, NodeId, PageSpec, Result, RouteHandle,
  RouteStatusView, Selector,
  runtime::{Control, RuntimeClient},
  view::{ListenerPage, ListenerView, MemberPage, MemberView, ResourcePage, ResourceView},
};

/// The public membership observations.
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
}

impl Resources {
  pub(crate) fn new(runtime: &RuntimeClient) -> Self {
    Self {
      runtime: runtime.clone(),
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
  pub async fn put(self, write: crate::ResourceWrite) -> Result<crate::view::ResourceMutationView> {
    crate::resource::check_write_shape(write.name(), write.labels())?;
    self
      .runtime
      .send_command(move |reply| Control::PutResource {
        write,
        expected: None,
        reply,
      })
      .await
  }

  /// Commits one resource write intent as a signed candidate record
  /// with a precondition (compare-and-swap): the candidate commits only
  /// when the stored winner still equals `expected` exactly, so a raced
  /// read-modify-write surfaces as an explicit
  /// [`crate::ErrorKind::Conflict`] instead of a silently lost update.
  pub async fn put_expected(
    self, write: crate::ResourceWrite, expected: crate::ResourceVersion,
  ) -> Result<crate::view::ResourceMutationView> {
    crate::resource::check_write_shape(write.name(), write.labels())?;
    self
      .runtime
      .send_command(move |reply| Control::PutResource {
        write,
        expected: Some(expected),
        reply,
      })
      .await
  }

  /// Creates signed removal evidence for one resource: the removal
  /// commits only when the locally stored winner still equals `expected`
  /// exactly and the removal strictly wins the tuple, so a stale request
  /// never removes newer metadata and never poses as a newer wall-clock
  /// winner. Removal is limited to core metadata; core never follows the
  /// resource URI or touches the caller's object.
  pub async fn delete(
    self, name: crate::ResourceName, expected: crate::ResourceVersion,
  ) -> Result<crate::view::ResourceMutationView> {
    self
      .runtime
      .send_command(move |reply| Control::RemoveResource {
        name,
        expected,
        reply,
      })
      .await
  }
}

/// The node's bound listeners.
pub struct Listeners {
  runtime: RuntimeClient,
}

impl Listeners {
  pub(crate) fn new(runtime: &RuntimeClient) -> Self {
    Self {
      runtime: runtime.clone(),
    }
  }

  /// Binds one new listener on the endpoint and returns its live view.
  pub async fn create(self, endpoint: Endpoint) -> Result<ListenerView> {
    self
      .runtime
      .send_command(move |reply| Control::Listen { endpoint, reply })
      .await
  }

  /// Unbinds one listener by id.
  pub async fn delete(self, listener: ListenerId) -> Result<()> {
    self
      .runtime
      .send_command(move |reply| Control::StopListener { listener, reply })
      .await
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
  /// it: the returned credential admits any number of joins until the
  /// generation is rotated or expires (ten minutes), so concurrent joins
  /// share one generation. With no live generation, one is created.
  /// [`Credentials::rotate`](Credentials::rotate) remains the
  /// revocation/upgrade step.
  pub async fn issue(self) -> Result<IssuedMergeCredential> {
    self
      .runtime
      .send_command(|reply| Control::IssueMergeCredential { reply })
      .await
  }

  /// Replaces the live join credential generation: the issued
  /// replacement admits joins from now on and the former generation
  /// admits none — the revocation/upgrade step next to
  /// [`Credentials::issue`](Credentials::issue).
  pub async fn rotate(self) -> Result<IssuedMergeCredential> {
    self
      .runtime
      .send_command(|reply| Control::RotateMergeCredential { reply })
      .await
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
