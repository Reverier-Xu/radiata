//! Packet route targets, selection, and the checked route envelope.
//!
//! A packet target is either an exact [`NodeId`] or a selector evaluated
//! against node-owned labels. Label targets expose matching members
//! incrementally through the sealed [`CandidateNodeReader`], and the
//! registered [`LoadBalancingPolicy`] selects exactly one eligible
//! destination; core validates that selection against the authoritative
//! descriptor store before any frame moves.
//!
//! The [`RouteContext`] is the per-hop routing envelope: it names the
//! trace, both route endpoints, the current upstream holder, the remaining
//! path, the visited chain, and the remaining hop budget. Every receiving
//! node re-validates the context against its session-authenticated peer
//! before any forwarding work, so mutation of the trace, endpoints,
//! protocol, metadata, or any route field fails closed before a body byte
//! moves. Authenticity comes from the mutually authenticated session
//! transcript (exporter binding): each hop proves the context was produced
//! by the peer it claims, and the canonical wire encoding rejects every
//! mutation.
//!
//! The path is the routing decision: a [`RouteNextHop`] policy plans it
//! once, at the node that opens the delivery, and every hop then follows
//! it — the next entry is the next hop, no per-hop policy runs, and the
//! plan's own construction (a simple path over the learned
//! [`graph::TopologyGraph`], or a caller-named path validated at
//! admission) is what makes the walk loop-free. A hop that receives an
//! exhausted path plans the remainder from itself, which is how the
//! unlearned fallback keeps multi-hop delivery working hop by hop without
//! any node holding a network-wide view.

use std::{collections::BTreeSet, fmt, sync::Arc};

use crate::{Error, NodeId, QualifiedTag, Result, api::BoxFuture};

pub(crate) mod forward;
pub(crate) mod graph;
pub(crate) mod outbound;
pub(crate) mod table;
pub(crate) mod trace;

pub(crate) use graph::{RouteOutcome, TopologyGraph};
pub(crate) use table::{RouteTable, insert_route, record_terminal_failure};

/// The maximum byte length of one selector input. The bound keeps parsing
/// work finite and independent of caller payloads; longer inputs are
/// rejected whole instead of being truncated.
pub(crate) const SELECTOR_INPUT_MAX_BYTES: usize = 1_024;

/// The maximum number of predicates in one selector.
pub(crate) const SELECTOR_MAX_PREDICATES: usize = 16;

/// The maximum number of values in one set (`in`/`notin`) predicate.
pub(crate) const SELECTOR_MAX_SET_VALUES: usize = 16;

/// One bounded label selector: a conjunction of predicates over the
/// closed selector key space.
///
/// Grammar (whitespace separates predicates):
///
/// ```text
/// predicate := key                          # existence
///            | "!" key                      # non-existence
///            | key "=" value                # equality
///            | key "!=" value               # inequality
///            | key WS+ "in" WS* "(" list ")"
///            | key WS+ "notin" WS* "(" list ")"
/// list      := value *( WS* "," WS* value )
/// ```
///
/// Keys are qualified tags in the closed `labels` category or one of the
/// two reserved resource label keys (`resources/type`, `resources/uri`);
/// every other category fails parsing. Values are bounded opaque UTF-8;
/// the characters `\`, whitespace (space, tab, LF, CR), `,`, `(`, `)`,
/// `=`, and `!` appear only escaped (`\X`, with whitespace as `\ `,
/// `\t`, `\n`, `\r`), so any representable label value round-trips
/// through the canonical form exactly. Set semantics follow the usual
/// label-selector rules: inequality and `notin` also match entries whose
/// key is absent, while equality and `in` require presence.
///
/// Parsing normalizes to one canonical representation — predicates sorted
/// by their canonical text with exact duplicates removed, set members
/// sorted and deduplicated, single spaces — so equal inputs converge to
/// one selector and distinct selectors stay distinguishable.
#[derive(Clone, Eq, PartialEq)]
pub struct Selector {
  canonical: Arc<str>,
  predicates: Vec<Predicate>,
}

/// One parsed predicate.
#[derive(Clone, Debug, Eq, PartialEq)]
enum Predicate {
  Exists(QualifiedTag),
  NotExists(QualifiedTag),
  Equals(QualifiedTag, Arc<str>),
  NotEquals(QualifiedTag, Arc<str>),
  In(QualifiedTag, Box<[Arc<str>]>),
  NotIn(QualifiedTag, Box<[Arc<str>]>),
}

impl Predicate {
  fn matches<'a>(&self, lookup: &impl Fn(&QualifiedTag) -> Option<&'a str>) -> bool {
    match self {
      Self::Exists(key) => lookup(key).is_some(),
      Self::NotExists(key) => lookup(key).is_none(),
      Self::Equals(key, value) => lookup(key) == Some(value.as_ref()),
      Self::NotEquals(key, value) => lookup(key).is_none_or(|found| found != value.as_ref()),
      Self::In(key, values) => {
        lookup(key).is_some_and(|found| values.iter().any(|v| v.as_ref() == found))
      }
      Self::NotIn(key, values) => {
        lookup(key).is_none_or(|found| !values.iter().any(|v| v.as_ref() == found))
      }
    }
  }

  /// The canonical text of this predicate: values escaped canonically,
  /// set members sorted and deduplicated.
  fn canonical(&self) -> String {
    match self {
      Self::Exists(key) => key.as_str().to_owned(),
      Self::NotExists(key) => format!("!{}", key.as_str()),
      Self::Equals(key, value) => format!("{}={}", key.as_str(), escape_value(value)),
      Self::NotEquals(key, value) => format!("{}!={}", key.as_str(), escape_value(value)),
      Self::In(key, values) => format!("{} in ({})", key.as_str(), canonical_set(values)),
      Self::NotIn(key, values) => {
        format!("{} notin ({})", key.as_str(), canonical_set(values))
      }
    }
  }
}

/// The canonical comma-joined text of one sorted, deduplicated value set.
fn canonical_set(values: &[Arc<str>]) -> String {
  let mut sorted: Vec<&str> = values.iter().map(AsRef::as_ref).collect();
  sorted.sort_unstable();
  sorted.dedup();
  sorted
    .into_iter()
    .map(escape_value)
    .collect::<Vec<_>>()
    .join(",")
}

/// The canonical escaping of one value: exactly the special characters
/// are escaped, whitespace by name (`\t`, `\n`, `\r`) except the space
/// (`\ `), everything else by literal backslash prefix.
fn escape_value(value: &str) -> String {
  let mut out = String::with_capacity(value.len());
  for character in value.chars() {
    match character {
      ' ' => out.push_str("\\ "),
      '\t' => out.push_str("\\t"),
      '\n' => out.push_str("\\n"),
      '\r' => out.push_str("\\r"),
      '\\' | ',' | '(' | ')' | '=' | '!' => {
        out.push('\\');
        out.push(character);
      }
      _ => out.push(character),
    }
  }
  out
}

/// Maps one escape letter to its character; every other escape is
/// malformed input.
fn unescape(escaped: char) -> Option<char> {
  Some(match escaped {
    ' ' => ' ',
    't' => '\t',
    'n' => '\n',
    'r' => '\r',
    '\\' | ',' | '(' | ')' | '=' | '!' => escaped,
    _ => return None,
  })
}

/// A cursor over the selector input. The grammar is flat (parentheses
/// nest at most one level inside a set list), so a hand-rolled cursor
/// keeps the bounds and failure modes explicit.
struct SelectorParser<'a> {
  input: &'a str,
  position: usize,
}

impl<'a> SelectorParser<'a> {
  fn new(input: &'a str) -> Self {
    Self { input, position: 0 }
  }

  fn rest(&self) -> &'a str {
    &self.input[self.position..]
  }

  fn peek(&self) -> Option<char> {
    self.rest().chars().next()
  }

  fn advance(&mut self) {
    if let Some(character) = self.peek() {
      self.position += character.len_utf8();
    }
  }

  fn skip_whitespace(&mut self) {
    while self.peek().is_some_and(char::is_whitespace) {
      self.advance();
    }
  }

  /// Parses one predicate key: tag characters up to the next operator or
  /// delimiter, validated against the closed selector key space.
  fn parse_key(&mut self) -> Result<QualifiedTag> {
    let start = self.position;
    while let Some(character) = self.peek() {
      if character.is_whitespace() || matches!(character, '=' | '!' | '(' | ')' | ',' | '\\') {
        break;
      }
      self.advance();
    }
    let text = &self.input[start..self.position];
    let tag = QualifiedTag::parse(text)?;
    // The closed selector key space: custom labels live in the `labels`
    // category; the only `resources` keys are the two reserved labels.
    match tag.category() {
      crate::protocol::tag::CATEGORY_LABELS => Ok(tag),
      crate::protocol::tag::CATEGORY_RESOURCES
        if tag.as_str() == crate::resource::RESERVED_TYPE_LABEL_KEY
          || tag.as_str() == crate::resource::RESERVED_URI_LABEL_KEY =>
      {
        Ok(tag)
      }
      _ => Err(Error::invalid_input("selector key")),
    }
  }

  /// Parses one value: literal characters and escapes up to the next
  /// unescaped delimiter (whitespace, or `,`/`)` inside a set list).
  fn parse_value(&mut self, in_list: bool) -> Result<Arc<str>> {
    let mut value = String::new();
    while let Some(character) = self.peek() {
      match character {
        '\\' => {
          self.advance();
          let escaped = self
            .peek()
            .and_then(unescape)
            .ok_or_else(|| Error::invalid_input("selector escape"))?;
          self.advance();
          value.push(escaped);
        }
        _ if character.is_whitespace() => break,
        ',' | ')' if in_list => break,
        '(' | ')' | ',' | '=' | '!' => {
          return Err(Error::invalid_input("selector value"));
        }
        _ => {
          self.advance();
          value.push(character);
        }
      }
    }
    crate::label::validate_bounded_value(&value, "selector value")?;
    Ok(Arc::from(value))
  }

  /// Parses the parenthesized value list of a set predicate; the list is
  /// the grammar's only nesting level. Items are comma-separated; a
  /// missing comma, a leading or trailing comma, and an empty list are
  /// malformed.
  fn parse_set(&mut self) -> Result<Vec<Arc<str>>> {
    if self.peek() != Some('(') {
      return Err(Error::invalid_input("selector set"));
    }
    self.advance();
    let mut values = Vec::new();
    loop {
      self.skip_whitespace();
      if values.len() >= SELECTOR_MAX_SET_VALUES {
        return Err(Error::resource_exhausted("selector set values"));
      }
      // parse_value fails on an empty item, which covers `()`, `(,a)`,
      // and `(a,)` fail-closed.
      values.push(self.parse_value(true)?);
      self.skip_whitespace();
      match self.peek() {
        Some(',') => self.advance(),
        Some(')') => {
          self.advance();
          break;
        }
        _ => return Err(Error::invalid_input("selector set")),
      }
    }
    Ok(values)
  }

  /// Attempts the operator tail after a key: equality, inequality, or a
  /// set membership. Returns `None` (restoring the cursor) when the key
  /// stands alone as an existence predicate.
  fn parse_operator_tail(&mut self, key: &QualifiedTag) -> Result<Option<Predicate>> {
    let checkpoint = self.position;
    self.skip_whitespace();
    match self.peek() {
      Some('=') => {
        self.advance();
        self.skip_whitespace();
        Ok(Some(Predicate::Equals(
          key.clone(),
          self.parse_value(false)?,
        )))
      }
      Some('!') => {
        self.advance();
        if self.peek() != Some('=') {
          // A bare `!` starts the next predicate (non-existence); the
          // parsed key stands alone as an existence predicate.
          self.position = checkpoint;
          return Ok(None);
        }
        self.advance();
        self.skip_whitespace();
        Ok(Some(Predicate::NotEquals(
          key.clone(),
          self.parse_value(false)?,
        )))
      }
      _ => {
        // Set membership requires the keyword as a whitespace-delimited
        // word so keys containing "in" never collide with the operator.
        for (keyword, set_variant) in [("in", true), ("notin", false)] {
          if let Some(after) = self.rest().strip_prefix(keyword) {
            let boundary = after
              .chars()
              .next()
              .is_none_or(|character| character.is_whitespace() || character == '(');
            if boundary {
              for _ in keyword.chars() {
                self.advance();
              }
              self.skip_whitespace();
              let values = self.parse_set()?;
              return Ok(Some(if set_variant {
                Predicate::In(key.clone(), values.into_boxed_slice())
              } else {
                Predicate::NotIn(key.clone(), values.into_boxed_slice())
              }));
            }
          }
        }
        self.position = checkpoint;
        Ok(None)
      }
    }
  }
}

impl Selector {
  /// Parses, bounds, and canonicalizes one selector expression.
  pub fn parse(value: &str) -> Result<Self> {
    if value.is_empty() || value.len() > SELECTOR_INPUT_MAX_BYTES {
      return Err(Error::invalid_input("selector input"));
    }
    let mut parser = SelectorParser::new(value);
    let predicates = Self::parse_predicate_stream(&mut parser, true)?;
    if predicates.is_empty() {
      return Err(Error::invalid_input("selector input"));
    }
    // Canonical order: by canonical predicate text, with exact duplicates
    // removed (conjunction is idempotent).
    let mut canonical: Vec<String> = predicates.iter().map(Predicate::canonical).collect();
    canonical.sort();
    canonical.dedup();
    let canonical = canonical.join(" ");
    // The canonical form is the stored, compared, and re-parsed
    // representation, so it must obey the same frozen input bound as the
    // raw expression: an escaping expansion that would push the canonical
    // form past the bound fails closed here instead of shipping a
    // selector whose own canonical text cannot reparse (the round-trip
    // invariant found by the selector fuzz target).
    if canonical.len() > SELECTOR_INPUT_MAX_BYTES {
      return Err(Error::invalid_input("selector input"));
    }
    // Reparse the joined canonical text so the stored predicate list is
    // exactly the canonical form's parse (canonical text round-trips).
    let reparsed = Self::parse_predicates(&canonical)?;
    Ok(Self {
      canonical: Arc::from(canonical),
      predicates: reparsed,
    })
  }

  /// Parses the already-canonical text back into predicates; the
  /// canonical form is inside every bound, so this cannot fail, and a
  /// failure is an internal invariant break.
  fn parse_predicates(canonical: &str) -> Result<Vec<Predicate>> {
    let mut parser = SelectorParser::new(canonical);
    Self::parse_predicate_stream(&mut parser, false)
  }

  /// The one predicate-parsing loop behind both entry points: raw input
  /// enforces the predicate-count bound, the canonical reparse does not
  /// (deduplication can only shrink it).
  fn parse_predicate_stream(
    parser: &mut SelectorParser<'_>, enforce_predicate_bound: bool,
  ) -> Result<Vec<Predicate>> {
    let mut predicates = Vec::new();
    loop {
      parser.skip_whitespace();
      if parser.peek().is_none() {
        break;
      }
      if enforce_predicate_bound && predicates.len() >= SELECTOR_MAX_PREDICATES {
        return Err(Error::resource_exhausted("selector predicates"));
      }
      let predicate = if parser.peek() == Some('!') {
        parser.advance();
        Predicate::NotExists(parser.parse_key()?)
      } else {
        let key = parser.parse_key()?;
        parser
          .parse_operator_tail(&key)?
          .unwrap_or(Predicate::Exists(key))
      };
      predicates.push(predicate);
    }
    Ok(predicates)
  }

  pub fn as_str(&self) -> &str {
    &self.canonical
  }

  /// Whether every predicate is satisfied under `lookup` (the single
  /// evaluator shared by node-label selection and reserved-aware resource
  /// selection).
  pub(crate) fn matches_with<'a>(&self, lookup: impl Fn(&QualifiedTag) -> Option<&'a str>) -> bool {
    self
      .predicates
      .iter()
      .all(|predicate| predicate.matches(&lookup))
  }

  /// Whether every predicate is satisfied by the node-owned `labels`.
  /// Node descriptors never carry reserved resource labels, so lookups
  /// resolve only the `labels` category.
  pub(crate) fn matches(&self, labels: &crate::LabelSet) -> bool {
    fn lookup<'a>(labels: &'a crate::LabelSet) -> impl Fn(&QualifiedTag) -> Option<&'a str> {
      move |tag| {
        crate::LabelKey::from_label_tag(tag)
          .and_then(|key| labels.get(&key))
          .map(|value| value.as_str())
      }
    }
    self.matches_with(lookup(labels))
  }
}

impl fmt::Debug for Selector {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_tuple("Selector")
      .field(&self.canonical)
      .finish()
  }
}

/// The sealed incremental view of label-matching member candidates. Core
/// implements it over the owner-marked descriptor store; external load
/// balancers consume pages but cannot substitute an unvalidated population.
pub trait CandidateNodeReader: private::Sealed + fmt::Debug + Send + Sync {
  /// Emits the next bounded page of descriptor-bearing members whose
  /// owned labels satisfy `selector`, in canonical node order.
  fn next_matching_nodes<'a>(
    &'a self, selector: &'a Selector, cursor: Option<crate::PageCursor>, limit: usize,
  ) -> BoxFuture<'a, Result<crate::MemberPage>>;
}

/// Prevents external implementations of the sealed reader traits.
pub(crate) mod private {
  pub trait Sealed {}
}

/// The caller-registered policy that picks exactly one eligible
/// destination from the incrementally exposed matching candidates.
pub trait LoadBalancingPolicy: fmt::Debug + Send + Sync + 'static {
  /// Selects exactly one eligible NodeId among the matching candidates.
  /// Implementations consume bounded pages; core independently validates
  /// the returned ID against the authoritative descriptor store, so an ID
  /// outside the observed pages fails closed at the route boundary.
  fn select<'a>(
    &'a self, selector: &'a Selector, candidates: &'a dyn CandidateNodeReader,
  ) -> BoxFuture<'a, Result<NodeId>>;
}

/// The per-hop route state carried in one open frame beyond the identity
/// fields the frame itself already holds (trace, source, destination).
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HopState {
  pub(crate) current: NodeId,
  pub(crate) visited: Vec<NodeId>,
  pub(crate) remaining_hops: u32,
  /// The remaining path after `current`, ending at the destination. Empty
  /// means the next holder plans the remainder from itself.
  pub(crate) path: Vec<NodeId>,
}

/// The checked outcome of receiving one routed packet at `local`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RouteProgress {
  /// This node is the selected destination; the stream is admitted
  /// locally through the ordinary incoming-stream admission path.
  Arrive,
  /// Forward along exactly one validated next hop with the advanced
  /// context. The forwarder never branches the body.
  Continue {
    next_hop: NodeId,
    context: RouteContext,
  },
}

/// The routing envelope of one packet (trace metadata: identity, selected
/// destination, progress — never payload bytes).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteContext {
  trace_id: crate::TraceId,
  source: NodeId,
  destination: NodeId,
  current: NodeId,
  /// The remaining path after `current`, ending at the destination.
  path: Vec<NodeId>,
  visited: Vec<NodeId>,
  remaining_hops: u32,
}

impl RouteContext {
  /// Builds the origin envelope: the source holds the packet, the planned
  /// path is the route the attempt will walk (empty for a direct
  /// delivery), and the full caller-selected budget remains.
  pub(crate) fn new(
    trace_id: crate::TraceId, source: NodeId, destination: NodeId, path: Vec<NodeId>, max_hops: u32,
  ) -> Self {
    Self {
      trace_id,
      current: source.clone(),
      source,
      destination,
      path,
      visited: Vec::new(),
      remaining_hops: max_hops,
    }
  }

  /// The trace this routing context was opened for. Test-only: no
  /// production reader and no fuzz target observes it, so it is not
  /// compiled into either shipped surface.
  #[cfg(test)]
  pub fn trace_id(&self) -> &crate::TraceId {
    &self.trace_id
  }

  pub fn source(&self) -> &NodeId {
    &self.source
  }

  /// The selected destination: the exact target node or the node the
  /// registered load balancer selected for a matching-label target.
  #[cfg(any(test, fuzzing))]
  pub fn destination(&self) -> &NodeId {
    &self.destination
  }

  /// The node that most recently held (and sent) this packet.
  pub fn current(&self) -> &NodeId {
    &self.current
  }

  /// The ordered chain of holders before the current one, starting at the
  /// source.
  pub fn visited(&self) -> &[NodeId] {
    &self.visited
  }

  /// The remaining path after the current holder, ending at the
  /// destination. Empty when the current holder must plan the remainder
  /// itself.
  pub fn path(&self) -> &[NodeId] {
    &self.path
  }

  /// The hop budget still available to this delivery attempt.
  pub fn remaining_hops(&self) -> u32 {
    self.remaining_hops
  }

  /// Projects the wire-carried per-hop state out of the envelope.
  pub(crate) fn hop_state(&self) -> HopState {
    HopState {
      current: self.current.clone(),
      visited: self.visited.clone(),
      remaining_hops: self.remaining_hops,
      path: self.path.clone(),
    }
  }

  /// The same envelope with its remaining path dropped: a re-dispatched
  /// alternative branch at this hop plans its own path instead of
  /// following the abandoned attempt's plan.
  pub(crate) fn replanned(mut self) -> Self {
    self.path = Vec::new();
    self
  }

  /// Rebuilds the envelope from one decoded open frame. A frame without a
  /// route state is a legacy direct delivery: the authenticated source
  /// held the packet and sent it directly.
  pub(crate) fn from_frame(
    trace_id: crate::TraceId, source: NodeId, destination: NodeId, route: Option<HopState>,
  ) -> Self {
    match route {
      Some(HopState {
        current,
        visited,
        remaining_hops,
        path,
      }) => Self {
        trace_id,
        source,
        destination,
        current,
        path,
        visited,
        remaining_hops,
      },
      None => Self::new(trace_id, source, destination, Vec::new(), 1),
    }
  }

  /// The origin's dispatch of one planned envelope: the first hop of the
  /// plan and the envelope that hop receives — the plan's tail, with the
  /// origin as the claimed holder. The origin's own send is not a relay,
  /// so it consumes no budget; every later hop does.
  pub(crate) fn dispatch(self) -> Result<(NodeId, Self)> {
    let mut hops = self.path.into_iter();
    let next_hop = hops
      .next()
      .ok_or_else(|| Error::invalid_input("route path"))?;
    Ok((
      next_hop,
      Self {
        path: hops.collect(),
        ..self
      },
    ))
  }

  /// Validates this envelope at the receiving node `local` against its
  /// session-authenticated `peer`, then produces the checked progress
  /// decision. Every rejection happens before any forwarding work:
  ///
  /// - the authenticated session peer must be the claimed current holder, so
  ///   endpoint substitutions fail closed (`NotTrusted`);
  /// - arrival requires the local node to be the destination;
  /// - forwarding requires budget left (`ResourceExhausted`), and the next hop
  ///   is the head of the remaining path.
  ///
  /// The path is not re-validated hop by hop: it was planned (or named and
  /// validated) once at the origin, and its construction is what makes the
  /// walk loop-free. The `plan` closure runs only when the remaining path
  /// is exhausted at a node that is not the destination — the unlearned
  /// fallback, and the alternative branch of a re-dispatch — and core
  /// re-validates what it returns (`InvalidInput` unless it is non-empty
  /// and duplicate-free, `ResourceExhausted` beyond the budget).
  pub(crate) fn receive(
    mut self, local: &NodeId, peer: &NodeId, plan: impl FnOnce(&Self) -> Result<Vec<NodeId>>,
  ) -> Result<RouteProgress> {
    // The authenticated session peer must be the claimed current holder,
    // so endpoint substitutions fail closed (`NotTrusted`).
    if self.current != *peer {
      return Err(Error::not_trusted("route holder"));
    }
    if self.destination == *local {
      return Ok(RouteProgress::Arrive);
    }
    // Forwarding work is bounded by the caller-selected hop budget; an
    // exhausted budget ends the route explicitly instead of looping.
    if self.remaining_hops == 0 {
      return Err(Error::resource_exhausted("route hops"));
    }
    let path = if self.path.is_empty() {
      let planned = plan(&self)?;
      validate_planned_path(&planned, self.remaining_hops)?;
      planned
    } else {
      std::mem::take(&mut self.path)
    };
    let mut hops = path.into_iter();
    let next_hop = hops
      .next()
      .ok_or_else(|| Error::invalid_input("route path"))?;
    let remaining: Vec<NodeId> = hops.collect();
    Ok(RouteProgress::Continue {
      next_hop,
      context: self.forward(local, remaining),
    })
  }

  /// Marks this envelope as having been forwarded by `local`: the previous
  /// holder joins the visited chain, `local` becomes the current holder,
  /// the remaining path loses its head, and the budget decreases once.
  /// Called only through [`Self::receive`]'s checked continuation.
  fn forward(mut self, local: &NodeId, remaining: Vec<NodeId>) -> Self {
    let previous = std::mem::replace(&mut self.current, local.clone());
    self.visited.push(previous);
    self.path = remaining;
    self.remaining_hops = self.remaining_hops.saturating_sub(1);
    self
  }
}

/// Validates one planned path at the route boundary: non-empty,
/// duplicate-free, and inside the remaining hop budget. A plan is a
/// prefix of a route — it may stop short of the destination, in which case
/// the node that receives its last entry plans the rest — so the plan's
/// own end is not the destination. The first hop's liveness is the
/// dispatching node's own check (it holds the session table).
pub(crate) fn validate_planned_path(path: &[NodeId], remaining_hops: u32) -> Result<()> {
  if path.is_empty() {
    return Err(Error::invalid_input("route path"));
  }
  if path.len() > usize::try_from(remaining_hops).unwrap_or(usize::MAX) {
    return Err(Error::resource_exhausted("route hops"));
  }
  let mut seen = BTreeSet::new();
  for node in path {
    if !seen.insert(node) {
      return Err(Error::invalid_input("route path"));
    }
  }
  Ok(())
}

/// Validates one decoded open frame's routing envelope at the local
/// admission boundary (stream admission, not forwarding). The envelope is
/// re-checked against the session-authenticated `peer` before anything
/// else, and a legacy direct frame (no route state) authenticates only
/// through the exact source-peer match. Forwarding is never a valid
/// outcome at this boundary — the frame either arrives exactly at `local`
/// or fails closed — so the plan is hardcoded to a typed refusal.
pub(crate) fn receive_open_envelope(
  trace_id: crate::TraceId, source: NodeId, destination: NodeId, route: Option<HopState>,
  local: &NodeId, peer: &NodeId,
) -> Result<RouteProgress> {
  RouteContext::from_frame(trace_id, source, destination, route)
    .receive(local, peer, |_| Err(Error::unsupported("route forwarding")))
}

/// The descriptor-store-backed candidate reader: streams bounded pages of
/// live members whose owned labels satisfy the selector, in canonical node
/// order (candidates are exposed incrementally, never as a
/// whole-population allocation).
#[derive(Debug)]
pub(crate) struct StoreCandidateReader {
  snapshot: Box<dyn crate::provider::StoreSnapshot>,
}

impl StoreCandidateReader {
  pub(crate) fn new(snapshot: Box<dyn crate::provider::StoreSnapshot>) -> Self {
    Self { snapshot }
  }
}

impl private::Sealed for StoreCandidateReader {}

impl CandidateNodeReader for StoreCandidateReader {
  fn next_matching_nodes<'a>(
    &'a self, selector: &'a Selector, cursor: Option<crate::PageCursor>, limit: usize,
  ) -> BoxFuture<'a, Result<crate::MemberPage>> {
    Box::pin(async move {
      let limit = limit.clamp(1, crate::paging::PAGE_MAX_ITEMS);
      let namespace = crate::membership::descriptor_namespace()?;
      let snapshot = self.snapshot.as_ref();
      let paged = crate::paging::scan_paged(
        snapshot,
        &namespace,
        &[],
        cursor.as_ref().map(|cursor| cursor.as_bytes()),
        limit,
        |_key, bytes| {
          let Ok(descriptor) = crate::membership::page::decode_descriptor(bytes) else {
            return Ok(None);
          };
          if !selector.matches(descriptor.labels()) {
            return Ok(None);
          }
          crate::membership::member_view(&descriptor, crate::ConnectivityStatus::Unknown).map(Some)
        },
      )
      .await?;
      crate::paging::finish_page(paged, crate::MemberPage::new)
    })
  }
}

/// The sealed per-hop decision inputs handed to a registered
/// [`RouteNextHop`] policy: the packet's trace, the final destination,
/// this node, the hop budget left for the attempt, and the live session
/// peers available as next hops (canonical order).
#[derive(Debug)]
pub struct NextHopView<'a> {
  pub(crate) trace: &'a crate::TraceId,
  pub(crate) destination: &'a NodeId,
  pub(crate) local: &'a NodeId,
  pub(crate) peers: &'a [NodeId],
  pub(crate) remaining_hops: u32,
}

impl NextHopView<'_> {
  /// The routed packet's trace id: stable across every hop of one
  /// delivery attempt and fresh per retry, so a policy can spread retry
  /// attempts across candidate relays while staying deterministic for a
  /// given attempt.
  pub fn trace(&self) -> &crate::TraceId {
    self.trace
  }

  pub fn destination(&self) -> &NodeId {
    self.destination
  }

  pub fn local(&self) -> &NodeId {
    self.local
  }

  /// The live authenticated peers eligible as the first hop of the plan.
  pub fn peers(&self) -> &[NodeId] {
    self.peers
  }

  /// The hop budget left for this delivery attempt: a plan longer than
  /// this can never be walked, so a policy bounds its path by it.
  pub fn remaining_hops(&self) -> u32 {
    self.remaining_hops
  }
}

/// The node-registered policy that plans the route for a packet whose
/// destination is not directly connected. Implementations run at the node
/// that opens the delivery (and at a hop whose carried path ran out)
/// under bounded work; the returned path fails closed at the route
/// boundary unless it is non-empty, duplicate-free, inside the hop
/// budget, ends at the destination, and starts at one of
/// [`NextHopView::peers`].
pub trait RouteNextHop: fmt::Debug + Send + Sync + 'static {
  /// The ordered path from [`NextHopView::local`] to
  /// [`NextHopView::destination`]: the nodes the packet is forwarded
  /// through, excluding the local node and ending at the destination.
  fn plan<'a>(&'a self, view: NextHopView<'a>) -> BoxFuture<'a, Result<Vec<NodeId>>>;
}

/// The built-in next-hop policy: it plans over the node's learned
/// topology graph — the success-rate weighted shortest path from this
/// node to the destination — and falls back to the historical trace-keyed
/// single relay while the graph holds no route.
///
/// The learned plan is the primary behavior: every routed delivery the
/// node observes records its path with a success or failure, so a
/// destination the node has reached before is reached along the path
/// that has been working, and an edge that keeps failing grows expensive
/// enough to route around. A learned path is simple by construction,
/// which is what makes the walk loop-free — the plan is computed once at
/// the origin and every hop follows it.
///
/// The fallback keeps delivery working before anything has been learned:
/// one hop to the live peer that minimizes a trace-keyed hash of the peer
/// id — a stable, uniform shuffle of the candidate set for the current
/// delivery attempt. The choice is deterministic for a given trace and
/// candidate set (the same attempt always picks the same relay, which
/// keeps replay tests simple) and fresh per retry: a caller retrying a
/// failed delivery opens a new trace, so the next attempt takes a
/// different relay path instead of repeating a failed one. On branching
/// topologies, where no stateless policy can tell which neighbor leads
/// toward the destination, that per-attempt variation is what turns
/// bounded caller-level retries into delivery.
///
/// This is the default policy: the node builder registers it under
/// [`DefaultNextHop::TAG`] unless the caller already did, and a node
/// without a caller-selected route policy resolves to that tag, so
/// multi-hop relay works out of the box. [`crate::NodeConfig::
/// with_route_policy`] selects a different registered policy instead;
/// registering a caller policy under [`DefaultNextHop::TAG`] replaces the
/// default outright.
///
/// A standalone [`DefaultNextHop::default`] instance carries no learned
/// topology — it is the fallback algorithm on its own, which is exactly
/// what a caller delegating to it from a wrapper policy wants.
#[derive(Debug, Default)]
pub struct DefaultNextHop {
  /// The node's learned topology, shared with the routing plane that
  /// records every observed outcome. `None` for a standalone instance.
  graph: Option<Arc<TopologyGraph>>,
}

impl DefaultNextHop {
  /// The well-known tag the built-in policy is registered under.
  pub const TAG: &'static str = "radiata.woooo.tech/route-policies/default";

  /// The built-in policy's canonical tag, parsed once. The literal is a
  /// fixed canonical constant; the impossible parse failure surfaces as
  /// an internal error instead of a panic.
  pub(crate) fn tag() -> Result<QualifiedTag> {
    static TAG: std::sync::OnceLock<std::result::Result<QualifiedTag, ()>> =
      std::sync::OnceLock::new();
    TAG
      .get_or_init(|| QualifiedTag::parse(Self::TAG).map_err(|_| ()))
      .clone()
      .map_err(|_| Error::internal("built-in next-hop policy tag"))
  }

  /// The node-scoped instance: the same algorithm over the node's learned
  /// topology.
  pub(crate) fn with_graph(graph: Arc<TopologyGraph>) -> Self {
    Self { graph: Some(graph) }
  }

  /// The trace-keyed relay rank of one candidate peer. The hash is keyed
  /// by the current attempt's trace, so the same attempt ranks a peer
  /// identically at every evaluation and a retry attempt (fresh trace)
  /// ranks it independently.
  fn rank(trace: &crate::TraceId, peer: &NodeId) -> u64 {
    let mut hasher = std::hash::DefaultHasher::new();
    std::hash::Hash::hash(&(trace.as_str(), peer.as_str()), &mut hasher);
    std::hash::Hasher::finish(&hasher)
  }
}

impl RouteNextHop for DefaultNextHop {
  fn plan<'a>(&'a self, view: NextHopView<'a>) -> BoxFuture<'a, Result<Vec<NodeId>>> {
    Box::pin(async move {
      // A connected destination is delivered directly: the plan is one
      // hop and the routing plane sends the frame over that session.
      if view.peers().contains(view.destination()) {
        return Ok(vec![view.destination().clone()]);
      }
      // The learned topology is the primary answer: the cheapest known
      // path, bounded by the budget left and starting at a live peer.
      if let Some(path) = self.graph.as_ref().and_then(|graph| {
        graph.path(
          view.local(),
          view.destination(),
          view.peers(),
          view.remaining_hops(),
        )
      }) {
        return Ok(path);
      }
      // Nothing learned yet: relay one hop, ranked per attempt.
      view
        .peers()
        .iter()
        .min_by_key(|peer| Self::rank(view.trace(), peer))
        .cloned()
        .map(|peer| vec![peer])
        .ok_or_else(|| Error::caller("no live peer to relay through"))
    })
  }
}

/// The built-in direct routing policy: the stream-level policy registered
/// under [`crate::RoutingPolicy::DIRECT`] that never relays. Its
/// [`RouteNextHop`] implementation refuses every plan, so a stream that
/// resolved it as a relay policy could never forward; the admission plane
/// recognizes the tag instead and keeps the node-level route policy's
/// behavior for such streams (direct delivery when the destination is
/// connected, the configured policy's plan otherwise).
#[derive(Debug)]
pub(crate) struct DirectRouting;

impl RouteNextHop for DirectRouting {
  fn plan<'a>(&'a self, _view: NextHopView<'a>) -> BoxFuture<'a, Result<Vec<NodeId>>> {
    Box::pin(async { Err(Error::route_unavailable("direct routing policy")) })
  }
}

/// The node-local routing policy map: the next-hop policies, the
/// stream-level routing policies, and the learned topology the built-in
/// policy plans over.
///
/// The map is born empty. [`Self::register_default`] installs the core
/// policies explicitly — the direct stream policy and the default next-hop
/// policy — and every other entry arrives through an explicit registration
/// call. A caller registration under the built-in domain stays refused for
/// routing policies; the default next-hop tag is an ordinary registry tag a
/// caller may claim before the default path runs.
pub(crate) struct RoutingRegistry {
  next_hops: std::sync::RwLock<std::collections::BTreeMap<QualifiedTag, Arc<dyn RouteNextHop>>>,
  routing_policies:
    std::sync::RwLock<std::collections::BTreeMap<QualifiedTag, Arc<dyn RouteNextHop>>>,
  /// The node-local learned topology: the routing plane records every
  /// observed route outcome here and the built-in policy plans over it.
  graph: Arc<TopologyGraph>,
}

impl RoutingRegistry {
  /// The empty routing map: no policy resolves until it is registered
  /// (explicitly, or through [`Self::register_default`]).
  pub(crate) fn new() -> Self {
    Self {
      next_hops: std::sync::RwLock::new(std::collections::BTreeMap::new()),
      routing_policies: std::sync::RwLock::new(std::collections::BTreeMap::new()),
      graph: Arc::new(TopologyGraph::new()),
    }
  }

  /// Installs the core policies under their canonical tags. An
  /// already-occupied tag (a caller-claimed next-hop tag) is left
  /// untouched, so the default path never replaces an explicit decision.
  /// Idempotent.
  pub(crate) fn register_default(&mut self) -> Result<&mut Self> {
    let next_hop_tag = DefaultNextHop::tag()?;
    {
      let mut policies = self
        .routing_policies
        .write()
        .map_err(Error::extension_registry)?;
      policies
        .entry(crate::RoutingPolicy::DIRECT.tag().clone())
        .or_insert_with(|| Arc::new(DirectRouting));
    }
    {
      let mut next_hops = self.next_hops.write().map_err(Error::extension_registry)?;
      next_hops
        .entry(next_hop_tag)
        .or_insert_with(|| Arc::new(DefaultNextHop::with_graph(Arc::clone(&self.graph))));
    }
    Ok(self)
  }

  /// The node's learned topology.
  pub(crate) fn graph(&self) -> &Arc<TopologyGraph> {
    &self.graph
  }

  /// Registers one next-hop policy under a canonical tag. A duplicate tag
  /// is a conflict; registration never replaces an existing entry.
  pub(crate) fn register_next_hop(
    &mut self, tag: QualifiedTag, value: Arc<dyn RouteNextHop>,
  ) -> Result<&mut Self> {
    {
      let mut policies = self.next_hops.write().map_err(Error::extension_registry)?;
      crate::api::insert_once(&mut policies, tag, value, "next-hop registration")?;
    }
    Ok(self)
  }

  /// Registers one stream-level routing policy under its canonical tag.
  /// A caller policy lives under a caller-owned domain: the built-in
  /// domain is reserved for the core direct policy. A duplicate tag is a
  /// conflict.
  pub(crate) fn register_routing_policy(
    &mut self, tag: QualifiedTag, value: Arc<dyn RouteNextHop>,
  ) -> Result<&mut Self> {
    if tag.domain() == crate::protocol::tag::BUILTIN_DOMAIN {
      return Err(Error::invalid_input("routing policy tag"));
    }
    {
      let mut policies = self
        .routing_policies
        .write()
        .map_err(Error::extension_registry)?;
      crate::api::insert_once(&mut policies, tag, value, "routing policy registration")?;
    }
    Ok(self)
  }

  /// The registered next-hop policy for one tag, when present.
  pub(crate) fn next_hop_policy(&self, tag: &QualifiedTag) -> Option<Arc<dyn RouteNextHop>> {
    self
      .next_hops
      .read()
      .ok()
      .and_then(|policies| policies.get(tag).cloned())
  }

  /// The registered stream routing policy for one tag, when present.
  pub(crate) fn routing_policy(&self, tag: &QualifiedTag) -> Option<Arc<dyn RouteNextHop>> {
    self
      .routing_policies
      .read()
      .ok()
      .and_then(|policies| policies.get(tag).cloned())
  }

  pub(crate) fn next_hop_count(&self) -> usize {
    self
      .next_hops
      .read()
      .map(|policies| policies.len())
      .unwrap_or(0)
  }

  pub(crate) fn routing_policy_count(&self) -> usize {
    self
      .routing_policies
      .read()
      .map(|policies| policies.len())
      .unwrap_or(0)
  }
}

impl Default for RoutingRegistry {
  fn default() -> Self {
    Self::new()
  }
}

impl fmt::Debug for RoutingRegistry {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("RoutingRegistry")
      .field("next_hops", &self.next_hop_count())
      .field("routing_policies", &self.routing_policy_count())
      .field("graph", &self.graph)
      .finish()
  }
}

/// The shared route-planning seam of the routing plane: resolves the
/// registered [`RouteNextHop`] policy named by `tag` against the route
/// view built from `trace`, `destination`, `local`, the alive `peers`,
/// and the budget left. `Ok(None)` means `tag` names no registered policy
/// — the callers apply their own observability and fallback; the policy's
/// own rejection propagates as `Err`.
pub(crate) async fn resolve_plan(
  registry: &RoutingRegistry, tag: &QualifiedTag, trace: &crate::TraceId, destination: &NodeId,
  local: &NodeId, peers: &[NodeId], remaining_hops: u32,
) -> Result<Option<Vec<NodeId>>> {
  let Some(policy) = registry.next_hop_policy(tag) else {
    return Ok(None);
  };
  policy
    .plan(NextHopView {
      trace,
      destination,
      local,
      peers,
      remaining_hops,
    })
    .await
    .map(Some)
}

/// One already-resolved policy's route plan: the same view
/// [`resolve_plan`] builds, for callers that hold the policy itself
/// (a stream's routing policy) instead of a node-level tag.
pub(crate) async fn plan_of(
  policy: &dyn RouteNextHop, trace: &crate::TraceId, destination: &NodeId, local: &NodeId,
  peers: &[NodeId], remaining_hops: u32,
) -> Result<Vec<NodeId>> {
  policy
    .plan(NextHopView {
      trace,
      destination,
      local,
      peers,
      remaining_hops,
    })
    .await
}

/// The origin's decided route for one outbound pump: the planned path and
/// the topology graph that observes the attempt's outcome. `None` at the
/// pump means a direct delivery — no route envelope and no topology
/// observation.
pub(crate) struct PlannedRoute {
  /// The path from the origin to the destination: excluding the origin,
  /// ending at the destination.
  pub(crate) path: Vec<NodeId>,
  /// The node's learned topology, which records the attempt's outcome.
  pub(crate) graph: Arc<TopologyGraph>,
}

#[cfg(test)]
mod tests {
  use std::sync::Arc;

  use proptest::strategy::Strategy as _;

  use super::{CandidateNodeReader, Selector, StoreCandidateReader};
  use crate::{
    Endpoint, ErrorKind, LabelKey, LabelSet, LabelValue, NodeId, Result, TraceId,
    provider::StorageFactory,
  };

  fn node(value: u8) -> NodeId {
    NodeId::parse(&format!("node-{value:021}")).unwrap()
  }

  /// The built-in default policy without learned topology is the
  /// trace-keyed single relay: deterministic for a given trace
  /// (order-independent), varying across fresh traces so caller retries
  /// explore different relay paths, and failing closed with a typed
  /// caller error when no live peer exists.
  #[tokio::test]
  async fn the_unlearned_default_policy_relays_one_trace_keyed_hop() {
    use super::{DefaultNextHop, NextHopView, RouteNextHop};

    let destination = node(9);
    let local = node(0);
    let policy = DefaultNextHop::default();
    let trace = TraceId::parse("trace-000000000000000000001").unwrap();
    let peers: Vec<NodeId> = [4, 2, 7].iter().map(|value| node(*value)).collect();
    let mut picks = std::collections::BTreeSet::new();
    for ordering in [[4, 2, 7], [7, 4, 2], [2, 7, 4]] {
      let shuffled: Vec<NodeId> = ordering.iter().map(|value| node(*value)).collect();
      let view = NextHopView {
        trace: &trace,
        destination: &destination,
        local: &local,
        peers: &shuffled,
        remaining_hops: 4,
      };
      let plan = policy.plan(view).await.unwrap();
      assert_eq!(
        plan.len(),
        1,
        "the unlearned fallback relays exactly one hop"
      );
      picks.insert(plan[0].clone());
    }
    assert_eq!(
      picks.len(),
      1,
      "one trace must pick one relay regardless of peer order"
    );
    // Fresh traces (retry attempts) explore the candidate set instead of
    // repeating one pick: over 64 traces, several distinct relays win.
    let mut winners = std::collections::BTreeSet::new();
    for seed in 1..=64_u32 {
      let trace = TraceId::parse(&format!("trace-{seed:021}")).unwrap();
      let view = NextHopView {
        trace: &trace,
        destination: &destination,
        local: &local,
        peers: &peers,
        remaining_hops: 4,
      };
      winners.insert(policy.plan(view).await.unwrap()[0].clone());
    }
    assert!(
      winners.len() >= 2,
      "retry attempts must not all repeat one relay: {winners:?}"
    );
    let view = NextHopView {
      trace: &trace,
      destination: &destination,
      local: &local,
      peers: &[],
      remaining_hops: 4,
    };
    let error = policy.plan(view).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::CallerError);
  }

  /// A connected destination is planned directly, and a learned path is
  /// planned whole: the policy answers with the path the routing plane
  /// then carries in the envelope.
  #[tokio::test]
  async fn the_default_policy_plans_direct_and_learned_paths() {
    use super::{DefaultNextHop, NextHopView, RouteNextHop, TopologyGraph};

    let trace = TraceId::parse("trace-000000000000000000001").unwrap();
    let local = node(1);
    let destination = node(9);
    let graph = Arc::new(TopologyGraph::new());
    let policy = DefaultNextHop::with_graph(Arc::clone(&graph));

    // A connected destination: one hop, the destination itself.
    let peers = [node(9), node(2)];
    let plan = policy
      .plan(NextHopView {
        trace: &trace,
        destination: &destination,
        local: &local,
        peers: &peers,
        remaining_hops: 4,
      })
      .await
      .unwrap();
    assert_eq!(plan, vec![node(9)]);

    // A learned path: the whole path, not just its first hop.
    graph.record(
      &destination,
      &local,
      &[node(2), node(5), destination.clone()],
      super::RouteOutcome::Delivered,
    );
    let peers = [node(2), node(3)];
    let plan = policy
      .plan(NextHopView {
        trace: &trace,
        destination: &destination,
        local: &local,
        peers: &peers,
        remaining_hops: 4,
      })
      .await
      .unwrap();
    assert_eq!(plan, vec![node(2), node(5), node(9)]);
  }

  /// The policy view exposes the hop budget left for the attempt, so a
  /// policy can bound its plan by it (C9), and the built-in policy's
  /// learned plan respects that bound.
  #[tokio::test]
  async fn the_policy_view_exposes_the_remaining_hop_budget() {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::{DefaultNextHop, NextHopView, RouteNextHop, TopologyGraph};

    #[derive(Debug)]
    struct BudgetProbe {
      seen: Arc<AtomicU32>,
    }

    impl RouteNextHop for BudgetProbe {
      fn plan<'a>(
        &'a self, view: NextHopView<'a>,
      ) -> crate::api::BoxFuture<'a, Result<Vec<NodeId>>> {
        self.seen.store(view.remaining_hops(), Ordering::SeqCst);
        Box::pin(async move { Ok(vec![view.destination().clone()]) })
      }
    }

    let trace = TraceId::parse("trace-000000000000000000001").unwrap();
    let local = node(1);
    let destination = node(9);
    let peers = [node(2)];
    let seen = Arc::new(AtomicU32::new(0));
    let probe = BudgetProbe {
      seen: Arc::clone(&seen),
    };
    let plan = probe
      .plan(NextHopView {
        trace: &trace,
        destination: &destination,
        local: &local,
        peers: &peers,
        remaining_hops: 3,
      })
      .await
      .unwrap();
    assert_eq!(plan, vec![destination]);
    assert_eq!(seen.load(Ordering::SeqCst), 3);

    // The built-in policy bounds its learned plan by the same budget: a
    // learned two-hop path is planned with two hops left and refused with
    // one.
    let graph = Arc::new(TopologyGraph::new());
    graph.record(
      &node(9),
      &local,
      &[node(2), node(9)],
      super::RouteOutcome::Delivered,
    );
    let policy = DefaultNextHop::with_graph(graph);
    let plan = policy
      .plan(NextHopView {
        trace: &trace,
        destination: &node(9),
        local: &local,
        peers: &peers,
        remaining_hops: 2,
      })
      .await
      .unwrap();
    assert_eq!(plan, vec![node(2), node(9)]);
    let plan = policy
      .plan(NextHopView {
        trace: &trace,
        destination: &node(9),
        local: &local,
        peers: &peers,
        remaining_hops: 1,
      })
      .await
      .unwrap();
    assert_eq!(
      plan,
      vec![node(2)],
      "a plan that cannot fit the budget falls back to one relay hop"
    );
  }

  /// The built-in direct policy is the registry's no-relay entry: it
  /// refuses every plan, so a stream that resolved it as a relay policy
  /// could never forward. The admission plane recognizes its tag and
  /// keeps the node-level route policy's behavior instead.
  #[tokio::test]
  async fn the_direct_routing_policy_never_relays() {
    use super::{DirectRouting, NextHopView, RouteNextHop};

    let destination = node(9);
    let local = node(0);
    let trace = TraceId::parse("trace-000000000000000000001").unwrap();
    let peers = [node(4), node(2)];
    let error = DirectRouting
      .plan(NextHopView {
        trace: &trace,
        destination: &destination,
        local: &local,
        peers: &peers,
        remaining_hops: 4,
      })
      .await
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::RouteUnavailable);
    assert_eq!(error.context(), "direct routing policy");
  }

  fn key(name: &str) -> LabelKey {
    LabelKey::parse(&format!("radiata.woooo.tech/labels/{name}")).unwrap()
  }

  fn labels(entries: &[(&str, &str)]) -> LabelSet {
    let mut set = LabelSet::new();
    for (name, value) in entries {
      set = set
        .insert(key(name), LabelValue::parse(value).unwrap())
        .unwrap();
    }
    set
  }

  // ---- route-context mutation fails before forwarding ----

  /// A frame whose claimed current holder differs from the
  /// session-authenticated peer is rejected before any progress decision.
  #[test]
  fn mutated_current_holder_fails_closed() {
    let context = crate::routing::RouteContext::new(
      TraceId::generate(&crate::api::SystemEntropy).unwrap(),
      node(1),
      node(3),
      vec![node(2), node(3)],
      4,
    );
    // The envelope claims node(1) is the holder, but the authenticated
    // session peer is node(9): an endpoint substitution.
    let error = context
      .receive(&node(2), &node(9), |_| Ok(vec![node(3)]))
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::NotTrusted);
  }

  /// A plan that the local node has to compute is validated at the route
  /// boundary: it must be non-empty, duplicate-free, and inside the
  /// budget. The carried path is not re-validated hop by hop — the origin
  /// planned it once — so only the peer check and the budget gate a
  /// followed path.
  #[test]
  fn a_planned_path_is_validated_at_the_route_boundary() {
    let trace = TraceId::generate(&crate::api::SystemEntropy).unwrap();
    // An exhausted path at a non-destination node: the plan decides.
    let context = crate::routing::RouteContext::new(trace.clone(), node(1), node(4), Vec::new(), 4);
    for (plan, expected) in [
      (Vec::new(), ErrorKind::InvalidInput),
      (vec![node(3), node(3)], ErrorKind::InvalidInput),
      (
        vec![node(2), node(3), node(4), node(5), node(6)],
        ErrorKind::ResourceExhausted,
      ),
    ] {
      let error = context
        .clone()
        .receive(&node(2), &node(1), |_| Ok(plan.clone()))
        .unwrap_err();
      assert_eq!(error.kind(), expected, "plan {plan:?}");
    }
    // A well-formed plan is followed from its head, and a plan that stops
    // short of the destination is a prefix the next holder continues.
    for (plan, head, tail) in [
      (vec![node(3), node(4)], node(3), vec![node(4)]),
      (vec![node(3)], node(3), Vec::new()),
    ] {
      match context
        .clone()
        .receive(&node(2), &node(1), |_| Ok(plan.clone()))
        .unwrap()
      {
        crate::routing::RouteProgress::Continue { next_hop, context } => {
          assert_eq!(next_hop, head);
          assert_eq!(context.path(), tail.as_slice());
        }
        crate::routing::RouteProgress::Arrive => panic!("mid-route arrival"),
      }
    }
  }

  // ---- label-target selection without unauthorized routing ----

  /// The selector grammar parses within bounds, canonicalizes equivalent
  /// forms to one representation, and evaluates existence and equality.
  #[test]
  fn selectors_parse_canonicalize_and_match() {
    let selector =
      Selector::parse("radiata.woooo.tech/labels/zone=edge radiata.woooo.tech/labels/gpu").unwrap();
    // Canonical order sorts keys; the same predicates in another order or
    // with extra whitespace converge to one selector.
    let reordered =
      Selector::parse("  radiata.woooo.tech/labels/gpu   radiata.woooo.tech/labels/zone=edge ")
        .unwrap();
    assert_eq!(selector, reordered);
    assert_eq!(
      selector.as_str(),
      "radiata.woooo.tech/labels/gpu radiata.woooo.tech/labels/zone=edge"
    );

    let matching = labels(&[("gpu", "yes"), ("zone", "edge")]);
    assert!(selector.matches(&matching));
    // Equality is exact; existence only requires presence.
    assert!(!selector.matches(&labels(&[("gpu", "yes"), ("zone", "core")])));
    assert!(
      !selector.matches(&labels(&[("zone", "edge")])),
      "existence of gpu is unsatisfied"
    );
    assert!(!selector.matches(&LabelSet::new()));

    // Malformed input fails without panic.
    assert_eq!(
      Selector::parse("").unwrap_err().kind(),
      ErrorKind::InvalidInput
    );
    assert_eq!(
      Selector::parse("not-a-tag").unwrap_err().kind(),
      ErrorKind::InvalidInput
    );
    assert_eq!(
      Selector::parse("radiata.woooo.tech/features/not-a-label")
        .unwrap_err()
        .kind(),
      ErrorKind::InvalidInput
    );
  }

  fn descriptor_with_labels(
    node_index: u8, revision: u64, set: LabelSet,
  ) -> crate::membership::NodeDescriptorV1 {
    use crate::identity::testing::scripted_signing;
    let signing = scripted_signing(u64::from(node_index));
    let public_key = crate::PublicKey::from_bytes(signing.verifying_key().to_bytes());
    crate::membership::NodeDescriptorV1::new(
      node(node_index),
      public_key,
      vec![Endpoint::parse(&format!("wss://node-{node_index}:9000")).unwrap()],
      revision,
      1,
    )
    .with_labels(set)
  }

  async fn candidate_store() -> Arc<dyn StorageFactory> {
    let factory: Arc<dyn StorageFactory> =
      Arc::new(crate::storage::contract::ReferenceFactory::new(
        crate::storage::contract::required_capabilities(),
      ));
    let store = crate::storage::MetadataStore::open(&factory, std::time::Duration::from_secs(10))
      .await
      .unwrap();
    for index in 1..=5_u8 {
      let set = if index % 2 == 0 {
        labels(&[("gpu", "yes"), ("zone", "edge")])
      } else {
        labels(&[("zone", "core")])
      };
      crate::membership::store::store_descriptor_ctx(
        &store,
        &crate::api::SystemEntropy,
        &descriptor_with_labels(index, 1, set),
      )
      .await
      .unwrap();
    }
    factory
  }

  async fn candidate_reader() -> StoreCandidateReader {
    let factory = candidate_store().await;
    let store = crate::storage::MetadataStore::open(&factory, std::time::Duration::from_secs(10))
      .await
      .unwrap();
    StoreCandidateReader::new(store.snapshot().await.unwrap())
  }

  /// Candidates stream in bounded pages in canonical node order, exposing
  /// only live members whose owned labels match — never a whole-population
  /// allocation.
  #[tokio::test]
  async fn matching_candidates_stream_in_bounded_pages() {
    let reader = candidate_reader().await;
    let selector = Selector::parse("radiata.woooo.tech/labels/zone=edge").unwrap();

    // Nodes 2 and 4 carry zone=edge; page limit one forces two pages, and
    // the trailing non-matching member ends the stream on a third call.
    let page = reader
      .next_matching_nodes(&selector, None, 1)
      .await
      .unwrap();
    assert_eq!(page.items().len(), 1);
    assert_eq!(page.items()[0].node_id(), &node(2));
    assert!(page.items()[0].labels().get(&key("zone")).is_some());
    let cursor = page.next().unwrap().clone();
    let page = reader
      .next_matching_nodes(&selector, Some(cursor), 1)
      .await
      .unwrap();
    assert_eq!(page.items().len(), 1);
    assert_eq!(page.items()[0].node_id(), &node(4));
    let cursor = page.next().unwrap().clone();
    let page = reader
      .next_matching_nodes(&selector, Some(cursor), 1)
      .await
      .unwrap();
    assert!(page.items().is_empty());
    assert!(page.next().is_none());

    // A nonmatching selector yields an empty stream, not an error.
    let none = Selector::parse("radiata.woooo.tech/labels/gpu=nope").unwrap();
    let page = reader.next_matching_nodes(&none, None, 8).await.unwrap();
    assert!(page.items().is_empty());
    assert!(page.next().is_none());
  }

  #[derive(Debug)]
  struct FirstCandidate;

  impl crate::LoadBalancingPolicy for FirstCandidate {
    fn select<'a>(
      &'a self, selector: &'a Selector, candidates: &'a dyn crate::CandidateNodeReader,
    ) -> crate::api::BoxFuture<'a, Result<NodeId>> {
      Box::pin(async move {
        let page = candidates.next_matching_nodes(selector, None, 8).await?;
        page
          .items()
          .first()
          .map(|view| view.node_id().clone())
          .ok_or_else(|| crate::Error::route_unavailable("packet candidates"))
      })
    }
  }

  /// Registry registration resolves by tag and rejects duplicates; the
  /// registered policy selects exactly one eligible node among the matching
  /// candidates.
  #[tokio::test]
  async fn load_balancer_registration_and_selection() -> Result<()> {
    let mut registry = crate::ExtensionRegistry::new();
    let tag = crate::QualifiedTag::parse("radiata.woooo.tech/policies/first")?;
    registry.register_load_balancer(tag.clone(), Arc::new(FirstCandidate))?;
    assert!(registry.has_load_balancer(&tag));
    // A duplicate tag registration conflicts.
    assert_eq!(
      registry
        .register_load_balancer(tag, Arc::new(FirstCandidate))
        .unwrap_err()
        .kind(),
      ErrorKind::Conflict
    );

    let reader = candidate_reader().await;
    let selector = Selector::parse("radiata.woooo.tech/labels/gpu=yes").unwrap();
    let policy = registry
      .load_balancer(&crate::QualifiedTag::parse(
        "radiata.woooo.tech/policies/first",
      )?)
      .unwrap();
    let selected = policy.select(&selector, &reader).await?;
    assert_eq!(selected, node(2));
    Ok(())
  }

  // ---- checked route progress ----

  /// The carried path is followed exactly, hop by hop: each hop forwards
  /// to the next path entry (no policy runs), the previous holder joins
  /// the visited chain, and the destination ends the walk.
  #[test]
  fn the_carried_path_is_followed_hop_by_hop() {
    let trace = TraceId::generate(&crate::api::SystemEntropy).unwrap();
    // The envelope as node 2 receives it: the origin planned the whole
    // path, node 1 already handed the frame over, and the remaining path
    // is 3 -> 4 -> 5.
    let arriving = crate::routing::RouteContext::from_frame(
      trace.clone(),
      node(1),
      node(5),
      Some(super::HopState {
        current: node(1),
        visited: Vec::new(),
        remaining_hops: 4,
        path: vec![node(3), node(4), node(5)],
      }),
    );
    let mut context = arriving;
    for (local_index, next_index) in [(2_u8, 3_u8), (3, 4), (4, 5)] {
      let step = context
        .clone()
        // The plan closure must never run while the path has a head.
        .receive(&node(local_index), &node(local_index - 1), |_| {
          panic!("a carried path must not consult the policy")
        })
        .unwrap();
      context = match step {
        crate::routing::RouteProgress::Continue { next_hop, context } => {
          assert_eq!(next_hop, node(next_index));
          assert_eq!(context.current(), &node(local_index));
          assert_eq!(context.visited().len(), usize::from(local_index - 1));
          context
        }
        crate::routing::RouteProgress::Arrive => panic!("mid-route arrival"),
      };
    }
    assert_eq!(context.trace_id(), &trace);
    assert!(context.path().is_empty());
    // The destination ends the walk without needing budget or a plan.
    match context
      .receive(&node(5), &node(4), |_| panic!("arrival plans nothing"))
      .unwrap()
    {
      crate::routing::RouteProgress::Arrive => {}
      crate::routing::RouteProgress::Continue { .. } => panic!("expected arrival"),
    }
  }

  /// Arrival happens exactly at the selected destination; the budget bounds
  /// total route work independent of how many hops are attempted.
  #[test]
  fn budget_bounds_route_work_and_arrival_is_exact() {
    let origin = crate::routing::RouteContext::new(
      TraceId::generate(&crate::api::SystemEntropy).unwrap(),
      node(1),
      node(5),
      vec![node(2), node(3), node(4), node(5)],
      3,
    );
    // Walk the route 1 -> 2 -> 3 -> 4 under receiver validation: each hop
    // consumes exactly one unit of budget.
    let mut context = origin;
    for local_index in [2_u8, 3, 4] {
      let step = context
        .clone()
        .receive(&node(local_index), &node(local_index - 1), |_| {
          Ok(vec![node(local_index + 1)])
        })
        .unwrap();
      context = match step {
        crate::routing::RouteProgress::Continue { context, .. } => context,
        crate::routing::RouteProgress::Arrive => panic!("premature arrival"),
      };
    }
    assert_eq!(context.current(), &node(4));
    assert_eq!(context.remaining_hops(), 0);

    // Arrival at the selected destination never needs budget: the packet
    // ends here even with the budget exhausted.
    match context
      .clone()
      .receive(&node(5), &node(4), |_| Ok(vec![node(5)]))
      .unwrap()
    {
      crate::routing::RouteProgress::Arrive => {}
      crate::routing::RouteProgress::Continue { .. } => panic!("expected arrival"),
    }
    // But a detour through an exhausted budget is rejected explicitly.
    let error = context
      .receive(&node(6), &node(4), |_| Ok(vec![node(7)]))
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::ResourceExhausted);
  }

  // ---- bounded work independent of stream length ----

  /// The envelope's work bound is a pure function of the caller-selected
  /// budget: an unlearned hop-by-hop walk of arbitrary attempted length
  /// always stops within the budget, appending exactly once per successful
  /// hop with constant per-hop memory.
  #[test]
  fn envelope_work_is_bounded_by_the_selected_budget() {
    let max_hops = 7_u32;
    let destination = node(200);
    let mut context = crate::routing::RouteContext::new(
      TraceId::generate(&crate::api::SystemEntropy).unwrap(),
      node(1),
      destination.clone(),
      Vec::new(),
      max_hops,
    );
    // Attempt to walk an unbounded linear route 1 -> 2 -> 3 -> ...; the
    // envelope must stop forwarding after exactly `max_hops` advances.
    let mut successes = 0_u32;
    loop {
      let local_index = u8::try_from(successes + 2).unwrap();
      let peer = context.current().clone();
      let planned = destination.clone();
      match context
        .clone()
        .receive(&node(local_index), &peer, |_| Ok(vec![planned.clone()]))
      {
        Ok(crate::routing::RouteProgress::Continue {
          context: advanced, ..
        }) => {
          successes += 1;
          assert_eq!(advanced.visited().len(), successes as usize);
          context = advanced;
        }
        Ok(crate::routing::RouteProgress::Arrive) => panic!("unexpected arrival"),
        Err(error) => {
          assert_eq!(error.kind(), ErrorKind::ResourceExhausted);
          break;
        }
      }
    }
    assert_eq!(successes, max_hops);
    assert_eq!(context.visited().len(), usize::try_from(max_hops).unwrap());
  }

  // ---- the full selector grammar ----

  /// Every grammar operator parses and evaluates with the documented set
  /// semantics: equality and `in` require the key present; inequality and
  /// `notin` also match entries whose key is absent.
  #[test]
  fn all_operators_parse_and_evaluate() {
    let set = labels(&[("zone", "edge"), ("gpu", "yes")]);
    // Equality and existence.
    assert!(
      Selector::parse("radiata.woooo.tech/labels/zone=edge")
        .unwrap()
        .matches(&set)
    );
    assert!(
      !Selector::parse("radiata.woooo.tech/labels/zone=core")
        .unwrap()
        .matches(&set)
    );
    assert!(
      Selector::parse("radiata.woooo.tech/labels/gpu")
        .unwrap()
        .matches(&set)
    );
    // Inequality matches a different value and an absent key alike.
    assert!(
      Selector::parse("radiata.woooo.tech/labels/zone!=core")
        .unwrap()
        .matches(&set)
    );
    assert!(
      Selector::parse("radiata.woooo.tech/labels/ssd!=yes")
        .unwrap()
        .matches(&set)
    );
    assert!(
      !Selector::parse("radiata.woooo.tech/labels/zone!=edge")
        .unwrap()
        .matches(&set)
    );
    // Set membership requires presence; non-membership matches absence.
    assert!(
      Selector::parse("radiata.woooo.tech/labels/zone in (core,edge)")
        .unwrap()
        .matches(&set)
    );
    assert!(
      !Selector::parse("radiata.woooo.tech/labels/ssd in (yes)")
        .unwrap()
        .matches(&set)
    );
    assert!(
      Selector::parse("radiata.woooo.tech/labels/ssd notin (yes)")
        .unwrap()
        .matches(&set)
    );
    assert!(
      !Selector::parse("radiata.woooo.tech/labels/zone notin (core,edge)")
        .unwrap()
        .matches(&set)
    );
    // Non-existence.
    assert!(
      Selector::parse("!radiata.woooo.tech/labels/ssd")
        .unwrap()
        .matches(&set)
    );
    assert!(
      !Selector::parse("!radiata.woooo.tech/labels/gpu")
        .unwrap()
        .matches(&set)
    );
  }

  /// Equivalent whitespace and operand forms canonicalize to one text,
  /// while distinct operators and escaped values stay distinguishable and
  /// round-trip exactly through `as_str`.
  #[test]
  fn canonicalization_normalizes_and_round_trips() {
    let spaced =
      Selector::parse("  radiata.woooo.tech/labels/zone = edge   radiata.woooo.tech/labels/gpu  ")
        .unwrap();
    let compact =
      Selector::parse("radiata.woooo.tech/labels/gpu radiata.woooo.tech/labels/zone=edge").unwrap();
    assert_eq!(spaced, compact);
    assert_eq!(
      spaced.as_str(),
      "radiata.woooo.tech/labels/gpu radiata.woooo.tech/labels/zone=edge"
    );
    // Set member order and duplicates collapse into one canonical list.
    let set_a = Selector::parse("radiata.woooo.tech/labels/zone in ( edge, core ,edge )").unwrap();
    let set_b = Selector::parse("radiata.woooo.tech/labels/zone in (core,edge)").unwrap();
    assert_eq!(set_a, set_b);
    assert_eq!(
      set_a.as_str(),
      "radiata.woooo.tech/labels/zone in (core,edge)"
    );
    // Exact duplicate predicates deduplicate.
    let duplicated =
      Selector::parse("radiata.woooo.tech/labels/gpu radiata.woooo.tech/labels/gpu").unwrap();
    assert_eq!(duplicated.as_str(), "radiata.woooo.tech/labels/gpu");

    // Distinct operators stay distinct.
    let equality = Selector::parse("radiata.woooo.tech/labels/zone=edge").unwrap();
    let inequality = Selector::parse("radiata.woooo.tech/labels/zone!=edge").unwrap();
    let membership = Selector::parse("radiata.woooo.tech/labels/zone in (edge)").unwrap();
    assert_ne!(equality, inequality);
    assert_ne!(equality, membership);
    assert_ne!(inequality, membership);

    // Escaped values round-trip exactly and stay distinct from their
    // unescaped counterparts.
    let escaped = Selector::parse("example.org/labels/note=x\\ y\\\\z").unwrap();
    assert_eq!(escaped.as_str(), "example.org/labels/note=x\\ y\\\\z");
    assert_eq!(Selector::parse(escaped.as_str()).unwrap(), escaped);
    assert!(escaped.matches(&{
      let mut set = LabelSet::new();
      set = set
        .insert(
          LabelKey::parse("example.org/labels/note").unwrap(),
          LabelValue::parse("x y\\z").unwrap(),
        )
        .unwrap();
      set
    }));
    assert!(
      !escaped.matches(&labels(&[])),
      "the escaped value is absent from an empty label set"
    );
    let plain = Selector::parse("example.org/labels/note=xyz").unwrap();
    assert_ne!(escaped, plain);
  }

  /// Grammar bounds hold: over-limit input, predicates, set members, and
  /// values are rejected with typed errors, and malformed shapes fail
  /// closed without panic.
  #[test]
  fn grammar_bounds_reject_overlimit_and_malformed_input() {
    // Input byte limit.
    let oversized = format!(
      "radiata.woooo.tech/labels/a in ({})",
      (0..300)
        .map(|index| format!("v{index}"))
        .collect::<Vec<_>>()
        .join(",")
    );
    assert!(oversized.len() > super::SELECTOR_INPUT_MAX_BYTES);
    assert_eq!(
      Selector::parse(&oversized).unwrap_err().kind(),
      ErrorKind::InvalidInput
    );
    // Canonical-form limit (selector fuzz finding): a set's
    // closing parenthesis may directly abut the next predicate with no
    // whitespace, and the canonical form inserts the separator space, so
    // an input within the raw byte bound can canonicalize past the same
    // bound. Such an input fails closed instead of shipping a selector
    // whose own canonical text cannot reparse. Eight notin pairs sit one
    // byte under the raw bound and one over the canonical bound.
    let key = |index: usize| format!("radiata.woooo.tech/labels/{}{index:0>2}", "a".repeat(30));
    let expands = (0..8)
      .map(|index| format!("{} notin (ed){}", key(index), key(index + 16)))
      .collect::<Vec<_>>()
      .join(" ");
    assert!(expands.len() <= super::SELECTOR_INPUT_MAX_BYTES);
    assert_eq!(
      Selector::parse(&expands).unwrap_err().kind(),
      ErrorKind::InvalidInput
    );
    // With the whitespace present the same shape fits both bounds and
    // the canonical text stays a reparse fixed point.
    let fits = (0..7)
      .map(|index| format!("{} notin (ed) {}", key(index), key(index + 16)))
      .collect::<Vec<_>>()
      .join(" ");
    assert!(fits.len() <= super::SELECTOR_INPUT_MAX_BYTES);
    let selector = Selector::parse(&fits).unwrap();
    assert!(selector.as_str().len() <= super::SELECTOR_INPUT_MAX_BYTES);
    assert_eq!(
      Selector::parse(selector.as_str()).unwrap().as_str(),
      selector.as_str()
    );
    // Predicate count limit.
    let many = (0..super::SELECTOR_MAX_PREDICATES + 1)
      .map(|index| format!("radiata.woooo.tech/labels/p{index:02}"))
      .collect::<Vec<_>>()
      .join(" ");
    assert_eq!(
      Selector::parse(&many).unwrap_err().kind(),
      ErrorKind::ResourceExhausted
    );
    // Set member limit (within the input budget).
    let members = (0..super::SELECTOR_MAX_SET_VALUES + 1)
      .map(|index| format!("v{index}"))
      .collect::<Vec<_>>()
      .join(",");
    assert_eq!(
      Selector::parse(&format!("example.org/labels/s in ({members})"))
        .unwrap_err()
        .kind(),
      ErrorKind::ResourceExhausted
    );
    // Value length limit.
    let long = "x".repeat(crate::label::LABEL_VALUE_MAX_BYTES + 1);
    assert_eq!(
      Selector::parse(&format!("example.org/labels/v={long}"))
        .unwrap_err()
        .kind(),
      ErrorKind::InvalidInput
    );
    // Malformed shapes fail closed.
    for malformed in [
      "radiata.woooo.tech/labels/a=(",
      "radiata.woooo.tech/labels/a in (",
      "radiata.woooo.tech/labels/a in (1,",
      "radiata.woooo.tech/labels/a in ()",
      "radiata.woooo.tech/labels/a in (1 2)",
      "radiata.woooo.tech/labels/a in (,1)",
      "radiata.woooo.tech/labels/a in (1,)",
      "radiata.woooo.tech/labels/a in ((1))",
      "radiata.woooo.tech/labels/a=",
      "radiata.woooo.tech/labels/a!",
      "radiata.woooo.tech/labels/a! =1",
      "!",
      "radiata.woooo.tech/labels/a=b=c",
      "radiata.woooo.tech/labels/a=bad\\q",
      "radiata.woooo.tech/features/not-a-label",
      "radiata.woooo.tech/resources/other=x",
    ] {
      assert!(
        Selector::parse(malformed).is_err(),
        "malformed selector must fail closed: {malformed:?}"
      );
    }
  }

  // ---- evaluator semantics against a reference ----

  /// One generated predicate with its independently computed reference
  /// semantics.
  #[derive(Clone, Debug)]
  enum RefPredicate {
    Exists(String),
    NotExists(String),
    Equals(String, String),
    NotEquals(String, String),
    In(String, Vec<String>),
    NotIn(String, Vec<String>),
  }

  /// The reference escaping, written directly from the documented escape
  /// set (independent of the implementation's encoder).
  fn ref_escape(value: &str) -> String {
    let mut out = String::new();
    for character in value.chars() {
      match character {
        ' ' => out.push_str("\\ "),
        '\t' => out.push_str("\\t"),
        '\n' => out.push_str("\\n"),
        '\r' => out.push_str("\\r"),
        '\\' | ',' | '(' | ')' | '=' | '!' => {
          out.push('\\');
          out.push(character);
        }
        _ => out.push(character),
      }
    }
    out
  }

  impl RefPredicate {
    fn text(&self) -> String {
      match self {
        Self::Exists(key) => key.clone(),
        Self::NotExists(key) => format!("!{key}"),
        Self::Equals(key, value) => format!("{key}={}", ref_escape(value)),
        Self::NotEquals(key, value) => format!("{key}!={}", ref_escape(value)),
        Self::In(key, values) => format!(
          "{key} in ({})",
          values
            .iter()
            .map(|value| ref_escape(value))
            .collect::<Vec<_>>()
            .join(",")
        ),
        Self::NotIn(key, values) => format!(
          "{key} notin ({})",
          values
            .iter()
            .map(|value| ref_escape(value))
            .collect::<Vec<_>>()
            .join(",")
        ),
      }
    }

    /// The reference evaluator: direct boolean logic over the label map.
    fn expected(&self, map: &std::collections::BTreeMap<String, String>) -> bool {
      match self {
        Self::Exists(key) => map.contains_key(key),
        Self::NotExists(key) => !map.contains_key(key),
        Self::Equals(key, value) => map.get(key) == Some(value),
        Self::NotEquals(key, value) => map.get(key).is_none_or(|found| found != value),
        Self::In(key, values) => map.get(key).is_some_and(|found| values.contains(found)),
        Self::NotIn(key, values) => map.get(key).is_none_or(|found| !values.contains(found)),
      }
    }
  }

  /// The selector key space for the property: custom labels across two
  /// caller domains plus both reserved resource labels.
  fn arb_key() -> impl proptest::strategy::Strategy<Value = String> {
    proptest::sample::select(vec![
      "radiata.woooo.tech/labels/zone",
      "example.org/labels/owner",
      "radiata.woooo.tech/resources/type",
      "radiata.woooo.tech/resources/uri",
    ])
    .prop_map(str::to_owned)
  }

  /// Values include characters that require escaping, so the property
  /// exercises the escape round-trip on every operator.
  fn arb_value() -> impl proptest::strategy::Strategy<Value = String> {
    proptest::sample::select(vec![
      "edge",
      "core",
      "gold",
      "x y",
      "a,b",
      "eq=v",
      "bang!",
      "p(aren)",
      "tab\there",
    ])
    .prop_map(str::to_owned)
  }

  fn arb_predicate() -> impl proptest::strategy::Strategy<Value = RefPredicate> {
    use proptest::prelude::*;
    (arb_key(), arb_value(), 0..6_u8)
      .prop_flat_map(|(key, value, variant)| {
        let set = proptest::collection::vec(arb_value(), 1..=3);
        (Just((key, value, variant)), set)
      })
      .prop_map(|((key, value, variant), values)| match variant {
        0 => RefPredicate::Exists(key),
        1 => RefPredicate::NotExists(key),
        2 => RefPredicate::Equals(key, value),
        3 => RefPredicate::NotEquals(key, value),
        4 => RefPredicate::In(key, values),
        _ => RefPredicate::NotIn(key, values),
      })
  }

  proptest::proptest! {
    /// The implementation matches the reference evaluator over absent,
    /// present, and overwritten (duplicate-assignment) labels for every
    /// grammar operator, and the canonical text reparses to an equal
    /// selector.
    #[test]
    fn evaluator_matches_reference_over_generated_label_spaces(
      predicates in proptest::collection::vec(arb_predicate(), 1..=8),
      assignments in proptest::collection::vec((arb_key(), arb_value()), 0..=6),
    ) {
      // Duplicate assignments overwrite: the map reflects the final
      // converged state of the applied update sequence.
      let map: std::collections::BTreeMap<String, String> =
        assignments.into_iter().collect();
      let text = predicates.iter().map(RefPredicate::text).collect::<Vec<_>>().join(" ");
      let selector = Selector::parse(&text).unwrap();
      let expected = predicates.iter().all(|predicate| predicate.expected(&map));
      let actual = selector.matches_with(|tag| map.get(tag.as_str()).map(String::as_str));
      proptest::prop_assert_eq!(actual, expected);
      proptest::prop_assert_eq!(Selector::parse(selector.as_str()).unwrap(), selector);
    }

    /// Hostile and malformed inputs never panic and never exceed the
    /// documented bounds.
    #[test]
    fn hostile_selector_input_never_panics(input in ".{0,1100}") {
      let result = std::panic::catch_unwind(|| Selector::parse(&input));
      proptest::prop_assert!(result.is_ok());
      if let Ok(Ok(selector)) = result {
        proptest::prop_assert!(selector.as_str().len() <= super::SELECTOR_INPUT_MAX_BYTES);
        proptest::prop_assert_eq!(Selector::parse(selector.as_str()).unwrap(), selector);
      }
    }
  }
}
