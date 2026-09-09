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
//! trace, both route endpoints, the current upstream holder, the visited
//! chain, and the remaining hop budget. Every receiving node re-validates
//! the context against its session-authenticated peer before any
//! forwarding work, so mutation of the trace, endpoints, protocol,
//! metadata, or any route field fails closed before a body byte moves.
//! Authenticity comes from the mutually authenticated session transcript
//! (exporter binding): each hop proves the context was produced
//! by the peer it claims, and the canonical wire encoding rejects every
//! mutation.

use std::{collections::BTreeSet, fmt, sync::Arc};

use crate::{Error, NodeId, QualifiedTag, Result, api::BoxFuture};

pub(crate) mod forward;
pub(crate) mod table;
pub(crate) mod trace;

pub(crate) use table::{RouteTable, insert_route};

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
      "labels" => Ok(tag),
      "resources"
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
    if value.is_empty() || value.len() > crate::label::LABEL_VALUE_MAX_BYTES {
      return Err(Error::invalid_input("selector value"));
    }
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
  visited: Vec<NodeId>,
  remaining_hops: u32,
}

impl RouteContext {
  /// Builds the origin envelope: the source holds the packet and the full
  /// caller-selected budget remains.
  pub(crate) fn new(
    trace_id: crate::TraceId, source: NodeId, destination: NodeId, max_hops: u32,
  ) -> Self {
    Self {
      trace_id,
      current: source.clone(),
      source,
      destination,
      visited: Vec::new(),
      remaining_hops: max_hops,
    }
  }

  pub fn trace_id(&self) -> &crate::TraceId {
    &self.trace_id
  }

  pub fn source(&self) -> &NodeId {
    &self.source
  }

  /// The selected destination: the exact target node or the node the
  /// registered load balancer selected for a matching-label target.
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

  /// Projects the wire-carried per-hop state out of the envelope.
  pub(crate) fn hop_state(&self) -> HopState {
    HopState {
      current: self.current.clone(),
      visited: self.visited.clone(),
      remaining_hops: self.remaining_hops,
    }
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
      }) => Self {
        trace_id,
        source,
        destination,
        current,
        visited,
        remaining_hops,
      },
      None => Self::new(trace_id, source, destination, 1),
    }
  }

  /// Validates this envelope at the receiving node `local` against its
  /// session-authenticated `peer`, then produces the checked progress
  /// decision. Every rejection happens before any forwarding work:
  ///
  /// - the authenticated session peer must be the claimed current holder, so
  ///   endpoint substitutions fail closed (`NotTrusted`);
  /// - the visited chain must start at the source, stay duplicate-free, and
  ///   never claim the local node (loop detection fails closed);
  /// - forwarding requires budget left (`ResourceExhausted`) and exactly one
  ///   caller-policy-selected next hop, which may not revisit any chain member
  ///   or the local node.
  ///
  /// The `choose_next` closure is the caller's single next-hop decision
  /// (the registered routing/load-balancing policy at a forwarder); core
  /// re-validates whatever it returns.
  pub(crate) fn receive(
    self, local: &NodeId, peer: &NodeId, choose_next: impl FnOnce(&Self) -> Result<NodeId>,
  ) -> Result<RouteProgress> {
    // Loop detection first: the receiving node must not appear anywhere in
    // the chain (including as the claimed sender), and the chain itself
    // must be duplicate-free.
    if self.current == *local || self.visited.contains(local) {
      return Err(Error::conflict("route loop"));
    }
    let mut seen = BTreeSet::new();
    for node in &self.visited {
      if !seen.insert(node.clone()) {
        return Err(Error::conflict("route loop"));
      }
    }
    // The chain must start at the authenticated source.
    if self
      .visited
      .first()
      .is_some_and(|first| *first != self.source)
    {
      return Err(Error::invalid_input("route chain"));
    }
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
    let next_hop = choose_next(&self);
    // The chosen hop must make forward progress: it cannot revisit any
    // chain member, the current holder, or loop back to this node.
    if let Ok(hop) = &next_hop
      && (hop == local || *hop == self.current || *hop == self.source || self.visited.contains(hop))
    {
      return Err(Error::conflict("route loop"));
    }
    let next_hop = next_hop?;
    Ok(RouteProgress::Continue {
      next_hop,
      context: self.forward(local),
    })
  }

  /// Marks this envelope as having been forwarded by `local`: the previous
  /// holder joins the visited chain, `local` becomes the current holder,
  /// and the budget decreases once. Called only through
  /// [`Self::receive`]'s checked continuation.
  fn forward(mut self, local: &NodeId) -> Self {
    let previous = std::mem::replace(&mut self.current, local.clone());
    self.visited.push(previous);
    self.remaining_hops = self.remaining_hops.saturating_sub(1);
    self
  }
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
      let limit = limit.clamp(1, crate::membership::page::DEFAULT_PAGE_LIMIT);
      let namespace = crate::StoreNamespace::new(crate::QualifiedTag::parse(
        crate::membership::NODE_DESCRIPTOR_NAMESPACE,
      )?);
      let mut scan = self.snapshot.scan(&namespace, &[]).await?;
      let paged = crate::paging::scan_paged(
        scan.as_mut(),
        cursor.as_ref().map(|cursor| cursor.as_bytes()),
        limit,
        |_key, bytes| {
          let Ok(descriptor) = crate::membership::page::decode_descriptor(bytes) else {
            return Ok(None);
          };
          if descriptor.removed() || !selector.matches(descriptor.labels()) {
            return Ok(None);
          }
          crate::membership::member_view(&descriptor, crate::ConnectivityStatus::Unknown).map(Some)
        },
      )
      .await?;
      let next = paged
        .next
        .map(|key| crate::PageCursor::new(std::sync::Arc::from(key)));
      Ok(crate::MemberPage::new(paged.items, next))
    })
  }
}

/// The sealed per-hop decision inputs handed to a registered
/// [`RouteNextHop`] policy: the final destination, this node, and the
/// live session peers available as next hops (canonical order).
#[derive(Debug)]
pub struct NextHopView<'a> {
  pub(crate) destination: &'a NodeId,
  pub(crate) local: &'a NodeId,
  pub(crate) peers: &'a [NodeId],
}

impl NextHopView<'_> {
  pub fn destination(&self) -> &NodeId {
    self.destination
  }

  pub fn local(&self) -> &NodeId {
    self.local
  }

  /// The live authenticated peers eligible as next hops.
  pub fn peers(&self) -> &[NodeId] {
    self.peers
  }
}

/// The node-registered policy that picks the single next hop for a routed
/// packet whose destination is not directly connected. Implementations run
/// at every forwarding node under bounded work; returning a NodeId outside
/// [`NextHopView::peers`] fails closed at the route boundary.
pub trait RouteNextHop: fmt::Debug + Send + Sync + 'static {
  fn next_hop<'a>(&'a self, view: NextHopView<'a>) -> BoxFuture<'a, Result<NodeId>>;
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
    NodeId::parse(&format!("node_{value:021}")).unwrap()
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
      4,
    );
    // The envelope claims node(1) is the holder, but the authenticated
    // session peer is node(9): an endpoint substitution.
    let error = context
      .receive(&node(2), &node(9), |_| Ok(node(3)))
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::NotTrusted);
  }

  /// A visited chain that does not start at the source, or that loops back
  /// through a chain member, cannot pass validation.
  #[test]
  fn mutated_chain_fails_closed() {
    // A forged chain whose first entry no longer matches the source.
    let forged = crate::routing::RouteContext {
      trace_id: TraceId::generate(&crate::api::SystemEntropy).unwrap(),
      source: node(1),
      destination: node(4),
      current: node(3),
      visited: vec![node(9), node(2)],
      remaining_hops: 2,
    };
    let error = forged
      .receive(&node(5), &node(3), |_| Ok(node(4)))
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidInput);

    // A duplicate entry in the chain is rejected as a loop.
    let duplicated = crate::routing::RouteContext {
      trace_id: TraceId::generate(&crate::api::SystemEntropy).unwrap(),
      source: node(1),
      destination: node(4),
      current: node(3),
      visited: vec![node(1), node(1)],
      remaining_hops: 2,
    };
    let error = duplicated
      .receive(&node(5), &node(3), |_| Ok(node(4)))
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Conflict);

    // A frame routed back to its own source cannot pass loop detection:
    // the receiving node already appears in the chain.
    let origin = crate::routing::RouteContext::new(
      TraceId::generate(&crate::api::SystemEntropy).unwrap(),
      node(1),
      node(4),
      4,
    );
    let walked = match origin
      .clone()
      .receive(&node(2), &node(1), |_| Ok(node(3)))
      .unwrap()
    {
      crate::routing::RouteProgress::Continue { context, .. } => context,
      crate::routing::RouteProgress::Arrive => panic!("mid-route arrival"),
    };
    let error = walked
      .receive(&node(1), &node(2), |_| Ok(node(4)))
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Conflict);
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
      false,
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

  /// Every hop advances exactly once along one chosen next edge; loop
  /// attempts through chain members fail closed.
  #[test]
  fn checked_progress_advances_once_and_rejects_loops() {
    let origin = crate::routing::RouteContext::new(
      TraceId::generate(&crate::api::SystemEntropy).unwrap(),
      node(1),
      node(5),
      4,
    );
    // Node 2 receives from the authenticated source and forwards to 3.
    let trace = origin.trace_id().clone();
    let step = origin.receive(&node(2), &node(1), |_| Ok(node(3))).unwrap();
    let second = match step {
      crate::routing::RouteProgress::Continue { next_hop, context } => {
        assert_eq!(next_hop, node(3));
        assert_eq!(context.current(), &node(2));
        assert_eq!(context.visited(), &[node(1)]);
        context
      }
      crate::routing::RouteProgress::Arrive => panic!("mid-route arrival"),
    };
    // Node 3 receives from node 2 and forwards to 4.
    let third = match second.receive(&node(3), &node(2), |_| Ok(node(4))).unwrap() {
      crate::routing::RouteProgress::Continue { next_hop, context } => {
        assert_eq!(next_hop, node(4));
        assert_eq!(context.visited(), &[node(1), node(2)]);
        context
      }
      crate::routing::RouteProgress::Arrive => panic!("mid-route arrival"),
    };
    assert_eq!(third.trace_id(), &trace);

    // A forwarder choosing an edge back into the chain fails closed.
    let error = third
      .clone()
      .receive(&node(4), &node(3), |_| Ok(node(1)))
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Conflict);
    // Choosing this very node as next hop is a self-loop.
    let error = third
      .receive(&node(4), &node(3), |_| Ok(node(4)))
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Conflict);
  }

  /// Arrival happens exactly at the selected destination; the budget bounds
  /// total route work independent of how many hops are attempted.
  #[test]
  fn budget_bounds_route_work_and_arrival_is_exact() {
    let origin = crate::routing::RouteContext::new(
      TraceId::generate(&crate::api::SystemEntropy).unwrap(),
      node(1),
      node(5),
      3,
    );
    // Walk the route 1 -> 2 -> 3 -> 4 under receiver validation: each hop
    // consumes exactly one unit of budget.
    let mut context = origin;
    for local_index in [2_u8, 3, 4] {
      let step = context
        .clone()
        .receive(&node(local_index), &node(local_index - 1), |_| {
          Ok(node(local_index + 1))
        })
        .unwrap();
      context = match step {
        crate::routing::RouteProgress::Continue { context, .. } => context,
        crate::routing::RouteProgress::Arrive => panic!("premature arrival"),
      };
    }
    assert_eq!(context.current(), &node(4));

    // Arrival at the selected destination never needs budget: the packet
    // ends here even with the budget exhausted.
    match context
      .clone()
      .receive(&node(5), &node(4), |_| Ok(node(1)))
      .unwrap()
    {
      crate::routing::RouteProgress::Arrive => {}
      crate::routing::RouteProgress::Continue { .. } => panic!("expected arrival"),
    }
    // But a detour through an exhausted budget is rejected explicitly.
    let error = context
      .receive(&node(6), &node(4), |_| Ok(node(7)))
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::ResourceExhausted);
  }

  // ---- bounded work independent of stream length ----

  /// The envelope's work bound is a pure function of the caller-selected
  /// budget: generated chains of arbitrary attempted length always stop
  /// within the budget, appending exactly once per successful hop with
  /// constant per-hop memory.
  #[test]
  fn envelope_work_is_bounded_by_the_selected_budget() {
    let max_hops = 7_u32;
    let mut context = crate::routing::RouteContext::new(
      TraceId::generate(&crate::api::SystemEntropy).unwrap(),
      node(1),
      node(200),
      max_hops,
    );
    // Attempt to walk an unbounded linear route 1 -> 2 -> 3 -> ...; the
    // envelope must stop forwarding after exactly `max_hops` advances.
    let mut successes = 0_u32;
    loop {
      let local_index = u8::try_from(successes + 2).unwrap();
      let next = local_index + 1;
      let peer = context.current().clone();
      match context
        .clone()
        .receive(&node(local_index), &peer, |_| Ok(node(next)))
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
