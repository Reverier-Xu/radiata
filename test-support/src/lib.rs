#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use std::collections::{BTreeMap, VecDeque};

pub mod ledger;

use sha2::{Digest as ShaDigest, Sha256};

pub const MAX_ARTIFACT_BYTES: usize = 1_048_576;
pub const MAX_RETAINED_EVENTS: usize = 10_000;
const EVENT_DIGEST_DOMAIN: &[u8] = b"radiata.woooo.tech/failure-replay/event-stream/v2";
const FAILURE_SCHEMA: &str = "radiata.woooo.tech/schemas/failure-replay";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForbiddenFieldClass {
  Credential,
  PrivateKey,
  ProviderHandle,
  Proof,
  Hmac,
  Exporter,
  TlsTicket,
  Transcript,
  Payload,
  PayloadDigest,
  OpaqueValue,
  ResourceLabel,
  ResourceValue,
  Selector,
  RealAddress,
  HostPath,
  Environment,
  ArbitraryError,
  HostileText,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AliasKind {
  Node,
  Endpoint,
  Path,
  Fault,
}

impl AliasKind {
  const fn prefix(self) -> &'static str {
    match self {
      Self::Node => "node",
      Self::Endpoint => "endpoint",
      Self::Path => "path",
      Self::Fault => "fault",
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Alias {
  kind: AliasKind,
  ordinal: u16,
}

impl Alias {
  pub const fn kind(self) -> AliasKind {
    self.kind
  }

  pub const fn ordinal(self) -> u16 {
    self.ordinal
  }

  pub fn render(self) -> String {
    format!("{}-{}", self.kind.prefix(), self.ordinal)
  }
}

pub struct AliasTable<T> {
  kind: AliasKind,
  sources: BTreeMap<T, Alias>,
}

impl<T: Copy + Ord> AliasTable<T> {
  pub const fn new(kind: AliasKind) -> Self {
    Self {
      kind,
      sources: BTreeMap::new(),
    }
  }

  pub fn register(&mut self, source: T) -> Result<Alias, SourceError> {
    if self.sources.contains_key(&source) {
      return Err(SourceError::DuplicateSource(self.kind));
    }
    let ordinal = self
      .sources
      .len()
      .checked_add(1)
      .and_then(|value| u16::try_from(value).ok())
      .ok_or(SourceError::AliasCapacity(self.kind))?;
    let alias = Alias {
      kind: self.kind,
      ordinal,
    };
    self.sources.insert(source, alias);
    Ok(alias)
  }

  pub fn resolve(&self, source: T) -> Result<Alias, SourceError> {
    self
      .sources
      .get(&source)
      .copied()
      .ok_or(SourceError::UnknownAlias(self.kind))
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceError {
  ForbiddenField(ForbiddenFieldClass),
  UnknownAlias(AliasKind),
  DuplicateSource(AliasKind),
  AliasCapacity(AliasKind),
  InvalidEventIndex,
  InvalidNormalizedEvent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NormalizedDropReason {
  Blocked,
  StaleLink,
  StaleBoot,
  StaleAddress,
}

impl NormalizedDropReason {
  const fn as_str(self) -> &'static str {
    match self {
      Self::Blocked => "blocked",
      Self::StaleLink => "stale-link",
      Self::StaleBoot => "stale-boot",
      Self::StaleAddress => "stale-address",
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EventKind {
  CheckpointReached,
  SendAccepted,
  Lost,
  DuplicateCreated,
  Reordered,
  Delivered,
  Dropped,
  Partitioned,
  Healed,
  Restarted,
  AddressChanged,
  WallClockChanged,
  QueueRejected,
}

impl EventKind {
  const fn as_str(self) -> &'static str {
    match self {
      Self::CheckpointReached => "checkpoint-reached",
      Self::SendAccepted => "send-accepted",
      Self::Lost => "lost",
      Self::DuplicateCreated => "duplicate-created",
      Self::Reordered => "reordered",
      Self::Delivered => "delivered",
      Self::Dropped => "dropped",
      Self::Partitioned => "partitioned",
      Self::Healed => "healed",
      Self::Restarted => "restarted",
      Self::AddressChanged => "address-changed",
      Self::WallClockChanged => "wall-clock-changed",
      Self::QueueRejected => "queue-rejected",
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NormalizedEvent {
  CheckpointReached {
    at_nanos: u64,
    component: EvidenceId,
    checkpoint: EvidenceId,
  },
  SendAccepted {
    at_nanos: u64,
    frame_id: u64,
    path: Alias,
    copies: u8,
    frame_bytes: u32,
  },
  Lost {
    at_nanos: u64,
    frame_id: u64,
  },
  DuplicateCreated {
    at_nanos: u64,
    frame_id: u64,
  },
  Reordered {
    at_nanos: u64,
    frame_id: u64,
    copy: u8,
  },
  Delivered {
    at_nanos: u64,
    frame_id: u64,
    copy: u8,
  },
  Dropped {
    at_nanos: u64,
    frame_id: u64,
    copy: u8,
    reason: NormalizedDropReason,
  },
  Partitioned {
    at_nanos: u64,
    path: Alias,
    fault: Alias,
    generation: u32,
  },
  Healed {
    at_nanos: u64,
    path: Alias,
    fault: Alias,
    generation: u32,
  },
  Restarted {
    at_nanos: u64,
    node: Alias,
    boot_epoch: u32,
  },
  AddressChanged {
    at_nanos: u64,
    node: Alias,
    endpoint: Alias,
    generation: u32,
  },
  WallClockChanged {
    at_nanos: u64,
    node: Alias,
    previous: u64,
    current: u64,
  },
  QueueRejected {
    at_nanos: u64,
    frame_id: u64,
    copies: u8,
    frame_bytes: u32,
  },
}

impl NormalizedEvent {
  pub const fn checkpoint_reached(
    at_nanos: u64, component: EvidenceId, checkpoint: EvidenceId,
  ) -> Self {
    Self::CheckpointReached {
      at_nanos,
      component,
      checkpoint,
    }
  }

  const fn kind(self) -> EventKind {
    match self {
      Self::CheckpointReached { .. } => EventKind::CheckpointReached,
      Self::SendAccepted { .. } => EventKind::SendAccepted,
      Self::Lost { .. } => EventKind::Lost,
      Self::DuplicateCreated { .. } => EventKind::DuplicateCreated,
      Self::Reordered { .. } => EventKind::Reordered,
      Self::Delivered { .. } => EventKind::Delivered,
      Self::Dropped { .. } => EventKind::Dropped,
      Self::Partitioned { .. } => EventKind::Partitioned,
      Self::Healed { .. } => EventKind::Healed,
      Self::Restarted { .. } => EventKind::Restarted,
      Self::AddressChanged { .. } => EventKind::AddressChanged,
      Self::WallClockChanged { .. } => EventKind::WallClockChanged,
      Self::QueueRejected { .. } => EventKind::QueueRejected,
    }
  }

  const fn at_nanos(self) -> u64 {
    match self {
      Self::CheckpointReached { at_nanos, .. }
      | Self::SendAccepted { at_nanos, .. }
      | Self::Lost { at_nanos, .. }
      | Self::DuplicateCreated { at_nanos, .. }
      | Self::Reordered { at_nanos, .. }
      | Self::Delivered { at_nanos, .. }
      | Self::Dropped { at_nanos, .. }
      | Self::Partitioned { at_nanos, .. }
      | Self::Healed { at_nanos, .. }
      | Self::Restarted { at_nanos, .. }
      | Self::AddressChanged { at_nanos, .. }
      | Self::WallClockChanged { at_nanos, .. }
      | Self::QueueRejected { at_nanos, .. } => at_nanos,
    }
  }

  fn validate_alias_roles(self) -> Result<(), SourceError> {
    let require = |alias: Alias, expected: AliasKind| {
      if alias.kind() == expected {
        Ok(())
      } else {
        Err(SourceError::InvalidNormalizedEvent)
      }
    };
    match self {
      Self::SendAccepted { path, .. } => require(path, AliasKind::Path),
      Self::Partitioned { path, fault, .. } | Self::Healed { path, fault, .. } => {
        require(path, AliasKind::Path)?;
        require(fault, AliasKind::Fault)
      }
      Self::Restarted { node, .. } | Self::WallClockChanged { node, .. } => {
        require(node, AliasKind::Node)
      }
      Self::AddressChanged { node, endpoint, .. } => {
        require(node, AliasKind::Node)?;
        require(endpoint, AliasKind::Endpoint)
      }
      _ => Ok(()),
    }
  }
}

pub trait NormalizedEventSource {
  fn prevalidated_events(
    &self,
  ) -> Result<
    Box<dyn ExactSizeIterator<Item = Result<NormalizedEvent, SourceError>> + '_>,
    SourceError,
  >;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvidenceId(&'static str);

impl EvidenceId {
  pub fn new(value: &'static str) -> Result<Self, MetadataError> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
      || bytes.len() > 64
      || !bytes[0].is_ascii_alphanumeric()
      || bytes
        .iter()
        .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_')))
    {
      return Err(MetadataError::InvalidEvidenceId);
    }
    Ok(Self(value))
  }

  pub const fn as_str(self) -> &'static str {
    self.0
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProducerKind {
  Property,
  Simulation,
  Fuzz,
  Crash,
  E2e,
  Soak,
}

impl ProducerKind {
  pub const ALL: [Self; 6] = [
    Self::Property,
    Self::Simulation,
    Self::Fuzz,
    Self::Crash,
    Self::E2e,
    Self::Soak,
  ];

  const fn as_str(self) -> &'static str {
    match self {
      Self::Property => "property",
      Self::Simulation => "simulation",
      Self::Fuzz => "fuzz",
      Self::Crash => "crash",
      Self::E2e => "e2e",
      Self::Soak => "soak",
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureClass {
  Assertion,
  Invariant,
  Panic,
  Timeout,
  Capacity,
}

impl FailureClass {
  const fn as_str(self) -> &'static str {
    match self {
      Self::Assertion => "assertion",
      Self::Invariant => "invariant",
      Self::Panic => "panic",
      Self::Timeout => "timeout",
      Self::Capacity => "capacity",
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataError {
  InvalidEvidenceId,
  InvalidHex,
  ReplayProducerMismatch,
  ReplaySeedMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutableId {
  CargoTest,
  Simulation,
  FuzzCorpus,
}

impl ExecutableId {
  pub const fn as_str(self) -> &'static str {
    match self {
      Self::CargoTest => "cargo-test",
      Self::Simulation => "simulation",
      Self::FuzzCorpus => "fuzz-corpus",
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CargoTestId {
  FailureArtifactSecurity,
}

impl CargoTestId {
  const fn filter(self) -> &'static str {
    match self {
      Self::FailureArtifactSecurity => "simulation_failure_artifact_security",
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FuzzTarget {
  WireDecode,
  PersistedDecode,
  Selector,
  Admission,
  FeatureSelection,
  Routing,
}

impl FuzzTarget {
  const fn as_str(self) -> &'static str {
    match self {
      Self::WireDecode => "wire_decode",
      Self::PersistedDecode => "persisted_decode",
      Self::Selector => "selector",
      Self::Admission => "admission",
      Self::FeatureSelection => "feature_selection",
      Self::Routing => "routing",
    }
  }

  fn parse(value: &str) -> Option<Self> {
    match value {
      "wire_decode" => Some(Self::WireDecode),
      "persisted_decode" => Some(Self::PersistedDecode),
      "selector" => Some(Self::Selector),
      "admission" => Some(Self::Admission),
      "feature_selection" => Some(Self::FeatureSelection),
      "routing" => Some(Self::Routing),
      _ => None,
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApprovedCorpusDigest([u8; 32]);

impl ApprovedCorpusDigest {
  pub const fn from_reviewed_bytes(bytes: [u8; 32]) -> Self {
    Self(bytes)
  }

  fn parse(value: &str) -> Result<Self, ReplayError> {
    let mut bytes = [0_u8; 32];
    decode_lower_hex(value, &mut bytes).map_err(|_| ReplayError::InvalidSpec)?;
    Ok(Self(bytes))
  }

  fn as_hex(self) -> String {
    encode_hex(&self.0)
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReplayKind {
  CargoTest(CargoTestId),
  SimulationNetworkFaultMatrix {
    seed: u64,
  },
  FuzzCorpus {
    target: FuzzTarget,
    digest: ApprovedCorpusDigest,
  },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplaySpec {
  kind: ReplayKind,
}

const SIMULATION_MATRIX_REPLAY_TEST: &str =
  "simulation::network::tests::simulation_network_fault_matrix_replay_exact_seed";

impl ReplaySpec {
  pub const fn cargo_test(test: CargoTestId) -> Self {
    Self {
      kind: ReplayKind::CargoTest(test),
    }
  }

  pub const fn simulation_network_fault_matrix(seed: u64) -> Self {
    Self {
      kind: ReplayKind::SimulationNetworkFaultMatrix { seed },
    }
  }

  pub const fn fuzz_corpus(target: FuzzTarget, digest: ApprovedCorpusDigest) -> Self {
    Self {
      kind: ReplayKind::FuzzCorpus { target, digest },
    }
  }

  pub fn parse<T: AsRef<str>>(executable_id: &str, argv: &[T]) -> Result<Self, ReplayError> {
    match executable_id {
      "cargo-test" => parse_cargo_test(argv),
      "simulation" => parse_simulation(argv),
      "fuzz-corpus" => parse_fuzz_corpus(argv),
      _ => Err(ReplayError::InvalidSpec),
    }
  }

  pub const fn executable_id(&self) -> ExecutableId {
    match self.kind {
      ReplayKind::CargoTest(_) => ExecutableId::CargoTest,
      ReplayKind::SimulationNetworkFaultMatrix { .. } => ExecutableId::Simulation,
      ReplayKind::FuzzCorpus { .. } => ExecutableId::FuzzCorpus,
    }
  }

  pub fn argv(&self) -> Vec<String> {
    match self.kind {
      ReplayKind::CargoTest(test) => vec![
        "--locked".to_owned(),
        "--lib".to_owned(),
        test.filter().to_owned(),
      ],
      ReplayKind::SimulationNetworkFaultMatrix { seed } => vec![
        "--scenario".to_owned(),
        "network-fault-matrix".to_owned(),
        "--seed".to_owned(),
        seed.to_string(),
      ],
      ReplayKind::FuzzCorpus { target, digest } => vec![
        "--target".to_owned(),
        target.as_str().to_owned(),
        "--entry".to_owned(),
        digest.as_hex(),
      ],
    }
  }

  pub fn materialize(&self) -> ReplayCommand {
    let args = match self.kind {
      ReplayKind::CargoTest(test) => vec![
        "test".to_owned(),
        "--locked".to_owned(),
        "--lib".to_owned(),
        test.filter().to_owned(),
      ],
      ReplayKind::SimulationNetworkFaultMatrix { seed } => vec![
        "--config".to_owned(),
        format!("env.RADIATA_SIM_SEED.value=\"{seed}\""),
        "--config".to_owned(),
        "env.RADIATA_SIM_SEED.force=true".to_owned(),
        "test".to_owned(),
        "--locked".to_owned(),
        "--lib".to_owned(),
        SIMULATION_MATRIX_REPLAY_TEST.to_owned(),
        "--".to_owned(),
        "--ignored".to_owned(),
        "--exact".to_owned(),
      ],
      ReplayKind::FuzzCorpus { target, digest } => vec![
        "fuzz".to_owned(),
        "run".to_owned(),
        target.as_str().to_owned(),
        "--".to_owned(),
        "--corpus-entry".to_owned(),
        digest.as_hex(),
      ],
    };
    ReplayCommand { args }
  }

  pub const fn simulation_seed(&self) -> Option<u64> {
    match self.kind {
      ReplayKind::SimulationNetworkFaultMatrix { seed } => Some(seed),
      _ => None,
    }
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayCommand {
  args: Vec<String>,
}

impl ReplayCommand {
  pub const fn program(&self) -> &'static str {
    "cargo"
  }

  pub fn args(&self) -> &[String] {
    &self.args
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayError {
  InvalidSpec,
}

fn parse_cargo_test<T: AsRef<str>>(argv: &[T]) -> Result<ReplaySpec, ReplayError> {
  if argv.len() != 3
    || argv[0].as_ref() != "--locked"
    || argv[1].as_ref() != "--lib"
    || argv[2].as_ref() != CargoTestId::FailureArtifactSecurity.filter()
  {
    return Err(ReplayError::InvalidSpec);
  }
  Ok(ReplaySpec::cargo_test(CargoTestId::FailureArtifactSecurity))
}

fn parse_simulation<T: AsRef<str>>(argv: &[T]) -> Result<ReplaySpec, ReplayError> {
  if argv.len() != 4
    || argv[0].as_ref() != "--scenario"
    || argv[1].as_ref() != "network-fault-matrix"
    || argv[2].as_ref() != "--seed"
  {
    return Err(ReplayError::InvalidSpec);
  }
  let seed = parse_canonical_u64(argv[3].as_ref())?;
  Ok(ReplaySpec::simulation_network_fault_matrix(seed))
}

fn parse_fuzz_corpus<T: AsRef<str>>(argv: &[T]) -> Result<ReplaySpec, ReplayError> {
  if argv.len() != 4 || argv[0].as_ref() != "--target" || argv[2].as_ref() != "--entry" {
    return Err(ReplayError::InvalidSpec);
  }
  let target = FuzzTarget::parse(argv[1].as_ref()).ok_or(ReplayError::InvalidSpec)?;
  let digest = ApprovedCorpusDigest::parse(argv[3].as_ref())?;
  Ok(ReplaySpec::fuzz_corpus(target, digest))
}

fn parse_canonical_u64(value: &str) -> Result<u64, ReplayError> {
  let bytes = value.as_bytes();
  if bytes.is_empty()
    || bytes.len() > 20
    || bytes.iter().any(|byte| !byte.is_ascii_digit())
    || (bytes.len() > 1 && bytes[0] == b'0')
  {
    return Err(ReplayError::InvalidSpec);
  }
  let parsed = value.parse::<u64>().map_err(|_| ReplayError::InvalidSpec)?;
  if parsed.to_string() != value {
    return Err(ReplayError::InvalidSpec);
  }
  Ok(parsed)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceManifest {
  producer: ProducerKind,
  scenario_id: EvidenceId,
  test_id: EvidenceId,
  seed: Option<u64>,
  failure_class: FailureClass,
  invariant_id: EvidenceId,
  replay: ReplaySpec,
}

impl EvidenceManifest {
  pub fn new(
    producer: ProducerKind, scenario_id: EvidenceId, test_id: EvidenceId, seed: Option<u64>,
    failure_class: FailureClass, invariant_id: EvidenceId, replay: ReplaySpec,
  ) -> Result<Self, MetadataError> {
    let replay_matches_producer = match producer {
      ProducerKind::Simulation => replay.executable_id() == ExecutableId::Simulation,
      ProducerKind::Fuzz => replay.executable_id() == ExecutableId::FuzzCorpus,
      ProducerKind::Property | ProducerKind::Crash | ProducerKind::E2e | ProducerKind::Soak => {
        replay.executable_id() == ExecutableId::CargoTest
      }
    };
    if !replay_matches_producer {
      return Err(MetadataError::ReplayProducerMismatch);
    }
    if producer == ProducerKind::Simulation && replay.simulation_seed() != seed {
      return Err(MetadataError::ReplaySeedMismatch);
    }
    Ok(Self {
      producer,
      scenario_id,
      test_id,
      seed,
      failure_class,
      invariant_id,
      replay,
    })
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactLimits {
  byte_ceiling: usize,
  event_ceiling: usize,
}

impl ArtifactLimits {
  const DEFAULT: Self = Self {
    byte_ceiling: MAX_ARTIFACT_BYTES,
    event_ceiling: MAX_RETAINED_EVENTS,
  };

  pub const fn for_test(byte_ceiling: usize, event_ceiling: usize) -> Result<Self, ArtifactError> {
    if byte_ceiling == 0
      || byte_ceiling > MAX_ARTIFACT_BYTES
      || event_ceiling == 0
      || event_ceiling > MAX_RETAINED_EVENTS
    {
      return Err(ArtifactError::InvalidLimits);
    }
    Ok(Self {
      byte_ceiling,
      event_ceiling,
    })
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactTruncation {
  total_events: usize,
  retained_events: usize,
  first_events: usize,
  last_events: usize,
  count_truncated: bool,
  byte_truncated: bool,
}

impl ArtifactTruncation {
  pub const fn total_events(self) -> usize {
    self.total_events
  }

  pub const fn retained_events(self) -> usize {
    self.retained_events
  }

  pub const fn omitted_events(self) -> usize {
    self.total_events - self.retained_events
  }

  pub const fn first_events(self) -> usize {
    self.first_events
  }

  pub const fn last_events(self) -> usize {
    self.last_events
  }

  pub const fn count_truncated(self) -> bool {
    self.count_truncated
  }

  pub const fn byte_truncated(self) -> bool {
    self.byte_truncated
  }

  const fn truncated(self) -> bool {
    self.count_truncated || self.byte_truncated
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventDigest([u8; 32]);

impl EventDigest {
  pub fn as_hex(self) -> String {
    encode_hex(&self.0)
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactBytes {
  bytes: Vec<u8>,
  producer: ProducerKind,
  event_digest: EventDigest,
  truncation: ArtifactTruncation,
  first_window: Vec<NormalizedEvent>,
  last_window: Vec<NormalizedEvent>,
}

impl ArtifactBytes {
  pub fn as_bytes(&self) -> &[u8] {
    &self.bytes
  }

  pub const fn producer(&self) -> ProducerKind {
    self.producer
  }

  pub const fn event_digest(&self) -> EventDigest {
    self.event_digest
  }

  pub const fn truncation(&self) -> ArtifactTruncation {
    self.truncation
  }

  pub fn first_window(&self) -> &[NormalizedEvent] {
    &self.first_window
  }

  pub fn last_window(&self) -> &[NormalizedEvent] {
    &self.last_window
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactError {
  ForbiddenField(ForbiddenFieldClass),
  Source(SourceError),
  InvalidLimits,
  EventCountOverflow,
  EventCountMismatch,
  EncodingOverflow,
  ByteCeiling,
  FixedFieldsExceedByteCeiling,
}

impl From<SourceError> for ArtifactError {
  fn from(value: SourceError) -> Self {
    match value {
      SourceError::ForbiddenField(class) => Self::ForbiddenField(class),
      other => Self::Source(other),
    }
  }
}

pub fn build_failure_artifact(
  manifest: &EvidenceManifest, source: &impl NormalizedEventSource,
) -> Result<ArtifactBytes, ArtifactError> {
  build_failure_artifact_with_limits(manifest, source, ArtifactLimits::DEFAULT)
}

pub fn build_failure_artifact_with_limits(
  manifest: &EvidenceManifest, source: &impl NormalizedEventSource, limits: ArtifactLimits,
) -> Result<ArtifactBytes, ArtifactError> {
  let mut events = source.prevalidated_events()?;
  let total_events = events.len();
  let total_u64 = u64::try_from(total_events).map_err(|_| ArtifactError::EventCountOverflow)?;
  let domain_len =
    u16::try_from(EVENT_DIGEST_DOMAIN.len()).map_err(|_| ArtifactError::EncodingOverflow)?;

  let mut hasher = Sha256::new();
  hasher.update(domain_len.to_be_bytes());
  hasher.update(EVENT_DIGEST_DOMAIN);
  hasher.update(total_u64.to_be_bytes());

  let mut windows = EventWindows::new(limits.event_ceiling);
  let mut consumed_events = 0_usize;
  for event in &mut events {
    let event = event?;
    consumed_events = consumed_events
      .checked_add(1)
      .ok_or(ArtifactError::EventCountOverflow)?;
    event.validate_alias_roles()?;
    let encoded = encode_event(event)?;
    let encoded_len = u32::try_from(encoded.len()).map_err(|_| ArtifactError::EncodingOverflow)?;
    hasher.update(encoded_len.to_be_bytes());
    hasher.update(encoded);
    windows.push(event);
  }
  if consumed_events != total_events {
    return Err(ArtifactError::EventCountMismatch);
  }
  let event_digest = EventDigest(hasher.finalize().into());

  let max_retained = total_events.min(limits.event_ceiling);
  let retained_events = select_retained_count(
    manifest,
    event_digest,
    total_events,
    max_retained,
    &windows,
    limits,
  )?;
  let (first_window, last_window) = windows.select(retained_events, total_events);
  let truncation = ArtifactTruncation {
    total_events,
    retained_events,
    first_events: first_window.len(),
    last_events: last_window.len(),
    count_truncated: total_events > limits.event_ceiling,
    byte_truncated: retained_events < max_retained,
  };
  let bytes = render_artifact(
    manifest,
    event_digest,
    truncation,
    &first_window,
    &last_window,
    limits.byte_ceiling,
  )?;
  Ok(ArtifactBytes {
    bytes,
    producer: manifest.producer,
    event_digest,
    truncation,
    first_window,
    last_window,
  })
}

fn select_retained_count(
  manifest: &EvidenceManifest, event_digest: EventDigest, total_events: usize, max_retained: usize,
  windows: &EventWindows, limits: ArtifactLimits,
) -> Result<usize, ArtifactError> {
  if candidate_fits(
    manifest,
    event_digest,
    total_events,
    max_retained,
    windows,
    limits,
  ) {
    return Ok(max_retained);
  }
  if !candidate_fits(manifest, event_digest, total_events, 0, windows, limits) {
    return Err(ArtifactError::FixedFieldsExceedByteCeiling);
  }
  let mut fitting = 0_usize;
  let mut rejected = max_retained;
  while rejected - fitting > 1 {
    let candidate = fitting + (rejected - fitting) / 2;
    if candidate_fits(
      manifest,
      event_digest,
      total_events,
      candidate,
      windows,
      limits,
    ) {
      fitting = candidate;
    } else {
      rejected = candidate;
    }
  }
  Ok(fitting)
}

fn candidate_fits(
  manifest: &EvidenceManifest, event_digest: EventDigest, total_events: usize,
  retained_events: usize, windows: &EventWindows, limits: ArtifactLimits,
) -> bool {
  let (first, last) = windows.select(retained_events, total_events);
  let truncation = ArtifactTruncation {
    total_events,
    retained_events,
    first_events: first.len(),
    last_events: last.len(),
    count_truncated: total_events > limits.event_ceiling,
    byte_truncated: retained_events < total_events.min(limits.event_ceiling),
  };
  render_artifact(
    manifest,
    event_digest,
    truncation,
    &first,
    &last,
    limits.byte_ceiling,
  )
  .is_ok()
}

struct EventWindows {
  first: Vec<NormalizedEvent>,
  last: VecDeque<NormalizedEvent>,
  first_capacity: usize,
  last_capacity: usize,
}

impl EventWindows {
  fn new(event_ceiling: usize) -> Self {
    let first_capacity = event_ceiling.div_ceil(2);
    let last_capacity = event_ceiling / 2;
    Self {
      first: Vec::with_capacity(first_capacity),
      last: VecDeque::with_capacity(last_capacity),
      first_capacity,
      last_capacity,
    }
  }

  fn push(&mut self, event: NormalizedEvent) {
    if self.first.len() < self.first_capacity {
      self.first.push(event);
    }
    if self.last_capacity == 0 {
      return;
    }
    if self.last.len() == self.last_capacity {
      self.last.pop_front();
    }
    self.last.push_back(event);
  }

  fn select(
    &self, retained_events: usize, total_events: usize,
  ) -> (Vec<NormalizedEvent>, Vec<NormalizedEvent>) {
    if retained_events == total_events {
      let first_count = total_events.min(self.first.len());
      let last_count = total_events - first_count;
      return (
        self.first[..first_count].to_vec(),
        self
          .last
          .iter()
          .skip(self.last.len() - last_count)
          .copied()
          .collect(),
      );
    }
    let first_count = retained_events.div_ceil(2);
    let last_count = retained_events / 2;
    (
      self.first[..first_count].to_vec(),
      self
        .last
        .iter()
        .skip(self.last.len() - last_count)
        .copied()
        .collect(),
    )
  }
}

fn render_artifact(
  manifest: &EvidenceManifest, event_digest: EventDigest, truncation: ArtifactTruncation,
  first: &[NormalizedEvent], last: &[NormalizedEvent], byte_ceiling: usize,
) -> Result<Vec<u8>, ArtifactError> {
  let mut writer = JsonWriter::new(byte_ceiling);
  writer.raw(b"{\"schema\":")?;
  writer.quoted(FAILURE_SCHEMA)?;
  writer.raw(b",\"producer\":")?;
  writer.quoted(manifest.producer.as_str())?;
  writer.raw(b",\"scenario_id\":")?;
  writer.quoted(manifest.scenario_id.as_str())?;
  writer.raw(b",\"test_id\":")?;
  writer.quoted(manifest.test_id.as_str())?;
  writer.raw(b",\"seed\":")?;
  match manifest.seed {
    Some(seed) => writer.unsigned(seed)?,
    None => writer.raw(b"null")?,
  }
  writer.raw(b",\"event_digest\":")?;
  writer.quoted(&event_digest.as_hex())?;
  writer.raw(b",\"failure_class\":")?;
  writer.quoted(manifest.failure_class.as_str())?;
  writer.raw(b",\"invariant_id\":")?;
  writer.quoted(manifest.invariant_id.as_str())?;
  writer.raw(b",\"bounds\":{\"artifact_bytes\":1048576,\"retained_events\":10000}")?;
  writer.raw(b",\"truncation\":{\"truncated\":")?;
  writer.boolean(truncation.truncated())?;
  writer.raw(b",\"count_truncated\":")?;
  writer.boolean(truncation.count_truncated)?;
  writer.raw(b",\"byte_truncated\":")?;
  writer.boolean(truncation.byte_truncated)?;
  writer.raw(b",\"total_events\":")?;
  writer.unsigned_usize(truncation.total_events)?;
  writer.raw(b",\"retained_events\":")?;
  writer.unsigned_usize(truncation.retained_events)?;
  writer.raw(b",\"omitted_events\":")?;
  writer.unsigned_usize(truncation.omitted_events())?;
  writer.raw(b",\"first_events\":")?;
  writer.unsigned_usize(truncation.first_events)?;
  writer.raw(b",\"last_events\":")?;
  writer.unsigned_usize(truncation.last_events)?;
  writer.raw(b"},\"events\":{\"first\":")?;
  write_events(&mut writer, first)?;
  writer.raw(b",\"last\":")?;
  write_events(&mut writer, last)?;
  writer.raw(b"},\"replay\":{\"executable_id\":")?;
  writer.quoted(manifest.replay.executable_id().as_str())?;
  writer.raw(b",\"argv\":[")?;
  for (index, argument) in manifest.replay.argv().iter().enumerate() {
    if index > 0 {
      writer.raw(b",")?;
    }
    writer.quoted(argument)?;
  }
  writer.raw(b"]}}")?;
  Ok(writer.finish())
}

fn write_events(writer: &mut JsonWriter, events: &[NormalizedEvent]) -> Result<(), ArtifactError> {
  writer.raw(b"[")?;
  for (index, event) in events.iter().enumerate() {
    if index > 0 {
      writer.raw(b",")?;
    }
    write_event(writer, *event)?;
  }
  writer.raw(b"]")
}

fn encode_event(event: NormalizedEvent) -> Result<Vec<u8>, ArtifactError> {
  let mut writer = JsonWriter::new(MAX_ARTIFACT_BYTES);
  write_event(&mut writer, event)?;
  Ok(writer.finish())
}

fn write_event(writer: &mut JsonWriter, event: NormalizedEvent) -> Result<(), ArtifactError> {
  writer.raw(b"{\"kind\":")?;
  writer.quoted(event.kind().as_str())?;
  writer.raw(b",\"at_nanos\":")?;
  writer.unsigned(event.at_nanos())?;
  match event {
    NormalizedEvent::CheckpointReached {
      component,
      checkpoint,
      ..
    } => {
      writer.raw(b",\"component\":")?;
      writer.quoted(component.as_str())?;
      writer.raw(b",\"checkpoint\":")?;
      writer.quoted(checkpoint.as_str())?;
    }
    NormalizedEvent::SendAccepted {
      frame_id,
      path,
      copies,
      frame_bytes,
      ..
    } => {
      writer.raw(b",\"frame_id\":")?;
      writer.unsigned(frame_id)?;
      writer.raw(b",\"path\":")?;
      writer.quoted(&path.render())?;
      writer.raw(b",\"copies\":")?;
      writer.unsigned(u64::from(copies))?;
      writer.raw(b",\"frame_bytes\":")?;
      writer.unsigned(u64::from(frame_bytes))?;
    }
    NormalizedEvent::Lost { frame_id, .. } | NormalizedEvent::DuplicateCreated { frame_id, .. } => {
      writer.raw(b",\"frame_id\":")?;
      writer.unsigned(frame_id)?;
    }
    NormalizedEvent::Reordered { frame_id, copy, .. }
    | NormalizedEvent::Delivered { frame_id, copy, .. } => {
      writer.raw(b",\"frame_id\":")?;
      writer.unsigned(frame_id)?;
      writer.raw(b",\"copy\":")?;
      writer.unsigned(u64::from(copy))?;
    }
    NormalizedEvent::Dropped {
      frame_id,
      copy,
      reason,
      ..
    } => {
      writer.raw(b",\"frame_id\":")?;
      writer.unsigned(frame_id)?;
      writer.raw(b",\"copy\":")?;
      writer.unsigned(u64::from(copy))?;
      writer.raw(b",\"reason\":")?;
      writer.quoted(reason.as_str())?;
    }
    NormalizedEvent::Partitioned {
      path,
      fault,
      generation,
      ..
    }
    | NormalizedEvent::Healed {
      path,
      fault,
      generation,
      ..
    } => {
      writer.raw(b",\"path\":")?;
      writer.quoted(&path.render())?;
      writer.raw(b",\"fault\":")?;
      writer.quoted(&fault.render())?;
      writer.raw(b",\"generation\":")?;
      writer.unsigned(u64::from(generation))?;
    }
    NormalizedEvent::Restarted {
      node, boot_epoch, ..
    } => {
      writer.raw(b",\"node\":")?;
      writer.quoted(&node.render())?;
      writer.raw(b",\"boot_epoch\":")?;
      writer.unsigned(u64::from(boot_epoch))?;
    }
    NormalizedEvent::AddressChanged {
      node,
      endpoint,
      generation,
      ..
    } => {
      writer.raw(b",\"node\":")?;
      writer.quoted(&node.render())?;
      writer.raw(b",\"endpoint\":")?;
      writer.quoted(&endpoint.render())?;
      writer.raw(b",\"generation\":")?;
      writer.unsigned(u64::from(generation))?;
    }
    NormalizedEvent::WallClockChanged {
      node,
      previous,
      current,
      ..
    } => {
      writer.raw(b",\"node\":")?;
      writer.quoted(&node.render())?;
      writer.raw(b",\"previous\":")?;
      writer.unsigned(previous)?;
      writer.raw(b",\"current\":")?;
      writer.unsigned(current)?;
    }
    NormalizedEvent::QueueRejected {
      frame_id,
      copies,
      frame_bytes,
      ..
    } => {
      writer.raw(b",\"frame_id\":")?;
      writer.unsigned(frame_id)?;
      writer.raw(b",\"copies\":")?;
      writer.unsigned(u64::from(copies))?;
      writer.raw(b",\"frame_bytes\":")?;
      writer.unsigned(u64::from(frame_bytes))?;
    }
  }
  writer.raw(b"}")
}

struct JsonWriter {
  bytes: Vec<u8>,
  limit: usize,
}

impl JsonWriter {
  fn new(limit: usize) -> Self {
    Self {
      bytes: Vec::new(),
      limit,
    }
  }

  fn raw(&mut self, value: &[u8]) -> Result<(), ArtifactError> {
    let next = self
      .bytes
      .len()
      .checked_add(value.len())
      .ok_or(ArtifactError::EncodingOverflow)?;
    if next > self.limit {
      return Err(ArtifactError::ByteCeiling);
    }
    self.bytes.extend_from_slice(value);
    Ok(())
  }

  fn quoted(&mut self, value: &str) -> Result<(), ArtifactError> {
    self.raw(b"\"")?;
    for byte in value.bytes() {
      match byte {
        b'"' => self.raw(b"\\\"")?,
        b'\\' => self.raw(b"\\\\")?,
        0x00..=0x1F => {
          let escaped = [
            b'\\',
            b'u',
            b'0',
            b'0',
            hex_digit(byte >> 4),
            hex_digit(byte & 0x0F),
          ];
          self.raw(&escaped)?;
        }
        _ => self.raw(&[byte])?,
      }
    }
    self.raw(b"\"")
  }

  fn unsigned(&mut self, value: u64) -> Result<(), ArtifactError> {
    self.raw(value.to_string().as_bytes())
  }

  fn unsigned_usize(&mut self, value: usize) -> Result<(), ArtifactError> {
    self.unsigned(u64::try_from(value).map_err(|_| ArtifactError::EncodingOverflow)?)
  }

  fn boolean(&mut self, value: bool) -> Result<(), ArtifactError> {
    self.raw(if value { b"true" } else { b"false" })
  }

  fn finish(self) -> Vec<u8> {
    self.bytes
  }
}

fn decode_lower_hex(value: &str, output: &mut [u8]) -> Result<(), MetadataError> {
  if value.len() != output.len() * 2
    || value
      .bytes()
      .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
  {
    return Err(MetadataError::InvalidHex);
  }
  for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
    output[index] = (decode_nibble(pair[0]) << 4) | decode_nibble(pair[1]);
  }
  Ok(())
}

const fn decode_nibble(value: u8) -> u8 {
  match value {
    b'0'..=b'9' => value - b'0',
    b'a'..=b'f' => value - b'a' + 10,
    _ => 0,
  }
}

fn encode_hex(bytes: &[u8]) -> String {
  let mut encoded = String::with_capacity(bytes.len() * 2);
  for byte in bytes {
    encoded.push(char::from(hex_digit(byte >> 4)));
    encoded.push(char::from(hex_digit(byte & 0x0F)));
  }
  encoded
}

const fn hex_digit(value: u8) -> u8 {
  match value {
    0..=9 => b'0' + value,
    _ => b'a' + (value - 10),
  }
}

#[cfg(test)]
mod tests {
  use std::cell::Cell;

  use super::*;

  struct FixedSource {
    events: Vec<NormalizedEvent>,
    preflight: Result<(), SourceError>,
    event_reads: Cell<usize>,
  }

  struct FixedEvents<'a> {
    events: std::slice::Iter<'a, NormalizedEvent>,
    reads: &'a Cell<usize>,
  }

  impl Iterator for FixedEvents<'_> {
    type Item = Result<NormalizedEvent, SourceError>;

    fn next(&mut self) -> Option<Self::Item> {
      let event = self.events.next().copied()?;
      self.reads.set(self.reads.get() + 1);
      Some(Ok(event))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
      self.events.size_hint()
    }
  }

  impl ExactSizeIterator for FixedEvents<'_> {}

  struct MismatchedSource {
    events: Vec<NormalizedEvent>,
    advertised: usize,
  }

  struct MismatchedEvents<'a> {
    events: std::slice::Iter<'a, NormalizedEvent>,
    advertised: usize,
  }

  impl Iterator for MismatchedEvents<'_> {
    type Item = Result<NormalizedEvent, SourceError>;

    fn next(&mut self) -> Option<Self::Item> {
      self.events.next().copied().map(Ok)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
      (self.advertised, Some(self.advertised))
    }
  }

  impl ExactSizeIterator for MismatchedEvents<'_> {}

  impl NormalizedEventSource for MismatchedSource {
    fn prevalidated_events(
      &self,
    ) -> Result<
      Box<dyn ExactSizeIterator<Item = Result<NormalizedEvent, SourceError>> + '_>,
      SourceError,
    > {
      Ok(Box::new(MismatchedEvents {
        events: self.events.iter(),
        advertised: self.advertised,
      }))
    }
  }

  impl NormalizedEventSource for FixedSource {
    fn prevalidated_events(
      &self,
    ) -> Result<
      Box<dyn ExactSizeIterator<Item = Result<NormalizedEvent, SourceError>> + '_>,
      SourceError,
    > {
      self.preflight?;
      Ok(Box::new(FixedEvents {
        events: self.events.iter(),
        reads: &self.event_reads,
      }))
    }
  }

  fn manifest(producer: ProducerKind) -> EvidenceManifest {
    EvidenceManifest::new(
      producer,
      EvidenceId::new("scenario-baseline").unwrap(),
      EvidenceId::new("shared-artifact-contract").unwrap(),
      Some(7),
      FailureClass::Invariant,
      EvidenceId::new("producer-neutral-schema").unwrap(),
      if producer == ProducerKind::Simulation {
        ReplaySpec::simulation_network_fault_matrix(7)
      } else if producer == ProducerKind::Fuzz {
        ReplaySpec::fuzz_corpus(
          FuzzTarget::WireDecode,
          ApprovedCorpusDigest::from_reviewed_bytes([0x33; 32]),
        )
      } else {
        ReplaySpec::cargo_test(CargoTestId::FailureArtifactSecurity)
      },
    )
    .unwrap()
  }

  fn source(events: Vec<NormalizedEvent>) -> FixedSource {
    FixedSource {
      events,
      preflight: Ok(()),
      event_reads: Cell::new(0),
    }
  }

  fn state_event(value: u64) -> NormalizedEvent {
    NormalizedEvent::checkpoint_reached(
      value,
      EvidenceId::new("fixture-component").unwrap(),
      EvidenceId::new("ready").unwrap(),
    )
  }

  #[test]
  fn simulation_failure_artifact_security_all_producer_classes_use_one_schema() {
    for producer in ProducerKind::ALL {
      let source = source(vec![state_event(5)]);
      let artifact = build_failure_artifact(&manifest(producer), &source).unwrap();
      assert!(
        artifact
          .as_bytes()
          .starts_with(b"{\"schema\":\"radiata.woooo.tech/schemas/failure-replay\"")
      );
      assert_eq!(artifact.producer(), producer);
      assert_eq!(source.event_reads.get(), 1);
      assert!(artifact.as_bytes().len() <= MAX_ARTIFACT_BYTES);
      assert!(
        artifact
          .as_bytes()
          .windows(18)
          .any(|value| value == b"checkpoint-reached")
      );
      assert!(
        !artifact
          .as_bytes()
          .windows(16)
          .any(|value| value == b"state-transition")
      );
      assert!(
        !artifact
          .as_bytes()
          .windows(10)
          .any(|value| value == b"\"machine\":")
      );
      assert!(
        !artifact
          .as_bytes()
          .windows(8)
          .any(|value| value == b"\"state\":")
      );
    }
  }

  #[test]
  fn simulation_failure_artifact_security_forbidden_preflight_reads_no_events() {
    let source = FixedSource {
      events: vec![state_event(1)],
      preflight: Err(SourceError::ForbiddenField(ForbiddenFieldClass::Credential)),
      event_reads: Cell::new(0),
    };
    assert_eq!(
      build_failure_artifact(&manifest(ProducerKind::Property), &source),
      Err(ArtifactError::ForbiddenField(
        ForbiddenFieldClass::Credential
      )),
    );
    assert_eq!(source.event_reads.get(), 0);
  }

  #[test]
  fn simulation_failure_artifact_security_rejects_inexact_event_streams() {
    for source in [
      MismatchedSource {
        events: vec![state_event(1)],
        advertised: 2,
      },
      MismatchedSource {
        events: vec![state_event(1), state_event(2)],
        advertised: 1,
      },
    ] {
      assert_eq!(
        build_failure_artifact(&manifest(ProducerKind::Property), &source),
        Err(ArtifactError::EventCountMismatch),
      );
    }
  }

  #[test]
  fn simulation_failure_artifact_security_aliases_ignore_source_values() {
    let mut first = AliasTable::new(AliasKind::Endpoint);
    let mut second = AliasTable::new(AliasKind::Endpoint);
    assert_eq!(first.register(111_u64).unwrap().render(), "endpoint-1");
    assert_eq!(first.register(999_u64).unwrap().render(), "endpoint-2");
    assert_eq!(second.register(999_u64).unwrap().render(), "endpoint-1");
    assert_eq!(second.register(111_u64).unwrap().render(), "endpoint-2");
    assert_eq!(
      first.register(111_u64),
      Err(SourceError::DuplicateSource(AliasKind::Endpoint)),
    );
  }

  #[test]
  fn simulation_failure_artifact_security_metadata_and_replay_are_validated() {
    assert!(EvidenceId::new("../../host-path").is_err());
    assert!(EvidenceId::new("hostile\ntext").is_err());
    assert!(ReplaySpec::parse("simulation", &["--scenario", "x", "--seed", "1"]).is_err());
    assert!(ReplaySpec::parse("/tmp/cargo", &["--locked", "--lib", "x"]).is_err());
    assert_eq!(
      EvidenceManifest::new(
        ProducerKind::Fuzz,
        EvidenceId::new("scenario-baseline").unwrap(),
        EvidenceId::new("wrong-replay").unwrap(),
        None,
        FailureClass::Invariant,
        EvidenceId::new("producer-replay-binding").unwrap(),
        ReplaySpec::cargo_test(CargoTestId::FailureArtifactSecurity),
      ),
      Err(MetadataError::ReplayProducerMismatch),
    );

    let fuzz = ReplaySpec::fuzz_corpus(
      FuzzTarget::WireDecode,
      ApprovedCorpusDigest::from_reviewed_bytes([0x33; 32]),
    );
    assert_eq!(ReplaySpec::parse("fuzz-corpus", &fuzz.argv()), Ok(fuzz));
  }

  #[test]
  fn simulation_failure_artifact_security_count_and_byte_truncation_are_exact() {
    let events = (0..=MAX_RETAINED_EVENTS as u64)
      .map(state_event)
      .collect::<Vec<_>>();
    let count_source = source(events);
    let artifact =
      build_failure_artifact(&manifest(ProducerKind::Property), &count_source).unwrap();
    assert_eq!(artifact.truncation().total_events(), 10_001);
    assert_eq!(artifact.truncation().retained_events(), 10_000);
    assert_eq!(artifact.truncation().first_events(), 5_000);
    assert_eq!(artifact.truncation().last_events(), 5_000);
    assert!(artifact.truncation().count_truncated());

    let byte_source = source((0..200).map(state_event).collect());
    let limits = ArtifactLimits::for_test(2_048, MAX_RETAINED_EVENTS).unwrap();
    let first =
      build_failure_artifact_with_limits(&manifest(ProducerKind::Property), &byte_source, limits)
        .unwrap();
    let second =
      build_failure_artifact_with_limits(&manifest(ProducerKind::Property), &byte_source, limits)
        .unwrap();
    assert_eq!(first, second);
    assert!(first.truncation().byte_truncated());
    assert!(first.as_bytes().len() <= 2_048);
  }

  #[test]
  fn simulation_failure_artifact_security_digest_covers_omitted_middle() {
    let first_events = (0..=MAX_RETAINED_EVENTS as u64)
      .map(state_event)
      .collect::<Vec<_>>();
    let mut second_events = first_events.clone();
    second_events[MAX_RETAINED_EVENTS / 2] = state_event(999_999);
    let first =
      build_failure_artifact(&manifest(ProducerKind::Property), &source(first_events)).unwrap();
    let second =
      build_failure_artifact(&manifest(ProducerKind::Property), &source(second_events)).unwrap();
    assert_eq!(first.first_window(), second.first_window());
    assert_eq!(first.last_window(), second.last_window());
    assert_ne!(first.event_digest(), second.event_digest());
  }

  #[test]
  fn simulation_failure_artifact_security_enforces_exact_fixed_byte_boundary() {
    let empty = source(Vec::new());
    let artifact = build_failure_artifact(&manifest(ProducerKind::Property), &empty).unwrap();
    let exact = artifact.as_bytes().len();
    assert!(
      build_failure_artifact_with_limits(
        &manifest(ProducerKind::Property),
        &empty,
        ArtifactLimits::for_test(exact, MAX_RETAINED_EVENTS).unwrap(),
      )
      .is_ok()
    );
    assert_eq!(
      build_failure_artifact_with_limits(
        &manifest(ProducerKind::Property),
        &empty,
        ArtifactLimits::for_test(exact - 1, MAX_RETAINED_EVENTS).unwrap(),
      ),
      Err(ArtifactError::FixedFieldsExceedByteCeiling),
    );
  }
}
