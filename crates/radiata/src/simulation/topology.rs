use std::{
  collections::{BTreeMap, BTreeSet},
  time::Duration,
};

const PROBABILITY_SCALE: u32 = 1_000_000;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct NodeKey(u64);

impl NodeKey {
  pub(crate) const fn new(value: u64) -> Self {
    Self(value)
  }

  pub(crate) const fn value(self) -> u64 {
    self.0
  }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct AddressId(u32);

impl AddressId {
  pub(crate) const fn new(value: u32) -> Self {
    Self(value)
  }

  pub(crate) const fn value(self) -> u32 {
    self.0
  }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct PartitionId(u32);

impl PartitionId {
  pub(crate) const fn new(value: u32) -> Self {
    Self(value)
  }

  pub(crate) const fn value(self) -> u32 {
    self.0
  }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct LinkKey {
  from: NodeKey,
  to: NodeKey,
}

impl LinkKey {
  pub(crate) const fn new(from: NodeKey, to: NodeKey) -> Self {
    Self { from, to }
  }

  pub(crate) const fn from(self) -> NodeKey {
    self.from
  }

  pub(crate) const fn to(self) -> NodeKey {
    self.to
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SimulationLimits {
  max_nodes: usize,
  max_links: usize,
  max_pending_frames: usize,
  max_pending_bytes: usize,
  max_recorded_events: usize,
  max_frame_bytes: usize,
}

impl SimulationLimits {
  pub(crate) fn new(
    max_nodes: usize, max_links: usize, max_pending_frames: usize, max_pending_bytes: usize,
    max_recorded_events: usize, max_frame_bytes: usize,
  ) -> SimResult<Self> {
    let max_recordable_bytes = usize::try_from(u32::MAX).unwrap_or(usize::MAX);
    if max_nodes == 0
      || u64::try_from(max_nodes).is_err()
      || max_links == 0
      || max_pending_frames == 0
      || max_pending_bytes == 0
      || max_recorded_events == 0
      || max_frame_bytes == 0
      || max_frame_bytes > max_recordable_bytes
      || max_frame_bytes > max_pending_bytes
    {
      return Err(SimulationError::InvalidLimit);
    }
    Ok(Self {
      max_nodes,
      max_links,
      max_pending_frames,
      max_pending_bytes,
      max_recorded_events,
      max_frame_bytes,
    })
  }

  pub(crate) const fn max_pending_frames(self) -> usize {
    self.max_pending_frames
  }

  pub(crate) const fn max_pending_bytes(self) -> usize {
    self.max_pending_bytes
  }

  pub(crate) const fn max_recorded_events(self) -> usize {
    self.max_recorded_events
  }

  pub(crate) const fn max_frame_bytes(self) -> usize {
    self.max_frame_bytes
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LinkPolicy {
  fixed_delay_nanos: u64,
  jitter_nanos: u64,
  loss_per_million: u32,
  duplicate_per_million: u32,
  reorder_per_million: u32,
  reorder_window_nanos: u64,
}

impl LinkPolicy {
  pub(crate) fn new(
    fixed_delay: Duration, jitter: Duration, loss_per_million: u32, duplicate_per_million: u32,
    reorder_per_million: u32, reorder_window: Duration,
  ) -> SimResult<Self> {
    if loss_per_million > PROBABILITY_SCALE
      || duplicate_per_million > PROBABILITY_SCALE
      || reorder_per_million > PROBABILITY_SCALE
      || (reorder_per_million > 0 && reorder_window.is_zero())
    {
      return Err(SimulationError::InvalidPolicy);
    }
    Ok(Self {
      fixed_delay_nanos: duration_nanos(fixed_delay)?,
      jitter_nanos: duration_nanos(jitter)?,
      loss_per_million,
      duplicate_per_million,
      reorder_per_million,
      reorder_window_nanos: duration_nanos(reorder_window)?,
    })
  }

  pub(crate) const fn fixed_delay_nanos(self) -> u64 {
    self.fixed_delay_nanos
  }

  pub(crate) const fn jitter_nanos(self) -> u64 {
    self.jitter_nanos
  }

  pub(crate) const fn loss_per_million(self) -> u32 {
    self.loss_per_million
  }

  pub(crate) const fn duplicate_per_million(self) -> u32 {
    self.duplicate_per_million
  }

  pub(crate) const fn reorder_per_million(self) -> u32 {
    self.reorder_per_million
  }

  pub(crate) const fn reorder_window_nanos(self) -> u64 {
    self.reorder_window_nanos
  }

  pub(crate) fn fixed_delay(self) -> Duration {
    Duration::from_nanos(self.fixed_delay_nanos)
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EndpointStamp {
  node: NodeKey,
  address: AddressId,
  boot_epoch: u32,
  address_generation: u32,
}

impl EndpointStamp {
  pub(crate) const fn node(self) -> NodeKey {
    self.node
  }

  pub(crate) const fn address(self) -> AddressId {
    self.address
  }

  pub(crate) const fn boot_epoch(self) -> u32 {
    self.boot_epoch
  }

  pub(crate) const fn address_generation(self) -> u32 {
    self.address_generation
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NodeState {
  address: AddressId,
  boot_epoch: u32,
  address_generation: u32,
  wall_time_nanos: u64,
}

impl NodeState {
  const fn new(address: AddressId) -> Self {
    Self {
      address,
      boot_epoch: 0,
      address_generation: 0,
      wall_time_nanos: 0,
    }
  }

  const fn stamp(self, node: NodeKey) -> EndpointStamp {
    EndpointStamp {
      node,
      address: self.address,
      boot_epoch: self.boot_epoch,
      address_generation: self.address_generation,
    }
  }

  pub(crate) const fn boot_epoch(self) -> u32 {
    self.boot_epoch
  }

  pub(crate) const fn address(self) -> AddressId {
    self.address
  }

  pub(crate) const fn address_generation(self) -> u32 {
    self.address_generation
  }

  pub(crate) const fn wall_time_nanos(self) -> u64 {
    self.wall_time_nanos
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LinkState {
  policy: LinkPolicy,
  partitions: BTreeSet<PartitionId>,
  generation: u32,
}

impl LinkState {
  pub(crate) const fn policy(&self) -> LinkPolicy {
    self.policy
  }

  pub(crate) fn is_blocked(&self) -> bool {
    !self.partitions.is_empty()
  }

  pub(crate) fn is_partitioned(&self, partition: PartitionId) -> bool {
    self.partitions.contains(&partition)
  }

  pub(crate) const fn generation(&self) -> u32 {
    self.generation
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Topology {
  limits: SimulationLimits,
  nodes: BTreeMap<NodeKey, NodeState>,
  links: BTreeMap<LinkKey, LinkState>,
}

impl Topology {
  pub(crate) fn new(limits: SimulationLimits) -> Self {
    Self {
      limits,
      nodes: BTreeMap::new(),
      links: BTreeMap::new(),
    }
  }

  pub(crate) fn add_node(&mut self, key: NodeKey, address: AddressId) -> SimResult<()> {
    if self.nodes.contains_key(&key) || self.nodes.len() >= self.limits.max_nodes {
      return Err(SimulationError::Capacity);
    }
    self.nodes.insert(key, NodeState::new(address));
    Ok(())
  }

  pub(crate) fn add_link(&mut self, key: LinkKey, policy: LinkPolicy) -> SimResult<()> {
    if key.from() == key.to()
      || !self.nodes.contains_key(&key.from())
      || !self.nodes.contains_key(&key.to())
    {
      return Err(SimulationError::UnknownEndpoint);
    }
    if self.links.contains_key(&key) || self.links.len() >= self.limits.max_links {
      return Err(SimulationError::Capacity);
    }
    self.links.insert(
      key,
      LinkState {
        policy,
        partitions: BTreeSet::new(),
        generation: 0,
      },
    );
    Ok(())
  }

  pub(crate) fn partition(&mut self, key: LinkKey, partition: PartitionId) -> SimResult<()> {
    let link = self
      .links
      .get_mut(&key)
      .ok_or(SimulationError::UnknownLink)?;
    if link.partitions.contains(&partition) {
      return Ok(());
    }
    let generation = link
      .generation
      .checked_add(1)
      .ok_or(SimulationError::Overflow)?;
    link.partitions.insert(partition);
    link.generation = generation;
    Ok(())
  }

  pub(crate) fn heal(&mut self, key: LinkKey, partition: PartitionId) -> SimResult<()> {
    let link = self
      .links
      .get_mut(&key)
      .ok_or(SimulationError::UnknownLink)?;
    if !link.partitions.contains(&partition) {
      return Ok(());
    }
    let generation = link
      .generation
      .checked_add(1)
      .ok_or(SimulationError::Overflow)?;
    link.partitions.remove(&partition);
    link.generation = generation;
    Ok(())
  }

  pub(crate) fn restart(&mut self, key: NodeKey) -> SimResult<u32> {
    let node = self
      .nodes
      .get_mut(&key)
      .ok_or(SimulationError::UnknownNode)?;
    let boot_epoch = node
      .boot_epoch
      .checked_add(1)
      .ok_or(SimulationError::Overflow)?;
    node.boot_epoch = boot_epoch;
    Ok(boot_epoch)
  }

  pub(crate) fn change_address(&mut self, key: NodeKey, address: AddressId) -> SimResult<u32> {
    let node = self
      .nodes
      .get_mut(&key)
      .ok_or(SimulationError::UnknownNode)?;
    let generation = node
      .address_generation
      .checked_add(1)
      .ok_or(SimulationError::Overflow)?;
    node.address = address;
    node.address_generation = generation;
    Ok(generation)
  }

  pub(crate) fn set_wall_time(&mut self, key: NodeKey, wall_time_nanos: u64) -> SimResult<u64> {
    let node = self
      .nodes
      .get_mut(&key)
      .ok_or(SimulationError::UnknownNode)?;
    let previous = node.wall_time_nanos;
    node.wall_time_nanos = wall_time_nanos;
    Ok(previous)
  }

  pub(crate) fn stamp(&self, key: NodeKey) -> SimResult<EndpointStamp> {
    let node = self.nodes.get(&key).ok_or(SimulationError::UnknownNode)?;
    Ok(node.stamp(key))
  }

  pub(crate) fn link(&self, key: LinkKey) -> SimResult<&LinkState> {
    self.links.get(&key).ok_or(SimulationError::UnknownLink)
  }

  pub(crate) fn node(&self, key: NodeKey) -> SimResult<&NodeState> {
    self.nodes.get(&key).ok_or(SimulationError::UnknownNode)
  }

  pub(crate) const fn limits(&self) -> SimulationLimits {
    self.limits
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SimulationError {
  InvalidLimit,
  InvalidPolicy,
  Capacity,
  UnknownNode,
  UnknownEndpoint,
  UnknownLink,
  Overflow,
  Invariant,
}

pub(crate) type SimResult<T> = Result<T, SimulationError>;

fn duration_nanos(duration: Duration) -> SimResult<u64> {
  u64::try_from(duration.as_nanos()).map_err(|_| SimulationError::Overflow)
}

#[cfg(test)]
mod tests {
  use std::time::Duration;

  use super::{AddressId, LinkKey, LinkPolicy, NodeKey, PartitionId, SimulationLimits, Topology};

  fn limits(max_nodes: usize) -> SimulationLimits {
    SimulationLimits::new(max_nodes, 2, 32, 4_096, 128, 1_024).unwrap()
  }

  fn policy(delay: u64) -> LinkPolicy {
    LinkPolicy::new(
      Duration::from_nanos(delay),
      Duration::ZERO,
      0,
      0,
      0,
      Duration::ZERO,
    )
    .unwrap()
  }

  #[test]
  fn simulation_topology_rejects_invalid_bounds_atomically() {
    assert!(SimulationLimits::new(0, 1, 1, 1, 1, 1).is_err());
    assert!(SimulationLimits::new(1, 0, 1, 1, 1, 1).is_err());
    assert!(SimulationLimits::new(2, 1, 0, 1, 1, 1).is_err());
    assert!(SimulationLimits::new(2, 1, 1, 0, 1, 1).is_err());
    assert!(SimulationLimits::new(2, 1, 1, 1, 0, 1).is_err());
    assert!(SimulationLimits::new(2, 1, 1, 1, 1, 0).is_err());
    assert!(SimulationLimits::new(2, 1, 1, 1, 1, 2).is_err());

    let huge = SimulationLimits::new(usize::MAX, 1, 1, 1, 1, 1).unwrap();
    let mut sparse = Topology::new(huge);
    sparse
      .add_node(NodeKey::new(u64::MAX), AddressId::new(1))
      .unwrap();

    let mut topology = Topology::new(limits(2));
    let configured = topology.limits();
    assert_eq!(configured.max_pending_frames(), 32);
    assert_eq!(configured.max_pending_bytes(), 4_096);
    assert_eq!(configured.max_recorded_events(), 128);
    assert_eq!(configured.max_frame_bytes(), 1_024);
    assert!(topology.node(NodeKey::new(99)).is_err());
    topology
      .add_node(NodeKey::new(1), AddressId::new(10))
      .unwrap();
    topology
      .add_node(NodeKey::new(2), AddressId::new(20))
      .unwrap();
    let before = topology.clone();

    assert!(
      topology
        .add_node(NodeKey::new(3), AddressId::new(30))
        .is_err()
    );
    assert!(
      topology
        .add_node(NodeKey::new(2), AddressId::new(21))
        .is_err()
    );
    assert_eq!(topology, before);
  }

  #[test]
  fn simulation_topology_preserves_directed_links() {
    let mut topology = Topology::new(limits(2));
    let left = NodeKey::new(1);
    let right = NodeKey::new(2);
    topology.add_node(left, AddressId::new(10)).unwrap();
    topology.add_node(right, AddressId::new(20)).unwrap();

    let outbound = LinkKey::new(left, right);
    let inbound = LinkKey::new(right, left);
    topology.add_link(outbound, policy(5)).unwrap();
    topology.add_link(inbound, policy(9)).unwrap();

    assert_eq!(
      topology.link(outbound).unwrap().policy().fixed_delay(),
      Duration::from_nanos(5)
    );
    let outbound_policy = topology.link(outbound).unwrap().policy();
    assert_eq!(outbound_policy.fixed_delay_nanos(), 5);
    assert_eq!(outbound_policy.jitter_nanos(), 0);
    assert_eq!(outbound_policy.loss_per_million(), 0);
    assert_eq!(outbound_policy.duplicate_per_million(), 0);
    assert_eq!(outbound_policy.reorder_per_million(), 0);
    assert_eq!(outbound_policy.reorder_window_nanos(), 0);
    assert_eq!(
      topology.link(inbound).unwrap().policy().fixed_delay(),
      Duration::from_nanos(9)
    );
    assert!(!topology.link(outbound).unwrap().is_blocked());
    assert!(!topology.link(inbound).unwrap().is_blocked());
  }

  #[test]
  fn simulation_topology_overflow_is_atomic() {
    let mut topology = Topology::new(limits(2));
    let left = NodeKey::new(1);
    let right = NodeKey::new(2);
    let link = LinkKey::new(left, right);
    topology.add_node(left, AddressId::new(10)).unwrap();
    topology.add_node(right, AddressId::new(20)).unwrap();
    topology.add_link(link, policy(1)).unwrap();

    topology.nodes.get_mut(&left).unwrap().boot_epoch = u32::MAX;
    let before_restart = topology.clone();
    assert!(topology.restart(left).is_err());
    assert_eq!(topology, before_restart);

    topology.nodes.get_mut(&left).unwrap().address_generation = u32::MAX;
    let before_address = topology.clone();
    assert!(topology.change_address(left, AddressId::new(11)).is_err());
    assert_eq!(topology, before_address);

    topology.links.get_mut(&link).unwrap().generation = u32::MAX;
    let before_partition = topology.clone();
    assert!(topology.partition(link, PartitionId::new(9)).is_err());
    assert_eq!(topology, before_partition);
  }

  #[test]
  fn simulation_topology_populates_more_than_1024_nodes_and_caps_links_independently() {
    let limits = SimulationLimits::new(1_025, 1, 1, 1, 1, 1).unwrap();
    let mut topology = Topology::new(limits);
    for value in 0..1_025_u64 {
      topology
        .add_node(NodeKey::new(value), AddressId::new(value as u32))
        .unwrap();
    }
    assert!(topology.node(NodeKey::new(1_024)).is_ok());

    topology
      .add_link(LinkKey::new(NodeKey::new(0), NodeKey::new(1)), policy(1))
      .unwrap();
    let before = topology.clone();
    assert_eq!(
      topology.add_link(LinkKey::new(NodeKey::new(1), NodeKey::new(2)), policy(1),),
      Err(super::SimulationError::Capacity),
    );
    assert_eq!(topology, before);
  }

  #[test]
  fn simulation_topology_keeps_overlapping_partitions_independent() {
    let mut topology = Topology::new(limits(2));
    let left = NodeKey::new(1);
    let right = NodeKey::new(2);
    let outbound = LinkKey::new(left, right);
    let inbound = LinkKey::new(right, left);
    topology.add_node(left, AddressId::new(10)).unwrap();
    topology.add_node(right, AddressId::new(20)).unwrap();
    topology.add_link(outbound, policy(1)).unwrap();
    topology.add_link(inbound, policy(1)).unwrap();

    topology.partition(outbound, PartitionId::new(1)).unwrap();
    topology.partition(outbound, PartitionId::new(2)).unwrap();
    let blocked_generation = topology.link(outbound).unwrap().generation();
    topology.heal(outbound, PartitionId::new(1)).unwrap();

    assert!(topology.link(outbound).unwrap().is_blocked());
    assert!(!topology.link(inbound).unwrap().is_blocked());
    assert!(topology.link(outbound).unwrap().generation() > blocked_generation);

    topology.heal(outbound, PartitionId::new(2)).unwrap();
    assert!(!topology.link(outbound).unwrap().is_blocked());
  }
}
