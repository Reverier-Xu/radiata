use sha2::{Digest as ShaDigest, Sha256};

use crate::{
  Digest,
  simulation::topology::{AddressId, LinkKey, NodeKey, PartitionId, SimResult, SimulationError},
};

const EVENT_STREAM_DOMAIN: &[u8] = b"radiata.woooo.tech/simulation/event-stream/v2";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct FrameId(u64);

impl FrameId {
  pub(crate) const fn new(value: u64) -> Self {
    Self(value)
  }

  pub(crate) const fn value(self) -> u64 {
    self.0
  }
}

/// The ordering key of one scheduled delivery. Sorting is deterministic:
/// deadline first, then the reorder rank (reordered deliveries sort after
/// in-order ones at equal deadlines, ordered by frame descending), then
/// frame identity and the per-copy enqueue id. The former `ordinal` field
/// was dropped because it duplicated `frame.value()`; the reorder rank is
/// kept because its exact value is part of the deterministic order.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct EventKey {
  deadline_nanos: u64,
  reorder_rank: u64,
  frame: FrameId,
  copy: u8,
  enqueue_id: u64,
}

impl EventKey {
  pub(crate) const fn new(
    deadline_nanos: u64, reorder_rank: u64, frame: FrameId, copy: u8, enqueue_id: u64,
  ) -> Self {
    Self {
      deadline_nanos,
      reorder_rank,
      frame,
      copy,
      enqueue_id,
    }
  }

  pub(crate) const fn deadline_nanos(self) -> u64 {
    self.deadline_nanos
  }

  pub(crate) const fn enqueue_id(self) -> u64 {
    self.enqueue_id
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DropReason {
  Blocked,
  StaleLink,
  StaleBoot,
  StaleAddress,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EventRecord {
  SendAccepted {
    at_nanos: u64,
    frame: FrameId,
    link: LinkKey,
    copies: u8,
    bytes: u32,
  },
  Lost {
    at_nanos: u64,
    frame: FrameId,
  },
  DuplicateCreated {
    at_nanos: u64,
    frame: FrameId,
  },
  Reordered {
    at_nanos: u64,
    frame: FrameId,
    copy: u8,
  },
  Delivered {
    at_nanos: u64,
    frame: FrameId,
    copy: u8,
  },
  Dropped {
    at_nanos: u64,
    frame: FrameId,
    copy: u8,
    reason: DropReason,
  },
  Partitioned {
    at_nanos: u64,
    link: LinkKey,
    partition: PartitionId,
    generation: u32,
  },
  Healed {
    at_nanos: u64,
    link: LinkKey,
    partition: PartitionId,
    generation: u32,
  },
  Restarted {
    at_nanos: u64,
    node: NodeKey,
    boot_epoch: u32,
  },
  AddressChanged {
    at_nanos: u64,
    node: NodeKey,
    address: AddressId,
    generation: u32,
  },
  WallClockChanged {
    at_nanos: u64,
    node: NodeKey,
    previous: u64,
    current: u64,
  },
  QueueRejected {
    at_nanos: u64,
    frame: FrameId,
    copies: u8,
    bytes: u32,
  },
}

impl EventRecord {
  pub(crate) const fn at_nanos(self) -> u64 {
    match self {
      Self::SendAccepted { at_nanos, .. }
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
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EventLog {
  max_records: usize,
  records: Vec<EventRecord>,
}

impl EventLog {
  pub(crate) fn new(max_records: usize) -> SimResult<Self> {
    if max_records == 0 {
      return Err(SimulationError::InvalidLimit);
    }
    let mut records = Vec::new();
    records
      .try_reserve_exact(max_records)
      .map_err(|_| SimulationError::Capacity)?;
    Ok(Self {
      max_records,
      records,
    })
  }

  pub(crate) fn push(&mut self, record: EventRecord) -> SimResult<()> {
    if self.records.len() >= self.max_records {
      return Err(SimulationError::Capacity);
    }
    self.records.push(record);
    Ok(())
  }

  pub(crate) fn records(&self) -> &[EventRecord] {
    &self.records
  }

  pub(crate) fn can_reserve(&self, reserved: usize, additional: usize) -> bool {
    self
      .records
      .len()
      .checked_add(reserved)
      .and_then(|value| value.checked_add(additional))
      .is_some_and(|value| value <= self.max_records)
  }

  pub(crate) fn digest(&self) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update((EVENT_STREAM_DOMAIN.len() as u16).to_be_bytes());
    hasher.update(EVENT_STREAM_DOMAIN);
    hasher.update((self.records.len() as u64).to_be_bytes());
    for record in &self.records {
      encode_record(&mut hasher, *record);
    }
    Digest::from_bytes(hasher.finalize().into())
  }
}

fn encode_record(hasher: &mut Sha256, record: EventRecord) {
  match record {
    EventRecord::SendAccepted {
      at_nanos,
      frame,
      link,
      copies,
      bytes,
    } => {
      encode_header(hasher, 1, at_nanos);
      encode_frame(hasher, frame);
      encode_link(hasher, link);
      hasher.update([copies]);
      hasher.update(bytes.to_be_bytes());
    }
    EventRecord::Lost { at_nanos, frame } => {
      encode_header(hasher, 2, at_nanos);
      encode_frame(hasher, frame);
    }
    EventRecord::DuplicateCreated { at_nanos, frame } => {
      encode_header(hasher, 3, at_nanos);
      encode_frame(hasher, frame);
    }
    EventRecord::Reordered {
      at_nanos,
      frame,
      copy,
    } => {
      encode_header(hasher, 4, at_nanos);
      encode_frame(hasher, frame);
      hasher.update([copy]);
    }
    EventRecord::Delivered {
      at_nanos,
      frame,
      copy,
    } => {
      encode_header(hasher, 5, at_nanos);
      encode_frame(hasher, frame);
      hasher.update([copy]);
    }
    EventRecord::Dropped {
      at_nanos,
      frame,
      copy,
      reason,
    } => {
      encode_header(hasher, 6, at_nanos);
      encode_frame(hasher, frame);
      hasher.update([copy, drop_reason_code(reason)]);
    }
    EventRecord::Partitioned {
      at_nanos,
      link,
      partition,
      generation,
    } => {
      encode_header(hasher, 7, at_nanos);
      encode_link(hasher, link);
      hasher.update(partition.value().to_be_bytes());
      hasher.update(generation.to_be_bytes());
    }
    EventRecord::Healed {
      at_nanos,
      link,
      partition,
      generation,
    } => {
      encode_header(hasher, 8, at_nanos);
      encode_link(hasher, link);
      hasher.update(partition.value().to_be_bytes());
      hasher.update(generation.to_be_bytes());
    }
    EventRecord::Restarted {
      at_nanos,
      node,
      boot_epoch,
    } => {
      encode_header(hasher, 9, at_nanos);
      hasher.update(node.value().to_be_bytes());
      hasher.update(boot_epoch.to_be_bytes());
    }
    EventRecord::AddressChanged {
      at_nanos,
      node,
      address,
      generation,
    } => {
      encode_header(hasher, 10, at_nanos);
      hasher.update(node.value().to_be_bytes());
      hasher.update(address.value().to_be_bytes());
      hasher.update(generation.to_be_bytes());
    }
    EventRecord::WallClockChanged {
      at_nanos,
      node,
      previous,
      current,
    } => {
      encode_header(hasher, 11, at_nanos);
      hasher.update(node.value().to_be_bytes());
      hasher.update(previous.to_be_bytes());
      hasher.update(current.to_be_bytes());
    }
    EventRecord::QueueRejected {
      at_nanos,
      frame,
      copies,
      bytes,
    } => {
      encode_header(hasher, 12, at_nanos);
      encode_frame(hasher, frame);
      hasher.update([copies]);
      hasher.update(bytes.to_be_bytes());
    }
  }
}

fn encode_header(hasher: &mut Sha256, variant: u8, at_nanos: u64) {
  hasher.update([variant]);
  hasher.update(at_nanos.to_be_bytes());
}

fn encode_frame(hasher: &mut Sha256, frame: FrameId) {
  hasher.update(frame.value().to_be_bytes());
}

fn encode_link(hasher: &mut Sha256, link: LinkKey) {
  hasher.update(link.from().value().to_be_bytes());
  hasher.update(link.to().value().to_be_bytes());
}

const fn drop_reason_code(reason: DropReason) -> u8 {
  match reason {
    DropReason::Blocked => 1,
    DropReason::StaleLink => 2,
    DropReason::StaleBoot => 3,
    DropReason::StaleAddress => 4,
  }
}

#[cfg(test)]
mod tests {
  use crate::simulation::{
    event::{DropReason, EventKey, EventLog, EventRecord, FrameId},
    topology::{AddressId, LinkKey, NodeKey},
  };

  #[test]
  fn simulation_event_order_is_total_at_equal_deadline() {
    let mut keys = [
      EventKey::new(10, 0, FrameId::new(2), 1, 7),
      EventKey::new(10, 0, FrameId::new(0), 0, 6),
      EventKey::new(10, u64::MAX - 1, FrameId::new(1), 0, 5),
      EventKey::new(10, 0, FrameId::new(0), 0, 4),
      EventKey::new(10, u64::MAX - 2, FrameId::new(2), 0, 8),
    ];
    keys.sort();

    // Deterministic total order at equal deadlines: in-order deliveries by
    // frame and enqueue id, reordered deliveries after them (frame
    // descending within the reordered group).
    assert_eq!(
      keys.iter().map(|key| key.frame.value()).collect::<Vec<_>>(),
      [0, 0, 2, 2, 1],
    );
    assert_eq!(
      keys.iter().map(|key| key.enqueue_id()).collect::<Vec<_>>(),
      [4, 6, 7, 8, 5],
    );
    assert!(keys.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(keys.iter().all(|key| key.deadline_nanos() == 10));
  }

  #[test]
  fn simulation_event_digest_is_canonical_and_behavior_only() {
    let link = LinkKey::new(NodeKey::new(1), NodeKey::new(2));
    let records = [
      EventRecord::SendAccepted {
        at_nanos: 5,
        frame: FrameId::new(9),
        link,
        copies: 2,
        bytes: 16,
      },
      EventRecord::Dropped {
        at_nanos: 7,
        frame: FrameId::new(9),
        copy: 1,
        reason: DropReason::StaleAddress,
      },
      EventRecord::AddressChanged {
        at_nanos: 8,
        node: NodeKey::new(2),
        address: AddressId::new(22),
        generation: 1,
      },
    ];
    let mut first = EventLog::new(3).unwrap();
    let mut second = EventLog::new(3).unwrap();
    for record in records {
      first.push(record).unwrap();
    }
    for record in records {
      second.push(record).unwrap();
    }

    assert_eq!(first.digest(), second.digest());
    assert_eq!(
      first.digest().as_bytes(),
      &[
        0x62, 0xB0, 0x68, 0x4A, 0xC5, 0x44, 0x6C, 0xF5, 0x47, 0xA3, 0xB5, 0xAD, 0xB0, 0x06, 0xBA,
        0x9B, 0xFC, 0xEF, 0x98, 0xD9, 0x52, 0x44, 0xBC, 0x95, 0x89, 0xFE, 0xBE, 0x68, 0x2A, 0xFF,
        0xC0, 0x54,
      ],
    );
    assert_eq!(first.records(), second.records());

    let mut changed = EventLog::new(3).unwrap();
    changed
      .push(EventRecord::SendAccepted {
        at_nanos: 5,
        frame: FrameId::new(9),
        link,
        copies: 1,
        bytes: 16,
      })
      .unwrap();
    assert_ne!(first.digest(), changed.digest());
  }

  #[test]
  fn simulation_event_digest_consumes_upper_node_key_bits() {
    let frame = FrameId::new(5);
    let low = EventRecord::SendAccepted {
      at_nanos: 1,
      frame,
      link: LinkKey::new(NodeKey::new(1), NodeKey::new(2)),
      copies: 1,
      bytes: 8,
    };
    let high = EventRecord::SendAccepted {
      at_nanos: 1,
      frame,
      link: LinkKey::new(NodeKey::new((1_u64 << 63) | 1), NodeKey::new(2)),
      copies: 1,
      bytes: 8,
    };
    let mut low_log = EventLog::new(1).unwrap();
    let mut high_log = EventLog::new(1).unwrap();
    low_log.push(low).unwrap();
    high_log.push(high).unwrap();
    assert_ne!(low_log.digest(), high_log.digest());
  }

  #[test]
  fn simulation_event_encoder_covers_closed_record_set() {
    let left = NodeKey::new(1);
    let right = NodeKey::new(2);
    let link = LinkKey::new(left, right);
    let frame = FrameId::new(3);
    let mut records = vec![
      EventRecord::Lost { at_nanos: 1, frame },
      EventRecord::DuplicateCreated { at_nanos: 2, frame },
      EventRecord::Reordered {
        at_nanos: 3,
        frame,
        copy: 1,
      },
      EventRecord::Partitioned {
        at_nanos: 4,
        link,
        partition: crate::simulation::topology::PartitionId::new(7),
        generation: 1,
      },
      EventRecord::Healed {
        at_nanos: 5,
        link,
        partition: crate::simulation::topology::PartitionId::new(7),
        generation: 2,
      },
      EventRecord::Restarted {
        at_nanos: 6,
        node: right,
        boot_epoch: 1,
      },
      EventRecord::WallClockChanged {
        at_nanos: 7,
        node: right,
        previous: 12,
        current: 3,
      },
      EventRecord::QueueRejected {
        at_nanos: 8,
        frame,
        copies: 2,
        bytes: 64,
      },
    ];
    for (offset, reason) in [
      DropReason::Blocked,
      DropReason::StaleLink,
      DropReason::StaleBoot,
      DropReason::StaleAddress,
    ]
    .into_iter()
    .enumerate()
    {
      records.push(EventRecord::Dropped {
        at_nanos: 9 + offset as u64,
        frame,
        copy: 0,
        reason,
      });
    }
    let mut log = EventLog::new(records.len()).unwrap();
    for record in records {
      assert!(record.at_nanos() > 0);
      log.push(record).unwrap();
    }

    assert_ne!(log.digest().as_bytes(), &[0; 32]);
  }

  #[test]
  fn simulation_event_log_rejects_capacity_before_mutation() {
    assert!(EventLog::new(0).is_err());
    assert!(EventLog::new(usize::MAX).is_err());
    let mut log = EventLog::new(1).unwrap();
    log
      .push(EventRecord::Delivered {
        at_nanos: 1,
        frame: FrameId::new(1),
        copy: 0,
      })
      .unwrap();
    let before = log.clone();

    assert!(
      log
        .push(EventRecord::Delivered {
          at_nanos: 2,
          frame: FrameId::new(2),
          copy: 0,
        })
        .is_err()
    );
    assert_eq!(log, before);
  }
}
