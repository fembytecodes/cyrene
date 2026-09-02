use std::collections::{BTreeMap, BTreeSet};

use cyrene_core::{Error, ErrorCode, ReplicaId, Result};

use crate::{Apply, Change, Replica};

/// One queued change between simulated replicas.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Envelope {
    /// Sending replica.
    pub from: ReplicaId,
    /// Intended recipient.
    pub to: ReplicaId,
    /// Replicated logical change.
    pub change: Change,
}

/// Deterministic in-memory transport for partition and ordering tests.
#[derive(Clone, Debug, Default)]
pub struct Simulator {
    replicas: BTreeMap<ReplicaId, Replica>,
    queue: Vec<Envelope>,
    partitions: BTreeSet<(ReplicaId, ReplicaId)>,
}

impl Simulator {
    /// Creates an empty simulator.
    pub const fn new() -> Self {
        Self {
            replicas: BTreeMap::new(),
            queue: Vec::new(),
            partitions: BTreeSet::new(),
        }
    }

    /// Adds a replica, replacing no existing identity.
    ///
    /// # Errors
    ///
    /// Returns an error when the identity is already present.
    pub fn add(&mut self, replica: Replica) -> Result<()> {
        let id = replica.id();
        if self.replicas.insert(id, replica).is_some() {
            return Err(Error::new(
                ErrorCode::InvalidInput,
                format!("simulator already contains replica {id}"),
            ));
        }
        Ok(())
    }

    /// Returns an immutable replica by identity.
    pub fn replica(&self, id: ReplicaId) -> Option<&Replica> {
        self.replicas.get(&id)
    }

    /// Returns a mutable replica by identity.
    pub fn replica_mut(&mut self, id: ReplicaId) -> Option<&mut Replica> {
        self.replicas.get_mut(&id)
    }

    /// Queues one change for every replica except its author.
    pub fn broadcast(&mut self, from: ReplicaId, change: &Change) {
        self.queue.extend(
            self.replicas
                .keys()
                .copied()
                .filter(|to| *to != from)
                .map(|to| Envelope {
                    from,
                    to,
                    change: change.clone(),
                }),
        );
    }

    /// Queues all changes the recipient's frontier is known to lack.
    ///
    /// # Errors
    ///
    /// Returns an error if either replica does not exist.
    pub fn reconcile(&mut self, from: ReplicaId, to: ReplicaId) -> Result<usize> {
        let target = self.replicas.get(&to).ok_or_else(|| missing_replica(to))?;
        let source = self
            .replicas
            .get(&from)
            .ok_or_else(|| missing_replica(from))?;
        let changes = source.missing_for(target.frontier());
        let count = changes.len();
        self.queue.extend(
            changes
                .into_iter()
                .map(|change| Envelope { from, to, change }),
        );
        Ok(count)
    }

    /// Duplicates a queued envelope to exercise idempotence.
    ///
    /// # Errors
    ///
    /// Returns an error when `index` is outside the queue.
    pub fn duplicate(&mut self, index: usize) -> Result<()> {
        let envelope =
            self.queue.get(index).cloned().ok_or_else(|| {
                Error::new(ErrorCode::InvalidInput, "queue index is out of bounds")
            })?;
        self.queue.push(envelope);
        Ok(())
    }

    /// Prevents delivery in both directions between two replicas.
    pub fn partition(&mut self, first: ReplicaId, second: ReplicaId) {
        self.partitions.insert(pair(first, second));
    }

    /// Restores delivery in both directions between two replicas.
    pub fn heal(&mut self, first: ReplicaId, second: ReplicaId) {
        self.partitions.remove(&pair(first, second));
    }

    /// Delivers one queued envelope by index.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing queue entry, an active partition, an
    /// unknown recipient, or an invalid change.
    pub fn deliver(&mut self, index: usize, now_ms: u64) -> Result<Apply> {
        let envelope =
            self.queue.get(index).cloned().ok_or_else(|| {
                Error::new(ErrorCode::InvalidInput, "queue index is out of bounds")
            })?;
        if self.partitions.contains(&pair(envelope.from, envelope.to)) {
            return Err(Error::new(
                ErrorCode::InvalidInput,
                "the simulated link is partitioned",
            ));
        }
        self.queue.remove(index);
        self.replicas
            .get_mut(&envelope.to)
            .ok_or_else(|| missing_replica(envelope.to))?
            .apply(envelope.change, now_ms)
    }

    /// Returns queued envelopes in their current delivery order.
    pub fn queue(&self) -> &[Envelope] {
        &self.queue
    }

    /// Reorders queued envelopes using a complete index permutation.
    ///
    /// # Errors
    ///
    /// Returns an error unless every current index occurs exactly once.
    pub fn reorder(&mut self, order: &[usize]) -> Result<()> {
        if order.len() != self.queue.len() {
            return Err(invalid_permutation());
        }
        let indexes = order.iter().copied().collect::<BTreeSet<_>>();
        if indexes.len() != order.len() || indexes.last().copied() != order.len().checked_sub(1) {
            return Err(invalid_permutation());
        }
        self.queue = order
            .iter()
            .map(|index| self.queue[*index].clone())
            .collect();
        Ok(())
    }
}

fn pair(first: ReplicaId, second: ReplicaId) -> (ReplicaId, ReplicaId) {
    if first <= second {
        (first, second)
    } else {
        (second, first)
    }
}

fn missing_replica(id: ReplicaId) -> Error {
    Error::new(
        ErrorCode::InvalidInput,
        format!("simulator has no replica {id}"),
    )
}

fn invalid_permutation() -> Error {
    Error::new(
        ErrorCode::InvalidInput,
        "queue order must be a complete index permutation",
    )
}

#[cfg(test)]
mod tests {
    use cyrene_core::{DocumentId, ReplicaId, SpaceId};

    use crate::{Operation, Replica, Simulator};

    #[test]
    fn partitioned_offline_edits_reconcile_after_healing() {
        let space = SpaceId::from_u128(1);
        let first_id = ReplicaId::from_u128(1);
        let second_id = ReplicaId::from_u128(2);
        let mut first = Replica::new(first_id, space);
        let mut second = Replica::new(second_id, space);
        first.register_schema("notes", 1).unwrap();
        second.register_schema("notes", 1).unwrap();
        let mut simulator = Simulator::new();
        simulator.add(first).unwrap();
        simulator.add(second).unwrap();
        simulator.partition(first_id, second_id);

        let first_change = simulator
            .replica_mut(first_id)
            .unwrap()
            .author(put(1, 1), 10)
            .unwrap();
        let second_change = simulator
            .replica_mut(second_id)
            .unwrap()
            .author(put(2, 2), 10)
            .unwrap();
        simulator.broadcast(first_id, &first_change);
        simulator.broadcast(second_id, &second_change);
        assert!(simulator.deliver(0, 10).is_err());

        simulator.heal(first_id, second_id);
        simulator.duplicate(0).unwrap();
        while !simulator.queue().is_empty() {
            simulator.deliver(0, 20).unwrap();
        }
        simulator.reconcile(first_id, second_id).unwrap();
        simulator.reconcile(second_id, first_id).unwrap();
        while !simulator.queue().is_empty() {
            simulator.deliver(0, 20).unwrap();
        }

        let first = simulator.replica(first_id).unwrap();
        let second = simulator.replica(second_id).unwrap();
        assert_eq!(
            first.documents().collect::<Vec<_>>(),
            second.documents().collect::<Vec<_>>()
        );
        assert_eq!(first.change_count(), 2);
        assert_eq!(second.change_count(), 2);
    }

    fn put(document: u128, value: u8) -> Operation {
        Operation::Put {
            collection: "notes".into(),
            document: DocumentId::from_u128(document),
            schema: 1,
            payload: vec![value],
        }
    }
}
