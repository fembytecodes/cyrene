use std::collections::{BTreeMap, BTreeSet};

use cyrene_core::{DocumentId, Error, ErrorCode, ReplicaId, Result, SpaceId};

use crate::{Change, ChangeId, Clock, Frontier, Operation, Timestamp};

const MAX_COLLECTION_BYTES: usize = 128;
const MAX_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;

/// Stable key of one document in materialized replica state.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DocumentKey {
    /// Typed collection containing the document.
    pub collection: String,
    /// Stable document identity.
    pub document: DocumentId,
}

/// Winning last-writer state for one document, including tombstones.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializedDocument {
    /// Schema fingerprint under which the mutation was authored.
    pub schema: u64,
    /// Payload for a live document, or `None` for a tombstone.
    pub payload: Option<Vec<u8>>,
    /// Logical timestamp of the winning mutation.
    pub timestamp: Timestamp,
    /// Identity of the winning change.
    pub change: ChangeId,
}

/// Outcome of applying a valid change.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Apply {
    /// A new change was retained. `visible` indicates whether it changed the
    /// materialized winner for its document.
    Applied {
        /// Whether visible state changed.
        visible: bool,
    },
    /// The exact change was already retained.
    Duplicate,
}

/// Deterministic state of one replica of a space.
#[derive(Clone, Debug)]
pub struct Replica {
    id: ReplicaId,
    space: SpaceId,
    next_counter: u64,
    clock: Clock,
    schemas: BTreeMap<String, BTreeSet<u64>>,
    changes: BTreeMap<ChangeId, Change>,
    frontier: Frontier,
    documents: BTreeMap<DocumentKey, MaterializedDocument>,
}

impl Replica {
    /// Creates an empty replica for one space.
    pub const fn new(id: ReplicaId, space: SpaceId) -> Self {
        Self {
            id,
            space,
            next_counter: 0,
            clock: Clock::new(id),
            schemas: BTreeMap::new(),
            changes: BTreeMap::new(),
            frontier: Frontier::new(),
            documents: BTreeMap::new(),
        }
    }

    /// Returns this replica's stable identity.
    pub const fn id(&self) -> ReplicaId {
        self.id
    }

    /// Returns the replicated space identity.
    pub const fn space(&self) -> SpaceId {
        self.space
    }

    /// Registers a schema fingerprint accepted for a collection.
    ///
    /// Multiple fingerprints may coexist while historical changes remain
    /// replayable across an explicit schema migration.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid collection name.
    pub fn register_schema(&mut self, collection: impl Into<String>, schema: u64) -> Result<()> {
        let collection = collection.into();
        validate_collection(&collection)?;
        self.schemas.entry(collection).or_default().insert(schema);
        Ok(())
    }

    /// Authors and immediately applies one local change.
    ///
    /// # Errors
    ///
    /// Returns an error when the operation is invalid, its schema is not
    /// configured, or the local change counter is exhausted.
    pub fn author(&mut self, operation: Operation, now_ms: u64) -> Result<Change> {
        self.validate_operation(&operation)?;
        let counter = self.next_counter.checked_add(1).ok_or_else(|| {
            Error::new(
                ErrorCode::InvalidData,
                "the local change counter is exhausted",
            )
        })?;
        let change = Change {
            id: ChangeId {
                replica: self.id,
                counter,
            },
            space: self.space,
            timestamp: self.clock.tick(now_ms),
            operation,
        };
        self.next_counter = counter;
        let outcome = self.apply_validated(change.clone());
        debug_assert!(matches!(outcome, Apply::Applied { .. }));
        Ok(change)
    }

    /// Applies one remote change idempotently.
    ///
    /// # Errors
    ///
    /// Returns an error if the change targets another space, is malformed,
    /// collides with a retained change ID, exceeds bounds, or uses an
    /// unconfigured schema. Invalid changes do not affect replica state.
    pub fn apply(&mut self, change: Change, now_ms: u64) -> Result<Apply> {
        self.validate_change(&change)?;
        if let Some(existing) = self.changes.get(&change.id) {
            return if existing == &change {
                Ok(Apply::Duplicate)
            } else {
                Err(Error::new(
                    ErrorCode::InvalidData,
                    format!(
                        "change {}:{} collides with different retained content",
                        change.id.replica, change.id.counter
                    ),
                ))
            };
        }
        self.clock.observe(change.timestamp, now_ms);
        Ok(self.apply_validated(change))
    }

    /// Returns the contiguous reconciliation frontier.
    pub const fn frontier(&self) -> &Frontier {
        &self.frontier
    }

    /// Returns retained changes absent beyond `peer`'s contiguous frontier.
    pub fn missing_for(&self, peer: &Frontier) -> Vec<Change> {
        self.changes
            .values()
            .filter(|change| change.id.counter > peer.get(change.id.replica))
            .cloned()
            .collect()
    }

    /// Returns one bounded page of changes between `peer` and a fixed target.
    ///
    /// The target should be a previously captured local frontier. Changes
    /// authored after that snapshot are excluded, so a reconciliation session
    /// terminates even while new writes continue.
    pub fn missing_for_target(
        &self,
        peer: &Frontier,
        target: &Frontier,
        limit: usize,
    ) -> (Vec<Change>, bool) {
        let mut changes = self
            .changes
            .values()
            .filter(|change| {
                change.id.counter > peer.get(change.id.replica)
                    && change.id.counter <= target.get(change.id.replica)
            })
            .take(limit.saturating_add(1))
            .cloned()
            .collect::<Vec<_>>();
        let has_more = changes.len() > limit;
        changes.truncate(limit);
        (changes, has_more)
    }

    /// Returns the winning state, including tombstones, for one document.
    pub fn document(
        &self,
        collection: &str,
        document: DocumentId,
    ) -> Option<&MaterializedDocument> {
        self.documents.get(&DocumentKey {
            collection: collection.to_owned(),
            document,
        })
    }

    /// Iterates over all materialized winners, including tombstones.
    pub fn documents(&self) -> impl Iterator<Item = (&DocumentKey, &MaterializedDocument)> {
        self.documents.iter()
    }

    /// Returns the number of retained unique changes.
    pub fn change_count(&self) -> usize {
        self.changes.len()
    }

    /// Iterates over retained changes affecting one document.
    pub fn changes_for_document(
        &self,
        collection: &str,
        document: DocumentId,
    ) -> impl Iterator<Item = &Change> {
        self.changes.values().filter(move |change| {
            change.operation.collection() == collection && change.operation.document() == document
        })
    }

    fn validate_change(&self, change: &Change) -> Result<()> {
        if change.space != self.space {
            return Err(Error::new(
                ErrorCode::InvalidInput,
                "a change cannot cross space boundaries",
            ));
        }
        if change.id.counter == 0 || change.timestamp.replica != change.id.replica {
            return Err(Error::new(
                ErrorCode::InvalidData,
                "a change has an invalid author counter or timestamp",
            ));
        }
        self.validate_operation(&change.operation)
    }

    fn validate_operation(&self, operation: &Operation) -> Result<()> {
        validate_collection(operation.collection())?;
        let accepted = self.schemas.get(operation.collection()).ok_or_else(|| {
            Error::new(
                ErrorCode::InvalidData,
                format!(
                    "collection '{}' has no configured schema",
                    operation.collection()
                ),
            )
        })?;
        if !accepted.contains(&operation.schema()) {
            return Err(Error::new(
                ErrorCode::InvalidData,
                format!(
                    "collection '{}' does not accept schema {:016x}",
                    operation.collection(),
                    operation.schema()
                ),
            ));
        }
        if let Operation::Put { payload, .. } = operation
            && payload.len() > MAX_PAYLOAD_BYTES
        {
            return Err(Error::new(
                ErrorCode::InvalidData,
                format!("replicated payload exceeds {MAX_PAYLOAD_BYTES} bytes"),
            ));
        }
        Ok(())
    }

    fn apply_validated(&mut self, change: Change) -> Apply {
        let key = match &change.operation {
            Operation::Put {
                collection,
                document,
                ..
            }
            | Operation::Delete {
                collection,
                document,
                ..
            } => DocumentKey {
                collection: collection.clone(),
                document: *document,
            },
        };
        let candidate = MaterializedDocument {
            schema: change.operation.schema(),
            payload: match &change.operation {
                Operation::Put { payload, .. } => Some(payload.clone()),
                Operation::Delete { .. } => None,
            },
            timestamp: change.timestamp,
            change: change.id,
        };
        let visible = self.documents.get(&key).is_none_or(|current| {
            (candidate.timestamp, candidate.change) > (current.timestamp, current.change)
        });
        if visible {
            self.documents.insert(key, candidate);
        }
        let author = change.id.replica;
        if author == self.id {
            self.next_counter = self.next_counter.max(change.id.counter);
        }
        self.changes.insert(change.id, change);
        self.advance_frontier(author);
        Apply::Applied { visible }
    }

    fn advance_frontier(&mut self, author: ReplicaId) {
        let mut counter = self.frontier.get(author);
        loop {
            let Some(next) = counter.checked_add(1) else {
                break;
            };
            if !self.changes.contains_key(&ChangeId {
                replica: author,
                counter: next,
            }) {
                break;
            }
            counter = next;
        }
        self.frontier.set(author, counter);
    }
}

fn validate_collection(collection: &str) -> Result<()> {
    if collection.is_empty() || collection.len() > MAX_COLLECTION_BYTES {
        return Err(Error::new(
            ErrorCode::InvalidInput,
            format!("collection names must contain between 1 and {MAX_COLLECTION_BYTES} bytes"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use cyrene_core::{DocumentId, ReplicaId, SpaceId};
    use proptest::prelude::*;

    use crate::{Apply, Change, Operation, Replica};

    const SCHEMA: u64 = 0xcafe;

    fn replica(id: u128, space: SpaceId) -> Replica {
        let mut replica = Replica::new(ReplicaId::from_u128(id), space);
        replica.register_schema("notes", SCHEMA).unwrap();
        replica
    }

    fn put(document: DocumentId, value: u8) -> Operation {
        Operation::Put {
            collection: "notes".into(),
            document,
            schema: SCHEMA,
            payload: vec![value],
        }
    }

    #[test]
    fn concurrent_writes_converge_independent_of_delivery_order() {
        let space = SpaceId::from_u128(1);
        let document = DocumentId::from_u128(1);
        let mut first = replica(1, space);
        let mut second = replica(2, space);
        let first_change = first.author(put(document, 1), 100).unwrap();
        let second_change = second.author(put(document, 2), 100).unwrap();

        first.apply(second_change.clone(), 100).unwrap();
        second.apply(first_change.clone(), 100).unwrap();

        assert_eq!(
            first.document("notes", document),
            second.document("notes", document)
        );
        assert_eq!(
            first.document("notes", document).unwrap().payload,
            Some(vec![2])
        );
        assert_eq!(first.apply(second_change, 100).unwrap(), Apply::Duplicate);
    }

    #[test]
    fn frontier_does_not_claim_changes_across_a_gap() {
        let space = SpaceId::from_u128(1);
        let document = DocumentId::from_u128(1);
        let author = ReplicaId::from_u128(1);
        let mut source = replica(1, space);
        let first = source.author(put(document, 1), 1).unwrap();
        let second = source.author(put(document, 2), 2).unwrap();
        let mut target = replica(2, space);

        target.apply(second, 2).unwrap();
        assert_eq!(target.frontier().get(author), 0);
        target.apply(first, 2).unwrap();
        assert_eq!(target.frontier().get(author), 2);
    }

    #[test]
    fn newer_delete_remains_as_a_tombstone() {
        let space = SpaceId::from_u128(1);
        let document = DocumentId::from_u128(1);
        let mut source = replica(1, space);
        source.author(put(document, 1), 1).unwrap();
        source
            .author(
                Operation::Delete {
                    collection: "notes".into(),
                    document,
                    schema: SCHEMA,
                },
                2,
            )
            .unwrap();
        assert_eq!(source.document("notes", document).unwrap().payload, None);
    }

    proptest! {
        #[test]
        fn arbitrary_reordering_and_duplication_converges(
            operations in prop::collection::vec((any::<bool>(), 0_u8..8, any::<u8>(), 0_u16..500, any::<bool>()), 1..80),
            first_seed in any::<u64>(),
            second_seed in any::<u64>(),
        ) {
            let space = SpaceId::from_u128(9);
            let mut first = replica(1, space);
            let mut second = replica(2, space);
            let mut changes = Vec::<Change>::new();
            for (use_second, document, value, now, delete) in operations {
                let document = DocumentId::from_u128(u128::from(document) + 1);
                let operation = if delete {
                    Operation::Delete {
                        collection: "notes".into(),
                        document,
                        schema: SCHEMA,
                    }
                } else {
                    put(document, value)
                };
                let author = if use_second { &mut second } else { &mut first };
                changes.push(author.author(operation, u64::from(now)).unwrap());
            }

            let mut first_order = changes.clone();
            first_order.sort_by_key(|change| mix(first_seed, change));
            let mut second_order = changes.clone();
            second_order.sort_by_key(|change| mix(second_seed, change));
            for change in first_order.iter().chain(first_order.iter().take(first_order.len() / 3)) {
                first.apply(change.clone(), 1_000).unwrap();
            }
            for change in second_order.iter().chain(second_order.iter().rev().take(second_order.len() / 2)) {
                second.apply(change.clone(), 1_000).unwrap();
            }

            let first_state = first.documents().collect::<Vec<_>>();
            let second_state = second.documents().collect::<Vec<_>>();
            prop_assert_eq!(first_state, second_state);
            prop_assert_eq!(first.frontier(), second.frontier());
            prop_assert_eq!(first.change_count(), changes.len());
            prop_assert_eq!(second.change_count(), changes.len());
        }
    }

    fn mix(seed: u64, change: &Change) -> u64 {
        let replica = change.id.replica.as_u128().to_be_bytes();
        let replica = u64::from_be_bytes(replica[..8].try_into().unwrap())
            ^ u64::from_be_bytes(replica[8..].try_into().unwrap());
        let mut value = seed ^ change.id.counter ^ replica.rotate_left(17);
        value ^= value >> 30;
        value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value ^= value >> 27;
        value.wrapping_mul(0x94d0_49bb_1331_11eb) ^ (value >> 31)
    }
}
