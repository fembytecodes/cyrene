use std::collections::{BTreeMap, BTreeSet};

use cyrene_core::{Error, ErrorCode, ReplicaId, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

/// Globally unique identity for one merge-aware datatype operation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct OpId {
    /// Replica authoring the operation.
    pub replica: ReplicaId,
    /// Strictly increasing actor-local counter beginning at one.
    pub counter: u64,
}

/// Local operation-ID generator for one replica and datatype editing session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Actor {
    replica: ReplicaId,
    counter: u64,
    limit: u64,
}

impl Actor {
    /// Creates an actor whose next operation counter is one.
    pub const fn new(replica: ReplicaId) -> Self {
        Self {
            replica,
            counter: 0,
            limit: u64::MAX,
        }
    }

    /// Restores an actor after its greatest durable counter.
    pub const fn after(replica: ReplicaId, counter: u64) -> Self {
        Self {
            replica,
            counter,
            limit: u64::MAX,
        }
    }

    /// Creates an actor restricted to a durably reserved counter range.
    ///
    /// The first issued counter is `counter + 1`; issuance stops at `limit`.
    ///
    /// # Errors
    ///
    /// Returns an error when `counter` is already beyond `limit`.
    pub fn reserved(replica: ReplicaId, counter: u64, limit: u64) -> Result<Self> {
        if counter > limit {
            return Err(Error::new(
                ErrorCode::InvalidInput,
                "an actor reservation cannot begin beyond its limit",
            ));
        }
        Ok(Self {
            replica,
            counter,
            limit,
        })
    }

    /// Returns the greatest ID issued by this actor, or zero before any issue.
    pub const fn counter(self) -> u64 {
        self.counter
    }

    fn issue(&mut self) -> Result<OpId> {
        if self.counter == self.limit {
            return Err(Error::new(
                ErrorCode::InvalidData,
                "the actor's durable operation-ID reservation is exhausted",
            ));
        }
        self.counter = self.counter.checked_add(1).ok_or_else(|| {
            Error::new(
                ErrorCode::InvalidData,
                "merge-aware operation counter is exhausted",
            )
        })?;
        Ok(OpId {
            replica: self.replica,
            counter: self.counter,
        })
    }
}

/// One commutative operation over a [`List`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ListOp<T> {
    /// Insert a uniquely identified value after an observed element.
    Insert {
        /// Identity of both the operation and new element.
        id: OpId,
        /// Predecessor observed at insertion time, or the list root.
        after: Option<OpId>,
        /// Inserted application value.
        value: T,
    },
    /// Hide an observed element while retaining its anchor for descendants.
    Delete {
        /// Unique identity of the deletion operation.
        id: OpId,
        /// Element that was observed and deleted.
        target: OpId,
    },
}

impl<T> ListOp<T> {
    /// Returns this operation's globally unique identity.
    pub const fn id(&self) -> OpId {
        match self {
            Self::Insert { id, .. } | Self::Delete { id, .. } => *id,
        }
    }
}

/// Outcome of applying an operation to a merge-aware datatype.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Apply {
    /// The operation was new and retained.
    Applied,
    /// The exact operation was already retained.
    Duplicate,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Entry<T> {
    after: Option<OpId>,
    value: T,
}

/// A deterministic, merge-aware replicated list.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct List<T> {
    inserts: BTreeMap<OpId, Entry<T>>,
    deletes: BTreeMap<OpId, OpId>,
}

#[derive(Serialize)]
struct WireListRef<'a, T> {
    inserts: Vec<(OpId, Option<OpId>, &'a T)>,
    deletes: Vec<(OpId, OpId)>,
}

#[derive(Deserialize)]
struct WireList<T> {
    inserts: Vec<(OpId, Option<OpId>, T)>,
    deletes: Vec<(OpId, OpId)>,
}

impl<T: Serialize> Serialize for List<T> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        WireListRef {
            inserts: self
                .inserts
                .iter()
                .map(|(id, entry)| (*id, entry.after, &entry.value))
                .collect(),
            deletes: self
                .deletes
                .iter()
                .map(|(id, target)| (*id, *target))
                .collect(),
        }
        .serialize(serializer)
    }
}

impl<'de, T> Deserialize<'de> for List<T>
where
    T: Clone + Deserialize<'de> + Eq,
{
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = WireList::<T>::deserialize(deserializer)?;
        let mut list = Self::new();
        for (id, after, value) in wire.inserts {
            list.apply(ListOp::Insert { id, after, value })
                .map_err(D::Error::custom)?;
        }
        for (id, target) in wire.deletes {
            list.apply(ListOp::Delete { id, target })
                .map_err(D::Error::custom)?;
        }
        Ok(list)
    }
}

impl<T> Default for List<T> {
    fn default() -> Self {
        Self {
            inserts: BTreeMap::new(),
            deletes: BTreeMap::new(),
        }
    }
}

impl<T> List<T> {
    /// Creates an empty list.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of currently visible elements.
    pub fn len(&self) -> usize {
        self.visible_ids().len()
    }

    /// Returns whether no element is currently visible.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Iterates over visible values in deterministic order.
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.visible_ids()
            .into_iter()
            .filter_map(|id| self.inserts.get(&id).map(|entry| &entry.value))
    }

    /// Returns the operation identity of the visible element at `index`.
    pub fn id_at(&self, index: usize) -> Option<OpId> {
        self.visible_ids().get(index).copied()
    }

    /// Creates and applies an insertion at a visible list index.
    ///
    /// # Errors
    ///
    /// Returns an error when `index` is greater than the visible length, the
    /// actor counter is exhausted, or its next ID collides with retained data.
    pub fn insert(&mut self, actor: &mut Actor, index: usize, value: T) -> Result<ListOp<T>>
    where
        T: Clone + Eq,
    {
        let visible = self.visible_ids();
        if index > visible.len() {
            return Err(Error::new(
                ErrorCode::InvalidInput,
                format!(
                    "list insertion index {index} exceeds length {}",
                    visible.len()
                ),
            ));
        }
        let operation = ListOp::Insert {
            id: actor.issue()?,
            after: index
                .checked_sub(1)
                .and_then(|previous| visible.get(previous).copied()),
            value,
        };
        self.apply(operation.clone())?;
        Ok(operation)
    }

    /// Creates and applies deletion of the visible element at `index`.
    ///
    /// # Errors
    ///
    /// Returns an error when `index` is not visible, the actor counter is
    /// exhausted, or its next ID collides with retained data.
    pub fn remove(&mut self, actor: &mut Actor, index: usize) -> Result<ListOp<T>>
    where
        T: Clone + Eq,
    {
        let target = self.id_at(index).ok_or_else(|| {
            Error::new(
                ErrorCode::InvalidInput,
                format!("list deletion index {index} is not visible"),
            )
        })?;
        let operation = ListOp::Delete {
            id: actor.issue()?,
            target,
        };
        self.apply(operation.clone())?;
        Ok(operation)
    }

    /// Applies an operation idempotently in any delivery order.
    ///
    /// Insertions whose anchors have not arrived remain retained and become
    /// visible when their ancestry is complete. Deletions may arrive before
    /// their target insertion.
    ///
    /// # Errors
    ///
    /// Returns an error if an operation ID is zero or collides with different
    /// retained content.
    pub fn apply(&mut self, operation: ListOp<T>) -> Result<Apply>
    where
        T: Clone + Eq,
    {
        validate_id(operation.id())?;
        if let Some(existing) = self.operation(operation.id()) {
            return if existing == operation {
                Ok(Apply::Duplicate)
            } else {
                Err(collision(operation.id()))
            };
        }
        match operation {
            ListOp::Insert { id, after, value } => {
                if let Some(anchor) = after {
                    validate_id(anchor)?;
                }
                if after == Some(id) {
                    return Err(Error::new(
                        ErrorCode::InvalidData,
                        "a list insertion cannot use itself as its anchor",
                    ));
                }
                self.inserts.insert(id, Entry { after, value });
            }
            ListOp::Delete { id, target } => {
                validate_id(target)?;
                self.deletes.insert(id, target);
            }
        }
        Ok(Apply::Applied)
    }

    /// Unions another replica state into this list.
    ///
    /// # Errors
    ///
    /// Returns an error on any operation-ID collision and leaves this list
    /// unchanged.
    pub fn merge(&mut self, other: &Self) -> Result<()>
    where
        T: Clone + Eq,
    {
        let mut staged = self.clone();
        for operation in other.operations() {
            staged.apply(operation)?;
        }
        *self = staged;
        Ok(())
    }

    /// Returns all retained operations in stable operation-ID order.
    pub fn operations(&self) -> Vec<ListOp<T>>
    where
        T: Clone,
    {
        let mut operations = self
            .inserts
            .iter()
            .map(|(id, entry)| ListOp::Insert {
                id: *id,
                after: entry.after,
                value: entry.value.clone(),
            })
            .chain(self.deletes.iter().map(|(id, target)| ListOp::Delete {
                id: *id,
                target: *target,
            }))
            .collect::<Vec<_>>();
        operations.sort_by_key(ListOp::id);
        operations
    }

    fn operation(&self, id: OpId) -> Option<ListOp<T>>
    where
        T: Clone,
    {
        self.inserts
            .get(&id)
            .map(|entry| ListOp::Insert {
                id,
                after: entry.after,
                value: entry.value.clone(),
            })
            .or_else(|| {
                self.deletes.get(&id).map(|target| ListOp::Delete {
                    id,
                    target: *target,
                })
            })
    }

    fn visible_ids(&self) -> Vec<OpId> {
        let deleted = self.deletes.values().copied().collect::<BTreeSet<_>>();
        let mut children = BTreeMap::<Option<OpId>, Vec<OpId>>::new();
        for (id, entry) in &self.inserts {
            children.entry(entry.after).or_default().push(*id);
        }
        let mut visible = Vec::new();
        let mut visiting = BTreeSet::new();
        visit(None, &children, &deleted, &mut visiting, &mut visible);
        visible
    }
}

fn visit(
    parent: Option<OpId>,
    children: &BTreeMap<Option<OpId>, Vec<OpId>>,
    deleted: &BTreeSet<OpId>,
    visiting: &mut BTreeSet<OpId>,
    visible: &mut Vec<OpId>,
) {
    let Some(direct_children) = children.get(&parent) else {
        return;
    };
    for child in direct_children {
        if !visiting.insert(*child) {
            continue;
        }
        if !deleted.contains(child) {
            visible.push(*child);
        }
        visit(Some(*child), children, deleted, visiting, visible);
        visiting.remove(child);
    }
}

fn validate_id(id: OpId) -> Result<()> {
    if id.counter == 0 {
        return Err(Error::new(
            ErrorCode::InvalidData,
            "merge-aware operation counter must be non-zero",
        ));
    }
    Ok(())
}

fn collision(id: OpId) -> Error {
    Error::new(
        ErrorCode::InvalidData,
        format!(
            "merge-aware operation {}:{} collides with different content",
            id.replica, id.counter
        ),
    )
}

#[cfg(test)]
mod tests {
    use cyrene_core::{ErrorCode, ReplicaId};
    use proptest::prelude::*;

    use crate::{Actor, Apply, List, ListOp, OpId};

    fn actor(id: u128) -> Actor {
        Actor::new(ReplicaId::from_u128(id))
    }

    #[test]
    fn concurrent_insertions_converge_in_operation_identity_order() {
        let mut first_actor = actor(1);
        let mut second_actor = actor(2);
        let mut first = List::new();
        let mut second = List::new();
        let first_op = first.insert(&mut first_actor, 0, "first").unwrap();
        let second_op = second.insert(&mut second_actor, 0, "second").unwrap();

        first.apply(second_op.clone()).unwrap();
        second.apply(first_op.clone()).unwrap();

        assert_eq!(first, second);
        assert_eq!(
            first.iter().copied().collect::<Vec<_>>(),
            ["first", "second"]
        );
        assert_eq!(first.apply(second_op).unwrap(), Apply::Duplicate);
    }

    #[test]
    fn child_and_delete_may_arrive_before_their_targets() {
        let replica = ReplicaId::from_u128(1);
        let parent = OpId {
            replica,
            counter: 1,
        };
        let child = OpId {
            replica,
            counter: 2,
        };
        let deletion = OpId {
            replica,
            counter: 3,
        };
        let mut list = List::new();
        list.apply(ListOp::Insert {
            id: child,
            after: Some(parent),
            value: 'b',
        })
        .unwrap();
        list.apply(ListOp::Delete {
            id: deletion,
            target: parent,
        })
        .unwrap();
        assert!(list.is_empty());

        list.apply(ListOp::Insert {
            id: parent,
            after: None,
            value: 'a',
        })
        .unwrap();
        assert_eq!(list.iter().copied().collect::<String>(), "b");
    }

    #[test]
    fn collision_rejects_merge_without_partial_changes() {
        let replica = ReplicaId::from_u128(1);
        let id = OpId {
            replica,
            counter: 1,
        };
        let mut first = List::new();
        first
            .apply(ListOp::Insert {
                id,
                after: None,
                value: "first",
            })
            .unwrap();
        let before = first.clone();
        let mut second = List::new();
        second
            .apply(ListOp::Insert {
                id,
                after: None,
                value: "different",
            })
            .unwrap();

        let error = first.merge(&second).unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidData);
        assert_eq!(first, before);
    }

    proptest! {
        #[test]
        fn arbitrary_delivery_order_and_duplication_converges(
            actions in prop::collection::vec((any::<bool>(), any::<bool>(), any::<u8>(), any::<u8>()), 1..100),
            first_seed in any::<u64>(),
            second_seed in any::<u64>(),
        ) {
            let mut source = List::new();
            let mut actors = [actor(1), actor(2)];
            let mut operations = Vec::new();
            for (second, delete, index, value) in actions {
                let actor = &mut actors[usize::from(second)];
                if delete && !source.is_empty() {
                    let index = usize::from(index) % source.len();
                    operations.push(source.remove(actor, index).unwrap());
                } else {
                    let index = usize::from(index) % (source.len() + 1);
                    operations.push(source.insert(actor, index, value).unwrap());
                }
            }

            let mut first_order = operations.clone();
            first_order.sort_by_key(|operation| mix(first_seed, operation.id()));
            let mut second_order = operations.clone();
            second_order.sort_by_key(|operation| mix(second_seed, operation.id()));
            let mut first = List::new();
            let mut second = List::new();
            for operation in first_order.iter().chain(first_order.iter().take(first_order.len() / 3)) {
                first.apply(operation.clone()).unwrap();
            }
            for operation in second_order.iter().chain(second_order.iter().rev().take(second_order.len() / 2)) {
                second.apply(operation.clone()).unwrap();
            }

            prop_assert_eq!(&first, &second);
            prop_assert_eq!(first.iter().copied().collect::<Vec<_>>(), source.iter().copied().collect::<Vec<_>>());
        }
    }

    fn mix(seed: u64, id: OpId) -> u64 {
        let replica = id.replica.as_u128().to_be_bytes();
        let replica = u64::from_be_bytes(replica[..8].try_into().unwrap())
            ^ u64::from_be_bytes(replica[8..].try_into().unwrap());
        let mut value = seed ^ id.counter ^ replica.rotate_left(23);
        value ^= value >> 30;
        value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value ^ (value >> 27)
    }
}
