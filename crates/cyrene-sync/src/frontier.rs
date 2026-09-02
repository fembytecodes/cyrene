use std::collections::BTreeMap;

use cyrene_core::ReplicaId;
use serde::{Deserialize, Serialize};

/// Greatest contiguous change counter known for each replica.
///
/// A frontier never claims receipt beyond a gap. It is therefore safe for
/// reconciliation even when changes arrive out of order.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Frontier(BTreeMap<ReplicaId, u64>);

impl Frontier {
    /// Creates an empty frontier.
    pub const fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Returns the greatest contiguous counter known for `replica`.
    pub fn get(&self, replica: ReplicaId) -> u64 {
        self.0.get(&replica).copied().unwrap_or(0)
    }

    /// Iterates over replicas with at least one contiguous change.
    pub fn iter(&self) -> impl Iterator<Item = (ReplicaId, u64)> + '_ {
        self.0.iter().map(|(replica, counter)| (*replica, *counter))
    }

    pub(crate) fn set(&mut self, replica: ReplicaId, counter: u64) {
        if counter == 0 {
            self.0.remove(&replica);
        } else {
            self.0.insert(replica, counter);
        }
    }
}
