use cyrene_core::{DocumentId, ReplicaId, SpaceId};
use serde::{Deserialize, Serialize};

use crate::Timestamp;

/// Globally unique identity of a replica-authored change.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ChangeId {
    /// Replica that authored the change.
    pub replica: ReplicaId,
    /// Strictly increasing author-local counter, beginning at one.
    pub counter: u64,
}

/// A logical mutation replicated between Cyrene replicas.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Change {
    /// Stable identity used for idempotence and reconciliation.
    pub id: ChangeId,
    /// Space to which this change belongs.
    pub space: SpaceId,
    /// Totally ordered logical commit time.
    pub timestamp: Timestamp,
    /// Application-level state transition.
    pub operation: Operation,
}

/// State transition carried by a [`Change`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Operation {
    /// Insert or replace a document using last-writer-wins semantics.
    Put {
        /// Typed collection name.
        collection: String,
        /// Stable document identity.
        document: DocumentId,
        /// Durable schema fingerprint declared by application code.
        schema: u64,
        /// Versioned application payload envelope.
        payload: Vec<u8>,
    },
    /// Record a last-writer-wins tombstone for a document.
    Delete {
        /// Typed collection name.
        collection: String,
        /// Stable document identity.
        document: DocumentId,
        /// Durable schema fingerprint declared by application code.
        schema: u64,
    },
}

impl Operation {
    /// Returns the collection affected by this operation.
    pub fn collection(&self) -> &str {
        match self {
            Self::Put { collection, .. } | Self::Delete { collection, .. } => collection,
        }
    }

    /// Returns the durable schema fingerprint under which it was authored.
    pub const fn schema(&self) -> u64 {
        match self {
            Self::Put { schema, .. } | Self::Delete { schema, .. } => *schema,
        }
    }

    /// Returns the stable document affected by this operation.
    pub const fn document(&self) -> DocumentId {
        match self {
            Self::Put { document, .. } | Self::Delete { document, .. } => *document,
        }
    }
}
