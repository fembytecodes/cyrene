//! Stable identifiers and storage-independent semantics used by Cyrene.

mod error;
mod id;
mod schema;

pub use error::{Error, ErrorCode, Result};
pub use id::{AppId, DocumentId, ReplicaId, SpaceId};
pub use schema::{FieldSchema, Schema};

/// The current durable storage envelope version.
pub const STORAGE_VERSION: u32 = 1;
