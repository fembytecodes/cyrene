//! Deterministic, transport-independent replication for Cyrene.
//!
//! Networking is intentionally absent from this crate. A [`Replica`] accepts
//! authenticated changes only after an outer layer has established identity
//! and authority. Its state machine tolerates duplicated and reordered input
//! and converges when replicas possess the same valid changes.

mod change;
mod clock;
mod frontier;
mod replica;
mod simulator;

pub use change::{Change, ChangeId, Operation};
pub use clock::{Clock, Timestamp};
pub use frontier::Frontier;
pub use replica::{Apply, DocumentKey, MaterializedDocument, Replica};
pub use simulator::{Envelope, Simulator};
