//! Cyrene makes durable, reactive application state feel local.
//!
//! The common path is an embedded SQLite-backed typed store with no required
//! service. The same application model can opt into deterministic replication,
//! authenticated LAN transport, explicit sharing, and an opaque relay fallback
//! without weakening local durability.

extern crate self as cyrene;

mod app;
mod codec;
mod collection;
mod link;
mod migration;
mod network;
mod relay;
mod replication;
mod transaction;

pub use app::{App, LocalStatus};
pub use collection::{Change, Collection, Subscription};
pub use cyrene_authority::{
    AuthorityError, Capability, EncryptedPayload, EncryptionError, InvitationError,
    InvitationSecret, OpaquePayload, Operation as AuthorizedOperation, Permission, ShareInvitation,
    SpaceAuthority, SpaceKey,
};
pub use cyrene_core::{DocumentId, Error, ErrorCode, Result, SpaceId};
pub use cyrene_core::{FieldSchema, Schema};
pub use cyrene_crdt::{Actor, List, ListOp, Merge, OpId, Text, TextOp};
pub use cyrene_identity::{
    Acknowledgement, Answer, DeviceId, DeviceIdentity, DevicePublicKey, Inviter, Joiner, Offer,
    PairedPeer, PairingCode, PairingError, UserAction, UserEvent, UserId, UserIdentity,
    UserIdentityError,
};
pub use cyrene_macros::Document;
pub use cyrene_net::{
    AuthenticatedConnection, CertificatePin, DiscoveredPeer, DiscoveryAdvertiser, DiscoveryBrowser,
    Listener, NetError, PeerCertificate, QuicCertificate, RelayClient, RelayDelivery,
    RelayEnvelope, RelayMailbox, RelayProtocolError, RelayRejection, RelayRequest, RelayResponse,
    connect as connect_peer,
};
pub use cyrene_store::{BackupReport, CompactionReport};
pub use cyrene_sync::{Change as ReplicationChange, Frontier};
pub use cyrene_trust::{
    DeviceMaterial, OsKeyStore, PeerRecord, RecoveryBundle, RecoverySecret, SpaceAccess,
    SpaceCredentials, TrustError, TrustStore, WrappingKey,
};
pub use link::DeviceLink;
pub use migration::Migration;
pub use network::{LanServer, NetworkSyncReceipt, PeerSyncError};
pub use relay::{
    ConnectivityOptions, ConnectivityReceipt, RelayPullReceipt, RelayPushReceipt, RelaySyncError,
    SyncFallbackError,
};
pub use replication::SyncReceipt;
pub use transaction::{Commit, LocalTransaction};

/// Common imports for a Cyrene application.
pub mod prelude {
    pub use crate::{
        Actor, App, Change, Collection, DeviceLink, DeviceMaterial, Document, DocumentId, Frontier,
        LanServer, List, LocalStatus, LocalTransaction, Migration, NetworkSyncReceipt, PeerRecord,
        ReplicationChange, Result, SyncReceipt, Text,
    };
    pub use serde::{Deserialize, Serialize};
}

/// A value that can be stored as a typed Cyrene document.
///
/// Derive this trait to assign stable document, field, and schema identities
/// while retaining ordinary Serde application values.
pub trait Document: serde::Serialize + serde::de::DeserializeOwned + Send + Sync + 'static {
    /// Durable schema metadata used to detect incompatible local data.
    const SCHEMA: Schema;

    /// Whether this document contains fields explicitly marked for merge.
    const HAS_MERGE_FIELDS: bool;

    /// Merges concurrent payload states into the selected document winner.
    ///
    /// Ordinary fields retain the winner's values. A derived implementation
    /// unions only fields annotated with `#[cyrene(merge)]`.
    ///
    /// # Errors
    ///
    /// Returns an error when an envelope cannot be decoded, a merge-aware field
    /// detects colliding operation identity, or the result cannot be encoded.
    fn merge_payloads(winner: &[u8], concurrent: &[&[u8]]) -> Result<Vec<u8>>;
}

/// Implementation details referenced by generated code.
#[doc(hidden)]
pub mod __private {
    use crate::{Document, Result, codec};

    /// Decodes a versioned typed document envelope.
    pub fn decode_document<T: Document>(payload: &[u8]) -> Result<T> {
        codec::decode(payload)
    }

    /// Encodes a typed document into its deterministic versioned envelope.
    pub fn encode_document<T: Document>(value: &T) -> Result<Vec<u8>> {
        codec::encode(value)
    }
}
