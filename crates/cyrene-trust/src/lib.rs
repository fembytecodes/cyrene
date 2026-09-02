//! Encrypted persistence for device credentials, peer pins, and invitations.
//!
//! [`OsKeyStore`] keeps the vault's [`WrappingKey`] in the host credential
//! store. The vault never persists it. Device signing and TLS private keys are sealed with
//! XChaCha20-Poly1305 before entering `SQLite`. Peer public records remain
//! inspectable, while invitation redemption and peer admission are atomic.

#![forbid(unsafe_code)]

use std::path::Path;

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use cyrene_authority::{Capability, Operation, ShareInvitation, SpaceAuthority, SpaceKey};
use cyrene_core::SpaceId;
use cyrene_identity::{
    DeviceIdentity, DevicePublicKey, PairedPeer, PairingError, UserEvent, UserId, UserIdentity,
    UserIdentityError,
};
use cyrene_net::{CertificatePin, PeerCertificate, QuicCertificate};
use keyring::{Entry, Error as KeyringError};
use rusqlite::{Connection, MAIN_DB, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

const VAULT_VERSION: u32 = 6;
const DEVICE_AAD: &[u8] = b"cyrene/trust-vault/device-material/1";
const SPACE_KEY_AAD: &[u8] = b"cyrene/trust-vault/space-key/1";
const KEYRING_SERVICE: &str = "dev.cyrene.trust";
const RECOVERY_DOMAIN: &[u8] = b"cyrene/recovery-bundle/1";
const RECOVERY_MAGIC: &[u8; 8] = b"CYRREC01";
const RECOVERY_VERSION: u8 = 1;
const MAX_RECOVERY_DATABASE_BYTES: usize = 256 * 1024 * 1024;
const VAULT_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS vault_meta (
     singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
     version INTEGER NOT NULL
 ) STRICT;
 CREATE TABLE IF NOT EXISTS device_material (
     singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
     public_key BLOB NOT NULL,
     certificate_der BLOB NOT NULL,
     sealed BLOB NOT NULL
 ) STRICT;
 CREATE TABLE IF NOT EXISTS invitations (
     invitation_id BLOB PRIMARY KEY NOT NULL,
     expires_at INTEGER NOT NULL,
     redeemed_at INTEGER
 ) STRICT;
 CREATE TABLE IF NOT EXISTS paired_peers (
     device_id BLOB PRIMARY KEY NOT NULL,
     public_key BLOB NOT NULL,
     certificate_der BLOB NOT NULL,
     paired_at INTEGER NOT NULL
 ) STRICT;
 CREATE TABLE IF NOT EXISTS peer_spaces (
     device_id BLOB NOT NULL REFERENCES paired_peers(device_id) ON DELETE CASCADE,
     space_id BLOB NOT NULL,
     PRIMARY KEY (device_id, space_id)
 ) STRICT;
 CREATE TABLE IF NOT EXISTS space_access (
     space_id BLOB PRIMARY KEY NOT NULL,
     issuer BLOB NOT NULL,
     epoch INTEGER NOT NULL CHECK (epoch >= 0),
     capability BLOB NOT NULL
 ) STRICT;
 CREATE TABLE IF NOT EXISTS space_keys (
     space_id BLOB NOT NULL,
     epoch INTEGER NOT NULL CHECK (epoch >= 0),
     sealed BLOB NOT NULL,
     PRIMARY KEY (space_id, epoch)
 ) STRICT;
 CREATE TABLE IF NOT EXISTS share_invitations (
     invitation_id BLOB PRIMARY KEY NOT NULL,
     offer_hash BLOB NOT NULL,
     expires_at INTEGER NOT NULL,
     redeemed_at INTEGER,
     subject BLOB,
     capability BLOB
 ) STRICT;
 CREATE TABLE IF NOT EXISTS space_members (
     space_id BLOB NOT NULL,
     subject BLOB NOT NULL,
     epoch INTEGER NOT NULL CHECK (epoch >= 0),
     capability BLOB NOT NULL,
     PRIMARY KEY (space_id, subject)
 ) STRICT;
 CREATE TABLE IF NOT EXISTS local_user (
     singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
     user_id BLOB UNIQUE NOT NULL
 ) STRICT;
 CREATE TABLE IF NOT EXISTS user_events (
     user_id BLOB NOT NULL,
     sequence INTEGER NOT NULL CHECK (sequence >= 0),
     digest BLOB NOT NULL,
     event BLOB NOT NULL,
     PRIMARY KEY (user_id, sequence)
 ) STRICT;";

/// A trust-vault failure.
#[derive(Debug, Error)]
pub enum TrustError {
    /// `SQLite` could not complete a durable operation.
    #[error("the trust vault could not complete a storage operation: {0}")]
    Storage(#[from] rusqlite::Error),
    /// Ciphertext authentication failed or encoded credentials were malformed.
    #[error("the trust vault could not authenticate its protected device material")]
    ProtectedMaterial,
    /// Secure operating-system randomness was unavailable.
    #[error("secure random generation failed")]
    Randomness,
    /// The host credential store could not be opened or used.
    #[error("the operating-system credential store failed: {0}")]
    KeyStore(String),
    /// No wrapping key exists in the selected credential-store slot.
    #[error("the operating-system credential store has no Cyrene key named {0:?}")]
    MissingWrappingKey(String),
    /// A wrapping key already exists in the selected credential-store slot.
    #[error("the operating-system credential store already has a Cyrene key named {0:?}")]
    WrappingKeyExists(String),
    /// The credential-store entry did not contain a Cyrene wrapping key.
    #[error("the Cyrene key named {name:?} is malformed: expected 32 bytes, found {length}")]
    MalformedWrappingKey {
        /// User-selected credential-store slot.
        name: String,
        /// Number of bytes returned by the credential store.
        length: usize,
    },
    /// A persisted capability does not match its space authority record.
    #[error("the capability does not match the stored space authority")]
    InconsistentCapability,
    /// Authority epochs are forward-only and cannot be rolled back.
    #[error("refusing to replace space authority epoch {current} with older epoch {proposed}")]
    AuthorityRollback {
        /// Current durable epoch.
        current: u64,
        /// Proposed stale epoch.
        proposed: u64,
    },
    /// A key is already retained for this space epoch.
    #[error("the trust vault already contains a key for this space epoch")]
    SpaceKeyExists,
    /// This vault has no local device identity to bind space authority to.
    #[error("the trust vault has no local device identity")]
    DeviceNotInitialized,
    /// The space already has local authority state.
    #[error("the space already has local authority state")]
    SpaceAlreadyInitialized,
    /// The accepted grant does not belong to this local device or inviting peer.
    #[error("the shared-space grant does not match the local device and inviting peer")]
    SharePrincipalMismatch,
    /// The vault already has a local user identity.
    #[error("the trust vault already has a local user identity")]
    UserAlreadyInitialized,
    /// A linked-user membership chain was invalid.
    #[error(transparent)]
    UserIdentity(#[from] UserIdentityError),
    /// Filesystem I/O failed while publishing a recovery snapshot.
    #[error("recovery filesystem operation failed: {0}")]
    RecoveryIo(#[from] std::io::Error),
    /// The encrypted recovery artifact was malformed or unsupported.
    #[error("the recovery bundle is invalid or unsupported")]
    InvalidRecoveryBundle,
    /// The recovery secret or encrypted artifact did not authenticate.
    #[error("the recovery bundle could not be authenticated")]
    RecoveryAuthentication,
    /// Restore never overwrites an existing destination.
    #[error("the recovery destination already exists")]
    RecoveryDestinationExists,
    /// A capability failed cryptographic or policy validation.
    #[error("space authority validation failed: {0}")]
    Authority(String),
    /// The vault already contains device credentials.
    #[error("the trust vault already contains a device identity")]
    AlreadyInitialized,
    /// The invitation is unknown, expired, or already redeemed.
    #[error("the invitation is unavailable, expired, or already redeemed")]
    InvitationUnavailable,
    /// A persisted public identity was malformed.
    #[error("the trust vault contains a malformed device public key")]
    Identity(#[from] PairingError),
    /// This build cannot read the vault's schema version.
    #[error("trust vault version {found} is unsupported; expected {expected}")]
    UnsupportedVersion {
        /// Version stored on disk.
        found: u32,
        /// Version supported by this build.
        expected: u32,
    },
}

/// A 256-bit key supplied by an OS key store or an equivalent protected source.
pub struct WrappingKey([u8; 32]);

impl WrappingKey {
    /// Generates a fresh key from operating-system randomness.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError::Randomness`] if secure randomness is unavailable.
    pub fn generate() -> Result<Self, TrustError> {
        let mut key = [0_u8; 32];
        getrandom::fill(&mut key).map_err(|_| TrustError::Randomness)?;
        Ok(Self(key))
    }

    /// Restores a key obtained from a protected source.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Exposes key bytes for transfer to an OS key store.
    pub const fn secret_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for WrappingKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// A zeroizing 256-bit secret protecting one portable recovery artifact.
pub struct RecoverySecret([u8; 32]);

impl RecoverySecret {
    /// Generates a new recovery secret from operating-system randomness.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError::Randomness`] if secure randomness is unavailable.
    pub fn generate() -> Result<Self, TrustError> {
        let mut secret = [0_u8; 32];
        getrandom::fill(&mut secret).map_err(|_| TrustError::Randomness)?;
        Ok(Self(secret))
    }

    /// Restores a secret from a protected phrase or token representation.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Exposes bytes only at an explicit recovery-secret encoding boundary.
    pub const fn secret_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for RecoverySecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for RecoverySecret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("RecoverySecret")
            .field(&"[REDACTED]")
            .finish()
    }
}

/// Versioned, authenticated ciphertext containing a consistent trust snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryBundle {
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
}

impl RecoveryBundle {
    /// Encodes this artifact into its stable portable binary representation.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(41 + self.ciphertext.len());
        bytes.extend_from_slice(RECOVERY_MAGIC);
        bytes.push(RECOVERY_VERSION);
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&(self.ciphertext.len() as u64).to_be_bytes());
        bytes.extend_from_slice(&self.ciphertext);
        bytes
    }

    /// Decodes a bounded portable recovery artifact.
    ///
    /// # Errors
    ///
    /// Returns an error for another version, malformed lengths, or an artifact
    /// above the recovery database limit plus cryptographic overhead.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TrustError> {
        let maximum = MAX_RECOVERY_DATABASE_BYTES + 1_024;
        if bytes.len() < 41 || bytes.len() > maximum || &bytes[..8] != RECOVERY_MAGIC {
            return Err(TrustError::InvalidRecoveryBundle);
        }
        if bytes[8] != RECOVERY_VERSION {
            return Err(TrustError::InvalidRecoveryBundle);
        }
        let nonce = bytes[9..33]
            .try_into()
            .map_err(|_| TrustError::InvalidRecoveryBundle)?;
        let length = u64::from_be_bytes(
            bytes[33..41]
                .try_into()
                .map_err(|_| TrustError::InvalidRecoveryBundle)?,
        );
        let length = usize::try_from(length).map_err(|_| TrustError::InvalidRecoveryBundle)?;
        let encoded_length = 41_usize
            .checked_add(length)
            .ok_or(TrustError::InvalidRecoveryBundle)?;
        if bytes.len() != encoded_length {
            return Err(TrustError::InvalidRecoveryBundle);
        }
        Ok(Self {
            nonce,
            ciphertext: bytes[41..].to_vec(),
        })
    }

    /// Authenticates the secret and validates the bounded inner snapshot.
    ///
    /// This permits a caller to reject a mistyped secret before allocating a
    /// new host credential-store slot.
    ///
    /// # Errors
    ///
    /// Returns an error if authentication fails or the plaintext is malformed.
    pub fn verify(&self, secret: &RecoverySecret) -> Result<(), TrustError> {
        let plaintext = self.open(secret)?;
        decode_recovery_plaintext(&plaintext).map(|_| ())
    }

    fn open(&self, secret: &RecoverySecret) -> Result<zeroize::Zeroizing<Vec<u8>>, TrustError> {
        let cipher = XChaCha20Poly1305::new_from_slice(secret.secret_bytes())
            .map_err(|_| TrustError::InvalidRecoveryBundle)?;
        cipher
            .decrypt(
                XNonce::from_slice(&self.nonce),
                Payload {
                    msg: &self.ciphertext,
                    aad: RECOVERY_DOMAIN,
                },
            )
            .map(zeroize::Zeroizing::new)
            .map_err(|_| TrustError::RecoveryAuthentication)
    }
}

/// Native credential-store access for a named Cyrene wrapping key.
///
/// Names are application-local slots, such as `default`, and are stored under
/// Cyrene's fixed service identifier. The implementation uses Keychain on
/// Apple platforms, Credential Manager on Windows, and the persistent Secret
/// Service/keyring provider on Linux.
#[derive(Debug)]
pub struct OsKeyStore {
    name: String,
    entry: Entry,
}

impl OsKeyStore {
    /// Opens a named slot in the host's native credential store.
    ///
    /// # Errors
    ///
    /// Returns an error if the slot name is invalid for the platform provider.
    pub fn open(name: impl Into<String>) -> Result<Self, TrustError> {
        let name = name.into();
        let entry = Entry::new(KEYRING_SERVICE, &name).map_err(|error| key_store_error(&error))?;
        Ok(Self { name, entry })
    }

    /// Stores a new wrapping key without replacing an existing key.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError::WrappingKeyExists`] when the slot is occupied, or
    /// an error from the native credential provider.
    pub fn store_new(&self, key: &WrappingKey) -> Result<(), TrustError> {
        match self.entry.get_secret() {
            Ok(_) => return Err(TrustError::WrappingKeyExists(self.name.clone())),
            Err(KeyringError::NoEntry) => {}
            Err(error) => return Err(key_store_error(&error)),
        }
        self.entry
            .set_secret(key.secret_bytes())
            .map_err(|error| key_store_error(&error))
    }

    /// Loads the wrapping key from this slot.
    ///
    /// # Errors
    ///
    /// Returns an error if the slot is missing, inaccessible, or malformed.
    pub fn load(&self) -> Result<WrappingKey, TrustError> {
        let secret = match self.entry.get_secret() {
            Ok(secret) => secret,
            Err(KeyringError::NoEntry) => {
                return Err(TrustError::MissingWrappingKey(self.name.clone()));
            }
            Err(error) => return Err(key_store_error(&error)),
        };
        let length = secret.len();
        let bytes = secret
            .try_into()
            .map_err(|_| TrustError::MalformedWrappingKey {
                name: self.name.clone(),
                length,
            })?;
        Ok(WrappingKey::from_bytes(bytes))
    }

    #[cfg(test)]
    fn with_entry(name: impl Into<String>, entry: Entry) -> Self {
        Self {
            name: name.into(),
            entry,
        }
    }
}

fn key_store_error(error: &KeyringError) -> TrustError {
    TrustError::KeyStore(error.to_string())
}

/// Restored private credentials for the local device.
pub struct DeviceMaterial {
    /// Long-lived Cyrene signing identity.
    pub identity: DeviceIdentity,
    /// Long-lived, pinned QUIC certificate and private key.
    pub certificate: QuicCertificate,
}

/// Public trust information retained for a paired device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerRecord {
    /// Authenticated Ed25519 public identity.
    pub public_key: DevicePublicKey,
    /// Exact DER certificate pinned during pairing.
    pub certificate_der: Vec<u8>,
    /// Unix timestamp at which this record was admitted.
    pub paired_at: u64,
}

/// Durable local authority material for one shared space.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SpaceAccess {
    /// Trusted issuer and current forward-looking epoch.
    pub authority: SpaceAuthority,
    /// Capability presented by this device during synchronization.
    pub capability: Capability,
}

/// Complete local credentials needed to synchronize one shared space.
pub struct SpaceCredentials {
    access: SpaceAccess,
    key: SpaceKey,
}

impl SpaceCredentials {
    /// Combines structurally matching authority and epoch key material.
    ///
    /// # Errors
    ///
    /// Returns an error if the capability does not match its authority.
    pub fn new(access: SpaceAccess, key: SpaceKey) -> Result<Self, TrustError> {
        if access.capability.space() != access.authority.space
            || access.capability.issuer() != access.authority.issuer
            || access.capability.epoch() != access.authority.epoch
        {
            return Err(TrustError::InconsistentCapability);
        }
        Ok(Self { access, key })
    }

    /// Returns the trusted authority record.
    pub const fn authority(&self) -> SpaceAuthority {
        self.access.authority
    }

    /// Returns the capability presented for this local device.
    pub const fn capability(&self) -> &Capability {
        &self.access.capability
    }

    /// Returns the content key for the current authority epoch.
    pub const fn key(&self) -> &SpaceKey {
        &self.key
    }
}

impl PeerRecord {
    /// Creates a durable record from a cryptographically confirmed pairing.
    pub fn from_pairing(peer: &PairedPeer, paired_at: u64) -> Self {
        Self {
            public_key: peer.public_key,
            certificate_der: peer.transport_binding().to_vec(),
            paired_at,
        }
    }

    /// Returns the certificate pin used by authenticated QUIC.
    pub fn certificate_pin(&self) -> CertificatePin {
        CertificatePin::from_certificate_der(&self.certificate_der)
    }

    /// Returns the public certificate accepted by [`cyrene_net::connect`].
    pub fn peer_certificate(&self) -> PeerCertificate {
        PeerCertificate::from_der(self.certificate_der.clone())
    }
}

/// A SQLite-backed encrypted trust vault.
pub struct TrustStore {
    connection: Connection,
    wrapping_key: WrappingKey,
}

impl TrustStore {
    /// Opens or creates a vault and verifies its schema version.
    ///
    /// # Errors
    ///
    /// Returns an error if `SQLite` cannot open or migrate the vault, or the file
    /// belongs to an unsupported Cyrene version.
    pub fn open(path: impl AsRef<Path>, wrapping_key: WrappingKey) -> Result<Self, TrustError> {
        let connection = Connection::open(path)?;
        let mut store = Self {
            connection,
            wrapping_key,
        };
        store.configure_and_migrate()?;
        Ok(store)
    }

    /// Opens an isolated in-memory vault.
    ///
    /// # Errors
    ///
    /// Returns an error if `SQLite` cannot create the schema.
    pub fn open_in_memory(wrapping_key: WrappingKey) -> Result<Self, TrustError> {
        let connection = Connection::open_in_memory()?;
        let mut store = Self {
            connection,
            wrapping_key,
        };
        store.configure_and_migrate()?;
        Ok(store)
    }

    fn configure_and_migrate(&mut self) -> Result<(), TrustError> {
        self.connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
             PRAGMA busy_timeout = 5000;",
        )?;
        let transaction = self.connection.transaction()?;
        transaction.execute_batch(VAULT_SCHEMA)?;
        let version = transaction
            .query_row(
                "SELECT version FROM vault_meta WHERE singleton = 1",
                [],
                |row| row.get::<_, u32>(0),
            )
            .optional()?;
        match version {
            None => {
                transaction.execute(
                    "INSERT INTO vault_meta (singleton, version) VALUES (1, ?1)",
                    [VAULT_VERSION],
                )?;
            }
            Some(VAULT_VERSION) => {}
            Some(1..=5) => {
                transaction.execute(
                    "UPDATE vault_meta SET version = ?1 WHERE singleton = 1",
                    [VAULT_VERSION],
                )?;
            }
            Some(found) => {
                return Err(TrustError::UnsupportedVersion {
                    found,
                    expected: VAULT_VERSION,
                });
            }
        }
        transaction.commit()?;
        Ok(())
    }

    /// Seals and durably stores the local credentials exactly once.
    ///
    /// # Errors
    ///
    /// Returns an error if credentials already exist, randomness or encryption
    /// fails, or `SQLite` cannot commit the row.
    pub fn initialize_device(&mut self, material: &DeviceMaterial) -> Result<(), TrustError> {
        let exists = self
            .connection
            .query_row(
                "SELECT 1 FROM device_material WHERE singleton = 1",
                [],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if exists {
            return Err(TrustError::AlreadyInitialized);
        }
        let public_key = material.identity.public_key().to_bytes();
        let certificate_der = material.certificate.certificate_der();
        let plaintext = encode_private_material(
            &material.identity.secret_bytes(),
            material.certificate.private_key_der(),
        );
        let sealed = seal(
            &self.wrapping_key,
            &device_aad(&public_key, certificate_der),
            &plaintext,
        )?;
        self.connection.execute(
            "INSERT INTO device_material
                 (singleton, public_key, certificate_der, sealed)
             VALUES (1, ?1, ?2, ?3)",
            params![public_key.as_slice(), certificate_der, sealed],
        )?;
        Ok(())
    }

    /// Opens and validates the local credentials, if initialized.
    ///
    /// # Errors
    ///
    /// Returns an error if `SQLite` fails, the wrapping key is wrong, ciphertext
    /// was modified, or the decoded credentials do not match their public row.
    pub fn load_device(&self) -> Result<Option<DeviceMaterial>, TrustError> {
        let row = self
            .connection
            .query_row(
                "SELECT public_key, certificate_der, sealed
                 FROM device_material WHERE singleton = 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .optional()?;
        let Some((public_key, certificate_der, sealed)) = row else {
            return Ok(None);
        };
        let public_key: [u8; 32] = public_key
            .try_into()
            .map_err(|_| TrustError::ProtectedMaterial)?;
        let plaintext = open(
            &self.wrapping_key,
            &device_aad(&public_key, &certificate_der),
            &sealed,
        )?;
        let (identity_secret, certificate_key) = decode_private_material(&plaintext)?;
        let identity = DeviceIdentity::from_secret_bytes(&identity_secret);
        if identity.public_key().to_bytes() != public_key {
            return Err(TrustError::ProtectedMaterial);
        }
        Ok(Some(DeviceMaterial {
            identity,
            certificate: QuicCertificate::from_der(certificate_der, certificate_key),
        }))
    }

    /// Records a newly issued invitation before it becomes externally visible.
    ///
    /// # Errors
    ///
    /// Returns an error if this identifier was already issued or `SQLite` cannot
    /// commit it.
    pub fn record_invitation(
        &mut self,
        invitation_id: [u8; 16],
        expires_at: u64,
    ) -> Result<(), TrustError> {
        self.connection.execute(
            "INSERT INTO invitations (invitation_id, expires_at)
             VALUES (?1, ?2)",
            params![invitation_id.as_slice(), to_i64(expires_at)?],
        )?;
        Ok(())
    }

    /// Atomically redeems an invitation and admits its authenticated peer.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError::InvitationUnavailable`] if the invitation is
    /// unknown, expired, or already redeemed. Storage errors roll back both
    /// redemption and peer admission.
    pub fn redeem_invitation(
        &mut self,
        invitation_id: [u8; 16],
        now: u64,
        peer: &PeerRecord,
    ) -> Result<(), TrustError> {
        self.redeem_invitation_with_spaces(invitation_id, now, peer, &[])
    }

    /// Atomically redeems an invitation and admits its peer and linked spaces.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError::InvitationUnavailable`] if the invitation cannot
    /// be redeemed, or a storage error without partially admitting state.
    pub fn redeem_invitation_with_spaces(
        &mut self,
        invitation_id: [u8; 16],
        now: u64,
        peer: &PeerRecord,
        spaces: &[SpaceId],
    ) -> Result<(), TrustError> {
        let transaction = self.connection.transaction()?;
        let now = to_i64(now)?;
        let changed = transaction.execute(
            "UPDATE invitations SET redeemed_at = ?2
             WHERE invitation_id = ?1
               AND redeemed_at IS NULL
               AND expires_at >= ?2",
            params![invitation_id.as_slice(), now],
        )?;
        if changed != 1 {
            return Err(TrustError::InvitationUnavailable);
        }
        upsert_peer(&transaction, peer)?;
        insert_peer_spaces(&transaction, peer.public_key, spaces)?;
        transaction.commit()?;
        Ok(())
    }

    /// Admits the inviter after the joining side confirms the pairing.
    ///
    /// The joining side has no locally issued invitation to redeem. It calls
    /// this only after verifying the inviter's final key confirmation.
    ///
    /// # Errors
    ///
    /// Returns an error if `SQLite` cannot commit the authenticated peer record.
    pub fn admit_peer(&mut self, peer: &PeerRecord) -> Result<(), TrustError> {
        self.admit_peer_with_spaces(peer, &[])
    }

    /// Admits a confirmed peer and its authenticated linked-space context.
    ///
    /// # Errors
    ///
    /// Returns an error if `SQLite` cannot atomically commit all records.
    pub fn admit_peer_with_spaces(
        &mut self,
        peer: &PeerRecord,
        spaces: &[SpaceId],
    ) -> Result<(), TrustError> {
        let transaction = self.connection.transaction()?;
        upsert_peer(&transaction, peer)?;
        insert_peer_spaces(&transaction, peer.public_key, spaces)?;
        transaction.commit()?;
        Ok(())
    }

    /// Returns a paired device's public trust record.
    ///
    /// # Errors
    ///
    /// Returns an error if `SQLite` fails or persisted key bytes are malformed.
    pub fn peer(&self, public_key: DevicePublicKey) -> Result<Option<PeerRecord>, TrustError> {
        let row = self
            .connection
            .query_row(
                "SELECT public_key, certificate_der, paired_at
                 FROM paired_peers WHERE device_id = ?1",
                [public_key.id().as_bytes().as_slice()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()?;
        row.map(decode_peer).transpose()
    }

    /// Lists paired devices in stable device-ID order.
    ///
    /// # Errors
    ///
    /// Returns an error if `SQLite` fails or any persisted key is malformed.
    pub fn peers(&self) -> Result<Vec<PeerRecord>, TrustError> {
        let mut statement = self.connection.prepare(
            "SELECT public_key, certificate_der, paired_at
             FROM paired_peers ORDER BY device_id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?;
        rows.map(|row| decode_peer(row?)).collect()
    }

    /// Lists spaces authenticated while linking with `peer`.
    ///
    /// # Errors
    ///
    /// Returns an error if `SQLite` fails or a stored space ID is malformed.
    pub fn peer_spaces(&self, peer: DevicePublicKey) -> Result<Vec<SpaceId>, TrustError> {
        let mut statement = self.connection.prepare(
            "SELECT space_id FROM peer_spaces
             WHERE device_id = ?1 ORDER BY space_id",
        )?;
        let rows = statement.query_map([peer.id().as_bytes().as_slice()], |row| {
            row.get::<_, Vec<u8>>(0)
        })?;
        rows.map(|row| {
            let bytes: [u8; 16] = row?.try_into().map_err(|_| TrustError::ProtectedMaterial)?;
            Ok(SpaceId::from_u128(u128::from_be_bytes(bytes)))
        })
        .collect()
    }

    /// Atomically stores this device's capability and trusted space epoch.
    ///
    /// Equal epochs may replace a renewed grant. A higher epoch advances
    /// authority. Lower epochs are rejected so restored or replayed state
    /// cannot silently undo forward-looking revocation.
    ///
    /// # Errors
    ///
    /// Returns an error if the capability does not exactly match the authority,
    /// the update rolls an epoch backward, encoding fails, or storage fails.
    pub fn store_space_access(&mut self, access: &SpaceAccess) -> Result<(), TrustError> {
        if access.capability.space() != access.authority.space
            || access.capability.issuer() != access.authority.issuer
            || access.capability.epoch() != access.authority.epoch
        {
            return Err(TrustError::InconsistentCapability);
        }
        let space = access.authority.space.as_u128().to_be_bytes();
        let current = self
            .connection
            .query_row(
                "SELECT epoch FROM space_access WHERE space_id = ?1",
                [space.as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .map(from_i64)
            .transpose()?;
        if let Some(current) = current
            && access.authority.epoch < current
        {
            return Err(TrustError::AuthorityRollback {
                current,
                proposed: access.authority.epoch,
            });
        }
        let capability =
            serde_json::to_vec(&access.capability).map_err(|_| TrustError::ProtectedMaterial)?;
        self.connection.execute(
            "INSERT INTO space_access (space_id, issuer, epoch, capability)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(space_id) DO UPDATE SET
                 issuer = excluded.issuer,
                 epoch = excluded.epoch,
                 capability = excluded.capability",
            params![
                space.as_slice(),
                access.authority.issuer.to_bytes().as_slice(),
                to_i64(access.authority.epoch)?,
                capability,
            ],
        )?;
        Ok(())
    }

    /// Loads this device's durable authority material for a space.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails or the record is malformed or
    /// internally inconsistent.
    pub fn space_access(&self, space: SpaceId) -> Result<Option<SpaceAccess>, TrustError> {
        let space_bytes = space.as_u128().to_be_bytes();
        let row = self
            .connection
            .query_row(
                "SELECT issuer, epoch, capability FROM space_access WHERE space_id = ?1",
                [space_bytes.as_slice()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .optional()?;
        let Some((issuer, epoch, capability)) = row else {
            return Ok(None);
        };
        let issuer = DevicePublicKey::from_bytes(
            issuer
                .try_into()
                .map_err(|_| TrustError::ProtectedMaterial)?,
        )?;
        let capability: Capability =
            serde_json::from_slice(&capability).map_err(|_| TrustError::ProtectedMaterial)?;
        let access = SpaceAccess {
            authority: SpaceAuthority {
                space,
                issuer,
                epoch: from_i64(epoch)?,
            },
            capability,
        };
        if access.capability.space() != space
            || access.capability.issuer() != issuer
            || access.capability.epoch() != access.authority.epoch
        {
            return Err(TrustError::InconsistentCapability);
        }
        Ok(Some(access))
    }

    /// Loads complete current credentials for a shared space.
    ///
    /// A partially persisted authority record fails closed rather than
    /// returning credentials with a missing or wrong-epoch key.
    ///
    /// # Errors
    ///
    /// Returns an error if authority or key storage is malformed or incomplete.
    pub fn space_credentials(
        &self,
        space: SpaceId,
    ) -> Result<Option<SpaceCredentials>, TrustError> {
        let Some(access) = self.space_access(space)? else {
            return Ok(None);
        };
        let key = self
            .space_key(space, access.authority.epoch)?
            .ok_or(TrustError::ProtectedMaterial)?;
        SpaceCredentials::new(access, key).map(Some)
    }

    /// Creates this device's initial owner authority and content key for a space.
    ///
    /// # Errors
    ///
    /// Returns an error if no device exists, authority already exists, key or
    /// capability generation fails, or the atomic epoch commit fails.
    pub fn initialize_owned_space(
        &mut self,
        space: SpaceId,
        now: u64,
    ) -> Result<SpaceCredentials, TrustError> {
        if self.space_access(space)?.is_some() {
            return Err(TrustError::SpaceAlreadyInitialized);
        }
        let device = self
            .load_device()?
            .ok_or(TrustError::DeviceNotInitialized)?;
        let key = SpaceKey::generate().map_err(|error| TrustError::Authority(error.to_string()))?;
        let capability = Capability::issue(
            &device.identity,
            space,
            1,
            device.identity.public_key(),
            cyrene_authority::Permission::ReadWrite,
            now,
            u64::MAX,
        )
        .map_err(|error| TrustError::Authority(error.to_string()))?;
        let access = SpaceAccess {
            authority: SpaceAuthority {
                space,
                issuer: device.identity.public_key(),
                epoch: 1,
            },
            capability,
        };
        self.commit_space_epoch(&access, &key, &[], now)?;
        SpaceCredentials::new(access, key)
    }

    /// Atomically accepts one shared space from its inviting owner device.
    ///
    /// The peer certificate pin, linked-space record, local capability,
    /// authority epoch, and sealed content key become durable together.
    ///
    /// # Errors
    ///
    /// Returns an error if the vault has no device, the grant is invalid or
    /// names another principal, authority already exists, or the transaction
    /// cannot commit.
    pub fn accept_shared_space(
        &mut self,
        peer: &PeerRecord,
        access: &SpaceAccess,
        key: &SpaceKey,
        now: u64,
    ) -> Result<(), TrustError> {
        validate_access(access, now)?;
        let device = self
            .load_device()?
            .ok_or(TrustError::DeviceNotInitialized)?;
        if access.capability.subject() != device.identity.public_key()
            || access.authority.issuer != peer.public_key
        {
            return Err(TrustError::SharePrincipalMismatch);
        }
        if self.space_access(access.authority.space)?.is_some() {
            return Err(TrustError::SpaceAlreadyInitialized);
        }
        let space = access.authority.space.as_u128().to_be_bytes();
        let sealed = seal(
            &self.wrapping_key,
            &space_key_aad(access.authority.space, access.authority.epoch),
            key.secret_bytes(),
        )?;
        let capability =
            serde_json::to_vec(&access.capability).map_err(|_| TrustError::ProtectedMaterial)?;
        let transaction = self.connection.transaction()?;
        upsert_peer(&transaction, peer)?;
        insert_peer_spaces(
            &transaction,
            peer.public_key,
            std::slice::from_ref(&access.authority.space),
        )?;
        transaction.execute(
            "INSERT INTO space_keys (space_id, epoch, sealed) VALUES (?1, ?2, ?3)",
            params![space.as_slice(), to_i64(access.authority.epoch)?, sealed],
        )?;
        transaction.execute(
            "INSERT INTO space_access (space_id, issuer, epoch, capability)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                space.as_slice(),
                access.authority.issuer.to_bytes().as_slice(),
                to_i64(access.authority.epoch)?,
                capability,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Creates a new user identity rooted in this vault's device.
    ///
    /// # Errors
    ///
    /// Returns an error if the vault has no device or already has a user, secure
    /// randomness is unavailable, encoding fails, or storage cannot commit the
    /// genesis event atomically.
    pub fn initialize_user_identity(&mut self) -> Result<UserIdentity, TrustError> {
        if self.user_identity()?.is_some() {
            return Err(TrustError::UserAlreadyInitialized);
        }
        let device = self
            .load_device()?
            .ok_or(TrustError::DeviceNotInitialized)?;
        let identity = UserIdentity::create(&device.identity)?;
        self.install_user_identity(&identity)?;
        Ok(identity)
    }

    /// Installs a complete verified user chain containing this local device.
    ///
    /// This is the durable acceptance boundary when another linked device
    /// transfers user identity history.
    ///
    /// # Errors
    ///
    /// Returns an error if another user is installed, this device is not a
    /// current member, event encoding fails, or the transaction cannot commit.
    pub fn install_user_identity(&mut self, identity: &UserIdentity) -> Result<(), TrustError> {
        if self.user_identity()?.is_some() {
            return Err(TrustError::UserAlreadyInitialized);
        }
        let device = self
            .load_device()?
            .ok_or(TrustError::DeviceNotInitialized)?;
        if !identity
            .devices()
            .any(|candidate| candidate == device.identity.public_key())
        {
            return Err(TrustError::SharePrincipalMismatch);
        }
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT INTO local_user (singleton, user_id) VALUES (1, ?1)",
            [identity.id().as_bytes().as_slice()],
        )?;
        for event in identity.events() {
            insert_user_event(&transaction, event)?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// Verifies and atomically appends the next linked-device membership event.
    ///
    /// # Errors
    ///
    /// Returns an error if no user is installed, the event is invalid, replayed,
    /// or forked, or durable append fails. Invalid events never mutate storage.
    pub fn apply_user_event(&mut self, event: &UserEvent) -> Result<UserIdentity, TrustError> {
        let mut identity = self
            .user_identity()?
            .ok_or(UserIdentityError::MissingGenesis)?;
        identity.apply(event.clone())?;
        let transaction = self.connection.transaction()?;
        insert_user_event(&transaction, event)?;
        transaction.commit()?;
        Ok(identity)
    }

    /// Loads and verifies this vault's complete local user identity chain.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails or any persisted event or digest is
    /// malformed, discontinuous, forked, or has an invalid signature.
    pub fn user_identity(&self) -> Result<Option<UserIdentity>, TrustError> {
        let user = self
            .connection
            .query_row(
                "SELECT user_id FROM local_user WHERE singleton = 1",
                [],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        let Some(user) = user else {
            return Ok(None);
        };
        let user: [u8; 32] = user.try_into().map_err(|_| TrustError::ProtectedMaterial)?;
        let user = UserId::from_bytes(user);
        let mut statement = self.connection.prepare(
            "SELECT digest, event FROM user_events
             WHERE user_id = ?1 ORDER BY sequence",
        )?;
        let rows = statement.query_map([user.as_bytes().as_slice()], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        let mut events = Vec::new();
        for row in rows {
            let (digest, encoded) = row?;
            let event: UserEvent =
                serde_json::from_slice(&encoded).map_err(|_| TrustError::ProtectedMaterial)?;
            if digest.as_slice() != event.digest() || event.user() != user {
                return Err(TrustError::ProtectedMaterial);
            }
            events.push(event);
        }
        Ok(Some(UserIdentity::from_events(events)?))
    }

    /// Atomically imports a verified chain that extends local user history.
    ///
    /// An identical chain is idempotent. A shorter chain or any event mismatch
    /// is treated as a fork. The local device may be absent from the final
    /// membership: accepting one's own signed removal is required for honest
    /// lost-device propagation.
    ///
    /// # Errors
    ///
    /// Returns an error if users differ, histories diverge or regress, event
    /// encoding fails, or the append transaction cannot commit.
    pub fn import_user_identity(
        &mut self,
        incoming: &UserIdentity,
    ) -> Result<UserIdentity, TrustError> {
        let Some(current) = self.user_identity()? else {
            self.install_user_identity(incoming)?;
            return Ok(incoming.clone());
        };
        if current.id() != incoming.id() || incoming.events().len() < current.events().len() {
            return Err(UserIdentityError::Fork.into());
        }
        if current
            .events()
            .iter()
            .zip(incoming.events())
            .any(|(local, remote)| local != remote)
        {
            return Err(UserIdentityError::Fork.into());
        }
        if incoming.events().len() == current.events().len() {
            return Ok(current);
        }
        let transaction = self.connection.transaction()?;
        for event in &incoming.events()[current.events().len()..] {
            insert_user_event(&transaction, event)?;
        }
        transaction.commit()?;
        Ok(incoming.clone())
    }

    /// Creates a consistent encrypted snapshot of the complete trust vault.
    ///
    /// The artifact includes this vault's current wrapping key only inside the
    /// recovery ciphertext. Application databases are intentionally separate;
    /// this artifact recovers identity, trust, authority, and content keys.
    ///
    /// # Errors
    ///
    /// Returns an error if checkpointing or serialization fails, the vault is
    /// above the recovery size bound, or randomness or encryption fails.
    pub fn export_recovery(&self, secret: &RecoverySecret) -> Result<RecoveryBundle, TrustError> {
        self.connection
            .execute_batch("PRAGMA wal_checkpoint(FULL);")?;
        let serialized = self.connection.serialize(MAIN_DB)?;
        if serialized.len() > MAX_RECOVERY_DATABASE_BYTES {
            return Err(TrustError::InvalidRecoveryBundle);
        }
        let mut plaintext = zeroize::Zeroizing::new(Vec::with_capacity(41 + serialized.len()));
        plaintext.push(RECOVERY_VERSION);
        plaintext.extend_from_slice(self.wrapping_key.secret_bytes());
        plaintext.extend_from_slice(&(serialized.len() as u64).to_be_bytes());
        plaintext.extend_from_slice(&serialized);
        let mut nonce = [0_u8; 24];
        getrandom::fill(&mut nonce).map_err(|_| TrustError::Randomness)?;
        let cipher = XChaCha20Poly1305::new_from_slice(secret.secret_bytes())
            .map_err(|_| TrustError::InvalidRecoveryBundle)?;
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: RECOVERY_DOMAIN,
                },
            )
            .map_err(|_| TrustError::RecoveryAuthentication)?;
        Ok(RecoveryBundle { nonce, ciphertext })
    }

    /// Restores an encrypted trust snapshot without overwriting any file.
    ///
    /// The recovered vault is integrity-checked and all protected material is
    /// re-encrypted under `new_wrapping_key` before an atomic no-clobber publish.
    /// Restoring clones the exported device identity; callers should remove a
    /// lost device or rotate credentials when another copy may still exist.
    ///
    /// # Errors
    ///
    /// Returns an error for authentication or format failure, an existing
    /// destination, invalid recovered storage, or any failed atomic publish.
    pub fn restore_recovery(
        path: impl AsRef<Path>,
        bundle: &RecoveryBundle,
        secret: &RecoverySecret,
        new_wrapping_key: &WrappingKey,
    ) -> Result<(), TrustError> {
        let path = path.as_ref();
        if path.exists() {
            return Err(TrustError::RecoveryDestinationExists);
        }
        let plaintext = bundle.open(secret)?;
        let (old_key, database) = decode_recovery_plaintext(&plaintext)?;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let temporary = tempfile::Builder::new()
            .prefix(".cyrene-recovery-")
            .tempfile_in(parent)?
            .into_temp_path();
        let temporary_path: &Path = temporary.as_ref();
        let mut temporary_file = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(temporary_path)?;
        std::io::Write::write_all(&mut temporary_file, database)?;
        temporary_file.sync_all()?;
        drop(temporary_file);

        let mut restored = Self::open(temporary_path, WrappingKey::from_bytes(old_key))?;
        if restored.load_device()?.is_none() {
            return Err(TrustError::InvalidRecoveryBundle);
        }
        let integrity: String =
            restored
                .connection
                .query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        if integrity != "ok" {
            return Err(TrustError::InvalidRecoveryBundle);
        }
        restored.rotate_wrapping_key(WrappingKey::from_bytes(*new_wrapping_key.secret_bytes()))?;
        drop(restored);
        temporary.persist_noclobber(path).map_err(|error| {
            if error.error.kind() == std::io::ErrorKind::AlreadyExists {
                TrustError::RecoveryDestinationExists
            } else {
                TrustError::RecoveryIo(error.error)
            }
        })?;
        Ok(())
    }

    /// Re-encrypts every protected vault secret under a new host wrapping key.
    ///
    /// # Errors
    ///
    /// Returns an error without changing the active key if any existing secret
    /// cannot authenticate, new sealing fails, or the transaction rolls back.
    pub fn rotate_wrapping_key(&mut self, new_key: WrappingKey) -> Result<(), TrustError> {
        let device = self
            .connection
            .query_row(
                "SELECT public_key, certificate_der, sealed
                 FROM device_material WHERE singleton = 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .optional()?;
        let resealed_device = device
            .map(|(public_key, certificate, sealed)| {
                let public: [u8; 32] = public_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| TrustError::ProtectedMaterial)?;
                let plaintext = zeroize::Zeroizing::new(open(
                    &self.wrapping_key,
                    &device_aad(&public, &certificate),
                    &sealed,
                )?);
                let resealed = seal(&new_key, &device_aad(&public, &certificate), &plaintext)?;
                Ok::<_, TrustError>(resealed)
            })
            .transpose()?;
        let space_rows = {
            let mut statement = self.connection.prepare(
                "SELECT space_id, epoch, sealed FROM space_keys ORDER BY space_id, epoch",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        let mut resealed_spaces = Vec::with_capacity(space_rows.len());
        for (space, epoch, sealed) in space_rows {
            let space_bytes: [u8; 16] = space
                .as_slice()
                .try_into()
                .map_err(|_| TrustError::ProtectedMaterial)?;
            let space_id = SpaceId::from_u128(u128::from_be_bytes(space_bytes));
            let epoch = from_i64(epoch)?;
            let plaintext = zeroize::Zeroizing::new(open(
                &self.wrapping_key,
                &space_key_aad(space_id, epoch),
                &sealed,
            )?);
            let resealed = seal(&new_key, &space_key_aad(space_id, epoch), &plaintext)?;
            resealed_spaces.push((space, epoch, resealed));
        }
        let transaction = self.connection.transaction()?;
        if let Some(sealed) = resealed_device {
            transaction.execute(
                "UPDATE device_material SET sealed = ?1 WHERE singleton = 1",
                [sealed],
            )?;
        }
        for (space, epoch, sealed) in resealed_spaces {
            transaction.execute(
                "UPDATE space_keys SET sealed = ?3 WHERE space_id = ?1 AND epoch = ?2",
                params![space, to_i64(epoch)?, sealed],
            )?;
        }
        transaction.commit()?;
        self.wrapping_key = new_key;
        Ok(())
    }

    /// Seals and retains a content key for one space epoch exactly once.
    ///
    /// Old epoch keys remain available for already-authorized history. A new
    /// epoch uses a distinct row, while replacement at the same epoch is
    /// refused to prevent split-brain ciphertext.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError::SpaceKeyExists`] for an occupied epoch or an error
    /// if encryption, randomness, or durable storage fails.
    pub fn store_space_key(
        &mut self,
        space: SpaceId,
        epoch: u64,
        key: &SpaceKey,
    ) -> Result<(), TrustError> {
        let sealed = seal(
            &self.wrapping_key,
            &space_key_aad(space, epoch),
            key.secret_bytes(),
        )?;
        let changed = self.connection.execute(
            "INSERT OR IGNORE INTO space_keys (space_id, epoch, sealed)
             VALUES (?1, ?2, ?3)",
            params![
                space.as_u128().to_be_bytes().as_slice(),
                to_i64(epoch)?,
                sealed,
            ],
        )?;
        if changed != 1 {
            return Err(TrustError::SpaceKeyExists);
        }
        Ok(())
    }

    /// Opens a retained content key for one space epoch.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails, the wrapping key is wrong, or the
    /// sealed key was modified or malformed.
    pub fn space_key(&self, space: SpaceId, epoch: u64) -> Result<Option<SpaceKey>, TrustError> {
        let sealed = self
            .connection
            .query_row(
                "SELECT sealed FROM space_keys WHERE space_id = ?1 AND epoch = ?2",
                params![space.as_u128().to_be_bytes().as_slice(), to_i64(epoch)?],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        let Some(sealed) = sealed else {
            return Ok(None);
        };
        let plaintext = open(&self.wrapping_key, &space_key_aad(space, epoch), &sealed)?;
        let bytes = plaintext
            .try_into()
            .map_err(|_| TrustError::ProtectedMaterial)?;
        Ok(Some(SpaceKey::from_bytes(bytes)))
    }

    /// Records a signed share invitation before its bearer token is released.
    ///
    /// # Errors
    ///
    /// Returns an error if the identifier already exists, encoding fails, or
    /// storage cannot commit the record.
    pub fn record_share_invitation(
        &mut self,
        invitation: &ShareInvitation,
    ) -> Result<(), TrustError> {
        self.require_current_invitation(invitation)?;
        let encoded = serde_json::to_vec(invitation).map_err(|_| TrustError::ProtectedMaterial)?;
        let hash = blake3::hash(&encoded);
        self.connection.execute(
            "INSERT INTO share_invitations
                 (invitation_id, offer_hash, expires_at)
             VALUES (?1, ?2, ?3)",
            params![
                invitation.id().as_slice(),
                hash.as_bytes().as_slice(),
                to_i64(invitation.expires_at())?,
            ],
        )?;
        Ok(())
    }

    /// Atomically redeems an invitation and admits its device-bound capability.
    ///
    /// Retrying the identical invitation for the same subject returns the
    /// already committed capability. Another subject, changed offer bytes, or
    /// an expired/unknown invitation fails without changing membership.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError::InvitationUnavailable`] for an invalid redemption,
    /// or an error if grant issuance, encoding, or storage fails.
    pub fn redeem_share_invitation(
        &mut self,
        invitation: &ShareInvitation,
        issuer: &DeviceIdentity,
        subject: DevicePublicKey,
        now: u64,
    ) -> Result<Capability, TrustError> {
        self.redeem_share_invitation_inner(invitation, issuer, subject, None, now)
    }

    /// Atomically redeems a share and admits the recipient's transport pin.
    ///
    /// # Errors
    ///
    /// Returns an error if `peer` is not the invited subject, redemption is
    /// unavailable, grant issuance fails, or the complete transaction cannot
    /// commit.
    pub fn redeem_share_invitation_with_peer(
        &mut self,
        invitation: &ShareInvitation,
        issuer: &DeviceIdentity,
        peer: &PeerRecord,
        now: u64,
    ) -> Result<Capability, TrustError> {
        self.redeem_share_invitation_inner(invitation, issuer, peer.public_key, Some(peer), now)
    }

    fn redeem_share_invitation_inner(
        &mut self,
        invitation: &ShareInvitation,
        issuer: &DeviceIdentity,
        subject: DevicePublicKey,
        peer: Option<&PeerRecord>,
        now: u64,
    ) -> Result<Capability, TrustError> {
        self.require_current_invitation(invitation)?;
        let encoded_offer =
            serde_json::to_vec(invitation).map_err(|_| TrustError::ProtectedMaterial)?;
        let offer_hash = blake3::hash(&encoded_offer);
        let capability = invitation
            .grant(issuer, subject, now)
            .map_err(|_| TrustError::InvitationUnavailable)?;
        let encoded_capability =
            serde_json::to_vec(&capability).map_err(|_| TrustError::ProtectedMaterial)?;
        let transaction = self.connection.transaction()?;
        let changed = transaction.execute(
            "UPDATE share_invitations
             SET redeemed_at = ?4, subject = ?5, capability = ?6
             WHERE invitation_id = ?1
               AND offer_hash = ?2
               AND expires_at >= ?3
               AND redeemed_at IS NULL",
            params![
                invitation.id().as_slice(),
                offer_hash.as_bytes().as_slice(),
                to_i64(now)?,
                to_i64(now)?,
                subject.to_bytes().as_slice(),
                encoded_capability,
            ],
        )?;
        if changed == 1 {
            transaction.execute(
                "INSERT INTO space_members (space_id, subject, epoch, capability)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(space_id, subject) DO UPDATE SET
                     epoch = excluded.epoch,
                     capability = excluded.capability",
                params![
                    invitation.space().as_u128().to_be_bytes().as_slice(),
                    subject.to_bytes().as_slice(),
                    to_i64(invitation.epoch())?,
                    serde_json::to_vec(&capability).map_err(|_| TrustError::ProtectedMaterial)?,
                ],
            )?;
            if let Some(peer) = peer {
                upsert_peer(&transaction, peer)?;
                insert_peer_spaces(
                    &transaction,
                    peer.public_key,
                    std::slice::from_ref(&invitation.space()),
                )?;
            }
            transaction.commit()?;
            return Ok(capability);
        }
        let existing = transaction
            .query_row(
                "SELECT capability FROM share_invitations
                 WHERE invitation_id = ?1 AND offer_hash = ?2 AND subject = ?3",
                params![
                    invitation.id().as_slice(),
                    offer_hash.as_bytes().as_slice(),
                    subject.to_bytes().as_slice(),
                ],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        let Some(existing) = existing else {
            return Err(TrustError::InvitationUnavailable);
        };
        serde_json::from_slice(&existing).map_err(|_| TrustError::ProtectedMaterial)
    }

    fn require_current_invitation(&self, invitation: &ShareInvitation) -> Result<(), TrustError> {
        let access = self
            .space_access(invitation.space())?
            .ok_or(TrustError::InvitationUnavailable)?;
        if access.authority.issuer != invitation.issuer()
            || access.authority.epoch != invitation.epoch()
        {
            return Err(TrustError::InvitationUnavailable);
        }
        Ok(())
    }

    /// Lists current device capabilities for a space in stable subject order.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails or a capability is malformed.
    pub fn space_members(&self, space: SpaceId) -> Result<Vec<Capability>, TrustError> {
        let mut statement = self.connection.prepare(
            "SELECT capability FROM space_members
             WHERE space_id = ?1 ORDER BY subject",
        )?;
        let rows = statement.query_map([space.as_u128().to_be_bytes().as_slice()], |row| {
            row.get::<_, Vec<u8>>(0)
        })?;
        rows.map(|row| serde_json::from_slice(&row?).map_err(|_| TrustError::ProtectedMaterial))
            .collect()
    }

    /// Loads the current forward grant for one member device.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails or the persisted grant is malformed.
    pub fn space_member(
        &self,
        space: SpaceId,
        subject: DevicePublicKey,
    ) -> Result<Option<Capability>, TrustError> {
        let encoded = self
            .connection
            .query_row(
                "SELECT capability FROM space_members
                 WHERE space_id = ?1 AND subject = ?2",
                params![
                    space.as_u128().to_be_bytes().as_slice(),
                    subject.to_bytes().as_slice(),
                ],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        encoded
            .map(|encoded| {
                serde_json::from_slice(&encoded).map_err(|_| TrustError::ProtectedMaterial)
            })
            .transpose()
    }

    /// Rotates an owned space while preserving every member not explicitly revoked.
    ///
    /// Retained devices receive fresh grants with their existing permissions.
    /// The returned credentials are immediately active locally; callers then
    /// distribute the new epoch through authenticated peer sessions.
    ///
    /// # Errors
    ///
    /// Returns an error if this device is not the issuer, the epoch overflows,
    /// capability or key generation fails, or the atomic transition fails.
    pub fn rotate_owned_space(
        &mut self,
        space: SpaceId,
        revoked: &[DevicePublicKey],
        now: u64,
    ) -> Result<SpaceCredentials, TrustError> {
        let device = self
            .load_device()?
            .ok_or(TrustError::DeviceNotInitialized)?;
        let current = self
            .space_credentials(space)?
            .ok_or(TrustError::InconsistentCapability)?;
        let owner = device.identity.public_key();
        if current.authority().issuer != owner || current.capability().subject() != owner {
            return Err(TrustError::SharePrincipalMismatch);
        }
        let epoch = current
            .authority()
            .epoch
            .checked_add(1)
            .ok_or(TrustError::ProtectedMaterial)?;
        let authority = SpaceAuthority {
            space,
            issuer: owner,
            epoch,
        };
        let local = SpaceAccess {
            authority,
            capability: Capability::issue(
                &device.identity,
                space,
                epoch,
                owner,
                current.capability().permission(),
                now,
                u64::MAX,
            )
            .map_err(|error| TrustError::Authority(error.to_string()))?,
        };
        let members = self
            .space_members(space)?
            .into_iter()
            .filter(|capability| !revoked.contains(&capability.subject()))
            .map(|capability| {
                Capability::issue(
                    &device.identity,
                    space,
                    epoch,
                    capability.subject(),
                    capability.permission(),
                    now,
                    u64::MAX,
                )
                .map_err(|error| TrustError::Authority(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let key = SpaceKey::generate().map_err(|error| TrustError::Authority(error.to_string()))?;
        self.commit_space_epoch(&local, &key, &members, now)?;
        SpaceCredentials::new(local, key)
    }

    /// Atomically installs a newer epoch delivered by the authenticated issuer.
    ///
    /// # Errors
    ///
    /// Returns an error unless the grant targets this local device, is signed
    /// by the existing issuer, advances the epoch, and commits with its key.
    pub fn accept_space_epoch(
        &mut self,
        peer: &PeerRecord,
        access: &SpaceAccess,
        key: &SpaceKey,
        now: u64,
    ) -> Result<(), TrustError> {
        validate_access(access, now)?;
        let device = self
            .load_device()?
            .ok_or(TrustError::DeviceNotInitialized)?;
        let current = self
            .space_access(access.authority.space)?
            .ok_or(TrustError::InconsistentCapability)?;
        if access.authority.issuer != peer.public_key
            || access.authority.issuer != current.authority.issuer
            || access.capability.subject() != device.identity.public_key()
            || access.authority.epoch <= current.authority.epoch
        {
            return Err(TrustError::SharePrincipalMismatch);
        }
        let space = access.authority.space.as_u128().to_be_bytes();
        let sealed = seal(
            &self.wrapping_key,
            &space_key_aad(access.authority.space, access.authority.epoch),
            key.secret_bytes(),
        )?;
        let capability =
            serde_json::to_vec(&access.capability).map_err(|_| TrustError::ProtectedMaterial)?;
        let transaction = self.connection.transaction()?;
        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO space_keys (space_id, epoch, sealed) VALUES (?1, ?2, ?3)",
            params![space.as_slice(), to_i64(access.authority.epoch)?, sealed],
        )?;
        if inserted != 1 {
            return Err(TrustError::SpaceKeyExists);
        }
        transaction.execute(
            "UPDATE space_access SET issuer = ?2, epoch = ?3, capability = ?4
             WHERE space_id = ?1",
            params![
                space.as_slice(),
                access.authority.issuer.to_bytes().as_slice(),
                to_i64(access.authority.epoch)?,
                capability,
            ],
        )?;
        upsert_peer(&transaction, peer)?;
        insert_peer_spaces(&transaction, peer.public_key, &[access.authority.space])?;
        transaction.commit()?;
        Ok(())
    }

    /// Atomically advances a space to a new key and membership epoch.
    ///
    /// `local` becomes this device's grant. `members` replaces the forward
    /// roster; omitted devices are revoked for the new epoch. Older content
    /// keys remain retained because revocation cannot erase history previously
    /// disclosed to an authorized device.
    ///
    /// # Errors
    ///
    /// Returns an error unless the proposed epoch is newer, every grant is
    /// valid for exactly the proposed authority, the new key slot is unused,
    /// and the complete transition commits durably.
    pub fn commit_space_epoch(
        &mut self,
        local: &SpaceAccess,
        key: &SpaceKey,
        members: &[Capability],
        now: u64,
    ) -> Result<(), TrustError> {
        validate_access(local, now)?;
        for capability in members {
            validate_capability(capability, local.authority, now)?;
        }
        let space = local.authority.space.as_u128().to_be_bytes();
        let current = self
            .connection
            .query_row(
                "SELECT epoch FROM space_access WHERE space_id = ?1",
                [space.as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .map(from_i64)
            .transpose()?;
        if let Some(current) = current
            && local.authority.epoch <= current
        {
            return Err(TrustError::AuthorityRollback {
                current,
                proposed: local.authority.epoch,
            });
        }
        let sealed = seal(
            &self.wrapping_key,
            &space_key_aad(local.authority.space, local.authority.epoch),
            key.secret_bytes(),
        )?;
        let local_capability =
            serde_json::to_vec(&local.capability).map_err(|_| TrustError::ProtectedMaterial)?;
        let transaction = self.connection.transaction()?;
        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO space_keys (space_id, epoch, sealed)
             VALUES (?1, ?2, ?3)",
            params![space.as_slice(), to_i64(local.authority.epoch)?, sealed],
        )?;
        if inserted != 1 {
            return Err(TrustError::SpaceKeyExists);
        }
        transaction.execute(
            "INSERT INTO space_access (space_id, issuer, epoch, capability)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(space_id) DO UPDATE SET
                 issuer = excluded.issuer,
                 epoch = excluded.epoch,
                 capability = excluded.capability",
            params![
                space.as_slice(),
                local.authority.issuer.to_bytes().as_slice(),
                to_i64(local.authority.epoch)?,
                local_capability,
            ],
        )?;
        transaction.execute(
            "DELETE FROM space_members WHERE space_id = ?1",
            [space.as_slice()],
        )?;
        for capability in members {
            transaction.execute(
                "INSERT INTO space_members (space_id, subject, epoch, capability)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    space.as_slice(),
                    capability.subject().to_bytes().as_slice(),
                    to_i64(local.authority.epoch)?,
                    serde_json::to_vec(capability).map_err(|_| TrustError::ProtectedMaterial)?,
                ],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }
}

fn validate_access(access: &SpaceAccess, now: u64) -> Result<(), TrustError> {
    if access.capability.space() != access.authority.space
        || access.capability.issuer() != access.authority.issuer
        || access.capability.epoch() != access.authority.epoch
    {
        return Err(TrustError::InconsistentCapability);
    }
    validate_capability(&access.capability, access.authority, now)
}

fn validate_capability(
    capability: &Capability,
    authority: SpaceAuthority,
    now: u64,
) -> Result<(), TrustError> {
    capability
        .authorize(authority, capability.subject(), Operation::Read, now)
        .map_err(|error| TrustError::Authority(error.to_string()))
}

fn insert_user_event(
    transaction: &rusqlite::Transaction<'_>,
    event: &UserEvent,
) -> Result<(), TrustError> {
    let encoded = serde_json::to_vec(event).map_err(|_| TrustError::ProtectedMaterial)?;
    transaction.execute(
        "INSERT INTO user_events (user_id, sequence, digest, event)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            event.user().as_bytes().as_slice(),
            to_i64(event.sequence())?,
            event.digest().as_slice(),
            encoded,
        ],
    )?;
    Ok(())
}

fn upsert_peer(
    transaction: &rusqlite::Transaction<'_>,
    peer: &PeerRecord,
) -> Result<(), TrustError> {
    transaction.execute(
        "INSERT INTO paired_peers
             (device_id, public_key, certificate_der, paired_at)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(device_id) DO UPDATE SET
             public_key = excluded.public_key,
             certificate_der = excluded.certificate_der,
             paired_at = excluded.paired_at",
        params![
            peer.public_key.id().as_bytes().as_slice(),
            peer.public_key.to_bytes().as_slice(),
            peer.certificate_der,
            to_i64(peer.paired_at)?,
        ],
    )?;
    Ok(())
}

fn insert_peer_spaces(
    transaction: &rusqlite::Transaction<'_>,
    peer: DevicePublicKey,
    spaces: &[SpaceId],
) -> Result<(), TrustError> {
    for space in spaces {
        transaction.execute(
            "INSERT OR IGNORE INTO peer_spaces (device_id, space_id) VALUES (?1, ?2)",
            params![
                peer.id().as_bytes().as_slice(),
                space.as_u128().to_be_bytes().as_slice()
            ],
        )?;
    }
    Ok(())
}

fn seal(key: &WrappingKey, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, TrustError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.secret_bytes())
        .map_err(|_| TrustError::ProtectedMaterial)?;
    let mut nonce = [0_u8; 24];
    getrandom::fill(&mut nonce).map_err(|_| TrustError::Randomness)?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| TrustError::ProtectedMaterial)?;
    let mut sealed = Vec::with_capacity(nonce.len() + ciphertext.len());
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&ciphertext);
    Ok(sealed)
}

fn open(key: &WrappingKey, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, TrustError> {
    if sealed.len() < 24 {
        return Err(TrustError::ProtectedMaterial);
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key.secret_bytes())
        .map_err(|_| TrustError::ProtectedMaterial)?;
    cipher
        .decrypt(
            XNonce::from_slice(&sealed[..24]),
            Payload {
                msg: &sealed[24..],
                aad,
            },
        )
        .map_err(|_| TrustError::ProtectedMaterial)
}

fn device_aad(public_key: &[u8; 32], certificate_der: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(DEVICE_AAD.len() + 64);
    aad.extend_from_slice(DEVICE_AAD);
    aad.extend_from_slice(public_key);
    aad.extend_from_slice(blake3::hash(certificate_der).as_bytes());
    aad
}

fn space_key_aad(space: SpaceId, epoch: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(SPACE_KEY_AAD.len() + 24);
    aad.extend_from_slice(SPACE_KEY_AAD);
    aad.extend_from_slice(&space.as_u128().to_be_bytes());
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad
}

fn encode_private_material(identity: &[u8; 32], certificate_key: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(40 + certificate_key.len());
    encoded.extend_from_slice(identity);
    encoded.extend_from_slice(&(certificate_key.len() as u64).to_be_bytes());
    encoded.extend_from_slice(certificate_key);
    encoded
}

fn decode_private_material(plaintext: &[u8]) -> Result<([u8; 32], Vec<u8>), TrustError> {
    if plaintext.len() < 40 {
        return Err(TrustError::ProtectedMaterial);
    }
    let identity = plaintext[..32]
        .try_into()
        .map_err(|_| TrustError::ProtectedMaterial)?;
    let length = u64::from_be_bytes(
        plaintext[32..40]
            .try_into()
            .map_err(|_| TrustError::ProtectedMaterial)?,
    );
    let length = usize::try_from(length).map_err(|_| TrustError::ProtectedMaterial)?;
    if plaintext.len() != 40 + length {
        return Err(TrustError::ProtectedMaterial);
    }
    Ok((identity, plaintext[40..].to_vec()))
}

fn decode_peer(
    (public_key, certificate_der, paired_at): (Vec<u8>, Vec<u8>, i64),
) -> Result<PeerRecord, TrustError> {
    let public_key = DevicePublicKey::from_bytes(
        public_key
            .try_into()
            .map_err(|_| TrustError::ProtectedMaterial)?,
    )?;
    let paired_at = u64::try_from(paired_at).map_err(|_| TrustError::ProtectedMaterial)?;
    Ok(PeerRecord {
        public_key,
        certificate_der,
        paired_at,
    })
}

fn to_i64(value: u64) -> Result<i64, TrustError> {
    i64::try_from(value).map_err(|_| TrustError::ProtectedMaterial)
}

fn from_i64(value: i64) -> Result<u64, TrustError> {
    u64::try_from(value).map_err(|_| TrustError::ProtectedMaterial)
}

fn decode_recovery_plaintext(bytes: &[u8]) -> Result<([u8; 32], &[u8]), TrustError> {
    if bytes.len() < 41 || bytes[0] != RECOVERY_VERSION {
        return Err(TrustError::InvalidRecoveryBundle);
    }
    let key = bytes[1..33]
        .try_into()
        .map_err(|_| TrustError::InvalidRecoveryBundle)?;
    let length = u64::from_be_bytes(
        bytes[33..41]
            .try_into()
            .map_err(|_| TrustError::InvalidRecoveryBundle)?,
    );
    let length = usize::try_from(length).map_err(|_| TrustError::InvalidRecoveryBundle)?;
    let encoded_length = 41_usize
        .checked_add(length)
        .ok_or(TrustError::InvalidRecoveryBundle)?;
    if length > MAX_RECOVERY_DATABASE_BYTES || bytes.len() != encoded_length {
        return Err(TrustError::InvalidRecoveryBundle);
    }
    Ok((key, &bytes[41..]))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use cyrene_identity::{Inviter, Joiner, PairingCode};

    use super::*;

    fn mock_key_store(name: &str) -> OsKeyStore {
        OsKeyStore::with_entry(
            name,
            Entry::new_with_credential(Box::new(keyring::mock::MockCredential::default())),
        )
    }

    #[test]
    fn os_key_store_round_trips_without_replacement() {
        let store = mock_key_store("test-device");
        let key = WrappingKey::from_bytes([42; 32]);
        store.store_new(&key).unwrap();
        assert_eq!(store.load().unwrap().secret_bytes(), &[42; 32]);
        assert!(matches!(
            store.store_new(&WrappingKey::from_bytes([7; 32])),
            Err(TrustError::WrappingKeyExists(name)) if name == "test-device"
        ));
    }

    #[test]
    fn os_key_store_fails_closed_for_missing_and_malformed_entries() {
        let missing = mock_key_store("missing");
        assert!(matches!(
            missing.load(),
            Err(TrustError::MissingWrappingKey(name)) if name == "missing"
        ));

        let malformed = mock_key_store("malformed");
        malformed.entry.set_secret(b"too short").unwrap();
        assert!(matches!(
            malformed.load(),
            Err(TrustError::MalformedWrappingKey { name, length: 9 }) if name == "malformed"
        ));
    }

    fn material() -> DeviceMaterial {
        DeviceMaterial {
            identity: DeviceIdentity::from_secret_bytes(&[7; 32]),
            certificate: QuicCertificate::generate().unwrap(),
        }
    }

    #[test]
    fn encrypted_recovery_restores_complete_trust_under_a_fresh_host_key() {
        let directory = tempfile::tempdir().unwrap();
        let source_path = directory.path().join("source.db");
        let restored_path = directory.path().join("restored.db");
        let old_key = [110; 32];
        let new_key = [111; 32];
        let recovery_secret = RecoverySecret::from_bytes([112; 32]);
        let expected_material = material();
        let expected_public_key = expected_material.identity.public_key();
        let expected_pin = expected_material.certificate.pin();
        let space = SpaceId::from_u128(0xc7_1234);

        let (bundle, expected_user) = {
            let mut store =
                TrustStore::open(&source_path, WrappingKey::from_bytes(old_key)).unwrap();
            store.initialize_device(&expected_material).unwrap();
            let user = store.initialize_user_identity().unwrap();
            initialize_owner_space(&mut store, &expected_material.identity, space, 3, 113);
            (store.export_recovery(&recovery_secret).unwrap(), user)
        };

        let encoded = bundle.to_bytes();
        let decoded = RecoveryBundle::from_bytes(&encoded).unwrap();
        assert_eq!(decoded, bundle);
        TrustStore::restore_recovery(
            &restored_path,
            &decoded,
            &recovery_secret,
            &WrappingKey::from_bytes(new_key),
        )
        .unwrap();

        let restored = TrustStore::open(&restored_path, WrappingKey::from_bytes(new_key)).unwrap();
        let material = restored.load_device().unwrap().unwrap();
        assert_eq!(material.identity.public_key(), expected_public_key);
        assert_eq!(material.certificate.pin(), expected_pin);
        assert_eq!(restored.user_identity().unwrap().unwrap(), expected_user);
        assert_eq!(
            restored
                .space_key(space, 3)
                .unwrap()
                .unwrap()
                .secret_bytes(),
            &[113; 32]
        );
        drop(restored);

        let wrong_key = TrustStore::open(&restored_path, WrappingKey::from_bytes(old_key)).unwrap();
        assert!(matches!(
            wrong_key.load_device(),
            Err(TrustError::ProtectedMaterial)
        ));
    }

    #[test]
    fn recovery_authentication_tamper_and_no_clobber_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let source_path = directory.path().join("source.db");
        let destination = directory.path().join("destination.db");
        let secret = RecoverySecret::from_bytes([120; 32]);
        let bundle = {
            let mut store =
                TrustStore::open(&source_path, WrappingKey::from_bytes([121; 32])).unwrap();
            store.initialize_device(&material()).unwrap();
            store.export_recovery(&secret).unwrap()
        };

        assert!(matches!(
            TrustStore::restore_recovery(
                &destination,
                &bundle,
                &RecoverySecret::from_bytes([122; 32]),
                &WrappingKey::from_bytes([123; 32]),
            ),
            Err(TrustError::RecoveryAuthentication)
        ));
        assert!(!destination.exists());

        let mut tampered = bundle.to_bytes();
        *tampered.last_mut().unwrap() ^= 1;
        let tampered = RecoveryBundle::from_bytes(&tampered).unwrap();
        assert!(matches!(
            TrustStore::restore_recovery(
                &destination,
                &tampered,
                &secret,
                &WrappingKey::from_bytes([123; 32]),
            ),
            Err(TrustError::RecoveryAuthentication)
        ));
        assert!(!destination.exists());

        std::fs::write(&destination, b"keep me").unwrap();
        assert!(matches!(
            TrustStore::restore_recovery(
                &destination,
                &bundle,
                &secret,
                &WrappingKey::from_bytes([123; 32]),
            ),
            Err(TrustError::RecoveryDestinationExists)
        ));
        assert_eq!(std::fs::read(destination).unwrap(), b"keep me");
    }

    #[test]
    fn recovery_parser_rejects_unsupported_and_impossible_lengths() {
        let mut artifact = vec![0_u8; 41];
        artifact[..8].copy_from_slice(RECOVERY_MAGIC);
        artifact[8] = RECOVERY_VERSION;
        artifact[33..41].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(matches!(
            RecoveryBundle::from_bytes(&artifact),
            Err(TrustError::InvalidRecoveryBundle)
        ));
        artifact[8] = RECOVERY_VERSION + 1;
        assert!(matches!(
            RecoveryBundle::from_bytes(&artifact),
            Err(TrustError::InvalidRecoveryBundle)
        ));
    }

    fn initialize_owner_space(
        store: &mut TrustStore,
        owner: &DeviceIdentity,
        space: SpaceId,
        epoch: u64,
        key: u8,
    ) {
        let capability = Capability::issue(
            owner,
            space,
            epoch,
            owner.public_key(),
            cyrene_authority::Permission::ReadWrite,
            0,
            u64::MAX,
        )
        .unwrap();
        store
            .commit_space_epoch(
                &SpaceAccess {
                    authority: SpaceAuthority {
                        space,
                        issuer: owner.public_key(),
                        epoch,
                    },
                    capability,
                },
                &SpaceKey::from_bytes([key; 32]),
                &[],
                100,
            )
            .unwrap();
    }

    #[test]
    fn protected_device_material_survives_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("trust.db");
        let expected = material();
        let expected_key = expected.identity.public_key();
        let expected_pin = expected.certificate.pin();
        {
            let mut store = TrustStore::open(&path, WrappingKey::from_bytes([9; 32])).unwrap();
            store.initialize_device(&expected).unwrap();
        }
        let store = TrustStore::open(&path, WrappingKey::from_bytes([9; 32])).unwrap();
        let restored = store.load_device().unwrap().unwrap();
        assert_eq!(restored.identity.public_key(), expected_key);
        assert_eq!(restored.certificate.pin(), expected_pin);
    }

    #[test]
    fn space_access_is_durable_and_epochs_never_roll_back() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("trust.db");
        let owner = DeviceIdentity::from_secret_bytes(&[17; 32]);
        let member = DeviceIdentity::from_secret_bytes(&[18; 32]);
        let space = SpaceId::from_u128(44);
        let access = |epoch| SpaceAccess {
            authority: SpaceAuthority {
                space,
                issuer: owner.public_key(),
                epoch,
            },
            capability: Capability::issue(
                &owner,
                space,
                epoch,
                member.public_key(),
                cyrene_authority::Permission::ReadWrite,
                100,
                200,
            )
            .unwrap(),
        };
        {
            let mut store = TrustStore::open(&path, WrappingKey::from_bytes([19; 32])).unwrap();
            store.store_space_access(&access(2)).unwrap();
            store.store_space_access(&access(3)).unwrap();
            assert!(matches!(
                store.store_space_access(&access(2)),
                Err(TrustError::AuthorityRollback {
                    current: 3,
                    proposed: 2
                })
            ));
        }
        let store = TrustStore::open(&path, WrappingKey::from_bytes([19; 32])).unwrap();
        let restored = store.space_access(space).unwrap().unwrap();
        assert_eq!(restored.authority.epoch, 3);
        assert_eq!(restored.capability.subject(), member.public_key());
    }

    #[test]
    fn mismatched_space_access_is_rejected() {
        let owner = DeviceIdentity::from_secret_bytes(&[20; 32]);
        let member = DeviceIdentity::from_secret_bytes(&[21; 32]);
        let capability = Capability::issue(
            &owner,
            SpaceId::from_u128(1),
            1,
            member.public_key(),
            cyrene_authority::Permission::ReadOnly,
            100,
            200,
        )
        .unwrap();
        let mut store = TrustStore::open_in_memory(WrappingKey::from_bytes([9; 32])).unwrap();
        assert!(matches!(
            store.store_space_access(&SpaceAccess {
                authority: SpaceAuthority {
                    space: SpaceId::from_u128(2),
                    issuer: owner.public_key(),
                    epoch: 1,
                },
                capability,
            }),
            Err(TrustError::InconsistentCapability)
        ));
    }

    #[test]
    fn space_keys_are_sealed_scoped_and_retained_across_rotation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("trust.db");
        let space = SpaceId::from_u128(55);
        {
            let mut store = TrustStore::open(&path, WrappingKey::from_bytes([23; 32])).unwrap();
            store
                .store_space_key(space, 1, &SpaceKey::from_bytes([1; 32]))
                .unwrap();
            store
                .store_space_key(space, 2, &SpaceKey::from_bytes([2; 32]))
                .unwrap();
            assert!(matches!(
                store.store_space_key(space, 2, &SpaceKey::from_bytes([3; 32])),
                Err(TrustError::SpaceKeyExists)
            ));
        }
        let store = TrustStore::open(&path, WrappingKey::from_bytes([23; 32])).unwrap();
        assert_eq!(
            store.space_key(space, 1).unwrap().unwrap().secret_bytes(),
            &[1; 32]
        );
        assert_eq!(
            store.space_key(space, 2).unwrap().unwrap().secret_bytes(),
            &[2; 32]
        );
        assert!(
            store
                .space_key(SpaceId::from_u128(56), 1)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn share_redemption_is_atomic_single_use_and_retry_safe() {
        let owner = DeviceIdentity::from_secret_bytes(&[50; 32]);
        let bob = DeviceIdentity::from_secret_bytes(&[51; 32]);
        let eve = DeviceIdentity::from_secret_bytes(&[52; 32]);
        let space = SpaceId::from_u128(70);
        let (invitation, _secret) = ShareInvitation::issue(
            &owner,
            space,
            2,
            &SpaceKey::from_bytes([53; 32]),
            cyrene_authority::Permission::ReadOnly,
            100,
            200,
        )
        .unwrap();
        let mut store = TrustStore::open_in_memory(WrappingKey::from_bytes([54; 32])).unwrap();
        initialize_owner_space(&mut store, &owner, space, 2, 53);
        store.record_share_invitation(&invitation).unwrap();
        let first = store
            .redeem_share_invitation(&invitation, &owner, bob.public_key(), 120)
            .unwrap();
        let retry = store
            .redeem_share_invitation(&invitation, &owner, bob.public_key(), 121)
            .unwrap();
        assert_eq!(retry, first);
        assert!(matches!(
            store.redeem_share_invitation(&invitation, &owner, eve.public_key(), 122),
            Err(TrustError::InvitationUnavailable)
        ));
        assert_eq!(store.space_members(space).unwrap(), vec![first]);
    }

    #[test]
    fn expired_share_invitation_never_admits_membership() {
        let owner = DeviceIdentity::from_secret_bytes(&[55; 32]);
        let member = DeviceIdentity::from_secret_bytes(&[56; 32]);
        let space = SpaceId::from_u128(71);
        let (invitation, _secret) = ShareInvitation::issue(
            &owner,
            space,
            1,
            &SpaceKey::from_bytes([57; 32]),
            cyrene_authority::Permission::ReadWrite,
            100,
            110,
        )
        .unwrap();
        let mut store = TrustStore::open_in_memory(WrappingKey::from_bytes([58; 32])).unwrap();
        initialize_owner_space(&mut store, &owner, space, 1, 57);
        store.record_share_invitation(&invitation).unwrap();
        assert!(matches!(
            store.redeem_share_invitation(&invitation, &owner, member.public_key(), 110),
            Err(TrustError::InvitationUnavailable)
        ));
        assert!(store.space_members(space).unwrap().is_empty());
    }

    #[test]
    fn epoch_rotation_atomically_revokes_omitted_members_and_retains_history_keys() {
        let owner = DeviceIdentity::from_secret_bytes(&[60; 32]);
        let bob = DeviceIdentity::from_secret_bytes(&[61; 32]);
        let eve = DeviceIdentity::from_secret_bytes(&[62; 32]);
        let space = SpaceId::from_u128(72);
        let authority = |epoch| SpaceAuthority {
            space,
            issuer: owner.public_key(),
            epoch,
        };
        let grant = |epoch, subject| {
            Capability::issue(
                &owner,
                space,
                epoch,
                subject,
                cyrene_authority::Permission::ReadWrite,
                100,
                300,
            )
            .unwrap()
        };
        let local_one = SpaceAccess {
            authority: authority(1),
            capability: grant(1, owner.public_key()),
        };
        let bob_one = grant(1, bob.public_key());
        let eve_one = grant(1, eve.public_key());
        let mut store = TrustStore::open_in_memory(WrappingKey::from_bytes([63; 32])).unwrap();
        store
            .commit_space_epoch(
                &local_one,
                &SpaceKey::from_bytes([1; 32]),
                &[bob_one, eve_one.clone()],
                150,
            )
            .unwrap();

        let local_two = SpaceAccess {
            authority: authority(2),
            capability: grant(2, owner.public_key()),
        };
        let bob_two = grant(2, bob.public_key());
        store
            .commit_space_epoch(
                &local_two,
                &SpaceKey::from_bytes([2; 32]),
                std::slice::from_ref(&bob_two),
                160,
            )
            .unwrap();

        assert_eq!(store.space_members(space).unwrap(), vec![bob_two]);
        assert_eq!(
            eve_one.authorize(
                authority(2),
                eve.public_key(),
                cyrene_authority::Operation::Read,
                170,
            ),
            Err(cyrene_authority::AuthorityError::StaleEpoch)
        );
        assert_eq!(
            store.space_key(space, 1).unwrap().unwrap().secret_bytes(),
            &[1; 32]
        );
        assert_eq!(
            store.space_key(space, 2).unwrap().unwrap().secret_bytes(),
            &[2; 32]
        );
        assert_eq!(store.space_access(space).unwrap().unwrap(), local_two);
    }

    #[test]
    fn rotation_invalidates_unredeemed_old_epoch_invitations() {
        let owner = DeviceIdentity::from_secret_bytes(&[70; 32]);
        let member = DeviceIdentity::from_secret_bytes(&[71; 32]);
        let space = SpaceId::from_u128(73);
        let mut store = TrustStore::open_in_memory(WrappingKey::from_bytes([72; 32])).unwrap();
        initialize_owner_space(&mut store, &owner, space, 1, 1);
        let (invitation, _secret) = ShareInvitation::issue(
            &owner,
            space,
            1,
            &SpaceKey::from_bytes([1; 32]),
            cyrene_authority::Permission::ReadWrite,
            100,
            300,
        )
        .unwrap();
        store.record_share_invitation(&invitation).unwrap();

        let local = SpaceAccess {
            authority: SpaceAuthority {
                space,
                issuer: owner.public_key(),
                epoch: 2,
            },
            capability: Capability::issue(
                &owner,
                space,
                2,
                owner.public_key(),
                cyrene_authority::Permission::ReadWrite,
                100,
                300,
            )
            .unwrap(),
        };
        store
            .commit_space_epoch(&local, &SpaceKey::from_bytes([2; 32]), &[], 150)
            .unwrap();
        assert!(matches!(
            store.redeem_share_invitation(&invitation, &owner, member.public_key(), 160),
            Err(TrustError::InvitationUnavailable)
        ));
    }

    #[test]
    fn owned_space_initialization_and_share_acceptance_are_complete_and_atomic() {
        let owner_material = DeviceMaterial {
            identity: DeviceIdentity::from_secret_bytes(&[80; 32]),
            certificate: QuicCertificate::generate().unwrap(),
        };
        let bob_material = DeviceMaterial {
            identity: DeviceIdentity::from_secret_bytes(&[81; 32]),
            certificate: QuicCertificate::generate().unwrap(),
        };
        let space = SpaceId::from_u128(74);
        let mut owner = TrustStore::open_in_memory(WrappingKey::from_bytes([82; 32])).unwrap();
        owner.initialize_device(&owner_material).unwrap();
        let owner_credentials = owner.initialize_owned_space(space, 100).unwrap();
        let (invitation, secret) = ShareInvitation::issue(
            &owner_material.identity,
            space,
            1,
            owner_credentials.key(),
            cyrene_authority::Permission::ReadWrite,
            100,
            200,
        )
        .unwrap();
        owner.record_share_invitation(&invitation).unwrap();
        let bob_capability = owner
            .redeem_share_invitation(
                &invitation,
                &owner_material.identity,
                bob_material.identity.public_key(),
                120,
            )
            .unwrap();
        let bob_key = invitation
            .open(owner_credentials.authority(), &secret, 120)
            .unwrap();
        let bob_access = SpaceAccess {
            authority: owner_credentials.authority(),
            capability: bob_capability,
        };
        let owner_peer = PeerRecord {
            public_key: owner_material.identity.public_key(),
            certificate_der: owner_material.certificate.certificate_der().to_vec(),
            paired_at: 120,
        };

        let mut bob = TrustStore::open_in_memory(WrappingKey::from_bytes([83; 32])).unwrap();
        bob.initialize_device(&bob_material).unwrap();
        bob.accept_shared_space(&owner_peer, &bob_access, &bob_key, 120)
            .unwrap();
        let loaded = bob.space_credentials(space).unwrap().unwrap();
        assert_eq!(loaded.authority(), owner_credentials.authority());
        assert_eq!(loaded.capability(), &bob_access.capability);
        assert_eq!(
            loaded.key().secret_bytes(),
            owner_credentials.key().secret_bytes()
        );
        assert_eq!(bob.peer(owner_peer.public_key).unwrap(), Some(owner_peer));
    }

    #[test]
    fn linked_user_chain_installs_restarts_removes_and_rejects_forks_atomically() {
        let directory = tempfile::tempdir().unwrap();
        let alice_path = directory.path().join("alice.db");
        let bob_path = directory.path().join("bob.db");
        let alice_material = DeviceMaterial {
            identity: DeviceIdentity::from_secret_bytes(&[100; 32]),
            certificate: QuicCertificate::generate().unwrap(),
        };
        let bob_material = DeviceMaterial {
            identity: DeviceIdentity::from_secret_bytes(&[101; 32]),
            certificate: QuicCertificate::generate().unwrap(),
        };
        let mut alice = TrustStore::open(&alice_path, WrappingKey::from_bytes([102; 32])).unwrap();
        alice.initialize_device(&alice_material).unwrap();
        let mut user = alice.initialize_user_identity().unwrap();
        let linked = user
            .link_device(&alice_material.identity, bob_material.identity.public_key())
            .unwrap();
        user = alice.apply_user_event(&linked).unwrap();

        {
            let mut bob = TrustStore::open(&bob_path, WrappingKey::from_bytes([103; 32])).unwrap();
            bob.initialize_device(&bob_material).unwrap();
            bob.install_user_identity(&user).unwrap();
        }
        let mut bob = TrustStore::open(&bob_path, WrappingKey::from_bytes([103; 32])).unwrap();
        assert_eq!(bob.user_identity().unwrap().unwrap(), user);

        let before_removal = bob.user_identity().unwrap().unwrap();
        let removal = before_removal
            .remove_device(&bob_material.identity, alice_material.identity.public_key())
            .unwrap();
        let competing = before_removal
            .link_device(
                &bob_material.identity,
                DeviceIdentity::from_secret_bytes(&[104; 32]).public_key(),
            )
            .unwrap();
        let after_removal = bob.apply_user_event(&removal).unwrap();
        assert!(matches!(
            bob.apply_user_event(&competing),
            Err(TrustError::UserIdentity(UserIdentityError::Fork))
        ));
        assert_eq!(bob.user_identity().unwrap().unwrap(), after_removal);

        let alice_after = alice.apply_user_event(&removal).unwrap();
        assert_eq!(alice_after, after_removal);
        assert!(matches!(
            alice_after.link_device(
                &alice_material.identity,
                DeviceIdentity::from_secret_bytes(&[105; 32]).public_key(),
            ),
            Err(UserIdentityError::UnauthorizedActor)
        ));
    }

    #[test]
    fn a_wrong_wrapping_key_fails_closed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("trust.db");
        {
            let mut store = TrustStore::open(&path, WrappingKey::from_bytes([9; 32])).unwrap();
            store.initialize_device(&material()).unwrap();
        }
        let store = TrustStore::open(&path, WrappingKey::from_bytes([8; 32])).unwrap();
        assert!(matches!(
            store.load_device(),
            Err(TrustError::ProtectedMaterial)
        ));
    }

    #[test]
    fn invitation_redemption_and_peer_admission_are_atomic_and_single_use() {
        let mut store = TrustStore::open_in_memory(WrappingKey::from_bytes([9; 32])).unwrap();
        let peer = PeerRecord {
            public_key: DeviceIdentity::from_secret_bytes(&[4; 32]).public_key(),
            certificate_der: vec![1, 2, 3],
            paired_at: 101,
        };
        store.record_invitation([5; 16], 110).unwrap();
        store.redeem_invitation([5; 16], 101, &peer).unwrap();
        assert_eq!(store.peer(peer.public_key).unwrap(), Some(peer.clone()));
        assert!(matches!(
            store.redeem_invitation([5; 16], 102, &peer),
            Err(TrustError::InvitationUnavailable)
        ));
    }

    #[test]
    fn expired_invitation_does_not_admit_a_peer() {
        let mut store = TrustStore::open_in_memory(WrappingKey::from_bytes([9; 32])).unwrap();
        let peer = PeerRecord {
            public_key: DeviceIdentity::from_secret_bytes(&[4; 32]).public_key(),
            certificate_der: vec![1, 2, 3],
            paired_at: 111,
        };
        store.record_invitation([5; 16], 110).unwrap();
        assert!(matches!(
            store.redeem_invitation([5; 16], 111, &peer),
            Err(TrustError::InvitationUnavailable)
        ));
        assert_eq!(store.peer(peer.public_key).unwrap(), None);
    }

    #[test]
    fn pairing_binds_the_certificate_admitted_to_the_vault() {
        let alice = material();
        let bob = DeviceMaterial {
            identity: DeviceIdentity::from_secret_bytes(&[8; 32]),
            certificate: QuicCertificate::generate().unwrap(),
        };
        let code = PairingCode::parse("C7YR-3N3K").unwrap();
        let (inviter, offer) = Inviter::start(
            &alice.identity,
            &code,
            alice.certificate.certificate_der(),
            100,
            Duration::from_secs(60),
        )
        .unwrap();
        let (joiner, answer) = Joiner::start(
            &bob.identity,
            &code,
            bob.certificate.certificate_der(),
            &offer,
            101,
        )
        .unwrap();
        let (alice_peer, acknowledgement) = inviter.finish(&answer, 102).unwrap();
        let bob_peer = joiner.finish(&acknowledgement).unwrap();

        let mut alice_store = TrustStore::open_in_memory(WrappingKey::from_bytes([1; 32])).unwrap();
        alice_store
            .record_invitation(offer.invitation_id(), offer.expires_at())
            .unwrap();
        let peer = PeerRecord::from_pairing(&alice_peer, 102);
        alice_store
            .redeem_invitation(offer.invitation_id(), 102, &peer)
            .unwrap();
        let admitted = alice_store
            .peer(bob.identity.public_key())
            .unwrap()
            .unwrap();

        assert_eq!(admitted.certificate_pin(), bob.certificate.pin());
        assert_eq!(
            bob_peer.transport_binding(),
            alice.certificate.certificate_der()
        );
    }

    #[test]
    fn linked_spaces_are_durable_deduplicated_and_peer_scoped() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("trust.db");
        let peer = PeerRecord {
            public_key: DeviceIdentity::from_secret_bytes(&[4; 32]).public_key(),
            certificate_der: vec![1, 2, 3],
            paired_at: 101,
        };
        let first = SpaceId::from_u128(1);
        let second = SpaceId::from_u128(2);
        {
            let mut store = TrustStore::open(&path, WrappingKey::from_bytes([9; 32])).unwrap();
            store
                .admit_peer_with_spaces(&peer, &[second, first, first])
                .unwrap();
        }
        let store = TrustStore::open(&path, WrappingKey::from_bytes([9; 32])).unwrap();
        assert_eq!(
            store.peer_spaces(peer.public_key).unwrap(),
            vec![first, second]
        );
    }
}
