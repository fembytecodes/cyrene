use std::{net::SocketAddr, time::Duration};

use cyrene_authority::{
    AuthorityError, Capability, EncryptionError, OpaquePayload, Operation, SpaceAuthority,
};
use cyrene_identity::{DeviceIdentity, DevicePublicKey};
use cyrene_net::{
    MAX_RELAY_BATCH, MAX_RELAY_BATCH_BYTES, RelayClient, RelayEnvelope, RelayMailbox,
    RelayProtocolError, RelayRejection, RelayResponse,
};
use cyrene_sync::{Change, Frontier};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    App, DeviceMaterial, Error, NetworkSyncReceipt, PeerRecord, Permission, SpaceCredentials,
    TrustError, TrustStore,
};

const PACKET_VERSION: u8 = 1;
const PACKET_DOMAIN: &[u8] = b"cyrene/relay/change-author/1";
const CIPHERTEXT_CONTEXT: &[u8] = b"cyrene/relay/change-envelope/1";
const EPOCH_PACKET_DOMAIN: &[u8] = b"cyrene/relay/epoch-update-author/1";
const EPOCH_CIPHERTEXT_CONTEXT: &[u8] = b"cyrene/relay/epoch-update-envelope/1";
const EPOCH_MAILBOX_PURPOSE: &[u8] = b"cyrene/relay/epoch-mailbox/1";

/// A failure while exchanging end-to-end encrypted changes through a relay.
#[derive(Debug, Error)]
pub enum RelaySyncError {
    /// Relay request construction or transport failed.
    #[error(transparent)]
    Protocol(#[from] RelayProtocolError),
    /// Space encryption or authentication failed.
    #[error(transparent)]
    Encryption(#[from] EncryptionError),
    /// Device capability verification failed.
    #[error(transparent)]
    Authority(#[from] AuthorityError),
    /// Local replication validation or durability failed.
    #[error(transparent)]
    Local(#[from] Error),
    /// Durable trust state was missing or malformed.
    #[error(transparent)]
    Trust(#[from] TrustError),
    /// A relay object was malformed, substituted, or incorrectly signed.
    #[error("the relay delivered an invalid encrypted change")]
    InvalidChange,
    /// The relay refused the operation under a stable public category.
    #[error("the relay rejected the operation: {0:?}")]
    Rejected(RelayRejection),
    /// The requested expiry or system clock was invalid.
    #[error("the relay retention interval is invalid")]
    InvalidRetention,
}

/// A failure after both the preferred direct path and relay fallback fail.
#[derive(Debug, Error)]
#[error("direct synchronization failed ({direct}); relay fallback failed: {relay}")]
pub struct SyncFallbackError {
    direct: String,
    relay: RelaySyncError,
}

/// Which optional connectivity path completed synchronization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectivityReceipt {
    /// A pinned mutually authenticated QUIC session completed.
    Direct(NetworkSyncReceipt),
    /// The direct attempt failed and opaque store-and-forward completed.
    Relay {
        /// Local history offered to the remote mailbox.
        pushed: RelayPushReceipt,
        /// Remote objects imported and acknowledged from the local mailbox.
        pulled: RelayPullReceipt,
    },
}

/// Deadlines and retention for direct-first relay synchronization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectivityOptions {
    /// Maximum time spent attempting direct QUIC before fallback.
    pub direct_deadline: Duration,
    /// Requested lifetime for newly published relay objects.
    pub relay_retention: Duration,
}

impl Default for ConnectivityOptions {
    fn default() -> Self {
        Self {
            direct_deadline: Duration::from_secs(3),
            relay_retention: Duration::from_secs(7 * 24 * 60 * 60),
        }
    }
}

/// Result of publishing this replica's current history to one mailbox.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayPushReceipt {
    /// Encrypted objects offered, including relay-side duplicates.
    pub offered: usize,
    /// Objects newly retained by the relay.
    pub stored: usize,
}

/// Result of draining this device's current epoch mailbox.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayPullReceipt {
    /// Encrypted objects downloaded and authenticated.
    pub received: usize,
    /// Previously unknown changes retained locally.
    pub retained: usize,
    /// Objects acknowledged only after durable local import.
    pub acknowledged: usize,
}

#[derive(Deserialize, Serialize)]
struct UnsignedChangePacket {
    version: u8,
    space: crate::SpaceId,
    epoch: u64,
    author: DevicePublicKey,
    capability: Capability,
    change: Change,
}

impl UnsignedChangePacket {
    fn signing_bytes(&self) -> Result<Vec<u8>, RelaySyncError> {
        serde_json::to_vec(self).map_err(|_| RelaySyncError::InvalidChange)
    }
}

#[derive(Deserialize, Serialize)]
struct ChangePacket {
    #[serde(flatten)]
    unsigned: UnsignedChangePacket,
    signature: Vec<u8>,
}

#[derive(Deserialize, Serialize)]
struct EpochKey([u8; 32]);

impl Drop for EpochKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Deserialize, Serialize)]
struct UnsignedEpochPacket {
    version: u8,
    previous_epoch: u64,
    access: crate::SpaceAccess,
    key: EpochKey,
}

impl UnsignedEpochPacket {
    fn signing_bytes(&self) -> Result<Vec<u8>, RelaySyncError> {
        serde_json::to_vec(self).map_err(|_| RelaySyncError::InvalidChange)
    }
}

#[derive(Deserialize, Serialize)]
struct EpochPacket {
    #[serde(flatten)]
    unsigned: UnsignedEpochPacket,
    signature: Vec<u8>,
}

impl App {
    /// Prefers pinned direct QUIC and falls back to opaque store-and-forward.
    ///
    /// The fallback is explicit in the return value. Local commits never wait
    /// for either path; this method synchronizes already-durable history only.
    /// Read-only devices pull but do not publish unauthorized local writes.
    ///
    /// # Errors
    ///
    /// Returns both failure summaries if direct synchronization and relay
    /// fallback fail. Missing or malformed space trust state is reported as a
    /// relay-side local failure after the direct attempt.
    pub async fn sync_peer_or_relay(
        &self,
        direct_address: SocketAddr,
        relay: &RelayClient,
        device: &DeviceMaterial,
        peer: &PeerRecord,
        vault: &mut TrustStore,
        options: ConnectivityOptions,
    ) -> Result<ConnectivityReceipt, SyncFallbackError> {
        let direct = tokio::time::timeout(
            options.direct_deadline,
            self.sync_peer_shared(direct_address, device, peer, vault),
        )
        .await;
        match direct {
            Ok(Ok(receipt)) => Ok(ConnectivityReceipt::Direct(receipt)),
            direct_failure => {
                let direct = match direct_failure {
                    Ok(Err(error)) => error.to_string(),
                    Err(_) => "direct synchronization deadline elapsed".to_owned(),
                    Ok(Ok(_)) => unreachable!(),
                };
                let fallback = self
                    .relay_after_direct_failure(relay, device, peer, vault, options.relay_retention)
                    .await;
                fallback.map_err(|relay| SyncFallbackError { direct, relay })
            }
        }
    }

    async fn relay_after_direct_failure(
        &self,
        client: &RelayClient,
        device: &DeviceMaterial,
        peer: &PeerRecord,
        vault: &mut TrustStore,
        retention: Duration,
    ) -> Result<ConnectivityReceipt, RelaySyncError> {
        self.relay_refresh_epochs(client, device, peer, vault)
            .await?;
        let credentials = vault
            .space_credentials(self.space_id())?
            .ok_or(TrustError::InconsistentCapability)?;
        let pushed = if credentials.capability().permission() == Permission::ReadWrite {
            self.relay_push(
                client,
                &device.identity,
                &credentials,
                peer.public_key,
                retention,
            )
            .await?
        } else {
            RelayPushReceipt {
                offered: 0,
                stored: 0,
            }
        };
        let pulled = self
            .relay_pull(client, &device.identity, &credentials)
            .await?;
        Ok(ConnectivityReceipt::Relay { pushed, pulled })
    }

    /// Publishes the current epoch transition to every retained member.
    ///
    /// Each update is signed by the issuer, encrypted under the immediately
    /// preceding epoch key, and routed through a purpose-separated mailbox for
    /// exactly one recipient. Calling this repeatedly is relay-idempotent.
    ///
    /// # Errors
    ///
    /// Returns an error if this device is not the space issuer, the preceding
    /// key is unavailable, encoding/encryption fails, or the relay rejects a
    /// member update.
    pub async fn relay_publish_epoch_updates(
        &self,
        client: &RelayClient,
        vault: &TrustStore,
        retention: Duration,
    ) -> Result<RelayPushReceipt, RelaySyncError> {
        let now = unix_time()?;
        let device = vault
            .load_device()?
            .ok_or(TrustError::DeviceNotInitialized)?;
        let current = vault
            .space_credentials(self.space_id())?
            .ok_or(TrustError::InconsistentCapability)?;
        if current.authority().issuer != device.identity.public_key()
            || current.authority().epoch <= 1
        {
            return Err(TrustError::SharePrincipalMismatch.into());
        }
        let previous_epoch = current.authority().epoch - 1;
        let previous_key = vault
            .space_key(self.space_id(), previous_epoch)?
            .ok_or(TrustError::ProtectedMaterial)?;
        let expires_at = now
            .checked_add(retention.as_secs())
            .ok_or(RelaySyncError::InvalidRetention)?;
        let mut receipt = RelayPushReceipt {
            offered: 0,
            stored: 0,
        };
        for capability in vault.space_members(self.space_id())? {
            let recipient = capability.subject();
            let mailbox = epoch_mailbox(&previous_key, recipient);
            let envelope = encode_epoch_update(
                &device.identity,
                previous_epoch,
                crate::SpaceAccess {
                    authority: current.authority(),
                    capability,
                },
                current.key(),
                &previous_key,
                &mailbox,
                expires_at,
                now,
            )?;
            let result = push_batch(client, &mailbox, vec![envelope], now).await?;
            receipt.offered += result.offered;
            receipt.stored += result.stored;
        }
        Ok(receipt)
    }

    /// Installs every consecutively available relay-delivered epoch update.
    ///
    /// Updates chain one epoch at a time: after installing one, the new key
    /// derives the mailbox for the next. Revoked members find no next update.
    /// Each object is acknowledged only after atomic trust-vault installation.
    ///
    /// # Errors
    ///
    /// Returns an error without acknowledgement if decryption, issuer
    /// signature, recipient grant, epoch continuity, or durable installation
    /// fails.
    pub async fn relay_refresh_epochs(
        &self,
        client: &RelayClient,
        device: &DeviceMaterial,
        peer: &PeerRecord,
        vault: &mut TrustStore,
    ) -> Result<usize, RelaySyncError> {
        let mut advanced = 0_usize;
        loop {
            let current = vault
                .space_credentials(self.space_id())?
                .ok_or(TrustError::InconsistentCapability)?;
            let mailbox = epoch_mailbox(current.key(), device.identity.public_key());
            let now = unix_time()?;
            let request = mailbox.pull(0, 1, now)?;
            let mut items = match client.exchange(&request).await? {
                RelayResponse::Deliveries { items } => items,
                RelayResponse::Rejected { code } => return Err(RelaySyncError::Rejected(code)),
                RelayResponse::Applied { .. } => return Err(RelaySyncError::InvalidChange),
            };
            let Some(delivery) = items.pop() else {
                return Ok(advanced);
            };
            let (access, key) = decode_epoch_update(
                &delivery.envelope,
                &current,
                &mailbox,
                peer.public_key,
                device.identity.public_key(),
                now,
            )?;
            vault.accept_space_epoch(peer, &access, &key, now)?;
            let acknowledge = mailbox.acknowledge(vec![delivery.envelope.id()], unix_time()?)?;
            match client.exchange(&acknowledge).await? {
                RelayResponse::Applied { changed: 1 } => advanced += 1,
                RelayResponse::Rejected { code } => return Err(RelaySyncError::Rejected(code)),
                _ => return Err(RelaySyncError::InvalidChange),
            }
        }
    }

    /// Publishes current durable history to one recipient's opaque mailbox.
    ///
    /// Every object is author-signed, then encrypted as a complete packet so
    /// the relay cannot inspect space, epoch, author, capability, or change
    /// metadata. Relay publication never alters local commit semantics.
    ///
    /// # Errors
    ///
    /// Returns an error if this device lacks write authority, encoding or
    /// encryption fails, an object exceeds relay bounds, or the relay rejects
    /// or fails the request.
    pub async fn relay_push(
        &self,
        client: &RelayClient,
        identity: &DeviceIdentity,
        credentials: &SpaceCredentials,
        recipient: DevicePublicKey,
        retention: Duration,
    ) -> Result<RelayPushReceipt, RelaySyncError> {
        let now = unix_time()?;
        credentials.capability().authorize(
            credentials.authority(),
            identity.public_key(),
            Operation::Write,
            now,
        )?;
        let expires_at = now
            .checked_add(retention.as_secs())
            .ok_or(RelaySyncError::InvalidRetention)?;
        let mailbox = RelayMailbox::derive(credentials.key().secret_bytes(), &recipient.to_bytes());
        let changes = self.changes_since(&Frontier::new())?;
        let mut offered = 0_usize;
        let mut stored = 0_usize;
        let mut batch = Vec::new();
        let mut batch_bytes = 0_usize;
        for change in &changes {
            let envelope = encode_change(change, identity, credentials, &mailbox, expires_at, now)?;
            let envelope_bytes = envelope.ciphertext().len();
            if !batch.is_empty()
                && (batch.len() == MAX_RELAY_BATCH
                    || batch_bytes.saturating_add(envelope_bytes) > MAX_RELAY_BATCH_BYTES)
            {
                let result = push_batch(client, &mailbox, std::mem::take(&mut batch), now).await?;
                offered += result.offered;
                stored += result.stored;
                batch_bytes = 0;
            }
            batch_bytes = batch_bytes
                .checked_add(envelope_bytes)
                .ok_or(RelaySyncError::InvalidChange)?;
            batch.push(envelope);
        }
        if !batch.is_empty() {
            let result = push_batch(client, &mailbox, batch, now).await?;
            offered += result.offered;
            stored += result.stored;
        }
        Ok(RelayPushReceipt { offered, stored })
    }

    /// Drains, authenticates, durably imports, and acknowledges this mailbox.
    ///
    /// A page is acknowledged only after its complete change batch commits
    /// locally. A crash between commit and acknowledgement safely replays
    /// duplicate changes through the idempotent import path.
    ///
    /// # Errors
    ///
    /// Returns an error without acknowledging the page if decryption, author
    /// signature, capability, schema, change, or durable import validation
    /// fails, or if the relay rejects the operation.
    pub async fn relay_pull(
        &self,
        client: &RelayClient,
        identity: &DeviceIdentity,
        credentials: &SpaceCredentials,
    ) -> Result<RelayPullReceipt, RelaySyncError> {
        let mailbox = RelayMailbox::derive(
            credentials.key().secret_bytes(),
            &identity.public_key().to_bytes(),
        );
        let mut cursor = 0_u64;
        let mut receipt = RelayPullReceipt {
            received: 0,
            retained: 0,
            acknowledged: 0,
        };
        loop {
            let now = unix_time()?;
            let limit =
                u16::try_from(MAX_RELAY_BATCH).map_err(|_| RelaySyncError::InvalidChange)?;
            let request = mailbox.pull(cursor, limit, now)?;
            let items = match client.exchange(&request).await? {
                RelayResponse::Deliveries { items } => items,
                RelayResponse::Rejected { code } => return Err(RelaySyncError::Rejected(code)),
                RelayResponse::Applied { .. } => return Err(RelaySyncError::InvalidChange),
            };
            if items.is_empty() {
                return Ok(receipt);
            }
            let changes = items
                .iter()
                .map(|delivery| decode_change(&delivery.envelope, credentials, &mailbox, now))
                .collect::<Result<Vec<_>, _>>()?;
            let imported = self.apply_changes(changes).await?;
            receipt.received += items.len();
            receipt.retained += imported.retained();
            let ids = items
                .iter()
                .map(|delivery| delivery.envelope.id())
                .collect::<Vec<_>>();
            cursor = items.last().map_or(cursor, |delivery| delivery.cursor);
            let acknowledge = mailbox.acknowledge(ids, unix_time()?)?;
            match client.exchange(&acknowledge).await? {
                RelayResponse::Applied { changed } => {
                    if usize::from(changed) != items.len() {
                        return Err(RelaySyncError::InvalidChange);
                    }
                    receipt.acknowledged += usize::from(changed);
                }
                RelayResponse::Rejected { code } => return Err(RelaySyncError::Rejected(code)),
                RelayResponse::Deliveries { .. } => return Err(RelaySyncError::InvalidChange),
            }
            if items.len() < MAX_RELAY_BATCH {
                return Ok(receipt);
            }
        }
    }
}

async fn push_batch(
    client: &RelayClient,
    mailbox: &RelayMailbox,
    envelopes: Vec<RelayEnvelope>,
    now: u64,
) -> Result<RelayPushReceipt, RelaySyncError> {
    let offered = envelopes.len();
    let request = mailbox.push(envelopes, now)?;
    match client.exchange(&request).await? {
        RelayResponse::Applied { changed } if usize::from(changed) <= offered => {
            Ok(RelayPushReceipt {
                offered,
                stored: usize::from(changed),
            })
        }
        RelayResponse::Rejected { code } => Err(RelaySyncError::Rejected(code)),
        _ => Err(RelaySyncError::InvalidChange),
    }
}

fn encode_change(
    change: &Change,
    identity: &DeviceIdentity,
    credentials: &SpaceCredentials,
    mailbox: &RelayMailbox,
    expires_at: u64,
    now: u64,
) -> Result<RelayEnvelope, RelaySyncError> {
    let unsigned = UnsignedChangePacket {
        version: PACKET_VERSION,
        space: credentials.authority().space,
        epoch: credentials.authority().epoch,
        author: identity.public_key(),
        capability: credentials.capability().clone(),
        change: change.clone(),
    };
    let signature = identity
        .sign(PACKET_DOMAIN, &unsigned.signing_bytes()?)
        .to_vec();
    let plaintext = serde_json::to_vec(&ChangePacket {
        unsigned,
        signature,
    })
    .map_err(|_| RelaySyncError::InvalidChange)?;
    let context = ciphertext_context(mailbox.route());
    let payload = credentials.key().seal_opaque(&context, &plaintext)?;
    let ciphertext = serde_json::to_vec(&payload).map_err(|_| RelaySyncError::InvalidChange)?;
    Ok(RelayEnvelope::with_opaque_id(
        change_object_id(credentials.key().secret_bytes(), change),
        ciphertext,
        expires_at,
        now,
    )?)
}

#[allow(clippy::too_many_arguments)]
fn encode_epoch_update(
    issuer: &DeviceIdentity,
    previous_epoch: u64,
    access: crate::SpaceAccess,
    new_key: &crate::SpaceKey,
    previous_key: &crate::SpaceKey,
    mailbox: &RelayMailbox,
    expires_at: u64,
    now: u64,
) -> Result<RelayEnvelope, RelaySyncError> {
    let unsigned = UnsignedEpochPacket {
        version: PACKET_VERSION,
        previous_epoch,
        access,
        key: EpochKey(*new_key.secret_bytes()),
    };
    let signature = issuer
        .sign(EPOCH_PACKET_DOMAIN, &unsigned.signing_bytes()?)
        .to_vec();
    let plaintext = Zeroizing::new(
        serde_json::to_vec(&EpochPacket {
            unsigned,
            signature,
        })
        .map_err(|_| RelaySyncError::InvalidChange)?,
    );
    let payload =
        previous_key.seal_opaque(&epoch_ciphertext_context(mailbox.route()), &plaintext)?;
    let ciphertext = serde_json::to_vec(&payload).map_err(|_| RelaySyncError::InvalidChange)?;
    let next_epoch = previous_epoch
        .checked_add(1)
        .ok_or(RelaySyncError::InvalidChange)?;
    Ok(RelayEnvelope::with_opaque_id(
        epoch_object_id(previous_key.secret_bytes(), mailbox.route(), next_epoch),
        ciphertext,
        expires_at,
        now,
    )?)
}

fn decode_epoch_update(
    envelope: &RelayEnvelope,
    current: &SpaceCredentials,
    mailbox: &RelayMailbox,
    issuer: DevicePublicKey,
    recipient: DevicePublicKey,
    now: u64,
) -> Result<(crate::SpaceAccess, crate::SpaceKey), RelaySyncError> {
    let payload: OpaquePayload =
        serde_json::from_slice(envelope.ciphertext()).map_err(|_| RelaySyncError::InvalidChange)?;
    let plaintext = Zeroizing::new(
        current
            .key()
            .open_opaque(&epoch_ciphertext_context(mailbox.route()), &payload)?,
    );
    let packet: EpochPacket =
        serde_json::from_slice(&plaintext).map_err(|_| RelaySyncError::InvalidChange)?;
    let expected_epoch = current
        .authority()
        .epoch
        .checked_add(1)
        .ok_or(RelaySyncError::InvalidChange)?;
    if packet.unsigned.version != PACKET_VERSION
        || packet.unsigned.previous_epoch != current.authority().epoch
        || packet.unsigned.access.authority.space != current.authority().space
        || packet.unsigned.access.authority.issuer != issuer
        || packet.unsigned.access.authority.issuer != current.authority().issuer
        || packet.unsigned.access.authority.epoch != expected_epoch
        || packet.unsigned.access.capability.subject() != recipient
        || !issuer.verify(
            EPOCH_PACKET_DOMAIN,
            &packet.unsigned.signing_bytes()?,
            &packet.signature,
        )
    {
        return Err(RelaySyncError::InvalidChange);
    }
    packet.unsigned.access.capability.authorize(
        packet.unsigned.access.authority,
        recipient,
        Operation::Read,
        now,
    )?;
    let key = crate::SpaceKey::from_bytes(packet.unsigned.key.0);
    Ok((packet.unsigned.access.clone(), key))
}

fn decode_change(
    envelope: &RelayEnvelope,
    credentials: &SpaceCredentials,
    mailbox: &RelayMailbox,
    now: u64,
) -> Result<Change, RelaySyncError> {
    let payload: OpaquePayload =
        serde_json::from_slice(envelope.ciphertext()).map_err(|_| RelaySyncError::InvalidChange)?;
    let plaintext = credentials
        .key()
        .open_opaque(&ciphertext_context(mailbox.route()), &payload)?;
    let packet: ChangePacket =
        serde_json::from_slice(&plaintext).map_err(|_| RelaySyncError::InvalidChange)?;
    let authority = SpaceAuthority {
        space: packet.unsigned.space,
        issuer: credentials.authority().issuer,
        epoch: packet.unsigned.epoch,
    };
    if packet.unsigned.version != PACKET_VERSION
        || authority != credentials.authority()
        || packet.unsigned.change.space != authority.space
        || !packet.unsigned.author.verify(
            PACKET_DOMAIN,
            &packet.unsigned.signing_bytes()?,
            &packet.signature,
        )
    {
        return Err(RelaySyncError::InvalidChange);
    }
    packet.unsigned.capability.authorize(
        authority,
        packet.unsigned.author,
        Operation::Write,
        now,
    )?;
    Ok(packet.unsigned.change)
}

fn ciphertext_context(route: DevicePublicKey) -> Vec<u8> {
    let mut context = Vec::with_capacity(CIPHERTEXT_CONTEXT.len() + 32);
    context.extend_from_slice(CIPHERTEXT_CONTEXT);
    context.extend_from_slice(&route.to_bytes());
    context
}

fn epoch_ciphertext_context(route: DevicePublicKey) -> Vec<u8> {
    let mut context = Vec::with_capacity(EPOCH_CIPHERTEXT_CONTEXT.len() + 32);
    context.extend_from_slice(EPOCH_CIPHERTEXT_CONTEXT);
    context.extend_from_slice(&route.to_bytes());
    context
}

fn epoch_mailbox(key: &crate::SpaceKey, recipient: DevicePublicKey) -> RelayMailbox {
    let mut discriminator = Vec::with_capacity(EPOCH_MAILBOX_PURPOSE.len() + 32);
    discriminator.extend_from_slice(EPOCH_MAILBOX_PURPOSE);
    discriminator.extend_from_slice(&recipient.to_bytes());
    RelayMailbox::derive(key.secret_bytes(), &discriminator)
}

fn epoch_object_id(key: &[u8; 32], route: DevicePublicKey, next_epoch: u64) -> [u8; 32] {
    let mut material = Vec::with_capacity(72);
    material.extend_from_slice(b"cyrene/relay/epoch-update-id/1");
    material.extend_from_slice(&route.to_bytes());
    material.extend_from_slice(&next_epoch.to_be_bytes());
    *blake3::keyed_hash(key, &material).as_bytes()
}

fn change_object_id(key: &[u8; 32], change: &Change) -> [u8; 32] {
    let mut material = Vec::with_capacity(56);
    material.extend_from_slice(b"cyrene/relay/change-id/1");
    material.extend_from_slice(&change.id.replica.as_u128().to_be_bytes());
    material.extend_from_slice(&change.id.counter.to_be_bytes());
    *blake3::keyed_hash(key, &material).as_bytes()
}

fn unix_time() -> Result<u64, RelaySyncError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| RelaySyncError::InvalidRetention)
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, sync::Arc};

    use cyrene_relay::{RelayLimits, RelayStore, serve_connection};
    use serde::{Deserialize, Serialize};
    use tokio::{net::TcpListener, sync::Mutex};

    use super::*;
    use crate::{
        Document, DocumentId, Permission, QuicCertificate, SpaceAccess, SpaceKey, WrappingKey,
    };

    #[derive(Clone, Debug, Document, Serialize, Deserialize)]
    struct Note {
        id: DocumentId,
        title: String,
    }

    fn credentials(
        owner: &DeviceIdentity,
        subject: DevicePublicKey,
        space: crate::SpaceId,
        key: u8,
        now: u64,
    ) -> SpaceCredentials {
        let authority = SpaceAuthority {
            space,
            issuer: owner.public_key(),
            epoch: 1,
        };
        SpaceCredentials::new(
            SpaceAccess {
                authority,
                capability: Capability::issue(
                    owner,
                    space,
                    1,
                    subject,
                    Permission::ReadWrite,
                    now.saturating_sub(1),
                    u64::MAX,
                )
                .unwrap(),
            },
            SpaceKey::from_bytes([key; 32]),
        )
        .unwrap()
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn offline_changes_cross_a_real_relay_and_ack_after_durable_import() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address: SocketAddr = listener.local_addr().unwrap();
        let store = Arc::new(Mutex::new(
            RelayStore::in_memory(RelayLimits::default()).unwrap(),
        ));
        let service_store = Arc::clone(&store);
        let service = tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                serve_connection(stream, &service_store).await.unwrap();
            }
        });
        let alice = DeviceMaterial {
            identity: DeviceIdentity::from_secret_bytes(&[11; 32]),
            certificate: QuicCertificate::generate().unwrap(),
        };
        let bob = DeviceMaterial {
            identity: DeviceIdentity::from_secret_bytes(&[12; 32]),
            certificate: QuicCertificate::generate().unwrap(),
        };
        let space = crate::SpaceId::new();
        let now = unix_time().unwrap();
        let alice_credentials =
            credentials(&alice.identity, alice.identity.public_key(), space, 13, now);
        let bob_credentials =
            credentials(&alice.identity, bob.identity.public_key(), space, 13, now);
        let mut alice_vault =
            TrustStore::open_in_memory(WrappingKey::from_bytes([15; 32])).unwrap();
        alice_vault.initialize_device(&alice).unwrap();
        alice_vault
            .commit_space_epoch(
                &SpaceAccess {
                    authority: alice_credentials.authority(),
                    capability: alice_credentials.capability().clone(),
                },
                alice_credentials.key(),
                std::slice::from_ref(bob_credentials.capability()),
                now,
            )
            .unwrap();
        let alice_app = App::in_memory_space(space).await.unwrap();
        let bob_app = App::in_memory_space(space).await.unwrap();
        let alice_notes = alice_app.collection::<Note>("notes");
        let bob_notes = bob_app.collection::<Note>("notes");
        let id = alice_notes
            .insert(Note {
                id: DocumentId::new(),
                title: "across the quiet internet".into(),
            })
            .await
            .unwrap();
        let client = RelayClient::new(address, Duration::from_secs(2));

        let pushed = alice_app
            .relay_push(
                &client,
                &alice.identity,
                &alice_credentials,
                bob.identity.public_key(),
                Duration::from_secs(60),
            )
            .await
            .unwrap();
        assert_eq!(pushed.offered, 1);
        assert_eq!(pushed.stored, 1);
        assert_eq!(store.lock().await.usage().unwrap().0, 1);
        let retried = alice_app
            .relay_push(
                &client,
                &alice.identity,
                &alice_credentials,
                bob.identity.public_key(),
                Duration::from_secs(60),
            )
            .await
            .unwrap();
        assert_eq!(retried.offered, 1);
        assert_eq!(retried.stored, 0);
        assert_eq!(store.lock().await.usage().unwrap().0, 1);

        let alice_peer = PeerRecord {
            public_key: alice.identity.public_key(),
            certificate_der: alice.certificate.certificate_der().to_vec(),
            paired_at: now,
        };
        let mut bob_vault = TrustStore::open_in_memory(WrappingKey::from_bytes([14; 32])).unwrap();
        bob_vault.initialize_device(&bob).unwrap();
        bob_vault
            .store_space_access(&SpaceAccess {
                authority: bob_credentials.authority(),
                capability: bob_credentials.capability().clone(),
            })
            .unwrap();
        bob_vault
            .store_space_key(space, 1, bob_credentials.key())
            .unwrap();
        bob_vault.admit_peer(&alice_peer).unwrap();
        let unavailable = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let unavailable_address = unavailable.local_addr().unwrap();
        drop(unavailable);
        let outcome = bob_app
            .sync_peer_or_relay(
                unavailable_address,
                &client,
                &bob,
                &alice_peer,
                &mut bob_vault,
                ConnectivityOptions {
                    direct_deadline: Duration::from_millis(100),
                    relay_retention: Duration::from_secs(60),
                },
            )
            .await
            .unwrap();
        let ConnectivityReceipt::Relay { pushed, pulled } = outcome else {
            panic!("unavailable direct endpoint should use the relay");
        };
        assert_eq!(pushed.offered, 0);
        assert_eq!(pulled.received, 1);
        assert_eq!(pulled.retained, 1);
        assert_eq!(pulled.acknowledged, 1);
        assert_eq!(store.lock().await.usage().unwrap(), (0, 0));
        assert_eq!(
            bob_notes.get(id).await.unwrap().unwrap().title,
            "across the quiet internet"
        );

        alice_vault.rotate_owned_space(space, &[], now).unwrap();
        let first_update = alice_app
            .relay_publish_epoch_updates(&client, &alice_vault, Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(first_update.stored, 1);
        alice_vault.rotate_owned_space(space, &[], now).unwrap();
        let second_update = alice_app
            .relay_publish_epoch_updates(&client, &alice_vault, Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(second_update.stored, 1);
        assert_eq!(
            bob_vault
                .space_credentials(space)
                .unwrap()
                .unwrap()
                .authority()
                .epoch,
            1
        );
        let advanced = bob_app
            .relay_refresh_epochs(&client, &bob, &alice_peer, &mut bob_vault)
            .await
            .unwrap();
        assert_eq!(advanced, 2);
        assert_eq!(
            bob_vault
                .space_credentials(space)
                .unwrap()
                .unwrap()
                .authority()
                .epoch,
            3
        );
        assert_eq!(
            bob_vault
                .space_credentials(space)
                .unwrap()
                .unwrap()
                .key()
                .secret_bytes(),
            alice_vault
                .space_credentials(space)
                .unwrap()
                .unwrap()
                .key()
                .secret_bytes()
        );

        alice_vault
            .rotate_owned_space(space, &[bob.identity.public_key()], now)
            .unwrap();
        let revoked_update = alice_app
            .relay_publish_epoch_updates(&client, &alice_vault, Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(revoked_update.offered, 0);
        assert_eq!(
            bob_app
                .relay_refresh_epochs(&client, &bob, &alice_peer, &mut bob_vault)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            bob_vault
                .space_credentials(space)
                .unwrap()
                .unwrap()
                .authority()
                .epoch,
            3
        );
        service.abort();
    }
}
