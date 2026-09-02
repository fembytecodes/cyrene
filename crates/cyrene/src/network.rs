use cyrene_authority::{
    AuthorityError, Capability, EncryptedPayload, EncryptionError,
    Operation as AuthorizedOperation, SpaceAuthority, SpaceKey,
};
use cyrene_core::SpaceId;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use cyrene_net::{
    AuthenticatedConnection, DiscoveryAdvertiser, DiscoveryBrowser, Listener, NetError, connect,
};
use cyrene_sync::{Change, ChangeId, Frontier};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

use crate::{
    App, DeviceIdentity, DeviceMaterial, Error, PeerRecord, SpaceAccess, SpaceCredentials,
    TrustError, TrustStore,
};

const PROTOCOL_VERSION: u8 = 1;
const MAX_CHANGES_PER_EXCHANGE: usize = 4_096;
const MAX_SYNC_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

/// A failure while reconciling replicas over an authenticated peer connection.
#[derive(Debug, Error)]
pub enum PeerSyncError {
    /// The authenticated transport failed.
    #[error(transparent)]
    Transport(#[from] NetError),
    /// Local validation, storage, or replication failed.
    #[error(transparent)]
    Local(#[from] Error),
    /// The peer spoke another protocol version or named another space.
    #[error("the peer proposed an incompatible synchronization session")]
    IncompatiblePeer,
    /// A peer violated the bounded pagination state machine.
    #[error("the peer sent an invalid synchronization page or acknowledgement")]
    InvalidPage,
    /// No matching paired device appeared before the requested deadline.
    #[error("the paired device was not discovered on the local network before the deadline")]
    PeerNotDiscovered,
    /// A discovered peer did not complete connection and sync before deadline.
    #[error("the discovered peer did not complete synchronization before the deadline")]
    Deadline,
    /// The peer did not present sufficient space authority.
    #[error(transparent)]
    Authority(#[from] AuthorityError),
    /// End-to-end space payload encryption or authentication failed.
    #[error(transparent)]
    Encryption(#[from] EncryptionError),
    /// Durable trust or epoch installation failed.
    #[error(transparent)]
    Trust(#[from] TrustError),
}

/// Counts work performed by one bidirectional peer reconciliation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkSyncReceipt {
    /// Changes received and validated from the peer.
    pub received: usize,
    /// Changes offered to the peer.
    pub sent: usize,
    /// Previously unknown incoming changes retained locally.
    pub retained: usize,
    /// Number of acknowledged bounded reconciliation rounds.
    pub rounds: usize,
}

/// An opt-in authenticated LAN server for one open application.
///
/// Creating this value binds QUIC and advertises reachability through mDNS.
/// Dropping it stops both. Trust remains explicit per call to [`Self::accept`].
pub struct LanServer<'identity> {
    app: App,
    identity: &'identity DeviceIdentity,
    listener: Listener,
    _advertisement: DiscoveryAdvertiser,
}

impl LanServer<'_> {
    /// Returns the bound QUIC address, including an OS-selected port.
    ///
    /// # Errors
    ///
    /// Returns an error if the socket address is unavailable.
    pub fn local_addr(&self) -> Result<SocketAddr, PeerSyncError> {
        Ok(self.listener.local_addr()?)
    }

    /// Accepts and synchronizes one explicitly paired device.
    ///
    /// # Errors
    ///
    /// Returns an error if transport authentication, protocol validation, or
    /// durable reconciliation fails.
    pub async fn accept(&self, peer: &PeerRecord) -> Result<NetworkSyncReceipt, PeerSyncError> {
        let connection = self.listener.accept(self.identity, peer.public_key).await?;
        self.app.sync_responder(&connection).await
    }

    /// Accepts one peer and enforces signed space authority in both directions.
    ///
    /// `ours` is presented to the peer. The peer's capability is checked
    /// against `authority` and the device identity proven by QUIC before any
    /// space history is disclosed or imported.
    ///
    /// # Errors
    ///
    /// Returns an error if transport authentication, capability verification,
    /// protocol validation, or durable reconciliation fails.
    pub async fn accept_authorized(
        &self,
        peer: &PeerRecord,
        credentials: &SpaceCredentials,
    ) -> Result<NetworkSyncReceipt, PeerSyncError> {
        let connection = self.listener.accept(self.identity, peer.public_key).await?;
        self.app
            .sync_responder_with_authority(
                &connection,
                Some(SessionAuthority {
                    authority: credentials.authority(),
                    capability: credentials.capability(),
                    key: credentials.key(),
                }),
            )
            .await
    }

    /// Accepts a retained shared-space member, advances stale authority, and syncs.
    ///
    /// The epoch key is disclosed only after pinned transport authentication,
    /// proof of an older valid grant, and a current-roster lookup for the
    /// transport-proven device.
    ///
    /// # Errors
    ///
    /// Returns an error if the peer is revoked, trust state is incomplete, or
    /// epoch negotiation or synchronization fails.
    pub async fn accept_shared(
        &self,
        peer: &PeerRecord,
        vault: &TrustStore,
    ) -> Result<NetworkSyncReceipt, PeerSyncError> {
        let connection = self.listener.accept(self.identity, peer.public_key).await?;
        let credentials = vault
            .space_credentials(self.app.space_id())?
            .ok_or(TrustError::InconsistentCapability)?;
        negotiate_epoch_responder(&connection, vault, &credentials).await?;
        self.app
            .sync_responder_with_authority(
                &connection,
                Some(SessionAuthority {
                    authority: credentials.authority(),
                    capability: credentials.capability(),
                    key: credentials.key(),
                }),
            )
            .await
    }
}

#[derive(Serialize, Deserialize)]
struct EpochHello {
    version: u8,
    space: SpaceId,
    capability: Capability,
}

#[derive(Serialize, Deserialize)]
enum EpochReply {
    Current {
        version: u8,
        space: SpaceId,
        epoch: u64,
    },
    Advance {
        version: u8,
        access: Box<SpaceAccess>,
        key: WireEpochKey,
    },
}

#[derive(Deserialize, Serialize)]
struct WireEpochKey([u8; 32]);

impl Drop for WireEpochKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Serialize, Deserialize)]
struct SyncHello {
    version: u8,
    space: SpaceId,
    target: Frontier,
    receiver_frontier: Frontier,
    capability: Option<Capability>,
}

#[derive(Serialize, Deserialize)]
struct SyncPage {
    version: u8,
    space: SpaceId,
    sender_target: Frontier,
    receiver_frontier: Frontier,
    changes: Vec<WireChange>,
    done: bool,
    capability: Option<Capability>,
}

#[derive(Serialize, Deserialize)]
enum WireChange {
    Plain(Change),
    Sealed {
        id: ChangeId,
        payload: EncryptedPayload,
    },
}

#[derive(Clone, Copy)]
struct SessionAuthority<'a> {
    authority: SpaceAuthority,
    capability: &'a Capability,
    key: &'a SpaceKey,
}

#[derive(Serialize, Deserialize)]
struct RoundAcknowledgement {
    version: u8,
    space: SpaceId,
    done: bool,
}

impl App {
    /// Starts an explicitly networked LAN server for this application.
    ///
    /// Local-only applications never invoke this method and open no sockets.
    /// The listener advertises the device's paired ID and exact certificate
    /// pin; discovery remains untrusted until [`LanServer::accept`] names a
    /// durable [`PeerRecord`].
    ///
    /// # Errors
    ///
    /// Returns an error if QUIC cannot bind or mDNS cannot advertise it.
    pub fn lan_server<'identity>(
        &self,
        address: SocketAddr,
        device: &'identity DeviceMaterial,
    ) -> Result<LanServer<'identity>, PeerSyncError> {
        let listener = Listener::bind(address, &device.certificate)?;
        let advertisement = listener.advertise(device.identity.id())?;
        Ok(LanServer {
            app: self.clone(),
            identity: &device.identity,
            listener,
            _advertisement: advertisement,
        })
    }

    /// Connects and synchronizes with a paired device at a known address.
    ///
    /// # Errors
    ///
    /// Returns an error if pinned QUIC, device authentication, or durable
    /// reconciliation fails.
    pub async fn sync_peer(
        &self,
        address: SocketAddr,
        device: &DeviceMaterial,
        peer: &PeerRecord,
    ) -> Result<NetworkSyncReceipt, PeerSyncError> {
        let bind = match address.ip() {
            IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        let connection = connect(
            bind,
            address,
            &peer.peer_certificate(),
            &device.identity,
            peer.public_key,
        )
        .await?;
        self.sync_initiator(&connection).await
    }

    /// Connects and synchronizes while enforcing signed space authority.
    ///
    /// The local capability is presented to the peer. The remote capability
    /// must authorize its transport-proven device to read before local history
    /// is sent, and to write before any remote changes are imported.
    ///
    /// # Errors
    ///
    /// Returns an error if transport, capability, protocol, or durable state
    /// validation fails.
    pub async fn sync_peer_authorized(
        &self,
        address: SocketAddr,
        device: &DeviceMaterial,
        peer: &PeerRecord,
        credentials: &SpaceCredentials,
    ) -> Result<NetworkSyncReceipt, PeerSyncError> {
        let bind = match address.ip() {
            IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        let connection = connect(
            bind,
            address,
            &peer.peer_certificate(),
            &device.identity,
            peer.public_key,
        )
        .await?;
        self.sync_initiator_with_authority(
            &connection,
            Some(SessionAuthority {
                authority: credentials.authority(),
                capability: credentials.capability(),
                key: credentials.key(),
            }),
        )
        .await
    }

    /// Connects to an issuer, installs a newer retained-member epoch, and syncs.
    ///
    /// This is the preferred shared-space path: callers do not need to detect
    /// stale credentials or split key refresh from data reconciliation.
    ///
    /// # Errors
    ///
    /// Returns an error if pinned transport, epoch authorization, atomic trust
    /// installation, or synchronization fails.
    pub async fn sync_peer_shared(
        &self,
        address: SocketAddr,
        device: &DeviceMaterial,
        peer: &PeerRecord,
        vault: &mut TrustStore,
    ) -> Result<NetworkSyncReceipt, PeerSyncError> {
        let bind = match address.ip() {
            IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        let connection = connect(
            bind,
            address,
            &peer.peer_certificate(),
            &device.identity,
            peer.public_key,
        )
        .await?;
        negotiate_epoch_initiator(&connection, vault, peer, self.space_id()).await?;
        let credentials = vault
            .space_credentials(self.space_id())?
            .ok_or(TrustError::InconsistentCapability)?;
        self.sync_initiator_with_authority(
            &connection,
            Some(SessionAuthority {
                authority: credentials.authority(),
                capability: credentials.capability(),
                key: credentials.key(),
            }),
        )
        .await
    }

    /// Discovers, authenticates, and synchronizes one already paired device.
    ///
    /// Unknown advertisements are ignored. Both the full device ID and
    /// certificate pin must match `peer`, after which pinned QUIC and mutual
    /// device proof still run.
    ///
    /// # Errors
    ///
    /// Returns an error if discovery fails, no matching peer appears, the
    /// deadline elapses during connection, or synchronization fails.
    pub async fn sync_nearby(
        &self,
        device: &DeviceMaterial,
        peer: &PeerRecord,
        wait: Duration,
    ) -> Result<NetworkSyncReceipt, PeerSyncError> {
        let browser = DiscoveryBrowser::start()?;
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(PeerSyncError::PeerNotDiscovered);
            }
            let Some(advertisement) = browser.next(remaining).await? else {
                return Err(PeerSyncError::PeerNotDiscovered);
            };
            if !advertisement.matches(peer.public_key, peer.certificate_pin()) {
                continue;
            }
            for address in advertisement.addresses {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    return Err(PeerSyncError::Deadline);
                }
                match tokio::time::timeout(remaining, self.sync_peer(address, device, peer)).await {
                    Ok(Ok(receipt)) => return Ok(receipt),
                    Ok(Err(_)) => {}
                    Err(_) => return Err(PeerSyncError::Deadline),
                }
            }
        }
    }

    /// Discovers and synchronizes a shared space with signed authority and
    /// epoch encryption.
    ///
    /// Unknown advertisements are ignored exactly as in [`Self::sync_nearby`].
    /// After pinned transport authentication, both peers must present current
    /// space capabilities and every change is carried as epoch ciphertext.
    ///
    /// # Errors
    ///
    /// Returns an error if discovery, transport, authorization, encryption, or
    /// durable reconciliation fails or the deadline elapses.
    pub async fn sync_nearby_authorized(
        &self,
        device: &DeviceMaterial,
        peer: &PeerRecord,
        credentials: &SpaceCredentials,
        wait: Duration,
    ) -> Result<NetworkSyncReceipt, PeerSyncError> {
        let browser = DiscoveryBrowser::start()?;
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(PeerSyncError::PeerNotDiscovered);
            }
            let Some(advertisement) = browser.next(remaining).await? else {
                return Err(PeerSyncError::PeerNotDiscovered);
            };
            if !advertisement.matches(peer.public_key, peer.certificate_pin()) {
                continue;
            }
            for address in advertisement.addresses {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    return Err(PeerSyncError::Deadline);
                }
                let sync = self.sync_peer_authorized(address, device, peer, credentials);
                match tokio::time::timeout(remaining, sync).await {
                    Ok(Ok(receipt)) => return Ok(receipt),
                    Ok(Err(_)) => {}
                    Err(_) => return Err(PeerSyncError::Deadline),
                }
            }
        }
    }

    /// Discovers an issuer, refreshes a retained shared epoch, and synchronizes.
    ///
    /// # Errors
    ///
    /// Returns an error if discovery, authenticated epoch refresh, durable
    /// installation, or reconciliation fails before the deadline.
    pub async fn sync_nearby_shared(
        &self,
        device: &DeviceMaterial,
        peer: &PeerRecord,
        vault: &mut TrustStore,
        wait: Duration,
    ) -> Result<NetworkSyncReceipt, PeerSyncError> {
        let browser = DiscoveryBrowser::start()?;
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(PeerSyncError::PeerNotDiscovered);
            }
            let Some(advertisement) = browser.next(remaining).await? else {
                return Err(PeerSyncError::PeerNotDiscovered);
            };
            if !advertisement.matches(peer.public_key, peer.certificate_pin()) {
                continue;
            }
            for address in advertisement.addresses {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    return Err(PeerSyncError::Deadline);
                }
                let sync = self.sync_peer_shared(address, device, peer, vault);
                match tokio::time::timeout(remaining, sync).await {
                    Ok(Ok(receipt)) => return Ok(receipt),
                    Ok(Err(_)) => {}
                    Err(_) => return Err(PeerSyncError::Deadline),
                }
            }
        }
    }

    /// Reconciles in both directions as the peer that opened the connection.
    ///
    /// Both sides must have opened compatible typed collections before the
    /// exchange. The session transfers authenticated logical history, imports
    /// it atomically, then returns only after the response stream is received.
    ///
    /// # Errors
    ///
    /// Returns an error if the transport fails, the peer targets another space
    /// or protocol, a batch exceeds its hard bound, or local validation and
    /// durable import fail.
    pub async fn sync_initiator(
        &self,
        connection: &AuthenticatedConnection,
    ) -> Result<NetworkSyncReceipt, PeerSyncError> {
        self.sync_initiator_with_authority(connection, None).await
    }

    async fn sync_initiator_with_authority(
        &self,
        connection: &AuthenticatedConnection,
        authorization: Option<SessionAuthority<'_>>,
    ) -> Result<NetworkSyncReceipt, PeerSyncError> {
        let local_target = self.replication_frontier()?;
        let hello = SyncHello {
            version: PROTOCOL_VERSION,
            space: self.space_id(),
            target: local_target.clone(),
            receiver_frontier: local_target.clone(),
            capability: authorization.map(|authorization| authorization.capability.clone()),
        };
        connection.send(&hello, MAX_SYNC_MESSAGE_BYTES).await?;
        let mut remote_target = None;
        let mut totals = NetworkSyncReceipt {
            received: 0,
            sent: 0,
            retained: 0,
            rounds: 0,
        };
        loop {
            let page: SyncPage = connection.receive(MAX_SYNC_MESSAGE_BYTES).await?;
            validate_session(page.version, page.space, self.space_id())?;
            validate_change_count(&page.changes)?;
            authorize_remote(
                authorization.map(|authorization| authorization.authority),
                page.capability.as_ref(),
                connection.peer(),
                !page.changes.is_empty(),
            )?;
            if remote_target
                .as_ref()
                .is_some_and(|target| target != &page.sender_target)
            {
                return Err(PeerSyncError::InvalidPage);
            }
            remote_target.get_or_insert_with(|| page.sender_target.clone());
            totals.received += page.changes.len();
            let incoming = decode_changes(page.changes, authorization, self.space_id())?;
            totals.retained += self.apply_changes(incoming).await?.retained();

            let outgoing = self.changes_toward(
                &page.receiver_frontier,
                &local_target,
                MAX_CHANGES_PER_EXCHANGE,
            )?;
            totals.sent += outgoing.changes.len();
            let local_done = !outgoing.has_more;
            let remote_done = page.done;
            let response = SyncPage {
                version: PROTOCOL_VERSION,
                space: self.space_id(),
                sender_target: local_target.clone(),
                receiver_frontier: self.replication_frontier()?,
                changes: encode_changes(outgoing.changes, authorization, self.space_id())?,
                done: local_done,
                capability: authorization.map(|authorization| authorization.capability.clone()),
            };
            connection.send(&response, MAX_SYNC_MESSAGE_BYTES).await?;
            let acknowledgement: RoundAcknowledgement =
                connection.receive(MAX_SYNC_MESSAGE_BYTES).await?;
            validate_session(
                acknowledgement.version,
                acknowledgement.space,
                self.space_id(),
            )?;
            totals.rounds += 1;
            let expected_done = local_done && remote_done;
            if acknowledgement.done != expected_done {
                return Err(PeerSyncError::InvalidPage);
            }
            if expected_done {
                return Ok(totals);
            }
        }
    }

    /// Reconciles in both directions as the peer that accepted the connection.
    ///
    /// # Errors
    ///
    /// Returns an error if the transport fails, the peer targets another space
    /// or protocol, a batch exceeds its hard bound, or local validation and
    /// durable import fail.
    pub async fn sync_responder(
        &self,
        connection: &AuthenticatedConnection,
    ) -> Result<NetworkSyncReceipt, PeerSyncError> {
        self.sync_responder_with_authority(connection, None).await
    }

    async fn sync_responder_with_authority(
        &self,
        connection: &AuthenticatedConnection,
        authorization: Option<SessionAuthority<'_>>,
    ) -> Result<NetworkSyncReceipt, PeerSyncError> {
        let hello: SyncHello = connection.receive(MAX_SYNC_MESSAGE_BYTES).await?;
        validate_session(hello.version, hello.space, self.space_id())?;
        authorize_remote(
            authorization.map(|authorization| authorization.authority),
            hello.capability.as_ref(),
            connection.peer(),
            false,
        )?;
        let local_target = self.replication_frontier()?;
        let mut initiator_frontier = hello.receiver_frontier;
        let mut totals = NetworkSyncReceipt {
            received: 0,
            sent: 0,
            retained: 0,
            rounds: 0,
        };
        loop {
            let outgoing =
                self.changes_toward(&initiator_frontier, &local_target, MAX_CHANGES_PER_EXCHANGE)?;
            totals.sent += outgoing.changes.len();
            let local_done = !outgoing.has_more;
            let page = SyncPage {
                version: PROTOCOL_VERSION,
                space: self.space_id(),
                sender_target: local_target.clone(),
                receiver_frontier: self.replication_frontier()?,
                changes: encode_changes(outgoing.changes, authorization, self.space_id())?,
                done: local_done,
                capability: authorization.map(|authorization| authorization.capability.clone()),
            };
            connection.send(&page, MAX_SYNC_MESSAGE_BYTES).await?;

            let response: SyncPage = connection.receive(MAX_SYNC_MESSAGE_BYTES).await?;
            validate_session(response.version, response.space, self.space_id())?;
            validate_change_count(&response.changes)?;
            authorize_remote(
                authorization.map(|authorization| authorization.authority),
                response.capability.as_ref(),
                connection.peer(),
                !response.changes.is_empty(),
            )?;
            if response.sender_target != hello.target {
                return Err(PeerSyncError::InvalidPage);
            }
            initiator_frontier = response.receiver_frontier;
            totals.received += response.changes.len();
            let incoming = decode_changes(response.changes, authorization, self.space_id())?;
            totals.retained += self.apply_changes(incoming).await?.retained();
            totals.rounds += 1;
            let done = local_done && response.done;
            connection
                .send(
                    &RoundAcknowledgement {
                        version: PROTOCOL_VERSION,
                        space: self.space_id(),
                        done,
                    },
                    MAX_SYNC_MESSAGE_BYTES,
                )
                .await?;
            if done {
                return Ok(totals);
            }
        }
    }
}

async fn negotiate_epoch_responder(
    connection: &AuthenticatedConnection,
    vault: &TrustStore,
    current: &SpaceCredentials,
) -> Result<(), PeerSyncError> {
    let hello: EpochHello = connection.receive(MAX_SYNC_MESSAGE_BYTES).await?;
    validate_session(hello.version, hello.space, current.authority().space)?;
    let presented_authority = SpaceAuthority {
        space: hello.space,
        issuer: current.authority().issuer,
        epoch: hello.capability.epoch(),
    };
    let now = unix_time_for_authority()?;
    hello
        .capability
        .authenticate_membership(presented_authority, connection.peer())?;
    if hello.capability.epoch() > current.authority().epoch {
        return Err(AuthorityError::StaleEpoch.into());
    }
    let member = vault
        .space_member(hello.space, connection.peer())?
        .ok_or(AuthorityError::WrongPrincipal)?;
    member.authorize(
        current.authority(),
        connection.peer(),
        AuthorizedOperation::Read,
        now,
    )?;
    let reply = if hello.capability.epoch() == current.authority().epoch {
        EpochReply::Current {
            version: PROTOCOL_VERSION,
            space: hello.space,
            epoch: current.authority().epoch,
        }
    } else {
        EpochReply::Advance {
            version: PROTOCOL_VERSION,
            access: Box::new(SpaceAccess {
                authority: current.authority(),
                capability: member,
            }),
            key: WireEpochKey(*current.key().secret_bytes()),
        }
    };
    connection.send(&reply, MAX_SYNC_MESSAGE_BYTES).await?;
    Ok(())
}

async fn negotiate_epoch_initiator(
    connection: &AuthenticatedConnection,
    vault: &mut TrustStore,
    peer: &PeerRecord,
    space: SpaceId,
) -> Result<(), PeerSyncError> {
    let current = vault
        .space_credentials(space)?
        .ok_or(TrustError::InconsistentCapability)?;
    connection
        .send(
            &EpochHello {
                version: PROTOCOL_VERSION,
                space,
                capability: current.capability().clone(),
            },
            MAX_SYNC_MESSAGE_BYTES,
        )
        .await?;
    let reply: EpochReply = connection.receive(MAX_SYNC_MESSAGE_BYTES).await?;
    match reply {
        EpochReply::Current {
            version,
            space: reply_space,
            epoch,
        } => {
            validate_session(version, reply_space, space)?;
            if epoch != current.authority().epoch {
                return Err(PeerSyncError::IncompatiblePeer);
            }
        }
        EpochReply::Advance {
            version,
            access,
            key,
        } => {
            validate_session(version, access.authority.space, space)?;
            let key = SpaceKey::from_bytes(key.0);
            vault.accept_space_epoch(peer, &access, &key, unix_time_for_authority()?)?;
        }
    }
    Ok(())
}

fn unix_time_for_authority() -> Result<u64, AuthorityError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| AuthorityError::NotYetValid)
}

fn encode_changes(
    changes: Vec<Change>,
    authorization: Option<SessionAuthority<'_>>,
    space: SpaceId,
) -> Result<Vec<WireChange>, PeerSyncError> {
    changes
        .into_iter()
        .map(|change| {
            let Some(authorization) = authorization else {
                return Ok(WireChange::Plain(change));
            };
            let id = change.id;
            let plaintext = serde_json::to_vec(&change).map_err(|_| PeerSyncError::InvalidPage)?;
            let payload = authorization.key.seal(
                space,
                authorization.authority.epoch,
                &change_context(id),
                &plaintext,
            )?;
            Ok(WireChange::Sealed { id, payload })
        })
        .collect()
}

fn decode_changes(
    changes: Vec<WireChange>,
    authorization: Option<SessionAuthority<'_>>,
    space: SpaceId,
) -> Result<Vec<Change>, PeerSyncError> {
    changes
        .into_iter()
        .map(|change| match (authorization, change) {
            (None, WireChange::Plain(change)) => Ok(change),
            (Some(authorization), WireChange::Sealed { id, payload }) => {
                let plaintext = authorization.key.open(
                    space,
                    authorization.authority.epoch,
                    &change_context(id),
                    &payload,
                )?;
                let change: Change =
                    serde_json::from_slice(&plaintext).map_err(|_| PeerSyncError::InvalidPage)?;
                if change.id != id || change.space != space {
                    return Err(PeerSyncError::InvalidPage);
                }
                Ok(change)
            }
            _ => Err(PeerSyncError::InvalidPage),
        })
        .collect()
}

fn change_context(id: ChangeId) -> Vec<u8> {
    let mut context = Vec::with_capacity(32);
    context.extend_from_slice(b"cyrene/change/1");
    context.extend_from_slice(&id.replica.as_u128().to_be_bytes());
    context.extend_from_slice(&id.counter.to_be_bytes());
    context
}

fn authorize_remote(
    authority: Option<SpaceAuthority>,
    capability: Option<&Capability>,
    peer: crate::DevicePublicKey,
    writes: bool,
) -> Result<(), PeerSyncError> {
    match (authority, capability) {
        (None, None) => Ok(()),
        (Some(authority), Some(capability)) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| AuthorityError::NotYetValid)?
                .as_secs();
            capability.authorize(authority, peer, AuthorizedOperation::Read, now)?;
            if writes {
                capability.authorize(authority, peer, AuthorizedOperation::Write, now)?;
            }
            Ok(())
        }
        _ => Err(AuthorityError::WrongPrincipal.into()),
    }
}

fn validate_session(
    version: u8,
    peer_space: SpaceId,
    local_space: SpaceId,
) -> Result<(), PeerSyncError> {
    if version != PROTOCOL_VERSION || peer_space != local_space {
        return Err(PeerSyncError::IncompatiblePeer);
    }
    Ok(())
}

fn validate_change_count<T>(changes: &[T]) -> Result<(), PeerSyncError> {
    if changes.len() > MAX_CHANGES_PER_EXCHANGE {
        return Err(PeerSyncError::InvalidPage);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use serde::{Deserialize, Serialize};

    use super::*;
    use crate::{DeviceIdentity, Document, QuicCertificate, connect_peer};

    #[derive(Clone, Debug, Document, Serialize, Deserialize)]
    struct Note {
        id: crate::DocumentId,
        title: String,
    }

    fn capability(
        issuer: &DeviceIdentity,
        subject: crate::DevicePublicKey,
        space: SpaceId,
        permission: crate::Permission,
        now: u64,
    ) -> Capability {
        Capability::issue(
            issuer,
            space,
            1,
            subject,
            permission,
            now.saturating_sub(1),
            now + 60,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn offline_replicas_converge_over_authenticated_quic() {
        let space = SpaceId::new();
        let alice_app = App::in_memory_space(space).await.unwrap();
        let bob_app = App::in_memory_space(space).await.unwrap();
        let alice_notes = alice_app.collection::<Note>("notes");
        let bob_notes = bob_app.collection::<Note>("notes");
        let alice_id = alice_notes
            .insert(Note {
                id: crate::DocumentId::new(),
                title: "from alice".into(),
            })
            .await
            .unwrap();
        let bob_id = bob_notes
            .insert(Note {
                id: crate::DocumentId::new(),
                title: "from bob".into(),
            })
            .await
            .unwrap();

        let alice_identity = DeviceIdentity::from_secret_bytes(&[1; 32]);
        let bob_identity = DeviceIdentity::from_secret_bytes(&[2; 32]);
        let certificate = QuicCertificate::generate().unwrap();
        let peer_certificate = certificate.public_certificate();
        let listener = crate::Listener::bind(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            &certificate,
        )
        .unwrap();
        let address = listener.local_addr().unwrap();

        let responder = async {
            let connection = listener
                .accept(&alice_identity, bob_identity.public_key())
                .await
                .unwrap();
            alice_app.sync_responder(&connection).await.unwrap()
        };
        let initiator = async {
            let connection = connect_peer(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                address,
                &peer_certificate,
                &bob_identity,
                alice_identity.public_key(),
            )
            .await
            .unwrap();
            bob_app.sync_initiator(&connection).await.unwrap()
        };
        let (alice_receipt, bob_receipt) = tokio::join!(responder, initiator);

        assert_eq!(alice_receipt.received, 1);
        assert_eq!(bob_receipt.received, 1);
        assert_eq!(
            alice_notes.get(bob_id).await.unwrap().unwrap().title,
            "from bob"
        );
        assert_eq!(
            bob_notes.get(alice_id).await.unwrap().unwrap().title,
            "from alice"
        );
        assert_eq!(
            alice_app.replication_frontier().unwrap(),
            bob_app.replication_frontier().unwrap()
        );
    }

    #[tokio::test]
    async fn histories_larger_than_one_batch_resume_to_a_fixed_frontier() {
        const CHANGE_COUNT: usize = MAX_CHANGES_PER_EXCHANGE + 17;

        let space = SpaceId::new();
        let alice_app = App::in_memory_space(space).await.unwrap();
        let bob_app = App::in_memory_space(space).await.unwrap();
        let alice_notes = alice_app.collection::<Note>("notes");
        let _bob_notes = bob_app.collection::<Note>("notes");
        let mut transaction = alice_app.transaction();
        for index in 0..CHANGE_COUNT {
            transaction
                .insert(
                    &alice_notes,
                    Note {
                        id: crate::DocumentId::new(),
                        title: format!("note {index}"),
                    },
                )
                .unwrap();
        }
        transaction.commit().await.unwrap();

        let alice_identity = DeviceIdentity::from_secret_bytes(&[11; 32]);
        let bob_identity = DeviceIdentity::from_secret_bytes(&[12; 32]);
        let certificate = QuicCertificate::generate().unwrap();
        let peer_certificate = certificate.public_certificate();
        let listener = crate::Listener::bind(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            &certificate,
        )
        .unwrap();
        let address = listener.local_addr().unwrap();

        let responder = async {
            let connection = listener
                .accept(&alice_identity, bob_identity.public_key())
                .await
                .unwrap();
            alice_app.sync_responder(&connection).await.unwrap()
        };
        let initiator = async {
            let connection = connect_peer(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                address,
                &peer_certificate,
                &bob_identity,
                alice_identity.public_key(),
            )
            .await
            .unwrap();
            bob_app.sync_initiator(&connection).await.unwrap()
        };
        let (alice_receipt, bob_receipt) = tokio::join!(responder, initiator);

        assert_eq!(alice_receipt.sent, CHANGE_COUNT);
        assert_eq!(bob_receipt.received, CHANGE_COUNT);
        assert_eq!(alice_receipt.rounds, 2);
        assert_eq!(bob_receipt.rounds, 2);
        assert_eq!(
            bob_app.status().await.unwrap().documents,
            CHANGE_COUNT as u64
        );
        assert_eq!(
            alice_app.replication_frontier().unwrap(),
            bob_app.replication_frontier().unwrap()
        );
    }

    #[tokio::test]
    async fn high_level_lan_facade_hides_transport_plumbing() {
        let space = SpaceId::new();
        let alice_app = App::in_memory_space(space).await.unwrap();
        let bob_app = App::in_memory_space(space).await.unwrap();
        let alice_notes = alice_app.collection::<Note>("notes");
        let bob_notes = bob_app.collection::<Note>("notes");
        let note_id = alice_notes
            .insert(Note {
                id: crate::DocumentId::new(),
                title: "pleasantly nearby".into(),
            })
            .await
            .unwrap();
        let alice = DeviceMaterial {
            identity: DeviceIdentity::from_secret_bytes(&[21; 32]),
            certificate: QuicCertificate::generate().unwrap(),
        };
        let bob = DeviceMaterial {
            identity: DeviceIdentity::from_secret_bytes(&[22; 32]),
            certificate: QuicCertificate::generate().unwrap(),
        };
        let alice_peer = PeerRecord {
            public_key: alice.identity.public_key(),
            certificate_der: alice.certificate.certificate_der().to_vec(),
            paired_at: 1,
        };
        let bob_peer = PeerRecord {
            public_key: bob.identity.public_key(),
            certificate_der: bob.certificate.certificate_der().to_vec(),
            paired_at: 1,
        };
        let server = alice_app
            .lan_server(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0), &alice)
            .unwrap();
        let address = server.local_addr().unwrap();

        let (server_receipt, client_receipt) = tokio::join!(
            server.accept(&bob_peer),
            bob_app.sync_peer(address, &bob, &alice_peer)
        );
        assert_eq!(server_receipt.unwrap().sent, 1);
        assert_eq!(client_receipt.unwrap().received, 1);
        assert_eq!(
            bob_notes.get(note_id).await.unwrap().unwrap().title,
            "pleasantly nearby"
        );
    }

    #[tokio::test]
    async fn read_only_capability_allows_pull_but_rejects_remote_writes() {
        let space = SpaceId::new();
        let alice_app = App::in_memory_space(space).await.unwrap();
        let bob_app = App::in_memory_space(space).await.unwrap();
        let alice_notes = alice_app.collection::<Note>("notes");
        let bob_notes = bob_app.collection::<Note>("notes");
        let alice_note = alice_notes
            .insert(Note {
                id: crate::DocumentId::new(),
                title: "owner history".into(),
            })
            .await
            .unwrap();
        let bob_note = bob_notes
            .insert(Note {
                id: crate::DocumentId::new(),
                title: "unauthorized write".into(),
            })
            .await
            .unwrap();

        let alice = DeviceIdentity::from_secret_bytes(&[31; 32]);
        let bob = DeviceIdentity::from_secret_bytes(&[32; 32]);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let authority = SpaceAuthority {
            space,
            issuer: alice.public_key(),
            epoch: 1,
        };
        let alice_capability = capability(
            &alice,
            alice.public_key(),
            space,
            crate::Permission::ReadWrite,
            now,
        );
        let bob_capability = capability(
            &alice,
            bob.public_key(),
            space,
            crate::Permission::ReadOnly,
            now,
        );
        let space_key = SpaceKey::from_bytes([33; 32]);
        let certificate = QuicCertificate::generate().unwrap();
        let peer_certificate = certificate.public_certificate();
        let listener = crate::Listener::bind(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            &certificate,
        )
        .unwrap();
        let address = listener.local_addr().unwrap();

        let responder = async {
            let connection = listener.accept(&alice, bob.public_key()).await.unwrap();
            alice_app
                .sync_responder_with_authority(
                    &connection,
                    Some(SessionAuthority {
                        authority,
                        capability: &alice_capability,
                        key: &space_key,
                    }),
                )
                .await
        };
        let initiator = async {
            let connection = connect_peer(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                address,
                &peer_certificate,
                &bob,
                alice.public_key(),
            )
            .await
            .unwrap();
            bob_app
                .sync_initiator_with_authority(
                    &connection,
                    Some(SessionAuthority {
                        authority,
                        capability: &bob_capability,
                        key: &space_key,
                    }),
                )
                .await
        };
        let (server_result, client_result) = tokio::join!(responder, initiator);

        assert!(matches!(
            server_result,
            Err(PeerSyncError::Authority(AuthorityError::Denied))
        ));
        assert!(client_result.is_err());
        assert!(alice_notes.get(bob_note).await.unwrap().is_none());
        assert_eq!(
            bob_notes.get(alice_note).await.unwrap().unwrap().title,
            "owner history"
        );
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn retained_member_advances_epoch_in_band_while_revoked_member_gets_nothing() {
        let space = SpaceId::new();
        let alice_app = App::in_memory_space(space).await.unwrap();
        let bob_app = App::in_memory_space(space).await.unwrap();
        let alice_notes = alice_app.collection::<Note>("notes");
        let bob_notes = bob_app.collection::<Note>("notes");
        let alice_note = alice_notes
            .insert(Note {
                id: crate::DocumentId::new(),
                title: "after rotation".into(),
            })
            .await
            .unwrap();
        let alice = DeviceMaterial {
            identity: DeviceIdentity::from_secret_bytes(&[41; 32]),
            certificate: QuicCertificate::generate().unwrap(),
        };
        let bob = DeviceMaterial {
            identity: DeviceIdentity::from_secret_bytes(&[42; 32]),
            certificate: QuicCertificate::generate().unwrap(),
        };
        let alice_peer = PeerRecord {
            public_key: alice.identity.public_key(),
            certificate_der: alice.certificate.certificate_der().to_vec(),
            paired_at: 1,
        };
        let bob_peer = PeerRecord {
            public_key: bob.identity.public_key(),
            certificate_der: bob.certificate.certificate_der().to_vec(),
            paired_at: 1,
        };
        let now = unix_time_for_authority().unwrap();
        let authority = SpaceAuthority {
            space,
            issuer: alice.identity.public_key(),
            epoch: 1,
        };
        let alice_access = SpaceAccess {
            authority,
            capability: Capability::issue(
                &alice.identity,
                space,
                1,
                alice.identity.public_key(),
                crate::Permission::ReadWrite,
                now.saturating_sub(1),
                u64::MAX,
            )
            .unwrap(),
        };
        let bob_access = SpaceAccess {
            authority,
            capability: Capability::issue(
                &alice.identity,
                space,
                1,
                bob.identity.public_key(),
                crate::Permission::ReadWrite,
                now.saturating_sub(1),
                u64::MAX,
            )
            .unwrap(),
        };
        let first_key = SpaceKey::from_bytes([43; 32]);
        let mut alice_vault =
            TrustStore::open_in_memory(crate::WrappingKey::from_bytes([44; 32])).unwrap();
        alice_vault.initialize_device(&alice).unwrap();
        alice_vault
            .commit_space_epoch(
                &alice_access,
                &first_key,
                std::slice::from_ref(&bob_access.capability),
                now,
            )
            .unwrap();
        let mut bob_vault =
            TrustStore::open_in_memory(crate::WrappingKey::from_bytes([45; 32])).unwrap();
        bob_vault.initialize_device(&bob).unwrap();
        bob_vault
            .accept_shared_space(&alice_peer, &bob_access, &first_key, now)
            .unwrap();

        alice_vault.rotate_owned_space(space, &[], now).unwrap();
        let server = alice_app
            .lan_server(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0), &alice)
            .unwrap();
        let address = server.local_addr().unwrap();
        let (server_result, client_result) = tokio::join!(
            server.accept_shared(&bob_peer, &alice_vault),
            bob_app.sync_peer_shared(address, &bob, &alice_peer, &mut bob_vault)
        );
        assert!(server_result.is_ok());
        assert!(client_result.is_ok());
        let alice_credentials = alice_vault.space_credentials(space).unwrap().unwrap();
        let bob_credentials = bob_vault.space_credentials(space).unwrap().unwrap();
        assert_eq!(alice_credentials.authority().epoch, 2);
        assert_eq!(bob_credentials.authority(), alice_credentials.authority());
        assert_eq!(
            bob_credentials.key().secret_bytes(),
            alice_credentials.key().secret_bytes()
        );
        assert_eq!(
            bob_notes.get(alice_note).await.unwrap().unwrap().title,
            "after rotation"
        );

        alice_vault
            .rotate_owned_space(space, &[bob.identity.public_key()], now)
            .unwrap();
        let server = alice_app
            .lan_server(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0), &alice)
            .unwrap();
        let address = server.local_addr().unwrap();
        let (server_result, client_result) = tokio::join!(
            server.accept_shared(&bob_peer, &alice_vault),
            bob_app.sync_peer_shared(address, &bob, &alice_peer, &mut bob_vault)
        );
        assert!(matches!(
            server_result,
            Err(PeerSyncError::Authority(AuthorityError::WrongPrincipal))
        ));
        assert!(client_result.is_err());
        assert_eq!(
            bob_vault
                .space_credentials(space)
                .unwrap()
                .unwrap()
                .authority()
                .epoch,
            2
        );
    }
}
