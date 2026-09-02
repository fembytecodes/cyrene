//! Opaque, signed store-and-forward relay protocol.
//!
//! Mailbox keys are pseudonymous and epoch-specific. The relay sees a routing
//! key, ciphertext sizes, expiry, and timing; it does not receive a Cyrene
//! space ID, device identity, capability, content key, or plaintext.

use std::{net::SocketAddr, time::Duration};

use cyrene_identity::{DeviceIdentity, DevicePublicKey, PairingError};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

const VERSION: u8 = 1;
const MAILBOX_DOMAIN: &[u8] = b"cyrene/relay/mailbox/1";
const REQUEST_DOMAIN: &[u8] = b"cyrene/relay/request/1";
/// Largest single opaque relay object accepted by the protocol.
pub const MAX_RELAY_ENVELOPE_BYTES: usize = 1024 * 1024;
/// Largest number of objects in one push, pull, or acknowledgement.
pub const MAX_RELAY_BATCH: usize = 256;
/// Largest aggregate opaque payload in one request.
pub const MAX_RELAY_BATCH_BYTES: usize = 4 * 1024 * 1024;
/// Maximum accepted request clock skew in seconds.
pub const MAX_RELAY_CLOCK_SKEW: u64 = 300;
/// Longest object retention requested through the public protocol.
pub const MAX_RELAY_RETENTION: u64 = 30 * 24 * 60 * 60;
const MAX_RELAY_FRAME_BYTES: usize = 24 * 1024 * 1024;

/// A relay protocol validation failure.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum RelayProtocolError {
    /// A wire version or structural field was invalid.
    #[error("the relay message is malformed or unsupported")]
    InvalidMessage,
    /// A request signature did not match its pseudonymous mailbox key.
    #[error("the relay request signature is invalid")]
    InvalidSignature,
    /// The request timestamp is outside the replay-defense window.
    #[error("the relay request timestamp is outside the accepted clock window")]
    StaleRequest,
    /// A payload or batch exceeded a public protocol bound.
    #[error("the relay request exceeds a protocol size bound")]
    LimitExceeded,
    /// Secure operating-system randomness was unavailable.
    #[error("secure random generation failed")]
    Randomness,
    /// A derived public key was invalid.
    #[error("the relay mailbox key is invalid")]
    InvalidKey,
    /// Connecting, reading, or writing the relay transport failed.
    #[error("relay transport failed: {0}")]
    Transport(String),
}

/// A small request/response client for a Cyrene relay endpoint.
#[derive(Clone, Copy, Debug)]
pub struct RelayClient {
    address: SocketAddr,
    timeout: Duration,
}

impl RelayClient {
    /// Configures an endpoint and per-request deadline.
    pub const fn new(address: SocketAddr, timeout: Duration) -> Self {
        Self { address, timeout }
    }

    /// Sends one signed operation and receives one bounded response.
    ///
    /// Payloads and mailbox authorization remain end-to-end protected by the
    /// protocol, so the transport may cross an untrusted proxy or tunnel.
    ///
    /// # Errors
    ///
    /// Returns an error for connection failure, deadline, malformed framing,
    /// oversized messages, or invalid JSON.
    pub async fn exchange(
        &self,
        request: &RelayRequest,
    ) -> Result<RelayResponse, RelayProtocolError> {
        tokio::time::timeout(self.timeout, self.exchange_inner(request))
            .await
            .map_err(|_| RelayProtocolError::Transport("request deadline elapsed".into()))?
    }

    async fn exchange_inner(
        &self,
        request: &RelayRequest,
    ) -> Result<RelayResponse, RelayProtocolError> {
        let mut stream = TcpStream::connect(self.address)
            .await
            .map_err(|error| RelayProtocolError::Transport(error.to_string()))?;
        let bytes = serde_json::to_vec(request)
            .map_err(|error| RelayProtocolError::Transport(error.to_string()))?;
        if bytes.is_empty() || bytes.len() > MAX_RELAY_FRAME_BYTES {
            return Err(RelayProtocolError::LimitExceeded);
        }
        let length = u32::try_from(bytes.len()).map_err(|_| RelayProtocolError::LimitExceeded)?;
        stream
            .write_all(&length.to_be_bytes())
            .await
            .map_err(|error| RelayProtocolError::Transport(error.to_string()))?;
        stream
            .write_all(&bytes)
            .await
            .map_err(|error| RelayProtocolError::Transport(error.to_string()))?;
        stream
            .flush()
            .await
            .map_err(|error| RelayProtocolError::Transport(error.to_string()))?;
        let response_length = stream
            .read_u32()
            .await
            .map_err(|error| RelayProtocolError::Transport(error.to_string()))?;
        let response_length =
            usize::try_from(response_length).map_err(|_| RelayProtocolError::LimitExceeded)?;
        if response_length == 0 || response_length > MAX_RELAY_FRAME_BYTES {
            return Err(RelayProtocolError::LimitExceeded);
        }
        let mut response = vec![0_u8; response_length];
        stream
            .read_exact(&mut response)
            .await
            .map_err(|error| RelayProtocolError::Transport(error.to_string()))?;
        serde_json::from_slice(&response)
            .map_err(|error| RelayProtocolError::Transport(error.to_string()))
    }
}

/// A pseudonymous signing key for one recipient in one space-key epoch.
pub struct RelayMailbox(DeviceIdentity);

impl RelayMailbox {
    /// Deterministically derives a mailbox from secret epoch material and an
    /// opaque recipient discriminator, normally its public device-key bytes.
    pub fn derive(epoch_secret: &[u8; 32], recipient: &[u8]) -> Self {
        let mut material = Vec::with_capacity(MAILBOX_DOMAIN.len() + recipient.len());
        material.extend_from_slice(MAILBOX_DOMAIN);
        material.extend_from_slice(recipient);
        let seed = *blake3::keyed_hash(epoch_secret, &material).as_bytes();
        Self(DeviceIdentity::from_secret_bytes(&seed))
    }

    /// Returns the opaque routing and verification key visible to the relay.
    pub fn route(&self) -> DevicePublicKey {
        self.0.public_key()
    }

    /// Creates a signed bounded push request.
    ///
    /// # Errors
    ///
    /// Returns an error if the batch is empty or above its bound, an envelope
    /// is invalid at `now`, or request randomness is unavailable.
    pub fn push(
        &self,
        envelopes: Vec<RelayEnvelope>,
        now: u64,
    ) -> Result<RelayRequest, RelayProtocolError> {
        if envelopes.is_empty() || envelopes.len() > MAX_RELAY_BATCH {
            return Err(RelayProtocolError::LimitExceeded);
        }
        for envelope in &envelopes {
            envelope.validate(now)?;
        }
        validate_aggregate_size(&envelopes)?;
        self.sign(RelayOperation::Push { envelopes }, now)
    }

    /// Creates a signed bounded pull request after a server-issued cursor.
    ///
    /// # Errors
    ///
    /// Returns an error if `limit` is zero or above the batch bound, or secure
    /// request randomness is unavailable.
    pub fn pull(
        &self,
        after: u64,
        limit: u16,
        now: u64,
    ) -> Result<RelayRequest, RelayProtocolError> {
        if limit == 0 || usize::from(limit) > MAX_RELAY_BATCH {
            return Err(RelayProtocolError::LimitExceeded);
        }
        self.sign(RelayOperation::Pull { after, limit }, now)
    }

    /// Creates a signed acknowledgement that deletes delivered object IDs.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty/oversized batch or unavailable randomness.
    pub fn acknowledge(
        &self,
        ids: Vec<[u8; 32]>,
        now: u64,
    ) -> Result<RelayRequest, RelayProtocolError> {
        if ids.is_empty() || ids.len() > MAX_RELAY_BATCH {
            return Err(RelayProtocolError::LimitExceeded);
        }
        self.sign(RelayOperation::Acknowledge { ids }, now)
    }

    fn sign(
        &self,
        operation: RelayOperation,
        issued_at: u64,
    ) -> Result<RelayRequest, RelayProtocolError> {
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce).map_err(|_| RelayProtocolError::Randomness)?;
        let unsigned = UnsignedRequest {
            version: VERSION,
            route: self.route(),
            issued_at,
            nonce,
            operation,
        };
        let signature = self.0.sign(REQUEST_DOMAIN, &unsigned.signing_bytes());
        Ok(RelayRequest {
            unsigned,
            signature: signature.to_vec(),
        })
    }
}

impl std::fmt::Debug for RelayMailbox {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RelayMailbox")
            .field("route", &self.route().id())
            .finish_non_exhaustive()
    }
}

/// One end-to-end encrypted object retained by an untrusted relay.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RelayEnvelope {
    id: [u8; 32],
    expires_at: u64,
    ciphertext: Vec<u8>,
}

impl RelayEnvelope {
    /// Wraps opaque ciphertext with a content-derived id and bounded expiry.
    ///
    /// # Errors
    ///
    /// Returns an error for empty/oversized ciphertext or expiry outside
    /// `(now, now + 30 days]`.
    pub fn new(ciphertext: Vec<u8>, expires_at: u64, now: u64) -> Result<Self, RelayProtocolError> {
        let id = *blake3::hash(&ciphertext).as_bytes();
        let envelope = Self {
            id,
            expires_at,
            ciphertext,
        };
        envelope.validate(now)?;
        Ok(envelope)
    }

    /// Wraps ciphertext with a caller-derived opaque id.
    ///
    /// This supports retry-stable deduplication when randomized encryption
    /// changes ciphertext bytes. The signed mailbox request authenticates the
    /// id; derive it with secret epoch material so it reveals no logical
    /// application identifier to the relay.
    ///
    /// # Errors
    ///
    /// Returns an error for empty/oversized ciphertext or invalid expiry.
    pub fn with_opaque_id(
        id: [u8; 32],
        ciphertext: Vec<u8>,
        expires_at: u64,
        now: u64,
    ) -> Result<Self, RelayProtocolError> {
        let envelope = Self {
            id,
            expires_at,
            ciphertext,
        };
        envelope.validate(now)?;
        Ok(envelope)
    }

    /// Returns the stable ciphertext-derived deduplication identity.
    pub const fn id(&self) -> [u8; 32] {
        self.id
    }

    /// Returns the requested Unix expiry time.
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Returns opaque end-to-end ciphertext.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    fn validate(&self, now: u64) -> Result<(), RelayProtocolError> {
        if self.ciphertext.is_empty()
            || self.ciphertext.len() > MAX_RELAY_ENVELOPE_BYTES
            || self.expires_at <= now
            || self.expires_at.saturating_sub(now) > MAX_RELAY_RETENTION
        {
            return Err(RelayProtocolError::LimitExceeded);
        }
        Ok(())
    }
}

/// A signed mailbox operation accepted by a relay service.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RelayRequest {
    #[serde(flatten)]
    unsigned: UnsignedRequest,
    signature: Vec<u8>,
}

impl RelayRequest {
    /// Authenticates this request and enforces public clock and size bounds.
    ///
    /// The service must additionally reject replayed `(route, nonce)` pairs.
    ///
    /// # Errors
    ///
    /// Returns a specific error for stale, malformed, oversized, or incorrectly
    /// signed input.
    pub fn verify(&self, now: u64) -> Result<(), RelayProtocolError> {
        if self.unsigned.version != VERSION {
            return Err(RelayProtocolError::InvalidMessage);
        }
        if self.unsigned.issued_at.abs_diff(now) > MAX_RELAY_CLOCK_SKEW {
            return Err(RelayProtocolError::StaleRequest);
        }
        match &self.unsigned.operation {
            RelayOperation::Push { envelopes } => {
                if envelopes.is_empty() || envelopes.len() > MAX_RELAY_BATCH {
                    return Err(RelayProtocolError::LimitExceeded);
                }
                for envelope in envelopes {
                    envelope.validate(now)?;
                }
                validate_aggregate_size(envelopes)?;
            }
            RelayOperation::Pull { limit, .. } => {
                if *limit == 0 || usize::from(*limit) > MAX_RELAY_BATCH {
                    return Err(RelayProtocolError::LimitExceeded);
                }
            }
            RelayOperation::Acknowledge { ids } => {
                if ids.is_empty() || ids.len() > MAX_RELAY_BATCH {
                    return Err(RelayProtocolError::LimitExceeded);
                }
            }
        }
        if !self.unsigned.route.verify(
            REQUEST_DOMAIN,
            &self.unsigned.signing_bytes(),
            &self.signature,
        ) {
            return Err(RelayProtocolError::InvalidSignature);
        }
        Ok(())
    }

    /// Returns the opaque mailbox routing key.
    pub const fn route(&self) -> DevicePublicKey {
        self.unsigned.route
    }

    /// Returns the request nonce used by server-side replay defense.
    pub const fn nonce(&self) -> [u8; 16] {
        self.unsigned.nonce
    }

    /// Returns the requested operation.
    pub const fn operation(&self) -> &RelayOperation {
        &self.unsigned.operation
    }
}

fn validate_aggregate_size(envelopes: &[RelayEnvelope]) -> Result<(), RelayProtocolError> {
    let size = envelopes.iter().try_fold(0_usize, |total, envelope| {
        total.checked_add(envelope.ciphertext.len())
    });
    if size.is_none_or(|size| size > MAX_RELAY_BATCH_BYTES) {
        return Err(RelayProtocolError::LimitExceeded);
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct UnsignedRequest {
    version: u8,
    route: DevicePublicKey,
    issued_at: u64,
    nonce: [u8; 16],
    operation: RelayOperation,
}

impl UnsignedRequest {
    fn signing_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("relay request fields always serialize")
    }
}

/// A bounded store-and-forward operation after signature verification.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum RelayOperation {
    /// Store deduplicated opaque objects until expiry or acknowledgement.
    Push {
        /// Opaque encrypted objects.
        envelopes: Vec<RelayEnvelope>,
    },
    /// Fetch objects after an opaque server sequence cursor.
    Pull {
        /// Last observed server cursor, or zero initially.
        after: u64,
        /// Maximum objects requested.
        limit: u16,
    },
    /// Delete processed objects by their ciphertext-derived IDs.
    Acknowledge {
        /// Object IDs to remove.
        ids: Vec<[u8; 32]>,
    },
}

/// One opaque object and its monotonic mailbox cursor.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RelayDelivery {
    /// Server-issued cursor used for the next pull.
    pub cursor: u64,
    /// End-to-end encrypted object.
    pub envelope: RelayEnvelope,
}

/// A relay response containing no application plaintext.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum RelayResponse {
    /// Push or acknowledgement result.
    Applied {
        /// Newly inserted or deleted objects.
        changed: u16,
    },
    /// Bounded ordered mailbox page.
    Deliveries {
        /// Objects ordered by server cursor.
        items: Vec<RelayDelivery>,
    },
    /// Public, non-sensitive failure category.
    Rejected {
        /// Stable machine-readable error code.
        code: RelayRejection,
    },
}

/// Stable public relay rejection categories.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum RelayRejection {
    /// Authentication or replay validation failed.
    Unauthorized,
    /// A protocol or service bound was exceeded.
    LimitExceeded,
    /// The service could not durably process the request.
    Unavailable,
}

impl From<PairingError> for RelayProtocolError {
    fn from(_: PairingError) -> Self {
        Self::InvalidKey
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mailbox_is_epoch_and_recipient_pseudonymous() {
        let first = RelayMailbox::derive(&[1; 32], &[2; 32]);
        let same = RelayMailbox::derive(&[1; 32], &[2; 32]);
        let another_recipient = RelayMailbox::derive(&[1; 32], &[3; 32]);
        let another_epoch = RelayMailbox::derive(&[4; 32], &[2; 32]);
        assert_eq!(first.route(), same.route());
        assert_ne!(first.route(), another_recipient.route());
        assert_ne!(first.route(), another_epoch.route());
    }

    #[test]
    fn signed_operations_verify_and_tampering_fails() {
        let mailbox = RelayMailbox::derive(&[5; 32], &[6; 32]);
        let envelope = RelayEnvelope::new(vec![7; 128], 1_100, 1_000).unwrap();
        let request = mailbox.push(vec![envelope], 1_000).unwrap();
        assert_eq!(request.verify(1_001), Ok(()));

        let mut encoded = serde_json::to_value(&request).unwrap();
        encoded["issued_at"] = serde_json::json!(1_002);
        let tampered: RelayRequest = serde_json::from_value(encoded).unwrap();
        assert_eq!(
            tampered.verify(1_002),
            Err(RelayProtocolError::InvalidSignature)
        );
        assert_eq!(request.verify(2_000), Err(RelayProtocolError::StaleRequest));
    }

    #[test]
    fn envelope_and_batch_bounds_fail_before_signing() {
        assert_eq!(
            RelayEnvelope::new(Vec::new(), 1_100, 1_000),
            Err(RelayProtocolError::LimitExceeded)
        );
        assert_eq!(
            RelayEnvelope::new(vec![1], 1_000 + MAX_RELAY_RETENTION + 1, 1_000),
            Err(RelayProtocolError::LimitExceeded)
        );
        let mailbox = RelayMailbox::derive(&[8; 32], &[9; 32]);
        assert!(matches!(
            mailbox.pull(0, 0, 1_000),
            Err(RelayProtocolError::LimitExceeded)
        ));
        assert!(matches!(
            mailbox.acknowledge(Vec::new(), 1_000),
            Err(RelayProtocolError::LimitExceeded)
        ));
    }
}
