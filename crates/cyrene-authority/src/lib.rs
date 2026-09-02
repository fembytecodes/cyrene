//! Offline-verifiable authority scoped to one Cyrene space.
//!
//! Transport identity answers “which device is connected?” A [`Capability`]
//! separately answers “what may that device do in this space?” Capabilities
//! are narrow, signed, expiring, and tied to one forward-moving key epoch.

#![forbid(unsafe_code)]

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use cyrene_core::SpaceId;
use cyrene_identity::{DeviceIdentity, DevicePublicKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

const CAPABILITY_DOMAIN: &[u8] = b"cyrene/capability/1";
const CAPABILITY_VERSION: u8 = 1;
const ENCRYPTION_DOMAIN: &[u8] = b"cyrene/space-payload/1";
const ENCRYPTION_VERSION: u8 = 1;
const OPAQUE_DOMAIN: &[u8] = b"cyrene/opaque-payload/1";
const INVITATION_DOMAIN: &[u8] = b"cyrene/share-invitation/1";
const INVITATION_CONTEXT: &[u8] = b"cyrene/share-invitation/key/1";
const INVITATION_VERSION: u8 = 1;

/// A zeroizing 256-bit content key for exactly one space epoch.
pub struct SpaceKey([u8; 32]);

impl SpaceKey {
    /// Generates a fresh content key using operating-system randomness.
    ///
    /// # Errors
    ///
    /// Returns [`EncryptionError::Randomness`] if secure randomness is
    /// unavailable.
    pub fn generate() -> Result<Self, EncryptionError> {
        let mut key = [0_u8; 32];
        getrandom::fill(&mut key).map_err(|_| EncryptionError::Randomness)?;
        Ok(Self(key))
    }

    /// Restores a key obtained through a protected invitation or vault.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Exposes bytes only for a protected persistence or distribution boundary.
    pub const fn secret_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Encrypts content for one space and epoch with caller-supplied context.
    ///
    /// Context should identify the logical record (for example a change ID)
    /// and is authenticated without being encrypted.
    ///
    /// # Errors
    ///
    /// Returns an error if randomness or encryption fails.
    pub fn seal(
        &self,
        space: SpaceId,
        epoch: u64,
        context: &[u8],
        plaintext: &[u8],
    ) -> Result<EncryptedPayload, EncryptionError> {
        let mut nonce = [0_u8; 24];
        getrandom::fill(&mut nonce).map_err(|_| EncryptionError::Randomness)?;
        let cipher =
            XChaCha20Poly1305::new_from_slice(&self.0).map_err(|_| EncryptionError::InvalidKey)?;
        let aad = payload_aad(space, epoch, context);
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| EncryptionError::Authentication)?;
        Ok(EncryptedPayload {
            version: ENCRYPTION_VERSION,
            space,
            epoch,
            nonce,
            ciphertext,
        })
    }

    /// Authenticates and decrypts a payload in its expected scope.
    ///
    /// # Errors
    ///
    /// Returns an error for another version, space, epoch, context, key, or any
    /// modified bytes.
    pub fn open(
        &self,
        expected_space: SpaceId,
        expected_epoch: u64,
        context: &[u8],
        payload: &EncryptedPayload,
    ) -> Result<Vec<u8>, EncryptionError> {
        if payload.version != ENCRYPTION_VERSION {
            return Err(EncryptionError::UnsupportedVersion(payload.version));
        }
        if payload.space != expected_space {
            return Err(EncryptionError::WrongSpace);
        }
        if payload.epoch != expected_epoch {
            return Err(EncryptionError::WrongEpoch);
        }
        let cipher =
            XChaCha20Poly1305::new_from_slice(&self.0).map_err(|_| EncryptionError::InvalidKey)?;
        let aad = payload_aad(payload.space, payload.epoch, context);
        cipher
            .decrypt(
                XNonce::from_slice(&payload.nonce),
                Payload {
                    msg: &payload.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| EncryptionError::Authentication)
    }

    /// Encrypts bytes without exposing their space or epoch in the envelope.
    ///
    /// The caller-provided context must bind every routing-independent value
    /// needed to prevent cross-protocol or cross-record substitution.
    ///
    /// # Errors
    ///
    /// Returns an error if randomness or authenticated encryption fails.
    pub fn seal_opaque(
        &self,
        context: &[u8],
        plaintext: &[u8],
    ) -> Result<OpaquePayload, EncryptionError> {
        let mut nonce = [0_u8; 24];
        getrandom::fill(&mut nonce).map_err(|_| EncryptionError::Randomness)?;
        let cipher =
            XChaCha20Poly1305::new_from_slice(&self.0).map_err(|_| EncryptionError::InvalidKey)?;
        let aad = opaque_aad(context);
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| EncryptionError::Authentication)?;
        Ok(OpaquePayload {
            version: ENCRYPTION_VERSION,
            nonce,
            ciphertext,
        })
    }

    /// Authenticates and opens a metadata-minimized opaque envelope.
    ///
    /// # Errors
    ///
    /// Returns an error for another version, context, key, or modified bytes.
    pub fn open_opaque(
        &self,
        context: &[u8],
        payload: &OpaquePayload,
    ) -> Result<Vec<u8>, EncryptionError> {
        if payload.version != ENCRYPTION_VERSION {
            return Err(EncryptionError::UnsupportedVersion(payload.version));
        }
        let cipher =
            XChaCha20Poly1305::new_from_slice(&self.0).map_err(|_| EncryptionError::InvalidKey)?;
        let aad = opaque_aad(context);
        cipher
            .decrypt(
                XNonce::from_slice(&payload.nonce),
                Payload {
                    msg: &payload.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| EncryptionError::Authentication)
    }
}

impl Drop for SpaceKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for SpaceKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("SpaceKey")
            .field(&"[REDACTED]")
            .finish()
    }
}

/// End-to-end encrypted application bytes for one space epoch.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedPayload {
    version: u8,
    space: SpaceId,
    epoch: u64,
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
}

/// Authenticated ciphertext that reveals no application routing metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpaquePayload {
    version: u8,
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
}

impl EncryptedPayload {
    /// Returns the epoch needed to open this opaque payload.
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    fn signing_bytes(&self, target: &mut Vec<u8>) {
        target.push(self.version);
        target.extend_from_slice(&self.space.as_u128().to_be_bytes());
        target.extend_from_slice(&self.epoch.to_be_bytes());
        target.extend_from_slice(&self.nonce);
        target.extend_from_slice(&(self.ciphertext.len() as u64).to_be_bytes());
        target.extend_from_slice(&self.ciphertext);
    }
}

/// High-entropy bearer secret accompanying a share invitation.
///
/// Possession reveals the invited epoch's content key, so this value is
/// intentionally neither serializable nor printable. Transport it through an
/// explicitly secret channel or an application-specific protected encoding.
pub struct InvitationSecret(SpaceKey);

impl InvitationSecret {
    /// Generates a fresh invitation secret.
    ///
    /// # Errors
    ///
    /// Returns an error if secure randomness is unavailable.
    pub fn generate() -> Result<Self, EncryptionError> {
        SpaceKey::generate().map(Self)
    }

    /// Restores a secret from a protected invitation-token encoding.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(SpaceKey::from_bytes(bytes))
    }

    /// Exposes bytes only at a protected invitation-token boundary.
    pub const fn secret_bytes(&self) -> &[u8; 32] {
        self.0.secret_bytes()
    }
}

impl std::fmt::Debug for InvitationSecret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("InvitationSecret")
            .field(&"[REDACTED]")
            .finish()
    }
}

/// Public, signed portion of a narrow share invitation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ShareInvitation {
    version: u8,
    id: [u8; 16],
    space: SpaceId,
    epoch: u64,
    issuer: DevicePublicKey,
    permission: Permission,
    issued_at: u64,
    expires_at: u64,
    encrypted_key: EncryptedPayload,
    signature: Vec<u8>,
}

impl ShareInvitation {
    /// Creates a signed invitation and a separate high-entropy bearer secret.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty validity interval or unavailable secure
    /// randomness or encryption.
    pub fn issue(
        issuer: &DeviceIdentity,
        space: SpaceId,
        epoch: u64,
        key: &SpaceKey,
        permission: Permission,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<(Self, InvitationSecret), InvitationError> {
        if expires_at <= issued_at {
            return Err(InvitationError::InvalidValidity);
        }
        let mut id = [0_u8; 16];
        getrandom::fill(&mut id).map_err(|_| InvitationError::Randomness)?;
        let secret = InvitationSecret::generate()?;
        let encrypted_key =
            secret
                .0
                .seal(space, epoch, &invitation_context(id), key.secret_bytes())?;
        let mut invitation = Self {
            version: INVITATION_VERSION,
            id,
            space,
            epoch,
            issuer: issuer.public_key(),
            permission,
            issued_at,
            expires_at,
            encrypted_key,
            signature: Vec::new(),
        };
        invitation.signature = issuer
            .sign(INVITATION_DOMAIN, &invitation.signing_bytes())
            .to_vec();
        Ok((invitation, secret))
    }

    /// Verifies the invitation and opens its epoch key for the bearer.
    ///
    /// # Errors
    ///
    /// Returns an error when scope, epoch, issuer, lifetime, signature, secret,
    /// or encrypted key is invalid.
    pub fn open(
        &self,
        authority: SpaceAuthority,
        secret: &InvitationSecret,
        now: u64,
    ) -> Result<SpaceKey, InvitationError> {
        self.verify(authority, now)?;
        let key = secret.0.open(
            self.space,
            self.epoch,
            &invitation_context(self.id),
            &self.encrypted_key,
        )?;
        let key: [u8; 32] = key.try_into().map_err(|_| InvitationError::MalformedKey)?;
        Ok(SpaceKey::from_bytes(key))
    }

    /// Issues the device-bound capability after the owner accepts a claimant.
    ///
    /// Invitation redemption must be committed exactly once by durable host
    /// state before this grant is released.
    ///
    /// # Errors
    ///
    /// Returns an error if the invitation is invalid, `issuer` is not its
    /// authority, or capability issuance fails.
    pub fn grant(
        &self,
        issuer: &DeviceIdentity,
        subject: DevicePublicKey,
        now: u64,
    ) -> Result<Capability, InvitationError> {
        let authority = SpaceAuthority {
            space: self.space,
            issuer: issuer.public_key(),
            epoch: self.epoch,
        };
        self.verify(authority, now)?;
        Capability::issue(
            issuer,
            self.space,
            self.epoch,
            subject,
            self.permission,
            now,
            u64::MAX,
        )
        .map_err(Into::into)
    }

    /// Returns the random invitation identity used for single-use redemption.
    pub const fn id(&self) -> [u8; 16] {
        self.id
    }

    /// Returns the invitation expiry as Unix seconds.
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Returns the invited permission.
    pub const fn permission(&self) -> Permission {
        self.permission
    }

    /// Returns the invited space.
    pub const fn space(&self) -> SpaceId {
        self.space
    }

    /// Returns the invited authority epoch.
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Returns the device that signed this invitation.
    pub const fn issuer(&self) -> DevicePublicKey {
        self.issuer
    }

    fn verify(&self, authority: SpaceAuthority, now: u64) -> Result<(), InvitationError> {
        if self.version != INVITATION_VERSION {
            return Err(InvitationError::UnsupportedVersion(self.version));
        }
        if self.space != authority.space
            || self.epoch != authority.epoch
            || self.issuer != authority.issuer
        {
            return Err(InvitationError::WrongAuthority);
        }
        if now < self.issued_at {
            return Err(InvitationError::NotYetValid);
        }
        if now >= self.expires_at {
            return Err(InvitationError::Expired);
        }
        if !self
            .issuer
            .verify(INVITATION_DOMAIN, &self.signing_bytes(), &self.signature)
        {
            return Err(InvitationError::InvalidSignature);
        }
        Ok(())
    }

    fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(256 + self.encrypted_key.ciphertext.len());
        bytes.push(self.version);
        bytes.extend_from_slice(&self.id);
        bytes.extend_from_slice(&self.space.as_u128().to_be_bytes());
        bytes.extend_from_slice(&self.epoch.to_be_bytes());
        bytes.extend_from_slice(&self.issuer.to_bytes());
        bytes.push(self.permission.tag());
        bytes.extend_from_slice(&self.issued_at.to_be_bytes());
        bytes.extend_from_slice(&self.expires_at.to_be_bytes());
        self.encrypted_key.signing_bytes(&mut bytes);
        bytes
    }
}

/// A share invitation issuance, verification, or opening failure.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum InvitationError {
    /// The invitation format is unknown.
    #[error("share invitation version {0} is unsupported")]
    UnsupportedVersion(u8),
    /// The validity interval is empty or reversed.
    #[error("invitation expiry must be later than issuance")]
    InvalidValidity,
    /// Secure randomness was unavailable.
    #[error("secure random generation failed")]
    Randomness,
    /// The invitation names another space, epoch, or issuer.
    #[error("the invitation belongs to another space authority")]
    WrongAuthority,
    /// The invitation's validity interval has not begun.
    #[error("the invitation is not valid yet")]
    NotYetValid,
    /// The invitation has expired.
    #[error("the invitation has expired")]
    Expired,
    /// The issuer signature is invalid.
    #[error("the invitation signature is invalid")]
    InvalidSignature,
    /// The decrypted content key was malformed.
    #[error("the invitation contained a malformed space key")]
    MalformedKey,
    /// End-to-end decryption or random generation failed.
    #[error(transparent)]
    Encryption(#[from] EncryptionError),
    /// Device-bound capability issuance failed.
    #[error(transparent)]
    Capability(#[from] AuthorityError),
}

fn invitation_context(id: [u8; 16]) -> Vec<u8> {
    let mut context = Vec::with_capacity(INVITATION_CONTEXT.len() + id.len());
    context.extend_from_slice(INVITATION_CONTEXT);
    context.extend_from_slice(&id);
    context
}

/// An end-to-end space encryption failure.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum EncryptionError {
    /// The encrypted payload format is unknown.
    #[error("encrypted payload version {0} is unsupported")]
    UnsupportedVersion(u8),
    /// Secure randomness was unavailable.
    #[error("secure random generation failed")]
    Randomness,
    /// The supplied content key was invalid.
    #[error("the space content key is invalid")]
    InvalidKey,
    /// The payload belongs to another space.
    #[error("the encrypted payload belongs to another space")]
    WrongSpace,
    /// The payload belongs to another key epoch.
    #[error("the encrypted payload belongs to another key epoch")]
    WrongEpoch,
    /// Authentication failed because key, context, or ciphertext did not match.
    #[error("the encrypted space payload could not be authenticated")]
    Authentication,
}

fn payload_aad(space: SpaceId, epoch: u64, context: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(ENCRYPTION_DOMAIN.len() + 32 + context.len());
    aad.extend_from_slice(ENCRYPTION_DOMAIN);
    aad.extend_from_slice(&space.as_u128().to_be_bytes());
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad.extend_from_slice(&(context.len() as u64).to_be_bytes());
    aad.extend_from_slice(context);
    aad
}

fn opaque_aad(context: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(OPAQUE_DOMAIN.len() + 8 + context.len());
    aad.extend_from_slice(OPAQUE_DOMAIN);
    aad.extend_from_slice(&(context.len() as u64).to_be_bytes());
    aad.extend_from_slice(context);
    aad
}

/// Authority granted to a device within one space.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Permission {
    /// Read and retain space contents, but do not author changes.
    ReadOnly,
    /// Read space contents and author changes.
    ReadWrite,
}

impl Permission {
    /// Returns whether this permission allows the requested operation.
    pub const fn allows(self, operation: Operation) -> bool {
        matches!(
            (self, operation),
            (Self::ReadOnly, Operation::Read)
                | (Self::ReadWrite, Operation::Read | Operation::Write)
        )
    }

    const fn tag(self) -> u8 {
        match self {
            Self::ReadOnly => 0,
            Self::ReadWrite => 1,
        }
    }
}

/// An operation checked at the space authorization boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    /// Read or replicate existing content.
    Read,
    /// Author or import a change attributed to this device.
    Write,
}

/// The trusted state against which a capability is evaluated.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SpaceAuthority {
    /// Space whose authority is being checked.
    pub space: SpaceId,
    /// Device currently authorized to issue direct capabilities.
    pub issuer: DevicePublicKey,
    /// Current forward-looking membership and encryption epoch.
    pub epoch: u64,
}

/// A signed, device-specific grant for exactly one space and epoch.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Capability {
    version: u8,
    space: SpaceId,
    epoch: u64,
    issuer: DevicePublicKey,
    subject: DevicePublicKey,
    permission: Permission,
    not_before: u64,
    expires_at: u64,
    nonce: [u8; 16],
    signature: Vec<u8>,
}

impl Capability {
    /// Issues a direct capability from the space authority to one device.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty validity interval or unavailable secure
    /// randomness.
    pub fn issue(
        issuer: &DeviceIdentity,
        space: SpaceId,
        epoch: u64,
        subject: DevicePublicKey,
        permission: Permission,
        not_before: u64,
        expires_at: u64,
    ) -> Result<Self, AuthorityError> {
        if expires_at <= not_before {
            return Err(AuthorityError::InvalidValidity);
        }
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce).map_err(|_| AuthorityError::Randomness)?;
        let mut capability = Self {
            version: CAPABILITY_VERSION,
            space,
            epoch,
            issuer: issuer.public_key(),
            subject,
            permission,
            not_before,
            expires_at,
            nonce,
            signature: Vec::new(),
        };
        capability.signature = issuer
            .sign(CAPABILITY_DOMAIN, &capability.signing_bytes())
            .to_vec();
        Ok(capability)
    }

    /// Verifies scope, epoch, lifetime, subject, signature, and permission.
    ///
    /// # Errors
    ///
    /// Returns a specific fail-closed reason when the grant cannot authorize
    /// the requested operation.
    pub fn authorize(
        &self,
        authority: SpaceAuthority,
        subject: DevicePublicKey,
        operation: Operation,
        now: u64,
    ) -> Result<(), AuthorityError> {
        if self.version != CAPABILITY_VERSION {
            return Err(AuthorityError::UnsupportedVersion(self.version));
        }
        if self.space != authority.space {
            return Err(AuthorityError::WrongSpace);
        }
        if self.epoch != authority.epoch {
            return Err(AuthorityError::StaleEpoch);
        }
        if self.issuer != authority.issuer || self.subject != subject {
            return Err(AuthorityError::WrongPrincipal);
        }
        if now < self.not_before {
            return Err(AuthorityError::NotYetValid);
        }
        if now >= self.expires_at {
            return Err(AuthorityError::Expired);
        }
        if !self
            .issuer
            .verify(CAPABILITY_DOMAIN, &self.signing_bytes(), &self.signature)
        {
            return Err(AuthorityError::InvalidSignature);
        }
        if !self.permission.allows(operation) {
            return Err(AuthorityError::Denied);
        }
        Ok(())
    }

    /// Authenticates signed membership without applying its old time window.
    ///
    /// This is intentionally narrower than authorization: it exists so a
    /// pinned, currently retained device can prove an older membership while
    /// receiving a replacement epoch. It does not authorize data access.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, wrongly scoped, substituted, or
    /// incorrectly signed capabilities.
    pub fn authenticate_membership(
        &self,
        authority: SpaceAuthority,
        subject: DevicePublicKey,
    ) -> Result<(), AuthorityError> {
        if self.version != CAPABILITY_VERSION {
            return Err(AuthorityError::UnsupportedVersion(self.version));
        }
        if self.space != authority.space {
            return Err(AuthorityError::WrongSpace);
        }
        if self.epoch != authority.epoch {
            return Err(AuthorityError::StaleEpoch);
        }
        if self.issuer != authority.issuer || self.subject != subject {
            return Err(AuthorityError::WrongPrincipal);
        }
        if !self
            .issuer
            .verify(CAPABILITY_DOMAIN, &self.signing_bytes(), &self.signature)
        {
            return Err(AuthorityError::InvalidSignature);
        }
        Ok(())
    }

    /// Returns the space named by this untrusted grant.
    pub const fn space(&self) -> SpaceId {
        self.space
    }

    /// Returns the granted permission after successful authorization.
    pub const fn permission(&self) -> Permission {
        self.permission
    }

    /// Returns the device named by this untrusted grant.
    pub const fn subject(&self) -> DevicePublicKey {
        self.subject
    }

    /// Returns the device that signed this grant.
    pub const fn issuer(&self) -> DevicePublicKey {
        self.issuer
    }

    /// Returns the forward-looking authority epoch named by this grant.
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(130);
        bytes.push(self.version);
        bytes.extend_from_slice(&self.space.as_u128().to_be_bytes());
        bytes.extend_from_slice(&self.epoch.to_be_bytes());
        bytes.extend_from_slice(&self.issuer.to_bytes());
        bytes.extend_from_slice(&self.subject.to_bytes());
        bytes.push(self.permission.tag());
        bytes.extend_from_slice(&self.not_before.to_be_bytes());
        bytes.extend_from_slice(&self.expires_at.to_be_bytes());
        bytes.extend_from_slice(&self.nonce);
        bytes
    }
}

/// A capability issuance or verification failure.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AuthorityError {
    /// The capability format is unknown.
    #[error("capability version {0} is unsupported")]
    UnsupportedVersion(u8),
    /// The requested interval is empty or reversed.
    #[error("capability expiry must be later than its start")]
    InvalidValidity,
    /// Secure randomness was unavailable.
    #[error("secure random generation failed")]
    Randomness,
    /// The capability belongs to another space.
    #[error("the capability belongs to another space")]
    WrongSpace,
    /// The capability is from another authority epoch.
    #[error("the capability is from a stale or future authority epoch")]
    StaleEpoch,
    /// The issuer or subject is not the expected principal.
    #[error("the capability names the wrong principal")]
    WrongPrincipal,
    /// The capability's validity interval has not begun.
    #[error("the capability is not valid yet")]
    NotYetValid,
    /// The capability has expired.
    #[error("the capability has expired")]
    Expired,
    /// The authority signature is invalid.
    #[error("the capability signature is invalid")]
    InvalidSignature,
    /// The capability does not permit the requested operation.
    #[error("the capability does not permit this operation")]
    Denied,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(permission: Permission) -> (DeviceIdentity, DeviceIdentity, Capability) {
        let owner = DeviceIdentity::generate().unwrap();
        let member = DeviceIdentity::generate().unwrap();
        let capability = Capability::issue(
            &owner,
            SpaceId::from_u128(7),
            3,
            member.public_key(),
            permission,
            100,
            200,
        )
        .unwrap();
        (owner, member, capability)
    }

    #[test]
    fn read_only_and_read_write_are_enforced_offline() {
        let (owner, member, read_only) = fixture(Permission::ReadOnly);
        let authority = SpaceAuthority {
            space: SpaceId::from_u128(7),
            issuer: owner.public_key(),
            epoch: 3,
        };
        assert_eq!(
            read_only.authorize(authority, member.public_key(), Operation::Read, 150),
            Ok(())
        );
        assert_eq!(
            read_only.authorize(authority, member.public_key(), Operation::Write, 150),
            Err(AuthorityError::Denied)
        );

        let (_, _, read_write) = fixture(Permission::ReadWrite);
        assert!(read_write.permission().allows(Operation::Write));
    }

    #[test]
    fn scope_epoch_subject_and_time_fail_closed() {
        let (owner, member, capability) = fixture(Permission::ReadWrite);
        let authority = SpaceAuthority {
            space: SpaceId::from_u128(7),
            issuer: owner.public_key(),
            epoch: 3,
        };
        assert_eq!(
            capability.authorize(authority, member.public_key(), Operation::Read, 99),
            Err(AuthorityError::NotYetValid)
        );
        assert_eq!(
            capability.authorize(authority, member.public_key(), Operation::Read, 200),
            Err(AuthorityError::Expired)
        );
        assert_eq!(
            capability.authorize(
                SpaceAuthority {
                    epoch: 4,
                    ..authority
                },
                member.public_key(),
                Operation::Read,
                150,
            ),
            Err(AuthorityError::StaleEpoch)
        );
        assert_eq!(
            capability.authorize(
                authority,
                DeviceIdentity::generate().unwrap().public_key(),
                Operation::Read,
                150,
            ),
            Err(AuthorityError::WrongPrincipal)
        );
    }

    #[test]
    fn serialized_tampering_invalidates_the_signature() {
        let (owner, member, capability) = fixture(Permission::ReadOnly);
        let mut encoded = serde_json::to_value(&capability).unwrap();
        encoded["permission"] = serde_json::json!("ReadWrite");
        let tampered: Capability = serde_json::from_value(encoded).unwrap();
        let authority = SpaceAuthority {
            space: SpaceId::from_u128(7),
            issuer: owner.public_key(),
            epoch: 3,
        };
        assert_eq!(
            tampered.authorize(authority, member.public_key(), Operation::Write, 150),
            Err(AuthorityError::InvalidSignature)
        );
    }

    #[test]
    fn space_payloads_are_scoped_and_authenticated() {
        let key = SpaceKey::from_bytes([8; 32]);
        let space = SpaceId::from_u128(9);
        let payload = key.seal(space, 4, b"change-7", b"hello").unwrap();
        assert_eq!(key.open(space, 4, b"change-7", &payload).unwrap(), b"hello");
        assert_eq!(
            key.open(space, 5, b"change-7", &payload),
            Err(EncryptionError::WrongEpoch)
        );
        assert_eq!(
            key.open(space, 4, b"change-8", &payload),
            Err(EncryptionError::Authentication)
        );
        assert_eq!(
            SpaceKey::from_bytes([7; 32]).open(space, 4, b"change-7", &payload),
            Err(EncryptionError::Authentication)
        );
    }

    #[test]
    fn opaque_payloads_hide_scope_and_bind_context() {
        let key = SpaceKey::from_bytes([9; 32]);
        let payload = key
            .seal_opaque(b"recipient-mailbox", b"private packet")
            .unwrap();
        let encoded = serde_json::to_vec(&payload).unwrap();
        assert!(!encoded.windows(14).any(|bytes| bytes == b"private packet"));
        assert_eq!(
            key.open_opaque(b"recipient-mailbox", &payload).unwrap(),
            b"private packet"
        );
        assert_eq!(
            key.open_opaque(b"another-mailbox", &payload),
            Err(EncryptionError::Authentication)
        );
        assert_eq!(
            SpaceKey::from_bytes([10; 32]).open_opaque(b"recipient-mailbox", &payload),
            Err(EncryptionError::Authentication)
        );
    }

    #[test]
    fn ciphertext_tampering_fails_closed() {
        let key = SpaceKey::from_bytes([8; 32]);
        let mut payload = key
            .seal(SpaceId::from_u128(9), 4, b"record", b"private")
            .unwrap();
        payload.ciphertext[0] ^= 1;
        assert_eq!(
            key.open(SpaceId::from_u128(9), 4, b"record", &payload),
            Err(EncryptionError::Authentication)
        );
    }

    #[test]
    fn invitation_opens_key_and_issues_only_device_bound_authority() {
        let owner = DeviceIdentity::from_secret_bytes(&[40; 32]);
        let member = DeviceIdentity::from_secret_bytes(&[41; 32]);
        let space = SpaceId::from_u128(88);
        let key = SpaceKey::from_bytes([42; 32]);
        let (invitation, secret) =
            ShareInvitation::issue(&owner, space, 7, &key, Permission::ReadOnly, 100, 200).unwrap();
        let authority = SpaceAuthority {
            space,
            issuer: owner.public_key(),
            epoch: 7,
        };
        assert_eq!(
            invitation
                .open(authority, &secret, 150)
                .unwrap()
                .secret_bytes(),
            &[42; 32]
        );
        let capability = invitation.grant(&owner, member.public_key(), 150).unwrap();
        assert_eq!(capability.subject(), member.public_key());
        assert_eq!(capability.permission(), Permission::ReadOnly);
        assert_eq!(
            capability.authorize(authority, member.public_key(), Operation::Read, 151),
            Ok(())
        );
        assert_eq!(
            capability.authorize(authority, member.public_key(), Operation::Read, 500),
            Ok(())
        );
    }

    #[test]
    fn expired_capability_can_authenticate_refresh_but_cannot_authorize_data() {
        let owner = DeviceIdentity::from_secret_bytes(&[45; 32]);
        let member = DeviceIdentity::from_secret_bytes(&[46; 32]);
        let space = SpaceId::from_u128(90);
        let authority = SpaceAuthority {
            space,
            issuer: owner.public_key(),
            epoch: 2,
        };
        let capability = Capability::issue(
            &owner,
            space,
            2,
            member.public_key(),
            Permission::ReadOnly,
            100,
            200,
        )
        .unwrap();
        assert_eq!(
            capability.authorize(authority, member.public_key(), Operation::Read, 200),
            Err(AuthorityError::Expired)
        );
        assert_eq!(
            capability.authenticate_membership(authority, member.public_key()),
            Ok(())
        );
        assert_eq!(
            capability.authenticate_membership(authority, owner.public_key()),
            Err(AuthorityError::WrongPrincipal)
        );
    }

    #[test]
    fn invitations_fail_for_wrong_secret_expiry_and_tampering() {
        let owner = DeviceIdentity::from_secret_bytes(&[43; 32]);
        let space = SpaceId::from_u128(89);
        let (invitation, secret) = ShareInvitation::issue(
            &owner,
            space,
            1,
            &SpaceKey::from_bytes([44; 32]),
            Permission::ReadWrite,
            100,
            200,
        )
        .unwrap();
        let authority = SpaceAuthority {
            space,
            issuer: owner.public_key(),
            epoch: 1,
        };
        assert!(matches!(
            invitation.open(authority, &InvitationSecret::from_bytes([1; 32]), 150),
            Err(InvitationError::Encryption(EncryptionError::Authentication))
        ));
        assert_eq!(
            invitation.open(authority, &secret, 200).unwrap_err(),
            InvitationError::Expired
        );

        let mut encoded = serde_json::to_value(&invitation).unwrap();
        encoded["permission"] = serde_json::json!("ReadOnly");
        let tampered: ShareInvitation = serde_json::from_value(encoded).unwrap();
        assert_eq!(
            tampered.open(authority, &secret, 150).unwrap_err(),
            InvitationError::InvalidSignature
        );
    }
}
