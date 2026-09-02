//! Durable device identities and short-code authenticated pairing.
//!
//! Pairing is deliberately transport-neutral. A caller carries [`Offer`],
//! [`Answer`], and [`Acknowledgement`] over a local socket, QR code, or another
//! untrusted channel. The short code is processed by SPAKE2 and never used as
//! an encryption key.

#![forbid(unsafe_code)]

mod user;

pub use user::{UserAction, UserEvent, UserId, UserIdentity, UserIdentityError};

use std::{fmt, time::Duration};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use thiserror::Error;

const PROTOCOL: &[u8] = b"cyrene/pairing/1";
const CODE_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// An error while creating or completing a pairing.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PairingError {
    /// The invitation's lifetime has elapsed.
    #[error("this pairing invitation has expired")]
    Expired,
    /// A message was malformed or belongs to another protocol version.
    #[error("the pairing message is invalid")]
    InvalidMessage,
    /// A device signature did not match the advertised public key.
    #[error("the pairing message has an invalid device signature")]
    InvalidSignature,
    /// The short codes or transcripts did not match.
    #[error("the pairing codes or transcripts do not match")]
    ConfirmationFailed,
    /// The operating system did not provide secure random bytes.
    #[error("secure random generation failed")]
    Randomness,
}

/// A stable identifier derived from a device's public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceId([u8; 32]);

impl DeviceId {
    /// Restores an identifier from its public hash bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the identifier bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for DeviceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "DeviceId({self})")
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0[..8] {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// A device's public identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DevicePublicKey([u8; 32]);

impl DevicePublicKey {
    /// Parses and validates an encoded Ed25519 public key.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::InvalidMessage`] when the bytes are not a valid
    /// compressed Ed25519 point.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, PairingError> {
        let key = Self(bytes);
        key.verifier()?;
        Ok(key)
    }

    /// Returns this key's stable device identifier.
    pub fn id(self) -> DeviceId {
        DeviceId(*blake3::hash(&[PROTOCOL, b"/device/", &self.0].concat()).as_bytes())
    }

    /// Returns the encoded Ed25519 public key.
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Verifies a signature in an application-specific domain.
    ///
    /// A domain must be a stable protocol identifier, not user-controlled
    /// input. Domain separation prevents a valid signature from one Cyrene
    /// protocol from being replayed in another.
    pub fn verify(self, domain: &[u8], message: &[u8], signature: &[u8]) -> bool {
        let Ok(signature) = Signature::from_slice(signature) else {
            return false;
        };
        let Ok(verifier) = self.verifier() else {
            return false;
        };
        verifier
            .verify_strict(&signature_message(domain, message), &signature)
            .is_ok()
    }

    fn verifier(self) -> Result<VerifyingKey, PairingError> {
        VerifyingKey::from_bytes(&self.0).map_err(|_| PairingError::InvalidMessage)
    }
}

/// A locally generated device identity.
///
/// The secret key is intentionally neither serializable nor printable. Use
/// [`DeviceIdentity::secret_bytes`] only at a protected persistence boundary.
pub struct DeviceIdentity(SigningKey);

impl DeviceIdentity {
    /// Generates a fresh identity from operating-system randomness.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::Randomness`] if the operating system random
    /// source is unavailable.
    pub fn generate() -> Result<Self, PairingError> {
        let mut secret = [0_u8; 32];
        getrandom::fill(&mut secret).map_err(|_| PairingError::Randomness)?;
        Ok(Self(SigningKey::from_bytes(&secret)))
    }

    /// Restores an identity from its secret encoding.
    pub fn from_secret_bytes(secret: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(secret))
    }

    /// Exposes the secret encoding for protected persistence.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Returns the public half of this identity.
    pub fn public_key(&self) -> DevicePublicKey {
        DevicePublicKey(self.0.verifying_key().to_bytes())
    }

    /// Returns this identity's stable identifier.
    pub fn id(&self) -> DeviceId {
        self.public_key().id()
    }

    /// Signs a message in an application-specific domain.
    pub fn sign(&self, domain: &[u8], message: &[u8]) -> [u8; 64] {
        self.0.sign(&signature_message(domain, message)).to_bytes()
    }
}

impl fmt::Debug for DeviceIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceIdentity")
            .field("id", &self.id())
            .finish_non_exhaustive()
    }
}

/// A human-entered, single-invitation pairing code.
pub struct PairingCode(String);

impl PairingCode {
    /// Generates an eight-character code with 40 bits of entropy.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::Randomness`] if the operating system random
    /// source is unavailable.
    pub fn generate() -> Result<Self, PairingError> {
        let mut random = [0_u8; 8];
        getrandom::fill(&mut random).map_err(|_| PairingError::Randomness)?;
        let code = random
            .into_iter()
            .map(|byte| char::from(CODE_ALPHABET[usize::from(byte & 31)]))
            .collect();
        Ok(Self(code))
    }

    /// Parses a code, ignoring spaces and hyphens and normalizing case.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::InvalidMessage`] if the normalized value is not
    /// exactly eight characters from Cyrene's unambiguous alphabet.
    pub fn parse(value: &str) -> Result<Self, PairingError> {
        let code: String = value
            .chars()
            .filter(|character| !matches!(character, ' ' | '-'))
            .flat_map(char::to_uppercase)
            .collect();
        if code.len() != 8 || !code.bytes().all(|byte| CODE_ALPHABET.contains(&byte)) {
            return Err(PairingError::InvalidMessage);
        }
        Ok(Self(code))
    }

    fn password(&self) -> Password {
        Password::new(self.0.as_bytes())
    }
}

impl fmt::Display for PairingCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}-{}", &self.0[..4], &self.0[4..])
    }
}

impl fmt::Debug for PairingCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairingCode([redacted])")
    }
}

/// The inviter's first wire message.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Offer {
    version: u8,
    invitation_id: [u8; 16],
    expires_at: u64,
    public_key: DevicePublicKey,
    transport_binding: Vec<u8>,
    context: Vec<u8>,
    pake_message: Vec<u8>,
    signature: Vec<u8>,
}

/// The joining device's wire response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Answer {
    public_key: DevicePublicKey,
    transport_binding: Vec<u8>,
    context: Vec<u8>,
    pake_message: Vec<u8>,
    confirmation: [u8; 32],
    signature: Vec<u8>,
}

/// The inviter's final key-confirmation message.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Acknowledgement {
    confirmation: [u8; 32],
}

/// A successfully authenticated peer and pairing session key.
pub struct PairedPeer {
    /// The peer's authenticated public key.
    pub public_key: DevicePublicKey,
    transport_binding: Vec<u8>,
    context: Vec<u8>,
    session_key: [u8; 32],
}

impl PairedPeer {
    /// Returns the peer's stable identifier.
    pub fn id(&self) -> DeviceId {
        self.public_key.id()
    }

    /// Returns key material scoped to this one pairing session.
    pub const fn session_key(&self) -> &[u8; 32] {
        &self.session_key
    }

    /// Returns the peer's authenticated transport binding.
    ///
    /// For Cyrene QUIC this is the peer's DER certificate, pinned exactly by
    /// the trust store after pairing.
    pub fn transport_binding(&self) -> &[u8] {
        &self.transport_binding
    }

    /// Returns peer-supplied context authenticated by the pairing transcript.
    ///
    /// The identity layer treats this as opaque bounded bytes. Higher layers
    /// use it for versioned device-link or invitation metadata.
    pub fn context(&self) -> &[u8] {
        &self.context
    }
}

impl Offer {
    /// Returns the durable invitation identifier.
    pub const fn invitation_id(&self) -> [u8; 16] {
        self.invitation_id
    }

    /// Returns the invitation expiry as Unix seconds.
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

/// Single-use inviter state.
pub struct Inviter<'a> {
    identity: &'a DeviceIdentity,
    offer: Offer,
    pake: Spake2<Ed25519Group>,
}

/// Single-use joining-device state awaiting the final acknowledgement.
pub struct Joiner {
    peer: DevicePublicKey,
    peer_binding: Vec<u8>,
    peer_context: Vec<u8>,
    session_key: [u8; 32],
    transcript: Vec<u8>,
}

impl<'a> Inviter<'a> {
    /// Creates an invitation that remains valid for `lifetime` after `now`.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::Randomness`] if the invitation identifier or
    /// SPAKE2 exchange cannot obtain secure operating-system randomness.
    pub fn start(
        identity: &'a DeviceIdentity,
        code: &PairingCode,
        transport_binding: &[u8],
        now: u64,
        lifetime: Duration,
    ) -> Result<(Self, Offer), PairingError> {
        Self::start_with_context(identity, code, transport_binding, &[], now, lifetime)
    }

    /// Creates an invitation with opaque, transcript-authenticated context.
    ///
    /// # Errors
    ///
    /// Returns an error if context exceeds 4 KiB or secure randomness is
    /// unavailable.
    pub fn start_with_context(
        identity: &'a DeviceIdentity,
        code: &PairingCode,
        transport_binding: &[u8],
        context: &[u8],
        now: u64,
        lifetime: Duration,
    ) -> Result<(Self, Offer), PairingError> {
        validate_transport_binding(transport_binding)?;
        validate_context(context)?;
        let mut invitation_id = [0_u8; 16];
        getrandom::fill(&mut invitation_id).map_err(|_| PairingError::Randomness)?;
        let expires_at = now.saturating_add(lifetime.as_secs());
        let (pake, pake_message) = Spake2::<Ed25519Group>::start_symmetric(
            &code.password(),
            &Identity::new(&pairing_context(&invitation_id)),
        );
        let mut offer = Offer {
            version: 1,
            invitation_id,
            expires_at,
            public_key: identity.public_key(),
            transport_binding: transport_binding.to_vec(),
            context: context.to_vec(),
            pake_message,
            signature: Vec::new(),
        };
        offer.signature = identity
            .0
            .sign(&offer_signing_bytes(&offer))
            .to_bytes()
            .to_vec();
        Ok((
            Self {
                identity,
                offer: offer.clone(),
                pake,
            },
            offer,
        ))
    }

    /// Authenticates an answer and creates the final acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns an error if the offer expired, the answer is malformed or
    /// unsigned, or its key confirmation does not match.
    pub fn finish(
        self,
        answer: &Answer,
        now: u64,
    ) -> Result<(PairedPeer, Acknowledgement), PairingError> {
        validate_offer(&self.offer, now)?;
        verify_signature(
            answer.public_key,
            &answer_signing_bytes(&self.offer, answer),
            &answer.signature,
        )?;
        let shared = self
            .pake
            .finish(&answer.pake_message)
            .map_err(|_| PairingError::InvalidMessage)?;
        let transcript = transcript_bytes(&self.offer, answer);
        let session_key = derive_session_key(&shared, &transcript);
        if confirmation(&session_key, b"joiner", &transcript) != answer.confirmation {
            return Err(PairingError::ConfirmationFailed);
        }
        // Retain the identity borrow in the state so callers cannot accidentally
        // outlive the key used to create this invitation.
        let _ = self.identity;
        let acknowledgement = Acknowledgement {
            confirmation: confirmation(&session_key, b"inviter", &transcript),
        };
        Ok((
            PairedPeer {
                public_key: answer.public_key,
                transport_binding: answer.transport_binding.clone(),
                context: answer.context.clone(),
                session_key,
            },
            acknowledgement,
        ))
    }
}

impl Joiner {
    /// Accepts an offer and prepares a signed, key-confirmed response.
    ///
    /// # Errors
    ///
    /// Returns an error if the offer expired, is malformed, has an invalid
    /// signature, or the SPAKE2 exchange rejects it.
    pub fn start(
        identity: &DeviceIdentity,
        code: &PairingCode,
        transport_binding: &[u8],
        offer: &Offer,
        now: u64,
    ) -> Result<(Self, Answer), PairingError> {
        Self::start_with_context(identity, code, transport_binding, &[], offer, now)
    }

    /// Accepts an offer with opaque, transcript-authenticated local context.
    ///
    /// # Errors
    ///
    /// Returns an error if context exceeds 4 KiB or normal offer validation
    /// and key exchange fails.
    pub fn start_with_context(
        identity: &DeviceIdentity,
        code: &PairingCode,
        transport_binding: &[u8],
        context: &[u8],
        offer: &Offer,
        now: u64,
    ) -> Result<(Self, Answer), PairingError> {
        validate_transport_binding(transport_binding)?;
        validate_context(context)?;
        validate_offer(offer, now)?;
        verify_signature(
            offer.public_key,
            &offer_signing_bytes(offer),
            &offer.signature,
        )?;
        let (pake, pake_message) = Spake2::<Ed25519Group>::start_symmetric(
            &code.password(),
            &Identity::new(&pairing_context(&offer.invitation_id)),
        );
        let shared = pake
            .finish(&offer.pake_message)
            .map_err(|_| PairingError::InvalidMessage)?;
        let mut answer = Answer {
            public_key: identity.public_key(),
            transport_binding: transport_binding.to_vec(),
            context: context.to_vec(),
            pake_message,
            confirmation: [0; 32],
            signature: Vec::new(),
        };
        let transcript = transcript_bytes(offer, &answer);
        let session_key = derive_session_key(&shared, &transcript);
        answer.confirmation = confirmation(&session_key, b"joiner", &transcript);
        answer.signature = identity
            .0
            .sign(&answer_signing_bytes(offer, &answer))
            .to_bytes()
            .to_vec();
        Ok((
            Self {
                peer: offer.public_key,
                peer_binding: offer.transport_binding.clone(),
                peer_context: offer.context.clone(),
                session_key,
                transcript,
            },
            answer,
        ))
    }

    /// Verifies the inviter's final key confirmation.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::ConfirmationFailed`] if the acknowledgement was
    /// not produced by the matching inviter exchange.
    pub fn finish(self, acknowledgement: &Acknowledgement) -> Result<PairedPeer, PairingError> {
        if confirmation(&self.session_key, b"inviter", &self.transcript)
            != acknowledgement.confirmation
        {
            return Err(PairingError::ConfirmationFailed);
        }
        Ok(PairedPeer {
            public_key: self.peer,
            transport_binding: self.peer_binding,
            context: self.peer_context,
            session_key: self.session_key,
        })
    }
}

fn validate_offer(offer: &Offer, now: u64) -> Result<(), PairingError> {
    if offer.version != 1 || offer.pake_message.is_empty() {
        return Err(PairingError::InvalidMessage);
    }
    validate_transport_binding(&offer.transport_binding)?;
    validate_context(&offer.context)?;
    if now > offer.expires_at {
        return Err(PairingError::Expired);
    }
    Ok(())
}

fn validate_context(context: &[u8]) -> Result<(), PairingError> {
    if context.len() > 4_096 {
        return Err(PairingError::InvalidMessage);
    }
    Ok(())
}

fn validate_transport_binding(binding: &[u8]) -> Result<(), PairingError> {
    if binding.is_empty() || binding.len() > 4_096 {
        return Err(PairingError::InvalidMessage);
    }
    Ok(())
}

fn verify_signature(
    key: DevicePublicKey,
    message: &[u8],
    encoded: &[u8],
) -> Result<(), PairingError> {
    let signature = Signature::from_slice(encoded).map_err(|_| PairingError::InvalidSignature)?;
    key.verifier()?
        .verify_strict(message, &signature)
        .map_err(|_| PairingError::InvalidSignature)
}

fn pairing_context(invitation_id: &[u8; 16]) -> Vec<u8> {
    [PROTOCOL, b"/spake2/", invitation_id].concat()
}

fn offer_signing_bytes(offer: &Offer) -> Vec<u8> {
    let mut bytes = Vec::new();
    push(&mut bytes, PROTOCOL);
    push(&mut bytes, b"offer");
    push(&mut bytes, &[offer.version]);
    push(&mut bytes, &offer.invitation_id);
    push(&mut bytes, &offer.expires_at.to_be_bytes());
    push(&mut bytes, &offer.public_key.0);
    push(&mut bytes, &offer.transport_binding);
    push(&mut bytes, &offer.context);
    push(&mut bytes, &offer.pake_message);
    bytes
}

fn answer_signing_bytes(offer: &Offer, answer: &Answer) -> Vec<u8> {
    let mut bytes = offer_signing_bytes(offer);
    push(&mut bytes, &offer.signature);
    push(&mut bytes, &answer.public_key.0);
    push(&mut bytes, &answer.transport_binding);
    push(&mut bytes, &answer.context);
    push(&mut bytes, &answer.pake_message);
    push(&mut bytes, &answer.confirmation);
    bytes
}

fn transcript_bytes(offer: &Offer, answer: &Answer) -> Vec<u8> {
    let mut bytes = offer_signing_bytes(offer);
    push(&mut bytes, &offer.signature);
    push(&mut bytes, &answer.public_key.0);
    push(&mut bytes, &answer.transport_binding);
    push(&mut bytes, &answer.context);
    push(&mut bytes, &answer.pake_message);
    bytes
}

fn push(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&(value.len() as u64).to_be_bytes());
    target.extend_from_slice(value);
}

fn signature_message(domain: &[u8], message: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(PROTOCOL.len() + domain.len() + message.len() + 24);
    push(&mut encoded, PROTOCOL);
    push(&mut encoded, domain);
    push(&mut encoded, message);
    encoded
}

fn derive_session_key(shared: &[u8], transcript: &[u8]) -> [u8; 32] {
    let mut material = Vec::with_capacity(shared.len() + transcript.len());
    push(&mut material, shared);
    push(&mut material, transcript);
    blake3::derive_key("cyrene pairing session key v1", &material)
}

fn confirmation(key: &[u8; 32], role: &[u8], transcript: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(PROTOCOL);
    hasher.update(role);
    hasher.update(transcript);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(byte: u8) -> DeviceIdentity {
        DeviceIdentity::from_secret_bytes(&[byte; 32])
    }

    #[test]
    fn two_devices_pair_and_authenticate_each_other() {
        let alice = identity(1);
        let bob = identity(2);
        let code = PairingCode::parse("C7YR-3N3K").unwrap();
        let (inviter, offer) =
            Inviter::start(&alice, &code, b"alice cert", 100, Duration::from_secs(60)).unwrap();
        let (joiner, answer) = Joiner::start(&bob, &code, b"bob cert", &offer, 101).unwrap();
        let (alice_peer, acknowledgement) = inviter.finish(&answer, 102).unwrap();
        let bob_peer = joiner.finish(&acknowledgement).unwrap();

        assert_eq!(alice_peer.id(), bob.id());
        assert_eq!(bob_peer.id(), alice.id());
        assert_eq!(alice_peer.session_key(), bob_peer.session_key());
        assert_eq!(alice_peer.transport_binding(), b"bob cert");
        assert_eq!(bob_peer.transport_binding(), b"alice cert");
    }

    #[test]
    fn different_codes_fail_key_confirmation() {
        let alice = identity(1);
        let bob = identity(2);
        let alice_code = PairingCode::parse("C7YR-3N3K").unwrap();
        let bob_code = PairingCode::parse("C7YR-3N3M").unwrap();
        let (inviter, offer) = Inviter::start(
            &alice,
            &alice_code,
            b"alice cert",
            100,
            Duration::from_secs(60),
        )
        .unwrap();
        let (_, answer) = Joiner::start(&bob, &bob_code, b"bob cert", &offer, 101).unwrap();

        assert!(matches!(
            inviter.finish(&answer, 102),
            Err(PairingError::ConfirmationFailed)
        ));
    }

    #[test]
    fn expired_offer_is_rejected() {
        let alice = identity(1);
        let bob = identity(2);
        let code = PairingCode::parse("C7YR-3N3K").unwrap();
        let (_, offer) =
            Inviter::start(&alice, &code, b"alice cert", 100, Duration::from_secs(5)).unwrap();
        assert!(matches!(
            Joiner::start(&bob, &code, b"bob cert", &offer, 106),
            Err(PairingError::Expired)
        ));
    }

    #[test]
    fn tampered_identity_is_rejected() {
        let alice = identity(1);
        let bob = identity(2);
        let code = PairingCode::parse("C7YR-3N3K").unwrap();
        let (_, mut offer) =
            Inviter::start(&alice, &code, b"alice cert", 100, Duration::from_secs(60)).unwrap();
        offer.public_key = bob.public_key();
        assert!(matches!(
            Joiner::start(&bob, &code, b"bob cert", &offer, 101),
            Err(PairingError::InvalidSignature)
        ));
    }

    #[test]
    fn secrets_are_redacted_from_debug_output() {
        let device = identity(7);
        let code = PairingCode::parse("C7YR-3N3K").unwrap();
        assert!(!format!("{device:?}").contains(&format!("{:?}", [7_u8; 32])));
        assert_eq!(format!("{code:?}"), "PairingCode([redacted])");
    }

    #[test]
    fn scoped_signatures_cannot_cross_protocol_domains() {
        let device = identity(7);
        let signature = device.sign(b"cyrene/test/a", b"hello");
        assert!(
            device
                .public_key()
                .verify(b"cyrene/test/a", b"hello", &signature)
        );
        assert!(
            !device
                .public_key()
                .verify(b"cyrene/test/b", b"hello", &signature)
        );
    }

    #[test]
    fn pairing_authenticates_bounded_context_in_both_directions() {
        let alice = identity(1);
        let bob = identity(2);
        let code = PairingCode::parse("C7YR-3N3K").unwrap();
        let (inviter, offer) = Inviter::start_with_context(
            &alice,
            &code,
            b"alice cert",
            b"alice linked space",
            100,
            Duration::from_secs(60),
        )
        .unwrap();
        let (joiner, answer) =
            Joiner::start_with_context(&bob, &code, b"bob cert", b"bob linked space", &offer, 101)
                .unwrap();
        let (alice_peer, acknowledgement) = inviter.finish(&answer, 102).unwrap();
        let bob_peer = joiner.finish(&acknowledgement).unwrap();
        assert_eq!(alice_peer.context(), b"bob linked space");
        assert_eq!(bob_peer.context(), b"alice linked space");
    }
}
