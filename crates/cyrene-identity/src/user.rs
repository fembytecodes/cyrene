use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{DeviceIdentity, DevicePublicKey};

const USER_DOMAIN: &[u8] = b"cyrene/user-identity/1";
const USER_VERSION: u8 = 1;

/// Stable identity of one person assembled from an explicit device chain.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct UserId([u8; 32]);

impl UserId {
    /// Restores a user identifier from its digest bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the complete digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0[..8] {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for UserId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "UserId({self})")
    }
}

/// One device-membership transition in a user identity chain.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum UserAction {
    /// Authorize a newly linked device as this user.
    Add(DevicePublicKey),
    /// Remove a linked device for all future user-identity epochs.
    Remove(DevicePublicKey),
}

/// Signed, hash-linked user device membership event.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct UserEvent {
    version: u8,
    user: UserId,
    sequence: u64,
    previous: [u8; 32],
    genesis_nonce: Option<[u8; 16]>,
    action: UserAction,
    actor: DevicePublicKey,
    signature: Vec<u8>,
}

impl UserEvent {
    /// Returns the user identity named by this untrusted event.
    pub const fn user(&self) -> UserId {
        self.user
    }

    /// Returns its zero-based chain position.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the membership transition after successful chain verification.
    pub const fn action(&self) -> UserAction {
        self.action
    }

    /// Returns the linked device that signed this event.
    pub const fn actor(&self) -> DevicePublicKey {
        self.actor
    }

    /// Returns the event digest used by the following chain link.
    pub fn digest(&self) -> [u8; 32] {
        let mut bytes = self.signing_bytes();
        push(&mut bytes, &self.signature);
        *blake3::hash(&bytes).as_bytes()
    }

    fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(180);
        push(&mut bytes, USER_DOMAIN);
        push(&mut bytes, &[self.version]);
        push(&mut bytes, self.user.as_bytes());
        push(&mut bytes, &self.sequence.to_be_bytes());
        push(&mut bytes, &self.previous);
        match self.genesis_nonce {
            Some(nonce) => {
                bytes.push(1);
                push(&mut bytes, &nonce);
            }
            None => bytes.push(0),
        }
        match self.action {
            UserAction::Add(device) => {
                bytes.push(0);
                push(&mut bytes, &device.to_bytes());
            }
            UserAction::Remove(device) => {
                bytes.push(1);
                push(&mut bytes, &device.to_bytes());
            }
        }
        push(&mut bytes, &self.actor.to_bytes());
        bytes
    }
}

/// Verified current membership and history for one user.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserIdentity {
    id: UserId,
    devices: BTreeSet<DevicePublicKey>,
    events: Vec<UserEvent>,
}

impl UserIdentity {
    /// Creates a new user rooted in the local device.
    ///
    /// # Errors
    ///
    /// Returns an error if secure randomness is unavailable.
    pub fn create(device: &DeviceIdentity) -> Result<Self, UserIdentityError> {
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce).map_err(|_| UserIdentityError::Randomness)?;
        let user = derive_user_id(device.public_key(), nonce);
        let mut event = UserEvent {
            version: USER_VERSION,
            user,
            sequence: 0,
            previous: [0; 32],
            genesis_nonce: Some(nonce),
            action: UserAction::Add(device.public_key()),
            actor: device.public_key(),
            signature: Vec::new(),
        };
        event.signature = device.sign(USER_DOMAIN, &event.signing_bytes()).to_vec();
        Self::from_events([event])
    }

    /// Reconstructs and verifies a complete event chain.
    ///
    /// # Errors
    ///
    /// Returns the first structural, signature, membership, or fork error.
    pub fn from_events(
        events: impl IntoIterator<Item = UserEvent>,
    ) -> Result<Self, UserIdentityError> {
        let mut identity = None;
        for event in events {
            match &mut identity {
                None => identity = Some(Self::from_genesis(event)?),
                Some(identity) => identity.apply(event)?,
            }
        }
        identity.ok_or(UserIdentityError::MissingGenesis)
    }

    /// Creates a signed event linking `device` to this user.
    ///
    /// The returned event is not active until durably applied.
    ///
    /// # Errors
    ///
    /// Returns an error if `actor` is not currently linked or `device` already
    /// belongs to this identity.
    pub fn link_device(
        &self,
        actor: &DeviceIdentity,
        device: DevicePublicKey,
    ) -> Result<UserEvent, UserIdentityError> {
        if self.devices.contains(&device) {
            return Err(UserIdentityError::AlreadyLinked);
        }
        self.issue(actor, UserAction::Add(device))
    }

    /// Creates a signed event removing `device` from future user authority.
    ///
    /// # Errors
    ///
    /// Returns an error if the actor or target is not linked, or removal would
    /// leave the user with no authorized devices.
    pub fn remove_device(
        &self,
        actor: &DeviceIdentity,
        device: DevicePublicKey,
    ) -> Result<UserEvent, UserIdentityError> {
        if !self.devices.contains(&device) {
            return Err(UserIdentityError::NotLinked);
        }
        if self.devices.len() == 1 {
            return Err(UserIdentityError::LastDevice);
        }
        self.issue(actor, UserAction::Remove(device))
    }

    /// Verifies and applies the next event in this exact chain.
    ///
    /// # Errors
    ///
    /// Returns an error without mutation for invalid signatures, unauthorized
    /// actors, non-contiguous sequences, or a competing predecessor.
    pub fn apply(&mut self, event: UserEvent) -> Result<(), UserIdentityError> {
        if event.version != USER_VERSION || event.user != self.id || event.genesis_nonce.is_some() {
            return Err(UserIdentityError::InvalidEvent);
        }
        let expected_sequence =
            u64::try_from(self.events.len()).map_err(|_| UserIdentityError::InvalidSequence)?;
        if event.sequence < expected_sequence {
            let index =
                usize::try_from(event.sequence).map_err(|_| UserIdentityError::InvalidSequence)?;
            return if self.events.get(index) == Some(&event) {
                Err(UserIdentityError::Duplicate)
            } else {
                Err(UserIdentityError::Fork)
            };
        }
        if event.sequence > expected_sequence {
            return Err(UserIdentityError::InvalidSequence);
        }
        let previous = self
            .events
            .last()
            .ok_or(UserIdentityError::MissingGenesis)?
            .digest();
        if event.previous != previous {
            return Err(UserIdentityError::Fork);
        }
        if !self.devices.contains(&event.actor) {
            return Err(UserIdentityError::UnauthorizedActor);
        }
        if !event
            .actor
            .verify(USER_DOMAIN, &event.signing_bytes(), &event.signature)
        {
            return Err(UserIdentityError::InvalidSignature);
        }
        match event.action {
            UserAction::Add(device) if self.devices.contains(&device) => {
                return Err(UserIdentityError::AlreadyLinked);
            }
            UserAction::Add(device) => {
                self.devices.insert(device);
            }
            UserAction::Remove(device) if !self.devices.contains(&device) => {
                return Err(UserIdentityError::NotLinked);
            }
            UserAction::Remove(_) if self.devices.len() == 1 => {
                return Err(UserIdentityError::LastDevice);
            }
            UserAction::Remove(device) => {
                self.devices.remove(&device);
            }
        }
        self.events.push(event);
        Ok(())
    }

    /// Returns the stable user identifier.
    pub const fn id(&self) -> UserId {
        self.id
    }

    /// Returns current linked devices in stable public-key order.
    pub fn devices(&self) -> impl ExactSizeIterator<Item = DevicePublicKey> + '_ {
        self.devices.iter().copied()
    }

    /// Returns the verified event history.
    pub fn events(&self) -> &[UserEvent] {
        &self.events
    }

    /// Returns the next event sequence, also serving as membership epoch.
    pub fn epoch(&self) -> u64 {
        u64::try_from(self.events.len()).unwrap_or(u64::MAX)
    }

    fn from_genesis(event: UserEvent) -> Result<Self, UserIdentityError> {
        let UserAction::Add(device) = event.action else {
            return Err(UserIdentityError::InvalidEvent);
        };
        let Some(nonce) = event.genesis_nonce else {
            return Err(UserIdentityError::MissingGenesis);
        };
        if event.version != USER_VERSION
            || event.sequence != 0
            || event.previous != [0; 32]
            || event.actor != device
            || event.user != derive_user_id(device, nonce)
        {
            return Err(UserIdentityError::InvalidEvent);
        }
        if !device.verify(USER_DOMAIN, &event.signing_bytes(), &event.signature) {
            return Err(UserIdentityError::InvalidSignature);
        }
        Ok(Self {
            id: event.user,
            devices: BTreeSet::from([device]),
            events: vec![event],
        })
    }

    fn issue(
        &self,
        actor: &DeviceIdentity,
        action: UserAction,
    ) -> Result<UserEvent, UserIdentityError> {
        if !self.devices.contains(&actor.public_key()) {
            return Err(UserIdentityError::UnauthorizedActor);
        }
        let mut event = UserEvent {
            version: USER_VERSION,
            user: self.id,
            sequence: self.epoch(),
            previous: self.events.last().expect("genesis exists").digest(),
            genesis_nonce: None,
            action,
            actor: actor.public_key(),
            signature: Vec::new(),
        };
        event.signature = actor.sign(USER_DOMAIN, &event.signing_bytes()).to_vec();
        Ok(event)
    }
}

/// A user device-chain creation or verification failure.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum UserIdentityError {
    /// No genesis event was supplied.
    #[error("the user identity has no genesis event")]
    MissingGenesis,
    /// Secure randomness was unavailable.
    #[error("secure random generation failed")]
    Randomness,
    /// Event fields do not form a supported identity transition.
    #[error("the user identity event is invalid")]
    InvalidEvent,
    /// Event sequence is not the next contiguous position.
    #[error("the user identity event has a non-contiguous sequence")]
    InvalidSequence,
    /// This exact event is already present in the verified chain.
    #[error("the user identity event is already applied")]
    Duplicate,
    /// Event names another predecessor at this chain position.
    #[error("the user identity event conflicts with this membership history")]
    Fork,
    /// The device signature is invalid.
    #[error("the user identity event signature is invalid")]
    InvalidSignature,
    /// The signing device is not a current member.
    #[error("the user identity event was signed by an unlinked device")]
    UnauthorizedActor,
    /// The target device is already linked.
    #[error("the device is already linked to this user")]
    AlreadyLinked,
    /// The target device is not linked.
    #[error("the device is not linked to this user")]
    NotLinked,
    /// A user identity must retain at least one device.
    #[error("the final linked device cannot be removed")]
    LastDevice,
}

fn derive_user_id(device: DevicePublicKey, nonce: [u8; 16]) -> UserId {
    let mut bytes = Vec::with_capacity(USER_DOMAIN.len() + 48);
    bytes.extend_from_slice(USER_DOMAIN);
    bytes.extend_from_slice(&device.to_bytes());
    bytes.extend_from_slice(&nonce);
    UserId(*blake3::hash(&bytes).as_bytes())
}

fn push(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&(value.len() as u64).to_be_bytes());
    target.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(byte: u8) -> DeviceIdentity {
        DeviceIdentity::from_secret_bytes(&[byte; 32])
    }

    #[test]
    fn devices_link_and_remove_through_verified_history() {
        let alice_laptop = identity(1);
        let alice_phone = identity(2);
        let mut user = UserIdentity::create(&alice_laptop).unwrap();
        let linked = user
            .link_device(&alice_laptop, alice_phone.public_key())
            .unwrap();
        user.apply(linked).unwrap();
        assert_eq!(user.devices().count(), 2);

        let removed = user
            .remove_device(&alice_phone, alice_laptop.public_key())
            .unwrap();
        user.apply(removed).unwrap();
        assert_eq!(
            user.devices().collect::<Vec<_>>(),
            vec![alice_phone.public_key()]
        );
        assert_eq!(
            user.link_device(&alice_laptop, identity(3).public_key()),
            Err(UserIdentityError::UnauthorizedActor)
        );
        assert_eq!(
            user.remove_device(&alice_phone, alice_phone.public_key()),
            Err(UserIdentityError::LastDevice)
        );
    }

    #[test]
    fn complete_history_reconstructs_the_same_user() {
        let laptop = identity(4);
        let phone = identity(5);
        let mut original = UserIdentity::create(&laptop).unwrap();
        original
            .apply(original.link_device(&laptop, phone.public_key()).unwrap())
            .unwrap();
        let restored = UserIdentity::from_events(original.events().iter().cloned()).unwrap();
        assert_eq!(restored, original);
    }

    #[test]
    fn tampering_and_competing_history_fail_without_mutation() {
        let laptop = identity(6);
        let phone = identity(7);
        let tablet = identity(8);
        let user = UserIdentity::create(&laptop).unwrap();
        let mut valid = user.link_device(&laptop, phone.public_key()).unwrap();
        let competing = user.link_device(&laptop, tablet.public_key()).unwrap();
        valid.signature[0] ^= 1;

        let mut unchanged = user.clone();
        assert_eq!(
            unchanged.apply(valid),
            Err(UserIdentityError::InvalidSignature)
        );
        assert_eq!(unchanged, user);

        unchanged.apply(competing.clone()).unwrap();
        let mut other_branch = user.clone();
        other_branch
            .apply(user.link_device(&laptop, phone.public_key()).unwrap())
            .unwrap();
        assert_eq!(other_branch.apply(competing), Err(UserIdentityError::Fork));
    }
}
