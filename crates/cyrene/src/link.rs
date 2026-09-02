use cyrene_core::{Error, ErrorCode, Result, SpaceId};
use serde::{Deserialize, Serialize};

const LINK_VERSION: u8 = 1;

/// Versioned device-link context authenticated by the pairing ceremony.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DeviceLink {
    spaces: Vec<SpaceId>,
}

impl DeviceLink {
    /// Creates an empty device link.
    pub const fn new() -> Self {
        Self { spaces: Vec::new() }
    }

    /// Adds a personal space for the linked device to join.
    #[must_use]
    pub fn with_space(mut self, space: SpaceId) -> Self {
        if !self.spaces.contains(&space) {
            self.spaces.push(space);
            self.spaces.sort_unstable();
        }
        self
    }

    /// Returns linked spaces in stable order.
    pub fn spaces(&self) -> &[SpaceId] {
        &self.spaces
    }

    /// Encodes this link as bounded pairing context.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails or the context exceeds the
    /// pairing protocol's 4 KiB bound.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let encoded = serde_json::to_vec(&WireDeviceLink {
            version: LINK_VERSION,
            spaces: self.spaces.clone(),
        })
        .map_err(|error| {
            Error::with_source(
                ErrorCode::InvalidData,
                "could not encode device-link context",
                error,
            )
        })?;
        if encoded.len() > 4_096 {
            return Err(Error::new(
                ErrorCode::InvalidInput,
                "device-link context exceeds the 4 KiB pairing bound",
            ));
        }
        Ok(encoded)
    }

    /// Decodes authenticated pairing context.
    ///
    /// Empty context represents a link with no application spaces.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, oversized, unsupported, or duplicate
    /// space metadata.
    pub fn decode(encoded: &[u8]) -> Result<Self> {
        if encoded.is_empty() {
            return Ok(Self::new());
        }
        if encoded.len() > 4_096 {
            return Err(Error::new(
                ErrorCode::InvalidData,
                "device-link context exceeds the protocol bound",
            ));
        }
        let wire: WireDeviceLink = serde_json::from_slice(encoded).map_err(|error| {
            Error::with_source(
                ErrorCode::InvalidData,
                "the paired device sent malformed link context",
                error,
            )
        })?;
        if wire.version != LINK_VERSION {
            return Err(Error::new(
                ErrorCode::InvalidData,
                format!("device-link version {} is unsupported", wire.version),
            ));
        }
        let mut spaces = wire.spaces;
        spaces.sort_unstable();
        let original_len = spaces.len();
        spaces.dedup();
        if spaces.len() != original_len {
            return Err(Error::new(
                ErrorCode::InvalidData,
                "device-link context contains a duplicate space",
            ));
        }
        Ok(Self { spaces })
    }
}

#[derive(Deserialize, Serialize)]
struct WireDeviceLink {
    version: u8,
    spaces: Vec<SpaceId>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linked_spaces_round_trip_in_stable_order() {
        let first = SpaceId::from_u128(1);
        let second = SpaceId::from_u128(2);
        let link = DeviceLink::new().with_space(second).with_space(first);
        assert_eq!(DeviceLink::decode(&link.encode().unwrap()).unwrap(), link);
        assert_eq!(link.spaces(), &[first, second]);
    }

    #[test]
    fn unknown_link_versions_fail_closed() {
        assert!(DeviceLink::decode(br#"{"version":2,"spaces":[]}"#).is_err());
    }
}
