use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use ulid::Ulid;

macro_rules! define_id {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(
            Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
        )]
        #[serde(transparent)]
        pub struct $name(Ulid);

        impl $name {
            /// Generates a new lexicographically sortable identifier.
            pub fn new() -> Self {
                Self(Ulid::new())
            }

            /// Restores an identifier from its 128-bit representation.
            pub const fn from_u128(value: u128) -> Self {
                Self(Ulid::from_parts(
                    (value >> 80) as u64,
                    value & ((1_u128 << 80) - 1),
                ))
            }

            /// Returns the identifier as an unsigned integer.
            pub const fn as_u128(self) -> u128 {
                self.0.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = ulid::DecodeError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                value.parse().map(Self)
            }
        }
    };
}

define_id!(AppId, "A stable identifier for an application namespace.");
define_id!(SpaceId, "A stable identifier for a Cyrene space.");
define_id!(DocumentId, "A stable identifier for a typed document.");
define_id!(ReplicaId, "A stable identifier for one durable replica.");

#[cfg(test)]
mod tests {
    use super::DocumentId;

    #[test]
    fn identifiers_round_trip_through_text() {
        let id = DocumentId::new();
        assert_eq!(id.to_string().parse(), Ok(id));
    }
}
