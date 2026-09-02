//! Explicit merge-aware datatypes for concurrent offline editing.
//!
//! [`List`] is a replicated growable array with observed tombstones. [`Text`]
//! is its Unicode-scalar text facade. Both accept operations in any order,
//! reject operation-ID collisions, and converge after receiving the same valid
//! operation set.

mod list;
mod text;

pub use list::{Actor, Apply, List, ListOp, OpId};
pub use text::{Text, TextOp};

/// A datatype whose independently edited states can be unioned deterministically.
pub trait Merge {
    /// Merges `other` into this value atomically.
    ///
    /// # Errors
    ///
    /// Returns an error when the states contain colliding operation identities.
    fn merge(&mut self, other: &Self) -> cyrene_core::Result<()>;
}

impl<T> Merge for List<T>
where
    T: Clone + Eq,
{
    fn merge(&mut self, other: &Self) -> cyrene_core::Result<()> {
        self.merge(other)
    }
}

impl Merge for Text {
    fn merge(&mut self, other: &Self) -> cyrene_core::Result<()> {
        self.merge(other)
    }
}
