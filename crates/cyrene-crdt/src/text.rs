use std::fmt;

use cyrene_core::Result;
use serde::{Deserialize, Serialize};

use crate::{Actor, Apply, List, ListOp};

/// One commutative operation over merge-aware [`Text`].
pub type TextOp = ListOp<char>;

/// Unicode-scalar text that preserves concurrent insertions and observed
/// deletions.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Text {
    characters: List<char>,
}

impl Text {
    /// Creates empty text.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of visible Unicode scalar values.
    pub fn len(&self) -> usize {
        self.characters.len()
    }

    /// Returns whether the text contains no visible characters.
    pub fn is_empty(&self) -> bool {
        self.characters.is_empty()
    }

    /// Inserts `value` before the visible character at `index`.
    ///
    /// Indexes count Unicode scalar values, not UTF-8 bytes or grapheme
    /// clusters.
    ///
    /// # Errors
    ///
    /// Returns an error for an out-of-bounds index, exhausted actor counter, or
    /// operation-ID collision. Earlier inserted characters remain applied if a
    /// later character fails.
    pub fn insert(
        &mut self,
        actor: &mut Actor,
        mut index: usize,
        value: &str,
    ) -> Result<Vec<TextOp>> {
        let mut operations = Vec::with_capacity(value.chars().count());
        for character in value.chars() {
            operations.push(self.characters.insert(actor, index, character)?);
            index += 1;
        }
        Ok(operations)
    }

    /// Deletes `count` visible Unicode scalar values beginning at `index`.
    ///
    /// # Errors
    ///
    /// Returns an error if the requested range is not fully visible, the actor
    /// counter is exhausted, or an operation ID collides. Earlier deletions
    /// remain applied if a later deletion fails.
    pub fn delete(&mut self, actor: &mut Actor, index: usize, count: usize) -> Result<Vec<TextOp>> {
        if index.checked_add(count).is_none_or(|end| end > self.len()) {
            return Err(cyrene_core::Error::new(
                cyrene_core::ErrorCode::InvalidInput,
                "text deletion range is not fully visible",
            ));
        }
        (0..count)
            .map(|_| self.characters.remove(actor, index))
            .collect()
    }

    /// Applies a text operation idempotently in any delivery order.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed or colliding operation identity.
    pub fn apply(&mut self, operation: TextOp) -> Result<Apply> {
        self.characters.apply(operation)
    }

    /// Unions another replica's text state atomically.
    ///
    /// # Errors
    ///
    /// Returns an error for an operation-ID collision and leaves this value
    /// unchanged.
    pub fn merge(&mut self, other: &Self) -> Result<()> {
        self.characters.merge(&other.characters)
    }

    /// Returns all retained text operations in stable identity order.
    pub fn operations(&self) -> Vec<TextOp> {
        self.characters.operations()
    }
}

impl fmt::Display for Text {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for character in self.characters.iter() {
            character.fmt(formatter)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use cyrene_core::ReplicaId;

    use crate::{Actor, Text};

    #[test]
    fn concurrent_text_edits_merge_without_losing_either_insertion() {
        let mut first_actor = Actor::new(ReplicaId::from_u128(1));
        let mut second_actor = Actor::new(ReplicaId::from_u128(2));
        let mut first = Text::new();
        let mut second = Text::new();
        first.insert(&mut first_actor, 0, "hello").unwrap();
        second.insert(&mut second_actor, 0, "owo").unwrap();

        let mut first_then_second = first.clone();
        first_then_second.merge(&second).unwrap();
        second.merge(&first).unwrap();

        assert_eq!(first_then_second, second);
        assert_eq!(first_then_second.to_string(), "helloowo");
    }

    #[test]
    fn indexes_unicode_scalars_instead_of_utf8_bytes() {
        let mut actor = Actor::new(ReplicaId::from_u128(1));
        let mut text = Text::new();
        text.insert(&mut actor, 0, "a🦀b").unwrap();
        text.delete(&mut actor, 1, 1).unwrap();
        assert_eq!(text.to_string(), "ab");
        assert_eq!(text.len(), 2);
    }
}
