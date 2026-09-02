/// The durable schema identity of a typed document.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Schema {
    /// Stable logical name of the document type.
    pub name: &'static str,
    /// Application-controlled schema version.
    pub version: u32,
    /// Deterministic fingerprint of field IDs, names, and Rust type tokens.
    pub fingerprint: u64,
    /// Fields known by this schema version.
    pub fields: &'static [FieldSchema],
}

/// Durable metadata for one document field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FieldSchema {
    /// Stable numeric field identity.
    pub id: u32,
    /// Current source-level field name.
    pub name: &'static str,
    /// Rust type tokens used for development-time compatibility checks.
    pub rust_type: &'static str,
}
