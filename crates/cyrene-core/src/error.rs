use std::fmt;

/// A stable, machine-readable Cyrene error code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ErrorCode {
    /// Durable storage could not be opened or queried.
    Storage,
    /// Stored application data could not be decoded.
    InvalidData,
    /// An application or schema invariant was violated.
    InvalidInput,
}

impl ErrorCode {
    /// Returns the stable textual representation shown in diagnostics.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Storage => "CYR-STO-001",
            Self::InvalidData => "CYR-DAT-001",
            Self::InvalidInput => "CYR-APP-001",
        }
    }
}

/// An error returned by a Cyrene operation.
#[derive(Debug, thiserror::Error)]
#[error("{message} ({code})")]
pub struct Error {
    code: ErrorCode,
    message: String,
    #[source]
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl Error {
    /// Creates an error without an underlying source.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            source: None,
        }
    }

    /// Attaches an underlying error to a contextual Cyrene error.
    pub fn with_source(
        code: ErrorCode,
        message: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }

    /// Returns the stable machine-readable error code.
    pub const fn code(&self) -> ErrorCode {
        self.code
    }

    /// Returns the human-readable context without the code or source.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A result whose error is a structured Cyrene error.
pub type Result<T> = std::result::Result<T, Error>;
