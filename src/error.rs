//! Error types shared across modules.

/// Errors that map to exit code 2 (usage / validation).
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct UsageError(pub String);
