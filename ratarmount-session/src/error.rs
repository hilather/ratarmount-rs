//! Session engine errors. Never includes `Busy`.

use std::path::PathBuf;

use thiserror::Error;

/// Errors returned by the Session engine.
///
/// The engine never emits `Busy`. Retryable variants are [`Self::NotWritable`]
/// and [`Self::SiblingNotWritable`].
#[derive(Debug, Error)]
pub enum Error {
    #[error("not found")]
    NotFound,
    #[error("sibling directory is not writable: {0}")]
    SiblingNotWritable(PathBuf),
    #[error("not writable: {0}")]
    NotWritable(PathBuf),
    #[error("password rejected or required")]
    BadPassword,
    #[error("unsupported format")]
    UnsupportedFormat(String),
    #[error("corrupt or mismatched index")]
    CorruptIndex(String),
    #[error("cancelled")]
    Cancelled,
    #[error("member path escapes destination")]
    PathEscape(String),
    #[error("{0}")]
    Internal(String),
}
