//! Session engine errors. Napi may synthesize `Busy`; this enum must not.

use std::path::PathBuf;

use thiserror::Error;

/// Errors returned by the Session engine.
///
/// Engine v1 does **not** produce `Busy`. Two [`crate::IndexJob`]s on the same
/// dest use distinct `{pid}.{seq}` tmps and last `publish_tmp` wins. Napi may
/// synthesize `Busy` when its handle table already has an in-flight job.
/// Retryable: [`Self::NotWritable`], [`Self::SiblingNotWritable`].
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
