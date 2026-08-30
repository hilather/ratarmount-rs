//! Blocking [`Session`] façade: `open`, listing, read, extract, find.

/// Blocking, `Send + Sync` façade over an archive.
///
/// Embedders share a session with [`std::sync::Arc`]. This type does **not**
/// implement [`Clone`]. `Drop` is the close API (no `close(self)`).
pub struct Session {
    #[allow(dead_code)]
    _private: (),
}

impl Session {
    #[cfg(test)]
    pub(crate) fn stub() -> Self {
        Self { _private: () }
    }
}
