//! [`Session`] stub. `open` / listing / read / extract / find land later.

/// Blocking, `Send + Sync` façade over an archive.
///
/// Embedders share a session with [`std::sync::Arc`]. This type does **not**
/// implement [`Clone`]. `Drop` is the close API (no `close(self)`).
///
/// I/O methods are not implemented in this skeleton:
/// `open`, `open_with_job`, `list_dirents_page`, `lookup`, `read_range`,
/// `extract_to`, `find`.
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
