//! Blocking index build (`IndexJob::run`).

/// Cold index-build handle. Engine stays blocking; the embedder owns threads /
/// `job_id`.
///
/// There is no `IndexJob::start` / `Session::from_open`.
pub struct IndexJob;
