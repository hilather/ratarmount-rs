//! Blocking index build. `IndexJob::run` is not implemented in this skeleton.

/// Cold index-build handle. Engine stays blocking; the embedder owns threads /
/// `job_id`.
///
/// There is no `IndexJob::start` / `Session::from_open`. `run` lands later.
pub struct IndexJob;
