//! Feature-gated NFSv4.1 spike (`embednfs` 0.4.1).
//!
//! PR 2 only proves bind + `NfsStop` + an unprivileged EXCHANGE_ID smoke
//! against `MemFs`. There is no `MountSource` adapter and no NFS4 codec.

mod serve;

pub use serve::{listen_v4_memfs_smoke, serve_v4_memfs_smoke};
