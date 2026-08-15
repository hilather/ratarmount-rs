//! Feature-gated NFSv4.1 export (`embednfs` 0.4.1).
//!
//! Read-only `MountSource` adapter + bind/serve. Overlay writes are a later PR.
//! Linux kernel `mount -t nfs` remains unverified (unprivileged CI).

mod adapter;
mod error;
mod serve;

pub use adapter::RatarmountNfs4;
pub use error::io_to_fserror;
pub use serve::{
    listen_v4_memfs_smoke, serve_v4, serve_v4_blocking, serve_v4_memfs_smoke, spawn_nfs4_thread,
};
