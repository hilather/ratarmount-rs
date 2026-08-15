//! Feature-gated NFSv4.1 export (`embednfs` 0.4.1).
//!
//! `MountSource` adapter + bind/serve. `-w` overlay create/write/mkdir/remove
//! /setattr-size match v3; rename and create_symlink stay `ReadOnly`.
//! Linux kernel `mount -t nfs` remains unverified (unprivileged CI).

mod adapter;
mod error;
mod serve;

pub use adapter::RatarmountNfs4;
pub use error::io_to_fserror;
pub use serve::{
    listen_v4_memfs_smoke, serve_v4, serve_v4_blocking, serve_v4_memfs_smoke, spawn_nfs4_thread,
};
