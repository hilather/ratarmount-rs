//! In-process NFSv3 export of a [`ratarmount_core::MountSource`].
//!
//! Userspace NFSv3 adapter. Default is read-only; `-w` overlay writes are
//! optional. The bind parser and error map live here so the CLI can validate
//! `--nfs-bind` without starting a listener.

mod bind;
mod error;
mod inode;
mod names;
mod reader;
mod serve;
mod vfs;

#[cfg(feature = "nfsv4")]
mod v4;

#[cfg(feature = "nfsv4")]
pub use v4::{listen_v4_memfs_smoke, serve_v4_memfs_smoke};

pub use bind::{nfs_bind_string, parse_nfs_bind, BindError, DEFAULT_NFS_BIND};
pub use error::io_to_nfsstat3;
pub use inode::ROOT_FILEID;
pub use nfsserve::nfs::nfsstat3;
pub use reader::{fill_read_for_nfs, DEFAULT_READER_SLOTS};
pub use serve::{
    bind_nfs, serve, serve_blocking, serve_listener, spawn_nfs_thread, NfsOptions, NfsServerHandle,
    NfsStop,
};
pub use vfs::RatarmountNfs;

/// Default NFSv3 listen port (unprivileged; clients must pass `port=` / `mountport=`).
pub const DEFAULT_NFS_PORT: u16 = 20490;
