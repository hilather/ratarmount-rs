//! In-process NFS export of a [`ratarmount_core::MountSource`].
//!
//! Userspace NFSv3 adapter (default). Optional NFSv4.1 (`--features nfsv4`,
//! `--nfs-vers 4`) is read-only in this crate revision. `-w` overlay writes
//! are v3-only until the v4 overlay PR. The bind parser and error map live
//! here so the CLI can validate `--nfs-bind` / `--nfs-vers` without starting
//! a listener.

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
pub use v4::{
    io_to_fserror, listen_v4_memfs_smoke, serve_v4, serve_v4_blocking, serve_v4_memfs_smoke,
    spawn_nfs4_thread, RatarmountNfs4,
};

pub use bind::{nfs_bind_string, parse_nfs_bind, BindError, DEFAULT_NFS_BIND};
pub use error::io_to_nfsstat3;
pub use inode::ROOT_FILEID;
pub use nfsserve::nfs::nfsstat3;
pub use reader::{fill_read_for_nfs, DEFAULT_READER_SLOTS};
pub use serve::{
    bind_nfs, parse_nfs_vers, serve, serve_blocking, serve_listener, spawn_nfs_thread, NfsOptions,
    NfsServerHandle, NfsStop, NfsVers, NfsVersError,
};
pub use vfs::RatarmountNfs;

/// Default NFSv3 listen port (unprivileged; clients must pass `port=` / `mountport=`).
pub const DEFAULT_NFS_PORT: u16 = 20490;
