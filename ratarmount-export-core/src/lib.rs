//! Shared bind, stop, inode, fill-loop, and reader LRU for export crates.
//!
//! Copied from `ratarmount-nfs` (`parse_nfs_bind`, `DEFAULT_NFS_BIND`
//! `127.0.0.1:20490`, `NfsStop`, `fill_read_for_nfs`, ROOT=1) **without**
//! migrating NFS onto this crate.

mod bind;
mod fill;
mod inode;
mod overlay;
mod reader;
mod stop;

pub use bind::{
    default_export_bind, export_bind_string, parse_export_bind, BindError, DEFAULT_HTTP_PORT,
    DEFAULT_NINEP_PORT, DEFAULT_SFTP_PORT, DEFAULT_SMB_PORT, DEFAULT_WEBDAV_PORT,
};
pub use fill::fill_read;
pub use inode::{InodeTable, ROOT_FILEID};
pub use overlay::{
    io_to_errno, overlay_create_file, overlay_mkdir, overlay_rename, overlay_to_io,
    overlay_truncate, overlay_unlink,
};
pub use reader::{fill_from_state, ReaderLru, SourceReadState, DEFAULT_READER_SLOTS};
pub use stop::{ExportServerHandle, ExportStop, STOP_POLL_INTERVAL};
