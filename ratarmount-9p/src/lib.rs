//! Userspace 9P2000.L TCP export of a [`ratarmount_core::MountSource`].
//!
//! Listen on `127.0.0.1:20493` (unprivileged; well-known 564 is residual).
//! Guest mount:
//!
//! ```text
//! mount -t 9p -o trans=tcp,port=20493,version=9p2000.L 127.0.0.1 /mnt
//! ```
//!
//! CLI `--ninep` / `--ninep-bind` are wired in the binary (PR-12), not this crate.
//! Writes (`Tlcreate` / `Twrite` / `Tmkdir` / `Tunlinkat` / `Trenameat` /
//! `Tsymlink`) require a [`WriteOverlay`] (`-w`); otherwise the server returns
//! `EROFS`.
//!
//! **Residual: virtio-9p / vhost-user-9p.** Those need a QEMU `virtio-9p-pci`
//! device or a vhost-user socket, not a second VFS. TCP `trans=tcp` is the v1
//! transport. Skip live QEMU in crate tests.

mod proto;
mod serve;
mod vfs;

pub use ratarmount_compositing::WriteOverlay;
pub use ratarmount_export_core::{
    fill_read, BindError, ExportServerHandle, ExportStop, DEFAULT_NINEP_PORT, DEFAULT_READER_SLOTS,
};
pub use serve::{
    parse_ninep_bind, serve_blocking, spawn_ninep_thread, NinepOptions, DEFAULT_NINEP_BIND,
};
pub use vfs::Ratarmount9p;
