//! Userspace SFTP export of a [`ratarmount_core::MountSource`] (P-10).
//!
//! Listen on `127.0.0.1:20222` (unprivileged; well-known 22 is residual).
//! CLI `--sftp` / `--sftp-bind` are wired in the binary (PR-12), not this crate.
//!
//! **MSRV spike (PR-11):** current `russh` 0.62+ declares `rust-version = "1.85"`
//! (edition 2024). Workspace MSRV is **1.74**, so the SSH-2 daemon is optional
//! feature `sftp-russh` (same pattern as `nfsv4`). Default `cargo test` does
//! **not** compile russh. `--sftp` (PR-12) should exit 2 with
//! [`SFTP_RUSSH_HINT`] unless the feature is on. Linux/macOS packages enable
//! the feature. SSH-2 is **not** implemented in this crate.
//!
//! Auth: `RATARMOUNT_SFTP_AUTHORIZED_KEYS` (default `~/.ssh/authorized_keys`
//! **only on loopback**). Non-loopback without an explicit keys file is
//! rejected so `$HOME` keys are not exposed on `0.0.0.0`. Password residual.
//! Host key: `RATARMOUNT_SFTP_HOST_KEY` or ephemeral ed25519.
//!
//! Residual: `--sftp-subsystem` stdio `sftp-server` (TCP listener is v1).

mod auth;
mod serve;
mod vfs;

#[cfg(feature = "sftp-russh")]
mod handler;

pub use auth::{
    authorized_keys_from_env, host_key_from_env, parse_authorized_keys, resolve_authorized_keys,
    AuthPolicyError, AuthorizedKeysSource,
};
pub use ratarmount_compositing::WriteOverlay;
pub use ratarmount_export_core::{
    fill_read, BindError, ExportServerHandle, ExportStop, DEFAULT_READER_SLOTS, DEFAULT_SFTP_PORT,
};
pub use serve::{
    parse_sftp_bind, serve_blocking, sftp_russh_compiled, spawn_sftp_thread, SftpOptions,
    DEFAULT_SFTP_BIND, SFTP_RUSSH_HINT,
};
pub use vfs::RatarmountSftp;

#[cfg(test)]
mod tests;
