//! Userspace SMB 2.0.2 export of a [`ratarmount_core::MountSource`] (P-2).
//!
//! Listen on `127.0.0.1:20445` (unprivileged; well-known 445 needs root).
//! Default share name is [`DEFAULT_SMB_SHARE`] (`ratarmount`).
//!
//! ```text
//! smbclient //127.0.0.1/ratarmount -p 20445 -N
//! ```
//!
//! CLI `--smb` / `--smb-bind` / `--smb-share` are wired in the binary (PR-12),
//! not this crate. Overlay writes (`CREATE`/`WRITE`/`SET_INFO`/`DELETE`)
//! require a [`WriteOverlay`] (`-w`); otherwise those ops return
//! `STATUS_ACCESS_DENIED`.
//!
//! **Residual: SMB signing and Finder/Explorer.** The dialect is a 2.0.2
//! subset (no message signing, no encryption, no preauth 3.1.1). Guest
//! `smbclient -N` `ls`/`get` on localhost is the v1 bar. NTLM passwords
//! (`RATARMOUNT_SMB_USER` / `RATARMOUNT_SMB_PASSWORD`) match the username
//! only — the NT response is not verified.

mod serve;
mod smb2;
mod vfs;

pub use ratarmount_compositing::WriteOverlay;
pub use ratarmount_export_core::{
    fill_read, BindError, ExportServerHandle, ExportStop, DEFAULT_READER_SLOTS, DEFAULT_SMB_PORT,
};
pub use serve::{
    parse_smb_bind, serve_blocking, smb_credentials_from_env, spawn_smb_thread, SmbOptions,
    DEFAULT_SMB_BIND, DEFAULT_SMB_SHARE,
};
pub use vfs::RatarmountSmb;

#[cfg(test)]
mod tests;
