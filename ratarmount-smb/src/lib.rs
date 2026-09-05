//! Userspace SMB 2.0.2 / 3.1.1 export of a [`ratarmount_core::MountSource`] (P-2).
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
//! Guest `smbclient -N` is the unsigned v1 bar (2.1 when offered so
//! `CAP_LEASING` is on; 2.0.2-only clients stay 2.0.2 without leases). When
//! `RATARMOUNT_SMB_PASSWORD` is set, NTLMv2 is required and SMB 2.0.2
//! HMAC-SHA256 signing applies; a 3.1.1-only client also gets SHA-512 preauth
//! and optional AES-128-GCM/CCM encryption. CREATE contexts grant R/RH/WH
//! leases and durable-handle-v1 (`DHnQ` grant / `DHnC` reconnect); conflicting
//! open/write sends LEASE_BREAK. Packet tests stand in for leases +
//! preauth+encrypt; Finder and Explorer are not a CI bar. Residual: Kerberos,
//! guest encrypt, WAN, durable v2.

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
