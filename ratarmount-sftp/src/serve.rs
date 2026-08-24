//! Bind / serve / stop. Tokio Runtime lives **inside** this crate when
//! `sftp-russh` is on (`main.rs` must not name tokio).

use std::io::{self, ErrorKind};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::sync::Arc;

use ratarmount_compositing::WriteOverlay;
use ratarmount_core::MountSource;
use ratarmount_export_core::{
    default_export_bind, parse_export_bind, BindError, ExportServerHandle, ExportStop,
    DEFAULT_READER_SLOTS, DEFAULT_SFTP_PORT,
};

use crate::auth::{
    authorized_keys_from_env, host_key_from_env, resolve_authorized_keys, AuthPolicyError,
};
use crate::vfs::RatarmountSftp;

/// Rebuild hint when the binary was not compiled with russh (PR-12 maps to exit 2).
pub const SFTP_RUSSH_HINT: &str =
    "rebuild with --features sftp-russh (russh MSRV 1.85 > workspace 1.74)";

/// `127.0.0.1:20222` — empty-string result of [`parse_sftp_bind`].
pub const DEFAULT_SFTP_BIND: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, DEFAULT_SFTP_PORT));

/// Listen / export options for [`serve_blocking`] / [`spawn_sftp_thread`].
#[derive(Clone)]
pub struct SftpOptions {
    pub bind: SocketAddr,
    pub stop: Option<ExportStop>,
    /// When set, OPEN-write / MKDIR / REMOVE / RENAME / SETSTAT-size go here.
    pub overlay: Option<Arc<WriteOverlay>>,
    pub readahead_bytes: usize,
    pub reader_slots: usize,
    /// `--sftp-authorized-keys`. `None` → env, then loopback `$HOME` default.
    pub authorized_keys: Option<PathBuf>,
    /// `RATARMOUNT_SFTP_HOST_KEY`. `None` → env, then ephemeral ed25519.
    pub host_key: Option<PathBuf>,
}

impl Default for SftpOptions {
    fn default() -> Self {
        Self {
            bind: default_export_bind(DEFAULT_SFTP_PORT),
            stop: None,
            overlay: None,
            readahead_bytes: 0,
            reader_slots: DEFAULT_READER_SLOTS,
            authorized_keys: None,
            host_key: None,
        }
    }
}

impl std::fmt::Debug for SftpOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SftpOptions")
            .field("bind", &self.bind)
            .field("stop", &self.stop.as_ref().map(|_| "ExportStop"))
            .field("overlay", &self.overlay.is_some())
            .field("readahead_bytes", &self.readahead_bytes)
            .field("reader_slots", &self.reader_slots)
            .field("authorized_keys", &self.authorized_keys)
            .field("host_key", &self.host_key)
            .finish()
    }
}

/// Parse `[host:]port` into an IPv4 listen address (default port 20222).
pub fn parse_sftp_bind(s: &str) -> Result<SocketAddr, BindError> {
    parse_export_bind(s, DEFAULT_SFTP_PORT)
}

/// `true` when this crate was built with russh (SSH-2 daemon present).
pub fn sftp_russh_compiled() -> bool {
    cfg!(feature = "sftp-russh")
}

#[cfg_attr(not(feature = "sftp-russh"), allow(dead_code))]
fn access_label(opts: &SftpOptions) -> &'static str {
    if opts.overlay.is_some() {
        "rw overlay"
    } else {
        "ro"
    }
}

#[cfg_attr(not(feature = "sftp-russh"), allow(dead_code))]
pub(crate) fn fs_from_opts(
    source: Arc<dyn MountSource>,
    opts: &SftpOptions,
) -> Arc<RatarmountSftp> {
    Arc::new(RatarmountSftp::with_overlay(
        source,
        opts.readahead_bytes,
        opts.reader_slots,
        opts.overlay.clone(),
    ))
}

pub(crate) fn resolved_authorized_keys(
    opts: &SftpOptions,
) -> Result<crate::auth::AuthorizedKeysSource, AuthPolicyError> {
    let explicit = opts
        .authorized_keys
        .clone()
        .or_else(authorized_keys_from_env);
    resolve_authorized_keys(opts.bind, explicit.as_deref())
}

#[cfg_attr(not(feature = "sftp-russh"), allow(dead_code))]
pub(crate) fn resolved_host_key(opts: &SftpOptions) -> Option<PathBuf> {
    opts.host_key.clone().or_else(host_key_from_env)
}

fn warn_non_loopback(addr: SocketAddr) {
    if !addr.ip().is_loopback() {
        log::warn!(
            "SFTP bind {addr} is not loopback; public-key auth is the security boundary (password residual)"
        );
    }
}

fn reject_v6(addr: SocketAddr) -> io::Result<()> {
    if addr.is_ipv6() {
        Err(io::Error::new(
            ErrorKind::AddrNotAvailable,
            BindError::Ipv6Unsupported.to_string(),
        ))
    } else {
        Ok(())
    }
}

fn feature_required() -> io::Error {
    io::Error::new(ErrorKind::Unsupported, SFTP_RUSSH_HINT)
}

/// SFTP-only: this thread owns bind + (when compiled) the russh Runtime.
pub fn serve_blocking(source: Arc<dyn MountSource>, opts: SftpOptions) -> io::Result<()> {
    reject_v6(opts.bind)?;
    warn_non_loopback(opts.bind);
    let keys = resolved_authorized_keys(&opts)?;
    if !sftp_russh_compiled() {
        return Err(feature_required());
    }
    #[cfg(feature = "sftp-russh")]
    {
        crate::handler::serve_russh_blocking(source, opts, keys)
    }
    #[cfg(not(feature = "sftp-russh"))]
    {
        let _ = (source, keys);
        Err(feature_required())
    }
}

/// FUSE+SFTP: dedicated thread. Returns after bind (or immediately on error).
pub fn spawn_sftp_thread(
    source: Arc<dyn MountSource>,
    opts: SftpOptions,
) -> io::Result<ExportServerHandle> {
    reject_v6(opts.bind)?;
    warn_non_loopback(opts.bind);
    let keys = resolved_authorized_keys(&opts)?;
    if !sftp_russh_compiled() {
        return Err(feature_required());
    }
    #[cfg(feature = "sftp-russh")]
    {
        crate::handler::spawn_russh_thread(source, opts, keys)
    }
    #[cfg(not(feature = "sftp-russh"))]
    {
        let _ = (source, keys);
        Err(feature_required())
    }
}

#[cfg_attr(not(feature = "sftp-russh"), allow(dead_code))]
pub(crate) fn log_listen(addr: SocketAddr, opts: &SftpOptions) {
    let access = access_label(opts);
    let ip = addr.ip();
    let port = addr.port();
    log::info!(
        "SFTP listening on {ip}:{port} ({access}). client: sftp -P {port} -o StrictHostKeyChecking=no {ip}"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::net::Ipv4Addr;

    use ratarmount_core::{create_root_file_info, FileInfo, ListResult};

    struct EmptyFs;
    impl MountSource for EmptyFs {
        fn list(&self, path: &str) -> Option<ListResult> {
            if path == "/" {
                Some(ListResult::Names(Vec::new()))
            } else {
                None
            }
        }
        fn lookup(&self, path: &str, _: i32) -> Option<FileInfo> {
            if path == "/" {
                Some(create_root_file_info())
            } else {
                None
            }
        }
        fn open(&self, _: &FileInfo, _: i32) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
            Ok(Box::new(Cursor::new(Vec::<u8>::new())))
        }
        fn is_immutable(&self) -> bool {
            true
        }
    }

    #[test]
    fn parse_sftp_bind_defaults_to_20222() {
        let a = parse_sftp_bind("").unwrap();
        assert_eq!(a.port(), 20222);
        assert_eq!(a, DEFAULT_SFTP_BIND);
        assert_ne!(a.port(), 20490);
        assert_eq!(
            parse_sftp_bind("0.0.0.0:0").unwrap(),
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
        );
    }

    /// Regression: non-loopback without keys file is rejected before listen.
    #[test]
    fn regression_non_loopback_without_keys_file_exits() {
        let opts = SftpOptions {
            bind: SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            authorized_keys: None,
            ..SftpOptions::default()
        };
        // Hermetic: if the process env has RATARMOUNT_SFTP_AUTHORIZED_KEYS the
        // policy allows start (then feature-gate may still fail). Clear via
        // resolve_authorized_keys(None) which this opts path uses only when env
        // is unset — still assert the policy helper, and serve when env is empty.
        if authorized_keys_from_env().is_some() {
            let err = resolve_authorized_keys(opts.bind, None).unwrap_err();
            assert_eq!(err, AuthPolicyError::NonLoopbackNeedsKeys);
            return;
        }
        let err = serve_blocking(Arc::new(EmptyFs), opts).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("authorized-keys")
                || msg.contains("AUTHORIZED_KEYS")
                || msg.contains("loopback"),
            "{msg}"
        );
        assert_eq!(err.kind(), ErrorKind::PermissionDenied);
    }

    #[test]
    fn serve_without_russh_is_rebuild_hint() {
        if sftp_russh_compiled() {
            return;
        }
        let opts = SftpOptions {
            bind: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            authorized_keys: Some(std::path::PathBuf::from("/dev/null")),
            ..SftpOptions::default()
        };
        let err = serve_blocking(Arc::new(EmptyFs), opts).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Unsupported);
        assert!(err.to_string().contains("sftp-russh"), "{err}");
        assert_eq!(err.to_string(), SFTP_RUSSH_HINT);
    }

    #[test]
    fn spawn_without_russh_is_rebuild_hint() {
        if sftp_russh_compiled() {
            return;
        }
        let opts = SftpOptions {
            bind: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            authorized_keys: Some(std::path::PathBuf::from("/dev/null")),
            ..SftpOptions::default()
        };
        match spawn_sftp_thread(Arc::new(EmptyFs), opts) {
            Err(err) => assert!(err.to_string().contains("sftp-russh"), "{err}"),
            Ok(_) => panic!("spawn without sftp-russh must fail"),
        }
    }
}
