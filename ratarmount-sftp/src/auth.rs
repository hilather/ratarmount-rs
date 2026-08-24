//! Authorized-keys policy and OpenSSH `authorized_keys` subset parser.
//!
//! Always compiled (MSRV 1.74). The russh server loads the same lines.

use std::env;
use std::fs;
use std::io::{self, ErrorKind};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// Where [`resolve_authorized_keys`] decided keys come from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthorizedKeysSource {
    /// `--sftp-authorized-keys` / `RATARMOUNT_SFTP_AUTHORIZED_KEYS`.
    Explicit(PathBuf),
    /// Loopback default: `$HOME/.ssh/authorized_keys` (file may be missing).
    HomeDefault(PathBuf),
}

/// Why SFTP auth setup refused to start.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthPolicyError {
    /// Bind is not loopback and no explicit keys file was given.
    ///
    /// Using `$HOME/.ssh/authorized_keys` on `0.0.0.0` would expose the
    /// operator's login keys on every interface.
    NonLoopbackNeedsKeys,
}

impl std::fmt::Display for AuthPolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonLoopbackNeedsKeys => write!(
                f,
                "SFTP bind is not loopback; pass --sftp-authorized-keys or RATARMOUNT_SFTP_AUTHORIZED_KEYS (refusing $HOME keys on 0.0.0.0)"
            ),
        }
    }
}

impl std::error::Error for AuthPolicyError {}

impl From<AuthPolicyError> for io::Error {
    fn from(e: AuthPolicyError) -> Self {
        io::Error::new(ErrorKind::PermissionDenied, e.to_string())
    }
}

/// `RATARMOUNT_SFTP_AUTHORIZED_KEYS` if set and non-empty.
pub fn authorized_keys_from_env() -> Option<PathBuf> {
    match env::var_os("RATARMOUNT_SFTP_AUTHORIZED_KEYS") {
        Some(p) if !p.is_empty() => Some(PathBuf::from(p)),
        _ => None,
    }
}

/// `RATARMOUNT_SFTP_HOST_KEY` if set and non-empty.
pub fn host_key_from_env() -> Option<PathBuf> {
    match env::var_os("RATARMOUNT_SFTP_HOST_KEY") {
        Some(p) if !p.is_empty() => Some(PathBuf::from(p)),
        _ => None,
    }
}

/// Pick an authorized-keys file for this bind.
///
/// * `explicit` (CLI flag / env) is always allowed, including on non-loopback.
/// * Loopback with no explicit path → `$HOME/.ssh/authorized_keys`.
/// * Non-loopback with no explicit path → [`AuthPolicyError::NonLoopbackNeedsKeys`].
pub fn resolve_authorized_keys(
    bind: SocketAddr,
    explicit: Option<&Path>,
) -> Result<AuthorizedKeysSource, AuthPolicyError> {
    if let Some(p) = explicit {
        return Ok(AuthorizedKeysSource::Explicit(p.to_path_buf()));
    }
    if bind.ip().is_loopback() {
        let mut p = env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/"));
        p.push(".ssh");
        p.push("authorized_keys");
        return Ok(AuthorizedKeysSource::HomeDefault(p));
    }
    Err(AuthPolicyError::NonLoopbackNeedsKeys)
}

/// OpenSSH `authorized_keys` subset: `ssh-ed25519` / `ssh-rsa` / `ecdsa-*`
/// lines, optional leading options. Comments and blanks skipped.
pub fn parse_authorized_keys(text: &str) -> Vec<String> {
    text.lines().filter_map(extract_key_line).collect()
}

/// Load [`parse_authorized_keys`] from a path. Missing home-default is empty.
#[cfg_attr(not(feature = "sftp-russh"), allow(dead_code))]
pub fn load_authorized_keys(src: &AuthorizedKeysSource) -> io::Result<Vec<String>> {
    let (path, missing_ok) = match src {
        AuthorizedKeysSource::Explicit(p) => (p.as_path(), false),
        AuthorizedKeysSource::HomeDefault(p) => (p.as_path(), true),
    };
    match fs::read_to_string(path) {
        Ok(text) => Ok(parse_authorized_keys(&text)),
        Err(e) if e.kind() == ErrorKind::NotFound && missing_ok => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

fn extract_key_line(line: &str) -> Option<String> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let parts: Vec<&str> = line.split_whitespace().collect();
    for i in 0..parts.len().saturating_sub(1) {
        if is_key_type(parts[i]) {
            return Some(format!("{} {}", parts[i], parts[i + 1]));
        }
    }
    None
}

fn is_key_type(tok: &str) -> bool {
    tok.starts_with("ssh-")
        || tok.starts_with("ecdsa-")
        || tok.starts_with("sk-ssh-")
        || tok.starts_with("sk-ecdsa-")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};

    fn loopback() -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, 20222))
    }

    fn any() -> SocketAddr {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 20222))
    }

    /// Regression: non-loopback without an authorized_keys file is rejected.
    #[test]
    fn regression_non_loopback_without_keys_file_rejected() {
        let err = resolve_authorized_keys(any(), None).unwrap_err();
        assert_eq!(err, AuthPolicyError::NonLoopbackNeedsKeys);
        let msg = err.to_string();
        assert!(
            msg.contains("authorized-keys") || msg.contains("AUTHORIZED_KEYS"),
            "{msg}"
        );
        assert!(msg.contains("0.0.0.0") || msg.contains("loopback"), "{msg}");
    }

    #[test]
    fn loopback_defaults_to_home_authorized_keys() {
        let src = resolve_authorized_keys(loopback(), None).unwrap();
        match src {
            AuthorizedKeysSource::HomeDefault(p) => {
                assert!(p.ends_with(".ssh/authorized_keys"), "{p:?}");
            }
            other => panic!("expected home default, got {other:?}"),
        }
    }

    #[test]
    fn explicit_path_allowed_on_non_loopback() {
        let p = Path::new("/tmp/ratarmount-sftp-keys");
        let src = resolve_authorized_keys(any(), Some(p)).unwrap();
        assert_eq!(src, AuthorizedKeysSource::Explicit(p.to_path_buf()));
    }

    #[test]
    fn parse_skips_comments_and_strips_options() {
        let text = "\
# comment
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKtfK9NJNRlP51T4TC0sB0WdCd2uRrVLv/GqdoV9fTNG test@host
from=\"1.2.3.4\" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC comment
\n";
        let keys = parse_authorized_keys(text);
        assert_eq!(keys.len(), 2);
        assert!(keys[0].starts_with("ssh-ed25519 AAAAC3Nza"));
        assert!(keys[1].starts_with("ssh-rsa AAAAB3Nza"));
        assert!(!keys[0].contains("test@host"));
        assert!(!keys[1].contains("from="));
    }

    #[test]
    fn missing_home_default_is_empty_not_error() {
        let src = AuthorizedKeysSource::HomeDefault(PathBuf::from(
            "/no/such/ratarmount-sftp-authorized_keys",
        ));
        let keys = load_authorized_keys(&src).unwrap();
        assert!(keys.is_empty());
    }
}
