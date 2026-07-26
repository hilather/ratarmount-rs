//! SFTP/SSH download-to-temp for `ssh://` and `sftp://` URLs.

use std::io::Write;
use std::net::TcpStream;
use std::path::{Path, PathBuf};

use log::debug;
use ssh2::Session;
use tempfile::NamedTempFile;
use url::Url;

use crate::{RemoteError, Result};

/// Parsed SSH/SFTP location.
#[derive(Debug, Clone)]
pub struct SshLocation {
    pub host: String,
    pub port: u16,
    pub user: Option<String>,
    pub password: Option<String>,
    /// Remote path (absolute if URL had `//` after host).
    pub path: String,
}

/// Parse `ssh://[user[:pass]@]host[:port]/path` or `sftp://…`.
///
/// Path rules (aligned with Python/fsspec):
/// - `ssh://host/rel` → relative path `rel`
/// - `ssh://host//abs` → absolute path `/abs`
pub fn parse_ssh_url(url_str: &str) -> Result<SshLocation> {
    let url = Url::parse(url_str).map_err(|e| RemoteError::Url(e.to_string()))?;
    match url.scheme() {
        "ssh" | "sftp" | "scp" => {}
        other => {
            return Err(RemoteError::UnsupportedScheme(other.to_string()));
        }
    }
    let host = url
        .host_str()
        .ok_or_else(|| RemoteError::Url("ssh URL missing host".into()))?
        .to_string();
    let port = url.port().unwrap_or(22);
    let user = if url.username().is_empty() {
        None
    } else {
        Some(url.username().to_string())
    };
    let password = url.password().map(|s| s.to_string());

    // url.path() always has a leading `/` for hierarchical URLs.
    // Double-slash after host → absolute; single → relative (strip one slash).
    let raw = url.path();
    let path = if raw.starts_with("//") {
        // ssh://host//home/user/file → /home/user/file
        raw[1..].to_string()
    } else if let Some(stripped) = raw.strip_prefix('/') {
        // ssh://host/relative/path → relative/path
        stripped.to_string()
    } else {
        raw.to_string()
    };
    if path.is_empty() {
        return Err(RemoteError::Url("ssh URL missing remote path".into()));
    }

    Ok(SshLocation {
        host,
        port,
        user,
        password,
        path,
    })
}

/// Download remote file via SFTP into a tempfile.
pub fn fetch_ssh_to_temp(url_str: &str) -> Result<(NamedTempFile, u64)> {
    let loc = parse_ssh_url(url_str)?;
    fetch_ssh_location_to_temp(&loc)
}

pub fn fetch_ssh_location_to_temp(loc: &SshLocation) -> Result<(NamedTempFile, u64)> {
    let addr = format!("{}:{}", loc.host, loc.port);
    debug!("ssh connect {addr} path={}", loc.path);

    let tcp =
        TcpStream::connect(&addr).map_err(|e| RemoteError::Ssh(format!("connect {addr}: {e}")))?;
    let mut sess = Session::new().map_err(|e| RemoteError::Ssh(e.to_string()))?;
    sess.set_tcp_stream(tcp);
    sess.handshake()
        .map_err(|e| RemoteError::Ssh(format!("handshake: {e}")))?;

    let user = loc
        .user
        .clone()
        .or_else(|| std::env::var("USER").ok())
        .or_else(|| std::env::var("LOGNAME").ok())
        .unwrap_or_else(|| "root".into());

    authenticate(&mut sess, &user, loc.password.as_deref())?;

    let sftp = sess
        .sftp()
        .map_err(|e| RemoteError::Ssh(format!("sftp: {e}")))?;
    let mut remote = sftp
        .open(Path::new(&loc.path))
        .map_err(|e| RemoteError::Ssh(format!("open {}: {e}", loc.path)))?;

    let mut tmp = NamedTempFile::new()?;
    let n = std::io::copy(&mut remote, &mut tmp)?;
    tmp.flush()?;
    Ok((tmp, n))
}

fn authenticate(sess: &mut Session, user: &str, password: Option<&str>) -> Result<()> {
    // 1) Password from URL
    if let Some(pw) = password {
        sess.userauth_password(user, pw)
            .map_err(|e| RemoteError::Ssh(format!("password auth: {e}")))?;
        if sess.authenticated() {
            return Ok(());
        }
    }

    // 2) Agent
    if let Ok(mut agent) = sess.agent() {
        if agent.connect().is_ok() && agent.list_identities().is_ok() {
            if let Ok(identities) = agent.identities() {
                for id in identities {
                    if agent.userauth(user, &id).is_ok() && sess.authenticated() {
                        return Ok(());
                    }
                }
            }
        }
    }

    // 3) Default identity files
    let home = std::env::var_os("HOME").map(PathBuf::from);
    if let Some(home) = home {
        for name in ["id_ed25519", "id_rsa", "id_ecdsa"] {
            let key = home.join(".ssh").join(name);
            if !key.exists() {
                continue;
            }
            // Try without passphrase first.
            if sess.userauth_pubkey_file(user, None, &key, None).is_ok() && sess.authenticated() {
                return Ok(());
            }
        }
    }

    // 4) Env password
    if let Ok(pw) = std::env::var("RATARMOUNT_SSH_PASSWORD") {
        sess.userauth_password(user, &pw)
            .map_err(|e| RemoteError::Ssh(format!("password auth (env): {e}")))?;
        if sess.authenticated() {
            return Ok(());
        }
    }

    Err(RemoteError::Ssh(format!(
        "SSH authentication failed for user {user:?} (tried password, agent, ~/.ssh/id_*)"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_relative_and_absolute() {
        let r = parse_ssh_url("ssh://alice@example.com/data/a.tar").unwrap();
        assert_eq!(r.host, "example.com");
        assert_eq!(r.port, 22);
        assert_eq!(r.user.as_deref(), Some("alice"));
        assert_eq!(r.path, "data/a.tar");

        let a = parse_ssh_url("sftp://bob@host:2222//home/bob/a.tar").unwrap();
        assert_eq!(a.port, 2222);
        assert_eq!(a.user.as_deref(), Some("bob"));
        assert_eq!(a.path, "/home/bob/a.tar");
    }

    #[test]
    fn parse_password() {
        let r = parse_ssh_url("ssh://u:secret@h//tmp/x").unwrap();
        assert_eq!(r.password.as_deref(), Some("secret"));
        assert_eq!(r.path, "/tmp/x");
    }
}
