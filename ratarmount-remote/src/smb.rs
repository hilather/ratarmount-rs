//! SMB/CIFS download-to-temp for `smb://` URLs.
//!
//! Pure-Rust SMB stacks are heavy (async runtimes, large dependency trees). This
//! module provides robust URL parsing and downloads via the Samba `smbclient`
//! CLI when available. Without `smbclient` on `PATH`, callers get a clear
//! install hint.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use log::debug;
use tempfile::NamedTempFile;
use url::Url;

use crate::{RemoteError, Result};

/// Parsed SMB location (`smb://[user[:pass]@]host[:port]/share/path`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmbLocation {
    pub host: String,
    /// SMB port (default 445).
    pub port: u16,
    /// Share name (first path segment after host).
    pub share: String,
    /// Path within the share (no leading slash; may be empty for share root).
    pub path: String,
    pub user: Option<String>,
    pub password: Option<String>,
    /// Optional Windows domain (from `DOMAIN;user` / `DOMAIN\user` userinfo).
    pub domain: Option<String>,
}

impl SmbLocation {
    /// UNC-style path for messaging: `//host/share/path`.
    pub fn unc_share(&self) -> String {
        format!("//{}/{}", self.host, self.share)
    }

    /// Path argument for `smbclient get` (forward slashes, no leading slash).
    pub fn remote_get_path(&self) -> &str {
        &self.path
    }
}

/// Parse `smb://[domain;]user[:pass]@host[:port]/share[/path…]`.
///
/// Path rules:
/// - First hierarchical segment after host is the **share**.
/// - Remaining segments are the path inside the share.
/// - Userinfo may encode a domain as `DOMAIN;user` or `DOMAIN\user` (URL-encoded
///   backslash is `%5C`).
pub fn parse_smb_url(url_str: &str) -> Result<SmbLocation> {
    let url = Url::parse(url_str).map_err(|e| RemoteError::Url(e.to_string()))?;
    if url.scheme() != "smb" {
        return Err(RemoteError::UnsupportedScheme(url.scheme().to_string()));
    }
    let host = url
        .host_str()
        .ok_or_else(|| RemoteError::Url("smb URL missing host".into()))?
        .to_string();
    let port = url.port().unwrap_or(445);

    // `url` may leave `;` / `\` percent-encoded in userinfo (`%3B`, `%5C`).
    let raw_user = if url.username().is_empty() {
        None
    } else {
        Some(percent_decode_userinfo(url.username()))
    };
    let (user, domain) = split_user_domain(raw_user);
    let password = url.password().map(percent_decode_userinfo);

    // url.path() is `/share` or `/share/dir/file` (leading slash).
    let raw = url.path().trim_start_matches('/');
    if raw.is_empty() {
        return Err(RemoteError::Url(
            "smb URL missing share (expected smb://host/share[/path])".into(),
        ));
    }
    let (share, path) = match raw.split_once('/') {
        Some((share, rest)) => (share.to_string(), rest.to_string()),
        None => (raw.to_string(), String::new()),
    };
    if share.is_empty() {
        return Err(RemoteError::Url("smb URL missing share name".into()));
    }

    Ok(SmbLocation {
        host,
        port,
        share,
        path,
        user,
        password,
        domain,
    })
}

/// Minimal percent-decoder for userinfo (`%XX` → byte). Invalid sequences kept as-is.
fn percent_decode_userinfo(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (from_hex(bytes[i + 1]), from_hex(bytes[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn from_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Split `DOMAIN;user` / `DOMAIN\user` into (user, Some(domain)).
fn split_user_domain(username: Option<String>) -> (Option<String>, Option<String>) {
    let Some(raw) = username else {
        return (None, None);
    };
    if let Some((dom, user)) = raw.split_once(';') {
        if !dom.is_empty() && !user.is_empty() {
            return (Some(user.to_string()), Some(dom.to_string()));
        }
    }
    if let Some((dom, user)) = raw.split_once('\\') {
        if !dom.is_empty() && !user.is_empty() {
            return (Some(user.to_string()), Some(dom.to_string()));
        }
    }
    (Some(raw), None)
}

/// Build argv for `smbclient //host/share … -c 'get remote local'`.
///
/// Exposed for unit tests (mock runners compare against this shape).
pub fn smbclient_download_args(loc: &SmbLocation, dest: &Path) -> Vec<String> {
    let mut args = vec![loc.unc_share(), "-p".into(), loc.port.to_string()];

    // Auth: URL credentials, then env password, else guest (`-N`, no prompt).
    if let Some(user) = loc.user.as_deref() {
        // `user%` / `user%pass` avoids interactive password prompts.
        let cred = match loc.password.as_deref() {
            Some(pw) => format!("{user}%{pw}"),
            None => format!("{user}%"),
        };
        args.push("-U".into());
        args.push(cred);
    } else if let Ok(pw) = std::env::var("RATARMOUNT_SMB_PASSWORD") {
        let user = std::env::var("RATARMOUNT_SMB_USER")
            .or_else(|_| std::env::var("USER"))
            .unwrap_or_else(|_| "guest".into());
        args.push("-U".into());
        args.push(format!("{user}%{pw}"));
    } else {
        args.push("-N".into());
    }

    if let Some(domain) = loc.domain.as_deref() {
        args.push("-W".into());
        args.push(domain.to_string());
    }

    // smbclient accepts forward slashes for the remote path.
    let remote = loc.path.replace('\\', "/");
    let dest_s = dest.to_string_lossy();
    let cmd = format!("get \"{remote}\" \"{dest_s}\"");
    args.push("-c".into());
    args.push(cmd);
    args
}

/// Locate `smbclient` on PATH.
pub fn find_smbclient() -> Option<PathBuf> {
    which_bin("smbclient")
}

fn which_bin(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            // On Unix, check executable bit lightly via metadata when possible.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = candidate.metadata() {
                    if meta.permissions().mode() & 0o111 == 0 {
                        continue;
                    }
                }
            }
            return Some(candidate);
        }
        // Windows: also try .exe
        #[cfg(windows)]
        {
            let exe = dir.join(format!("{name}.exe"));
            if exe.is_file() {
                return Some(exe);
            }
        }
    }
    None
}

/// Download via `smbclient` into a tempfile.
pub fn fetch_smb_to_temp(url_str: &str) -> Result<(NamedTempFile, u64)> {
    let loc = parse_smb_url(url_str)?;
    fetch_smb_location_to_temp(&loc)
}

pub fn fetch_smb_location_to_temp(loc: &SmbLocation) -> Result<(NamedTempFile, u64)> {
    fetch_smb_location_to_temp_with(loc, run_smbclient_get)
}

/// Injectable runner for tests: write the remote file to `dest`, return byte count.
pub fn fetch_smb_location_to_temp_with<F>(
    loc: &SmbLocation,
    runner: F,
) -> Result<(NamedTempFile, u64)>
where
    F: FnOnce(&SmbLocation, &Path) -> Result<u64>,
{
    if loc.path.is_empty() {
        return Err(RemoteError::Smb(
            "smb URL must include a file path under the share (smb://host/share/path/to/file)"
                .into(),
        ));
    }
    let tmp = NamedTempFile::new()?;
    let dest = tmp.path().to_path_buf();
    // Runner writes via a separate open of `dest` (smbclient does the same).
    let reported = runner(loc, &dest)?;
    let size = std::fs::metadata(&dest)?.len();
    if reported != 0 && reported != size {
        debug!("smb runner reported {reported} bytes, file size is {size}");
    }
    Ok((tmp, size))
}

/// Default runner: invoke real `smbclient`.
pub fn run_smbclient_get(loc: &SmbLocation, dest: &Path) -> Result<u64> {
    let bin = find_smbclient().ok_or_else(|| {
        RemoteError::Smb(
            "smbclient not found on PATH; install Samba client tools \
             (e.g. `apt install smbclient` / `dnf install samba-client`) to fetch smb:// URLs"
                .into(),
        )
    })?;

    let args = smbclient_download_args(loc, dest);
    debug!(
        "smbclient {} {}",
        bin.display(),
        redact_smbclient_args(&args).join(" ")
    );

    let output = Command::new(&bin)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| RemoteError::Smb(format!("failed to spawn smbclient: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let detail = if !stderr.trim().is_empty() {
            stderr.trim().to_string()
        } else {
            stdout.trim().to_string()
        };
        return Err(RemoteError::Smb(format!(
            "smbclient failed for {}/{}: {detail}",
            loc.unc_share(),
            loc.path
        )));
    }

    let meta = std::fs::metadata(dest).map_err(|e| {
        RemoteError::Smb(format!(
            "smbclient reported success but {} missing: {e}",
            dest.display()
        ))
    })?;
    if meta.len() == 0 {
        // Empty file may be valid; only error if stderr hints at NT status issues.
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.to_ascii_lowercase().contains("nt_status") {
            return Err(RemoteError::Smb(format!(
                "smbclient empty result for {}/{}: {}",
                loc.unc_share(),
                loc.path,
                stderr.trim()
            )));
        }
    }
    Ok(meta.len())
}

/// Redact `user%password` after `-U` for logs.
fn redact_smbclient_args(args: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len());
    let mut redact_next = false;
    for a in args {
        if redact_next {
            if let Some((u, _)) = a.split_once('%') {
                out.push(format!("{u}%***"));
            } else {
                out.push("***".into());
            }
            redact_next = false;
        } else {
            redact_next = a == "-U";
            out.push(a.clone());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[test]
    fn parse_basic() {
        let loc = parse_smb_url("smb://fileserver/backups/archives/a.tar").unwrap();
        assert_eq!(loc.host, "fileserver");
        assert_eq!(loc.port, 445);
        assert_eq!(loc.share, "backups");
        assert_eq!(loc.path, "archives/a.tar");
        assert!(loc.user.is_none());
        assert!(loc.password.is_none());
        assert!(loc.domain.is_none());
        assert_eq!(loc.unc_share(), "//fileserver/backups");
    }

    #[test]
    fn parse_auth_port_and_domain_semicolon() {
        let loc =
            parse_smb_url("smb://CORP;alice:s3cret@nas.example:1445/data/iso/x.iso").unwrap();
        assert_eq!(loc.host, "nas.example");
        assert_eq!(loc.port, 1445);
        assert_eq!(loc.share, "data");
        assert_eq!(loc.path, "iso/x.iso");
        assert_eq!(loc.user.as_deref(), Some("alice"));
        assert_eq!(loc.password.as_deref(), Some("s3cret"));
        assert_eq!(loc.domain.as_deref(), Some("CORP"));
    }

    #[test]
    fn parse_domain_backslash() {
        // url crate: backslash in userinfo may need encoding; percent-encoded works.
        let loc = parse_smb_url("smb://CORP%5Cbob:pw@host/share/f.bin").unwrap();
        assert_eq!(loc.user.as_deref(), Some("bob"));
        assert_eq!(loc.domain.as_deref(), Some("CORP"));
        assert_eq!(loc.password.as_deref(), Some("pw"));
        assert_eq!(loc.share, "share");
        assert_eq!(loc.path, "f.bin");
    }

    #[test]
    fn parse_share_only_path_empty() {
        let loc = parse_smb_url("smb://host/myshare").unwrap();
        assert_eq!(loc.share, "myshare");
        assert!(loc.path.is_empty());
    }

    #[test]
    fn parse_rejects_missing_share() {
        let err = parse_smb_url("smb://hostonly").unwrap_err();
        assert!(err.to_string().contains("share") || err.to_string().contains("url"));
    }

    #[test]
    fn parse_rejects_other_scheme() {
        let err = parse_smb_url("http://x/y").unwrap_err();
        assert!(matches!(err, RemoteError::UnsupportedScheme(_)));
    }

    #[test]
    fn smbclient_args_with_auth() {
        let loc = SmbLocation {
            host: "h".into(),
            port: 445,
            share: "s".into(),
            path: "dir/file.tar".into(),
            user: Some("u".into()),
            password: Some("p".into()),
            domain: Some("D".into()),
        };
        let dest = Path::new("/tmp/out.bin");
        let args = smbclient_download_args(&loc, dest);
        assert_eq!(args[0], "//h/s");
        assert!(args.contains(&"-p".into()));
        assert!(args.contains(&"445".into()));
        assert!(args.contains(&"-U".into()));
        assert!(args.contains(&"u%p".into()));
        assert!(args.contains(&"-W".into()));
        assert!(args.contains(&"D".into()));
        assert!(args.contains(&"-c".into()));
        let c = args.iter().position(|a| a == "-c").unwrap();
        assert!(args[c + 1].contains("get "));
        assert!(args[c + 1].contains("dir/file.tar"));
        assert!(args[c + 1].contains("/tmp/out.bin"));
        // Guest -N should not appear when -U is used.
        assert!(!args.iter().any(|a| a == "-N"));
    }

    #[test]
    fn smbclient_args_guest() {
        let loc = SmbLocation {
            host: "h".into(),
            port: 445,
            share: "pub".into(),
            path: "a.tar".into(),
            user: None,
            password: None,
            domain: None,
        };
        let args = smbclient_download_args(&loc, Path::new("/tmp/x"));
        assert!(args.contains(&"-N".into()));
        assert!(!args.contains(&"-U".into()));
    }

    #[test]
    fn fetch_with_mock_runner() {
        let loc = parse_smb_url("smb://mockhost/share/nested/a.tar").unwrap();
        let body = b"smb-mock-file-body";
        let calls = Arc::new(AtomicUsize::new(0));
        let calls2 = Arc::clone(&calls);
        let (tmp, size) = fetch_smb_location_to_temp_with(&loc, move |l, dest| {
            calls2.fetch_add(1, Ordering::SeqCst);
            assert_eq!(l.share, "share");
            assert_eq!(l.path, "nested/a.tar");
            // Mimic smbclient: write through a fresh open of the dest path.
            std::fs::write(dest, body).map_err(RemoteError::Io)?;
            Ok(body.len() as u64)
        })
        .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(size, body.len() as u64);
        let from_path = std::fs::read(tmp.path()).unwrap();
        assert_eq!(from_path, body);
    }

    #[test]
    fn redact_hides_password() {
        let redacted = redact_smbclient_args(&[
            "//h/s".into(),
            "-U".into(),
            "alice:s3cret".into(), // no % form
            "-U".into(),
            "alice%s3cret".into(),
        ]);
        assert_eq!(redacted[2], "***");
        assert_eq!(redacted[4], "alice%***");
    }

    #[test]
    fn fetch_rejects_empty_file_path() {
        let loc = parse_smb_url("smb://host/shareonly").unwrap();
        let err = fetch_smb_location_to_temp_with(&loc, |_l, _d| Ok(0)).unwrap_err();
        assert!(err.to_string().contains("file path") || err.to_string().contains("smb"));
    }

    #[test]
    fn missing_smbclient_error_is_clear() {
        // Only run the real runner check if smbclient is truly absent; otherwise
        // skip the "not found" assertion (CI may have samba-client installed).
        if find_smbclient().is_some() {
            return;
        }
        let loc = parse_smb_url("smb://no-such-host.invalid/share/a.tar").unwrap();
        let err = run_smbclient_get(&loc, Path::new("/tmp/ratarmount-smb-test-dest")).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("smbclient") && (msg.contains("install") || msg.contains("not found")),
            "unexpected message: {msg}"
        );
    }
}
