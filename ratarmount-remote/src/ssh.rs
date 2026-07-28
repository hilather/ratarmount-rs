//! SFTP/SSH download-to-temp for `ssh://` and `sftp://` URLs.
//!
//! # OpenSSH config
//!
//! Before connecting, settings are merged from a pragmatic subset of OpenSSH
//! `ssh_config(5)`:
//!
//! | Keyword | Effect |
//! |---------|--------|
//! | `Host` / patterns (`*`, `?`, `!neg`) | Select blocks by URL host alias |
//! | `HostName` | Real TCP host (alias → address) |
//! | `User` | Login name when URL omits user |
//! | `Port` | TCP port when URL omits port |
//! | `IdentityFile` | Private key path(s); `~` expanded |
//! | `IdentitiesOnly` | When `yes`, skip agent + default `~/.ssh/id_*` keys |
//!
//! ## Config path
//!
//! 1. `RATARMOUNT_SSH_CONFIG` — if set, only that file is read (tests/override)
//! 2. else `~/.ssh/config` when it exists (missing file → empty config)
//!
//! ## Precedence
//!
//! URL fields always override config for the same property:
//!
//! - **password** from URL (or `RATARMOUNT_SSH_PASSWORD`) wins over keys
//! - **user** from URL overrides `User`
//! - **port** from URL overrides `Port` (omitted URL port → config → `22`)
//! - **host** in the URL is the *alias* used for `Host` matching; `HostName`
//!   replaces the connect address only
//!
//! First-obtained single-value options win across matching `Host` blocks
//! (OpenSSH order: more specific blocks should appear first). `IdentityFile`
//! accumulates from every matching block.
//!
//! ## Authentication order
//!
//! 1. Password from URL
//! 2. SSH agent (skipped if `IdentitiesOnly yes`)
//! 3. `IdentityFile` keys from config
//! 4. Default `~/.ssh/id_ed25519|id_rsa|id_ecdsa` (skipped if `IdentitiesOnly yes`)
//! 5. `RATARMOUNT_SSH_PASSWORD`

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};

use log::debug;
use ssh2::Session;
use tempfile::NamedTempFile;
use url::Url;

use crate::{RemoteError, Result};

/// Env var: alternate path to an OpenSSH-style config file (unit tests / override).
pub const SSH_CONFIG_ENV: &str = "RATARMOUNT_SSH_CONFIG";

/// Parsed SSH/SFTP location (from URL only; config applied at connect time).
#[derive(Debug, Clone)]
pub struct SshLocation {
    /// Host alias from the URL (used for `Host` matching in ssh_config).
    pub host: String,
    /// Port from the URL when present; `None` if omitted (config / default 22).
    pub port: Option<u16>,
    pub user: Option<String>,
    pub password: Option<String>,
    /// Remote path (absolute if URL had `//` after host).
    pub path: String,
}

/// Effective connection parameters after URL + ssh_config merge.
#[derive(Debug, Clone)]
pub struct SshConnectParams {
    /// TCP host (`HostName` or URL host).
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: Option<String>,
    /// Configured private key paths (expanded).
    pub identity_files: Vec<PathBuf>,
    /// When true, do not try agent or default identity files.
    pub identities_only: bool,
    pub path: String,
}

/// One `Host` block from ssh_config.
#[derive(Debug, Clone, Default)]
struct HostBlock {
    patterns: Vec<String>,
    hostname: Option<String>,
    user: Option<String>,
    port: Option<u16>,
    identity_files: Vec<String>,
    identities_only: Option<bool>,
}

/// Parsed OpenSSH config (subset).
#[derive(Debug, Clone, Default)]
pub struct SshConfig {
    blocks: Vec<HostBlock>,
}

/// Settings collected from matching `Host` blocks.
#[derive(Debug, Clone, Default)]
pub struct SshConfigMatch {
    pub hostname: Option<String>,
    pub user: Option<String>,
    pub port: Option<u16>,
    pub identity_files: Vec<PathBuf>,
    pub identities_only: bool,
}

/// Parse `ssh://[user[:pass]@]host[:port]/path` or `sftp://…`.
///
/// Path rules (aligned with Python/fsspec):
/// - `ssh://host/rel` → relative path `rel`
/// - `ssh://host//abs` → absolute path `/abs`
///
/// Does **not** apply ssh_config; use [`resolve_ssh_connect`] or
/// [`fetch_ssh_location_to_temp`] for merge + connect.
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
    // Preserve "omitted" so Port from ssh_config can apply.
    let port = url.port();
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

/// Resolve config path: `RATARMOUNT_SSH_CONFIG` or `~/.ssh/config`.
pub fn ssh_config_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var(SSH_CONFIG_ENV) {
        let pb = PathBuf::from(p);
        if pb.as_os_str().is_empty() {
            return None;
        }
        return Some(pb);
    }
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".ssh").join("config"))
}

/// Load ssh_config from the default path (or env override). Missing file → empty.
pub fn load_ssh_config() -> Result<SshConfig> {
    let Some(path) = ssh_config_path() else {
        return Ok(SshConfig::default());
    };
    if !path.exists() {
        // Override path that does not exist: still empty (tests may set env to a temp that is created).
        debug!("ssh_config: no file at {}", path.display());
        return Ok(SshConfig::default());
    }
    parse_ssh_config_file(&path)
}

/// Parse an OpenSSH-style config file (subset of keywords).
pub fn parse_ssh_config_file(path: &Path) -> Result<SshConfig> {
    let f = std::fs::File::open(path)
        .map_err(|e| RemoteError::Ssh(format!("ssh_config {}: {e}", path.display())))?;
    parse_ssh_config_reader(BufReader::new(f))
}

/// Parse config text from any reader.
pub fn parse_ssh_config_reader<R: BufRead>(reader: R) -> Result<SshConfig> {
    let mut blocks: Vec<HostBlock> = Vec::new();
    let mut current: Option<HostBlock> = None;

    for line in reader.lines() {
        let line = line.map_err(|e| RemoteError::Ssh(format!("ssh_config read: {e}")))?;
        let line = strip_ssh_comment(&line);
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let (key, value) = split_ssh_kv(line);
        let key_l = key.to_ascii_lowercase();

        if key_l == "host" {
            if let Some(b) = current.take() {
                blocks.push(b);
            }
            let patterns: Vec<String> = value
                .split_whitespace()
                .filter(|p| !p.is_empty())
                .map(|s| s.to_string())
                .collect();
            current = Some(HostBlock {
                patterns,
                ..Default::default()
            });
            continue;
        }

        // Options before any Host are treated as matching all hosts ("Host *").
        let block = current.get_or_insert_with(|| HostBlock {
            patterns: vec!["*".into()],
            ..Default::default()
        });

        match key_l.as_str() {
            "hostname" => {
                if block.hostname.is_none() && !value.is_empty() {
                    block.hostname = Some(value.to_string());
                }
            }
            "user" => {
                if block.user.is_none() && !value.is_empty() {
                    block.user = Some(value.to_string());
                }
            }
            "port" => {
                if block.port.is_none() {
                    if let Ok(p) = value.parse::<u16>() {
                        block.port = Some(p);
                    }
                }
            }
            "identityfile" => {
                if !value.is_empty() {
                    block.identity_files.push(value.to_string());
                }
            }
            "identitiesonly" if block.identities_only.is_none() => {
                block.identities_only = Some(parse_ssh_yes(value));
            }
            // Ignore other keywords (Match, Include, ProxyJump, …) for this subset.
            _ => {}
        }
    }
    if let Some(b) = current.take() {
        blocks.push(b);
    }
    Ok(SshConfig { blocks })
}

fn strip_ssh_comment(line: &str) -> String {
    // OpenSSH: `#` starts a comment unless inside quotes (we skip quote complexity).
    if let Some(i) = line.find('#') {
        line[..i].to_string()
    } else {
        line.to_string()
    }
}

fn split_ssh_kv(line: &str) -> (&str, &str) {
    // `Key value` or `Key=value` (optional whitespace around `=`).
    if let Some(eq) = line.find('=') {
        let (k, rest) = line.split_at(eq);
        let v = rest[1..].trim();
        return (k.trim(), v.trim_matches('"'));
    }
    let mut parts = line.splitn(2, char::is_whitespace);
    let k = parts.next().unwrap_or("").trim();
    let v = parts.next().unwrap_or("").trim().trim_matches('"');
    (k, v)
}

fn parse_ssh_yes(v: &str) -> bool {
    matches!(
        v.to_ascii_lowercase().as_str(),
        "yes" | "true" | "1" | "on"
    )
}

/// Glob-style match for OpenSSH Host patterns (`*`, `?`). Case-sensitive.
pub fn host_pattern_matches(pattern: &str, host: &str) -> bool {
    host_glob_match(pattern.as_bytes(), host.as_bytes())
}

fn host_glob_match(pat: &[u8], text: &[u8]) -> bool {
    let mut pi = 0;
    let mut ti = 0;
    let mut star_pi: Option<usize> = None;
    let mut star_ti = 0;
    while ti < text.len() {
        if pi < pat.len() && (pat[pi] == b'?' || pat[pi] == text[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < pat.len() && pat[pi] == b'*' {
            star_pi = Some(pi);
            star_ti = ti;
            pi += 1;
        } else if let Some(sp) = star_pi {
            pi = sp + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }
    while pi < pat.len() && pat[pi] == b'*' {
        pi += 1;
    }
    pi == pat.len()
}

/// Whether `host` matches a Host line's patterns (supports `!` negation).
pub fn host_line_matches(patterns: &[String], host: &str) -> bool {
    if patterns.is_empty() {
        return false;
    }
    let mut any_positive = false;
    let mut matched_positive = false;
    for p in patterns {
        if let Some(neg) = p.strip_prefix('!') {
            if host_pattern_matches(neg, host) {
                return false;
            }
        } else {
            any_positive = true;
            if host_pattern_matches(p, host) {
                matched_positive = true;
            }
        }
    }
    if !any_positive {
        // Only negations: match unless excluded (OpenSSH treats that oddly; require a positive).
        return false;
    }
    matched_positive
}

impl SshConfig {
    /// Collect first-won options for `host` alias (OpenSSH first-obtained rule).
    pub fn match_host(&self, host: &str) -> SshConfigMatch {
        let mut out = SshConfigMatch::default();
        let mut identities_only_set = false;
        for block in &self.blocks {
            if !host_line_matches(&block.patterns, host) {
                continue;
            }
            if out.hostname.is_none() {
                if let Some(ref h) = block.hostname {
                    out.hostname = Some(h.clone());
                }
            }
            if out.user.is_none() {
                if let Some(ref u) = block.user {
                    out.user = Some(u.clone());
                }
            }
            if out.port.is_none() {
                if let Some(p) = block.port {
                    out.port = Some(p);
                }
            }
            if !identities_only_set {
                if let Some(v) = block.identities_only {
                    out.identities_only = v;
                    identities_only_set = true;
                }
            }
            // IdentityFile is multi-valued: accumulate from every matching block.
            for id in &block.identity_files {
                out.identity_files.push(expand_tilde(id));
            }
        }
        out
    }
}

/// Expand leading `~/` using `$HOME`.
pub fn expand_tilde(path: &str) -> PathBuf {
    if path == "~" {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home);
        }
        return PathBuf::from(path);
    }
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(path)
}

fn default_ssh_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "root".into())
}

/// Merge URL location with ssh_config. URL user/port/password override config.
pub fn resolve_ssh_connect(loc: &SshLocation, config: &SshConfig) -> SshConnectParams {
    let m = config.match_host(&loc.host);
    let host = m.hostname.unwrap_or_else(|| loc.host.clone());
    let port = loc.port.or(m.port).unwrap_or(22);
    let user = loc
        .user
        .clone()
        .or(m.user)
        .unwrap_or_else(default_ssh_user);
    SshConnectParams {
        host,
        port,
        user,
        password: loc.password.clone(),
        identity_files: m.identity_files,
        identities_only: m.identities_only,
        path: loc.path.clone(),
    }
}

/// Load default config and resolve connect params for a parsed location.
pub fn resolve_ssh_connect_default(loc: &SshLocation) -> Result<SshConnectParams> {
    let cfg = load_ssh_config()?;
    Ok(resolve_ssh_connect(loc, &cfg))
}

/// Download remote file via SFTP into a tempfile.
pub fn fetch_ssh_to_temp(url_str: &str) -> Result<(NamedTempFile, u64)> {
    let loc = parse_ssh_url(url_str)?;
    fetch_ssh_location_to_temp(&loc)
}

pub fn fetch_ssh_location_to_temp(loc: &SshLocation) -> Result<(NamedTempFile, u64)> {
    let params = resolve_ssh_connect_default(loc)?;
    fetch_ssh_params_to_temp(&params)
}

fn fetch_ssh_params_to_temp(params: &SshConnectParams) -> Result<(NamedTempFile, u64)> {
    let addr = format!("{}:{}", params.host, params.port);
    debug!(
        "ssh connect {addr} user={} path={} identities_only={} identity_files={}",
        params.user,
        params.path,
        params.identities_only,
        params.identity_files.len()
    );

    let tcp =
        TcpStream::connect(&addr).map_err(|e| RemoteError::Ssh(format!("connect {addr}: {e}")))?;
    let mut sess = Session::new().map_err(|e| RemoteError::Ssh(e.to_string()))?;
    sess.set_tcp_stream(tcp);
    sess.handshake()
        .map_err(|e| RemoteError::Ssh(format!("handshake: {e}")))?;

    authenticate(&mut sess, params)?;

    let sftp = sess
        .sftp()
        .map_err(|e| RemoteError::Ssh(format!("sftp: {e}")))?;
    let mut remote = sftp
        .open(Path::new(&params.path))
        .map_err(|e| RemoteError::Ssh(format!("open {}: {e}", params.path)))?;

    let mut tmp = NamedTempFile::new()?;
    let n = std::io::copy(&mut remote, &mut tmp)?;
    tmp.flush()?;
    Ok((tmp, n))
}

fn authenticate(sess: &mut Session, params: &SshConnectParams) -> Result<()> {
    let user = &params.user;

    // 1) Password from URL
    if let Some(pw) = params.password.as_deref() {
        sess.userauth_password(user, pw)
            .map_err(|e| RemoteError::Ssh(format!("password auth: {e}")))?;
        if sess.authenticated() {
            return Ok(());
        }
    }

    // 2) Agent (skipped when IdentitiesOnly)
    if !params.identities_only {
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
    }

    // 3) IdentityFile from config
    for key in &params.identity_files {
        if !key.exists() {
            debug!("ssh identity missing: {}", key.display());
            continue;
        }
        if sess.userauth_pubkey_file(user, None, key, None).is_ok() && sess.authenticated() {
            return Ok(());
        }
    }

    // 4) Default identity files (skipped when IdentitiesOnly)
    if !params.identities_only {
        let home = std::env::var_os("HOME").map(PathBuf::from);
        if let Some(home) = home {
            for name in ["id_ed25519", "id_rsa", "id_ecdsa"] {
                let key = home.join(".ssh").join(name);
                if !key.exists() {
                    continue;
                }
                if sess.userauth_pubkey_file(user, None, &key, None).is_ok()
                    && sess.authenticated()
                {
                    return Ok(());
                }
            }
        }
    }

    // 5) Env password
    if let Ok(pw) = std::env::var("RATARMOUNT_SSH_PASSWORD") {
        sess.userauth_password(user, &pw)
            .map_err(|e| RemoteError::Ssh(format!("password auth (env): {e}")))?;
        if sess.authenticated() {
            return Ok(());
        }
    }

    Err(RemoteError::Ssh(format!(
        "SSH authentication failed for user {user:?} (tried password, agent, IdentityFile, ~/.ssh/id_*)"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::Mutex;

    /// Serialize tests that mutate process environment.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn parse_relative_and_absolute() {
        let r = parse_ssh_url("ssh://alice@example.com/data/a.tar").unwrap();
        assert_eq!(r.host, "example.com");
        assert_eq!(r.port, None);
        assert_eq!(r.user.as_deref(), Some("alice"));
        assert_eq!(r.path, "data/a.tar");

        let a = parse_ssh_url("sftp://bob@host:2222//home/bob/a.tar").unwrap();
        assert_eq!(a.port, Some(2222));
        assert_eq!(a.user.as_deref(), Some("bob"));
        assert_eq!(a.path, "/home/bob/a.tar");
    }

    #[test]
    fn parse_password() {
        let r = parse_ssh_url("ssh://u:secret@h//tmp/x").unwrap();
        assert_eq!(r.password.as_deref(), Some("secret"));
        assert_eq!(r.path, "/tmp/x");
    }

    #[test]
    fn host_glob_basics() {
        assert!(host_pattern_matches("*", "anything"));
        assert!(host_pattern_matches("*.example.com", "a.example.com"));
        assert!(!host_pattern_matches("*.example.com", "example.com"));
        assert!(host_pattern_matches("host?", "host1"));
        assert!(!host_pattern_matches("host?", "host12"));
        assert!(host_line_matches(
            &["*.lab".into(), "!bad.lab".into()],
            "good.lab"
        ));
        assert!(!host_line_matches(
            &["*.lab".into(), "!bad.lab".into()],
            "bad.lab"
        ));
    }

    #[test]
    fn parse_config_and_merge_precedence() {
        let text = r#"
# comment
Host mystage
    HostName 10.0.0.5
    User deploy
    Port 2222
    IdentityFile ~/.ssh/stage_ed25519
    IdentitiesOnly yes

Host *.example.com
    User fromstar
    Port 2200
    IdentityFile /keys/star_key

Host *
    User defaultuser
    Port 22
    IdentityFile ~/.ssh/id_default
"#;
        let cfg = parse_ssh_config_reader(text.as_bytes()).unwrap();

        // Alias → HostName, user/port/keys from block; IdentitiesOnly.
        let loc = parse_ssh_url("ssh://mystage//var/data/a.tar").unwrap();
        let p = resolve_ssh_connect(&loc, &cfg);
        assert_eq!(p.host, "10.0.0.5");
        assert_eq!(p.port, 2222);
        assert_eq!(p.user, "deploy");
        assert!(p.identities_only);
        assert_eq!(p.identity_files.len(), 2); // stage + Host * id_default accumulate
        assert!(p.identity_files[0]
            .to_string_lossy()
            .contains("stage_ed25519"));

        // URL overrides User and Port; HostName still from config.
        let loc2 = parse_ssh_url("ssh://alice@mystage:99//tmp/x").unwrap();
        let p2 = resolve_ssh_connect(&loc2, &cfg);
        assert_eq!(p2.host, "10.0.0.5");
        assert_eq!(p2.port, 99);
        assert_eq!(p2.user, "alice");
        assert_eq!(p2.password, None);

        // Password still from URL.
        let loc3 = parse_ssh_url("ssh://alice:s3cr3t@mystage//tmp/x").unwrap();
        let p3 = resolve_ssh_connect(&loc3, &cfg);
        assert_eq!(p3.password.as_deref(), Some("s3cr3t"));
        assert_eq!(p3.user, "alice");

        // Wildcard host without specific block match for HostName.
        let loc4 = parse_ssh_url("ssh://box.example.com//a").unwrap();
        let p4 = resolve_ssh_connect(&loc4, &cfg);
        assert_eq!(p4.host, "box.example.com");
        assert_eq!(p4.user, "fromstar");
        assert_eq!(p4.port, 2200);
        // identity from *.example.com and Host *
        assert_eq!(p4.identity_files.len(), 2);
        assert!(!p4.identities_only);
    }

    #[test]
    fn first_obtained_user_wins() {
        let text = r#"
Host foo
    User first
Host foo
    User second
    Port 2222
"#;
        let cfg = parse_ssh_config_reader(text.as_bytes()).unwrap();
        let loc = parse_ssh_url("ssh://foo//x").unwrap();
        let p = resolve_ssh_connect(&loc, &cfg);
        assert_eq!(p.user, "first");
        assert_eq!(p.port, 2222);
    }

    #[test]
    fn equals_form_and_identity_accumulate() {
        let text = r#"
Host bar
  HostName=real.internal
  Port=2022
  IdentityFile=/a/key
  IdentityFile=/b/key
"#;
        let cfg = parse_ssh_config_reader(text.as_bytes()).unwrap();
        let m = cfg.match_host("bar");
        assert_eq!(m.hostname.as_deref(), Some("real.internal"));
        assert_eq!(m.port, Some(2022));
        assert_eq!(m.identity_files.len(), 2);
    }

    #[test]
    fn parse_config_file_and_env_override_path() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            tmp,
            "Host envhost\n    HostName 192.0.2.1\n    User envuser\n    Port 2201\n"
        )
        .unwrap();
        tmp.flush().unwrap();

        let cfg = parse_ssh_config_file(tmp.path()).unwrap();
        let loc = parse_ssh_url("ssh://envhost//data/f.tar").unwrap();
        let p = resolve_ssh_connect(&loc, &cfg);
        assert_eq!(p.host, "192.0.2.1");
        assert_eq!(p.user, "envuser");
        assert_eq!(p.port, 2201);

        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var(SSH_CONFIG_ENV, tmp.path());
        let path = ssh_config_path().expect("env path");
        assert_eq!(path, tmp.path());
        let loaded = load_ssh_config().unwrap();
        std::env::remove_var(SSH_CONFIG_ENV);
        let p2 = resolve_ssh_connect(&loc, &loaded);
        assert_eq!(p2.host, "192.0.2.1");
        assert_eq!(p2.port, 2201);
    }

    #[test]
    fn expand_tilde_home() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var_os("HOME");
        std::env::set_var("HOME", "/home/testuser");
        let p = expand_tilde("~/.ssh/id_ed25519");
        assert_eq!(p, PathBuf::from("/home/testuser/.ssh/id_ed25519"));
        let p2 = expand_tilde("/abs/key");
        assert_eq!(p2, PathBuf::from("/abs/key"));
        match prev {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
    }
}
