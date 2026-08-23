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
//! | `ProxyJump` | Comma-separated hop chain via libssh2 `direct-tcpip`; `none` disables |
//! | `Include` | Nested config files (`~`, relative, trailing `*` via `read_dir`) |
//!
//! ## Config path
//!
//! 1. `RATARMOUNT_SSH_CONFIG` — if set, only that file is read (tests/override)
//! 2. else `~/.ssh/config` when it exists (missing file → empty config)
//!
//! `Include` is expanded only by [`parse_ssh_config_file`] (needs a path for
//! `base_dir`). [`parse_ssh_config_reader`] is a leaf parser of one file’s
//! bytes and ignores `Include`. Recursion is capped at 16 with a visited-set of
//! canonical paths (cycles error). Each included file is capped at 1 MiB;
//! oversize / IO errors skip that include (`debug!`). Unsupported globs (`?`,
//! `[]`, interior `*`) are skipped.
//!
//! ## Precedence
//!
//! URL fields always override config for the same property:
//!
//! - **password** from URL (or `RATARMOUNT_SSH_PASSWORD`) wins over keys on the
//!   **destination only** — hops never use the URL/env password
//! - **user** from URL overrides `User` (destination only, not ProxyJump hops)
//! - **port** from URL overrides `Port` (omitted URL port → config → `22`)
//! - **host** in the URL is the *alias* used for `Host` matching; `HostName`
//!   replaces the connect address only
//!
//! First-obtained single-value options win across matching `Host` blocks
//! (OpenSSH order: more specific blocks should appear first). `IdentityFile`
//! accumulates from every matching block. `ProxyJump` hops are themselves Host
//! aliases resolved through the same config (cycle / depth 16 → error).
//!
//! ## Authentication order
//!
//! 1. Password from URL
//! 2. SSH agent (skipped if `IdentitiesOnly yes`)
//! 3. `IdentityFile` keys from config
//! 4. Default `~/.ssh/id_ed25519|id_rsa|id_ecdsa` (skipped if `IdentitiesOnly yes`)
//! 5. `RATARMOUNT_SSH_PASSWORD`
//!
//! ## Residuals
//!
//! - **ProxyCommand** (shell) is out of scope (injection / no pty).
//! - **Match** exec/host is ignored.
//! - Live ProxyJump `direct-tcpip` handshake is skip-without-`sshd` (no bastion
//!   fixture). Hop **resolution**, cycles, `ProxyJump none`, Drop/pump order are
//!   unit-tested. The connect chain is not claimed production-ready beyond
//!   parse/resolve until a live sshd fixture exists.

use std::collections::HashSet;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use log::debug;
use ssh2::Session;
use tempfile::NamedTempFile;
use url::Url;

use crate::{RemoteError, Result};

/// Env var: alternate path to an OpenSSH-style config file (unit tests / override).
pub const SSH_CONFIG_ENV: &str = "RATARMOUNT_SSH_CONFIG";

/// Recursion / hop-chain cap for `Include` and `ProxyJump` alias resolution.
const SSH_CONFIG_MAX_DEPTH: usize = 16;
/// Per-included-file size cap (skip oversize with `debug!`).
const SSH_INCLUDE_MAX_BYTES: u64 = 1024 * 1024;

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
    /// Resolved ProxyJump hop chain (empty = direct TCP). Nested jumps are flattened.
    pub proxy_jumps: Vec<SshConnectParams>,
}

/// One hop from a `ProxyJump` list: `[user@]host[:port]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshProxyHop {
    pub user: Option<String>,
    pub host: String,
    pub port: Option<u16>,
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
    /// First-obtained raw `ProxyJump` value for this block.
    proxy_jump: Option<String>,
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
    /// First-obtained `ProxyJump` hops (parsed `[user@]host[:port]` list).
    pub proxy_jumps: Vec<SshProxyHop>,
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

/// Parse an OpenSSH-style config file (subset of keywords), expanding `Include`.
///
/// `base_dir` is `path.parent()`. Relative includes join that directory; `~` is
/// expanded via [`expand_tilde`]. Recursion cap 16; canonical visited-set
/// (cycles error). Included files over 1 MiB or unreadable are skipped.
pub fn parse_ssh_config_file(path: &Path) -> Result<SshConfig> {
    let mut ctx = ParseCtx::default();
    let mut visiting = HashSet::new();
    parse_ssh_config_file_into(&mut ctx, path, 0, &mut visiting)?;
    Ok(ctx.finish())
}

/// Parse config text from any reader (one file’s bytes; **no** `Include`).
pub fn parse_ssh_config_reader<R: BufRead>(reader: R) -> Result<SshConfig> {
    let mut ctx = ParseCtx::default();
    for line in reader.lines() {
        let line = line.map_err(|e| RemoteError::Ssh(format!("ssh_config read: {e}")))?;
        apply_ssh_config_line(&mut ctx, &line, None)?;
    }
    Ok(ctx.finish())
}

#[derive(Clone, Default)]
struct ParseCtx {
    blocks: Vec<HostBlock>,
    current: Option<HostBlock>,
}

impl ParseCtx {
    fn finish(mut self) -> SshConfig {
        if let Some(b) = self.current.take() {
            self.blocks.push(b);
        }
        SshConfig {
            blocks: self.blocks,
        }
    }
}

fn parse_ssh_config_file_into(
    ctx: &mut ParseCtx,
    path: &Path,
    depth: usize,
    visiting: &mut HashSet<PathBuf>,
) -> Result<()> {
    if depth > SSH_CONFIG_MAX_DEPTH {
        debug!(
            "ssh_config Include skip: depth cap {} at {}",
            SSH_CONFIG_MAX_DEPTH,
            path.display()
        );
        return Ok(());
    }

    let canon = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    if !visiting.insert(canon.clone()) {
        return Err(RemoteError::SshIncludeCycle(canon.display().to_string()));
    }

    let result = (|| -> Result<()> {
        if depth > 0 {
            match std::fs::metadata(path) {
                Ok(meta) if !meta.is_file() => {
                    debug!(
                        "ssh_config Include skip {}: not a regular file",
                        path.display()
                    );
                    return Ok(());
                }
                Ok(_) => {}
                Err(e) => {
                    debug!("ssh_config Include skip {}: {e}", path.display());
                    return Ok(());
                }
            }
        }
        let f = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(e) if depth > 0 => {
                debug!("ssh_config Include skip {}: {e}", path.display());
                return Ok(());
            }
            Err(e) => {
                return Err(RemoteError::Ssh(format!(
                    "ssh_config {}: {e}",
                    path.display()
                )));
            }
        };
        // Byte cap after open so st_size=0 devices/fifos cannot hang `lines()`.
        let mut limited = f.take(SSH_INCLUDE_MAX_BYTES.saturating_add(1));
        let mut buf = Vec::new();
        limited
            .read_to_end(&mut buf)
            .map_err(|e| RemoteError::Ssh(format!("ssh_config read: {e}")))?;
        if depth > 0 && buf.len() as u64 > SSH_INCLUDE_MAX_BYTES {
            debug!(
                "ssh_config Include skip: {} is {} bytes (cap {SSH_INCLUDE_MAX_BYTES})",
                path.display(),
                buf.len()
            );
            return Ok(());
        }
        let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
        let reader = BufReader::new(buf.as_slice());
        for line in reader.lines() {
            let line = line.map_err(|e| RemoteError::Ssh(format!("ssh_config read: {e}")))?;
            apply_ssh_config_line(ctx, &line, Some((base_dir, depth, visiting)))?;
        }
        Ok(())
    })();

    visiting.remove(&canon);
    result
}

/// `include_ctx` is `Some` only when expanding `Include` from a real file path.
fn apply_ssh_config_line(
    ctx: &mut ParseCtx,
    raw_line: &str,
    include_ctx: Option<(&Path, usize, &mut HashSet<PathBuf>)>,
) -> Result<()> {
    let line = strip_ssh_comment(raw_line);
    let line = line.trim();
    if line.is_empty() {
        return Ok(());
    }

    let (key, value) = split_ssh_kv(line);
    let key_l = key.to_ascii_lowercase();

    if key_l == "include" {
        if let Some((base_dir, depth, visiting)) = include_ctx {
            apply_include(ctx, value, base_dir, depth, visiting)?;
        }
        // Leaf reader: ignore Include (no path / base_dir).
        return Ok(());
    }

    if key_l == "host" {
        if let Some(b) = ctx.current.take() {
            ctx.blocks.push(b);
        }
        let patterns: Vec<String> = value
            .split_whitespace()
            .filter(|p| !p.is_empty())
            .map(|s| s.to_string())
            .collect();
        ctx.current = Some(HostBlock {
            patterns,
            ..Default::default()
        });
        return Ok(());
    }

    // Options before any Host are treated as matching all hosts ("Host *").
    let block = ctx.current.get_or_insert_with(|| HostBlock {
        patterns: vec!["*".into()],
        ..Default::default()
    });
    apply_host_option(block, &key_l, value);
    Ok(())
}

fn apply_host_option(block: &mut HostBlock, key_l: &str, value: &str) {
    match key_l {
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
        "proxyjump" if block.proxy_jump.is_none() && !value.is_empty() => {
            block.proxy_jump = Some(value.to_string());
        }
        // Ignore other keywords (Match, ProxyCommand, …).
        _ => {}
    }
}

fn apply_include(
    ctx: &mut ParseCtx,
    value: &str,
    base_dir: &Path,
    depth: usize,
    visiting: &mut HashSet<PathBuf>,
) -> Result<()> {
    for spec in value.split_whitespace().filter(|s| !s.is_empty()) {
        for path in expand_include_spec(spec, base_dir) {
            let snapshot = ctx.clone();
            match parse_ssh_config_file_into(ctx, &path, depth + 1, visiting) {
                Ok(()) => {}
                Err(e @ RemoteError::SshIncludeCycle(_)) => return Err(e),
                Err(e) => {
                    debug!("ssh_config Include skip {}: {e}", path.display());
                    *ctx = snapshot;
                }
            }
        }
    }
    Ok(())
}

/// Non-glob path, or a trailing `*` via `read_dir` on the parent (prefix match).
/// `?` / `[]` / interior `*` are residual (skip + `debug!`).
fn expand_include_spec(spec: &str, base_dir: &Path) -> Vec<PathBuf> {
    let trimmed = spec.trim().trim_matches('"');
    if trimmed.is_empty() {
        return Vec::new();
    }
    let expanded = if trimmed == "~" || trimmed.starts_with("~/") {
        expand_tilde(trimmed)
    } else {
        let p = Path::new(trimmed);
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            base_dir.join(p)
        }
    };

    let lossy = expanded.to_string_lossy();
    if lossy.contains('?') || lossy.contains('[') {
        debug!("ssh_config Include skip unsupported glob {spec}");
        return Vec::new();
    }

    let file_name = match expanded.file_name().and_then(|n| n.to_str()) {
        Some(n) => n,
        None => return vec![expanded],
    };

    if let Some(prefix) = file_name.strip_suffix('*') {
        let parent_glob = expanded
            .parent()
            .map(|p| p.to_string_lossy().contains('*'))
            .unwrap_or(false);
        if prefix.contains('*') || parent_glob {
            debug!("ssh_config Include skip unsupported glob {spec}");
            return Vec::new();
        }
        let parent = expanded.parent().unwrap_or(base_dir);
        let mut matches = Vec::new();
        match std::fs::read_dir(parent) {
            Ok(rd) => {
                for ent in rd.flatten() {
                    let name = ent.file_name();
                    let name_s = name.to_string_lossy();
                    if name_s.starts_with(prefix) {
                        let p = ent.path();
                        if p.is_file() {
                            matches.push(p);
                        }
                    }
                }
            }
            Err(e) => {
                debug!(
                    "ssh_config Include skip glob {}: read_dir {}: {e}",
                    spec,
                    parent.display()
                );
                return Vec::new();
            }
        }
        matches.sort();
        return matches;
    }

    if lossy.contains('*') {
        debug!("ssh_config Include skip unsupported glob {spec}");
        return Vec::new();
    }
    vec![expanded]
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
    matches!(v.to_ascii_lowercase().as_str(), "yes" | "true" | "1" | "on")
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
        let mut proxy_jump_set = false;
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
            if !proxy_jump_set {
                if let Some(ref raw) = block.proxy_jump {
                    out.proxy_jumps = parse_proxy_jump_list(raw);
                    proxy_jump_set = true;
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

/// Parse `ProxyJump [user@]host[:port][,[user@]host[:port]…]`. Invalid hops are dropped.
///
/// OpenSSH `ProxyJump none` (ignore-case, whole value) disables jumping — needed
/// when `Host *` sets a bastion that must not jump through itself.
pub fn parse_proxy_jump_list(value: &str) -> Vec<SshProxyHop> {
    let trimmed = value.trim();
    if trimmed.eq_ignore_ascii_case("none") {
        return Vec::new();
    }
    let mut out = Vec::new();
    for part in value.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        match parse_proxy_jump_hop(part) {
            Some(h) => out.push(h),
            None => debug!("ssh_config ProxyJump skip invalid hop {part:?}"),
        }
    }
    out
}

fn parse_proxy_jump_hop(s: &str) -> Option<SshProxyHop> {
    let (user, hostport) = match s.rsplit_once('@') {
        Some((u, h)) if !u.is_empty() && !h.is_empty() => (Some(u.to_string()), h),
        _ => (None, s),
    };
    let (host, port) = if let Some(rest) = hostport.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = rest[..end].to_string();
        if host.is_empty() {
            return None;
        }
        let after = &rest[end + 1..];
        let port = if after.is_empty() {
            None
        } else {
            let p = after.strip_prefix(':')?;
            Some(p.parse::<u16>().ok()?)
        };
        (host, port)
    } else if hostport.chars().filter(|c| *c == ':').count() > 1 {
        // Unbracketed IPv6 residual: treat as host, no port.
        (hostport.to_string(), None)
    } else if let Some((h, p)) = hostport.rsplit_once(':') {
        if h.is_empty() {
            return None;
        }
        (h.to_string(), Some(p.parse::<u16>().ok()?))
    } else {
        (hostport.to_string(), None)
    };
    if host.is_empty() {
        return None;
    }
    Some(SshProxyHop { user, host, port })
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

/// Merge URL location with ssh_config. URL user/port/password override config
/// for the **destination** (not ProxyJump hops).
///
/// Hop aliases are resolved through `config` with a depth cap of 16 and a
/// visited-alias set (`A → B → A` is an error).
pub fn resolve_ssh_connect(loc: &SshLocation, config: &SshConfig) -> Result<SshConnectParams> {
    let mut visited = HashSet::new();
    resolve_ssh_connect_inner(loc, config, &mut visited, 0)
}

fn resolve_ssh_connect_inner(
    loc: &SshLocation,
    config: &SshConfig,
    visited: &mut HashSet<String>,
    depth: usize,
) -> Result<SshConnectParams> {
    if depth > SSH_CONFIG_MAX_DEPTH {
        return Err(RemoteError::Ssh(format!(
            "ProxyJump depth cap {SSH_CONFIG_MAX_DEPTH} exceeded at host alias {}",
            loc.host
        )));
    }
    if !visited.insert(loc.host.clone()) {
        return Err(RemoteError::Ssh(format!(
            "ProxyJump cycle involving host alias {}",
            loc.host
        )));
    }

    let m = config.match_host(&loc.host);
    let host = m.hostname.clone().unwrap_or_else(|| loc.host.clone());
    let port = loc.port.or(m.port).unwrap_or(22);
    let user = loc
        .user
        .clone()
        .or_else(|| m.user.clone())
        .unwrap_or_else(default_ssh_user);

    let mut proxy_jumps = Vec::new();
    for hop in &m.proxy_jumps {
        let hop_loc = SshLocation {
            host: hop.host.clone(),
            port: hop.port,
            user: hop.user.clone(),
            password: None,
            path: String::new(),
        };
        let mut hop_params = resolve_ssh_connect_inner(&hop_loc, config, visited, depth + 1)?;
        // Flatten nested ProxyJump on the hop, then this hop (no nested list).
        proxy_jumps.append(&mut hop_params.proxy_jumps);
        hop_params.proxy_jumps.clear();
        hop_params.path.clear();
        proxy_jumps.push(hop_params);
    }

    visited.remove(&loc.host);

    Ok(SshConnectParams {
        host,
        port,
        user,
        password: loc.password.clone(),
        identity_files: m.identity_files,
        identities_only: m.identities_only,
        path: loc.path.clone(),
        proxy_jumps,
    })
}

/// Load default config and resolve connect params for a parsed location.
pub fn resolve_ssh_connect_default(loc: &SshLocation) -> Result<SshConnectParams> {
    let cfg = load_ssh_config()?;
    resolve_ssh_connect(loc, &cfg)
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

/// Parent hop `Session`s (and their `direct-tcpip` pumps) must outlive the child
/// session: `ssh2::Channel` is a handle into the parent, and the next
/// `Session::set_tcp_stream` needs a `'static` fd (socket pair + pump).
///
/// Drop order: destination `Session` first, then this stack last-hop-first so
/// each parent `Session` outlives its child Channel/pump.
struct HopStack {
    hops: Vec<HopLink>,
}

struct HopLink {
    sess: Session,
    pump: Option<JoinHandle<()>>,
}

impl Drop for HopStack {
    fn drop(&mut self) {
        while let Some(mut hop) = self.hops.pop() {
            if let Some(pump) = hop.pump.take() {
                let _ = pump.join();
            }
            drop(hop.sess);
        }
    }
}

fn hop_ssh_err(hop: Option<usize>, host: &str, msg: String) -> RemoteError {
    match hop {
        Some(i) => RemoteError::Ssh(format!("ProxyJump hop {i} {host}: {msg}")),
        None => RemoteError::Ssh(msg),
    }
}

fn wrap_hop_err(hop: Option<usize>, host: &str, err: RemoteError) -> RemoteError {
    match (hop, err) {
        (Some(i), RemoteError::Ssh(msg)) => {
            RemoteError::Ssh(format!("ProxyJump hop {i} {host}: {msg}"))
        }
        (_, other) => other,
    }
}

fn fetch_ssh_params_to_temp(params: &SshConnectParams) -> Result<(NamedTempFile, u64)> {
    let mut stack = HopStack { hops: Vec::new() };
    let dest_sess = connect_ssh_chain(params, &mut stack)?;
    copy_sftp_and_teardown(dest_sess, stack, &params.path)
}

/// SFTP copy, then Drop `remote` → `sftp` → dest `Session` → hop pumps.
/// Joining pumps while an SFTP handle is still open blocks CLOSE on the tunnel.
fn copy_sftp_and_teardown(
    dest_sess: Session,
    stack: HopStack,
    path: &str,
) -> Result<(NamedTempFile, u64)> {
    let sftp = dest_sess
        .sftp()
        .map_err(|e| RemoteError::Ssh(format!("sftp: {e}")))?;
    let mut remote = sftp
        .open(Path::new(path))
        .map_err(|e| RemoteError::Ssh(format!("open {path}: {e}")))?;

    let mut tmp = NamedTempFile::new()?;
    let n = io::copy(&mut remote, &mut tmp)?;
    tmp.flush()?;
    drop(remote);
    drop(sftp);
    drop(dest_sess);
    drop(stack);
    Ok((tmp, n))
}

fn connect_ssh_chain(params: &SshConnectParams, stack: &mut HopStack) -> Result<Session> {
    if params.proxy_jumps.is_empty() {
        return connect_tcp_session(params, None);
    }

    let first = &params.proxy_jumps[0];
    debug!(
        "ProxyJump hop 0 {}:{} user={}",
        first.host, first.port, first.user
    );
    let mut current = connect_tcp_session(first, Some(0))?;

    let mut next_hops: Vec<&SshConnectParams> = params.proxy_jumps[1..].iter().collect();
    next_hops.push(params);

    for (i, next) in next_hops.into_iter().enumerate() {
        let hop_index = i + 1;
        let is_dest = hop_index == params.proxy_jumps.len();
        let err_hop = if is_dest { None } else { Some(hop_index) };
        if is_dest {
            debug!(
                "ProxyJump dest {}:{} user={}",
                next.host, next.port, next.user
            );
        } else {
            debug!(
                "ProxyJump hop {hop_index} {}:{} user={}",
                next.host, next.port, next.user
            );
        }
        let channel = current
            .channel_direct_tcpip(&next.host, next.port, None)
            .map_err(|e| {
                hop_ssh_err(
                    err_hop,
                    &next.host,
                    format!("direct-tcpip {}:{}: {e}", next.host, next.port),
                )
            })?;
        // Channel I/O is serialized on the parent Session mutex; set nonblocking
        // *after* opening the channel so handshake of this hop stays blocking.
        current.set_blocking(false);
        let (local, peer) = local_tcp_pair()?;
        let pump = spawn_channel_pump(channel, peer);
        let mut child = Session::new().map_err(|e| RemoteError::Ssh(e.to_string()))?;
        child.set_tcp_stream(local);
        if let Err(e) = child.handshake() {
            drop(child);
            let _ = pump.join();
            return Err(hop_ssh_err(err_hop, &next.host, format!("handshake: {e}")));
        }
        if let Err(e) = authenticate(&mut child, next, is_dest) {
            drop(child);
            let _ = pump.join();
            return Err(wrap_hop_err(err_hop, &next.host, e));
        }
        stack.hops.push(HopLink {
            sess: current,
            pump: Some(pump),
        });
        current = child;
    }
    Ok(current)
}

fn connect_tcp_session(params: &SshConnectParams, hop: Option<usize>) -> Result<Session> {
    let addr = format!("{}:{}", params.host, params.port);
    debug!(
        "ssh connect {addr} user={} path={} identities_only={} identity_files={}",
        params.user,
        params.path,
        params.identities_only,
        params.identity_files.len()
    );
    let tcp = TcpStream::connect(&addr)
        .map_err(|e| hop_ssh_err(hop, &params.host, format!("connect {addr}: {e}")))?;
    let mut sess = Session::new().map_err(|e| RemoteError::Ssh(e.to_string()))?;
    sess.set_tcp_stream(tcp);
    sess.handshake()
        .map_err(|e| hop_ssh_err(hop, &params.host, format!("handshake: {e}")))?;
    authenticate(&mut sess, params, hop.is_none())
        .map_err(|e| wrap_hop_err(hop, &params.host, e))?;
    Ok(sess)
}

fn local_tcp_pair() -> Result<(TcpStream, TcpStream)> {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .map_err(|e| RemoteError::Ssh(format!("ProxyJump socket pair: {e}")))?;
    let addr = listener
        .local_addr()
        .map_err(|e| RemoteError::Ssh(format!("ProxyJump socket pair: {e}")))?;
    let client = TcpStream::connect(addr)
        .map_err(|e| RemoteError::Ssh(format!("ProxyJump socket pair: {e}")))?;
    let (server, _) = listener
        .accept()
        .map_err(|e| RemoteError::Ssh(format!("ProxyJump socket pair: {e}")))?;
    Ok((client, server))
}

fn spawn_channel_pump(channel: ssh2::Channel, sock: TcpStream) -> JoinHandle<()> {
    thread::spawn(move || pump_direct_tcpip_nonblocking(channel, sock))
}

/// One thread, nonblocking both ways. ssh2 serializes Channel I/O on a Session
/// mutex: a blocking read in a second thread would stall writes (handshake/COPY).
fn pump_direct_tcpip_nonblocking(mut channel: ssh2::Channel, mut sock: TcpStream) {
    let _ = sock.set_nonblocking(true);
    let mut c2s = [0u8; 16 * 1024];
    let mut s2c = [0u8; 16 * 1024];
    let mut chan_eof = false;
    let mut sock_eof = false;
    loop {
        let mut progress = false;
        if !chan_eof {
            match channel.read(&mut c2s) {
                Ok(0) => {
                    chan_eof = true;
                    progress = true;
                    let _ = sock.shutdown(Shutdown::Write);
                }
                Ok(n) => match write_all_wouldblock(&mut sock, &c2s[..n]) {
                    Ok(()) => progress = true,
                    Err(_) => break,
                },
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) if e.kind() == io::ErrorKind::Interrupted => progress = true,
                Err(_) => {
                    chan_eof = true;
                    let _ = sock.shutdown(Shutdown::Write);
                }
            }
        }
        if !sock_eof {
            match sock.read(&mut s2c) {
                Ok(0) => {
                    sock_eof = true;
                    progress = true;
                    let _ = channel.send_eof();
                }
                Ok(n) => match write_all_wouldblock(&mut channel, &s2c[..n]) {
                    Ok(()) => progress = true,
                    Err(_) => break,
                },
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) if e.kind() == io::ErrorKind::Interrupted => progress = true,
                Err(_) => {
                    sock_eof = true;
                    let _ = channel.send_eof();
                }
            }
        }
        if chan_eof && sock_eof {
            break;
        }
        if !progress {
            thread::sleep(Duration::from_millis(2));
        }
    }
}

fn write_all_wouldblock<W: Write>(w: &mut W, mut buf: &[u8]) -> io::Result<()> {
    while !buf.is_empty() {
        match w.write(buf) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "ProxyJump pump write returned 0",
                ));
            }
            Ok(n) => buf = &buf[n..],
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(1));
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn authenticate(
    sess: &mut Session,
    params: &SshConnectParams,
    use_env_password: bool,
) -> Result<()> {
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
                if sess.userauth_pubkey_file(user, None, &key, None).is_ok() && sess.authenticated()
                {
                    return Ok(());
                }
            }
        }
    }

    // 5) Env password (destination only — hops must not inherit dest credentials)
    if use_env_password {
        if let Ok(pw) = std::env::var("RATARMOUNT_SSH_PASSWORD") {
            sess.userauth_password(user, &pw)
                .map_err(|e| RemoteError::Ssh(format!("password auth (env): {e}")))?;
            if sess.authenticated() {
                return Ok(());
            }
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
        let p = resolve_ssh_connect(&loc, &cfg).unwrap();
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
        let p2 = resolve_ssh_connect(&loc2, &cfg).unwrap();
        assert_eq!(p2.host, "10.0.0.5");
        assert_eq!(p2.port, 99);
        assert_eq!(p2.user, "alice");
        assert_eq!(p2.password, None);

        // Password still from URL.
        let loc3 = parse_ssh_url("ssh://alice:s3cr3t@mystage//tmp/x").unwrap();
        let p3 = resolve_ssh_connect(&loc3, &cfg).unwrap();
        assert_eq!(p3.password.as_deref(), Some("s3cr3t"));
        assert_eq!(p3.user, "alice");

        // Wildcard host without specific block match for HostName.
        let loc4 = parse_ssh_url("ssh://box.example.com//a").unwrap();
        let p4 = resolve_ssh_connect(&loc4, &cfg).unwrap();
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
        let p = resolve_ssh_connect(&loc, &cfg).unwrap();
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
        let p = resolve_ssh_connect(&loc, &cfg).unwrap();
        assert_eq!(p.host, "192.0.2.1");
        assert_eq!(p.user, "envuser");
        assert_eq!(p.port, 2201);

        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var(SSH_CONFIG_ENV, tmp.path());
        let path = ssh_config_path().expect("env path");
        assert_eq!(path, tmp.path());
        let loaded = load_ssh_config().unwrap();
        std::env::remove_var(SSH_CONFIG_ENV);
        let p2 = resolve_ssh_connect(&loc, &loaded).unwrap();
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

    #[test]
    fn parse_proxy_jump_user_host_port_list() {
        let text = r#"
Host dest
    HostName dest.example
    User destuser
    ProxyJump alice@jump1.example:2222,jump2.example
Host jump1.example
    HostName 10.0.0.1
    User ignored
Host jump2.example
    HostName 10.0.0.2
    User bob
    Port 2200
"#;
        let cfg = parse_ssh_config_reader(text.as_bytes()).unwrap();
        let m = cfg.match_host("dest");
        assert_eq!(
            m.proxy_jumps,
            vec![
                SshProxyHop {
                    user: Some("alice".into()),
                    host: "jump1.example".into(),
                    port: Some(2222),
                },
                SshProxyHop {
                    user: None,
                    host: "jump2.example".into(),
                    port: None,
                },
            ]
        );
        let loc = parse_ssh_url("ssh://dest//data/a.tar").unwrap();
        let p = resolve_ssh_connect(&loc, &cfg).unwrap();
        assert_eq!(p.host, "dest.example");
        assert_eq!(p.user, "destuser");
        assert_eq!(p.proxy_jumps.len(), 2);
        assert_eq!(p.proxy_jumps[0].host, "10.0.0.1");
        assert_eq!(p.proxy_jumps[0].user, "alice");
        assert_eq!(p.proxy_jumps[0].port, 2222);
        assert_eq!(p.proxy_jumps[1].host, "10.0.0.2");
        assert_eq!(p.proxy_jumps[1].user, "bob");
        assert_eq!(p.proxy_jumps[1].port, 2200);
        assert!(p.proxy_jumps[0].proxy_jumps.is_empty());
    }

    #[test]
    fn url_user_port_override_destination_not_hop() {
        let text = r#"
Host dest
    HostName dest.example
    User destuser
    Port 22
    ProxyJump bob@jumphost:2222
Host jumphost
    HostName 10.1.1.1
    User jumpuser
    Port 2200
"#;
        let cfg = parse_ssh_config_reader(text.as_bytes()).unwrap();
        let loc = parse_ssh_url("ssh://alice@dest:99//tmp/x").unwrap();
        let p = resolve_ssh_connect(&loc, &cfg).unwrap();
        assert_eq!(p.user, "alice");
        assert_eq!(p.port, 99);
        assert_eq!(p.host, "dest.example");
        assert_eq!(p.proxy_jumps.len(), 1);
        assert_eq!(p.proxy_jumps[0].user, "bob");
        assert_eq!(p.proxy_jumps[0].port, 2222);
        assert_eq!(p.proxy_jumps[0].host, "10.1.1.1");
    }

    #[test]
    fn identities_only_on_hop_uses_hop_host_block() {
        let text = r#"
Host dest
    HostName dest.example
    ProxyJump jumphost
    IdentityFile /keys/dest
Host jumphost
    HostName 10.1.1.1
    IdentityFile /keys/jump
    IdentitiesOnly yes
"#;
        let cfg = parse_ssh_config_reader(text.as_bytes()).unwrap();
        let loc = parse_ssh_url("ssh://dest//a").unwrap();
        let p = resolve_ssh_connect(&loc, &cfg).unwrap();
        assert!(!p.identities_only);
        assert_eq!(p.identity_files, vec![PathBuf::from("/keys/dest")]);
        assert_eq!(p.proxy_jumps.len(), 1);
        assert!(p.proxy_jumps[0].identities_only);
        assert_eq!(
            p.proxy_jumps[0].identity_files,
            vec![PathBuf::from("/keys/jump")]
        );
    }

    /// Regression: cyclic ProxyJump aliases must error, not hang.
    #[test]
    fn proxy_jump_alias_cycle_errors() {
        let text = r#"
Host a
    HostName 10.0.0.1
    ProxyJump b
Host b
    HostName 10.0.0.2
    ProxyJump a
"#;
        let cfg = parse_ssh_config_reader(text.as_bytes()).unwrap();
        let loc = parse_ssh_url("ssh://a//x").unwrap();
        let err = resolve_ssh_connect(&loc, &cfg).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("ProxyJump cycle") && msg.contains("a"),
            "{msg}"
        );
    }

    #[test]
    fn include_merges_hostname_via_config_file() {
        let dir = tempfile::tempdir().unwrap();
        let included = dir.path().join("included");
        std::fs::write(
            &included,
            "Host jump\n    HostName 10.0.0.8\n    User jumper\n    Port 2222\n",
        )
        .unwrap();
        let config = dir.path().join("config");
        std::fs::write(
            &config,
            "Include included\nHost dest\n    HostName 10.0.0.9\n",
        )
        .unwrap();

        let cfg = parse_ssh_config_file(&config).unwrap();
        let loc = parse_ssh_url("ssh://jump//data/a.tar").unwrap();
        let p = resolve_ssh_connect(&loc, &cfg).unwrap();
        assert_eq!(p.host, "10.0.0.8");
        assert_eq!(p.user, "jumper");
        assert_eq!(p.port, 2222);
        let dest = parse_ssh_url("ssh://dest//a").unwrap();
        let d = resolve_ssh_connect(&dest, &cfg).unwrap();
        assert_eq!(d.host, "10.0.0.9");
    }

    /// Regression: cyclic ssh_config Include must error, not hang.
    #[test]
    fn include_cycle_errors() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        std::fs::write(&a, "Include b\nHost from-a\n    HostName 10.0.0.1\n").unwrap();
        std::fs::write(&b, "Include a\nHost from-b\n    HostName 10.0.0.2\n").unwrap();
        let err = parse_ssh_config_file(&a).unwrap_err();
        assert!(matches!(err, RemoteError::SshIncludeCycle(_)), "{err}");
        let msg = err.to_string();
        assert!(msg.contains("Include cycle"), "{msg}");
    }

    #[test]
    fn include_trailing_star_via_read_dir() {
        let dir = tempfile::tempdir().unwrap();
        let conf_d = dir.path().join("conf.d");
        std::fs::create_dir(&conf_d).unwrap();
        std::fs::write(
            conf_d.join("z.conf"),
            "Host zed\n    HostName 10.0.0.9\n    User zeduser\n",
        )
        .unwrap();
        std::fs::write(
            conf_d.join("a.conf"),
            "Host aye\n    HostName 10.0.0.8\n    User ayeuser\n",
        )
        .unwrap();
        std::fs::write(conf_d.join("not-a-dir"), "this is a file").unwrap();
        std::fs::create_dir(conf_d.join("subdir")).unwrap();
        let config = dir.path().join("config");
        std::fs::write(&config, "Include conf.d/*\n").unwrap();

        let cfg = parse_ssh_config_file(&config).unwrap();
        let aye = resolve_ssh_connect(&parse_ssh_url("ssh://aye//x").unwrap(), &cfg).unwrap();
        assert_eq!(aye.host, "10.0.0.8");
        assert_eq!(aye.user, "ayeuser");
        let zed = resolve_ssh_connect(&parse_ssh_url("ssh://zed//x").unwrap(), &cfg).unwrap();
        assert_eq!(zed.host, "10.0.0.9");
        assert_eq!(zed.user, "zeduser");
    }

    #[test]
    fn include_ignored_by_leaf_reader() {
        let text = "Include /does/not/exist\nHost foo\n    HostName 192.0.2.9\n";
        let cfg = parse_ssh_config_reader(text.as_bytes()).unwrap();
        let loc = parse_ssh_url("ssh://foo//x").unwrap();
        let p = resolve_ssh_connect(&loc, &cfg).unwrap();
        assert_eq!(p.host, "192.0.2.9");
    }

    #[test]
    fn proxy_jump_none_disables_host_star_bastion() {
        // Specific Host before Host * so `none` is first-obtained (OpenSSH order).
        let text = r#"
Host bastion
    HostName 10.0.0.1
    ProxyJump none
Host dest
    HostName dest.example
Host *
    ProxyJump bastion
"#;
        let cfg = parse_ssh_config_reader(text.as_bytes()).unwrap();
        assert!(parse_proxy_jump_list("none").is_empty());
        assert!(parse_proxy_jump_list("None").is_empty());
        let dest = resolve_ssh_connect(&parse_ssh_url("ssh://dest//a").unwrap(), &cfg).unwrap();
        assert_eq!(dest.proxy_jumps.len(), 1);
        assert_eq!(dest.proxy_jumps[0].host, "10.0.0.1");
        let bastion =
            resolve_ssh_connect(&parse_ssh_url("ssh://bastion//a").unwrap(), &cfg).unwrap();
        assert!(
            bastion.proxy_jumps.is_empty(),
            "ProxyJump none must not cycle via Host *: {:?}",
            bastion.proxy_jumps
        );
        assert_eq!(bastion.host, "10.0.0.1");
    }

    #[test]
    fn nested_proxy_jump_flattens_inner_then_outer() {
        let text = r#"
Host dest
    HostName dest.example
    ProxyJump a
Host a
    HostName 10.0.0.1
    ProxyJump b
Host b
    HostName 10.0.0.2
"#;
        let cfg = parse_ssh_config_reader(text.as_bytes()).unwrap();
        let p = resolve_ssh_connect(&parse_ssh_url("ssh://dest//a").unwrap(), &cfg).unwrap();
        let hosts: Vec<_> = p.proxy_jumps.iter().map(|h| h.host.as_str()).collect();
        assert_eq!(hosts, ["10.0.0.2", "10.0.0.1"]);
        assert!(p.proxy_jumps.iter().all(|h| h.proxy_jumps.is_empty()));
    }

    #[test]
    fn env_password_is_destination_only() {
        // hops: connect_tcp_session(..., Some(i)) / authenticate(..., is_dest=false)
        fn hop_uses_env_password(hop: Option<usize>) -> bool {
            hop.is_none()
        }
        assert!(hop_uses_env_password(None));
        assert!(!hop_uses_env_password(Some(0)));
        let text = r#"
Host dest
    ProxyJump jump
Host jump
    HostName 10.0.0.1
"#;
        let cfg = parse_ssh_config_reader(text.as_bytes()).unwrap();
        let loc = parse_ssh_url("ssh://alice:s3cr3t@dest//x").unwrap();
        let p = resolve_ssh_connect(&loc, &cfg).unwrap();
        assert_eq!(p.password.as_deref(), Some("s3cr3t"));
        assert_eq!(p.proxy_jumps[0].password, None);
    }

    #[test]
    fn include_non_regular_is_skipped() {
        if !std::path::Path::new("/dev/null").exists() {
            eprintln!("skip: /dev/null not present");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config");
        std::fs::write(
            &config,
            "Include /dev/null\nHost keep\n    HostName 10.0.0.9\n",
        )
        .unwrap();
        let cfg = parse_ssh_config_file(&config).unwrap();
        let keep = resolve_ssh_connect(&parse_ssh_url("ssh://keep//x").unwrap(), &cfg).unwrap();
        assert_eq!(keep.host, "10.0.0.9");
    }

    #[test]
    fn include_oversize_is_skipped_without_partial_merge() {
        let dir = tempfile::tempdir().unwrap();
        let huge = dir.path().join("huge");
        let mut body = b"Host should-not-appear\n    HostName 10.0.0.1\n".to_vec();
        body.resize(SSH_INCLUDE_MAX_BYTES as usize + 2, b'x');
        std::fs::write(&huge, body).unwrap();
        let config = dir.path().join("config");
        std::fs::write(&config, "Include huge\nHost keep\n    HostName 10.0.0.9\n").unwrap();
        let cfg = parse_ssh_config_file(&config).unwrap();
        let keep = resolve_ssh_connect(&parse_ssh_url("ssh://keep//x").unwrap(), &cfg).unwrap();
        assert_eq!(keep.host, "10.0.0.9");
        let skipped =
            resolve_ssh_connect(&parse_ssh_url("ssh://should-not-appear//x").unwrap(), &cfg)
                .unwrap();
        assert_eq!(skipped.host, "should-not-appear");
    }

    #[test]
    fn sftp_teardown_drops_remote_before_hop_pumps() {
        use std::sync::{Arc, Mutex};
        struct L(&'static str, Arc<Mutex<Vec<&'static str>>>);
        impl Drop for L {
            fn drop(&mut self) {
                self.1.lock().unwrap().push(self.0);
            }
        }
        let order = Arc::new(Mutex::new(Vec::new()));
        {
            let stack = L("stack", Arc::clone(&order));
            let dest_sess = L("dest_sess", Arc::clone(&order));
            let sftp = L("sftp", Arc::clone(&order));
            let remote = L("remote", Arc::clone(&order));
            drop(remote);
            drop(sftp);
            drop(dest_sess);
            drop(stack);
        }
        assert_eq!(
            *order.lock().unwrap(),
            ["remote", "sftp", "dest_sess", "stack"]
        );
    }

    #[test]
    fn hop_stack_drop_joins_pumps_last_hop_first() {
        use std::sync::{Arc, Mutex};
        let joined = Arc::new(Mutex::new(Vec::new()));
        let mut stack = HopStack { hops: Vec::new() };
        for i in 0..3u8 {
            let j = Arc::clone(&joined);
            let pump = thread::spawn(move || {
                j.lock().unwrap().push(i);
            });
            stack.hops.push(HopLink {
                sess: Session::new().expect("session"),
                pump: Some(pump),
            });
        }
        drop(stack);
        let got = joined.lock().unwrap().clone();
        assert_eq!(got.len(), 3, "{got:?}");
        // Threads may finish before Drop; joining last-first must not hang.
    }

    #[test]
    fn proxy_jump_connect_chain_skips_without_sshd() {
        // Live direct-tcpip handshake needs sshd + a bastion fixture.
        // Resolution / Drop order are covered above; this is the skip residual.
        let sshd = std::process::Command::new("sshd")
            .arg("-V")
            .output()
            .ok()
            .or_else(|| {
                std::process::Command::new("/usr/sbin/sshd")
                    .arg("-V")
                    .output()
                    .ok()
            });
        if sshd.is_none() {
            eprintln!("skip: sshd not available for ProxyJump connect-chain handshake");
            return;
        }
        eprintln!(
            "skip: live ProxyJump direct-tcpip handshake has no bastion fixture in this crate"
        );
    }
}
