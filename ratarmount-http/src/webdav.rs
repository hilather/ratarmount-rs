//! WebDAV PROPFIND/GET export (P-6) on the HTTP listener.
//!
//! Depth 0/1 `multistatus`; Depth infinity is 403. GET/HEAD reuse the P-5
//! Range handler. PUT/DELETE/MKCOL/MOVE/COPY require a [`WriteOverlay`] (`-w`);
//! without it they return 403. Class-2 exclusive LOCK/UNLOCK (in-memory) and
//! PROPPATCH (live props no-op) are implemented. Basic auth is read from
//! `RATARMOUNT_WEBDAV_USER` / `RATARMOUNT_WEBDAV_PASSWORD` inside `serve_*`
//! when the user env is set. Same-port HTTP+WebDAV mux and Finder/Explorer
//! as a CI bar are residual.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::unix::io::FromRawFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ratarmount_compositing::WriteOverlay;
use ratarmount_core::{is_dir_mode, FileInfo, MountSource};
use ratarmount_export_core::{
    fill_read, overlay_create_file, overlay_mkdir, overlay_rename, overlay_to_io, overlay_unlink,
    parse_export_bind, BindError, ExportStop, DEFAULT_WEBDAV_PORT,
};

use crate::request::{
    archive_path, collect_if_tokens, last_modified_header, percent_encode_segment, PathError,
};

/// Default `--webdav-bind` (`127.0.0.1:20492`). Separate from HTTP 20491.
pub const DEFAULT_WEBDAV_BIND: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, DEFAULT_WEBDAV_PORT));

/// Listen / export options for [`serve_webdav_blocking`] / [`spawn_webdav_thread`].
#[derive(Clone)]
pub struct WebDavOptions {
    pub bind: SocketAddr,
    pub stop: Option<ExportStop>,
    /// PUT/DELETE/MKCOL/MOVE. Callers should also pass this overlay as `source`.
    pub overlay: Option<Arc<WriteOverlay>>,
    pub readahead_bytes: u64,
}

impl Default for WebDavOptions {
    fn default() -> Self {
        Self {
            bind: DEFAULT_WEBDAV_BIND,
            stop: None,
            overlay: None,
            readahead_bytes: 0,
        }
    }
}

impl std::fmt::Debug for WebDavOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebDavOptions")
            .field("bind", &self.bind)
            .field("stop", &self.stop.as_ref().map(|_| "ExportStop"))
            .field("overlay", &self.overlay.is_some())
            .field("readahead_bytes", &self.readahead_bytes)
            .finish()
    }
}

/// Parse `[host:]port` into an IPv4 listen address (default port 20492).
pub fn parse_webdav_bind(s: &str) -> Result<SocketAddr, BindError> {
    parse_export_bind(s, DEFAULT_WEBDAV_PORT)
}

/// DAV compliance class advertised on WebDAV responses.
pub(crate) const DAV_COMPLIANCE: &str = "1,2";

pub(crate) const MAX_LOCKS: usize = 1024;
pub(crate) const DEFAULT_LOCK_TTL_SECS: u64 = 600;
pub(crate) const MAX_LOCK_TTL_SECS: u64 = 3600;

const WEBDAV_USER_ENV: &str = "RATARMOUNT_WEBDAV_USER";
const WEBDAV_PASSWORD_ENV: &str = "RATARMOUNT_WEBDAV_PASSWORD";

/// Crate-internal Basic credentials. Called from `serve_webdav_*` / `spawn_webdav_thread`.
///
/// When the user is `Some` (password may be empty), the listener requires
/// `Authorization: Basic`. Unset user → none-auth.
pub fn webdav_credentials_from_env() -> (Option<String>, Option<String>) {
    let user = match std::env::var(WEBDAV_USER_ENV) {
        Ok(u) if !u.is_empty() => Some(u),
        _ => None,
    };
    let pass = std::env::var(WEBDAV_PASSWORD_ENV).ok();
    (user, pass)
}

/// XOR-loop compare (no `subtle` crate). Length mismatch still scans both sides.
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = a.len() ^ b.len();
    let n = a.len().max(b.len());
    for i in 0..n {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        diff |= (x ^ y) as usize;
    }
    diff == 0
}

pub(crate) fn basic_authorized(
    want: Option<&(String, String)>,
    authorization: Option<&str>,
) -> bool {
    let Some((user, pass)) = want else {
        return true;
    };
    let Some(header) = authorization.map(str::trim).filter(|s| !s.is_empty()) else {
        return false;
    };
    let rest = if header.len() >= 6 && header[..6].eq_ignore_ascii_case("Basic ") {
        header[6..].trim()
    } else {
        return false;
    };
    let Some(decoded) = base64_decode(rest) else {
        return false;
    };
    let expected = format!("{user}:{pass}");
    ct_eq(&decoded, expected.as_bytes())
}

#[allow(clippy::manual_is_multiple_of)] // MSRV 1.74: `is_multiple_of` is newer
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut bytes: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    while bytes.len() % 4 != 0 {
        bytes.push(b'=');
        if bytes.len() > s.len() + 3 {
            return None;
        }
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let pad = chunk.iter().filter(|&&c| c == b'=').count();
        let a = val(chunk[0])?;
        let b = val(chunk[1])?;
        let c = if chunk[2] == b'=' { 0 } else { val(chunk[2])? };
        let d = if chunk[3] == b'=' { 0 } else { val(chunk[3])? };
        let n = ((a as u32) << 18) | ((b as u32) << 12) | ((c as u32) << 6) | (d as u32);
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    Some(out)
}

/// Encode `user:pass` as `Basic …` (tests / debug helpers).
#[cfg(test)]
pub(crate) fn basic_auth_header(user: &str, pass: &str) -> String {
    format!(
        "Basic {}",
        base64_encode(format!("{user}:{pass}").as_bytes())
    )
}

#[cfg(test)]
fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 3 <= data.len() {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | (data[i + 2] as u32);
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
        out.push(TABLE[(n & 0x3f) as usize] as char);
        i += 3;
    }
    match data.len() - i {
        1 => {
            let n = (data[i] as u32) << 16;
            out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
            out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
            out.push('=');
            out.push('=');
        }
        2 => {
            let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8);
            out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
            out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
            out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
            out.push('=');
        }
        _ => {}
    }
    out
}

/// In-memory exclusive write locks (process-local; cap [`MAX_LOCKS`]).
#[derive(Default)]
pub(crate) struct LockTable {
    by_path: HashMap<String, LockEntry>,
    by_token: HashMap<String, String>,
}

pub(crate) struct LockEntry {
    pub token: String,
    pub owner: String,
    pub expires: Instant,
    pub timeout_secs: u64,
}

impl LockTable {
    pub(crate) fn expire(&mut self) {
        let now = Instant::now();
        let expired: Vec<String> = self
            .by_path
            .iter()
            .filter(|(_, e)| e.expires <= now)
            .map(|(p, _)| p.clone())
            .collect();
        for p in expired {
            if let Some(e) = self.by_path.remove(&p) {
                self.by_token.remove(&e.token);
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.by_path.len()
    }

    pub(crate) fn get_path(&self, path: &str) -> Option<&LockEntry> {
        self.by_path.get(path)
    }

    pub(crate) fn insert(&mut self, path: String, entry: LockEntry) -> bool {
        if self.by_path.len() >= MAX_LOCKS && !self.by_path.contains_key(&path) {
            return false;
        }
        if let Some(old) = self.by_path.remove(&path) {
            self.by_token.remove(&old.token);
        }
        self.by_token.insert(entry.token.clone(), path.clone());
        self.by_path.insert(path, entry);
        true
    }

    pub(crate) fn refresh(&mut self, path: &str, ttl: Duration) -> Option<&LockEntry> {
        let e = self.by_path.get_mut(path)?;
        e.timeout_secs = ttl.as_secs().clamp(1, MAX_LOCK_TTL_SECS);
        e.expires = Instant::now() + Duration::from_secs(e.timeout_secs);
        self.by_path.get(path)
    }

    pub(crate) fn remove_token(&mut self, token: &str) -> Option<String> {
        let path = self.by_token.remove(token)?;
        self.by_path.remove(&path);
        Some(path)
    }

    pub(crate) fn remove_path(&mut self, path: &str) {
        if let Some(e) = self.by_path.remove(path) {
            self.by_token.remove(&e.token);
        }
    }

    pub(crate) fn token_path(&self, token: &str) -> Option<&str> {
        self.by_token.get(token).map(String::as_str)
    }
}

pub(crate) fn new_lock_token() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let mix =
        t.as_nanos() as u64 ^ u64::from(std::process::id()).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("opaquelocktoken:{mix:016x}{n:016x}")
}

pub(crate) fn parse_timeout_header(header: Option<&str>) -> u64 {
    let Some(h) = header.map(str::trim).filter(|s| !s.is_empty()) else {
        return DEFAULT_LOCK_TTL_SECS;
    };
    for part in h.split(',') {
        let p = part.trim();
        let digits = if let Some(rest) = p.strip_prefix("Second-") {
            rest
        } else if p.len() > 7 && p[..7].eq_ignore_ascii_case("Second-") {
            &p[7..]
        } else {
            continue;
        };
        if let Ok(n) = digits.parse::<u64>() {
            return n.clamp(1, MAX_LOCK_TTL_SECS);
        }
    }
    DEFAULT_LOCK_TTL_SECS
}

pub(crate) fn if_list_contains_token(if_header: Option<&str>, token: &str) -> bool {
    let Some(h) = if_header else {
        return false;
    };
    collect_if_tokens(h)
        .iter()
        .any(|t| ct_eq(t.as_bytes(), token.as_bytes()))
}

pub(crate) fn lock_body_is_shared(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    lower.contains("<d:shared") || lower.contains("<shared")
}

pub(crate) fn extract_lock_owner(xml: &str) -> String {
    let lower = xml.to_ascii_lowercase();
    for tag in ["<d:owner>", "<owner>"] {
        if let Some(i) = lower.find(tag) {
            let start = i + tag.len();
            if let Some(end) = lower[start..].find("</") {
                return xml[start..start + end].trim().to_string();
            }
        }
    }
    String::new()
}

pub(crate) fn token_debug_prefix(token: &str) -> &str {
    let hex = token.strip_prefix("opaquelocktoken:").unwrap_or(token);
    let n = hex.len().min(8);
    &hex[..n]
}

pub(crate) fn lockdiscovery_xml(path: &str, entry: &LockEntry, is_dir: bool) -> String {
    let href = xml_escape(&href_for(path, is_dir));
    let token_esc = xml_escape(&entry.token);
    let now = Instant::now();
    let remain = entry
        .expires
        .saturating_duration_since(now)
        .as_secs()
        .max(1);
    let mut s = String::from(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<D:prop xmlns:D=\"DAV:\">\n  <D:lockdiscovery>\n    <D:activelock>\n      <D:locktype><D:write/></D:locktype>\n      <D:lockscope><D:exclusive/></D:lockscope>\n      <D:depth>0</D:depth>\n",
    );
    s.push_str(&format!("      <D:timeout>Second-{remain}</D:timeout>\n"));
    s.push_str("      <D:locktoken><D:href>");
    s.push_str(&token_esc);
    s.push_str("</D:href></D:locktoken>\n      <D:lockroot><D:href>");
    s.push_str(&href);
    s.push_str("</D:href></D:lockroot>\n");
    if !entry.owner.is_empty() {
        s.push_str("      <D:owner>");
        s.push_str(&xml_escape(&entry.owner));
        s.push_str("</D:owner>\n");
    }
    s.push_str("    </D:activelock>\n  </D:lockdiscovery>\n</D:prop>\n");
    s
}

/// Live DAV properties we already emit on PROPFIND (PROPPATCH is a no-op).
fn is_live_prop(local: &str) -> bool {
    matches!(
        local,
        "getcontentlength" | "getlastmodified" | "resourcetype"
    )
}

/// Local names of properties named in a PROPPATCH body (`set`/`remove`).
pub(crate) fn proppatch_prop_local_names(xml: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find('<') {
        rest = &rest[start + 1..];
        if rest.starts_with('/') || rest.starts_with('!') || rest.starts_with('?') {
            if let Some(e) = rest.find('>') {
                rest = &rest[e + 1..];
            } else {
                break;
            }
            continue;
        }
        let name_end = rest
            .find(|c: char| c.is_whitespace() || c == '>' || c == '/')
            .unwrap_or(rest.len());
        let raw = &rest[..name_end];
        let local = raw.rsplit(':').next().unwrap_or(raw);
        let lower = local.to_ascii_lowercase();
        if !matches!(
            lower.as_str(),
            "" | "propertyupdate" | "set" | "remove" | "prop"
        ) {
            names.push(lower);
        }
        if let Some(e) = rest.find('>') {
            rest = &rest[e + 1..];
        } else {
            break;
        }
    }
    names
}

pub(crate) fn proppatch_multistatus(path: &str, is_dir: bool, xml_body: &str) -> String {
    let href = xml_escape(&href_for(path, is_dir));
    let names = proppatch_prop_local_names(xml_body);
    let mut live: Vec<&str> = Vec::new();
    let mut dead: Vec<&str> = Vec::new();
    for n in &names {
        if is_live_prop(n) {
            live.push(n.as_str());
        } else {
            dead.push(n.as_str());
        }
    }
    let mut body = String::from(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<D:multistatus xmlns:D=\"DAV:\">\n  <D:response>\n    <D:href>",
    );
    body.push_str(&href);
    body.push_str("</D:href>\n");
    if !live.is_empty() {
        body.push_str("    <D:propstat>\n      <D:prop>\n");
        for n in live {
            body.push_str("        <D:");
            body.push_str(n);
            body.push_str("/>\n");
        }
        body.push_str(
            "      </D:prop>\n      <D:status>HTTP/1.1 200 OK</D:status>\n    </D:propstat>\n",
        );
    }
    if !dead.is_empty() {
        body.push_str("    <D:propstat>\n      <D:prop>\n");
        for n in dead {
            body.push_str("        <D:");
            body.push_str(n);
            body.push_str("/>\n");
        }
        body.push_str(
            "      </D:prop>\n      <D:status>HTTP/1.1 403 Forbidden</D:status>\n    </D:propstat>\n",
        );
    }
    body.push_str("  </D:response>\n</D:multistatus>\n");
    body
}

/// RFC 4918 Depth: only 0 and 1 in v1. Missing / infinity / other → 403.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PropfindDepth {
    Zero,
    One,
    ForbiddenInfinity,
}

pub(crate) fn parse_depth(header: Option<&str>) -> PropfindDepth {
    match header.map(str::trim).filter(|s| !s.is_empty()) {
        Some("0") => PropfindDepth::Zero,
        Some("1") => PropfindDepth::One,
        // RFC 4918: missing Depth is treated as infinity.
        _ => PropfindDepth::ForbiddenInfinity,
    }
}

pub(crate) fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

/// Path-absolute href; collections get a trailing `/`.
pub(crate) fn href_for(path: &str, is_dir: bool) -> String {
    if path == "/" {
        return "/".into();
    }
    let mut href = String::from("/");
    for seg in path.trim_start_matches('/').split('/') {
        if seg.is_empty() {
            continue;
        }
        href.push_str(&percent_encode_segment(seg));
        href.push('/');
    }
    if !is_dir && href.len() > 1 {
        href.pop();
    }
    href
}

fn response_xml(href: &str, fi: &FileInfo) -> String {
    let is_dir = is_dir_mode(fi.mode);
    let href_esc = xml_escape(href);
    let mut s = String::new();
    s.push_str("  <D:response>\n    <D:href>");
    s.push_str(&href_esc);
    s.push_str("</D:href>\n    <D:propstat>\n      <D:prop>\n");
    if is_dir {
        s.push_str("        <D:resourcetype><D:collection/></D:resourcetype>\n");
    } else {
        s.push_str("        <D:resourcetype/>\n");
        s.push_str("        <D:getcontentlength>");
        s.push_str(&fi.size.to_string());
        s.push_str("</D:getcontentlength>\n");
    }
    if let Some(lm) = last_modified_header(fi.mtime) {
        s.push_str("        <D:getlastmodified>");
        s.push_str(&xml_escape(&lm));
        s.push_str("</D:getlastmodified>\n");
    }
    s.push_str("      </D:prop>\n      <D:status>HTTP/1.1 200 OK</D:status>\n    </D:propstat>\n  </D:response>\n");
    s
}

/// 207 Multi-Status body for Depth 0 (self) or 1 (self + children).
pub(crate) fn propfind_multistatus(
    source: &dyn MountSource,
    path: &str,
    fi: &FileInfo,
    depth: PropfindDepth,
) -> String {
    let mut body = String::from(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<D:multistatus xmlns:D=\"DAV:\">\n",
    );
    body.push_str(&response_xml(&href_for(path, is_dir_mode(fi.mode)), fi));
    if depth == PropfindDepth::One && is_dir_mode(fi.mode) {
        if let Some(dents) = source.list_dirents(path) {
            for d in dents {
                let child = if path == "/" {
                    format!("/{}", d.name)
                } else {
                    format!("{path}/{}", d.name)
                };
                let child_fi = source.lookup(&child, 0).unwrap_or(FileInfo {
                    size: d.size,
                    mtime: 0.0,
                    mode: d.mode,
                    linkname: String::new(),
                    uid: 0,
                    gid: 0,
                    userdata: Vec::new(),
                });
                body.push_str(&response_xml(
                    &href_for(&child, is_dir_mode(child_fi.mode)),
                    &child_fi,
                ));
            }
        }
    }
    body.push_str("</D:multistatus>\n");
    body
}

fn parent_path(path: &str) -> String {
    if path == "/" {
        return "/".into();
    }
    match path.rsplit_once('/') {
        Some(("", _)) | None => "/".into(),
        Some((p, _)) => p.to_string(),
    }
}

/// True when `path`'s parent exists as a directory in `source`.
pub(crate) fn parent_is_dir(source: &dyn MountSource, path: &str) -> bool {
    let parent = parent_path(path);
    if parent == "/" {
        return true;
    }
    source
        .lookup(&parent, 0)
        .map(|fi| is_dir_mode(fi.mode))
        .unwrap_or(false)
}

pub(crate) fn destination_archive_path(dest: &str) -> Result<String, PathError> {
    archive_path(dest)
}

pub(crate) const MAX_PUT_BYTES: u64 = 64 * 1024 * 1024;

/// Create/replace `path` from leftover header bytes + the rest of `stream`.
///
/// Returns `true` when the resource already existed (204) vs created (201).
pub(crate) fn put_overlay(
    overlay: &WriteOverlay,
    path: &str,
    stream: &mut dyn Read,
    leftover: &[u8],
    content_len: u64,
) -> io::Result<bool> {
    let existed = MountSource::lookup(overlay, path, 0).is_some();
    let fd = overlay_create_file(overlay, path, 0o644)?;
    // SAFETY: `overlay_create_file` returns a new fd we own.
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    let result = (|| -> io::Result<()> {
        let mut remaining = content_len;
        if !leftover.is_empty() && remaining > 0 {
            let n = leftover.len().min(remaining as usize);
            file.write_all(&leftover[..n])?;
            remaining -= n as u64;
        }
        let mut buf = vec![0u8; 64 * 1024];
        while remaining > 0 {
            let want = (remaining as usize).min(buf.len());
            let n = stream.read(&mut buf[..want])?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "short PUT body",
                ));
            }
            file.write_all(&buf[..n])?;
            remaining -= n as u64;
        }
        file.flush()?;
        Ok(())
    })();
    overlay.finish_owned_write_fd(file);
    result?;
    Ok(existed)
}

/// Copy `src` onto overlay `dest` without reading an HTTP body (not [`put_overlay`]).
pub(crate) fn copy_overlay_file(
    overlay: &WriteOverlay,
    source: &dyn MountSource,
    src: &str,
    dest: &str,
) -> io::Result<()> {
    let Some(fi) = source.lookup(src, 0) else {
        return Err(io::Error::new(io::ErrorKind::NotFound, src));
    };
    if is_dir_mode(fi.mode) {
        return Err(io::Error::new(
            io::ErrorKind::IsADirectory,
            "COPY source is a collection",
        ));
    }
    if fi.size > MAX_PUT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "COPY too large",
        ));
    }
    let fd = overlay_create_file(overlay, dest, 0o644)?;
    // SAFETY: `overlay_create_file` returns a new fd we own.
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    let result = (|| -> io::Result<()> {
        if fi.size == 0 {
            file.flush()?;
            return Ok(());
        }
        let mut reader = source.open(&fi, 0)?;
        let mut remaining = fi.size;
        let mut buf = vec![0u8; 64 * 1024];
        while remaining > 0 {
            let want = (remaining as usize).min(buf.len());
            let n = fill_read(reader.as_mut(), &mut buf[..want])?;
            if n == 0 {
                break;
            }
            file.write_all(&buf[..n])?;
            remaining -= n as u64;
        }
        file.flush()?;
        Ok(())
    })();
    overlay.finish_owned_write_fd(file);
    result
}

pub(crate) fn delete_overlay(overlay: &WriteOverlay, path: &str) -> io::Result<()> {
    let is_dir = MountSource::lookup(overlay, path, 0)
        .map(|fi| is_dir_mode(fi.mode))
        .unwrap_or(false);
    if is_dir {
        overlay.rmdir(path).map_err(overlay_to_io)
    } else {
        overlay_unlink(overlay, path)
    }
}

pub(crate) fn mkcol_overlay(overlay: &WriteOverlay, path: &str) -> io::Result<()> {
    overlay_mkdir(overlay, path, 0o755)
}

pub(crate) fn move_overlay(overlay: &WriteOverlay, from: &str, to: &str) -> io::Result<()> {
    overlay_rename(overlay, from, to)
}

pub(crate) fn overlay_status(err: &io::Error) -> (u16, &'static str) {
    match err.kind() {
        io::ErrorKind::NotFound => (404, "Not Found"),
        io::ErrorKind::PermissionDenied => (403, "Forbidden"),
        io::ErrorKind::AlreadyExists => (405, "Method Not Allowed"),
        io::ErrorKind::InvalidInput => (400, "Bad Request"),
        io::ErrorKind::IsADirectory | io::ErrorKind::NotADirectory => (409, "Conflict"),
        _ => {
            let msg = err.to_string();
            if msg.contains("not empty") {
                (409, "Conflict")
            } else {
                (500, "Internal Server Error")
            }
        }
    }
}

/// Drain up to `content_len` leftover+stream bytes (PROPFIND/MKCOL bodies).
pub(crate) fn drain_body(
    stream: &mut dyn Read,
    leftover: &[u8],
    content_len: u64,
) -> io::Result<()> {
    let mut remaining = content_len.saturating_sub(leftover.len() as u64);
    let mut buf = [0u8; 4096];
    while remaining > 0 {
        let want = (remaining as usize).min(buf.len());
        let n = stream.read(&mut buf[..want])?;
        if n == 0 {
            break;
        }
        remaining -= n as u64;
    }
    Ok(())
}

/// Read leftover + stream into a buffer, capped at `cap` (LOCK/PROPPATCH XML).
pub(crate) fn read_limited_body(
    stream: &mut dyn Read,
    leftover: &[u8],
    content_len: u64,
    cap: usize,
) -> io::Result<Vec<u8>> {
    let take = (content_len as usize).min(cap);
    let mut body = Vec::with_capacity(take);
    let mut remaining = take;
    if !leftover.is_empty() && remaining > 0 {
        let n = leftover.len().min(remaining);
        body.extend_from_slice(&leftover[..n]);
        remaining -= n;
    }
    while remaining > 0 {
        let mut buf = vec![0u8; remaining.min(64 * 1024)];
        let n = stream.read(&mut buf)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&buf[..n]);
        remaining -= n;
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratarmount_core::{create_root_file_info, S_IFDIR, S_IFREG};

    fn file_fi(size: u64, mtime: f64) -> FileInfo {
        FileInfo {
            size,
            mtime,
            mode: S_IFREG | 0o644,
            linkname: String::new(),
            uid: 0,
            gid: 0,
            userdata: Vec::new(),
        }
    }

    #[test]
    fn depth_only_zero_and_one() {
        assert_eq!(parse_depth(Some("0")), PropfindDepth::Zero);
        assert_eq!(parse_depth(Some("1")), PropfindDepth::One);
        assert_eq!(
            parse_depth(Some("infinity")),
            PropfindDepth::ForbiddenInfinity
        );
        assert_eq!(
            parse_depth(Some("Infinity")),
            PropfindDepth::ForbiddenInfinity
        );
        assert_eq!(parse_depth(None), PropfindDepth::ForbiddenInfinity);
        assert_eq!(parse_depth(Some("")), PropfindDepth::ForbiddenInfinity);
        assert_eq!(parse_depth(Some("2")), PropfindDepth::ForbiddenInfinity);
    }

    #[test]
    fn href_collections_have_slash() {
        assert_eq!(href_for("/", true), "/");
        assert_eq!(href_for("/sub", true), "/sub/");
        assert_eq!(href_for("/hello.txt", false), "/hello.txt");
        assert_eq!(href_for("/a b", false), "/a%20b");
    }

    #[test]
    fn response_xml_has_length_and_collection() {
        let file = response_xml("/hello.txt", &file_fi(26, 1_592_222_400.0));
        assert!(file.contains("<D:getcontentlength>26</D:getcontentlength>"));
        assert!(file.contains("<D:resourcetype/>"));
        assert!(file.contains("Mon, 15 Jun 2020 12:00:00 GMT"));
        assert!(!file.contains("<D:collection/>"));

        let mut dir = create_root_file_info();
        dir.mode = S_IFDIR | 0o755;
        let d = response_xml("/sub/", &dir);
        assert!(d.contains("<D:collection/>"));
        assert!(!d.contains("getcontentlength"));
    }

    #[test]
    fn parse_webdav_bind_empty_is_20492() {
        assert_eq!(parse_webdav_bind("").unwrap(), DEFAULT_WEBDAV_BIND);
        assert_eq!(
            parse_webdav_bind("20492").unwrap().port(),
            DEFAULT_WEBDAV_PORT
        );
        assert_eq!(DEFAULT_WEBDAV_PORT, 20492);
        assert_ne!(DEFAULT_WEBDAV_PORT, 20491);
    }

    #[test]
    fn lock_table_cap_is_1024() {
        let mut t = LockTable::default();
        let ttl = Duration::from_secs(600);
        for i in 0..MAX_LOCKS {
            let token = format!("opaquelocktoken:{i:032x}");
            assert!(
                t.insert(
                    format!("/p{i}"),
                    LockEntry {
                        token,
                        owner: String::new(),
                        expires: Instant::now() + ttl,
                        timeout_secs: 600,
                    }
                ),
                "insert {i}"
            );
        }
        assert_eq!(t.len(), MAX_LOCKS);
        assert!(
            !t.insert(
                "/overflow".into(),
                LockEntry {
                    token: "opaquelocktoken:ff".into(),
                    owner: String::new(),
                    expires: Instant::now() + ttl,
                    timeout_secs: 600,
                }
            ),
            "excess LOCK must be rejected"
        );
        assert!(t.get_path("/p0").is_some());
        assert!(t.refresh("/p0", Duration::from_secs(60)).is_some());
    }

    #[test]
    fn parse_timeout_second_n_capped() {
        assert_eq!(parse_timeout_header(None), DEFAULT_LOCK_TTL_SECS);
        assert_eq!(parse_timeout_header(Some("Second-30")), 30);
        assert_eq!(
            parse_timeout_header(Some("Second-99999")),
            MAX_LOCK_TTL_SECS
        );
        assert_eq!(parse_timeout_header(Some("Infinite, Second-120")), 120);
        assert_eq!(
            parse_timeout_header(Some("Infinite")),
            DEFAULT_LOCK_TTL_SECS
        );
    }

    #[test]
    fn basic_ct_eq_and_header() {
        let want = ("dav".to_string(), "s3cret".to_string());
        let hdr = basic_auth_header("dav", "s3cret");
        assert!(basic_authorized(Some(&want), Some(&hdr)));
        assert!(!basic_authorized(Some(&want), None));
        assert!(!basic_authorized(
            Some(&want),
            Some(&basic_auth_header("dav", "wrong"))
        ));
        assert!(basic_authorized(None, None));
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"ab"));
    }

    #[test]
    fn proppatch_splits_live_and_dead() {
        let xml = concat!(
            "<D:propertyupdate xmlns:D=\"DAV:\" xmlns:Z=\"urn:z\">",
            "<D:set><D:prop>",
            "<D:getlastmodified>x</D:getlastmodified>",
            "<Z:Win32LastModifiedTime>y</Z:Win32LastModifiedTime>",
            "</D:prop></D:set></D:propertyupdate>"
        );
        let names = proppatch_prop_local_names(xml);
        assert!(names.contains(&"getlastmodified".into()), "{names:?}");
        assert!(names.contains(&"win32lastmodifiedtime".into()), "{names:?}");
        let body = proppatch_multistatus("/hello.txt", false, xml);
        assert!(body.contains("HTTP/1.1 200 OK"), "{body}");
        assert!(body.contains("HTTP/1.1 403 Forbidden"), "{body}");
    }

    #[test]
    fn shared_lock_body_detected() {
        assert!(lock_body_is_shared(
            "<D:lockscope><D:shared/></D:lockscope>"
        ));
        assert!(!lock_body_is_shared(
            "<D:lockscope><D:exclusive/></D:lockscope>"
        ));
    }
}
