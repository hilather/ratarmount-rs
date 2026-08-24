//! Remote directory mounts (F-1): S3 prefixes, SSH dirs, WebDAV collections, HTTP autoindex.
//!
//! [`DropboxMountSource`] stays on its own type. Later schemes (GCS/Azure/rclone/IPFS)
//! export `open_*_folder` from their modules and must not edit this file.

use std::collections::BTreeMap;
use std::io::{self, Read};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use log::debug;
use ratarmount_core::{
    create_root_file_info, is_dir_mode, normpath, ArchiveRead, CheapDirent, FileInfo, ListResult,
    MountSource, UserData, S_IFDIR, S_IFMT, S_IFREG,
};
use url::Url;

use crate::s3::{
    list_s3_prefix, parse_s3_url_allow_prefix, s3_location_is_dir, S3Location, S3RangeFile,
};
use crate::ssh::{
    fetch_ssh_location_to_temp, list_ssh_path, parse_ssh_url, ssh_path_is_dir, SshLocation,
};
use crate::webdav::{parse_webdav_url, propfind_entries, webdav_is_collection, WebDavLocation};
use crate::{
    open_http_range, parse_http_url, HttpAuth, HttpLocation, HttpRangeFile, RemoteError, Result,
    USER_AGENT,
};

/// Default listing-cache TTL (seconds), matching Dropbox.
pub const DEFAULT_REMOTE_LIST_TTL_SECS: u64 = 30;

/// Env override for [`DEFAULT_REMOTE_LIST_TTL_SECS`] (`0` disables caching).
pub const REMOTE_LIST_TTL_ENV: &str = "RATARMOUNT_REMOTE_LIST_TTL_SECS";

/// One child of a remote directory.
#[derive(Debug, Clone, PartialEq)]
pub struct RemoteDirent {
    pub name: String,
    /// Backend-native path (S3 key, SSH path, or `http(s)://` URL).
    pub remote_path: String,
    pub is_dir: bool,
    pub size: u64,
    pub mtime: f64,
}

impl RemoteDirent {
    fn to_file_info(&self) -> FileInfo {
        FileInfo {
            size: self.size,
            mtime: self.mtime,
            mode: if self.is_dir {
                S_IFDIR | 0o755
            } else {
                S_IFREG | 0o644
            },
            linkname: String::new(),
            uid: 0,
            gid: 0,
            userdata: vec![UserData::Other(self.remote_path.clone())],
        }
    }
}

/// Backend listing / open / dir-probe operations for [`RemoteFolderMountSource`].
pub trait RemoteListing: Send + Sync {
    fn list(&self, remote_path: &str) -> Result<Vec<RemoteDirent>>;
    fn stat(&self, remote_path: &str) -> Result<Option<RemoteDirent>> {
        let (parent, name) = split_parent(remote_path);
        if name.is_empty() {
            return Ok(None);
        }
        Ok(self.list(&parent)?.into_iter().find(|e| e.name == name))
    }
    fn open_range(&self, remote_path: &str, size: u64) -> Result<Box<dyn ArchiveRead>>;
    /// `true` when `remote_path` is a directory (trailing slash, collection, LIST, …).
    fn is_dir(&self, remote_path: &str) -> Result<bool> {
        Ok(self.stat(remote_path)?.map(|e| e.is_dir).unwrap_or(false))
    }
    fn join(&self, root: &str, rel: &str) -> String {
        join_path(root, rel)
    }
}

struct CachedListing {
    entries: Vec<RemoteDirent>,
    fetched_at: Instant,
}

/// Mount a remote folder as a [`MountSource`] (list + Range/download-on-open).
///
/// Listings are cached with a TTL ([`DEFAULT_REMOTE_LIST_TTL_SECS`] /
/// [`REMOTE_LIST_TTL_ENV`]). Cheap [`MountSource::list_dirents`] carries real size + mode.
pub struct RemoteFolderMountSource<L: RemoteListing> {
    root: String,
    listing: L,
    list_ttl: Duration,
    listing_cache: Mutex<BTreeMap<String, CachedListing>>,
}

impl<L: RemoteListing> std::fmt::Debug for RemoteFolderMountSource<L> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteFolderMountSource")
            .field("root", &self.root)
            .field("list_ttl_secs", &self.list_ttl.as_secs())
            .finish_non_exhaustive()
    }
}

impl<L: RemoteListing> RemoteFolderMountSource<L> {
    pub fn new(root: String, listing: L) -> Self {
        Self {
            root,
            listing,
            list_ttl: Duration::from_secs(remote_list_ttl_secs()),
            listing_cache: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn with_list_ttl_secs(mut self, secs: u64) -> Self {
        self.list_ttl = Duration::from_secs(secs);
        self
    }

    fn remote_for(&self, virtual_path: &str) -> String {
        let v = normpath(virtual_path);
        if v == "/" {
            return self.root.clone();
        }
        self.listing.join(&self.root, v.trim_start_matches('/'))
    }

    fn list_dir_entries(&self, virtual_path: &str) -> Result<Vec<RemoteDirent>> {
        let v = normpath(virtual_path);
        let now = Instant::now();
        {
            let cache = self
                .listing_cache
                .lock()
                .map_err(|_| RemoteError::Url("listing cache lock poisoned".into()))?;
            if let Some(cached) = cache.get(&v) {
                if !self.list_ttl.is_zero() && now.duration_since(cached.fetched_at) < self.list_ttl
                {
                    return Ok(cached.entries.clone());
                }
            }
        }
        let remote = self.remote_for(&v);
        let entries = self.listing.list(&remote)?;
        let mut cache = self
            .listing_cache
            .lock()
            .map_err(|_| RemoteError::Url("listing cache lock poisoned".into()))?;
        cache.insert(
            v,
            CachedListing {
                entries: entries.clone(),
                fetched_at: Instant::now(),
            },
        );
        Ok(entries)
    }

    fn lookup_entry(&self, virtual_path: &str) -> Result<Option<RemoteDirent>> {
        let v = normpath(virtual_path);
        if v == "/" {
            return Ok(Some(RemoteDirent {
                name: String::new(),
                remote_path: self.root.clone(),
                is_dir: true,
                size: 0,
                mtime: 0.0,
            }));
        }
        let parent = match v.rsplit_once('/') {
            Some(("", _)) => "/".to_string(),
            Some((p, _)) if !p.is_empty() => p.to_string(),
            _ => "/".to_string(),
        };
        let name = v.rsplit('/').next().unwrap_or("").to_string();
        let entries = self.list_dir_entries(&parent)?;
        if let Some(ent) = entries.into_iter().find(|e| e.name == name) {
            return Ok(Some(ent));
        }
        let remote = self.remote_for(&v);
        self.listing.stat(&remote)
    }
}

impl<L: RemoteListing + 'static> MountSource for RemoteFolderMountSource<L> {
    fn list(&self, path: &str) -> Option<ListResult> {
        let entries = self.list_dir_entries(path).ok()?;
        let mut map = BTreeMap::new();
        for ent in entries {
            let mut fi = ent.to_file_info();
            if fi.userdata.is_empty() {
                fi.userdata = vec![UserData::Other(ent.remote_path.clone())];
            }
            map.insert(ent.name, fi);
        }
        Some(ListResult::Infos(map))
    }

    fn list_dirents(&self, path: &str) -> Option<Vec<CheapDirent>> {
        let entries = self.list_dir_entries(path).ok()?;
        Some(
            entries
                .into_iter()
                .map(|ent| CheapDirent {
                    name: ent.name,
                    mode: if ent.is_dir {
                        S_IFDIR | 0o755
                    } else {
                        S_IFREG | 0o644
                    },
                    size: ent.size,
                })
                .collect(),
        )
    }

    fn lookup(&self, path: &str, _file_version: i32) -> Option<FileInfo> {
        let path = normpath(path);
        if path == "/" {
            return Some(create_root_file_info());
        }
        let ent = self.lookup_entry(&path).ok().flatten()?;
        Some(ent.to_file_info())
    }

    fn open(&self, file_info: &FileInfo, _buffering: i32) -> io::Result<Box<dyn ArchiveRead>> {
        if is_dir_mode(file_info.mode) || file_info.mode & S_IFMT == S_IFDIR {
            return Err(io::Error::new(
                io::ErrorKind::IsADirectory,
                "is a directory",
            ));
        }
        let remote = file_info
            .userdata
            .iter()
            .rev()
            .find_map(|u| match u {
                UserData::Other(s) => Some(s.as_str()),
                _ => None,
            })
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "missing remote path userdata")
            })?;
        if remote.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty remote path",
            ));
        }
        self.listing
            .open_range(remote, file_info.size)
            .map_err(|e| io::Error::other(e.to_string()))
    }

    fn is_immutable(&self) -> bool {
        false
    }
}

/// Listing cache TTL in seconds ([`REMOTE_LIST_TTL_ENV`], default 30). `0` disables caching.
pub fn remote_list_ttl_secs() -> u64 {
    match std::env::var(REMOTE_LIST_TTL_ENV) {
        Ok(s) if !s.is_empty() => s.parse::<u64>().unwrap_or(DEFAULT_REMOTE_LIST_TTL_SECS),
        _ => DEFAULT_REMOTE_LIST_TTL_SECS,
    }
}

/// F-1 backends only (`s3` / `ssh` / `webdav` / `http`). Other schemes: `Ok(None)`.
pub fn try_open_remote_folder(s: &str) -> Result<Option<Arc<dyn MountSource>>> {
    let Some(scheme) = s.split_once("://").map(|(a, _)| a) else {
        return Ok(None);
    };
    match scheme.to_ascii_lowercase().as_str() {
        "s3" => try_open_s3_folder(s),
        "ssh" | "sftp" | "scp" => try_open_ssh_folder(s),
        "webdav" | "webdavs" => try_open_webdav_folder(s),
        "http" | "https" => try_open_http_folder(s),
        _ => Ok(None),
    }
}

fn try_open_s3_folder(s: &str) -> Result<Option<Arc<dyn MountSource>>> {
    let loc = parse_s3_url_allow_prefix(s)?;
    if !s3_location_is_dir(&loc)? {
        return Ok(None);
    }
    let listing = S3Listing {
        bucket: loc.bucket.clone(),
    };
    Ok(Some(Arc::new(RemoteFolderMountSource::new(
        loc.key, listing,
    ))))
}

fn try_open_ssh_folder(s: &str) -> Result<Option<Arc<dyn MountSource>>> {
    let loc = parse_ssh_url(s)?;
    if !ssh_path_is_dir(&loc, &loc.path)? {
        return Ok(None);
    }
    let root = loc.path.clone();
    Ok(Some(Arc::new(RemoteFolderMountSource::new(
        root,
        SshListing { loc },
    ))))
}

fn try_open_webdav_folder(s: &str) -> Result<Option<Arc<dyn MountSource>>> {
    let loc = parse_webdav_url(s)?;
    if !webdav_is_collection(&loc)? {
        return Ok(None);
    }
    let root = loc.http_url.clone();
    Ok(Some(Arc::new(RemoteFolderMountSource::new(
        root,
        WebDavListing { loc },
    ))))
}

fn try_open_http_folder(s: &str) -> Result<Option<Arc<dyn MountSource>>> {
    let loc = parse_http_url(s)?;
    if !http_url_is_dir(&loc.url, loc.auth.as_ref(), loc.cookie.as_deref())? {
        return Ok(None);
    }
    let root = if loc.url.ends_with('/') {
        loc.url.clone()
    } else {
        format!("{}/", loc.url)
    };
    Ok(Some(Arc::new(RemoteFolderMountSource::new(
        root,
        HttpIndexListing { loc },
    ))))
}

// ---------------------------------------------------------------------------
// Backends
// ---------------------------------------------------------------------------

struct S3Listing {
    bucket: String,
}

impl RemoteListing for S3Listing {
    fn list(&self, remote_path: &str) -> Result<Vec<RemoteDirent>> {
        let loc = S3Location {
            bucket: self.bucket.clone(),
            key: remote_path.trim_start_matches('/').to_string(),
        };
        Ok(list_s3_prefix(&loc)?
            .into_iter()
            .map(|e| RemoteDirent {
                name: e.name,
                remote_path: e.key,
                is_dir: e.is_dir,
                size: e.size,
                mtime: 0.0,
            })
            .collect())
    }

    fn is_dir(&self, remote_path: &str) -> Result<bool> {
        s3_location_is_dir(&S3Location {
            bucket: self.bucket.clone(),
            key: remote_path.trim_start_matches('/').to_string(),
        })
    }

    fn open_range(&self, remote_path: &str, size: u64) -> Result<Box<dyn ArchiveRead>> {
        let loc = S3Location {
            bucket: self.bucket.clone(),
            key: remote_path.to_string(),
        };
        // Known size from listing: live Range, no full-object download.
        if size > 0 {
            Ok(Box::new(S3RangeFile::range_backed(loc, size)))
        } else {
            Ok(Box::new(S3RangeFile::open_location(&loc)?))
        }
    }
}

struct SshListing {
    loc: SshLocation,
}

impl RemoteListing for SshListing {
    fn list(&self, remote_path: &str) -> Result<Vec<RemoteDirent>> {
        let ents = if remote_path.is_empty() || remote_path == self.loc.path {
            crate::ssh::list_ssh_location(&self.loc)?
        } else {
            list_ssh_path(&self.loc, remote_path)?
        };
        Ok(ents
            .into_iter()
            .map(|e| RemoteDirent {
                name: e.name,
                remote_path: e.path,
                is_dir: e.is_dir,
                size: e.size,
                mtime: e.mtime,
            })
            .collect())
    }

    fn is_dir(&self, remote_path: &str) -> Result<bool> {
        ssh_path_is_dir(&self.loc, remote_path)
    }

    fn open_range(&self, remote_path: &str, _size: u64) -> Result<Box<dyn ArchiveRead>> {
        let mut loc = self.loc.clone();
        loc.path = remote_path.to_string();
        let (tmp, _) = fetch_ssh_location_to_temp(&loc)?;
        Ok(Box::new(tmp))
    }
}

struct WebDavListing {
    loc: WebDavLocation,
}

impl RemoteListing for WebDavListing {
    fn list(&self, remote_path: &str) -> Result<Vec<RemoteDirent>> {
        let mut loc = self.loc.clone();
        loc.http_url = remote_path.to_string();
        Ok(propfind_entries(&loc, 1)?
            .into_iter()
            .map(|e| RemoteDirent {
                name: e.name,
                remote_path: e.href,
                is_dir: e.is_dir,
                size: e.size,
                mtime: 0.0,
            })
            .collect())
    }

    fn is_dir(&self, remote_path: &str) -> Result<bool> {
        let mut loc = self.loc.clone();
        loc.http_url = remote_path.to_string();
        webdav_is_collection(&loc)
    }

    fn join(&self, root: &str, rel: &str) -> String {
        http_url_join(root, rel)
    }

    fn open_range(&self, remote_path: &str, size: u64) -> Result<Box<dyn ArchiveRead>> {
        let url = webdav_url_with_userinfo(remote_path, &self.loc);
        if size > 0 {
            Ok(Box::new(HttpRangeFile::range_backed(&url, size)))
        } else {
            Ok(Box::new(open_http_range(&url)?))
        }
    }
}

struct HttpIndexListing {
    loc: HttpLocation,
}

impl RemoteListing for HttpIndexListing {
    fn list(&self, remote_path: &str) -> Result<Vec<RemoteDirent>> {
        let html = http_get_body(
            remote_path,
            self.loc.auth.as_ref(),
            self.loc.cookie.as_deref(),
        )?;
        Ok(parse_http_autoindex(&html, remote_path))
    }

    fn is_dir(&self, remote_path: &str) -> Result<bool> {
        http_url_is_dir(
            remote_path,
            self.loc.auth.as_ref(),
            self.loc.cookie.as_deref(),
        )
    }

    fn join(&self, root: &str, rel: &str) -> String {
        http_url_join(root, rel)
    }

    fn open_range(&self, remote_path: &str, size: u64) -> Result<Box<dyn ArchiveRead>> {
        let url = url_with_http_auth(remote_path, self.loc.auth.as_ref());
        if size > 0 {
            Ok(Box::new(HttpRangeFile::range_backed(&url, size)))
        } else {
            Ok(Box::new(open_http_range(&url)?))
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP autoindex
// ---------------------------------------------------------------------------

fn http_url_is_dir(url: &str, auth: Option<&HttpAuth>, cookie: Option<&str>) -> Result<bool> {
    let trailing = url.ends_with('/');
    if !trailing {
        match http_head_content_type(url, auth, cookie) {
            Ok(Some(ct)) if content_type_is_html(&ct) => {}
            Ok(_) => return Ok(false),
            Err(e) => {
                debug!("HTTP HEAD {url} (dir probe) failed: {e}");
                return Ok(false);
            }
        }
    }
    match http_get_body(url, auth, cookie) {
        Ok(html) => {
            if !parse_http_autoindex(&html, url).is_empty() {
                return Ok(true);
            }
            if looks_like_autoindex(&html) {
                return Ok(true);
            }
            Ok(trailing)
        }
        Err(_) if trailing => Ok(true),
        Err(_) => Ok(false),
    }
}

fn content_type_is_html(ct: &str) -> bool {
    let ct = ct.to_ascii_lowercase();
    ct.contains("text/html") || ct.contains("application/xhtml")
}

fn looks_like_autoindex(html: &str) -> bool {
    html.to_ascii_lowercase().contains("index of")
}

/// Parse nginx/apache autoindex HTML (`<a href="name">`). No JS SPAs.
pub fn parse_http_autoindex(html: &str, base_url: &str) -> Vec<RemoteDirent> {
    let mut out = Vec::new();
    let lower = html.to_ascii_lowercase();
    let mut search = 0;
    while let Some(rel) = lower[search..].find("href=") {
        let abs = search + rel + 5;
        let rest = &html[abs..];
        let href = match rest.as_bytes().first() {
            Some(b'"') => rest[1..].split('"').next().unwrap_or(""),
            Some(b'\'') => rest[1..].split('\'').next().unwrap_or(""),
            _ => rest
                .split(|c: char| c.is_whitespace() || c == '>')
                .next()
                .unwrap_or(""),
        };
        search = abs + 1;
        let href = href.trim();
        if href.is_empty() {
            continue;
        }
        let href = href.replace("&amp;", "&");
        if skip_autoindex_href(&href) {
            continue;
        }
        let joined = http_url_join(base_url, &href);
        if let (Ok(base), Ok(child)) = (Url::parse(base_url), Url::parse(&joined)) {
            if let (Some(bh), Some(ch)) = (base.host_str(), child.host_str()) {
                if bh != ch {
                    continue;
                }
            }
            let bp = base.path().trim_end_matches('/');
            let cp = child.path().trim_end_matches('/');
            if bp == cp {
                continue;
            }
        }
        let is_dir = href.ends_with('/') || joined.ends_with('/');
        let name = child_name_from_href(&href);
        if name.is_empty() || name == "." || name == ".." {
            continue;
        }
        let size = autoindex_size_after(html, abs, is_dir);
        out.push(RemoteDirent {
            name,
            remote_path: joined,
            is_dir,
            size,
            mtime: 0.0,
        });
    }
    out
}

fn skip_autoindex_href(href: &str) -> bool {
    let h = href.trim();
    if h.is_empty() || h == "/" || h == "./" || h == "." {
        return true;
    }
    if h.starts_with('#') || h.starts_with('?') || h.starts_with("//") {
        return true;
    }
    let lower = h.to_ascii_lowercase();
    if lower.starts_with("javascript:")
        || lower.starts_with("mailto:")
        || lower.starts_with("data:")
    {
        return true;
    }
    if h == ".." || h == "../" || h.starts_with("../") {
        return true;
    }
    false
}

fn child_name_from_href(href: &str) -> String {
    let path = href
        .split_once("://")
        .map(|(_, rest)| rest.split_once('/').map(|(_, p)| p).unwrap_or(rest))
        .unwrap_or(href);
    let path = path.split(['?', '#']).next().unwrap_or(path);
    percent_decode(path.trim_end_matches('/').rsplit('/').next().unwrap_or(""))
}

fn autoindex_size_after(html: &str, href_abs: usize, is_dir: bool) -> u64 {
    if is_dir {
        return 0;
    }
    let after = &html[href_abs.min(html.len())..];
    let line_end = after.find('\n').unwrap_or(after.len());
    let line = &after[..line_end];
    let after_a = line
        .find("</a>")
        .or_else(|| line.find("</A>"))
        .map(|i| &line[i + 4..])
        .unwrap_or(line);
    after_a
        .split_whitespace()
        .rev()
        .find_map(|tok| tok.replace(',', "").parse::<u64>().ok())
        .unwrap_or(0)
}

fn percent_decode(s: &str) -> String {
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

fn http_url_join(base: &str, rel: &str) -> String {
    if rel.starts_with("http://") || rel.starts_with("https://") {
        return rel.to_string();
    }
    let base = if base.ends_with('/') {
        base.to_string()
    } else {
        format!("{base}/")
    };
    match Url::parse(&base) {
        Ok(u) => u
            .join(rel)
            .map(|j| j.to_string())
            .unwrap_or_else(|_| format!("{base}{}", rel.trim_start_matches('/'))),
        Err(_) => join_path(&base, rel),
    }
}

fn url_with_http_auth(url: &str, auth: Option<&HttpAuth>) -> String {
    let Some(auth) = auth else {
        return url.to_string();
    };
    let Ok(mut u) = Url::parse(url) else {
        return url.to_string();
    };
    let _ = u.set_username(&auth.username);
    if let Some(pw) = &auth.password {
        let _ = u.set_password(Some(pw));
    }
    u.to_string()
}

fn webdav_url_with_userinfo(url: &str, loc: &WebDavLocation) -> String {
    let Some(user) = loc.username.as_deref() else {
        return url.to_string();
    };
    let Ok(mut u) = Url::parse(url) else {
        return url.to_string();
    };
    let _ = u.set_username(user);
    if let Some(pw) = loc.password.as_deref() {
        let _ = u.set_password(Some(pw));
    }
    u.to_string()
}

fn apply_http_headers(
    mut req: ureq::Request,
    auth: Option<&HttpAuth>,
    cookie: Option<&str>,
) -> ureq::Request {
    if let Some(a) = auth {
        req = req.set("Authorization", &a.authorization_header());
    }
    if let Some(c) = cookie {
        if !c.is_empty() {
            req = req.set("Cookie", c);
        }
    }
    req
}

fn http_head_content_type(
    url: &str,
    auth: Option<&HttpAuth>,
    cookie: Option<&str>,
) -> Result<Option<String>> {
    let req = apply_http_headers(ureq::head(url).set("User-Agent", USER_AGENT), auth, cookie);
    match req.call() {
        Ok(resp) => Ok(resp.header("Content-Type").map(|s| s.to_string())),
        Err(ureq::Error::Status(_, resp)) => Ok(resp.header("Content-Type").map(|s| s.to_string())),
        Err(e) => Err(RemoteError::Http(e.to_string())),
    }
}

const HTTP_INDEX_BODY_CAP: u64 = 1024 * 1024;

fn http_get_body(url: &str, auth: Option<&HttpAuth>, cookie: Option<&str>) -> Result<String> {
    let req = apply_http_headers(ureq::get(url).set("User-Agent", USER_AGENT), auth, cookie);
    let resp = req.call().map_err(|e| RemoteError::Http(e.to_string()))?;
    if !(200..300).contains(&resp.status()) {
        return Err(RemoteError::Http(format!(
            "HTTP {} for index GET",
            resp.status()
        )));
    }
    let mut buf = String::new();
    resp.into_reader()
        .take(HTTP_INDEX_BODY_CAP)
        .read_to_string(&mut buf)
        .map_err(RemoteError::Io)?;
    Ok(buf)
}

fn join_path(root: &str, rel: &str) -> String {
    let rel = rel.trim_start_matches('/');
    if rel.is_empty() {
        return root.to_string();
    }
    if root.is_empty() {
        return rel.to_string();
    }
    if root.ends_with('/') {
        format!("{root}{rel}")
    } else {
        format!("{root}/{rel}")
    }
}

fn split_parent(remote_path: &str) -> (String, String) {
    let trimmed = remote_path.trim_end_matches('/');
    match trimmed.rsplit_once('/') {
        Some((p, name)) => {
            let parent = if p.is_empty() {
                "/".to_string()
            } else {
                p.to_string()
            };
            (parent, name.to_string())
        }
        None => (String::new(), trimmed.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write as IoWrite};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex as StdMutex;
    use std::thread;

    struct FakeListing {
        dirs: BTreeMap<String, Vec<RemoteDirent>>,
        files: BTreeMap<String, Vec<u8>>,
    }

    impl RemoteListing for FakeListing {
        fn list(&self, remote_path: &str) -> Result<Vec<RemoteDirent>> {
            Ok(self.dirs.get(remote_path).cloned().unwrap_or_default())
        }
        fn open_range(&self, remote_path: &str, _size: u64) -> Result<Box<dyn ArchiveRead>> {
            let data = self.files.get(remote_path).cloned().unwrap_or_default();
            Ok(Box::new(std::io::Cursor::new(data)))
        }
        fn is_dir(&self, remote_path: &str) -> Result<bool> {
            Ok(self.dirs.contains_key(remote_path))
        }
    }

    #[test]
    fn try_open_remote_folder_ignores_non_f1_schemes() {
        for input in [
            "dropbox:///vault",
            "smb://host/share/dir/",
            "ftp://host/dir/",
            "/local/path",
            "file:///tmp/x",
        ] {
            assert!(
                try_open_remote_folder(input).unwrap().is_none(),
                "{input} is not an F-1 folder scheme"
            );
        }
    }

    #[test]
    fn parse_http_autoindex_nginx_and_apache() {
        let nginx = r#"<html><head><title>Index of /dir/</title></head>
<body><h1>Index of /dir/</h1><hr><pre><a href="../">../</a>
<a href="file.tar">file.tar</a>                 01-Jan-2020 00:00              42
<a href="subdir/">subdir/</a>                   01-Jan-2020 00:00                 -
</pre><hr></body></html>"#;
        let ents = parse_http_autoindex(nginx, "http://host.example/dir/");
        assert!(ents
            .iter()
            .any(|e| e.name == "file.tar" && !e.is_dir && e.size == 42));
        assert!(ents.iter().any(|e| e.name == "subdir" && e.is_dir));
        assert!(!ents.iter().any(|e| e.name == ".."));

        let apache = r#"<html><body><ul>
<li><a href="?C=N;O=D">Name</a></li>
<li><a href="a.tar">a.tar</a></li>
<li><a href="nested/">nested/</a></li>
</ul></body></html>"#;
        let ents = parse_http_autoindex(apache, "http://host.example/dir/");
        assert_eq!(ents.len(), 2, "{ents:?}");
        assert!(ents.iter().any(|e| e.name == "a.tar" && !e.is_dir));
        assert!(ents.iter().any(|e| e.name == "nested" && e.is_dir));
    }

    #[test]
    fn folder_list_dirents_sizes_match_lookup() {
        let listing = FakeListing {
            dirs: BTreeMap::from([(
                "prefix/".into(),
                vec![
                    RemoteDirent {
                        name: "a.tar".into(),
                        remote_path: "prefix/a.tar".into(),
                        is_dir: false,
                        size: 11,
                        mtime: 0.0,
                    },
                    RemoteDirent {
                        name: "sub".into(),
                        remote_path: "prefix/sub/".into(),
                        is_dir: true,
                        size: 0,
                        mtime: 0.0,
                    },
                ],
            )]),
            files: BTreeMap::from([("prefix/a.tar".into(), b"hello-world".to_vec())]),
        };
        let ms = RemoteFolderMountSource::new("prefix/".into(), listing).with_list_ttl_secs(30);
        let dents = ms.list_dirents("/").expect("dirents");
        let a = dents.iter().find(|d| d.name == "a.tar").expect("a.tar");
        assert_eq!(a.size, 11);
        assert_eq!(a.mode & S_IFMT, S_IFREG);
        let sub = dents.iter().find(|d| d.name == "sub").expect("sub");
        assert_eq!(sub.size, 0);
        assert_eq!(sub.mode & S_IFMT, S_IFDIR);
        assert_eq!(ms.lookup("/a.tar", 0).unwrap().size, 11);
        let fi = ms.lookup("/a.tar", 0).unwrap();
        let mut r = ms.open(&fi, 0).unwrap();
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"hello-world");
    }

    /// Serialize tests that mutate process AWS env.
    static ENV_LOCK: StdMutex<()> = StdMutex::new(());

    struct EnvGuard {
        saved: Vec<(String, Option<String>)>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl EnvGuard {
        fn acquire(keys: &[&str]) -> Self {
            let lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let mut saved = Vec::new();
            for &k in keys {
                saved.push((k.to_string(), std::env::var(k).ok()));
                std::env::remove_var(k);
            }
            Self { saved, _lock: lock }
        }
        fn set(&self, key: &str, val: &str) {
            std::env::set_var(key, val);
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (k, v) in self.saved.drain(..) {
                match v {
                    Some(val) => std::env::set_var(&k, val),
                    None => std::env::remove_var(&k),
                }
            }
        }
    }

    struct MockListS3 {
        base_url: String,
        object_gets: Arc<AtomicUsize>,
        list_gets: Arc<AtomicUsize>,
        _join: Option<thread::JoinHandle<()>>,
    }

    impl MockListS3 {
        fn spawn(page1: String, page2: String, file_body: Vec<u8>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let base_url = format!("http://{}", listener.local_addr().unwrap());
            let object_gets = Arc::new(AtomicUsize::new(0));
            let list_gets = Arc::new(AtomicUsize::new(0));
            let og = Arc::clone(&object_gets);
            let lg = Arc::clone(&list_gets);
            let join = thread::spawn(move || {
                for stream in listener.incoming().take(64) {
                    let Ok(mut stream) = stream else { continue };
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut request_line = String::new();
                    if reader.read_line(&mut request_line).is_err() {
                        continue;
                    }
                    loop {
                        let mut line = String::new();
                        if reader.read_line(&mut line).is_err() {
                            break;
                        }
                        if line == "\r\n" || line == "\n" || line.is_empty() {
                            break;
                        }
                    }
                    let path = request_line
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or("/")
                        .to_string();
                    if path.contains("list-type=2") {
                        lg.fetch_add(1, Ordering::SeqCst);
                        let body = if path.contains("continuation-token=") {
                            page2.as_bytes()
                        } else {
                            page1.as_bytes()
                        };
                        let _ = write!(
                            stream,
                            "HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = stream.write_all(body);
                        continue;
                    }
                    // Object GET (Range or full) — listing must not hit this.
                    og.fetch_add(1, Ordering::SeqCst);
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nAccept-Ranges: bytes\r\nConnection: close\r\n\r\n",
                        file_body.len()
                    );
                    let _ = stream.write_all(&file_body);
                }
            });
            Self {
                base_url,
                object_gets,
                list_gets,
                _join: Some(join),
            }
        }
    }

    const PAGE1: &str = r#"<?xml version="1.0"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>bucket</Name>
  <Prefix>prefix/</Prefix>
  <IsTruncated>true</IsTruncated>
  <NextContinuationToken>page-2-token</NextContinuationToken>
  <Contents><Key>prefix/a.tar</Key><Size>11</Size></Contents>
</ListBucketResult>"#;

    const PAGE2: &str = r#"<?xml version="1.0"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>bucket</Name>
  <Prefix>prefix/</Prefix>
  <IsTruncated>false</IsTruncated>
  <Contents><Key>prefix/b.bin</Key><Size>7</Size></Contents>
  <CommonPrefixes><Prefix>prefix/sub/</Prefix></CommonPrefixes>
</ListBucketResult>"#;

    /// Regression: truncated ListObjectsV2 page is not a complete listing.
    /// Regression: s3://bucket/prefix/ lists children without downloading objects.
    #[test]
    fn s3_prefix_folder_lists_children_without_downloading_objects() {
        let file_body = b"hello-world".to_vec();
        let mock = MockListS3::spawn(PAGE1.to_string(), PAGE2.to_string(), file_body.clone());
        let _g = EnvGuard::acquire(&[
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "AWS_REGION",
            "AWS_DEFAULT_REGION",
            "AWS_ENDPOINT_URL",
            "S3_ENDPOINT_URL",
            "AWS_ANONYMOUS",
            "RATARMOUNT_S3_ANONYMOUS",
            "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
            "AWS_CONTAINER_CREDENTIALS_FULL_URI",
            "RATARMOUNT_IMDS_BASE",
        ]);
        _g.set("AWS_ANONYMOUS", "1");
        _g.set("AWS_ENDPOINT_URL", &mock.base_url);
        _g.set("RATARMOUNT_IMDS_BASE", "http://127.0.0.1:1");

        let ms = try_open_remote_folder("s3://bucket/prefix/")
            .unwrap()
            .expect("prefix/ is a folder");
        let dents = ms.list_dirents("/").expect("dirents");
        assert!(
            dents.iter().any(|d| d.name == "a.tar" && d.size == 11),
            "page 1 child missing: {dents:?}"
        );
        assert!(
            dents.iter().any(|d| d.name == "b.bin" && d.size == 7),
            "page 2 child missing (truncated page treated as complete?): {dents:?}"
        );
        assert!(
            dents
                .iter()
                .any(|d| d.name == "sub" && d.mode & S_IFMT == S_IFDIR),
            "common prefix missing: {dents:?}"
        );
        assert_eq!(
            mock.object_gets.load(Ordering::SeqCst),
            0,
            "listing must not GetObject children"
        );
        assert!(mock.list_gets.load(Ordering::SeqCst) >= 2);

        let fi = ms.lookup("/a.tar", 0).expect("lookup a.tar");
        assert_eq!(fi.size, 11);
        let mut r = ms.open(&fi, 0).unwrap();
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, file_body);
        assert!(mock.object_gets.load(Ordering::SeqCst) >= 1);
    }

    #[test]
    fn truncated_list_objects_v2_page_without_token_is_error() {
        let xml = r#"<ListBucketResult>
  <IsTruncated>true</IsTruncated>
  <Contents><Key>prefix/a.tar</Key><Size>1</Size></Contents>
</ListBucketResult>"#;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut request_line = String::new();
                let _ = reader.read_line(&mut request_line);
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).is_err() {
                        break;
                    }
                    if line == "\r\n" || line == "\n" || line.is_empty() {
                        break;
                    }
                }
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{xml}",
                    xml.len()
                );
            }
        });
        let _g = EnvGuard::acquire(&[
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "AWS_ENDPOINT_URL",
            "S3_ENDPOINT_URL",
            "AWS_ANONYMOUS",
            "RATARMOUNT_S3_ANONYMOUS",
            "RATARMOUNT_IMDS_BASE",
            "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
            "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        ]);
        _g.set("AWS_ANONYMOUS", "1");
        _g.set("AWS_ENDPOINT_URL", &base_url);
        _g.set("RATARMOUNT_IMDS_BASE", "http://127.0.0.1:1");
        let err = crate::s3::list_s3_prefix(&S3Location {
            bucket: "bucket".into(),
            key: "prefix/".into(),
        })
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("truncated") || msg.contains("not complete"),
            "unexpected: {msg}"
        );
    }

    struct MockHttpIndex {
        addr: String,
        _join: Option<thread::JoinHandle<()>>,
    }

    impl MockHttpIndex {
        fn spawn(index_html: String, file_body: Vec<u8>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = format!("http://{}", listener.local_addr().unwrap());
            let join = thread::spawn(move || {
                for stream in listener.incoming().take(32) {
                    let Ok(mut stream) = stream else { continue };
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut request_line = String::new();
                    if reader.read_line(&mut request_line).is_err() {
                        continue;
                    }
                    loop {
                        let mut line = String::new();
                        if reader.read_line(&mut line).is_err() {
                            break;
                        }
                        if line == "\r\n" || line == "\n" || line.is_empty() {
                            break;
                        }
                    }
                    let path = request_line
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or("/")
                        .to_string();
                    let is_head = request_line.starts_with("HEAD ");
                    if path.ends_with("/a.tar") || path.ends_with("a.tar") {
                        let _ = write!(
                            stream,
                            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nAccept-Ranges: bytes\r\nConnection: close\r\n\r\n",
                            file_body.len()
                        );
                        if !is_head {
                            let _ = stream.write_all(&file_body);
                        }
                    } else {
                        let _ = write!(
                            stream,
                            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            index_html.len()
                        );
                        if !is_head {
                            let _ = stream.write_all(index_html.as_bytes());
                        }
                    }
                }
            });
            Self {
                addr,
                _join: Some(join),
            }
        }
    }

    #[test]
    fn http_autoindex_folder_lists_and_opens() {
        let html = r#"<html><head><title>Index of /dir/</title></head>
<body><h1>Index of /dir/</h1>
<a href="a.tar">a.tar</a>                 01-Jan-2020 00:00              15
<a href="sub/">sub/</a>                   01-Jan-2020 00:00                 -
</body></html>"#;
        let body = b"http-file-bytes".to_vec();
        let mock = MockHttpIndex::spawn(html.to_string(), body.clone());
        let url = format!("{}/dir/", mock.addr);
        let ms = try_open_remote_folder(&url)
            .unwrap()
            .expect("http autoindex is a folder");
        let dents = ms.list_dirents("/").expect("dirents");
        assert!(dents.iter().any(|d| d.name == "a.tar"));
        assert!(dents
            .iter()
            .any(|d| d.name == "sub" && d.mode & S_IFMT == S_IFDIR));
        let fi = ms.lookup("/a.tar", 0).expect("lookup");
        let mut r = ms.open(&fi, 0).unwrap();
        let mut got = Vec::new();
        r.read_to_end(&mut got).unwrap();
        assert_eq!(got, body);
    }

    struct MockWebDav {
        addr: String,
        _join: Option<thread::JoinHandle<()>>,
    }

    impl MockWebDav {
        fn spawn(propfind_xml: String, file_body: Vec<u8>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = format!("http://{}", listener.local_addr().unwrap());
            let join = thread::spawn(move || {
                for stream in listener.incoming().take(32) {
                    let Ok(mut stream) = stream else { continue };
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut request_line = String::new();
                    if reader.read_line(&mut request_line).is_err() {
                        continue;
                    }
                    let mut content_len = 0usize;
                    loop {
                        let mut line = String::new();
                        if reader.read_line(&mut line).is_err() {
                            break;
                        }
                        if line == "\r\n" || line == "\n" || line.is_empty() {
                            break;
                        }
                        if let Some(v) = line.split_once(':') {
                            if v.0.eq_ignore_ascii_case("content-length") {
                                content_len = v.1.trim().parse().unwrap_or(0);
                            }
                        }
                    }
                    if content_len > 0 {
                        let mut sink = vec![0u8; content_len];
                        let _ = std::io::Read::read_exact(&mut reader, &mut sink);
                    }
                    let method = request_line.split_whitespace().next().unwrap_or("");
                    let path = request_line
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or("/")
                        .to_string();
                    if method.eq_ignore_ascii_case("PROPFIND") {
                        let _ = write!(
                            stream,
                            "HTTP/1.1 207 Multi-Status\r\nContent-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            propfind_xml.len()
                        );
                        let _ = stream.write_all(propfind_xml.as_bytes());
                    } else if path.contains("a.tar") {
                        let _ = write!(
                            stream,
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nAccept-Ranges: bytes\r\nConnection: close\r\n\r\n",
                            file_body.len()
                        );
                        let _ = stream.write_all(&file_body);
                    } else {
                        let _ = write!(
                            stream,
                            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        );
                    }
                }
            });
            Self {
                addr,
                _join: Some(join),
            }
        }
    }

    #[test]
    fn webdav_propfind_folder_lists_children() {
        let xml = r#"<?xml version="1.0"?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:href>/dav/</D:href>
    <D:propstat><D:prop><D:resourcetype><D:collection/></D:resourcetype></D:prop></D:propstat>
  </D:response>
  <D:response>
    <D:href>/dav/a.tar</D:href>
    <D:propstat><D:prop><D:getcontentlength>8</D:getcontentlength><D:resourcetype/></D:prop></D:propstat>
  </D:response>
  <D:response>
    <D:href>/dav/sub/</D:href>
    <D:propstat><D:prop><D:resourcetype><D:collection/></D:resourcetype></D:prop></D:propstat>
  </D:response>
</D:multistatus>"#;
        let body = b"webdav!!".to_vec();
        let mock = MockWebDav::spawn(xml.to_string(), body.clone());
        let url = format!("webdav://{}/dav/", mock.addr.trim_start_matches("http://"));
        let ms = try_open_remote_folder(&url)
            .unwrap()
            .expect("webdav collection is a folder");
        let dents = ms.list_dirents("/").expect("dirents");
        assert!(
            dents.iter().any(|d| d.name == "a.tar" && d.size == 8),
            "{dents:?}"
        );
        assert!(dents
            .iter()
            .any(|d| d.name == "sub" && d.mode & S_IFMT == S_IFDIR));
        let fi = ms.lookup("/a.tar", 0).expect("lookup");
        let mut r = ms.open(&fi, 0).unwrap();
        let mut got = Vec::new();
        r.read_to_end(&mut got).unwrap();
        assert_eq!(got, body);
    }

    #[test]
    fn ssh_folder_skips_without_sshd() {
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
            eprintln!("skip: sshd not available for live SFTP folder mount");
            return;
        }
        eprintln!("skip: live SFTP folder mount has no sshd fixture");
    }
}
