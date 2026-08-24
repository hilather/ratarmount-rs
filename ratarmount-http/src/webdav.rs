//! WebDAV PROPFIND/GET export (P-6) on the HTTP listener.
//!
//! Depth 0/1 `multistatus`; Depth infinity is 403. GET/HEAD reuse the P-5
//! Range handler. PUT/DELETE/MKCOL/MOVE require a [`WriteOverlay`] (`-w`);
//! without it they return 403. Auth is none in v1 (localhost boundary).
//! Finder/Explorer quirks are residual.

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::unix::io::FromRawFd;
use std::sync::Arc;

use ratarmount_compositing::WriteOverlay;
use ratarmount_core::{is_dir_mode, FileInfo, MountSource};
use ratarmount_export_core::{
    overlay_create_file, overlay_mkdir, overlay_rename, overlay_to_io, overlay_unlink,
    parse_export_bind, BindError, ExportStop, DEFAULT_WEBDAV_PORT,
};

use crate::request::{archive_path, last_modified_header, percent_encode_segment, PathError};

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
    let result = (|| -> io::Result<()> {
        // SAFETY: `overlay_create_file` returns a new fd we own.
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
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
    overlay.release_write_fd(fd);
    result?;
    Ok(existed)
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
}
