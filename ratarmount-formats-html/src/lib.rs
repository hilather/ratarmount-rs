//! HTML data-URL extract MountSource (`backendName=HTMLMountSource`).
//!
//! Scans HTML for `data:` URLs (base64 or plain), decodes them, and exposes each
//! payload as a virtual file. Matches Python `HTMLMountSource` best-effort.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Cursor, Read};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Instant;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ratarmount_core::{
    normpath, FileInfo, ListModeResult, ListResult, MountSource, OpenOptions, UserData,
};
use ratarmount_index::{IndexError, SqliteIndex};
use regex::Regex;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const BACKEND_NAME: &str = "HTMLMountSource";

#[derive(Debug, Error)]
pub enum HtmlError {
    #[error(transparent)]
    Index(#[from] IndexError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("{0}")]
    Msg(String),
}

pub type Result<T> = std::result::Result<T, HtmlError>;

/// Loose HTML detection (Python `is_html_file`).
pub fn looks_like_html(path: &Path) -> bool {
    let ext_ok = path.extension().and_then(|e| e.to_str()).is_some_and(|e| {
        let e = e.to_ascii_lowercase();
        e == "html" || e == "htm"
    });
    let Ok(mut f) = File::open(path) else {
        return false;
    };
    let mut chunk = [0u8; 512];
    let n = match f.read(&mut chunk) {
        Ok(n) => n,
        Err(_) => return false,
    };
    let lower: Vec<u8> = chunk[..n].iter().map(|b| b.to_ascii_lowercase()).collect();
    if lower.contains(&0) {
        return false;
    }
    if lower.windows(14).any(|w| w == b"<!doctype html") {
        return true;
    }
    // Starts with `<!` is a common quick check from the task description.
    if chunk[..n].starts_with(b"<!") {
        return true;
    }
    let tags: &[&[u8]] = &[
        b"<html", b"<head", b"<title", b"<script", b"<style", b"<table", b"<a href",
    ];
    let content = tags.iter().any(|t| lower.windows(t.len()).any(|w| w == *t));
    if content {
        return true;
    }
    // Extension alone is insufficient without content; require content match
    // unless extension + starts with `<`.
    ext_ok && chunk[..n].contains(&b'<')
}

fn unescape_html_entities(s: &str) -> String {
    // Minimal entity unescape for data-URL payloads seen in fixtures.
    let mut out = s
        .replace("&#47;", "/")
        .replace("&#x2f;", "/")
        .replace("&#X2F;", "/")
        .replace("&sol;", "/")
        .replace("&#54;", "6")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#34;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'");
    // Generic decimal numeric entities &#NNN;
    let re = Regex::new(r"&#(\d+);").unwrap();
    out = re
        .replace_all(&out, |caps: &regex::Captures| {
            let n: u32 = caps[1].parse().unwrap_or(0);
            char::from_u32(n).map(|c| c.to_string()).unwrap_or_default()
        })
        .into_owned();
    out
}

/// Decode a full data URL string into (mime_type, payload).
fn decode_data_url(raw: &str) -> Option<(String, Vec<u8>)> {
    let s = unescape_html_entities(raw);
    let s = s.trim();
    if !s.starts_with("data:") {
        return None;
    }
    let rest = &s[5..];
    let comma = rest.find(',')?;
    let meta = &rest[..comma];
    let data = &rest[comma + 1..];
    if data.is_empty() {
        return None;
    }

    let mut mime = "text/plain".to_string();
    let mut is_base64 = false;
    let mut encoding = "utf-8".to_string();

    if !meta.is_empty() {
        let parts: Vec<&str> = meta.split(';').map(|p| p.trim()).collect();
        if let Some(first) = parts.first() {
            if first.contains('/') {
                mime = first.to_string();
            } else if first.eq_ignore_ascii_case("utf-8") || first.eq_ignore_ascii_case("utf8") {
                encoding = "utf-8".into();
            }
        }
        for p in &parts {
            let pl = p.to_ascii_lowercase();
            if pl == "base64" {
                is_base64 = true;
            } else if pl == "utf-8" || pl == "utf8" {
                encoding = "utf-8".into();
            } else if let Some((k, v)) = p.split_once('=') {
                if k.trim().eq_ignore_ascii_case("charset") {
                    encoding = v.trim().to_string();
                }
            }
        }
    }

    // percent-decode then base64 if needed
    let unquoted = percent_encoding::percent_decode_str(data)
        .decode_utf8_lossy()
        .into_owned();

    let payload = if is_base64 {
        // Strip whitespace sometimes present in HTML.
        let cleaned: String = unquoted.chars().filter(|c| !c.is_whitespace()).collect();
        B64.decode(cleaned.as_bytes()).ok()?
    } else {
        // utf-8 / ascii / other: keep raw bytes of the unquoted payload.
        let _ = encoding;
        unquoted.into_bytes()
    };

    Some((mime, payload))
}

fn mime_extension(mime: &str) -> String {
    let m = mime.to_ascii_lowercase();
    if m.ends_with("/javascript") || m == "application/javascript" || m == "text/javascript" {
        return ".js".into();
    }
    match m.as_str() {
        "image/png" => ".png".into(),
        "image/jpeg" | "image/jpg" => ".jpg".into(),
        "image/gif" => ".gif".into(),
        "image/svg+xml" => ".svg".into(),
        "image/x-icon" | "image/vnd.microsoft.icon" => ".ico".into(),
        "text/css" => ".css".into(),
        "text/html" => ".html".into(),
        "text/plain" => ".txt".into(),
        "application/json" => ".json".into(),
        "application/pdf" => ".pdf".into(),
        "font/ttf" | "application/x-font-ttf" => ".ttf".into(),
        "font/woff" => ".woff".into(),
        "font/woff2" => ".woff2".into(),
        _ => {
            if let Some((_, sub)) = m.split_once('/') {
                let sub = sub.split('+').next().unwrap_or(sub);
                if !sub.is_empty() && sub.len() < 8 {
                    return format!(".{sub}");
                }
            }
            String::new()
        }
    }
}

struct Embedded {
    name: String,
    data: Vec<u8>,
    /// Character/byte span of the data URL in the source file (for index columns).
    span_start: i64,
    span_end: i64,
}

fn gather_embedded(html: &str) -> Vec<Embedded> {
    // Match quoted data URLs and CSS url(data:...) forms.
    let re_dq = Regex::new(r#""(data:[^"]+)""#).unwrap();
    let re_sq = Regex::new(r#"'(data:[^']+)'"#).unwrap();
    let re_css = Regex::new(r#"url\(\s*(data:[^)]+)\s*\)"#).unwrap();

    let mut spans: Vec<(usize, usize, String)> = Vec::new();
    for re in [&re_dq, &re_sq, &re_css] {
        for caps in re.captures_iter(html) {
            if let Some(m) = caps.get(1) {
                spans.push((m.start(), m.end(), m.as_str().to_string()));
            }
        }
    }
    // Prefer longer/earlier spans; drop exact duplicates by start.
    spans.sort_by_key(|(s, e, _)| (*s, *e));
    spans.dedup_by_key(|(s, _, _)| *s);

    let mut out = Vec::new();
    let mut used_names: HashMap<String, u32> = HashMap::new();

    for (start, end, url) in spans {
        let Some((mime, data)) = decode_data_url(&url) else {
            continue;
        };
        if data.is_empty() {
            continue;
        }
        let ext = mime_extension(&mime);
        let mut name = {
            let mut hasher = Sha256::new();
            hasher.update(&data);
            format!("{:x}{ext}", hasher.finalize())
        };
        let key = name.clone();
        if let Some(n) = used_names.get_mut(&key) {
            *n += 1;
            let count = *n;
            if let Some((stem, e)) = name.rsplit_once('.') {
                name = format!("{stem}-{count}.{e}");
            } else {
                name = format!("{name}-{count}");
            }
        } else {
            used_names.insert(key, 0);
        }
        out.push(Embedded {
            name,
            data,
            span_start: start as i64,
            span_end: end as i64,
        });
    }
    out
}

pub struct HtmlMountSource {
    #[allow(dead_code)]
    archive_path: PathBuf,
    index: SqliteIndex,
    /// Decoded payloads keyed by index offsetheader (= payload id).
    payloads: Mutex<HashMap<i64, Vec<u8>>>,
    #[allow(dead_code)]
    options: OpenOptions,
}

impl HtmlMountSource {
    pub fn open(
        archive_path: impl AsRef<Path>,
        index_path: Option<&Path>,
        options: &OpenOptions,
        product_version: &str,
        recreate: bool,
    ) -> Result<Self> {
        let archive_path = archive_path.as_ref().to_path_buf();
        if !looks_like_html(&archive_path) {
            return Err(HtmlError::Msg("Not a valid HTML file!".into()));
        }

        // Always rebuild: decoded image sizes may not be stable across tools,
        // and payloads live in-process. Force memory index like Python PDF.
        let _ = (index_path, recreate);
        let mut opts = options.clone();
        opts.index_in_memory = true;

        Self::create_index(&archive_path, &opts, product_version)
    }

    fn create_index(
        archive_path: &Path,
        options: &OpenOptions,
        product_version: &str,
    ) -> Result<Self> {
        let _ = options;
        println!(
            "Creating offset dictionary for {} ...",
            archive_path.display()
        );
        let t0 = Instant::now();

        let bytes = std::fs::read(archive_path)?;
        // Lossy UTF-8 is fine for scanning data URLs.
        let html = String::from_utf8_lossy(&bytes).into_owned();
        let files = gather_embedded(&html);

        let mtime = std::fs::metadata(archive_path)
            .map(|m| {
                use std::os::unix::fs::MetadataExt;
                m.mtime() as f64
            })
            .unwrap_or(0.0);

        let index = SqliteIndex::create_writable(None)?;
        index.begin_write()?;
        let mut payloads = HashMap::new();
        let mut generated = std::collections::BTreeSet::new();

        for (i, emb) in files.into_iter().enumerate() {
            let id = i as i64;
            let nfull = normpath(&emb.name);
            let (path, base) = split_name(&nfull);
            ensure_parents(&index, &path, &mut generated, mtime)?;
            let mode = (ratarmount_core::S_IFREG | 0o777) as i64;
            index.insert_file(
                &path,
                &base,
                emb.span_start,
                emb.span_end,
                emb.data.len() as i64,
                mtime,
                mode,
                0,
                "",
                0,
                0,
                false,
                false,
                false,
                0,
            )?;
            // Store under span_start as key (offsetheader column).
            payloads.insert(emb.span_start, emb.data);
            let _ = id;
        }

        index.store_versions(product_version)?;
        index.store_metadata_key_value("backendName", BACKEND_NAME)?;
        store_stats(&index, archive_path)?;
        index.commit_write()?;

        let secs = t0.elapsed().as_secs_f64();
        println!(
            "Creating offset dictionary for {} took {secs:.2}s",
            archive_path.display()
        );

        let index = index.into_read_only()?;
        Ok(Self {
            archive_path: archive_path.to_path_buf(),
            index,
            payloads: Mutex::new(payloads),
            options: options.clone(),
        })
    }
}

impl MountSource for HtmlMountSource {
    fn list(&self, path: &str) -> Option<ListResult> {
        self.index.list(path).ok().flatten().map(ListResult::Infos)
    }

    fn list_mode(&self, path: &str) -> Option<ListModeResult> {
        self.index
            .list_mode(path)
            .ok()
            .flatten()
            .map(ListModeResult::Modes)
    }

    fn lookup(&self, path: &str, file_version: i32) -> Option<FileInfo> {
        self.index.lookup(path, file_version).ok().flatten()
    }

    fn open(
        &self,
        file_info: &FileInfo,
        _buffering: i32,
    ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
        if file_info.mode & ratarmount_core::S_IFMT == ratarmount_core::S_IFDIR {
            return Err(io::Error::new(
                io::ErrorKind::IsADirectory,
                "is a directory",
            ));
        }
        let key = file_info
            .userdata
            .iter()
            .rev()
            .find_map(|u| match u {
                UserData::Tar(t) => t.offsetheader.map(|v| v as i64).or(Some(t.offset as i64)),
                _ => None,
            })
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing html userdata"))?;
        let map = self
            .payloads
            .lock()
            .map_err(|_| io::Error::other("html payload lock poisoned"))?;
        let data = map
            .get(&key)
            .cloned()
            .ok_or_else(|| io::Error::other(format!("missing html payload for key {key}")))?;
        Ok(Box::new(Cursor::new(data)))
    }

    fn is_immutable(&self) -> bool {
        true
    }
}

fn split_name(full: &str) -> (String, String) {
    match full.rsplit_once('/') {
        Some(("", n)) => (String::new(), n.to_string()),
        Some((p, n)) => (p.to_string(), n.to_string()),
        None => (String::new(), full.to_string()),
    }
}

fn ensure_parents(
    index: &SqliteIndex,
    path: &str,
    generated: &mut std::collections::BTreeSet<String>,
    mtime: f64,
) -> Result<()> {
    if path.is_empty() {
        return Ok(());
    }
    let parts: Vec<&str> = path
        .trim_start_matches('/')
        .split('/')
        .filter(|p| !p.is_empty())
        .collect();
    let mut cur = String::new();
    for (i, part) in parts.iter().enumerate() {
        let parent = if i == 0 { String::new() } else { cur.clone() };
        cur = if parent.is_empty() {
            format!("/{part}")
        } else {
            format!("{parent}/{part}")
        };
        if generated.contains(&cur) {
            continue;
        }
        generated.insert(cur.clone());
        let mode = (ratarmount_core::S_IFDIR | 0o755) as i64;
        index.insert_file(
            &parent, part, 0, 0, 0, mtime, mode, 0, "", 0, 0, false, false, true, 0,
        )?;
    }
    Ok(())
}

fn store_stats(index: &SqliteIndex, path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path)?;
    let json = format!(
        "{{\"st_size\":{},\"st_mtime\":{},\"st_mtime_ns\":{}}}",
        meta.size(),
        meta.mtime(),
        meta.mtime_nsec()
    );
    index.store_metadata_key_value("tarstats", &json)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn py_fixture(name: &str) -> PathBuf {
        let root = std::env::var("RATARMOUNT_PY_ROOT")
            .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into());
        PathBuf::from(root).join("tests").join(name)
    }

    #[test]
    fn decode_base64_png_prefix() {
        let (mime, data) = decode_data_url("data:image/png;base64,aGVsbG8=").unwrap();
        assert_eq!(mime, "image/png");
        assert_eq!(data, b"hello");
    }

    #[test]
    fn save_page_we() {
        let path = py_fixture("save_page_we.html");
        if !path.exists() {
            return;
        }
        assert!(looks_like_html(&path));
        let m = HtmlMountSource::open(&path, None, &OpenOptions::default(), "0.1.0", true).unwrap();
        let list = m.list("/").expect("list root");
        match list {
            ListResult::Infos(map) => {
                assert!(!map.is_empty(), "expected embedded files");
                // Open every file and ensure non-empty where size > 0
                for (_n, fi) in map {
                    if fi.mode & ratarmount_core::S_IFMT == ratarmount_core::S_IFDIR {
                        continue;
                    }
                    let mut r = m.open(&fi, 0).unwrap();
                    let mut buf = Vec::new();
                    r.read_to_end(&mut buf).unwrap();
                    assert_eq!(buf.len() as u64, fi.size);
                }
            }
            _ => panic!("expected infos"),
        }
    }
}
