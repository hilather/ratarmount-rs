//! Index path resolution (Python `SQLiteIndex.get_possible_index_file_paths` subset).
//!
//! Also materializes remote / URL index paths (`http(s)://`, `file://`) for Python parity
//! with fsspec-backed index download (`SQLiteIndex._load_index`).

use std::io::Write;
use std::path::{Path, PathBuf};

use log::{debug, warn};

use crate::{IndexError, Result};

/// Where the SQLite index lives for a mount.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IndexLocation {
    /// Pure in-memory SQLite (`--index-file :memory:`).
    Memory,
    /// On-disk index file.
    Path(PathBuf),
}

impl IndexLocation {
    pub fn as_path(&self) -> Option<&Path> {
        match self {
            Self::Memory => None,
            Self::Path(p) => Some(p.as_path()),
        }
    }

    pub fn is_memory(&self) -> bool {
        matches!(self, Self::Memory)
    }
}

/// Sentinel accepted by `--index-file`.
pub const MEMORY_INDEX: &str = ":memory:";

const USER_AGENT: &str = "ratarmount-rs/0.1";

/// Default folder list matching Python CLI:
/// `["", $XDG_CACHE_HOME/ratarmount, ~/.ratarmount]` (empty = next to archive).
pub fn default_index_folders() -> Vec<PathBuf> {
    let mut folders = vec![PathBuf::new()]; // next to archive
    if let Some(xdg) = xdg_cache_home() {
        let p = xdg.join("ratarmount");
        if p.parent().map(|par| par.is_dir()).unwrap_or(false) || xdg.is_dir() {
            folders.push(p);
        }
    }
    folders.push(expand_user(Path::new("~/.ratarmount")));
    folders
}

/// Parse `--index-folders` value: JSON list, comma-separated, or single path.
/// Empty string entries mean "next to the archive".
pub fn parse_index_folders(s: &str) -> Vec<PathBuf> {
    let s = s.trim();
    if s.is_empty() {
        return vec![PathBuf::new()];
    }
    if s.starts_with('[') {
        if let Ok(v) = serde_json::from_str::<Vec<String>>(s) {
            return v.into_iter().map(|x| expand_user(Path::new(&x))).collect();
        }
    }
    if s.contains(',') {
        return s
            .split(',')
            .map(|part| {
                let part = part.trim();
                if part.is_empty() {
                    PathBuf::new()
                } else {
                    expand_user(Path::new(part))
                }
            })
            .collect();
    }
    vec![expand_user(Path::new(s))]
}

/// Expand `~` / `~/…` like Python `os.path.expanduser`.
pub fn expand_user(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    if s == "~" {
        if let Some(home) = home_dir() {
            return home;
        }
    } else if let Some(rest) = s.strip_prefix("~/") {
        if let Some(home) = home_dir() {
            return home.join(rest);
        }
    }
    path.to_path_buf()
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

fn xdg_cache_home() -> Option<PathBuf> {
    if let Some(x) = std::env::var_os("XDG_CACHE_HOME") {
        if !x.is_empty() {
            return Some(PathBuf::from(x));
        }
    }
    home_dir().map(|h| h.join(".cache"))
}

/// Default on-disk index path next to the archive (`archive + ".index.sqlite"`).
pub fn default_index_path(archive: &Path) -> PathBuf {
    let mut s = archive.as_os_str().to_os_string();
    s.push(".index.sqlite");
    PathBuf::from(s)
}

/// Candidate index paths for an archive given folder list (Python semantics).
///
/// - Empty folder → `archive.index.sqlite` next to the archive.
/// - Non-empty folder → `folder / (archive_path with '/' replaced by '_')`.
pub fn possible_index_paths(archive: &Path, folders: &[PathBuf]) -> Vec<PathBuf> {
    let default = default_index_path(archive);
    if folders.is_empty() {
        return vec![default];
    }
    let archive_s = archive.to_string_lossy();
    let index_as_name = format!("{archive_s}.index.sqlite").replace('/', "_");
    let mut out = Vec::new();
    for folder in folders {
        if folder.as_os_str().is_empty() {
            out.push(default.clone());
        } else {
            out.push(folder.join(&index_as_name));
        }
    }
    out
}

/// True if `s` is an absolute `http(s)://` or `file://` URL suitable as an index path.
pub fn is_index_url(s: &str) -> bool {
    let s = s.trim();
    s.starts_with("http://")
        || s.starts_with("https://")
        || s.starts_with("file://")
}

/// Sibling index URL convention for a remote archive: `archive_url + ".index.sqlite"`.
///
/// Returns `None` when `archive_url` is not `http(s)://`.
pub fn sibling_index_url(archive_url: &str) -> Option<String> {
    let s = archive_url.trim();
    if s.starts_with("http://") || s.starts_with("https://") {
        Some(format!("{s}.index.sqlite"))
    } else {
        None
    }
}

/// Materialize an index path or URL to a local filesystem path.
///
/// * Local paths and `file://` → expanded local path (no copy).
/// * `http(s)://` → download into a kept tempfile (dir: `RATARMOUNT_INDEX_TMPDIR` if set).
///
/// Matches Python `SQLiteIndex._load_index` URL materialization (without compressed-index
/// decompression, which remains a follow-up).
pub fn maybe_fetch_index_url(index_spec: &str) -> Result<PathBuf> {
    let s = index_spec.trim();
    if s.is_empty() {
        return Err(IndexError::Invalid("empty index path".into()));
    }

    // Python strips a single `file://` prefix when `count('://') == 1`.
    if let Some(rest) = s.strip_prefix("file://") {
        if !rest.contains("://") {
            return Ok(expand_user(Path::new(rest)));
        }
    }

    if s.starts_with("http://") || s.starts_with("https://") {
        return fetch_index_http(s);
    }

    // Non-URL local path (including Windows-ish schemes we do not handle specially).
    Ok(expand_user(Path::new(s)))
}

fn index_temp_dir() -> Option<PathBuf> {
    std::env::var_os("RATARMOUNT_INDEX_TMPDIR")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

fn fetch_index_http(url: &str) -> Result<PathBuf> {
    debug!("fetching remote index from {url}");
    let resp = ureq::get(url)
        .set("User-Agent", USER_AGENT)
        .call()
        .map_err(|e| IndexError::Remote(e.to_string()))?;
    let status = resp.status();
    if !(200..300).contains(&status) {
        return Err(IndexError::Remote(format!("HTTP {status} for {url}")));
    }

    let mut builder = tempfile::Builder::new();
    builder.prefix("ratarmount-index-").suffix(".tmp.sqlite.index");
    let mut tmp = if let Some(dir) = index_temp_dir() {
        std::fs::create_dir_all(&dir)?;
        builder.tempfile_in(&dir)?
    } else {
        builder.tempfile()?
    };

    let mut reader = resp.into_reader();
    let n = std::io::copy(&mut reader, &mut tmp)?;
    tmp.flush()?;
    let path = tmp
        .into_temp_path()
        .keep()
        .map_err(|e| IndexError::Io(e.error))?;
    debug!("remote index {url} -> {} ({n} bytes)", path.display());
    Ok(path)
}

/// Resolve where to load/create the index.
///
/// * `explicit` — from `--index-file` (`None`, `":memory:"`, path string, or `http(s)://` / `file://` URL).
/// * `folders` — from `--index-folders` (empty → default folders).
/// * `recreate` — skip loading existing; still prefer a writable path for create.
///
/// Absolute `http(s)://` explicit paths are downloaded to a local tempfile and returned as
/// [`IndexLocation::Path`]. Fetch failures for an explicit remote URL fall through to folder
/// candidates (Python trial-and-error style) after a warning.
pub fn resolve_index_location(
    archive: &Path,
    explicit: Option<&str>,
    folders: &[PathBuf],
    recreate: bool,
) -> IndexLocation {
    if let Some(e) = explicit {
        let e = e.trim();
        if e == MEMORY_INDEX {
            return IndexLocation::Memory;
        }
        if e.is_empty() {
            // fall through to folders
        } else if is_index_url(e) {
            match maybe_fetch_index_url(e) {
                Ok(p) => return IndexLocation::Path(p),
                Err(err) => {
                    warn!("could not materialize index URL {e}: {err}");
                    // fall through to folders
                }
            }
        } else {
            return IndexLocation::Path(expand_user(Path::new(e)));
        }
    }

    let folders = if folders.is_empty() {
        default_index_folders()
    } else {
        folders.to_vec()
    };
    let candidates = possible_index_paths(archive, &folders);

    if !recreate {
        for p in &candidates {
            if path_is_usable_existing_index(p) {
                return IndexLocation::Path(p.clone());
            }
        }
    }

    for p in &candidates {
        if path_can_create_index(p) {
            return IndexLocation::Path(p.clone());
        }
    }

    // Last resort: memory (matches Python when no writable location exists).
    IndexLocation::Memory
}

fn path_is_usable_existing_index(path: &Path) -> bool {
    match std::fs::metadata(path) {
        Ok(m) => m.is_file() && m.len() > 0,
        Err(_) => false,
    }
}

fn path_can_create_index(path: &Path) -> bool {
    if let Some(parent) = path.parent() {
        if parent.as_os_str().is_empty() {
            // relative path in cwd
            return test_writable_dir(Path::new("."));
        }
        if !parent.exists() && std::fs::create_dir_all(parent).is_err() {
            return false;
        }
        return test_writable_dir(parent);
    }
    test_writable_dir(Path::new("."))
}

fn test_writable_dir(dir: &Path) -> bool {
    let probe = dir.join(format!(".ratarmount-write-test-{}", std::process::id()));
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
    {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;

    /// Minimal HTTP/1.1 mock serving a fixed body for GET (and HEAD).
    struct MockHttp {
        base: String,
        _join: Option<thread::JoinHandle<()>>,
        hits: Arc<Mutex<usize>>,
    }

    impl MockHttp {
        fn spawn(body: Vec<u8>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let hits = Arc::new(Mutex::new(0usize));
            let hits_c = Arc::clone(&hits);
            let join = thread::spawn(move || {
                for stream in listener.incoming().take(32) {
                    let Ok(mut stream) = stream else { continue };
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut request_line = String::new();
                    if reader.read_line(&mut request_line).is_err() {
                        continue;
                    }
                    // Drain headers.
                    loop {
                        let mut line = String::new();
                        if reader.read_line(&mut line).is_err() {
                            break;
                        }
                        if line == "\r\n" || line == "\n" || line.is_empty() {
                            break;
                        }
                    }
                    {
                        *hits_c.lock().unwrap() += 1;
                    }
                    let is_head = request_line.starts_with("HEAD ");
                    let header = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(header.as_bytes());
                    if !is_head {
                        let _ = stream.write_all(&body);
                    }
                }
            });
            Self {
                base,
                _join: Some(join),
                hits,
            }
        }

        fn url(&self, path: &str) -> String {
            format!("{}{}", self.base, path)
        }
    }

    #[test]
    fn parse_comma_and_json() {
        let v = parse_index_folders(",~/.foo");
        assert_eq!(v.len(), 2);
        assert!(v[0].as_os_str().is_empty());
        assert!(v[1].ends_with(".foo") || v[1].to_string_lossy().contains(".foo"));

        let v = parse_index_folders(r#"["/tmp/a","/tmp/b"]"#);
        assert_eq!(v, vec![PathBuf::from("/tmp/a"), PathBuf::from("/tmp/b")]);
    }

    #[test]
    fn memory_explicit() {
        let loc = resolve_index_location(Path::new("/tmp/a.tar"), Some(":memory:"), &[], false);
        assert_eq!(loc, IndexLocation::Memory);
    }

    #[test]
    fn next_to_archive_default() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        std::fs::write(&archive, b"x").unwrap();
        let loc = resolve_index_location(&archive, None, &[PathBuf::new()], true);
        match loc {
            IndexLocation::Path(p) => {
                assert_eq!(p, default_index_path(&archive));
                assert!(p.to_string_lossy().ends_with("a.tar.index.sqlite"));
            }
            IndexLocation::Memory => panic!("expected path"),
        }
    }

    #[test]
    fn is_index_url_detects_schemes() {
        assert!(is_index_url("http://example.com/a.index.sqlite"));
        assert!(is_index_url("https://example.com/a.index.sqlite"));
        assert!(is_index_url("file:///tmp/a.index.sqlite"));
        assert!(!is_index_url("/tmp/a.index.sqlite"));
        assert!(!is_index_url(":memory:"));
        assert!(!is_index_url("s3://bucket/key"));
    }

    #[test]
    fn sibling_index_url_appends_suffix() {
        assert_eq!(
            sibling_index_url("http://host/path/a.tar"),
            Some("http://host/path/a.tar.index.sqlite".into())
        );
        assert_eq!(
            sibling_index_url("https://host/a.tar.gz"),
            Some("https://host/a.tar.gz.index.sqlite".into())
        );
        assert_eq!(sibling_index_url("/local/a.tar"), None);
        assert_eq!(sibling_index_url("file:///tmp/a.tar"), None);
    }

    #[test]
    fn maybe_fetch_file_url_and_local() {
        let dir = tempfile::tempdir().unwrap();
        let idx = dir.path().join("t.index.sqlite");
        std::fs::write(&idx, b"SQLite format 3\0").unwrap();

        let via_file = maybe_fetch_index_url(&format!("file://{}", idx.display())).unwrap();
        assert_eq!(via_file, idx);

        let via_local = maybe_fetch_index_url(idx.to_str().unwrap()).unwrap();
        assert_eq!(via_local, idx);
    }

    #[test]
    fn maybe_fetch_http_downloads_to_temp() {
        // Fake SQLite header (enough for path materialization tests).
        let body = b"SQLite format 3\0rest-of-fake-index".to_vec();
        let mock = MockHttp::spawn(body.clone());
        let url = mock.url("/archive.tar.index.sqlite");

        let path = maybe_fetch_index_url(&url).unwrap();
        assert!(path.is_file());
        let got = std::fs::read(&path).unwrap();
        assert_eq!(got, body);
        assert!(*mock.hits.lock().unwrap() >= 1);

        // Cleanup kept tempfile.
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn maybe_fetch_http_empty_body() {
        let mock = MockHttp::spawn(Vec::new());
        let url = mock.url("/empty.index.sqlite");
        let path = maybe_fetch_index_url(&url).unwrap();
        assert!(path.is_file());
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn resolve_index_location_materializes_http_explicit() {
        let body = b"SQLite format 3\0".to_vec();
        let mock = MockHttp::spawn(body.clone());
        let url = mock.url("/idx.sqlite");

        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        std::fs::write(&archive, b"x").unwrap();

        let loc = resolve_index_location(&archive, Some(&url), &[PathBuf::new()], false);
        match loc {
            IndexLocation::Path(p) => {
                assert!(p.is_file());
                assert_eq!(std::fs::read(&p).unwrap(), body);
                let _ = std::fs::remove_file(&p);
            }
            IndexLocation::Memory => panic!("expected materialized path"),
        }
    }

    #[test]
    fn resolve_index_location_file_url_explicit() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        let idx = dir.path().join("custom.index.sqlite");
        std::fs::write(&archive, b"x").unwrap();
        std::fs::write(&idx, b"SQLite format 3\0").unwrap();

        let file_url = format!("file://{}", idx.display());
        let loc = resolve_index_location(&archive, Some(&file_url), &[], false);
        assert_eq!(loc, IndexLocation::Path(idx));
    }

    #[test]
    fn resolve_index_location_local_explicit_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        let idx = dir.path().join("local.index.sqlite");
        std::fs::write(&archive, b"x").unwrap();
        let loc = resolve_index_location(&archive, Some(idx.to_str().unwrap()), &[], true);
        assert_eq!(loc, IndexLocation::Path(idx));
    }

    #[test]
    fn sibling_then_fetch() {
        let body = b"SQLite format 3\0sibling".to_vec();
        let mock = MockHttp::spawn(body.clone());
        let archive_url = mock.url("/data/bundle.tar");
        let idx_url = sibling_index_url(&archive_url).unwrap();
        assert!(idx_url.ends_with("/data/bundle.tar.index.sqlite"));
        // Mock serves any path with the same body; fetch sibling URL.
        let path = maybe_fetch_index_url(&idx_url).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), body);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn maybe_fetch_rejects_empty_spec() {
        let err = maybe_fetch_index_url("  ").unwrap_err();
        assert!(matches!(err, IndexError::Invalid(_)));
    }
}
