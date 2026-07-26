//! Index path resolution (Python `SQLiteIndex.get_possible_index_file_paths` subset).

use std::path::{Path, PathBuf};

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

/// Resolve where to load/create the index.
///
/// * `explicit` — from `--index-file` (`None`, `":memory:"`, or a path string).
/// * `folders` — from `--index-folders` (empty → default folders).
/// * `recreate` — skip loading existing; still prefer a writable path for create.
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
}
