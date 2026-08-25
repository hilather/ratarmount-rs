//! `ratarmount find PATTERN ARCHIVE` — locate over the 0.7.x catalog (F-3).
//!
//! No FUSE. Default query is glob/LIKE; `--fts` (find-argv only) uses FTS5 MATCH.
//! Stdout is TSV `path\tsize\tmtime` (optional hash columns when `--hashes` is set).

use std::io::{self, Write};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ratarmount_core::OpenOptions;
use ratarmount_index::{
    fill_content_hashes, resolve_index_location, SearchHit, SearchQuery, SqliteIndex, MEMORY_INDEX,
};

/// Options for a locate query (CLI `find` or control-plane glob).
#[derive(Clone, Debug, Default)]
pub struct LocateOptions<'a> {
    /// FTS5 `MATCH` (`--fts` or a `fts:` pattern prefix).
    pub fts: bool,
    /// Attach `user.hash.*` columns when they are already stored (cheap).
    pub include_hashes: bool,
    /// Fill `user.hash.*` xattrs before searching (find `--hashes ALGO`).
    pub fill_hashes: &'a [String],
}

/// TSV `path\tsize\tmtime` plus optional `key=value` hash columns.
pub fn format_hits_tsv(hits: &[SearchHit], include_hashes: bool) -> String {
    let mut out = String::new();
    for h in hits {
        out.push_str(&h.path);
        out.push('\t');
        out.push_str(&h.size.to_string());
        out.push('\t');
        out.push_str(&h.mtime.to_string());
        if include_hashes {
            for (k, v) in &h.hashes {
                out.push('\t');
                out.push_str(k);
                out.push('=');
                out.push_str(v);
            }
        }
        out.push('\n');
    }
    out
}

/// Locate over `archive`'s on-disk sidecar, creating it via [`crate::factory::open_path`]
/// when missing or stale. `:memory:` indexes are rejected.
pub fn locate_hits(
    archive: &Path,
    pattern: &str,
    open_opts: &OpenOptions,
    loc: &LocateOptions<'_>,
) -> Result<Vec<SearchHit>, String> {
    let idx = open_index_for_find(archive, open_opts)?;
    query_index(&idx, archive, pattern, loc)
}

/// Search an existing sidecar only (control plane / socket). Does not cold-index.
pub fn search_existing_sidecar(
    archive: &Path,
    pattern: &str,
    open_opts: &OpenOptions,
    loc: &LocateOptions<'_>,
) -> Result<Vec<SearchHit>, String> {
    let idx = open_existing_sidecar(archive, open_opts)?;
    query_index(&idx, archive, pattern, loc)
}

/// Callback for [`ratarmount_compositing::ControlFolderOptions::with_on_search`].
///
/// Glob only (control `search/<pattern>`). `:memory:` / missing sidecar → the
/// stable error line `error: search requires an on-disk index`.
pub fn tsv_search_callback(
    archive: PathBuf,
    open_opts: OpenOptions,
) -> Arc<dyn Fn(&str) -> String + Send + Sync> {
    Arc::new(move |pattern: &str| {
        match search_existing_sidecar(&archive, pattern, &open_opts, &LocateOptions::default()) {
            Ok(hits) => format_hits_tsv(&hits, false),
            Err(e) => format!("error: {e}\n"),
        }
    })
}

/// Print TSV and return the process exit code (0 matches, 1 none, 2 error).
pub fn run(archive: &Path, pattern: &str, open_opts: &OpenOptions, loc: &LocateOptions<'_>) -> i32 {
    match locate_hits(archive, pattern, open_opts, loc) {
        Ok(hits) => {
            let tsv = format_hits_tsv(&hits, loc.include_hashes);
            let _ = io::stdout().write_all(tsv.as_bytes());
            let _ = io::stdout().flush();
            if hits.is_empty() {
                1
            } else {
                0
            }
        }
        Err(e) => {
            eprintln!("error: {e}");
            2
        }
    }
}

fn query_index(
    idx: &SqliteIndex,
    archive: &Path,
    pattern: &str,
    loc: &LocateOptions<'_>,
) -> Result<Vec<SearchHit>, String> {
    let (fts, pattern) = split_fts_pattern(pattern, loc.fts);
    if !loc.fill_hashes.is_empty() {
        fill_content_hashes(idx, archive, loc.fill_hashes).map_err(|e| e.to_string())?;
    }
    if fts {
        idx.ensure_fts5().map_err(|e| e.to_string())?;
        let q = SearchQuery {
            include_hashes: loc.include_hashes,
            ..SearchQuery::fts(pattern)
        };
        idx.search_query(&q).map_err(|e| e.to_string())
    } else {
        let q = SearchQuery {
            include_hashes: loc.include_hashes,
            ..SearchQuery::glob(pattern)
        };
        idx.search_query(&q).map_err(|e| e.to_string())
    }
}

fn split_fts_pattern(pattern: &str, force_fts: bool) -> (bool, &str) {
    if let Some(rest) = pattern.strip_prefix("fts:") {
        return (true, rest);
    }
    (force_fts, pattern)
}

fn memory_index_error() -> String {
    "search requires an on-disk index".into()
}

fn explicit_index_arg(open_opts: &OpenOptions) -> Option<String> {
    open_opts
        .index_file_path
        .as_ref()
        .map(|p| p.to_string_lossy().into_owned())
}

fn reject_memory(open_opts: &OpenOptions) -> Result<(), String> {
    if open_opts.index_in_memory {
        return Err(memory_index_error());
    }
    if explicit_index_arg(open_opts).as_deref() == Some(MEMORY_INDEX) {
        return Err(memory_index_error());
    }
    Ok(())
}

fn open_existing_sidecar(archive: &Path, open_opts: &OpenOptions) -> Result<SqliteIndex, String> {
    reject_memory(open_opts)?;
    let loc = resolve_index_location(
        archive,
        explicit_index_arg(open_opts).as_deref(),
        &open_opts.index_folders,
        false,
    );
    let Some(idx_path) = loc.as_path() else {
        return Err(memory_index_error());
    };
    if !idx_path.exists() {
        return Err(memory_index_error());
    }
    SqliteIndex::open_writable(idx_path).map_err(|e| e.to_string())
}

fn open_index_for_find(archive: &Path, open_opts: &OpenOptions) -> Result<SqliteIndex, String> {
    reject_memory(open_opts)?;
    if !archive.exists() {
        return Err(format!("not found: {}", archive.display()));
    }
    let explicit = explicit_index_arg(open_opts);
    let loc = resolve_index_location(
        archive,
        explicit.as_deref(),
        &open_opts.index_folders,
        open_opts.clear_index_cache,
    );
    let Some(idx_path) = loc.as_path().map(Path::to_path_buf) else {
        return Err(memory_index_error());
    };

    let warm = !open_opts.clear_index_cache
        && idx_path.exists()
        && sidecar_tarstats_ok(&idx_path, archive);
    if !warm {
        // factory::open_path seals with a "Successfully loaded offset dictionary"
        // println (Python harness contract). Keep find stdout as TSV only.
        silence_stdout(|| {
            crate::factory::open_path(archive, open_opts, open_opts.clear_index_cache)
        })
        .map_err(|e| e.to_string())?;
        let loc = resolve_index_location(
            archive,
            explicit.as_deref(),
            &open_opts.index_folders,
            false,
        );
        let Some(idx_path) = loc.as_path() else {
            return Err(memory_index_error());
        };
        if !idx_path.exists() {
            return Err(memory_index_error());
        }
        return SqliteIndex::open_writable(idx_path).map_err(|e| e.to_string());
    }
    SqliteIndex::open_writable(&idx_path).map_err(|e| e.to_string())
}

fn sidecar_tarstats_ok(idx_path: &Path, archive: &Path) -> bool {
    match SqliteIndex::open_writable(idx_path) {
        Ok(idx) => idx.check_tarstats_matches_archive(archive).is_ok(),
        Err(_) => false,
    }
}

/// Redirect stdout to `/dev/null` for `f`, then restore. Best-effort.
fn silence_stdout<T>(f: impl FnOnce() -> T) -> T {
    let _ = io::stdout().flush();
    // SAFETY: duplicating STDOUT_FILENO to restore after `/dev/null` redirect.
    let saved = unsafe { libc::dup(libc::STDOUT_FILENO) };
    if saved < 0 {
        return f();
    }
    restore_stdout_after(saved, f)
}

fn restore_stdout_after<T>(saved: RawFd, f: impl FnOnce() -> T) -> T {
    let devnull = std::fs::OpenOptions::new().write(true).open("/dev/null");
    match devnull {
        Ok(null) => {
            // SAFETY: `saved` is a dup of stdout; `null` is an open `/dev/null`.
            unsafe {
                libc::dup2(null.as_raw_fd(), libc::STDOUT_FILENO);
            }
            let out = f();
            unsafe {
                libc::dup2(saved, libc::STDOUT_FILENO);
                libc::close(saved);
            }
            let _ = io::stdout().flush();
            out
        }
        Err(_) => {
            // SAFETY: `saved` is an unused dup we still own.
            unsafe {
                libc::close(saved);
            }
            f()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratarmount_formats_tar::{write_tar_eof, write_ustar_members, UstarMember, UstarPayload};
    use std::process::Command;

    fn member<'a>(path: &'a str, bytes: &'a [u8], mtime: u64) -> UstarMember<'a> {
        UstarMember {
            path,
            payload: UstarPayload::File { bytes },
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime,
        }
    }

    fn write_fits_tar(path: &Path) {
        let a = b"fits";
        let b = b"fits2";
        let txt = b"hello";
        let members = [
            member("a.fits", a, 1),
            member("dir/b.fits", b, 2),
            member("readme.txt", txt, 3),
        ];
        let mut out = Vec::new();
        write_ustar_members(&mut out, &members).unwrap();
        write_tar_eof(&mut out).unwrap();
        std::fs::write(path, out).unwrap();
    }

    fn find_opts(_dir: &Path) -> OpenOptions {
        OpenOptions {
            // Empty folder = sidecar next to the archive (CLI default).
            index_folders: vec![PathBuf::new()],
            write_index: true,
            ..OpenOptions::default()
        }
    }

    fn hit_paths(hits: &[SearchHit]) -> Vec<&str> {
        hits.iter().map(|h| h.path.as_str()).collect()
    }

    fn ratarmount_bin() -> Option<PathBuf> {
        if let Some(p) = option_env!("CARGO_BIN_EXE_ratarmount") {
            let path = PathBuf::from(p);
            if path.is_file() {
                return Some(path);
            }
        }
        let mut exe = std::env::current_exe().ok()?;
        exe.pop();
        if exe.file_name().and_then(|s| s.to_str()) == Some("deps") {
            exe.pop();
        }
        exe.push(format!("ratarmount{}", std::env::consts::EXE_SUFFIX));
        exe.is_file().then_some(exe)
    }

    /// Regression: `find '*.fits'` without FUSE returns every matching basename as TSV.
    #[test]
    fn find_glob() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        write_fits_tar(&archive);
        let opts = find_opts(dir.path());
        let loc = LocateOptions::default();
        let hits = locate_hits(&archive, "*.fits", &opts, &loc).expect("locate");
        assert_eq!(hit_paths(&hits), vec!["/a.fits", "/dir/b.fits"]);
        assert_eq!(hits[0].size, 4);
        let tsv = format_hits_tsv(&hits, false);
        assert!(tsv.contains("/a.fits\t4\t"), "{tsv}");
        assert!(tsv.contains("/dir/b.fits\t5\t"), "{tsv}");
        assert!(!tsv.contains("readme.txt"), "{tsv}");

        let none = locate_hits(&archive, "*.nope", &opts, &loc).expect("empty");
        assert!(none.is_empty());

        let Some(bin) = ratarmount_bin() else {
            eprintln!("skip: ratarmount binary not built next to test exe (API glob still ran)");
            return;
        };
        let out = Command::new(&bin)
            .args(["find", "*.fits", archive.to_str().unwrap()])
            .current_dir(dir.path())
            .output()
            .expect("spawn find");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success(),
            "find exit {:?}: {stderr} {stdout}",
            out.status.code()
        );
        let tsv_lines: Vec<&str> = stdout.lines().filter(|l| l.contains('\t')).collect();
        assert!(
            tsv_lines.iter().any(|l| l.starts_with("/a.fits\t")),
            "stdout={stdout:?}"
        );
        assert!(
            tsv_lines.iter().any(|l| l.starts_with("/dir/b.fits\t")),
            "stdout={stdout:?}"
        );
    }

    /// Regression: `:memory:` / missing archive are clear errors (need an on-disk index).
    #[test]
    fn find_glob_rejects_memory_and_missing() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        write_fits_tar(&archive);

        let mem = OpenOptions {
            index_in_memory: true,
            index_file_path: Some(PathBuf::from(MEMORY_INDEX)),
            ..find_opts(dir.path())
        };
        let err = locate_hits(&archive, "*.fits", &mem, &LocateOptions::default()).unwrap_err();
        assert!(
            err.contains("on-disk index"),
            "memory must not locate, got {err}"
        );

        let missing = dir.path().join("nope.tar");
        let err = locate_hits(
            &missing,
            "*.fits",
            &find_opts(dir.path()),
            &LocateOptions::default(),
        )
        .unwrap_err();
        assert!(err.contains("not found"), "{err}");
    }
}
