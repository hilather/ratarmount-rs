//! `ratarmount find PATTERN ARCHIVE` — locate over the 0.7.x catalog (F-3).
//!
//! No FUSE. Default query is glob/LIKE; `--fts` (find-argv only) uses FTS5 MATCH.
//! `--offset-order` (find-argv only) re-sorts today's path-order LIMIT set by
//! `offsetheader`. Stdout is TSV `path\tsize\tmtime` (optional hash columns
//! when `--hashes` is set).

use std::io::{self, Write};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Weak};

use ratarmount_compositing::{live_search_tsv, WriteOverlay};
use ratarmount_core::{CheapSearchHit, MountSource, OpenOptions};
use ratarmount_index::{
    fill_content_hashes, resolve_index_location, resolve_prepared_index_location, SearchHit,
    SearchQuery, SqliteIndex, DEFAULT_SEARCH_LIMIT, MEMORY_INDEX,
};
use ratarmount_session::{query_index, split_fts_pattern};

/// Options for a locate query (CLI `find` or control-plane glob).
#[derive(Clone, Debug, Default)]
pub struct LocateOptions<'a> {
    /// FTS5 `MATCH` (`--fts` or a `fts:` pattern prefix).
    pub fts: bool,
    /// Attach `user.hash.*` columns when they are already stored (cheap).
    pub include_hashes: bool,
    /// Fill `user.hash.*` xattrs before searching (find `--hashes ALGO`).
    pub fill_hashes: &'a [String],
    /// Re-sort today's path-order LIMIT set by `offsetheader` (find `--offset-order`).
    pub offset_order: bool,
    /// AND predicates: NAME, NAME=VALUE, NAME!=VALUE.
    pub xattrs: &'a [String],
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

/// Locate over `archive`'s on-disk sidecar, creating it via [`ratarmount_session::factory::open_path`]
/// when missing or stale. `:memory:` indexes are rejected.
pub fn locate_hits(
    archive: &Path,
    pattern: &str,
    open_opts: &OpenOptions,
    loc: &LocateOptions<'_>,
) -> Result<Vec<SearchHit>, String> {
    let idx = open_index_for_find(archive, open_opts)?;
    query_index_cli(&idx, archive, pattern, loc, open_opts.read_only_index)
}

/// Search an existing sidecar only (control plane / socket). Does not cold-index.
pub fn search_existing_sidecar(
    archive: &Path,
    pattern: &str,
    open_opts: &OpenOptions,
    loc: &LocateOptions<'_>,
) -> Result<Vec<SearchHit>, String> {
    let idx = open_existing_sidecar(archive, open_opts)?;
    query_index_cli(&idx, archive, pattern, loc, open_opts.read_only_index)
}

/// Sidecar-only SearchFn (no overlay / SoA). Live mounts use [`live_search_callback`].
///
/// Glob only. `:memory:` / missing sidecar → `error: search requires an on-disk index`.
/// Kept for tests and callers that have no `MountSource`; the bin uses
/// [`live_search_callback`] for control/socket.
#[allow(dead_code)]
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

/// One SearchFn for control file ≡ socket. Closes over the pre-Control source
/// plus optional overlay (steps in [`live_search_tsv`]).
///
/// The callback stores [`Weak`] handles. The control thread is detached and
/// starts in the serving process (the daemon child, after `fork`). A strong
/// [`Arc`] held by that thread would outlive the mount, so [`WriteOverlay`]'s
/// last owner would never drop and the final `pending_rows` replay would not run.
/// After unmount, upgrade fails and search reports that the archive is gone.
pub fn live_search_callback(
    source: Arc<dyn MountSource>,
    overlay: Option<Arc<WriteOverlay>>,
    archive: PathBuf,
    open_opts: OpenOptions,
) -> Arc<dyn Fn(&str) -> String + Send + Sync> {
    let source = Arc::downgrade(&source);
    let overlay = overlay.as_ref().map(Arc::downgrade);
    Arc::new(move |pattern: &str| {
        let Some(source) = source.upgrade() else {
            return "error: archive is not mounted\n".to_string();
        };
        let overlay: Option<Arc<WriteOverlay>> = overlay.as_ref().and_then(Weak::upgrade);
        live_search_tsv(source.as_ref(), overlay.as_deref(), pattern, |pat| {
            search_existing_sidecar(
                archive.as_path(),
                pat,
                &open_opts,
                &LocateOptions::default(),
            )
            .map(|hits| hits.into_iter().map(CheapSearchHit::from).collect())
        })
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

fn query_index_cli(
    idx: &SqliteIndex,
    archive: &Path,
    pattern: &str,
    loc: &LocateOptions<'_>,
    read_only_index: bool,
) -> Result<Vec<SearchHit>, String> {
    let (fts, pattern) = split_fts_pattern(pattern, loc.fts);
    if !loc.fill_hashes.is_empty() {
        if read_only_index {
            return Err(
                "--no-recreate-index forbids --hashes; prepare hashes before starting workers"
                    .into(),
            );
        }
        fill_content_hashes(idx, archive, loc.fill_hashes).map_err(|e| e.to_string())?;
    }
    if fts {
        if read_only_index {
            if !idx.has_files_fts().map_err(|e| e.to_string())? {
                return Err("--no-recreate-index requires prepared FTS; stop workers and prepare FTS before searching".into());
            }
        } else {
            idx.ensure_fts5().map_err(|e| e.to_string())?;
        }
    }
    let predicates = loc
        .xattrs
        .iter()
        .map(|s| parse_xattr_filter(s))
        .collect::<Result<Vec<_>, _>>()?;
    let mut hits = Vec::new();
    let mut cursor: Option<(String, Option<i64>)> = None;
    loop {
        let q = SearchQuery {
            include_hashes: loc.include_hashes,
            offset_order: false,
            after: cursor
                .as_ref()
                .map(|(path, offset)| ratarmount_index::FindAfter {
                    fullpath: path,
                    offsetheader: *offset,
                }),
            limit: DEFAULT_SEARCH_LIMIT,
            ..if fts {
                SearchQuery::fts(pattern)
            } else {
                SearchQuery::glob(pattern)
            }
        };
        let page = query_index(idx, &q)?;
        let done = page.len() < DEFAULT_SEARCH_LIMIT;
        if let Some(last) = page.last() {
            cursor = Some((last.path.clone(), last.offsetheader));
        }
        for hit in page {
            let mut matches = true;
            for (name, op, expected) in &predicates {
                let value = match hit.offsetheader {
                    Some(offset) => idx.get_xattr(offset, name).map_err(|e| e.to_string())?,
                    None => None,
                };
                matches &= match op {
                    0 => value.is_some(),
                    1 => value.as_deref() == Some(expected.as_bytes()),
                    _ => value.is_some_and(|v| v != expected.as_bytes()),
                };
            }
            if matches {
                hits.push(hit);
            }
            if hits.len() == DEFAULT_SEARCH_LIMIT {
                break;
            }
        }
        if done || hits.len() == DEFAULT_SEARCH_LIMIT {
            break;
        }
    }
    if loc.offset_order {
        hits.sort_by(|a, b| {
            ratarmount_index::cmp_offset_then_name(a.offsetheader, &a.path, b.offsetheader, &b.path)
        });
    }
    Ok(hits)
}

fn parse_xattr_filter(text: &str) -> Result<(String, u8, String), String> {
    let (name, op, value) = if let Some((name, value)) = text.split_once("!=") {
        (name, 2, value)
    } else if let Some((name, value)) = text.split_once('=') {
        (name, 1, value)
    } else {
        (text, 0, "")
    };
    if name.is_empty() || name.contains(['!', '\0', '\n']) {
        return Err(format!("invalid xattr filter: {text}"));
    }
    let name = if name.starts_with("user.") {
        name.into()
    } else {
        format!("user.{name}")
    };
    Ok((name, op, value.into()))
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

fn open_prepared_sidecar(archive: &Path, open_opts: &OpenOptions) -> Result<SqliteIndex, String> {
    reject_memory(open_opts)?;
    let loc = resolve_prepared_index_location(
        archive,
        explicit_index_arg(open_opts).as_deref(),
        &open_opts.index_folders,
    )
    .map_err(|e| e.to_string())?;
    let path = loc.as_path().ok_or_else(memory_index_error)?;
    let idx = SqliteIndex::open_read_only_for_open(path, open_opts).map_err(|e| e.to_string())?;
    idx.check_prepared_tarstats(archive)
        .map_err(|e| e.to_string())?;
    // Dispatch verifies the selected backend as well as the archive identity.
    // No strict path may rescue an invalid catalog with a cold build.
    silence_stdout(|| ratarmount_session::factory::open_path(archive, open_opts, false))
        .map_err(|e| e.to_string())?;
    Ok(idx)
}

fn open_existing_sidecar(archive: &Path, open_opts: &OpenOptions) -> Result<SqliteIndex, String> {
    if open_opts.read_only_index {
        return open_prepared_sidecar(archive, open_opts);
    }
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
    if open_opts.read_only_index {
        return open_prepared_sidecar(archive, open_opts);
    }
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
            ratarmount_session::factory::open_path(archive, open_opts, open_opts.clear_index_cache)
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
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-B0016-M01","item":"ratarmount::find::silence_stdout","disposition":"out-of-family","category":"runtime-resource-or-descriptor-handoff","reason":"standard descriptor handoff: duplicates or redirects a standard stream descriptor; opens no pathname and reads no file content","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
    )]
    let saved = unsafe { libc::dup(libc::STDOUT_FILENO) };
    if saved < 0 {
        return f();
    }
    restore_stdout_after(saved, f)
}

fn restore_stdout_after<T>(saved: RawFd, f: impl FnOnce() -> T) -> T {
    let devnull = {
        #[expect(
            clippy::disallowed_types,
            reason = r###"internal-read:v1 {"id":"IR-B0017-T01","item":"ratarmount::find::restore_stdout_after","disposition":"support","category":"builder-type-support","reason":"Builder type support: standard descriptor handoff","mode_policy":"unchanged-from-e6ca64e","creation":{"policy":"none","basis":"This is a type/import reference; it acquires no file or directory."}}"###
        )]
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-B0017-M01","item":"ratarmount::find::restore_stdout_after","disposition":"support","category":"builder-setup","reason":"Prepare the builder for this item's separately reviewed open/create leaf.","mode_policy":"unchanged-from-e6ca64e","creation":{"policy":"none","basis":"Builder construction/setup only; the separate open/create leaf owns pathname acquisition and permissions."},"supports_disposition":"out-of-family","baseline_reason":"standard descriptor handoff"}"###
        )]
        let mut __inventory_value_0 = std::fs::OpenOptions::new();
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-B0017-M02","item":"ratarmount::find::restore_stdout_after","disposition":"out-of-family","category":"runtime-resource-or-descriptor-handoff","reason":"standard descriptor handoff","mode_policy":"unchanged-from-e6ca64e","creation":{"policy":"unchanged-from-e6ca64e","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###
        )]
        let __inventory_value_1 = __inventory_value_0.write(true).open("/dev/null");
        __inventory_value_1
    };
    match devnull {
        Ok(null) => {
            // SAFETY: `saved` is a dup of stdout; `null` is an open `/dev/null`.
            unsafe {
                #[expect(
                    clippy::disallowed_methods,
                    reason = r###"internal-read:v1 {"id":"IR-B0018-M01","item":"ratarmount::find::restore_stdout_after","disposition":"out-of-family","category":"runtime-resource-or-descriptor-handoff","reason":"standard descriptor handoff: duplicates or redirects a standard stream descriptor; opens no pathname and reads no file content","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
                )]
                libc::dup2(null.as_raw_fd(), libc::STDOUT_FILENO);
            }
            let out = f();
            unsafe {
                #[expect(
                    clippy::disallowed_methods,
                    reason = r###"internal-read:v1 {"id":"IR-B0019-M01","item":"ratarmount::find::restore_stdout_after","disposition":"out-of-family","category":"runtime-resource-or-descriptor-handoff","reason":"standard descriptor handoff: duplicates or redirects a standard stream descriptor; opens no pathname and reads no file content","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
                )]
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
            xattrs: &[],
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

    /// Regression: live FTS search must query prepared state without populating it.
    #[test]
    fn regression_prepared_index_live_search_fts_is_immutable() {
        for prepared_fts in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let archive = dir.path().join("archive.tar");
            write_fits_tar(&archive);
            let index = dir.path().join("archive.tar.index.sqlite");
            let mut options = OpenOptions {
                index_file_path: Some(index.clone()),
                ..Default::default()
            };
            drop(ratarmount_session::factory::open_path(&archive, &options, false).unwrap());
            if prepared_fts {
                let db = SqliteIndex::open_writable(&index).unwrap();
                db.ensure_fts5().unwrap();
            }
            SqliteIndex::finalize_prepared(&index).unwrap();
            options.read_only_index = true;
            options.write_index = false;
            let source = ratarmount_session::factory::open_path(&archive, &options, false).unwrap();
            let overlay = Arc::new(
                crate::base_identity::fixtures::overlay_over(
                    source.clone(),
                    dir.path().join("overlay"),
                    archive.to_str().unwrap(),
                    Vec::new(),
                )
                .unwrap(),
            );
            let snapshot = || {
                std::fs::read_dir(dir.path())
                    .unwrap()
                    .filter_map(|e| {
                        let p = e.unwrap().path();
                        p.is_file().then(|| {
                            (
                                p.file_name().unwrap().to_owned(),
                                std::fs::read(&p).unwrap(),
                            )
                        })
                    })
                    .collect::<std::collections::BTreeMap<_, _>>()
            };
            let before = snapshot();
            let callback = live_search_callback(
                source.clone(),
                Some(overlay.clone()),
                archive.clone(),
                options,
            );
            let answer = callback("fts:fits");
            if prepared_fts {
                assert!(answer.contains("a.fits"), "{answer}");
            } else {
                assert!(answer.contains("prepared FTS"), "{answer}");
            }
            assert_eq!(snapshot(), before);
            drop(callback);
            drop(overlay);
            drop(source);
            assert_eq!(snapshot(), before);
        }
    }

    /// Regression: xattr predicates match index bytes and do not treat missing as !=.
    #[test]
    fn regression_provenance_find_xattr_filters() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("trace.tar");
        let attrs = vec![("user.train_ok".into(), b"false".to_vec())];
        let mut tagged = member("tagged", b"trace", 1);
        tagged.xattrs = &attrs;
        let mut out = Vec::new();
        write_ustar_members(&mut out, &[tagged, member("untagged", b"other", 2)]).unwrap();
        write_tar_eof(&mut out).unwrap();
        std::fs::write(&archive, out).unwrap();
        for (filter, expected) in [
            ("train_ok", 1),
            ("train_ok=false", 1),
            ("user.train_ok!=true", 1),
            ("train_ok=true", 0),
            ("train_ok!=false", 0),
        ] {
            let filters = vec![filter.into()];
            let loc = LocateOptions {
                xattrs: &filters,
                ..Default::default()
            };
            let hits = locate_hits(&archive, "*", &find_opts(dir.path()), &loc).unwrap();
            assert_eq!(hits.len(), expected, "{filter}");
            if expected == 1 {
                assert_eq!(hits[0].path, "/tagged");
            }
        }
    }

    /// Regression: filtering a pre-limited page hides matches beyond the first 10k rows.
    #[test]
    fn regression_provenance_find_filters_before_limit() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("many.tar");
        let names: Vec<_> = (0..DEFAULT_SEARCH_LIMIT + 1)
            .map(|i| format!("a{i:05}"))
            .collect();
        let mut members: Vec<_> = names.iter().map(|name| member(name, b"", 0)).collect();
        let attrs = vec![
            ("user.train_ok".into(), b"false".to_vec()),
            ("user.teacher".into(), b"model".to_vec()),
        ];
        let mut last = member("zz-last", b"", 0);
        last.xattrs = &attrs;
        members.push(last);
        let mut out = Vec::new();
        write_ustar_members(&mut out, &members).unwrap();
        write_tar_eof(&mut out).unwrap();
        std::fs::write(&archive, out).unwrap();
        let filters = vec!["train_ok=false".into(), "teacher".into()];
        let loc = LocateOptions {
            xattrs: &filters,
            ..Default::default()
        };
        let hits = locate_hits(&archive, "*", &find_opts(dir.path()), &loc).unwrap();
        assert_eq!(hit_paths(&hits), ["/zz-last"]);
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
        let _processes = ratarmount_index::test_process::spawning();
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

    fn write_za_tar(path: &Path) {
        let z = b"zzzz";
        let a = b"aaaa";
        let members = [member("z.txt", z, 1), member("a.txt", a, 2)];
        let mut out = Vec::new();
        write_ustar_members(&mut out, &members).unwrap();
        write_tar_eof(&mut out).unwrap();
        std::fs::write(path, out).unwrap();
    }

    /// Regression: find `--offset-order` TSV follows `offsetheader` (CLI path).
    #[test]
    fn find_offset_order() {
        let _processes = ratarmount_index::test_process::spawning();
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("za.tar");
        write_za_tar(&archive);
        let opts = find_opts(dir.path());

        let default =
            locate_hits(&archive, "*", &opts, &LocateOptions::default()).expect("default");
        assert_eq!(hit_paths(&default), vec!["/a.txt", "/z.txt"]);

        let Some(bin) = ratarmount_bin() else {
            eprintln!("skip: ratarmount binary not built next to test exe (API order still ran)");
            return;
        };

        let out = Command::new(&bin)
            .args(["find", "--offset-order", "*", archive.to_str().unwrap()])
            .current_dir(dir.path())
            .output()
            .expect("spawn find --offset-order");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success(),
            "find --offset-order exit {:?}: {stderr} {stdout}",
            out.status.code()
        );
        let names: Vec<&str> = stdout
            .lines()
            .filter(|l| l.contains('\t'))
            .map(|l| l.split('\t').next().unwrap_or(""))
            .collect();
        assert_eq!(names, vec!["/z.txt", "/a.txt"], "stdout={stdout:?}");

        let out = Command::new(&bin)
            .args(["find", "*", archive.to_str().unwrap()])
            .current_dir(dir.path())
            .output()
            .expect("spawn find");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let names: Vec<&str> = stdout
            .lines()
            .filter(|l| l.contains('\t'))
            .map(|l| l.split('\t').next().unwrap_or(""))
            .collect();
        assert_eq!(names, vec!["/a.txt", "/z.txt"], "default stdout={stdout:?}");
    }

    /// Control / socket TSV stays path order when `SearchQuery.offset_order` exists.
    #[test]
    fn control_search_stays_path_order() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("za.tar");
        write_za_tar(&archive);
        let opts = find_opts(dir.path());
        locate_hits(&archive, "*", &opts, &LocateOptions::default()).expect("index");

        let cb = tsv_search_callback(archive.clone(), opts);
        let tsv = cb("*");
        let names: Vec<&str> = tsv
            .lines()
            .filter(|l| l.contains('\t'))
            .map(|l| l.split('\t').next().unwrap_or(""))
            .collect();
        assert_eq!(names, vec!["/a.txt", "/z.txt"], "control TSV={tsv:?}");
    }

    /// Regression: sidecar-only callback still formats TSV (control tests are not enough).
    #[test]
    fn tsv_search_callback_sidecar_only() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        write_fits_tar(&archive);
        let opts = find_opts(dir.path());
        let _ = locate_hits(&archive, "*.fits", &opts, &LocateOptions::default()).expect("index");
        let cb = tsv_search_callback(archive, opts);
        let tsv = cb("*.fits");
        assert!(tsv.contains("/a.fits\t4\t"), "{tsv}");
        assert!(!tsv.starts_with("error:"), "{tsv}");
    }

    /// Regression: warm sidecar find keeps mem: None (do not load MemIndex).
    #[test]
    fn find_glob_warm_sidecar_mem_stays_none() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        write_fits_tar(&archive);
        let opts = find_opts(dir.path());
        let _ = locate_hits(&archive, "*.fits", &opts, &LocateOptions::default()).expect("index");
        let idx = open_existing_sidecar(&archive, &opts).expect("warm sidecar");
        assert!(
            !idx.has_mem_index(),
            "open_writable / find must keep mem: None"
        );
        let hits = idx.search("*.fits").unwrap();
        assert_eq!(hit_paths(&hits), vec!["/a.fits", "/dir/b.fits"]);
        assert!(!idx.has_mem_index());
    }

    /// Regression: CLI first page stays 10_000; Session::find default page is 200.
    #[test]
    fn find_session_parity() {
        use ratarmount_session::{
            FindCursor, FindOpts, IndexPolicy, OpenRequest, Recreate, Session, SourceSpec,
            DEFAULT_FIND_PAGE,
        };

        assert_eq!(DEFAULT_SEARCH_LIMIT, 10_000);
        assert_eq!(DEFAULT_FIND_PAGE, 200);
        let q = SearchQuery::glob("*.fits");
        assert_eq!(q.limit, 10_000);
        assert!(q.after.is_none());

        let dir = tempfile::tempdir().unwrap();
        let names: Vec<String> = (0..250).map(|i| format!("f{i:03}.txt")).collect();
        let payload = b"x";
        let members: Vec<UstarMember<'_>> = names
            .iter()
            .map(|n| member(n.as_str(), payload, 1))
            .collect();
        let archive = dir.path().join("many.tar");
        {
            let mut out = Vec::new();
            write_ustar_members(&mut out, &members).unwrap();
            write_tar_eof(&mut out).unwrap();
            std::fs::write(&archive, out).unwrap();
        }
        let opts = find_opts(dir.path());
        let cli = locate_hits(&archive, "*.txt", &opts, &LocateOptions::default()).expect("cli");
        assert_eq!(cli.len(), 250, "CLI first page limit is 10_000");

        let idx = dir.path().join("many.tar.index.sqlite");
        let session = Session::open(OpenRequest {
            source: SourceSpec::Path(archive.clone()),
            index: IndexPolicy::Explicit,
            explicit_index: Some(idx),
            extra_dirs: Vec::new(),
            password: None,
            recursive: false,
            recursion_depth: None,
            parallelization: Default::default(),
            recreate: Recreate::IfInvalid,
        })
        .expect("session open");
        let page = session
            .find("*.txt", FindOpts::default())
            .expect("session find");
        assert_eq!(page.entries.len(), 200, "session limit 0 → 200");
        assert!(
            matches!(page.next_cursor, Some(FindCursor::AfterPath { .. })),
            "session first page must have a next cursor"
        );
        let cli_paths: Vec<&str> = cli.iter().map(|h| h.path.as_str()).collect();
        let sess_paths: Vec<&str> = page.entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(&cli_paths[..200], sess_paths.as_slice());

        let rest = session
            .find(
                "*.txt",
                FindOpts {
                    cursor: page.next_cursor.unwrap(),
                    ..FindOpts::default()
                },
            )
            .unwrap();
        assert_eq!(rest.entries.len(), 50);
        assert!(rest.next_cursor.is_none());
        let all: Vec<&str> = sess_paths
            .into_iter()
            .chain(rest.entries.iter().map(|e| e.path.as_str()))
            .collect();
        assert_eq!(all, cli_paths);
    }
}
