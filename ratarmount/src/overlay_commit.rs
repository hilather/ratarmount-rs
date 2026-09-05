//! Live overlay commit (uncompressed TAR and `.tar.zst`): interval + on-exit.
//!
//! `--commit-overlay-interval` is a per-file settle time: only overlay files
//! whose host mtime is at least that old are persisted. On-exit still flushes
//! the whole overlay.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use ratarmount_compositing::{
    classify_createable_archive, maybe_create_empty_write_archive, maybe_wrap_payload_cache,
    patch_sidecar_at, patch_sidecar_if_present, sidecar_path_for_patch, CommitKind, CommitOutcome,
    EmptyArchiveKind, EmptyCreateOutcome, IndexPatchWindow, OverlayError, WriteOverlay,
};
use ratarmount_compress::{
    detect_compression, open_seekable_zstd_with_threads, scan_zstd_frames_path, CompressionFormat,
};
use ratarmount_core::{MountSource, OpenOptions};
use ratarmount_formats_tar::SqliteIndexedTar;
use ratarmount_index::{serialize_tarstats, tar_stats_from_path, IndexPointer, SqliteIndex};
use ratarmount_nfs::NfsStop;
use ratarmount_session::factory;

/// Warn when the last zstd frame's uncompressed size exceeds this.
const LIVE_COMMIT_WARN_LAST_FRAME: u64 = 64 * 1024 * 1024;

static GOT_TERM: AtomicBool = AtomicBool::new(false);

extern "C" fn on_term_signal(_: libc::c_int) {
    GOT_TERM.store(true, Ordering::SeqCst);
}

/// Parse `--commit-overlay-interval`: `0`/`0s` off; `2s`/`15m`/`1h` or a bare second count.
pub fn parse_interval(s: &str) -> Result<Option<Duration>, String> {
    let t = s.trim();
    if t.is_empty() {
        return Ok(None);
    }
    let (num_s, mult) = if let Some(n) = t.strip_suffix('s') {
        (n, 1u64)
    } else if let Some(n) = t.strip_suffix('m') {
        (n, 60)
    } else if let Some(n) = t.strip_suffix('h') {
        (n, 3600)
    } else {
        (t, 1)
    };
    let n: u64 = num_s
        .trim()
        .parse()
        .map_err(|_| format!("invalid --commit-overlay-interval {s:?}"))?;
    if n == 0 {
        return Ok(None);
    }
    let secs = n.saturating_mul(mult);
    if secs == 0 {
        return Ok(None);
    }
    Ok(Some(Duration::from_secs(secs)))
}

pub fn install_term_signal_flag() {
    unsafe {
        libc::signal(
            libc::SIGINT,
            on_term_signal as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGTERM,
            on_term_signal as *const () as libc::sighandler_t,
        );
    }
}

pub fn term_requested() -> bool {
    GOT_TERM.load(Ordering::SeqCst)
}

pub fn spawn_signal_nfs_stop(stop: NfsStop) {
    thread::Builder::new()
        .name("ratarmount-nfs-signal".into())
        .spawn(move || {
            while !GOT_TERM.load(Ordering::SeqCst) && !stop.is_stopped() {
                thread::sleep(Duration::from_millis(50));
            }
            stop.request_stop();
        })
        .expect("signal stopper thread");
}

/// SIGINT/`GOT_TERM` calls every export stop (NFS `NfsStop` and `ExportStop`).
///
/// NFS-only keeps [`spawn_signal_nfs_stop`]. Multi-export (`--http` + `--nfs`, …)
/// uses this helper so one Ctrl-C stops every listener.
pub fn spawn_signal_export_stops(stops: Vec<Arc<dyn Fn() + Send + Sync>>) {
    thread::Builder::new()
        .name("ratarmount-export-signal".into())
        .spawn(move || {
            while !GOT_TERM.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(50));
            }
            for stop in &stops {
                stop();
            }
        })
        .expect("export signal stopper thread");
}

/// Watch [`term_requested`] and unmount FUSE so `mount_blocking` returns
/// (then the caller can `--commit-overlay-on-exit`). Replaces default SIGINT
/// terminate — without this, Ctrl-C only sets a flag and the mount stays up.
pub fn spawn_signal_fuse_unmount(mp: PathBuf) {
    thread::Builder::new()
        .name("ratarmount-fuse-signal".into())
        .spawn(move || {
            while !GOT_TERM.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(50));
            }
            let _ = ratarmount_fuse::unmount(&mp);
        })
        .expect("fuse signal unmount thread");
}

/// Persist target for live overlay commit (local file or F-7 spool).
#[derive(Debug, Clone)]
pub struct LiveCommitArchive {
    /// Local path passed to `enqueue_commit` / `persist_by_format` (the spool for `s3://`).
    pub path: PathBuf,
    /// Original `s3://` URL when this is an F-7 write-through mount.
    pub s3_url: Option<String>,
}

pub fn spawn_interval_commits(
    overlay: Arc<WriteOverlay>,
    archive: PathBuf,
    interval: Duration,
    stop: Option<NfsStop>,
    opts: OpenOptions,
    s3_url: Option<String>,
) {
    // Poll at least once a second so a file enters the archive ~`interval`
    // after its last host mtime, not up to 2× interval later. The settle
    // threshold is still `interval` (only idle files are persisted).
    let poll = Duration::from_secs(1).min(interval);
    thread::Builder::new()
        .name("ratarmount-overlay-commit".into())
        .spawn(move || loop {
            let start = Instant::now();
            while start.elapsed() < poll {
                if term_requested() || stop.as_ref().is_some_and(|s| s.is_stopped()) {
                    return;
                }
                thread::sleep(Duration::from_millis(50));
            }
            if term_requested() || stop.as_ref().is_some_and(|s| s.is_stopped()) {
                return;
            }
            let ov = Arc::clone(&overlay);
            let opts_c = opts.clone();
            let s3 = s3_url.clone();
            match overlay.enqueue_commit(&archive, CommitKind::IntervalIdle(interval), |p| {
                if let Some(url) = s3.as_deref() {
                    // Patch+PUT already ran in after_persist; p is the spool.
                    let _ = p;
                    factory::open_live_remote(url, &opts_c).map_err(OverlayError::Msg)
                } else {
                    if let Some(window) = ov.last_patch_window() {
                        patch_sidecar_if_present(p, &window, &opts_c)?;
                    }
                    reopen_live_archive(p, &opts_c).map_err(OverlayError::Msg)
                }
            }) {
                Ok(CommitOutcome::DidWork) => log::info!(
                    "interval overlay commit wrote idle files into {}",
                    archive.display()
                ),
                Ok(CommitOutcome::Nothing) => {
                    log::debug!("interval overlay commit: nothing idle to do")
                }
                Ok(CommitOutcome::Coalesced) => {
                    log::debug!("interval overlay commit coalesced (persist already in flight)")
                }
                Ok(CommitOutcome::Disabled) => {
                    log::debug!("interval overlay commit skipped (remount required)")
                }
                Err(e) => log::error!("interval overlay commit failed: {e}"),
            }
        })
        .expect("interval commit thread");
}

pub fn apply_live_commit(
    overlay: &WriteOverlay,
    archive: &Path,
    reopen_and_reset: bool,
    opts: &OpenOptions,
) -> Result<bool, String> {
    if reopen_and_reset {
        // Unused by spawn_interval_commits (IntervalIdle) and on-exit (OnExit).
        // persist-all + reopen is neither idle-only nor persist-only, so it is
        // not a CommitKind. Direct `commit_live` is not coalesced (NFS tests).
        overlay
            .commit_live(archive, |p| {
                if let Some(window) = overlay.last_patch_window() {
                    patch_sidecar_if_present(p, &window, opts)?;
                }
                reopen_live_archive(p, opts).map_err(ratarmount_compositing::OverlayError::Msg)
            })
            .map_err(|e| e.to_string())
    } else {
        let did = match overlay.enqueue_commit(archive, CommitKind::OnExit, |_| {
            Err(OverlayError::Msg("on-exit persist does not reopen".into()))
        }) {
            Ok(CommitOutcome::DidWork) => true,
            Ok(_) => false,
            Err(e) => return Err(e.to_string()),
        };
        if did && !overlay.has_after_persist() {
            if let Some(window) = overlay.last_patch_window() {
                patch_sidecar_if_present(archive, &window, opts).map_err(|e| e.to_string())?;
            }
        }
        Ok(did)
    }
}

fn reopen_live_archive(archive: &Path, opts: &OpenOptions) -> Result<Arc<dyn MountSource>, String> {
    let mut o = opts.clone();
    let sidecar = sidecar_path_for_patch(archive, &o);
    // Stop forcing in-memory rebuild when a patched sibling exists (K3).
    if sidecar.is_none() {
        log::info!("incremental reindex skipped (no sidecar); rebuilding");
        o.index_in_memory = true;
    }
    match detect_compression(archive) {
        Ok(CompressionFormat::None) => {
            if let Some(idx) = sidecar.as_ref() {
                let mut materialised = None;
                match SqliteIndexedTar::open_with_existing_index(
                    archive,
                    archive,
                    idx,
                    o.clone(),
                    &mut materialised,
                ) {
                    Ok(tar) => {
                        return Ok(maybe_wrap_payload_cache(
                            Arc::new(tar) as Arc<dyn MountSource>,
                            o.index_in_memory,
                        ))
                    }
                    Err(e) => {
                        log::info!("incremental reindex skipped ({e}); rebuilding");
                        o.index_in_memory = true;
                    }
                }
            }
            let mut materialised = None;
            let tar = SqliteIndexedTar::create_index(
                archive,
                archive,
                None,
                &o,
                env!("CARGO_PKG_VERSION"),
                &mut materialised,
            )
            .map_err(|e| format!("reopen TAR after live commit: {e}"))?;
            Ok(maybe_wrap_payload_cache(
                Arc::new(tar) as Arc<dyn MountSource>,
                o.index_in_memory,
            ))
        }
        Ok(CompressionFormat::Zstd) => {
            // Fresh scan / seek table — do not go through factory::open_zstd
            // (that would import stale zstdblocks from before persist). After
            // patch, zstdblocks are new and open_with_existing_index_body may
            // import them (K6).
            let threads = o.threads_for("zstd");
            let body = open_seekable_zstd_with_threads(archive, threads)
                .map_err(|e| format!("reopen .tar.zst after live commit: {e}"))?;
            if let Some(idx) = sidecar.as_ref() {
                match SqliteIndexedTar::open_with_existing_index_body(
                    archive,
                    Arc::clone(&body),
                    idx,
                    o.clone(),
                ) {
                    Ok(tar) => {
                        return Ok(maybe_wrap_payload_cache(
                            Arc::new(tar) as Arc<dyn MountSource>,
                            o.index_in_memory,
                        ))
                    }
                    Err(e) => {
                        log::info!("incremental reindex skipped ({e}); rebuilding");
                        o.index_in_memory = true;
                    }
                }
            }
            let tar = SqliteIndexedTar::create_index_body(
                archive,
                body,
                None,
                &o,
                env!("CARGO_PKG_VERSION"),
            )
            .map_err(|e| format!("reopen .tar.zst after live commit: {e}"))?;
            Ok(maybe_wrap_payload_cache(
                Arc::new(tar) as Arc<dyn MountSource>,
                o.index_in_memory,
            ))
        }
        Ok(other) => Err(format!(
            "live overlay commit reopen supports uncompressed TAR and .tar.zst only (got {other:?})"
        )),
        Err(e) => Err(format!("reopen after live commit: detect compression: {e}")),
    }
}

/// Where create-if-missing was requested (`-w` mount vs offline `--commit-overlay`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateMissingContext {
    Mount,
    OfflineCommit,
}

/// Create a missing uncompressed `.tar` / `.tar.zst` before factory open or offline commit.
///
/// Remote URLs are never created (including `file://`). Offline `--commit-overlay` refuses
/// a missing `.tar.zst` without touching the path (K13).
pub fn maybe_create_missing_write_base(
    path: &Path,
    ctx: CreateMissingContext,
) -> Result<EmptyCreateOutcome, String> {
    if ratarmount_remote::is_remote_url(&path.to_string_lossy()) {
        return Ok(EmptyCreateOutcome::Unchanged);
    }
    if matches!(ctx, CreateMissingContext::OfflineCommit)
        && matches!(
            classify_createable_archive(path),
            Ok(Some(EmptyArchiveKind::TarZst))
        )
    {
        let missing = matches!(
            std::fs::symlink_metadata(path),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound
        );
        if missing {
            return Err(
                "offline --commit-overlay does not support .tar.zst (use --commit-overlay-on-exit / --commit-overlay-interval)"
                    .into(),
            );
        }
        return Ok(EmptyCreateOutcome::Unchanged);
    }
    maybe_create_empty_write_archive(path).map_err(|e| e.to_string())
}

/// Startup gate: durable `-w` + a single uncompressed TAR or `.tar.zst`.
pub fn validate_live_commit_args(
    write_overlay: Option<&Path>,
    inputs: &[PathBuf],
) -> Result<PathBuf, String> {
    let ov = write_overlay.ok_or_else(|| {
        "--commit-overlay-on-exit / --commit-overlay-interval require --write-overlay <folder>"
            .to_string()
    })?;
    if ov.as_os_str() == ":temp:" {
        return Err(
            "--commit-overlay-on-exit / --commit-overlay-interval cannot use --write-overlay :temp:"
                .into(),
        );
    }
    if inputs.len() != 1 {
        return Err(
            "--commit-overlay-on-exit / --commit-overlay-interval require a single uncompressed TAR or .tar.zst"
                .into(),
        );
    }
    let archive = inputs[0].clone();
    if !archive.is_file() {
        return Err(format!(
            "live overlay commit requires an uncompressed TAR or .tar.zst file (got {})",
            archive.display()
        ));
    }
    ratarmount_compositing::live_commit_is_supported(&archive).map_err(|e| e.to_string())?;
    maybe_warn_large_zstd_last_frame(&archive);
    Ok(archive)
}

/// Offline `--commit-overlay` is not on the V-4 / F-7 executor.
pub fn refuse_offline_s3_commit(archive: &Path) -> Result<(), String> {
    let s = archive.to_string_lossy();
    if s.starts_with("s3://") {
        return Err(
            "offline --commit-overlay does not support s3:// (use --commit-overlay-on-exit / --commit-overlay-interval)"
                .into(),
        );
    }
    Ok(())
}

/// Startup gate for live commit, including F-7 `s3://` spool + write probe.
pub fn prepare_live_commit_args(
    write_overlay: Option<&Path>,
    inputs: &[PathBuf],
) -> Result<LiveCommitArchive, String> {
    let ov = write_overlay.ok_or_else(|| {
        "--commit-overlay-on-exit / --commit-overlay-interval require --write-overlay <folder>"
            .to_string()
    })?;
    if ov.as_os_str() == ":temp:" {
        return Err(
            "--commit-overlay-on-exit / --commit-overlay-interval cannot use --write-overlay :temp:"
                .into(),
        );
    }
    if inputs.len() != 1 {
        return Err(
            "--commit-overlay-on-exit / --commit-overlay-interval require a single uncompressed TAR or .tar.zst"
                .into(),
        );
    }
    let s = inputs[0].to_string_lossy();
    if s.starts_with("s3://") {
        let spool = spool_s3_for_live_commit(s.as_ref())?;
        let path = validate_live_commit_args(Some(ov), std::slice::from_ref(&spool))?;
        return Ok(LiveCommitArchive {
            path,
            s3_url: Some(s.into_owned()),
        });
    }
    if ratarmount_remote::is_remote_url(s.as_ref()) {
        return Err(format!(
            "live overlay commit supports local TAR/ZST or s3:// TAR/ZST only (got {s})"
        ));
    }
    let path = validate_live_commit_args(Some(ov), inputs)?;
    Ok(LiveCommitArchive { path, s3_url: None })
}

/// Attach F-7 AfterPersist (patch sidecar + multipart PUT + pointer). Uses `Weak` so
/// the overlay does not hold a strong cycle.
pub fn attach_f7_after_persist(overlay: &Arc<WriteOverlay>, s3_url: String, mut opts: OpenOptions) {
    // Pin the sidecar the mount actually opened (G-2 user-cache), not only CLI `--index-file`.
    let need_pin = !matches!(opts.index_file_path.as_ref(), Some(p) if p.is_file());
    if need_pin {
        if let Some(p) = sidecar_path_for_patch(Path::new(&s3_url), &opts) {
            opts.index_file_path = Some(p);
        }
    }
    let weak = Arc::downgrade(overlay);
    overlay.set_after_persist(move |spool| {
        let ov = weak
            .upgrade()
            .ok_or_else(|| OverlayError::Msg("overlay dropped during F-7 PUT".into()))?;
        let window = ov
            .last_patch_window()
            .ok_or_else(|| OverlayError::Msg("missing patch window for F-7 PUT".into()))?;
        f7_patch_put(spool, &s3_url, &window, &opts)
    });
}

/// Persist post-step for IntervalIdle and OnExit: patch mount sidecar from spool,
/// PUT spool to `s3://`, then blob+pointer. Does not forget overlay or reopen.
///
/// K4 order is persist → patch → PUT object → PUT blob+pointer. The sidecar is
/// copied first; a failed object PUT restores those bytes so remount cannot skip
/// tarstats with a pre-commit catalog.
pub fn f7_patch_put(
    spool: &Path,
    s3_url: &str,
    window: &IndexPatchWindow,
    opts: &OpenOptions,
) -> std::result::Result<(), OverlayError> {
    let sidecar = f7_mount_sidecar(s3_url, opts);
    let backup = match sidecar.as_ref() {
        Some(sc) => {
            checkpoint_sqlite(sc)?;
            let bytes = std::fs::read(sc).map_err(|e| {
                OverlayError::Msg(format!("F-7 sidecar backup {}: {e}", sc.display()))
            })?;
            Some((sc.clone(), bytes))
        }
        None => None,
    };
    if let Some(sc) = sidecar.as_ref() {
        patch_sidecar_at(spool, sc, window, opts)?;
        store_content_tarstats(sc, spool)?;
    }
    match ratarmount_remote::put_s3_file(s3_url, spool, "application/octet-stream") {
        Ok(_) => {
            if let Some(sc) = sidecar.as_ref() {
                put_index_blob_and_pointer(spool, s3_url, sc)?;
            }
            Ok(())
        }
        Err(e) => {
            if let Some((path, bytes)) = backup {
                restore_sidecar_bytes(&path, &bytes)?;
            }
            Err(OverlayError::Msg(format!("F-7 PUT {s3_url}: {e}")))
        }
    }
}

fn f7_mount_sidecar(s3_url: &str, opts: &OpenOptions) -> Option<PathBuf> {
    if let Some(p) = opts.index_file_path.as_ref() {
        if p.is_file() {
            return Some(p.clone());
        }
    }
    sidecar_path_for_patch(Path::new(s3_url), opts)
}

fn store_content_tarstats(sidecar: &Path, body: &Path) -> std::result::Result<(), OverlayError> {
    let mut stats = tar_stats_from_path(body).map_err(|e| OverlayError::Msg(e.to_string()))?;
    // Remote remount checks size + edge hashes, not spool mtime.
    stats.st_mtime = 0;
    stats.st_mtime_ns = Some(0);
    let idx = SqliteIndex::open_writable(sidecar).map_err(|e| OverlayError::Msg(e.to_string()))?;
    idx.store_metadata_key_value("tarstats", &serialize_tarstats(&stats))
        .map_err(|e| OverlayError::Msg(e.to_string()))?;
    Ok(())
}

fn checkpoint_sqlite(path: &Path) -> std::result::Result<(), OverlayError> {
    // WAL rows must land in the main file before PutObject of the sqlite blob.
    let conn = rusqlite::Connection::open(path).map_err(|e| OverlayError::Msg(e.to_string()))?;
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .map_err(|e| OverlayError::Msg(e.to_string()))?;
    Ok(())
}

fn restore_sidecar_bytes(path: &Path, bytes: &[u8]) -> std::result::Result<(), OverlayError> {
    let _ = checkpoint_sqlite(path);
    let mut wal = path.as_os_str().to_os_string();
    wal.push("-wal");
    let mut shm = path.as_os_str().to_os_string();
    shm.push("-shm");
    let _ = std::fs::remove_file(PathBuf::from(wal));
    let _ = std::fs::remove_file(PathBuf::from(shm));
    std::fs::write(path, bytes)
        .map_err(|e| OverlayError::Msg(format!("F-7 restore sidecar {}: {e}", path.display())))
}

fn put_index_blob_and_pointer(
    spool: &Path,
    s3_url: &str,
    sidecar: &Path,
) -> std::result::Result<(), OverlayError> {
    checkpoint_sqlite(sidecar)?;
    let ptr = IndexPointer::for_blob(sidecar, Some(spool))
        .map_err(|e| OverlayError::Msg(format!("F-7 index pointer: {e}")))?;
    let json = format!(
        "{{\n  \"schema\": \"{}\",\n  \"index_id\": \"{}\",\n  \"etag_sha256\": \"{}\",\n  \"generated_at\": \"{}\"\n}}\n",
        ptr.schema, ptr.index_id, ptr.etag_sha256, ptr.generated_at
    );
    ratarmount_remote::publish_index_to_s3(
        s3_url,
        sidecar,
        &ratarmount_remote::S3IndexPointer {
            index_id: ptr.index_id,
            json: json.into_bytes(),
        },
    )
    .map_err(|e| OverlayError::Msg(format!("F-7 publish index: {e}")))?;
    Ok(())
}

fn spool_s3_for_live_commit(url: &str) -> Result<PathBuf, String> {
    ratarmount_remote::s3_create_and_abort_multipart_upload(url).map_err(|e| {
        format!("s3:// live overlay commit write probe failed (need non-anonymous AWS credentials): {e}")
    })?;
    let dest = f7_spool_path(url)?;
    let (tmp, _) = ratarmount_remote::fetch_s3_to_temp(url)
        .map_err(|e| format!("s3:// live overlay commit GET {url}: {e}"))?;
    std::fs::copy(tmp.path(), &dest)
        .map_err(|e| format!("s3:// live overlay commit spool {}: {e}", dest.display()))?;
    Ok(dest)
}

fn f7_spool_path(url: &str) -> Result<PathBuf, String> {
    let root = std::env::var("RATARMOUNT_COMMIT_SPOOL_DIR")
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let dir = root.join(format!("ratarmount-f7-{}", std::process::id()));
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("s3:// live overlay commit spool dir {}: {e}", dir.display()))?;
    let loc = ratarmount_remote::parse_s3_url(url).map_err(|e| e.to_string())?;
    let safe: String = loc
        .key
        .chars()
        .map(|c| match c {
            '/' | '\\' | ':' | ' ' => '_',
            c if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' => c,
            _ => '_',
        })
        .collect();
    let safe = if safe.is_empty() {
        "object".into()
    } else {
        safe
    };
    Ok(dir.join(safe))
}

/// K4: warn once at startup; never refuse on size.
fn maybe_warn_large_zstd_last_frame(archive: &Path) -> bool {
    match detect_compression(archive) {
        Ok(CompressionFormat::Zstd) => {}
        _ => return false,
    }
    let Ok(map) = scan_zstd_frames_path(archive) else {
        return false;
    };
    let last_plain = map.frames.last().map(|f| f.uncompressed_size).unwrap_or(0);
    if last_plain > LIVE_COMMIT_WARN_LAST_FRAME {
        let msg = format!(
            "live .tar.zst commit will rewrite {last_plain} uncompressed \
             (large last frame); persist still copies the compressed file"
        );
        eprintln!("warning: {msg}");
        log::warn!("{msg}");
        true
    } else {
        false
    }
}

pub fn maybe_commit_on_exit(
    overlay: Option<&WriteOverlay>,
    archive: Option<&Path>,
    enabled: bool,
    opts: &OpenOptions,
) {
    if !enabled {
        return;
    }
    let (Some(ov), Some(path)) = (overlay, archive) else {
        return;
    };
    match apply_live_commit(ov, path, false, opts) {
        Ok(true) => eprintln!("committed write overlay into {}", path.display()),
        Ok(false) => log::debug!("on-exit overlay commit: nothing to do"),
        Err(e) => {
            eprintln!("error: on-exit overlay commit failed: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
pub(crate) fn set_term_flag_for_test(v: bool) {
    GOT_TERM.store(v, Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn parse_interval_off() {
        assert_eq!(parse_interval("0").unwrap(), None);
        assert_eq!(parse_interval("0s").unwrap(), None);
        assert_eq!(parse_interval("").unwrap(), None);
    }

    #[test]
    fn parse_interval_units() {
        assert_eq!(parse_interval("2s").unwrap(), Some(Duration::from_secs(2)));
        assert_eq!(
            parse_interval("15m").unwrap(),
            Some(Duration::from_secs(900))
        );
        assert_eq!(
            parse_interval("1h").unwrap(),
            Some(Duration::from_secs(3600))
        );
        assert_eq!(parse_interval("3").unwrap(), Some(Duration::from_secs(3)));
    }

    #[test]
    fn fuse_unmount_watcher_runs_after_term_flag() {
        let dir = tempfile::tempdir().unwrap();
        let mp = dir.path().join("mnt");
        std::fs::create_dir_all(&mp).unwrap();
        set_term_flag_for_test(false);
        spawn_signal_fuse_unmount(mp);
        set_term_flag_for_test(true);
        // Watcher must observe the flag and return (unmount of a non-mount is fine).
        thread::sleep(Duration::from_millis(200));
        set_term_flag_for_test(false);
    }

    fn write_tiny_tar_zst(path: &std::path::Path) {
        let payload = b"x\n";
        let member = ratarmount_formats_tar::UstarMember {
            path: "a.txt",
            payload: ratarmount_formats_tar::UstarPayload::File { bytes: payload },
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime: 0,
        };
        let mut tar = Vec::new();
        ratarmount_formats_tar::write_ustar_members(&mut tar, &[member]).unwrap();
        ratarmount_formats_tar::write_tar_eof(&mut tar).unwrap();
        let zst = ratarmount_compress::encode_zstd_frame(&tar, 3).unwrap();
        std::fs::write(path, zst).unwrap();
    }

    fn write_split_tar_zst(path: &std::path::Path, prefix: &[u8], last: &[u8]) {
        fn member<'a>(path: &'a str, bytes: &'a [u8]) -> ratarmount_formats_tar::UstarMember<'a> {
            ratarmount_formats_tar::UstarMember {
                path,
                payload: ratarmount_formats_tar::UstarPayload::File { bytes },
                mode: 0o644,
                uid: 0,
                gid: 0,
                mtime: 0,
            }
        }
        let mut f0 = Vec::new();
        ratarmount_formats_tar::write_ustar_members(&mut f0, &[member("prefix.txt", prefix)])
            .unwrap();
        let mut f1 = Vec::new();
        ratarmount_formats_tar::write_ustar_members(&mut f1, &[member("last.txt", last)]).unwrap();
        ratarmount_formats_tar::write_tar_eof(&mut f1).unwrap();
        let mut out = Vec::new();
        out.extend(ratarmount_compress::encode_zstd_frame(&f0, 3).unwrap());
        out.extend(ratarmount_compress::encode_zstd_frame(&f1, 3).unwrap());
        std::fs::write(path, out).unwrap();
    }

    /// Regression: on-exit persist patches the sibling sidecar so remount
    /// without `-c` is warm (tarstats match; no prefix-frame decode).
    #[test]
    fn live_commit_on_exit_remount_uses_patched_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let prefix = b"keep-prefix\n";
        let last = b"last-frame\n";
        let extra = b"on-exit-new\n";
        let archive = dir.path().join("a.tar.zst");
        write_split_tar_zst(&archive, prefix, last);
        let sidecar = ratarmount_index::default_index_path(&archive);
        {
            let body = open_seekable_zstd_with_threads(&archive, 1).expect("open zstd");
            let _ = SqliteIndexedTar::create_index_body(
                &archive,
                body,
                Some(&sidecar),
                &OpenOptions::default(),
                env!("CARGO_PKG_VERSION"),
            )
            .expect("create sidecar");
        }
        let map_before = scan_zstd_frames_path(&archive).unwrap();
        let prefix_end = map_before.frames.last().unwrap().compressed_offset as usize;
        let prefix_bytes = std::fs::read(&archive).unwrap()[..prefix_end].to_vec();

        let overlay_dir = dir.path().join("ov");
        std::fs::create_dir_all(&overlay_dir).unwrap();
        let body = open_seekable_zstd_with_threads(&archive, 1).expect("open zstd");
        let base = SqliteIndexedTar::open_with_existing_index_body(
            &archive,
            body,
            &sidecar,
            OpenOptions::default(),
        )
        .expect("warm base");
        let ov = WriteOverlay::new(Arc::new(base) as Arc<dyn MountSource>, &overlay_dir).unwrap();
        std::fs::write(overlay_dir.join("new.bin"), extra).unwrap();

        let opts = OpenOptions {
            index_file_path: Some(sidecar.clone()),
            ..OpenOptions::default()
        };
        assert!(
            apply_live_commit(&ov, &archive, false, &opts).expect("on-exit persist"),
            "expected persist"
        );

        let after = std::fs::read(&archive).unwrap();
        assert_eq!(
            &after[..prefix_end],
            prefix_bytes.as_slice(),
            "prefix frames must stay byte-identical"
        );

        let idx = ratarmount_index::SqliteIndex::open_read_only(&sidecar).expect("patched sidecar");
        idx.check_tarstats_matches_archive(&archive)
            .expect("on-exit patch must bump tarstats");

        // Remount without `-c`: warm-open the patched sidecar (no create_index_body).
        let body = open_seekable_zstd_with_threads(&archive, 1).expect("fresh zstd");
        let remount = SqliteIndexedTar::open_with_existing_index_body(
            &archive,
            body,
            &sidecar,
            OpenOptions::default(),
        )
        .expect("remount without -c must use patched sidecar");
        let fi = remount.lookup("/new.bin", 0).expect("new member indexed");
        let got = remount.read(&fi, extra.len(), 0).expect("read new");
        assert_eq!(got, extra);
        let pfi = remount.lookup("/prefix.txt", 0).expect("prefix member");
        assert_eq!(
            remount.read(&pfi, prefix.len(), 0).expect("read prefix"),
            prefix
        );
    }

    /// Regression: apply_live_commit (on-exit) waits for an in-flight interval
    /// persist then commit_atomic remaining — same plan is not spliced twice.
    #[test]
    fn overlay_commit_on_exit_waits_for_interval_inflight() {
        let dir = tempfile::tempdir().unwrap();
        let extra = b"on-exit-wait\n";
        let archive = dir.path().join("a.tar.zst");
        write_tiny_tar_zst(&archive);
        let overlay_dir = dir.path().join("ov");
        std::fs::create_dir_all(&overlay_dir).unwrap();
        let body = open_seekable_zstd_with_threads(&archive, 1).expect("open zstd");
        let base = SqliteIndexedTar::create_index_body(
            &archive,
            body,
            None,
            &OpenOptions {
                index_in_memory: true,
                ..OpenOptions::default()
            },
            env!("CARGO_PKG_VERSION"),
        )
        .expect("index");
        let ov = Arc::new(
            WriteOverlay::new(Arc::new(base) as Arc<dyn MountSource>, &overlay_dir).unwrap(),
        );
        std::fs::write(overlay_dir.join("new.bin"), extra).unwrap();
        // Backdate so the interval idle filter includes the new file.
        {
            use std::os::unix::ffi::OsStrExt;
            let path = overlay_dir.join("new.bin");
            let ts = std::time::SystemTime::now()
                .checked_sub(Duration::from_secs(30))
                .unwrap();
            let d = ts.duration_since(std::time::UNIX_EPOCH).unwrap();
            let spec = libc::timespec {
                tv_sec: d.as_secs() as libc::time_t,
                tv_nsec: d.subsec_nanos() as libc::c_long,
            };
            let times = [spec, spec];
            let c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
            assert_eq!(
                unsafe {
                    libc::utimensat(
                        libc::AT_FDCWD,
                        c.as_ptr(),
                        times.as_ptr(),
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                },
                0
            );
        }
        ov.set_persist_delay_for_test(Duration::from_millis(300));

        let archive_t = archive.clone();
        let ov_t = Arc::clone(&ov);
        let interval = thread::spawn(move || {
            ov_t.enqueue_commit(
                &archive_t,
                CommitKind::IntervalIdle(Duration::from_secs(10)),
                |p| {
                    reopen_live_archive(
                        p,
                        &OpenOptions {
                            index_in_memory: true,
                            ..OpenOptions::default()
                        },
                    )
                    .map_err(OverlayError::Msg)
                },
            )
        });
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(2) {
            if ov.persist_inflight_for_test() {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert!(
            ov.persist_inflight_for_test(),
            "interval never set inflight"
        );

        let opts = OpenOptions {
            index_in_memory: true,
            ..OpenOptions::default()
        };
        let did = apply_live_commit(&ov, &archive, false, &opts).expect("on-exit");
        assert!(
            !did,
            "on-exit must not splice again after interval committed the plan"
        );
        let interval = interval.join().expect("interval thread").expect("interval");
        assert_eq!(interval, CommitOutcome::DidWork);
        assert!(!overlay_dir.join("new.bin").exists());

        let map = scan_zstd_frames_path(&archive).unwrap();
        let mut src = std::fs::File::open(&archive).unwrap();
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        ratarmount_compress::decode_zstd_frames_to(&mut src, &map, 0, tmp.as_file_mut()).unwrap();
        let listing = std::process::Command::new("tar")
            .args(["-tf"])
            .arg(tmp.path())
            .output()
            .expect("tar -tf");
        let n = String::from_utf8_lossy(&listing.stdout)
            .lines()
            .filter(|l| l.trim_end_matches('/') == "new.bin")
            .count();
        assert_eq!(n, 1, "new.bin must appear once after interval+on-exit");
    }

    #[test]
    fn live_commit_rejects_gzip_interval() {
        let dir = tempfile::tempdir().unwrap();
        let ov = dir.path().join("ov");
        std::fs::create_dir_all(&ov).unwrap();
        let gz = dir.path().join("a.tar.gz");
        std::fs::write(&gz, [0x1f, 0x8b, 0x08, 0x00]).unwrap();
        let err = validate_live_commit_args(Some(&ov), &[gz]).unwrap_err();
        assert!(err.contains("gzip"), "{err}");
        assert!(err.contains("uncompressed"), "{err}");
    }

    #[test]
    fn live_commit_accepts_tar_zst() {
        let dir = tempfile::tempdir().unwrap();
        let ov = dir.path().join("ov");
        std::fs::create_dir_all(&ov).unwrap();
        let path = dir.path().join("a.tar.zst");
        write_tiny_tar_zst(&path);
        let got = validate_live_commit_args(Some(&ov), std::slice::from_ref(&path))
            .expect("accept .tar.zst");
        assert_eq!(got, path);
    }

    #[test]
    fn live_commit_1024_one_frame_tar_zst_does_not_warn() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.tar.zst");
        let mut eof = Vec::new();
        ratarmount_formats_tar::write_tar_eof(&mut eof).unwrap();
        let zst = ratarmount_compress::encode_zstd_frame(&eof, 3).unwrap();
        std::fs::write(&path, zst).unwrap();
        assert!(!maybe_warn_large_zstd_last_frame(&path));
    }

    #[test]
    fn live_commit_last_frame_over_64mib_still_warns() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.tar.zst");
        let plain = vec![0u8; (LIVE_COMMIT_WARN_LAST_FRAME as usize) + 1];
        let zst = ratarmount_compress::encode_zstd_frame(&plain, 3).unwrap();
        std::fs::write(&path, zst).unwrap();
        assert!(maybe_warn_large_zstd_last_frame(&path));
    }

    #[test]
    fn create_missing_validate_live_commit_after_helper() {
        let dir = tempfile::tempdir().unwrap();
        let ov = dir.path().join("ov");
        std::fs::create_dir_all(&ov).unwrap();
        let tar = dir.path().join("new.tar");
        maybe_create_missing_write_base(&tar, CreateMissingContext::Mount)
            .expect("create missing .tar");
        let got = validate_live_commit_args(Some(&ov), std::slice::from_ref(&tar))
            .expect("accept created .tar");
        assert_eq!(got, tar);

        let zst = dir.path().join("new.tar.zst");
        maybe_create_missing_write_base(&zst, CreateMissingContext::Mount)
            .expect("create missing .tar.zst");
        let got = validate_live_commit_args(Some(&ov), std::slice::from_ref(&zst))
            .expect("accept created .tar.zst");
        assert_eq!(got, zst);
    }

    #[test]
    fn create_missing_remote_url_never_creates() {
        let url = PathBuf::from("https://example.com/a.tar");
        let got = maybe_create_missing_write_base(&url, CreateMissingContext::Mount)
            .expect("remote skip");
        assert_eq!(got, EmptyCreateOutcome::Unchanged);
        let offline = maybe_create_missing_write_base(&url, CreateMissingContext::OfflineCommit)
            .expect("offline remote skip");
        assert_eq!(offline, EmptyCreateOutcome::Unchanged);
        // Without the remote skip, classify would see basename `a.tar` and try the
        // parent `https://example.com` → "parent directory does not exist".
        assert!(!url.exists());

        // Regression: docker://ubuntu:24.04 is not a local path (WHATWG-invalid).
        let docker = PathBuf::from("docker://ubuntu:24.04");
        let got = maybe_create_missing_write_base(&docker, CreateMissingContext::Mount)
            .expect("docker skip");
        assert_eq!(got, EmptyCreateOutcome::Unchanged);
        assert!(!docker.exists());
    }

    #[test]
    fn create_missing_offline_tar_zst_does_not_create() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("new.tar.zst");
        let err = maybe_create_missing_write_base(&path, CreateMissingContext::OfflineCommit)
            .expect_err("K13");
        assert!(err.contains("on-exit") || err.contains("interval"), "{err}");
        assert!(err.contains(".tar.zst"), "{err}");
        assert!(!path.exists());
    }

    #[test]
    fn create_missing_offline_existing_tar_zst_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.tar.zst");
        std::fs::write(&path, b"keep").unwrap();
        let got = maybe_create_missing_write_base(&path, CreateMissingContext::OfflineCommit)
            .expect("existing zstd");
        assert_eq!(got, EmptyCreateOutcome::Unchanged);
        assert_eq!(std::fs::read(&path).unwrap(), b"keep");
    }

    #[test]
    fn commit_overlay_refuses_s3() {
        let err = refuse_offline_s3_commit(Path::new("s3://bucket/a.tar")).unwrap_err();
        assert!(err.contains("s3://"), "{err}");
        assert!(err.contains("offline") || err.contains("on-exit"), "{err}");
    }

    #[test]
    fn f7_anonymous_exits_2() {
        let _g = EnvGuard::acquire(AWS_ENV_KEYS);
        _g.set("RATARMOUNT_S3_ANONYMOUS", "1");
        _g.set("RATARMOUNT_IMDS_BASE", "http://127.0.0.1:1");
        let dir = tempfile::tempdir().unwrap();
        let ov = dir.path().join("ov");
        std::fs::create_dir_all(&ov).unwrap();
        let err = prepare_live_commit_args(Some(&ov), &[PathBuf::from("s3://bucket/a.tar.zst")])
            .unwrap_err();
        assert!(
            err.contains("anonymous") || err.contains("GET-only") || err.contains("non-anonymous"),
            "{err}"
        );
    }

    #[test]
    fn f7_requires_write_creds() {
        let _g = EnvGuard::acquire(AWS_ENV_KEYS);
        _g.set("RATARMOUNT_IMDS_BASE", "http://127.0.0.1:1");
        let dir = tempfile::tempdir().unwrap();
        let ov = dir.path().join("ov");
        std::fs::create_dir_all(&ov).unwrap();
        let err = prepare_live_commit_args(Some(&ov), &[PathBuf::from("s3://bucket/a.tar.zst")])
            .unwrap_err();
        assert!(
            err.contains("credentials")
                || err.contains("AWS_ACCESS_KEY")
                || err.contains("write probe"),
            "{err}"
        );
    }

    #[test]
    fn live_commit_rejects_gzip_s3() {
        let mock = MockS3Rw::spawn(Vec::new(), false);
        mock.objects
            .lock()
            .unwrap()
            .insert("a.tar.gz".into(), b"\x1f\x8b\x08\x00gzip-not-tar".to_vec());
        let dir = tempfile::tempdir().unwrap();
        let _g = env_signed_s3(&mock.base_url, dir.path());
        let ov = dir.path().join("ov");
        std::fs::create_dir_all(&ov).unwrap();
        let err = prepare_live_commit_args(Some(&ov), &[PathBuf::from("s3://bucket/a.tar.gz")])
            .unwrap_err();
        assert!(
            err.contains("gzip") || err.contains("uncompressed"),
            "{err}"
        );
    }

    #[test]
    fn f7_reopen_ignores_spool_uses_ranges() {
        let extra = b"f7-range-new\n";
        let h = f7_ready_overlay(extra);
        assert!(h
            .ov
            .commit_live(&h.spool, |_| {
                factory::open_live_remote(&h.url, &h.opts).map_err(OverlayError::Msg)
            })
            .expect("commit"));
        std::fs::remove_file(&h.spool).expect("delete spool");
        let fi = h.ov.lookup("/new.bin", 0).expect("new member after reopen");
        let got =
            h.ov.read(&fi, extra.len(), 0)
                .expect("cat after spool delete");
        assert_eq!(got, extra);
        assert!(
            h.mock.range_headers.load(Ordering::SeqCst) >= 1,
            "reopen must Range-GET, not File::open(spool); log={:?}",
            h.mock.log.lock().unwrap()
        );
    }

    #[test]
    fn f7_pointer_blob_has_new_member() {
        let extra = b"f7-blob-member\n";
        let h = f7_ready_overlay(extra);
        assert!(h
            .ov
            .commit_live(&h.spool, |_| {
                factory::open_live_remote(&h.url, &h.opts).map_err(OverlayError::Msg)
            })
            .expect("commit"));
        let objects = h.mock.objects.lock().unwrap();
        let blob_key = objects
            .keys()
            .find(|k| k.contains(".index.") && k.ends_with(".sqlite"))
            .cloned()
            .expect("blob PUT");
        let blob = objects.get(&blob_key).cloned().expect("blob body");
        drop(objects);
        let blob_path = h.dir.path().join("blob.sqlite");
        std::fs::write(&blob_path, &blob).unwrap();
        let idx = SqliteIndex::open_read_only(&blob_path).expect("open blob");
        let fi = idx
            .lookup("/new.bin", 0)
            .expect("lookup")
            .expect("appended name in patched blob");
        assert_eq!(fi.size, extra.len() as u64);
    }

    #[test]
    fn overlay_commit_put_fail_keeps_overlay() {
        let extra = b"f7-keep-overlay\n";
        let mock = MockS3Rw::spawn(Vec::new(), true);
        let dir = tempfile::tempdir().unwrap();
        let zst = f7_seed_zst();
        mock.objects.lock().unwrap().insert("a.tar.zst".into(), zst);
        let _g = env_signed_s3(&mock.base_url, dir.path());
        let ov_dir = dir.path().join("ov");
        std::fs::create_dir_all(&ov_dir).unwrap();
        let live =
            prepare_live_commit_args(Some(&ov_dir), &[PathBuf::from("s3://bucket/a.tar.zst")])
                .expect("prepare");
        let sidecar = dir.path().join("mount.index.sqlite");
        {
            let body = open_seekable_zstd_with_threads(&live.path, 1).unwrap();
            let _ = SqliteIndexedTar::create_index_body(
                &live.path,
                body,
                Some(&sidecar),
                &OpenOptions::default(),
                env!("CARGO_PKG_VERSION"),
            )
            .unwrap();
        }
        let opts = OpenOptions {
            index_file_path: Some(sidecar),
            ..OpenOptions::default()
        };
        let body = open_seekable_zstd_with_threads(&live.path, 1).unwrap();
        let base = SqliteIndexedTar::open_with_existing_index_body(
            &live.path,
            body,
            opts.index_file_path.as_ref().unwrap(),
            opts.clone(),
        )
        .unwrap();
        let ov =
            Arc::new(WriteOverlay::new(Arc::new(base) as Arc<dyn MountSource>, &ov_dir).unwrap());
        std::fs::write(ov_dir.join("new.bin"), extra).unwrap();
        attach_f7_after_persist(&ov, live.s3_url.clone().unwrap(), opts.clone());
        let err = ov
            .commit_live(&live.path, |_| panic!("reopen must not run when PUT fails"))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("PUT") || err.contains("after-persist") || err.contains("500"),
            "{err}"
        );
        assert!(
            ov_dir.join("new.bin").exists(),
            "PUT failure must keep overlay"
        );
        assert!(ov.interval_disabled());
        let sidecar = opts.index_file_path.as_ref().unwrap();
        let idx = SqliteIndex::open_read_only(sidecar).expect("restored sidecar");
        assert!(
            idx.lookup("/new.bin", 0).expect("lookup").is_none(),
            "PUT failure must restore pre-commit sidecar (no ghost member)"
        );
        let src = factory::open_live_remote(live.s3_url.as_ref().unwrap(), &opts)
            .expect("reopen after PUT fail");
        assert!(
            src.lookup("/new.bin", 0).is_none(),
            "remount with same --index-file must not skip tarstats into a pre-commit catalog"
        );
        assert!(src.lookup("/old.txt", 0).is_some());
    }

    #[test]
    fn overlay_commit_live_s3_patched_sidecar_no_rebuild() {
        let extra = b"f7-patched-member\n";
        let h = f7_ready_overlay(extra);
        assert!(h
            .ov
            .commit_live(&h.spool, |_| {
                factory::open_live_remote(&h.url, &h.opts).map_err(OverlayError::Msg)
            })
            .expect("commit"));
        let sidecar = h.opts.index_file_path.as_ref().unwrap();
        let idx = SqliteIndex::open_read_only(sidecar).expect("patched sidecar");
        let fi = idx
            .lookup("/new.bin", 0)
            .expect("lookup")
            .expect("patched sidecar lists appended member without full rebuild");
        assert_eq!(fi.size, extra.len() as u64);
        let old = idx
            .lookup("/old.txt", 0)
            .expect("lookup old")
            .expect("prefix member kept without full rebuild");
        assert_eq!(old.size, 5);
    }

    /// Regression: default G-2 sidecar (no `--index-file`) still PUTs blob+pointer.
    #[test]
    fn f7_default_g2_sidecar_publishes_pointer() {
        let extra = b"f7-g2-default\n";
        let mock = MockS3Rw::spawn(Vec::new(), false);
        let dir = tempfile::tempdir().unwrap();
        mock.objects
            .lock()
            .unwrap()
            .insert("a.tar.zst".into(), f7_seed_zst());
        let env = env_signed_s3(&mock.base_url, dir.path());
        let ov_dir = dir.path().join("ov");
        std::fs::create_dir_all(&ov_dir).unwrap();
        let cache = dir.path().join("g2-cache");
        std::fs::create_dir_all(&cache).unwrap();
        let live =
            prepare_live_commit_args(Some(&ov_dir), &[PathBuf::from("s3://bucket/a.tar.zst")])
                .expect("prepare");
        let url = "s3://bucket/a.tar.zst";
        let opts_g2 = OpenOptions {
            index_file_path: None,
            index_folders: vec![cache.clone()],
            ..OpenOptions::default()
        };
        let sidecar = sidecar_path_for_patch(Path::new(url), &opts_g2)
            .or_else(|| {
                match ratarmount_index::resolve_index_location(
                    Path::new(url),
                    None,
                    &opts_g2.index_folders,
                    false,
                ) {
                    ratarmount_index::IndexLocation::Path(p) => Some(p),
                    _ => None,
                }
            })
            .expect("G-2 dest");
        if let Some(parent) = sidecar.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        {
            let body = open_seekable_zstd_with_threads(&live.path, 1).unwrap();
            let _ = SqliteIndexedTar::create_index_body(
                &live.path,
                body,
                Some(&sidecar),
                &opts_g2,
                env!("CARGO_PKG_VERSION"),
            )
            .unwrap();
        }
        assert!(
            sidecar.is_file(),
            "G-2 sidecar must exist at {}",
            sidecar.display()
        );
        let body = open_seekable_zstd_with_threads(&live.path, 1).unwrap();
        let base = SqliteIndexedTar::open_with_existing_index_body(
            &live.path,
            body,
            &sidecar,
            opts_g2.clone(),
        )
        .unwrap();
        let ov =
            Arc::new(WriteOverlay::new(Arc::new(base) as Arc<dyn MountSource>, &ov_dir).unwrap());
        std::fs::write(ov_dir.join("new.bin"), extra).unwrap();
        attach_f7_after_persist(&ov, url.to_string(), opts_g2);
        assert!(ov
            .commit_live(&live.path, |_| {
                factory::open_live_remote(url, &OpenOptions::default()).map_err(OverlayError::Msg)
            })
            .expect("commit"));
        let objects = mock.objects.lock().unwrap();
        assert!(
            objects.keys().any(|k| k.ends_with(".index.ptr")),
            "default G-2 must PUT pointer; keys={:?}",
            objects.keys().collect::<Vec<_>>()
        );
        let blob_key = objects
            .keys()
            .find(|k| k.contains(".index.") && k.ends_with(".sqlite"))
            .cloned()
            .expect("blob PUT without --index-file");
        let blob = objects.get(&blob_key).cloned().unwrap();
        drop(objects);
        let blob_path = dir.path().join("g2-blob.sqlite");
        std::fs::write(&blob_path, blob).unwrap();
        let idx = SqliteIndex::open_read_only(&blob_path).unwrap();
        assert!(idx.lookup("/new.bin", 0).unwrap().is_some());
        let _ = env;
    }

    /// Regression: on-exit F-7 must not re-patch spool mtime after f7_patch_put.
    #[test]
    fn f7_on_exit_blob_matches_sidecar_mtime_zero() {
        let extra = b"f7-on-exit\n";
        let h = f7_ready_overlay(extra);
        assert!(
            apply_live_commit(&h.ov, &h.spool, false, &h.opts).expect("on-exit"),
            "expected persist"
        );
        let sidecar = h.opts.index_file_path.as_ref().unwrap();
        let stats = SqliteIndex::open_read_only(sidecar)
            .unwrap()
            .tarstats()
            .unwrap()
            .expect("tarstats");
        assert_eq!(stats.st_mtime, 0, "on-exit must keep content tarstats");
        assert_eq!(stats.st_mtime_ns, Some(0));
        let objects = h.mock.objects.lock().unwrap();
        let blob_key = objects
            .keys()
            .find(|k| k.contains(".index.") && k.ends_with(".sqlite"))
            .cloned()
            .expect("blob PUT");
        let blob = objects.get(&blob_key).cloned().unwrap();
        drop(objects);
        let sidecar_id = IndexPointer::for_blob(sidecar, None).unwrap().index_id;
        let blob_path = h.dir.path().join("on-exit-blob.sqlite");
        std::fs::write(&blob_path, &blob).unwrap();
        let blob_id = IndexPointer::for_blob(&blob_path, None).unwrap().index_id;
        assert_eq!(
            sidecar_id, blob_id,
            "on-exit must not rewrite sidecar after pointer PUT"
        );
    }

    fn f7_seed_zst() -> Vec<u8> {
        let payload = b"seed\n";
        let member = ratarmount_formats_tar::UstarMember {
            path: "old.txt",
            payload: ratarmount_formats_tar::UstarPayload::File { bytes: payload },
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime: 0,
        };
        let mut tar = Vec::new();
        ratarmount_formats_tar::write_ustar_members(&mut tar, &[member]).unwrap();
        ratarmount_formats_tar::write_tar_eof(&mut tar).unwrap();
        ratarmount_compress::encode_zstd_frame(&tar, 3).unwrap()
    }

    struct F7Harness {
        mock: MockS3Rw,
        spool: PathBuf,
        ov: Arc<WriteOverlay>,
        opts: OpenOptions,
        url: String,
        dir: tempfile::TempDir,
        _env: EnvGuard,
    }

    fn f7_ready_overlay(extra: &[u8]) -> F7Harness {
        let mock = MockS3Rw::spawn(Vec::new(), false);
        let dir = tempfile::tempdir().unwrap();
        let zst = f7_seed_zst();
        mock.objects.lock().unwrap().insert("a.tar.zst".into(), zst);
        let env = env_signed_s3(&mock.base_url, dir.path());
        let ov_dir = dir.path().join("ov");
        std::fs::create_dir_all(&ov_dir).unwrap();
        let live =
            prepare_live_commit_args(Some(&ov_dir), &[PathBuf::from("s3://bucket/a.tar.zst")])
                .expect("prepare");
        let sidecar = dir.path().join("mount.index.sqlite");
        {
            let body = open_seekable_zstd_with_threads(&live.path, 1).unwrap();
            let _ = SqliteIndexedTar::create_index_body(
                &live.path,
                body,
                Some(&sidecar),
                &OpenOptions::default(),
                env!("CARGO_PKG_VERSION"),
            )
            .unwrap();
        }
        let opts = OpenOptions {
            index_file_path: Some(sidecar),
            ..OpenOptions::default()
        };
        let body = open_seekable_zstd_with_threads(&live.path, 1).unwrap();
        let base = SqliteIndexedTar::open_with_existing_index_body(
            &live.path,
            body,
            opts.index_file_path.as_ref().unwrap(),
            opts.clone(),
        )
        .unwrap();
        let ov =
            Arc::new(WriteOverlay::new(Arc::new(base) as Arc<dyn MountSource>, &ov_dir).unwrap());
        std::fs::write(ov_dir.join("new.bin"), extra).unwrap();
        let url = live.s3_url.clone().unwrap();
        attach_f7_after_persist(&ov, url.clone(), opts.clone());
        F7Harness {
            mock,
            spool: live.path,
            ov,
            opts,
            url,
            dir,
            _env: env,
        }
    }

    const AWS_ENV_KEYS: &[&str] = &[
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
        "AWS_CONTAINER_AUTHORIZATION_TOKEN",
        "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
        "RATARMOUNT_IMDS_BASE",
        "AWS_EC2_METADATA_SERVICE_ENDPOINT",
        "RATARMOUNT_COMMIT_SPOOL_DIR",
    ];

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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

    fn env_signed_s3(endpoint: &str, spool: &Path) -> EnvGuard {
        let g = EnvGuard::acquire(AWS_ENV_KEYS);
        g.set("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE");
        g.set("AWS_SECRET_ACCESS_KEY", "secretsecretsecretsecretsecr");
        g.set("AWS_ENDPOINT_URL", endpoint);
        g.set("AWS_REGION", "us-east-1");
        g.set("RATARMOUNT_IMDS_BASE", "http://127.0.0.1:1");
        g.set("RATARMOUNT_COMMIT_SPOOL_DIR", &spool.to_string_lossy());
        g
    }

    struct MockS3Rw {
        base_url: String,
        log: Arc<std::sync::Mutex<Vec<String>>>,
        objects: Arc<std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>>,
        range_headers: Arc<std::sync::atomic::AtomicUsize>,
        _join: Option<std::thread::JoinHandle<()>>,
    }

    impl MockS3Rw {
        fn spawn(initial: Vec<u8>, fail_put: bool) -> Self {
            use std::io::{BufRead, BufReader, Read, Write};
            use std::net::TcpListener;
            use std::sync::atomic::AtomicUsize;

            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let local = listener.local_addr().unwrap();
            let base_url = format!("http://{local}");
            let log = Arc::new(std::sync::Mutex::new(Vec::new()));
            let objects = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
            if !initial.is_empty() {
                objects.lock().unwrap().insert("a.tar.zst".into(), initial);
            }
            let range_headers = Arc::new(AtomicUsize::new(0));
            let log_c = Arc::clone(&log);
            let objects_c = Arc::clone(&objects);
            let range_c = Arc::clone(&range_headers);
            let next_upload = Arc::new(AtomicUsize::new(1));
            type PartsMap = std::collections::HashMap<(String, u32), Vec<u8>>;
            let parts: Arc<std::sync::Mutex<PartsMap>> =
                Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
            let parts_c = Arc::clone(&parts);
            let join = std::thread::spawn(move || {
                for stream in listener.incoming().take(256) {
                    let Ok(mut stream) = stream else { continue };
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut request_line = String::new();
                    if reader.read_line(&mut request_line).is_err() {
                        continue;
                    }
                    let mut has_auth = false;
                    let mut range_hdr: Option<String> = None;
                    let mut content_length = 0usize;
                    loop {
                        let mut line = String::new();
                        if reader.read_line(&mut line).is_err() {
                            break;
                        }
                        if line == "\r\n" || line == "\n" || line.is_empty() {
                            break;
                        }
                        let lower = line.to_ascii_lowercase();
                        if lower.starts_with("authorization:") {
                            has_auth = true;
                        }
                        if let Some(rest) = lower.strip_prefix("content-length:") {
                            content_length = rest.trim().parse().unwrap_or(0);
                        }
                        if let Some((_, v)) = line.split_once(':') {
                            if lower.starts_with("range:") {
                                range_hdr = Some(v.trim().to_string());
                            }
                        }
                    }
                    let method = request_line.split_whitespace().next().unwrap_or("");
                    let target = request_line.split_whitespace().nth(1).unwrap_or("");
                    let (path, query) = match target.split_once('?') {
                        Some((p, q)) => (p, q),
                        None => (target, ""),
                    };
                    let key = path
                        .trim_start_matches('/')
                        .split_once('/')
                        .map(|(_, k)| k.to_string())
                        .unwrap_or_default();
                    {
                        let mut lg = log_c.lock().unwrap();
                        lg.push(format!("{method} {key}"));
                    }
                    if range_hdr.is_some() {
                        range_c.fetch_add(1, Ordering::SeqCst);
                    }
                    let mut body = vec![0u8; content_length.min(64 * 1024 * 1024)];
                    if !body.is_empty() && reader.read_exact(&mut body).is_err() {
                        continue;
                    }
                    if !has_auth {
                        let msg = b"AccessDenied";
                        let _ = write!(
                            stream,
                            "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            msg.len()
                        );
                        let _ = stream.write_all(msg);
                        continue;
                    }
                    if method == "GET" {
                        let held = objects_c.lock().unwrap();
                        let Some(obj) = held.get(&key).cloned() else {
                            drop(held);
                            let msg = b"NoSuchKey";
                            let _ = write!(
                                stream,
                                "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                msg.len()
                            );
                            let _ = stream.write_all(msg);
                            continue;
                        };
                        drop(held);
                        if let Some(ref r) = range_hdr {
                            if let Some((start, end)) = parse_bytes_range(r, obj.len()) {
                                let end = end.min(obj.len().saturating_sub(1));
                                if start <= end && start < obj.len() {
                                    let slice = &obj[start..=end];
                                    let cr = format!("bytes {start}-{end}/{}", obj.len());
                                    let _ = write!(
                                        stream,
                                        "HTTP/1.1 206 Partial Content\r\nContent-Range: {cr}\r\nContent-Length: {}\r\nAccept-Ranges: bytes\r\nConnection: close\r\n\r\n",
                                        slice.len()
                                    );
                                    let _ = stream.write_all(slice);
                                    continue;
                                }
                            }
                        }
                        let _ = write!(
                            stream,
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nAccept-Ranges: bytes\r\nConnection: close\r\n\r\n",
                            obj.len()
                        );
                        let _ = stream.write_all(&obj);
                        continue;
                    }
                    let params = parse_query(query);
                    if method == "POST" && params.iter().any(|(k, _)| k == "uploads") {
                        let n = next_upload.fetch_add(1, Ordering::SeqCst);
                        let upload_id = format!("mpu-test-{n}");
                        let xml = format!(
                            "<InitiateMultipartUploadResult><Bucket>bucket</Bucket>\
                             <Key>{key}</Key><UploadId>{upload_id}</UploadId></InitiateMultipartUploadResult>"
                        );
                        let _ = write!(
                            stream,
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{xml}",
                            xml.len()
                        );
                        continue;
                    }
                    if method == "DELETE" && params.iter().any(|(k, _)| k == "uploadId") {
                        let _ = write!(
                            stream,
                            "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        );
                        continue;
                    }
                    if method == "PUT" {
                        if fail_put && params.iter().all(|(k, _)| k != "partNumber") {
                            let msg = b"InternalError";
                            let _ = write!(
                                stream,
                                "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                msg.len()
                            );
                            let _ = stream.write_all(msg);
                            continue;
                        }
                        if let Some(part) = params
                            .iter()
                            .find(|(k, _)| k == "partNumber")
                            .and_then(|(_, v)| v.parse::<u32>().ok())
                        {
                            let upload_id = params
                                .iter()
                                .find(|(k, _)| k == "uploadId")
                                .map(|(_, v)| v.as_str())
                                .unwrap_or("");
                            parts_c
                                .lock()
                                .unwrap()
                                .insert((upload_id.to_string(), part), body);
                            let _ = write!(
                                stream,
                                "HTTP/1.1 200 OK\r\nETag: \"part-{part}\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            );
                            continue;
                        }
                        objects_c.lock().unwrap().insert(key, body);
                        let _ = write!(
                            stream,
                            "HTTP/1.1 200 OK\r\nETag: \"put\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        );
                        continue;
                    }
                    if method == "POST" {
                        if let Some(upload_id) = params
                            .iter()
                            .find(|(k, _)| k == "uploadId")
                            .map(|(_, v)| v.clone())
                        {
                            let mut held = parts_c.lock().unwrap();
                            let mut nums: Vec<u32> = held
                                .keys()
                                .filter(|(id, _)| id == &upload_id)
                                .map(|(_, n)| *n)
                                .collect();
                            nums.sort_unstable();
                            let mut assembled = Vec::new();
                            for n in nums {
                                if let Some(p) = held.remove(&(upload_id.clone(), n)) {
                                    assembled.extend_from_slice(&p);
                                }
                            }
                            drop(held);
                            objects_c.lock().unwrap().insert(key, assembled);
                            let xml = "<CompleteMultipartUploadResult><ETag>\"mpu\"</ETag></CompleteMultipartUploadResult>";
                            let _ = write!(
                                stream,
                                "HTTP/1.1 200 OK\r\nETag: \"mpu\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{xml}",
                                xml.len()
                            );
                            continue;
                        }
                    }
                    let msg = b"UnexpectedRequest";
                    let _ = write!(
                        stream,
                        "HTTP/1.1 400 Bad Request\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        msg.len()
                    );
                    let _ = stream.write_all(msg);
                }
            });
            Self {
                base_url,
                log,
                objects,
                range_headers,
                _join: Some(join),
            }
        }
    }

    fn parse_bytes_range(header: &str, total: usize) -> Option<(usize, usize)> {
        let rest = header.trim().strip_prefix("bytes=")?;
        let (a, b) = rest.split_once('-')?;
        let start: usize = a.parse().ok()?;
        if b.is_empty() {
            if total == 0 {
                return None;
            }
            return Some((start, total - 1));
        }
        let end: usize = b.parse().ok()?;
        Some((start, end))
    }

    fn parse_query(q: &str) -> Vec<(String, String)> {
        if q.is_empty() {
            return Vec::new();
        }
        q.split('&')
            .filter(|p| !p.is_empty())
            .map(|p| match p.split_once('=') {
                Some((k, v)) => (k.to_string(), v.to_string()),
                None => (p.to_string(), String::new()),
            })
            .collect()
    }
}
