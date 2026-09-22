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
    classify_createable_archive, maybe_create_empty_write_archive, patch_sidecar_if_present,
    sidecar_path_for_patch, CommitKind, CommitOutcome, EmptyArchiveKind, EmptyCreateOutcome,
    OverlayError, RemoteDownload, RemoteObjectHead, RemotePublishError, RemotePublishRequest,
    WriteOverlay,
};
use ratarmount_compress::{
    detect_compression, open_seekable_zstd_with_threads, scan_zstd_frames_path, CompressionFormat,
};
use ratarmount_core::{MountSource, OpenOptions};
use ratarmount_formats_tar::SqliteIndexedTar;
use ratarmount_index::{index_pointer_to_json, IndexPointer, SqliteIndex, META_SIDECAR_WHOLE_MAX};
use ratarmount_nfs::NfsStop;

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

pub fn spawn_interval_commits(
    overlay: Arc<WriteOverlay>,
    archive: PathBuf,
    interval: Duration,
    stop: Option<NfsStop>,
    opts: OpenOptions,
) {
    // Poll at least once a second so a file enters the archive ~`interval`
    // after its last host mtime, not up to 2× interval later. The settle
    // threshold is still `interval` (only idle files are persisted).
    let poll = Duration::from_secs(1).min(interval);
    let remote_kind = live_remote_kind(&archive.to_string_lossy());
    let remote_url = archive.to_string_lossy().into_owned();
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
            match overlay.enqueue_commit(&archive, CommitKind::IntervalIdle(interval), |p| {
                match remote_kind {
                    // Reopen is the URL only. Patch ran inside publish.
                    LiveRemote::S3 => reopen_s3_mount(&remote_url, &opts),
                    LiveRemote::Gcs => reopen_gcs_mount(&remote_url, &opts),
                    LiveRemote::Azure => reopen_azure_mount(&remote_url, &opts),
                    LiveRemote::Local => {
                        if let Some(window) = ov.last_patch_window() {
                            patch_sidecar_if_present(p, &window, &opts)?;
                        }
                        reopen_live_archive(p, &opts).map_err(OverlayError::Msg)
                    }
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
        if did && !remote_publish_patches_sidecar(live_remote_kind(&archive.to_string_lossy())) {
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
                    Ok(tar) => return Ok(Arc::new(tar) as Arc<dyn MountSource>),
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
            Ok(Arc::new(tar) as Arc<dyn MountSource>)
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
                    Ok(tar) => return Ok(Arc::new(tar) as Arc<dyn MountSource>),
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
            Ok(Arc::new(tar) as Arc<dyn MountSource>)
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
    let shown = archive.to_string_lossy();
    if matches!(
        live_remote_kind(&shown),
        LiveRemote::S3 | LiveRemote::Gcs | LiveRemote::Azure
    ) {
        if !live_commit_archive_name(&shown) {
            return Err(format!(
                "live overlay commit requires an uncompressed TAR or .tar.zst file (got {})",
                archive.display()
            ));
        }
        // Do not create the key and do not stat it as a local file.
        return Ok(archive);
    }
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

/// Offline `--commit-overlay` on an object-store URL. Not a live-queue job.
pub fn offline_remote_commit_error(archive: &Path) -> Option<&'static str> {
    let s = archive.to_string_lossy();
    if ratarmount_remote::is_object_store_archive_url(&s) {
        Some(
            "offline --commit-overlay does not upload; use --commit-overlay-on-exit or --commit-overlay-interval",
        )
    } else {
        None
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LiveRemote {
    Local,
    S3,
    Gcs,
    Azure,
}

fn live_remote_kind(url: &str) -> LiveRemote {
    if url.starts_with("s3://") {
        LiveRemote::S3
    } else if url.starts_with("gs://") {
        LiveRemote::Gcs
    } else if url.starts_with("az://") || url.starts_with("azure://") {
        LiveRemote::Azure
    } else {
        LiveRemote::Local
    }
}

fn remote_publish_patches_sidecar(kind: LiveRemote) -> bool {
    matches!(kind, LiveRemote::S3 | LiveRemote::Gcs | LiveRemote::Azure)
}

fn live_commit_archive_name(url: &str) -> bool {
    let lower = url.trim().to_ascii_lowercase();
    lower.ends_with(".tar")
        || lower.ends_with(".tar.zst")
        || lower.ends_with(".tzst")
        || lower.ends_with(".tar.zstd")
}

/// Wire one `s3://` archive into the live queue. `-w` is not decided here.
pub fn install_s3_live_commit(overlay: &WriteOverlay, archive: &Path, opts: &OpenOptions) {
    let url_head = archive.to_string_lossy().into_owned();
    let url_dl = url_head.clone();
    let url_pub = url_head.clone();
    let url_label = url_pub.clone();
    let opts_pub = opts.clone();
    overlay.install_remote_live_commit_for(
        &url_label,
        Box::new(move || {
            let head = ratarmount_remote::head_s3_object(&url_head)
                .map_err(|e| OverlayError::Msg(e.to_string()))?;
            Ok(RemoteObjectHead {
                etag: head.etag,
                len: head.len,
            })
        }),
        Box::new(move || {
            let loc = ratarmount_remote::parse_s3_url(&url_dl)
                .map_err(|e| OverlayError::Msg(e.to_string()))?;
            let (file, len) = ratarmount_remote::fetch_s3_location_to_temp_prefer_range(&loc, None)
                .map_err(|e| OverlayError::Msg(e.to_string()))?;
            Ok(RemoteDownload { file, len })
        }),
        Box::new(move |req| publish_s3(&url_pub, &opts_pub, req)),
        ratarmount_remote::OBJECT_STORE_IO_TIMEOUT,
    );
}

/// Wire one object-store archive into the live queue. Local paths are unchanged.
/// The `gs://` arm calls [`publish_gcs`]. The `az://` arm calls [`publish_azure`].
/// `-w` is not decided here.
pub fn install_object_store_live_commit(
    overlay: &WriteOverlay,
    archive: &Path,
    opts: &OpenOptions,
) {
    let url = archive.to_string_lossy().into_owned();
    match live_remote_kind(&url) {
        LiveRemote::Local => {}
        LiveRemote::S3 => install_s3_live_commit(overlay, archive, opts),
        LiveRemote::Gcs => {
            let url_head = url.clone();
            let url_dl = url.clone();
            let url_pub = url;
            let url_label = url_pub.clone();
            let opts_pub = opts.clone();
            overlay.install_remote_live_commit_for(
                &url_label,
                Box::new(move || {
                    let head = ratarmount_remote::head_gcs_object(&url_head)
                        .map_err(|e| OverlayError::Msg(e.to_string()))?;
                    Ok(RemoteObjectHead {
                        etag: head.etag,
                        len: head.len,
                    })
                }),
                Box::new(move || {
                    let loc = ratarmount_remote::parse_gcs_url(&url_dl)
                        .map_err(|e| OverlayError::Msg(e.to_string()))?;
                    let (file, len) =
                        ratarmount_remote::fetch_gcs_location_to_temp_prefer_range(&loc, None)
                            .map_err(|e| OverlayError::Msg(e.to_string()))?;
                    Ok(RemoteDownload { file, len })
                }),
                Box::new(move |req| publish_gcs(&url_pub, &opts_pub, req)),
                ratarmount_remote::OBJECT_STORE_IO_TIMEOUT,
            );
        }
        LiveRemote::Azure => {
            let url_head = url.clone();
            let url_dl = url.clone();
            let url_pub = url;
            let url_label = url_pub.clone();
            let opts_pub = opts.clone();
            overlay.install_remote_live_commit_for(
                &url_label,
                Box::new(move || {
                    let head = ratarmount_remote::head_azure_object(&url_head)
                        .map_err(|e| OverlayError::Msg(e.to_string()))?;
                    Ok(RemoteObjectHead {
                        etag: head.etag,
                        len: head.len,
                    })
                }),
                Box::new(move || {
                    let loc = ratarmount_remote::parse_azure_url(&url_dl)
                        .map_err(|e| OverlayError::Msg(e.to_string()))?;
                    let (file, len) =
                        ratarmount_remote::fetch_azure_location_to_temp_prefer_range(&loc, None)
                            .map_err(|e| OverlayError::Msg(e.to_string()))?;
                    Ok(RemoteDownload { file, len })
                }),
                Box::new(move |req| publish_azure(&url_pub, &opts_pub, req)),
                ratarmount_remote::OBJECT_STORE_IO_TIMEOUT,
            );
        }
    }
}

const S3_PUT_SINGLE_MAX: u64 = 8 * 1024 * 1024;

/// `ensure_s3_write_ok` formats `{op} HTTP 412 precondition failed: {body}`.
/// The first ` HTTP ` status is the code. A 500 body that mentions 412 stays retryable.
fn is_s3_http_412(msg: &str) -> bool {
    match msg.find(" HTTP ") {
        Some(i) => msg[i + " HTTP ".len()..].starts_with("412"),
        None => false,
    }
}

fn map_s3_put(err: ratarmount_remote::RemoteError) -> RemotePublishError {
    let msg = err.to_string();
    if is_s3_http_412(&msg) {
        RemotePublishError::EtagMismatch(msg)
    } else {
        RemotePublishError::Retryable(msg)
    }
}

const SIDECAR_NOT_REBUILT: &str =
    "sidecar file table was not rebuilt from the uploaded spool; leaving the previous pointer";

fn tarstats_hex_eq(stored: Option<&str>, got: &str) -> bool {
    match stored.map(str::trim).filter(|s| !s.is_empty()) {
        Some(want) => !got.trim().is_empty() && want.eq_ignore_ascii_case(got.trim()),
        None => false,
    }
}

/// Partial windows keep file-table rows from the mount. Those rows describe the
/// pre-splice spool only when size, prefix, and suffix match, and the full hash
/// matches when the sidecar stored one. `window_start == 0` rebuilds every row.
/// Missing tarstats is a refusal.
fn sidecar_file_table_rebuilt_for_upload(
    sidecar: &Path,
    req: &RemotePublishRequest,
) -> std::result::Result<(), RemotePublishError> {
    if req.window.window_start == 0 {
        return Ok(());
    }
    let idx = SqliteIndex::open_read_only(sidecar)
        .map_err(|e| RemotePublishError::Retryable(e.to_string()))?;
    let Some(stats) = idx
        .tarstats()
        .map_err(|e| RemotePublishError::Retryable(e.to_string()))?
    else {
        return Err(RemotePublishError::Retryable(SIDECAR_NOT_REBUILT.into()));
    };
    let full_ok = match stats.full_sha256.as_deref() {
        Some(stored) => tarstats_hex_eq(Some(stored), &req.presplice_sha256),
        None => true,
    };
    if stats.st_size == req.presplice_len
        && tarstats_hex_eq(
            stats.prefix512_sha256.as_deref(),
            &req.presplice_prefix512_sha256,
        )
        && tarstats_hex_eq(
            stats.suffix512_sha256.as_deref(),
            &req.presplice_suffix512_sha256,
        )
        && full_ok
    {
        Ok(())
    } else {
        Err(RemotePublishError::Retryable(SIDECAR_NOT_REBUILT.into()))
    }
}

/// The file-table check runs before the object PUT. A refusal leaves the
/// previous pointer unstamped. When the object already contains the splice,
/// the error is [`RemotePublishError::PointerRefused`] so the caller forgets
/// the stashed plan and a remount does not append those members again.
fn publish_s3(
    url: &str,
    opts: &OpenOptions,
    req: &RemotePublishRequest,
) -> std::result::Result<(), RemotePublishError> {
    let loc = ratarmount_remote::parse_s3_url(url)
        .map_err(|e| RemotePublishError::Retryable(e.to_string()))?;
    let sidecar = sidecar_path_for_patch(Path::new(url), opts);
    if let Some(ref path) = sidecar {
        if let Err(e) = sidecar_file_table_rebuilt_for_upload(path, req) {
            let msg = e.to_string();
            return Err(if req.skip_object_put {
                RemotePublishError::PointerRefused(msg)
            } else {
                RemotePublishError::Retryable(msg)
            });
        }
    }
    if req.skip_object_put {
        log::info!(
            "s3 live commit object already matches the spliced spool; not uploading it again"
        );
    } else {
        let len = std::fs::metadata(&req.staged)
            .map_err(|e| RemotePublishError::Retryable(e.to_string()))?
            .len();
        let etag = req.etag_at_download.as_deref();
        log::info!(
            "s3 live commit uploading {len} bytes prefix={} etag={}",
            req.prefix_compressed_bytes,
            etag.unwrap_or("-")
        );
        let put = if len <= S3_PUT_SINGLE_MAX {
            let body = std::fs::read(&req.staged)
                .map_err(|e| RemotePublishError::Retryable(e.to_string()))?;
            ratarmount_remote::put_s3_object(&loc, &body, etag, Some("application/octet-stream"))
        } else {
            let copy = if req.prefix_compressed_bytes == 0 {
                None
            } else {
                Some(req.prefix_compressed_bytes)
            };
            ratarmount_remote::put_s3_multipart(
                &loc,
                &req.staged,
                copy,
                etag,
                Some("application/octet-stream"),
            )
        };
        if let Err(e) = put {
            return Err(map_s3_put(e));
        }
    }
    let Some(sidecar) = sidecar else {
        log::info!("incremental reindex skipped (no sidecar); rebuilding");
        return Ok(());
    };
    if let Err(e) = patch_sidecar_if_present(&req.staged, &req.window, opts) {
        return Err(RemotePublishError::PointerRefused(format!(
            "incremental reindex failed after object replace: {e}"
        )));
    }
    let blob_len = std::fs::metadata(&sidecar).map(|m| m.len()).unwrap_or(0);
    if blob_len > META_SIDECAR_WHOLE_MAX {
        log::warn!(
            "skipping s3 index pointer PUT for {url}: sidecar is {blob_len} bytes, above META_SIDECAR_WHOLE_MAX ({META_SIDECAR_WHOLE_MAX})"
        );
        return Ok(());
    }
    let pointer = match IndexPointer::for_blob(&sidecar, Some(&req.staged)) {
        Ok(p) => p,
        Err(e) => {
            log::warn!("index pointer skipped ({e})");
            return Ok(());
        }
    };
    let json = match index_pointer_to_json(&pointer) {
        Ok(j) => j,
        Err(e) => {
            log::warn!("index pointer skipped ({e})");
            return Ok(());
        }
    };
    match ratarmount_remote::put_s3_index_siblings(
        &loc,
        &pointer.index_id,
        json.as_bytes(),
        &sidecar,
    ) {
        Ok(ratarmount_remote::S3IndexSiblingPut::Uploaded) => {}
        Ok(ratarmount_remote::S3IndexSiblingPut::Skipped { blob_len, limit }) => {
            log::warn!("skipping s3 index sibling PUT for {url}: blob {blob_len} above {limit}");
        }
        Err(e) => {
            log::warn!(
                "s3 index pointer PUT failed after object replace for s3://{}/{}: {e}",
                loc.bucket,
                loc.key
            );
        }
    }
    Ok(())
}

fn map_gcs_put(err: ratarmount_remote::RemoteError) -> RemotePublishError {
    let msg = err.to_string();
    if is_s3_http_412(&msg) {
        RemotePublishError::EtagMismatch(msg)
    } else {
        RemotePublishError::Retryable(msg)
    }
}

fn gcs_index_locations(
    archive: &ratarmount_remote::GcsLocation,
    index_id: &str,
) -> std::result::Result<
    (
        ratarmount_remote::GcsLocation,
        ratarmount_remote::GcsLocation,
    ),
    String,
> {
    let id = index_id.trim().to_ascii_lowercase();
    if id.len() != 64 || !id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(format!(
            "index_id must be 64 lowercase hex, not {index_id:?}"
        ));
    }
    let bucket = archive.bucket.clone();
    Ok((
        ratarmount_remote::GcsLocation {
            bucket: bucket.clone(),
            object: format!("{}.index.{id}.sqlite", archive.object),
        },
        ratarmount_remote::GcsLocation {
            bucket,
            object: format!("{}.index.ptr", archive.object),
        },
    ))
}

/// Same order as [`publish_s3`]: file-table check, object PUT, patch, `for_blob`,
/// blob PUT, pointer PUT. One PUT, no multipart, no well-known key. A failed
/// object PUT is retryable and does not disable the interval.
fn publish_gcs(
    url: &str,
    opts: &OpenOptions,
    req: &RemotePublishRequest,
) -> std::result::Result<(), RemotePublishError> {
    let loc = ratarmount_remote::parse_gcs_url(url)
        .map_err(|e| RemotePublishError::Retryable(e.to_string()))?;
    let sidecar = sidecar_path_for_patch(Path::new(url), opts);
    if let Some(ref path) = sidecar {
        if let Err(e) = sidecar_file_table_rebuilt_for_upload(path, req) {
            let msg = e.to_string();
            return Err(if req.skip_object_put {
                RemotePublishError::PointerRefused(msg)
            } else {
                RemotePublishError::Retryable(msg)
            });
        }
    }
    if req.skip_object_put {
        log::info!(
            "gcs live commit object already matches the spliced spool; not uploading it again"
        );
    } else {
        let len = std::fs::metadata(&req.staged)
            .map(|m| m.len())
            .map_err(|e| RemotePublishError::Retryable(e.to_string()))?;
        log::info!(
            "gcs live commit uploading {len} bytes prefix={}",
            req.prefix_compressed_bytes
        );
        if let Err(e) =
            ratarmount_remote::put_gcs_file(&loc, &req.staged, "application/octet-stream")
        {
            return Err(map_gcs_put(e));
        }
    }
    let Some(sidecar) = sidecar else {
        log::info!("incremental reindex skipped (no sidecar); rebuilding");
        return Ok(());
    };
    if let Err(e) = patch_sidecar_if_present(&req.staged, &req.window, opts) {
        return Err(RemotePublishError::PointerRefused(format!(
            "incremental reindex failed after object replace: {e}"
        )));
    }
    let blob_len = std::fs::metadata(&sidecar).map(|m| m.len()).unwrap_or(0);
    if blob_len > META_SIDECAR_WHOLE_MAX {
        log::warn!(
            "skipping gcs index pointer PUT for {url}: sidecar is {blob_len} bytes, above META_SIDECAR_WHOLE_MAX ({META_SIDECAR_WHOLE_MAX})"
        );
        return Ok(());
    }
    let pointer = match IndexPointer::for_blob(&sidecar, Some(&req.staged)) {
        Ok(p) => p,
        Err(e) => {
            log::warn!("index pointer skipped ({e})");
            return Ok(());
        }
    };
    let json = match index_pointer_to_json(&pointer) {
        Ok(j) => j,
        Err(e) => {
            log::warn!("index pointer skipped ({e})");
            return Ok(());
        }
    };
    let (blob_loc, ptr_loc) = match gcs_index_locations(&loc, &pointer.index_id) {
        Ok(v) => v,
        Err(e) => {
            log::warn!("index pointer skipped ({e})");
            return Ok(());
        }
    };
    let blob = match std::fs::read(&sidecar) {
        Ok(b) => b,
        Err(e) => {
            log::warn!("gcs index blob read failed after object replace: {e}");
            return Ok(());
        }
    };
    if let Err(e) = ratarmount_remote::put_gcs_object(
        &blob_loc,
        &blob,
        ratarmount_remote::OCI_INDEX_ARTIFACT_TYPE,
    ) {
        log::warn!(
            "gcs index blob PUT failed after object replace for gs://{}/{}: {e}",
            loc.bucket,
            loc.object
        );
        return Ok(());
    }
    if let Err(e) = ratarmount_remote::put_gcs_object(&ptr_loc, json.as_bytes(), "application/json")
    {
        log::warn!(
            "gcs index pointer PUT failed after object replace for gs://{}/{}: {e}",
            loc.bucket,
            loc.object
        );
    }
    Ok(())
}

fn map_azure_put(err: ratarmount_remote::RemoteError) -> RemotePublishError {
    let msg = err.to_string();
    if is_s3_http_412(&msg) {
        RemotePublishError::EtagMismatch(msg)
    } else {
        RemotePublishError::Retryable(msg)
    }
}

fn azure_index_locations(
    archive: &ratarmount_remote::AzureLocation,
    index_id: &str,
) -> std::result::Result<
    (
        ratarmount_remote::AzureLocation,
        ratarmount_remote::AzureLocation,
    ),
    String,
> {
    let id = index_id.trim().to_ascii_lowercase();
    if id.len() != 64 || !id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(format!(
            "index_id must be 64 lowercase hex, not {index_id:?}"
        ));
    }
    let container = archive.container.clone();
    Ok((
        ratarmount_remote::AzureLocation {
            container: container.clone(),
            blob: format!("{}.index.{id}.sqlite", archive.blob),
        },
        ratarmount_remote::AzureLocation {
            container,
            blob: format!("{}.index.ptr", archive.blob),
        },
    ))
}

/// Same order as [`publish_gcs`]: file-table check, object upload, patch,
/// `for_blob`, blob PUT, pointer PUT. No well-known key. A failed block list
/// is retryable: the caller does not forget the overlay and does not bump
/// `commit_generation`, so the next attempt reuses the same block ids.
fn publish_azure(
    url: &str,
    opts: &OpenOptions,
    req: &RemotePublishRequest,
) -> std::result::Result<(), RemotePublishError> {
    let loc = ratarmount_remote::parse_azure_url(url)
        .map_err(|e| RemotePublishError::Retryable(e.to_string()))?;
    let sidecar = sidecar_path_for_patch(Path::new(url), opts);
    if let Some(ref path) = sidecar {
        if let Err(e) = sidecar_file_table_rebuilt_for_upload(path, req) {
            let msg = e.to_string();
            return Err(if req.skip_object_put {
                RemotePublishError::PointerRefused(msg)
            } else {
                RemotePublishError::Retryable(msg)
            });
        }
    }
    if req.skip_object_put {
        log::info!(
            "azure live commit object already matches the spliced spool; not uploading it again"
        );
    } else {
        let len = std::fs::metadata(&req.staged)
            .map(|m| m.len())
            .map_err(|e| RemotePublishError::Retryable(e.to_string()))?;
        log::info!(
            "azure live commit uploading {len} bytes prefix={} generation={}",
            req.prefix_compressed_bytes,
            req.commit_generation
        );
        let if_match = req.etag_at_download.as_deref().filter(|s| !s.is_empty());
        if let Err(e) = ratarmount_remote::put_azure_blocks(
            &loc,
            &req.staged,
            "application/octet-stream",
            req.commit_generation,
            if_match,
        ) {
            return Err(map_azure_put(e));
        }
    }
    let Some(sidecar) = sidecar else {
        log::info!("incremental reindex skipped (no sidecar); rebuilding");
        return Ok(());
    };
    if let Err(e) = patch_sidecar_if_present(&req.staged, &req.window, opts) {
        return Err(RemotePublishError::PointerRefused(format!(
            "incremental reindex failed after object replace: {e}"
        )));
    }
    let blob_len = std::fs::metadata(&sidecar).map(|m| m.len()).unwrap_or(0);
    if blob_len > META_SIDECAR_WHOLE_MAX {
        log::warn!(
            "skipping azure index pointer PUT for {url}: sidecar is {blob_len} bytes, above META_SIDECAR_WHOLE_MAX ({META_SIDECAR_WHOLE_MAX})"
        );
        return Ok(());
    }
    let pointer = match IndexPointer::for_blob(&sidecar, Some(&req.staged)) {
        Ok(p) => p,
        Err(e) => {
            log::warn!("index pointer skipped ({e})");
            return Ok(());
        }
    };
    let json = match index_pointer_to_json(&pointer) {
        Ok(j) => j,
        Err(e) => {
            log::warn!("index pointer skipped ({e})");
            return Ok(());
        }
    };
    let (blob_loc, ptr_loc) = match azure_index_locations(&loc, &pointer.index_id) {
        Ok(v) => v,
        Err(e) => {
            log::warn!("index pointer skipped ({e})");
            return Ok(());
        }
    };
    if let Err(e) = ratarmount_remote::put_azure_blocks(
        &blob_loc,
        &sidecar,
        ratarmount_remote::OCI_INDEX_ARTIFACT_TYPE,
        req.commit_generation,
        None,
    ) {
        return Err(map_azure_put(e));
    }
    if let Err(e) = ratarmount_remote::put_azure_bytes(
        &ptr_loc,
        json.as_bytes(),
        "application/json",
        req.commit_generation,
        None,
    ) {
        // Not Ok: a 400 here used to bump commit_generation and forget the overlay
        // while the pointer stayed stale.
        return Err(map_azure_put(e));
    }
    Ok(())
}

fn url_is_tar_zst(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    lower.ends_with(".tar.zst") || lower.ends_with(".tzst") || lower.ends_with(".tar.zstd")
}

/// Reopen via [`ratarmount_remote::open_s3_range`] only. The spool path is not a mount.
fn reopen_s3_mount(url: &str, opts: &OpenOptions) -> Result<Arc<dyn MountSource>, OverlayError> {
    let range = ratarmount_remote::open_s3_range(url)
        .map_err(|e| OverlayError::Msg(format!("reopen s3: {e}")))?;
    let label = PathBuf::from(url);
    let mut o = opts.clone();
    o.index_in_memory = true;
    o.index_file_path = None;
    o.write_index = false;
    if url_is_tar_zst(url) {
        let threads = o.threads_for("zstd");
        let body = ratarmount_compress::open_seekable_zstd_with_threads_from_reader(
            range, threads, &label,
        )
        .map_err(|e| OverlayError::Msg(format!("reopen s3 zstd: {e}")))?;
        let tar =
            SqliteIndexedTar::create_index_body(&label, body, None, &o, env!("CARGO_PKG_VERSION"))
                .map_err(|e| OverlayError::Msg(format!("reopen s3 tar.zst: {e}")))?;
        Ok(Arc::new(tar))
    } else {
        let tar =
            SqliteIndexedTar::open_from_reader(range, &label, None, &o, env!("CARGO_PKG_VERSION"))
                .map_err(|e| OverlayError::Msg(format!("reopen s3 tar: {e}")))?;
        Ok(Arc::new(tar))
    }
}

/// Reopen via [`ratarmount_remote::open_gcs_range`] only. The spool path is not a mount.
fn reopen_gcs_mount(url: &str, opts: &OpenOptions) -> Result<Arc<dyn MountSource>, OverlayError> {
    let range = ratarmount_remote::open_gcs_range(url)
        .map_err(|e| OverlayError::Msg(format!("reopen gcs: {e}")))?;
    let label = PathBuf::from(url);
    let mut o = opts.clone();
    o.index_in_memory = true;
    o.index_file_path = None;
    o.write_index = false;
    if url_is_tar_zst(url) {
        let threads = o.threads_for("zstd");
        let body = ratarmount_compress::open_seekable_zstd_with_threads_from_reader(
            range, threads, &label,
        )
        .map_err(|e| OverlayError::Msg(format!("reopen gcs zstd: {e}")))?;
        let tar =
            SqliteIndexedTar::create_index_body(&label, body, None, &o, env!("CARGO_PKG_VERSION"))
                .map_err(|e| OverlayError::Msg(format!("reopen gcs tar.zst: {e}")))?;
        Ok(Arc::new(tar))
    } else {
        let tar =
            SqliteIndexedTar::open_from_reader(range, &label, None, &o, env!("CARGO_PKG_VERSION"))
                .map_err(|e| OverlayError::Msg(format!("reopen gcs tar: {e}")))?;
        Ok(Arc::new(tar))
    }
}

/// Reopen via [`ratarmount_remote::open_azure_range`] only. The spool path is not a mount.
fn reopen_azure_mount(url: &str, opts: &OpenOptions) -> Result<Arc<dyn MountSource>, OverlayError> {
    let range = ratarmount_remote::open_azure_range(url)
        .map_err(|e| OverlayError::Msg(format!("reopen azure: {e}")))?;
    let label = PathBuf::from(url);
    let mut o = opts.clone();
    o.index_in_memory = true;
    o.index_file_path = None;
    o.write_index = false;
    if url_is_tar_zst(url) {
        let threads = o.threads_for("zstd");
        let body = ratarmount_compress::open_seekable_zstd_with_threads_from_reader(
            range, threads, &label,
        )
        .map_err(|e| OverlayError::Msg(format!("reopen azure zstd: {e}")))?;
        let tar =
            SqliteIndexedTar::create_index_body(&label, body, None, &o, env!("CARGO_PKG_VERSION"))
                .map_err(|e| OverlayError::Msg(format!("reopen azure tar.zst: {e}")))?;
        Ok(Arc::new(tar))
    } else {
        let tar =
            SqliteIndexedTar::open_from_reader(range, &label, None, &o, env!("CARGO_PKG_VERSION"))
                .map_err(|e| OverlayError::Msg(format!("reopen azure tar: {e}")))?;
        Ok(Arc::new(tar))
    }
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
        Err(e) => eprintln!("error: on-exit overlay commit failed: {e}"),
    }
}

#[cfg(test)]
pub(crate) fn set_term_flag_for_test(v: bool) {
    GOT_TERM.store(v, Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn sha256_file(path: &std::path::Path) -> String {
        let mut f = std::fs::File::open(path).unwrap();
        ratarmount_index::sha256_hex_stream(&mut f).unwrap()
    }

    fn publish_req(
        staged: &std::path::Path,
        window_start: u64,
        from_frame: Option<usize>,
    ) -> RemotePublishRequest {
        let (prefix, suffix) = ratarmount_index::archive_edge_hashes(staged).unwrap();
        RemotePublishRequest {
            staged: staged.to_path_buf(),
            prefix_compressed_bytes: 0,
            etag_at_download: Some("\"reget\"".into()),
            window: ratarmount_compositing::IndexPatchWindow {
                window_start,
                from_frame,
                offsets_shifted: window_start > 0,
            },
            skip_object_put: true,
            presplice_len: std::fs::metadata(staged).unwrap().len(),
            presplice_sha256: sha256_file(staged),
            presplice_prefix512_sha256: prefix,
            presplice_suffix512_sha256: suffix,
            commit_generation: 0,
        }
    }

    fn assert_publish_leaves_previous_pointer(
        sidecar: &std::path::Path,
        mount_len: u64,
        req: &RemotePublishRequest,
    ) {
        let before = SqliteIndex::open_read_only(sidecar)
            .unwrap()
            .tarstats()
            .unwrap()
            .expect("mount tarstats");
        assert_eq!(before.st_size, mount_len);
        assert!(before.full_sha256.is_some());
        let opts = OpenOptions {
            index_file_path: Some(sidecar.to_path_buf()),
            index_in_memory: false,
            ..OpenOptions::default()
        };
        let err = publish_s3("s3://bkt/data/a.tar", &opts, req).unwrap_err();
        match err {
            RemotePublishError::Retryable(ref msg)
            | RemotePublishError::PointerRefused(ref msg) => {
                assert!(msg.contains("leaving the previous pointer"), "{msg}");
            }
            RemotePublishError::EtagMismatch(msg) => {
                panic!("re-GET mismatch must not be an ETag failure: {msg}")
            }
        }
        let after = SqliteIndex::open_read_only(sidecar)
            .unwrap()
            .tarstats()
            .unwrap()
            .expect("tarstats after refused publish");
        assert_eq!(
            after.st_size, before.st_size,
            "tarstats must not be stamped"
        );
        assert_eq!(after.full_sha256, before.full_sha256);
        assert_ne!(
            after.full_sha256.as_deref().map(|s| s.to_ascii_lowercase()),
            Some(req.presplice_sha256.to_ascii_lowercase()),
            "stamp would record the re-GET, not the mounted generation"
        );
    }

    /// Regression: uncompressed delete window is the mount's offset, not the re-GET.
    #[test]
    fn publish_refuses_stamp_when_reget_differs_uncompressed_delete() {
        let dir = tempfile::tempdir().unwrap();
        let mount = dir.path().join("mount.tar");
        let keep = b"keep-mount\n";
        let dropped = b"drop-mount\n";
        let members = [
            ratarmount_formats_tar::UstarMember {
                path: "keep.txt",
                payload: ratarmount_formats_tar::UstarPayload::File { bytes: keep },
                mode: 0o644,
                uid: 0,
                gid: 0,
                mtime: 0,
            },
            ratarmount_formats_tar::UstarMember {
                path: "drop.txt",
                payload: ratarmount_formats_tar::UstarPayload::File { bytes: dropped },
                mode: 0o644,
                uid: 0,
                gid: 0,
                mtime: 0,
            },
        ];
        let mut tar = Vec::new();
        ratarmount_formats_tar::write_ustar_members(&mut tar, &members).unwrap();
        ratarmount_formats_tar::write_tar_eof(&mut tar).unwrap();
        std::fs::write(&mount, &tar).unwrap();
        let sidecar = dir.path().join("mount.index.sqlite");
        {
            let opts = OpenOptions {
                write_index: true,
                index_minimum_file_count: 0,
                ..OpenOptions::default()
            };
            let mut mat = None;
            let _idx = SqliteIndexedTar::create_index(
                &mount,
                &mount,
                Some(&sidecar),
                &opts,
                "test",
                &mut mat,
            )
            .expect("index mount tar");
        }
        let spool = dir.path().join("reget.tar");
        let other = b"different-reget-bytes-not-the-mount\n";
        let spool_members = [
            ratarmount_formats_tar::UstarMember {
                path: "keep.txt",
                payload: ratarmount_formats_tar::UstarPayload::File { bytes: other },
                mode: 0o644,
                uid: 0,
                gid: 0,
                mtime: 0,
            },
            ratarmount_formats_tar::UstarMember {
                path: "drop.txt",
                payload: ratarmount_formats_tar::UstarPayload::File { bytes: other },
                mode: 0o644,
                uid: 0,
                gid: 0,
                mtime: 0,
            },
        ];
        let mut spool_tar = Vec::new();
        ratarmount_formats_tar::write_ustar_members(&mut spool_tar, &spool_members).unwrap();
        ratarmount_formats_tar::write_tar_eof(&mut spool_tar).unwrap();
        std::fs::write(&spool, &spool_tar).unwrap();
        let window_start = 512 + (keep.len() as u64).div_ceil(512) * 512;
        assert!(window_start > 0);
        let req = publish_req(&spool, window_start, None);
        assert_publish_leaves_previous_pointer(
            &sidecar,
            std::fs::metadata(&mount).unwrap().len(),
            &req,
        );
    }

    /// Regression: .tar.zst prefix splice keeps rows before window_start from the mount.
    #[test]
    fn publish_refuses_stamp_when_reget_differs_tar_zst_splice() {
        let dir = tempfile::tempdir().unwrap();
        let mount = dir.path().join("mount.tar.zst");
        write_split_tar_zst(&mount, b"prefix-mount\n", b"last-mount\n");
        let sidecar = dir.path().join("mount.index.sqlite");
        {
            let body = open_seekable_zstd_with_threads(&mount, 1).expect("open zstd");
            let opts = OpenOptions {
                write_index: true,
                index_minimum_file_count: 0,
                ..OpenOptions::default()
            };
            let _idx =
                SqliteIndexedTar::create_index_body(&mount, body, Some(&sidecar), &opts, "test")
                    .expect("index mount tar.zst");
        }
        let map = scan_zstd_frames_path(&mount).unwrap();
        assert!(
            map.frames.len() >= 2,
            "prefix-preserving splice needs two frames"
        );
        let window_start = map.frames[1].uncompressed_offset;
        assert!(window_start > 0);
        let spool = dir.path().join("reget.tar.zst");
        write_split_tar_zst(
            &spool,
            b"prefix-reget-differs-from-mount\n",
            b"last-reget-differs\n",
        );
        let req = publish_req(&spool, window_start, Some(1));
        assert_publish_leaves_previous_pointer(
            &sidecar,
            std::fs::metadata(&mount).unwrap().len(),
            &req,
        );
    }

    fn ustar_archive(name: &str, payload: &[u8]) -> Vec<u8> {
        let member = ratarmount_formats_tar::UstarMember {
            path: name,
            payload: ratarmount_formats_tar::UstarPayload::File { bytes: payload },
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime: 0,
        };
        let mut tar = Vec::new();
        ratarmount_formats_tar::write_ustar_members(&mut tar, &[member]).unwrap();
        ratarmount_formats_tar::write_tar_eof(&mut tar).unwrap();
        tar
    }

    /// Regression: same-size re-GET above the full-hash cap, prefix differs.
    /// The pointer is not PUT and tarstats are not stamped.
    #[test]
    fn publish_refuses_same_size_reget_over_full_hash_cap() {
        let dir = tempfile::tempdir().unwrap();
        let payload_len = ratarmount_index::TARSTATS_FULL_HASH_MAX as usize;
        let payload = vec![b'A'; payload_len];
        let mount_bytes = ustar_archive("aaaa.txt", &payload);
        let mut reget_payload = payload.clone();
        reget_payload[..512].fill(b'B');
        let reget_bytes = ustar_archive("bbbb.txt", &reget_payload);
        assert_eq!(mount_bytes.len(), reget_bytes.len());
        assert!(mount_bytes.len() as u64 > ratarmount_index::TARSTATS_FULL_HASH_MAX);
        assert_ne!(&mount_bytes[..512], &reget_bytes[..512]);
        let mount = dir.path().join("mount.tar");
        let spool = dir.path().join("reget.tar");
        std::fs::write(&mount, &mount_bytes).unwrap();
        std::fs::write(&spool, &reget_bytes).unwrap();
        let sidecar = dir.path().join("mount.index.sqlite");
        {
            let opts = OpenOptions {
                write_index: true,
                index_minimum_file_count: 0,
                ..OpenOptions::default()
            };
            let mut mat = None;
            let _idx = SqliteIndexedTar::create_index(
                &mount,
                &mount,
                Some(&sidecar),
                &opts,
                "test",
                &mut mat,
            )
            .expect("index large tar");
        }
        let before = SqliteIndex::open_read_only(&sidecar)
            .unwrap()
            .tarstats()
            .unwrap()
            .expect("edge tarstats");
        assert!(before.st_size > ratarmount_index::TARSTATS_FULL_HASH_MAX);
        assert!(before.full_sha256.is_none(), "above the full-hash cap");
        assert!(before.prefix512_sha256.is_some());
        assert!(before.suffix512_sha256.is_some());
        let mut req = publish_req(&spool, 512, None);
        req.skip_object_put = false;
        assert_ne!(
            before
                .prefix512_sha256
                .as_deref()
                .map(|s| s.to_ascii_lowercase()),
            Some(req.presplice_prefix512_sha256.to_ascii_lowercase())
        );
        let before_bytes = std::fs::read(&sidecar).unwrap();
        let opts = OpenOptions {
            index_file_path: Some(sidecar.clone()),
            index_in_memory: false,
            ..OpenOptions::default()
        };
        let err = publish_s3("s3://bkt/data/a.tar", &opts, &req).unwrap_err();
        match err {
            RemotePublishError::Retryable(msg) => {
                assert!(msg.contains("leaving the previous pointer"), "{msg}");
            }
            other => panic!("check runs before the object PUT: {other}"),
        }
        assert_eq!(
            std::fs::read(&sidecar).unwrap(),
            before_bytes,
            "tarstats must not be stamped and the pointer sqlite is unchanged"
        );
    }

    /// Regression: a partial window with no tarstats row is a refusal.
    #[test]
    fn publish_refuses_partial_window_when_tarstats_missing() {
        let dir = tempfile::tempdir().unwrap();
        let sidecar = dir.path().join("bare.index.sqlite");
        {
            let mut idx = SqliteIndex::create_writable(Some(&sidecar)).unwrap();
            idx.publish_tmp().unwrap();
        }
        assert!(SqliteIndex::open_read_only(&sidecar)
            .unwrap()
            .tarstats()
            .unwrap()
            .is_none());
        let spool = dir.path().join("reget.tar");
        std::fs::write(&spool, ustar_archive("keep.txt", b"reget-bytes\n")).unwrap();
        let req = publish_req(&spool, 512, None);
        let opts = OpenOptions {
            index_file_path: Some(sidecar.clone()),
            index_in_memory: false,
            ..OpenOptions::default()
        };
        let err = publish_s3("s3://bkt/data/a.tar", &opts, &req).unwrap_err();
        match err {
            RemotePublishError::PointerRefused(msg) => {
                assert!(msg.contains("leaving the previous pointer"), "{msg}");
            }
            other => panic!("missing tarstats must refuse the pointer: {other}"),
        }
        assert!(SqliteIndex::open_read_only(&sidecar)
            .unwrap()
            .tarstats()
            .unwrap()
            .is_none());
    }

    #[test]
    fn map_s3_put_matches_http_412_status_prefix_only() {
        let mismatch = map_s3_put(ratarmount_remote::RemoteError::S3(
            "PutObject HTTP 412 precondition failed: lost update".into(),
        ));
        assert!(
            matches!(mismatch, RemotePublishError::EtagMismatch(_)),
            "{mismatch}"
        );
        let retry = map_s3_put(ratarmount_remote::RemoteError::S3(
            "PutObject HTTP 500: body mentions HTTP 412".into(),
        ));
        assert!(matches!(retry, RemotePublishError::Retryable(_)), "{retry}");
    }
}
