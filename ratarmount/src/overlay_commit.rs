//! Live overlay commit (uncompressed TAR and `.tar.zst`): interval + on-exit.
//!
//! `--commit-overlay-interval` is a per-file settle time: only overlay files
//! whose host mtime is at least that old are persisted. On-exit still flushes
//! the whole overlay.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use ratarmount_compositing::{
    classify_createable_archive, maybe_create_empty_write_archive, maybe_wrap_payload_cache,
    patch_sidecar_if_present, sidecar_path_for_patch, CommitKind, CommitOutcome, EmptyArchiveKind,
    EmptyCreateOutcome, OverlayError, RemoteDownload, RemoteObjectHead, RemotePublishError,
    RemotePublishRequest, WriteOverlay,
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
/// Last signal number seen by [`on_term_signal`]; 0 until a real signal arrives.
static TERM_SIGNAL: AtomicI32 = AtomicI32::new(0);
/// Real signals delivered so far. Lets the unmount watcher tell a new signal from the sticky flag.
static TERM_COUNT: AtomicUsize = AtomicUsize::new(0);

extern "C" fn on_term_signal(sig: libc::c_int) {
    // Only atomic stores: async-signal-safe.
    TERM_SIGNAL.store(sig, Ordering::SeqCst);
    TERM_COUNT.fetch_add(1, Ordering::SeqCst);
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

/// Ask interval commit and signal watchers to stop.
///
/// The mount path calls this before joining the interval thread and dropping
/// [`WriteOverlay`]. `std::process::exit` skips that drop, so the flag has to
/// be set while destructors still run.
pub fn request_shutdown() {
    GOT_TERM.store(true, Ordering::SeqCst);
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
///
/// The unmount retries while the mount is briefly busy. SIGTERM, and only
/// SIGTERM, falls back to a logged lazy unmount if it is still busy after that.
///
/// Installs the term handler itself (idempotent), so it exists exactly in the process that
/// serves the mount: a daemon parent that only waits for the mount keeps default signals.
pub fn spawn_signal_fuse_unmount(mp: PathBuf) {
    // A signal before the mount is up makes the first unmount fail ("not mounted") and the
    // watcher waits for the next signal (same as `:temp:` mounts before this change).
    install_term_signal_flag();
    thread::Builder::new()
        .name("ratarmount-fuse-signal".into())
        .spawn(move || {
            signal_unmount_watcher(
                &mp,
                &term_state,
                &|p| ratarmount_fuse::unmount(p),
                &|p| ratarmount_fuse::unmount_lazy(p),
                Duration::from_millis(50),
            );
        })
        .expect("fuse signal unmount thread");
}

/// Logs a failure once per distinct message. A commit refused because the
/// base changed is retried on every tick; the same refusal every second would
/// flood the log, while a new observed stamp is new information.
#[derive(Default)]
struct RepeatedFailure(Option<String>);

impl RepeatedFailure {
    /// `true` when `message` differs from the previous failure.
    fn is_new(&mut self, message: &str) -> bool {
        let new = self.0.as_deref() != Some(message);
        if new {
            self.0 = Some(message.to_owned());
        }
        new
    }

    fn clear(&mut self) {
        self.0 = None;
    }
}

/// Snapshot of the termination flags.
struct TermState {
    count: usize,
    signal: Option<libc::c_int>,
    /// [`GOT_TERM`]: set by a signal or by [`request_shutdown`].
    flagged: bool,
}

fn term_state() -> TermState {
    // The handler stores signal, count, then flag. Reading in the reverse order
    // means a flag seen set implies the count and signal that set it are visible.
    let flagged = GOT_TERM.load(Ordering::SeqCst);
    let count = TERM_COUNT.load(Ordering::SeqCst);
    let signal = TERM_SIGNAL.load(Ordering::SeqCst);
    TermState {
        count,
        signal: (signal != 0).then_some(signal),
        flagged,
    }
}

/// Error payloads are read through `Debug` (tests and diagnostics) only.
#[derive(Debug)]
#[allow(dead_code)]
enum SignalUnmountOutcome {
    Unmounted,
    LazyFallback,
    /// Both the retried unmount and the lazy fallback failed.
    LazyFailed(std::io::Error, std::io::Error),
    Failed(std::io::Error),
    /// No real signal: a programmatic [`request_shutdown`].
    Skipped,
}

fn signal_name(sig: libc::c_int) -> String {
    match sig {
        libc::SIGTERM => "SIGTERM".to_string(),
        libc::SIGINT => "SIGINT".to_string(),
        other => format!("signal {other}"),
    }
}

/// One unmount attempt for `signal`. Lazy (`-z`) runs only for SIGTERM and only
/// when the retried unmount still reported the mount busy.
fn signal_unmount(
    mp: &Path,
    signal: Option<libc::c_int>,
    unmount: &dyn Fn(&Path) -> std::io::Result<()>,
    lazy: &dyn Fn(&Path) -> std::io::Result<()>,
) -> SignalUnmountOutcome {
    let Some(sig) = signal else {
        return SignalUnmountOutcome::Skipped;
    };
    let name = signal_name(sig);
    match unmount(mp) {
        Ok(()) => SignalUnmountOutcome::Unmounted,
        Err(e) if sig == libc::SIGTERM && e.kind() == std::io::ErrorKind::ResourceBusy => {
            log::warn!(
                "{name}: {} still busy after retries ({e}); lazy unmount (fusermount3 -u -z)",
                mp.display()
            );
            match lazy(mp) {
                Ok(()) => {
                    log::warn!(
                        "{name}: {} lazily detached; waiting for open files to close before exiting",
                        mp.display()
                    );
                    SignalUnmountOutcome::LazyFallback
                }
                Err(lazy_err) => {
                    log::error!(
                        "{name}: could not unmount {}: {e}; lazy unmount also failed: {lazy_err}",
                        mp.display()
                    );
                    SignalUnmountOutcome::LazyFailed(e, lazy_err)
                }
            }
        }
        Err(e) => {
            log::warn!("{name}: unmount of {} failed: {e}", mp.display());
            SignalUnmountOutcome::Failed(e)
        }
    }
}

/// Run [`signal_unmount`] for each new signal until one ends the attempt
/// (unmounted or lazy-detached). A failed attempt, including a failed lazy
/// fallback, keeps the watcher alive so the next signal retries. A programmatic
/// shutdown before any signal ends it without unmounting.
fn signal_unmount_watcher(
    mp: &Path,
    state: &dyn Fn() -> TermState,
    unmount: &dyn Fn(&Path) -> std::io::Result<()>,
    lazy: &dyn Fn(&Path) -> std::io::Result<()>,
    poll: Duration,
) {
    let mut seen = 0;
    loop {
        let st = state();
        // A recorded signal counts as at least one even if the snapshot was torn.
        let count = st.count.max(usize::from(st.signal.is_some()));
        if count != seen {
            seen = count;
            match signal_unmount(mp, st.signal, unmount, lazy) {
                SignalUnmountOutcome::Unmounted | SignalUnmountOutcome::LazyFallback => return,
                SignalUnmountOutcome::LazyFailed(..)
                | SignalUnmountOutcome::Failed(_)
                | SignalUnmountOutcome::Skipped => {}
            }
        } else if st.flagged && seen == 0 {
            return;
        }
        thread::sleep(poll);
    }
}

pub fn spawn_interval_commits(
    overlay: Arc<WriteOverlay>,
    archive: PathBuf,
    interval: Duration,
    stop: Option<NfsStop>,
    opts: OpenOptions,
) -> thread::JoinHandle<()> {
    // Poll at least once a second so a file enters the archive ~`interval`
    // after its last host mtime, not up to 2× interval later. The settle
    // threshold is still `interval` (only idle files are persisted).
    let poll = Duration::from_secs(1).min(interval);
    let remote_kind = live_remote_kind(&archive.to_string_lossy());
    let remote_url = archive.to_string_lossy().into_owned();
    thread::Builder::new()
        .name("ratarmount-overlay-commit".into())
        .spawn(move || {
            let mut failures = RepeatedFailure::default();
            loop {
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
                        LiveRemote::Hf => ov.reopen_remote_live_commit(),
                        LiveRemote::Local => {
                            if let Some(window) = ov.last_patch_window() {
                                patch_sidecar_if_present(p, &window, &opts)?;
                            }
                            reopen_live_archive(p, &opts).map_err(OverlayError::Msg)
                        }
                    }
                }) {
                    Ok(CommitOutcome::DidWork) => {
                        failures.clear();
                        log::info!(
                            "interval overlay commit wrote idle files into {}",
                            overlay.commit_archive_path(&archive).display()
                        )
                    }
                    Ok(CommitOutcome::Nothing) => {
                        log::debug!("interval overlay commit: nothing idle to do")
                    }
                    Ok(CommitOutcome::Coalesced) => {
                        log::debug!("interval overlay commit coalesced (persist already in flight)")
                    }
                    Ok(CommitOutcome::Disabled) => {
                        log::debug!("interval overlay commit skipped (remount required)")
                    }
                    Err(e) => {
                        let message = e.to_string();
                        if failures.is_new(&message) {
                            log::error!("interval overlay commit failed: {message}");
                        } else {
                            log::debug!("interval overlay commit failed again: {message}");
                        }
                    }
                }
            }
        })
        .expect("interval commit thread")
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
                patch_sidecar_if_present(&overlay.commit_archive_path(archive), &window, opts)
                    .map_err(|e| e.to_string())?;
            }
        }
        Ok(did)
    }
}

pub fn open_rolling_series(
    base: &Path,
    policy: ratarmount_compositing::RollPolicy,
    opts: &OpenOptions,
) -> Result<Arc<ratarmount_compositing::RollingMountSource>, String> {
    let opts = opts.clone();
    // The mount classified and recovered every generation first (see main), so
    // the opener does not recover them before the identity gates decided.
    let recover = opts.recover_journals;
    ratarmount_compositing::RollingMountSource::open_with_recovery(
        base,
        policy,
        move |path| {
            ratarmount_session::factory::open_path(path, &opts, false).map_err(OverlayError::Msg)
        },
        recover,
    )
    .map(Arc::new)
    .map_err(|e| e.to_string())
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
    if path.to_string_lossy().starts_with("git://")
        || ratarmount_remote::is_remote_url(&path.to_string_lossy())
    {
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

/// Allow the publication flag for live Hub writes without requesting index-only publication.
pub fn live_hf_create_pr(
    inputs: &[PathBuf],
    interval: &str,
    on_exit: bool,
    create_pr: bool,
) -> bool {
    create_pr
        && (on_exit || parse_interval(interval).is_ok_and(|i| i.is_some()))
        && inputs.len() == 1
        && live_remote_kind(&inputs[0].to_string_lossy()) == LiveRemote::Hf
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
        LiveRemote::Hf | LiveRemote::S3 | LiveRemote::Gcs | LiveRemote::Azure
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
    if live_remote_kind(&s) == LiveRemote::Hf || ratarmount_remote::is_object_store_archive_url(&s)
    {
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
    Hf,
    S3,
    Gcs,
    Azure,
}

fn live_remote_kind(url: &str) -> LiveRemote {
    if ratarmount_remote::remote_url_scheme(url).as_deref() == Some("hf") {
        LiveRemote::Hf
    } else if url.starts_with("s3://") {
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
    matches!(
        kind,
        LiveRemote::Hf | LiveRemote::S3 | LiveRemote::Gcs | LiveRemote::Azure
    )
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

/// Wire one remote archive into the live queue. Hub mounts require their pinned branch identity.
/// The `gs://` arm calls [`publish_gcs`]. The `az://` arm calls [`publish_azure`].
/// `-w` is not decided here.
pub fn install_object_store_live_commit(
    overlay: &WriteOverlay,
    archive: &Path,
    opts: &OpenOptions,
    create_pr: bool,
) -> Result<(), String> {
    let url = archive.to_string_lossy().into_owned();
    match live_remote_kind(&url) {
        LiveRemote::Local => {}
        LiveRemote::Hf => install_hf_live_commit(overlay, &url, opts, create_pr)?,
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
    Ok(())
}

const S3_PUT_SINGLE_MAX: u64 = 8 * 1024 * 1024;

struct HfLiveCommit {
    repo: ratarmount_remote::HfRepo,
    revision: String,
    create_pr: bool,
    refused: bool,
}

impl HfLiveCommit {
    fn ready(&self) -> Result<(), OverlayError> {
        if self.refused {
            Err(OverlayError::Msg(
                "hf live commit disabled; remount required after a conflict or uncertain publication"
                    .into(),
            ))
        } else {
            Ok(())
        }
    }
}

fn install_hf_live_commit(
    overlay: &WriteOverlay,
    url: &str,
    opts: &OpenOptions,
    create_pr: bool,
) -> Result<(), String> {
    let mut repo = ratarmount_remote::HfRepo::resolve(url).map_err(|e| e.to_string())?;
    let revision = repo.live_commit_branch().map_err(|e| e.to_string())?;
    // The branch may have moved since the factory opened the base. Never adopt that push.
    let root = overlay.lookup("/", 0).ok_or("Hub mount has no root")?;
    let pinned = overlay
        .get_xattr(&root, "user.hf.commit")
        .ok_or("Hub mount has no pinned commit identity")?;
    repo.commit = String::from_utf8(pinned).map_err(|_| "invalid Hub mount commit identity")?;
    let state = Arc::new(std::sync::Mutex::new(HfLiveCommit {
        repo,
        revision,
        create_pr,
        refused: false,
    }));
    let head = state.clone();
    let download = state.clone();
    let publish = state.clone();
    let opts_pub = opts.clone();
    overlay.install_remote_live_commit_for(
        url,
        Box::new(move || {
            let mut state = head.lock().expect("hf live commit");
            state.ready()?;
            let current = state.repo.at_revision(&state.revision)
                .map_err(|e| OverlayError::Msg(e.to_string()))?;
            if current.commit != state.repo.commit {
                state.refused = true;
                log::error!("hf branch changed since the pinned commit; further commits refused; remount required");
                return Err(OverlayError::Msg("hf branch changed; remount required".into()));
            }
            let range = state.repo.open_file(&state.repo.location.path)
                .map_err(|e| OverlayError::Msg(e.to_string()))?;
            Ok(RemoteObjectHead { etag: Some(state.repo.commit.clone()), len: range.len() })
        }),
        Box::new(move || {
            let state = download.lock().expect("hf live commit");
            state.ready()?;
            let mut range = state.repo.open_file(&state.repo.location.path)
                .map_err(|e| OverlayError::Msg(e.to_string()))?;
            let mut file = tempfile::NamedTempFile::new()?;
            let len = std::io::copy(&mut range, &mut file)?;
            if len != range.len() {
                return Err(OverlayError::Msg("short Hub archive download".into()));
            }
            Ok(RemoteDownload { file, len })
        }),
        Box::new(move |request| {
            let mut state = publish.lock().expect("hf live commit");
            publish_hf(&mut state, &opts_pub, request)
        }),
        Duration::from_secs(300),
    );
    let opts = opts.clone();
    overlay.install_remote_reopen(Box::new(move || {
        let state = state.lock().expect("hf live commit");
        state.ready()?;
        reopen_hf_mount(&state.repo, &opts)
    }));
    Ok(())
}

/// The staged `.tar.zst`'s `zstdblocks` pairs, read through a managed reader
/// (the staged file may be open as a database in this process; a raw `File`
/// close would release that connection's locks).
fn staged_zstd_blocks(staged: &Path) -> Result<Vec<(i64, i64)>, String> {
    let mut cursor = ratarmount_index::managed_read::ManagedReadCursor::open(staged)
        .map_err(|e| e.to_string())?;
    let blocks = ratarmount_compress::export_zstd_blocks_from_reader(&mut cursor)
        .map_err(|e| e.to_string())?;
    Ok(blocks
        .into_iter()
        .map(|(c, d)| (c as i64, d as i64))
        .collect())
}

fn publish_hf(
    state: &mut HfLiveCommit,
    opts: &OpenOptions,
    req: &RemotePublishRequest,
) -> Result<(), RemotePublishError> {
    let retryable = RemotePublishError::Retryable;
    state.ready().map_err(|e| retryable(e.to_string()))?;
    if req.etag_at_download.as_deref() != Some(&state.repo.commit) || req.skip_object_put {
        state.refused = true;
        return Err(retryable(
            "Hub archive parent changed; remount required".into(),
        ));
    }
    // Build a fresh snapshot without mutating the index still used by the pinned base.
    // Even :memory: mounts publish all three names, and a failed upload leaves the old index usable.
    let dir = tempfile::tempdir().map_err(|e| retryable(e.to_string()))?;
    let sidecar = dir.path().join("index.sqlite");
    let mut index_opts = opts.clone();
    index_opts.index_in_memory = false;
    index_opts.index_file_path = Some(sidecar.clone());
    index_opts.write_index = true;
    index_opts.read_only_index = false;
    index_opts.ignore_zeros = true;
    let source = match detect_compression(&req.staged).map_err(|e| retryable(e.to_string()))? {
        CompressionFormat::Zstd => {
            let body = open_seekable_zstd_with_threads(&req.staged, opts.threads_for("zstd"))
                .map_err(|e| retryable(e.to_string()))?;
            SqliteIndexedTar::create_index_body(
                &req.staged,
                body,
                Some(&sidecar),
                &index_opts,
                env!("CARGO_PKG_VERSION"),
            )
        }
        _ => SqliteIndexedTar::create_index(
            &req.staged,
            &req.staged,
            Some(&sidecar),
            &index_opts,
            env!("CARGO_PKG_VERSION"),
            &mut None,
        ),
    }
    .map_err(|e| retryable(e.to_string()))?;
    drop(source);
    let index = SqliteIndex::open_writable(&sidecar).map_err(|e| retryable(e.to_string()))?;
    index
        .store_tarstats_for_path(&req.staged)
        .map_err(|e| retryable(e.to_string()))?;
    if url_is_tar_zst(&state.repo.location.path) {
        let blocks = staged_zstd_blocks(&req.staged).map_err(retryable)?;
        index
            .set_zstd_blocks(&blocks)
            .map_err(|e| retryable(e.to_string()))?;
    }
    index
        .wal_checkpoint_truncate()
        .map_err(|e| retryable(e.to_string()))?;
    drop(index);
    if std::fs::metadata(&sidecar)
        .map_err(|e| retryable(e.to_string()))?
        .len()
        > META_SIDECAR_WHOLE_MAX
    {
        return Err(retryable(format!("Hub index exceeds publication limit ({META_SIDECAR_WHOLE_MAX} bytes); archive was not committed")));
    }
    let pointer = IndexPointer::for_blob(&sidecar, Some(&req.staged))
        .map_err(|e| retryable(e.to_string()))?;
    let json = index_pointer_to_json(&pointer).map_err(|e| retryable(e.to_string()))?;
    // Managed (#151): the sidecar is the mount's own index.
    let blob =
        ratarmount_index::managed_read::read(&sidecar).map_err(|e| retryable(e.to_string()))?;
    let blob_path = format!(
        "{}.index.{}.sqlite",
        state.repo.location.path, pointer.index_id
    );
    let pointer_path = format!("{}.index.ptr", state.repo.location.path);
    // A lost response can hide a successful commit/PR. Refuse all later writes until remount.
    state.refused = true;
    let result = state
        .repo
        .commit_archive(
            &req.staged,
            &[
                ratarmount_remote::HfCommitFile {
                    path: &blob_path,
                    content: &blob,
                },
                ratarmount_remote::HfCommitFile {
                    path: &pointer_path,
                    content: json.as_bytes(),
                },
            ],
            &state.revision,
            state.create_pr,
            &state.repo.commit,
        )
        .map_err(|e| {
            log::error!("hf atomic commit failed; further commits refused; remount required: {e}");
            retryable(e.to_string())
        })?;
    state.repo.commit = result.commit;
    if state.create_pr {
        let number = result
            .pull_request_url
            .as_deref()
            .and_then(|url| url.trim_end_matches('/').rsplit('/').next())
            .and_then(|n| n.parse::<u64>().ok())
            .ok_or_else(|| {
                retryable(
                    "Hub commit succeeded but returned no PR identity; remount required".into(),
                )
            })?;
        state.revision = format!("refs/pr/{number}");
        state.create_pr = false;
        log::info!("hf live commit continues on {}", state.revision);
    }
    state.refused = false;
    log::info!(
        "hf archive and index committed atomically at {}",
        state.repo.commit
    );
    Ok(())
}

fn reopen_hf_mount(
    repo: &ratarmount_remote::HfRepo,
    opts: &OpenOptions,
) -> Result<Arc<dyn MountSource>, OverlayError> {
    let range = repo
        .open_file(&repo.location.path)
        .map_err(|e| OverlayError::Msg(e.to_string()))?;
    let label = PathBuf::from(repo.resolve_url(&repo.location.path));
    let mut o = opts.clone();
    o.index_in_memory = true;
    o.index_file_path = None;
    o.write_index = false;
    o.ignore_zeros = true;
    let tar = if url_is_tar_zst(&repo.location.path) {
        let body = ratarmount_compress::open_seekable_zstd_with_threads_from_reader(
            range,
            o.threads_for("zstd"),
            &label,
        )
        .map_err(|e| OverlayError::Msg(e.to_string()))?;
        SqliteIndexedTar::create_index_body(&label, body, None, &o, env!("CARGO_PKG_VERSION"))
    } else {
        SqliteIndexedTar::open_from_reader(range, &label, None, &o, env!("CARGO_PKG_VERSION"))
    }
    .map_err(|e| OverlayError::Msg(e.to_string()))?;
    Ok(Arc::new(ratarmount_remote::HfMountSource::new(
        Arc::new(tar),
        repo.commit.clone(),
    )))
}

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
            // Managed (#151): the staged archive may be a database open here.
            let body = ratarmount_index::managed_read::read(&req.staged)
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
    // Managed (#151): the sidecar is the mount's own index.
    let blob = match ratarmount_index::managed_read::read(&sidecar) {
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
        Ok(true) => eprintln!(
            "committed write overlay into {}",
            ov.commit_archive_path(path).display()
        ),
        Ok(false) => log::debug!("on-exit overlay commit: nothing to do"),
        Err(e) => eprintln!("error: on-exit overlay commit failed: {e}"),
    }
}

#[cfg(test)]
pub(crate) fn set_term_flag_for_test(v: bool) {
    GOT_TERM.store(v, Ordering::SeqCst);
}

/// Zero all three termination statics. Callers hold [`term_flag_test_lock`].
#[cfg(test)]
pub(crate) fn reset_term_state_for_test() {
    GOT_TERM.store(false, Ordering::SeqCst);
    TERM_SIGNAL.store(0, Ordering::SeqCst);
    TERM_COUNT.store(0, Ordering::SeqCst);
}

/// Serializes tests that flip [`GOT_TERM`]. The flag is process-global.
#[cfg(test)]
pub(crate) fn term_flag_test_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    &LOCK
}

#[cfg(test)]
mod tests {
    /// A refused interval commit is retried every tick; it logs once per
    /// distinct message (a new observed stamp is new information) and again
    /// after a success.
    #[test]
    fn regression_interval_refusal_logs_once_per_distinct_message() {
        let mut failures = RepeatedFailure::default();
        assert!(failures.is_new("base mismatch: size=1"));
        assert!(!failures.is_new("base mismatch: size=1"));
        assert!(failures.is_new("base mismatch: size=2"));
        failures.clear();
        assert!(failures.is_new("base mismatch: size=2"));
    }

    use super::*;

    /// Regression: hf commit URLs must not be stat-ed as local filenames.
    #[test]
    fn regression_hf_commit_url_is_remote_and_offline_refused() {
        let archive = std::path::PathBuf::from("hf://datasets/org/data/a.tar.zst");
        let got = super::validate_live_commit_args(
            Some(std::path::Path::new("overlay")),
            std::slice::from_ref(&archive),
        )
        .unwrap();
        assert_eq!(got, archive);
        assert!(super::offline_remote_commit_error(&archive)
            .unwrap()
            .contains("offline --commit-overlay does not upload"));
    }

    fn hf_test_archive(compressed: bool) -> Vec<u8> {
        let tar = crate::publish_index::tests::publish_tar();
        if compressed {
            ratarmount_compress::encode_zstd_frame(&tar, 3).unwrap()
        } else {
            tar
        }
    }

    fn hf_test_overlay(url: &str, root: &Path, create_pr: bool) -> WriteOverlay {
        let repo = ratarmount_remote::HfRepo::resolve(url).unwrap();
        let opts = OpenOptions {
            index_in_memory: true,
            ..Default::default()
        };
        let base = reopen_hf_mount(&repo, &opts).unwrap();
        let overlay = crate::base_identity::fixtures::new_overlay(base, root).unwrap();
        install_object_store_live_commit(&overlay, Path::new(url), &opts, create_pr).unwrap();
        overlay
    }

    fn hf_test_tick(overlay: &WriteOverlay, url: &str) -> Result<CommitOutcome, OverlayError> {
        overlay.enqueue_commit(
            Path::new(url),
            CommitKind::IntervalIdle(Duration::ZERO),
            |_| overlay.reopen_remote_live_commit(),
        )
    }

    /// Regression: the production interval thread still refused hf:// after a successful publication.
    #[test]
    fn regression_hf_live_interval_thread_keeps_serving() {
        use crate::publish_index::tests::{PublishEnv, PublishServer};
        let _term = term_flag_test_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let server = PublishServer::live(hf_test_archive(true));
        let _env = PublishEnv::new(&[
            ("HF_ENDPOINT", &server.url),
            ("HF_TOKEN", "hf-test"),
            ("HF_HUB_OFFLINE", "0"),
            ("RATARMOUNT_HF_SHARE_CACHE", "0"),
            ("RATARMOUNT_PAYLOAD_CACHE_BYTES", "0"),
        ]);
        let url = "hf://datasets/org/data@main/a.tar.zst";
        let overlay = Arc::new(hf_test_overlay(url, &dir.path().join("ov"), false));
        std::fs::write(overlay.root().join("interval.txt"), b"interval output").unwrap();
        set_term_flag_for_test(false);
        let handle = spawn_interval_commits(
            overlay.clone(),
            PathBuf::from(url),
            Duration::from_millis(1),
            None,
            OpenOptions::default(),
        );
        let start = Instant::now();
        while overlay.commit_generation() == 0 && start.elapsed() < Duration::from_secs(10) {
            thread::sleep(Duration::from_millis(10));
        }
        set_term_flag_for_test(true);
        let joined = handle.join();
        set_term_flag_for_test(false);
        joined.unwrap();
        assert_eq!(overlay.commit_generation(), 1, "interval did not publish");
        let fi = overlay.lookup("/interval.txt", 0).unwrap();
        assert_eq!(overlay.read(&fi, 100, 0).unwrap(), b"interval output");
        assert!(!overlay.root().join("interval.txt").exists());
    }

    /// Regression: an interval published an archive without its matching index, or kept serving old bytes.
    #[test]
    fn regression_hf_live_atomic_archive_index_pointer_and_repinned_reads() {
        use crate::publish_index::tests::{PublishEnv, PublishServer};
        for compressed in [false, true] {
            if !compressed
                && !["gtar", "gnutar", "tar"].iter().any(|name| {
                    std::process::Command::new(name)
                        .arg("--version")
                        .output()
                        .is_ok_and(|out| String::from_utf8_lossy(&out.stdout).contains("GNU tar"))
                })
            {
                eprintln!("skip: GNU tar unavailable; tar.zst core regression still runs");
                continue;
            }
            let dir = tempfile::tempdir().unwrap();
            let server = PublishServer::live(hf_test_archive(compressed));
            let _env = PublishEnv::new(&[
                ("HF_ENDPOINT", &server.url),
                ("HF_TOKEN", "hf-test"),
                ("HF_HUB_OFFLINE", "0"),
                ("RATARMOUNT_HF_SHARE_CACHE", "0"),
                ("RATARMOUNT_PAYLOAD_CACHE_BYTES", "0"),
                ("XDG_CACHE_HOME", dir.path().join("cache").to_str().unwrap()),
                (
                    "RATARMOUNT_HF_TREE_CACHE",
                    dir.path().join("trees").to_str().unwrap(),
                ),
            ]);
            let name = if compressed { "a.tar.zst" } else { "a.tar" };
            let url = format!("hf://datasets/org/data@main/{name}");
            let overlay = hf_test_overlay(&url, &dir.path().join("ov"), false);
            std::fs::write(overlay.root().join("hello.txt"), b"new bytes after commit").unwrap();
            assert_eq!(
                hf_test_tick(&overlay, &url).unwrap(),
                CommitOutcome::DidWork
            );
            assert!(!overlay.root().join("hello.txt").exists());
            let root = overlay.lookup("/", 0).unwrap();
            assert_eq!(
                overlay.get_xattr(&root, "user.hf.commit"),
                Some("b".repeat(40).into_bytes())
            );
            let fi = overlay.lookup("/hello.txt", 0).unwrap();
            assert_eq!(
                overlay.read(&fi, 100, 0).unwrap(),
                b"new bytes after commit"
            );
            {
                let state = server.state.lock().unwrap();
                let commits: Vec<_> = state
                    .requests
                    .iter()
                    .filter(|(_, p, _)| p.contains("/commit/"))
                    .collect();
                assert_eq!(commits.len(), 1);
                let ops: Vec<serde_json::Value> = std::str::from_utf8(&commits[0].2)
                    .unwrap()
                    .lines()
                    .map(|l| serde_json::from_str(l).unwrap())
                    .collect();
                assert_eq!(ops[0]["value"]["parentCommit"], "a".repeat(40));
                assert_eq!(ops[1]["key"], "lfsFile");
                assert_eq!(ops[1]["value"]["path"], name);
                let ptr: serde_json::Value =
                    serde_json::from_slice(&state.objects[&format!("{name}.index.ptr")]).unwrap();
                let blob = &state.objects
                    [&format!("{name}.index.{}.sqlite", ptr["index_id"].as_str().unwrap())];
                assert_eq!(ptr["index_id"], ratarmount_index::sha256_hex(blob));
                let archive = dir.path().join(name);
                let index = dir.path().join("published.sqlite");
                std::fs::write(&archive, &state.objects[name]).unwrap();
                std::fs::write(&index, blob).unwrap();
                let idx = SqliteIndex::open_read_only(&index).unwrap();
                let actual = ratarmount_index::tar_stats_from_path(&archive).unwrap();
                ratarmount_index::check_tarstats_matches_remote(
                    &idx.tarstats().unwrap().unwrap(),
                    actual.st_size,
                    actual.prefix512_sha256.as_deref(),
                    actual.suffix512_sha256.as_deref(),
                    actual.full_sha256.as_deref(),
                )
                .unwrap();
                if compressed {
                    assert!(!idx.get_zstd_blocks().unwrap().is_empty());
                }
            }
            let scans = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let bundle = crate::publish_index::tests::build_publish_index(
                &url,
                &dir.path().join("discovered.sqlite"),
                scans.clone(),
            );
            assert_eq!(
                scans.load(Ordering::Relaxed),
                0,
                "fresh remote index should avoid a rebuild"
            );
            let fi = bundle.source.lookup("/hello.txt", 0).unwrap();
            assert_eq!(
                bundle.source.read(&fi, 100, 0).unwrap(),
                b"new bytes after commit"
            );
            drop(bundle);
            // The next commit must use the previous result, never the mount's original SHA.
            std::fs::write(overlay.root().join("second.txt"), b"second commit").unwrap();
            assert_eq!(
                hf_test_tick(&overlay, &url).unwrap(),
                CommitOutcome::DidWork
            );
            let fi = overlay.lookup("/second.txt", 0).unwrap();
            assert_eq!(overlay.read(&fi, 100, 0).unwrap(), b"second commit");
            let state = server.state.lock().unwrap();
            let last = state
                .requests
                .iter()
                .rfind(|(_, p, _)| p.contains("/commit/"))
                .unwrap();
            let header: serde_json::Value = serde_json::from_str(
                std::str::from_utf8(&last.2)
                    .unwrap()
                    .lines()
                    .next()
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(header["value"]["parentCommit"], "b".repeat(40));
        }
    }

    /// Regression: a concurrent parent update or lost commit response must never be retried or clobbered.
    #[test]
    fn regression_hf_live_parent_conflict_and_uncertain_response_stop_commits() {
        use crate::publish_index::tests::{PublishEnv, PublishServer};
        for failure in [
            "during-setup",
            "before-download",
            "at-commit",
            "lost-response",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let archive = hf_test_archive(true);
            let server = PublishServer::live(archive.clone());
            let _env = PublishEnv::new(&[
                ("HF_ENDPOINT", &server.url),
                ("HF_TOKEN", "hf-test"),
                ("HF_HUB_OFFLINE", "0"),
                ("RATARMOUNT_HF_SHARE_CACHE", "0"),
                ("RATARMOUNT_PAYLOAD_CACHE_BYTES", "0"),
            ]);
            let url = "hf://datasets/org/data@main/a.tar.zst";
            let overlay = if failure == "during-setup" {
                let repo = ratarmount_remote::HfRepo::resolve(url).unwrap();
                let opts = OpenOptions {
                    index_in_memory: true,
                    ..Default::default()
                };
                let base = reopen_hf_mount(&repo, &opts).unwrap();
                let overlay =
                    crate::base_identity::fixtures::new_overlay(base, dir.path().join("ov"))
                        .unwrap();
                server.state.lock().unwrap().head = "f".repeat(40);
                install_object_store_live_commit(&overlay, Path::new(url), &opts, false).unwrap();
                overlay
            } else {
                hf_test_overlay(url, &dir.path().join("ov"), false)
            };
            std::fs::write(overlay.root().join("new.txt"), b"keep on failure").unwrap();
            {
                let mut state = server.state.lock().unwrap();
                match failure {
                    "before-download" => state.head = "f".repeat(40),
                    "at-commit" => state.conflict_on_commit = true,
                    "lost-response" => state.fail_commit_response = true,
                    _ => {}
                }
            }
            let err = hf_test_tick(&overlay, url).unwrap_err().to_string();
            assert!(!err.contains("hf-test"), "token leaked: {err}");
            assert!(overlay.root().join("new.txt").exists());
            let requests = server.state.lock().unwrap().requests.len();
            let err = hf_test_tick(&overlay, url).unwrap_err().to_string();
            assert!(err.contains("remount required"), "{err}");
            assert_eq!(
                requests,
                server.state.lock().unwrap().requests.len(),
                "a refused mount must make no more requests"
            );
            assert!(overlay
                .enqueue_commit(Path::new(url), CommitKind::OnExit, |_| unreachable!())
                .is_err());
            let state = server.state.lock().unwrap();
            if failure != "lost-response" {
                assert_eq!(state.objects["a.tar.zst"], archive);
                assert!(!state.objects.contains_key("a.tar.zst.index.ptr"));
            }
        }
    }

    /// Regression: verbose live publication logs exposed the write token or a Hub error body.
    #[test]
    fn regression_hf_live_logs_do_not_contain_token() {
        use crate::publish_index::tests::{PublishEnv, PublishServer};
        struct Writer {
            owner: thread::ThreadId,
            bytes: Arc<std::sync::Mutex<Vec<u8>>>,
        }
        impl std::io::Write for Writer {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if thread::current().id() == self.owner {
                    self.bytes.lock().unwrap().extend_from_slice(bytes);
                }
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let bytes = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut builder = env_logger::Builder::new();
        builder.parse_filters("debug,ureq::unit=trace");
        crate::configure_http_logging(&mut builder);
        builder.target(env_logger::Target::Pipe(Box::new(Writer {
            owner: thread::current().id(),
            bytes: bytes.clone(),
        })));
        log::set_boxed_logger(Box::new(builder.build())).expect("install live Hub test logger");
        log::set_max_level(log::LevelFilter::Debug);
        let dir = tempfile::tempdir().unwrap();
        let server = PublishServer::live(hf_test_archive(true));
        let _env = PublishEnv::new(&[
            ("HF_ENDPOINT", &server.url),
            ("HF_TOKEN", "hf-test"),
            ("HF_HUB_OFFLINE", "0"),
            ("RATARMOUNT_HF_SHARE_CACHE", "0"),
            ("RATARMOUNT_PAYLOAD_CACHE_BYTES", "0"),
        ]);
        let url = "hf://datasets/org/data@main/a.tar.zst";
        let overlay = hf_test_overlay(url, &dir.path().join("ov"), false);
        std::fs::write(overlay.root().join("secret.txt"), b"output").unwrap();
        server.state.lock().unwrap().conflict_on_commit = true;
        assert!(hf_test_tick(&overlay, url).is_err());
        let logs = String::from_utf8(bytes.lock().unwrap().clone()).unwrap();
        assert!(logs.contains("further commits refused"), "{logs}");
        assert!(!logs.contains("hf-test"), "token leaked: {logs}");
        assert!(
            !logs.contains("must never appear"),
            "Hub response body leaked: {logs}"
        );
    }

    /// Regression: --create-pr opened a fresh PR on every interval instead of continuing on its ref.
    #[test]
    fn regression_hf_live_create_pr_continues_same_pr_with_parent() {
        use crate::publish_index::tests::{PublishEnv, PublishServer};
        let dir = tempfile::tempdir().unwrap();
        let server = PublishServer::live(hf_test_archive(true));
        let _env = PublishEnv::new(&[
            ("HF_ENDPOINT", &server.url),
            ("HF_TOKEN", "hf-test"),
            ("HF_HUB_OFFLINE", "0"),
            ("RATARMOUNT_HF_SHARE_CACHE", "0"),
            ("RATARMOUNT_PAYLOAD_CACHE_BYTES", "0"),
        ]);
        let url = "hf://datasets/org/data@dev/a.tar.zst";
        let overlay = hf_test_overlay(url, &dir.path().join("ov"), true);
        for name in ["first.txt", "second.txt"] {
            std::fs::write(overlay.root().join(name), name).unwrap();
            assert_eq!(hf_test_tick(&overlay, url).unwrap(), CommitOutcome::DidWork);
        }
        let state = server.state.lock().unwrap();
        let commits: Vec<_> = state
            .requests
            .iter()
            .filter(|(_, p, _)| p.contains("/commit/"))
            .collect();
        assert!(commits[0].1.ends_with("/dev?create_pr=1"));
        assert!(commits[1].1.ends_with("/refs%2Fpr%2F7"));
        assert!(!commits[1].1.contains("create_pr"));
        assert_eq!(
            state.head,
            "a".repeat(40),
            "PR must not change mounted branch"
        );
    }

    /// Regression: SHA/tag mounts silently targeted main, or --create-pr was rejected for live Hub writes.
    #[test]
    fn regression_hf_live_branch_revision_and_create_pr_options() {
        use crate::publish_index::tests::{PublishEnv, PublishServer};
        let server = PublishServer::live(hf_test_archive(true));
        let _env = PublishEnv::new(&[
            ("HF_ENDPOINT", &server.url),
            ("HF_TOKEN", "hf-test"),
            ("HF_HUB_OFFLINE", "0"),
            ("RATARMOUNT_HF_SHARE_CACHE", "0"),
        ]);
        for revision in ["main", "dev", "v1", &"a".repeat(40)] {
            let repo = ratarmount_remote::HfRepo::resolve(&format!(
                "hf://datasets/org/data@{revision}/a.tar.zst"
            ))
            .unwrap();
            let result = repo.live_commit_branch();
            assert_eq!(result.is_ok(), revision == "main" || revision == "dev");
            if let Err(error) = result {
                assert!(error.to_string().contains("branch revision"));
            }
        }
        let input = [PathBuf::from("hf://datasets/org/data@main/a.tar.zst")];
        assert!(live_hf_create_pr(&input, "1s", false, true));
        assert!(live_hf_create_pr(&input, "0", true, true));
        assert!(!live_hf_create_pr(&input, "0", false, true));
        assert!(!live_hf_create_pr(
            &["s3://b/a.tar".into()],
            "1s",
            true,
            true
        ));
    }

    /// Regression: on-exit Hub commits must publish all siblings even with an in-memory mount index.
    #[test]
    fn regression_hf_live_on_exit_atomic_publication() {
        use crate::publish_index::tests::{PublishEnv, PublishServer};
        let dir = tempfile::tempdir().unwrap();
        let server = PublishServer::live(hf_test_archive(true));
        let _env = PublishEnv::new(&[
            ("HF_ENDPOINT", &server.url),
            ("HF_TOKEN", "hf-test"),
            ("HF_HUB_OFFLINE", "0"),
            ("RATARMOUNT_HF_SHARE_CACHE", "0"),
            ("RATARMOUNT_PAYLOAD_CACHE_BYTES", "0"),
        ]);
        let url = "hf://datasets/org/data@main/a.tar.zst";
        let overlay = hf_test_overlay(url, &dir.path().join("ov"), false);
        std::fs::write(overlay.root().join("exit.txt"), b"flush on exit").unwrap();
        assert!(
            apply_live_commit(&overlay, Path::new(url), false, &OpenOptions::default()).unwrap()
        );
        let state = server.state.lock().unwrap();
        assert!(state.objects.contains_key("a.tar.zst.index.ptr"));
        assert_eq!(
            state
                .requests
                .iter()
                .filter(|(_, p, _)| p.contains("/commit/"))
                .count(),
            1
        );
    }

    /// Regression: real Hub write-back must keep the mount readable at its newly committed SHA.
    #[test]
    #[ignore = "writes archive and sidecars to RATARMOUNT_TEST_HF_REPO; requires a write-scoped token"]
    fn regression_hf_live_private_repo_writeback() {
        let Ok(repo_id) = std::env::var("RATARMOUNT_TEST_HF_REPO") else {
            eprintln!("skip: set RATARMOUNT_TEST_HF_REPO=org/private-test-repo and HF_TOKEN");
            return;
        };
        if !["HF_TOKEN", "HUGGING_FACE_HUB_TOKEN"].iter().any(|key| {
            std::env::var(key)
                .ok()
                .is_some_and(|v| !v.trim().is_empty())
        }) {
            eprintln!("skip: live Hub write-back requires an explicit write-scoped HF_TOKEN");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let name = format!(
            "ratarmount-tests/hfw-{}.tar.zst",
            dir.path().file_name().unwrap().to_string_lossy()
        );
        let url = format!("hf://datasets/{repo_id}@main/{name}");
        let repo = ratarmount_remote::HfRepo::resolve(&url).unwrap();
        let archive = hf_test_archive(true);
        repo.commit_files(
            &[ratarmount_remote::HfCommitFile {
                path: &name,
                content: &archive,
            }],
            Some("main"),
            false,
            Some(&repo.commit),
        )
        .unwrap();
        let overlay = hf_test_overlay(&url, &dir.path().join("ov"), false);
        std::fs::write(
            overlay.root().join("live.txt"),
            b"private Hub overlay output",
        )
        .unwrap();
        assert_eq!(
            hf_test_tick(&overlay, &url).unwrap(),
            CommitOutcome::DidWork
        );
        let fi = overlay.lookup("/live.txt", 0).unwrap();
        assert_eq!(
            overlay.read(&fi, 100, 0).unwrap(),
            b"private Hub overlay output"
        );
        let repo = ratarmount_remote::HfRepo::resolve(&url).unwrap();
        let pointer_url = repo.resolve_url(&format!("{name}.index.ptr"));
        let bytes = repo.fetch_bytes(&pointer_url, 64 * 1024).unwrap();
        let pointer =
            ratarmount_index::parse_index_pointer_json(std::str::from_utf8(&bytes).unwrap())
                .unwrap();
        let blob = repo
            .fetch_bytes(
                &repo.resolve_url(&format!("{name}.index.{}.sqlite", pointer.index_id)),
                META_SIDECAR_WHOLE_MAX,
            )
            .unwrap();
        assert_eq!(ratarmount_index::sha256_hex(&blob), pointer.index_id);
        eprintln!(
            "live write-back retained test archive and sidecars at {url}, commit {}",
            repo.commit
        );
    }

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

    fn busy() -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::ResourceBusy, "busy")
    }

    /// Records the order of unmount/lazy calls.
    fn run_signal_unmount(
        signal: Option<libc::c_int>,
        unmount: fn() -> std::io::Result<()>,
        lazy: fn() -> std::io::Result<()>,
    ) -> (SignalUnmountOutcome, Vec<&'static str>) {
        let calls = std::cell::RefCell::new(Vec::new());
        let out = signal_unmount(
            Path::new("/m"),
            signal,
            &|_| {
                calls.borrow_mut().push("unmount");
                unmount()
            },
            &|_| {
                calls.borrow_mut().push("lazy");
                lazy()
            },
        );
        (out, calls.into_inner())
    }

    /// Regression: SIGTERM on a still-busy mount unmounted once, ignored the error and left it.
    #[test]
    fn regression_sigterm_busy_falls_back_to_lazy() {
        let (out, calls) = run_signal_unmount(Some(libc::SIGTERM), || Err(busy()), || Ok(()));
        assert!(matches!(out, SignalUnmountOutcome::LazyFallback), "{out:?}");
        assert_eq!(calls, ["unmount", "lazy"]);
        let (out, calls) = run_signal_unmount(
            Some(libc::SIGTERM),
            || Err(busy()),
            || Err(std::io::Error::other("no")),
        );
        assert!(
            matches!(out, SignalUnmountOutcome::LazyFailed(..)),
            "{out:?}"
        );
        assert_eq!(calls, ["unmount", "lazy"]);
    }

    #[test]
    fn regression_sigterm_not_busy_or_ok_never_lazy() {
        let (out, calls) = run_signal_unmount(
            Some(libc::SIGTERM),
            || Err(std::io::Error::other("not mounted")),
            || Ok(()),
        );
        assert!(matches!(out, SignalUnmountOutcome::Failed(_)), "{out:?}");
        assert_eq!(calls, ["unmount"]);
        let (out, calls) = run_signal_unmount(Some(libc::SIGTERM), || Ok(()), || Ok(()));
        assert!(matches!(out, SignalUnmountOutcome::Unmounted), "{out:?}");
        assert_eq!(calls, ["unmount"]);
    }

    /// SIGINT gets the retrying unmount but never `-z`; a programmatic shutdown does nothing.
    #[test]
    fn regression_sigint_and_programmatic_never_lazy() {
        let (out, calls) = run_signal_unmount(Some(libc::SIGINT), || Err(busy()), || Ok(()));
        assert!(matches!(out, SignalUnmountOutcome::Failed(_)), "{out:?}");
        assert_eq!(calls, ["unmount"]);
        let (out, calls) = run_signal_unmount(None, || Err(busy()), || Ok(()));
        assert!(matches!(out, SignalUnmountOutcome::Skipped), "{out:?}");
        assert!(calls.is_empty());
    }

    fn watcher_thread(
        count: Arc<AtomicUsize>,
        signal: Arc<AtomicI32>,
        flagged: Arc<AtomicBool>,
        calls: Arc<std::sync::Mutex<Vec<&'static str>>>,
    ) -> std::sync::mpsc::Receiver<()> {
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let c = Arc::clone(&calls);
            let l = Arc::clone(&calls);
            signal_unmount_watcher(
                Path::new("/m"),
                &|| {
                    let n = count.load(Ordering::SeqCst);
                    let s = signal.load(Ordering::SeqCst);
                    TermState {
                        count: n,
                        signal: (s != 0).then_some(s),
                        flagged: flagged.load(Ordering::SeqCst),
                    }
                },
                &move |_| {
                    c.lock().unwrap().push("unmount");
                    Err(busy())
                },
                &move |_| {
                    l.lock().unwrap().push("lazy");
                    Ok(())
                },
                Duration::from_millis(2),
            );
            let _ = tx.send(());
        });
        rx
    }

    /// Regression: a failed SIGINT attempt must not end the watcher; a later SIGTERM still
    /// reaches the lazy fallback.
    #[test]
    fn regression_signal_watcher_survives_failed_attempt() {
        let count = Arc::new(AtomicUsize::new(0));
        let signal = Arc::new(AtomicI32::new(0));
        let flagged = Arc::new(AtomicBool::new(false));
        let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
        let done = watcher_thread(
            Arc::clone(&count),
            Arc::clone(&signal),
            Arc::clone(&flagged),
            Arc::clone(&calls),
        );
        signal.store(libc::SIGINT, Ordering::SeqCst);
        count.store(1, Ordering::SeqCst);
        flagged.store(true, Ordering::SeqCst);
        thread::sleep(Duration::from_millis(100));
        assert!(
            done.try_recv().is_err(),
            "watcher exited after a failed SIGINT"
        );
        assert_eq!(*calls.lock().unwrap(), ["unmount"]);
        signal.store(libc::SIGTERM, Ordering::SeqCst);
        count.store(2, Ordering::SeqCst);
        done.recv_timeout(Duration::from_secs(5))
            .expect("watcher ends after SIGTERM");
        assert_eq!(*calls.lock().unwrap(), ["unmount", "unmount", "lazy"]);
    }

    /// Programmatic `request_shutdown` (flag, no signal) ends the watcher without unmounting.
    #[test]
    fn regression_signal_watcher_programmatic_shutdown_does_nothing() {
        let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
        let done = watcher_thread(
            Arc::new(AtomicUsize::new(0)),
            Arc::new(AtomicI32::new(0)),
            Arc::new(AtomicBool::new(true)),
            Arc::clone(&calls),
        );
        done.recv_timeout(Duration::from_secs(5))
            .expect("watcher ends");
        assert!(calls.lock().unwrap().is_empty());
    }

    /// Regression: a SIGTERM landing between the watcher's separate reads gave
    /// `{count: 0, signal: SIGTERM, flagged: true}`; the watcher took the programmatic-shutdown
    /// exit and dropped the signal. A recorded signal must always be handled.
    #[test]
    fn regression_signal_watcher_torn_snapshot_still_unmounts() {
        let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
        let done = watcher_thread(
            Arc::new(AtomicUsize::new(0)),
            Arc::new(AtomicI32::new(libc::SIGTERM)),
            Arc::new(AtomicBool::new(true)),
            Arc::clone(&calls),
        );
        done.recv_timeout(Duration::from_secs(5))
            .expect("watcher ends");
        assert_eq!(*calls.lock().unwrap(), ["unmount", "lazy"]);
    }

    /// Resets the process-global termination statics when dropped.
    struct ResetTermState;

    impl Drop for ResetTermState {
        fn drop(&mut self) {
            reset_term_state_for_test();
        }
    }

    /// Regression (mutants `on_term_signal -> ()`, `signal != 0` -> `==`): the real handler and
    /// the real snapshot must agree. Already passes on 3681863; it pins the pair.
    #[test]
    fn regression_term_state_follows_handler() {
        let _lock = term_flag_test_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _reset = ResetTermState;
        reset_term_state_for_test();
        let st = term_state();
        assert_eq!((st.count, st.signal, st.flagged), (0, None, false));
        request_shutdown();
        let st = term_state();
        assert_eq!((st.count, st.signal, st.flagged), (0, None, true));
        reset_term_state_for_test();
        on_term_signal(libc::SIGTERM);
        let st = term_state();
        assert_eq!(
            (st.count, st.signal, st.flagged),
            (1, Some(libc::SIGTERM), true)
        );
        on_term_signal(libc::SIGINT);
        let st = term_state();
        assert_eq!(
            (st.count, st.signal, st.flagged),
            (2, Some(libc::SIGINT), true)
        );
    }

    type Results = Arc<std::sync::Mutex<std::collections::VecDeque<std::io::Result<()>>>>;

    fn results(items: Vec<std::io::Result<()>>) -> Results {
        Arc::new(std::sync::Mutex::new(items.into()))
    }

    /// Watcher whose unmount/lazy results are scripted. Returns (done, calls).
    #[allow(clippy::type_complexity)]
    fn scripted_watcher(
        count: Arc<AtomicUsize>,
        signal: Arc<AtomicI32>,
        unmount_results: Results,
        lazy_results: Results,
    ) -> (
        std::sync::mpsc::Receiver<()>,
        Arc<std::sync::Mutex<Vec<&'static str>>>,
    ) {
        let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (tx, rx) = std::sync::mpsc::channel();
        let (c, l) = (Arc::clone(&calls), Arc::clone(&calls));
        thread::spawn(move || {
            signal_unmount_watcher(
                Path::new("/m"),
                &|| {
                    let n = count.load(Ordering::SeqCst);
                    let s = signal.load(Ordering::SeqCst);
                    TermState {
                        count: n,
                        signal: (s != 0).then_some(s),
                        flagged: n > 0,
                    }
                },
                &move |_| {
                    c.lock().unwrap().push("unmount");
                    unmount_results
                        .lock()
                        .unwrap()
                        .pop_front()
                        .unwrap_or(Ok(()))
                },
                &move |_| {
                    l.lock().unwrap().push("lazy");
                    lazy_results.lock().unwrap().pop_front().unwrap_or(Ok(()))
                },
                Duration::from_millis(2),
            );
            let _ = tx.send(());
        });
        (rx, calls)
    }

    /// Regression: after a failed lazy fallback the watcher exited, so a later SIGTERM was
    /// ignored although the mount was still being served.
    #[test]
    fn regression_signal_watcher_lazy_failed_keeps_looping() {
        let count = Arc::new(AtomicUsize::new(0));
        let signal = Arc::new(AtomicI32::new(0));
        let (done, calls) = scripted_watcher(
            Arc::clone(&count),
            Arc::clone(&signal),
            results(vec![Err(busy()), Ok(())]),
            results(vec![Err(std::io::Error::other("no"))]),
        );
        signal.store(libc::SIGTERM, Ordering::SeqCst);
        count.store(1, Ordering::SeqCst);
        thread::sleep(Duration::from_millis(200));
        assert_eq!(*calls.lock().unwrap(), ["unmount", "lazy"]);
        count.store(2, Ordering::SeqCst);
        let ended = done.recv_timeout(Duration::from_secs(2)).is_ok();
        assert_eq!(
            *calls.lock().unwrap(),
            ["unmount", "lazy", "unmount"],
            "a second SIGTERM after LazyFailed must retry the unmount"
        );
        assert!(ended, "watcher must end once the retried unmount succeeds");
    }

    /// A successful lazy detach ends the watcher after exactly one lazy call. Already passes on
    /// 3681863; it keeps K2 from looping after a lazy success.
    #[test]
    fn regression_signal_watcher_lazy_fallback_calls_lazy_once() {
        let count = Arc::new(AtomicUsize::new(0));
        let signal = Arc::new(AtomicI32::new(libc::SIGTERM));
        let (done, calls) = scripted_watcher(
            Arc::clone(&count),
            signal,
            results(vec![Err(busy()), Err(busy())]),
            results(vec![Ok(())]),
        );
        count.store(1, Ordering::SeqCst);
        done.recv_timeout(Duration::from_secs(2))
            .expect("watcher ends after the lazy detach");
        thread::sleep(Duration::from_millis(50));
        assert_eq!(*calls.lock().unwrap(), ["unmount", "lazy"]);
    }

    fn write_tiny_tar_zst(path: &std::path::Path) {
        let payload = b"x\n";
        let member = ratarmount_formats_tar::UstarMember {
            xattrs: &[],
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
                xattrs: &[],
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
        let ov = crate::base_identity::fixtures::new_overlay(
            Arc::new(base) as Arc<dyn MountSource>,
            &overlay_dir,
        )
        .unwrap();
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
            crate::base_identity::fixtures::new_overlay(
                Arc::new(base) as Arc<dyn MountSource>,
                &overlay_dir,
            )
            .unwrap(),
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

    /// Regression: Git URLs ending in archive suffixes must reach the Git parser unchanged.
    #[test]
    fn regression_git_url_write_base_is_never_created_as_archive() {
        for url in [
            "git:///srv/repo.tar",
            "git:///srv/repo#branch.tar.zst",
            "git://host/repo.tar",
        ] {
            for context in [
                CreateMissingContext::Mount,
                CreateMissingContext::OfflineCommit,
            ] {
                assert_eq!(
                    maybe_create_missing_write_base(Path::new(url), context).unwrap(),
                    EmptyCreateOutcome::Unchanged
                );
            }
        }
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
                xattrs: &[],
                path: "keep.txt",
                payload: ratarmount_formats_tar::UstarPayload::File { bytes: keep },
                mode: 0o644,
                uid: 0,
                gid: 0,
                mtime: 0,
            },
            ratarmount_formats_tar::UstarMember {
                xattrs: &[],
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
                xattrs: &[],
                path: "keep.txt",
                payload: ratarmount_formats_tar::UstarPayload::File { bytes: other },
                mode: 0o644,
                uid: 0,
                gid: 0,
                mtime: 0,
            },
            ratarmount_formats_tar::UstarMember {
                xattrs: &[],
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
            xattrs: &[],
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

    // ---------------------------------------------------------------------
    // R11-S7 (#151): live-commit publication reads index and archive bytes
    // through managed readers.
    // ---------------------------------------------------------------------

    type Publish = fn(&str, &OpenOptions, &RemotePublishRequest) -> Result<(), RemotePublishError>;

    /// Publish `a.tar` to `{scheme}://bucket/a.tar` while session A keeps the
    /// mount's WAL index open (an idle connection: WAL keeps its main-file
    /// SHARED lock for the connection's life; an open read transaction would
    /// block the sidecar patch's checkpoint). The session's lock survives the
    /// publish, and every managed read of the index and the staged archive
    /// keeps a lock taken on the file it reads.
    #[cfg(unix)]
    fn s7_object_store_publish(scheme: &str, publish: Publish) {
        use crate::publish_index::tests::{publish_tar, PublishEnv, PublishServer};
        use ratarmount_index::managed_read::{
            lock_probe::other_process_sees_lock, with_close_probes,
        };
        let dir = tempfile::tempdir().unwrap();
        let tar = dir.path().join("a.tar");
        std::fs::write(&tar, publish_tar()).unwrap();
        let sidecar = dir.path().join("index.sqlite");
        let mut build = OpenOptions {
            index_file_path: Some(sidecar.clone()),
            ..Default::default()
        };
        drop(
            crate::factory::build_mount_source(
                std::slice::from_ref(&tar),
                &mut build,
                false,
                false,
            )
            .unwrap(),
        );
        let server = PublishServer::new(publish_tar(), false, false);
        let _env = PublishEnv::new(&[
            ("AWS_ACCESS_KEY_ID", "test"),
            ("AWS_SECRET_ACCESS_KEY", "secret"),
            ("AWS_ENDPOINT_URL", &server.url),
            ("AWS_REGION", "us-east-1"),
            ("RATARMOUNT_S3_ANONYMOUS", "0"),
            ("AWS_ANONYMOUS", "0"),
            ("RATARMOUNT_GCS_ENDPOINT", &server.url),
            ("GOOGLE_OAUTH_ACCESS_TOKEN", "test"),
            ("RATARMOUNT_GCS_ANONYMOUS", "0"),
            ("AZURE_STORAGE_ACCOUNT", "test"),
            ("AZURE_STORAGE_KEY", "c2VjcmV0"),
            ("AZURE_STORAGE_ENDPOINT", &server.url),
            ("RATARMOUNT_AZURE_ANONYMOUS", "0"),
        ]);
        let session = rusqlite::Connection::open(&sidecar).unwrap();
        let _: i64 = session
            .query_row("SELECT count(*) FROM files", [], |r| r.get(0))
            .unwrap();
        assert!(
            other_process_sees_lock(&sidecar),
            "an idle WAL connection keeps its main-file lock"
        );
        let stats = ratarmount_index::tar_stats_from_path(&tar).unwrap();
        let req = RemotePublishRequest {
            staged: tar.clone(),
            prefix_compressed_bytes: 0,
            etag_at_download: None,
            window: ratarmount_compositing::IndexPatchWindow {
                window_start: 0,
                from_frame: None,
                offsets_shifted: false,
            },
            skip_object_put: false,
            presplice_len: stats.st_size,
            presplice_sha256: stats.full_sha256.clone().unwrap(),
            presplice_prefix512_sha256: stats.prefix512_sha256.clone().unwrap(),
            presplice_suffix512_sha256: stats.suffix512_sha256.clone().unwrap(),
            commit_generation: 1,
        };
        let opts = OpenOptions {
            index_file_path: Some(sidecar.clone()),
            index_in_memory: false,
            ..Default::default()
        };
        let url = format!("{scheme}://bucket/a.tar");
        let (got, probes) = with_close_probes(|_| true, || publish(&url, &opts, &req));
        got.unwrap_or_else(|e| panic!("{scheme}: {e}"));
        assert!(
            probes
                .iter()
                .any(|(p, _)| *p == sidecar.canonicalize().unwrap()),
            "{scheme}: the index was read through a managed reader: {probes:?}"
        );
        assert!(
            probes
                .iter()
                .any(|(p, _)| *p == tar.canonicalize().unwrap()),
            "{scheme}: the staged archive was read through a managed reader: {probes:?}"
        );
        assert!(probes.iter().all(|(_, kept)| *kept), "{scheme}: {probes:?}");
        let puts = server
            .state
            .lock()
            .unwrap()
            .requests
            .iter()
            .filter(|(m, _, _)| m == "PUT")
            .count();
        assert!(puts >= 2, "{scheme}: archive and pointer were put");
        assert!(
            other_process_sees_lock(&sidecar),
            "{scheme}: session A's lock on the index survived the publish"
        );
        drop(session);
    }

    /// Regression (R11-S7-FIX2, #151): the Hub live commit exported the staged
    /// `.tar.zst`'s `zstdblocks` through `export_zstd_blocks`, a raw `File`
    /// whose close released every POSIX lock this process held on the file.
    #[cfg(unix)]
    #[test]
    fn regression_live_commit_zstd_blocks_keep_staged_lock() {
        use ratarmount_index::managed_read::{lock_probe::other_process_sees_lock, VfsLockHolder};
        let dir = tempfile::tempdir().unwrap();
        let zst = dir.path().join("a.tar.zst");
        let mut body = Vec::new();
        for chunk in [&b"first frame"[..], &b"second frame"[..]] {
            body.extend(zstd::encode_all(chunk, 3).unwrap());
        }
        std::fs::write(&zst, body).unwrap();
        let holder = VfsLockHolder::shared(&zst).unwrap();
        assert!(other_process_sees_lock(&zst));
        let blocks = staged_zstd_blocks(&zst).unwrap();
        assert!(
            other_process_sees_lock(&zst),
            "the zstdblocks export kept this process's lock on the staged file"
        );
        drop(holder);
        let want: Vec<(i64, i64)> = ratarmount_compress::export_zstd_blocks(&zst)
            .unwrap()
            .into_iter()
            .map(|(c, d)| (c as i64, d as i64))
            .collect();
        assert_eq!(blocks, want);
        assert_eq!(
            blocks.len(),
            3,
            "two frames and the EOF sentinel: {blocks:?}"
        );
    }

    /// Regression (R11-S7, #151): the S3 live commit read the staged archive
    /// (single PutObject body) and the mount's index (pointer hash, sibling
    /// body) through raw `File`s.
    #[cfg(unix)]
    #[test]
    fn regression_live_commit_s3_reads_keep_index_lock() {
        s7_object_store_publish("s3", publish_s3);
    }

    /// Regression (R11-S7-FIX12, #151): the S3 single PutObject body was read
    /// with `std::fs::read`, whose close released every POSIX lock this
    /// process held on the staged archive. The test above still passed with
    /// that raw read (other managed reads of the archive satisfied its probe
    /// and nothing locked the archive), so this one holds a lock on the
    /// staged archive, takes the single-PUT path with no sidecar (no other
    /// read of the archive), and checks that the lock survives and the PUT
    /// carried the archive's bytes.
    #[cfg(unix)]
    #[test]
    fn regression_live_commit_s3_single_put_body_keeps_archive_lock() {
        use crate::publish_index::tests::{publish_tar, PublishEnv, PublishServer};
        use ratarmount_index::managed_read::{lock_probe::other_process_sees_lock, VfsLockHolder};
        let dir = tempfile::tempdir().unwrap();
        let tar = dir.path().join("a.tar");
        std::fs::write(&tar, publish_tar()).unwrap();
        let server = PublishServer::new(publish_tar(), false, false);
        let _env = PublishEnv::new(&[
            ("AWS_ACCESS_KEY_ID", "test"),
            ("AWS_SECRET_ACCESS_KEY", "secret"),
            ("AWS_ENDPOINT_URL", &server.url),
            ("AWS_REGION", "us-east-1"),
            ("RATARMOUNT_S3_ANONYMOUS", "0"),
            ("AWS_ANONYMOUS", "0"),
        ]);
        let stats = ratarmount_index::tar_stats_from_path(&tar).unwrap();
        let req = RemotePublishRequest {
            staged: tar.clone(),
            prefix_compressed_bytes: 0,
            etag_at_download: None,
            window: ratarmount_compositing::IndexPatchWindow {
                window_start: 0,
                from_frame: None,
                offsets_shifted: false,
            },
            skip_object_put: false,
            presplice_len: stats.st_size,
            presplice_sha256: stats.full_sha256.clone().unwrap(),
            presplice_prefix512_sha256: stats.prefix512_sha256.clone().unwrap(),
            presplice_suffix512_sha256: stats.suffix512_sha256.clone().unwrap(),
            commit_generation: 1,
        };
        let opts = OpenOptions {
            index_in_memory: true,
            ..Default::default()
        };
        let holder = VfsLockHolder::shared(&tar).unwrap();
        assert!(other_process_sees_lock(&tar));
        publish_s3("s3://bucket/a.tar", &opts, &req).unwrap();
        assert!(
            other_process_sees_lock(&tar),
            "the single-PUT body read kept this process's lock on the staged archive"
        );
        drop(holder);
        let state = server.state.lock().unwrap();
        let puts: Vec<_> = state
            .requests
            .iter()
            .filter(|(m, _, _)| m == "PUT")
            .collect();
        assert_eq!(puts.len(), 1, "one PutObject, no pointer: {puts:?}");
        assert_eq!(
            puts[0].2,
            publish_tar(),
            "the PUT body is the staged archive"
        );
    }

    /// Regression (R11-S7, #151): the GCS live commit read the staged archive
    /// (MD5 + body) and the index blob through raw `File`s.
    #[cfg(unix)]
    #[test]
    fn regression_live_commit_gcs_reads_keep_index_lock() {
        s7_object_store_publish("gs", publish_gcs);
    }

    /// Regression (R11-S7, #151): the Azure live commit read the staged archive
    /// and the index (pointer hash, sibling body) through raw `File`s.
    #[cfg(unix)]
    #[test]
    fn regression_live_commit_azure_reads_keep_index_lock() {
        s7_object_store_publish("az", publish_azure);
    }

    /// Regression (R11-S7, #151): the Hub live commit read the fresh sidecar's
    /// body and the staged archive (pointer tarstats, LFS upload) through raw
    /// `File`s; every managed read keeps a lock taken on the file it reads.
    #[cfg(unix)]
    #[test]
    fn regression_live_commit_hf_reads_keep_index_lock() {
        use crate::publish_index::tests::{PublishEnv, PublishServer};
        use ratarmount_index::managed_read::with_close_probes;
        let dir = tempfile::tempdir().unwrap();
        let server = PublishServer::live(hf_test_archive(true));
        let _env = PublishEnv::new(&[
            ("HF_ENDPOINT", &server.url),
            ("HF_TOKEN", "hf-test"),
            ("HF_HUB_OFFLINE", "0"),
            ("RATARMOUNT_HF_SHARE_CACHE", "0"),
            ("RATARMOUNT_PAYLOAD_CACHE_BYTES", "0"),
            ("XDG_CACHE_HOME", dir.path().join("cache").to_str().unwrap()),
            (
                "RATARMOUNT_HF_TREE_CACHE",
                dir.path().join("trees").to_str().unwrap(),
            ),
        ]);
        let url = "hf://datasets/org/data@main/a.tar.zst";
        let overlay = hf_test_overlay(url, &dir.path().join("ov"), false);
        std::fs::write(overlay.root().join("hello.txt"), b"new bytes").unwrap();
        let (got, probes) = with_close_probes(|_| true, || hf_test_tick(&overlay, url));
        assert_eq!(got.unwrap(), CommitOutcome::DidWork);
        assert!(
            probes
                .iter()
                .any(|(p, _)| p.file_name().unwrap() == "index.sqlite"),
            "the sidecar body was read through a managed reader: {probes:?}"
        );
        assert!(probes.iter().all(|(_, kept)| *kept), "{probes:?}");
    }
}

#[cfg(test)]
mod rolling_tests {
    use super::*;
    use ratarmount_compositing::{CommitMode, RollPolicy, SeriesName};
    use std::fs;

    /// Regression: rolling must build/patch a distinct index and manifest for each generation.
    #[test]
    fn rolling_per_archive_sidecars_and_on_exit_patch() {
        for suffix in ["tar", "tar.zst"] {
            let dir = tempfile::tempdir().unwrap();
            let base = dir.path().join(format!("traces.{suffix}"));
            let opts = OpenOptions {
                write_index: true,
                ..Default::default()
            };
            let series =
                open_rolling_series(&base, "1B".parse::<RollPolicy>().unwrap(), &opts).unwrap();
            let original = series.active_path();
            let mut overlay = crate::base_identity::fixtures::new_overlay(
                series.clone(),
                dir.path().join("overlay"),
            )
            .unwrap();
            overlay.set_rolling(series.clone());
            overlay.set_commit_mode(CommitMode::Append);
            overlay.set_manifest_hashes(Some("new".into()));
            fs::write(overlay.root().join("one"), b"one").unwrap();
            assert!(apply_live_commit(&overlay, &original, true, &opts).unwrap());
            let names = SeriesName::new(&base).unwrap();
            let first = names.generation(1).unwrap();
            let first_sidecar = sidecar_path_for_patch(&first, &opts).expect("first index");
            let first_bytes = fs::read(&first).unwrap();
            let first_index_bytes = fs::read(&first_sidecar).unwrap();
            fs::write(overlay.root().join("two"), b"two").unwrap();
            assert!(apply_live_commit(&overlay, &original, false, &opts).unwrap());
            let second = names.generation(2).unwrap();
            assert_eq!(series.active_path(), second);
            assert_eq!(fs::read(&first).unwrap(), first_bytes);
            assert_eq!(fs::read(&first_sidecar).unwrap(), first_index_bytes);
            for path in [&first, &second] {
                let index = sidecar_path_for_patch(path, &opts).expect("per-archive index");
                SqliteIndex::open_read_only(&index)
                    .unwrap()
                    .check_tarstats_matches_archive(path)
                    .unwrap();
                assert!(PathBuf::from(format!("{}.manifest.jsonl", path.display())).is_file());
            }
            drop(overlay);
            drop(series);
            let remount = open_rolling_series(&base, "1G".parse().unwrap(), &opts).unwrap();
            assert!(remount.lookup("/one", 0).is_some());
            assert!(remount.lookup("/two", 0).is_some());
        }
    }
}
