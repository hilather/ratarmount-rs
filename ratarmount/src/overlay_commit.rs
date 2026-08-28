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
    OverlayError, WriteOverlay,
};
use ratarmount_compress::{
    detect_compression, open_seekable_zstd_with_threads, scan_zstd_frames_path, CompressionFormat,
};
use ratarmount_core::{MountSource, OpenOptions};
use ratarmount_formats_tar::SqliteIndexedTar;
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
                if let Some(window) = ov.last_patch_window() {
                    patch_sidecar_if_present(p, &window, &opts)?;
                }
                reopen_live_archive(p, &opts).map_err(OverlayError::Msg)
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
        if did {
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
}
