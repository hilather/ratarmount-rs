//! Live overlay commit (uncompressed TAR and `.tar.zst`): interval + on-exit.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use ratarmount_compositing::{
    classify_createable_archive, maybe_create_empty_write_archive, EmptyArchiveKind,
    EmptyCreateOutcome, WriteOverlay,
};
use ratarmount_compress::{
    detect_compression, open_seekable_zstd_with_threads, scan_zstd_frames_path, CompressionFormat,
};
use ratarmount_core::{MountSource, OpenOptions};
use ratarmount_formats_tar::SqliteIndexedTar;
use ratarmount_nfs::NfsStop;

/// Startup / tick warning when the last frame is the whole file or larger than this.
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
    thread::Builder::new()
        .name("ratarmount-overlay-commit".into())
        .spawn(move || loop {
            let start = Instant::now();
            while start.elapsed() < interval {
                if term_requested() || stop.as_ref().is_some_and(|s| s.is_stopped()) {
                    return;
                }
                thread::sleep(Duration::from_millis(50));
            }
            if term_requested() || stop.as_ref().is_some_and(|s| s.is_stopped()) {
                return;
            }
            match apply_live_commit(&overlay, &archive, true, &opts) {
                Ok(true) => log::info!("interval overlay commit wrote {}", archive.display()),
                Ok(false) => log::debug!("interval overlay commit: nothing to do"),
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
                reopen_live_archive(p, opts).map_err(ratarmount_compositing::OverlayError::Msg)
            })
            .map_err(|e| e.to_string())
    } else {
        overlay.commit_atomic(archive).map_err(|e| e.to_string())
    }
}

fn reopen_live_archive(archive: &Path, opts: &OpenOptions) -> Result<Arc<dyn MountSource>, String> {
    let mut o = opts.clone();
    // Interval swap must not fight the on-disk index / stale zstdblocks.
    o.index_in_memory = true;
    match detect_compression(archive) {
        Ok(CompressionFormat::None) => {
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
            // (that would import stale zstdblocks from before persist).
            let threads = o.threads_for("zstd");
            let body = open_seekable_zstd_with_threads(archive, threads)
                .map_err(|e| format!("reopen .tar.zst after live commit: {e}"))?;
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

pub fn maybe_commit_on_exit(overlay: Option<&WriteOverlay>, archive: Option<&Path>, enabled: bool) {
    if !enabled {
        return;
    }
    let (Some(ov), Some(path)) = (overlay, archive) else {
        return;
    };
    match apply_live_commit(ov, path, false, &OpenOptions::default()) {
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
