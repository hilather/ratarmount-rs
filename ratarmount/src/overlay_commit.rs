//! Live overlay commit (uncompressed TAR only): interval + on-exit.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use ratarmount_compositing::WriteOverlay;
use ratarmount_core::{MountSource, OpenOptions};
use ratarmount_formats_tar::SqliteIndexedTar;
use ratarmount_nfs::NfsStop;

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

pub fn spawn_interval_commits(
    overlay: Arc<WriteOverlay>,
    archive: PathBuf,
    interval: Duration,
    stop: Option<NfsStop>,
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
            match apply_live_commit(&overlay, &archive, true) {
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
) -> Result<bool, String> {
    if reopen_and_reset {
        overlay
            .commit_live_uncompressed_tar(archive, |p| {
                reopen_uncompressed_tar(p).map_err(ratarmount_compositing::OverlayError::Msg)
            })
            .map_err(|e| e.to_string())
    } else {
        overlay
            .commit_uncompressed_tar_atomic(archive)
            .map_err(|e| e.to_string())
    }
}

fn reopen_uncompressed_tar(archive: &Path) -> Result<Arc<dyn MountSource>, String> {
    let opts = OpenOptions {
        index_in_memory: true,
        ..OpenOptions::default()
    };
    let mut materialised = None;
    let tar = SqliteIndexedTar::create_index(
        archive,
        archive,
        None,
        &opts,
        env!("CARGO_PKG_VERSION"),
        &mut materialised,
    )
    .map_err(|e| format!("reopen TAR after live commit: {e}"))?;
    Ok(Arc::new(tar) as Arc<dyn MountSource>)
}

/// Startup gate: durable `-w` + a single uncompressed TAR.
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
            "--commit-overlay-on-exit / --commit-overlay-interval require a single uncompressed TAR"
                .into(),
        );
    }
    let archive = inputs[0].clone();
    if !archive.is_file() {
        return Err(format!(
            "live overlay commit requires an uncompressed TAR file (got {})",
            archive.display()
        ));
    }
    ratarmount_compositing::live_commit_is_supported(&archive).map_err(|e| e.to_string())?;
    Ok(archive)
}

pub fn maybe_commit_on_exit(overlay: Option<&WriteOverlay>, archive: Option<&Path>, enabled: bool) {
    if !enabled {
        return;
    }
    let (Some(ov), Some(path)) = (overlay, archive) else {
        return;
    };
    match apply_live_commit(ov, path, false) {
        Ok(true) => eprintln!("committed write overlay into {}", path.display()),
        Ok(false) => log::debug!("on-exit overlay commit: nothing to do"),
        Err(e) => eprintln!("error: on-exit overlay commit failed: {e}"),
    }
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
}
