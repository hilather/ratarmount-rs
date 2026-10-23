//! Shared by the FUSE test files (`#[path = "support/unmount.rs"] mod unmount;`).
//!
//! Every new mount gets probed by the desktop (`gvfsd-trash` looks up
//! `.Trash` and `.Trash-<uid>` on it), and that probe can hold a transient
//! reference that makes the first `fusermount3 -u` fail with EBUSY (about one
//! in five on btrfs). It is not a pending FUSE RELEASE. A bounded retry clears
//! it; a mount that stays busy is a failure, never a pass on a fallback.
#![allow(dead_code)]

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Mountpoint references held by other processes, for a failure report:
/// `fuser -vm` and every `/proc/*/{fd,cwd,root,exe}` link under `mnt`.
pub fn log_holders(mnt: &Path) {
    eprintln!("holders of {}:", mnt.display());
    match Command::new("fuser").arg("-vm").arg(mnt).output() {
        Ok(out) => eprintln!(
            "fuser -vm: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
        Err(e) => eprintln!("fuser unavailable: {e}"),
    }
    let roots: Vec<PathBuf> = [Some(mnt.to_path_buf()), mnt.canonicalize().ok()]
        .into_iter()
        .flatten()
        .collect();
    let mut found = 0;
    for entry in fs::read_dir("/proc").into_iter().flatten().flatten() {
        let pid = entry.file_name();
        if !pid.to_string_lossy().bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let dir = entry.path();
        let comm = fs::read_to_string(dir.join("comm")).unwrap_or_default();
        let mut links = vec![
            ("cwd".to_string(), dir.join("cwd")),
            ("root".to_string(), dir.join("root")),
            ("exe".to_string(), dir.join("exe")),
        ];
        for fd in fs::read_dir(dir.join("fd")).into_iter().flatten().flatten() {
            links.push((
                format!("fd {}", fd.file_name().to_string_lossy()),
                fd.path(),
            ));
        }
        for (kind, link) in links {
            if let Ok(target) = fs::read_link(&link) {
                if roots.iter().any(|root| target.starts_with(root)) {
                    found += 1;
                    eprintln!(
                        "  pid {} ({}) {kind} -> {}",
                        pid.to_string_lossy(),
                        comm.trim(),
                        target.display()
                    );
                }
            }
        }
    }
    if found == 0 {
        eprintln!("  no process holds an fd, cwd, root or exe under the mount");
    }
}

pub fn is_mounted(mnt: &Path) -> bool {
    fs::metadata(mnt)
        .is_ok_and(|m| Some(m.dev()) != fs::metadata(mnt.parent().unwrap()).ok().map(|p| p.dev()))
}

/// `fusermount3 -u` with a bounded retry. An external prober of a new mount
/// (the desktop's `gvfsd-trash` looks up `.Trash` and `.Trash-<uid>` on
/// every mount) can hold a transient reference that makes the first `-u`
/// return EBUSY; it is not a pending FUSE RELEASE, and a retry clears it.
/// If the mount is still busy after `limit`, the holders are logged, a lazy
/// unmount leaves nothing stale, and the result is an `Err` so the test
/// fails instead of passing on the fallback.
pub fn unmount_within(mnt: &Path, limit: Duration, label: &str) -> Result<(), String> {
    let deadline = Instant::now() + limit;
    loop {
        let ok = Command::new("fusermount3")
            .arg("-u")
            .arg(mnt)
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        // Already unmounted by an earlier attempt also ends the loop.
        if ok || !is_mounted(mnt) {
            return Ok(());
        }
        if Instant::now() > deadline {
            eprintln!(
                "{label}: fusermount3 -u {} still busy after {limit:?}",
                mnt.display()
            );
            log_holders(mnt);
            let _ = Command::new("fusermount3")
                .arg("-u")
                .arg("-z")
                .arg(mnt)
                .status();
            return Err(format!(
                "{label}: fusermount3 -u {} stayed busy for {limit:?} (lazy unmount used for cleanup; holders logged above)",
                mnt.display()
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}
