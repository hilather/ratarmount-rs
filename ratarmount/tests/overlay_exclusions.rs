//! Regression: the recorded exclusion set of a directory base's weak digest
//! (overlay, journal, lowers, mount point) through the real CLI. Overlay
//! creation and remount need no /dev/fuse; mounts and `--journal` do (Linux).

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use ratarmount_compositing::OverlayMeta;

fn private_env(cmd: &mut Command, dir: &Path) {
    let home = dir.join("home");
    fs::create_dir_all(&home).unwrap();
    cmd.env("HOME", &home)
        .env("XDG_CACHE_HOME", home.join(".cache"));
}

fn cli(root: &Path, args: &[&OsStr]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ratarmount"));
    private_env(&mut cmd, root);
    cmd.args(args).output().unwrap()
}

fn ok(out: Output) -> String {
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

/// `--no-mount -w OVERLAY [flags] BASE`: creation/reopen only.
fn no_mount(root: &Path, overlay: &Path, base: &Path, flags: &[&str]) -> Output {
    let mut args: Vec<&OsStr> = vec![
        OsStr::new("--no-mount"),
        OsStr::new("--index-file"),
        OsStr::new(":memory:"),
        OsStr::new("-w"),
        overlay.as_os_str(),
    ];
    args.extend(flags.iter().map(OsStr::new));
    args.push(base.as_os_str());
    cli(root, &args)
}

fn excludes(overlay: &Path) -> String {
    OverlayMeta::read(overlay)
        .unwrap()
        .unwrap()
        .get("base_weak_excludes")
        .unwrap_or("")
        .to_string()
}

fn digest(overlay: &Path) -> String {
    OverlayMeta::read(overlay)
        .unwrap()
        .unwrap()
        .base_digest()
        .unwrap_or("")
        .to_string()
}

fn base_dir(root: &Path) -> PathBuf {
    let base = root.join("base");
    fs::create_dir(&base).unwrap();
    fs::write(base.join("f"), b"one").unwrap();
    base
}

/// Regression (G5a): `-w B/new/ov B` where `B/new` does not exist records the
/// topmost new component (`new`), so the remount, the seal and `verify` agree
/// even though creating the overlay added `B/new`. Weak and strong variants.
#[test]
fn regression_overlay_in_new_parent_cli_remount_seal_and_verify_pass() {
    let tmp = tempfile::tempdir().unwrap();
    let base = base_dir(tmp.path());
    let overlay = base.join("new/ov");
    ok(no_mount(tmp.path(), &overlay, &base, &[]));
    assert_eq!(excludes(&overlay), r#"["new"]"#);
    let recorded = digest(&overlay);
    assert!(recorded.starts_with("weak:"), "{recorded}");
    ok(no_mount(tmp.path(), &overlay, &base, &[]));
    assert_eq!(digest(&overlay), recorded);
    ok(cli(
        tmp.path(),
        &[
            OsStr::new("overlay"),
            OsStr::new("seal"),
            overlay.as_os_str(),
        ],
    ));
    // `verify` gains its base comparison in the verify-base commit; today it
    // must at least not fail because the exclusion set is wrong.
    ok(cli(
        tmp.path(),
        &[
            OsStr::new("overlay"),
            OsStr::new("verify"),
            overlay.as_os_str(),
        ],
    ));

    // Strong variant (own base): digest-base echoes the topmost-new exclusion.
    let base = tmp.path().join("base2");
    fs::create_dir(&base).unwrap();
    fs::write(base.join("f"), b"one").unwrap();
    let strong = base.join("new2/ov2");
    let out = cli(
        tmp.path(),
        &[
            OsStr::new("overlay"),
            OsStr::new("digest-base"),
            base.as_os_str(),
            OsStr::new("--exclude-overlay"),
            strong.as_os_str(),
        ],
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("excluding: new2"));
    let supplied = ok(out).trim().to_string();
    ok(no_mount(
        tmp.path(),
        &strong,
        &base,
        &["--base-digest", &supplied],
    ));
    assert_eq!(digest(&strong), supplied);
    ok(no_mount(
        tmp.path(),
        &strong,
        &base,
        &["--base-digest", &supplied],
    ));
    // A real base edit afterwards refuses the strong one (weak companion).
    fs::write(base.join("f"), b"edited!").unwrap();
    let refused = no_mount(tmp.path(), &strong, &base, &["--base-digest", &supplied]);
    assert_eq!(refused.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("--force-base-mismatch"));
    // Weak, unsealed (a sealed overlay is refused earlier, for being sealed).
    let base3 = tmp.path().join("base3");
    fs::create_dir(&base3).unwrap();
    fs::write(base3.join("f"), b"one").unwrap();
    let weak = base3.join("new3/ov3");
    ok(no_mount(tmp.path(), &weak, &base3, &[]));
    ok(no_mount(tmp.path(), &weak, &base3, &[]));
    fs::write(base3.join("f"), b"edited!").unwrap();
    let refused = no_mount(tmp.path(), &weak, &base3, &[]);
    assert_eq!(refused.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("--force-base-mismatch"));
}

/// Regression (G5c, creation half): a lower created with its overlay inside a
/// directory base records that exclusion; a new top outside the base over the
/// sealed lower opens and remounts without a weak mismatch.
#[test]
fn regression_lower_with_own_exclusions_then_new_top_outside_the_base() {
    let tmp = tempfile::tempdir().unwrap();
    let base = base_dir(tmp.path());
    let lower = base.join("lower-ov");
    ok(no_mount(tmp.path(), &lower, &base, &[]));
    assert_eq!(excludes(&lower), r#"["lower-ov"]"#);
    ok(cli(
        tmp.path(),
        &[OsStr::new("overlay"), OsStr::new("seal"), lower.as_os_str()],
    ));
    let top = tmp.path().join("top");
    let lower_flag = lower.to_str().unwrap();
    ok(no_mount(tmp.path(), &top, &base, &["--lower", lower_flag]));
    ok(no_mount(tmp.path(), &top, &base, &["--lower", lower_flag]));
    // The top's own measurement of the base equals the lower's.
    assert_eq!(digest(&top), digest(&lower));
    // A top inside the base in a not-yet-existing parent records `top-dir`,
    // beside the lower layer the caller passed.
    let inner = base.join("top-dir/ov");
    ok(no_mount(
        tmp.path(),
        &inner,
        &base,
        &["--lower", lower_flag],
    ));
    assert_eq!(excludes(&inner), r#"["lower-ov","top-dir"]"#);
    ok(no_mount(
        tmp.path(),
        &inner,
        &base,
        &["--lower", lower_flag],
    ));
}

#[cfg(target_os = "linux")]
mod mounted {
    use super::*;
    use std::os::unix::fs::MetadataExt;
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    fn available() -> bool {
        if !Path::new("/dev/fuse").exists()
            || Command::new("fusermount3")
                .arg("--version")
                .output()
                .is_err()
        {
            eprintln!("skip: /dev/fuse or fusermount3 unavailable");
            return false;
        }
        true
    }

    /// One foreground `-w` mount; `Ok` once it was ready, served and unmounted
    /// cleanly, `Err(stderr)` if it exited first (a refusal).
    fn cycle(
        root: &Path,
        overlay: &Path,
        base: &Path,
        mnt: &Path,
        flags: &[&OsStr],
        work: &dyn Fn(&Path),
    ) -> Result<(), String> {
        cycle_with(root, Some(overlay), base, mnt, flags, work)
    }

    /// [`cycle`], optionally without `-w` (a read-only mount of a `--lower`).
    fn cycle_with(
        root: &Path,
        overlay: Option<&Path>,
        base: &Path,
        mnt: &Path,
        flags: &[&OsStr],
        work: &dyn Fn(&Path),
    ) -> Result<(), String> {
        let stderr_path = root.join("mount.stderr");
        let stderr = fs::File::create(&stderr_path).unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ratarmount"));
        private_env(&mut cmd, root);
        let mut child = cmd
            .args(["-f", "--passthrough", "off", "--index-file", ":memory:"])
            .args(
                overlay
                    .iter()
                    .flat_map(|o| [OsStr::new("-w"), o.as_os_str()]),
            )
            .args(flags)
            .arg(base)
            .arg(mnt)
            .stdin(Stdio::null())
            .stderr(stderr)
            .spawn()
            .unwrap();
        let parent_dev = fs::metadata(mnt.parent().unwrap()).ok().map(|m| m.dev());
        let deadline = Instant::now() + Duration::from_secs(30);
        let unmount = || {
            let _ = Command::new("fusermount3").arg("-u").arg(mnt).status();
        };
        let ready = loop {
            if fs::metadata(mnt).is_ok_and(|m| Some(m.dev()) != parent_dev)
                && fs::read_dir(mnt).is_ok()
            {
                break true;
            }
            if let Some(status) = child.try_wait().unwrap() {
                assert!(!status.success(), "mount exited 0 before it was ready");
                break false;
            }
            if Instant::now() > deadline {
                unmount();
                let _ = child.kill();
                let _ = child.wait();
                panic!("mount not ready within 30 s");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        if !ready {
            return Err(fs::read_to_string(&stderr_path).unwrap());
        }
        work(mnt);
        unmount();
        let start = Instant::now();
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success(), "unmount exit {status}");
                return Ok(());
            }
            if start.elapsed() > Duration::from_secs(30) {
                let _ = child.kill();
                let _ = child.wait();
                panic!("mount did not exit after unmount");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Regression: after sealing L against B, an ordinary `B/new.log` appeared
    /// and a read-only `--lower L --journal B/new.log` mount excluded that
    /// existing file from the base check and accepted the changed base. Only a
    /// path that does not exist yet (this mount creates it) may be excluded.
    #[test]
    fn regression_invocation_exclusion_cannot_hide_an_existing_base_file() {
        if !available() {
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let base = base_dir(tmp.path());
        let lower = tmp.path().join("lower");
        ok(no_mount(tmp.path(), &lower, &base, &[]));
        ok(cli(
            tmp.path(),
            &[OsStr::new("overlay"), OsStr::new("seal"), lower.as_os_str()],
        ));
        let mnt = tmp.path().join("mnt");
        fs::create_dir(&mnt).unwrap();
        let ro = |journal: &Path, extra: &[&OsStr]| {
            let mut flags = vec![
                OsStr::new("--lower"),
                lower.as_os_str(),
                OsStr::new("--journal"),
                journal.as_os_str(),
            ];
            flags.extend_from_slice(extra);
            cycle_with(tmp.path(), None, &base, &mnt, &flags, &|_| {})
        };
        // A journal path that does not exist is created by this mount: allowed.
        ro(&tmp.path().join("fresh.jsonl"), &[]).unwrap();
        // An ordinary file that is already in the base is a base change.
        let existing = base.join("new.log");
        fs::write(&existing, b"someone's file").unwrap();
        let error = ro(&existing, &[]).unwrap_err();
        assert!(error.contains("different base"), "{error}");
        // The explicit override still works.
        ro(&existing, &[OsStr::new("--force-stack-mismatch")]).unwrap();
    }

    fn write_through(name: &'static str) -> impl Fn(&Path) {
        move |mnt: &Path| fs::write(mnt.join(name), b"written through the mount").unwrap()
    }

    /// Regression (Matt's rule): a mount point inside the base, created by the
    /// mount after the digest was taken, must be in the recorded excluded set
    /// or the next mount reports a false weak mismatch. Overlay beside the base
    /// and overlay inside it; mount point absent and present beforehand.
    #[test]
    fn regression_mountpoint_inside_directory_base_remounts_without_weak_mismatch() {
        if !available() {
            return;
        }
        for (overlay_inside, mnt_preexists) in [(false, false), (true, false), (true, true)] {
            let tmp = tempfile::tempdir().unwrap();
            let base = base_dir(tmp.path());
            let overlay = if overlay_inside {
                base.join(".ov")
            } else {
                tmp.path().join("ov")
            };
            let mnt = base.join("mnt");
            if mnt_preexists {
                fs::create_dir(&mnt).unwrap();
            }
            let label = format!("overlay_inside={overlay_inside} mnt_preexists={mnt_preexists}");
            cycle(tmp.path(), &overlay, &base, &mnt, &[], &write_through("a"))
                .unwrap_or_else(|e| panic!("{label}: first mount: {e}"));
            let recorded = digest(&overlay);
            assert!(recorded.starts_with("weak:"), "{label}: {recorded}");
            assert!(
                excludes(&overlay).contains("\"mnt\""),
                "{label}: mount point missing from {}",
                excludes(&overlay)
            );
            cycle(tmp.path(), &overlay, &base, &mnt, &[], &write_through("b"))
                .unwrap_or_else(|e| panic!("{label}: remount refused: {e}"));
            assert_eq!(digest(&overlay), recorded, "{label}");
            // A real base edit is still caught.
            fs::write(base.join("f"), b"edited!").unwrap();
            let error = cycle(tmp.path(), &overlay, &base, &mnt, &[], &|_| {}).unwrap_err();
            assert!(error.contains("--force-base-mismatch"), "{label}: {error}");
        }
    }

    /// Regression (G5b): a journal added on a later mount is appended to the
    /// recorded set, the grown journal does not break `overlay verify` or a
    /// journal-free remount, and a journal path that is base content is refused.
    #[test]
    fn regression_journal_added_later_cli_appends_and_journal_free_remount_passes() {
        if !available() {
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let base = base_dir(tmp.path());
        fs::write(base.join("existing.txt"), b"base content").unwrap();
        let overlay = base.join(".ov");
        let mnt = tmp.path().join("mnt");
        fs::create_dir(&mnt).unwrap();
        cycle(tmp.path(), &overlay, &base, &mnt, &[], &write_through("a")).unwrap();
        assert_eq!(excludes(&overlay), r#"[".ov"]"#);
        let recorded = digest(&overlay);

        let journal = base.join("j.jsonl");
        let flags = [OsStr::new("--journal"), journal.as_os_str()];
        cycle(
            tmp.path(),
            &overlay,
            &base,
            &mnt,
            &flags,
            &write_through("b"),
        )
        .unwrap();
        assert_eq!(excludes(&overlay), r#"[".ov","j.jsonl"]"#);
        assert!(fs::metadata(&journal).unwrap().len() > 0, "journal grew");
        assert_eq!(digest(&overlay), recorded, "not re-recorded");

        // Journal-free remount and a sealed verify pass with the grown journal.
        cycle(tmp.path(), &overlay, &base, &mnt, &[], &write_through("c")).unwrap();
        ok(cli(
            tmp.path(),
            &[
                OsStr::new("overlay"),
                OsStr::new("seal"),
                overlay.as_os_str(),
            ],
        ));
        ok(cli(
            tmp.path(),
            &[
                OsStr::new("overlay"),
                OsStr::new("verify"),
                overlay.as_os_str(),
            ],
        ));
    }

    /// Regression (G5b, refusal half): a journal that already exists in the
    /// base is base content; it is refused and the recorded set is untouched.
    #[test]
    fn regression_journal_path_existing_in_base_is_refused_and_appends_nothing() {
        if !available() {
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let base = base_dir(tmp.path());
        fs::write(base.join("existing.txt"), b"base content").unwrap();
        let overlay = base.join(".ov");
        let mnt = tmp.path().join("mnt");
        fs::create_dir(&mnt).unwrap();
        cycle(tmp.path(), &overlay, &base, &mnt, &[], &|_| {}).unwrap();
        let before = excludes(&overlay);
        let journal = base.join("existing.txt");
        let flags = [OsStr::new("--journal"), journal.as_os_str()];
        let error = cycle(tmp.path(), &overlay, &base, &mnt, &flags, &|_| {}).unwrap_err();
        assert!(
            error.contains("already exists, so it is base content"),
            "{error}"
        );
        assert_eq!(excludes(&overlay), before);
        assert_eq!(fs::read(&journal).unwrap(), b"base content");
    }
}
