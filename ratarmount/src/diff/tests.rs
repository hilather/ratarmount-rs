use super::*;
use ratarmount_compositing::WriteOverlay;
use ratarmount_formats_tar::{write_tar_eof, write_ustar_members, UstarMember, UstarPayload};
use std::os::fd::FromRawFd;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::process::Command;
use std::sync::Arc;

fn args(root: &Path) -> DiffArgs {
    DiffArgs {
        directory: root.into(),
        base: None,
        git: false,
        context: 3,
        stat: false,
        name_status: false,
        include_git_dir: false,
    }
}

fn base_tar(root: &Path, files: &[(&str, &[u8], u32)]) -> factory::MountBundle {
    let path = root.join("base.tar");
    let members: Vec<_> = files
        .iter()
        .map(|(path, bytes, mode)| UstarMember {
            path,
            payload: if mode & S_IFMT == S_IFLNK {
                UstarPayload::Symlink {
                    target: std::str::from_utf8(bytes).unwrap(),
                }
            } else {
                UstarPayload::File { bytes }
            },
            mode: mode & 0o777,
            uid: 0,
            gid: 0,
            mtime: 0,
        })
        .collect();
    let mut tar = fs::File::create(&path).unwrap();
    write_ustar_members(&mut tar, &members).unwrap();
    write_tar_eof(&mut tar).unwrap();
    drop(tar);
    let mut options = OpenOptions {
        index_in_memory: true,
        write_index: false,
        ..OpenOptions::default()
    };
    factory::build_mount_source_ex(
        &[path],
        &mut options,
        false,
        factory::CompositingOptions::default(),
    )
    .unwrap()
}

fn put(overlay: &WriteOverlay, path: &str, content: &[u8]) {
    let fd = overlay.create_file(path, 0o644).unwrap();
    let mut file = unsafe { fs::File::from_raw_fd(fd) };
    file.write_all(content).unwrap();
    overlay.finish_owned_write_fd(file);
}

/// Regression: unified patches describe additions, deletions and missing newlines in sorted order.
#[test]
fn regression_diff_unified_golden() {
    let tmp = tempfile::tempdir().unwrap();
    let base = base_tar(
        tmp.path(),
        &[
            ("a", b"one\ntwo\nthree\n", 0o100644),
            ("delete", b"gone\n", 0o100644),
            ("mode", b"same\n", 0o100644),
        ],
    );
    let overlay = WriteOverlay::new(Arc::clone(&base.source), tmp.path().join("overlay")).unwrap();
    put(&overlay, "/a", b"one\nTWO\nthree\n");
    overlay.unlink("/delete").unwrap();
    put(&overlay, "/empty", b"");
    overlay.ensure_modifiable("/mode").unwrap();
    fs::set_permissions(
        overlay.root().join("mode"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    put(&overlay, "/nested/new", b"new");
    let overlay_root = overlay.root().to_path_buf();
    drop(overlay);
    let args = args(&overlay_root);
    let changes = collect(&args, base.source.as_ref()).unwrap();
    let output = patch::render(&changes, &args).unwrap();
    assert_eq!(output, concat!(
        "--- a/a\n+++ b/a\n@@ -1,3 +1,3 @@\n one\n-two\n+TWO\n three\n",
        "deleted file mode 100644\n--- a/delete\n+++ /dev/null\n@@ -1 +0,0 @@\n-gone\n",
        "new file mode 100644\n--- /dev/null\n+++ b/empty\n",
        "old mode 100644\nnew mode 100755\n--- a/mode\n+++ b/mode\n",
        "new file mode 100644\n--- /dev/null\n+++ b/nested/new\n@@ -0,0 +1 @@\n+new\n\\ No newline at end of file\n",
    ));
}

fn snapshot(source: &dyn MountSource, path: &str, entries: &mut BTreeMap<String, Entry>) {
    for child in source.list_dirents(path).unwrap() {
        let full = format!("{}/{}", path.trim_end_matches('/'), child.name);
        if excluded(&full, false) {
            continue;
        }
        let fi = source.lookup(&full, 0).unwrap();
        if fi.mode & S_IFMT == S_IFDIR {
            snapshot(source, &full, entries);
        } else {
            base_entries(source, full.trim_start_matches('/'), false, entries).unwrap();
            let entry = entries.get_mut(full.trim_start_matches('/')).unwrap();
            entry.mode = entry.git_mode();
        }
    }
}

fn materialize(entries: &BTreeMap<String, Entry>, root: &Path) {
    for (path, entry) in entries {
        let file = root.join(path);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        if entry.mode & S_IFMT == S_IFLNK {
            symlink(std::ffi::OsStr::from_bytes(&entry.data), &file).unwrap();
        } else {
            fs::write(&file, &entry.data).unwrap();
            fs::set_permissions(&file, fs::Permissions::from_mode(entry.mode & 0o777)).unwrap();
        }
    }
}

/// Regression: Git must apply binary, symlink, empty-file, mode, type and rename patches exactly.
#[test]
fn regression_diff_git_apply_matches_overlay_view() {
    if Command::new("git").arg("--version").output().is_err() {
        eprintln!("skip: git is unavailable");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let base = base_tar(
        tmp.path(),
        &[
            ("a", b"one\ntwo\nthree\n", 0o100644),
            ("delete", b"gone\n", 0o100644),
            ("mode", b"same\n", 0o100644),
            ("link", b"old-target", 0o120000),
            ("executable", b"before\n", 0o100755),
            ("bin", b"\0old\xff", 0o100644),
            ("delete-bin", b"\0delete", 0o100644),
            ("empty-delete", b"", 0o100644),
            ("rename", b"rename\n", 0o100644),
            ("rename-bin", b"\0rename", 0o100644),
            ("no-newline", b"before", 0o100644),
            ("nested/keep", b"keep\n", 0o100644),
            ("removed/child", b"child\n", 0o100644),
            ("to-link", b"regular\n", 0o100644),
            ("to-file", b"target", 0o120000),
            ("to-dir", b"regular\n", 0o100644),
            ("to-file-dir/child", b"child\n", 0o100644),
        ],
    );
    let overlay = WriteOverlay::new(Arc::clone(&base.source), tmp.path().join("overlay")).unwrap();
    put(&overlay, "/a", b"one\nTWO\nthree\n");
    overlay.ensure_modifiable("/executable").unwrap();
    put(&overlay, "/executable", b"after\n");
    for path in [
        "/delete",
        "/delete-bin",
        "/empty-delete",
        "/removed/child",
        "/to-link",
        "/to-file",
        "/to-dir",
        "/to-file-dir/child",
    ] {
        overlay.unlink(path).unwrap();
    }
    for path in ["/removed", "/to-file-dir"] {
        overlay.rmdir(path).unwrap();
    }
    // Recreate the formerly deleted directory name as a regular file.
    put(&overlay, "/to-file-dir", b"replacement\n");
    overlay.mkdir("/to-dir", 0o755).unwrap();
    put(&overlay, "/to-dir/child", b"replacement\n");
    put(&overlay, "/empty-new", b"");
    put(&overlay, "/nested/new", b"new\n");
    put(&overlay, "/bin", b"\0new\xfe");
    put(
        &overlay,
        "/new-bin",
        &(0..=255).cycle().take(2048).collect::<Vec<_>>(),
    );
    put(&overlay, "/no-newline", b"after");
    put(&overlay, "/space quote\" tab\t café", b"quoted\n");
    overlay.ensure_modifiable("/mode").unwrap();
    fs::set_permissions(
        overlay.root().join("mode"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    overlay.unlink("/link").unwrap();
    overlay.create_symlink("/link", "new-target").unwrap();
    overlay.create_symlink("/to-link", "new-target").unwrap();
    put(&overlay, "/to-file", b"now regular\n");
    overlay.rename("/rename", "/renamed").unwrap();
    overlay.rename("/rename-bin", "/renamed-bin").unwrap();
    // An unchanged copy-up and synthetic metadata must not appear in a patch.
    overlay.ensure_modifiable("/nested/keep").unwrap();
    fs::create_dir_all(overlay.root().join(".git/refs")).unwrap();
    fs::write(overlay.root().join(".git/HEAD"), b"synthetic").unwrap();
    fs::write(
        overlay
            .root()
            .join("nested/.RATARMOUNT.OVERLAY.SQLITE-stage"),
        b"internal",
    )
    .unwrap();
    let mut expected = BTreeMap::new();
    snapshot(&overlay, "/", &mut expected);
    let overlay_root = overlay.root().to_path_buf();
    drop(overlay);
    let mut args = args(&overlay_root);
    args.git = true;
    let changes = collect(&args, base.source.as_ref()).unwrap();
    let patch = patch::render(&changes, &args).unwrap();
    assert!(patch.contains("similarity index 100%\nrename from rename\nrename to renamed\n"));
    assert!(patch.contains("GIT binary patch\nliteral"));
    assert!(!patch.contains("synthetic"));
    assert!(!patch.contains("OVERLAY.SQLITE"));
    assert!(!patch.contains("nested/keep"));
    let checkout = tmp.path().join("checkout");
    fs::create_dir(&checkout).unwrap();
    let mut initial = BTreeMap::new();
    snapshot(base.source.as_ref(), "/", &mut initial);
    materialize(&initial, &checkout);
    let patch_file = tmp.path().join("attempt.patch");
    fs::write(&patch_file, &patch).unwrap();
    for check in [true, false] {
        let mut cmd = Command::new("git");
        cmd.current_dir(&checkout).args(["apply", "--binary"]);
        if check {
            cmd.arg("--check");
        }
        let output = cmd.arg(&patch_file).output().unwrap();
        assert!(
            output.status.success(),
            "git apply (check={check}): {}\n{patch}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let folder = ratarmount_compositing::FolderMountSource::new(&checkout).unwrap();
    let mut actual = BTreeMap::new();
    snapshot(&folder, "/", &mut actual);
    assert_eq!(actual, expected);
    // The reverse literals must also be valid.
    let output = Command::new("git")
        .current_dir(&checkout)
        .args(["apply", "--reverse"])
        .arg(&patch_file)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut restored = BTreeMap::new();
    snapshot(&folder, "/", &mut restored);
    assert_eq!(restored, initial);
}

/// Regression: duplicate-content renames pair once, deterministically; summaries omit internals.
#[test]
fn regression_diff_renames_summaries_and_internal_paths() {
    let tmp = tempfile::tempdir().unwrap();
    let base = base_tar(
        tmp.path(),
        &[("a", b"same\n", 0o100644), ("b", b"same\n", 0o100644)],
    );
    let overlay = WriteOverlay::new(Arc::clone(&base.source), tmp.path().join("overlay")).unwrap();
    overlay.unlink("/a").unwrap();
    overlay.unlink("/b").unwrap();
    put(&overlay, "/y", b"same\n");
    put(&overlay, "/z", b"same\n");
    fs::create_dir_all(overlay.root().join(".git")).unwrap();
    fs::write(overlay.root().join(".git/HEAD"), b"head").unwrap();
    fs::create_dir_all(overlay.root().join("nested")).unwrap();
    fs::write(
        overlay.root().join("nested/.ratarmount-overlay.used"),
        b"marker",
    )
    .unwrap();
    let overlay_root = overlay.root().to_path_buf();
    drop(overlay);
    let mut args = args(&overlay_root);
    args.name_status = true;
    let changes = collect(&args, base.source.as_ref()).unwrap();
    assert_eq!(
        patch::render(&changes, &args).unwrap(),
        "R100\ta\ty\nR100\tb\tz\n"
    );
    args.name_status = false;
    args.stat = true;
    assert_eq!(patch::render(&changes, &args).unwrap(), " a => y | 0 (+0 -0)\n b => z | 0 (+0 -0)\n 2 files changed, 0 insertions(+), 0 deletions(-)\n");
    args.include_git_dir = true;
    assert!(collect(&args, base.source.as_ref())
        .unwrap()
        .iter()
        .any(|c| c.to == ".git/HEAD"));
}

/// Regression: verb parsing must never consume the overlay as a mountpoint.
#[test]
fn regression_diff_flag_keeps_directory() {
    let args = crate::parse_args_from([
        "ratarmount",
        "diff",
        "overlay",
        "--git",
        "--base",
        "base.tar",
        "-U",
        "0",
    ])
    .unwrap();
    assert!(args.paths.is_empty());
    let diff = args.diff.unwrap();
    assert_eq!(diff.directory, PathBuf::from("overlay"));
    assert_eq!(diff.context, 0);
    assert!(crate::parse_args_from(["ratarmount", "diff", "overlay"])
        .unwrap()
        .diff
        .is_some());
    assert!(crate::parse_args_from(["ratarmount", "diff"]).is_err());
    assert!(crate::parse_args_from(["ratarmount", "diff", "one", "two"]).is_err());
    assert!(crate::parse_args_from(["ratarmount", "diff", "one", "-U", "-1"]).is_err());
    assert!(crate::parse_args_from(["ratarmount", "--no-mount", "diff"])
        .unwrap()
        .diff
        .is_none());
}

/// Regression: missing/corrupt DBs and escaping tombstones fail without initialization.
#[test]
fn regression_diff_database_errors_never_create_or_repair() {
    let tmp = tempfile::tempdir().unwrap();
    assert!(tombstones(tmp.path(), false).is_err());
    assert_eq!(fs::read_dir(tmp.path()).unwrap().count(), 0);
    fs::write(tmp.path().join(HIDDEN_DB), b"corrupt").unwrap();
    assert!(tombstones(tmp.path(), false).is_err());
    assert_eq!(fs::read(tmp.path().join(HIDDEN_DB)).unwrap(), b"corrupt");
    fs::remove_file(tmp.path().join(HIDDEN_DB)).unwrap();
    let conn = Connection::open(tmp.path().join(HIDDEN_DB)).unwrap();
    conn.execute_batch("CREATE TABLE files(path TEXT, name TEXT, deleted INTEGER); INSERT INTO files VALUES('/../', 'outside', 1);").unwrap();
    assert!(tombstones(tmp.path(), false)
        .unwrap_err()
        .contains("invalid overlay path"));
}

/// Regression: an active mount's exclusively locked database must be refused offline.
#[test]
fn regression_diff_active_overlay_is_locked() {
    let tmp = tempfile::tempdir().unwrap();
    let base = ratarmount_compositing::FolderMountSource::new(tmp.path()).unwrap();
    let overlay = WriteOverlay::new(Arc::new(base), tmp.path().join("overlay")).unwrap();
    let root = overlay.root().to_path_buf();
    assert!(tombstones(&root, false).unwrap_err().contains("locked"));
    drop(overlay);
    assert!(tombstones(&root, false).unwrap().is_empty());
}

/// Regression: binary summaries and symlink text must not read through link targets.
#[test]
fn regression_diff_binary_summary_and_symlink_text() {
    let tmp = tempfile::tempdir().unwrap();
    let base = base_tar(
        tmp.path(),
        &[
            ("bin", b"\0before", 0o100644),
            ("link", b"missing-before", 0o120000),
        ],
    );
    let overlay = WriteOverlay::new(Arc::clone(&base.source), tmp.path().join("overlay")).unwrap();
    put(&overlay, "/bin", b"\0after");
    overlay.unlink("/link").unwrap();
    overlay.create_symlink("/link", "missing-after").unwrap();
    let overlay_root = overlay.root().to_path_buf();
    drop(overlay);
    let args = args(&overlay_root);
    let patch = patch::render(&collect(&args, base.source.as_ref()).unwrap(), &args).unwrap();
    assert!(patch.contains("Binary files a/bin and b/bin differ\n"));
    assert!(patch.contains("-missing-before\n\\ No newline at end of file\n+missing-after\n\\ No newline at end of file\n"));
}

/// Regression: Git mode normalization must omit non-executable permission-only changes.
#[test]
fn regression_diff_git_ignores_unrepresentable_permissions() {
    let tmp = tempfile::tempdir().unwrap();
    let base = base_tar(tmp.path(), &[("mode", b"same\n", 0o100644)]);
    let overlay = WriteOverlay::new(Arc::clone(&base.source), tmp.path().join("overlay")).unwrap();
    overlay.ensure_modifiable("/mode").unwrap();
    fs::set_permissions(
        overlay.root().join("mode"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let overlay_root = overlay.root().to_path_buf();
    drop(overlay);
    let mut args = args(&overlay_root);
    let changes = collect(&args, base.source.as_ref()).unwrap();
    assert!(patch::render(&changes, &args)
        .unwrap()
        .contains("new mode 100600\n--- a/mode\n+++ b/mode\n"));
    args.git = true;
    assert!(collect(&args, base.source.as_ref()).unwrap().is_empty());
    fs::set_permissions(overlay_root.join("mode"), fs::Permissions::from_mode(0o654)).unwrap();
    assert!(collect(&args, base.source.as_ref()).unwrap().is_empty());
}
