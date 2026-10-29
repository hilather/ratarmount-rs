use super::*;
use ratarmount_compositing::{is_overlay_internal_path, HIDDEN_DB};
use ratarmount_core::OpenOptions;
use ratarmount_core::S_IFLNK;
use ratarmount_session::factory;
use rusqlite::Connection;
use std::collections::BTreeMap;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;

#[path = "../../tests/diff/cow.rs"]
pub(crate) mod cow;

#[derive(Clone, Debug, PartialEq, Eq)]
struct SnapshotEntry {
    mode: u32,
    data: Vec<u8>,
}
impl SnapshotEntry {
    fn git_mode(&self) -> u32 {
        if self.mode & S_IFMT == S_IFLNK {
            0o120000
        } else if self.mode & 0o100 != 0 {
            0o100755
        } else {
            0o100644
        }
    }
}

fn collect(args: &DiffArgs, source: Arc<dyn MountSource>) -> io::Result<Vec<Change>> {
    render_changes(
        &core::change_set(&args.directory, source, &args.options())?,
        args,
    )
}
fn render_text(changes: &[Change], args: &DiffArgs) -> io::Result<String> {
    let mut output = Vec::new();
    patch::render(changes, args, &mut output)?;
    String::from_utf8(output).map_err(io::Error::other)
}
fn tombstones(root: &Path, _: bool) -> Result<BTreeSet<String>, String> {
    core::mentioned_paths(root).map_err(|e| e.to_string())
}
fn excluded(path: &str, include_git: bool) -> bool {
    is_overlay_internal_path(path) || (!include_git && path.split('/').any(|p| p == ".git"))
}

use ratarmount_compositing::WriteOverlay;
use ratarmount_formats_tar::{write_tar_eof, write_ustar_members, UstarMember, UstarPayload};
use std::os::fd::FromRawFd;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::process::Command;
use std::sync::Arc;

fn args(root: &Path) -> DiffArgs {
    DiffArgs {
        directory: root.into(),
        ..Default::default()
    }
}

fn base_tar(root: &Path, files: &[(&str, &[u8], u32)]) -> factory::MountBundle {
    let path = root.join("base.tar");
    let members: Vec<_> = files
        .iter()
        .map(|(path, bytes, mode)| UstarMember {
            xattrs: &[],
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
    let overlay = crate::base_identity::fixtures::new_overlay(
        Arc::clone(&base.source),
        tmp.path().join("overlay"),
    )
    .unwrap();
    put(&overlay, "/a", b"one\nTWO\nthree\n");
    overlay.unlink("/delete").unwrap();
    put(&overlay, "/empty", b"");
    overlay.ensure_modifiable("/mode").unwrap();
    overlay
        .set_metadata(
            "/mode",
            &ratarmount_compositing::OverlayMetadata {
                mode: Some(0o755),
                ..Default::default()
            },
        )
        .unwrap();
    put(&overlay, "/nested/new", b"new");
    let overlay_root = overlay.root().to_path_buf();
    drop(overlay);
    let args = args(&overlay_root);
    let changes = collect(&args, base.source.clone()).unwrap();
    let output = render_text(&changes, &args).unwrap();
    assert_eq!(output, concat!(
        "--- a/a\n+++ b/a\n@@ -1,3 +1,3 @@\n one\n-two\n+TWO\n three\n",
        "deleted file mode 100644\n--- a/delete\n+++ /dev/null\n@@ -1 +0,0 @@\n-gone\n",
        "new file mode 100644\n--- /dev/null\n+++ b/empty\n",
        "old mode 100644\nnew mode 100755\n--- a/mode\n+++ b/mode\n",
        "new file mode 100644\n--- /dev/null\n+++ b/nested/new\n@@ -0,0 +1 @@\n+new\n\\ No newline at end of file\n",
    ));
}

fn snapshot(source: &dyn MountSource, path: &str, entries: &mut BTreeMap<String, SnapshotEntry>) {
    for child in source.list_dirents(path).unwrap_or_default() {
        let full = format!("{}/{}", path.trim_end_matches('/'), child.name);
        if excluded(&full, false) {
            continue;
        }
        let fi = source.lookup(&full, 0).unwrap();
        if fi.mode & S_IFMT == S_IFDIR {
            snapshot(source, &full, entries);
        } else {
            let mut data = Vec::new();
            if fi.mode & S_IFMT == S_IFLNK {
                data.extend_from_slice(fi.linkname.as_bytes());
            } else {
                source.open(&fi, 0).unwrap().read_to_end(&mut data).unwrap();
            }
            let mut entry = SnapshotEntry {
                mode: fi.mode,
                data,
            };
            entry.mode = entry.git_mode();
            entries.insert(full.trim_start_matches('/').into(), entry);
        }
    }
}

fn materialize(entries: &BTreeMap<String, SnapshotEntry>, root: &Path) {
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
    let _processes = ratarmount_index::test_process::spawning();
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
    let overlay = crate::base_identity::fixtures::new_overlay(
        Arc::clone(&base.source),
        tmp.path().join("overlay"),
    )
    .unwrap();
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
    overlay
        .set_metadata(
            "/mode",
            &ratarmount_compositing::OverlayMetadata {
                mode: Some(0o644),
                ..Default::default()
            },
        )
        .unwrap();
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
    let changes = collect(&args, base.source.clone()).unwrap();
    let patch = render_text(&changes, &args).unwrap();
    assert!(!patch.contains("rename from"));
    let mut renamed = DiffArgs {
        directory: overlay_root.clone(),
        ..Default::default()
    };
    renamed.git = true;
    renamed.detect_renames = true;
    let renamed_patch =
        render_text(&collect(&renamed, base.source.clone()).unwrap(), &renamed).unwrap();
    assert!(
        renamed_patch.contains("similarity index 100%\nrename from rename\nrename to renamed\n")
    );
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
    let overlay = crate::base_identity::fixtures::new_overlay(
        Arc::clone(&base.source),
        tmp.path().join("overlay"),
    )
    .unwrap();
    overlay.unlink("/a").unwrap();
    overlay.unlink("/b").unwrap();
    put(&overlay, "/y", b"same\n");
    put(&overlay, "/z", b"same\n");
    fs::create_dir_all(overlay.root().join(".git")).unwrap();
    put(&overlay, "/.git/HEAD", b"head");
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
    args.detect_renames = true;
    let changes = collect(&args, base.source.clone()).unwrap();
    assert_eq!(
        render_text(&changes, &args).unwrap(),
        "R100\ta\ty\nR100\tb\tz\nA\tnested\n"
    );
    args.name_status = false;
    args.stat = true;
    assert_eq!(render_text(&changes, &args).unwrap(), " a => y | 0 (+0 -0)\n b => z | 0 (+0 -0)\n nested | 0 (+0 -0)\n 3 files changed, 0 insertions(+), 0 deletions(-), 10 bytes written\n");
    args.include_git_dir = true;
    assert!(collect(&args, base.source.clone())
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
    let positional = crate::parse_args_from(["ratarmount", "diff", "one", "two"]).unwrap();
    assert!(positional.paths.is_empty());
    assert_eq!(
        positional.diff.unwrap().base_source,
        Some(PathBuf::from("two"))
    );
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
    let overlay =
        crate::base_identity::fixtures::new_overlay(Arc::new(base), tmp.path().join("overlay"))
            .unwrap();
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
    let overlay = crate::base_identity::fixtures::new_overlay(
        Arc::clone(&base.source),
        tmp.path().join("overlay"),
    )
    .unwrap();
    put(&overlay, "/bin", b"\0after");
    overlay.unlink("/link").unwrap();
    overlay.create_symlink("/link", "missing-after").unwrap();
    let overlay_root = overlay.root().to_path_buf();
    drop(overlay);
    let args = args(&overlay_root);
    let patch = render_text(&collect(&args, base.source.clone()).unwrap(), &args).unwrap();
    assert!(patch.contains("Binary files a/bin and b/bin differ\n"));
    assert!(patch.contains("-missing-before\n\\ No newline at end of file\n+missing-after\n\\ No newline at end of file\n"));
}

/// Regression: Git mode normalization must omit non-executable permission-only changes.
#[test]
fn regression_diff_git_ignores_unrepresentable_permissions() {
    let tmp = tempfile::tempdir().unwrap();
    let base = base_tar(tmp.path(), &[("mode", b"same\n", 0o100644)]);
    let overlay = crate::base_identity::fixtures::new_overlay(
        Arc::clone(&base.source),
        tmp.path().join("overlay"),
    )
    .unwrap();
    overlay.ensure_modifiable("/mode").unwrap();
    overlay
        .set_metadata(
            "/mode",
            &ratarmount_compositing::OverlayMetadata {
                mode: Some(0o600),
                ..Default::default()
            },
        )
        .unwrap();
    let overlay_root = overlay.root().to_path_buf();
    drop(overlay);
    let mut args = args(&overlay_root);
    let changes = collect(&args, base.source.clone()).unwrap();
    assert!(render_text(&changes, &args)
        .unwrap()
        .contains("new mode 100600\n--- a/mode\n+++ b/mode\n"));
    args.git = true;
    assert!(
        render_text(&collect(&args, base.source.clone()).unwrap(), &args)
            .unwrap()
            .is_empty()
    );
    fs::set_permissions(overlay_root.join("mode"), fs::Permissions::from_mode(0o654)).unwrap();
    assert!(
        render_text(&collect(&args, base.source.clone()).unwrap(), &args)
            .unwrap()
            .is_empty()
    );
}

fn git_roundtrip_case(case: &str) {
    let _processes = ratarmount_index::test_process::spawning();
    let tmp = tempfile::tempdir().unwrap();
    let baseline: &[(&str, &[u8], u32)] = match case {
        "added" | "empty_dir" | "nested" => &[],
        "symlink" => &[("file", b"old-target", 0o120000)],
        "binary" => &[("file", b"\0old\xff", 0o100644)],
        "crlf" => &[("file", b"a\r\nb\r\n", 0o100644)],
        "no_newline" => &[("file", b"before", 0o100644)],
        "latin1" => &[("file", b"caf\xe9\nold\xff\n", 0o100644)],
        _ => &[("file", b"old\n", 0o100644)],
    };
    let base = base_tar(tmp.path(), baseline);
    let dir = tmp.path().join("overlay");
    let overlay = crate::base_identity::fixtures::new_overlay(base.source.clone(), &dir).unwrap();
    match case {
        "added" => put(&overlay, "/file", b"added\n"),
        "modified" => cow::cow_write(&overlay, "/file", b"modified\n"),
        "deleted" => overlay.unlink("/file").unwrap(),
        "type_changed" => {
            overlay.unlink("/file").unwrap();
            overlay.create_symlink("/file", "target").unwrap();
        }
        "symlink" => {
            overlay.unlink("/file").unwrap();
            overlay.create_symlink("/file", "new-target").unwrap();
        }
        "empty_dir" => overlay.mkdir("/empty", 0o755).unwrap(),
        "mode" => overlay
            .set_metadata(
                "/file",
                &ratarmount_compositing::OverlayMetadata {
                    mode: Some(0o755),
                    ..Default::default()
                },
            )
            .unwrap(),
        "binary" => cow::cow_write(&overlay, "/file", b"\0new\xfe"),
        "nested" => put(&overlay, "/dir/subdir/file", b"nested\n"),
        "crlf" => cow::cow_write(&overlay, "/file", b"a\r\nB\r\n"),
        "no_newline" => cow::cow_write(&overlay, "/file", b"after"),
        "latin1" => cow::cow_write(&overlay, "/file", b"caf\xe9\nnew\xfe\n"),
        _ => unreachable!(),
    }
    let mut expected = BTreeMap::new();
    snapshot(&overlay, "/", &mut expected);
    drop(overlay);
    let opts = DiffArgs {
        directory: dir.clone(),
        git: true,
        ..Default::default()
    };
    let changes = core::change_set(&dir, base.source.clone(), &opts.options()).unwrap();
    assert_eq!(changes.len(), if case == "nested" { 3 } else { 1 });
    if case == "nested" {
        assert_eq!(changes[0].manifest_row()["path"], "dir");
        assert_eq!(changes[1].manifest_row()["path"], "dir/subdir");
        assert!(changes[..2]
            .iter()
            .all(|c| c.kind() == "dir" && c.status == core::Status::Added));
    }
    if case == "empty_dir" {
        assert_eq!(changes[0].manifest_row()["type"], "dir");
    }
    let mut patch = Vec::new();
    patch::render(&render_changes(&changes, &opts).unwrap(), &opts, &mut patch).unwrap();
    if case == "latin1" {
        assert!(patch
            .windows(b"+new\xfe\n".len())
            .any(|w| w == b"+new\xfe\n"));
        assert!(!patch.windows(16).any(|w| w == b"GIT binary patch"));
    }
    if Command::new("git").arg("--version").output().is_err() {
        eprintln!("skip: git is unavailable ({case} round trip)");
        return;
    }
    let checkout = tmp.path().join("checkout");
    fs::create_dir(&checkout).unwrap();
    let mut initial = BTreeMap::new();
    snapshot(base.source.as_ref(), "/", &mut initial);
    materialize(&initial, &checkout);
    assert!(Command::new("git")
        .arg("init")
        .arg("--quiet")
        .current_dir(&checkout)
        .status()
        .unwrap()
        .success());
    // Git does not represent empty directories. Its projection must still match
    // every representable entry; the directory is checked in the manifest above.
    if !patch.is_empty() {
        let file = tmp.path().join("edit.patch");
        fs::write(&file, &patch).unwrap();
        let result = Command::new("git")
            .args(["apply", "--binary"])
            .arg(file)
            .current_dir(&checkout)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{case}: {}\n{}",
            String::from_utf8_lossy(&result.stderr),
            String::from_utf8_lossy(&patch)
        );
    }
    let folder = ratarmount_compositing::FolderMountSource::new(&checkout).unwrap();
    let mut actual = BTreeMap::new();
    snapshot(&folder, "/", &mut actual);
    assert_eq!(actual, expected, "{case}");
}

macro_rules! roundtrip_tests {
    ($($name:ident => $case:literal),* $(,)?) => {$(
        #[doc = concat!("Regression: git apply round trip for ", $case, ".")]
        #[test]
        fn $name() { git_roundtrip_case($case); }
    )*};
}
roundtrip_tests! {
    regression_diff_roundtrip_added => "added",
    regression_diff_roundtrip_modified => "modified",
    regression_diff_roundtrip_deleted => "deleted",
    regression_diff_roundtrip_type_changed => "type_changed",
    regression_diff_roundtrip_symlink => "symlink",
    regression_diff_roundtrip_empty_dir_manifest => "empty_dir",
    regression_diff_roundtrip_mode => "mode",
    regression_diff_roundtrip_binary => "binary",
    regression_diff_roundtrip_nested => "nested",
    regression_diff_roundtrip_crlf => "crlf",
    regression_diff_roundtrip_no_newline => "no_newline",
    regression_diff_roundtrip_latin1 => "latin1",
}

fn command_fixture() -> (tempfile::TempDir, DiffArgs) {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().join("base");
    fs::create_dir(&base).unwrap();
    fs::write(base.join("a"), b"old\n").unwrap();
    let dir = tmp.path().join("overlay");
    let source = Arc::new(ratarmount_compositing::FolderMountSource::new(&base).unwrap());
    let overlay = crate::base_identity::fixtures::new_overlay(source, &dir).unwrap();
    put(&overlay, "/a", b"new\n");
    drop(overlay);
    let args = DiffArgs {
        directory: dir,
        base_source: Some(base),
        output: Some(tmp.path().join("output")),
        ..Default::default()
    };
    (tmp, args)
}
fn meta_set(dir: &Path, keys: &[(&str, &str)]) {
    let conn = Connection::open(dir.join(HIDDEN_DB)).unwrap();
    OverlayMeta::set_many(&conn, keys).unwrap();
}
fn output(args: &DiffArgs) -> Vec<u8> {
    fs::read(args.output.as_ref().unwrap()).unwrap()
}

/// Regression: all base-less modes work, patch/stat refuse, and metadata resolves an omitted BASE.
#[test]
fn regression_diff_base_omitted_modes_and_metadata_default() {
    let (_tmp, mut args) = command_fixture();
    let base = args.base_source.take().unwrap();
    assert_eq!(run(&args, &Default::default()), 2);
    args.stat = true;
    assert_eq!(run(&args, &Default::default()), 2);
    args.stat = false;
    args.manifest = true;
    assert_eq!(run(&args, &Default::default()), 0);
    let row: serde_json::Value = serde_json::from_slice(&output(&args)).unwrap();
    assert_eq!(row["status"], "written");
    assert!(row.get("base_hash").is_none());
    args.manifest = false;
    args.hash = true;
    args.json = true;
    assert_eq!(run(&args, &Default::default()), 0);
    let row: serde_json::Value = serde_json::from_slice(&output(&args)).unwrap();
    assert_eq!(row["files"], 1);
    assert_eq!(row["base"], "none");
    args.hash = false;
    args.json = false;
    args.name_only = true;
    assert_eq!(run(&args, &Default::default()), 1);
    assert_eq!(output(&args), b"a\n");
    args.name_only = false;
    args.name_status = true;
    assert_eq!(run(&args, &Default::default()), 1);
    assert_eq!(output(&args), b"written\ta\n");
    args.name_status = false;
    meta_set(&args.directory, &[("base_url", base.to_str().unwrap())]);
    assert_eq!(run(&args, &Default::default()), 1);
    assert!(String::from_utf8(output(&args))
        .unwrap()
        .contains("-old\n+new\n"));
}

/// Regression: hidden --base remains compatible and a positional BASE takes precedence.
#[test]
fn regression_diff_positional_alias_and_mode_conflicts() {
    let (_tmp, mut args) = command_fixture();
    args.base = Some("missing-alias-base".into());
    assert_eq!(run(&args, &Default::default()), 1);
    args.base = args.base_source.take();
    assert_eq!(run(&args, &Default::default()), 1);
    for modes in [
        ["--git", "--manifest"],
        ["--patch", "--hash"],
        ["--stat", "--name-status"],
    ] {
        assert!(DiffArgs::try_parse_from(["diff", "dir", modes[0], modes[1]]).is_err());
    }
    assert!(DiffArgs::try_parse_from(["diff", "dir", "--algo", "unknown"]).is_err());
    let mut help = Vec::new();
    use clap::CommandFactory;
    DiffArgs::command().write_long_help(&mut help).unwrap();
    let help = String::from_utf8(help).unwrap();
    assert!(help.contains("3  Size/file limit exceeded"));
    assert!(!help.contains("--base <"));
}

/// Regression: --strict checks top and lower seals; hash JSON uses recorded identity.
#[test]
fn regression_diff_seals_lowers_and_hash_json() {
    let (tmp, mut args) = command_fixture();
    args.hash = true;
    args.json = true;
    args.strict = true;
    assert_eq!(run(&args, &Default::default()), 2);
    meta_set(
        &args.directory,
        &[
            ("sealed_at", "now"),
            ("base_digest", "sha256:base"),
            ("stack_digest", "sha256:stack"),
        ],
    );
    assert_eq!(run(&args, &Default::default()), 0);
    let row: serde_json::Value = serde_json::from_slice(&output(&args)).unwrap();
    assert_eq!(row["base"], "sha256:base");
    assert_eq!(row["stack"], "sha256:stack");
    assert_eq!(row["sealed"], true);
    assert_eq!(row["normalize"], "exact");
    assert_eq!(row["algo"], "sha256");
    let lower = tmp.path().join("lower");
    drop(
        crate::base_identity::fixtures::new_overlay(
            Arc::new(
                ratarmount_compositing::FolderMountSource::new(args.base_source.as_ref().unwrap())
                    .unwrap(),
            ),
            &lower,
        )
        .unwrap(),
    );
    args.lower.push(lower.clone());
    assert_eq!(run(&args, &Default::default()), 2);
    meta_set(&lower, &[("sealed_at", "now")]);
    assert_eq!(run(&args, &Default::default()), 0);
    let conn = Connection::open(args.directory.join(HIDDEN_DB)).unwrap();
    conn.execute("DELETE FROM meta WHERE key='stack_digest'", [])
        .unwrap();
    drop(conn);
    assert_eq!(run(&args, &Default::default()), 0);
    let row: serde_json::Value = serde_json::from_slice(&output(&args)).unwrap();
    assert_eq!(
        row["stack"],
        ratarmount_compositing::stack_digest("sha256:base", &[])
    );
    args.strict = false;
    let conn = Connection::open(args.directory.join(HIDDEN_DB)).unwrap();
    conn.execute("DROP TABLE meta", []).unwrap();
    drop(conn);
    assert_eq!(run(&args, &Default::default()), 0);
}

/// Regression: a pending archive base (digest recorded as "") made
/// `diff --hash --json` derive a stack digest from the empty string, so every
/// uncached archive emitted the same stack key. Base and stack are null.
#[test]
fn regression_diff_hash_json_pending_base_has_no_stack() {
    let (_tmp, mut args) = command_fixture();
    args.hash = true;
    args.json = true;
    meta_set(
        &args.directory,
        &[("base_digest_kind", "pending"), ("base_digest", "")],
    );
    let conn = Connection::open(args.directory.join(HIDDEN_DB)).unwrap();
    conn.execute("DELETE FROM meta WHERE key='stack_digest'", [])
        .unwrap();
    drop(conn);
    assert_eq!(run(&args, &Default::default()), 0);
    let row: serde_json::Value = serde_json::from_slice(&output(&args)).unwrap();
    assert!(row["base"].is_null(), "{row}");
    assert!(row["stack"].is_null(), "{row}");
    assert_eq!(row["base_pending"], true);
    assert_eq!(row["base_digest_state"], "pending");
}

/// `diff --hash --json` reports `base_digest_state` for present and none too.
#[test]
fn regression_diff_hash_json_base_digest_state_present_and_none() {
    for (kind, digest, state) in [
        ("strong", "sha256:abc", "present"),
        ("weak", "sha256:def", "present"),
        ("none", "none", "none"),
    ] {
        let (_tmp, mut args) = command_fixture();
        args.hash = true;
        args.json = true;
        // A made-up strong digest cannot match the real base; the state is
        // what is under test, so override the (intended) identity refusal.
        args.identity.force_base_mismatch = kind == "strong";
        meta_set(
            &args.directory,
            &[("base_digest_kind", kind), ("base_digest", digest)],
        );
        assert_eq!(run(&args, &Default::default()), 0);
        let row: serde_json::Value = serde_json::from_slice(&output(&args)).unwrap();
        assert_eq!(row["base_digest_state"], state, "{kind}: {row}");
        assert_eq!(row["base_pending"], false, "{kind}: {row}");
    }
}

/// Regression: --between rejects different stacks, gives the empty constant for identical trees, and applies A→B.
#[test]
fn regression_diff_between_stack_checks_and_apply() {
    let _processes = ratarmount_index::test_process::spawning();
    let (tmp, mut args) = command_fixture();
    let base: Arc<dyn MountSource> = Arc::new(
        ratarmount_compositing::FolderMountSource::new(args.base_source.as_ref().unwrap()).unwrap(),
    );
    let other = tmp.path().join("other");
    let ov = crate::base_identity::fixtures::new_overlay(base.clone(), &other).unwrap();
    put(&ov, "/a", b"new\n");
    drop(ov);
    meta_set(&args.directory, &[("stack_digest", "same")]);
    meta_set(&other, &[("stack_digest", "different")]);
    args.between = Some(other.clone());
    args.hash = true;
    assert_eq!(run(&args, &Default::default()), 2);
    meta_set(&other, &[("stack_digest", "same")]);
    assert_eq!(run(&args, &Default::default()), 0);
    assert_eq!(
        output(&args),
        format!("{}\n", core::EMPTY_SHA256).as_bytes()
    );
    let ov = crate::base_identity::fixtures::new_overlay(base.clone(), &args.directory).unwrap();
    put(&ov, "/a", b"second\n");
    put(&ov, "/extra", b"extra\n");
    drop(ov);
    args.hash = false;
    args.git = true;
    assert_eq!(run(&args, &Default::default()), 1);
    let checkout = tmp.path().join("checkout");
    fs::create_dir(&checkout).unwrap();
    fs::write(checkout.join("a"), b"new\n").unwrap();
    if Command::new("git").arg("--version").output().is_ok() {
        let result = Command::new("git")
            .arg("apply")
            .arg(args.output.as_ref().unwrap())
            .current_dir(&checkout)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(fs::read(checkout.join("a")).unwrap(), b"second\n");
        assert_eq!(fs::read(checkout.join("extra")).unwrap(), b"extra\n");
    } else {
        eprintln!("skip: git unavailable for --between apply");
    }
    for dir in [&args.directory, &other] {
        Connection::open(dir.join(HIDDEN_DB))
            .unwrap()
            .execute("DROP TABLE meta", [])
            .unwrap();
    }
    assert_eq!(run(&args, &Default::default()), 2);
    let lower = tmp.path().join("lower");
    drop(crate::base_identity::fixtures::new_overlay(base, &lower).unwrap());
    args.lower.push(lower);
    assert_eq!(run(&args, &Default::default()), 1);
}

/// Regression: output and work bounds exit 3 without publishing partial patches; manifests ignore patch limits.
#[test]
fn regression_diff_limits_and_sparse_file_exit_three() {
    let (_tmp, mut args) = command_fixture();
    args.max_patch_bytes = Some(1);
    fs::write(args.output.as_ref().unwrap(), b"keep").unwrap();
    assert_eq!(run(&args, &Default::default()), 3);
    assert_eq!(output(&args), b"keep");
    args.max_patch_bytes = Some(8);
    assert_eq!(run(&args, &Default::default()), 3); // Fits input, not headers.
    fs::OpenOptions::new()
        .write(true)
        .open(args.directory.join("a"))
        .unwrap()
        .set_len(10 * 1024 * 1024 * 1024)
        .unwrap();
    args.max_patch_bytes = Some(1024);
    let start = std::time::Instant::now();
    assert_eq!(run(&args, &Default::default()), 3);
    assert!(start.elapsed() < std::time::Duration::from_secs(10));
    // The streaming hasher is tested independently with bounded reader chunks;
    // keep the routine CLI test small rather than hashing 10 GiB in debug mode.
    fs::OpenOptions::new()
        .write(true)
        .open(args.directory.join("a"))
        .unwrap()
        .set_len(1024 * 1024)
        .unwrap();
    args.manifest = true;
    assert_eq!(run(&args, &Default::default()), 0);
    args.max_files = Some(0);
    assert_eq!(run(&args, &Default::default()), 3);
    args.max_files = None;
    args.manifest = false;
    args.max_patch_bytes = None;
    args.stat = true;
    args.json = true;
    assert_eq!(run(&args, &Default::default()), 1);
    let row: serde_json::Value = serde_json::from_slice(&output(&args)).unwrap();
    assert_eq!(row["bytes_written"], 1024 * 1024);
}

/// Regression: normalization and rename detection never change exact patch bytes or manifest identity.
#[test]
fn regression_diff_normalize_does_not_rewrite_patch_and_renames_opt_in() {
    let (_tmp, mut args) = command_fixture();
    args.git = true;
    assert_eq!(run(&args, &Default::default()), 1);
    let exact = output(&args);
    args.normalize = "loose".into();
    assert_eq!(run(&args, &Default::default()), 1);
    assert_eq!(output(&args), exact);
    args.git = false;
    args.hash = true;
    args.normalize = "exact".into();
    assert_eq!(run(&args, &Default::default()), 0);
    let hash = output(&args);
    args.detect_renames = true;
    assert_eq!(run(&args, &Default::default()), 0);
    assert_eq!(output(&args), hash);
    args.hash = false;
    args.manifest = true;
    assert_eq!(run(&args, &Default::default()), 0);
    let manifest = output(&args);
    args.detect_renames = false;
    assert_eq!(run(&args, &Default::default()), 0);
    assert_eq!(output(&args), manifest);
    args.manifest = false;
    args.hash = true;
    args.algo = "blake3".into();
    assert_eq!(run(&args, &Default::default()), 0);
    assert!(output(&args).starts_with(b"blake3:"));
}

/// Regression: text above --max-diff-bytes deliberately falls back to Git literals and round-trips.
#[test]
fn regression_diff_large_text_binary_fallback() {
    let (_tmp, mut args) = command_fixture();
    args.git = true;
    args.max_diff_bytes = 1;
    assert_eq!(run(&args, &Default::default()), 1);
    let patch = output(&args);
    assert!(String::from_utf8(patch)
        .unwrap()
        .contains("GIT binary patch\nliteral 4\n"));
}

/// Regression: the live socket renderer preserves Latin-1 byte hunks without opening locked SQLite.
#[test]
fn regression_diff_live_latin1_socket_bytes() {
    let tmp = tempfile::tempdir().unwrap();
    let base = base_tar(tmp.path(), &[("a", b"before\xff\n", 0o100644)]);
    let dir = tmp.path().join("overlay");
    let overlay = crate::base_identity::fixtures::new_overlay(base.source.clone(), &dir).unwrap();
    put(&overlay, "/a", b"after\xfe\n");
    let args = DiffArgs {
        directory: dir,
        git: true,
        ..Default::default()
    };
    let bytes = render_source(&args, base.source, Some(vec![])).unwrap();
    assert!(bytes
        .windows(b"+after\xfe\n".len())
        .any(|w| w == b"+after\xfe\n"));
    let mut json = serde_json::Map::new();
    core::json_bytes(&mut json, "patch", &bytes);
    assert!(json.contains_key("patch_b64"));
    assert!(!json.contains_key("patch"));
}

/// Regression: a 10 GiB sparse payload produces a manifest using bounded content buffers.
#[test]
#[ignore = "scale test: streams 10 GiB; run explicitly with --ignored"]
fn regression_diff_sparse_manifest_streams_ten_gib() {
    let (_tmp, mut args) = command_fixture();
    fs::OpenOptions::new()
        .write(true)
        .open(args.directory.join("a"))
        .unwrap()
        .set_len(10 * 1024 * 1024 * 1024)
        .unwrap();
    args.manifest = true;
    args.max_patch_bytes = Some(1024);
    assert_eq!(run(&args, &Default::default()), 0);
    let row: serde_json::Value = serde_json::from_slice(&output(&args)).unwrap();
    assert_eq!(row["size"], 10u64 * 1024 * 1024 * 1024);
    assert!(row["hash"].as_str().unwrap().starts_with("sha256:"));
}

/// Regression: recorded lowers are opened when --lower is omitted and copy-ups compare against the prepared bytes.
#[test]
fn regression_diff_recorded_lowers_default_and_copy_up() {
    let (tmp, mut args) = command_fixture();
    let base: Arc<dyn MountSource> = Arc::new(
        ratarmount_compositing::FolderMountSource::new(args.base_source.as_ref().unwrap()).unwrap(),
    );
    let lower_dir = tmp.path().join("prepared");
    let prepared = crate::base_identity::fixtures::new_overlay(base.clone(), &lower_dir).unwrap();
    put(&prepared, "/a", b"prepared\n");
    put(&prepared, "/blib/x", b"build\n");
    drop(prepared);
    let records = serde_json::to_string(&vec![ratarmount_compositing::LowerLayerRecord {
        path: lower_dir.clone(),
        layer_digest: "sha256:prepared".into(),
        sealed_at: "now".into(),
    }])
    .unwrap();
    meta_set(&lower_dir, &[("sealed_at", "now")]);
    meta_set(&args.directory, &[("lower_layers", &records)]);
    args.manifest = true;
    assert_eq!(run(&args, &Default::default()), 0);
    let row: serde_json::Value = serde_json::from_slice(&output(&args)).unwrap();
    assert_eq!(row["path"], "a");
    assert_eq!(row["status"], "modified");
    assert_eq!(row["base_layer"], "lower:1");
    args.manifest = false;
    args.git = true;
    assert_eq!(run(&args, &Default::default()), 1);
    assert!(String::from_utf8(output(&args))
        .unwrap()
        .contains("-prepared\n+new\n"));
    let lower = compose_stack(base, &[(lower_dir, Immutability::Immutable)]).unwrap();
    let attempt = crate::base_identity::fixtures::new_overlay(lower, &args.directory).unwrap();
    put(&attempt, "/a", b"prepared\n");
    attempt.unlink("/blib/x").unwrap();
    drop(attempt);
    args.git = false;
    args.name_status = true;
    assert_eq!(run(&args, &Default::default()), 1);
    assert_eq!(output(&args), b"D\tblib/x\n");
}
