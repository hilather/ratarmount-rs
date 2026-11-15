use super::*;
use ratarmount_compositing::overlay_changes::{canonical_hash, change_set, ChangeOptions};
use ratarmount_compositing::{Immutability, OverlayMeta, ReadOnlyOverlayLayer};
use ratarmount_core::OpenOptions;
use ratarmount_formats_tar::{write_tar_eof, write_ustar_members, UstarMember, UstarPayload};
use ratarmount_session::factory;
use std::io::Write;

use crate::diff::tests::cow;

struct Fixture {
    temp: tempfile::TempDir,
    base: PathBuf,
    source: Arc<dyn MountSource>,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().join("base.tar");
        let mut file = fs::File::create(&base).unwrap();
        let files: &[(&str, &[u8])] = &[
            ("a", b"one\ntwo\nthree\n"),
            ("delete", b"remove me\n"),
            ("type", b"regular\n"),
            ("mode", b"same\n"),
            ("nested/base", b"keep\n"),
            ("crlf", b"old\r\n"),
            ("no-newline", b"old"),
            ("latin", b"caf\xe9\n"),
            ("binary", b"\x00old binary"),
        ];
        let mut members: Vec<_> = files
            .iter()
            .map(|(path, bytes)| UstarMember {
                path,
                payload: UstarPayload::File { bytes },
                mode: 0o644,
                uid: 0,
                gid: 0,
                mtime: 0,
                xattrs: &[],
            })
            .collect();
        members.push(UstarMember {
            path: "link",
            payload: UstarPayload::Symlink { target: "a" },
            mode: 0o777,
            uid: 0,
            gid: 0,
            mtime: 0,
            xattrs: &[],
        });
        write_ustar_members(&mut file, &members).unwrap();
        write_tar_eof(&mut file).unwrap();
        drop(file);
        let source = factory::open_path(
            &base,
            &OpenOptions {
                index_in_memory: true,
                write_index: false,
                ..Default::default()
            },
            false,
        )
        .unwrap();
        Self { temp, base, source }
    }

    fn args(&self, name: &str) -> ImportArgs {
        ImportArgs {
            lower: Vec::new(),
            allow_unsealed_lower: false,
            mtime: "1234567890".into(),
            no_seal: true,
            reject: false,
            json: true,
            max_patch_bytes: 16 * 1024 * 1024,
            patch: self.temp.path().join("patch"),
            directory: self.temp.path().join(name),
            base: self.base.to_str().unwrap().into(),
        }
    }

    fn apply(&self, args: &ImportArgs, bytes: &[u8]) -> Result<(String, i32), String> {
        let parsed = parse::parse(bytes, args.max_patch_bytes).map_err(|e| e.to_string())?;
        import(
            args,
            &parsed,
            ImportStack {
                base: crate::base_identity::fixtures::classify(&self.base),
                view: self.source.clone(),
                lower_layers: Vec::new(),
                inputs: vec![self.base.clone()],
            },
            mtime(&args.mtime)?,
        )
    }

    fn hash(&self, dir: &Path) -> String {
        let opts = ChangeOptions::default();
        canonical_hash(&change_set(dir, self.source.clone(), &opts).unwrap(), &opts).unwrap()
    }

    fn view(&self, dir: &Path) -> ReadOnlyOverlayLayer {
        ReadOnlyOverlayLayer::new(self.source.clone(), dir, Immutability::Shared).unwrap()
    }
}

fn put(overlay: &WriteOverlay, path: &str, data: &[u8], mode: u32) {
    let fd = overlay.create_file(path, mode).unwrap();
    let mut file = unsafe { fs::File::from_raw_fd(fd) };
    file.write_all(data).unwrap();
    overlay.finish_owned_write_fd(file);
    overlay
        .set_metadata(
            path,
            &OverlayMetadata {
                mode: Some(mode),
                ..Default::default()
            },
        )
        .unwrap();
}

fn roundtrip(case: &str) {
    let f = Fixture::new();
    let a = f.temp.path().join("a-overlay");
    let ov = crate::base_identity::fixtures::overlay_over(
        f.source.clone(),
        &a,
        f.base.to_str().unwrap(),
        Vec::new(),
    )
    .unwrap();
    match case {
        "added" => put(&ov, "/new", b"added\n", 0o644),
        "modified" => cow::cow_write(&ov, "/a", b"one\nchanged\nthree\n"),
        "deleted" => ov.unlink("/delete").unwrap(),
        "type_changed" => {
            ov.unlink("/type").unwrap();
            ov.create_symlink("/type", "a").unwrap();
        }
        "symlink_to_file" => {
            ov.unlink("/link").unwrap();
            put(&ov, "/link", b"regular now\n", 0o644);
        }
        "symlink" => ov.create_symlink("/new-link", "../../outside").unwrap(),
        "symlink_modified" => {
            ov.unlink("/link").unwrap();
            ov.create_symlink("/link", "new target").unwrap();
        }
        "empty_file" => put(&ov, "/empty", b"", 0o644),
        "mode" => ov
            .set_metadata(
                "/mode",
                &OverlayMetadata {
                    mode: Some(0o755),
                    ..Default::default()
                },
            )
            .unwrap(),
        "binary" => cow::cow_write(&ov, "/binary", b"\x00new\xffbinary\x01\x02"),
        "binary_added" => put(&ov, "/new-bin", b"\x00binary added", 0o644),
        "binary_deleted" => ov.unlink("/binary").unwrap(),
        "nested" => {
            ov.mkdir("/new-dir", 0o755).unwrap();
            ov.mkdir("/new-dir/sub", 0o755).unwrap();
            put(&ov, "/new-dir/sub/file", b"nested\n", 0o644);
        }
        "crlf" => cow::cow_write(&ov, "/crlf", b"new\r\nsecond\r\n"),
        "no_newline" => cow::cow_write(&ov, "/no-newline", b"new"),
        "latin1" => cow::cow_write(&ov, "/latin", b"caf\xe9, d\xe9j\xe0 vu\n"),
        "quoted" => put(&ov, "/caf\u{e9}\t\"\\.txt", b"quoted\n", 0o644),
        "empty_dir" => ov.mkdir("/empty-dir", 0o755).unwrap(),
        "file_to_dir" => {
            ov.unlink("/type").unwrap();
            ov.mkdir("/type", 0o755).unwrap();
            put(&ov, "/type/y", b"inside\n", 0o644);
        }
        "dir_to_file" => {
            ov.unlink("/nested/base").unwrap();
            ov.rmdir("/nested").unwrap();
            put(&ov, "/nested", b"now a file\n", 0o644);
        }
        _ => unreachable!(),
    }
    drop(ov);
    let args = f.args("imported");
    let diff = crate::diff::DiffArgs {
        directory: a.clone(),
        base_source: Some(f.base.clone()),
        git: true,
        output: Some(args.patch.clone()),
        ..Default::default()
    };
    assert_eq!(crate::diff::run(&diff, &Default::default()), 1);
    let patch = fs::read(&args.patch).unwrap();
    let (_, code) = f
        .apply(&args, &patch)
        .unwrap_or_else(|e| panic!("{case}: {e}\n{}", String::from_utf8_lossy(&patch)));
    assert_eq!(code, 0);
    if case == "empty_dir" {
        assert!(patch.is_empty());
        assert!(f.view(&args.directory).lookup("/empty-dir", 0).is_none());
        assert_ne!(f.hash(&a), f.hash(&args.directory));
    } else {
        assert_eq!(f.hash(&a), f.hash(&args.directory), "{case}");
    }
}

macro_rules! roundtrips {
    ($($name:ident => $case:literal),* $(,)?) => { $(
        /// Regression: diff -> import must retain exact content, type and mode.
        #[test]
        fn $name() { roundtrip($case); }
    )* };
}
roundtrips! {
    regression_import_roundtrip_added => "added",
    regression_import_roundtrip_modified => "modified",
    regression_import_roundtrip_deleted => "deleted",
    regression_import_roundtrip_type_changed => "type_changed",
    regression_import_roundtrip_symlink_to_file => "symlink_to_file",
    regression_import_roundtrip_symlink => "symlink",
    regression_import_roundtrip_symlink_modified => "symlink_modified",
    regression_import_roundtrip_empty_file => "empty_file",
    regression_import_roundtrip_mode => "mode",
    regression_import_roundtrip_binary_literal => "binary",
    regression_import_roundtrip_binary_added => "binary_added",
    regression_import_roundtrip_binary_deleted => "binary_deleted",
    regression_import_roundtrip_nested_dirs => "nested",
    regression_import_roundtrip_crlf => "crlf",
    regression_import_roundtrip_no_newline => "no_newline",
    regression_import_roundtrip_latin1 => "latin1",
    regression_import_roundtrip_quoted_paths => "quoted",
    regression_import_empty_dirs_are_not_representable => "empty_dir",
    regression_import_roundtrip_file_replaced_by_directory => "file_to_dir",
    regression_import_roundtrip_directory_replaced_by_file => "dir_to_file",
}

/// Regression: exact context may move, but mismatched context is never fuzzed.
#[test]
fn regression_import_offset_hunks_without_fuzz() {
    let patches = parse::parse(
        b"--- a/a\n+++ b/a\n@@ -1,2 +1,2 @@\n one\n-two\n+TWO\n@@ -3 +3 @@\n-three\n+THREE\n",
        1024,
    )
    .unwrap();
    let hunks = &patches[0].hunks;
    let (result, failed) = apply_hunks(b"prefix\none\ntwo\nthree\n", hunks, 1024).unwrap();
    assert!(failed.is_empty());
    assert_eq!(result, b"prefix\none\nTWO\nTHREE\n");
    let (_, failed) = apply_hunks(b"ONE\ntwo\nthree\n", hunks, 1024).unwrap();
    assert_eq!(failed, [0]);
    let p = parse::parse(b"--- a/a\n+++ b/a\n@@ -99,0 +100 @@\n+oops\n", 1024).unwrap();
    assert_eq!(apply_hunks(b"one\n", &p[0].hunks, 1024).unwrap().1, [0]);
}

/// Regression: partial successful hunks must not leak into a rejected file.
#[test]
fn regression_import_reject_keeps_original_and_writes_failed_hunks() {
    let f = Fixture::new();
    let mut args = f.args("reject");
    args.reject = true;
    let patch = b"--- a/a\n+++ b/a\n@@ -1 +1 @@\n-one\n+ONE\n@@ -3 +3 @@\n-missing\n+THREE\n--- /dev/null\n+++ b/ok\n@@ -0,0 +1 @@\n+okay\n";
    let (output, code) = f.apply(&args, patch).unwrap();
    assert_eq!(code, 1);
    let json: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(json["rejected"], 1);
    assert_eq!(
        fs::read(args.directory.join("a")).unwrap(),
        b"one\ntwo\nthree\n"
    );
    assert_eq!(fs::read(args.directory.join("ok")).unwrap(), b"okay\n");
    assert_eq!(
        fs::read(args.directory.join("a.rej")).unwrap(),
        b"diff a/a b/a\t(rejected hunks)\n@@ -3 +3 @@\n-missing\n+THREE\n"
    );
}

/// Regression: failure after a valid file must remove the entire partial overlay.
#[test]
fn regression_import_abort_removes_partial_directory() {
    let f = Fixture::new();
    let args = f.args("abort");
    fs::create_dir(&args.directory).unwrap();
    let patch = b"--- /dev/null\n+++ b/ok\n@@ -0,0 +1 @@\n+okay\n--- a/a\n+++ b/a\n@@ -1 +1 @@\n-missing\n+changed\n";
    let error = f.apply(&args, patch).unwrap_err();
    assert!(error.contains("a: hunk #1"), "{error}");
    assert!(!args.directory.exists());
}

/// Regression: rename/copy preimages and subsequent hunks must retain the old bytes.
#[test]
fn regression_import_rename_and_copy_with_hunks() {
    for copy in [false, true] {
        let f = Fixture::new();
        let args = f.args("rename");
        let verb = if copy { "copy" } else { "rename" };
        let patch = format!("diff --git a/a b/moved\nsimilarity index 70%\n{verb} from a\n{verb} to moved\n--- a/a\n+++ b/moved\n@@ -1,3 +1,3 @@\n one\n-two\n+TWO\n three\n");
        f.apply(&args, patch.as_bytes()).unwrap();
        let view = f.view(&args.directory);
        assert_eq!(view.lookup("/a", 0).is_some(), copy);
        assert_eq!(
            fs::read(args.directory.join("moved")).unwrap(),
            b"one\nTWO\nthree\n"
        );
    }
}

/// Regression: unsafe names on either side, including unused Git headers, must fail closed.
#[test]
fn regression_import_refuses_traversal_absolute_nul_and_non_utf8_paths() {
    for path in [
        b"a/../escape".as_slice(),
        b"../escape",
        b"/absolute",
        b"a//empty",
        b"a/./dot",
        b"a/nul\0x",
        b"a/\xff",
    ] {
        for side in [0, 1] {
            let mut patch = b"diff --git ".to_vec();
            patch.extend_from_slice(if side == 0 { path } else { b"a/safe" });
            patch.push(b' ');
            patch.extend_from_slice(if side == 1 { path } else { b"b/safe" });
            patch.extend_from_slice(b"\n--- a/safe\n+++ b/safe\n@@ -1 +1 @@\n-old\n+new\n");
            assert!(parse::parse(&patch, 1024).is_err(), "{patch:?}");
        }
    }
    assert!(parse::parse(
        b"diff --git a/x b/x\nrename from ../bad\nrename to x\n",
        1024
    )
    .is_err());
    assert!(parse::parse(b"--- /dev/null\n+++ b/.ratarmount.overlay.sqlite\n", 1024).is_err());
}

/// Regression: `.ratarmount-control/` paths (N6) are refused on either side;
/// the same name below a subdirectory or as a longer sibling name is ordinary.
#[test]
fn regression_import_refuses_control_dir_paths_parse() {
    for path in [".ratarmount-control/x", ".ratarmount-control"] {
        let add = format!("--- /dev/null\n+++ b/{path}\n@@ -0,0 +1 @@\n+x\n");
        assert!(parse::parse(add.as_bytes(), 1024).is_err(), "{add}");
        let del = format!("--- a/{path}\n+++ /dev/null\n@@ -1 +0,0 @@\n-x\n");
        assert!(parse::parse(del.as_bytes(), 1024).is_err(), "{del}");
    }
    let rename =
        b"diff --git a/x b/.ratarmount-control/x\nrename from x\nrename to .ratarmount-control/x\n";
    assert!(parse::parse(rename, 1024).is_err());
    for path in ["sub/.ratarmount-control/x", ".ratarmount-controlx"] {
        let add = format!("--- /dev/null\n+++ b/{path}\n@@ -0,0 +1 @@\n+x\n");
        assert!(parse::parse(add.as_bytes(), 1024).is_ok(), "{add}");
    }
}

/// Regression: neither lower nor newly written symlink parents may be traversed.
#[test]
fn regression_import_refuses_lower_and_overlay_symlink_components() {
    let f = Fixture::new();
    let args = f.args("lower-link");
    let error = f
        .apply(
            &args,
            b"--- /dev/null\n+++ b/link/file\n@@ -0,0 +1 @@\n+escape\n",
        )
        .unwrap_err();
    assert!(error.contains("symlink parent /link"), "{error}");
    assert!(!args.directory.exists());
    let args = f.args("new-link");
    let error = f.apply(&args, b"diff --git a/new-link b/new-link\nnew file mode 120000\n--- /dev/null\n+++ b/new-link\n@@ -0,0 +1 @@\n+../../outside\n\\ No newline at end of file\n--- /dev/null\n+++ b/new-link/file\n@@ -0,0 +1 @@\n+escape\n").unwrap_err();
    assert!(error.contains("symlink parent /new-link"), "{error}");
    assert!(!args.directory.exists());
}

/// Regression: a malformed delta section and `Binary files … differ` must name the affected path.
#[test]
fn regression_import_delta_and_contentless_binary_name_path() {
    for body in [
        "GIT binary patch\ndelta 12\n",
        "Binary files a/binary and b/binary differ\n",
    ] {
        let patch = format!("diff --git a/binary b/binary\n{body}");
        let error = parse::parse(patch.as_bytes(), 1024)
            .unwrap_err()
            .to_string();
        assert!(error.contains("binary:"), "{error}");
        assert!(
            error.contains("delta") || error.contains("no content"),
            "{error}"
        );
    }
}

/// Regression: plain diff -u timestamps, C-quoted paths and Latin-1 hunks are bytes.
#[test]
fn regression_import_plain_diff_quoted_path_and_latin1() {
    let f = Fixture::new();
    let args = f.args("plain");
    let patch = b"--- a/latin\t2020-01-01 00:00:00\n+++ b/latin\t2026-10-17 00:00:00\n@@ -1 +1 @@\n-caf\xe9\n+d\xe9j\xe0\n--- /dev/null\n+++ \"b/caf\\303\\251\"\n@@ -0,0 +1 @@\n+coffee\n";
    f.apply(&args, patch).unwrap();
    assert_eq!(
        fs::read(args.directory.join("latin")).unwrap(),
        b"d\xe9j\xe0\n"
    );
    assert_eq!(fs::read(args.directory.join("café")).unwrap(), b"coffee\n");
}

/// Regression: mode and mtime writes must survive close/reopen, including symlinks.
#[test]
fn regression_import_mtime_and_modes_survive_sealing() {
    let f = Fixture::new();
    let mut args = f.args("sealed");
    args.no_seal = false;
    let (json, code) = f.apply(&args, b"diff --git a/mode b/mode\nold mode 100644\nnew mode 100755\ndiff --git a/link b/link\n--- a/link\n+++ b/link\n@@ -1 +1 @@\n-a\n\\ No newline at end of file\n+elsewhere\n\\ No newline at end of file\n").unwrap();
    assert_eq!(code, 0);
    let json: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(json["layer_digest"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    let meta = OverlayMeta::read(&args.directory).unwrap().unwrap();
    assert!(meta.layer_sealed());
    assert_eq!(meta.base_url(), Some(args.base.as_str()));
    assert_eq!(meta.base_digest_kind(), Some("strong"));
    let view = f.view(&args.directory);
    assert_eq!(view.lookup("/mode", 0).unwrap().mode & 0o777, 0o755);
    for path in ["/mode", "/link"] {
        assert_eq!(view.lookup(path, 0).unwrap().mtime, 1234567890.0);
    }
    drop(view);
    assert!(
        ratarmount_compositing::overlay_seal::verify(&args.directory, f.source.clone())
            .unwrap()
            .ok
    );
    ratarmount_compositing::overlay_seal::unseal(&args.directory).unwrap();
}

/// Regression: nonempty destinations and symlinks must never be deleted on failure.
#[test]
fn regression_import_preserves_existing_destination() {
    let f = Fixture::new();
    let args = f.args("exists");
    fs::create_dir(&args.directory).unwrap();
    fs::write(args.directory.join("keep"), b"untouched").unwrap();
    assert!(f.apply(&args, b"").is_err());
    assert_eq!(fs::read(args.directory.join("keep")).unwrap(), b"untouched");
    let link = f.temp.path().join("dest-link");
    std::os::unix::fs::symlink(&args.directory, &link).unwrap();
    assert!(validate_destination(&link).is_err());
}

/// Regression: malformed counts, binary expansion and invalid mtime must not panic or allocate unboundedly.
#[test]
fn regression_import_malformed_and_size_limits() {
    for patch in [
        b"--- a/a\n+++ b/a\n@@ -1,999 +1 @@\n-old\n+new\n".as_slice(),
        b"--- a/a\n+++ b/a\n@@ -18446744073709551615,2 +1 @@\n",
        b"diff --git a/bin b/bin\nGIT binary patch\nliteral 9999999999\n",
        b"--- a/a\n+++ b/a\n@@ -1 +1 @@\n-old\n+new",
    ] {
        assert!(parse::parse(patch, 64).is_err());
    }
    assert!(read_bounded(&b"12345"[..], 4).is_err());
    for value in ["NaN", "inf", "1e999", "9223372036854775808", "bad"] {
        assert!(parse_mtime(value).is_err());
    }
    assert_eq!(mtime("-1.5").unwrap(), -1.5);
    assert!(mtime("now").unwrap() > 0.0);
}

/// Regression: import flags must not consume PATCH, NEW_OVERLAY_DIR or BASE.
#[test]
fn regression_import_clap_positionals_not_stolen() {
    let parsed = crate::parse_args_from([
        "ratarmount",
        "overlay",
        "import",
        "--lower",
        "prepared",
        "--mtime",
        "123",
        "--no-seal",
        "--json",
        "--reject",
        "--allow-unsealed-lower",
        "-",
        "new",
        "base.tar",
    ])
    .unwrap();
    assert!(parsed.paths.is_empty());
    let crate::overlay_cmd::OverlayCommand::Import(args) = parsed.overlay.unwrap().command else {
        panic!("import")
    };
    assert_eq!(args.patch, Path::new("-"));
    assert_eq!(args.directory, Path::new("new"));
    assert_eq!(args.base, "base.tar");
    assert_eq!(args.lower, [PathBuf::from("prepared")]);
    assert_eq!(args.mtime, "123");
    for fields in [vec!["patch", "new"], vec!["patch", "new", "base", "extra"]] {
        assert!(
            crate::parse_args_from([vec!["ratarmount", "overlay", "import"], fields].concat())
                .is_err()
        );
    }
}

fn git_binary_roundtrip(external: bool) {
    let _processes = ratarmount_index::test_process::spawning();
    if external
        && std::process::Command::new("git")
            .arg("--version")
            .output()
            .is_err()
    {
        eprintln!("skip: git is unavailable; git2 literal import is tested separately");
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path().join("repo");
    let repo = git2::Repository::init(&repo_dir).unwrap();
    fs::write(repo_dir.join("text"), b"old\n").unwrap();
    fs::write(repo_dir.join("bin"), b"\x00old binary\xff").unwrap();
    let mut index = repo.index().unwrap();
    index
        .add_all(["*"], git2::IndexAddOption::DEFAULT, None)
        .unwrap();
    index.write().unwrap();
    let tree_id = index.write_tree().unwrap();
    let tree = repo.find_tree(tree_id).unwrap();
    let sig = git2::Signature::now("Import test", "test@example.invalid").unwrap();
    let commit = repo
        .commit(Some("HEAD"), &sig, &sig, "base", &tree, &[])
        .unwrap();
    let source: Arc<dyn MountSource> = Arc::new(
        ratarmount_formats_git::GitMountSource::open(&repo_dir, Some(&commit.to_string())).unwrap(),
    );
    let base = PathBuf::from(format!("{}@{commit}", repo_dir.display()));
    let f = Fixture { temp, base, source };
    let a = f.temp.path().join("expected");
    // The base is a Git commit: the real factory classifies `repo@commit`.
    let token = crate::base_identity::fixtures::classify(&f.base);
    let ov = WriteOverlay::open(
        &token,
        f.source.clone(),
        &a,
        &ratarmount_compositing::CreateOptions::default(),
    )
    .unwrap();
    for (name, data) in [
        ("text", b"caf\xe9\n".as_slice()),
        ("bin", b"\x00new binary\xfe"),
        ("new", b"added\n"),
    ] {
        fs::write(repo_dir.join(name), data).unwrap();
        put(&ov, &format!("/{name}"), data, 0o644);
    }
    drop(ov);
    index
        .add_all(["*"], git2::IndexAddOption::DEFAULT, None)
        .unwrap();
    index.write().unwrap();
    let bytes = if external {
        let output = std::process::Command::new("git")
            .current_dir(&repo_dir)
            .args(["diff", "--binary", "--no-ext-diff", "--no-textconv", "HEAD"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    } else {
        let mut opts = git2::DiffOptions::new();
        opts.show_binary(true);
        let diff = repo
            .diff_tree_to_index(Some(&tree), Some(&index), Some(&mut opts))
            .unwrap();
        let mut bytes = Vec::new();
        diff.print(git2::DiffFormat::Patch, |_, _, line| {
            if matches!(line.origin(), ' ' | '+' | '-') {
                bytes.push(line.origin() as u8);
            }
            bytes.extend_from_slice(line.content());
            true
        })
        .unwrap();
        bytes
    };
    assert!(bytes
        .windows(b"GIT binary patch".len())
        .any(|s| s == b"GIT binary patch"));
    let args = f.args("actual");
    let patches = parse::parse(&bytes, args.max_patch_bytes).unwrap();
    let stack = ImportStack::open(&args, &Default::default()).unwrap();
    assert_eq!(
        stack.base.actual().git_tree(),
        Some(tree_id.to_string().as_str())
    );
    import(&args, &patches, stack, 123.0).unwrap();
    assert_eq!(f.hash(&a), f.hash(&args.directory));
    let meta = OverlayMeta::read(&args.directory).unwrap().unwrap();
    assert_eq!(
        meta.base_digest(),
        Some(format!("git-tree:{tree_id}").as_str())
    );
}

/// Regression: the pure libgit2 producer's binary and byte-text patches must import.
#[test]
fn regression_import_git2_binary_patch() {
    git_binary_roundtrip(false);
}

/// Regression: real git diff --binary must import to the same tree.
#[test]
fn regression_import_real_git_binary_patch() {
    git_binary_roundtrip(true);
}

/// Regression: a space followed by b/ inside a Git path is not the header separator.
#[test]
fn regression_import_unquoted_spaces_and_plain_mode_headers() {
    let p = parse::parse(
        b"diff --git a/has b/sub/file b/has b/sub/file\nold mode 100644\nnew mode 100755\n",
        4096,
    )
    .unwrap();
    assert_eq!(p[0].old.as_deref(), Some("has b/sub/file"));
    assert_eq!(p[0].new.as_deref(), Some("has b/sub/file"));
    let p = parse::parse(b"new file mode 100755\n--- /dev/null\n+++ b/executable\n@@ -0,0 +1 @@\n+run\nnew file mode 100644\n--- /dev/null\n+++ b/text\n@@ -0,0 +1 @@\n+text\n", 4096).unwrap();
    assert_eq!(p.len(), 2);
    assert_eq!(p[0].new_mode, Some(0o100755));
    assert_eq!(p[1].new_mode, Some(0o100644));
}

/// Regression: a failed type-change deletion must not become an addition or exit 2 with --reject.
#[test]
fn regression_import_reject_type_change_and_repeated_file_sections() {
    let f = Fixture::new();
    let mut args = f.args("repeated-reject");
    args.reject = true;
    let patch = b"diff --git a/type b/type\ndeleted file mode 100644\n--- a/type\n+++ /dev/null\n@@ -1 +0,0 @@\n-wrong preimage\ndiff --git a/type b/type\nnew file mode 120000\n--- /dev/null\n+++ b/type\n@@ -0,0 +1 @@\n+a\n\\ No newline at end of file\n--- a/type\n+++ b/type\n@@ -1 +1 @@\n-also wrong\n+new\n";
    let (_, code) = f.apply(&args, patch).unwrap();
    assert_eq!(code, 1);
    assert_eq!(fs::read(args.directory.join("type")).unwrap(), b"regular\n");
    let rejects = fs::read(args.directory.join("type.rej")).unwrap();
    assert_eq!(rejects, b"diff a/type b/type\t(rejected hunks)\n@@ -1 +0,0 @@\n-wrong preimage\n@@ -1 +1 @@\n-also wrong\n+new\n");
}

/// Regression: import sealed its rows against the RAW base instead of the
/// composed view (base under the `--lower` layers). A file a lower layer added
/// and the imported patch modifies was recorded `Added`; the seal hashes
/// against the composed view, so it is `Modified`, and the sealed layer
/// verifies against that same view.
#[test]
fn regression_import_lower_added_then_modified_seals_modified() {
    use ratarmount_compositing::overlay_changes::Status;
    let f = Fixture::new();
    let lower = f.temp.path().join("lower");
    let ov = crate::base_identity::fixtures::overlay_over(
        f.source.clone(),
        &lower,
        f.base.to_str().unwrap(),
        Vec::new(),
    )
    .unwrap();
    put(&ov, "/added", b"from lower\n", 0o644);
    drop(ov);
    crate::base_identity::fixtures::seal(&lower, f.source.clone()).unwrap();
    let mut args = f.args("top");
    args.lower = vec![lower.clone()];
    args.no_seal = false;
    let patch = b"--- a/added\n+++ b/added\n@@ -1 +1 @@\n-from lower\n+from top\n";
    let parsed = parse::parse(patch, args.max_patch_bytes).unwrap();
    let stack = ImportStack::open(&args, &Default::default()).unwrap();
    import(&args, &parsed, stack, 1.0).unwrap();
    let view = ratarmount_compositing::compose_stack(
        f.source.clone(),
        &[(lower, Immutability::Immutable)],
    )
    .unwrap();
    let changes = change_set(&args.directory, view.clone(), &ChangeOptions::default()).unwrap();
    let row = changes
        .iter()
        .find(|c| c.path == b"added")
        .expect("a row for /added");
    assert_eq!(row.status, Status::Modified, "{row:?}");
    assert!(
        ratarmount_compositing::overlay_seal::verify(&args.directory, view)
            .unwrap()
            .ok
    );
}

/// Stand-in for SIGKILL during the write phase: same create/open path and
/// marker as `import`, writes the first `n` entries, then returns without
/// clearing the marker and without the error cleanup (`import` removes the
/// whole directory on any error, which would hide the marker).
fn simulate_killed_import(f: &Fixture, args: &ImportArgs, files: &[(&str, &[u8])], n: usize) {
    fs::create_dir(&args.directory).unwrap();
    let overlay = super::super::overlay_create::create_overlay(
        &crate::base_identity::fixtures::classify(&f.base),
        f.source.clone(),
        &args.directory,
        ratarmount_compositing::CreateOptions::default(),
        std::slice::from_ref(&f.base),
        false,
    )
    .unwrap();
    begin_import(&overlay).unwrap();
    for (path, data) in files.iter().take(n) {
        write_entry(&overlay, path, data, S_IFREG | 0o644, 1.0).unwrap();
    }
    drop(overlay);
}

/// Regression: a killed `overlay import --no-seal` left a partial overlay that fsck reported clean.
#[test]
fn regression_import_killed_midway_leaves_marker() {
    let f = Fixture::new();
    let args = f.args("killed");
    simulate_killed_import(&f, &args, &[("x", b"1\n"), ("y", b"2\n"), ("z", b"3\n")], 2);
    let meta = OverlayMeta::read(&args.directory).unwrap().unwrap();
    assert!(meta.get("import_in_progress").is_some());
    let report = ratarmount_compositing::overlay_fsck::fsck(&args.directory, false).unwrap();
    assert!(!report.is_clean());
    assert_eq!(report.import_incomplete, 1);
    let err = crate::base_identity::fixtures::seal(&args.directory, f.source.clone())
        .unwrap_err()
        .to_string();
    assert!(err.contains("import"), "{err}");
    assert!(!OverlayMeta::read(&args.directory)
        .unwrap()
        .unwrap()
        .layer_sealed());
}

/// Compatibility: a normal import (unsealed or sealed) leaves no marker.
#[test]
fn regression_import_clears_marker_on_success() {
    let f = Fixture::new();
    for seal in [false, true] {
        let mut args = f.args(if seal { "sealed" } else { "unsealed" });
        args.no_seal = !seal;
        f.apply(&args, b"--- /dev/null\n+++ b/ok\n@@ -0,0 +1 @@\n+okay\n")
            .unwrap();
        let meta = OverlayMeta::read(&args.directory).unwrap().unwrap();
        assert!(meta.get("import_in_progress").is_none(), "seal={seal}");
        assert!(
            ratarmount_compositing::overlay_fsck::fsck(&args.directory, false)
                .unwrap()
                .is_clean()
        );
    }
}

const DELETE_TYPE: &[u8] = b"diff --git a/type b/type\ndeleted file mode 100644\n--- a/type\n+++ /dev/null\n@@ -1 +0,0 @@\n-regular\n";
const ADD_TYPE_Y: &[u8] = b"diff --git a/type/y b/type/y\nnew file mode 100644\n--- /dev/null\n+++ b/type/y\n@@ -0,0 +1 @@\n+inside\n";
const ADD_NESTED: &[u8] = b"diff --git a/nested b/nested\nnew file mode 100644\n--- /dev/null\n+++ b/nested\n@@ -0,0 +1 @@\n+now a file\n";
const DELETE_NESTED_BASE: &[u8] = b"diff --git a/nested/base b/nested/base\ndeleted file mode 100644\n--- a/nested/base\n+++ /dev/null\n@@ -1 +0,0 @@\n-keep\n";

fn is_dir(view: &ReadOnlyOverlayLayer, path: &str) -> bool {
    view.lookup(path, 0)
        .is_some_and(|fi| fi.mode & S_IFMT == ratarmount_core::S_IFDIR)
}

fn fsck_clean(dir: &Path) {
    let report = ratarmount_compositing::overlay_fsck::fsck(dir, false).unwrap();
    assert!(report.is_clean(), "{report:?}");
}

/// Regression (#329): deleting file `type` and adding `type/y` failed with
/// "parent /type is not a directory" because the lower view still had the file.
#[test]
fn regression_import_file_replaced_by_directory() {
    let f = Fixture::new();
    let args = f.args("file-to-dir");
    let (_, code) = f.apply(&args, &[DELETE_TYPE, ADD_TYPE_Y].concat()).unwrap();
    assert_eq!(code, 0);
    let view = f.view(&args.directory);
    assert!(is_dir(&view, "/type"));
    assert!(args.directory.join("type").is_dir());
    assert_eq!(
        fs::read(args.directory.join("type/y")).unwrap(),
        b"inside\n"
    );
    fsck_clean(&args.directory);
}

/// Regression (#329): `add nested` precedes `delete nested/base` in Git's
/// order; the directory being replaced is emptied and removed first.
#[test]
fn regression_import_directory_replaced_by_file() {
    let f = Fixture::new();
    let args = f.args("dir-to-file");
    let (_, code) = f
        .apply(&args, &[ADD_NESTED, DELETE_NESTED_BASE].concat())
        .unwrap();
    assert_eq!(code, 0);
    let view = f.view(&args.directory);
    let fi = view.lookup("/nested", 0).unwrap();
    assert_eq!(fi.mode & S_IFMT, S_IFREG);
    assert!(view.lookup("/nested/base", 0).is_none());
    assert_eq!(
        fs::read(args.directory.join("nested")).unwrap(),
        b"now a file\n"
    );
    fsck_clean(&args.directory);
    // An add over a directory whose children are not all deleted still fails.
    let args = f.args("dir-to-file-partial");
    let error = f.apply(&args, ADD_NESTED).unwrap_err();
    assert!(error.contains("added file already exists"), "{error}");
}

/// Regression (#329): a stream that modifies a path and then deletes it reads
/// the second preimage from the overlay; deletions are not hoisted globally.
#[test]
fn regression_import_modify_then_delete_stream_unchanged() {
    let f = Fixture::new();
    let args = f.args("modify-delete");
    let patch = b"--- a/a\n+++ b/a\n@@ -1 +1 @@\n-one\n+ONE\ndiff --git a/a b/a\ndeleted file mode 100644\n--- a/a\n+++ /dev/null\n@@ -1,3 +0,0 @@\n-ONE\n-two\n-three\n";
    let (_, code) = f.apply(&args, patch).unwrap();
    assert_eq!(code, 0);
    assert!(f.view(&args.directory).lookup("/a", 0).is_none());
}

/// Regression (#329): only a directory replaced by a file is removed; an
/// import that merely empties a directory keeps it.
#[test]
fn regression_import_emptied_directory_is_kept() {
    let f = Fixture::new();
    let args = f.args("emptied");
    let (_, code) = f.apply(&args, DELETE_NESTED_BASE).unwrap();
    assert_eq!(code, 0);
    let view = f.view(&args.directory);
    assert!(is_dir(&view, "/nested"));
    assert!(view.lookup("/nested/base", 0).is_none());
}

/// Regression (#329): with --reject, a failed section under a file that this
/// import turned into a directory restores the lower file (the whole type
/// change is rejected) and writes its hunks to `type.rej`.
#[test]
fn regression_import_type_change_reject_restores_lower() {
    let f = Fixture::new();
    let mut args = f.args("type-reject");
    args.reject = true;
    let add_z: &[u8] = b"--- /dev/null\n+++ b/type/z\n@@ -0,0 +1 @@\n+zed\n";
    let bad: &[u8] = b"--- a/type/y\n+++ b/type/y\n@@ -1 +1 @@\n-wrong\n+new\n";
    let later: &[u8] = b"--- /dev/null\n+++ b/type/w\n@@ -0,0 +1 @@\n+late\n";
    let (output, code) = f
        .apply(
            &args,
            &[DELETE_TYPE, ADD_TYPE_Y, add_z, bad, later].concat(),
        )
        .unwrap();
    assert_eq!(code, 1, "{output}");
    let view = f.view(&args.directory);
    let fi = view.lookup("/type", 0).unwrap();
    assert_eq!(fi.mode & S_IFMT, S_IFREG);
    assert_eq!(fs::read(args.directory.join("type")).unwrap(), b"regular\n");
    for gone in ["/type/y", "/type/z", "/type/w"] {
        assert!(view.lookup(gone, 0).is_none(), "{gone}");
    }
    assert_eq!(
        fs::read(args.directory.join("type.rej")).unwrap(),
        b"diff a/type/y b/type/y\t(rejected hunks)\n@@ -1 +1 @@\n-wrong\n+new\n"
    );
    let json: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(json["rejected"], 1);
    assert_eq!(json["files"], 0, "nothing below type is kept: {output}");
    fsck_clean(&args.directory);
    // The same stream sealed: the restored type change must not make fsck
    // or seal refuse (that would turn exit 1 into exit 2).
    let mut args = f.args("type-reject-sealed");
    args.reject = true;
    args.no_seal = false;
    let (output, code) = f
        .apply(
            &args,
            &[DELETE_TYPE, ADD_TYPE_Y, add_z, bad, later].concat(),
        )
        .unwrap();
    assert_eq!(code, 1, "{output}");
    let json: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert!(json["layer_digest"].is_string(), "{output}");
    assert!(
        ratarmount_compositing::overlay_seal::verify(&args.directory, f.source.clone())
            .unwrap()
            .ok
    );
}

/// Regression (#329): skipping the parent check for sections of a rejected
/// file must not let a rename into a symlink parent reach `restore`.
#[test]
fn regression_import_reject_still_refuses_symlink_parent() {
    let f = Fixture::new();
    let outside = f.temp.path().join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("file"), b"outside\n").unwrap();
    let mut args = f.args("reject-link");
    args.reject = true;
    let patch = format!(
        "--- a/a\n+++ b/a\n@@ -1 +1 @@\n-missing\n+x\ndiff --git a/new-link b/new-link\nnew file mode 120000\n--- /dev/null\n+++ b/new-link\n@@ -0,0 +1 @@\n+{}\n\\ No newline at end of file\ndiff --git a/a b/new-link/file\nsimilarity index 50%\nrename from a\nrename to new-link/file\n--- a/a\n+++ b/new-link/file\n@@ -1 +1 @@\n-missing\n+x\n",
        outside.display()
    );
    let error = f.apply(&args, patch.as_bytes()).unwrap_err();
    assert!(error.contains("symlink parent /new-link"), "{error}");
    assert_eq!(fs::read(outside.join("file")).unwrap(), b"outside\n");
}

/// Regression (#329): with --reject, a failing deletion of a child of the
/// directory being replaced rejects the whole directory -> file change.
#[test]
fn regression_import_directory_to_file_reject_keeps_directory() {
    let f = Fixture::new();
    let mut args = f.args("dir-reject");
    args.reject = true;
    let bad: &[u8] = b"diff --git a/nested/base b/nested/base\ndeleted file mode 100644\n--- a/nested/base\n+++ /dev/null\n@@ -1 +0,0 @@\n-wrong\n";
    let (_, code) = f.apply(&args, &[ADD_NESTED, bad].concat()).unwrap();
    assert_eq!(code, 1);
    let view = f.view(&args.directory);
    assert!(is_dir(&view, "/nested"));
    assert!(view.lookup("/nested/base", 0).is_some());
    let rej = fs::read(args.directory.join("nested.rej")).unwrap();
    assert!(
        rej.ends_with(b"@@ -1 +0,0 @@\n-wrong\n"),
        "{}",
        String::from_utf8_lossy(&rej)
    );
    assert!(
        rej.windows(b"+now a file\n".len())
            .any(|w| w == b"+now a file\n"),
        "{}",
        String::from_utf8_lossy(&rej)
    );
}

/// Regression (#329): lower symlink parents remain refused even after deletion;
/// folder-backed lower lookups can still follow the link's target.
#[test]
fn regression_import_deleted_lower_symlink_parent_is_refused() {
    let f = Fixture::new();
    let args = f.args("link-to-dir");
    let patch = b"diff --git a/link b/link\ndeleted file mode 120000\n--- a/link\n+++ /dev/null\n@@ -1 +0,0 @@\n-a\n\\ No newline at end of file\ndiff --git a/link/f b/link/f\nnew file mode 100644\n--- /dev/null\n+++ b/link/f\n@@ -0,0 +1 @@\n+real\n";
    let error = f.apply(&args, patch).unwrap_err();
    assert!(error.contains("symlink parent /link"), "{error}");
    assert!(!args.directory.exists());
}

/// Regression (#329): a failed first child addition must restore the deleted
/// lower file even though no replacement directory has been created yet.
#[test]
fn regression_import_type_change_reject_before_first_child() {
    let f = Fixture::new();
    let mut args = f.args("first-child-reject");
    args.reject = true;
    let bad: &[u8] = b"--- /dev/null\n+++ b/type/y\n@@ -1,0 +2 @@\n+inside\n";
    let (output, code) = f.apply(&args, &[DELETE_TYPE, bad].concat()).unwrap();
    assert_eq!(code, 1, "{output}");
    assert_eq!(fs::read(args.directory.join("type")).unwrap(), b"regular\n");
    assert!(args.directory.join("type.rej").is_file());
    let json: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(json["files"], 0);
    fsck_clean(&args.directory);
}

/// Regression (#329): a rejected directory replacement must undo earlier
/// child edits, not leave a partially changed directory behind.
#[test]
fn regression_import_directory_reject_restores_earlier_changes() {
    let f = Fixture::new();
    let mut args = f.args("earlier-child-reject");
    args.reject = true;
    let modify: &[u8] = b"--- a/nested/base\n+++ b/nested/base\n@@ -1 +1 @@\n-keep\n+changed\n";
    let (output, code) = f
        .apply(&args, &[modify, ADD_NESTED, DELETE_NESTED_BASE].concat())
        .unwrap();
    assert_eq!(code, 1, "{output}");
    let view = f.view(&args.directory);
    let fi = view.lookup("/nested/base", 0).unwrap();
    assert_eq!(view.read(&fi, 100, 0).unwrap(), b"keep\n");
    let json: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(json["files"], 0);
    assert!(fs::read(args.directory.join("nested.rej"))
        .unwrap()
        .ends_with(b"@@ -1 +0,0 @@\n-keep\n"));
    fsck_clean(&args.directory);
}

/// Regression (#329): a later failed hunk at a directory-to-file replacement
/// restores the original directory and its deleted descendants, then seals.
#[test]
fn regression_import_directory_reject_after_replacement() {
    let f = Fixture::new();
    let mut args = f.args("late-directory-reject");
    args.reject = true;
    args.no_seal = false;
    let bad: &[u8] = b"--- a/nested\n+++ b/nested\n@@ -1 +1 @@\n-wrong\n+changed\n";
    let (output, code) = f
        .apply(&args, &[ADD_NESTED, DELETE_NESTED_BASE, bad].concat())
        .unwrap();
    assert_eq!(code, 1, "{output}");
    let view = f.view(&args.directory);
    assert!(is_dir(&view, "/nested"));
    let fi = view.lookup("/nested/base", 0).unwrap();
    assert_eq!(view.read(&fi, 100, 0).unwrap(), b"keep\n");
    let json: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(json["files"], 0);
    assert!(json["layer_digest"].is_string());
    fsck_clean(&args.directory);
    drop(view);
    assert!(
        ratarmount_compositing::overlay_seal::verify(&args.directory, f.source.clone())
            .unwrap()
            .ok
    );
    ratarmount_compositing::overlay_seal::unseal(&args.directory).unwrap();
}

/// Regression (#329): hoisted deletions must not discard a child that an
/// earlier failed section already promised to preserve under --reject.
#[test]
fn regression_import_directory_replacement_preserves_rejected_child() {
    let f = Fixture::new();
    let mut args = f.args("already-rejected-child");
    args.reject = true;
    let bad: &[u8] = b"--- a/nested/base\n+++ b/nested/base\n@@ -1 +1 @@\n-wrong\n+changed\n";
    let (output, code) = f
        .apply(&args, &[bad, ADD_NESTED, DELETE_NESTED_BASE].concat())
        .unwrap();
    assert_eq!(code, 1, "{output}");
    let view = f.view(&args.directory);
    assert!(is_dir(&view, "/nested"));
    let fi = view.lookup("/nested/base", 0).unwrap();
    assert_eq!(view.read(&fi, 100, 0).unwrap(), b"keep\n");
    assert!(args.directory.join("nested.rej").is_file());
    let json: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(json["files"], 0);
    assert_eq!(json["rejected"], 1);
    fsck_clean(&args.directory);
}

/// Regression (#329): restoring a rejected replacement also restores pruned
/// empty subdirectories and removes children added earlier in the stream.
#[test]
fn regression_import_directory_reject_restores_pruned_tree() {
    use ratarmount_compositing::FolderMountSource;
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path().join("base");
    fs::create_dir_all(base.join("nested/sub/empty")).unwrap();
    fs::write(base.join("nested/sub/base"), b"keep\n").unwrap();
    let source = Arc::new(FolderMountSource::new(&base).unwrap());
    let f = Fixture { temp, base, source };
    let mut args = f.args("tree-reject");
    args.reject = true;
    let add = b"--- /dev/null\n+++ b/nested/added\n@@ -0,0 +1 @@\n+extra\n";
    let deletes = b"--- a/nested/added\n+++ /dev/null\n@@ -1 +0,0 @@\n-extra\n--- a/nested/sub/base\n+++ /dev/null\n@@ -1 +0,0 @@\n-keep\n";
    let bad = b"--- a/nested\n+++ b/nested\n@@ -1 +1 @@\n-wrong\n+changed\n";
    let (output, code) = f
        .apply(
            &args,
            &[
                add.as_slice(),
                ADD_NESTED,
                deletes.as_slice(),
                bad.as_slice(),
            ]
            .concat(),
        )
        .unwrap();
    assert_eq!(code, 1, "{output}");
    let view = f.view(&args.directory);
    assert!(is_dir(&view, "/nested/sub/empty"));
    assert!(view.lookup("/nested/added", 0).is_none());
    let fi = view.lookup("/nested/sub/base", 0).unwrap();
    assert_eq!(view.read(&fi, 100, 0).unwrap(), b"keep\n");
    fsck_clean(&args.directory);
}

/// Regression (#329): sections suppressed by a restored non-directory must
/// not read a preimage through it before deciding to skip the section.
#[test]
fn regression_import_rejected_symlink_descendant_is_not_read() {
    use ratarmount_compositing::FolderMountSource;
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path().join("base");
    let outside = temp.path().join("outside");
    fs::create_dir(&base).unwrap();
    fs::create_dir(&outside).unwrap();
    // Any accidental read attempt fails the per-file limit before opening.
    fs::write(outside.join("large"), vec![b'x'; 8192]).unwrap();
    std::os::unix::fs::symlink("../outside", base.join("link")).unwrap();
    let source = Arc::new(FolderMountSource::new(&base).unwrap());
    let f = Fixture { temp, base, source };
    let mut args = f.args("reject-link-read");
    args.reject = true;
    args.max_patch_bytes = 4096;
    let patch = b"diff --git a/link b/link\ndeleted file mode 120000\n--- a/link\n+++ /dev/null\n@@ -1 +0,0 @@\n-wrong\n\\ No newline at end of file\ndiff --git a/link/large b/stolen\nsimilarity index 100%\ncopy from link/large\ncopy to stolen\n";
    let (output, code) = f.apply(&args, patch).unwrap();
    assert_eq!(code, 1, "{output}");
    assert_eq!(
        fs::read_link(args.directory.join("link")).unwrap(),
        Path::new("../outside")
    );
    assert!(!args.directory.join("stolen").exists());
    fsck_clean(&args.directory);
}

/// Regression (#329): a failed lower listing is not an empty directory. A
/// replacement must refuse before it can hide children missing from the list.
#[test]
fn regression_import_directory_replacement_refuses_failed_lower_listing() {
    use ratarmount_compositing::FolderMountSource;
    struct FailedListing {
        inner: Arc<dyn MountSource>,
        path: &'static str,
    }
    impl MountSource for FailedListing {
        fn list(&self, path: &str) -> Option<ListResult> {
            if path == self.path {
                None
            } else {
                self.inner.list(path)
            }
        }
        fn lookup(&self, path: &str, version: i32) -> Option<FileInfo> {
            self.inner.lookup(path, version)
        }
        fn open(
            &self,
            fi: &FileInfo,
            buffering: i32,
        ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
            self.inner.open(fi, buffering)
        }
        fn is_immutable(&self) -> bool {
            self.inner.is_immutable()
        }
    }
    for missing in ["/nested", "/nested/hidden"] {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().join("base");
        fs::create_dir_all(base.join("nested/hidden")).unwrap();
        fs::write(base.join("nested/base"), b"keep\n").unwrap();
        fs::write(base.join("nested/hidden/secret"), b"preserve\n").unwrap();
        let source = Arc::new(FailedListing {
            inner: Arc::new(FolderMountSource::new(&base).unwrap()),
            path: missing,
        });
        let f = Fixture { temp, base, source };
        for reject in [false, true] {
            let mut args = f.args("missing-listing");
            args.reject = reject;
            let patch = if missing == "/nested" {
                ADD_NESTED.to_vec()
            } else {
                [ADD_NESTED, DELETE_NESTED_BASE].concat()
            };
            let error = f.apply(&args, &patch).unwrap_err();
            assert!(
                error.contains("cannot list lower directory"),
                "{missing}: {error}"
            );
            assert!(!args.directory.exists());
            assert_eq!(
                fs::read(f.base.join("nested/hidden/secret")).unwrap(),
                b"preserve\n"
            );
        }
    }
}

/// A `diff --git` section modifying `path` with a forward delta from `pre` to `post`.
fn delta_section(path: &str, pre: &[u8], post: &[u8], index: Option<String>) -> Vec<u8> {
    use parse::tests::{encode85, make_delta, zlib};
    let index = index
        .unwrap_or_else(|| format!("{}..{}", parse::blob_ids(pre)[0], parse::blob_ids(post)[0]));
    let forward = make_delta(pre, post);
    let reverse = make_delta(post, pre);
    let mut patch =
        format!("diff --git a/{path} b/{path}\nindex {index} 100644\nGIT binary patch\n")
            .into_bytes();
    patch.extend(format!("delta {}\n", forward.len()).as_bytes());
    patch.extend(encode85(&zlib(&forward)));
    patch.extend(format!("delta {}\n", reverse.len()).as_bytes());
    patch.extend(encode85(&zlib(&reverse)));
    patch
}

const TEXT_A: &[u8] =
    b"diff --git a/a b/a\n--- a/a\n+++ b/a\n@@ -1,3 +1,3 @@\n one\n-two\n+TWO\n three\n";

/// Regression (#343): a `delta` binary section applies to the lower preimage,
/// with abbreviated and full blob ids, alongside text hunks.
#[test]
fn regression_import_binary_delta_applies_to_preimage() {
    let f = Fixture::new();
    let pre = b"\x00old binary";
    let post = b"\x00new binary, longer\xff";
    for (name, index) in [
        ("full", None),
        (
            "abbrev",
            Some(format!(
                "{}..{}",
                &parse::blob_ids(pre)[0][..7],
                &parse::blob_ids(post)[0][..7]
            )),
        ),
    ] {
        let args = f.args(name);
        let patch = [delta_section("binary", pre, post, index), TEXT_A.to_vec()].concat();
        let (_, code) = f.apply(&args, &patch).unwrap();
        assert_eq!(code, 0);
        let view = f.view(&args.directory);
        let fi = view.lookup("/binary", 0).unwrap();
        assert_eq!(fi.mode & 0o7777, 0o644);
        assert_eq!(
            read_entry(&view, "binary", 1 << 20).unwrap().unwrap().1,
            post
        );
        assert_eq!(
            read_entry(&view, "a", 1 << 20).unwrap().unwrap().1,
            b"one\nTWO\nthree\n"
        );
    }
}

/// Regression (#343): a delta whose index line does not match the preimage is
/// refused naming the path (exit 2, partial overlay removed); `--reject` keeps
/// the lower file, writes the section to `PATH.rej` and applies other files.
/// A non-regular or missing preimage and a source-size mismatch behave alike.
#[test]
fn regression_import_binary_delta_wrong_preimage_and_reject() {
    let f = Fixture::new();
    let lower = b"\x00old binary";
    let other = b"\x00other base";
    let post = b"\x00new binary";
    let wrong = delta_section("binary", other, post, None);
    // Blob id matches the lower bytes, but the delta was made for 3 more bytes.
    let longer = [lower.as_slice(), b"xyz"].concat();
    let sized = delta_section(
        "binary",
        &longer,
        post,
        Some(format!(
            "{}..{}",
            parse::blob_ids(lower)[0],
            parse::blob_ids(post)[0]
        )),
    );
    let on_link = delta_section("link", b"a", b"b", None);
    for (case, section, message) in [
        ("blob", wrong, "sha1 information is lacking or useless"),
        ("size", sized, "does not match the preimage size"),
        ("link", on_link, "not a regular file"),
    ] {
        let mut args = f.args(&format!("{case}-strict"));
        let patch = [section.clone(), TEXT_A.to_vec()].concat();
        let error = f.apply(&args, &patch).unwrap_err();
        let path = if case == "link" { "link:" } else { "binary:" };
        assert!(
            error.contains(path) && error.contains(message),
            "{case}: {error}"
        );
        assert!(!args.directory.exists(), "{case}");
        args.directory = f.temp.path().join(format!("{case}-reject"));
        args.reject = true;
        let (json, code) = f.apply(&args, &patch).unwrap();
        assert_eq!(code, 1, "{case}: {json}");
        assert!(json.contains("\"rejected\":1"), "{json}");
        let view = f.view(&args.directory);
        let name = if case == "link" { "link" } else { "binary" };
        let restored = view.lookup(&format!("/{name}"), 0).unwrap();
        if case == "link" {
            assert_eq!(restored.linkname, "a");
        } else {
            assert_eq!(read_entry(&view, name, 1 << 20).unwrap().unwrap().1, lower);
        }
        let rej = read_entry(&view, &format!("{name}.rej"), 1 << 20)
            .unwrap()
            .unwrap()
            .1;
        let rej = String::from_utf8(rej).unwrap();
        assert!(rej.contains(&format!("diff a/{name} b/{name}")), "{rej}");
        assert!(
            rej.contains("\nindex ") && rej.contains("GIT binary patch\ndelta "),
            "{rej}"
        );
        assert_eq!(
            read_entry(&view, "a", 1 << 20).unwrap().unwrap().1,
            b"one\nTWO\nthree\n"
        );
    }
}

/// Regression (#343): a delta declaring a postimage over --max-patch-bytes is
/// refused while parsing, before the target is allocated or anything is written.
#[test]
fn regression_import_binary_delta_over_max_patch_bytes() {
    let f = Fixture::new();
    let pre = b"\x00old binary";
    let post = vec![7u8; 4096];
    let mut args = f.args("budget");
    args.max_patch_bytes = 1024;
    let patch = delta_section("binary", pre, &post, None);
    let error = f.apply(&args, &patch).unwrap_err();
    assert!(
        error.contains("binary:") && error.contains("exceeds --max-patch-bytes"),
        "{error}"
    );
    assert!(!args.directory.exists());
    args.max_patch_bytes = 8192;
    args.directory = f.temp.path().join("budget-ok");
    assert_eq!(f.apply(&args, &patch).unwrap().1, 0);
}

fn git(dir: &Path, args: &[&str]) -> std::process::Output {
    let output = std::process::Command::new("git")
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .args(["-c", "user.name=t", "-c", "user.email=t@example.invalid"])
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn noise(seed: u32, len: usize) -> Vec<u8> {
    let mut x = seed | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            (x >> 8) as u8
        })
        .collect()
}

/// Regression (#343): real `git diff --binary` delta sections (random bytes, a
/// docx-like zip, and a 96 KiB file needing multi-byte copy sizes), with full and
/// abbreviated index lines, import to the same tree as the edited files; then
/// `diff --git` of the result imports to the same canonical hash.
#[test]
fn regression_import_real_git_binary_delta() {
    let _processes = ratarmount_index::test_process::spawning();
    if std::process::Command::new("git")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("skip: git is unavailable; delta import is tested with built deltas");
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path().join("repo");
    fs::create_dir(&repo_dir).unwrap();
    git(&repo_dir, &["init", "-q"]);
    let mut docx = b"PK\x03\x04\x14\x00\x06\x00\x08\x00\x00\x00!\x00".to_vec();
    docx.extend(b"[Content_Types].xml");
    docx.extend(noise(3, 3000));
    docx.extend(b"PK\x01\x02\x14\x00word/document.xml\x00\x00");
    docx.extend(noise(4, 1500));
    let files = [
        ("random.bin", [vec![0u8], noise(1, 2000)].concat()),
        ("t/etc/x.docx", docx),
        ("big.bin", [vec![0u8], noise(2, 96 * 1024)].concat()),
    ];
    for (name, data) in &files {
        let path = repo_dir.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, data).unwrap();
    }
    git(&repo_dir, &["add", "-A"]);
    git(&repo_dir, &["commit", "-qm", "base"]);
    let commit = String::from_utf8(git(&repo_dir, &["rev-parse", "HEAD"]).stdout).unwrap();
    let commit = commit.trim();
    let mut edited = Vec::new();
    for (name, data) in &files {
        let mut data = data.clone();
        for at in [17, data.len() / 2, data.len() - 9] {
            data[at] ^= 0x5a;
        }
        if *name == "big.bin" {
            data.splice(70_000..70_000, b"inserted bytes".iter().copied());
        }
        fs::write(repo_dir.join(name), &data).unwrap();
        edited.push((*name, data));
    }
    let full = git(
        &repo_dir,
        &["diff", "--binary", "--no-ext-diff", "--no-textconv", "HEAD"],
    )
    .stdout;
    let text = String::from_utf8(full.clone()).unwrap();
    assert_eq!(
        text.matches("\nGIT binary patch\ndelta ").count(),
        files.len(),
        "git chose literal sections:\n{text}"
    );
    // `--binary` implies full ids; abbreviate them to 7 digits as well.
    let abbrev: String = text
        .lines()
        .map(|line| match line.strip_prefix("index ") {
            Some(rest) => {
                let (ids, mode) = rest.split_once(' ').unwrap();
                let (old, new) = ids.split_once("..").unwrap();
                format!("index {}..{} {mode}\n", &old[..7], &new[..7])
            }
            None => format!("{line}\n"),
        })
        .collect();
    let source: Arc<dyn MountSource> =
        Arc::new(ratarmount_formats_git::GitMountSource::open(&repo_dir, Some(commit)).unwrap());
    let base = PathBuf::from(format!("{}@{commit}", repo_dir.display()));
    let f = Fixture { temp, base, source };
    let expected = f.temp.path().join("expected");
    let token = crate::base_identity::fixtures::classify(&f.base);
    let ov = WriteOverlay::open(
        &token,
        f.source.clone(),
        &expected,
        &ratarmount_compositing::CreateOptions::default(),
    )
    .unwrap();
    for (name, data) in &edited {
        cow::cow_write(&ov, &format!("/{name}"), data);
    }
    drop(ov);
    for (label, patch) in [("full", full), ("abbrev", abbrev.into_bytes())] {
        let args = f.args(label);
        let patches = parse::parse(&patch, args.max_patch_bytes).unwrap();
        assert!(patches.iter().all(|p| p.delta.is_some()), "{label}");
        let stack = ImportStack::open(&args, &Default::default()).unwrap();
        assert_eq!(import(&args, &patches, stack, 123.0).unwrap().1, 0);
        let view = f.view(&args.directory);
        for (name, data) in &edited {
            assert_eq!(
                &read_entry(&view, name, 1 << 20).unwrap().unwrap().1,
                data,
                "{label} {name}"
            );
        }
        assert_eq!(f.hash(&expected), f.hash(&args.directory), "{label}");
    }
    // Reverse round trip: ratarmount's own `diff --git` (literal sections) of
    // the imported overlay must import to the same canonical hash.
    let args = f.args("again");
    let diff = crate::diff::DiffArgs {
        directory: f.temp.path().join("full"),
        base_source: Some(f.base.clone()),
        git: true,
        output: Some(args.patch.clone()),
        ..Default::default()
    };
    assert_eq!(crate::diff::run(&diff, &Default::default()), 1);
    let patch = fs::read(&args.patch).unwrap();
    let patches = parse::parse(&patch, args.max_patch_bytes).unwrap();
    let stack = ImportStack::open(&args, &Default::default()).unwrap();
    assert_eq!(import(&args, &patches, stack, 123.0).unwrap().1, 0);
    assert_eq!(f.hash(&expected), f.hash(&args.directory));
}
