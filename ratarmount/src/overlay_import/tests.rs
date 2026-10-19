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

/// Regression: unsupported binary encodings must name the affected path.
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
