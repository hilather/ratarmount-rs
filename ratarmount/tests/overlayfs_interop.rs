//! Kernel overlayfs probe is opt-in; synthetic CLI coverage always runs without FUSE.
#![cfg(target_os = "linux")]

#[path = "support/token.rs"]
mod token;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ratarmount_compositing::{compose_stack, FolderMountSource, Immutability};
use ratarmount_core::{MountSource, S_IFDIR, S_IFLNK, S_IFMT, S_IFREG};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

type Snapshot = BTreeMap<String, Value>;

fn cli(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_ratarmount"))
        .args(args)
        .output()
        .unwrap()
}

fn success(output: &std::process::Output) {
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Regression: upperdir CLI dispatch must report errors as exit 2 and emit a usable manifest.
#[test]
fn regression_upperdir_cli_whiteout_manifest_and_error_exit() {
    let root = tempfile::tempdir().unwrap();
    let base = root.path().join("base");
    let upper = root.path().join("upper");
    let dest = root.path().join("imported");
    fs::create_dir(&base).unwrap();
    fs::create_dir(&upper).unwrap();
    fs::set_permissions(&upper, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(base.join("deleted"), b"lower").unwrap();
    fs::write(upper.join(".wh.deleted"), b"").unwrap();
    fs::write(upper.join("added"), b"upper").unwrap();
    success(&cli(&[
        "overlay",
        "import-upperdir",
        upper.to_str().unwrap(),
        dest.to_str().unwrap(),
        base.to_str().unwrap(),
    ]));
    let manifest = cli(&["diff", "--manifest", dest.to_str().unwrap()]);
    success(&manifest);
    let rows: Vec<Value> = String::from_utf8(manifest.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(rows.len(), 3);
    // FolderMountSource has a synthetic 0777 root; import preserves the upper's 0755.
    assert_eq!(rows[0]["path"], "");
    assert_eq!(rows[0]["mode"], "040755");
    assert_eq!(rows[0]["status"], "modified");
    assert_eq!(rows[1]["path"], "added");
    assert_eq!(
        rows[1]["hash"],
        format!("sha256:{:x}", Sha256::digest(b"upper"))
    );
    assert_eq!(rows[2]["path"], "deleted");
    assert_eq!(rows[2]["status"], "deleted");
    let error = cli(&[
        "overlay",
        "import-upperdir",
        upper.to_str().unwrap(),
        dest.to_str().unwrap(),
        base.to_str().unwrap(),
    ]);
    assert_eq!(error.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&error.stderr).contains("empty directory"));
    ratarmount_compositing::overlay_seal::unseal(&dest).unwrap();
}

struct Mount {
    child: Child,
    path: PathBuf,
}

impl Mount {
    fn start(base: &Path, lower: &Path, path: &Path) -> Self {
        fs::create_dir(path).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_ratarmount"));
        command.args(["-f", "--passthrough", "off", "--index-file", ":memory:"]);
        if std::env::var_os("RATARMOUNT_OVERLAYFS_ALLOW_OTHER").as_deref()
            == Some(std::ffi::OsStr::new("1"))
        {
            command.args(["-o", "allow_other"]);
        }
        let child = command
            .arg("--lower")
            .arg(lower)
            .arg(base)
            .arg(path)
            .stdin(Stdio::null())
            .spawn()
            .unwrap();
        let mut mount = Self {
            child,
            path: path.into(),
        };
        let deadline = Instant::now() + Duration::from_secs(30);
        while !path.join("Makefile").exists() {
            assert!(
                mount.child.try_wait().unwrap().is_none(),
                "read-only ratarmount exited"
            );
            assert!(
                Instant::now() < deadline,
                "read-only ratarmount mount timeout"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        mount
    }
}

impl Drop for Mount {
    fn drop(&mut self) {
        let _ = Command::new("fusermount3")
            .arg("-u")
            .arg(&self.path)
            .status();
        let deadline = Instant::now() + Duration::from_secs(10);
        while self.child.try_wait().ok().flatten().is_none() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn snapshot(source: &dyn MountSource, path: &str, out: &mut Snapshot) {
    if path == "/" {
        let root = source.lookup("/", 0).unwrap();
        out.insert(
            String::new(),
            json!({"type":"dir", "mode":format!("{:06o}", root.mode), "size":0}),
        );
    }
    for child in source.list_dirents(path).unwrap() {
        let name = format!("{}/{}", path.trim_end_matches('/'), child.name);
        let fi = source.lookup(&name, 0).unwrap();
        let mode = format!("{:06o}", fi.mode);
        let row = match fi.mode & S_IFMT {
            S_IFDIR => json!({"type":"dir", "mode":mode, "size":0}),
            S_IFLNK => {
                json!({"type":"symlink", "mode":mode, "size":fi.linkname.len(), "hash":format!("sha256:{:x}", Sha256::digest(fi.linkname.as_bytes())), "target":fi.linkname})
            }
            S_IFREG => {
                let mut hash = Sha256::new();
                let mut reader = source.open(&fi, libc::O_RDONLY).unwrap();
                let mut buffer = [0u8; 8192];
                loop {
                    let n = reader.read(&mut buffer).unwrap();
                    if n == 0 {
                        break;
                    }
                    hash.update(&buffer[..n]);
                }
                json!({"type":"file", "mode":mode, "size":fi.size, "hash":format!("sha256:{:x}", hash.finalize())})
            }
            _ => panic!("unexpected file type: {name}"),
        };
        out.insert(name.trim_start_matches('/').into(), row);
        if fi.mode & S_IFMT == S_IFDIR {
            snapshot(source, &name, out);
        }
    }
}

fn check_manifest(manifest: &Path, before: &Snapshot, after: &Snapshot) {
    let expected: BTreeSet<_> = before
        .keys()
        .chain(after.keys())
        .filter(|path| before.get(*path) != after.get(*path))
        .cloned()
        .collect();
    let mut seen = BTreeSet::new();
    for line in fs::read_to_string(manifest).unwrap().lines() {
        let row: Value = serde_json::from_str(line).unwrap();
        let path = row["path"].as_str().unwrap();
        assert!(seen.insert(path.to_owned()), "duplicate row: {path}");
        let old = before.get(path);
        let new = after.get(path);
        let status = match (old, new) {
            (None, Some(_)) => "added",
            (Some(_), None) => "deleted",
            (Some(a), Some(b)) if a["type"] != b["type"] => "type_changed",
            (Some(_), Some(_)) => "modified",
            _ => panic!("manifest path absent from both kernel snapshots: {path}"),
        };
        assert_eq!(row["status"], status, "{path}");
        assert_eq!(row["type"], new.or(old).unwrap()["type"], "{path}");
        if let Some(new) = new {
            for key in ["mode", "size", "hash", "target"] {
                assert_eq!(row[key], new[key], "{path}: {key}");
            }
        }
        if let Some(old) = old {
            assert_eq!(row["base_hash"], old["hash"], "{path}");
        }
    }
    assert_eq!(
        seen, expected,
        "manifest differs from independent kernel snapshots"
    );
}

/// Regression: build/test, whiteouts and opaque replacement must agree with the kernel merged view.
#[test]
fn regression_overlayfs_read_only_lower_and_imported_upper_match_kernel() {
    if std::env::var_os("RATARMOUNT_TEST_OVERLAYFS").as_deref() != Some(std::ffi::OsStr::new("1")) {
        eprintln!("skip: set RATARMOUNT_TEST_OVERLAYFS=1 for kernel overlayfs interop");
        return;
    }
    if !Path::new("/dev/fuse").exists() {
        eprintln!("skip: /dev/fuse unavailable");
        return;
    }
    for tool in [
        "bash",
        "unshare",
        "mount",
        "umount",
        "make",
        "python3",
        "fusermount3",
    ] {
        if Command::new(tool).arg("--version").output().is_err() {
            eprintln!("skip: {tool} unavailable");
            return;
        }
    }
    let probe = Command::new("unshare")
        .args(["-Urm", "true"])
        .output()
        .unwrap();
    if !probe.status.success() {
        eprintln!(
            "skip: unprivileged user/mount namespaces unavailable: {}",
            String::from_utf8_lossy(&probe.stderr)
        );
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let base = root.path().join("base");
    fs::create_dir_all(base.join("opaque/sub")).unwrap();
    fs::create_dir_all(base.join("to-file/sub")).unwrap();
    for name in ["opaque/sub/old", "to-file/sub/old", "to-dir", "remove-me"] {
        fs::write(base.join(name), b"old\n").unwrap();
    }
    fs::write(base.join("input"), b"base\n").unwrap();
    fs::write(base.join("Makefile"), b"all:\n\tmkdir -p build\n\tcat input > build/result\n\ttest \"$$(cat build/result)\" = prepared\n").unwrap();
    let lower = root.path().join("prepared");
    let source: Arc<dyn MountSource> = Arc::new(FolderMountSource::new(&base).unwrap());
    let writer =
        token::overlay_over(source.clone(), &lower, base.to_str().unwrap(), Vec::new()).unwrap();
    use std::os::fd::FromRawFd;
    let mut file = unsafe { fs::File::from_raw_fd(writer.create_file("/input", 0o644).unwrap()) };
    file.write_all(b"prepared\n").unwrap();
    writer.finish_owned_write_fd(file);
    drop(writer);
    token::seal(&lower, source.clone()).unwrap();
    let mount = Mount::start(&base, &lower, &root.path().join("lower-mnt"));
    let script =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../test-harness/overlayfs-interop/run.sh");
    let output = Command::new("unshare")
        .args(["-Urm", "bash"])
        .arg(script)
        .arg(env!("CARGO_BIN_EXE_ratarmount"))
        .arg(root.path())
        .output()
        .unwrap();
    if output.status.code() == Some(77) {
        eprintln!(
            "skip: kernel overlayfs rejected this FUSE lowerdir/configuration:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        drop(mount);
        ratarmount_compositing::overlay_seal::unseal(&lower).unwrap();
        return;
    }
    success(&output);
    eprintln!("{}", String::from_utf8_lossy(&output.stdout));
    let before: Snapshot =
        serde_json::from_slice(&fs::read(root.path().join("before.json")).unwrap()).unwrap();
    let after: Snapshot =
        serde_json::from_slice(&fs::read(root.path().join("after.json")).unwrap()).unwrap();
    for name in ["imported-native", "imported-copy"] {
        check_manifest(&root.path().join(format!("{name}.jsonl")), &before, &after);
        let stack = compose_stack(
            source.clone(),
            &[
                (lower.clone(), Immutability::Immutable),
                (root.path().join(name), Immutability::Immutable),
            ],
        )
        .unwrap();
        let mut actual = Snapshot::new();
        snapshot(stack.as_ref(), "/", &mut actual);
        assert_eq!(
            actual, after,
            "{name}: composed view differs from kernel view"
        );
        drop(stack);
        ratarmount_compositing::overlay_seal::unseal(&root.path().join(name)).unwrap();
    }
    drop(mount);
    ratarmount_compositing::overlay_seal::unseal(&lower).unwrap();
}
