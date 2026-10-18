//! Regression: operation journal callbacks, root controls and rule denials on real FUSE.
#![cfg(target_os = "linux")]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;

struct Mount {
    child: Child,
    path: PathBuf,
}

impl Mount {
    fn start(base: &Path, mount: &Path, journal: Option<&Path>, overlay: Option<&Path>) -> Self {
        fs::create_dir_all(mount).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_ratarmount"));
        command.args(["-f", "--direct-io"]);
        if let Some(journal) = journal {
            command
                .args(["--journal-sync", "--journal-exclude", "excluded/**"])
                .arg("--journal")
                .arg(journal);
        }
        if let Some(overlay) = overlay {
            command
                .arg("-w")
                .arg(overlay)
                .args(["--overlay-readonly", "protected/**"]);
        }
        let child = command
            .arg(base)
            .arg(mount)
            .stdin(Stdio::null())
            .spawn()
            .unwrap();
        let mut result = Self {
            child,
            path: mount.into(),
        };
        let deadline = Instant::now() + Duration::from_secs(30);
        while !mount.join("input").exists() {
            assert!(result.child.try_wait().unwrap().is_none(), "mount exited");
            assert!(Instant::now() < deadline, "mount timed out");
            std::thread::sleep(Duration::from_millis(20));
        }
        result
    }

    fn stop(&mut self) {
        assert!(Command::new("fusermount3")
            .arg("-u")
            .arg(&self.path)
            .status()
            .unwrap()
            .success());
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(Instant::now() < deadline, "unmount timed out");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Mount {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = Command::new("fusermount3")
                .arg("-uz")
                .arg(&self.path)
                .status();
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn available() -> bool {
    if !Path::new("/dev/fuse").exists() {
        eprintln!("skip: /dev/fuse unavailable");
        return false;
    }
    for tool in ["python3", "fusermount3"] {
        if Command::new(tool).arg("--version").output().is_err() {
            eprintln!("skip: {tool} unavailable");
            return false;
        }
    }
    true
}

fn fixture(base: &Path) {
    let mut archive = Vec::new();
    let payload = vec![b'x'; 8192];
    let members = ["input", "protected/input", "excluded/input"].map(|path| {
        ratarmount_formats_tar::UstarMember {
            path,
            payload: ratarmount_formats_tar::UstarPayload::File { bytes: &payload },
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime: 0,
            xattrs: &[],
        }
    });
    ratarmount_formats_tar::write_ustar_members(&mut archive, &members).unwrap();
    fs::write(base, archive).unwrap();
}

fn events(path: &Path) -> Vec<Value> {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter(|s| !s.is_empty())
        .map(|s| serde_json::from_str(s).unwrap())
        .collect()
}

#[test]
fn regression_fuse_journal_sequence_ranges_pid_exclusions_and_status() {
    if !available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("base.tar");
    fixture(&base);
    let journal = dir.path().join("trace.jsonl");
    let overlay = dir.path().join("overlay");
    let mut mount = Mount::start(
        &base,
        &dir.path().join("mnt"),
        Some(&journal),
        Some(&overlay),
    );
    let script = r#"
import errno, json, os, subprocess, sys, time
root, exe = sys.argv[1:]
f = os.open(root + '/input', os.O_RDONLY)
assert os.pread(f, 4096, 0) == b'x' * 4096
assert os.pread(f, 4096, 4096) == b'x' * 4096
os.close(f)
# RELEASE is asynchronous to close(2); wait for its counters before marking.
for _ in range(200):
    if json.loads(os.getxattr(root, 'user.ratarmount.stats'))['ops'].get('read', 0): break
    time.sleep(.01)
else: raise AssertionError('RELEASE not observed')
subprocess.run([exe, 'journal', 'mark', root, 'turn1'], check=True)
with open(root + '/output', 'wb', buffering=0) as f: f.write(b'new')
os.mkdir(root + '/dir')
os.rename(root + '/output', root + '/dir/renamed')
os.symlink('input', root + '/link')
try: os.open(root + '/protected/input', os.O_WRONLY)
except OSError as e: assert e.errno == errno.EROFS
else: raise AssertionError('readonly rule bypassed')
with open(root + '/excluded/input', 'rb') as f: assert f.read() == b'x' * 8192
stats = json.loads(os.getxattr(root, 'user.ratarmount.stats'))
assert stats['bytes_read'] >= 8192 and stats['erofs_denied'] == 1
assert os.getxattr(root, 'user.ratarmount.sealed') == b'0'
assert os.getxattr(root, 'user.ratarmount.base_digest').startswith(b'sha256:')
assert 'user.ratarmount.stats' in os.listxattr(root)
print(os.getpid())
"#;
    let child = Command::new("python3")
        .args(["-c", script])
        .arg(&mount.path)
        .arg(env!("CARGO_BIN_EXE_ratarmount"))
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    mount.stop();
    let records = events(&journal);
    assert_eq!(records[0]["journal"], 1);
    let read = records
        .iter()
        .find(|r| r["op"] == "read" && r["path"] == "input")
        .unwrap();
    assert_eq!(read["pid"], pid);
    assert_eq!(read["layer"], "base");
    assert_eq!(read["ranges"], serde_json::json!([[0, 8192]]));
    assert!(records
        .iter()
        .all(|r| !r["path"].as_str().unwrap_or("").starts_with("excluded")));
    let mut previous = 0;
    for (op, path) in [
        ("open", "input"),
        ("read", "input"),
        ("mark", ""),
        ("create", "output"),
        ("mkdir", "dir"),
        ("rename", "output"),
        ("symlink", "link"),
        ("denied", "protected/input"),
    ] {
        let index = records
            .iter()
            .position(|r| r["op"] == op && (op == "mark" || r["path"] == path))
            .unwrap();
        assert!(index > previous, "unexpected {op} order");
        previous = index;
    }
    let rename = records.iter().find(|r| r["op"] == "rename").unwrap();
    assert_eq!(rename["to"], "dir/renamed");
    assert!(records
        .iter()
        .any(|r| r["op"] == "write" && r["path"] == "output" && r["bytes"] == 3));
    let summary = Command::new(env!("CARGO_BIN_EXE_ratarmount"))
        .args(["journal", "summarize"])
        .arg(&journal)
        .arg("--json")
        .output()
        .unwrap();
    assert!(summary.status.success());
    let summary: Value = serde_json::from_slice(&summary.stdout).unwrap();
    assert!(summary["files_read"]
        .as_array()
        .unwrap()
        .contains(&Value::from("input")));
}

#[test]
fn regression_fuse_journal_readonly_mark_reaches_root_control() {
    if !available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("base.tar");
    fixture(&base);
    let journal = dir.path().join("trace");
    let mut mount = Mount::start(&base, &dir.path().join("mnt"), Some(&journal), None);
    assert!(Command::new(env!("CARGO_BIN_EXE_ratarmount"))
        .args(["journal", "mark"])
        .arg(&mount.path)
        .arg("read-only turn")
        .status()
        .unwrap()
        .success());
    assert_eq!(
        fs::write(mount.path.join("output"), "bad")
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EROFS)
    );
    mount.stop();
    assert!(events(&journal)
        .iter()
        .any(|event| event["label"] == "read-only turn"));
    let mut no_journal = Mount::start(&base, &dir.path().join("plain"), None, None);
    let check = "import errno, os, sys\ntry: os.setxattr(sys.argv[1], 'user.ratarmount.mark', b'turn')\nexcept OSError as e: assert e.errno == errno.EROFS, e\nelse: raise AssertionError('mark unexpectedly succeeded')";
    assert!(Command::new("python3")
        .args(["-c", check])
        .arg(&no_journal.path)
        .status()
        .unwrap()
        .success());
    no_journal.stop();
}

/// Regression: a directory base records a weak digest and the journal header
/// copies it (`weak:`); a supplied digest is copied as given (`sha256:`).
#[test]
fn regression_fuse_journal_header_records_directory_base_digest_kinds() {
    if !available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("base");
    fs::create_dir(&base).unwrap();
    fs::write(base.join("input"), vec![b'x'; 8192]).unwrap();
    let supplied = format!("sha256:{}", "ab".repeat(32));
    for (name, flag, expected) in [
        ("weak", None, "weak:"),
        ("strong", Some(&supplied), "sha256:"),
    ] {
        let journal = dir.path().join(format!("{name}.jsonl"));
        let overlay = dir.path().join(format!("{name}-overlay"));
        let mount = dir.path().join(format!("{name}-mnt"));
        fs::create_dir_all(&mount).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_ratarmount"));
        command
            .args(["-f", "--passthrough", "off", "--journal"])
            .arg(&journal)
            .arg("-w")
            .arg(&overlay);
        if let Some(digest) = flag {
            command.args(["--base-digest", digest]);
        }
        let child = command
            .arg(&base)
            .arg(&mount)
            .stdin(Stdio::null())
            .spawn()
            .unwrap();
        let mut guard = Mount {
            child,
            path: mount.clone(),
        };
        let deadline = Instant::now() + Duration::from_secs(30);
        while !mount.join("input").exists() {
            assert!(guard.child.try_wait().unwrap().is_none(), "mount exited");
            assert!(Instant::now() < deadline, "mount timed out");
            std::thread::sleep(Duration::from_millis(20));
        }
        guard.stop();
        let header = &events(&journal)[0];
        let recorded = header["base_digest"].as_str().unwrap_or("");
        assert!(recorded.starts_with(expected), "{name}: {header}");
    }
}
