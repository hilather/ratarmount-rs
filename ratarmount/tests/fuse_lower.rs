//! Regression: composed lower layers through the kernel FUSE client.
#![cfg(target_os = "linux")]

use ratarmount_compositing::{
    compose_stack, FolderMountSource, Immutability, OverlayMeta, WriteOverlay,
};
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn available() -> bool {
    if !Path::new("/dev/fuse").exists() {
        eprintln!("skip: /dev/fuse unavailable");
        return false;
    }
    if Command::new("fusermount3")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("skip: fusermount3 unavailable");
        return false;
    }
    true
}

struct Mount {
    child: Child,
    path: PathBuf,
}
impl Mount {
    fn start(base: &Path, lower: &Path, top: Option<&Path>, path: &Path) -> Self {
        fs::create_dir(path).unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ratarmount"));
        cmd.args([
            "-f",
            "--passthrough",
            "off",
            "--index-file",
            ":memory:",
            "--lower",
        ])
        .arg(lower);
        if let Some(top) = top {
            cmd.arg("-w").arg(top);
        }
        let child = cmd
            .arg(base)
            .arg(path)
            .stdin(Stdio::null())
            .spawn()
            .unwrap();
        let mut mount = Self {
            child,
            path: path.into(),
        };
        let deadline = Instant::now() + Duration::from_secs(20);
        while !path.join("Makefile").exists() {
            assert!(mount.child.try_wait().unwrap().is_none(), "mount exited");
            assert!(Instant::now() < deadline, "mount timeout");
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

fn fixture(root: &Path) -> (PathBuf, PathBuf) {
    let base = root.join("base");
    fs::create_dir_all(base.join("lib")).unwrap();
    fs::write(base.join("Makefile"), b"base makefile").unwrap();
    fs::write(base.join("lib/Foo.pm"), b"base source").unwrap();
    fs::write(base.join("recreated"), b"base file").unwrap();
    let prepared = root.join("prepared");
    let overlay =
        WriteOverlay::new(Arc::new(FolderMountSource::new(&base).unwrap()), &prepared).unwrap();
    overlay.unlink("/recreated").unwrap();
    drop(overlay);
    fs::create_dir(prepared.join("blib")).unwrap();
    fs::write(prepared.join("blib/x"), b"built x").unwrap();
    fs::write(prepared.join("blib/copy"), b"prepared bytes").unwrap();
    fs::write(prepared.join("Makefile"), b"prepared makefile").unwrap();
    ratarmount_compositing::overlay_fsck::fsck(&prepared, true).unwrap();
    ratarmount_compositing::overlay_seal::seal(
        &prepared,
        Arc::new(FolderMountSource::new(&base).unwrap()),
    )
    .unwrap();
    (base, prepared)
}

/// Regression: attempt tombstones, lower-only copy-up, and re-created names disagreed with the stack.
#[test]
fn regression_fuse_lower_composed_reads_listing_and_copy_up() {
    if !available() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (base, lower) = fixture(root.path());
    let top = root.path().join("attempt");
    let path = root.path().join("mnt");
    let mount = Mount::start(&base, &lower, Some(&top), &path);
    assert_eq!(
        fs::read(path.join("Makefile")).unwrap(),
        b"prepared makefile"
    );
    fs::write(path.join("lib/Foo.pm"), b"attempt source").unwrap();
    fs::remove_file(path.join("blib/x")).unwrap();
    fs::write(path.join("recreated"), b"attempt recreation").unwrap();
    // Open without O_TRUNC: copy-up must retain all the lower-only bytes.
    let mut copy = fs::OpenOptions::new()
        .read(true)
        .append(true)
        .open(path.join("blib/copy"))
        .unwrap();
    copy.write_all(b" + attempt").unwrap();
    copy.seek(SeekFrom::Start(0)).unwrap();
    let mut bytes = Vec::new();
    copy.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"prepared bytes + attempt");
    drop(copy);
    let mut names: Vec<_> = fs::read_dir(path.join("blib"))
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    names.sort();
    assert_eq!(names, ["copy"]);
    assert_eq!(
        fs::read(path.join("lib/Foo.pm")).unwrap(),
        b"attempt source"
    );
    assert_eq!(
        fs::read(path.join("recreated")).unwrap(),
        b"attempt recreation"
    );
    assert_eq!(
        fs::read(lower.join("blib/copy")).unwrap(),
        b"prepared bytes"
    );
    drop(mount);
    assert_eq!(
        fs::read(top.join("blib/copy")).unwrap(),
        b"prepared bytes + attempt"
    );
    // Also verify the same view without FUSE caches after unmount.
    let stack = compose_stack(
        Arc::new(FolderMountSource::new(base).unwrap()),
        &[
            (lower.clone(), Immutability::Immutable),
            (top, Immutability::Shared),
        ],
    )
    .unwrap();
    assert!(stack.lookup("/blib/x", 0).is_none());
    assert!(stack.lookup("/recreated", 0).is_some());
    ratarmount_compositing::overlay_seal::unseal(&lower).unwrap();
}

/// Regression: sealed lower SQLite locks prevented two writable tops from sharing content.
#[test]
fn regression_fuse_lower_two_tops_share_sealed_bytes() {
    if !available() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (base, lower) = fixture(root.path());
    let a = root.path().join("a");
    let b = root.path().join("b");
    let _first = Mount::start(&base, &lower, Some(&root.path().join("top-a")), &a);
    let _second = Mount::start(&base, &lower, Some(&root.path().join("top-b")), &b);
    assert_eq!(
        fs::read(a.join("blib/copy")).unwrap(),
        fs::read(b.join("blib/copy")).unwrap()
    );
    fs::write(a.join("blib/copy"), b"first attempt").unwrap();
    assert_eq!(fs::read(b.join("blib/copy")).unwrap(), b"prepared bytes");
    drop((_first, _second));
    ratarmount_compositing::overlay_seal::unseal(&lower).unwrap();
}

/// Regression: a composed mount without -w must serve the lower view read-only.
#[test]
fn regression_fuse_lower_read_only_without_top() {
    if !available() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (base, lower) = fixture(root.path());
    let path = root.path().join("mnt");
    let _mount = Mount::start(&base, &lower, None, &path);
    assert_eq!(
        fs::read(path.join("Makefile")).unwrap(),
        b"prepared makefile"
    );
    assert_eq!(fs::read(path.join("blib/x")).unwrap(), b"built x");
    assert!(!path.join("recreated").exists());
    assert_eq!(
        fs::write(path.join("new"), b"no")
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EROFS)
    );
    drop(_mount);
    ratarmount_compositing::overlay_seal::unseal(&lower).unwrap();
}

fn root_xattr(mount: &Path, name: &str) -> String {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(mount.as_os_str().as_bytes()).unwrap();
    let name = std::ffi::CString::new(name).unwrap();
    let mut buf = vec![0u8; 64 * 1024];
    let n = unsafe {
        libc::getxattr(
            path.as_ptr(),
            name.as_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
        )
    };
    assert!(n >= 0, "getxattr: {}", std::io::Error::last_os_error());
    buf.truncate(n as usize);
    String::from_utf8(buf).unwrap()
}

/// Regression: a read-only `--lower` mount (no `-w` top) served empty
/// `user.ratarmount.stack_digest`/`layers` and `sealed` 0, so a grader could
/// not tell which stack it was reading.
#[test]
fn regression_fuse_lower_read_only_root_xattrs_name_the_stack() {
    if !available() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (base, lower) = fixture(root.path());
    let path = root.path().join("mnt");
    let _mount = Mount::start(&base, &lower, None, &path);
    let layer_digest = OverlayMeta::read(&lower)
        .unwrap()
        .unwrap()
        .get("layer_digest")
        .unwrap()
        .to_owned();
    // The mounted base's own weak identity (the fixture lower is kind `none`
    // and records none), never the lower's recorded digest.
    let base_digest = ratarmount_compositing::overlay_meta::directory_weak_digest(
        &base,
        &ratarmount_compositing::overlay_meta::BaseExcludes::default(),
    )
    .unwrap();
    assert_eq!(
        root_xattr(&path, "user.ratarmount.stack_digest"),
        ratarmount_compositing::stack_digest(&base_digest, &[&layer_digest])
    );
    assert_eq!(
        root_xattr(&path, "user.ratarmount.base_digest"),
        base_digest
    );
    assert_eq!(root_xattr(&path, "user.ratarmount.sealed"), "1");
    let layers: serde_json::Value =
        serde_json::from_str(&root_xattr(&path, "user.ratarmount.layers")).unwrap();
    assert_eq!(layers[0]["layer_digest"], layer_digest);
    assert_eq!(
        layers[0]["path"],
        lower.canonicalize().unwrap().to_str().unwrap()
    );
    drop(_mount);
    ratarmount_compositing::overlay_seal::unseal(&lower).unwrap();
}
