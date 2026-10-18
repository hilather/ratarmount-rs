//! Regression: portable layers through the CLI and the kernel FUSE client.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::process::Child;
use std::process::{Command, Output};
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

use ratarmount_compositing::{FolderMountSource, OverlayCreateInfo, WriteOverlay};

fn command(args: &[&Path], cache: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ratarmount"))
        .env("XDG_CACHE_HOME", cache)
        .args(args)
        .output()
        .unwrap()
}

fn expect(output: Output, code: i32) -> String {
    assert_eq!(
        output.status.code(),
        Some(code),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

struct Fixture {
    tmp: tempfile::TempDir,
    base: PathBuf,
    overlay: PathBuf,
    bundle: PathBuf,
    cache: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("base");
        fs::create_dir(&base).unwrap();
        fs::write(base.join("deleted"), b"old").unwrap();
        let overlay = tmp.path().join("overlay");
        let source = Arc::new(FolderMountSource::new(&base).unwrap());
        let writer = WriteOverlay::new_with_create_info(
            source.clone(),
            &overlay,
            &OverlayCreateInfo {
                base_url: base.to_str().unwrap().into(),
                ..Default::default()
            },
        )
        .unwrap();
        writer.unlink("/deleted").unwrap();
        let fd = writer.create_file("/payload", 0o751).unwrap();
        writer.close_overlay_fd(fd);
        fs::write(overlay.join("payload"), b"bundle bytes\n").unwrap();
        drop(writer);
        ratarmount_compositing::overlay_seal::seal(&overlay, source).unwrap();
        let bundle = tmp.path().join("bundle.tar.zst");
        let cache = tmp.path().join("cache");
        expect(
            command(
                &[Path::new("overlay"), Path::new("pack"), &overlay, &bundle],
                &cache,
            ),
            0,
        );
        Self {
            tmp,
            base,
            overlay,
            bundle,
            cache,
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fn writable(path: &Path) {
            let Ok(meta) = fs::symlink_metadata(path) else {
                return;
            };
            if meta.is_dir() {
                fs::set_permissions(
                    path,
                    fs::Permissions::from_mode(meta.permissions().mode() | 0o700),
                )
                .unwrap();
                for child in fs::read_dir(path).unwrap() {
                    writable(&child.unwrap().path());
                }
            }
        }
        writable(self.tmp.path());
    }
}

/// Regression: pack/unpack and a bundle passed as --lower must work without a
/// FUSE mount, keep the same seal, and reuse the digest cache across processes.
#[test]
fn regression_bundle_cli_roundtrip_and_lower_cache() {
    let f = Fixture::new();
    let restored = f.tmp.path().join("restored");
    let digest = expect(
        command(
            &[
                Path::new("overlay"),
                Path::new("unpack"),
                &f.bundle,
                &restored,
            ],
            &f.cache,
        ),
        0,
    );
    assert_eq!(
        expect(
            command(
                &[Path::new("overlay"), Path::new("verify"), &restored],
                &f.cache
            ),
            0
        ),
        digest
    );
    for _ in 0..2 {
        expect(
            command(
                &[
                    Path::new("--no-mount"),
                    Path::new("--lower"),
                    &f.bundle,
                    &f.base,
                ],
                &f.cache,
            ),
            0,
        );
    }
    let cached = f
        .cache
        .join("ratarmount/layers")
        .join(digest.trim().strip_prefix("sha256:").unwrap());
    assert_eq!(fs::read(cached.join("payload")).unwrap(), b"bundle bytes\n");
    assert_eq!(
        fs::read_dir(f.cache.join("ratarmount/layers"))
            .unwrap()
            .count(),
        1
    );
    fs::set_permissions(f.overlay.join("payload"), fs::Permissions::from_mode(0o751)).unwrap();
    fs::write(f.overlay.join("payload"), b"tampered payload").unwrap();
    let tampered = f.tmp.path().join("tampered.tar.zst");
    expect(
        command(
            &[
                Path::new("overlay"),
                Path::new("pack"),
                &f.overlay,
                &tampered,
            ],
            &f.cache,
        ),
        0,
    );
    expect(
        command(
            &[
                Path::new("overlay"),
                Path::new("unpack"),
                &tampered,
                &f.tmp.path().join("tampered"),
            ],
            &f.cache,
        ),
        1,
    );
    expect(
        command(
            &[
                Path::new("overlay"),
                Path::new("unseal"),
                &f.overlay,
                Path::new("--i-know"),
            ],
            &f.cache,
        ),
        0,
    );
    let refused = f.tmp.path().join("unsealed.tar.zst");
    expect(
        command(
            &[
                Path::new("overlay"),
                Path::new("pack"),
                &f.overlay,
                &refused,
            ],
            &f.cache,
        ),
        2,
    );
    assert!(!refused.exists());
}

#[cfg(target_os = "linux")]
struct Mount {
    child: Child,
    path: PathBuf,
}
#[cfg(target_os = "linux")]
impl Mount {
    fn start(f: &Fixture, lower: bool) -> Self {
        let path = f
            .tmp
            .path()
            .join(if lower { "lower-mount" } else { "bundle-mount" });
        fs::create_dir(&path).unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ratarmount"));
        cmd.env("XDG_CACHE_HOME", &f.cache).args([
            "-f",
            "--passthrough",
            "off",
            "--index-file",
            ":memory:",
        ]);
        if lower {
            cmd.arg("--lower").arg(&f.bundle).arg(&f.base);
        } else {
            cmd.arg(&f.bundle);
        }
        let child = cmd.arg(&path).spawn().unwrap();
        let mut mount = Self { child, path };
        let ready = mount.path.join(if lower { "payload" } else { "meta.json" });
        let deadline = Instant::now() + Duration::from_secs(30);
        while !ready.exists() {
            assert!(mount.child.try_wait().unwrap().is_none(), "mount exited");
            assert!(Instant::now() < deadline, "mount timeout");
            std::thread::sleep(Duration::from_millis(50));
        }
        mount
    }
}
#[cfg(target_os = "linux")]
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

/// Regression: a bundle must mount as an ordinary tar.zst showing its envelope,
/// and as a lower showing the composed layer with tombstones applied.
#[test]
#[cfg(target_os = "linux")]
fn regression_fuse_bundle_direct_and_as_lower() {
    if !Path::new("/dev/fuse").exists() {
        eprintln!("skip: /dev/fuse unavailable");
        return;
    }
    if Command::new("fusermount3")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("skip: fusermount3 unavailable");
        return;
    }
    let f = Fixture::new();
    {
        let mount = Mount::start(&f, false);
        assert_eq!(
            fs::read(mount.path.join("layer/payload")).unwrap(),
            b"bundle bytes\n"
        );
        assert!(mount.path.join("manifest.jsonl").exists());
        assert!(mount.path.join("meta.json").exists());
    }
    {
        let mount = Mount::start(&f, true);
        assert_eq!(
            fs::read(mount.path.join("payload")).unwrap(),
            b"bundle bytes\n"
        );
        assert!(!mount.path.join("deleted").exists());
        assert!(!mount.path.join("layer").exists());
    }
}
