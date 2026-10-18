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

#[path = "diff/cow.rs"]
mod cow;

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
        fs::write(base.join("payload"), b"original\n").unwrap();
        fs::set_permissions(base.join("payload"), fs::Permissions::from_mode(0o751)).unwrap();
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
        cow::cow_write(&writer, "/payload", b"bundle bytes\n");
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
fn regression_cow_bundle_cli_roundtrip_and_lower_cache() {
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
    // Regression: publishing renames the sealed root (macOS needs write
    // permission for that); the published root must be read-only again.
    assert_eq!(
        fs::metadata(&restored).unwrap().permissions().mode() & 0o222,
        0
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
    // The entry is named by the SHA-256 of the bundle bytes (not by the
    // layer digest it claims) and has no stray copy or staging directory.
    let bundle_hex =
        ratarmount_index::sha256_hex_stream(&mut fs::File::open(&f.bundle).unwrap()).unwrap();
    let cached = f.cache.join("ratarmount/layers").join(&bundle_hex);
    assert_ne!(bundle_hex, digest.trim().strip_prefix("sha256:").unwrap());
    assert_eq!(fs::read(cached.join("payload")).unwrap(), b"bundle bytes\n");
    assert_eq!(layer_entries(&f.cache), vec![bundle_hex]);
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

/// Entries of the lower cache that are neither hidden staging nor `.verified`.
fn layer_entries(cache: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(cache.join("ratarmount/layers"))
        .map(|d| {
            d.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| !n.starts_with('.') && !n.ends_with(".verified"))
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

/// Re-tar `bundle` with one member's payload replaced; the seal metadata is
/// untouched, so the bundle is self-consistent but lies about its content.
fn retar_with(bundle: &Path, out: &Path, member: &str, payload: &[u8]) {
    use std::io::Read;
    let body = ratarmount_compress::open_seekable_zstd(bundle).unwrap();
    let mut archive = tar::Archive::new(body.open_reader().unwrap());
    let mut builder = tar::Builder::new(Vec::new());
    for entry in archive.entries().unwrap() {
        let mut entry = entry.unwrap();
        let path = entry.path().unwrap().to_string_lossy().into_owned();
        let mut header = entry.header().clone();
        let pax: Vec<(String, Vec<u8>)> = entry
            .pax_extensions()
            .unwrap()
            .map(|exts| {
                exts.map(|e| {
                    let e = e.unwrap();
                    (e.key().unwrap().to_owned(), e.value_bytes().to_vec())
                })
                .collect()
            })
            .unwrap_or_default();
        let mut data = Vec::new();
        entry.read_to_end(&mut data).unwrap();
        if path == member {
            data = payload.to_vec();
            header.set_size(data.len() as u64);
        }
        if !pax.is_empty() {
            builder
                .append_pax_extensions(pax.iter().map(|(k, v)| (k.as_str(), v.as_slice())))
                .unwrap();
        }
        header.set_cksum();
        builder.append(&header, &data[..]).unwrap();
    }
    let bytes = builder.into_inner().unwrap();
    let mut writer = ratarmount_compress::ZstdFrameWriter::new(fs::File::create(out).unwrap(), 3);
    writer.write_frame(&bytes[..]).unwrap();
    writer.finish().unwrap();
}

/// Regression (Keystone blocker 1): a tampered bundle that claims a valid
/// `layer_digest` is refused as a `--lower` against the base it is mounted
/// on, even when the base is not at its recorded path; nothing is cached, and
/// the genuine bundle still serves afterwards.
#[test]
fn regression_cow_evil_lower_bundle_refused_then_good_serves() {
    let f = Fixture::new();
    let evil = f.tmp.path().join("evil.tar.zst");
    retar_with(&f.bundle, &evil, "layer/payload", b"EVIL bytes!\n");
    let moved = f.tmp.path().join("base-away");
    fs::rename(&f.base, &moved).unwrap();
    let output = command(
        &[Path::new("--no-mount"), Path::new("--lower"), &evil, &moved],
        &f.cache,
    );
    assert_ne!(output.status.code(), Some(0), "evil lower was accepted");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("payload"), "{stderr}");
    assert!(layer_entries(&f.cache).is_empty());
    expect(
        command(
            &[
                Path::new("--no-mount"),
                Path::new("--lower"),
                &f.bundle,
                &moved,
            ],
            &f.cache,
        ),
        0,
    );
    let entries = layer_entries(&f.cache);
    assert_eq!(entries.len(), 1);
    assert_eq!(
        fs::read(
            f.cache
                .join("ratarmount/layers")
                .join(&entries[0])
                .join("payload")
        )
        .unwrap(),
        b"bundle bytes\n"
    );
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

/// Regression: a COW bundle must mount as an ordinary tar.zst showing its envelope,
/// and as a lower serving the edited payload with tombstones applied.
#[test]
#[cfg(target_os = "linux")]
fn regression_cow_fuse_bundle_direct_and_as_lower() {
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
