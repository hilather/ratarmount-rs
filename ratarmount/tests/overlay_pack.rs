//! Regression: portable layers through the CLI and the kernel FUSE client.

#[path = "support/token.rs"]
mod token;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::process::Child;
use std::process::{Command, Output};
use std::sync::Arc;
use std::time::Duration;
#[cfg(target_os = "linux")]
use std::time::Instant;

use ratarmount_compositing::FolderMountSource;

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
        let writer =
            token::overlay_over(source.clone(), &overlay, base.to_str().unwrap(), Vec::new())
                .unwrap();
        writer.unlink("/deleted").unwrap();
        cow::cow_write(&writer, "/payload", b"bundle bytes\n");
        drop(writer);
        token::seal(&overlay, source).unwrap();
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
                let _ = fs::set_permissions(
                    path,
                    fs::Permissions::from_mode(meta.permissions().mode() | 0o700),
                );
                if let Ok(children) = fs::read_dir(path) {
                    for child in children.flatten() {
                        writable(&child.path());
                    }
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

/// Regression: an overlay from an earlier build holds a credentialed `base_url`
/// and `base_remote_token`; `pack` exported both raw, in `meta.json` and in the
/// bundled database.
#[test]
fn regression_pack_redacts_credentialed_base_in_meta_and_db() {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().join("base");
    fs::create_dir(&base).unwrap();
    fs::write(base.join("f"), b"x").unwrap();
    let overlay = tmp.path().join("overlay");
    let source = Arc::new(FolderMountSource::new(&base).unwrap());
    let writer =
        token::overlay_over(source.clone(), &overlay, base.to_str().unwrap(), Vec::new()).unwrap();
    cow::cow_write(&writer, "/f", b"changed\n");
    drop(writer);
    // Earlier-build shape: raw URL and a JSON array of raw inputs.
    let raw = "https://user:s3cr3t@h.example/b.tar?X-Amz-Signature=deadbeef";
    {
        let conn = rusqlite::Connection::open(overlay.join(".ratarmount.overlay.sqlite")).unwrap();
        conn.execute("UPDATE meta SET value=?1 WHERE key='base_url'", [raw])
            .unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO meta(key,value) VALUES('base_remote_token', ?1)",
            [serde_json::to_string(&[raw, "/plain/second"]).unwrap()],
        )
        .unwrap();
    }
    token::seal(&overlay, source).unwrap();
    let before = fs::read(overlay.join(".ratarmount.overlay.sqlite")).unwrap();
    let bundle = tmp.path().join("bundle.tar.zst");
    let cache = tmp.path().join("cache");
    expect(
        command(
            &[
                Path::new("overlay"),
                Path::new("pack"),
                &overlay,
                &bundle,
                &base,
            ],
            &cache,
        ),
        0,
    );
    assert_eq!(
        fs::read(overlay.join(".ratarmount.overlay.sqlite")).unwrap(),
        before,
        "pack must not modify the source overlay"
    );
    let bytes = fs::read(&bundle).unwrap();
    let mut tar_bytes = Vec::new();
    std::io::Read::read_to_end(
        &mut zstd::stream::read::Decoder::new(&bytes[..]).unwrap(),
        &mut tar_bytes,
    )
    .unwrap();
    let mut archive = tar::Archive::new(&tar_bytes[..]);
    let (mut meta_json, mut db) = (Vec::new(), Vec::new());
    for entry in archive.entries().unwrap() {
        let mut entry = entry.unwrap();
        let path = entry.path().unwrap().to_string_lossy().into_owned();
        if path == "meta.json" {
            std::io::Read::read_to_end(&mut entry, &mut meta_json).unwrap();
        } else if path == "layer/.ratarmount.overlay.sqlite" {
            std::io::Read::read_to_end(&mut entry, &mut db).unwrap();
        }
    }
    assert!(!db.is_empty() && !meta_json.is_empty());
    for (name, data) in [("meta.json", &meta_json), ("database", &db)] {
        let text = String::from_utf8_lossy(data);
        for secret in ["s3cr3t", "deadbeef"] {
            assert!(!text.contains(secret), "{name} leaked {secret}");
        }
    }
    let extracted = tmp.path().join("db.sqlite");
    fs::write(&extracted, &db).unwrap();
    let conn = rusqlite::Connection::open(&extracted).unwrap();
    let mut stmt = conn.prepare("SELECT key, value FROM meta").unwrap();
    let rows: std::collections::BTreeMap<String, String> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let json: std::collections::BTreeMap<String, String> =
        serde_json::from_slice(&meta_json).unwrap();
    assert_eq!(rows, json, "meta.json must equal the bundled database meta");
    assert_eq!(rows["base_url"], "https://h.example/b.tar");
    assert_eq!(
        rows["base_remote_token"],
        r#"["https://h.example/b.tar","/plain/second"]"#
    );
    // The redacted bundle still unpacks.
    let restored = tmp.path().join("restored");
    let out = command(
        &[
            Path::new("overlay"),
            Path::new("unpack"),
            &bundle,
            &restored,
        ],
        &cache,
    );
    assert!(
        out.status.code().is_some_and(|c| c == 0 || c == 1),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains("does not match"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn unpack_cmd(f: &Fixture, dest: &Path, extra: &[&str], env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ratarmount"));
    cmd.env("XDG_CACHE_HOME", &f.cache)
        .env("HOME", f.tmp.path())
        .env_remove("RATARMOUNT_BUNDLE_MAX_BYTES")
        .env_remove("RATARMOUNT_BUNDLE_MAX_ENTRIES")
        .args(["overlay", "unpack"])
        .arg(&f.bundle)
        .arg(dest)
        .args(extra);
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().unwrap()
}

fn expect_cap_refusal(output: Output, dest: &Path, what: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert_eq!(output.status.code(), Some(2), "stderr: {stderr}");
    assert!(
        stderr.contains("extracts more than") && stderr.contains(what),
        "stderr: {stderr}"
    );
    assert!(!dest.exists(), "destination must be absent");
}

/// Regression: a bundle extracting more entries or bytes than the caps (set
/// through the environment) is refused, leaving no destination; before the
/// caps existed the variables were ignored and the unpack succeeded.
#[test]
fn regression_unpack_env_caps_refuse_bundle() {
    let f = Fixture::new();
    let dest = f.tmp.path().join("env-entries");
    expect_cap_refusal(
        unpack_cmd(&f, &dest, &[], &[("RATARMOUNT_BUNDLE_MAX_ENTRIES", "2")]),
        &dest,
        "entries",
    );
    let dest = f.tmp.path().join("env-bytes");
    expect_cap_refusal(
        unpack_cmd(&f, &dest, &[], &[("RATARMOUNT_BUNDLE_MAX_BYTES", "100")]),
        &dest,
        "bytes",
    );
}

/// The flags take the same caps and beat the environment.
#[test]
fn regression_unpack_flag_caps_refuse_bundle_and_override_env() {
    let f = Fixture::new();
    let dest = f.tmp.path().join("flag-entries");
    expect_cap_refusal(
        unpack_cmd(&f, &dest, &["--max-entries", "2"], &[]),
        &dest,
        "entries",
    );
    let dest = f.tmp.path().join("flag-bytes");
    expect_cap_refusal(
        unpack_cmd(&f, &dest, &["--max-bytes", "100"], &[]),
        &dest,
        "bytes",
    );
    let dest = f.tmp.path().join("flag-wins");
    let out = unpack_cmd(
        &f,
        &dest,
        &["--max-entries", "1000000", "--max-bytes", "1G"],
        &[
            ("RATARMOUNT_BUNDLE_MAX_ENTRIES", "2"),
            ("RATARMOUNT_BUNDLE_MAX_BYTES", "100"),
        ],
    );
    expect(out, 0);
    assert!(dest.is_dir());
}

/// Run `overlay pack OVERLAY OUT` with the pack-hold seam, SIGKILL it while it
/// holds its output temp file, and return the entries it left beside `OUT`.
fn kill_pack(f: &Fixture, out: &Path) -> Vec<String> {
    let ready = f.tmp.path().join("pack-ready");
    let _ = fs::remove_file(&ready);
    let mut child = Command::new(env!("CARGO_BIN_EXE_ratarmount"))
        .env("XDG_CACHE_HOME", &f.cache)
        .env("RATARMOUNT_TEST_PACK_HOLD", &ready)
        .args(["overlay", "pack"])
        .arg(&f.overlay)
        .arg(out)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !ready.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "pack never started writing"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    child.kill().unwrap(); // SIGKILL
    child.wait().unwrap();
    assert!(!out.exists(), "killed pack published a bundle");
    entries(out.parent().unwrap())
}

fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

fn backdate(path: &Path, secs: u64) {
    let when = std::time::SystemTime::now() - Duration::from_secs(secs);
    fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(when))
        .unwrap();
}

/// Regression (I3): a SIGKILLed `overlay pack` left an empty `.tmpXXXXXX`
/// (and its staging directory) beside the bundle, and the next pack never
/// swept them. Now they carry a `.ratarmount-pack-` name and the next pack
/// removes the dead ones; young, locked, foreign-named and symlinked files stay.
#[test]
fn regression_pack_sweeps_killed_pack_leftovers() {
    use std::os::fd::AsRawFd;
    let f = Fixture::new();
    let work = f.tmp.path().join("out");
    fs::create_dir(&work).unwrap();
    let out = work.join("b.tar.zst");
    let left = kill_pack(&f, &out);
    let temps: Vec<&String> = left
        .iter()
        .filter(|n| n.starts_with(".ratarmount-pack-"))
        .collect();
    assert!(
        !temps.is_empty(),
        "no recognisable pack leftovers: {left:?}"
    );
    assert!(
        left.iter().all(|n| n.starts_with(".ratarmount-pack-")),
        "anonymous leftovers: {left:?}"
    );
    let dead_file = work.join(
        temps
            .iter()
            .find(|n| n.ends_with(".tmp"))
            .expect("temp file"),
    );
    assert_eq!(fs::metadata(&dead_file).unwrap().len(), 0);
    // Negatives: a young dead-shaped file, a live (locked) old one, foreign
    // names, an old symlink and the old anonymous `.tmpXXXXXX` shape.
    let young = work.join(".ratarmount-pack-Yg9Zq1.tmp");
    fs::write(&young, b"").unwrap();
    let live = work.join(".ratarmount-pack-Lv3Aa0.tmp");
    fs::write(&live, b"").unwrap();
    backdate(&live, 3600);
    let live_file = fs::File::open(&live).unwrap();
    assert_eq!(
        unsafe { libc::flock(live_file.as_raw_fd(), libc::LOCK_EX) },
        0
    );
    let mut keep = vec![young, live];
    for name in [
        ".ratarmount-pack-notes.tmp",
        ".ratarmount-pack-aB3xY.tmp",
        ".ratarmount-pack-aB3xY99.tmp",
        ".ratarmount-pack-aB3xY9.tmp.bak",
        "x.ratarmount-pack-aB3xY9.tmp",
        ".tmpAb3xY9",
    ] {
        let path = work.join(name);
        fs::write(&path, b"").unwrap();
        backdate(&path, 3600);
        keep.push(path);
    }
    let target = f.tmp.path().join("precious");
    fs::write(&target, b"x").unwrap();
    let link = work.join(".ratarmount-pack-Sy1Mk2.tmp");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    keep.push(link);
    // The killed pack's leftovers are fresh: backdate them like a pack that
    // died long ago, then a second pack sweeps them.
    for name in &left {
        if work.join(name).is_file() {
            backdate(&work.join(name), 3600);
        }
    }
    expect(
        command(
            &[Path::new("overlay"), Path::new("pack"), &f.overlay, &out],
            &f.cache,
        ),
        0,
    );
    assert!(out.exists());
    let after = entries(&work);
    for name in &left {
        assert!(!after.contains(name), "not swept: {name} in {after:?}");
    }
    for path in keep {
        assert!(path.symlink_metadata().is_ok(), "swept {}", path.display());
    }
    assert!(target.exists());
    drop(live_file);
}
