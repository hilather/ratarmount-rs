//! Local OCI registry + bound Git rootfs, with and without a kernel mount.
#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use ratarmount_compositing::SourceBind;
use ratarmount_core::OpenOptions;
use ratarmount_formats_tar::{write_ustar_members, UstarMember, UstarPayload};
use ratarmount_session::factory::{
    build_mount_source_with_bindings, CompositingOptions, SourceBindings,
};
use sha2::{Digest, Sha256};

struct Registry {
    url: String,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Registry {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("docker://{}/test:latest", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let shutdown = Arc::clone(&stop);
        let mut tar = Vec::new();
        write_ustar_members(
            &mut tar,
            &[
                UstarMember {
                    path: "etc/os-release",
                    payload: UstarPayload::File {
                        bytes: b"test image\n",
                    },
                    mode: 0o644,
                    uid: 0,
                    gid: 0,
                    mtime: 0,
                    xattrs: &[],
                },
                UstarMember {
                    path: "repo/image-file",
                    payload: UstarPayload::File { bytes: b"base\n" },
                    mode: 0o644,
                    uid: 0,
                    gid: 0,
                    mtime: 0,
                    xattrs: &[],
                },
            ],
        )
        .unwrap();
        let digest = format!("sha256:{:x}", Sha256::digest(&tar));
        let manifest = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": digest, "size": tar.len()}]
        })).unwrap();
        let thread = thread::spawn(move || {
            while !shutdown.load(Ordering::SeqCst) {
                let (mut stream, _) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(e) => panic!("registry accept: {e}"),
                };
                // macOS/BSD accept inherits the listener's O_NONBLOCK.
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    continue;
                }
                let request: Vec<_> = line.split_whitespace().map(str::to_string).collect();
                if request.len() < 2 {
                    continue;
                }
                let mut range = None;
                loop {
                    line.clear();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    if let Some((key, value)) = line.split_once(':') {
                        if key.eq_ignore_ascii_case("range") {
                            range = value
                                .trim()
                                .strip_prefix("bytes=")
                                .and_then(|v| v.split_once('-'))
                                .and_then(|(a, b)| {
                                    Some((a.parse::<usize>().ok()?, b.parse::<usize>().ok()?))
                                });
                        }
                    }
                }
                let (body, kind) = if request[1].contains("/manifests/") {
                    (
                        manifest.as_slice(),
                        "application/vnd.oci.image.manifest.v1+json",
                    )
                } else if request[1].ends_with(&format!("/blobs/{digest}")) {
                    (tar.as_slice(), "application/octet-stream")
                } else {
                    let _ = stream.write_all(
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    );
                    continue;
                };
                let (status, bytes, extra) = match range {
                    Some((start, end)) if start < body.len() => {
                        let end = end.min(body.len() - 1);
                        (
                            "206 Partial Content",
                            &body[start..=end],
                            format!("Content-Range: bytes {start}-{end}/{}\r\n", body.len()),
                        )
                    }
                    _ => ("200 OK", body, String::new()),
                };
                let header = format!("HTTP/1.1 {status}\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nAccept-Ranges: bytes\r\n{extra}Connection: close\r\n\r\n", bytes.len());
                if stream.write_all(header.as_bytes()).is_ok() && request[0] != "HEAD" {
                    let _ = stream.write_all(bytes);
                }
            }
        });
        Self {
            url,
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for Registry {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.thread.take().unwrap().join().unwrap();
    }
}

fn repo(path: &Path) -> String {
    let repo = git2::Repository::init_bare(path).unwrap();
    let signature = git2::Signature::now("test", "test@example.test").unwrap();
    let mut builder = repo.treebuilder(None).unwrap();
    builder
        .insert("code", repo.blob(b"pinned source\n").unwrap(), 0o100644)
        .unwrap();
    let tree = repo.find_tree(builder.write().unwrap()).unwrap();
    repo.commit(Some("HEAD"), &signature, &signature, "base", &tree, &[])
        .unwrap()
        .to_string()
}

/// Regression: the factory must bind a Git snapshot alongside an actual OCI URL.
#[test]
fn regression_oci_image_bound_repo_factory() {
    let registry = Registry::new();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("repo.git");
    let sha = repo(&path);
    let bundle = build_mount_source_with_bindings(
        &[PathBuf::from(&registry.url)],
        &mut OpenOptions {
            index_in_memory: true,
            ..Default::default()
        },
        false,
        CompositingOptions::default(),
        SourceBindings {
            binds: vec![SourceBind {
                mount_path: "/repo".into(),
                source: format!("{}@{sha}", path.display()),
            }],
            ..Default::default()
        },
    )
    .unwrap();
    for (path, bytes) in [
        ("/etc/os-release", b"test image\n".as_slice()),
        ("/repo/code", b"pinned source\n"),
        ("/repo/image-file", b"base\n"),
    ] {
        let fi = bundle.source.lookup(path, 0).unwrap();
        assert_eq!(bundle.source.read(&fi, 100, 0).unwrap(), bytes);
    }
    let output = Command::new(env!("CARGO_BIN_EXE_ratarmount"))
        .args([
            "--no-mount",
            "--index-file",
            ":memory:",
            "--git-synthetic-head",
            "--bind",
        ])
        .arg(format!("/repo={}@{sha}", path.display()))
        .arg(&registry.url)
        .env("XDG_CACHE_HOME", dir.path().join("cache"))
        .env_remove("RATARMOUNT_FORCE_GIT")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(dir
        .path()
        .join("cache/ratarmount/git-synthetic-v1")
        .is_dir());
}

struct Mount {
    child: Child,
    path: PathBuf,
}

impl Drop for Mount {
    fn drop(&mut self) {
        let _ = Command::new("fusermount3")
            .arg("-uz")
            .arg(&self.path)
            .status();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Regression: image + bound repo + writable synthetic .git must work through kernel FUSE.
#[test]
fn fuse_image_repo_union() {
    if !Path::new("/dev/fuse").exists()
        || Command::new("fusermount3")
            .arg("--version")
            .output()
            .is_err()
    {
        eprintln!("skip: /dev/fuse or fusermount3 unavailable");
        return;
    }
    let registry = Registry::new();
    let dir = tempfile::tempdir().unwrap();
    let repo_path = dir.path().join("repo.git");
    let sha = repo(&repo_path);
    let mountpoint = dir.path().join("mnt");
    std::fs::create_dir(&mountpoint).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ratarmount"))
        .args([
            "-f",
            "--index-file",
            ":memory:",
            "--git-synthetic-head",
            "--bind",
        ])
        .arg(format!("/repo={}@{sha}", repo_path.display()))
        .arg("-w")
        .arg(dir.path().join("overlay"))
        .arg(&registry.url)
        .arg(&mountpoint)
        .env("XDG_CACHE_HOME", dir.path().join("cache"))
        .env_remove("RATARMOUNT_FORCE_GIT")
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut mount = Mount {
        child,
        path: mountpoint.clone(),
    };
    let deadline = Instant::now() + Duration::from_secs(20);
    while !mountpoint.join("etc/os-release").exists() {
        assert!(
            mount.child.try_wait().unwrap().is_none(),
            "mount exited early"
        );
        assert!(Instant::now() < deadline, "mount timed out");
        thread::sleep(Duration::from_millis(25));
    }
    assert_eq!(
        std::fs::read(mountpoint.join("repo/code")).unwrap(),
        b"pinned source\n"
    );
    assert!(mountpoint.join("repo/.git/HEAD").is_file());
    assert!(!mountpoint.join(".git").exists());
    std::fs::write(mountpoint.join("repo/code"), b"attempt\n").unwrap();
    assert_eq!(
        std::fs::read(mountpoint.join("repo/code")).unwrap(),
        b"attempt\n"
    );
    assert_eq!(
        std::fs::read(mountpoint.join("repo/image-file")).unwrap(),
        b"base\n"
    );
    let original = ratarmount_formats_git::GitMountSource::open(&repo_path, Some(&sha)).unwrap();
    use ratarmount_core::MountSource;
    assert_eq!(
        original
            .read(&original.lookup("/code", 0).unwrap(), 100, 0)
            .unwrap(),
        b"pinned source\n"
    );
}
