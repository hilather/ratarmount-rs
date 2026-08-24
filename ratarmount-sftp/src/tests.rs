//! Crate-level tests: sftp client skip-without, russh serve (feature-gated).

use std::io::{self, Cursor, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use ratarmount_core::{create_root_file_info, FileInfo, ListResult, MountSource};
use ratarmount_export_core::ExportStop;
use ratarmount_formats_tar::{
    write_tar_eof, write_ustar_members, SqliteIndexedTar, UstarMember, UstarPayload,
};

use crate::{
    serve_blocking, sftp_russh_compiled, spawn_sftp_thread, ExportServerHandle, SftpOptions,
};

struct EmptyFs;
impl MountSource for EmptyFs {
    fn list(&self, path: &str) -> Option<ListResult> {
        if path == "/" {
            Some(ListResult::Names(Vec::new()))
        } else {
            None
        }
    }
    fn lookup(&self, path: &str, _: i32) -> Option<FileInfo> {
        if path == "/" {
            Some(create_root_file_info())
        } else {
            None
        }
    }
    fn open(&self, _: &FileInfo, _: i32) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
        Ok(Box::new(Cursor::new(Vec::<u8>::new())))
    }
    fn is_immutable(&self) -> bool {
        true
    }
}

fn which(bin: &str) -> Option<PathBuf> {
    env_path_dirs().find_map(|dir| {
        let p = dir.join(bin);
        if p.is_file() {
            Some(p)
        } else {
            None
        }
    })
}

fn env_path_dirs() -> impl Iterator<Item = PathBuf> {
    std::env::var_os("PATH")
        .into_iter()
        .flat_map(|p| std::env::split_paths(&p).collect::<Vec<_>>())
}

fn tar_source() -> Arc<dyn MountSource> {
    let mut buf = Vec::new();
    write_ustar_members(
        &mut buf,
        &[UstarMember {
            path: "hello.txt",
            payload: UstarPayload::File {
                bytes: b"hello sftp\n",
            },
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime: 0,
        }],
    )
    .unwrap();
    write_tar_eof(&mut buf).unwrap();
    let opts = ratarmount_core::OpenOptions {
        index_in_memory: true,
        write_index: false,
        ..ratarmount_core::OpenOptions::default()
    };
    let tar = SqliteIndexedTar::open_from_reader(
        Cursor::new(buf),
        std::path::Path::new("memory://sftp-fixture.tar"),
        None,
        &opts,
        "test",
    )
    .expect("index tar");
    Arc::new(tar)
}

fn join_stop(handle: ExportServerHandle, stop: ExportStop) {
    stop.request_stop();
    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(handle.join());
    });
    rx.recv_timeout(Duration::from_secs(5))
        .expect("SFTP serve stop timed out")
        .expect("join");
}

fn ssh_keygen_ed25519(dir: &Path) -> Option<(PathBuf, PathBuf)> {
    let keygen = which("ssh-keygen")?;
    let privk = dir.join("id_ed25519");
    let status = Command::new(keygen)
        .args(["-t", "ed25519", "-f"])
        .arg(&privk)
        .args(["-N", "", "-q"])
        .status()
        .ok()?;
    if !status.success() {
        return None;
    }
    let pubk = dir.join("id_ed25519.pub");
    if !pubk.is_file() {
        return None;
    }
    Some((privk, pubk))
}

fn sftp_batch(
    port: u16,
    ident: &Path,
    batch: &Path,
    extra_args: &[&str],
) -> Option<(bool, String)> {
    let sftp = which("sftp")?;
    let mut cmd = Command::new(sftp);
    cmd.arg("-P")
        .arg(port.to_string())
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg("-o")
        .arg("UserKnownHostsFile=/dev/null")
        .arg("-o")
        .arg("GlobalKnownHostsFile=/dev/null")
        .arg("-o")
        .arg(format!("IdentityFile={}", ident.display()))
        .arg("-o")
        .arg("IdentitiesOnly=yes")
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("-b")
        .arg(batch);
    for a in extra_args {
        cmd.arg(a);
    }
    cmd.arg("127.0.0.1");
    cmd.stdin(Stdio::null());
    let out = cmd.output().ok()?;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    Some((out.status.success(), format!("{stdout}\n{stderr}")))
}

/// OpenSSH `sftp` skip-without. When `sftp-russh` is off this is a documented
/// skip (default CI stays 1.74). When compiled, requires `sftp` + `ssh-keygen`.
#[test]
fn sftp_client_ls_get_skip_without() {
    if !sftp_russh_compiled() {
        eprintln!("skip: crate built without sftp-russh (russh MSRV 1.85 > workspace 1.74)");
        return;
    }
    if which("sftp").is_none() {
        eprintln!("skip: sftp not on PATH");
        return;
    }
    if which("ssh-keygen").is_none() {
        eprintln!("skip: ssh-keygen not on PATH");
        return;
    }
    run_sftp_client_ls_get();
}

fn run_sftp_client_ls_get() {
    let td = tempfile::tempdir().unwrap();
    let (ident, pubk) = ssh_keygen_ed25519(td.path()).expect("ssh-keygen");
    let auth = td.path().join("authorized_keys");
    std::fs::copy(&pubk, &auth).unwrap();
    let host_key = td.path().join("host_ed25519");

    let stop = ExportStop::new();
    let opts = SftpOptions {
        bind: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        stop: Some(stop.clone()),
        authorized_keys: Some(auth),
        host_key: Some(host_key),
        ..SftpOptions::default()
    };
    let handle = spawn_sftp_thread(tar_source(), opts).expect("spawn sftp");
    let port = handle.port;

    let batch = td.path().join("batch");
    std::fs::write(
        &batch,
        format!("lcd {}\nls\nget hello.txt hello.out\n", td.path().display()),
    )
    .unwrap();
    let (ok, log) = sftp_batch(port, &ident, &batch, &[]).expect("run sftp");
    assert!(ok, "sftp failed: {log}");
    assert!(
        log.contains("hello.txt") || td.path().join("hello.out").is_file(),
        "sftp ls/get log: {log}"
    );
    if td.path().join("hello.out").is_file() {
        let body = std::fs::read(td.path().join("hello.out")).unwrap();
        assert_eq!(body, b"hello sftp\n");
    }
    join_stop(handle, stop);
}

#[test]
fn overlay_write_via_sftp_client_skip_without() {
    if !sftp_russh_compiled() {
        eprintln!("skip: crate built without sftp-russh (russh MSRV 1.85 > workspace 1.74)");
        return;
    }
    if which("sftp").is_none() {
        eprintln!("skip: sftp not on PATH");
        return;
    }
    if which("ssh-keygen").is_none() {
        eprintln!("skip: ssh-keygen not on PATH");
        return;
    }
    run_sftp_overlay_put();
}

fn run_sftp_overlay_put() {
    use ratarmount_compositing::WriteOverlay;

    let td = tempfile::tempdir().unwrap();
    let (ident, pubk) = ssh_keygen_ed25519(td.path()).expect("ssh-keygen");
    let auth = td.path().join("authorized_keys");
    std::fs::copy(&pubk, &auth).unwrap();
    let host_key = td.path().join("host_ed25519");
    let ovdir = td.path().join("ov");
    std::fs::create_dir(&ovdir).unwrap();
    let inner: Arc<dyn MountSource> = Arc::new(EmptyFs);
    let ov = Arc::new(WriteOverlay::new(inner.clone(), &ovdir).expect("overlay"));
    let source: Arc<dyn MountSource> = ov.clone();

    let stop = ExportStop::new();
    let opts = SftpOptions {
        bind: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        stop: Some(stop.clone()),
        overlay: Some(ov),
        authorized_keys: Some(auth),
        host_key: Some(host_key),
        ..SftpOptions::default()
    };
    let handle = spawn_sftp_thread(source, opts).expect("spawn sftp");
    let port = handle.port;

    let local = td.path().join("local.txt");
    std::fs::write(&local, b"overlay-bytes").unwrap();
    let batch = td.path().join("batch");
    let mut f = std::fs::File::create(&batch).unwrap();
    writeln!(f, "lcd {}", td.path().display()).unwrap();
    writeln!(f, "put {} /ov.txt", local.display()).unwrap();
    writeln!(f, "get /ov.txt got.txt").unwrap();
    drop(f);

    let (ok, log) = sftp_batch(port, &ident, &batch, &[]).expect("run sftp");
    assert!(ok, "sftp put/get failed: {log}");
    let got = td.path().join("got.txt");
    if got.is_file() {
        assert_eq!(std::fs::read(got).unwrap(), b"overlay-bytes");
    }
    join_stop(handle, stop);
}

#[test]
fn serve_stop_exits_when_compiled() {
    if !sftp_russh_compiled() {
        eprintln!("skip: crate built without sftp-russh");
        return;
    }
    let td = tempfile::tempdir().unwrap();
    let auth = td.path().join("authorized_keys");
    std::fs::write(&auth, "").unwrap();
    let stop = ExportStop::new();
    let opts = SftpOptions {
        bind: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        stop: Some(stop.clone()),
        authorized_keys: Some(auth),
        host_key: Some(td.path().join("host_ed25519")),
        ..SftpOptions::default()
    };
    let handle = spawn_sftp_thread(Arc::new(EmptyFs), opts).expect("spawn");
    thread::sleep(Duration::from_millis(50));
    join_stop(handle, stop);
}

#[test]
fn serve_blocking_rejects_v6() {
    let opts = SftpOptions {
        bind: "[::1]:20222".parse().unwrap(),
        ..SftpOptions::default()
    };
    let err = serve_blocking(Arc::new(EmptyFs), opts).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::AddrNotAvailable);
}
