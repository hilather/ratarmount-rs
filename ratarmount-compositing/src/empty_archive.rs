//! Create a POSIX-empty uncompressed TAR or one-frame `.tar.zst` (`O_EXCL`).

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

use ratarmount_compress::{encode_zstd_frame_to, name_suggests_compressed_tar};
use tempfile::NamedTempFile;

use crate::name_suggests_tar_zst;
use crate::write_overlay::OverlayError;

/// Persist-grade zstd level (`SPLICE_ENCODE_LEVEL` in `zstd_splice.rs`).
const EMPTY_TAR_ZST_LEVEL: i32 = 3;

/// Uncompressed `.tar` vs framed `.tar.zst` / `.tzst` / `.tar.zstd`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmptyArchiveKind {
    UncompressedTar,
    TarZst,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmptyCreateOutcome {
    Created,
    InitializedEmpty,
    Unchanged,
}

/// Name only. No filesystem, no URL parsing.
///
/// `Ok(None)` — not a createable name (caller keeps today's not-found / folder bind).
/// `Err` — known type we refuse to **create**. Combine with `symlink_metadata`:
/// `Err` + exists → Unchanged; `Err` + missing → fail.
pub fn classify_createable_archive(path: &Path) -> Result<Option<EmptyArchiveKind>, OverlayError> {
    if name_suggests_tar_zst(path) {
        return Ok(Some(EmptyArchiveKind::TarZst));
    }
    let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
        return Ok(None);
    };
    let l = name.to_ascii_lowercase();
    if l.ends_with(".tar") {
        return Ok(Some(EmptyArchiveKind::UncompressedTar));
    }
    if name_suggests_compressed_tar(path) || name_suggests_zip_or_sevenzip(&l) {
        return Err(refuse_create_err(path));
    }
    Ok(None)
}

fn name_suggests_zip_or_sevenzip(lower_name: &str) -> bool {
    lower_name.ends_with(".zip") || lower_name.ends_with(".jar") || lower_name.ends_with(".7z")
}

fn refuse_create_err(path: &Path) -> OverlayError {
    OverlayError::Msg(format!(
        "cannot create missing {} (only uncompressed .tar and .tar.zst)",
        path.display()
    ))
}

/// Create or initialize a pre-existing 0-byte **createable** regular file. Local FS only.
///
/// Never clobbers `len > 0`. `AlreadyExists` after `O_EXCL` is Unchanged for any
/// regular file. Do not `?` classify first: `Err` + existing path → `Unchanged`.
pub fn maybe_create_empty_write_archive(path: &Path) -> Result<EmptyCreateOutcome, OverlayError> {
    let class = classify_createable_archive(path);
    let meta = fs::symlink_metadata(path);
    match (class, meta) {
        (Ok(None), _) => Ok(EmptyCreateOutcome::Unchanged),
        (Err(e), Err(io_err)) if io_err.kind() == io::ErrorKind::NotFound => Err(e),
        (Err(_), Ok(_)) => Ok(EmptyCreateOutcome::Unchanged),
        (Err(_), Err(io_err)) => Err(io_err.into()),
        (Ok(Some(kind)), Err(io_err))
            if io_err.kind() == io::ErrorKind::NotFound
                || io_err.raw_os_error() == Some(libc::ENOTDIR) =>
        {
            create_new_empty_archive(path, kind)
        }
        (Ok(Some(_)), Err(io_err)) => Err(io_err.into()),
        (Ok(Some(_)), Ok(m)) if m.file_type().is_dir() => Err(OverlayError::Msg(format!(
            "{} is a directory",
            path.display()
        ))),
        (Ok(Some(_)), Ok(m)) if m.file_type().is_symlink() => Err(OverlayError::Msg(
            "refusing to create archive at symlink path".into(),
        )),
        (Ok(Some(_)), Ok(m)) if !m.file_type().is_file() => Err(OverlayError::Msg(
            "refusing to create archive at non-regular path".into(),
        )),
        (Ok(Some(kind)), Ok(m)) if m.len() == 0 => initialize_empty_archive(path, kind),
        (Ok(Some(_)), Ok(_)) => Ok(EmptyCreateOutcome::Unchanged),
    }
}

fn create_new_empty_archive(
    path: &Path,
    kind: EmptyArchiveKind,
) -> Result<EmptyCreateOutcome, OverlayError> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o666);
    }
    match opts.open(path) {
        Ok(mut f) => {
            let wrote = write_empty_archive(&mut f, kind).and_then(|_| f.sync_all());
            if let Err(e) = wrote {
                let _ = fs::remove_file(path);
                return Err(e.into());
            }
            sync_parent_dir(path);
            eprintln!("created empty archive {}", path.display());
            log::info!("created empty archive {}", path.display());
            Ok(EmptyCreateOutcome::Created)
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => match fs::symlink_metadata(path) {
            Ok(m) if m.file_type().is_file() => Ok(EmptyCreateOutcome::Unchanged),
            Ok(m) if m.file_type().is_dir() => Err(OverlayError::Msg(format!(
                "{} is a directory",
                path.display()
            ))),
            Ok(m) if m.file_type().is_symlink() => Err(OverlayError::Msg(
                "refusing to create archive at symlink path".into(),
            )),
            Ok(_) => Err(OverlayError::Msg(
                "refusing to create archive at non-regular path".into(),
            )),
            Err(stat_err) => Err(stat_err.into()),
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => Err(OverlayError::Msg(format!(
            "cannot create {}: parent directory does not exist",
            path.display()
        ))),
        Err(e) if e.raw_os_error() == Some(libc::ENOTDIR) => Err(OverlayError::Msg(format!(
            "cannot create {}: parent is not a directory",
            path.display()
        ))),
        Err(e) => Err(e.into()),
    }
}

fn initialize_empty_archive(
    path: &Path,
    kind: EmptyArchiveKind,
) -> Result<EmptyCreateOutcome, OverlayError> {
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    let mut tmp = match parent {
        Some(dir) => NamedTempFile::new_in(dir)?,
        None => NamedTempFile::new()?,
    };
    write_empty_archive(tmp.as_file_mut(), kind)?;
    apply_create_mode(tmp.as_file())?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| OverlayError::Io(e.error))?;
    sync_parent_dir(path);
    eprintln!("initialized empty archive {}", path.display());
    log::info!("initialized empty archive {}", path.display());
    Ok(EmptyCreateOutcome::InitializedEmpty)
}

/// Same as `OpenOptions::mode(0o666)`: umask applies (NamedTempFile is 0o600).
/// WHY: `PermissionsExt` / `umask` are Unix-only; Windows keeps tempfile mode.
fn apply_create_mode(file: &File) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mask = unsafe {
            let prev = libc::umask(0);
            libc::umask(prev);
            prev
        };
        file.set_permissions(fs::Permissions::from_mode(0o666 & !(mask as u32)))
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        Ok(())
    }
}

fn write_empty_archive<W: Write>(out: &mut W, kind: EmptyArchiveKind) -> io::Result<()> {
    match kind {
        EmptyArchiveKind::UncompressedTar => ratarmount_formats_tar::write_tar_eof(out),
        EmptyArchiveKind::TarZst => {
            let mut eof = Vec::new();
            ratarmount_formats_tar::write_tar_eof(&mut eof)?;
            encode_zstd_frame_to(eof.as_slice(), out, EMPTY_TAR_ZST_LEVEL)
                .map(|_| ())
                .map_err(|e| io::Error::other(e.to_string()))
        }
    }
}

fn sync_parent_dir(path: &Path) {
    if let Some(parent) = path.parent() {
        if parent.as_os_str().is_empty() {
            return;
        }
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::live_commit_is_supported;
    use ratarmount_compress::{
        decode_zstd_frames_to, detect_compression, scan_zstd_frames_path, CompressionFormat,
    };
    use std::os::unix::fs::{symlink, FileTypeExt, PermissionsExt};
    use std::sync::Barrier;
    use std::thread;

    fn decode_zst_payload(path: &Path) -> (usize, u64, Vec<u8>) {
        let map = scan_zstd_frames_path(path).unwrap();
        let frames = map.frames.len();
        let uncomp = map.frames[0].uncompressed_size;
        let mut src = File::open(path).unwrap();
        let mut out = Vec::new();
        decode_zstd_frames_to(&mut src, &map, 0, &mut out).unwrap();
        (frames, uncomp, out)
    }

    fn find_gnu_tar() -> Option<std::path::PathBuf> {
        for name in ["gtar", "gnutar", "tar"] {
            let Ok(out) = std::process::Command::new(name).arg("--version").output() else {
                continue;
            };
            if String::from_utf8_lossy(&out.stdout).contains("GNU tar") {
                return Some(std::path::PathBuf::from(name));
            }
        }
        None
    }

    #[test]
    fn maybe_create_missing_tar_is_1024_zeros() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive.tar");
        assert_eq!(
            maybe_create_empty_write_archive(&path).unwrap(),
            EmptyCreateOutcome::Created
        );
        let bytes = fs::read(&path).unwrap();
        assert_eq!(bytes.len(), 1024);
        assert!(bytes.iter().all(|&b| b == 0));
    }

    #[test]
    fn maybe_create_missing_tar_zst_suffixes_are_one_frame() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["a.tar.zst", "b.tzst", "c.tar.zstd"] {
            let path = dir.path().join(name);
            assert_eq!(
                maybe_create_empty_write_archive(&path).unwrap(),
                EmptyCreateOutcome::Created,
                "{name}"
            );
            assert_eq!(
                detect_compression(&path).unwrap(),
                CompressionFormat::Zstd,
                "{name}"
            );
            let (frames, uncomp, decoded) = decode_zst_payload(&path);
            assert_eq!(frames, 1, "{name}");
            assert_eq!(uncomp, 1024, "{name}");
            assert_eq!(decoded, vec![0u8; 1024], "{name}");
        }
    }

    #[test]
    fn maybe_create_existing_nonempty_tar_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive.tar");
        fs::write(&path, b"secret").unwrap();
        assert_eq!(
            maybe_create_empty_write_archive(&path).unwrap(),
            EmptyCreateOutcome::Unchanged
        );
        assert_eq!(fs::read(&path).unwrap(), b"secret");
    }

    #[test]
    fn maybe_create_existing_unsupported_types_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        for (name, bytes) in [
            ("a.tar.gz", &b""[..]),
            ("a.tar.gz", &b"gzip-bytes"[..]),
            ("a.zip", &b""[..]),
            ("a.zip", &b"PK\x03\x04"[..]),
            ("a.7z", &b""[..]),
            ("a.7z", &b"7z\xbc\xaf"[..]),
        ] {
            let path = dir.path().join(name);
            fs::write(&path, bytes).unwrap();
            let got = maybe_create_empty_write_archive(&path)
                .unwrap_or_else(|e| panic!("{name}: unexpected Err {e}"));
            assert_eq!(got, EmptyCreateOutcome::Unchanged, "{name}");
            assert_eq!(fs::read(&path).unwrap(), bytes, "{name}");
        }
    }

    #[test]
    fn maybe_create_missing_tar_gz_is_err() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.tar.gz");
        let err = maybe_create_empty_write_archive(&path)
            .unwrap_err()
            .to_string();
        assert!(err.contains("cannot create"), "{err}");
        assert!(err.contains("only uncompressed .tar"), "{err}");
        assert!(!path.exists());
    }

    #[test]
    fn maybe_create_dir_named_archive_tar_is_err() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive.tar");
        fs::create_dir(&path).unwrap();
        let err = maybe_create_empty_write_archive(&path)
            .unwrap_err()
            .to_string();
        assert!(err.contains("is a directory"), "{err}");
        assert!(path.is_dir());
    }

    #[test]
    fn maybe_create_existing_dir_without_createable_name_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["folder", "archive.tar.gz"] {
            let path = dir.path().join(name);
            fs::create_dir(&path).unwrap();
            assert_eq!(
                maybe_create_empty_write_archive(&path).unwrap(),
                EmptyCreateOutcome::Unchanged,
                "{name}"
            );
            assert!(path.is_dir(), "{name}");
        }
    }

    #[test]
    fn maybe_create_dangling_symlink_named_archive_tar_is_err() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive.tar");
        symlink("missing-target", &path).unwrap();
        let err = maybe_create_empty_write_archive(&path)
            .unwrap_err()
            .to_string();
        assert!(err.contains("symlink"), "{err}");
        assert!(fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    fn maybe_create_fifo_named_archive_tar_is_err() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive.tar");
        let Some(c_path) = path.to_str().and_then(|s| std::ffi::CString::new(s).ok()) else {
            eprintln!("skip: fifo path is not CString-safe");
            return;
        };
        let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o644) };
        if rc != 0 {
            eprintln!("skip: mkfifo failed");
            return;
        }
        let err = maybe_create_empty_write_archive(&path)
            .unwrap_err()
            .to_string();
        assert!(err.contains("non-regular"), "{err}");
        assert!(fs::symlink_metadata(&path).unwrap().file_type().is_fifo());
    }

    #[test]
    fn maybe_create_parent_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nope").join("a.tar");
        let err = maybe_create_empty_write_archive(&path)
            .unwrap_err()
            .to_string();
        assert!(err.contains("parent directory does not exist"), "{err}");
        assert!(!path.exists());
    }

    #[test]
    fn maybe_create_parent_is_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("notdir");
        fs::write(&parent, b"x").unwrap();
        let path = parent.join("a.tar");
        let err = maybe_create_empty_write_archive(&path)
            .unwrap_err()
            .to_string();
        assert!(err.contains("parent is not a directory"), "{err}");
    }

    #[test]
    fn maybe_create_preexisting_zero_byte_tar_initialized() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive.tar");
        fs::write(&path, b"").unwrap();
        assert_eq!(
            maybe_create_empty_write_archive(&path).unwrap(),
            EmptyCreateOutcome::InitializedEmpty
        );
        let bytes = fs::read(&path).unwrap();
        assert_eq!(bytes.len(), 1024);
        assert!(bytes.iter().all(|&b| b == 0));
    }

    #[test]
    fn initialize_empty_matches_create_new_mode() {
        let dir = tempfile::tempdir().unwrap();
        let created = dir.path().join("created.tar");
        assert_eq!(
            maybe_create_empty_write_archive(&created).unwrap(),
            EmptyCreateOutcome::Created
        );
        let init = dir.path().join("init.tar");
        fs::write(&init, b"").unwrap();
        assert_eq!(
            maybe_create_empty_write_archive(&init).unwrap(),
            EmptyCreateOutcome::InitializedEmpty
        );
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&created), mode(&init));
    }

    /// Regression: AlreadyExists on a 0-byte regular file does not truncate.
    #[test]
    fn regression_already_exists_zero_byte_regular_file_does_not_truncate() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive.tar");
        fs::write(&path, b"").unwrap();
        assert_eq!(
            create_new_empty_archive(&path, EmptyArchiveKind::UncompressedTar).unwrap(),
            EmptyCreateOutcome::Unchanged
        );
        assert_eq!(fs::read(&path).unwrap(), b"");
    }

    #[test]
    fn classify_refuses_known_uncreated_types() {
        for name in [
            "a.tar.gz",
            "a.tgz",
            "a.tar.bz2",
            "a.tbz",
            "a.tar.gzip",
            "a.tar.xz",
            "a.zip",
            "a.jar",
            "a.7z",
            "a.tar.lz4",
        ] {
            let err = classify_createable_archive(Path::new(name))
                .expect_err(name)
                .to_string();
            assert!(err.contains("cannot create"), "{name}: {err}");
        }
    }

    #[test]
    fn classify_unknown_and_bare_tar_are_none() {
        for name in ["disk.iso", "nosuffix", "typo-folder", "tar"] {
            assert_eq!(
                classify_createable_archive(Path::new(name)).unwrap(),
                None,
                "{name}"
            );
        }
    }

    #[test]
    fn live_commit_is_supported_on_just_created_archives() {
        let dir = tempfile::tempdir().unwrap();
        let tar = dir.path().join("new.tar");
        assert_eq!(
            maybe_create_empty_write_archive(&tar).unwrap(),
            EmptyCreateOutcome::Created
        );
        live_commit_is_supported(&tar).expect("created .tar");

        let zst = dir.path().join("new.tar.zst");
        assert_eq!(
            maybe_create_empty_write_archive(&zst).unwrap(),
            EmptyCreateOutcome::Created
        );
        live_commit_is_supported(&zst).expect("created .tar.zst");
    }

    #[test]
    fn gnu_tar_append_smoke_on_1024_zero_file() {
        let Some(tar_bin) = find_gnu_tar() else {
            eprintln!("skip: GNU tar missing");
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("empty.tar");
        {
            let mut f = File::create(&archive).unwrap();
            ratarmount_formats_tar::write_tar_eof(&mut f).unwrap();
        }
        fs::write(dir.path().join("hello.txt"), b"hello\n").unwrap();
        let status = std::process::Command::new(tar_bin)
            .args(["--append", "-C"])
            .arg(dir.path())
            .args(["--file"])
            .arg(&archive)
            .arg("hello.txt")
            .status()
            .expect("run GNU tar --append");
        assert!(
            status.success(),
            "GNU tar --append on 1024-zero TAR failed: {status}"
        );
    }

    #[test]
    fn two_thread_create_new_race() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("race.tar");
        let barrier = std::sync::Arc::new(Barrier::new(2));
        let spawn = |path: std::path::PathBuf, barrier: std::sync::Arc<Barrier>| {
            thread::spawn(move || {
                barrier.wait();
                maybe_create_empty_write_archive(&path)
            })
        };
        let h1 = spawn(path.clone(), barrier.clone());
        let h2 = spawn(path.clone(), barrier);
        let r1 = h1.join().expect("thread 1");
        let r2 = h2.join().expect("thread 2");
        let o1 = r1.expect("thread 1 create");
        let o2 = r2.expect("thread 2 create");
        assert!(
            !(o1 == EmptyCreateOutcome::Created && o2 == EmptyCreateOutcome::Created),
            "O_EXCL must admit only one creator"
        );
        // InitializedEmpty is K6 (pre-stat of a 0-byte in-progress winner), not AlreadyExists.
        assert!(
            matches!(
                (o1, o2),
                (
                    EmptyCreateOutcome::Created,
                    EmptyCreateOutcome::Unchanged | EmptyCreateOutcome::InitializedEmpty
                ) | (
                    EmptyCreateOutcome::Unchanged | EmptyCreateOutcome::InitializedEmpty,
                    EmptyCreateOutcome::Created
                )
            ),
            "unexpected race outcomes {o1:?} {o2:?}"
        );
        let bytes = fs::read(&path).unwrap();
        assert_eq!(bytes.len(), 1024);
        assert!(bytes.iter().all(|&b| b == 0));
    }
}
