//! Overlay write helpers + `io::Error` → errno map (FUSE/NFS `io_to_*`).

use std::io::{self, ErrorKind};

use ratarmount_compositing::{OverlayError, WriteOverlay};

/// Map `std::io::Error` onto a libc errno.
///
/// Password / permission failures must not collapse to generic EIO — that is
/// what users see when opening encrypted nested 7z without `--password`.
pub fn io_to_errno(err: &io::Error) -> i32 {
    match err.kind() {
        ErrorKind::NotFound => libc::ENOENT,
        ErrorKind::PermissionDenied => libc::EACCES,
        ErrorKind::IsADirectory => libc::EISDIR,
        ErrorKind::AlreadyExists => libc::EEXIST,
        ErrorKind::InvalidInput => libc::EINVAL,
        ErrorKind::Unsupported => libc::ENOSYS,
        _ => libc::EIO,
    }
}

/// Convert [`OverlayError`] into `io::Error` for protocol adapters.
pub fn overlay_to_io(err: OverlayError) -> io::Error {
    match err {
        OverlayError::Io(e) => e,
        other => io::Error::other(other.to_string()),
    }
}

pub fn overlay_create_file(overlay: &WriteOverlay, path: &str, mode: u32) -> io::Result<i32> {
    overlay.create_file(path, mode).map_err(overlay_to_io)
}

pub fn overlay_mkdir(overlay: &WriteOverlay, path: &str, mode: u32) -> io::Result<()> {
    overlay.mkdir(path, mode).map_err(overlay_to_io)
}

pub fn overlay_unlink(overlay: &WriteOverlay, path: &str) -> io::Result<()> {
    overlay.unlink(path).map_err(overlay_to_io)
}

pub fn overlay_rename(overlay: &WriteOverlay, from: &str, to: &str) -> io::Result<()> {
    overlay.rename(from, to).map_err(overlay_to_io)
}

pub fn overlay_truncate(overlay: &WriteOverlay, path: &str, size: u64) -> io::Result<()> {
    overlay.truncate(path, size).map_err(overlay_to_io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::sync::Arc;

    use ratarmount_core::{FileInfo, ListResult, MountSource};

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
                Some(ratarmount_core::create_root_file_info())
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

    /// Regression: PermissionDenied must not collapse to generic EIO.
    #[test]
    fn io_to_errno_maps_kinds() {
        assert_eq!(
            io_to_errno(&io::Error::new(ErrorKind::PermissionDenied, "pw")),
            libc::EACCES
        );
        assert_eq!(
            io_to_errno(&io::Error::new(ErrorKind::NotFound, "x")),
            libc::ENOENT
        );
        assert_eq!(
            io_to_errno(&io::Error::new(ErrorKind::IsADirectory, "d")),
            libc::EISDIR
        );
        assert_eq!(
            io_to_errno(&io::Error::new(ErrorKind::AlreadyExists, "e")),
            libc::EEXIST
        );
        assert_eq!(
            io_to_errno(&io::Error::new(ErrorKind::InvalidInput, "i")),
            libc::EINVAL
        );
        assert_eq!(
            io_to_errno(&io::Error::new(ErrorKind::Unsupported, "u")),
            libc::ENOSYS
        );
        assert_eq!(io_to_errno(&io::Error::other("generic")), libc::EIO);
    }

    #[test]
    fn overlay_to_io_passthrough() {
        let io_err = overlay_to_io(OverlayError::Io(io::Error::new(
            ErrorKind::PermissionDenied,
            "need password",
        )));
        assert_eq!(io_err.kind(), ErrorKind::PermissionDenied);
        assert_eq!(io_to_errno(&io_err), libc::EACCES);

        let msg = overlay_to_io(OverlayError::Msg("sqlite busy".into()));
        assert_eq!(io_to_errno(&msg), libc::EIO);
    }

    #[test]
    fn overlay_helpers_create_rename_unlink() {
        let td = tempfile::tempdir().unwrap();
        let ov = WriteOverlay::new(Arc::new(EmptyFs) as Arc<dyn MountSource>, td.path())
            .expect("overlay");
        overlay_mkdir(&ov, "/d", 0o755).expect("mkdir");
        let fd = overlay_create_file(&ov, "/d/f", 0o644).expect("create");
        ov.close_overlay_fd(fd);
        overlay_truncate(&ov, "/d/f", 0).expect("truncate");
        overlay_rename(&ov, "/d/f", "/d/g").expect("rename");
        overlay_unlink(&ov, "/d/g").expect("unlink");
    }
}
