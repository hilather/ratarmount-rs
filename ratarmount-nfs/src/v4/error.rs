//! Map `std::io::Error` onto embednfs [`FsError`].

use std::io::ErrorKind;

use embednfs::FsError;

/// Password / permission failures must not collapse to generic I/O — that is
/// what users see when opening encrypted nested 7z without `--password`.
///
/// Unknown fileid is [`ErrorKind::NotFound`] from [`crate::reader::ReaderLru`];
/// the VFS layer remaps that to [`FsError::Stale`]. Lookup name-miss is
/// [`FsError::NotFound`] without going through `io::Error`.
pub fn io_to_fserror(err: &std::io::Error) -> FsError {
    if err.raw_os_error() == Some(libc::EPERM) {
        return FsError::PermissionDenied;
    }
    match err.kind() {
        ErrorKind::ReadOnlyFilesystem => FsError::ReadOnly,
        // embednfs has no DQUOT variant; NOSPC is its capacity-error response.
        ErrorKind::QuotaExceeded | ErrorKind::StorageFull => FsError::NoSpace,
        ErrorKind::AlreadyExists => FsError::AlreadyExists,
        ErrorKind::NotFound => FsError::NotFound,
        ErrorKind::PermissionDenied => FsError::AccessDenied,
        ErrorKind::IsADirectory => FsError::IsDirectory,
        ErrorKind::InvalidInput => FsError::InvalidInput,
        ErrorKind::Unsupported => FsError::Unsupported,
        _ => FsError::Io,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error, ErrorKind};

    /// Regression: both policy kinds and raw capacity errnos retain protocol status.
    #[test]
    fn regression_overlay_policy_errno_mapping() {
        assert_eq!(
            io_to_fserror(&Error::from_raw_os_error(libc::EPERM)),
            FsError::PermissionDenied
        );
        assert_eq!(
            io_to_fserror(&Error::new(ErrorKind::ReadOnlyFilesystem, "policy")),
            FsError::ReadOnly
        );
        assert_eq!(
            io_to_fserror(&Error::from_raw_os_error(libc::EROFS)),
            FsError::ReadOnly
        );
        assert_eq!(
            io_to_fserror(&Error::new(ErrorKind::QuotaExceeded, "policy")),
            FsError::NoSpace
        );
        assert_eq!(
            io_to_fserror(&Error::from_raw_os_error(libc::EDQUOT)),
            FsError::NoSpace
        );
        assert_eq!(
            io_to_fserror(&Error::new(ErrorKind::StorageFull, "policy")),
            FsError::NoSpace
        );
        assert_eq!(
            io_to_fserror(&Error::from_raw_os_error(libc::ENOSPC)),
            FsError::NoSpace
        );
    }

    #[test]
    fn v4_io_to_fserror_maps_kinds() {
        assert_eq!(
            io_to_fserror(&Error::new(ErrorKind::AlreadyExists, "x")),
            FsError::AlreadyExists
        );
        assert_eq!(
            io_to_fserror(&Error::new(ErrorKind::NotFound, "x")),
            FsError::NotFound
        );
        assert_eq!(
            io_to_fserror(&Error::new(ErrorKind::PermissionDenied, "x")),
            FsError::AccessDenied
        );
        assert_eq!(
            io_to_fserror(&Error::new(ErrorKind::IsADirectory, "x")),
            FsError::IsDirectory
        );
        assert_eq!(
            io_to_fserror(&Error::new(ErrorKind::InvalidInput, "x")),
            FsError::InvalidInput
        );
        assert_eq!(
            io_to_fserror(&Error::new(ErrorKind::Unsupported, "x")),
            FsError::Unsupported
        );
        assert_eq!(
            io_to_fserror(&Error::new(ErrorKind::UnexpectedEof, "x")),
            FsError::Io
        );
    }
}
