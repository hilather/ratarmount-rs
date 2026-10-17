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
    // Rust does not classify both Darwin unsupported-operation errnos as Unsupported.
    // A predicate also handles platforms where these constants are aliases.
    if err
        .raw_os_error()
        .is_some_and(|raw| raw == libc::ENOTSUP || raw == libc::EOPNOTSUPP)
    {
        return FsError::Unsupported;
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
    /// Regression: raw permission/unsupported (including Darwin ENOTSUP) and unknown errors keep their old statuses.
    #[test]
    fn regression_nfs_preserves_legacy_raw_errors() {
        for (raw, expected) in [
            (libc::EPERM, FsError::AccessDenied),
            (libc::EOPNOTSUPP, FsError::Unsupported),
            (libc::ENOTSUP, FsError::Unsupported),
            (libc::ENOTEMPTY, FsError::Io),
            (libc::ENOTDIR, FsError::Io),
            (libc::ELOOP, FsError::Io),
            (libc::EXDEV, FsError::Io),
            (libc::EBUSY, FsError::Io),
            (libc::EMFILE, FsError::Io),
            (libc::ENFILE, FsError::Io),
            (libc::EROFS, FsError::ReadOnly),
            (libc::EDQUOT, FsError::NoSpace),
            (libc::ENOSPC, FsError::NoSpace),
        ] {
            assert_eq!(
                io_to_fserror(&std::io::Error::from_raw_os_error(raw)),
                expected,
                "raw {raw}"
            );
        }
    }

    use super::*;
    use std::io::{Error, ErrorKind};

    /// Regression: both policy kinds and raw capacity errnos retain protocol status.
    #[test]
    fn regression_overlay_policy_errno_mapping() {
        assert_eq!(
            io_to_fserror(&Error::from_raw_os_error(libc::EPERM)),
            FsError::AccessDenied
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
