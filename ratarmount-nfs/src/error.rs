//! Map `std::io::Error` onto NFSv3 status (mirror of FUSE `io_to_errno`).

use std::io::ErrorKind;

use nfsserve::nfs::nfsstat3;

/// Password / permission failures must not collapse to generic I/O — that is
/// what users see when opening encrypted nested 7z without `--password`.
pub fn io_to_nfsstat3(err: &std::io::Error) -> nfsstat3 {
    if err.raw_os_error() == Some(libc::EPERM) {
        return nfsstat3::NFS3ERR_PERM;
    }
    match err.kind() {
        ErrorKind::ReadOnlyFilesystem => nfsstat3::NFS3ERR_ROFS,
        ErrorKind::QuotaExceeded => nfsstat3::NFS3ERR_DQUOT,
        ErrorKind::StorageFull => nfsstat3::NFS3ERR_NOSPC,
        ErrorKind::NotFound => nfsstat3::NFS3ERR_NOENT,
        ErrorKind::PermissionDenied => nfsstat3::NFS3ERR_ACCES,
        ErrorKind::IsADirectory => nfsstat3::NFS3ERR_ISDIR,
        ErrorKind::AlreadyExists => nfsstat3::NFS3ERR_EXIST,
        ErrorKind::InvalidInput => nfsstat3::NFS3ERR_INVAL,
        ErrorKind::Unsupported => nfsstat3::NFS3ERR_NOTSUPP,
        // `ErrorKind::NotADirectory` is Rust 1.83+; written for the former 1.74 MSRV. VFS-layer
        // `readdir` on a file returns `NFS3ERR_NOTDIR` without going through
        // `io::Error`.
        _ => nfsstat3::NFS3ERR_IO,
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
            io_to_nfsstat3(&Error::from_raw_os_error(libc::EPERM)) as u32,
            nfsstat3::NFS3ERR_PERM as u32
        );
        assert_eq!(
            io_to_nfsstat3(&Error::new(ErrorKind::ReadOnlyFilesystem, "policy")) as u32,
            nfsstat3::NFS3ERR_ROFS as u32
        );
        assert_eq!(
            io_to_nfsstat3(&Error::from_raw_os_error(libc::EROFS)) as u32,
            nfsstat3::NFS3ERR_ROFS as u32
        );
        assert_eq!(
            io_to_nfsstat3(&Error::new(ErrorKind::QuotaExceeded, "policy")) as u32,
            nfsstat3::NFS3ERR_DQUOT as u32
        );
        assert_eq!(
            io_to_nfsstat3(&Error::from_raw_os_error(libc::EDQUOT)) as u32,
            nfsstat3::NFS3ERR_DQUOT as u32
        );
        assert_eq!(
            io_to_nfsstat3(&Error::new(ErrorKind::StorageFull, "policy")) as u32,
            nfsstat3::NFS3ERR_NOSPC as u32
        );
        assert_eq!(
            io_to_nfsstat3(&Error::from_raw_os_error(libc::ENOSPC)) as u32,
            nfsstat3::NFS3ERR_NOSPC as u32
        );
    }

    fn as_u32(s: nfsstat3) -> u32 {
        s as u32
    }

    #[test]
    fn maps_kinds() {
        assert_eq!(
            as_u32(io_to_nfsstat3(&Error::new(ErrorKind::NotFound, "x"))),
            as_u32(nfsstat3::NFS3ERR_NOENT)
        );
        assert_eq!(
            as_u32(io_to_nfsstat3(&Error::new(
                ErrorKind::PermissionDenied,
                "x"
            ))),
            as_u32(nfsstat3::NFS3ERR_ACCES)
        );
        assert_eq!(
            as_u32(io_to_nfsstat3(&Error::new(ErrorKind::IsADirectory, "x"))),
            as_u32(nfsstat3::NFS3ERR_ISDIR)
        );
        assert_eq!(
            as_u32(io_to_nfsstat3(&Error::new(ErrorKind::AlreadyExists, "x"))),
            as_u32(nfsstat3::NFS3ERR_EXIST)
        );
        assert_eq!(
            as_u32(io_to_nfsstat3(&Error::new(ErrorKind::InvalidInput, "x"))),
            as_u32(nfsstat3::NFS3ERR_INVAL)
        );
        assert_eq!(
            as_u32(io_to_nfsstat3(&Error::new(ErrorKind::Unsupported, "x"))),
            as_u32(nfsstat3::NFS3ERR_NOTSUPP)
        );
        assert_eq!(
            as_u32(io_to_nfsstat3(&Error::new(ErrorKind::UnexpectedEof, "x"))),
            as_u32(nfsstat3::NFS3ERR_IO)
        );
    }
}
