//! Map `std::io::Error` onto NFSv3 status (mirror of FUSE `io_to_errno`).

use std::io::ErrorKind;

use nfsserve::nfs::nfsstat3;

/// Password / permission failures must not collapse to generic I/O — that is
/// what users see when opening encrypted nested 7z without `--password`.
pub fn io_to_nfsstat3(err: &std::io::Error) -> nfsstat3 {
    match err.kind() {
        ErrorKind::NotFound => nfsstat3::NFS3ERR_NOENT,
        ErrorKind::PermissionDenied => nfsstat3::NFS3ERR_ACCES,
        ErrorKind::IsADirectory => nfsstat3::NFS3ERR_ISDIR,
        ErrorKind::AlreadyExists => nfsstat3::NFS3ERR_EXIST,
        ErrorKind::InvalidInput => nfsstat3::NFS3ERR_INVAL,
        ErrorKind::Unsupported => nfsstat3::NFS3ERR_NOTSUPP,
        // `ErrorKind::NotADirectory` is Rust 1.83+; MSRV is 1.74. VFS-layer
        // `readdir` on a file returns `NFS3ERR_NOTDIR` without going through
        // `io::Error`.
        _ => nfsstat3::NFS3ERR_IO,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error, ErrorKind};

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
