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
    match err.kind() {
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

    #[test]
    fn v4_io_to_fserror_maps_kinds() {
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
