//! Exact file-range copies, with opportunistic kernel acceleration.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CopyMethod {
    Reflink,
    CopyFileRange,
    IoCopy,
}

impl std::fmt::Display for CopyMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Reflink => "reflink",
            Self::CopyFileRange => "copy_file_range",
            Self::IoCopy => "io::copy",
        })
    }
}

/// Copy exactly `len` bytes without truncating the destination. Both cursors
/// finish immediately after the copied range. Reflink denotes a cloned middle
/// with at most two block fragments copied normally. Different offset alignment
/// cannot be cloned and falls back. Short sources are errors, never success.
pub fn copy_range(
    src: &mut File,
    src_off: u64,
    dst: &mut File,
    dst_off: u64,
    len: u64,
) -> io::Result<CopyMethod> {
    copy_range_inner(src, src_off, dst, dst_off, len, None, 1 << 30)
}

fn copy_range_inner(
    src: &mut File,
    src_off: u64,
    dst: &mut File,
    dst_off: u64,
    len: u64,
    forced_error: Option<i32>,
    max_chunk: u64,
) -> io::Result<CopyMethod> {
    let end = src_off.checked_add(len).ok_or_else(invalid_range)?;
    let dst_end = dst_off.checked_add(len).ok_or_else(invalid_range)?;
    if end > i64::MAX as u64 || dst_end > i64::MAX as u64 {
        return Err(invalid_range());
    }
    if end > src.metadata()?.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "short copy source",
        ));
    }
    let mut method = CopyMethod::IoCopy;
    #[cfg(target_os = "linux")]
    let mut copied = 0;
    #[cfg(not(target_os = "linux"))]
    let copied = 0;
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::MetadataExt;
        if src.metadata()?.dev() == dst.metadata()?.dev()
            && src.metadata()?.ino() == dst.metadata()?.ino()
        {
            return Err(invalid_range());
        }
        // fstatfs reports the filesystem block size (st_blksize is an I/O hint).
        let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
        let block = if unsafe { libc::fstatfs(src.as_raw_fd(), &mut stat) } == 0 {
            u64::try_from(stat.f_bsize).unwrap_or(4096).max(1)
        } else {
            4096
        };
        let head = ((block - src_off % block) % block).min(len);
        let middle = (len - head) / block * block;
        if forced_error.is_none() && src_off % block == dst_off % block && middle > 0 {
            #[repr(C)]
            struct CloneRange {
                src_fd: i64,
                src_offset: u64,
                src_length: u64,
                dest_offset: u64,
            }
            let range = CloneRange {
                src_fd: i64::from(src.as_raw_fd()),
                src_offset: src_off + head,
                src_length: middle,
                dest_offset: dst_off + head,
            };
            // Linux _IOW(0x94, 13, struct file_clone_range).
            if unsafe { libc::ioctl(dst.as_raw_fd(), libc::FICLONERANGE, &range) } == 0 {
                copy_io(src, src_off, dst, dst_off, head)?;
                copy_io(
                    src,
                    src_off + head + middle,
                    dst,
                    dst_off + head + middle,
                    len - head - middle,
                )?;
                src.seek(SeekFrom::Start(end))?;
                dst.seek(SeekFrom::Start(dst_end))?;
                return Ok(CopyMethod::Reflink);
            }
        }
        let mut source_offset = src_off as libc::off64_t;
        let mut dest_offset = dst_off as libc::off64_t;
        while copied < len {
            let n = if let Some(errno) = forced_error {
                Err(io::Error::from_raw_os_error(errno))
            } else {
                let n = unsafe {
                    libc::copy_file_range(
                        src.as_raw_fd(),
                        &mut source_offset,
                        dst.as_raw_fd(),
                        &mut dest_offset,
                        (len - copied).min(max_chunk) as usize,
                        0,
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as u64)
                }
            };
            match n {
                Ok(0) => break,
                Ok(n) => {
                    copied += n;
                    method = CopyMethod::CopyFileRange;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e)
                    if matches!(
                        e.raw_os_error(),
                        Some(
                            libc::EXDEV
                                | libc::ENOSYS
                                | libc::EOPNOTSUPP
                                | libc::EINVAL
                                | libc::EPERM
                        )
                    ) =>
                {
                    break
                }
                Err(e) => return Err(e),
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (forced_error, max_chunk);
    if copied < len {
        copy_io(src, src_off + copied, dst, dst_off + copied, len - copied)?;
        method = CopyMethod::IoCopy;
    }
    src.seek(SeekFrom::Start(end))?;
    dst.seek(SeekFrom::Start(dst_end))?;
    Ok(method)
}

fn invalid_range() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "invalid file copy range")
}

fn copy_io(src: &mut File, src_off: u64, dst: &mut File, dst_off: u64, len: u64) -> io::Result<()> {
    src.seek(SeekFrom::Start(src_off))?;
    dst.seek(SeekFrom::Start(dst_off))?;
    let n = io::copy(&mut src.take(len), dst)?;
    if n != len {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "short copy source",
        ));
    }
    Ok(())
}

/// Whole-file copy to a sibling temporary file. macOS cloning creates a new
/// pathname, so it is attempted here, never for a partial range or an open fd.
pub fn copy_to_temp(
    src: &mut File,
    parent: &Path,
) -> io::Result<(tempfile::NamedTempFile, CopyMethod)> {
    #[cfg(target_os = "macos")]
    {
        use std::ffi::CString;
        use std::os::fd::AsRawFd;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::PermissionsExt;
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-B0222-I01","disposition":"output-owner","mode_policy":"unchanged-from-e6ca64e","item":"ratarmount_compress::fastcopy::copy_to_temp","native_observed":false,"creation":{"policy":"private-temporary-directory","basis":"tempfile::tempdir_in creates the macOS clone staging directory with tempfile private defaults; original unchanged-from-e6ca64e mode provenance is retained."},"category":"compression-staging","reason":"macOS private clone staging directory"}"###
        )]
        let dir = tempfile::tempdir_in(parent)?;
        let path = dir.path().join("clone");
        let name = CString::new(path.as_os_str().as_bytes()).map_err(|_| invalid_range())?;
        if unsafe { libc::fclonefileat(src.as_raw_fd(), libc::AT_FDCWD, name.as_ptr(), 0) } == 0 {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
            #[expect(
                clippy::disallowed_methods,
                reason = r###"internal-read:v1 {"id":"IR-B0223-I01","disposition":"output-owner","mode_policy":"unchanged-from-e6ca64e","item":"ratarmount_compress::fastcopy::copy_to_temp","native_observed":false,"creation":{"policy":"private-named-temporary-file","basis":"NamedTempFile allocates a private sibling; the previously cloned file is then renamed over that temporary pathname, retaining the reviewed existing clone flow."},"category":"compression-staging","reason":"macOS named clone output publication"}"###
            )]
            let tmp = tempfile::NamedTempFile::new_in(parent)?;
            std::fs::rename(&path, tmp.path())?;
            let (_, temp_path) = tmp.into_parts();
            let mut options = std::fs::OpenOptions::new();
            options.read(true).write(true);
            #[expect(
                clippy::disallowed_methods,
                reason = r###"internal-read:v1 {"id":"IR-B0224-I01","disposition":"out-of-family","category":"runtime-resource-or-descriptor-handoff","reason":"range-copy probe on a private temporary file","mode_policy":"unchanged-from-e6ca64e","item":"ratarmount_compress::fastcopy::copy_to_temp","native_observed":false,"creation":{"policy":"none","basis":"The read/write OpenOptions path reopens the already-created temporary clone after rename; it requests no creation."}}"###
            )]
            let file = options.open(&temp_path)?;
            return Ok((
                tempfile::NamedTempFile::from_parts(file, temp_path),
                CopyMethod::Reflink,
            ));
        }
    }
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-B0225-M01","item":"ratarmount_compress::fastcopy::copy_to_temp","disposition":"output-owner","mode_policy":"unchanged-from-e6ca64e","category":"output-owner","reason":"Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"unchanged-from-e6ca64e","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###
    )]
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    let len = src.metadata()?.len();
    let method = copy_range(src, 0, tmp.as_file_mut(), 0, len)?;
    Ok((tmp, method))
}

pub fn log_commit_copy(len: u64, method: CopyMethod) {
    log::info!(
        "commit: prefix {:.1} GiB via {method}",
        len as f64 / (1024.0 * 1024.0 * 1024.0)
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn check(src_off: u64, dst_off: u64, forced: Option<i32>) -> CopyMethod {
        let mut src = tempfile::tempfile().unwrap();
        let mut dst = tempfile::tempfile().unwrap();
        let data: Vec<_> = (0..100_000).map(|i| (i % 251) as u8).collect();
        src.write_all(&data).unwrap();
        dst.write_all(&vec![0xa5; 110_000]).unwrap();
        let len = 80_021;
        let method =
            copy_range_inner(&mut src, src_off, &mut dst, dst_off, len, forced, 7919).unwrap();
        assert_eq!(src.stream_position().unwrap(), src_off + len);
        assert_eq!(dst.stream_position().unwrap(), dst_off + len);
        dst.rewind().unwrap();
        let mut actual = Vec::new();
        dst.read_to_end(&mut actual).unwrap();
        let mut expected = vec![0xa5; 110_000];
        expected[dst_off as usize..(dst_off + len) as usize]
            .copy_from_slice(&data[src_off as usize..(src_off + len) as usize]);
        assert_eq!(actual, expected);
        method
    }

    /// Regression: unaligned range copies changed surrounding bytes.
    #[test]
    fn copy_range_unaligned_bytes() {
        check(13, 13, None);
        check(13, 37, None);
    }

    /// Regression: unavailable/cross-filesystem kernel copies must use the fallback.
    #[cfg(target_os = "linux")]
    #[test]
    fn copy_range_enosys_exdev_fallback() {
        for errno in [libc::ENOSYS, libc::EXDEV, libc::EOPNOTSUPP, libc::EINVAL] {
            assert_eq!(check(13, 13, Some(errno)), CopyMethod::IoCopy);
        }
    }

    /// Regression: aligned middle of an unaligned range should share extents.
    #[cfg(target_os = "linux")]
    #[test]
    fn copy_range_reflink_filesystem() {
        use std::os::fd::AsRawFd;
        let f = tempfile::tempfile().unwrap();
        let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::fstatfs(f.as_raw_fd(), &mut stat) }, 0);
        if !matches!(stat.f_type, libc::BTRFS_SUPER_MAGIC | libc::XFS_SUPER_MAGIC) {
            eprintln!("skip: reflink assertion needs btrfs/XFS (set TMPDIR)");
            return;
        }
        assert_eq!(check(13, 13, None), CopyMethod::Reflink);
    }

    /// Regression: whole-file clone/copy must preserve source and destination bytes.
    #[test]
    fn copy_to_temp_contents_and_source_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let mut source = tempfile::tempfile_in(dir.path()).unwrap();
        let bytes: Vec<_> = (0..90_013).map(|i| (i % 253) as u8).collect();
        source.write_all(&bytes).unwrap();
        let (dest, _method) = copy_to_temp(&mut source, dir.path()).unwrap();
        assert_eq!(std::fs::read(dest.path()).unwrap(), bytes);
        source.rewind().unwrap();
        let mut actual = Vec::new();
        source.read_to_end(&mut actual).unwrap();
        assert_eq!(actual, bytes);
        #[cfg(target_os = "macos")]
        {
            use std::os::fd::AsRawFd;
            let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
            assert_eq!(unsafe { libc::fstatfs(source.as_raw_fd(), &mut stat) }, 0);
            let name = unsafe { std::ffi::CStr::from_ptr(stat.f_fstypename.as_ptr()) };
            if name.to_bytes() == b"apfs" {
                assert_eq!(_method, CopyMethod::Reflink);
            }
        }
    }

    /// Regression: a short source must not silently produce a partial archive.
    #[test]
    fn copy_range_short_source() {
        let mut src = tempfile::tempfile().unwrap();
        let mut dst = tempfile::tempfile().unwrap();
        assert_eq!(
            copy_range(&mut src, 0, &mut dst, 0, 1).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
}
