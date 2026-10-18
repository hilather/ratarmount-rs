//! `fstat`/`fstatat` for the overlay verbs (fsck, seal, verify, pack, unpack).
//!
//! rustix 1.1 (latest as of 2026-10) panics on Apple platforms when a
//! timestamp lies in (-1 s, 0): macOS reports it as `{0 s, negative ns}` and
//! rustix's normalization asserts `secs < 0`. A grading command that panics on
//! a real overlay is a silent mis-grade path, so on Apple these call libc
//! directly and normalize every timestamp themselves. `{0, -n}` is the valid
//! instant `{-1, 1e9 - n}`. Elsewhere they are the rustix calls unchanged.

use std::io;
use std::os::fd::AsFd;

use rustix::fs::{AtFlags, Stat};

/// Normalize `(secs, nsecs)` so that `nsecs` is in `0..1_000_000_000`,
/// borrowing from `secs`. Saturates instead of overflowing.
pub fn normalize_timespec(secs: i64, nsecs: i64) -> (i64, i64) {
    const NANOS: i64 = 1_000_000_000;
    (
        secs.saturating_add(nsecs.div_euclid(NANOS)),
        nsecs.rem_euclid(NANOS),
    )
}

#[cfg(not(target_vendor = "apple"))]
pub fn fstat<Fd: AsFd>(fd: Fd) -> io::Result<Stat> {
    Ok(rustix::fs::fstat(fd)?)
}

#[cfg(not(target_vendor = "apple"))]
pub fn statat<Fd: AsFd, P: rustix::path::Arg>(
    dirfd: Fd,
    path: P,
    flags: AtFlags,
) -> io::Result<Stat> {
    Ok(rustix::fs::statat(dirfd, path, flags)?)
}

#[cfg(target_vendor = "apple")]
fn normalized(mut st: Stat) -> Stat {
    for (secs, nsecs) in [
        (&mut st.st_atime, &mut st.st_atime_nsec),
        (&mut st.st_mtime, &mut st.st_mtime_nsec),
        (&mut st.st_ctime, &mut st.st_ctime_nsec),
        (&mut st.st_birthtime, &mut st.st_birthtime_nsec),
    ] {
        let (s, n) = normalize_timespec(*secs, *nsecs);
        (*secs, *nsecs) = (s, n);
    }
    st
}

#[cfg(target_vendor = "apple")]
pub fn fstat<Fd: AsFd>(fd: Fd) -> io::Result<Stat> {
    use std::os::fd::AsRawFd;
    // rustix::fs::Stat is libc::stat on Apple targets.
    let mut st = std::mem::MaybeUninit::<Stat>::uninit();
    if unsafe { libc::fstat(fd.as_fd().as_raw_fd(), st.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(normalized(unsafe { st.assume_init() }))
}

#[cfg(target_vendor = "apple")]
pub fn statat<Fd: AsFd, P: rustix::path::Arg>(
    dirfd: Fd,
    path: P,
    flags: AtFlags,
) -> io::Result<Stat> {
    use std::os::fd::AsRawFd;
    let dirfd = dirfd.as_fd().as_raw_fd();
    let st = path.into_with_c_str(|path| {
        let mut st = std::mem::MaybeUninit::<Stat>::uninit();
        if unsafe { libc::fstatat(dirfd, path.as_ptr(), st.as_mut_ptr(), flags.bits() as _) } != 0 {
            let errno = io::Error::last_os_error().raw_os_error();
            return Err(rustix::io::Errno::from_raw_os_error(
                errno.unwrap_or(libc::EIO),
            ));
        }
        Ok(unsafe { st.assume_init() })
    })?;
    Ok(normalized(st))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{Duration, UNIX_EPOCH};

    /// Regression: macOS reports mtimes in (-1 s, 0) as {0 s, negative ns};
    /// that is the instant {-1 s, 1e9 - n ns}, not an error or a panic.
    #[test]
    fn regression_normalize_negative_nanoseconds() {
        assert_eq!(normalize_timespec(0, -250_000_000), (-1, 750_000_000));
        assert_eq!(normalize_timespec(-1, -1), (-2, 999_999_999));
        assert_eq!(normalize_timespec(5, 1_500_000_000), (6, 500_000_000));
        assert_eq!(normalize_timespec(7, 0), (7, 0));
        assert_eq!(normalize_timespec(i64::MIN, -1).0, i64::MIN);
    }

    /// Regression: rustix 1.1 panicked in stat on macOS for a file whose
    /// mtime is 250 ms before the epoch (overlay pack/seal/verify crashed).
    #[test]
    fn regression_stat_mtime_just_before_epoch() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("f");
        let file = fs::File::create(&path).unwrap();
        file.set_times(fs::FileTimes::new().set_modified(UNIX_EPOCH - Duration::from_millis(250)))
            .unwrap();
        let dir = fs::File::open(tmp.path()).unwrap();
        for st in [
            fstat(&file).unwrap(),
            statat(&dir, "f", AtFlags::SYMLINK_NOFOLLOW).unwrap(),
        ] {
            #[allow(clippy::unnecessary_cast)]
            let (secs, nsecs) = (st.st_mtime as i64, st.st_mtime_nsec as i64);
            assert_eq!((secs, nsecs), (-1, 750_000_000));
        }
        assert!(statat(&dir, "missing", AtFlags::SYMLINK_NOFOLLOW).is_err());
    }
}
