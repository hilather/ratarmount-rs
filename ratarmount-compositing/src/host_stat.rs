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

/// Test seam (unit tests, and CLI tests via the `test-hooks` feature): force a
/// panic inside the guarded stat call for any path ending in the given suffix,
/// standing in for the rustix macOS panic. The CLI reads the suffix from
/// `RATARMOUNT_TEST_STAT_PANIC`.
#[cfg(any(test, feature = "test-hooks"))]
static PANIC_SUFFIX: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

#[cfg(test)]
pub fn set_panic_for_test(suffix: Option<&str>) {
    *PANIC_SUFFIX.lock().unwrap() = suffix.map(str::to_owned);
}

#[cfg(any(test, feature = "test-hooks"))]
fn panic_for_test(path: &str) {
    let suffix = PANIC_SUFFIX
        .lock()
        .ok()
        .and_then(|g| g.clone())
        .or_else(|| std::env::var("RATARMOUNT_TEST_STAT_PANIC").ok());
    if suffix.is_some_and(|s| !s.is_empty() && path.ends_with(&s)) {
        panic!("forced stat panic for {path}");
    }
}

#[cfg(not(any(test, feature = "test-hooks")))]
fn panic_for_test(_path: &str) {}

/// Run a stat call so that a panic inside it (rustix 1.1 asserts on some
/// macOS timestamps) is an `io::Error` naming the path, never an abort of the
/// verb. The default panic hook still prints its one-line message.
fn guarded<T>(path: &str, f: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        panic_for_test(path);
        f()
    }))
    .unwrap_or_else(|_| {
        Err(io::Error::other(format!(
            "internal error reading file metadata (rustix panic) for {path}"
        )))
    })
}

fn arg_name<P: rustix::path::Arg>(path: &P) -> String {
    path.as_cow_c_str()
        .map(|c| c.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// `fstat` of an fd whose path the caller knows; the path only names the file
/// in the error if the stat panics.
pub fn fstat_named<Fd: AsFd>(fd: Fd, path: impl AsRef<std::path::Path>) -> io::Result<Stat> {
    let path = path.as_ref().to_string_lossy();
    guarded(&path, || fstat_raw(fd))
}

pub fn fstat<Fd: AsFd>(fd: Fd) -> io::Result<Stat> {
    guarded("<open file>", || fstat_raw(fd))
}

pub fn statat<Fd: AsFd, P: rustix::path::Arg>(
    dirfd: Fd,
    path: P,
    flags: AtFlags,
) -> io::Result<Stat> {
    let name = arg_name(&path);
    guarded(&name, || statat_raw(dirfd, path, flags))
}

#[cfg(not(target_vendor = "apple"))]
fn fstat_raw<Fd: AsFd>(fd: Fd) -> io::Result<Stat> {
    Ok(rustix::fs::fstat(fd)?)
}

#[cfg(not(target_vendor = "apple"))]
fn statat_raw<Fd: AsFd, P: rustix::path::Arg>(
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
fn fstat_raw<Fd: AsFd>(fd: Fd) -> io::Result<Stat> {
    use std::os::fd::AsRawFd;
    // rustix::fs::Stat is libc::stat on Apple targets.
    let mut st = std::mem::MaybeUninit::<Stat>::uninit();
    if unsafe { libc::fstat(fd.as_fd().as_raw_fd(), st.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(normalized(unsafe { st.assume_init() }))
}

#[cfg(target_vendor = "apple")]
fn statat_raw<Fd: AsFd, P: rustix::path::Arg>(
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

/// Set the permission bits of the entry `name` of `dir`, which the caller
/// found by `statat(.., SYMLINK_NOFOLLOW)` as `expected` (never a directory or
/// a symlink), WITHOUT opening a descriptor that could read or write it.
/// `mode` maps the entry's current `st_mode` to the new one.
///
/// Closing any descriptor of a file releases every fcntl lock the process
/// holds on it, so opening a file to `fchmod` it released the locks of an
/// overlay database open in this process (#149). On Linux the entry is
/// pinned with an `O_PATH | O_NOFOLLOW` descriptor (whose close releases
/// nothing), checked to be the same file as `expected`, and changed through
/// `/proc/self/fd`. Elsewhere it is changed by name with
/// `fchmodat(.., AT_SYMLINK_NOFOLLOW)` after a name check: a symlink is never
/// followed, but a swap of the name between the check and the change is not
/// detected (a weaker, pathname-race boundary).
pub fn chmod_entry_at<Fd: AsFd>(
    dir: Fd,
    name: &std::ffi::CStr,
    expected: &Stat,
    mode: impl FnOnce(rustix::fs::RawMode) -> rustix::fs::RawMode,
) -> io::Result<()> {
    let same = |now: &Stat| {
        now.st_dev == expected.st_dev
            && now.st_ino == expected.st_ino
            && now.st_mode & libc::S_IFMT == expected.st_mode & libc::S_IFMT
            && !matches!(now.st_mode & libc::S_IFMT, libc::S_IFDIR | libc::S_IFLNK)
    };
    let changed = || {
        io::Error::other(format!(
            "{} changed while its permissions were being set; nothing was changed",
            name.to_string_lossy()
        ))
    };
    #[cfg(target_os = "linux")]
    {
        use rustix::fs::{Mode, OFlags};
        use std::os::fd::AsRawFd;
        let pinned = rustix::fs::openat(
            dir,
            name,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let now = fstat_named(&pinned, name.to_string_lossy().as_ref())?;
        if !same(&now) {
            return Err(changed());
        }
        let proc = format!("/proc/self/fd/{}", pinned.as_raw_fd());
        rustix::fs::chmod(proc.as_str(), Mode::from_raw_mode(mode(now.st_mode))).map_err(|e| {
            io::Error::new(
                io::Error::from(e).kind(),
                format!(
                    "cannot set the permissions of {} through {proc} (is /proc mounted?): {e}",
                    name.to_string_lossy()
                ),
            )
        })?;
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let dir = dir.as_fd();
        let now = statat(dir, name, AtFlags::SYMLINK_NOFOLLOW)?;
        if !same(&now) {
            return Err(changed());
        }
        rustix::fs::chmodat(
            dir,
            name,
            rustix::fs::Mode::from_raw_mode(mode(now.st_mode)),
            AtFlags::SYMLINK_NOFOLLOW,
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{Duration, UNIX_EPOCH};

    /// Regression (#149): `chmod_entry_at` changes the file it was shown and
    /// nothing else. A name swapped to another file after the caller's stat
    /// is refused and neither file changes; a symlink is refused (never
    /// followed); the expected file is changed. On Linux the check runs on an
    /// `O_PATH` pin, so it also holds between the check and the change.
    #[test]
    fn regression_chmod_entry_at_refuses_a_swapped_name() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        fs::write(dir.join("a"), b"a").unwrap();
        fs::write(dir.join("b"), b"b").unwrap();
        fs::set_permissions(dir.join("a"), fs::Permissions::from_mode(0o644)).unwrap();
        fs::set_permissions(dir.join("b"), fs::Permissions::from_mode(0o644)).unwrap();
        let root = fs::File::open(dir).unwrap();
        let name = c"a";
        let a = statat(&root, name, AtFlags::SYMLINK_NOFOLLOW).unwrap();
        fs::rename(dir.join("b"), dir.join("a")).unwrap();
        let error = chmod_entry_at(&root, name, &a, |_| 0o400).unwrap_err();
        assert!(error.to_string().contains("changed"), "{error}");
        let mode = |p: &str| {
            fs::symlink_metadata(dir.join(p))
                .unwrap()
                .permissions()
                .mode()
        };
        assert_eq!(mode("a") & 0o777, 0o644, "the substitute was changed");

        let now = statat(&root, name, AtFlags::SYMLINK_NOFOLLOW).unwrap();
        chmod_entry_at(&root, name, &now, |m| m & !0o222).unwrap();
        assert_eq!(mode("a") & 0o777, 0o444);

        fs::write(dir.join("target"), b"t").unwrap();
        fs::set_permissions(dir.join("target"), fs::Permissions::from_mode(0o644)).unwrap();
        symlink("target", dir.join("link")).unwrap();
        let link = statat(&root, c"link", AtFlags::SYMLINK_NOFOLLOW).unwrap();
        assert!(chmod_entry_at(&root, c"link", &link, |_| 0o400).is_err());
        assert_eq!(mode("target") & 0o777, 0o644, "a symlink was followed");
    }

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

    /// Regression: a panic inside the stat call (rustix on macOS) becomes an
    /// `io::Error` naming the path instead of unwinding into the verb.
    #[test]
    fn regression_host_stat_panic_becomes_io_error_naming_path() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("poisoned.bin"), b"x").unwrap();
        fs::write(tmp.path().join("fine.bin"), b"x").unwrap();
        let dir = fs::File::open(tmp.path()).unwrap();
        let file = fs::File::open(tmp.path().join("poisoned.bin")).unwrap();
        set_panic_for_test(Some("poisoned.bin"));
        let at = statat(&dir, "poisoned.bin", AtFlags::SYMLINK_NOFOLLOW);
        let named = fstat_named(&file, "overlay/poisoned.bin");
        let ok = statat(&dir, "fine.bin", AtFlags::SYMLINK_NOFOLLOW);
        set_panic_for_test(None);
        let err = at.unwrap_err();
        assert!(err.to_string().contains("poisoned.bin"), "{err}");
        assert!(err.to_string().contains("rustix panic"), "{err}");
        let err = named.unwrap_err();
        assert!(err.to_string().contains("overlay/poisoned.bin"), "{err}");
        assert!(ok.is_ok());
    }
}
