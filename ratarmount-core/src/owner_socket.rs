//! Owner-only Unix socket binding shared by the CSI driver and the Docker volume
//! plugin (#182).
//!
//! The socket is bound inside a fresh 0700 sibling staging directory, changed to
//! mode 0600, then renamed onto the final path without replacing anything there.
//! umask(2) is process-global and would race threads that already exist when a
//! daemon binds, so it is never touched.

use std::fs;
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static SOCKET_STAGING_SEQ: AtomicU64 = AtomicU64::new(0);

// `sun_path` holds 107 bytes plus the NUL (#145).
/// Prefix of the staging directory name.
pub const STAGING_PREFIX: &str = ".rm";
/// Random characters after [`STAGING_PREFIX`].
pub const STAGING_RANDOM_LEN: usize = 8;
/// Longest socket path `sockaddr_un.sun_path` can hold (without its NUL).
pub const SUN_PATH_MAX: usize = 107;
/// Bytes the staged bind path adds to the parent: `/.rmXXXXXXXX/s`.
pub const STAGING_OVERHEAD: usize = 1 + STAGING_PREFIX.len() + STAGING_RANDOM_LEN + 2;
/// Longest parent directory whose staged path fits `sun_path` as is. Longer
/// directories bind through the staging directory's `/proc/self/fd` alias.
pub const MAX_DIRECT_DIR_LEN: usize = SUN_PATH_MAX - STAGING_OVERHEAD;
/// Where the staging directory's descriptor alias is looked up.
pub const PROC_SELF_FD: &str = "/proc/self/fd";

fn staging_name() -> String {
    use std::hash::{BuildHasher, Hasher};
    const ALPHABET: &[u8; 36] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    // RandomState is seeded per process; the inputs keep names distinct within it.
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u32(std::process::id());
    hasher.write_u64(SOCKET_STAGING_SEQ.fetch_add(1, Ordering::Relaxed));
    hasher.write_u128(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or(0),
    );
    let mut bits = hasher.finish();
    let mut name = String::from(STAGING_PREFIX);
    for _ in 0..STAGING_RANDOM_LEN {
        name.push(ALPHABET[(bits % 36) as usize] as char);
        bits /= 36;
    }
    name
}

/// Creates a fresh 0700 staging directory. Anyone who can write to `parent` can
/// pre-create names so that all 16 attempts hit EEXIST; that is a denial of
/// service, as one colliding name was before, and never a bind elsewhere.
fn stage_dir(parent: &Path) -> io::Result<PathBuf> {
    let mut last = None;
    for _ in 0..16 {
        let dir = parent.join(staging_name());
        {
            let __inventory_condition_2626 = {
                #[expect(
                    clippy::disallowed_types,
                    reason = r###"internal-read:v1 {"id":"IR-E0034-T01","item":"ratarmount_core::owner_socket::stage_dir","disposition":"support","category":"builder-type-support","reason":"Builder type support: Construct the mode-aware builder for a fresh daemon (CSI, volume plugin) socket staging directory.","creation":{"policy":"none","basis":"This is a type/import reference; it acquires no file or directory."}}"###
                )]
                #[expect(
                    clippy::disallowed_methods,
                    reason = r###"internal-read:v1 {"id":"IR-E0034-M01","item":"ratarmount_core::owner_socket::stage_dir","disposition":"support","category":"creation-builder","reason":"Construct the mode-aware builder for a fresh daemon (CSI, volume plugin) socket staging directory.","creation":{"policy":"none","basis":"Builder setup only; the distinct create event owns the 0700 directory creation."}}"###
                )]
                let mut __inventory_value_0 = fs::DirBuilder::new();
                #[expect(
                    clippy::disallowed_methods,
                    reason = r###"internal-read:v1 {"id":"IR-E0035-M01","item":"ratarmount_core::owner_socket::stage_dir","disposition":"output-owner","category":"socket-staging-directory","reason":"Create the fresh daemon (CSI, volume plugin) socket staging directory using its generated collision-retried name.","creation":{"policy":"exclusive-directory","basis":"The builder requests 0700 and retries EEXIST without binding elsewhere; staging cleanup is retained."}}"###
                )]
                let __inventory_value_1 = __inventory_value_0.mode(0o700).create(&dir);
                __inventory_value_1
            };
            match __inventory_condition_2626 {
                Ok(()) => return Ok(dir),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => last = Some(error),
                Err(error) => return Err(error),
            }
        }
    }
    Err(last.unwrap_or_else(|| io::Error::from(io::ErrorKind::AlreadyExists)))
}

/// Removes the staging directory, and the staged socket if rename did not run.
struct StagingDir {
    path: PathBuf,
    handle: Option<fs::File>,
    bound: bool,
}

impl StagingDir {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            handle: None,
            bound: false,
        }
    }

    fn publish(&self, path: &Path) -> io::Result<()> {
        let fd = self
            .handle
            .as_ref()
            .expect("opened staging directory")
            .as_raw_fd();
        // SAFETY: fd is held open and `s` is inside the checked owner-only
        // directory. Renaming that directory cannot redirect this chmod.
        if unsafe { libc::fchmodat(fd, c"s".as_ptr(), 0o600, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        rename_noreplace(fd, path)
    }
}

impl Drop for StagingDir {
    fn drop(&mut self) {
        if self.bound {
            if let Some(handle) = &self.handle {
                // SAFETY: unlink only the socket we created in the held directory.
                unsafe { libc::unlinkat(handle.as_raw_fd(), c"s".as_ptr(), 0) };
            }
        }
        let Ok(meta) = fs::symlink_metadata(&self.path) else {
            return;
        };
        if !meta.file_type().is_dir() || meta.uid() != euid() {
            return;
        }
        if let Some(handle) = &self.handle {
            let Ok(opened) = handle.metadata() else {
                return;
            };
            if meta.dev() != opened.dev() || meta.ino() != opened.ino() {
                return;
            }
        }
        // Never recursively remove a replacement or a pre-existing `s`. If the
        // open/check/bind failed, this removes only an empty staging directory.
        let _ = fs::remove_dir(&self.path);
    }
}

fn euid() -> u32 {
    // SAFETY: geteuid only reads this process's credential.
    unsafe { libc::geteuid() }
}

/// Refuses a path the kernel cannot bind: an interior NUL, or more than
/// [`SUN_PATH_MAX`] bytes. Daemons call it before creating any directory (#185).
pub fn socket_path_fits(path: &Path) -> io::Result<()> {
    // `sockaddr_un.sun_path` is 108 bytes, including the trailing NUL.
    // An interior NUL would truncate the path the kernel binds.
    let bytes = path.as_os_str().as_encoded_bytes();
    if bytes.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "socket path must contain no NUL",
        ));
    }
    if bytes.len() > SUN_PATH_MAX {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "socket path {} is {} bytes, over the {SUN_PATH_MAX}-byte sun_path limit",
                path.display(),
                bytes.len()
            ),
        ));
    }
    Ok(())
}

/// The opened staging directory must be a directory owned by this process's
/// effective user with mode 0700 (#182). Anyone who can write to the parent can
/// rename another directory into the staging name between its creation and
/// the open; binding there would publish a socket that user can reach.
fn check_staging_dir(dir: &Path, meta: &fs::Metadata, euid: u32) -> io::Result<()> {
    let mode = meta.mode() & 0o7777;
    if !meta.is_dir() || meta.uid() != euid || mode != 0o700 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "socket staging directory {} must be a directory owned by uid {euid} with \
                 mode 0700; it is owned by uid {} with mode {mode:04o}",
                dir.display(),
                meta.uid()
            ),
        ));
    }
    Ok(())
}

/// Binds `s` inside the staging directory. When `dir/s` is too long for `sun_path`,
/// bind through `<proc_self_fd>/<fd>/s`, the alias of an fd open on the staging
/// directory (Linux has no bindat(2)). The alias must resolve to that directory.
fn bind_staged(
    staging: &mut StagingDir,
    path: &Path,
    proc_self_fd: &Path,
) -> io::Result<UnixListener> {
    let dir = &staging.path;
    let handle = {
        #[expect(
            clippy::disallowed_types,
            reason = r###"internal-read:v1 {"id":"IR-B0289-T01","item":"ratarmount_core::owner_socket::bind_staged","disposition":"support","category":"builder-type-support","reason":"Builder type support: O_DIRECTORY | O_NOFOLLOW handle on the socket staging directory, used to check and normalize private staging permissions, bind through /proc/self/fd, and anchor socket publication and cleanup; reads no file content","creation":{"policy":"none","basis":"This is a type/import reference; it acquires no file or directory."}}"###
        )]
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-B0289-M01","item":"ratarmount_core::owner_socket::bind_staged","disposition":"support","category":"builder-setup","reason":"Prepare the builder for this item's separately reviewed open/create leaf.","creation":{"policy":"none","basis":"Builder construction/setup only; the separate open/create leaf owns pathname acquisition and permissions."},"supports_disposition":"out-of-family","baseline_reason":"O_DIRECTORY | O_NOFOLLOW handle on the socket staging directory, used to check and normalize private staging permissions, bind through /proc/self/fd, and anchor socket publication and cleanup; reads no file content"}"###
        )]
        let mut __inventory_value_0 = fs::OpenOptions::new();
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-B0289-M02","item":"ratarmount_core::owner_socket::bind_staged","disposition":"out-of-family","category":"directory-handle-or-durability","reason":"O_DIRECTORY | O_NOFOLLOW handle on the socket staging directory, used to check and normalize private staging permissions, bind through /proc/self/fd, and anchor socket publication and cleanup; reads no file content","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
        )]
        let __inventory_value_1 = __inventory_value_0
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(dir);
        __inventory_value_1
    }?;
    let mut opened = handle.metadata()?;
    // Linux inherits S_ISGID from shared parents even when mkdir requests 0700.
    // Normalize only this private, owned case, through the held descriptor;
    // never chmod an unsafe replacement into passing the check.
    if opened.is_dir() && opened.uid() == euid() && opened.mode() & 0o7777 == 0o2700 {
        handle.set_permissions(fs::Permissions::from_mode(0o700))?;
        opened = handle.metadata()?;
    }
    check_staging_dir(dir, &opened, euid())?;
    staging.handle = Some(handle);
    bind_checked(staging, path, proc_self_fd)
}

fn staged_socket_exists(fd: RawFd) -> io::Result<bool> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: fd is a live directory descriptor; stat points to writable storage.
    let result = unsafe {
        libc::fstatat(
            fd,
            c"s".as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::NotFound {
        return Ok(false);
    }
    Err(error)
}

fn bind_checked(
    staging: &mut StagingDir,
    path: &Path,
    proc_self_fd: &Path,
) -> io::Result<UnixListener> {
    let dir = &staging.path;
    let handle = staging.handle.as_ref().expect("checked staging directory");
    let opened = handle.metadata()?;
    let fd = handle.as_raw_fd();
    if staged_socket_exists(fd)? {
        return Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "staging socket already exists",
        ));
    }
    let staged = dir.join("s");
    let alias = proc_self_fd.join(handle.as_raw_fd().to_string());
    let alias_matches = fs::metadata(&alias)
        .is_ok_and(|meta| meta.dev() == opened.dev() && meta.ino() == opened.ino());
    let listener = if staged.as_os_str().as_encoded_bytes().len() <= SUN_PATH_MAX {
        UnixListener::bind(&staged)?
    } else {
        if !alias_matches {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "socket path {}: its directory is {} bytes; without {} the directory \
                     may be at most {MAX_DIRECT_DIR_LEN} bytes, because the socket is \
                     bound in a staging directory first ({SUN_PATH_MAX}-byte sun_path limit)",
                    path.display(),
                    dir.parent()
                        .map_or(0, |parent| parent.as_os_str().as_encoded_bytes().len()),
                    proc_self_fd.display()
                ),
            ));
        }
        UnixListener::bind(alias.join("s"))?
    };
    // A short pathname can be replaced after the owner/mode check. Only return
    // the listener if binding created `s` in the held directory, where other
    // users cannot create entries. This also works without /proc. A listener
    // bound in a replacement is closed without ever accepting requests.
    if !staged_socket_exists(fd)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "socket staging directory changed during bind",
        ));
    }
    staging.bound = true;
    Ok(listener)
}

/// Publish `s` from the held staging directory at `path` without replacing
/// anything already there. rename(2)
/// would silently replace a live socket (#117); RENAME_NOREPLACE restores the
/// EADDRINUSE a plain bind(path) gave. Other errors (EINVAL on a filesystem without
/// RENAME_NOREPLACE, ENOSYS under a seccomp profile) pass through: no replacing fallback.
fn rename_noreplace(from_dir_fd: RawFd, path: &Path) -> io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let to = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    // musl's libc crate bindings may lack renameat2 (musl 1.2.3); call the syscall directly.
    // SAFETY: from_dir_fd is held open and both strings are NUL-terminated.
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-E0036-M01","item":"ratarmount_core::owner_socket::rename_noreplace","disposition":"out-of-family","category":"socket-publication","reason":"Publish an already-created daemon (CSI, volume plugin) socket with the renameat2 no-replace syscall.","creation":{"policy":"none","basis":"This syscall renames s relative to the held, checked staging directory with RENAME_NOREPLACE; it acquires no file descriptor or new inode."}}"###
    )]
    let rc = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            from_dir_fd,
            c"s".as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if rc == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::EEXIST) {
        return Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            format!("socket already in use: {}", path.display()),
        ));
    }
    Err(error)
}

/// Binds an owner-only (0600) listening socket at `path`. The parent directory
/// must exist. Anything already at `path` makes this fail with `AddrInUse`.
pub fn bind_private(path: &Path) -> io::Result<UnixListener> {
    bind_private_with(path, Path::new(PROC_SELF_FD))
}

/// [`bind_private`] with another `/proc/self/fd` directory (a test seam).
pub fn bind_private_with(path: &Path, proc_self_fd: &Path) -> io::Result<UnixListener> {
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    socket_path_fits(path)?;
    let mut staging = StagingDir::new(stage_dir(parent)?);
    let listener = bind_staged(&mut staging, path, proc_self_fd)?;
    staging.publish(path)?;
    Ok(listener)
}

/// Names of `.rm` staging directories left in `parent` (for daemon tests).
#[doc(hidden)]
pub fn staging_names(parent: &Path) -> Vec<String> {
    let mut names = Vec::new();
    let Ok(entries) = fs::read_dir(parent) else {
        return names;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let random = name.strip_prefix(STAGING_PREFIX).unwrap_or("");
        if random.len() == STAGING_RANDOM_LEN
            && random
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        {
            names.push(name.to_string());
        }
    }
    names.sort();
    names
}

#[cfg(test)]
mod owner_only_socket_tests {
    use super::*;
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    use std::os::unix::net::UnixStream;

    /// Regression: setgid socket parents produce private 2700 staging directories,
    /// which must be normalized to 0700 instead of refusing a legitimate bind.
    #[test]
    fn regression_182_setgid_parent_binds() {
        let base = tempfile::tempdir_in("/tmp").unwrap();
        for parent_len in [40, MAX_DIRECT_DIR_LEN + 1] {
            let parent = base.path().join(
                "p".repeat(parent_len - base.path().as_os_str().as_encoded_bytes().len() - 1),
            );
            fs::create_dir(&parent).unwrap();
            fs::set_permissions(&parent, fs::Permissions::from_mode(0o2775)).unwrap();
            let created = stage_dir(&parent).unwrap();
            assert_eq!(fs::metadata(&created).unwrap().mode() & 0o7777, 0o2700);
            fs::remove_dir(&created).unwrap();
            let sock = parent.join("s");
            let _listener = bind_private(&sock).unwrap();
            assert_eq!(fs::metadata(&sock).unwrap().mode() & 0o7777, 0o600);
            UnixStream::connect(&sock).unwrap();
            assert!(staging_names(&parent).is_empty());
            assert_eq!(fs::metadata(&parent).unwrap().mode() & 0o7777, 0o2775);
        }
    }

    /// Regression: refusing an unsafe staging directory must not delete an
    /// existing `s` inside the replacement directory during error cleanup.
    #[test]
    fn regression_182_rejected_staging_preserves_existing_file() {
        for (mode, error_kind) in [
            (0o755, io::ErrorKind::PermissionDenied),
            (0o700, io::ErrorKind::AddrInUse),
        ] {
            let base = tempfile::tempdir().unwrap();
            let mut staging = StagingDir::new(stage_dir(base.path()).unwrap());
            let path = staging.path.clone();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            fs::write(path.join("s"), b"keep me").unwrap();
            let error = bind_staged(
                &mut staging,
                &base.path().join("socket"),
                Path::new(PROC_SELF_FD),
            )
            .unwrap_err();
            assert_eq!(error.kind(), error_kind);
            drop(staging);
            assert_eq!(fs::read(path.join("s")).unwrap(), b"keep me");
        }
    }

    /// Regression: a directory swapped after the owner/mode check must never
    /// return a listener from the replacement, even on the short no-/proc path.
    #[test]
    fn regression_182_swap_after_check_refuses_short_bind() {
        let base = tempfile::tempdir().unwrap();
        let path = stage_dir(base.path()).unwrap();
        let handle = fs::File::open(&path).unwrap();
        check_staging_dir(&path, &handle.metadata().unwrap(), euid()).unwrap();
        let mut staging = StagingDir::new(path.clone());
        staging.handle = Some(handle);
        let moved = base.path().join("moved");
        fs::rename(&path, &moved).unwrap();
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o777)).unwrap();

        let error = bind_checked(
            &mut staging,
            &base.path().join("socket"),
            &base.path().join("no-proc"),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(
            UnixStream::connect(path.join("s")).unwrap_err().kind(),
            io::ErrorKind::ConnectionRefused
        );
        drop(staging);
        assert!(fs::symlink_metadata(path.join("s"))
            .unwrap()
            .file_type()
            .is_socket());
        assert!(!moved.join("s").exists());
    }

    /// Regression: a post-bind directory swap redirected chmod, rename and
    /// cleanup to an unrelated `s`. Both publication and error cleanup use the fd.
    #[test]
    fn regression_182_swap_after_bind_preserves_replacement() {
        for publish in [false, true] {
            let base = tempfile::tempdir().unwrap();
            let mut staging = StagingDir::new(stage_dir(base.path()).unwrap());
            let path = staging.path.clone();
            let socket = base.path().join("socket");
            let listener = bind_staged(&mut staging, &socket, Path::new(PROC_SELF_FD)).unwrap();
            let moved = base.path().join("moved");
            fs::rename(&path, &moved).unwrap();
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
            let victim = base.path().join("victim");
            fs::write(&victim, b"keep me").unwrap();
            fs::set_permissions(&victim, fs::Permissions::from_mode(0o640)).unwrap();
            std::os::unix::fs::symlink(&victim, path.join("s")).unwrap();
            if publish {
                staging.publish(&socket).unwrap();
                assert!(fs::symlink_metadata(&socket)
                    .unwrap()
                    .file_type()
                    .is_socket());
                assert_eq!(fs::metadata(&socket).unwrap().mode() & 0o7777, 0o600);
                UnixStream::connect(&socket).unwrap();
                listener.accept().unwrap();
            } else {
                fs::write(&socket, b"occupied").unwrap();
                assert_eq!(
                    staging.publish(&socket).unwrap_err().kind(),
                    io::ErrorKind::AddrInUse
                );
                assert_eq!(fs::read(&socket).unwrap(), b"occupied");
            }
            drop(staging);
            assert_eq!(fs::read(&victim).unwrap(), b"keep me");
            assert_eq!(fs::metadata(&victim).unwrap().mode() & 0o7777, 0o640);
            assert_eq!(fs::read_link(path.join("s")).unwrap(), victim);
            assert!(!moved.join("s").exists());
        }
    }

    /// Regression: owner-only socket is mode 0600, staging dir is gone, client uses the final path.
    #[test]
    fn regression_owner_only_socket_final_path() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path();
        let created = stage_dir(parent).unwrap();
        assert_eq!(
            fs::symlink_metadata(&created).unwrap().mode() & 0o777,
            0o700
        );
        fs::remove_dir(&created).unwrap();

        let sock = parent.join("daemon.sock");
        let listener = bind_private(&sock).unwrap();
        assert_eq!(fs::symlink_metadata(&sock).unwrap().mode() & 0o777, 0o600);
        let bound = listener
            .local_addr()
            .unwrap()
            .as_pathname()
            .unwrap()
            .to_path_buf();
        // local_addr keeps the staging path; the renamed socket is the final path.
        assert_eq!(bound.file_name(), Some(std::ffi::OsStr::new("s")));
        assert_eq!(bound.parent().unwrap().parent(), Some(parent));
        assert_ne!(bound, sock);
        assert!(!bound.exists());
        UnixStream::connect(&sock).unwrap();
        assert!(staging_names(parent).is_empty());
    }

    /// Regression: a leftover `.rm*` staging directory and its socket must not block the next bind.
    #[test]
    fn regression_owner_only_socket_stale_staging_dir() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path();
        let first = stage_dir(parent).unwrap();
        let stale_sock = first.join("s");
        let _stale_listener = UnixListener::bind(&stale_sock).unwrap();
        let sock = parent.join("daemon.sock");
        let listener = bind_private(&sock).unwrap();
        assert!(fs::symlink_metadata(&first).unwrap().is_dir());
        assert!(fs::symlink_metadata(&stale_sock)
            .unwrap()
            .file_type()
            .is_socket());
        UnixStream::connect(&sock).unwrap();
        assert_eq!(
            staging_names(parent),
            vec![first.file_name().unwrap().to_str().unwrap().to_string()]
        );
        drop(listener);
    }

    /// Regression: publishing onto a directory fails (as AddrInUse) and leaves no staging directory.
    #[test]
    fn regression_owner_only_socket_rename_failure_removes_staging() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path();
        let target = parent.join("daemon.sock");
        fs::create_dir(&target).unwrap();
        let error = bind_private(&target).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
        assert!(fs::symlink_metadata(&target).unwrap().is_dir());
        assert!(staging_names(parent).is_empty());
    }

    /// Regression #117: a second bind onto a live socket must not replace it (rename(2) did).
    #[test]
    fn regression_owner_only_socket_second_bind_is_addr_in_use() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path();
        let sock = parent.join("daemon.sock");
        let first = bind_private(&sock).unwrap();
        let ino = fs::symlink_metadata(&sock).unwrap().ino();
        let error = bind_private(&sock).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
        assert_eq!(fs::symlink_metadata(&sock).unwrap().ino(), ino);
        // The first daemon is still the one reachable at the final path.
        let client = UnixStream::connect(&sock).unwrap();
        drop(client);
        drop(first);
        assert!(staging_names(parent).is_empty());
    }

    /// Regression #117: two concurrent starts on one path yield exactly one winner.
    #[test]
    fn regression_owner_only_socket_concurrent_bind_one_winner() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path();
        for i in 0..50 {
            let sock = parent.join(format!("daemon.sock-{i}"));
            let barrier = std::sync::Barrier::new(2);
            let results: Vec<_> = std::thread::scope(|scope| {
                let handles: Vec<_> = (0..2)
                    .map(|_| {
                        scope.spawn(|| {
                            barrier.wait();
                            bind_private(&sock)
                        })
                    })
                    .collect();
                handles.into_iter().map(|h| h.join().unwrap()).collect()
            });
            let oks = results.iter().filter(|r| r.is_ok()).count();
            assert_eq!(oks, 1, "iteration {i}: expected exactly one winner");
            for error in results.iter().filter_map(|r| r.as_ref().err()) {
                assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
            }
            UnixStream::connect(&sock).unwrap();
            assert!(staging_names(parent).is_empty());
        }
    }

    /// Regression #145: without /proc a directory over {MAX_DIRECT_DIR_LEN} bytes cannot be
    /// staged; the error names the real limit and no staging dir is left behind.
    #[test]
    fn regression_145_without_proc_long_dir_refused_with_limit() {
        let base = tempfile::tempdir_in("/tmp").unwrap();
        let no_proc = base.path().join("no-proc/self/fd");
        let base_len = base.path().as_os_str().as_encoded_bytes().len();
        let leaf_len = (MAX_DIRECT_DIR_LEN + 1)
            .checked_sub(base_len + 1)
            .expect("/tmp temp dir too long");
        let parent = base.path().join("d".repeat(leaf_len));
        fs::create_dir(&parent).unwrap();
        let sock = parent.join("daemon.sock");
        assert!(sock.as_os_str().as_encoded_bytes().len() <= 107);
        let error = bind_private_with(&sock, &no_proc).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        let message = error.to_string();
        assert!(
            message.contains(&format!("at most {MAX_DIRECT_DIR_LEN} bytes")),
            "{message}"
        );
        assert!(message.contains("107-byte sun_path limit"), "{message}");
        assert!(message.contains("no-proc/self/fd"), "{message}");
        assert!(staging_names(&parent).is_empty());

        // A directory short enough to bind directly never needs /proc.
        let short = base.path().join("daemon.sock");
        let listener = bind_private_with(&short, &no_proc).unwrap();
        UnixStream::connect(&short).unwrap();
        assert!(staging_names(base.path()).is_empty());
        drop(listener);
    }

    /// Regression: an interior NUL is rejected before bind, matching validate_socket_path.
    #[test]
    fn regression_owner_only_socket_sun_path_rejects_interior_nul() {
        use std::os::unix::ffi::OsStrExt;
        let path = Path::new(std::ffi::OsStr::from_bytes(b"/tmp/a\0b"));
        let error = socket_path_fits(path).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("NUL"));
    }

    /// Regression #145: the staging name adds a fixed 14 bytes, so a directory of exactly
    /// MAX_DIRECT_DIR_LEN bytes binds the staged path at 107 bytes; one more byte binds
    /// through the /proc/self/fd alias instead of being refused.
    #[test]
    fn regression_owner_only_socket_sun_path_exact_107_binds() {
        assert_eq!(STAGING_OVERHEAD, 14);
        assert_eq!(
            staging_name().len(),
            STAGING_PREFIX.len() + STAGING_RANDOM_LEN
        );
        let base = tempfile::tempdir_in("/tmp").unwrap();
        let base_len = base.path().as_os_str().as_encoded_bytes().len();
        let parent = base
            .path()
            .join("p".repeat(MAX_DIRECT_DIR_LEN - base_len - 1));
        fs::create_dir(&parent).unwrap();
        assert_eq!(
            parent.as_os_str().as_encoded_bytes().len(),
            MAX_DIRECT_DIR_LEN
        );
        let sock = parent.join("daemon.sock");
        let listener = bind_private(&sock).unwrap();
        let bound = listener
            .local_addr()
            .unwrap()
            .as_pathname()
            .unwrap()
            .to_path_buf();
        assert_eq!(bound.as_os_str().as_encoded_bytes().len(), 107);
        assert_eq!(bound.file_name(), Some(std::ffi::OsStr::new("s")));
        UnixStream::connect(&sock).unwrap();
        assert!(staging_names(&parent).is_empty());

        let longer = base.path().join("p".repeat(MAX_DIRECT_DIR_LEN - base_len));
        fs::create_dir(&longer).unwrap();
        let longer_sock = longer.join("daemon.sock");
        let listener = bind_private(&longer_sock).unwrap();
        let bound = listener.local_addr().unwrap();
        let bound = bound.as_pathname().unwrap();
        assert!(bound.starts_with(PROC_SELF_FD), "{}", bound.display());
        UnixStream::connect(&longer_sock).unwrap();
        assert!(staging_names(&longer).is_empty());
    }

    /// Regression #145: a target path over 107 bytes is refused even when its
    /// directory is short enough to stage in (clients could never connect to it).
    #[test]
    fn regression_145_target_over_sun_path_refused() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("s".repeat(120));
        let error = bind_private(&sock).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("107-byte sun_path limit"));
        assert!(staging_names(dir.path()).is_empty());
    }

    /// Regression #145: a directory over 93 bytes with an exactly-107-byte socket path
    /// was refused because the staged bind path added 14 bytes; it must bind and publish.
    #[test]
    fn regression_145_long_dir_exact_107_socket_binds() {
        let base = tempfile::tempdir_in("/tmp").unwrap();
        let base_len = base.path().as_os_str().as_encoded_bytes().len();
        let name = "daemon.sock";
        let leaf_len = (107 - name.len() - 1)
            .checked_sub(base_len + 1)
            .expect("/tmp temp dir too long");
        let parent = base.path().join("p".repeat(leaf_len));
        fs::create_dir(&parent).unwrap();
        let parent_len = parent.as_os_str().as_encoded_bytes().len();
        assert!(parent_len > 93, "directory is {parent_len} bytes");
        let sock = parent.join(name);
        assert_eq!(sock.as_os_str().as_encoded_bytes().len(), 107);
        let listener =
            bind_private(&sock).unwrap_or_else(|e| panic!("bind {}: {e}", sock.display()));
        let bound = listener
            .local_addr()
            .unwrap()
            .as_pathname()
            .unwrap()
            .to_path_buf();
        // The kernel bound the short /proc alias, not the 120-byte staging path.
        assert!(bound.starts_with(PROC_SELF_FD), "{}", bound.display());
        assert!(
            bound.as_os_str().as_encoded_bytes().len() <= 107,
            "{}",
            bound.display()
        );
        assert_eq!(bound.file_name(), Some(std::ffi::OsStr::new("s")));
        let meta = fs::symlink_metadata(&sock).unwrap();
        assert!(meta.file_type().is_socket());
        assert_eq!(meta.mode() & 0o777, 0o600);
        UnixStream::connect(&sock).unwrap();
        assert!(staging_names(&parent).is_empty());
        drop(listener);
    }

    /// Regression #145: a ~90-byte socket path (under sun_path) was refused with the
    /// SUN_LEN error because the staging path added ~30 bytes.
    #[test]
    fn regression_145_ninety_byte_socket_path_binds() {
        let base = tempfile::tempdir().unwrap();
        let base_len = base.path().as_os_str().as_encoded_bytes().len();
        let name = "daemon.sock";
        let leaf_len = (90 - name.len() - 1)
            .checked_sub(base_len + 1)
            .filter(|&len| len >= 1)
            .unwrap_or_else(|| panic!("temp dir {} too long", base.path().display()));
        let parent = base.path().join("q".repeat(leaf_len));
        fs::create_dir(&parent).unwrap();
        let sock = parent.join(name);
        assert_eq!(sock.as_os_str().as_encoded_bytes().len(), 90);
        let listener =
            bind_private(&sock).unwrap_or_else(|e| panic!("bind {}: {e}", sock.display()));
        let meta = fs::symlink_metadata(&sock).unwrap();
        assert!(meta.file_type().is_socket());
        assert_eq!(meta.mode() & 0o777, 0o600);
        UnixStream::connect(&sock).unwrap();
        assert!(staging_names(&parent).is_empty());
        drop(listener);
    }
    /// Regression #182: a staging directory that is not mode 0700 (or not owned by
    /// this user) is refused after it is opened, and nothing is bound in it.
    #[test]
    fn regression_182_staging_dir_owner_and_mode_checked() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".rmaaaaaaaa");
        let mut staging = StagingDir::new(path.clone());
        fs::create_dir(&path).unwrap();
        let sock = dir.path().join("daemon.sock");
        for mode in [0o755, 0o770, 0o2701, 0o2770, 0o1700, 0o4700] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            let error = bind_staged(&mut staging, &sock, Path::new(PROC_SELF_FD)).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert!(
                error.to_string().contains(&format!("mode {mode:04o}")),
                "{error}"
            );
            assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, mode);
            assert!(fs::symlink_metadata(path.join("s")).is_err());
        }

        fs::set_permissions(&path, fs::Permissions::from_mode(0o2700)).unwrap();
        let listener = bind_staged(&mut staging, &sock, Path::new(PROC_SELF_FD)).unwrap();
        assert_eq!(
            staging.handle.as_ref().unwrap().metadata().unwrap().mode() & 0o7777,
            0o700
        );
        assert!(fs::symlink_metadata(path.join("s"))
            .unwrap()
            .file_type()
            .is_socket());
        drop(listener);

        // Another owner is refused even with mode 0700.
        let meta = fs::symlink_metadata(&path).unwrap();
        let error = check_staging_dir(&path, &meta, meta.uid().wrapping_add(1)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("owned by uid"), "{error}");
        check_staging_dir(&path, &meta, meta.uid()).unwrap();
        // A non-directory is refused.
        let file = dir.path().join("file");
        fs::write(&file, b"").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o700)).unwrap();
        let meta = fs::symlink_metadata(&file).unwrap();
        assert!(check_staging_dir(&file, &meta, meta.uid()).is_err());
        // A symlinked staging directory is refused by O_NOFOLLOW before any check.
        let link = dir.path().join(".rmbbbbbbbb");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(bind_staged(&mut StagingDir::new(link), &sock, Path::new(PROC_SELF_FD)).is_err());
    }
}
