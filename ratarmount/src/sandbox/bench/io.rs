//! Eight acquisition leaves (M01–M07 plus the cleanup O_PATH pin); callers supply admitted roots and single-component children.
use rustix::fd::{AsFd, AsRawFd, OwnedFd};
use rustix::fs::{self, Mode, OFlags, CWD};
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

pub(super) fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}
pub(super) fn component(name: &str) -> io::Result<()> {
    if name.is_empty() || matches!(name, "." | "..") || name.contains(['/', '\0']) {
        return Err(invalid("unsafe child component"));
    }
    Ok(())
}
fn child_component(name: &CStr) -> io::Result<()> {
    let name = name.to_bytes();
    if name.is_empty() || matches!(name, b"." | b"..") || name.contains(&b'/') {
        return Err(invalid("unsafe child component"));
    }
    Ok(())
}
fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}
pub(super) fn open_artifact(path: &Path) -> io::Result<File> {
    if path.symlink_metadata()?.file_type().is_symlink() {
        return Err(invalid("artifact symlink refused"));
    }
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-GAP0-B4A1-M01","item":"ratarmount::sandbox::bench::io::open_artifact","disposition":"out-of-family","category":"benchmark-artifact","reason":"Open only the admitted pinned local archive without following its final symlink; nonblocking open followed by regular-file and bounded size checks precedes hashing and decoding.","creation":{"policy":"none","basis":"Existing local archive only; no creation or substitution."}}"###
    )]
    let fd = fs::openat(
        CWD,
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOCTTY,
        Mode::empty(),
    )?;
    let file = File::from(fd);
    if !file.metadata()?.is_file() {
        return Err(invalid("artifact must be a regular file"));
    }
    Ok(file)
}
pub(super) fn open_directory(path: &Path) -> io::Result<OwnedFd> {
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-GAP0-B4A1-M02","item":"ratarmount::sandbox::bench::io::open_directory","disposition":"out-of-family","category":"benchmark-directory","reason":"Open an admitted canonical source/output/scratch parent or root as a no-follow directory descriptor for confined operations.","creation":{"policy":"none","basis":"Existing admitted directory only."}}"###
    )]
    let fd = fs::openat(CWD, path, directory_flags(), Mode::empty())?;
    Ok(fd)
}
pub(super) fn open_child_directory(parent: impl AsFd, name: &CStr) -> io::Result<OwnedFd> {
    child_component(name)?;
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-GAP0-B4A1-M03","item":"ratarmount::sandbox::bench::io::open_child_directory","disposition":"out-of-family","category":"benchmark-descent","reason":"Descend one validated child of a held directory using O_DIRECTORY and O_NOFOLLOW; archive-created symlinks are never traversed.","creation":{"policy":"none","basis":"Existing confined directory; no descriptor duplication or creation."}}"###
    )]
    let fd = fs::openat(parent, name, directory_flags(), Mode::empty())?;
    Ok(fd)
}
pub(super) fn create_directory(parent: &OwnedFd, name: &str) -> io::Result<OwnedFd> {
    component(name)?;
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-GAP0-B4A1-M04","item":"ratarmount::sandbox::bench::io::create_directory","disposition":"output-owner","category":"benchmark-owned-directory","reason":"Create both exclusive bench-owned private roots and confined archive extraction directories at one mkdirat site, initially 0700. Private roots stay 0700; recorded archive directory metadata is applied only to extracted directories after descendants.","creation":{"policy":"exclusive-directory-relative","basis":"Validated single-component child of a held parent; mkdirat requests 0700 and refuses collisions, then no-follow reopen and fchmod establish 0700 before any descendants."}}"###
    )]
    fs::mkdirat(parent, name, Mode::from_raw_mode(0o700))?;
    let fd = open_child_directory(parent, &CString::new(name)?)?;
    fs::fchmod(&fd, Mode::from_raw_mode(0o700))?;
    Ok(fd)
}
pub(super) fn create_output(parent: &OwnedFd, name: &str) -> io::Result<File> {
    component(name)?;
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-GAP0-B4A1-M05","item":"ratarmount::sandbox::bench::io::create_output","disposition":"output-owner","category":"benchmark-output","reason":"Create exclusive owned logs and ungraded status/control outputs relative to the private output root; move log descriptors into child stdio.","creation":{"policy":"exclusive-file-relative","basis":"O_EXCL and O_NOFOLLOW prevent replacement; initial mode 0600, never widened."}}"###
    )]
    let fd = fs::openat(
        parent,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )?;
    fs::fchmod(&fd, Mode::from_raw_mode(0o600))?;
    Ok(File::from(fd))
}
pub(super) fn create_tree_file(parent: &OwnedFd, name: &str) -> io::Result<File> {
    component(name)?;
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-GAP0-B4A1-M06","item":"ratarmount::sandbox::bench::io::create_tree_file","disposition":"output-owner","category":"benchmark-extraction-file","reason":"Create an exclusive confined regular archive member at 0600; apply accepted archive file metadata after writing its bounded contents.","creation":{"policy":"exclusive-file-relative","basis":"Held no-follow parent and single-component name; O_EXCL and O_NOFOLLOW refuse aliases or replacement."}}"###
    )]
    let fd = fs::openat(
        parent,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )?;
    Ok(File::from(fd))
}
pub(super) fn open_run_log(parent: &OwnedFd, name: &str) -> io::Result<Vec<u8>> {
    component(name)?;
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-GAP0-B4A1-M07","item":"ratarmount::sandbox::bench::io::open_run_log","disposition":"out-of-family","category":"benchmark-completed-log","reason":"Read at most 64 KiB of a completed owned regular runtime log through its private root, without following symlinks or cloning the child stdio descriptor.","creation":{"policy":"none","basis":"Read-only completed owned log; no creation or truncation."}}"###
    )]
    let fd = fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let file = File::from(fd);
    if !file.metadata()?.is_file() {
        return Err(invalid("run log must be regular"));
    }
    let mut bytes = Vec::new();
    file.take(64 * 1024).read_to_end(&mut bytes)?;
    Ok(bytes)
}

#[derive(Debug)]
struct CleanupFailure {
    primary: String,
    cleanup: String,
}
impl std::fmt::Display for CleanupFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}; cleanup: {}", self.primary, self.cleanup)
    }
}
impl std::error::Error for CleanupFailure {}
pub(super) fn error_parts(error: &io::Error) -> (String, Option<String>) {
    match error
        .get_ref()
        .and_then(|e| e.downcast_ref::<CleanupFailure>())
    {
        Some(failure) => (failure.primary.clone(), Some(failure.cleanup.clone())),
        None => (error.to_string(), None),
    }
}
// Keep source recovery failures even if the caller's subsequent removal succeeds.
pub(super) fn with_cleanup(error: io::Error, cleanup: io::Result<()>) -> io::Error {
    match cleanup {
        Ok(()) => error,
        Err(secondary) => {
            let (primary, previous) = error_parts(&error);
            let mut cleanup = secondary.to_string();
            if let Some(previous) = previous {
                if previous != cleanup {
                    cleanup = format!("{previous}; {cleanup}");
                }
            }
            io::Error::new(error.kind(), CleanupFailure { primary, cleanup })
        }
    }
}
fn writable_child(parent: impl AsFd, name: &CStr) -> io::Result<()> {
    child_component(name)?;
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-GAP0-B4A2-M08","item":"ratarmount::sandbox::bench::io::writable_child","disposition":"out-of-family","category":"benchmark-cleanup-directory","reason":"Pin one no-follow directory child of a held private parent with O_PATH so mode-000 archive or runtime directories can be chmodded through its proc fd before confined cleanup.","creation":{"policy":"none","basis":"Existing owned directory only; no content read or creation. Symlinks and non-directories are unlinked without chmod."}}"###
    )]
    let pinned = fs::openat(
        parent,
        name,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let proc = format!("/proc/self/fd/{}", pinned.as_raw_fd());
    fs::chmod(proc.as_str(), Mode::from_raw_mode(0o700)).map_err(|error| {
        let hint = if error == rustix::io::Errno::NOENT {
            " (is /proc mounted?)"
        } else {
            ""
        };
        io::Error::other(format!(
            "cannot set directory permissions through {proc}{hint}: {error}"
        ))
    })
}
// One listing fd per frame; parents remain writable until their children are gone.
fn walk(root: OwnedFd, remove: bool) -> io::Result<()> {
    let mut dir = fs::Dir::new(root)?;
    // On btrfs, a long-lived fd opened before children existed can miss them after fchmod.
    // Dir::new preserves the offset; explicitly rewind each listing before reading.
    dir.rewind();
    let mut stack = vec![(dir, None::<CString>)];
    while let Some((dir, _)) = stack.last_mut() {
        if let Some(entry) = dir.read() {
            let entry = entry?;
            let name = entry.file_name();
            if matches!(name.to_bytes(), b"." | b"..") {
                continue;
            }
            child_component(name)?;
            let fd = dir.fd()?;
            let stat = fs::statat(fd, name, fs::AtFlags::SYMLINK_NOFOLLOW)?;
            if fs::FileType::from_raw_mode(stat.st_mode) == fs::FileType::Directory {
                if stack.len() >= 256 {
                    return Err(invalid(
                        "cleanup directory depth exceeds 256; remaining tree preserved",
                    ));
                }
                let dir = &stack.last().unwrap().0;
                writable_child(dir.fd()?, name)?;
                let child = open_child_directory(dir.fd()?, name)?;
                let mut child = fs::Dir::new(child)?;
                child.rewind();
                stack.push((child, Some(name.to_owned())));
            } else if remove {
                fs::unlinkat(fd, name, fs::AtFlags::empty())?;
            }
        } else {
            let (_, name) = stack.pop().unwrap();
            if remove {
                if let (Some((parent, _)), Some(name)) = (stack.last(), name) {
                    fs::unlinkat(parent.fd()?, name.as_c_str(), fs::AtFlags::REMOVEDIR)?;
                }
            }
        }
    }
    Ok(())
}
pub(super) fn make_removable(root: OwnedFd) -> io::Result<()> {
    fs::fchmod(&root, Mode::from_raw_mode(0o700))?;
    walk(root, false)
}
pub(super) fn remove_tree(parent: &OwnedFd, name: &str) -> io::Result<()> {
    component(name)?;
    let stat = match fs::statat(parent, name, fs::AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(rustix::io::Errno::NOENT) => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if fs::FileType::from_raw_mode(stat.st_mode) != fs::FileType::Directory {
        fs::unlinkat(parent, name, fs::AtFlags::empty())?;
        return Ok(());
    }
    let child = CString::new(name)?;
    writable_child(parent, &child)?;
    walk(open_child_directory(parent, &child)?, true)?;
    fs::unlinkat(parent, name, fs::AtFlags::REMOVEDIR)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    // Regression: a long-lived empty-directory fd missed later children during recovery.
    // Reproduces only on filesystems with btrfs-like getdents behaviour; ext4/tmpfs may pass without rewind.
    #[test]
    fn regression_bench_make_removable_rewinds_long_lived_directory() {
        let dir = tempfile::tempdir().unwrap();
        let parent = open_directory(dir.path()).unwrap();
        let root = create_directory(&parent, "tree").unwrap();
        let child = create_directory(&root, "child").unwrap();
        fs::fchmod(&child, Mode::from_raw_mode(0o500)).unwrap();
        fs::fchmod(&root, Mode::from_raw_mode(0o500)).unwrap();
        make_removable(root).unwrap();
        assert_eq!(
            dir.path()
                .join("tree/child")
                .metadata()
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        remove_tree(&parent, "tree").unwrap();
    }
    // Regression: a later successful removal discarded an earlier make_removable error (R-2).
    #[test]
    fn regression_bench_cleanup_secondary_survives_later_success() {
        let failure = with_cleanup(
            invalid("extract failed"),
            Err(io::Error::other("metadata failed")),
        );
        assert_eq!(failure.kind(), io::ErrorKind::InvalidInput);
        let failure = with_cleanup(failure, Ok(()));
        assert_eq!(
            error_parts(&failure),
            ("extract failed".into(), Some("metadata failed".into()))
        );
        let failure = with_cleanup(failure, Err(io::Error::other("remove failed")));
        assert_eq!(
            error_parts(&failure),
            (
                "extract failed".into(),
                Some("metadata failed; remove failed".into())
            )
        );
    }
    // Regression: cleanup chmod followed an outside symlink or could not open mode-000 children.
    #[test]
    fn regression_bench_cleanup_held_handles_do_not_follow_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let parent = open_directory(dir.path()).unwrap();
        let tree = create_directory(&parent, "tree").unwrap();
        let outside = dir.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o500)).unwrap();
        symlink(&outside, dir.path().join("tree/link")).unwrap();
        let zero = create_directory(&tree, "zero").unwrap();
        create_directory(&zero, "child").unwrap();
        fs::fchmod(&zero, Mode::empty()).unwrap();
        remove_tree(&parent, "tree").unwrap();
        assert!(!dir.path().join("tree").exists());
        assert_eq!(
            outside.metadata().unwrap().permissions().mode() & 0o777,
            0o500
        );
        std::fs::set_permissions(outside, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    // Regression: runtime-created non-UTF-8 file and directory names aborted held-handle cleanup.
    #[test]
    fn regression_bench_cleanup_non_utf8_names() {
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile::tempdir().unwrap();
        let parent = open_directory(dir.path()).unwrap();
        create_directory(&parent, "tree").unwrap();
        let tree = dir.path().join("tree");
        std::fs::write(
            tree.join(std::ffi::OsStr::from_bytes(b"file-\xff")),
            b"file",
        )
        .unwrap();
        let child = tree.join(std::ffi::OsStr::from_bytes(b"dir-\xff"));
        std::fs::create_dir(&child).unwrap();
        std::fs::write(child.join("child"), b"child").unwrap();
        std::fs::set_permissions(&child, std::fs::Permissions::from_mode(0o000)).unwrap();
        remove_tree(&parent, "tree").unwrap();
        assert!(!tree.exists());
    }
    // Regression: unbounded cleanup recursion panicked or removed the root after depth overflow.
    #[test]
    fn regression_bench_cleanup_depth_cap_keeps_tree() {
        let dir = tempfile::tempdir().unwrap();
        let parent = open_directory(dir.path()).unwrap();
        let mut current = create_directory(&parent, "tree").unwrap();
        for _ in 0..257 {
            current = create_directory(&current, "d").unwrap();
        }
        let error = remove_tree(&parent, "tree").unwrap_err();
        assert!(error
            .to_string()
            .contains("cleanup directory depth exceeds 256; remaining tree preserved"));
        assert!(dir.path().join("tree").exists());
        let subtree = open_directory(&dir.path().join("tree/d/d")).unwrap();
        remove_tree(&subtree, "d").unwrap();
        remove_tree(&parent, "tree").unwrap();
    }
}
