//! Seven acquisition leaves; callers supply admitted roots and single-component children.
use rustix::fd::OwnedFd;
use rustix::fs::{self, Mode, OFlags, CWD};
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
pub(super) fn open_child_directory(parent: &OwnedFd, name: &str) -> io::Result<OwnedFd> {
    component(name)?;
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
    let fd = open_child_directory(parent, name)?;
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
