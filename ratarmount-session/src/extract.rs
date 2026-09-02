//! Streaming extract (`Session::extract_to`).

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use ratarmount_core::{
    is_dir_mode, is_lnk_mode, query_normpath, read_exact_or_short, FileInfo, UserData,
};

use crate::read::map_member_io;
use crate::types::{DirCursor, ExtractProgress, ExtractRequest, Overwrite};
use crate::{Error, Session};

const COPY_BUF: usize = 64 * 1024;
/// Progress / cancel check interval while copying a member.
const PROGRESS_EVERY: u64 = 8 * 1024 * 1024;
const EXTRACT_ALL_PAGE: u32 = 1024;

impl Session {
    /// Stream members to `req.dest_dir`. `progress` may be called between
    /// members and every 8 MiB copied. `cancel` is checked at those points.
    pub fn extract_to(
        &self,
        req: ExtractRequest,
        progress: Option<&dyn Fn(ExtractProgress)>,
        cancel: Option<&AtomicBool>,
    ) -> Result<(), Error> {
        std::fs::create_dir_all(&req.dest_dir).map_err(|e| map_dest_io(e, &req.dest_dir))?;
        let mut state = ExtractState {
            files_done: 0,
            files_hint: if req.members.is_empty() {
                None
            } else {
                Some(req.members.len() as u64)
            },
            bytes_out: 0,
        };
        if req.members.is_empty() {
            self.extract_all(&req, progress, cancel, &mut state)
        } else {
            for member in &req.members {
                if cancelled(cancel) {
                    return Err(Error::Cancelled);
                }
                self.extract_one_named(member, &req, progress, cancel, &mut state)?;
            }
            Ok(())
        }
    }

    fn extract_all(
        &self,
        req: &ExtractRequest,
        progress: Option<&dyn Fn(ExtractProgress)>,
        cancel: Option<&AtomicBool>,
        state: &mut ExtractState,
    ) -> Result<(), Error> {
        if let Some(cat) = self.catalog() {
            let mut after_path: Option<String> = None;
            let mut after_oh: Option<i64> = None;
            let mut prev_path: Option<String> = None;
            loop {
                if cancelled(cancel) {
                    return Err(Error::Cancelled);
                }
                let page = cat
                    .list_extract_payload_page(after_path.as_deref(), after_oh, EXTRACT_ALL_PAGE)
                    .map_err(|e| Error::Internal(e.to_string()))?;
                if page.is_empty() {
                    break;
                }
                for row in &page {
                    if cancelled(cancel) {
                        return Err(Error::Cancelled);
                    }
                    if prev_path.as_deref() == Some(row.fullpath.as_str()) {
                        continue;
                    }
                    self.extract_one_named(&row.fullpath, req, progress, cancel, state)?;
                    prev_path = Some(row.fullpath.clone());
                }
                if (page.len() as u32) < EXTRACT_ALL_PAGE {
                    break;
                }
                let Some(last) = page.last() else {
                    break;
                };
                after_path = Some(last.fullpath.clone());
                after_oh = Some(last.offsetheader);
            }
            return Ok(());
        }
        extract_all_via_dirents(self, req, progress, cancel, state)
    }

    fn extract_one_named(
        &self,
        member: &str,
        req: &ExtractRequest,
        progress: Option<&dyn Fn(ExtractProgress)>,
        cancel: Option<&AtomicBool>,
        state: &mut ExtractState,
    ) -> Result<(), Error> {
        let dest = dest_path_for_member(&req.dest_dir, member, req.allow_unsafe_paths)?;
        if !req.allow_unsafe_paths {
            ensure_no_intermediate_symlink(&req.dest_dir, &dest, member)?;
        }
        emit(progress, state, Some(member.to_string()));
        let lookup_path = query_normpath(member);
        let Some(fi) = self.mount_source().lookup(&lookup_path, 0) else {
            return Err(Error::NotFound);
        };
        if is_generated(&fi) {
            state.files_done += 1;
            emit(progress, state, Some(member.to_string()));
            return Ok(());
        }
        if is_dir_mode(fi.mode) {
            if !req.allow_unsafe_paths && dest_is_symlink(&dest)? {
                return Err(Error::PathEscape(member.to_string()));
            }
            std::fs::create_dir_all(&dest).map_err(|e| map_dest_io(e, &dest))?;
            state.files_done += 1;
            emit(progress, state, Some(member.to_string()));
            return Ok(());
        }
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(|e| map_dest_io(e, parent))?;
        }
        if is_lnk_mode(fi.mode) {
            extract_symlink(&dest, &fi.linkname, req.overwrite)?;
            state.files_done += 1;
            emit(progress, state, Some(member.to_string()));
            return Ok(());
        }
        if matches!(req.overwrite, Overwrite::Skip) && dest_exists_nofollow(&dest)? {
            state.files_done += 1;
            emit(progress, state, Some(member.to_string()));
            return Ok(());
        }
        copy_member(self, &fi, &dest, progress, cancel, state, member)
    }
}

struct ExtractState {
    files_done: u64,
    files_hint: Option<u64>,
    bytes_out: u64,
}

fn extract_all_via_dirents(
    session: &Session,
    req: &ExtractRequest,
    progress: Option<&dyn Fn(ExtractProgress)>,
    cancel: Option<&AtomicBool>,
    state: &mut ExtractState,
) -> Result<(), Error> {
    let mut dirs = vec!["/".to_string()];
    while let Some(dir) = dirs.pop() {
        let mut cursor = DirCursor::Start;
        loop {
            if cancelled(cancel) {
                return Err(Error::Cancelled);
            }
            let page = session.list_dirents_page(&dir, cursor, EXTRACT_ALL_PAGE)?;
            for e in &page.entries {
                if e.is_dir {
                    dirs.push(e.path.clone());
                    continue;
                }
                session.extract_one_named(&e.path, req, progress, cancel, state)?;
            }
            match page.next_cursor {
                Some(next) => cursor = next,
                None => break,
            }
        }
    }
    Ok(())
}

fn copy_member(
    session: &Session,
    fi: &FileInfo,
    dest: &Path,
    progress: Option<&dyn Fn(ExtractProgress)>,
    cancel: Option<&AtomicBool>,
    state: &mut ExtractState,
    member: &str,
) -> Result<(), Error> {
    let mut src = session.mount_source().open(fi, 0).map_err(map_member_io)?;
    // Write to a sibling tmp, then rename. File::create(dest) would truncate an
    // existing file immediately; cancel / member IO then unlinked that dest and
    // destroyed the pre-existing contents. persist_extract_tmp replaces a dest
    // symlink (nofollow) only after the copy succeeds.
    let (mut out, tmp) = create_extract_tmp(dest)?;
    let copy_res: Result<(), Error> = (|| {
        let mut buf = [0u8; COPY_BUF];
        let mut since_progress = 0u64;
        loop {
            if cancelled(cancel) {
                return Err(Error::Cancelled);
            }
            let n = read_exact_or_short(&mut src, &mut buf).map_err(map_member_io)?;
            if n == 0 {
                break;
            }
            out.write_all(&buf[..n]).map_err(|e| map_dest_io(e, dest))?;
            state.bytes_out += n as u64;
            since_progress += n as u64;
            if since_progress >= PROGRESS_EVERY {
                if cancelled(cancel) {
                    return Err(Error::Cancelled);
                }
                emit(progress, state, Some(member.to_string()));
                since_progress = 0;
            }
        }
        out.flush().map_err(|e| map_dest_io(e, dest))?;
        Ok(())
    })();
    drop(out);
    match copy_res {
        Ok(()) => {
            persist_extract_tmp(&tmp, dest)?;
            state.files_done += 1;
            emit(progress, state, Some(member.to_string()));
            Ok(())
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Sibling of `dest` so `rename` stays on the same filesystem.
fn create_extract_tmp(dest: &Path) -> Result<(std::fs::File, PathBuf), Error> {
    static SEQ: AtomicU64 = AtomicU64::new(1);
    let parent = dest
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let stem = dest
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "extract".into());
    for _ in 0..32 {
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let tmp = parent.join(format!(".{stem}.extract-{seq}.tmp"));
        match OpenOptions::new().write(true).create_new(true).open(&tmp) {
            Ok(f) => return Ok((f, tmp)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(map_dest_io(e, dest)),
        }
    }
    Err(Error::Internal(format!(
        "could not allocate extract temp next to {}",
        dest.display()
    )))
}

/// Atomically replace `dest` with a completed tmp. Dest is removed only after
/// the copy succeeded (Windows cannot `rename` over an existing file).
fn persist_extract_tmp(tmp: &Path, dest: &Path) -> Result<(), Error> {
    match std::fs::rename(tmp, dest) {
        Ok(()) => Ok(()),
        Err(e) => {
            if !dest_exists_nofollow(dest)? {
                let _ = std::fs::remove_file(tmp);
                return Err(map_dest_io(e, dest));
            }
            if dest_is_dir_nofollow(dest)? {
                let _ = std::fs::remove_file(tmp);
                return Err(Error::Internal(format!(
                    "refusing to replace directory {}",
                    dest.display()
                )));
            }
            // Copy is complete; replacing dest is now the remaining risk.
            if let Err(rm) = std::fs::remove_file(dest) {
                let _ = std::fs::remove_file(tmp);
                return Err(map_dest_io(rm, dest));
            }
            if let Err(rn) = std::fs::rename(tmp, dest) {
                // dest is already gone; keep tmp so the completed copy survives.
                return Err(map_dest_io(rn, dest));
            }
            Ok(())
        }
    }
}

fn dest_is_dir_nofollow(path: &Path) -> Result<bool, Error> {
    match std::fs::symlink_metadata(path) {
        Ok(m) => Ok(m.file_type().is_dir()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(map_dest_io(e, path)),
    }
}

fn emit(
    progress: Option<&dyn Fn(ExtractProgress)>,
    state: &ExtractState,
    current_path: Option<String>,
) {
    if let Some(cb) = progress {
        cb(ExtractProgress {
            files_done: state.files_done,
            files_hint: state.files_hint,
            bytes_out: state.bytes_out,
            current_path,
        });
    }
}

fn cancelled(cancel: Option<&AtomicBool>) -> bool {
    cancel.is_some_and(|c| c.load(Ordering::Relaxed))
}

fn is_generated(fi: &FileInfo) -> bool {
    fi.userdata.iter().rev().any(|ud| match ud {
        UserData::Tar(t) => t.isgenerated,
        UserData::Other(_) => false,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SymlinkAction {
    /// Leave dest untouched (non-Unix skip, or Skip when dest exists).
    SkipUnchanged,
    Write,
}

fn symlink_action(unix: bool, dest_exists: bool, overwrite: Overwrite) -> SymlinkAction {
    if !unix {
        return SymlinkAction::SkipUnchanged;
    }
    if dest_exists && matches!(overwrite, Overwrite::Skip) {
        return SymlinkAction::SkipUnchanged;
    }
    SymlinkAction::Write
}

fn extract_symlink(dest: &Path, target: &str, overwrite: Overwrite) -> Result<(), Error> {
    if symlink_action(cfg!(unix), dest.exists(), overwrite) == SymlinkAction::SkipUnchanged {
        return Ok(());
    }
    #[cfg(unix)]
    {
        if dest.exists() {
            std::fs::remove_file(dest).map_err(|e| map_dest_io(e, dest))?;
        }
        std::os::unix::fs::symlink(target, dest).map_err(|e| map_dest_io(e, dest))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = target;
        Ok(())
    }
}

/// Default dest layout: `dest_dir` + relative member path.
pub(crate) fn dest_path_for_member(
    dest_dir: &Path,
    member: &str,
    allow_unsafe: bool,
) -> Result<PathBuf, Error> {
    if !allow_unsafe && member_path_is_unsafe(member) {
        return Err(Error::PathEscape(member.to_string()));
    }
    if allow_unsafe {
        let p = Path::new(member);
        if p.is_absolute() {
            return Ok(p.to_path_buf());
        }
        return Ok(dest_dir.join(member.trim_start_matches(['/', '\\'])));
    }
    let rel = member.trim_start_matches('/');
    let mut out = dest_dir.to_path_buf();
    for c in Path::new(rel).components() {
        match c {
            Component::CurDir => {}
            Component::Normal(s) => out.push(s),
            Component::Prefix(_) | Component::RootDir | Component::ParentDir => {
                return Err(Error::PathEscape(member.to_string()));
            }
        }
    }
    Ok(out)
}

fn member_path_is_unsafe(member: &str) -> bool {
    if looks_windows_prefix(member) {
        return true;
    }
    let stripped = member.trim_start_matches('/');
    if looks_windows_prefix(stripped) {
        return true;
    }
    if member.starts_with("//") || member.starts_with('\\') {
        return true;
    }
    member.replace('\\', "/").split('/').any(|seg| seg == "..")
}

fn looks_windows_prefix(p: &str) -> bool {
    let b = p.as_bytes();
    b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic()
}

/// Refuse `dest_dir/a/b` when `dest_dir/a` is a symlink (tar-slip).
///
/// `File::create` and `create_dir_all` follow intermediate dest-dir
/// components, so a crafted archive (`escape` → `../outside`, then
/// `escape/pwned.txt`) would write outside `dest_dir`.
fn ensure_no_intermediate_symlink(dest_dir: &Path, dest: &Path, member: &str) -> Result<(), Error> {
    let rel = dest
        .strip_prefix(dest_dir)
        .map_err(|_| Error::PathEscape(member.to_string()))?;
    let mut cur = dest_dir.to_path_buf();
    let comps: Vec<_> = rel.components().collect();
    for (i, c) in comps.iter().enumerate() {
        let Component::Normal(s) = c else {
            return Err(Error::PathEscape(member.to_string()));
        };
        cur.push(s);
        if i + 1 == comps.len() {
            break;
        }
        if dest_is_symlink(&cur)? {
            return Err(Error::PathEscape(member.to_string()));
        }
    }
    Ok(())
}

fn dest_is_symlink(path: &Path) -> Result<bool, Error> {
    match std::fs::symlink_metadata(path) {
        Ok(m) => Ok(m.file_type().is_symlink()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(map_dest_io(e, path)),
    }
}

fn dest_exists_nofollow(path: &Path) -> Result<bool, Error> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(map_dest_io(e, path)),
    }
}

fn map_dest_io(e: io::Error, dest: &Path) -> Error {
    match e.kind() {
        io::ErrorKind::PermissionDenied => Error::NotWritable(dest.to_path_buf()),
        io::ErrorKind::NotFound => Error::NotFound,
        _ => Error::Internal(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{IndexPolicy, OpenRequest, Recreate, SourceSpec};
    use ratarmount_formats_tar::{write_tar_eof, write_ustar_members, UstarMember, UstarPayload};

    fn member_file<'a>(path: &'a str, bytes: &'a [u8]) -> UstarMember<'a> {
        UstarMember {
            path,
            payload: UstarPayload::File { bytes },
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime: 0,
        }
    }

    fn write_tar(path: &Path, members: &[UstarMember<'_>]) {
        let mut f = std::fs::File::create(path).unwrap();
        write_ustar_members(&mut f, members).unwrap();
        write_tar_eof(&mut f).unwrap();
        f.flush().unwrap();
    }

    fn open_tar(dir: &Path, name: &str, members: &[UstarMember<'_>]) -> Session {
        let tar = dir.join(name);
        write_tar(&tar, members);
        let idx = dir.join(format!("{name}.index.sqlite"));
        Session::open(OpenRequest {
            source: SourceSpec::Path(tar),
            index: IndexPolicy::Explicit,
            explicit_index: Some(idx),
            extra_dirs: Vec::new(),
            password: None,
            recursive: false,
            recursion_depth: None,
            recreate: Recreate::IfInvalid,
        })
        .expect("Session::open")
    }

    /// Regression: extract one member to disk; bytes match.
    #[test]
    fn extract_to() {
        let dir = tempfile::tempdir().unwrap();
        let payload = b"hello extract\n";
        let session = open_tar(dir.path(), "one.tar", &[member_file("hello.txt", payload)]);
        let dest = dir.path().join("out");
        session
            .extract_to(
                ExtractRequest {
                    members: vec!["/hello.txt".into()],
                    dest_dir: dest.clone(),
                    overwrite: Overwrite::Replace,
                    allow_unsafe_paths: false,
                },
                None,
                None,
            )
            .expect("extract_to");
        let got = std::fs::read(dest.join("hello.txt")).unwrap();
        assert_eq!(got, payload);
    }

    /// Regression: extract rejects `../` and absolute member paths.
    #[test]
    fn extract_to_path_escape() {
        let dir = tempfile::tempdir().unwrap();
        let session = open_tar(dir.path(), "esc.tar", &[member_file("a.txt", b"x")]);
        let dest = dir.path().join("out");
        for member in ["../evil.txt", "C:\\Windows\\x.txt", "//etc/passwd"] {
            let err = session
                .extract_to(
                    ExtractRequest {
                        members: vec![member.into()],
                        dest_dir: dest.clone(),
                        overwrite: Overwrite::Replace,
                        allow_unsafe_paths: false,
                    },
                    None,
                    None,
                )
                .unwrap_err();
            assert!(
                matches!(err, Error::PathEscape(ref s) if s == member),
                "expected PathEscape({member}), got {err:?}"
            );
            assert!(!dest.join("evil.txt").exists());
        }
        // Archive-style leading slash is dest_dir-relative, not absolute escape.
        session
            .extract_to(
                ExtractRequest {
                    members: vec!["/a.txt".into()],
                    dest_dir: dest.clone(),
                    overwrite: Overwrite::Replace,
                    allow_unsafe_paths: false,
                },
                None,
                None,
            )
            .unwrap();
        assert_eq!(std::fs::read(dest.join("a.txt")).unwrap(), b"x");
    }

    fn member_symlink<'a>(path: &'a str, target: &'a str) -> UstarMember<'a> {
        UstarMember {
            path,
            payload: UstarPayload::Symlink { target },
            mode: 0o777,
            uid: 0,
            gid: 0,
            mtime: 0,
        }
    }

    /// Regression: extract must not write through a dest-dir symlink out of dest_dir.
    ///
    /// `File::create` / `create_dir_all` follow `dest/escape` when it is a
    /// leftover (or previously extracted) symlink. Same class as a crafted
    /// archive that plants `escape` → `../outside` then `escape/pwned.txt`.
    #[cfg(unix)]
    #[test]
    fn extract_to_path_escape_via_dest_dir_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        let victim = outside.join("pwned.txt");
        let dest = dir.path().join("out");
        std::fs::create_dir_all(&dest).unwrap();
        std::os::unix::fs::symlink(&outside, dest.join("escape")).unwrap();
        let session = open_tar(
            dir.path(),
            "slip.tar",
            &[member_file("escape/pwned.txt", b"pwned")],
        );
        let err = session
            .extract_to(
                ExtractRequest {
                    members: vec!["/escape/pwned.txt".into()],
                    dest_dir: dest,
                    overwrite: Overwrite::Replace,
                    allow_unsafe_paths: false,
                },
                None,
                None,
            )
            .unwrap_err();
        assert!(
            matches!(err, Error::PathEscape(ref s) if s.contains("pwned")),
            "expected PathEscape for escape/pwned.txt, got {err:?}"
        );
        assert!(
            !victim.exists(),
            "must not write through dest-dir symlink to {}",
            victim.display()
        );
    }

    /// Two-step slip: extract a symlink-only archive, then a file under that name.
    #[cfg(unix)]
    #[test]
    fn extract_to_path_escape_via_prior_archive_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        let victim = outside.join("pwned.txt");
        let dest = dir.path().join("out");
        let link_session = open_tar(
            dir.path(),
            "link.tar",
            &[member_symlink("escape", "../outside")],
        );
        link_session
            .extract_to(
                ExtractRequest {
                    members: vec!["/escape".into()],
                    dest_dir: dest.clone(),
                    overwrite: Overwrite::Replace,
                    allow_unsafe_paths: false,
                },
                None,
                None,
            )
            .expect("extract symlink");
        assert!(
            dest.join("escape").is_symlink(),
            "first extract must plant dest/escape symlink"
        );
        let file_session = open_tar(
            dir.path(),
            "file.tar",
            &[member_file("escape/pwned.txt", b"pwned")],
        );
        let err = file_session
            .extract_to(
                ExtractRequest {
                    members: vec!["/escape/pwned.txt".into()],
                    dest_dir: dest,
                    overwrite: Overwrite::Replace,
                    allow_unsafe_paths: false,
                },
                None,
                None,
            )
            .unwrap_err();
        assert!(
            matches!(err, Error::PathEscape(_)),
            "expected PathEscape, got {err:?}"
        );
        assert!(!victim.exists(), "must not write {}", victim.display());
    }

    /// Regression: Replace must unlink a dest symlink, not follow it.
    #[cfg(unix)]
    #[test]
    fn extract_to_replace_unlinks_dest_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim.txt");
        std::fs::write(&victim, b"keep-me").unwrap();
        let session = open_tar(dir.path(), "one.tar", &[member_file("hello.txt", b"hello")]);
        let dest = dir.path().join("out");
        std::fs::create_dir_all(&dest).unwrap();
        std::os::unix::fs::symlink(&victim, dest.join("hello.txt")).unwrap();
        session
            .extract_to(
                ExtractRequest {
                    members: vec!["/hello.txt".into()],
                    dest_dir: dest.clone(),
                    overwrite: Overwrite::Replace,
                    allow_unsafe_paths: false,
                },
                None,
                None,
            )
            .expect("replace dest symlink");
        assert_eq!(std::fs::read(dest.join("hello.txt")).unwrap(), b"hello");
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep-me");
        assert!(
            !std::fs::symlink_metadata(dest.join("hello.txt"))
                .unwrap()
                .file_type()
                .is_symlink(),
            "Replace must swap the dest symlink for a regular file"
        );
    }

    /// Regression: Replace must not unlink a dest directory (or its children).
    #[test]
    fn extract_to_replace_refuses_dest_directory() {
        let dir = tempfile::tempdir().unwrap();
        let session = open_tar(dir.path(), "one.tar", &[member_file("hello.txt", b"hello")]);
        let dest = dir.path().join("out");
        let dest_dir = dest.join("hello.txt");
        std::fs::create_dir_all(&dest_dir).unwrap();
        std::fs::write(dest_dir.join("child"), b"keep").unwrap();
        let err = session
            .extract_to(
                ExtractRequest {
                    members: vec!["/hello.txt".into()],
                    dest_dir: dest.clone(),
                    overwrite: Overwrite::Replace,
                    allow_unsafe_paths: false,
                },
                None,
                None,
            )
            .unwrap_err();
        assert!(
            matches!(err, Error::Internal(ref s) if s.contains("refusing to replace directory")),
            "expected refuse-directory, got {err:?}"
        );
        assert_eq!(std::fs::read(dest_dir.join("child")).unwrap(), b"keep");
        let leftovers: Vec<_> = std::fs::read_dir(&dest)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name())
            .filter(|n| {
                n.to_string_lossy().contains(".extract-") && n.to_string_lossy().ends_with(".tmp")
            })
            .collect();
        assert!(
            leftovers.is_empty(),
            "refuse-directory must unlink tmp, leftover {leftovers:?}"
        );
    }

    /// Regression: Skip must not follow a dangling dest symlink and create the target.
    #[cfg(unix)]
    #[test]
    fn extract_to_skip_does_not_follow_dangling_dest_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim.txt");
        let session = open_tar(dir.path(), "one.tar", &[member_file("hello.txt", b"hello")]);
        let dest = dir.path().join("out");
        std::fs::create_dir_all(&dest).unwrap();
        std::os::unix::fs::symlink(&victim, dest.join("hello.txt")).unwrap();
        session
            .extract_to(
                ExtractRequest {
                    members: vec!["/hello.txt".into()],
                    dest_dir: dest.clone(),
                    overwrite: Overwrite::Skip,
                    allow_unsafe_paths: false,
                },
                None,
                None,
            )
            .expect("skip dangling dest symlink");
        assert!(
            !victim.exists(),
            "Skip must not File::create through a dangling dest symlink"
        );
        assert!(
            std::fs::symlink_metadata(dest.join("hello.txt"))
                .unwrap()
                .file_type()
                .is_symlink(),
            "dangling dest symlink must stay"
        );
    }

    #[test]
    fn ensure_no_intermediate_symlink_rejects_parent_link() {
        let dir = tempfile::tempdir().unwrap();
        let dest_dir = dir.path().join("out");
        std::fs::create_dir_all(&dest_dir).unwrap();
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        let mid = dest_dir.join("escape");
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&outside, &mid).unwrap();
            let dest = dest_dir.join("escape").join("pwned.txt");
            let err = ensure_no_intermediate_symlink(&dest_dir, &dest, "escape/pwned.txt")
                .expect_err("intermediate symlink");
            assert!(matches!(err, Error::PathEscape(ref s) if s == "escape/pwned.txt"));
        }
        #[cfg(not(unix))]
        {
            let _ = (outside, mid);
            let dest = dest_dir.join("safe").join("a.txt");
            ensure_no_intermediate_symlink(&dest_dir, &dest, "safe/a.txt")
                .expect("missing parents are ok");
        }
    }

    /// Extract-all uses catalog keyset pages, not `list_visible_files_by_offset`.
    #[test]
    fn extract_all_keyset() {
        let src = include_str!("extract.rs");
        let flatten_call = ["list_visible_files_by_", "offset("].concat();
        assert!(
            !src.contains(&flatten_call),
            "extract-all must not call the flatten API"
        );
        assert!(
            src.contains("list_extract_payload_page("),
            "extract-all must keyset-walk catalog pages"
        );

        let dir = tempfile::tempdir().unwrap();
        let session = open_tar(
            dir.path(),
            "all.tar",
            &[
                member_file("a.txt", b"aaa"),
                member_file("sub/b.txt", b"bbb"),
            ],
        );
        let dest = dir.path().join("out");
        let ticks = std::sync::atomic::AtomicU32::new(0);
        session
            .extract_to(
                ExtractRequest {
                    members: Vec::new(),
                    dest_dir: dest.clone(),
                    overwrite: Overwrite::Replace,
                    allow_unsafe_paths: false,
                },
                Some(&|_| {
                    ticks.fetch_add(1, Ordering::Relaxed);
                }),
                None,
            )
            .expect("extract-all");
        assert_eq!(std::fs::read(dest.join("a.txt")).unwrap(), b"aaa");
        assert_eq!(std::fs::read(dest.join("sub/b.txt")).unwrap(), b"bbb");
        assert!(ticks.load(Ordering::Relaxed) > 0);
    }

    #[test]
    fn extract_to_overwrite_skip_and_replace() {
        let dir = tempfile::tempdir().unwrap();
        let session = open_tar(dir.path(), "ow.tar", &[member_file("a.txt", b"new")]);
        let dest = dir.path().join("out");
        std::fs::create_dir_all(&dest).unwrap();
        std::fs::write(dest.join("a.txt"), b"old").unwrap();
        session
            .extract_to(
                ExtractRequest {
                    members: vec!["/a.txt".into()],
                    dest_dir: dest.clone(),
                    overwrite: Overwrite::Skip,
                    allow_unsafe_paths: false,
                },
                None,
                None,
            )
            .unwrap();
        assert_eq!(std::fs::read(dest.join("a.txt")).unwrap(), b"old");
        session
            .extract_to(
                ExtractRequest {
                    members: vec!["/a.txt".into()],
                    dest_dir: dest.clone(),
                    overwrite: Overwrite::Replace,
                    allow_unsafe_paths: false,
                },
                None,
                None,
            )
            .unwrap();
        assert_eq!(std::fs::read(dest.join("a.txt")).unwrap(), b"new");
    }

    #[test]
    fn extract_to_cancel() {
        let dir = tempfile::tempdir().unwrap();
        let session = open_tar(dir.path(), "c.tar", &[member_file("a.txt", b"x")]);
        let dest = dir.path().join("out");
        let cancel = AtomicBool::new(true);
        let err = session
            .extract_to(
                ExtractRequest {
                    members: vec!["/a.txt".into()],
                    dest_dir: dest,
                    overwrite: Overwrite::Replace,
                    allow_unsafe_paths: false,
                },
                None,
                Some(&cancel),
            )
            .unwrap_err();
        assert!(matches!(err, Error::Cancelled));
    }

    /// Regression: cancel mid-copy unlinks the truncated dest (Skip must not keep a tail).
    #[test]
    fn extract_to_cancel_unlinks_partial() {
        const BIG: u64 = 9 * 1024 * 1024;
        let dir = tempfile::tempdir().unwrap();
        let payload = dir.path().join("big.bin");
        {
            let f = std::fs::File::create(&payload).unwrap();
            f.set_len(BIG).unwrap();
        }
        let tar = dir.path().join("big.tar");
        {
            let mut f = std::fs::File::create(&tar).unwrap();
            write_ustar_members(
                &mut f,
                &[UstarMember {
                    path: "big.bin",
                    payload: UstarPayload::FileOnDisk {
                        path: &payload,
                        size: BIG,
                    },
                    mode: 0o644,
                    uid: 0,
                    gid: 0,
                    mtime: 0,
                }],
            )
            .unwrap();
            write_tar_eof(&mut f).unwrap();
            f.flush().unwrap();
        }
        let idx = dir.path().join("big.tar.index.sqlite");
        let session = Session::open(OpenRequest {
            source: SourceSpec::Path(tar),
            index: IndexPolicy::Explicit,
            explicit_index: Some(idx),
            extra_dirs: Vec::new(),
            password: None,
            recursive: false,
            recursion_depth: None,
            recreate: Recreate::IfInvalid,
        })
        .unwrap();
        let dest = dir.path().join("out");
        let out_file = dest.join("big.bin");
        let cancel = AtomicBool::new(false);
        let err = session
            .extract_to(
                ExtractRequest {
                    members: vec!["/big.bin".into()],
                    dest_dir: dest,
                    overwrite: Overwrite::Replace,
                    allow_unsafe_paths: false,
                },
                Some(&|p| {
                    if p.bytes_out >= PROGRESS_EVERY {
                        cancel.store(true, Ordering::Relaxed);
                    }
                }),
                Some(&cancel),
            )
            .unwrap_err();
        assert!(matches!(err, Error::Cancelled));
        assert!(
            !out_file.exists(),
            "Cancelled copy must unlink dest, got exists={}",
            out_file.exists()
        );
    }

    /// Regression: Replace + cancel must not destroy a pre-existing dest.
    ///
    /// `File::create(dest)` truncated the live file; the error path then
    /// `remove_file`d it. Cancel (or a later member read error) left the
    /// caller with neither the new bytes nor the original file.
    #[test]
    fn extract_to_replace_cancel_preserves_existing() {
        const BIG: u64 = 9 * 1024 * 1024;
        let dir = tempfile::tempdir().unwrap();
        let payload = dir.path().join("big.bin");
        {
            let f = std::fs::File::create(&payload).unwrap();
            f.set_len(BIG).unwrap();
        }
        let tar = dir.path().join("big.tar");
        {
            let mut f = std::fs::File::create(&tar).unwrap();
            write_ustar_members(
                &mut f,
                &[UstarMember {
                    path: "big.bin",
                    payload: UstarPayload::FileOnDisk {
                        path: &payload,
                        size: BIG,
                    },
                    mode: 0o644,
                    uid: 0,
                    gid: 0,
                    mtime: 0,
                }],
            )
            .unwrap();
            write_tar_eof(&mut f).unwrap();
            f.flush().unwrap();
        }
        let idx = dir.path().join("big.tar.index.sqlite");
        let session = Session::open(OpenRequest {
            source: SourceSpec::Path(tar),
            index: IndexPolicy::Explicit,
            explicit_index: Some(idx),
            extra_dirs: Vec::new(),
            password: None,
            recursive: false,
            recursion_depth: None,
            recreate: Recreate::IfInvalid,
        })
        .unwrap();
        let dest = dir.path().join("out");
        std::fs::create_dir_all(&dest).unwrap();
        let out_file = dest.join("big.bin");
        let original = b"keep-me-old-content";
        std::fs::write(&out_file, original).unwrap();
        let cancel = AtomicBool::new(false);
        let err = session
            .extract_to(
                ExtractRequest {
                    members: vec!["/big.bin".into()],
                    dest_dir: dest.clone(),
                    overwrite: Overwrite::Replace,
                    allow_unsafe_paths: false,
                },
                Some(&|p| {
                    if p.bytes_out >= PROGRESS_EVERY {
                        cancel.store(true, Ordering::Relaxed);
                    }
                }),
                Some(&cancel),
            )
            .unwrap_err();
        assert!(matches!(err, Error::Cancelled));
        assert_eq!(
            std::fs::read(&out_file).unwrap(),
            original,
            "Replace+cancel must leave the pre-existing dest intact"
        );
        let leftovers: Vec<_> = std::fs::read_dir(&dest)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name())
            .filter(|n| {
                n.to_string_lossy().contains(".extract-") && n.to_string_lossy().ends_with(".tmp")
            })
            .collect();
        assert!(
            leftovers.is_empty(),
            "cancel must unlink the extract tmp, leftover {leftovers:?}"
        );
    }

    /// Regression: Replace + cancel must not unlink a dest symlink or its victim.
    ///
    /// Pre-copy `remove_file(dest)` (#34) plus cancel would drop the symlink
    /// before persist. Tmp+rename must leave the dest dentry and victim intact.
    #[cfg(unix)]
    #[test]
    fn extract_to_replace_cancel_preserves_dest_symlink() {
        const BIG: u64 = 9 * 1024 * 1024;
        let dir = tempfile::tempdir().unwrap();
        let payload = dir.path().join("big.bin");
        {
            let f = std::fs::File::create(&payload).unwrap();
            f.set_len(BIG).unwrap();
        }
        let tar = dir.path().join("big.tar");
        {
            let mut f = std::fs::File::create(&tar).unwrap();
            write_ustar_members(
                &mut f,
                &[UstarMember {
                    path: "big.bin",
                    payload: UstarPayload::FileOnDisk {
                        path: &payload,
                        size: BIG,
                    },
                    mode: 0o644,
                    uid: 0,
                    gid: 0,
                    mtime: 0,
                }],
            )
            .unwrap();
            write_tar_eof(&mut f).unwrap();
            f.flush().unwrap();
        }
        let idx = dir.path().join("big.tar.index.sqlite");
        let session = Session::open(OpenRequest {
            source: SourceSpec::Path(tar),
            index: IndexPolicy::Explicit,
            explicit_index: Some(idx),
            extra_dirs: Vec::new(),
            password: None,
            recursive: false,
            recursion_depth: None,
            recreate: Recreate::IfInvalid,
        })
        .unwrap();
        let dest = dir.path().join("out");
        std::fs::create_dir_all(&dest).unwrap();
        let victim = dir.path().join("victim.txt");
        let original = b"keep-symlink-victim";
        std::fs::write(&victim, original).unwrap();
        let out_file = dest.join("big.bin");
        std::os::unix::fs::symlink(&victim, &out_file).unwrap();
        let cancel = AtomicBool::new(false);
        let err = session
            .extract_to(
                ExtractRequest {
                    members: vec!["/big.bin".into()],
                    dest_dir: dest.clone(),
                    overwrite: Overwrite::Replace,
                    allow_unsafe_paths: false,
                },
                Some(&|p| {
                    if p.bytes_out >= PROGRESS_EVERY {
                        cancel.store(true, Ordering::Relaxed);
                    }
                }),
                Some(&cancel),
            )
            .unwrap_err();
        assert!(matches!(err, Error::Cancelled));
        assert!(
            std::fs::symlink_metadata(&out_file)
                .unwrap()
                .file_type()
                .is_symlink(),
            "Replace+cancel must leave the dest symlink in place"
        );
        assert_eq!(
            std::fs::read(&victim).unwrap(),
            original,
            "Replace+cancel must not follow or truncate the dest symlink victim"
        );
        let leftovers: Vec<_> = std::fs::read_dir(&dest)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name())
            .filter(|n| {
                n.to_string_lossy().contains(".extract-") && n.to_string_lossy().ends_with(".tmp")
            })
            .collect();
        assert!(
            leftovers.is_empty(),
            "cancel must unlink the extract tmp, leftover {leftovers:?}"
        );
    }

    #[test]
    fn extract_symlink_replace_skips_dest_on_non_unix() {
        assert_eq!(
            symlink_action(false, true, Overwrite::Replace),
            SymlinkAction::SkipUnchanged
        );
        assert_eq!(
            symlink_action(false, false, Overwrite::Replace),
            SymlinkAction::SkipUnchanged
        );
        assert_eq!(
            symlink_action(true, true, Overwrite::Skip),
            SymlinkAction::SkipUnchanged
        );
        assert_eq!(
            symlink_action(true, true, Overwrite::Replace),
            SymlinkAction::Write
        );
        assert_eq!(
            symlink_action(true, false, Overwrite::Replace),
            SymlinkAction::Write
        );
    }

    #[test]
    fn extract_to_encrypted_7z_is_bad_password() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("encrypted-hello.7z");
        std::fs::write(
            &archive,
            include_bytes!("../../ratarmount-formats-sevenzip/testdata/encrypted-hello.7z"),
        )
        .unwrap();
        let idx = dir.path().join("encrypted-hello.7z.index.sqlite");
        let session = Session::open(OpenRequest {
            source: SourceSpec::Path(archive),
            index: IndexPolicy::Explicit,
            explicit_index: Some(idx),
            extra_dirs: Vec::new(),
            password: None,
            recursive: false,
            recursion_depth: None,
            recreate: Recreate::IfInvalid,
        })
        .expect("metadata-only 7z open");
        let dest = dir.path().join("out");
        let err = session
            .extract_to(
                ExtractRequest {
                    members: vec!["/secret.txt".into()],
                    dest_dir: dest,
                    overwrite: Overwrite::Replace,
                    allow_unsafe_paths: false,
                },
                None,
                None,
            )
            .unwrap_err();
        assert!(
            matches!(err, Error::BadPassword),
            "expected BadPassword, got {err:?}"
        );
    }
}
