//! Streaming extract (`Session::extract_to`).

use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use ratarmount_core::{is_dir_mode, is_lnk_mode, query_normpath, FileInfo, UserData};

use crate::read::fill_read;
use crate::types::{DirCursor, ExtractProgress, ExtractRequest, Overwrite};
use crate::{Error, Session};

/// Copy buffer size. Extract never slurps a member into one `Vec`.
const COPY_BUF: usize = 64 * 1024;
/// Progress / cancel check interval while copying a member.
const PROGRESS_EVERY: u64 = 8 * 1024 * 1024;
/// Extract-all catalog keyset page (not a fat flatten of the payload set).
const EXTRACT_ALL_PAGE: u32 = 1024;

const DUMPDIR_DELETE_LINKNAME: &str = "\0GNU.dumpdir.delete";

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
                    self.extract_one_named(&row.fullpath, req, progress, cancel, state)?;
                }
                if (page.len() as u32) < EXTRACT_ALL_PAGE {
                    break;
                }
                let last = page.last().expect("non-empty page");
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
        emit(progress, state, Some(member.to_string()));
        let lookup_path = query_normpath(member);
        let Some(fi) = self.mount_source().lookup(&lookup_path, 0) else {
            return Err(Error::NotFound);
        };
        if is_dumpdir(&fi) || is_generated(&fi) {
            state.files_done += 1;
            emit(progress, state, Some(member.to_string()));
            return Ok(());
        }
        if is_dir_mode(fi.mode) {
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
        if matches!(req.overwrite, Overwrite::Skip) && dest.exists() {
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
    let mut out = std::fs::File::create(dest).map_err(|e| map_dest_io(e, dest))?;
    let mut buf = [0u8; COPY_BUF];
    let mut since_progress = 0u64;
    loop {
        let n = fill_read(&mut src, &mut buf).map_err(map_member_io)?;
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
    state.files_done += 1;
    emit(progress, state, Some(member.to_string()));
    Ok(())
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

fn is_dumpdir(fi: &FileInfo) -> bool {
    fi.linkname == DUMPDIR_DELETE_LINKNAME
}

fn is_generated(fi: &FileInfo) -> bool {
    fi.userdata.iter().rev().any(|ud| match ud {
        UserData::Tar(t) => t.isgenerated,
        UserData::Other(_) => false,
    })
}

fn extract_symlink(dest: &Path, target: &str, overwrite: Overwrite) -> Result<(), Error> {
    if dest.exists() {
        match overwrite {
            Overwrite::Skip => return Ok(()),
            Overwrite::Replace => {
                std::fs::remove_file(dest).map_err(|e| map_dest_io(e, dest))?;
            }
        }
    }
    #[cfg(unix)]
    {
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

fn map_dest_io(e: io::Error, dest: &Path) -> Error {
    match e.kind() {
        io::ErrorKind::PermissionDenied => Error::NotWritable(dest.to_path_buf()),
        io::ErrorKind::NotFound => Error::NotFound,
        _ => Error::Internal(e.to_string()),
    }
}

fn map_member_io(e: io::Error) -> Error {
    match e.kind() {
        io::ErrorKind::NotFound => Error::NotFound,
        io::ErrorKind::PermissionDenied => Error::Internal(format!("permission denied: {e}")),
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
}
