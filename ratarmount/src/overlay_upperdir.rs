//! Translate a quiescent kernel overlayfs upperdir through WriteOverlay.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read};
use std::os::fd::FromRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

use clap::Args;
use ratarmount_compositing::{is_overlay_internal_path, OverlayMetadata, WriteOverlay};
use ratarmount_core::{MountSource, S_IFDIR, S_IFLNK, S_IFMT, S_IFREG};

#[derive(Debug, Args)]
pub struct ImportUpperdirArgs {
    /// Sealed lower overlays, bottom to top (the same stack used by overlayfs).
    #[arg(long, action = clap::ArgAction::Append)]
    pub lower: Vec<PathBuf>,
    /// Leave the imported overlay writable instead of sealing it.
    #[arg(long)]
    pub no_seal: bool,
    /// Stopped overlayfs upperdir, with its whiteouts and xattrs intact.
    pub upperdir: PathBuf,
    /// Must not exist, or must be an empty directory.
    pub directory: PathBuf,
    pub base: String,
}

struct Entry {
    host: PathBuf,
    meta: fs::Metadata,
    kind: Kind,
}

enum Kind {
    Directory {
        children: BTreeMap<String, Entry>,
        opaque: bool,
    },
    File,
    Symlink(String),
    Whiteout,
}

pub fn run(
    args: &ImportUpperdirArgs,
    context: &crate::base_identity::OverlayRunContext,
) -> Result<(String, i32), String> {
    use crate::overlay_import::{validate_destination, ImportStack};

    validate_destination(&args.directory)?;
    let upper = scan(&args.upperdir, "/")?;
    if !matches!(upper.kind, Kind::Directory { .. }) {
        return Err("UPPERDIR must be a directory, not a file or symlink".into());
    }
    let input = args.upperdir.canonicalize().map_err(|e| e.to_string())?;
    let output = if args.directory.exists() {
        args.directory.canonicalize()
    } else {
        args.directory
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."))
            .canonicalize()
            .map(|p| p.join(args.directory.file_name().unwrap_or_default()))
    }
    .map_err(|e| e.to_string())?;
    if input.starts_with(&output) || output.starts_with(&input) {
        return Err("UPPERDIR and NEW_OVERLAY_DIR must not contain one another".into());
    }
    let _progress = crate::diff::ProgressToStderr::new().map_err(|e| e.to_string())?;
    let stack = ImportStack::open_base(&args.base, &args.lower, false, context)?;
    validate_destination(&args.directory)?;
    if !args.directory.exists() {
        fs::create_dir(&args.directory).map_err(|e| e.to_string())?;
    }
    let result = (|| {
        let overlay = crate::overlay_create::create_overlay(
            &stack.base,
            stack.view.clone(),
            &args.directory,
            ratarmount_compositing::CreateOptions {
                lower_layers: stack.lower_layers.clone(),
                ..Default::default()
            },
            &stack.inputs,
            false,
        )
        .map_err(|e| e.to_string())?;
        apply(&upper, "/", false, &overlay, stack.view.as_ref())?;
        drop(overlay);
        let output = if args.no_seal {
            format!("imported upperdir into {}", args.directory.display())
        } else {
            ratarmount_compositing::overlay_seal::seal(&args.directory, &stack.base, stack.view)
                .map_err(|e| e.to_string())?
                .layer_digest
        };
        Ok((output, 0))
    })();
    if let Err(error) = &result {
        let _ = ratarmount_compositing::overlay_seal::unseal(&args.directory);
        if let Err(e) = fs::remove_dir_all(&args.directory) {
            return Err(format!(
                "{error}; cleanup {}: {e}",
                args.directory.display()
            ));
        }
    }
    result
}

fn child_path(parent: &str, name: &str) -> Result<String, String> {
    if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\0']) {
        return Err(format!("invalid upperdir child name: {name:?}"));
    }
    let path = format!("{}/{name}", parent.trim_end_matches('/'));
    if is_overlay_internal_path(&path) {
        return Err(format!("reserved overlay path: {path}"));
    }
    Ok(path)
}

fn scan(host: &Path, path: &str) -> Result<Entry, String> {
    let meta = fs::symlink_metadata(host).map_err(|e| format!("{}: {e}", host.display()))?;
    for prefix in ["trusted.overlay.", "user.overlay."] {
        for name in ["redirect", "metacopy"] {
            if xattr(host, &format!("{prefix}{name}"))?.is_some() {
                return Err(format!(
                    "{}: unsupported overlayfs {name}; redirect_dir and metacopy must be off",
                    host.display()
                ));
            }
        }
    }
    let kind = if meta.is_dir() {
        let mut opaque = false;
        for name in ["trusted.overlay.opaque", "user.overlay.opaque"] {
            opaque |= xattr(host, name)?.as_deref() == Some(b"y");
        }
        let mut children = BTreeMap::new();
        for child in fs::read_dir(host).map_err(|e| format!("{}: {e}", host.display()))? {
            let child = child.map_err(|e| e.to_string())?;
            let name = child.file_name().into_string().map_err(|_| {
                format!("{}: non-UTF-8 name is unsupported (EILSEQ)", host.display())
            })?;
            let mut entry = scan(&child.path(), &child_path(path, &name)?)?;
            let name = if name == ".wh..wh..opq" {
                if !matches!(entry.kind, Kind::File | Kind::Whiteout) {
                    return Err("opaque marker must be a regular file or device 0:0".into());
                }
                opaque = true;
                continue;
            } else if let Some(target) = name.strip_prefix(".wh.") {
                child_path(path, target)?;
                if !matches!(entry.kind, Kind::File | Kind::Whiteout) {
                    return Err("whiteout marker must be a regular file or device 0:0".into());
                }
                entry.kind = Kind::Whiteout;
                target.to_owned()
            } else {
                name
            };
            if children.insert(name.clone(), entry).is_some() {
                return Err(format!(
                    "{path}: conflicting upper entry and whiteout for {name}"
                ));
            }
        }
        Kind::Directory { children, opaque }
    } else if meta.file_type().is_symlink() {
        let target = fs::read_link(host).map_err(|e| e.to_string())?;
        Kind::Symlink(
            target
                .into_os_string()
                .into_string()
                .map_err(|_| format!("{path}: non-UTF-8 symlink target is unsupported (EILSEQ)"))?,
        )
    } else if meta.file_type().is_char_device() && meta.rdev() == 0 {
        Kind::Whiteout
    } else if meta.is_file() {
        // Recent overlayfs can encode whiteouts as zero-length regular files.
        if xattr(host, "user.overlay.whiteout")?.is_some()
            || xattr(host, "trusted.overlay.whiteout")?.is_some()
        {
            Kind::Whiteout
        } else {
            Kind::File
        }
    } else {
        return Err(format!("{path}: unsupported upperdir file type"));
    };
    Ok(Entry {
        host: host.into(),
        meta,
        kind,
    })
}

/// Read link metadata itself, never its target. ENOTSUP also covers marker-only copies.
fn xattr(path: &Path, name: &str) -> Result<Option<Vec<u8>>, String> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let host = CString::new(path.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    let key = CString::new(name).map_err(|e| e.to_string())?;
    let mut value = vec![0u8; 65536];
    #[cfg(target_os = "linux")]
    let n = unsafe {
        libc::lgetxattr(
            host.as_ptr(),
            key.as_ptr(),
            value.as_mut_ptr().cast(),
            value.len(),
        )
    };
    #[cfg(target_os = "macos")]
    let n = unsafe {
        libc::getxattr(
            host.as_ptr(),
            key.as_ptr(),
            value.as_mut_ptr().cast(),
            value.len(),
            0,
            libc::XATTR_NOFOLLOW,
        )
    };
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let n = {
        let _ = (host, key);
        return Err("upperdir xattr inspection is supported on Linux and macOS only".into());
    };
    if n >= 0 {
        value.truncate(n as usize);
        return Ok(Some(value));
    }
    let error = io::Error::last_os_error();
    #[cfg(target_os = "macos")]
    let absent = error.raw_os_error() == Some(libc::ENOATTR);
    #[cfg(not(target_os = "macos"))]
    let absent = error.raw_os_error() == Some(libc::ENODATA);
    if absent || error.raw_os_error() == Some(libc::ENOTSUP) {
        Ok(None)
    } else {
        Err(format!("{}: read {name}: {error}", path.display()))
    }
}

fn lower_children(lower: &dyn MountSource, path: &str) -> Result<Vec<String>, String> {
    if !lower
        .lookup(path, 0)
        .is_some_and(|fi| fi.mode & S_IFMT == S_IFDIR)
    {
        return Ok(Vec::new());
    }
    lower
        .list_dirents(path)
        .ok_or_else(|| format!("{path}: cannot list lower directory"))?
        .into_iter()
        .map(|e| child_path(path, &e.name))
        .collect()
}

fn remove_lower(overlay: &WriteOverlay, lower: &dyn MountSource, path: &str) -> Result<(), String> {
    for child in lower_children(lower, path)? {
        remove_lower(overlay, lower, &child)?;
    }
    // No host entry exists yet. unlink records a tombstone for directories too,
    // including an absent whiteout target, without following lower symlinks.
    overlay.unlink(path).map_err(|e| format!("{path}: {e}"))
}

fn apply(
    entry: &Entry,
    path: &str,
    inherited_opaque: bool,
    overlay: &WriteOverlay,
    lower: &dyn MountSource,
) -> Result<(), String> {
    if matches!(entry.kind, Kind::Whiteout) {
        return remove_lower(overlay, lower, path);
    }
    let kind = match entry.kind {
        Kind::Directory { .. } => S_IFDIR,
        Kind::Symlink(_) => S_IFLNK,
        _ => S_IFREG,
    };
    if path != "/"
        && lower
            .lookup(path, 0)
            .is_some_and(|fi| fi.mode & S_IFMT != kind)
    {
        remove_lower(overlay, lower, path)?;
    }
    match &entry.kind {
        Kind::Directory { children, opaque } => {
            if path != "/" {
                overlay
                    .mkdir(path, 0o700)
                    .map_err(|e| format!("{path}: {e}"))?;
            }
            let opaque = inherited_opaque || *opaque;
            if opaque {
                for child in lower_children(lower, path)? {
                    let name = child.rsplit('/').next().expect("child name");
                    if !children.contains_key(name) {
                        remove_lower(overlay, lower, &child)?;
                    }
                }
            }
            for (name, child) in children {
                apply(child, &child_path(path, name)?, opaque, overlay, lower)?;
            }
        }
        Kind::Symlink(target) => {
            if overlay.lookup(path, 0).is_some() {
                overlay.unlink(path).map_err(|e| e.to_string())?;
            }
            overlay
                .create_symlink(path, target)
                .map_err(|e| format!("{path}: {e}"))?;
        }
        Kind::File => {
            // Admitted (R10-FIX3): an upperdir file that is another name of
            // an open overlay database (the destination's) is refused without
            // a descriptor of it being closed.
            let mut input = ratarmount_core::db_inodes::open_admitted(
                &entry.host,
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
                0,
            )
            .map(fs::File::from)
            .map_err(|e| format!("{path}: {e}"))?;
            let current = input.metadata().map_err(|e| e.to_string())?;
            if !current.is_file()
                || (current.dev(), current.ino()) != (entry.meta.dev(), entry.meta.ino())
            {
                return Err(format!(
                    "{path}: upperdir changed during import; unmount it first"
                ));
            }
            let fd = overlay
                .create_file(path, 0o600)
                .map_err(|e| format!("{path}: {e}"))?;
            let file = unsafe { fs::File::from_raw_fd(fd) };
            let copied = (|| {
                let mut buffer = vec![0u8; 128 * 1024];
                let mut offset = 0;
                loop {
                    let n = input.read(&mut buffer)?;
                    if n == 0 {
                        break;
                    }
                    overlay.write_all_at(&file, path, offset, &buffer[..n])?;
                    offset += n as u64;
                }
                Ok::<_, io::Error>(())
            })();
            overlay.finish_owned_write_fd(file);
            copied.map_err(|e| format!("{path}: {e}"))?;
        }
        Kind::Whiteout => unreachable!(),
    }
    // Apply directory attributes after children, so mkdir/write cannot change
    // the recorded mtime or make a restrictive directory block its own import.
    overlay
        .set_metadata(
            path,
            &OverlayMetadata {
                mode: (kind != S_IFLNK).then_some(entry.meta.mode() & 0o7777),
                mtime: Some(entry.meta.mtime() as f64 + entry.meta.mtime_nsec() as f64 / 1e9),
                ..Default::default()
            },
        )
        .map_err(|e| format!("{path}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratarmount_compositing::{
        FolderMountSource, Immutability, OverlayMeta, ReadOnlyOverlayLayer,
    };
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::sync::Arc;

    struct Fixture {
        root: tempfile::TempDir,
        base: PathBuf,
        upper: PathBuf,
        dest: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let base = root.path().join("base");
            let upper = root.path().join("upper");
            let dest = root.path().join("imported");
            fs::create_dir(&base).unwrap();
            fs::create_dir(&upper).unwrap();
            Self {
                root,
                base,
                upper,
                dest,
            }
        }

        fn args(&self) -> ImportUpperdirArgs {
            ImportUpperdirArgs {
                lower: Vec::new(),
                no_seal: true,
                upperdir: self.upper.clone(),
                directory: self.dest.clone(),
                base: self.base.to_str().unwrap().into(),
            }
        }

        fn source(&self) -> Arc<dyn MountSource> {
            Arc::new(FolderMountSource::new(&self.base).unwrap())
        }

        fn import(&self) -> ReadOnlyOverlayLayer {
            run(&self.args(), &Default::default()).unwrap();
            ReadOnlyOverlayLayer::new(self.source(), &self.dest, Immutability::Shared).unwrap()
        }
    }

    fn bytes(source: &dyn MountSource, path: &str) -> Vec<u8> {
        let fi = source.lookup(path, 0).unwrap();
        let mut data = Vec::new();
        source
            .open(&fi, libc::O_RDONLY)
            .unwrap()
            .read_to_end(&mut data)
            .unwrap();
        data
    }

    /// Regression: whiteout markers leaked as files and lower directories kept descendants.
    #[test]
    fn regression_upperdir_whiteouts_hide_files_and_directory_descendants() {
        let f = Fixture::new();
        fs::write(f.base.join("deleted"), b"old").unwrap();
        fs::create_dir_all(f.base.join("gone/sub")).unwrap();
        fs::write(f.base.join("gone/sub/file"), b"old").unwrap();
        for marker in [".wh.deleted", ".wh.gone", ".wh.absent"] {
            fs::write(f.upper.join(marker), b"").unwrap();
        }
        fs::write(f.upper.join("added"), b"new").unwrap();
        let view = f.import();
        for path in [
            "/deleted",
            "/gone",
            "/gone/sub",
            "/gone/sub/file",
            "/absent",
            "/.wh.deleted",
        ] {
            assert!(view.lookup(path, 0).is_none(), "{path}");
        }
        assert_eq!(bytes(&view, "/added"), b"new");
        assert_eq!(view.list_dirents("/").unwrap().len(), 1);
        let db =
            rusqlite::Connection::open(f.dest.join(ratarmount_compositing::HIDDEN_DB)).unwrap();
        let deleted: usize = db
            .query_row("SELECT count(*) FROM files WHERE deleted=1", [], |r| {
                r.get(0)
            })
            .unwrap();
        // WriteOverlay drops tombstones of nonexistent targets ("absent").
        assert_eq!(deleted, 4);
    }

    /// Regression (R10-FIX3, r10 review): an upperdir file that is a hard
    /// link of an overlay database open in this process was read through a
    /// plain open and closed, releasing the holder's locks. The admitted
    /// open refuses it: the import fails naming the database, and another
    /// process is still busy on the holder's lock.
    #[test]
    fn regression_upperdir_input_refuses_a_db_alias() {
        let f = Fixture::new();
        let db = f.root.path().join("held.sqlite");
        rusqlite::Connection::open(&db)
            .unwrap()
            .execute_batch("CREATE TABLE files (x)")
            .unwrap();
        fs::hard_link(&db, f.upper.join("payload")).unwrap();
        let holder = ratarmount_compositing::open_overlay_db(
            &db,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
            ratarmount_compositing::DbName::Path,
        )
        .unwrap();
        holder.execute_batch("BEGIN IMMEDIATE").unwrap();
        let error = run(&f.args(), &Default::default()).unwrap_err();
        assert!(error.contains("open overlay database"), "{error}");
        assert!(
            crate::overlay_pack::tests::pack_db_lock_busy_in_child(&db),
            "the import released the holder's lock"
        );
        holder
            .execute_batch("INSERT INTO files VALUES (1); COMMIT")
            .unwrap();
    }

    /// Regression: an opaque parent must also suppress lower grandchildren under retained directories.
    #[test]
    fn regression_upperdir_opaque_hides_lower_children_recursively() {
        let f = Fixture::new();
        for dir in ["opaque/kept/deep", "opaque/removed/sub", "merge"] {
            fs::create_dir_all(f.base.join(dir)).unwrap();
        }
        for file in [
            "opaque/kept/deep/old",
            "opaque/kept/old",
            "opaque/removed/sub/old",
            "merge/old",
        ] {
            fs::write(f.base.join(file), b"lower").unwrap();
        }
        fs::create_dir_all(f.upper.join("opaque/kept/deep")).unwrap();
        fs::create_dir(f.upper.join("merge")).unwrap();
        fs::write(f.upper.join("opaque/.wh..wh..opq"), b"").unwrap();
        fs::write(f.upper.join("opaque/kept/deep/new"), b"upper").unwrap();
        fs::write(f.upper.join("merge/new"), b"upper").unwrap();
        let view = f.import();
        for file in [
            "/opaque/kept/deep/old",
            "/opaque/kept/old",
            "/opaque/removed/sub/old",
            "/opaque/removed",
        ] {
            assert!(view.lookup(file, 0).is_none(), "{file}");
        }
        assert_eq!(bytes(&view, "/opaque/kept/deep/new"), b"upper");
        assert_eq!(bytes(&view, "/merge/old"), b"lower");
        assert_eq!(bytes(&view, "/merge/new"), b"upper");
        assert!(view.lookup("/opaque/.wh..wh..opq", 0).is_none());
    }

    /// Regression: opaque root markers must hide root entries without tombstoning the root.
    #[test]
    fn regression_upperdir_opaque_root_and_type_replacements() {
        let f = Fixture::new();
        fs::create_dir_all(f.base.join("to-file/sub")).unwrap();
        fs::write(f.base.join("to-file/sub/old"), b"old").unwrap();
        fs::write(f.base.join("to-dir"), b"old").unwrap();
        fs::write(f.base.join("hidden"), b"old").unwrap();
        symlink("hidden", f.base.join("to-link")).unwrap();
        fs::write(f.upper.join(".wh..wh..opq"), b"").unwrap();
        fs::write(f.upper.join("to-file"), b"replacement").unwrap();
        fs::create_dir(f.upper.join("to-dir")).unwrap();
        fs::write(f.upper.join("to-dir/new"), b"new").unwrap();
        symlink("../../outside", f.upper.join("to-link")).unwrap();
        let view = f.import();
        assert_eq!(bytes(&view, "/to-file"), b"replacement");
        assert!(view.lookup("/to-file/sub/old", 0).is_none());
        assert_eq!(bytes(&view, "/to-dir/new"), b"new");
        assert!(view.lookup("/hidden", 0).is_none());
        assert_eq!(
            view.lookup("/to-link", 0).unwrap().linkname,
            "../../outside"
        );
    }

    /// Regression: import followed symlink targets and lost modes or directory/symlink mtimes.
    #[test]
    fn regression_upperdir_preserves_metadata_without_following_symlinks() {
        let f = Fixture::new();
        let outside = f.root.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("untouched"), b"outside").unwrap();
        fs::create_dir(f.upper.join("dir")).unwrap();
        fs::write(f.upper.join("dir/file"), b"payload").unwrap();
        symlink(&outside, f.upper.join("link")).unwrap();
        let time = 1_234_567_890.25;
        for (path, mode) in [
            ("/dir/file", Some(0o751)),
            ("/dir", Some(0o750)),
            ("/link", None),
        ] {
            use std::ffi::CString;
            use std::os::unix::ffi::OsStrExt;
            let host = f.upper.join(path.trim_start_matches('/'));
            if let Some(mode) = mode {
                fs::set_permissions(&host, fs::Permissions::from_mode(mode)).unwrap();
            }
            let host = CString::new(host.as_os_str().as_bytes()).unwrap();
            let times = [libc::timespec {
                tv_sec: 1_234_567_890,
                tv_nsec: 250_000_000,
            }; 2];
            assert_eq!(
                unsafe {
                    libc::utimensat(
                        libc::AT_FDCWD,
                        host.as_ptr(),
                        times.as_ptr(),
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                },
                0
            );
        }
        let view = f.import();
        assert_eq!(view.lookup("/dir/file", 0).unwrap().mode & 0o7777, 0o751);
        assert_eq!(view.lookup("/dir", 0).unwrap().mode & 0o7777, 0o750);
        for path in ["/dir/file", "/dir", "/link"] {
            assert_eq!(view.lookup(path, 0).unwrap().mtime, time, "{path}");
        }
        assert_eq!(
            view.lookup("/link", 0).unwrap().linkname,
            outside.to_str().unwrap()
        );
        assert_eq!(fs::read(outside.join("untouched")).unwrap(), b"outside");
        assert!(fs::symlink_metadata(f.dest.join("link"))
            .unwrap()
            .file_type()
            .is_symlink());
    }

    /// Regression: an upperdir import must seal by default and use the composed lower stack.
    #[test]
    fn regression_upperdir_seals_and_records_lower_stack_identity() {
        let f = Fixture::new();
        let lower = f.root.path().join("lower");
        let writer = crate::base_identity::fixtures::new_overlay(f.source(), &lower).unwrap();
        drop(writer);
        fs::write(lower.join("lower-only"), b"prepared").unwrap();
        ratarmount_compositing::overlay_fsck::fsck(&lower, true).unwrap();
        let seal = crate::base_identity::fixtures::seal(&lower, f.source()).unwrap();
        fs::write(f.upper.join(".wh.lower-only"), b"").unwrap();
        let mut args = f.args();
        args.lower = vec![lower.clone()];
        args.no_seal = false;
        run(&args, &Default::default()).unwrap();
        let meta = OverlayMeta::read(&f.dest).unwrap().unwrap();
        assert!(meta.layer_sealed());
        assert_eq!(
            meta.lower_layers().unwrap()[0].layer_digest,
            seal.layer_digest
        );
        let stack = ReadOnlyOverlayLayer::new(f.source(), &lower, Immutability::Immutable).unwrap();
        let view =
            ReadOnlyOverlayLayer::new(Arc::new(stack), &f.dest, Immutability::Immutable).unwrap();
        assert!(view.lookup("/lower-only", 0).is_none());
        drop(view);
        ratarmount_compositing::overlay_seal::unseal(&f.dest).unwrap();
        ratarmount_compositing::overlay_seal::unseal(&lower).unwrap();
    }

    /// Regression: malformed marker paths or a symlink upper root could escape the import tree.
    #[test]
    fn regression_upperdir_refuses_unsafe_markers_and_destinations() {
        for marker in [".wh.", ".wh..", ".wh...", ".wh..ratarmount.overlay.sqlite"] {
            let f = Fixture::new();
            fs::write(f.upper.join(marker), b"").unwrap();
            assert!(run(&f.args(), &Default::default()).is_err(), "{marker}");
            assert!(!f.dest.exists());
        }
        let f = Fixture::new();
        let mut args = f.args();
        args.directory = f.upper.join("output");
        assert!(run(&args, &Default::default())
            .unwrap_err()
            .contains("contain one another"));
        fs::write(f.dest.clone(), b"keep").unwrap();
        assert!(run(&f.args(), &Default::default()).is_err());
        assert_eq!(fs::read(&f.dest).unwrap(), b"keep");
        fs::remove_file(&f.dest).unwrap();
        args = f.args();
        let link = f.root.path().join("link");
        symlink(&f.upper, &link).unwrap();
        args.upperdir = link;
        assert!(run(&args, &Default::default())
            .unwrap_err()
            .contains("UPPERDIR must be a directory"));
    }

    /// Regression: special files could block import and non-UTF-8 paths were lossy.
    #[test]
    fn regression_upperdir_refuses_special_files_and_non_utf8() {
        use std::ffi::{CString, OsString};
        use std::os::unix::ffi::{OsStrExt, OsStringExt};
        let f = Fixture::new();
        let fifo = f.upper.join("fifo");
        let path = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        assert!(run(&f.args(), &Default::default())
            .unwrap_err()
            .contains("unsupported upperdir file type"));
        fs::remove_file(fifo).unwrap();
        let path = f.upper.join(OsString::from_vec(b"bad\xff".to_vec()));
        match fs::write(&path, b"data") {
            Ok(()) => {
                assert!(run(&f.args(), &Default::default())
                    .unwrap_err()
                    .contains("EILSEQ"));
                fs::remove_file(path).unwrap();
            }
            // APFS refuses non-UTF-8 names itself; symlink targets still work.
            Err(e) if e.raw_os_error() == Some(libc::EILSEQ) => {
                eprintln!("skip: filesystem rejects non-UTF-8 file names");
            }
            Err(e) => panic!("{e}"),
        }
        symlink(
            OsString::from_vec(b"target\xff".to_vec()),
            f.upper.join("link"),
        )
        .unwrap();
        assert!(run(&f.args(), &Default::default())
            .unwrap_err()
            .contains("EILSEQ"));
        assert!(!f.dest.exists());
    }

    /// Regression: streaming upperdir copies must keep bytes after the first buffer.
    #[test]
    fn regression_upperdir_large_file_stream_is_not_truncated() {
        let f = Fixture::new();
        let payload: Vec<_> = (0..400_000).map(|i| (i % 251) as u8).collect();
        fs::write(f.upper.join("large"), &payload).unwrap();
        assert_eq!(bytes(&f.import(), "/large"), payload);
    }

    #[cfg(target_os = "linux")]
    fn set_xattr(path: &Path, name: &str, value: &[u8]) -> bool {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        let name = CString::new(name).unwrap();
        let n = unsafe {
            libc::setxattr(
                path.as_ptr(),
                name.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
            )
        };
        if n == 0 {
            return true;
        }
        let e = io::Error::last_os_error();
        if matches!(
            e.raw_os_error(),
            Some(libc::ENOTSUP | libc::EPERM | libc::EACCES)
        ) {
            eprintln!("skip: upperdir xattr fixture unavailable: {e}");
            return false;
        }
        panic!("setxattr: {e}");
    }

    /// Regression: redirect/metacopy xattrs were silently imported as complete data.
    #[cfg(target_os = "linux")]
    #[test]
    fn regression_upperdir_refuses_redirect_and_metacopy() {
        for attr in ["user.overlay.redirect", "user.overlay.metacopy"] {
            let f = Fixture::new();
            fs::write(f.upper.join("file"), b"").unwrap();
            if !set_xattr(&f.upper.join("file"), attr, b"") {
                return;
            }
            let error = run(&f.args(), &Default::default()).unwrap_err();
            assert!(
                error.contains("redirect_dir and metacopy must be off"),
                "{error}"
            );
            assert!(!f.dest.exists());
        }
    }

    /// Regression: userxattr opaque directories and xattr whiteouts leaked lower content.
    #[cfg(target_os = "linux")]
    #[test]
    fn regression_upperdir_userxattr_opaque_and_whiteout() {
        let f = Fixture::new();
        fs::write(f.base.join("hidden"), b"old").unwrap();
        fs::write(f.base.join("deleted"), b"old").unwrap();
        fs::write(f.upper.join("deleted"), b"").unwrap();
        if !set_xattr(&f.upper, "user.overlay.opaque", b"y")
            || !set_xattr(&f.upper.join("deleted"), "user.overlay.whiteout", b"")
        {
            return;
        }
        let view = f.import();
        assert!(view.lookup("/hidden", 0).is_none());
        assert!(view.lookup("/deleted", 0).is_none());
    }

    /// Regression: device 0:0 whiteouts must become tombstones, never copied device nodes.
    #[cfg(target_os = "linux")]
    #[test]
    fn regression_upperdir_device_whiteout_or_explicit_skip() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let f = Fixture::new();
        fs::write(f.base.join("deleted"), b"old").unwrap();
        let path = CString::new(f.upper.join("deleted").as_os_str().as_bytes()).unwrap();
        if unsafe { libc::mknod(path.as_ptr(), libc::S_IFCHR | 0o600, 0) } != 0 {
            let e = io::Error::last_os_error();
            if matches!(e.raw_os_error(), Some(libc::EPERM | libc::EACCES)) {
                eprintln!("skip: mknod device 0:0 requires privileges: {e}");
                return;
            }
            panic!("mknod: {e}");
        }
        assert!(f.import().lookup("/deleted", 0).is_none());
    }

    /// Regression: clap must keep all three upperdir import positionals intact.
    #[test]
    fn regression_upperdir_cli_positionals() {
        let args = crate::parse_args_from([
            "ratarmount",
            "overlay",
            "import-upperdir",
            "--lower",
            "prepared",
            "--no-seal",
            "upper",
            "output",
            "base",
        ])
        .unwrap();
        assert!(args.paths.is_empty());
        let crate::overlay_cmd::OverlayCommand::ImportUpperdir(import) =
            args.overlay.unwrap().command
        else {
            panic!("wrong command");
        };
        assert_eq!(import.lower, [PathBuf::from("prepared")]);
        assert_eq!(import.upperdir, Path::new("upper"));
        assert_eq!(import.directory, Path::new("output"));
        assert_eq!(import.base, "base");
        assert!(import.no_seal);
    }
}
