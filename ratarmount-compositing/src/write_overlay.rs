//! Write overlay: redirect creates/writes/deletes to a host folder.
//! Mirrors Python `WritableFolderMountSource` (subset) + `commit_overlay`.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, File, OpenOptions as FsOpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::FromRawFd;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};

use bzip2::write::BzEncoder;
use flate2::write::GzEncoder;
use flate2::Compression as GzCompression;
use ratarmount_compress::{
    body_looks_like_tar, decode_zstd_frames_to, detect_compression, materialize,
    open_seekable_zstd, scan_zstd_frames_path, splice_zstd_last_frames_replace, CompressionFormat,
    ZstdFrameMap, DEFAULT_MEMORY_CAP,
};
use ratarmount_core::{
    create_root_file_info, normpath, CheapDirent, FileInfo, ListModeResult, ListResult,
    MountSource, UserData,
};
use ratarmount_formats_tar::{
    find_last_tar_eof, rewrite_tar_suffix, window_has_member_boundary, RewriteTarSuffix,
    UstarMember, UstarPayload,
};
use rusqlite::{params, Connection, OpenFlags};
use thiserror::Error;
use xz2::write::XzEncoder;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

pub const HIDDEN_DB: &str = ".ratarmount.overlay.sqlite";

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS "files" (
    "path"    VARCHAR(65535) NOT NULL,
    "name"    VARCHAR(65535) NOT NULL,
    "mtime"   REAL,
    "mode"    INTEGER,
    "uid"     INTEGER,
    "gid"     INTEGER,
    "deleted" BOOL,
    PRIMARY KEY (path, name)
);
"#;

#[derive(Debug, Error)]
pub enum OverlayError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error("{0}")]
    Msg(String),
}

pub type Result<T> = std::result::Result<T, OverlayError>;

/// Union of a read-only base with a writable overlay folder + deletion DB.
pub struct WriteOverlay {
    base: Arc<dyn MountSource>,
    /// After a live TAR commit, the reopened archive.
    replacement: RwLock<Option<Arc<dyn MountSource>>>,
    root: PathBuf,
    db: Mutex<Connection>,
    /// Writers take a read lock; live commit takes the write lock.
    commit_gate: RwLock<()>,
    /// Set when persist succeeded but reopen failed (K11). Further interval
    /// ticks must not persist again (overlay still holds the committed names).
    interval_disabled: AtomicBool,
    /// Bumped after every successful commit persist. Cached FileInfos /
    /// reader handles keyed to pre-commit base offsets are invalid after a
    /// commit (delete/replace shift TAR member offsets), so read caches
    /// (NFS reader LRU, inode FileInfo) watch this counter.
    commit_generation: std::sync::atomic::AtomicU64,
    /// Overlay FDs still open for write (FUSE keeps the fd until release).
    /// Interval settle must not persist/unlink these: later pwrite would hit
    /// an unlinked inode and the extra bytes would never reach the archive.
    write_fds: Mutex<HashMap<i32, String>>,
}

impl WriteOverlay {
    pub fn new(base: Arc<dyn MountSource>, overlay: impl AsRef<Path>) -> Result<Self> {
        let root = overlay.as_ref().to_path_buf();
        if root.exists() {
            if !root.is_dir() {
                return Err(OverlayError::Msg(format!(
                    "overlay path must be a folder: {}",
                    root.display()
                )));
            }
        } else {
            fs::create_dir_all(&root)?;
        }
        // Canonical root so confinement checks use a stable absolute prefix.
        let root = root.canonicalize().map_err(OverlayError::Io)?;
        let db_path = root.join(HIDDEN_DB);
        let conn = Connection::open(&db_path)?;
        conn.execute_batch("PRAGMA LOCKING_MODE = EXCLUSIVE;")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self {
            base,
            replacement: RwLock::new(None),
            root,
            db: Mutex::new(conn),
            commit_gate: RwLock::new(()),
            interval_disabled: AtomicBool::new(false),
            commit_generation: std::sync::atomic::AtomicU64::new(0),
            write_fds: Mutex::new(HashMap::new()),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// True after persist-ok + reopen-err; further interval ticks must remount.
    pub fn interval_disabled(&self) -> bool {
        self.interval_disabled.load(Ordering::SeqCst)
    }

    fn current_base(&self) -> Arc<dyn MountSource> {
        self.replacement
            .read()
            .expect("overlay replacement")
            .clone()
            .unwrap_or_else(|| Arc::clone(&self.base))
    }

    /// Swap the archive view after a successful live commit (interval).
    pub fn replace_base(&self, new_base: Arc<dyn MountSource>) {
        *self.replacement.write().expect("overlay replacement") = Some(new_base);
    }

    fn realpath(&self, path: &str) -> PathBuf {
        let path = normpath(path);
        if path == "/" {
            return self.root.clone();
        }
        self.root.join(path.trim_start_matches('/'))
    }

    /// Ensure a host path under the overlay cannot escape the overlay root via
    /// intermediate or final-component symlinks (`libc::open` follows by default).
    ///
    /// - Final component that is a symlink → PermissionDenied (O_NOFOLLOW policy).
    /// - Resolved parent/path must stay under the canonical overlay root.
    fn ensure_under_root(&self, host_path: &Path) -> io::Result<()> {
        let root = &self.root;

        match fs::symlink_metadata(host_path) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "overlay refuses to follow symlink at {}",
                        host_path.display()
                    ),
                ));
            }
            Ok(_) => {
                let canon = fs::canonicalize(host_path)?;
                if !path_is_under(root, &canon) {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!(
                            "overlay path escapes overlay root: {} not under {}",
                            canon.display(),
                            root.display()
                        ),
                    ));
                }
                return Ok(());
            }
            Err(_) => {
                // Path missing: walk up to an existing ancestor and verify it.
            }
        }

        let mut ancestor = host_path.to_path_buf();
        while ancestor.pop() {
            match fs::symlink_metadata(&ancestor) {
                Ok(meta) if meta.file_type().is_symlink() => {
                    // Intermediate symlink: resolve and require confinement.
                    let canon = fs::canonicalize(&ancestor).map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            format!(
                                "overlay parent symlink not confinable ({}): {e}",
                                ancestor.display()
                            ),
                        )
                    })?;
                    if !path_is_under(root, &canon) {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            format!(
                                "overlay parent symlink escapes overlay root: {} → {}",
                                ancestor.display(),
                                canon.display()
                            ),
                        ));
                    }
                    return Ok(());
                }
                Ok(_) => {
                    let canon = fs::canonicalize(&ancestor)?;
                    if !path_is_under(root, &canon) {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            format!(
                                "overlay path escapes overlay root: {} not under {}",
                                canon.display(),
                                root.display()
                            ),
                        ));
                    }
                    return Ok(());
                }
                Err(_) => continue,
            }
        }

        // No existing ancestor found — joined path must still be under root by construction.
        if path_is_under(root, host_path) {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "overlay path escapes overlay root: {} not under {}",
                    host_path.display(),
                    root.display()
                ),
            ))
        }
    }

    fn split(path: &str) -> (String, String) {
        let path = normpath(path);
        if path == "/" {
            return (String::new(), String::new());
        }
        match path.rsplit_once('/') {
            Some(("", name)) => (String::new(), name.to_string()),
            Some((dir, name)) => (dir.to_string(), name.to_string()),
            None => (String::new(), path),
        }
    }

    pub fn is_deleted(&self, path: &str) -> bool {
        let (folder, name) = Self::split(path);
        let db = self.db.lock().expect("overlay db");
        db.query_row(
            r#"SELECT COUNT(*) > 0 FROM "files" WHERE path = ?1 AND name = ?2 AND deleted = 1"#,
            params![folder, name],
            |r| r.get::<_, i64>(0),
        )
        .map(|n| n != 0)
        .unwrap_or(false)
    }

    pub fn list_deleted(&self, path: &str) -> Vec<String> {
        let path = normpath(path).trim_end_matches('/').to_string();
        let db = self.db.lock().expect("overlay db");
        let mut stmt =
            match db.prepare(r#"SELECT name FROM "files" WHERE path = ?1 AND deleted = 1"#) {
                Ok(s) => s,
                Err(_) => return vec![HIDDEN_DB.to_string()],
            };
        let rows = stmt
            .query_map(params![path], |r| r.get::<_, String>(0))
            .into_iter()
            .flatten()
            .filter_map(|r| r.ok());
        let mut out: Vec<String> = rows.collect();
        // Hide overlay DB and SQLite sidecars
        for suf in ["", "-journal", "-shm", "-wal"] {
            out.push(format!("{HIDDEN_DB}{suf}"));
        }
        out
    }

    fn mark_deleted(&self, path: &str) -> Result<()> {
        let (folder, name) = Self::split(path);
        let db = self.db.lock().expect("overlay db");
        if self.current_base().exists(path) {
            db.execute(
                r#"INSERT OR REPLACE INTO "files" (path,name,deleted) VALUES (?1,?2,1)"#,
                params![folder, name],
            )?;
        } else {
            db.execute(
                r#"DELETE FROM "files" WHERE path = ?1 AND name = ?2"#,
                params![folder, name],
            )?;
        }
        Ok(())
    }

    fn mark_present(&self, path: &str, mode: u32) -> Result<()> {
        let (folder, name) = Self::split(path);
        let db = self.db.lock().expect("overlay db");
        db.execute(
            r#"INSERT OR IGNORE INTO "files" (path,name,mode,deleted) VALUES (?1,?2,?3,0)"#,
            params![folder, name, mode as i64],
        )?;
        db.execute(
            r#"UPDATE "files" SET deleted = 0 WHERE path = ?1 AND name = ?2"#,
            params![folder, name],
        )?;
        Ok(())
    }

    fn ensure_parent(&self, path: &str) -> Result<()> {
        let (parent, _) = Self::split(path);
        if parent.is_empty() || parent == "/" {
            return Ok(());
        }
        let real_parent = self.realpath(&parent);
        self.ensure_under_root(&real_parent)?;
        if !real_parent.exists() && self.current_base().is_dir(&parent) {
            fs::create_dir_all(&real_parent)?;
        }
        Ok(())
    }

    /// Copy base file into overlay (COW) if not already present.
    pub fn ensure_modifiable(&self, path: &str) -> Result<()> {
        self.ensure_parent(path)?;
        let real = self.realpath(path);
        self.ensure_under_root(&real)?;
        // Use symlink_metadata so a planted escape symlink is not treated as "present".
        if fs::symlink_metadata(&real).is_ok() {
            // Existing entry must stay under root (final symlink already rejected).
            return Ok(());
        }
        let Some(fi) = self.current_base().lookup(path, 0) else {
            // New file: just ensure parent
            return Ok(());
        };
        if fi.mode & ratarmount_core::S_IFMT == ratarmount_core::S_IFDIR {
            fs::create_dir_all(&real)?;
            return Ok(());
        }
        if fi.mode & ratarmount_core::S_IFMT == ratarmount_core::S_IFLNK {
            // COW a symlink as a symlink: archive symlinks carry no content,
            // so copying the body would materialize an empty regular file and
            // a later commit would drop the link member entirely.
            if let Some(parent) = real.parent() {
                fs::create_dir_all(parent)?;
            }
            std::os::unix::fs::symlink(&fi.linkname, &real)?;
            return Ok(());
        }
        let mut src = self.current_base().open(&fi, 0)?;
        let mut dst = FsOpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&real)?;
        io::copy(&mut src, &mut dst)?;
        Ok(())
    }

    /// True when the overlay root has a real file (or symlink) for this path.
    pub fn has_file(&self, path: &str) -> bool {
        let real = self.realpath(path);
        real.is_file() || real.is_symlink()
    }

    pub fn create_file(&self, path: &str, mode: u32) -> Result<i32> {
        let _gate = self.commit_gate.read().expect("overlay commit gate");
        let fd = self.create_file_inner(path, mode)?;
        self.register_write_fd(fd, path);
        Ok(fd)
    }

    fn register_write_fd(&self, fd: i32, path: &str) {
        self.write_fds
            .lock()
            .expect("overlay write fds")
            .insert(fd, normpath(path));
    }

    /// Drop the write-open pin without closing `fd` (caller already closed it).
    pub fn release_write_fd(&self, fd: i32) {
        self.write_fds
            .lock()
            .expect("overlay write fds")
            .remove(&fd);
    }

    /// Unregister a write-open pin and close `fd` (FUSE release / NFS create).
    pub fn close_overlay_fd(&self, fd: i32) {
        self.release_write_fd(fd);
        let _ = unsafe { File::from_raw_fd(fd) };
    }

    fn write_open_hosts(&self) -> HashSet<PathBuf> {
        self.write_fds
            .lock()
            .expect("overlay write fds")
            .values()
            .map(|p| self.realpath(p))
            .collect()
    }

    fn create_file_inner(&self, path: &str, mode: u32) -> Result<i32> {
        self.ensure_parent(path)?;
        let real = self.realpath(path);
        self.ensure_under_root(&real)?;
        if let Some(parent) = real.parent() {
            self.ensure_under_root(parent)?;
            fs::create_dir_all(parent)?;
        }
        let f = FsOpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode & 0o7777)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&real)?;
        let fd = {
            use std::os::unix::io::IntoRawFd;
            f.into_raw_fd()
        };
        self.mark_present(path, mode | ratarmount_core::S_IFREG)?;
        Ok(fd)
    }

    pub fn open_overlay_fd(&self, path: &str, flags: i32) -> Result<i32> {
        let _gate = self.commit_gate.read().expect("overlay commit gate");
        self.ensure_modifiable(path)?;
        let real = self.realpath(path);
        self.ensure_under_root(&real)?;
        // If still missing and write flags, create empty
        if fs::symlink_metadata(&real).is_err()
            && (flags & (libc::O_WRONLY | libc::O_RDWR | libc::O_CREAT)) != 0
        {
            self.create_file_inner(path, 0o644)?;
        }
        if fs::symlink_metadata(&real).is_err() {
            return Err(OverlayError::Io(io::Error::new(
                io::ErrorKind::NotFound,
                format!("no overlay file at {}", real.display()),
            )));
        }
        // Never follow host symlinks out of the overlay folder.
        let flags = flags | libc::O_NOFOLLOW;
        let fd = unsafe { libc::open(c_path(&real)?.as_ptr(), flags, 0o644) };
        if fd < 0 {
            return Err(OverlayError::Io(io::Error::last_os_error()));
        }
        // Double-check the opened path still resolves under the overlay root.
        if let Ok(canon) = fs::canonicalize(&real) {
            if !path_is_under(&self.root, &canon) {
                let _ = unsafe { libc::close(fd) };
                return Err(OverlayError::Io(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "overlay open resolved outside overlay root",
                )));
            }
        }
        if (flags & (libc::O_WRONLY | libc::O_RDWR)) != 0 {
            self.register_write_fd(fd, path);
        }
        let (folder, name) = Self::split(path);
        let db = self.db.lock().expect("overlay db");
        let _ = db.execute(
            r#"UPDATE "files" SET deleted = 0 WHERE path = ?1 AND name = ?2"#,
            params![folder, name],
        );
        Ok(fd)
    }

    pub fn mkdir(&self, path: &str, mode: u32) -> Result<()> {
        let _gate = self.commit_gate.read().expect("overlay commit gate");
        self.ensure_parent(path)?;
        let real = self.realpath(path);
        self.ensure_under_root(&real)?;
        fs::create_dir_all(&real)?;
        let _ = fs::set_permissions(&real, fs::Permissions::from_mode(mode & 0o7777));
        self.mark_present(path, mode | ratarmount_core::S_IFDIR)?;
        Ok(())
    }

    pub fn unlink(&self, path: &str) -> Result<()> {
        let _gate = self.commit_gate.read().expect("overlay commit gate");
        self.unlink_inner(path)
    }

    fn unlink_inner(&self, path: &str) -> Result<()> {
        let real = self.realpath(path);
        // unlink of a symlink removes the link itself (safe); refuse only when the
        // joined path is not under the overlay root by construction.
        if !path_is_under(&self.root, &real) {
            return Err(OverlayError::Io(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "overlay unlink path escapes overlay root",
            )));
        }
        // remove_file unlinks symlinks without following them.
        if fs::symlink_metadata(&real).is_ok() {
            fs::remove_file(&real)?;
        }
        self.mark_deleted(path)?;
        Ok(())
    }

    pub fn rmdir(&self, path: &str) -> Result<()> {
        let _gate = self.commit_gate.read().expect("overlay commit gate");
        let real = self.realpath(path);
        self.ensure_under_root(&real)?;
        // POSIX: refuse non-directories and non-empty dirs in the union view.
        // Committing a bare dir tombstone would recursively delete base
        // children (GNU tar --delete) or orphan them (zstd splice drops only
        // the dir member) — the two paths also disagree with each other.
        match self.lookup(path, 0) {
            Some(fi) if fi.mode & ratarmount_core::S_IFMT == ratarmount_core::S_IFDIR => {}
            Some(_) => {
                return Err(OverlayError::Io(io::Error::new(
                    io::ErrorKind::NotADirectory,
                    format!("rmdir: not a directory: {path}"),
                )));
            }
            None => {
                return Err(OverlayError::Io(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("rmdir: no such directory: {path}"),
                )));
            }
        }
        let has_children = match self.list(path) {
            Some(ListResult::Infos(m)) => !m.is_empty(),
            Some(ListResult::Names(n)) => !n.is_empty(),
            None => false,
        };
        if has_children {
            return Err(OverlayError::Io(io::Error::new(
                io::ErrorKind::DirectoryNotEmpty,
                format!("rmdir: directory not empty: {path}"),
            )));
        }
        if real.exists() {
            fs::remove_dir(&real)?;
        }
        self.mark_deleted(path)?;
        Ok(())
    }

    pub fn truncate(&self, path: &str, size: u64) -> Result<()> {
        let _gate = self.commit_gate.read().expect("overlay commit gate");
        self.ensure_modifiable(path)?;
        let real = self.realpath(path);
        self.ensure_under_root(&real)?;
        let f = FsOpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&real)?;
        f.set_len(size)?;
        Ok(())
    }

    /// Create a symlink in the overlay folder (`O_NOFOLLOW` / no escape).
    pub fn create_symlink(&self, path: &str, target: &str) -> Result<()> {
        let _gate = self.commit_gate.read().expect("overlay commit gate");
        if target.is_empty() {
            return Err(OverlayError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty symlink target",
            )));
        }
        self.ensure_parent(path)?;
        let real = self.realpath(path);
        self.ensure_under_root(&real)?;
        if fs::symlink_metadata(&real).is_ok() || self.lookup(path, 0).is_some() {
            return Err(OverlayError::Io(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("symlink destination exists: {path}"),
            )));
        }
        if let Some(parent) = real.parent() {
            fs::create_dir_all(parent)?;
        }
        std::os::unix::fs::symlink(target, &real)?;
        self.mark_present(path, ratarmount_core::S_IFLNK | 0o777)?;
        Ok(())
    }

    /// Rename within the overlay (COW archive members first).
    pub fn rename(&self, from: &str, to: &str) -> Result<()> {
        let _gate = self.commit_gate.read().expect("overlay commit gate");
        let from = normpath(from);
        let to = normpath(to);
        if from == "/" || to == "/" || from == to {
            return Err(OverlayError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid rename paths",
            )));
        }
        self.ensure_parent(&to)?;
        let from_real_meta = fs::symlink_metadata(self.realpath(&from));
        let from_is_dir = from_real_meta
            .as_ref()
            .map(|m| m.file_type().is_dir())
            .unwrap_or_else(|_| self.current_base().is_dir(&from));
        if from_is_dir {
            return Err(OverlayError::Io(io::Error::new(
                io::ErrorKind::IsADirectory,
                "directory rename is not supported on the write overlay",
            )));
        }
        // COW the source before touching the destination: if the copy fails
        // (read error, ENOSPC), the destination must not already be unlinked.
        self.ensure_modifiable(&from)?;
        let from_real = self.realpath(&from);
        let to_real = self.realpath(&to);
        self.ensure_rename_confined(&from_real)?;
        self.ensure_rename_confined(&to_real)?;
        if fs::symlink_metadata(&from_real).is_err() {
            return Err(OverlayError::Io(io::Error::new(
                io::ErrorKind::NotFound,
                format!("rename source missing: {from}"),
            )));
        }
        if self.lookup(&to, 0).is_some() {
            let dest_real = self.realpath(&to);
            let dest_is_dir = fs::symlink_metadata(&dest_real)
                .map(|m| m.file_type().is_dir())
                .unwrap_or_else(|_| self.current_base().is_dir(&to));
            if dest_is_dir {
                return Err(OverlayError::Io(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "rename destination is a directory",
                )));
            }
            self.unlink_inner(&to)?;
        }
        if let Some(parent) = to_real.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::rename(&from_real, &to_real)?;
        self.mark_deleted(&from)?;
        let mode = fs::symlink_metadata(&to_real)?.mode();
        self.mark_present(&to, mode)?;
        Ok(())
    }

    /// True when `archive` can be live-committed (uncompressed TAR or `.tar.zst`).
    pub fn live_commit_supported(archive: &Path) -> Result<()> {
        live_commit_is_supported(archive)
    }

    /// Persist only (on-exit). No reopen/reset.
    pub fn commit_atomic(&self, archive: &Path) -> Result<bool> {
        live_commit_is_supported(archive)?;
        let format = detect_live_commit_format(archive)?;
        if format != CompressionFormat::Zstd {
            ensure_gnu_tar()?;
        }
        let _gate = self.commit_gate.write().expect("overlay commit gate");
        if self.interval_disabled() {
            return Err(interval_disabled_err());
        }
        let plan = {
            let db = self.db.lock().expect("overlay db");
            collect_overlay_commit_plan_from_conn(&self.root, Some(&db), None, &HashSet::new())?
        };
        if plan.is_empty() {
            return Ok(false);
        }
        self.persist_by_format(archive, format, &plan)?;
        self.commit_generation.fetch_add(1, Ordering::SeqCst);
        Ok(true)
    }

    /// Dispatcher: uncompressed TAR (GNU tar) or `.tar.zst` (last-frame splice).
    ///
    /// Commits every overlay change, then wipes the overlay folder. Interval
    /// ticks use [`Self::commit_live_idle`] so recently modified files stay
    /// in the overlay until they settle.
    pub fn commit_live(
        &self,
        archive: &Path,
        reopen: impl FnOnce(&Path) -> Result<Arc<dyn MountSource>>,
    ) -> Result<bool> {
        self.commit_live_inner(archive, None, reopen)
    }

    /// Interval persist: only overlay files whose host mtime is at least
    /// `idle_for` in the past **and** that have no open write fd. Still-hot
    /// files (and parent dirs they need) stay in the overlay. Delete
    /// tombstones are already settled and go out on the same tick.
    pub fn commit_live_idle(
        &self,
        archive: &Path,
        idle_for: Duration,
        reopen: impl FnOnce(&Path) -> Result<Arc<dyn MountSource>>,
    ) -> Result<bool> {
        // Shared lock so a 1 Hz empty poll does not stall overlay writers.
        {
            let _gate = self.commit_gate.read().expect("overlay commit gate");
            if self.interval_disabled() {
                return Err(interval_disabled_err());
            }
            let cutoff = SystemTime::now()
                .checked_sub(idle_for)
                .unwrap_or(SystemTime::UNIX_EPOCH);
            let busy = self.write_open_hosts();
            let plan = {
                let db = self.db.lock().expect("overlay db");
                collect_overlay_commit_plan_from_conn(&self.root, Some(&db), Some(cutoff), &busy)?
            };
            if plan.is_empty() {
                return Ok(false);
            }
        }
        self.commit_live_inner(archive, Some(idle_for), reopen)
    }

    fn commit_live_inner(
        &self,
        archive: &Path,
        idle_for: Option<Duration>,
        reopen: impl FnOnce(&Path) -> Result<Arc<dyn MountSource>>,
    ) -> Result<bool> {
        live_commit_is_supported(archive)?;
        let format = detect_live_commit_format(archive)?;
        if format != CompressionFormat::Zstd {
            ensure_gnu_tar()?;
        }
        let _gate = self.commit_gate.write().expect("overlay commit gate");
        if self.interval_disabled() {
            return Err(interval_disabled_err());
        }
        let cutoff = idle_for.map(|d| {
            SystemTime::now()
                .checked_sub(d)
                .unwrap_or(SystemTime::UNIX_EPOCH)
        });
        let busy = if cutoff.is_some() {
            self.write_open_hosts()
        } else {
            HashSet::new()
        };
        let plan = {
            let db = self.db.lock().expect("overlay db");
            collect_overlay_commit_plan_from_conn(&self.root, Some(&db), cutoff, &busy)?
        };
        if plan.is_empty() {
            return Ok(false);
        }
        self.persist_by_format(archive, format, &plan)?;
        match reopen(archive) {
            Ok(src) => {
                *self.replacement.write().expect("overlay replacement") = Some(src);
                // Bump before overlay cleanup: readers must drop pre-commit
                // offsets even if forget/reset fails.
                self.commit_generation.fetch_add(1, Ordering::SeqCst);
                let cleanup = if idle_for.is_some() {
                    self.forget_committed_overlay(&plan)
                } else {
                    reset_overlay_dir(&self.root).and_then(|_| {
                        self.db
                            .lock()
                            .expect("overlay db")
                            .execute(r#"DELETE FROM "files""#, [])?;
                        Ok(())
                    })
                };
                if let Err(e) = cleanup {
                    self.interval_disabled.store(true, Ordering::SeqCst);
                    return Err(OverlayError::Msg(format!(
                        "persist succeeded; overlay cleanup failed (remount required): {e}"
                    )));
                }
                Ok(true)
            }
            Err(e) => {
                self.interval_disabled.store(true, Ordering::SeqCst);
                Err(OverlayError::Msg(format!(
                    "persist succeeded; reopen failed (remount required): {e}"
                )))
            }
        }
    }

    /// Drop only the overlay files / tombstones that this idle tick persisted.
    /// Unsettled siblings stay so the next tick can pick them up.
    fn forget_committed_overlay(&self, plan: &OverlayCommitPlan) -> Result<()> {
        let db = self.db.lock().expect("overlay db");
        let mut dirs: Vec<&str> = Vec::new();
        for (rel, is_dir) in &plan.append_entries {
            if *is_dir {
                dirs.push(rel.as_str());
                continue;
            }
            let host = self.realpath(rel);
            match fs::remove_file(&host) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
            delete_overlay_files_row(&db, rel)?;
        }
        dirs.sort_by_key(|p| std::cmp::Reverse(p.matches('/').count()));
        for rel in dirs {
            let host = self.realpath(rel);
            // Not empty: a hot child appeared or was skipped. Leave the dir.
            match fs::remove_dir(&host) {
                Ok(()) => {}
                Err(e)
                    if e.kind() == io::ErrorKind::NotFound
                        || e.kind() == io::ErrorKind::DirectoryNotEmpty => {}
                Err(e) => return Err(e.into()),
            }
            delete_overlay_files_row(&db, rel)?;
        }
        for rel in &plan.deleted_paths {
            if plan.append_entries.iter().any(|(p, _)| p == rel) {
                continue;
            }
            delete_overlay_files_row(&db, rel)?;
        }
        // Drop leftover empty parents so a later tick does not persist them
        // as extra TAR directory members. Stop at a dir that still has a
        // hot sibling.
        let mut parents: Vec<String> = plan
            .append_entries
            .iter()
            .filter_map(|(rel, is_dir)| {
                if *is_dir {
                    None
                } else {
                    rel.rsplit_once('/').map(|(p, _)| p.to_string())
                }
            })
            .collect();
        parents.sort();
        parents.dedup();
        parents.sort_by_key(|p| std::cmp::Reverse(p.matches('/').count()));
        for parent in parents {
            prune_empty_overlay_ancestors(&self.root, &db, &parent)?;
        }
        Ok(())
    }

    /// Persist only (on-exit). Thin wrapper over [`Self::commit_atomic`].
    pub fn commit_uncompressed_tar_atomic(&self, archive: &Path) -> Result<bool> {
        self.commit_atomic(archive)
    }

    /// Persist, swap base, and wipe overlay under **one** write lock (interval).
    pub fn commit_live_uncompressed_tar(
        &self,
        archive: &Path,
        reopen: impl FnOnce(&Path) -> Result<Arc<dyn MountSource>>,
    ) -> Result<bool> {
        self.commit_live(archive, reopen)
    }

    fn persist_by_format(
        &self,
        archive: &Path,
        format: CompressionFormat,
        plan: &OverlayCommitPlan,
    ) -> Result<()> {
        match format {
            CompressionFormat::Zstd => self.persist_tar_zst_plan(archive, plan),
            _ => self.persist_uncompressed_tar_plan(archive, plan),
        }
    }

    /// Last-N zstd frame rewrite. Never calls GNU tar (K3).
    fn persist_tar_zst_plan(&self, archive: &Path, plan: &OverlayCommitPlan) -> Result<()> {
        let map = scan_zstd_frames_path(archive).map_err(|e| OverlayError::Msg(e.to_string()))?;
        let (from_idx, rewrite_window_start_uncomp) = find_last_n_tar_window(archive, &map)?;
        let base = self.current_base();
        let mut last_window_deletes = HashSet::new();
        for path in &plan.deleted_paths {
            match classify_tar_zst_path(base.as_ref(), path, rewrite_window_start_uncomp)? {
                TarZstPathClass::OverlayOnly => {}
                TarZstPathClass::LastWindow => {
                    last_window_deletes.insert(path.clone());
                }
            }
        }
        let pending = self.collect_ustar_pending(&plan.append_entries)?;
        splice_zstd_last_frames_replace(archive, from_idx, |mut suffix, stream_offset, mut out| {
            let members: Vec<UstarMember<'_>> =
                pending.iter().map(PendingUstar::as_member).collect();
            let opts = RewriteTarSuffix {
                deleted_paths: &last_window_deletes,
                append: &members,
                encoding: "utf-8",
            };
            // Extra refs so R/W are `&mut dyn …` (Sized); the hook itself is unsized.
            rewrite_tar_suffix(&mut suffix, stream_offset, &opts, &mut out).map(|_| ())
        })
        .map_err(|e| OverlayError::Msg(e.to_string()))?;
        Ok(())
    }

    fn collect_ustar_pending(
        &self,
        append_entries: &[(String, bool)],
    ) -> Result<Vec<PendingUstar>> {
        let mut out = Vec::with_capacity(append_entries.len());
        for (rel, is_dir) in append_entries {
            let host = self.realpath(rel);
            let meta = fs::symlink_metadata(&host)?;
            let mode = meta.mode() & 0o7777;
            let uid = meta.uid();
            let gid = meta.gid();
            let mtime = meta.mtime().max(0) as u64;
            // Symlink first: `ensure_under_root` refuses the final component.
            let kind = if meta.file_type().is_symlink() {
                self.ensure_parent_confined(&host)?;
                let target = fs::read_link(&host)?;
                PendingKind::Symlink {
                    target: target.to_string_lossy().into_owned(),
                }
            } else if *is_dir || meta.file_type().is_dir() {
                self.ensure_under_root(&host)?;
                PendingKind::Directory
            } else {
                self.ensure_under_root(&host)?;
                PendingKind::FileOnDisk { size: meta.len() }
            };
            out.push(PendingUstar {
                path: rel.clone(),
                host,
                kind,
                mode,
                uid,
                gid,
                mtime,
            });
        }
        Ok(out)
    }

    /// Confinement for rename endpoints: `rename(2)` never follows symlinks,
    /// so a symlink final component only needs a confined parent (the plain
    /// `ensure_under_root` rejects final symlinks — an anti-escape policy for
    /// open/read/write that does not apply here).
    fn ensure_rename_confined(&self, host_path: &Path) -> Result<()> {
        match fs::symlink_metadata(host_path) {
            Ok(meta) if meta.file_type().is_symlink() => self
                .ensure_parent_confined(host_path)
                .map_err(OverlayError::Io),
            _ => self.ensure_under_root(host_path).map_err(OverlayError::Io),
        }
    }

    /// Confine a symlink's parent without following the final component.
    fn ensure_parent_confined(&self, host_path: &Path) -> io::Result<()> {
        let parent = host_path.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "overlay symlink has no parent",
            )
        })?;
        let canon = fs::canonicalize(parent)?;
        if !path_is_under(&self.root, &canon) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "overlay symlink parent escapes overlay root: {} not under {}",
                    canon.display(),
                    self.root.display()
                ),
            ));
        }
        Ok(())
    }

    fn persist_uncompressed_tar_plan(
        &self,
        archive: &Path,
        plan: &OverlayCommitPlan,
    ) -> Result<()> {
        let parent = archive.parent().filter(|p| !p.as_os_str().is_empty());
        let mut tmp = match parent {
            Some(dir) => tempfile::NamedTempFile::new_in(dir)?,
            None => tempfile::NamedTempFile::new()?,
        };
        {
            let mut src = File::open(archive)?;
            io::copy(&mut src, tmp.as_file_mut())?;
            tmp.as_file().sync_all()?;
        }
        let work_tar = tmp.path().to_path_buf();
        let list_dir = tempfile::tempdir()?;
        let deletion_list = list_dir.path().join("deletions.lst");
        let append_list = list_dir.path().join("append.lst");
        fs::write(&deletion_list, &plan.deletions_nul)?;
        fs::write(&append_list, &plan.appends_nul)?;
        if !plan.deletions_nul.is_empty() {
            let output = tar_env_command()
                .args([
                    "--delete",
                    "--null",
                    &format!("--files-from={}", deletion_list.display()),
                    "--file",
                ])
                .arg(&work_tar)
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .output()?;
            let stderr = String::from_utf8_lossy(&output.stderr);
            let unfiltered: Vec<&str> = stderr
                .lines()
                .filter(|line| {
                    let line = line.trim();
                    !line.is_empty()
                        && !line.contains("tar: Exiting with failure")
                        && !line.contains("Not found in archive")
                })
                .collect();
            if !unfiltered.is_empty() {
                for line in &unfiltered {
                    eprintln!("{line}");
                }
                return Err(OverlayError::Msg(
                    "There were problems when trying to delete files.".into(),
                ));
            }
        }
        if !plan.appends_nul.is_empty() {
            let status = tar_env_command()
                .args(["--append", "-C"])
                .arg(&self.root)
                .args([
                    "--null",
                    &format!("--files-from={}", append_list.display()),
                    "--file",
                ])
                .arg(&work_tar)
                .status()?;
            if !status.success() {
                return Err(OverlayError::Msg(format!(
                    "tar --append failed with {status}"
                )));
            }
        }
        tmp.as_file().sync_all()?;
        tmp.persist(archive).map_err(|e| {
            OverlayError::Msg(format!(
                "Failed to replace '{}' after live TAR commit: {}",
                archive.display(),
                e.error
            ))
        })?;
        Ok(())
    }

    /// Remove overlay files (except the hidden DB) and clear deletion/present rows.
    pub fn reset_overlay_contents(&self) -> Result<()> {
        let _gate = self.commit_gate.write().expect("overlay commit gate");
        reset_overlay_dir(&self.root)?;
        let db = self.db.lock().expect("overlay db");
        db.execute(r#"DELETE FROM "files""#, [])?;
        Ok(())
    }

    fn overlay_file_info(&self, path: &str) -> Option<FileInfo> {
        let real = self.realpath(path);
        // symlink_metadata so a dangling overlay symlink is still visible.
        let meta = fs::symlink_metadata(&real).ok()?;
        let linkname = if meta.file_type().is_symlink() {
            fs::read_link(&real)
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default()
        } else {
            String::new()
        };
        Some(FileInfo {
            size: meta.len(),
            mtime: meta.mtime() as f64,
            mode: meta.mode(),
            linkname,
            uid: meta.uid(),
            gid: meta.gid(),
            userdata: vec![UserData::Other(format!("overlay:{path}"))],
        })
    }
}

impl MountSource for WriteOverlay {
    fn list(&self, path: &str) -> Option<ListResult> {
        let path = normpath(path);
        if self.is_deleted(&path) && path != "/" {
            return None;
        }
        let deleted: std::collections::HashSet<String> =
            self.list_deleted(&path).into_iter().collect();

        let mut map = std::collections::BTreeMap::new();

        if let Some(base_list) = self.current_base().list(&path) {
            match base_list {
                ListResult::Infos(m) => {
                    for (k, v) in m {
                        if !deleted.contains(&k) {
                            map.insert(k, v);
                        }
                    }
                }
                ListResult::Names(names) => {
                    for name in names {
                        if deleted.contains(&name) {
                            continue;
                        }
                        let full = join(&path, &name);
                        if let Some(fi) = self.current_base().lookup(&full, 0) {
                            map.insert(name, fi);
                        }
                    }
                }
            }
        }

        // Overlay folder entries
        let real = self.realpath(&path);
        if let Ok(rd) = fs::read_dir(&real) {
            for ent in rd.flatten() {
                let name = ent.file_name().to_string_lossy().into_owned();
                if name.starts_with(HIDDEN_DB) || deleted.contains(&name) {
                    continue;
                }
                let full = join(&path, &name);
                if let Some(fi) = self.overlay_file_info(&full) {
                    map.insert(name, fi);
                }
            }
        }

        if path == "/" || !map.is_empty() || self.current_base().is_dir(&path) {
            Some(ListResult::Infos(map))
        } else {
            None
        }
    }

    fn list_dirents(&self, path: &str) -> Option<Vec<CheapDirent>> {
        let path = normpath(path);
        if self.is_deleted(&path) && path != "/" {
            return None;
        }
        let deleted: HashSet<String> = self.list_deleted(&path).into_iter().collect();
        let mut by_name: BTreeMap<String, CheapDirent> = BTreeMap::new();

        if let Some(base_dents) = self.current_base().list_dirents(&path) {
            for d in base_dents {
                if !deleted.contains(&d.name) {
                    by_name.insert(d.name.clone(), d);
                }
            }
        }

        let real = self.realpath(&path);
        if let Ok(rd) = fs::read_dir(&real) {
            for ent in rd.flatten() {
                let name = ent.file_name().to_string_lossy().into_owned();
                if name.starts_with(HIDDEN_DB) || deleted.contains(&name) {
                    continue;
                }
                let full = join(&path, &name);
                if let Some(fi) = self.overlay_file_info(&full) {
                    by_name.insert(
                        name.clone(),
                        CheapDirent {
                            name,
                            mode: fi.mode,
                            size: fi.size,
                        },
                    );
                }
            }
        }

        if path == "/" || !by_name.is_empty() || self.current_base().is_dir(&path) {
            Some(by_name.into_values().collect())
        } else {
            None
        }
    }

    fn list_mode(&self, path: &str) -> Option<ListModeResult> {
        let dents = self.list_dirents(path)?;
        Some(ListModeResult::Modes(
            dents.into_iter().map(|d| (d.name, d.mode)).collect(),
        ))
    }

    fn lookup(&self, path: &str, file_version: i32) -> Option<FileInfo> {
        let path = normpath(path);
        if path == "/" {
            return Some(create_root_file_info());
        }
        if self.is_deleted(&path) {
            return None;
        }
        if let Some(fi) = self.overlay_file_info(&path) {
            return Some(fi);
        }
        self.current_base().lookup(&path, file_version)
    }

    fn open(
        &self,
        file_info: &FileInfo,
        buffering: i32,
    ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
        // Prefer overlay path if tagged
        if let Some(UserData::Other(s)) = file_info.userdata.last() {
            if let Some(path) = s.strip_prefix("overlay:") {
                let real = self.realpath(path);
                self.ensure_under_root(&real)?;
                match FsOpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(&real)
                {
                    Ok(f) => return Ok(Box::new(f)),
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {
                        // Live commit wiped the overlay file; serve from the new base.
                        if let Some(fi) = self.current_base().lookup(path, 0) {
                            return self.current_base().open(&fi, buffering);
                        }
                        return Err(e);
                    }
                    Err(e) => return Err(e),
                }
            }
        }
        self.current_base().open(file_info, buffering)
    }

    fn is_immutable(&self) -> bool {
        false
    }

    fn content_generation(&self) -> u64 {
        // Own commit counter dominates; forward the base in case an inner
        // mutable source (stacked overlay) also changes under us.
        self.commit_generation
            .load(Ordering::SeqCst)
            .saturating_add(self.base.content_generation())
    }

    fn member_seek_is_cheap(&self, file_info: &FileInfo) -> bool {
        if let Some(UserData::Other(s)) = file_info.userdata.last() {
            if s.starts_with("overlay:") {
                return true;
            }
        }
        self.current_base().member_seek_is_cheap(file_info)
    }
}

fn join(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{parent}/{name}")
    }
}

/// Component-wise path prefix check (safe vs string prefix `/tmp/ov` vs `/tmp/ov-evil`).
fn path_is_under(root: &Path, candidate: &Path) -> bool {
    candidate.starts_with(root)
}

fn c_path(path: &Path) -> io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
}

/// Options for [`commit_overlay`].
#[derive(Clone, Debug)]
pub struct CommitOverlayOptions {
    /// When true, skip interactive "commit" confirmation (for harness / automation).
    pub yes: bool,
    /// Verbosity: 0 = quiet, 1+ = print plan (Python `printDebug`).
    pub debug: u8,
}

impl Default for CommitOverlayOptions {
    fn default() -> Self {
        Self {
            yes: false,
            debug: 1,
        }
    }
}

/// Apply overlay folder modifications to a TAR or ZIP archive.
///
/// **TAR** (GNU tar): supports uncompressed TAR and gzip / bzip2 / xz compressed TAR
/// via decompress → `tar --delete` / `tar --append` → recompress.
///
/// **ZIP** (full rebuild, not in-place): rebuilds a new ZIP from the base archive plus
/// overlay adds/deletes. Unchanged members are raw-copied (preserves store/deflate and
/// other methods). Overlay file bodies are written as **deflate** (directories as empty
/// directory entries). Atomic replace of the original path. Runtime scales with archive
/// size (full rewrite). Encrypted / multi-part / spanned ZIPs are not supported for commit.
///
/// Shared plan:
/// 1. Collect deleted paths from `.ratarmount.overlay.sqlite`
/// 2. Walk overlay files → delete-then-append list
/// 3. Apply format-specific commit
///
/// Returns `Ok(true)` if changes were committed, `Ok(false)` if nothing to do or canceled.
pub fn commit_overlay(
    write_overlay: impl AsRef<Path>,
    archive_file: impl AsRef<Path>,
    opts: &CommitOverlayOptions,
) -> Result<bool> {
    let write_overlay = write_overlay.as_ref();
    let archive_file = archive_file.as_ref();

    if !write_overlay.is_dir() {
        return Err(OverlayError::Msg(
            "Need an existing write overlay folder for committing changes.".into(),
        ));
    }
    if !archive_file.is_file() {
        return Err(OverlayError::Msg(format!(
            "Specified archive '{}' to commit to does not exist or is not a file!",
            archive_file.display()
        )));
    }

    if is_zip_archive(archive_file)? {
        return commit_overlay_zip(write_overlay, archive_file, opts);
    }

    commit_overlay_tar(write_overlay, archive_file, opts)
}

/// Overlay changes collected for commit (paths relative to archive root, `/`-separated).
struct OverlayCommitPlan {
    /// Null-terminated path variants for GNU tar `--files-from`.
    deletions_nul: Vec<u8>,
    /// Null-terminated paths for GNU tar `--append --files-from`.
    appends_nul: Vec<u8>,
    /// Normalized relative paths marked deleted (DB + files being replaced).
    deleted_paths: HashSet<String>,
    /// Overlay entries to add: `(relative path, is_directory)`.
    append_entries: Vec<(String, bool)>,
}

impl OverlayCommitPlan {
    fn is_empty(&self) -> bool {
        self.deleted_paths.is_empty() && self.append_entries.is_empty()
    }
}

fn collect_overlay_commit_plan(write_overlay: &Path) -> Result<OverlayCommitPlan> {
    let db_path = write_overlay.join(HIDDEN_DB);
    let conn = if db_path.is_file() {
        Some(Connection::open_with_flags(
            &db_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?)
    } else {
        None
    };
    collect_overlay_commit_plan_from_conn(write_overlay, conn.as_ref(), None, &HashSet::new())
}

fn collect_overlay_commit_plan_from_conn(
    write_overlay: &Path,
    conn: Option<&Connection>,
    idle_cutoff: Option<SystemTime>,
    busy_hosts: &HashSet<PathBuf>,
) -> Result<OverlayCommitPlan> {
    let mut deletions_nul: Vec<u8> = Vec::new();
    let mut appends_nul: Vec<u8> = Vec::new();
    let mut deleted_paths: HashSet<String> = HashSet::new();
    let mut append_entries: Vec<(String, bool)> = Vec::new();
    let mut skipped: HashSet<String> = HashSet::new();

    if let Some(conn) = conn {
        let mut stmt = conn.prepare(r#"SELECT path, name FROM "files" WHERE deleted = 1"#)?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        for row in rows {
            let (path, name) = row?;
            let rel = join_rel(&path, &name);
            let norm = normalize_archive_rel_path(&rel);
            if !norm.is_empty() {
                deleted_paths.insert(norm);
            }
            add_deletion_variants(&mut deletions_nul, &rel);
        }
    }

    // Overlay walk: files to append (and replace = delete + append)
    let suffixes = ["", "-journal", "-shm", "-wal"];
    let ignored: Vec<String> = suffixes.iter().map(|s| format!("{HIDDEN_DB}{s}")).collect();

    let overlay_str = write_overlay.to_string_lossy();
    let overlay_prefix = if overlay_str.ends_with('/') {
        overlay_str.to_string()
    } else {
        format!("{overlay_str}/")
    };

    for entry in walkdir_files_and_empty_dirs(write_overlay)? {
        let full = entry.path;
        let is_dir = entry.is_dir;
        let rel = if full == write_overlay {
            continue;
        } else if let Ok(r) = full.strip_prefix(write_overlay) {
            r.to_string_lossy().replace('\\', "/")
        } else if let Some(rest) = full.to_string_lossy().strip_prefix(&overlay_prefix) {
            rest.to_string()
        } else {
            continue;
        };
        let rel = rel.trim_start_matches('/').to_string();
        if rel.is_empty() {
            continue;
        }
        if ignored.iter().any(|i| rel == *i || rel.ends_with(i)) {
            continue;
        }
        // Only top-level DB name
        if ignored.contains(&rel) {
            continue;
        }
        let norm = normalize_archive_rel_path(&rel);
        if let Some(cutoff) = idle_cutoff {
            if !overlay_entry_is_idle(&full, cutoff, busy_hosts) {
                skipped.insert(norm);
                continue;
            }
        }
        if is_dir {
            // Empty dirs only (walkdir_files_and_empty_dirs already filters)
            appends_nul.extend(rel.as_bytes());
            appends_nul.push(0);
            append_entries.push((norm, true));
        } else {
            add_deletion_variants(&mut deletions_nul, &rel);
            deleted_paths.insert(norm.clone());
            appends_nul.extend(rel.as_bytes());
            appends_nul.push(0);
            append_entries.push((norm, false));
        }
    }

    if idle_cutoff.is_some() && !skipped.is_empty() {
        // A hot file under dir/ must not persist dir/ as an empty member
        // (and must not wipe that parent from the overlay).
        append_entries.retain(|(p, is_dir)| {
            if !is_dir {
                return true;
            }
            !skipped.iter().any(|s| s == p || path_is_under_rel(p, s))
        });
        appends_nul.clear();
        for (rel, _) in &append_entries {
            appends_nul.extend(rel.as_bytes());
            appends_nul.push(0);
        }
    }

    Ok(OverlayCommitPlan {
        deletions_nul,
        appends_nul,
        deleted_paths,
        append_entries,
    })
}

fn overlay_entry_is_idle(path: &Path, cutoff: SystemTime, busy_hosts: &HashSet<PathBuf>) -> bool {
    if busy_hosts.contains(path) {
        return false;
    }
    match fs::symlink_metadata(path).and_then(|m| m.modified()) {
        Ok(mtime) => mtime <= cutoff,
        Err(_) => false,
    }
}

fn path_is_under_rel(parent: &str, child: &str) -> bool {
    child.starts_with(parent) && child.as_bytes().get(parent.len()) == Some(&b'/')
}

fn delete_overlay_files_row(db: &Connection, rel: &str) -> Result<()> {
    let (folder, name) = WriteOverlay::split(rel);
    db.execute(
        r#"DELETE FROM "files" WHERE path = ?1 AND name = ?2"#,
        params![folder, name],
    )?;
    Ok(())
}

fn prune_empty_overlay_ancestors(root: &Path, db: &Connection, start: &str) -> Result<()> {
    let mut cur = Some(start.to_string());
    while let Some(rel) = cur {
        if rel.is_empty() || rel == "/" {
            break;
        }
        let host = if rel == "/" {
            root.to_path_buf()
        } else {
            root.join(rel.trim_start_matches('/'))
        };
        if host == root {
            break;
        }
        match fs::remove_dir(&host) {
            Ok(()) => {
                delete_overlay_files_row(db, &rel)?;
                cur = rel.rsplit_once('/').map(|(p, _)| p.to_string());
            }
            Err(e)
                if e.kind() == io::ErrorKind::NotFound
                    || e.kind() == io::ErrorKind::DirectoryNotEmpty =>
            {
                break;
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

fn confirm_commit(opts: &CommitOverlayOptions) -> Result<bool> {
    if opts.yes {
        return Ok(true);
    }
    print!("Please confirm by entering \"commit\". Any other input will cancel.\n> ");
    let _ = io::stdout().flush();
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(line.trim() == "commit")
}

/// Strip leading `./` / `/` and trailing `/` for stable path matching.
fn normalize_archive_rel_path(path: &str) -> String {
    let p = path
        .trim_start_matches('/')
        .trim_start_matches("./")
        .trim_end_matches('/');
    p.to_string()
}

/// True if path looks like a ZIP local/central/EOCD signature (`PK…`).
fn is_zip_archive(path: &Path) -> Result<bool> {
    let mut f = File::open(path)?;
    let mut magic = [0u8; 4];
    let n = f.read(&mut magic)?;
    if n >= 4 && magic[0] == b'P' && magic[1] == b'K' {
        // Local header, central directory, EOCD, or spanned data descriptor.
        return Ok(matches!(
            (magic[2], magic[3]),
            (0x03, 0x04) | (0x05, 0x06) | (0x07, 0x08) | (0x01, 0x02) | (0x06, 0x06) | (0x06, 0x07)
        ));
    }
    // Extension fallback (empty / exotic zips that don't open as files we can magic).
    Ok(path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("zip") || e.eq_ignore_ascii_case("jar")))
}

/// True when a ZIP member should be dropped (explicit delete or replaced by overlay).
fn zip_member_dropped(member_name: &str, plan: &OverlayCommitPlan) -> bool {
    let norm = normalize_archive_rel_path(member_name);
    if norm.is_empty() {
        return false;
    }
    if plan.deleted_paths.contains(&norm) {
        return true;
    }
    // Overlay replace / add with same path (dirs may only be in append_entries).
    plan.append_entries.iter().any(|(p, _)| p == &norm)
}

/// Rebuild ZIP from base + overlay (full archive rewrite, atomic replace).
///
/// Unchanged members are **raw-copied** (preserves store/deflate/etc.). Overlay files are
/// written with **deflate**. Not in-place append; cost is O(archive size).
fn commit_overlay_zip(
    write_overlay: &Path,
    zip_file: &Path,
    opts: &CommitOverlayOptions,
) -> Result<bool> {
    let plan = collect_overlay_commit_plan(write_overlay)?;

    if plan.is_empty() {
        if opts.debug >= 1 {
            println!("Nothing to commit.");
        }
        return Ok(false);
    }

    if opts.debug >= 1 {
        println!(
            "To commit the overlay folder to the ZIP archive, the archive will be fully rebuilt:"
        );
        println!();
        println!(
            "    # full rebuild (not in-place) of {}",
            zip_file.display()
        );
        if !plan.deleted_paths.is_empty() {
            println!(
                "    # drop {} deleted/replaced path(s)",
                plan.deleted_paths.len()
            );
        }
        if !plan.append_entries.is_empty() {
            println!(
                "    # add/replace {} overlay path(s) from {}",
                plan.append_entries.len(),
                write_overlay.display()
            );
            for (p, is_dir) in &plan.append_entries {
                if *is_dir {
                    println!("    #   dir  {p}/");
                } else {
                    println!("    #   file {p}  (deflate)");
                }
            }
        }
        println!();
        println!(
            "ZIP commit-overlay rewrites the entire archive (store/deflate members preserved \
             via raw copy; overlay files stored with deflate). Performance scales with size."
        );
        println!("Committing is an experimental feature!");
    }

    if !confirm_commit(opts)? {
        if opts.debug >= 1 {
            println!("Canceled");
        }
        return Ok(false);
    }

    rebuild_zip_with_overlay(write_overlay, zip_file, &plan)?;

    if opts.debug >= 1 {
        println!(
            "Committed successfully. You can now remove the overlay folder at {}.",
            write_overlay.display()
        );
    }
    Ok(true)
}

fn rebuild_zip_with_overlay(
    write_overlay: &Path,
    zip_file: &Path,
    plan: &OverlayCommitPlan,
) -> Result<()> {
    let src = File::open(zip_file).map_err(|e| {
        OverlayError::Msg(format!(
            "Failed to open ZIP '{}' for commit: {e}",
            zip_file.display()
        ))
    })?;
    let mut archive = ZipArchive::new(src).map_err(|e| {
        OverlayError::Msg(format!("Failed to read ZIP '{}': {e}", zip_file.display()))
    })?;

    let parent = zip_file.parent().filter(|p| !p.as_os_str().is_empty());
    let mut tmp = match parent {
        Some(dir) => tempfile::NamedTempFile::new_in(dir)?,
        None => tempfile::NamedTempFile::new()?,
    };

    {
        let mut writer = ZipWriter::new(tmp.as_file_mut());

        // Preserve archive comment when present.
        let comment = archive.comment().to_vec();
        if !comment.is_empty() {
            writer.set_raw_comment(comment.into_boxed_slice());
        }

        let n = archive.len();
        for i in 0..n {
            let name = archive
                .name_for_index(i)
                .ok_or_else(|| OverlayError::Msg(format!("ZIP member index {i} has no name")))?
                .to_string();
            if zip_member_dropped(&name, plan) {
                continue;
            }
            // Raw copy preserves compression method and encrypted payload bytes without decrypt.
            let file = archive.by_index_raw(i).map_err(|e| {
                OverlayError::Msg(format!("Failed to read ZIP member '{name}' for copy: {e}"))
            })?;
            writer.raw_copy_file(file).map_err(|e| {
                OverlayError::Msg(format!("Failed to copy ZIP member '{name}': {e}"))
            })?;
        }

        let file_opts =
            SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        let dir_opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);

        for (rel, is_dir) in &plan.append_entries {
            if *is_dir {
                // ZIP directory entries conventionally end with '/'.
                let dir_name = if rel.ends_with('/') {
                    rel.clone()
                } else {
                    format!("{rel}/")
                };
                writer.add_directory(&dir_name, dir_opts).map_err(|e| {
                    OverlayError::Msg(format!("Failed to add directory '{dir_name}' to ZIP: {e}"))
                })?;
            } else {
                let src_path = write_overlay.join(rel);
                let mut src_file = File::open(&src_path).map_err(|e| {
                    OverlayError::Msg(format!(
                        "Failed to open overlay file '{}': {e}",
                        src_path.display()
                    ))
                })?;
                writer.start_file(rel.as_str(), file_opts).map_err(|e| {
                    OverlayError::Msg(format!("Failed to start ZIP file '{rel}': {e}"))
                })?;
                io::copy(&mut src_file, &mut writer).map_err(|e| {
                    OverlayError::Msg(format!(
                        "Failed to write overlay file '{rel}' into ZIP: {e}"
                    ))
                })?;
            }
        }

        writer.finish().map_err(|e| {
            OverlayError::Msg(format!(
                "Failed to finalize rebuilt ZIP for '{}': {e}",
                zip_file.display()
            ))
        })?;
    }
    tmp.as_file().sync_all()?;

    tmp.persist(zip_file).map_err(|e| {
        OverlayError::Msg(format!(
            "Failed to replace '{}' with rebuilt ZIP: {}",
            zip_file.display(),
            e.error
        ))
    })?;
    Ok(())
}

/// Apply overlay to TAR (GNU tar) — uncompressed or gzip/bzip2/xz.
fn commit_overlay_tar(
    write_overlay: &Path,
    tar_file: &Path,
    opts: &CommitOverlayOptions,
) -> Result<bool> {
    ensure_gnu_tar()?;

    let format = detect_compression(tar_file).map_err(|e| {
        OverlayError::Msg(format!(
            "Failed to detect compression for '{}': {e}",
            tar_file.display()
        ))
    })?;

    // Keep materialized temp alive until recompress finishes.
    let (work_tar, _materialized): (PathBuf, Option<tempfile::NamedTempFile>) = match format {
        CompressionFormat::None => {
            if !is_uncompressed_tar(tar_file)? {
                return Err(OverlayError::Msg(
                    "Archive does not look like an uncompressed TAR or ZIP \
                     (ustar/GNU magic missing; ZIP uses PK signature)."
                        .into(),
                ));
            }
            (tar_file.to_path_buf(), None)
        }
        CompressionFormat::Gzip | CompressionFormat::Bzip2 | CompressionFormat::Xz => {
            let (tmp, _) = materialize(tar_file, format).map_err(|e| {
                OverlayError::Msg(format!(
                    "Failed to decompress '{}' for commit: {e}",
                    tar_file.display()
                ))
            })?;
            if !is_uncompressed_tar(tmp.path())? {
                return Err(OverlayError::Msg(format!(
                    "Decompressed content of '{}' does not look like a TAR archive.",
                    tar_file.display()
                )));
            }
            let path = tmp.path().to_path_buf();
            (path, Some(tmp))
        }
        other => {
            return Err(OverlayError::Msg(format!(
                "Currently, commit-overlay supports ZIP, uncompressed TAR, and \
                 gzip/bzip2/xz compressed TAR (got {other:?})."
            )));
        }
    };

    let plan = collect_overlay_commit_plan(write_overlay)?;

    let tmp = tempfile::tempdir()?;
    let deletion_list = tmp.path().join("deletions.lst");
    let append_list = tmp.path().join("append.lst");

    fs::write(&deletion_list, &plan.deletions_nul)?;
    fs::write(&append_list, &plan.appends_nul)?;

    if plan.is_empty() {
        if opts.debug >= 1 {
            println!("Nothing to commit.");
        }
        return Ok(false);
    }

    if opts.debug >= 1 {
        println!(
            "To commit the overlay folder to the archive, these commands have to be executed:"
        );
        println!();
        if format != CompressionFormat::None {
            println!("    # decompress {} -> temp TAR, then:", tar_file.display());
        }
        if !plan.deletions_nul.is_empty() {
            println!(
                "    tar --delete --null --files-from='{}' --file '{}' 2>&1 |",
                deletion_list.display(),
                work_tar.display()
            );
            println!("       sed '/^tar: Exiting with failure/d; /^tar.*Not found in archive/d'");
        }
        if !plan.appends_nul.is_empty() {
            println!(
                "    tar --append -C '{}' --null --files-from='{}' --file '{}'",
                write_overlay.display(),
                append_list.display(),
                work_tar.display()
            );
        }
        if format != CompressionFormat::None {
            println!(
                "    # recompress temp TAR -> {} ({format:?})",
                tar_file.display()
            );
        }
        println!();
        println!("Committing is an experimental feature!");
    }

    if !confirm_commit(opts)? {
        if opts.debug >= 1 {
            println!("Canceled");
        }
        return Ok(false);
    }

    if !plan.deletions_nul.is_empty() {
        let output = tar_env_command()
            .args([
                "--delete",
                "--null",
                &format!("--files-from={}", deletion_list.display()),
                "--file",
            ])
            .arg(&work_tar)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        let unfiltered: Vec<&str> = stderr
            .lines()
            .filter(|line| {
                let line = line.trim();
                !line.is_empty()
                    && !line.contains("tar: Exiting with failure")
                    && !line.contains("Not found in archive")
            })
            .collect();
        if !unfiltered.is_empty() {
            for line in &unfiltered {
                eprintln!("{line}");
            }
            return Err(OverlayError::Msg(
                "There were problems when trying to delete files.".into(),
            ));
        }
    }

    if !plan.appends_nul.is_empty() {
        let status = tar_env_command()
            .args(["--append", "-C"])
            .arg(write_overlay)
            .args([
                "--null",
                &format!("--files-from={}", append_list.display()),
                "--file",
            ])
            .arg(&work_tar)
            .status()?;
        if !status.success() {
            return Err(OverlayError::Msg(format!(
                "tar --append failed with {status}"
            )));
        }
    }

    if format != CompressionFormat::None {
        recompress_replace(&work_tar, tar_file, format)?;
    }

    if opts.debug >= 1 {
        println!(
            "Committed successfully. You can now remove the overlay folder at {}.",
            write_overlay.display()
        );
    }
    Ok(true)
}

/// Compress `plain` with `format` and atomically replace `dest`.
fn recompress_replace(plain: &Path, dest: &Path, format: CompressionFormat) -> Result<()> {
    let parent = dest.parent().filter(|p| !p.as_os_str().is_empty());
    let mut tmp = match parent {
        Some(dir) => tempfile::NamedTempFile::new_in(dir)?,
        None => tempfile::NamedTempFile::new()?,
    };

    {
        let mut src = BufReader::new(File::open(plain)?);
        let mut out = BufWriter::new(tmp.as_file_mut());
        match format {
            CompressionFormat::Gzip => {
                let mut enc = GzEncoder::new(&mut out, GzCompression::default());
                io::copy(&mut src, &mut enc)?;
                enc.finish()?;
            }
            CompressionFormat::Bzip2 => {
                let mut enc = BzEncoder::new(&mut out, bzip2::Compression::default());
                io::copy(&mut src, &mut enc)?;
                enc.finish()?;
            }
            CompressionFormat::Xz => {
                let mut enc = XzEncoder::new(&mut out, 6);
                io::copy(&mut src, &mut enc)?;
                enc.finish()?;
            }
            other => {
                return Err(OverlayError::Msg(format!(
                    "internal: recompress_replace called with unsupported format {other:?}"
                )));
            }
        }
        out.flush()?;
    }
    tmp.as_file().sync_all()?;

    // Atomic replace on the same filesystem (parent chosen to match dest).
    tmp.persist(dest).map_err(|e| {
        OverlayError::Msg(format!(
            "Failed to replace '{}' with recompressed archive: {}",
            dest.display(),
            e.error
        ))
    })?;
    Ok(())
}

fn join_rel(path: &str, name: &str) -> String {
    let path = path.trim_start_matches('/').trim_end_matches('/');
    if path.is_empty() {
        name.trim_start_matches('/').to_string()
    } else {
        format!("{path}/{}", name.trim_start_matches('/'))
    }
}

fn add_deletion_variants(buf: &mut Vec<u8>, path_relative_to_root: &str) {
    let p = path_relative_to_root.trim_start_matches('/');
    for variant in [p.to_string(), format!("/{p}"), format!("./{p}")] {
        buf.extend(variant.as_bytes());
        buf.push(0);
    }
}

/// Uncompressed TAR or `.tar.zst` — gzip/bzip2/xz TAR and ZIP stay rejected.
pub fn live_commit_is_supported(archive: &Path) -> Result<()> {
    if is_zip_archive(archive)? {
        return Err(OverlayError::Msg(
            "live overlay commit supports uncompressed TAR only (not ZIP)".into(),
        ));
    }
    let format = detect_live_commit_format(archive)?;
    match format {
        CompressionFormat::None => {
            if !is_uncompressed_tar(archive)? {
                return Err(OverlayError::Msg(format!(
                    "'{}' is not an uncompressed TAR",
                    archive.display()
                )));
            }
            Ok(())
        }
        CompressionFormat::Zstd => {
            if !looks_like_tar_zst(archive)? {
                return Err(OverlayError::Msg(
                    "plain .zst is not a TAR; live commit not supported".into(),
                ));
            }
            Ok(())
        }
        CompressionFormat::Gzip | CompressionFormat::Bzip2 | CompressionFormat::Xz => {
            Err(OverlayError::Msg(format!(
                "live overlay commit supports uncompressed TAR and .tar.zst only \
                 (got {format:?}; gzip/bzip2/xz stay offline --commit-overlay)"
            )))
        }
        other => Err(OverlayError::Msg(format!(
            "live overlay commit supports uncompressed TAR and .tar.zst only (got {other:?})"
        ))),
    }
}

fn detect_live_commit_format(archive: &Path) -> Result<CompressionFormat> {
    detect_compression(archive).map_err(|e| {
        OverlayError::Msg(format!(
            "Failed to detect compression for '{}': {e}",
            archive.display()
        ))
    })
}

fn interval_disabled_err() -> OverlayError {
    OverlayError::Msg("live overlay commit disabled after reopen failure; remount required".into())
}

/// `.tar.zst` / `.tzst` / `.tar.zstd` only — not `.taz`.
pub fn name_suggests_tar_zst(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    let l = name.to_ascii_lowercase();
    l.ends_with(".tar.zst") || l.ends_with(".tzst") || l.ends_with(".tar.zstd")
}

fn looks_like_tar_zst(archive: &Path) -> Result<bool> {
    if name_suggests_tar_zst(archive) {
        return Ok(true);
    }
    let body = open_seekable_zstd(archive).map_err(|e| OverlayError::Msg(e.to_string()))?;
    body_looks_like_tar(&body).map_err(|e| OverlayError::Msg(e.to_string()))
}

const LAST_FRAME_WARN_BYTES: u64 = 64 * 1024 * 1024;

fn last_zstd_plain_needs_warn(plain: u64) -> bool {
    plain > LAST_FRAME_WARN_BYTES
}

fn warn_large_zstd_window(window_plain: u64) {
    if last_zstd_plain_needs_warn(window_plain) {
        log::warn!(
            "live .tar.zst commit will rewrite {window_plain} uncompressed \
             (large last frame); persist still copies the compressed file"
        );
    }
}

/// Grow last-N until the decoded suffix contains a TAR EOF (K6). Never refuse on size.
fn find_last_n_tar_window(archive: &Path, map: &ZstdFrameMap) -> Result<(usize, u64)> {
    if map.frames.is_empty() {
        return Err(OverlayError::Msg("TAR EOF not found (truncated?)".into()));
    }
    let last_plain = map.frames.last().map(|f| f.uncompressed_size).unwrap_or(0);
    warn_large_zstd_window(last_plain);
    let mut src = File::open(archive)?;
    for n in 1..=map.frames.len() {
        let from_idx = map.frames.len() - n;
        let window_plain: u64 = map.frames[from_idx..]
            .iter()
            .map(|f| f.uncompressed_size)
            .sum();
        if n > 1 {
            warn_large_zstd_window(window_plain);
        }
        let mut suffix = tempfile::spooled_tempfile(DEFAULT_MEMORY_CAP as usize);
        decode_zstd_frames_to(&mut src, map, from_idx, &mut suffix)
            .map_err(|e| OverlayError::Msg(e.to_string()))?;
        suffix.seek(SeekFrom::Start(0))?;
        let stream_offset = map.frames[from_idx].uncompressed_offset;
        // The window must both contain the TAR EOF and start at a parseable
        // member boundary (or be pure padding). A member spanning the whole
        // window has no findable data end — grow the window instead of
        // risking a miscut.
        let has_eof = find_last_tar_eof(&mut suffix, stream_offset)?.is_some();
        let has_boundary = window_has_member_boundary(&mut suffix, stream_offset)
            .map_err(|e| OverlayError::Msg(e.to_string()))?;
        if has_eof && has_boundary {
            return Ok((from_idx, stream_offset));
        }
    }
    Err(OverlayError::Msg(
        "TAR EOF / member boundary not found (truncated?)".into(),
    ))
}

enum TarZstPathClass {
    OverlayOnly,
    LastWindow,
}

fn tar_offsetheaders_in(fi: &FileInfo) -> impl Iterator<Item = u64> + '_ {
    fi.userdata.iter().filter_map(|u| match u {
        UserData::Tar(t) => t.offsetheader,
        _ => None,
    })
}

fn lookup_version(base: &dyn MountSource, path: &str, i: i32) -> Option<FileInfo> {
    // Always probe `.versions/{i}` first. `FileVersionLayer(AutoMount)` reports
    // `versions() == 1` (AutoMount uses the trait default) while older copies
    // only exist at `{path}.versions/{i}`.
    if i >= 1 {
        if let Some(fi) = base.lookup(&format!("{path}.versions/{i}"), 0) {
            return Some(fi);
        }
    }
    base.lookup(path, i)
}

fn archive_lookup_path(rel: &str) -> String {
    let n = normalize_archive_rel_path(rel);
    if n.is_empty() {
        "/".into()
    } else {
        format!("/{n}")
    }
}

fn all_tar_offsetheaders(base: &dyn MountSource, path: &str) -> Result<Vec<u64>> {
    let path = archive_lookup_path(path);
    let mut out = Vec::new();
    // Walk `.versions/{i}` until miss. Do not stop at `versions()` — AutoMount
    // (and similar wrappers) report 1 even when FileVersionLayer exposes more.
    const MAX_VERSION_WALK: i32 = 1024;
    for i in 1..=MAX_VERSION_WALK {
        match base.lookup(&format!("{path}.versions/{i}"), 0) {
            Some(fi) => out.extend(tar_offsetheaders_in(&fi)),
            None => break,
        }
    }
    let nver = base.versions(&path);
    if nver == 0 && out.is_empty() {
        if let Some(fi) = base.lookup(&path, 0) {
            out.extend(tar_offsetheaders_in(&fi));
            if out.is_empty() {
                return Err(cannot_classify_err(&path));
            }
        }
        return Ok(out);
    }
    for i in 1..=nver {
        if let Some(fi) = lookup_version(base, &path, i as i32) {
            out.extend(tar_offsetheaders_in(&fi));
        }
    }
    if let Some(fi) = base.lookup(&path, 0) {
        out.extend(tar_offsetheaders_in(&fi));
    }
    out.sort_unstable();
    out.dedup();
    if out.is_empty() {
        return Err(cannot_classify_err(&path));
    }
    Ok(out)
}

fn cannot_classify_err(path: &str) -> OverlayError {
    OverlayError::Msg(format!(
        "live overlay commit for .tar.zst cannot classify '{path}' (no TAR offsetheader)"
    ))
}

fn earlier_frame_err(path: &str) -> OverlayError {
    let shown = archive_lookup_path(path);
    OverlayError::Msg(format!(
        "error: live overlay commit for .tar.zst is append-only (and last-frame replace/delete);\n\
               '{shown}' has a version in an earlier zstd frame\n\
               (delete would undelete that copy). The whole commit was skipped\n\
               (including pending appends). Undo the delete or omit\n\
               --commit-overlay-interval / --commit-overlay-on-exit."
    ))
}

fn classify_tar_zst_path(
    base: &dyn MountSource,
    path: &str,
    rewrite_window_start_uncomp: u64,
) -> Result<TarZstPathClass> {
    let ohs = all_tar_offsetheaders(base, path)?;
    if ohs.is_empty() {
        return Ok(TarZstPathClass::OverlayOnly);
    }
    if ohs.iter().any(|&oh| oh < rewrite_window_start_uncomp) {
        return Err(earlier_frame_err(path));
    }
    Ok(TarZstPathClass::LastWindow)
}

struct PendingUstar {
    path: String,
    host: PathBuf,
    kind: PendingKind,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime: u64,
}

enum PendingKind {
    FileOnDisk { size: u64 },
    Directory,
    Symlink { target: String },
}

impl PendingUstar {
    fn as_member(&self) -> UstarMember<'_> {
        UstarMember {
            path: &self.path,
            payload: match &self.kind {
                PendingKind::FileOnDisk { size } => UstarPayload::FileOnDisk {
                    path: &self.host,
                    size: *size,
                },
                PendingKind::Directory => UstarPayload::Directory,
                PendingKind::Symlink { target } => UstarPayload::Symlink { target },
            },
            mode: self.mode,
            uid: self.uid,
            gid: self.gid,
            mtime: self.mtime,
        }
    }
}

fn reset_overlay_dir(root: &Path) -> Result<()> {
    let rd = match fs::read_dir(root) {
        Ok(r) => r,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    for ent in rd.flatten() {
        let name = ent.file_name();
        let name_s = name.to_string_lossy();
        if name_s == HIDDEN_DB
            || name_s == format!("{HIDDEN_DB}-journal")
            || name_s == format!("{HIDDEN_DB}-shm")
            || name_s == format!("{HIDDEN_DB}-wal")
        {
            continue;
        }
        let p = ent.path();
        let meta = match fs::symlink_metadata(&p) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.file_type().is_dir() {
            fs::remove_dir_all(&p)?;
        } else {
            fs::remove_file(&p)?;
        }
    }
    Ok(())
}

fn is_uncompressed_tar(path: &Path) -> Result<bool> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = File::open(path)?;
    // Reject common compression magics
    let mut magic = [0u8; 6];
    let n = f.read(&mut magic)?;
    if n >= 2 && magic[0] == 0x1f && magic[1] == 0x8b {
        return Ok(false); // gzip
    }
    if n >= 3 && &magic[..3] == b"BZh" {
        return Ok(false);
    }
    if n >= 6 && &magic[..6] == b"\xFD7zXZ\0" {
        return Ok(false);
    }
    if n >= 4 && &magic[..4] == b"\x28\xb5\x2f\xfd" {
        return Ok(false);
    }
    // ustar at 257
    f.seek(SeekFrom::Start(257))?;
    let mut ustar = [0u8; 5];
    let n = f.read(&mut ustar)?;
    if n == 5 && (&ustar == b"ustar" || ustar.starts_with(b"ustar") || &ustar == b"GNU  ") {
        return Ok(true);
    }
    Ok(is_posix_or_gnu_empty_tar(&mut f)?)
}

/// POSIX/GNU empty TAR: 1024..=10240, 512-aligned, all-zero. Reads at most 10 KiB.
fn is_posix_or_gnu_empty_tar(f: &mut File) -> io::Result<bool> {
    let n = f.metadata()?.len();
    if !(1024..=10240).contains(&n) || n % 512 != 0 {
        return Ok(false);
    }
    f.seek(SeekFrom::Start(0))?;
    let mut buf = [0u8; 10240];
    let len = n as usize;
    f.read_exact(&mut buf[..len])?;
    Ok(buf[..len].iter().all(|&b| b == 0))
}

/// Resolve a GNU tar binary (`tar` on Linux, often `gtar` via Homebrew on macOS).
fn find_gnu_tar() -> Option<PathBuf> {
    for name in ["gtar", "gnutar", "tar"] {
        let Ok(out) = Command::new(name).arg("--version").output() else {
            continue;
        };
        let text = String::from_utf8_lossy(&out.stdout);
        if text.contains("GNU tar") {
            return Some(PathBuf::from(name));
        }
    }
    None
}

fn ensure_gnu_tar() -> Result<()> {
    if find_gnu_tar().is_some() {
        return Ok(());
    }
    Err(OverlayError::Msg(
        "Currently, GNU tar is required for --commit-overlay \
         (install `gtar` via Homebrew on macOS, or use Linux GNU tar)."
            .into(),
    ))
}

fn tar_env_command() -> Command {
    let bin = find_gnu_tar().unwrap_or_else(|| PathBuf::from("tar"));
    let mut cmd = Command::new(bin);
    // Locale C for reproducible/stable messages (Python run_without_locale)
    cmd.env("LC_ALL", "C");
    cmd.env("LC_LANG", "C");
    cmd.env("LANGUAGE", "C");
    // Clear LC_* that might already be set by clearing via env_clear is too aggressive;
    // setting LC_ALL=C is enough for most systems.
    cmd
}

struct WalkEntry {
    path: PathBuf,
    is_dir: bool,
}

/// Files + empty directories under `root` (topdown=False equivalent for empty dirs).
fn walkdir_files_and_empty_dirs(root: &Path) -> Result<Vec<WalkEntry>> {
    let mut out = Vec::new();
    fn walk(dir: &Path, root: &Path, out: &mut Vec<WalkEntry>) -> Result<()> {
        let mut files = Vec::new();
        let mut dirs = Vec::new();
        let rd = match fs::read_dir(dir) {
            Ok(r) => r,
            Err(_) => return Ok(()),
        };
        for ent in rd.flatten() {
            let p = ent.path();
            let ft = ent.file_type()?;
            if ft.is_dir() {
                dirs.push(p);
            } else if ft.is_file() || ft.is_symlink() {
                files.push(p);
            }
        }
        for d in &dirs {
            walk(d, root, out)?;
        }
        for f in files {
            out.push(WalkEntry {
                path: f,
                is_dir: false,
            });
        }
        // Empty directory (no files; may still have subdirs already walked)
        if dirs.is_empty() {
            // re-check: empty of files and dirs
            let empty = fs::read_dir(dir)?.next().is_none();
            if empty && dir != root {
                out.push(WalkEntry {
                    path: dir.to_path_buf(),
                    is_dir: true,
                });
            }
        } else {
            // Python: if not filenames and dirpath: append empty folder
            // Only when this dir has no filenames (even if it has subdirs that had content)
            let has_file = fs::read_dir(dir)?.any(|e| {
                e.ok()
                    .map(|e| {
                        e.file_type()
                            .map(|t| t.is_file() || t.is_symlink())
                            .unwrap_or(false)
                    })
                    .unwrap_or(false)
            });
            if !has_file && dir != root {
                // Still append dirpath if no files directly — matches Python "not filenames"
                out.push(WalkEntry {
                    path: dir.to_path_buf(),
                    is_dir: true,
                });
            }
        }
        Ok(())
    }
    walk(root, root, &mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command as StdCommand;
    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipArchive, ZipWriter};

    fn write_zero_file(path: &Path, n: usize) {
        fs::write(path, vec![0u8; n]).unwrap();
    }

    /// Regression: POSIX empty TAR is recognized as uncompressed TAR.
    #[test]
    fn is_uncompressed_tar_posix_empty_1024_zeros() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.tar");
        {
            let mut f = File::create(&path).unwrap();
            ratarmount_formats_tar::write_tar_eof(&mut f).unwrap();
        }
        assert!(
            is_uncompressed_tar(&path).unwrap(),
            "1024-zero POSIX empty TAR"
        );
        assert!(
            !ratarmount_compress::looks_like_tar(&path).unwrap(),
            "looks_like_tar must stay false on 1024 zeros"
        );
    }

    #[test]
    fn is_uncompressed_tar_gnu_empty_10240_zeros() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.tar");
        write_zero_file(&path, 10240);
        assert!(is_uncompressed_tar(&path).unwrap());
    }

    #[test]
    fn is_uncompressed_tar_rejects_too_short_or_unaligned() {
        let dir = tempfile::tempdir().unwrap();
        for n in [0usize, 512, 1025] {
            let path = dir.path().join(format!("z{n}.tar"));
            write_zero_file(&path, n);
            assert!(
                !is_uncompressed_tar(&path).unwrap(),
                "{n}-byte zeros must not be an empty TAR"
            );
        }
    }

    #[test]
    fn is_uncompressed_tar_rejects_over_10240_zero_head_tail_dirty_middle() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dirty.tar");
        let mut buf = vec![0u8; 20 * 1024];
        buf[12 * 1024] = 1;
        fs::write(&path, &buf).unwrap();
        assert!(!is_uncompressed_tar(&path).unwrap());
    }

    #[test]
    fn warn_large_zstd_window_1024_one_frame_does_not_warn() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.tar.zst");
        let mut eof = Vec::new();
        ratarmount_formats_tar::write_tar_eof(&mut eof).unwrap();
        let zst = ratarmount_compress::encode_zstd_frame(&eof, 3).unwrap();
        fs::write(&path, zst).unwrap();
        let map = scan_zstd_frames_path(&path).unwrap();
        assert_eq!(map.frames.len(), 1);
        assert_eq!(map.frames[0].uncompressed_size, 1024);
        assert!(!last_zstd_plain_needs_warn(map.frames[0].uncompressed_size));
    }

    #[test]
    fn warn_large_zstd_window_last_frame_over_64mib_warns() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.tar.zst");
        let plain = vec![0u8; (LAST_FRAME_WARN_BYTES as usize) + 1];
        let zst = ratarmount_compress::encode_zstd_frame(&plain, 3).unwrap();
        fs::write(&path, zst).unwrap();
        let map = scan_zstd_frames_path(&path).unwrap();
        assert_eq!(map.frames.len(), 1);
        assert!(map.frames[0].uncompressed_size > LAST_FRAME_WARN_BYTES);
        assert!(last_zstd_plain_needs_warn(map.frames[0].uncompressed_size));
    }

    fn write_sample_zip(path: &Path, members: &[(&str, &[u8], CompressionMethod)]) {
        let file = File::create(path).unwrap();
        let mut zw = ZipWriter::new(file);
        for (name, data, method) in members {
            let opts = SimpleFileOptions::default().compression_method(*method);
            zw.start_file(*name, opts).unwrap();
            zw.write_all(data).unwrap();
        }
        zw.finish().unwrap();
    }

    /// Regression: ZIP --commit-overlay add file (full rebuild) → reopen list/read.
    /// Symptom: commit-overlay rejected non-TAR archives (upstream #154).
    #[test]
    fn commit_overlay_zip_add_file() {
        let dir = tempfile::tempdir().unwrap();
        let zip_path = dir.path().join("a.zip");
        write_sample_zip(
            &zip_path,
            &[
                ("old.txt", b"old zip\n", CompressionMethod::Stored),
                ("nested/keep.txt", b"keep me\n", CompressionMethod::Deflated),
            ],
        );

        let overlay = dir.path().join("ov");
        fs::create_dir_all(&overlay).unwrap();
        let base = Arc::new(NullBase) as Arc<dyn MountSource>;
        {
            let _ov = WriteOverlay::new(base, &overlay).unwrap();
            fs::write(overlay.join("new.txt"), b"hello zip commit\n").unwrap();
        }

        let opts = CommitOverlayOptions {
            yes: true,
            debug: 0,
        };
        commit_overlay(&overlay, &zip_path, &opts).expect("commit_overlay zip");

        // Still a ZIP after commit
        let magic = fs::read(&zip_path).unwrap();
        assert!(
            magic.len() >= 4 && &magic[..2] == b"PK",
            "archive should remain ZIP after commit"
        );

        let file = File::open(&zip_path).unwrap();
        let mut archive = ZipArchive::new(file).unwrap();
        let names: Vec<String> = (0..archive.len())
            .filter_map(|i| archive.name_for_index(i).map(|s| s.to_string()))
            .collect();
        assert!(
            names
                .iter()
                .any(|n| normalize_archive_rel_path(n) == "old.txt"),
            "zip listing: {names:?}"
        );
        assert!(
            names
                .iter()
                .any(|n| normalize_archive_rel_path(n) == "nested/keep.txt"),
            "zip listing: {names:?}"
        );
        assert!(
            names
                .iter()
                .any(|n| normalize_archive_rel_path(n) == "new.txt"),
            "zip listing: {names:?}"
        );

        // Read overlay-added content
        {
            let mut f = archive.by_name("new.txt").unwrap();
            let mut body = String::new();
            f.read_to_string(&mut body).unwrap();
            assert_eq!(body, "hello zip commit\n");
        }
        // Unchanged stored member still readable
        {
            let mut f = archive.by_name("old.txt").unwrap();
            let mut body = String::new();
            f.read_to_string(&mut body).unwrap();
            assert_eq!(body, "old zip\n");
        }
        // Unchanged deflated member still readable
        {
            let mut f = archive.by_name("nested/keep.txt").unwrap();
            let mut body = String::new();
            f.read_to_string(&mut body).unwrap();
            assert_eq!(body, "keep me\n");
        }
    }

    /// Regression: ZIP commit replaces existing member and honors DB delete.
    #[test]
    fn commit_overlay_zip_replace_and_delete() {
        let dir = tempfile::tempdir().unwrap();
        let zip_path = dir.path().join("b.zip");
        write_sample_zip(
            &zip_path,
            &[
                ("keep.txt", b"keep\n", CompressionMethod::Stored),
                ("gone.txt", b"remove me\n", CompressionMethod::Stored),
                ("mut.txt", b"old mut\n", CompressionMethod::Deflated),
            ],
        );

        let overlay = dir.path().join("ov");
        fs::create_dir_all(&overlay).unwrap();
        let base = Arc::new(NullBase) as Arc<dyn MountSource>;
        {
            let ov = WriteOverlay::new(base, &overlay).unwrap();
            // Replace mut.txt via overlay file (also marks delete+append on commit walk)
            fs::write(overlay.join("mut.txt"), b"new mut\n").unwrap();
            // Delete gone.txt in overlay DB (base would have had it)
            // NullBase has no files; insert deleted row directly to simulate unlink of base path.
            {
                let db = ov.db.lock().expect("db");
                db.execute(
                    r#"INSERT OR REPLACE INTO "files" (path,name,deleted) VALUES ('','gone.txt',1)"#,
                    [],
                )
                .unwrap();
            }
            // Drop overlay so exclusive SQLite lock is released before commit.
            drop(ov);
        }

        let opts = CommitOverlayOptions {
            yes: true,
            debug: 0,
        };
        commit_overlay(&overlay, &zip_path, &opts).expect("commit_overlay zip replace/delete");

        let file = File::open(&zip_path).unwrap();
        let mut archive = ZipArchive::new(file).unwrap();
        let names: Vec<String> = (0..archive.len())
            .filter_map(|i| archive.name_for_index(i).map(|s| s.to_string()))
            .collect();
        assert!(
            names
                .iter()
                .any(|n| normalize_archive_rel_path(n) == "keep.txt"),
            "{names:?}"
        );
        assert!(
            !names
                .iter()
                .any(|n| normalize_archive_rel_path(n) == "gone.txt"),
            "gone.txt should be deleted: {names:?}"
        );
        assert!(
            names
                .iter()
                .any(|n| normalize_archive_rel_path(n) == "mut.txt"),
            "{names:?}"
        );
        let mut f = archive.by_name("mut.txt").unwrap();
        let mut body = String::new();
        f.read_to_string(&mut body).unwrap();
        assert_eq!(body, "new mut\n");
    }

    #[test]
    fn is_zip_archive_detects_pk_magic() {
        let dir = tempfile::tempdir().unwrap();
        let zip_path = dir.path().join("c.zip");
        write_sample_zip(&zip_path, &[("x", b"y", CompressionMethod::Stored)]);
        assert!(is_zip_archive(&zip_path).unwrap());

        let tarish = dir.path().join("not-a-zip.bin");
        fs::write(&tarish, b"ustar is not here but also not PK").unwrap();
        assert!(!is_zip_archive(&tarish).unwrap());
    }

    #[test]
    fn commit_overlay_add_file() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("data");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("old.txt"), b"old\n").unwrap();
        let tar = dir.path().join("a.tar");
        let st = StdCommand::new("tar")
            .args(["-cf"])
            .arg(&tar)
            .arg("-C")
            .arg(&src)
            .arg("old.txt")
            .status()
            .unwrap();
        assert!(st.success());

        let overlay = dir.path().join("ov");
        fs::create_dir_all(&overlay).unwrap();
        // Create hidden DB so schema exists (optional for append-only)
        let base = Arc::new(NullBase) as Arc<dyn MountSource>;
        {
            let _ov = WriteOverlay::new(base, &overlay).unwrap();
            fs::write(overlay.join("new.txt"), b"hello commit\n").unwrap();
            // Drop overlay so exclusive SQLite lock is released before commit.
        }

        let opts = CommitOverlayOptions {
            yes: true,
            debug: 0,
        };
        match commit_overlay(&overlay, &tar, &opts) {
            Ok(_) => {}
            Err(e) if e.to_string().contains("GNU tar") => {
                eprintln!("skip: {e}");
                return;
            }
            Err(e) => panic!("commit_overlay: {e}"),
        }

        let list = StdCommand::new("tar")
            .args(["-tf"])
            .arg(&tar)
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&list.stdout);
        assert!(text.contains("new.txt"), "tar listing: {text}");
        assert!(text.contains("old.txt"), "tar listing: {text}");
    }

    #[test]
    fn commit_overlay_add_file_tar_gz() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("data");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("old.txt"), b"old gz\n").unwrap();
        let tgz = dir.path().join("a.tar.gz");
        let st = StdCommand::new("tar")
            .args(["-czf"])
            .arg(&tgz)
            .arg("-C")
            .arg(&src)
            .arg("old.txt")
            .status()
            .unwrap();
        assert!(st.success());

        // Sanity: starts with gzip magic
        let magic = fs::read(&tgz).unwrap();
        assert!(magic.len() >= 2 && magic[0] == 0x1f && magic[1] == 0x8b);

        let overlay = dir.path().join("ov");
        fs::create_dir_all(&overlay).unwrap();
        let base = Arc::new(NullBase) as Arc<dyn MountSource>;
        {
            let _ov = WriteOverlay::new(base, &overlay).unwrap();
            fs::write(overlay.join("new.txt"), b"hello gzip commit\n").unwrap();
        }

        let opts = CommitOverlayOptions {
            yes: true,
            debug: 0,
        };
        match commit_overlay(&overlay, &tgz, &opts) {
            Ok(_) => {}
            Err(e) if e.to_string().contains("GNU tar") => {
                eprintln!("skip: {e}");
                return;
            }
            Err(e) => panic!("commit_overlay tar.gz: {e}"),
        }

        // Still gzip-compressed after commit
        let magic = fs::read(&tgz).unwrap();
        assert!(
            magic.len() >= 2 && magic[0] == 0x1f && magic[1] == 0x8b,
            "archive should remain gzip after commit"
        );

        // List via tar -tzf (or gunzip | tar if needed)
        let list = StdCommand::new("tar")
            .args(["-tzf"])
            .arg(&tgz)
            .output()
            .unwrap();
        assert!(
            list.status.success(),
            "tar -tzf failed: {}",
            String::from_utf8_lossy(&list.stderr)
        );
        let text = String::from_utf8_lossy(&list.stdout);
        assert!(text.contains("new.txt"), "tar.gz listing: {text}");
        assert!(text.contains("old.txt"), "tar.gz listing: {text}");

        // Extract new.txt and verify content
        let extract = dir.path().join("out");
        fs::create_dir_all(&extract).unwrap();
        let st = StdCommand::new("tar")
            .args(["-xzf"])
            .arg(&tgz)
            .arg("-C")
            .arg(&extract)
            .arg("new.txt")
            .status()
            .unwrap();
        assert!(st.success());
        let body = fs::read_to_string(extract.join("new.txt")).unwrap();
        assert_eq!(body, "hello gzip commit\n");
    }

    /// Minimal immutable empty base for WriteOverlay construction in tests.
    struct NullBase;
    impl MountSource for NullBase {
        fn list(&self, _path: &str) -> Option<ListResult> {
            Some(ListResult::Infos(Default::default()))
        }
        fn lookup(&self, path: &str, _: i32) -> Option<FileInfo> {
            if path == "/" {
                Some(create_root_file_info())
            } else {
                None
            }
        }
        fn open(&self, _: &FileInfo, _: i32) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
            Err(io::Error::new(io::ErrorKind::NotFound, "null base"))
        }
        fn is_immutable(&self) -> bool {
            true
        }
    }

    /// Regression: overlay open/create must not follow host symlinks outside root.
    ///
    /// Symptom: `realpath` is join+normpath only; `libc::open` / `File::create`
    /// follow symlinks, so a pre-seeded symlink under the overlay folder can
    /// redirect writes to arbitrary host paths.
    #[test]
    fn overlay_rejects_symlink_escape_outside_root() {
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        let outside_file = outside.join("secret.txt");
        fs::write(&outside_file, b"secret-data").unwrap();

        let overlay = dir.path().join("ov");
        fs::create_dir_all(&overlay).unwrap();
        // Plant a file symlink and a directory symlink pointing outside the overlay.
        std::os::unix::fs::symlink(&outside_file, overlay.join("escape")).unwrap();
        std::os::unix::fs::symlink(&outside, overlay.join("outdir")).unwrap();

        let base = Arc::new(NullBase) as Arc<dyn MountSource>;
        let ov = WriteOverlay::new(base, &overlay).unwrap();

        // create_file through file symlink must fail and not clobber outside content.
        let err = ov.create_file("/escape", 0o644);
        assert!(
            err.is_err(),
            "create_file through escape symlink must fail, got Ok"
        );
        assert_eq!(
            fs::read(&outside_file).unwrap(),
            b"secret-data",
            "outside file must remain untouched after create_file"
        );

        // open_overlay_fd must not follow the escape symlink either.
        let err = ov.open_overlay_fd("/escape", libc::O_RDWR | libc::O_CREAT);
        assert!(
            err.is_err(),
            "open_overlay_fd through escape symlink must fail, got Ok"
        );
        assert_eq!(
            fs::read(&outside_file).unwrap(),
            b"secret-data",
            "outside file must remain untouched after open_overlay_fd"
        );

        // create under a directory symlink must not write outside the overlay.
        let err = ov.create_file("/outdir/pwned.txt", 0o644);
        assert!(
            err.is_err(),
            "create_file under dir symlink must fail, got Ok"
        );
        assert!(
            !outside.join("pwned.txt").exists(),
            "must not create files outside overlay via dir symlink"
        );

        // mkdir via escape dir symlink must fail.
        let err = ov.mkdir("/outdir/evil-dir", 0o755);
        assert!(err.is_err(), "mkdir under dir symlink must fail, got Ok");
        assert!(
            !outside.join("evil-dir").exists(),
            "must not mkdir outside overlay via dir symlink"
        );

        // Normal create inside overlay still works.
        let fd = ov.create_file("/safe.txt", 0o644).expect("safe create");
        assert!(fd >= 0);
        unsafe {
            libc::close(fd);
        }
        assert!(overlay.join("safe.txt").exists() || ov.root().join("safe.txt").exists());
    }

    /// Counts `list()` so we can prove WriteOverlay uses `base.list_dirents`.
    struct ListCallCounter {
        inner: ratarmount_formats_zip::ZipMountSource,
        list_calls: std::sync::atomic::AtomicUsize,
    }

    impl MountSource for ListCallCounter {
        fn list(&self, path: &str) -> Option<ListResult> {
            self.list_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.list(path)
        }

        fn list_dirents(&self, path: &str) -> Option<Vec<CheapDirent>> {
            self.inner.list_dirents(path)
        }

        fn lookup(&self, path: &str, file_version: i32) -> Option<FileInfo> {
            self.inner.lookup(path, file_version)
        }

        fn versions(&self, path: &str) -> u32 {
            self.inner.versions(path)
        }

        fn open(
            &self,
            file_info: &FileInfo,
            buffering: i32,
        ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
            self.inner.open(file_info, buffering)
        }

        fn is_immutable(&self) -> bool {
            self.inner.is_immutable()
        }
    }

    fn zip_counted_base() -> (
        tempfile::TempDir,
        Arc<ListCallCounter>,
        &'static [u8],
        &'static [u8],
    ) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("overlay-base.zip");
        let a: &'static [u8] = b"alpha-payload\n";
        let b: &'static [u8] = b"bravo-bytes-here\n";
        write_sample_zip(
            &path,
            &[
                ("a.txt", a, CompressionMethod::Stored),
                ("b.bin", b, CompressionMethod::Stored),
            ],
        );
        let opts = ratarmount_core::OpenOptions {
            index_in_memory: true,
            ..ratarmount_core::OpenOptions::default()
        };
        let zip = ratarmount_formats_zip::ZipMountSource::open(&path, None, &opts, "test", true)
            .expect("open zip");
        let counted = Arc::new(ListCallCounter {
            inner: zip,
            list_calls: std::sync::atomic::AtomicUsize::new(0),
        });
        (dir, counted, a, b)
    }

    /// Regression: `-w` readdir called `base.list()`.
    #[test]
    fn overlay_list_dirents_base_plus_overlay_minus_deletes_without_base_list() {
        let (dir, counted, _a, b) = zip_counted_base();
        let overlay = dir.path().join("ov");
        fs::create_dir_all(&overlay).unwrap();
        let ov = WriteOverlay::new(Arc::clone(&counted) as Arc<dyn MountSource>, &overlay)
            .expect("overlay");

        ov.unlink("/a.txt").expect("delete base a.txt");
        let fd = ov.create_file("/c.txt", 0o644).expect("overlay create");
        unsafe {
            libc::close(fd);
        }
        fs::write(ov.root().join("c.txt"), b"overlay-only\n").unwrap();

        let dents = ov.list_dirents("/").expect("cheap overlay dirents");
        assert_eq!(
            counted.list_calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "WriteOverlay::list_dirents must not call base.list() (fat FileInfo map)"
        );
        let by_name: BTreeMap<_, _> = dents.into_iter().map(|d| (d.name, d.size)).collect();
        assert!(
            !by_name.contains_key("a.txt"),
            "deleted base name must be gone: {by_name:?}"
        );
        assert_eq!(by_name.get("b.bin").copied(), Some(b.len() as u64));
        assert_eq!(
            by_name.get("c.txt").copied(),
            Some(b"overlay-only\n".len() as u64)
        );
        assert!(
            !by_name.keys().any(|n| n.starts_with(HIDDEN_DB)),
            "overlay DB must stay hidden: {by_name:?}"
        );
    }

    /// Regression: create-then-list reported leftover base size.
    #[test]
    fn overlay_list_dirents_create_empty_has_size_zero() {
        let (dir, counted, a, _b) = zip_counted_base();
        let overlay = dir.path().join("ov");
        fs::create_dir_all(&overlay).unwrap();
        let ov = WriteOverlay::new(Arc::clone(&counted) as Arc<dyn MountSource>, &overlay)
            .expect("overlay");

        assert!(
            !a.is_empty(),
            "base member must have a leftover size to regress against"
        );
        let fd = ov
            .create_file("/a.txt", 0o644)
            .expect("create empty overlay");
        unsafe {
            libc::close(fd);
        }

        let dents = ov.list_dirents("/").expect("cheap overlay dirents");
        assert_eq!(
            counted.list_calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "WriteOverlay::list_dirents must not call base.list()"
        );
        let a_dent = dents
            .iter()
            .find(|d| d.name == "a.txt")
            .expect("overlay-created a.txt");
        assert_eq!(
            a_dent.size,
            0,
            "create-then-list must not report leftover base size {}",
            a.len()
        );
    }

    fn make_tiny_tar(dir: &Path, members: &[(&str, &[u8])]) -> PathBuf {
        let tree = dir.join("tree");
        fs::create_dir_all(&tree).unwrap();
        for (name, body) in members {
            let p = tree.join(name);
            if let Some(parent) = p.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(&p, body).unwrap();
        }
        let tar = dir.join("a.tar");
        let mut cmd = StdCommand::new("tar");
        cmd.arg("-cf").arg(&tar).arg("-C").arg(&tree);
        for (name, _) in members {
            cmd.arg(name);
        }
        assert!(cmd.status().unwrap().success());
        tar
    }

    #[test]
    fn overlay_rename_and_symlink_persist() {
        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("ov");
        fs::create_dir_all(&overlay).unwrap();
        let ov = WriteOverlay::new(Arc::new(NullBase) as Arc<dyn MountSource>, &overlay).unwrap();
        let fd = ov.create_file("/src.txt", 0o644).unwrap();
        unsafe {
            libc::close(fd);
        }
        fs::write(overlay.join("src.txt"), b"renamed-bytes\n").unwrap();
        ov.rename("/src.txt", "/dst.txt").expect("rename");
        assert!(ov.lookup("/src.txt", 0).is_none());
        let fi = ov.lookup("/dst.txt", 0).expect("dst");
        assert_eq!(fi.size, b"renamed-bytes\n".len() as u64);

        ov.create_symlink("/link", "dst.txt").expect("symlink");
        let link = ov.lookup("/link", 0).expect("link info");
        assert!(ratarmount_core::is_lnk_mode(link.mode));
        assert_eq!(link.linkname, "dst.txt");
        let dents = ov.list_dirents("/").unwrap();
        let names: Vec<_> = dents.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"dst.txt"), "{names:?}");
        assert!(names.contains(&"link"), "{names:?}");
    }

    /// Regression: renaming (or COW-ing) a base symlink must materialize a
    /// symlink in the overlay — copying its "content" yielded an empty
    /// regular file, and a later commit dropped the link member entirely.
    #[test]
    fn rename_base_symlink_stays_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let base_dir = dir.path().join("base");
        fs::create_dir_all(&base_dir).unwrap();
        fs::write(base_dir.join("target.txt"), b"payload\n").unwrap();
        std::os::unix::fs::symlink("target.txt", base_dir.join("link")).unwrap();

        let overlay = dir.path().join("ov");
        fs::create_dir_all(&overlay).unwrap();
        let base = crate::folder::FolderMountSource::new(&base_dir).unwrap();
        let ov = WriteOverlay::new(Arc::new(base) as Arc<dyn MountSource>, &overlay).unwrap();

        ov.rename("/link", "/link2").expect("rename symlink");
        let meta = fs::symlink_metadata(overlay.join("link2")).expect("overlay link2");
        assert!(
            meta.file_type().is_symlink(),
            "rename must COW a symlink as a symlink, got {:?}",
            meta.file_type()
        );
        assert_eq!(
            fs::read_link(overlay.join("link2")).unwrap(),
            std::path::PathBuf::from("target.txt")
        );
        let fi = ov.lookup("/link2", 0).expect("lookup link2");
        assert!(ratarmount_core::is_lnk_mode(fi.mode));
        assert_eq!(fi.linkname, "target.txt");
        assert!(ov.lookup("/link", 0).is_none(), "old name must be gone");
    }

    /// Regression: rmdir must refuse non-empty union dirs (base children
    /// included) and non-directories — committing a bare dir tombstone would
    /// recursively delete or orphan the children depending on commit format.
    #[test]
    fn rmdir_refuses_nonempty_and_non_dir() {
        let dir = tempfile::tempdir().unwrap();
        let base_dir = dir.path().join("base");
        fs::create_dir_all(base_dir.join("full")).unwrap();
        fs::write(base_dir.join("full").join("a.txt"), b"a\n").unwrap();
        fs::create_dir_all(base_dir.join("empty")).unwrap();
        fs::write(base_dir.join("file.txt"), b"f\n").unwrap();

        let overlay = dir.path().join("ov");
        fs::create_dir_all(&overlay).unwrap();
        let base = crate::folder::FolderMountSource::new(&base_dir).unwrap();
        let ov = WriteOverlay::new(Arc::new(base) as Arc<dyn MountSource>, &overlay).unwrap();

        let err = ov.rmdir("/full").expect_err("non-empty base dir");
        assert!(
            err.to_string().contains("not empty"),
            "unexpected error: {err}"
        );
        let err = ov.rmdir("/file.txt").expect_err("file is not a dir");
        assert!(
            err.to_string().contains("not a directory"),
            "unexpected error: {err}"
        );
        let err = ov.rmdir("/missing").expect_err("missing path");
        assert!(
            err.to_string().contains("no such directory"),
            "unexpected error: {err}"
        );
        ov.rmdir("/empty").expect("empty dir rmdir");
        assert!(
            ov.lookup("/empty", 0).is_none(),
            "empty dir must be gone from the union view"
        );
        // Children of the refused dir are untouched.
        let fi = ov.lookup("/full/a.txt", 0).expect("child survives");
        assert_eq!(fi.size, 2);
    }

    /// Regression: rename must not delete the destination when the source
    /// COW fails — copy the source first, unlink the destination last.
    #[test]
    fn rename_keeps_destination_when_source_cow_fails() {
        struct FailOpenBase;
        impl MountSource for FailOpenBase {
            fn list(&self, _path: &str) -> Option<ListResult> {
                Some(ListResult::Infos(Default::default()))
            }
            fn lookup(&self, path: &str, _: i32) -> Option<FileInfo> {
                if path == "/" {
                    return Some(create_root_file_info());
                }
                if path == "/src" {
                    return Some(FileInfo {
                        size: 5,
                        mtime: 0.0,
                        mode: ratarmount_core::S_IFREG | 0o644,
                        linkname: String::new(),
                        uid: 0,
                        gid: 0,
                        userdata: vec![],
                    });
                }
                None
            }
            fn open(
                &self,
                _: &FileInfo,
                _: i32,
            ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
                Err(io::Error::new(io::ErrorKind::PermissionDenied, "boom"))
            }
            fn is_immutable(&self) -> bool {
                true
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("ov");
        fs::create_dir_all(&overlay).unwrap();
        let ov =
            WriteOverlay::new(Arc::new(FailOpenBase) as Arc<dyn MountSource>, &overlay).unwrap();
        let fd = ov.create_file("/dst", 0o644).unwrap();
        unsafe {
            libc::close(fd);
        }
        fs::write(overlay.join("dst"), b"precious\n").unwrap();

        let err = ov.rename("/src", "/dst").expect_err("source COW must fail");
        assert!(
            err.to_string().contains("boom"),
            "expected the COW error, got: {err}"
        );
        assert_eq!(
            fs::read(overlay.join("dst")).unwrap(),
            b"precious\n",
            "destination must survive a failed rename"
        );
        assert!(ov.lookup("/dst", 0).is_some(), "dst still listed");
    }

    #[test]
    fn live_commit_uncompressed_tar_add_replace_delete_no_duplicate() {
        let dir = tempfile::tempdir().unwrap();
        let old_payload = dir.path().join("old-expected.bin");
        fs::write(&old_payload, b"old-body\n").unwrap();
        let new_payload = dir.path().join("new-expected.bin");
        fs::write(&new_payload, b"new-body-unique\n").unwrap();
        let replaced_payload = dir.path().join("replaced-expected.bin");
        fs::write(&replaced_payload, b"replaced-body\n").unwrap();

        let tar = make_tiny_tar(
            dir.path(),
            &[
                ("old.txt", &fs::read(&old_payload).unwrap()),
                ("gone.txt", b"delete-me\n"),
                ("keep.txt", b"orig-keep\n"),
            ],
        );
        let _ = replaced_payload;

        let overlay = dir.path().join("ov");
        fs::create_dir_all(&overlay).unwrap();
        let opts = ratarmount_core::OpenOptions {
            index_in_memory: true,
            ..ratarmount_core::OpenOptions::default()
        };
        let mut materialised = None;
        let base = ratarmount_formats_tar::SqliteIndexedTar::create_index(
            &tar,
            &tar,
            None,
            &opts,
            "test",
            &mut materialised,
        )
        .expect("index tar");
        let ov = WriteOverlay::new(Arc::new(base) as Arc<dyn MountSource>, &overlay).unwrap();
        fs::write(overlay.join("new.txt"), fs::read(&new_payload).unwrap()).unwrap();
        fs::write(overlay.join("keep.txt"), b"replaced-body\n").unwrap();
        ov.unlink("/gone.txt").expect("mark gone deleted");

        match ov.commit_uncompressed_tar_atomic(&tar) {
            Ok(true) => {}
            Err(e) if e.to_string().contains("GNU tar") => {
                eprintln!("skip: {e}");
                return;
            }
            other => panic!("commit_uncompressed_tar_atomic: {other:?}"),
        }

        let list = StdCommand::new("tar")
            .args(["-tf"])
            .arg(&tar)
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&list.stdout);
        assert!(text.contains("new.txt"), "{text}");
        assert!(text.contains("old.txt"), "{text}");
        assert!(text.contains("keep.txt"), "{text}");
        assert!(
            !text.contains("gone.txt"),
            "deleted member still listed: {text}"
        );
        let new_count = text
            .lines()
            .filter(|l| l.trim_end_matches('/') == "new.txt")
            .count();
        assert_eq!(new_count, 1, "first commit must not duplicate: {text}");

        let extracted = dir.path().join("ex");
        fs::create_dir_all(&extracted).unwrap();
        assert!(StdCommand::new("tar")
            .args(["-xf"])
            .arg(&tar)
            .arg("-C")
            .arg(&extracted)
            .status()
            .unwrap()
            .success());
        assert!(
            fs::read(extracted.join("new.txt")).unwrap() == fs::read(&new_payload).unwrap(),
            "new.txt must cmp to overlay source file"
        );
        assert_eq!(
            fs::read(extracted.join("keep.txt")).unwrap(),
            b"replaced-body\n"
        );

        ov.reset_overlay_contents().expect("reset");
        assert!(!overlay.join("new.txt").exists());
        match ov.commit_uncompressed_tar_atomic(&tar) {
            Ok(false) => {}
            Ok(true) => panic!("second commit with empty overlay must be a no-op"),
            Err(e) => panic!("second commit: {e}"),
        }
        let list2 = StdCommand::new("tar")
            .args(["-tf"])
            .arg(&tar)
            .output()
            .unwrap();
        let text2 = String::from_utf8_lossy(&list2.stdout);
        let new_count2 = text2
            .lines()
            .filter(|l| l.trim_end_matches('/') == "new.txt")
            .count();
        assert_eq!(new_count2, 1, "second tick must not duplicate: {text2}");
    }

    #[test]
    fn live_commit_rejects_gzip_and_zip() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("t");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("a"), b"x").unwrap();
        let tgz = dir.path().join("a.tar.gz");
        let st = StdCommand::new("tar")
            .args(["-czf"])
            .arg(&tgz)
            .arg("-C")
            .arg(&src)
            .arg("a")
            .status()
            .unwrap();
        assert!(st.success());
        let err = live_commit_is_supported(&tgz).unwrap_err().to_string();
        assert!(err.contains("uncompressed"), "{err}");
        assert!(err.contains("gzip"), "{err}");

        let zip = dir.path().join("a.zip");
        write_sample_zip(&zip, &[("a", b"x", CompressionMethod::Stored)]);
        let err = live_commit_is_supported(&zip).unwrap_err().to_string();
        assert!(
            err.contains("ZIP") || err.contains("uncompressed TAR"),
            "{err}"
        );
    }

    fn generated_payload(tag: &str) -> Vec<u8> {
        format!("p-{tag}-{}\n", std::process::id()).into_bytes()
    }

    fn ustar_file<'a>(path: &'a str, bytes: &'a [u8]) -> UstarMember<'a> {
        UstarMember {
            path,
            payload: UstarPayload::File { bytes },
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime: 0,
        }
    }

    fn pack_tar(members: &[UstarMember<'_>]) -> Vec<u8> {
        let mut buf = Vec::new();
        ratarmount_formats_tar::write_ustar_members(&mut buf, members).unwrap();
        ratarmount_formats_tar::write_tar_eof(&mut buf).unwrap();
        buf
    }

    fn pack_tar_no_eof(members: &[UstarMember<'_>]) -> Vec<u8> {
        let mut buf = Vec::new();
        ratarmount_formats_tar::write_ustar_members(&mut buf, members).unwrap();
        buf
    }

    fn concat_zstd_frames(plains: &[&[u8]], with_seek_table: bool) -> Vec<u8> {
        let mut out = Vec::new();
        let mut entries = Vec::new();
        for p in plains {
            let f = ratarmount_compress::encode_zstd_frame(p, 3).unwrap();
            entries.push((f.len() as u32, p.len() as u32));
            out.extend_from_slice(&f);
        }
        if with_seek_table {
            out.extend_from_slice(&ratarmount_compress::build_seek_table_skippable(&entries));
        }
        out
    }

    /// One uncompressed TAR split across two zstd frames (EOF only in the last frame).
    fn write_split_tar_zst(
        path: &Path,
        first: &[UstarMember<'_>],
        last: &[UstarMember<'_>],
        with_seek_table: bool,
    ) {
        let f0 = pack_tar_no_eof(first);
        let mut f1 = pack_tar_no_eof(last);
        ratarmount_formats_tar::write_tar_eof(&mut f1).unwrap();
        fs::write(path, concat_zstd_frames(&[&f0, &f1], with_seek_table)).unwrap();
    }

    fn write_single_frame_tar_zst(path: &Path, members: &[UstarMember<'_>]) {
        let tar = pack_tar(members);
        fs::write(path, concat_zstd_frames(&[&tar], false)).unwrap();
    }

    fn write_complete_tar_frames_zst(path: &Path, frames: &[Vec<u8>]) {
        let refs: Vec<&[u8]> = frames.iter().map(|v| v.as_slice()).collect();
        fs::write(path, concat_zstd_frames(&refs, false)).unwrap();
    }

    fn reopen_tar_zst(
        path: &Path,
        ignore_zeros: bool,
    ) -> std::result::Result<Arc<dyn MountSource>, OverlayError> {
        let body = open_seekable_zstd(path).map_err(|e| OverlayError::Msg(e.to_string()))?;
        let opts = ratarmount_core::OpenOptions {
            index_in_memory: true,
            ignore_zeros,
            ..ratarmount_core::OpenOptions::default()
        };
        ratarmount_formats_tar::SqliteIndexedTar::create_index_body(path, body, None, &opts, "test")
            .map(|t| Arc::new(t) as Arc<dyn MountSource>)
            .map_err(|e| OverlayError::Msg(e.to_string()))
    }

    fn open_tar_zst_base(path: &Path, ignore_zeros: bool) -> Arc<dyn MountSource> {
        reopen_tar_zst(path, ignore_zeros).expect("index tar.zst")
    }

    fn read_member(src: &dyn MountSource, path: &str) -> Vec<u8> {
        let fi = src
            .lookup(path, 0)
            .unwrap_or_else(|| panic!("missing {path}"));
        src.read(&fi, fi.size as usize, 0).expect("read member")
    }

    fn overlay_with_base(base: Arc<dyn MountSource>, overlay: &Path) -> WriteOverlay {
        fs::create_dir_all(overlay).unwrap();
        WriteOverlay::new(base, overlay).unwrap()
    }

    fn seek_table_footer_present(bytes: &[u8]) -> bool {
        if bytes.len() < 4 {
            return false;
        }
        let n = bytes.len();
        u32::from_le_bytes(bytes[n - 4..].try_into().unwrap()) == 0x8F92_EAB1
    }

    #[test]
    fn live_commit_accepts_tar_zst() {
        let dir = tempfile::tempdir().unwrap();
        let seed = generated_payload("accept");
        let path = dir.path().join("a.tar.zst");
        write_single_frame_tar_zst(&path, &[ustar_file("seed.txt", &seed)]);
        live_commit_is_supported(&path).expect(".tar.zst must be accepted");

        let tzst = dir.path().join("b.tzst");
        write_single_frame_tar_zst(&tzst, &[ustar_file("seed.txt", &seed)]);
        live_commit_is_supported(&tzst).expect(".tzst must be accepted");

        let zstd = dir.path().join("c.tar.zstd");
        write_single_frame_tar_zst(&zstd, &[ustar_file("seed.txt", &seed)]);
        live_commit_is_supported(&zstd).expect(".tar.zstd must be accepted");

        let plain = dir.path().join("plain.zst");
        let not_tar = ratarmount_compress::encode_zstd_frame(b"not-a-tar-body", 3).unwrap();
        fs::write(&plain, not_tar).unwrap();
        let err = live_commit_is_supported(&plain).unwrap_err().to_string();
        assert!(
            err.contains("plain .zst") && err.contains("not a TAR"),
            "{err}"
        );
    }

    #[test]
    fn live_commit_tar_zst_multi_frame_append() {
        let dir = tempfile::tempdir().unwrap();
        let prefix = generated_payload("mf-prefix");
        let last = generated_payload("mf-last");
        let extra = generated_payload("mf-new");
        let archive = dir.path().join("a.tar.zst");
        write_split_tar_zst(
            &archive,
            &[ustar_file("prefix.txt", &prefix)],
            &[ustar_file("last.txt", &last)],
            false,
        );
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
        fs::write(overlay.join("new.txt"), &extra).unwrap();

        assert!(ov
            .commit_live(&archive, |p| reopen_tar_zst(p, false))
            .expect("commit"));
        let src = open_tar_zst_base(&archive, false);
        assert_eq!(read_member(src.as_ref(), "/prefix.txt"), prefix);
        assert_eq!(read_member(src.as_ref(), "/last.txt"), last);
        assert_eq!(read_member(src.as_ref(), "/new.txt"), extra);
    }

    #[test]
    fn live_commit_tar_zst_single_frame_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let seed = generated_payload("sf-seed");
        let extra = generated_payload("sf-new");
        let archive = dir.path().join("a.tar.zst");
        write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
        fs::write(overlay.join("new.txt"), &extra).unwrap();

        assert!(ov
            .commit_live(&archive, |p| reopen_tar_zst(p, false))
            .expect("commit"));
        let src = open_tar_zst_base(&archive, false);
        assert_eq!(read_member(src.as_ref(), "/seed.txt"), seed);
        assert_eq!(read_member(src.as_ref(), "/new.txt"), extra);
    }

    #[test]
    fn live_commit_tar_zst_seek_table_rewrite() {
        let dir = tempfile::tempdir().unwrap();
        let prefix = generated_payload("st-prefix");
        let last = generated_payload("st-last");
        let extra = generated_payload("st-new");
        let archive = dir.path().join("a.tar.zst");
        write_split_tar_zst(
            &archive,
            &[ustar_file("prefix.txt", &prefix)],
            &[ustar_file("last.txt", &last)],
            true,
        );
        let before = fs::read(&archive).unwrap();
        assert!(seek_table_footer_present(&before));
        let map = scan_zstd_frames_path(&archive).unwrap();
        assert!(map.seek_table.is_some());
        let rewrite_start = map.frames.last().unwrap().compressed_offset as usize;
        let prefix_bytes = before[..rewrite_start].to_vec();

        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
        fs::write(overlay.join("new.txt"), &extra).unwrap();
        assert!(ov
            .commit_live(&archive, |p| reopen_tar_zst(p, false))
            .expect("commit"));

        let after = fs::read(&archive).unwrap();
        assert_eq!(
            &after[..rewrite_start],
            prefix_bytes.as_slice(),
            "prefix frames must stay byte-identical"
        );
        assert!(
            seek_table_footer_present(&after),
            "seek-table footer must be rewritten"
        );
        let out_map = scan_zstd_frames_path(&archive).unwrap();
        assert!(out_map.seek_table.is_some());
        let src = open_tar_zst_base(&archive, false);
        assert_eq!(read_member(src.as_ref(), "/prefix.txt"), prefix);
        assert_eq!(read_member(src.as_ref(), "/new.txt"), extra);
    }

    #[test]
    fn live_commit_tar_zst_last_frame_starts_mid_member() {
        let dir = tempfile::tempdir().unwrap();
        let big = generated_payload("mid-big").repeat(200);
        let after = generated_payload("mid-after");
        let extra = generated_payload("mid-new");
        let tar = pack_tar(&[ustar_file("big.bin", &big), ustar_file("after.txt", &after)]);
        // First member: 512-byte header + payload. Split inside the payload.
        let mid = 512 + big.len() / 2;
        assert!(mid < 512 + big.len(), "split must be mid-payload");
        let archive = dir.path().join("a.tar.zst");
        fs::write(
            &archive,
            concat_zstd_frames(&[&tar[..mid], &tar[mid..]], false),
        )
        .unwrap();

        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
        fs::write(overlay.join("new.txt"), &extra).unwrap();
        assert!(ov
            .commit_live(&archive, |p| reopen_tar_zst(p, false))
            .expect("commit"));
        let src = open_tar_zst_base(&archive, false);
        assert_eq!(read_member(src.as_ref(), "/big.bin"), big);
        assert_eq!(read_member(src.as_ref(), "/after.txt"), after);
        assert_eq!(read_member(src.as_ref(), "/new.txt"), extra);
    }

    #[test]
    fn live_commit_tar_zst_last_window_replace_two_ticks() {
        let dir = tempfile::tempdir().unwrap();
        let seed = generated_payload("rw-seed");
        let tick1 = generated_payload("rw-t1");
        let tick2 = generated_payload("rw-t2");
        let archive = dir.path().join("a.tar.zst");
        write_split_tar_zst(
            &archive,
            &[ustar_file("seed.txt", &seed)],
            &[ustar_file("keep.txt", b"keep\n")],
            false,
        );
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
        fs::write(overlay.join("tick.bin"), &tick1).unwrap();
        assert!(ov
            .commit_live(&archive, |p| reopen_tar_zst(p, false))
            .expect("tick 1"));
        assert!(!overlay.join("tick.bin").exists());

        fs::write(overlay.join("tick.bin"), &tick2).unwrap();
        assert!(ov
            .commit_live(&archive, |p| reopen_tar_zst(p, false))
            .expect("tick 2"));
        let src = open_tar_zst_base(&archive, false);
        assert_eq!(read_member(src.as_ref(), "/tick.bin"), tick2);
        assert_eq!(read_member(src.as_ref(), "/seed.txt"), seed);
    }

    #[test]
    fn live_commit_tar_zst_earlier_frame_delete_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let prefix = generated_payload("ef-prefix");
        let last = generated_payload("ef-last");
        let archive = dir.path().join("a.tar.zst");
        write_split_tar_zst(
            &archive,
            &[ustar_file("old.txt", &prefix)],
            &[ustar_file("last.txt", &last)],
            false,
        );
        let before = fs::read(&archive).unwrap();
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
        ov.unlink("/old.txt").expect("unlink prefix member");
        let err = ov
            .commit_live(&archive, |p| reopen_tar_zst(p, false))
            .unwrap_err()
            .to_string();
        assert!(err.contains("append-only"), "{err}");
        assert!(err.contains("/old.txt"), "{err}");
        assert_eq!(
            fs::read(&archive).unwrap(),
            before,
            "archive must be unchanged"
        );
    }

    /// Regression: same name in frame 0 and last frame; unlink must fail the tick.
    #[test]
    fn live_commit_tar_zst_same_name_both_frames_unlink_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let v1 = generated_payload("dup-v1");
        let v2 = generated_payload("dup-v2");
        let archive = dir.path().join("a.tar.zst");
        write_split_tar_zst(
            &archive,
            &[ustar_file("dup.txt", &v1)],
            &[ustar_file("dup.txt", &v2)],
            false,
        );
        let before = fs::read(&archive).unwrap();
        // ignore_zeros so both versions are indexed (split-suffix still one stream).
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
        ov.unlink("/dup.txt").expect("unlink newest");
        let err = ov
            .commit_live(&archive, |p| reopen_tar_zst(p, false))
            .unwrap_err()
            .to_string();
        assert!(err.contains("append-only"), "{err}");
        assert!(err.contains("/dup.txt"), "{err}");
        assert_eq!(fs::read(&archive).unwrap(), before);
    }

    #[test]
    fn live_commit_tar_zst_mixed_plan_skips_pending_appends() {
        let dir = tempfile::tempdir().unwrap();
        let prefix = generated_payload("mix-old");
        let last = generated_payload("mix-last");
        let extra = generated_payload("mix-new");
        let archive = dir.path().join("a.tar.zst");
        write_split_tar_zst(
            &archive,
            &[ustar_file("old.txt", &prefix)],
            &[ustar_file("last.txt", &last)],
            false,
        );
        let before = fs::read(&archive).unwrap();
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
        fs::write(overlay.join("new.txt"), &extra).unwrap();
        ov.unlink("/old.txt").expect("unlink earlier-frame name");
        let err = ov
            .commit_live(&archive, |p| reopen_tar_zst(p, false))
            .unwrap_err()
            .to_string();
        assert!(err.contains("append-only"), "{err}");
        assert!(err.contains("pending appends"), "{err}");
        assert_eq!(fs::read(&archive).unwrap(), before);
        let src = open_tar_zst_base(&archive, false);
        assert!(
            src.lookup("/new.txt", 0).is_none(),
            "new name must not be persisted when the tick fails"
        );
        assert!(overlay.join("new.txt").exists());
    }

    #[test]
    fn live_commit_tar_zst_reopen_fail_keeps_overlay_and_disables() {
        let dir = tempfile::tempdir().unwrap();
        let seed = generated_payload("rf-seed");
        let extra = generated_payload("rf-new");
        let archive = dir.path().join("a.tar.zst");
        write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
        fs::write(overlay.join("new.txt"), &extra).unwrap();

        let err = ov
            .commit_live(&archive, |_| {
                Err(OverlayError::Msg("stub reopen fail".into()))
            })
            .unwrap_err()
            .to_string();
        assert!(err.contains("remount required"), "{err}");
        assert!(
            overlay.join("new.txt").exists(),
            "overlay must be kept after reopen failure"
        );
        assert!(ov.interval_disabled());

        let second = ov
            .commit_live(&archive, |_| {
                panic!("second tick must not persist after interval_disabled")
            })
            .unwrap_err()
            .to_string();
        assert!(
            second.contains("remount required"),
            "second tick skipped via interval_disabled, not Ok(false): {second}"
        );
        assert!(overlay.join("new.txt").exists());
        // Persist did run on the first tick — remount should see the new member.
        let src = open_tar_zst_base(&archive, false);
        assert_eq!(read_member(src.as_ref(), "/new.txt"), extra);
    }

    #[test]
    fn live_commit_tar_zst_empty_second_tick() {
        let dir = tempfile::tempdir().unwrap();
        let seed = generated_payload("es-seed");
        let extra = generated_payload("es-new");
        let archive = dir.path().join("a.tar.zst");
        write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
        fs::write(overlay.join("new.txt"), &extra).unwrap();
        assert!(ov
            .commit_live(&archive, |p| reopen_tar_zst(p, false))
            .expect("first tick"));
        assert!(!overlay.join("new.txt").exists());
        match ov.commit_live(&archive, |p| reopen_tar_zst(p, false)) {
            Ok(false) => {}
            other => panic!("empty second tick must be Ok(false), got {other:?}"),
        }
    }

    fn set_mtime_age(path: &Path, age: Duration) {
        use std::os::unix::ffi::OsStrExt;
        let ts = SystemTime::now()
            .checked_sub(age)
            .expect("mtime age within epoch");
        let d = ts
            .duration_since(std::time::UNIX_EPOCH)
            .expect("mtime after epoch");
        let spec = libc::timespec {
            tv_sec: d.as_secs() as libc::time_t,
            tv_nsec: d.subsec_nanos() as libc::c_long,
        };
        let times = [spec, spec];
        let c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        let rc = unsafe {
            libc::utimensat(
                libc::AT_FDCWD,
                c.as_ptr(),
                times.as_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        assert_eq!(rc, 0, "utimensat {}", path.display());
    }

    /// Regression: interval settle time skips files still being written.
    #[test]
    fn live_commit_idle_skips_recent_keeps_overlay() {
        let dir = tempfile::tempdir().unwrap();
        let seed = generated_payload("idle-seed");
        let settled = generated_payload("idle-settled");
        let hot = generated_payload("idle-hot");
        let archive = dir.path().join("a.tar.zst");
        write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
        fs::write(overlay.join("settled.txt"), &settled).unwrap();
        fs::write(overlay.join("hot.txt"), &hot).unwrap();
        set_mtime_age(&overlay.join("settled.txt"), Duration::from_secs(30));

        assert!(ov
            .commit_live_idle(&archive, Duration::from_secs(10), |p| reopen_tar_zst(
                p, false
            ))
            .expect("idle tick"));
        assert!(
            !overlay.join("settled.txt").exists(),
            "settled file must leave the overlay"
        );
        assert!(
            overlay.join("hot.txt").exists(),
            "recently modified file must stay in the overlay"
        );
        assert_eq!(fs::read(overlay.join("hot.txt")).unwrap(), hot);

        let src = open_tar_zst_base(&archive, false);
        assert_eq!(read_member(src.as_ref(), "/seed.txt"), seed);
        assert_eq!(read_member(src.as_ref(), "/settled.txt"), settled);
        assert!(
            src.lookup("/hot.txt", 0).is_none(),
            "hot file must not be in the archive yet"
        );
        assert_eq!(
            read_member(&ov as &dyn MountSource, "/hot.txt"),
            hot,
            "mount view still serves the overlay copy"
        );
    }

    /// Regression: interval settle must not persist a file that still has an
    /// open write fd. FUSE keeps that fd across pauses; unlinking would send
    /// later pwrite bytes to a detached inode (silent truncation).
    #[test]
    fn live_commit_idle_skips_open_write_fd() {
        let dir = tempfile::tempdir().unwrap();
        let seed = generated_payload("idle-open-seed");
        let first = generated_payload("idle-open-first");
        let second = generated_payload("idle-open-second");
        let archive = dir.path().join("a.tar.zst");
        write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
        let fd = ov.create_file("/open.txt", 0o644).expect("create");
        let n = unsafe { libc::write(fd, first.as_ptr() as *const _, first.len()) };
        assert_eq!(n as usize, first.len(), "first write");
        set_mtime_age(&overlay.join("open.txt"), Duration::from_secs(30));

        match ov.commit_live_idle(&archive, Duration::from_secs(10), |p| {
            reopen_tar_zst(p, false)
        }) {
            Ok(false) => {}
            other => panic!("open write fd must skip idle persist, got {other:?}"),
        }
        assert!(
            overlay.join("open.txt").exists(),
            "open write fd must keep the overlay file"
        );

        let n = unsafe {
            libc::pwrite(
                fd,
                second.as_ptr() as *const _,
                second.len(),
                first.len() as i64,
            )
        };
        assert_eq!(n as usize, second.len(), "second write after skipped tick");
        ov.close_overlay_fd(fd);
        set_mtime_age(&overlay.join("open.txt"), Duration::from_secs(30));

        assert!(ov
            .commit_live_idle(&archive, Duration::from_secs(10), |p| reopen_tar_zst(
                p, false
            ))
            .expect("idle tick after close"));
        assert!(!overlay.join("open.txt").exists());

        let mut want = first.clone();
        want.extend_from_slice(&second);
        let src = open_tar_zst_base(&archive, false);
        assert_eq!(read_member(src.as_ref(), "/open.txt"), want);
    }

    /// Regression: after the hot file settles, a later tick persists it once.
    #[test]
    fn live_commit_idle_second_tick_after_settle() {
        let dir = tempfile::tempdir().unwrap();
        let seed = generated_payload("idle2-seed");
        let settled = generated_payload("idle2-settled");
        let later = generated_payload("idle2-later");
        let archive = dir.path().join("a.tar.zst");
        write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
        fs::write(overlay.join("settled.txt"), &settled).unwrap();
        fs::write(overlay.join("later.txt"), &later).unwrap();
        set_mtime_age(&overlay.join("settled.txt"), Duration::from_secs(30));

        assert!(ov
            .commit_live_idle(&archive, Duration::from_secs(10), |p| reopen_tar_zst(
                p, false
            ))
            .expect("first idle tick"));
        assert!(overlay.join("later.txt").exists());

        set_mtime_age(&overlay.join("later.txt"), Duration::from_secs(30));
        assert!(ov
            .commit_live_idle(&archive, Duration::from_secs(10), |p| reopen_tar_zst(
                p, false
            ))
            .expect("second idle tick"));
        assert!(!overlay.join("later.txt").exists());

        let src = open_tar_zst_base(&archive, false);
        assert_eq!(read_member(src.as_ref(), "/settled.txt"), settled);
        assert_eq!(read_member(src.as_ref(), "/later.txt"), later);
        match ov.commit_live_idle(&archive, Duration::from_secs(10), |p| {
            reopen_tar_zst(p, false)
        }) {
            Ok(false) => {}
            other => panic!("third tick must be empty, got {other:?}"),
        }
    }

    /// Regression: a hot replace must not delete the base member without appending.
    #[test]
    fn live_commit_idle_hot_replace_leaves_base_member() {
        let dir = tempfile::tempdir().unwrap();
        let orig = generated_payload("idle-rep-orig");
        let newer = generated_payload("idle-rep-new");
        let archive = dir.path().join("a.tar.zst");
        write_single_frame_tar_zst(&archive, &[ustar_file("keep.txt", &orig)]);
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
        fs::write(overlay.join("keep.txt"), &newer).unwrap();

        match ov.commit_live_idle(&archive, Duration::from_secs(10), |p| {
            reopen_tar_zst(p, false)
        }) {
            Ok(false) => {}
            other => panic!("hot replace must not persist, got {other:?}"),
        }
        assert!(overlay.join("keep.txt").exists());
        let src = open_tar_zst_base(&archive, false);
        assert_eq!(
            read_member(src.as_ref(), "/keep.txt"),
            orig,
            "base member must survive a skipped hot replace"
        );
        assert_eq!(read_member(&ov as &dyn MountSource, "/keep.txt"), newer);
    }

    /// Regression: delete tombstones are already settled and commit on an idle tick.
    #[test]
    fn live_commit_idle_commits_delete_tombstone() {
        let dir = tempfile::tempdir().unwrap();
        let keep = generated_payload("idle-del-keep");
        let gone = generated_payload("idle-del-gone");
        let archive = dir.path().join("a.tar.zst");
        write_single_frame_tar_zst(
            &archive,
            &[ustar_file("keep.txt", &keep), ustar_file("gone.txt", &gone)],
        );
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
        ov.unlink("/gone.txt").expect("tombstone");

        assert!(ov
            .commit_live_idle(&archive, Duration::from_secs(10), |p| reopen_tar_zst(
                p, false
            ))
            .expect("idle delete tick"));
        let src = open_tar_zst_base(&archive, false);
        assert_eq!(read_member(src.as_ref(), "/keep.txt"), keep);
        assert!(
            src.lookup("/gone.txt", 0).is_none(),
            "deleted member must leave the archive"
        );
        assert!(ov.lookup("/gone.txt", 0).is_none());
    }

    /// Regression: a hot nested sibling must keep its parent dir in the overlay.
    #[test]
    fn live_commit_idle_nested_hot_sibling_keeps_parent() {
        let dir = tempfile::tempdir().unwrap();
        let seed = generated_payload("idle-nest-seed");
        let settled = generated_payload("idle-nest-settled");
        let hot = generated_payload("idle-nest-hot");
        let archive = dir.path().join("a.tar.zst");
        write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
        fs::create_dir_all(overlay.join("dir")).unwrap();
        fs::write(overlay.join("dir/settled.txt"), &settled).unwrap();
        fs::write(overlay.join("dir/hot.txt"), &hot).unwrap();
        set_mtime_age(&overlay.join("dir/settled.txt"), Duration::from_secs(30));

        assert!(ov
            .commit_live_idle(&archive, Duration::from_secs(10), |p| reopen_tar_zst(
                p, false
            ))
            .expect("idle nested tick"));
        assert!(!overlay.join("dir/settled.txt").exists());
        assert!(
            overlay.join("dir/hot.txt").exists(),
            "hot sibling must keep the parent dir"
        );
        let src = open_tar_zst_base(&archive, false);
        assert_eq!(read_member(src.as_ref(), "/dir/settled.txt"), settled);
        assert!(src.lookup("/dir/hot.txt", 0).is_none());
        assert_eq!(read_member(&ov as &dyn MountSource, "/dir/hot.txt"), hot);
    }

    /// Regression: after the last file in a new dir settles, prune the empty
    /// parent so a later tick does not persist a bare directory member.
    #[test]
    fn live_commit_idle_prunes_empty_parent_after_last_file() {
        let dir = tempfile::tempdir().unwrap();
        let seed = generated_payload("idle-prune-seed");
        let only = generated_payload("idle-prune-only");
        let archive = dir.path().join("a.tar.zst");
        write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
        fs::create_dir_all(overlay.join("dir")).unwrap();
        fs::write(overlay.join("dir/only.txt"), &only).unwrap();
        set_mtime_age(&overlay.join("dir/only.txt"), Duration::from_secs(30));
        // Dir mtime is refreshed by the file write; backdate so a leftover
        // empty dir would look idle on the next tick if it were not pruned.
        set_mtime_age(&overlay.join("dir"), Duration::from_secs(30));

        assert!(ov
            .commit_live_idle(&archive, Duration::from_secs(10), |p| reopen_tar_zst(
                p, false
            ))
            .expect("idle prune tick"));
        assert!(
            !overlay.join("dir").exists(),
            "empty parent must be pruned from the overlay"
        );
        let src = open_tar_zst_base(&archive, false);
        assert_eq!(read_member(src.as_ref(), "/dir/only.txt"), only);

        match ov.commit_live_idle(&archive, Duration::from_secs(10), |p| {
            reopen_tar_zst(p, false)
        }) {
            Ok(false) => {}
            other => panic!("second tick must not persist leftover dir, got {other:?}"),
        }
    }

    /// Regression: FileVersionLayer wrap (factory default); same name in both frames.
    #[test]
    fn live_commit_tar_zst_file_version_layer_same_name_unlink_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let v1 = generated_payload("fvl-v1");
        let v2 = generated_payload("fvl-v2");
        let archive = dir.path().join("a.tar.zst");
        // Two complete-TAR frames so both versions exist only with ignore_zeros.
        write_complete_tar_frames_zst(
            &archive,
            &[
                pack_tar(&[ustar_file("dup.txt", &v1)]),
                pack_tar(&[ustar_file("dup.txt", &v2)]),
            ],
        );
        let before = fs::read(&archive).unwrap();
        let tar = open_tar_zst_base(&archive, true);
        let layered = crate::FileVersionLayer::new(tar);
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(Arc::new(layered) as Arc<dyn MountSource>, &overlay);
        assert!(ov.current_base().versions("/dup.txt") > 1);
        ov.unlink("/dup.txt").expect("unlink newest");
        let err = ov
            .commit_live(&archive, |p| reopen_tar_zst(p, true))
            .unwrap_err()
            .to_string();
        assert!(err.contains("append-only"), "{err}");
        assert!(err.contains("/dup.txt"), "{err}");
        assert_eq!(fs::read(&archive).unwrap(), before);
    }

    /// Regression: overlay symlink must persist as a symlink (`linkname` remounts).
    #[test]
    fn live_commit_tar_zst_overlay_symlink_persists_linkname() {
        let dir = tempfile::tempdir().unwrap();
        let seed = generated_payload("sy-seed");
        let target = format!("tgt-{}", std::process::id());
        let archive = dir.path().join("a.tar.zst");
        write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
        ov.create_symlink("/link", &target)
            .expect("overlay symlink");
        assert!(ov
            .commit_live(&archive, |p| reopen_tar_zst(p, false))
            .expect("commit symlink"));
        let src = open_tar_zst_base(&archive, false);
        let fi = src.lookup("/link", 0).expect("symlink remounted");
        assert!(
            ratarmount_core::is_lnk_mode(fi.mode),
            "expected symlink mode, got {:o}",
            fi.mode
        );
        assert_eq!(fi.linkname, target);
        assert_eq!(read_member(src.as_ref(), "/seed.txt"), seed);
    }

    /// Regression: FileVersionLayer(AutoMount) reports versions()==1; unlink still rejects.
    #[test]
    fn live_commit_tar_zst_file_version_layer_automount_same_name_unlink_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let v1 = generated_payload("am-v1");
        let v2 = generated_payload("am-v2");
        let archive = dir.path().join("a.tar.zst");
        write_complete_tar_frames_zst(
            &archive,
            &[
                pack_tar(&[ustar_file("dup.txt", &v1)]),
                pack_tar(&[ustar_file("dup.txt", &v2)]),
            ],
        );
        let before = fs::read(&archive).unwrap();
        let tar = open_tar_zst_base(&archive, true);
        let open_nested: crate::OpenNestedFn =
            Arc::new(|_p| Err(io::Error::other("no nested open in live-commit test")));
        let automount = crate::AutoMountLayer::new(tar, 1, open_nested);
        assert_eq!(
            automount.versions("/dup.txt"),
            1,
            "AutoMount default versions() is 1 if exists"
        );
        let layered = crate::FileVersionLayer::new(Arc::new(automount) as Arc<dyn MountSource>);
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(Arc::new(layered) as Arc<dyn MountSource>, &overlay);
        ov.unlink("/dup.txt").expect("unlink newest");
        let err = ov
            .commit_live(&archive, |p| reopen_tar_zst(p, true))
            .unwrap_err()
            .to_string();
        assert!(err.contains("append-only"), "{err}");
        assert!(err.contains("/dup.txt"), "{err}");
        assert_eq!(fs::read(&archive).unwrap(), before);
    }

    /// Regression: versions()==1 still walks .versions/{i} until miss.
    #[test]
    fn live_commit_tar_zst_versions_undercount_still_probes_version_paths() {
        let dir = tempfile::tempdir().unwrap();
        let v1 = generated_payload("uc-v1");
        let v2 = generated_payload("uc-v2");
        let archive = dir.path().join("a.tar.zst");
        write_split_tar_zst(
            &archive,
            &[ustar_file("dup.txt", &v1)],
            &[ustar_file("dup.txt", &v2)],
            false,
        );
        let before = fs::read(&archive).unwrap();
        let map = scan_zstd_frames_path(&archive).unwrap();
        let last_start = map.frames.last().unwrap().uncompressed_offset;
        let base = Arc::new(VersionsUndercount {
            oldest: tar_fi_at(0),
            newest: tar_fi_at(last_start),
        }) as Arc<dyn MountSource>;
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(base, &overlay);
        assert_eq!(ov.current_base().versions("/dup.txt"), 1);
        assert!(ov.current_base().lookup("/dup.txt.versions/1", 0).is_some());
        ov.unlink("/dup.txt").expect("unlink newest");
        let err = ov
            .commit_live(&archive, |p| reopen_tar_zst(p, false))
            .unwrap_err()
            .to_string();
        assert!(err.contains("append-only"), "{err}");
        assert!(err.contains("/dup.txt"), "{err}");
        assert_eq!(fs::read(&archive).unwrap(), before);
    }

    fn tar_fi_at(offsetheader: u64) -> FileInfo {
        FileInfo {
            size: 1,
            mtime: 0.0,
            mode: ratarmount_core::S_IFREG | 0o644,
            linkname: String::new(),
            uid: 0,
            gid: 0,
            userdata: vec![UserData::Tar(ratarmount_core::SQLiteIndexedTarUserData {
                offset: offsetheader.saturating_add(512),
                offsetheader: Some(offsetheader),
                istar: false,
                issparse: false,
                isgenerated: false,
                recursiondepth: 0,
            })],
        }
    }

    /// `versions()` lies (always 1) but `.versions/{i}` serves every copy.
    struct VersionsUndercount {
        oldest: FileInfo,
        newest: FileInfo,
    }

    impl MountSource for VersionsUndercount {
        fn list(&self, _path: &str) -> Option<ListResult> {
            Some(ListResult::Infos(Default::default()))
        }
        fn lookup(&self, path: &str, file_version: i32) -> Option<FileInfo> {
            let path = normpath(path);
            if path == "/dup.txt.versions/1" {
                return Some(self.oldest.clone());
            }
            if path == "/dup.txt.versions/2" || path == "/dup.txt" {
                let _ = file_version;
                return Some(self.newest.clone());
            }
            if path == "/" {
                return Some(create_root_file_info());
            }
            None
        }
        fn versions(&self, path: &str) -> u32 {
            if normpath(path) == "/dup.txt" {
                1
            } else {
                0
            }
        }
        fn open(&self, _: &FileInfo, _: i32) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "versions-undercount stub",
            ))
        }
        fn is_immutable(&self) -> bool {
            true
        }
    }

    /// Regression: complete-TAR multi-frame remount with ignore_zeros sees prefix + new.
    #[test]
    fn live_commit_tar_zst_complete_frames_ignore_zeros() {
        let dir = tempfile::tempdir().unwrap();
        let prefix = generated_payload("cf-prefix");
        let last = generated_payload("cf-last");
        let extra = generated_payload("cf-new");
        let archive = dir.path().join("a.tar.zst");
        write_complete_tar_frames_zst(
            &archive,
            &[
                pack_tar(&[ustar_file("prefix.txt", &prefix)]),
                pack_tar(&[ustar_file("last.txt", &last)]),
            ],
        );
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, true), &overlay);
        fs::write(overlay.join("new.txt"), &extra).unwrap();
        assert!(ov
            .commit_live(&archive, |p| reopen_tar_zst(p, true))
            .expect("commit"));
        let src = open_tar_zst_base(&archive, true);
        assert_eq!(read_member(src.as_ref(), "/prefix.txt"), prefix);
        assert_eq!(read_member(src.as_ref(), "/last.txt"), last);
        assert_eq!(read_member(src.as_ref(), "/new.txt"), extra);
    }

    #[test]
    fn live_commit_tar_zst_complete_frames_without_ignore_zeros() {
        let dir = tempfile::tempdir().unwrap();
        let prefix = generated_payload("cf0-prefix");
        let last = generated_payload("cf0-last");
        let extra = generated_payload("cf0-new");
        let archive = dir.path().join("a.tar.zst");
        write_complete_tar_frames_zst(
            &archive,
            &[
                pack_tar(&[ustar_file("prefix.txt", &prefix)]),
                pack_tar(&[ustar_file("last.txt", &last)]),
            ],
        );
        let overlay = dir.path().join("ov");
        // Base indexed with -i so last-frame names exist for classification; reopen without.
        let ov = overlay_with_base(open_tar_zst_base(&archive, true), &overlay);
        fs::write(overlay.join("new.txt"), &extra).unwrap();
        assert!(ov
            .commit_live(&archive, |p| reopen_tar_zst(p, false))
            .expect("commit"));

        // Default parse stops at the first 512-zero block (end of frame 0).
        let default = open_tar_zst_base(&archive, false);
        assert_eq!(read_member(default.as_ref(), "/prefix.txt"), prefix);
        assert!(
            default.lookup("/last.txt", 0).is_none(),
            "without ignore_zeros, last-frame names stay invisible"
        );
        assert!(
            default.lookup("/new.txt", 0).is_none(),
            "new members live after the first frame EOF"
        );

        // The rewritten last complete TAR frame itself contains last + new, not prefix.
        let map = scan_zstd_frames_path(&archive).unwrap();
        let last_idx = map.frames.len() - 1;
        let mut src = File::open(&archive).unwrap();
        let mut last_plain = Vec::new();
        decode_zstd_frames_to(&mut src, &map, last_idx, &mut last_plain).unwrap();
        let last_tar = ratarmount_formats_tar::SqliteIndexedTar::open_from_reader(
            std::io::Cursor::new(last_plain),
            "last-frame.tar",
            None,
            &ratarmount_core::OpenOptions {
                index_in_memory: true,
                ..ratarmount_core::OpenOptions::default()
            },
            "test",
        )
        .expect("index last frame");
        assert!(last_tar.lookup("/prefix.txt", 0).is_none());
        assert_eq!(read_member(&last_tar, "/last.txt"), last);
        assert_eq!(read_member(&last_tar, "/new.txt"), extra);
    }
}
