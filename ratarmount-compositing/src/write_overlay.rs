//! Write overlay: redirect creates/writes/deletes to a host folder.
//! Mirrors Python `WritableFolderMountSource` (subset).

use std::fs::{self, File, OpenOptions as FsOpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ratarmount_core::{
    create_root_file_info, normpath, FileInfo, ListModeResult, ListResult, MountSource, UserData,
};
use rusqlite::{params, Connection};
use thiserror::Error;

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
    root: PathBuf,
    db: Mutex<Connection>,
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
        let db_path = root.join(HIDDEN_DB);
        let conn = Connection::open(&db_path)?;
        conn.execute_batch("PRAGMA LOCKING_MODE = EXCLUSIVE;")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self {
            base,
            root,
            db: Mutex::new(conn),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn realpath(&self, path: &str) -> PathBuf {
        let path = normpath(path);
        if path == "/" {
            return self.root.clone();
        }
        self.root.join(path.trim_start_matches('/'))
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
        let mut stmt = match db.prepare(
            r#"SELECT name FROM "files" WHERE path = ?1 AND deleted = 1"#,
        ) {
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
        if self.base.exists(path) {
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
        if !real_parent.exists() && self.base.is_dir(&parent) {
            fs::create_dir_all(&real_parent)?;
        }
        Ok(())
    }

    /// Copy base file into overlay (COW) if not already present.
    pub fn ensure_modifiable(&self, path: &str) -> Result<()> {
        self.ensure_parent(path)?;
        let real = self.realpath(path);
        if real.exists() {
            return Ok(());
        }
        let Some(fi) = self.base.lookup(path, 0) else {
            // New file: just ensure parent
            return Ok(());
        };
        if fi.mode & libc::S_IFMT == libc::S_IFDIR {
            fs::create_dir_all(&real)?;
            return Ok(());
        }
        let mut src = self.base.open(&fi, 0)?;
        let mut dst = File::create(&real)?;
        io::copy(&mut src, &mut dst)?;
        Ok(())
    }

    pub fn create_file(&self, path: &str, mode: u32) -> Result<i32> {
        self.ensure_parent(path)?;
        let real = self.realpath(path);
        if let Some(parent) = real.parent() {
            fs::create_dir_all(parent)?;
        }
        let f = FsOpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode & 0o7777)
            .open(&real)?;
        let fd = {
            use std::os::unix::io::IntoRawFd;
            f.into_raw_fd()
        };
        self.mark_present(path, mode | libc::S_IFREG as u32)?;
        Ok(fd)
    }

    pub fn open_overlay_fd(&self, path: &str, flags: i32) -> Result<i32> {
        self.ensure_modifiable(path)?;
        let real = self.realpath(path);
        // If still missing and write flags, create empty
        if !real.exists() && (flags & (libc::O_WRONLY | libc::O_RDWR)) != 0 {
            self.create_file(path, 0o644)?;
        }
        let fd = unsafe { libc::open(c_path(&real)?.as_ptr(), flags, 0o644) };
        if fd < 0 {
            return Err(OverlayError::Io(io::Error::last_os_error()));
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
        self.ensure_parent(path)?;
        let real = self.realpath(path);
        fs::create_dir_all(&real)?;
        let _ = fs::set_permissions(&real, fs::Permissions::from_mode(mode & 0o7777));
        self.mark_present(path, mode | libc::S_IFDIR as u32)?;
        Ok(())
    }

    pub fn unlink(&self, path: &str) -> Result<()> {
        let real = self.realpath(path);
        if real.exists() {
            fs::remove_file(&real)?;
        }
        self.mark_deleted(path)?;
        Ok(())
    }

    pub fn rmdir(&self, path: &str) -> Result<()> {
        let real = self.realpath(path);
        if real.exists() {
            fs::remove_dir(&real)?;
        }
        self.mark_deleted(path)?;
        Ok(())
    }

    pub fn truncate(&self, path: &str, size: u64) -> Result<()> {
        self.ensure_modifiable(path)?;
        let real = self.realpath(path);
        let f = FsOpenOptions::new().write(true).open(&real)?;
        f.set_len(size)?;
        Ok(())
    }

    fn overlay_file_info(&self, path: &str) -> Option<FileInfo> {
        let real = self.realpath(path);
        if !real.exists() {
            return None;
        }
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

        if let Some(base_list) = self.base.list(&path) {
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
                        if let Some(fi) = self.base.lookup(&full, 0) {
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

        if path == "/" || !map.is_empty() || self.base.is_dir(&path) {
            Some(ListResult::Infos(map))
        } else {
            None
        }
    }

    fn list_mode(&self, path: &str) -> Option<ListModeResult> {
        match self.list(path)? {
            ListResult::Infos(m) => Some(ListModeResult::Modes(
                m.into_iter().map(|(k, v)| (k, v.mode)).collect(),
            )),
            ListResult::Names(n) => Some(ListModeResult::Names(n)),
        }
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
        self.base.lookup(&path, file_version)
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
                return Ok(Box::new(File::open(real)?));
            }
        }
        // If real overlay file exists for a path we cannot recover, fall back to base.
        self.base.open(file_info, buffering)
    }

    fn is_immutable(&self) -> bool {
        false
    }
}

fn join(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{parent}/{name}")
    }
}

fn c_path(path: &Path) -> io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
}

// Silence unused import if Write not needed elsewhere
#[allow(dead_code)]
fn _w() {
    let _ = std::io::sink().write(&[]);
}
