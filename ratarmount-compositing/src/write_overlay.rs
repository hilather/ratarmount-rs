//! Write overlay: redirect creates/writes/deletes to a host folder.
//! Mirrors Python `WritableFolderMountSource` (subset) + `commit_overlay`.

use std::fs::{self, File, OpenOptions as FsOpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use ratarmount_core::{
    create_root_file_info, normpath, FileInfo, ListModeResult, ListResult, MountSource, UserData,
};
use rusqlite::{params, Connection, OpenFlags};
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
        self.mark_present(path, mode | libc::S_IFREG)?;
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
        self.mark_present(path, mode | libc::S_IFDIR)?;
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

/// Apply overlay folder modifications to an **uncompressed** TAR using GNU tar.
///
/// Mirrors Python `commit_overlay`:
/// 1. Collect deleted paths from `.ratarmount.overlay.sqlite`
/// 2. Walk overlay files → delete-then-append list
/// 3. `tar --delete` then `tar --append -C overlay`
///
/// Returns `Ok(true)` if changes were committed, `Ok(false)` if nothing to do or canceled.
pub fn commit_overlay(
    write_overlay: impl AsRef<Path>,
    tar_file: impl AsRef<Path>,
    opts: &CommitOverlayOptions,
) -> Result<bool> {
    let write_overlay = write_overlay.as_ref();
    let tar_file = tar_file.as_ref();

    if !write_overlay.is_dir() {
        return Err(OverlayError::Msg(
            "Need an existing write overlay folder for committing changes.".into(),
        ));
    }
    if !tar_file.is_file() {
        return Err(OverlayError::Msg(format!(
            "Specified TAR '{}' to commit to does not exist or is not a file!",
            tar_file.display()
        )));
    }
    if !is_uncompressed_tar(tar_file)? {
        return Err(OverlayError::Msg(
            "Currently, only modifications to an uncompressed TAR may be committed.".into(),
        ));
    }
    ensure_gnu_tar()?;

    let tmp = tempfile::tempdir()?;
    let deletion_list = tmp.path().join("deletions.lst");
    let append_list = tmp.path().join("append.lst");

    let mut deletions: Vec<u8> = Vec::new();
    let mut appends: Vec<u8> = Vec::new();

    // Deletions from hidden DB
    let db_path = write_overlay.join(HIDDEN_DB);
    if db_path.is_file() {
        let conn = Connection::open_with_flags(
            &db_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        let mut stmt = conn.prepare(
            r#"SELECT path, name FROM "files" WHERE deleted = 1"#,
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?;
        for row in rows {
            let (path, name) = row?;
            let rel = join_rel(&path, &name);
            add_deletion_variants(&mut deletions, &rel);
        }
    }

    // Overlay walk: files to append (and replace = delete + append)
    let suffixes = ["", "-journal", "-shm", "-wal"];
    let ignored: Vec<String> = suffixes
        .iter()
        .map(|s| format!("{HIDDEN_DB}{s}"))
        .collect();

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
        if is_dir {
            // Empty dirs only (walkdir_files_and_empty_dirs already filters)
            appends.extend(rel.as_bytes());
            appends.push(0);
        } else {
            add_deletion_variants(&mut deletions, &rel);
            appends.extend(rel.as_bytes());
            appends.push(0);
        }
    }

    fs::write(&deletion_list, &deletions)?;
    fs::write(&append_list, &appends)?;

    if deletions.is_empty() && appends.is_empty() {
        if opts.debug >= 1 {
            println!("Nothing to commit.");
        }
        return Ok(false);
    }

    if opts.debug >= 1 {
        println!("To commit the overlay folder to the archive, these commands have to be executed:");
        println!();
        if !deletions.is_empty() {
            println!(
                "    tar --delete --null --files-from='{}' --file '{}' 2>&1 |",
                deletion_list.display(),
                tar_file.display()
            );
            println!("       sed '/^tar: Exiting with failure/d; /^tar.*Not found in archive/d'");
        }
        if !appends.is_empty() {
            println!(
                "    tar --append -C '{}' --null --files-from='{}' --file '{}'",
                write_overlay.display(),
                append_list.display(),
                tar_file.display()
            );
        }
        println!();
        println!("Committing is an experimental feature!");
    }

    let confirmed = if opts.yes {
        true
    } else {
        print!("Please confirm by entering \"commit\". Any other input will cancel.\n> ");
        let _ = io::stdout().flush();
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        line.trim() == "commit"
    };

    if !confirmed {
        if opts.debug >= 1 {
            println!("Canceled");
        }
        return Ok(false);
    }

    if !deletions.is_empty() {
        let output = tar_env_command()
            .args([
                "--delete",
                "--null",
                &format!("--files-from={}", deletion_list.display()),
                "--file",
            ])
            .arg(tar_file)
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

    if !appends.is_empty() {
        let status = tar_env_command()
            .args([
                "--append",
                "-C",
            ])
            .arg(write_overlay)
            .args([
                "--null",
                &format!("--files-from={}", append_list.display()),
                "--file",
            ])
            .arg(tar_file)
            .status()?;
        if !status.success() {
            return Err(OverlayError::Msg(format!(
                "tar --append failed with {status}"
            )));
        }
    }

    if opts.debug >= 1 {
        println!(
            "Committed successfully. You can now remove the overlay folder at {}.",
            write_overlay.display()
        );
    }
    Ok(true)
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
    Ok(n == 5 && (&ustar == b"ustar" || ustar.starts_with(b"ustar") || &ustar == b"GNU  "))
}

fn ensure_gnu_tar() -> Result<()> {
    let out = Command::new("tar")
        .arg("--version")
        .output()
        .map_err(|e| OverlayError::Msg(format!("Currently, GNU tar must be installed: {e}")))?;
    let text = String::from_utf8_lossy(&out.stdout);
    if !text.contains("GNU tar") {
        return Err(OverlayError::Msg(
            "Currently, GNU tar is required for --commit-overlay.".into(),
        ));
    }
    Ok(())
}

fn tar_env_command() -> Command {
    let mut cmd = Command::new("tar");
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
                    .map(|e| e.file_type().map(|t| t.is_file() || t.is_symlink()).unwrap_or(false))
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
        commit_overlay(&overlay, &tar, &opts).unwrap();

        let list = StdCommand::new("tar")
            .args(["-tf"])
            .arg(&tar)
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&list.stdout);
        assert!(text.contains("new.txt"), "tar listing: {text}");
        assert!(text.contains("old.txt"), "tar listing: {text}");
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
        fn open(
            &self,
            _: &FileInfo,
            _: i32,
        ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
            Err(io::Error::new(io::ErrorKind::NotFound, "null base"))
        }
        fn is_immutable(&self) -> bool {
            true
        }
    }
}
