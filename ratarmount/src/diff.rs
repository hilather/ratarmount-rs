//! Offline patches from overlay content and durable tombstones.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use clap::Parser;
use ratarmount_compositing::{is_overlay_internal_path, HIDDEN_DB};
use ratarmount_core::{metadata_mode, MountSource, OpenOptions, S_IFDIR, S_IFLNK, S_IFMT, S_IFREG};
use ratarmount_session::factory;
use rusqlite::{Connection, OpenFlags};

mod patch;
#[cfg(test)]
mod tests;

#[derive(Debug, Parser)]
#[command(
    name = "ratarmount diff",
    about = "Compare a write overlay with its read-only base (no mount or git required)"
)]
pub struct DiffArgs {
    pub directory: PathBuf,
    /// Original archive, committed Git repository, folder, or remote URL.
    #[arg(long)]
    pub base: Option<PathBuf>,
    /// Emit a git-apply-compatible patch, including binary literals and renames.
    #[arg(long)]
    pub git: bool,
    /// Number of unified context lines.
    #[arg(short = 'U', long, default_value_t = 3)]
    pub context: usize,
    /// Print per-file line counts and totals instead of a patch.
    #[arg(long, conflicts_with = "name_status")]
    pub stat: bool,
    /// Print A/M/D/T/R100 and paths instead of a patch.
    #[arg(long)]
    pub name_status: bool,
    /// Include .git directories (normally omitted for synthetic-head overlays).
    #[arg(long)]
    pub include_git_dir: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    mode: u32,
    data: Vec<u8>,
}

impl Entry {
    fn git_mode(&self) -> u32 {
        if self.mode & S_IFMT == S_IFLNK {
            0o120000
        } else if self.mode & 0o100 != 0 {
            0o100755
        } else {
            0o100644
        }
    }
}

#[derive(Debug)]
struct Change {
    from: String,
    to: String,
    old: Option<Entry>,
    new: Option<Entry>,
}

impl Change {
    fn status(&self) -> &'static str {
        match (&self.old, &self.new) {
            (None, _) => "A",
            (_, None) => "D",
            (Some(_), Some(_)) if self.from != self.to => "R100",
            (Some(a), Some(b)) if a.mode & S_IFMT != b.mode & S_IFMT => "T",
            _ => "M",
        }
    }
}

fn excluded(path: &str, include_git: bool) -> bool {
    is_overlay_internal_path(path) || (!include_git && path.split('/').any(|part| part == ".git"))
}

fn checked_path(path: &str) -> Result<String, String> {
    let path = path.trim_start_matches('/');
    if path.is_empty()
        || path
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == "..")
    {
        return Err(format!("invalid overlay path {path:?}"));
    }
    Ok(path.to_owned())
}

fn tombstones(root: &Path, include_git: bool) -> Result<BTreeSet<String>, String> {
    let db = root.join(HIDDEN_DB);
    let read = || -> Result<_, Box<dyn std::error::Error>> {
        if !fs::symlink_metadata(&db)?.is_file() {
            return Err("overlay database must be a regular file".into());
        }
        let conn = Connection::open_with_flags(
            &db,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        let mut stmt =
            conn.prepare("SELECT path, name FROM files WHERE deleted = 1 ORDER BY path, name")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut paths = BTreeSet::new();
        for row in rows {
            let (parent, name) = row?;
            let path = checked_path(&format!("{}/{name}", parent.trim_end_matches('/')))?;
            if !excluded(&path, include_git) {
                paths.insert(path);
            }
        }
        Ok(paths)
    };
    read().map_err(|e| {
        format!(
            "error reading existing overlay database {}: {e}",
            db.display()
        )
    })
}

fn deleted(path: &str, tombstones: &BTreeSet<String>) -> bool {
    let mut ancestor = path;
    loop {
        if tombstones.contains(ancestor) {
            return true;
        }
        match ancestor.rsplit_once('/') {
            Some((parent, _)) => ancestor = parent,
            None => return false,
        }
    }
}

fn host_entries(
    root: &Path,
    rel: &str,
    include_git: bool,
    removed: &BTreeSet<String>,
    entries: &mut BTreeMap<String, Option<Entry>>,
) -> Result<(), String> {
    for child in fs::read_dir(root.join(rel)).map_err(|e| e.to_string())? {
        let child = child.map_err(|e| e.to_string())?;
        let name = child
            .file_name()
            .into_string()
            .map_err(|_| "overlay path is not UTF-8")?;
        let path = if rel.is_empty() {
            name
        } else {
            format!("{rel}/{name}")
        };
        if excluded(&path, include_git) || deleted(&path, removed) {
            continue;
        }
        let meta = fs::symlink_metadata(child.path()).map_err(|e| e.to_string())?;
        if meta.is_dir() {
            entries.insert(path.clone(), None);
            host_entries(root, &path, include_git, removed, entries)?;
        } else {
            let data = if meta.is_symlink() {
                fs::read_link(child.path())
                    .map_err(|e| e.to_string())?
                    .as_os_str()
                    .as_bytes()
                    .to_vec()
            } else if meta.is_file() {
                fs::read(child.path()).map_err(|e| format!("{path}: {e}"))?
            } else {
                return Err(format!(
                    "{path}: only regular files and symlinks can be diffed"
                ));
            };
            entries.insert(
                path,
                Some(Entry {
                    mode: metadata_mode(&meta),
                    data,
                }),
            );
        }
    }
    Ok(())
}

fn base_entries(
    source: &dyn MountSource,
    path: &str,
    include_git: bool,
    entries: &mut BTreeMap<String, Entry>,
) -> Result<(), String> {
    if excluded(path, include_git) || entries.contains_key(path) {
        return Ok(());
    }
    let full = format!("/{path}");
    let Some(fi) = source.lookup(&full, 0) else {
        return Ok(());
    };
    let data = match fi.mode & S_IFMT {
        S_IFDIR => {
            let children = source
                .list_dirents(&full)
                .ok_or_else(|| format!("cannot list base directory {path}"))?;
            for child in children {
                let name = checked_path(&child.name)?;
                if name.contains('/') {
                    return Err(format!("invalid base directory entry {name:?}"));
                }
                base_entries(source, &format!("{path}/{name}"), include_git, entries)?;
            }
            return Ok(());
        }
        S_IFLNK => fi.linkname.as_bytes().to_vec(),
        S_IFREG => {
            let mut data = Vec::new();
            source
                .open(&fi, 0)
                .map_err(|e| format!("{path}: {e}"))?
                .read_to_end(&mut data)
                .map_err(|e| format!("{path}: {e}"))?;
            if data.len() as u64 != fi.size {
                return Err(format!(
                    "{path}: short base read (expected {}, got {})",
                    fi.size,
                    data.len()
                ));
            }
            data
        }
        _ => return Err(format!("{path}: unsupported base file type")),
    };
    entries.insert(
        path.into(),
        Entry {
            mode: fi.mode,
            data,
        },
    );
    Ok(())
}

fn collect(args: &DiffArgs, source: &dyn MountSource) -> Result<Vec<Change>, String> {
    let removed = tombstones(&args.directory, args.include_git_dir)?;
    let mut host = BTreeMap::new();
    host_entries(
        &args.directory,
        "",
        args.include_git_dir,
        &removed,
        &mut host,
    )?;
    let mut old = BTreeMap::new();
    for path in &removed {
        base_entries(source, path, args.include_git_dir, &mut old)?;
    }
    for (path, entry) in &host {
        // Existing host directories are just COW parents, not recursive edits.
        if entry.is_none()
            && source
                .lookup(&format!("/{path}"), 0)
                .is_some_and(|fi| fi.mode & S_IFMT == S_IFDIR)
        {
            continue;
        }
        base_entries(source, path, args.include_git_dir, &mut old)?;
    }
    let paths: BTreeSet<_> = old.keys().chain(host.keys()).cloned().collect();
    let mut changes = Vec::new();
    for path in paths {
        let before = old.remove(&path);
        let after = host.remove(&path).flatten();
        let equal = before == after
            || (args.git
                && before
                    .as_ref()
                    .zip(after.as_ref())
                    .is_some_and(|(a, b)| a.git_mode() == b.git_mode() && a.data == b.data));
        if !equal {
            changes.push(Change {
                from: path.clone(),
                to: path,
                old: before,
                new: after,
            });
        }
    }
    if args.git || args.name_status || args.stat {
        detect_renames(&mut changes);
    }
    Ok(changes)
}

fn detect_renames(changes: &mut Vec<Change>) {
    // Stable, one-to-one pairing, including duplicate-content candidates.
    let mut pairs = Vec::new();
    let mut used = BTreeSet::new();
    for (i, change) in changes.iter().enumerate().filter(|(_, c)| c.new.is_none()) {
        let before = change.old.as_ref().expect("deletion");
        if let Some((j, _)) = changes.iter().enumerate().find(|(j, c)| {
            !used.contains(j)
                && c.old.is_none()
                && c.new.as_ref().is_some_and(|after| {
                    before.mode & S_IFMT == after.mode & S_IFMT && before.data == after.data
                })
        }) {
            used.insert(j);
            pairs.push((i, j));
        }
    }
    for (i, j) in pairs {
        changes[i].to = changes[j].to.clone();
        changes[i].new = changes[j].new.take();
    }
    let mut index = 0;
    changes.retain(|_| {
        let keep = !used.contains(&index);
        index += 1;
        keep
    });
    changes.sort_by(|a, b| a.from.cmp(&b.from).then(a.to.cmp(&b.to)));
}

// Factory backends print cold-index progress to stdout. During the single-threaded
// CLI open, send it to stderr so stdout remains a patch. Restore on all errors.
struct ProgressToStderr(OwnedFd);

impl ProgressToStderr {
    fn new() -> io::Result<Self> {
        io::stdout().flush()?;
        let fd = unsafe { libc::fcntl(libc::STDOUT_FILENO, libc::F_DUPFD_CLOEXEC, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let saved = Self(unsafe { OwnedFd::from_raw_fd(fd) });
        if unsafe { libc::dup2(libc::STDERR_FILENO, libc::STDOUT_FILENO) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(saved)
    }
}

impl Drop for ProgressToStderr {
    fn drop(&mut self) {
        let _ = io::stdout().flush();
        unsafe {
            libc::dup2(self.0.as_raw_fd(), libc::STDOUT_FILENO);
        }
    }
}

fn execute(args: &DiffArgs) -> Result<(String, bool), String> {
    let base = args.base.as_ref().ok_or("--base SOURCE is required: the overlay does not store original contents or its base location")?;
    // Validate before opening the base; never initialize a missing overlay DB.
    tombstones(&args.directory, args.include_git_dir)?;
    let mut options = OpenOptions {
        write_index: false,
        index_in_memory: true,
        // A working repository means its committed tree, not local edits.
        git: base.join(".git").exists(),
        ..OpenOptions::default()
    };
    let changes = {
        let _progress = ProgressToStderr::new().map_err(|e| e.to_string())?;
        let bundle = factory::build_mount_source_ex(
            std::slice::from_ref(base),
            &mut options,
            false,
            factory::CompositingOptions::default(),
        )?;
        collect(args, bundle.source.as_ref())?
    };
    Ok((
        patch::render(&changes, args).map_err(|e| e.to_string())?,
        !changes.is_empty(),
    ))
}

pub fn run(args: &DiffArgs) -> i32 {
    match execute(args) {
        Ok((output, changed)) => match io::stdout().lock().write_all(output.as_bytes()) {
            Ok(()) => i32::from(changed),
            Err(error) => {
                eprintln!("diff: {error}");
                2
            }
        },
        Err(error) => {
            eprintln!("diff: {error}");
            2
        }
    }
}
