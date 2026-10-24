//! Shared sandbox policies and read-only overlay accounting.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, ThreadId};

use regex::Regex;
use rusqlite::OpenFlags;

use crate::write_overlay::is_overlay_internal_path;
use crate::{OverlayError, OverlayMutation, OverlayPolicy, HIDDEN_DB};

/// Logical named content, excluding bookkeeping. Symlinks are never followed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OverlayUsage {
    pub bytes: u64,
    /// Regular files plus symlinks, as charged by the policy hooks.
    pub files: u64,
    pub directories: u64,
    pub symlinks: u64,
}

impl OverlayUsage {
    pub fn scan(root: &Path) -> io::Result<Self> {
        fn walk(dir: &Path, usage: &mut OverlayUsage) -> io::Result<()> {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                if is_overlay_internal_path(&entry.file_name().to_string_lossy()) {
                    continue;
                }
                let meta = entry.path().symlink_metadata()?;
                if meta.is_dir() {
                    usage.directories += 1;
                    walk(&entry.path(), usage)?;
                } else if meta.is_file() || meta.is_symlink() {
                    usage.files += 1;
                    usage.bytes = usage.bytes.checked_add(meta.len()).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "overlay size overflows u64")
                    })?;
                    usage.symlinks += u64::from(meta.is_symlink());
                }
            }
            Ok(())
        }
        let mut usage = Self::default();
        walk(root, &mut usage)?;
        Ok(usage)
    }
}

/// Offline snapshot. `files_deleted` counts durable tombstones (including rmdir).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OverlayStats {
    pub usage: OverlayUsage,
    pub files_deleted: u64,
}

impl OverlayStats {
    /// Open the existing DB read-only: never initialize or repair an overlay.
    pub fn read(root: &Path) -> Result<Self, OverlayError> {
        let db = root.join(HIDDEN_DB);
        let meta = fs::symlink_metadata(&db)?;
        if !meta.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "overlay database must be a regular file",
            )
            .into());
        }
        let conn = crate::open_overlay_db(
            &db,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            crate::DbName::Path,
        )?;
        let files_deleted =
            conn.query_row("SELECT count(*) FROM files WHERE deleted = 1", [], |row| {
                row.get(0)
            })?;
        Ok(Self {
            usage: OverlayUsage::scan(root)?,
            files_deleted,
        })
    }
}

/// Parse bytes or an integer with a binary K/M/G/T suffix (case insensitive).
pub fn parse_overlay_size(value: &str) -> Result<u64, String> {
    let value = value.trim();
    let (digits, shift) = match value.as_bytes().last().map(u8::to_ascii_uppercase) {
        Some(b'K') => (&value[..value.len() - 1], 10),
        Some(b'M') => (&value[..value.len() - 1], 20),
        Some(b'G') => (&value[..value.len() - 1], 30),
        Some(b'T') => (&value[..value.len() - 1], 40),
        _ => (value, 0),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!(
            "invalid overlay size {value:?}; expected bytes or an integer with K/M/G/T"
        ));
    }
    digits
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(1u64 << shift))
        .ok_or_else(|| format!("overlay size {value:?} overflows u64"))
}

struct PathGlob {
    pattern: String,
    parts: Vec<Option<Regex>>,
    literal_components: usize,
}

impl PathGlob {
    fn new(pattern: &str) -> io::Result<Self> {
        let original = pattern.to_string();
        let pattern = pattern.trim_start_matches('/').trim_end_matches('/');
        if pattern.is_empty()
            || pattern
                .split('/')
                .any(|c| c.is_empty() || c == "." || c == "..")
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "read-only glob must be a nonempty root-relative path without . or .. components",
            ));
        }
        let mut parts = Vec::new();
        for component in pattern.split('/') {
            if component == "**" {
                parts.push(None);
                continue;
            }
            if component.contains("**") {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "** must occupy an entire path component",
                ));
            }
            let mut regex = String::from("(?s)^");
            for ch in component.chars() {
                match ch {
                    '*' => regex.push_str(".*"),
                    '?' => regex.push('.'),
                    ch => regex.push_str(&regex::escape(&ch.to_string())),
                }
            }
            regex.push('$');
            parts.push(Some(Regex::new(&regex).map_err(io::Error::other)?));
        }
        Ok(Self {
            pattern: original,
            parts,
            literal_components: pattern
                .split('/')
                .filter(|part| !part.contains(['*', '?']))
                .count(),
        })
    }

    // A completed pattern covers everything below it. Remaining states describe
    // possible matching children, even if they do not currently exist.
    fn protects(&self, path: &str, ancestors: bool) -> bool {
        Self::matches(&self.parts, path, ancestors, true)
    }

    fn is_root(&self, path: &str) -> bool {
        let end = self
            .parts
            .iter()
            .rposition(Option::is_some)
            .map_or(0, |i| i + 1);
        Self::matches(&self.parts[..end], path, false, false)
    }

    fn matches(parts: &[Option<Regex>], path: &str, ancestors: bool, subtree: bool) -> bool {
        let epsilon = |states: &mut HashSet<usize>| {
            for (i, part) in parts.iter().enumerate() {
                if part.is_none() && states.contains(&i) {
                    states.insert(i + 1);
                }
            }
        };
        let mut states = HashSet::from([0]);
        for component in path.trim_matches('/').split('/').filter(|c| !c.is_empty()) {
            epsilon(&mut states);
            if subtree && states.contains(&parts.len()) {
                return true;
            }
            states = states
                .into_iter()
                .filter_map(|i| match parts.get(i) {
                    Some(None) => Some(i),
                    Some(Some(re)) if re.is_match(component) => Some(i + 1),
                    _ => None,
                })
                .collect();
        }
        epsilon(&mut states);
        states.contains(&parts.len()) || ancestors && !states.is_empty()
    }
}

type DenialObserver = dyn Fn(&str, OverlayMutation) + Send + Sync;

/// Case-sensitive, root-anchored rules; matches cover their entire subtree.
/// More literal components win, with allow rules winning ties.
pub struct ReadOnlyGlobs {
    globs: Vec<PathGlob>,
    allows: Vec<PathGlob>,
    overlay_root: Option<PathBuf>,
    cow: Mutex<CopyReservations>,
    erofs_denied: AtomicU64,
    denial_observer: Mutex<Option<Arc<DenialObserver>>>,
}

impl ReadOnlyGlobs {
    /// Each item may contain comma-separated patterns. Empty items are errors.
    pub fn new(patterns: impl IntoIterator<Item = impl AsRef<str>>) -> io::Result<Self> {
        Self::with_allow(patterns, std::iter::empty::<&str>())
    }

    /// Parse read-only rules and exceptions. Each item may contain comma-separated
    /// patterns. Exceptions require at least one read-only rule.
    pub fn with_allow(
        readonly: impl IntoIterator<Item = impl AsRef<str>>,
        allow: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> io::Result<Self> {
        fn parse(patterns: impl IntoIterator<Item = impl AsRef<str>>) -> io::Result<Vec<PathGlob>> {
            let mut globs = Vec::new();
            for value in patterns {
                for pattern in value.as_ref().split(',') {
                    globs.push(PathGlob::new(pattern.trim())?);
                }
            }
            Ok(globs)
        }
        let globs = parse(readonly)?;
        let allows = parse(allow)?;
        if globs.is_empty() && !allows.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "overlay allow rules require at least one read-only rule",
            ));
        }
        Ok(Self {
            globs,
            allows,
            overlay_root: None,
            cow: Mutex::new(CopyReservations::default()),
            erofs_denied: AtomicU64::new(0),
            denial_observer: Mutex::new(None),
        })
    }

    /// Original rules in input order, with comma-separated items expanded and
    /// surrounding whitespace trimmed. Suitable for overlay metadata.
    pub fn rules_json(&self) -> serde_json::Value {
        serde_json::json!({
            "readonly": self.globs.iter().map(|g| &g.pattern).collect::<Vec<_>>(),
            "allow": self.allows.iter().map(|g| &g.pattern).collect::<Vec<_>>(),
        })
    }

    pub fn erofs_denied(&self) -> u64 {
        self.erofs_denied.load(Ordering::Relaxed)
    }

    /// Called once per returned EROFS, with the requested path and policy op.
    /// Metadata/xattr changes use the existing Write/CopyOnWrite operations.
    /// Like other policy hooks, observers must not call back into the overlay.
    pub fn set_denial_observer(&self, f: Arc<DenialObserver>) {
        *self
            .denial_observer
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(f);
    }

    fn deny(&self, path: &str, op: OverlayMutation, message: String) -> io::Error {
        self.erofs_denied.fetch_add(1, Ordering::Relaxed);
        let observer = self
            .denial_observer
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(observer) = observer {
            observer(path, op);
        }
        io::Error::new(io::ErrorKind::ReadOnlyFilesystem, message)
    }

    /// Resolve host parent symlinks too, so full-path frontends cannot bypass
    /// rules through an alias to pre-existing protected overlay content.
    pub fn with_overlay_root(mut self, root: &Path) -> io::Result<Self> {
        self.overlay_root = Some(root.canonicalize()?);
        Ok(self)
    }

    fn resolved_parent_path(&self, path: &str) -> Option<String> {
        let root = self.overlay_root.as_ref()?;
        let host = root.join(path.trim_start_matches('/'));
        let mut parent = host.parent()?;
        let mut suffix = PathBuf::from(host.file_name()?);
        loop {
            match parent.canonicalize() {
                Ok(resolved) => {
                    return resolved
                        .join(suffix)
                        .strip_prefix(root)
                        .ok()
                        .map(|p| format!("/{}", p.to_string_lossy()))
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    suffix = PathBuf::from(parent.file_name()?).join(suffix);
                    parent = parent.parent()?;
                }
                Err(_) => return None,
            }
        }
    }

    pub fn protects(&self, path: &str) -> bool {
        self.denies_path(path, false)
    }

    fn denies_path(&self, path: &str, ancestors: bool) -> bool {
        let allow = self
            .allows
            .iter()
            .filter(|g| g.protects(path, false))
            .map(|g| g.literal_components)
            .max();
        let readonly = self
            .globs
            .iter()
            .filter(|g| g.protects(path, ancestors))
            .map(|g| g.literal_components)
            .max();
        // Keep exception roots inside protected subtrees anchored. Fully canceled
        // read-only rules have no protected boundary to preserve.
        let exception_root = ancestors
            && self.allows.iter().any(|g| g.is_root(path))
            && self.has_protected_parent(path);
        exception_root || readonly.is_some_and(|score| allow.is_none_or(|a| score > a))
    }

    fn has_protected_parent(&self, path: &str) -> bool {
        let path = path.trim_matches('/');
        !path.is_empty() && self.protects(path.rsplit_once('/').map_or("", |(parent, _)| parent))
    }
}

impl OverlayPolicy for ReadOnlyGlobs {
    fn check_mutation(&self, op: OverlayMutation, paths: &[&str]) -> io::Result<()> {
        let ancestors = matches!(
            op,
            OverlayMutation::Rename | OverlayMutation::Rmdir | OverlayMutation::Reset
        );
        let mut cow = self.cow.lock().unwrap_or_else(|e| e.into_inner());
        for path in paths {
            let resolved = self.resolved_parent_path(path);
            if self.denies_path(path, ancestors)
                || resolved
                    .as_deref()
                    .is_some_and(|p| self.denies_path(p, ancestors))
            {
                drop(cow);
                return Err(self.deny(path, op, format!("protected overlay path: {path}")));
            }
            // COW publishes after dropping the gate to copy. Keep its parents
            // stable until accounting settles, including physical symlink targets.
            if !self.globs.is_empty()
                && matches!(
                    op,
                    OverlayMutation::Unlink
                        | OverlayMutation::Rmdir
                        | OverlayMutation::Rename
                        | OverlayMutation::Reset
                )
            {
                for (_, copying) in cow.copies.keys() {
                    let target = self.resolved_parent_path(copying);
                    let is_parent = |parent: &str, child: &str| {
                        parent == "/"
                            || child
                                .strip_prefix(parent)
                                .is_some_and(|tail| tail.starts_with('/'))
                    };
                    if [Some(*path), resolved.as_deref()]
                        .into_iter()
                        .flatten()
                        .any(|parent| {
                            is_parent(parent, copying)
                                || target
                                    .as_deref()
                                    .is_some_and(|child| is_parent(parent, child))
                        })
                    {
                        let message =
                            format!("cannot replace COW parent {path} while copying {copying}");
                        drop(cow);
                        return Err(self.deny(path, op, message));
                    }
                }
            }
        }
        cow.mutation(op, paths);
        Ok(())
    }
    fn check_write(&self, path: &str, _: u64, _: u64, _: u64) -> io::Result<()> {
        self.check_mutation(OverlayMutation::Write, &[path])
    }
    fn bytes_changed(&self, path: &str, added: u64, removed: u64) {
        self.cow
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .changed(path, added, removed);
    }
    fn file_created(&self, path: &str) {
        self.cow
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .created(path);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuotaUsage {
    pub bytes: u64,
    pub files: u64,
    pub byte_limit: Option<u64>,
    pub file_limit: Option<u64>,
    pub erofs_denied: u64,
}

impl QuotaUsage {
    pub fn status_text(&self) -> String {
        let limit = |v: Option<u64>| {
            v.map(|n| n.to_string())
                .unwrap_or_else(|| "unlimited".into())
        };
        format!(
            "overlay_bytes {}\noverlay_quota_bytes {}\noverlay_files {}\noverlay_quota_files {}\nerofs_denied {}\n",
            self.bytes,
            limit(self.byte_limit),
            self.files,
            limit(self.file_limit),
            self.erofs_denied,
        )
    }
}

#[derive(Default)]
struct CopyReservations {
    // The thread distinguishes competing copies to the same path. Reservations
    // span the synchronous copy, including callbacks after the gate is released.
    copies: HashMap<(ThreadId, String), u64>,
    checks: HashSet<(ThreadId, String)>,
}

impl CopyReservations {
    fn mutation(&mut self, op: OverlayMutation, paths: &[&str]) {
        let thread = thread::current().id();
        if op != OverlayMutation::Write {
            self.checks.retain(|(id, _)| *id != thread);
        }
        if op == OverlayMutation::CopyOnWrite {
            for path in paths {
                self.checks.insert((thread, path.to_string()));
            }
        }
    }

    fn changed(&mut self, path: &str, added: u64, removed: u64) {
        let key = (thread::current().id(), path.to_string());
        if let Some(bytes) = self.copies.get_mut(&key) {
            // Includes the zero-byte refund when an empty COW copy fails.
            if removed >= *bytes && added == 0 {
                self.copies.remove(&key);
                self.checks.remove(&key);
            } else {
                *bytes = bytes.saturating_add(added).saturating_sub(removed);
            }
        } else if self.checks.contains(&key) && removed == 0 {
            self.copies.insert(key, added);
        }
    }

    fn created(&mut self, path: &str) {
        let key = (thread::current().id(), path.to_string());
        self.copies.remove(&key);
        self.checks.remove(&key);
    }
}

#[derive(Default)]
struct QuotaState {
    bytes: u64,
    files: u64,
    cow: CopyReservations,
}

pub struct OverlayQuota {
    root: PathBuf,
    byte_limit: Option<u64>,
    file_limit: Option<u64>,
    state: Mutex<QuotaState>,
    readonly: Option<Arc<ReadOnlyGlobs>>,
}

impl OverlayQuota {
    pub fn new(root: &Path, byte_limit: Option<u64>, file_limit: Option<u64>) -> io::Result<Self> {
        let usage = OverlayUsage::scan(root)?;
        Ok(Self {
            root: root.canonicalize()?,
            readonly: None,
            byte_limit,
            file_limit,
            state: Mutex::new(QuotaState {
                bytes: usage.bytes,
                files: usage.files,
                ..Default::default()
            }),
        })
    }

    /// Include this policy's live denial count in the shared status snapshot.
    pub fn with_readonly(mut self, rules: Arc<ReadOnlyGlobs>) -> Self {
        self.readonly = Some(rules);
        self
    }

    /// Rescan the locked directory and replace the byte and file counters.
    pub fn rescan(&self) -> io::Result<QuotaUsage> {
        let usage = OverlayUsage::scan(&self.root)?;
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.bytes = usage.bytes;
        state.files = usage.files;
        drop(state);
        Ok(self.usage())
    }

    pub fn usage(&self) -> QuotaUsage {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        QuotaUsage {
            bytes: state.bytes,
            files: state.files + state.cow.copies.len() as u64,
            byte_limit: self.byte_limit,
            file_limit: self.file_limit,
            erofs_denied: self
                .readonly
                .as_ref()
                .map_or(0, |rules| rules.erofs_denied()),
        }
    }

    fn host_exists(&self, path: &str) -> bool {
        fs::symlink_metadata(self.root.join(path.trim_start_matches('/'))).is_ok()
    }

    fn check_file_slot(&self, path: &str, state: &QuotaState) -> io::Result<()> {
        if !self.host_exists(path)
            && !state
                .cow
                .copies
                .contains_key(&(thread::current().id(), path.to_string()))
            && self
                .file_limit
                .is_some_and(|limit| state.files + state.cow.copies.len() as u64 >= limit)
        {
            return Err(io::Error::new(
                io::ErrorKind::QuotaExceeded,
                "overlay file quota exceeded",
            ));
        }
        Ok(())
    }
}

impl OverlayPolicy for OverlayQuota {
    fn rescan(&self) -> io::Result<()> {
        let usage = OverlayUsage::scan(&self.root)?;
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.bytes = usage.bytes;
        state.files = usage.files;
        Ok(())
    }

    fn check_mutation(&self, op: OverlayMutation, paths: &[&str]) -> io::Result<()> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.cow.mutation(op, paths);
        if matches!(
            op,
            OverlayMutation::Create | OverlayMutation::Symlink | OverlayMutation::OpenWrite
        ) {
            for path in paths {
                self.check_file_slot(path, &state)?;
            }
        }
        Ok(())
    }

    fn check_write(&self, path: &str, offset: u64, len: u64, current_size: u64) -> io::Result<()> {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let growth = offset
            .checked_add(len)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::QuotaExceeded, "overlay extent overflows u64")
            })?
            .saturating_sub(current_size);
        if growth > 0
            && self
                .byte_limit
                .is_some_and(|limit| state.bytes.checked_add(growth).is_none_or(|n| n > limit))
        {
            return Err(io::Error::new(
                io::ErrorKind::QuotaExceeded,
                "overlay byte quota exceeded",
            ));
        }
        if state
            .cow
            .checks
            .contains(&(thread::current().id(), path.to_string()))
        {
            self.check_file_slot(path, &state)?;
        }
        Ok(())
    }

    fn bytes_changed(&self, path: &str, added: u64, removed: u64) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.bytes = state.bytes.saturating_add(added).saturating_sub(removed);
        state.cow.changed(path, added, removed);
    }
    fn file_created(&self, path: &str) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.cow.created(path);
        state.files += 1;
    }
    fn file_removed(&self, _: &str) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.files = state.files.saturating_sub(1);
    }
}

/// Checks run in order (install read-only rules first); accounting reaches all policies.
pub struct CompositeOverlayPolicy(pub Vec<Arc<dyn OverlayPolicy>>);

impl OverlayPolicy for CompositeOverlayPolicy {
    fn check_mutation(&self, op: OverlayMutation, paths: &[&str]) -> io::Result<()> {
        for policy in &self.0 {
            policy.check_mutation(op, paths)?;
        }
        Ok(())
    }
    fn check_write(&self, path: &str, offset: u64, len: u64, size: u64) -> io::Result<()> {
        for policy in &self.0 {
            policy.check_write(path, offset, len, size)?;
        }
        Ok(())
    }
    fn bytes_changed(&self, path: &str, added: u64, removed: u64) {
        for policy in &self.0 {
            policy.bytes_changed(path, added, removed);
        }
    }
    fn file_created(&self, path: &str) {
        for policy in &self.0 {
            policy.file_created(path);
        }
    }
    fn file_removed(&self, path: &str) {
        for policy in &self.0 {
            policy.file_removed(path);
        }
    }
    fn rescan(&self) -> io::Result<()> {
        for policy in &self.0 {
            policy.rescan()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ControlFolderMountSource, ControlFolderOptions};
    use ratarmount_core::{MountSource, OpenOptions};
    use ratarmount_formats_tar::SqliteIndexedTar;
    use ratarmount_formats_tar::{write_tar_eof, write_ustar_members, UstarMember, UstarPayload};
    use rusqlite::Connection;
    use std::fs::File;
    use std::io::{Cursor, Read};

    fn archive() -> Arc<dyn MountSource> {
        archive_with_paths(&["t/file", "outside", "deleted", "empty"])
    }

    fn archive_with_paths(paths: &[&str]) -> Arc<dyn MountSource> {
        let mut bytes = Vec::new();
        let members: Vec<_> = paths
            .iter()
            .map(|path| UstarMember {
                xattrs: &[],
                path,
                payload: UstarPayload::File {
                    bytes: if *path == "empty" {
                        &b""[..]
                    } else {
                        &b"base"[..]
                    },
                },
                mode: 0o644,
                uid: 0,
                gid: 0,
                mtime: 0,
            })
            .collect();
        write_ustar_members(&mut bytes, &members).unwrap();
        write_tar_eof(&mut bytes).unwrap();
        Arc::new(
            SqliteIndexedTar::open_from_reader(
                Cursor::new(bytes),
                "policy.tar",
                None,
                &OpenOptions::default(),
                "test",
            )
            .unwrap(),
        )
    }

    /// Regression: anchored, case-sensitive globs must cover directory nodes and arbitrary depth.
    #[test]
    fn regression_readonly_glob_anchoring_and_directory() {
        for (pattern, path, matched) in [
            ("tests/**", "tests", true),
            ("tests/**", "/tests/a/b.t", true),
            ("/tests/**", "/tests/a", true),
            ("tests/**", "/other/tests/a", false),
            ("tests/**", "/Tests/a", false),
            ("*.rs", "/a.rs", true),
            ("*.rs", "/x/a.rs", false),
            ("**/*.rs", "/x/y/a.rs", true),
            ("**/*.rs", "/a.rs", true),
            ("t/*", "/t/a/b", true),
            ("t/?/z", "/t/a/z", true),
            ("t/?/z", "/t/ab/z", false),
            ("a/**/z", "/a/z", true),
            ("a/**/z", "/a/x/y/z", true),
            ("a/**/z", "/a/x/y", false),
            ("t/[x]", "/t/[x]", true),
            ("t/", "/t/a", true),
            ("**", "/", true),
            ("t/?", "/t/é", true),
            ("t/*", "/t", false),
        ] {
            assert_eq!(
                ReadOnlyGlobs::new([pattern]).unwrap().protects(path),
                matched,
                "{pattern} {path}"
            );
        }
        let rules = ReadOnlyGlobs::new(["t/**,tests/**", "src/private"]).unwrap();
        assert!(rules.protects("/tests/a"));
        assert!(rules.protects("/src/private/x"));
        for bad in ["", "t,,a", "../x", "a/./b", "a//b", "x**y"] {
            assert!(ReadOnlyGlobs::new([bad]).is_err(), "{bad}");
        }
        let rules = ReadOnlyGlobs::new(["a/*/protected"]).unwrap();
        assert!(rules
            .check_mutation(OverlayMutation::Rename, &["/a", "/b"])
            .is_err());
        assert!(rules
            .check_mutation(OverlayMutation::Rename, &["/b", "/c"])
            .is_ok());
    }

    /// Regression: exceptions must permit every mutation and creation of their own root,
    /// while both rename endpoints and protected ancestors remain guarded.
    #[test]
    fn regression_readonly_allow_per_op_truth_table() {
        use OverlayMutation::*;
        let rules = ReadOnlyGlobs::with_allow(["t/**"], ["t/agent/**"]).unwrap();
        let paths = ["/t/suite", "/t/agent", "/t/agent/leaf", "/other"];
        for (op, expected) in [
            (CopyOnWrite, [false, true, true, true]),
            (Create, [false, true, true, true]),
            (OpenWrite, [false, true, true, true]),
            (Write, [false, true, true, true]),
            (Mkdir, [false, true, true, true]),
            (Unlink, [false, true, true, true]),
            (Rmdir, [false, false, true, true]),
            (Truncate, [false, true, true, true]),
            (Symlink, [false, true, true, true]),
            (Rename, [false, false, true, true]),
            (Reset, [false, false, true, true]),
        ] {
            for (path, allowed) in paths.into_iter().zip(expected) {
                let result = rules.check_mutation(op, &[path]);
                assert_eq!(result.is_ok(), allowed, "{op:?} {path}: {result:?}");
                if let Err(error) = result {
                    assert_eq!(error.kind(), io::ErrorKind::ReadOnlyFilesystem);
                }
            }
        }
        for (from, to, allowed) in [
            ("/t", "/moved", false),
            ("/t/agent", "/moved", false),
            ("/outside", "/t/agent", false),
            ("/t/agent/a", "/t/agent/b", true),
            ("/t/agent/a", "/outside", true),
            ("/outside", "/t/agent/a", true),
            ("/t/agent/a", "/t/suite/a", false),
            ("/t/suite/a", "/t/agent/a", false),
        ] {
            assert_eq!(
                rules.check_mutation(Rename, &[from, to]).is_ok(),
                allowed,
                "rename {from} -> {to}"
            );
        }
        assert!(rules.check_mutation(Reset, &["/"]).is_err());
    }

    /// Regression: specificity counts whole literal components; allow wins ties,
    /// independently of rule order, and more specific protected descendants stay fixed.
    #[test]
    fn regression_readonly_allow_specificity_and_ties() {
        for readonly in [
            ["t/**", "t/agent/private/**"],
            ["t/agent/private/**", "t/**"],
        ] {
            let rules = ReadOnlyGlobs::with_allow(readonly, ["t/agent/**"]).unwrap();
            assert!(!rules.protects("/t/agent/a"));
            assert!(rules.protects("/t/agent/private/a"));
            assert!(rules
                .check_mutation(OverlayMutation::Rename, &["/t/agent"])
                .is_err());
        }
        for (readonly, allow, path, denied) in [
            ("t/agent/**", "t/agent/**", "/t/agent", false),
            (
                "t/*/long-literal/**",
                "t/agent/**",
                "/t/agent/long-literal/file",
                false,
            ),
            (
                "t/agent/**",
                "t/ag?nt/long-literal/**",
                "/t/agent/long-literal/file",
                false,
            ),
            (
                "t/agent/private/**",
                "t/agent/*/**",
                "/t/agent/private/file",
                true,
            ),
            ("t/**", "t/agent/*", "/t/agent", true),
            ("t/**", "t/agent/*", "/t/agent/file/deep", false),
            ("t/**", "t/**/agent/**", "/t/a/b/agent", false),
        ] {
            let rules = ReadOnlyGlobs::with_allow([readonly], [allow]).unwrap();
            assert_eq!(
                rules.protects(path),
                denied,
                "{readonly} vs {allow}: {path}"
            );
        }
        // An identical allow cancels the protected boundary at and below its root.
        let canceled = ReadOnlyGlobs::with_allow(["t/**"], ["t/**"]).unwrap();
        for path in ["/t", "/t/agent", "/t/agent/leaf"] {
            canceled
                .check_mutation(OverlayMutation::Rename, &[path])
                .unwrap();
        }
        // A redundant exception inside an allowed subtree adds no boundary.
        let redundant =
            ReadOnlyGlobs::with_allow(["t/**"], ["t/agent/**", "t/agent/leaf/**"]).unwrap();
        redundant
            .check_mutation(OverlayMutation::Rename, &["/t/agent/leaf"])
            .unwrap();
        let rules =
            ReadOnlyGlobs::with_allow(["t/**", "t/agent/work/*/secret"], ["t/agent/**"]).unwrap();
        assert!(!rules.protects("/t/agent/work"));
        assert!(rules
            .check_mutation(OverlayMutation::Rename, &["/t/agent/work"])
            .is_err());
        assert!(rules
            .check_mutation(OverlayMutation::Rename, &["/t/agent/leaf"])
            .is_ok());
    }

    /// Regression: metadata export must preserve rule order and reject invalid exceptions.
    #[test]
    fn regression_readonly_rules_json_and_invalid_allow() {
        let rules = ReadOnlyGlobs::with_allow(
            [" t/**, /tests/ ", "src/private"],
            ["t/agent/**,tests/new", "t/agent/**"],
        )
        .unwrap();
        assert_eq!(
            rules.rules_json(),
            serde_json::json!({
                "readonly": ["t/**", "/tests/", "src/private"],
                "allow": ["t/agent/**", "tests/new", "t/agent/**"],
            })
        );
        assert!(ReadOnlyGlobs::with_allow(std::iter::empty::<&str>(), ["t/agent/**"]).is_err());
        for bad in ["", "t,,a", "../x", "a/./b", "a//b", "x**y"] {
            assert!(ReadOnlyGlobs::with_allow(["t/**"], [bad]).is_err(), "{bad}");
        }
        assert_eq!(
            ReadOnlyGlobs::new(["t"]).unwrap().rules_json(),
            serde_json::json!({"readonly": ["t"], "allow": []})
        );
    }

    /// Regression: multiple protected paths and COW-parent guards count and notify
    /// exactly once per policy error; successful checks and queries never count.
    #[test]
    fn regression_readonly_denial_counter_and_observer_once() {
        let rules = Arc::new(ReadOnlyGlobs::with_allow(["t/**"], ["t/agent/**"]).unwrap());
        let events = Arc::new(Mutex::new(Vec::new()));
        let weak = Arc::downgrade(&rules);
        let observed = events.clone();
        rules.set_denial_observer(Arc::new(move |path, op| {
            let rules = weak.upgrade().unwrap();
            assert!(rules.erofs_denied() > 0);
            // Observers run without the observer or reservation mutex held.
            rules.set_denial_observer(Arc::new(|_, _| {}));
            rules.bytes_changed("/unused", 0, 0);
            observed.lock().unwrap().push((path.to_string(), op));
        }));
        assert!(rules.protects("/t/suite"));
        rules
            .check_mutation(OverlayMutation::Create, &["/t/agent/a"])
            .unwrap();
        assert_eq!(rules.erofs_denied(), 0);
        assert!(rules
            .check_mutation(OverlayMutation::Rename, &["/t/a", "/t/b"])
            .is_err());
        assert_eq!(rules.erofs_denied(), 1);
        assert_eq!(
            *events.lock().unwrap(),
            [("/t/a".into(), OverlayMutation::Rename)]
        );
        let observed = events.clone();
        rules.set_denial_observer(Arc::new(move |path, op| {
            observed.lock().unwrap().push((path.to_string(), op));
        }));
        assert!(rules.check_write("/t/a", 0, 1, 0).is_err());
        rules.check_write("/t/agent/a", 0, 1, 0).unwrap();
        rules
            .check_mutation(OverlayMutation::CopyOnWrite, &["/outside/file"])
            .unwrap();
        rules.bytes_changed("/outside/file", 1, 0);
        assert!(rules
            .check_mutation(OverlayMutation::Rename, &["/outside", "/elsewhere"])
            .is_err());
        assert_eq!(rules.erofs_denied(), 3);
        assert_eq!(
            *events.lock().unwrap(),
            [
                ("/t/a".into(), OverlayMutation::Rename),
                ("/t/a".into(), OverlayMutation::Write),
                ("/outside".into(), OverlayMutation::Rename),
            ]
        );
        rules.file_created("/outside/file");
        rules
            .check_mutation(OverlayMutation::Rename, &["/outside", "/elsewhere"])
            .unwrap();
        assert_eq!(rules.erofs_denied(), 3);
    }

    /// Regression: real overlay writes, chmod and xattrs must honor exceptions
    /// without copying or altering protected archive members.
    #[cfg(unix)]
    #[test]
    fn regression_readonly_allow_overlay_mutations() {
        let root = tempfile::tempdir().unwrap();
        let mut overlay = crate::WriteOverlay::new_for_tests(
            archive_with_paths(&["t/file", "t/agent/base"]),
            root.path(),
        )
        .unwrap();
        let protected = new_file(&overlay, "/t/host");
        let rules = Arc::new(
            ReadOnlyGlobs::with_allow(["t/**"], ["t/agent/**"])
                .unwrap()
                .with_overlay_root(root.path())
                .unwrap(),
        );
        overlay.set_policy(Some(rules.clone()));
        let ro = io::ErrorKind::ReadOnlyFilesystem;
        denied(overlay.create_file("/t/new", 0o644), ro);
        denied(overlay.mkdir("/t/blocked", 0o755), ro);
        denied(overlay.ensure_modifiable("/t/file"), ro);
        assert_eq!(
            overlay
                .write_at(&protected, "/t/host", 0, b"no")
                .unwrap_err()
                .kind(),
            ro
        );
        denied(overlay.truncate("/t/file", 0), ro);
        denied(overlay.unlink("/t/file"), ro);
        let attrs = crate::OverlayMetadata {
            mode: Some(0o600),
            ..Default::default()
        };
        denied(overlay.set_metadata("/t/file", &attrs), ro);
        denied(overlay.set_xattr("/t/file", "user.test", b"x", 0), ro);
        overlay.mkdir("/t/agent", 0o755).unwrap();
        overlay.mkdir("/t/agent/dir", 0o755).unwrap();
        let file = new_file(&overlay, "/t/agent/dir/new");
        overlay
            .write_at(&file, "/t/agent/dir/new", 0, b"yes")
            .unwrap();
        overlay.truncate("/t/agent/dir/new", 2).unwrap();
        overlay.ensure_modifiable("/t/agent/base").unwrap();
        overlay.set_metadata("/t/agent/base", &attrs).unwrap();
        overlay
            .set_xattr("/t/agent/base", "user.test", b"x", 0)
            .unwrap();
        overlay.create_symlink("/t/agent/link", "base").unwrap();
        overlay.unlink("/t/agent/link").unwrap();
        overlay
            .rename("/t/agent/dir/new", "/t/agent/dir/moved")
            .unwrap();
        denied(overlay.rename("/t/agent/dir/moved", "/t/moved"), ro);
        denied(overlay.rename("/t/agent", "/moved"), ro);
        overlay.unlink("/t/agent/dir/moved").unwrap();
        overlay.rmdir("/t/agent/dir").unwrap();
        assert_eq!(rules.erofs_denied(), 10);
        overlay.finish_owned_write_fd(file);
        overlay.finish_owned_write_fd(protected);
    }

    /// Regression: an allowed spelling cannot bypass a protected host symlink target.
    #[cfg(unix)]
    #[test]
    fn regression_readonly_allow_symlink_alias() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("t/agent")).unwrap();
        fs::create_dir_all(root.path().join("t/private")).unwrap();
        std::os::unix::fs::symlink("../private", root.path().join("t/agent/alias")).unwrap();
        let rules = ReadOnlyGlobs::with_allow(["t/**"], ["t/agent/**"])
            .unwrap()
            .with_overlay_root(root.path())
            .unwrap();
        assert!(rules
            .check_mutation(OverlayMutation::Create, &["/t/agent/alias/file"])
            .is_err());
        rules
            .check_mutation(OverlayMutation::Unlink, &["/t/agent/alias"])
            .unwrap();
        assert_eq!(rules.erofs_denied(), 1);
    }

    /// Regression: invalid and overflowing quota sizes must fail before opening an archive.
    #[test]
    fn regression_overlay_size_overflow() {
        for (text, expected) in [
            ("0", 0),
            ("12", 12),
            ("2K", 2048),
            ("3m", 3 << 20),
            ("4G", 4 << 30),
            ("1T", 1 << 40),
        ] {
            assert_eq!(parse_overlay_size(text).unwrap(), expected);
        }
        for text in [
            "",
            "K",
            "-1",
            "+1",
            "1.5G",
            "1GB",
            "18446744073709551615K",
            "18446744073709551616",
        ] {
            assert!(parse_overlay_size(text).is_err(), "{text}");
        }
    }

    #[cfg(unix)]
    fn new_file(overlay: &crate::WriteOverlay, path: &str) -> File {
        use std::os::fd::FromRawFd;
        unsafe { File::from_raw_fd(overlay.create_file(path, 0o644).unwrap()) }
    }

    fn denied<T: std::fmt::Debug>(result: Result<T, OverlayError>, kind: io::ErrorKind) {
        assert!(
            matches!(result, Err(OverlayError::Io(ref error)) if error.kind() == kind),
            "{result:?}"
        );
    }

    /// Regression: each protected mutation, both rename endpoints and ancestor renames fail with EROFS.
    #[cfg(unix)]
    #[test]
    fn regression_readonly_mutations_and_parent_rename() {
        let root = tempfile::tempdir().unwrap();
        let mut overlay = crate::WriteOverlay::new_for_tests(archive(), root.path()).unwrap();
        overlay.mkdir("/t/empty", 0o755).unwrap();
        let protected = new_file(&overlay, "/t/host");
        let outside = new_file(&overlay, "/allowed");
        overlay.set_policy(Some(Arc::new(
            ReadOnlyGlobs::new(["t/**", "parent/*/test"])
                .unwrap()
                .with_overlay_root(root.path())
                .unwrap(),
        )));
        let ro = io::ErrorKind::ReadOnlyFilesystem;
        denied(overlay.ensure_modifiable("/t/file"), ro);
        denied(overlay.create_file("/t/new", 0o644), ro);
        denied(overlay.mkdir("/t/newdir", 0o755), ro);
        denied(overlay.unlink("/t/file"), ro);
        denied(overlay.rmdir("/t/empty"), ro);
        denied(overlay.rmdir("/t"), ro);
        denied(overlay.truncate("/t/host", 1), ro);
        denied(overlay.create_symlink("/t/link", "target"), ro);
        denied(overlay.rename("/t/file", "/moved"), ro);
        denied(overlay.rename("/outside", "/t/file"), ro);
        denied(overlay.rename("/t", "/t2"), ro);
        denied(overlay.rename("/parent", "/elsewhere"), ro);
        denied(overlay.open_overlay_fd("/t/host", libc::O_WRONLY), ro);
        denied(overlay.reset_overlay_contents(), ro);
        assert_eq!(
            overlay
                .write_at(&protected, "/t/host", 0, b"x")
                .unwrap_err()
                .kind(),
            ro
        );
        assert_eq!(
            overlay
                .truncate_file(&protected, "/t/host", 1)
                .unwrap_err()
                .kind(),
            ro
        );
        let read = overlay.open_overlay_fd("/t/host", libc::O_RDONLY).unwrap();
        overlay.close_overlay_fd(read);
        let mut payload = Vec::new();
        overlay
            .open(&overlay.lookup("/t/file", 0).unwrap(), 0)
            .unwrap()
            .read_to_end(&mut payload)
            .unwrap();
        assert_eq!(payload, b"base");
        overlay.write_at(&outside, "/allowed", 0, b"yes").unwrap();
        overlay.truncate("/allowed", 2).unwrap();
        overlay.mkdir("/ok", 0o755).unwrap();
        overlay.create_symlink("/ok/link", "target").unwrap();
        overlay.rename("/allowed", "/ok/moved").unwrap();
        overlay.unlink("/ok/link").unwrap();
        overlay.unlink("/ok/moved").unwrap();
        overlay.rmdir("/ok").unwrap();
        overlay.ensure_modifiable("/outside").unwrap();
        overlay.finish_owned_write_fd(protected);
        overlay.finish_owned_write_fd(outside);
    }

    /// Regression: COW, sparse writes, truncate, unlink and rename must keep byte/file usage exact.
    #[cfg(unix)]
    #[test]
    fn regression_quota_growth_unlink_and_startup_scan() {
        let root = tempfile::tempdir().unwrap();
        let mut overlay = crate::WriteOverlay::new_for_tests(archive(), root.path()).unwrap();
        fs::write(root.path().join("preexisting"), b"abc").unwrap();
        let quota = Arc::new(OverlayQuota::new(root.path(), Some(10), Some(3)).unwrap());
        assert_eq!((quota.usage().bytes, quota.usage().files), (3, 1));
        overlay.set_policy(Some(quota.clone()));
        overlay.ensure_modifiable("/outside").unwrap();
        assert_eq!((quota.usage().bytes, quota.usage().files), (7, 2));
        let file = new_file(&overlay, "/new");
        overlay.write_at(&file, "/new", 0, b"abc").unwrap();
        assert_eq!(quota.usage().bytes, 10);
        assert_eq!(
            overlay.write_at(&file, "/new", 3, b"x").unwrap_err().kind(),
            io::ErrorKind::QuotaExceeded
        );
        assert_eq!(
            overlay
                .write_at(&file, "/new", u64::MAX, b"x")
                .unwrap_err()
                .kind(),
            io::ErrorKind::QuotaExceeded
        );
        denied(
            overlay.create_file("/overfiles", 0o644),
            io::ErrorKind::QuotaExceeded,
        );
        denied(
            overlay.ensure_modifiable("/empty"),
            io::ErrorKind::QuotaExceeded,
        );
        overlay.truncate("/new", 1).unwrap();
        assert_eq!(quota.usage().bytes, 8);
        overlay.truncate("/new", 3).unwrap();
        denied(overlay.truncate("/new", 4), io::ErrorKind::QuotaExceeded);
        overlay.unlink("/preexisting").unwrap();
        assert_eq!((quota.usage().bytes, quota.usage().files), (7, 2));
        overlay.create_symlink("/link", "abc").unwrap();
        assert_eq!((quota.usage().bytes, quota.usage().files), (10, 3));
        overlay.unlink("/link").unwrap();
        overlay.rename("/new", "/preexisting").unwrap();
        assert_eq!((quota.usage().bytes, quota.usage().files), (7, 2));
        overlay.finish_owned_write_fd(file);
        assert_eq!(
            OverlayUsage::scan(root.path()).unwrap().bytes,
            quota.usage().bytes
        );
        let restart = OverlayQuota::new(root.path(), Some(1), None).unwrap();
        assert_eq!(restart.usage().bytes, 7);
        // Already over quota: no-growth operations and recovery remain possible.
        restart.check_write("/preexisting", 0, 1, 3).unwrap();
        assert!(restart.check_write("/preexisting", 3, 1, 3).is_err());
    }

    /// Regression: several concurrent writers must never exceed the global quota.
    #[cfg(unix)]
    #[test]
    fn regression_quota_concurrent_writers_never_exceed_cap() {
        let root = tempfile::tempdir().unwrap();
        let mut overlay = crate::WriteOverlay::new_for_tests(archive(), root.path()).unwrap();
        let quota = Arc::new(OverlayQuota::new(root.path(), Some(101), Some(8)).unwrap());
        overlay.set_policy(Some(quota.clone()));
        let overlay = Arc::new(overlay);
        let threads: Vec<_> = (0..8)
            .map(|i| {
                let overlay = overlay.clone();
                std::thread::spawn(move || {
                    let path = format!("/writer{i}");
                    let file = new_file(&overlay, &path);
                    for offset in 0..101 {
                        if let Err(error) = overlay.write_at(&file, &path, offset, b"x") {
                            assert_eq!(error.kind(), io::ErrorKind::QuotaExceeded);
                            break;
                        }
                    }
                    overlay.finish_owned_write_fd(file);
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        assert_eq!(quota.usage().bytes, 101);
        assert_eq!(OverlayUsage::scan(root.path()).unwrap().bytes, 101);
        assert_eq!(quota.usage().files, 8);
    }

    /// Regression: stats must include host additions/modifications and durable tombstones only.
    #[cfg(unix)]
    #[test]
    fn regression_overlay_stats_exact_counts_and_readonly_db() {
        let root = tempfile::tempdir().unwrap();
        let overlay = crate::WriteOverlay::new_for_tests(archive(), root.path()).unwrap();
        let file = new_file(&overlay, "/added");
        overlay.write_at(&file, "/added", 0, b"hello").unwrap();
        overlay.finish_owned_write_fd(file);
        overlay.truncate("/outside", 2).unwrap();
        overlay.unlink("/deleted").unwrap();
        overlay.mkdir("/created", 0o755).unwrap();
        overlay.create_symlink("/link", "added").unwrap();
        drop(overlay);
        fs::write(
            root.path().join(".RATARMOUNT.OVERLAY.SQLITE.extra"),
            b"ignored",
        )
        .unwrap();
        fs::create_dir(root.path().join(".ratarmount.overlay.sqlite.hidden")).unwrap();
        fs::write(
            root.path()
                .join(".ratarmount.overlay.sqlite.hidden/ignored"),
            b"ignored",
        )
        .unwrap();
        let before = fs::read(root.path().join(HIDDEN_DB)).unwrap();
        let stats = OverlayStats::read(root.path()).unwrap();
        assert_eq!(
            stats,
            OverlayStats {
                usage: OverlayUsage {
                    bytes: 12,
                    files: 3,
                    directories: 1,
                    symlinks: 1
                },
                files_deleted: 1
            }
        );
        assert_eq!(fs::read(root.path().join(HIDDEN_DB)).unwrap(), before);
    }

    /// Regression: missing, malformed and locked databases must fail without initializing a DB.
    #[test]
    fn regression_overlay_stats_missing_locked_db_does_not_create() {
        let root = tempfile::tempdir().unwrap();
        assert!(OverlayStats::read(root.path()).is_err());
        assert!(!root.path().join(HIDDEN_DB).exists());
        let conn = Connection::open(root.path().join(HIDDEN_DB)).unwrap();
        assert!(matches!(
            OverlayStats::read(root.path()),
            Err(OverlayError::Sqlite(_))
        ));
        conn.execute_batch("CREATE TABLE files (deleted INTEGER); BEGIN EXCLUSIVE;")
            .unwrap();
        assert!(OverlayStats::read(root.path()).unwrap_err().is_locked());
    }

    /// Regression: virtual status must reflect quota usage after writes, not a startup snapshot.
    #[cfg(unix)]
    #[test]
    fn regression_control_status_live_quota_usage() {
        let root = tempfile::tempdir().unwrap();
        let mut overlay = crate::WriteOverlay::new_for_tests(archive(), root.path()).unwrap();
        let rules = Arc::new(ReadOnlyGlobs::with_allow(["t/**"], ["t/agent/**"]).unwrap());
        let quota = Arc::new(
            OverlayQuota::new(root.path(), Some(10), Some(2))
                .unwrap()
                .with_readonly(rules.clone()),
        );
        overlay.set_policy(Some(Arc::new(CompositeOverlayPolicy(vec![
            rules.clone(),
            quota.clone(),
        ]))));
        let overlay = Arc::new(overlay);
        let control =
            ControlFolderMountSource::new(overlay.clone(), ControlFolderOptions::enabled())
                .with_on_status(Some(Arc::new(move || quota.usage().status_text())));
        let read_status = || {
            let info = control.lookup("/.ratarmount-control/status", 0).unwrap();
            let mut text = String::new();
            control
                .open(&info, 0)
                .unwrap()
                .read_to_string(&mut text)
                .unwrap();
            text
        };
        assert!(read_status().contains(
            "overlay_bytes 0\noverlay_quota_bytes 10\noverlay_files 0\noverlay_quota_files 2\n"
        ));
        assert!(read_status().contains("erofs_denied 0\n"));
        denied(overlay.unlink("/t/file"), io::ErrorKind::ReadOnlyFilesystem);
        assert!(read_status().contains("erofs_denied 1\n"));
        let file = new_file(&overlay, "/new");
        overlay.write_at(&file, "/new", 0, b"abc").unwrap();
        assert!(
            read_status().contains("overlay_bytes 3\noverlay_quota_bytes 10\noverlay_files 1\n")
        );
        overlay.finish_owned_write_fd(file);
    }
    struct GatedArchive {
        inner: Arc<dyn MountSource>,
        entered: std::sync::mpsc::Sender<()>,
        release: Arc<std::sync::Barrier>,
        fail: bool,
    }

    impl MountSource for GatedArchive {
        fn is_immutable(&self) -> bool {
            self.inner.is_immutable()
        }
        fn list(&self, path: &str) -> Option<ratarmount_core::ListResult> {
            self.inner.list(path)
        }
        fn lookup(&self, path: &str, version: i32) -> Option<ratarmount_core::FileInfo> {
            self.inner.lookup(path, version)
        }
        fn open(
            &self,
            info: &ratarmount_core::FileInfo,
            buffering: i32,
        ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
            self.entered.send(()).unwrap();
            self.release.wait();
            if self.fail {
                return Err(io::Error::other("injected COW read failure"));
            }
            self.inner.open(info, buffering)
        }
    }

    /// Regression: a copying COW file must reserve its slot, and failures must refund even empty copies.
    #[test]
    fn regression_quota_cow_file_reservation_and_failure_refund() {
        for (path, size) in [("/outside", 4), ("/empty", 0)] {
            for fail in [false, true] {
                let root = tempfile::tempdir().unwrap();
                let (entered_tx, entered_rx) = std::sync::mpsc::channel();
                let release = Arc::new(std::sync::Barrier::new(2));
                let base = Arc::new(GatedArchive {
                    inner: archive(),
                    entered: entered_tx,
                    release: release.clone(),
                    fail,
                });
                let mut overlay = crate::WriteOverlay::new_for_tests(base, root.path()).unwrap();
                let quota = Arc::new(OverlayQuota::new(root.path(), Some(4), Some(1)).unwrap());
                overlay.set_policy(Some(quota.clone()));
                let overlay = Arc::new(overlay);
                let worker_overlay = overlay.clone();
                let worker = thread::spawn(move || worker_overlay.ensure_modifiable(path));
                entered_rx
                    .recv_timeout(std::time::Duration::from_secs(10))
                    .unwrap();
                assert_eq!((quota.usage().bytes, quota.usage().files), (size, 1));
                let rejected = overlay.ensure_modifiable("/deleted");
                release.wait();
                let result = worker.join().unwrap();
                denied(rejected, io::ErrorKind::QuotaExceeded);
                assert_eq!(result.is_err(), fail);
                assert_eq!(
                    (quota.usage().bytes, quota.usage().files),
                    if fail { (0, 0) } else { (size, 1) }
                );
            }
        }
    }

    /// Regression: held unlinked-file growth is bytes only, and closing on another thread refunds it.
    #[cfg(unix)]
    #[test]
    fn regression_quota_unlinked_fd_does_not_leak_file_slot() {
        let root = tempfile::tempdir().unwrap();
        let mut overlay = crate::WriteOverlay::new_for_tests(archive(), root.path()).unwrap();
        let quota = Arc::new(OverlayQuota::new(root.path(), Some(10), Some(1)).unwrap());
        overlay.set_policy(Some(quota.clone()));
        let overlay = Arc::new(overlay);
        let file = new_file(&overlay, "/new");
        overlay.write_at(&file, "/new", 0, b"abc").unwrap();
        overlay.unlink("/new").unwrap();
        let other = new_file(&overlay, "/other");
        overlay.write_at(&file, "/new", 3, b"xy").unwrap();
        assert_eq!((quota.usage().bytes, quota.usage().files), (2, 1));
        let worker_overlay = overlay.clone();
        thread::spawn(move || worker_overlay.finish_owned_write_fd(file))
            .join()
            .unwrap();
        assert_eq!((quota.usage().bytes, quota.usage().files), (0, 1));
        overlay.finish_owned_write_fd(other);
    }
    /// Regression: startup usage must not follow dangling or directory symlinks, or charge internal files.
    #[cfg(unix)]
    #[test]
    fn regression_quota_scan_symlinks_and_zero_limits() {
        let root = tempfile::tempdir().unwrap();
        let external = tempfile::tempdir().unwrap();
        fs::write(external.path().join("large"), [0; 1024]).unwrap();
        std::os::unix::fs::symlink(external.path(), root.path().join("external")).unwrap();
        std::os::unix::fs::symlink("missing", root.path().join("dangling")).unwrap();
        fs::create_dir(root.path().join("nested")).unwrap();
        fs::write(
            root.path().join("nested/.ratarmount-overlay.used"),
            b"internal",
        )
        .unwrap();
        let quota = OverlayQuota::new(root.path(), Some(0), Some(0)).unwrap();
        assert_eq!(quota.usage().files, 2);
        assert_eq!(
            quota.usage().bytes,
            external.path().as_os_str().len() as u64 + 7
        );
        let empty = tempfile::tempdir().unwrap();
        let mut overlay = crate::WriteOverlay::new_for_tests(archive(), empty.path()).unwrap();
        overlay.set_policy(Some(Arc::new(
            OverlayQuota::new(empty.path(), Some(0), Some(0)).unwrap(),
        )));
        overlay.mkdir("/directory", 0o755).unwrap();
        denied(
            overlay.create_file("/new", 0o644),
            io::ErrorKind::QuotaExceeded,
        );
        denied(
            overlay.create_symlink("/link", "target"),
            io::ErrorKind::QuotaExceeded,
        );
    }
    /// Regression: full-path frontends must not mutate protected content through an overlay symlink alias.
    #[cfg(unix)]
    #[test]
    fn regression_readonly_parent_symlink_cannot_bypass_rules() {
        let root = tempfile::tempdir().unwrap();
        let mut overlay = crate::WriteOverlay::new_for_tests(archive(), root.path()).unwrap();
        overlay.ensure_modifiable("/t/file").unwrap();
        overlay.set_policy(Some(Arc::new(
            ReadOnlyGlobs::new(["t/**"])
                .unwrap()
                .with_overlay_root(root.path())
                .unwrap(),
        )));
        overlay.create_symlink("/alias", "t").unwrap();
        let ro = io::ErrorKind::ReadOnlyFilesystem;
        denied(overlay.create_file("/alias/new", 0o644), ro);
        denied(overlay.mkdir("/alias/newdir", 0o755), ro);
        denied(overlay.create_symlink("/alias/link", "target"), ro);
        denied(overlay.unlink("/alias/file"), ro);
        denied(overlay.truncate("/alias/file", 0), ro);
        denied(overlay.open_overlay_fd("/alias/file", libc::O_WRONLY), ro);
        denied(overlay.rename("/outside", "/alias/file"), ro);
        denied(overlay.rename("/alias/file", "/moved"), ro);
        // Resolve the nearest existing ancestor when deeper parents are absent.
        denied(overlay.create_file("/alias/missing/new", 0o644), ro);
        let read = overlay
            .open_overlay_fd("/alias/file", libc::O_RDONLY)
            .unwrap();
        overlay.close_overlay_fd(read);
        overlay.unlink("/alias").unwrap();
        assert_eq!(fs::read(root.path().join("t/file")).unwrap(), b"base");
    }
    /// Regression: replacing a COW parent mid-copy must not redirect publication into a protected directory.
    #[cfg(unix)]
    #[test]
    fn regression_readonly_cow_parent_replacement_cannot_redirect() {
        for symlinked in [false, true] {
            for fail in [false, true] {
                let root = tempfile::tempdir().unwrap();
                let (entered_tx, entered_rx) = std::sync::mpsc::channel();
                let release = Arc::new(std::sync::Barrier::new(2));
                let base = Arc::new(GatedArchive {
                    inner: archive_with_paths(&[if symlinked { "t/child/file" } else { "t/file" }]),
                    entered: entered_tx,
                    release: release.clone(),
                    fail,
                });
                let mut overlay = crate::WriteOverlay::new_for_tests(base, root.path()).unwrap();
                overlay.mkdir("/protected", 0o755).unwrap();
                if symlinked {
                    overlay.mkdir("/physical/child", 0o755).unwrap();
                    // An intermediate alias is allowed. An immediate symlink
                    // parent is rejected by ensure_parent before archive open.
                    std::os::unix::fs::symlink("physical", root.path().join("t")).unwrap();
                }
                let path = if symlinked {
                    "/t/child/file"
                } else {
                    "/t/file"
                };
                let rules = Arc::new(
                    ReadOnlyGlobs::new(["protected/**"])
                        .unwrap()
                        .with_overlay_root(root.path())
                        .unwrap(),
                );
                overlay.set_policy(Some(Arc::new(CompositeOverlayPolicy(vec![
                    rules.clone(),
                    Arc::new(OverlayQuota::new(root.path(), Some(64), Some(4)).unwrap()),
                ]))));
                let overlay = Arc::new(overlay);
                let worker_overlay = overlay.clone();
                let worker = thread::spawn(move || worker_overlay.ensure_modifiable(path));
                entered_rx
                    .recv_timeout(std::time::Duration::from_secs(10))
                    .unwrap();
                // Hide the base child so rmdir would otherwise see an empty parent.
                overlay.unlink(path).unwrap();
                let unlink_alias = rules.check_mutation(OverlayMutation::Unlink, &["/t"]);
                let rename_parent =
                    rules.check_mutation(OverlayMutation::Rename, &["/other", "/t"]);
                let parent = if symlinked { "/physical/child" } else { "/t" };
                let rename = overlay.rename(parent, "/replacement");
                let removal = overlay.rmdir(parent);
                if removal.is_ok() {
                    // This was the bypass before the reservation-parent guard.
                    overlay
                        .create_symlink(
                            parent,
                            if symlinked {
                                "../protected"
                            } else {
                                "protected"
                            },
                        )
                        .unwrap();
                }
                release.wait();
                let result = worker.join().unwrap();
                assert_eq!(result.is_err(), fail);
                let copied = root.path().join(path.trim_start_matches('/'));
                if fail {
                    assert!(!copied.exists());
                } else {
                    assert_eq!(fs::read(copied).unwrap(), b"base");
                }
                assert_eq!(
                    unlink_alias.unwrap_err().kind(),
                    io::ErrorKind::ReadOnlyFilesystem
                );
                assert_eq!(
                    rename_parent.unwrap_err().kind(),
                    io::ErrorKind::ReadOnlyFilesystem
                );
                denied(removal, io::ErrorKind::ReadOnlyFilesystem);
                denied(rename, io::ErrorKind::ReadOnlyFilesystem);
                assert!(!root.path().join("protected/file").exists());
                // Both successful and failed copies must release the parent guard.
                overlay.unlink(path).unwrap();
                if symlinked {
                    overlay.unlink("/t").unwrap();
                }
                overlay.rmdir(parent).unwrap();
            }
        }
    }
}
