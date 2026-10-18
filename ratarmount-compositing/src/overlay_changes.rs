//! Change sets, manifest rows and canonical hashes shared by diff and overlay tools.
//!
//! Paths are mount-relative UTF-8 at the MountSource boundary. The manifest and
//! canonical row writers accept bytes, including synthetic non-UTF-8 paths.

#[cfg(unix)]
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::fd::OwnedFd;
use std::path::Path;
use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ratarmount_core::{
    ArchiveRead, FileInfo, ListResult, MountSource, S_IFDIR, S_IFLNK, S_IFMT, S_IFREG,
};
use regex::bytes::Regex;
use rusqlite::{Connection, OpenFlags};
#[cfg(unix)]
use rustix::fs::{self as host, AtFlags, Dir, Mode, OFlags, Stat};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::{
    is_overlay_internal_path, serving_layer, Immutability, LayerIndex, ReadOnlyOverlayLayer,
    HIDDEN_DB,
};

/// SHA-256 of the empty canonical stream, independent of the base or stack.
pub const EMPTY_SHA256: &str =
    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Normalize {
    #[default]
    Exact,
    Strict,
    Loose,
}

impl Normalize {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Strict => "strict",
            Self::Loose => "loose",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Algorithm {
    #[default]
    Sha256,
    Blake3,
}

impl Algorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Blake3 => "blake3",
        }
    }
}

/// Options used when constructing and hashing a change set. Use Exact for
/// patches. Limits fail with [`LimitExceeded`], before opening file contents.
#[derive(Clone, Debug, Default)]
pub struct ChangeOptions {
    pub normalize: Normalize,
    pub algo: Algorithm,
    pub excludes: Vec<String>,
    pub ignore_mode: bool,
    pub include_git_dir: bool,
    pub max_files: Option<usize>,
    /// Optional input-work budget for patch generation. In addition to the
    /// rendered-output limit, refuse a single payload exceeding this size.
    pub max_content_bytes: Option<u64>,
}

#[derive(Debug)]
pub struct LimitExceeded(pub String);

impl std::fmt::Display for LimitExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for LimitExceeded {}

pub fn limit_error(message: impl Into<String>) -> io::Error {
    io::Error::other(LimitExceeded(message.into()))
}

pub fn is_limit_error(error: &io::Error) -> bool {
    error.get_ref().is_some_and(|e| e.is::<LimitExceeded>())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    Added,
    Modified,
    Deleted,
    TypeChanged,
    Written,
}
impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Added => "added",
            Self::Modified => "modified",
            Self::Deleted => "deleted",
            Self::TypeChanged => "type_changed",
            Self::Written => "written",
        }
    }
    pub fn letter(self) -> &'static str {
        match self {
            Self::Added => "A",
            Self::Modified => "M",
            Self::Deleted => "D",
            Self::TypeChanged => "T",
            Self::Written => "written",
        }
    }
}

/// A content snapshot. Regular files are reopened through their MountSource;
/// hashing never retains the payload. Symlinks contain their target bytes.
#[derive(Clone)]
pub struct Entry {
    pub mode: u32,
    pub size: u64,
    pub hash: Option<String>,
    pub target: Option<Vec<u8>>,
    source: Arc<dyn MountSource>,
    info: FileInfo,
}
impl Entry {
    /// Construct an entry from bytes supplied by an importer or live snapshot.
    pub fn from_bytes(mode: u32, data: Vec<u8>, opts: &ChangeOptions) -> io::Result<Self> {
        struct Memory(Arc<[u8]>);
        impl MountSource for Memory {
            fn is_immutable(&self) -> bool {
                true
            }
            fn list(&self, _: &str) -> Option<ListResult> {
                None
            }
            fn lookup(&self, _: &str, _: i32) -> Option<FileInfo> {
                None
            }
            fn open(&self, _: &FileInfo, _: i32) -> io::Result<Box<dyn ArchiveRead>> {
                Ok(Box::new(io::Cursor::new(self.0.clone())))
            }
        }
        let target = (mode & S_IFMT == S_IFLNK).then(|| data.clone());
        let hash = if mode & S_IFMT == S_IFDIR {
            None
        } else {
            Some(content_hash(
                &mut data.as_slice(),
                if target.is_some() {
                    Normalize::Exact
                } else {
                    opts.normalize
                },
                opts.algo,
            )?)
        };
        let mut info = ratarmount_core::create_root_file_info();
        info.mode = mode;
        info.size = data.len() as u64;
        Ok(Self {
            mode,
            size: info.size,
            hash,
            target,
            source: Arc::new(Memory(data.into())),
            info,
        })
    }
    pub fn kind(&self) -> &'static str {
        match self.mode & S_IFMT {
            S_IFDIR => "dir",
            S_IFLNK => "symlink",
            _ => "file",
        }
    }
    pub fn git_mode(&self) -> u32 {
        if self.mode & S_IFMT == S_IFLNK {
            0o120000
        } else if self.mode & 0o100 != 0 {
            0o100755
        } else {
            0o100644
        }
    }
    /// Open exact bytes, regardless of the normalization used for `hash`.
    pub fn open(&self) -> io::Result<Box<dyn ArchiveRead>> {
        if let Some(target) = &self.target {
            return Ok(Box::new(io::Cursor::new(target.clone())));
        }
        if self.mode & S_IFMT == S_IFDIR {
            return Ok(Box::new(io::Cursor::new(Vec::<u8>::new())));
        }
        self.source.open(&self.info, 0)
    }
    /// Intended for bounded text hunks. Large/binary rendering should use open.
    pub fn read_bytes(&self) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        self.open()?
            .take(self.size.saturating_add(1))
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 != self.size {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "content size changed during diff",
            ));
        }
        Ok(bytes)
    }
}
impl std::fmt::Debug for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entry")
            .field("mode", &self.mode)
            .field("size", &self.size)
            .field("hash", &self.hash)
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
pub struct Change {
    pub path: Vec<u8>,
    pub status: Status,
    pub old: Option<Entry>,
    pub new: Option<Entry>,
    pub base_layer: Option<LayerIndex>,
}

impl Change {
    pub fn kind(&self) -> &'static str {
        self.new
            .as_ref()
            .or(self.old.as_ref())
            .map_or("file", Entry::kind)
    }
    /// Canonical row: path NUL status NUL type NUL mode NUL content-hash NUL.
    /// A deletion has the old type/mode but no new content hash.
    pub fn write_canonical_row(&self, out: &mut dyn Write, opts: &ChangeOptions) -> io::Result<()> {
        let entry = self.new.as_ref().or(self.old.as_ref());
        let mode = if opts.ignore_mode {
            String::new()
        } else {
            entry.map_or_else(String::new, |e| format!("{:06o}", e.mode))
        };
        for field in [
            self.path.as_slice(),
            self.status.as_str().as_bytes(),
            self.kind().as_bytes(),
            mode.as_bytes(),
            self.new
                .as_ref()
                .and_then(|e| e.hash.as_deref())
                .unwrap_or("")
                .as_bytes(),
        ] {
            out.write_all(field)?;
            out.write_all(b"\0")?;
        }
        Ok(())
    }
    pub fn row_hash(&self, opts: &ChangeOptions) -> io::Result<String> {
        let mut hash = ContentDigest::new(opts.algo);
        self.write_canonical_row(&mut hash, opts)?;
        Ok(hash.finish())
    }
    pub fn manifest_row(&self) -> Value {
        let mut row = Map::new();
        json_bytes(&mut row, "path", &self.path);
        row.insert("status".into(), self.status.as_str().into());
        row.insert("type".into(), self.kind().into());
        if let Some(new) = &self.new {
            row.insert("layer".into(), "top".into());
            row.insert("mode".into(), format!("{:06o}", new.mode).into());
            if new.hash.is_some() || new.kind() == "dir" {
                row.insert("size".into(), new.size.into());
            }
            if let Some(hash) = &new.hash {
                row.insert("hash".into(), hash.clone().into());
            }
            if let Some(target) = &new.target {
                json_bytes(&mut row, "target", target);
            }
        }
        if let Some(hash) = self.old.as_ref().and_then(|e| e.hash.as_ref()) {
            row.insert("base_hash".into(), hash.clone().into());
        }
        if let Some(layer) = self.base_layer {
            row.insert("base_layer".into(), layer.to_string().into());
        }
        Value::Object(row)
    }
}

/// JSON byte-string convention shared by manifest consumers.
pub fn json_bytes(row: &mut Map<String, Value>, key: &str, bytes: &[u8]) {
    match std::str::from_utf8(bytes) {
        Ok(text) => {
            row.insert(key.into(), text.into());
        }
        Err(_) => {
            row.insert(format!("{key}_b64"), STANDARD.encode(bytes).into());
        }
    }
}

/// Hash precomputed rows. Construct `changes` with the same options: content
/// normalization, exclusions and mode-only filtering occur during comparison.
pub fn canonical_hash(changes: &[Change], opts: &ChangeOptions) -> io::Result<String> {
    let mut sorted: Vec<_> = changes.iter().collect();
    sorted.sort_by(|a, b| a.path.cmp(&b.path));
    let mut hash = ContentDigest::new(opts.algo);
    for change in sorted {
        change.write_canonical_row(&mut hash, opts)?;
    }
    Ok(hash.finish())
}

pub fn write_manifest(changes: &[Change], out: &mut dyn Write) -> io::Result<()> {
    let mut sorted: Vec<_> = changes.iter().collect();
    sorted.sort_by(|a, b| a.path.cmp(&b.path));
    for change in sorted {
        serde_json::to_writer(&mut *out, &change.manifest_row())?;
        out.write_all(b"\n")?;
    }
    Ok(())
}

/// Git's binary heuristic; non-UTF-8 text is still text.
pub fn binary(prefix: &[u8]) -> bool {
    prefix[..prefix.len().min(8192)].contains(&0)
}

#[derive(Clone)]
enum ContentDigest {
    Sha256(Sha256),
    Blake3(Box<blake3::Hasher>),
}
impl ContentDigest {
    fn new(algo: Algorithm) -> Self {
        match algo {
            Algorithm::Sha256 => Self::Sha256(Sha256::new()),
            Algorithm::Blake3 => Self::Blake3(Box::new(blake3::Hasher::new())),
        }
    }
    fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Sha256(h) => h.update(bytes),
            Self::Blake3(h) => {
                h.update(bytes);
            }
        }
    }
    fn finish(self) -> String {
        match self {
            Self::Sha256(h) => format!("sha256:{:x}", h.finalize()),
            Self::Blake3(h) => format!("blake3:{}", h.finalize().to_hex()),
        }
    }
}
impl Write for ContentDigest {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// Streams normalized text into one digest. Bytes that may still be dropped
// are deferred instead of hashed: blank lines as a count, and the whitespace
// since the last non-whitespace byte in a bounded buffer. A whitespace run
// longer than the buffer falls back to a digest checkpoint, so memory stays
// bounded and the digest state is only cloned once per overflowing run.
// Kept bytes are staged in `staged` so the digest sees large updates.
struct TextDigest {
    out: ContentDigest,
    staged: Vec<u8>,
    /// Newlines owed before the next non-whitespace byte.
    pending_lines: u64,
    /// Whitespace on the current line since its last non-whitespace byte.
    blanks: Vec<u8>,
    /// `out` before this line's deferred newlines and whitespace, once
    /// `blanks` overflowed and they were hashed speculatively.
    checkpoint: Option<ContentDigest>,
    nonblank: bool,
    loose: bool,
    cap: usize,
}
impl TextDigest {
    const BLANK_CAP: usize = 64 * 1024;
    const STAGE: usize = 64 * 1024;
    fn new(algo: Algorithm, loose: bool) -> Self {
        Self::with_cap(algo, loose, Self::BLANK_CAP)
    }
    fn with_cap(algo: Algorithm, loose: bool, cap: usize) -> Self {
        Self {
            out: ContentDigest::new(algo),
            staged: Vec::with_capacity(Self::STAGE),
            pending_lines: 0,
            blanks: Vec::new(),
            checkpoint: None,
            nonblank: false,
            loose,
            cap,
        }
    }
    fn emit(&mut self, bytes: &[u8]) {
        if self.staged.len() + bytes.len() > Self::STAGE {
            self.out.update(&self.staged);
            self.staged.clear();
            if bytes.len() > Self::STAGE {
                self.out.update(bytes);
                return;
            }
        }
        self.staged.extend_from_slice(bytes);
    }
    fn commit(&mut self) {
        self.out.update(&self.staged);
        self.staged.clear();
    }
    fn newlines(&mut self, mut count: u64) {
        let block = [b'\n'; 4096];
        while count != 0 {
            let n = count.min(block.len() as u64) as usize;
            self.emit(&block[..n]);
            count -= n as u64;
        }
    }
    /// Hash the deferred newlines (unless already hashed) and whitespace.
    fn flush_deferred(&mut self) {
        if !self.nonblank {
            self.newlines(self.pending_lines);
            self.pending_lines = 0;
        }
        let blanks = std::mem::take(&mut self.blanks);
        self.emit(&blanks);
        self.blanks = blanks;
        self.blanks.clear();
    }
    fn whitespace(&mut self, run: &[u8]) {
        if self.checkpoint.is_some() {
            self.emit(run);
        } else if self.blanks.len() + run.len() <= self.cap {
            self.blanks.extend_from_slice(run);
        } else {
            self.commit();
            self.checkpoint = Some(self.out.clone());
            let pending = self.pending_lines;
            self.flush_deferred();
            // Restored on rollback together with `out`.
            self.pending_lines = pending;
            self.emit(run);
        }
    }
    fn content(&mut self, run: &[u8]) {
        if self.checkpoint.take().is_some() {
            // Everything deferred is already in `out` and is now committed.
            if !self.nonblank {
                self.pending_lines = 0;
            }
        } else {
            self.flush_deferred();
        }
        self.nonblank = true;
        self.emit(run);
    }
    /// Drop this line's trailing whitespace (and, for a blank line, its
    /// speculatively hashed newlines).
    fn rollback(&mut self) {
        if let Some(checkpoint) = self.checkpoint.take() {
            self.staged.clear();
            self.out = checkpoint;
        }
        self.blanks.clear();
    }
    fn update(&mut self, bytes: &[u8]) {
        for part in bytes.split_inclusive(|b| *b == b'\n') {
            let newline = part.last() == Some(&b'\n');
            let text = if newline {
                &part[..part.len() - 1]
            } else {
                part
            };
            // Everything up to the last non-whitespace byte is kept, interior
            // whitespace included; hash it in one update.
            let kept = text
                .iter()
                .rposition(|b| !b.is_ascii_whitespace())
                .map_or(0, |i| i + 1);
            if kept != 0 {
                self.content(&text[..kept]);
            }
            if kept != text.len() {
                self.whitespace(&text[kept..]);
            }
            if newline {
                self.rollback();
                if self.nonblank {
                    self.pending_lines = 1;
                } else if !self.loose {
                    self.pending_lines += 1;
                }
                self.nonblank = false;
            }
        }
    }
    fn finish(mut self) -> String {
        self.rollback();
        if !self.nonblank && !self.loose {
            self.newlines(self.pending_lines.saturating_sub(1));
        }
        self.commit();
        self.out.finish()
    }
}

/// Stream a normalized content hash using bounded memory, including for lines
/// larger than the read buffer. Symlink targets must use Exact.
pub fn content_hash(
    reader: &mut dyn Read,
    normalize: Normalize,
    algo: Algorithm,
) -> io::Result<String> {
    let mut prefix = Vec::with_capacity(8192);
    reader.take(8192).read_to_end(&mut prefix)?;
    let exact = normalize == Normalize::Exact || binary(&prefix);
    let mut raw = ContentDigest::new(algo);
    let mut text = TextDigest::new(algo, normalize == Normalize::Loose);
    let mut update = |bytes: &[u8]| {
        if exact {
            raw.update(bytes);
        } else {
            text.update(bytes);
        }
    };
    update(&prefix);
    let mut block = [0u8; 64 * 1024];
    loop {
        let n = match reader.read(&mut block) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if n == 0 {
            break;
        }
        update(&block[..n]);
    }
    Ok(if exact { raw.finish() } else { text.finish() })
}

/// Gitignore-style exclusion patterns. Unlike the policy matcher these support
/// bracket classes, directory-only matches and unanchored component patterns.
pub struct Excludes {
    patterns: Vec<(Regex, bool)>,
    include_git: bool,
}
impl Excludes {
    pub fn new(opts: &ChangeOptions) -> io::Result<Self> {
        let mut patterns = Vec::new();
        for glob in &opts.excludes {
            let dir = glob.ends_with('/');
            let anchored = glob.starts_with('/');
            let glob = glob.trim_start_matches('/').trim_end_matches('/');
            if glob.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "empty exclude glob",
                ));
            }
            let mut re = if anchored || glob.contains('/') {
                "^".to_owned()
            } else {
                "(?:^|/)".to_owned()
            };
            let chars: Vec<_> = glob.chars().collect();
            let mut i = 0;
            while i < chars.len() {
                match chars[i] {
                    '*' if chars.get(i + 1) == Some(&'*') => {
                        while chars.get(i + 1) == Some(&'*') {
                            i += 1;
                        }
                        if chars.get(i + 1) == Some(&'/') {
                            re.push_str("(?:.*/)?");
                            i += 1;
                        } else {
                            re.push_str(".*");
                        }
                    }
                    '*' => re.push_str("[^/]*"),
                    '?' => re.push_str("[^/]"),
                    '[' => {
                        let start = i;
                        i += 1;
                        let mut class = String::from("[");
                        if matches!(chars.get(i), Some('!' | '^')) {
                            class.push('^');
                            i += 1;
                        }
                        while i < chars.len() && chars[i] != ']' {
                            if chars[i] == '\\' {
                                class.push('\\');
                            }
                            class.push(chars[i]);
                            i += 1;
                        }
                        if i == chars.len() {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidInput,
                                format!("invalid exclude class in {glob:?} at {start}"),
                            ));
                        }
                        class.push(']');
                        re.push_str(&class);
                    }
                    '\\' if i + 1 < chars.len() => {
                        i += 1;
                        re.push_str(&regex::escape(&chars[i].to_string()));
                    }
                    c => re.push_str(&regex::escape(&c.to_string())),
                }
                i += 1;
            }
            re.push('$');
            patterns.push((
                Regex::new(&re).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?,
                dir,
            ));
        }
        Ok(Self {
            patterns,
            include_git: opts.include_git_dir,
        })
    }
    pub fn matches(&self, path: &str, is_dir: bool) -> bool {
        if internal_path(path) || (!self.include_git && path.split('/').any(|p| p == ".git")) {
            return true;
        }
        let path = path.trim_start_matches('/');
        let mut end = path.len();
        loop {
            if self.patterns.iter().any(|(re, dir)| {
                (!dir || is_dir || end < path.len()) && re.is_match(&path.as_bytes()[..end])
            }) {
                return true;
            }
            match path[..end].rfind('/') {
                Some(i) => end = i,
                None => return false,
            }
        }
    }
}

fn corrupt(row: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("corrupt overlay row: invalid overlay path {row:?}"),
    )
}

/// Validate a mount-relative path without silently normalizing traversal away.
pub fn validate_relative_path(path: &str) -> io::Result<()> {
    if path.is_empty()
        || path.starts_with('/')
        || path.contains('\0')
        || path
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == "..")
    {
        return Err(corrupt(path));
    }
    Ok(())
}

// Shared by diff, fsck and seal. Internal directories are pruned before opening
// them; every other entry is lstat'ed and directory opens refuse symlinks.
pub(crate) fn internal_path(path: &str) -> bool {
    is_overlay_internal_path(path)
        || path
            .split('/')
            .any(|part| part.to_ascii_lowercase().starts_with(".ratarmount-spool-"))
}

#[cfg(unix)]
fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

#[cfg(unix)]
pub(crate) fn walk_host_entries(
    fd: &OwnedFd,
    parent: &str,
    hosts: &mut BTreeMap<String, Stat>,
) -> io::Result<()> {
    for entry in Dir::read_from(fd)? {
        let entry = entry?;
        let name = entry.file_name().to_str().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "overlay contains a non-UTF-8 name",
            )
        })?;
        if name == "." || name == ".." {
            continue;
        }
        let path = if parent.is_empty() {
            name.to_owned()
        } else {
            format!("{parent}/{name}")
        };
        if internal_path(&path) {
            continue;
        }
        let stat = host::statat(fd, name, AtFlags::SYMLINK_NOFOLLOW)?;
        if stat.st_mode & libc::S_IFMT == libc::S_IFDIR {
            let child = host::openat(fd, name, directory_flags(), Mode::empty())?;
            walk_host_entries(&child, &path, hosts)?;
        }
        hosts.insert(path, stat);
    }
    Ok(())
}

#[cfg(not(unix))]
fn walk_host_paths(top: &Path, parent: &str, paths: &mut BTreeSet<String>) -> io::Result<()> {
    for entry in std::fs::read_dir(top)? {
        let entry = entry?;
        let name = entry.file_name().into_string().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "overlay contains a non-UTF-8 name",
            )
        })?;
        let path = if parent.is_empty() {
            name
        } else {
            format!("{parent}/{name}")
        };
        if internal_path(&path) {
            continue;
        }
        if std::fs::symlink_metadata(entry.path())?.is_dir() {
            walk_host_paths(&entry.path(), &path, paths)?;
        }
        paths.insert(path);
    }
    Ok(())
}

/// Enumerate host entries, files rows and metadata-only mentions. COW files
/// need no row: host entries are authoritative for presence. The database stores
/// absolute *mount* parent directories ("", "/", "/lib"), not host paths;
/// names must be one relative component. Do not trim arbitrary leading slashes.
pub fn mentioned_paths(top: &Path) -> io::Result<BTreeSet<String>> {
    mentioned_paths_with_immutability(top, Immutability::Shared)
}

pub(crate) fn mentioned_paths_with_immutability(
    top: &Path,
    immutability: Immutability,
) -> io::Result<BTreeSet<String>> {
    let db = top.join(HIDDEN_DB);
    if !std::fs::symlink_metadata(&db)?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "overlay database must be a regular file",
        ));
    }
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = match immutability {
        Immutability::Shared => Connection::open_with_flags(&db, flags),
        Immutability::Immutable => Connection::open_with_flags(
            crate::overlay_layer::immutable_uri(&db.canonicalize()?),
            flags | OpenFlags::SQLITE_OPEN_URI,
        ),
    }
    .map_err(io::Error::other)?;
    conn.busy_timeout(std::time::Duration::ZERO)
        .map_err(io::Error::other)?;
    let mut stmt = conn
        .prepare("SELECT path,name FROM files")
        .map_err(io::Error::other)?;
    let rows = stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
        .map_err(io::Error::other)?;
    let mut paths = BTreeSet::new();
    for row in rows {
        let (parent, name) = row.map_err(io::Error::other)?;
        let original = format!("({parent:?}, {name:?})");
        // WriteOverlay stores root chmod/utime as ("", ""). This is the
        // mount root, not a relative-path traversal or a missing child name.
        if parent.is_empty() && name.is_empty() {
            paths.insert(String::new());
            continue;
        }
        if name.contains('/') {
            return Err(corrupt(&original));
        }
        validate_relative_path(&name).map_err(|_| corrupt(&original))?;
        let parent = parent.strip_prefix('/').unwrap_or(&parent);
        if !parent.is_empty() {
            validate_relative_path(parent).map_err(|_| corrupt(&original))?;
        }
        paths.insert(if parent.is_empty() {
            name
        } else {
            format!("{parent}/{name}")
        });
    }
    let metadata: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='overlay_metadata' AND type='table')", [], |r| r.get(0)).map_err(io::Error::other)?;
    if metadata {
        let mut stmt = conn
            .prepare("SELECT path FROM overlay_metadata")
            .map_err(io::Error::other)?;
        for row in stmt
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(io::Error::other)?
        {
            let row = row.map_err(io::Error::other)?;
            if row == "/" {
                continue;
            }
            let path = row.strip_prefix('/').unwrap_or(&row);
            validate_relative_path(path).map_err(|_| corrupt(&row))?;
            paths.insert(path.to_owned());
        }
    }
    #[cfg(unix)]
    {
        let root = host::open(top, directory_flags(), Mode::empty())?;
        let mut hosts = BTreeMap::new();
        walk_host_entries(&root, "", &mut hosts)?;
        paths.extend(hosts.into_keys());
    }
    #[cfg(not(unix))]
    walk_host_paths(top, "", &mut paths)?;
    paths.retain(|path| !internal_path(path));
    Ok(paths)
}

/// Empty lower view for base-less inspection. Prefer change_set_without_base,
/// which reports `written` rather than guessing added versus modified.
pub struct EmptySource;
impl MountSource for EmptySource {
    fn is_immutable(&self) -> bool {
        true
    }
    fn list(&self, _: &str) -> Option<ListResult> {
        None
    }
    fn lookup(&self, _: &str, _: i32) -> Option<FileInfo> {
        None
    }
    fn open(&self, _: &FileInfo, _: i32) -> io::Result<Box<dyn ArchiveRead>> {
        Err(io::ErrorKind::NotFound.into())
    }
}

pub fn change_set(
    top_dir: &Path,
    lower_view: Arc<dyn MountSource>,
    opts: &ChangeOptions,
) -> io::Result<Vec<Change>> {
    let paths = mentioned_paths(top_dir)?;
    let top = Arc::new(ReadOnlyOverlayLayer::new(
        lower_view.clone(),
        top_dir,
        Immutability::Shared,
    )?);
    compare_paths(paths, top, Some(lower_view), opts)
}

pub fn change_set_without_base(top_dir: &Path, opts: &ChangeOptions) -> io::Result<Vec<Change>> {
    let paths = mentioned_paths(top_dir)?;
    let top = Arc::new(ReadOnlyOverlayLayer::new(
        Arc::new(EmptySource),
        top_dir,
        Immutability::Shared,
    )?);
    // Resolve metadata-only mentions before enforcing a row limit: some are
    // time-only, ignored mode changes, or excluded directory entries.
    let mut comparison = opts.clone();
    comparison.max_files = None;
    let mut changes = compare_paths(paths, top, None, &comparison)?;
    // Without the base, a metadata-only chmod has no resolvable payload. It is
    // still a write, never a deletion; expose its known mode without inventing
    // an empty content hash or a size. Time-only mentions are not diff changes.
    if changes.iter().any(|c| c.new.is_none() && c.old.is_none()) {
        let conn =
            Connection::open_with_flags(top_dir.join(HIDDEN_DB), OpenFlags::SQLITE_OPEN_READ_ONLY)
                .map_err(io::Error::other)?;
        let has_metadata: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='overlay_metadata' AND type='table')", [], |r| r.get(0)).map_err(io::Error::other)?;
        let mut stmt = conn
            .prepare("SELECT path,name,mode,deleted FROM files")
            .map_err(io::Error::other)?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<u32>>(2)?,
                    r.get::<_, Option<i64>>(3)?,
                ))
            })
            .map_err(io::Error::other)?;
        let mut omit = BTreeSet::new();
        for row in rows {
            let (parent, name, mode, deleted) = row.map_err(io::Error::other)?;
            let parent = parent.strip_prefix('/').unwrap_or(&parent);
            let path = if parent.is_empty() {
                name
            } else {
                format!("{parent}/{name}")
            };
            let Ok(index) = changes.binary_search_by(|c| c.path.as_slice().cmp(path.as_bytes()))
            else {
                continue;
            };
            let change = &mut changes[index];
            if change.new.is_some() || change.old.is_some() {
                continue;
            }
            if deleted == Some(1) {
                continue;
            }
            let metadata_mode = if has_metadata {
                use rusqlite::OptionalExtension;
                conn.query_row(
                    "SELECT mode FROM overlay_metadata WHERE path=?1",
                    [format!("/{path}")],
                    |r| r.get::<_, Option<u32>>(0),
                )
                .optional()
                .map_err(io::Error::other)?
            } else {
                None
            };
            let Some(metadata_mode) = metadata_mode else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{path}: overlay row has no backing entry or metadata override"),
                ));
            };
            if opts.ignore_mode || metadata_mode.is_none() {
                omit.insert(path.into_bytes());
                continue;
            }
            let mut info = ratarmount_core::create_root_file_info();
            info.mode = mode.unwrap_or(S_IFREG) & !0o7777 | metadata_mode.unwrap() & 0o7777;
            change.status = Status::Written;
            change.new = Some(Entry {
                mode: info.mode,
                size: 0,
                hash: None,
                target: None,
                source: Arc::new(EmptySource),
                info,
            });
        }
        changes.retain(|c| !omit.contains(&c.path));
    }
    let excludes = Excludes::new(opts)?;
    changes.retain(|c| {
        !excludes.matches(
            std::str::from_utf8(&c.path).expect("validated overlay path"),
            c.kind() == "dir",
        )
    });
    if opts.max_files.is_some_and(|max| changes.len() > max) {
        return Err(limit_error("change set exceeds --max-files"));
    }
    Ok(changes)
}

/// Compare the union of two overlays' mentions, resolving both against the same
/// stack. Stack identity is a caller responsibility (metadata/CLI policy).
pub fn between(
    top_dir: &Path,
    other_dir: &Path,
    stack: Arc<dyn MountSource>,
    opts: &ChangeOptions,
) -> io::Result<Vec<Change>> {
    let mut paths = mentioned_paths(top_dir)?;
    paths.extend(mentioned_paths(other_dir)?);
    let top = Arc::new(ReadOnlyOverlayLayer::new(
        stack.clone(),
        top_dir,
        Immutability::Shared,
    )?);
    let other = Arc::new(ReadOnlyOverlayLayer::new(
        stack,
        other_dir,
        Immutability::Shared,
    )?);
    compare_paths(paths, top, Some(other), opts)
}

// A MountSource lookup can accept paths below symlinks; diff treats links as
// data and checks every ancestor before asking for the leaf.
fn safe_lookup(source: &dyn MountSource, path: &str) -> Option<FileInfo> {
    for (i, _) in path.match_indices('/') {
        if i > 0 && source.lookup(&format!("/{}", &path[..i]), 0)?.mode & S_IFMT != S_IFDIR {
            return None;
        }
    }
    source.lookup(&format!("/{path}"), 0)
}

fn add_children(
    source: &dyn MountSource,
    path: &str,
    paths: &mut BTreeSet<String>,
    excludes: &Excludes,
) -> io::Result<()> {
    for child in source.list_dirents(&format!("/{path}")).unwrap_or_default() {
        validate_relative_path(&child.name)?;
        if child.name.contains('/') {
            return Err(corrupt(&child.name));
        }
        let full = format!("{path}/{}", child.name);
        if !excludes.matches(&full, child.mode & S_IFMT == S_IFDIR) {
            paths.insert(full);
        }
    }
    Ok(())
}

/// Compare an explicit set of relative paths. Also expands removed/replaced
/// directories so patches contain their removed descendants. Exclusion happens
/// before any content open on either source. Suitable for live snapshot callers.
pub fn compare_paths(
    mut paths: BTreeSet<String>,
    top: Arc<dyn MountSource>,
    lower: Option<Arc<dyn MountSource>>,
    opts: &ChangeOptions,
) -> io::Result<Vec<Change>> {
    let excludes = Excludes::new(opts)?;
    let mut candidates = Vec::new();
    while let Some(path) = paths.pop_first() {
        if !path.is_empty() {
            validate_relative_path(&path)?;
        }
        if excludes.matches(&path, false) {
            continue;
        }
        let old = lower.as_ref().and_then(|s| safe_lookup(s.as_ref(), &path));
        let new = safe_lookup(top.as_ref(), &path);
        let is_dir =
            |fi: &Option<FileInfo>| fi.as_ref().is_some_and(|f| f.mode & S_IFMT == S_IFDIR);
        if excludes.matches(&path, is_dir(&new) || is_dir(&old)) {
            continue;
        }
        if !path.is_empty() && is_dir(&old) && !is_dir(&new) {
            add_children(
                lower.as_ref().unwrap().as_ref(),
                &path,
                &mut paths,
                &excludes,
            )?;
        }
        if !path.is_empty() && is_dir(&new) && !is_dir(&old) {
            add_children(top.as_ref(), &path, &mut paths, &excludes)?;
        }
        if old.is_none() && new.is_none() && lower.is_some() {
            continue;
        }
        for fi in [&old, &new].into_iter().flatten() {
            if fi.mode & S_IFMT == S_IFREG
                && opts.max_content_bytes.is_some_and(|max| fi.size > max)
            {
                return Err(limit_error(format!(
                    "{path}: payload exceeds --max-patch-bytes input-work budget"
                )));
            }
        }
        candidates.push((path, old, new));
    }
    let mut changes = Vec::new();
    for (path, old, new) in candidates {
        let before = old
            .map(|fi| entry(lower.as_ref().unwrap().clone(), fi, opts, true))
            .transpose()?;
        let after = new
            .map(|fi| entry(top.clone(), fi, opts, false))
            .transpose()?;
        let status = match (&before, &after) {
            (None, Some(_)) if lower.is_none() => Status::Written,
            (None, Some(_)) => Status::Added,
            (Some(_), None) | (None, None) => Status::Deleted,
            (Some(a), Some(b)) if a.kind() != b.kind() => Status::TypeChanged,
            (Some(a), Some(b)) if a.hash == b.hash && (opts.ignore_mode || a.mode == b.mode) => {
                continue
            }
            _ => Status::Modified,
        };
        if opts.max_files.is_some_and(|max| changes.len() >= max) {
            return Err(limit_error("change set exceeds --max-files"));
        }
        let base_layer = lower
            .as_ref()
            .and_then(|s| serving_layer(s.as_ref(), &format!("/{path}")));
        changes.push(Change {
            path: path.into_bytes(),
            status,
            old: before,
            new: after,
            base_layer,
        });
    }
    changes.sort_by(|a, b| a.path.cmp(&b.path));
    changes.dedup_by(|a, b| a.path == b.path);
    Ok(changes)
}

fn entry(
    source: Arc<dyn MountSource>,
    fi: FileInfo,
    opts: &ChangeOptions,
    lower: bool,
) -> io::Result<Entry> {
    let kind = fi.mode & S_IFMT;
    if !matches!(kind, S_IFREG | S_IFLNK | S_IFDIR) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "only regular files, directories and symlinks can be diffed",
        ));
    }
    let target = (kind == S_IFLNK).then(|| fi.linkname.as_bytes().to_vec());
    let mut result = Entry {
        mode: fi.mode,
        size: if kind == S_IFDIR {
            0
        } else if let Some(t) = &target {
            t.len() as u64
        } else {
            fi.size
        },
        hash: None,
        target,
        source,
        info: fi,
    };
    if kind == S_IFDIR {
        return Ok(result);
    }
    // A materialized lower overlay may inherit an index hash xattr from the
    // base even though its host payload changed. Only trust such inherited
    // hashes when no layer has replaced the payload.
    let replaced_payload = result.info.userdata.iter().any(|data| {
        matches!(data, ratarmount_core::UserData::Other(tag)
            if tag.strip_prefix("overlay-layer:").and_then(|s| s.split_once(':')).is_some_and(|(_, rest)| rest.starts_with("host:")))
    });
    if lower
        && !replaced_payload
        && kind == S_IFREG
        && opts.normalize == Normalize::Exact
        && opts.algo == Algorithm::Sha256
    {
        if let Some(value) = result.source.get_xattr(&result.info, "user.hash.sha256") {
            if let Ok(value) = std::str::from_utf8(&value) {
                let hex = value.strip_prefix("sha256:").unwrap_or(value);
                if hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                    result.hash = Some(format!("sha256:{}", hex.to_ascii_lowercase()));
                }
            }
        }
    }
    if result.hash.is_none() {
        #[cfg(test)]
        if !lower {
            TOP_OPENS.set(TOP_OPENS.get() + 1);
        }
        let mut reader = result.open()?.take(result.size.saturating_add(1));
        let hash = content_hash(
            &mut reader,
            if kind == S_IFLNK {
                Normalize::Exact
            } else {
                opts.normalize
            },
            opts.algo,
        )?;
        if reader.limit() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "content size changed during hashing",
            ));
        }
        result.hash = Some(hash);
    }
    Ok(result)
}

#[cfg(test)]
thread_local! { static TOP_OPENS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }

/// Use the same copy-up and truncating open as FUSE's open_inode.
#[cfg(test)]
pub(crate) fn cow_write(overlay: &crate::WriteOverlay, path: &str, bytes: &[u8]) {
    use std::os::fd::FromRawFd;
    assert!(
        overlay.lookup(path, 0).is_some(),
        "COW needs an existing {path}"
    );
    let fd = overlay
        .open_overlay_fd(path, libc::O_WRONLY | libc::O_TRUNC)
        .unwrap();
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    file.write_all(bytes).unwrap();
    overlay.finish_owned_write_fd(file);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FolderMountSource, OverlayMetadata, WriteOverlay};
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn fixture() -> (tempfile::TempDir, Arc<dyn MountSource>) {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir(tmp.path().join("base")).unwrap();
        fs::write(tmp.path().join("base/a"), b"old\n").unwrap();
        let base = Arc::new(FolderMountSource::new(tmp.path().join("base")).unwrap());
        (tmp, base)
    }
    fn put(overlay: &WriteOverlay, path: &str, data: &[u8]) {
        use std::os::fd::FromRawFd;
        let fd = overlay.create_file(path, 0o644).unwrap();
        let mut file = unsafe { fs::File::from_raw_fd(fd) };
        file.write_all(data).unwrap();
        overlay.finish_owned_write_fd(file);
    }
    fn edits(
        tmp: &Path,
        name: &str,
        base: Arc<dyn MountSource>,
        content: &[u8],
        opts: &ChangeOptions,
    ) -> Vec<Change> {
        let dir = tmp.join(name);
        let ov = WriteOverlay::new(base.clone(), &dir).unwrap();
        cow_write(&ov, "/a", content);
        drop(ov);
        change_set(&dir, base, opts).unwrap()
    }
    fn hash(mut data: &[u8], normalize: Normalize) -> String {
        content_hash(&mut data, normalize, Algorithm::Sha256).unwrap()
    }

    /// Regression: COW open and setattr truncate publish host content without files rows.
    #[test]
    fn regression_cow_open_and_truncate_leave_no_files_rows() {
        let (tmp, base) = fixture();
        for operation in ["open", "truncate"] {
            let dir = tmp.path().join(operation);
            let ov = WriteOverlay::new(base.clone(), &dir).unwrap();
            if operation == "open" {
                cow_write(&ov, "/a", b"changed\n");
            } else {
                ov.set_attributes("/a", Some(2), &OverlayMetadata::default())
                    .unwrap();
            }
            drop(ov);
            assert_eq!(
                fs::read(dir.join("a")).unwrap(),
                if operation == "open" {
                    b"changed\n".as_slice()
                } else {
                    b"ol"
                }
            );
            let conn = Connection::open(dir.join(HIDDEN_DB)).unwrap();
            assert_eq!(
                conn.query_row("SELECT count(*) FROM files", [], |r| r.get::<_, i64>(0))
                    .unwrap(),
                0
            );
        }
    }

    /// Regression: host-only COW edits disappeared from diff, manifest and canonical hash.
    #[test]
    fn regression_cow_changes_match_rowed_edits() {
        let (tmp, base) = fixture();
        let opts = ChangeOptions::default();
        let dir = tmp.path().join("cow");
        let ov = WriteOverlay::new(base.clone(), &dir).unwrap();
        cow_write(&ov, "/a", b"new\n");
        drop(ov);
        let changes = change_set(&dir, base.clone(), &opts).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].status, Status::Modified);
        assert_eq!(
            changes[0].manifest_row()["base_hash"],
            hash(b"old\n", Normalize::Exact)
        );
        let digest = canonical_hash(&changes, &opts).unwrap();
        assert_ne!(digest, EMPTY_SHA256);
        let rowed_dir = tmp.path().join("rowed");
        let ov = WriteOverlay::new(base.clone(), &rowed_dir).unwrap();
        put(&ov, "/a", b"new\n");
        drop(ov);
        let rowed = change_set(&rowed_dir, base, &opts).unwrap();
        assert_eq!(digest, canonical_hash(&rowed, &opts).unwrap());
    }

    /// Regression: between and base-less diff ignored host-only edits on either side.
    #[test]
    fn regression_cow_between_and_without_base() {
        let (tmp, base) = fixture();
        fs::write(tmp.path().join("base/b"), b"old b").unwrap();
        let a = tmp.path().join("one");
        let b = tmp.path().join("two");
        for (dir, path) in [(&a, "/a"), (&b, "/b")] {
            let ov = WriteOverlay::new(base.clone(), dir).unwrap();
            cow_write(&ov, path, b"changed");
            drop(ov);
        }
        let opts = ChangeOptions::default();
        let changes = between(&b, &a, base.clone(), &opts).unwrap();
        assert_eq!(
            changes
                .iter()
                .map(|c| c.path.as_slice())
                .collect::<Vec<_>>(),
            [b"a", b"b"]
        );
        assert!(changes.iter().all(|c| c.status == Status::Modified));
        assert_eq!(
            changes[0].old.as_ref().unwrap().read_bytes().unwrap(),
            b"changed"
        );
        assert_eq!(
            changes[0].new.as_ref().unwrap().read_bytes().unwrap(),
            b"old\n"
        );
        assert!(between(&a, &a, base, &opts).unwrap().is_empty());
        let changes = change_set_without_base(&b, &opts).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].path, b"b");
        assert_eq!(changes[0].status, Status::Written);
    }

    /// Regression: implicit COW parents were added directories; reverted edits must disappear.
    #[test]
    fn regression_cow_implicit_parents_and_reverted_content() {
        use std::os::unix::fs::PermissionsExt;
        let (tmp, base) = fixture();
        let parent = tmp.path().join("base/lib");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(parent.join("f"), b"base").unwrap();
        let dir = tmp.path().join("overlay");
        let ov = WriteOverlay::new(base.clone(), &dir).unwrap();
        cow_write(&ov, "/lib/f", b"changed");
        drop(ov);
        fs::set_permissions(dir.join("lib"), fs::Permissions::from_mode(0o755)).unwrap();
        let opts = ChangeOptions::default();
        let changes = change_set(&dir, base.clone(), &opts).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].path, b"lib/f");
        let ov = WriteOverlay::new(base.clone(), &dir).unwrap();
        cow_write(&ov, "/lib/f", b"base");
        drop(ov);
        assert!(change_set(&dir, base.clone(), &opts).unwrap().is_empty());
        // Host-only directories still have meaning if absent below, or if their mode changes.
        fs::create_dir(dir.join("empty")).unwrap();
        fs::set_permissions(dir.join("lib"), fs::Permissions::from_mode(0o700)).unwrap();
        let changes = change_set(&dir, base, &opts).unwrap();
        assert_eq!(changes.len(), 2);
        assert_eq!(
            (
                changes[0].path.as_slice(),
                changes[0].status,
                changes[0].kind()
            ),
            (b"empty".as_slice(), Status::Added, "dir")
        );
        assert_eq!(
            (changes[1].path.as_slice(), changes[1].status),
            (b"lib".as_slice(), Status::Modified)
        );
    }

    /// Regression: host walking followed symlinks or exposed staging and bookkeeping entries.
    #[test]
    fn regression_cow_host_walk_skips_internal_entries_and_symlink_targets() {
        let (tmp, base) = fixture();
        let dir = tmp.path().join("overlay");
        let ov = WriteOverlay::new(base.clone(), &dir).unwrap();
        cow_write(&ov, "/a", b"changed");
        drop(ov);
        let outside = tmp.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("secret"), b"do not read").unwrap();
        std::os::unix::fs::symlink(&outside, dir.join("link")).unwrap();
        fs::create_dir(dir.join("sub")).unwrap();
        for parent in [dir.clone(), dir.join("sub")] {
            for name in [
                ".ratarmount.overlay.cow-partial",
                ".ratarmount-spool-partial",
                ".ratarmount-sealed",
                crate::OVERLAY_MARKER,
            ] {
                if parent.join(name).is_file() {
                    fs::remove_file(parent.join(name)).unwrap();
                }
                fs::create_dir(parent.join(name)).unwrap();
                fs::write(parent.join(name).join("hidden"), b"internal").unwrap();
            }
        }
        let paths = mentioned_paths(&dir).unwrap();
        assert_eq!(
            paths,
            BTreeSet::from(["a".into(), "link".into(), "sub".into()])
        );
        let changes = change_set(&dir, base, &ChangeOptions::default()).unwrap();
        assert_eq!(changes.len(), 3);
        assert_eq!(changes[1].kind(), "symlink");
        assert_eq!(
            changes[1].new.as_ref().unwrap().target.as_deref(),
            Some(outside.to_str().unwrap().as_bytes())
        );
    }

    /// Regression: the same edit through independent overlays has one canonical hash.
    #[test]
    fn regression_hash_same_edit_two_overlays() {
        let (tmp, base) = fixture();
        let opts = ChangeOptions::default();
        let a = edits(tmp.path(), "one", base.clone(), b"new\n", &opts);
        let b = edits(tmp.path(), "two", base, b"new\n", &opts);
        assert_eq!(
            canonical_hash(&a, &opts).unwrap(),
            canonical_hash(&b, &opts).unwrap()
        );
        assert_eq!(a[0].row_hash(&opts).unwrap(), b[0].row_hash(&opts).unwrap());
    }
    /// Regression: unrelated stack contents alter the stack ID, not the edit hash.
    #[test]
    fn regression_hash_unrelated_stack_files() {
        let (tmp, base) = fixture();
        let opts = ChangeOptions::default();
        let before = crate::overlay_meta::directory_digest(&tmp.path().join("base")).unwrap();
        let a = edits(tmp.path(), "one", base.clone(), b"new\n", &opts);
        fs::write(tmp.path().join("base/unrelated"), b"unrelated").unwrap();
        let after = crate::overlay_meta::directory_digest(&tmp.path().join("base")).unwrap();
        let b = edits(tmp.path(), "two", base, b"new\n", &opts);
        assert_eq!(
            canonical_hash(&a, &opts).unwrap(),
            canonical_hash(&b, &opts).unwrap()
        );
        assert_ne!(
            crate::stack_digest(&before, &[]),
            crate::stack_digest(&after, &[])
        );
    }
    /// Regression: CRLF, trailing whitespace and final newline normalize without losing Latin-1.
    #[test]
    fn regression_hash_strict_whitespace_property() {
        let (tmp, base) = fixture();
        let mut opts = ChangeOptions::default();
        let a = edits(tmp.path(), "one", base.clone(), b"new\xff \t\r\n", &opts);
        let b = edits(tmp.path(), "two", base.clone(), b"new\xff", &opts);
        assert_ne!(
            canonical_hash(&a, &opts).unwrap(),
            canonical_hash(&b, &opts).unwrap()
        );
        opts.normalize = Normalize::Strict;
        let a = change_set(&tmp.path().join("one"), base.clone(), &opts).unwrap();
        let b = change_set(&tmp.path().join("two"), base, &opts).unwrap();
        assert_eq!(
            canonical_hash(&a, &opts).unwrap(),
            canonical_hash(&b, &opts).unwrap()
        );
        assert_eq!(
            hash(b"new\xff \t\r\n", Normalize::Strict),
            hash(b"new\xff", Normalize::Exact)
        );
    }
    /// Regression: mode-only changes participate unless ignore-mode is requested.
    #[test]
    fn regression_hash_mode_only_and_ignore_mode() {
        let (tmp, base) = fixture();
        let dir = tmp.path().join("overlay");
        let ov = WriteOverlay::new(base.clone(), &dir).unwrap();
        ov.set_metadata(
            "/a",
            &OverlayMetadata {
                mode: Some(0o755),
                ..Default::default()
            },
        )
        .unwrap();
        drop(ov);
        let mut opts = ChangeOptions::default();
        let changes = change_set(&dir, base.clone(), &opts).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].new.as_ref().unwrap().mode, 0o100755);
        assert_ne!(canonical_hash(&changes, &opts).unwrap(), EMPTY_SHA256);
        opts.ignore_mode = true;
        assert!(change_set(&dir, base, &opts).unwrap().is_empty());
    }
    /// Regression: excluded content never contributes to the canonical hash.
    #[test]
    fn regression_hash_excluded_edits_do_not_contribute() {
        let (tmp, base) = fixture();
        let opts = ChangeOptions {
            excludes: vec!["ignored".into()],
            ..Default::default()
        };
        let a = edits(tmp.path(), "one", base.clone(), b"new\n", &opts);
        let dir = tmp.path().join("two");
        let ov = WriteOverlay::new(base.clone(), &dir).unwrap();
        put(&ov, "/a", b"new\n");
        put(&ov, "/ignored", b"different");
        drop(ov);
        let b = change_set(&dir, base, &opts).unwrap();
        assert_eq!(
            canonical_hash(&a, &opts).unwrap(),
            canonical_hash(&b, &opts).unwrap()
        );
    }
    /// Regression: the empty canonical stream has a documented, stable constant.
    #[test]
    fn regression_hash_empty_constant_and_row_encoding() {
        let opts = ChangeOptions::default();
        assert_eq!(canonical_hash(&[], &opts).unwrap(), EMPTY_SHA256);
        let change = Change {
            path: b"a".to_vec(),
            status: Status::Added,
            old: None,
            new: Some(Entry::from_bytes(0o100644, b"new".to_vec(), &opts).unwrap()),
            base_layer: None,
        };
        let mut row = Vec::new();
        change.write_canonical_row(&mut row, &opts).unwrap();
        assert_eq!(
            row,
            format!(
                "a\0added\0file\0100644\0{}\0",
                hash(b"new", Normalize::Exact)
            )
            .as_bytes()
        );
        assert_eq!(
            canonical_hash(std::slice::from_ref(&change), &opts).unwrap(),
            hash(&row, Normalize::Exact)
        );
        let mut ignored = opts.clone();
        ignored.ignore_mode = true;
        row.clear();
        change.write_canonical_row(&mut row, &ignored).unwrap();
        assert!(row.starts_with(b"a\0added\0file\0\0"));
        let opts = ChangeOptions {
            algo: Algorithm::Blake3,
            ..Default::default()
        };
        assert_eq!(
            canonical_hash(&[], &opts).unwrap(),
            "blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }
    /// Regression: loose removes blank lines, strict retains them, binary ignores normalization.
    #[test]
    fn regression_hash_loose_blank_lines_and_binary() {
        assert_eq!(
            hash(b"\n a \r\n \t\n b\n\n", Normalize::Loose),
            hash(b" a\n b", Normalize::Exact)
        );
        assert_ne!(
            hash(b"a\n\nb\n", Normalize::Strict),
            hash(b"a\nb\n", Normalize::Strict)
        );
        assert_eq!(
            hash(b"a\0 \r\n\n", Normalize::Loose),
            hash(b"a\0 \r\n\n", Normalize::Exact)
        );
        assert!(!binary(b"Latin-1 \xff"));
        let mut late = vec![b'a'; 8192];
        late.push(0);
        assert!(!binary(&late));
        late[8191] = 0;
        assert!(binary(&late));
    }
    /// Regression: normalization is chunk-independent and does not buffer huge lines or spaces.
    #[test]
    fn regression_hash_normalization_streams_across_chunk_boundaries() {
        struct Small<'a>(&'a [u8], usize);
        impl Read for Small<'_> {
            fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
                let n = out.len().min(self.1);
                self.0.read(&mut out[..n])
            }
        }
        let mut data = b"a".to_vec();
        data.extend(vec![b' '; 200_000]);
        data.extend_from_slice(b"b\r\n \t\nlast \r\n");
        for normalize in [Normalize::Exact, Normalize::Strict, Normalize::Loose] {
            let expected = hash(&data, normalize);
            for n in [1, 7, 4096, 8191] {
                assert_eq!(
                    content_hash(&mut Small(&data, n), normalize, Algorithm::Sha256).unwrap(),
                    expected
                );
            }
        }
        assert_eq!(
            hash(b"a\n\n", Normalize::Strict),
            hash(b"a\n", Normalize::Exact)
        );
    }
    /// In-memory statement of the documented rules, independent of TextDigest.
    fn reference_normalize(data: &[u8], loose: bool) -> Vec<u8> {
        let mut lines: Vec<&[u8]> = data
            .split(|b| *b == b'\n')
            .map(|line| {
                let end = line
                    .iter()
                    .rposition(|b| !b.is_ascii_whitespace())
                    .map_or(0, |i| i + 1);
                &line[..end]
            })
            .collect();
        if lines.len() > 1 && lines.last() == Some(&&b""[..]) {
            lines.pop(); // ignore one final newline
        }
        if loose {
            lines.retain(|line| !line.is_empty());
        }
        lines.join(&b'\n')
    }

    /// Regression: strict/loose hashing cloned the digest state per line and per
    /// whitespace run (1 GiB of text: 21 s SHA-256, 65 s BLAKE3 vs 0.9 s exact).
    /// The deferred-buffer digest must equal hashing the reference
    /// normalization for any chunking and for whitespace runs past the buffer.
    #[test]
    fn regression_text_digest_matches_reference_for_any_chunking_and_cap() {
        let alphabet = b"ab \t\r\n\x0b\x0c";
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut next = |n: usize| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state % n as u64) as usize
        };
        let mut inputs: Vec<Vec<u8>> = vec![
            b"".to_vec(),
            b"\n".to_vec(),
            b"\n\n\na".to_vec(),
            b"a\n\n\n".to_vec(),
            b"  \n \n".to_vec(),
            b"a   ".to_vec(),
            b"\r\n\r\nx \r\n\r\n".to_vec(),
        ];
        for _ in 0..400 {
            let len = next(40);
            inputs.push((0..len).map(|_| alphabet[next(alphabet.len())]).collect());
        }
        // Past the 64 KiB stage and blank buffers: long words, long space runs.
        let mut big = Vec::new();
        while big.len() < 300_000 {
            let byte = alphabet[next(alphabet.len())];
            let run = if next(50) == 0 { 70_000 } else { 1 + next(12) };
            big.extend(std::iter::repeat_n(byte, run));
        }
        inputs.push(big);
        for data in &inputs {
            for loose in [false, true] {
                for algo in [Algorithm::Sha256, Algorithm::Blake3] {
                    let mut want = ContentDigest::new(algo);
                    want.update(&reference_normalize(data, loose));
                    let want = want.finish();
                    for cap in [0, 1, 3, TextDigest::BLANK_CAP] {
                        for chunk in [1, 2, 5, 64, 1 << 20] {
                            let mut got = TextDigest::with_cap(algo, loose, cap);
                            for part in data.chunks(chunk) {
                                got.update(part);
                            }
                            assert_eq!(
                                got.finish(),
                                want,
                                "data={data:?} loose={loose} cap={cap} chunk={chunk}"
                            );
                        }
                    }
                }
            }
        }
    }

    /// Regression: write-then-revert and tombstone-of-nothing must not become changes.
    #[test]
    fn regression_changes_revert_and_tombstone_of_nothing() {
        let (tmp, base) = fixture();
        let dir = tmp.path().join("overlay");
        let ov = WriteOverlay::new(base.clone(), &dir).unwrap();
        cow_write(&ov, "/a", b"new");
        cow_write(&ov, "/a", b"old\n");
        put(&ov, "/transient", b"x");
        ov.unlink("/transient").unwrap();
        drop(ov);
        assert!(change_set(&dir, base, &ChangeOptions::default())
            .unwrap()
            .is_empty());
    }
    /// Regression: DB mentions include empty directories, symlink targets, type changes and metadata-only modes.
    #[test]
    fn regression_changes_manifest_types_and_metadata() {
        let (tmp, base) = fixture();
        let dir = tmp.path().join("overlay");
        let ov = WriteOverlay::new(base.clone(), &dir).unwrap();
        ov.mkdir("/empty", 0o755).unwrap();
        ov.unlink("/a").unwrap();
        ov.create_symlink("/a", "/outside/never-open").unwrap();
        put(&ov, "/nested/new", b"written");
        drop(ov);
        let changes = change_set(&dir, base, &ChangeOptions::default()).unwrap();
        let a = changes.iter().find(|c| c.path == b"a").unwrap();
        assert_eq!(a.status, Status::TypeChanged);
        assert_eq!(
            a.new.as_ref().unwrap().target.as_deref(),
            Some(b"/outside/never-open".as_slice())
        );
        assert_eq!(a.manifest_row()["type"], "symlink");
        assert_eq!(a.manifest_row()["base_layer"], "base");
        let empty = changes
            .iter()
            .find(|c| c.path == b"empty")
            .unwrap()
            .manifest_row();
        assert_eq!(empty["type"], "dir");
        assert_eq!(empty["status"], "added");
        assert!(empty.get("hash").is_none());
    }
    /// Regression: JSON writers preserve synthetic non-UTF-8 paths and targets in base64.
    #[test]
    fn regression_manifest_non_utf8_path_and_target_base64() {
        let opts = ChangeOptions::default();
        let c = Change {
            path: b"bad\xff".to_vec(),
            status: Status::Added,
            old: None,
            new: Some(Entry::from_bytes(0o120000, b"target\xfe".to_vec(), &opts).unwrap()),
            base_layer: None,
        };
        let row = c.manifest_row();
        assert!(row.get("path").is_none());
        assert!(row.get("target").is_none());
        assert_eq!(
            STANDARD.decode(row["path_b64"].as_str().unwrap()).unwrap(),
            b"bad\xff"
        );
        assert_eq!(
            STANDARD
                .decode(row["target_b64"].as_str().unwrap())
                .unwrap(),
            b"target\xfe"
        );
    }
    /// Regression: repeated manifest and hash runs are byte-sorted and deterministic.
    #[test]
    fn regression_changes_determinism() {
        let (tmp, base) = fixture();
        let dir = tmp.path().join("overlay");
        let ov = WriteOverlay::new(base.clone(), &dir).unwrap();
        for p in ["/z", "/a", "/é", "/a!", "/A"] {
            put(&ov, p, b"new");
        }
        drop(ov);
        let opts = ChangeOptions::default();
        let a = change_set(&dir, base.clone(), &opts).unwrap();
        let b = change_set(&dir, base, &opts).unwrap();
        assert!(a.windows(2).all(|w| w[0].path < w[1].path));
        let mut out1 = Vec::new();
        let mut out2 = Vec::new();
        write_manifest(&a, &mut out1).unwrap();
        write_manifest(&b, &mut out2).unwrap();
        assert_eq!(out1, out2);
        assert_eq!(
            canonical_hash(&a, &opts).unwrap(),
            canonical_hash(&b, &opts).unwrap()
        );
    }
    struct Counting {
        inner: Arc<dyn MountSource>,
        opens: Arc<AtomicUsize>,
        cached: bool,
    }
    impl MountSource for Counting {
        fn list(&self, path: &str) -> Option<ListResult> {
            self.inner.list(path)
        }
        fn lookup(&self, path: &str, version: i32) -> Option<FileInfo> {
            self.inner.lookup(path, version)
        }
        fn open(&self, fi: &FileInfo, buffering: i32) -> io::Result<Box<dyn ArchiveRead>> {
            self.opens.fetch_add(1, Ordering::Relaxed);
            self.inner.open(fi, buffering)
        }
        fn is_immutable(&self) -> bool {
            self.inner.is_immutable()
        }
        fn get_xattr(&self, _: &FileInfo, key: &str) -> Option<Vec<u8>> {
            (self.cached && key == "user.hash.sha256").then(|| {
                hash(b"old\n", Normalize::Exact)
                    .trim_start_matches("sha256:")
                    .as_bytes()
                    .to_vec()
            })
        }
    }
    /// Regression: exclude blib before all 1,000 host/lower content opens.
    #[test]
    fn regression_cow_excludes_short_circuit_thousand_files() {
        let (tmp, base) = fixture();
        fs::create_dir(tmp.path().join("base/blib")).unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let base: Arc<dyn MountSource> = Arc::new(Counting {
            inner: base,
            opens: count.clone(),
            cached: false,
        });
        let dir = tmp.path().join("overlay");
        let ov = WriteOverlay::new(base.clone(), &dir).unwrap();
        for i in 0..1000 {
            fs::write(tmp.path().join(format!("base/blib/{i}")), b"old").unwrap();
            cow_write(&ov, &format!("/blib/{i}"), b"new");
        }
        drop(ov);
        count.store(0, Ordering::Relaxed);
        TOP_OPENS.set(0);
        let opts = ChangeOptions {
            excludes: vec!["blib/".into()],
            ..Default::default()
        };
        assert!(change_set(&dir, base, &opts).unwrap().is_empty());
        assert_eq!(count.load(Ordering::Relaxed), 0);
        assert_eq!(TOP_OPENS.get(), 0);
    }
    /// Regression: cached lower SHA-256 avoids reads only for exact SHA-256.
    #[test]
    fn regression_changes_cached_lower_hash() {
        let (tmp, source) = fixture();
        let count = Arc::new(AtomicUsize::new(0));
        let base: Arc<dyn MountSource> = Arc::new(Counting {
            inner: source,
            opens: count.clone(),
            cached: true,
        });
        let dir = tmp.path().join("overlay");
        let ov = WriteOverlay::new(base.clone(), &dir).unwrap();
        put(&ov, "/a", b"new");
        drop(ov);
        count.store(0, Ordering::Relaxed);
        change_set(&dir, base.clone(), &ChangeOptions::default()).unwrap();
        assert_eq!(count.load(Ordering::Relaxed), 0);
        change_set(
            &dir,
            base,
            &ChangeOptions {
                normalize: Normalize::Strict,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(count.load(Ordering::Relaxed) > 0);
    }
    /// Regression: gitignore globs respect anchoring, directory-only rules, classes and globstars.
    #[test]
    fn regression_changes_exclude_glob_semantics() {
        for (glob, yes, no) in [
            ("*.o", "deep/a.o", "deep/a.c"),
            ("/a?", "ab", "deep/ab"),
            ("src/[a-c].?", "src/b.c", "src/d.c"),
            ("**/t/**", "x/t/deep/a", "x/tt/a"),
            ("[!a]*", "b", "a"),
        ] {
            let rules = Excludes::new(&ChangeOptions {
                excludes: vec![glob.into()],
                ..Default::default()
            })
            .unwrap();
            assert!(rules.matches(yes, false), "{glob}: {yes}");
            assert!(!rules.matches(no, false), "{glob}: {no}");
        }
        let rules = Excludes::new(&ChangeOptions {
            excludes: vec!["build/".into()],
            ..Default::default()
        })
        .unwrap();
        assert!(!rules.matches("build", false));
        assert!(rules.matches("build", true));
        assert!(rules.matches("x/build/a", false));
        assert!(Excludes::new(&ChangeOptions {
            excludes: vec!["bad[".into()],
            ..Default::default()
        })
        .is_err());
    }
    /// Regression: malformed DB rows are rejected before normalization or content access.
    #[test]
    fn regression_changes_corrupt_paths_and_missing_database() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(mentioned_paths(tmp.path()).is_err());
        assert_eq!(fs::read_dir(tmp.path()).unwrap().count(), 0);
        let conn = Connection::open(tmp.path().join(HIDDEN_DB)).unwrap();
        conn.execute_batch("CREATE TABLE files(path TEXT,name TEXT)")
            .unwrap();
        for (parent, name) in [
            ("/..", "escape"),
            ("", "/absolute"),
            ("//absolute", "x"),
            ("", "nul\0name"),
            ("/a/../b", "x"),
            ("", "a/b"),
        ] {
            conn.execute("INSERT INTO files VALUES(?1,?2)", (parent, name))
                .unwrap();
            let error = mentioned_paths(tmp.path()).unwrap_err().to_string();
            assert!(error.contains("corrupt overlay row"), "{error}");
            conn.execute("DELETE FROM files", []).unwrap();
        }
    }
    /// Regression: lower layers contribute their view and provenance, not their own edits.
    #[test]
    fn regression_changes_lower_view_only_attempt_edits() {
        let (tmp, base) = fixture();
        fs::create_dir(tmp.path().join("base/lib")).unwrap();
        fs::write(tmp.path().join("base/lib/Foo.pm"), b"source").unwrap();
        let prepared = tmp.path().join("prepared");
        let ov = WriteOverlay::new(base.clone(), &prepared).unwrap();
        put(&ov, "/blib/x", b"build");
        put(&ov, "/Makefile", b"prepared");
        drop(ov);
        let lower = crate::compose_stack(base, &[(prepared, Immutability::Shared)]).unwrap();
        let attempt = tmp.path().join("attempt");
        let ov = WriteOverlay::new(lower.clone(), &attempt).unwrap();
        cow_write(&ov, "/lib/Foo.pm", b"attempt");
        ov.unlink("/blib/x").unwrap();
        drop(ov);
        let changes = change_set(&attempt, lower, &ChangeOptions::default()).unwrap();
        assert_eq!(
            changes
                .iter()
                .map(|c| c.path.as_slice())
                .collect::<Vec<_>>(),
            [b"blib/x".as_slice(), b"lib/Foo.pm".as_slice()]
        );
        assert_eq!(changes[0].base_layer, Some(LayerIndex::Lower(1)));
        assert_eq!(changes[0].manifest_row()["base_layer"], "lower:1");
    }

    /// Regression: a COW source edit and rebuilt lower-layer output produced an empty diff.
    #[test]
    fn regression_cow_lower_view_lists_base_and_build_edits() {
        let (tmp, base) = fixture();
        fs::create_dir(tmp.path().join("base/lib")).unwrap();
        fs::write(tmp.path().join("base/lib/Foo.pm"), b"source\n").unwrap();
        let prepared = tmp.path().join("prepared");
        let ov = WriteOverlay::new(base.clone(), &prepared).unwrap();
        ov.mkdir("/blib", 0o755).unwrap();
        put(&ov, "/blib/x", b"build\n");
        drop(ov);
        let lower = crate::compose_stack(base, &[(prepared, Immutability::Shared)]).unwrap();
        let attempt = tmp.path().join("attempt");
        let ov = WriteOverlay::new(lower.clone(), &attempt).unwrap();
        cow_write(&ov, "/lib/Foo.pm", b"edited\n");
        cow_write(&ov, "/blib/x", b"rebuilt\n");
        drop(ov);
        let conn = Connection::open(attempt.join(HIDDEN_DB)).unwrap();
        assert_eq!(
            conn.query_row("SELECT count(*) FROM files", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0
        );
        let changes = change_set(&attempt, lower, &ChangeOptions::default()).unwrap();
        assert_eq!(
            changes
                .iter()
                .map(|c| c.path.as_slice())
                .collect::<Vec<_>>(),
            [b"blib/x".as_slice(), b"lib/Foo.pm".as_slice()]
        );
        assert!(changes.iter().all(|c| c.status == Status::Modified));
        assert_eq!(changes[0].base_layer, Some(LayerIndex::Lower(1)));
        assert_eq!(changes[1].base_layer, Some(LayerIndex::Base));
    }
    /// Regression: identical composed trees compare empty, even with different mentions.
    #[test]
    fn regression_changes_between_identical_and_union() {
        let (tmp, base) = fixture();
        let opts = ChangeOptions::default();
        edits(tmp.path(), "one", base.clone(), b"new", &opts);
        edits(tmp.path(), "two", base.clone(), b"new", &opts);
        assert_eq!(
            canonical_hash(
                &between(
                    &tmp.path().join("two"),
                    &tmp.path().join("one"),
                    base.clone(),
                    &opts
                )
                .unwrap(),
                &opts
            )
            .unwrap(),
            EMPTY_SHA256
        );
        let dir = tmp.path().join("two");
        let ov = WriteOverlay::new(base.clone(), &dir).unwrap();
        put(&ov, "/extra", b"extra");
        drop(ov);
        let changes = between(&tmp.path().join("one"), &dir, base, &opts).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].status, Status::Deleted);
        assert_eq!(changes[0].path, b"extra");
    }
    /// Regression: base-less inspection labels writes without guessing added/modified.
    #[test]
    fn regression_changes_without_base_written() {
        let (tmp, base) = fixture();
        let dir = tmp.path().join("overlay");
        let ov = WriteOverlay::new(base, &dir).unwrap();
        put(&ov, "/new", b"new");
        ov.unlink("/a").unwrap();
        drop(ov);
        let changes = change_set_without_base(&dir, &ChangeOptions::default()).unwrap();
        assert_eq!(changes[0].status, Status::Deleted);
        assert_eq!(changes[1].status, Status::Written);
        assert!(changes[1].base_layer.is_none());
    }
    /// Regression: sparse giant payloads fail the patch-work budget before any host opens.
    #[test]
    fn regression_changes_sparse_limit_before_open_and_max_files() {
        let (tmp, base) = fixture();
        let dir = tmp.path().join("overlay");
        let ov = WriteOverlay::new(base.clone(), &dir).unwrap();
        put(&ov, "/giant", b"");
        drop(ov);
        fs::OpenOptions::new()
            .write(true)
            .open(dir.join("giant"))
            .unwrap()
            .set_len(10 * 1024 * 1024 * 1024)
            .unwrap();
        TOP_OPENS.set(0);
        let error = change_set(
            &dir,
            base.clone(),
            &ChangeOptions {
                max_content_bytes: Some(1024),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(is_limit_error(&error));
        assert_eq!(TOP_OPENS.get(), 0);
        let opts = ChangeOptions {
            max_files: Some(0),
            excludes: vec!["giant".into()],
            ..Default::default()
        };
        assert!(change_set(&dir, base.clone(), &opts).unwrap().is_empty());
        fs::OpenOptions::new()
            .write(true)
            .open(dir.join("giant"))
            .unwrap()
            .set_len(1)
            .unwrap();
        assert!(is_limit_error(
            &change_set(
                &dir,
                base,
                &ChangeOptions {
                    max_files: Some(0),
                    ..Default::default()
                }
            )
            .unwrap_err()
        ));
    }
    /// Regression: neither leaf nor ancestor symlinks expose host target bytes.
    #[cfg(unix)]
    #[test]
    fn regression_changes_symlinks_are_data() {
        let (tmp, base) = fixture();
        let dir = tmp.path().join("overlay");
        let ov = WriteOverlay::new(base.clone(), &dir).unwrap();
        ov.create_symlink("/outside", tmp.path().join("base").to_str().unwrap())
            .unwrap();
        drop(ov);
        let conn = Connection::open(dir.join(HIDDEN_DB)).unwrap();
        conn.execute(
            "INSERT INTO files(path,name,deleted) VALUES('/outside','a',0)",
            [],
        )
        .unwrap();
        drop(conn);
        let changes = change_set(&dir, base, &ChangeOptions::default()).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].path, b"outside");
        assert_eq!(changes[0].kind(), "symlink");
    }
    /// Regression: base-less metadata-only chmod must not be reported as a deletion or empty file.
    #[test]
    fn regression_changes_baseless_metadata_is_written() {
        let (tmp, base) = fixture();
        let dir = tmp.path().join("overlay");
        let ov = WriteOverlay::new(base, &dir).unwrap();
        ov.set_metadata(
            "/a",
            &OverlayMetadata {
                mode: Some(0o755),
                ..Default::default()
            },
        )
        .unwrap();
        drop(ov);
        let changes = change_set_without_base(&dir, &ChangeOptions::default()).unwrap();
        assert_eq!(changes.len(), 1);
        let row = changes[0].manifest_row();
        assert_eq!(row["status"], "written");
        assert_eq!(row["mode"], "100755");
        assert!(row.get("hash").is_none());
        assert!(row.get("size").is_none());
        assert!(change_set_without_base(
            &dir,
            &ChangeOptions {
                ignore_mode: true,
                ..Default::default()
            }
        )
        .unwrap()
        .is_empty());
    }

    /// Regression: a lower overlay's changed payload must not reuse its base's inherited hash xattr.
    #[test]
    fn regression_changes_lower_payload_invalidates_inherited_hash() {
        let (tmp, source) = fixture();
        let base: Arc<dyn MountSource> = Arc::new(Counting {
            inner: source,
            opens: Arc::new(AtomicUsize::new(0)),
            cached: true,
        });
        let lower_dir = tmp.path().join("lower");
        let ov = WriteOverlay::new(base.clone(), &lower_dir).unwrap();
        put(&ov, "/a", b"prepared");
        drop(ov);
        let lower = crate::compose_stack(base, &[(lower_dir, Immutability::Shared)]).unwrap();
        let top = tmp.path().join("top");
        let ov = WriteOverlay::new(lower.clone(), &top).unwrap();
        put(&ov, "/a", b"old\n");
        drop(ov);
        let changes = change_set(&top, lower, &ChangeOptions::default()).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(
            changes[0].old.as_ref().unwrap().hash.as_deref(),
            Some(hash(b"prepared", Normalize::Exact).as_str())
        );
    }
    /// Regression: the valid empty-name root metadata row is not path corruption.
    #[test]
    fn regression_changes_root_mode_row_is_valid() {
        let (tmp, base) = fixture();
        let dir = tmp.path().join("overlay");
        let ov = WriteOverlay::new(base.clone(), &dir).unwrap();
        ov.set_metadata(
            "/",
            &OverlayMetadata {
                mode: Some(0o700),
                ..Default::default()
            },
        )
        .unwrap();
        drop(ov);
        let changes = change_set(&dir, base, &ChangeOptions::default()).unwrap();
        assert_eq!(changes.len(), 1);
        assert!(changes[0].path.is_empty());
        assert_eq!(changes[0].manifest_row()["type"], "dir");
        assert_eq!(changes[0].manifest_row()["mode"], "040700");
        let without_base = change_set_without_base(&dir, &ChangeOptions::default()).unwrap();
        assert_eq!(without_base.len(), 1);
        assert_eq!(without_base[0].status, Status::Written);
    }
    /// Regression: ignored/excluded base-less metadata rows do not exhaust max-files.
    #[test]
    fn regression_changes_baseless_exclusions_and_file_limit() {
        let (tmp, base) = fixture();
        fs::create_dir(tmp.path().join("base/dir")).unwrap();
        let top = tmp.path().join("top");
        let ov = WriteOverlay::new(base, &top).unwrap();
        ov.set_metadata(
            "/dir",
            &OverlayMetadata {
                mode: Some(0o700),
                ..Default::default()
            },
        )
        .unwrap();
        drop(ov);
        assert!(change_set_without_base(
            &top,
            &ChangeOptions {
                excludes: vec!["dir/".into()],
                max_files: Some(0),
                ..Default::default()
            }
        )
        .unwrap()
        .is_empty());
        assert!(change_set_without_base(
            &top,
            &ChangeOptions {
                ignore_mode: true,
                max_files: Some(0),
                ..Default::default()
            }
        )
        .unwrap()
        .is_empty());
        assert!(is_limit_error(
            &change_set_without_base(
                &top,
                &ChangeOptions {
                    max_files: Some(0),
                    ..Default::default()
                }
            )
            .unwrap_err()
        ));
    }

    /// Golden fixture for the canonical hash definition. A fixed overlay, built
    /// through the same COW open FUSE uses (no `files` row for `/a`), must keep
    /// these exact bytes and digests. Changing them changes every recorded
    /// seal, bundle and grading hash: update only with a format version bump.
    /// `test-harness/canonical-hash/reference.py` reproduces the SHA-256 values
    /// independently. Linux only: macOS reports symlink mode 0755, not 0777.
    #[cfg(target_os = "linux")]
    #[test]
    fn golden_canonical_hash_fixture() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let base_dir = tmp.path().join("base");
        fs::create_dir_all(base_dir.join("keep")).unwrap();
        for (name, body) in [
            ("a", b"old\n".as_slice()),
            ("keep/gone.txt", b"gone\n"),
            ("keep/stay.txt", b"stay\n"),
            ("tool", b"#!/bin/sh\n"),
        ] {
            fs::write(base_dir.join(name), body).unwrap();
            fs::set_permissions(base_dir.join(name), fs::Permissions::from_mode(0o644)).unwrap();
        }
        let base: Arc<dyn MountSource> = Arc::new(FolderMountSource::new(&base_dir).unwrap());
        let dir = tmp.path().join("overlay");
        let ov = WriteOverlay::new(base.clone(), &dir).unwrap();
        cow_write(&ov, "/a", b"new\n");
        put(&ov, "/added.txt", b"one  \r\ntwo\t\n\n");
        ov.unlink("/keep/gone.txt").unwrap();
        ov.set_attributes(
            "/tool",
            None,
            &OverlayMetadata {
                mode: Some(0o755),
                ..Default::default()
            },
        )
        .unwrap();
        ov.create_symlink("/link", "a").unwrap();
        ov.mkdir("/dir", 0o755).unwrap();
        drop(ov);
        // Pin host modes so the umask cannot leak into the fixture.
        fs::set_permissions(dir.join("added.txt"), fs::Permissions::from_mode(0o644)).unwrap();
        fs::set_permissions(dir.join("dir"), fs::Permissions::from_mode(0o755)).unwrap();
        let conn = Connection::open(dir.join(HIDDEN_DB)).unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM files WHERE path='' AND name='a'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0,
            "the fixture must exercise a row-less COW edit"
        );
        drop(conn);

        let digest = |normalize, algo| {
            let opts = ChangeOptions {
                normalize,
                algo,
                ..Default::default()
            };
            canonical_hash(&change_set(&dir, base.clone(), &opts).unwrap(), &opts).unwrap()
        };
        let opts = ChangeOptions::default();
        let mut stream = Vec::new();
        for change in change_set(&dir, base.clone(), &opts).unwrap() {
            change.write_canonical_row(&mut stream, &opts).unwrap();
        }
        let got = [
            String::from_utf8(stream).unwrap().replace('\0', "|"),
            digest(Normalize::Exact, Algorithm::Sha256),
            digest(Normalize::Strict, Algorithm::Sha256),
            digest(Normalize::Loose, Algorithm::Sha256),
            digest(Normalize::Exact, Algorithm::Blake3),
        ];
        let want = [
            "a|modified|file|100644|sha256:7aa7a5359173d05b63cfd682e3c38487f3cb4f7f1d60659fe59fab1505977d4c|added.txt|added|file|100644|sha256:f553d63a4fb1dd6dc6cba87232d677814a3fead4d03ab645d46aefebd68ceded|dir|added|dir|040755||keep/gone.txt|deleted|file|100644||link|added|symlink|120777|sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb|tool|modified|file|100755|sha256:a8076d3d28d21e02012b20eaf7dbf75409a6277134439025f282e368e3305abf|",
            "sha256:d1ff1abce4ef923a02e7c6f4fee513333b8fc4ccaef983a2c6395d3d7fa67026",
            "sha256:1fac458db6df916fa9721ef40833e417af99988f90cfa06fbf477a241d46cc37",
            "sha256:73a1c14c339962ca7a2960c48972d7935a9cd82a14bf9c0c2cebb779b02d7aa6",
            "blake3:8ae7dafb36e31e43a419c459e00971e868f5aab31200910dff08c2db0ae18709",
        ];
        assert_eq!(got, want, "canonical hash definition drifted");
    }
}
