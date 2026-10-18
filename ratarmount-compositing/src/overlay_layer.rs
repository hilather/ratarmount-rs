//! Read-only views of write-overlay directories, composed from bottom to top.

use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File};
use std::io::{self, Seek};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ratarmount_core::{
    create_root_file_info, metadata_mode, normpath, read_exact_or_short, ArchiveRead,
    BackingExtent, CheapDirent, FileInfo, ListModeResult, ListResult, MountSource, UserData,
};
use rusqlite::{Connection, OpenFlags};

use crate::write_overlay::{file_info_from_overlay_meta, open_options_nofollow, set_info_atime};
use crate::{is_overlay_internal_path, OverlayMetadata, HIDDEN_DB};

/// Whether the caller guarantees that the overlay directory will not change.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Immutability {
    /// A sealed layer. SQLite opens with `mode=ro&immutable=1` and takes no locks.
    Immutable,
    /// An unsealed layer. SQLite opens read-only and can report a busy writer.
    /// Rows are still a construction-time snapshot; reopen to refresh them.
    Shared,
}

/// Entry provenance in a composed lower view. Lower layers are numbered from 1,
/// bottom to top, matching their order in [`compose_stack`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LayerIndex {
    Base,
    Lower(usize),
}

impl std::fmt::Display for LayerIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Base => f.write_str("base"),
            Self::Lower(index) => write!(f, "lower:{index}"),
        }
    }
}

/// One overlay directory over an existing view. Construction reads all SQL rows
/// in one transaction and closes the database; lookups never query SQLite.
/// Host files remain on disk and are opened independently for each reader.
///
/// Like `WriteOverlay`, host metadata supplies materialized entries, with
/// permission overrides from `overlay_metadata` (also used to preserve sealed
/// modes). All metadata overrides apply to entries inherited from the inner view.
/// This includes rows created by chmod/utime without copying a payload.
pub struct ReadOnlyOverlayLayer {
    inner: Arc<dyn MountSource>,
    root: PathBuf,
    immutability: Immutability,
    index: usize,
    // The files table's mode/mtime/uid/gid are bookkeeping, not read metadata.
    rows: HashMap<String, bool>,
    metadata: HashMap<String, OverlayMetadata>,
    xattrs: HashMap<String, BTreeMap<String, Option<Vec<u8>>>>,
}

impl ReadOnlyOverlayLayer {
    pub fn new(
        inner: Arc<dyn MountSource>,
        overlay: impl AsRef<Path>,
        immutability: Immutability,
    ) -> io::Result<Self> {
        let dir = overlay.as_ref();
        let root = dir.canonicalize().map_err(|e| directory_error(dir, e))?;
        // Fail at construction, rather than quietly presenting only the base.
        for entry in fs::read_dir(&root).map_err(|e| directory_error(dir, e))? {
            entry.map_err(|e| directory_error(dir, e))?;
        }
        let db_path = root.join(HIDDEN_DB);
        let db_meta = fs::symlink_metadata(&db_path).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("overlay database {}: {e}", db_path.display()),
            )
        })?;
        if !db_meta.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "overlay database {} is not a regular file",
                    db_path.display()
                ),
            ));
        }
        let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let conn = match immutability {
            Immutability::Immutable => Connection::open_with_flags(
                immutable_uri(&db_path),
                flags | OpenFlags::SQLITE_OPEN_URI,
            ),
            Immutability::Shared => Connection::open_with_flags(&db_path, flags),
        }
        .map_err(|e| database_error(&root, e))?;
        conn.busy_timeout(std::time::Duration::ZERO)
            .map_err(|e| database_error(&root, e))?;
        let tx = conn
            .unchecked_transaction()
            .map_err(|e| database_error(&root, e))?;
        let tables: Vec<String> = tx
            .prepare("SELECT name FROM sqlite_master WHERE type='table'")
            .and_then(|mut stmt| stmt.query_map([], |r| r.get(0))?.collect())
            .map_err(|e| database_error(&root, e))?;
        if !tables.iter().any(|t| t == "files") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "overlay database {} has no files table; its deletions would be lost \
                     (unlinked archive members reappear). Restore it, or use a new empty folder",
                    db_path.display()
                ),
            ));
        }
        let rows = tx
            .prepare("SELECT path,name,deleted FROM files")
            .and_then(|mut stmt| {
                stmt.query_map([], |r| {
                    let folder: String = r.get(0)?;
                    let name: String = r.get(1)?;
                    let deleted: Option<i64> = r.get(2)?;
                    Ok((normpath(&join(&folder, &name)), deleted == Some(1)))
                })?
                .collect::<rusqlite::Result<HashMap<_, _>>>()
            })
            .map_err(|e| database_error(&root, e))?;
        // Legacy overlays can predate either auxiliary table. A writer would
        // create the missing tables empty; a read-only layer leaves them absent.
        let mut metadata = HashMap::new();
        if tables.iter().any(|t| t == "overlay_metadata") {
            let mut stmt = tx
                .prepare("SELECT path,mode,atime,mtime FROM overlay_metadata")
                .map_err(|e| database_error(&root, e))?;
            let attrs = stmt
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        OverlayMetadata {
                            mode: r.get(1)?,
                            atime: r.get(2)?,
                            mtime: r.get(3)?,
                            ..Default::default()
                        },
                    ))
                })
                .map_err(|e| database_error(&root, e))?;
            for row in attrs {
                let (path, attrs) = row.map_err(|e| database_error(&root, e))?;
                metadata.insert(normpath(&path), attrs);
            }
        }
        let mut xattrs = HashMap::<_, BTreeMap<_, _>>::new();
        if tables.iter().any(|t| t == "xattrs") {
            let mut stmt = tx
                .prepare("SELECT path,name,value FROM xattrs")
                .map_err(|e| database_error(&root, e))?;
            let attrs = stmt
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, Option<Vec<u8>>>(2)?,
                    ))
                })
                .map_err(|e| database_error(&root, e))?;
            for row in attrs {
                let (path, name, value) = row.map_err(|e| database_error(&root, e))?;
                xattrs
                    .entry(normpath(&path))
                    .or_default()
                    .insert(name, value);
            }
        }
        tx.commit().map_err(|e| database_error(&root, e))?;
        // Root cookies retain the depth even when a host entry replaces all of
        // the inner entry's cookies. This also supports manually nested layers.
        let index = inner
            .lookup("/", 0)
            .and_then(|fi| fi.userdata.iter().rev().find_map(layer_tag).map(|t| t.0))
            .unwrap_or(0)
            + 1;
        Ok(Self {
            inner,
            root,
            immutability,
            index,
            rows,
            metadata,
            xattrs,
        })
    }

    /// Top-most layer supplying an entry or overriding its metadata/xattrs.
    /// Tombstoned and absent paths return `None`. For a writable top, callers
    /// determine `top` there before consulting this lower-view provenance.
    pub fn serving_layer(&self, path: &str) -> Option<LayerIndex> {
        serving_layer(self, path)
    }

    fn is_deleted(&self, path: &str) -> bool {
        path != "/" && self.rows.get(path) == Some(&true)
    }

    fn mentions(&self, path: &str) -> bool {
        self.rows.contains_key(path)
            || self.metadata.contains_key(path)
            || self.xattrs.contains_key(path)
    }

    /// Do not traverse symlinks in any host parent, even if their targets stay
    /// inside the layer. Symlinks are mount entries, never host directory aliases.
    fn host_path(&self, path: &str) -> io::Result<PathBuf> {
        let mut host = self.root.clone();
        let mut parts = path.trim_start_matches('/').split('/').peekable();
        while let Some(part) = parts.next() {
            host.push(part);
            if parts.peek().is_some() {
                let meta = fs::symlink_metadata(&host)?;
                if !meta.is_dir() {
                    return Err(io::Error::new(
                        io::ErrorKind::NotADirectory,
                        format!("overlay parent {} is not a directory", host.display()),
                    ));
                }
            }
        }
        Ok(host)
    }

    fn host_info(&self, path: &str) -> Option<FileInfo> {
        let host = self.host_path(path).ok()?;
        let meta = fs::symlink_metadata(&host).ok()?;
        let mut fi = file_info_from_overlay_meta(path, &host, &meta);
        if let Some(mode) = self.metadata.get(path).and_then(|m| m.mode) {
            fi.mode = (fi.mode & !0o7777) | (mode & 0o7777);
        }
        fi.userdata.pop(); // Replace WriteOverlay's cookie with this layer's cookie.
        self.tag(&mut fi, "host", path);
        Some(fi)
    }

    fn host_entries(&self, path: &str) -> Option<fs::ReadDir> {
        let host = self.host_path(path).ok()?;
        if !fs::symlink_metadata(&host).ok()?.is_dir() {
            return None;
        }
        fs::read_dir(host).ok()
    }

    fn can_list(&self, path: &str) -> bool {
        if self.is_deleted(path) {
            return false;
        }
        match self.host_path(path).and_then(fs::symlink_metadata) {
            Ok(meta) => meta.is_dir(),
            Err(e) => e.kind() == io::ErrorKind::NotFound,
        }
    }

    fn apply_metadata(&self, path: &str, fi: &mut FileInfo) {
        if let Some(attrs) = self.metadata.get(path) {
            if let Some(mode) = attrs.mode {
                fi.mode = (fi.mode & !0o7777) | (mode & 0o7777);
            }
            if let Some(mtime) = attrs.mtime {
                fi.mtime = mtime;
            }
            if let Some(atime) = attrs.atime {
                set_info_atime(fi, atime);
            }
        }
    }

    fn tag(&self, fi: &mut FileInfo, kind: &str, path: &str) {
        fi.userdata.push(UserData::Other(format!(
            "overlay-layer:{}:{kind}:{path}",
            self.index
        )));
    }

    fn tag_inner(&self, fi: &mut FileInfo, path: &str) {
        self.apply_metadata(path, fi);
        self.tag(
            fi,
            if self.mentions(path) {
                "metadata"
            } else {
                "inner"
            },
            path,
        );
    }

    fn cookie<'a>(&self, fi: &'a FileInfo) -> Option<(&'a str, &'a str)> {
        let (index, kind, path) = layer_tag(fi.userdata.last()?)?;
        (index == self.index).then_some((kind, path))
    }

    fn inner_info(&self, fi: &FileInfo) -> FileInfo {
        let mut fi = fi.clone();
        if self.cookie(&fi).is_some() {
            fi.userdata.pop();
        }
        fi
    }

    fn open_host(&self, path: &str) -> io::Result<File> {
        if is_overlay_internal_path(path) || self.is_deleted(path) {
            return Err(io::Error::from(io::ErrorKind::NotFound));
        }
        let host = self.host_path(path)?;
        if fs::symlink_metadata(&host)?.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("overlay refuses to follow symlink at {}", host.display()),
            ));
        }
        #[cfg(unix)]
        {
            use std::os::fd::{AsRawFd, FromRawFd};
            use std::os::unix::fs::OpenOptionsExt;
            // Pin each parent descriptor: checking symlink_metadata alone
            // leaves a race if an unsealed layer swaps a directory for a link.
            let mut file = open_options_nofollow()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
                .open(&self.root)?;
            let path = normpath(path);
            let mut parts = path.trim_start_matches('/').split('/').peekable();
            while let Some(part) = parts.next() {
                let name = std::ffi::CString::new(part)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
                let flags = libc::O_RDONLY
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC
                    | libc::O_NONBLOCK
                    | if parts.peek().is_some() {
                        libc::O_DIRECTORY
                    } else {
                        0
                    };
                // SAFETY: file and name remain alive during openat. A successful
                // call returns a new descriptor owned by the File below.
                let fd = unsafe { libc::openat(file.as_raw_fd(), name.as_ptr(), flags) };
                if fd < 0 {
                    return Err(io::Error::last_os_error());
                }
                file = unsafe { File::from_raw_fd(fd) };
            }
            Ok(file)
        }
        #[cfg(not(unix))]
        open_options_nofollow().read(true).open(host)
    }

    fn attrs(&self, fi: &FileInfo) -> BTreeMap<String, Vec<u8>> {
        let Some((_, path)) = self.cookie(fi) else {
            return source_xattrs(self.inner.as_ref(), fi);
        };
        if self.lookup(path, 0).is_none() {
            return BTreeMap::new();
        }
        let mut attrs = self
            .inner
            .lookup(path, 0)
            .map(|fi| source_xattrs(self.inner.as_ref(), &fi))
            .unwrap_or_default();
        if let Some(rows) = self.xattrs.get(path) {
            // BTreeMap puts the replacement sentinel before every named row.
            for (name, value) in rows {
                if name.is_empty() {
                    attrs.clear();
                } else if let Some(value) = value {
                    attrs.insert(name.clone(), value.clone());
                } else {
                    attrs.remove(name);
                }
            }
        }
        attrs
    }
}

impl MountSource for ReadOnlyOverlayLayer {
    fn list(&self, path: &str) -> Option<ListResult> {
        if is_overlay_internal_path(path) {
            return None;
        }
        let path = normpath(path);
        if !self.can_list(&path) {
            return None;
        }
        let mut entries = BTreeMap::new();
        if let Some(base) = self.inner.list(&path) {
            let base = match base {
                ListResult::Infos(map) => map,
                ListResult::Names(names) => names
                    .into_iter()
                    .filter_map(|name| {
                        self.inner
                            .lookup(&join(&path, &name), 0)
                            .map(|fi| (name, fi))
                    })
                    .collect(),
            };
            for (name, mut fi) in base {
                let full = join(&path, &name);
                if !is_overlay_internal_path(&name) && !self.is_deleted(&full) {
                    self.tag_inner(&mut fi, &full);
                    entries.insert(name, fi);
                }
            }
        }
        if let Some(rd) = self.host_entries(&path) {
            for ent in rd.flatten() {
                let name = ent.file_name().to_string_lossy().into_owned();
                let full = join(&path, &name);
                if !is_overlay_internal_path(&name) && !self.is_deleted(&full) {
                    if let Some(fi) = self.host_info(&full) {
                        entries.insert(name, fi);
                    }
                }
            }
        }
        if path == "/" || !entries.is_empty() || self.inner.is_dir(&path) {
            Some(ListResult::Infos(entries))
        } else {
            None
        }
    }

    fn list_dirents(&self, path: &str) -> Option<Vec<CheapDirent>> {
        if is_overlay_internal_path(path) {
            return None;
        }
        let path = normpath(path);
        if !self.can_list(&path) {
            return None;
        }
        let mut entries = BTreeMap::new();
        if let Some(base) = self.inner.list_dirents(&path) {
            for mut d in base {
                let full = join(&path, &d.name);
                if is_overlay_internal_path(&d.name) || self.is_deleted(&full) {
                    continue;
                }
                if let Some(mode) = self.metadata.get(&full).and_then(|m| m.mode) {
                    d.mode = (d.mode & !0o7777) | (mode & 0o7777);
                }
                entries.insert(d.name.clone(), d);
            }
        }
        if let Some(rd) = self.host_entries(&path) {
            for ent in rd.flatten() {
                let name = ent.file_name().to_string_lossy().into_owned();
                let full = join(&path, &name);
                if is_overlay_internal_path(&name) || self.is_deleted(&full) {
                    continue;
                }
                if let Ok(meta) = fs::symlink_metadata(ent.path()) {
                    entries.insert(
                        name.clone(),
                        CheapDirent {
                            name,
                            mode: self
                                .metadata
                                .get(&full)
                                .and_then(|m| m.mode)
                                .map_or(metadata_mode(&meta), |mode| {
                                    (metadata_mode(&meta) & !0o7777) | (mode & 0o7777)
                                }),
                            size: meta.len(),
                        },
                    );
                }
            }
        }
        if path == "/" || !entries.is_empty() || self.inner.is_dir(&path) {
            Some(entries.into_values().collect())
        } else {
            None
        }
    }

    fn list_mode(&self, path: &str) -> Option<ListModeResult> {
        Some(ListModeResult::Modes(
            self.list_dirents(path)?
                .into_iter()
                .map(|d| (d.name, d.mode))
                .collect(),
        ))
    }

    fn lookup(&self, path: &str, file_version: i32) -> Option<FileInfo> {
        if is_overlay_internal_path(path) {
            return None;
        }
        let path = normpath(path);
        if path == "/" {
            let mut fi = create_root_file_info();
            self.apply_metadata(&path, &mut fi);
            self.tag(&mut fi, "root", &path);
            return Some(fi);
        }
        if self.is_deleted(&path) {
            return None;
        }
        if let Err(e) = self.host_path(&path) {
            if e.kind() != io::ErrorKind::NotFound {
                return None;
            }
        }
        self.host_info(&path).or_else(|| {
            self.inner.lookup(&path, file_version).map(|mut fi| {
                self.tag_inner(&mut fi, &path);
                fi
            })
        })
    }

    fn open(&self, fi: &FileInfo, buffering: i32) -> io::Result<Box<dyn ArchiveRead>> {
        if let Some(("host", path)) = self.cookie(fi) {
            return Ok(Box::new(self.open_host(path)?));
        }
        self.inner.open(&self.inner_info(fi), buffering)
    }

    fn read(&self, fi: &FileInfo, size: usize, offset: u64) -> io::Result<Vec<u8>> {
        if let Some(("host", path)) = self.cookie(fi) {
            let mut file = self.open_host(path)?;
            file.seek(io::SeekFrom::Start(offset))?;
            let mut bytes = vec![0; size];
            let n = read_exact_or_short(&mut file, &mut bytes)?;
            bytes.truncate(n);
            return Ok(bytes);
        }
        self.inner.read(&self.inner_info(fi), size, offset)
    }

    fn member_seek_is_cheap(&self, fi: &FileInfo) -> bool {
        matches!(self.cookie(fi), Some(("host", _)))
            || self.inner.member_seek_is_cheap(&self.inner_info(fi))
    }

    fn supports_backing_extents(&self) -> bool {
        self.inner.supports_backing_extents()
    }

    fn backing_extent(&self, fi: &FileInfo) -> Option<BackingExtent> {
        if matches!(self.cookie(fi), Some(("host", _))) {
            return None;
        }
        self.inner.backing_extent(&self.inner_info(fi))
    }

    fn content_generation(&self) -> u64 {
        self.inner.content_generation()
    }

    fn is_immutable(&self) -> bool {
        self.immutability == Immutability::Immutable && self.inner.is_immutable()
    }

    fn list_xattr(&self, fi: &FileInfo) -> Vec<String> {
        self.attrs(fi).into_keys().collect()
    }

    fn get_xattr(&self, fi: &FileInfo, key: &str) -> Option<Vec<u8>> {
        self.attrs(fi).remove(key)
    }
}

/// Compose layers in bottom-to-top order. An empty list returns the base.
pub fn compose_stack(
    mut base: Arc<dyn MountSource>,
    layers: &[(PathBuf, Immutability)],
) -> io::Result<Arc<dyn MountSource>> {
    for (path, immutability) in layers {
        base = Arc::new(ReadOnlyOverlayLayer::new(base, path, *immutability)?);
    }
    Ok(base)
}

/// Provenance for a path in the view returned by [`compose_stack`]. Metadata-only
/// mentions count as this layer; an untouched entry retains its lower origin.
pub fn serving_layer(source: &dyn MountSource, path: &str) -> Option<LayerIndex> {
    let fi = source.lookup(path, 0)?;
    Some(
        fi.userdata
            .iter()
            .rev()
            .filter_map(layer_tag)
            .find(|(_, kind, _)| *kind != "inner")
            .map_or(LayerIndex::Base, |(index, _, _)| LayerIndex::Lower(index)),
    )
}

fn layer_tag(data: &UserData) -> Option<(usize, &str, &str)> {
    let UserData::Other(tag) = data else {
        return None;
    };
    let (index, rest) = tag.strip_prefix("overlay-layer:")?.split_once(':')?;
    let (kind, path) = rest.split_once(':')?;
    Some((index.parse().ok()?, kind, path))
}

fn join(parent: &str, name: &str) -> String {
    format!("{}/{name}", parent.trim_end_matches('/'))
}

fn source_xattrs(source: &dyn MountSource, fi: &FileInfo) -> BTreeMap<String, Vec<u8>> {
    source
        .list_xattr(fi)
        .into_iter()
        .filter_map(|name| source.get_xattr(fi, &name).map(|value| (name, value)))
        .collect()
}

fn directory_error(dir: &Path, error: io::Error) -> io::Error {
    io::Error::new(
        error.kind(),
        format!("cannot read overlay directory {}: {error}", dir.display()),
    )
}

fn database_error(dir: &Path, error: rusqlite::Error) -> io::Error {
    let busy = matches!(
        error.sqlite_error_code(),
        Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
    );
    io::Error::new(
        if busy {
            io::ErrorKind::WouldBlock
        } else {
            io::ErrorKind::InvalidData
        },
        format!(
            "cannot read overlay database in {}{}: {error}",
            dir.display(),
            if busy {
                " (busy: another writer may have the overlay mounted)"
            } else {
                ""
            }
        ),
    )
}

pub(crate) fn immutable_uri(path: &Path) -> String {
    use std::fmt::Write;
    let mut uri = String::from("file:");
    for byte in path.as_os_str().as_encoded_bytes() {
        if byte.is_ascii_alphanumeric() || b"/-._~".contains(byte) {
            uri.push(*byte as char);
        } else {
            write!(&mut uri, "%{byte:02X}").expect("write URI");
        }
    }
    uri.push_str("?mode=ro&immutable=1");
    uri
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{overlay_atime, WriteOverlay, OVERLAY_MARKER};
    use ratarmount_core::{S_IFDIR, S_IFLNK, S_IFMT, S_IFREG};
    use std::io::{Cursor, Read};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Base {
        files: BTreeMap<String, FileInfo>,
        bodies: BTreeMap<String, Vec<u8>>,
        attrs: BTreeMap<String, BTreeMap<String, Vec<u8>>>,
        fat_lists: AtomicUsize,
        immutable: bool,
    }

    impl Base {
        fn new() -> Self {
            let mut base = Self {
                files: BTreeMap::new(),
                bodies: BTreeMap::new(),
                attrs: BTreeMap::new(),
                fat_lists: AtomicUsize::new(0),
                immutable: true,
            };
            base.files.insert("/".into(), create_root_file_info());
            for (path, body) in [
                ("/Makefile", "all: original\n"),
                ("/lib/Foo.pm", "package Foo;\n"),
                ("/restore", "base restore"),
                ("/deleted", "base delete"),
                ("/chmod", "base chmod"),
                ("/untouched", "base untouched"),
                ("/renamed", "destination"),
                ("/xattr-only", "base xattr"),
            ] {
                base.add_file(path, body.as_bytes());
            }
            for path in ["/chmod", "/Makefile", "/renamed", "/xattr-only"] {
                base.attrs.insert(
                    path.into(),
                    BTreeMap::from([
                        ("user.keep".into(), b"inherited".to_vec()),
                        ("user.remove".into(), b"remove me".to_vec()),
                    ]),
                );
            }
            base
        }

        fn add_file(&mut self, path: &str, body: &[u8]) {
            let mut fi = create_root_file_info();
            fi.mode = S_IFREG | 0o644;
            fi.size = body.len() as u64;
            fi.mtime = 123.0;
            fi.userdata = vec![UserData::Other(format!("base:{path}"))];
            self.files.insert(path.into(), fi);
            self.bodies.insert(path.into(), body.to_vec());
            let mut parent = Path::new(path).parent();
            while let Some(dir) = parent {
                let path = dir.to_str().unwrap();
                self.files
                    .entry(path.into())
                    .or_insert_with(create_root_file_info);
                parent = dir.parent();
            }
        }

        fn path(fi: &FileInfo) -> &str {
            let Some(UserData::Other(tag)) = fi.userdata.last() else {
                panic!("missing base cookie");
            };
            tag.strip_prefix("base:")
                .expect("wrapper did not remove its cookie")
        }

        fn children(&self, path: &str) -> Option<BTreeMap<String, FileInfo>> {
            if !self.is_dir(path) {
                return None;
            }
            Some(
                self.files
                    .iter()
                    .filter_map(|(full, fi)| {
                        let (parent, name) = full.rsplit_once('/')?;
                        (full != "/" && parent == path.trim_end_matches('/'))
                            .then(|| (name.to_string(), fi.clone()))
                    })
                    .collect(),
            )
        }
    }

    impl MountSource for Base {
        fn list(&self, path: &str) -> Option<ListResult> {
            self.fat_lists.fetch_add(1, Ordering::Relaxed);
            self.children(path).map(ListResult::Infos)
        }
        fn list_dirents(&self, path: &str) -> Option<Vec<CheapDirent>> {
            Some(
                self.children(path)?
                    .into_iter()
                    .map(|(name, fi)| CheapDirent {
                        name,
                        mode: fi.mode,
                        size: fi.size,
                    })
                    .collect(),
            )
        }
        fn lookup(&self, path: &str, _: i32) -> Option<FileInfo> {
            self.files.get(path).cloned()
        }
        fn open(&self, fi: &FileInfo, _: i32) -> io::Result<Box<dyn ArchiveRead>> {
            Ok(Box::new(Cursor::new(self.bodies[Self::path(fi)].clone())))
        }
        fn is_immutable(&self) -> bool {
            self.immutable
        }
        fn content_generation(&self) -> u64 {
            19
        }
        fn member_seek_is_cheap(&self, fi: &FileInfo) -> bool {
            let _ = Self::path(fi);
            false
        }
        fn list_xattr(&self, fi: &FileInfo) -> Vec<String> {
            if fi.mode & S_IFMT == S_IFDIR {
                return Vec::new();
            }
            self.attrs
                .get(Self::path(fi))
                .map(|m| m.keys().cloned().collect())
                .unwrap_or_default()
        }
        fn get_xattr(&self, fi: &FileInfo, key: &str) -> Option<Vec<u8>> {
            if fi.mode & S_IFMT == S_IFDIR {
                return None;
            }
            self.attrs.get(Self::path(fi))?.get(key).cloned()
        }
    }

    #[cfg(unix)]
    fn write(overlay: &WriteOverlay, path: &str, offset: u64, bytes: &[u8]) {
        let fd = overlay
            .open_overlay_fd(path, libc::O_RDWR | libc::O_CREAT)
            .unwrap();
        let file = overlay.clone_overlay_fd(fd, path).unwrap();
        overlay.write_all_at(&file, path, offset, bytes).unwrap();
        overlay.finish_owned_write_fd(file);
        overlay.close_overlay_fd(fd);
    }

    fn bytes(source: &dyn MountSource, path: &str) -> Vec<u8> {
        let fi = source.lookup(path, 0).unwrap();
        let mut result = Vec::new();
        source
            .open(&fi, 0)
            .unwrap()
            .read_to_end(&mut result)
            .unwrap();
        assert_eq!(source.read(&fi, result.len() + 10, 0).unwrap(), result);
        assert!(source
            .read(&fi, 10, result.len() as u64 + 1)
            .unwrap()
            .is_empty());
        result
    }

    fn names(source: &dyn MountSource, path: &str) -> Vec<String> {
        source
            .list_dirents(path)
            .unwrap()
            .into_iter()
            .map(|d| d.name)
            .collect()
    }

    fn same_info(a: &FileInfo, b: &FileInfo) {
        assert_eq!(
            (a.size, a.mode, a.uid, a.gid, &a.linkname),
            (b.size, b.mode, b.uid, b.gid, &b.linkname)
        );
        assert_eq!(a.mtime, b.mtime);
        // Reading the shared host files/directories/symlinks changes their
        // atime between views. Check deterministic metadata-only atimes below.
    }

    fn compare_views(a: &dyn MountSource, b: &dyn MountSource, path: &str) {
        match (a.lookup(path, 0), b.lookup(path, 0)) {
            (None, None) => return,
            (Some(afi), Some(bfi)) => {
                same_info(&afi, &bfi);
                assert_eq!(source_xattrs(a, &afi), source_xattrs(b, &bfi), "{path}");
                if afi.mode & S_IFMT == S_IFREG {
                    assert_eq!(bytes(a, path), bytes(b, path));
                }
                if afi.mode & S_IFMT != S_IFDIR {
                    return;
                }
            }
            pair => panic!("lookup differs for {path}: {pair:?}"),
        }
        let ad = a.list_dirents(path).map(|v| {
            v.into_iter()
                .map(|d| (d.name, d.mode, d.size))
                .collect::<Vec<_>>()
        });
        let bd = b.list_dirents(path).map(|v| {
            v.into_iter()
                .map(|d| (d.name, d.mode, d.size))
                .collect::<Vec<_>>()
        });
        assert_eq!(ad, bd, "dirents for {path}");
        assert_eq!(
            format!("{:?}", a.list_mode(path)),
            format!("{:?}", b.list_mode(path))
        );
        match (a.list(path), b.list(path)) {
            (None, None) => {}
            (Some(ListResult::Infos(am)), Some(ListResult::Infos(bm))) => {
                assert_eq!(am.keys().collect::<Vec<_>>(), bm.keys().collect::<Vec<_>>());
                for (name, afi) in am {
                    let bfi = &bm[&name];
                    same_info(&afi, bfi);
                    assert_eq!(source_xattrs(a, &afi), source_xattrs(b, bfi));
                    if afi.mode & S_IFMT == S_IFREG {
                        assert_eq!(
                            a.read(&afi, afi.size as usize + 1, 0).unwrap(),
                            b.read(bfi, bfi.size as usize + 1, 0).unwrap()
                        );
                    }
                    compare_views(a, b, &join(path, &name));
                }
            }
            pair => panic!("listing differs for {path}: {pair:?}"),
        }
    }

    /// Regression: a read-only layer must preserve WriteOverlay's host metadata,
    /// metadata-only chmod/utime, inherited/removed xattrs, and rename sentinels.
    #[cfg(unix)]
    #[test]
    fn regression_read_only_view_matches_write_overlay() {
        let dir = tempfile::tempdir().unwrap();
        let base: Arc<dyn MountSource> = Arc::new(Base::new());
        let writer = WriteOverlay::new(base.clone(), dir.path()).unwrap();
        let fd = writer.create_file("/new", 0o640).unwrap();
        writer.close_overlay_fd(fd);
        write(&writer, "/new", 0, b"new payload");
        write(&writer, "/Makefile", 5, b"changed!");
        writer.unlink("/deleted").unwrap();
        writer.mkdir("/made", 0o750).unwrap();
        write(&writer, "/made/child", 0, b"child");
        writer.mkdir("/empty", 0o700).unwrap();
        writer.create_symlink("/link", "missing-target").unwrap();
        for path in ["/chmod", "/new", "/"] {
            writer
                .set_metadata(
                    path,
                    &OverlayMetadata {
                        mode: Some(0o751),
                        atime: Some(1234.25),
                        mtime: Some(5678.5),
                        ..Default::default()
                    },
                )
                .unwrap();
        }
        writer.remove_xattr("/chmod", "user.remove").unwrap();
        writer
            .set_xattr("/chmod", "user.binary", b"\0\xff", 0)
            .unwrap();
        writer
            .set_xattr("/xattr-only", "user.new", b"no copy-up", 0)
            .unwrap();
        writer
            .set_xattr("/new", "user.only", b"new value", 0)
            .unwrap();
        writer.rename("/new", "/renamed").unwrap();
        assert!(!dir.path().join("chmod").exists());
        assert!(!dir.path().join("xattr-only").exists());
        drop(writer);
        for kind in [Immutability::Shared, Immutability::Immutable] {
            let layer = ReadOnlyOverlayLayer::new(base.clone(), dir.path(), kind).unwrap();
            let writer = WriteOverlay::new(base.clone(), dir.path()).unwrap();
            compare_views(&layer, &writer, "/");
            compare_views(&layer, &writer, "/deleted");
            for source in [&layer as &dyn MountSource, &writer] {
                assert_eq!(overlay_atime(&source.lookup("/chmod", 0).unwrap()), 1234.25);
                assert_eq!(overlay_atime(&source.lookup("/", 0).unwrap()), 1234.25);
            }
            let fi = layer.lookup("/renamed", 0).unwrap();
            assert_eq!(layer.list_xattr(&fi), ["user.only"]);
            assert_eq!(
                layer.get_xattr(&fi, "user.only"),
                Some(b"new value".to_vec())
            );
        }
    }

    /// Regression: upper mentions must win, lower tombstones must hide base
    /// entries, and a later layer must be able to recreate a deleted path.
    #[cfg(unix)]
    #[test]
    fn regression_layer_stack_delete_recreate_and_provenance() {
        let temp = tempfile::tempdir().unwrap();
        let prepared = temp.path().join("prepared");
        let attempt = temp.path().join("attempt");
        let base: Arc<dyn MountSource> = Arc::new(Base::new());
        let writer = WriteOverlay::new(base.clone(), &prepared).unwrap();
        writer.mkdir("/blib", 0o755).unwrap();
        write(&writer, "/blib/x", 0, b"build x");
        write(&writer, "/blib/keep", 0, b"build keep");
        write(&writer, "/Makefile", 5, b"prepared");
        writer.unlink("/restore").unwrap();
        writer.unlink("/deleted").unwrap();
        drop(writer);
        let lower =
            compose_stack(base.clone(), &[(prepared.clone(), Immutability::Immutable)]).unwrap();
        assert!(lower.lookup("/restore", 0).is_none());
        let writer = WriteOverlay::new(lower, &attempt).unwrap();
        write(&writer, "/lib/Foo.pm", 8, b"Bar");
        writer.unlink("/blib/x").unwrap();
        write(&writer, "/restore", 0, b"recreated");
        writer
            .set_metadata(
                "/Makefile",
                &OverlayMetadata {
                    mode: Some(0o751),
                    ..Default::default()
                },
            )
            .unwrap();
        writer
            .set_xattr("/blib/keep", "user.layer", b"attempt", 0)
            .unwrap();
        drop(writer);
        let stack = compose_stack(
            base,
            &[
                (prepared, Immutability::Immutable),
                (attempt, Immutability::Immutable),
            ],
        )
        .unwrap();
        assert_eq!(names(stack.as_ref(), "/blib"), ["keep"]);
        assert_eq!(names(stack.as_ref(), "/lib"), ["Foo.pm"]);
        assert!(!names(stack.as_ref(), "/").contains(&"deleted".to_string()));
        assert!(stack.lookup("/blib/x", 0).is_none());
        assert!(stack.lookup("/deleted", 0).is_none());
        assert_eq!(bytes(stack.as_ref(), "/Makefile"), b"all: prepared\n");
        assert_eq!(bytes(stack.as_ref(), "/lib/Foo.pm"), b"package Bar;\n");
        assert_eq!(bytes(stack.as_ref(), "/restore"), b"recreated");
        assert_eq!(bytes(stack.as_ref(), "/blib/keep"), b"build keep");
        let Some(ListResult::Infos(list)) = stack.list("/") else {
            panic!()
        };
        assert_eq!(list["Makefile"].mode & 0o7777, 0o751);
        assert_eq!(stack.lookup("/Makefile", 0).unwrap().mode & 0o7777, 0o751);
        let keep = stack.lookup("/blib/keep", 0).unwrap();
        assert_eq!(
            stack.get_xattr(&keep, "user.layer"),
            Some(b"attempt".to_vec())
        );
        for (path, index) in [
            ("/untouched", LayerIndex::Base),
            ("/blib", LayerIndex::Lower(1)),
            ("/restore", LayerIndex::Lower(2)),
            ("/Makefile", LayerIndex::Lower(2)),
            ("/blib/keep", LayerIndex::Lower(2)),
        ] {
            assert_eq!(serving_layer(stack.as_ref(), path), Some(index), "{path}");
        }
        assert_eq!(serving_layer(stack.as_ref(), "/deleted"), None);
        assert_eq!(LayerIndex::Lower(2).to_string(), "lower:2");
        assert_eq!(LayerIndex::Base.to_string(), "base");
        assert!(stack.is_immutable());
    }

    /// Regression: copy-up through stacked cookies must copy the lower layer's
    /// bytes and xattrs, including paths absent from the original base.
    #[cfg(unix)]
    #[test]
    fn regression_copy_up_reads_lower_layer_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let lower = temp.path().join("lower");
        let middle = temp.path().join("middle");
        let top = temp.path().join("top");
        let base: Arc<dyn MountSource> = Arc::new(Base::new());
        let writer = WriteOverlay::new(base.clone(), &lower).unwrap();
        write(&writer, "/only-lower", 0, b"lower bytes");
        writer
            .set_xattr("/only-lower", "user.build", b"prepared", 0)
            .unwrap();
        drop(writer);
        drop(WriteOverlay::new(base.clone(), &middle).unwrap());
        let stack = compose_stack(
            base,
            &[
                (lower, Immutability::Immutable),
                (middle, Immutability::Immutable),
            ],
        )
        .unwrap();
        assert_eq!(
            serving_layer(stack.as_ref(), "/only-lower"),
            Some(LayerIndex::Lower(1))
        );
        let writer = WriteOverlay::new(stack, &top).unwrap();
        assert_eq!(bytes(&writer, "/only-lower"), b"lower bytes");
        writer.ensure_modifiable("/only-lower").unwrap();
        assert_eq!(fs::read(top.join("only-lower")).unwrap(), b"lower bytes");
        write(&writer, "/only-lower", 11, b" + edit");
        assert_eq!(bytes(&writer, "/only-lower"), b"lower bytes + edit");
        assert_eq!(
            writer.xattrs_for_path("/only-lower").unwrap()["user.build"],
            b"prepared"
        );
    }

    /// Regression: row caches must not hide COW files from lookups, listings or reads.
    #[test]
    fn regression_cow_read_only_layer_matches_writer_without_rows() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("overlay");
        let base: Arc<dyn MountSource> = Arc::new(Base::new());
        let writer = WriteOverlay::new(base.clone(), &dir).unwrap();
        crate::overlay_changes::cow_write(&writer, "/lib/Foo.pm", b"changed\n");
        drop(writer);
        let conn = Connection::open(dir.join(HIDDEN_DB)).unwrap();
        assert_eq!(
            conn.query_row("SELECT count(*) FROM files", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0
        );
        drop(conn);
        let layer = ReadOnlyOverlayLayer::new(base.clone(), &dir, Immutability::Shared).unwrap();
        let writer = WriteOverlay::new(base, &dir).unwrap();
        compare_views(&writer, &layer, "/");
        assert_eq!(bytes(&layer, "/lib/Foo.pm"), b"changed\n");
        assert_eq!(
            layer.serving_layer("/lib/Foo.pm"),
            Some(LayerIndex::Lower(1))
        );
    }

    /// Regression: opening a sealed chmod -w directory must not create SQLite
    /// sidecars or mutate the database, even for URI-special path characters.
    #[cfg(unix)]
    #[test]
    fn regression_immutable_layer_opens_read_only_directory() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("layer ?#% ü");
        let base: Arc<dyn MountSource> = Arc::new(Base::new());
        let writer = WriteOverlay::new(base.clone(), &dir).unwrap();
        write(&writer, "/resident", 0, b"resident bytes");
        drop(writer);
        let before = fs::read(dir.join(HIDDEN_DB)).unwrap();
        fs::set_permissions(dir.join(HIDDEN_DB), fs::Permissions::from_mode(0o444)).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o555)).unwrap();
        let result = ReadOnlyOverlayLayer::new(base, &dir, Immutability::Immutable);
        // Restore on a failed assertion too, so the temp directory remains removable.
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        let layer = result.unwrap();
        assert_eq!(bytes(&layer, "/resident"), b"resident bytes");
        assert_eq!(fs::read(dir.join(HIDDEN_DB)).unwrap(), before);
        let mut names = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect::<Vec<_>>();
        names.sort();
        assert_eq!(
            names,
            [OVERLAY_MARKER, HIDDEN_DB, "resident"].map(std::ffi::OsString::from)
        );
    }

    /// Regression: independent stacks over one sealed layer must not share a
    /// SQLite lock or seek cursor between concurrent readers.
    #[cfg(unix)]
    #[test]
    fn regression_immutable_stacks_read_concurrently() {
        let dir = tempfile::tempdir().unwrap();
        let base: Arc<dyn MountSource> = Arc::new(Base::new());
        let payload = (0..65536).map(|i| (i % 251) as u8).collect::<Vec<_>>();
        let writer = WriteOverlay::new(base.clone(), dir.path()).unwrap();
        write(&writer, "/resident", 0, &payload);
        drop(writer);
        let layers = [(dir.path().to_path_buf(), Immutability::Immutable)];
        let a = compose_stack(base.clone(), &layers).unwrap();
        let b = compose_stack(base, &layers).unwrap();
        std::thread::scope(|scope| {
            for thread in 0..8 {
                let stack = if thread % 2 == 0 {
                    a.clone()
                } else {
                    b.clone()
                };
                let payload = &payload;
                scope.spawn(move || {
                    let fi = stack.lookup("/resident", 0).unwrap();
                    let mut reader = stack.open(&fi, 0).unwrap();
                    for i in 0..64 {
                        let offset = (thread * 7919 + i * 997) % (payload.len() - 1024);
                        reader.seek(io::SeekFrom::Start(offset as u64)).unwrap();
                        let mut buf = [0; 1024];
                        reader.read_exact(&mut buf).unwrap();
                        assert_eq!(buf, payload[offset..offset + 1024]);
                    }
                });
            }
        });
    }

    /// Regression: bookkeeping names at every depth, including base entries,
    /// must stay hidden in lookups and both cheap and fat listings.
    #[test]
    fn regression_layer_internal_names_hidden() {
        let dir = tempfile::tempdir().unwrap();
        let mut base = Base::new();
        let internal = [
            HIDDEN_DB,
            ".RATARMOUNT.OVERLAY.SQLITE-wal",
            OVERLAY_MARKER,
            ".RATARMOUNT.OVERLAY.COW-temp",
        ];
        for name in internal {
            base.add_file(&format!("/{name}"), b"base bookkeeping");
            base.add_file(&format!("/nested/{name}"), b"nested bookkeeping");
        }
        let base: Arc<dyn MountSource> = Arc::new(base);
        drop(WriteOverlay::new(base.clone(), dir.path()).unwrap());
        fs::create_dir(dir.path().join("nested")).unwrap();
        for name in internal {
            fs::write(dir.path().join("nested").join(name), b"host bookkeeping").unwrap();
        }
        let layer = ReadOnlyOverlayLayer::new(base, dir.path(), Immutability::Immutable).unwrap();
        for parent in ["/", "/nested"] {
            for name in internal {
                let path = join(parent, name);
                assert!(layer.lookup(&path, 0).is_none());
                assert!(layer.list(&path).is_none());
                assert!(layer.list_dirents(&format!("{path}/child")).is_none());
            }
            assert!(names(&layer, parent)
                .iter()
                .all(|name| !is_overlay_internal_path(name)));
            let Some(ListResult::Infos(map)) = layer.list(parent) else {
                panic!()
            };
            assert!(map.keys().all(|name| !is_overlay_internal_path(name)));
        }
    }

    /// Regression: a host symlink to an outside file/directory must remain a
    /// symlink entry; neither open nor lookup/list through it may read its target.
    #[cfg(unix)]
    #[test]
    fn regression_layer_symlink_never_follows_host_target() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("layer");
        let outside = temp.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("secret"), b"secret").unwrap();
        let mut base = Base::new();
        base.add_file("/dir-link/secret", b"shadowed base directory");
        let base: Arc<dyn MountSource> = Arc::new(base);
        let writer = WriteOverlay::new(base.clone(), &dir).unwrap();
        writer.unlink("/dir-link/secret").unwrap();
        writer.rmdir("/dir-link").unwrap();
        for (path, target) in [
            ("/file-link", outside.join("secret")),
            ("/dir-link", outside.clone()),
        ] {
            writer
                .create_symlink(path, target.to_str().unwrap())
                .unwrap();
        }
        drop(writer);
        let layer = ReadOnlyOverlayLayer::new(base, &dir, Immutability::Immutable).unwrap();
        let fi = layer.lookup("/file-link", 0).unwrap();
        assert_eq!(fi.mode & S_IFMT, S_IFLNK);
        assert_eq!(fi.linkname, outside.join("secret").to_str().unwrap());
        assert!(layer.open(&fi, 0).is_err());
        assert!(layer.read(&fi, 20, 0).is_err());
        assert!(layer.lookup("/dir-link/secret", 0).is_none());
        assert!(layer.list("/dir-link").is_none());
        assert!(layer.list_dirents("/dir-link").is_none());
        assert!(names(&layer, "/").contains(&"dir-link".into()));
        let Some(ListResult::Infos(map)) = layer.list("/") else {
            panic!()
        };
        assert_eq!(map["file-link"].linkname, fi.linkname);
        assert_eq!(layer.lookup("/dir-link", 0).unwrap().mode & S_IFMT, S_IFLNK);
    }

    /// Regression: cookies issued before a host file/parent is replaced by a
    /// symlink must not open the replacement's target.
    #[cfg(unix)]
    #[test]
    fn regression_layer_stale_cookie_refuses_replaced_symlink() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("layer");
        let outside = temp.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("file"), b"secret").unwrap();
        let base: Arc<dyn MountSource> = Arc::new(Base::new());
        let writer = WriteOverlay::new(base.clone(), &dir).unwrap();
        writer.mkdir("/parent", 0o755).unwrap();
        write(&writer, "/parent/file", 0, b"layer file");
        drop(writer);
        let layer = ReadOnlyOverlayLayer::new(base, &dir, Immutability::Shared).unwrap();
        let fi = layer.lookup("/parent/file", 0).unwrap();
        fs::remove_file(dir.join("parent/file")).unwrap();
        symlink(outside.join("file"), dir.join("parent/file")).unwrap();
        assert!(layer.open(&fi, 0).is_err());
        fs::remove_file(dir.join("parent/file")).unwrap();
        fs::remove_dir(dir.join("parent")).unwrap();
        symlink(&outside, dir.join("parent")).unwrap();
        assert!(layer.open(&fi, 0).is_err());
        assert!(layer.list("/parent").is_none());
        assert!(layer.list_dirents("/parent").is_none());
        assert!(layer.lookup("/parent/file", 0).is_none());
    }

    /// Regression: missing/table-less layer databases must fail closed with
    /// the directory named, never recreate an empty tombstone set (#96).
    #[test]
    fn regression_layer_missing_or_tableless_database_refused() {
        let temp = tempfile::tempdir().unwrap();
        for kind in [Immutability::Shared, Immutability::Immutable] {
            let dir = temp.path().join(format!("{kind:?}"));
            fs::create_dir(&dir).unwrap();
            let open = || {
                ReadOnlyOverlayLayer::new(Arc::new(Base::new()), &dir, kind)
                    .err()
                    .expect("must refuse")
            };
            let error = open();
            assert_eq!(error.kind(), io::ErrorKind::NotFound);
            assert!(error.to_string().contains(dir.to_str().unwrap()));
            assert!(!dir.join(HIDDEN_DB).exists());
            let conn = Connection::open(dir.join(HIDDEN_DB)).unwrap();
            conn.execute_batch("CREATE TABLE unrelated(value TEXT)")
                .unwrap();
            drop(conn);
            let before = fs::read(dir.join(HIDDEN_DB)).unwrap();
            let error = open();
            assert!(error.to_string().contains("has no files table"));
            assert!(error.to_string().contains("its deletions would be lost"));
            assert!(error.to_string().contains(dir.to_str().unwrap()));
            assert_eq!(fs::read(dir.join(HIDDEN_DB)).unwrap(), before);
        }
    }

    /// Regression: a mounted writer must produce a clear read-only busy error,
    /// rather than an empty layer or a constructor that quietly writes schema.
    #[test]
    fn regression_shared_layer_reports_busy_writer() {
        let dir = tempfile::tempdir().unwrap();
        let base: Arc<dyn MountSource> = Arc::new(Base::new());
        let _writer = WriteOverlay::new(base.clone(), dir.path()).unwrap();
        let error = ReadOnlyOverlayLayer::new(base, dir.path(), Immutability::Shared)
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert!(error.to_string().contains("busy"));
        assert!(error.to_string().contains(dir.path().to_str().unwrap()));
    }

    /// Regression: cached tombstones/metadata/xattrs must not query SQLite on
    /// lookup, and cheap listing must not call the inner source's fat listing.
    #[cfg(unix)]
    #[test]
    fn regression_layer_cached_rows_and_cheap_listing() {
        let dir = tempfile::tempdir().unwrap();
        let base = Arc::new(Base::new());
        let writer = WriteOverlay::new(base.clone(), dir.path()).unwrap();
        writer.unlink("/deleted").unwrap();
        writer
            .set_metadata(
                "/chmod",
                &OverlayMetadata {
                    mode: Some(0o711),
                    ..Default::default()
                },
            )
            .unwrap();
        writer
            .set_xattr("/chmod", "user.cached", b"cached", 0)
            .unwrap();
        write(&writer, "/resident", 0, b"resident");
        drop(writer);
        let layer =
            ReadOnlyOverlayLayer::new(base.clone(), dir.path(), Immutability::Shared).unwrap();
        fs::remove_file(dir.path().join(HIDDEN_DB)).unwrap();
        let fi = layer.lookup("/chmod", 0).unwrap();
        assert_eq!(fi.mode & 0o7777, 0o711);
        assert_eq!(
            layer.get_xattr(&fi, "user.cached"),
            Some(b"cached".to_vec())
        );
        assert!(layer.lookup("/deleted", 0).is_none());
        assert_eq!(bytes(&layer, "/resident"), b"resident");
        base.fat_lists.store(0, Ordering::Relaxed);
        assert!(names(&layer, "/").contains(&"resident".into()));
        layer.list_mode("/").unwrap();
        assert_eq!(base.fat_lists.load(Ordering::Relaxed), 0);
        assert_eq!(layer.content_generation(), 19);
        assert!(!layer.is_immutable());
        assert!(!layer.member_seek_is_cheap(&fi));
        assert!(layer.member_seek_is_cheap(&layer.lookup("/resident", 0).unwrap()));
        assert_eq!(layer.serving_layer("/resident"), Some(LayerIndex::Lower(1)));
        assert_eq!(layer.versions("/deleted"), 0);
        assert_eq!(layer.versions("/resident"), 1);
    }

    /// Regression: legacy overlays without metadata/xattr tables must open
    /// without creating those tables, and a mutable inner source stays mutable.
    #[test]
    fn regression_legacy_layer_does_not_create_auxiliary_tables() {
        let dir = tempfile::tempdir().unwrap();
        let mut base = Base::new();
        base.immutable = false;
        let base: Arc<dyn MountSource> = Arc::new(base);
        drop(WriteOverlay::new(base.clone(), dir.path()).unwrap());
        let conn = Connection::open(dir.path().join(HIDDEN_DB)).unwrap();
        conn.execute_batch("DROP TABLE overlay_metadata; DROP TABLE xattrs;")
            .unwrap();
        drop(conn);
        let before = fs::read(dir.path().join(HIDDEN_DB)).unwrap();
        let layer =
            ReadOnlyOverlayLayer::new(base.clone(), dir.path(), Immutability::Immutable).unwrap();
        assert_eq!(bytes(&layer, "/untouched"), b"base untouched");
        assert!(!layer.is_immutable());
        assert_eq!(layer.content_generation(), 19);
        assert_eq!(fs::read(dir.path().join(HIDDEN_DB)).unwrap(), before);
        let empty = compose_stack(base.clone(), &[]).unwrap();
        assert!(Arc::ptr_eq(&empty, &base));
    }

    /// Regression: unreadable/missing/non-directory layer paths must be named
    /// in the constructor error, rather than looking like an empty overlay.
    #[cfg(unix)]
    #[test]
    fn regression_layer_unreadable_directory_named_in_error() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let base: Arc<dyn MountSource> = Arc::new(Base::new());
        let missing = dir.path().join("missing");
        let error = ReadOnlyOverlayLayer::new(base.clone(), &missing, Immutability::Immutable)
            .err()
            .unwrap();
        assert!(error.to_string().contains(missing.to_str().unwrap()));
        let file = dir.path().join("file");
        fs::write(&file, b"not a folder").unwrap();
        let error = ReadOnlyOverlayLayer::new(base.clone(), &file, Immutability::Immutable)
            .err()
            .unwrap();
        assert!(error.to_string().contains(file.to_str().unwrap()));
        if ratarmount_core::effective_uid() == 0 {
            eprintln!("skip: root bypasses directory permission checks");
            return;
        }
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o0)).unwrap();
        let result = ReadOnlyOverlayLayer::new(base, dir.path(), Immutability::Immutable);
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let error = result.err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains(dir.path().to_str().unwrap()));
    }
}
