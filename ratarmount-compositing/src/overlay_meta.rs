//! Overlay identity, creation metadata, and cheap remount verification.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use ratarmount_index::{cached_archive_digest, sha256_hex, sha256_hex_stream, ArchiveDigestStamp};
use rusqlite::{params, Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::write_overlay::Result;
use crate::{OverlayError, HIDDEN_DB};

pub const META_SCHEMA: &str =
    "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum BaseDigestRequest {
    #[default]
    Compute,
    Supplied(String),
    None,
}

impl std::str::FromStr for BaseDigestRequest {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        if value == "none" {
            return Ok(Self::None);
        }
        if let Some(hex) = value.strip_prefix("sha256:") {
            if hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Ok(Self::Supplied(format!(
                    "sha256:{}",
                    hex.to_ascii_lowercase()
                )));
            }
        }
        Err("base digest must be sha256:<64 hex digits> or none".into())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LowerLayerRecord {
    pub path: PathBuf,
    pub layer_digest: String,
    pub sealed_at: String,
}

/// Identity supplied by a caller that knows the original base positional.
/// `local_path` may differ from `base_url` (for example a pinned remote download).
/// Set `index_path` only for an existing index whose cache may be updated.
#[derive(Clone, Debug, Default)]
pub struct OverlayCreateInfo {
    pub base_url: String,
    pub base_digest: BaseDigestRequest,
    pub lower_layers: Vec<LowerLayerRecord>,
    pub force_base_mismatch: bool,
    pub local_path: Option<PathBuf>,
    pub index_path: Option<PathBuf>,
    /// Tree id of the source actually mounted, after any Git subtree selection.
    pub git_tree: Option<String>,
    /// Cheap remote identity, e.g. ETag or Content-Length + Last-Modified.
    pub remote_token: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(transparent)]
pub struct OverlayMeta {
    values: BTreeMap<String, String>,
}

impl OverlayMeta {
    /// Read without creating a directory, database, or table. `None` means an
    /// existing legacy database with no meta table; a missing DB is an error.
    pub fn read(dir: impl AsRef<Path>) -> Result<Option<Self>> {
        let db = dir.as_ref().join(HIDDEN_DB);
        if !fs::symlink_metadata(&db)?.is_file() {
            return Err(OverlayError::Msg(format!(
                "overlay database {} must be a regular file",
                db.display()
            )));
        }
        let read = || -> Result<Option<Self>> {
            let conn = Connection::open_with_flags(
                &db,
                OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )?;
            conn.busy_timeout(std::time::Duration::ZERO)?;
            Self::from_connection(&conn)
        };
        read().map_err(|error| match error {
            OverlayError::Sqlite(rusqlite::Error::SqliteFailure(code, _))
                if matches!(
                    code.code,
                    rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
                ) =>
            {
                OverlayError::Sqlite(rusqlite::Error::SqliteFailure(
                    code,
                    Some(format!("overlay {} is in use", dir.as_ref().display())),
                ))
            }
            error => error,
        })
    }

    pub fn from_connection(conn: &Connection) -> Result<Option<Self>> {
        let exists: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='meta')",
            [],
            |row| row.get(0),
        )?;
        if !exists {
            return Ok(None);
        }
        let mut statement = conn.prepare("SELECT key, value FROM meta ORDER BY key")?;
        let values = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        Ok(Some(Self { values }))
    }

    pub fn values(&self) -> &BTreeMap<String, String> {
        &self.values
    }
    pub fn get(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(String::as_str)
    }
    pub fn format_version(&self) -> Result<Option<u32>> {
        self.get("format_version")
            .map(|value| {
                value
                    .parse()
                    .map_err(|_| OverlayError::Msg("invalid overlay format_version".into()))
            })
            .transpose()
    }
    pub fn legacy(&self) -> bool {
        self.get("format_version").is_none_or(|v| v == "1")
    }
    pub fn base_url(&self) -> Option<&str> {
        self.get("base_url")
    }
    pub fn base_digest(&self) -> Option<&str> {
        self.get("base_digest")
    }
    pub fn base_digest_kind(&self) -> Option<&str> {
        self.get("base_digest_kind")
    }
    pub fn stack_digest(&self) -> Option<&str> {
        self.get("stack_digest")
    }
    pub fn layer_sealed(&self) -> bool {
        self.get("sealed_at").is_some()
    }
    pub fn lower_layers(&self) -> Result<Vec<LowerLayerRecord>> {
        self.get("lower_layers").map_or(Ok(Vec::new()), |value| {
            serde_json::from_str(value)
                .map_err(|e| OverlayError::Msg(format!("invalid lower_layers: {e}")))
        })
    }

    /// Write through the caller's connection (and transaction, if any).
    pub fn set(conn: &Connection, key: &str, value: &str) -> Result<()> {
        Self::set_many(conn, &[(key, value)])
    }

    /// An atomic batch, also safe within a caller-owned transaction.
    pub fn set_many(conn: &Connection, values: &[(&str, &str)]) -> Result<()> {
        conn.execute_batch("SAVEPOINT overlay_meta_write")?;
        let result = (|| -> rusqlite::Result<()> {
            for (key, value) in values {
                conn.execute("INSERT INTO meta (key,value) VALUES (?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value", params![key, value])?;
            }
            conn.execute_batch("RELEASE overlay_meta_write")
        })();
        if result.is_err() {
            let _ =
                conn.execute_batch("ROLLBACK TO overlay_meta_write; RELEASE overlay_meta_write");
        }
        result.map_err(Into::into)
    }
}

/// Digest of the base and ordered lower-layer digests, including the final LF.
pub fn stack_digest(base: &str, layers: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for digest in std::iter::once(base).chain(layers.iter().copied()) {
        hasher.update(digest.as_bytes());
        hasher.update(b"\n");
    }
    format!("sha256:{:x}", hasher.finalize())
}

/// Sorted, length-framed manifest of relative OS path bytes, mode, size and
/// content SHA-256. Symlinks hash their target bytes and are never followed.
/// Directories use size zero; special files are refused instead of opened.
pub fn directory_digest(root: &Path) -> Result<String> {
    fn visit(root: &Path, rel: &Path, paths: &mut Vec<PathBuf>) -> Result<()> {
        paths.push(rel.to_path_buf());
        for entry in fs::read_dir(root.join(rel))? {
            let entry = entry?;
            let child = rel.join(entry.file_name());
            if entry.file_type()?.is_dir() {
                visit(root, &child, paths)?;
            } else {
                paths.push(child);
            }
        }
        Ok(())
    }
    let mut paths = Vec::new();
    visit(root, Path::new(""), &mut paths)?;
    paths.sort_by(|a, b| {
        a.as_os_str()
            .as_encoded_bytes()
            .cmp(b.as_os_str().as_encoded_bytes())
    });
    let mut hasher = Sha256::new();
    for rel in paths {
        let path = root.join(&rel);
        let meta = fs::symlink_metadata(&path)?;
        let (size, content) = if meta.is_dir() {
            (0, String::new())
        } else if meta.is_file() {
            (meta.len(), sha256_hex_stream(&mut fs::File::open(&path)?)?)
        } else if meta.is_symlink() {
            let target = fs::read_link(&path)?;
            let bytes = target.as_os_str().as_encoded_bytes();
            (bytes.len() as u64, sha256_hex(bytes))
        } else {
            return Err(OverlayError::Msg(format!(
                "cannot digest special file {}",
                path.display()
            )));
        };
        let name = rel.as_os_str().as_encoded_bytes();
        hasher.update((name.len() as u64).to_le_bytes());
        hasher.update(name);
        hasher.update(ratarmount_core::metadata_mode(&meta).to_le_bytes());
        hasher.update(size.to_le_bytes());
        hasher.update((content.len() as u64).to_le_bytes());
        hasher.update(content.as_bytes());
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn timestamp() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

impl OverlayCreateInfo {
    fn path(&self) -> Option<&Path> {
        self.local_path.as_deref().or_else(|| {
            (!self.base_url.is_empty()
                && !self.base_url.contains("://")
                && self.git_tree.is_none()
                && self.remote_token.is_none())
            .then(|| Path::new(&self.base_url))
        })
    }

    fn stamp(&self) -> Result<Option<ArchiveDigestStamp>> {
        self.path()
            .filter(|p| p.is_file())
            .map(ArchiveDigestStamp::read)
            .transpose()
            .map_err(Into::into)
    }

    fn digest(&self) -> Result<(String, &'static str)> {
        match &self.base_digest {
            BaseDigestRequest::Supplied(digest) => {
                let validated: BaseDigestRequest = digest.parse().map_err(OverlayError::Msg)?;
                let BaseDigestRequest::Supplied(digest) = validated else {
                    return Err(OverlayError::Msg(
                        "supplied digest must be sha256:<hex>".into(),
                    ));
                };
                return Ok((digest, "strong"));
            }
            BaseDigestRequest::None => return Ok(("none".into(), "none")),
            BaseDigestRequest::Compute => {}
        }
        if let Some(tree) = &self.git_tree {
            return Ok((format!("git-tree:{tree}"), "git-tree"));
        }
        if let Some(path) = self.path() {
            if path.is_dir() {
                return Ok((directory_digest(path)?, "strong"));
            }
            let digest = cached_archive_digest(path, self.index_path.as_deref()).map_err(|e| {
                OverlayError::Msg(format!("cannot hash base {}: {e}", path.display()))
            })?;
            return Ok((digest, "strong"));
        }
        let token =
            serde_json::to_vec(&(&self.base_url, &self.remote_token)).expect("strings serialize");
        Ok((format!("weak:{}", sha256_hex(&token)), "weak"))
    }
}

/// Called only during WriteOverlay open, before tombstone repair or COW sweep.
pub(crate) fn initialize(
    conn: &Connection,
    had_files: bool,
    info: Option<&OverlayCreateInfo>,
    overlay_root: &Path,
) -> Result<()> {
    let previous = OverlayMeta::from_connection(conn)?;
    if had_files {
        if let Some(meta) = previous.filter(|m| !m.values.is_empty()) {
            if !meta.legacy() {
                if let Some(info) = info {
                    verify(conn, &meta, info)?;
                }
            }
            return Ok(());
        }
        // A schema-only migration must never claim to know a legacy base.
        return OverlayMeta::set(conn, "format_version", "1");
    }
    let default = OverlayCreateInfo {
        base_digest: BaseDigestRequest::None,
        ..Default::default()
    };
    let info = info.unwrap_or(&default);
    if info.base_digest == BaseDigestRequest::Compute && info.git_tree.is_none() {
        if let Some(path) = info.path().filter(|path| path.is_dir()) {
            if overlay_root.starts_with(path.canonicalize()?) {
                return Err(OverlayError::Msg(
                    "cannot compute a directory base digest with the overlay inside the base; place the overlay outside the base or supply --base-digest".into(),
                ));
            }
        }
    }
    let before = info.stamp()?;
    let (digest, kind) = info.digest()?;
    if info.stamp()? != before {
        return Err(OverlayError::Msg("base changed while hashing".into()));
    }
    let mut values = BTreeMap::from([
        ("format_version", "2".to_owned()),
        ("ratarmount_version", env!("CARGO_PKG_VERSION").to_owned()),
        ("created_at", timestamp()),
        ("base_url", info.base_url.clone()),
        ("base_digest", digest.clone()),
        ("base_digest_kind", kind.to_owned()),
        (
            "lower_layers",
            serde_json::to_string(&info.lower_layers)
                .map_err(|e| OverlayError::Msg(e.to_string()))?,
        ),
        (
            "stack_digest",
            stack_digest(
                &digest,
                &info
                    .lower_layers
                    .iter()
                    .map(|l| l.layer_digest.as_str())
                    .collect::<Vec<_>>(),
            ),
        ),
    ]);
    if let Some(stamp) = before {
        values.insert("base_size", stamp.size.to_string());
        values.insert("base_mtime_ns", stamp.mtime_ns.to_string());
    }
    if let Some(path) = info.path().filter(|p| p.is_file()) {
        values.insert(
            "base_local_path",
            path.canonicalize()?.to_string_lossy().into_owned(),
        );
    }
    if let Some(index) = &info.index_path {
        values.insert(
            "base_index_path",
            std::path::absolute(index)?.to_string_lossy().into_owned(),
        );
    }
    if let Some(tree) = &info.git_tree {
        values.insert("base_git_tree", tree.clone());
    }
    if let Some(token) = &info.remote_token {
        values.insert("base_remote_token", token.clone());
    }
    OverlayMeta::set_many(
        conn,
        &values
            .iter()
            .map(|(k, v)| (*k, v.as_str()))
            .collect::<Vec<_>>(),
    )
}

/// Advance the baseline only after archive persistence succeeds. Legacy overlays
/// retain their unknown identity. The caller holds the commit gate / DB lock.
pub(crate) fn refresh_committed_base(conn: &Connection, archive: &Path) -> Result<()> {
    let Some(meta) = OverlayMeta::from_connection(conn)?.filter(|meta| !meta.legacy()) else {
        return Ok(());
    };
    let archive = archive.canonicalize()?;
    let stamp = ArchiveDigestStamp::read(&archive)?;
    let sibling = PathBuf::from(format!("{}.index.sqlite", archive.display()));
    let index = if meta.get("base_local_path") == archive.to_str() {
        meta.get("base_index_path")
            .map(Path::new)
            .unwrap_or(&sibling)
    } else {
        &sibling
    };
    let digest = match meta.base_digest_kind() {
        Some("strong") => ratarmount_index::refresh_archive_digest(&archive, Some(index))
            .map_err(|error| OverlayError::Msg(format!("cannot hash committed base: {error}")))?,
        Some("weak") => format!("weak:size={},mtime_ns={}", stamp.size, stamp.mtime_ns),
        _ => meta.base_digest().unwrap_or("none").to_owned(),
    };
    if ArchiveDigestStamp::read(&archive)? != stamp {
        return Err(OverlayError::Msg(
            "base changed while hashing committed archive".into(),
        ));
    }
    let layers = meta.lower_layers()?;
    let stack = stack_digest(
        &digest,
        &layers
            .iter()
            .map(|l| l.layer_digest.as_str())
            .collect::<Vec<_>>(),
    );
    OverlayMeta::set_many(
        conn,
        &[
            ("base_size", &stamp.size.to_string()),
            ("base_mtime_ns", &stamp.mtime_ns.to_string()),
            ("base_digest", &digest),
            ("stack_digest", &stack),
            ("base_committed_at", &timestamp()),
            ("base_local_path", &archive.to_string_lossy()),
            ("base_index_path", &index.to_string_lossy()),
        ],
    )
}

pub(crate) fn refresh_committed_base_offline(overlay: &Path, archive: &Path) -> Result<()> {
    let db = overlay.join(HIDDEN_DB);
    // Some offline callers commit a directory of files without an overlay DB.
    if !db.exists() {
        return Ok(());
    }
    let conn = Connection::open_with_flags(db, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    conn.busy_timeout(std::time::Duration::ZERO)?;
    refresh_committed_base(&conn, archive)
}

fn verify(conn: &Connection, meta: &OverlayMeta, info: &OverlayCreateInfo) -> Result<()> {
    if meta.base_digest_kind() == Some("none") {
        return Ok(());
    }
    let old = meta.base_digest().unwrap_or("none");
    let mismatch = if let Some(recorded) = meta.get("base_git_tree") {
        (info.git_tree.as_deref() != Some(recorded)).then(|| {
            format!(
                "git-tree:{}",
                info.git_tree.as_deref().unwrap_or("unavailable")
            )
        })
    } else if let (Some(size), Some(mtime)) = (meta.get("base_size"), meta.get("base_mtime_ns")) {
        match info.stamp()? {
            Some(now) if now.size.to_string() == size && now.mtime_ns.to_string() == mtime => None,
            Some(now) => Some(format!(
                "weak:size={},mtime_ns={} (current SHA-256 not recomputed)",
                now.size, now.mtime_ns
            )),
            None => Some("unavailable (local archive missing)".into()),
        }
    } else {
        None
    };
    let mismatch = mismatch.or_else(|| match &info.base_digest {
        BaseDigestRequest::Supplied(digest) if digest != old => Some(digest.clone()),
        _ => None,
    });
    if let Some(current) = mismatch {
        if !info.force_base_mismatch {
            return Err(OverlayError::Msg(format!("base mismatch: recorded digest {old}; current digest {current}; use --force-base-mismatch to override")));
        }
        OverlayMeta::set(conn, "base_mismatch_forced_at", &timestamp())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FolderMountSource, WriteOverlay};
    use ratarmount_core::{ArchiveRead, FileInfo, ListResult, MountSource};
    use std::io;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    fn base(root: &Path) -> Arc<dyn MountSource> {
        Arc::new(FolderMountSource::new(root).unwrap())
    }

    fn info(path: &Path) -> OverlayCreateInfo {
        OverlayCreateInfo {
            base_url: path.to_str().unwrap().into(),
            ..Default::default()
        }
    }

    /// Regression: committing must preserve digest opt-out and legacy identities.
    #[test]
    fn regression_overlay_meta_commit_preserves_kind_and_legacy() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("base.tar");
        fs::write(&archive, b"after commit").unwrap();
        for kind in ["none", "weak"] {
            let conn = Connection::open_in_memory().unwrap();
            conn.execute_batch(META_SCHEMA).unwrap();
            OverlayMeta::set_many(
                &conn,
                &[
                    ("format_version", "2"),
                    ("base_digest_kind", kind),
                    ("base_digest", kind),
                    ("lower_layers", "[]"),
                ],
            )
            .unwrap();
            refresh_committed_base(&conn, &archive).unwrap();
            let meta = OverlayMeta::from_connection(&conn).unwrap().unwrap();
            assert_eq!(meta.base_digest_kind(), Some(kind));
            assert_eq!(meta.get("base_size"), Some("12"));
            assert!(meta.get("base_committed_at").is_some());
            if kind == "none" {
                assert_eq!(meta.base_digest(), Some("none"));
            } else {
                assert!(meta.base_digest().unwrap().starts_with("weak:size=12,"));
            }
        }
        let conn = Connection::open_in_memory().unwrap();
        refresh_committed_base(&conn, &archive).unwrap();
        assert!(OverlayMeta::from_connection(&conn).unwrap().is_none());
        conn.execute_batch(META_SCHEMA).unwrap();
        OverlayMeta::set(&conn, "format_version", "1").unwrap();
        refresh_committed_base(&conn, &archive).unwrap();
        let meta = OverlayMeta::from_connection(&conn).unwrap().unwrap();
        assert_eq!(meta.values().len(), 1);
        assert!(meta.legacy());
    }

    /// Regression: new overlays lacked creation identity and stack ordering.
    #[test]
    fn regression_overlay_meta_creation_keys_and_stack_vector() {
        assert_eq!(
            stack_digest("sha256:base", &["sha256:first", "sha256:second"]),
            "sha256:4e3fef1cc62d99d7f6cb7fd49747c58d4f5f72e513cb7f3ed443c7fc44c31a6c"
        );
        let root = tempfile::tempdir().unwrap();
        let archive = root.path().join("base.tar");
        fs::write(&archive, b"abc").unwrap();
        let overlay = root.path().join("overlay");
        let mut info = info(&archive);
        info.lower_layers.push(LowerLayerRecord {
            path: "prepared".into(),
            layer_digest: "sha256:first".into(),
            sealed_at: "2026-10-17T00:00:00Z".into(),
        });
        drop(WriteOverlay::new_with_create_info(base(root.path()), &overlay, &info).unwrap());
        let meta = OverlayMeta::read(&overlay).unwrap().unwrap();
        for key in [
            "format_version",
            "ratarmount_version",
            "created_at",
            "base_url",
            "base_digest",
            "base_digest_kind",
            "lower_layers",
            "stack_digest",
            "base_size",
            "base_mtime_ns",
        ] {
            assert!(meta.get(key).is_some(), "missing {key}");
        }
        chrono::DateTime::parse_from_rfc3339(meta.get("created_at").unwrap()).unwrap();
        assert_eq!(meta.format_version().unwrap(), Some(2));
        assert!(!meta.legacy());
        assert!(!meta.layer_sealed());
        assert_eq!(meta.base_digest_kind(), Some("strong"));
        assert_eq!(meta.base_url(), Some(info.base_url.as_str()));
        assert_eq!(
            meta.base_digest(),
            Some("sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        assert_eq!(meta.lower_layers().unwrap(), info.lower_layers);
        assert_eq!(
            meta.stack_digest(),
            Some(stack_digest(meta.base_digest().unwrap(), &["sha256:first"]).as_str())
        );
    }

    /// Regression: legacy overlays must keep tombstones and remain digest-free after migration.
    #[test]
    fn regression_overlay_meta_legacy_migration_preserves_deletions() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("deleted"), b"base").unwrap();
        let overlay = root.path().join("overlay");
        fs::create_dir(&overlay).unwrap();
        let conn = Connection::open(overlay.join(HIDDEN_DB)).unwrap();
        conn.execute_batch("CREATE TABLE files (path TEXT, name TEXT, mtime REAL, mode INTEGER, uid INTEGER, gid INTEGER, deleted BOOL, PRIMARY KEY(path,name)); INSERT INTO files VALUES ('','deleted',0,33188,0,0,1);").unwrap();
        drop(conn);
        assert!(OverlayMeta::read(&overlay).unwrap().is_none());
        let mut context = info(Path::new("missing base that must never be hashed"));
        context.force_base_mismatch = false;
        let ov = WriteOverlay::new_with_create_info(base(root.path()), &overlay, &context).unwrap();
        assert!(ov.lookup("/deleted", 0).is_none());
        drop(ov);
        let meta = OverlayMeta::read(&overlay).unwrap().unwrap();
        assert!(meta.legacy());
        assert_eq!(
            meta.values(),
            &BTreeMap::from([("format_version".into(), "1".into())])
        );
    }

    struct CountingBase(AtomicUsize);
    impl MountSource for CountingBase {
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
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(io::Error::other("base payload must not be read"))
        }
    }

    /// Regression: a caller-supplied digest must never hash or open base payloads.
    #[test]
    fn regression_overlay_meta_supplied_digest_reads_no_base_bytes() {
        let root = tempfile::tempdir().unwrap();
        let source = Arc::new(CountingBase(AtomicUsize::new(0)));
        // A nonexistent local file would make the real file hasher fail.
        let mut context = info(&root.path().join("unreadable-base"));
        context.base_digest = BaseDigestRequest::Supplied(format!("sha256:{}", "a".repeat(64)));
        let overlay = root.path().join("overlay");
        drop(WriteOverlay::new_with_create_info(source.clone(), &overlay, &context).unwrap());
        assert_eq!(source.0.load(Ordering::SeqCst), 0);
        assert_eq!(
            OverlayMeta::read(&overlay).unwrap().unwrap().base_digest(),
            Some(format!("sha256:{}", "a".repeat(64)).as_str())
        );
    }

    /// Regression: unchanged remounts rehashed bytes; changed bases were silently accepted.
    #[test]
    fn regression_overlay_meta_remount_mismatch_and_force() {
        let root = tempfile::tempdir().unwrap();
        let archive = root.path().join("a.tar");
        fs::write(&archive, b"abc").unwrap();
        let overlay = root.path().join("overlay");
        let mut context = info(&archive);
        drop(WriteOverlay::new_with_create_info(base(root.path()), &overlay, &context).unwrap());
        let old = OverlayMeta::read(&overlay)
            .unwrap()
            .unwrap()
            .base_digest()
            .unwrap()
            .to_owned();
        // Deliberately preserving size and mtime demonstrates the documented
        // cheap check: a remount must not compare newly hashed contents.
        let modified = fs::metadata(&archive).unwrap().modified().unwrap();
        fs::write(&archive, b"xyz").unwrap();
        fs::File::options()
            .write(true)
            .open(&archive)
            .unwrap()
            .set_modified(modified)
            .unwrap();
        context.index_path = Some(root.path().join("missing-index"));
        drop(WriteOverlay::new_with_create_info(base(root.path()), &overlay, &context).unwrap());
        assert!(!context.index_path.as_ref().unwrap().exists());
        fs::write(&archive, b"changed").unwrap();
        let error = WriteOverlay::new_with_create_info(base(root.path()), &overlay, &context)
            .err()
            .unwrap()
            .to_string();
        assert!(
            error.contains(&old) && error.contains("current digest weak:size=7"),
            "{error}"
        );
        assert!(OverlayMeta::read(&overlay)
            .unwrap()
            .unwrap()
            .get("base_mismatch_forced_at")
            .is_none());
        context.force_base_mismatch = true;
        drop(WriteOverlay::new_with_create_info(base(root.path()), &overlay, &context).unwrap());
        let meta = OverlayMeta::read(&overlay).unwrap().unwrap();
        assert!(meta.get("base_mismatch_forced_at").is_some());
        assert_eq!(meta.base_digest(), Some(old.as_str()));
    }

    /// Regression: Git refs need a tree identity, while unavailable remote metadata stays weak.
    #[test]
    fn regression_overlay_meta_git_remote_and_none_kinds() {
        let root = tempfile::tempdir().unwrap();
        let mut context = OverlayCreateInfo {
            base_url: "repo@main".into(),
            git_tree: Some("a".repeat(40)),
            ..Default::default()
        };
        let overlay = root.path().join("git");
        drop(WriteOverlay::new_with_create_info(base(root.path()), &overlay, &context).unwrap());
        assert_eq!(
            OverlayMeta::read(&overlay)
                .unwrap()
                .unwrap()
                .base_digest_kind(),
            Some("git-tree")
        );
        context.git_tree = Some("b".repeat(40));
        let error = WriteOverlay::new_with_create_info(base(root.path()), &overlay, &context)
            .err()
            .unwrap()
            .to_string();
        assert!(
            error.contains(&format!("git-tree:{}", "a".repeat(40)))
                && error.contains(&format!("git-tree:{}", "b".repeat(40)))
        );
        let remote = OverlayCreateInfo {
            base_url: "hf://datasets/a/b@main/snapshot.tar".into(),
            ..Default::default()
        };
        assert_eq!(remote.digest().unwrap().1, "weak");
        assert_eq!(remote.digest().unwrap(), remote.digest().unwrap());
        let with_token = OverlayCreateInfo {
            remote_token: Some("etag:123".into()),
            ..remote.clone()
        };
        assert_ne!(remote.digest().unwrap().0, with_token.digest().unwrap().0);
        let overlay = root.path().join("no-context");
        drop(WriteOverlay::new(base(root.path()), &overlay).unwrap());
        let meta = OverlayMeta::read(&overlay).unwrap().unwrap();
        assert_eq!(meta.base_digest_kind(), Some("none"));
        assert_eq!(meta.format_version().unwrap(), Some(2));
    }

    /// Regression: a directory digest depended on creation order or followed symlinks.
    #[test]
    fn regression_overlay_meta_directory_digest_deterministic() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        for (root, names) in [(a.path(), ["one", "two"]), (b.path(), ["two", "one"])] {
            for name in names {
                fs::write(root.join(name), name).unwrap();
            }
            fs::create_dir(root.join("empty")).unwrap();
        }
        assert_eq!(
            directory_digest(a.path()).unwrap(),
            directory_digest(b.path()).unwrap()
        );
        fs::write(b.path().join("one"), "changed").unwrap();
        assert_ne!(
            directory_digest(a.path()).unwrap(),
            directory_digest(b.path()).unwrap()
        );
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/absent-target", a.path().join("link")).unwrap();
            assert!(directory_digest(a.path()).is_ok());
            use std::os::unix::fs::PermissionsExt;
            let before = directory_digest(a.path()).unwrap();
            fs::set_permissions(a.path().join("one"), fs::Permissions::from_mode(0o755)).unwrap();
            assert_ne!(directory_digest(a.path()).unwrap(), before);
        }
    }

    /// Regression: a directory digest included its own SQLite journal and changed as metadata was written.
    #[test]
    fn regression_overlay_meta_directory_cannot_hash_its_own_overlay() {
        let root = tempfile::tempdir().unwrap();
        let overlay = root.path().join("overlay");
        let mut context = info(root.path());
        let error = WriteOverlay::new_with_create_info(base(root.path()), &overlay, &context)
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("overlay inside the base"), "{error}");
        assert!(!overlay.join(HIDDEN_DB).exists());
        assert!(!overlay.join(crate::OVERLAY_MARKER).exists());
        context.base_digest = BaseDigestRequest::Supplied(format!("sha256:{}", "a".repeat(64)));
        drop(WriteOverlay::new_with_create_info(base(root.path()), &overlay, &context).unwrap());
        assert_eq!(
            OverlayMeta::read(&overlay)
                .unwrap()
                .unwrap()
                .base_digest_kind(),
            Some("strong")
        );
    }

    /// Regression: read-only metadata inspection created files or hid SQLITE_BUSY.
    #[test]
    fn regression_overlay_meta_read_only_missing_and_in_use() {
        let root = tempfile::tempdir().unwrap();
        let overlay = root.path().join("overlay");
        assert!(OverlayMeta::read(&overlay).is_err());
        assert!(!overlay.exists());
        let ov = WriteOverlay::new(base(root.path()), &overlay).unwrap();
        let error = OverlayMeta::read(&overlay).unwrap_err().to_string();
        assert!(error.contains("in use"), "{error}");
        drop(ov);
        let db = overlay.join(HIDDEN_DB);
        let before = fs::read(&db).unwrap();
        assert!(OverlayMeta::read(&overlay).unwrap().is_some());
        assert_eq!(before, fs::read(&db).unwrap());
    }

    /// Regression: metadata batches must roll back together and respect caller transactions.
    #[test]
    fn regression_overlay_meta_set_many_atomic_in_transaction() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(META_SCHEMA).unwrap();
        conn.execute_batch("CREATE TRIGGER reject_bad BEFORE INSERT ON meta WHEN NEW.key='bad' BEGIN SELECT RAISE(ABORT, 'bad key'); END;").unwrap();
        let tx = conn.transaction().unwrap();
        OverlayMeta::set(&tx, "kept", "yes").unwrap();
        assert!(OverlayMeta::set_many(&tx, &[("rolled_back", "yes"), ("bad", "no")]).is_err());
        let meta = OverlayMeta::from_connection(&tx).unwrap().unwrap();
        assert_eq!(meta.get("kept"), Some("yes"));
        assert_eq!(meta.get("rolled_back"), None);
        tx.rollback().unwrap();
        assert!(OverlayMeta::from_connection(&conn)
            .unwrap()
            .unwrap()
            .values()
            .is_empty());
    }
}
