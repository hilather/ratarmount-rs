//! Index path resolution (Python `SQLiteIndex.get_possible_index_file_paths` subset).
//!
//! Also materializes remote / URL index paths (`http(s)://`, `file://`) and decompresses
//! gzip/xz/zstd/bzip2 index blobs for Python parity with `SQLiteIndex._load_index`.
//!
//! Portable artifact identity (G-2): [`INDEX_MEDIA_TYPE`] names this SQLite **blob
//! family** (`v1`). Inner [`crate::INDEX_VERSION`] (`"0.7.0"`) is the `files` schema.
//! Those are not the same string and this is **not** SOCI / eStargz / nydus zTOC.
//! Inbound clients parse RFC 8288 `Link: rel="describedby"` on HEAD of the
//! **archive** URL ([`parse_link_describedby`]) and try sibling URLs
//! ([`sibling_index_pointer_url`], [`sibling_index_candidates`],
//! [`object_store_sibling_index_candidates`]). Local folder order in
//! [`resolve_index_location`] is unchanged (`oci:{digest}` cache stays first
//! among folder candidates).

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use log::{debug, warn};
use serde::{Deserialize, Serialize};

use crate::{
    parse_tarstats_json, serialize_tarstats, tar_stats_from_path, IndexError, Result, TarStats,
};

/// SQLite database header magic (16 bytes including trailing NUL).
const SQLITE_MAGIC: &[u8] = b"SQLite format 3\0";

const GZIP_MAGIC: &[u8] = &[0x1f, 0x8b];
const XZ_MAGIC: &[u8] = &[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00];
const ZSTD_MAGIC: &[u8] = &[0x28, 0xb5, 0x2f, 0xfd];
const BZIP2_MAGIC: &[u8] = b"BZh";

/// Where the SQLite index lives for a mount.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IndexLocation {
    /// Pure in-memory SQLite (`--index-file :memory:`).
    Memory,
    /// On-disk index file.
    Path(PathBuf),
}

impl IndexLocation {
    pub fn as_path(&self) -> Option<&Path> {
        match self {
            Self::Memory => None,
            Self::Path(p) => Some(p.as_path()),
        }
    }

    pub fn is_memory(&self) -> bool {
        matches!(self, Self::Memory)
    }
}

/// Sentinel accepted by `--index-file`.
pub const MEMORY_INDEX: &str = ":memory:";

/// HTTP/OCI media type for a portable ratarmount SQLite index **blob**.
///
/// `v1` names this artifact family (on-disk or wrapped `.gz` / `.zst` / `.xz` /
/// `.bz2` SQLite sidecar). It is **not** the inner catalog schema and is **not**
/// SOCI / eStargz / nydus zTOC. The `files` table schema remains
/// [`crate::INDEX_VERSION`] (`"0.7.0"`).
pub const INDEX_MEDIA_TYPE: &str = "application/vnd.ratarmount.index.v1+sqlite";

/// IANA `rel` for an index that describes the archive (RFC 8288 inbound HEAD).
///
/// Clients parse `Link` on the **archive** URL. `--http` tree export is not an
/// archive server; outbound `Link` on `index.sqlite` is not inbound discovery.
pub const INDEX_LINK_REL: &str = "describedby";

/// Sibling of the well-known SQLite blob (`{archive}.index.ptr`). Not [`crate::INDEX_VERSION`].
/// Not SOCI.
pub const INDEX_POINTER_SCHEMA: &str = "ratarmount.index.pointer.v1";

/// `index_id` / `etag_sha256` are lowercase hex SHA-256 of the SQLite blob (never uuid).
pub const INDEX_ID_HEX_LEN: usize = 64;

/// Number of `{archive}.index.{id}.sqlite` pins kept when a pointer is written
/// (current pin + previous when `K=2`). V-2a-only installs stay K=1 (no extra copy).
pub const INDEX_POINTER_KEEP_LAST: usize = 2;

/// Immutable snapshot pointer (`{archive}.index.ptr`). Additional discovery candidate;
/// the well-known `{archive}.index.sqlite` stays a real 0.7.x SQLite blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexPointer {
    pub schema: String,
    /// Lowercase hex SHA-256 of the SQLite blob — 64 hex, never uuid.
    pub index_id: String,
    /// Identical to [`Self::index_id`].
    pub etag_sha256: String,
    /// RFC 3339 UTC timestamp.
    pub generated_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive_tarstats: Option<serde_json::Value>,
}

impl IndexPointer {
    /// Fingerprint `blob` (streaming SHA-256) and optional archive tarstats.
    pub fn for_blob(blob: &Path, archive: Option<&Path>) -> Result<Self> {
        let index_id = sha256_file_hex(blob)?;
        let archive_tarstats = match archive {
            Some(p) if p.is_file() => match tar_stats_from_path(p) {
                Ok(stats) => serde_json::from_str(&serialize_tarstats(&stats)).ok(),
                Err(e) => {
                    warn!(
                        "index pointer: could not fingerprint archive {}: {e}",
                        p.display()
                    );
                    None
                }
            },
            _ => None,
        };
        Ok(Self {
            schema: INDEX_POINTER_SCHEMA.to_string(),
            etag_sha256: index_id.clone(),
            index_id,
            generated_at: rfc3339_utc_now(),
            archive_tarstats,
        })
    }

    /// Schema + 64-hex `index_id` (path-escape / uuid rejected).
    pub fn validate(&self) -> Result<()> {
        if self.schema != INDEX_POINTER_SCHEMA {
            return Err(IndexError::Invalid(format!(
                "index pointer schema {:?} (expected {INDEX_POINTER_SCHEMA})",
                self.schema
            )));
        }
        let id = parse_index_id(&self.index_id)?;
        let etag = parse_index_id(&self.etag_sha256)?;
        if id != etag {
            return Err(IndexError::Invalid(
                "index pointer etag_sha256 must equal index_id".into(),
            ));
        }
        Ok(())
    }

    /// Parsed archive fingerprint when present and well-formed.
    pub fn tarstats(&self) -> Option<TarStats> {
        let v = self.archive_tarstats.as_ref()?;
        parse_tarstats_json(&v.to_string()).ok()
    }
}

/// `{archive}.index.ptr` (sibling of `{archive}.index.sqlite`, not `{well_known}.ptr`).
pub fn index_pointer_path(archive: &Path) -> PathBuf {
    let mut s = archive.as_os_str().to_os_string();
    s.push(".index.ptr");
    PathBuf::from(s)
}

/// Treat `index_file` as `{base}.index.sqlite` when it uses that suffix.
pub fn archive_base_from_index_path(index_file: &Path) -> PathBuf {
    let s = index_file.as_os_str().to_string_lossy();
    match s.strip_suffix(".index.sqlite") {
        Some(base) => PathBuf::from(base),
        None => index_file.to_path_buf(),
    }
}

/// Pointer sibling of an index blob (`foo.index.sqlite` → `foo.index.ptr`).
pub fn index_pointer_path_for_index_file(index_file: &Path) -> PathBuf {
    index_pointer_path(&archive_base_from_index_path(index_file))
}

/// `{archive}.index.{64hex}.sqlite`. Rejects uuid / path-escape (`index_id` must be 64 hex).
pub fn index_id_path(archive: &Path, index_id: &str) -> Result<PathBuf> {
    let id = parse_index_id(index_id)?;
    let mut s = archive.as_os_str().to_os_string();
    s.push(".index.");
    s.push(id.as_str());
    s.push(".sqlite");
    Ok(PathBuf::from(s))
}

/// Lowercase 64-hex SHA-256 id. Rejects uuid and path components.
pub fn parse_index_id(s: &str) -> Result<String> {
    let t = s.trim().to_ascii_lowercase();
    if t.len() != INDEX_ID_HEX_LEN || !t.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(IndexError::Invalid(format!(
            "index_id must be {INDEX_ID_HEX_LEN} lowercase hex sha256(blob), not {s:?}"
        )));
    }
    Ok(t)
}

/// Parse pointer JSON (remote GET body). Schema / id mismatch → `Err`.
pub fn parse_index_pointer_json(s: &str) -> Result<IndexPointer> {
    let ptr: IndexPointer =
        serde_json::from_str(s).map_err(|e| IndexError::Invalid(format!("index pointer: {e}")))?;
    ptr.validate()?;
    Ok(ptr)
}

/// Load `{archive}.index.ptr`. Missing file → `Ok(None)`. Invalid schema / id → `Err`.
pub fn load_index_pointer(path: &Path) -> Result<Option<IndexPointer>> {
    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let mut s = String::new();
    f.read_to_string(&mut s)?;
    parse_index_pointer_json(&s)
        .map(Some)
        .map_err(|e| IndexError::Invalid(format!("index pointer {}: {e}", path.display())))
}

/// Atomically replace `path` with pretty-printed pointer JSON (tmp + rename).
pub fn store_index_pointer_atomic(path: &Path, ptr: &IndexPointer) -> Result<()> {
    ptr.validate()?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let json = serde_json::to_vec_pretty(ptr)
        .map_err(|e| IndexError::Invalid(format!("serialize index pointer: {e}")))?;
    let mut builder = tempfile::Builder::new();
    builder.prefix(".ratarmount-index-ptr-").suffix(".tmp");
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    let mut tmp = match parent {
        Some(p) => builder.tempfile_in(p)?,
        None => builder.tempfile_in(".")?,
    };
    tmp.write_all(&json)?;
    tmp.write_all(b"\n")?;
    tmp.flush()?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| IndexError::Io(e.error))?;
    Ok(())
}

/// Resolve `--index-id HEX` to a local SQLite path.
///
/// Snapshot `{archive}.index.{id}.sqlite` and the well-known sidecar are accepted
/// only when their **streaming** SHA-256 equals `id`. A stale pointer that still
/// names `id` after `-c` replaced well-known is **not** enough — missing snapshot
/// is unknown id (exit 2), not a silent well-known bind of generation N+1.
pub fn resolve_index_id_path(archive: &Path, index_id: &str) -> Result<PathBuf> {
    let id = parse_index_id(index_id)?;
    let snapshot = index_id_path(archive, &id)?;
    if path_is_usable_existing_index(&snapshot) {
        let got = sha256_file_hex(&snapshot)?;
        if got == id {
            return Ok(snapshot);
        }
        return Err(IndexError::Invalid(format!(
            "index snapshot {} sha256 {got} != requested {id}",
            snapshot.display()
        )));
    }
    let well_known = default_index_path(archive);
    if path_is_usable_existing_index(&well_known) {
        let got = sha256_file_hex(&well_known)?;
        if got == id {
            return Ok(well_known);
        }
    }
    Err(IndexError::Invalid(format!(
        "unknown index_id {id} (no matching {} and well-known is not that blob)",
        snapshot.display()
    )))
}

/// Resolve `--index-id` and refuse when stored tarstats no longer match `archive`.
pub fn bind_local_index_id(archive: &Path, index_id: &str) -> Result<PathBuf> {
    let path = resolve_index_id_path(archive, index_id)?;
    let idx = crate::SqliteIndex::open_read_only(&path)?;
    idx.check_tarstats_matches_archive(archive)?;
    Ok(path)
}

/// Hardlink (else atomic copy) `well_known` to `{archive}.index.{id}.sqlite`.
///
/// `id` is the already-known pin name (pointer `index_id` / sha256 of the blob
/// being published) — this does **not** invent an id by hashing a sidecar on `-c`.
/// An existing dest whose streaming SHA-256 is not `id` is replaced (leftover
/// nonempty truncated file is not success). Copy uses tmp+rename.
pub fn snapshot_index_id(archive: &Path, well_known: &Path, id: &str) -> Result<Option<PathBuf>> {
    let id = match parse_index_id(id) {
        Ok(id) => id,
        Err(_) => return Ok(None),
    };
    if !path_is_usable_existing_index(well_known) {
        return Ok(None);
    }
    let dest = index_id_path(archive, &id)?;
    if dest == well_known {
        return Ok(None);
    }
    if path_is_usable_existing_index(&dest) {
        let got = sha256_file_hex(&dest)?;
        if got == id {
            return Ok(Some(dest));
        }
    }
    if let Some(parent) = dest.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    match std::fs::hard_link(well_known, &dest) {
        Ok(()) => Ok(Some(dest)),
        Err(_) => {
            atomic_copy_file(well_known, &dest)?;
            let got = sha256_file_hex(&dest)?;
            if got != id {
                let _ = std::fs::remove_file(&dest);
                return Err(IndexError::Invalid(format!(
                    "index snapshot {} sha256 {got} != {id} after copy",
                    dest.display()
                )));
            }
            Ok(Some(dest))
        }
    }
}

/// Unlink `{archive}.index.{hex}.sqlite` pins not in `keep_ids` (capped at
/// [`INDEX_POINTER_KEEP_LAST`], first ids win).
pub fn prune_index_snapshots(archive: &Path, keep_ids: &[&str]) -> Result<()> {
    let mut keep = Vec::new();
    for s in keep_ids {
        if let Ok(id) = parse_index_id(s) {
            if !keep.contains(&id) {
                keep.push(id);
            }
        }
        if keep.len() >= INDEX_POINTER_KEEP_LAST {
            break;
        }
    }
    for (id, path) in list_index_id_snapshots(archive) {
        if !keep.contains(&id) {
            let _ = std::fs::remove_file(&path);
        }
    }
    Ok(())
}

/// Write a new pointer for `blob` and pin `{archive}.index.{new_id}.sqlite`
/// (hardlink of `blob` after it holds the published bytes). Keep-last-K uses
/// [`INDEX_POINTER_KEEP_LAST`] (current pin + previous pointer id).
pub fn publish_index_pointer(
    archive: &Path,
    blob: &Path,
    tarstats_archive: Option<&Path>,
) -> Result<IndexPointer> {
    let ptr_path = index_pointer_path(archive);
    let new_id = sha256_file_hex(blob)?;
    let old_id = match load_index_pointer(&ptr_path) {
        Ok(Some(old)) => parse_index_id(&old.index_id).ok(),
        Ok(None) => None,
        Err(e) => {
            warn!("ignoring invalid index pointer {}: {e}", ptr_path.display());
            None
        }
    };
    snapshot_index_id(archive, blob, &new_id)?;
    let mut keep: Vec<&str> = vec![new_id.as_str()];
    if let Some(ref old) = old_id {
        if old.as_str() != new_id.as_str() {
            keep.push(old.as_str());
        }
    }
    prune_index_snapshots(archive, &keep)?;
    let ptr = IndexPointer::for_blob(blob, tarstats_archive)?;
    store_index_pointer_atomic(&ptr_path, &ptr)?;
    Ok(ptr)
}

fn atomic_copy_file(src: &Path, dest: &Path) -> Result<()> {
    if let Some(parent) = dest.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut builder = tempfile::Builder::new();
    builder.prefix(".ratarmount-index-snap-").suffix(".tmp");
    let parent = dest.parent().filter(|p| !p.as_os_str().is_empty());
    let mut tmp = match parent {
        Some(p) => builder.tempfile_in(p)?,
        None => builder.tempfile_in(".")?,
    };
    {
        let mut in_f = File::open(src)?;
        std::io::copy(&mut in_f, &mut tmp)?;
        tmp.flush()?;
        tmp.as_file().sync_all()?;
    }
    tmp.persist(dest).map_err(|e| IndexError::Io(e.error))?;
    Ok(())
}

fn sha256_file_hex(path: &Path) -> Result<String> {
    let mut f = File::open(path)?;
    crate::hashing::sha256_hex_stream(&mut f).map_err(IndexError::from)
}

fn list_index_id_snapshots(archive: &Path) -> Vec<(String, PathBuf)> {
    let parent = match archive.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let Some(name) = archive.file_name() else {
        return Vec::new();
    };
    let prefix = format!("{}.index.", name.to_string_lossy());
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(&parent) else {
        return out;
    };
    for ent in entries.flatten() {
        let fname = ent.file_name();
        let fname = fname.to_string_lossy();
        let Some(rest) = fname.strip_prefix(&prefix) else {
            continue;
        };
        let Some(hex) = rest.strip_suffix(".sqlite") else {
            continue;
        };
        if parse_index_id(hex).is_ok() {
            out.push((hex.to_ascii_lowercase(), parent.join(ent.file_name())));
        }
    }
    out
}

fn rfc3339_utc_now() -> String {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format_rfc3339_utc(dur.as_secs())
}

/// Civil date from Unix day count (Howard Hinnant `civil_from_days`).
fn format_rfc3339_utc(unix_secs: u64) -> String {
    let days = (unix_secs / 86_400) as i64;
    let tod = unix_secs % 86_400;
    let hour = tod / 3600;
    let min = (tod % 3600) / 60;
    let sec = tod % 60;
    let (y, m, d) = civil_from_unix_days(days);
    format!("{y:04}-{m:02}-{d:02}T{hour:02}:{min:02}:{sec:02}Z")
}

fn civil_from_unix_days(days: i64) -> (i32, u8, u8) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m as u8, d as u8)
}

/// Compressed sidecar suffixes tried after `{url}.index.sqlite`.
const SIBLING_COMPRESSED_SUFFIXES: &[&str] = &[".gz", ".zst", ".xz", ".bz2"];

const USER_AGENT: &str = "ratarmount-rs/0.1";

/// Default folder list matching Python CLI:
/// `["", $XDG_CACHE_HOME/ratarmount, ~/.ratarmount]` (empty = next to archive).
pub fn default_index_folders() -> Vec<PathBuf> {
    let mut folders = vec![PathBuf::new()]; // next to archive
    if let Some(xdg) = xdg_cache_home() {
        let p = xdg.join("ratarmount");
        if p.parent().map(|par| par.is_dir()).unwrap_or(false) || xdg.is_dir() {
            folders.push(p);
        }
    }
    folders.push(expand_user(Path::new("~/.ratarmount")));
    folders
}

/// Parse `--index-folders` value: JSON list, comma-separated, or single path.
/// Empty string entries mean "next to the archive".
pub fn parse_index_folders(s: &str) -> Vec<PathBuf> {
    let s = s.trim();
    if s.is_empty() {
        return vec![PathBuf::new()];
    }
    if s.starts_with('[') {
        if let Ok(v) = serde_json::from_str::<Vec<String>>(s) {
            return v.into_iter().map(|x| expand_user(Path::new(&x))).collect();
        }
    }
    if s.contains(',') {
        return s
            .split(',')
            .map(|part| {
                let part = part.trim();
                if part.is_empty() {
                    PathBuf::new()
                } else {
                    expand_user(Path::new(part))
                }
            })
            .collect();
    }
    vec![expand_user(Path::new(s))]
}

/// Expand `~` / `~/…` like Python `os.path.expanduser`.
pub fn expand_user(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    if s == "~" {
        if let Some(home) = home_dir() {
            return home;
        }
    } else if let Some(rest) = s.strip_prefix("~/") {
        if let Some(home) = home_dir() {
            return home.join(rest);
        }
    }
    path.to_path_buf()
}

fn home_dir() -> Option<PathBuf> {
    home_dir_from(
        std::env::var_os("HOME").as_deref(),
        std::env::var_os("USERPROFILE").as_deref(),
        std::env::var_os("HOMEDRIVE").as_deref(),
        std::env::var_os("HOMEPATH").as_deref(),
    )
}

/// `HOME`, else `USERPROFILE`, else `HOMEDRIVE`+`HOMEPATH`. Empty values skip.
///
/// WHY: Windows has no `HOME` by default. `meta-v3` still uses
/// [`xdg_cache_home`] (`$HOME/.cache`); do not migrate to Library/Caches.
fn home_dir_from(
    home: Option<&std::ffi::OsStr>,
    userprofile: Option<&std::ffi::OsStr>,
    homedrive: Option<&std::ffi::OsStr>,
    homepath: Option<&std::ffi::OsStr>,
) -> Option<PathBuf> {
    if let Some(h) = home {
        if !h.is_empty() {
            return Some(PathBuf::from(h));
        }
    }
    if let Some(h) = userprofile {
        if !h.is_empty() {
            return Some(PathBuf::from(h));
        }
    }
    match (homedrive, homepath) {
        (Some(d), Some(p)) if !d.is_empty() && !p.is_empty() => {
            let mut s = d.to_os_string();
            s.push(p);
            Some(PathBuf::from(s))
        }
        _ => None,
    }
}

fn xdg_cache_home() -> Option<PathBuf> {
    if let Some(x) = std::env::var_os("XDG_CACHE_HOME") {
        if !x.is_empty() {
            return Some(PathBuf::from(x));
        }
    }
    home_dir().map(|h| h.join(".cache"))
}

/// Default on-disk index path next to the archive (`archive + ".index.sqlite"`).
pub fn default_index_path(archive: &Path) -> PathBuf {
    let mut s = archive.as_os_str().to_os_string();
    s.push(".index.sqlite");
    PathBuf::from(s)
}

/// Candidate index paths for an archive given folder list (Python semantics).
///
/// - Empty folder → `archive.index.sqlite` next to the archive.
/// - Non-empty folder → `folder / (archive_path with '/' replaced by '_')`.
pub fn possible_index_paths(archive: &Path, folders: &[PathBuf]) -> Vec<PathBuf> {
    let default = default_index_path(archive);
    if folders.is_empty() {
        return vec![default];
    }
    let archive_s = archive.to_string_lossy();
    let index_as_name = format!("{archive_s}.index.sqlite").replace('/', "_");
    let mut out = Vec::new();
    for folder in folders {
        if folder.as_os_str().is_empty() {
            out.push(default.clone());
        } else {
            out.push(folder.join(&index_as_name));
        }
    }
    out
}

/// True if `s` is an absolute `http(s)://` or `file://` URL suitable as an index path.
pub fn is_index_url(s: &str) -> bool {
    let s = s.trim();
    s.starts_with("http://") || s.starts_with("https://") || s.starts_with("file://")
}

/// Sibling index URL convention for a remote archive: `archive_url + ".index.sqlite"`.
///
/// Returns `None` when `archive_url` is not `http(s)://`. Object-store well-known
/// keys use [`object_store_sibling_index_candidates`]. Compressed suffixes are
/// listed by [`sibling_index_candidates`].
pub fn sibling_index_url(archive_url: &str) -> Option<String> {
    let s = archive_url.trim();
    if s.starts_with("http://") || s.starts_with("https://") {
        Some(format!("{s}.index.sqlite"))
    } else {
        None
    }
}

fn with_compressed_suffixes(base: String) -> Vec<String> {
    let mut out = Vec::with_capacity(1 + SIBLING_COMPRESSED_SUFFIXES.len());
    out.push(base.clone());
    for suf in SIBLING_COMPRESSED_SUFFIXES {
        out.push(format!("{base}{suf}"));
    }
    out
}

fn remote_index_sibling_url(s: &str) -> bool {
    s.starts_with("http://")
        || s.starts_with("https://")
        || s.starts_with("s3://")
        || s.starts_with("gs://")
        || s.starts_with("az://")
        || s.starts_with("azure://")
}

/// `{archive_url}.index.ptr` for http(s) and S3/GCS/Azure. Additional candidate
/// (not a replacement for the well-known SQLite blob).
pub fn sibling_index_pointer_url(archive_url: &str) -> Option<String> {
    let s = archive_url.trim();
    if remote_index_sibling_url(s) {
        Some(format!("{s}.index.ptr"))
    } else {
        None
    }
}

/// `{archive_url}.index.{64hex}.sqlite`. Rejects uuid / path-escape ids.
pub fn sibling_index_id_url(archive_url: &str, index_id: &str) -> Option<String> {
    let id = parse_index_id(index_id).ok()?;
    let s = archive_url.trim();
    if remote_index_sibling_url(s) {
        Some(format!("{s}.index.{id}.sqlite"))
    } else {
        None
    }
}

/// Immutable blob URL then `.gz` / `.zst` / `.xz` / `.bz2`.
pub fn sibling_index_id_candidates(archive_url: &str, index_id: &str) -> Vec<String> {
    match sibling_index_id_url(archive_url, index_id) {
        Some(base) => with_compressed_suffixes(base),
        None => Vec::new(),
    }
}

/// http(s) sibling index URLs: uncompressed [`sibling_index_url`] then `.gz` /
/// `.zst` / `.xz` / `.bz2`. Empty for `s3://`, `file://`, and local paths.
pub fn sibling_index_candidates(archive_url: &str) -> Vec<String> {
    let Some(base) = sibling_index_url(archive_url) else {
        return Vec::new();
    };
    with_compressed_suffixes(base)
}

/// Well-known `{url}.index.sqlite` (+ compressed) for S3/GCS/Azure. Empty for
/// http(s) (those use [`sibling_index_candidates`]) and local paths.
pub fn object_store_sibling_index_candidates(archive_url: &str) -> Vec<String> {
    let s = archive_url.trim();
    if !(s.starts_with("s3://")
        || s.starts_with("gs://")
        || s.starts_with("az://")
        || s.starts_with("azure://"))
    {
        return Vec::new();
    }
    with_compressed_suffixes(format!("{s}.index.sqlite"))
}

/// Parse RFC 8288 `Link` header value(s) from HEAD of an **archive** URL.
///
/// Returns the first http(s) target whose `rel` includes [`INDEX_LINK_REL`]
/// (`describedby`). When several describedby links exist, a matching
/// [`INDEX_MEDIA_TYPE`] `type` parameter is preferred. Relative targets are
/// resolved against `archive_url`. Non-http(s) targets (including `s3://`) are
/// ignored.
pub fn parse_link_describedby(link_header: &str, archive_url: &str) -> Option<String> {
    let mut typed = None;
    let mut untyped = None;
    for (target, params) in parse_rfc8288_link_values(link_header) {
        if !rel_includes_describedby(&params) {
            continue;
        }
        let Some(url) = resolve_http_index_url(archive_url, &target) else {
            continue;
        };
        if type_is_index_media(&params) {
            if typed.is_none() {
                typed = Some(url);
            }
        } else if untyped.is_none() {
            untyped = Some(url);
        }
    }
    typed.or(untyped)
}

fn rel_includes_describedby(params: &[(String, String)]) -> bool {
    params.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("rel")
            && v.split_whitespace()
                .any(|r| r.eq_ignore_ascii_case(INDEX_LINK_REL))
    })
}

fn type_is_index_media(params: &[(String, String)]) -> bool {
    params.iter().any(|(k, v)| {
        if !k.eq_ignore_ascii_case("type") {
            return false;
        }
        let got = v.split(';').next().unwrap_or(v).trim();
        got.eq_ignore_ascii_case(INDEX_MEDIA_TYPE)
    })
}

/// Split a `Link` header into `(uri-reference, params)` pairs (RFC 8288).
fn parse_rfc8288_link_values(header: &str) -> Vec<(String, Vec<(String, String)>)> {
    let mut out = Vec::new();
    for raw in split_on_top_level(header, b',') {
        let raw = raw.trim();
        if raw.is_empty() || !raw.starts_with('<') {
            continue;
        }
        let Some(end) = raw.find('>') else {
            continue;
        };
        let target = raw[1..end].trim().to_string();
        if target.is_empty() {
            continue;
        }
        let params = parse_link_params(raw[end + 1..].trim());
        out.push((target, params));
    }
    out
}

fn parse_link_params(s: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let s = s.trim_start_matches(';').trim();
    if s.is_empty() {
        return out;
    }
    for part in split_on_top_level(s, b';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some(pair) = split_link_param(part) {
            out.push(pair);
        }
    }
    out
}

fn split_link_param(part: &str) -> Option<(String, String)> {
    let mut in_quotes = false;
    let mut escape = false;
    let mut eq = None;
    for (i, b) in part.bytes().enumerate() {
        if escape {
            escape = false;
            continue;
        }
        if in_quotes {
            if b == b'\\' {
                escape = true;
            } else if b == b'"' {
                in_quotes = false;
            }
            continue;
        }
        if b == b'"' {
            in_quotes = true;
            continue;
        }
        if b == b'=' {
            eq = Some(i);
            break;
        }
    }
    let eq = eq?;
    let key = part[..eq].trim();
    if key.is_empty() {
        return None;
    }
    Some((
        key.to_string(),
        unquote_quoted_string(part[eq + 1..].trim()),
    ))
}

fn unquote_quoted_string(s: &str) -> String {
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        let inner = &s[1..s.len() - 1];
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                if let Some(n) = chars.next() {
                    out.push(n);
                }
            } else {
                out.push(c);
            }
        }
        out
    } else {
        s.to_string()
    }
}

/// Split `s` on `delim` not inside quoted-strings or `<angle>` URI refs.
fn split_on_top_level(s: &str, delim: u8) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut in_quotes = false;
    let mut in_angles = false;
    let mut escape = false;
    for (i, b) in s.bytes().enumerate() {
        if escape {
            escape = false;
            continue;
        }
        if in_quotes {
            if b == b'\\' {
                escape = true;
            } else if b == b'"' {
                in_quotes = false;
            }
            continue;
        }
        match b {
            b'"' if !in_angles => in_quotes = true,
            b'<' if !in_quotes => in_angles = true,
            b'>' if in_angles => in_angles = false,
            d if d == delim && !in_angles => {
                parts.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&s[start..]);
    parts
}

fn strip_url_fragment(s: &str) -> &str {
    s.split_once('#').map(|(b, _)| b).unwrap_or(s)
}

/// Resolve `target` against an http(s) `archive_url`. Other schemes return `None`.
fn resolve_http_index_url(archive_url: &str, target: &str) -> Option<String> {
    let target = strip_url_fragment(target.trim());
    if target.is_empty() {
        return None;
    }
    if target.starts_with("http://") || target.starts_with("https://") {
        return Some(target.to_string());
    }
    if target.contains("://") {
        return None;
    }
    let base = strip_url_fragment(archive_url.trim());
    if !(base.starts_with("http://") || base.starts_with("https://")) {
        return None;
    }
    if let Some(rest) = target.strip_prefix("//") {
        let scheme = if base.starts_with("https://") {
            "https:"
        } else {
            "http:"
        };
        return Some(format!("{scheme}//{rest}"));
    }
    let (origin, path) = http_origin_and_path(base)?;
    if target.starts_with('/') {
        return Some(format!("{origin}{target}"));
    }
    let dir = match path.rfind('/') {
        Some(i) => &path[..=i],
        None => "/",
    };
    Some(format!("{origin}{dir}{target}"))
}

fn http_origin_and_path(base: &str) -> Option<(&str, &str)> {
    let scheme_len = if base.starts_with("https://") {
        8
    } else if base.starts_with("http://") {
        7
    } else {
        return None;
    };
    let after = &base[scheme_len..];
    let host_len = after
        .find('/')
        .or_else(|| after.find('?'))
        .unwrap_or(after.len());
    let origin = &base[..scheme_len + host_len];
    let rest = &after[host_len..];
    let path = rest.split_once('?').map(|(p, _)| p).unwrap_or(rest);
    Some((origin, path))
}

/// Materialize an index path or URL to a local filesystem path ready for SQLite open.
///
/// * Local paths and `file://` → expanded local path (no copy unless compressed).
/// * `http(s)://` → download into a kept tempfile (dir: `RATARMOUNT_INDEX_TMPDIR` if set).
/// * Compressed indexes (gzip/xz/zstd/bzip2) → decompress into a kept tempfile with a real
///   SQLite header (Python `SQLiteIndex._load_index` / `_undo_compression`).
pub fn maybe_fetch_index_url(index_spec: &str) -> Result<PathBuf> {
    let s = index_spec.trim();
    if s.is_empty() {
        return Err(IndexError::Invalid("empty index path".into()));
    }

    // Python strips a single `file://` prefix when `count('://') == 1`.
    let (local, http_url) = if let Some(rest) = s.strip_prefix("file://") {
        let p = if !rest.contains("://") {
            expand_user(Path::new(rest))
        } else {
            // Chained URL not supported without fsspec; treat as opaque local-ish path.
            expand_user(Path::new(s))
        };
        (p, None)
    } else if s.starts_with("http://") || s.starts_with("https://") {
        (fetch_index_http(s)?, Some(s))
    } else {
        // Non-URL local path (including Windows-ish schemes we do not handle specially).
        (expand_user(Path::new(s)), None)
    };

    match materialize_index_file(&local) {
        Ok(p) => Ok(p),
        Err(err) => {
            if let Some(url) = http_url {
                crate::invalidate_meta_cache_identity("http", url);
            }
            Err(err)
        }
    }
}

/// Ensure `path` is an on-disk SQLite index file, decompressing if needed.
///
/// * Already uncompressed (or non-existent / empty) → returned unchanged.
/// * gzip (`.gz` / `1f 8b`), xz (`.xz`), zstd (`.zst`/`.zstd`), bzip2 (`.bz2`) → decompressed
///   into a kept tempfile under `RATARMOUNT_INDEX_TMPDIR` when set.
///
/// Errors if compression is detected but decompression fails, or the decompressed payload
/// does not start with the SQLite magic (`SQLite format 3\0`).
pub fn materialize_index_file(path: &Path) -> Result<PathBuf> {
    let meta = match std::fs::metadata(path) {
        Ok(m) if m.is_file() && m.len() > 0 => m,
        // Missing / empty / non-file: pass through (create path or later open will fail).
        _ => return Ok(path.to_path_buf()),
    };

    let mut header = [0u8; 16];
    let n = {
        let mut f = File::open(path)?;
        f.read(&mut header)?
    };
    let header = &header[..n];

    // Uncompressed SQLite: open as-is.
    if header.starts_with(SQLITE_MAGIC) {
        return Ok(path.to_path_buf());
    }

    let Some(fmt) = detect_index_compression(path, header) else {
        // Unknown / plain non-SQLite blob — leave validation to SQLite open.
        return Ok(path.to_path_buf());
    };

    debug!(
        "detected {}-compressed index {} ({} bytes); decompressing",
        fmt.name(),
        path.display(),
        meta.len()
    );
    decompress_index_to_temp(path, fmt)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IndexCompression {
    Gzip,
    Xz,
    Zstd,
    Bzip2,
}

impl IndexCompression {
    fn name(self) -> &'static str {
        match self {
            Self::Gzip => "gzip",
            Self::Xz => "xz",
            Self::Zstd => "zstd",
            Self::Bzip2 => "bzip2",
        }
    }
}

/// Detect compressed index by file magic, falling back to well-known suffixes.
fn detect_index_compression(path: &Path, header: &[u8]) -> Option<IndexCompression> {
    if header.starts_with(GZIP_MAGIC) {
        return Some(IndexCompression::Gzip);
    }
    if header.len() >= XZ_MAGIC.len() && header.starts_with(XZ_MAGIC) {
        return Some(IndexCompression::Xz);
    }
    if header.len() >= ZSTD_MAGIC.len() && header.starts_with(ZSTD_MAGIC) {
        return Some(IndexCompression::Zstd);
    }
    if header.len() >= BZIP2_MAGIC.len() && header.starts_with(BZIP2_MAGIC) {
        return Some(IndexCompression::Bzip2);
    }

    // Suffix fallback (case-insensitive), for incomplete/odd producers.
    let name = path.file_name()?.to_string_lossy();
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".gz") {
        return Some(IndexCompression::Gzip);
    }
    if lower.ends_with(".xz") {
        return Some(IndexCompression::Xz);
    }
    if lower.ends_with(".zst") || lower.ends_with(".zstd") {
        return Some(IndexCompression::Zstd);
    }
    if lower.ends_with(".bz2") {
        return Some(IndexCompression::Bzip2);
    }
    None
}

fn decompress_index_to_temp(path: &Path, fmt: IndexCompression) -> Result<PathBuf> {
    let input = File::open(path).map_err(|e| {
        IndexError::Invalid(format!(
            "cannot open {}-compressed index {}: {e}",
            fmt.name(),
            path.display()
        ))
    })?;

    let mut reader: Box<dyn Read> = match fmt {
        IndexCompression::Gzip => Box::new(flate2::read::GzDecoder::new(input)),
        IndexCompression::Xz => Box::new(xz2::read::XzDecoder::new(input)),
        IndexCompression::Zstd => {
            let dec = zstd::stream::read::Decoder::new(input).map_err(|e| {
                IndexError::Invalid(format!(
                    "cannot create zstd decoder for {}: {e}",
                    path.display()
                ))
            })?;
            Box::new(dec)
        }
        IndexCompression::Bzip2 => Box::new(bzip2::read::BzDecoder::new(input)),
    };

    let mut builder = tempfile::Builder::new();
    builder
        .prefix("ratarmount-index-")
        .suffix(".tmp.sqlite.index");
    let mut tmp = if let Some(dir) = index_temp_dir() {
        std::fs::create_dir_all(&dir)?;
        builder.tempfile_in(&dir)?
    } else {
        builder.tempfile()?
    };

    let n = std::io::copy(&mut reader, &mut tmp).map_err(|e| {
        IndexError::Invalid(format!(
            "failed to decompress {}-compressed index {}: {e}",
            fmt.name(),
            path.display()
        ))
    })?;
    tmp.flush()?;

    // Verify SQLite magic on the decompressed payload.
    tmp.seek(SeekFrom::Start(0))?;
    let mut magic = [0u8; 16];
    let got = tmp.read(&mut magic).unwrap_or(0);
    if got < SQLITE_MAGIC.len() || !magic[..SQLITE_MAGIC.len()].starts_with(SQLITE_MAGIC) {
        // Drop tempfile on scope exit (not kept) so a bad decompress does not litter.
        return Err(IndexError::Invalid(format!(
            "decompressed {}-compressed index {} is not a SQLite database (missing '{}…' header, {} bytes)",
            fmt.name(),
            path.display(),
            String::from_utf8_lossy(&SQLITE_MAGIC[..15]),
            n
        )));
    }

    let out = tmp
        .into_temp_path()
        .keep()
        .map_err(|e| IndexError::Io(e.error))?;
    debug!(
        "decompressed {}-compressed index {} -> {} ({} bytes)",
        fmt.name(),
        path.display(),
        out.display(),
        n
    );
    Ok(out)
}

fn index_temp_dir() -> Option<PathBuf> {
    std::env::var_os("RATARMOUNT_INDEX_TMPDIR")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// Whole-GET a sidecar URL through the V-3 XDG LRU (URL-first).
/// Pointer etag revalidation is `MetaCache` API; V-2b wires it from `.ptr`.
fn fetch_index_http(url: &str) -> Result<PathBuf> {
    let cache = crate::MetaCache::from_env();
    let identity = crate::cache_identity("http", url);
    cache.get_or_fetch_path_with_etag(&identity, None, || fetch_index_http_uncached(url))
}

fn fetch_index_http_uncached(url: &str) -> Result<(PathBuf, Option<String>)> {
    debug!("fetching remote index from {url}");
    let resp = ureq::get(url)
        .set("User-Agent", USER_AGENT)
        .call()
        .map_err(|e| IndexError::Remote(e.to_string()))?;
    let status = resp.status();
    if !(200..300).contains(&status) {
        return Err(IndexError::Remote(format!("HTTP {status} for {url}")));
    }
    let etag = resp
        .header("ETag")
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let mut builder = tempfile::Builder::new();
    builder
        .prefix("ratarmount-index-")
        .suffix(".tmp.sqlite.index");
    let mut tmp = if let Some(dir) = index_temp_dir() {
        std::fs::create_dir_all(&dir)?;
        builder.tempfile_in(&dir)?
    } else {
        builder.tempfile()?
    };

    let mut reader = resp.into_reader();
    let n = std::io::copy(&mut reader, &mut tmp)?;
    tmp.flush()?;
    let path = tmp
        .into_temp_path()
        .keep()
        .map_err(|e| IndexError::Io(e.error))?;
    debug!("remote index {url} -> {} ({n} bytes)", path.display());
    Ok((path, etag))
}

/// First usable existing candidate (unless `recreate`), else first creatable path.
///
/// Shared by [`resolve_index_location`] (Python `:memory:` last resort) and
/// session `resolve_index` (Sibling errors instead of memory).
pub fn pick_index_path(archive: &Path, folders: &[PathBuf], recreate: bool) -> Option<PathBuf> {
    let candidates = possible_index_paths(archive, folders);
    if !recreate {
        for p in &candidates {
            if let Some(mp) = try_materialize_existing_index(p) {
                return Some(mp);
            }
        }
    }
    for p in &candidates {
        if path_can_create_index(p) {
            return Some(p.clone());
        }
    }
    None
}

/// True when `path` is a remote archive id (`scheme://…`), not a filesystem path.
///
/// Used so sibling create does not `create_dir_all("https://host")` in cwd.
pub fn looks_like_url_archive(path: &Path) -> bool {
    path.to_string_lossy().contains("://")
}

/// Local sibling sidecars: pointer snapshot then well-known `{archive}.index.sqlite`.
pub fn local_sibling_index_candidates(archive: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let ptr_path = index_pointer_path(archive);
    match load_index_pointer(&ptr_path) {
        Ok(Some(ptr)) => {
            if let Ok(snap) = index_id_path(archive, &ptr.index_id) {
                out.push(snap);
            }
        }
        Ok(None) => {}
        Err(e) => {
            warn!("ignoring invalid index pointer {}: {e}", ptr_path.display());
        }
    }
    out.push(default_index_path(archive));
    out
}

/// Parent directory of the well-known sibling sidecar (`{archive}.index.sqlite`).
pub fn sibling_parent_dir(archive: &Path) -> PathBuf {
    match archive.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// Existing sibling pointer snapshot, well-known sidecar, then extra_dirs files.
/// Never creates directories or probes writability.
pub fn find_existing_sibling_index(archive: &Path, extra_dirs: &[PathBuf]) -> Option<PathBuf> {
    for p in local_sibling_index_candidates(archive) {
        if let Some(mp) = try_materialize_existing_index(&p) {
            return Some(mp);
        }
    }
    let extras: Vec<PathBuf> = extra_dirs
        .iter()
        .filter(|d| !d.as_os_str().is_empty())
        .cloned()
        .collect();
    if extras.is_empty() {
        return None;
    }
    let candidates = possible_index_paths(archive, &extras);
    for p in &candidates {
        if let Some(mp) = try_materialize_existing_index(p) {
            return Some(mp);
        }
    }
    None
}

/// Sibling-policy location: never `:memory:`.
///
/// Existing pointer snapshot, then well-known sidecar, then existing files in
/// non-empty `extra_dirs`. If none exist, return the well-known path when its
/// parent is writable. `scheme://` archives never mkdir; `Err(parent)` so
/// callers can leave the sidecar unbound (remote sibling GET) or map to
/// `SiblingNotWritable`. Does **not** create under `extra_dirs` or `local-index-v1`.
pub fn resolve_sibling_index_location(
    archive: &Path,
    extra_dirs: &[PathBuf],
    recreate: bool,
) -> std::result::Result<IndexLocation, PathBuf> {
    if !recreate {
        if let Some(p) = find_existing_sibling_index(archive, extra_dirs) {
            return Ok(IndexLocation::Path(p));
        }
    }

    // Remote ids are not filesystem parents (`https://host` would mkdir in cwd).
    if looks_like_url_archive(archive) {
        return Err(sibling_parent_dir(archive));
    }

    let well_known = default_index_path(archive);
    if path_can_create_index(&well_known) {
        return Ok(IndexLocation::Path(well_known));
    }
    Err(sibling_parent_dir(archive))
}

/// Resolve where to load/create the index.
///
/// * `explicit` — from `--index-file` (`None`, `":memory:"`, path string, or `http(s)://` / `file://` URL).
/// * `folders` — from `--index-folders` (empty → default folders).
/// * `recreate` — skip loading existing; still prefer a writable path for create.
///
/// Absolute `http(s)://` explicit paths are downloaded to a local tempfile and returned as
/// [`IndexLocation::Path`]. Compressed indexes are decompressed to a kept tempfile. Fetch /
/// decompress failures for an explicit remote URL fall through to folder candidates (Python
/// trial-and-error style) after a warning.
///
/// Local folder candidate order is unchanged (G-2 K12): next-to-archive / `oci:{digest}`
/// cache names stay first among [`possible_index_paths`]. HTTP `Link` / sibling GET /
/// OCI referrers are applied by callers **after** this function on a local miss.
///
/// Last resort is [`IndexLocation::Memory`] (Python/CLI `CliCompat` parity). Session
/// embedders use [`resolve_sibling_index_location`] which errors instead of memory.
pub fn resolve_index_location(
    archive: &Path,
    explicit: Option<&str>,
    folders: &[PathBuf],
    recreate: bool,
) -> IndexLocation {
    if let Some(e) = explicit {
        let e = e.trim();
        if e == MEMORY_INDEX {
            return IndexLocation::Memory;
        }
        if e.is_empty() {
            // fall through to folders
        } else if is_index_url(e) {
            match maybe_fetch_index_url(e) {
                Ok(p) => return IndexLocation::Path(p),
                Err(err) => {
                    warn!("could not materialize index URL {e}: {err}");
                    // fall through to folders
                }
            }
        } else {
            let p = expand_user(Path::new(e));
            match materialize_index_file(&p) {
                Ok(mp) => return IndexLocation::Path(mp),
                Err(err) => {
                    warn!("could not materialize index {}: {err}", p.display());
                    return IndexLocation::Path(p);
                }
            }
        }
    }

    let folders = if folders.is_empty() {
        default_index_folders()
    } else {
        folders.to_vec()
    };
    match pick_index_path(archive, &folders, recreate) {
        Some(p) => IndexLocation::Path(p),
        // Last resort: memory (matches Python when no writable location exists).
        None => IndexLocation::Memory,
    }
}

fn try_materialize_existing_index(path: &Path) -> Option<PathBuf> {
    if !path_is_usable_existing_index(path) {
        return None;
    }
    match materialize_index_file(path) {
        Ok(mp) => Some(mp),
        Err(err) => {
            warn!(
                "could not materialize existing index {}: {err}",
                path.display()
            );
            None
        }
    }
}

/// Non-empty regular file (warm sidecar candidate).
pub fn path_is_usable_existing_index(path: &Path) -> bool {
    match std::fs::metadata(path) {
        Ok(m) => m.is_file() && m.len() > 0,
        Err(_) => false,
    }
}

/// Parent of `path` exists (or can be created) and passes [`test_writable_dir`].
///
/// `scheme://` paths are never created (`https://host` is not a directory).
pub fn path_can_create_index(path: &Path) -> bool {
    if looks_like_url_archive(path) {
        return false;
    }
    if let Some(parent) = path.parent() {
        if looks_like_url_archive(parent) {
            return false;
        }
        if parent.as_os_str().is_empty() {
            // relative path in cwd
            return test_writable_dir(Path::new("."));
        }
        if !parent.exists() && std::fs::create_dir_all(parent).is_err() {
            return false;
        }
        return test_writable_dir(parent);
    }
    test_writable_dir(Path::new("."))
}

/// Probe whether `dir` allows creating a new file (unlink the probe afterwards).
pub fn test_writable_dir(dir: &Path) -> bool {
    let probe = dir.join(format!(".ratarmount-write-test-{}", std::process::id()));
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
    {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;

    #[test]
    fn home_dir_prefers_home_then_userprofile_then_homedrive_path() {
        assert_eq!(
            home_dir_from(
                Some(OsStr::new("/home/u")),
                Some(OsStr::new(r"C:\Users\u")),
                None,
                None
            ),
            Some(PathBuf::from("/home/u"))
        );
        assert_eq!(
            home_dir_from(
                Some(OsStr::new("")),
                Some(OsStr::new(r"C:\Users\u")),
                None,
                None
            ),
            Some(PathBuf::from(r"C:\Users\u"))
        );
        assert_eq!(
            home_dir_from(
                None,
                None,
                Some(OsStr::new("C:")),
                Some(OsStr::new(r"\Users\u"))
            ),
            Some(PathBuf::from(r"C:\Users\u"))
        );
        assert_eq!(home_dir_from(None, None, None, None), None);
        assert_eq!(
            home_dir_from(Some(OsStr::new("")), Some(OsStr::new("")), None, None),
            None
        );
    }

    /// Minimal HTTP/1.1 mock serving a fixed body for GET (and HEAD).
    struct MockHttp {
        base: String,
        _join: Option<thread::JoinHandle<()>>,
        hits: Arc<Mutex<usize>>,
    }

    impl MockHttp {
        fn spawn(body: Vec<u8>) -> Self {
            Self::spawn_with_extra_headers(body, Vec::new())
        }

        fn spawn_with_extra_headers(body: Vec<u8>, extra_headers: Vec<(String, String)>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let hits = Arc::new(Mutex::new(0usize));
            let hits_c = Arc::clone(&hits);
            let join = thread::spawn(move || {
                for stream in listener.incoming().take(32) {
                    let Ok(mut stream) = stream else { continue };
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut request_line = String::new();
                    if reader.read_line(&mut request_line).is_err() {
                        continue;
                    }
                    // Drain headers.
                    loop {
                        let mut line = String::new();
                        if reader.read_line(&mut line).is_err() {
                            break;
                        }
                        if line == "\r\n" || line == "\n" || line.is_empty() {
                            break;
                        }
                    }
                    {
                        *hits_c.lock().unwrap() += 1;
                    }
                    let is_head = request_line.starts_with("HEAD ");
                    let mut header = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n",
                        body.len()
                    );
                    for (k, v) in &extra_headers {
                        header.push_str(k);
                        header.push_str(": ");
                        header.push_str(v);
                        header.push_str("\r\n");
                    }
                    header.push_str("\r\n");
                    let _ = stream.write_all(header.as_bytes());
                    if !is_head {
                        let _ = stream.write_all(&body);
                    }
                }
            });
            Self {
                base,
                _join: Some(join),
                hits,
            }
        }

        fn url(&self, path: &str) -> String {
            format!("{}{}", self.base, path)
        }
    }

    fn with_isolated_xdg<R>(f: impl FnOnce() -> R) -> R {
        let _g = crate::meta_cache::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let old_xdg = std::env::var_os("XDG_CACHE_HOME");
        let old_cap = std::env::var_os(crate::META_CACHE_BYTES_ENV);
        std::env::set_var("XDG_CACHE_HOME", dir.path());
        std::env::remove_var(crate::META_CACHE_BYTES_ENV);
        let r = f();
        match old_xdg {
            Some(v) => std::env::set_var("XDG_CACHE_HOME", v),
            None => std::env::remove_var("XDG_CACHE_HOME"),
        }
        match old_cap {
            Some(v) => std::env::set_var(crate::META_CACHE_BYTES_ENV, v),
            None => std::env::remove_var(crate::META_CACHE_BYTES_ENV),
        }
        r
    }

    #[test]
    fn parse_comma_and_json() {
        let v = parse_index_folders(",~/.foo");
        assert_eq!(v.len(), 2);
        assert!(v[0].as_os_str().is_empty());
        assert!(v[1].ends_with(".foo") || v[1].to_string_lossy().contains(".foo"));

        let v = parse_index_folders(r#"["/tmp/a","/tmp/b"]"#);
        assert_eq!(v, vec![PathBuf::from("/tmp/a"), PathBuf::from("/tmp/b")]);
    }

    #[test]
    fn memory_explicit() {
        let loc = resolve_index_location(Path::new("/tmp/a.tar"), Some(":memory:"), &[], false);
        assert_eq!(loc, IndexLocation::Memory);
    }

    /// Regression: Sibling + unwritable parent + no sidecar → parent path, not `:memory:`.
    #[test]
    fn sibling_not_writable() {
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("not-a-dir");
        std::fs::write(&blocker, b"file").unwrap();
        let archive = blocker.join("a.tar");
        let extra = tempfile::tempdir().unwrap();
        let err = resolve_sibling_index_location(&archive, &[extra.path().to_path_buf()], false)
            .expect_err("unwritable sibling parent must not fall back");
        assert_eq!(err, blocker);
        assert!(pick_index_path(&archive, &[PathBuf::new()], true).is_none());
    }

    /// Regression: CliCompat / Python last resort stays `:memory:` when nothing is writable.
    #[test]
    fn resolve_index_location_unwritable_falls_back_to_memory() {
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("not-a-dir");
        std::fs::write(&blocker, b"file").unwrap();
        let archive = dir.path().join("a.tar");
        std::fs::write(&archive, b"x").unwrap();
        let loc = resolve_index_location(&archive, None, &[blocker], true);
        assert_eq!(loc, IndexLocation::Memory);
    }

    /// Regression: extra_dirs existing sidecar is used when the sibling parent is unwritable.
    #[test]
    fn sibling_existing_extra_dir_used_when_parent_not_writable() {
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("not-a-dir");
        std::fs::write(&blocker, b"file").unwrap();
        let archive = blocker.join("a.tar");
        let extra = tempfile::tempdir().unwrap();
        let extra_dir = extra.path().to_path_buf();
        let cand = possible_index_paths(&archive, std::slice::from_ref(&extra_dir));
        let idx = cand[0].clone();
        if let Some(parent) = idx.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&idx, b"SQLite format 3\0extra").unwrap();
        let loc = resolve_sibling_index_location(&archive, std::slice::from_ref(&extra_dir), false)
            .expect("existing extra_dirs sidecar");
        assert_eq!(loc, IndexLocation::Path(idx));
    }

    /// Regression: `scheme://` sibling create must not mkdir `https:` in cwd.
    #[test]
    fn sibling_url_does_not_mkdir_scheme_dirs() {
        let marker = format!("ratarmount-pr6-{}-mkdir", std::process::id());
        let archive = PathBuf::from(format!("https://{marker}.example.invalid/a.tar"));
        let well_known = default_index_path(&archive);
        assert!(!path_can_create_index(&well_known));
        let err = resolve_sibling_index_location(&archive, &[], true)
            .expect_err("URL sibling is not a local create path");
        assert_eq!(err, sibling_parent_dir(&archive));
        let leaked = Path::new("https:").join(format!("{marker}.example.invalid"));
        assert!(
            !leaked.exists(),
            "must not mkdir URL-shaped parent {}",
            leaked.display()
        );
        assert!(find_existing_sibling_index(&archive, &[]).is_none());
    }

    #[test]
    fn sibling_writable_plans_well_known() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        std::fs::write(&archive, b"x").unwrap();
        let loc = resolve_sibling_index_location(&archive, &[], true).unwrap();
        assert_eq!(loc, IndexLocation::Path(default_index_path(&archive)));
    }

    #[test]
    fn sibling_existing_file_used_when_parent_not_writable() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        std::fs::write(&archive, b"x").unwrap();
        let idx = default_index_path(&archive);
        std::fs::write(&idx, b"SQLite format 3\0existing").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let orig = std::fs::metadata(dir.path()).unwrap().permissions();
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o555)).unwrap();
            let loc = resolve_sibling_index_location(&archive, &[], false);
            let _ = std::fs::set_permissions(dir.path(), orig);
            match loc {
                Ok(IndexLocation::Path(p)) => assert_eq!(p, idx),
                Ok(IndexLocation::Memory) => panic!("existing sibling must not become :memory:"),
                Err(_) => {
                    // Root can still write 0555 dirs; existing file should still win.
                    if test_writable_dir(dir.path()) {
                        eprintln!("skip: parent still writable (root?)");
                    } else {
                        panic!("existing sibling sidecar must be returned");
                    }
                }
            }
        }
        #[cfg(not(unix))]
        {
            let loc = resolve_sibling_index_location(&archive, &[], false).unwrap();
            assert_eq!(loc, IndexLocation::Path(idx));
        }
    }

    #[test]
    fn next_to_archive_default() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        std::fs::write(&archive, b"x").unwrap();
        let loc = resolve_index_location(&archive, None, &[PathBuf::new()], true);
        match loc {
            IndexLocation::Path(p) => {
                assert_eq!(p, default_index_path(&archive));
                assert!(p.to_string_lossy().ends_with("a.tar.index.sqlite"));
            }
            IndexLocation::Memory => panic!("expected path"),
        }
    }

    #[test]
    fn is_index_url_detects_schemes() {
        assert!(is_index_url("http://example.com/a.index.sqlite"));
        assert!(is_index_url("https://example.com/a.index.sqlite"));
        assert!(is_index_url("file:///tmp/a.index.sqlite"));
        assert!(!is_index_url("/tmp/a.index.sqlite"));
        assert!(!is_index_url(":memory:"));
        assert!(!is_index_url("s3://bucket/key"));
    }

    #[test]
    fn sibling_index_url_appends_suffix() {
        assert_eq!(
            sibling_index_url("http://host/path/a.tar"),
            Some("http://host/path/a.tar.index.sqlite".into())
        );
        assert_eq!(
            sibling_index_url("https://host/a.tar.gz"),
            Some("https://host/a.tar.gz.index.sqlite".into())
        );
        assert_eq!(sibling_index_url("/local/a.tar"), None);
        assert_eq!(sibling_index_url("file:///tmp/a.tar"), None);
    }

    #[test]
    fn sibling_index_candidates_http_only_extends_uncompressed() {
        let cands = sibling_index_candidates("http://host/path/a.tar");
        assert_eq!(
            cands[0],
            sibling_index_url("http://host/path/a.tar").unwrap()
        );
        assert_eq!(
            cands,
            vec![
                "http://host/path/a.tar.index.sqlite".to_string(),
                "http://host/path/a.tar.index.sqlite.gz".into(),
                "http://host/path/a.tar.index.sqlite.zst".into(),
                "http://host/path/a.tar.index.sqlite.xz".into(),
                "http://host/path/a.tar.index.sqlite.bz2".into(),
            ]
        );
        assert!(sibling_index_candidates("s3://bucket/key").is_empty());
        assert!(sibling_index_candidates("file:///tmp/a.tar").is_empty());
        assert!(sibling_index_candidates("/local/a.tar").is_empty());
    }

    #[test]
    fn sibling_index_pointer_and_id_urls_http_and_object_store() {
        let id = "a".repeat(INDEX_ID_HEX_LEN);
        assert_eq!(
            sibling_index_pointer_url("http://host/path/a.tar").as_deref(),
            Some("http://host/path/a.tar.index.ptr")
        );
        assert_eq!(
            sibling_index_pointer_url("s3://bucket/key.tar").as_deref(),
            Some("s3://bucket/key.tar.index.ptr")
        );
        assert_eq!(
            sibling_index_pointer_url("gs://b/o.bin").as_deref(),
            Some("gs://b/o.bin.index.ptr")
        );
        assert_eq!(
            sibling_index_pointer_url("az://c/blob").as_deref(),
            Some("az://c/blob.index.ptr")
        );
        assert_eq!(
            sibling_index_pointer_url("azure://c/blob").as_deref(),
            Some("azure://c/blob.index.ptr")
        );
        assert!(sibling_index_pointer_url("/local/a.tar").is_none());
        assert!(sibling_index_pointer_url("file:///tmp/a.tar").is_none());

        assert_eq!(
            sibling_index_id_url("s3://bucket/key.tar", &id),
            Some(format!("s3://bucket/key.tar.index.{id}.sqlite"))
        );
        assert!(sibling_index_id_url("s3://bucket/key.tar", "not-hex").is_none());
        assert!(sibling_index_id_url("s3://bucket/key.tar", "../escape").is_none());
        let cands = sibling_index_id_candidates("https://h/a.tar", &id);
        assert_eq!(cands[0], format!("https://h/a.tar.index.{id}.sqlite"));
        assert!(cands.iter().any(|u| u.ends_with(".sqlite.gz")));

        let store = object_store_sibling_index_candidates("s3://bucket/key.tar");
        assert_eq!(store[0], "s3://bucket/key.tar.index.sqlite");
        assert!(store.iter().any(|u| u.ends_with(".index.sqlite.gz")));
        assert!(object_store_sibling_index_candidates("http://h/a.tar").is_empty());
        assert!(object_store_sibling_index_candidates("/local/a.tar").is_empty());
    }

    #[test]
    fn parse_index_pointer_json_rejects_schema_and_uuid() {
        let err = parse_index_pointer_json("{}").unwrap_err().to_string();
        assert!(err.contains("index pointer"), "{err}");
        let uuid = serde_json::json!({
            "schema": INDEX_POINTER_SCHEMA,
            "index_id": "550e8400-e29b-41d4-a716-446655440000",
            "etag_sha256": "550e8400-e29b-41d4-a716-446655440000",
            "generated_at": "2026-01-01T00:00:00Z",
        });
        assert!(parse_index_pointer_json(&uuid.to_string()).is_err());
        let bad_schema = serde_json::json!({
            "schema": "not.a.pointer",
            "index_id": "a".repeat(INDEX_ID_HEX_LEN),
            "etag_sha256": "a".repeat(INDEX_ID_HEX_LEN),
            "generated_at": "2026-01-01T00:00:00Z",
        });
        let err = parse_index_pointer_json(&bad_schema.to_string())
            .unwrap_err()
            .to_string();
        assert!(err.contains("schema"), "{err}");
    }

    #[test]
    fn possible_index_paths_empty_folder_first_for_oci_digest_label() {
        // K12: local folder candidates are unchanged; empty folder (sidecar /
        // `oci:{digest}` cache name) stays first.
        let archive = Path::new("oci:sha256:deadbeef");
        let paths = possible_index_paths(archive, &[PathBuf::new(), PathBuf::from("/cache")]);
        assert_eq!(paths[0], default_index_path(archive));
        assert!(paths[0].to_string_lossy().starts_with("oci:"));
        assert!(paths[1].starts_with("/cache"));
    }

    #[test]
    fn maybe_fetch_file_url_and_local() {
        let dir = tempfile::tempdir().unwrap();
        let idx = dir.path().join("t.index.sqlite");
        std::fs::write(&idx, b"SQLite format 3\0").unwrap();

        let via_file = maybe_fetch_index_url(&format!("file://{}", idx.display())).unwrap();
        assert_eq!(via_file, idx);

        let via_local = maybe_fetch_index_url(idx.to_str().unwrap()).unwrap();
        assert_eq!(via_local, idx);
    }

    #[test]
    fn maybe_fetch_http_downloads_to_temp() {
        with_isolated_xdg(|| {
            // Fake SQLite header (enough for path materialization tests).
            let body = b"SQLite format 3\0rest-of-fake-index".to_vec();
            let mock = MockHttp::spawn(body.clone());
            let url = mock.url("/archive.tar.index.sqlite");

            let path = maybe_fetch_index_url(&url).unwrap();
            assert!(path.is_file());
            let got = std::fs::read(&path).unwrap();
            assert_eq!(got, body);
            assert!(*mock.hits.lock().unwrap() >= 1);

            // Cleanup kept tempfile / XDG blob.
            let _ = std::fs::remove_file(&path);
        });
    }

    /// Regression: remount of a well-known sidecar (no `.ptr`) is a V-3 cache
    /// hit — extra sidecar GET count is 0. Returned path opens read-only.
    #[test]
    fn maybe_fetch_http_remount_well_known_sidecar_cache_hit() {
        with_isolated_xdg(|| {
            let tmp = tempfile::tempdir().unwrap();
            let src = tmp.path().join("real.sqlite");
            {
                let mut idx = crate::SqliteIndex::create_writable(Some(&src)).unwrap();
                idx.publish_tmp().unwrap();
            }
            let body = std::fs::read(&src).unwrap();
            let mock = MockHttp::spawn(body.clone());
            let url = mock.url("/a.tar.zst.index.sqlite");
            let p1 = maybe_fetch_index_url(&url).unwrap();
            let hits1 = *mock.hits.lock().unwrap();
            assert!(hits1 >= 1);
            assert!(p1.is_file());
            let p2 = maybe_fetch_index_url(&url).unwrap();
            let hits2 = *mock.hits.lock().unwrap();
            assert_eq!(
                hits2, hits1,
                "second fetch must not GET the sidecar again (no .ptr required)"
            );
            assert_eq!(std::fs::read(&p2).unwrap(), body);
            assert!(crate::is_meta_cache_path(&p2), "{}", p2.display());
            crate::SqliteIndex::open_read_only(&p2).unwrap();
            let _ = std::fs::remove_file(&p1);
            if p2 != p1 {
                let _ = std::fs::remove_file(&p2);
            }
        });
    }

    /// Regression: corrupting the cached blob forces exactly one refetch.
    #[test]
    fn maybe_fetch_http_corrupt_cache_refetches() {
        with_isolated_xdg(|| {
            let body = b"SQLite format 3\0ok-sidecar".to_vec();
            let mock = MockHttp::spawn(body.clone());
            let url = mock.url("/c.index.sqlite");
            let p1 = maybe_fetch_index_url(&url).unwrap();
            std::fs::write(&p1, b"truncated").unwrap();
            let hits1 = *mock.hits.lock().unwrap();
            let p2 = maybe_fetch_index_url(&url).unwrap();
            let hits2 = *mock.hits.lock().unwrap();
            assert_eq!(hits2, hits1 + 1, "corrupt cache must refetch once");
            assert_eq!(std::fs::read(&p2).unwrap(), body);
            let _ = std::fs::remove_file(&p2);
        });
    }

    /// Regression: `file://` sidecars skip the XDG LRU.
    #[test]
    fn maybe_fetch_file_url_skips_meta_cache() {
        let dir = tempfile::tempdir().unwrap();
        let idx = dir.path().join("t.index.sqlite");
        std::fs::write(&idx, b"SQLite format 3\0").unwrap();
        let via = maybe_fetch_index_url(&format!("file://{}", idx.display())).unwrap();
        assert_eq!(via, idx);
        assert!(
            !crate::is_meta_cache_path(&via),
            "file:// must not be stored in meta-v3"
        );
    }

    #[test]
    fn maybe_fetch_http_empty_body() {
        with_isolated_xdg(|| {
            let mock = MockHttp::spawn(Vec::new());
            let url = mock.url("/empty.index.sqlite");
            let path = maybe_fetch_index_url(&url).unwrap();
            assert!(path.is_file());
            assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
            let _ = std::fs::remove_file(&path);
        });
    }

    #[test]
    fn resolve_index_location_materializes_http_explicit() {
        with_isolated_xdg(|| {
            let body = b"SQLite format 3\0".to_vec();
            let mock = MockHttp::spawn(body.clone());
            let url = mock.url("/idx.sqlite");

            let dir = tempfile::tempdir().unwrap();
            let archive = dir.path().join("a.tar");
            std::fs::write(&archive, b"x").unwrap();

            let loc = resolve_index_location(&archive, Some(&url), &[PathBuf::new()], false);
            match loc {
                IndexLocation::Path(p) => {
                    assert!(p.is_file());
                    assert_eq!(std::fs::read(&p).unwrap(), body);
                    let _ = std::fs::remove_file(&p);
                }
                IndexLocation::Memory => panic!("expected materialized path"),
            }
        });
    }

    #[test]
    fn resolve_index_location_file_url_explicit() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        let idx = dir.path().join("custom.index.sqlite");
        std::fs::write(&archive, b"x").unwrap();
        std::fs::write(&idx, b"SQLite format 3\0").unwrap();

        let file_url = format!("file://{}", idx.display());
        let loc = resolve_index_location(&archive, Some(&file_url), &[], false);
        assert_eq!(loc, IndexLocation::Path(idx));
    }

    #[test]
    fn resolve_index_location_local_explicit_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        let idx = dir.path().join("local.index.sqlite");
        std::fs::write(&archive, b"x").unwrap();
        let loc = resolve_index_location(&archive, Some(idx.to_str().unwrap()), &[], true);
        assert_eq!(loc, IndexLocation::Path(idx));
    }

    #[test]
    fn sibling_then_fetch() {
        with_isolated_xdg(|| {
            let body = b"SQLite format 3\0sibling".to_vec();
            let mock = MockHttp::spawn(body.clone());
            let archive_url = mock.url("/data/bundle.tar");
            let idx_url = sibling_index_url(&archive_url).unwrap();
            assert!(idx_url.ends_with("/data/bundle.tar.index.sqlite"));
            // Mock serves any path with the same body; fetch sibling URL.
            let path = maybe_fetch_index_url(&idx_url).unwrap();
            assert_eq!(std::fs::read(&path).unwrap(), body);
            let _ = std::fs::remove_file(&path);
        });
    }

    #[test]
    fn maybe_fetch_rejects_empty_spec() {
        let err = maybe_fetch_index_url("  ").unwrap_err();
        assert!(matches!(err, IndexError::Invalid(_)));
    }

    /// Tiny fake SQLite header payload used as compression round-trip body.
    fn tiny_sqlite_bytes() -> Vec<u8> {
        let mut v = SQLITE_MAGIC.to_vec();
        v.extend_from_slice(b"tiny-index-payload-for-tests");
        v
    }

    fn write_gzip(path: &Path, data: &[u8]) {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        let f = File::create(path).unwrap();
        let mut enc = GzEncoder::new(f, Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap();
    }

    fn write_xz(path: &Path, data: &[u8]) {
        let f = File::create(path).unwrap();
        let mut enc = xz2::write::XzEncoder::new(f, 6);
        enc.write_all(data).unwrap();
        enc.finish().unwrap();
    }

    fn write_zstd(path: &Path, data: &[u8]) {
        let f = File::create(path).unwrap();
        let mut enc = zstd::stream::write::Encoder::new(f, 3).unwrap();
        enc.write_all(data).unwrap();
        enc.finish().unwrap();
    }

    fn write_bzip2(path: &Path, data: &[u8]) {
        let f = File::create(path).unwrap();
        let mut enc = bzip2::write::BzEncoder::new(f, bzip2::Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap();
    }

    fn assert_sqlite_magic(path: &Path) {
        let mut f = File::open(path).unwrap();
        let mut magic = [0u8; 16];
        f.read_exact(&mut magic).unwrap();
        assert_eq!(&magic, SQLITE_MAGIC, "path={}", path.display());
    }

    #[test]
    fn materialize_uncompressed_passthrough() {
        let dir = tempfile::tempdir().unwrap();
        let idx = dir.path().join("plain.index.sqlite");
        let body = tiny_sqlite_bytes();
        std::fs::write(&idx, &body).unwrap();

        let out = materialize_index_file(&idx).unwrap();
        assert_eq!(out, idx);
        assert_eq!(std::fs::read(&out).unwrap(), body);
    }

    #[test]
    fn materialize_gzip_index() {
        let dir = tempfile::tempdir().unwrap();
        let body = tiny_sqlite_bytes();
        let gz = dir.path().join("t.index.sqlite.gz");
        write_gzip(&gz, &body);

        let out = materialize_index_file(&gz).unwrap();
        assert_ne!(out, gz);
        assert_sqlite_magic(&out);
        assert_eq!(std::fs::read(&out).unwrap(), body);
        let _ = std::fs::remove_file(&out);
    }

    #[test]
    fn materialize_xz_index() {
        let dir = tempfile::tempdir().unwrap();
        let body = tiny_sqlite_bytes();
        let xz = dir.path().join("t.index.sqlite.xz");
        write_xz(&xz, &body);

        let out = materialize_index_file(&xz).unwrap();
        assert_sqlite_magic(&out);
        assert_eq!(std::fs::read(&out).unwrap(), body);
        let _ = std::fs::remove_file(&out);
    }

    #[test]
    fn materialize_zstd_index() {
        let dir = tempfile::tempdir().unwrap();
        let body = tiny_sqlite_bytes();
        let zst = dir.path().join("t.index.sqlite.zst");
        write_zstd(&zst, &body);

        let out = materialize_index_file(&zst).unwrap();
        assert_sqlite_magic(&out);
        assert_eq!(std::fs::read(&out).unwrap(), body);
        let _ = std::fs::remove_file(&out);
    }

    #[test]
    fn materialize_zstd_zstd_suffix() {
        let dir = tempfile::tempdir().unwrap();
        let body = tiny_sqlite_bytes();
        let zst = dir.path().join("t.index.sqlite.zstd");
        write_zstd(&zst, &body);

        let out = materialize_index_file(&zst).unwrap();
        assert_sqlite_magic(&out);
        let _ = std::fs::remove_file(&out);
    }

    #[test]
    fn materialize_bzip2_index() {
        let dir = tempfile::tempdir().unwrap();
        let body = tiny_sqlite_bytes();
        let bz2 = dir.path().join("t.index.sqlite.bz2");
        write_bzip2(&bz2, &body);

        let out = materialize_index_file(&bz2).unwrap();
        assert_sqlite_magic(&out);
        assert_eq!(std::fs::read(&out).unwrap(), body);
        let _ = std::fs::remove_file(&out);
    }

    #[test]
    fn materialize_gzip_without_sqlite_payload_errors() {
        let dir = tempfile::tempdir().unwrap();
        let gz = dir.path().join("not-sqlite.gz");
        write_gzip(&gz, b"this is not a sqlite database");

        let err = materialize_index_file(&gz).unwrap_err();
        match err {
            IndexError::Invalid(msg) => {
                assert!(
                    msg.contains("not a SQLite") || msg.contains("SQLite"),
                    "unexpected msg: {msg}"
                );
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn maybe_fetch_decompresses_local_gzip() {
        let dir = tempfile::tempdir().unwrap();
        let body = tiny_sqlite_bytes();
        let gz = dir.path().join("idx.sqlite.gz");
        write_gzip(&gz, &body);

        let out = maybe_fetch_index_url(gz.to_str().unwrap()).unwrap();
        assert_sqlite_magic(&out);
        assert_eq!(std::fs::read(&out).unwrap(), body);
        let _ = std::fs::remove_file(&out);
    }

    #[test]
    fn maybe_fetch_http_gzip_index() {
        with_isolated_xdg(|| {
            let body = tiny_sqlite_bytes();
            let dir = tempfile::tempdir().unwrap();
            let gz_path = dir.path().join("remote.gz");
            write_gzip(&gz_path, &body);
            let gz_bytes = std::fs::read(&gz_path).unwrap();

            let mock = MockHttp::spawn(gz_bytes);
            let url = mock.url("/archive.tar.index.sqlite.gz");
            let out = maybe_fetch_index_url(&url).unwrap();
            assert_sqlite_magic(&out);
            assert_eq!(std::fs::read(&out).unwrap(), body);
            let _ = std::fs::remove_file(&out);
        });
    }

    /// Regression: a cached compressed sidecar that fails to materialize is
    /// dropped so the next fetch GETs again (not a sticky XDG gzip blob).
    #[test]
    fn maybe_fetch_http_gzip_bad_payload_invalidates_and_refetches() {
        with_isolated_xdg(|| {
            let dir = tempfile::tempdir().unwrap();
            let gz = dir.path().join("bad.gz");
            write_gzip(&gz, b"this is not a sqlite database");
            let gz_bytes = std::fs::read(&gz).unwrap();
            let mock = MockHttp::spawn(gz_bytes);
            let url = mock.url("/archive.tar.index.sqlite.gz");
            assert!(maybe_fetch_index_url(&url).is_err());
            let hits1 = *mock.hits.lock().unwrap();
            assert!(hits1 >= 1);
            assert!(maybe_fetch_index_url(&url).is_err());
            assert_eq!(
                *mock.hits.lock().unwrap(),
                hits1 + 1,
                "failed gzip materialize must invalidate and refetch"
            );
        });
    }

    #[test]
    fn resolve_explicit_gzip_index() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        std::fs::write(&archive, b"x").unwrap();
        let body = tiny_sqlite_bytes();
        let gz = dir.path().join("custom.index.sqlite.gz");
        write_gzip(&gz, &body);

        let loc = resolve_index_location(&archive, Some(gz.to_str().unwrap()), &[], false);
        match loc {
            IndexLocation::Path(p) => {
                assert_sqlite_magic(&p);
                assert_eq!(std::fs::read(&p).unwrap(), body);
                if p != gz {
                    let _ = std::fs::remove_file(&p);
                }
            }
            IndexLocation::Memory => panic!("expected path"),
        }
    }

    #[test]
    fn detect_compression_by_magic_ignores_wrong_suffix() {
        // File named .sqlite but gzip-compressed body must still decompress.
        let dir = tempfile::tempdir().unwrap();
        let body = tiny_sqlite_bytes();
        let path = dir.path().join("sneaky.index.sqlite");
        write_gzip(&path, &body);
        let out = materialize_index_file(&path).unwrap();
        assert_sqlite_magic(&out);
        assert_eq!(std::fs::read(&out).unwrap(), body);
        let _ = std::fs::remove_file(&out);
    }

    #[test]
    fn parse_link_describedby_rfc8288() {
        // v1 is the blob family; 0.7.0 is the files schema — not SOCI.
        assert_ne!(INDEX_MEDIA_TYPE, crate::INDEX_VERSION);
        assert_eq!(crate::INDEX_VERSION, "0.7.0");
        assert_eq!(
            INDEX_MEDIA_TYPE,
            "application/vnd.ratarmount.index.v1+sqlite"
        );
        assert_eq!(INDEX_LINK_REL, "describedby");

        let archive = "http://host/path/a.tar";
        assert_eq!(
            parse_link_describedby(
                &format!("<http://cdn/a.index.sqlite>; rel=\"{INDEX_LINK_REL}\"; type=\"{INDEX_MEDIA_TYPE}\""),
                archive
            )
            .as_deref(),
            Some("http://cdn/a.index.sqlite")
        );
        // Relative URI; unquoted rel; extra relation tokens.
        assert_eq!(
            parse_link_describedby("</a.tar.index.sqlite>; rel=describedby prefetch", archive)
                .as_deref(),
            Some("http://host/a.tar.index.sqlite")
        );
        // Prefer matching media type over an earlier describedby of another type.
        let mixed = format!(
            "<http://host/other.json>; rel=\"describedby\"; type=\"application/json\", \
             <http://host/good.index.sqlite>; rel=\"describedby\"; type=\"{INDEX_MEDIA_TYPE}\""
        );
        assert_eq!(
            parse_link_describedby(&mixed, archive).as_deref(),
            Some("http://host/good.index.sqlite")
        );
        // Comma inside quoted title must not split links.
        assert_eq!(
            parse_link_describedby(
                "<http://host/idx.sqlite>; rel=\"describedby\"; title=\"a, b\"",
                archive
            )
            .as_deref(),
            Some("http://host/idx.sqlite")
        );
        assert!(parse_link_describedby(
            "<s3://bucket/a.index.sqlite>; rel=\"describedby\"",
            archive
        )
        .is_none());
        assert!(
            parse_link_describedby("<http://host/idx.sqlite>; rel=\"prefetch\"", archive).is_none()
        );
        assert!(parse_link_describedby("", archive).is_none());
    }

    /// Regression: inbound HEAD of an **archive** URL follows RFC 8288
    /// `Link: rel="describedby"` to the portable index blob (not SOCI).
    #[test]
    fn link_describedby_archive_head() {
        with_isolated_xdg(|| {
            let body = tiny_sqlite_bytes();
            let link = format!(
            "</archive.tar.index.sqlite>; rel=\"{INDEX_LINK_REL}\"; type=\"{INDEX_MEDIA_TYPE}\""
        );
            let mock =
                MockHttp::spawn_with_extra_headers(body.clone(), vec![("Link".into(), link)]);
            let archive_url = mock.url("/archive.tar");

            let resp = ureq::head(&archive_url)
                .set("User-Agent", USER_AGENT)
                .call()
                .unwrap();
            let header = resp.header("Link").expect("archive HEAD must expose Link");
            let idx_url = parse_link_describedby(header, &archive_url)
                .expect("describedby http(s) index URL");
            assert!(idx_url.starts_with("http://"));
            assert_eq!(idx_url, mock.url("/archive.tar.index.sqlite"));

            let path = maybe_fetch_index_url(&idx_url).unwrap();
            assert_eq!(std::fs::read(&path).unwrap(), body);
            let _ = std::fs::remove_file(&path);
            assert!(*mock.hits.lock().unwrap() >= 2);
        });
    }

    /// Regression: http(s) sibling auto-fetch tries uncompressed + compressed
    /// suffixes; S3/file URLs are not candidates.
    #[test]
    fn sibling_candidates_fetch() {
        with_isolated_xdg(|| {
            let body = tiny_sqlite_bytes();
            let dir = tempfile::tempdir().unwrap();
            let gz_path = dir.path().join("sib.gz");
            write_gzip(&gz_path, &body);
            let gz_bytes = std::fs::read(&gz_path).unwrap();

            let mock = MockHttp::spawn(gz_bytes);
            let archive_url = mock.url("/data/bundle.tar");
            let cands = sibling_index_candidates(&archive_url);
            assert_eq!(
                cands.first().map(String::as_str),
                sibling_index_url(&archive_url).as_deref()
            );
            assert!(cands.iter().any(|u| u.ends_with(".index.sqlite.gz")));
            assert!(cands.iter().any(|u| u.ends_with(".index.sqlite.zst")));
            assert!(cands.iter().any(|u| u.ends_with(".index.sqlite.xz")));
            assert!(cands.iter().any(|u| u.ends_with(".index.sqlite.bz2")));
            assert_eq!(cands.len(), 5);
            assert!(sibling_index_candidates("s3://bucket/key").is_empty());
            assert!(sibling_index_candidates("file:///tmp/a.tar").is_empty());

            let gz = cands.iter().find(|u| u.ends_with(".gz")).unwrap();
            let path = maybe_fetch_index_url(gz).unwrap();
            assert_sqlite_magic(&path);
            assert_eq!(std::fs::read(&path).unwrap(), body);
            let _ = std::fs::remove_file(&path);
        });
    }

    fn hex_id(blob: &[u8]) -> String {
        crate::sha256_hex(blob)
    }

    /// Regression: pointer JSON is schema v1, id is sha256(blob) 64 hex, store is rename-atomic.
    #[test]
    fn index_pointer_store_load_atomic() {
        assert_eq!(INDEX_POINTER_KEEP_LAST, 2);
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        let blob = dir.path().join("a.tar.index.sqlite");
        std::fs::write(&archive, b"archive-bytes").unwrap();
        let payload = b"SQLite format 3\0pointer-blob";
        std::fs::write(&blob, payload).unwrap();

        let ptr_path = index_pointer_path(&archive);
        assert_eq!(ptr_path, index_pointer_path_for_index_file(&blob));
        assert!(ptr_path.to_string_lossy().ends_with("a.tar.index.ptr"));
        assert!(!ptr_path.to_string_lossy().ends_with(".index.sqlite.ptr"));

        let ptr = IndexPointer::for_blob(&blob, Some(&archive)).unwrap();
        assert_eq!(ptr.schema, INDEX_POINTER_SCHEMA);
        assert_eq!(ptr.index_id, hex_id(payload));
        assert_eq!(ptr.etag_sha256, ptr.index_id);
        assert_eq!(ptr.index_id.len(), INDEX_ID_HEX_LEN);
        assert!(ptr.generated_at.ends_with('Z') && ptr.generated_at.contains('T'));
        store_index_pointer_atomic(&ptr_path, &ptr).unwrap();
        assert!(ptr_path.is_file());
        let loaded = load_index_pointer(&ptr_path).unwrap().expect("ptr");
        assert_eq!(loaded.index_id, ptr.index_id);
        assert_eq!(loaded.schema, INDEX_POINTER_SCHEMA);
        assert!(loaded.tarstats().is_some());

        // Second store replaces in place (rename); no leftover tmp.
        let ptr2 = IndexPointer::for_blob(&blob, Some(&archive)).unwrap();
        store_index_pointer_atomic(&ptr_path, &ptr2).unwrap();
        let loaded2 = load_index_pointer(&ptr_path).unwrap().unwrap();
        assert_eq!(loaded2.index_id, ptr.index_id);
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .contains(".ratarmount-index-ptr-")
            })
            .collect();
        assert!(
            leftovers.is_empty(),
            "atomic store left tmp files: {leftovers:?}"
        );
    }

    #[test]
    fn parse_index_id_rejects_uuid_and_path_escape() {
        assert!(parse_index_id("not-hex").is_err());
        assert!(parse_index_id("550e8400-e29b-41d4-a716-446655440000").is_err());
        assert!(parse_index_id("../".repeat(16).as_str()).is_err());
        assert!(parse_index_id(&"a".repeat(64)).is_ok());
        assert!(parse_index_id(&"A".repeat(64)).is_ok()); // normalized
        assert_eq!(parse_index_id(&"A".repeat(64)).unwrap(), "a".repeat(64));
    }

    #[test]
    fn format_rfc3339_unix_epoch() {
        assert_eq!(format_rfc3339_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_rfc3339_utc(1_704_067_200), "2024-01-01T00:00:00Z");
    }

    /// Regression: remount `--index-id` of N while N+1 is well-known (keep-last-K=2).
    #[test]
    fn resolve_index_id_keeps_previous_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        std::fs::write(&archive, b"a").unwrap();
        let well_known = default_index_path(&archive);

        let blob_n = b"SQLite format 3\0snapshot-N";
        std::fs::write(&well_known, blob_n).unwrap();
        let id_n = hex_id(blob_n);
        publish_index_pointer(&archive, &well_known, Some(&archive)).unwrap();

        let blob_np1 = b"SQLite format 3\0snapshot-N+1-bytes";
        let np1 = dir.path().join("np1.sqlite");
        std::fs::write(&np1, blob_np1).unwrap();
        // Pin of N is a hardlink of well-known. Rename (not in-place write)
        // so the pin inode stays N when dest becomes N+1 (`-c` tmp+rename).
        std::fs::rename(&np1, &well_known).unwrap();
        publish_index_pointer(&archive, &well_known, Some(&archive)).unwrap();
        let id_np1 = hex_id(blob_np1);

        let snap_n = index_id_path(&archive, &id_n).unwrap();
        assert!(snap_n.is_file(), "K=2 must keep index.{{old_id}}.sqlite");
        assert_eq!(std::fs::read(&snap_n).unwrap(), blob_n);
        assert_eq!(std::fs::read(&well_known).unwrap(), blob_np1);

        let resolved_n = resolve_index_id_path(&archive, &id_n).unwrap();
        assert_eq!(resolved_n, snap_n);
        let resolved_np1 = resolve_index_id_path(&archive, &id_np1).unwrap();
        let np1_bytes = std::fs::read(&resolved_np1).unwrap();
        assert_eq!(np1_bytes, blob_np1);
        assert_eq!(hex_id(&np1_bytes), id_np1);

        let err = resolve_index_id_path(&archive, &"b".repeat(64)).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unknown") || msg.contains("index_id"), "{msg}");
    }

    /// Regression: stale pointer naming N after well-known is N+1 must not bind N+1.
    #[test]
    fn resolve_index_id_stale_pointer_without_snapshot_refuses_well_known() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        std::fs::write(&archive, b"a").unwrap();
        let well_known = default_index_path(&archive);
        let blob_n = b"SQLite format 3\0gen-N";
        std::fs::write(&well_known, blob_n).unwrap();
        let id_n = hex_id(blob_n);
        let ptr = IndexPointer::for_blob(&well_known, Some(&archive)).unwrap();
        store_index_pointer_atomic(&index_pointer_path(&archive), &ptr).unwrap();
        assert_eq!(ptr.index_id, id_n);

        let blob_np1 = b"SQLite format 3\0gen-N+1-xxxx";
        let np1 = dir.path().join("np1.sqlite");
        std::fs::write(&np1, blob_np1).unwrap();
        std::fs::rename(&np1, &well_known).unwrap();
        assert_eq!(std::fs::read(&well_known).unwrap(), blob_np1);

        let err = resolve_index_id_path(&archive, &id_n).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("unknown") || msg.contains("index_id") || msg.contains("not that blob"),
            "{msg}"
        );
        assert_ne!(hex_id(&std::fs::read(&well_known).unwrap()), id_n);
    }

    /// Regression: leftover nonempty snapshot with the wrong SHA is replaced, not kept.
    #[test]
    fn snapshot_index_id_replaces_wrong_sha_leftover() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        let well_known = default_index_path(&archive);
        let blob_n = b"SQLite format 3\0good-pin-bytes";
        std::fs::write(&well_known, blob_n).unwrap();
        let id_n = hex_id(blob_n);
        let dest = index_id_path(&archive, &id_n).unwrap();
        std::fs::write(&dest, b"SQLite format 3\0truncated").unwrap();
        assert_ne!(hex_id(&std::fs::read(&dest).unwrap()), id_n);

        let got = snapshot_index_id(&archive, &well_known, &id_n)
            .unwrap()
            .expect("pin");
        assert_eq!(got, dest);
        assert_eq!(std::fs::read(&dest).unwrap(), blob_n);
        assert_eq!(hex_id(&std::fs::read(&dest).unwrap()), id_n);
    }

    /// Regression: `--index-id` must not bind a leftover snapshot whose SHA is not the id.
    #[test]
    fn resolve_index_id_refuses_wrong_sha_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        let id_n = hex_id(b"SQLite format 3\0wanted");
        let dest = index_id_path(&archive, &id_n).unwrap();
        std::fs::write(&dest, b"SQLite format 3\0not-the-id").unwrap();
        let err = resolve_index_id_path(&archive, &id_n).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("sha256") || msg.contains("!="), "{msg}");
    }

    /// Regression: `--index-id` tarstats mismatch refuses (no silent well-known fallback).
    #[test]
    fn bind_local_index_id_tarstats_mismatch_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        std::fs::write(&archive, b"old-content").unwrap();
        let idx_path = default_index_path(&archive);
        {
            let mut idx = crate::SqliteIndex::create_writable(Some(&idx_path)).unwrap();
            idx.store_versions("0.1.0").unwrap();
            idx.store_tarstats_for_path(&archive).unwrap();
            idx.publish_tmp().unwrap();
        }
        let id = {
            let bytes = std::fs::read(&idx_path).unwrap();
            hex_id(&bytes)
        };
        publish_index_pointer(&archive, &idx_path, Some(&archive)).unwrap();
        bind_local_index_id(&archive, &id).expect("matching archive");

        std::fs::write(&archive, b"new-content-longer").unwrap();
        let err = bind_local_index_id(&archive, &id).expect_err("mismatch");
        assert!(
            matches!(err, IndexError::Mismatch(_))
                || err.to_string().contains("mismatch")
                || err.to_string().contains("size"),
            "expected tarstats refuse, got {err:?}"
        );
    }

    #[test]
    fn load_index_pointer_rejects_wrong_schema() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.tar.index.ptr");
        std::fs::write(
            &path,
            r#"{"schema":"nope","index_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","etag_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","generated_at":"1970-01-01T00:00:00Z"}"#,
        )
        .unwrap();
        let err = load_index_pointer(&path).unwrap_err();
        assert!(err.to_string().contains("schema"), "{err}");
        assert!(load_index_pointer(&dir.path().join("missing.ptr"))
            .unwrap()
            .is_none());
    }
}
