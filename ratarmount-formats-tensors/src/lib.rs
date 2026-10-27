//! Read-only safetensors and GGUF v2/v3 mounts with SQLite listings and stenciled
//! tensor ranges. Nested readers are retained in place, without a temporary body.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ratarmount_compress::{SeekRead, StenciledFile};
use ratarmount_core::{
    CheapDirent, CheapSearchHit, FileInfo, ListModeResult, ListResult, MountSource, OpenOptions,
    UserData,
};
use ratarmount_index::{IndexError, NestedBodyFingerprint, SqliteIndex};
use serde_json::{json, Value};
use thiserror::Error;

mod gguf;
mod safetensors;
#[cfg(test)]
mod tests;

pub const BACKEND_NAME: &str = "TensorsMountSource";
/// Compile-time header budget for either format (100 MiB). Tensor payloads are
/// never included in this budget or read while building the file table.
pub const MAX_HEADER_SIZE: u64 = 100 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum TensorsError {
    #[error(transparent)]
    Index(#[from] IndexError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Invalid(String),
}

pub type Result<T> = std::result::Result<T, TensorsError>;

fn invalid(message: impl Into<String>) -> TensorsError {
    TensorsError::Invalid(message.into())
}

fn checked_add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b)
        .ok_or_else(|| invalid("tensor offset overflow"))
}

fn elements(shape: &[u64]) -> Result<u64> {
    if shape.contains(&0) {
        return Ok(0);
    }
    shape.iter().try_fold(1u64, |n, &d| {
        n.checked_mul(d)
            .ok_or_else(|| invalid("tensor shape overflow"))
    })
}

struct Tensor {
    name: String,
    offset: u64,
    size: u64,
    sidecar: Value,
}

struct Parsed {
    tensors: Vec<Tensor>,
    metadata: Value,
    raw_header: Option<(u64, u64)>,
}

fn parse<R: Read + Seek>(reader: &mut R, size: u64) -> Result<Parsed> {
    reader.seek(SeekFrom::Start(0))?;
    let mut magic = [0; 4];
    reader.read_exact(&mut magic)?;
    reader.seek(SeekFrom::Start(0))?;
    if &magic == b"GGUF" || &magic == b"FUGG" {
        gguf::parse(reader, size)
    } else {
        safetensors::parse(reader, size)
    }
}

struct SharedReader(Mutex<Box<dyn SeekRead>>);

struct PositionedReader {
    shared: Arc<SharedReader>,
    position: u64,
}

impl Read for PositionedReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut reader = self
            .shared
            .0
            .lock()
            .map_err(|_| io::Error::other("tensor reader poisoned"))?;
        reader.seek(SeekFrom::Start(self.position))?;
        let n = reader.read(buf)?;
        self.position += n as u64;
        Ok(n)
    }
}

impl Seek for PositionedReader {
    fn seek(&mut self, seek: SeekFrom) -> io::Result<u64> {
        let position = match seek {
            SeekFrom::Start(n) => i128::from(n),
            SeekFrom::Current(n) => i128::from(self.position) + i128::from(n),
            SeekFrom::End(n) => {
                let mut reader = self
                    .shared
                    .0
                    .lock()
                    .map_err(|_| io::Error::other("tensor reader poisoned"))?;
                i128::from(reader.seek(SeekFrom::End(0))?) + i128::from(n)
            }
        };
        self.position = u64::try_from(position)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid tensor seek"))?;
        Ok(self.position)
    }
}

enum Backend {
    Path(PathBuf),
    Shared(Arc<SharedReader>),
}

pub struct TensorsMountSource {
    backend: Backend,
    index: SqliteIndex,
}

impl TensorsMountSource {
    pub fn open(
        archive_path: impl AsRef<Path>,
        index_path: Option<&Path>,
        options: &OpenOptions,
        product_version: &str,
        recreate: bool,
    ) -> Result<Self> {
        let path = archive_path.as_ref();
        let ip = (!options.index_in_memory && !options.index_compact_only).then(|| {
            index_path
                .map(Path::to_path_buf)
                .unwrap_or_else(|| default_index_path(path))
        });
        if !recreate && !options.clear_index_cache {
            if options.read_only_index {
                if let Some(ip) = &ip {
                    let index = Self::existing(ip, options)?;
                    index.check_tarstats_matches_archive(path)?;
                    return Ok(Self {
                        backend: Backend::Path(path.to_path_buf()),
                        index,
                    });
                }
            }
            if let Some(ip) = &ip {
                if let Ok(index) = Self::existing(ip, options) {
                    if index.check_tarstats_matches_archive(path).is_ok() {
                        return Ok(Self {
                            backend: Backend::Path(path.to_path_buf()),
                            index,
                        });
                    }
                }
            }
        }
        let mut reader = File::open(path)?;
        let size = reader.metadata()?.len();
        let parsed = parse(&mut reader, size)?;
        let index = build_index(parsed, ip.as_deref(), options, product_version)?;
        index.store_tarstats_for_path(path)?;
        index.commit_write()?;
        Ok(Self {
            backend: Backend::Path(path.to_path_buf()),
            index: index.into_read_only()?,
        })
    }

    /// Same call shape as AR: `None` uses a memory/compact index; `Some` allows
    /// durable SQLite reuse, verified using the shared nested-body fingerprint.
    /// The label is virtual and is never opened as a host filesystem path.
    pub fn open_from_reader<R: Read + Seek + Send + 'static>(
        mut reader: R,
        _archive_label: impl AsRef<Path>,
        index_path: Option<&Path>,
        options: &OpenOptions,
        product_version: &str,
    ) -> Result<Self> {
        let size = reader.seek(SeekFrom::End(0))?;
        let ip = index_path.filter(|_| !options.index_in_memory && !options.index_compact_only);
        let fingerprint = if ip.is_some() {
            Some(serde_json::to_string(
                &NestedBodyFingerprint::from_seekable_body(&mut reader, size)?,
            )?)
        } else {
            None
        };
        let existing = if let Some(path) =
            ip.filter(|_| options.read_only_index && !options.clear_index_cache)
        {
            let index = Self::existing(path, options)?;
            if index.metadata()?.get("tensorReaderFingerprint") != fingerprint.as_ref() {
                return Err(invalid("prepared tensor reader index fingerprint mismatch; --no-recreate-index forbids rebuilding"));
            }
            Some(index)
        } else if !options.clear_index_cache {
            ip.and_then(|ip| Self::existing(ip, options).ok())
                .filter(|idx| {
                    idx.metadata()
                        .ok()
                        .and_then(|m| m.get("tensorReaderFingerprint").cloned())
                        == fingerprint
                })
        } else {
            None
        };
        let index = if let Some(index) = existing {
            index
        } else {
            let parsed = parse(&mut reader, size)?;
            let index = build_index(parsed, ip, options, product_version)?;
            index.store_metadata_key_value(
                "tarstats",
                &json!({"st_size":size,"st_mtime":0,"st_mtime_ns":0}).to_string(),
            )?;
            if let Some(fp) = fingerprint {
                index.store_metadata_key_value("tensorReaderFingerprint", &fp)?;
            }
            index.commit_write()?;
            index.into_read_only()?
        };
        Ok(Self {
            backend: Backend::Shared(Arc::new(SharedReader(Mutex::new(Box::new(reader))))),
            index,
        })
    }

    fn existing(path: &Path, options: &OpenOptions) -> Result<SqliteIndex> {
        let index = SqliteIndex::open_read_only_for_open(path, options)?;
        index.check_backend_name(BACKEND_NAME)?;
        if index.metadata()?.get("tensorSchema").map(String::as_str) != Some("1") {
            return Err(invalid("unsupported tensor index schema"));
        }
        Ok(index)
    }
}

/// Dots separate components. Percent encoding leaves only ASCII letters,
/// digits, `_` and `-` literal; empty components use the reserved `%EMPTY`.
/// Consequently generated `.json` and `.tensor` suffixes cannot be input names.
/// Reserve `__metadata__` and `__header__` components by escaping their first
/// underscore, so tensor sidecars cannot replace the generated root JSON files.
fn tensor_path(name: &str) -> String {
    name.split('.')
        .map(|part| {
            if part.is_empty() {
                return "%EMPTY".to_string();
            }
            if matches!(part, "__metadata__" | "__header__") {
                return format!("%5F{}", &part[1..]);
            }
            let mut encoded = String::new();
            for byte in part.bytes() {
                if byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-') {
                    encoded.push(char::from(byte));
                } else {
                    use std::fmt::Write;
                    write!(&mut encoded, "%{byte:02X}").expect("write to String");
                }
            }
            encoded
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn build_index(
    mut parsed: Parsed,
    path: Option<&Path>,
    options: &OpenOptions,
    version: &str,
) -> Result<SqliteIndex> {
    parsed.tensors.sort_by(|a, b| a.name.cmp(&b.name));
    let paths: BTreeSet<_> = parsed
        .tensors
        .iter()
        .map(|t| tensor_path(&t.name))
        .collect();
    if paths.len() != parsed.tensors.len() {
        return Err(invalid("duplicate tensor name"));
    }
    let mut directories = BTreeSet::new();
    for path in &paths {
        for (i, _) in path.match_indices('/') {
            directories.insert(path[..i].to_string());
        }
    }
    // Sweep ranges once; mark every participant without a quadratic overlap list.
    let mut order: Vec<_> = (0..parsed.tensors.len())
        .filter(|&i| parsed.tensors[i].size > 0)
        .collect();
    order.sort_by_key(|&i| parsed.tensors[i].offset);
    let mut furthest: Option<(u64, usize)> = None;
    let mut overlaps = BTreeSet::new();
    for i in order {
        let t = &parsed.tensors[i];
        let end = checked_add(t.offset, t.size)?;
        if let Some((max_end, j)) = furthest {
            if t.offset < max_end {
                overlaps.insert(i);
                overlaps.insert(j);
            }
        }
        if furthest.is_none_or(|(max_end, _)| end > max_end) {
            furthest = Some((end, i));
        }
    }
    let index = SqliteIndex::create_writable_for_open(path, options)?;
    index.begin_write()?;
    // Every intermediate component needs its own directory row: readdir of the
    // parent and path-walking lookups (FUSE resolves `/layer/0/weight` one
    // component at a time) only see rows, never implied prefixes. Without these
    // a standalone mount listed just the root JSON files. BTreeSet order puts
    // parents before children.
    for directory in &directories {
        insert_directory(&index, directory)?;
    }
    for (i, tensor) in parsed.tensors.iter_mut().enumerate() {
        let mut path = tensor_path(&tensor.name);
        if directories.contains(&path) {
            path.push_str(".tensor");
        }
        tensor.sidecar["name"] = json!(tensor.name);
        tensor.sidecar["path"] = json!(path);
        tensor.sidecar["overlapping"] = json!(overlaps.contains(&i));
        insert(&index, &path, tensor.offset, tensor.size, "")?;
        let sidecar = serde_json::to_string_pretty(&tensor.sidecar)?;
        insert(
            &index,
            &format!("{path}.json"),
            0,
            sidecar.len() as u64,
            &sidecar,
        )?;
    }
    let metadata = serde_json::to_string_pretty(&parsed.metadata)?;
    insert(
        &index,
        "__metadata__.json",
        0,
        metadata.len() as u64,
        &metadata,
    )?;
    if let Some((offset, size)) = parsed.raw_header {
        insert(&index, "__header__.json", offset, size, "")?;
    }
    index.store_versions(version)?;
    index.store_metadata_key_value("backendName", BACKEND_NAME)?;
    index.store_metadata_key_value("tensorSchema", "1")?;
    Ok(index)
}

/// Split `a/b/c` into the SQLite `path` column (`/a/b`, or empty at the root) and `name`.
fn split_parent(full: &str) -> (String, &str) {
    let (path, name) = full.rsplit_once('/').unwrap_or(("", full));
    let path = if path.is_empty() {
        String::new()
    } else {
        format!("/{path}")
    };
    (path, name)
}

/// A generated, read-only directory row for one tensor path prefix.
fn insert_directory(index: &SqliteIndex, full: &str) -> Result<()> {
    let (path, name) = split_parent(full);
    index.insert_file(
        &path,
        name,
        0,
        0,
        0,
        0.0,
        (ratarmount_core::S_IFDIR | 0o555) as i64,
        0,
        "",
        0,
        0,
        false,
        false,
        true,
        0,
    )?;
    Ok(())
}

fn insert(index: &SqliteIndex, full: &str, offset: u64, size: u64, inline: &str) -> Result<()> {
    let (path, name) = split_parent(full);
    let offset =
        i64::try_from(offset).map_err(|_| invalid("tensor offset exceeds SQLite range"))?;
    let size = i64::try_from(size).map_err(|_| invalid("tensor size exceeds SQLite range"))?;
    index.insert_file(
        &path,
        name,
        offset,
        offset,
        size,
        0.0,
        (ratarmount_core::S_IFREG | 0o444) as i64,
        0,
        inline,
        0,
        0,
        false,
        false,
        !inline.is_empty(),
        0,
    )?;
    Ok(())
}

impl MountSource for TensorsMountSource {
    fn list(&self, path: &str) -> Option<ListResult> {
        self.index.list(path).ok().flatten().map(ListResult::Infos)
    }
    fn list_mode(&self, path: &str) -> Option<ListModeResult> {
        self.index
            .list_mode(path)
            .ok()
            .flatten()
            .map(ListModeResult::Modes)
    }
    fn list_dirents(&self, path: &str) -> Option<Vec<CheapDirent>> {
        self.index.list_dirents(path).ok().flatten().map(|rows| {
            rows.into_iter()
                .map(|d| CheapDirent {
                    name: d.name,
                    mode: d.mode,
                    size: d.size,
                })
                .collect()
        })
    }
    fn search_cheap(&self, pattern: &str) -> Option<Vec<CheapSearchHit>> {
        if pattern.starts_with("fts:") {
            None
        } else {
            self.index.search_cheap(pattern).ok()
        }
    }
    fn lookup(&self, path: &str, file_version: i32) -> Option<FileInfo> {
        self.index.lookup(path, file_version).ok().flatten()
    }
    fn open(
        &self,
        file_info: &FileInfo,
        _buffering: i32,
    ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
        if ratarmount_core::is_dir_mode(file_info.mode) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot read tensor directory",
            ));
        }
        if !file_info.linkname.is_empty() {
            return Ok(Box::new(Cursor::new(
                file_info.linkname.clone().into_bytes(),
            )));
        }
        let offset = file_info
            .userdata
            .iter()
            .rev()
            .find_map(|ud| match ud {
                UserData::Tar(t) => Some(t.offset),
                _ => None,
            })
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "missing tensor userdata")
            })?;
        let regions = vec![(offset, file_info.size)];
        match &self.backend {
            Backend::Path(path) => Ok(Box::new(StenciledFile::new(File::open(path)?, regions))),
            Backend::Shared(shared) => Ok(Box::new(StenciledFile::new(
                PositionedReader {
                    shared: Arc::clone(shared),
                    position: 0,
                },
                regions,
            ))),
        }
    }
    fn is_immutable(&self) -> bool {
        true
    }
}

pub fn default_index_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".index.sqlite");
    PathBuf::from(name)
}

/// Bounded structural sniff; opening always performs full validation.
pub fn looks_like_safetensors(path: &Path) -> bool {
    if path
        .extension()
        .and_then(|s| s.to_str())
        .is_some_and(|s| s.eq_ignore_ascii_case("safetensors"))
    {
        return true;
    }
    File::open(path)
        .ok()
        .is_some_and(|mut reader| looks_like_safetensors_reader(&mut reader))
}

/// Reader sniff rewinds to zero, like factory magic dispatch.
pub fn looks_like_safetensors_reader<R: Read + Seek>(reader: &mut R) -> bool {
    let sniff = || -> io::Result<bool> {
        reader.seek(SeekFrom::Start(0))?;
        let mut length = [0; 8];
        reader.read_exact(&mut length)?;
        let n = u64::from_le_bytes(length);
        let mut first = [0];
        reader.read_exact(&mut first)?;
        let size = reader.seek(SeekFrom::End(0))?;
        Ok(n > 1 && n <= MAX_HEADER_SIZE && n <= size.saturating_sub(8) && first[0] == b'{')
    }();
    let rewound = reader.seek(SeekFrom::Start(0)).is_ok();
    sniff.unwrap_or(false) && rewound
}

pub fn looks_like_gguf(path: &Path) -> bool {
    if path
        .extension()
        .and_then(|s| s.to_str())
        .is_some_and(|s| s.eq_ignore_ascii_case("gguf"))
    {
        return true;
    }
    File::open(path).ok().is_some_and(|mut reader| {
        let mut magic = [0; 4];
        reader.read_exact(&mut magic).is_ok() && matches!(&magic, b"GGUF" | b"FUGG")
    })
}
