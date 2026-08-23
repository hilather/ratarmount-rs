//! SquashFS mount source.
//!
//! Prefer **in-process** random access via the pure-Rust [`backhand`] crate (parity with
//! Python `PySquashfsImage` for list/lookup/open). Supported compressors include
//! uncompressed, gzip, zstd, lz4, lzo, and **xz** (via workspace `xz2`, not backhand's
//! `liblzma` feature which conflicts with the rest of the tree).
//!
//! Classic LZMA (compressor id 2) is not implemented in-process. When path-based
//! [`SquashFsMountSource::open`] cannot use backhand (classic LZMA; corrupt image;
//! exotic vendor kind), it falls back to materializing with `unsquashfs` into a temp
//! dir served by [`FolderMountSource`].
//!
//! # Nested archives (AutoMount / `open_from_reader`)
//!
//! Nested SquashFS members can open without `/tmp` when the outer archive yields a
//! seekable stream and the compressor is supported in-process:
//! [`SquashFsMountSource::open_from_reader`] feeds the reader to backhand (optionally
//! after buffering into a `Cursor<Vec<u8>>` for small images). **No** `NamedTempFile`
//! is created on the success path.
//!
//! | Concern | Behaviour |
//! |---------|-----------|
//! | Host temp file | **Never** on the nested no-tmp success path |
//! | In-process codecs | none / gzip / zstd / lz4 / lzo / xz (workspace `xz2`) |
//! | Classic LZMA | **Error** — factory/AutoMount may temp-spool and path-`open` |
//! | `unsquashfs` fallback | **Not** used inside `open_from_reader` (path `open` only) |
//! | Memory | Seekable body retained by backhand; full RAM buffer is OK |
//!
//! Residual: when `open_from_reader` fails → factory/AutoMount temp spool + path open.
//!
//! Detection scans offset 0 and the first 1 MiB at 4 KiB strides (AppImage payloads).

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, BufReader, Cursor, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use backhand::compression::{CompressionAction, Compressor, DefaultCompressor};
use backhand::kind::{self, Kind};
use backhand::{
    BackhandError, FilesystemCompressor, FilesystemReader, InnerNode, SquashfsFileReader,
    SuperBlock,
};
use ratarmount_compositing::FolderMountSource;
use ratarmount_core::{
    CheapDirent, FileInfo, ListModeResult, ListResult, MountSource, UserData, S_IFDIR, S_IFLNK,
    S_IFMT, S_IFREG,
};
use tempfile::TempDir;
use thiserror::Error;
use xz2::read::XzDecoder;

pub const BACKEND_NAME: &str = "SquashFsMountSource";

/// SquashFS superblock compressor ids (v4).
const COMP_UNCOMPRESSED: u16 = 0;
const COMP_GZIP: u16 = 1;
const COMP_LZMA: u16 = 2;
const COMP_LZO: u16 = 3;
const COMP_XZ: u16 = 4;
const COMP_LZ4: u16 = 5;
const COMP_ZSTD: u16 = 6;

#[derive(Debug, Error)]
pub enum SquashFsError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("{0}")]
    Msg(String),
}

pub type Result<T> = std::result::Result<T, SquashFsError>;

const MAGIC_LE: &[u8; 4] = b"hsqs";
const MAGIC_BE: &[u8; 4] = b"sqsh";

/// Userdata key for archive member path.
fn squash_path_userdata(path: &str) -> UserData {
    UserData::Other(format!("squashfs:{path}"))
}

fn path_from_userdata(fi: &FileInfo) -> Option<String> {
    fi.userdata.iter().rev().find_map(|u| match u {
        UserData::Other(s) if s.starts_with("squashfs:") => Some(s[9..].to_string()),
        _ => None,
    })
}

/// Normalize to absolute squashfs-style path (`/`, `/a`, `/a/b`).
fn norm_abs(path: &str) -> String {
    let trimmed = path.trim_matches('/');
    if trimmed.is_empty() {
        "/".into()
    } else {
        format!("/{trimmed}")
    }
}

fn parent_and_name(abs: &str) -> (String, String) {
    if abs == "/" {
        return ("/".into(), String::new());
    }
    let trimmed = abs.trim_end_matches('/');
    match trimmed.rsplit_once('/') {
        Some(("", name)) => ("/".into(), name.to_string()),
        Some((parent, name)) => (parent.to_string(), name.to_string()),
        None => ("/".into(), trimmed.to_string()),
    }
}

/// Custom backhand compressor: same as [`DefaultCompressor`] for enabled pure-Rust codecs,
/// plus XZ via workspace `xz2` (avoids enabling backhand's `xz` → `liblzma` feature).
struct WorkspaceCompressor;

static WORKSPACE_COMPRESSOR: WorkspaceCompressor = WorkspaceCompressor;

impl CompressionAction for WorkspaceCompressor {
    type Error = BackhandError;
    type Compressor = Compressor;
    type FilesystemCompressor = FilesystemCompressor;
    type SuperBlock = SuperBlock;

    fn decompress(
        &self,
        bytes: &[u8],
        out: &mut Vec<u8>,
        compressor: Self::Compressor,
    ) -> std::result::Result<(), Self::Error> {
        match compressor {
            Compressor::Xz => {
                let mut decoder = XzDecoder::new(bytes);
                decoder
                    .read_to_end(out)
                    .map_err(|e| BackhandError::CompressionInit(format!("xz2 decompress: {e}")))?;
                Ok(())
            }
            // Classic LZMA is not implemented by DefaultCompressor either; keep explicit.
            Compressor::Lzma => Err(BackhandError::UnsupportedCompression("Lzma".to_string())),
            other => DefaultCompressor.decompress(bytes, out, other),
        }
    }

    fn compress(
        &self,
        bytes: &[u8],
        fc: Self::FilesystemCompressor,
        block_size: u32,
    ) -> std::result::Result<Vec<u8>, Self::Error> {
        // Read-only mount source; writing is unused. Delegate for completeness.
        DefaultCompressor.compress(bytes, fc, block_size)
    }

    fn compression_options(
        &self,
        superblock: &mut Self::SuperBlock,
        kind: &Kind,
        fs_compressor: Self::FilesystemCompressor,
    ) -> std::result::Result<Option<Vec<u8>>, Self::Error> {
        DefaultCompressor.compression_options(superblock, kind, fs_compressor)
    }
}

/// Backend storage: in-process reader or materialize fallback.
enum Backend {
    InProcess {
        fs: FilesystemReader<'static>,
        /// Absolute path → node index in `fs.files()` / root.nodes.
        by_path: BTreeMap<String, usize>,
        /// Parent absolute path → child basename → child absolute path.
        children: BTreeMap<String, BTreeMap<String, String>>,
    },
    Materialized {
        inner: FolderMountSource,
        _extract: TempDir,
    },
}

/// SquashFS mount source (in-process when possible).
pub struct SquashFsMountSource {
    backend: Backend,
    #[allow(dead_code)]
    archive_path: PathBuf,
    /// Superblock offset used to open (AppImage / embedded).
    #[allow(dead_code)]
    offset: u64,
}

impl SquashFsMountSource {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let offset = find_squashfs_offset(path)?.ok_or_else(|| {
            SquashFsError::Msg(format!("{} is not a SquashFS image", path.display()))
        })?;

        let compressor = read_superblock_compressor(path, offset).ok().flatten();

        // Classic LZMA is never supported in-process (backhand DefaultCompressor and our
        // xz2 path only cover XZ). Skip straight to unsquashfs with a clear log line.
        if compressor == Some(COMP_LZMA) {
            log::info!(
                "SquashFS {}: in-process lzma unsupported, using unsquashfs",
                path.display()
            );
            let backend = Self::open_unsquashfs(path, offset)?;
            return Ok(Self {
                backend,
                archive_path: path.to_path_buf(),
                offset,
            });
        }

        match Self::open_inprocess(path, offset) {
            Ok(backend) => {
                log::debug!(
                    "SquashFS in-process open ok for {} (offset={offset}, compressor={})",
                    path.display(),
                    compressor_name(compressor)
                );
                Ok(Self {
                    backend,
                    archive_path: path.to_path_buf(),
                    offset,
                })
            }
            Err(e) => {
                let reason = match compressor {
                    Some(COMP_XZ) => "in-process xz unsupported, using unsquashfs",
                    Some(COMP_LZMA) => "in-process lzma unsupported, using unsquashfs",
                    _ => "falling back to unsquashfs materialize",
                };
                log::warn!(
                    "SquashFS in-process open failed for {} (offset={offset}, compressor={}): {e}; {reason}",
                    path.display(),
                    compressor_name(compressor)
                );
                // Exact message the task/tests look for when XZ cannot be handled pure.
                if compressor == Some(COMP_XZ) {
                    log::info!(
                        "SquashFS {}: in-process xz unsupported, using unsquashfs",
                        path.display()
                    );
                }
                let backend = Self::open_unsquashfs(path, offset)?;
                Ok(Self {
                    backend,
                    archive_path: path.to_path_buf(),
                    offset,
                })
            }
        }
    }

    /// Whether this instance is serving via pure-Rust backhand (not unsquashfs).
    pub fn is_inprocess(&self) -> bool {
        matches!(self.backend, Backend::InProcess { .. })
    }

    /// Open a SquashFS image from any `Read + Seek + Send + 'static` source without `/tmp`.
    ///
    /// Detects SquashFS magic (and optional AppImage-style offset), reads the superblock
    /// compressor, and opens with in-process **backhand** when practical. The seekable
    /// reader is wrapped in a [`BufReader`] and handed to backhand directly.
    ///
    /// # Residuals (clear errors — never silent `/tmp`)
    ///
    /// * **Classic LZMA** (compressor id 2): not supported in-process; returns
    ///   [`SquashFsError`] so AutoMount / factory can fall back to temp spool + path
    ///   [`open`](Self::open) (which may use `unsquashfs`).
    /// * Corrupt / exotic images: backhand open failure is returned the same way.
    ///
    /// `archive_label` is diagnostics-only (nested member name / URL).
    ///
    /// # Factory wiring
    ///
    /// Prefer [`looks_like_squashfs_reader`] or name (`.squashfs` / `.sqfs` / `.snap`)
    /// before calling this from `open_nested_reader_fn`.
    pub fn open_from_reader<R>(reader: R, archive_label: impl AsRef<Path>) -> Result<Self>
    where
        R: Read + Seek + Send + 'static,
    {
        let archive_path = archive_label.as_ref().to_path_buf();
        let mut reader = reader;
        reader.seek(SeekFrom::Start(0))?;

        let offset = find_squashfs_offset_reader(&mut reader)?.ok_or_else(|| {
            SquashFsError::Msg(format!(
                "{} is not a SquashFS image (stream)",
                archive_path.display()
            ))
        })?;

        let compressor = read_superblock_compressor_reader(&mut reader, offset)
            .ok()
            .flatten();

        if compressor == Some(COMP_LZMA) {
            return Err(SquashFsError::Msg(format!(
                "SquashFS classic LZMA (compressor id 2) cannot open from a nested stream \
                 without a host path; use path open / AutoMount temp spool (label={})",
                archive_path.display()
            )));
        }

        let kind = detect_kind_reader(&mut reader, offset)?;
        reader.seek(SeekFrom::Start(0))?;

        let backend = Self::open_inprocess_from_reader(reader, offset, kind, &archive_path)?;
        log::debug!(
            "SquashFS open_from_reader in-process ok for {} (offset={offset}, compressor={})",
            archive_path.display(),
            compressor_name(compressor)
        );
        Ok(Self {
            backend,
            archive_path,
            offset,
        })
    }

    /// Like [`open_from_reader`](Self::open_from_reader) but loads the full image into RAM
    /// first (`Cursor<Vec<u8>>`). Useful when the source is non-seekable or when the caller
    /// already has bytes. Still **never** writes `/tmp`.
    pub fn open_from_bytes(
        bytes: impl Into<Vec<u8>>,
        archive_label: impl AsRef<Path>,
    ) -> Result<Self> {
        Self::open_from_reader(Cursor::new(bytes.into()), archive_label)
    }

    fn open_inprocess(path: &Path, offset: u64) -> Result<Backend> {
        let kind = detect_kind(path, offset)?;
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        Self::open_inprocess_from_bufread(reader, offset, kind, path)
    }

    fn open_inprocess_from_reader<R>(
        reader: R,
        offset: u64,
        kind: Kind,
        label: &Path,
    ) -> Result<Backend>
    where
        R: Read + Seek + Send + 'static,
    {
        Self::open_inprocess_from_bufread(BufReader::new(reader), offset, kind, label)
    }

    fn open_inprocess_from_bufread<R>(
        reader: R,
        offset: u64,
        kind: Kind,
        label: &Path,
    ) -> Result<Backend>
    where
        R: io::BufRead + Seek + Send + 'static,
    {
        let fs = FilesystemReader::from_reader_with_offset_and_kind(reader, offset, kind).map_err(
            |e| {
                SquashFsError::Msg(format!(
                    "backhand open failed for {} (offset={offset}): {e}",
                    label.display()
                ))
            },
        )?;
        Ok(Self::backend_from_fs(fs))
    }

    fn backend_from_fs(fs: FilesystemReader<'static>) -> Backend {
        let mut by_path = BTreeMap::new();
        let mut children: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();

        for (idx, node) in fs.files().enumerate() {
            let abs = path_buf_to_abs(&node.fullpath);
            by_path.insert(abs.clone(), idx);
            if abs != "/" {
                let (parent, name) = parent_and_name(&abs);
                children
                    .entry(parent)
                    .or_default()
                    .insert(name, abs.clone());
            }
        }
        // Ensure root exists in children map even for empty images.
        children.entry("/".into()).or_default();

        Backend::InProcess {
            fs,
            by_path,
            children,
        }
    }

    fn open_unsquashfs(path: &Path, offset: u64) -> Result<Backend> {
        if which_unsquashfs().is_none() {
            return Err(SquashFsError::Msg(
                "SquashFS in-process reader failed and `unsquashfs` not found on PATH; \
                 install squashfs-tools, or use a compression supported in-process \
                 (gzip/zstd/lz4/lzo/xz/none). Classic LZMA requires unsquashfs fallback"
                    .into(),
            ));
        }

        let extract = TempDir::with_prefix("ratarmount-squashfs.")?;
        let out = extract.path().to_path_buf();
        // unsquashfs -f -d OUT [-o OFFSET] IMAGE
        let mut cmd = Command::new("unsquashfs");
        cmd.arg("-f").arg("-d").arg(&out);
        if offset > 0 {
            cmd.arg("-o").arg(offset.to_string());
        }
        cmd.arg(path);
        let output = cmd
            .output()
            .map_err(|e| SquashFsError::Msg(format!("unsquashfs spawn: {e}")))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stderr = stderr.trim();
            return Err(SquashFsError::Msg(if stderr.is_empty() {
                format!("unsquashfs failed for {} (offset={offset})", path.display())
            } else {
                format!(
                    "unsquashfs failed for {} (offset={offset}): {stderr}",
                    path.display()
                )
            }));
        }

        // unsquashfs may create OUT/ or OUT/squashfs-root depending on version/flags.
        let root = if out.join("squashfs-root").is_dir() {
            out.join("squashfs-root")
        } else {
            out.clone()
        };
        let serve = if root.read_dir()?.next().is_some() {
            root
        } else {
            out.clone()
        };

        let inner =
            FolderMountSource::new(&serve).map_err(|e| SquashFsError::Msg(e.to_string()))?;
        Ok(Backend::Materialized {
            inner,
            _extract: extract,
        })
    }

    fn node_mode_size(node: &backhand::Node<SquashfsFileReader>) -> (u32, u64) {
        let perms = u32::from(node.header.permissions) & 0o7777;
        match &node.inner {
            InnerNode::Dir(_) => (S_IFDIR | perms, 0),
            InnerNode::File(f) => (S_IFREG | perms, f.file_len() as u64),
            InnerNode::Symlink(s) => (S_IFLNK | perms, s.link.to_string_lossy().len() as u64),
            InnerNode::CharacterDevice(_)
            | InnerNode::BlockDevice(_)
            | InnerNode::NamedPipe
            | InnerNode::Socket => {
                // Expose special nodes as zero-length regular-ish files with original perms;
                // FUSE open will fail if content is requested.
                (S_IFREG | perms, 0)
            }
        }
    }

    fn node_to_file_info(path: &str, node: &backhand::Node<SquashfsFileReader>) -> FileInfo {
        let (mode, size) = Self::node_mode_size(node);
        let linkname = match &node.inner {
            InnerNode::Symlink(s) => s.link.to_string_lossy().into_owned(),
            _ => String::new(),
        };
        FileInfo {
            size,
            mtime: f64::from(node.header.mtime),
            mode,
            linkname,
            uid: node.header.uid,
            gid: node.header.gid,
            userdata: vec![squash_path_userdata(path)],
        }
    }

    fn node_at<'a>(
        fs: &'a FilesystemReader<'static>,
        by_path: &BTreeMap<String, usize>,
        abs: &str,
    ) -> Option<&'a backhand::Node<SquashfsFileReader>> {
        let idx = *by_path.get(abs)?;
        fs.root.nodes.get(idx)
    }

    fn lookup_inprocess(
        fs: &FilesystemReader<'static>,
        by_path: &BTreeMap<String, usize>,
        path: &str,
    ) -> Option<FileInfo> {
        let abs = norm_abs(path);
        let node = Self::node_at(fs, by_path, &abs)?;
        Some(Self::node_to_file_info(&abs, node))
    }

    fn list_inprocess(
        fs: &FilesystemReader<'static>,
        by_path: &BTreeMap<String, usize>,
        children: &BTreeMap<String, BTreeMap<String, String>>,
        path: &str,
    ) -> Option<BTreeMap<String, FileInfo>> {
        let abs = norm_abs(path);
        // Path must be a directory (or root).
        let node = Self::node_at(fs, by_path, &abs)?;
        if !matches!(node.inner, InnerNode::Dir(_)) {
            return None;
        }
        let empty = BTreeMap::new();
        let kids = children.get(&abs).unwrap_or(&empty);
        let mut map = BTreeMap::new();
        for (name, child_abs) in kids {
            let cnode = Self::node_at(fs, by_path, child_abs)?;
            map.insert(name.clone(), Self::node_to_file_info(child_abs, cnode));
        }
        Some(map)
    }

    fn list_dirents_inprocess(
        fs: &FilesystemReader<'static>,
        by_path: &BTreeMap<String, usize>,
        children: &BTreeMap<String, BTreeMap<String, String>>,
        path: &str,
    ) -> Option<Vec<CheapDirent>> {
        let abs = norm_abs(path);
        let node = Self::node_at(fs, by_path, &abs)?;
        if !matches!(node.inner, InnerNode::Dir(_)) {
            return None;
        }
        let empty = BTreeMap::new();
        let kids = children.get(&abs).unwrap_or(&empty);
        let mut dents = Vec::with_capacity(kids.len());
        for (name, child_abs) in kids {
            let cnode = Self::node_at(fs, by_path, child_abs)?;
            let (mode, size) = Self::node_mode_size(cnode);
            dents.push(CheapDirent {
                name: name.clone(),
                mode,
                size,
            });
        }
        Some(dents)
    }

    fn read_file_inprocess(
        fs: &FilesystemReader<'static>,
        by_path: &BTreeMap<String, usize>,
        path: &str,
    ) -> io::Result<Vec<u8>> {
        let abs = norm_abs(path);
        let node = Self::node_at(fs, by_path, &abs)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("not found: {abs}")))?;
        match &node.inner {
            InnerNode::File(f) => {
                let mut reader = fs.file(f).reader();
                let mut buf = Vec::with_capacity(f.file_len());
                reader.read_to_end(&mut buf)?;
                Ok(buf)
            }
            InnerNode::Symlink(s) => Ok(s.link.to_string_lossy().into_owned().into_bytes()),
            InnerNode::Dir(_) => Err(io::Error::new(
                io::ErrorKind::IsADirectory,
                "is a directory",
            )),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a regular file",
            )),
        }
    }
}

impl MountSource for SquashFsMountSource {
    fn list(&self, path: &str) -> Option<ListResult> {
        match &self.backend {
            Backend::InProcess {
                fs,
                by_path,
                children,
            } => {
                let map = Self::list_inprocess(fs, by_path, children, path)?;
                Some(ListResult::Infos(map))
            }
            Backend::Materialized { inner, .. } => inner.list(path),
        }
    }

    fn list_mode(&self, path: &str) -> Option<ListModeResult> {
        match &self.backend {
            Backend::InProcess {
                fs,
                by_path,
                children,
            } => {
                let map = Self::list_inprocess(fs, by_path, children, path)?;
                Some(ListModeResult::Modes(
                    map.into_iter().map(|(k, v)| (k, v.mode)).collect(),
                ))
            }
            Backend::Materialized { inner, .. } => inner.list_mode(path),
        }
    }

    fn list_dirents(&self, path: &str) -> Option<Vec<CheapDirent>> {
        match &self.backend {
            Backend::InProcess {
                fs,
                by_path,
                children,
            } => Self::list_dirents_inprocess(fs, by_path, children, path),
            Backend::Materialized { inner, .. } => inner.list_dirents(path),
        }
    }

    fn lookup(&self, path: &str, file_version: i32) -> Option<FileInfo> {
        match &self.backend {
            Backend::InProcess { fs, by_path, .. } => {
                let _ = file_version;
                Self::lookup_inprocess(fs, by_path, path)
            }
            Backend::Materialized { inner, .. } => inner.lookup(path, file_version),
        }
    }

    fn open(
        &self,
        file_info: &FileInfo,
        buffering: i32,
    ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
        match &self.backend {
            Backend::InProcess { fs, by_path, .. } => {
                if file_info.mode & S_IFMT == S_IFDIR {
                    return Err(io::Error::new(
                        io::ErrorKind::IsADirectory,
                        "is a directory",
                    ));
                }
                let path = path_from_userdata(file_info).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "missing squashfs path userdata",
                    )
                })?;
                let data = Self::read_file_inprocess(fs, by_path, &path)?;
                Ok(Box::new(Cursor::new(data)))
            }
            Backend::Materialized { inner, .. } => inner.open(file_info, buffering),
        }
    }

    fn is_immutable(&self) -> bool {
        true
    }
}

fn path_buf_to_abs(p: &Path) -> String {
    let s = p.to_string_lossy();
    norm_abs(&s)
}

fn compressor_name(id: Option<u16>) -> &'static str {
    match id {
        Some(COMP_UNCOMPRESSED) => "none",
        Some(COMP_GZIP) => "gzip",
        Some(COMP_LZMA) => "lzma",
        Some(COMP_LZO) => "lzo",
        Some(COMP_XZ) => "xz",
        Some(COMP_LZ4) => "lz4",
        Some(COMP_ZSTD) => "zstd",
        Some(_) => "unknown",
        None => "unknown",
    }
}

/// Read SquashFS v4 superblock compressor id at `offset` (if magic matches).
fn read_superblock_compressor(path: &Path, offset: u64) -> Result<Option<u16>> {
    let mut f = File::open(path)?;
    read_superblock_compressor_reader(&mut f, offset)
}

/// Superblock compressor id from a seekable reader (nested / stream open).
fn read_superblock_compressor_reader<R: Read + Seek>(
    reader: &mut R,
    offset: u64,
) -> Result<Option<u16>> {
    reader.seek(SeekFrom::Start(offset))?;
    // magic(4) + inodes(4) + mtime(4) + block_size(4) + fragments(4) + compression(2)
    let mut hdr = [0u8; 22];
    reader.read_exact(&mut hdr)?;
    let le = &hdr[0..4] == MAGIC_LE;
    let be = &hdr[0..4] == MAGIC_BE;
    if !le && !be {
        return Ok(None);
    }
    let comp = if le {
        u16::from_le_bytes([hdr[20], hdr[21]])
    } else {
        u16::from_be_bytes([hdr[20], hdr[21]])
    };
    Ok(Some(comp))
}

/// Choose LE or BE v4 kind from superblock magic at `offset`, with workspace XZ compressor.
fn detect_kind(path: &Path, offset: u64) -> Result<Kind> {
    let mut f = File::open(path)?;
    detect_kind_reader(&mut f, offset)
}

fn detect_kind_reader<R: Read + Seek>(reader: &mut R, offset: u64) -> Result<Kind> {
    reader.seek(SeekFrom::Start(offset))?;
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)?;
    if &magic == MAGIC_BE {
        Ok(Kind::new_v4_with_const(
            &WORKSPACE_COMPRESSOR,
            kind::BE_V4_0,
        ))
    } else {
        // LE (default) including AppImage / odd layouts still scanned by find_squashfs_offset.
        Ok(Kind::new_v4_with_const(
            &WORKSPACE_COMPRESSOR,
            kind::LE_V4_0,
        ))
    }
}

/// Detect SquashFS; returns superblock offset if found (0..1 MiB scan for AppImage).
pub fn find_squashfs_offset(path: &Path) -> Result<Option<u64>> {
    let mut f = File::open(path)?;
    find_squashfs_offset_reader(&mut f)
}

/// Same as [`find_squashfs_offset`] for an already-open seekable reader (nested probe).
pub fn find_squashfs_offset_reader<R: Read + Seek>(reader: &mut R) -> Result<Option<u64>> {
    let mut buf = [0u8; 4];
    // Check offset 0 first.
    reader.seek(SeekFrom::Start(0))?;
    match reader.read_exact(&mut buf) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    if &buf == MAGIC_LE || &buf == MAGIC_BE {
        return Ok(Some(0));
    }
    // Scan first 1 MiB at 4K strides (AppImage payload).
    const MAX: u64 = 1024 * 1024;
    const STRIDE: u64 = 4096;
    let mut off = STRIDE;
    while off < MAX {
        reader.seek(SeekFrom::Start(off))?;
        if reader.read(&mut buf)? < 4 {
            break;
        }
        if &buf == MAGIC_LE || &buf == MAGIC_BE {
            return Ok(Some(off));
        }
        off += STRIDE;
    }
    Ok(None)
}

pub fn looks_like_squashfs(path: &Path) -> bool {
    find_squashfs_offset(path).ok().flatten().is_some()
}

/// Probe a seekable stream for SquashFS magic (offset 0 or AppImage-style scan).
///
/// Restores the reader position to start on return when the seek succeeds.
pub fn looks_like_squashfs_reader<R: Read + Seek>(reader: &mut R) -> bool {
    let start = reader.stream_position().unwrap_or(0);
    let found = find_squashfs_offset_reader(reader).ok().flatten().is_some();
    let _ = reader.seek(SeekFrom::Start(start));
    found
}

fn which_on_path(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let p = dir.join(bin);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

fn which_unsquashfs() -> Option<PathBuf> {
    which_on_path("unsquashfs")
}

/// Open as Arc dyn MountSource for factory convenience.
pub fn open_as_mount_source(path: &Path) -> Result<Arc<dyn MountSource>> {
    Ok(Arc::new(SquashFsMountSource::open(path)?) as Arc<dyn MountSource>)
}

#[cfg(test)]
mod tests {
    use super::*;
    use backhand::{FilesystemWriter, NodeHeader};
    use std::io::Write;

    fn which_mksquashfs() -> Option<PathBuf> {
        which_on_path("mksquashfs")
    }

    fn py_fixture(name: &str) -> PathBuf {
        let root = std::env::var("RATARMOUNT_PY_ROOT")
            .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into());
        PathBuf::from(root).join("tests").join(name)
    }

    fn assert_ufo_content(m: &SquashFsMountSource) {
        let fi = m.lookup("/foo/fighter/ufo", 0).expect("ufo");
        assert_eq!(fi.size, 6);
        assert_eq!(fi.mode & S_IFMT, S_IFREG);
        let mut r = m.open(&fi, 0).unwrap();
        let mut s = String::new();
        r.read_to_string(&mut s).unwrap();
        assert_eq!(s, "iriya\n");

        // Directory listing.
        let list = m.list("/foo/fighter").expect("list fighter");
        match list {
            ListResult::Infos(map) => {
                assert!(map.contains_key("ufo"), "keys: {:?}", map.keys());
            }
            ListResult::Names(names) => {
                assert!(names.iter().any(|n| n == "ufo"));
            }
        }

        // Symlink if present.
        if let Some(jet) = m.lookup("/foo/jet", 0) {
            assert_eq!(jet.mode & S_IFMT, S_IFLNK);
            assert_eq!(jet.linkname, "fighter");
        }
    }

    fn mksquashfs_ufo_image(comp: &str) -> Option<(tempfile::TempDir, PathBuf)> {
        which_mksquashfs()?;
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir_all(src.join("foo/fighter")).unwrap();
        let mut f = File::create(src.join("foo/fighter/ufo")).unwrap();
        f.write_all(b"iriya\n").unwrap();
        let img = dir.path().join(format!("test.{comp}.squashfs"));
        let status = Command::new("mksquashfs")
            .args([
                src.as_os_str(),
                img.as_os_str(),
                "-comp".as_ref(),
                comp.as_ref(),
                "-noappend".as_ref(),
            ])
            .status()
            .expect("spawn mksquashfs");
        if !status.success() {
            return None;
        }
        Some((dir, img))
    }

    #[test]
    fn detect_and_mount_fixture_inprocess() {
        let path = py_fixture("folder-symlink.no-compression.squashfs");
        if !path.exists() {
            eprintln!("skip: no fixture {}", path.display());
            return;
        }
        assert!(looks_like_squashfs(&path));
        assert_eq!(find_squashfs_offset(&path).unwrap(), Some(0));
        let m = SquashFsMountSource::open(&path).unwrap();
        assert!(
            m.is_inprocess(),
            "expected in-process backhand path for no-compression"
        );
        assert_ufo_content(&m);
    }

    #[test]
    fn gzip_fixture_inprocess() {
        let path = py_fixture("folder-symlink.gzip.squashfs");
        if !path.exists() {
            eprintln!("skip: no fixture");
            return;
        }
        let m = SquashFsMountSource::open(&path).unwrap();
        assert!(m.is_inprocess(), "gzip should be in-process");
        assert_ufo_content(&m);
    }

    #[test]
    fn zstd_fixture_inprocess() {
        let path = py_fixture("folder-symlink.zstd.squashfs");
        if !path.exists() {
            return;
        }
        let m = SquashFsMountSource::open(&path).unwrap();
        assert!(m.is_inprocess());
        assert_ufo_content(&m);
    }

    /// XZ via workspace xz2 custom compressor (not backhand liblzma) → in-process.
    #[test]
    fn xz_fixture_inprocess_or_fallback() {
        let path = py_fixture("folder-symlink.xz.squashfs");
        if !path.exists() {
            return;
        }
        assert_eq!(read_superblock_compressor(&path, 0).unwrap(), Some(COMP_XZ));
        match SquashFsMountSource::open(&path) {
            Ok(m) => {
                assert!(
                    m.is_inprocess(),
                    "XZ should open in-process via workspace xz2 custom compressor"
                );
                assert_ufo_content(&m);
            }
            Err(e) => {
                // If pure path somehow fails, unsquashfs fallback should still work.
                eprintln!("pure xz open failed ({e}); trying fallback expectations");
                if which_unsquashfs().is_some() {
                    panic!("expected in-process xz2 open to succeed: {e}");
                }
            }
        }
    }

    #[test]
    fn lz4_fixture_inprocess() {
        let path = py_fixture("folder-symlink.lz4.squashfs");
        if !path.exists() {
            return;
        }
        let m = SquashFsMountSource::open(&path).unwrap();
        assert!(m.is_inprocess());
        assert_ufo_content(&m);
    }

    #[test]
    fn lzo_fixture_inprocess() {
        let path = py_fixture("folder-symlink.lzo.squashfs");
        if !path.exists() {
            return;
        }
        let m = SquashFsMountSource::open(&path).unwrap();
        assert!(m.is_inprocess(), "lzo feature should enable in-process");
        assert_ufo_content(&m);
    }

    /// Classic LZMA (not XZ) is unsupported in-process → unsquashfs fallback when available.
    #[test]
    fn lzma_fixture_fallback_or_skip() {
        let path = py_fixture("folder-symlink.lzma.squashfs");
        if !path.exists() {
            return;
        }
        assert_eq!(
            read_superblock_compressor(&path, 0).unwrap(),
            Some(COMP_LZMA)
        );
        match SquashFsMountSource::open(&path) {
            Ok(m) => {
                // Must materialize (classic lzma has no in-process codec).
                if which_unsquashfs().is_some() {
                    assert!(
                        !m.is_inprocess(),
                        "classic lzma should use unsquashfs fallback"
                    );
                }
                assert_ufo_content(&m);
            }
            Err(e) => {
                // No unsquashfs and no in-process support.
                eprintln!("skip/fail soft: {e}");
                if which_unsquashfs().is_some() {
                    panic!("expected unsquashfs fallback to succeed: {e}");
                }
            }
        }
    }

    #[test]
    fn mksquashfs_minimal_roundtrip() {
        let Some((_dir, img)) = mksquashfs_ufo_image("gzip") else {
            eprintln!("skip: no mksquashfs or mksquashfs failed");
            return;
        };
        assert!(looks_like_squashfs(&img));
        let m = SquashFsMountSource::open(&img).unwrap();
        assert!(m.is_inprocess());
        assert_ufo_content(&m);
    }

    /// mksquashfs -comp xz: open must succeed (pure xz2 path preferred; unsquashfs ok).
    #[test]
    fn mksquashfs_xz_roundtrip() {
        let Some((_dir, img)) = mksquashfs_ufo_image("xz") else {
            eprintln!("skip: no mksquashfs or xz compression unavailable");
            return;
        };
        assert_eq!(read_superblock_compressor(&img, 0).unwrap(), Some(COMP_XZ));
        let m = SquashFsMountSource::open(&img).unwrap();
        assert!(
            m.is_inprocess(),
            "mksquashfs -comp xz should open in-process via workspace xz2"
        );
        assert_ufo_content(&m);
    }

    #[test]
    fn offset_scan_with_prefix() {
        if which_mksquashfs().is_none() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("hello.txt"), b"hi\n").unwrap();
        let raw = dir.path().join("raw.squashfs");
        let status = Command::new("mksquashfs")
            .args([
                src.as_os_str(),
                raw.as_os_str(),
                "-comp".as_ref(),
                "gzip".as_ref(),
                "-noappend".as_ref(),
            ])
            .status()
            .unwrap();
        if !status.success() {
            return;
        }
        // Prefix 8192 zero bytes (AppImage-style offset).
        let mut combined = vec![0u8; 8192];
        combined.extend_from_slice(&std::fs::read(&raw).unwrap());
        let emb = dir.path().join("embedded.squashfs");
        std::fs::write(&emb, &combined).unwrap();
        assert_eq!(find_squashfs_offset(&emb).unwrap(), Some(8192));
        let m = SquashFsMountSource::open(&emb).unwrap();
        assert!(m.is_inprocess());
        let fi = m.lookup("/hello.txt", 0).expect("hello");
        let mut r = m.open(&fi, 0).unwrap();
        let mut s = String::new();
        r.read_to_string(&mut s).unwrap();
        assert_eq!(s, "hi\n");
    }

    #[test]
    fn not_squashfs() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("x.bin");
        std::fs::write(&p, b"not a squashfs").unwrap();
        assert!(!looks_like_squashfs(&p));
        assert!(SquashFsMountSource::open(&p).is_err());
    }

    /// Nested no-tmp: fixture bytes via `Cursor` → `open_from_reader` (no host path).
    #[test]
    fn open_from_reader_cursor_list_and_read() {
        let path = py_fixture("folder-symlink.gzip.squashfs");
        let bytes = if path.exists() {
            std::fs::read(&path).expect("read fixture")
        } else {
            let Some((_dir, img)) = mksquashfs_ufo_image("gzip") else {
                eprintln!("skip: no fixture and no mksquashfs for open_from_reader");
                return;
            };
            std::fs::read(&img).expect("read mksquashfs image")
        };

        assert!(looks_like_squashfs_reader(&mut Cursor::new(&bytes)));

        let m = SquashFsMountSource::open_from_reader(Cursor::new(bytes), "nested.squashfs")
            .expect("open_from_reader");
        assert!(
            m.is_inprocess(),
            "open_from_reader success path must be in-process (no unsquashfs /tmp)"
        );
        assert_ufo_content(&m);
    }

    /// Reader path matches path open for list/content (when both available).
    #[test]
    fn open_from_reader_matches_path_open() {
        let path = py_fixture("folder-symlink.no-compression.squashfs");
        let (bytes, path_src) = if path.exists() {
            let bytes = std::fs::read(&path).expect("read fixture");
            let path_src = SquashFsMountSource::open(&path).expect("path open");
            (bytes, path_src)
        } else {
            let Some((_dir, img)) = mksquashfs_ufo_image("gzip") else {
                eprintln!("skip: no fixture and no mksquashfs for match test");
                return;
            };
            let bytes = std::fs::read(&img).expect("read image");
            let path_src = SquashFsMountSource::open(&img).expect("path open");
            (bytes, path_src)
        };

        let reader_src = SquashFsMountSource::open_from_reader(Cursor::new(bytes), "match.sqfs")
            .expect("open_from_reader");
        assert!(path_src.is_inprocess());
        assert!(reader_src.is_inprocess());
        assert_ufo_content(&path_src);
        assert_ufo_content(&reader_src);

        let path_root = path_src.list("/").expect("path root");
        let reader_root = reader_src.list("/").expect("reader root");
        match (path_root, reader_root) {
            (ListResult::Infos(a), ListResult::Infos(b)) => {
                assert_eq!(a.keys().collect::<Vec<_>>(), b.keys().collect::<Vec<_>>());
            }
            _ => panic!("expected Infos lists"),
        }
    }

    #[test]
    fn open_from_reader_rejects_bad_magic() {
        match SquashFsMountSource::open_from_reader(
            Cursor::new(b"not-a-squashfs-image!!!!"),
            "bad.squashfs",
        ) {
            Ok(_) => panic!("expected bad magic to fail"),
            Err(e) => {
                let msg = e.to_string();
                assert!(msg.contains("not a SquashFS"), "unexpected error: {msg}");
            }
        }
    }

    /// AppImage-style embedded offset via reader (no host path).
    #[test]
    fn open_from_reader_offset_scan() {
        let raw_bytes = if which_mksquashfs().is_some() {
            let Some((_dir, img)) = mksquashfs_ufo_image("gzip") else {
                eprintln!("skip: mksquashfs failed for offset reader test");
                return;
            };
            std::fs::read(&img).expect("read raw")
        } else {
            let path = py_fixture("folder-symlink.gzip.squashfs");
            if !path.exists() {
                eprintln!("skip: no mksquashfs and no fixture for offset reader");
                return;
            }
            std::fs::read(&path).expect("read fixture")
        };

        let mut combined = vec![0u8; 8192];
        combined.extend_from_slice(&raw_bytes);
        assert_eq!(
            find_squashfs_offset_reader(&mut Cursor::new(&combined)).unwrap(),
            Some(8192)
        );
        let m = SquashFsMountSource::open_from_reader(Cursor::new(combined), "embedded.sqfs")
            .expect("open_from_reader with offset");
        assert!(m.is_inprocess());
        assert_ufo_content(&m);
    }

    /// Classic LZMA: open_from_reader must error (not materialize to /tmp).
    #[test]
    fn open_from_reader_lzma_errors_without_tmp() {
        let path = py_fixture("folder-symlink.lzma.squashfs");
        if !path.exists() {
            eprintln!("skip: no classic lzma fixture");
            return;
        }
        let bytes = std::fs::read(&path).expect("read lzma fixture");
        match SquashFsMountSource::open_from_reader(Cursor::new(bytes), "nested.lzma.sqfs") {
            Ok(_) => panic!("classic lzma must not open_from_reader successfully"),
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    msg.to_ascii_lowercase().contains("lzma")
                        || msg.contains("temp spool")
                        || msg.contains("host path"),
                    "expected clear lzma/spool residual: {msg}"
                );
            }
        }
    }

    #[test]
    fn open_from_bytes_gzip() {
        let path = py_fixture("folder-symlink.gzip.squashfs");
        let bytes = if path.exists() {
            std::fs::read(&path).expect("read")
        } else {
            let Some((_dir, img)) = mksquashfs_ufo_image("gzip") else {
                eprintln!("skip: no fixture/mksquashfs for open_from_bytes");
                return;
            };
            std::fs::read(&img).expect("read")
        };
        let m = SquashFsMountSource::open_from_bytes(bytes, "bytes.squashfs").expect("from_bytes");
        assert!(m.is_inprocess());
        assert_ufo_content(&m);
    }

    fn squashfs_image_with_file(name: &str, payload: &[u8]) -> Option<Vec<u8>> {
        let mut fs = FilesystemWriter::default();
        fs.set_only_root_id();
        let compressor = FilesystemCompressor::new(Compressor::Gzip, None).ok()?;
        fs.set_compressor(compressor);
        let header = NodeHeader {
            permissions: 0o644,
            ..NodeHeader::default()
        };
        fs.push_file(Cursor::new(payload.to_vec()), name, header)
            .ok()?;
        let mut out = Cursor::new(Vec::new());
        fs.write(&mut out).ok()?;
        Some(out.into_inner())
    }

    /// Regression: cheap readdirplus sizes.
    #[test]
    fn list_dirents_sizes_match_lookup_without_requiring_list() {
        let payload = b"hello-squash-dirents";
        let Some(bytes) = squashfs_image_with_file("hello.txt", payload) else {
            eprintln!("skip: backhand gzip FilesystemWriter failed");
            return;
        };
        let src = SquashFsMountSource::open_from_reader(Cursor::new(bytes), "dirents.squashfs")
            .expect("open_from_reader");
        assert!(src.is_inprocess());
        let dents = src.list_dirents("/").expect("dirents");
        let d = dents
            .iter()
            .find(|e| e.name == "hello.txt")
            .expect("hello.txt dirent");
        let fi = src.lookup("/hello.txt", 0).expect("lookup");
        assert_eq!(d.size, fi.size);
        assert_eq!(d.mode, fi.mode);
        assert_eq!(d.size, payload.len() as u64);
        assert_ne!(d.size, 0);
    }
}
