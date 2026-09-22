//! Seekable zstd / gzip rewriter. No CLI and no SQLite.
//!
//! Zstd output is multi-frame zstd plus an official seek-table footer
//! ([`build_seek_table_skippable`], descriptor byte 0, no per-frame checksum).
//! Gzip output is a byte copy of a gzip input plus a sidecar beside the
//! output. The default sidecar is `.rgzi` only; `.gzidx` and both are opt-in.
//! The body and every sidecar are renamed into place only after the temps are
//! durable, so a failed index leaves the previous files alone. TAR
//! member names are never parsed and never sorted: uncompressed bytes stay in
//! input order, so a two-member TAR stays in offset order.
//!
//! A footer is invented only when frames are packed from offset 0 with no gaps
//! and every size fits `u32`. Copy when the input is already multi-frame with
//! a seek table. Otherwise copy and do not invent a footer (a size above
//! `u32`, a leading skippable frame, or a skippable frame between data
//! frames). A single zstd frame, or gzip/plain bytes aimed at a zstd
//! destination, is recompressed by `zstd::stream::read::Decoder` (or a
//! gzip/plain reader) into [`encode_zstd_frame_to`] of a `frame_size`
//! [`std::io::Read::take`]. `frame_size == 0` or `frame_size > u32::MAX` is
//! an error on that path.
//!
//! The destination suffix picks the family: `.zst` / `.tzst` / `.zstd` /
//! `.tar.zst` / `.tar.zstd`, or `.gz` / `.tgz` / `.gzip` / `.tar.gz`.
//! bzip2, xz, lz4, 7z, zip, and other codecs are a v1 error. Publish is a
//! temp file in the output parent, `sync_all`, then rename. An existing
//! final-component symlink is not followed: without `overwrite` it is refused,
//! and with `overwrite` rename replaces the symlink itself.

use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use flate2::read::MultiGzDecoder;
use tempfile::NamedTempFile;

use crate::gzip_seek::{SeekableGzip, DEFAULT_GZIP_SEEK_SPACING};
use crate::zstd_seek::{
    build_seek_table_skippable, encode_zstd_frame_to, scan_zstd_frames, ZstdFrameMap,
};
use crate::{
    detect_compression_extension, detect_compression_magic, CompressError, CompressionFormat,
    Result,
};

/// Default uncompressed frame size (8 MiB). Matches `split -b 8M` in
/// `docs/zstd-random-access.md`.
pub const DEFAULT_REPACK_FRAME_SIZE: u64 = 8 * 1024 * 1024;

/// Default zstd level for a recompress.
pub const DEFAULT_REPACK_ZSTD_LEVEL: i32 = 3;

/// Gzip index written beside a gzip output. Default is [`GzipSidecar::Rgzi`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GzipSidecar {
    /// `{output}.rgzi`.
    Rgzi,
    /// `{output}.gzidx` (32 KiB windows; opt-in).
    Gzidx,
    /// Both `.rgzi` and `.gzidx`.
    Both,
}

/// Options for [`repack_seekable`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RepackOptions {
    /// Uncompressed bytes per recompressed zstd frame. `0` or above `u32::MAX`
    /// is an error on the recompress path. Ignored when the input is copied.
    pub frame_size: u64,
    /// Zstd compression level for a recompress.
    pub zstd_level: i32,
    /// Sidecar for a gzip destination. Ignored for zstd output.
    pub gzip_sidecar: GzipSidecar,
    /// Replace an existing output file or selected sidecar. A successful gzip
    /// overwrite also removes the sidecar that was not selected. Never follows
    /// a final symlink.
    pub overwrite: bool,
}

impl Default for RepackOptions {
    fn default() -> Self {
        Self {
            frame_size: DEFAULT_REPACK_FRAME_SIZE,
            zstd_level: DEFAULT_REPACK_ZSTD_LEVEL,
            gzip_sidecar: GzipSidecar::Rgzi,
            overwrite: false,
        }
    }
}

/// What [`repack_seekable`] did to the compressed bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepackAction {
    /// At least two frames and a seek-table footer. Output bytes match the input.
    Copied,
    /// At least two frames, no footer, every size fits `u32`. Prefix bytes unchanged.
    SeekTableAppended,
    /// At least two frames and no footer, but a footer must not be invented.
    ///
    /// A size does not fit `u32`, or the frames are not packed from offset 0
    /// (a skippable frame before or between data frames). Bytes are copied.
    CopiedWithoutFooter,
    /// Single zstd frame, or gzip/plain input written as zstd, chunked at `frame_size`.
    Recompressed { frames: u32 },
    /// Gzip input copied to a gzip destination; the selected sidecar(s) were written.
    ///
    /// Plain (or any non-gzip) input to a `.gz` destination is an error, not this variant.
    CopiedWithGzipIndex { format: GzipSidecar },
}

/// Lengths after a successful [`repack_seekable`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RepackReport {
    pub action: RepackAction,
    /// On-disk input length.
    pub input_len: u64,
    /// On-disk output length (sidecars not included).
    pub output_len: u64,
    /// Uncompressed payload length.
    pub uncompressed_len: u64,
}

/// Rewrite `input` into a seekable `output`.
///
/// Refuses `input == output` after canonicalizing. Refuses an existing output
/// or sidecar unless [`RepackOptions::overwrite`]. Does not follow a final
/// symlink at `output`.
pub fn repack_seekable(input: &Path, output: &Path, opts: &RepackOptions) -> Result<RepackReport> {
    refuse_same_path(input, output)?;
    let dest = output_family(output)?;
    let kind = classify_input(input)?;
    let sidecars: Vec<PathBuf> = match dest {
        Dest::Gzip => gzip_sidecar_exts(opts.gzip_sidecar)
            .iter()
            .map(|ext| sidecar_path(output, ext))
            .collect(),
        Dest::Zstd => Vec::new(),
    };
    for sidecar in &sidecars {
        refuse_same_path(input, sidecar)?;
    }
    ensure_destination(output, opts.overwrite)?;
    for sidecar in &sidecars {
        ensure_destination(sidecar, opts.overwrite)?;
    }
    match dest {
        Dest::Zstd => repack_zstd_dest(input, output, opts, kind),
        Dest::Gzip => repack_gzip_dest(input, output, opts, kind),
    }
}

/// Invent a footer iff there are at least two frames, no footer span, every
/// size fits in `u32`, and the frames are packed from offset 0 with no gaps.
///
/// A skippable frame before or between data frames makes `compressed_offset`
/// diverge from the sum of `compressed_size`. The seek-table loader places
/// frame *i* at that sum, so inventing a footer would hide a correct scan.
/// `maybe_rebuild_seek_table` never invents; this function is the only inventor.
fn should_invent_seek_table(map: &ZstdFrameMap) -> bool {
    if map.frames.len() < 2 || map.seek_table.is_some() {
        return false;
    }
    if map.frames[0].compressed_offset != 0 {
        return false;
    }
    let packed = map.frames.windows(2).all(|pair| {
        pair[1].compressed_offset == pair[0].compressed_offset + pair[0].compressed_size
    });
    packed
        && map.frames.iter().all(|frame| {
            u32::try_from(frame.compressed_size).is_ok()
                && u32::try_from(frame.uncompressed_size).is_ok()
        })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Dest {
    Zstd,
    Gzip,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum InputKind {
    Zstd,
    Gzip,
    Plain,
}

fn v1_reads_err() -> CompressError {
    CompressError::Msg("repack-seekable v1 reads gzip, zstd, or uncompressed bytes".into())
}

fn v1_gzip_out_err() -> CompressError {
    CompressError::Msg("repack-seekable v1 gzip output is a byte copy of a gzip input".into())
}

fn v1_suffix_err() -> CompressError {
    CompressError::Msg(
        "repack-seekable v1 writes zstd (.zst, .tzst, .zstd, .tar.zst, .tar.zstd) or gzip (.gz, .tgz, .gzip, .tar.gz)".into(),
    )
}

fn output_family(path: &Path) -> Result<Dest> {
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if name.ends_with(".tar.zst")
        || name.ends_with(".tar.zstd")
        || name.ends_with(".tzst")
        || name.ends_with(".zstd")
        || name.ends_with(".zst")
    {
        return Ok(Dest::Zstd);
    }
    if name.ends_with(".tar.gz")
        || name.ends_with(".tgz")
        || name.ends_with(".gzip")
        || name.ends_with(".gz")
    {
        return Ok(Dest::Gzip);
    }
    Err(v1_suffix_err())
}

fn classify_input(path: &Path) -> Result<InputKind> {
    let mut file = File::open(path)?;
    let mut buf = [0u8; 16];
    let n = file.read(&mut buf)?;
    let magic = &buf[..n];
    // 7z and zip are not compression magics, so they would otherwise look plain.
    if is_zip_or_7z(magic) {
        return Err(v1_reads_err());
    }
    match detect_compression_magic(magic)? {
        CompressionFormat::Zstd => Ok(InputKind::Zstd),
        CompressionFormat::Gzip => Ok(InputKind::Gzip),
        CompressionFormat::None => match detect_compression_extension(path) {
            Some(_) => Err(v1_reads_err()),
            None if rejected_extension(path) => Err(v1_reads_err()),
            None => Ok(InputKind::Plain),
        },
        _ => Err(v1_reads_err()),
    }
}

fn is_zip_or_7z(magic: &[u8]) -> bool {
    const SEVEN_Z: [u8; 6] = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];
    if magic.len() >= 6 && magic[..6] == SEVEN_Z {
        return true;
    }
    magic.len() >= 4
        && magic.starts_with(b"PK")
        && matches!(
            (magic[2], magic[3]),
            (0x03, 0x04) | (0x05, 0x06) | (0x07, 0x08) | (0x01, 0x02)
        )
}

fn rejected_extension(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    let name = name.to_ascii_lowercase();
    [".7z", ".zip", ".bz2", ".bzip2", ".xz", ".txz", ".tbz2"]
        .iter()
        .any(|ext| name.ends_with(ext))
}

fn refuse_same_path(input: &Path, output: &Path) -> Result<()> {
    if paths_equal(input, output)? {
        return Err(CompressError::Msg(format!(
            "repack-seekable refuses to write '{}' onto itself",
            input.display()
        )));
    }
    Ok(())
}

fn paths_equal(input: &Path, output: &Path) -> Result<bool> {
    if input == output {
        return Ok(true);
    }
    let in_can = input.canonicalize()?;
    if let Ok(out_can) = output.canonicalize() {
        return Ok(in_can == out_can);
    }
    let Some(name) = output.file_name() else {
        return Err(CompressError::Msg(
            "repack-seekable output path has no file name".into(),
        ));
    };
    if name.is_empty() || name == "." || name == ".." {
        return Err(CompressError::Msg(
            "repack-seekable output path has no file name".into(),
        ));
    }
    let parent = parent_dir(output);
    Ok(parent.canonicalize()?.join(name) == in_can)
}

fn ensure_destination(path: &Path, overwrite: bool) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.is_dir() {
                return Err(CompressError::Msg(format!(
                    "repack-seekable refuses to replace directory '{}'",
                    path.display()
                )));
            }
            if meta.file_type().is_symlink() {
                if !overwrite {
                    return Err(CompressError::Msg(format!(
                        "repack-seekable refuses to follow symlink '{}'",
                        path.display()
                    )));
                }
                return Ok(());
            }
            if !overwrite {
                return Err(CompressError::Msg(format!(
                    "repack-seekable output '{}' already exists",
                    path.display()
                )));
            }
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

fn parent_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    }
}

fn gzip_sidecar_exts(kind: GzipSidecar) -> &'static [&'static str] {
    match kind {
        GzipSidecar::Rgzi => &["rgzi"],
        GzipSidecar::Gzidx => &["gzidx"],
        GzipSidecar::Both => &["rgzi", "gzidx"],
    }
}

fn sidecar_path(output: &Path, ext: &str) -> PathBuf {
    let mut name = output.file_name().unwrap_or_default().to_os_string();
    name.push(".");
    name.push(ext);
    match output.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.join(name),
        _ => PathBuf::from(name),
    }
}

fn repack_zstd_dest(
    input: &Path,
    output: &Path,
    opts: &RepackOptions,
    kind: InputKind,
) -> Result<RepackReport> {
    let input_len = fs::metadata(input)?.len();
    if kind == InputKind::Zstd {
        let mut src = File::open(input)?;
        let map = scan_zstd_frames(&mut src).map_err(|e| {
            CompressError::Msg(format!(
                "repack-seekable: zstd frame sizes are not measurable: {e}"
            ))
        })?;
        let frames = map.frames.len() as u64;
        if map.frames.len() >= 2 && map.seek_table.is_some() {
            let uncompressed_len = sum_uncompressed(&map)?;
            let output_len = write_atomic(output, |out| copy_path(input, out))?;
            return Ok(report(
                RepackAction::Copied,
                input_len,
                output_len,
                uncompressed_len,
                frames,
            ));
        }
        if should_invent_seek_table(&map) {
            let uncompressed_len = sum_uncompressed(&map)?;
            // Sizes fit `u32`: `should_invent_seek_table` just returned true.
            let entries: Vec<(u32, u32)> = map
                .frames
                .iter()
                .map(|frame| {
                    (
                        u32::try_from(frame.compressed_size).expect("compressed size fits u32"),
                        u32::try_from(frame.uncompressed_size).expect("uncompressed size fits u32"),
                    )
                })
                .collect();
            let output_len = write_atomic(output, |out| {
                copy_path(input, out)?;
                out.write_all(&build_seek_table_skippable(&entries))?;
                Ok(())
            })?;
            return Ok(report(
                RepackAction::SeekTableAppended,
                input_len,
                output_len,
                uncompressed_len,
                frames,
            ));
        }
        if map.frames.len() >= 2 && map.seek_table.is_none() {
            let uncompressed_len = sum_uncompressed(&map)?;
            let output_len = write_atomic(output, |out| copy_path(input, out))?;
            return Ok(report(
                RepackAction::CopiedWithoutFooter,
                input_len,
                output_len,
                uncompressed_len,
                frames,
            ));
        }
    }
    recompress_to_output(input, output, opts, kind, input_len)
}

fn repack_gzip_dest(
    input: &Path,
    output: &Path,
    opts: &RepackOptions,
    kind: InputKind,
) -> Result<RepackReport> {
    if kind != InputKind::Gzip {
        return Err(v1_gzip_out_err());
    }
    let input_len = fs::metadata(input)?.len();
    let parent = parent_dir(output);

    // Temps are durable before any final name is replaced. An index error
    // drops the temps and leaves the previous archive and sidecars.
    let mut body = NamedTempFile::new_in(parent)?;
    copy_path(input, body.as_file_mut())?;
    body.as_file_mut().flush()?;
    body.as_file().sync_all()?;

    let indexed = SeekableGzip::open(body.path(), DEFAULT_GZIP_SEEK_SPACING)?;
    let uncompressed_len = indexed.uncompressed_size();
    let blobs = gzip_index_blobs(&indexed, opts.gzip_sidecar);
    drop(indexed);

    let mut sides = Vec::with_capacity(blobs.len());
    for (ext, blob) in gzip_sidecar_exts(opts.gzip_sidecar).iter().zip(blobs) {
        let mut side = NamedTempFile::new_in(parent)?;
        side.write_all(&blob)?;
        side.as_file_mut().flush()?;
        side.as_file().sync_all()?;
        sides.push((side, sidecar_path(output, ext)));
    }

    let output_len = body.as_file().metadata()?.len();
    publish_with_sidecars(body, output, sides)?;
    if opts.overwrite {
        // After the new body is in place. A failed publish restores the
        // previous archive and must leave this sibling alone.
        remove_unselected_gzip_sidecar(output, opts.gzip_sidecar)?;
    }
    Ok(report(
        RepackAction::CopiedWithGzipIndex {
            format: opts.gzip_sidecar,
        },
        input_len,
        output_len,
        uncompressed_len,
        0,
    ))
}

/// `.rgzi` when the selection is gzidx, `.gzidx` when it is rgzi. `Both` keeps both.
fn remove_unselected_gzip_sidecar(output: &Path, kind: GzipSidecar) -> Result<()> {
    let ext = match kind {
        GzipSidecar::Rgzi => "gzidx",
        GzipSidecar::Gzidx => "rgzi",
        GzipSidecar::Both => return Ok(()),
    };
    match fs::remove_file(sidecar_path(output, ext)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

fn gzip_index_blobs(indexed: &SeekableGzip, kind: GzipSidecar) -> Vec<Vec<u8>> {
    match kind {
        GzipSidecar::Rgzi => vec![indexed.export_seek_index_blob()],
        GzipSidecar::Gzidx => vec![indexed.export_indexed_gzip_blob()],
        GzipSidecar::Both => vec![
            indexed.export_seek_index_blob(),
            indexed.export_indexed_gzip_blob(),
        ],
    }
}

/// Rename `body` onto `output`, then each sidecar. If a later rename fails,
/// put the previous files back so a gzip file is not left without its index.
fn publish_with_sidecars(
    body: NamedTempFile,
    output: &Path,
    sides: Vec<(NamedTempFile, PathBuf)>,
) -> Result<()> {
    let output_bak = move_aside(output)?;
    if let Err(e) = persist_replacing(body, output) {
        if let Some(bak) = output_bak.as_deref() {
            restore_backup(output, bak);
        }
        return Err(e);
    }

    let mut done: Vec<(PathBuf, Option<PathBuf>)> = Vec::with_capacity(sides.len());
    for (side, sidecar) in sides {
        let sidecar_bak = match move_aside(&sidecar) {
            Ok(bak) => bak,
            Err(e) => {
                undo_publish(output, &output_bak, &done);
                return Err(e);
            }
        };
        if let Err(e) = persist_replacing(side, &sidecar) {
            let _ = fs::remove_file(&sidecar);
            if let Some(bak) = sidecar_bak.as_deref() {
                restore_backup(&sidecar, bak);
            }
            undo_publish(output, &output_bak, &done);
            return Err(e);
        }
        done.push((sidecar, sidecar_bak));
    }

    if let Some(bak) = output_bak {
        let _ = fs::remove_file(bak);
    }
    for (_, bak) in done {
        if let Some(bak) = bak {
            let _ = fs::remove_file(bak);
        }
    }
    Ok(())
}

fn undo_publish(output: &Path, output_bak: &Option<PathBuf>, done: &[(PathBuf, Option<PathBuf>)]) {
    let _ = fs::remove_file(output);
    if let Some(bak) = output_bak {
        restore_backup(output, bak);
    }
    for (path, bak) in done.iter().rev() {
        let _ = fs::remove_file(path);
        if let Some(bak) = bak {
            restore_backup(path, bak);
        }
    }
}

fn move_aside(path: &Path) -> Result<Option<PathBuf>> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
        Ok(_) => {}
    }
    let (file, bak) = NamedTempFile::new_in(parent_dir(path))?
        .keep()
        .map_err(|e| {
            CompressError::Msg(format!(
                "repack-seekable failed to stage a backup of '{}': {}",
                path.display(),
                e.error
            ))
        })?;
    drop(file);
    if let Err(e) = fs::rename(path, &bak) {
        let _ = fs::remove_file(&bak);
        return Err(e.into());
    }
    Ok(Some(bak))
}

fn restore_backup(dest: &Path, backup: &Path) {
    let _ = fs::remove_file(dest);
    let _ = fs::rename(backup, dest);
}

fn persist_replacing(tmp: NamedTempFile, dest: &Path) -> Result<()> {
    tmp.persist(dest).map_err(|e| {
        CompressError::Msg(format!(
            "repack-seekable failed to publish '{}': {}",
            dest.display(),
            e.error
        ))
    })?;
    Ok(())
}

fn recompress_to_output(
    input: &Path,
    output: &Path,
    opts: &RepackOptions,
    kind: InputKind,
    input_len: u64,
) -> Result<RepackReport> {
    check_frame_size(opts.frame_size)?;
    let mut produced = (0u32, 0u64);
    let output_len = write_atomic(output, |out| {
        produced = recompress_kind(input, out, opts, kind)?;
        Ok(())
    })?;
    let (frames, uncompressed_len) = produced;
    Ok(report(
        RepackAction::Recompressed { frames },
        input_len,
        output_len,
        uncompressed_len,
        u64::from(frames),
    ))
}

fn recompress_kind(
    input: &Path,
    out: &mut File,
    opts: &RepackOptions,
    kind: InputKind,
) -> Result<(u32, u64)> {
    match kind {
        InputKind::Zstd => {
            let file = File::open(input)?;
            let mut dec = zstd::stream::read::Decoder::new(file)
                .map_err(|e| CompressError::Msg(e.to_string()))?;
            recompress_read_to_zstd(&mut dec, out, opts.frame_size, opts.zstd_level)
        }
        InputKind::Gzip => {
            let file = File::open(input)?;
            // Multi-member: a single gzip decoder stops at the first member and
            // would drop the rest of the input byte stream.
            let mut dec = MultiGzDecoder::new(file);
            recompress_read_to_zstd(&mut dec, out, opts.frame_size, opts.zstd_level)
        }
        InputKind::Plain => {
            let mut file = File::open(input)?;
            recompress_read_to_zstd(&mut file, out, opts.frame_size, opts.zstd_level)
        }
    }
}

fn check_frame_size(frame_size: u64) -> Result<()> {
    if frame_size == 0 || frame_size > u64::from(u32::MAX) {
        return Err(CompressError::Msg(format!(
            "repack frame_size {frame_size} must be 1..=u32::MAX"
        )));
    }
    Ok(())
}

/// Stream `dec` into independent zstd frames of at most `frame_size` plain bytes.
///
/// The encoder is fed by `Read::take`, not a buffer of the whole input.
fn recompress_read_to_zstd<R: Read>(
    dec: &mut R,
    out: &mut File,
    frame_size: u64,
    level: i32,
) -> Result<(u32, u64)> {
    let mut entries: Vec<(u32, u32)> = Vec::new();
    let mut uncompressed = 0u64;
    loop {
        let start = out.stream_position()?;
        let mut limited = dec.by_ref().take(frame_size);
        let (comp, plain) = encode_zstd_frame_to(&mut limited, out, level)?;
        if plain == 0 {
            // Encoder::finish emits a frame even when `take` is already at EOF.
            out.flush()?;
            out.seek(SeekFrom::Start(start))?;
            out.set_len(start)?;
            break;
        }
        let comp_u = u32::try_from(comp).map_err(|_| {
            CompressError::Msg(format!(
                "repack compressed frame of {comp} bytes exceeds u32::MAX"
            ))
        })?;
        let plain_u = u32::try_from(plain).map_err(|_| {
            CompressError::Msg(format!(
                "repack uncompressed frame of {plain} bytes exceeds u32::MAX"
            ))
        })?;
        entries.push((comp_u, plain_u));
        uncompressed = uncompressed.checked_add(plain).ok_or_else(|| {
            CompressError::Msg("repack-seekable uncompressed length overflow".into())
        })?;
        if plain < frame_size {
            break;
        }
    }
    out.write_all(&build_seek_table_skippable(&entries))?;
    let frames = u32::try_from(entries.len()).map_err(|_| {
        CompressError::Msg("repack-seekable produced more than u32::MAX frames".into())
    })?;
    Ok((frames, uncompressed))
}

fn sum_uncompressed(map: &ZstdFrameMap) -> Result<u64> {
    let mut n = 0u64;
    for frame in &map.frames {
        n = n.checked_add(frame.uncompressed_size).ok_or_else(|| {
            CompressError::Msg("repack-seekable uncompressed length overflow".into())
        })?;
    }
    Ok(n)
}

fn copy_path(input: &Path, out: &mut File) -> Result<()> {
    let mut src = File::open(input)?;
    io::copy(&mut src, out)?;
    Ok(())
}

fn write_atomic(output: &Path, write_body: impl FnOnce(&mut File) -> Result<()>) -> Result<u64> {
    let mut tmp = NamedTempFile::new_in(parent_dir(output))?;
    write_body(tmp.as_file_mut())?;
    tmp.as_file_mut().flush()?;
    tmp.as_file().sync_all()?;
    let len = tmp.as_file().metadata()?.len();
    persist_replacing(tmp, output)?;
    Ok(len)
}

fn report(
    action: RepackAction,
    input_len: u64,
    output_len: u64,
    uncompressed_len: u64,
    frames: u64,
) -> RepackReport {
    let footer_omitted = matches!(action, RepackAction::CopiedWithoutFooter);
    log::info!(
        "repack-seekable action={action:?} frames={frames} input_len={input_len} output_len={output_len} uncompressed_len={uncompressed_len} footer_omitted_for_u32={footer_omitted}"
    );
    RepackReport {
        action,
        input_len,
        output_len,
        uncompressed_len,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gzip_seek::GzipSeekBlobFormat;
    use crate::zstd_seek::{
        build_seek_table_skippable, encode_zstd_frame, scan_zstd_frames, ZstdFrameInfo,
        ZstdFrameMap,
    };
    use crate::{open_seekable_zstd, try_import_gzip_seek_blob};
    use std::fs::{self, File};
    use std::io::{Read, Seek, SeekFrom, Write};

    fn pack_frames(parts: &[&[u8]], with_seek_table: bool) -> Vec<u8> {
        let mut out = Vec::new();
        let mut entries = Vec::new();
        for part in parts {
            let frame = encode_zstd_frame(part, 3).unwrap();
            entries.push((frame.len() as u32, part.len() as u32));
            out.extend_from_slice(&frame);
        }
        if with_seek_table {
            out.extend_from_slice(&build_seek_table_skippable(&entries));
        }
        out
    }

    fn gzip_bytes(data: &[u8]) -> Vec<u8> {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    fn ustar_header(name: &str, size: u64) -> [u8; 512] {
        let mut header = [0u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        header[100..108].copy_from_slice(b"0000644\0");
        header[108..116].copy_from_slice(b"0000000\0");
        header[116..124].copy_from_slice(b"0000000\0");
        let size_field = format!("{size:011o}\0");
        header[124..136].copy_from_slice(size_field.as_bytes());
        header[136..148].copy_from_slice(b"00000000000\0");
        header[148..156].copy_from_slice(b"        ");
        header[156] = b'0';
        header[257..262].copy_from_slice(b"ustar");
        header[263..265].copy_from_slice(b"00");
        let sum: u32 = header.iter().map(|b| u32::from(*b)).sum();
        let checksum = format!("{sum:06o}\0 ");
        header[148..156].copy_from_slice(checksum.as_bytes());
        header
    }

    fn ustar_member(name: &str, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&ustar_header(name, data.len() as u64));
        out.extend_from_slice(data);
        let pad = (512 - (data.len() % 512)) % 512;
        out.resize(out.len() + pad, 0);
        out
    }

    /// Two ustar members plus the terminating zero blocks. Length is a multiple of 512.
    fn two_member_tar() -> Vec<u8> {
        let mut out = ustar_member("a.txt", b"alpha-payload");
        out.extend(ustar_member("b.txt", b"bravo-payload"));
        out.resize(out.len() + 1024, 0);
        out
    }

    fn ustar_names(data: &[u8]) -> Vec<String> {
        let mut names = Vec::new();
        let mut off = 0usize;
        while off + 512 <= data.len() {
            let block = &data[off..off + 512];
            if block.iter().all(|b| *b == 0) {
                break;
            }
            if &block[257..262] != b"ustar" {
                break;
            }
            let end = block[..100].iter().position(|b| *b == 0).unwrap_or(100);
            names.push(String::from_utf8_lossy(&block[..end]).into_owned());
            let size = parse_octal(&block[124..136]);
            let data_pad = (512 - (size % 512)) % 512;
            off += 512 + size + data_pad;
        }
        names
    }

    fn parse_octal(field: &[u8]) -> usize {
        let end = field
            .iter()
            .position(|b| *b == 0 || *b == b' ')
            .unwrap_or(field.len());
        let text = std::str::from_utf8(&field[..end]).unwrap_or("0");
        usize::from_str_radix(text, 8).unwrap_or(0)
    }

    #[test]
    fn repack_copies_multiframe_with_seek_table() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("in.zst");
        let output = dir.path().join("out.zst");
        let bytes = pack_frames(&[b"one", b"two-two", b"three"], true);
        fs::write(&input, &bytes).unwrap();
        let report = repack_seekable(&input, &output, &RepackOptions::default()).unwrap();
        assert_eq!(report.action, RepackAction::Copied);
        assert_eq!(fs::read(&output).unwrap(), bytes);
        assert_eq!(report.input_len, report.output_len);
    }

    #[test]
    fn repack_appends_seek_table_without_touching_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("in.zst");
        let output = dir.path().join("out.zst");
        let bytes = pack_frames(&[b"alpha", b"beta-beta", b"gamma"], false);
        fs::write(&input, &bytes).unwrap();
        let report = repack_seekable(&input, &output, &RepackOptions::default()).unwrap();
        assert_eq!(report.action, RepackAction::SeekTableAppended);
        let out = fs::read(&output).unwrap();
        assert!(out.len() > bytes.len());
        assert_eq!(&out[..bytes.len()], bytes.as_slice());
        let body = open_seekable_zstd(&output).unwrap();
        // `open_seekable_zstd` returns `Arc<dyn SeekableBody>`, so
        // `SeekableZstd::used_seek_table` is not callable. `kind` is that flag.
        assert_eq!(body.kind(), "zstd-seek-table");
        let mut reader = body.open_reader().unwrap();
        reader.seek(SeekFrom::Start(b"alpha".len() as u64)).unwrap();
        let mut byte = [0u8; 1];
        reader.read_exact(&mut byte).unwrap();
        assert_eq!(byte, [b'b']);
        let mut src = File::open(&output).unwrap();
        let map = scan_zstd_frames(&mut src).unwrap();
        assert!(map.seek_table.is_some());
        assert!(map.frames.len() >= 2);
    }

    /// Regression: a skippable frame between data frames must not gain a seek-table
    /// footer. The loader would place frame 2 at the sum of `cSize` from 0 and
    /// skip the gap.
    #[test]
    fn repack_skippable_gap_copies_without_footer() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("in.zst");
        let output = dir.path().join("out.zst");
        let first = encode_zstd_frame(b"AAAA", 3).unwrap();
        let second = encode_zstd_frame(b"BBBB-second", 3).unwrap();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&first);
        let gap = b"gap!";
        bytes.extend_from_slice(&0x184D_2A50u32.to_le_bytes());
        bytes.extend_from_slice(&(gap.len() as u32).to_le_bytes());
        bytes.extend_from_slice(gap);
        bytes.extend_from_slice(&second);
        fs::write(&input, &bytes).unwrap();

        let report = repack_seekable(&input, &output, &RepackOptions::default()).unwrap();
        assert_eq!(report.action, RepackAction::CopiedWithoutFooter);
        assert_eq!(fs::read(&output).unwrap(), bytes);

        let body = open_seekable_zstd(&output).unwrap();
        assert_ne!(body.kind(), "zstd-seek-table");
        let mut reader = body.open_reader().unwrap();
        reader.seek(SeekFrom::Start(4)).unwrap();
        let mut buf = vec![0u8; b"BBBB-second".len()];
        reader.read_exact(&mut buf).unwrap();
        assert_eq!(buf, b"BBBB-second");
    }

    /// Regression: single-frame zstd recompress round-trips; a random read matches
    /// the source and two ustar members stay in input order.
    #[test]
    fn repack_recompresses_single_frame_and_roundtrips() {
        let tar = two_member_tar();
        let frame_size = 512u64;
        assert_eq!(tar.len() as u64 % frame_size, 0);
        assert!(tar.len() as u64 > frame_size);

        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("in.zst");
        let output = dir.path().join("out.tar.zst");
        let compressed = encode_zstd_frame(&tar, 3).unwrap();
        fs::write(&input, &compressed).unwrap();
        let mut src = File::open(&input).unwrap();
        assert_eq!(scan_zstd_frames(&mut src).unwrap().frames.len(), 1);

        let opts = RepackOptions {
            frame_size,
            ..RepackOptions::default()
        };
        let report = repack_seekable(&input, &output, &opts).unwrap();
        let RepackAction::Recompressed { frames } = report.action else {
            panic!("expected recompress, got {:?}", report.action);
        };
        assert!(frames > 1);

        let mut out_file = File::open(&output).unwrap();
        let map = scan_zstd_frames(&mut out_file).unwrap();
        assert!(map.seek_table.is_some());
        assert_eq!(map.frames.len() as u64, tar.len() as u64 / frame_size);
        assert!(map
            .frames
            .iter()
            .all(|frame| frame.uncompressed_size == frame_size));

        let body = open_seekable_zstd(&output).unwrap();
        assert_eq!(body.kind(), "zstd-seek-table");
        let mut reader = body.open_reader().unwrap();
        let mut got = Vec::new();
        reader.read_to_end(&mut got).unwrap();
        assert_eq!(got, tar);
        assert_eq!(
            ustar_names(&got),
            vec!["a.txt".to_string(), "b.txt".to_string()]
        );

        let at = tar
            .windows(b"bravo-payload".len())
            .position(|window| window == b"bravo-payload")
            .unwrap();
        let mut reader = body.open_reader().unwrap();
        reader.seek(SeekFrom::Start(at as u64)).unwrap();
        let mut buf = vec![0u8; b"bravo-payload".len()];
        reader.read_exact(&mut buf).unwrap();
        assert_eq!(buf, b"bravo-payload");

        // The encoder must be fed by `take(frame_size)`, not a slurped buffer.
        let src_text = include_str!("repack_seekable.rs");
        let prod = src_text.split("mod tests").next().unwrap();
        let fn_body = prod
            .split("fn recompress_read_to_zstd")
            .nth(1)
            .unwrap()
            .split("\nfn ")
            .next()
            .unwrap();
        assert!(
            fn_body.contains(".take(frame_size)"),
            "encoder must be fed by take(frame_size)"
        );
        assert!(
            fn_body.contains("encode_zstd_frame_to(&mut limited"),
            "encode_zstd_frame_to must read the take"
        );
        assert!(!fn_body.contains("decode_zstd_frames_to("));
        assert!(!prod.contains("maybe_rebuild_seek_table("));
    }

    #[test]
    fn should_invent_seek_table_false_when_uncompressed_exceeds_u32() {
        let overflow = u32::MAX as u64 + 1;
        let map = ZstdFrameMap {
            frames: vec![
                ZstdFrameInfo {
                    compressed_offset: 0,
                    uncompressed_offset: 0,
                    compressed_size: 10,
                    uncompressed_size: overflow,
                },
                ZstdFrameInfo {
                    compressed_offset: 10,
                    uncompressed_offset: overflow,
                    compressed_size: 10,
                    uncompressed_size: 10,
                },
            ],
            seek_table: None,
        };
        assert!(!should_invent_seek_table(&map));

        let mut fits = map.clone();
        fits.frames[0].uncompressed_size = 10;
        fits.frames[1].uncompressed_offset = 10;
        assert!(should_invent_seek_table(&fits));
        let mut gapped = fits.clone();
        gapped.frames[1].compressed_offset += 1;
        assert!(!should_invent_seek_table(&gapped));
        fits.seek_table = Some(0..1);
        assert!(!should_invent_seek_table(&fits));
    }

    #[test]
    fn repack_gzip_copy_writes_rgzi() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("in.gz");
        let output = dir.path().join("out.gz");
        let raw = b"hello gzip repack";
        let gz = gzip_bytes(raw);
        fs::write(&input, &gz).unwrap();
        let report = repack_seekable(&input, &output, &RepackOptions::default()).unwrap();
        assert_eq!(
            report.action,
            RepackAction::CopiedWithGzipIndex {
                format: GzipSidecar::Rgzi,
            }
        );
        assert_eq!(fs::read(&output).unwrap(), gz);
        assert_eq!(report.uncompressed_len, raw.len() as u64);
        let rgzi = dir.path().join("out.gz.rgzi");
        let parsed = try_import_gzip_seek_blob(&fs::read(&rgzi).unwrap()).unwrap();
        assert_eq!(parsed.uncompressed_size, raw.len() as u64);
        assert!(!dir.path().join("out.gz.gzidx").exists());
    }

    #[test]
    fn repack_gzip_copy_writes_gzidx_and_both() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("in.gz");
        let raw = b"hello gzip sidecars";
        let gz = gzip_bytes(raw);
        fs::write(&input, &gz).unwrap();

        let gzidx_out = dir.path().join("only.gz");
        let gzidx_opts = RepackOptions {
            gzip_sidecar: GzipSidecar::Gzidx,
            ..RepackOptions::default()
        };
        let report = repack_seekable(&input, &gzidx_out, &gzidx_opts).unwrap();
        assert_eq!(
            report.action,
            RepackAction::CopiedWithGzipIndex {
                format: GzipSidecar::Gzidx,
            }
        );
        assert_eq!(fs::read(&gzidx_out).unwrap(), gz);
        assert!(!dir.path().join("only.gz.rgzi").exists());
        let gzidx = fs::read(dir.path().join("only.gz.gzidx")).unwrap();
        let parsed = try_import_gzip_seek_blob(&gzidx).unwrap();
        assert_eq!(parsed.format, GzipSeekBlobFormat::IndexedGzip);
        assert_eq!(parsed.uncompressed_size, raw.len() as u64);

        let both_out = dir.path().join("both.gz");
        let both_opts = RepackOptions {
            gzip_sidecar: GzipSidecar::Both,
            ..RepackOptions::default()
        };
        let report = repack_seekable(&input, &both_out, &both_opts).unwrap();
        assert_eq!(
            report.action,
            RepackAction::CopiedWithGzipIndex {
                format: GzipSidecar::Both,
            }
        );
        assert_eq!(fs::read(&both_out).unwrap(), gz);
        let rgzi =
            try_import_gzip_seek_blob(&fs::read(dir.path().join("both.gz.rgzi")).unwrap()).unwrap();
        assert_eq!(rgzi.format, GzipSeekBlobFormat::Rgzi);
        let both_gzidx =
            try_import_gzip_seek_blob(&fs::read(dir.path().join("both.gz.gzidx")).unwrap())
                .unwrap();
        assert_eq!(both_gzidx.format, GzipSeekBlobFormat::IndexedGzip);
    }

    /// Overwrite with gzidx drops a stale `.rgzi`. The new `.gzidx` is the index
    /// of the new body. A failed publish leaves the previous archive and both sidecars.
    #[test]
    fn repack_gzip_overwrite_gzidx_drops_stale_rgzi() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("in.gz");
        let output = dir.path().join("out.gz");
        let rgzi = dir.path().join("out.gz.rgzi");
        let gzidx = dir.path().join("out.gz.gzidx");
        let new_raw = b"new-gzip-body";
        let new_gz = gzip_bytes(new_raw);
        fs::write(&input, &new_gz).unwrap();
        fs::write(&output, gzip_bytes(b"old-gzip-body")).unwrap();
        fs::write(&rgzi, b"old-rgzi").unwrap();
        fs::write(&gzidx, b"old-gzidx").unwrap();

        let opts = RepackOptions {
            gzip_sidecar: GzipSidecar::Gzidx,
            overwrite: true,
            ..RepackOptions::default()
        };
        let report = repack_seekable(&input, &output, &opts).unwrap();
        assert_eq!(
            report.action,
            RepackAction::CopiedWithGzipIndex {
                format: GzipSidecar::Gzidx,
            }
        );
        assert_eq!(fs::read(&output).unwrap(), new_gz);
        assert!(!rgzi.exists(), "stale .rgzi must not describe the new gzip");
        let indexed = SeekableGzip::open(&output, DEFAULT_GZIP_SEEK_SPACING).unwrap();
        assert_eq!(indexed.uncompressed_size(), new_raw.len() as u64);
        assert_eq!(
            fs::read(&gzidx).unwrap(),
            indexed.export_indexed_gzip_blob()
        );

        let fail_in = dir.path().join("bad.gz");
        let fail_out = dir.path().join("fail.gz");
        let fail_rgzi = dir.path().join("fail.gz.rgzi");
        let fail_gzidx = dir.path().join("fail.gz.gzidx");
        fs::write(&fail_in, b"\x1f\x8b").unwrap();
        fs::write(&fail_out, b"old-archive").unwrap();
        fs::write(&fail_rgzi, b"old-rgzi").unwrap();
        fs::write(&fail_gzidx, b"old-gzidx").unwrap();
        assert!(repack_seekable(&fail_in, &fail_out, &opts).is_err());
        assert_eq!(fs::read(&fail_out).unwrap(), b"old-archive");
        assert_eq!(fs::read(&fail_rgzi).unwrap(), b"old-rgzi");
        assert_eq!(fs::read(&fail_gzidx).unwrap(), b"old-gzidx");
    }

    #[test]
    fn repack_plain_to_gz_is_error() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("plain.txt");
        let output = dir.path().join("out.gz");
        fs::write(&input, b"not gzip").unwrap();
        let err = repack_seekable(&input, &output, &RepackOptions::default()).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("v1"), "{msg}");
        assert!(
            !msg.contains("CopiedWithGzipIndex"),
            "plain to .gz must not be CopiedWithGzipIndex: {msg}"
        );
        assert!(!output.exists());
    }

    #[test]
    fn repack_refuses_same_path_and_existing_output() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("in.zst");
        let bytes = pack_frames(&[b"one", b"two"], true);
        fs::write(&input, &bytes).unwrap();

        let err = repack_seekable(&input, &input, &RepackOptions::default()).unwrap_err();
        assert!(err.to_string().contains("itself"), "{err}");
        assert_eq!(fs::read(&input).unwrap(), bytes);

        let dotted = dir.path().join(".").join("in.zst");
        let err = repack_seekable(&input, &dotted, &RepackOptions::default()).unwrap_err();
        assert!(err.to_string().contains("itself"), "{err}");
        assert_eq!(fs::read(&input).unwrap(), bytes);

        let output = dir.path().join("out.zst");
        fs::write(&output, b"keep-me").unwrap();
        let err = repack_seekable(&input, &output, &RepackOptions::default()).unwrap_err();
        assert!(err.to_string().contains("already exists"), "{err}");
        assert_eq!(fs::read(&output).unwrap(), b"keep-me");

        let opts = RepackOptions {
            overwrite: true,
            ..RepackOptions::default()
        };
        let err = repack_seekable(&input, &input, &opts).unwrap_err();
        assert!(err.to_string().contains("itself"), "{err}");

        let report = repack_seekable(&input, &output, &opts).unwrap();
        assert_eq!(report.action, RepackAction::Copied);
        assert_eq!(fs::read(&output).unwrap(), bytes);

        #[cfg(unix)]
        {
            let precious = dir.path().join("precious.zst");
            fs::write(&precious, b"precious").unwrap();
            let link = dir.path().join("link.zst");
            std::os::unix::fs::symlink(&precious, &link).unwrap();
            let err = repack_seekable(&input, &link, &RepackOptions::default()).unwrap_err();
            assert!(err.to_string().contains("symlink"), "{err}");
            assert_eq!(fs::read(&precious).unwrap(), b"precious");

            repack_seekable(&input, &link, &opts).unwrap();
            assert_eq!(fs::read(&precious).unwrap(), b"precious");
            assert!(!fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink());
            assert_eq!(fs::read(&link).unwrap(), bytes);
        }
    }

    #[test]
    fn repack_rejects_bzip2_input() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("in.bz2");
        let output = dir.path().join("out.zst");
        let mut enc = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::fast());
        enc.write_all(b"bz-payload").unwrap();
        fs::write(&input, enc.finish().unwrap()).unwrap();
        let err = repack_seekable(&input, &output, &RepackOptions::default()).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("v1"), "{msg}");
        assert!(!output.exists());
    }

    #[test]
    fn repack_rejects_frame_size_above_u32() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("plain.txt");
        let output = dir.path().join("out.zst");
        fs::write(&input, b"hello").unwrap();
        let opts = RepackOptions {
            frame_size: u32::MAX as u64 + 1,
            ..RepackOptions::default()
        };
        let err = repack_seekable(&input, &output, &opts).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("u32"), "{msg}");
        assert!(!output.exists());
    }

    #[test]
    fn repack_rejects_frame_size_zero() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("plain.txt");
        let output = dir.path().join("out.zst");
        let original = b"hello";
        fs::write(&input, original).unwrap();
        let opts = RepackOptions {
            frame_size: 0,
            ..RepackOptions::default()
        };
        let err = repack_seekable(&input, &output, &opts).unwrap_err();
        assert!(err.to_string().contains("frame_size"), "{err}");
        assert_eq!(fs::read(&input).unwrap(), original);
        assert!(!output.exists());
    }

    /// Regression: a failed gzip index must not replace an existing archive or `.rgzi`.
    #[test]
    fn repack_gzip_index_failure_keeps_existing_output() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("in.gz");
        fs::write(&input, b"\x1f\x8b").unwrap();
        let output = dir.path().join("out.gz");
        let sidecar = dir.path().join("out.gz.rgzi");
        fs::write(&output, b"old-archive").unwrap();
        fs::write(&sidecar, b"old-index").unwrap();
        let opts = RepackOptions {
            overwrite: true,
            ..RepackOptions::default()
        };
        assert!(repack_seekable(&input, &output, &opts).is_err());
        assert_eq!(fs::read(&output).unwrap(), b"old-archive");
        assert_eq!(fs::read(&sidecar).unwrap(), b"old-index");
    }
}
