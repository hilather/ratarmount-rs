//! Offline producer: rewrite a stream as randomly-accessible zstd (or gzip + sidecar).
//!
//! Default output is independent zstd frames plus an official seek-table footer
//! (magic [`crate::SEEKABLE_MAGIC`]). Already-chunked zstd is copied, not recompressed,
//! unless [`RepackOptions::force`] is set.

use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};

#[cfg(test)]
use std::cell::Cell;

use flate2::read::MultiGzDecoder;
use log::warn;

use crate::gzip_seek::{SeekableGzip, DEFAULT_GZIP_SEEK_SPACING};
use crate::zstd_seek::{
    build_seek_table_skippable, encode_zstd_frame_to, scan_zstd_frames_path, ZstdFrameInfo,
    ZstdFrameMap,
};
use crate::{detect_compression, CompressError, CompressionFormat, Result};

/// Default uncompressed bytes per output zstd frame (8 MiB).
pub const DEFAULT_REPACK_FRAME_SIZE: u64 = 8 * 1024 * 1024;

/// Encode / copy options for [`repack_seekable`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepackOptions {
    /// Uncompressed bytes per output zstd frame.
    pub frame_size: u64,
    /// zstd compression level (passed to [`encode_zstd_frame_to`]).
    pub level: i32,
    /// Keep gzip bytes and write a sibling `*.rgzi` (and optional GZIDX) sidecar.
    pub keep_gzip: bool,
    /// Also write `{OUT}.gzidx` via [`SeekableGzip::export_indexed_gzip_blob`].
    pub write_gzidx: bool,
    /// Recompress into `frame_size` windows even when input is already multi-frame.
    pub force: bool,
}

impl Default for RepackOptions {
    fn default() -> Self {
        Self {
            frame_size: DEFAULT_REPACK_FRAME_SIZE,
            level: 3,
            keep_gzip: false,
            write_gzidx: false,
            force: false,
        }
    }
}

/// What [`repack_seekable`] did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RepackOutcome {
    /// `IN == OUT` and the file already had a seek table (no tmp+rename).
    DidNothing,
    CopiedExistingSeekable,
    AppendedSeekTable,
    /// Input already multi-frame but a frame exceeded `u32`; bytes copied; no footer.
    CopiedWithoutSeekTable,
    Recompressed {
        frames: usize,
        uncompressed: u64,
        /// False if a recompressed frame exceeded `u32` and the footer was omitted.
        wrote_seek_table: bool,
    },
    WroteGzipSidecar {
        points: usize,
    },
}

/// Make `input` randomly accessible as `output`.
///
/// v1 codecs: uncompressed, gzip, zstd. Other formats return
/// [`CompressError::Unsupported`].
pub fn repack_seekable(input: &Path, output: &Path, opts: &RepackOptions) -> Result<RepackOutcome> {
    if opts.frame_size == 0 || opts.frame_size > u64::from(u32::MAX) {
        return Err(CompressError::Msg(
            "repack frame size must be between 1 and u32::MAX".into(),
        ));
    }
    let format = detect_compression(input)?;
    if opts.keep_gzip && format != CompressionFormat::Gzip {
        return Err(CompressError::Msg("keep_gzip requires a gzip input".into()));
    }
    if opts.write_gzidx && !opts.keep_gzip {
        return Err(CompressError::Msg("write_gzidx requires keep_gzip".into()));
    }
    match format {
        CompressionFormat::Gzip if opts.keep_gzip => write_gzip_sidecar(input, output, opts),
        CompressionFormat::Gzip => {
            let file = File::open(input)?;
            let decoder = MultiGzDecoder::new(BufReader::new(file));
            recompress_to_zstd(decoder, output, opts)
        }
        CompressionFormat::Zstd => repack_zstd(input, output, opts),
        CompressionFormat::None => {
            let file = File::open(input)?;
            recompress_to_zstd(BufReader::new(file), output, opts)
        }
        other => Err(CompressError::Unsupported(unsupported_format(other))),
    }
}

fn unsupported_format(format: CompressionFormat) -> &'static str {
    match format {
        CompressionFormat::Bzip2 => "repack-seekable v1 does not rewrite bzip2",
        CompressionFormat::Xz => "repack-seekable v1 does not rewrite xz",
        CompressionFormat::Lz4 => "repack-seekable v1 does not rewrite lz4",
        CompressionFormat::Lzip => "repack-seekable v1 does not rewrite lzip",
        CompressionFormat::Lzo => "repack-seekable v1 does not rewrite lzo",
        CompressionFormat::CompressZ => "repack-seekable v1 does not rewrite compress .Z",
        CompressionFormat::Lzma => "repack-seekable v1 does not rewrite lzma",
        CompressionFormat::Zlib => "repack-seekable v1 does not rewrite zlib",
        CompressionFormat::Lrzip => "repack-seekable v1 does not rewrite lrzip",
        CompressionFormat::None | CompressionFormat::Gzip | CompressionFormat::Zstd => {
            "repack-seekable v1 supports uncompressed, gzip, and zstd only"
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ZstdPlan {
    CopySeekable,
    AppendOrCopy,
    Recompress,
}

fn zstd_plan(map: &ZstdFrameMap, force: bool) -> ZstdPlan {
    if force {
        return ZstdPlan::Recompress;
    }
    if map.seek_table.is_some() {
        return ZstdPlan::CopySeekable;
    }
    if map.frames.len() > 1 {
        return ZstdPlan::AppendOrCopy;
    }
    ZstdPlan::Recompress
}

fn repack_zstd(input: &Path, output: &Path, opts: &RepackOptions) -> Result<RepackOutcome> {
    if !opts.force {
        let map = scan_zstd_frames_path(input)?;
        match zstd_plan(&map, false) {
            ZstdPlan::CopySeekable => {
                if paths_are_same(input, output) {
                    return Ok(RepackOutcome::DidNothing);
                }
                copy_file_sync(input, output)?;
                return Ok(RepackOutcome::CopiedExistingSeekable);
            }
            ZstdPlan::AppendOrCopy => return append_or_copy_zstd(input, output, &map),
            ZstdPlan::Recompress => {}
        }
    }
    let file = File::open(input)?;
    let decoder = zstd::stream::read::Decoder::new(BufReader::new(file))?;
    recompress_to_zstd(decoder, output, opts)
}

/// Copy data frames; append a seek table when every `cSize`/`dSize` fits `u32`.
fn append_or_copy_zstd(input: &Path, output: &Path, map: &ZstdFrameMap) -> Result<RepackOutcome> {
    let last = map
        .frames
        .last()
        .ok_or_else(|| CompressError::Msg("no zstd frames found".into()))?;
    let frames_end = last
        .compressed_offset
        .checked_add(last.compressed_size)
        .ok_or_else(|| CompressError::Msg("zstd frame size overflow".into()))?;
    match maybe_build_seek_table(&map.frames) {
        Some(table) => {
            write_output_tmp(output, |dst| {
                copy_prefix(input, dst, frames_end)?;
                dst.write_all(&table)?;
                Ok(())
            })?;
            Ok(RepackOutcome::AppendedSeekTable)
        }
        None => {
            if paths_are_same(input, output) {
                let len = File::open(input)?.metadata()?.len();
                if len == frames_end {
                    return Ok(RepackOutcome::CopiedWithoutSeekTable);
                }
            }
            write_output_tmp(output, |dst| copy_prefix(input, dst, frames_end))?;
            Ok(RepackOutcome::CopiedWithoutSeekTable)
        }
    }
}

fn maybe_build_seek_table(frames: &[ZstdFrameInfo]) -> Option<Vec<u8>> {
    #[cfg(test)]
    if FORCE_SEEK_TABLE_OVERFLOW.with(Cell::get) {
        warn!("dropping zstd seek table: frame size exceeds u32");
        return None;
    }
    let entries = try_seek_table_entries(frames)?;
    Some(build_seek_table_skippable(&entries))
}

/// Seek-table `cSize` is the compressed-offset span (includes skippable gaps),
/// matching live-commit `maybe_rebuild_seek_table`.
fn try_seek_table_entries(frames: &[ZstdFrameInfo]) -> Option<Vec<(u32, u32)>> {
    let mut entries = Vec::with_capacity(frames.len());
    for (i, f) in frames.iter().enumerate() {
        let c_raw = if i + 1 < frames.len() {
            frames[i + 1]
                .compressed_offset
                .checked_sub(frames[i].compressed_offset)
        } else {
            Some(f.compressed_size)
        };
        let c = match c_raw.and_then(|n| u32::try_from(n).ok()) {
            Some(v) => v,
            None => {
                warn!(
                    "dropping zstd seek table: frame size exceeds u32 (frame {i} compressed span)"
                );
                return None;
            }
        };
        let d = match u32::try_from(f.uncompressed_size) {
            Ok(v) => v,
            Err(_) => {
                warn!(
                    "dropping zstd seek table: frame size exceeds u32 (frame {i} uncompressed {})",
                    f.uncompressed_size
                );
                return None;
            }
        };
        entries.push((c, d));
    }
    Some(entries)
}

#[cfg(test)]
thread_local! {
    // `const { Cell::new(false) }` needs rustc 1.79; workspace MSRV is 1.74.
    #[allow(clippy::missing_const_for_thread_local)]
    static FORCE_SEEK_TABLE_OVERFLOW: Cell<bool> = Cell::new(false);
}

fn recompress_to_zstd<R: Read>(
    mut src: R,
    output: &Path,
    opts: &RepackOptions,
) -> Result<RepackOutcome> {
    let mut entries: Vec<(u64, u64)> = Vec::new();
    let mut wrote_seek_table = true;
    write_output_tmp(output, |dst| {
        loop {
            let mut first = [0u8; 1];
            let n = src.read(&mut first)?;
            if n == 0 {
                break;
            }
            let rest = opts.frame_size.saturating_sub(1);
            let mut chunk = io::Cursor::new(first).chain(src.by_ref().take(rest));
            let (comp, plain) = encode_zstd_frame_to(&mut chunk, dst, opts.level)?;
            entries.push((comp, plain));
            if plain < opts.frame_size {
                break;
            }
        }
        if entries.is_empty() {
            let (comp, plain) = encode_zstd_frame_to(io::empty(), dst, opts.level)?;
            entries.push((comp, plain));
        }
        let mut table_entries = Vec::with_capacity(entries.len());
        let mut overflow = false;
        for &(c, d) in &entries {
            match (u32::try_from(c), u32::try_from(d)) {
                (Ok(c32), Ok(d32)) => table_entries.push((c32, d32)),
                _ => {
                    overflow = true;
                    break;
                }
            }
        }
        if overflow {
            warn!("dropping zstd seek table: frame size exceeds u32");
            wrote_seek_table = false;
        } else {
            dst.write_all(&build_seek_table_skippable(&table_entries))?;
        }
        Ok(())
    })?;
    let uncompressed: u64 = entries.iter().map(|(_, d)| *d).sum();
    Ok(RepackOutcome::Recompressed {
        frames: entries.len(),
        uncompressed,
        wrote_seek_table,
    })
}

fn write_gzip_sidecar(input: &Path, output: &Path, opts: &RepackOptions) -> Result<RepackOutcome> {
    if !paths_are_same(input, output) {
        copy_file_sync(input, output)?;
    }
    let gzip = SeekableGzip::open(output, DEFAULT_GZIP_SEEK_SPACING)?;
    write_bytes_tmp(
        &sidecar_path(output, "rgzi"),
        &gzip.export_seek_index_blob(),
    )?;
    if opts.write_gzidx {
        write_bytes_tmp(
            &sidecar_path(output, "gzidx"),
            &gzip.export_indexed_gzip_blob(),
        )?;
    }
    Ok(RepackOutcome::WroteGzipSidecar {
        points: gzip.checkpoint_count(),
    })
}

fn sidecar_path(output: &Path, ext: &str) -> PathBuf {
    let mut name = output
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_else(|| "out".into());
    name.push(".");
    name.push(ext);
    match output.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.join(name),
        _ => PathBuf::from(name),
    }
}

fn copy_prefix(input: &Path, dst: &mut File, nbytes: u64) -> Result<()> {
    let mut src = File::open(input)?;
    let copied = io::copy(&mut Read::by_ref(&mut src).take(nbytes), dst)?;
    if copied != nbytes {
        return Err(CompressError::Msg(format!(
            "repack short copy: copied {copied}, expected {nbytes}"
        )));
    }
    Ok(())
}

fn copy_file_sync(input: &Path, output: &Path) -> Result<()> {
    write_output_tmp(output, |dst| {
        let mut src = File::open(input)?;
        io::copy(&mut src, dst)?;
        Ok(())
    })
}

fn write_bytes_tmp(path: &Path, bytes: &[u8]) -> Result<()> {
    write_output_tmp(path, |dst| {
        dst.write_all(bytes)?;
        Ok(())
    })
}

fn write_output_tmp<F>(output: &Path, write: F) -> Result<()>
where
    F: FnOnce(&mut File) -> Result<()>,
{
    let tmp = tmp_path_for(output);
    let mut file = File::create(&tmp)?;
    let _guard = TmpGuard(tmp.clone());
    write(&mut file)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&tmp, output)?;
    Ok(())
}

fn tmp_path_for(output: &Path) -> PathBuf {
    let pid = std::process::id();
    let mut name = output
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_else(|| "repack".into());
    name.push(format!(".tmp.{pid}"));
    match output.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.join(name),
        _ => PathBuf::from(name),
    }
}

struct TmpGuard(PathBuf);

impl Drop for TmpGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn paths_are_same(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(ca), Ok(cb)) => ca == cb,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gzip_seek::{
        parse_gzip_seek_index_blob, SeekableGzip, DEFAULT_GZIP_SEEK_SPACING, GZIP_SEEK_INDEX_MAGIC,
        INDEXED_GZIP_INDEX_MAGIC,
    };
    use crate::zstd_seek::{
        encode_zstd_frame, open_seekable_zstd, scan_zstd_frames_path, SEEKABLE_MAGIC,
    };
    use std::io::{Read, Write};

    fn pack_frames(parts: &[&[u8]], with_seek_table: bool) -> Vec<u8> {
        let mut out = Vec::new();
        let mut entries = Vec::new();
        for p in parts {
            let f = encode_zstd_frame(p, 3).unwrap();
            entries.push((f.len() as u32, p.len() as u32));
            out.extend_from_slice(&f);
        }
        if with_seek_table {
            out.extend_from_slice(&build_seek_table_skippable(&entries));
        }
        out
    }

    fn has_seek_table_footer(bytes: &[u8]) -> bool {
        if bytes.len() < 4 {
            return false;
        }
        let n = bytes.len();
        u32::from_le_bytes(bytes[n - 4..].try_into().unwrap()) == SEEKABLE_MAGIC
    }

    fn encode_gz(data: &[u8]) -> Vec<u8> {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    fn tiny_opts() -> RepackOptions {
        RepackOptions {
            frame_size: 32,
            level: 3,
            ..RepackOptions::default()
        }
    }

    fn skippable_frame(payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + payload.len());
        out.extend_from_slice(&0x184D_2A50u32.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn with_forced_seek_table_overflow<T>(f: impl FnOnce() -> T) -> T {
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                FORCE_SEEK_TABLE_OVERFLOW.with(|c| c.set(false));
            }
        }
        FORCE_SEEK_TABLE_OVERFLOW.with(|c| c.set(true));
        let _reset = Reset;
        f()
    }

    /// Regression: already-seekable zstd is copied byte-for-byte (no recompress).
    #[test]
    fn repack_already_seekable() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("in.zst");
        let output = dir.path().join("out.zst");
        let payload = pack_frames(&[b"frame-one-payload!!", b"frame-two-payload!!"], true);
        std::fs::write(&input, &payload).unwrap();

        let outcome = repack_seekable(&input, &output, &tiny_opts()).unwrap();
        assert_eq!(outcome, RepackOutcome::CopiedExistingSeekable);
        let out_bytes = std::fs::read(&output).unwrap();
        assert_eq!(out_bytes, payload);
        assert!(has_seek_table_footer(&out_bytes));

        let body = open_seekable_zstd(&output).unwrap();
        assert_eq!(body.kind(), "zstd-seek-table");
        let mut got = Vec::new();
        body.open_reader().unwrap().read_to_end(&mut got).unwrap();
        assert_eq!(got, b"frame-one-payload!!frame-two-payload!!");
    }

    /// Regression: in-place already-seekable skips tmp+rename.
    #[test]
    fn repack_inplace_did_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("same.zst");
        let payload = pack_frames(&[b"alpha-frame-bytes", b"beta-frame-bytes!"], true);
        std::fs::write(&path, &payload).unwrap();

        #[cfg(unix)]
        let ino_before = {
            use std::os::unix::fs::MetadataExt;
            std::fs::metadata(&path).unwrap().ino()
        };

        let outcome = repack_seekable(&path, &path, &tiny_opts()).unwrap();
        assert_eq!(outcome, RepackOutcome::DidNothing);
        assert_eq!(std::fs::read(&path).unwrap(), payload);

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(std::fs::metadata(&path).unwrap().ino(), ino_before);
        }
    }

    /// Regression: multi-frame zstd without a footer gets an official seek table.
    #[test]
    fn repack_appends_seek_table() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("plain.zst");
        let output = dir.path().join("seekable.zst");
        let parts: [&[u8]; 2] = [b"hello world!!!!", b"second frame payload"];
        let payload = pack_frames(&parts, false);
        std::fs::write(&input, &payload).unwrap();
        assert!(!has_seek_table_footer(&payload));

        let outcome = repack_seekable(&input, &output, &tiny_opts()).unwrap();
        assert_eq!(outcome, RepackOutcome::AppendedSeekTable);
        let out_bytes = std::fs::read(&output).unwrap();
        assert!(has_seek_table_footer(&out_bytes));
        assert_eq!(&out_bytes[..payload.len()], payload.as_slice());

        let map = scan_zstd_frames_path(&output).unwrap();
        assert!(map.seek_table.is_some());
        assert_eq!(map.frames.len(), 2);

        let body = open_seekable_zstd(&output).unwrap();
        assert_eq!(body.kind(), "zstd-seek-table");
        let mut got = Vec::new();
        body.open_reader().unwrap().read_to_end(&mut got).unwrap();
        assert_eq!(got, b"hello world!!!!second frame payload");
    }

    /// Regression: skippable gaps must be folded into seek-table cSize (offset deltas).
    #[test]
    fn repack_appends_seek_table_skippable_gaps() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("gapped.zst");
        let output = dir.path().join("seekable.zst");
        let p0 = b"hello world!!!!";
        let p1 = b"second frame payload";
        let f0 = encode_zstd_frame(p0, 3).unwrap();
        let f1 = encode_zstd_frame(p1, 3).unwrap();
        let skip = skippable_frame(b"skip-meta-padding!!");
        let mut payload = f0.clone();
        payload.extend_from_slice(&skip);
        payload.extend_from_slice(&f1);
        std::fs::write(&input, &payload).unwrap();

        let before = scan_zstd_frames_path(&input).unwrap();
        assert_eq!(before.frames.len(), 2);
        assert!(before.seek_table.is_none());
        assert!(
            before.frames[1].compressed_offset > before.frames[0].compressed_size,
            "fixture must have a skippable gap between data frames"
        );

        let outcome = repack_seekable(&input, &output, &tiny_opts()).unwrap();
        assert_eq!(outcome, RepackOutcome::AppendedSeekTable);

        let after = scan_zstd_frames_path(&output).unwrap();
        assert!(after.seek_table.is_some());
        assert_eq!(
            after.frames[0].compressed_size,
            before.frames[1].compressed_offset - before.frames[0].compressed_offset,
            "cSize must be the offset span, not the data-frame compressed_size"
        );

        let body = open_seekable_zstd(&output).unwrap();
        assert_eq!(body.kind(), "zstd-seek-table");
        let mut got = Vec::new();
        body.open_reader().unwrap().read_to_end(&mut got).unwrap();
        let mut expected = p0.to_vec();
        expected.extend_from_slice(p1);
        assert_eq!(got, expected);
    }

    /// Regression: frame size > u32 copies frames and omits a lying seek table.
    #[test]
    fn repack_drops_table_when_u32_overflow() {
        let oversized = [ZstdFrameInfo {
            compressed_offset: 0,
            uncompressed_offset: 0,
            compressed_size: u32::MAX as u64 + 1,
            uncompressed_size: 10,
        }];
        assert!(try_seek_table_entries(&oversized).is_none());
        assert!(maybe_build_seek_table(&oversized).is_none());

        let too_plain = [ZstdFrameInfo {
            compressed_offset: 0,
            uncompressed_offset: 0,
            compressed_size: 10,
            uncompressed_size: u32::MAX as u64 + 1,
        }];
        assert!(try_seek_table_entries(&too_plain).is_none());

        let gapped = [
            ZstdFrameInfo {
                compressed_offset: 0,
                uncompressed_offset: 0,
                compressed_size: 100,
                uncompressed_size: 10,
            },
            ZstdFrameInfo {
                compressed_offset: 150,
                uncompressed_offset: 10,
                compressed_size: 20,
                uncompressed_size: 5,
            },
        ];
        assert_eq!(
            try_seek_table_entries(&gapped).unwrap(),
            vec![(150, 10), (20, 5)],
            "cSize is the offset delta, not compressed_size"
        );
        let span_overflow = [
            ZstdFrameInfo {
                compressed_offset: 0,
                uncompressed_offset: 0,
                compressed_size: 10,
                uncompressed_size: 10,
            },
            ZstdFrameInfo {
                compressed_offset: u32::MAX as u64 + 1,
                uncompressed_offset: 10,
                compressed_size: 20,
                uncompressed_size: 5,
            },
        ];
        assert!(try_seek_table_entries(&span_overflow).is_none());

        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("mf.zst");
        let output = dir.path().join("copied.zst");
        let payload = pack_frames(&[b"chunk-A-payload!!", b"chunk-B-payload!!"], false);
        std::fs::write(&input, &payload).unwrap();
        let mut map = scan_zstd_frames_path(&input).unwrap();
        assert_eq!(map.frames.len(), 2);
        map.frames[0].uncompressed_size = u32::MAX as u64 + 1;
        assert_eq!(zstd_plan(&map, false), ZstdPlan::AppendOrCopy);
        assert_eq!(zstd_plan(&map, true), ZstdPlan::Recompress);

        let outcome = append_or_copy_zstd(&input, &output, &map).unwrap();
        assert_eq!(outcome, RepackOutcome::CopiedWithoutSeekTable);
        let out_bytes = std::fs::read(&output).unwrap();
        assert_eq!(out_bytes, payload);
        assert!(!has_seek_table_footer(&out_bytes));

        let hooked = dir.path().join("hooked.zst");
        let hooked_out = with_forced_seek_table_overflow(|| {
            repack_seekable(&input, &hooked, &tiny_opts()).unwrap()
        });
        assert_eq!(hooked_out, RepackOutcome::CopiedWithoutSeekTable);
        assert!(!has_seek_table_footer(&std::fs::read(&hooked).unwrap()));

        let too_big = RepackOptions {
            frame_size: u64::from(u32::MAX) + 1,
            ..tiny_opts()
        };
        let err = repack_seekable(&input, &dir.path().join("big.zst"), &too_big)
            .unwrap_err()
            .to_string();
        assert!(err.contains("u32::MAX"), "{err}");

        let force = RepackOptions {
            force: true,
            ..tiny_opts()
        };
        let forced = dir.path().join("forced.zst");
        let force_out = repack_seekable(&input, &forced, &force).unwrap();
        match force_out {
            RepackOutcome::Recompressed {
                frames,
                uncompressed,
                wrote_seek_table,
            } => {
                assert!(frames >= 2, "force must split into frame_size windows");
                assert_eq!(uncompressed, (2 * b"chunk-A-payload!!".len()) as u64);
                assert!(wrote_seek_table);
            }
            other => panic!("expected Recompressed, got {other:?}"),
        }
        let forced_bytes = std::fs::read(&forced).unwrap();
        assert!(has_seek_table_footer(&forced_bytes));
    }

    /// Regression: gzip keep path writes RGZI via `export_seek_index_blob` and round-trips.
    #[test]
    fn repack_gzip_rgzi_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("in.gz");
        let output = dir.path().join("out.gz");
        let mut raw = Vec::new();
        for i in 0..400 {
            writeln!(&mut raw, "rgzi {i:04} {}", "x".repeat(40)).unwrap();
        }
        std::fs::write(&input, encode_gz(&raw)).unwrap();

        let opts = RepackOptions {
            keep_gzip: true,
            write_gzidx: true,
            ..tiny_opts()
        };
        let outcome = repack_seekable(&input, &output, &opts).unwrap();
        match outcome {
            RepackOutcome::WroteGzipSidecar { points } => assert!(points >= 1),
            other => panic!("expected WroteGzipSidecar, got {other:?}"),
        }
        assert_eq!(
            std::fs::read(&output).unwrap(),
            std::fs::read(&input).unwrap()
        );

        let rgzi_path = sidecar_path(&output, "rgzi");
        let blob = std::fs::read(&rgzi_path).unwrap();
        assert!(blob.starts_with(GZIP_SEEK_INDEX_MAGIC));
        let parsed = parse_gzip_seek_index_blob(&blob).unwrap();
        assert_eq!(parsed.uncompressed_size, raw.len() as u64);

        let imported =
            SeekableGzip::open_with_imported_index(&output, DEFAULT_GZIP_SEEK_SPACING, 1, &blob)
                .unwrap();
        let mut got = Vec::new();
        imported.reader().unwrap().read_to_end(&mut got).unwrap();
        assert_eq!(got, raw);

        let gzidx = std::fs::read(sidecar_path(&output, "gzidx")).unwrap();
        assert!(gzidx.starts_with(INDEXED_GZIP_INDEX_MAGIC));

        let err = repack_seekable(
            &input,
            &dir.path().join("no-keep.gz"),
            &RepackOptions {
                write_gzidx: true,
                keep_gzip: false,
                ..tiny_opts()
            },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("write_gzidx requires keep_gzip"), "{err}");
    }

    /// Regression: gzip without keep_gzip transcodes to framed zstd + seek table.
    #[test]
    fn repack_gzip_transcodes_to_zstd() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("in.gz");
        let output = dir.path().join("out.zst");
        let plain = b"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        std::fs::write(&input, encode_gz(plain)).unwrap();

        let outcome = repack_seekable(&input, &output, &tiny_opts()).unwrap();
        match outcome {
            RepackOutcome::Recompressed {
                frames,
                uncompressed,
                wrote_seek_table,
            } => {
                assert!(frames >= 2);
                assert_eq!(uncompressed, plain.len() as u64);
                assert!(wrote_seek_table);
            }
            other => panic!("expected Recompressed, got {other:?}"),
        }
        let body = open_seekable_zstd(&output).unwrap();
        assert_eq!(body.kind(), "zstd-seek-table");
        let mut got = Vec::new();
        body.open_reader().unwrap().read_to_end(&mut got).unwrap();
        assert_eq!(got, plain);
    }

    /// Regression: single-frame zstd must recompress into framed zstd + seek table.
    #[test]
    fn repack_seekable_single_frame() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("one.zst");
        let output = dir.path().join("many.zst");
        let plain = b"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        std::fs::write(&input, encode_zstd_frame(plain, 3).unwrap()).unwrap();
        let before = scan_zstd_frames_path(&input).unwrap();
        assert_eq!(before.frames.len(), 1);
        assert!(before.seek_table.is_none());

        let outcome = repack_seekable(&input, &output, &tiny_opts()).unwrap();
        match outcome {
            RepackOutcome::Recompressed {
                frames,
                uncompressed,
                wrote_seek_table,
            } => {
                assert!(frames >= 2);
                assert_eq!(uncompressed, plain.len() as u64);
                assert!(wrote_seek_table);
            }
            other => panic!("expected Recompressed, got {other:?}"),
        }
        let body = open_seekable_zstd(&output).unwrap();
        assert_eq!(body.kind(), "zstd-seek-table");
        let mut got = Vec::new();
        body.open_reader().unwrap().read_to_end(&mut got).unwrap();
        assert_eq!(got, plain);
    }
}
