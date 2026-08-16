//! TAR-agnostic last-N zstd splice (prefix copy + transform + one new frame).
//!
//! Overlay persist chooses `from_idx` and supplies the transform. This crate
//! does not depend on `ratarmount-formats-tar`. The decoded last-N is
//! materialized as [`SeekRead`] so the caller does not recopy the suffix.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use tempfile::NamedTempFile;

use crate::seekable_body::{SeekRead, DEFAULT_MEMORY_CAP};
use crate::zstd_seek::{
    build_seek_table_skippable, decode_zstd_frames_to, encode_zstd_frame_to, scan_zstd_frames,
    ZstdFrameMap,
};
use crate::{CompressError, Result};

/// Fixed encode level: original frame parameters are unrecoverable (design).
const SPLICE_ENCODE_LEVEL: i32 = 3;

/// Bytes copied / written by [`splice_zstd_last_frames`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpliceStats {
    /// Compressed prefix copied (`frames[from_idx].compressed_offset`).
    pub prefix_compressed_bytes: u64,
    /// Compressed size of the newly encoded last frame.
    pub new_frame_compressed_size: u64,
    /// Uncompressed size of the newly encoded last frame.
    pub new_frame_uncompressed_size: u64,
    /// True if a rebuilt seek-table footer was written.
    pub wrote_seek_table: bool,
}

/// Copy compressed prefix `[0, frames[from_idx].compressed_offset)`,
/// decode frames `[from_idx..]`, run `transform`, encode one new last frame,
/// write optional rebuilt seek table. `transform` reads the decoded suffix
/// and writes the new uncompressed last-frame body.
pub fn splice_zstd_last_frames<R, W, F>(
    src: &mut R,
    map: &ZstdFrameMap,
    from_idx: usize,
    transform: F,
    dst: &mut W,
) -> Result<SpliceStats>
where
    R: Read + Seek,
    W: Write,
    F: FnOnce(&mut dyn SeekRead, u64, &mut dyn Write) -> io::Result<()>,
{
    if from_idx >= map.frames.len() {
        return Err(CompressError::Msg(format!(
            "splice from_idx {from_idx} past {} frames",
            map.frames.len()
        )));
    }

    let prefix_len = map.frames[from_idx].compressed_offset;
    src.seek(SeekFrom::Start(0))?;
    let copied = io::copy(&mut src.by_ref().take(prefix_len), dst)?;
    if copied != prefix_len {
        return Err(CompressError::Msg(format!(
            "zstd splice prefix short: copied {copied}, expected {prefix_len}"
        )));
    }

    let mut suffix = spill_sink();
    decode_zstd_frames_to(src, map, from_idx, &mut suffix)?;
    suffix.seek(SeekFrom::Start(0))?;

    // Spooled: transform output spills to disk once it exceeds DEFAULT_MEMORY_CAP,
    // independent of the input last-N hint (K4).
    let mut new_plain = spill_sink();
    let stream_offset = map.frames[from_idx].uncompressed_offset;
    transform(&mut suffix, stream_offset, &mut new_plain)?;
    new_plain.flush()?;
    new_plain.seek(SeekFrom::Start(0))?;

    let (new_comp, new_plain_len) = encode_zstd_frame_to(&mut new_plain, dst, SPLICE_ENCODE_LEVEL)?;

    let wrote_seek_table =
        if let Some(table) = maybe_rebuild_seek_table(map, from_idx, new_comp, new_plain_len) {
            dst.write_all(&table)?;
            true
        } else {
            false
        };
    dst.flush()?;

    Ok(SpliceStats {
        prefix_compressed_bytes: prefix_len,
        new_frame_compressed_size: new_comp,
        new_frame_uncompressed_size: new_plain_len,
        wrote_seek_table,
    })
}

/// Sibling [`NamedTempFile`] in `path.parent()`, splice, sync, persist.
///
/// On failure before persist the original inode is untouched.
pub fn splice_zstd_last_frames_replace<F>(
    path: &Path,
    from_idx: usize,
    transform: F,
) -> Result<SpliceStats>
where
    F: FnOnce(&mut dyn SeekRead, u64, &mut dyn Write) -> io::Result<()>,
{
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    let mut tmp = match parent {
        Some(dir) => NamedTempFile::new_in(dir)?,
        None => NamedTempFile::new()?,
    };
    let mut src = File::open(path)?;
    let map = scan_zstd_frames(&mut src)?;
    let stats = splice_zstd_last_frames(&mut src, &map, from_idx, transform, tmp.as_file_mut())?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| {
        CompressError::Msg(format!(
            "Failed to replace '{}' after zstd splice: {}",
            path.display(),
            e.error
        ))
    })?;
    Ok(stats)
}

fn spill_sink() -> tempfile::SpooledTempFile {
    tempfile::spooled_tempfile(DEFAULT_MEMORY_CAP as usize)
}

/// Rebuild skippable seek table for prefix frames + one new last frame.
///
/// `None` if the input had no table (do not invent a footer) or any `cSize`/`dSize`
/// exceeds `u32::MAX` (leaving a stale footer is a silent wrong-read).
fn maybe_rebuild_seek_table(
    map: &ZstdFrameMap,
    from_idx: usize,
    new_comp: u64,
    new_plain: u64,
) -> Option<Vec<u8>> {
    map.seek_table.as_ref()?;
    let mut entries = Vec::with_capacity(from_idx.saturating_add(1));
    for (i, f) in map.frames[..from_idx].iter().enumerate() {
        // cSize from offset deltas so skippable gaps in the copied prefix stay consistent.
        let c_raw = map.frames[i + 1]
            .compressed_offset
            .checked_sub(map.frames[i].compressed_offset);
        let c = match c_raw.and_then(|n| u32::try_from(n).ok()) {
            Some(v) => v,
            None => {
                log::warn!(
                    "dropping zstd seek table: frame size exceeds u32 (frame {i} compressed span)"
                );
                return None;
            }
        };
        let d = match u32::try_from(f.uncompressed_size) {
            Ok(v) => v,
            Err(_) => {
                log::warn!(
                    "dropping zstd seek table: frame size exceeds u32 (frame {i} uncompressed {})",
                    f.uncompressed_size
                );
                return None;
            }
        };
        entries.push((c, d));
    }
    let new_c = match u32::try_from(new_comp) {
        Ok(v) => v,
        Err(_) => {
            log::warn!("dropping zstd seek table: frame size exceeds u32");
            return None;
        }
    };
    let new_d = match u32::try_from(new_plain) {
        Ok(v) => v,
        Err(_) => {
            log::warn!("dropping zstd seek table: frame size exceeds u32");
            return None;
        }
    };
    entries.push((new_c, new_d));
    Some(build_seek_table_skippable(&entries))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zstd_seek::{encode_zstd_frame, scan_zstd_frames_path, ZstdFrameInfo};
    use crate::{open_seekable_zstd, open_seekable_zstd_from_reader};
    use std::io::Cursor;

    /// Official seekable-format footer magic (`0x8F92EAB1`).
    const SEEKABLE_MAGIC: u32 = 0x8F92_EAB1;

    fn generated_payload(tag: &str, n: usize) -> Vec<u8> {
        let mut out = format!("{tag}-{}-", std::process::id()).into_bytes();
        out.extend((0..n).map(|i| ((i.wrapping_mul(31) + tag.len()) % 251) as u8));
        out
    }

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

    fn append_extra(
        extra: Vec<u8>,
    ) -> impl FnOnce(&mut dyn SeekRead, u64, &mut dyn Write) -> io::Result<()> {
        move |suffix, _off, out| {
            // Seekable hook: overlay persist will scan the suffix; prove we did not hand a forward-only Read.
            let end = suffix.seek(SeekFrom::End(0))?;
            suffix.seek(SeekFrom::Start(0))?;
            let copied = io::copy(suffix, out)?;
            assert_eq!(copied, end, "transform must see the full decoded last-N");
            out.write_all(&extra)?;
            Ok(())
        }
    }

    fn read_body(label: &str, bytes: &[u8]) -> (Vec<u8>, &'static str) {
        let body = open_seekable_zstd_from_reader(Cursor::new(bytes.to_vec()), label).unwrap();
        let kind = body.kind();
        let mut all = Vec::new();
        body.open_reader().unwrap().read_to_end(&mut all).unwrap();
        (all, kind)
    }

    /// Regression: prefix frames stay byte-identical; remount sees the transformed suffix.
    #[test]
    fn splice_zstd_multi_frame_prefix_identity() {
        let prefix_plain = generated_payload("mf-prefix", 64);
        let last_plain = generated_payload("mf-last", 48);
        let extra = generated_payload("mf-extra", 1024);
        let src_bytes = pack_frames(&[&prefix_plain, &last_plain], false);
        let mut src = Cursor::new(src_bytes.clone());
        let map = scan_zstd_frames(&mut src).unwrap();
        assert_eq!(map.frames.len(), 2);
        assert!(map.seek_table.is_none());
        let old_frame1_offset = map.frames[1].compressed_offset as usize;

        let mut dst = Vec::new();
        let stats =
            splice_zstd_last_frames(&mut src, &map, 1, append_extra(extra.clone()), &mut dst)
                .unwrap();
        assert_eq!(stats.prefix_compressed_bytes, old_frame1_offset as u64);
        assert!(!stats.wrote_seek_table);
        assert_eq!(&dst[..old_frame1_offset], &src_bytes[..old_frame1_offset]);
        assert!(!has_seek_table_footer(&dst));

        let (all, kind) = read_body("splice-mf.zst", &dst);
        assert_eq!(kind, "zstd-frames");
        let mut expected = prefix_plain.clone();
        expected.extend_from_slice(&last_plain);
        expected.extend_from_slice(&extra);
        assert_eq!(all, expected);
        assert_eq!(
            stats.new_frame_uncompressed_size,
            (last_plain.len() + extra.len()) as u64
        );

        // Seek-table fixture remounts via the footer-priority opener.
        let src_st = pack_frames(&[&prefix_plain, &last_plain], true);
        let mut src_st_cur = Cursor::new(src_st.clone());
        let map_st = scan_zstd_frames(&mut src_st_cur).unwrap();
        assert!(map_st.seek_table.is_some());
        let mut dst_st = Vec::new();
        let stats_st = splice_zstd_last_frames(
            &mut src_st_cur,
            &map_st,
            1,
            append_extra(extra.clone()),
            &mut dst_st,
        )
        .unwrap();
        assert!(stats_st.wrote_seek_table);
        let prefix_end = map_st.frames[1].compressed_offset as usize;
        assert_eq!(&dst_st[..prefix_end], &src_st[..prefix_end]);
        let (all_st, kind_st) = read_body("splice-mf-st.zst", &dst_st);
        assert_eq!(kind_st, "zstd-seek-table");
        assert_eq!(all_st, expected);
    }

    /// Last-N merge: three frames, rewrite from frame 1 (not only the final frame).
    #[test]
    fn splice_zstd_three_frame_from_idx_one() {
        let p0 = generated_payload("n3-p0", 40);
        let p1 = generated_payload("n3-p1", 28);
        let p2 = generated_payload("n3-p2", 16);
        let extra = generated_payload("n3-extra", 64);

        let src_bytes = pack_frames(&[&p0, &p1, &p2], true);
        let mut src = Cursor::new(src_bytes.clone());
        let map = scan_zstd_frames(&mut src).unwrap();
        assert_eq!(map.frames.len(), 3);
        assert!(map.seek_table.is_some());
        let prefix_end = map.frames[1].compressed_offset as usize;

        let mut dst = Vec::new();
        let stats =
            splice_zstd_last_frames(&mut src, &map, 1, append_extra(extra.clone()), &mut dst)
                .unwrap();
        assert_eq!(stats.prefix_compressed_bytes, prefix_end as u64);
        assert_eq!(&dst[..prefix_end], &src_bytes[..prefix_end]);
        assert!(stats.wrote_seek_table);

        let out_map = scan_zstd_frames(&mut Cursor::new(&dst)).unwrap();
        assert_eq!(out_map.frames.len(), 2);
        assert!(out_map.seek_table.is_some());
        assert_eq!(
            out_map.frames[0].compressed_size,
            map.frames[0].compressed_size
        );
        assert_eq!(
            out_map.frames[0].uncompressed_size,
            map.frames[0].uncompressed_size
        );
        assert_eq!(
            out_map.frames[1].compressed_size,
            stats.new_frame_compressed_size
        );
        assert_eq!(
            out_map.frames[1].uncompressed_size,
            stats.new_frame_uncompressed_size
        );

        let (all, kind) = read_body("splice-n3.zst", &dst);
        assert_eq!(kind, "zstd-seek-table");
        let mut expected = p0.clone();
        expected.extend_from_slice(&p1);
        expected.extend_from_slice(&p2);
        expected.extend_from_slice(&extra);
        assert_eq!(all, expected);
        assert_eq!(
            stats.new_frame_uncompressed_size,
            (p1.len() + p2.len() + extra.len()) as u64
        );
    }

    /// Single-frame rewrite: `from_idx == 0` produces one new data frame.
    #[test]
    fn splice_zstd_single_frame() {
        let plain = generated_payload("sf-body", 80);
        let extra = generated_payload("sf-extra", 32);
        let src_bytes = pack_frames(&[&plain], false);
        let mut src = Cursor::new(src_bytes);
        let map = scan_zstd_frames(&mut src).unwrap();
        assert_eq!(map.frames.len(), 1);

        let mut dst = Vec::new();
        let stats =
            splice_zstd_last_frames(&mut src, &map, 0, append_extra(extra.clone()), &mut dst)
                .unwrap();
        assert_eq!(stats.prefix_compressed_bytes, 0);
        assert!(!stats.wrote_seek_table);

        let out_map = scan_zstd_frames(&mut Cursor::new(&dst)).unwrap();
        assert_eq!(out_map.frames.len(), 1);
        assert!(out_map.seek_table.is_none());
        assert_eq!(
            out_map.frames[0].compressed_size,
            stats.new_frame_compressed_size
        );
        assert_eq!(
            out_map.frames[0].uncompressed_size,
            stats.new_frame_uncompressed_size
        );

        let (all, _) = read_body("splice-sf.zst", &dst);
        let mut expected = plain.clone();
        expected.extend_from_slice(&extra);
        assert_eq!(all, expected);

        // Same rewrite when the input already had a seek table: one frame + new footer.
        let src_st = pack_frames(&[&plain], true);
        let mut src_st_cur = Cursor::new(src_st);
        let map_st = scan_zstd_frames(&mut src_st_cur).unwrap();
        let mut dst_st = Vec::new();
        let stats_st = splice_zstd_last_frames(
            &mut src_st_cur,
            &map_st,
            0,
            append_extra(extra.clone()),
            &mut dst_st,
        )
        .unwrap();
        assert!(stats_st.wrote_seek_table);
        assert!(has_seek_table_footer(&dst_st));
        let out_st = scan_zstd_frames(&mut Cursor::new(&dst_st)).unwrap();
        assert_eq!(out_st.frames.len(), 1);
        assert!(out_st.seek_table.is_some());
        let (all_st, _kind_st) = read_body("splice-sf-st.zst", &dst_st);
        // Small single-frame + footer is FullDecode (`zstd`); payload still remounts.
        assert_eq!(all_st, expected);
    }

    /// Seek table rewrite: footer magic present; last cSize matches the new frame;
    /// prefix uncompressed range matches the generated seed.
    #[test]
    fn splice_zstd_seek_table_rewrite() {
        let prefix_plain = generated_payload("st-prefix", 96);
        let last_plain = generated_payload("st-last", 40);
        let extra = generated_payload("st-extra", 1024);
        let src_bytes = pack_frames(&[&prefix_plain, &last_plain], true);
        let mut src = Cursor::new(src_bytes.clone());
        let map = scan_zstd_frames(&mut src).unwrap();
        assert!(map.seek_table.is_some());
        assert!(has_seek_table_footer(&src_bytes));

        let mut dst = Vec::new();
        let stats =
            splice_zstd_last_frames(&mut src, &map, 1, append_extra(extra.clone()), &mut dst)
                .unwrap();
        assert!(stats.wrote_seek_table);
        assert!(has_seek_table_footer(&dst));

        let out_map = scan_zstd_frames(&mut Cursor::new(&dst)).unwrap();
        assert!(out_map.seek_table.is_some());
        assert_eq!(out_map.frames.len(), 2);
        assert_eq!(
            out_map.frames[1].compressed_size,
            stats.new_frame_compressed_size
        );
        assert_eq!(
            out_map.frames[1].uncompressed_size,
            stats.new_frame_uncompressed_size
        );
        assert_eq!(
            out_map.frames[0].uncompressed_size,
            prefix_plain.len() as u64
        );
        assert_eq!(
            out_map.frames[0].compressed_size,
            map.frames[0].compressed_size
        );

        let body =
            open_seekable_zstd_from_reader(Cursor::new(dst.clone()), "splice-st.zst").unwrap();
        assert_eq!(body.kind(), "zstd-seek-table");
        let mut r = body.open_reader().unwrap();
        let mut prefix_got = vec![0u8; prefix_plain.len()];
        r.read_exact(&mut prefix_got).unwrap();
        assert_eq!(prefix_got, prefix_plain);

        r.seek(SeekFrom::Start(0)).unwrap();
        let mut all = Vec::new();
        r.read_to_end(&mut all).unwrap();
        let mut expected = prefix_plain.clone();
        expected.extend_from_slice(&last_plain);
        expected.extend_from_slice(&extra);
        assert_eq!(all, expected);
    }

    /// u32 overflow drops the footer; spliced data frames still remount.
    #[test]
    fn splice_zstd_seek_table_u32_overflow_drops_footer() {
        // cSize comes from offset deltas; a span > u32::MAX drops the footer.
        let fake = ZstdFrameMap {
            frames: vec![
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
            ],
            seek_table: Some(120..140),
        };
        assert!(maybe_rebuild_seek_table(&fake, 1, 20, 5).is_none());

        let fake_plain = ZstdFrameMap {
            frames: vec![
                ZstdFrameInfo {
                    compressed_offset: 0,
                    uncompressed_offset: 0,
                    compressed_size: 10,
                    uncompressed_size: u32::MAX as u64 + 1,
                },
                ZstdFrameInfo {
                    compressed_offset: 10,
                    uncompressed_offset: u32::MAX as u64 + 1,
                    compressed_size: 20,
                    uncompressed_size: 5,
                },
            ],
            seek_table: Some(30..50),
        };
        assert!(maybe_rebuild_seek_table(&fake_plain, 1, 20, 5).is_none());
        assert!(maybe_rebuild_seek_table(&fake, 1, u32::MAX as u64 + 1, 5).is_none());
        assert!(maybe_rebuild_seek_table(&fake, 1, 20, u32::MAX as u64 + 1).is_none());
        assert!(maybe_rebuild_seek_table(
            &ZstdFrameMap {
                frames: fake.frames.clone(),
                seek_table: None,
            },
            1,
            20,
            5
        )
        .is_none());

        // Real splice: lie about prefix dSize so the rebuild overflows without 4 GiB I/O.
        // Prefix copy still uses compressed_offset (unchanged).
        let prefix_plain = generated_payload("ov-prefix", 48);
        let last_plain = generated_payload("ov-last", 24);
        let extra = generated_payload("ov-extra", 16);
        let src_bytes = pack_frames(&[&prefix_plain, &last_plain], true);
        let mut src = Cursor::new(src_bytes);
        let mut map = scan_zstd_frames(&mut src).unwrap();
        assert!(map.seek_table.is_some());
        map.frames[0].uncompressed_size = u32::MAX as u64 + 1;

        let mut dst = Vec::new();
        let stats =
            splice_zstd_last_frames(&mut src, &map, 1, append_extra(extra.clone()), &mut dst)
                .unwrap();
        assert!(!stats.wrote_seek_table);
        assert!(!has_seek_table_footer(&dst));

        let out_map = scan_zstd_frames(&mut Cursor::new(&dst)).unwrap();
        assert!(out_map.seek_table.is_none());
        assert_eq!(out_map.frames.len(), 2);

        let (all, kind) = read_body("splice-ov.zst", &dst);
        assert_eq!(kind, "zstd-frames");
        let mut expected = prefix_plain;
        expected.extend_from_slice(&last_plain);
        expected.extend_from_slice(&extra);
        assert_eq!(all, expected);
    }

    /// Prefix seek-table cSize is the compressed_offset span, not recorded compressed_size
    /// (skippable gaps live inside the byte-copied prefix).
    #[test]
    fn splice_zstd_seek_table_prefix_csize_uses_offset_deltas() {
        let map = ZstdFrameMap {
            frames: vec![
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
            ],
            seek_table: Some(170..190),
        };
        let table = maybe_rebuild_seek_table(&map, 1, 20, 5).unwrap();
        assert_eq!(table, build_seek_table_skippable(&[(150, 10), (20, 5)]));
    }

    /// Regression: leaving the old footer after a last-frame rewrite is why K5
    /// rebuilds (or drops) the table. Loader prefers the stale last-entry size.
    #[test]
    fn splice_zstd_stale_seek_table_loader_is_wrong() {
        let prefix_plain = generated_payload("stale-prefix", 64);
        let last_plain = generated_payload("stale-last", 32);
        let extra = generated_payload("stale-extra", 1024);
        let src_bytes = pack_frames(&[&prefix_plain, &last_plain], true);
        let mut src = Cursor::new(src_bytes.clone());
        let map = scan_zstd_frames(&mut src).unwrap();
        let table_range = map.seek_table.clone().expect("fixture has a seek table");
        let old_table = src_bytes[table_range.start as usize..].to_vec();
        let old_last_plain = last_plain.len() as u64;
        let old_total = (prefix_plain.len() + last_plain.len()) as u64;

        let mut new_plain = last_plain.clone();
        new_plain.extend_from_slice(&extra);
        let new_frame = encode_zstd_frame(&new_plain, 3).unwrap();
        let prefix_end = map.frames[1].compressed_offset as usize;
        let mut stale = src_bytes[..prefix_end].to_vec();
        stale.extend_from_slice(&new_frame);
        stale.extend_from_slice(&old_table);

        let stale_map = scan_zstd_frames(&mut Cursor::new(&stale)).unwrap();
        assert!(
            stale_map.seek_table.is_some(),
            "loader must prefer the leftover footer"
        );
        let stale_last = stale_map.frames.last().unwrap();
        assert_eq!(
            stale_last.uncompressed_size, old_last_plain,
            "stale last-entry dSize hides the rewritten suffix"
        );
        assert_ne!(stale_last.uncompressed_size, new_plain.len() as u64);

        let body = open_seekable_zstd_from_reader(Cursor::new(stale), "stale-footer.zst").unwrap();
        assert_eq!(body.kind(), "zstd-seek-table");
        assert_eq!(
            body.size(),
            old_total,
            "seek-table remount reports the old uncompressed total"
        );
        let mut expected_new = prefix_plain.clone();
        expected_new.extend_from_slice(&new_plain);
        // Truncated last-frame decode may error or yield the old (short) payload — never the new suffix.
        let mut got = Vec::new();
        if body.open_reader().unwrap().read_to_end(&mut got).is_ok() {
            assert_eq!(got.len() as u64, old_total);
            assert_ne!(got, expected_new);
        }
    }

    /// `replace` writes a sibling tempfile, persist-overwrites, and leaves the
    /// original bytes in place if splice fails before persist.
    #[test]
    fn splice_zstd_replace_persists_sibling() {
        let prefix_plain = generated_payload("rp-prefix", 40);
        let last_plain = generated_payload("rp-last", 20);
        let extra = generated_payload("rp-extra", 8);
        let src_bytes = pack_frames(&[&prefix_plain, &last_plain], true);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("replace.zst");
        std::fs::write(&path, &src_bytes).unwrap();

        let map = scan_zstd_frames_path(&path).unwrap();
        let from_idx = 1;
        let stats =
            splice_zstd_last_frames_replace(&path, from_idx, append_extra(extra.clone())).unwrap();
        assert!(stats.wrote_seek_table);
        assert_eq!(
            stats.prefix_compressed_bytes,
            map.frames[from_idx].compressed_offset
        );

        let after = std::fs::read(&path).unwrap();
        assert_eq!(
            &after[..map.frames[from_idx].compressed_offset as usize],
            &src_bytes[..map.frames[from_idx].compressed_offset as usize]
        );
        let body = open_seekable_zstd(&path).unwrap();
        assert_eq!(body.kind(), "zstd-seek-table");
        let mut all = Vec::new();
        body.open_reader().unwrap().read_to_end(&mut all).unwrap();
        let mut expected = prefix_plain.clone();
        expected.extend_from_slice(&last_plain);
        expected.extend_from_slice(&extra);
        assert_eq!(all, expected);

        // Bad from_idx must not touch the inode.
        let before_fail = std::fs::read(&path).unwrap();
        let err = splice_zstd_last_frames_replace(&path, 99, append_extra(extra)).unwrap_err();
        assert!(err.to_string().contains("from_idx"), "{err}");
        assert_eq!(std::fs::read(&path).unwrap(), before_fail);
    }

    /// Transform `Err` after a non-empty suffix must not persist over the original inode.
    #[test]
    fn splice_zstd_replace_transform_err_leaves_inode() {
        let prefix_plain = generated_payload("tf-prefix", 24);
        let last_plain = generated_payload("tf-last", 16);
        let src_bytes = pack_frames(&[&prefix_plain, &last_plain], false);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("transform-err.zst");
        std::fs::write(&path, &src_bytes).unwrap();

        let err = splice_zstd_last_frames_replace(&path, 1, |suffix, _off, _out| {
            let n = io::copy(suffix, &mut io::sink())?;
            assert!(n > 0, "transform must see a non-empty decoded suffix");
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "transform failed after suffix",
            ))
        })
        .unwrap_err();
        assert!(
            err.to_string().contains("transform failed after suffix"),
            "{err}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), src_bytes);
    }

    #[test]
    fn splice_zstd_from_idx_out_of_range() {
        let plain = generated_payload("oor", 8);
        let src_bytes = pack_frames(&[&plain], false);
        let mut src = Cursor::new(src_bytes);
        let map = scan_zstd_frames(&mut src).unwrap();
        let err = splice_zstd_last_frames(
            &mut src,
            &map,
            1,
            append_extra(b"x".to_vec()),
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("from_idx"), "{err}");
    }

    #[test]
    fn splice_zstd_transform_sees_stream_offset() {
        let prefix_plain = generated_payload("off-prefix", 20);
        let last_plain = generated_payload("off-last", 12);
        let src_bytes = pack_frames(&[&prefix_plain, &last_plain], false);
        let mut src = Cursor::new(src_bytes);
        let map = scan_zstd_frames(&mut src).unwrap();
        let expect_off = map.frames[1].uncompressed_offset;
        assert_eq!(expect_off, prefix_plain.len() as u64);
        let mut dst = Vec::new();
        splice_zstd_last_frames(
            &mut src,
            &map,
            1,
            |suffix, off, out| {
                assert_eq!(off, expect_off);
                io::copy(suffix, out)?;
                Ok(())
            },
            &mut dst,
        )
        .unwrap();
        let (all, _) = read_body("splice-off.zst", &dst);
        let mut expected = prefix_plain;
        expected.extend_from_slice(&last_plain);
        assert_eq!(all, expected);
    }
}
