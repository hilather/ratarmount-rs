#![allow(
    clippy::disallowed_methods,
    reason = "Splice regression fixtures directly exercise the restricted journal and splice APIs"
)]

use super::*;
use crate::zstd_seek::{encode_zstd_frame, scan_zstd_frames_path, ZstdFrameInfo};
use crate::{open_seekable_zstd, open_seekable_zstd_from_reader};
use std::io::Cursor;

thread_local! {
    pub(super) static SEEK_TABLE_FRAME_LIMIT: std::cell::Cell<u64> = const {
        std::cell::Cell::new(u32::MAX as u64)
    };
}

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
        splice_zstd_last_frames(&mut src, &map, 1, append_extra(extra.clone()), &mut dst).unwrap();
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
        splice_zstd_last_frames(&mut src, &map, 1, append_extra(extra.clone()), &mut dst).unwrap();
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
        splice_zstd_last_frames(&mut src, &map, 0, append_extra(extra.clone()), &mut dst).unwrap();
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
        splice_zstd_last_frames(&mut src, &map, 1, append_extra(extra.clone()), &mut dst).unwrap();
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

    let body = open_seekable_zstd_from_reader(Cursor::new(dst.clone()), "splice-st.zst").unwrap();
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
        splice_zstd_last_frames(&mut src, &map, 1, append_extra(extra.clone()), &mut dst).unwrap();
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
    let stats = splice_zstd_last_frames_replace(
        &path,
        from_idx,
        append_extra(extra.clone()),
        &std::fs::metadata(&path).unwrap(),
        &mut || Ok(()),
    )
    .unwrap();
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
    let err = splice_zstd_last_frames_replace(
        &path,
        99,
        append_extra(extra),
        &std::fs::metadata(&path).unwrap(),
        &mut || Ok(()),
    )
    .unwrap_err();
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

    let original = std::fs::metadata(&path).unwrap();
    let transform = |suffix: &mut dyn SeekRead, _off: u64, _out: &mut dyn Write| {
        let n = io::copy(suffix, &mut io::sink())?;
        assert!(n > 0, "transform must see a non-empty decoded suffix");
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "transform failed after suffix",
        ))
    };
    let err = splice_zstd_last_frames_replace(&path, 1, transform, &original, &mut || Ok(()))
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

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn assert_238_splice_prewrite_guard(append: bool) {
    use std::os::fd::AsRawFd;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("guarded.zst");
    let before = pack_frames(&[b"prefix", b"old contents"], true);
    std::fs::write(&path, &before).unwrap();
    let original = std::fs::metadata(&path).unwrap();
    let competing = File::open(&path).unwrap();
    let mut called = false;
    let mut guard = || {
        called = true;
        assert_eq!(
            unsafe { libc::flock(competing.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            -1,
            "splice prewrite guard must run while the archive is locked"
        );
        assert_eq!(io::Error::last_os_error().kind(), io::ErrorKind::WouldBlock);
        Err(io::Error::other("sealed splice refusal"))
    };
    let result = if append {
        splice_zstd_last_frames_append_with(
            &path,
            1,
            append_extra(b"new contents".to_vec()),
            &original,
            &mut guard,
            &mut |_| panic!("refused splice cannot restamp its base"),
        )
    } else {
        splice_zstd_last_frames_replace(
            &path,
            1,
            append_extra(b"new contents".to_vec()),
            &original,
            &mut guard,
        )
    };
    assert!(called, "splice prewrite guard was skipped");
    let error = match result.unwrap_err() {
        CompressError::Io(error)
        | CompressError::Replace(crate::commit_journal::ReplaceError::Refused(error)) => error,
        other => panic!("unexpected refusal: {other}"),
    };
    assert_eq!(error.to_string(), "sealed splice refusal");
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert!(!crate::commit_journal::journal_path(&path).exists());
    assert_eq!(
        crate::commit_journal::offline_journal_probe(&path).unwrap(),
        (None, None)
    );
    assert!(crate::commit_journal::same_stamp(
        &original,
        &std::fs::metadata(&path).unwrap()
    ));
}

/// Regression: #238 a zstd append checks sealing under its archive lock
/// before journal publication, locator writes, or archive mutation.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn regression_238_zstd_append_prewrite_guard_runs_under_lock() {
    assert_238_splice_prewrite_guard(true);
}

/// Regression: #238 a zstd copy checks sealing under its archive lock
/// before publishing the replacement archive.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn regression_238_zstd_copy_prewrite_guard_runs_under_lock() {
    assert_238_splice_prewrite_guard(false);
}

/// Regression: #238 the oversized-frame fallback must check sealing under
/// the archive lock before copy publication, just like ordinary appends.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn regression_238_zstd_oversized_append_prewrite_guard_runs_under_lock() {
    struct ResetLimit(u64);
    impl Drop for ResetLimit {
        fn drop(&mut self) {
            SEEK_TABLE_FRAME_LIMIT.with(|limit| limit.set(self.0));
        }
    }
    let _reset = ResetLimit(SEEK_TABLE_FRAME_LIMIT.with(|limit| limit.replace(16)));
    assert_238_splice_prewrite_guard(true);

    // Also prove that the bounded seam selects the copy fallback: a permitted
    // publication produces decodable frames with no seek table or journal.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("oversized.zst");
    let before = pack_frames(&[b"prefix", b"old contents"], true);
    std::fs::write(&path, before).unwrap();
    let original = std::fs::metadata(&path).unwrap();
    let stats = splice_zstd_last_frames_append_with(
        &path,
        1,
        append_extra(b"new contents".to_vec()),
        &original,
        &mut || Ok(()),
        &mut |_| panic!("copy publication cannot take the journal unlink path"),
    )
    .unwrap();
    assert!(!stats.wrote_seek_table);
    let bytes = std::fs::read(&path).unwrap();
    assert!(!has_seek_table_footer(&bytes));
    assert_eq!(
        read_body("oversized.zst", &bytes).0,
        b"prefixold contentsnew contents"
    );
    assert!(!crate::commit_journal::journal_path(&path).exists());
}
