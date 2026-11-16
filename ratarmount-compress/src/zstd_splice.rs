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

#[cfg(any(test, feature = "test-hooks"))]
thread_local! {
    static SEEK_TABLE_SIZE_LIMIT: std::cell::Cell<u64> = const { std::cell::Cell::new(u32::MAX as u64) };
}

/// Restore the previous per-thread seek-table size limit when dropped.
#[cfg(any(test, feature = "test-hooks"))]
pub struct SeekTableLimitGuard(u64);

#[cfg(any(test, feature = "test-hooks"))]
impl Drop for SeekTableLimitGuard {
    fn drop(&mut self) {
        SEEK_TABLE_SIZE_LIMIT.with(|limit| limit.set(self.0));
    }
}

/// Exercise the oversized-frame publication route with a small fixture.
#[cfg(any(test, feature = "test-hooks"))]
pub fn zstd_splice_seek_table_limit_for_test(limit: u64) -> SeekTableLimitGuard {
    SeekTableLimitGuard(SEEK_TABLE_SIZE_LIMIT.with(|slot| slot.replace(limit)))
}

/// Exercise oversized splice publication without writing a 4 GiB test fixture.
#[cfg(any(test, feature = "test-hooks"))]
pub fn with_splice_frame_size_limit<T>(limit: u32, run: impl FnOnce() -> T) -> T {
    let _reset = zstd_splice_seek_table_limit_for_test(u64::from(limit));
    run()
}

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

    write_zstd_splice_suffix(src, map, from_idx, transform, dst)
}

/// Encode only the replacement suffix and seek table. The caller preserves the
/// prefix, either by copying it or by journaled in-place replacement.
pub fn write_zstd_splice_suffix<R, W, F>(
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
    let prefix_len = map
        .frames
        .get(from_idx)
        .ok_or_else(|| {
            CompressError::Msg(format!(
                "splice from_idx {from_idx} past {} frames",
                map.frames.len()
            ))
        })?
        .compressed_offset;
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
/// The copy is read only from the file still exactly at `reference` (device,
/// inode, length, mtime, ctime): the caller's gate snapshot, or the stamp its
/// own rolled-back attempt left under the lock
/// ([`crate::commit_journal::ReplaceError::RolledBack`]). It is published only
/// while the archive is still exactly that stamp with no journal pending,
/// under its lock ([`crate::commit_journal::guard_copy`]). On failure before
/// persist the original inode is untouched. `before_write` runs under that
/// lock immediately before publication.
pub fn splice_zstd_last_frames_replace<F>(
    path: &Path,
    from_idx: usize,
    transform: F,
    reference: &std::fs::Metadata,
    before_write: crate::commit_journal::BeforeWrite,
) -> Result<SpliceStats>
where
    F: FnOnce(&mut dyn SeekRead, u64, &mut dyn Write) -> io::Result<()>,
{
    #[expect(
        clippy::disallowed_methods,
        reason = "The copy splice convenience API delegates with the caller pre-publication guard"
    )]
    splice_zstd_last_frames_replace_guarded(path, from_idx, transform, reference, before_write)
}

/// Copy splice with a caller guard under the archive lock immediately before
/// publication. Preparation may read and stage bytes but cannot publish them.
pub fn splice_zstd_last_frames_replace_guarded<F>(
    path: &Path,
    from_idx: usize,
    transform: F,
    reference: &std::fs::Metadata,
    before_write: crate::commit_journal::BeforeWrite,
) -> Result<SpliceStats>
where
    F: FnOnce(&mut dyn SeekRead, u64, &mut dyn Write) -> io::Result<()>,
{
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-B0277-M01","item":"ratarmount_compress::zstd_splice::splice_zstd_last_frames_replace_guarded","disposition":"output-owner","mode_policy":"private-staging-then-source-archive-metadata","category":"output-owner","reason":"Stage the replacement privately; restore accepted archive metadata by fd before publication (#235).","creation":{"policy":"private-named-temporary-file","basis":"NamedTempFile retains private staging defaults; the finished replacement inherits accepted source permission bits and permitted ownership by fd before rename."}}"###
    )]
    let mut tmp = NamedTempFile::new_in(parent)?;
    crate::commit_journal::fault::point("copy source open")?;
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-B0278-M01","item":"ratarmount_compress::zstd_splice::splice_zstd_last_frames_replace_guarded","disposition":"residual","reason":"zstd splice source of the base archive under the commit journal; mutation ownership belongs to the excluded broader machinery","family":"commit-journal-recovery","issue":"#196","category":"commit-journal-recovery","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
    )]
    let mut src = File::open(path)?;
    let source = src.metadata()?;
    if !crate::commit_journal::same_stamp(reference, &source) {
        return Err(CompressError::Msg(format!(
            "{} changed before the copy fallback (it is no longer the file the commit gate \
             accepted); nothing was published, retry",
            path.display()
        )));
    }
    crate::commit_journal::fault::point("copy source opened")?;
    let map = scan_zstd_frames(&mut src)?;
    let prefix = map
        .frames
        .get(from_idx)
        .ok_or_else(|| {
            CompressError::Msg(format!(
                "splice from_idx {from_idx} past {} frames",
                map.frames.len()
            ))
        })?
        .compressed_offset;
    let method = crate::fastcopy::copy_range(&mut src, 0, tmp.as_file_mut(), 0, prefix)?;
    crate::fastcopy::log_commit_copy(prefix, method);
    let stats = write_zstd_splice_suffix(&mut src, &map, from_idx, transform, tmp.as_file_mut())?;
    crate::fastcopy::preserve_archive_metadata(path, &source, tmp.as_file())?;
    tmp.as_file().sync_all()?;
    #[expect(
        clippy::disallowed_methods,
        reason = "The splice implementation holds the journal copy guard while publishing the staged archive"
    )]
    let _guard = crate::commit_journal::guard_copy(path, &source).map_err(CompressError::Io)?;
    before_write()?;
    crate::commit_journal::test_prewrite_hold()?;
    before_write()?;
    tmp.persist(path).map_err(|e| {
        CompressError::Msg(format!(
            "Failed to replace '{}' after zstd splice: {}",
            path.display(),
            e.error
        ))
    })?;
    Ok(stats)
}

/// Journaled in-place splice. Requires a seek table and stages only the suffix.
pub fn splice_zstd_last_frames_append<F>(
    path: &Path,
    from_idx: usize,
    transform: F,
    original: &std::fs::Metadata,
) -> Result<SpliceStats>
where
    F: FnOnce(&mut dyn SeekRead, u64, &mut dyn Write) -> io::Result<()>,
{
    #[expect(
        clippy::disallowed_methods,
        reason = "The append convenience API delegates to the implementation with an empty unlink hook"
    )]
    let result = splice_zstd_last_frames_append_with(
        path,
        from_idx,
        transform,
        original,
        &mut || Ok(()),
        &mut |_| Ok(()),
    );
    result
}

/// [`splice_zstd_last_frames_append`] with a `before_unlink` hook that runs
/// under the archive lock with the final stamp, before the journal is
/// unlinked. `original` is the caller's snapshot of the archive (the file
/// its gate judged): the source opened here must still be exactly that file,
/// and the replacement compares it again under the archive lock. A failure
/// of the journaled replacement is [`CompressError::Replace`]. `before_write`
/// runs under the archive lock before any mutation or copy publication.
pub fn splice_zstd_last_frames_append_with<F>(
    path: &Path,
    from_idx: usize,
    transform: F,
    original: &std::fs::Metadata,
    before_write: crate::commit_journal::BeforeWrite,
    before_unlink: crate::commit_journal::BeforeUnlink,
) -> Result<SpliceStats>
where
    F: FnOnce(&mut dyn SeekRead, u64, &mut dyn Write) -> io::Result<()>,
{
    #[expect(
        clippy::disallowed_methods,
        reason = "The append splice convenience API delegates with the caller pre-write guard"
    )]
    splice_zstd_last_frames_append_guarded(
        path,
        from_idx,
        transform,
        original,
        before_write,
        before_unlink,
    )
}

/// Journaled splice with a caller guard before any journal, locator or archive
/// mutation; the copy fallback uses it under the publication lock as well.
pub fn splice_zstd_last_frames_append_guarded<F>(
    path: &Path,
    from_idx: usize,
    transform: F,
    original: &std::fs::Metadata,
    before_write: crate::commit_journal::BeforeWrite,
    before_unlink: crate::commit_journal::BeforeUnlink,
) -> Result<SpliceStats>
where
    F: FnOnce(&mut dyn SeekRead, u64, &mut dyn Write) -> io::Result<()>,
{
    crate::commit_journal::fault::check("before splice scan")?;
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-B0279-M01","item":"ratarmount_compress::zstd_splice::splice_zstd_last_frames_append_guarded","disposition":"residual","reason":"zstd splice source of the base archive under the commit journal; mutation ownership belongs to the excluded broader machinery","family":"commit-journal-recovery","issue":"#196","category":"commit-journal-recovery","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
    )]
    let mut src = File::open(path)?;
    let source = src.metadata()?;
    if !crate::commit_journal::same_stamp(original, &source) {
        return Err(CompressError::Msg(
            "archive changed while preparing append; retry with a fresh plan".into(),
        ));
    }
    let map = scan_zstd_frames(&mut src)?;
    if map.seek_table.is_none() {
        return Err(CompressError::Msg(
            "append splice requires a zstd seek table".into(),
        ));
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-B0280-M01","item":"ratarmount_compress::zstd_splice::splice_zstd_last_frames_append_guarded","disposition":"output-owner","mode_policy":"unchanged-from-e6ca64e","category":"output-owner","reason":"Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"unchanged-from-e6ca64e","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###
    )]
    let mut tail = NamedTempFile::new_in(parent)?;
    let stats = write_zstd_splice_suffix(&mut src, &map, from_idx, transform, tail.as_file_mut())?;
    if !stats.wrote_seek_table {
        // A new frame may exceed the seek-table u32 limit. Keep the existing
        // no-size-refusal rule: publish the staged suffix through copy/rename.
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-B0281-M01","item":"ratarmount_compress::zstd_splice::splice_zstd_last_frames_append_guarded","disposition":"output-owner","mode_policy":"private-staging-then-source-archive-metadata","category":"output-owner","reason":"Stage the replacement privately; restore accepted archive metadata by fd before publication (#235).","creation":{"policy":"private-named-temporary-file","basis":"NamedTempFile retains private staging defaults; the finished replacement inherits accepted source permission bits and permitted ownership by fd before rename."}}"###
        )]
        let mut tmp = NamedTempFile::new_in(parent)?;
        let method = crate::fastcopy::copy_range(
            &mut src,
            0,
            tmp.as_file_mut(),
            0,
            stats.prefix_compressed_bytes,
        )?;
        crate::fastcopy::log_commit_copy(stats.prefix_compressed_bytes, method);
        tail.as_file_mut().rewind()?;
        io::copy(tail.as_file_mut(), tmp.as_file_mut())?;
        crate::fastcopy::preserve_archive_metadata(path, &source, tmp.as_file())?;
        tmp.as_file().sync_all()?;
        // Published only over the file the copy was read from, unchanged and
        // with no journal pending, under its lock.
        #[expect(
            clippy::disallowed_methods,
            reason = "The oversized splice fallback holds the journal guard while publishing its staged copy"
        )]
        let _guard = crate::commit_journal::guard_copy(path, &source).map_err(CompressError::Io)?;
        before_write()?;
        crate::commit_journal::test_prewrite_hold()?;
        before_write()?;
        tmp.persist(path).map_err(|e| e.error)?;
        return Ok(stats);
    }
    #[expect(
        clippy::disallowed_methods,
        reason = "The append splice commits its checked suffix through the journal implementation"
    )]
    crate::commit_journal::replace_suffix_if_unchanged_guarded(
        path,
        stats.prefix_compressed_bytes,
        tail.as_file_mut(),
        original,
        before_write,
        before_unlink,
    )
    .map_err(CompressError::Replace)?;
    log::info!(
        "commit: prefix {:.1} GiB retained via append",
        stats.prefix_compressed_bytes as f64 / (1024.0 * 1024.0 * 1024.0)
    );
    Ok(stats)
}

fn spill_sink() -> tempfile::SpooledTempFile {
    {
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-E0028-M01","item":"ratarmount_compress::zstd_splice::spill_sink","disposition":"output-owner","category":"compression-staging","reason":"Construct the spill sink used for the compressed rewrite tail.","creation":{"policy":"spill-private-temporary","basis":"SpooledTempFile uses the existing memory cap and tempfile defaults on disk rollover; it does not create a named archive input."}}"###
        )]
        let __inventory_value_0 = tempfile::spooled_tempfile(DEFAULT_MEMORY_CAP as usize);
        __inventory_value_0
    }
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
    #[cfg(any(test, feature = "test-hooks"))]
    if SEEK_TABLE_SIZE_LIMIT.with(|limit| new_comp > limit.get() || new_plain > limit.get()) {
        return None;
    }
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
#[path = "zstd_splice_tests.rs"]
mod tests;
