#![forbid(unused_macros)]

// Regression: every retained journal restriction needs its own diagnostic,
// including test helpers and convenience wrappers without production callers.
type Transform =
    fn(&mut dyn ratarmount_compress::SeekRead, u64, &mut dyn std::io::Write) -> std::io::Result<()>;

pub fn witnesses() {
    let _ = ratarmount_compress::commit_journal::recover;
    let _ = ratarmount_compress::commit_journal::recover_with;
    let _ = ratarmount_compress::commit_journal::recover_guarded;
    let _ = ratarmount_compress::commit_journal::authorize_owned;
    let _ = ratarmount_compress::commit_journal::authorize_forced;
    let _ = ratarmount_compress::commit_journal::replace_suffix_if_unchanged_with;
    let _ = ratarmount_compress::commit_journal::replace_suffix_with_hook;
    let _ = ratarmount_compress::commit_journal::guard_copy;
    let _ = ratarmount_compress::splice_zstd_last_frames_append::<Transform>;
    let _ = ratarmount_compress::splice_zstd_last_frames_append_with::<Transform>;
    let _ = ratarmount_compress::splice_zstd_last_frames_replace::<Transform>;
}
