//! Compositing layers: folder bind, union, recursive auto-mount, write overlay,
//! file versions, path prefix, path transform, in-FS control folder, OCI overlayfs,
//! G-3 payload cache.
//!
//! Session's Windows check compiles this crate; `missing_xattr_errno` uses `libc::ENODATA` on Linux and Windows and `libc::ENOATTR` only on other targets.

#[macro_use]
mod quiet_print;
mod automount;
pub mod base_sidecars;
mod control;
mod empty_archive;
mod folder;
pub mod host_stat;
pub mod journal_recovery;
mod oci_whiteout;
pub mod overlay_changes;
pub mod overlay_db;
#[cfg(unix)]
pub mod overlay_fsck;
pub mod overlay_gate;
pub mod overlay_identity;
pub mod overlay_layer;
pub mod overlay_meta;
mod overlay_policy;
#[cfg(unix)]
pub mod overlay_seal;
mod path_intern;
mod payload;
mod prefix;
mod rolling;
mod transform;
mod union;
mod unopened;
mod versioning;
mod write_overlay;

#[cfg(test)]
mod overlay_identity_tests;
#[cfg(test)]
mod search_cheap;

pub use automount::{
    is_archive_filename, is_archive_filename_with, parse_recursive_extensions,
    strip_archive_extension, AutoMountLayer, AutoMountOptions, NestedOpenContext, OpenNestedFn,
    OpenNestedReaderFn, RecursiveExtSet,
};
pub use base_sidecars::is_ratarmount_sidecar_name;
pub use control::{
    live_search_tsv, ControlFolderMountSource, ControlFolderOptions, CONTROL_DIR_NAME,
    CONTROL_DIR_PATH,
};
pub use empty_archive::{
    classify_createable_archive, maybe_create_empty_write_archive, EmptyArchiveKind,
    EmptyCreateOutcome,
};
pub use folder::FolderMountSource;
pub use journal_recovery::{
    authorize_mount_recovery, classify_mount_journal, journal_agrees, recover_journal_at,
    MountJournal, MountRecords, Owner, Record,
};
pub use oci_whiteout::OciImageMountSource;
pub use overlay_db::{open_overlay_db, DbName, OverlayDbError};
pub use overlay_gate::{
    compare_base_identity, ensure_journal_is_for_archive, forced_base_record,
    forced_relocation_record, identity_rows, record_forced_base_rows, shape_verdict, verify_base,
    BaseProbe, Recorded, Verdict,
};
pub use overlay_identity::{
    ActualBase, BaseKind, BaseLocation, ClassifiedBase, CreateOptions, IndexProvenance, OpenBase,
    Opened, SealedRecord, ServedKind, ServedLocation,
};
pub use overlay_layer::{
    compose_stack, serving_layer, Immutability, LayerIndex, ReadOnlyOverlayLayer,
};
pub use overlay_meta::{
    append_base_excludes, base_digest_state, directory_digest, directory_digest_calls_this_thread,
    directory_digest_excluding, directory_weak_digest, directory_weak_walks_this_thread,
    record_base_digest, redact_meta_values, resolve_base_excludes, resolve_pending_base_digest,
    stack_digest, BaseCheck, BaseComparison, BaseDigestRequest, BaseExcludes, BaseStrength,
    LowerLayerRecord, OverlayMeta, PendingBase, BASE_COMPARISON_KEYS,
};
pub use overlay_policy::{
    parse_overlay_size, CompositeOverlayPolicy, OverlayQuota, OverlayStats, OverlayUsage,
    QuotaUsage, ReadOnlyGlobs,
};
pub use payload::{maybe_wrap_payload_cache, PayloadCacheLayer};
pub use prefix::{validate_mount_path, PrefixMountSource, SourceBind};
pub use rolling::{RollPolicy, RollingMountSource, SeriesName};
pub use transform::TransformMountSource;
pub use union::{UnionMountOptions, UnionMountSource};
pub use unopened::UnopenedSource;
pub use versioning::FileVersionLayer;
pub use write_overlay::{
    commit_overlay, commit_overlay_raw_dir, is_control_reserved_path, is_overlay_internal_path,
    live_commit_is_supported, name_suggests_tar_zst, overlay_atime, overlay_db_absent,
    overlay_only_names, patch_sidecar_if_present, sidecar_path_for_patch, CommitKind, CommitMode,
    CommitOutcome, CommitOverlayOptions, IndexPatchWindow, OverlayError, OverlayMetadata,
    OverlayMutation, OverlayPolicy, Parked, RawDirCommit, RemoteDownload, RemoteObjectHead,
    RemotePublishError, RemotePublishRequest, WriteOverlay, HIDDEN_DB, LEGACY_OVERLAY_MARKER,
    OVERLAY_MARKER,
};
