//! Compositing layers: folder bind, union, recursive auto-mount, write overlay,
//! file versions, path prefix, path transform, in-FS control folder, OCI overlayfs.

mod automount;
mod control;
mod empty_archive;
mod folder;
mod oci_whiteout;
mod path_intern;
mod prefix;
mod transform;
mod union;
mod versioning;
mod write_overlay;

#[cfg(test)]
mod search_cheap;

pub use automount::{
    is_archive_filename, is_archive_filename_with, parse_recursive_extensions,
    strip_archive_extension, AutoMountLayer, AutoMountOptions, NestedOpenContext, OpenNestedFn,
    OpenNestedReaderFn, RecursiveExtSet,
};
pub use control::{
    live_search_tsv, ControlFolderMountSource, ControlFolderOptions, CONTROL_DIR_NAME,
    CONTROL_DIR_PATH,
};
pub use empty_archive::{
    classify_createable_archive, maybe_create_empty_write_archive, EmptyArchiveKind,
    EmptyCreateOutcome,
};
pub use folder::FolderMountSource;
pub use oci_whiteout::OciImageMountSource;
pub use prefix::PrefixMountSource;
pub use transform::TransformMountSource;
pub use union::{UnionMountOptions, UnionMountSource};
pub use versioning::FileVersionLayer;
pub use write_overlay::{
    commit_overlay, live_commit_is_supported, name_suggests_tar_zst, overlay_only_names,
    patch_sidecar_if_present, sidecar_path_for_patch, CommitKind, CommitOutcome,
    CommitOverlayOptions, IndexPatchWindow, OverlayError, WriteOverlay, HIDDEN_DB,
};
