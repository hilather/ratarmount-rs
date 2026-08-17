//! Compositing layers: folder bind, union, recursive auto-mount, write overlay,
//! file versions, path prefix, path transform, in-FS control folder.

mod automount;
mod control;
mod empty_archive;
mod folder;
mod path_intern;
mod prefix;
mod transform;
mod union;
mod versioning;
mod write_overlay;

pub use automount::{
    is_archive_filename, is_archive_filename_with, parse_recursive_extensions,
    strip_archive_extension, AutoMountLayer, AutoMountOptions, NestedOpenContext, OpenNestedFn,
    OpenNestedReaderFn, RecursiveExtSet,
};
pub use control::{
    ControlFolderMountSource, ControlFolderOptions, CONTROL_DIR_NAME, CONTROL_DIR_PATH,
};
pub use empty_archive::{
    classify_createable_archive, maybe_create_empty_write_archive, EmptyArchiveKind,
    EmptyCreateOutcome,
};
pub use folder::FolderMountSource;
pub use prefix::PrefixMountSource;
pub use transform::TransformMountSource;
pub use union::{UnionMountOptions, UnionMountSource};
pub use versioning::FileVersionLayer;
pub use write_overlay::{
    commit_overlay, live_commit_is_supported, name_suggests_tar_zst, CommitOverlayOptions,
    OverlayError, WriteOverlay, HIDDEN_DB,
};
