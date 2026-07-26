//! Compositing layers: folder bind, union, recursive auto-mount, write overlay,
//! file versions, path prefix, path transform.

mod automount;
mod folder;
mod prefix;
mod transform;
mod union;
mod versioning;
mod write_overlay;

pub use automount::{
    is_archive_filename, is_archive_filename_with, parse_recursive_extensions,
    strip_archive_extension, AutoMountLayer, AutoMountOptions, OpenNestedFn, RecursiveExtSet,
};
pub use folder::FolderMountSource;
pub use prefix::PrefixMountSource;
pub use transform::TransformMountSource;
pub use union::{UnionMountOptions, UnionMountSource};
pub use versioning::FileVersionLayer;
pub use write_overlay::{
    commit_overlay, CommitOverlayOptions, WriteOverlay, HIDDEN_DB,
};
