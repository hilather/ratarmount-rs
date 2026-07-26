//! Compositing layers: folder bind, union, recursive auto-mount, write overlay.

mod automount;
mod folder;
mod union;
mod write_overlay;

pub use automount::{is_archive_filename, AutoMountLayer, OpenNestedFn};
pub use folder::FolderMountSource;
pub use union::UnionMountSource;
pub use write_overlay::{WriteOverlay, HIDDEN_DB};
