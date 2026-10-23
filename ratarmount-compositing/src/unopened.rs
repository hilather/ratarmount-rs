//! The source of a base that was classified but never opened.

use std::io;

use ratarmount_core::{FileInfo, ListResult, MountSource};

/// A [`MountSource`] with nothing in it, for a [`crate::ClassifiedBase`] whose
/// caller needs the identity only (an offline `--commit-overlay` classifies
/// the archive it is about to rewrite without indexing it). Unlike a stand-in
/// directory it exposes no files: every lookup misses and every open fails.
pub struct UnopenedSource;

impl MountSource for UnopenedSource {
    fn is_immutable(&self) -> bool {
        false
    }

    fn list(&self, _: &str) -> Option<ListResult> {
        None
    }

    fn lookup(&self, _: &str, _: i32) -> Option<FileInfo> {
        None
    }

    fn open(&self, _: &FileInfo, _: i32) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
        Err(io::Error::other(
            "this base was classified without being opened",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The source of a classified-only base serves nothing.
    #[test]
    fn unopened_source_serves_nothing() {
        let source = UnopenedSource;
        assert!(source.list("/").is_none());
        assert!(source.lookup("/f", 0).is_none());
    }
}
