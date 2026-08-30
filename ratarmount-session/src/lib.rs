//! In-process [`Session`] API for ratarmount-rs embedders.
//!
//! This crate is the **supported embedder surface**. Do not import the
//! `ratarmount` binary crate — that pulls FUSE, NFS, SMB, HTTP, 9P, and SFTP.
//! The default dependency graph of `ratarmount-session` has no `fuser`
//! (`cargo tree -p ratarmount-session -i fuser` is empty). TAR/ZIP/7z are
//! always compiled; other L2 is `formats-all` (G5.3). `--no-default-features`
//! drops libarchive/git/….
//!
//! Archive factory glue (`open_path`, `build_mount_source_ex`) lives in
//! [`factory`] so the CLI can share it. Embedders should use [`Session`], not
//! the factory module.
//!
//! Contract: types, [`Error`] (no `Busy`), [`Session`] (no [`Clone`]; share via
//! [`std::sync::Arc`]). See `docs/session-api.md`.

mod error;
mod extract;
pub mod factory;
mod index_job;
mod locate;
mod read;
mod resolve;
mod session;
mod types;

pub use error::Error;
pub use index_job::IndexJob;
pub use locate::{query_index, split_fts_pattern, DEFAULT_FIND_PAGE};
pub use ratarmount_core::{IndexBuildHooks, IndexBuildTick};
pub use ratarmount_index::IndexLocation;
pub use read::RangeReader;
pub use resolve::resolve_index;
pub use session::Session;
pub use types::{
    DirCursor, DirEnt, DirPage, ExtractProgress, ExtractRequest, FindCursor, FindOpts, FindPage,
    IndexPhase, IndexPolicy, IndexProgress, OpenRequest, Overwrite, ReadRequest, Recreate,
    SourceSpec,
};

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;
    use std::path::PathBuf;
    use std::sync::Arc;

    fn engine_error_variant_name(err: &Error) -> &'static str {
        // Exhaustive: adding `Busy` (or any other variant) fails this compile.
        match err {
            Error::NotFound => "NotFound",
            Error::SiblingNotWritable(_) => "SiblingNotWritable",
            Error::NotWritable(_) => "NotWritable",
            Error::BadPassword => "BadPassword",
            Error::UnsupportedFormat(_) => "UnsupportedFormat",
            Error::CorruptIndex(_) => "CorruptIndex",
            Error::Cancelled => "Cancelled",
            Error::PathEscape(_) => "PathEscape",
            Error::Internal(_) => "Internal",
        }
    }

    #[test]
    fn dir_cursor_after_name_constructs() {
        let cursor = DirCursor::AfterName {
            name: "file.txt".into(),
        };
        match cursor {
            DirCursor::AfterName { name } => assert_eq!(name, "file.txt"),
            DirCursor::Start => panic!("expected AfterName"),
        }
    }

    #[test]
    fn find_cursor_after_path_constructs() {
        let cursor = FindCursor::AfterPath {
            path: "/a/b".into(),
            offsetheader: Some(512),
        };
        match cursor {
            FindCursor::AfterPath { path, offsetheader } => {
                assert_eq!(path, "/a/b");
                assert_eq!(offsetheader, Some(512));
            }
            FindCursor::Start => panic!("expected AfterPath"),
        }
    }

    #[test]
    fn engine_error_has_no_busy_variant() {
        let samples = [
            Error::NotFound,
            Error::SiblingNotWritable(PathBuf::from("/archive")),
            Error::NotWritable(PathBuf::from("/dest")),
            Error::BadPassword,
            Error::UnsupportedFormat("rar".into()),
            Error::CorruptIndex("tarstats mismatch".into()),
            Error::Cancelled,
            Error::PathEscape("../etc/passwd".into()),
            Error::Internal("boom".into()),
        ];
        for err in &samples {
            let name = engine_error_variant_name(err);
            assert_ne!(name, "Busy");
            assert!(
                !format!("{err:?}").starts_with("Busy"),
                "engine Error must not produce Busy: {err:?}"
            );
        }
    }

    #[test]
    fn open_request_holds_secret_string_without_factory() {
        let req = OpenRequest {
            source: SourceSpec::Path(PathBuf::from("/tmp/a.tar")),
            index: IndexPolicy::Sibling,
            explicit_index: None,
            extra_dirs: Vec::new(),
            password: Some(SecretString::new("secret".into())),
            recursive: false,
            recursion_depth: None,
            recreate: Recreate::IfInvalid,
        };
        assert!(req.password.is_some());
        assert!(matches!(req.source, SourceSpec::Path(_)));
        let debug = format!("{req:?}");
        assert!(!debug.contains("secret"), "{debug}");
        assert!(
            debug.contains("REDACTED") || debug.contains("Secret"),
            "{debug}"
        );
    }

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn session_is_send_sync_shared_via_arc() {
        assert_send_sync::<Session>();
        assert_send_sync::<IndexJob>();
        let session = Session::stub();
        let shared = Arc::new(session);
        let _clone = Arc::clone(&shared);
    }

    #[test]
    fn factory_open_path_is_reachable() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("no-such-archive.tar");
        let err = match crate::factory::open_path(
            &missing,
            &ratarmount_core::OpenOptions::default(),
            false,
        ) {
            Ok(_) => panic!("missing archive should not open"),
            Err(e) => e,
        };
        assert!(!err.is_empty(), "open_path should report the missing path");
    }

    #[test]
    fn error_variants_construct() {
        assert_eq!(Error::NotFound.to_string(), "not found");
        assert_eq!(
            Error::SiblingNotWritable(PathBuf::from("/ro")).to_string(),
            "sibling directory is not writable: /ro"
        );
        assert_eq!(
            Error::NotWritable(PathBuf::from("/x")).to_string(),
            "not writable: /x"
        );
        assert_eq!(
            Error::BadPassword.to_string(),
            "password rejected or required"
        );
        assert_eq!(
            Error::UnsupportedFormat("iso".into()).to_string(),
            "unsupported format"
        );
        assert_eq!(
            Error::CorruptIndex("bad".into()).to_string(),
            "corrupt or mismatched index"
        );
        assert_eq!(Error::Cancelled.to_string(), "cancelled");
        assert_eq!(
            Error::PathEscape("..".into()).to_string(),
            "member path escapes destination"
        );
        assert_eq!(Error::Internal("x".into()).to_string(), "x");
    }
}
