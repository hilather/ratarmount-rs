//! Fail-closed seal transitions on platforms without the Unix directory lock.

use std::io;
use std::path::Path;
use std::sync::Arc;

use ratarmount_core::MountSource;

#[derive(Debug)]
pub struct SealOutcome {
    pub layer_digest: String,
    pub sealed_at: String,
    pub already_sealed: bool,
}

fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "overlay seal/unseal is not supported on this platform",
    )
}

pub fn seal(
    _dir: &Path,
    _base: &crate::ClassifiedBase,
    _composed: Arc<dyn MountSource>,
) -> io::Result<SealOutcome> {
    Err(unsupported())
}

pub fn reseal(_record: &crate::SealedRecord) -> io::Result<SealOutcome> {
    Err(unsupported())
}

pub fn unseal(_dir: &Path) -> io::Result<()> {
    Err(unsupported())
}

/// Meta row of a layer that records preimage pins (#341).
pub const PREIMAGE_DIGEST_KEY: &str = "base_preimage_digest";

/// Preimage pins are rehashed on Unix only, as layers are sealed. A layer
/// that records pins is refused here rather than used unchecked; one that
/// records none has nothing to check.
pub fn check_preimages(dir: &Path, _lower_view: Arc<dyn MountSource>) -> io::Result<Vec<String>> {
    let meta = crate::OverlayMeta::read(dir).map_err(io::Error::other)?;
    let Some(meta) = meta else {
        return Ok(Vec::new());
    };
    let conn = crate::open_overlay_db(
        &dir.join(crate::HIDDEN_DB),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        crate::DbName::Immutable,
    )?;
    let table: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='seal_preimages')",
        [], |row| row.get(0),
    ).map_err(io::Error::other)?;
    let rows: bool = table
        && conn
            .query_row("SELECT EXISTS(SELECT 1 FROM seal_preimages)", [], |row| {
                row.get(0)
            })
            .map_err(io::Error::other)?;
    if meta.get(PREIMAGE_DIGEST_KEY).is_some() || rows {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the layer records preimage pins, which can only be checked on Unix",
        ));
    }
    Ok(Vec::new())
}

pub struct SealOperation;

impl SealOperation {
    pub fn acquire(_dir: &Path) -> io::Result<Self> {
        Err(unsupported())
    }

    pub fn acquire_until(_dir: &Path, _deadline: Option<std::time::Instant>) -> io::Result<Self> {
        Err(unsupported())
    }

    pub fn finish_if_sealed(&self) -> io::Result<Option<SealOutcome>> {
        Err(unsupported())
    }

    pub fn seal(
        self,
        _base: &crate::ClassifiedBase,
        _composed: Arc<dyn MountSource>,
    ) -> io::Result<SealOutcome> {
        Err(unsupported())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: a non-Unix commit remains supported, but no seal transition
    /// may claim success without the Unix permission and directory-lock rules.
    #[test]
    fn regression_nonunix_seal_and_unseal_refuse_without_changes() {
        let dir = tempfile::tempdir().unwrap();
        let source: Arc<dyn MountSource> =
            Arc::new(crate::FolderMountSource::new(dir.path()).unwrap());
        let base =
            crate::ClassifiedBase::for_tests(source.clone(), crate::ServedKind::Folder, None);
        let record = crate::SealedRecord {
            dir: dir.path().to_path_buf(),
            layer_digest: String::new(),
            sealed_at: String::new(),
            meta: crate::OverlayMeta::default(),
        };
        let errors = [
            seal(dir.path(), &base, source.clone()).unwrap_err(),
            reseal(&record).unwrap_err(),
            unseal(dir.path()).unwrap_err(),
            SealOperation::acquire(dir.path()).err().unwrap(),
            SealOperation::acquire_until(dir.path(), None)
                .err()
                .unwrap(),
            SealOperation.finish_if_sealed().unwrap_err(),
            SealOperation.seal(&base, source).unwrap_err(),
        ];
        for error in errors {
            assert_eq!(error.kind(), io::ErrorKind::Unsupported);
            assert_eq!(
                error.to_string(),
                "overlay seal/unseal is not supported on this platform"
            );
        }
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    /// Regression (#341): a layer with preimage pins is refused where they
    /// cannot be rehashed; one without pins has none to check.
    #[test]
    fn regression_nonunix_preimage_pins_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let source: Arc<dyn MountSource> =
            Arc::new(crate::FolderMountSource::new(dir.path()).unwrap());
        let conn = rusqlite::Connection::open(dir.path().join(crate::HIDDEN_DB)).unwrap();
        conn.execute_batch(crate::overlay_meta::META_SCHEMA)
            .unwrap();
        crate::OverlayMeta::set(&conn, "format_version", "2").unwrap();
        drop(conn);
        assert!(check_preimages(dir.path(), source.clone())
            .unwrap()
            .is_empty());
        let conn = rusqlite::Connection::open(dir.path().join(crate::HIDDEN_DB)).unwrap();
        crate::OverlayMeta::set(&conn, PREIMAGE_DIGEST_KEY, "sha256:x").unwrap();
        drop(conn);
        let error = check_preimages(dir.path(), source).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }

    /// Regression: removing only the binding left a pin table that the
    /// non-Unix fallback silently accepted instead of refusing to skip it.
    #[test]
    fn regression_nonunix_preimage_pins_without_binding_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let source: Arc<dyn MountSource> =
            Arc::new(crate::FolderMountSource::new(dir.path()).unwrap());
        let conn = rusqlite::Connection::open(dir.path().join(crate::HIDDEN_DB)).unwrap();
        conn.execute_batch(crate::overlay_meta::META_SCHEMA)
            .unwrap();
        crate::OverlayMeta::set(&conn, "format_version", "2").unwrap();
        conn.execute_batch(
            "CREATE TABLE seal_preimages(path TEXT); INSERT INTO seal_preimages VALUES ('f');",
        )
        .unwrap();
        drop(conn);
        let error = check_preimages(dir.path(), source).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }
}
