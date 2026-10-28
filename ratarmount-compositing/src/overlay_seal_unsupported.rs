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

pub struct SealOperation;

impl SealOperation {
    pub fn acquire(_dir: &Path) -> io::Result<Self> {
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
}
