//! Copy a portable 0.7.x SQLite sidecar (`--publish-index` / `--publish-index-to`).
//!
//! Local copy + atomic replace. No S3 PUT in v1 (`aws s3 cp`). OCI referrer PUT
//! is residual (discovery is referrer GET on local miss).

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use ratarmount_index::{default_index_path, INDEX_MEDIA_TYPE};

pub struct PublishIndexOpts<'a> {
    pub archive: &'a Path,
    pub sidecar: &'a Path,
    pub dest: Option<&'a Path>,
    pub no_recreate_index: bool,
}

/// Copy `sidecar` to `dest` (or `{archive}.index.sqlite`).
pub fn publish_index(opts: PublishIndexOpts<'_>) -> Result<PathBuf, String> {
    if !opts.sidecar.is_file() {
        return Err(format!(
            "no on-disk index to publish ({})",
            opts.sidecar.display()
        ));
    }
    let dest = match opts.dest {
        Some(p) => p.to_path_buf(),
        None => default_index_path(opts.archive),
    };
    if dest == opts.sidecar {
        let bytes = fs::metadata(&dest).map(|m| m.len()).unwrap_or(0);
        log::info!(
            "published index {} ({bytes} bytes, {INDEX_MEDIA_TYPE})",
            dest.display()
        );
        return Ok(dest);
    }
    if opts.no_recreate_index && dest.exists() {
        return Err(format!(
            "--no-recreate-index: refusing to overwrite {}",
            dest.display()
        ));
    }
    atomic_copy(opts.sidecar, &dest)
        .map_err(|e| format!("publish-index {}: {e}", dest.display()))?;
    let bytes = fs::metadata(&dest).map(|m| m.len()).unwrap_or(0);
    log::info!(
        "published index {} ({bytes} bytes, {INDEX_MEDIA_TYPE})",
        dest.display()
    );
    eprintln!(
        "published index {} ({bytes} bytes, {INDEX_MEDIA_TYPE})",
        dest.display()
    );
    Ok(dest)
}

fn atomic_copy(src: &Path, dest: &Path) -> io::Result<()> {
    if let Some(parent) = dest.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let mut builder = tempfile::Builder::new();
    builder.prefix(".ratarmount-publish-").suffix(".tmp");
    let parent = dest.parent().filter(|p| !p.as_os_str().is_empty());
    let mut tmp = match parent {
        Some(p) => builder.tempfile_in(p)?,
        None => builder.tempfile_in(".")?,
    };
    {
        let mut in_f = fs::File::open(src)?;
        io::copy(&mut in_f, &mut tmp)?;
        tmp.flush()?;
    }
    tmp.persist(dest).map_err(|e| e.error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Regression: `--publish-index` copies the sidecar (atomic replace).
    #[test]
    fn publish_index_copies_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        fs::write(&archive, b"archive-bytes").unwrap();
        let sidecar = dir.path().join("src.index.sqlite");
        let blob = b"SQLite format 3\0publish-me";
        fs::write(&sidecar, blob).unwrap();
        let dest = dir.path().join("out.index.sqlite");
        let got = publish_index(PublishIndexOpts {
            archive: &archive,
            sidecar: &sidecar,
            dest: Some(&dest),
            no_recreate_index: false,
        })
        .expect("publish");
        assert_eq!(got, dest);
        assert_eq!(fs::read(&dest).unwrap(), blob);
    }

    #[test]
    fn publish_index_refuses_overwrite_when_no_recreate() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        fs::write(&archive, b"a").unwrap();
        let sidecar = dir.path().join("src.index.sqlite");
        fs::write(&sidecar, b"SQLite format 3\0new").unwrap();
        let dest = dir.path().join("out.index.sqlite");
        fs::write(&dest, b"old").unwrap();
        let err = publish_index(PublishIndexOpts {
            archive: &archive,
            sidecar: &sidecar,
            dest: Some(&dest),
            no_recreate_index: true,
        })
        .unwrap_err();
        assert!(err.contains("--no-recreate-index"), "{err}");
        assert_eq!(fs::read(&dest).unwrap(), b"old");
    }
}
