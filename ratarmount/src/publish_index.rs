//! Copy a portable 0.7.x SQLite sidecar (`--publish-index` / `--publish-index-to`).
//!
//! Local copy + atomic replace. No S3 PUT in v1 (`aws s3 cp`). OCI referrer PUT
//! is residual (discovery is referrer GET on local miss).

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use ratarmount_index::{
    archive_base_from_index_path, default_index_path, index_pointer_path, load_index_pointer,
    parse_index_id, publish_index_pointer, snapshot_index_id, INDEX_MEDIA_TYPE,
};

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
    let base = archive_base_from_index_path(&dest);
    if dest != opts.sidecar {
        if opts.no_recreate_index && dest.exists() {
            return Err(format!(
                "--no-recreate-index: refusing to overwrite {}",
                dest.display()
            ));
        }
        // Snapshot dest (previous blob) using old_id from the existing pointer
        // before replace. Do not SHA-256 the sidecar to invent an id.
        if dest.exists() {
            if let Ok(Some(old)) = load_index_pointer(&index_pointer_path(&base)) {
                if let Ok(old_id) = parse_index_id(&old.index_id) {
                    let _ = snapshot_index_id(&base, &dest, &old_id);
                }
            }
        }
        atomic_copy(opts.sidecar, &dest)
            .map_err(|e| format!("publish-index {}: {e}", dest.display()))?;
    }
    publish_index_pointer(&base, &dest, Some(opts.archive), None).map_err(|e| {
        format!(
            "publish-index pointer {}: {e}",
            index_pointer_path(&base).display()
        )
    })?;
    let bytes = fs::metadata(&dest).map(|m| m.len()).unwrap_or(0);
    log::info!(
        "published index {} ({bytes} bytes, {INDEX_MEDIA_TYPE})",
        dest.display()
    );
    if dest != opts.sidecar {
        eprintln!(
            "published index {} ({bytes} bytes, {INDEX_MEDIA_TYPE})",
            dest.display()
        );
    }
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
        let ptr_path = ratarmount_index::index_pointer_path_for_index_file(&dest);
        let ptr = ratarmount_index::load_index_pointer(&ptr_path)
            .unwrap()
            .expect("pointer next to dest");
        assert_eq!(ptr.schema, ratarmount_index::INDEX_POINTER_SCHEMA);
        assert_eq!(ptr.index_id, ratarmount_index::sha256_hex(blob));
        assert_eq!(ptr.etag_sha256, ptr.index_id);
    }

    /// Regression: dest == sidecar still writes `{archive}.index.ptr`.
    #[test]
    fn publish_index_dest_eq_sidecar_writes_ptr() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        fs::write(&archive, b"archive-bytes").unwrap();
        let sidecar = ratarmount_index::default_index_path(&archive);
        let blob = b"SQLite format 3\0same-path";
        fs::write(&sidecar, blob).unwrap();
        let got = publish_index(PublishIndexOpts {
            archive: &archive,
            sidecar: &sidecar,
            dest: None,
            no_recreate_index: false,
        })
        .expect("publish");
        assert_eq!(got, sidecar);
        assert_eq!(fs::read(&sidecar).unwrap(), blob);
        let ptr_path = ratarmount_index::index_pointer_path(&archive);
        assert!(ptr_path.is_file(), "dest==sidecar must still write .ptr");
        let ptr = ratarmount_index::load_index_pointer(&ptr_path)
            .unwrap()
            .expect("ptr");
        assert_eq!(ptr.index_id, ratarmount_index::sha256_hex(blob));
    }

    /// Regression: remount `--index-id` of N while N+1 is well-known (keep-last-K=2).
    #[test]
    fn publish_index_keep_last_k_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        fs::write(&archive, b"archive-bytes").unwrap();
        let dest = dir.path().join("out.index.sqlite");
        let blob_n = b"SQLite format 3\0blob-N";
        let sidecar_n = dir.path().join("n.index.sqlite");
        fs::write(&sidecar_n, blob_n).unwrap();
        publish_index(PublishIndexOpts {
            archive: &archive,
            sidecar: &sidecar_n,
            dest: Some(&dest),
            no_recreate_index: false,
        })
        .unwrap();
        let id_n = ratarmount_index::sha256_hex(blob_n);

        let blob_np1 = b"SQLite format 3\0blob-N+1-more";
        let sidecar_np1 = dir.path().join("np1.index.sqlite");
        fs::write(&sidecar_np1, blob_np1).unwrap();
        publish_index(PublishIndexOpts {
            archive: &archive,
            sidecar: &sidecar_np1,
            dest: Some(&dest),
            no_recreate_index: false,
        })
        .unwrap();
        let id_np1 = ratarmount_index::sha256_hex(blob_np1);
        assert_eq!(fs::read(&dest).unwrap(), blob_np1);

        let base = ratarmount_index::archive_base_from_index_path(&dest);
        let snap = ratarmount_index::index_id_path(&base, &id_n).unwrap();
        assert!(
            snap.is_file(),
            "previous blob kept as index.{{old_id}}.sqlite"
        );
        assert_eq!(fs::read(&snap).unwrap(), blob_n);
        assert_eq!(
            ratarmount_index::resolve_index_id_path(&base, &id_n).unwrap(),
            snap
        );
        assert_eq!(
            ratarmount_index::resolve_index_id_path(&base, &id_np1).unwrap(),
            dest
        );
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
