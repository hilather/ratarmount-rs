//! Copy a portable 0.7.x SQLite sidecar (`--publish-index` / `--publish-index-to`).
//!
//! Local copy + atomic replace. `s3://` archives PUT the sqlite blob then
//! `{url}.index.ptr` (GCS/Azure PUT residual). OCI referrer PUT is residual
//! (discovery is referrer GET on local miss).

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use ratarmount_index::{
    archive_base_from_index_path, default_index_path, index_pointer_path, publish_index_pointer,
    INDEX_MEDIA_TYPE,
};

pub struct PublishIndexOpts<'a> {
    pub archive: &'a Path,
    pub sidecar: &'a Path,
    pub dest: Option<&'a Path>,
    pub no_recreate_index: bool,
}

/// Copy `sidecar` to `dest` (or `{archive}.index.sqlite`). `s3://` also PUTs.
pub fn publish_index(opts: PublishIndexOpts<'_>) -> Result<PathBuf, String> {
    if !opts.sidecar.is_file() {
        return Err(format!(
            "no on-disk index to publish ({})",
            opts.sidecar.display()
        ));
    }
    let archive_s = opts.archive.to_string_lossy();
    if archive_s.starts_with("s3://") {
        return publish_index_s3(opts, archive_s.as_ref());
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
        atomic_copy(opts.sidecar, &dest)
            .map_err(|e| format!("publish-index {}: {e}", dest.display()))?;
    }
    // Pin dest as `{base}.index.{new_id}.sqlite` (hardlink after dest holds the
    // published bytes) so dest==sidecar + later `-c` still keeps generation N.
    publish_index_pointer(&base, &dest, Some(opts.archive)).map_err(|e| {
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

fn publish_index_s3(opts: PublishIndexOpts<'_>, archive_url: &str) -> Result<PathBuf, String> {
    let dest = opts.dest.map(|p| p.to_path_buf());
    if let Some(ref dest) = dest {
        if opts.no_recreate_index && dest.exists() {
            return Err(format!(
                "--no-recreate-index: refusing to overwrite {}",
                dest.display()
            ));
        }
        if dest != opts.sidecar {
            atomic_copy(opts.sidecar, dest)
                .map_err(|e| format!("publish-index {}: {e}", dest.display()))?;
        }
    }
    let blob = dest.as_deref().unwrap_or(opts.sidecar);
    // WAL rows must land in the main file before PutObject.
    {
        let conn = rusqlite::Connection::open(blob).map_err(|e| e.to_string())?;
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .map_err(|e| e.to_string())?;
    }
    let ptr = ratarmount_index::IndexPointer::for_blob(blob, None)
        .map_err(|e| format!("publish-index pointer: {e}"))?;
    let json = format!(
        "{{\n  \"schema\": \"{}\",\n  \"index_id\": \"{}\",\n  \"etag_sha256\": \"{}\",\n  \"generated_at\": \"{}\"\n}}\n",
        ptr.schema, ptr.index_id, ptr.etag_sha256, ptr.generated_at
    );
    ratarmount_remote::publish_index_to_s3(
        archive_url,
        blob,
        &ratarmount_remote::S3IndexPointer {
            index_id: ptr.index_id,
            json: json.into_bytes(),
        },
    )
    .map_err(|e| format!("publish-index {archive_url}: {e}"))?;
    let published = dest.unwrap_or_else(|| opts.sidecar.to_path_buf());
    let bytes = fs::metadata(&published).map(|m| m.len()).unwrap_or(0);
    log::info!("published index {archive_url} ({bytes} bytes, {INDEX_MEDIA_TYPE})");
    eprintln!("published index {archive_url} ({bytes} bytes, {INDEX_MEDIA_TYPE})");
    Ok(published)
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
        let resolved_np1 = ratarmount_index::resolve_index_id_path(&base, &id_np1).unwrap();
        assert_eq!(fs::read(&resolved_np1).unwrap(), blob_np1);
    }

    /// Regression: dest==sidecar `--publish-index` pins N so remount `--index-id` of N
    /// still works after well-known is rebuilt to N+1 (`-c` tmp+rename).
    #[test]
    fn publish_index_dest_eq_sidecar_keep_last_k_across_rebuild() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        fs::write(&archive, b"archive-bytes").unwrap();
        let sidecar = ratarmount_index::default_index_path(&archive);
        let blob_n = b"SQLite format 3\0sidecar-N";
        fs::write(&sidecar, blob_n).unwrap();
        publish_index(PublishIndexOpts {
            archive: &archive,
            sidecar: &sidecar,
            dest: None,
            no_recreate_index: false,
        })
        .unwrap();
        let id_n = ratarmount_index::sha256_hex(blob_n);

        let blob_np1 = b"SQLite format 3\0sidecar-N+1";
        let np1 = dir.path().join("np1.tmp");
        fs::write(&np1, blob_np1).unwrap();
        fs::rename(&np1, &sidecar).unwrap();
        publish_index(PublishIndexOpts {
            archive: &archive,
            sidecar: &sidecar,
            dest: None,
            no_recreate_index: false,
        })
        .unwrap();

        let snap = ratarmount_index::index_id_path(&archive, &id_n).unwrap();
        assert!(snap.is_file(), "dest==sidecar must pin index.{{id}}.sqlite");
        assert_eq!(fs::read(&snap).unwrap(), blob_n);
        assert_eq!(
            ratarmount_index::resolve_index_id_path(&archive, &id_n).unwrap(),
            snap
        );
        let id_np1 = ratarmount_index::sha256_hex(blob_np1);
        let resolved_np1 = ratarmount_index::resolve_index_id_path(&archive, &id_np1).unwrap();
        assert_eq!(fs::read(&resolved_np1).unwrap(), blob_np1);
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
