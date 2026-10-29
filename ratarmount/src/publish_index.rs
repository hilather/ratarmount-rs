//! Copy a portable 0.7.x SQLite sidecar (`--publish-index` / `--publish-index-to`).
//!
//! Local copies keep the existing snapshot protocol. Remote publication writes an
//! immutable blob before its pointer, or both names in one atomic Hub commit.

use std::fs;
use std::io::{self, Read, SeekFrom, Write};
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

/// Validate before building an index or sending any write requests.
pub fn validate_publish_options(
    publishing: bool,
    inputs: &[PathBuf],
    dest: Option<&Path>,
    revision: Option<&str>,
    create_pr: bool,
) -> Result<(), String> {
    if !publishing {
        if revision.is_some() || create_pr {
            return Err(
                "--publish-revision / --create-pr require --publish-index or --publish-index-to"
                    .into(),
            );
        }
        return Ok(());
    }
    if inputs.len() != 1 {
        return Err("index publication requires exactly one archive".into());
    }
    let target = dest.unwrap_or(&inputs[0]).to_string_lossy();
    if ratarmount_remote::is_remote_url(&target) && !remote_publish_url(&target) {
        return Err("index publication supports hf://, s3://, gs://, az:// and local paths".into());
    }
    if (revision.is_some() || create_pr) && !target.starts_with("hf://") {
        return Err("--publish-revision / --create-pr require an hf:// destination".into());
    }
    Ok(())
}

fn remote_publish_url(url: &str) -> bool {
    url.starts_with("hf://") || ratarmount_remote::is_object_store_archive_url(url)
}

/// The caller has already opened the archive through the session factory.
pub fn publish_validated_index(
    opts: PublishIndexOpts<'_>,
    revision: Option<&str>,
    create_pr: bool,
) -> Result<(), String> {
    let target = opts.dest.unwrap_or(opts.archive).to_string_lossy();
    if !remote_publish_url(&target) {
        return publish_index(opts).map(|_| ());
    }
    publish_remote(opts, &target, revision, create_pr).map_err(|e| format!("publish-index: {e}"))
}

fn remote_reader(
    url: &str,
    repo: Option<&ratarmount_remote::HfRepo>,
) -> Result<Box<dyn ratarmount_core::ArchiveRead>, String> {
    let result: ratarmount_remote::Result<Box<dyn ratarmount_core::ArchiveRead>> =
        if let Some(repo) = repo {
            repo.open_file(&repo.location.path)
                .map(|r| Box::new(r) as _)
        } else if url.starts_with("s3://") {
            ratarmount_remote::open_s3_range(url).map(|r| Box::new(r) as _)
        } else if url.starts_with("gs://") {
            ratarmount_remote::open_gcs_range(url).map(|r| Box::new(r) as _)
        } else if url.starts_with("az://") || url.starts_with("azure://") {
            ratarmount_remote::open_azure_range(url).map(|r| Box::new(r) as _)
        } else {
            return Err("unsupported remote archive for publication".into());
        };
    result.map_err(|e| e.to_string())
}

fn fingerprint(
    reader: &mut dyn ratarmount_core::ArchiveRead,
) -> Result<ratarmount_index::TarStats, String> {
    use ratarmount_index::{
        sha256_hex_stream, TarStats, TARSTATS_FULL_HASH_MAX, TARSTATS_SAMPLE_BYTES,
    };
    let len = reader.seek(SeekFrom::End(0)).map_err(|e| e.to_string())?;
    let mut hash = |offset, count| -> Result<String, String> {
        reader
            .seek(SeekFrom::Start(offset))
            .map_err(|e| e.to_string())?;
        let mut window = (&mut *reader).take(count);
        let hash = sha256_hex_stream(&mut window).map_err(|e| e.to_string())?;
        if window.limit() != 0 {
            return Err("archive truncated while fingerprinting for publication".into());
        }
        Ok(hash)
    };
    let sample = len.min(TARSTATS_SAMPLE_BYTES as u64);
    Ok(TarStats {
        st_size: len,
        st_mtime: 0,
        st_mtime_ns: None,
        prefix512_sha256: Some(hash(0, sample)?),
        suffix512_sha256: Some(hash(len.saturating_sub(sample), sample)?),
        full_sha256: if len <= TARSTATS_FULL_HASH_MAX {
            Some(hash(0, len)?)
        } else {
            None
        },
    })
}

fn verify_stats(
    stored: &ratarmount_index::TarStats,
    actual: &ratarmount_index::TarStats,
) -> Result<(), String> {
    ratarmount_index::check_tarstats_matches_remote(
        stored,
        actual.st_size,
        actual.prefix512_sha256.as_deref(),
        actual.suffix512_sha256.as_deref(),
        actual.full_sha256.as_deref(),
    )
    .map_err(|e| format!("archive no longer matches the index: {e}"))
}

fn publish_remote(
    opts: PublishIndexOpts<'_>,
    target: &str,
    revision: Option<&str>,
    create_pr: bool,
) -> Result<(), String> {
    use ratarmount_index::{IndexPointer, SqliteIndex, META_SIDECAR_WHOLE_MAX};
    let metadata = SqliteIndex::open_read_only(opts.sidecar)
        .and_then(|i| i.metadata())
        .map_err(|e| e.to_string())?;
    let source = opts.archive.to_string_lossy();
    let source_repo = if source.starts_with("hf://") {
        let repo = ratarmount_remote::HfRepo::resolve(&source).map_err(|e| e.to_string())?;
        if metadata.get("hf.commit") != Some(&repo.commit)
            || metadata.get("hf.resolve_url") != Some(&repo.resolve_url(&repo.location.path))
        {
            return Err(
                "Hub archive revision changed or index provenance is missing; rebuild and retry"
                    .into(),
            );
        }
        Some(repo)
    } else {
        None
    };
    let stats = if opts.archive.is_file() {
        SqliteIndex::open_read_only(opts.sidecar)
            .and_then(|i| i.check_tarstats_matches_archive(opts.archive))
            .map_err(|e| e.to_string())?;
        ratarmount_index::tar_stats_from_path(opts.archive).map_err(|e| e.to_string())?
    } else {
        let mut reader = remote_reader(&source, source_repo.as_ref())?;
        let actual = fingerprint(reader.as_mut())?;
        if let Some(stored) = SqliteIndex::open_read_only(opts.sidecar)
            .and_then(|i| i.tarstats())
            .map_err(|e| e.to_string())?
        {
            // Fresh remote factory indexes may only contain synthetic size statistics.
            if stored.prefix512_sha256.is_some()
                || stored.suffix512_sha256.is_some()
                || stored.full_sha256.is_some()
            {
                verify_stats(&stored, &actual)?;
            }
        }
        actual
    };
    let target_repo = if target.starts_with("hf://") {
        let repo = if source == target {
            source_repo.clone().ok_or("missing Hub source")?
        } else {
            ratarmount_remote::HfRepo::resolve(target).map_err(|e| e.to_string())?
        };
        repo.require_publish_token().map_err(|e| e.to_string())?;
        let branch = repo.publish_branch(revision).map_err(|e| e.to_string())?;
        let repo = if branch == repo.location.revision {
            repo
        } else {
            repo.at_revision(&branch).map_err(|e| e.to_string())?
        };
        Some(repo)
    } else {
        None
    };
    // An explicit destination is an archive URL, whose bytes must match the source.
    // Resolving another branch also requires validating that branch's archive bytes.
    if source != target
        || target_repo
            .as_ref()
            .zip(source_repo.as_ref())
            .is_some_and(|(a, b)| a.commit != b.commit)
    {
        let mut reader = remote_reader(target, target_repo.as_ref())?;
        verify_stats(&stats, &fingerprint(reader.as_mut())?)?;
    }
    // Snapshot before fingerprinting the blob. Do not rewrite an index held by the mount.
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-B0086-M01","item":"ratarmount::publish_index::publish_remote","disposition":"output-owner","mode_policy":"unchanged-from-e6ca64e","category":"output-owner","reason":"Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"unchanged-from-e6ca64e","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###
    )]
    let tmp = tempfile::NamedTempFile::new().map_err(|e| e.to_string())?;
    snapshot_sidecar(opts.sidecar, tmp.path())?;
    {
        let index = SqliteIndex::open_writable(tmp.path()).map_err(|e| e.to_string())?;
        index
            .store_metadata_key_value("tarstats", &ratarmount_index::serialize_tarstats(&stats))
            .map_err(|e| e.to_string())?;
        index.wal_checkpoint_truncate().map_err(|e| e.to_string())?;
    }
    if fs::metadata(tmp.path()).map_err(|e| e.to_string())?.len() > META_SIDECAR_WHOLE_MAX {
        return Err(format!(
            "index exceeds publication limit ({META_SIDECAR_WHOLE_MAX} bytes)"
        ));
    }
    let mut pointer = IndexPointer::for_blob(tmp.path(), None).map_err(|e| e.to_string())?;
    pointer.archive_tarstats = Some(
        serde_json::from_str(&ratarmount_index::serialize_tarstats(&stats))
            .map_err(|e| e.to_string())?,
    );
    let mut value = serde_json::to_value(&pointer).map_err(|e| e.to_string())?;
    if let Some(repo) = source_repo.as_ref().or(target_repo.as_ref()) {
        value["archive_hf_commit"] = serde_json::json!(repo.commit);
        value["archive_hf_resolve_url"] = serde_json::json!(repo.resolve_url(&repo.location.path));
    }
    let pointer_bytes = serde_json::to_vec(&value).map_err(|e| e.to_string())?;
    if let Some(repo) = target_repo {
        // Managed (#151): the snapshot is read through SQLite's VFS.
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-B0087-M01","item":"ratarmount::publish_index::publish_remote","disposition":"sqlite-snapshot","regression":"regression_publish_index_readers_keep_index_lock","category":"sqlite-snapshot","reason":"Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
        )]
        let blob = ratarmount_index::managed_read::read(tmp.path()).map_err(|e| e.to_string())?;
        let blob_path = format!("{}.index.{}.sqlite", repo.location.path, pointer.index_id);
        let pointer_path = format!("{}.index.ptr", repo.location.path);
        let result = repo
            .commit_files(
                &[
                    ratarmount_remote::HfCommitFile {
                        path: &blob_path,
                        content: &blob,
                    },
                    ratarmount_remote::HfCommitFile {
                        path: &pointer_path,
                        content: &pointer_bytes,
                    },
                ],
                Some(&repo.location.revision),
                create_pr,
                Some(&repo.commit),
            )
            .map_err(|e| e.to_string())?;
        eprintln!("published index at Hub commit {}", result.commit);
        if let Some(pr) = result.pull_request_url {
            eprintln!("pull request: {pr}");
        }
    } else {
        ratarmount_remote::put_object_store_index_siblings(
            target,
            &pointer.index_id,
            &pointer_bytes,
            tmp.path(),
        )
        .map_err(|e| e.to_string())?;
        eprintln!("published index {target}.index.ptr");
    }
    Ok(())
}

// VACUUM INTO takes a consistent SQLite snapshot including committed WAL pages.
// A filesystem copy can silently omit metadata while the mounted index is open.
fn snapshot_sidecar(source: &Path, dest: &Path) -> Result<(), String> {
    let source =
        rusqlite::Connection::open_with_flags(source, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|e| e.to_string())?;
    let dest = dest
        .to_str()
        .ok_or("publication snapshot path is not UTF-8")?;
    source
        .execute("VACUUM INTO ?1", [dest])
        .map_err(|e| format!("snapshot index: {e}"))?;
    Ok(())
}

fn atomic_copy(src: &Path, dest: &Path) -> io::Result<()> {
    if let Some(parent) = dest.parent() {
        if !parent.as_os_str().is_empty() {
            #[expect(
                clippy::disallowed_methods,
                reason = r###"internal-read:v1 {"id":"IR-E0132-M01","item":"ratarmount::publish_index::atomic_copy","disposition":"output-owner","category":"published-index-directory","reason":"Create the publication destination parent before atomic managed-source index copying.","creation":{"policy":"recursive-directory","basis":"Only output parents are created; the separately reviewed managed copy and tempfile publication preserve source/input obligations."}}"###
            )]
            fs::create_dir_all(parent)?;
        }
    }
    let mut builder = tempfile::Builder::new();
    builder.prefix(".ratarmount-publish-").suffix(".tmp");
    let parent = dest.parent().filter(|p| !p.as_os_str().is_empty());
    let mut tmp = match parent {
        Some(p) => {
            #[expect(
                clippy::disallowed_methods,
                reason = r###"internal-read:v1 {"id":"IR-B0088-M01","item":"ratarmount::publish_index::atomic_copy","disposition":"output-owner","mode_policy":"unchanged-from-e6ca64e","category":"output-owner","reason":"Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"unchanged-from-e6ca64e","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###
            )]
            let __inventory_value_0 = builder.tempfile_in(p);
            __inventory_value_0
        }?,
        None => {
            #[expect(
                clippy::disallowed_methods,
                reason = r###"internal-read:v1 {"id":"IR-B0089-M01","item":"ratarmount::publish_index::atomic_copy","disposition":"output-owner","mode_policy":"unchanged-from-e6ca64e","category":"output-owner","reason":"Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"unchanged-from-e6ca64e","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###
            )]
            let __inventory_value_0 = builder.tempfile_in(".");
            __inventory_value_0
        }?,
    };
    {
        // Managed (#151): the source is an index that may be open here.
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-B0090-M01","item":"ratarmount::publish_index::atomic_copy","disposition":"managed-read","regression":"regression_publish_index_readers_keep_index_lock","category":"managed-read","reason":"Use the reviewed managed reader under the existing lock guarantee.","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
        )]
        ratarmount_index::managed_read::copy_into(src, &mut tmp)?;
        tmp.flush()?;
    }
    tmp.persist(dest).map_err(|e| e.error)?;
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
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
    // Acquire before test_process guards: a queued exclusive writer can block
    // readers while a publication holding this mutex requests a lock probe.
    static PUBLISH_ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());
    pub(crate) struct PublishEnv {
        saved: Vec<(String, Option<std::ffi::OsString>)>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }
    impl PublishEnv {
        pub(crate) fn new(values: &[(&str, &str)]) -> Self {
            let lock = PUBLISH_ENV.lock().unwrap_or_else(|e| e.into_inner());
            let mut updates = std::collections::BTreeMap::new();
            for key in [
                "AWS_ACCESS_KEY_ID",
                "AWS_SECRET_ACCESS_KEY",
                "AWS_SESSION_TOKEN",
                "AWS_ENDPOINT_URL",
                "S3_ENDPOINT_URL",
                "AWS_ANONYMOUS",
                "RATARMOUNT_S3_ANONYMOUS",
                "CLOUDSDK_AUTH_ACCESS_TOKEN",
                "GOOGLE_OAUTH_ACCESS_TOKEN",
                "GOOGLE_APPLICATION_CREDENTIALS",
                "GOOGLE_HMAC_KEY",
                "GOOGLE_HMAC_SECRET",
                "RATARMOUNT_GCS_ANONYMOUS",
                "CLOUDSDK_ANONYMOUS",
                "AZURE_STORAGE_SAS_TOKEN",
                "AZURE_STORAGE_KEY",
                "AZURE_STORAGE_ACCOUNT",
                "HF_TOKEN",
                "HUGGING_FACE_HUB_TOKEN",
                "HF_ENDPOINT",
            ] {
                updates.insert(key, None);
            }
            for &(key, value) in values {
                updates.insert(key, Some(value));
            }
            let saved = updates
                .into_iter()
                .map(|(key, value)| {
                    let old = std::env::var_os(key);
                    if let Some(value) = value {
                        std::env::set_var(key, value);
                    } else {
                        std::env::remove_var(key);
                    }
                    (key.to_string(), old)
                })
                .collect();
            Self { saved, _lock: lock }
        }
    }
    impl Drop for PublishEnv {
        fn drop(&mut self) {
            for (key, value) in self.saved.drain(..) {
                if let Some(value) = value {
                    std::env::set_var(key, value);
                } else {
                    std::env::remove_var(key);
                }
            }
        }
    }
    #[derive(Default)]
    pub(crate) struct PublishState {
        pub(crate) objects: std::collections::BTreeMap<String, Vec<u8>>,
        pub(crate) requests: Vec<(String, String, Vec<u8>)>,
        commit: bool,
        pub(crate) conflict_on_commit: bool,
        pub(crate) fail_commit_response: bool,
        pub(crate) head: String,
        pr_head: String,
        generation: usize,
        snapshots: std::collections::BTreeMap<String, std::collections::BTreeMap<String, Vec<u8>>>,
        lfs: std::collections::BTreeMap<String, Vec<u8>>,
    }
    pub(crate) struct PublishServer {
        pub(crate) url: String,
        pub(crate) state: std::sync::Arc<std::sync::Mutex<PublishState>>,
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
        join: Option<std::thread::JoinHandle<()>>,
    }
    impl PublishServer {
        pub(crate) fn new(archive: Vec<u8>, fail_blob: bool, fail_pointer: bool) -> Self {
            Self::with_live(archive, fail_blob, fail_pointer, false)
        }
        pub(crate) fn live(archive: Vec<u8>) -> Self {
            Self::with_live(archive, false, false, true)
        }
        fn with_live(archive: Vec<u8>, fail_blob: bool, fail_pointer: bool, live: bool) -> Self {
            use std::io::{BufRead, BufReader};
            use std::sync::{
                atomic::{AtomicBool, Ordering},
                Arc, Mutex,
            };
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let state = Arc::new(Mutex::new(PublishState::default()));
            if live {
                let mut state = state.lock().unwrap();
                state.head = "a".repeat(40);
                let name = if archive.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
                    "a.tar.zst"
                } else {
                    "a.tar"
                };
                state.objects.insert(name.into(), archive.clone());
                let objects = state.objects.clone();
                state.snapshots.insert("a".repeat(40), objects);
            }
            let upload_url = url.clone();
            let shared = state.clone();
            let stop = Arc::new(AtomicBool::new(false));
            let stopped = stop.clone();
            let join = std::thread::spawn(move || {
                while !stopped.load(Ordering::Relaxed) {
                    let (mut stream, _) = match listener.accept() {
                        Ok(v) => v,
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            std::thread::sleep(std::time::Duration::from_millis(2));
                            continue;
                        }
                        Err(_) => break,
                    };
                    // macOS/BSD accept inherits the listener's O_NONBLOCK.
                    stream.set_nonblocking(false).unwrap();
                    stream
                        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                        .unwrap();
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        continue;
                    }
                    let fields: Vec<_> = line.split_whitespace().collect();
                    let method = fields[0].to_string();
                    let path = fields[1].to_string();
                    let mut headers = std::collections::BTreeMap::new();
                    loop {
                        let mut line = String::new();
                        reader.read_line(&mut line).unwrap();
                        if line == "\r\n" || line.is_empty() {
                            break;
                        }
                        let (k, v) = line.trim().split_once(':').unwrap();
                        headers.insert(k.to_ascii_lowercase(), v.trim().to_string());
                    }
                    let n = headers
                        .get("content-length")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0);
                    let mut body = vec![0; n];
                    reader.read_exact(&mut body).unwrap();
                    let mut state = shared.lock().unwrap();
                    state
                        .requests
                        .push((method.clone(), path.clone(), body.clone()));
                    let mut status = 200;
                    let mut extra = Vec::<(String, String)>::new();
                    let mut response = if path.contains("/revision/") {
                        let revision = path.rsplit('/').next().unwrap();
                        let sha = if live {
                            if revision.len() == 40 {
                                revision.to_string()
                            } else if revision.starts_with("refs%2Fpr%2F") {
                                state.pr_head.clone()
                            } else {
                                state.head.clone()
                            }
                        } else if state.commit {
                            "b".repeat(40)
                        } else {
                            "a".repeat(40)
                        };
                        serde_json::json!({"sha":sha}).to_string().into_bytes()
                    } else if path.ends_with("/refs") {
                        serde_json::json!({"branches":[{"name":"main"},{"name":"dev"}],"tags":[{"name":"v1"}]}).to_string().into_bytes()
                    } else if path.contains("/tree/") {
                        status = 404;
                        extra.push(("X-Error-Code".into(), "EntryNotFound".into()));
                        vec![]
                    } else if path.contains("/preupload/") {
                        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
                        serde_json::json!({"files":v["files"].as_array().unwrap().iter().map(|f|serde_json::json!({"path":f["path"],"uploadMode":"regular","shouldIgnore":false})).collect::<Vec<_>>()}).to_string().into_bytes()
                    } else if live && path.ends_with("/info/lfs/objects/batch") {
                        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
                        let object = &v["objects"][0];
                        serde_json::json!({"transfer":"basic","objects":[{"oid":object["oid"],"size":object["size"],"actions":{"upload":{"href":format!("{upload_url}/lfs/{}",object["oid"].as_str().unwrap())}}}]}).to_string().into_bytes()
                    } else if live && path.starts_with("/lfs/") && method == "PUT" {
                        assert!(
                            !headers.contains_key("authorization"),
                            "Hub token leaked to storage"
                        );
                        state
                            .lfs
                            .insert(path.trim_start_matches("/lfs/").into(), body.clone());
                        vec![]
                    } else if live && path.contains("/commit/") {
                        let ops: Vec<serde_json::Value> = std::str::from_utf8(&body)
                            .unwrap()
                            .lines()
                            .map(|l| serde_json::from_str(l).unwrap())
                            .collect();
                        let pr = path.contains("create_pr=1");
                        let on_pr = path.contains("refs%2Fpr%2F");
                        if state.conflict_on_commit {
                            state.head = "f".repeat(40);
                        }
                        let parent = if on_pr { &state.pr_head } else { &state.head };
                        // A new PR forks the specified parent; writes to an existing ref require its head.
                        if !pr && ops[0]["value"]["parentCommit"].as_str() != Some(parent) {
                            status = 409;
                            b"conflict: hf-test must never appear in logs".to_vec()
                        } else {
                            assert_eq!(ops.len(), 4, "archive, index and pointer must be atomic");
                            let mut next = state.objects.clone();
                            for op in &ops[1..] {
                                let v = &op["value"];
                                let bytes = if op["key"] == "lfsFile" {
                                    state.lfs[v["oid"].as_str().unwrap()].clone()
                                } else {
                                    decode_base64(v["content"].as_str().unwrap())
                                };
                                next.insert(v["path"].as_str().unwrap().into(), bytes);
                            }
                            state.generation += 1;
                            let commit = format!("{:x}", state.generation + 10).repeat(40);
                            state.snapshots.insert(commit.clone(), next.clone());
                            state.objects = next;
                            if pr || on_pr {
                                state.pr_head = commit.clone();
                            } else {
                                state.head = commit.clone();
                            }
                            if state.fail_commit_response {
                                status = 500;
                            }
                            serde_json::json!({"commitOid":commit,"pullRequestUrl":if pr {Some(format!("{upload_url}/datasets/org/data/discussions/7"))} else {None}}).to_string().into_bytes()
                        }
                    } else if path.contains("/commit/") {
                        // Publish both names only after parsing the complete commit payload.
                        let mut next = state.objects.clone();
                        for line in std::str::from_utf8(&body).unwrap().lines() {
                            let v: serde_json::Value = serde_json::from_str(line).unwrap();
                            if v["key"] == "header" {
                                assert_eq!(v["value"]["parentCommit"], "a".repeat(40));
                                continue;
                            }
                            let bytes = decode_base64(v["value"]["content"].as_str().unwrap());
                            next.insert(v["value"]["path"].as_str().unwrap().into(), bytes);
                        }
                        state.objects = next;
                        state.commit = true;
                        serde_json::json!({"commitOid":"b".repeat(40)})
                            .to_string()
                            .into_bytes()
                    } else if method == "PUT" {
                        assert!(
                            headers.contains_key("authorization"),
                            "object-store PUT must be authenticated"
                        );
                        assert!(headers.contains_key("content-type"));
                        if (fail_blob && path.contains(".sqlite"))
                            || (fail_pointer && path.ends_with(".ptr"))
                        {
                            status = 500;
                        } else {
                            state.objects.insert(path.clone(), body);
                        }
                        vec![]
                    } else if live && path.contains("/resolve/") {
                        let (commit, key) = path
                            .split("/resolve/")
                            .nth(1)
                            .unwrap()
                            .split_once('/')
                            .unwrap();
                        match state.snapshots.get(commit).and_then(|s| s.get(key)) {
                            Some(bytes) => bytes.clone(),
                            None => {
                                status = 404;
                                vec![]
                            }
                        }
                    } else if path.ends_with("a.tar") || path.ends_with("a.tar.zst") {
                        archive.clone()
                    } else {
                        // Hub resolve URLs pin the newly published commit. Object stores use path-style URLs.
                        let key = path
                            .split("/resolve/")
                            .nth(1)
                            .and_then(|s| s.split_once('/'))
                            .map(|(_, key)| key)
                            .unwrap_or(&path);
                        if let Some(bytes) = state.objects.get(key) {
                            bytes.clone()
                        } else {
                            status = 404;
                            vec![]
                        }
                    };
                    if path.starts_with("/api/") || path.contains("/resolve/") {
                        assert_eq!(
                            headers.get("authorization").map(String::as_str),
                            Some("Bearer hf-test")
                        );
                    }
                    let total = response.len();
                    if status == 200 && method == "GET" {
                        if let Some(range) =
                            headers.get("range").and_then(|v| v.strip_prefix("bytes="))
                        {
                            let (start, end) = range.split_once('-').unwrap();
                            let start: usize = start.parse().unwrap();
                            let end = end
                                .parse::<usize>()
                                .unwrap_or(total.saturating_sub(1))
                                .min(total.saturating_sub(1));
                            response = response[start..=end].to_vec();
                            status = 206;
                            extra.push((
                                "Content-Range".into(),
                                format!("bytes {start}-{end}/{total}"),
                            ));
                        }
                    }
                    write!(stream,"HTTP/1.1 {status} Mock\r\nContent-Length: {}\r\nAccept-Ranges: bytes\r\nConnection: close\r\n",if method=="HEAD" {total}else{response.len()}).unwrap();
                    for (k, v) in extra {
                        write!(stream, "{k}: {v}\r\n").unwrap();
                    }
                    stream.write_all(b"\r\n").unwrap();
                    if method != "HEAD" {
                        let _ = stream.write_all(&response);
                    }
                }
            });
            Self {
                url,
                state,
                stop,
                join: Some(join),
            }
        }
    }
    impl Drop for PublishServer {
        fn drop(&mut self) {
            self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
            let _ = std::net::TcpStream::connect(self.url.trim_start_matches("http://"));
            self.join.take().unwrap().join().unwrap();
        }
    }
    fn decode_base64(s: &str) -> Vec<u8> {
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut bits = 0u32;
        let mut count = 0;
        let mut out = vec![];
        for c in s.bytes().take_while(|c| *c != b'=') {
            bits = (bits << 6) | alphabet.iter().position(|v| *v == c).unwrap() as u32;
            count += 6;
            if count >= 8 {
                count -= 8;
                out.push((bits >> count) as u8);
            }
        }
        out
    }
    pub(crate) fn publish_tar() -> Vec<u8> {
        let mut tar = vec![0u8; 2048];
        tar[..9].copy_from_slice(b"hello.txt");
        tar[100..108].copy_from_slice(b"0000644\0");
        tar[108..116].copy_from_slice(b"0000000\0");
        tar[116..124].copy_from_slice(b"0000000\0");
        tar[124..136].copy_from_slice(b"00000000003\0");
        tar[136..148].copy_from_slice(b"00000000000\0");
        tar[148..156].fill(b' ');
        tar[156] = b'0';
        tar[257..263].copy_from_slice(b"ustar\0");
        tar[263..265].copy_from_slice(b"00");
        let checksum: u32 = tar[..512].iter().map(|b| *b as u32).sum();
        tar[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
        tar[512..515].copy_from_slice(b"hi\n");
        tar
    }
    pub(crate) fn build_publish_index(
        url: &str,
        path: &Path,
        scan: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) -> crate::factory::MountBundle {
        let mut opts = ratarmount_core::OpenOptions {
            index_file_path: Some(path.into()),
            ..Default::default()
        };
        // Direct factory builds emit WRITE/FINALIZE; the Session API adds SCAN.
        // Counting all builder events also catches cold builds of tiny fixtures.
        opts.index_build.on_progress = Some(std::sync::Arc::new(move |_| {
            scan.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }));
        crate::factory::build_mount_source(&[url.into()], &mut opts, false, false).unwrap()
    }

    /// Regression: a published Hub sidecar must be discovered on a cold cache without scanning the archive again.
    #[test]
    fn regression_publish_index_hf_discovery_zero_scan() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };
        for compressed in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let cache = dir.path().join("cache");
            let (name, archive) = if compressed {
                let tar = dir.path().join("source.tar");
                let zst = dir.path().join("source.tar.zst");
                fs::write(&tar, publish_tar()).unwrap();
                ratarmount_compress::repack_seekable(&tar, &zst, &Default::default()).unwrap();
                ("a.tar.zst", fs::read(zst).unwrap())
            } else {
                ("a.tar", publish_tar())
            };
            let archive_len = archive.len();
            let server = PublishServer::new(archive, false, false);
            let _env = PublishEnv::new(&[
                ("HF_ENDPOINT", &server.url),
                ("HF_TOKEN", "hf-test"),
                ("HF_HUB_OFFLINE", "0"),
                ("XDG_CACHE_HOME", cache.to_str().unwrap()),
                (
                    "RATARMOUNT_HF_TREE_CACHE",
                    dir.path().join("trees").to_str().unwrap(),
                ),
            ]);
            let url = &format!("hf://datasets/org/data@main/{name}");
            let sidecar = dir.path().join("built.sqlite");
            let scan = Arc::new(AtomicUsize::new(0));
            drop(build_publish_index(url, &sidecar, scan.clone()));
            assert!(scan.load(Ordering::Relaxed) > 0);
            publish_validated_index(
                PublishIndexOpts {
                    archive: Path::new(url),
                    sidecar: &sidecar,
                    dest: None,
                    no_recreate_index: false,
                },
                None,
                false,
            )
            .unwrap();
            {
                let state = server.state.lock().unwrap();
                let ptr: serde_json::Value =
                    serde_json::from_slice(&state.objects[&format!("{name}.index.ptr")]).unwrap();
                let id = ptr["index_id"].as_str().unwrap();
                let blob = &state.objects[&format!("{name}.index.{id}.sqlite")];
                assert_eq!(id, ratarmount_index::sha256_hex(blob));
                assert_eq!(ptr["archive_hf_commit"], "a".repeat(40));
                assert_eq!(ptr["archive_tarstats"]["st_size"], archive_len);
            }
            scan.store(0, Ordering::Relaxed);
            let bundle =
                build_publish_index(url, &dir.path().join("discovered.sqlite"), scan.clone());
            assert_eq!(scan.load(Ordering::Relaxed), 0);
            let info = bundle.source.lookup("/hello.txt", 0).unwrap();
            let mut file = bundle.source.open(&info, 0).unwrap();
            let mut content = Vec::new();
            file.read_to_end(&mut content).unwrap();
            assert_eq!(content, b"hi\n");
            let state = server.state.lock().unwrap();
            assert!(state
                .requests
                .iter()
                .any(|(_, p, _)| p
                    .contains(&format!("/resolve/{}/{name}.index.ptr", "b".repeat(40)))));
        }
    }

    /// Regression: object-store publication must PUT the blob first and leave no new pointer when either PUT fails.
    #[test]
    fn regression_publish_index_object_store_blob_then_pointer_fail_closed() {
        for scheme in ["s3", "gs", "az"] {
            for (fail_blob, fail_pointer) in [(false, false), (true, false), (false, true)] {
                let dir = tempfile::tempdir().unwrap();
                let tar = dir.path().join("a.tar");
                fs::write(&tar, publish_tar()).unwrap();
                let sidecar = dir.path().join("index.sqlite");
                let mut opts = ratarmount_core::OpenOptions {
                    index_file_path: Some(sidecar.clone()),
                    ..Default::default()
                };
                drop(
                    crate::factory::build_mount_source(
                        std::slice::from_ref(&tar),
                        &mut opts,
                        false,
                        false,
                    )
                    .unwrap(),
                );
                let server = PublishServer::new(publish_tar(), fail_blob, fail_pointer);
                server.state.lock().unwrap().objects.insert(
                    "/bucket/a.tar.index.ptr".into(),
                    b"previous pointer".to_vec(),
                );
                let _env = PublishEnv::new(&[
                    ("AWS_ACCESS_KEY_ID", "test"),
                    ("AWS_SECRET_ACCESS_KEY", "secret"),
                    ("AWS_ENDPOINT_URL", &server.url),
                    ("AWS_REGION", "us-east-1"),
                    ("RATARMOUNT_S3_ANONYMOUS", "0"),
                    ("AWS_ANONYMOUS", "0"),
                    ("RATARMOUNT_GCS_ENDPOINT", &server.url),
                    ("GOOGLE_OAUTH_ACCESS_TOKEN", "test"),
                    ("RATARMOUNT_GCS_ANONYMOUS", "0"),
                    ("AZURE_STORAGE_ACCOUNT", "test"),
                    ("AZURE_STORAGE_KEY", "c2VjcmV0"),
                    ("AZURE_STORAGE_ENDPOINT", &server.url),
                    ("RATARMOUNT_AZURE_ANONYMOUS", "0"),
                ]);
                let url = format!("{scheme}://bucket/a.tar");
                let remote_sidecar = dir.path().join("remote.sqlite");
                if !fail_blob && !fail_pointer {
                    let mut remote_opts = ratarmount_core::OpenOptions {
                        index_file_path: Some(remote_sidecar.clone()),
                        ..Default::default()
                    };
                    drop(
                        crate::factory::build_mount_source(
                            &[PathBuf::from(&url)],
                            &mut remote_opts,
                            false,
                            false,
                        )
                        .unwrap(),
                    );
                }
                let result = publish_validated_index(
                    PublishIndexOpts {
                        archive: if !fail_blob && !fail_pointer {
                            Path::new(&url)
                        } else {
                            &tar
                        },
                        sidecar: if !fail_blob && !fail_pointer {
                            &remote_sidecar
                        } else {
                            &sidecar
                        },
                        dest: if !fail_blob && !fail_pointer {
                            None
                        } else {
                            Some(Path::new(&url))
                        },
                        no_recreate_index: false,
                    },
                    None,
                    false,
                );
                assert_eq!(
                    result.is_err(),
                    fail_blob || fail_pointer,
                    "{scheme}: {result:?}"
                );
                let state = server.state.lock().unwrap();
                let puts: Vec<_> = state
                    .requests
                    .iter()
                    .filter(|(m, _, _)| m == "PUT")
                    .collect();
                assert_eq!(puts.len(), if fail_blob { 1 } else { 2 });
                assert!(puts[0].1.ends_with(".sqlite"));
                if !fail_blob {
                    assert!(puts[1].1.ends_with(".ptr"));
                    let pointer: serde_json::Value = serde_json::from_slice(&puts[1].2).unwrap();
                    assert!(puts[0].1.contains(pointer["index_id"].as_str().unwrap()));
                    assert_eq!(
                        pointer["index_id"],
                        ratarmount_index::sha256_hex(&puts[0].2)
                    );
                }
                let visible_pointer = &state.objects["/bucket/a.tar.index.ptr"];
                if fail_blob || fail_pointer {
                    assert_eq!(visible_pointer, b"previous pointer");
                } else {
                    assert_eq!(visible_pointer, &puts[1].2);
                }
            }
        }
    }

    /// Regression: mismatched explicit destination bytes must prevent all publication writes.
    #[test]
    fn regression_publish_index_remote_destination_mismatch_refused() {
        let stored = ratarmount_index::TarStats {
            st_size: 3,
            st_mtime: 0,
            st_mtime_ns: None,
            prefix512_sha256: Some("a".repeat(64)),
            suffix512_sha256: None,
            full_sha256: None,
        };
        let mut actual = stored.clone();
        actual.prefix512_sha256 = Some("b".repeat(64));
        assert!(verify_stats(&stored, &actual).is_err());
        let inputs = vec![PathBuf::from("a.tar")];
        assert!(validate_publish_options(
            true,
            &inputs,
            Some(Path::new("http://host/a.tar")),
            None,
            false
        )
        .is_err());
        assert!(validate_publish_options(true, &inputs, None, None, true).is_err());
        assert!(validate_publish_options(false, &inputs, None, Some("main"), false).is_err());
        assert!(validate_publish_options(
            true,
            &["a.tar".into(), "b.tar".into()],
            None,
            None,
            false
        )
        .is_err());
    }

    /// Regression: opt-in real Hub publication must produce discoverable, zero-scan sidecars.
    #[test]
    #[ignore = "writes archive and index files to RATARMOUNT_TEST_HF_REPO; requires explicit user approval"]
    fn regression_publish_index_hf_live() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };
        let Ok(repo_id) = std::env::var("RATARMOUNT_TEST_HF_REPO") else {
            eprintln!("skip: set RATARMOUNT_TEST_HF_REPO=user/repo and a write-scoped HF_TOKEN");
            return;
        };
        if !["HF_TOKEN", "HUGGING_FACE_HUB_TOKEN"]
            .iter()
            .any(|k| std::env::var(k).ok().is_some_and(|v| !v.trim().is_empty()))
        {
            eprintln!("skip: real Hub publication requires an explicit HF_TOKEN or HUGGING_FACE_HUB_TOKEN");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let name = format!(
            "ratarmount-tests/{}.tar",
            dir.path().file_name().unwrap().to_string_lossy()
        );
        let url = format!("hf://datasets/{repo_id}@main/{name}");
        let repo = ratarmount_remote::HfRepo::resolve(&url).unwrap();
        let tar = publish_tar();
        repo.commit_files(
            &[ratarmount_remote::HfCommitFile {
                path: &name,
                content: &tar,
            }],
            Some("main"),
            false,
            Some(&repo.commit),
        )
        .unwrap();
        let scan = Arc::new(AtomicUsize::new(0));
        let sidecar = dir.path().join("built.sqlite");
        drop(build_publish_index(&url, &sidecar, scan.clone()));
        publish_validated_index(
            PublishIndexOpts {
                archive: Path::new(&url),
                sidecar: &sidecar,
                dest: None,
                no_recreate_index: false,
            },
            None,
            false,
        )
        .unwrap();
        scan.store(0, Ordering::Relaxed);
        let bundle = build_publish_index(&url, &dir.path().join("fetched.sqlite"), scan.clone());
        assert!(bundle.source.lookup("/hello.txt", 0).is_some());
        assert_eq!(scan.load(Ordering::Relaxed), 0);
        eprintln!("live publication retained test archive and sidecars at {url}");
    }
    /// Regression: short reads must hash the complete fingerprint window; truncated windows must fail closed.
    #[test]
    fn regression_publish_index_fingerprint_short_reads_and_truncation() {
        use std::io::Seek;
        struct Reader {
            inner: io::Cursor<Vec<u8>>,
            extra: u64,
        }
        impl Read for Reader {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                let n = buf.len().min(1);
                self.inner.read(&mut buf[..n])
            }
        }
        impl Seek for Reader {
            fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
                if pos == SeekFrom::End(0) {
                    Ok(self.inner.get_ref().len() as u64 + self.extra)
                } else {
                    self.inner.seek(pos)
                }
            }
        }
        let mut reader = Reader {
            inner: io::Cursor::new(b"hello".to_vec()),
            extra: 0,
        };
        let stats = fingerprint(&mut reader).unwrap();
        assert_eq!(
            stats.full_sha256.as_deref(),
            Some(ratarmount_index::sha256_hex(b"hello").as_str())
        );
        reader.extra = 1;
        assert!(fingerprint(&mut reader).unwrap_err().contains("truncated"));
    }
    /// Regression: filesystem-copy publication omitted committed SQLite WAL pages held open by a mount.
    #[test]
    fn regression_publish_index_snapshot_includes_wal() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("source.sqlite");
        let dest = dir.path().join("snapshot.sqlite");
        let connection = rusqlite::Connection::open(&src).unwrap();
        connection.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE marker(value TEXT); INSERT INTO marker VALUES ('committed WAL');").unwrap();
        assert!(
            fs::metadata(dir.path().join("source.sqlite-wal"))
                .unwrap()
                .len()
                > 0
        );
        snapshot_sidecar(&src, &dest).unwrap();
        let snapshot = rusqlite::Connection::open(&dest).unwrap();
        let value: String = snapshot
            .query_row("SELECT value FROM marker", [], |r| r.get(0))
            .unwrap();
        assert_eq!(value, "committed WAL");
    }

    /// A connection holding SHARED on a WAL index `path` (read transaction).
    #[cfg(unix)]
    fn s7_wal_holder(path: &Path) -> rusqlite::Connection {
        let c = rusqlite::Connection::open(path).unwrap();
        c.execute_batch("BEGIN").unwrap();
        let _: i64 = c
            .query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get(0))
            .unwrap();
        assert!(ratarmount_index::managed_read::lock_probe::other_process_sees_lock(path));
        c
    }

    /// Regression: (R11-S7, #151): publication snapshots the live sidecar with
    /// `VACUUM INTO` (committed WAL pages included, ordinary connection policy)
    /// and must not release the session's lock on the source.
    #[cfg(unix)]
    #[test]
    fn regression_publish_index_snapshot_keeps_source_lock() {
        use ratarmount_index::managed_read::lock_probe::other_process_sees_lock;
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("source.sqlite");
        let c = rusqlite::Connection::open(&src).unwrap();
        c.execute_batch(
            "PRAGMA journal_mode=WAL; CREATE TABLE marker(value TEXT); INSERT INTO marker VALUES ('committed WAL');",
        )
        .unwrap();
        let holder = s7_wal_holder(&src);
        let dest = dir.path().join("snapshot.sqlite");
        snapshot_sidecar(&src, &dest).unwrap();
        assert!(other_process_sees_lock(&src), "source lock kept");
        let value: String = rusqlite::Connection::open(&dest)
            .unwrap()
            .query_row("SELECT value FROM marker", [], |r| r.get(0))
            .unwrap();
        assert_eq!(value, "committed WAL");
        drop(holder);
        drop(c);
    }

    /// Regression: (R11-S7, #151): publication read its index bytes (the local
    /// atomic copy's source, the snapshot's pointer hash and object-store
    /// sibling body, the Hub body) through raw `File`s. The local copy keeps
    /// the session's lock on the live sidecar; every managed read of the
    /// remote publication keeps a lock taken on the file it reads.
    #[cfg(unix)]
    #[test]
    fn regression_publish_index_readers_keep_index_lock() {
        use ratarmount_index::managed_read::{
            lock_probe::other_process_sees_lock, with_close_probes,
        };
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("live.index.sqlite");
        let c = rusqlite::Connection::open(&src).unwrap();
        c.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE t(x); INSERT INTO t VALUES (1);")
            .unwrap();
        let holder = s7_wal_holder(&src);
        atomic_copy(&src, &dir.path().join("copy.sqlite")).unwrap();
        assert!(other_process_sees_lock(&src), "local copy kept the lock");
        drop(holder);
        drop(c);

        // Object store (S3): pointer hash and sibling body of the snapshot.
        let tar = dir.path().join("a.tar");
        fs::write(&tar, publish_tar()).unwrap();
        let server = PublishServer::new(publish_tar(), false, false);
        let _env = PublishEnv::new(&[
            ("AWS_ACCESS_KEY_ID", "test"),
            ("AWS_SECRET_ACCESS_KEY", "secret"),
            ("AWS_ENDPOINT_URL", &server.url),
            ("AWS_REGION", "us-east-1"),
            ("RATARMOUNT_S3_ANONYMOUS", "0"),
            ("AWS_ANONYMOUS", "0"),
            ("HF_ENDPOINT", &server.url),
            ("HF_TOKEN", "hf-test"),
            ("HF_HUB_OFFLINE", "0"),
            ("XDG_CACHE_HOME", dir.path().join("cache").to_str().unwrap()),
            (
                "RATARMOUNT_HF_TREE_CACHE",
                dir.path().join("trees").to_str().unwrap(),
            ),
        ]);
        let url = "s3://bucket/a.tar";
        let remote_sidecar = dir.path().join("remote.sqlite");
        let mut remote_opts = ratarmount_core::OpenOptions {
            index_file_path: Some(remote_sidecar.clone()),
            ..Default::default()
        };
        drop(
            crate::factory::build_mount_source(
                &[PathBuf::from(url)],
                &mut remote_opts,
                false,
                false,
            )
            .unwrap(),
        );
        let opts = PublishIndexOpts {
            archive: Path::new(url),
            sidecar: &remote_sidecar,
            dest: None,
            no_recreate_index: false,
        };
        let (got, probes) =
            with_close_probes(|_| true, || publish_validated_index(opts, None, false));
        got.unwrap();
        assert!(probes.len() >= 2, "pointer hash and blob body: {probes:?}");
        assert!(probes.iter().all(|(_, kept)| *kept), "{probes:?}");

        // Hub: the snapshot's body.
        let hf = "hf://datasets/org/data@main/a.tar";
        let sidecar = dir.path().join("built.sqlite");
        drop(build_publish_index(
            hf,
            &sidecar,
            std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        ));
        let opts = PublishIndexOpts {
            archive: Path::new(hf),
            sidecar: &sidecar,
            dest: None,
            no_recreate_index: false,
        };
        let (got, probes) =
            with_close_probes(|_| true, || publish_validated_index(opts, None, false));
        got.unwrap();
        assert!(probes.len() >= 2, "pointer hash and Hub body: {probes:?}");
        assert!(probes.iter().all(|(_, kept)| *kept), "{probes:?}");
    }
}
