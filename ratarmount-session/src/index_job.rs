//! Blocking index build (`IndexJob::run`).

use ratarmount_core::IndexBuildHooks;
use ratarmount_index::IndexLocation;

use crate::session::Session;
use crate::types::{OpenRequest, Recreate};
use crate::Error;

/// Cold index-build handle. Engine stays blocking; the embedder owns threads /
/// `job_id`.
///
/// There is no `IndexJob::start` / `Session::from_open`.
pub struct IndexJob;

impl IndexJob {
    /// Cold build ([`Recreate::Always`] semantics). On success the sidecar is
    /// published (tmp+rename). Caller then [`Session::open`] warm, or
    /// [`Session::open_with_job`] does run+open internally.
    ///
    /// Cancel never [`ratarmount_index::SqliteIndex::publish_tmp`]; Drop unlinks
    /// tmp and the previous dest sidecar stays valid. Does **not** run CLI
    /// `--hashes` / `--publish-index` / overlay wrap (`main.rs` keeps that tail).
    pub fn run(req: OpenRequest, hooks: IndexBuildHooks) -> Result<IndexLocation, Error> {
        let mut req = req;
        req.recreate = Recreate::Always;
        let session = Session::open_with_job(req, &hooks)?;
        Ok(session.index_location())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::factory;
    use crate::types::{IndexPolicy, SourceSpec};
    use crate::Session;
    use ratarmount_core::{IndexBuildTick, OpenOptions};
    use ratarmount_formats_tar::{write_tar_eof, write_ustar_members, UstarMember, UstarPayload};
    use ratarmount_index::{SqliteIndex, INDEX_VERSION};
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    fn member_file<'a>(path: &'a str, bytes: &'a [u8]) -> UstarMember<'a> {
        UstarMember {
            path,
            payload: UstarPayload::File { bytes },
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime: 0,
        }
    }

    fn write_tar(path: &Path, members: &[UstarMember<'_>]) {
        let mut f = std::fs::File::create(path).unwrap();
        write_ustar_members(&mut f, members).unwrap();
        write_tar_eof(&mut f).unwrap();
        f.flush().unwrap();
    }

    fn explicit_req(tar: PathBuf, idx: PathBuf, recreate: Recreate) -> OpenRequest {
        OpenRequest {
            source: SourceSpec::Path(tar),
            index: IndexPolicy::Explicit,
            explicit_index: Some(idx),
            extra_dirs: Vec::new(),
            password: None,
            recursive: false,
            recursion_depth: None,
            recreate,
        }
    }

    fn tmp_names(dir: &Path, dest: &Path) -> Vec<String> {
        let prefix = format!("{}.tmp.", dest.file_name().unwrap().to_string_lossy());
        std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(&prefix) || n.contains(".tmp."))
            .collect()
    }

    /// G2.5: ≥2048 members → Scan + batch Write ticks + Finalize (≥ 4 events).
    /// Do not use the 1k paging TAR as the sole proof (1000/512 ≈ 1 write tick).
    #[test]
    fn index_job_progress_events() {
        let dir = tempfile::tempdir().unwrap();
        let names: Vec<String> = (0..2048).map(|i| format!("f{i:04}.txt")).collect();
        let payload = b"x";
        let members: Vec<UstarMember<'_>> = names
            .iter()
            .map(|n| member_file(n.as_str(), payload))
            .collect();
        let tar = dir.path().join("g25.tar");
        write_tar(&tar, &members);
        let idx = dir.path().join("g25.tar.index.sqlite");

        let ticks = Arc::new(Mutex::new(Vec::new()));
        let ticks_cb = Arc::clone(&ticks);
        let hooks = IndexBuildHooks {
            on_progress: Some(Arc::new(move |t: IndexBuildTick| {
                ticks_cb.lock().unwrap().push(t);
            })),
            cancel: None,
        };
        let loc = IndexJob::run(explicit_req(tar, idx.clone(), Recreate::IfInvalid), hooks)
            .expect("IndexJob::run");
        assert_eq!(loc, IndexLocation::Path(idx.clone()));
        assert!(idx.exists());

        let got = ticks.lock().unwrap().clone();
        assert!(
            got.len() >= 4,
            "G2.5 progress ≥ 4 events, got {}: {got:?}",
            got.len()
        );
        assert_eq!(got.first().unwrap().phase, IndexBuildTick::PHASE_SCAN);
        let writes = got
            .iter()
            .filter(|t| t.phase == IndexBuildTick::PHASE_WRITE)
            .count();
        assert!(
            writes >= 4,
            "2048/512 batches should yield ≥4 Write ticks, got {writes}: {got:?}"
        );
        assert_eq!(got.last().unwrap().phase, IndexBuildTick::PHASE_FINALIZE);
        assert!(
            got.last().unwrap().entries >= 2048,
            "finalize entries: {got:?}"
        );
    }

    /// Cancel at ~50% leaves dest sidecar valid; tmp is gone.
    #[test]
    fn index_job_cancel() {
        let dir = tempfile::tempdir().unwrap();
        let names: Vec<String> = (0..2048).map(|i| format!("f{i:04}.txt")).collect();
        let payload = b"x";
        let members: Vec<UstarMember<'_>> = names
            .iter()
            .map(|n| member_file(n.as_str(), payload))
            .collect();
        let tar = dir.path().join("cancel.tar");
        write_tar(&tar, &members);
        let idx = dir.path().join("cancel.tar.index.sqlite");

        drop(
            Session::open(explicit_req(tar.clone(), idx.clone(), Recreate::IfInvalid))
                .expect("seed sidecar"),
        );
        let before = std::fs::read(&idx).unwrap();
        assert!(!before.is_empty());

        let cancel = Arc::new(AtomicBool::new(false));
        let cancel_cb = Arc::clone(&cancel);
        let hooks = IndexBuildHooks {
            on_progress: Some(Arc::new(move |t: IndexBuildTick| {
                if t.phase == IndexBuildTick::PHASE_WRITE && t.entries >= 1024 {
                    cancel_cb.store(true, Ordering::Relaxed);
                }
            })),
            cancel: Some(Arc::clone(&cancel)),
        };
        let err = IndexJob::run(explicit_req(tar, idx.clone(), Recreate::Always), hooks)
            .expect_err("cancel must fail the job");
        assert!(
            matches!(err, Error::Cancelled),
            "expected Cancelled, got {err:?}"
        );
        let leftover = tmp_names(dir.path(), &idx);
        assert!(leftover.is_empty(), "tmp must be gone: {leftover:?}");
        let after = std::fs::read(&idx).unwrap();
        assert_eq!(before, after, "dest sidecar must stay the previous file");
    }

    /// G7.1: sidecar written by IndexJob opens with factory (CLI-equivalent).
    #[test]
    fn index_job_g7_factory_opens_job_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let payload = b"hello";
        let members = [member_file("a.txt", payload)];
        let tar = dir.path().join("g71.tar");
        write_tar(&tar, &members);
        let idx = dir.path().join("g71.tar.index.sqlite");
        let loc = IndexJob::run(
            explicit_req(tar.clone(), idx.clone(), Recreate::Always),
            IndexBuildHooks::default(),
        )
        .expect("IndexJob::run");
        assert_eq!(loc, IndexLocation::Path(idx.clone()));

        let cat = SqliteIndex::open_catalog_read_only(&idx).expect("validate sidecar");
        assert!(
            cat.file_count().unwrap() >= 1,
            "IndexJob sidecar must have files rows"
        );
        assert_eq!(
            cat.backend_name().unwrap().as_deref(),
            Some("SQLiteIndexedTar")
        );
        assert_eq!(INDEX_VERSION, "0.7.0", "IndexJob sidecar stays 0.7.x");

        let opts = OpenOptions {
            write_index: false,
            read_only_index: true,
            index_file_path: Some(idx.clone()),
            ..OpenOptions::default()
        };
        let src = factory::open_path(&tar, &opts, false).expect("CLI-equivalent factory open");
        let fi = src.lookup("/a.txt", 0).expect("a.txt");
        assert_eq!(fi.size, payload.len() as u64);
    }

    /// G7.2: Session::open of a CLI-written sidecar (`factory::open_path` cold).
    #[test]
    fn index_job_g7_session_opens_cli_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let payload = b"cli";
        let members = [member_file("cli.txt", payload)];
        let tar = dir.path().join("g72.tar");
        write_tar(&tar, &members);
        let idx = dir.path().join("g72.tar.index.sqlite");
        let opts = OpenOptions {
            write_index: true,
            index_file_path: Some(idx.clone()),
            ..OpenOptions::default()
        };
        drop(factory::open_path(&tar, &opts, true).expect("CLI cold index"));
        assert!(idx.exists());

        let session = Session::open(explicit_req(tar, idx, Recreate::Never)).expect("warm open");
        let hit = session.lookup("/cli.txt").unwrap().expect("cli.txt");
        assert_eq!(hit.size, payload.len() as u64);
        assert_eq!(session.catalog_has_mem_index(), Some(false));
    }
}
