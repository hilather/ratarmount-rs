//! R1c-1: the supervisor's finalize, retained attempts and their durability
//! (plan `docs/tasks/plans/localai-r1c1-finalize-retain.md` §7).
//!
//! Unit tests drive a real `Supervisor` with the Fake mounter over real
//! overlays (`fixtures::overlay_over_with`) and real bases registered through
//! `create_base`. Linux-dependent tests return early elsewhere through
//! `cfg!` (the sandbox test files are not N4-reviewed).

use super::daemon::{Supervisor, TestIds};
use super::process::StopOutcome;
use super::protocol::{
    ApiError, Attempt, BaseOptions, JournalSpec, Operation, OperationV2, Overlay,
};
use super::tests::{exit, private_tempdir, Fake};
use ratarmount_compositing::{BaseDigestRequest, FolderMountSource, OverlayMeta};
use serde_json::{json, Value};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// Finalize and retain are Linux only (ruling 7).
pub(super) fn linux() -> bool {
    if !cfg!(target_os = "linux") {
        eprintln!("skip: the sandbox supervisor's finalize and retain are Linux only");
        return false;
    }
    true
}

/// Step S trusts only ext2/3/4, xfs, btrfs and tmpfs, also in tests: a
/// temporary directory elsewhere fails, never skips.
pub(super) fn check_tmp(dir: &Path) {
    let root = crate::overlay_pack::open_root(dir).unwrap();
    use std::os::fd::AsFd;
    let kind = super::daemon::fs_type(root.as_fd()).unwrap();
    assert!(
        [0xEF53, 0x5846_5342, 0x9123_683E, 0x0102_1994].contains(&kind),
        "the finalize tests need the temporary directory ({}) on ext4, xfs, btrfs or tmpfs (TMPDIR selects it, with a /tmp fallback for long paths), not filesystem type {kind:#x}",
        dir.display()
    );
}

/// A supervisor over a fresh state directory with a directory base `task`.
pub(super) struct Env {
    pub(super) sup: Supervisor<Fake>,
    pub(super) fake: Fake,
    pub(super) base: PathBuf,
    pub(super) state: tempfile::TempDir,
    pub(super) scratch: Scratch,
}

impl Env {
    pub(super) fn new() -> Self {
        Self::with_timeout(Duration::from_secs(2))
    }

    pub(super) fn with_timeout(timeout: Duration) -> Self {
        let state = private_tempdir();
        let scratch = Scratch(private_tempdir());
        check_tmp(state.path());
        let base = scratch.path().join("base");
        fs::create_dir(&base).unwrap();
        fs::write(base.join("f"), "original\n").unwrap();
        fs::write(base.join("g"), "gone\n").unwrap();
        let fake = Fake::default();
        let mut sup = Supervisor::open(state.path(), 64, timeout, fake.clone()).unwrap();
        sup.test_ids = Some(TestIds::default());
        sup.handle(Operation::CreateBase {
            name: "task".into(),
            source: base.to_str().unwrap().into(),
            options: BaseOptions::default(),
        })
        .unwrap();
        Self {
            sup,
            fake,
            base,
            state,
            scratch,
        }
    }

    /// A restart: the supervisor is dropped (releasing `daemon.lock`) and
    /// opened again on the same state with the same Fake.
    pub(super) fn reopen(self) -> Self {
        let Self {
            sup,
            fake,
            base,
            state,
            scratch,
        } = self;
        let timeout = sup.timeout;
        drop(sup);
        let mut sup = Supervisor::open(state.path(), 64, timeout, fake.clone()).unwrap();
        sup.test_ids = Some(TestIds::default());
        Self {
            sup,
            fake,
            base,
            state,
            scratch,
        }
    }

    pub(super) fn view(&self) -> Arc<dyn ratarmount_core::MountSource> {
        Arc::new(FolderMountSource::new(&self.base).unwrap())
    }

    /// An ID-less v2 `new` of one attempt, `retain` and a journal as given,
    /// whose overlay is then created as the child would and edited.
    pub(super) fn attempt(&mut self, retain: bool, journal: bool) -> Attempt {
        let result = self
            .sup
            .handle(OperationV2::New {
                base: "task".into(),
                count: 1,
                overlay: Overlay::Disk,
                quota: None,
                readonly_globs: vec![],
                request_id: None,
                lowers: vec![],
                journal: journal.then(JournalSpec::default),
                retain,
            })
            .unwrap();
        let attempt: Attempt = serde_json::from_value(result[0].clone()).unwrap();
        self.edit(&attempt);
        attempt
    }

    /// Creates the attempt's overlay over the base and edits it.
    pub(super) fn edit(&self, attempt: &Attempt) {
        let overlay = crate::base_identity::fixtures::overlay_over_with(
            self.view(),
            &attempt.overlay_dir,
            self.base.to_str().unwrap(),
            Vec::new(),
            BaseDigestRequest::Compute,
        )
        .unwrap();
        overlay.create_symlink("/link", "/target").unwrap();
        overlay.unlink("/g").unwrap();
    }

    pub(super) fn finalize(
        &mut self,
        id: &str,
        pack: bool,
        request_id: Option<&str>,
    ) -> Result<Value, ApiError> {
        self.sup.handle(OperationV2::Finalize {
            id: id.into(),
            pack,
            request_id: request_id.map(Into::into),
        })
    }

    pub(super) fn status(&self, id: &str) -> String {
        self.sup.attempts[id].status.clone()
    }

    pub(super) fn stops(&self) -> usize {
        self.fake.0.lock().unwrap().stops.len()
    }

    pub(super) fn requests_len(&self) -> u64 {
        fs::metadata(self.sup.root.join(super::requests::NAME))
            .unwrap()
            .len()
    }
}

fn sealed(overlay: &Path) -> bool {
    OverlayMeta::read_no_recovery(overlay)
        .unwrap()
        .is_some_and(|meta| meta.layer_sealed())
}

/// Regression (R1c-1 T3): a supervisor finalize must report what `sandbox
/// run` reports plus the seal and the attempt: `layer_digest` and
/// `sealed_at` equal to the overlay's rows, the journal summary of the
/// attempt's journal, `bytes_written` measured before fsck, `erofs_denied`
/// from the child's `status` (`null` when never read), outputs under
/// `attempts/ID`, within the response cap.
#[test]
fn regression_supervisor_finalize_report() {
    if !linux() {
        return;
    }
    let mut env = Env::new();
    // A journaled attempt whose child answers `status`.
    env.fake.0.lock().unwrap().erofs_denied = Some(3);
    let attempt = env.attempt(false, true);
    let root = attempt.path.parent().unwrap().to_path_buf();
    let journal = concat!(
        "{\"journal\":1}\n",
        "{\"op\":\"open\",\"path\":\"/f\",\"layer\":\"base\",\"comm\":\"sh\"}\n",
        "{\"op\":\"read\",\"path\":\"/f\",\"ts\":1,\"bytes\":9}\n",
        "{\"op\":\"write\",\"path\":\"/new\",\"ts\":2,\"bytes\":5}\n",
    );
    fs::write(root.join("journal.jsonl"), journal).unwrap();
    let report = env.finalize(&attempt.id, true, None).unwrap();
    let meta = OverlayMeta::read_no_recovery(&attempt.overlay_dir)
        .unwrap()
        .unwrap();
    assert_eq!(report["status"], "finalized");
    assert_eq!(report["attempt"]["id"], attempt.id.as_str());
    assert_eq!(report["attempt"]["status"], "finalized");
    assert_eq!(report["attempt"]["path"], json!(attempt.path));
    assert_eq!(report["attempt"]["overlay_dir"], json!(attempt.overlay_dir));
    assert_eq!(report["layer_digest"], meta.get("layer_digest").unwrap());
    assert_eq!(report["sealed_at"], meta.get("sealed_at").unwrap());
    assert_eq!(report["stack_digest"], json!(meta.stack_digest()));
    assert_eq!(report["patch_hash"]["sealed"], true);
    assert_eq!(report["patch_hash"]["files"], 2);
    assert_eq!(report["patch_hash"]["normalize"], "strict");
    assert_eq!(report["fsck_result"], "ok");
    assert_eq!(report["erofs_denied"], 3);
    let summary = crate::journal_cmd::summarize(journal.as_bytes(), None, None).unwrap();
    assert_eq!(
        report["journal_summary"],
        json!({"path": root.join("journal.summary.json"), "files_read": summary.files_read.len(),
            "files_read_then_written": summary.files_read_then_written.len(),
            "files_written_blind": summary.files_written_blind.len()})
    );
    assert_eq!(report["manifest_path"], json!(root.join("manifest.jsonl")));
    assert_eq!(report["bundle"], json!(root.join("bundle.tar.zst")));
    for output in ["manifest.jsonl", "journal.summary.json", "bundle.tar.zst"] {
        assert!(root.join(output).is_file(), "{output}");
    }
    // bytes_written counts the payload before fsck: the symlink's target.
    assert_eq!(report["bytes_written"], "/target".len());
    assert!(serde_json::to_vec(&report).unwrap().len() < super::protocol::MAX_RESPONSE);
    assert_eq!(env.status(&attempt.id), "finalized");
    // erofs_denied is null when the child never answered `status`.
    env.fake.0.lock().unwrap().erofs_denied = None;
    let quiet = env.attempt(false, false);
    let report = env.finalize(&quiet.id, false, None).unwrap();
    assert!(report["erofs_denied"].is_null(), "{report}");
    assert!(report["bundle"].is_null());
    assert!(report["journal_summary"].is_null());
}

/// Regression (R1c-1 T4, Keystone #6): a finalize under a request ID is
/// retry-safe. `Busy` and `Detaching` answer `writers_active` without
/// sealing or killing anything; the same ID then reaches `done`, whose replay
/// runs nothing; another body is `idempotency_conflict`; an ID-less repeat of
/// a finalized attempt syncs again and answers the stored report; a held
/// overlay root flock answers `writers_active`; a successful pack is never
/// repeated after a later phase fails; and an ID drawn again starts clean.
#[test]
fn regression_supervisor_finalize_request_id_idempotent() {
    if !linux() {
        return;
    }
    let mut env = Env::with_timeout(Duration::from_millis(400));
    let attempt = env.attempt(false, false);
    let id = attempt.id.clone();
    // Busy: nothing changes.
    env.fake
        .0
        .lock()
        .unwrap()
        .stop_outcomes
        .push_back(StopOutcome::Busy);
    let error = env.finalize(&id, false, Some("r1")).unwrap_err();
    assert_eq!(error.code, "writers_active", "{}", error.message);
    assert_eq!(env.status(&id), "ready");
    assert!(env
        .fake
        .0
        .lock()
        .unwrap()
        .mounts
        .contains_key(&attempt.path));
    assert!(
        env.fake.0.lock().unwrap().cleaned.is_empty(),
        "no kill, no cleanup"
    );
    assert!(!sealed(&attempt.overlay_dir));
    assert_eq!(
        env.sup.requests.status("r1"),
        Some(super::requests::Status::Retryable)
    );
    // Failed: the answer's suffix says what actually changed.
    for (top_removed, suffix) in [
        (false, "nothing was changed"),
        (
            true,
            "the top mount was removed, but the attempt is still mounted and keeps its status",
        ),
    ] {
        env.fake
            .0
            .lock()
            .unwrap()
            .stop_outcomes
            .push_back(StopOutcome::Failed {
                detail: "DETAIL".into(),
                top_removed,
            });
        let error = env.finalize(&id, false, Some("r1")).unwrap_err();
        assert_eq!(error.code, "io");
        assert_eq!(
            error.message,
            format!("cannot unmount attempt {id}: DETAIL; {suffix}")
        );
        assert_eq!(env.status(&id), "ready");
        assert!(!sealed(&attempt.overlay_dir));
    }
    // Detaching: unmounted, the child still serves.
    env.fake
        .0
        .lock()
        .unwrap()
        .stop_outcomes
        .push_back(StopOutcome::Detaching);
    let error = env.finalize(&id, false, Some("r1")).unwrap_err();
    assert_eq!(error.code, "writers_active", "{}", error.message);
    assert_eq!(env.status(&id), "finalizing");
    assert!(!sealed(&attempt.overlay_dir));
    // The child exits; a retry checks it once, without waiting again.
    env.fake.0.lock().unwrap().alive.clear();
    let done = env.finalize(&id, false, Some("r1")).unwrap();
    assert_eq!(
        env.fake.0.lock().unwrap().stops.last().unwrap().1,
        Duration::ZERO
    );
    assert_eq!(env.status(&id), "finalized");
    assert!(sealed(&attempt.overlay_dir));
    // The replay of `done` runs nothing.
    let (stops, syncs) = (env.stops(), env.sup.seams.syncs.len());
    let replay = env.finalize(&id, false, Some("r1")).unwrap();
    assert_eq!(
        serde_json::to_vec(&replay).unwrap(),
        serde_json::to_vec(&done).unwrap()
    );
    assert_eq!((env.stops(), env.sup.seams.syncs.len()), (stops, syncs));
    assert_eq!(
        env.finalize(&id, true, Some("r1")).unwrap_err().code,
        "idempotency_conflict"
    );
    // An ID-less repeat syncs again (no stop, seal or hash) and answers the
    // stored report byte for byte.
    let manifest = attempt.path.parent().unwrap().join("manifest.jsonl");
    let before = fs::metadata(&manifest).unwrap();
    let again = env.finalize(&id, false, None).unwrap();
    assert_eq!(
        serde_json::to_vec(&again).unwrap(),
        serde_json::to_vec(&done).unwrap()
    );
    assert_eq!(env.stops(), stops);
    assert!(
        env.sup.seams.syncs.len() > syncs,
        "the fast path syncs again"
    );
    let after = fs::metadata(&manifest).unwrap();
    assert_eq!(
        (before.ino(), before.mtime_nsec()),
        (after.ino(), after.mtime_nsec())
    );
    // `pack` against a report without a bundle, before any sync.
    let syncs = env.sup.seams.syncs.len();
    let error = env.finalize(&id, true, None).unwrap_err();
    assert_eq!(error.code, "invalid_request");
    assert!(
        error.message.contains("without a bundle"),
        "{}",
        error.message
    );
    assert_eq!(env.sup.seams.syncs.len(), syncs);

    // The top's overlay root flock held by another seal: writers_active.
    let held = env.attempt(false, false);
    let lock =
        ratarmount_compositing::overlay_seal::SealOperation::acquire(&held.overlay_dir).unwrap();
    let error = env.finalize(&held.id, false, Some("held")).unwrap_err();
    assert_eq!(error.code, "writers_active", "{}", error.message);
    assert!(!sealed(&held.overlay_dir));
    drop(lock);
    env.finalize(&held.id, false, Some("held")).unwrap();

    // A file planted at the bundle path fails the pack after the seal; once
    // removed, the same ID packs once over the sealed top (read-only fsck).
    let planted = env.attempt(false, false);
    let bundle = planted.path.parent().unwrap().join("bundle.tar.zst");
    fs::write(&bundle, b"planted").unwrap();
    let error = env
        .finalize(&planted.id, true, Some("planted"))
        .unwrap_err();
    assert_eq!(error.code, "io", "{}", error.message);
    assert!(
        sealed(&planted.overlay_dir),
        "the seal came before the pack"
    );
    fs::remove_file(&bundle).unwrap();
    let report = env.finalize(&planted.id, true, Some("planted")).unwrap();
    assert_eq!(report["fsck_result"], "ok");
    assert!(bundle.is_file());

    // Pack, then a later failure: the bundle is never packed again.
    let later = env.attempt(false, false);
    let root = later.path.parent().unwrap().to_path_buf();
    fs::create_dir(root.join("manifest.jsonl")).unwrap();
    let error = env.finalize(&later.id, true, Some("later")).unwrap_err();
    assert_eq!(error.code, "io", "{}", error.message);
    let first = fs::metadata(root.join("bundle.tar.zst")).unwrap();
    let bytes = fs::read(root.join("bundle.tar.zst")).unwrap();
    fs::remove_dir(root.join("manifest.jsonl")).unwrap();
    let report = env.finalize(&later.id, true, Some("later")).unwrap();
    let second = fs::metadata(root.join("bundle.tar.zst")).unwrap();
    assert_eq!(
        (first.ino(), first.mtime_nsec()),
        (second.ino(), second.mtime_nsec())
    );
    assert_eq!(fs::read(root.join("bundle.tar.zst")).unwrap(), bytes);
    assert_eq!(report["bundle"], json!(root.join("bundle.tar.zst")));

    // (i) An ID drawn again starts clean: a packed attempt whose manifest
    // write failed is destroyed; a new attempt of that name packs its own
    // bundle, and the old request answers `not_found`.
    let old = env.attempt(false, false);
    let root = old.path.parent().unwrap().to_path_buf();
    fs::create_dir(root.join("manifest.jsonl")).unwrap();
    assert_eq!(
        env.finalize(&old.id, true, Some("R1")).unwrap_err().code,
        "io"
    );
    assert!(env.sup.attempt_state[&old.id].finalize.progress.packed);
    env.sup
        .handle(Operation::Destroy {
            id: Some(old.id.clone()),
            base: None,
        })
        .unwrap();
    env.sup
        .test_ids
        .as_mut()
        .unwrap()
        .queue
        .push_back(old.id.clone());
    let new = env.attempt(false, false);
    assert_eq!(new.id, old.id);
    assert!(!env.sup.attempt_state[&new.id].finalize.progress.packed);
    let report = env.finalize(&new.id, true, Some("R2")).unwrap();
    assert!(root.join("bundle.tar.zst").is_file());
    assert_eq!(report["bundle"], json!(root.join("bundle.tar.zst")));
    let stops = env.stops();
    let error = env.finalize(&old.id, true, Some("R1")).unwrap_err();
    assert_eq!(error.code, "not_found", "{}", error.message);
    assert_eq!(env.stops(), stops, "neither attempt is touched");
    assert_eq!(env.status(&new.id), "finalized");

    // (ii) A journaled attempt refused by step 4b is destroyed; a new
    // journaled attempt of that name whose child exits 0 finalizes.
    let refused = env.attempt(false, true);
    env.fake
        .0
        .lock()
        .unwrap()
        .exits
        .insert(refused.path.clone(), Some(exit(1)));
    fs::write(refused.path.parent().unwrap().join("journal.jsonl"), "").unwrap();
    assert_eq!(
        env.finalize(&refused.id, false, None).unwrap_err().code,
        "io"
    );
    env.sup
        .handle(Operation::Destroy {
            id: Some(refused.id.clone()),
            base: None,
        })
        .unwrap();
    env.fake.0.lock().unwrap().exits.clear();
    env.sup
        .test_ids
        .as_mut()
        .unwrap()
        .queue
        .push_back(refused.id.clone());
    let fresh = env.attempt(false, true);
    assert_eq!(fresh.id, refused.id);
    fs::write(
        fresh.path.parent().unwrap().join("journal.jsonl"),
        "{\"journal\":1}\n",
    )
    .unwrap();
    assert!(env.sup.attempt_state[&fresh.id]
        .finalize
        .journal_failure
        .is_none());
    env.finalize(&fresh.id, false, None).unwrap();
}

/// Sets the request log's caps for the supervisors this thread opens.
pub(super) struct Limits;

impl Limits {
    pub(super) fn set(limits: super::requests::Limits) -> Self {
        super::requests::TEST_LIMITS.with(|l| l.set(Some(limits)));
        Self
    }
}

impl Drop for Limits {
    fn drop(&mut self) {
        super::requests::TEST_LIMITS.with(|l| l.set(None));
    }
}

/// A v2 `new` of one attempt under `request_id`.
fn new_with_id(env: &mut Env, request_id: &str) -> Result<Value, ApiError> {
    env.sup.handle(OperationV2::New {
        base: "task".into(),
        count: 1,
        overlay: Overlay::Disk,
        quota: None,
        readonly_globs: vec![],
        request_id: Some(request_id.into()),
        lowers: vec![],
        journal: None,
        retain: false,
    })
}

/// The live `requests.jsonl` line of request `id`.
fn line_of(env: &Env, id: &str) -> Vec<u8> {
    let prefix = format!("\"id\":\"{id}\"");
    env.sup
        .requests
        .live_lines()
        .into_iter()
        .find(|line| String::from_utf8_lossy(line).contains(&prefix))
        .unwrap()
}

/// Regression (R1c-1 T23, ruling 5): a retried finalize redirected to
/// another attempt. X fails with a retryable error under R, X is destroyed
/// and its ID drawn again for a new attempt: retrying R answers `not_found`,
/// appends nothing, touches the new X not at all and stays `retryable` with
/// its stored target, also after a compaction and after a restart. Control:
/// without the destroy, the retry finalizes the original X, whose `done`
/// record then reserves the ID.
#[test]
fn regression_supervisor_finalize_retry_never_redirects() {
    if !linux() {
        return;
    }
    // Only the compaction floor is lowered: the record and byte caps stay
    // R1a's, so R is never evicted.
    let _limits = Limits::set(super::requests::Limits::new(65_536, 64 << 20, 4 << 20, 1).unwrap());
    let mut env = Env::new();
    let x = env.attempt(false, false);
    let i1 = env.sup.attempt_state[&x.id].instance.clone();
    env.fake
        .0
        .lock()
        .unwrap()
        .stop_outcomes
        .push_back(StopOutcome::Busy);
    assert_eq!(
        env.finalize(&x.id, false, Some("R")).unwrap_err().code,
        "writers_active"
    );
    let target = super::requests::Target {
        id: x.id.clone(),
        instance: i1.clone(),
    };
    assert_eq!(env.sup.requests.target("R"), Some(&target));
    env.sup
        .handle(Operation::Destroy {
            id: Some(x.id.clone()),
            base: None,
        })
        .unwrap();
    env.sup
        .test_ids
        .as_mut()
        .unwrap()
        .queue
        .push_back(x.id.clone());
    let again = env.attempt(false, false);
    assert_eq!(again.id, x.id);
    let i2 = env.sup.attempt_state[&again.id].instance.clone();
    assert_ne!(i1, i2);
    let check = |env: &mut Env, line: &[u8]| {
        let (len, stops, statuses, syncs) = (
            env.requests_len(),
            env.stops(),
            env.fake.0.lock().unwrap().status_calls,
            env.sup.seams.syncs.len(),
        );
        for _ in 0..2 {
            let error = env.finalize(&x.id, false, Some("R")).unwrap_err();
            assert_eq!(error.code, "not_found", "{}", error.message);
        }
        assert_eq!(env.requests_len(), len, "nothing appended");
        assert_eq!(
            (
                env.stops(),
                env.fake.0.lock().unwrap().status_calls,
                env.sup.seams.syncs.len()
            ),
            (stops, statuses, syncs),
            "the new attempt is never touched"
        );
        assert_eq!(
            env.sup.requests.status("R"),
            Some(super::requests::Status::Retryable)
        );
        assert_eq!(line_of(env, "R"), line);
    };
    let line = line_of(&env, "R");
    check(&mut env, &line);
    assert_eq!(env.status(&again.id), "ready");
    assert!(!sealed(&again.overlay_dir));
    // After a compaction of superseded lines: one request ID that fails
    // retryably again and again supersedes its own lines.
    let running = String::from_utf8(line.clone())
        .unwrap()
        .replace("\"t\":\"retryable\"", "\"t\":\"running\"");
    for _ in 0..12 {
        {
            let mut state = env.fake.0.lock().unwrap();
            state.fail_spawn = Some(state.spawns + 1);
        }
        assert_eq!(new_with_id(&mut env, "s").unwrap_err().code, "spawn_failed");
    }
    assert!(env.sup.requests.events.borrow().contains(&"compact"));
    let file = fs::read_to_string(env.sup.root.join(super::requests::NAME)).unwrap();
    assert!(
        !file.contains(&running),
        "R's running line was compacted away"
    );
    assert!(file.contains(std::str::from_utf8(&line).unwrap()));
    check(&mut env, &line);
    // After a restart: `reconcile` removes the new X; a third draws X again.
    let mut env = env.reopen();
    env.sup
        .test_ids
        .as_mut()
        .unwrap()
        .queue
        .push_back(x.id.clone());
    let third = env.attempt(false, false);
    assert_eq!(third.id, x.id);
    check(&mut env, &line);

    // Control: without the destroy the retry finalizes the original X.
    let mut env = Env::new();
    let x = env.attempt(false, false);
    env.fake
        .0
        .lock()
        .unwrap()
        .stop_outcomes
        .push_back(StopOutcome::Busy);
    assert_eq!(
        env.finalize(&x.id, false, Some("R")).unwrap_err().code,
        "writers_active"
    );
    let report = env.finalize(&x.id, false, Some("R")).unwrap();
    assert_eq!(report["attempt"]["id"], x.id.as_str());
    assert_eq!(
        env.sup.requests.status("R"),
        Some(super::requests::Status::Done)
    );
    env.sup
        .handle(Operation::Destroy {
            id: Some(x.id.clone()),
            base: None,
        })
        .unwrap();
    env.sup
        .test_ids
        .as_mut()
        .unwrap()
        .queue
        .push_back(x.id.clone());
    let other = env.attempt(false, false);
    assert_ne!(other.id, x.id, "the done record reserves its target's ID");
}

/// Regression (R1c-1 T25, Keystone approval note (a)): a finalize record
/// could be evicted from the retry window while its target attempt existed,
/// so a retry ran as a new request. Records of a live target are never
/// evicted: when the caps cannot be met without one, a new request is refused
/// with `capacity` and nothing is written (fail closed); once the target is
/// destroyed they are evicted as before.
#[test]
fn regression_request_log_finalize_record_pinned_while_target_exists() {
    if !linux() {
        return;
    }
    let _limits = Limits::set(super::requests::Limits::new(3, 64 << 20, 4 << 20, 8 << 20).unwrap());
    let mut env = Env::new();
    let x = env.attempt(false, false);
    for request in ["F1", "F2"] {
        env.fake
            .0
            .lock()
            .unwrap()
            .stop_outcomes
            .push_back(StopOutcome::Busy);
        assert_eq!(
            env.finalize(&x.id, false, Some(request)).unwrap_err().code,
            "writers_active"
        );
    }
    // `new` records are evicted, oldest first, around the pinned ones.
    for request in ["N1", "N2", "N3"] {
        new_with_id(&mut env, request).unwrap();
    }
    assert_eq!(env.sup.requests.status("N1"), None);
    assert_eq!(env.sup.requests.status("N2"), None);
    env.fake
        .0
        .lock()
        .unwrap()
        .stop_outcomes
        .push_back(StopOutcome::Busy);
    assert_eq!(
        env.finalize(&x.id, false, Some("F3")).unwrap_err().code,
        "writers_active"
    );
    assert_eq!(env.sup.requests.status("N3"), None);
    // Only pinned records remain: a new request is refused, nothing written.
    let (len, spawns) = (env.requests_len(), env.fake.0.lock().unwrap().spawns);
    let error = new_with_id(&mut env, "N4").unwrap_err();
    assert_eq!(error.code, "capacity", "{}", error.message);
    assert!(
        error.message.contains("finalize records"),
        "{}",
        error.message
    );
    assert_eq!(env.requests_len(), len);
    assert_eq!(env.fake.0.lock().unwrap().spawns, spawns);
    for request in ["F1", "F2", "F3"] {
        assert_eq!(
            env.sup.requests.status(request),
            Some(super::requests::Status::Retryable),
            "{request}"
        );
    }
    // A retry still acts on its target.
    env.fake
        .0
        .lock()
        .unwrap()
        .stop_outcomes
        .push_back(StopOutcome::Busy);
    assert_eq!(
        env.finalize(&x.id, false, Some("F1")).unwrap_err().code,
        "writers_active"
    );
    // Once the target is gone its records are evictable again.
    env.sup
        .handle(Operation::Destroy {
            id: Some(x.id.clone()),
            base: None,
        })
        .unwrap();
    new_with_id(&mut env, "N4").unwrap();
    assert_eq!(env.sup.requests.status("F2"), None, "the oldest goes first");
}

/// A request log in its own directory, its finalize records unpinned.
fn bare_log(dir: &Path) -> super::requests::RequestLog {
    let mut log = super::requests::RequestLog::open(dir, super::requests::limits()).unwrap();
    log.set_pins(super::requests::Pins::default());
    log
}

/// Regression (R1c-1 T11, ruling 5's format): finalize records must store
/// their resolved target in every state, in a versioned line schema, through
/// compaction and reopen. Finalize lines are `v: 2` with `op: "finalize"` and
/// `target {id, instance}`; `new` lines stay R1a's `v: 1` bytes; only a
/// `done` finalize record reserves its target's ID; a restart resolves a cut
/// off finalize to a `v: 2` `failed` line with its target and the finalize
/// message; malformed `v: 2` lines and a `v: 1` finalize refuse the start.
#[test]
fn regression_request_log_finalize_lines() {
    use super::requests::{Status, Target, FINALIZE_INTERRUPTED, INTERRUPTED, NAME};
    let dir = private_tempdir();
    let hash = format!("sha256:{}", "0".repeat(64));
    let target = Target {
        id: "attempt-AAAAAA".into(),
        instance: "0123456789abcdef0123456789abcdef".into(),
    };
    let mut log = bare_log(dir.path());
    log.begin("n", &hash).unwrap();
    log.finish(
        "n",
        &hash,
        Ok((vec!["attempt-NNNNNN".into()], json!(["x"]))),
    )
    .unwrap();
    log.begin_finalize("f", &hash, &target).unwrap();
    assert_eq!(log.target("f"), Some(&target));
    assert!(log
        .finish_finalize(
            "f",
            &hash,
            &target,
            Err(ApiError::new("writers_active", "busy"))
        )
        .is_err());
    assert_eq!(log.status("f"), Some(Status::Retryable));
    assert!(
        !log.is_reserved(&target.id),
        "a retryable record reserves nothing"
    );
    log.begin_finalize("d", &hash, &target).unwrap();
    log.finish_finalize("d", &hash, &target, Ok(json!({"status": "finalized"})))
        .unwrap();
    assert!(
        log.is_reserved(&target.id),
        "a done record reserves its target"
    );
    log.begin_finalize("cut", &hash, &target).unwrap();
    let lines: Vec<Value> = log
        .live_lines()
        .iter()
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect();
    let by_id = |id: &str| lines.iter().find(|line| line["id"] == id).unwrap().clone();
    assert_eq!(by_id("n")["v"], 1);
    assert!(by_id("n").get("target").is_none());
    for (id, t) in [("f", "retryable"), ("d", "done"), ("cut", "running")] {
        let line = by_id(id);
        assert_eq!((line["v"].clone(), line["t"].clone()), (json!(2), json!(t)));
        assert_eq!(line["op"], "finalize");
        assert_eq!(line["target"], json!(target));
    }
    assert_eq!(by_id("d")["attempts"], json!([target.id]));
    drop(log);
    // The cut-off record resolves to `failed interrupted` with its target.
    let mut log = bare_log(dir.path());
    log.resolve_interrupted().unwrap();
    let failed: Value = serde_json::from_slice(log.live_lines().last().unwrap()).unwrap();
    assert_eq!(failed["v"], 2);
    assert_eq!(failed["t"], "failed");
    assert_eq!(failed["target"], json!(target));
    assert_eq!(failed["attempts"], json!([]));
    assert_eq!(failed["error"]["message"], FINALIZE_INTERRUPTED);
    let lines = log.live_lines();
    drop(log);
    // A reopen replays the same records, line for line.
    let log = bare_log(dir.path());
    assert_eq!(log.live_lines(), lines);
    assert_eq!(log.target("f"), Some(&target));
    drop(log);
    // R1a's message for a cut-off `new`.
    let other = private_tempdir();
    let mut log = bare_log(other.path());
    log.begin("cut-new", &hash).unwrap();
    drop(log);
    let mut log = bare_log(other.path());
    log.resolve_interrupted().unwrap();
    let failed: Value = serde_json::from_slice(log.live_lines().last().unwrap()).unwrap();
    assert_eq!(
        (failed["v"].clone(), failed["error"]["message"].clone()),
        (json!(1), json!(INTERRUPTED))
    );
    // Schema errors refuse the start.
    let good = fs::read_to_string(dir.path().join(NAME)).unwrap();
    let retryable = good
        .lines()
        .find(|line| line.contains("\"id\":\"f\""))
        .unwrap()
        .to_owned();
    let mut no_target: Value = serde_json::from_str(&retryable).unwrap();
    no_target.as_object_mut().unwrap().remove("target");
    let mut new_op: Value = serde_json::from_str(&retryable).unwrap();
    new_op["op"] = json!("new");
    let mut instance: Value = serde_json::from_str(&retryable).unwrap();
    instance["target"]["instance"] = json!("0123456789ABCDEF0123456789ABCDEF");
    let mut short: Value = serde_json::from_str(&retryable).unwrap();
    short["target"]["instance"] = json!("0123");
    let mut bad_id: Value = serde_json::from_str(&retryable).unwrap();
    bad_id["target"]["id"] = json!("../x");
    let mut v1: Value = serde_json::from_str(&retryable).unwrap();
    v1["v"] = json!(1);
    v1.as_object_mut().unwrap().remove("target");
    for bad in [no_target, new_op, instance, short, bad_id, v1] {
        let bad_dir = private_tempdir();
        fs::write(bad_dir.path().join(NAME), format!("{good}{bad}\n")).unwrap();
        fs::set_permissions(bad_dir.path().join(NAME), fs::Permissions::from_mode(0o600)).unwrap();
        let error = super::requests::RequestLog::open(bad_dir.path(), super::requests::limits())
            .err()
            .expect("refused");
        assert_eq!(error.code, "invalid_request", "{bad}: {}", error.message);
        assert!(
            error.message.contains("unsupported request record"),
            "{}",
            error.message
        );
    }
    // The finalize hash: `id` is hashed, `request_id` and a false `pack` not.
    let hash = |line: &str| {
        let super::protocol::Op::V2(operation) = super::protocol::Request::parse(line.as_bytes())
            .unwrap()
            .operation
        else {
            panic!("v2 line");
        };
        super::requests::op_hash(&operation)
    };
    assert_eq!(
        hash(r#"{"version":2,"op":"finalize","id":"attempt-000001","pack":true}"#),
        // SHA-256 of `{"id":"attempt-000001","op":"finalize","pack":true,"version":2}`.
        "sha256:6eab73d383499d6526f1c700b5acca6347f6c1e8338505fd534d1f027946a9d1"
    );
    assert_eq!(
        hash(r#"{"version":2,"op":"finalize","id":"a","request_id":"r","pack":false}"#),
        hash(r#"{"version":2,"op":"finalize","id":"a"}"#)
    );
    assert_ne!(
        hash(r#"{"version":2,"op":"finalize","id":"a"}"#),
        hash(r#"{"version":2,"op":"finalize","id":"b"}"#)
    );
    // v1 has no finalize and no retain (R1a's U1).
    for line in [
        r#"{"version":1,"op":"finalize","id":"a"}"#,
        r#"{"version":1,"op":"new","base":"t","retain":true}"#,
        r#"{"version":1,"op":"list","all":true}"#,
    ] {
        let rejection = super::protocol::Request::parse(line.as_bytes()).unwrap_err();
        assert_eq!(rejection.error.code, "invalid_request", "{line}");
    }
}

/// Regression (R1c-1 T24, ruling 7, finalize half): finalize must be
/// refused off Linux before anything is resolved, recorded or stopped. On
/// Linux the test override says "not Linux"; on macOS nothing is overridden.
#[test]
fn regression_supervisor_finalize_linux_only() {
    let state = private_tempdir();
    let base = private_tempdir();
    let fake = Fake::default();
    let mut sup = Supervisor::open(state.path(), 8, Duration::from_secs(2), fake.clone()).unwrap();
    sup.seams.not_linux = true;
    sup.handle(Operation::CreateBase {
        name: "task".into(),
        source: base.path().to_str().unwrap().into(),
        options: BaseOptions::default(),
    })
    .unwrap();
    let attempts = sup
        .handle(Operation::New {
            base: "task".into(),
            count: 1,
            overlay: Overlay::Disk,
            quota: None,
            readonly_globs: vec![],
        })
        .unwrap();
    let id = attempts[0]["id"].as_str().unwrap().to_owned();
    let log = sup.root.join(super::requests::NAME);
    let len = fs::metadata(&log).unwrap().len();
    for (target, request_id) in [
        (id.as_str(), None),
        (id.as_str(), Some("r")),
        ("attempt-unknown", Some("r2")),
        ("attempt-unknown", None),
    ] {
        let error = sup
            .handle(OperationV2::Finalize {
                id: target.into(),
                pack: false,
                request_id: request_id.map(Into::into),
            })
            .unwrap_err();
        assert_eq!(error.code, "invalid_request", "{}", error.message);
        assert!(error.message.contains("Linux only"), "{}", error.message);
    }
    assert_eq!(fs::metadata(&log).unwrap().len(), len, "nothing appended");
    let state = fake.0.lock().unwrap();
    assert!(state.stops.is_empty());
    assert_eq!(state.status_calls, 0);
    drop(state);
    // v1 and every other v2 request behave as today.
    sup.handle(Operation::List { base: None }).unwrap();
    sup.handle(Operation::Stats { id: id.clone() }).unwrap();
    sup.handle(OperationV2::New {
        base: "task".into(),
        count: 1,
        overlay: Overlay::Disk,
        quota: None,
        readonly_globs: vec![],
        request_id: Some("plain".into()),
        lowers: vec![],
        journal: None,
        retain: false,
    })
    .unwrap();
    sup.handle(Operation::Destroy {
        id: Some(id),
        base: None,
    })
    .unwrap();
}

/// Regression (R1c-1 Keystone implementation note (1)): `stats` answered a
/// bare io error ("No such file or directory (os error 2)") when its overlay
/// scan failed, naming neither the path nor the step; so did finalize's
/// `bytes_written` measurement. Both name the step and the overlay path.
#[test]
fn regression_supervisor_usage_scan_errors_name_path_and_step() {
    if !linux() {
        return;
    }
    let mut env = Env::new();
    let attempt = env.attempt(false, false);
    let moved = env.scratch.path().join("moved-overlay");
    fs::rename(&attempt.overlay_dir, &moved).unwrap();
    let error = env
        .sup
        .handle(Operation::Stats {
            id: attempt.id.clone(),
        })
        .unwrap_err();
    assert_eq!(error.code, "io");
    assert!(
        error.message.contains("stats of attempt"),
        "{}",
        error.message
    );
    assert!(
        error
            .message
            .contains(attempt.overlay_dir.to_str().unwrap()),
        "{}",
        error.message
    );
    let error = env.finalize(&attempt.id, false, None).unwrap_err();
    assert_eq!(error.code, "io", "{}", error.message);
    assert!(error.message.contains("bytes_written"), "{}", error.message);
    assert!(
        error
            .message
            .contains(attempt.overlay_dir.to_str().unwrap()),
        "{}",
        error.message
    );
    fs::rename(&moved, &attempt.overlay_dir).unwrap();
}

/// Regression (R1c-1 T9): finalize's `erofs_denied` comes from the child's
/// inspection socket: a one-line JSON `status` reply decoded by the
/// production client; 0 without a policy; an error, not a hang, once the
/// overlay is dropped.
#[test]
fn regression_supervisor_status_reads_real_denials() {
    use ratarmount_compositing::{
        CompositeOverlayPolicy, OverlayPolicy, OverlayQuota, ReadOnlyGlobs,
    };
    let dir = private_tempdir();
    let base = dir.path().join("base");
    fs::create_dir(&base).unwrap();
    let source: Arc<dyn ratarmount_core::MountSource> =
        Arc::new(FolderMountSource::new(&base).unwrap());
    let root = dir.path().join("attempt");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let attempt = Attempt {
        id: "attempt-000001".into(),
        base: "task".into(),
        path: root.join("mnt"),
        overlay_dir: root.join("overlay"),
        status: "ready".into(),
    };
    let socket = super::inspection::socket_path(&attempt);
    let mut overlay =
        crate::base_identity::fixtures::new_overlay(source.clone(), &attempt.overlay_dir).unwrap();
    let rules = Arc::new(
        ReadOnlyGlobs::with_allow(&["tests/**".to_owned()], &[] as &[String])
            .and_then(|rules| rules.with_overlay_root(overlay.root()))
            .unwrap(),
    );
    let quota = Arc::new(
        OverlayQuota::new(overlay.root(), None, None)
            .unwrap()
            .with_readonly(rules.clone()),
    );
    let policies: Vec<Arc<dyn OverlayPolicy>> = vec![rules, quota.clone()];
    overlay.set_policy(Some(Arc::new(CompositeOverlayPolicy(policies))));
    let overlay = Arc::new(overlay);
    let inspector = super::start_inspection(&socket, &overlay, Some(quota)).unwrap();
    let timeout = Duration::from_secs(5);
    assert_eq!(
        super::inspection::status(&attempt, timeout)
            .unwrap()
            .erofs_denied,
        0
    );
    assert!(
        overlay.mkdir("/tests", 0o755).is_err(),
        "the rule denies it"
    );
    assert_eq!(
        super::inspection::status(&attempt, timeout)
            .unwrap()
            .erofs_denied,
        1
    );
    drop(inspector);
    // Without a policy: 0.
    let inspector = super::start_inspection(&socket, &overlay, None).unwrap();
    assert_eq!(
        super::inspection::status(&attempt, timeout)
            .unwrap()
            .erofs_denied,
        0
    );
    // The overlay dropped: an error, not a hang.
    drop(overlay);
    let started = std::time::Instant::now();
    assert!(super::inspection::status(&attempt, timeout).is_err());
    assert!(started.elapsed() < timeout + Duration::from_secs(1));
    drop(inspector);
}

/// Regression (PR #251 review round 1, Keystone (2); sweep 1 Codex B1 and
/// Claude N4): finalize read `erofs_denied` through `ProcessMounter::status`
/// with a fixed 5 s timeout, so a mount process whose inspection socket
/// accepted the connection and never answered held the serial serve loop
/// (`serve` → `respond` → `handle`) for 5 s, whatever `--timeout` said; and
/// once that socket's backlog was full (a child that stopped accepting, its
/// earlier connects still queued) the connect itself held it until the
/// listener closed. The read gets `finalize_wait()`, the smaller of
/// `--timeout` and 10 s, the connect included; an unanswered read leaves
/// `erofs_denied` null and the finalize goes on. Each stalled finalize, the
/// whole `handle` call, takes at most a finalize of the same attempt shape
/// without a stall plus that wait (and a second of slack), so no other step
/// waits on the socket. A watchdog closes the listener after a few seconds,
/// so a regression fails instead of hanging.
#[test]
fn regression_supervisor_finalize_stalled_status_socket_holds_at_most_finalize_wait() {
    if !linux() {
        return;
    }
    let wait = Duration::from_millis(1500);
    let mut env = Env::with_timeout(wait);
    env.fake.0.lock().unwrap().process_status = true;
    let last_read = |env: &Env| {
        let state = env.fake.0.lock().unwrap();
        (
            *state.status_timeouts.last().unwrap(),
            *state.status_held.last().unwrap(),
        )
    };
    // The baseline: no socket at all, so the read fails at once.
    let attempt = env.attempt(false, false);
    let started = std::time::Instant::now();
    env.finalize(&attempt.id, false, None).unwrap();
    let baseline = started.elapsed();
    for full_backlog in [false, true] {
        let attempt = env.attempt(false, false);
        let path = super::inspection::socket_path(&attempt);
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        // Backlog 0: the one queued connect fills it.
        let _queued = full_backlog.then(|| {
            rustix::net::listen(&listener, 0).unwrap();
            std::os::unix::net::UnixStream::connect(&path).unwrap()
        });
        let (done, finished) = std::sync::mpsc::channel::<()>();
        let watchdog = std::thread::spawn(move || {
            let _ = finished.recv_timeout(wait + Duration::from_secs(5));
            drop(listener);
        });
        let started = std::time::Instant::now();
        let report = env.finalize(&attempt.id, false, Some(&attempt.id));
        let total = started.elapsed();
        let _ = done.send(());
        watchdog.join().unwrap();
        let report = report.unwrap();
        assert_eq!(report["status"], "finalized", "{report}");
        assert!(report["erofs_denied"].is_null(), "{report}");
        let (timeout, held) = last_read(&env);
        assert_eq!(timeout, wait, "full backlog {full_backlog}");
        assert!(
            held >= wait * 8 / 10,
            "full backlog {full_backlog}: the read waited for the socket: {held:?}"
        );
        assert!(
            held < wait + Duration::from_secs(1),
            "full backlog {full_backlog}: the read held handle() for {held:?}, past finalize_wait() {wait:?}"
        );
        assert!(
            total < baseline + wait + Duration::from_secs(1),
            "full backlog {full_backlog}: the finalize held the serve loop for {total:?} (baseline {baseline:?}, finalize_wait() {wait:?})"
        );
    }
    // `--timeout` above 10 s: the read gets 10 s.
    let mut env = Env::with_timeout(Duration::from_secs(30));
    env.fake.0.lock().unwrap().erofs_denied = Some(2);
    let attempt = env.attempt(false, false);
    let report = env.finalize(&attempt.id, false, None).unwrap();
    assert_eq!(report["erofs_denied"], 2);
    assert_eq!(
        env.fake.0.lock().unwrap().status_timeouts,
        [Duration::from_secs(10)]
    );
}

/// Regression (R1c-1 T21, sweep 2 Codex B2): a journaled attempt whose mount
/// process failed at unmount was finalized from a summarizable prefix of its
/// journal. The kept exit status decides, whatever the status label: 1 or
/// none refuses (also on every retry, under any request ID or none), 0
/// finalizes (a `crashed` attempt too); attempts without a journal are not
/// affected.
#[test]
fn regression_supervisor_finalize_journal_exit_status() {
    if !linux() {
        return;
    }
    let mut env = Env::new();
    let journaled = |env: &mut Env, code: Option<i32>| {
        let attempt = env.attempt(false, true);
        let root = attempt.path.parent().unwrap().to_path_buf();
        fs::write(
            root.join("journal.jsonl"),
            "{\"journal\":1}\n{\"op\":\"read\",\"path\":\"/f\",\"ts\":1,\"bytes\":9}\n{\"op\":\"wr",
        )
        .unwrap();
        env.fake
            .0
            .lock()
            .unwrap()
            .exits
            .insert(attempt.path.clone(), code.map(exit));
        attempt
    };
    // A: exit 1, a torn last line.
    let a = journaled(&mut env, Some(1));
    for request_id in [Some("a1"), Some("a1"), Some("a2"), None] {
        let error = env.finalize(&a.id, false, request_id).unwrap_err();
        assert_eq!(error.code, "io", "{}", error.message);
        assert!(error.message.contains("exited with"), "{}", error.message);
        assert!(!sealed(&a.overlay_dir));
        env.sup.supervise();
    }
    env.sup
        .handle(Operation::Destroy {
            id: Some(a.id.clone()),
            base: None,
        })
        .unwrap();
    // B: exit 0.
    let b = journaled(&mut env, Some(0));
    env.finalize(&b.id, false, None).unwrap();
    // C: already `crashed` (its child exited 0 after an outside unmount).
    let c = journaled(&mut env, Some(0));
    env.sup.attempts.get_mut(&c.id).unwrap().status = "crashed".into();
    env.finalize(&c.id, false, None).unwrap();
    // D: no journal, exit 1.
    let d = env.attempt(false, false);
    env.fake
        .0
        .lock()
        .unwrap()
        .exits
        .insert(d.path.clone(), Some(exit(1)));
    env.finalize(&d.id, false, None).unwrap();
    // E: journaled, no status ever recorded.
    let e = journaled(&mut env, None);
    let error = env.finalize(&e.id, false, None).unwrap_err();
    assert_eq!(error.code, "io");
    assert!(
        error.message.contains("unknown status"),
        "{}",
        error.message
    );
}

/// A supplied strong base digest: directory-base layers that are lowers
/// record one (R1b refuses `weak` lowers).
pub(super) const D: &str =
    "sha256:1111111111111111111111111111111111111111111111111111111111111111";

/// What a child records of the sealed layer `dir`.
pub(super) fn record(dir: &Path) -> ratarmount_compositing::LowerLayerRecord {
    let meta = OverlayMeta::read_no_recovery(dir).unwrap().unwrap();
    ratarmount_compositing::LowerLayerRecord {
        path: dir.canonicalize().unwrap(),
        layer_digest: meta.get("layer_digest").unwrap().into(),
        sealed_at: meta.get("sealed_at").unwrap().into(),
    }
}

/// Owner write and search bits on every directory below `path`, so sealed
/// trees can be removed.
pub(super) fn writable(path: &Path) {
    let Ok(entry) = fs::symlink_metadata(path) else {
        return;
    };
    if entry.is_dir() {
        let mode = entry.permissions().mode() & 0o7777;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode | 0o700));
        for child in fs::read_dir(path).into_iter().flatten().flatten() {
            writable(&child.path());
        }
    }
}

/// A temporary directory whose sealed (read-only) trees are made writable
/// again before it is removed.
pub(super) struct Scratch(tempfile::TempDir);

impl Scratch {
    pub(super) fn path(&self) -> &Path {
        self.0.path()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        writable(self.0.path());
    }
}

impl Env {
    /// The scratch directory, canonical (lowers are compared canonically).
    pub(super) fn dir(&self) -> PathBuf {
        self.scratch.path().canonicalize().unwrap()
    }

    /// The base under `lowers`.
    pub(super) fn stack_view(&self, lowers: &[PathBuf]) -> Arc<dyn ratarmount_core::MountSource> {
        let layers: Vec<_> = lowers
            .iter()
            .map(|path| {
                (
                    path.clone(),
                    ratarmount_compositing::Immutability::Immutable,
                )
            })
            .collect();
        ratarmount_compositing::compose_stack(self.view(), &layers).unwrap()
    }

    fn token(
        &self,
        view: Arc<dyn ratarmount_core::MountSource>,
    ) -> ratarmount_compositing::ClassifiedBase {
        ratarmount_compositing::ClassifiedBase::open(
            &mut crate::base_identity::fixtures::FixtureOpener {
                source: view,
                kind: ratarmount_compositing::ServedKind::Folder,
                inputs: vec![self.base.to_string_lossy().into_owned()],
                location: Some(ratarmount_compositing::ServedLocation::Local(
                    self.base.clone(),
                )),
            },
        )
        .unwrap()
    }

    /// A sealed directory layer `name` in the scratch directory, written over
    /// `lowers`, recording the strong base digest `D`, holding `files`.
    pub(super) fn layer(&self, name: &str, lowers: &[&Path], files: &[(&str, &str)]) -> PathBuf {
        let dir = self.dir().join(name);
        let lowers: Vec<PathBuf> = lowers.iter().map(|path| path.to_path_buf()).collect();
        let view = self.stack_view(&lowers);
        let overlay = ratarmount_compositing::WriteOverlay::open(
            &self.token(view.clone()),
            view.clone(),
            &dir,
            &ratarmount_compositing::CreateOptions {
                lower_layers: lowers.iter().map(|lower| record(lower)).collect(),
                base_digest: BaseDigestRequest::Supplied(D.into()),
                ..Default::default()
            },
        )
        .unwrap();
        drop(overlay);
        for (path, content) in files {
            let path = dir.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, content).unwrap();
        }
        ratarmount_compositing::overlay_fsck::fsck(&dir, true).unwrap();
        ratarmount_compositing::overlay_seal::seal(&dir, &self.token(view.clone()), view).unwrap();
        dir
    }

    /// Unseals `dir`, rewrites `file` and seals it again (a new seal pair).
    pub(super) fn reseal(&self, dir: &Path, lowers: &[&Path], file: &str) {
        ratarmount_compositing::overlay_seal::unseal(dir).unwrap();
        fs::write(dir.join(file), "changed after validation\n").unwrap();
        let lowers: Vec<PathBuf> = lowers.iter().map(|path| path.to_path_buf()).collect();
        let view = self.stack_view(&lowers);
        ratarmount_compositing::overlay_fsck::fsck(dir, true).unwrap();
        ratarmount_compositing::overlay_seal::seal(dir, &self.token(view.clone()), view).unwrap();
    }

    /// A v2 `new` over `lowers`, whose top is created over the base and the
    /// layers the (Fake) child took, then edited.
    pub(super) fn layered(&mut self, lowers: &[&Path], retain: bool) -> Attempt {
        let result = self
            .sup
            .handle(OperationV2::New {
                base: "task".into(),
                count: 1,
                overlay: Overlay::Disk,
                quota: None,
                readonly_globs: vec![],
                request_id: None,
                lowers: lowers
                    .iter()
                    .map(|p| p.to_str().unwrap().to_owned())
                    .collect(),
                journal: None,
                retain,
            })
            .unwrap();
        let attempt: Attempt = serde_json::from_value(result[0].clone()).unwrap();
        let records = self.sup.taken_lowers[&attempt.id].clone().unwrap();
        let paths: Vec<PathBuf> = records.iter().map(|r| r.path.clone()).collect();
        let overlay = crate::base_identity::fixtures::overlay_over_with(
            self.stack_view(&paths),
            &attempt.overlay_dir,
            self.base.to_str().unwrap(),
            records,
            BaseDigestRequest::Compute,
        )
        .unwrap();
        overlay.create_symlink("/link", "/target").unwrap();
        drop(overlay);
        attempt
    }

    /// Registers base `name` with `source` and `options`; its first v1
    /// attempt, whose overlay is created and edited.
    pub(super) fn base_attempt(
        &mut self,
        name: &str,
        source: &str,
        options: BaseOptions,
    ) -> Attempt {
        self.sup
            .handle(Operation::CreateBase {
                name: name.into(),
                source: source.into(),
                options,
            })
            .unwrap();
        let result = self
            .sup
            .handle(Operation::New {
                base: name.into(),
                count: 1,
                overlay: Overlay::Disk,
                quota: None,
                readonly_globs: vec![],
            })
            .unwrap();
        serde_json::from_value(result[0].clone()).unwrap()
    }
}

/// CRC-32 (IEEE), for a stored ZIP.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// A one-member stored ZIP.
pub(super) fn stored_zip(name: &str, data: &[u8]) -> Vec<u8> {
    let (crc, size, len) = (crc32(data), data.len() as u32, name.len() as u16);
    let mut zip = Vec::new();
    zip.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
    for value in [20u16, 0, 0, 0, 0] {
        zip.extend_from_slice(&value.to_le_bytes());
    }
    for value in [crc, size, size] {
        zip.extend_from_slice(&value.to_le_bytes());
    }
    zip.extend_from_slice(&len.to_le_bytes());
    zip.extend_from_slice(&0u16.to_le_bytes());
    zip.extend_from_slice(name.as_bytes());
    zip.extend_from_slice(data);
    let central = zip.len() as u32;
    zip.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
    for value in [20u16, 20, 0, 0, 0, 0] {
        zip.extend_from_slice(&value.to_le_bytes());
    }
    for value in [crc, size, size] {
        zip.extend_from_slice(&value.to_le_bytes());
    }
    for value in [len, 0, 0, 0, 0] {
        zip.extend_from_slice(&value.to_le_bytes());
    }
    zip.extend_from_slice(&0u32.to_le_bytes());
    zip.extend_from_slice(&0u32.to_le_bytes());
    zip.extend_from_slice(name.as_bytes());
    let central_size = zip.len() as u32 - central;
    zip.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    for value in [0u16, 0, 1, 1] {
        zip.extend_from_slice(&value.to_le_bytes());
    }
    zip.extend_from_slice(&central_size.to_le_bytes());
    zip.extend_from_slice(&central.to_le_bytes());
    zip.extend_from_slice(&0u16.to_le_bytes());
    zip
}

/// Builds the prepared index of `archive` in `indexes` in-process, as the
/// supervisor's `create_base` preparation does.
pub(super) fn prepare_index(archive: &Path, indexes: &Path) -> PathBuf {
    let options = ratarmount_core::OpenOptions {
        index_folders: vec![indexes.to_path_buf()],
        ..Default::default()
    };
    drop(ratarmount_session::factory::open_path(archive, &options, false).unwrap());
    let index = fs::read_dir(indexes)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension().is_some_and(|e| e == "sqlite"))
        .unwrap();
    ratarmount_index::SqliteIndex::finalize_prepared(&index).unwrap();
    index
}

/// Regression (R1c-1 T6, rulings 4, 6 and 7, Matt's scope rule): finalize
/// supports only what the sandbox path uses and refuses everything else with
/// `invalid_request` before anything stops: bases with binds, recursion, a
/// remote source, `git_synthetic_head` or a non-TAR archive; trees on
/// filesystems whose fsync it cannot rely on (also a lower's parent);
/// mounts inside a tree; never-verified stacks and starting attempts;
/// malformed and unknown IDs write nothing. A changed or locked recorded
/// lower is `lower_changed` before the stop.
#[test]
fn regression_supervisor_finalize_scope_refusals() {
    if !linux() {
        return;
    }
    const OVERLAYFS: i64 = 0x794c_7630;
    let mut env = Env::new();
    let refused = |env: &mut Env, id: &str, code: &str, needle: &str| {
        let stops = env.stops();
        let error = env.finalize(id, false, None).expect_err(needle);
        assert_eq!(error.code, code, "{}", error.message);
        assert!(
            error.message.contains(needle),
            "{needle}: {}",
            error.message
        );
        assert_eq!(env.stops(), stops, "refused before the stop");
    };
    // Bases outside the sandbox path.
    let other = env.dir().join("other");
    fs::create_dir(&other).unwrap();
    let cases = [
        (
            "binds",
            env.base.to_str().unwrap().to_owned(),
            BaseOptions {
                binds: vec![format!("/sub={}", other.display())],
                ..Default::default()
            },
            "binds",
        ),
        (
            "rec",
            env.base.to_str().unwrap().to_owned(),
            BaseOptions {
                recursive: true,
                ..Default::default()
            },
            "recursive",
        ),
        (
            "remote",
            "hf://datasets/org/repo".to_owned(),
            BaseOptions::default(),
            "local base",
        ),
        (
            "synthetic",
            env.base.to_str().unwrap().to_owned(),
            BaseOptions {
                git_synthetic_head: true,
                ..Default::default()
            },
            "git_synthetic_head",
        ),
    ];
    for (name, source, options, needle) in cases {
        let attempt = env.base_attempt(name, &source, options);
        refused(&mut env, &attempt.id, "invalid_request", needle);
    }
    // Ruling 4: a ZIP base, by its prepared index's backendName.
    let zip = env.dir().join("base.zip");
    fs::write(&zip, stored_zip("hello.txt", b"zip base\n")).unwrap();
    let attempt = env.base_attempt("zip", zip.to_str().unwrap(), BaseOptions::default());
    prepare_index(&zip, &env.sup.root.join("indexes/zip"));
    refused(&mut env, &attempt.id, "invalid_request", "ZipMountSource");

    // Trees off the filesystem allowlist, at the preflight.
    let lower = env.layer("A", &[], &[("a.txt", "a\n")]);
    let layered = env.layered(&[&lower], false);
    let root = layered.path.parent().unwrap().to_path_buf();
    let indexes = env.sup.root.join("indexes/task");
    for (tree, kind, name) in [
        (lower.clone(), OVERLAYFS, "overlayfs"),
        (root.clone(), 0x6573_5546, "FUSE"),
        (indexes.clone(), 0x6969, "NFS"),
    ] {
        env.sup
            .seams
            .fs_types
            .borrow_mut()
            .insert(tree.clone(), kind);
        let error = env.finalize(&layered.id, false, None).unwrap_err();
        assert_eq!(error.code, "invalid_request", "{}", error.message);
        assert!(
            error.message.contains(tree.to_str().unwrap()),
            "{}",
            error.message
        );
        assert!(error.message.contains(name), "{}", error.message);
        env.sup.seams.fs_types.borrow_mut().clear();
        assert!(!sealed(&layered.overlay_dir));
    }
    assert_eq!(env.stops(), 0);
    // S's backstop: the type changes after step 2; refused before any fsync.
    let types = env.sup.seams.fs_types.clone();
    let switched = root.clone();
    env.sup.seams.before_sync = Some(Box::new(move || {
        types.borrow_mut().insert(switched, OVERLAYFS);
    }));
    let syncs = env.sup.seams.syncs.len();
    let error = env.finalize(&layered.id, false, None).unwrap_err();
    assert_eq!(error.code, "io", "{}", error.message);
    assert!(error.message.contains("overlayfs"), "{}", error.message);
    assert!(
        env.sup.poisoned.is_empty(),
        "a type refusal poisons nothing"
    );
    let synced: Vec<&PathBuf> = env.sup.seams.syncs[syncs..].iter().collect();
    assert!(
        synced.iter().all(|path| !path.starts_with(&root)),
        "nothing in the refused tree was synced: {synced:?}"
    );
    env.sup.seams.fs_types.borrow_mut().clear();
    env.finalize(&layered.id, false, None).unwrap();

    // A lower that is the root of its own filesystem (its parent on another
    // device): its parent's type is checked, and synced.
    fs::create_dir(env.dir().join("deep")).unwrap();
    let own = env.layer("deep/Own", &[], &[("own.txt", "own\n")]);
    let parent = own.parent().unwrap().to_path_buf();
    let attempt = env.layered(&[&own], false);
    // The parent on device 4242; the lower keeps its real device.
    env.sup.seams.devices.insert(parent.clone(), 4242);
    env.sup
        .seams
        .devices
        .insert(own.clone(), fs::metadata(&own).unwrap().dev());
    env.sup
        .seams
        .fs_types
        .borrow_mut()
        .insert(parent.clone(), OVERLAYFS);
    let error = env.finalize(&attempt.id, false, None).unwrap_err();
    assert_eq!(error.code, "invalid_request", "{}", error.message);
    assert!(
        error.message.contains(parent.to_str().unwrap()),
        "{}",
        error.message
    );
    assert!(!sealed(&attempt.overlay_dir));
    env.sup.seams.fs_types.borrow_mut().clear();
    let syncs = env.sup.seams.syncs.len();
    env.finalize(&attempt.id, false, None).unwrap();
    let synced = &env.sup.seams.syncs[syncs..];
    assert!(synced.contains(&parent), "the lower's parent is synced");
    // The parent's chain ends at the parent, whose device is another than
    // its own parent's (the scratch directory, no ancestor of the state).
    assert!(!synced.contains(&env.dir()), "{synced:?}");
    env.sup.seams.devices.clear();
    // Without the override the chain goes on through the scratch directory.
    let again = env.layered(&[&own], false);
    let syncs = env.sup.seams.syncs.len();
    env.finalize(&again.id, false, None).unwrap();
    assert!(env.sup.seams.syncs[syncs..].contains(&env.dir()));

    // Mounts inside a tree.
    let attempt = env.layered(&[&lower], false);
    let root = attempt.path.parent().unwrap().to_path_buf();
    for (mount, needle) in [
        (lower.join("sub"), "has a mount inside it"),
        (indexes.join("x"), "has a mount inside it"),
        (attempt.path.join("inner"), "unmount"),
    ] {
        env.fake.0.lock().unwrap().extra_mounts = vec![mount.clone()];
        refused(&mut env, &attempt.id, "invalid_request", needle);
        env.fake.0.lock().unwrap().extra_mounts.clear();
    }
    // The attempt's own mount point is not refused.
    assert!(env
        .fake
        .0
        .lock()
        .unwrap()
        .mounts
        .contains_key(&attempt.path));
    let _ = root;
    // A recorded lower a cleaner deleted: R1b's lower_changed, first.
    let doomed = env.layer("Doomed", &[], &[("d.txt", "d\n")]);
    let attempt = env.layered(&[&doomed], false);
    writable(&doomed);
    fs::remove_dir_all(&doomed).unwrap();
    refused(
        &mut env,
        &attempt.id,
        "lower_changed",
        doomed.to_str().unwrap(),
    );
    // A recorded lower resealed after the attempt took it.
    let changed = env.layer("Changed", &[], &[("c.txt", "c\n")]);
    let attempt = env.layered(&[&changed], false);
    env.reseal(&changed, &[], "c.txt");
    refused(&mut env, &attempt.id, "lower_changed", "no longer sealed");
    // A recorded lower whose database another connection holds locked; the
    // same request ID proceeds once that connection is closed.
    let locked = env.layer("Locked", &[], &[("l.txt", "l\n")]);
    let attempt = env.layered(&[&locked], false);
    let db = locked.join(ratarmount_compositing::HIDDEN_DB);
    let mode = fs::metadata(&db).unwrap().permissions().mode();
    fs::set_permissions(&db, fs::Permissions::from_mode(mode | 0o200)).unwrap();
    let holder = rusqlite::Connection::open(&db).unwrap();
    holder.execute_batch("BEGIN EXCLUSIVE").unwrap();
    let error = env
        .finalize(&attempt.id, false, Some("locked"))
        .unwrap_err();
    assert_eq!(error.code, "lower_changed", "{}", error.message);
    assert_eq!(env.status(&attempt.id), "ready");
    drop(holder);
    fs::set_permissions(&db, fs::Permissions::from_mode(mode)).unwrap();
    env.finalize(&attempt.id, false, Some("locked")).unwrap();
    // A layered attempt never verified; a starting attempt.
    let attempt = env.layered(&[&lower], false);
    env.sup.taken_lowers.insert(attempt.id.clone(), None);
    refused(&mut env, &attempt.id, "invalid_request", "never verified");
    let attempt = env.attempt(false, false);
    env.sup.attempts.get_mut(&attempt.id).unwrap().status = "starting".into();
    env.fake
        .0
        .lock()
        .unwrap()
        .mounts
        .insert(attempt.path.clone(), super::process::MountState::Starting);
    refused(&mut env, &attempt.id, "invalid_request", "still starting");
    // Malformed and unknown IDs write nothing; the request ID stays free.
    let len = env.requests_len();
    let long = "a".repeat(129);
    for id in ["", "../x", "a/b", ".x", long.as_str()] {
        for request_id in [None, Some("free")] {
            let error = env.finalize(id, false, request_id).unwrap_err();
            assert_eq!(error.code, "invalid_request", "{id:?}");
        }
    }
    let error = env
        .finalize("attempt-unknown", false, Some("free"))
        .unwrap_err();
    assert_eq!(error.code, "not_found", "{}", error.message);
    assert_eq!(env.requests_len(), len, "nothing appended");
    // The request ID is free: another body under it is no conflict.
    new_with_id(&mut env, "free").unwrap();
    let env = env.reopen();
    assert!(env.sup.attempts.is_empty(), "a clean reopen");
}

/// A small TAR with `f`.
pub(super) fn tar_bytes(content: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    ratarmount_formats_tar::write_ustar_members(
        &mut bytes,
        &[ratarmount_formats_tar::UstarMember {
            path: "f",
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime: 0,
            xattrs: &[],
            payload: ratarmount_formats_tar::UstarPayload::File { bytes: content },
        }],
    )
    .unwrap();
    ratarmount_formats_tar::write_tar_eof(&mut bytes).unwrap();
    bytes
}

/// The `.tar.zst` of `tar`, written with the repository's zstd frame writer.
pub(super) fn tar_zst(tar: &[u8]) -> Vec<u8> {
    let mut writer = ratarmount_compress::ZstdFrameWriter::new(Vec::new(), 3);
    writer.write_frame(tar).unwrap();
    writer.finish().unwrap()
}

impl Env {
    /// Registers the archive `source` as base `name` with its prepared index
    /// built in-process, and creates an attempt whose top is opened over the
    /// factory-served archive as a worker child opens it (the read-only
    /// prepared index, so the top records `pending`).
    pub(super) fn archive_attempt(&mut self, name: &str, source: &Path) -> Attempt {
        self.sup
            .handle(Operation::CreateBase {
                name: name.into(),
                source: source.to_str().unwrap().into(),
                options: BaseOptions::default(),
            })
            .unwrap();
        let indexes = self.sup.root.join("indexes").join(name);
        prepare_index(source, &indexes);
        let result = self
            .sup
            .handle(Operation::New {
                base: name.into(),
                count: 1,
                overlay: Overlay::Disk,
                quota: None,
                readonly_globs: vec![],
            })
            .unwrap();
        let attempt: Attempt = serde_json::from_value(result[0].clone()).unwrap();
        let token = self.worker_token(name, source, &indexes);
        let overlay = ratarmount_compositing::WriteOverlay::open(
            &token,
            token.source(),
            &attempt.overlay_dir,
            &ratarmount_compositing::CreateOptions::default(),
        )
        .unwrap();
        overlay.create_symlink("/link", "/target").unwrap();
        drop(overlay);
        attempt
    }
}

/// Regression (R1c-1 T7): finalize over each base the sandbox serves. A TAR
/// and a `.tar.zst` with prepared indexes: a worker top records `pending`
/// and is sealed `strong`; S syncs `indexes/<base>/`; a changed archive and
/// a pending commit journal are `base_open_failed` with nothing sealed and
/// nothing written. A directory base: an edit is refused with the gate's
/// text. A Git base: a new commit on the ref is refused.
#[test]
fn regression_supervisor_finalize_bases() {
    if !linux() {
        return;
    }
    let mut env = Env::new();
    for (name, bytes) in [
        ("tar", tar_bytes(b"tar base\n")),
        ("zst", tar_zst(&tar_bytes(b"zst base\n"))),
    ] {
        let source = env.dir().join(if name == "tar" {
            "base.tar"
        } else {
            "base.tar.zst"
        });
        fs::write(&source, &bytes).unwrap();
        let attempt = env.archive_attempt(name, &source);
        let before = OverlayMeta::read_no_recovery(&attempt.overlay_dir)
            .unwrap()
            .unwrap();
        assert_eq!(before.base_digest_kind(), Some("pending"), "{name}");
        let syncs = env.sup.seams.syncs.len();
        let report = env.finalize(&attempt.id, false, None).unwrap();
        assert_eq!(
            report["patch_hash"]["base_digest_state"], "present",
            "{name}"
        );
        let meta = OverlayMeta::read_no_recovery(&attempt.overlay_dir)
            .unwrap()
            .unwrap();
        assert_eq!(meta.base_digest_kind(), Some("strong"), "{name}");
        let indexes = env.sup.root.join("indexes").join(name);
        let synced = &env.sup.seams.syncs[syncs..];
        assert!(synced.contains(&indexes), "{name}: {synced:?}");
        assert!(
            synced.iter().any(|path| path.starts_with(&indexes)
                && path.extension().is_some_and(|e| e == "sqlite")),
            "{name}: the prepared index is synced: {synced:?}"
        );
        assert!(synced.contains(&env.sup.root.join("indexes")), "{name}");
        // A changed archive: refused by its prepared index.
        let changed = env.attempt_on(name);
        let index = fs::read_dir(&indexes)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path.extension().is_some_and(|e| e == "sqlite"))
            .unwrap();
        let index_before = fs::read(&index).unwrap();
        let mut grown = bytes.clone();
        grown.extend_from_slice(&[0; 512]);
        fs::write(&source, &grown).unwrap();
        let error = env.finalize(&changed.id, false, None).unwrap_err();
        assert_eq!(error.code, "base_open_failed", "{name}: {}", error.message);
        assert!(!sealed(&changed.overlay_dir), "{name}");
        assert_eq!(fs::read(&index).unwrap(), index_before, "{name}");
        fs::write(&source, &bytes).unwrap();
    }
    // A pending commit journal beside the TAR (as an interrupted commit
    // leaves it): refused naming the journal; nothing changes.
    let source = env.dir().join("journaled.tar");
    crate::base_identity::tests::write_tar_file(&source);
    let attempt = env.archive_attempt("journaled", &source);
    crate::base_identity::tests::crash_commit(&source, "archive truncate");
    let journal = ratarmount_compress::commit_journal::journal_path(&source);
    let (archive, journal_bytes) = (fs::read(&source).unwrap(), fs::read(&journal).unwrap());
    let error = env.finalize(&attempt.id, false, None).unwrap_err();
    assert_eq!(error.code, "base_open_failed", "{}", error.message);
    assert!(
        error.message.contains("commit journal"),
        "{}",
        error.message
    );
    assert!(!sealed(&attempt.overlay_dir));
    assert_eq!(fs::read(&source).unwrap(), archive);
    assert_eq!(fs::read(&journal).unwrap(), journal_bytes);
    // The same refusal from a gated `diff` of a finalized attempt.
    let clean = env.dir().join("clean.tar");
    crate::base_identity::tests::write_tar_file(&clean);
    let attempt = env.archive_attempt("clean", &clean);
    env.finalize(&attempt.id, false, None).unwrap();
    crate::base_identity::tests::crash_commit(&clean, "archive truncate");
    let error = env
        .sup
        .handle(Operation::Diff {
            id: attempt.id.clone(),
            git: true,
        })
        .unwrap_err();
    assert_eq!(error.code, "base_open_failed", "{}", error.message);
    assert!(
        error.message.contains("commit journal"),
        "{}",
        error.message
    );
    // A directory base: an edit is refused with the gate's text.
    let attempt = env.attempt(false, false);
    env.finalize(&attempt.id, false, None).unwrap();
    let edited = env.attempt(false, false);
    fs::write(env.base.join("f"), "edited during the run, longer\n").unwrap();
    let error = env.finalize(&edited.id, false, None).unwrap_err();
    assert_eq!(error.code, "io", "{}", error.message);
    assert!(
        error.message.contains("--force-base-mismatch"),
        "{}",
        error.message
    );
    assert!(!sealed(&edited.overlay_dir));
    fs::write(env.base.join("f"), "original\n").unwrap();
    // A Git base: `git:///…#<ref>`, sealed `git-tree`; a new commit on the
    // ref is refused.
    let repo = env.dir().join("repo");
    let git = |args: &[&str]| {
        std::process::Command::new("git")
            .arg("-C")
            .arg(&repo)
            .args(args)
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@example.com")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@example.com")
            .output()
    };
    fs::create_dir(&repo).unwrap();
    if git(&["init", "-q", "-b", "main"]).is_err() {
        eprintln!("skip: the Git row needs the git CLI");
        return;
    }
    fs::write(repo.join("file"), "one\n").unwrap();
    assert!(git(&["add", "file"]).unwrap().status.success());
    assert!(git(&["commit", "-q", "-m", "one"])
        .unwrap()
        .status
        .success());
    let url = format!("git://{}#main", repo.display());
    let attempt = env.archive_attempt_url("git", &url);
    let report = env.finalize(&attempt.id, false, None).unwrap();
    assert_eq!(report["status"], "finalized");
    let meta = OverlayMeta::read_no_recovery(&attempt.overlay_dir)
        .unwrap()
        .unwrap();
    assert_eq!(meta.base_digest_kind(), Some("git-tree"));
    let moved = env.attempt_on_url("git", &url);
    fs::write(repo.join("file"), "two\n").unwrap();
    assert!(git(&["commit", "-q", "-am", "two"])
        .unwrap()
        .status
        .success());
    let error = env.finalize(&moved.id, false, None).unwrap_err();
    assert!(
        error.code == "io" || error.code == "base_open_failed",
        "{}: {}",
        error.code,
        error.message
    );
    assert!(!sealed(&moved.overlay_dir));
}

impl Env {
    /// The base as a worker child opens it: the read-only prepared index of
    /// `indexes`, never an in-memory one.
    fn worker_token(
        &self,
        name: &str,
        source: &Path,
        indexes: &Path,
    ) -> ratarmount_compositing::ClassifiedBase {
        let base = self.sup.base(name).unwrap().clone();
        let mut options = super::daemon::base_open_options(&base, indexes);
        let mut opener = crate::base_identity::FactoryOpener::new(
            vec![source.to_string_lossy().into_owned()],
            vec![source.to_path_buf()],
            &mut options,
            false,
            Default::default(),
            Default::default(),
            false,
        );
        ratarmount_compositing::ClassifiedBase::open(&mut opener).unwrap()
    }

    /// Another attempt on the registered archive base `name`.
    pub(super) fn attempt_on(&mut self, name: &str) -> Attempt {
        let source = PathBuf::from(&self.sup.base(name).unwrap().source);
        self.attempt_on_source(name, &source)
    }

    fn attempt_on_source(&mut self, name: &str, source: &Path) -> Attempt {
        let indexes = self.sup.root.join("indexes").join(name);
        let result = self
            .sup
            .handle(Operation::New {
                base: name.into(),
                count: 1,
                overlay: Overlay::Disk,
                quota: None,
                readonly_globs: vec![],
            })
            .unwrap();
        let attempt: Attempt = serde_json::from_value(result[0].clone()).unwrap();
        let token = self.worker_token(name, source, &indexes);
        let overlay = ratarmount_compositing::WriteOverlay::open(
            &token,
            token.source(),
            &attempt.overlay_dir,
            &ratarmount_compositing::CreateOptions::default(),
        )
        .unwrap();
        overlay.create_symlink("/link", "/target").unwrap();
        drop(overlay);
        attempt
    }

    /// [`archive_attempt`](Self::archive_attempt) for a `git:///` URL base.
    fn archive_attempt_url(&mut self, name: &str, url: &str) -> Attempt {
        self.sup
            .handle(Operation::CreateBase {
                name: name.into(),
                source: url.into(),
                options: BaseOptions::default(),
            })
            .unwrap();
        self.attempt_on_source(name, Path::new(url))
    }

    fn attempt_on_url(&mut self, name: &str, url: &str) -> Attempt {
        self.attempt_on_source(name, Path::new(url))
    }
}

/// Regression (R1c-1 T10): `diff` of a finalized attempt read its overlay
/// against a base it never gated, so an edited base rendered a wrong patch.
/// It classifies and gates first (writing nothing): `diff_failed` after the
/// base is edited, the overlay unchanged; restored, it renders; a layered
/// one composes its recorded layers.
#[test]
fn regression_supervisor_finalize_diff_gates_base() {
    if !linux() {
        return;
    }
    let mut env = Env::new();
    let attempt = env.attempt(false, false);
    env.finalize(&attempt.id, false, None).unwrap();
    let diff = |env: &mut Env, id: &str| {
        env.sup.handle(Operation::Diff {
            id: id.into(),
            git: true,
        })
    };
    let rendered = diff(&mut env, &attempt.id).unwrap();
    let db = attempt.overlay_dir.join(ratarmount_compositing::HIDDEN_DB);
    let db_before = fs::read(&db).unwrap();
    let file = env.base.join("f");
    let modified = fs::metadata(&file).unwrap().modified().unwrap();
    fs::write(&file, "edited after the finalize, longer\n").unwrap();
    let error = diff(&mut env, &attempt.id).unwrap_err();
    assert_eq!(error.code, "diff_failed", "{}", error.message);
    assert_eq!(
        fs::read(&db).unwrap(),
        db_before,
        "the overlay is unchanged"
    );
    // Restored with its mtime (the weak digest covers size and mtime).
    fs::write(&file, "original\n").unwrap();
    fs::File::options()
        .write(true)
        .open(&file)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(modified))
        .unwrap();
    assert_eq!(diff(&mut env, &attempt.id).unwrap(), rendered);
    // A layered attempt composes its recorded layers.
    let lower = env.layer("A", &[], &[("a.txt", "from A\n")]);
    let layered = env.layered(&[&lower], false);
    env.finalize(&layered.id, false, None).unwrap();
    let patch = diff(&mut env, &layered.id).unwrap();
    let text = patch["patch"].as_str().unwrap();
    assert!(
        !text.contains("a.txt"),
        "A is beneath, not in the patch: {text}"
    );
    assert!(text.contains("link"), "{text}");
}

/// Regression (R1c-1 T13d, sweep 4 Claude N4): after a `Detaching` answer
/// the child still serves and holds its overlay database, so `diff` and
/// `stats` must go through its inspection socket; once it exited they read
/// the offline database.
#[test]
fn regression_supervisor_finalize_detaching_stays_inspectable() {
    if !linux() {
        return;
    }
    let mut env = Env::new();
    let attempt = env.attempt(false, false);
    // The child's overlay and inspection socket, holding the database.
    let overlay = Arc::new(
        crate::base_identity::fixtures::overlay_over_with(
            env.view(),
            &attempt.overlay_dir,
            env.base.to_str().unwrap(),
            Vec::new(),
            BaseDigestRequest::Compute,
        )
        .unwrap(),
    );
    let inspector =
        super::start_inspection(&super::inspection::socket_path(&attempt), &overlay, None).unwrap();
    env.fake.0.lock().unwrap().inspection = true;
    env.fake
        .0
        .lock()
        .unwrap()
        .stop_outcomes
        .push_back(StopOutcome::Detaching);
    assert_eq!(
        env.finalize(&attempt.id, false, None).unwrap_err().code,
        "writers_active"
    );
    assert_eq!(env.status(&attempt.id), "finalizing");
    let stats = env
        .sup
        .handle(Operation::Stats {
            id: attempt.id.clone(),
        })
        .unwrap();
    assert_eq!(stats["files_deleted"], 1, "{stats}");
    let patch = env
        .sup
        .handle(Operation::Diff {
            id: attempt.id.clone(),
            git: true,
        })
        .unwrap();
    assert!(patch["patch"].as_str().unwrap().contains("g"), "{patch}");
    // The child exited: offline.
    drop(inspector);
    drop(overlay);
    env.fake.0.lock().unwrap().alive.clear();
    env.fake.0.lock().unwrap().inspection = false;
    let offline = env
        .sup
        .handle(Operation::Stats {
            id: attempt.id.clone(),
        })
        .unwrap();
    assert_eq!(offline["files_deleted"], 1, "{offline}");
    env.finalize(&attempt.id, false, None).unwrap();
}

const KILL_STATE: &str = "RATARMOUNT_SANDBOX_FINALIZE_KILL_STATE";
const KILL_MARKER: &str = "RATARMOUNT_SANDBOX_FINALIZE_KILL_MARKER";
const KILL_POINT: &str = "RATARMOUNT_SANDBOX_FINALIZE_KILL_POINT";

/// The child of a kill test: a supervisor on `KILL_STATE` whose base is the
/// directory `KILL_STATE/../base`; an attempt (retained when the kill point
/// is a commit point), finalized under request ID `k`; at `KILL_POINT` it
/// writes `KILL_MARKER` and waits to be killed.
pub(super) fn kill_child(point: &str) {
    let state = PathBuf::from(std::env::var_os(KILL_STATE).unwrap());
    let marker = PathBuf::from(std::env::var_os(KILL_MARKER).unwrap());
    let base = state.parent().unwrap().join("base");
    let fake = Fake::default();
    let mut sup = Supervisor::open(&state, 8, Duration::from_secs(60), fake).unwrap();
    sup.handle(Operation::CreateBase {
        name: "task".into(),
        source: base.to_str().unwrap().into(),
        options: BaseOptions::default(),
    })
    .unwrap();
    let retain = point != "before_sync";
    let result = sup
        .handle(OperationV2::New {
            base: "task".into(),
            count: 1,
            overlay: Overlay::Disk,
            quota: None,
            readonly_globs: vec![],
            request_id: None,
            lowers: vec![],
            journal: None,
            retain,
        })
        .unwrap();
    let attempt: Attempt = serde_json::from_value(result[0].clone()).unwrap();
    let overlay = crate::base_identity::fixtures::overlay_over_with(
        Arc::new(FolderMountSource::new(&base).unwrap()),
        &attempt.overlay_dir,
        base.to_str().unwrap(),
        Vec::new(),
        BaseDigestRequest::Compute,
    )
    .unwrap();
    overlay.create_symlink("/link", "/target").unwrap();
    drop(overlay);
    let pause = {
        let marker = marker.clone();
        move || {
            fs::write(&marker, b"paused").unwrap();
            std::thread::sleep(Duration::from_secs(60));
        }
    };
    if point == "before_sync" {
        sup.seams.before_sync = Some(Box::new(pause));
    } else {
        let point = point.to_owned();
        let mut pause = Some(pause);
        sup.seams.commit_points = Some(Box::new(move |reached| {
            if reached == point {
                if let Some(pause) = pause.take() {
                    pause();
                }
            }
        }));
    }
    let answer = sup.handle(OperationV2::Finalize {
        id: attempt.id.clone(),
        pack: false,
        request_id: Some("k".into()),
    });
    panic!("the parent should have killed this child: {answer:?}");
}

/// Runs `test` re-executed as a child at kill point `point` over `state`
/// and SIGKILLs it once it paused there; at most 30 s.
pub(super) fn kill_at(test: &str, point: &str, state: &Path, marker: &Path) {
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture"])
        .env(KILL_POINT, point)
        .env(KILL_STATE, state)
        .env(KILL_MARKER, marker)
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while !marker.exists() {
        if let Some(status) = child.try_wait().unwrap() {
            panic!("{point} child exited early: {status}");
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{point} child never reached its kill point");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    child.kill().unwrap();
    child.wait().unwrap();
}

/// A kill test's state directory, beside a directory base.
pub(super) fn kill_state() -> (tempfile::TempDir, PathBuf) {
    let dir = private_tempdir();
    let base = dir.path().join("base");
    fs::create_dir(&base).unwrap();
    fs::write(base.join("f"), "original\n").unwrap();
    let state = dir.path().join("state");
    (dir, state)
}

/// Regression (R1c-1 T8, Keystone #2): a sealed (read-only) attempt tree
/// failed `remove_dir_all` with `EACCES`, so `destroy` of a finalized
/// attempt failed and a crash between seal and the end of finalize blocked
/// every later start. `destroy` removes a finalized disk attempt and a
/// finalized tmpfs attempt; after a SIGKILL after the seal, the restart
/// removes the sealed tree and the request is `failed interrupted` with the
/// finalize message.
#[test]
fn regression_supervisor_remove_sealed_trees() {
    if let Ok(point) = std::env::var(KILL_POINT) {
        return kill_child(&point);
    }
    if !linux() {
        return;
    }
    let mut env = Env::new();
    let attempt = env.attempt(false, false);
    env.finalize(&attempt.id, false, None).unwrap();
    assert!(sealed(&attempt.overlay_dir));
    env.sup
        .handle(Operation::Destroy {
            id: Some(attempt.id.clone()),
            base: None,
        })
        .unwrap();
    assert!(!attempt.path.parent().unwrap().exists());
    // A tmpfs attempt, where /dev/shm is tmpfs.
    let shm_is_tmpfs = crate::overlay_pack::open_root(Path::new("/dev/shm")).is_ok_and(|fd| {
        use std::os::fd::AsFd;
        super::daemon::fs_type(fd.as_fd()).is_ok_and(|kind| kind == 0x0102_1994)
    });
    if shm_is_tmpfs {
        let result = env
            .sup
            .handle(Operation::New {
                base: "task".into(),
                count: 1,
                overlay: Overlay::Tmpfs,
                quota: None,
                readonly_globs: vec![],
            })
            .unwrap();
        let ram: Attempt = serde_json::from_value(result[0].clone()).unwrap();
        env.edit(&ram);
        env.finalize(&ram.id, false, None).unwrap();
        assert!(sealed(&ram.overlay_dir));
        env.sup
            .handle(Operation::Destroy {
                id: Some(ram.id.clone()),
                base: None,
            })
            .unwrap();
        assert!(!ram.overlay_dir.exists());
    } else {
        eprintln!("skip: the tmpfs row needs /dev/shm on tmpfs");
    }
    // SIGKILL after the seal, before step S.
    let (dir, state) = kill_state();
    let marker = dir.path().join("marker");
    let processes = ratarmount_index::test_process::spawning();
    kill_at(
        "sandbox::finalize_tests::regression_supervisor_remove_sealed_trees",
        "before_sync",
        &state,
        &marker,
    );
    drop(processes);
    let _processes = ratarmount_index::test_process::exclusive();
    let sup = Supervisor::open(&state, 8, Duration::from_secs(2), Fake::default()).unwrap();
    assert_eq!(fs::read_dir(state.join("attempts")).unwrap().count(), 0);
    assert_eq!(
        sup.requests.status("k"),
        Some(super::requests::Status::Failed)
    );
    let line = String::from_utf8(sup.requests.live_lines().last().unwrap().clone()).unwrap();
    assert!(
        line.contains(super::requests::FINALIZE_INTERRUPTED),
        "{line}"
    );
    assert!(line.contains("\"v\":2"), "{line}");
    drop(sup);
    writable(dir.path());
}

/// The real device of `path`.
fn dev(path: &Path) -> u64 {
    fs::symlink_metadata(path).unwrap().dev()
}

/// Regression (R1c-1 T17 finalize half, rulings 1+2 and 6): every finalize
/// syncs what it references and trusts no fsync error. A failed fsync poisons
/// its whole filesystem until a restart (also for another lower holding a
/// hard link to that inode), while another filesystem still finalizes; every
/// node is checked on the descriptor that is synced (its device, its type,
/// its inode, its own filesystem type), so a mismatch or a node swapped
/// after its listing is refused before its fsync and poisons nothing; names
/// that are not UTF-8 are refused, never skipped; read-only images are
/// refused before the stop; a poisoned second lower is refused before the
/// stop with no fsync at all; an entry lock held past the deadline is
/// `in_use`.
#[test]
fn regression_supervisor_finalize_sync_poison() {
    if !linux() {
        return;
    }
    const EIO: i32 = 5;
    const EROFS: i32 = 30;
    const EINVAL: i32 = 22;
    // An injected fsync failure on a top file.
    let mut env = Env::new();
    let attempt = env.attempt(false, false);
    let db = attempt.overlay_dir.join(ratarmount_compositing::HIDDEN_DB);
    env.sup.seams.fsync_errors.insert(db.clone(), EIO);
    let error = env.finalize(&attempt.id, false, Some("p1")).unwrap_err();
    assert_eq!(error.code, "io", "{}", error.message);
    assert!(error.message.contains("cannot sync"), "{}", error.message);
    assert!(env.sup.poisoned.contains(&dev(&db)));
    assert_eq!(env.status(&attempt.id), "finalizing", "no report");
    env.sup.seams.fsync_errors.clear();
    for request_id in [Some("p1"), Some("p2"), None] {
        let syncs = env.sup.seams.syncs.len();
        let error = env.finalize(&attempt.id, false, request_id).unwrap_err();
        assert_eq!(error.code, "io", "{}", error.message);
        assert!(
            error.message.contains("failed earlier"),
            "{}",
            error.message
        );
        assert_eq!(env.sup.seams.syncs.len(), syncs, "refused before any fsync");
    }
    // Another lower holding a hard link to an inode on that filesystem.
    let first = env.layer("First", &[], &[("x", "shared\n")]);
    let linked = env.dir().join("Linked");
    {
        let view = env.view();
        let overlay = crate::base_identity::fixtures::overlay_over_with(
            view.clone(),
            &linked,
            env.base.to_str().unwrap(),
            Vec::new(),
            BaseDigestRequest::Supplied(D.into()),
        )
        .unwrap();
        drop(overlay);
        fs::hard_link(first.join("x"), linked.join("x")).unwrap();
        ratarmount_compositing::overlay_fsck::fsck(&linked, true).unwrap();
        ratarmount_compositing::overlay_seal::seal(&linked, &env.token(view.clone()), view)
            .unwrap();
    }
    let attempt = env.layered(&[&linked], false);
    let syncs = env.sup.seams.syncs.len();
    let stops = env.stops();
    let error = env.finalize(&attempt.id, false, None).unwrap_err();
    assert!(
        error.message.contains("failed earlier"),
        "{}",
        error.message
    );
    assert_eq!((env.sup.seams.syncs.len(), env.stops()), (syncs, stops));
    env.sup
        .handle(Operation::Destroy {
            id: Some(attempt.id.clone()),
            base: None,
        })
        .unwrap();
    // A finalize whose trees all report another device succeeds. The
    // override covers the whole temporary root (the state directory and the
    // scratch directory are siblings under it): `/tmp` cannot be written
    // literally, `private_tempdir` honors `TMPDIR`.
    let elsewhere = env.attempt(false, false);
    env.sup
        .seams
        .devices
        .insert(env.dir().parent().unwrap().to_path_buf(), 999);
    env.finalize(&elsewhere.id, false, None).unwrap();
    env.sup.seams.devices.clear();
    drop(env);

    // An injected open failure of a directory S syncs (the state root, an
    // ancestor of `attempts/ID`) poisons nothing: `io` naming it, and the
    // same request ID completes once it opens again.
    let mut env = Env::new();
    let attempt = env.attempt(false, false);
    let ancestor = env.sup.root.clone();
    env.sup.seams.open_errors.insert(ancestor.clone(), EIO);
    let error = env.finalize(&attempt.id, false, Some("o")).unwrap_err();
    assert_eq!(error.code, "io", "{}", error.message);
    assert!(
        error.message.contains(ancestor.to_str().unwrap()),
        "{}",
        error.message
    );
    assert!(
        env.sup.poisoned.is_empty(),
        "an open failure poisons nothing"
    );
    env.sup.seams.open_errors.clear();
    let report = env.finalize(&attempt.id, false, Some("o")).unwrap();
    assert_eq!(report["status"], "finalized", "{report}");
    assert!(env.sup.seams.syncs.contains(&ancestor));
    drop(env);

    // Every node's device: one regular file of a lower reports another
    // device than its directories; refused before its fsync, both while
    // that device is clean and while it is poisoned; nothing is poisoned.
    let mut env = Env::new();
    let lower = env.layer(
        "L",
        &[],
        &[("a.txt", "a\n"), ("b.txt", "b\n"), ("sub/c.txt", "c\n")],
    );
    let attempt = env.layered(&[&lower], false);
    env.sup.seams.devices.insert(lower.clone(), 2002);
    env.sup.seams.devices.insert(lower.join("b.txt"), 3003);
    for poisoned in [false, true] {
        if poisoned {
            env.sup.poisoned.insert(3003);
        }
        let syncs = env.sup.seams.syncs.len();
        let error = env.finalize(&attempt.id, false, None).unwrap_err();
        assert_eq!(error.code, "io", "{}", error.message);
        for needle in [lower.join("b.txt").to_str().unwrap(), "3003", "2002"] {
            assert!(
                error.message.contains(needle),
                "{needle}: {}",
                error.message
            );
        }
        let synced = &env.sup.seams.syncs[syncs..];
        assert!(synced.contains(&lower.join("a.txt")), "{synced:?}");
        for never in [lower.join("b.txt"), lower.join("sub/c.txt"), lower.clone()] {
            assert!(
                !synced.contains(&never),
                "{never:?} after the mismatch: {synced:?}"
            );
        }
        assert_eq!(
            env.sup.poisoned.iter().copied().collect::<Vec<_>>(),
            if poisoned { vec![3003] } else { vec![] },
            "a mismatch poisons nothing"
        );
    }
    env.sup.seams.devices.clear();
    env.sup.poisoned.clear();
    env.finalize(&attempt.id, false, None).unwrap();

    // A node swapped between its listing and its open.
    for swap in ["symlink", "fifo", "file", "directory"] {
        let attempt = env.attempt(false, false);
        let root = attempt.path.parent().unwrap().to_path_buf();
        let target = if swap == "directory" {
            attempt.path.clone()
        } else {
            root.join("manifest.jsonl")
        };
        let hooked = target.clone();
        let kind = swap.to_owned();
        env.sup.seams.before_open = Some(Box::new(move |path: &Path| {
            if path != hooked {
                return;
            }
            match kind.as_str() {
                "symlink" => {
                    fs::remove_file(path).unwrap();
                    std::os::unix::fs::symlink("/etc/hostname", path).unwrap();
                }
                "fifo" => {
                    fs::remove_file(path).unwrap();
                    let name = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
                    // SAFETY: mkfifo on a NUL-terminated path.
                    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
                }
                "file" => {
                    let other = path.with_extension("other");
                    fs::write(&other, b"another inode").unwrap();
                    fs::rename(&other, path).unwrap();
                }
                _ => {
                    fs::remove_dir(path).unwrap();
                    std::os::unix::fs::symlink("/tmp", path).unwrap();
                }
            }
        }));
        let syncs = env.sup.seams.syncs.len();
        let error = env.finalize(&attempt.id, false, None).unwrap_err();
        assert_eq!(error.code, "io", "{swap}: {}", error.message);
        assert!(
            error.message.contains(target.to_str().unwrap()),
            "{swap}: {}",
            error.message
        );
        assert!(!env.sup.seams.syncs[syncs..].contains(&target), "{swap}");
        assert!(env.sup.poisoned.is_empty(), "{swap}");
        env.sup.seams.before_open = None;
    }

    // A name that is not UTF-8 in a directory lower.
    let odd = env.layer("Odd", &[], &[("a.txt", "a\n")]);
    let attempt = env.layered(&[&odd], false);
    {
        use std::os::unix::ffi::OsStrExt;
        let mode = fs::metadata(&odd).unwrap().permissions().mode();
        fs::set_permissions(&odd, fs::Permissions::from_mode(mode | 0o200)).unwrap();
        let name = odd.join(std::ffi::OsStr::from_bytes(b"\xffname"));
        fs::write(&name, b"x").unwrap();
        fs::set_permissions(&name, fs::Permissions::from_mode(0o444)).unwrap();
        fs::set_permissions(&odd, fs::Permissions::from_mode(mode)).unwrap();
    }
    let syncs = env.sup.seams.syncs.len();
    let error = env.finalize(&attempt.id, false, None).unwrap_err();
    assert_eq!(error.code, "io", "{}", error.message);
    assert!(error.message.contains("not UTF-8"), "{}", error.message);
    assert!(
        error.message.contains(odd.to_str().unwrap()),
        "{}",
        error.message
    );
    assert!(
        env.sup.seams.syncs[syncs..]
            .iter()
            .all(|path| !path.starts_with(&odd)),
        "nothing in it is synced"
    );

    // A file whose own filesystem is off the allowlist while its device
    // matches: refused before its fsync, nothing after it synced.
    let attempt = env.attempt(false, false);
    let root = attempt.path.parent().unwrap().to_path_buf();
    let manifest = root.join("manifest.jsonl");
    env.sup
        .seams
        .fs_types
        .borrow_mut()
        .insert(manifest.clone(), 0x794c_7630);
    let syncs = env.sup.seams.syncs.len();
    let error = env.finalize(&attempt.id, false, None).unwrap_err();
    assert_eq!(error.code, "io", "{}", error.message);
    assert!(error.message.contains("overlayfs"), "{}", error.message);
    let synced = &env.sup.seams.syncs[syncs..];
    for never in [manifest.clone(), attempt.overlay_dir.clone(), root.clone()] {
        assert!(!synced.contains(&never), "{never:?}: {synced:?}");
    }
    env.sup.seams.fs_types.borrow_mut().clear();
    assert!(env.sup.poisoned.is_empty());
    drop(env);

    // No fsync error is exempt: EINVAL and EROFS poison, from a file, a
    // lower's parent and an ancestor alike.
    for errno in [EINVAL, EROFS] {
        for place in ["file", "parent", "ancestor"] {
            let mut env = Env::new();
            let lower = env.layer("P", &[], &[("p.txt", "p\n")]);
            let attempt = env.layered(&[&lower], false);
            let path = match place {
                "file" => attempt.overlay_dir.join(ratarmount_compositing::HIDDEN_DB),
                "parent" => env.dir(),
                _ => env.sup.root.clone(),
            };
            env.sup.seams.fsync_errors.insert(path.clone(), errno);
            let error = env.finalize(&attempt.id, false, None).unwrap_err();
            assert_eq!(error.code, "io", "{errno} {place}: {}", error.message);
            assert!(!env.sup.poisoned.is_empty(), "{errno} {place} poisons");
        }
    }

    // Read-only images are refused before the stop, as a lower or its parent.
    for kind in [0x7371_7368, 0xE0F5_E1E2, 0x9660] {
        for parent in [false, true] {
            let mut env = Env::new();
            let lower = env.layer("I", &[], &[("i.txt", "i\n")]);
            let attempt = env.layered(&[&lower], false);
            let typed = if parent { env.dir() } else { lower.clone() };
            env.sup.seams.fs_types.borrow_mut().insert(typed, kind);
            let error = env.finalize(&attempt.id, false, None).unwrap_err();
            assert_eq!(
                error.code, "invalid_request",
                "{kind:#x}: {}",
                error.message
            );
            assert_eq!(env.stops(), 0);
            assert!(!sealed(&attempt.overlay_dir));
        }
    }

    // The pre-check: the second of two lowers on a poisoned device.
    let mut env = Env::new();
    let first = env.layer("One", &[], &[("1.txt", "1\n")]);
    let second = env.layer("Two", &[&first], &[("2.txt", "2\n")]);
    let attempt = env.layered(&[&first, &second], false);
    env.sup.seams.devices.insert(second.clone(), 5005);
    env.sup.poisoned.insert(5005);
    let error = env.finalize(&attempt.id, false, None).unwrap_err();
    assert_eq!(error.code, "io", "{}", error.message);
    assert!(
        error.message.contains("failed earlier"),
        "{}",
        error.message
    );
    assert_eq!(env.stops(), 0);
    assert!(env.sup.seams.syncs.is_empty(), "no fsync at all");
    assert!(!sealed(&attempt.overlay_dir));
    drop(env);

    // An entry lock held past the deadline: `in_use`, nothing poisoned.
    let mut env = Env::with_timeout(Duration::from_millis(300));
    let lower = env.layer("Held", &[], &[("h.txt", "h\n")]);
    let attempt = env.layered(&[&lower], false);
    let held = crate::overlay_pack::lock_layer_entry(
        &lower,
        std::time::Instant::now() + Duration::from_secs(1),
    )
    .unwrap();
    let error = env.finalize(&attempt.id, false, Some("lk")).unwrap_err();
    assert_eq!(error.code, "in_use", "{}", error.message);
    assert!(env.sup.poisoned.is_empty());
    drop(held);
    env.finalize(&attempt.id, false, Some("lk")).unwrap();
}

/// A pause point another thread controls: `wait` blocks until `release`.
#[derive(Clone, Default)]
pub(super) struct Gate(Arc<(std::sync::Mutex<(bool, bool)>, std::sync::Condvar)>);

impl Gate {
    /// Marks the gate reached, then blocks until it is released.
    pub(super) fn wait(&self) {
        let (lock, cvar) = &*self.0;
        let mut state = lock.lock().unwrap();
        state.0 = true;
        cvar.notify_all();
        while !state.1 {
            state = cvar.wait(state).unwrap();
        }
    }

    /// Blocks until a thread reached the gate.
    pub(super) fn reached(&self) {
        let (lock, cvar) = &*self.0;
        let mut state = lock.lock().unwrap();
        while !state.0 {
            state = cvar.wait(state).unwrap();
        }
    }

    pub(super) fn release(&self) {
        let (lock, cvar) = &*self.0;
        lock.lock().unwrap().1 = true;
        cvar.notify_all();
    }
}

impl Env {
    /// A sealed layer `name` packed into `name.tar.zst`: (layer, bundle).
    pub(super) fn bundle(&self, name: &str, files: &[(&str, &str)]) -> (PathBuf, PathBuf) {
        let layer = self.layer(name, &[], files);
        let bundle = self.dir().join(format!("{name}.tar.zst"));
        crate::overlay_pack::pack(
            &layer,
            &bundle,
            self.view(),
            &crate::overlay_pack::PackOptions::default(),
        )
        .unwrap();
        (layer, bundle)
    }

    /// Finishes an interrupted seal or publication of the sealed layer `dir`
    /// (`ratarmount overlay seal DIR` on a sealed layer): its sentinel and
    /// every read-only mode restored.
    pub(super) fn seal_again(&self, dir: &Path) {
        let view = self.view();
        ratarmount_compositing::overlay_seal::seal(dir, &self.token(view.clone()), view).unwrap();
    }
}

/// Fills (or hits) `cache` with `bundle` over `base` on a new thread, whose
/// `publish_layer` (when `publish` is set) or hit (otherwise) pauses at `gate`.
fn cache_thread(
    bundle: PathBuf,
    cache: PathBuf,
    base: PathBuf,
    gate: Option<(Gate, bool)>,
) -> std::thread::JoinHandle<std::io::Result<PathBuf>> {
    std::thread::spawn(move || {
        if let Some((gate, publish)) = gate {
            let hook: Box<dyn Fn(&Path)> = Box::new(move |_| gate.wait());
            if publish {
                crate::overlay_pack::AFTER_PUBLISH_RENAME.with(|h| *h.borrow_mut() = Some(hook));
            } else {
                crate::overlay_pack::AFTER_HIT_CHECK.with(|h| *h.borrow_mut() = Some(hook));
            }
        }
        let view: Arc<dyn ratarmount_core::MountSource> =
            Arc::new(FolderMountSource::new(&base).unwrap());
        crate::overlay_pack::cached_lower_in(&bundle, &cache, view, None)
    })
}

/// The position of the first event equal to `event`.
fn at(events: &[String], event: &str) -> usize {
    events
        .iter()
        .position(|e| e == event)
        .unwrap_or_else(|| panic!("no event {event:?} in {events:#?}"))
}

/// The position of the first fsync event of `path` by step S.
fn fsync_at(events: &[String], path: &str) -> usize {
    events
        .iter()
        .position(|e| e.starts_with("fsync @") && e.ends_with(&format!(" {path}")))
        .unwrap_or_else(|| panic!("no fsync of {path} in {events:#?}"))
}

/// Regression (R1c-1 T20.2, ruling 1+2: ordering after publish): a cache
/// entry was synced, or recorded, before its publication completed. S waits
/// on the entry lock that `publish_layer` holds across its rename and mode
/// restore (`in_use` at its deadline, nothing synced), and its first fsync
/// comes after the restore and the unlock, files first, then the entry, then
/// its parent; a hit holding the lock shared makes S wait until it returned.
#[test]
fn regression_layer_entry_lock_orders_sync_after_publish() {
    if !linux() {
        return;
    }
    let mut env = Env::with_timeout(Duration::from_millis(300));
    let (_, bundle) = env.bundle("B", &[("b.txt", "b\n")]);
    let cache = env.dir().join("cache");
    let base = env.base.clone();
    let entry = cache_thread(bundle.clone(), cache.clone(), base.clone(), None)
        .join()
        .unwrap()
        .unwrap();
    let attempt = env.layered(&[&entry], false);
    // Before S: the entry is purged and refilled by a fill that pauses
    // between its rename and its mode restore.
    let gate = Gate::default();
    let filler = std::sync::Arc::new(std::sync::Mutex::new(None));
    {
        let (gate, filler, entry, bundle, cache, base) = (
            gate.clone(),
            filler.clone(),
            entry.clone(),
            bundle.clone(),
            cache.clone(),
            base.clone(),
        );
        env.sup.seams.before_sync = Some(Box::new(move || {
            writable(&entry);
            fs::remove_dir_all(&entry).unwrap();
            *filler.lock().unwrap() = Some(cache_thread(
                bundle,
                cache,
                base,
                Some((gate.clone(), true)),
            ));
            gate.reached();
        }));
    }
    let error = env.finalize(&attempt.id, false, Some("o")).unwrap_err();
    assert_eq!(error.code, "in_use", "{}", error.message);
    assert!(
        env.sup
            .seams
            .syncs
            .iter()
            .all(|path| !path.starts_with(&entry)),
        "nothing of the entry is synced while its publication runs"
    );
    gate.release();
    let refilled = filler
        .lock()
        .unwrap()
        .take()
        .unwrap()
        .join()
        .unwrap()
        .unwrap();
    assert_eq!(refilled, entry);
    env.finalize(&attempt.id, false, Some("o")).unwrap();
    let events = crate::overlay_pack::events::under(&env.dir());
    let entry_text = entry
        .display()
        .to_string()
        .replace(&env.dir().display().to_string(), "$ROOT");
    let unlock = events
        .iter()
        .rposition(|e| e == &format!("unlock {entry_text}"))
        .unwrap();
    let restore = events
        .iter()
        .rposition(|e| e == &format!("restore {entry_text}"))
        .unwrap();
    let file = fsync_at(&events, &format!("{entry_text}/b.txt"));
    let root = fsync_at(&events, &entry_text);
    let parent = fsync_at(&events, entry_text.rsplit_once('/').unwrap().0);
    assert!(restore < unlock && unlock < file, "{events:#?}");
    assert!(
        file < root && root < parent,
        "files, entry, parent: {events:#?}"
    );

    // A hit holding the lock shared: S waits until the hit returned.
    let mut env = Env::new();
    let (_, bundle) = env.bundle("H", &[("h.txt", "h\n")]);
    let cache = env.dir().join("cache");
    let base = env.base.clone();
    let entry = cache_thread(bundle.clone(), cache.clone(), base.clone(), None)
        .join()
        .unwrap()
        .unwrap();
    let attempt = env.layered(&[&entry], false);
    let gate = Gate::default();
    let hit = cache_thread(bundle, cache, base, Some((gate.clone(), false)));
    gate.reached();
    let release = {
        let gate = gate.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            gate.release();
        })
    };
    env.finalize(&attempt.id, false, None).unwrap();
    release.join().unwrap();
    assert_eq!(hit.join().unwrap().unwrap(), entry);
    let events = crate::overlay_pack::events::under(&env.dir());
    let entry_text = entry
        .display()
        .to_string()
        .replace(&env.dir().display().to_string(), "$ROOT");
    let returned = at(&events, &format!("hit {entry_text}"));
    let first = fsync_at(&events, &format!("{entry_text}/h.txt"));
    assert!(returned < first, "S waited for the hit: {events:#?}");
}

/// Regression (R1c-1 T20.3, ruling 1+2: two concurrent hits): hits of an
/// entry whose publication is in flight returned its path before the
/// publication completed. Two hits on two threads both wait for the fill's
/// restore and unlock and return the same sealed root; a hit while S holds
/// the lock returns after S's last event; a `finalize_top` as `sandbox run`
/// calls it (its top's flock held, composing a bundle lower whose entry S
/// holds) waits for S and completes, and S never waits on a top's flock.
#[test]
fn regression_layer_entry_lock_concurrent_hits_wait() {
    if !linux() {
        return;
    }
    let mut env = Env::new();
    let (_, bundle) = env.bundle("C", &[("c.txt", "c\n")]);
    let cache = env.dir().join("cache");
    let base = env.base.clone();
    let fill = Gate::default();
    let filler = cache_thread(
        bundle.clone(),
        cache.clone(),
        base.clone(),
        Some((fill.clone(), true)),
    );
    fill.reached();
    let hits: Vec<_> = (0..2)
        .map(|_| cache_thread(bundle.clone(), cache.clone(), base.clone(), None))
        .collect();
    std::thread::sleep(Duration::from_millis(200));
    assert!(hits.iter().all(|hit| !hit.is_finished()), "both hits wait");
    fill.release();
    let entry = filler.join().unwrap().unwrap();
    for hit in hits {
        assert_eq!(hit.join().unwrap().unwrap(), entry);
    }
    let mode = fs::metadata(&entry).unwrap().permissions().mode();
    assert_eq!(mode & 0o222, 0, "the sealed mode");
    let events = crate::overlay_pack::events::under(&env.dir());
    let entry_text = entry
        .display()
        .to_string()
        .replace(&env.dir().display().to_string(), "$ROOT");
    let unlock = at(&events, &format!("unlock {entry_text}"));
    let hit_events: Vec<usize> = events
        .iter()
        .enumerate()
        .filter(|(_, e)| *e == &format!("hit {entry_text}"))
        .map(|(i, _)| i)
        .collect();
    assert_eq!(hit_events.len(), 2);
    assert!(hit_events.iter().all(|i| *i > unlock), "{events:#?}");

    // A hit while S holds the lock returns after S's last event, and a
    // `sandbox run`-style finalize composing the bundle waits for S too.
    let attempt = env.layered(&[&entry], false);
    let waiting = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    {
        let (waiting, bundle, cache, base, scratch) = (
            waiting.clone(),
            bundle.clone(),
            cache.clone(),
            base.clone(),
            env.dir(),
        );
        env.sup.seams.after_lower_lock = Some(Box::new(move |_| {
            let mut waiting = waiting.lock().unwrap();
            waiting.push(cache_thread(
                bundle.clone(),
                cache.clone(),
                base.clone(),
                None,
            ));
            // A top over the base composing the bundle, finalized as
            // `sandbox run` does: its own flock first, then the entry's.
            let top = scratch.join("run-top");
            let overlay = crate::base_identity::fixtures::overlay_over_with(
                Arc::new(FolderMountSource::new(&base).unwrap()),
                &top,
                base.to_str().unwrap(),
                Vec::new(),
                BaseDigestRequest::Compute,
            )
            .unwrap();
            overlay.create_symlink("/run", "/target").unwrap();
            drop(overlay);
            let (bundle, cache, base2) = (bundle.clone(), cache.clone(), base.clone());
            waiting.push(std::thread::spawn(move || {
                let mut classify =
                    |_: Option<&OverlayMeta>| Ok(crate::base_identity::fixtures::classify(&base2));
                let mut compose = |source: Arc<dyn ratarmount_core::MountSource>| {
                    let layer = crate::overlay_pack::cached_lower_in(
                        &bundle,
                        &cache,
                        source.clone(),
                        None,
                    )?;
                    ratarmount_compositing::compose_stack(
                        source,
                        &[(layer, ratarmount_compositing::Immutability::Immutable)],
                    )
                };
                let manifest = top.with_extension("manifest.jsonl");
                super::finalize::finalize_top(
                    super::finalize::FinalizeTop {
                        top: &top,
                        repair: super::finalize::Repair::Always,
                        classify: &mut classify,
                        compose: &mut compose,
                        base_digest: None,
                        seal: Some(None),
                        pack: None,
                        manifest: &manifest,
                        journal: None,
                        #[cfg(test)]
                        before_meta_read: None,
                    },
                    &mut super::finalize::FinalizeProgress::default(),
                )
                .map(|_| top.clone())
            }));
            drop(waiting);
            std::thread::sleep(Duration::from_millis(300));
        }));
    }
    env.finalize(&attempt.id, false, None).unwrap();
    let mut waiting = waiting.lock().unwrap();
    let run = waiting.pop().unwrap();
    let hit = waiting.pop().unwrap();
    assert_eq!(hit.join().unwrap().unwrap(), entry);
    run.join().unwrap().unwrap();
    let events = crate::overlay_pack::events::under(&env.dir());
    let parent = entry_text.rsplit_once('/').unwrap().0.to_owned();
    let last = events
        .iter()
        .rposition(|e| e.starts_with("fsync @") && e.ends_with(&format!(" {parent}")))
        .unwrap();
    let hits_after: Vec<usize> = events
        .iter()
        .enumerate()
        .filter(|(i, e)| *i > hit_events[1] && *e == &format!("hit {entry_text}"))
        .map(|(i, _)| i)
        .collect();
    assert!(hits_after.len() >= 2, "{events:#?}");
    assert!(
        hits_after.iter().all(|i| *i > last),
        "after S's last event: {events:#?}"
    );
}

const FILL_BUNDLE: &str = "RATARMOUNT_SANDBOX_FILL_BUNDLE";
const FILL_CACHE: &str = "RATARMOUNT_SANDBOX_FILL_CACHE";
const FILL_BASE: &str = "RATARMOUNT_SANDBOX_FILL_BASE";
const FILL_MARKER: &str = "RATARMOUNT_SANDBOX_FILL_MARKER";

/// Regression (R1c-1 T20.5, sweep 1 Codex B1, run 2 sweep 4 Codex B1):
/// releasing the entry lock does not prove a publication completed. A filler
/// killed between its rename and its mode restore, a failed restore and an
/// interrupted `overlay unseal` leave writable nodes; a hit refuses such an
/// entry (never repairs it) and names `ratarmount overlay seal X`; a finalize
/// refuses it before the stop, also as a directory lower and for an
/// interrupted seal of a user's layer; a writable node below a read-only
/// root stops S before its fsync. Without `flock` (ENOLCK) fills and hits
/// proceed unlocked; any other lock error fails them.
#[test]
fn regression_layer_entry_lock_incomplete_publication() {
    if let Some(bundle) = std::env::var_os(FILL_BUNDLE) {
        // The killed filler: pauses after its rename until killed.
        let marker = PathBuf::from(std::env::var_os(FILL_MARKER).unwrap());
        crate::overlay_pack::AFTER_PUBLISH_RENAME.with(|h| {
            *h.borrow_mut() = Some(Box::new(move |_| {
                fs::write(&marker, b"paused").unwrap();
                std::thread::sleep(Duration::from_secs(60));
            }))
        });
        let base = PathBuf::from(std::env::var_os(FILL_BASE).unwrap());
        let view: Arc<dyn ratarmount_core::MountSource> =
            Arc::new(FolderMountSource::new(&base).unwrap());
        let cache = PathBuf::from(std::env::var_os(FILL_CACHE).unwrap());
        let _ = crate::overlay_pack::cached_lower_in(Path::new(&bundle), &cache, view, None);
        panic!("the parent should have killed this filler");
    }
    if !linux() {
        return;
    }
    let mut env = Env::new();
    let (_, bundle) = env.bundle("K", &[("k.txt", "k\n")]);
    let cache = env.dir().join("cache");
    // Killed filler.
    let marker = env.dir().join("filled");
    {
        let _processes = ratarmount_index::test_process::spawning();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "sandbox::finalize_tests::regression_layer_entry_lock_incomplete_publication",
                "--nocapture",
            ])
            .env(FILL_BUNDLE, &bundle)
            .env(FILL_CACHE, &cache)
            .env(FILL_BASE, &env.base)
            .env(FILL_MARKER, &marker)
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while !marker.exists() {
            assert!(
                child.try_wait().unwrap().is_none(),
                "the filler exited early"
            );
            assert!(
                std::time::Instant::now() < deadline,
                "the filler never paused"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        child.kill().unwrap();
        child.wait().unwrap();
    }
    let entry = fs::read_dir(&cache)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.is_dir() && p.file_name().unwrap().len() == 64)
        .expect("the killed filler's published entry");
    assert_ne!(
        fs::metadata(&entry).unwrap().permissions().mode() & 0o200,
        0
    );
    let base = env.base.clone();
    let hit = || {
        let view: Arc<dyn ratarmount_core::MountSource> =
            Arc::new(FolderMountSource::new(&base).unwrap());
        crate::overlay_pack::cached_lower_in(&bundle, &cache, view, None)
    };
    let error = hit().unwrap_err().to_string();
    assert!(error.contains("not a completely sealed layer"), "{error}");
    assert!(error.contains("ratarmount overlay seal"), "{error}");
    // The same entry named as a directory lower: accepted by R1b's
    // validation (its seal rows are intact), refused by finalize before the
    // stop with the remedy; after it, the same request ID finalizes.
    let attempt = env.layered(&[&entry], false);
    let stops = env.stops();
    let error = env.finalize(&attempt.id, false, Some("dl")).unwrap_err();
    assert_eq!(error.code, "lower_changed", "{}", error.message);
    assert!(
        error.message.contains("ratarmount overlay seal"),
        "{}",
        error.message
    );
    assert_eq!(env.stops(), stops, "before the stop");
    assert!(!sealed(&attempt.overlay_dir));
    env.seal_again(&entry);
    assert_eq!(
        fs::metadata(&entry).unwrap().permissions().mode() & 0o222,
        0
    );
    assert_eq!(
        hit().unwrap(),
        entry,
        "the hit returns the path after the seal"
    );
    env.finalize(&attempt.id, false, Some("dl")).unwrap();

    // A failed mode restore: the lost-race hit refuses the writable root.
    let (_, other) = env.bundle("R", &[("r.txt", "r\n")]);
    crate::overlay_pack::FAIL_PUBLISH_RESTORE.with(|f| f.set(true));
    let view: Arc<dyn ratarmount_core::MountSource> =
        Arc::new(FolderMountSource::new(&env.base).unwrap());
    let error = crate::overlay_pack::cached_lower_in(&other, &cache, view, None)
        .unwrap_err()
        .to_string();
    crate::overlay_pack::FAIL_PUBLISH_RESTORE.with(|f| f.set(false));
    assert!(error.contains("not a completely sealed layer"), "{error}");

    // An interrupted unseal: every node writable, the seal rows and the
    // sentinel intact.
    let (_, unsealed) = env.bundle("U", &[("u.txt", "u\n"), ("d/v.txt", "v\n")]);
    let view: Arc<dyn ratarmount_core::MountSource> =
        Arc::new(FolderMountSource::new(&env.base).unwrap());
    let entry =
        crate::overlay_pack::cached_lower_in(&unsealed, &cache, view.clone(), None).unwrap();
    let attempt = env.layered(&[&entry], false);
    fn all_writable(path: &Path) {
        let mode = fs::symlink_metadata(path).unwrap().permissions().mode();
        fs::set_permissions(path, fs::Permissions::from_mode(mode | 0o200)).unwrap();
        if path.is_dir() {
            for child in fs::read_dir(path).unwrap() {
                let child = child.unwrap().path();
                if !child.is_symlink() {
                    all_writable(&child);
                }
            }
        }
    }
    all_writable(&entry);
    let error = crate::overlay_pack::cached_lower_in(&unsealed, &cache, view.clone(), None)
        .unwrap_err()
        .to_string();
    assert!(error.contains("not a completely sealed layer"), "{error}");
    let stops = env.stops();
    assert_eq!(
        env.finalize(&attempt.id, false, None).unwrap_err().code,
        "lower_changed"
    );
    assert_eq!(env.stops(), stops);
    env.seal_again(&entry);
    crate::overlay_pack::cached_lower_in(&unsealed, &cache, view.clone(), None).unwrap();
    env.finalize(&attempt.id, false, None).unwrap();

    // A writable node below a read-only root: the hit returns the path, S
    // stops at that node before its fsync.
    let (_, below) = env.bundle("W", &[("w.txt", "w\n"), ("deep/x.txt", "x\n")]);
    let entry = crate::overlay_pack::cached_lower_in(&below, &cache, view.clone(), None).unwrap();
    let attempt = env.layered(&[&entry], false);
    let deep = entry.join("deep");
    let mode = fs::metadata(&deep).unwrap().permissions().mode();
    fs::set_permissions(&deep, fs::Permissions::from_mode(mode | 0o200)).unwrap();
    assert_eq!(
        crate::overlay_pack::cached_lower_in(&below, &cache, view.clone(), None).unwrap(),
        entry
    );
    let syncs = env.sup.seams.syncs.len();
    let error = env.finalize(&attempt.id, false, None).unwrap_err();
    assert_eq!(error.code, "lower_changed", "{}", error.message);
    assert!(
        error.message.contains(deep.to_str().unwrap()),
        "{}",
        error.message
    );
    let synced = &env.sup.seams.syncs[syncs..];
    assert!(!synced.contains(&deep) && !synced.contains(&deep.join("x.txt")));
    fs::set_permissions(&deep, fs::Permissions::from_mode(mode)).unwrap();

    // An interrupted seal of a user's directory lower: root and children
    // writable, the sentinel missing.
    let user = env.layer("User", &[], &[("y.txt", "y\n")]);
    let attempt = env.layered(&[&user], false);
    all_writable(&user);
    fs::remove_file(user.join(".ratarmount-sealed")).unwrap();
    let stops = env.stops();
    let error = env.finalize(&attempt.id, false, None).unwrap_err();
    assert_eq!(error.code, "lower_changed", "{}", error.message);
    assert_eq!(env.stops(), stops);
    env.seal_again(&user);
    assert!(user.join(".ratarmount-sealed").exists());
    env.finalize(&attempt.id, false, None).unwrap();

    // A cache filesystem without flock: unlocked, the check still runs.
    let (_, nolock) = env.bundle("N", &[("n.txt", "n\n")]);
    crate::overlay_pack::ENTRY_FLOCK_ERRNO.with(|e| e.set(Some(37)));
    let filled = crate::overlay_pack::cached_lower_in(&nolock, &cache, view.clone(), None);
    let hit_again = crate::overlay_pack::cached_lower_in(&nolock, &cache, view.clone(), None);
    crate::overlay_pack::ENTRY_FLOCK_ERRNO.with(|e| e.set(None));
    let entry = filled.unwrap();
    assert_eq!(hit_again.unwrap(), entry);
    all_writable(&entry);
    crate::overlay_pack::ENTRY_FLOCK_ERRNO.with(|e| e.set(Some(37)));
    let refused = crate::overlay_pack::cached_lower_in(&nolock, &cache, view.clone(), None);
    crate::overlay_pack::ENTRY_FLOCK_ERRNO.with(|e| e.set(None));
    assert!(refused
        .unwrap_err()
        .to_string()
        .contains("not a completely sealed layer"));
    // Another lock error fails the fill and the hit.
    let (_, failing) = env.bundle("F", &[("f.txt", "f\n")]);
    crate::overlay_pack::ENTRY_FLOCK_ERRNO.with(|e| e.set(Some(5)));
    let error = crate::overlay_pack::cached_lower_in(&failing, &cache, view.clone(), None)
        .unwrap_err()
        .to_string();
    crate::overlay_pack::ENTRY_FLOCK_ERRNO.with(|e| e.set(None));
    assert!(error.contains("cannot lock layer"), "{error}");
}

/// Regression (R1c-1 T20.7, ruling 6's second half): S re-checked only a
/// lower's write bit. Under the entry lock it reads the seal again and
/// checks the path still names the locked inode: a lower resealed after the
/// top was sealed over it, or replaced by a byte-identical copy after S took
/// its lock, answers `lower_changed` with no fsync at all; an untouched
/// lower, its database included, is synced through the admitted open.
#[test]
fn regression_supervisor_finalize_rechecks_lower_identity_at_sync() {
    if !linux() {
        return;
    }
    // (i) Resealed after `finalize_top` returned.
    let mut env = Env::new();
    let a = env.layer("A", &[], &[("a.txt", "a\n")]);
    let b = env.layer("B", &[&a], &[("b.txt", "b\n")]);
    let attempt = env.layered(&[&a, &b], false);
    let recorded = record(&a);
    {
        let (a, base) = (a.clone(), env.base.clone());
        let token = env.token(env.view());
        env.sup.seams.before_sync = Some(Box::new(move || {
            ratarmount_compositing::overlay_seal::unseal(&a).unwrap();
            fs::write(a.join("a.txt"), "changed after the top was sealed\n").unwrap();
            let view: Arc<dyn ratarmount_core::MountSource> =
                Arc::new(FolderMountSource::new(&base).unwrap());
            ratarmount_compositing::overlay_fsck::fsck(&a, true).unwrap();
            ratarmount_compositing::overlay_seal::seal(&a, &token, view).unwrap();
        }));
    }
    let error = env.finalize(&attempt.id, false, None).unwrap_err();
    assert_eq!(error.code, "lower_changed", "{}", error.message);
    assert!(
        error.message.contains(&recorded.layer_digest),
        "{}",
        error.message
    );
    assert!(
        error.message.contains(&recorded.sealed_at),
        "{}",
        error.message
    );
    assert_ne!(record(&a).sealed_at, recorded.sealed_at);
    assert!(env.sup.seams.syncs.is_empty(), "no fsync at all");
    drop(env);

    // (ii) Replaced by a byte-identical copy after S took its lock.
    let mut env = Env::new();
    let a = env.layer("A", &[], &[("a.txt", "a\n")]);
    let attempt = env.layered(&[&a], false);
    {
        let a = a.clone();
        env.sup.seams.after_lower_lock = Some(Box::new(move |_| {
            let aside = a.with_file_name("A.aside");
            let copy = a.with_file_name("A.copy");
            let status = std::process::Command::new("cp")
                .arg("-a")
                .arg(&a)
                .arg(&copy)
                .status()
                .unwrap();
            assert!(status.success());
            fs::rename(&a, &aside).unwrap();
            fs::rename(&copy, &a).unwrap();
        }));
    }
    let error = env.finalize(&attempt.id, false, None).unwrap_err();
    assert_eq!(error.code, "lower_changed", "{}", error.message);
    assert!(error.message.contains("replaced"), "{}", error.message);
    assert!(env.sup.seams.syncs.is_empty(), "no fsync at all");
    drop(env);

    // (iii) Untouched: synced, its database through the admitted open.
    let mut env = Env::new();
    let a = env.layer("A", &[], &[("a.txt", "a\n")]);
    let attempt = env.layered(&[&a], false);
    env.finalize(&attempt.id, false, None).unwrap();
    assert!(env
        .sup
        .seams
        .syncs
        .contains(&a.join(ratarmount_compositing::HIDDEN_DB)));
}

impl Env {
    /// [`Env::new`] with the state directory inside `parent`.
    pub(super) fn new_in(parent: &Path) -> Self {
        let mut env = Self::new();
        let state = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir_in(parent)
            .unwrap();
        let fake = env.fake.clone();
        let mut sup = Supervisor::open(state.path(), 64, Duration::from_secs(2), fake).unwrap();
        sup.test_ids = Some(TestIds::default());
        sup.handle(Operation::CreateBase {
            name: "task".into(),
            source: env.base.to_str().unwrap().into(),
            options: BaseOptions::default(),
        })
        .unwrap();
        env.sup = sup;
        env.state = state;
        env
    }

    /// A bundle of a layer over `lowers`: (layer, bundle).
    pub(super) fn bundle_over(
        &self,
        name: &str,
        lowers: &[&Path],
        files: &[(&str, &str)],
    ) -> (PathBuf, PathBuf) {
        let layer = self.layer(name, lowers, files);
        let bundle = self.dir().join(format!("{name}.tar.zst"));
        let lowers: Vec<PathBuf> = lowers.iter().map(|p| p.to_path_buf()).collect();
        crate::overlay_pack::pack(
            &layer,
            &bundle,
            self.stack_view(&lowers),
            &crate::overlay_pack::PackOptions::default(),
        )
        .unwrap();
        (layer, bundle)
    }

    /// The Fake child resolves bundle lowers through the real cache code.
    pub(super) fn real_cache(&self, cache: &Path) {
        self.fake.0.lock().unwrap().real_cache = Some((cache.to_path_buf(), self.view()));
    }
}

/// The directories above `dir`'s parent on the parent's device (S3's
/// chain rule), the parent included.
fn chain_of(dir: &Path) -> Vec<PathBuf> {
    let parent = dir.parent().unwrap();
    let device = dev(parent);
    let mut chain = vec![parent.to_path_buf()];
    let mut current = parent.parent();
    while let Some(next) = current {
        if fs::symlink_metadata(next).map(|m| m.dev()).ok() != Some(device) {
            break;
        }
        chain.push(next.to_path_buf());
        current = next.parent();
    }
    chain
}

/// Regression (R1c-1 T20.4, ruling 1+2 "every finalize", sweep 1 Codex
/// B3): S ran only for retained attempts. A finalize without `retain` syncs
/// each lower (files, directory, parent; the cache entry under its lock),
/// the top, `attempts/ID`, `indexes/<base>/`, then every ancestor once,
/// deepest first, before it answers. An ID-less repeat syncs again and
/// answers the stored report byte for byte, while a same-ID replay runs
/// nothing; the fast path syncs a refilled cache entry, and answers
/// `lower_changed` for a purged one.
#[test]
fn regression_supervisor_finalize_without_retain_syncs() {
    if !linux() {
        return;
    }
    let mut env = Env::new();
    let directory = env.layer("Dir", &[], &[("d.txt", "d\n")]);
    let (_, bundle) = env.bundle_over("Bnd", &[&directory], &[("b.txt", "b\n")]);
    let cache = env.dir().join("cache");
    env.real_cache(&cache);
    // A first attempt fills the entry; the next one is a cache hit.
    let _filled = env.layered(&[&directory, &bundle], false);
    let attempt = env.layered(&[&directory, &bundle], false);
    let entry = env.sup.taken_lowers[&attempt.id].clone().unwrap()[1]
        .path
        .clone();
    assert!(entry.starts_with(&cache));
    let root = attempt.path.parent().unwrap().to_path_buf();
    let indexes = env.sup.root.join("indexes/task");
    let report = env.finalize(&attempt.id, false, Some("w")).unwrap();
    let synced = env.sup.seams.syncs.clone();
    let pos = |path: &Path| {
        let found: Vec<usize> = synced
            .iter()
            .enumerate()
            .filter(|(_, p)| p.as_path() == path)
            .map(|(i, _)| i)
            .collect();
        assert_eq!(found.len(), 1, "{path:?} synced once: {synced:#?}");
        found[0]
    };
    // Each lower: its files, its root, its parent; bottom first.
    assert!(pos(&directory.join("d.txt")) < pos(&directory));
    assert!(pos(&directory) < pos(directory.parent().unwrap()));
    assert!(pos(directory.parent().unwrap()) < pos(&entry.join("b.txt")));
    assert!(pos(&entry.join("b.txt")) < pos(&entry));
    assert!(pos(&entry) < pos(&cache));
    // Then the top and its tree, then the prepared state.
    assert!(pos(&cache) < pos(&attempt.overlay_dir.join(ratarmount_compositing::HIDDEN_DB)));
    assert!(pos(&attempt.overlay_dir) < pos(&root));
    assert!(pos(&root) < pos(&indexes));
    // Then each ancestor once, deepest first.
    let mut ancestors: Vec<PathBuf> = [
        chain_of(&root),
        chain_of(&indexes),
        chain_of(&directory),
        chain_of(&entry),
    ]
    .concat()
    .into_iter()
    .filter(|dir| dir != directory.parent().unwrap() && dir != &cache)
    .collect();
    ancestors.sort();
    ancestors.dedup();
    let mut positions: Vec<(usize, usize)> = ancestors
        .iter()
        .map(|dir| (pos(dir), dir.components().count()))
        .collect();
    positions.sort();
    assert!(positions.iter().all(|(at, _)| *at > pos(&indexes)));
    assert!(
        positions.windows(2).all(|pair| pair[0].1 >= pair[1].1),
        "deepest first: {positions:?}"
    );
    // A same-ID replay runs nothing; an ID-less repeat syncs it all again.
    let replay = env.finalize(&attempt.id, false, Some("w")).unwrap();
    assert_eq!(
        serde_json::to_vec(&replay).unwrap(),
        serde_json::to_vec(&report).unwrap()
    );
    assert_eq!(env.sup.seams.syncs.len(), synced.len());
    let again = env.finalize(&attempt.id, false, None).unwrap();
    assert_eq!(
        serde_json::to_vec(&again).unwrap(),
        serde_json::to_vec(&report).unwrap()
    );
    assert_eq!(env.sup.seams.syncs[synced.len()..], synced[..]);
    // The fast path syncs a refilled entry (a new inode at the same path).
    let old = fs::metadata(&entry).unwrap().ino();
    writable(&entry);
    fs::remove_dir_all(&entry).unwrap();
    let _refill = env.layered(&[&directory, &bundle], false);
    assert_ne!(fs::metadata(&entry).unwrap().ino(), old);
    let before = env.sup.seams.syncs.len();
    env.finalize(&attempt.id, false, None).unwrap();
    assert!(env.sup.seams.syncs[before..].contains(&entry.join("b.txt")));
    // Purged and not refilled: R1b's lower_changed from the re-read.
    writable(&entry);
    fs::remove_dir_all(&entry).unwrap();
    let error = env.finalize(&attempt.id, false, None).unwrap_err();
    assert_eq!(error.code, "lower_changed", "{}", error.message);
}

/// Regression (R1c-1 T20.6, sweep 2 Codex B1, sweep 3 Codex B1): a cache
/// hierarchy the first fill created recursively was never synced, and an
/// unreadable ancestor ended the walk early. A finalize over that bundle
/// syncs the entry, `layers/`, `ratarmount/`, the cache root and every
/// ancestor on that filesystem once, deepest first; an unreadable
/// ancestor (mode 0300) is refused before the stop, also on `layers/` itself
/// and above the state root, and with `io` when it turns unreadable after
/// step 2; a 0711 directory on another device ends the chain unopened.
#[test]
fn regression_supervisor_finalize_syncs_new_cache_ancestors() {
    if !linux() {
        return;
    }
    let mut env = Env::new();
    let (_, bundle) = env.bundle("N", &[("n.txt", "n\n")]);
    let root = env.dir().join("xdg");
    let cache = root.join("ratarmount/layers");
    assert!(!root.exists());
    env.real_cache(&cache);
    let attempt = env.layered(&[&bundle], false);
    assert!(env.sup.seams.syncs.is_empty(), "the fill syncs nothing");
    let entry = env.sup.taken_lowers[&attempt.id].clone().unwrap()[0]
        .path
        .clone();
    assert_eq!(entry.parent().unwrap(), cache);
    env.finalize(&attempt.id, false, None).unwrap();
    let synced = env.sup.seams.syncs.clone();
    let mut expected = vec![cache.clone()];
    expected.extend(chain_of(&cache));
    let positions: Vec<usize> = expected
        .iter()
        .map(|dir| {
            let found: Vec<usize> = synced
                .iter()
                .enumerate()
                .filter(|(_, p)| *p == dir)
                .map(|(i, _)| i)
                .collect();
            assert_eq!(found.len(), 1, "{dir:?} once: {synced:#?}");
            found[0]
        })
        .collect();
    assert!(
        positions.windows(2).all(|p| p[0] < p[1]),
        "deepest first: {expected:?}"
    );
    for dir in chain_of(&env.sup.root.join("attempts/x")) {
        assert!(synced.contains(&dir), "{dir:?}");
    }
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skip: mode bits do not refuse root");
        return;
    }
    // An unreadable ancestor through which the fill created the cache.
    let p = env.dir().join("p");
    fs::create_dir(&p).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o300)).unwrap();
    env.real_cache(&p.join("cache/ratarmount/layers"));
    let attempt = env.layered(&[&bundle], false);
    let error = env.finalize(&attempt.id, false, None).unwrap_err();
    assert_eq!(error.code, "invalid_request", "{}", error.message);
    assert!(
        error
            .message
            .contains(&format!("{} cannot be opened", p.display())),
        "{}",
        error.message
    );
    assert!(!sealed(&attempt.overlay_dir));
    // P on `layers/` itself.
    fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
    let layers = p.join("cache/ratarmount/layers");
    fs::set_permissions(&layers, fs::Permissions::from_mode(0o300)).unwrap();
    let error = env.finalize(&attempt.id, false, None).unwrap_err();
    assert_eq!(error.code, "invalid_request", "{}", error.message);
    assert!(
        error.message.contains(layers.to_str().unwrap()),
        "{}",
        error.message
    );
    fs::set_permissions(&layers, fs::Permissions::from_mode(0o700)).unwrap();
    // Unreadable only after step 2: S answers io naming it.
    {
        let p = p.clone();
        env.sup.seams.before_sync = Some(Box::new(move || {
            fs::set_permissions(&p, fs::Permissions::from_mode(0o300)).unwrap();
        }));
    }
    let error = env.finalize(&attempt.id, false, None).unwrap_err();
    assert_eq!(error.code, "io", "{}", error.message);
    assert!(
        error.message.contains(p.to_str().unwrap()),
        "{}",
        error.message
    );
    fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
    env.finalize(&attempt.id, false, None).unwrap();
    // A 0711 directory on another device ends the chain unopened.
    let q = env.dir().join("q");
    fs::create_dir(&q).unwrap();
    env.real_cache(&q.join("cache/ratarmount/layers"));
    let attempt = env.layered(&[&bundle], false);
    fs::set_permissions(&q, fs::Permissions::from_mode(0o711)).unwrap();
    env.sup.seams.devices.insert(q.clone(), 7777);
    env.sup
        .seams
        .devices
        .insert(q.join("cache"), dev(&q.join("cache")));
    env.finalize(&attempt.id, false, None).unwrap();
    assert!(!env.sup.seams.syncs.contains(&q));
    env.sup.seams.devices.clear();
    fs::set_permissions(&q, fs::Permissions::from_mode(0o700)).unwrap();
    drop(env);
    // Above the state root.
    let parent = private_tempdir();
    let mut env = Env::new_in(parent.path());
    let attempt = env.attempt(false, false);
    fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o300)).unwrap();
    let error = env.finalize(&attempt.id, false, None).unwrap_err();
    fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(error.code, "invalid_request", "{}", error.message);
    assert!(
        error.message.contains(parent.path().to_str().unwrap()),
        "{}",
        error.message
    );
    assert!(!sealed(&attempt.overlay_dir));
}

impl Env {
    /// [`Env::new`] whose supervisor allows `max` attempts.
    pub(super) fn with_max_attempts(max: usize) -> Self {
        let mut env = Self::new();
        let state = private_tempdir();
        let mut sup =
            Supervisor::open(state.path(), max, Duration::from_secs(2), env.fake.clone()).unwrap();
        sup.test_ids = Some(TestIds::default());
        sup.handle(Operation::CreateBase {
            name: "task".into(),
            source: env.base.to_str().unwrap().into(),
            options: BaseOptions::default(),
        })
        .unwrap();
        env.sup = sup;
        env.state = state;
        env
    }

    /// The bundle cache root the retain preflight reads, whose
    /// `ratarmount/layers` the Fake child fills through the real cache code.
    pub(super) fn cache_at(&mut self, root: &Path) {
        self.sup.seams.cache_root = Some(root.to_path_buf());
        self.real_cache(&root.join("ratarmount/layers"));
    }

    /// A v2 `new` of one attempt on base `name` over `lowers`.
    pub(super) fn new_v2(
        &mut self,
        name: &str,
        lowers: &[&Path],
        overlay: Overlay,
        retain: bool,
        request_id: Option<&str>,
    ) -> Result<Value, ApiError> {
        self.sup.handle(OperationV2::New {
            base: name.into(),
            count: 1,
            overlay,
            quota: None,
            readonly_globs: vec![],
            request_id: request_id.map(Into::into),
            lowers: lowers
                .iter()
                .map(|p| p.to_str().unwrap().to_owned())
                .collect(),
            journal: None,
            retain,
        })
    }

    /// [`new_v2`](Self::new_v2) on the archive base `name`, whose top is
    /// opened as a worker child opens it (its read-only prepared index) over
    /// the layers that child took, and edited when `edit`.
    pub(super) fn archive_new(
        &mut self,
        name: &str,
        lowers: &[&Path],
        retain: bool,
        edit: bool,
    ) -> Result<Attempt, ApiError> {
        let result = self.new_v2(name, lowers, Overlay::Disk, retain, None)?;
        let attempt: Attempt = serde_json::from_value(result[0].clone()).unwrap();
        let source = PathBuf::from(&self.sup.base(name).unwrap().source);
        let indexes = self.sup.root.join("indexes").join(name);
        let token = self.worker_token(name, &source, &indexes);
        let records = self
            .sup
            .taken_lowers
            .get(&attempt.id)
            .cloned()
            .flatten()
            .unwrap_or_default();
        let layers: Vec<_> = records
            .iter()
            .map(|r| {
                (
                    r.path.clone(),
                    ratarmount_compositing::Immutability::Immutable,
                )
            })
            .collect();
        let view = ratarmount_compositing::compose_stack(token.source(), &layers).unwrap();
        let overlay = ratarmount_compositing::WriteOverlay::open(
            &token,
            view,
            &attempt.overlay_dir,
            &ratarmount_compositing::CreateOptions {
                lower_layers: records,
                ..Default::default()
            },
        )
        .unwrap();
        if edit {
            overlay
                .create_symlink(&format!("/{}", attempt.id), "/target")
                .unwrap();
        }
        drop(overlay);
        Ok(attempt)
    }

    /// Registers a TAR holding `content` as base `name`, with its prepared index.
    pub(super) fn tar_base(&mut self, name: &str, content: &[u8]) -> PathBuf {
        let source = self.dir().join(format!("{name}.tar"));
        fs::write(&source, tar_bytes(content)).unwrap();
        self.sup
            .handle(Operation::CreateBase {
                name: name.into(),
                source: source.to_str().unwrap().into(),
                options: BaseOptions::default(),
            })
            .unwrap();
        prepare_index(&source, &self.sup.root.join("indexes").join(name));
        source
    }

    /// Every `retained.jsonl` line, parsed.
    pub(super) fn retained_jsonl(&self) -> Vec<Value> {
        fs::read_to_string(self.sup.root.join(super::retained::NAME))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    /// The `retained.jsonl` lines of `id`.
    pub(super) fn retained_lines_of(&self, id: &str) -> Vec<Value> {
        self.retained_jsonl()
            .into_iter()
            .filter(|line| line["id"] == id)
            .collect()
    }

    /// The reply bytes of v1 `list`, v2 `list` or v2 `list` with `all`.
    pub(super) fn list_bytes(&mut self, version: u8, all: bool) -> Vec<u8> {
        let line = match (version, all) {
            (1, _) => r#"{"version":1,"op":"list"}"#,
            (_, false) => r#"{"version":2,"op":"list"}"#,
            (_, true) => r#"{"version":2,"op":"list","all":true}"#,
        };
        super::daemon::respond(&mut self.sup, line.as_bytes())
    }

    /// The IDs and statuses v2 `list` with `all` answers.
    pub(super) fn listed_all(&mut self) -> Vec<(String, String)> {
        let reply: Value = serde_json::from_slice(&self.list_bytes(2, true)).unwrap();
        reply["result"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| {
                (
                    item["id"].as_str().unwrap().to_owned(),
                    item["status"].as_str().unwrap().to_owned(),
                )
            })
            .collect()
    }

    /// The retained tree of `id`.
    pub(super) fn kept(&self, id: &str) -> PathBuf {
        self.sup.root.join(super::retained::DIR).join(id)
    }

    /// The commit's appends and renames this supervisor recorded.
    pub(super) fn commit_events(&self) -> Vec<String> {
        crate::overlay_pack::events::under(&self.sup.root)
            .into_iter()
            .filter(|event| event.starts_with("append ") || event.starts_with("rename "))
            .collect()
    }
}

/// Every node below `dir` (itself included): its type and mode, and a
/// regular file's bytes or a symlink's target.
pub(super) fn snapshot(dir: &Path) -> std::collections::BTreeMap<PathBuf, (u32, Vec<u8>)> {
    let mut nodes = std::collections::BTreeMap::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(path) = pending.pop() {
        let meta = fs::symlink_metadata(&path).unwrap();
        let content = if meta.is_dir() {
            for child in fs::read_dir(&path).unwrap() {
                pending.push(child.unwrap().path());
            }
            Vec::new()
        } else if meta.file_type().is_symlink() {
            use std::os::unix::ffi::OsStrExt;
            fs::read_link(&path)
                .unwrap()
                .as_os_str()
                .as_bytes()
                .to_vec()
        } else {
            fs::read(&path).unwrap()
        };
        nodes.insert(path, (meta.mode(), content));
    }
    nodes
}

/// Regression (R1c-1 T11r): `retain: false` must hash like R1a's `new`
/// (R1a's golden digest unchanged), `retain: true` must change the hash,
/// and v1 has no `retain`.
#[test]
fn regression_request_log_retain_hash_unchanged() {
    let hash = |line: &str| {
        let super::protocol::Op::V2(operation) = super::protocol::Request::parse(line.as_bytes())
            .unwrap()
            .operation
        else {
            panic!("v2 line");
        };
        super::requests::op_hash(&operation)
    };
    assert_eq!(
        hash(r#"{"version":2,"op":"new","base":"task","request_id":"r","retain":false}"#),
        "sha256:7c90b0d547f54b6b875948f96f3781758eb2820c17b9a32d2a8dd2536ebc135e"
    );
    assert_eq!(
        hash(r#"{"version":2,"op":"new","base":"task","retain":false}"#),
        hash(r#"{"version":2,"op":"new","base":"task"}"#)
    );
    assert_ne!(
        hash(r#"{"version":2,"op":"new","base":"task","retain":true}"#),
        hash(r#"{"version":2,"op":"new","base":"task"}"#)
    );
    let rejection =
        super::protocol::Request::parse(br#"{"version":1,"op":"new","base":"t","retain":true}"#)
            .unwrap_err();
    assert_eq!(rejection.error.code, "invalid_request");
}

/// Regression (R1c-1 T24r, ruling 7, retain half): `new` with `retain` must
/// be refused off Linux before anything is resolved, recorded, created or
/// spawned; on Linux the test override says "not Linux", on macOS nothing is
/// overridden. A `new` without `retain` still succeeds.
#[test]
fn regression_supervisor_retain_linux_only() {
    let state = private_tempdir();
    let base = private_tempdir();
    let fake = Fake::default();
    let mut sup = Supervisor::open(state.path(), 8, Duration::from_secs(2), fake.clone()).unwrap();
    sup.seams.not_linux = true;
    sup.handle(Operation::CreateBase {
        name: "task".into(),
        source: base.path().to_str().unwrap().into(),
        options: BaseOptions::default(),
    })
    .unwrap();
    let log = sup.root.join(super::requests::NAME);
    let len = fs::metadata(&log).unwrap().len();
    for (name, request_id) in [("task", None), ("task", Some("r")), ("missing", Some("r2"))] {
        let error = sup
            .handle(OperationV2::New {
                base: name.into(),
                count: 1,
                overlay: Overlay::Disk,
                quota: None,
                readonly_globs: vec![],
                request_id: request_id.map(Into::into),
                lowers: vec![],
                journal: None,
                retain: true,
            })
            .unwrap_err();
        assert_eq!(error.code, "invalid_request", "{}", error.message);
        assert!(error.message.contains("Linux only"), "{}", error.message);
    }
    assert_eq!(fs::metadata(&log).unwrap().len(), len, "nothing appended");
    assert_eq!(fake.0.lock().unwrap().spawns, 0);
    assert_eq!(fs::read_dir(sup.root.join("attempts")).unwrap().count(), 0);
    assert_eq!(fs::read_dir(sup.root.join("retained")).unwrap().count(), 0);
    assert!(!sup.root.join("ram-root.json").exists());
    sup.handle(OperationV2::New {
        base: "task".into(),
        count: 1,
        overlay: Overlay::Disk,
        quota: None,
        readonly_globs: vec![],
        request_id: Some("plain".into()),
        lowers: vec![],
        journal: None,
        retain: false,
    })
    .unwrap();
}

/// Nothing a refused `new` may leave: no new attempt directory, no spawn
/// and no RAM state.
fn nothing_started(env: &Env, spawns: usize) {
    assert_eq!(env.fake.0.lock().unwrap().spawns, spawns);
    assert_eq!(
        fs::read_dir(env.sup.root.join("attempts")).unwrap().count(),
        env.sup.attempts.len()
    );
    assert!(!env.sup.root.join("ram-root.json").exists());
}

/// A stack of `count` sealed directory layers in `parent` (created), each
/// sealed over the ones beneath it.
fn stack_in(env: &Env, parent: &Path, count: usize) -> Vec<PathBuf> {
    fs::create_dir_all(parent).unwrap();
    let mut layers: Vec<PathBuf> = Vec::new();
    for i in 0..count {
        let beneath: Vec<&Path> = layers.iter().map(PathBuf::as_path).collect();
        let name = parent
            .join(format!("L{i:02}"))
            .strip_prefix(env.dir())
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        layers.push(env.layer(&name, &beneath, &[(&format!("{i}.txt"), "x\n")]));
    }
    layers
}

/// Regression: a failed source stat let retain skip the TAR check and start
/// an attempt for a prepared ZIP. Refuse before even drawing an attempt ID,
/// whether the source is inaccessible or gone; Git URLs remain admissible.
#[test]
fn regression_supervisor_retain_source_stat_failure_before_allocation() {
    if !linux() {
        return;
    }
    let mut env = Env::new();
    let parent = env.dir().join("source");
    fs::create_dir(&parent).unwrap();
    let zip = parent.join("base.zip");
    fs::write(&zip, stored_zip("hello.txt", b"zip base\n")).unwrap();
    env.sup
        .handle(Operation::CreateBase {
            name: "zip".into(),
            source: zip.to_str().unwrap().into(),
            options: BaseOptions::default(),
        })
        .unwrap();
    prepare_index(&zip, &env.sup.root.join("indexes/zip"));
    env.sup
        .test_ids
        .as_mut()
        .unwrap()
        .queue
        .push_back("attempt-proof".into());
    let spawns = env.fake.0.lock().unwrap().spawns;
    let zip_error = env
        .new_v2("zip", &[], Overlay::Disk, true, None)
        .unwrap_err();
    assert_eq!(zip_error.code, "invalid_request");
    assert!(zip_error.message.contains("ZipMountSource"));

    let original_mode = fs::metadata(&parent).unwrap().permissions();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o000)).unwrap();
    let stat_error = fs::metadata(&zip).err();
    let inaccessible = if stat_error
        .as_ref()
        .is_some_and(|error| error.kind() == std::io::ErrorKind::PermissionDenied)
    {
        Some([
            env.new_v2("zip", &[], Overlay::Disk, true, None),
            env.new_v2("zip", &[], Overlay::Disk, true, Some("zip-permission")),
        ])
    } else {
        None
    };
    fs::set_permissions(&parent, original_mode).unwrap();
    if let Some(error) = stat_error.as_ref() {
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::PermissionDenied,
            "{error}"
        );
    } else {
        eprintln!(
            "skip: this user can search a mode-000 directory; the missing-source case still runs"
        );
    }
    if let Some(results) = inaccessible {
        let stat_message = stat_error.unwrap().to_string();
        for result in results {
            let error = result.unwrap_err();
            assert_eq!(error.code, "invalid_request", "{}", error.message);
            assert!(
                error.message.contains(zip.to_str().unwrap()),
                "{}",
                error.message
            );
            assert!(error.message.contains(&stat_message), "{}", error.message);
            nothing_started(&env, spawns);
            assert_eq!(
                env.sup.test_ids.as_ref().unwrap().queue.front().unwrap(),
                "attempt-proof"
            );
        }
        assert_eq!(
            env.sup.requests.status("zip-permission"),
            Some(super::requests::Status::Retryable)
        );
    }

    fs::rename(&parent, env.dir().join("moved-source")).unwrap();
    for request_id in [None, Some("zip-missing")] {
        let error = env
            .new_v2("zip", &[], Overlay::Disk, true, request_id)
            .unwrap_err();
        assert_eq!(error.code, "invalid_request", "{}", error.message);
        assert!(
            error.message.contains(zip.to_str().unwrap()),
            "{}",
            error.message
        );
        nothing_started(&env, spawns);
        assert_eq!(
            env.sup.test_ids.as_ref().unwrap().queue.front().unwrap(),
            "attempt-proof"
        );
    }
    assert_eq!(
        env.sup.requests.status("zip-missing"),
        Some(super::requests::Status::Retryable)
    );
    fs::rename(env.dir().join("moved-source"), &parent).unwrap();
    let error = env
        .new_v2("zip", &[], Overlay::Disk, true, Some("zip-missing"))
        .unwrap_err();
    assert!(
        error.message.contains("ZipMountSource"),
        "{}",
        error.message
    );
    nothing_started(&env, spawns);
    assert_eq!(
        env.sup.test_ids.as_ref().unwrap().queue.front().unwrap(),
        "attempt-proof"
    );

    // A missing directory base must fail at the same point as a missing
    // archive, rather than reaching the worker.
    let moved_base = env.dir().join("moved-base");
    fs::rename(&env.base, &moved_base).unwrap();
    let missing_directory = env.new_v2("task", &[], Overlay::Disk, true, None);
    fs::rename(&moved_base, &env.base).unwrap();
    let error = missing_directory.unwrap_err();
    assert_eq!(error.code, "invalid_request", "{}", error.message);
    assert!(
        error.message.contains(env.base.to_str().unwrap()),
        "{}",
        error.message
    );
    nothing_started(&env, spawns);
    assert_eq!(
        env.sup.test_ids.as_ref().unwrap().queue.front().unwrap(),
        "attempt-proof"
    );

    // A Git URL is an alias, not a path to pass to fs::metadata. The Fake
    // worker lets this assert admission without depending on a Git CLI.
    env.sup
        .handle(Operation::CreateBase {
            name: "git".into(),
            source: format!("git://{}#main", env.base.display()),
            options: BaseOptions::default(),
        })
        .unwrap();
    env.new_v2("git", &[], Overlay::Disk, true, None).unwrap();
    assert_eq!(env.fake.0.lock().unwrap().spawns, spawns + 1);
}

/// Regression (R1c-1 T12, ruling 4 and the scope rule): `retain` must be
/// refused, before any attempt exists, on what finalize cannot retain: a
/// non-TAR archive judged by its prepared index's `backendName` (v1 on that
/// base unchanged), an archive without a prepared index or without a TAR
/// index, a RAM overlay, a full `--max-retained` (every live attempt created
/// with `retain`, and every slot of a batch's `count`, counts); by the
/// durability rule for
/// `attempts/`, `indexes/`, each directory lower and each bundle position's
/// cache directory (never the bundle file); and a future `retained.jsonl`
/// line over 64 KiB (escapes counted) is `capacity`.
#[test]
fn regression_supervisor_retain_preflight() {
    if !linux() {
        return;
    }
    const OVERLAYFS: i64 = 0x794c_7630;
    let mut env = Env::new();
    // Ruling 4: a ZIP base.
    let zip = env.dir().join("base.zip");
    fs::write(&zip, stored_zip("hello.txt", b"zip base\n")).unwrap();
    env.sup
        .handle(Operation::CreateBase {
            name: "zip".into(),
            source: zip.to_str().unwrap().into(),
            options: BaseOptions::default(),
        })
        .unwrap();
    prepare_index(&zip, &env.sup.root.join("indexes/zip"));
    let spawns = env.fake.0.lock().unwrap().spawns;
    for request_id in [None, Some("zip-r")] {
        let error = env
            .new_v2("zip", &[], Overlay::Disk, true, request_id)
            .unwrap_err();
        assert_eq!(error.code, "invalid_request", "{}", error.message);
        assert!(
            error.message.contains("ZipMountSource"),
            "{}",
            error.message
        );
        nothing_started(&env, spawns);
    }
    assert_eq!(
        env.sup.requests.status("zip-r"),
        Some(super::requests::Status::Retryable)
    );
    // v1 on the same base behaves as today.
    let result = env
        .sup
        .handle(Operation::New {
            base: "zip".into(),
            count: 1,
            overlay: Overlay::Disk,
            quota: None,
            readonly_globs: vec![],
        })
        .unwrap();
    let id = result[0]["id"].as_str().unwrap().to_owned();
    env.sup.handle(Operation::Stats { id: id.clone() }).unwrap();
    env.sup
        .handle(Operation::Destroy {
            id: Some(id),
            base: None,
        })
        .unwrap();
    // A TAR base and a `.tar.zst` base are accepted.
    env.tar_base("tar", b"tar base\n");
    env.new_v2("tar", &[], Overlay::Disk, true, None).unwrap();
    let zst = env.dir().join("base.tar.zst");
    fs::write(&zst, tar_zst(&tar_bytes(b"zst base\n"))).unwrap();
    env.sup
        .handle(Operation::CreateBase {
            name: "zst".into(),
            source: zst.to_str().unwrap().into(),
            options: BaseOptions::default(),
        })
        .unwrap();
    prepare_index(&zst, &env.sup.root.join("indexes/zst"));
    env.new_v2("zst", &[], Overlay::Disk, true, None).unwrap();
    // An archive without a prepared index.
    let bare = env.dir().join("bare.tar");
    fs::write(&bare, tar_bytes(b"bare\n")).unwrap();
    env.sup
        .handle(Operation::CreateBase {
            name: "bare".into(),
            source: bare.to_str().unwrap().into(),
            options: BaseOptions::default(),
        })
        .unwrap();
    let error = env
        .new_v2("bare", &[], Overlay::Disk, true, None)
        .unwrap_err();
    assert_eq!(error.code, "invalid_request", "{}", error.message);
    assert!(
        error.message.contains("has no prepared index"),
        "{}",
        error.message
    );
    // A single compressed file: its index records no TAR backend.
    let single = env.dir().join("single.txt.zst");
    fs::write(&single, tar_zst(b"just text, no TAR header\n")).unwrap();
    env.sup
        .handle(Operation::CreateBase {
            name: "single".into(),
            source: single.to_str().unwrap().into(),
            options: BaseOptions::default(),
        })
        .unwrap();
    let indexes = env.sup.root.join("indexes/single");
    let options = ratarmount_core::OpenOptions {
        index_folders: vec![indexes.clone()],
        ..Default::default()
    };
    drop(ratarmount_session::factory::open_path(&single, &options, false).unwrap());
    // The factory keeps the zstd block table in an index without a
    // `backendName`.
    assert!(fs::read_dir(&indexes).unwrap().any(|entry| entry
        .unwrap()
        .path()
        .extension()
        .is_some_and(|e| e == "sqlite")));
    let error = env
        .new_v2("single", &[], Overlay::Disk, true, None)
        .unwrap_err();
    assert_eq!(error.code, "invalid_request", "{}", error.message);
    assert!(
        error.message.contains("has no TAR index"),
        "{}",
        error.message
    );
    // A RAM overlay.
    let error = env
        .new_v2("task", &[], Overlay::Tmpfs, true, None)
        .unwrap_err();
    assert_eq!(error.code, "invalid_request", "{}", error.message);
    assert!(error.message.contains("disk overlay"), "{}", error.message);
    assert!(!env.sup.root.join("ram-root.json").exists());
    // --max-retained: full, and 0.
    env.sup.max_retained = env.sup.held().len();
    let error = env
        .new_v2("task", &[], Overlay::Disk, true, None)
        .unwrap_err();
    assert_eq!(error.code, "capacity", "{}", error.message);
    env.sup.max_retained = 0;
    let error = env
        .new_v2("task", &[], Overlay::Disk, true, None)
        .unwrap_err();
    assert_eq!(error.code, "capacity", "{}", error.message);
    // One slot over the held count: a batch counts its whole `count`, and a
    // live, unfinalized attempt created with `retain` holds a slot.
    env.sup.max_retained = env.sup.held().len() + 1;
    let spawns = env.fake.0.lock().unwrap().spawns;
    let error = env
        .sup
        .handle(OperationV2::New {
            base: "task".into(),
            count: 2,
            overlay: Overlay::Disk,
            quota: None,
            readonly_globs: vec![],
            request_id: None,
            lowers: vec![],
            journal: None,
            retain: true,
        })
        .unwrap_err();
    assert_eq!(error.code, "capacity", "{}", error.message);
    nothing_started(&env, spawns);
    let live = env.attempt(true, false);
    assert!(env.sup.held().contains(&live.id));
    let spawns = env.fake.0.lock().unwrap().spawns;
    let error = env
        .new_v2("task", &[], Overlay::Disk, true, None)
        .unwrap_err();
    assert_eq!(error.code, "capacity", "{}", error.message);
    nothing_started(&env, spawns);
    env.sup.max_retained = super::retained::MAX_RETAINED;
    // The durability rule at `new`: attempts/, indexes/<base>/'s parent, a
    // directory lower's root or its parent on overlayfs.
    let lower = env.layer("A", &[], &[("a.txt", "a\n")]);
    for typed in [
        env.sup.root.join("attempts"),
        env.sup.root.join("indexes"),
        lower.clone(),
        lower.parent().unwrap().to_path_buf(),
    ] {
        env.sup
            .seams
            .fs_types
            .borrow_mut()
            .insert(typed.clone(), OVERLAYFS);
        let spawns = env.fake.0.lock().unwrap().spawns;
        let error = env
            .new_v2("task", &[&lower], Overlay::Disk, true, None)
            .unwrap_err();
        assert_eq!(
            error.code, "invalid_request",
            "{typed:?}: {}",
            error.message
        );
        assert!(
            error.message.contains(typed.to_str().unwrap()),
            "{}",
            error.message
        );
        assert!(error.message.contains("overlayfs"), "{}", error.message);
        nothing_started(&env, spawns);
        env.sup.seams.fs_types.borrow_mut().clear();
    }
    // Bundle positions are judged by their cache directory, never the
    // bundle file. A cache that does not exist yet: its deepest existing
    // ancestor.
    let (_, bundle) = env.bundle("B", &[("b.txt", "b\n")]);
    let xdg = env.dir().join("xdg");
    env.cache_at(&xdg);
    env.sup
        .seams
        .fs_types
        .borrow_mut()
        .insert(env.dir(), OVERLAYFS);
    let spawns = env.fake.0.lock().unwrap().spawns;
    let error = env
        .new_v2("task", &[&bundle], Overlay::Disk, true, None)
        .unwrap_err();
    assert_eq!(error.code, "invalid_request", "{}", error.message);
    assert!(
        error.message.contains(env.dir().to_str().unwrap()),
        "{}",
        error.message
    );
    nothing_started(&env, spawns);
    env.sup.seams.fs_types.borrow_mut().clear();
    // An existing cache directory on overlayfs.
    let layers = xdg.join("ratarmount/layers");
    fs::create_dir_all(&layers).unwrap();
    env.sup
        .seams
        .fs_types
        .borrow_mut()
        .insert(layers.clone(), OVERLAYFS);
    let error = env
        .new_v2("task", &[&bundle], Overlay::Disk, true, None)
        .unwrap_err();
    assert!(
        error.message.contains(layers.to_str().unwrap()),
        "{}",
        error.message
    );
    env.sup.seams.fs_types.borrow_mut().clear();
    // A bundle file on overlayfs whose cache directory is allowed.
    env.sup
        .seams
        .fs_types
        .borrow_mut()
        .insert(bundle.clone(), OVERLAYFS);
    env.new_v2("task", &[&bundle], Overlay::Disk, true, None)
        .unwrap();
    env.sup.seams.fs_types.borrow_mut().clear();
    // The record preflight: lower paths of control characters, each escaped
    // as six bytes, make the future line pass 64 KiB (SQLite opens no path
    // over 512 bytes, so plain characters cannot).
    let escaped = env
        .dir()
        .join("\u{1}".repeat(200))
        .join("\u{2}".repeat(200));
    let heavy = stack_in(&env, &escaped, 32);
    let refs: Vec<&Path> = heavy.iter().map(PathBuf::as_path).collect();
    let spawns = env.fake.0.lock().unwrap().spawns;
    for request_id in [None, Some("big")] {
        let error = env
            .new_v2("task", &refs, Overlay::Disk, true, request_id)
            .unwrap_err();
        assert_eq!(error.code, "capacity", "{}", error.message);
        assert!(
            error.message.contains("65536-byte bound"),
            "{}",
            error.message
        );
        nothing_started(&env, spawns);
    }
    // Without `retain` the same stack is accepted.
    env.layered(&refs, false);
    // 32 lowers with paths of about 250 bytes are accepted with `retain`.
    let long = env.dir().join("p".repeat(200));
    let plain = stack_in(&env, &long, 32);
    assert!(plain[31].to_str().unwrap().len() >= 220, "{:?}", plain[31]);
    let refs: Vec<&Path> = plain.iter().map(PathBuf::as_path).collect();
    env.new_v2("task", &refs, Overlay::Disk, true, None)
        .unwrap();
}

/// Regression (R1c-1 T13, source test 8 without `forget`): a retained
/// attempt lives in `retained/ID`, is listed only by v2 `list` with `all`
/// (v1 `list` and v2 `list` without `all` hide it and answer the same
/// bytes), is never destroyed, survives `destroy {base}`, `shutdown` and
/// `destroy_all`, can be diffed and stat'ed, never counts toward
/// `--max-attempts`, and keeps its ID reserved.
#[test]
fn regression_supervisor_retained_lifecycle() {
    if !linux() {
        return;
    }
    let mut env = Env::new();
    let attempt = env.attempt(true, false);
    let report = env.finalize(&attempt.id, false, None).unwrap();
    let kept = env.kept(&attempt.id);
    assert_eq!(report["status"], "retained");
    assert_eq!(report["attempt"]["status"], "retained");
    assert_eq!(report["attempt"]["path"], json!(kept.join("mnt")));
    assert_eq!(
        report["attempt"]["overlay_dir"],
        json!(kept.join("overlay"))
    );
    assert_eq!(report["manifest_path"], json!(kept.join("manifest.jsonl")));
    assert!(kept.join("overlay").is_dir());
    assert!(kept.join("manifest.jsonl").is_file());
    assert!(!attempt.path.parent().unwrap().exists());
    assert!(sealed(&kept.join("overlay")));
    assert_eq!(
        env.listed_all(),
        vec![(attempt.id.clone(), "retained".to_owned())]
    );
    // The commit dropped the child's mount-table entry at the old path.
    assert_eq!(
        env.fake.0.lock().unwrap().forgotten,
        vec![attempt.path.clone()]
    );
    // v1 and v2 `list` hide it and answer the same bytes.
    let other = env.attempt(false, false);
    let v1 = String::from_utf8(env.list_bytes(1, false)).unwrap();
    let v2 = String::from_utf8(env.list_bytes(2, false)).unwrap();
    assert_eq!(v2.replacen("\"version\":2", "\"version\":1", 1), v1);
    assert!(!v1.contains(&attempt.id), "{v1}");
    assert!(v1.contains(&other.id), "{v1}");
    // Never destroyed: by ID, by base, at shutdown.
    let error = env
        .sup
        .handle(Operation::Destroy {
            id: Some(attempt.id.clone()),
            base: None,
        })
        .unwrap_err();
    assert_eq!(error.code, "retained", "{}", error.message);
    env.sup
        .handle(Operation::Destroy {
            id: None,
            base: Some("task".into()),
        })
        .unwrap();
    assert!(!other.path.parent().unwrap().exists());
    env.sup.destroy_all().unwrap();
    assert!(kept.join("overlay").is_dir());
    // `diff` and `stats` work.
    let patch = env
        .sup
        .handle(Operation::Diff {
            id: attempt.id.clone(),
            git: true,
        })
        .unwrap();
    assert!(patch["patch"].as_str().unwrap().contains("link"), "{patch}");
    let stats = env
        .sup
        .handle(Operation::Stats {
            id: attempt.id.clone(),
        })
        .unwrap();
    assert_eq!(stats["files_deleted"], 1, "{stats}");
    // The test ID source drawing a retained ID gets it redrawn.
    env.sup
        .test_ids
        .as_mut()
        .unwrap()
        .queue
        .push_back(attempt.id.clone());
    let redrawn = env.attempt(false, false);
    assert_ne!(redrawn.id, attempt.id);
    // `shutdown` keeps it too.
    env.sup.handle(Operation::Shutdown).unwrap();
    assert!(kept.join("overlay").is_dir());
    assert_eq!(
        env.listed_all(),
        vec![(attempt.id.clone(), "retained".to_owned())]
    );
    // Retained attempts never count toward --max-attempts (Keystone #1).
    let mut small = Env::with_max_attempts(2);
    for _ in 0..2 {
        let attempt = small.attempt(true, false);
        small.finalize(&attempt.id, false, None).unwrap();
    }
    small.attempt(false, false);
    small.attempt(false, false);
    assert_eq!(small.sup.retained.len(), 2);
}

/// Regression (R1c-1 T10r): `diff` of a retained attempt read its overlay
/// against a base it never gated. It classifies and gates first, writing
/// nothing: `diff_failed` after the directory base is edited, the retained
/// overlay unchanged; restored, it renders again.
#[test]
fn regression_supervisor_retained_diff_gates_base() {
    if !linux() {
        return;
    }
    let mut env = Env::new();
    let attempt = env.attempt(true, false);
    env.finalize(&attempt.id, false, None).unwrap();
    let id = attempt.id.clone();
    let diff = |env: &mut Env| {
        env.sup.handle(Operation::Diff {
            id: id.clone(),
            git: true,
        })
    };
    let rendered = diff(&mut env).unwrap();
    let overlay = env.kept(&attempt.id).join("overlay");
    let before = snapshot(&overlay);
    let file = env.base.join("f");
    let modified = fs::metadata(&file).unwrap().modified().unwrap();
    fs::write(&file, "edited after the retain, longer\n").unwrap();
    let error = diff(&mut env).unwrap_err();
    assert_eq!(error.code, "diff_failed", "{}", error.message);
    assert_eq!(snapshot(&overlay), before, "the overlay is unchanged");
    fs::write(&file, "original\n").unwrap();
    fs::File::options()
        .write(true)
        .open(&file)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(modified))
        .unwrap();
    assert_eq!(diff(&mut env).unwrap(), rendered);
}

/// Regression (R1c-1 T14, ruling 3): a retained attempt is a lower within
/// the run by exactly `retained/ID/overlay` (R1b's reserved exception) once
/// its commit is acknowledged; the bundle, other paths under `retained/`,
/// `…/overlay/.`, a symlink into it, and unknown, unacknowledged or
/// preserved IDs are refused; R1b's stack and base rules still apply; `over`
/// comes from the requested paths, never from a digest (two empty layers
/// share one).
#[test]
fn regression_supervisor_retained_as_lower() {
    if !linux() {
        return;
    }
    let mut env = Env::new();
    env.tar_base("tar", b"lowers\n");
    let a = env.archive_new("tar", &[], true, true).unwrap();
    env.finalize(&a.id, true, None).unwrap();
    let dir = env.kept(&a.id);
    let a_overlay = dir.join("overlay");
    // Accepted, composed, and synced by S as a lower.
    let layered = env.archive_new("tar", &[&a_overlay], false, true).unwrap();
    assert_eq!(
        env.sup.attempt_state[&layered.id].over,
        std::slice::from_ref(&a.id)
    );
    assert_eq!(
        env.sup.taken_lowers[&layered.id].clone().unwrap()[0].path,
        a_overlay
    );
    let report = env.finalize(&layered.id, false, None).unwrap();
    assert_eq!(report["status"], "finalized");
    assert!(env
        .sup
        .seams
        .syncs
        .contains(&a_overlay.join(ratarmount_compositing::HIDDEN_DB)));
    // Refused before anything starts.
    let link = env.dir().join("into-retained");
    std::os::unix::fs::symlink(&a_overlay, &link).unwrap();
    for refused in [
        dir.join("bundle.tar.zst"),
        dir.clone(),
        PathBuf::from(format!("{}/.", a_overlay.display())),
        link,
        env.kept("attempt-999999").join("overlay"),
    ] {
        let spawns = env.fake.0.lock().unwrap().spawns;
        let error = env
            .new_v2("tar", &[&refused], Overlay::Disk, false, None)
            .unwrap_err();
        assert_eq!(
            error.code, "invalid_request",
            "{refused:?}: {}",
            error.message
        );
        nothing_started(&env, spawns);
    }
    // Unacknowledged: R4's open failed; once acknowledged it is accepted.
    let u = env.archive_new("tar", &[], true, true).unwrap();
    let retained = env.sup.root.join("retained");
    env.sup.seams.open_errors.insert(retained.clone(), 5);
    assert_eq!(env.finalize(&u.id, false, None).unwrap_err().code, "io");
    env.sup.seams.open_errors.clear();
    let u_overlay = env.kept(&u.id).join("overlay");
    let error = env
        .new_v2("tar", &[&u_overlay], Overlay::Disk, false, None)
        .unwrap_err();
    assert_eq!(error.code, "invalid_request", "{}", error.message);
    assert!(
        error.message.contains("not yet acknowledged"),
        "{}",
        error.message
    );
    env.finalize(&u.id, false, None).unwrap();
    env.archive_new("tar", &[&u_overlay], false, false).unwrap();
    // R1b's stack check: a retained layer sealed over [A] without A.
    let over_a = env.archive_new("tar", &[&a_overlay], true, true).unwrap();
    env.finalize(&over_a.id, false, None).unwrap();
    let b_overlay = env.kept(&over_a.id).join("overlay");
    let error = env
        .new_v2("tar", &[&b_overlay], Overlay::Disk, false, None)
        .unwrap_err();
    assert_eq!(error.code, "invalid_request", "{}", error.message);
    assert!(error.message.contains("sealed over"), "{}", error.message);
    // A layer retained over a directory base records `weak`: refused.
    let weak = env.attempt(true, false);
    env.finalize(&weak.id, false, None).unwrap();
    let weak_overlay = env.kept(&weak.id).join("overlay");
    let error = env
        .new_v2("task", &[&weak_overlay], Overlay::Disk, false, None)
        .unwrap_err();
    assert_eq!(error.code, "invalid_request", "{}", error.message);
    assert!(error.message.contains("weak"), "{}", error.message);
    // Two empty layers share a digest; `over` names the one requested.
    let e1 = env.archive_new("tar", &[], true, false).unwrap();
    env.finalize(&e1.id, false, None).unwrap();
    let e2 = env.archive_new("tar", &[], true, false).unwrap();
    env.finalize(&e2.id, false, None).unwrap();
    let digest = |id: &str| record(&env.kept(id).join("overlay")).layer_digest;
    assert_eq!(
        digest(&e1.id),
        ratarmount_compositing::overlay_changes::EMPTY_SHA256
    );
    assert_eq!(digest(&e1.id), digest(&e2.id));
    let e1_overlay = env.kept(&e1.id).join("overlay");
    let over_e1 = env
        .archive_new("tar", &[&e1_overlay], false, false)
        .unwrap();
    assert_eq!(
        env.sup.attempt_state[&over_e1.id].over,
        std::slice::from_ref(&e1.id)
    );
    // Preserved: retained before a restart, it is no lower of this run.
    let mut env = env.reopen();
    let error = env
        .new_v2("tar", &[&a_overlay], Overlay::Disk, false, None)
        .unwrap_err();
    assert_eq!(error.code, "invalid_request", "{}", error.message);
    assert!(
        error.message.contains("before a restart"),
        "{}",
        error.message
    );
}

/// Regression (R1c-1 T15, ruling 3): the retained record must hold the
/// identity restart recovery resolves by, never a digest alone: the ID and
/// instance, the base, the paths, `layer_digest` and `sealed_at` equal to
/// the overlay's rows, the prefix equal to the child's records (a bundle
/// position by its cache path and `sealed_at`), `over`, and the finalize
/// answer as `report`, byte for byte.
#[test]
fn regression_supervisor_retain_identity_record() {
    if !linux() {
        return;
    }
    let mut env = Env::new();
    env.tar_base("tar", b"identity\n");
    let a = env.archive_new("tar", &[], true, true).unwrap();
    env.finalize(&a.id, false, None).unwrap();
    let a_overlay = env.kept(&a.id).join("overlay");
    let attempt = env.archive_new("tar", &[&a_overlay], true, true).unwrap();
    let records = env.sup.taken_lowers[&attempt.id].clone().unwrap();
    let instance = env.sup.attempt_state[&attempt.id].instance.clone();
    let report = env.finalize(&attempt.id, true, None).unwrap();
    let lines = env.retained_lines_of(&attempt.id);
    assert_eq!(lines.len(), 1);
    let line = &lines[0];
    let overlay = env.kept(&attempt.id).join("overlay");
    let meta = OverlayMeta::read_no_recovery(&overlay).unwrap().unwrap();
    let mut members: Vec<&str> = line
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    members.sort_unstable();
    assert_eq!(
        members,
        [
            "base",
            "id",
            "instance",
            "layer_digest",
            "over",
            "paths",
            "prefix",
            "report",
            "sealed_at",
            "t",
            "v"
        ]
    );
    assert_eq!(line["v"], 1);
    assert_eq!(line["t"], "retained");
    assert_eq!(line["id"], attempt.id.as_str());
    assert_eq!(line["instance"], instance.as_str());
    assert!(super::requests::is_instance(&instance));
    assert_eq!(line["base"], "tar");
    assert_eq!(line["layer_digest"], meta.get("layer_digest").unwrap());
    assert_eq!(line["sealed_at"], meta.get("sealed_at").unwrap());
    assert_eq!(line["prefix"], json!(records));
    assert_eq!(line["over"], json!([a.id]));
    assert_eq!(line["paths"]["overlay"], json!(overlay));
    assert_eq!(
        line["paths"]["bundle"],
        json!(env.kept(&attempt.id).join("bundle.tar.zst"))
    );
    assert_eq!(
        serde_json::to_vec(&line["report"]).unwrap(),
        serde_json::to_vec(&report).unwrap()
    );
    // A bundle position names its cache path, with its `sealed_at`.
    let directory = env.layer("Dir", &[], &[("d.txt", "d\n")]);
    let (layer, bundle) = env.bundle_over("Bnd", &[&directory], &[("b.txt", "b\n")]);
    let xdg = env.dir().join("xdg");
    env.cache_at(&xdg);
    let stacked = env.layered(&[&directory, &bundle], true);
    let records = env.sup.taken_lowers[&stacked.id].clone().unwrap();
    assert!(records[1].path.starts_with(xdg.join("ratarmount/layers")));
    assert_eq!(records[1].sealed_at, record(&layer).sealed_at);
    let report = env.finalize(&stacked.id, false, None).unwrap();
    let line = env.retained_lines_of(&stacked.id).pop().unwrap();
    assert_eq!(line["prefix"], json!(records));
    assert_eq!(line["prefix"][1]["path"], json!(records[1].path));
    assert_eq!(line["over"], json!([]));
    assert!(line["paths"]["bundle"].is_null());
    assert_eq!(
        serde_json::to_vec(&line["report"]).unwrap(),
        serde_json::to_vec(&report).unwrap()
    );
}

/// Draws `id` through the test ID source and asserts the `new` got
/// another ID: something still reserves it.
fn assert_redrawn(sup: &mut Supervisor<Fake>, id: &str) {
    sup.test_ids.as_mut().unwrap().queue.push_back(id.into());
    let result = sup
        .handle(Operation::New {
            base: "task".into(),
            count: 1,
            overlay: Overlay::Disk,
            quota: None,
            readonly_globs: vec![],
        })
        .unwrap();
    let drawn = result[0]["id"].as_str().unwrap().to_owned();
    assert_ne!(drawn, id);
    sup.destroy(&drawn).unwrap();
}

/// Appends and ends retained records of other IDs until `retained.jsonl`
/// compacts.
fn force_retained_compaction(sup: &mut Supervisor<Fake>) {
    for i in 0..40 {
        let id = format!("filler-{i}");
        sup.retained_log
            .append_retained(&super::retained::Retained {
                id: id.clone(),
                instance: "0".repeat(32),
                base: "task".into(),
                layer_digest: ratarmount_compositing::overlay_changes::EMPTY_SHA256.into(),
                sealed_at: "filler".into(),
                prefix: vec![],
                over: vec![],
                paths: super::retained::Paths {
                    overlay: PathBuf::from("/filler"),
                    bundle: None,
                },
                report: json!({"pad": "p".repeat(60_000)}),
            })
            .unwrap();
        sup.retained_log.append_aborted(&id).unwrap();
        if sup.retained_log.events.borrow().contains(&"compact") {
            return;
        }
    }
    panic!("retained.jsonl never compacted");
}

/// Regression (R1c-1 T16, Keystone #2): a real SIGKILL at each commit point
/// of a retain, after R1 (S), R2 (the record), R3 (the rename) and R4 (the
/// syncs) before `done`. After the reopen `attempts/` is empty and the
/// request is a `v: 2` `failed interrupted` line with its target. After R1
/// nothing reserves the ID; after R2 the live record alone reserves it
/// (also after a compaction) and takes a `--max-retained` slot; after R3 and
/// R4 `retained/ID` is kept byte and mode for byte and mode, reserved, not
/// listed, not served (`invalid_request`, writing no request line) and never
/// destroyed, also as a bare name once `retained.jsonl` is moved aside.
#[test]
fn regression_supervisor_retain_crash_points() {
    if let Ok(point) = std::env::var(KILL_POINT) {
        return kill_child(&point);
    }
    if !linux() {
        return;
    }
    use super::requests::{Status, FINALIZE_INTERRUPTED};
    for point in [
        "after_sync",
        "after_record",
        "after_rename",
        "after_acknowledge",
    ] {
        let (dir, state) = kill_state();
        let marker = dir.path().join("marker");
        let processes = ratarmount_index::test_process::spawning();
        kill_at(
            "sandbox::finalize_tests::regression_supervisor_retain_crash_points",
            point,
            &state,
            &marker,
        );
        drop(processes);
        let _processes = ratarmount_index::test_process::exclusive();
        let retained = state.join("retained");
        let before = snapshot(&retained);
        let open = || {
            let mut sup =
                Supervisor::open(&state, 8, Duration::from_secs(2), Fake::default()).unwrap();
            sup.test_ids = Some(TestIds::default());
            sup
        };
        let mut sup = open();
        assert_eq!(
            fs::read_dir(state.join("attempts")).unwrap().count(),
            0,
            "{point}"
        );
        assert_eq!(sup.requests.status("k"), Some(Status::Failed), "{point}");
        let line: Value = serde_json::from_slice(
            &sup.requests
                .live_lines()
                .into_iter()
                .find(|line| String::from_utf8_lossy(line).contains("\"id\":\"k\""))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(line["v"], 2, "{point}");
        assert_eq!(line["error"]["code"], "interrupted", "{point}");
        assert_eq!(line["error"]["message"], FINALIZE_INTERRUPTED, "{point}");
        let id = line["target"]["id"].as_str().unwrap().to_owned();
        assert!(super::requests::is_instance(
            line["target"]["instance"].as_str().unwrap()
        ));
        match point {
            "after_sync" => {
                assert!(sup.retained_log.live(&id).is_none());
                assert_eq!(fs::read_dir(&retained).unwrap().count(), 0);
                assert!(fs::read(state.join(super::retained::NAME))
                    .unwrap()
                    .is_empty());
                assert!(!sup.held().contains(&id));
                assert!(!sup.requests.is_reserved(&id));
                sup.test_ids.as_mut().unwrap().queue.push_back(id.clone());
                let result = sup
                    .handle(Operation::New {
                        base: "task".into(),
                        count: 1,
                        overlay: Overlay::Disk,
                        quota: None,
                        readonly_globs: vec![],
                    })
                    .unwrap();
                assert_eq!(result[0]["id"], id.as_str(), "the ID may be drawn again");
            }
            "after_record" => {
                assert!(sup.retained_log.live(&id).is_some());
                assert_eq!(fs::read_dir(&retained).unwrap().count(), 0);
                assert!(sup.bare_retained.is_empty());
                assert!(sup.held().contains(&id));
                assert_redrawn(&mut sup, &id);
                force_retained_compaction(&mut sup);
                assert!(sup.retained_log.live(&id).is_some());
                assert_redrawn(&mut sup, &id);
                drop(sup);
                let mut sup = open();
                assert_redrawn(&mut sup, &id);
                // One --max-retained slot.
                sup.max_retained = 1;
                let error = sup
                    .handle(OperationV2::New {
                        base: "task".into(),
                        count: 1,
                        overlay: Overlay::Disk,
                        quota: None,
                        readonly_globs: vec![],
                        request_id: None,
                        lowers: vec![],
                        journal: None,
                        retain: true,
                    })
                    .unwrap_err();
                assert_eq!(error.code, "capacity", "{}", error.message);
            }
            _ => {
                assert!(sup.retained_log.live(&id).is_some(), "{point}");
                assert!(retained.join(&id).join("overlay").is_dir(), "{point}");
                assert_eq!(snapshot(&retained), before, "{point}: kept as it was");
                let not_served = |sup: &mut Supervisor<Fake>| {
                    assert!(sup.held().contains(&id));
                    let listed: Value = serde_json::from_slice(&super::daemon::respond(
                        sup,
                        br#"{"version":2,"op":"list","all":true}"#,
                    ))
                    .unwrap();
                    assert_eq!(listed["result"], json!([]), "{point}: not listed");
                    for operation in [
                        OperationV2::Finalize {
                            id: id.clone(),
                            pack: false,
                            request_id: None,
                        },
                        OperationV2::Diff {
                            id: id.clone(),
                            git: true,
                        },
                    ] {
                        let error = sup.handle(operation).unwrap_err();
                        assert_eq!(error.code, "invalid_request", "{}", error.message);
                        assert!(
                            error.message.contains("does not serve"),
                            "{}",
                            error.message
                        );
                    }
                    let error = sup.destroy(&id).unwrap_err();
                    assert_eq!(error.code, "retained", "{}", error.message);
                    // Under a fresh request ID nothing is appended.
                    let log = state.join(super::requests::NAME);
                    let len = fs::metadata(&log).unwrap().len();
                    let error = sup
                        .handle(OperationV2::Finalize {
                            id: id.clone(),
                            pack: false,
                            request_id: Some("fresh".into()),
                        })
                        .unwrap_err();
                    assert_eq!(error.code, "invalid_request", "{}", error.message);
                    assert_eq!(fs::metadata(&log).unwrap().len(), len);
                    assert_eq!(sup.requests.status("fresh"), None);
                    assert_redrawn(sup, &id);
                    assert_eq!(snapshot(&retained), before, "{point}: still as it was");
                };
                not_served(&mut sup);
                drop(sup);
                let mut sup = open();
                not_served(&mut sup);
                drop(sup);
                // `retained.jsonl` moved aside: a bare name, no instance.
                fs::rename(
                    state.join(super::retained::NAME),
                    dir.path().join("aside.jsonl"),
                )
                .unwrap();
                let mut sup = open();
                assert!(sup.bare_retained.contains(&id), "{point}");
                assert!(sup.retained_log.live(&id).is_none());
                not_served(&mut sup);
                drop(sup);
                drop(open());
            }
        }
        writable(dir.path());
    }
}

/// Regression (R1c-1 T22, sweep 3 Codex N3): R3 refused by a stray
/// `retained/ID` leaves the tree in `attempts/`, the stray unchanged, an
/// `aborted` line and a `retryable` request; the same ID retains once the
/// stray is gone. When the `aborted` append fails but its truncation works,
/// the record stays live, holding its ID and a `--max-retained` slot also
/// after the attempt is destroyed and after a restart, where the retry of
/// the original request answers `not_found` (its attempt is gone and the
/// stray is no sealed layer) and nothing serves the ID. When the truncation
/// fails too, `retained.jsonl` is `Broken`: every later `retain` is `io`,
/// a finalize without `retain` succeeds, and `destroy` removes the tree.
#[test]
fn regression_supervisor_retain_rename_failure() {
    if !linux() {
        return;
    }
    use super::requests::{Status, Target};
    use super::state_log::{Append, Fault};
    let plant = |env: &Env, id: &str| {
        let stray = env.kept(id);
        fs::create_dir(&stray).unwrap();
        fs::write(stray.join("stray"), b"planted\n").unwrap();
        stray
    };
    let kinds = |env: &Env, id: &str| -> Vec<String> {
        env.retained_lines_of(id)
            .iter()
            .map(|line| line["t"].as_str().unwrap().to_owned())
            .collect()
    };
    // R3 refused: aborted, retryable, then retained once the stray is gone.
    let mut env = Env::new();
    let attempt = env.attempt(true, false);
    let stray = plant(&env, &attempt.id);
    let stray_before = snapshot(&stray);
    let error = env.finalize(&attempt.id, false, Some("r")).unwrap_err();
    assert_eq!(error.code, "io", "{}", error.message);
    assert!(
        error.message.contains(stray.to_str().unwrap()),
        "{}",
        error.message
    );
    assert!(attempt.overlay_dir.is_dir(), "the tree stays in attempts/");
    assert_eq!(snapshot(&stray), stray_before);
    assert_eq!(kinds(&env, &attempt.id), ["retained", "aborted"]);
    assert!(env.sup.retained_log.live(&attempt.id).is_none());
    assert_eq!(env.sup.requests.status("r"), Some(Status::Retryable));
    let root = env.sup.root.display().to_string();
    let events: Vec<String> = env
        .commit_events()
        .into_iter()
        .filter(|event| event.contains(&attempt.id) || event.contains("retained.jsonl"))
        .collect();
    assert_eq!(
        events,
        [
            "append Retained $ROOT/retained.jsonl".to_owned(),
            format!("rename $ROOT/retained/{}", attempt.id),
            "append Aborted $ROOT/retained.jsonl".to_owned(),
        ],
        "{root}"
    );
    fs::remove_dir_all(&stray).unwrap();
    let report = env.finalize(&attempt.id, false, Some("r")).unwrap();
    assert_eq!(report["status"], "retained");
    assert_eq!(env.sup.requests.status("r"), Some(Status::Done));
    assert!(sealed(&env.kept(&attempt.id).join("overlay")));
    assert_eq!(
        kinds(&env, &attempt.id),
        ["retained", "aborted", "retained"]
    );

    // The `aborted` append fails, its truncation works: the record stays
    // live; a retry writes a new `retained` line.
    let attempt = env.attempt(true, false);
    let stray = plant(&env, &attempt.id);
    let log = env.sup.root.join(super::retained::NAME);
    env.sup
        .retained_log
        .faults
        .push(Fault::Write(Append::Aborted));
    assert_eq!(
        env.finalize(&attempt.id, false, None).unwrap_err().code,
        "io"
    );
    assert!(!env.sup.retained_log.broken());
    assert!(env.sup.retained_log.live(&attempt.id).is_some());
    assert!(env.sup.held().contains(&attempt.id));
    assert_eq!(
        kinds(&env, &attempt.id),
        ["retained"],
        "the torn line is gone"
    );
    assert!(fs::read(&log).unwrap().ends_with(b"\n"));
    fs::remove_dir_all(&stray).unwrap();
    env.finalize(&attempt.id, false, None).unwrap();
    assert_eq!(kinds(&env, &attempt.id), ["retained", "retained"]);
    drop(env);

    // The orphan record after its attempt is gone, under --max-retained 1.
    let mut env = Env::new();
    env.sup.max_retained = 1;
    let attempt = env.attempt(true, false);
    let id = attempt.id.clone();
    let target = Target {
        id: id.clone(),
        instance: env.sup.attempt_state[&id].instance.clone(),
    };
    let stray = plant(&env, &id);
    let stray_before = snapshot(&stray);
    env.sup
        .retained_log
        .faults
        .push(Fault::Write(Append::Aborted));
    assert_eq!(env.finalize(&id, false, Some("o")).unwrap_err().code, "io");
    assert_eq!(env.sup.requests.target("o"), Some(&target));
    env.sup
        .handle(Operation::Destroy {
            id: Some(id.clone()),
            base: None,
        })
        .unwrap();
    assert!(!attempt.path.parent().unwrap().exists());
    let orphan = |env: &mut Env| {
        assert!(env.sup.retained_log.live(&id).is_some());
        assert!(env.sup.held().contains(&id));
        let spawns = env.fake.0.lock().unwrap().spawns;
        let error = env
            .new_v2("task", &[], Overlay::Disk, true, None)
            .unwrap_err();
        assert_eq!(error.code, "capacity", "{}", error.message);
        nothing_started(env, spawns);
        assert_redrawn(&mut env.sup, &id);
        for operation in [
            OperationV2::Finalize {
                id: id.clone(),
                pack: false,
                request_id: None,
            },
            OperationV2::Diff {
                id: id.clone(),
                git: true,
            },
            OperationV2::Stats { id: id.clone() },
        ] {
            let error = env.sup.handle(operation).unwrap_err();
            assert_eq!(error.code, "invalid_request", "{}", error.message);
            assert!(
                error.message.contains("does not serve"),
                "{}",
                error.message
            );
        }
        assert_eq!(env.sup.destroy(&id).unwrap_err().code, "retained");
        let len = env.requests_len();
        let error = env.finalize(&id, false, Some("fresh")).unwrap_err();
        assert_eq!(error.code, "invalid_request", "{}", error.message);
        assert_eq!(env.requests_len(), len);
        // The original request's attempt is gone and the stray is no
        // sealed layer: `not_found`, nothing appended, still retryable.
        let error = env.finalize(&id, false, Some("o")).unwrap_err();
        assert_eq!(error.code, "not_found", "{}", error.message);
        assert_eq!(env.requests_len(), len);
        assert_eq!(env.sup.requests.status("o"), Some(Status::Retryable));
        assert_eq!(env.sup.requests.target("o"), Some(&target));
        assert_eq!(snapshot(&stray), stray_before);
    };
    orphan(&mut env);
    let mut env = env.reopen();
    env.sup.max_retained = 1;
    orphan(&mut env);
    drop(env);

    // The truncation fails too: `Broken`.
    let mut env = Env::new();
    let later = env.attempt(true, false);
    let plain = env.attempt(false, false);
    let attempt = env.attempt(true, false);
    plant(&env, &attempt.id);
    env.sup
        .retained_log
        .faults
        .extend([Fault::Write(Append::Aborted), Fault::Truncate]);
    assert_eq!(
        env.finalize(&attempt.id, false, None).unwrap_err().code,
        "io"
    );
    assert!(env.sup.retained_log.broken());
    let error = env
        .new_v2("task", &[], Overlay::Disk, true, None)
        .unwrap_err();
    assert_eq!(error.code, "io", "{}", error.message);
    assert!(
        error.message.contains("retained log unavailable"),
        "{}",
        error.message
    );
    let stops = env.stops();
    let error = env.finalize(&later.id, false, None).unwrap_err();
    assert_eq!(error.code, "io", "{}", error.message);
    assert!(
        error.message.contains("retained log unavailable"),
        "{}",
        error.message
    );
    assert_eq!(env.stops(), stops, "refused before the stop");
    env.finalize(&plain.id, false, None).unwrap();
    env.sup
        .handle(Operation::Destroy {
            id: Some(attempt.id.clone()),
            base: None,
        })
        .unwrap();
    assert!(!attempt.path.parent().unwrap().exists());
}

/// Regression (R1c-1 T17r, rulings 1+2 and 6, retain half): a retain must
/// leave no `retained` line and no rename when S fails (an injected fsync
/// error of any errno, which poisons, or a node on another device, which
/// does not). An fsync failure at R4 leaves the entry listed `finalizing`
/// only by `list` with `all`, poisons the state filesystem, keeps it refused
/// as a lower and never destroyed; after a restart its retry answers the
/// not-served `invalid_request` without appending; the request log still
/// compacts and serves. An open failure at R4 poisons nothing, and the same
/// request then completes R4 and R5.
#[test]
fn regression_supervisor_retain_sync_poison() {
    if !linux() {
        return;
    }
    const EIO: i32 = 5;
    let nothing_committed = |env: &Env, id: &str| {
        assert!(env.commit_events().is_empty(), "{:?}", env.commit_events());
        assert!(env.retained_lines_of(id).is_empty());
        assert_eq!(
            fs::read_dir(env.sup.root.join("retained")).unwrap().count(),
            0
        );
    };
    // An fsync failure in S, of any errno.
    for errno in [EIO, 22, 30] {
        let mut env = Env::new();
        let attempt = env.attempt(true, false);
        env.sup.seams.fsync_errors.insert(
            attempt.overlay_dir.join(ratarmount_compositing::HIDDEN_DB),
            errno,
        );
        let error = env.finalize(&attempt.id, false, None).unwrap_err();
        assert_eq!(error.code, "io", "{errno}: {}", error.message);
        assert!(!env.sup.poisoned.is_empty(), "{errno} poisons");
        nothing_committed(&env, &attempt.id);
    }
    // A node on another device: refused before its fsync, nothing poisoned.
    let mut env = Env::new();
    let lower = env.layer("L", &[], &[("a.txt", "a\n"), ("b.txt", "b\n")]);
    let attempt = env.layered(&[&lower], true);
    env.sup.seams.devices.insert(lower.clone(), 2002);
    env.sup.seams.devices.insert(lower.join("b.txt"), 3003);
    let error = env.finalize(&attempt.id, false, None).unwrap_err();
    assert_eq!(error.code, "io", "{}", error.message);
    assert!(error.message.contains("3003"), "{}", error.message);
    assert!(env.sup.poisoned.is_empty());
    nothing_committed(&env, &attempt.id);
    drop(env);

    // An fsync failure at R4; only the compaction floor is lowered.
    let _limits = Limits::set(super::requests::Limits::new(65_536, 64 << 20, 4 << 20, 1).unwrap());
    let mut env = Env::new();
    let attempt = env.attempt(true, false);
    let other = env.attempt(false, false);
    let retained = env.sup.root.join("retained");
    env.sup.seams.fsync_errors.insert(retained.clone(), EIO);
    let error = env.finalize(&attempt.id, false, Some("q")).unwrap_err();
    assert_eq!(error.code, "io", "{}", error.message);
    assert!(error.message.contains("cannot sync"), "{}", error.message);
    env.sup.seams.fsync_errors.clear();
    assert!(env.sup.poisoned.contains(&dev(&retained)));
    assert_eq!(
        env.sup.requests.status("q"),
        Some(super::requests::Status::Retryable)
    );
    let kept = env.kept(&attempt.id);
    assert!(kept.join("overlay").is_dir(), "R3 happened");
    assert!(env
        .listed_all()
        .contains(&(attempt.id.clone(), "finalizing".to_owned())));
    for version in [1, 2] {
        let reply = String::from_utf8(env.list_bytes(version, false)).unwrap();
        assert!(!reply.contains(&attempt.id), "{reply}");
    }
    let error = env.finalize(&other.id, false, None).unwrap_err();
    assert_eq!(error.code, "io", "{}", error.message);
    assert!(
        error.message.contains("failed earlier"),
        "{}",
        error.message
    );
    let overlay = kept.join("overlay");
    let error = env
        .new_v2("task", &[&overlay], Overlay::Disk, false, None)
        .unwrap_err();
    assert_eq!(error.code, "invalid_request", "{}", error.message);
    assert!(
        error.message.contains("not yet acknowledged"),
        "{}",
        error.message
    );
    let before = snapshot(&kept);
    assert_eq!(env.sup.destroy(&attempt.id).unwrap_err().code, "retained");
    assert_eq!(snapshot(&kept), before, "destroy deletes nothing");
    // The logs stay out of it: `requests.jsonl` still compacts, and a `new`
    // under a fresh request ID is answered as before.
    for _ in 0..12 {
        {
            let mut state = env.fake.0.lock().unwrap();
            state.fail_spawn = Some(state.spawns + 1);
        }
        assert_eq!(new_with_id(&mut env, "s").unwrap_err().code, "spawn_failed");
    }
    assert!(env.sup.requests.events.borrow().contains(&"compact"));
    assert!(!env.sup.requests.is_broken());
    new_with_id(&mut env, "after").unwrap();
    // A kept result is never reported as gone.
    let mut env = env.reopen();
    let len = env.requests_len();
    let error = env.finalize(&attempt.id, false, Some("q")).unwrap_err();
    assert_eq!(error.code, "invalid_request", "{}", error.message);
    assert!(
        error.message.contains("does not serve"),
        "{}",
        error.message
    );
    assert_eq!(env.requests_len(), len);
    assert_eq!(snapshot(&kept), before);
    drop(env.reopen());

    // An open failure at R4 poisons nothing; the same request completes.
    let mut env = Env::new();
    let attempt = env.attempt(true, false);
    let retained = env.sup.root.join("retained");
    env.sup.seams.open_errors.insert(retained, EIO);
    let error = env.finalize(&attempt.id, false, Some("p")).unwrap_err();
    assert_eq!(error.code, "io", "{}", error.message);
    assert!(env.sup.poisoned.is_empty());
    assert_eq!(
        env.listed_all(),
        vec![(attempt.id.clone(), "finalizing".to_owned())]
    );
    env.sup.seams.open_errors.clear();
    let report = env.finalize(&attempt.id, false, Some("p")).unwrap();
    assert_eq!(report["status"], "retained");
    assert_eq!(
        env.sup.requests.status("p"),
        Some(super::requests::Status::Done)
    );
    assert_eq!(
        env.listed_all(),
        vec![(attempt.id.clone(), "retained".to_owned())]
    );
}

/// Regression (sweep 1 review, kept-target retry contract): a retry under a
/// stored target whose kept overlay's database cannot be read (another
/// connection holds it under `BEGIN EXCLUSIVE`) is the check's failure,
/// never `not_found`: it answers `writers_active`, appends nothing and
/// stays `retryable`; once the database reads again the same retry answers
/// the not-served `invalid_request`, as T17r expects. Discarding the
/// metadata read's error used to turn the failure into "not the record's
/// layer" and reported the kept result as gone.
#[test]
fn regression_supervisor_retain_kept_target_unreadable_is_not_not_found() {
    if !linux() {
        return;
    }
    let mut env = Env::new();
    let attempt = env.attempt(true, false);
    // A retryable finalize record holds the target: an fsync failure at R4.
    env.sup
        .seams
        .fsync_errors
        .insert(env.sup.root.join("retained"), 5);
    let error = env.finalize(&attempt.id, false, Some("q")).unwrap_err();
    assert_eq!(error.code, "io", "{}", error.message);
    env.sup.seams.fsync_errors.clear();
    assert_eq!(
        env.sup.requests.status("q"),
        Some(super::requests::Status::Retryable)
    );
    // After a restart the kept tree is not served; its record holds the ID.
    let mut env = env.reopen();
    let db = env
        .kept(&attempt.id)
        .join("overlay")
        .join(ratarmount_compositing::HIDDEN_DB);
    // Hold the kept database, as the busy-database test holds the top's.
    let mode = fs::metadata(&db).unwrap().permissions().mode();
    fs::set_permissions(&db, fs::Permissions::from_mode(mode | 0o200)).unwrap();
    let holder = rusqlite::Connection::open(&db).unwrap();
    fs::set_permissions(&db, fs::Permissions::from_mode(mode)).unwrap();
    holder.execute_batch("BEGIN EXCLUSIVE").unwrap();
    let len = env.requests_len();
    let error = env.finalize(&attempt.id, false, Some("q")).unwrap_err();
    assert_eq!(error.code, "writers_active", "{}", error.message);
    assert_eq!(env.requests_len(), len, "nothing appended");
    assert_eq!(
        env.sup.requests.status("q"),
        Some(super::requests::Status::Retryable)
    );
    drop(holder);
    let error = env.finalize(&attempt.id, false, Some("q")).unwrap_err();
    assert_eq!(error.code, "invalid_request", "{}", error.message);
    assert!(
        error.message.contains("does not serve"),
        "{}",
        error.message
    );
    assert_eq!(env.requests_len(), len, "nothing appended");
}

/// Regression: a stray retained path makes R3 fail with EEXIST; after the
/// aborted record and the attempt's destruction or restart, the stray
/// reserves the ID but must not make a retry of the gone target not-served.
#[test]
fn regression_supervisor_retain_aborted_rename_retry_after_restart_is_not_found() {
    if !linux() {
        return;
    }
    for destroy_first in [false, true] {
        let mut env = Env::new();
        let attempt = env.attempt(true, false);
        let stray = env.kept(&attempt.id);
        fs::create_dir(&stray).unwrap();
        fs::write(stray.join("stray"), b"unrelated").unwrap();
        let before = snapshot(&stray);
        let error = env.finalize(&attempt.id, false, Some("r")).unwrap_err();
        assert_eq!(error.code, "io", "{}", error.message);
        let lines = env.retained_lines_of(&attempt.id);
        assert_eq!(
            lines
                .iter()
                .map(|line| line["t"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["retained", "aborted"]
        );
        assert!(env.sup.retained_log.live(&attempt.id).is_none());
        let target = env.sup.requests.target("r").unwrap().clone();
        assert_eq!(
            env.sup.requests.status("r"),
            Some(super::requests::Status::Retryable)
        );
        if destroy_first {
            env.sup.destroy(&attempt.id).unwrap();
        }
        let mut env = env.reopen();
        assert!(!attempt.path.parent().unwrap().exists());
        assert!(env.sup.bare_retained.contains(&attempt.id));
        let len = env.requests_len();
        for _ in 0..2 {
            let error = env.finalize(&attempt.id, false, Some("r")).unwrap_err();
            assert_eq!(error.code, "not_found", "{}", error.message);
            assert_eq!(env.requests_len(), len);
            assert_eq!(
                env.sup.requests.status("r"),
                Some(super::requests::Status::Retryable)
            );
            assert_eq!(env.sup.requests.target("r"), Some(&target));
            assert_eq!(snapshot(&stray), before);
        }
    }
}

/// Regression: a bare retained name reserves its ID, but cannot identify a
/// retry's stored instance, even if the directory happens to be sealed.
#[test]
fn regression_supervisor_retain_retry_of_bare_kept_tree_is_not_found() {
    if !linux() {
        return;
    }
    let mut env = Env::new();
    let attempt = env.attempt(true, false);
    // A retryable finalize record holds the target: an fsync failure at R4.
    env.sup
        .seams
        .fsync_errors
        .insert(env.sup.root.join("retained"), 5);
    let error = env.finalize(&attempt.id, false, Some("q")).unwrap_err();
    assert_eq!(error.code, "io", "{}", error.message);
    env.sup.seams.fsync_errors.clear();
    assert_eq!(
        env.sup.requests.status("q"),
        Some(super::requests::Status::Retryable)
    );
    // `retained.jsonl` moved aside and a restart: a bare name, no record.
    let aside = env.dir().join("aside.jsonl");
    fs::rename(env.sup.root.join(super::retained::NAME), &aside).unwrap();
    let mut env = env.reopen();
    assert!(env.sup.bare_retained.contains(&attempt.id));
    assert!(env.sup.retained_log.live(&attempt.id).is_none());
    let len = env.requests_len();
    let error = env.finalize(&attempt.id, false, Some("q")).unwrap_err();
    assert_eq!(error.code, "not_found", "{}", error.message);
    assert_eq!(env.requests_len(), len, "nothing appended");
    assert_eq!(
        env.sup.requests.status("q"),
        Some(super::requests::Status::Retryable)
    );
    // A fresh request still sees the reserved name as not served.
    let error = env.finalize(&attempt.id, false, Some("fresh")).unwrap_err();
    assert_eq!(error.code, "invalid_request", "{}", error.message);
    assert!(
        error.message.contains("does not serve"),
        "{}",
        error.message
    );
}

/// Regression (sweep 1 review): the retained fast path's tree carried
/// `retained/ID/mnt` as the mount point a stop removes, so the durability
/// preflight accepted a mount at that exact path even though no stop runs
/// there, and S then refused it with a less specific device-mismatch `io`.
/// A mount at or below `retained/ID/mnt` is refused at the preflight like
/// any other mount inside a tree. The finalized (non-retained) fast path
/// names no `mnt` either (PR A's still exempted `attempts/ID/mnt`, so a
/// mount there reached S's `io` instead; sweep 3 review): no stop runs on
/// a fast path.
#[test]
fn regression_supervisor_retain_fast_path_refuses_a_mount_at_mnt() {
    if !linux() {
        return;
    }
    for retain in [true, false] {
        let mut env = Env::new();
        let attempt = env.attempt(retain, false);
        env.finalize(&attempt.id, false, None).unwrap();
        let root = if retain {
            env.kept(&attempt.id)
        } else {
            attempt.path.parent().unwrap().to_path_buf()
        };
        for mount in [root.join("mnt"), root.join("mnt/inner")] {
            env.fake.0.lock().unwrap().extra_mounts = vec![mount.clone()];
            let error = env.finalize(&attempt.id, false, None).unwrap_err();
            assert_eq!(
                error.code, "invalid_request",
                "{retain} {mount:?}: {}",
                error.message
            );
            assert!(
                error.message.contains("has a mount inside it"),
                "{retain} {mount:?}: {}",
                error.message
            );
            env.fake.0.lock().unwrap().extra_mounts.clear();
        }
        env.finalize(&attempt.id, false, None).unwrap();
    }
}

/// Regression (sweep 2 review): `new` with `retain` ran the durability
/// preflight for `indexes/<base>/` and the bundle cache with the mount
/// check off, so a mount inside the prepared-index tree passed `new` and
/// was refused only at finalize — the gap §5.5 closes before anything
/// starts. The check now runs there as at finalize; `attempts/` stays
/// exempt, since it holds the running attempts' own `mnt` mounts.
#[test]
fn regression_supervisor_retain_new_checks_mounts_in_the_index_tree() {
    if !linux() {
        return;
    }
    let mut env = Env::new();
    let indexes = env.sup.indexes("task");
    let new_retain = |lowers: Vec<String>| OperationV2::New {
        base: "task".into(),
        count: 1,
        overlay: Overlay::Disk,
        quota: None,
        readonly_globs: vec![],
        request_id: None,
        lowers,
        journal: None,
        retain: true,
    };
    env.fake.0.lock().unwrap().extra_mounts = vec![indexes.join("x")];
    let error = env.sup.handle(new_retain(vec![])).unwrap_err();
    assert_eq!(error.code, "invalid_request", "{}", error.message);
    assert!(
        error.message.contains("has a mount inside it"),
        "{}",
        error.message
    );
    nothing_started(&env, 0);
    // A mount inside the bundle cache's eventual layers directory is
    // refused the same way (none can exist below it while the directory
    // itself does not exist, so checking it only then refuses nothing it
    // should not).
    let xdg = env.dir().join("xdg");
    let layers = xdg.join("ratarmount/layers");
    fs::create_dir_all(&layers).unwrap();
    env.cache_at(&xdg);
    let (_, bundle) = env.bundle("B", &[("b.txt", "b\n")]);
    env.fake.0.lock().unwrap().extra_mounts = vec![layers.join("x")];
    let error = env
        .sup
        .handle(new_retain(vec![bundle.to_str().unwrap().to_owned()]))
        .unwrap_err();
    assert_eq!(error.code, "invalid_request", "{}", error.message);
    assert!(
        error.message.contains("has a mount inside it"),
        "{}",
        error.message
    );
    nothing_started(&env, 0);
    // Without the mounts the same requests pass their preflights, and a
    // live attempt's own mount under `attempts/` does not refuse another
    // `new` with `retain` (the exemption the mount check cannot apply).
    env.fake.0.lock().unwrap().extra_mounts.clear();
    let first = env.attempt(true, false);
    assert!(env.fake.0.lock().unwrap().mounts.contains_key(&first.path));
    env.layered(&[&bundle], true);
}

/// Regression (sweep 1 review): an entry under `retained/` was taken as a
/// bare name unchecked, so a stray file counted toward `--max-retained`,
/// was pinned and answered as a kept attempt. `open_retained` now does for
/// `retained/` what `reconcile` does for `attempts/`: each entry must be a
/// directory with an attempt-ID name, or the start is refused.
#[test]
fn regression_supervisor_retained_dir_refuses_strays() {
    if !linux() {
        return;
    }
    let env = Env::new();
    let retained = env.sup.root.join("retained");
    let state = env.state.path().to_path_buf();
    let fake = env.fake.clone();
    // A directory with an attempt-ID name stays a bare name.
    fs::create_dir(retained.join("bare1")).unwrap();
    drop(env.sup);
    let open = || Supervisor::open(&state, 64, Duration::from_secs(2), fake.clone());
    // A file is not an attempt; neither is a symlink to a directory, nor a
    // directory whose name is no attempt ID.
    let file = retained.join("README");
    fs::write(&file, b"not an attempt\n").unwrap();
    let error = open().map(|_| ()).unwrap_err();
    assert_eq!(error.code, "invalid_request", "{}", error.message);
    assert!(error.message.contains("README"), "{}", error.message);
    fs::remove_file(&file).unwrap();
    std::os::unix::fs::symlink("bare1", retained.join("alias")).unwrap();
    assert_eq!(open().map(|_| ()).unwrap_err().code, "invalid_request");
    fs::remove_file(retained.join("alias")).unwrap();
    fs::create_dir(retained.join("-invalid")).unwrap();
    assert_eq!(open().map(|_| ()).unwrap_err().code, "invalid_request");
    fs::remove_dir(retained.join("-invalid")).unwrap();
    // With only the bare directory left, the daemon opens and still holds it.
    let sup = open().unwrap();
    assert!(sup.bare_retained.contains("bare1"));
    assert!(sup.held().contains("bare1"));
}

/// The positions of the fsync events of `path` in `events` (as
/// `events::under(root)` gives them).
fn fsyncs_of(events: &[String], root: &Path, path: &Path) -> Vec<usize> {
    let text = path
        .display()
        .to_string()
        .replace(&root.display().to_string(), "$ROOT");
    let event = format!("fsync @$ROOT {text}");
    events
        .iter()
        .enumerate()
        .filter(|(_, e)| **e == event)
        .map(|(i, _)| i)
        .collect()
}

/// Regression (R1c-1 T20.1, ruling 1+2, pre-R1c hit): a cache entry
/// published before the attempt with no sync (as the pre-R1c route left
/// entries — staged beside the destination and renamed into place, with no
/// entry lock and no fsync), named by the attempt's records as a cache hit,
/// was never made durable by a retain. The recorder shows, in order: the
/// entry's files, the entry, its parent; the top; `attempts/ID`;
/// `indexes/<base>/`; the S3 ancestors, deepest first and each once; then
/// the `retained` append, the rename, `retained/` and `attempts/`. Every
/// sync comes from that finalize; a second retained attempt over the same
/// entry syncs it again.
#[test]
fn regression_supervisor_retain_syncs_preexisting_cache_entry() {
    if !linux() {
        return;
    }
    use sha2::Digest;
    let mut env = Env::new();
    let (layer, bundle) = env.bundle("Pre", &[("p.txt", "p\n")]);
    let xdg = env.dir().join("xdg");
    let cache = xdg.join("ratarmount/layers");
    fs::create_dir_all(&cache).unwrap();
    // The pre-R1c fill: the sealed entry renamed into place under the name
    // `private_copy` gives it, the bundle bytes' digest — no lock, no sync.
    // Renaming a directory updates its `..`, which needs a write bit on it,
    // as `publish_layer`'s fchmod dance grants and restores.
    let mode = fs::metadata(&layer).unwrap().permissions().mode() & 0o7777;
    fs::set_permissions(&layer, fs::Permissions::from_mode(mode | 0o200)).unwrap();
    let entry = cache.join(format!(
        "{:x}",
        sha2::Sha256::digest(fs::read(&bundle).unwrap())
    ));
    fs::rename(&layer, &entry).unwrap();
    fs::set_permissions(&entry, fs::Permissions::from_mode(mode)).unwrap();
    env.cache_at(&xdg);
    let attempt = env.layered(&[&bundle], true);
    assert_eq!(
        env.sup.taken_lowers[&attempt.id].clone().unwrap()[0].path,
        entry,
        "a cache hit"
    );
    let root = env.sup.root.clone();
    let fsyncs = |events: &[String]| events.iter().filter(|e| e.starts_with("fsync @")).count();
    assert_eq!(fsyncs(&crate::overlay_pack::events::under(&root)), 0);
    let tree = attempt.path.parent().unwrap().to_path_buf();
    let indexes = root.join("indexes/task");
    env.finalize(&attempt.id, false, None).unwrap();
    let events = crate::overlay_pack::events::under(&root);
    assert_eq!(
        fsyncs(&events),
        env.sup.seams.syncs.len(),
        "every sync is the finalize's"
    );
    let once = |path: &Path| {
        let found = fsyncs_of(&events, &root, path);
        assert_eq!(found.len(), 1, "{path:?} once: {events:#?}");
        found[0]
    };
    // The lower, then the top, then the attempt's tree, then the index.
    assert!(once(&entry.join("p.txt")) < once(&entry));
    assert!(once(&entry) < once(&cache));
    let db = attempt.overlay_dir.join(ratarmount_compositing::HIDDEN_DB);
    assert!(once(&cache) < once(&db));
    assert!(once(&db) < once(&attempt.overlay_dir));
    assert!(once(&attempt.overlay_dir) < once(&tree));
    assert!(once(&tree) < once(&indexes));
    // The S3 ancestors: deepest first, each once, after the index.
    let mut ancestors: Vec<PathBuf> = [chain_of(&tree), chain_of(&indexes), chain_of(&entry)]
        .concat()
        .into_iter()
        .filter(|dir| dir != &cache)
        .collect();
    ancestors.sort();
    ancestors.dedup();
    let attempts = root.join("attempts");
    let mut positions: Vec<(usize, usize)> = ancestors
        .iter()
        .map(|dir| {
            let found = fsyncs_of(&events, &root, dir);
            // `attempts/` is synced again at R4.
            let expected = if dir == &attempts { 2 } else { 1 };
            assert_eq!(found.len(), expected, "{dir:?}: {events:#?}");
            (found[0], dir.components().count())
        })
        .collect();
    positions.sort();
    assert!(positions.iter().all(|(at, _)| *at > once(&indexes)));
    assert!(
        positions.windows(2).all(|pair| pair[0].1 >= pair[1].1),
        "deepest first: {positions:?}"
    );
    // Then the commit: the record, the rename, `retained/`, `attempts/`.
    let last_s3 = positions.last().unwrap().0;
    let append = at(&events, "append Retained $ROOT/retained.jsonl");
    let rename = at(&events, &format!("rename $ROOT/retained/{}", attempt.id));
    let retained = once(&root.join("retained"));
    let r4_attempts = fsyncs_of(&events, &root, &attempts)[1];
    assert!(last_s3 < append && append < rename, "{events:#?}");
    assert!(rename < retained && retained < r4_attempts, "{events:#?}");
    assert_eq!(r4_attempts, events.len() - 1, "{events:#?}");
    // A second retained attempt over the same entry syncs it again.
    let second = env.layered(&[&bundle], true);
    let before = env.sup.seams.syncs.len();
    env.finalize(&second.id, false, None).unwrap();
    assert!(env.sup.seams.syncs[before..].contains(&entry.join("p.txt")));
    assert!(env.sup.seams.syncs[before..].contains(&entry));
}

/// Regression (R1c-1 T20.4r, ruling 1+2 "every finalize", retain half): a
/// retained attempt's S syncs each lower (the cache entry under its lock),
/// the top, `attempts/ID`, `indexes/<base>/` and the ancestors before R4
/// syncs `retained/` and `attempts/`; a same-ID replay runs nothing; an
/// ID-less repeat walks `retained/ID` (never `attempts/ID`) and answers the
/// stored report byte for byte; the fast path syncs a refilled entry and
/// answers `lower_changed` for a purged one.
#[test]
fn regression_supervisor_retain_syncs_retained_tree() {
    if !linux() {
        return;
    }
    let mut env = Env::new();
    let directory = env.layer("Dir", &[], &[("d.txt", "d\n")]);
    let (_, bundle) = env.bundle_over("Bnd", &[&directory], &[("b.txt", "b\n")]);
    let xdg = env.dir().join("xdg");
    env.cache_at(&xdg);
    let _filled = env.layered(&[&directory, &bundle], false);
    let attempt = env.layered(&[&directory, &bundle], true);
    let entry = env.sup.taken_lowers[&attempt.id].clone().unwrap()[1]
        .path
        .clone();
    let tree = attempt.path.parent().unwrap().to_path_buf();
    let indexes = env.sup.root.join("indexes/task");
    let report = env.finalize(&attempt.id, false, Some("w")).unwrap();
    assert_eq!(report["status"], "retained");
    let synced = env.sup.seams.syncs.clone();
    let pos = |path: &Path| {
        synced
            .iter()
            .position(|p| p == path)
            .unwrap_or_else(|| panic!("{path:?} not synced: {synced:#?}"))
    };
    assert!(pos(&directory.join("d.txt")) < pos(&directory));
    assert!(pos(&directory) < pos(&entry.join("b.txt")));
    assert!(pos(&entry.join("b.txt")) < pos(&entry));
    assert!(pos(&entry) < pos(&attempt.overlay_dir));
    assert!(pos(&attempt.overlay_dir) < pos(&tree));
    assert!(pos(&tree) < pos(&indexes));
    assert_eq!(
        synced[synced.len() - 2..],
        [env.sup.root.join("retained"), env.sup.root.join("attempts")],
        "R4 last"
    );
    // A same-ID replay runs nothing.
    let replay = env.finalize(&attempt.id, false, Some("w")).unwrap();
    assert_eq!(
        serde_json::to_vec(&replay).unwrap(),
        serde_json::to_vec(&report).unwrap()
    );
    assert_eq!(env.sup.seams.syncs.len(), synced.len());
    // An ID-less repeat walks retained/ID.
    let kept = env.kept(&attempt.id);
    let again = env.finalize(&attempt.id, false, None).unwrap();
    assert_eq!(
        serde_json::to_vec(&again).unwrap(),
        serde_json::to_vec(&report).unwrap()
    );
    let resynced = env.sup.seams.syncs[synced.len()..].to_vec();
    for path in [
        directory.join("d.txt"),
        entry.join("b.txt"),
        kept.join("overlay").join(ratarmount_compositing::HIDDEN_DB),
        kept.join("overlay"),
        kept.clone(),
        env.sup.root.join("retained"),
        indexes.clone(),
    ] {
        assert!(resynced.contains(&path), "{path:?}: {resynced:#?}");
    }
    assert!(
        resynced.iter().all(|path| !path.starts_with(&tree)),
        "{resynced:#?}"
    );
    // The fast path syncs a refilled entry (a new inode at the same path).
    let old = fs::metadata(&entry).unwrap().ino();
    writable(&entry);
    fs::remove_dir_all(&entry).unwrap();
    let _refill = env.layered(&[&directory, &bundle], false);
    assert_ne!(fs::metadata(&entry).unwrap().ino(), old);
    let before = env.sup.seams.syncs.len();
    env.finalize(&attempt.id, false, None).unwrap();
    assert!(env.sup.seams.syncs[before..].contains(&entry.join("b.txt")));
    // Purged and not refilled: R1b's lower_changed from the re-read.
    writable(&entry);
    fs::remove_dir_all(&entry).unwrap();
    let error = env.finalize(&attempt.id, false, None).unwrap_err();
    assert_eq!(error.code, "lower_changed", "{}", error.message);
}

/// Regression (R1c-1 T20.6r, sweep 2 Codex B1, retain half): a retained
/// attempt over a bundle whose fill created the cache hierarchy syncs the
/// entry, `layers/` and every ancestor on that filesystem once; with an
/// ancestor `P` made unreadable after `new`, its finalize is refused at the
/// preflight naming `P`, before the stop: nothing sealed, no report, no
/// `retained` line and no rename; restored, it retains.
#[test]
fn regression_supervisor_retain_syncs_new_cache_ancestors() {
    if !linux() {
        return;
    }
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skip: mode bits do not refuse root");
        return;
    }
    let mut env = Env::new();
    let (_, bundle) = env.bundle("N", &[("n.txt", "n\n")]);
    let xdg = env.dir().join("xdg");
    let cache = xdg.join("ratarmount/layers");
    env.cache_at(&xdg);
    let attempt = env.layered(&[&bundle], true);
    assert!(env.sup.seams.syncs.is_empty(), "the fill syncs nothing");
    env.finalize(&attempt.id, false, None).unwrap();
    let synced = env.sup.seams.syncs.clone();
    for dir in std::iter::once(cache.clone()).chain(chain_of(&cache)) {
        assert_eq!(
            synced.iter().filter(|p| **p == dir).count(),
            1,
            "{dir:?} once: {synced:#?}"
        );
    }
    // P unreadable after `new`.
    let p = env.dir().join("p");
    fs::create_dir(&p).unwrap();
    env.cache_at(&p.join("cache"));
    let attempt = env.layered(&[&bundle], true);
    fs::set_permissions(&p, fs::Permissions::from_mode(0o300)).unwrap();
    let (stops, events) = (env.stops(), env.commit_events().len());
    let error = env.finalize(&attempt.id, false, None).unwrap_err();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(error.code, "invalid_request", "{}", error.message);
    assert!(
        error
            .message
            .contains(&format!("{} cannot be opened", p.display())),
        "{}",
        error.message
    );
    assert_eq!(env.stops(), stops, "refused before the stop");
    assert!(!sealed(&attempt.overlay_dir));
    assert_eq!(env.commit_events().len(), events);
    assert!(env.retained_lines_of(&attempt.id).is_empty());
    assert_eq!(
        env.finalize(&attempt.id, false, None).unwrap()["status"],
        "retained"
    );
}

/// Regression (R1c-1 T20.7r, ruling 6's second half, retain half): S
/// re-reads each lower's seal under its entry lock and checks the path still
/// names the locked inode; a lower resealed after the top was sealed over
/// it, or replaced by a byte-identical copy after S took its lock, answers
/// `lower_changed` with no fsync, no `retained` line and no rename; an
/// untouched lower is synced and the attempt retained.
#[test]
fn regression_supervisor_retain_rechecks_lower_identity_at_sync() {
    if !linux() {
        return;
    }
    // (i) Resealed after `finalize_top` returned.
    let mut env = Env::new();
    let a = env.layer("A", &[], &[("a.txt", "a\n")]);
    let b = env.layer("B", &[&a], &[("b.txt", "b\n")]);
    let attempt = env.layered(&[&a, &b], true);
    let recorded = record(&a);
    {
        let (a, base) = (a.clone(), env.base.clone());
        let token = env.token(env.view());
        env.sup.seams.before_sync = Some(Box::new(move || {
            ratarmount_compositing::overlay_seal::unseal(&a).unwrap();
            fs::write(a.join("a.txt"), "changed after the top was sealed\n").unwrap();
            let view: Arc<dyn ratarmount_core::MountSource> =
                Arc::new(FolderMountSource::new(&base).unwrap());
            ratarmount_compositing::overlay_fsck::fsck(&a, true).unwrap();
            ratarmount_compositing::overlay_seal::seal(&a, &token, view).unwrap();
        }));
    }
    let error = env.finalize(&attempt.id, false, None).unwrap_err();
    assert_eq!(error.code, "lower_changed", "{}", error.message);
    assert!(
        error.message.contains(&recorded.sealed_at),
        "{}",
        error.message
    );
    assert!(env.sup.seams.syncs.is_empty(), "no fsync at all");
    assert!(env.commit_events().is_empty());
    assert!(env.retained_lines_of(&attempt.id).is_empty());
    drop(env);

    // (ii) Replaced by a byte-identical copy after S took its lock.
    let mut env = Env::new();
    let a = env.layer("A", &[], &[("a.txt", "a\n")]);
    let attempt = env.layered(&[&a], true);
    {
        let a = a.clone();
        env.sup.seams.after_lower_lock = Some(Box::new(move |_| {
            let copy = a.with_file_name("A.copy");
            let status = std::process::Command::new("cp")
                .arg("-a")
                .arg(&a)
                .arg(&copy)
                .status()
                .unwrap();
            assert!(status.success());
            fs::rename(&a, a.with_file_name("A.aside")).unwrap();
            fs::rename(&copy, &a).unwrap();
        }));
    }
    let error = env.finalize(&attempt.id, false, None).unwrap_err();
    assert_eq!(error.code, "lower_changed", "{}", error.message);
    assert!(error.message.contains("replaced"), "{}", error.message);
    assert!(env.sup.seams.syncs.is_empty(), "no fsync at all");
    assert!(env.commit_events().is_empty());
    assert!(env.retained_lines_of(&attempt.id).is_empty());
    drop(env);

    // (iii) Untouched: synced and retained.
    let mut env = Env::new();
    let a = env.layer("A", &[], &[("a.txt", "a\n")]);
    let attempt = env.layered(&[&a], true);
    assert_eq!(
        env.finalize(&attempt.id, false, None).unwrap()["status"],
        "retained"
    );
    assert!(env
        .sup
        .seams
        .syncs
        .contains(&a.join(ratarmount_compositing::HIDDEN_DB)));
}

/// Regression (R1c-1 T26, Keystone approval note (a) across a restart): a
/// retained attempt still exists after a restart (kept, not served), so its
/// finalize records must stay pinned, never evicted to make room: with the
/// record cap filled by them a new request is `capacity` with nothing
/// written, before and after the restart, and with `retained.jsonl` moved
/// aside (a bare name pins by ID).
#[test]
fn regression_supervisor_retain_finalize_record_pinned_across_restart() {
    if !linux() {
        return;
    }
    let _limits = Limits::set(super::requests::Limits::new(3, 64 << 20, 4 << 20, 8 << 20).unwrap());
    let mut env = Env::new();
    let x = env.attempt(true, false);
    env.fake
        .0
        .lock()
        .unwrap()
        .stop_outcomes
        .push_back(StopOutcome::Busy);
    assert_eq!(
        env.finalize(&x.id, false, Some("F1")).unwrap_err().code,
        "writers_active"
    );
    assert_eq!(
        env.finalize(&x.id, false, Some("F2")).unwrap()["status"],
        "retained"
    );
    env.finalize(&x.id, false, Some("F3")).unwrap();
    let full = |env: &mut Env| {
        let (len, spawns) = (env.requests_len(), env.fake.0.lock().unwrap().spawns);
        let error = new_with_id(env, "N").unwrap_err();
        assert_eq!(error.code, "capacity", "{}", error.message);
        assert!(
            error.message.contains("finalize records"),
            "{}",
            error.message
        );
        assert_eq!(env.requests_len(), len);
        assert_eq!(env.fake.0.lock().unwrap().spawns, spawns);
        for request in ["F1", "F2", "F3"] {
            assert!(env.sup.requests.status(request).is_some(), "{request}");
        }
    };
    full(&mut env);
    let mut env = env.reopen();
    assert!(env.sup.retained.is_empty(), "kept, not served");
    full(&mut env);
    let aside = env.dir().join("aside.jsonl");
    fs::rename(env.sup.root.join(super::retained::NAME), &aside).unwrap();
    let mut env = env.reopen();
    assert!(env.sup.bare_retained.contains(&x.id));
    full(&mut env);
}

/// One `retained` record of `id` with a report padded by `pad` bytes.
fn retained_record(id: &str, pad: usize) -> super::retained::Retained {
    super::retained::Retained {
        id: id.into(),
        instance: "0123456789abcdef0123456789abcdef".into(),
        base: "task".into(),
        layer_digest: ratarmount_compositing::overlay_changes::EMPTY_SHA256.into(),
        sealed_at: "2026-11-02T00:00:00.000000000+00:00".into(),
        prefix: vec![],
        over: vec![],
        paths: super::retained::Paths {
            overlay: PathBuf::from(format!("/state/retained/{id}/overlay")),
            bundle: None,
        },
        report: json!({"pad": "p".repeat(pad)}),
    }
}

/// Regression (R1c-1 E2): `retained.jsonl` must be refused before
/// `reconcile` when it is a symlink, has a second link or is group-readable,
/// as `requests.jsonl` is.
#[test]
fn regression_state_log_retained_unsafe_file_refused_before_reconcile() {
    for case in ["symlink", "link", "mode"] {
        let state = private_tempdir();
        drop(Supervisor::open(state.path(), 8, Duration::from_secs(2), Fake::default()).unwrap());
        let log = state.path().join(super::retained::NAME);
        let stale = state.path().join("attempts/attempt-stale");
        fs::create_dir(&stale).unwrap();
        fs::set_permissions(&stale, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(stale.join("marker"), b"").unwrap();
        match case {
            "symlink" => {
                let target = state.path().join("elsewhere.jsonl");
                fs::write(&target, b"").unwrap();
                fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
                fs::remove_file(&log).unwrap();
                std::os::unix::fs::symlink(&target, &log).unwrap();
            }
            "link" => fs::hard_link(&log, state.path().join("second-link")).unwrap(),
            _ => fs::set_permissions(&log, fs::Permissions::from_mode(0o640)).unwrap(),
        }
        let error = Supervisor::open(state.path(), 8, Duration::from_secs(2), Fake::default())
            .err()
            .expect("refused");
        assert!(
            error.message.contains(super::retained::NAME),
            "{case}: {}",
            error.message
        );
        assert!(
            stale.join("marker").exists(),
            "{case}: refused before reconcile"
        );
    }
}

/// Regression (R1c-1 E2): replay must truncate a torn tail, refuse a damaged
/// middle line, an unknown `t` (a later release's) or `v` with the retained
/// advice; `aborted` ends a record, and compaction drops ended records while
/// keeping the live lines byte for byte.
#[test]
fn regression_state_log_retained_replay_and_compaction() {
    use super::retained::{RetainedLog, NAME};
    let dir = private_tempdir();
    let path = dir.path().join(NAME);
    let mut log = RetainedLog::open(dir.path()).unwrap();
    log.append_retained(&retained_record("attempt-000001", 10))
        .unwrap();
    log.append_retained(&retained_record("attempt-000002", 10))
        .unwrap();
    log.append_aborted("attempt-000001").unwrap();
    let live = log.live_lines();
    assert_eq!(live.len(), 1);
    assert!(log.live("attempt-000001").is_none());
    drop(log);
    // A torn tail is truncated.
    let len = fs::metadata(&path).unwrap().len();
    let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
    std::io::Write::write_all(&mut file, br#"{"v":1,"id":"attempt-000003","t":"reta"#).unwrap();
    drop(file);
    let log = RetainedLog::open(dir.path()).unwrap();
    assert_eq!(fs::metadata(&path).unwrap().len(), len);
    assert_eq!(log.live_lines(), live);
    assert!(log.live("attempt-000002").is_some());
    drop(log);
    // A damaged middle line, a later release's `t` or `v`: refused.
    let good = fs::read_to_string(&path).unwrap();
    for bad in [
        "{not json",
        r#"{"v":1,"id":"attempt-000004","t":"forgotten"}"#,
        r#"{"v":2,"id":"attempt-000004","t":"aborted"}"#,
        r#"{"v":1,"id":"attempt-000004","t":"aborted","extra":1}"#,
    ] {
        let bad_dir = private_tempdir();
        let bad_path = bad_dir.path().join(NAME);
        fs::write(&bad_path, format!("{bad}\n{good}")).unwrap();
        fs::set_permissions(&bad_path, fs::Permissions::from_mode(0o600)).unwrap();
        let error = RetainedLog::open(bad_dir.path()).err().expect("refused");
        assert!(
            error
                .message
                .contains("moving it aside keeps every retained/ tree"),
            "{bad}: {}",
            error.message
        );
    }
    // Compaction keeps only the live lines, byte for byte.
    let mut log = RetainedLog::open(dir.path()).unwrap();
    let mut last = String::new();
    for i in 0..40 {
        last = format!("filler-{i}");
        log.append_retained(&retained_record(&last, 60_000))
            .unwrap();
        log.append_aborted(&last).unwrap();
        if log.events.borrow().contains(&"compact") {
            break;
        }
    }
    assert!(log.events.borrow().contains(&"compact"));
    assert_eq!(log.live_lines(), live);
    // The live line first, byte for byte; after it at most the lines of the
    // filler whose append triggered the compaction.
    let file = fs::read(&path).unwrap();
    assert!(file.starts_with(&live[0]));
    let rest = String::from_utf8(file[live[0].len()..].to_vec()).unwrap();
    assert!(rest.lines().count() <= 2, "{}", rest.len());
    for line in rest.lines() {
        let value: Value = serde_json::from_str(line).unwrap();
        assert_eq!(value["id"], last.as_str());
    }
    drop(log);
    assert_eq!(RetainedLog::open(dir.path()).unwrap().live_lines(), live);
}

/// Regression (R1c-1 E2): a failed `retained.jsonl` append must leave memory
/// and the file as before when its truncation works, and `Broken` otherwise
/// (until a restart truncates the torn tail); a record over 64 KiB is
/// `capacity` with nothing written; its fault queue and events are its own,
/// never `requests.jsonl`'s.
#[test]
fn regression_state_log_retained_append_failures() {
    use super::retained::{RetainedLog, LINE_BOUND, NAME, TEST_FAULTS};
    use super::state_log::{Append, Fault};
    let dir = private_tempdir();
    let path = dir.path().join(NAME);
    TEST_FAULTS.with(|faults| faults.borrow_mut().push(Fault::Sync(Append::Retained)));
    let requests =
        super::requests::RequestLog::open(dir.path(), super::requests::limits()).unwrap();
    assert!(requests.faults.is_empty());
    let mut log = RetainedLog::open(dir.path()).unwrap();
    assert_eq!(log.faults, [Fault::Sync(Append::Retained)]);
    let len = fs::metadata(&path).unwrap().len();
    assert!(log
        .append_retained(&retained_record("attempt-000001", 10))
        .is_err());
    assert!(!log.broken());
    assert_eq!(fs::metadata(&path).unwrap().len(), len);
    assert!(log.live("attempt-000001").is_none());
    assert!(log.events.borrow().contains(&"append"));
    assert!(!requests.events.borrow().contains(&"append"));
    // Over 64 KiB: capacity, nothing written.
    let error = log
        .append_retained(&retained_record("attempt-000002", LINE_BOUND as usize))
        .unwrap_err();
    assert_eq!(error.code, "capacity", "{}", error.message);
    assert_eq!(fs::metadata(&path).unwrap().len(), len);
    // A write and its truncation fail: `Broken`.
    log.append_retained(&retained_record("attempt-000003", 10))
        .unwrap();
    let len = fs::metadata(&path).unwrap().len();
    log.faults
        .extend([Fault::Write(Append::Aborted), Fault::Truncate]);
    assert!(log.append_aborted("attempt-000003").is_err());
    assert!(log.broken());
    assert!(log.live("attempt-000003").is_some());
    let error = log.append_aborted("attempt-000003").unwrap_err();
    assert_eq!(error.code, "io", "{}", error.message);
    assert!(
        error.message.contains("retained log unavailable"),
        "{}",
        error.message
    );
    drop(log);
    let log = RetainedLog::open(dir.path()).unwrap();
    assert!(!log.broken());
    assert_eq!(fs::metadata(&path).unwrap().len(), len);
    assert!(log.live("attempt-000003").is_some());
}

/// A replay of the `requests.jsonl` in `dir`, opened from a copy: its live
/// lines.
fn replay_of(dir: &Path) -> Vec<Vec<u8>> {
    let copy = private_tempdir();
    fs::copy(
        dir.join(super::requests::NAME),
        copy.path().join(super::requests::NAME),
    )
    .unwrap();
    bare_log(copy.path()).live_lines()
}

/// Regression (R1c-1 sweep 1 Codex B1): replay kept every finalize record
/// while the run had evicted an unpinned one, so a restart evicted a `new`
/// record the run kept, and its retry started a second batch. Eviction is
/// now the same in both, pins unknown to replay: the run moves a pinned
/// record a new line would evict to the end of the window by appending its
/// line again. Memory equals a replay of the file after every step, through
/// pins, unpins, evictions, those re-appends, compaction and reopens.
#[test]
fn regression_request_log_replay_matches_the_run() {
    use super::requests::{RequestLog, Status, Target};
    // A record cap of 3 and R1a's compaction floor: nothing is compacted
    // until the last part, so the file keeps every evicted line.
    let limits = Limits::set(super::requests::Limits::new(3, 64 << 20, 4 << 20, 8 << 20).unwrap());
    let hash = format!("sha256:{}", "0".repeat(64));
    let target = |n: u8| Target {
        id: format!("attempt-00000{n}"),
        instance: format!("{n:032x}"),
    };
    let dir = private_tempdir();
    let check = |log: &RequestLog| assert_eq!(log.live_lines(), replay_of(dir.path()));
    let finalize = |log: &mut RequestLog, id: &str, target: &Target| {
        log.begin_finalize(id, &hash, target).unwrap();
        let busy = ApiError::new("writers_active", "busy");
        assert!(log.finish_finalize(id, &hash, target, Err(busy)).is_err());
    };
    let new = |log: &mut RequestLog, id: &str| {
        log.begin(id, &hash).unwrap();
        log.finish(id, &hash, Ok((vec![], json!([])))).unwrap();
    };
    let mut log = bare_log(dir.path());
    // Codex's case: F's target is gone when N3 evicts F.
    let x = target(1);
    log.pin(x.clone());
    finalize(&mut log, "F", &x);
    check(&log);
    log.unpin(&x);
    for id in ["N1", "N2", "N3"] {
        new(&mut log, id);
        check(&log);
    }
    assert_eq!(log.status("F"), None);
    assert_eq!(log.status("N1"), Some(Status::Done));
    let live = log.live_lines();
    drop(log);
    let mut log = bare_log(dir.path());
    assert_eq!(log.live_lines(), live, "a reopen keeps what the run kept");
    assert_eq!(log.status("N1"), Some(Status::Done));
    // A pinned record a new line would evict is moved, never evicted.
    let y = target(2);
    log.pin(y.clone());
    finalize(&mut log, "G", &y);
    check(&log);
    for id in ["N4", "N5", "N6"] {
        new(&mut log, id);
        check(&log);
    }
    assert_eq!(log.status("G"), Some(Status::Retryable));
    assert_eq!(log.status("N4"), None, "N6 evicted N4, not G");
    assert_eq!(log.status("N5"), Some(Status::Done));
    // A restart while G's target exists keeps G, and G's retry still lands.
    let live = log.live_lines();
    drop(log);
    let mut log = bare_log(dir.path());
    assert_eq!(log.live_lines(), live);
    log.pin(y.clone());
    finalize(&mut log, "G", &y);
    check(&log);
    assert!(!log.events.borrow().contains(&"compact"));
    // With the compaction floor lowered: once G's target is gone, G is
    // evicted in turn, and the compacted file still replays to memory.
    drop((log, limits));
    let _limits = Limits::set(super::requests::Limits::new(3, 64 << 20, 4 << 20, 1).unwrap());
    let mut log = bare_log(dir.path());
    log.pin(y.clone());
    for id in ["N7", "N8"] {
        new(&mut log, id);
        check(&log);
    }
    assert_eq!(log.status("G"), Some(Status::Retryable));
    log.unpin(&y);
    new(&mut log, "N9");
    check(&log);
    assert_eq!(log.status("G"), None);
    assert!(log.events.borrow().contains(&"compact"));
    let live = log.live_lines();
    drop(log);
    assert_eq!(bare_log(dir.path()).live_lines(), live);
}

/// Regression (sweep 5 review): `pin` while the pins are unknown (`None`,
/// every finalize record held between `open` and `set_pins`) must not narrow
/// the set to that one target, which would silently make every other
/// target's records evictable. Until `set_pins` a `new` that only evicting
/// a pinned record could admit is `capacity`; `pin` then narrows as usual.
#[test]
fn regression_request_log_pin_before_set_pins_keeps_everything_pinned() {
    use super::requests::{Pins, RequestLog, Status, Target};
    let _limits = Limits::set(super::requests::Limits::new(3, 64 << 20, 4 << 20, 1).unwrap());
    let dir = private_tempdir();
    let hash = format!("sha256:{}", "0".repeat(64));
    let target = |n: u8| Target {
        id: format!("attempt-00000{n}"),
        instance: format!("{n:032x}"),
    };
    let (x, y, z) = (target(1), target(2), target(3));
    let mut log = RequestLog::open(dir.path(), super::requests::limits()).unwrap();
    for (id, target) in [("F", &x), ("G", &y), ("H", &z)] {
        log.begin_finalize(id, &hash, target).unwrap();
        let busy = ApiError::new("writers_active", "busy");
        assert!(log.finish_finalize(id, &hash, target, Err(busy)).is_err());
    }
    // `pin` under unknown pins holds every record: `N` is `capacity`, never
    // "G or H evicted".
    log.pin(x.clone());
    let error = log.begin("N", &hash).unwrap_err();
    assert_eq!(error.code, "capacity", "{}", error.message);
    // `set_pins` then installs the real set: `N` fits by evicting `G`, the
    // oldest record its targets do not name; `F` (pinned) is moved, `H`
    // (unpinned) is not reached.
    log.set_pins(Pins {
        targets: [x].into_iter().collect(),
        ids: Default::default(),
    });
    log.begin("N", &hash).unwrap();
    log.finish("N", &hash, Ok((vec![], json!([])))).unwrap();
    assert_eq!(log.status("F"), Some(Status::Retryable));
    assert_eq!(log.status("G"), None);
    assert_eq!(log.status("H"), Some(Status::Retryable));
}

const HOT_POINT: &str = "hot_journal";

/// The child of the hot-journal test: a write transaction on the overlay
/// database `KILL_STATE` that spills its cache (so the journal is synced and
/// uncommitted pages reach the database file), then `KILL_MARKER`, then it
/// waits to be killed.
fn hot_journal_writer() {
    let db = PathBuf::from(std::env::var_os(KILL_STATE).unwrap());
    let marker = PathBuf::from(std::env::var_os(KILL_MARKER).unwrap());
    let conn = rusqlite::Connection::open(&db).unwrap();
    conn.execute_batch(
        "PRAGMA cache_size = 2; BEGIN IMMEDIATE; CREATE TABLE killed_writer(x BLOB); \
         INSERT INTO killed_writer VALUES (zeroblob(400000));",
    )
    .unwrap();
    fs::write(&marker, b"paused").unwrap();
    std::thread::sleep(Duration::from_secs(60));
    panic!("the parent should have killed this child");
}

/// Regression (R1c-1 sweep 1 Claude B1): an attempt whose mount process was
/// killed mid-write left a hot journal in its top's database, and finalize
/// read the top without recovery, so every try answered `io` and the
/// attempt could only be destroyed. Finalize now reads it as fsck does: the
/// unsealed top's journal is rolled back (the killed write is gone), and the
/// attempt is sealed.
#[test]
fn regression_supervisor_finalize_rolls_back_a_killed_writers_journal() {
    if std::env::var(KILL_POINT).as_deref() == Ok(HOT_POINT) {
        return hot_journal_writer();
    }
    if !linux() {
        return;
    }
    let mut env = Env::new();
    let attempt = env.attempt(false, false);
    let db = attempt.overlay_dir.join(ratarmount_compositing::HIDDEN_DB);
    let marker = env.dir().join("marker");
    let processes = ratarmount_index::test_process::spawning();
    kill_at(
        "sandbox::finalize_tests::regression_supervisor_finalize_rolls_back_a_killed_writers_journal",
        HOT_POINT,
        &db,
        &marker,
    );
    drop(processes);
    let _processes = ratarmount_index::test_process::exclusive();
    let journal = PathBuf::from(format!("{}-journal", db.display()));
    assert!(journal.is_file(), "the killed writer left its journal");
    assert!(
        OverlayMeta::read_no_recovery(&attempt.overlay_dir).is_err(),
        "a hot journal"
    );
    let report = env.finalize(&attempt.id, false, Some("h")).unwrap();
    assert_eq!(report["status"], "finalized", "{report}");
    assert_eq!(report["patch_hash"]["files"], 2, "{report}");
    assert!(!journal.exists());
    assert!(sealed(&attempt.overlay_dir));
    let conn = rusqlite::Connection::open_with_flags(
        &db,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap();
    let tables: i64 = conn
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE name = 'killed_writer'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(tables, 0, "the killed write was rolled back");
}

/// Regression (R1c-1 sweep 1 Codex B2): a top database another connection
/// held (`BEGIN EXCLUSIVE`) after the stop was answered `io` ("is in use"),
/// because the metadata read lost the lock's classification. It is
/// `writers_active`, nothing is sealed, the request stays `retryable`, and
/// the same request ID finalizes once the holder is gone.
#[test]
fn regression_supervisor_finalize_locked_top_database_is_writers_active() {
    if !linux() {
        return;
    }
    let mut env = Env::new();
    let attempt = env.attempt(false, false);
    let db = attempt.overlay_dir.join(ratarmount_compositing::HIDDEN_DB);
    let holder = rusqlite::Connection::open(&db).unwrap();
    holder.execute_batch("BEGIN EXCLUSIVE").unwrap();
    let error = env.finalize(&attempt.id, false, Some("l")).unwrap_err();
    assert_eq!(error.code, "writers_active", "{}", error.message);
    assert!(error.message.contains("in use"), "{}", error.message);
    assert_eq!(
        env.sup.requests.status("l"),
        Some(super::requests::Status::Retryable)
    );
    drop(holder);
    assert!(!sealed(&attempt.overlay_dir));
    let report = env.finalize(&attempt.id, false, Some("l")).unwrap();
    assert_eq!(report["status"], "finalized", "{report}");
    assert!(sealed(&attempt.overlay_dir));
}

/// Every entry below `dir`, symlinks unfollowed: its mode and a file's
/// bytes or a symlink's target.
fn tree_state(dir: &Path) -> std::collections::BTreeMap<PathBuf, (u32, Vec<u8>)> {
    let mut entries = std::collections::BTreeMap::new();
    for child in fs::read_dir(dir).unwrap() {
        let path = child.unwrap().path();
        let meta = fs::symlink_metadata(&path).unwrap();
        let content = if meta.file_type().is_symlink() {
            fs::read_link(&path)
                .unwrap()
                .into_os_string()
                .into_encoded_bytes()
        } else if meta.is_dir() {
            entries.extend(tree_state(&path));
            Vec::new()
        } else {
            fs::read(&path).unwrap()
        };
        entries.insert(path, (meta.mode(), content));
    }
    entries
}

/// Regression (PR #251 review round 1, Keystone (4)): `classify_gate_compose`
/// mapped its metadata read with `io::Error::other`, so a top database that
/// another connection took after fsck answered `io` instead of
/// `writers_active`; so did the read after the outputs. Both use `meta_error`
/// now (the gate's own error is never a busy database: it compares the
/// metadata already read). Busy at the gate read: `writers_active`, and
/// nothing changed from that read on (the top is not sealed, its tree is as it
/// was, no manifest or bundle), the request stays `retryable`, and the same
/// request ID finalizes once the holder is gone. Busy at the report read
/// (sealed and packed by then): `writers_active` too, and the retry resumes
/// without packing again. The stop ran before both reads, so the attempt is
/// `finalizing`.
#[test]
fn regression_supervisor_finalize_busy_database_after_fsck_is_writers_active() {
    use std::cell::RefCell;
    use std::rc::Rc;
    if !linux() {
        return;
    }
    let mut env = Env::new();
    for point in ["gate", "report"] {
        let attempt = env.attempt(false, false);
        let root = attempt.path.parent().unwrap().to_path_buf();
        let db = attempt.overlay_dir.join(ratarmount_compositing::HIDDEN_DB);
        // The hook takes the database at `point`, after a snapshot of the top.
        let holder: Rc<RefCell<Option<rusqlite::Connection>>> = Rc::default();
        let before = Rc::new(RefCell::new(None));
        let (held, seen, top) = (holder.clone(), before.clone(), attempt.overlay_dir.clone());
        env.sup.seams.before_meta_read = Some(Box::new(move |at| {
            if at == point {
                *seen.borrow_mut() = Some(tree_state(&top));
                // Sealed by the report read, the database is read-only: open
                // it writable and restore its mode, as `overlay_seal`'s
                // busy-unseal test does.
                let mode = fs::metadata(&db).unwrap().permissions().mode();
                fs::set_permissions(&db, fs::Permissions::from_mode(mode | 0o200)).unwrap();
                let conn = rusqlite::Connection::open(&db).unwrap();
                fs::set_permissions(&db, fs::Permissions::from_mode(mode)).unwrap();
                conn.execute_batch("BEGIN EXCLUSIVE").unwrap();
                *held.borrow_mut() = Some(conn);
            }
        }));
        let request = format!("busy-{point}");
        let error = env.finalize(&attempt.id, true, Some(&request)).unwrap_err();
        assert!(
            holder.borrow().is_some(),
            "{point}: the hook took the database"
        );
        assert_eq!(error.code, "writers_active", "{point}: {}", error.message);
        assert!(
            error.message.contains("its database is busy"),
            "{point}: {}",
            error.message
        );
        assert_eq!(
            env.sup.requests.status(&request),
            Some(super::requests::Status::Retryable),
            "{point}"
        );
        assert_eq!(env.status(&attempt.id), "finalizing", "{point}");
        let bundle = root.join("bundle.tar.zst");
        drop(holder.borrow_mut().take());
        if point == "gate" {
            assert_eq!(
                tree_state(&attempt.overlay_dir),
                before.borrow_mut().take().unwrap(),
                "nothing changed from the gate read on"
            );
            assert!(!sealed(&attempt.overlay_dir));
            for output in ["manifest.jsonl", "bundle.tar.zst"] {
                assert!(!root.join(output).exists(), "{output}");
            }
            assert!(!env.sup.attempt_state[&attempt.id].finalize.progress.packed);
        } else {
            assert!(sealed(&attempt.overlay_dir));
            assert!(env.sup.attempt_state[&attempt.id].finalize.progress.packed);
        }
        let packed = fs::metadata(&bundle)
            .ok()
            .map(|m| (m.ino(), m.mtime_nsec()));
        let report = env.finalize(&attempt.id, true, Some(&request)).unwrap();
        assert_eq!(report["status"], "finalized", "{point}: {report}");
        assert_eq!(report["bundle"], json!(bundle), "{point}");
        assert!(sealed(&attempt.overlay_dir));
        if let Some(packed) = packed {
            let again = fs::metadata(&bundle).unwrap();
            assert_eq!(packed, (again.ino(), again.mtime_nsec()), "packed once");
        }
    }
}

const REAL_MOUNTS_CHILD: &str = "RATARMOUNT_SANDBOX_REAL_MOUNTS_CHILD";
const T17_REAL_MOUNTS: &str =
    "sandbox::finalize_tests::regression_supervisor_finalize_sync_poison_real_mounts";

/// Runs `mount` (or `umount`) with `args` inside the test's namespace.
fn run_mount(program: &str, args: &[&std::ffi::OsStr]) {
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{program} {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The production filesystem probe against S's allowlist (ext2/3/4, xfs,
/// btrfs, tmpfs), with the type in the refusal.
fn allowlist(fd: std::os::fd::BorrowedFd<'_>, path: &Path) -> Result<(), String> {
    let kind = super::daemon::fs_type(fd).map_err(|e| e.to_string())?;
    if [0xEF53, 0x5846_5342, 0x9123_683E, 0x0102_1994].contains(&kind) {
        Ok(())
    } else {
        Err(format!(
            "{} is on filesystem type {kind:#x}",
            path.display()
        ))
    }
}

/// `sync_tree` over `tree` with the filesystem check `filesystem`: its
/// refusal and the paths it synced first.
fn sync_with(
    tree: &Path,
    filesystem: &dyn Fn(std::os::fd::BorrowedFd<'_>, &Path) -> Result<(), String>,
) -> (Result<(), crate::overlay_pack::SyncError>, Vec<PathBuf>) {
    let fd = crate::overlay_pack::open_root(tree).unwrap();
    let mut synced = Vec::new();
    let mut fsync = |_: std::os::fd::BorrowedFd<'_>, path: &Path| {
        synced.push(path.to_path_buf());
        Ok(())
    };
    let result = crate::overlay_pack::sync_tree(
        &fd,
        tree,
        &mut crate::overlay_pack::SyncChecks {
            filesystem,
            device: &|_, real| real,
            read_only: false,
            fsync: &mut fsync,
            before_open: None,
        },
    );
    (result, synced)
}

/// T17's real-mount rows, run as root of a private user and mount
/// namespace (`unshare -Urm`), each printing `row (x) passed` or why it
/// was skipped.
fn real_mount_rows() {
    use std::ffi::OsStr;
    let os = |path: &Path| path.as_os_str().to_owned();
    let mut env = Env::new();
    let root = env.dir();
    let test_device = dev(&root);
    let shm = Path::new("/dev/shm");
    let shm_tmpfs = crate::overlay_pack::open_root(shm).is_ok_and(|fd| {
        use std::os::fd::AsFd;
        super::daemon::fs_type(fd.as_fd()).is_ok_and(|kind| kind == 0x0102_1994)
    });
    let shm_ok = shm_tmpfs && dev(shm) != test_device;
    let shm_dir = tempfile::Builder::new().tempdir_in(shm).unwrap();
    let shm_root = shm_dir.path().to_path_buf();
    // A supervisor whose mount table is the kernel's (this namespace's).
    let state = root.join("state");
    let mut sup = Supervisor::open(
        &state,
        8,
        Duration::from_secs(2),
        super::process::ProcessMounter::new(PathBuf::from("/nonexistent/ratarmount")),
    )
    .unwrap();
    let tree_with = |name: &str, files: &[&str]| {
        let tree = root.join(name);
        fs::create_dir(&tree).unwrap();
        for file in files {
            fs::write(tree.join(file), format!("{file}\n")).unwrap();
        }
        tree
    };
    let overlay = |name: &str, lower: &Path, upper: &Path, work: &Path, xino_off: bool| {
        let merged = root.join(name);
        for dir in [upper, work, &merged] {
            fs::create_dir_all(dir).unwrap();
        }
        let mut options = format!(
            "lowerdir={},upperdir={},workdir={}",
            lower.display(),
            upper.display(),
            work.display()
        );
        if xino_off {
            options.push_str(",xino=off");
        }
        run_mount(
            "mount",
            &[
                OsStr::new("-t"),
                OsStr::new("overlay"),
                OsStr::new("overlay"),
                OsStr::new("-o"),
                OsStr::new(&options),
                &os(&merged),
            ],
        );
        merged
    };
    let skip = |row: &str| {
        println!(
            "skip: row {row} needs /dev/shm on tmpfs, on another device than {}",
            root.display()
        )
    };

    // (a) A lower-only file on another device under overlayfs.
    if shm_ok {
        let lower = shm_root.join("a-lower");
        fs::create_dir_all(lower.join("sub")).unwrap();
        fs::write(lower.join("only.txt"), b"lower only\n").unwrap();
        fs::write(lower.join("sub/deep.txt"), b"deep\n").unwrap();
        let merged = overlay(
            "a-merged",
            &lower,
            &root.join("a-up"),
            &root.join("a-work"),
            true,
        );
        // The kernel reports the lower-only file on another device than its
        // directory: tmpfs's own, or (newer kernels) a per-layer device.
        let file = fs::symlink_metadata(merged.join("only.txt")).unwrap().dev();
        println!(
            "(a): file st_dev {file}, merged directory {}, tmpfs lower {}",
            dev(&merged),
            dev(&lower)
        );
        assert_ne!(
            file,
            dev(&merged),
            "the file is on another device than its directory"
        );
        let error = sup.lowers_preflight([merged.as_path()]).unwrap_err();
        assert_eq!(error.code, "invalid_request", "{}", error.message);
        assert!(error.message.contains("overlayfs"), "{}", error.message);
        let (result, synced) = sync_with(&merged, &|_, _| Ok(()));
        match result {
            Err(crate::overlay_pack::SyncError::Mismatch(message)) => {
                assert!(message.contains("only.txt"), "{message}");
                assert!(message.contains(&file.to_string()), "{message}");
            }
            other => panic!("(a): {other:?}"),
        }
        assert!(synced.is_empty(), "{synced:?}");
        run_mount("umount", &[&os(&merged)]);
        println!("row (a) passed");
    } else {
        skip("(a)");
    }

    // (b) Uniform devices with lower-only files: the device check alone
    // passes; the type check refuses.
    let lower = tree_with("b-lower", &["only.txt"]);
    let merged = overlay(
        "b-merged",
        &lower,
        &root.join("b-up"),
        &root.join("b-work"),
        false,
    );
    let device = dev(&merged);
    assert_eq!(
        fs::symlink_metadata(merged.join("only.txt")).unwrap().dev(),
        device
    );
    let error = sup.lowers_preflight([merged.as_path()]).unwrap_err();
    assert!(error.message.contains("overlayfs"), "{}", error.message);
    let (result, synced) = sync_with(&merged, &allowlist);
    match result {
        Err(crate::overlay_pack::SyncError::Mismatch(message)) => {
            assert!(message.contains("0x794c7630"), "{message}")
        }
        other => panic!("(b): {other:?}"),
    }
    assert!(synced.is_empty(), "{synced:?}");
    run_mount("umount", &[&os(&merged)]);
    println!("row (b) passed");

    // (c) A file bind-mounted into a tree on an allowed filesystem.
    if shm_ok {
        let tree = tree_with("c-tree", &["a.txt", "f.txt"]);
        let source = shm_root.join("c-source.txt");
        fs::write(&source, b"elsewhere\n").unwrap();
        run_mount(
            "mount",
            &[OsStr::new("--bind"), &os(&source), &os(&tree.join("f.txt"))],
        );
        assert_ne!(dev(&tree.join("f.txt")), dev(&tree));
        fs::set_permissions(&tree, fs::Permissions::from_mode(0o555)).unwrap();
        let error = sup.lowers_preflight([tree.as_path()]).unwrap_err();
        assert_eq!(error.code, "invalid_request", "{}", error.message);
        assert!(
            error.message.contains("has a mount inside it"),
            "{}",
            error.message
        );
        let (result, synced) = sync_with(&tree, &allowlist);
        match result {
            Err(crate::overlay_pack::SyncError::Mismatch(message)) => {
                assert!(message.contains("f.txt"), "{message}")
            }
            other => panic!("(c): {other:?}"),
        }
        assert!(!synced.contains(&tree.join("f.txt")), "{synced:?}");
        run_mount("umount", &[&os(&tree.join("f.txt"))]);
        fs::set_permissions(&tree, fs::Permissions::from_mode(0o755)).unwrap();
        println!("row (c) passed");
    } else {
        skip("(c)");
    }

    // (d) An overlayfs file that reports the tree's device, bind-mounted
    // into it: only its own fstatfs refuses it.
    if shm_ok {
        let lower = tree_with("d-lower", &["only.txt"]);
        let merged = overlay(
            "d-merged",
            &lower,
            &shm_root.join("d-up"),
            &shm_root.join("d-work"),
            true,
        );
        let file_device = dev(&merged.join("only.txt"));
        println!("(d): overlayfs file st_dev {file_device}, test directory {test_device}");
        let tree = tree_with("d-tree", &["a.txt", "f.txt"]);
        run_mount(
            "mount",
            &[
                OsStr::new("--bind"),
                &os(&merged.join("only.txt")),
                &os(&tree.join("f.txt")),
            ],
        );
        // Where the file reports the tree's device (older kernels report a
        // lower-only file's real device), only its own fstatfs can refuse it;
        // where it reports a per-layer device, the device check refuses it
        // first. Either way it is refused before its fsync.
        let same_device = dev(&tree.join("f.txt")) == dev(&tree);
        fs::set_permissions(&tree, fs::Permissions::from_mode(0o555)).unwrap();
        let error = sup.lowers_preflight([tree.as_path()]).unwrap_err();
        assert!(
            error.message.contains("has a mount inside it"),
            "{}",
            error.message
        );
        let (result, synced) = sync_with(&tree, &allowlist);
        match result {
            Err(crate::overlay_pack::SyncError::Mismatch(message)) => {
                assert!(message.contains("f.txt"), "{message}");
                if same_device {
                    assert!(message.contains("0x794c7630"), "{message}");
                }
                println!(
                    "(d): refused by the {} check: {message}",
                    if same_device { "type" } else { "device" }
                );
            }
            other => panic!("(d): {other:?}"),
        }
        // The type check alone, as where the devices agree: the device
        // override reports the tree's device for the file.
        let tree_device = dev(&tree);
        let fd = crate::overlay_pack::open_root(&tree).unwrap();
        let mut fsync = |_: std::os::fd::BorrowedFd<'_>, _: &Path| Ok(());
        let typed = crate::overlay_pack::sync_tree(
            &fd,
            &tree,
            &mut crate::overlay_pack::SyncChecks {
                filesystem: &allowlist,
                device: &|_, _| tree_device,
                read_only: false,
                fsync: &mut fsync,
                before_open: None,
            },
        );
        match typed {
            Err(crate::overlay_pack::SyncError::Mismatch(message)) => {
                assert!(
                    message.contains("f.txt") && message.contains("0x794c7630"),
                    "{message}"
                )
            }
            other => panic!("(d) type check: {other:?}"),
        }
        assert!(!synced.contains(&tree.join("f.txt")), "{synced:?}");
        run_mount("umount", &[&os(&tree.join("f.txt"))]);
        run_mount("umount", &[&os(&merged)]);
        fs::set_permissions(&tree, fs::Permissions::from_mode(0o755)).unwrap();
        println!("row (d) passed");
    } else {
        skip("(d)");
    }

    // (e) A lower that is itself a mount point: a tmpfs holding a copy of a
    // sealed layer is accepted, and S syncs its files, its root, then its
    // parent on the test directory's filesystem.
    let layer = env.layer("E", &[], &[("e.txt", "e\n")]);
    let lower = root.join("e-lower");
    fs::create_dir(&lower).unwrap();
    run_mount(
        "mount",
        &[
            OsStr::new("-t"),
            OsStr::new("tmpfs"),
            OsStr::new("-o"),
            OsStr::new("mode=0755"),
            OsStr::new("tmpfs"),
            &os(&lower),
        ],
    );
    let status = std::process::Command::new("cp")
        .arg("-a")
        .arg(format!("{}/.", layer.display()))
        .arg(&lower)
        .status()
        .unwrap();
    assert!(status.success());
    fs::set_permissions(&lower, fs::metadata(&layer).unwrap().permissions()).unwrap();
    assert_ne!(dev(&lower), test_device);
    sup.lowers_preflight([lower.as_path()]).unwrap();
    let attempt_root = state.join("attempts/attempt-e");
    let attempt = Attempt {
        id: "attempt-e".into(),
        base: "task".into(),
        path: attempt_root.join("mnt"),
        overlay_dir: attempt_root.join("overlay"),
        status: "finalizing".into(),
    };
    let indexes = state.join("indexes/task");
    for dir in [&attempt.path, &attempt.overlay_dir, &indexes] {
        fs::create_dir_all(dir).unwrap();
    }
    sup.sync_step(&attempt, &attempt_root, &indexes, &[record(&lower)])
        .unwrap();
    let synced = &sup.seams.syncs;
    let at = |path: &Path| {
        synced
            .iter()
            .position(|p| p == path)
            .unwrap_or_else(|| panic!("{path:?} not synced: {synced:#?}"))
    };
    assert!(at(&lower.join("e.txt")) < at(&lower));
    assert!(at(&lower) < at(&root), "then its parent");
    writable(&lower);
    run_mount("umount", &[&os(&lower)]);
    println!("row (e) passed");
    drop(sup);
    env.sup.seams.syncs.clear();
}

/// Regression (R1c-1 T17 real mounts, ruling 6; opt-in
/// `RATARMOUNT_TEST_OVERLAYFS=1`): the device and type checks were proved
/// only through overrides, never against what the kernel reports. In a
/// private user and mount namespace: (a) a lower-only overlayfs file on
/// another device is refused by the preflight (overlayfs) and, with the type
/// check admitting overlayfs, by `sync_tree`'s device check before its
/// fsync; (b) with uniform devices only the type check refuses it; (c) a
/// bind-mounted file is refused by the preflight's mount check and by the
/// device check; (d) an overlayfs file reporting the tree's device is
/// refused by the mount check and by its own `fstatfs`; (e) a lower that is
/// itself a tmpfs mount is accepted and synced, then its parent.
#[test]
fn regression_supervisor_finalize_sync_poison_real_mounts() {
    if std::env::var_os(REAL_MOUNTS_CHILD).is_some() {
        return real_mount_rows();
    }
    if !linux() {
        return;
    }
    if std::env::var_os("RATARMOUNT_TEST_OVERLAYFS").is_none() {
        eprintln!("skip: set RATARMOUNT_TEST_OVERLAYFS=1 for T17's real-mount rows (unprivileged user namespaces)");
        return;
    }
    let namespaces = std::process::Command::new("unshare")
        .args(["-Urm", "true"])
        .status()
        .is_ok_and(|status| status.success());
    if !namespaces {
        eprintln!("skip: unprivileged user and mount namespaces are unavailable (unshare -Urm)");
        return;
    }
    let _processes = ratarmount_index::test_process::spawning();
    let output = std::process::Command::new("unshare")
        .args(["-Urm", "--"])
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", T17_REAL_MOUNTS, "--nocapture"])
        .env(REAL_MOUNTS_CHILD, "1")
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    eprintln!("{text}");
    assert!(output.status.success(), "{text}");
    for row in ["(a)", "(b)", "(c)", "(d)", "(e)"] {
        assert!(
            text.contains(&format!("row {row} passed"))
                || text.contains(&format!("skip: row {row}")),
            "{row}: {text}"
        );
    }
}

/// A private directory under the workspace's `target/`, a disk filesystem
/// (unlike `/tmp`, often tmpfs, where fsync costs nothing), for timings.
fn disk_dir() -> tempfile::TempDir {
    let target = Path::new(env!("CARGO_MANIFEST_DIR")).join("../target");
    fs::create_dir_all(&target).unwrap();
    tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(target)
        .unwrap()
}

/// The filesystem type of `path`, for the timing lines.
fn fs_name(path: &Path) -> String {
    use std::os::fd::AsFd;
    let fd = crate::overlay_pack::open_root(path).unwrap();
    match super::daemon::fs_type(fd.as_fd()).unwrap() {
        0xEF53 => "ext4".into(),
        0x5846_5342 => "xfs".into(),
        0x9123_683E => "btrfs".into(),
        0x0102_1994 => "tmpfs".into(),
        other => format!("{other:#x}"),
    }
}

/// Timing for the PR (Risk 4): one finalize of an attempt over a 128 MiB
/// TAR base, whose worker top records `pending`, so the seal hashes the
/// whole archive in the serve loop.
#[test]
#[ignore = "timing for the PR: cargo test -p ratarmount --bin ratarmount finalize_timing_tar_base -- --ignored --nocapture"]
fn finalize_timing_tar_base() {
    let disk = disk_dir();
    let mut env = Env::new_in(disk.path());
    let source = disk.path().join("base.tar");
    fs::write(&source, tar_bytes(&vec![7u8; 128 << 20])).unwrap();
    let attempt = env.archive_attempt("tar", &source);
    let started = std::time::Instant::now();
    let report = env.finalize(&attempt.id, false, None).unwrap();
    println!(
        "timing: finalize of an attempt over a 128 MiB TAR base on {}: {:?} (base_digest_state {})",
        fs_name(disk.path()),
        started.elapsed(),
        report["patch_hash"]["base_digest_state"]
    );
}

/// Timing for the PR (Risk 2): one finalize over a prepared lower of
/// 10,000 files, its step S timed on its own.
#[test]
#[ignore = "timing for the PR: cargo test -p ratarmount --bin ratarmount finalize_timing_sync_10k_files -- --ignored --nocapture"]
fn finalize_timing_sync_10k_files() {
    let disk = disk_dir();
    let mut env = Env::new_in(disk.path());
    let files: Vec<(String, String)> = (0..10_000)
        .map(|i| (format!("d{:02}/f{i:05}.txt", i % 100), format!("{i}\n")))
        .collect();
    let refs: Vec<(&str, &str)> = files
        .iter()
        .map(|(a, b)| (a.as_str(), b.as_str()))
        .collect();
    let lower = env.layer(disk.path().join("L").to_str().unwrap(), &[], &refs);
    let attempt = env.layered(&[&lower], false);
    let s_started = Arc::new(std::sync::Mutex::new(None));
    {
        let s_started = s_started.clone();
        env.sup.seams.before_sync = Some(Box::new(move || {
            *s_started.lock().unwrap() = Some(std::time::Instant::now());
        }));
    }
    let started = std::time::Instant::now();
    env.finalize(&attempt.id, false, None).unwrap();
    let s = s_started.lock().unwrap().unwrap().elapsed();
    println!(
        "timing: finalize over a 10,000-file lower on {}: {:?} in all, step S {:?} ({} fsyncs)",
        fs_name(&lower),
        started.elapsed(),
        s,
        env.sup.seams.syncs.len()
    );
}

/// Timing for the PR: a start with 4,096 retained entries (kept, not
/// served).
#[test]
#[ignore = "timing for the PR: cargo test -p ratarmount --bin ratarmount retained_start_timing_4096 -- --ignored --nocapture"]
fn retained_start_timing_4096() {
    let disk = disk_dir();
    let state = disk.path().join("state");
    drop(Supervisor::open(&state, 8, Duration::from_secs(2), Fake::default()).unwrap());
    {
        let mut log = super::retained::RetainedLog::open(&state).unwrap();
        for i in 0..4096 {
            let id = format!("attempt-{i:06}");
            log.append_retained(&retained_record(&id, 3000)).unwrap();
            fs::create_dir_all(state.join("retained").join(&id).join("overlay")).unwrap();
        }
    }
    let started = std::time::Instant::now();
    let sup = Supervisor::open(&state, 8, Duration::from_secs(2), Fake::default()).unwrap();
    let elapsed = started.elapsed();
    assert_eq!(sup.retained_log.live_ids().count(), 4096);
    println!(
        "timing: a start with 4,096 retained entries on {}: {elapsed:?}",
        fs_name(&state)
    );
}

/// Regression (R1c-1 sweep 1 Claude N3): on 32-bit glibc `f_type` is an
/// `i32`, so a magic with the top bit set (btrfs) arrived sign-extended and
/// never matched the allowlist. The magic is the low 32 bits.
#[test]
fn regression_supervisor_fs_magic_keeps_32_bit_magics() {
    use super::daemon::fs_magic;
    for magic in [
        0x9123_683Eu32,
        0xEF53,
        0x5846_5342,
        0x0102_1994,
        0x794c_7630,
    ] {
        assert_eq!(
            fs_magic(i64::from(magic as i32)),
            i64::from(magic),
            "{magic:#x} from an i32"
        );
        assert_eq!(fs_magic(i64::from(magic)), i64::from(magic), "{magic:#x}");
    }
}

/// Regression (R1c-1 sweep 1 Claude N4): `new` with `retain` and a bundle
/// lower was refused ("Too many levels of symbolic links") when the cache
/// root was a symlink whose `ratarmount/layers` did not exist yet, although
/// the child follows the symlink and finalize syncs the resolved path. The
/// preflight checks the resolved directory.
#[test]
fn regression_supervisor_retain_preflight_follows_a_symlinked_cache_root() {
    if !linux() {
        return;
    }
    let mut env = Env::new();
    let (_, bundle) = env.bundle("B", &[("b.txt", "b\n")]);
    let real = env.dir().join("real-cache");
    fs::create_dir(&real).unwrap();
    let link = env.dir().join("cache-link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    env.cache_at(&link);
    let attempt = env.layered(&[&bundle], true);
    let entry = env.sup.taken_lowers[&attempt.id].clone().unwrap()[0]
        .path
        .clone();
    assert!(entry.starts_with(&real), "{entry:?}");
    let report = env.finalize(&attempt.id, false, None).unwrap();
    assert_eq!(report["status"], "retained", "{report}");
    assert!(env.sup.seams.syncs.contains(&entry));
}

/// Regression (sweep 3 review): a bundle cache path that is not UTF-8 — a
/// `XDG_CACHE_HOME`/`HOME` value, or a symlink it resolves through — made
/// the `retained` record of the retain preflight fail to serialize, and the
/// `expect` in `Retained::line` panicked the whole daemon (every live
/// attempt's child died with it). `new` with `retain` and a bundle lower
/// now refuses it with `invalid_request`, existing or not, before anything
/// starts, and the next request is still answered.
#[test]
fn regression_supervisor_retain_non_utf8_cache_path() {
    if !linux() {
        return;
    }
    use std::os::unix::ffi::OsStrExt;
    let mut env = Env::new();
    let (_, bundle) = env.bundle("B", &[("b.txt", "b\n")]);
    let cache = env.dir().join(std::ffi::OsStr::from_bytes(b"cache-\xff"));
    env.sup.seams.cache_root = Some(cache.clone());
    // A cache root that does not exist yet: the check still sees the path
    // the record would name (its deepest existing ancestor is UTF-8).
    let spawns = env.fake.0.lock().unwrap().spawns;
    for request_id in [None, Some("nonutf8")] {
        let error = env
            .new_v2("task", &[&bundle], Overlay::Disk, true, request_id)
            .unwrap_err();
        assert_eq!(error.code, "invalid_request", "{}", error.message);
        assert!(error.message.contains("UTF-8"), "{}", error.message);
        nothing_started(&env, spawns);
    }
    assert_eq!(
        env.sup.requests.status("nonutf8"),
        Some(super::requests::Status::Retryable)
    );
    // An existing non-UTF-8 cache directory resolves to a non-UTF-8 path.
    fs::create_dir_all(cache.join("ratarmount/layers")).unwrap();
    let error = env
        .new_v2("task", &[&bundle], Overlay::Disk, true, None)
        .unwrap_err();
    assert_eq!(error.code, "invalid_request", "{}", error.message);
    assert!(error.message.contains("UTF-8"), "{}", error.message);
    nothing_started(&env, spawns);
    // The supervisor is unaffected: the next request is answered.
    env.new_v2("task", &[], Overlay::Disk, true, None).unwrap();
}

/// Regression (sweep 4 review): a relative `XDG_CACHE_HOME` — the real repro
/// held the bytes `cache-\xff` — whose path exists nowhere below the working
/// directory the daemon runs with left the ancestor walk without an existing
/// ancestor, so the preflight substituted `/` for it, `strip_prefix("/")`
/// failed and the record position became `/`: the filesystem, UTF-8 and
/// record-size checks inspected the root instead of the configured path, and
/// `new` with `retain` created the cache and spawned the worker, which then
/// failed `mount_failed` on the non-UTF-8 cache path. The cache path is made
/// absolute first and `new` answers `invalid_request` before anything is
/// created or spawned.
#[test]
fn regression_supervisor_retain_absent_relative_cache_path() {
    if !linux() {
        return;
    }
    use std::os::unix::ffi::OsStrExt;
    let mut env = Env::new();
    let (_, bundle) = env.bundle("B", &[("b.txt", "b\n")]);
    env.sup.seams.cache_root = Some(PathBuf::from(std::ffi::OsStr::from_bytes(b"cache-\xff")));
    let spawns = env.fake.0.lock().unwrap().spawns;
    let error = env
        .new_v2("task", &[&bundle], Overlay::Disk, true, Some("relcache"))
        .unwrap_err();
    assert_eq!(error.code, "invalid_request", "{}", error.message);
    assert!(error.message.contains("UTF-8"), "{}", error.message);
    nothing_started(&env, spawns);
    assert_eq!(
        env.sup.requests.status("relcache"),
        Some(super::requests::Status::Retryable)
    );
}

/// Regression: a missing cache component followed by `..` made preflight
/// inspect the wrong filesystem, then the worker created the component and
/// filled a cache on a refused filesystem. Refuse before spawn or creation.
#[test]
fn regression_supervisor_retain_unresolved_cache_parent_is_refused() {
    if !linux() {
        return;
    }
    let mut env = Env::new();
    let (_, bundle) = env.bundle("B", &[("b.txt", "b\n")]);
    let missing = env.dir().join("missing");
    let refused = env.dir().join("overlay-view");
    fs::create_dir(&refused).unwrap();
    env.sup
        .seams
        .fs_types
        .borrow_mut()
        .insert(refused.clone(), 0x794c_7630);
    env.cache_at(&missing.join("../overlay-view/cache"));
    let spawns = env.fake.0.lock().unwrap().spawns;
    for request in [None, Some("parent-cache")] {
        let error = env
            .new_v2("task", &[&bundle], Overlay::Disk, true, request)
            .unwrap_err();
        assert_eq!(error.code, "invalid_request", "{}", error.message);
        assert!(error.message.contains(".."), "{}", error.message);
        nothing_started(&env, spawns);
        assert!(!missing.exists());
        assert!(!refused.join("cache").exists());
    }
    assert_eq!(
        env.sup.requests.status("parent-cache"),
        Some(super::requests::Status::Retryable)
    );
    // Once the component exists, `..` belongs to the resolved prefix. Its
    // actual destination must be checked, then the same retry can proceed.
    fs::create_dir(&missing).unwrap();
    let error = env
        .new_v2(
            "task",
            &[&bundle],
            Overlay::Disk,
            true,
            Some("parent-cache"),
        )
        .unwrap_err();
    assert_eq!(error.code, "invalid_request", "{}", error.message);
    assert!(error.message.contains("overlayfs"), "{}", error.message);
    nothing_started(&env, spawns);
    env.sup.seams.fs_types.borrow_mut().clear();
    env.new_v2(
        "task",
        &[&bundle],
        Overlay::Disk,
        true,
        Some("parent-cache"),
    )
    .unwrap();
    let expected = refused
        .canonicalize()
        .unwrap()
        .join("cache/ratarmount/layers");
    assert_eq!(
        env.fake
            .0
            .lock()
            .unwrap()
            .specs
            .last()
            .unwrap()
            .bundle_cache
            .as_ref(),
        Some(&expected)
    );
}

/// Regression: a symlink inside the configured cache path could make the
/// worker use a different cache than the one preflight checked and sized.
/// Pass the one resolved directory through the sandbox child interface.
#[test]
fn regression_supervisor_retain_uses_the_preflighted_cache_path() {
    if !linux() {
        return;
    }
    let mut env = Env::new();
    let (_, bundle) = env.bundle("B", &[("b.txt", "b\n")]);
    let xdg = env.dir().join("xdg");
    fs::create_dir_all(xdg.join("ratarmount")).unwrap();
    let real = env.dir().join("cache-real");
    let other = env.dir().join("cache-other");
    fs::create_dir(&real).unwrap();
    fs::create_dir(&other).unwrap();
    let link = xdg.join("ratarmount/layers");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    env.cache_at(&xdg);
    let changed_link = link.clone();
    let changed_target = other.clone();
    env.fake.0.lock().unwrap().before_capture = Some(Box::new(move || {
        fs::remove_file(&changed_link).unwrap();
        std::os::unix::fs::symlink(&changed_target, &changed_link).unwrap();
    }));
    let attempt = env.layered(&[&bundle], true);
    let canonical = real.canonicalize().unwrap();
    let recorded = env.sup.taken_lowers[&attempt.id].clone().unwrap();
    assert!(recorded[0].path.starts_with(&canonical));
    assert_eq!(fs::read_dir(&other).unwrap().count(), 0);
    let state = env.fake.0.lock().unwrap();
    assert_eq!(
        state.specs.last().unwrap().bundle_cache.as_ref(),
        Some(&canonical)
    );
    drop(state);
    let spec = super::process::SpawnSpec {
        lowers: std::slice::from_ref(&bundle),
        bundle_cache: Some(&canonical),
        ..Default::default()
    };
    let argv = super::process::mount_args(
        env.sup.base("task").unwrap(),
        &env.sup.indexes("task"),
        &attempt,
        &spec,
    );
    let parsed =
        crate::parse_args_from(std::iter::once(std::ffi::OsString::from("ratarmount")).chain(argv))
            .unwrap();
    assert_eq!(
        parsed.sandbox_bundle_cache.as_deref(),
        Some(canonical.as_path())
    );
    let report = env.finalize(&attempt.id, false, None).unwrap();
    assert_eq!(report["status"], "retained");
    assert_eq!(
        env.retained_lines_of(&attempt.id).last().unwrap()["prefix"][0]["path"],
        json!(recorded[0].path)
    );
}

/// Regression (sweep 4 review): `widest_report` is the hand-kept estimate the
/// record preflight uses for the `retained.jsonl` line an attempt would
/// write. If a field the real report grows is missing or narrower there,
/// `new` admits a stack whose commit then refuses `capacity` on every try:
/// the attempt can never be retained. The stored report of a real retain —
/// with a journal and a bundle, its widest shapes — must serialize no larger
/// than the estimate built for its stack.
#[test]
fn regression_supervisor_retain_report_fits_the_preflight_estimate() {
    if !linux() {
        return;
    }
    let mut env = Env::new();
    let attempt = env.attempt(true, true);
    fs::write(
        attempt.path.parent().unwrap().join("journal.jsonl"),
        "{\"journal\":1}\n{\"op\":\"read\",\"path\":\"/f\",\"ts\":1,\"bytes\":9}\n",
    )
    .unwrap();
    let report = env.finalize(&attempt.id, true, None).unwrap();
    assert_eq!(report["status"], "retained", "{report}");
    let entry = &env.sup.retained[&attempt.id];
    let widest = super::retained::widest_report(&entry.attempt, &env.kept(&attempt.id));
    let real = serde_json::to_vec(&entry.report).unwrap().len();
    let estimate = serde_json::to_vec(&widest).unwrap().len();
    assert!(real <= estimate, "real report {real} > estimate {estimate}");
    // A Git base's `git-tree:` + 64 digits is the widest `patch_hash.base`
    // (2 bytes wider than `sha256:`), and must fit the same estimate.
    let mut git = entry.report.clone();
    git["patch_hash"]["base"] = json!(format!("git-tree:{}", "f".repeat(64)));
    let real = serde_json::to_vec(&git).unwrap().len();
    assert!(
        real <= estimate,
        "git-base report {real} > estimate {estimate}"
    );
}

/// Regression (R1c-1 sweep 1 Claude N5): a lower removed after step 3 was
/// answered `io` by S's first device read, where S's lock step answers
/// R1b's `lower_changed`; it is `lower_changed` naming the lower, before
/// any fsync.
#[test]
fn regression_supervisor_finalize_lower_removed_before_sync_is_lower_changed() {
    if !linux() {
        return;
    }
    let mut env = Env::new();
    let a = env.layer("A", &[], &[("a.txt", "a\n")]);
    let attempt = env.layered(&[&a], false);
    {
        let (a, aside) = (a.clone(), a.with_file_name("A.aside"));
        env.sup.seams.before_sync = Some(Box::new(move || fs::rename(&a, &aside).unwrap()));
    }
    let error = env.finalize(&attempt.id, false, None).unwrap_err();
    assert_eq!(error.code, "lower_changed", "{}", error.message);
    assert!(
        error.message.contains(a.to_str().unwrap()),
        "{}",
        error.message
    );
    assert!(env.sup.seams.syncs.is_empty());
}

/// Regression (R1c-1 sweep 1 Claude N6): a try that packed and then failed
/// a later phase left its bundle unreported when the next try did not ask
/// for `pack` (`bundle: null` in the report and the retained record, while
/// the bundle was synced and moved with the attempt). It is reported once
/// packed, with and without `retain`.
#[test]
fn regression_supervisor_finalize_reports_an_earlier_tries_bundle() {
    if !linux() {
        return;
    }
    for retain in [false, true] {
        let mut env = Env::new();
        let attempt = env.attempt(retain, false);
        let root = attempt.path.parent().unwrap().to_path_buf();
        // The manifest write fails after a successful pack.
        fs::create_dir(root.join("manifest.jsonl")).unwrap();
        let error = env.finalize(&attempt.id, true, None).unwrap_err();
        assert_eq!(error.code, "io", "{}", error.message);
        assert!(env.sup.attempt_state[&attempt.id].finalize.progress.packed);
        fs::remove_dir(root.join("manifest.jsonl")).unwrap();
        let report = env.finalize(&attempt.id, false, None).unwrap();
        let tree = if retain {
            env.kept(&attempt.id)
        } else {
            root.clone()
        };
        let bundle = tree.join("bundle.tar.zst");
        assert_eq!(report["bundle"], json!(bundle), "{retain}: {report}");
        assert!(bundle.is_file());
        // The bundle was synced where it was packed, before any rename.
        assert!(env.sup.seams.syncs.contains(&root.join("bundle.tar.zst")));
        if retain {
            let line = env.retained_lines_of(&attempt.id).pop().unwrap();
            assert_eq!(line["paths"]["bundle"], json!(bundle));
        }
    }
}
