//! `finalize_top`: the tail that `sandbox run` and the supervisor's
//! `finalize` share (R1c-1 §5.3). In `sandbox run`'s order: fsck; classify,
//! gate, then compose and seal under the top's overlay root flock; pack; then
//! the canonical hash, the manifest and the journal summary.
//!
//! Classifying and gating come before composing, so a changed base is refused
//! with the gate's text before any bundle lower is copied or verified. When
//! sealing, all of phase 2 runs under the top's overlay root flock
//! (`SealOperation`'s contract): seal takes only that flock and then its
//! database transaction, never an archive lock.

use ratarmount_compositing::overlay_changes::{self, ChangeOptions, Normalize};
use ratarmount_compositing::overlay_seal::{SealOperation, SealOutcome};
use ratarmount_compositing::{overlay_fsck, ClassifiedBase, OverlayMeta};
use ratarmount_core::MountSource;
use serde_json::{json, Value};
use std::fs::{self, File};
use std::io::{self, BufReader};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

/// What a finalize keeps across its tries, updated as each phase completes so
/// it survives an error from a later phase. `sandbox run` passes a fresh one;
/// the supervisor keeps one per attempt. (R1c-2 adds the first try's fsck
/// `repaired:N` here.)
#[derive(Clone, Debug, Default)]
pub struct FinalizeProgress {
    /// Set the moment `pack` returned `Ok`: a later try never packs onto its
    /// own bundle (`pack` publishes with `persist_noclobber`).
    pub packed: bool,
}

/// How phase 1 runs fsck.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Repair {
    /// `sandbox run`: repair, as before (its top is never sealed here).
    Always,
    /// The supervisor: repair unless an earlier try sealed the top, which is
    /// then checked read-only (fsck refuses to repair a sealed overlay).
    UnlessSealed,
}

/// The bundle to pack and the journal it includes.
pub struct Pack<'a> {
    /// As given; made absolute right before packing.
    pub bundle: &'a Path,
    pub journal: Option<&'a Path>,
}

/// One `finalize_top` call. `classify` gets the top's metadata and returns
/// the classified base; `compose` gets that base's source and returns the view
/// the layer is sealed and hashed over.
pub struct FinalizeTop<'a> {
    pub top: &'a Path,
    pub repair: Repair,
    pub classify: &'a mut dyn FnMut(Option<&OverlayMeta>) -> io::Result<ClassifiedBase>,
    pub compose: &'a mut dyn FnMut(Arc<dyn MountSource>) -> io::Result<Arc<dyn MountSource>>,
    /// A supplied strong base digest for the gate (`--base-digest`).
    pub base_digest: Option<String>,
    /// Seal, waiting for the top's overlay root flock until the deadline
    /// (`Some(None)` waits as `SealOperation::acquire` does).
    pub seal: Option<Option<Instant>>,
    pub pack: Option<Pack<'a>>,
    /// The manifest to write (overwritten).
    pub manifest: &'a Path,
    /// The journal to summarize and the summary to write (overwritten).
    pub journal: Option<(&'a Path, &'a Path)>,
    /// Test seam: runs before each metadata read after fsck, with its name
    /// (`"gate"`, then `"report"`).
    #[cfg(test)]
    pub before_meta_read: Option<ReadHook>,
}

/// What a report reads off a finalized top.
pub struct Finalized {
    pub fsck_result: String,
    /// The canonical hash of the change set (`Normalize::Strict`).
    pub patch: String,
    pub files: usize,
    /// The top's metadata after the outputs were written.
    pub meta: OverlayMeta,
    pub manifest: PathBuf,
    pub journal_summary: Option<Value>,
    pub bundle: Option<PathBuf>,
    /// The seal's outcome, when sealing (an earlier try's seal is reported
    /// as `already_sealed`).
    pub seal: Option<SealOutcome>,
}

impl Finalized {
    /// `sandbox run`'s `patch_hash` object, which the supervisor reports too.
    pub fn patch_hash(&self) -> Value {
        let meta = &self.meta;
        json!({"patch":self.patch, "base":meta.known_base_digest(), "stack":meta.stack_digest(), "files":self.files, "normalize":"strict", "algo":"sha256", "excludes":[], "sealed":meta.layer_sealed(), "base_pending":meta.base_digest_kind() == Some("pending"), "base_digest_state":meta.base_digest_state()})
    }
}

/// An overlay-metadata error as `fsck` reports one: a database another
/// process holds is `WouldBlock` (the supervisor answers `writers_active`).
fn meta_error(error: ratarmount_compositing::OverlayError) -> io::Error {
    if error.is_locked() {
        io::Error::new(io::ErrorKind::WouldBlock, error.to_string())
    } else {
        io::Error::other(error)
    }
}

/// Phase 1: fsck, which must be clean. Its own function: the R1c-2 seam for
/// keeping a first try's `repaired:N` in [`FinalizeProgress`].
fn check(top: &Path, repair: Repair) -> io::Result<String> {
    let repair = match repair {
        Repair::Always => true,
        // The read that fsck makes: an unsealed, writable top's hot journal
        // (a mount process killed mid-write) is rolled back, as `fsck(top,
        // true)` would; a sealed top's is refused and never written.
        Repair::UnlessSealed => !OverlayMeta::read(top)
            .map_err(meta_error)?
            .is_some_and(|meta| meta.layer_sealed()),
    };
    let fsck = overlay_fsck::fsck(top, repair)?;
    if !fsck.is_clean() {
        return Err(io::Error::other(format!("fsck: {}", fsck.result())));
    }
    Ok(fsck.result())
}

/// Classify, gate, then compose: the gate's refusal comes before any bundle
/// lower is resolved.
fn classify_gate_compose(
    request: &mut FinalizeTop<'_>,
) -> io::Result<(ClassifiedBase, Arc<dyn MountSource>)> {
    #[cfg(test)]
    if let Some(hook) = request.before_meta_read.as_mut() {
        hook("gate");
    }
    let recorded = OverlayMeta::read(request.top).map_err(meta_error)?;
    let base = (request.classify)(recorded.as_ref())?;
    // The gate's error is its text and is never a busy database, so it stays
    // `io` (a refusal included): it compares the metadata read above, and the
    // only database it opens is the base's prepared index, which a read-only
    // index (the supervisor's) opens immutable, taking no locks, while any
    // other index's digest-cache read failure is ignored.
    crate::overlay_cmd::gate_base(
        request.top,
        recorded.as_ref(),
        &base,
        &crate::overlay_cmd::BaseIdentityArgs {
            force_base_mismatch: false,
            base_digest: request.base_digest.clone(),
        },
    )
    .map_err(io::Error::other)?;
    let lower = (request.compose)(base.source())?;
    Ok((base, lower))
}

/// Finalizes `request.top` (R1c-1 §5.3); `progress` survives a failed try.
pub fn finalize_top(
    mut request: FinalizeTop<'_>,
    progress: &mut FinalizeProgress,
) -> io::Result<Finalized> {
    let top = request.top;
    let fsck_result = check(top, request.repair)?;
    // The base is classified through the factory and gated against what the
    // overlay recorded BEFORE anything is sealed or packed: a base edited
    // during the run fails closed instead of being sealed as if unchanged.
    let (lower, seal) = match request.seal {
        Some(deadline) => {
            let operation = SealOperation::acquire_until(top, deadline)?;
            let earlier = operation.finish_if_sealed()?;
            let (base, lower) = classify_gate_compose(&mut request)?;
            let outcome = match earlier {
                Some(outcome) => outcome,
                None => operation.seal(&base, lower.clone())?,
            };
            (lower, Some(outcome))
        }
        None => (classify_gate_compose(&mut request)?.1, None),
    };
    let bundle = request
        .pack
        .as_ref()
        .map(|pack| std::path::absolute(pack.bundle))
        .transpose()?;
    if let (Some(pack), Some(bundle)) = (&request.pack, &bundle) {
        if !progress.packed {
            crate::overlay_pack::pack(
                top,
                bundle,
                lower.clone(),
                &crate::overlay_pack::PackOptions {
                    include_journal: pack.journal.map(Path::to_path_buf),
                    ..Default::default()
                },
            )?;
            progress.packed = true;
        }
    }
    let options = ChangeOptions {
        normalize: Normalize::Strict,
        ..Default::default()
    };
    let changes = overlay_changes::change_set(top, lower, &options)?;
    let patch = overlay_changes::canonical_hash(&changes, &options)?;
    let manifest = request.manifest;
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-B0131-M01","item":"ratarmount::sandbox::finalize::finalize_top","disposition":"output-owner","mode_policy":"unchanged-from-e6ca64e","category":"output-owner","reason":"Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"unchanged-from-e6ca64e","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###
    )]
    overlay_changes::write_manifest(&changes, &mut File::create(manifest)?)?;
    #[cfg(test)]
    if let Some(hook) = request.before_meta_read.as_mut() {
        hook("report");
    }
    let meta = OverlayMeta::read(top)
        .map_err(meta_error)?
        .ok_or_else(|| io::Error::other("overlay metadata missing"))?;
    let journal_summary = match request.journal {
        Some((journal, path)) => {
            #[expect(
                clippy::disallowed_methods,
                reason = r###"internal-read:v1 {"id":"IR-B0132-M01","item":"ratarmount::sandbox::finalize::finalize_top","disposition":"out-of-family","category":"structured-control-record","reason":"operation journal JSONL summarized after the run","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
            )]
            let summary =
                crate::journal_cmd::summarize(BufReader::new(File::open(journal)?), None, None)?;
            #[expect(
                clippy::disallowed_methods,
                reason = r###"internal-read:v1 {"id":"IR-B0133-M01","item":"ratarmount::sandbox::finalize::finalize_top","disposition":"output-owner","mode_policy":"unchanged-from-e6ca64e","category":"output-owner","reason":"Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"unchanged-from-e6ca64e","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###
            )]
            serde_json::to_writer(File::create(path)?, &summary)?;
            Some(
                json!({"path":path, "files_read":summary.files_read.len(), "files_read_then_written":summary.files_read_then_written.len(), "files_written_blind":summary.files_written_blind.len()}),
            )
        }
        None => None,
    };
    Ok(Finalized {
        fsck_result,
        patch,
        files: changes.len(),
        meta,
        manifest: manifest.to_path_buf(),
        journal_summary,
        bundle,
        seal,
    })
}

// ---------------------------------------------------------------------------
// The supervisor's `finalize` (R1c-1 §5.4–§5.6).

use super::daemon::{io_error, Supervisor};
use super::lowers;
use super::process::{Mounter, StopOutcome};
use super::protocol::{ApiError, Attempt, Base, OperationV2};
use super::requests::{self, Status, Target};
use ratarmount_compositing::LowerLayerRecord;
use std::collections::BTreeSet;
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::fs::MetadataExt;
use std::time::Duration;

type ApiResult<T> = std::result::Result<T, ApiError>;

/// The filesystem types whose fsync finalize relies on (§5.5): ext2/3/4,
/// xfs, btrfs, and tmpfs, which has no storage to lose.
const EXT4: i64 = 0xEF53;
const XFS: i64 = 0x5846_5342;
const BTRFS: i64 = 0x9123_683E;
const TMPFS: i64 = 0x0102_1994;
/// What the probe answers off Linux; the allowlist refuses it.
pub const UNKNOWN_FS: i64 = -1;

fn allowed(kind: i64) -> bool {
    matches!(kind, EXT4 | XFS | BTRFS | TMPFS)
}

fn fs_name(kind: i64) -> String {
    match kind {
        EXT4 => "ext2/3/4".into(),
        XFS => "xfs".into(),
        BTRFS => "btrfs".into(),
        TMPFS => "tmpfs".into(),
        0x794c_7630 => "overlayfs".into(),
        0x6573_5546 => "FUSE".into(),
        0x6969 => "NFS".into(),
        0x7371_7368 => "squashfs".into(),
        0xE0F5_E1E2 => "erofs".into(),
        0x9660 => "iso9660".into(),
        0x2fc1_2fc1 => "ZFS".into(),
        0xF2F5_2010 => "f2fs".into(),
        0xca45_1a4e => "bcachefs".into(),
        UNKNOWN_FS => "an unknown filesystem".into(),
        other => format!("a filesystem of type {other:#x}"),
    }
}

/// Why `path`'s filesystem is refused.
fn off_allowlist(path: &Path, kind: i64) -> String {
    format!(
        "{} is on {}, whose fsync finalize cannot rely on (overlayfs skips files that exist only in a lower layer, FUSE may drop it, and nothing syncs the image file behind a read-only image such as squashfs); keep the state directory, the bundle cache and every lower, and the directory each one sits in, on ext4, xfs, btrfs or tmpfs (inside a container, a volume mounted at or above that directory)",
        path.display(),
        fs_name(kind)
    )
}

fn invalid(message: impl Into<String>) -> ApiError {
    ApiError::new("invalid_request", message)
}

pub(super) fn lower_changed(message: impl Into<String>) -> ApiError {
    let message = message.into();
    ApiError::new(
        "lower_changed",
        lowers::excerpt(&message, lowers::MESSAGE_BYTES),
    )
}

fn writers_active(message: impl Into<String>) -> ApiError {
    ApiError::new("writers_active", message)
}

fn poisoned_error(path: &Path) -> ApiError {
    ApiError::new(
        "io",
        format!(
            "a sync on the filesystem of {} failed earlier in this daemon run, so its data may be lost; every finalize on it is refused until the daemon restarts, and a restart discards every attempt that is not retained; check the storage first",
            path.display()
        ),
    )
}

fn fsync_failed(path: &Path, error: &io::Error) -> ApiError {
    ApiError::new(
        "io",
        format!(
            "cannot sync {}: {error}; its filesystem may have lost data, so every finalize on it is refused until the daemon restarts, and a restart discards every attempt that is not retained; check the storage first",
            path.display()
        ),
    )
}

/// The writable-node refusal of step S1(a) and the preflight.
fn writable_lower(lower: &Path, node: &Path) -> ApiError {
    lower_changed(format!(
        "lower {} has a writable {}, so it is not a completely published or sealed layer; run `ratarmount overlay seal {}`, which finishes an interrupted seal or publication by restoring its sentinel and read-only modes, then retry",
        lower.display(),
        node.display(),
        lower.display()
    ))
}

/// A test hook given a path.
#[cfg(test)]
pub type PathHook = Box<dyn FnOnce(&Path)>;
/// A test hook given each path it is reached for.
#[cfg(test)]
pub type PathsHook = Box<dyn Fn(&Path)>;
/// A test hook given the name of each metadata read it runs before.
#[cfg(test)]
pub type ReadHook = Box<dyn FnMut(&str)>;
/// A test hook given each commit point's name.
#[cfg(test)]
pub type PointHook = Box<dyn FnMut(&str)>;
/// Test seams of the supervisor's finalize; each is `#[cfg(test)]`.
#[cfg(test)]
#[derive(Default)]
pub struct Seams {
    /// Pretend the host is not Linux (ruling 7).
    pub not_linux: bool,
    /// The filesystem type a path reports (otherwise its `fstatfs`); shared,
    /// so a hook can switch it between steps.
    pub fs_types: std::rc::Rc<std::cell::RefCell<std::collections::BTreeMap<PathBuf, i64>>>,
    /// The device a path reports (otherwise its `st_dev`): the entry of
    /// its longest prefix, so a whole tree can report one device.
    pub devices: std::collections::BTreeMap<PathBuf, u64>,
    /// An errno the fsync of a path fails with.
    pub fsync_errors: std::collections::BTreeMap<PathBuf, i32>,
    /// An errno the directory open of a path fails with (step S's lower
    /// parents and chain directories, and R4).
    pub open_errors: std::collections::BTreeMap<PathBuf, i32>,
    /// The bundle cache root the retain preflight reads (else from the
    /// environment, which parallel tests share).
    pub cache_root: Option<PathBuf>,
    /// Runs once after `finalize_top` returned, before step S.
    pub before_sync: Option<Box<dyn FnOnce()>>,
    /// `FinalizeTop::before_meta_read` of the next `finalize_top` call.
    pub before_meta_read: Option<ReadHook>,
    /// Runs once after S took a lower's entry lock, before its re-check.
    pub after_lower_lock: Option<PathHook>,
    /// Runs between a regular file's listing and its open in step S.
    pub before_open: Option<PathsHook>,
    /// Every fsync of step S and the commit, with its path, in order.
    pub syncs: Vec<PathBuf>,
    /// Runs at each commit point (`after_sync`, `after_record`,
    /// `after_rename`, `after_acknowledge`).
    pub commit_points: Option<PointHook>,
}

/// One tree the durability rule judges: its root and, for the attempt's
/// own tree, the mount point the stop removes.
struct Tree<'a> {
    path: &'a Path,
    lower: bool,
    mnt: Option<&'a Path>,
    /// Refuse a mount strictly below the root (not for `attempts/` at a
    /// `new` with `retain`, which holds the live attempts' mount points).
    mounts: bool,
}

/// Classifies the supervisor's base for finalize (§5.4 step 6) and the gated
/// `diff`: the offline journal rule first, as every offline verb applies it
/// (a pending commit journal is refused), then the factory with `open_base`'s
/// options, no index rebuild, the Git reference pinned.
pub(super) fn classify_supervised(
    base: &Base,
    indexes: &Path,
) -> std::result::Result<ClassifiedBase, String> {
    ratarmount_compositing::journal_recovery::check_offline_journal(Path::new(&base.source))
        .map_err(|e| e.to_string())?;
    let mut options = super::daemon::base_open_options(base, indexes);
    let mut opener = crate::base_identity::FactoryOpener::new(
        vec![base.source.clone()],
        vec![PathBuf::from(&base.source)],
        &mut options,
        false,
        Default::default(),
        Default::default(),
        true,
    );
    ClassifiedBase::open(&mut opener)
}

/// Which operation a scope refusal names.
#[derive(Clone, Copy)]
pub(super) enum Scope {
    Finalize,
    Retain,
}

impl Scope {
    fn name(self) -> &'static str {
        match self {
            Self::Finalize => "finalize",
            Self::Retain => "retain",
        }
    }
}

/// The base and archive rules of the scope preflight (§5.5, ruling 4): a
/// local base without binds or recursion and without `git_synthetic_head`;
/// a regular-file source must be a TAR archive by its prepared index's
/// `backendName`. Directory and Git sources need no index. Retain refuses
/// a local source it cannot stat before creating an attempt; a Git URL is
/// an alias rather than a pathname.
pub(super) fn scope_preflight(base: &Base, indexes: &Path, scope: Scope) -> ApiResult<()> {
    let name = &base.name;
    lowers::check_base_for(base, scope.name())?;
    if base.options.git_synthetic_head {
        return Err(invalid(format!(
            "base {name} has git_synthetic_head, which {} does not support; register the base without git_synthetic_head to finalize or retain it",
            scope.name()
        )));
    }
    let source = Path::new(&base.source);
    let is_git = matches!(scope, Scope::Retain)
        && ratarmount_formats_git::parse_git_url(&base.source)
            .ok()
            .flatten()
            .is_some();
    let metadata = if is_git {
        None
    } else {
        match fs::metadata(source) {
            Ok(metadata) => Some(metadata),
            Err(error) if matches!(scope, Scope::Retain) => {
                return Err(invalid(format!(
                    "base {name} source {} cannot be inspected for retain: {error}",
                    source.display()
                )))
            }
            Err(_) => None,
        }
    };
    if metadata.is_some_and(|meta| meta.is_file()) {
        let tar_only = "finalize and retain support TAR archives only";
        let index = match ratarmount_index::resolve_prepared_index_location(
            source,
            None,
            &[indexes.to_path_buf()],
        ) {
            Ok(ratarmount_index::IndexLocation::Path(index)) => index,
            _ => {
                return Err(invalid(format!(
                    "base {name} has no prepared index; {tar_only}"
                )))
            }
        };
        let backend = ratarmount_index::SqliteIndex::open_lookup(&index)
            .and_then(|index| index.backend_name())
            .map_err(|e| {
                invalid(format!(
                    "base {name} has no prepared index ({} cannot be read: {e}); {tar_only}",
                    index.display()
                ))
            })?;
        match backend.as_deref() {
            Some(ratarmount_formats_tar::BACKEND_NAME) => {}
            Some(other) => {
                return Err(invalid(format!(
                    "base {name} is indexed by {other}, not as a TAR archive; {tar_only}"
                )))
            }
            None => return Err(invalid(format!("base {name} has no TAR index; {tar_only}"))),
        }
    }
    Ok(())
}

impl<M: Mounter> Supervisor<M> {
    /// How long finalize waits for a child, a lock or a deadline: the
    /// smaller of `--timeout` and 10 s.
    fn finalize_wait(&self) -> Duration {
        self.timeout.min(Duration::from_secs(10))
    }

    /// v2 `finalize` (§5.4 steps 0 and 1, and R1a's request-ID layer).
    pub(super) fn finalize(
        &mut self,
        id: String,
        pack: bool,
        request_id: Option<String>,
    ) -> ApiResult<Value> {
        // Step 0: the platform rule answers first, then the ID is validated,
        // all before anything is resolved or recorded.
        self.platform_rule()?;
        super::daemon::validate_name(&id)?;
        let Some(request_id) = request_id else {
            let target = self.resolve_target(&id)?;
            return self.finalize_target(&target, pack);
        };
        super::daemon::validate_name(&request_id).map_err(|_| {
            invalid("request_id must start with an ASCII letter or digit, then letters, digits, dot, underscore or hyphen (max 128)")
        })?;
        let hash = requests::op_hash(&OperationV2::Finalize {
            id: id.clone(),
            pack,
            request_id: Some(request_id.clone()),
        });
        let stored = match self.requests.lookup(&request_id) {
            Some((_, recorded)) if recorded != hash => {
                return Err(ApiError::new(
                    "idempotency_conflict",
                    "request_id was first used with another request body; use a new request_id",
                ))
            }
            Some((Status::Done | Status::Failed, _)) => return self.requests.stored(&request_id),
            // A record stays running only while the log is Broken.
            Some((Status::Running, _)) => return Err(self.requests.unavailable()),
            Some((Status::Retryable, _)) => self.requests.target(&request_id).cloned(),
            None => None,
        };
        let target = match stored {
            // Ruling 5: a retry acts only on its stored target, never
            // re-resolved; a target that is gone answers `not_found` and
            // writes nothing.
            Some(target) => {
                self.check_stored_target(&target)?;
                target
            }
            // Step 1: resolved once, before `running` is written; a refusal
            // here writes nothing (there is no target to bind).
            None => self.resolve_target(&id)?,
        };
        self.requests.begin_finalize(&request_id, &hash, &target)?;
        let outcome = self.finalize_target(&target, pack);
        self.requests
            .finish_finalize(&request_id, &hash, &target, outcome)
    }

    /// Step 1 without a stored target: the attempts map, then the retained
    /// map. An ID a retained record holds that names neither is not served;
    /// an ID that names nothing is `not_found`.
    fn resolve_target(&self, id: &str) -> ApiResult<Target> {
        if let Some(target) = self.attempt_target(id) {
            return Ok(target);
        }
        if let Some(target) = self.retained_target(id) {
            return Ok(target);
        }
        if self.held().contains(id) {
            return Err(self.not_served(id));
        }
        Err(ApiError::new("not_found", "unknown attempt"))
    }

    /// A stored target must still name its attempt, by ID and instance.
    fn check_stored_target(&self, target: &Target) -> ApiResult<()> {
        if self.attempt_target(&target.id).as_ref() == Some(target)
            || self.retained_target(&target.id).as_ref() == Some(target)
        {
            return Ok(());
        }
        // Kept in `retained/` but not served (it was retained, and the
        // daemon restarted since): the not-served answer, never "gone". A
        // metadata read that fails is the check's own error, not absence.
        let kept = self.kept_unserved(target).map_err(|error| {
            let error = meta_error(error);
            if error.kind() == io::ErrorKind::WouldBlock {
                writers_active(format!(
                    "the overlay of attempt {} is locked or its database is busy ({error}); retry",
                    target.id
                ))
            } else {
                ApiError::new("io", format!("finalize of attempt {}: {error}", target.id))
            }
        })?;
        if kept {
            return Err(self.not_served(&target.id));
        }
        Err(ApiError::new(
            "not_found",
            format!(
                "attempt {} that this request finalizes is gone (destroyed, or discarded by a restart); a retry never acts on another attempt of the same name",
                target.id
            ),
        ))
    }

    /// Steps 1 (the fast path) to 8 on a resolved target.
    fn finalize_target(&mut self, target: &Target, pack: bool) -> ApiResult<Value> {
        if self.retained_target(&target.id).is_some() {
            return self.finalize_retained(target, pack);
        }
        let id = target.id.clone();
        let attempt = self.attempt(&id)?.clone();
        match attempt.status.as_str() {
            "finalized" => return self.fast_path(&id, pack),
            "starting" => {
                return Err(invalid(format!(
                    "attempt {id} is still starting; finalize it once it is ready"
                )))
            }
            _ => {}
        }
        if let Some(failure) = &self.attempt_state[&id].finalize.journal_failure {
            return Err(ApiError::new("io", failure.clone()));
        }
        let base = self.base(&attempt.base)?.clone();
        let indexes = self.indexes(&base.name);
        let root = attempt.path.parent().expect("attempt root").to_path_buf();
        // Step 2: the scope preflight, then the durability preflight's half
        // for the state trees.
        scope_preflight(&base, &indexes, Scope::Finalize)?;
        if self.attempt_state[&id].retain {
            self.retain_finalize_preflight(&attempt)?;
        }
        self.durability_preflight(&self.state_trees(
            &attempt,
            &root,
            &indexes,
            Some(&attempt.path),
        ))?;
        // Step 3: the recorded lowers, re-read; then the preflight's lower half.
        let records = self.recorded_lowers(&id)?;
        let layers = lowers::recorded_layers(&records).map_err(lower_changed)?;
        self.lowers_preflight(records.iter().map(|record| record.path.as_path()))?;
        // Step 4: `erofs_denied` while the child serves, within
        // `finalize_wait()` as the child's exit, the root flock and S's entry
        // locks are (a child that does not answer holds the serial serve loop
        // no longer), then the stop.
        if attempt.status != "finalizing" || self.mounter.child_alive(&attempt) {
            if let Ok(denied) = self.mounter.status(&attempt, self.finalize_wait()) {
                self.state_mut(&id).finalize.erofs_denied = Some(denied);
            }
        }
        let wait = if self.attempt_state[&id].finalize.detaching {
            Duration::ZERO
        } else {
            self.finalize_wait()
        };
        let stopped = self
            .mounter
            .stop(&attempt, wait)
            .map_err(|e| ApiError::new(&e.code, format!("stopping attempt {id}: {}", e.message)))?;
        let exit = match stopped {
            StopOutcome::Busy => {
                return Err(writers_active(format!(
                    "attempt {id} is still in use: its mount is busy (EBUSY); stop every process using it (its container) and retry; nothing was changed"
                )))
            }
            StopOutcome::Failed {
                detail,
                top_removed,
            } => {
                let outcome = if top_removed {
                    "the top mount was removed, but the attempt is still mounted and keeps its status"
                } else {
                    "nothing was changed"
                };
                return Err(ApiError::new(
                    "io",
                    format!("cannot unmount attempt {id}: {detail}; {outcome}"),
                ));
            }
            StopOutcome::Detaching => {
                self.set_status(&id, "finalizing");
                self.state_mut(&id).finalize.detaching = true;
                return Err(writers_active(format!(
                    "the mount process of attempt {id} has not exited after the unmount; another mount namespace (a container's copy of the mount) may hold the attempt; stop it and retry"
                )));
            }
            StopOutcome::Stopped { exit } => exit,
        };
        self.set_status(&id, "finalizing");
        self.state_mut(&id).finalize.detaching = false;
        // Step 4b: a journaled attempt finalizes only after exit status 0.
        let journaled = self.attempt_state[&id].journal;
        if journaled && !exit.is_some_and(|status| status.success()) {
            let status = exit.map_or_else(|| "an unknown status".to_owned(), |s| s.to_string());
            let message = format!(
                "the mount process of attempt {id} exited with {status}; its operation journal may be incomplete; destroy the attempt"
            );
            self.state_mut(&id).finalize.journal_failure = Some(message.clone());
            return Err(ApiError::new("io", message));
        }
        // Step 5: `bytes_written`, first measurement kept.
        if self.attempt_state[&id].finalize.bytes_written.is_none() {
            let quota = ratarmount_compositing::OverlayQuota::new(&attempt.overlay_dir, None, None)
                .map_err(|e| {
                    io_error(
                        &format!("finalize of attempt {id}: measuring bytes_written"),
                        &attempt.overlay_dir,
                        e,
                    )
                })?;
            self.state_mut(&id).finalize.bytes_written = Some(quota.usage().bytes);
        }
        // Step 6: `finalize_top` under a deadline for the root flock.
        let journal = root.join("journal.jsonl");
        if journaled && fs::symlink_metadata(&journal).is_err() {
            return Err(io_error(
                &format!("finalize of attempt {id}: its operation journal is missing"),
                &journal,
                "not found",
            ));
        }
        let manifest = root.join("manifest.jsonl");
        let summary = root.join("journal.summary.json");
        let bundle = root.join("bundle.tar.zst");
        let classify_failed = std::cell::RefCell::new(None);
        let finalized = {
            let mut classify = |_: Option<&OverlayMeta>| {
                classify_supervised(&base, &indexes).map_err(|error| {
                    *classify_failed.borrow_mut() = Some(error.clone());
                    io::Error::other(error)
                })
            };
            let mut compose = |source| ratarmount_compositing::compose_stack(source, &layers);
            let deadline = Instant::now() + self.finalize_wait();
            let mut progress = self.attempt_state[&id].finalize.progress.clone();
            let result = finalize_top(
                FinalizeTop {
                    top: &attempt.overlay_dir,
                    repair: Repair::UnlessSealed,
                    classify: &mut classify,
                    compose: &mut compose,
                    base_digest: None,
                    seal: Some(Some(deadline)),
                    pack: pack.then(|| Pack {
                        bundle: &bundle,
                        journal: journaled.then_some(journal.as_path()),
                    }),
                    manifest: &manifest,
                    journal: journaled.then_some((journal.as_path(), summary.as_path())),
                    #[cfg(test)]
                    before_meta_read: self.seams.before_meta_read.take(),
                },
                &mut progress,
            );
            // What completed survives a later phase's error.
            self.state_mut(&id).finalize.progress = progress;
            result
        };
        let finalized = finalized.map_err(|error| {
            if let Some(message) = classify_failed.borrow_mut().take() {
                ApiError::new("base_open_failed", message)
            } else if error.kind() == io::ErrorKind::WouldBlock {
                writers_active(format!(
                    "the overlay of attempt {id} is locked or its database is busy ({error}); retry"
                ))
            } else {
                ApiError::new("io", format!("finalize of attempt {id}: {error}"))
            }
        })?;
        // Step 7: the sync step, in every finalize.
        #[cfg(test)]
        if let Some(hook) = self.seams.before_sync.take() {
            hook();
        }
        self.sync_step(&attempt, &root, &indexes, &records)?;
        // Step 8: the report.
        let seal = finalized.seal.as_ref().expect("finalize seals");
        let state = &self.attempt_state[&id];
        let report = json!({
            "status": "finalized",
            "attempt": {
                "id": id, "base": attempt.base, "path": attempt.path,
                "overlay_dir": attempt.overlay_dir, "status": "finalized"
            },
            "patch_hash": finalized.patch_hash(),
            "layer_digest": seal.layer_digest,
            "sealed_at": seal.sealed_at,
            "stack_digest": finalized.meta.stack_digest(),
            "fsck_result": finalized.fsck_result,
            "bytes_written": state.finalize.bytes_written,
            "erofs_denied": state.finalize.erofs_denied,
            "manifest_path": finalized.manifest,
            "journal_summary": finalized.journal_summary,
            // A bundle an earlier try packed is reported even when this try
            // did not ask for `pack`.
            "bundle": finalized
                .bundle
                .clone()
                .or_else(|| state.finalize.progress.packed.then(|| bundle.clone())),
        });
        if self.attempt_state[&id].retain {
            return self.commit_retained(target, &attempt, report, &records);
        }
        self.set_status(&id, "finalized");
        self.state_mut(&id).finalize.report = Some(report.clone());
        Ok(report)
    }

    /// Step 1's fast path for a `finalized` attempt: `pack` against a report
    /// without a bundle is refused first; then the recorded lowers are read
    /// again, the durability preflight runs and S syncs again everything the
    /// stored report references, which then answers.
    fn fast_path(&mut self, id: &str, pack: bool) -> ApiResult<Value> {
        let report = self.attempt_state[id]
            .finalize
            .report
            .clone()
            .expect("a finalized attempt keeps its report");
        if pack && report["bundle"].is_null() {
            return Err(invalid(format!(
                "attempt {id} was finalized without a bundle; run `ratarmount overlay pack` on its layer"
            )));
        }
        let attempt = self.attempt(id)?.clone();
        let base = self.base(&attempt.base)?.clone();
        let indexes = self.indexes(&base.name);
        let root = attempt.path.parent().expect("attempt root").to_path_buf();
        let records = self.recorded_lowers(id)?;
        lowers::recorded_layers(&records).map_err(lower_changed)?;
        self.durability_preflight(&self.state_trees(&attempt, &root, &indexes, None))?;
        self.lowers_preflight(records.iter().map(|record| record.path.as_path()))?;
        self.sync_step(&attempt, &root, &indexes, &records)?;
        Ok(report)
    }

    /// The layers the attempt's child took (step 3): a layered attempt never
    /// verified is refused.
    fn recorded_lowers(&self, id: &str) -> ApiResult<Vec<LowerLayerRecord>> {
        match self.taken_lowers.get(id) {
            None => Ok(Vec::new()),
            Some(None) => Err(invalid(format!(
                "lower stack of attempt {id} was never verified; destroy it"
            ))),
            Some(Some(records)) => Ok(records.clone()),
        }
    }

    fn state_mut(&mut self, id: &str) -> &mut super::daemon::AttemptState {
        self.attempt_state
            .get_mut(id)
            .expect("a live attempt has its state")
    }

    fn set_status(&mut self, id: &str, status: &str) {
        if let Some(attempt) = self.attempts.get_mut(id) {
            attempt.status = status.into();
        }
    }

    /// The attempt's own trees: its root (`mnt` is the mount point a stop
    /// removes; `None` where no stop runs, on the retained fast path and in
    /// S), a RAM `overlay_dir` outside it, and the base's prepared state
    /// `indexes/<base>/`.
    fn state_trees<'a>(
        &self,
        attempt: &'a Attempt,
        root: &'a Path,
        indexes: &'a Path,
        mnt: Option<&'a Path>,
    ) -> Vec<Tree<'a>> {
        let mut trees = vec![Tree {
            path: root,
            lower: false,
            mnt,
            mounts: true,
        }];
        if !attempt.overlay_dir.starts_with(root) {
            trees.push(Tree {
                path: &attempt.overlay_dir,
                lower: false,
                mnt: None,
                mounts: true,
            });
        }
        trees.push(Tree {
            path: indexes,
            lower: false,
            mnt: None,
            mounts: true,
        });
        trees
    }

    /// The filesystem type of the descriptor `fd` of `path`.
    fn fs_type_of(&self, fd: BorrowedFd<'_>, path: &Path) -> io::Result<i64> {
        #[cfg(test)]
        if let Some(kind) = self.seams.fs_types.borrow().get(path) {
            return Ok(*kind);
        }
        let _ = path;
        super::daemon::fs_type(fd)
    }

    /// The device `path` reports, by its `lstat` (search permission only).
    fn device_of(&self, path: &Path) -> io::Result<u64> {
        let real = fs::symlink_metadata(path)?.dev();
        Ok(self.device_override(path, real))
    }

    fn device_override(&self, path: &Path, real: u64) -> u64 {
        #[cfg(test)]
        if let Some((_, device)) = self
            .seams
            .devices
            .iter()
            .filter(|(prefix, _)| path.starts_with(prefix))
            .max_by_key(|(prefix, _)| prefix.components().count())
        {
            return *device;
        }
        let _ = path;
        real
    }

    /// The chain of a tree (§5.6 S3): its parent and every directory above
    /// it on the parent's device, up to the root of that filesystem. The
    /// first directory on another device ends it, unopened. A parent that
    /// cannot be read is the caller's refusal: `invalid_request` before the
    /// stop, `io` in step S (only a race after the tree's own `lstat` reaches
    /// that there).
    fn chain(&self, tree: &Path) -> std::result::Result<Vec<PathBuf>, (PathBuf, io::Error)> {
        let Some(parent) = tree.parent() else {
            return Ok(Vec::new());
        };
        let device = self
            .device_of(parent)
            .map_err(|e| (parent.to_path_buf(), e))?;
        let mut chain = vec![parent.to_path_buf()];
        let mut current = parent.parent();
        while let Some(dir) = current {
            match self.device_of(dir) {
                Ok(found) if found == device => chain.push(dir.to_path_buf()),
                // Another device, or a directory that cannot be stat'ed
                // (which needs only search permission on its parent): the
                // chain ends there.
                _ => break,
            }
            current = dir.parent();
        }
        Ok(chain)
    }

    /// The durability preflight's lower half (§5.5): each lower path as a
    /// read-only tree. At finalize it runs after step 3's re-read, so a
    /// lower a cleaner deleted is R1b's `lower_changed` first.
    pub(super) fn lowers_preflight<'a>(
        &self,
        paths: impl IntoIterator<Item = &'a Path>,
    ) -> ApiResult<()> {
        let trees: Vec<Tree<'_>> = paths
            .into_iter()
            .map(|path| Tree {
                path,
                lower: true,
                mnt: None,
                mounts: true,
            })
            .collect();
        self.durability_preflight(&trees)
    }

    /// The durability preflight of a `new` with `retain` for a directory
    /// that is not yet a tree (`attempts/`, `indexes/<base>/`, a bundle
    /// cache directory): its type, chain and devices. `mounts` is §5.5's
    /// mount check; it cannot run on `attempts/`, which holds the running
    /// attempts' `attempts/ID/mnt` mounts (the mount rule excepts a tree's
    /// own `mnt`, not its siblings').
    pub(super) fn retain_trees_preflight(&self, dir: &Path, mounts: bool) -> ApiResult<()> {
        self.durability_preflight(&[Tree {
            path: dir,
            lower: false,
            mnt: None,
            mounts,
        }])
    }

    /// The durability preflight of a retained entry's fast path: its tree
    /// (no stop runs for it, so `retained/ID/mnt` is no mount exception),
    /// the base's prepared state and its lowers.
    pub(super) fn retained_trees_preflight(
        &self,
        attempt: &Attempt,
        root: &Path,
        indexes: &Path,
        records: &[LowerLayerRecord],
    ) -> ApiResult<()> {
        self.durability_preflight(&self.state_trees(attempt, root, indexes, None))?;
        self.lowers_preflight(records.iter().map(|record| record.path.as_path()))
    }

    /// The durability preflight (§5.5, ruling 6), before anything stops or
    /// starts: for each tree, its root and its parent on an allowlisted
    /// filesystem, each chain directory opened as step S will open it, no
    /// mount strictly below the root (the attempt's own mount point
    /// excepted; a mount below it is refused), a lower root without a write
    /// bit, and nothing on a poisoned device.
    fn durability_preflight(&self, trees: &[Tree<'_>]) -> ApiResult<()> {
        let mounts = self.mounter.mount_points().map_err(|e| {
            ApiError::new(
                &e.code,
                format!("finalize: reading the mount table: {}", e.message),
            )
        })?;
        for tree in trees {
            let path = tree.path;
            let root = crate::overlay_pack::open_root(path)
                .map_err(|e| invalid(format!("{} cannot be opened: {e}", path.display())))?;
            self.check_filesystem(root.as_fd(), path, None)?;
            let stat = ratarmount_compositing::host_stat::fstat_named(&root, path)
                .map_err(|e| invalid(format!("{} cannot be read: {e}", path.display())))?;
            #[allow(clippy::unnecessary_cast)]
            let device = self.device_override(path, stat.st_dev as u64);
            if self.poisoned.contains(&device) {
                return Err(poisoned_error(path));
            }
            if tree.lower && stat.st_mode & 0o222 != 0 {
                return Err(writable_lower(path, path));
            }
            let chain = self
                .chain(path)
                .map_err(|(dir, e)| invalid(format!("{} cannot be read: {e}", dir.display())))?;
            for (i, dir) in chain.into_iter().enumerate() {
                let directory = super::state_log::open_dir(&dir).map_err(|e| {
                    invalid(format!(
                        "{} cannot be opened: {e}; finalize syncs every directory above the state directory, the bundle cache and each lower on the same filesystem, so each must be readable",
                        dir.display()
                    ))
                })?;
                if i == 0 {
                    self.check_filesystem(directory.as_fd(), &dir, Some(path))?;
                }
                let device = self.device_of(&dir).unwrap_or(u64::MAX);
                if self.poisoned.contains(&device) {
                    return Err(poisoned_error(&dir));
                }
            }
            for mount in mounts.iter().filter(|_| tree.mounts) {
                if !mount.starts_with(path) || mount == path {
                    continue;
                }
                match tree.mnt {
                    Some(mnt) if mount == mnt => {}
                    Some(mnt) if mount.starts_with(mnt) => {
                        return Err(invalid(format!(
                            "{} is mounted inside attempt mount point {}: unmount {} first; finalize never unmounts it for you",
                            mount.display(),
                            mnt.display(),
                            mount.display()
                        )))
                    }
                    _ => {
                        return Err(invalid(format!(
                            "{} has a mount inside it at {}; finalize syncs only trees that lie wholly on one filesystem",
                            path.display(),
                            mount.display()
                        )))
                    }
                }
            }
        }
        Ok(())
    }

    /// `invalid_request` unless the filesystem of `fd` (at `path`) is on the
    /// allowlist. `of` names the tree a parent belongs to.
    fn check_filesystem(
        &self,
        fd: BorrowedFd<'_>,
        path: &Path,
        of: Option<&Path>,
    ) -> ApiResult<()> {
        let kind = self.fs_type_of(fd, path).map_err(|e| {
            invalid(format!(
                "{}: cannot read its filesystem type: {e}",
                path.display()
            ))
        })?;
        if allowed(kind) {
            return Ok(());
        }
        Err(invalid(match of {
            Some(tree) => format!(
                "the directory {} that {} sits in, which finalize syncs too: {}",
                path.display(),
                tree.display(),
                off_allowlist(path, kind)
            ),
            None => off_allowlist(path, kind),
        }))
    }

    /// Step S (§5.6): every lower the child took, under its entry lock and
    /// after its identity is checked again, then the attempt's own trees,
    /// then every chain directory, deepest first and each once. Every fsync
    /// error poisons its filesystem.
    pub(super) fn sync_step(
        &mut self,
        attempt: &Attempt,
        root: &Path,
        indexes: &Path,
        records: &[LowerLayerRecord],
    ) -> ApiResult<()> {
        let deadline = Instant::now() + self.finalize_wait();
        let mut roots: Vec<PathBuf> = records.iter().map(|r| r.path.clone()).collect();
        let own: Vec<PathBuf> = self
            .state_trees(attempt, root, indexes, None)
            .into_iter()
            .map(|tree| tree.path.to_path_buf())
            .collect();
        roots.extend(own.iter().cloned());
        // The pre-check: nothing is synced if any root or chain directory is
        // on a poisoned device.
        let mut chains = BTreeSet::new();
        let mut lower_parents = BTreeSet::new();
        for tree in &roots {
            // A lower deleted since step 3 is R1b's `lower_changed`, as
            // its own lock step would answer.
            let device = self.device_of(tree).map_err(|e| {
                match records.iter().find(|record| record.path == *tree) {
                    Some(record) => lower_changed(
                        lowers::recorded_layers(std::slice::from_ref(record))
                            .err()
                            .unwrap_or_else(|| format!("lower {}: {e}", tree.display())),
                    ),
                    None => io_error("finalize: step S", tree, e),
                }
            })?;
            if self.poisoned.contains(&device) {
                return Err(poisoned_error(tree));
            }
            let chain = self
                .chain(tree)
                .map_err(|(dir, e)| io_error("finalize: step S", &dir, e))?;
            for dir in chain {
                if self
                    .device_of(&dir)
                    .is_ok_and(|device| self.poisoned.contains(&device))
                {
                    return Err(poisoned_error(&dir));
                }
                chains.insert(dir);
            }
        }
        // S1: each lower, bottom first.
        for record in records {
            self.sync_lower(record, deadline)?;
            if let Some(parent) = record.path.parent() {
                lower_parents.insert(parent.to_path_buf());
            }
        }
        // S2: the attempt's own trees.
        for tree in &own {
            let fd = crate::overlay_pack::open_root(tree)
                .map_err(|e| io_error("finalize: step S", tree, e))?;
            self.sync_one_tree(&fd, tree, None)?;
        }
        // S3: every chain directory, deepest first, each once.
        let mut chains: Vec<PathBuf> = chains
            .into_iter()
            .filter(|dir| !lower_parents.contains(dir))
            .collect();
        chains.sort_by_key(|dir| std::cmp::Reverse(dir.components().count()));
        for dir in chains {
            self.sync_dir_strict(&dir)?;
        }
        Ok(())
    }

    /// S1 for one lower: (a) the entry lock, and the locked root without a
    /// write bit; (b) R1b's re-read of its seal, and the path still naming
    /// the locked inode; (c) the tree from the locked descriptor, then its
    /// parent.
    fn sync_lower(&mut self, record: &LowerLayerRecord, deadline: Instant) -> ApiResult<()> {
        let path = &record.path;
        let locked = match crate::overlay_pack::lock_layer_entry(path, deadline) {
            Ok(fd) => fd,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                return Err(ApiError::new("in_use", format!("{e}; retry")))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(lower_changed(
                    lowers::recorded_layers(std::slice::from_ref(record))
                        .err()
                        .unwrap_or_else(|| format!("lower {}: {e}", path.display())),
                ))
            }
            Err(e) => return Err(io_error("finalize: locking a lower", path, e)),
        };
        #[cfg(test)]
        if let Some(hook) = self.seams.after_lower_lock.take() {
            hook(path);
        }
        let stat = ratarmount_compositing::host_stat::fstat_named(&locked, path)
            .map_err(|e| io_error("finalize: step S", path, e))?;
        if stat.st_mode & 0o222 != 0 {
            return Err(writable_lower(path, path));
        }
        // (b) Its connection is closed when this returns: the walk's
        // admitted opens never meet a registered database.
        lowers::recorded_layers(std::slice::from_ref(record)).map_err(lower_changed)?;
        let named = fs::symlink_metadata(path).map_err(|e| {
            lower_changed(format!(
                "lower {} was replaced after its sync started: {e}",
                path.display()
            ))
        })?;
        #[allow(clippy::unnecessary_cast)]
        if (named.dev(), named.ino()) != (stat.st_dev as u64, stat.st_ino as u64) {
            return Err(lower_changed(format!(
                "lower {} was replaced after its sync started",
                path.display()
            )));
        }
        self.sync_one_tree(&locked, path, Some(path))?;
        if let Some(parent) = path.parent() {
            self.sync_dir_strict(parent)?;
        }
        drop(locked);
        Ok(())
    }

    /// `sync_tree` with the supervisor's checks; `lower` is set for a lower
    /// (read-only) tree.
    fn sync_one_tree(
        &mut self,
        fd: &std::os::fd::OwnedFd,
        path: &Path,
        lower: Option<&Path>,
    ) -> ApiResult<()> {
        #[cfg(test)]
        let mut synced = Vec::new();
        let result = {
            let filesystem = |fd: BorrowedFd<'_>, path: &Path| -> std::result::Result<(), String> {
                let kind = self.fs_type_of(fd, path).map_err(|e| {
                    format!("{}: cannot read its filesystem type: {e}", path.display())
                })?;
                if allowed(kind) {
                    Ok(())
                } else {
                    Err(off_allowlist(path, kind))
                }
            };
            let device = |path: &Path, real: u64| self.device_override(path, real);
            let mut fsync = |fd: BorrowedFd<'_>, path: &Path| -> io::Result<()> {
                #[cfg(test)]
                {
                    if let Some(errno) = self.seams.fsync_errors.get(path) {
                        return Err(io::Error::from_raw_os_error(*errno));
                    }
                }
                rustix::fs::fsync(fd)?;
                #[cfg(test)]
                synced.push(path.to_path_buf());
                #[cfg(not(test))]
                let _ = path;
                Ok(())
            };
            #[cfg(test)]
            let before_open = self.seams.before_open.as_deref();
            crate::overlay_pack::sync_tree(
                fd,
                path,
                &mut crate::overlay_pack::SyncChecks {
                    filesystem: &filesystem,
                    device: &device,
                    read_only: lower.is_some(),
                    fsync: &mut fsync,
                    #[cfg(test)]
                    before_open,
                },
            )
        };
        #[cfg(test)]
        self.record_syncs(synced);
        result.map_err(|error| match error {
            crate::overlay_pack::SyncError::Writable(node) => {
                writable_lower(lower.unwrap_or(path), &node)
            }
            crate::overlay_pack::SyncError::Mismatch(message) => ApiError::new("io", message),
            crate::overlay_pack::SyncError::Fsync {
                device,
                path,
                error,
            } => {
                self.poisoned.insert(device);
                fsync_failed(&path, &error)
            }
            crate::overlay_pack::SyncError::Other(message) => ApiError::new("io", message),
        })
    }

    /// The engine's directory open for S's lower parents and chains, then its checks
    /// on the descriptor (a directory, not on a poisoned device, on an
    /// allowlisted filesystem) and its fsync; a failed fsync poisons.
    pub(super) fn sync_dir_strict(&mut self, dir: &Path) -> ApiResult<()> {
        #[cfg(test)]
        if let Some(errno) = self.seams.open_errors.get(dir) {
            return Err(io_error(
                "finalize: opening a directory to sync it",
                dir,
                io::Error::from_raw_os_error(*errno),
            ));
        }
        let directory = super::state_log::open_dir(dir)
            .map_err(|e| io_error("finalize: opening a directory to sync it", dir, e))?;
        let meta = directory
            .metadata()
            .map_err(|e| io_error("finalize: step S", dir, e))?;
        let device = self.device_override(dir, meta.dev());
        if self.poisoned.contains(&device) {
            return Err(poisoned_error(dir));
        }
        let kind = self
            .fs_type_of(directory.as_fd(), dir)
            .map_err(|e| io_error("finalize: reading the filesystem type", dir, e))?;
        if !allowed(kind) {
            return Err(ApiError::new("io", off_allowlist(dir, kind)));
        }
        #[cfg(test)]
        if let Some(errno) = self.seams.fsync_errors.get(dir) {
            self.poisoned.insert(device);
            return Err(fsync_failed(dir, &io::Error::from_raw_os_error(*errno)));
        }
        if let Err(error) = directory.sync_all() {
            self.poisoned.insert(device);
            return Err(fsync_failed(dir, &error));
        }
        #[cfg(test)]
        self.record_syncs(vec![dir.to_path_buf()]);
        Ok(())
    }

    #[cfg(test)]
    fn record_syncs(&mut self, synced: Vec<PathBuf>) {
        for path in &synced {
            crate::overlay_pack::events::record(&format!("fsync @{}", self.root.display()), path);
        }
        self.seams.syncs.extend(synced);
    }
}
