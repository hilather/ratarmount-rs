//! Process-wide Fork-N worker phase and writable-storage admission.
//!
//! An uninstalled slot is the legacy path: guards are no-ops and opens stay
//! with the caller. Only [`WorkerPhase::Preparing`] suppresses speculative work.

use std::cell::Cell;
use std::fs::File;
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::Mutex;

use crate::OpenOptions;

const INACTIVE: u8 = 0;
const PREPARING: u8 = 1;
const SERVING: u8 = 2;

static PHASE: AtomicU8 = AtomicU8::new(INACTIVE);

/// Who may start speculative workers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkerPhase {
    /// Legacy single mount. Speculative work is unchanged.
    Inactive,
    /// Daemon Fork-N, before any constructor and until the child holds every lock.
    /// The only phase that suppresses speculative work.
    Preparing,
    /// Foreground Fork-N, and the daemon child after handoff. No suppression.
    Serving,
}

impl WorkerPhase {
    fn from_u8(value: u8) -> Self {
        match value {
            PREPARING => Self::Preparing,
            SERVING => Self::Serving,
            _ => Self::Inactive,
        }
    }

    fn as_u8(self) -> u8 {
        match self {
            Self::Inactive => INACTIVE,
            Self::Preparing => PREPARING,
            Self::Serving => SERVING,
        }
    }
}

/// Current phase. Default [`WorkerPhase::Inactive`].
pub fn phase() -> WorkerPhase {
    WorkerPhase::from_u8(PHASE.load(Ordering::Acquire))
}

/// Install the phase. Legacy never calls this.
pub fn set_phase(phase: WorkerPhase) {
    PHASE.store(phase.as_u8(), Ordering::Release);
}

/// True only while daemon preparation must not start a pool, prefetch, or fadvise.
pub fn preparing() -> bool {
    phase() == WorkerPhase::Preparing
}

thread_local! {
    static NESTED_OPEN: Cell<u32> = const { Cell::new(0) };
}

/// Counts nested archive opens on this thread. A torrent found there returns
/// `Unsupported` instead of the daemon process-exit sentence.
pub struct NestedOpenGuard;

impl NestedOpenGuard {
    pub fn enter() -> Self {
        NESTED_OPEN.with(|depth| depth.set(depth.get().saturating_add(1)));
        Self
    }
}

impl Drop for NestedOpenGuard {
    fn drop(&mut self) {
        NESTED_OPEN.with(|depth| depth.set(depth.get().saturating_sub(1)));
    }
}

pub fn nested_open() -> bool {
    NESTED_OPEN.with(|depth| depth.get() > 0)
}

static POOL_LIVE: AtomicBool = AtomicBool::new(false);
static SQLITE_OPEN: AtomicUsize = AtomicUsize::new(0);

/// A source executor exists and has not been joined. The worker-free permit
/// reads this without taking that pool's lock.
pub fn note_pool_live() {
    POOL_LIVE.store(true, Ordering::Release);
}

/// The pool has been joined. A live pool refuses the permit without fork.
pub fn note_pool_joined() {
    POOL_LIVE.store(false, Ordering::Release);
}

pub fn pool_is_live() -> bool {
    POOL_LIVE.load(Ordering::Acquire)
}

/// A parent SQLite connection was opened and must be closed before fork.
pub fn register_sqlite() {
    SQLITE_OPEN.fetch_add(1, Ordering::Release);
}

/// A parent SQLite connection was dropped.
pub fn unregister_sqlite() {
    SQLITE_OPEN.fetch_sub(1, Ordering::Release);
}

pub fn sqlite_open_count() -> usize {
    SQLITE_OPEN.load(Ordering::Acquire)
}

/// Refuse fork while a pool is live or a parent SQLite connection is open.
/// Does not take the pool lock and does not fork.
pub fn worker_free_permit() -> Result<(), String> {
    if phase() != WorkerPhase::Preparing {
        return Err("fork-n worker-free permit requires Preparing".into());
    }
    if pool_is_live() {
        return Err("fork-n refuses fork while a worker pool is live or unjoined".into());
    }
    if sqlite_open_count() != 0 {
        return Err("fork-n refuses fork while a parent SQLite connection is open".into());
    }
    Ok(())
}

/// Overlay database name. Companions are this name plus `-wal`, `-shm`, `-journal`.
pub const OVERLAY_DB_NAME: &str = ".ratarmount.overlay.sqlite";

struct Slot {
    tops: Vec<PathBuf>,
    mountpoints: Vec<PathBuf>,
    admitted: Vec<String>,
}

static SLOT: Mutex<Option<Slot>> = Mutex::new(None);

/// Install the cohort. Later [`admit`] calls see these tops and mountpoints.
pub fn install(tops: Vec<PathBuf>, mountpoints: Vec<PathBuf>) {
    let mut guard = SLOT.lock().unwrap_or_else(|e| e.into_inner());
    *guard = Some(Slot {
        tops,
        mountpoints,
        admitted: Vec::new(),
    });
}

/// Remove the cohort. Legacy opens resume.
pub fn uninstall() {
    let mut guard = SLOT.lock().unwrap_or_else(|e| e.into_inner());
    *guard = None;
}

pub fn installed() -> bool {
    SLOT.lock().unwrap_or_else(|e| e.into_inner()).is_some()
}

/// Record a constructor the closed table admitted.
pub fn note_admitted(id: &str) {
    if let Some(slot) = SLOT.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
        if !slot.admitted.iter().any(|s| s == id) {
            slot.admitted.push(id.to_string());
        }
    }
}

pub fn admitted_constructors() -> Vec<String> {
    SLOT.lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .map(|s| s.admitted.clone())
        .unwrap_or_default()
}

thread_local! {
    static OPEN_COUNT: Cell<u64> = const { Cell::new(0) };
    static CREATE_COUNT: Cell<u64> = const { Cell::new(0) };
}

/// Test spy: `File::open`s performed by [`admit`] on this thread, tagged admit.
pub fn test_open_count() -> u64 {
    OPEN_COUNT.with(|c| c.get())
}

/// Test spy: create/truncate calls the opener reached after a successful admit.
pub fn test_create_count() -> u64 {
    CREATE_COUNT.with(|c| c.get())
}

pub fn test_reset_spies() {
    OPEN_COUNT.with(|c| c.set(0));
    CREATE_COUNT.with(|c| c.set(0));
}

/// Count a create or truncate that admission allowed. A refusal never calls this.
pub fn note_create() {
    CREATE_COUNT.with(|c| c.set(c.get().saturating_add(1)));
}

/// What [`admit`] tells the caller to do with the path.
#[derive(Debug)]
pub enum Admitted {
    /// No cohort is installed. The caller opens or creates as it does today.
    Legacy,
    /// The path is inside the cohort and was opened here. Do not open it again.
    Opened(File),
    /// The path is inside the cohort and was not opened. The caller may create it.
    Checked,
}

/// Admit `path` before the caller opens or creates it.
///
/// `open` asks admission to return the [`File`] when a cohort is installed.
/// `overlay_owner` is the top whose own database and `-wal`/`-shm`/`-journal`
/// companions are not a "under a top" hit. Mountpoint containment still refuses
/// those paths. A missing final component is checked against the existing
/// ancestor plus the lexical remainder and is not created.
pub fn admit(path: &Path, open: bool, overlay_owner: Option<&Path>) -> io::Result<Admitted> {
    let guard = SLOT.lock().unwrap_or_else(|e| e.into_inner());
    let Some(slot) = guard.as_ref() else {
        return Ok(Admitted::Legacy);
    };
    let resolved = resolve_for_admit(path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("fork-n refuses to resolve {}: {e}", path.display()),
        )
    })?;
    if contained(&resolved, &slot.mountpoints) {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            format!(
                "fork-n refuses {}: canonical path is under a cohort mountpoint",
                path.display()
            ),
        ));
    }
    let own_db = overlay_owner.is_some_and(|owner| is_own_overlay_db(&resolved, owner));
    if !own_db && contained(&resolved, &slot.tops) {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            format!(
                "fork-n refuses {}: canonical path is under a cohort top",
                path.display()
            ),
        ));
    }
    if open {
        let file = File::open(path).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("fork-n admit open {}: {e}", path.display()),
            )
        })?;
        OPEN_COUNT.with(|c| c.set(c.get().saturating_add(1)));
        Ok(Admitted::Opened(file))
    } else {
        Ok(Admitted::Checked)
    }
}

/// [`File::open`] when a cohort is installed, otherwise the caller's open.
/// A refusal is returned before any open. The returned file is the admit file.
pub fn open_admitted(path: &Path) -> io::Result<File> {
    match admit(path, true, None)? {
        Admitted::Legacy => File::open(path),
        Admitted::Opened(file) => Ok(file),
        Admitted::Checked => File::open(path),
    }
}

/// Check a path the caller is about to create or truncate. Does not create it.
pub fn admit_create(path: &Path) -> io::Result<()> {
    match admit(path, false, None)? {
        Admitted::Legacy | Admitted::Checked => Ok(()),
        Admitted::Opened(file) => {
            drop(file);
            Ok(())
        }
    }
}

/// Same as [`admit_create`] for one top's database and its companions.
pub fn admit_overlay_db(db: &Path, owner: &Path) -> io::Result<()> {
    admit(db, false, Some(owner))?;
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut name = db.as_os_str().to_os_string();
        name.push(suffix);
        admit(Path::new(&name), false, Some(owner))?;
    }
    Ok(())
}

fn is_own_overlay_db(resolved: &Path, owner: &Path) -> bool {
    let Ok(owner) = resolve_for_admit(owner).or_else(|_| {
        if owner.exists() {
            owner.canonicalize()
        } else {
            Err(io::Error::new(ErrorKind::NotFound, "owner"))
        }
    }) else {
        return false;
    };
    let Some(parent) = resolved.parent() else {
        return false;
    };
    if parent != owner.as_path() {
        return false;
    }
    let Some(name) = resolved.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    name == OVERLAY_DB_NAME
        || name == concat_db("-wal")
        || name == concat_db("-shm")
        || name == concat_db("-journal")
}

fn concat_db(suffix: &str) -> String {
    format!("{OVERLAY_DB_NAME}{suffix}")
}

fn contained(path: &Path, roots: &[PathBuf]) -> bool {
    roots
        .iter()
        .any(|root| path == root || path.starts_with(root))
}

/// Canonicalize `path`. A missing final component uses the existing ancestor
/// plus the lexical remainder. A symlink loop, a missing ancestor, or any
/// other canonicalize error is returned as a refusal.
fn resolve_for_admit(path: &Path) -> io::Result<PathBuf> {
    match path.canonicalize() {
        Ok(resolved) => Ok(resolved),
        Err(err) if err.kind() == ErrorKind::NotFound => resolve_missing_tail(path),
        Err(err) => Err(err),
    }
}

fn resolve_missing_tail(path: &Path) -> io::Result<PathBuf> {
    let mut missing: Vec<std::ffi::OsString> = Vec::new();
    let mut cur = path.to_path_buf();
    loop {
        if std::fs::symlink_metadata(&cur).is_ok() {
            break;
        }
        let Some(parent) = cur.parent() else {
            return Err(io::Error::new(
                ErrorKind::NotFound,
                format!("fork-n cannot resolve {}", path.display()),
            ));
        };
        if parent.as_os_str().is_empty() {
            return Err(io::Error::new(
                ErrorKind::NotFound,
                format!("fork-n cannot resolve {}", path.display()),
            ));
        }
        if let Some(name) = cur.file_name() {
            missing.push(name.to_os_string());
        }
        if parent == cur {
            return Err(io::Error::new(
                ErrorKind::NotFound,
                format!("fork-n cannot resolve {}", path.display()),
            ));
        }
        cur = parent.to_path_buf();
    }
    let mut resolved = cur.canonicalize()?;
    for name in missing.into_iter().rev() {
        resolved.push(name);
    }
    Ok(resolved)
}

/// Closed constructor table. Default refuse. `Ok` when no cohort is installed.
pub fn guard_constructor(path: &Path, options: &OpenOptions) -> Result<(), String> {
    if !installed() {
        return Ok(());
    }
    #[cfg(debug_assertions)]
    if let Ok(log) = std::env::var("RATARMOUNT_TEST_FORK_N_PHASE_LOG") {
        let _ = std::fs::write(&log, format!("{:?}\n", phase()));
    }
    let id = classify_constructor(path, options);
    if id == "torrent" && nested_open() {
        return Err(format!(
            "Unsupported: fork-n refuses nested torrent {}",
            path.display()
        ));
    }
    if !constructor_admitted(&id) {
        let hint = daemon_foreground_hint(&id);
        return Err(if hint {
            format!("fork-n has no storage coverage for {id}; use --foreground")
        } else {
            format!("fork-n has no storage coverage for {id}")
        });
    }
    note_admitted(&id);
    Ok(())
}

fn constructor_admitted(id: &str) -> bool {
    matches!(
        id,
        "local-folder"
            | "tar"
            | "qcow2"
            | "vmdk"
            | "http-range"
            | "zstd"
            | "index"
            | "sqlite"
            | "bundle-cache"
            | "range-cache"
            | "materialized"
            | "seek-sidecar"
            | "split-volume"
    )
}

/// Daemon-only `use --foreground` on the coverage diagnostic. Torrent uses the
/// earlier ban instead. Foreground coverage errors do not include the hint.
fn daemon_foreground_hint(id: &str) -> bool {
    if phase() != WorkerPhase::Preparing {
        return false;
    }
    matches!(
        id,
        "ssh-proxyjump"
            | "hub-cache-publication"
            | "rapidgzip"
            | "sqlite-memory"
            | "sqlite-compact-shell"
            | "sqlar"
    )
}

fn classify_constructor(path: &Path, options: &OpenOptions) -> String {
    let text = path.to_string_lossy();
    let lower = text.to_ascii_lowercase();
    if options.use_backends.iter().any(|b| {
        let b = b.to_ascii_lowercase();
        b.contains("rapidgzip") || b == "gzip-rapidgzip"
    }) {
        return "rapidgzip".into();
    }
    if options.index_in_memory {
        return "sqlite-memory".into();
    }
    if options.index_compact_only {
        return "sqlite-compact-shell".into();
    }
    if lower.starts_with("magnet:") || lower.ends_with(".torrent") {
        return "torrent".into();
    }
    if lower.starts_with("ssh://") || lower.starts_with("sftp://") || lower.starts_with("scp://") {
        return "ssh-proxyjump".into();
    }
    if lower.contains("huggingface") && lower.contains("publication") {
        return "hub-cache-publication".into();
    }
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return "http-range".into();
    }
    if lower.ends_with(".sqlar") {
        return "sqlar".into();
    }
    if lower.ends_with(".qcow2") {
        return "qcow2".into();
    }
    if lower.ends_with(".vmdk") {
        return "vmdk".into();
    }
    if path.is_dir() {
        return "local-folder".into();
    }
    if is_tar_name(&lower) {
        return "tar".into();
    }
    if lower.ends_with(".zst") || lower.ends_with(".zstd") {
        return "zstd".into();
    }
    "unknown".into()
}

fn is_tar_name(lower: &str) -> bool {
    lower.ends_with(".tar")
        || lower.ends_with(".tar.gz")
        || lower.ends_with(".tgz")
        || lower.ends_with(".tar.zst")
        || lower.ends_with(".tar.bz2")
        || lower.ends_with(".tar.xz")
        || lower.ends_with(".tar.lz4")
}

/// True when `name` is a torrent input by spelling, including builds that do
/// not compile the bittorrent feature (`.torrent` and `magnet:`).
pub fn torrent_spelling(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("magnet:") || lower.ends_with(".torrent")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    static LOCK: StdMutex<()> = StdMutex::new(());

    struct Guard;
    impl Drop for Guard {
        fn drop(&mut self) {
            uninstall();
            set_phase(WorkerPhase::Inactive);
            note_pool_joined();
        }
    }

    fn hold() -> (std::sync::MutexGuard<'static, ()>, Guard) {
        let g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        test_reset_spies();
        (g, Guard)
    }

    /// Regression: an uninstalled slot does not open or refuse a path.
    #[test]
    fn fork_n_uninstalled_admit_is_legacy() {
        let (_lock, _guard) = hold();
        uninstall();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        std::fs::write(&path, b"x").unwrap();
        match admit(&path, true, None).unwrap() {
            Admitted::Legacy => {}
            other => panic!(
                "expected legacy, got opened={}",
                matches!(other, Admitted::Opened(_))
            ),
        }
        assert_eq!(test_open_count(), 0);
    }

    /// Regression: a backing path under a mountpoint is refused before open.
    #[test]
    fn fork_n_admit_refuses_mountpoint_before_open() {
        let (_lock, _guard) = hold();
        let dir = tempfile::tempdir().unwrap();
        let mp = dir.path().join("mnt");
        let top = dir.path().join("top");
        std::fs::create_dir(&mp).unwrap();
        std::fs::create_dir(&top).unwrap();
        let backing = mp.join("disk.raw");
        std::fs::write(&backing, b"raw").unwrap();
        install(
            vec![top.canonicalize().unwrap()],
            vec![mp.canonicalize().unwrap()],
        );
        let err = admit(&backing, true, None).unwrap_err();
        assert!(err.to_string().contains(&backing.display().to_string()));
        assert_eq!(test_open_count(), 0);
        assert!(backing.is_file());
    }

    /// Regression: a missing final component under a mountpoint is not created.
    #[test]
    fn fork_n_admit_absent_component_does_not_create() {
        let (_lock, _guard) = hold();
        let dir = tempfile::tempdir().unwrap();
        let mp = dir.path().join("mnt");
        std::fs::create_dir(&mp).unwrap();
        let dest = mp.join("index.sqlite");
        assert!(!dest.exists());
        install(
            vec![dir.path().join("top")],
            vec![mp.canonicalize().unwrap()],
        );
        let err = admit_create(&dest).unwrap_err();
        assert!(err.to_string().contains("mountpoint"), "{err}");
        assert!(!dest.exists(), "refusal must not create the destination");
        assert_eq!(test_create_count(), 0);
    }

    /// Regression: the owning top's database is not a hit; a sibling top's is.
    #[test]
    fn fork_n_admit_own_overlay_db_is_exempt() {
        let (_lock, _guard) = hold();
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        std::fs::create_dir(&a).unwrap();
        std::fs::create_dir(&b).unwrap();
        let db = a.join(OVERLAY_DB_NAME);
        std::fs::write(&db, b"db").unwrap();
        install(
            vec![a.canonicalize().unwrap(), b.canonicalize().unwrap()],
            vec![],
        );
        admit_overlay_db(&db, &a).unwrap();
        let foreign = b.join(OVERLAY_DB_NAME);
        std::fs::write(&foreign, b"db").unwrap();
        assert!(admit(&foreign, false, Some(&a)).is_err());
    }

    /// Regression: a `-wal` symlink into a mountpoint is a hit.
    #[test]
    fn fork_n_admit_wal_symlink_into_mountpoint() {
        let (_lock, _guard) = hold();
        let dir = tempfile::tempdir().unwrap();
        let top = dir.path().join("top");
        let mp = dir.path().join("mnt");
        std::fs::create_dir(&top).unwrap();
        std::fs::create_dir(&mp).unwrap();
        let db = top.join(OVERLAY_DB_NAME);
        std::fs::write(&db, b"db").unwrap();
        let inside = mp.join("stolen-wal");
        std::fs::write(&inside, b"wal").unwrap();
        let wal = {
            let mut name = db.as_os_str().to_os_string();
            name.push("-wal");
            PathBuf::from(name)
        };
        std::os::unix::fs::symlink(&inside, &wal).unwrap();
        install(
            vec![top.canonicalize().unwrap()],
            vec![mp.canonicalize().unwrap()],
        );
        let err = admit(&wal, false, Some(&top)).unwrap_err();
        assert!(err.to_string().contains("mountpoint"), "{err}");
    }

    /// Regression: a live pool refuses the permit without clearing the flag.
    #[test]
    fn fork_n_worker_free_permit_refuses_live_pool() {
        let (_lock, _guard) = hold();
        set_phase(WorkerPhase::Preparing);
        note_pool_live();
        let err = worker_free_permit().unwrap_err();
        assert!(err.contains("unjoined") || err.contains("live"), "{err}");
        assert!(pool_is_live());
        note_pool_joined();
        worker_free_permit().unwrap();
    }

    /// Regression: Preparing is the only phase that suppresses speculative work.
    #[test]
    fn fork_n_only_preparing_suppresses() {
        let (_lock, _guard) = hold();
        set_phase(WorkerPhase::Inactive);
        assert!(!preparing());
        set_phase(WorkerPhase::Serving);
        assert!(!preparing());
        set_phase(WorkerPhase::Preparing);
        assert!(preparing());
    }

    /// Regression: rapidgzip and in-memory sqlite are outside the closed table.
    #[test]
    fn fork_n_guard_constructor_default_refuse() {
        let (_lock, _guard) = hold();
        install(vec![], vec![]);
        set_phase(WorkerPhase::Serving);
        let mut options = OpenOptions {
            use_backends: vec!["rapidgzip".into()],
            ..OpenOptions::default()
        };
        let err = guard_constructor(Path::new("a.tar"), &options).unwrap_err();
        assert!(err.contains("no storage coverage for rapidgzip"), "{err}");
        assert!(!err.contains("use --foreground"), "{err}");
        set_phase(WorkerPhase::Preparing);
        let err = guard_constructor(Path::new("a.tar"), &options).unwrap_err();
        assert!(err.contains("use --foreground"), "{err}");
        options.use_backends.clear();
        options.index_in_memory = true;
        let err = guard_constructor(Path::new("a.tar"), &options).unwrap_err();
        assert!(err.contains("sqlite-memory"), "{err}");
        assert!(err.contains("use --foreground"), "{err}");
    }
}
