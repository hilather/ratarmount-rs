//! Fork-N writable-storage admission.
//!
//! An uninstalled slot is the legacy path: opens stay with the caller and no
//! fork-n error is invented. PR2a does not install a worker phase.

use std::fs::File;
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// Overlay database name. Companions are this name plus `-wal`, `-shm`, `-journal`.
pub const OVERLAY_DB_NAME: &str = ".ratarmount.overlay.sqlite";

struct Slot {
    tops: Vec<PathBuf>,
    mountpoints: Vec<PathBuf>,
}

static SLOT: Mutex<Option<Slot>> = Mutex::new(None);
static ADMIT: AtomicU64 = AtomicU64::new(0);
static OPEN: AtomicU64 = AtomicU64::new(0);
static CREATE: AtomicU64 = AtomicU64::new(0);
static TRUNCATE: AtomicU64 = AtomicU64::new(0);

/// Install the cohort. Later [`admit`] calls see these tops and mountpoints.
pub fn install(tops: Vec<PathBuf>, mountpoints: Vec<PathBuf>) {
    let mut guard = SLOT.lock().unwrap_or_else(|e| e.into_inner());
    *guard = Some(Slot { tops, mountpoints });
    flush_spies();
}

/// Remove the cohort. Legacy opens resume.
pub fn uninstall() {
    let mut guard = SLOT.lock().unwrap_or_else(|e| e.into_inner());
    *guard = None;
}

pub fn installed() -> bool {
    SLOT.lock().unwrap_or_else(|e| e.into_inner()).is_some()
}

/// Canonical path, or the existing ancestor plus one missing final component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedAdmit {
    /// The path exists. Canonical when a cohort is installed; the original
    /// path, uncanonicalized, when it is not.
    Existing(PathBuf),
    /// Only the final component is missing. The ancestor was canonicalized.
    Absent(PathBuf),
}

/// Resolve `path` for admission.
///
/// Uninstalled, this returns [`ResolvedAdmit::Existing`] of the original path
/// and does not canonicalize. Installed, a symlink loop or a missing ancestor
/// is the raw I/O error (the caller adds `fork-n refuses to resolve`). Only
/// the final component may be [`ResolvedAdmit::Absent`].
pub fn resolve_for_admit(path: &Path) -> io::Result<ResolvedAdmit> {
    if !installed() {
        return Ok(ResolvedAdmit::Existing(path.to_path_buf()));
    }
    // Do not lock `SLOT` here. [`admit`] already holds it, and this mutex is
    // not re-entrant.
    resolve_installed(path)
}

fn resolve_installed(path: &Path) -> io::Result<ResolvedAdmit> {
    match path.canonicalize() {
        Ok(resolved) => Ok(ResolvedAdmit::Existing(resolved)),
        Err(err) if err.kind() == ErrorKind::NotFound => resolve_absent_final(path),
        Err(err) => Err(err),
    }
}

fn resolve_absent_final(path: &Path) -> io::Result<ResolvedAdmit> {
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    let Some(parent) = parent else {
        return Err(io::Error::new(
            ErrorKind::NotFound,
            format!("fork-n cannot resolve {}", path.display()),
        ));
    };
    // A missing intermediate directory is a missing ancestor, not Absent.
    let ancestor = parent.canonicalize()?;
    let mut composed = ancestor;
    if let Some(name) = path.file_name() {
        composed.push(name);
    }
    Ok(ResolvedAdmit::Absent(composed))
}

/// True when `path` is equal to or under an installed mountpoint or top.
pub fn cohort_contains(path: &Path) -> bool {
    let guard = SLOT.lock().unwrap_or_else(|e| e.into_inner());
    let Some(slot) = guard.as_ref() else {
        return false;
    };
    contained(path, &slot.mountpoints) || contained(path, &slot.tops)
}

/// What [`admit`] tells the caller to do with the path.
#[derive(Debug)]
pub enum Admitted {
    /// No cohort is installed. The caller opens or creates as it does today.
    Legacy,
    /// The path was opened here. Do not open it again.
    Opened(File),
    /// Containment passed and the file was not opened.
    Checked,
}

/// Admit `path` before the caller opens or creates it.
///
/// `open` asks admission to return the [`File`]. `overlay_owner` is the top
/// whose own database and companions are not a "under a top" hit. Mountpoint
/// containment still refuses those paths, and it is checked first.
pub fn admit(path: &Path, open: bool, overlay_owner: Option<&Path>) -> io::Result<Admitted> {
    let guard = SLOT.lock().unwrap_or_else(|e| e.into_inner());
    let Some(slot) = guard.as_ref() else {
        return Ok(Admitted::Legacy);
    };
    let resolved = resolve_installed(path).map_err(|err| {
        io::Error::new(
            err.kind(),
            format!("fork-n refuses to resolve {}: {err}", path.display()),
        )
    })?;
    let resolved_path = match resolved {
        ResolvedAdmit::Existing(path) | ResolvedAdmit::Absent(path) => path,
    };
    if contained(&resolved_path, &slot.mountpoints) {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            format!(
                "fork-n refuses {}: canonical path is under a cohort mountpoint",
                path.display()
            ),
        ));
    }
    let own_db = overlay_owner.is_some_and(|owner| is_own_overlay_db(&resolved_path, owner));
    if !own_db && contained(&resolved_path, &slot.tops) {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            format!(
                "fork-n refuses {}: canonical path is under a cohort top",
                path.display()
            ),
        ));
    }
    drop(guard);
    note_admit();
    if open {
        let file = File::open(path)?;
        Ok(Admitted::Opened(file))
    } else {
        Ok(Admitted::Checked)
    }
}

/// [`File::open`] when a cohort is installed, otherwise the caller's open.
/// Spy `open` increments once per successful call, not inside [`admit`].
pub fn open_admitted(path: &Path) -> io::Result<File> {
    let file = match admit(path, true, None)? {
        Admitted::Legacy | Admitted::Checked => File::open(path)?,
        Admitted::Opened(file) => file,
    };
    note_open();
    Ok(file)
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

/// Admit one top's database and the `-wal` / `-shm` / `-journal` beside it.
pub fn admit_overlay_db(db: &Path, owner: &Path) -> io::Result<()> {
    admit(db, false, Some(owner))?;
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut name = db.as_os_str().to_os_string();
        name.push(suffix);
        admit(Path::new(&name), false, Some(owner))?;
    }
    Ok(())
}

/// A create that admission allowed and that actually opened the new file.
pub fn note_create() {
    CREATE.fetch_add(1, Ordering::Relaxed);
    flush_spies();
}

/// A truncate that admission allowed and that actually opened the file.
pub fn note_truncate() {
    TRUNCATE.fetch_add(1, Ordering::Relaxed);
    flush_spies();
}

/// Write the spy file when the test environment variable is set.
pub fn flush_spies() {
    #[cfg(debug_assertions)]
    {
        let Ok(path) = std::env::var("RATARMOUNT_TEST_FORK_N_SPY_LOG") else {
            return;
        };
        let text = format!(
            "admit={}\nopen={}\ncreate={}\ntruncate={}\n",
            ADMIT.load(Ordering::Relaxed),
            OPEN.load(Ordering::Relaxed),
            CREATE.load(Ordering::Relaxed),
            TRUNCATE.load(Ordering::Relaxed),
        );
        let _ = std::fs::write(path, text);
    }
}

fn note_admit() {
    ADMIT.fetch_add(1, Ordering::Relaxed);
    flush_spies();
}

fn note_open() {
    OPEN.fetch_add(1, Ordering::Relaxed);
    flush_spies();
}

fn is_own_overlay_db(resolved: &Path, owner: &Path) -> bool {
    let owner = owner.canonicalize().unwrap_or_else(|_| owner.to_path_buf());
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
        || name == format!("{OVERLAY_DB_NAME}-wal")
        || name == format!("{OVERLAY_DB_NAME}-shm")
        || name == format!("{OVERLAY_DB_NAME}-journal")
}

fn contained(path: &Path, roots: &[PathBuf]) -> bool {
    roots
        .iter()
        .any(|root| path == root.as_path() || path.starts_with(root))
}
