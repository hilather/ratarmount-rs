//! Checked acquisition (design §5): the inode SQLite actually acquired.
//!
//! [`open_checked`] arms this thread, calls `sqlite3_open_v2` through
//! rusqlite, and judges the evidence the installed `open`/`stat` wrappers
//! collected inside SQLite's own acquisition:
//!
//! * a **fresh descriptor**: the first successful `O_NOFOLLOW` open (every
//!   database open of `unixOpen` carries it; housekeeping opens do not) is
//!   `fstat`ed before SQLite sees it. A mismatch is never returned to SQLite:
//!   a descriptor proved non-regular is closed, a regular or unidentifiable
//!   one is retained for the life of the process (it may be an inode this
//!   process holds POSIX locks on, and closing it would release them);
//! * a **reused descriptor** (SQLite's `findReusableFd`, no open): accepted
//!   only for an existing file, when at least one successful armed `stat`
//!   was seen and every one agreed.
//!
//! Every successful armed `stat` must agree; the first mismatch is kept.
//! Arming is thread-local: other threads' opens pass through unchanged.
//!
//! Standard descriptors: `robust_open` closes a descriptor below 3 before
//! SQLite ties it to an inode, so vacant slots 0-2 are filled with
//! `/dev/null` before arming and again immediately before the real open. If
//! another thread empties a slot in between (a contract violation), the
//! policy of design §5 "Low descriptors" applies. Where `/dev/null` cannot be
//! opened (a chroot without device nodes) the fill does nothing and that
//! policy is the only defense.
//!
//! Names (design §6): a relative path is made absolute (its final symlink is
//! not resolved). That is what keeps SQLite's URI syntax out: libsqlite3-sys
//! compiles `SQLITE_USE_URI`, so SQLite parses EVERY name that starts with
//! `file:` as a URI (whose `vfs=` would override the pinned VFS and whose
//! `modeof=` would `stat` another path inside the armed window), whether or
//! not the caller's flags carry `SQLITE_OPEN_URI`; a name starting with `/`
//! never does. [`NameMode::Immutable`] is the only URI: built here from the
//! absolute path, every byte outside `[A-Za-z0-9/._~-]` percent-encoded.

use std::fmt;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags};

use super::install::InstallStatus;

/// `(st_dev, st_ino)`.
pub type DbId = (u64, u64);

/// What the acquisition must find.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expect {
    /// The regular file classified before the open: same `(dev, ino)`, and
    /// non-empty when `require_nonempty` (a marked record).
    Existing { id: DbId, require_nonempty: bool },
    /// Nothing was at the path: the empty regular file SQLite creates. An
    /// empty file planted before the open is indistinguishable; this is not
    /// exclusive creation.
    Fresh,
}

/// How the name reaches SQLite.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameMode {
    Path,
    /// `file:<percent-encoded absolute path>?mode=ro&immutable=1`, built by
    /// this module. The flags must be read-only, without `SQLITE_OPEN_CREATE`.
    Immutable,
}

/// The evidence an [`Acquired`] rests on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verification {
    /// SQLite's own fresh descriptor was `fstat`ed before SQLite used it.
    UnixDescriptor,
    /// SQLite reused a parked descriptor; every successful selection `stat`
    /// reported the expected inode.
    UnixReuse,
    /// Windows: pathname type checks only, no identity (design §9).
    WindowsPathTypeOnly,
}

#[derive(Debug)]
pub struct Acquired {
    pub conn: Connection,
    pub id: Option<DbId>,
    pub verification: Verification,
    /// A standard descriptor (0-2) on the database that was duplicated to a
    /// higher slot and kept open. Diagnostic only; never owned by the caller.
    pub retained_low_fd: Option<i32>,
}

#[derive(Debug)]
pub struct Refusal {
    pub error: AcquireError,
    /// A descriptor this module kept open (never closed: it may be an inode
    /// this process holds locks on). Diagnostic only; never owned by the caller.
    pub retained_fd: Option<i32>,
}

#[derive(Debug)]
pub enum AcquireError {
    /// No wrappers are installed; checked opens fail closed.
    Unavailable(InstallStatus),
    InvalidRequest(&'static str),
    /// This thread is already inside a checked acquisition.
    Reentrant,
    NotRegular {
        mode: u32,
    },
    OtherFile {
        actual: DbId,
    },
    NotFresh {
        len: u64,
    },
    /// A marked record that is empty: a lost record, never an unrecorded one.
    EmptyRecord,
    Fstat(i32),
    DescriptorFlags(i32),
    /// A second database open within one acquisition.
    UnexpectedOpen,
    /// SQLite reused a descriptor and no successful `stat` vouched for it.
    ReusedUnverified,
    /// SQLite's open landed on a standard descriptor that could not be moved
    /// (`locks_may_be_released: false`; it is retained), or on writable
    /// stdout/stderr, which was re-pointed at `/dev/null`: that close may
    /// have released this process's locks on the inode.
    LowDescriptor {
        fd: i32,
        locks_may_be_released: bool,
    },
    Sqlite(rusqlite::Error),
}

impl fmt::Display for AcquireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(status) => write!(f, "checked SQLite open unavailable: {status}"),
            Self::InvalidRequest(why) => write!(f, "invalid checked SQLite open: {why}"),
            Self::Reentrant => write!(f, "nested checked SQLite open on one thread"),
            Self::NotRegular { mode } => {
                write!(f, "the database is not a regular file (mode {mode:o})")
            }
            Self::OtherFile { actual } => write!(
                f,
                "SQLite acquired another file (dev {}, inode {}) than the one classified",
                actual.0, actual.1
            ),
            Self::NotFresh { len } => write!(
                f,
                "a file ({len} bytes) appeared where no database was before the open"
            ),
            Self::EmptyRecord => write!(f, "the recorded database is empty (lost record)"),
            Self::Fstat(e) => write!(
                f,
                "fstat of SQLite's database descriptor failed: {}",
                std::io::Error::from_raw_os_error(*e)
            ),
            Self::DescriptorFlags(e) => write!(
                f,
                "restoring the database descriptor's flags failed: {}",
                std::io::Error::from_raw_os_error(*e)
            ),
            Self::UnexpectedOpen => write!(f, "a second database open in one acquisition"),
            Self::ReusedUnverified => {
                write!(f, "SQLite reused a descriptor that no stat vouched for")
            }
            Self::LowDescriptor {
                fd,
                locks_may_be_released,
            } => {
                write!(
                    f,
                    "SQLite's database open landed on standard descriptor {fd}; another thread \
                     closed it during the acquisition"
                )?;
                if *locks_may_be_released {
                    write!(
                        f,
                        "; it was re-pointed at /dev/null, which may have released this \
                         process's locks on the database"
                    )?;
                }
                Ok(())
            }
            Self::Sqlite(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for AcquireError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Sqlite(e) => Some(e),
            _ => None,
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.error)?;
        if let Some(fd) = self.retained_fd {
            write!(f, " (descriptor {fd} retained)")?;
        }
        Ok(())
    }
}

impl std::error::Error for Refusal {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.error.source()
    }
}

/// A validation failure latched during the acquisition (`Copy`, for TLS).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mismatch {
    NotRegular { mode: u32 },
    OtherFile { actual: DbId },
    NotFresh { len: u64 },
    EmptyRecord,
    Fstat(i32),
    DescriptorFlags(i32),
    UnexpectedOpen,
}

impl From<Mismatch> for AcquireError {
    fn from(m: Mismatch) -> Self {
        match m {
            Mismatch::NotRegular { mode } => Self::NotRegular { mode },
            Mismatch::OtherFile { actual } => Self::OtherFile { actual },
            Mismatch::NotFresh { len } => Self::NotFresh { len },
            Mismatch::EmptyRecord => Self::EmptyRecord,
            Mismatch::Fstat(e) => Self::Fstat(e),
            Mismatch::DescriptorFlags(e) => Self::DescriptorFlags(e),
            Mismatch::UnexpectedOpen => Self::UnexpectedOpen,
        }
    }
}

/// The fields of a `stat` result the judgment reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Seen {
    pub(crate) mode: u32,
    pub(crate) id: DbId,
    pub(crate) size: u64,
}

const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;

/// Judge one observation. `fresh_open`: it is the `fstat` of the descriptor
/// SQLite is about to receive (else a path `stat`); `accepted`: the identity
/// of an already accepted fresh descriptor.
pub(crate) fn judge(
    expect: Expect,
    seen: Seen,
    fresh_open: bool,
    accepted: Option<DbId>,
) -> Result<DbId, Mismatch> {
    if seen.mode & S_IFMT != S_IFREG {
        return Err(Mismatch::NotRegular { mode: seen.mode });
    }
    match expect {
        Expect::Existing {
            id,
            require_nonempty,
        } => {
            if seen.id != id {
                Err(Mismatch::OtherFile { actual: seen.id })
            } else if require_nonempty && seen.size == 0 {
                Err(Mismatch::EmptyRecord)
            } else {
                Ok(id)
            }
        }
        Expect::Fresh if fresh_open => {
            if seen.size != 0 {
                Err(Mismatch::NotFresh { len: seen.size })
            } else {
                Ok(seen.id)
            }
        }
        // A path stat: before the accepted open, something is already there;
        // afterwards it must be the accepted inode.
        Expect::Fresh => match accepted {
            None => Err(Mismatch::NotFresh { len: seen.size }),
            Some(id) if id == seen.id => Ok(id),
            Some(_) => Err(Mismatch::OtherFile { actual: seen.id }),
        },
    }
}

/// A standard descriptor the database open landed on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Low {
    pub(crate) fd: i32,
    /// Refuse the acquisition (the duplicate failed, or writable stdout/stderr).
    pub(crate) fatal: bool,
    pub(crate) released: bool,
}

/// The evidence of one acquisition: `Copy` scalars only, so the callbacks
/// neither allocate nor drop anything.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Acquisition {
    pub(crate) expect: Expect,
    /// The accepted fresh descriptor's identity.
    pub(crate) first: Option<DbId>,
    /// A database open succeeded (accepted or not).
    pub(crate) opened: bool,
    /// The first validation failure; never replaced.
    pub(crate) refusal: Option<Mismatch>,
    /// Successful armed stats (saturating).
    pub(crate) stats: u32,
    pub(crate) low: Option<Low>,
    /// A refused descriptor kept open for the life of the process.
    pub(crate) retained: Option<i32>,
}

impl Acquisition {
    pub(crate) const fn new(expect: Expect) -> Self {
        Self {
            expect,
            first: None,
            opened: false,
            refusal: None,
            stats: 0,
            low: None,
            retained: None,
        }
    }

    pub(crate) fn latch(&mut self, m: Mismatch) {
        if self.refusal.is_none() {
            self.refusal = Some(m);
        }
    }

    /// Record a successful armed `stat` (design §5 `checked_stat`).
    pub(crate) fn on_stat(&mut self, seen: Seen) {
        self.stats = self.stats.saturating_add(1);
        if let Err(m) = judge(self.expect, seen, false, self.first) {
            self.latch(m);
        }
    }

    /// Nothing more may be opened: refused, or a fatal low-descriptor event.
    pub(crate) fn decided(&self) -> bool {
        self.refusal.is_some() || self.low.is_some_and(|l| l.fatal)
    }
}

/// Design §5 "Final decision" (N3: an SQLite error after an accepted fresh
/// descriptor, with no latched mismatch and no low-descriptor event, is that
/// SQLite error). The evidence has already been taken and the thread disarmed.
pub(crate) fn decide(
    a: Acquisition,
    result: rusqlite::Result<Connection>,
) -> Result<Acquired, Refusal> {
    // A refusal reports what stays open: a retained descriptor, else a low
    // slot that was kept (not re-pointed) after its duplicate was handed on.
    let kept = a.retained.or(a.low.filter(|l| !l.released).map(|l| l.fd));
    let refuse = |error: AcquireError| Refusal {
        error,
        retained_fd: kept,
    };
    if let Some(low) = a.low.filter(|l| l.fatal) {
        drop(result);
        return Err(refuse(AcquireError::LowDescriptor {
            fd: low.fd,
            locks_may_be_released: low.released,
        }));
    }
    if let Some(m) = a.refusal {
        // A returned connection here was validated or reused; its close goes
        // through SQLite's `unixClose`, which re-parks it under any lock.
        drop(result);
        return Err(refuse(m.into()));
    }
    let conn = result.map_err(|e| refuse(AcquireError::Sqlite(e)))?;
    let retained_low_fd = a.low.map(|l| l.fd);
    match (a.first, a.expect) {
        (Some(id), _) => Ok(Acquired {
            conn,
            id: Some(id),
            verification: Verification::UnixDescriptor,
            retained_low_fd,
        }),
        (None, Expect::Existing { id, .. }) if a.stats > 0 => Ok(Acquired {
            conn,
            id: Some(id),
            verification: Verification::UnixReuse,
            retained_low_fd,
        }),
        _ => {
            drop(conn);
            Err(refuse(AcquireError::ReusedUnverified))
        }
    }
}

/// The `file:` URI of [`NameMode::Immutable`] for the absolute `path`.
pub fn immutable_uri(path: &Path) -> String {
    use std::fmt::Write;
    let mut uri = String::from("file:");
    for byte in path.as_os_str().as_encoded_bytes() {
        if byte.is_ascii_alphanumeric() || b"/-._~".contains(byte) {
            uri.push(*byte as char);
        } else {
            write!(&mut uri, "%{byte:02X}").expect("write URI");
        }
    }
    uri.push_str("?mode=ro&immutable=1");
    uri
}

/// Validate the request (before anything is armed): the name SQLite gets
/// (see the module docs) and its flags.
pub(crate) fn request(
    path: &Path,
    flags: OpenFlags,
    mode: NameMode,
    expect: Expect,
) -> Result<Request, AcquireError> {
    if flags.intersects(OpenFlags::SQLITE_OPEN_MEMORY | OpenFlags::SQLITE_OPEN_SHARED_CACHE) {
        return Err(AcquireError::InvalidRequest(
            "memory and shared-cache databases bypass the acquisition evidence",
        ));
    }
    if mode == NameMode::Immutable
        && (flags.intersects(OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE)
            || !flags.contains(OpenFlags::SQLITE_OPEN_READ_ONLY))
    {
        return Err(AcquireError::InvalidRequest(
            "an immutable open must be read-only, without SQLITE_OPEN_CREATE",
        ));
    }
    // Not canonicalized: the final component may be a symlink SQLite follows
    // (or refuses under SQLITE_OPEN_NOFOLLOW) itself.
    let path = std::path::absolute(path)
        .map_err(|_| AcquireError::InvalidRequest("the path cannot be made absolute"))?;
    // Stripping SQLITE_OPEN_URI does not stop URI parsing (see the module
    // docs); the absolute name does. It is only added back for the URI built
    // here.
    let mut flags = (flags - OpenFlags::SQLITE_OPEN_URI) | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE;
    // An existing file that vanished must not be created anew (and then
    // refused and retained as a 0-byte file).
    if matches!(expect, Expect::Existing { .. }) {
        flags -= OpenFlags::SQLITE_OPEN_CREATE;
    }
    let name = match mode {
        NameMode::Path => path.clone(),
        NameMode::Immutable => {
            flags |= OpenFlags::SQLITE_OPEN_URI;
            PathBuf::from(immutable_uri(&path))
        }
    };
    Ok(Request { path, name, flags })
}

/// A validated request.
#[derive(Debug)]
pub(crate) struct Request {
    /// The absolute path of the database.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub(crate) path: PathBuf,
    /// What SQLite gets: `path`, or the immutable URI.
    pub(crate) name: PathBuf,
    pub(crate) flags: OpenFlags,
}

/// Open `path` and prove which inode SQLite acquired.
pub fn open_checked(
    path: &Path,
    flags: OpenFlags,
    mode: NameMode,
    expect: Expect,
) -> Result<Acquired, Refusal> {
    let refuse = |error| Refusal {
        error,
        retained_fd: None,
    };
    let request = request(path, flags, mode, expect).map_err(refuse)?;
    #[cfg(windows)]
    return path_type_only::open(&request, expect);
    #[cfg(not(windows))]
    {
        if let Err(status) = super::install::installed() {
            return Err(refuse(AcquireError::Unavailable(status)));
        }
        // F6 (r11 S6): the VFS and the two syscall slots still hold what the
        // installation left; checked before arming, never repaired.
        if let Err(reason) = super::install::hooks_intact() {
            return Err(refuse(AcquireError::Unavailable(
                super::install::InstallStatus::HooksReplaced(reason),
            )));
        }
        imp::open(&request.name, request.flags, expect)
    }
}

/// Windows (design §9): no syscall hook, so pathname type checks before and
/// after the open, and no identity ([`Verification::WindowsPathTypeOnly`]).
/// SQLite's Windows VFS ignores `SQLITE_OPEN_NOFOLLOW`, so both checks use
/// `lstat` semantics under that flag: a final-component symlink substituted
/// after the first check is refused by the second. Compiled into Unix tests
/// too, which pin that substitution.
#[cfg(any(windows, test))]
pub(crate) mod path_type_only {
    use std::fs;

    use rusqlite::{Connection, OpenFlags};

    use super::{AcquireError, Acquired, Expect, Refusal, Request, Verification};

    #[cfg(test)]
    thread_local! {
        /// Runs once between SQLite's open and the check after it.
        pub(crate) static AFTER_OPEN: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
            const { std::cell::RefCell::new(None) };
    }

    pub(crate) fn check(
        request: &Request,
        expect: Expect,
        after: bool,
    ) -> Result<(), AcquireError> {
        let entry = if request.flags.contains(OpenFlags::SQLITE_OPEN_NOFOLLOW) {
            fs::symlink_metadata(&request.path)
        } else {
            fs::metadata(&request.path)
        };
        match entry {
            Ok(m) if !m.is_file() => Err(AcquireError::NotRegular { mode: 0 }),
            Ok(m) => match expect {
                Expect::Fresh if !after && m.len() > 0 => {
                    Err(AcquireError::NotFresh { len: m.len() })
                }
                Expect::Existing {
                    require_nonempty: true,
                    ..
                } if m.len() == 0 => Err(AcquireError::EmptyRecord),
                _ => Ok(()),
            },
            // Missing before the open: SQLite creates it or fails itself.
            Err(_) if !after => Ok(()),
            Err(e) => Err(AcquireError::Fstat(e.raw_os_error().unwrap_or(0))),
        }
    }

    pub(crate) fn open(request: &Request, expect: Expect) -> Result<Acquired, Refusal> {
        let refuse = |error| Refusal {
            error,
            retained_fd: None,
        };
        check(request, expect, false).map_err(refuse)?;
        let conn = Connection::open_with_flags(&request.name, request.flags)
            .map_err(|e| refuse(AcquireError::Sqlite(e)))?;
        #[cfg(test)]
        if let Some(hook) = AFTER_OPEN.with(|h| h.borrow_mut().take()) {
            hook();
        }
        check(request, expect, true).map_err(refuse)?;
        Ok(Acquired {
            conn,
            id: None,
            verification: Verification::WindowsPathTypeOnly,
            retained_low_fd: None,
        })
    }
}

/// Regression (S3 skeptic #1): the Windows path-type-only open ignored
/// `SQLITE_OPEN_NOFOLLOW` (both checks followed symlinks), so a final
/// component replaced by a symlink after the first check was accepted.
#[cfg(all(test, unix))]
mod path_type_only_tests {
    use std::fs;

    use rusqlite::{Connection, OpenFlags};

    use super::path_type_only::{check, open, AFTER_OPEN};
    use super::{request, AcquireError, Expect, NameMode, Verification};

    const RO: OpenFlags = OpenFlags::SQLITE_OPEN_READ_ONLY;

    /// The Windows check ignores the identity.
    fn existing() -> Expect {
        Expect::Existing {
            id: (0, 0),
            require_nonempty: true,
        }
    }

    #[test]
    fn regression_path_type_only_open_honours_nofollow() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.sqlite");
        let other = dir.path().join("other.sqlite");
        for p in [&a, &other] {
            Connection::open(p)
                .unwrap()
                .execute_batch("CREATE TABLE t(x)")
                .unwrap();
        }
        let link = dir.path().join("link.sqlite");
        std::os::unix::fs::symlink(&other, &link).unwrap();

        // A symlink at the name: refused before the open under NOFOLLOW,
        // followed without it.
        let nofollow = request(
            &link,
            RO | OpenFlags::SQLITE_OPEN_NOFOLLOW,
            NameMode::Path,
            existing(),
        )
        .unwrap();
        assert!(matches!(
            check(&nofollow, existing(), false),
            Err(AcquireError::NotRegular { .. })
        ));
        let follow = request(&link, RO, NameMode::Path, existing()).unwrap();
        check(&follow, existing(), false).unwrap();

        // Substituted after SQLite's open: the check after it refuses.
        let substitute = || {
            let (a, other) = (a.clone(), other.clone());
            AFTER_OPEN.with(|h| {
                *h.borrow_mut() = Some(Box::new(move || {
                    fs::remove_file(&a).unwrap();
                    std::os::unix::fs::symlink(&other, &a).unwrap();
                }))
            });
        };
        substitute();
        let req = request(
            &a,
            RO | OpenFlags::SQLITE_OPEN_NOFOLLOW,
            NameMode::Path,
            existing(),
        )
        .unwrap();
        let Err(refusal) = open(&req, existing()) else {
            panic!("a symlink substituted after the open must be refused");
        };
        assert!(
            matches!(refusal.error, AcquireError::NotRegular { .. }),
            "{:?}",
            refusal.error
        );

        // Without NOFOLLOW the symlink to a regular file is followed.
        fs::remove_file(&a).unwrap();
        Connection::open(&a)
            .unwrap()
            .execute_batch("CREATE TABLE t(x)")
            .unwrap();
        substitute();
        let req = request(&a, RO, NameMode::Path, existing()).unwrap();
        let acquired = open(&req, existing()).expect("followed without NOFOLLOW");
        assert_eq!(acquired.verification, Verification::WindowsPathTypeOnly);
        assert!(acquired.id.is_none());
    }
}

#[cfg(all(
    target_pointer_width = "64",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_endian = "little",
    any(all(target_os = "linux", target_env = "gnu"), target_os = "macos")
))]
pub(crate) mod imp {
    use std::cell::Cell;
    use std::os::raw::{c_char, c_int};
    use std::path::Path;

    use rusqlite::{Connection, OpenFlags};

    use super::{
        decide, AcquireError, Acquired, Acquisition, Expect, Low, Mismatch, Refusal, Seen,
    };

    /// The VFS whose syscall table carries the wrappers (design §6).
    const VFS: &str = if cfg!(target_os = "macos") {
        "unix-posix"
    } else {
        "unix"
    };

    pub(crate) type RealOpen = unsafe extern "C" fn(*const c_char, c_int, c_int) -> c_int;
    pub(crate) type RealStat = unsafe extern "C" fn(*const c_char, *mut libc::stat) -> c_int;

    thread_local! {
        static ARMED: Cell<Option<Acquisition>> = const { Cell::new(None) };
        /// Set for the whole acquisition, independently of `ARMED`: the
        /// callbacks take the evidence out of `ARMED` while they run, so a
        /// nested `open_checked` from inside one (another library's wrapper
        /// of SQLite's `open`, a test seam) must still see this thread busy.
        static ACTIVE: Cell<bool> = const { Cell::new(false) };
    }

    /// Read errno directly (no std machinery inside the callbacks).
    fn errno() -> c_int {
        #[cfg(target_os = "linux")]
        let e = unsafe { *libc::__errno_location() };
        #[cfg(target_os = "macos")]
        let e = unsafe { *libc::__error() };
        e
    }

    pub(crate) fn set_errno(e: c_int) {
        #[cfg(target_os = "linux")]
        unsafe {
            *libc::__errno_location() = e
        };
        #[cfg(target_os = "macos")]
        unsafe {
            *libc::__error() = e
        };
    }

    /// Arms this thread; disarms on every exit.
    pub(crate) struct ArmGuard(());

    /// How many acquisitions this process armed (tests: a refusal before
    /// arming leaves it unchanged).
    #[cfg(test)]
    pub(crate) static ARMS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

    impl ArmGuard {
        pub(crate) fn arm(expect: Expect) -> Result<Self, AcquireError> {
            #[cfg(test)]
            ARMS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let gone =
                AcquireError::InvalidRequest("thread-local storage is gone (thread exiting)");
            let Ok(active) = ACTIVE.try_with(|c| c.replace(true)) else {
                return Err(gone);
            };
            if active {
                return Err(AcquireError::Reentrant);
            }
            ARMED
                .try_with(|cell| {
                    let outer = cell.replace(Some(Acquisition::new(expect)));
                    debug_assert!(outer.is_none(), "evidence without an active marker");
                })
                .map(|()| Self(()))
                .map_err(|_| {
                    let _ = ACTIVE.try_with(|c| c.set(false));
                    gone
                })
        }

        /// Take the evidence and disarm.
        pub(crate) fn finish(self) -> Acquisition {
            let a = ARMED.with(|c| c.take());
            let _ = ACTIVE.try_with(|c| c.set(false));
            std::mem::forget(self);
            a.expect("armed acquisition")
        }

        #[cfg(test)]
        pub(crate) fn active() -> bool {
            ACTIVE.with(|c| c.get())
        }

        #[cfg(test)]
        pub(crate) fn peek() -> Option<Acquisition> {
            ARMED.with(|c| c.get())
        }

        #[cfg(test)]
        pub(crate) fn update(f: impl FnOnce(&mut Acquisition)) {
            ARMED.with(|c| {
                let mut a = c.take().expect("armed");
                f(&mut a);
                c.set(Some(a));
            })
        }
    }

    impl Drop for ArmGuard {
        fn drop(&mut self) {
            let _ = ARMED.try_with(|c| c.set(None));
            let _ = ACTIVE.try_with(|c| c.set(false));
        }
    }

    /// Occupy vacant slots 0-2 with `/dev/null` (no `O_CLOEXEC` there),
    /// closing only the first descriptor of our own at 3 or above. No `dup2`:
    /// a slot is never replaced, only filled while empty.
    pub(crate) fn fill_low_descriptors() {
        let saved = errno();
        loop {
            // SAFETY: a constant C string; the descriptor is ours.
            let fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR) };
            if fd < 0 {
                break;
            }
            if fd >= 3 {
                unsafe { libc::close(fd) };
                break;
            }
        }
        set_errno(saved);
    }

    fn set_cloexec(fd: c_int) {
        // SAFETY: plain fcntl on a descriptor we hold.
        unsafe {
            let f = libc::fcntl(fd, libc::F_GETFD);
            if f >= 0 {
                libc::fcntl(fd, libc::F_SETFD, f | libc::FD_CLOEXEC);
            }
        }
    }

    /// Writable stdout/stderr on the database: re-point the slot at
    /// `/dev/null` (the close may release this process's locks). If that
    /// fails, terminate rather than keep database-backed stdout/stderr.
    fn repoint_to_devnull(fd: c_int) {
        // SAFETY: plain syscalls on descriptors of this process.
        unsafe {
            let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC);
            if null < 0 || libc::dup2(null, fd) < 0 {
                libc::_exit(127);
            }
            libc::close(null);
        }
    }

    // The casts widen on macOS (`u16` mode, `i32` device).
    #[allow(clippy::unnecessary_cast)]
    fn seen(st: &libc::stat) -> Seen {
        Seen {
            mode: st.st_mode as u32,
            id: (st.st_dev as u64, st.st_ino as u64),
            size: st.st_size as u64,
        }
    }

    /// The installed `open` wrapper. Unarmed (or a TLS failure): forward
    /// unchanged. No allocation, logging, registry lock or unwinding.
    ///
    /// # Safety
    ///
    /// The arguments of SQLite's `"open"` system call; `real` is the captured
    /// original.
    pub(crate) unsafe fn on_open(
        real: RealOpen,
        path: *const c_char,
        flags: c_int,
        mode: c_int,
    ) -> c_int {
        let taken = ARMED.try_with(|c| c.take());
        let Ok(Some(mut a)) = taken else {
            return unsafe { real(path, flags, mode) };
        };
        let fd = unsafe { armed_open(&mut a, real, path, flags, mode) };
        let e = errno();
        let _ = ARMED.try_with(|c| c.set(Some(a)));
        set_errno(e);
        fd
    }

    #[allow(clippy::unnecessary_cast)] // `u16` mode on macOS
    unsafe fn armed_open(
        a: &mut Acquisition,
        real: RealOpen,
        path: *const c_char,
        flags: c_int,
        mode: c_int,
    ) -> c_int {
        // Housekeeping (the `/dev/null` placeholder of `robust_open`, ...).
        if flags & libc::O_NOFOLLOW == 0 {
            return unsafe { real(path, flags, mode) };
        }
        if a.decided() || a.opened {
            if !a.decided() {
                a.latch(Mismatch::UnexpectedOpen);
            }
            #[cfg(any(test, feature = "test-hooks"))]
            seams::fire(seams::Seam::RefusedOpen);
            set_errno(libc::EACCES);
            return -1;
        }
        fill_low_descriptors();
        #[cfg(any(test, feature = "test-hooks"))]
        seams::fire(seams::Seam::AfterLowFdFill);
        let fd = unsafe { real(path, flags | libc::O_NONBLOCK, mode) };
        if fd < 0 {
            // SQLite's ordinary retry (read-write, then read-only) may follow.
            return fd;
        }
        a.opened = true;
        #[cfg(any(test, feature = "test-hooks"))]
        {
            let e = errno();
            seams::fire(seams::Seam::AfterRealOpen);
            set_errno(e);
        }
        // SAFETY: `st` is written by fstat before it is read.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::fstat(fd, &mut st) };
        let fstat_errno = if rc == 0 { 0 } else { errno() };
        #[cfg(any(test, feature = "test-hooks"))]
        let (rc, fstat_errno) = match seams::fstat_failure() {
            Some(e) => (-1, e),
            None => (rc, fstat_errno),
        };
        let judged = if rc == 0 {
            super::judge(a.expect, seen(&st), true, None)
        } else {
            Err(Mismatch::Fstat(fstat_errno))
        };
        // Below 3, the window policy comes first, whatever the judgment.
        let mut fd = fd;
        if fd < 3 {
            let writable = flags & libc::O_ACCMODE != libc::O_RDONLY;
            if writable && fd != 0 {
                repoint_to_devnull(fd);
                a.low = Some(Low {
                    fd,
                    fatal: true,
                    released: true,
                });
                set_errno(libc::EACCES);
                return -1;
            }
            set_cloexec(fd);
            // SAFETY: duplicate a descriptor we hold.
            let hi = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
            if hi < 0 {
                a.low = Some(Low {
                    fd,
                    fatal: true,
                    released: false,
                });
                set_errno(libc::EMFILE);
                return -1;
            }
            a.low = Some(Low {
                fd,
                fatal: false,
                released: false,
            });
            fd = hi;
        }
        let id = match judged {
            Ok(id) => id,
            Err(m) => {
                let not_regular = rc == 0 && (st.st_mode as u32) & super::S_IFMT != super::S_IFREG;
                if not_regular {
                    // A FIFO, device or directory cannot be a database of ours.
                    unsafe { libc::close(fd) };
                } else {
                    set_cloexec(fd);
                    a.retained = Some(fd);
                }
                a.latch(m);
                set_errno(libc::EACCES);
                return -1;
            }
        };
        if flags & libc::O_NONBLOCK == 0 {
            // SAFETY: plain fcntl on a descriptor we hold.
            let fl = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if fl < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, fl & !libc::O_NONBLOCK) } < 0 {
                a.latch(Mismatch::DescriptorFlags(errno()));
                set_cloexec(fd);
                a.retained = Some(fd);
                set_errno(libc::EACCES);
                return -1;
            }
        }
        a.first = Some(id);
        fd
    }

    /// The installed `stat` wrapper: the original's result, always; a
    /// successful armed stat is judged and counted.
    ///
    /// # Safety
    ///
    /// The arguments of SQLite's `"stat"` system call; `real` is the captured
    /// original.
    pub(crate) unsafe fn on_stat(
        real: RealStat,
        path: *const c_char,
        buf: *mut libc::stat,
    ) -> c_int {
        let rc = unsafe { real(path, buf) };
        if rc != 0 {
            return rc;
        }
        let e = errno();
        if let Ok(Some(mut a)) = ARMED.try_with(|c| c.take()) {
            // SAFETY: the original filled `buf`.
            a.on_stat(seen(unsafe { &*buf }));
            #[cfg(any(test, feature = "test-hooks"))]
            seams::fire(seams::Seam::AfterArmedStat(a.stats));
            let _ = ARMED.try_with(|c| c.set(Some(a)));
        }
        set_errno(e);
        rc
    }

    pub(super) fn open(path: &Path, flags: OpenFlags, expect: Expect) -> Result<Acquired, Refusal> {
        fill_low_descriptors();
        let guard = ArmGuard::arm(expect).map_err(|error| Refusal {
            error,
            retained_fd: None,
        })?;
        let result = Connection::open_with_flags_and_vfs(path, flags, VFS);
        let a = guard.finish();
        decide(a, result)
    }

    /// Test seams: thread-local, so parallel tests never see each other's.
    /// Other crates' tests reach them through the `test-hooks` feature
    /// (`checked_open::test_seams`); a normal build has none.
    #[cfg(any(test, feature = "test-hooks"))]
    pub mod seams {
        use std::cell::{Cell, RefCell};

        #[allow(clippy::enum_variant_names)]
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum Seam {
            /// In the `open` wrapper, after the low-descriptor fill.
            AfterLowFdFill,
            /// After SQLite's real database `open` succeeded.
            AfterRealOpen,
            /// In the `open` wrapper, a second database `open` refused before
            /// any real `open` (the acquisition is decided or already opened).
            RefusedOpen,
            /// After the n-th successful armed `stat`. Runs under SQLite's
            /// global unix mutex during `findReusableFd`: filesystem only.
            AfterArmedStat(u32),
        }

        type Hook = Box<dyn FnMut(Seam)>;

        thread_local! {
            static HOOK: RefCell<Option<Hook>> = const { RefCell::new(None) };
            static FSTAT: Cell<Option<i32>> = const { Cell::new(None) };
        }

        /// A `RATARMOUNT_TEST_` string in every binary built with these
        /// seams, so `packaging/test-no-test-hooks-in-release.sh` finds a
        /// `test-hooks` build (the seams have no environment name of their
        /// own).
        pub const RELEASE_MARKER: &str = "RATARMOUNT_TEST_CHECKED_OPEN_SEAMS";

        pub(crate) fn fire(seam: Seam) {
            std::hint::black_box(RELEASE_MARKER);
            HOOK.with(|h| {
                if let Some(f) = h.borrow_mut().as_mut() {
                    f(seam)
                }
            })
        }

        pub(crate) fn fstat_failure() -> Option<i32> {
            FSTAT.with(|c| c.get())
        }

        /// Removes the seams of this thread when dropped.
        pub struct Seams;

        impl Seams {
            pub fn set(hook: impl FnMut(Seam) + 'static) -> Self {
                HOOK.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
                Self
            }
            pub fn fail_fstat(self, errno: i32) -> Self {
                FSTAT.with(|c| c.set(Some(errno)));
                self
            }
        }

        impl Drop for Seams {
            fn drop(&mut self) {
                HOOK.with(|h| *h.borrow_mut() = None);
                FSTAT.with(|c| c.set(None));
            }
        }
    }
}

/// Targets without verified wrappers: `installed()` already refused.
#[cfg(not(all(
    target_pointer_width = "64",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_endian = "little",
    any(all(target_os = "linux", target_env = "gnu"), target_os = "macos")
)))]
mod imp {
    use std::path::Path;

    use rusqlite::OpenFlags;

    use super::{AcquireError, Acquired, Expect, Refusal};

    pub(super) fn open(_: &Path, _: OpenFlags, _: Expect) -> Result<Acquired, Refusal> {
        Err(Refusal {
            error: AcquireError::Unavailable(super::super::install::installed().err().unwrap_or(
                if cfg!(unix) {
                    super::InstallStatus::UnsupportedAbi
                } else {
                    super::InstallStatus::UnsupportedPlatform
                },
            )),
            retained_fd: None,
        })
    }
}

#[cfg(all(
    test,
    target_pointer_width = "64",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_endian = "little",
    any(all(target_os = "linux", target_env = "gnu"), target_os = "macos")
))]
#[path = "acquire_tests.rs"]
mod tests;
