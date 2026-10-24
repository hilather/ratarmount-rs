//! Installation of the `open`/`stat` wrappers (design §3).
//!
//! Two independent once cells: the constructor's observation, and the terminal
//! installation result. A constructor that abstains (more than one thread, or
//! an unknown count) records only its observation, so a later permitted
//! private-instance initializer can still install. Whatever the installer
//! returns, success or failure, is terminal: pointer mutation is never retried.

use std::ffi::CStr;
use std::fmt;
use std::sync::OnceLock;

use rusqlite::ffi;

use super::elf::ExportFailure;
use super::host::{host_object, same_private_image, HostFailure, ImageIdentity, Lookup};

/// What the load-time constructor saw.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CtorObservation {
    /// Exactly one thread: the constructor ran the installer.
    AttemptedSingleThread,
    /// More than one thread, or `None` when the count could not be read: the
    /// constructor did not touch SQLite.
    AbstainedThreads(Option<u32>),
}

/// Which exclusion proof allowed the installation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallWhy {
    SingleThread,
    PrivateInstance,
}

/// A successful installation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Witness {
    pub why: InstallWhy,
    pub threads_at_install: Option<u32>,
    /// How many exported dynamic symbols the Linux private-instance proof
    /// inspected (none starts with `sqlite3`). `None` for the single-thread
    /// constructor and on macOS, whose proof keeps the one-name probe.
    /// Diagnostic evidence, not another authorization.
    pub exports_checked: Option<u32>,
}

/// Why the installer failed. Terminal: the installer never runs twice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallFailure {
    SqliteInitialize(i32),
    VfsMissing(&'static str),
    VfsVersion {
        vfs: &'static str,
        version: i32,
    },
    NoSyscallInterface(&'static str),
    /// macOS: `"unix-posix"` does not share `"unix"`'s syscall table.
    VfsSyscallsDiffer,
    /// The VFS has no current pointer for this syscall.
    OriginalMissing(&'static str),
    /// `xSetSystemCall` returned this SQLite code.
    Set {
        name: &'static str,
        rc: i32,
    },
    /// The getter did not return the pointer just set.
    Verify(&'static str),
    /// An earlier installation attempt already published other original
    /// pointers than the ones now in the slots.
    OriginalsDiffer,
    /// Private-instance path: a VFS method lives in another image.
    ForeignVfs(HostFailure),
    /// Undoing a partial installation failed for this syscall: the slot holds
    /// neither the captured pointer nor (necessarily) the wrapper. Installed
    /// wrappers stay unarmed pass-throughs; checked opens stay disabled.
    RestoreFailed(&'static str),
}

impl fmt::Display for InstallFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SqliteInitialize(rc) => write!(f, "sqlite3_initialize returned {rc}"),
            Self::VfsMissing(vfs) => write!(f, "SQLite has no {vfs:?} VFS"),
            Self::VfsVersion { vfs, version } => {
                write!(f, "SQLite VFS {vfs:?} is version {version}, need 3")
            }
            Self::NoSyscallInterface(vfs) => {
                write!(f, "SQLite VFS {vfs:?} has no system-call interface")
            }
            Self::VfsSyscallsDiffer => {
                write!(
                    f,
                    "SQLite VFS \"unix-posix\" does not share the \"unix\" system calls"
                )
            }
            Self::OriginalMissing(name) => write!(f, "SQLite has no {name:?} system call"),
            Self::Set { name, rc } => {
                write!(f, "setting SQLite's {name:?} system call returned {rc}")
            }
            Self::Verify(name) => {
                write!(f, "SQLite's {name:?} system call did not take the wrapper")
            }
            Self::OriginalsDiffer => write!(
                f,
                "SQLite's system calls differ from the originals an earlier install captured"
            ),
            Self::ForeignVfs(host) => write!(f, "SQLite VFS method check: {host}"),
            Self::RestoreFailed(name) => {
                write!(
                    f,
                    "restoring SQLite's {name:?} system call after a failed install failed"
                )
            }
        }
    }
}

/// Why checked opens are unavailable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallStatus {
    /// No constructor ran and no private initializer succeeded.
    NotRun,
    /// The constructor abstained (thread count, `None` = unreadable) and no
    /// private initializer has installed since.
    AbstainedThreads(Option<u32>),
    /// The private-instance loader check refused.
    NotPrivate(HostFailure),
    Failed(InstallFailure),
    UnsupportedPlatform,
    /// A Unix target whose `stat` layout and loader proof are not verified
    /// (32-bit, musl, BSDs, ...).
    UnsupportedAbi,
    /// Acquisition only (r11 S6, F6): the installation succeeded, but the
    /// selected VFS or one of the two syscall slots no longer holds what it
    /// left (named here). Never stored: [`installed`] keeps reporting the
    /// historical installation result. Nothing is repaired; restoring the
    /// exact state lets later acquisitions proceed.
    HooksReplaced(&'static str),
}

impl fmt::Display for InstallStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const CONTRACT: &str = "the SQLite system-call wrappers are installed only while the \
                                process has exactly one thread, or by a private-instance initializer";
        match self {
            Self::NotRun => write!(f, "the SQLite system-call wrappers were never installed"),
            Self::AbstainedThreads(Some(n)) => {
                write!(f, "the process had {n} threads at load time; {CONTRACT}")
            }
            Self::AbstainedThreads(None) => write!(
                f,
                "the thread count could not be read at load time ({}); {CONTRACT}",
                THREAD_COUNT_SOURCE
            ),
            Self::NotPrivate(host) => write!(f, "not a private SQLite instance: {host}"),
            Self::Failed(failure) => {
                write!(
                    f,
                    "installing the SQLite system-call wrappers failed: {failure}"
                )
            }
            Self::UnsupportedPlatform => {
                write!(f, "checked SQLite opens are not supported on this platform")
            }
            Self::UnsupportedAbi => {
                write!(
                    f,
                    "checked SQLite opens are not verified for this target's ABI"
                )
            }
            Self::HooksReplaced(reason) if *reason == NO_SNAPSHOT => write!(
                f,
                "the SQLite system-call wrappers were installed, but {reason} \
                 (an internal fault of the installation, not outside code)"
            ),
            Self::HooksReplaced(reason) => write!(
                f,
                "the SQLite system-call wrappers were installed, but {reason}; \
                 something reconfigured SQLite after the installation"
            ),
        }
    }
}

/// F6: the installation result exists but its VFS snapshot does not (an
/// internal fault: the installer publishes the snapshot before the result).
pub(crate) const NO_SNAPSHOT: &str = "no snapshot of the installation was published";

/// Where the constructor reads the thread count, for the abstention message.
const THREAD_COUNT_SOURCE: &str = if cfg!(target_os = "linux") {
    "/proc/self/stat was unreadable or malformed; is /proc masked?"
} else if cfg!(target_os = "macos") {
    "proc_pidinfo(PROC_PIDTASKINFO) failed"
} else {
    "no thread-count source on this platform"
};

/// The two once cells of design §3.
pub(crate) struct InstallState {
    ctor: OnceLock<CtorObservation>,
    install: OnceLock<Result<Witness, InstallFailure>>,
}

impl InstallState {
    pub(crate) const fn new() -> Self {
        Self {
            ctor: OnceLock::new(),
            install: OnceLock::new(),
        }
    }

    /// The constructor entry: install only with exactly one thread; otherwise
    /// record the observation and leave the installation cell empty.
    pub(crate) fn constructor(
        &self,
        threads: Option<u32>,
        install: impl FnOnce(InstallWhy) -> Result<Witness, InstallFailure>,
    ) {
        if threads == Some(1) {
            let _ = self.ctor.set(CtorObservation::AttemptedSingleThread);
            self.install
                .get_or_init(|| install(InstallWhy::SingleThread));
        } else {
            let _ = self.ctor.set(CtorObservation::AbstainedThreads(threads));
        }
    }

    pub(crate) fn observation(&self) -> Option<CtorObservation> {
        self.ctor.get().copied()
    }

    /// `installed()`: never installs.
    pub(crate) fn status(&self) -> Result<Witness, InstallStatus> {
        match self.install.get() {
            Some(result) => result.map_err(InstallStatus::Failed),
            None => Err(match self.ctor.get() {
                Some(CtorObservation::AbstainedThreads(n)) => InstallStatus::AbstainedThreads(*n),
                _ => InstallStatus::NotRun,
            }),
        }
    }

    /// The private initializer: a terminal result is returned unchanged; a
    /// failed proof leaves the cell empty; a passed proof runs the installer
    /// at most once across all callers.
    pub(crate) fn private<P>(
        &self,
        proof: impl FnOnce() -> Result<P, HostFailure>,
        install: impl FnOnce(P) -> Result<Witness, InstallFailure>,
    ) -> Result<Witness, InstallStatus> {
        if let Some(result) = self.install.get() {
            return result.map_err(InstallStatus::Failed);
        }
        let proved = proof().map_err(InstallStatus::NotPrivate)?;
        (*self.install.get_or_init(|| install(proved))).map_err(InstallStatus::Failed)
    }
}

pub(crate) type SyscallPtr = ffi::sqlite3_syscall_ptr;
pub(crate) type ErasedFn = unsafe extern "C" fn();

/// `xGetSystemCall` / `xSetSystemCall` of one VFS (or a test fake).
pub(crate) trait SyscallTable {
    fn get(&self, name: &CStr) -> SyscallPtr;
    fn set(&self, name: &CStr, f: SyscallPtr) -> std::os::raw::c_int;
}

/// The pointers SQLite used before the wrappers were installed.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Originals {
    pub(crate) open: ErasedFn,
    pub(crate) stat: ErasedFn,
}

fn addr(f: SyscallPtr) -> usize {
    f.map_or(0, |f| f as usize)
}

/// Steps 3-7 of design §3: capture both pointers, publish them, set `open`
/// then `stat` and verify each by the getter. On a failure after the first
/// mutation, restore the exact captured pointers (never null: SQLite maps null
/// to its built-in default, which need not be what was captured) and verify.
pub(crate) fn install_overrides(
    table: &dyn SyscallTable,
    originals: &OnceLock<Originals>,
    open_hook: ErasedFn,
    stat_hook: ErasedFn,
) -> Result<(), InstallFailure> {
    let open = table
        .get(c"open")
        .ok_or(InstallFailure::OriginalMissing("open"))?;
    let stat = table
        .get(c"stat")
        .ok_or(InstallFailure::OriginalMissing("stat"))?;
    let saved = *originals.get_or_init(|| Originals { open, stat });
    if saved.open as usize != open as usize || saved.stat as usize != stat as usize {
        // Another installation already published different originals.
        return Err(InstallFailure::OriginalsDiffer);
    }
    let slots: [(&CStr, &'static str, ErasedFn, ErasedFn); 2] = [
        (c"open", "open", open, open_hook),
        (c"stat", "stat", stat, stat_hook),
    ];
    for (i, &(name, label, _, hook)) in slots.iter().enumerate() {
        let rc = table.set(name, Some(hook));
        let failure = if rc != ffi::SQLITE_OK {
            Some(InstallFailure::Set { name: label, rc })
        } else if addr(table.get(name)) != hook as usize {
            Some(InstallFailure::Verify(label))
        } else {
            None
        };
        if let Some(failure) = failure {
            // Restore every slot touched so far, this one included, newest
            // first; a slot that still holds its captured pointer is left alone.
            for &(name, label, captured, _) in slots[..=i].iter().rev() {
                if addr(table.get(name)) == captured as usize {
                    continue;
                }
                if table.set(name, Some(captured)) != ffi::SQLITE_OK
                    || addr(table.get(name)) != captured as usize
                {
                    return Err(InstallFailure::RestoreFailed(label));
                }
            }
            return Err(failure);
        }
    }
    Ok(())
}

/// Parse `num_threads` (field 20) from `/proc/self/stat`: the fields after the
/// LAST `)` (the command name may contain `)` and spaces) start at field 3.
/// Anything malformed is `None`.
#[cfg_attr(not(any(test, target_os = "linux")), allow(dead_code))]
pub(crate) fn parse_num_threads(stat: &[u8]) -> Option<u32> {
    let close = stat.iter().rposition(|&b| b == b')')?;
    let mut fields = stat[close + 1..]
        .split(|&b| b == b' ')
        .filter(|f| !f.is_empty());
    parse_count(fields.nth(17)?)
}

/// A positive decimal count; no sign, no spaces, no overflow.
#[cfg_attr(not(any(test, target_os = "linux")), allow(dead_code))]
fn parse_count(digits: &[u8]) -> Option<u32> {
    if digits.is_empty() || digits.len() > 9 {
        return None;
    }
    let mut n = 0u32;
    for &d in digits {
        if !d.is_ascii_digit() {
            return None;
        }
        n = n * 10 + u32::from(d - b'0');
    }
    (n > 0).then_some(n)
}

/// Test seam (unit-test builds only): the constructor's thread count is read
/// from this variable instead (`"unknown"` = unreadable).
#[cfg(test)]
pub(crate) const PRETEND_THREADS_ENV: &CStr = c"RATARMOUNT_TEST_PRETEND_THREADS";

#[cfg(test)]
fn pretend_threads() -> Option<Option<u32>> {
    // SAFETY: called from the constructor (single thread) or tests that do not
    // set the variable concurrently; the result is copied out at once.
    let value = unsafe { libc::getenv(PRETEND_THREADS_ENV.as_ptr()) };
    if value.is_null() {
        return None;
    }
    Some(parse_count(unsafe { CStr::from_ptr(value) }.to_bytes()))
}

/// The current thread count without allocating, logging or panicking.
pub(crate) fn thread_count() -> Option<u32> {
    #[cfg(test)]
    if let Some(pretend) = pretend_threads() {
        return pretend;
    }
    os_thread_count()
}

#[cfg(target_os = "linux")]
fn os_thread_count() -> Option<u32> {
    let mut buf = [0u8; 1024];
    // SAFETY: plain syscalls on a local buffer and our own descriptor.
    let fd = unsafe {
        libc::open(
            c"/proc/self/stat".as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return None;
    }
    let mut len = 0usize;
    while len < buf.len() {
        let n = unsafe { libc::read(fd, buf[len..].as_mut_ptr().cast(), buf.len() - len) };
        if n < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        if n <= 0 {
            break;
        }
        len += n as usize;
    }
    unsafe { libc::close(fd) };
    parse_num_threads(&buf[..len])
}

#[cfg(target_os = "macos")]
fn os_thread_count() -> Option<u32> {
    // SAFETY: `proc_taskinfo` is plain data; `proc_pidinfo` fills at most `size` bytes.
    let mut info: libc::proc_taskinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_taskinfo>() as libc::c_int;
    let rc = unsafe {
        libc::proc_pidinfo(
            libc::getpid(),
            libc::PROC_PIDTASKINFO,
            0,
            (&mut info as *mut libc::proc_taskinfo).cast(),
            size,
        )
    };
    if rc != size {
        return None;
    }
    u32::try_from(info.pti_threadnum).ok().filter(|&n| n > 0)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn os_thread_count() -> Option<u32> {
    None
}

/// The loader check of design §4: the constructor, `module_anchor` and the
/// linked SQLite entry points are in one image that is not the executable,
/// and that image exports no SQLite ([`export_check`]). Returns the image and
/// how many exports were inspected (Linux).
pub(crate) fn private_proof(
    module_anchor: *const std::ffi::c_void,
) -> Result<(ImageIdentity, Option<u32>), HostFailure> {
    let anchors = [
        ("constructor", imp::ctor_anchor()),
        ("module", module_anchor as usize),
        (
            "sqlite3_initialize",
            ffi::sqlite3_initialize as *const () as usize,
        ),
        (
            "sqlite3_vfs_find",
            ffi::sqlite3_vfs_find as *const () as usize,
        ),
        (
            "sqlite3_open_v2",
            ffi::sqlite3_open_v2 as *const () as usize,
        ),
    ];
    proof_decision(&anchors, module_anchor as usize, &host_object, export_check)
}

/// The decision of [`private_proof`], with the loader lookup and the export
/// check as parameters so tests drive it: every anchor in one non-executable
/// image, then that image's export check; either refusal is the proof's
/// (r11 S6 skeptic: a refusal dropped here passed every test).
pub(super) fn proof_decision(
    anchors: &[(&'static str, usize)],
    module: usize,
    lookup: &dyn Fn(usize) -> Lookup,
    exports: impl FnOnce(usize, ImageIdentity) -> Result<Option<u32>, HostFailure>,
) -> Result<(ImageIdentity, Option<u32>), HostFailure> {
    let image = same_private_image(lookup, anchors)?;
    let exports = exports(module, image)?;
    Ok((image, exports))
}

/// The private-instance export check, 64-bit little-endian Linux glibc (r11
/// S6): every defined, externally bindable dynamic symbol of the proof image
/// is inspected; a `sqlite3*` name, or an inspection that cannot complete,
/// refuses. Replaces the one-name `sqlite3_libversion` probe there.
#[cfg(all(
    target_pointer_width = "64",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_endian = "little",
    target_os = "linux",
    target_env = "gnu"
))]
pub(super) fn export_check(
    anchor: usize,
    image: ImageIdentity,
) -> Result<Option<u32>, HostFailure> {
    let elf = super::elf::image_containing(anchor).map_err(HostFailure::ExportInspection)?;
    if elf.id != image.id {
        return Err(HostFailure::ImageMismatch {
            what: "export inspection",
        });
    }
    super::elf::image_exports_no_sqlite(&elf)
        .map(Some)
        .map_err(export_refusal)
}

/// Elsewhere (macOS): the own-handle `sqlite3_libversion` probe, a
/// conservative rejection check (design §4, "Symbol privacy"); the wheel
/// export audit is the exhaustive check there.
#[cfg(not(all(
    target_pointer_width = "64",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_endian = "little",
    target_os = "linux",
    target_env = "gnu"
)))]
pub(super) fn export_check(
    anchor: usize,
    image: ImageIdentity,
) -> Result<Option<u32>, HostFailure> {
    use super::host::{own_handle_symbol, refuse_exported_sqlite};
    refuse_exported_sqlite(
        &host_object,
        image,
        own_handle_symbol(anchor, c"sqlite3_libversion"),
    )?;
    Ok(None)
}

/// A failed export inspection as the private proof reports it.
#[cfg_attr(
    not(any(
        test,
        all(
            target_pointer_width = "64",
            any(target_arch = "x86_64", target_arch = "aarch64"),
            target_endian = "little",
            target_os = "linux",
            target_env = "gnu"
        )
    )),
    allow(dead_code)
)]
fn export_refusal(failure: ExportFailure) -> HostFailure {
    match failure {
        ExportFailure::Elf(e) => HostFailure::ExportInspection(e),
        ExportFailure::Sqlite(name) => HostFailure::SqliteExportedNamed(name),
    }
}

/// The installation state, once cells and wrappers of verified targets:
/// 64-bit little-endian Linux glibc and macOS on x86_64/aarch64. Other
/// targets (`aarch64_be` included) fail closed.
#[cfg(all(
    target_pointer_width = "64",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_endian = "little",
    any(all(target_os = "linux", target_env = "gnu"), target_os = "macos")
))]
mod imp {
    use std::ffi::CStr;
    use std::os::raw::{c_char, c_int};
    use std::sync::OnceLock;

    use rusqlite::ffi;

    use super::super::acquire::imp as acquire;
    use super::super::host::{host_object, same_image_as, HostFailure, ImageIdentity, Lookup};
    use super::{
        install_overrides, private_proof, thread_count, CtorObservation, ErasedFn, InstallFailure,
        InstallState, InstallStatus, InstallWhy, Originals, SyscallPtr, SyscallTable, Witness,
    };

    pub(super) static STATE: InstallState = InstallState::new();
    pub(super) static ORIGINALS: OnceLock<Originals> = OnceLock::new();
    /// F6: the selected VFSes as the successful installation left them,
    /// published before the installation result.
    pub(super) static SNAPSHOT: OnceLock<Vec<VfsSnapshot>> = OnceLock::new();

    /// Why [`check_hooks`] refused, per VFS.
    #[derive(Debug, PartialEq, Eq)]
    pub(super) struct Reasons {
        missing: &'static str,
        replaced: &'static str,
        version: &'static str,
        methods: &'static str,
        open: &'static str,
        stat: &'static str,
    }

    pub(super) const UNIX_REASONS: Reasons = Reasons {
        missing: "the \"unix\" VFS is no longer registered",
        replaced: "the \"unix\" VFS was replaced",
        version: "the \"unix\" VFS changed its version",
        methods: "a \"unix\" VFS method (xOpen, xSetSystemCall, xGetSystemCall) changed",
        open: "the \"unix\" VFS's \"open\" system call was replaced",
        stat: "the \"unix\" VFS's \"stat\" system call was replaced",
    };
    #[cfg_attr(not(any(test, target_os = "macos")), allow(dead_code))]
    pub(super) const POSIX_REASONS: Reasons = Reasons {
        missing: "the \"unix-posix\" VFS is no longer registered",
        replaced: "the \"unix-posix\" VFS was replaced",
        version: "the \"unix-posix\" VFS changed its version",
        methods: "a \"unix-posix\" VFS method (xOpen, xSetSystemCall, xGetSystemCall) changed",
        open: "the \"unix-posix\" VFS's \"open\" system call was replaced",
        stat: "the \"unix-posix\" VFS's \"stat\" system call was replaced",
    };

    /// One selected VFS at installation: identity, version and the three
    /// methods the installation relies on.
    #[derive(Clone, Copy, Debug)]
    pub(super) struct VfsSnapshot {
        pub(super) name: &'static CStr,
        pub(super) reasons: &'static Reasons,
        pub(super) vfs: usize,
        pub(super) version: c_int,
        pub(super) methods: [usize; 3],
    }

    /// The three methods of a VFS that passed the version-3 gate.
    ///
    /// # Safety
    ///
    /// `vfs` points to a live structure of SQLite's version-3 layout.
    unsafe fn methods(vfs: *mut ffi::sqlite3_vfs) -> [usize; 3] {
        let v = unsafe { &*vfs };
        [
            v.xOpen.map_or(0, |f| f as usize),
            v.xSetSystemCall.map_or(0, |f| f as usize),
            v.xGetSystemCall.map_or(0, |f| f as usize),
        ]
    }

    /// F6 (r11 S6): every snapshotted VFS is still the registered one under
    /// its name, with the same version and methods, and its `open`/`stat`
    /// slots hold `hooks`. Identity and version are compared before any
    /// version-3 field is read, and the methods before the getter is called;
    /// a VFS whose identity changed is never dereferenced. A diagnostic under
    /// the continuing contract (nothing reconfigures SQLite concurrently),
    /// not synchronization: a replace-and-restore between two checks, or a
    /// change after this one, is not seen.
    ///
    /// # Safety
    ///
    /// `find` returns null or a live registered VFS; a snapshot's VFS, when
    /// `find` returns it, still has its version-3 layout (it is compared
    /// first).
    pub(super) unsafe fn check_hooks(
        snaps: &[VfsSnapshot],
        find: &dyn Fn(&CStr) -> *mut ffi::sqlite3_vfs,
        hooks: [usize; 2],
    ) -> Result<(), &'static str> {
        for s in snaps {
            let cur = find(s.name);
            if cur.is_null() {
                return Err(s.reasons.missing);
            }
            if cur as usize != s.vfs {
                return Err(s.reasons.replaced);
            }
            // SAFETY: `iVersion` is the first field of every version.
            let version = unsafe { std::ptr::addr_of!((*cur).iVersion).read() };
            if version != s.version {
                return Err(s.reasons.version);
            }
            // SAFETY: the same VFS with the same (>= 3) version as installed.
            if unsafe { methods(cur) } != s.methods {
                return Err(s.reasons.methods);
            }
            let table = VfsTable(cur);
            if super::addr(table.get(c"open")) != hooks[0] {
                return Err(s.reasons.open);
            }
            if super::addr(table.get(c"stat")) != hooks[1] {
                return Err(s.reasons.stat);
            }
        }
        Ok(())
    }

    /// The installed wrappers' addresses as SQLite's slots hold them.
    fn hook_addrs() -> [usize; 2] {
        [
            erased::from_open(hook_open) as usize,
            erased::from_stat(hook_stat) as usize,
        ]
    }

    pub(super) fn hooks_intact() -> Result<(), &'static str> {
        let snaps = SNAPSHOT.get().ok_or(super::NO_SNAPSHOT)?;
        let find = |name: &CStr| {
            // SAFETY: SQLite is initialized (the installation ran); a
            // registered VFS lives for the process.
            unsafe { ffi::sqlite3_vfs_find(name.as_ptr()) }
        };
        // SAFETY: `find` is SQLite's own lookup; the snapshot passed the
        // version-3 gate at installation.
        unsafe { check_hooks(snaps, &find, hook_addrs()) }
    }

    pub(super) use acquire::{RealOpen, RealStat};

    /// The only conversions between SQLite's erased `sqlite3_syscall_ptr` and
    /// the real signatures. SAFETY: SQLite's `"open"` slot holds an
    /// `int (*)(const char*, int, int)` (its `posixOpen` wrapper takes the
    /// mode as `int`, not variadic) and `"stat"` an
    /// `int (*)(const char*, struct stat*)`; this module is compiled only for
    /// targets whose `libc::stat` matches the layout SQLite was built with.
    mod erased {
        use super::{ErasedFn, RealOpen, RealStat};

        pub(in super::super) fn from_open(f: RealOpen) -> ErasedFn {
            unsafe { std::mem::transmute::<RealOpen, ErasedFn>(f) }
        }
        pub(in super::super) fn from_stat(f: RealStat) -> ErasedFn {
            unsafe { std::mem::transmute::<RealStat, ErasedFn>(f) }
        }
        pub(in super::super) fn to_open(f: ErasedFn) -> RealOpen {
            unsafe { std::mem::transmute::<ErasedFn, RealOpen>(f) }
        }
        pub(in super::super) fn to_stat(f: ErasedFn) -> RealStat {
            unsafe { std::mem::transmute::<ErasedFn, RealStat>(f) }
        }
    }

    fn set_errno(e: c_int) {
        acquire::set_errno(e)
    }

    /// The `open` wrapper: a pass-through to the captured original unless
    /// this thread is inside a checked acquisition (design §5). No
    /// allocation, logging or panic.
    pub(super) unsafe extern "C" fn hook_open(
        path: *const c_char,
        flags: c_int,
        mode: c_int,
    ) -> c_int {
        match ORIGINALS.get() {
            Some(o) => unsafe { acquire::on_open(erased::to_open(o.open), path, flags, mode) },
            None => {
                set_errno(libc::ENOSYS);
                -1
            }
        }
    }

    /// The `stat` wrapper: the original's result; an armed acquisition
    /// judges each successful stat.
    pub(super) unsafe extern "C" fn hook_stat(path: *const c_char, buf: *mut libc::stat) -> c_int {
        match ORIGINALS.get() {
            Some(o) => unsafe { acquire::on_stat(erased::to_stat(o.stat), path, buf) },
            None => {
                set_errno(libc::ENOSYS);
                -1
            }
        }
    }

    pub(super) struct VfsTable(pub(super) *mut ffi::sqlite3_vfs);

    impl SyscallTable for VfsTable {
        fn get(&self, name: &CStr) -> SyscallPtr {
            // SAFETY: `find_vfs` checked the version and the method.
            unsafe {
                (*self.0)
                    .xGetSystemCall
                    .and_then(|get| get(self.0, name.as_ptr()))
            }
        }
        fn set(&self, name: &CStr, f: SyscallPtr) -> c_int {
            // SAFETY: as above; only called under an exclusion proof.
            match unsafe { (*self.0).xSetSystemCall } {
                Some(set) => unsafe { set(self.0, name.as_ptr(), f) },
                None => ffi::SQLITE_ERROR,
            }
        }
    }

    pub(super) fn find_vfs(
        name: &CStr,
        label: &'static str,
    ) -> Result<*mut ffi::sqlite3_vfs, InstallFailure> {
        // SAFETY: SQLite is initialized; the returned VFS lives for the process.
        let vfs = unsafe { ffi::sqlite3_vfs_find(name.as_ptr()) };
        if vfs.is_null() {
            return Err(InstallFailure::VfsMissing(label));
        }
        // SAFETY: a registered VFS is at least the version-1 prefix.
        unsafe { check_vfs(vfs, label) }
    }

    /// Version gate of a VFS that may be a shorter version-1/2 structure: read
    /// only `iVersion` through the raw pointer, and touch (or borrow) the
    /// version-3 fields only after `iVersion >= 3`.
    ///
    /// # Safety
    ///
    /// `vfs` points to a live structure of at least SQLite's version-1 layout.
    pub(super) unsafe fn check_vfs(
        vfs: *mut ffi::sqlite3_vfs,
        label: &'static str,
    ) -> Result<*mut ffi::sqlite3_vfs, InstallFailure> {
        // SAFETY: `iVersion` is the first field of every version.
        let version = unsafe { std::ptr::addr_of!((*vfs).iVersion).read() };
        if version < 3 {
            return Err(InstallFailure::VfsVersion {
                vfs: label,
                version,
            });
        }
        // SAFETY: version 3 has the full structure.
        let v = unsafe { &*vfs };
        if v.xSetSystemCall.is_none() || v.xGetSystemCall.is_none() {
            return Err(InstallFailure::NoSyscallInterface(label));
        }
        Ok(vfs)
    }

    /// One selectable VFS: its registered name, the method labels the
    /// private path's image check reports, and F6's refusal texts. The name
    /// travels with the VFS pointer, so the snapshot never pairs them by
    /// position.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) struct MethodLabels {
        pub(super) name: &'static CStr,
        pub(super) methods: [&'static str; 3],
        pub(super) reasons: &'static Reasons,
    }
    pub(super) const UNIX_METHODS: MethodLabels = MethodLabels {
        name: c"unix",
        methods: ["unix xOpen", "unix xSetSystemCall", "unix xGetSystemCall"],
        reasons: &UNIX_REASONS,
    };
    #[cfg_attr(not(any(test, target_os = "macos")), allow(dead_code))]
    pub(super) const POSIX_METHODS: MethodLabels = MethodLabels {
        name: c"unix-posix",
        methods: [
            "unix-posix xOpen",
            "unix-posix xSetSystemCall",
            "unix-posix xGetSystemCall",
        ],
        reasons: &POSIX_REASONS,
    };

    /// The VFSes whose methods serve checked opens: `"unix"`, whose syscall
    /// table is set, and on macOS the selected `"unix-posix"` (design §6).
    pub(super) fn selected_vfses(
        unix: *mut ffi::sqlite3_vfs,
    ) -> Result<Vec<(*mut ffi::sqlite3_vfs, MethodLabels)>, InstallFailure> {
        #[allow(unused_mut)]
        let mut vfses = vec![(unix, UNIX_METHODS)];
        #[cfg(target_os = "macos")]
        vfses.push((find_vfs(c"unix-posix", "unix-posix")?, POSIX_METHODS));
        Ok(vfses)
    }

    /// Design §4: `xOpen`, `xSetSystemCall` and `xGetSystemCall` of every
    /// selected VFS live in the proof's image.
    ///
    /// # Safety
    ///
    /// Every VFS passed the version-3 gate ([`check_vfs`]).
    pub(super) unsafe fn vfs_methods_in_image(
        lookup: &dyn Fn(usize) -> Lookup,
        image: ImageIdentity,
        vfses: &[(*mut ffi::sqlite3_vfs, MethodLabels)],
    ) -> Result<(), HostFailure> {
        for &(vfs, labels) in vfses {
            let v = unsafe { &*vfs };
            same_image_as(
                lookup,
                image,
                &[
                    (labels.methods[0], v.xOpen.map_or(0, |f| f as usize)),
                    (
                        labels.methods[1],
                        v.xSetSystemCall.map_or(0, |f| f as usize),
                    ),
                    (
                        labels.methods[2],
                        v.xGetSystemCall.map_or(0, |f| f as usize),
                    ),
                ],
            )?;
        }
        Ok(())
    }

    /// The real installer (design §3 steps 1-7). `image`: the private-instance
    /// proof, whose image must also own the selected VFS's methods (`lookup`:
    /// [`host_object`], or a test catalog).
    pub(super) fn install_real(
        why: InstallWhy,
        threads: Option<u32>,
        image: Option<(ImageIdentity, Option<u32>)>,
        lookup: &dyn Fn(usize) -> Lookup,
    ) -> Result<Witness, InstallFailure> {
        // SAFETY: called only under an exclusion proof.
        let rc = unsafe { ffi::sqlite3_initialize() };
        if rc != ffi::SQLITE_OK {
            return Err(InstallFailure::SqliteInitialize(rc));
        }
        let unix = find_vfs(c"unix", "unix")?;
        let vfses = selected_vfses(unix)?;
        // The selected VFS's methods are checked before any of them is called.
        if let Some((image, _)) = image {
            // SAFETY: every entry passed `find_vfs`.
            unsafe { vfs_methods_in_image(lookup, image, &vfses) }
                .map_err(InstallFailure::ForeignVfs)?;
        }
        let table = VfsTable(unix);
        #[cfg(target_os = "macos")]
        {
            let posix = vfses[1].0;
            let (u, p) = unsafe { (&*unix, &*posix) };
            let same = |a: Option<usize>, b: Option<usize>| a.is_some() && a == b;
            let posix_table = VfsTable(posix);
            if !same(
                u.xSetSystemCall.map(|f| f as usize),
                p.xSetSystemCall.map(|f| f as usize),
            ) || !same(
                u.xGetSystemCall.map(|f| f as usize),
                p.xGetSystemCall.map(|f| f as usize),
            ) || super::addr(table.get(c"open")) != super::addr(posix_table.get(c"open"))
                || super::addr(table.get(c"stat")) != super::addr(posix_table.get(c"stat"))
            {
                return Err(InstallFailure::VfsSyscallsDiffer);
            }
        }
        install_overrides(
            &table,
            &ORIGINALS,
            erased::from_open(hook_open),
            erased::from_stat(hook_stat),
        )?;
        // F6: published before the caller stores the installation result.
        let snaps = vfses
            .iter()
            .map(|&(vfs, labels)| VfsSnapshot {
                name: labels.name,
                reasons: labels.reasons,
                vfs: vfs as usize,
                // SAFETY: every entry passed `find_vfs` (version >= 3).
                version: unsafe { std::ptr::addr_of!((*vfs).iVersion).read() },
                methods: unsafe { methods(vfs) },
            })
            .collect();
        // Cannot fail: this is the only setter, and `STATE` admits one
        // installation. No assertion: this runs in the load-time
        // constructor, where a panic would abort the process.
        let _ = SNAPSHOT.set(snaps);
        Ok(Witness {
            why,
            threads_at_install: threads,
            exports_checked: image.and_then(|(_, exports)| exports),
        })
    }

    /// Load-time constructor. No allocation, logging or panic in the
    /// observation; SQLite's own initialization may allocate.
    extern "C" fn constructor() {
        let threads = thread_count();
        STATE.constructor(threads, |why| {
            install_real(why, threads, None, &host_object)
        });
    }

    /// Registers [`constructor`] with the loader. [`ctor_anchor`] references
    /// it by address so that any caller of `installed()` links the object
    /// that carries it. Never read its value: at a macOS deployment target of
    /// 14.0 Apple's linker rewrites `__mod_init_func` into `__init_offsets`
    /// (32-bit image offsets), so the stored word is not an address.
    #[used]
    #[cfg_attr(target_os = "linux", link_section = ".init_array")]
    #[cfg_attr(
        target_os = "macos",
        link_section = "__DATA,__mod_init_func,mod_init_funcs"
    )]
    static CTOR_ANCHOR: extern "C" fn() = constructor;

    /// The constructor's code address (the loader proof's first anchor).
    pub(super) fn ctor_anchor() -> usize {
        // Address only, never the value (see `CTOR_ANCHOR`): this reference
        // keeps the init-section entry linked. Do not remove it as dead code.
        std::hint::black_box(std::ptr::addr_of!(CTOR_ANCHOR));
        std::hint::black_box(constructor as extern "C" fn()) as *const () as usize
    }

    pub(super) fn status() -> Result<Witness, InstallStatus> {
        std::hint::black_box(ctor_anchor());
        STATE.status()
    }

    pub(super) fn observation() -> Option<CtorObservation> {
        STATE.observation()
    }

    pub(super) fn private(anchor: *const std::ffi::c_void) -> Result<Witness, InstallStatus> {
        STATE.private(
            || private_proof(anchor),
            |image| {
                install_real(
                    InstallWhy::PrivateInstance,
                    thread_count(),
                    Some(image),
                    &host_object,
                )
            },
        )
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::checked_open::install::PRETEND_THREADS_ENV;

        /// Regression (R11-CI-FIX2): the macOS wheel (deployment target 14.0)
        /// refused its private-instance install with `UnknownImage
        /// {constructor}`: the anchor was the word stored in the init
        /// section, which that linker rewrites into a 32-bit offset that
        /// `dladdr` cannot resolve. The anchor is the constructor's address
        /// and resolves to an image (main here; the DSO fixture covers a
        /// non-main image). Red only at macOS 14.0 (CI step).
        #[test]
        fn regression_ctor_anchor_is_the_constructor_address() {
            assert_eq!(ctor_anchor(), constructor as extern "C" fn() as usize);
            assert!(
                matches!(host_object(ctor_anchor()), Lookup::Found(_)),
                "constructor anchor resolves to no image"
            );
        }

        fn real_slot(name: &CStr) -> usize {
            let vfs = find_vfs(c"unix", "unix").expect("unix VFS");
            super::super::addr(VfsTable(vfs).get(name))
        }

        /// Regression: the constructor of this (single-threaded at load time)
        /// test binary must install the wrappers; SQLite's `open`/`stat` slots
        /// then hold the pass-throughs and an ordinary database still works.
        /// Needs a single-threaded start before `main`: under an `LD_PRELOAD`
        /// that starts threads, or ThreadSanitizer, the constructor correctly
        /// abstains and this test fails.
        #[test]
        fn regression_sqlite_hook_installed_with_one_thread() {
            assert_eq!(
                status(),
                Ok(Witness {
                    why: InstallWhy::SingleThread,
                    threads_at_install: Some(1),
                    exports_checked: None,
                })
            );
            assert_eq!(observation(), Some(CtorObservation::AttemptedSingleThread));
            assert_eq!(real_slot(c"open"), erased::from_open(hook_open) as usize);
            assert_eq!(real_slot(c"stat"), erased::from_stat(hook_stat) as usize);
            #[cfg(target_os = "macos")]
            {
                let posix = VfsTable(find_vfs(c"unix-posix", "unix-posix").unwrap());
                assert_eq!(super::super::addr(posix.get(c"open")), real_slot(c"open"));
            }
            // A terminal result is returned unchanged by a private initializer.
            assert_eq!(private(std::ptr::null()), status());

            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("t.sqlite");
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch("CREATE TABLE t(x); INSERT INTO t VALUES (7);")
                .unwrap();
            drop(conn);
            let conn = rusqlite::Connection::open(&path).unwrap();
            let x: i64 = conn.query_row("SELECT x FROM t", [], |r| r.get(0)).unwrap();
            assert_eq!(x, 7);
        }

        /// Regression (r11 S1 skeptic P1): the version gate borrowed the whole
        /// `sqlite3_vfs` before checking `iVersion`, which is undefined
        /// behaviour for a legacy VFS registered as the shorter version-1/2
        /// structure. The gate must read only `iVersion` of such a structure.
        /// Each one is placed so that it ends at a `PROT_NONE` guard page: a
        /// read of any version-3 field faults.
        #[test]
        fn regression_install_short_vfs_version_checked_before_borrow() {
            let v1 = std::mem::offset_of!(ffi::sqlite3_vfs, xCurrentTimeInt64);
            let v2 = std::mem::offset_of!(ffi::sqlite3_vfs, xSetSystemCall);
            assert!(v1 < v2 && v2 < std::mem::size_of::<ffi::sqlite3_vfs>());
            // SAFETY: anonymous private mapping, unmapped below.
            let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
            let map = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    2 * page,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANON,
                    -1,
                    0,
                )
            };
            assert_ne!(map, libc::MAP_FAILED);
            let guard = unsafe { map.cast::<u8>().add(page) };
            assert_eq!(
                unsafe { libc::mprotect(guard.cast(), page, libc::PROT_NONE) },
                0
            );
            for (size, version) in [(v1, 1), (v2, 2)] {
                assert_eq!(size % 8, 0);
                let short = unsafe { guard.sub(size) };
                // SAFETY: `size` writable bytes before the guard page.
                unsafe {
                    std::ptr::write_bytes(short, 0, size);
                    short.cast::<std::os::raw::c_int>().write(version);
                }
                assert_eq!(
                    unsafe { check_vfs(short.cast(), "short") },
                    Err(InstallFailure::VfsVersion {
                        vfs: "short",
                        version
                    })
                );
            }
            assert_eq!(unsafe { libc::munmap(map, 2 * page) }, 0);
            // The real VFS passes the same gate.
            let unix = unsafe { ffi::sqlite3_vfs_find(c"unix".as_ptr()) };
            assert_eq!(unsafe { check_vfs(unix, "unix") }, Ok(unix));
        }

        /// A zeroed version-3 VFS whose three checked methods are `methods`
        /// (addresses only; never called).
        fn fake_vfs(methods: [usize; 3]) -> Box<ffi::sqlite3_vfs> {
            // SAFETY: all-zero is a valid `sqlite3_vfs` (null pointers, `None`
            // methods); each method is written as a non-null pointer value.
            let mut vfs: Box<ffi::sqlite3_vfs> = Box::new(unsafe { std::mem::zeroed() });
            vfs.iVersion = 3;
            let p: *mut ffi::sqlite3_vfs = &mut *vfs;
            unsafe {
                std::ptr::addr_of_mut!((*p).xOpen)
                    .cast::<usize>()
                    .write(methods[0]);
                std::ptr::addr_of_mut!((*p).xSetSystemCall)
                    .cast::<usize>()
                    .write(methods[1]);
                std::ptr::addr_of_mut!((*p).xGetSystemCall)
                    .cast::<usize>()
                    .write(methods[2]);
            }
            vfs
        }

        /// Regression (r11 S1 review/skeptic P2): on macOS the private path
        /// checked the image of `"unix"`'s `xOpen` although `"unix-posix"` is
        /// the VFS that opens databases, so a `"unix-posix"` from another image
        /// sharing unix's syscall methods passed. Every selected VFS's `xOpen`,
        /// `xSetSystemCall` and `xGetSystemCall` must be in the proof's image,
        /// and a refusal names the method. Catalog rows, the platform's
        /// selected list, and the real loader.
        #[test]
        fn regression_install_foreign_vfs_method_refused() {
            const LIB: ImageIdentity = ImageIdentity {
                id: 0x1000,
                main: false,
            };
            let catalog = |addr: usize| match addr >> 8 {
                1 => Lookup::Found(LIB),
                2 => Lookup::Found(ImageIdentity {
                    id: 0x2000,
                    main: false,
                }),
                3 => Lookup::Found(ImageIdentity {
                    id: 0x3000,
                    main: true,
                }),
                _ => Lookup::Unknown,
            };
            let unix = fake_vfs([0x101, 0x102, 0x103]);
            let check = |posix_open: usize| {
                let posix = fake_vfs([posix_open, 0x102, 0x103]);
                let vfses = [
                    (&*unix as *const _ as *mut ffi::sqlite3_vfs, UNIX_METHODS),
                    (&*posix as *const _ as *mut ffi::sqlite3_vfs, POSIX_METHODS),
                ];
                unsafe { vfs_methods_in_image(&catalog, LIB, &vfses) }
            };
            assert_eq!(check(0x104), Ok(()));
            assert_eq!(
                check(0x201),
                Err(HostFailure::ImageMismatch {
                    what: "unix-posix xOpen"
                })
            );
            assert_eq!(
                check(0x301),
                Err(HostFailure::MainExecutable {
                    what: "unix-posix xOpen"
                })
            );
            assert_eq!(
                check(0x901),
                Err(HostFailure::UnknownImage {
                    what: "unix-posix xOpen"
                })
            );
            assert_eq!(
                InstallFailure::ForeignVfs(HostFailure::ImageMismatch {
                    what: "unix-posix xOpen"
                })
                .to_string(),
                "SQLite VFS method check: unix-posix xOpen is in another image than the constructor"
            );

            // The selected list: "unix-posix" on macOS (design §6), with "unix".
            let real_unix = find_vfs(c"unix", "unix").unwrap();
            let selected = selected_vfses(real_unix).unwrap();
            assert_eq!(selected[0], (real_unix, UNIX_METHODS));
            #[cfg(target_os = "macos")]
            {
                let posix = find_vfs(c"unix-posix", "unix-posix").unwrap();
                assert_eq!(selected[1..], [(posix, POSIX_METHODS)]);
            }
            #[cfg(not(target_os = "macos"))]
            assert_eq!(selected.len(), 1);

            // The real loader, with libc as the "private" image.
            let libc_image = match host_object(libc::qsort as *const () as usize) {
                Lookup::Found(image) if !image.main => image,
                other => {
                    eprintln!("skip: libc linked statically ({other:?}); real-loader rows");
                    return;
                }
            };
            // One address for all three methods: only the image matters, and
            // Darwin's `free`/`malloc` live in libsystem_malloc, not in
            // `qsort`'s libsystem_c (r11 S1 skeptic P2).
            let qsort = libc::qsort as *const () as usize;
            let in_libc = [qsort; 3];
            let all_libc = fake_vfs(in_libc);
            let vfs = |v: &ffi::sqlite3_vfs| (v as *const _ as *mut ffi::sqlite3_vfs, UNIX_METHODS);
            assert_eq!(
                unsafe { vfs_methods_in_image(&host_object, libc_image, &[vfs(&all_libc)]) },
                Ok(())
            );
            let exe_getter = fake_vfs([
                in_libc[0],
                in_libc[1],
                regression_install_foreign_vfs_method_refused as *const () as usize,
            ]);
            assert_eq!(
                unsafe { vfs_methods_in_image(&host_object, libc_image, &[vfs(&exe_getter)]) },
                Err(HostFailure::MainExecutable {
                    what: "unix xGetSystemCall"
                })
            );
            // This executable's bundled SQLite is no method of libc's image.
            assert_eq!(
                unsafe { vfs_methods_in_image(&host_object, libc_image, &selected) },
                Err(HostFailure::MainExecutable { what: "unix xOpen" })
            );
        }

        /// Regression (r11 S1 review 1): no test failed if the real
        /// installer's VFS-method check was deleted. `install_real` with a
        /// proof image that owns none of the methods must refuse, naming the
        /// first method, before any slot is read or set. (Without the check
        /// it would reach `install_overrides`, which reports `OriginalsDiffer`
        /// against this binary's installed hooks, or installs.)
        #[test]
        fn regression_install_real_refuses_foreign_vfs_before_any_set() {
            const OTHER: ImageIdentity = ImageIdentity {
                id: 0x5150,
                main: false,
            };
            let open_before = real_slot(c"open");
            let stat_before = real_slot(c"stat");
            let originals_before = ORIGINALS.get().map(|o| (o.open as usize, o.stat as usize));
            let asked = std::cell::RefCell::new(Vec::new());
            let lookup = |addr: usize| {
                asked.borrow_mut().push(addr);
                Lookup::Found(ImageIdentity {
                    id: 0x6000,
                    main: false,
                })
            };
            assert_eq!(
                install_real(
                    InstallWhy::PrivateInstance,
                    Some(3),
                    Some((OTHER, None)),
                    &lookup
                ),
                Err(InstallFailure::ForeignVfs(HostFailure::ImageMismatch {
                    what: "unix xOpen"
                }))
            );
            let unix = find_vfs(c"unix", "unix").unwrap();
            let x_open = unsafe { (*unix).xOpen }.map_or(0, |f| f as usize);
            assert_eq!(*asked.borrow(), [x_open], "first anchor: unix xOpen");
            assert_eq!(real_slot(c"open"), open_before);
            assert_eq!(real_slot(c"stat"), stat_before);
            assert_eq!(
                ORIGINALS.get().map(|o| (o.open as usize, o.stat as usize)),
                originals_before
            );
        }

        thread_local! {
            /// The fake getter's `open` and `stat` slots.
            static FAKE_SLOTS: std::cell::Cell<[usize; 2]> =
                const { std::cell::Cell::new([0x501, 0x502]) };
        }

        unsafe extern "C" fn fake_get(
            _vfs: *mut ffi::sqlite3_vfs,
            name: *const c_char,
        ) -> ffi::sqlite3_syscall_ptr {
            let [open, stat] = FAKE_SLOTS.with(|s| s.get());
            let name = unsafe { CStr::from_ptr(name) };
            let addr = if name == c"open" { open } else { stat };
            // SAFETY: only compared as an address, never called.
            unsafe { std::mem::transmute::<usize, ffi::sqlite3_syscall_ptr>(addr) }
        }

        thread_local! {
            static GETTER_CALLS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
        }

        /// A getter that counts its calls and answers like [`fake_get`].
        unsafe extern "C" fn counting_get(
            vfs: *mut ffi::sqlite3_vfs,
            name: *const c_char,
        ) -> ffi::sqlite3_syscall_ptr {
            GETTER_CALLS.with(|c| c.set(c.get() + 1));
            unsafe { fake_get(vfs, name) }
        }

        /// Regression (r11 S6, F6): an acquisition must not arm when the
        /// selected VFS, its methods or a syscall slot no longer hold what
        /// the installation left. Fake catalog: a VFS that is gone, replaced
        /// (another structure under the name: never dereferenced), of
        /// another version (compared before any version-3 field), with a
        /// changed method (`xOpen`, `xSetSystemCall`, `xGetSystemCall`, a
        /// missing getter; every method compared before the getter is
        /// called), or with a replaced `open` or `stat`; each refusal names
        /// the VFS (the macOS pair: `"unix-posix"` after `"unix"`). A missing
        /// snapshot is reported as an internal fault, not as outside code.
        /// The real-snapshot rows need a single-threaded start (the
        /// constructor installed).
        #[test]
        fn regression_hooks_intact_vfs_validation() {
            let getter = fake_get as *const () as usize;
            let unix = fake_vfs([0x101, 0x102, getter]);
            let posix = fake_vfs([0x201, 0x102, getter]);
            let snap = |vfs: &ffi::sqlite3_vfs, name, reasons| VfsSnapshot {
                name,
                reasons,
                vfs: vfs as *const _ as usize,
                version: 3,
                methods: [vfs.xOpen.map_or(0, |f| f as usize), 0x102, getter],
            };
            let snaps = [
                snap(&unix, c"unix", &UNIX_REASONS),
                snap(&posix, c"unix-posix", &POSIX_REASONS),
            ];
            let hooks = [0x501, 0x502];
            let ptr = |v: &ffi::sqlite3_vfs| v as *const _ as *mut ffi::sqlite3_vfs;
            let catalog = |u: *mut ffi::sqlite3_vfs, p: *mut ffi::sqlite3_vfs| {
                move |name: &CStr| if name == c"unix" { u } else { p }
            };
            let check = |find: &dyn Fn(&CStr) -> *mut ffi::sqlite3_vfs| unsafe {
                check_hooks(&snaps, find, hooks)
            };
            assert_eq!(check(&catalog(ptr(&unix), ptr(&posix))), Ok(()));
            assert_eq!(
                check(&catalog(std::ptr::null_mut(), ptr(&posix))),
                Err(UNIX_REASONS.missing)
            );
            assert_eq!(
                check(&catalog(ptr(&unix), std::ptr::null_mut())),
                Err(POSIX_REASONS.missing)
            );
            // Another structure under the name: refused on identity alone (its
            // version is 0, which the check never reaches).
            let other: Box<ffi::sqlite3_vfs> = Box::new(unsafe { std::mem::zeroed() });
            assert_eq!(
                check(&catalog(ptr(&other), ptr(&posix))),
                Err(UNIX_REASONS.replaced)
            );
            let mut changed = fake_vfs([0x101, 0x102, getter]);
            let mut snaps2 = snaps;
            snaps2[0].vfs = ptr(&changed) as usize;
            changed.iVersion = 2;
            assert_eq!(
                unsafe { check_hooks(&snaps2, &catalog(ptr(&changed), ptr(&posix)), hooks) },
                Err(UNIX_REASONS.version)
            );
            changed.iVersion = 3;
            assert_eq!(
                unsafe { check_hooks(&snaps2, &catalog(ptr(&changed), ptr(&posix)), hooks) },
                Ok(())
            );
            // Written through the owning `Box` (never through a pointer made
            // from a shared reference).
            let set_method = |vfs: &mut ffi::sqlite3_vfs, i: usize, value: usize| {
                let p: *mut ffi::sqlite3_vfs = vfs;
                // SAFETY: a method slot is a nullable function pointer;
                // `value` is only compared as an address, never called
                // (except `counting_get`, a real getter).
                unsafe {
                    match i {
                        0 => std::ptr::addr_of_mut!((*p).xOpen)
                            .cast::<usize>()
                            .write(value),
                        1 => std::ptr::addr_of_mut!((*p).xSetSystemCall)
                            .cast::<usize>()
                            .write(value),
                        _ => std::ptr::addr_of_mut!((*p).xGetSystemCall)
                            .cast::<usize>()
                            .write(value),
                    }
                }
            };
            set_method(&mut changed, 0, 0x109);
            assert_eq!(
                unsafe { check_hooks(&snaps2, &catalog(ptr(&changed), ptr(&posix)), hooks) },
                Err(UNIX_REASONS.methods)
            );
            set_method(&mut changed, 0, 0x101);
            // Every method is compared, and all of them before the getter is
            // called: a changed setter, a changed getter (a counting getter
            // that must never run) and a missing getter refuse as `methods`.
            let counting = counting_get as *const () as usize;
            for (i, value) in [(1, 0x10a), (2, counting), (2, 0)] {
                set_method(&mut changed, i, value);
                GETTER_CALLS.with(|c| c.set(0));
                assert_eq!(
                    unsafe { check_hooks(&snaps2, &catalog(ptr(&changed), ptr(&posix)), hooks) },
                    Err(UNIX_REASONS.methods),
                    "method {i} = {value:#x}"
                );
                assert_eq!(GETTER_CALLS.with(|c| c.get()), 0, "getter called");
                set_method(&mut changed, i, [0x101, 0x102, getter][i]);
            }
            // The getter of an intact VFS is called (the counting getter
            // installed in the snapshot too).
            let mut counted = snaps2;
            counted[0].methods[2] = counting;
            set_method(&mut changed, 2, counting);
            GETTER_CALLS.with(|c| c.set(0));
            assert_eq!(
                unsafe { check_hooks(&counted, &catalog(ptr(&changed), ptr(&posix)), hooks) },
                Ok(())
            );
            assert_eq!(GETTER_CALLS.with(|c| c.get()), 2, "open and stat read");
            set_method(&mut changed, 2, getter);
            // A changed method of the second (macOS) VFS refuses with its name.
            let mut posix_changed = fake_vfs([0x201, 0x10b, getter]);
            let mut snaps_posix = snaps;
            snaps_posix[1].vfs = ptr(&posix_changed) as usize;
            set_method(&mut posix_changed, 1, 0x102);
            assert_eq!(
                unsafe {
                    check_hooks(
                        &snaps_posix,
                        &catalog(ptr(&unix), ptr(&posix_changed)),
                        hooks,
                    )
                },
                Ok(())
            );
            set_method(&mut posix_changed, 1, 0x10b);
            assert_eq!(
                unsafe {
                    check_hooks(
                        &snaps_posix,
                        &catalog(ptr(&unix), ptr(&posix_changed)),
                        hooks,
                    )
                },
                Err(POSIX_REASONS.methods)
            );
            for (slots, want) in [
                ([0x509, 0x502], UNIX_REASONS.open),
                ([0x501, 0x509], UNIX_REASONS.stat),
                ([0x501, 0x502], ""),
            ] {
                FAKE_SLOTS.with(|s| s.set(slots));
                let got = check(&catalog(ptr(&unix), ptr(&posix)));
                if want.is_empty() {
                    assert_eq!(got, Ok(()));
                } else {
                    assert_eq!(got, Err(want));
                }
            }
            // The posix VFS is checked too: replace it alone.
            let snaps_posix_only = [snaps[1]];
            FAKE_SLOTS.with(|s| s.set([0x509, 0x502]));
            let got =
                unsafe { check_hooks(&snaps_posix_only, &catalog(ptr(&unix), ptr(&posix)), hooks) };
            assert_eq!(got, Err(POSIX_REASONS.open));
            assert!(POSIX_REASONS.open.contains("unix-posix"));
            FAKE_SLOTS.with(|s| s.set([0x501, 0x502]));
            // The real installation published its snapshot: the platform's
            // selected VFSes, intact.
            let real = SNAPSHOT.get().expect("snapshot");
            let want: &[&CStr] = if cfg!(target_os = "macos") {
                &[c"unix", c"unix-posix"]
            } else {
                &[c"unix"]
            };
            assert_eq!(real.iter().map(|s| s.name).collect::<Vec<_>>(), want);
            assert_eq!(hooks_intact(), Ok(()));
            let internal = InstallStatus::HooksReplaced(super::super::NO_SNAPSHOT).to_string();
            assert!(internal.contains("internal fault"), "{internal}");
            assert!(!internal.contains("reconfigured"), "{internal}");
            let outside = InstallStatus::HooksReplaced(UNIX_REASONS.open).to_string();
            assert!(outside.contains("reconfigured SQLite"), "{outside}");
        }

        const HOOKS_CHILD_ENV: &str = "RATARMOUNT_TEST_HOOKS_CHILD";

        /// Child of `regression_hooks_replaced_refuses_before_arming` and
        /// `regression_hooks_status_is_historical`.
        #[test]
        fn hooks_child() {
            use crate::checked_open::{open_checked, AcquireError, Expect, NameMode};
            use std::sync::atomic::Ordering;
            if std::env::var_os(HOOKS_CHILD_ENV).is_none() {
                return;
            }
            let arms = || crate::checked_open::acquire::imp::ARMS.load(Ordering::SeqCst);
            let installed = status();
            assert!(
                matches!(
                    installed,
                    Ok(Witness {
                        why: InstallWhy::SingleThread,
                        ..
                    })
                ),
                "{installed:?}"
            );
            let observed = observation();
            let dir = tempfile::tempdir().unwrap();
            let db = dir.path().canonicalize().unwrap().join("t.sqlite");
            let open = || {
                open_checked(
                    &db,
                    rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                        | rusqlite::OpenFlags::SQLITE_OPEN_CREATE,
                    NameMode::Path,
                    Expect::Fresh,
                )
            };
            let _ = std::fs::remove_file(&db);
            assert!(open().is_ok());
            let table = VfsTable(find_vfs(c"unix", "unix").unwrap());
            let originals = *ORIGINALS.get().unwrap();
            for (name, label, original, hook, reason) in [
                (
                    c"open",
                    "open",
                    originals.open,
                    erased::from_open(hook_open),
                    UNIX_REASONS.open,
                ),
                (
                    c"stat",
                    "stat",
                    originals.stat,
                    erased::from_stat(hook_stat),
                    UNIX_REASONS.stat,
                ),
            ] {
                // Another library sets the slot back to the original.
                assert_eq!(table.set(name, Some(original)), ffi::SQLITE_OK, "{label}");
                let before = arms();
                let refusal = open().unwrap_err();
                assert!(
                    matches!(
                        refusal.error,
                        AcquireError::Unavailable(InstallStatus::HooksReplaced(r)) if r == reason
                    ),
                    "{label}: {refusal}"
                );
                assert!(
                    refusal.to_string().contains("reconfigured SQLite"),
                    "{refusal}"
                );
                assert_eq!(arms(), before, "{label}: refused before arming");
                assert_eq!(
                    super::super::addr(table.get(name)),
                    original as usize,
                    "no repair"
                );
                // The installation history is unchanged: `installed()`, the
                // constructor's observation, and the terminal result a
                // private initializer gets (nothing reinstalls or repairs).
                assert_eq!(status(), installed, "{label}");
                assert_eq!(observation(), observed, "{label}");
                assert_eq!(private(hooks_child as *const std::ffi::c_void), installed);
                assert_eq!(
                    super::super::addr(table.get(name)),
                    original as usize,
                    "{label}: a private initializer repairs nothing"
                );
                assert_eq!(hooks_intact(), Err(reason));
                println!("HOOKS-CHILD:historical {label}");
                // Restoring the exact state lets acquisitions proceed again.
                assert_eq!(table.set(name, Some(hook)), ffi::SQLITE_OK);
                assert_eq!(hooks_intact(), Ok(()));
                let _ = std::fs::remove_file(&db);
                assert!(open().is_ok(), "{label}: after restoration");
                assert_eq!(status(), installed);
                assert_eq!(observation(), observed);
            }
            println!("HOOKS-CHILD:ok");
        }

        /// Regression (r11 S6, F6): a syscall slot replaced after a successful
        /// installation (another library, in this child: `open`, then
        /// `stat`) must make checked acquisitions refuse with
        /// `HooksReplaced` before arming, repair nothing, and leave
        /// `installed()` reporting the historical result; restoring the
        /// wrapper lets acquisitions proceed. Runs in a child (it rewrites
        /// this process's SQLite slots).
        #[test]
        fn regression_hooks_replaced_refuses_before_arming() {
            run_hooks_child();
        }

        /// Regression (r11 S6 fix skeptic #2, addendum §8): while a slot is
        /// replaced, `installed()`, the constructor's observation and a
        /// private initializer's terminal result keep the historical
        /// installation (nothing reinstalls or repairs), and restoring the
        /// slot changes none of them. Same child as
        /// `regression_hooks_replaced_refuses_before_arming`; this test
        /// requires its per-slot historical rows.
        #[test]
        fn regression_hooks_status_is_historical() {
            let stdout = run_hooks_child();
            for label in ["open", "stat"] {
                assert!(
                    stdout.contains(&format!("HOOKS-CHILD:historical {label}\n")),
                    "{label}: {stdout}"
                );
            }
        }

        /// Run `hooks_child` in a child process; its stdout on success.
        fn run_hooks_child() -> String {
            let out = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "checked_open::install::imp::tests::hooks_child",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(HOOKS_CHILD_ENV, "1")
                .output()
                .unwrap();
            let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
            assert!(
                out.status.success() && stdout.contains("HOOKS-CHILD:ok"),
                "child failed: {stdout}\n{}",
                String::from_utf8_lossy(&out.stderr)
            );
            stdout
        }

        const CHILD_ENV: &str = "RATARMOUNT_TEST_ABSTAIN_CHILD";

        /// Child of `regression_checked_open_never_installs_lazily` (no-op
        /// unless spawned by it).
        #[test]
        fn abstain_child() {
            let Ok(want) = std::env::var(CHILD_ENV) else {
                return;
            };
            let want: Option<u32> = want.parse().ok();
            let open_before = real_slot(c"open");
            let stat_before = real_slot(c"stat");
            assert_ne!(open_before, erased::from_open(hook_open) as usize);
            assert_ne!(stat_before, erased::from_stat(hook_stat) as usize);
            assert_eq!(status(), Err(InstallStatus::AbstainedThreads(want)));
            assert_eq!(observation(), Some(CtorObservation::AbstainedThreads(want)));
            // Database work does not install anything lazily.
            let conn = rusqlite::Connection::open_in_memory().unwrap();
            conn.execute_batch("CREATE TABLE t(x)").unwrap();
            drop(conn);
            let dir = tempfile::tempdir().unwrap();
            let db = dir.path().canonicalize().unwrap().join("t.sqlite");
            drop(rusqlite::Connection::open(&db).unwrap());
            // A checked open fails closed and installs nothing either.
            let refusal = crate::checked_open::open_checked(
                &db,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
                crate::checked_open::NameMode::Path,
                crate::checked_open::Expect::Fresh,
            )
            .unwrap_err();
            assert!(
                matches!(
                    refusal.error,
                    crate::checked_open::AcquireError::Unavailable(
                        InstallStatus::AbstainedThreads(got)
                    ) if got == want
                ),
                "{refusal}"
            );
            // An executable is no private instance; the refusal does not poison.
            assert_eq!(
                private(abstain_child as *const std::ffi::c_void),
                Err(InstallStatus::NotPrivate(HostFailure::MainExecutable {
                    what: "constructor"
                }))
            );
            assert_eq!(status(), Err(InstallStatus::AbstainedThreads(want)));
            assert_eq!(real_slot(c"open"), open_before);
            assert_eq!(real_slot(c"stat"), stat_before);
            assert!(ORIGINALS.get().is_none());
            println!("ABSTAIN-CHILD:ok");
        }

        /// Regression: a constructor that saw more than one thread (or could
        /// not count them) must not install, and nothing later (database
        /// opens, `installed()`, a refused private initializer, a checked
        /// open) may install lazily: SQLite's slots stay untouched, and the
        /// checked open refuses with `Unavailable`.
        #[test]
        fn regression_checked_open_never_installs_lazily() {
            for (pretend, want) in [("2", "2"), ("unknown", "none")] {
                let out = std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "checked_open::install::imp::tests::abstain_child",
                        "--nocapture",
                        "--test-threads=1",
                    ])
                    .env(PRETEND_THREADS_ENV.to_str().unwrap(), pretend)
                    .env(CHILD_ENV, want)
                    .output()
                    .unwrap();
                let stdout = String::from_utf8_lossy(&out.stdout);
                assert!(
                    out.status.success() && stdout.contains("ABSTAIN-CHILD:ok"),
                    "child ({pretend}) failed: {stdout}\n{}",
                    String::from_utf8_lossy(&out.stderr)
                );
            }
        }
    }
}

/// Unverified targets: nothing is installed.
#[cfg(not(all(
    target_pointer_width = "64",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_endian = "little",
    any(all(target_os = "linux", target_env = "gnu"), target_os = "macos")
)))]
mod imp {
    use super::{CtorObservation, InstallStatus, Witness};

    const UNSUPPORTED: InstallStatus = if cfg!(unix) {
        InstallStatus::UnsupportedAbi
    } else {
        InstallStatus::UnsupportedPlatform
    };

    pub(super) fn ctor_anchor() -> usize {
        0
    }
    pub(super) fn status() -> Result<Witness, InstallStatus> {
        Err(UNSUPPORTED)
    }
    pub(super) fn observation() -> Option<CtorObservation> {
        None
    }
    pub(super) fn private(_anchor: *const std::ffi::c_void) -> Result<Witness, InstallStatus> {
        Err(UNSUPPORTED)
    }
    pub(super) fn hooks_intact() -> Result<(), &'static str> {
        Err("checked opens are not supported on this target")
    }
}

/// Whether this target is one the wrappers are verified for (the
/// checked-open target predicate). On any other target [`installed`] is
/// `UnsupportedPlatform` (Windows) or `UnsupportedAbi` (another Unix ABI).
pub const VERIFIED_TARGET: bool = cfg!(all(
    target_pointer_width = "64",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_endian = "little",
    any(
        all(target_os = "linux", target_env = "gnu"),
        target_os = "macos"
    )
));

/// The terminal installation result, or why there is none. Never installs.
pub fn installed() -> Result<Witness, InstallStatus> {
    imp::status()
}

/// F6 (r11 S6), called by every checked acquisition after [`installed`]
/// succeeded and before arming: the VFS and syscall slots still hold what
/// the installation left. Repairs nothing.
pub(crate) fn hooks_intact() -> Result<(), &'static str> {
    imp::hooks_intact()
}

/// What the load-time constructor observed (`None`: it did not run, or the
/// target is unsupported).
pub fn constructor_observation() -> Option<CtorObservation> {
    imp::observation()
}

/// Install the wrappers into a private SQLite instance whose constructor
/// abstained. Returns the terminal result if one exists; a failed loader proof
/// leaves installation possible for a later call. Once the proof passes, every
/// result is terminal, a failed VFS-method image check inside the installation
/// ([`InstallFailure::ForeignVfs`]) included.
///
/// The loader proof refuses ([`InstallStatus::NotPrivate`]) an executable
/// host, anchors in different images, and an image that exports SQLite: on
/// 64-bit little-endian Linux glibc any defined, externally bindable
/// `sqlite3*` dynamic symbol ([`HostFailure::SqliteExportedNamed`]) or a
/// dynamic symbol table it cannot read completely
/// ([`HostFailure::ExportInspection`]); on macOS an own-handle
/// `sqlite3_libversion`.
///
/// # Safety
///
/// The caller is the first operation of an artifact (e.g. the Python
/// `_native` module initializer, before it publishes anything) and guarantees:
/// this SQLite instance has no concurrent users; its symbols are private to
/// the containing artifact; no public operation can reach it until this call
/// returns success; and no other code replaces these system-call hooks or
/// shuts down or reconfigures the instance afterwards. The loader check
/// refuses an executable host or a SQLite from another image, but cannot
/// prove the absence of an already-published entry point.
pub unsafe fn install_private_instance(
    unpublished_module_anchor: *const std::ffi::c_void,
) -> Result<Witness, InstallStatus> {
    imp::private(unpublished_module_anchor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Barrier;

    const PRIVATE: Witness = Witness {
        why: InstallWhy::PrivateInstance,
        threads_at_install: Some(3),
        exports_checked: Some(9),
    };

    // Distinct bodies so no two share an address.
    unsafe extern "C" fn default_open() {
        std::hint::black_box(1u32);
    }
    unsafe extern "C" fn default_stat() {
        std::hint::black_box(2u32);
    }
    unsafe extern "C" fn custom_open() {
        std::hint::black_box(3u32);
    }
    unsafe extern "C" fn custom_stat() {
        std::hint::black_box(4u32);
    }
    unsafe extern "C" fn open_hook() {
        std::hint::black_box(5u32);
    }
    unsafe extern "C" fn stat_hook() {
        std::hint::black_box(6u32);
    }

    /// A fake `xSetSystemCall`/`xGetSystemCall` with SQLite's semantics: null
    /// means "the built-in default", which differs from the custom pointer the
    /// slot holds initially.
    #[derive(Default)]
    struct Fake {
        open: Cell<SyscallPtr>,
        stat: Cell<SyscallPtr>,
        sets: Cell<u32>,
        /// Every `set` call's slot name, in order.
        log: std::cell::RefCell<Vec<&'static str>>,
        fail_stat: bool,
        fail_restore_open: bool,
        ignore_open_set: bool,
    }

    impl Fake {
        fn new() -> Self {
            let fake = Self::default();
            fake.open.set(Some(custom_open));
            fake.stat.set(Some(custom_stat));
            fake
        }
        fn slot(&self, name: &CStr) -> Option<(&Cell<SyscallPtr>, ErasedFn)> {
            match name.to_bytes() {
                b"open" => Some((&self.open, default_open as ErasedFn)),
                b"stat" => Some((&self.stat, default_stat as ErasedFn)),
                _ => None,
            }
        }
    }

    impl SyscallTable for Fake {
        fn get(&self, name: &CStr) -> SyscallPtr {
            self.slot(name).and_then(|(cell, _)| cell.get())
        }
        fn set(&self, name: &CStr, f: SyscallPtr) -> std::os::raw::c_int {
            self.sets.set(self.sets.get() + 1);
            self.log.borrow_mut().push(match name.to_bytes() {
                b"open" => "open",
                b"stat" => "stat",
                _ => "?",
            });
            let Some((cell, default)) = self.slot(name) else {
                return ffi::SQLITE_NOTFOUND;
            };
            let is_hook = addr(f) == open_hook as *const () as usize
                || addr(f) == stat_hook as *const () as usize;
            if (self.fail_stat && name == c"stat")
                || (self.fail_restore_open && name == c"open" && !is_hook)
            {
                return ffi::SQLITE_ERROR;
            }
            if self.ignore_open_set && name == c"open" && is_hook {
                return ffi::SQLITE_OK;
            }
            cell.set(Some(f.unwrap_or(default)));
            ffi::SQLITE_OK
        }
    }

    fn fake_install(
        fake: &Fake,
        originals: &OnceLock<Originals>,
    ) -> Result<Witness, InstallFailure> {
        install_overrides(fake, originals, open_hook, stat_hook).map(|()| PRIVATE)
    }

    /// Regression (r9 v4 #1): constructor abstention seeded the installation
    /// cell, so a later permitted private initializer could never install.
    #[test]
    fn regression_install_abstention_does_not_seed_install() {
        let state = InstallState::new();
        let calls = AtomicU32::new(0);
        state.constructor(Some(2), |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(PRIVATE)
        });
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            state.observation(),
            Some(CtorObservation::AbstainedThreads(Some(2)))
        );
        assert_eq!(
            state.status(),
            Err(InstallStatus::AbstainedThreads(Some(2)))
        );
        assert!(state.install.get().is_none());
        for _ in 0..2 {
            let got = state.private(
                || Ok(()),
                |()| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(PRIVATE)
                },
            );
            assert_eq!(got, Ok(PRIVATE));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(state.status(), Ok(PRIVATE));
        // The observation is kept for diagnostics.
        assert_eq!(
            state.observation(),
            Some(CtorObservation::AbstainedThreads(Some(2)))
        );
    }

    /// Regression: an unreadable thread count (masked `/proc`) must abstain
    /// without a single setter call, and say the count is unknown.
    #[test]
    fn regression_install_unknown_threads_abstains() {
        let state = InstallState::new();
        let fake = Fake::new();
        let originals = OnceLock::new();
        state.constructor(None, |_| fake_install(&fake, &originals));
        assert_eq!(fake.sets.get(), 0);
        assert!(originals.get().is_none());
        assert_eq!(state.status(), Err(InstallStatus::AbstainedThreads(None)));
        let unknown = InstallStatus::AbstainedThreads(None).to_string();
        assert!(unknown.contains("could not be read"), "{unknown}");
        // The message names this platform's source (r11 S1 review nit 4).
        #[cfg(target_os = "linux")]
        assert!(unknown.contains("/proc/self/stat"), "{unknown}");
        #[cfg(target_os = "macos")]
        assert!(
            unknown.contains("proc_pidinfo") && !unknown.contains("/proc"),
            "{unknown}"
        );
        assert!(InstallStatus::AbstainedThreads(Some(4))
            .to_string()
            .contains("4 threads"));
        // Exactly one thread installs, through the same production sequence.
        let state = InstallState::new();
        state.constructor(Some(1), |_| fake_install(&fake, &originals));
        assert_eq!(state.status(), Ok(PRIVATE));
        assert_eq!(addr(fake.open.get()), open_hook as *const () as usize);
        assert_eq!(addr(fake.stat.get()), stat_hook as *const () as usize);
        // Design step 5: `open` is set before `stat` (r11 S1 review 4).
        assert_eq!(*fake.log.borrow(), ["open", "stat"]);
        assert_eq!(
            state.observation(),
            Some(CtorObservation::AttemptedSingleThread)
        );
    }

    /// Regression: a failed private-instance proof must not store a terminal
    /// result; only a passing proof starts an installation.
    #[test]
    fn regression_install_proof_failure_does_not_poison() {
        let state = InstallState::new();
        let calls = AtomicU32::new(0);
        let refusal = HostFailure::MainExecutable {
            what: "constructor",
        };
        let got = state.private(
            || Err::<(), _>(refusal),
            |()| {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(PRIVATE)
            },
        );
        assert_eq!(got, Err(InstallStatus::NotPrivate(refusal)));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(state.status(), Err(InstallStatus::NotRun));
        let got = state.private(
            || Ok(()),
            |()| {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(PRIVATE)
            },
        );
        assert_eq!(got, Ok(PRIVATE));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // With a terminal result, even a failing proof returns it unchanged.
        assert_eq!(
            state.private(|| Err::<(), _>(refusal), |()| unreachable!()),
            Ok(PRIVATE)
        );
    }

    /// Regression (r11 S6): the Linux private proof walks every export; an
    /// inspection that cannot complete, or a `sqlite3*` export, refuses
    /// before any installation and leaves the cell empty (a later valid
    /// proof still installs). Each refusal names what it saw.
    ///
    /// Regression (r11 S6 fix skeptic #1): this test fabricated the refusal
    /// inside `InstallState::private`, so replacing the proof's
    /// `export_check(..)?` with `.ok().flatten()` passed every test. The
    /// refusals now go through the proof's own decision ([`proof_decision`],
    /// called by `private_proof` with the real lookup and export check), and
    /// the export check must run on the proof's image and module anchor.
    #[test]
    fn regression_private_export_inspection_fails_closed() {
        use super::super::elf::{ElfError, SymbolName};
        const IMAGE: ImageIdentity = ImageIdentity {
            id: 0x7000,
            main: false,
        };
        const MODULE: usize = 0x7010;
        let anchors = [
            ("constructor", 0x7008),
            ("module", MODULE),
            ("sqlite3_open_v2", 0x7020),
        ];
        let lookup = |addr: usize| {
            if (0x7000..0x8000).contains(&addr) {
                Lookup::Found(IMAGE)
            } else {
                Lookup::Unknown
            }
        };
        let seen = Cell::new(None);
        let check = |result: Result<Option<u32>, HostFailure>| {
            let seen = &seen;
            move |module: usize, image: ImageIdentity| {
                seen.set(Some((module, image)));
                result
            }
        };
        // A passing inspection: the proof's image and the walked count.
        assert_eq!(
            proof_decision(&anchors, MODULE, &lookup, check(Ok(Some(42)))),
            Ok((IMAGE, Some(42)))
        );
        assert_eq!(seen.take(), Some((MODULE, IMAGE)));
        // An image refusal comes first: the export check does not run.
        assert_eq!(
            proof_decision(
                &[("constructor", 0x9000), ("module", MODULE)],
                MODULE,
                &lookup,
                check(Ok(Some(1)))
            ),
            Err(HostFailure::UnknownImage {
                what: "constructor"
            })
        );
        assert_eq!(seen.take(), None);
        let named =
            HostFailure::SqliteExportedNamed(SymbolName::from_prefix(b"sqlite3_open", false));
        for (failure, refusal, text) in [
            (
                ExportFailure::Elf(ElfError::Missing("DT_SYMENT")),
                HostFailure::ExportInspection(ElfError::Missing("DT_SYMENT")),
                "could not be inspected: no DT_SYMENT",
            ),
            (
                ExportFailure::Elf(ElfError::WorkLimit("symbols")),
                HostFailure::ExportInspection(ElfError::WorkLimit("symbols")),
                "too many symbols",
            ),
            (
                ExportFailure::Sqlite(SymbolName::from_prefix(b"sqlite3_open", false)),
                named,
                "exports sqlite3_open",
            ),
        ] {
            assert_eq!(export_refusal(failure), refusal);
            let shown = InstallStatus::NotPrivate(refusal).to_string();
            assert!(shown.contains(text), "{shown}");
            let state = InstallState::new();
            let calls = AtomicU32::new(0);
            let got = state.private(
                || {
                    proof_decision(
                        &anchors,
                        MODULE,
                        &lookup,
                        check(Err(export_refusal(failure))),
                    )
                },
                |(image, exports)| {
                    assert_eq!((image, exports), (IMAGE, Some(42)));
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(PRIVATE)
                },
            );
            assert_eq!(got, Err(InstallStatus::NotPrivate(refusal)));
            assert_eq!(
                seen.take(),
                Some((MODULE, IMAGE)),
                "checked the proof's image"
            );
            assert_eq!(calls.load(Ordering::SeqCst), 0, "nothing installed");
            assert_eq!(state.status(), Err(InstallStatus::NotRun), "not terminal");
            // A later valid proof still installs.
            let got = state.private(
                || proof_decision(&anchors, MODULE, &lookup, check(Ok(Some(42)))),
                |(image, exports)| {
                    assert_eq!((image, exports), (IMAGE, Some(42)));
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(PRIVATE)
                },
            );
            assert_eq!(got, Ok(PRIVATE));
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }
    }

    /// Regression: a failure after the first mutation must restore the EXACT
    /// captured pointer (not null, which SQLite maps to its built-in default),
    /// be terminal (no second attempt touches the table), and a failed
    /// restoration is its own status.
    #[test]
    fn regression_install_failure_is_terminal() {
        // `stat` cannot be set: `open` goes back to the captured custom pointer.
        let fake = Fake {
            fail_stat: true,
            ..Fake::new()
        };
        let originals = OnceLock::new();
        let state = InstallState::new();
        state.constructor(Some(1), |_| fake_install(&fake, &originals));
        let failed = Err(InstallStatus::Failed(InstallFailure::Set {
            name: "stat",
            rc: ffi::SQLITE_ERROR,
        }));
        assert_eq!(state.status(), failed);
        assert_eq!(
            addr(fake.open.get()),
            custom_open as *const () as usize,
            "not the default, not the hook"
        );
        assert_eq!(addr(fake.stat.get()), custom_stat as *const () as usize);
        // `open` first, then the failing `stat`, then `open` restored.
        assert_eq!(*fake.log.borrow(), ["open", "stat", "open"]);
        let o = originals
            .get()
            .expect("originals published before mutation");
        assert_eq!(
            (o.open as usize, o.stat as usize),
            (
                custom_open as *const () as usize,
                custom_stat as *const () as usize
            )
        );
        let sets = fake.sets.get();
        assert_eq!(
            state.private(|| Ok(()), |()| fake_install(&fake, &originals)),
            failed
        );
        state.constructor(Some(1), |_| fake_install(&fake, &originals));
        assert_eq!(fake.sets.get(), sets, "no retry of pointer mutation");

        // The getter does not report the wrapper: verify failure, restored.
        let fake = Fake {
            ignore_open_set: true,
            ..Fake::new()
        };
        let state = InstallState::new();
        state.constructor(Some(1), |_| fake_install(&fake, &OnceLock::new()));
        assert_eq!(
            state.status(),
            Err(InstallStatus::Failed(InstallFailure::Verify("open")))
        );
        assert_eq!(addr(fake.open.get()), custom_open as *const () as usize);
        assert_eq!(addr(fake.stat.get()), custom_stat as *const () as usize);

        // The restoration itself fails: a distinct terminal failure.
        let fake = Fake {
            fail_stat: true,
            fail_restore_open: true,
            ..Fake::new()
        };
        let state = InstallState::new();
        state.constructor(Some(1), |_| fake_install(&fake, &OnceLock::new()));
        let restore = Err(InstallStatus::Failed(InstallFailure::RestoreFailed("open")));
        assert_eq!(state.status(), restore);
        assert_eq!(
            addr(fake.open.get()),
            open_hook as *const () as usize,
            "the wrapper stays (pass-through)"
        );
        let sets = fake.sets.get();
        assert_eq!(
            state.private(|| Ok(()), |()| fake_install(&fake, &OnceLock::new())),
            restore
        );
        assert_eq!(fake.sets.get(), sets);

        // A slot SQLite does not have: nothing is mutated.
        struct Empty;
        impl SyscallTable for Empty {
            fn get(&self, _: &CStr) -> SyscallPtr {
                None
            }
            fn set(&self, _: &CStr, _: SyscallPtr) -> std::os::raw::c_int {
                panic!("no mutation without both originals")
            }
        }
        assert_eq!(
            install_overrides(&Empty, &OnceLock::new(), open_hook, stat_hook),
            Err(InstallFailure::OriginalMissing("open"))
        );

        // Originals published earlier differ from the slots now (r11 S1
        // review 7: unreachable through the terminal cell; defensive):
        // refused before any mutation.
        let fake = Fake::new();
        let seeded = OnceLock::new();
        let _ = seeded.set(Originals {
            open: default_open,
            stat: default_stat,
        });
        assert_eq!(
            install_overrides(&fake, &seeded, open_hook, stat_hook),
            Err(InstallFailure::OriginalsDiffer)
        );
        assert_eq!(fake.sets.get(), 0);
        assert_eq!(addr(fake.open.get()), custom_open as *const () as usize);
    }

    /// Regression: two private initializers that both pass the proof must run
    /// the installer once and observe one identical terminal result.
    #[test]
    fn regression_install_competing_private_initializers_once() {
        const N: usize = 8;
        let state = InstallState::new();
        let calls = AtomicU32::new(0);
        let barrier = Barrier::new(N);
        let results: Vec<_> = std::thread::scope(|s| {
            let handles: Vec<_> = (0..N)
                .map(|_| {
                    s.spawn(|| {
                        barrier.wait();
                        state.private(
                            || Ok(()),
                            |()| {
                                calls.fetch_add(1, Ordering::SeqCst);
                                std::thread::sleep(std::time::Duration::from_millis(20));
                                Err(InstallFailure::Verify("stat"))
                            },
                        )
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        for r in &results {
            assert_eq!(
                *r,
                Err(InstallStatus::Failed(InstallFailure::Verify("stat")))
            );
        }
    }

    /// Regression (r11 S1 review 5): the supported-target predicate matched
    /// big-endian `aarch64_be`, whose ABI is not verified. Every copy (the
    /// `imp` modules, `mod.rs`, `host.rs`, the tests) must be the same
    /// little-endian predicate. Regression (r11 S6): the live ELF inspection
    /// (`elf.rs`, the Linux export check) uses the narrower Linux glibc copy
    /// of it, which must be identical everywhere too.
    #[test]
    fn regression_target_predicate_copies_agree() {
        let compact = |s: &str| s.split_whitespace().collect::<String>();
        let head = "target_pointer_width = \"64\", \
             any(target_arch = \"x86_64\", target_arch = \"aarch64\"), \
             target_endian = \"little\", ";
        let predicate = compact(&format!(
            "{head}any(all(target_os = \"linux\", target_env = \"gnu\"), target_os = \"macos\")"
        ));
        let linux = compact(&format!(
            "{head}target_os = \"linux\", target_env = \"gnu\")"
        ));
        for (file, text, min, min_linux) in [
            ("mod.rs", include_str!("mod.rs"), 1, 1),
            ("install.rs", include_str!("install.rs"), 4, 3),
            ("host.rs", include_str!("host.rs"), 2, 0),
            ("acquire.rs", include_str!("acquire.rs"), 3, 0),
            ("elf.rs", include_str!("elf.rs"), 0, 1),
            ("elf_tests.rs", include_str!("elf_tests.rs"), 0, 1),
        ] {
            let text = compact(text);
            let starts = text
                .matches(&predicate[..predicate.find(',').unwrap()])
                .count();
            let full = text.matches(predicate.as_str()).count();
            let full_linux = text.matches(linux.as_str()).count();
            assert!(full >= min, "{file}: {full} copies of the predicate");
            assert!(
                full_linux >= min_linux,
                "{file}: {full_linux} copies of the Linux predicate"
            );
            assert_eq!(
                starts,
                full + full_linux,
                "{file}: a predicate copy differs"
            );
        }
    }

    /// Regression (r11 S4 skeptic P2): `VERIFIED_TARGET` is what dependents
    /// (the `_native` status test) branch on; it must agree with the
    /// installation status: false exactly when the status is the unsupported
    /// fallback.
    #[test]
    fn regression_verified_target_matches_install_status() {
        let unsupported = matches!(
            installed(),
            Err(InstallStatus::UnsupportedPlatform | InstallStatus::UnsupportedAbi)
        );
        assert_eq!(super::VERIFIED_TARGET, !unsupported);
    }

    /// Regression (r11 S1 skeptic P2): on a target outside the predicate
    /// (32-bit, musl, BSD, big-endian, Windows) nothing is installed and the
    /// status says why; a private initializer gets the same answer.
    #[cfg(not(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        target_endian = "little",
        any(all(target_os = "linux", target_env = "gnu"), target_os = "macos")
    )))]
    #[test]
    fn regression_unsupported_target_reports_unsupported() {
        let want = if cfg!(unix) {
            InstallStatus::UnsupportedAbi
        } else {
            InstallStatus::UnsupportedPlatform
        };
        assert_eq!(installed(), Err(want));
        assert_eq!(constructor_observation(), None);
        let anchor = regression_unsupported_target_reports_unsupported as *const std::ffi::c_void;
        // SAFETY: nothing is installed on this target.
        assert_eq!(unsafe { install_private_instance(anchor) }, Err(want));
        assert_eq!(installed(), Err(want));
    }

    /// Regression: `/proc/self/stat` parsing must take the fields after the
    /// LAST `)` and treat anything malformed as an unknown count (abstain).
    #[test]
    fn regression_thread_count_parser_rows() {
        let tail = " S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 3 0 99 1000";
        let line = |comm: &str| format!("4242 ({comm}){tail}\n").into_bytes();
        assert_eq!(parse_num_threads(&line("cat")), Some(3));
        assert_eq!(
            parse_num_threads(&line("a) S 9 9 9 9 9 9 9 9 9 9 9 9 9 9 9 9 7 (b")),
            Some(3)
        );
        assert_eq!(parse_num_threads(&line("two  spaces")), Some(3));
        assert_eq!(parse_num_threads(b"4242 (x) S 1 2 3"), None, "truncated");
        assert_eq!(
            parse_num_threads(b"4242 x S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 3"),
            None
        );
        assert_eq!(parse_num_threads(b""), None);
        for bad in ["0", "-1", "3a", "99999999999"] {
            let text = format!("1 (x) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 {bad} 0");
            assert_eq!(parse_num_threads(text.as_bytes()), None, "{bad}");
        }
        // The real reader works in this process (any positive count).
        #[cfg(target_os = "linux")]
        assert!(os_thread_count().is_some_and(|n| n >= 1));
    }

    /// Regression (Fable r11 nit 13): the constructor initializes SQLite in
    /// every binary that reaches `checked_open`, so a later `sqlite3_config`
    /// call (or rusqlite's `config_log`, which calls it) would fail at run
    /// time, and a `sqlite3_shutdown` would discard the installed hooks'
    /// contract (`install_private_instance`'s safety section). No workspace
    /// source may call any of them. Limit: only workspace `.rs` sources are
    /// scanned; a dependency calling `sqlite3_config` would show up only as a
    /// run-time `SQLITE_MISUSE`.
    #[test]
    fn regression_no_sqlite_config_after_constructor() {
        let needles = [
            ["sqlite3_", "config("].concat(),
            ["config_", "log("].concat(),
            ["sqlite3_", "shutdown("].concat(),
        ];
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap();
        let mut stack = vec![root.to_path_buf()];
        let mut hits = Vec::new();
        let mut scanned = 0;
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap().flatten() {
                let path = entry.path();
                let name = entry.file_name();
                let name = name.to_string_lossy();
                let Ok(kind) = entry.file_type() else {
                    continue;
                };
                if kind.is_dir() {
                    if !name.starts_with('.') && name != "target" && name != "node_modules" {
                        stack.push(path);
                    }
                } else if kind.is_file() && name.ends_with(".rs") {
                    scanned += 1;
                    let text = std::fs::read_to_string(&path).unwrap_or_default();
                    if needles.iter().any(|n| text.contains(n.as_str())) {
                        hits.push(path);
                    }
                }
            }
        }
        assert!(
            scanned > 100,
            "scanned only {scanned} files under {}",
            root.display()
        );
        assert!(
            hits.is_empty(),
            "sqlite3_config or sqlite3_shutdown after the constructor: {hits:?}"
        );
    }
}
