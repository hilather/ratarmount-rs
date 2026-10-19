//! Refuse a FUSE mount point that is, lies inside, covers, or aliases a directory the
//! single-threaded daemon reads by path (a served folder, a `--bind` source folder or
//! the `-w` overlay directory).
//!
//! A FUSE mount placed inside its own base makes the daemon `stat` its own mount
//! point and deadlock. The guard resolves paths read-only (no `mkdir`, no
//! `canonicalize`), compares the mount point with every base by three sound checks
//! (lexical, mount views from `/proc/self/mountinfo`, same-view inode) and reports the
//! first conflict. It runs before the overlay database/marker, any fork and the mount.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;

use crate::Args;

#[cfg(test)]
mod tests;

// ---------------------------------------------------------------------------
// Filesystem identity abstraction
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Node {
    Dir,
    Symlink(PathBuf),
    Other,
}

pub(crate) trait FsIdentity {
    /// Absolute, symlink-free current directory.
    fn cwd(&self) -> io::Result<PathBuf>;
    /// `symlink_metadata` (+ `read_link`); `Err(NotFound)` when missing.
    fn lstat(&self, p: &Path) -> io::Result<Node>;
    /// `metadata` (symlinks followed): `Dir` or `Other`; `Err` when missing or dangling.
    fn stat(&self, p: &Path) -> io::Result<Node>;
    /// `(st_dev, st_ino)` of an existing directory.
    fn dir_id(&self, p: &Path) -> Option<(u64, u64)>;
    /// Linux: the mount the kernel resolves `p` into. `None` elsewhere.
    fn mount_id(&self, p: &Path) -> Option<u64>;
    /// Linux: the bytes of `/proc/self/mountinfo`. `None` elsewhere or on error.
    fn mountinfo_bytes(&self) -> Option<Vec<u8>>;
}

pub(crate) struct RealFs {
    cwd: OnceLock<Result<PathBuf, String>>,
}

impl RealFs {
    pub(crate) fn new() -> Self {
        Self {
            cwd: OnceLock::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_cwd(p: PathBuf) -> Self {
        let cwd = OnceLock::new();
        let _ = cwd.set(Ok(p));
        Self { cwd }
    }
}

impl FsIdentity for RealFs {
    fn cwd(&self) -> io::Result<PathBuf> {
        match self
            .cwd
            .get_or_init(|| std::env::current_dir().map_err(|e| e.to_string()))
        {
            Ok(p) => Ok(p.clone()),
            Err(e) => Err(io::Error::other(e.clone())),
        }
    }

    fn lstat(&self, p: &Path) -> io::Result<Node> {
        let md = std::fs::symlink_metadata(p)?;
        let ft = md.file_type();
        Ok(if ft.is_symlink() {
            Node::Symlink(std::fs::read_link(p)?)
        } else if ft.is_dir() {
            Node::Dir
        } else {
            Node::Other
        })
    }

    fn stat(&self, p: &Path) -> io::Result<Node> {
        let md = std::fs::metadata(p)?;
        Ok(if md.is_dir() { Node::Dir } else { Node::Other })
    }

    fn dir_id(&self, p: &Path) -> Option<(u64, u64)> {
        use std::os::unix::fs::MetadataExt;
        let md = std::fs::metadata(p).ok()?;
        md.is_dir().then(|| (md.dev(), md.ino()))
    }

    fn mount_id(&self, p: &Path) -> Option<u64> {
        #[cfg(target_os = "linux")]
        {
            linux_mount_id(p)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = p;
            None
        }
    }

    fn mountinfo_bytes(&self) -> Option<Vec<u8>> {
        #[cfg(target_os = "linux")]
        {
            std::fs::read("/proc/self/mountinfo").ok()
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    }
}

/// `statx(STATX_MNT_ID)` offsets from the UAPI `struct statx` (256 bytes). The libc
/// `statx` wrapper is not named so gnu, musl and uclibc all compile.
#[cfg(target_os = "linux")]
const STATX_MNT_ID: u32 = 0x1000;
#[cfg(target_os = "linux")]
const STX_MASK: usize = 0;
#[cfg(target_os = "linux")]
const STX_MNT_ID: usize = 144;

#[cfg(target_os = "linux")]
pub(crate) fn mount_id_statx(p: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let cpath = std::ffi::CString::new(p.as_os_str().as_bytes()).ok()?;
    let mut buf = [0u8; 256];
    // SAFETY: `buf` is the 256-byte statx buffer and `cpath` is NUL-terminated.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_statx,
            libc::AT_FDCWD,
            cpath.as_ptr(),
            0 as libc::c_int,
            STATX_MNT_ID as libc::c_uint,
            buf.as_mut_ptr(),
        )
    };
    let mask = u32::from_ne_bytes(buf[STX_MASK..STX_MASK + 4].try_into().ok()?);
    if rc == 0 && mask & STATX_MNT_ID != 0 {
        Some(u64::from_ne_bytes(
            buf[STX_MNT_ID..STX_MNT_ID + 8].try_into().ok()?,
        ))
    } else {
        None
    }
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct FileHandle {
    handle_bytes: u32,
    handle_type: i32,
    f_handle: [u8; 128],
}

/// Kernels before 5.8: `name_to_handle_at` reports the mount id of the path.
#[cfg(target_os = "linux")]
pub(crate) fn mount_id_handle(p: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let cpath = std::ffi::CString::new(p.as_os_str().as_bytes()).ok()?;
    let mut fh = FileHandle {
        handle_bytes: 128,
        handle_type: 0,
        f_handle: [0; 128],
    };
    let mut mnt_id: libc::c_int = -1;
    // SAFETY: `fh` has the kernel `struct file_handle` layout with 128 handle bytes.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_name_to_handle_at,
            libc::AT_FDCWD,
            cpath.as_ptr(),
            &mut fh as *mut FileHandle,
            &mut mnt_id as *mut libc::c_int,
            0 as libc::c_int,
        )
    };
    let errno = if rc == 0 {
        0
    } else {
        io::Error::last_os_error().raw_os_error().unwrap_or(0)
    };
    #[allow(clippy::useless_conversion)] // c_long is i32 on 32-bit targets
    let rc = i64::from(rc);
    handle_result(rc, errno, mnt_id)
}

pub(crate) fn handle_result(rc: i64, errno: i32, mnt_id: i32) -> Option<u64> {
    #[cfg(target_os = "linux")]
    let overflow = libc::EOVERFLOW;
    #[cfg(not(target_os = "linux"))]
    let overflow = 75;
    if rc == 0 || (rc == -1 && errno == overflow) {
        u64::try_from(mnt_id).ok()
    } else {
        None
    }
}

#[cfg(target_os = "linux")]
fn linux_mount_id(p: &Path) -> Option<u64> {
    mount_id_statx(p).or_else(|| mount_id_handle(p))
}

// ---------------------------------------------------------------------------
// Resolver: read-only, non-strict realpath
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub(crate) struct Target {
    pub given: PathBuf,
    /// Given path made absolute lexically (cwd joined), for the "resolves to" suffix.
    lexical: PathBuf,
    /// Symlink-free path; missing components stay lexical.
    pub full: PathBuf,
    /// Longest existing prefix of `full`.
    pub anchor: PathBuf,
    pub tail: PathBuf,
}

impl Target {
    pub(crate) fn exact(&self) -> bool {
        self.tail.as_os_str().is_empty()
    }
}

#[derive(Debug)]
pub(crate) enum ResolveError {
    Cwd(io::Error),
    NotADirectory(PathBuf),
    TooManyLinks(PathBuf),
    Io(PathBuf, io::Error),
}

fn walk<'a, F: FsIdentity>(
    fs: &F,
    cur: &mut PathBuf,
    comps: impl Iterator<Item = Component<'a>>,
    hops: &mut u32,
) -> Result<(), ResolveError> {
    for c in comps {
        match c {
            Component::RootDir | Component::Prefix(_) => *cur = PathBuf::from("/"),
            Component::CurDir => {}
            Component::ParentDir => {
                cur.pop();
            }
            Component::Normal(name) => {
                let next = cur.join(name);
                match fs.lstat(&next) {
                    Err(e) if e.kind() == io::ErrorKind::NotFound => *cur = next,
                    Err(e) => return Err(ResolveError::Io(next, e)),
                    Ok(Node::Dir) => *cur = next,
                    Ok(Node::Other) => return Err(ResolveError::NotADirectory(next)),
                    Ok(Node::Symlink(target)) => {
                        *hops += 1;
                        if *hops > 40 {
                            return Err(ResolveError::TooManyLinks(next));
                        }
                        walk(fs, cur, target.components(), hops)?;
                    }
                }
            }
        }
    }
    Ok(())
}

/// Predict `canonicalize(given)` after the directories ratarmount itself creates exist.
///
/// Between the early check and `create_dir_all(mount point)` ratarmount creates only
/// plain directories (index parents, the `-w` directory, mount point parents) and
/// regular files. A plain directory resolves like a missing lexical component and
/// `create_dir_all` recurses on the lexical `parent()`, so every missing prefix is
/// created as a plain directory: for every layout where creation succeeds on HEAD,
/// this walk (symlinks followed, including dangling ones, `..` applied physically for
/// existing parts and lexically for missing ones) predicts the final canonical path.
pub(crate) fn resolve<F: FsIdentity>(fs: &F, given: &Path) -> Result<Target, ResolveError> {
    let mut cur;
    let lexical;
    if given.is_absolute() {
        cur = PathBuf::from("/");
        lexical = given.to_path_buf();
    } else {
        let c = fs.cwd().map_err(ResolveError::Cwd)?;
        lexical = c.join(given);
        cur = c;
    }
    let mut hops = 0;
    walk(fs, &mut cur, given.components(), &mut hops)?;
    let mut anchor = cur.clone();
    while !matches!(fs.lstat(&anchor), Ok(Node::Dir)) {
        if !anchor.pop() {
            break;
        }
    }
    let tail = cur
        .strip_prefix(&anchor)
        .map(Path::to_path_buf)
        .unwrap_or_default();
    Ok(Target {
        given: given.to_path_buf(),
        lexical,
        full: cur,
        anchor,
        tail,
    })
}

// ---------------------------------------------------------------------------
// mountinfo
// ---------------------------------------------------------------------------

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone)]
pub(crate) struct MountEntry {
    pub id: u64,
    #[allow(dead_code)]
    pub parent: u64,
    pub dev: (u32, u32),
    pub root: PathBuf,
    pub mount_point: PathBuf,
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn parse_mountinfo(bytes: &[u8]) -> Vec<MountEntry> {
    use crate::sandbox::process::unescape_mountinfo_field;
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    fn num<T: std::str::FromStr>(f: &[u8]) -> Option<T> {
        std::str::from_utf8(f).ok()?.parse().ok()
    }
    bytes
        .split(|b| *b == b'\n')
        .filter_map(|line| {
            let mut f = line.split(|b| *b == b' ');
            let id = num(f.next()?)?;
            let parent = num(f.next()?)?;
            let (maj, min) = {
                let d = f.next()?;
                let mut it = d.split(|b| *b == b':');
                (num(it.next()?)?, num(it.next()?)?)
            };
            let root = PathBuf::from(OsString::from_vec(unescape_mountinfo_field(f.next()?)?));
            let mount_point =
                PathBuf::from(OsString::from_vec(unescape_mountinfo_field(f.next()?)?));
            Some(MountEntry {
                id,
                parent,
                dev: (maj, min),
                root,
                mount_point,
            })
        })
        .collect()
}

/// Every path at which the physical location of `t` is visible through any mount of
/// the same superblock as the mount holding `t.anchor`. Mount-propagation targets are
/// a subset of these (copies land only in binds whose root is an ancestor).
#[cfg(any(target_os = "linux", test))]
fn views<'a, F: FsIdentity>(
    fs: &F,
    mi: &'a [MountEntry],
    t: &Target,
) -> Option<Vec<(PathBuf, &'a MountEntry)>> {
    let id = fs.mount_id(&t.anchor)?;
    let e0 = mi.iter().find(|e| e.id == id)?;
    let below = match t.anchor.strip_prefix(&e0.mount_point) {
        Ok(b) => b.to_path_buf(),
        Err(_) => {
            // Anchor spelled differently from the mount point (case/Unicode alias):
            // map by identity to the deepest ancestor that is the mount point.
            let want = fs.dir_id(&e0.mount_point)?;
            let a = t
                .anchor
                .ancestors()
                .find(|a| fs.mount_id(a) == Some(id) && fs.dir_id(a) == Some(want))?;
            t.anchor.strip_prefix(a).ok()?.to_path_buf()
        }
    };
    let phys = e0.root.join(&below).join(&t.tail);
    Some(
        mi.iter()
            .filter(|e| e.dev == e0.dev)
            .filter_map(|e| {
                let rest = match phys.strip_prefix(&e.root) {
                    Ok(r) => r.to_path_buf(),
                    Err(_) => alias_rest(fs, e0, e, t)?,
                };
                Some((e.mount_point.join(rest), e))
            })
            .collect(),
    )
}

/// `phys` relative to `e.root` when `t` is spelled differently (case/Unicode alias) from
/// the entry root below the mount boundary: the entry root is reachable through `e0`, so
/// find the ancestor of the anchor that is that same directory.
#[cfg(any(target_os = "linux", test))]
fn alias_rest<F: FsIdentity>(
    fs: &F,
    e0: &MountEntry,
    e: &MountEntry,
    t: &Target,
) -> Option<PathBuf> {
    let under = e.root.strip_prefix(&e0.root).ok()?;
    let via_e0 = e0.mount_point.join(under);
    // The path may now be overmounted by an unrelated mount: its inode is then not
    // the entry root inside `e0`.
    if fs.mount_id(&via_e0) != Some(e0.id) {
        return None;
    }
    let want = fs.dir_id(&via_e0)?;
    let a = t
        .anchor
        .ancestors()
        .find(|a| fs.mount_id(a) == Some(e0.id) && fs.dir_id(a) == Some(want))?;
    Some(t.anchor.strip_prefix(a).ok()?.join(&t.tail))
}

#[derive(PartialEq, Eq, Debug)]
enum View {
    Mount(u64),
    Dev(u64),
}

fn view_of<F: FsIdentity>(fs: &F, dir: &Path) -> Option<View> {
    if let Some(id) = fs.mount_id(dir) {
        return Some(View::Mount(id));
    }
    fs.dir_id(dir).map(|(dev, _)| View::Dev(dev))
}

// ---------------------------------------------------------------------------
// Relations
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Relation {
    Equal,
    Inside,
    Contains,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Via {
    Path,
    View {
        root: PathBuf,
        mount_point: PathBuf,
        id: u64,
        view: PathBuf,
    },
    Inode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BaseRole {
    Folder,
    Overlay,
    TempOverlay,
}

#[derive(Debug, Clone)]
pub(crate) struct Base {
    pub role: BaseRole,
    pub given: PathBuf,
    pub target: Target,
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Hint {
    pub computed_default: bool,
    pub dot_input: bool,
}

fn compare_rel(a: &Path, b: &Path) -> Option<Relation> {
    if a == b {
        Some(Relation::Equal)
    } else if a.starts_with(b) {
        Some(Relation::Inside)
    } else if b.starts_with(a) {
        Some(Relation::Contains)
    } else {
        None
    }
}

#[cfg(any(target_os = "linux", test))]
/// Compare a generated view with a base: lexically, then through the inode of the
/// directory above the view's mount point (case/Unicode aliases of the base spelling).
fn relation_view<F: FsIdentity>(
    fs: &F,
    v: &Path,
    e: &MountEntry,
    base: &Target,
) -> Option<Relation> {
    if let Some(r) = compare_rel(v, &base.full) {
        return Some(r);
    }
    let p = e.mount_point.parent().unwrap_or_else(|| Path::new("/"));
    let pid = fs.mount_id(p)?;
    let bid = fs.mount_id(&base.anchor)?;
    let vb = view_of(fs, &base.anchor)?;
    let idp = fs.dir_id(p);
    for a in p.ancestors() {
        let Some(ida) = fs.dir_id(a) else { continue };
        for b in base.anchor.ancestors() {
            if a == b || fs.dir_id(b) != Some(ida) || view_of(fs, b).as_ref() != Some(&vb) {
                continue;
            }
            // The daemon's name walk from `b` must cross into the mount holding `p`
            // (same mount for the whole chain, or an intervening mount that the walk
            // enters by name); an overmount on another mount (C3) is not reached.
            let (Ok(pa), Ok(bb)) = (p.strip_prefix(a), base.full.strip_prefix(b)) else {
                continue;
            };
            let walked = b.join(pa);
            let reaches = if pid == bid {
                fs.mount_id(a) == Some(pid) && view_of(fs, a) == view_of(fs, p)
            } else {
                fs.mount_id(&walked) == Some(pid) && fs.dir_id(&walked) == idp
            };
            if !reaches {
                continue;
            }
            let Ok(va) = v.strip_prefix(a) else { continue };
            if let Some(r) = compare_rel(va, bb) {
                return Some(r);
            }
        }
    }
    None
}

struct MpCtx<'a> {
    t: &'a Target,
    mount_id: Option<u64>,
    #[cfg(any(target_os = "linux", test))]
    views: Option<Vec<(PathBuf, &'a MountEntry)>>,
}

fn relation<F: FsIdentity>(fs: &F, mp: &MpCtx<'_>, base: &Target) -> Option<(Relation, Via)> {
    // 1. Lexical.
    if let Some(r) = compare_rel(&mp.t.full, &base.full) {
        return Some((r, Via::Path));
    }
    // 2. Views.
    #[cfg(any(target_os = "linux", test))]
    if let Some(vs) = &mp.views {
        for (view, e) in vs {
            if Some(e.id) == mp.mount_id {
                continue;
            }
            if let Some(r) = relation_view(fs, view, e, base) {
                return Some((
                    r,
                    Via::View {
                        root: e.root.clone(),
                        mount_point: e.mount_point.clone(),
                        id: e.id,
                        view: view.clone(),
                    },
                ));
            }
        }
    }
    // 3. Same-view inode.
    let vm = view_of(fs, &mp.t.anchor)?;
    let vb = view_of(fs, &base.anchor)?;
    let anchor_id = fs.dir_id(&mp.t.anchor);
    for a in mp.t.anchor.ancestors() {
        let Some(ida) = fs.dir_id(a) else { continue };
        let va = view_of(fs, a);
        // An ancestor above a mount boundary on the mount-point side (the view
        // differs from the anchor's) still matches when it is in the base's own view
        // and the base's name walk from the pair reaches the anchor by crossing that
        // boundary.
        let crossing = va.as_ref() != Some(&vm);
        if crossing && va.as_ref() != Some(&vb) {
            continue;
        }
        for b in base.anchor.ancestors() {
            if a == b || fs.dir_id(b) != Some(ida) || view_of(fs, b).as_ref() != Some(&vb) {
                continue;
            }
            let (Ok(ma), Ok(bb)) = (mp.t.full.strip_prefix(a), base.full.strip_prefix(b)) else {
                continue;
            };
            if crossing {
                let rest = mp.t.anchor.strip_prefix(a).unwrap_or(Path::new(""));
                let walked = fs.dir_id(&b.join(rest));
                if walked.is_none() || walked != anchor_id {
                    continue;
                }
            }
            if let Some(r) = compare_rel(ma, bb) {
                return Some((r, Via::Inode));
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

fn shown(t: &Target) -> String {
    if t.full == t.lexical {
        t.given.display().to_string()
    } else {
        format!("{} (resolves to {})", t.given.display(), t.full.display())
    }
}

fn alias_suffix(via: &Via) -> String {
    match via {
        Via::Path => String::new(),
        Via::View {
            root,
            mount_point,
            view,
            ..
        } => format!(
            " (it is also visible at {} through the bind mount of {} at {}, and a FUSE mount propagates to bind mounts)",
            view.display(),
            root.display(),
            mount_point.display()
        ),
        Via::Inode => " (through a bind mount or filesystem alias: same directory)".to_string(),
    }
}

fn role_phrase(role: BaseRole) -> &'static str {
    match role {
        BaseRole::Folder => "the folder being mounted",
        BaseRole::Overlay => "the write-overlay directory (-w)",
        BaseRole::TempOverlay => "the temporary write overlay",
    }
}

fn conflict_message(mp: &Target, base: &Base, rel: Relation, via: &Via, hint: Hint) -> String {
    let mps = shown(mp);
    let bs = shown(&base.target);
    let alias = alias_suffix(via);
    let phrase = role_phrase(base.role);
    let dot = if hint.dot_input {
        " The default mount point for \".\" is \"mount\"; pass an explicit mount point outside the folder."
    } else {
        ""
    };
    match (rel, base.role) {
        (Relation::Equal, BaseRole::Folder) => {
            let advice = if hint.dot_input {
                "Pass an explicit mount point outside the folder".to_string()
            } else {
                format!(
                    "Use another mount point, e.g. {}.mounted",
                    base.given.display().to_string().trim_end_matches('/')
                )
            };
            format!(
                "mount point {mps} is {phrase}{alias}; mounting a folder on itself deadlocks the FUSE daemon. {advice}"
            )
        }
        (Relation::Equal, BaseRole::Overlay) => {
            format!("mount point {mps} is {phrase}{alias}; choose a mount point outside it")
        }
        (Relation::Equal, BaseRole::TempOverlay) => {
            format!("mount point {mps} is {phrase} {bs}{alias}; choose a mount point outside it")
        }
        (Relation::Inside, BaseRole::Folder) => format!(
            "mount point {mps} is inside {phrase} {bs}{alias}; the daemon would stat its own mount point and hang. Choose a mount point outside it{dot}"
        ),
        (Relation::Inside, _) => format!(
            "mount point {mps} is inside {phrase} {bs}{alias}; choose a mount point outside it{dot}"
        ),
        (Relation::Contains, _) => format!(
            "mount point {mps} would cover {phrase} {bs}{alias}, which the daemon reads by path. Choose a mount point that is not an ancestor of it"
        ),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Subject {
    Mount,
    Overlay,
}

fn resolve_error_message(e: ResolveError, subject: Subject, given: &Path, default: bool) -> String {
    let g = given.display();
    match (e, subject) {
        (ResolveError::Cwd(e), _) => {
            format!("cannot resolve relative path {g}: cannot determine the current directory: {e}")
        }
        (ResolveError::NotADirectory(_), Subject::Mount) if default => format!(
            "default mount point {g} exists and is not a directory; pass a mount point explicitly"
        ),
        (ResolveError::NotADirectory(p), Subject::Mount) => format!(
            "cannot use {g} as a mount point: {} is not a directory",
            p.display()
        ),
        (ResolveError::NotADirectory(p), Subject::Overlay) => format!(
            "cannot use {g} as the write-overlay directory: {} is not a directory",
            p.display()
        ),
        (ResolveError::TooManyLinks(p), Subject::Mount) => format!(
            "cannot resolve mount point {g}: too many levels of symbolic links at {}",
            p.display()
        ),
        (ResolveError::TooManyLinks(p), Subject::Overlay) => format!(
            "cannot resolve write-overlay directory {g}: too many levels of symbolic links at {}",
            p.display()
        ),
        (ResolveError::Io(p, e), Subject::Mount) => {
            format!("cannot resolve mount point {g}: {}: {e}", p.display())
        }
        (ResolveError::Io(p, e), Subject::Overlay) => format!(
            "cannot resolve write-overlay directory {g}: {}: {e}",
            p.display()
        ),
    }
}

// ---------------------------------------------------------------------------
// Bases and checks
// ---------------------------------------------------------------------------

/// `looks_like_git`, through the abstraction (`p/.git` exists, or a bare repository);
/// symlinks are followed like the factory's `is_dir`/`is_file`/`exists`.
fn looks_like_git_fs<F: FsIdentity>(fs: &F, dir: &Path) -> bool {
    if !matches!(fs.stat(dir), Ok(Node::Dir)) {
        return false;
    }
    if fs.stat(&dir.join(".git")).is_ok() {
        return true;
    }
    matches!(fs.stat(&dir.join("HEAD")), Ok(Node::Other))
        && matches!(fs.stat(&dir.join("objects")), Ok(Node::Dir))
        && matches!(fs.stat(&dir.join("refs")), Ok(Node::Dir))
}

/// `Path::exists` on a raw operand (any kind, symlinks followed), as
/// `split_inline_reference` asks before splitting `@REV`.
fn operand_exists<F: FsIdentity>(fs: &F, c: &Path) -> bool {
    let Some(name) = c.file_name() else {
        return matches!(resolve(fs, c), Ok(t) if t.exact());
    };
    let parent = match c.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    match resolve(fs, parent) {
        Ok(t) if t.exact() => fs.stat(&t.full.join(name)).is_ok(),
        _ => false,
    }
}

/// Every possible base root for every raw local operand, at call time. An operand that
/// exists now is a base when it is a directory (the literal path wins in the factory);
/// otherwise its `@REV`-stripped prefix is a base when that is a git repository.
pub(crate) fn bases_now<F: FsIdentity>(
    fs: &F,
    candidates: &[PathBuf],
    overlay: Option<(&Path, bool)>,
) -> Result<Vec<Base>, String> {
    let mut out = Vec::new();
    for c in candidates {
        match resolve(fs, c) {
            Ok(t) if t.exact() => out.push(Base {
                role: BaseRole::Folder,
                given: c.clone(),
                target: t,
            }),
            Err(ResolveError::Cwd(e)) => {
                return Err(resolve_error_message(
                    ResolveError::Cwd(e),
                    Subject::Mount,
                    c,
                    false,
                ))
            }
            // Best effort: any other resolve error (not a directory, loops, I/O) means
            // the operand is not a base the daemon could walk; only a missing current
            // directory is fatal, since no relative path can be judged.
            _ => {}
        }
        // An existing literal path (file included) wins over `@REV` in the factory.
        if operand_exists(fs, c) {
            continue;
        }
        let Some(text) = c.to_str() else { continue };
        for (at, _) in text.rmatch_indices('@') {
            let prefix = &text[..at];
            if prefix.is_empty() {
                continue;
            }
            let p = Path::new(prefix);
            if let Ok(t) = resolve(fs, p) {
                if t.exact() && looks_like_git_fs(fs, &t.full) {
                    out.push(Base {
                        role: BaseRole::Folder,
                        given: p.to_path_buf(),
                        target: t,
                    });
                    break;
                }
            }
        }
    }
    if let Some((w, temp)) = overlay {
        let t = resolve(fs, w).map_err(|e| resolve_error_message(e, Subject::Overlay, w, false))?;
        out.push(Base {
            role: if temp {
                BaseRole::TempOverlay
            } else {
                BaseRole::Overlay
            },
            given: w.to_path_buf(),
            target: t,
        });
    }
    Ok(out)
}

pub(crate) fn check_mount_point<F: FsIdentity>(
    fs: &F,
    mp: &Path,
    bases: &[Base],
    hint: Hint,
) -> Result<(), String> {
    let t = resolve(fs, mp)
        .map_err(|e| resolve_error_message(e, Subject::Mount, mp, hint.computed_default))?;
    #[cfg(any(target_os = "linux", test))]
    let mountinfo = fs.mountinfo_bytes().map(|b| parse_mountinfo(&b));
    let ctx = MpCtx {
        t: &t,
        mount_id: fs.mount_id(&t.anchor),
        #[cfg(any(target_os = "linux", test))]
        views: mountinfo.as_deref().and_then(|mi| views(fs, mi, &t)),
    };
    for base in bases {
        if let Some((rel, via)) = relation(fs, &ctx, &base.target) {
            return Err(conflict_message(&t, base, rel, &via, hint));
        }
    }
    Ok(())
}

#[derive(Debug)]
pub(crate) struct MountPlan {
    pub mp: PathBuf,
    /// Raw local, non-URL operands in argument order (binds last).
    pub candidates: Vec<PathBuf>,
    pub overlay_temp: bool,
    pub hint: Hint,
    pub derived_rolling_input: Option<PathBuf>,
}

pub(crate) fn skip_guard(args: &Args, explicit: Option<&Path>, publishing: bool) -> bool {
    args.no_mount
        || args.unmount
        || args.find
        || (publishing && explicit.is_none())
        || (crate::any_export(args) && explicit.is_none())
}

pub(crate) fn plan_mount_point<F: FsIdentity>(
    fs: &F,
    args: &Args,
    explicit: Option<PathBuf>,
    inputs: &[PathBuf],
) -> Result<MountPlan, String> {
    let computed_default = explicit.is_none();
    let mut derived_rolling_input = None;
    let mp = match explicit {
        Some(mp) => mp,
        None => {
            let input = effective_default_input(args, inputs);
            if args.roll_every.is_some() {
                derived_rolling_input = Some(input.clone());
            }
            default_for_input(fs, &input)
        }
    };
    let hint = Hint {
        computed_default,
        dot_input: computed_default && inputs.first().is_some_and(|i| i.file_name().is_none()),
    };
    let candidates: Vec<PathBuf> = inputs
        .iter()
        .filter(|i| !ratarmount_remote::is_remote_url(&i.to_string_lossy()))
        .cloned()
        .collect();
    let overlay_temp = args
        .write_overlay
        .as_ref()
        .is_some_and(|w| w.as_os_str() == ":temp:");
    let overlay = args.write_overlay.clone().filter(|_| !overlay_temp);
    let bases = bases_now(fs, &candidates, overlay.as_deref().map(|w| (w, false)))?;
    check_mount_point(fs, &mp, &bases, hint)?;
    Ok(MountPlan {
        mp,
        candidates,
        overlay_temp,
        hint,
        derived_rolling_input,
    })
}

/// Re-check after the factory opened the inputs and `main` prepared the `-w`
/// directory: index folders created while opening make new bases visible.
pub(crate) fn decisive_check<F: FsIdentity>(
    fs: &F,
    plan: &MountPlan,
    overlay_actual: Option<&Path>,
) -> Result<(), String> {
    let bases = bases_now(
        fs,
        &plan.candidates,
        overlay_actual.map(|w| (w, plan.overlay_temp)),
    )?;
    check_mount_point(fs, &plan.mp, &bases, plan.hint)
}

/// What `WriteOverlay::new` did on HEAD for a missing directory
/// (`write_overlay.rs:963-972`); an existing non-directory is left for it to report.
pub(crate) fn prepare_overlay_dir(w: &Path) -> io::Result<()> {
    if !w.exists() {
        std::fs::create_dir_all(w)
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Default mount point
// ---------------------------------------------------------------------------

/// `default_mountpoint`, except a folder whose default would be itself becomes
/// `<default>.mounted` (upstream parity). URL-shaped inputs never touch the filesystem.
pub(crate) fn default_for_input<F: FsIdentity>(fs: &F, input: &Path) -> PathBuf {
    let s = input.to_string_lossy();
    if ratarmount_remote::is_remote_url(&s) {
        return crate::default_mountpoint(input);
    }
    if let Some(d) = crate::default_mountpoint_url(&s) {
        return d;
    }
    let d = crate::default_mountpoint(input);
    if let (Ok(ti), Ok(td)) = (resolve(fs, input), resolve(fs, &d)) {
        if ti.exact()
            && td.exact()
            && (ti.full == td.full
                || fs
                    .dir_id(&ti.full)
                    .is_some_and(|id| fs.dir_id(&td.full) == Some(id)))
        {
            return PathBuf::from(format!("{}.mounted", d.display()));
        }
    }
    d
}

/// The path `main` derives the default from: the rolling active generation when
/// `--roll-every` applies (read-only, same as HEAD), else the first input.
pub(crate) fn effective_default_input(args: &Args, inputs: &[PathBuf]) -> PathBuf {
    let first = inputs.first().cloned().unwrap_or_default();
    if args.roll_every.is_some()
        && inputs.len() == 1
        && args.source_binds.is_empty()
        && args.corpus_list.is_none()
        && !args.find
    {
        let derived = ratarmount_compositing::SeriesName::new(&inputs[0])
            .and_then(|name| {
                let found = name.discover()?;
                name.generation(found.last().map_or(1, |(n, _)| *n))
            })
            .ok();
        return derived.unwrap_or(first);
    }
    first
}

pub(crate) fn rolling_derivation_notice(
    derived: &Path,
    actual: &Path,
    mp: &Path,
) -> Option<String> {
    (derived != actual).then(|| {
        format!(
            "internal: rolling active generation {} differs from the one used to name the default mount point ({}); keeping the mount point {}",
            actual.display(),
            derived.display(),
            mp.display()
        )
    })
}
