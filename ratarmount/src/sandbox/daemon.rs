use super::process::{self, MountState, Mounter, ProcessMounter};
use super::protocol::*;
use ratarmount_session::factory;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

type Result<T> = std::result::Result<T, ApiError>;

fn invalid(message: impl Into<String>) -> ApiError {
    ApiError::new("invalid_request", message)
}

pub fn validate_name(name: &str) -> Result<()> {
    if name.len() > 128
        || !name
            .bytes()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric())
        || !name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
    {
        return Err(invalid("names must start with an ASCII letter/digit, then letters, digits, dot, underscore or hyphen (max 128)"));
    }
    Ok(())
}

fn private_dir(path: &Path) -> Result<()> {
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    }
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_dir() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
        return Err(ApiError::new(
            "unsafe_path",
            format!(
                "{} must be an owned, private directory (0700), not a symlink",
                path.display()
            ),
        ));
    }
    Ok(())
}

pub fn lock(path: &Path) -> Result<File> {
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o077 != 0
        || meta.nlink() != 1
    {
        return Err(ApiError::new(
            "unsafe_path",
            "lock must be a private, owned regular file",
        ));
    }
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(ApiError::new(
            "in_use",
            "socket or state directory already in use",
        ));
    }
    Ok(file)
}

pub struct SocketGuard {
    pub listener: UnixListener,
    path: PathBuf,
    inode: u64,
    _lock: File,
}

impl SocketGuard {
    pub fn bind(path: &Path) -> Result<Self> {
        super::inspection::validate_socket_path(path)?;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let meta = fs::metadata(parent)?;
        // A sticky directory (e.g. /tmp) also prevents another uid replacing our socket.
        // libc::S_ISVTX is u16 on macOS and u32 on Linux; the bit value is the same.
        const STICKY_BIT: u32 = 0o1000;
        if !meta.is_dir()
            || (meta.mode() & 0o022 != 0 && meta.mode() & STICKY_BIT == 0)
            || (meta.uid() != unsafe { libc::geteuid() }
                && !(meta.uid() == 0 && meta.mode() & STICKY_BIT != 0))
        {
            return Err(ApiError::new(
                "unsafe_path",
                "socket parent must not be writable by other users unless sticky",
            ));
        }
        let mut lock_name = path.as_os_str().to_os_string();
        lock_name.push(".lock");
        let guard = lock(Path::new(&lock_name))?;
        match fs::symlink_metadata(path) {
            Ok(meta) => {
                check_socket_metadata(&meta, unsafe { libc::geteuid() })?;
                if socket_alive(path)? {
                    return Err(ApiError::new("in_use", "socket already has a listener"));
                }
                fs::remove_file(path)?;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        // Bind under a restrictive umask; never expose a permissive socket before chmod.
        // This runs before the daemon creates any threads.
        let old = unsafe { libc::umask(0o177) };
        let bound = UnixListener::bind(path);
        unsafe {
            libc::umask(old);
        }
        let listener = bound?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        let inode = fs::symlink_metadata(path)?.ino();
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener,
            path: path.into(),
            inode,
            _lock: guard,
        })
    }
}

#[cfg(target_os = "linux")]
fn socket_alive(path: &Path) -> io::Result<bool> {
    use std::os::fd::{FromRawFd, OwnedFd};
    let bytes = path.as_os_str().as_encoded_bytes();
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if bytes.len() >= address.sun_path.len() || bytes.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Unix socket path",
        ));
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (to, from) in address.sun_path.iter_mut().zip(bytes) {
        *to = *from as libc::c_char;
    }
    let fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let length = std::mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1;
    if unsafe {
        libc::connect(
            fd.as_raw_fd(),
            &address as *const _ as *const libc::sockaddr,
            length as libc::socklen_t,
        )
    } == 0
    {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ECONNREFUSED | libc::ENOENT) => Ok(false),
        // A full listen backlog is still a live socket, never grounds to unlink it.
        Some(libc::EAGAIN | libc::EINPROGRESS) => Ok(true),
        _ => Err(error),
    }
}

#[cfg(not(target_os = "linux"))]
fn socket_alive(path: &Path) -> io::Result<bool> {
    match UnixStream::connect(path) {
        Ok(_) => Ok(true),
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
            ) =>
        {
            Ok(false)
        }
        Err(e) => Err(e),
    }
}

pub fn check_socket_metadata(meta: &fs::Metadata, uid: u32) -> Result<()> {
    if !meta.file_type().is_socket() || meta.uid() != uid {
        return Err(ApiError::new(
            "unsafe_path",
            "existing socket path must be an owned socket, never a symlink or regular file",
        ));
    }
    Ok(())
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        if fs::symlink_metadata(&self.path)
            .is_ok_and(|m| m.ino() == self.inode && m.file_type().is_socket())
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    version: u32,
    bases: BTreeMap<String, Base>,
}

fn atomic_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let parent = path.parent().expect("state path has parent");
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer(&mut file, value).map_err(|e| invalid(e.to_string()))?;
    file.as_file().sync_all()?;
    file.persist(path).map_err(|e| ApiError::from(e.error))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

pub struct Supervisor<M: Mounter> {
    pub root: PathBuf,
    pub mounter: M,
    pub attempts: BTreeMap<String, Attempt>,
    bases: BTreeMap<String, Base>,
    ram_root: Option<PathBuf>,
    max_attempts: usize,
    timeout: Duration,
    pub stopping: bool,
    _lock: File,
}

impl<M: Mounter> Supervisor<M> {
    pub fn open(root: &Path, max_attempts: usize, timeout: Duration, mounter: M) -> Result<Self> {
        private_dir(root)?;
        let root = fs::canonicalize(root)?;
        if root.to_str().is_none() {
            return Err(invalid("state path must be UTF-8"));
        }
        let guard = lock(&root.join("daemon.lock"))?;
        private_dir(&root.join("attempts"))?;
        private_dir(&root.join("indexes"))?;
        let bases = match fs::read(root.join("bases.json")) {
            Ok(bytes) => {
                let state: State = serde_json::from_slice(&bytes)
                    .map_err(|e| invalid(format!("invalid persisted bases: {e}")))?;
                if state.version != VERSION {
                    return Err(ApiError::new(
                        "unsupported_version",
                        "unsupported state version",
                    ));
                }
                for (name, base) in &state.bases {
                    validate_name(name)?;
                    if name != &base.name {
                        return Err(invalid("base key/name mismatch"));
                    }
                    validate_base(base, &root.join("indexes").join(name))?;
                }
                state.bases
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(e.into()),
        };
        let ram_root: Option<PathBuf> = match fs::read(root.join("ram-root.json")) {
            Ok(bytes) => Some(serde_json::from_slice(&bytes).map_err(|e| invalid(e.to_string()))?),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        if let Some(ram) = &ram_root {
            if ram.file_name() != Some(std::ffi::OsStr::new(&ram_name(&root))) {
                return Err(ApiError::new(
                    "unsafe_path",
                    "RAM state directory name does not match state identity",
                ));
            }
            if ram.exists() {
                private_dir(ram)?;
                verify_tmpfs(ram)?;
            }
        }
        let mut supervisor = Self {
            root,
            mounter,
            attempts: BTreeMap::new(),
            bases,
            ram_root,
            max_attempts,
            timeout,
            stopping: false,
            _lock: guard,
        };
        supervisor.reconcile()?;
        Ok(supervisor)
    }

    fn indexes(&self, base: &str) -> PathBuf {
        self.root.join("indexes").join(base)
    }

    fn save(&self) -> Result<()> {
        atomic_json(
            &self.root.join("bases.json"),
            &State {
                version: VERSION,
                bases: self.bases.clone(),
            },
        )
    }

    fn reconcile(&mut self) -> Result<()> {
        // No PID adoption: never signal a persisted pid that may now be reused.
        for entry in fs::read_dir(self.root.join("attempts"))? {
            let entry = entry?;
            let id = entry
                .file_name()
                .into_string()
                .map_err(|_| invalid("non-UTF-8 attempt directory"))?;
            validate_name(&id)?;
            private_dir(&entry.path())?;
            let path = entry.path().join("mnt");
            if fs::symlink_metadata(&path).is_ok_and(|m| !m.is_dir()) {
                return Err(invalid("unsafe stale mountpoint"));
            }
            self.mounter.cleanup(&path)?;
            fs::remove_dir_all(entry.path())?;
        }
        if let Some(ram) = &self.ram_root {
            if ram.exists() {
                // All FUSE mounts are gone before any RAM overlay is removed.
                for entry in fs::read_dir(ram)? {
                    let entry = entry?;
                    let id = entry
                        .file_name()
                        .into_string()
                        .map_err(|_| invalid("invalid RAM attempt name"))?;
                    validate_name(&id)?;
                    private_dir(&entry.path())?;
                    fs::remove_dir_all(entry.path())?;
                }
            }
        }
        Ok(())
    }

    pub fn supervise(&mut self) {
        for attempt in self.attempts.values_mut() {
            if attempt.status == "crashed" {
                continue;
            }
            match self.mounter.poll(attempt) {
                Ok(MountState::Ready) => attempt.status = "ready".into(),
                Ok(MountState::Starting) if attempt.status == "starting" => {}
                _ => attempt.status = "crashed".into(),
            }
        }
    }

    pub fn handle(&mut self, operation: Operation) -> Result<Value> {
        self.supervise();
        match operation {
            Operation::CreateBase {
                name,
                source,
                options,
            } => {
                let mut base = Base {
                    name,
                    source,
                    options,
                };
                let indexes = self.indexes(&base.name);
                validate_base(&base, &indexes)?;
                base.source = absolute_source(&base.source)?;
                for bind in &mut base.options.binds {
                    let parsed: ratarmount_compositing::SourceBind =
                        bind.parse().map_err(invalid)?;
                    *bind = format!("{}={}", parsed.mount_path, absolute_source(&parsed.source)?);
                }
                if self.bases.contains_key(&base.name) {
                    return Err(ApiError::new(
                        "already_exists",
                        "base already exists; choose a new name",
                    ));
                }
                private_dir(&indexes)?;
                self.mounter.prepare(&base, &indexes, self.timeout)?;
                self.bases.insert(base.name.clone(), base.clone());
                if let Err(e) = self.save() {
                    self.bases.remove(&base.name);
                    return Err(e);
                }
                Ok(json!(base))
            }
            Operation::New {
                base,
                count,
                overlay,
                quota,
                readonly_globs,
            } => self.new_attempts(&base, count, overlay, quota, readonly_globs),
            Operation::List { base } => {
                if let Some(name) = &base {
                    self.base(name)?;
                }
                Ok(json!(self
                    .attempts
                    .values()
                    .filter(|a| base.as_ref().is_none_or(|b| b == &a.base))
                    .collect::<Vec<_>>()))
            }
            Operation::Diff { id, git } => {
                let attempt = self.attempt(&id)?.clone();
                let deleted = self.mounter.deleted_paths(&attempt)?;
                let base = self.base(&attempt.base)?;
                let source = open_base(base, &self.indexes(&base.name))?;
                let patch = crate::diff::render_source(
                    &crate::diff::DiffArgs {
                        directory: attempt.overlay_dir.clone(),
                        git,
                        ..Default::default()
                    },
                    source.source.clone(),
                    deleted,
                )
                .map_err(|e| ApiError::new("diff_failed", e))?;
                let mut response = serde_json::Map::new();
                ratarmount_compositing::overlay_changes::json_bytes(&mut response, "patch", &patch);
                Ok(serde_json::Value::Object(response))
            }
            Operation::Stats { id } => {
                let attempt = self.attempt(&id)?.clone();
                let stats = if let Some(deleted) = self.mounter.deleted_paths(&attempt)? {
                    crate::overlay_stats::render(
                        ratarmount_compositing::OverlayStats {
                            usage: ratarmount_compositing::OverlayUsage::scan(
                                &attempt.overlay_dir,
                            )?,
                            files_deleted: deleted.len() as u64,
                        },
                        true,
                    )
                } else {
                    crate::overlay_stats::run(&crate::overlay_stats::StatsArgs {
                        directory: attempt.overlay_dir,
                        json: true,
                    })
                    .map_err(|e| ApiError::new("stats_failed", e))?
                };
                serde_json::from_str(&stats).map_err(|e| invalid(e.to_string()))
            }
            Operation::Destroy { id, base } => {
                match (id, base) {
                    (Some(id), None) => {
                        self.destroy(&id)?;
                    }
                    (None, Some(name)) => {
                        self.base(&name)?;
                        let ids: Vec<_> = self
                            .attempts
                            .values()
                            .filter(|a| a.base == name)
                            .map(|a| a.id.clone())
                            .collect();
                        for id in ids {
                            self.destroy(&id)?;
                        }
                    }
                    _ => return Err(invalid("destroy requires exactly one of id or base")),
                }
                Ok(json!({"destroyed": true}))
            }
            Operation::Shutdown => {
                self.destroy_all()?;
                self.stopping = true;
                Ok(json!({"shutdown": true}))
            }
        }
    }

    fn base(&self, name: &str) -> Result<&Base> {
        self.bases
            .get(name)
            .ok_or_else(|| ApiError::new("not_found", "unknown base"))
    }
    fn attempt(&self, id: &str) -> Result<&Attempt> {
        self.attempts
            .get(id)
            .ok_or_else(|| ApiError::new("not_found", "unknown attempt"))
    }

    fn ram_root(&mut self) -> Result<PathBuf> {
        if let Some(root) = &self.ram_root {
            private_dir(root)?;
            verify_tmpfs(root)?;
            return Ok(root.clone());
        }
        let runtime = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
        for parent in std::iter::once(PathBuf::from("/dev/shm")).chain(runtime) {
            if verify_tmpfs(&parent).is_err() {
                continue;
            }
            let root = fs::canonicalize(parent)?.join(ram_name(&self.root));
            match private_dir(&root) {
                Ok(()) => {}
                Err(error) if error.code == "io" => continue,
                Err(error) => return Err(error),
            }
            atomic_json(&self.root.join("ram-root.json"), &root)?;
            self.ram_root = Some(root.clone());
            return Ok(root);
        }
        Err(ApiError::new(
            "unsupported",
            "no writable tmpfs; choose disk overlays",
        ))
    }

    fn new_attempts(
        &mut self,
        name: &str,
        count: usize,
        overlay: Overlay,
        quota: Option<u64>,
        readonly: Vec<String>,
    ) -> Result<Value> {
        let base = self.base(name)?.clone();
        if count == 0 || count > self.max_attempts.saturating_sub(self.attempts.len()) {
            return Err(ApiError::new(
                "capacity",
                "count must be positive and fit --max-attempts (including crashed attempts)",
            ));
        }
        // Attempt policy can only tighten the base policy.
        let quota = match (base.options.quota, quota) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        let readonly: Vec<_> = base
            .options
            .readonly_globs
            .iter()
            .cloned()
            .chain(readonly)
            .collect();
        ratarmount_compositing::ReadOnlyGlobs::with_allow(&readonly, &base.options.allow_globs)
            .map_err(|e| invalid(e.to_string()))?;
        let ram = match overlay {
            Overlay::Disk => None,
            Overlay::Tmpfs => Some(self.ram_root()?),
        };
        let indexes = self.indexes(name);
        let mut ids = Vec::new();
        let deadline = Instant::now() + self.timeout;
        let result = (|| {
            for _ in 0..count {
                if Instant::now() >= deadline {
                    return Err(ApiError::new("timeout", "attempt batch startup timed out"));
                }
                let dir = tempfile::Builder::new()
                    .prefix("attempt-")
                    .permissions(fs::Permissions::from_mode(0o700))
                    .tempdir_in(self.root.join("attempts"))?
                    .keep();
                let id = dir.file_name().unwrap().to_str().unwrap().to_owned();
                let attempt = Attempt {
                    id: id.clone(),
                    base: name.into(),
                    path: dir.join("mnt"),
                    overlay_dir: ram
                        .as_ref()
                        .map_or_else(|| dir.join("overlay"), |p| p.join(&id)),
                    status: "starting".into(),
                };
                // Record before spawning so partial batches and initialization errors clean up.
                ids.push(id.clone());
                self.attempts.insert(id, attempt.clone());
                private_dir(&attempt.path)?;
                private_dir(&attempt.overlay_dir)?;
                self.mounter
                    .spawn(&base, &indexes, &attempt, quota, &readonly)?;
            }
            loop {
                self.supervise();
                if let Some(id) = ids.iter().find(|id| self.attempts[*id].status == "crashed") {
                    let log = self.attempts[id].path.parent().unwrap().join("mount.log");
                    let mut diagnostic = String::new();
                    if let Ok(file) = File::open(log) {
                        let _ = file.take(8192).read_to_string(&mut diagnostic);
                    }
                    return Err(ApiError::new(
                        "mount_failed",
                        format!("attempt {id} exited or lost its mount during setup: {diagnostic}"),
                    ));
                }
                if ids.iter().all(|id| self.attempts[id].status == "ready") {
                    break;
                }
                if Instant::now() >= deadline {
                    return Err(ApiError::new(
                        "timeout",
                        "attempt mount readiness timed out",
                    ));
                }
                thread::sleep(Duration::from_millis(20));
            }
            Ok(json!(ids
                .iter()
                .map(|id| &self.attempts[id])
                .collect::<Vec<_>>()))
        })();
        if let Err(mut error) = result {
            let mut retained = Vec::new();
            for id in &ids {
                if self.destroy(id).is_err() {
                    retained.push(id.clone());
                }
            }
            if !retained.is_empty() {
                error.message.push_str(&format!(
                    "; cleanup failed, retained attempts: {}",
                    retained.join(", ")
                ));
            }
            return Err(error);
        }
        result
    }

    pub fn destroy(&mut self, id: &str) -> Result<()> {
        let attempt = self.attempt(id)?.clone();
        self.mounter.cleanup(&attempt.path)?;
        if attempt.overlay_dir.exists() {
            fs::remove_dir_all(&attempt.overlay_dir)?;
        }
        fs::remove_dir_all(attempt.path.parent().expect("attempt root"))?;
        self.attempts.remove(id);
        Ok(())
    }

    pub fn destroy_all(&mut self) -> Result<()> {
        let ids: Vec<_> = self.attempts.keys().cloned().collect();
        let mut error = None;
        for id in ids {
            if let Err(e) = self.destroy(&id) {
                error = Some(e);
            }
        }
        error.map_or(Ok(()), Err)
    }
}

fn ram_name(root: &Path) -> String {
    format!(
        "ratarmount-sandbox-{:x}",
        Sha256::digest(root.as_os_str().as_encoded_bytes())
    )
}

#[cfg(target_os = "linux")]
fn verify_tmpfs(path: &Path) -> Result<()> {
    let name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|e| invalid(e.to_string()))?;
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(name.as_ptr(), &mut stat) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    if stat.f_type != libc::TMPFS_MAGIC {
        return Err(ApiError::new("unsupported", "RAM overlay requires tmpfs"));
    }
    Ok(())
}
#[cfg(not(target_os = "linux"))]
fn verify_tmpfs(_path: &Path) -> Result<()> {
    Err(ApiError::new("unsupported", "tmpfs overlays require Linux"))
}

fn absolute_source(source: &str) -> Result<String> {
    // Probe only an ASCII scheme prefix: the legacy URL detector also slices
    // its input at byte seven for restic, which need not be a UTF-8 boundary.
    let remote = source
        .get(..7)
        .is_some_and(|s| s.eq_ignore_ascii_case("restic:"))
        || source.split_once("://").is_some_and(|(scheme, _)| {
            scheme.is_ascii() && ratarmount_remote::is_remote_url(&format!("{scheme}://"))
        });
    if Path::new(source).is_absolute() || remote {
        return Ok(source.into());
    }
    std::env::current_dir()?
        .join(source)
        .into_os_string()
        .into_string()
        .map_err(|_| invalid("source path must be UTF-8"))
}

fn validate_base(base: &Base, indexes: &Path) -> Result<()> {
    validate_name(&base.name)?;
    if base.source.is_empty() || base.source.contains('\0') {
        return Err(invalid("source must not be empty or contain NUL"));
    }
    let attempt = Attempt {
        id: "validate".into(),
        base: base.name.clone(),
        path: PathBuf::from("/unused/mnt"),
        overlay_dir: PathBuf::from("/unused/overlay"),
        status: "starting".into(),
    };
    // Reuse the mount CLI's option validation, including readonly patterns and binds.
    crate::parse_args_from(std::iter::once(OsString::from("ratarmount")).chain(
        process::mount_args(
            base,
            indexes,
            &attempt,
            base.options.quota,
            &base.options.readonly_globs,
        ),
    ))
    .map_err(|e| invalid(e.to_string()))?;
    Ok(())
}
use std::ffi::OsString;

fn open_base(base: &Base, indexes: &Path) -> Result<factory::MountBundle> {
    let mut options = ratarmount_core::OpenOptions {
        index_folders: vec![indexes.into()],
        write_index: false,
        git_synthetic_head: base.options.git_synthetic_head,
        recursive: base.options.recursive,
        recursion_depth: base.options.recursive.then_some(-1),
        gnu_incremental: Some(false),
        ..Default::default()
    };
    let binds = base
        .options
        .binds
        .iter()
        .map(|s| s.parse())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(invalid)?;
    factory::build_mount_source_with_bindings(
        &[PathBuf::from(&base.source)],
        &mut options,
        false,
        factory::CompositingOptions {
            recursive: base.options.recursive,
            ..Default::default()
        },
        factory::SourceBindings {
            binds,
            ..Default::default()
        },
    )
    .map_err(|e| ApiError::new("base_open_failed", e))
}

struct Connection {
    stream: UnixStream,
    input: Vec<u8>,
    active: Instant,
}

fn send(stream: &mut UnixStream, response: Response) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(&response)?;
    if bytes.len() + 1 > MAX_RESPONSE {
        bytes = serde_json::to_vec(&Response::from_result(Err(ApiError::new(
            "response_too_large",
            "response exceeds 64 MiB; export the diff locally",
        ))))?;
    }
    bytes.push(b'\n');
    stream.set_nonblocking(false)?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let result = stream.write_all(&bytes);
    stream.set_nonblocking(true)?;
    result
}

pub fn serve(socket: &Path, root: &Path, limit: usize, timeout: Duration) -> Result<()> {
    if !cfg!(target_os = "linux") {
        return Err(ApiError::new(
            "unsupported",
            "sandbox supervision currently requires Linux",
        ));
    }
    // Create only the private root before binding, so the socket can live inside
    // it. An occupied socket must not trigger any attempt reconciliation.
    private_dir(root)?;
    let socket = SocketGuard::bind(socket)?;
    let mut supervisor = Supervisor::open(
        root,
        limit,
        timeout,
        ProcessMounter::new(std::env::current_exe()?),
    )?;
    crate::overlay_commit::install_term_signal_flag();
    let mut connections: Vec<Connection> = Vec::new();
    while !supervisor.stopping && !crate::overlay_commit::term_requested() {
        supervisor.supervise();
        match socket.listener.accept() {
            Ok((stream, _)) if connections.len() < 32 => {
                stream.set_nonblocking(true)?;
                connections.push(Connection {
                    stream,
                    input: Vec::new(),
                    active: Instant::now(),
                });
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e.into()),
        }
        connections.retain_mut(|connection| {
            if supervisor.stopping {
                return false;
            }
            let mut bytes = [0; 8192];
            match connection.stream.read(&mut bytes) {
                Ok(0) if !connection.input.contains(&b'\n') => return false,
                Ok(0) => {}
                Ok(n) => {
                    connection.input.extend_from_slice(&bytes[..n]);
                    connection.active = Instant::now();
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => return false,
            }
            if let Some(end) = connection.input.iter().position(|c| *c == b'\n') {
                let result = if end > MAX_REQUEST {
                    Err(invalid("request exceeds 1 MiB"))
                } else {
                    Request::parse(&connection.input[..end])
                        .and_then(|r| supervisor.handle(r.operation))
                };
                connection.input.drain(..=end);
                connection.active = Instant::now();
                return send(&mut connection.stream, Response::from_result(result)).is_ok();
            }
            if connection.input.len() > MAX_REQUEST {
                let _ = send(
                    &mut connection.stream,
                    Response::from_result(Err(invalid("request exceeds 1 MiB"))),
                );
                return false;
            }
            connection.active.elapsed() < Duration::from_secs(30)
        });
        thread::sleep(Duration::from_millis(10));
    }
    supervisor.destroy_all()
}
