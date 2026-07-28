//! In-FS control folder (Python `/.ratarmount-control/`).
//!
//! Wraps an inner [`MountSource`] and exposes virtual files under
//! `/.ratarmount-control/` for status / pid / unmount / help. Opening or
//! reading `unmount` invokes an optional callback (orchestrator wires unmount).

use std::collections::BTreeMap;
use std::io::{self, Cursor};
use std::sync::Arc;

use ratarmount_core::{
    create_root_file_info, normpath, FileInfo, ListModeResult, ListResult, MountSource, UserData,
    S_IFDIR, S_IFMT, S_IFREG,
};

/// Directory name at the mount root (hidden, leading dot).
pub const CONTROL_DIR_NAME: &str = ".ratarmount-control";
/// Absolute path of the control directory.
pub const CONTROL_DIR_PATH: &str = "/.ratarmount-control";

const TAG_PREFIX: &str = "control:";
const TAG_DIR: &str = "control:dir";
const TAG_STATUS: &str = "control:status";
const TAG_PID: &str = "control:pid";
const TAG_UNMOUNT: &str = "control:unmount";
const TAG_HELP: &str = "control:help";

/// Virtual control file names inside [`CONTROL_DIR_PATH`].
const CONTROL_FILES: &[&str] = &["status", "pid", "unmount", "help"];

/// Options for [`ControlFolderMountSource`].
#[derive(Clone, Default)]
pub struct ControlFolderOptions {
    /// When `false`, the control folder is not exposed (full pass-through).
    pub enabled: bool,
    /// Optional label included in `status` output (e.g. mount point path).
    pub label: Option<String>,
    /// Invoked when `unmount` is opened or read.
    pub on_unmount: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl ControlFolderOptions {
    /// Enabled control folder with no label or unmount callback.
    pub fn enabled() -> Self {
        Self {
            enabled: true,
            label: None,
            on_unmount: None,
        }
    }

    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    pub fn with_on_unmount(mut self, f: Arc<dyn Fn() + Send + Sync>) -> Self {
        self.on_unmount = Some(f);
        self
    }
}

/// MountSource wrapper that injects `/.ratarmount-control/` virtual files.
pub struct ControlFolderMountSource {
    inner: Arc<dyn MountSource>,
    enabled: bool,
    label: Option<String>,
    on_unmount: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl ControlFolderMountSource {
    /// Wrap `inner` with an optional in-FS control interface.
    pub fn new(inner: Arc<dyn MountSource>, options: ControlFolderOptions) -> Self {
        Self {
            inner,
            enabled: options.enabled,
            label: options.label,
            on_unmount: options.on_unmount,
        }
    }

    fn control_dir_info() -> FileInfo {
        FileInfo {
            size: 0,
            mtime: 0.0,
            mode: S_IFDIR | 0o555,
            linkname: String::new(),
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
            userdata: vec![UserData::Other(TAG_DIR.into())],
        }
    }

    fn file_info_for(name: &str, content_len: u64) -> FileInfo {
        let tag = match name {
            "status" => TAG_STATUS,
            "pid" => TAG_PID,
            "unmount" => TAG_UNMOUNT,
            "help" => TAG_HELP,
            _ => TAG_STATUS,
        };
        // unmount is world-writable in spirit (Python allows write to trigger);
        // mode is regular readable (+ write bit for unmount so tools open O_WRONLY).
        let mode = if name == "unmount" {
            S_IFREG | 0o666
        } else {
            S_IFREG | 0o444
        };
        FileInfo {
            size: content_len,
            mtime: 0.0,
            mode,
            linkname: String::new(),
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
            userdata: vec![UserData::Other(tag.into())],
        }
    }

    fn control_tag(file_info: &FileInfo) -> Option<&str> {
        file_info.userdata.iter().rev().find_map(|u| match u {
            UserData::Other(s) if s.starts_with(TAG_PREFIX) => Some(s.as_str()),
            _ => None,
        })
    }

    fn is_control_path(path: &str) -> bool {
        let path = normpath(path);
        path == CONTROL_DIR_PATH
            || path.starts_with(CONTROL_DIR_PATH) && {
                path.as_bytes().get(CONTROL_DIR_PATH.len()) == Some(&b'/')
            }
    }

    /// Basename of a direct child of the control dir, if any.
    fn control_file_name(path: &str) -> Option<String> {
        let path = normpath(path);
        let prefix = concat!("/.ratarmount-control", "/");
        let rest = path.strip_prefix(prefix)?;
        if rest.is_empty() || rest.contains('/') {
            return None;
        }
        Some(rest.to_string())
    }

    fn status_text(&self) -> String {
        let mut s = String::new();
        match &self.label {
            Some(label) => s.push_str(&format!("mounted {label}\n")),
            None => s.push_str("mounted\n"),
        }
        s.push_str(&format!("pid {}\n", std::process::id()));
        if let Some(listing) = self.inner.list("/") {
            let names: Vec<String> = match listing {
                ListResult::Names(n) => n,
                ListResult::Infos(m) => m.into_keys().collect(),
            };
            s.push_str("root:\n");
            for name in names.iter().take(128) {
                // Avoid advertising our own control dir twice if inner had one.
                if name == CONTROL_DIR_NAME {
                    continue;
                }
                s.push_str(&format!("  {name}\n"));
            }
        }
        s
    }

    fn pid_text() -> String {
        format!("{}\n", std::process::id())
    }

    fn help_text() -> String {
        "ratarmount control files:\n\
         status  - mount status and root listing\n\
         pid     - ratarmount process id\n\
         unmount - open or write to request unmount\n\
         help    - this text\n"
            .to_string()
    }

    fn unmount_text() -> String {
        "ok\n".to_string()
    }

    fn content_for_name(&self, name: &str) -> Option<String> {
        match name {
            "status" => Some(self.status_text()),
            "pid" => Some(Self::pid_text()),
            "unmount" => Some(Self::unmount_text()),
            "help" => Some(Self::help_text()),
            _ => None,
        }
    }

    fn content_for_tag(&self, tag: &str) -> Option<String> {
        match tag {
            TAG_STATUS => Some(self.status_text()),
            TAG_PID => Some(Self::pid_text()),
            TAG_UNMOUNT => Some(Self::unmount_text()),
            TAG_HELP => Some(Self::help_text()),
            _ => None,
        }
    }

    fn fire_unmount(&self) {
        if let Some(cb) = &self.on_unmount {
            cb();
        }
    }

    fn merge_control_into_root(&self, listing: ListResult) -> ListResult {
        let dir_fi = Self::control_dir_info();
        match listing {
            ListResult::Names(mut names) => {
                if !names.iter().any(|n| n == CONTROL_DIR_NAME) {
                    names.push(CONTROL_DIR_NAME.to_string());
                }
                ListResult::Names(names)
            }
            ListResult::Infos(mut map) => {
                map.insert(CONTROL_DIR_NAME.to_string(), dir_fi);
                ListResult::Infos(map)
            }
        }
    }
}

impl MountSource for ControlFolderMountSource {
    fn list(&self, path: &str) -> Option<ListResult> {
        let path = normpath(path);
        if !self.enabled {
            return self.inner.list(&path);
        }

        if path == CONTROL_DIR_PATH {
            let mut map = BTreeMap::new();
            for name in CONTROL_FILES {
                let content = self.content_for_name(name).unwrap_or_default();
                map.insert(
                    (*name).to_string(),
                    Self::file_info_for(name, content.len() as u64),
                );
            }
            return Some(ListResult::Infos(map));
        }

        if Self::is_control_path(&path) {
            // Nested under control but not the dir itself → no children (files only).
            return None;
        }

        let inner = self.inner.list(&path)?;
        if path == "/" {
            Some(self.merge_control_into_root(inner))
        } else {
            Some(inner)
        }
    }

    fn list_mode(&self, path: &str) -> Option<ListModeResult> {
        match self.list(path)? {
            ListResult::Names(n) => Some(ListModeResult::Names(n)),
            ListResult::Infos(m) => Some(ListModeResult::Modes(
                m.into_iter().map(|(k, v)| (k, v.mode)).collect(),
            )),
        }
    }

    fn lookup(&self, path: &str, file_version: i32) -> Option<FileInfo> {
        let path = normpath(path);
        if !self.enabled {
            return self.inner.lookup(&path, file_version);
        }

        if path == "/" {
            return Some(create_root_file_info());
        }

        if path == CONTROL_DIR_PATH {
            return Some(Self::control_dir_info());
        }

        if let Some(name) = Self::control_file_name(&path) {
            let content = self.content_for_name(&name)?;
            return Some(Self::file_info_for(&name, content.len() as u64));
        }

        // Deeper bogus control paths → missing
        if Self::is_control_path(&path) {
            return None;
        }

        self.inner.lookup(&path, file_version)
    }

    fn open(
        &self,
        file_info: &FileInfo,
        buffering: i32,
    ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
        if let Some(tag) = Self::control_tag(file_info) {
            if tag == TAG_DIR {
                return Err(io::Error::new(
                    io::ErrorKind::IsADirectory,
                    "control directory",
                ));
            }
            if tag == TAG_UNMOUNT {
                self.fire_unmount();
            }
            let content = self.content_for_tag(tag).unwrap_or_default();
            return Ok(Box::new(Cursor::new(content.into_bytes())));
        }
        self.inner.open(file_info, buffering)
    }

    fn read(&self, file_info: &FileInfo, size: usize, offset: u64) -> io::Result<Vec<u8>> {
        // open() fires the unmount callback for TAG_UNMOUNT; serve content via Cursor.
        let mut file = self.open(file_info, 0)?;
        use std::io::{Read, Seek, SeekFrom};
        file.seek(SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; size];
        let mut filled = 0;
        while filled < buf.len() {
            match file.read(&mut buf[filled..]) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        buf.truncate(filled);
        Ok(buf)
    }

    fn versions(&self, path: &str) -> u32 {
        let path = normpath(path);
        if self.enabled && (path == CONTROL_DIR_PATH || Self::control_file_name(&path).is_some()) {
            return 1;
        }
        if self.enabled && Self::is_control_path(&path) {
            return 0;
        }
        self.inner.versions(&path)
    }

    fn is_immutable(&self) -> bool {
        // Control folder is virtual; mutability of the rest matches inner.
        self.inner.is_immutable()
    }

    fn statfs(&self) -> ratarmount_core::StatFs {
        self.inner.statfs()
    }

    fn list_xattr(&self, file_info: &FileInfo) -> Vec<String> {
        if Self::control_tag(file_info).is_some() {
            return Vec::new();
        }
        self.inner.list_xattr(file_info)
    }

    fn get_xattr(&self, file_info: &FileInfo, key: &str) -> Option<Vec<u8>> {
        if Self::control_tag(file_info).is_some() {
            return None;
        }
        self.inner.get_xattr(file_info, key)
    }

    fn exists(&self, path: &str) -> bool {
        self.lookup(path, 0).is_some()
    }

    fn is_dir(&self, path: &str) -> bool {
        self.lookup(path, 0)
            .map(|fi| fi.mode & S_IFMT == S_IFDIR)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use crate::folder::FolderMountSource;

    struct NullBase;
    impl MountSource for NullBase {
        fn list(&self, path: &str) -> Option<ListResult> {
            if path == "/" || path.is_empty() {
                Some(ListResult::Infos(BTreeMap::new()))
            } else {
                None
            }
        }
        fn lookup(&self, path: &str, _: i32) -> Option<FileInfo> {
            if normpath(path) == "/" {
                Some(create_root_file_info())
            } else {
                None
            }
        }
        fn open(&self, _: &FileInfo, _: i32) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
            Err(io::Error::new(io::ErrorKind::NotFound, "null base"))
        }
        fn is_immutable(&self) -> bool {
            true
        }
    }

    fn names_from_list(r: ListResult) -> Vec<String> {
        match r {
            ListResult::Names(n) => n,
            ListResult::Infos(m) => m.into_keys().collect(),
        }
    }

    fn read_all(ms: &dyn MountSource, path: &str) -> String {
        let fi = ms.lookup(path, 0).expect("lookup");
        let mut f = ms.open(&fi, 0).expect("open");
        let mut buf = String::new();
        f.read_to_string(&mut buf).unwrap();
        buf
    }

    #[test]
    fn disabled_is_passthrough() {
        let inner = Arc::new(NullBase) as Arc<dyn MountSource>;
        let ms = ControlFolderMountSource::new(
            inner,
            ControlFolderOptions {
                enabled: false,
                ..Default::default()
            },
        );
        let root = names_from_list(ms.list("/").unwrap());
        assert!(!root.iter().any(|n| n == CONTROL_DIR_NAME));
        assert!(ms.lookup(CONTROL_DIR_PATH, 0).is_none());
    }

    #[test]
    fn list_root_includes_control_dir() {
        let inner = Arc::new(NullBase) as Arc<dyn MountSource>;
        let ms = ControlFolderMountSource::new(inner, ControlFolderOptions::enabled());
        let root = names_from_list(ms.list("/").unwrap());
        assert!(root.iter().any(|n| n == CONTROL_DIR_NAME));
        let fi = ms.lookup(CONTROL_DIR_PATH, 0).unwrap();
        assert_eq!(fi.mode & S_IFMT, S_IFDIR);
    }

    #[test]
    fn list_control_dir_shows_virtual_files() {
        let inner = Arc::new(NullBase) as Arc<dyn MountSource>;
        let ms = ControlFolderMountSource::new(inner, ControlFolderOptions::enabled());
        let names = names_from_list(ms.list(CONTROL_DIR_PATH).unwrap());
        for expected in CONTROL_FILES {
            assert!(
                names.iter().any(|n| n == *expected),
                "missing {expected} in {names:?}"
            );
        }
    }

    #[test]
    fn status_and_pid_readable() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("hello.txt"), b"hi").unwrap();
        let folder = FolderMountSource::new(dir.path()).unwrap();
        let inner = Arc::new(folder) as Arc<dyn MountSource>;
        let ms = ControlFolderMountSource::new(
            inner,
            ControlFolderOptions::enabled().with_label("/mnt/test"),
        );

        let status = read_all(&ms, &format!("{CONTROL_DIR_PATH}/status"));
        assert!(status.contains("mounted /mnt/test"), "{status}");
        assert!(
            status.contains(&format!("pid {}", std::process::id())),
            "{status}"
        );
        assert!(status.contains("hello.txt"), "{status}");

        let pid = read_all(&ms, &format!("{CONTROL_DIR_PATH}/pid"));
        assert_eq!(pid.trim(), std::process::id().to_string());

        let help = read_all(&ms, &format!("{CONTROL_DIR_PATH}/help"));
        assert!(help.contains("unmount"), "{help}");
    }

    #[test]
    fn unmount_open_fires_callback() {
        let fired = Arc::new(AtomicBool::new(false));
        let fired2 = Arc::clone(&fired);
        let inner = Arc::new(NullBase) as Arc<dyn MountSource>;
        let ms = ControlFolderMountSource::new(
            inner,
            ControlFolderOptions::enabled().with_on_unmount(Arc::new(move || {
                fired2.store(true, Ordering::SeqCst);
            })),
        );
        let fi = ms
            .lookup(&format!("{CONTROL_DIR_PATH}/unmount"), 0)
            .unwrap();
        let _ = ms.open(&fi, 0).unwrap();
        assert!(fired.load(Ordering::SeqCst));
    }

    #[test]
    fn unmount_read_fires_callback() {
        let count = Arc::new(AtomicUsize::new(0));
        let count2 = Arc::clone(&count);
        let inner = Arc::new(NullBase) as Arc<dyn MountSource>;
        let ms = ControlFolderMountSource::new(
            inner,
            ControlFolderOptions::enabled().with_on_unmount(Arc::new(move || {
                count2.fetch_add(1, Ordering::SeqCst);
            })),
        );
        let fi = ms
            .lookup(&format!("{CONTROL_DIR_PATH}/unmount"), 0)
            .unwrap();
        let data = ms.read(&fi, 64, 0).unwrap();
        assert_eq!(String::from_utf8_lossy(&data).trim(), "ok");
        // read() goes through open(), which fires the callback once
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn pass_through_other_paths() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), b"body").unwrap();
        let folder = FolderMountSource::new(dir.path()).unwrap();
        let inner = Arc::new(folder) as Arc<dyn MountSource>;
        let ms = ControlFolderMountSource::new(inner, ControlFolderOptions::enabled());

        let names = names_from_list(ms.list("/").unwrap());
        assert!(names.iter().any(|n| n == "a.txt"));
        assert!(names.iter().any(|n| n == CONTROL_DIR_NAME));

        let body = read_all(&ms, "/a.txt");
        assert_eq!(body, "body");
        assert!(ms.lookup("/missing", 0).is_none());
    }

    #[test]
    fn open_control_dir_is_error() {
        let inner = Arc::new(NullBase) as Arc<dyn MountSource>;
        let ms = ControlFolderMountSource::new(inner, ControlFolderOptions::enabled());
        let fi = ms.lookup(CONTROL_DIR_PATH, 0).unwrap();
        let err = match ms.open(&fi, 0) {
            Ok(_) => panic!("expected IsADirectory for control dir open"),
            Err(e) => e,
        };
        assert_eq!(err.kind(), io::ErrorKind::IsADirectory);
    }
}
