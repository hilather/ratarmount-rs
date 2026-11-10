//! Linux libfuse3 mount helper. fuser serves requests through the duplicated fd.

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::io;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::ptr::{self, NonNull};
use std::sync::OnceLock;

use fuser::{Config, MountOption, SessionACL};
use log::{info, warn};

pub(crate) const SONAMES: [&CStr; 2] = [c"libfuse3.so.4", c"libfuse3.so.3"];

#[repr(C)]
struct FuseArgs {
    argc: c_int,
    argv: *mut *mut c_char,
    allocated: c_int,
}

type SessionNew =
    unsafe extern "C" fn(*mut FuseArgs, *const c_void, usize, *mut c_void) -> *mut c_void;
type SessionMount = unsafe extern "C" fn(*mut c_void, *const c_char) -> c_int;
type SessionFd = unsafe extern "C" fn(*mut c_void) -> c_int;
type SessionUnmount = unsafe extern "C" fn(*mut c_void);
type SessionDestroy = unsafe extern "C" fn(*mut c_void);
type FreeArgs = unsafe extern "C" fn(*mut FuseArgs);

#[derive(Debug)]
struct Api {
    soname: &'static CStr,
    new: SessionNew,
    mount: SessionMount,
    fd: SessionFd,
    unmount: SessionUnmount,
    destroy: SessionDestroy,
    free_args: FreeArgs,
}

fn api() -> io::Result<&'static Api> {
    static API: OnceLock<Result<Api, String>> = OnceLock::new();
    API.get_or_init(|| load(&SONAMES))
        .as_ref()
        .map_err(|error| io::Error::new(io::ErrorKind::NotFound, error.clone()))
}

pub(super) fn preflight() -> io::Result<()> {
    api().map(drop)
}

fn symbol(handle: *mut c_void, name: &CStr) -> Option<NonNull<c_void>> {
    // SAFETY: load passes a live dlopen handle and a terminated symbol name.
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-LIBFUSE3-DLSYM","item":"ratarmount_fuse::libfuse3::symbol","disposition":"out-of-family","category":"dynamic-loader-symbol","reason":"Resolve the libfuse3 mount API in the loaded library","creation":{"policy":"none","basis":"resolves a libfuse3 entry point in the handle dlopen just returned; creates no pathname"}}"###
    )]
    let address = unsafe { libc::dlsym(handle, name.as_ptr()) };
    NonNull::new(address)
}

fn load(candidates: &[&'static CStr]) -> Result<Api, String> {
    let mut failures = Vec::new();
    'candidate: for &soname in candidates {
        // SAFETY: the name is terminated; successful handles stay open for the
        // process lifetime so every published function pointer remains valid.
        let handle = unsafe { libc::dlopen(soname.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        if handle.is_null() {
            // SAFETY: dlerror returns a thread-local terminated diagnostic or NULL.
            let error = unsafe {
                let error = libc::dlerror();
                if error.is_null() {
                    "unknown loader error".into()
                } else {
                    CStr::from_ptr(error).to_string_lossy().into_owned()
                }
            };
            failures.push(format!("{}: {error}", soname.to_string_lossy()));
            continue;
        }
        let mut symbols = Vec::with_capacity(6);
        for name in [
            c"fuse_session_new",
            c"fuse_session_mount",
            c"fuse_session_fd",
            c"fuse_session_unmount",
            c"fuse_session_destroy",
            c"fuse_opt_free_args",
        ] {
            let Some(address) = symbol(handle, name) else {
                failures.push(format!(
                    "{}: missing {}",
                    soname.to_string_lossy(),
                    name.to_string_lossy()
                ));
                // SAFETY: no API from this failed candidate escapes.
                unsafe { libc::dlclose(handle) };
                continue 'candidate;
            };
            symbols.push(address);
        }
        // SAFETY: these are the six default FUSE_3.0 entry points, in the order
        // above, with their libfuse C signatures. The handle is never closed.
        return Ok(unsafe {
            Api {
                soname,
                new: std::mem::transmute::<*mut c_void, SessionNew>(symbols[0].as_ptr()),
                mount: std::mem::transmute::<*mut c_void, SessionMount>(symbols[1].as_ptr()),
                fd: std::mem::transmute::<*mut c_void, SessionFd>(symbols[2].as_ptr()),
                unmount: std::mem::transmute::<*mut c_void, SessionUnmount>(symbols[3].as_ptr()),
                destroy: std::mem::transmute::<*mut c_void, SessionDestroy>(symbols[4].as_ptr()),
                free_args: std::mem::transmute::<*mut c_void, FreeArgs>(symbols[5].as_ptr()),
            }
        });
    }
    Err(format!(
        "cannot load libfuse3 (tried {}); install the distribution's fuse3 package",
        failures.join("; ")
    ))
}

fn option_string(option: &MountOption) -> String {
    match option {
        MountOption::FSName(name) => format!("fsname={name}"),
        MountOption::Subtype(subtype) => format!("subtype={subtype}"),
        MountOption::CUSTOM(value) => value.to_string(),
        MountOption::AutoUnmount => "auto_unmount".to_string(),
        MountOption::DefaultPermissions => "default_permissions".to_string(),
        MountOption::Dev => "dev".to_string(),
        MountOption::NoDev => "nodev".to_string(),
        MountOption::Suid => "suid".to_string(),
        MountOption::NoSuid => "nosuid".to_string(),
        MountOption::RO => "ro".to_string(),
        MountOption::RW => "rw".to_string(),
        MountOption::Exec => "exec".to_string(),
        MountOption::NoExec => "noexec".to_string(),
        MountOption::Atime => "atime".to_string(),
        MountOption::NoAtime => "noatime".to_string(),
        MountOption::DirSync => "dirsync".to_string(),
        MountOption::Sync => "sync".to_string(),
        MountOption::Async => "async".to_string(),
    }
}

fn mount_args(options: &[MountOption], acl: SessionACL) -> Vec<CString> {
    let mut args = vec![CString::new("rust-fuse").unwrap()];
    for option in options {
        args.push(CString::new("-o").unwrap());
        args.push(CString::new(option_string(option)).unwrap());
    }
    if acl != SessionACL::Owner {
        args.push(CString::new("-o").unwrap());
        args.push(CString::new("allow_other").unwrap());
    }
    args
}

// fuser 0.18's fuse_lowlevel_ops has 45 optional function pointers. All are
// NULL: only libfuse's mount helper is used, never its request dispatcher.
const LOWLEVEL_OPS: [usize; 45] = [0; 45];

pub(crate) struct Mount {
    api: &'static Api,
    session: NonNull<c_void>,
    mountpoint: CString,
}

// SAFETY: like fuser's libfuse MountImpl, the session has one owner and is
// accessed only for teardown after the Rust request loop releases its fd.
unsafe impl Send for Mount {}

fn last_os_error() -> io::Error {
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(0) {
        io::Error::other("Unspecified Error")
    } else {
        error
    }
}

pub(crate) fn mount(mountpoint: &Path, config: &Config) -> io::Result<(OwnedFd, Mount)> {
    // Session::from_fd skips the validation that Session::new used to perform.
    if config.acl == SessionACL::Owner && config.mount_options.contains(&MountOption::AutoUnmount) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("auto_unmount requires acl != Owner, got: {:?}", config.acl),
        ));
    }
    for (index, option) in config.mount_options.iter().enumerate() {
        for other in &config.mount_options[index + 1..] {
            if super::mount_options_conflict(option, other) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Conflicting mount options found: {option:?}, {other:?}"),
                ));
            }
        }
    }
    let api = api()?;
    let mountpoint = CString::new(mountpoint.as_os_str().as_bytes())?;
    let owned = mount_args(&config.mount_options, config.acl);
    let mut ptrs: Vec<*mut c_char> = owned
        .iter()
        .map(|s| s.as_ptr().cast_mut())
        .chain(std::iter::once(ptr::null_mut()))
        .collect();
    let mut args = FuseArgs {
        argc: owned.len() as c_int,
        argv: ptrs.as_mut_ptr(),
        allocated: 0,
    };
    // SAFETY: the vectors outlive this call. libfuse can replace argv and args,
    // but does not write Rust-owned string bytes. argc excludes the NULL sentinel.
    let session = unsafe {
        (api.new)(
            &mut args,
            LOWLEVEL_OPS.as_ptr().cast(),
            size_of::<[usize; 45]>(),
            ptr::null_mut(),
        )
    };
    let error = session.is_null().then(last_os_error);
    // SAFETY: this frees only libfuse's replacement argv (allocated != 0),
    // including on failure, and leaves our original vectors alone.
    unsafe { (api.free_args)(&mut args) };
    if let Some(error) = error {
        return Err(error);
    }
    let session = NonNull::new(session).unwrap();
    // SAFETY: session is live; mountpoint is a terminated pathname.
    if unsafe { (api.mount)(session.as_ptr(), mountpoint.as_ptr()) } != 0 {
        let error = last_os_error();
        // SAFETY: mounting failed, so there is no established mount to unmount.
        unsafe { (api.destroy)(session.as_ptr()) };
        return Err(error);
    }
    // Arm before fd lookup/duplication: either failure must unmount too.
    let guard = Mount {
        api,
        session,
        mountpoint,
    };
    // SAFETY: libfuse owns the established session and its /dev/fuse descriptor.
    let fd = unsafe { (api.fd)(session.as_ptr()) };
    if fd < 0 {
        return Err(io::Error::other(
            "libfuse3 fuse_session_fd returned a negative descriptor",
        ));
    }
    // SAFETY: the guard keeps libfuse's original descriptor alive for this dup.
    let fd = unsafe { BorrowedFd::borrow_raw(fd) };
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-LIBFUSE3-SESSION-FD","item":"ratarmount_fuse::libfuse3::mount","disposition":"out-of-family","category":"descriptor-handoff","reason":"Hand an independently owned FUSE descriptor to fuser","creation":{"policy":"none","basis":"duplicates the /dev/fuse descriptor libfuse just opened for the mount; the duplicate is handed to fuser"}}"###
    )]
    let fd = fd.try_clone_to_owned()?;
    info!("libfuse: mounted through {}", api.soname.to_string_lossy());
    Ok((fd, guard))
}

impl Drop for Mount {
    fn drop(&mut self) {
        // Match fuser 0.18's libfuse3 teardown. A successful umount leaves the
        // session alive; on EPERM libfuse uses the privileged fusermount helper.
        // SAFETY: this guard owns the mounted session and terminated pathname.
        if unsafe { libc::umount(self.mountpoint.as_ptr()) } != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EPERM) {
                // SAFETY: the Rust session/fd has already dropped.
                unsafe {
                    (self.api.unmount)(self.session.as_ptr());
                    (self.api.destroy)(self.session.as_ptr());
                }
            } else {
                // This may happen if a user already called umount.
                warn!("Unmount failed: {error}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: portable mounting must prefer the new SONAME over the old one.
    #[test]
    fn libfuse3_soname_order() {
        assert_eq!(SONAMES, [c"libfuse3.so.4", c"libfuse3.so.3"]);
    }

    /// Regression: a missing library reports every candidate in attempted order.
    #[test]
    fn libfuse3_missing_candidates() {
        let error = load(&[c"libfuse3-missing-a.so", c"libfuse3-missing-b.so"]).unwrap_err();
        assert!(error.starts_with("cannot load libfuse3 (tried libfuse3-missing-a.so:"));
        assert!(
            error.find("libfuse3-missing-a.so:").unwrap()
                < error.find("libfuse3-missing-b.so:").unwrap()
        );
        assert!(error.ends_with("install the distribution's fuse3 package"));
    }

    /// Regression: an opened DSO without the FUSE API must fall through, not publish it.
    #[test]
    fn libfuse3_missing_symbol() {
        let error = load(&[c"libc.so.6"]).unwrap_err();
        assert!(
            error.contains("libc.so.6: missing fuse_session_new"),
            "{error}"
        );
        if let Some(host) = host_api() {
            let fallback = load(&[c"libc.so.6", host.soname]).unwrap();
            assert_eq!(fallback.soname, host.soname);
        }
    }

    fn host_api() -> Option<Api> {
        let mut opened = None;
        for &soname in &SONAMES {
            // SAFETY: probe only whether dlopen itself succeeds, not symbols.
            let handle =
                unsafe { libc::dlopen(soname.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
            if !handle.is_null() {
                opened = Some(soname);
                unsafe { libc::dlclose(handle) };
                break;
            }
        }
        let Some(soname) = opened else {
            eprintln!("skip: neither host libfuse3 SONAME can be opened");
            return None;
        };
        let api = load(&SONAMES).expect("an installed libfuse3 must export the complete mount API");
        assert_eq!(api.soname, soname);
        Some(api)
    }

    /// Regression: an installed host library missing a required symbol is a failure.
    #[test]
    fn libfuse3_host_symbols() {
        if let Some(api) = host_api() {
            eprintln!("host libfuse3: {}", api.soname.to_string_lossy());
        }
    }

    /// Regression: libfuse may replace argv; freeing its copy must not free Rust storage.
    #[test]
    fn libfuse3_argument_ownership() {
        let Some(api) = host_api() else { return };
        let owned = mount_args(
            &[MountOption::FSName("regression".into()), MountOption::RO],
            SessionACL::Owner,
        );
        let original = owned.clone();
        let mut ptrs: Vec<*mut c_char> = owned
            .iter()
            .map(|s| s.as_ptr().cast_mut())
            .chain(std::iter::once(ptr::null_mut()))
            .collect();
        let original_ptrs = ptrs.clone();
        let mut args = FuseArgs {
            argc: owned.len() as c_int,
            argv: ptrs.as_mut_ptr(),
            allocated: 0,
        };
        assert!(ptrs[args.argc as usize].is_null());
        let session = unsafe {
            (api.new)(
                &mut args,
                LOWLEVEL_OPS.as_ptr().cast(),
                size_of::<[usize; 45]>(),
                ptr::null_mut(),
            )
        };
        let allocated = args.allocated;
        let replacement = args.argv;
        unsafe {
            (api.free_args)(&mut args);
            if !session.is_null() {
                (api.destroy)(session);
            }
        }
        assert!(!session.is_null(), "fuse_session_new failed");
        assert_ne!(
            allocated, 0,
            "options must exercise libfuse's allocated argv"
        );
        assert_ne!(replacement, ptrs.as_mut_ptr());
        assert_eq!(args.argc, 0);
        assert!(args.argv.is_null());
        assert_eq!(args.allocated, 0);
        assert_eq!(owned, original);
        assert_eq!(ptrs, original_ptrs);
    }

    /// Regression: the runtime mount helper must pass fuser's exact argument vectors.
    #[test]
    fn libfuse3_mount_args() {
        use MountOption::*;
        let options = [
            FSName("archive".into()),
            Subtype("ratarmount".into()),
            CUSTOM("foo".into()),
            AutoUnmount,
            RO,
        ];
        for acl in [SessionACL::Owner, SessionACL::All, SessionACL::RootAndOwner] {
            let args = mount_args(&options, acl);
            let mut expected = vec![
                "rust-fuse",
                "-o",
                "fsname=archive",
                "-o",
                "subtype=ratarmount",
                "-o",
                "foo",
                "-o",
                "auto_unmount",
                "-o",
                "ro",
            ];
            if acl != SessionACL::Owner {
                expected.extend(["-o", "allow_other"]);
            }
            assert_eq!(
                args.iter().map(|s| s.to_str().unwrap()).collect::<Vec<_>>(),
                expected
            );
        }
        assert_eq!(
            mount_args(&[], SessionACL::Owner),
            [CString::new("rust-fuse").unwrap()]
        );
    }

    /// Regression: every fuser MountOption retains its libfuse spelling.
    #[test]
    fn libfuse3_option_strings() {
        use MountOption::*;
        for (option, expected) in [
            (FSName("name".into()), "fsname=name"),
            (Subtype("sub".into()), "subtype=sub"),
            (CUSTOM("custom=value".into()), "custom=value"),
            (AutoUnmount, "auto_unmount"),
            (DefaultPermissions, "default_permissions"),
            (Dev, "dev"),
            (NoDev, "nodev"),
            (Suid, "suid"),
            (NoSuid, "nosuid"),
            (RO, "ro"),
            (RW, "rw"),
            (Exec, "exec"),
            (NoExec, "noexec"),
            (Atime, "atime"),
            (NoAtime, "noatime"),
            (DirSync, "dirsync"),
            (Sync, "sync"),
            (Async, "async"),
        ] {
            assert_eq!(option_string(&option), expected);
        }
    }

    /// Regression: from_fd must not bypass Session::new's option refusals.
    #[test]
    fn libfuse3_refuses_invalid_options_before_loading() {
        let mut config = Config::default();
        config.mount_options = vec![MountOption::AutoUnmount];
        let error = mount(Path::new("unused"), &config).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error
            .to_string()
            .contains("auto_unmount requires acl != Owner"));
        for pair in [
            [MountOption::RO, MountOption::RW],
            [MountOption::Dev, MountOption::NoDev],
            [MountOption::Suid, MountOption::NoSuid],
            [MountOption::Exec, MountOption::NoExec],
            [MountOption::Atime, MountOption::NoAtime],
            [MountOption::Sync, MountOption::Async],
        ] {
            config.mount_options = pair.into();
            let error = mount(Path::new("unused"), &config).err().unwrap();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert!(error
                .to_string()
                .contains("Conflicting mount options found"));
        }
    }
}
