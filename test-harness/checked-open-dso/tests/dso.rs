//! Loads the fixture shared object (see `src/lib.rs`) and drives the real
//! private-instance installation of #151.

#![cfg(unix)]

use std::ffi::CString;
use std::path::PathBuf;

const LIB: &str = "ratarmount_checked_open_fixture";

/// The cdylib cargo built for this package: beside the test executable in
/// `deps/`, or uplifted one directory up.
fn fixture_path() -> Option<PathBuf> {
    let name = format!(
        "{}{LIB}{}",
        std::env::consts::DLL_PREFIX,
        std::env::consts::DLL_SUFFIX
    );
    let exe = std::env::current_exe().ok()?;
    let deps = exe.parent()?;
    [deps.join(&name), deps.parent()?.join(&name)]
        .into_iter()
        .find(|p| p.is_file())
}

type Text = unsafe extern "C" fn(*mut u8, usize) -> usize;

fn text(f: impl FnOnce(*mut u8, usize) -> usize) -> String {
    let mut buf = vec![0u8; 512];
    let n = f(buf.as_mut_ptr(), buf.len());
    assert!(n < buf.len(), "fixture text truncated");
    buf.truncate(n);
    String::from_utf8(buf).unwrap()
}

/// Regression (r11 S1 skeptic P2): no test reached the production
/// private-instance installation (`install_real` with the proof's image and
/// its VFS-method check). A shared object that links ratarmount-index and its
/// SQLite is loaded into a process that already has several threads: its
/// constructor must abstain; a module anchor in the executable or in libc
/// must be refused without poisoning; the real private initializer must then install
/// (`PrivateInstance`), change SQLite's `"open"` slot, keep databases
/// working and return the same terminal result on a second call.
#[test]
fn regression_dso_private_instance_installs_after_abstention() {
    let Some(path) = fixture_path() else {
        panic!(
            "the fixture shared object was not built beside {:?}",
            std::env::current_exe()
        );
    };
    // A second thread before the load: the constructor must see more than one.
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let parked = std::thread::spawn(move || {
        let _ = rx.recv();
    });

    let c_path = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: loading our own fixture; its constructor is the code under test.
    let handle = unsafe { libc::dlopen(c_path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!handle.is_null(), "dlopen {path:?} failed");
    let sym = |name: &std::ffi::CStr| {
        let p = unsafe { libc::dlsym(handle, name.as_ptr()) };
        assert!(!p.is_null(), "missing {name:?}");
        p
    };
    let install_at: unsafe extern "C" fn(usize, *mut u8, usize) -> usize =
        unsafe { std::mem::transmute(sym(c"fixture_install")) };
    let install = |anchor: usize| text(|b, n| unsafe { install_at(anchor, b, n) });
    let status_fn: Text = unsafe { std::mem::transmute(sym(c"fixture_status")) };
    let status = || text(|b, n| unsafe { status_fn(b, n) });
    let open_slot: extern "C" fn() -> usize =
        unsafe { std::mem::transmute(sym(c"fixture_open_slot")) };
    let roundtrip: unsafe extern "C" fn(*const libc::c_char) -> libc::c_int =
        unsafe { std::mem::transmute(sym(c"fixture_db_roundtrip")) };
    // This executable does not link SQLite: the fixture's is private. (macOS
    // may have the system libsqlite3 loaded, so Linux only.)
    #[cfg(target_os = "linux")]
    assert!(unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"sqlite3_vfs_find".as_ptr()) }.is_null());

    let before = status();
    assert!(
        before.starts_with("(Some(AbstainedThreads(Some(")
            && before.contains("Err(AbstainedThreads(Some("),
        "constructor did not abstain: {before}"
    );
    let slot_before = open_slot();
    assert_ne!(slot_before, 0);

    // Refused proofs: nothing installed, nothing poisoned.
    let exe_anchor = fixture_path as *const () as usize;
    assert_eq!(
        install(exe_anchor),
        "Err(NotPrivate(MainExecutable { what: \"module\" }))"
    );
    let image = |addr: usize| unsafe {
        let mut info: libc::Dl_info = std::mem::zeroed();
        (libc::dladdr(addr as *const libc::c_void, &mut info) != 0)
            .then_some(info.dli_fbase as usize)
    };
    let libc_is_shared = matches!(
        (image(libc::qsort as *const () as usize), image(exe_anchor)),
        (Some(l), Some(e)) if l != e
    );
    if libc_is_shared {
        assert_eq!(
            install(libc::qsort as *const () as usize),
            "Err(NotPrivate(ImageMismatch { what: \"module\" }))"
        );
    } else {
        eprintln!("skip: libc linked statically; foreign-DSO anchor row");
    }
    assert_eq!(status(), before, "a refused proof stores nothing");
    assert_eq!(open_slot(), slot_before);

    let first = install(0);
    assert!(
        first.starts_with("Ok(Witness { why: PrivateInstance, threads_at_install: Some("),
        "private install: {first}"
    );
    let slot_after = open_slot();
    assert_ne!(slot_after, slot_before, "the open slot holds the wrapper");
    assert_eq!(install(0), first, "terminal result");
    assert_eq!(install(exe_anchor), first, "terminal result, any anchor");
    assert_eq!(open_slot(), slot_after);
    let after = status();
    assert!(after.contains(&first), "{after}");

    let dir = std::env::temp_dir().join(format!("ratarmount-dso-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = CString::new(dir.join("t.sqlite").into_os_string().into_encoded_bytes()).unwrap();
    assert_eq!(
        unsafe { roundtrip(db.as_ptr()) },
        0,
        "database work through the wrappers"
    );
    let _ = std::fs::remove_dir_all(&dir);

    drop(tx);
    parked.join().unwrap();
}
