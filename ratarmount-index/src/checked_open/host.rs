//! Which loaded image owns an address (design §4, "Runtime image checks").
//!
//! The private-instance path may install only when the constructor, the
//! caller's module anchor and the SQLite entry points (and, inside the
//! installation, the selected VFS's methods) all live in one image that is not
//! the main executable. An interposed or separately linked SQLite resolves to
//! another image and is refused.

use std::fmt;

use super::elf::{ElfError, SymbolName};

/// One loaded image, as the loader reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageIdentity {
    /// Linux: the image's program-header address; macOS: its Mach-O header.
    pub id: usize,
    /// The main executable (PIE or not).
    pub main: bool,
}

/// Why the loader check refused the private-instance path. `what` names the
/// address that failed (`"constructor"`, `"module"`, `"sqlite3_vfs_find"`,
/// `"xOpen"`, ...).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostFailure {
    /// No loader information on this platform or process.
    LoaderUnavailable,
    /// No loaded image contains the address.
    UnknownImage { what: &'static str },
    /// More than one image claims the address (or its ranges overflow).
    Ambiguous { what: &'static str },
    /// The address is in the main executable, which cannot be a private instance.
    MainExecutable { what: &'static str },
    /// The address is in a different image than the first anchor.
    ImageMismatch { what: &'static str },
    /// The proof image's own handle resolves `sqlite3_libversion` to itself:
    /// its SQLite is exported, so not private (design §4, "Symbol privacy").
    SqliteExported,
    /// Linux: the proof image's dynamic symbols could not be inspected
    /// completely (partial inspection never accepts).
    ExportInspection(ElfError),
    /// Linux: the proof image exports this `sqlite3*` dynamic symbol (a full
    /// walk of its defined, externally bindable dynamic symbols).
    SqliteExportedNamed(SymbolName),
}

impl fmt::Display for HostFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LoaderUnavailable => write!(f, "no loader information"),
            Self::UnknownImage { what } => write!(f, "{what} is in no loaded image"),
            Self::Ambiguous { what } => write!(f, "{what} is claimed by more than one image"),
            Self::MainExecutable { what } => write!(f, "{what} is in the main executable"),
            Self::ImageMismatch { what } => {
                write!(f, "{what} is in another image than the constructor")
            }
            Self::SqliteExported => write!(f, "the image exports sqlite3_libversion"),
            Self::ExportInspection(e) => {
                write!(f, "the image's dynamic symbols could not be inspected: {e}")
            }
            Self::SqliteExportedNamed(name) => write!(f, "the image exports {name}"),
        }
    }
}

/// Result of looking up one address.
#[allow(dead_code)] // not every platform's loader constructs every variant
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Lookup {
    Found(ImageIdentity),
    Unknown,
    Ambiguous,
    Unavailable,
}

/// The image-catalog check: every anchor resolves to the same non-main image.
/// `lookup` is the loader (or a test catalog).
pub(crate) fn same_private_image(
    lookup: &dyn Fn(usize) -> Lookup,
    anchors: &[(&'static str, usize)],
) -> Result<ImageIdentity, HostFailure> {
    let mut first: Option<ImageIdentity> = None;
    for &(what, addr) in anchors {
        let image = match lookup(addr) {
            Lookup::Found(image) => image,
            Lookup::Unknown => return Err(HostFailure::UnknownImage { what }),
            Lookup::Ambiguous => return Err(HostFailure::Ambiguous { what }),
            Lookup::Unavailable => return Err(HostFailure::LoaderUnavailable),
        };
        if image.main {
            return Err(HostFailure::MainExecutable { what });
        }
        match first {
            None => first = Some(image),
            Some(first) if first.id != image.id => return Err(HostFailure::ImageMismatch { what }),
            Some(_) => {}
        }
    }
    first.ok_or(HostFailure::UnknownImage {
        what: "(no anchor)",
    })
}

#[cfg_attr(
    not(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        target_endian = "little",
        any(all(target_os = "linux", target_env = "gnu"), target_os = "macos")
    )),
    allow(dead_code)
)]
/// Inside the private-instance installation: every `anchor` (the selected
/// VFS's methods) resolves to `image`, the image the proof established. An
/// error names the anchor that failed.
pub(crate) fn same_image_as(
    lookup: &dyn Fn(usize) -> Lookup,
    image: ImageIdentity,
    anchors: &[(&'static str, usize)],
) -> Result<(), HostFailure> {
    for &(what, addr) in anchors {
        match lookup(addr) {
            Lookup::Found(found) if found.main => return Err(HostFailure::MainExecutable { what }),
            Lookup::Found(found) if found.id != image.id => {
                return Err(HostFailure::ImageMismatch { what })
            }
            Lookup::Found(_) => {}
            Lookup::Unknown => return Err(HostFailure::UnknownImage { what }),
            Lookup::Ambiguous => return Err(HostFailure::Ambiguous { what }),
            Lookup::Unavailable => return Err(HostFailure::LoaderUnavailable),
        }
    }
    Ok(())
}

/// The own-handle export probe of design §4 ("Symbol privacy"): `found` is
/// what `dlsym` on the proof image's own handle returned for
/// `sqlite3_libversion`. Refuse only when that symbol is defined in the image
/// itself (a handle also searches the image's dependencies, whose exports are
/// not its own). A conservative rejection check, not an export proof: the
/// final-wheel export audit (`packaging/audit_native_exports.py`) is that.
/// When the probe cannot look (`dladdr` fails, no file name, no
/// `RTLD_NOLOAD` handle) `found` is `None` and the image is accepted. A wheel
/// built locally from the sdist is never audited, so on macOS this one-symbol
/// check is its only runtime evidence. 64-bit Linux glibc walks every export
/// instead (r11 S6, `elf::image_exports_no_sqlite`).
#[cfg_attr(all(target_os = "linux", not(test)), allow(dead_code))]
pub(crate) fn refuse_exported_sqlite(
    lookup: &dyn Fn(usize) -> Lookup,
    image: ImageIdentity,
    found: Option<usize>,
) -> Result<(), HostFailure> {
    match found.map(lookup) {
        Some(Lookup::Found(owner)) if owner.id == image.id => Err(HostFailure::SqliteExported),
        _ => Ok(()),
    }
}

/// `dlsym(name)` through the own handle of the image containing `anchor`
/// (`dladdr`, then `dlopen(RTLD_NOLOAD)`, which loads nothing). `None` when
/// the image has no handle or the name resolves nowhere.
#[cfg(any(all(target_os = "linux", target_env = "gnu"), target_os = "macos"))]
#[cfg_attr(all(target_os = "linux", not(test)), allow(dead_code))]
pub(crate) fn own_handle_symbol(anchor: usize, name: &std::ffi::CStr) -> Option<usize> {
    // SAFETY: `Dl_info` is plain data; `dladdr` fills it or returns 0. The
    // handle from `dlopen(RTLD_NOLOAD)` refers to an already loaded image and
    // is released with `dlclose` after the lookup.
    unsafe {
        let mut info: libc::Dl_info = std::mem::zeroed();
        if libc::dladdr(anchor as *const libc::c_void, &mut info) == 0 || info.dli_fname.is_null() {
            return None;
        }
        let handle = libc::dlopen(info.dli_fname, libc::RTLD_LAZY | libc::RTLD_NOLOAD);
        if handle.is_null() {
            return None;
        }
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-E0056-M01","item":"ratarmount_index::checked_open::host::own_handle_symbol","disposition":"out-of-family","category":"checked-open-host-probe","reason":"Look up the checked-open host-test symbol through the already-loaded image own handle, then release that handle.","creation":{"policy":"none","basis":"dlsym performs the reviewed own_handle_symbol probe, not arbitrary loader use or creation of a pathname resource."}}"###
        )]
        let found = libc::dlsym(handle, name.as_ptr());
        libc::dlclose(handle);
        (!found.is_null()).then_some(found as usize)
    }
}

/// Every other platform: no loader, nothing found.
#[cfg(not(any(all(target_os = "linux", target_env = "gnu"), target_os = "macos")))]
#[allow(dead_code)]
pub(crate) fn own_handle_symbol(_anchor: usize, _name: &std::ffi::CStr) -> Option<usize> {
    None
}

/// Linux: the unique image with a `PT_LOAD` segment containing `addr`; the
/// main executable is the one whose program headers are `getauxval(AT_PHDR)`.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub(crate) fn host_object(addr: usize) -> Lookup {
    struct Search {
        addr: u64,
        main_phdr: usize,
        matches: u32,
        overflow: bool,
        found: ImageIdentity,
    }

    // ELF fields are `u32` on 32-bit targets.
    #[allow(clippy::useless_conversion)]
    unsafe extern "C" fn visit(
        info: *mut libc::dl_phdr_info,
        _size: libc::size_t,
        data: *mut libc::c_void,
    ) -> libc::c_int {
        // SAFETY: `data` is the `Search` passed below; `info` is valid for this
        // call. Nothing here can panic (no indexing, checked arithmetic).
        let search = unsafe { &mut *(data as *mut Search) };
        let info = unsafe { &*info };
        if info.dlpi_phdr.is_null() {
            return 0;
        }
        let phdrs = unsafe { std::slice::from_raw_parts(info.dlpi_phdr, info.dlpi_phnum as usize) };
        let mut hit = false;
        for ph in phdrs {
            if ph.p_type != libc::PT_LOAD {
                continue;
            }
            let start = u64::from(info.dlpi_addr).checked_add(u64::from(ph.p_vaddr));
            let end = start.and_then(|s| s.checked_add(u64::from(ph.p_memsz)));
            match (start, end) {
                (Some(start), Some(end)) => {
                    if start <= search.addr && search.addr < end {
                        hit = true;
                    }
                }
                _ => search.overflow = true,
            }
        }
        if hit {
            search.matches = search.matches.saturating_add(1);
            search.found = ImageIdentity {
                id: info.dlpi_phdr as usize,
                main: info.dlpi_phdr as usize == search.main_phdr,
            };
        }
        0
    }

    // SAFETY: `getauxval` has no preconditions.
    let main_phdr = unsafe { libc::getauxval(libc::AT_PHDR) } as usize;
    if main_phdr == 0 {
        return Lookup::Unavailable;
    }
    let mut search = Search {
        addr: addr as u64,
        main_phdr,
        matches: 0,
        overflow: false,
        found: ImageIdentity { id: 0, main: false },
    };
    // SAFETY: `visit` only reads the loader's records and writes `search`.
    unsafe { libc::dl_iterate_phdr(Some(visit), &mut search as *mut Search as *mut libc::c_void) };
    match (search.matches, search.overflow) {
        (_, true) => Lookup::Ambiguous,
        (0, false) => Lookup::Unknown,
        (1, false) => Lookup::Found(search.found),
        _ => Lookup::Ambiguous,
    }
}

/// macOS: `dladdr`'s image base; the main executable is image 0.
#[cfg(target_os = "macos")]
pub(crate) fn host_object(addr: usize) -> Lookup {
    // SAFETY: `Dl_info` is plain data; `dladdr` fills it or returns 0.
    let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
    if unsafe { libc::dladdr(addr as *const libc::c_void, &mut info) } == 0
        || info.dli_fbase.is_null()
    {
        return Lookup::Unknown;
    }
    // SAFETY: image 0 is the main executable; the call has no preconditions.
    // libc points to the `mach2` crate, which this workspace does not use.
    #[allow(deprecated)]
    let main = unsafe { libc::_dyld_get_image_header(0) };
    if main.is_null() {
        return Lookup::Unavailable;
    }
    Lookup::Found(ImageIdentity {
        id: info.dli_fbase as usize,
        main: std::ptr::eq(info.dli_fbase.cast_const(), main.cast::<libc::c_void>()),
    })
}

/// Every other platform: no loader proof.
#[cfg(not(any(all(target_os = "linux", target_env = "gnu"), target_os = "macos")))]
pub(crate) fn host_object(_addr: usize) -> Lookup {
    Lookup::Unavailable
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIB: ImageIdentity = ImageIdentity {
        id: 0x1000,
        main: false,
    };
    const OTHER: ImageIdentity = ImageIdentity {
        id: 0x2000,
        main: false,
    };
    const EXE: ImageIdentity = ImageIdentity {
        id: 0x3000,
        main: true,
    };

    /// Test catalog: an address's image is encoded in its high bits.
    fn catalog(addr: usize) -> Lookup {
        match addr >> 8 {
            1 => Lookup::Found(LIB),
            2 => Lookup::Found(OTHER),
            3 => Lookup::Found(EXE),
            4 => Lookup::Ambiguous,
            5 => Lookup::Unavailable,
            _ => Lookup::Unknown,
        }
    }

    fn anchors(vfs_find: usize) -> [(&'static str, usize); 5] {
        [
            ("constructor", 0x101),
            ("module", 0x102),
            ("sqlite3_initialize", 0x103),
            ("sqlite3_vfs_find", vfs_find),
            ("sqlite3_open_v2", 0x105),
        ]
    }

    /// Regression: the private-instance path must refuse an executable host and
    /// a SQLite (or one of its entry points) from another image than the
    /// constructor: an interposed or separately linked SQLite resolves to its
    /// own image. Catalog rows plus the real loader (this test binary is a PIE
    /// executable; libc is a real shared object unless linked `crt-static`).
    /// The real shared-object fixture is `test-harness/ratarmount-checked-open-fixture`.
    #[test]
    fn regression_host_rejects_executable_and_foreign_sqlite() {
        assert_eq!(same_private_image(&catalog, &anchors(0x104)), Ok(LIB));
        let rows: [(usize, HostFailure); 5] = [
            (
                0x204,
                HostFailure::ImageMismatch {
                    what: "sqlite3_vfs_find",
                },
            ),
            (
                0x304,
                HostFailure::MainExecutable {
                    what: "sqlite3_vfs_find",
                },
            ),
            (
                0x404,
                HostFailure::Ambiguous {
                    what: "sqlite3_vfs_find",
                },
            ),
            (0x504, HostFailure::LoaderUnavailable),
            (
                0x904,
                HostFailure::UnknownImage {
                    what: "sqlite3_vfs_find",
                },
            ),
        ];
        for (addr, want) in rows {
            assert_eq!(
                same_private_image(&catalog, &anchors(addr)),
                Err(want),
                "{addr:#x}"
            );
        }
        // Inside the installation: each VFS method against the proof's image.
        assert_eq!(same_image_as(&catalog, LIB, &[("xOpen", 0x101)]), Ok(()));
        for (addr, want) in [
            (0x201, HostFailure::ImageMismatch { what: "xOpen" }),
            (0x301, HostFailure::MainExecutable { what: "xOpen" }),
            (0x401, HostFailure::Ambiguous { what: "xOpen" }),
            (0x501, HostFailure::LoaderUnavailable),
            (0, HostFailure::UnknownImage { what: "xOpen" }),
        ] {
            assert_eq!(
                same_image_as(&catalog, LIB, &[("xSetSystemCall", 0x102), ("xOpen", addr)]),
                Err(want),
                "{addr:#x}"
            );
        }
        // An executable constructor refuses before any other anchor is looked at.
        let exe_first = [("constructor", 0x301), ("module", 0x201)];
        assert_eq!(
            same_private_image(&catalog, &exe_first),
            Err(HostFailure::MainExecutable {
                what: "constructor"
            })
        );
        assert_eq!(
            same_private_image(&catalog, &[]),
            Err(HostFailure::UnknownImage {
                what: "(no anchor)"
            })
        );

        #[cfg(any(all(target_os = "linux", target_env = "gnu"), target_os = "macos"))]
        {
            let exe = match host_object(
                regression_host_rejects_executable_and_foreign_sqlite as *const () as usize,
            ) {
                Lookup::Found(image) => image,
                other => panic!("test function not found in the executable: {other:?}"),
            };
            assert!(exe.main, "the test binary is the main executable: {exe:?}");
            let sqlite = host_object(rusqlite::ffi::sqlite3_vfs_find as *const () as usize);
            assert_eq!(
                sqlite,
                Lookup::Found(exe),
                "bundled SQLite is linked into the executable"
            );
            // A static executable (`crt-static`) carries libc itself.
            match host_object(libc::qsort as *const () as usize) {
                Lookup::Found(libc_image) if cfg!(target_feature = "crt-static") => {
                    assert_eq!(libc_image, exe, "static libc is in the executable");
                }
                Lookup::Found(libc_image) => {
                    assert!(!libc_image.main, "libc is a shared object: {libc_image:?}");
                    assert_ne!(libc_image.id, exe.id);
                }
                other => panic!("libc's qsort not found: {other:?}"),
            }
            let local = 0u8;
            assert_eq!(
                host_object(&local as *const u8 as usize),
                Lookup::Unknown,
                "stack"
            );
            // The real private proof of this executable refuses at its first
            // anchor: the constructor, which only verified targets have
            // (r11 S1 skeptic P2: i686/riscv64/ppc64le glibc have none).
            let proof = super::super::install::private_proof(
                regression_host_rejects_executable_and_foreign_sqlite as *const libc::c_void,
            );
            if cfg!(all(
                target_pointer_width = "64",
                any(target_arch = "x86_64", target_arch = "aarch64"),
                target_endian = "little",
                any(
                    all(target_os = "linux", target_env = "gnu"),
                    target_os = "macos"
                )
            )) {
                assert_eq!(
                    proof,
                    Err(HostFailure::MainExecutable {
                        what: "constructor"
                    })
                );
            } else {
                assert_eq!(
                    proof,
                    Err(HostFailure::UnknownImage {
                        what: "constructor"
                    })
                );
            }
        }
    }

    /// Regression: (#151, design §4 "Symbol privacy"): the private-instance
    /// proof must refuse an image whose own handle resolves
    /// `sqlite3_libversion` to itself (its SQLite is exported, so another
    /// library may already call it), and must not refuse because a dependency
    /// of the image exports one. Catalog rows, then the real `dlopen`
    /// (`RTLD_NOLOAD`) / `dlsym` probe on libc, which does export its own
    /// `qsort` and no `sqlite3_libversion`. The fixture DSO test runs the probe
    /// on an image that must pass.
    #[test]
    fn regression_private_proof_refuses_exported_sqlite() {
        assert_eq!(refuse_exported_sqlite(&catalog, LIB, None), Ok(()));
        assert_eq!(
            refuse_exported_sqlite(&catalog, LIB, Some(0x150)),
            Err(HostFailure::SqliteExported)
        );
        for dependency in [0x250, 0x350, 0x450, 0x550, 0x950] {
            assert_eq!(
                refuse_exported_sqlite(&catalog, LIB, Some(dependency)),
                Ok(()),
                "{dependency:#x}"
            );
        }
        assert_eq!(
            HostFailure::SqliteExported.to_string(),
            "the image exports sqlite3_libversion"
        );

        #[cfg(any(all(target_os = "linux", target_env = "gnu"), target_os = "macos"))]
        {
            if cfg!(target_feature = "crt-static") {
                eprintln!("skip: static libc has no own handle");
                return;
            }
            let qsort = libc::qsort as *const () as usize;
            let Lookup::Found(libc_image) = host_object(qsort) else {
                panic!("libc's qsort is in no image");
            };
            let own = own_handle_symbol(qsort, c"qsort");
            assert!(own.is_some(), "libc's own handle resolves qsort");
            assert_eq!(
                refuse_exported_sqlite(&host_object, libc_image, own),
                Err(HostFailure::SqliteExported),
                "an own export is seen through the real loader"
            );
            assert_eq!(
                refuse_exported_sqlite(
                    &host_object,
                    libc_image,
                    own_handle_symbol(qsort, c"sqlite3_libversion")
                ),
                Ok(())
            );
            let local = 0u8;
            assert_eq!(
                own_handle_symbol(&local as *const u8 as usize, c"qsort"),
                None,
                "an address in no image has no handle"
            );
        }
    }
}
