fn main() {
    let has_rar5 = if let Ok(lib) = pkg_config::Config::new().probe("libarchive") {
        for path in lib.include_paths {
            println!("cargo:include={}", path.display());
        }
        // RAR5 support landed in libarchive 3.4.0 (not present on Rocky 8 / older EL).
        version_at_least(&lib.version, 3, 4, 0)
    } else {
        // Fallback: common linker flag; assume modern host when pkg-config missing.
        println!("cargo:rustc-link-lib=archive");
        true
    };
    if has_rar5 {
        println!("cargo:rustc-cfg=libarchive_has_rar5");
    }
    // Silence unexpected_cfgs lint for our custom cfg on newer rustc.
    println!("cargo:rustc-check-cfg=cfg(libarchive_has_rar5)");
    println!("cargo:rerun-if-changed=build.rs");
}

fn version_at_least(version: &str, major: u32, minor: u32, patch: u32) -> bool {
    let mut parts = version
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse::<u32>().ok());
    let maj = parts.next().unwrap_or(0);
    let min = parts.next().unwrap_or(0);
    let pat = parts.next().unwrap_or(0);
    (maj, min, pat) >= (major, minor, patch)
}
