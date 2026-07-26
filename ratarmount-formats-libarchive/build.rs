fn main() {
    if let Ok(lib) = pkg_config::Config::new().probe("libarchive") {
        for path in lib.include_paths {
            println!("cargo:include={}", path.display());
        }
    } else {
        // Fallback: common linker flag
        println!("cargo:rustc-link-lib=archive");
    }
    println!("cargo:rerun-if-changed=build.rs");
}
