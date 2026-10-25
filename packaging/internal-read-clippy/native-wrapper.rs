//! Portable launcher for the native Cargo compiler wrapper (including MSVC).
use std::process::{Command, exit};

fn main() {
    let status = Command::new(std::env::var_os("INTERNAL_READ_NATIVE_PYTHON").unwrap())
        .arg(std::env::var_os("INTERNAL_READ_NATIVE_SCRIPT").unwrap())
        .arg("--wrap")
        .args(std::env::args_os().skip(1))
        .status()
        .expect("run native compiler wrapper");
    exit(status.code().unwrap_or(1));
}
