// Regression: native Windows Clippy must diagnose this Windows-only read.
#[cfg(windows)]
pub fn unreviewed_windows_read() {
    let _ = std::fs::read("fixture");
}
