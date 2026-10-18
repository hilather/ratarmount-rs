use std::fs::File;
use std::io::Write;
use std::os::fd::FromRawFd;

use ratarmount_compositing::WriteOverlay;
use ratarmount_core::MountSource;

/// Modify an existing base/lower file via FUSE's truncating copy-up open path.
pub fn cow_write(overlay: &WriteOverlay, path: &str, bytes: &[u8]) {
    assert!(
        overlay.lookup(path, 0).is_some(),
        "COW needs an existing {path}"
    );
    let fd = overlay
        .open_overlay_fd(path, libc::O_WRONLY | libc::O_TRUNC)
        .unwrap();
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(bytes).unwrap();
    overlay.finish_owned_write_fd(file);
}
