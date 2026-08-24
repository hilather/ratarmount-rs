//! SFTP export of a `MountSource` (P-10). Stub until the SFTP export PR.

/// Marker so `cargo test -p ratarmount-sftp` has a compiling lib.
pub fn crate_is_stub() {}

#[cfg(test)]
mod tests {
    #[test]
    fn stub_compiles() {
        super::crate_is_stub();
    }
}
