//! SMB/CIFS export of a `MountSource` (P-2). Stub until the SMB export PR.

/// Marker so `cargo test -p ratarmount-smb` has a compiling lib.
pub fn crate_is_stub() {}

#[cfg(test)]
mod tests {
    #[test]
    fn stub_compiles() {
        super::crate_is_stub();
    }
}
