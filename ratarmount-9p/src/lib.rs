//! 9P2000.L export of a `MountSource` (P-7). Stub until the 9P export PR.

/// Marker so `cargo test -p ratarmount-9p` has a compiling lib.
pub fn crate_is_stub() {}

#[cfg(test)]
mod tests {
    #[test]
    fn stub_compiles() {
        super::crate_is_stub();
    }
}
