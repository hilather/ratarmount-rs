//! HTTP Range export of a `MountSource` (P-5). Stub until the HTTP export PR.

/// Marker so `cargo test -p ratarmount-http` has a compiling lib.
pub fn crate_is_stub() {}

#[cfg(test)]
mod tests {
    #[test]
    fn stub_compiles() {
        super::crate_is_stub();
    }
}
