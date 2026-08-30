//! Bounded member reader for [`crate::ReadRequest`].

/// Seek + capped `Read`. Never holds the member as `Vec<u8>`.
///
/// There is no `read_all`.
pub struct RangeReader {
    #[allow(dead_code)]
    _private: (),
}
