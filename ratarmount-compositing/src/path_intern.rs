//! Crate-local intern table for union folder-cache and AutoMount mount-point keys.
//!
//! Maps store `u32` ids; each distinct path string is retained once. Public
//! MountSource APIs still take `&str` and intern on the way in.

use std::collections::HashMap;
use std::sync::Arc;

/// Interned path keys (`get(id) -> &str`, `intern(&str) -> u32`).
#[derive(Debug, Default)]
pub struct PathIntern {
    strings: Vec<Arc<str>>,
    by_str: HashMap<Arc<str>, u32>,
}

impl PathIntern {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert `s` if missing and return its id.
    pub fn intern(&mut self, s: &str) -> u32 {
        if let Some(&id) = self.by_str.get(s) {
            return id;
        }
        let id = u32::try_from(self.strings.len()).expect("path intern id overflow");
        let arc: Arc<str> = Arc::from(s);
        self.strings.push(Arc::clone(&arc));
        self.by_str.insert(arc, id);
        id
    }

    pub fn get(&self, id: u32) -> &str {
        self.strings
            .get(id as usize)
            .map(|a| a.as_ref())
            .unwrap_or("")
    }

    /// Existing id only; does not insert.
    pub fn lookup(&self, s: &str) -> Option<u32> {
        self.by_str.get(s).copied()
    }

    pub fn clear(&mut self) {
        self.strings.clear();
        self.by_str.clear();
    }
}

/// `path` is `mp` or a descendant of `mp` as a directory prefix.
///
/// Equivalent to `path == mp || path.starts_with(&(mp.to_owned() + "/"))` without
/// allocating the `mp + "/"` prefix on every comparison.
#[inline]
pub(crate) fn path_is_self_or_descendant(path: &str, mp: &str) -> bool {
    path == mp || (path.starts_with(mp) && path.as_bytes().get(mp.len()) == Some(&b'/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intern_reuses_id_for_same_path() {
        let mut p = PathIntern::new();
        let a = p.intern("/a/b/c/d/e");
        let b = p.intern("/a/b/c/d/e");
        assert_eq!(a, b);
        assert_eq!(p.get(a), "/a/b/c/d/e");
        assert_eq!(p.lookup("/a/b/c/d/e"), Some(a));
        assert_eq!(p.lookup("/missing"), None);
        let c = p.intern("/a/b/c/d/f");
        assert_ne!(a, c);
        assert_eq!(p.get(c), "/a/b/c/d/f");
    }

    #[test]
    fn path_is_self_or_descendant_does_not_allocate_prefix() {
        assert!(path_is_self_or_descendant("/foo", "/foo"));
        assert!(path_is_self_or_descendant("/foo/bar", "/foo"));
        assert!(path_is_self_or_descendant("/foo.tar/inner", "/foo.tar"));
        assert!(!path_is_self_or_descendant("/foobar", "/foo"));
        assert!(!path_is_self_or_descendant("/foo.tar", "/foo"));
        assert!(!path_is_self_or_descendant("/foo", "/foo/bar"));
    }
}
