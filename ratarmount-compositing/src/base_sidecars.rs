//! Names ratarmount itself writes next to a base archive.
//!
//! A directory base's digest (weak manifest or strong tree hash) must not move
//! when ratarmount publishes an index, rotates a snapshot, stages a temporary
//! file or journals a commit inside the base. One predicate, shared by both
//! walks, decides which non-directory entries are invisible to the digest.

/// Pinned-snapshot index name `X.index.<64 lowercase hex>.sqlite`.
fn is_index_snapshot(name: &str) -> bool {
    name.find(".index.").is_some_and(|at| {
        name[at + ".index.".len()..]
            .strip_suffix(".sqlite")
            .is_some_and(|id| {
                id.len() == 64 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            })
    })
}

/// `tempfile`'s default staging name: `.tmp` plus six alphanumerics.
fn is_tempfile_name(name: &str) -> bool {
    name.strip_prefix(".tmp")
        .is_some_and(|rest| rest.len() == 6 && rest.bytes().all(|b| b.is_ascii_alphanumeric()))
}

/// `X.index.sqlite` and its SQLite companions, pointers, compressed
/// candidates and writable-build staging names (patterns 1-6 of the plan).
fn is_index_sidecar(name: &str) -> bool {
    if is_index_snapshot(name) || name.ends_with(".index.ptr") {
        return true;
    }
    let Some(at) = name.find(".index.sqlite") else {
        return false;
    };
    let rest = &name[at + ".index.sqlite".len()..];
    if matches!(
        rest,
        "" | "-wal" | "-shm" | "-journal" | ".gz" | ".zst" | ".zstd" | ".xz" | ".bz2"
    ) {
        return true;
    }
    // `<dest>.tmp.<pid>.<seq>` staging plus that file's own SQLite companions.
    rest.strip_prefix(".tmp.").is_some_and(|tail| {
        let tail = ["-wal", "-shm", "-journal"]
            .iter()
            .find_map(|s| tail.strip_suffix(s))
            .unwrap_or(tail);
        let mut parts = tail.split('.');
        let ok = |p: Option<&str>| {
            p.is_some_and(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
        };
        ok(parts.next()) && ok(parts.next()) && parts.next().is_none()
    })
}

/// True when `name` (a non-directory entry) was written by ratarmount beside
/// an archive and so is not part of the base's identity. `sibling_exists`
/// answers from the directory listing the caller already read: the
/// generic-extension sidecars (`.rgzi`, `.gzidx`, `.manifest.jsonl`) count
/// only next to the archive they describe.
pub fn is_ratarmount_sidecar_name(name: &str, sibling_exists: &dyn Fn(&str) -> bool) -> bool {
    if is_index_sidecar(name)
        || name.ends_with(ratarmount_compress::commit_journal::COMMIT_JOURNAL_SUFFIX)
        || is_tempfile_name(name)
    {
        return true;
    }
    if (name.starts_with(".ratarmount-index-ptr-") || name.starts_with(".ratarmount-index-snap-"))
        && name.ends_with(".tmp")
    {
        return true;
    }
    if name.starts_with("ratarmount-index-") && name.ends_with(".tmp.sqlite.index") {
        return true;
    }
    for suffix in [".rgzi", ".gzidx", ".manifest.jsonl"] {
        if let Some(stem) = name.strip_suffix(suffix) {
            if !stem.is_empty() && sibling_exists(stem) {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is(name: &str, siblings: &[&str]) -> bool {
        is_ratarmount_sidecar_name(name, &|s| siblings.contains(&s))
    }

    /// Every writer output the plan inventories is invisible; look-alikes are not.
    #[test]
    fn regression_sidecar_predicate_table() {
        let id = "ab".repeat(32);
        for name in [
            "a.tar.index.sqlite",
            "a.tar.index.sqlite-wal",
            "a.tar.index.sqlite-shm",
            "a.tar.index.sqlite-journal",
            "a.tar.index.ptr",
            &format!("a.tar.index.{id}.sqlite"),
            "a.tar.index.sqlite.gz",
            "a.tar.index.sqlite.zst",
            "a.tar.index.sqlite.zstd",
            "a.tar.index.sqlite.xz",
            "a.tar.index.sqlite.bz2",
            "a.tar.index.sqlite.tmp.123.4",
            "a.tar.index.sqlite.tmp.123.4-wal",
            ".ratarmount-index-ptr-x.tmp",
            ".ratarmount-index-snap-x.tmp",
            "ratarmount-index-x.tmp.sqlite.index",
            ".tmpAb12Cd",
            "a.tar.ratarmount-commit-journal",
        ] {
            assert!(is(name, &[]), "{name} should be a sidecar");
        }
        for name in ["a.gz.rgzi", "a.gz.gzidx", "a.tar.manifest.jsonl"] {
            let stem = name.rsplit_once('.').map(|(s, _)| s).unwrap();
            let stem = stem.strip_suffix(".manifest").unwrap_or(stem);
            assert!(is(name, &[stem]), "{name} next to {stem}");
            assert!(!is(name, &[]), "{name} without its archive is content");
        }
        for name in [
            ".tmpAb12C",
            ".tmpAb12Cde",
            "x.index.txt",
            "notes.txt",
            "a.tar.index.sqlite.tmp.x.y",
            "a.tar.index.sqlite.tmp.1",
            "a.tar.index.ABAB.sqlite",
        ] {
            assert!(!is(name, &[]), "{name} is base content");
        }
    }
}
