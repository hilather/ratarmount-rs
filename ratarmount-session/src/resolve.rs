//! `resolve_index` façade.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use ratarmount_index::{
    materialize_index_file, resolve_index_location, resolve_sibling_index_location, IndexLocation,
};

use crate::types::IndexPolicy;
use crate::Error;

pub(crate) static TEMP_INDEX_SEQ: AtomicU32 = AtomicU32::new(1);

pub(crate) fn temp_index_path() -> PathBuf {
    let seq = TEMP_INDEX_SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir()
        .join(format!("ratarmount-session-{}", std::process::id()))
        .join(format!("index-{seq}.sqlite"))
}

/// Resolve where the 0.7.x sidecar should live.
///
/// [`IndexPolicy::Sibling`] + no usable file + unwritable parent →
/// [`Error::SiblingNotWritable`]. Never `:memory:` except [`IndexPolicy::Memory`]
/// and [`IndexPolicy::CliCompat`] last resort (Python parity).
///
/// [`IndexPolicy::UserCache`] (`local-index-v1`) is not implemented here; it
/// errors rather than writing `meta-v3`.
pub fn resolve_index(
    archive: &Path,
    policy: IndexPolicy,
    explicit_index: Option<&Path>,
    extra_dirs: &[PathBuf],
    recreate: bool,
) -> Result<IndexLocation, Error> {
    match policy {
        IndexPolicy::Memory => Ok(IndexLocation::Memory),
        IndexPolicy::Explicit => {
            let p =
                explicit_index.ok_or_else(|| Error::Internal("explicit_index required".into()))?;
            match materialize_index_file(p) {
                Ok(mp) => Ok(IndexLocation::Path(mp)),
                Err(err) => {
                    log::warn!("could not materialize index {}: {err}", p.display());
                    Ok(IndexLocation::Path(p.to_path_buf()))
                }
            }
        }
        IndexPolicy::Temp => {
            let p = temp_index_path();
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).map_err(|e| Error::Internal(e.to_string()))?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ =
                        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
                }
            }
            Ok(IndexLocation::Path(p))
        }
        IndexPolicy::Sibling => resolve_sibling_index_location(archive, extra_dirs, recreate)
            .map_err(Error::SiblingNotWritable),
        IndexPolicy::UserCache => Err(Error::Internal(
            "IndexPolicy::UserCache (local-index-v1) is not implemented; not meta-v3".into(),
        )),
        IndexPolicy::CliCompat => {
            let explicit = explicit_index.map(|p| p.to_string_lossy().into_owned());
            Ok(resolve_index_location(
                archive,
                explicit.as_deref(),
                extra_dirs,
                recreate,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{OpenRequest, Recreate, SourceSpec};
    use crate::Session;
    use ratarmount_formats_tar::{write_tar_eof, write_ustar_members, UstarMember, UstarPayload};
    use ratarmount_index::default_index_path;
    use std::io::Write;

    fn member_file<'a>(path: &'a str, bytes: &'a [u8]) -> UstarMember<'a> {
        UstarMember {
            path,
            payload: UstarPayload::File { bytes },
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime: 0,
        }
    }

    fn write_tar(path: &Path, members: &[UstarMember<'_>]) {
        let mut f = std::fs::File::create(path).unwrap();
        write_ustar_members(&mut f, members).unwrap();
        write_tar_eof(&mut f).unwrap();
        f.flush().unwrap();
    }

    fn sibling_req_recreate(tar: PathBuf, recreate: Recreate) -> OpenRequest {
        OpenRequest {
            source: SourceSpec::Path(tar),
            index: IndexPolicy::Sibling,
            explicit_index: None,
            extra_dirs: Vec::new(),
            password: None,
            recursive: false,
            recursion_depth: None,
            recreate,
        }
    }

    fn sibling_req(tar: PathBuf) -> OpenRequest {
        sibling_req_recreate(tar, Recreate::IfInvalid)
    }

    fn url_scheme_leak(marker: &str) -> bool {
        Path::new("https:")
            .join(format!("{marker}.example.invalid"))
            .exists()
            || Path::new("http:")
                .join(format!("{marker}.example.invalid"))
                .exists()
    }

    /// Regression: Sibling + unwritable parent → SiblingNotWritable, not `:memory:`.
    #[test]
    fn resolve_sibling_not_writable() {
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("not-a-dir");
        std::fs::write(&blocker, b"file").unwrap();
        let archive = blocker.join("a.tar");
        let extra = tempfile::tempdir().unwrap();
        let err = resolve_index(
            &archive,
            IndexPolicy::Sibling,
            None,
            &[extra.path().to_path_buf()],
            false,
        )
        .expect_err("sibling must not fall back");
        match err {
            Error::SiblingNotWritable(p) => assert_eq!(p, blocker),
            other => panic!("expected SiblingNotWritable, got {other:?}"),
        }

        let err = match Session::open(sibling_req(archive)) {
            Err(e) => e,
            Ok(_) => panic!("open must not use :memory:"),
        };
        match err {
            Error::SiblingNotWritable(p) => assert_eq!(p, blocker),
            other => panic!("expected SiblingNotWritable, got {other:?}"),
        }
        let sqlite_left = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .any(|e| e.file_name().to_string_lossy().contains(".index.sqlite"));
        assert!(
            !sqlite_left,
            "must not create a sidecar on SiblingNotWritable"
        );
    }

    /// Regression: Session Sibling on chmod-unwritable archive dir is not `:memory:`.
    #[cfg(unix)]
    #[test]
    fn resolve_sibling_not_writable_open() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let tar = dir.path().join("a.tar");
        write_tar(&tar, &[member_file("a.txt", b"hi")]);
        let orig = std::fs::metadata(dir.path()).unwrap().permissions();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o555)).unwrap();
        let result = Session::open(sibling_req(tar.clone()));
        let still_writable = ratarmount_index::test_writable_dir(dir.path());
        let _ = std::fs::set_permissions(dir.path(), orig);
        match result {
            Err(Error::SiblingNotWritable(p)) => {
                assert_eq!(p, dir.path());
                assert!(
                    !default_index_path(&tar).exists(),
                    "SiblingNotWritable must not create a sidecar"
                );
            }
            Ok(session) => {
                let loc = session.into_index_location();
                assert!(
                    !loc.is_memory(),
                    "Session Sibling must not create :memory: on unwritable parent"
                );
                if still_writable {
                    eprintln!("skip: parent still writable (root?)");
                } else {
                    panic!("expected SiblingNotWritable, got Ok({loc:?})");
                }
            }
            Err(e) => panic!("expected SiblingNotWritable, got {e:?}"),
        }
    }

    #[test]
    fn resolve_sibling_writable_open_creates_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let tar = dir.path().join("a.tar");
        write_tar(&tar, &[member_file("a.txt", b"hi")]);
        let session = Session::open(sibling_req(tar.clone())).expect("Sibling open");
        let idx = default_index_path(&tar);
        assert!(
            idx.exists(),
            "writable sibling should create {}",
            idx.display()
        );
        assert_eq!(session.catalog_path(), Some(idx.as_path()));
        assert!(!session.index_is_memory());
        assert!(session.lookup("/a.txt").unwrap().is_some());
    }

    /// Regression: CliCompat still falls back to `:memory:` when nothing is writable.
    #[test]
    fn resolve_clicompat_memory_last_resort() {
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("not-a-dir");
        std::fs::write(&blocker, b"file").unwrap();
        let archive = dir.path().join("a.tar");
        std::fs::write(&archive, b"x").unwrap();
        let loc = resolve_index(
            &archive,
            IndexPolicy::CliCompat,
            None,
            std::slice::from_ref(&blocker),
            true,
        )
        .unwrap();
        assert_eq!(loc, IndexLocation::Memory);

        write_tar(&archive, &[member_file("a.txt", b"hi")]);
        let session = Session::open(OpenRequest {
            source: SourceSpec::Path(archive.clone()),
            index: IndexPolicy::CliCompat,
            explicit_index: None,
            extra_dirs: vec![blocker],
            password: None,
            recursive: false,
            recursion_depth: None,
            recreate: Recreate::IfInvalid,
        })
        .expect("CliCompat memory last resort should still open");
        assert!(session.index_is_memory());
        assert!(session.catalog_path().is_none());
        assert!(
            !default_index_path(&archive).exists(),
            "CliCompat memory last resort must not write a sibling sidecar"
        );
        let hit = session.lookup("/a.txt").unwrap().expect("a.txt");
        assert_eq!(hit.size, 2);
    }

    #[test]
    fn resolve_user_cache_does_not_write_meta_v3() {
        let xdg = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let tar = dir.path().join("a.tar");
        write_tar(&tar, &[member_file("a.txt", b"hi")]);
        let err = resolve_index(&tar, IndexPolicy::UserCache, None, &[], false).unwrap_err();
        match err {
            Error::Internal(msg) => {
                assert!(msg.contains("local-index-v1"), "{msg}");
                assert!(msg.contains("not meta-v3"), "{msg}");
            }
            other => panic!("expected Internal, got {other:?}"),
        }
        let old_xdg = std::env::var_os("XDG_CACHE_HOME");
        std::env::set_var("XDG_CACHE_HOME", xdg.path());
        let open_err = match Session::open(OpenRequest {
            source: SourceSpec::Path(tar),
            index: IndexPolicy::UserCache,
            explicit_index: None,
            extra_dirs: Vec::new(),
            password: None,
            recursive: false,
            recursion_depth: None,
            recreate: Recreate::IfInvalid,
        }) {
            Err(e) => e,
            Ok(_) => {
                match &old_xdg {
                    Some(v) => std::env::set_var("XDG_CACHE_HOME", v),
                    None => std::env::remove_var("XDG_CACHE_HOME"),
                }
                panic!("UserCache is not implemented");
            }
        };
        match old_xdg {
            Some(v) => std::env::set_var("XDG_CACHE_HOME", v),
            None => std::env::remove_var("XDG_CACHE_HOME"),
        }
        match open_err {
            Error::Internal(msg) => {
                assert!(msg.contains("local-index-v1"), "{msg}");
                assert!(msg.contains("not meta-v3"), "{msg}");
            }
            other => panic!("expected Internal, got {other:?}"),
        }
        let meta_v3 = xdg.path().join("ratarmount").join("meta-v3");
        assert!(
            !meta_v3.exists()
                || std::fs::read_dir(&meta_v3)
                    .map(|it| it.count() == 0)
                    .unwrap_or(true),
            "UserCache must not write meta-v3: {}",
            meta_v3.display()
        );
    }

    /// Recreate::Never + missing sidecar is NotFound even if the sibling parent is unwritable.
    #[test]
    fn resolve_sibling_never_missing_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("not-a-dir");
        std::fs::write(&blocker, b"file").unwrap();
        let archive = blocker.join("a.tar");
        let err = match Session::open(sibling_req_recreate(archive, Recreate::Never)) {
            Err(e) => e,
            Ok(_) => panic!("Never + missing sidecar must not open"),
        };
        match err {
            Error::NotFound => {}
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    /// Regression: scheme:// Sibling must not mkdir `https:` / skip remote discovery.
    #[test]
    fn resolve_sibling_url_does_not_mkdir() {
        let marker = format!("ratarmount-pr6-{}-url", std::process::id());
        let archive = PathBuf::from(format!("https://{marker}.example.invalid/a.tar"));
        let err = resolve_index(&archive, IndexPolicy::Sibling, None, &[], false).unwrap_err();
        match err {
            Error::SiblingNotWritable(_) => {}
            other => panic!("expected SiblingNotWritable for URL helper, got {other:?}"),
        }
        assert!(
            !url_scheme_leak(&marker),
            "resolve_index must not mkdir URL parents"
        );

        let url = format!("http://127.0.0.1:1/{marker}.example.invalid/a.tar");
        let open_err = match Session::open(OpenRequest {
            source: SourceSpec::Url(url),
            index: IndexPolicy::Sibling,
            explicit_index: None,
            extra_dirs: Vec::new(),
            password: None,
            recursive: false,
            recursion_depth: None,
            recreate: Recreate::IfInvalid,
        }) {
            Err(e) => e,
            Ok(_) => panic!("URL open should not succeed against 127.0.0.1:1"),
        };
        assert!(
            !matches!(open_err, Error::SiblingNotWritable(_)),
            "Session URL Sibling must not SNW; got {open_err:?}"
        );
        assert!(
            !url_scheme_leak(&marker),
            "Session::open must not mkdir URL parents"
        );
    }
}
