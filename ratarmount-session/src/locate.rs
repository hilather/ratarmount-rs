//! Catalog / cheap locate helpers for [`Session::find`].

use ratarmount_core::CheapSearchHit;
use ratarmount_index::{
    cmp_offset_then_name, FindAfter, SearchHit, SearchQuery, SqliteIndex, MAX_DIR_PAGE,
};

use crate::session::Session;
use crate::types::{DirEnt, FindCursor, FindOpts, FindPage};
use crate::Error;

/// Default `Session::find` page size when [`FindOpts::limit`] is 0.
pub const DEFAULT_FIND_PAGE: u32 = 200;

/// `fts:` prefix forces FTS5; otherwise [`force_fts`].
pub fn split_fts_pattern(pattern: &str, force_fts: bool) -> (bool, &str) {
    if let Some(rest) = pattern.strip_prefix("fts:") {
        return (true, rest);
    }
    (force_fts, pattern)
}

/// Thin [`SqliteIndex::search_query`] wrapper; does not call [`SqliteIndex::ensure_fts5`].
pub fn query_index(idx: &SqliteIndex, q: &SearchQuery<'_>) -> Result<Vec<SearchHit>, String> {
    idx.search_query(q).map_err(|e| e.to_string())
}

impl Session {
    /// Catalog glob/FTS locate, keyset-paged on `(fullpath, offsetheader)`.
    ///
    /// Prefers sidecar SQL. When there is no catalog, pages `search_cheap` if
    /// that `Vec` is already the full answer. Does not merge the two.
    /// [`SqliteIndex::ensure_fts5`] runs only when `opts.fts` or `fts:` is set.
    pub fn find(&self, pattern: &str, opts: FindOpts) -> Result<FindPage, Error> {
        let limit = if opts.limit == 0 {
            DEFAULT_FIND_PAGE
        } else {
            opts.limit.min(MAX_DIR_PAGE)
        };
        let (fts, pat) = split_fts_pattern(pattern, opts.fts);
        let after = match &opts.cursor {
            FindCursor::Start => None,
            FindCursor::AfterPath { path, offsetheader } => Some(FindAfter {
                fullpath: path.as_str(),
                offsetheader: *offsetheader,
            }),
        };
        let fetch = (limit as usize).saturating_add(1);
        let q = SearchQuery {
            pattern: pat,
            fts,
            include_hashes: opts.include_hashes,
            limit: fetch,
            offset_order: false,
            after,
        };

        let mut hits = if let Some(cat) = &self.catalog {
            find_catalog_hits(self, cat, &q, fts)?
        } else if fts {
            return Err(Error::Internal(
                "files_fts is not present; call ensure_fts5".into(),
            ));
        } else if let Some(cheap) = self.source.source().search_cheap(pat) {
            page_cheap_hits(cheap, q.after, fetch)
        } else {
            Vec::new()
        };

        let next_cursor = next_cursor_from_hits(&hits, limit as usize);
        if hits.len() > limit as usize {
            hits.truncate(limit as usize);
        }
        if opts.offset_order {
            hits.sort_by(|a, b| {
                cmp_offset_then_name(a.offsetheader, &a.path, b.offsetheader, &b.path)
            });
        }

        Ok(FindPage {
            pattern: pattern.to_string(),
            fts,
            entries: hits.into_iter().map(dirent_from_search_hit).collect(),
            next_cursor,
            total_hint: None,
        })
    }
}

fn find_catalog_hits(
    session: &Session,
    cat: &SqliteIndex,
    q: &SearchQuery<'_>,
    fts: bool,
) -> Result<Vec<SearchHit>, Error> {
    if fts {
        let has_fts = cat
            .has_files_fts()
            .map_err(|e| Error::Internal(e.to_string()))?;
        if has_fts {
            return query_index(cat, q).map_err(Error::Internal);
        }
        let Some(path) = session.loc.path() else {
            return Err(Error::Internal(
                "files_fts is not present; call ensure_fts5".into(),
            ));
        };
        let w = SqliteIndex::open_writable(path).map_err(|e| Error::Internal(e.to_string()))?;
        w.ensure_fts5()
            .map_err(|e| Error::Internal(e.to_string()))?;
        let hits = query_index(&w, q).map_err(Error::Internal)?;
        drop(w);
        Ok(hits)
    } else {
        query_index(cat, q).map_err(Error::Internal)
    }
}

fn page_cheap_hits(
    mut hits: Vec<CheapSearchHit>,
    after: Option<FindAfter<'_>>,
    fetch: usize,
) -> Vec<SearchHit> {
    hits.sort_by(|a, b| {
        a.path.cmp(&b.path).then_with(|| {
            a.offsetheader
                .unwrap_or(-1)
                .cmp(&b.offsetheader.unwrap_or(-1))
        })
    });
    hits.into_iter()
        .filter(|h| cheap_after(h, after))
        .take(fetch)
        .map(search_hit_from_cheap)
        .collect()
}

fn cheap_after(h: &CheapSearchHit, after: Option<FindAfter<'_>>) -> bool {
    let Some(a) = after else {
        return true;
    };
    h.path.as_str() > a.fullpath
        || (h.path.as_str() == a.fullpath
            && h.offsetheader.unwrap_or(-1) > a.offsetheader.unwrap_or(-1))
}

fn search_hit_from_cheap(h: CheapSearchHit) -> SearchHit {
    SearchHit {
        path: h.path,
        name: h.name,
        size: h.size,
        mtime: h.mtime,
        offsetheader: h.offsetheader,
        hashes: Vec::new(),
    }
}

fn next_cursor_from_hits(hits: &[SearchHit], limit: usize) -> Option<FindCursor> {
    if hits.len() <= limit {
        return None;
    }
    let last = hits.get(limit.saturating_sub(1))?;
    Some(FindCursor::AfterPath {
        path: last.path.clone(),
        offsetheader: last.offsetheader,
    })
}

fn dirent_from_search_hit(h: SearchHit) -> DirEnt {
    DirEnt {
        name: h.name,
        path: h.path,
        is_dir: false,
        size: h.size.max(0) as u64,
        mtime: Some(h.mtime as i64),
        mode: 0,
        archive_offset: h.offsetheader.filter(|&o| o >= 0).map(|o| o as u64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{IndexPolicy, OpenRequest, Recreate, SourceSpec};
    use ratarmount_formats_tar::{write_tar_eof, write_ustar_members, UstarMember, UstarPayload};
    use std::io::Write;
    use std::path::Path;

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

    fn open_tar(dir: &Path, name: &str, members: &[UstarMember<'_>]) -> Session {
        let tar = dir.join(name);
        write_tar(&tar, members);
        let idx = dir.join(format!("{name}.index.sqlite"));
        Session::open(OpenRequest {
            source: SourceSpec::Path(tar),
            index: IndexPolicy::Explicit,
            explicit_index: Some(idx),
            extra_dirs: Vec::new(),
            password: None,
            recursive: false,
            recursion_depth: None,
            recreate: Recreate::IfInvalid,
        })
        .expect("Session::open")
    }

    fn page_keys(page: &FindPage) -> Vec<(String, Option<i64>)> {
        page.entries
            .iter()
            .map(|e| (e.path.clone(), e.archive_offset.map(|o| o as i64)))
            .collect()
    }

    /// Regression: Session::find glob pages with composite keyset; duplicates kept.
    #[test]
    fn find_glob_pages_composite_keyset() {
        let dir = tempfile::tempdir().unwrap();
        let v1 = b"v1";
        let v2 = b"v2xx";
        let a = b"a";
        let z = b"z";
        let members = [
            member_file("a.fits", a),
            member_file("dup.fits", v1),
            member_file("dup.fits", v2),
            member_file("z.fits", z),
        ];
        let session = open_tar(dir.path(), "dup.tar", &members);

        let mut seen = Vec::new();
        let mut cursor = FindCursor::Start;
        let mut pages = 0u32;
        loop {
            let page = session
                .find(
                    "*.fits",
                    FindOpts {
                        limit: 1,
                        cursor,
                        ..FindOpts::default()
                    },
                )
                .expect("find page");
            assert!(page.entries.len() <= 1);
            assert!(!page.fts);
            for e in &page.entries {
                seen.push((e.path.clone(), e.archive_offset));
            }
            pages += 1;
            match page.next_cursor {
                None => break,
                Some(next) => cursor = next,
            }
        }
        assert_eq!(
            pages, 4,
            "four catalog rows including two dup.fits versions"
        );
        let paths: Vec<&str> = seen.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(
            paths,
            vec!["/a.fits", "/dup.fits", "/dup.fits", "/z.fits"],
            "duplicates per path must not be skipped"
        );
        assert_ne!(
            seen[1].1, seen[2].1,
            "the two /dup.fits hits must differ in offsetheader"
        );

        let first = session
            .find(
                "*.fits",
                FindOpts {
                    limit: 2,
                    ..FindOpts::default()
                },
            )
            .unwrap();
        assert_eq!(
            page_keys(&first)
                .iter()
                .map(|(p, _)| p.as_str())
                .collect::<Vec<_>>(),
            vec!["/a.fits", "/dup.fits"]
        );
        let FindCursor::AfterPath { path, offsetheader } = first.next_cursor.unwrap() else {
            panic!("expected AfterPath");
        };
        assert_eq!(path, "/dup.fits");
        let second = session
            .find(
                "*.fits",
                FindOpts {
                    limit: 2,
                    cursor: FindCursor::AfterPath { path, offsetheader },
                    ..FindOpts::default()
                },
            )
            .unwrap();
        assert_eq!(
            second
                .entries
                .iter()
                .map(|e| e.path.as_str())
                .collect::<Vec<_>>(),
            vec!["/dup.fits", "/z.fits"]
        );
        assert!(second.next_cursor.is_none());
    }

    /// Regression: Session::open must not create `"files_fts"`.
    #[test]
    fn ensure_fts5_not_on_session_open() {
        let dir = tempfile::tempdir().unwrap();
        let payload = b"hi";
        let session = open_tar(dir.path(), "fts.tar", &[member_file("a.txt", payload)]);
        let has = session
            .catalog
            .as_ref()
            .map(|c| c.has_files_fts().unwrap())
            .expect("path-backed catalog");
        assert!(
            !has,
            "Session::open must not call ensure_fts5 / create files_fts"
        );
    }

    /// FTS is opt-in on find (`fts:` / FindOpts.fts), not a side effect of open.
    #[test]
    fn find_fts_opt_in_creates_files_fts() {
        let dir = tempfile::tempdir().unwrap();
        let payload = b"fits";
        let session = open_tar(
            dir.path(),
            "fts2.tar",
            &[
                member_file("a.fits", payload),
                member_file("readme.txt", b"hello"),
            ],
        );
        assert!(
            !session.catalog.as_ref().unwrap().has_files_fts().unwrap(),
            "open does not build FTS"
        );
        let page = session
            .find("fts:fits", FindOpts::default())
            .expect("fts find");
        assert!(page.fts);
        let paths: Vec<&str> = page.entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(paths, vec!["/a.fits"]);
        assert!(
            session.catalog.as_ref().unwrap().has_files_fts().unwrap(),
            "live RO catalog must see files_fts after opt-in find (no reopen)"
        );
        let again = session
            .find("fts:fits", FindOpts::default())
            .expect("second fts page uses existing files_fts");
        assert_eq!(
            again
                .entries
                .iter()
                .map(|e| e.path.as_str())
                .collect::<Vec<_>>(),
            vec!["/a.fits"]
        );
    }

    /// Regression: FTS with no catalog is an error, not a successful empty page.
    #[test]
    fn find_fts_without_catalog_errors() {
        let session = Session::stub();
        let err = session
            .find("fts:token", FindOpts::default())
            .expect_err("FTS without catalog");
        match err {
            Error::Internal(msg) => assert!(
                msg.contains("files_fts"),
                "expected files_fts unavailable, got {msg}"
            ),
            other => panic!("expected Internal, got {other:?}"),
        }
        let err = session
            .find(
                "token",
                FindOpts {
                    fts: true,
                    ..FindOpts::default()
                },
            )
            .expect_err("FindOpts.fts without catalog");
        assert!(matches!(err, Error::Internal(_)));
    }

    /// Regression: no-catalog search_cheap Some pages both offsetheaders for one path.
    #[test]
    fn find_cheap_pages_composite_keyset() {
        use ratarmount_core::{ArchiveRead, CheapSearchHit, FileInfo, MountSource};
        use std::sync::Arc;

        struct CheapDupMount;
        impl MountSource for CheapDupMount {
            fn list(&self, _path: &str) -> Option<ratarmount_core::ListResult> {
                None
            }
            fn lookup(&self, _path: &str, _file_version: i32) -> Option<FileInfo> {
                None
            }
            fn open(
                &self,
                _file_info: &FileInfo,
                _buffering: i32,
            ) -> std::io::Result<Box<dyn ArchiveRead>> {
                Err(std::io::Error::other("cheap-dup"))
            }
            fn is_immutable(&self) -> bool {
                true
            }
            fn search_cheap(&self, pattern: &str) -> Option<Vec<CheapSearchHit>> {
                if pattern.starts_with("fts:") {
                    return None;
                }
                Some(vec![
                    CheapSearchHit {
                        path: "/dup.fits".into(),
                        name: "dup.fits".into(),
                        size: 1,
                        mtime: 1.0,
                        offsetheader: Some(512),
                    },
                    CheapSearchHit {
                        path: "/dup.fits".into(),
                        name: "dup.fits".into(),
                        size: 2,
                        mtime: 1.0,
                        offsetheader: Some(1024),
                    },
                ])
            }
        }

        let session = Session::from_local_source(Arc::new(CheapDupMount));
        let first = session
            .find(
                "*.fits",
                FindOpts {
                    limit: 1,
                    ..FindOpts::default()
                },
            )
            .expect("cheap page 1");
        assert_eq!(first.entries.len(), 1);
        assert_eq!(first.entries[0].path, "/dup.fits");
        assert_eq!(first.entries[0].archive_offset, Some(512));
        let cursor = first.next_cursor.expect("next after first dup");
        let second = session
            .find(
                "*.fits",
                FindOpts {
                    limit: 1,
                    cursor,
                    ..FindOpts::default()
                },
            )
            .expect("cheap page 2");
        assert_eq!(second.entries.len(), 1);
        assert_eq!(second.entries[0].path, "/dup.fits");
        assert_eq!(second.entries[0].archive_offset, Some(1024));
        assert!(second.next_cursor.is_none());
    }
}
