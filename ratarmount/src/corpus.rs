//! Read-only, pinned Git corpora with a shared bounded repository cache.
use std::collections::{HashMap, VecDeque};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ratarmount_compositing::{
    validate_mount_path, PrefixMountSource, UnionMountOptions, UnionMountSource,
};
use ratarmount_core::{
    normpath, ArchiveRead, CheapDirent, FileInfo, ListResult, MountSource, UserData,
};
use ratarmount_formats_git::GitMountSource;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Entry {
    repo: PathBuf,
    sha: String,
    mount_path: String,
}

pub(crate) fn parse_list(text: &str, base: &Path) -> Result<Vec<Entry>, String> {
    let mut entries = Vec::new();
    for (line_number, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let parsed = (|| {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.is_empty() || fields.len() > 2 {
                return Err("expected REPO@SHA [MOUNT/PATH]".into());
            }
            let (repo, sha) = fields[0].rsplit_once('@').ok_or("expected REPO@SHA")?;
            if repo.is_empty() || sha.len() != 40 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(
                    "corpus entries require a repository and a full 40-digit commit SHA".into(),
                );
            }
            let path = Path::new(repo);
            let default = {
                let name = path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .ok_or("missing repository name")?;
                let name = name.strip_suffix(".git").unwrap_or(name);
                match path
                    .parent()
                    .and_then(|p| p.file_name())
                    .and_then(|s| s.to_str())
                {
                    Some(org) => format!("{org}/{name}"),
                    None => name.to_string(),
                }
            };
            let mount_path = format!(
                "/{}",
                fields
                    .get(1)
                    .copied()
                    .unwrap_or(&default)
                    .trim_start_matches('/')
            );
            validate_mount_path(&mount_path)?;
            if mount_path.trim_matches('/').is_empty() {
                return Err("corpus mount paths must not be root".into());
            }
            Ok(Entry {
                repo: if path.is_absolute() {
                    path.to_path_buf()
                } else {
                    base.join(path)
                },
                sha: sha.to_ascii_lowercase(),
                mount_path: normpath(&mount_path),
            })
        })();
        entries.push(parsed.map_err(|e: String| format!("corpus line {}: {e}", line_number + 1))?);
    }
    if entries.is_empty() {
        return Err("corpus list contains no repositories".into());
    }
    Ok(entries)
}

type Opener = dyn Fn(&Entry) -> io::Result<Arc<dyn MountSource>> + Send + Sync;

struct Cache {
    sources: HashMap<usize, Arc<dyn MountSource>>,
    order: VecDeque<usize>,
}

struct Pool {
    entries: Vec<Entry>,
    capacity: usize,
    cache: Mutex<Cache>,
    opener: Box<Opener>,
}

impl Pool {
    fn get(&self, index: usize) -> io::Result<Arc<dyn MountSource>> {
        // Serialize misses as well as eviction, so concurrent requests cannot
        // open the same repository twice or exceed the idle-source bound.
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| io::Error::other("corpus cache poisoned"))?;
        if let Some(source) = cache.sources.get(&index).cloned() {
            cache.order.retain(|&i| i != index);
            cache.order.push_back(index);
            return Ok(source);
        }
        if cache.sources.len() == self.capacity {
            if let Some(old) = cache.order.pop_front() {
                cache.sources.remove(&old);
            }
        }
        let source = (self.opener)(&self.entries[index])?;
        cache.sources.insert(index, Arc::clone(&source));
        cache.order.push_back(index);
        Ok(source)
    }
}

struct LazyRepo {
    pool: Arc<Pool>,
    index: usize,
}

impl LazyRepo {
    fn source(&self) -> Option<Arc<dyn MountSource>> {
        self.pool
            .get(self.index)
            .map_err(|e| {
                log::error!(
                    "corpus {}: {e}",
                    self.pool.entries[self.index].repo.display()
                );
            })
            .ok()
    }

    fn cookie(&self, path: &str, version: i32, mut fi: FileInfo) -> FileInfo {
        fi.userdata.push(UserData::Other(format!(
            "corpus:{version}:{}",
            normpath(path)
        )));
        fi
    }

    fn resolve(&self, fi: &FileInfo) -> io::Result<(Arc<dyn MountSource>, FileInfo)> {
        let Some(UserData::Other(cookie)) = fi.userdata.last() else {
            return Err(io::Error::other("missing corpus cookie"));
        };
        let (version, path) = cookie
            .strip_prefix("corpus:")
            .and_then(|s| s.split_once(':'))
            .ok_or_else(|| io::Error::other("invalid corpus cookie"))?;
        let version = version
            .parse()
            .map_err(|_| io::Error::other("invalid corpus version"))?;
        let source = self.pool.get(self.index)?;
        let info = source
            .lookup(path, version)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, path))?;
        Ok((source, info))
    }
}

impl MountSource for LazyRepo {
    fn list(&self, path: &str) -> Option<ListResult> {
        match self.source()?.list(path)? {
            ListResult::Infos(map) => Some(ListResult::Infos(
                map.into_iter()
                    .map(|(name, fi)| {
                        let full = format!("{}/{name}", path.trim_end_matches('/'));
                        (name, self.cookie(&full, 0, fi))
                    })
                    .collect(),
            )),
            names => Some(names),
        }
    }
    fn list_dirents(&self, path: &str) -> Option<Vec<CheapDirent>> {
        self.source()?.list_dirents(path)
    }
    fn lookup(&self, path: &str, version: i32) -> Option<FileInfo> {
        Some(self.cookie(path, version, self.source()?.lookup(path, version)?))
    }
    fn open(&self, fi: &FileInfo, buffering: i32) -> io::Result<Box<dyn ArchiveRead>> {
        let (source, info) = self.resolve(fi)?;
        source.open(&info, buffering)
    }
    fn list_xattr(&self, fi: &FileInfo) -> Vec<String> {
        self.resolve(fi)
            .map(|(source, info)| source.list_xattr(&info))
            .unwrap_or_default()
    }
    fn get_xattr(&self, fi: &FileInfo, key: &str) -> Option<Vec<u8>> {
        let (source, info) = self.resolve(fi).ok()?;
        source.get_xattr(&info, key)
    }
    // Prevent enclosing unions from eagerly walking the repositories to build
    // their directory cache. Each underlying committed tree remains pinned.
    fn is_immutable(&self) -> bool {
        false
    }
}

fn build(entries: Vec<Entry>, capacity: usize, opener: Box<Opener>) -> Arc<dyn MountSource> {
    let pool = Arc::new(Pool {
        entries,
        capacity: capacity.max(1),
        opener,
        cache: Mutex::new(Cache {
            sources: HashMap::new(),
            order: VecDeque::new(),
        }),
    });
    let sources = pool
        .entries
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            Arc::new(PrefixMountSource::new(
                &entry.mount_path,
                Arc::new(LazyRepo {
                    pool: Arc::clone(&pool),
                    index,
                }),
            )) as Arc<dyn MountSource>
        })
        .collect();
    Arc::new(UnionMountSource::new_with_options(
        sources,
        UnionMountOptions {
            max_cache_entries: 0,
            max_cache_depth: 1,
            max_seconds_to_cache: 0.0,
            ..Default::default()
        },
    ))
}

pub(crate) fn open(list: &Path, capacity: usize) -> Result<Arc<dyn MountSource>, String> {
    let text = std::fs::read_to_string(list).map_err(|e| format!("{}: {e}", list.display()))?;
    let entries = parse_list(&text, list.parent().unwrap_or(Path::new(".")))?;
    Ok(build(
        entries,
        capacity,
        Box::new(|entry| {
            let source =
                GitMountSource::open(&entry.repo, Some(&entry.sha)).map_err(io::Error::other)?;
            if source.resolved_commit().to_string() != entry.sha {
                return Err(io::Error::other(
                    "corpus revision did not resolve to the pinned commit",
                ));
            }
            Ok(Arc::new(source))
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratarmount_compositing::FolderMountSource;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Regression: corpus parsing must reject floating refs and escaping paths without opening repos.
    #[test]
    fn regression_corpus_list_requires_pinned_commits() {
        let sha = "a".repeat(40);
        let entries = parse_list(
            &format!(
                "# pinned corpus\n\norg/name.git@{sha}\nother.git@{sha} custom/deep # comment\n"
            ),
            Path::new("/lists"),
        )
        .unwrap();
        assert_eq!(entries[0].mount_path, "/org/name");
        assert_eq!(entries[0].repo, Path::new("/lists/org/name.git"));
        assert_eq!(entries[1].mount_path, "/custom/deep");
        for text in [
            "repo.git@HEAD".to_string(),
            format!("repo.git@{sha} ../escape"),
            format!("repo.git@{sha} /"),
            format!("repo.git@{sha} a extra"),
            "# empty".into(),
        ] {
            assert!(parse_list(&text, Path::new(".")).is_err(), "{text}");
        }
    }

    /// Regression: listing 10,000 corpus bindings eagerly opened all repositories.
    #[test]
    fn regression_corpus_root_listing_opens_zero_repositories() {
        let entries = (0..10_000)
            .map(|i| Entry {
                repo: PathBuf::from(format!("r{i}.git")),
                sha: "a".repeat(40),
                mount_path: format!("/org/r{i}"),
            })
            .collect();
        let source = build(
            entries,
            2,
            Box::new(|_| panic!("listing namespace must not open a repo")),
        );
        assert_eq!(source.list_dirents("/").unwrap()[0].name, "org");
        assert_eq!(source.list_dirents("/org").unwrap().len(), 10_000);
        assert!(source.lookup("/org/r123", 0).is_some());
        assert!(source.lookup("/other/file", 0).is_none());
        assert!(matches!(source.list("/"), Some(ListResult::Infos(map)) if map.len() == 1));
        let bundle = ratarmount_session::factory::build_mount_source_with_bindings(
            &[],
            &mut ratarmount_core::OpenOptions {
                index_in_memory: true,
                ..Default::default()
            },
            false,
            ratarmount_session::factory::CompositingOptions {
                recursive: true,
                lazy: true,
                file_versions: true,
                ..Default::default()
            },
            ratarmount_session::factory::SourceBindings {
                sources: vec![source],
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(bundle.source.list_dirents("/").unwrap()[0].name, "org");
    }

    /// Regression: eviction must close idle repos and old metadata cookies must reopen pinned bytes.
    #[test]
    fn regression_corpus_lru_eviction_keeps_file_cookies_valid() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("file"), b"pinned bytes").unwrap();
        let opens = Arc::new(AtomicUsize::new(0));
        let weak_sources = Arc::new(Mutex::new(Vec::new()));
        let opened = Arc::clone(&opens);
        let weak = Arc::clone(&weak_sources);
        let root = dir.path().to_path_buf();
        let entries = (0..3)
            .map(|i| Entry {
                repo: root.clone(),
                sha: "a".repeat(40),
                mount_path: format!("/r{i}"),
            })
            .collect();
        let source = build(
            entries,
            2,
            Box::new(move |_| {
                opened.fetch_add(1, Ordering::SeqCst);
                let source =
                    Arc::new(FolderMountSource::new(&root).unwrap()) as Arc<dyn MountSource>;
                weak.lock().unwrap().push(Arc::downgrade(&source));
                Ok(source)
            }),
        );
        assert_eq!(opens.load(Ordering::SeqCst), 0);
        let first = source.lookup("/r0/file", 0).unwrap();
        let second = source.lookup("/r1/file", 0).unwrap();
        // Touch r0: r1 must be the least recently used source.
        assert_eq!(source.read(&first, 12, 0).unwrap(), b"pinned bytes");
        let _ = source.lookup("/r2/file", 0).unwrap();
        assert!(weak_sources.lock().unwrap()[1].upgrade().is_none());
        assert_eq!(opens.load(Ordering::SeqCst), 3);
        assert_eq!(source.read(&second, 12, 0).unwrap(), b"pinned bytes");
        assert_eq!(source.read(&first, 12, 0).unwrap(), b"pinned bytes");
        assert_eq!(opens.load(Ordering::SeqCst), 5);
        assert!(
            weak_sources
                .lock()
                .unwrap()
                .iter()
                .filter(|s| s.upgrade().is_some())
                .count()
                <= 2
        );
        let ListResult::Infos(list) = source.list("/r2").unwrap() else {
            panic!("infos");
        };
        assert_eq!(source.read(&list["file"], 12, 0).unwrap(), b"pinned bytes");
    }

    /// Regression: corpus repos must read the listed commit after HEAD moves and after eviction.
    #[test]
    fn regression_corpus_reopen_uses_pinned_commit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("repo.git");
        let repo = git2::Repository::init_bare(&path).unwrap();
        let signature = git2::Signature::now("test", "test@example.test").unwrap();
        let mut tree = repo.treebuilder(None).unwrap();
        tree.insert("file", repo.blob(b"old").unwrap(), 0o100644)
            .unwrap();
        let tree = repo.find_tree(tree.write().unwrap()).unwrap();
        let first = repo
            .commit(Some("HEAD"), &signature, &signature, "first", &tree, &[])
            .unwrap();
        let mut next = repo.treebuilder(None).unwrap();
        next.insert("file", repo.blob(b"new").unwrap(), 0o100644)
            .unwrap();
        let next = repo.find_tree(next.write().unwrap()).unwrap();
        repo.commit(
            Some("HEAD"),
            &signature,
            &signature,
            "second",
            &next,
            &[&repo.find_commit(first).unwrap()],
        )
        .unwrap();
        let list = dir.path().join("list.txt");
        std::fs::write(
            &list,
            format!("repo.git@{first} org/a\nrepo.git@{first} org/b\n"),
        )
        .unwrap();
        let source = open(&list, 1).unwrap();
        let fi = source.lookup("/org/a/file", 0).unwrap();
        let _ = source.lookup("/org/b/file", 0).unwrap();
        assert_eq!(source.read(&fi, 100, 0).unwrap(), b"old");
    }
}
