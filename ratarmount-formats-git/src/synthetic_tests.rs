use super::*;
use std::collections::BTreeSet;
use std::fs;
use std::process::Command;

fn test_dir() -> tempfile::TempDir {
    // macOS's default temp path can include the system /var symlink.
    tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap()
}

fn fixture(path: &Path) -> (Repository, Oid, Oid, Oid) {
    let repo = Repository::init(path).unwrap();
    let initial = repo.blob(b"before\n").unwrap();
    let fix_blob = repo.blob(b"secret future fix\n").unwrap();
    let mut nested = repo.treebuilder(None).unwrap();
    nested.insert("code.txt", initial, 0o100644).unwrap();
    let subtree = nested.write().unwrap();
    let mut builder = repo.treebuilder(None).unwrap();
    builder.insert("code.txt", initial, 0o100644).unwrap();
    builder.insert("sub", subtree, 0o040000).unwrap();
    builder
        .insert("run", repo.blob(b"#!/bin/sh\n").unwrap(), 0o100755)
        .unwrap();
    #[cfg(unix)]
    builder
        .insert("link", repo.blob(b"code.txt").unwrap(), 0o120000)
        .unwrap();
    let first_tree = repo.find_tree(builder.write().unwrap()).unwrap();
    let sig = git2::Signature::new(
        "source",
        "source@example.test",
        &git2::Time::new(1_600_000_000, 60),
    )
    .unwrap();
    let first = repo
        .commit(
            Some("HEAD"),
            &sig,
            &sig,
            "private original message",
            &first_tree,
            &[],
        )
        .unwrap();
    builder.insert("fix.txt", fix_blob, 0o100644).unwrap();
    let fix_tree = repo.find_tree(builder.write().unwrap()).unwrap();
    let second = repo
        .commit(
            Some("HEAD"),
            &sig,
            &sig,
            "future fix",
            &fix_tree,
            &[&repo.find_commit(first).unwrap()],
        )
        .unwrap();
    drop((builder, nested, first_tree, fix_tree));
    (repo, first, second, fix_blob)
}

fn materialize(source: &dyn MountSource, vpath: &str, destination: &Path) {
    fs::create_dir_all(destination).unwrap();
    for entry in source.list_dirents(vpath).unwrap() {
        let path = format!("{}/{name}", vpath.trim_end_matches('/'), name = entry.name);
        let fi = source.lookup(&path, 0).unwrap();
        let target = destination.join(entry.name);
        match fi.mode & ratarmount_core::S_IFMT {
            ratarmount_core::S_IFDIR => materialize(source, &path, &target),
            #[cfg(unix)]
            ratarmount_core::S_IFLNK => std::os::unix::fs::symlink(&fi.linkname, target).unwrap(),
            _ => {
                let mut file = fs::File::create(&target).unwrap();
                io::copy(&mut source.open(&fi, 0).unwrap(), &mut file).unwrap();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    file.set_permissions(fs::Permissions::from_mode(fi.mode & 0o777))
                        .unwrap();
                }
                let time = std::time::UNIX_EPOCH + std::time::Duration::from_secs_f64(fi.mtime);
                file.set_modified(time).unwrap();
            }
        }
    }
}

/// Regression: a misspelled explicit ref silently mounted HEAD, exposing a later fix.
#[test]
fn regression_bad_ref_does_not_fall_back_to_head() {
    let dir = test_dir();
    let (repo, first, second, _) = fixture(dir.path());
    let src = GitMountSource::open(dir.path(), Some(&first.to_string())).unwrap();
    assert_eq!(src.resolved_commit(), first);
    assert!(src.lookup("/fix.txt", 0).is_none());
    assert!(src.lookup("/code.txt", 0).is_some());
    assert_eq!(
        src.get_xattr(&src.lookup("/", 0).unwrap(), COMMIT_XATTR),
        Some(first.to_string().into_bytes())
    );
    let error = GitMountSource::open(dir.path(), Some("missing-ref"))
        .err()
        .unwrap()
        .to_string();
    assert!(
        error.contains("cannot resolve git ref \"missing-ref\""),
        "{error}"
    );
    repo.set_head_detached(second).unwrap();
    assert_eq!(
        GitMountSource::open(dir.path(), None)
            .unwrap()
            .resolved_commit(),
        second
    );
    repo.set_head_detached(first).unwrap();
    assert_eq!(
        GitMountSource::open(dir.path(), None)
            .unwrap()
            .resolved_commit(),
        first
    );
}

/// Regression: inline ref parsing must preserve literal @ paths and reflog syntax.
#[test]
fn regression_inline_ref_preserves_literal_at_paths() {
    let dir = test_dir();
    let path = dir.path().join("repo@name.git");
    let (_, first, _, _) = fixture(&path);
    assert!(split_inline_reference(&path).is_none());
    let inline = PathBuf::from(format!("{}@{first}", path.display()));
    assert_eq!(
        split_inline_reference(&inline),
        Some((path.clone(), first.to_string()))
    );
    let inline = PathBuf::from(format!("{}@HEAD@{{0}}", path.display()));
    assert_eq!(
        split_inline_reference(&inline),
        Some((path, "HEAD@{0}".into()))
    );
}

/// Regression: synthetic Git must never copy future/history objects, refs or config.
#[test]
fn regression_synthetic_head_excludes_future_objects() {
    let dir = test_dir();
    let (repo, first, second, fix_blob) = fixture(&dir.path().join("source"));
    repo.remote("origin", "https://example.invalid/private")
        .unwrap();
    repo.tag_lightweight("future", &repo.find_object(second, None).unwrap(), false)
        .unwrap();
    let cache = dir.path().join("cache");
    let src = GitMountSource::open(repo.workdir().unwrap(), Some(&first.to_string()))
        .unwrap()
        .with_synthetic_head(&cache)
        .unwrap();
    let copy = dir.path().join("copy");
    materialize(&src, "/", &copy);
    let synthetic = Repository::open(copy.join(".git")).unwrap();
    let head = synthetic.head().unwrap().peel_to_commit().unwrap();
    assert_eq!(head.parent_count(), 0);
    assert_eq!(head.author().name(), Some("ratarmount"));
    assert_eq!(head.committer().when().seconds(), 1_600_000_000);
    assert_eq!(head.committer().when().offset_minutes(), 0);
    assert_eq!(head.message(), Some("Synthetic sandbox HEAD\n"));
    assert_eq!(head.tree_id(), repo.find_commit(first).unwrap().tree_id());
    let odb = synthetic.odb().unwrap();
    let mut actual = BTreeSet::new();
    odb.foreach(|oid| {
        actual.insert(*oid);
        true
    })
    .unwrap();
    let mut expected = BTreeSet::from([head.id()]);
    fn walk(repo: &Repository, oid: Oid, expected: &mut BTreeSet<Oid>) {
        expected.insert(oid);
        for e in repo.find_tree(oid).unwrap().iter() {
            if e.kind() == Some(ObjectType::Tree) {
                walk(repo, e.id(), expected);
            } else {
                expected.insert(e.id());
            }
        }
    }
    walk(&repo, head.tree_id(), &mut expected);
    assert_eq!(actual, expected);
    for absent in [first, second, fix_blob] {
        assert!(!actual.contains(&absent));
    }
    assert_eq!(
        synthetic
            .references()
            .unwrap()
            .map(|r| r.unwrap().name().unwrap().to_owned())
            .collect::<Vec<_>>(),
        ["refs/heads/sandbox"]
    );
    for path in [
        "/logs",
        "/packed-refs",
        "/objects/info/alternates",
        "/hooks",
    ] {
        assert!(src.lookup(&format!("/.git{path}"), 0).is_none());
    }
    assert!(synthetic.remotes().unwrap().is_empty());
    let index = synthetic.index().unwrap();
    for entry in index.iter() {
        let path = format!("/{}", std::str::from_utf8(&entry.path).unwrap());
        let fi = src.lookup(&path, 0).unwrap();
        assert_eq!(entry.file_size as u64, fi.size);
        assert_eq!(entry.mtime.seconds() as f64, fi.mtime);
        assert_eq!(
            entry.mode & ratarmount_core::S_IFMT,
            fi.mode & ratarmount_core::S_IFMT
        );
        if entry.mode & ratarmount_core::S_IFMT == ratarmount_core::S_IFREG {
            assert_eq!(entry.mode & 0o100, fi.mode & 0o100);
        }
        assert_eq!(entry.flags & 0x8000, 0, "must not assume unchanged");
    }
    let before = src.lookup("/.git/index", 0).unwrap().mtime;
    let again = GitMountSource::open(repo.workdir().unwrap(), Some(&first.to_string()))
        .unwrap()
        .with_synthetic_head(&cache)
        .unwrap();
    assert_eq!(again.lookup("/.git/index", 0).unwrap().mtime, before);
    let rebuilt = GitMountSource::open(repo.workdir().unwrap(), Some(&first.to_string()))
        .unwrap()
        .with_synthetic_head(&dir.path().join("other-cache"))
        .unwrap();
    let head_file = rebuilt.lookup("/.git/refs/heads/sandbox", 0).unwrap();
    assert_eq!(
        rebuilt.read(&head_file, 100, 0).unwrap(),
        format!("{}\n", head.id()).as_bytes()
    );
    assert!(src.lookup("/.git/../HEAD", 0).is_none());
}

/// Regression: prefix sandboxes must not include sibling trees or their blobs.
#[test]
fn regression_synthetic_prefix_has_only_selected_tree() {
    let dir = test_dir();
    let (repo, first, _, _) = fixture(&dir.path().join("repo"));
    let src = GitMountSource::open(repo.workdir().unwrap(), Some(&first.to_string()))
        .unwrap()
        .with_prefix("sub")
        .unwrap()
        .with_synthetic_head(&dir.path().join("cache"))
        .unwrap();
    let copy = dir.path().join("copy");
    materialize(&src, "/", &copy);
    let synthetic = Repository::open(&copy).unwrap();
    assert_eq!(
        synthetic
            .head()
            .unwrap()
            .peel_to_commit()
            .unwrap()
            .tree_id(),
        repo.find_commit(first)
            .unwrap()
            .tree()
            .unwrap()
            .get_name("sub")
            .unwrap()
            .id()
    );
    assert!(src.lookup("/run", 0).is_none());
    assert!(src.lookup("/code.txt", 0).is_some());
    assert!(GitMountSource::open(repo.workdir().unwrap(), None)
        .unwrap()
        .with_prefix("missing")
        .is_err());
    assert!(GitMountSource::open(repo.workdir().unwrap(), None)
        .unwrap()
        .with_prefix("code.txt")
        .is_err());
    assert!(!synthetic
        .odb()
        .unwrap()
        .exists(repo.find_commit(first).unwrap().tree_id()));
}

fn git(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args([
            "-c",
            "user.name=Agent",
            "-c",
            "user.email=agent@example.test",
        ])
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_OBJECT_DIRECTORY")
        .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

/// Regression: an exposed tree without a matching index makes Git status dirty.
#[test]
fn regression_synthetic_git_status_diff_add_and_stash() {
    if Command::new("git").arg("--version").output().is_err() {
        eprintln!("skip: git CLI missing (pure git2 object/index tests still run)");
        return;
    }
    let dir = test_dir();
    let (repo, first, second, fix_blob) = fixture(&dir.path().join("repo"));
    let src = GitMountSource::open(repo.workdir().unwrap(), Some(&first.to_string()))
        .unwrap()
        .with_synthetic_head(&dir.path().join("cache"))
        .unwrap();
    let copy = dir.path().join("copy");
    materialize(&src, "/", &copy);
    assert_eq!(git(&copy, &["status", "--porcelain"]), "");
    assert_eq!(git(&copy, &["log", "--oneline"]).lines().count(), 1);
    assert_eq!(git(&copy, &["reflog"]), "");
    let all_objects = git(&copy, &["cat-file", "--batch-all-objects", "--batch-check"]);
    assert!(!all_objects.contains(&second.to_string()));
    assert!(!all_objects.contains(&fix_blob.to_string()));
    fs::write(copy.join("code.txt"), "agent edit\n").unwrap();
    assert!(git(&copy, &["diff"]).contains("+agent edit"));
    git(&copy, &["add", "code.txt"]);
    assert!(git(&copy, &["diff", "--cached"]).contains("+agent edit"));
    // Same-size edits immediately after staging must survive Git's stat shortcut.
    fs::write(copy.join("code.txt"), "other edit\n").unwrap();
    assert!(git(&copy, &["diff"]).contains("+other edit"));
    git(&copy, &["stash", "push", "-m", "attempt"]);
    assert_eq!(git(&copy, &["status", "--porcelain"]), "");
    git(&copy, &["stash", "pop"]);
    assert_eq!(fs::read(copy.join("code.txt")).unwrap(), b"other edit\n");
    assert!(git(&copy, &["diff"]).contains("+other edit"));
    assert_eq!(git(&copy, &["log", "--oneline"]).lines().count(), 1);
}

/// Regression: concurrent attempts must reuse one complete synthetic repository.
#[test]
fn regression_synthetic_cache_concurrent_open_is_atomic() {
    let dir = test_dir();
    let path = dir.path().join("repo");
    let (_, first, _, _) = fixture(&path);
    let cache = dir.path().join("cache");
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..4)
            .map(|_| {
                scope.spawn(|| {
                    let src = GitMountSource::open(&path, Some(&first.to_string()))
                        .unwrap()
                        .with_synthetic_head(&cache)
                        .unwrap();
                    let fi = src.lookup("/.git/refs/heads/sandbox", 0).unwrap();
                    let head = src.read(&fi, 100, 0).unwrap();
                    assert!(src.lookup("/.git/index", 0).unwrap().size > 0);
                    head
                })
            })
            .collect();
        let heads: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert!(heads.iter().all(|h| h == &heads[0]));
    });
    assert_eq!(
        fs::read_dir(&cache)
            .unwrap()
            .filter(|e| e.as_ref().unwrap().file_type().unwrap().is_dir())
            .count(),
        1
    );
}

/// Regression: unavailable submodule commits must fail at open, not disappear in readdir.
#[test]
fn regression_synthetic_gitlink_fails_before_cache_publication() {
    let dir = test_dir();
    let repo = Repository::init(dir.path().join("repo")).unwrap();
    let mut builder = repo.treebuilder(None).unwrap();
    builder
        .insert(
            "submodule",
            Oid::from_str("1111111111111111111111111111111111111111").unwrap(),
            0o160000,
        )
        .unwrap();
    let tree = repo.find_tree(builder.write().unwrap()).unwrap();
    let sig = git2::Signature::now("test", "test@example.test").unwrap();
    repo.commit(Some("HEAD"), &sig, &sig, "gitlink", &tree, &[])
        .unwrap();
    let cache = dir.path().join("cache");
    let error = GitMountSource::open(repo.workdir().unwrap(), None)
        .unwrap()
        .with_synthetic_head(&cache)
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("gitlinks"), "{error}");
    assert!(fs::read_dir(&cache)
        .unwrap()
        .all(|e| !e.unwrap().file_type().unwrap().is_dir()));
}

/// Regression: lossy symlink targets change the mounted bytes and make status dirty.
#[test]
fn regression_synthetic_unrepresentable_symlink_target_is_rejected() {
    let dir = test_dir();
    let repo = Repository::init(dir.path().join("repo")).unwrap();
    for target in [&b"bad\xff"[..], &b"bad\0target"[..]] {
        let blob = repo.blob(target).unwrap();
        let mut builder = repo.treebuilder(None).unwrap();
        builder.insert("a-regular", blob, 0o100644).unwrap();
        builder.insert("z-link", blob, 0o120000).unwrap();
        let tree = repo.find_tree(builder.write().unwrap()).unwrap();
        let sig = git2::Signature::now("test", "test@example.test").unwrap();
        let commit = repo.commit(None, &sig, &sig, "link", &tree, &[]).unwrap();
        let error = GitMountSource::open(repo.workdir().unwrap(), Some(&commit.to_string()))
            .unwrap()
            .with_synthetic_head(&dir.path().join("cache"))
            .err()
            .unwrap()
            .to_string();
        assert!(
            error.contains("UTF-8 symlink targets without NUL"),
            "{error}"
        );
    }
}

fn cache_entry(cache: &Path) -> PathBuf {
    fs::read_dir(cache)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.is_dir())
        .unwrap()
}

/// Regression: the source SHA xattr disclosed history lookup keys in synthetic sandboxes.
#[test]
fn regression_synthetic_source_commit_xattr_is_absent_on_every_path() {
    fn check(src: &GitMountSource, path: &str) {
        let fi = src.lookup(path, 0).unwrap();
        assert!(src.list_xattr(&fi).is_empty(), "{path}");
        assert!(src.get_xattr(&fi, COMMIT_XATTR).is_none(), "{path}");
        if fi.mode & ratarmount_core::S_IFMT == ratarmount_core::S_IFDIR {
            for entry in src.list_dirents(path).unwrap() {
                check(
                    src,
                    &format!("{}/{}", path.trim_end_matches('/'), entry.name),
                );
            }
        }
    }
    let dir = test_dir();
    let (repo, first, _, _) = fixture(&dir.path().join("repo"));
    let src = GitMountSource::open(repo.workdir().unwrap(), Some(&first.to_string())).unwrap();
    for path in ["/", "/code.txt", "/sub/code.txt"] {
        let fi = src.lookup(path, 0).unwrap();
        assert_eq!(src.list_xattr(&fi), [COMMIT_XATTR]);
        assert_eq!(
            src.get_xattr(&fi, COMMIT_XATTR),
            Some(first.to_string().into_bytes())
        );
    }
    let src = src.with_synthetic_head(&dir.path().join("cache")).unwrap();
    check(&src, "/");
}

/// Regression: a pre-existing cache could inject alternates, hooks, refs or altered objects.
#[test]
fn regression_synthetic_cache_rejects_untrusted_contents() {
    let dir = test_dir();
    let (repo, first, _, _) = fixture(&dir.path().join("repo"));
    for (i, path) in [
        "objects/info/alternates",
        "packed-refs",
        "hooks/pre-commit",
        "refs/heads/future",
        "HEAD",
        "config",
        "index",
        "refs/heads/sandbox",
        "object",
    ]
    .iter()
    .enumerate()
    {
        let cache = dir.path().join(format!("cache-{i}"));
        let open = || {
            GitMountSource::open(repo.workdir().unwrap(), Some(&first.to_string()))
                .unwrap()
                .with_synthetic_head(&cache)
        };
        drop(open().unwrap());
        let root = cache_entry(&cache);
        let target = if *path == "object" {
            let head = fs::read_to_string(root.join("refs/heads/sandbox")).unwrap();
            root.join(format!("objects/{}/{}", &head[..2], head[2..].trim()))
        } else {
            root.join(path)
        };
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        if target.exists() {
            fs::remove_file(&target).unwrap();
        }
        fs::write(
            target,
            repo.path().join("objects").to_string_lossy().as_bytes(),
        )
        .unwrap();
        assert!(open().is_err(), "served altered {path}");
    }
}

/// Regression: writable roots and symlinked entries allowed cache redirection.
#[cfg(unix)]
#[test]
fn regression_synthetic_cache_refuses_unsafe_root_and_symlinked_entry() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let dir = test_dir();
    let (repo, first, _, _) = fixture(&dir.path().join("repo"));
    let cache = dir.path().join("cache");
    fs::create_dir(&cache).unwrap();
    fs::set_permissions(&cache, fs::Permissions::from_mode(0o755)).unwrap();
    let open = || {
        GitMountSource::open(repo.workdir().unwrap(), Some(&first.to_string()))
            .unwrap()
            .with_synthetic_head(&cache)
    };
    drop(open().unwrap());
    let root = cache_entry(&cache);
    assert_eq!(
        fs::metadata(&cache).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(&root).unwrap().permissions().mode() & 0o777,
        0o700
    );
    fs::set_permissions(&cache, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(open()
        .err()
        .unwrap()
        .to_string()
        .contains("not group/world-writable"));
    fs::set_permissions(&cache, fs::Permissions::from_mode(0o700)).unwrap();
    let other = dir.path().join("other");
    fs::rename(&root, &other).unwrap();
    symlink(&other, &root).unwrap();
    assert!(open().is_err());
    fs::remove_file(&root).unwrap();
    fs::rename(&other, &root).unwrap();
    fs::rename(&cache, &other).unwrap();
    symlink(&other, &cache).unwrap();
    assert!(open().is_err());
}

/// Regression: replacing a validated file or ancestor with a symlink redirected reads.
#[cfg(unix)]
#[test]
fn regression_synthetic_cache_later_symlink_swap_cannot_redirect_reads() {
    use std::os::unix::fs::symlink;
    let dir = test_dir();
    let (repo, first, _, _) = fixture(&dir.path().join("repo"));
    let cache = dir.path().join("cache");
    let src = GitMountSource::open(repo.workdir().unwrap(), Some(&first.to_string()))
        .unwrap()
        .with_synthetic_head(&cache)
        .unwrap();
    let root = cache_entry(&cache);
    let fi = src.lookup("/.git/HEAD", 0).unwrap();
    fs::remove_file(root.join("HEAD")).unwrap();
    symlink(repo.path().join("HEAD"), root.join("HEAD")).unwrap();
    assert!(src.open(&fi, 0).is_err());
    let fi = src.lookup("/.git/refs/heads/sandbox", 0).unwrap();
    fs::rename(root.join("refs"), root.join("old-refs")).unwrap();
    symlink(root.join("old-refs"), root.join("refs")).unwrap();
    assert!(src.open(&fi, 0).is_err());
    // An ordinary replacement is also refused after validation.
    let fi = src.lookup("/.git/config", 0).unwrap();
    fs::write(root.join("config"), b"[core]\n bare=true\n").unwrap();
    assert!(src.open(&fi, 0).is_err());
}

/// Regression: overlay commits could trigger automatic GC/maintenance or fsmonitor hooks.
#[test]
fn regression_synthetic_config_disables_automatic_git_work() {
    let dir = test_dir();
    let (repo, first, _, _) = fixture(&dir.path().join("repo"));
    let src = GitMountSource::open(repo.workdir().unwrap(), Some(&first.to_string()))
        .unwrap()
        .with_synthetic_head(&dir.path().join("cache"))
        .unwrap();
    let bytes = src
        .read(&src.lookup("/.git/config", 0).unwrap(), 4096, 0)
        .unwrap();
    assert_eq!(bytes, synthetic::CONFIG);
    let copy = dir.path().join("copy");
    materialize(&src, "/", &copy);
    let config = git2::Config::open(&copy.join(".git/config")).unwrap();
    assert_eq!(config.get_i64("gc.auto").unwrap(), 0);
    assert!(!config.get_bool("maintenance.auto").unwrap());
    assert!(!config.get_bool("core.fsmonitor").unwrap());
    assert!(config.get_string("core.hooksPath").is_err());
    assert!(src.lookup("/.git/hooks", 0).is_none());
}

/// Regression: commit times after 2038 wrapped to negative index mtimes.
#[test]
fn regression_synthetic_future_index_timestamp_is_clamped() {
    let dir = test_dir();
    let (repo, first, _, _) = fixture(&dir.path().join("repo"));
    let time = i32::MAX as i64 + 86400;
    let sig = git2::Signature::new("test", "test@example.test", &git2::Time::new(time, 0)).unwrap();
    let future = repo
        .commit(
            None,
            &sig,
            &sig,
            "future date",
            &repo.find_commit(first).unwrap().tree().unwrap(),
            &[],
        )
        .unwrap();
    let src = GitMountSource::open(repo.workdir().unwrap(), Some(&future.to_string()))
        .unwrap()
        .with_synthetic_head(&dir.path().join("cache"))
        .unwrap();
    let copy = dir.path().join("copy");
    materialize(&src, "/", &copy);
    let synthetic = Repository::open(&copy).unwrap();
    assert_eq!(
        synthetic
            .head()
            .unwrap()
            .peel_to_commit()
            .unwrap()
            .time()
            .seconds(),
        time
    );
    for entry in synthetic.index().unwrap().iter() {
        assert_eq!(entry.mtime.seconds(), i32::MAX);
        assert_eq!(entry.ctime.seconds(), i32::MAX);
        assert_eq!(entry.flags & 0x8000, 0);
    }
    assert_eq!(src.lookup("/code.txt", 0).unwrap().mtime, time as f64);
    if Command::new("git").arg("--version").output().is_err() {
        eprintln!("skip: git CLI missing; index timestamp assertions ran with git2");
        return;
    }
    assert_eq!(git(&copy, &["status", "--porcelain"]), "");
}

/// Regression: an agent with a different uid needs explicit trust of the mounted path.
#[test]
fn regression_synthetic_different_uid_requires_safe_directory() {
    let dir = test_dir();
    let (repo, first, _, _) = fixture(&dir.path().join("repo"));
    let src = GitMountSource::open(repo.workdir().unwrap(), Some(&first.to_string()))
        .unwrap()
        .with_synthetic_head(&dir.path().join("cache"))
        .unwrap();
    for path in ["/", "/code.txt", "/.git", "/.git/HEAD"] {
        assert_eq!(
            src.lookup(path, 0).unwrap().uid,
            ratarmount_core::effective_uid()
        );
    }
    if Command::new("git").arg("--version").output().is_err() {
        eprintln!("skip: git CLI missing; mounted ownership assertions ran");
        return;
    }
    let copy = dir.path().join("copy");
    materialize(&src, "/", &copy);
    let run = |safe: &str| {
        Command::new("git")
            .arg("-C")
            .arg(&copy)
            .args(["-c", "safe.directory=", "-c", safe, "status", "--porcelain"])
            .env("GIT_TEST_ASSUME_DIFFERENT_OWNER", "1")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .output()
            .unwrap()
    };
    let rejected = run("safe.directory=");
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("dubious ownership"));
    let trusted = run(&format!("safe.directory={}", copy.display()));
    assert!(
        trusted.status.success(),
        "{}",
        String::from_utf8_lossy(&trusted.stderr)
    );
    assert!(trusted.stdout.is_empty());
}

/// Regression: a malformed file-mode entry must not admit a source commit into the cache allowlist.
#[test]
fn regression_synthetic_file_entry_cannot_reference_commit_object() {
    let dir = test_dir();
    let (repo, first, _, _) = fixture(&dir.path().join("repo"));
    let mut raw = b"100644 disguised-commit\0".to_vec();
    raw.extend_from_slice(first.as_bytes());
    let tree = repo.odb().unwrap().write(ObjectType::Tree, &raw).unwrap();
    let sig = git2::Signature::now("test", "test@example.test").unwrap();
    let commit = repo
        .commit(
            None,
            &sig,
            &sig,
            "malformed tree",
            &repo.find_tree(tree).unwrap(),
            &[],
        )
        .unwrap();
    let cache = dir.path().join("cache");
    let error = GitMountSource::open(repo.workdir().unwrap(), Some(&commit.to_string()))
        .unwrap()
        .with_synthetic_head(&cache)
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("unexpected Git object type"), "{error}");
    assert_eq!(fs::read_dir(cache).unwrap().count(), 0);
}
