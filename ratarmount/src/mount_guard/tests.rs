//! Unit tests: an in-memory `FakeFs` (with casefold aliases, mount ids and mountinfo)
//! drives the pure logic; `RealFs` tests run on temporary directories.

use super::*;
use clap::Parser;
use std::collections::BTreeMap;
use std::ffi::OsString;
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt;
use std::os::unix::ffi::OsStringExt;

// ---------------------------------------------------------------------------
// FakeFs
// ---------------------------------------------------------------------------

#[derive(Clone)]
enum K {
    Dir,
    File,
    Link(PathBuf),
}

#[derive(Clone)]
struct N {
    k: K,
    ino: u64,
    dev: u64,
    mnt: u64,
}

struct FakeFs {
    nodes: BTreeMap<PathBuf, N>,
    aliases: BTreeMap<PathBuf, PathBuf>,
    cwd: PathBuf,
    mountinfo: Option<Vec<u8>>,
    linux: bool,
    mnt_ids: bool,
    panic_cwd: bool,
    /// Paths whose `mount_id` is unavailable (statx and handle both fail).
    no_mnt: Vec<PathBuf>,
    next: u64,
}

const ROOT_MI: &str = "1 0 8:1 / / rw - ext4 /dev/sda1 rw";

fn mi(lines: &[&str]) -> Option<Vec<u8>> {
    Some(lines.join("\n").into_bytes())
}

impl FakeFs {
    fn new() -> Self {
        let mut f = FakeFs {
            nodes: BTreeMap::new(),
            aliases: BTreeMap::new(),
            cwd: PathBuf::from("/P"),
            mountinfo: mi(&[ROOT_MI]),
            linux: true,
            mnt_ids: true,
            panic_cwd: false,
            no_mnt: Vec::new(),
            next: 100,
        };
        f.nodes.insert(
            PathBuf::from("/"),
            N {
                k: K::Dir,
                ino: 2,
                dev: 1,
                mnt: 1,
            },
        );
        f
    }

    /// The standard tree: `/P/{B/{sub/deep},C}`, cwd `/P`.
    fn std() -> Self {
        let mut f = Self::new();
        f.dir("/P/B/sub/deep");
        f.dir("/P/C");
        f
    }

    fn fresh(&mut self) -> u64 {
        self.next += 1;
        self.next
    }

    fn key(&self, p: &Path) -> PathBuf {
        for (alt, real) in &self.aliases {
            if let Ok(rest) = p.strip_prefix(alt) {
                return real.join(rest);
            }
        }
        p.to_path_buf()
    }

    fn dir(&mut self, p: &str) {
        let mut cur = PathBuf::new();
        for c in Path::new(p).components() {
            cur.push(c);
            if !self.nodes.contains_key(&cur) {
                let parent = cur.parent().map(Path::to_path_buf).unwrap_or_default();
                let (dev, mnt) = self.nodes.get(&parent).map_or((1, 1), |n| (n.dev, n.mnt));
                let ino = self.fresh();
                self.nodes.insert(
                    cur.clone(),
                    N {
                        k: K::Dir,
                        ino,
                        dev,
                        mnt,
                    },
                );
            }
        }
    }

    fn file(&mut self, p: &str) {
        self.dir(Path::new(p).parent().unwrap().to_str().unwrap());
        let ino = self.fresh();
        self.nodes.insert(
            PathBuf::from(p),
            N {
                k: K::File,
                ino,
                dev: 1,
                mnt: 1,
            },
        );
    }

    fn link(&mut self, p: &str, target: &str) {
        self.dir(Path::new(p).parent().unwrap().to_str().unwrap());
        let ino = self.fresh();
        self.nodes.insert(
            PathBuf::from(p),
            N {
                k: K::Link(PathBuf::from(target)),
                ino,
                dev: 1,
                mnt: 1,
            },
        );
    }

    fn remove(&mut self, p: &str) {
        let p = PathBuf::from(p);
        self.nodes.retain(|k, _| !k.starts_with(&p));
    }

    /// A bind mount: `dst` becomes a copy of the `src` subtree (same inodes) in mount `mnt`.
    fn bind(&mut self, src: &str, dst: &str, mnt: u64) {
        self.remove(dst);
        self.dir(Path::new(dst).parent().unwrap().to_str().unwrap());
        let copies: Vec<(PathBuf, N)> = self
            .nodes
            .iter()
            .filter(|(k, _)| k.starts_with(src))
            .map(|(k, n)| {
                let mut n = n.clone();
                n.mnt = mnt;
                (Path::new(dst).join(k.strip_prefix(src).unwrap()), n)
            })
            .collect();
        self.nodes.extend(copies);
    }

    /// A fresh tmpfs mounted at `dst`.
    fn tmpfs(&mut self, dst: &str, mnt: u64, dev: u64) {
        self.remove(dst);
        self.dir(Path::new(dst).parent().unwrap().to_str().unwrap());
        let ino = self.fresh();
        self.nodes.insert(
            PathBuf::from(dst),
            N {
                k: K::Dir,
                ino,
                dev,
                mnt,
            },
        );
    }

    fn alias(&mut self, alt: &str, real: &str) {
        self.aliases.insert(PathBuf::from(alt), PathBuf::from(real));
    }
}

impl FsIdentity for FakeFs {
    fn cwd(&self) -> io::Result<PathBuf> {
        assert!(!self.panic_cwd, "cwd() must not be called");
        Ok(self.cwd.clone())
    }
    fn lstat(&self, p: &Path) -> io::Result<Node> {
        match self.nodes.get(&self.key(p)) {
            None => Err(io::ErrorKind::NotFound.into()),
            Some(N { k: K::Dir, .. }) => Ok(Node::Dir),
            Some(N { k: K::File, .. }) => Ok(Node::Other),
            Some(N { k: K::Link(t), .. }) => Ok(Node::Symlink(t.clone())),
        }
    }
    fn stat(&self, p: &Path) -> io::Result<Node> {
        let mut cur = p.to_path_buf();
        for _ in 0..40 {
            match self.lstat(&cur)? {
                Node::Symlink(t) => {
                    let mut n = if t.is_absolute() {
                        PathBuf::from("/")
                    } else {
                        cur.parent().unwrap_or(Path::new("/")).to_path_buf()
                    };
                    for c in t.components() {
                        match c {
                            Component::ParentDir => {
                                n.pop();
                            }
                            Component::Normal(x) => n.push(x),
                            _ => {}
                        }
                    }
                    cur = n;
                }
                n => return Ok(n),
            }
        }
        Err(io::Error::other("loop"))
    }
    fn dir_id(&self, p: &Path) -> Option<(u64, u64)> {
        match self.nodes.get(&self.key(p)) {
            Some(N {
                k: K::Dir,
                dev,
                ino,
                ..
            }) => Some((*dev, *ino)),
            _ => None,
        }
    }
    fn mount_id(&self, p: &Path) -> Option<u64> {
        if !self.linux || !self.mnt_ids || self.no_mnt.iter().any(|n| n == p) {
            return None;
        }
        self.nodes.get(&self.key(p)).map(|n| n.mnt)
    }
    fn mountinfo_bytes(&self) -> Option<Vec<u8>> {
        if self.linux {
            self.mountinfo.clone()
        } else {
            None
        }
    }
}

fn run_ov<F: FsIdentity>(fs: &F, mp: &str, cands: &[&str], ov: Option<&str>) -> Result<(), String> {
    let c: Vec<PathBuf> = cands.iter().map(PathBuf::from).collect();
    let bases = bases_now(fs, &c, ov.map(|w| (Path::new(w), false)))?;
    check_mount_point(fs, Path::new(mp), &bases, Hint::default())
}

fn run<F: FsIdentity>(fs: &F, mp: &str, cands: &[&str]) -> Result<(), String> {
    run_ov(fs, mp, cands, None)
}

#[track_caller]
fn refused(r: Result<(), String>, needles: &[&str]) -> String {
    let msg = r.expect_err("expected a refusal");
    for n in needles {
        assert!(msg.contains(n), "message {msg:?} lacks {n:?}");
    }
    msg
}

// ---------------------------------------------------------------------------
// Resolver
// ---------------------------------------------------------------------------

#[test]
fn regression_mount_in_base_resolve_existing_dir_exact() {
    let fs = FakeFs::std();
    let t = resolve(&fs, Path::new("/P/B")).unwrap();
    assert!(t.exact());
    assert_eq!(t.full, Path::new("/P/B"));
    assert_eq!(t.anchor, Path::new("/P/B"));
}

#[test]
fn regression_mount_in_base_resolve_missing_tail_lexical() {
    let fs = FakeFs::std();
    let t = resolve(&fs, Path::new("B/new/deeper")).unwrap();
    assert_eq!(t.full, Path::new("/P/B/new/deeper"));
    assert_eq!(t.anchor, Path::new("/P/B"));
    assert_eq!(t.tail, Path::new("new/deeper"));
}

#[test]
fn regression_mount_in_base_resolve_symlink_component() {
    let mut fs = FakeFs::std();
    fs.link("/P/L", "B");
    let t = resolve(&fs, Path::new("L/sub")).unwrap();
    assert_eq!(t.full, Path::new("/P/B/sub"));
}

#[test]
fn regression_mount_in_base_resolve_dangling_symlink_follows_target() {
    let mut fs = FakeFs::std();
    fs.link("/P/B/L3", "../ov");
    let t = resolve(&fs, Path::new("B/L3/mnt")).unwrap();
    assert_eq!(t.full, Path::new("/P/ov/mnt"));
    assert_eq!(t.anchor, Path::new("/P"));
}

#[test]
fn regression_mount_in_base_resolve_dotdot_after_missing_pops() {
    let fs = FakeFs::std();
    let t = resolve(&fs, Path::new("new/../B/mnt")).unwrap();
    assert_eq!(t.full, Path::new("/P/B/mnt"));
}

#[test]
fn regression_mount_in_base_resolve_dotdot_after_symlink_is_physical() {
    let mut fs = FakeFs::std();
    fs.link("/P/L5", "C");
    // L5/.. is the parent of the link target (/P), not of the link.
    let t = resolve(&fs, Path::new("B/sub/../../L5/../mnt")).unwrap();
    assert_eq!(t.full, Path::new("/P/mnt"));
    fs.link("/P/B/L6", "/P/C/x");
    fs.dir("/P/C/x");
    let t = resolve(&fs, Path::new("B/L6/../mnt")).unwrap();
    assert_eq!(t.full, Path::new("/P/C/mnt"));
}

#[test]
fn regression_mount_in_base_resolve_dotdot_at_root_stays() {
    let fs = FakeFs::std();
    let t = resolve(&fs, Path::new("/../../P")).unwrap();
    assert_eq!(t.full, Path::new("/P"));
}

#[test]
fn regression_mount_in_base_resolve_absolute_symlink_target_restarts() {
    let mut fs = FakeFs::std();
    fs.link("/P/A", "/P/B/sub");
    let t = resolve(&fs, Path::new("A/deep")).unwrap();
    assert_eq!(t.full, Path::new("/P/B/sub/deep"));
}

#[test]
fn regression_mount_in_base_resolve_relative_uses_cwd_lazily() {
    let mut fs = FakeFs::std();
    fs.panic_cwd = true;
    let t = resolve(&fs, Path::new("/P/B")).unwrap();
    assert!(t.exact());
}

#[test]
fn regression_mount_in_base_resolve_file_component_is_not_a_directory() {
    let mut fs = FakeFs::std();
    fs.file("/P/F");
    assert!(matches!(
        resolve(&fs, Path::new("/P/F/mnt")),
        Err(ResolveError::NotADirectory(_))
    ));
    assert!(matches!(
        resolve(&fs, Path::new("/P/F")),
        Err(ResolveError::NotADirectory(_))
    ));
}

#[test]
fn regression_mount_in_base_resolve_symlink_loop_is_too_many_links() {
    let mut fs = FakeFs::std();
    fs.link("/P/X", "Y");
    fs.link("/P/Y", "X");
    assert!(matches!(
        resolve(&fs, Path::new("/P/X/mnt")),
        Err(ResolveError::TooManyLinks(_))
    ));
}

#[test]
fn regression_mount_in_base_resolve_symlink_loop_real_fs() {
    let td = tempfile::tempdir().unwrap();
    let root = td.path().canonicalize().unwrap();
    std::os::unix::fs::symlink("y", root.join("x")).unwrap();
    std::os::unix::fs::symlink("x", root.join("y")).unwrap();
    assert!(matches!(
        resolve(&RealFs::new(), &root.join("x/mnt")),
        Err(ResolveError::TooManyLinks(_))
    ));
}

#[test]
fn regression_mount_in_base_resolve_matches_std_create_dir_all() {
    let td = tempfile::tempdir().unwrap();
    let root = td.path().canonicalize().unwrap();
    let fs = RealFs::with_cwd(root.clone());
    std::fs::create_dir_all(root.join("real/sub")).unwrap();
    std::os::unix::fs::symlink("real", root.join("L")).unwrap();
    // Dangling link whose target is created first by `create_dir_all` of the target.
    std::os::unix::fs::symlink("later", root.join("D")).unwrap();
    // A dangling link is followed once its target exists (HEAD's `create_dir_all` fails
    // with EEXIST on a dangling last component, so the target is created first).
    std::fs::create_dir(root.join("later")).unwrap();
    for given in [
        "D/x",
        "a/b/c",
        "a/../b",
        "L/../m",
        "L/sub/m",
        "real/",
        "real/./sub/n",
        "missing/../real/sub/z",
    ] {
        let predicted = resolve(&fs, Path::new(given)).unwrap().full;
        std::fs::create_dir_all(root.join(given)).unwrap();
        assert_eq!(
            root.join(given).canonicalize().unwrap(),
            predicted,
            "given {given}"
        );
    }
}

#[test]
fn regression_mount_in_base_resolve_existing_equals_canonicalize() {
    let td = tempfile::tempdir().unwrap();
    let root = td.path().canonicalize().unwrap();
    std::fs::create_dir_all(root.join("a/b")).unwrap();
    std::os::unix::fs::symlink("a/b", root.join("L")).unwrap();
    std::os::unix::fs::symlink("../L", root.join("a/M")).unwrap();
    let fs = RealFs::with_cwd(root.clone());
    for given in ["a/b", "L", "a/M", "a/M/..", "L/../b"] {
        let t = resolve(&fs, Path::new(given)).unwrap();
        assert_eq!(
            root.join(given).canonicalize().unwrap(),
            t.full,
            "given {given}"
        );
    }
}

#[test]
fn regression_mount_in_base_resolve_predicts_post_overlay_resolution() {
    // A1: cwd P, folder C, absent ov, L -> ov: `-w ov C L/../mnt` resolves to P/mnt.
    let td = tempfile::tempdir().unwrap();
    let root = td.path().canonicalize().unwrap();
    std::fs::create_dir_all(root.join("C")).unwrap();
    std::os::unix::fs::symlink("ov", root.join("L")).unwrap();
    let fs = RealFs::with_cwd(root.clone());
    let before = resolve(&fs, Path::new("L/../mnt")).unwrap().full;
    std::fs::create_dir_all(root.join("ov")).unwrap();
    let after = resolve(&fs, Path::new("L/../mnt")).unwrap().full;
    // After `ov` exists, `L/..` is the physical parent of `ov`, the same place.
    assert_eq!(before, root.join("mnt"));
    assert_eq!(after, root.join("mnt"));
}

// ---------------------------------------------------------------------------
// Lexical relations
// ---------------------------------------------------------------------------

#[test]
fn regression_mount_in_base_lexical_equal() {
    let fs = FakeFs::std();
    refused(
        run(&fs, "B", &["B"]),
        &["is the folder being mounted", "B.mounted"],
    );
}

#[test]
fn regression_mount_in_base_lexical_inside() {
    let fs = FakeFs::std();
    refused(
        run(&fs, "B/mnt", &["B"]),
        &["inside the folder being mounted"],
    );
}

#[test]
fn regression_mount_in_base_lexical_deep_inside() {
    let fs = FakeFs::std();
    refused(
        run(&fs, "B/a/b/mnt", &["B"]),
        &["inside the folder being mounted"],
    );
}

#[test]
fn regression_mount_in_base_lexical_contains_ancestor_of_base() {
    let fs = FakeFs::std();
    refused(
        run(&fs, "/P", &["B"]),
        &["would cover the folder being mounted"],
    );
    refused(run(&fs, "/", &["B"]), &["would cover"]);
}

#[test]
fn regression_mount_in_base_lexical_contains_trailing_slash() {
    let fs = FakeFs::std();
    refused(run(&fs, "/P/", &["B/"]), &["would cover"]);
    refused(run(&fs, "B/", &["B"]), &["is the folder being mounted"]);
}

#[test]
fn regression_mount_in_base_lexical_sibling_and_prefix_not_conflict() {
    let mut fs = FakeFs::std();
    fs.dir("/P/B.mounted");
    fs.dir("/P/Bx");
    fs.dir("/P/B2");
    for mp in ["B.mounted", "Bx", "B2", "B.mounted/m", "C"] {
        run(&fs, mp, &["B"]).unwrap();
    }
}

#[test]
fn regression_mount_in_base_lexical_missing_sibling_not_conflict() {
    let fs = FakeFs::std();
    run(&fs, "new/deep/mnt", &["B"]).unwrap();
}

#[test]
fn regression_mount_in_base_lexical_union_second_folder() {
    let fs = FakeFs::std();
    refused(
        run(&fs, "B/mnt", &["C", "B"]),
        &["inside the folder being mounted"],
    );
}

#[test]
fn regression_mount_in_base_lexical_overlay_equal_inside_contains() {
    let mut fs = FakeFs::std();
    fs.dir("/P/ov");
    refused(
        run_ov(&fs, "ov", &["C"], Some("ov")),
        &["is the write-overlay directory (-w)"],
    );
    refused(
        run_ov(&fs, "ov/mnt", &["C"], Some("ov")),
        &["inside the write-overlay directory (-w)"],
    );
    refused(run_ov(&fs, "/P", &["C"], Some("ov")), &["would cover"]);
}

#[test]
fn regression_mount_in_base_lexical_overlay_absent_inside_contains_sibling() {
    let fs = FakeFs::std();
    refused(
        run_ov(&fs, "ov/mnt", &["C"], Some("ov")),
        &["inside the write-overlay directory"],
    );
    refused(run_ov(&fs, "/P", &["C"], Some("ov/x")), &["would cover"]);
    run_ov(&fs, "mnt", &["C"], Some("ov")).unwrap();
}

#[test]
fn regression_mount_in_base_lexical_both_missing_under_common_anchor() {
    let fs = FakeFs::std();
    refused(
        run_ov(&fs, "new/ov/mnt", &["C"], Some("new/ov")),
        &["inside the write-overlay directory"],
    );
}

#[test]
fn regression_mount_in_base_lexical_temp_overlay_not_a_base_early() {
    let fs = FakeFs::std();
    let mut args = Args::try_parse_from(["ratarmount", "-w", ":temp:", "C", "B/mnt"]).unwrap();
    args.write_overlay = Some(PathBuf::from(":temp:"));
    let plan = plan_mount_point(
        &fs,
        &args,
        Some(PathBuf::from("mnt")),
        &[PathBuf::from("C")],
    )
    .unwrap();
    assert!(plan.overlay_temp);
}

#[test]
fn regression_mount_in_base_lexical_archive_and_url_never_conflict() {
    let mut fs = FakeFs::std();
    fs.file("/P/B/x.tar");
    run(&fs, "B/mnt", &["B/x.tar", "https://host/B"]).unwrap();
    run(&fs, "mnt", &["https://host/B/mnt"]).unwrap();
}

#[test]
fn regression_mount_in_base_lexical_symlink_ancestor_inside() {
    let mut fs = FakeFs::std();
    fs.link("/P/L", "B");
    refused(
        run(&fs, "L/mnt", &["B"]),
        &["inside the folder", "resolves to /P/B/mnt"],
    );
}

#[test]
fn regression_mount_in_base_lexical_symlink_input_base() {
    let mut fs = FakeFs::std();
    fs.link("/P/L", "B");
    refused(run(&fs, "B/mnt", &["L"]), &["inside the folder"]);
}

#[test]
fn regression_mount_in_base_lexical_dangling_symlink_mount_point_into_overlay_inside() {
    let mut fs = FakeFs::std();
    fs.link("/P/L", "ov");
    refused(
        run_ov(&fs, "L/mnt", &["C"], Some("ov")),
        &["inside the write-overlay directory"],
    );
    refused(
        run_ov(&fs, "L", &["C"], Some("ov")),
        &["is the write-overlay directory"],
    );
}

#[test]
fn regression_mount_in_base_lexical_overlay_dependent_dotdot_layout_ok() {
    let mut fs = FakeFs::std();
    fs.link("/P/L2", "ov");
    run_ov(&fs, "L2/../mnt", &["C"], Some("ov")).unwrap();
}

#[test]
fn regression_mount_in_base_lexical_overlay_dependent_dangling_link_in_base_ok() {
    let mut fs = FakeFs::std();
    fs.link("/P/B/L3", "../ov");
    run_ov(&fs, "B/L3/mnt", &["B"], Some("ov/data")).unwrap();
}

#[test]
fn regression_mount_in_base_lexical_dangling_symlink_into_base_refused() {
    let mut fs = FakeFs::std();
    fs.link("/P/L4", "B/new");
    refused(run(&fs, "L4/mnt", &["B"]), &["inside the folder"]);
}

#[test]
fn regression_mount_in_base_lexical_first_conflict_in_base_order_reported() {
    let fs = FakeFs::std();
    let msg = refused(
        run(&fs, "B/mnt", &["C", "B", "B/sub"]),
        &["inside the folder"],
    );
    assert!(msg.contains("folder being mounted B;"), "{msg}");
}

#[test]
fn regression_mount_in_base_lexical_dotdot_escape_via_missing() {
    let fs = FakeFs::std();
    refused(run(&fs, "new/../B/mnt", &["B"]), &["inside the folder"]);
}

// ---------------------------------------------------------------------------
// Candidates, bases, decisive
// ---------------------------------------------------------------------------

#[test]
fn regression_mount_in_base_bases_now_only_directories() {
    let mut fs = FakeFs::std();
    fs.file("/P/x.tar");
    fs.link("/P/L", "B");
    fs.dir("/P/R/.git");
    let cands: Vec<PathBuf> = ["x.tar", "missing", "B", "L", "R@HEAD"]
        .iter()
        .map(PathBuf::from)
        .collect();
    let bases = bases_now(&fs, &cands, None).unwrap();
    let given: Vec<_> = bases.iter().map(|b| b.given.to_str().unwrap()).collect();
    assert_eq!(given, ["B", "L", "R"]);
}

#[test]
fn regression_mount_in_base_bases_reclassified_at_decisive_check() {
    let mut fs = FakeFs::std();
    fs.file("/P/x.tar");
    let args = Args::try_parse_from(["ratarmount", "x.tar", "Z", "Z/mnt"]).unwrap();
    let inputs = vec![PathBuf::from("x.tar"), PathBuf::from("Z")];
    let plan = plan_mount_point(&fs, &args, Some(PathBuf::from("Z/mnt")), &inputs).unwrap();
    fs.dir("/P/Z");
    fs.file("/P/Z/x.tar.index.sqlite");
    let msg = decisive_check(&fs, &plan, None).unwrap_err();
    assert!(msg.contains("inside the folder being mounted Z"), "{msg}");
}

#[test]
fn regression_mount_in_base_candidates_keep_missing_and_file_inputs() {
    let mut fs = FakeFs::std();
    fs.file("/P/x.tar");
    let args = Args::try_parse_from(["ratarmount", "x.tar"]).unwrap();
    let inputs = vec![
        PathBuf::from("x.tar"),
        PathBuf::from("missing"),
        PathBuf::from("https://host/B"),
    ];
    let plan = plan_mount_point(&fs, &args, Some(PathBuf::from("mnt")), &inputs).unwrap();
    assert_eq!(
        plan.candidates,
        [PathBuf::from("x.tar"), PathBuf::from("missing")]
    );
}

#[test]
fn regression_mount_in_base_decisive_uses_actual_temp_overlay() {
    let mut fs = FakeFs::std();
    fs.dir("/tmp/ratarmount-write-overlay.abc");
    let mut args = Args::try_parse_from(["ratarmount", "C", "/tmp"]).unwrap();
    args.write_overlay = Some(PathBuf::from(":temp:"));
    let inputs = vec![PathBuf::from("C")];
    let plan = plan_mount_point(&fs, &args, Some(PathBuf::from("/tmp")), &inputs).unwrap();
    let ov = Path::new("/tmp/ratarmount-write-overlay.abc");
    let msg = decisive_check(&fs, &plan, Some(ov)).unwrap_err();
    assert!(
        msg.contains("would cover the temporary write overlay"),
        "{msg}"
    );
    let plan = plan_mount_point(&fs, &args, Some(PathBuf::from("/tmp/other")), &inputs).unwrap();
    decisive_check(&fs, &plan, Some(ov)).unwrap();
}

#[test]
fn regression_mount_in_base_decisive_same_verdict_when_nothing_changed() {
    let fs = FakeFs::std();
    let args = Args::try_parse_from(["ratarmount", "B"]).unwrap();
    let inputs = vec![PathBuf::from("B")];
    for mp in ["mnt", "B.mounted", "C/m"] {
        let plan = plan_mount_point(&fs, &args, Some(PathBuf::from(mp)), &inputs).unwrap();
        decisive_check(&fs, &plan, None).unwrap();
    }
}

// ---------------------------------------------------------------------------
// D1: @REV
// ---------------------------------------------------------------------------

#[test]
fn regression_mount_in_base_rev_literal_created_later_refused() {
    let mut fs = FakeFs::std();
    fs.dir("/P/B/.git");
    let args = Args::try_parse_from(["ratarmount", "B@HEAD"]).unwrap();
    let inputs = vec![PathBuf::from("B@HEAD")];
    // B@HEAD absent: only the repository prefix B is a base; the mount point is outside.
    let plan = plan_mount_point(&fs, &args, Some(PathBuf::from("B@HEAD/mnt")), &inputs).unwrap();
    // B@HEAD/mnt is outside of B lexically, so the early check passes.
    fs.dir("/P/B@HEAD");
    let msg = decisive_check(&fs, &plan, None).unwrap_err();
    assert!(msg.contains("B@HEAD"), "{msg}");
    assert!(msg.contains("inside the folder being mounted"), "{msg}");
}

#[test]
fn regression_mount_in_base_rev_stripped_repo_is_base() {
    let mut fs = FakeFs::std();
    fs.dir("/P/B/.git");
    let msg = refused(run(&fs, "B/mnt", &["B@HEAD"]), &["inside the folder"]);
    assert!(msg.contains("folder being mounted B;"), "{msg}");
}

#[test]
fn regression_mount_in_base_rev_non_git_prefix_not_base() {
    let mut fs = FakeFs::std();
    fs.file("/P/foo@bar");
    fs.dir("/P/foo");
    run(&fs, "foo/mnt", &["foo@bar"]).unwrap();
}

#[test]
fn regression_mount_in_base_rev_existing_literal_wins_over_repo_prefix() {
    // The literal directory exists, so the factory serves it, not the repository B.
    let mut fs = FakeFs::std();
    fs.dir("/P/B/.git");
    fs.dir("/P/B@HEAD");
    run(&fs, "B/mnt", &["B@HEAD"]).unwrap();
    refused(run(&fs, "B@HEAD/mnt", &["B@HEAD"]), &["inside the folder"]);
}

/// Regression: an existing archive `B@archive.tar` next to a repository `B` was refused as
/// the folder `B` (the factory gives an existing literal path precedence).
#[test]
fn regression_mount_in_base_rev_existing_file_operand_is_not_split() {
    let mut fs = FakeFs::std();
    fs.dir("/P/B/.git");
    fs.file("/P/B@archive.tar");
    run(&fs, "B/mnt", &["B@archive.tar"]).unwrap();
    run(&fs, "/P/B/mnt", &["/P/B@archive.tar"]).unwrap();
    // A dangling symlink does not exist (`Path::exists`), so the split still applies.
    let mut fs = FakeFs::std();
    fs.dir("/P/B/.git");
    fs.link("/P/B@HEAD", "/nowhere");
    refused(run(&fs, "B/mnt", &["B@HEAD"]), &["inside the folder"]);
}

/// Regression: a bare repository with `objects -> ../objects` opened as `B@HEAD` had no
/// base (the guard used `lstat`, the factory follows symlinks).
#[test]
fn regression_mount_in_base_rev_symlinked_bare_repo_is_base() {
    let mut fs = FakeFs::std();
    fs.dir("/P/shared/objects");
    fs.dir("/P/B");
    fs.file("/P/B/HEAD");
    fs.dir("/P/B/refs");
    fs.link("/P/B/objects", "../shared/objects");
    refused(run(&fs, "B/mnt", &["B@HEAD"]), &["inside the folder"]);
    // `.git` as a dangling symlink is not `exists()`.
    let mut fs = FakeFs::std();
    fs.link("/P/B/.git", "/nowhere");
    run(&fs, "B/mnt", &["B@HEAD"]).unwrap();
}

// ---------------------------------------------------------------------------
// Views
// ---------------------------------------------------------------------------

fn mi_lines(extra: &[&str]) -> Option<Vec<u8>> {
    let mut v = vec![ROOT_MI];
    v.extend_from_slice(extra);
    mi(&v)
}

#[test]
fn regression_mount_in_base_views_s1_subtree_bind() {
    let mut fs = FakeFs::std();
    fs.bind("/P/B/sub", "/alias", 101);
    fs.mountinfo = mi_lines(&["101 1 8:1 /P/B/sub /alias rw - ext4 /dev/sda1 rw"]);
    let msg = refused(
        run(&fs, "/alias/mnt", &["/P/B"]),
        &["inside the folder", "also visible at /P/B/sub/mnt"],
    );
    assert!(msg.contains("through the bind mount of"), "{msg}");
}

#[test]
fn regression_mount_in_base_views_hidden_overmount_a2() {
    for order in [true, false] {
        let mut fs = FakeFs::std();
        fs.dir("/P/Cx");
        fs.dir("/alias");
        fs.bind("/P/B/sub", "/alias", 102);
        let l101 = "101 1 8:1 /P/Cx /alias/deep rw - ext4 /dev/sda1 rw";
        let l102 = "102 1 8:1 /P/B/sub /alias rw - ext4 /dev/sda1 rw";
        fs.mountinfo = if order {
            mi_lines(&[l101, l102])
        } else {
            mi_lines(&[l102, l101])
        };
        refused(
            run(&fs, "/alias/deep/mnt", &["/P/B"]),
            &["inside the folder being mounted /P/B"],
        );
    }
}

#[test]
fn regression_mount_in_base_views_hidden_mount_alone_is_not_an_alias() {
    let mut fs = FakeFs::std();
    fs.dir("/alias/deep");
    fs.bind("/P/C", "/alias/deep", 101);
    fs.mountinfo = mi_lines(&["101 1 8:1 /P/C /alias/deep rw - ext4 /dev/sda1 rw"]);
    run(&fs, "/alias/deep/mnt", &["/P/B"]).unwrap();
}

#[test]
fn regression_mount_in_base_views_descendant_mount_under_base_c2() {
    let mut fs = FakeFs::std();
    fs.dir("/C");
    fs.bind("/C", "/P/B/sub", 101);
    fs.mountinfo = mi_lines(&["101 1 8:1 /C /P/B/sub rw - ext4 /dev/sda1 rw"]);
    let r = run(&fs, "/C/mnt", &["/P/B"]);
    let msg = refused(r, &["inside the folder", "also visible at /P/B/sub/mnt"]);
    assert!(msg.contains("bind mount of /C at /P/B/sub"), "{msg}");
}

#[test]
fn regression_mount_in_base_views_descendant_mount_other_device_c2() {
    let mut fs = FakeFs::std();
    fs.tmpfs("/C", 101, 40);
    fs.bind("/C", "/P/B/sub", 102);
    fs.mountinfo = mi_lines(&[
        "101 1 0:40 / /C rw - tmpfs tmpfs rw",
        "102 1 0:40 / /P/B/sub rw - tmpfs tmpfs rw",
    ]);
    refused(
        run(&fs, "/C/mnt", &["/P/B"]),
        &["also visible at /P/B/sub/mnt"],
    );
}

#[test]
fn regression_mount_in_base_views_chroot_tree_tmp_bind_refused() {
    let mut fs = FakeFs::new();
    fs.dir("/srv/chroot/tmp");
    fs.tmpfs("/tmp", 101, 40);
    fs.bind("/tmp", "/srv/chroot/tmp", 102);
    fs.mountinfo = mi_lines(&[
        "101 1 0:40 / /tmp rw - tmpfs tmpfs rw",
        "102 1 0:40 / /srv/chroot/tmp rw - tmpfs tmpfs rw",
    ]);
    refused(
        run(&fs, "/tmp/view", &["/srv/chroot"]),
        &["also visible at /srv/chroot/tmp/view"],
    );
}

fn c3_fs() -> FakeFs {
    let mut fs = FakeFs::std();
    fs.dir("/C");
    fs.bind("/P", "/alias", 101);
    fs.bind("/C", "/alias/B", 102);
    fs.mountinfo = mi_lines(&[
        "101 1 8:1 /P /alias rw - ext4 /dev/sda1 rw",
        "102 1 8:1 /C /alias/B rw - ext4 /dev/sda1 rw",
    ]);
    fs
}

#[test]
fn regression_mount_in_base_views_overmount_view_allowed_c3() {
    run(&c3_fs(), "/alias/B/mnt", &["/P/B"]).unwrap();
}

#[test]
fn regression_mount_in_base_views_contains_via_bind_of_parent() {
    let mut fs = FakeFs::std();
    fs.bind("/P", "/alias", 101);
    fs.mountinfo = mi_lines(&["101 1 8:1 /P /alias rw - ext4 /dev/sda1 rw"]);
    refused(run(&fs, "/alias", &["/P/B"]), &["would cover"]);
}

#[test]
fn regression_mount_in_base_views_bind_root_below_mount_point_not_contains() {
    let mut fs = FakeFs::new();
    fs.dir("/Q/R/B");
    fs.dir("/P");
    fs.bind("/Q/R", "/P", 101);
    fs.mountinfo = mi_lines(&["101 1 8:1 /Q/R /P rw - ext4 /dev/sda1 rw"]);
    run(&fs, "/Q", &["/P/B"]).unwrap();
}

#[test]
fn regression_mount_in_base_views_btrfs_subvolumes_ok() {
    let mut fs = FakeFs::new();
    fs.dir("/home/u/mnt");
    fs.dir("/P/B");
    fs.tmpfs("/home", 60, 30);
    fs.dir("/home/u");
    fs.mountinfo = mi(&[
        "33 2 0:30 /@ / rw - btrfs /dev/x rw",
        "60 33 0:30 /@home /home rw - btrfs /dev/x rw",
    ]);
    run(&fs, "/home/u/mnt", &["/P/B"]).unwrap();
}

#[test]
fn regression_mount_in_base_views_different_device_ok() {
    let mut fs = FakeFs::std();
    fs.tmpfs("/other", 101, 40);
    fs.mountinfo = mi_lines(&["101 1 0:40 / /other rw - tmpfs tmpfs rw"]);
    run(&fs, "/other/mnt", &["/P/B"]).unwrap();
}

#[test]
fn regression_mount_in_base_views_hidden_under_overmount_in_base_is_conservative() {
    // /C at /P/B/sub, then /D over it: the hidden bind is still a view (documented).
    let mut fs = FakeFs::std();
    fs.dir("/C");
    fs.dir("/D");
    fs.bind("/C", "/P/B/sub", 101);
    fs.bind("/D", "/P/B/sub", 102);
    fs.mountinfo = mi_lines(&[
        "101 1 8:1 /C /P/B/sub rw - ext4 /dev/sda1 rw",
        "102 1 8:1 /D /P/B/sub rw - ext4 /dev/sda1 rw",
    ]);
    refused(
        run(&fs, "/C/mnt", &["/P/B"]),
        &["also visible at /P/B/sub/mnt"],
    );
}

#[test]
fn regression_mount_in_base_plan_git_inline_ref_stripped() {
    let (_td, root) = real_dir();
    std::fs::create_dir_all(root.join("B/.git")).unwrap();
    let fs = RealFs::with_cwd(root);
    let args = Args::try_parse_from(["ratarmount", "B@HEAD", "B/mnt"]).unwrap();
    let msg = plan_mount_point(
        &fs,
        &args,
        Some(PathBuf::from("B/mnt")),
        &[PathBuf::from("B@HEAD")],
    )
    .unwrap_err();
    assert!(msg.contains("inside the folder being mounted B;"), "{msg}");
}

#[test]
fn regression_mount_in_base_views_mount_id_unknown_skips_check() {
    let mut fs = FakeFs::std();
    fs.mnt_ids = false;
    refused(run(&fs, "B/mnt", &["B"]), &["inside"]);
    fs.bind("/P/B/sub", "/alias", 101);
    fs.mountinfo = mi_lines(&["101 1 8:1 /P/B/sub /alias rw - ext4 /dev/sda1 rw"]);
    // Without mount ids and without a shared inode chain the bind alias is invisible
    // for a mount point under the bind; documented residual.
    fs.nodes.get_mut(Path::new("/alias")).unwrap().ino = 9999;
    run(&fs, "/alias/mnt", &["/P/B"]).unwrap();
}

#[test]
fn regression_mount_in_base_views_mountinfo_unavailable_skips_check() {
    let mut fs = FakeFs::std();
    fs.mountinfo = None;
    refused(run(&fs, "B/mnt", &["B"]), &["inside"]);
    run(&fs, "mnt", &["B"]).unwrap();
}

#[test]
fn regression_mount_in_base_views_anchor_mount_absent_from_table_skips() {
    let mut fs = FakeFs::std();
    fs.mountinfo = mi(&["77 1 0:5 / /unrelated rw - tmpfs t rw"]);
    run(&fs, "mnt", &["B"]).unwrap();
    refused(run(&fs, "B/mnt", &["B"]), &["inside"]);
}

#[test]
fn regression_mount_in_base_views_non_utf8_entries() {
    let mut fs = FakeFs::new();
    let bad = OsString::from_vec(b"/P/B/su\xffb".to_vec());
    let mut raw = ROOT_MI.as_bytes().to_vec();
    raw.extend_from_slice(
        b"\n55 1 0:9 / /x\xffy rw - tmpfs t rw\n101 1 8:1 /C /P/B/su\xffb rw - ext4 d rw",
    );
    assert!(String::from_utf8(raw.clone()).is_err());
    fs.mountinfo = Some(raw);
    fs.dir("/P/B");
    fs.dir("/C");
    let sub = PathBuf::from(&bad);
    fs.nodes.insert(
        sub.clone(),
        N {
            k: K::Dir,
            ino: 4242,
            dev: 1,
            mnt: 101,
        },
    );
    // /C bound at the non-UTF-8 path under the base; mount point /C/mnt.
    let c_ino = fs.nodes[Path::new("/C")].ino;
    fs.nodes.get_mut(&sub).unwrap().ino = c_ino;
    let msg = refused(run(&fs, "/C/mnt", &["/P/B"]), &["inside the folder"]);
    assert!(msg.contains("also visible at"), "{msg}");
}

#[test]
fn regression_mount_in_base_mountinfo_parse_fields_and_escapes() {
    let bytes = b"36 35 98:0 /my\\040dir /mnt\\011x rw - ext3 /dev/root rw\nbroken line\n\
                  37 35 0:5 /a\\012b /c\\134d rw - tmpfs t rw\n";
    let es = parse_mountinfo(bytes);
    assert_eq!(es.len(), 2);
    assert_eq!(es[0].id, 36);
    assert_eq!(es[0].parent, 35);
    assert_eq!(es[0].dev, (98, 0));
    assert_eq!(es[0].root, Path::new("/my dir"));
    assert_eq!(es[0].mount_point, Path::new("/mnt\tx"));
    assert_eq!(es[1].root, Path::new("/a\nb"));
    assert_eq!(es[1].mount_point, Path::new("/c\\d"));
}

#[test]
fn regression_mount_in_base_mountinfo_stacked_same_mount_point() {
    let es = parse_mountinfo(
        b"39 26 0:38 / /proc/sys/fs/binfmt_misc rw - autofs a rw\n74 39 0:45 / /proc/sys/fs/binfmt_misc rw - binfmt_misc b rw\n",
    );
    assert_eq!(es.len(), 2);
    assert_eq!(es[0].mount_point, es[1].mount_point);
}

// D2: case alias + descendant bind.

#[test]
fn regression_mount_in_base_views_case_alias_base_with_descendant_bind() {
    let mut fs = FakeFs::new();
    fs.dir("/FS/P/B");
    fs.tmpfs("/C", 101, 40);
    fs.dir("/FS/P/B/sub");
    fs.bind("/C", "/FS/P/B/sub", 102);
    fs.alias("/FS/p/b", "/FS/P/B");
    fs.mountinfo = mi_lines(&[
        "101 1 0:40 / /C rw - tmpfs tmpfs rw",
        "102 1 0:40 / /FS/P/B/sub rw - tmpfs tmpfs rw",
    ]);
    // The base is spelled with a different case; lexical comparison of the view fails.
    refused(
        run(&fs, "/C/mnt", &["/FS/p/b"]),
        &["inside the folder", "also visible at /FS/P/B/sub/mnt"],
    );
}

#[test]
fn regression_mount_in_base_views_case_alias_anchor_maps_by_identity() {
    let mut fs = FakeFs::new();
    fs.dir("/FS/P/B");
    fs.tmpfs("/C", 101, 40);
    fs.dir("/FS/P/B/sub");
    fs.bind("/C", "/FS/P/B/sub", 102);
    fs.alias("/CC", "/C");
    fs.mountinfo = mi_lines(&[
        "101 1 0:40 / /C rw - tmpfs tmpfs rw",
        "102 1 0:40 / /FS/P/B/sub rw - tmpfs tmpfs rw",
    ]);
    refused(
        run(&fs, "/CC/mnt", &["/FS/P/B"]),
        &["also visible at /FS/P/B/sub/mnt"],
    );
}

/// Regression: `/FS/C` bound at `/FS/P/B/sub` refused `/FS/C/mnt` but accepted `/FS/c/mnt`
/// (the bind root was matched lexically below the mount boundary).
#[test]
fn regression_mount_in_base_views_case_alias_below_bind_boundary() {
    let mut fs = FakeFs::new();
    fs.dir("/FS/P/B/sub");
    fs.dir("/FS/C");
    fs.bind("/FS/C", "/FS/P/B/sub", 102);
    fs.alias("/FS/c", "/FS/C");
    fs.mountinfo = mi_lines(&["102 1 8:1 /FS/C /FS/P/B/sub rw - ext4 /dev/sda1 rw"]);
    for mp in ["/FS/C/mnt", "/FS/c/mnt"] {
        refused(
            run(&fs, mp, &["/FS/P/B"]),
            &["inside the folder", "also visible at /FS/P/B/sub/mnt"],
        );
    }
    run(&fs, "/FS/other/mnt", &["/FS/P/B"]).unwrap();
}

/// Regression: a filesystem mounted at `/FS/P/B` and mount point `/FS/P/B/mnt`: base
/// `/FS/P` is refused, but its case alias `/FS/p` was accepted (check 3 discarded the
/// ancestors above the mount boundary).
#[test]
fn regression_mount_in_base_case_alias_across_intervening_mount() {
    let mut fs = FakeFs::new();
    fs.tmpfs("/FS/P/B", 102, 40);
    fs.alias("/FS/p", "/FS/P");
    fs.mountinfo = mi_lines(&["102 1 0:40 / /FS/P/B rw - tmpfs tmpfs rw"]);
    for base in ["/FS/P", "/FS/p"] {
        refused(run(&fs, "/FS/P/B/mnt", &[base]), &["inside the folder"]);
    }
    // Not under the alias: unrelated.
    run(&fs, "/FS/P/B/mnt", &["/FS/Q"]).unwrap();
    // macOS-style fallback (no mount ids): same-dev view comparison.
    fs.mnt_ids = false;
    refused(run(&fs, "/FS/P/B/mnt", &["/FS/p"]), &["inside the folder"]);
}

/// Regression: a filesystem mounted at `/FS/P/B` serving base `/FS/P/B`; mount point
/// `/FS/P` is refused (it covers the base) but its case alias `/FS/p` was accepted
/// (check 3 dropped the base-side ancestors above the mount boundary).
#[test]
fn regression_mount_in_base_case_alias_across_mount_covering() {
    let mut fs = FakeFs::new();
    fs.tmpfs("/FS/P/B", 102, 40);
    fs.alias("/FS/p", "/FS/P");
    fs.mountinfo = mi_lines(&["102 1 0:40 / /FS/P/B rw - tmpfs tmpfs rw"]);
    for mp in ["/FS/P", "/FS/p"] {
        refused(run(&fs, mp, &["/FS/P/B"]), &["would cover"]);
    }
    run(&fs, "/FS/Q", &["/FS/P/B"]).unwrap();
    // macOS-style fallback (no mount ids): same-dev view comparison.
    fs.mnt_ids = false;
    for mp in ["/FS/P", "/FS/p"] {
        refused(run(&fs, mp, &["/FS/P/B"]), &["would cover"]);
    }
}

/// Covering direction, descendant-bind variant: `/C` is bound at `/FS/P/B/sub` (below
/// an intervening mount); a mount point `/FS/P/B/sub` or its case alias covers base `/C`.
#[test]
fn regression_mount_in_base_case_alias_descendant_bind_covering() {
    let mut fs = FakeFs::new();
    fs.tmpfs("/FS/P/B", 102, 40);
    fs.tmpfs("/C", 103, 41);
    fs.bind("/C", "/FS/P/B/sub", 104);
    fs.alias("/FS/p", "/FS/P");
    fs.mountinfo = mi_lines(&[
        "102 1 0:40 / /FS/P/B rw - tmpfs tmpfs rw",
        "103 1 0:41 / /C rw - tmpfs tmpfs rw",
        "104 102 0:41 / /FS/P/B/sub rw - tmpfs tmpfs rw",
    ]);
    let a = run(&fs, "/FS/P/B/sub", &["/C"]).is_err();
    let b = run(&fs, "/FS/p/B/sub", &["/C"]).is_err();
    assert_eq!(a, b, "alias must be refused whenever the original is");
    assert!(a, "bind root covering its source is refused");
}

/// Regression (descendant-bind variant): the bind of the mount-point filesystem sits
/// below an intervening mount (`/FS/P/B`), so the view's parent and the base anchor
/// are on different mounts; the base `/FS/p` still walks into the copy.
#[test]
fn regression_mount_in_base_case_alias_descendant_bind_across_intervening_mount() {
    let mut fs = FakeFs::new();
    fs.tmpfs("/FS/P/B", 102, 40);
    fs.tmpfs("/C", 103, 41);
    fs.bind("/C", "/FS/P/B/sub", 104);
    fs.alias("/FS/p", "/FS/P");
    fs.mountinfo = mi_lines(&[
        "102 1 0:40 / /FS/P/B rw - tmpfs tmpfs rw",
        "103 1 0:41 / /C rw - tmpfs tmpfs rw",
        "104 102 0:41 / /FS/P/B/sub rw - tmpfs tmpfs rw",
    ]);
    for base in ["/FS/P", "/FS/p"] {
        refused(
            run(&fs, "/C/mnt", &[base]),
            &["inside the folder", "also visible at /FS/P/B/sub/mnt"],
        );
    }
    run(&fs, "/C/mnt", &["/FS/Q"]).unwrap();
}

/// Regression: `relation_view` dropped base-side ancestors above a mount boundary. `/C`
/// is bound at `/FS/P/B` and another filesystem is mounted at `/FS/P/B/D`; a mount over
/// `/C` propagates to `/FS/P/B` and covers base `/FS/P/B/D`, but the case alias
/// `/FS/p/B/D` was accepted.
#[test]
fn regression_mount_in_base_views_case_alias_covering_across_mount() {
    let mut fs = FakeFs::new();
    fs.tmpfs("/C", 103, 41);
    fs.bind("/C", "/FS/P/B", 102);
    fs.tmpfs("/FS/P/B/D", 105, 42);
    fs.alias("/FS/p", "/FS/P");
    fs.mountinfo = mi_lines(&[
        "103 1 0:41 / /C rw - tmpfs tmpfs rw",
        "102 1 0:41 / /FS/P/B rw - tmpfs tmpfs rw",
        "105 102 0:42 / /FS/P/B/D rw - tmpfs tmpfs rw",
    ]);
    for base in ["/FS/P/B/D", "/FS/p/B/D"] {
        refused(run(&fs, "/C", &[base]), &["would cover"]);
    }
    // Unrelated base stays accepted.
    run(&fs, "/C", &["/FS/Q"]).unwrap();
    // `relation_view` needs mount ids (views come from mountinfo); no Dev-fallback variant.
}

/// Regression: the source of a bind (`/FS/C` bound at `/P/B/sub`) was later overmounted
/// by an unrelated bind of `/D`; `/D/mnt` was refused against base `/P/B` because
/// `alias_rest` trusted the inode now reached through `/FS/C`.
#[test]
fn regression_mount_in_base_alias_rest_overmounted_source_not_trusted() {
    let mut fs = FakeFs::std();
    fs.dir("/FS/C");
    fs.dir("/D");
    fs.bind("/FS/C", "/P/B/sub", 102);
    fs.bind("/D", "/FS/C", 103);
    fs.mountinfo = mi_lines(&[
        "102 1 8:1 /FS/C /P/B/sub rw - ext4 /dev/sda1 rw",
        "103 1 8:1 /D /FS/C rw - ext4 /dev/sda1 rw",
    ]);
    run(&fs, "/D/mnt", &["/P/B"]).unwrap();
    // The same overmount does not hide a real conflict: /FS/C is D's copy.
    refused(run(&fs, "/P/B/sub/mnt", &["/P/B"]), &["inside the folder"]);
}

#[test]
fn regression_mount_in_base_views_case_alias_c3_still_accepted() {
    let mut fs = c3_fs();
    fs.alias("/ALIAS", "/alias");
    fs.alias("/p/b", "/P/B");
    run(&fs, "/ALIAS/B/mnt", &["/p/b"]).unwrap();
}

// ---------------------------------------------------------------------------
// Same-view inode
// ---------------------------------------------------------------------------

#[test]
fn regression_mount_in_base_inode_case_alias_existing_overlay_inside() {
    let mut fs = FakeFs::std();
    fs.dir("/P/ov");
    fs.alias("/P/OV", "/P/ov");
    let msg = refused(
        run_ov(&fs, "OV/mnt", &["C"], Some("ov")),
        &["inside the write-overlay directory", "same directory"],
    );
    assert!(msg.contains("OV/mnt"), "{msg}");
}

#[test]
fn regression_mount_in_base_inode_case_alias_deeper_chain_inside() {
    let mut fs = FakeFs::std();
    fs.dir("/P/ov/x");
    fs.alias("/P/OV", "/P/ov");
    refused(
        run_ov(&fs, "OV/x/mnt", &["C"], Some("ov")),
        &["inside the write-overlay directory"],
    );
}

#[test]
fn regression_mount_in_base_inode_unicode_alias_existing_base_inside() {
    let mut fs = FakeFs::std();
    fs.dir("/P/caf\u{e9}");
    fs.alias("/P/cafe\u{301}", "/P/caf\u{e9}");
    refused(
        run(&fs, "cafe\u{301}/mnt", &["caf\u{e9}"]),
        &["inside the folder"],
    );
}

#[test]
fn regression_mount_in_base_inode_firmlink_alias_inside() {
    let mut fs = FakeFs::std();
    fs.linux = false;
    fs.dir("/System/Volumes/Data/Users/u/B");
    fs.alias("/Users", "/System/Volumes/Data/Users");
    refused(
        run(&fs, "/Users/u/B/mnt", &["/System/Volumes/Data/Users/u/B"]),
        &["inside the folder"],
    );
}

#[test]
fn regression_mount_in_base_inode_overmount_view_not_projected_c3() {
    // With mount ids the C3 layout is accepted; without them, only st_dev gates and
    // the documented over-refusal appears.
    let fs = c3_fs();
    run(&fs, "/alias/B/mnt", &["/P/B"]).unwrap();
    let mut fs = c3_fs();
    fs.mnt_ids = false;
    fs.mountinfo = None;
    // Same device everywhere: the alias chain is projected (documented over-refusal).
    refused(run(&fs, "/alias/B/mnt", &["/P/B"]), &["inside the folder"]);
}

#[test]
fn regression_mount_in_base_inode_mixed_view_kinds_not_projected() {
    // /B2 is a bind of /P/B; /B2/x is a directory in it. When the ancestor /B2 has no
    // mount id its view is `Dev`, the anchor's is `Mount`: the pair is skipped.
    let mut fs = FakeFs::std();
    fs.bind("/P/B", "/B2", 101);
    fs.dir("/B2/x");
    fs.mountinfo = None;
    refused(
        run(&fs, "/B2/x/mnt", &["/P/B"]),
        &["inside the folder", "same directory"],
    );
    fs.no_mnt.push(PathBuf::from("/B2"));
    run(&fs, "/B2/x/mnt", &["/P/B"]).unwrap();
}

#[test]
fn regression_mount_in_base_inode_chain_crosses_mount_not_projected() {
    // C3 without mountinfo: the (/alias, /P) pair has equal inodes, but /alias is in
    // another mount than the mount point's anchor, so it is not projected.
    let mut fs = c3_fs();
    fs.mountinfo = None;
    run(&fs, "/alias/B/mnt", &["/P/B"]).unwrap();
}

#[test]
fn regression_mount_in_base_inode_bind_alias_without_mountinfo_still_caught() {
    let mut fs = FakeFs::std();
    fs.bind("/P/B", "/B2", 101);
    fs.dir("/B2/x");
    fs.mountinfo = None;
    refused(
        run(&fs, "/B2/x/mnt", &["/P/B"]),
        &["inside the folder", "same directory"],
    );
}

#[test]
fn regression_mount_in_base_inode_same_path_pair_skipped() {
    let fs = FakeFs::std();
    run(&fs, "C/mnt", &["B"]).unwrap();
}

#[test]
fn regression_mount_in_base_inode_same_ino_different_dev_ok() {
    let mut fs = FakeFs::std();
    fs.tmpfs("/T", 101, 40);
    let ino = fs.nodes[Path::new("/P/B")].ino;
    fs.nodes.get_mut(Path::new("/T")).unwrap().ino = ino;
    fs.mountinfo = mi_lines(&["101 1 0:40 / /T rw - tmpfs t rw"]);
    run(&fs, "/T/mnt", &["/P/B"]).unwrap();
}

#[test]
fn regression_mount_in_base_inode_late_check_catches_case_alias_created_overlay() {
    let mut fs = FakeFs::std();
    let args = Args::try_parse_from(["ratarmount", "-w", "ov", "C", "OV/mnt"]).unwrap();
    let inputs = vec![PathBuf::from("C")];
    let plan = plan_mount_point(&fs, &args, Some(PathBuf::from("OV/mnt")), &inputs).unwrap();
    fs.dir("/P/ov");
    fs.alias("/P/OV", "/P/ov");
    let msg = decisive_check(&fs, &plan, Some(Path::new("ov"))).unwrap_err();
    assert!(msg.contains("inside the write-overlay directory"), "{msg}");
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

#[test]
fn regression_mount_in_base_message_wording_by_role() {
    let mut fs = FakeFs::std();
    fs.dir("/P/ov");
    let m = refused(
        run(&fs, "B", &["B"]),
        &["mounting a folder on itself deadlocks"],
    );
    assert!(
        m.starts_with("mount point B is the folder being mounted"),
        "{m}"
    );
    refused(
        run_ov(&fs, "ov", &["C"], Some("ov")),
        &[
            "is the write-overlay directory (-w)",
            "choose a mount point outside it",
        ],
    );
    refused(
        run(&fs, "B/m", &["B"]),
        &["the daemon would stat its own mount point and hang"],
    );
    refused(run(&fs, "/P", &["B"]), &["which the daemon reads by path"]);
}

#[test]
fn regression_mount_in_base_message_dot_input_hint() {
    let fs = FakeFs::std();
    let hint = Hint {
        computed_default: true,
        dot_input: true,
    };
    let c = [PathBuf::from("/P/B")];
    let bases = bases_now(&fs, &c, None).unwrap();
    let mut fs2 = FakeFs::std();
    fs2.cwd = PathBuf::from("/P/B");
    let msg = check_mount_point(
        &fs2,
        Path::new("mount"),
        &bases_now(&fs2, &[PathBuf::from(".")], None).unwrap(),
        hint,
    )
    .unwrap_err();
    assert!(
        msg.contains("pass an explicit mount point outside the folder"),
        "{msg}"
    );
    let msg = check_mount_point(&fs, Path::new("/P/B"), &bases, hint).unwrap_err();
    assert!(
        msg.contains("Pass an explicit mount point outside the folder"),
        "{msg}"
    );
}

#[test]
fn regression_mount_in_base_message_view_suffix_names_view_and_bind() {
    let via = Via::View {
        root: PathBuf::from("/C"),
        mount_point: PathBuf::from("/P/B/sub"),
        id: 101,
        view: PathBuf::from("/P/B/sub/mnt"),
    };
    let s = alias_suffix(&via);
    assert!(s.contains("/P/B/sub/mnt") && s.contains("bind mount of /C at /P/B/sub"));
}

#[test]
fn regression_mount_in_base_message_inode_suffix() {
    assert!(alias_suffix(&Via::Inode).contains("same directory"));
    assert!(alias_suffix(&Via::Path).is_empty());
}

#[test]
fn regression_mount_in_base_message_resolves_to_suffix() {
    let mut fs = FakeFs::std();
    fs.link("/P/L", "B");
    refused(run(&fs, "L/m", &["B"]), &["L/m (resolves to /P/B/m)"]);
}

#[test]
fn regression_mount_in_base_message_temp_overlay_wording() {
    let fs = FakeFs::std();
    let b = bases_now(&fs, &[], Some((Path::new("/P/B"), true))).unwrap();
    let msg = check_mount_point(&fs, Path::new("/P/B/m"), &b, Hint::default()).unwrap_err();
    assert!(
        msg.contains("inside the temporary write overlay /P/B"),
        "{msg}"
    );
}

#[test]
fn regression_mount_in_base_message_not_a_directory_explicit_vs_default() {
    let mut fs = FakeFs::std();
    fs.file("/P/F");
    let e = check_mount_point(&fs, Path::new("F"), &[], Hint::default()).unwrap_err();
    assert!(
        e.contains("cannot use F as a mount point: /P/F is not a directory"),
        "{e}"
    );
    let h = Hint {
        computed_default: true,
        dot_input: false,
    };
    let e = check_mount_point(&fs, Path::new("F"), &[], h).unwrap_err();
    assert!(
        e.contains("default mount point F exists and is not a directory"),
        "{e}"
    );
    let e = bases_now(&fs, &[], Some((Path::new("F"), false))).unwrap_err();
    assert!(e.contains("as the write-overlay directory"), "{e}");
}

// ---------------------------------------------------------------------------
// Defaults, plan, skip
// ---------------------------------------------------------------------------

fn real_dir() -> (tempfile::TempDir, PathBuf) {
    let td = tempfile::tempdir().unwrap();
    let root = td.path().canonicalize().unwrap();
    (td, root)
}

#[test]
fn regression_mount_in_base_skip_predicate_table() {
    let p = |a: &[&str]| {
        let mut v = vec!["ratarmount"];
        v.extend_from_slice(a);
        Args::try_parse_from(v).unwrap()
    };
    assert!(skip_guard(&p(&["--no-mount", "B"]), None, false));
    assert!(skip_guard(&p(&["-u", "mnt"]), None, false));
    assert!(skip_guard(&p(&["--http", "B"]), None, false));
    assert!(skip_guard(&p(&["B"]), None, true));
    assert!(!skip_guard(
        &p(&["--http", "B", "mnt"]),
        Some(Path::new("mnt")),
        false
    ));
    assert!(!skip_guard(&p(&["B", "mnt"]), Some(Path::new("mnt")), true));
    assert!(!skip_guard(&p(&["B"]), None, false));
}

#[test]
fn regression_mount_in_base_plan_default_bare_folder() {
    let (_td, root) = real_dir();
    std::fs::create_dir(root.join("B")).unwrap();
    let fs = RealFs::with_cwd(root.clone());
    assert_eq!(
        default_for_input(&fs, Path::new("B")),
        Path::new("B.mounted")
    );
    assert_eq!(
        default_for_input(&fs, Path::new("B/")),
        Path::new("B.mounted")
    );
    let args = Args::try_parse_from(["ratarmount", "B"]).unwrap();
    let plan = plan_mount_point(&fs, &args, None, &[PathBuf::from("B")]).unwrap();
    assert_eq!(plan.mp, Path::new("B.mounted"));
    assert!(plan.hint.computed_default);
}

#[test]
fn regression_mount_in_base_plan_default_symlink_input() {
    let (_td, root) = real_dir();
    std::fs::create_dir(root.join("B")).unwrap();
    std::os::unix::fs::symlink("B", root.join("L")).unwrap();
    let fs = RealFs::with_cwd(root.clone());
    assert_eq!(
        default_for_input(&fs, Path::new("L")),
        Path::new("L.mounted")
    );
}

#[test]
fn regression_mount_in_base_plan_default_absolute_other_cwd() {
    let (_td, root) = real_dir();
    let fs = RealFs::with_cwd(root.clone());
    std::fs::create_dir(root.join("B")).unwrap();
    let other = tempfile::tempdir().unwrap();
    let fs2 = RealFs::with_cwd(other.path().canonicalize().unwrap());
    assert_eq!(default_for_input(&fs2, &root.join("B")), Path::new("B"));
    drop(fs);
}

#[test]
fn regression_mount_in_base_plan_default_archive() {
    let (_td, root) = real_dir();
    std::fs::write(root.join("x.tar.gz"), b"").unwrap();
    let fs = RealFs::with_cwd(root);
    assert_eq!(
        default_for_input(&fs, Path::new("x.tar.gz")),
        Path::new("x")
    );
}

#[test]
fn regression_mount_in_base_plan_default_url_unchanged() {
    let mut fs = FakeFs::std();
    fs.panic_cwd = true;
    assert_eq!(
        default_for_input(&fs, Path::new("https://host/dir/a.tar.gz")),
        Path::new("a")
    );
}

#[test]
fn regression_mount_in_base_plan_default_url_unaffected_by_local_collision() {
    let mut fs = FakeFs::std();
    fs.dir("/P/https:/host/B");
    fs.link("/P/B2", "B");
    fs.panic_cwd = true;
    assert_eq!(
        default_for_input(&fs, Path::new("https://host/B")),
        Path::new("B")
    );
}

#[test]
fn regression_mount_in_base_plan_default_dotted_name() {
    let (_td, root) = real_dir();
    std::fs::create_dir(root.join("B.d")).unwrap();
    let fs = RealFs::with_cwd(root);
    assert_eq!(default_for_input(&fs, Path::new("B.d")), Path::new("B"));
}

#[test]
fn regression_mount_in_base_plan_default_dot_input_refused() {
    let (_td, root) = real_dir();
    std::fs::create_dir(root.join("B")).unwrap();
    let fs = RealFs::with_cwd(root.join("B"));
    let args = Args::try_parse_from(["ratarmount", "."]).unwrap();
    let msg = plan_mount_point(&fs, &args, None, &[PathBuf::from(".")]).unwrap_err();
    assert!(msg.contains("inside the folder being mounted"), "{msg}");
    assert!(msg.contains("pass an explicit mount point"), "{msg}");
}

#[test]
fn regression_mount_in_base_plan_default_exists_as_file() {
    let (_td, root) = real_dir();
    std::fs::create_dir(root.join("B")).unwrap();
    std::fs::write(root.join("B.mounted"), b"x").unwrap();
    let fs = RealFs::with_cwd(root);
    let args = Args::try_parse_from(["ratarmount", "B"]).unwrap();
    let msg = plan_mount_point(&fs, &args, None, &[PathBuf::from("B")]).unwrap_err();
    assert!(
        msg.contains("default mount point B.mounted exists and is not a directory"),
        "{msg}"
    );
}

#[test]
fn regression_mount_in_base_plan_default_exists_as_dir_reused() {
    let (_td, root) = real_dir();
    std::fs::create_dir(root.join("B")).unwrap();
    std::fs::create_dir(root.join("B.mounted")).unwrap();
    let fs = RealFs::with_cwd(root);
    let args = Args::try_parse_from(["ratarmount", "B"]).unwrap();
    let plan = plan_mount_point(&fs, &args, None, &[PathBuf::from("B")]).unwrap();
    assert_eq!(plan.mp, Path::new("B.mounted"));
}

#[test]
fn regression_mount_in_base_plan_default_rolling_series() {
    let (_td, root) = real_dir();
    let fs = RealFs::with_cwd(root.clone());
    let args =
        Args::try_parse_from(["ratarmount", "--roll-every", "1d", "-w", "ov", "logs.tar"]).unwrap();
    let inputs = vec![root.join("logs.tar")];
    let name = |p: PathBuf| p.file_name().unwrap().to_owned();
    assert_eq!(
        name(effective_default_input(&args, &inputs)),
        "logs.000001.tar"
    );
    std::fs::write(root.join("logs.000003.tar"), b"").unwrap();
    assert_eq!(
        name(effective_default_input(&args, &inputs)),
        "logs.000003.tar"
    );
    let plan = plan_mount_point(&fs, &args, None, &inputs).unwrap();
    assert_eq!(plan.mp, Path::new("logs.000003"));
    assert_eq!(name(plan.derived_rolling_input.unwrap()), "logs.000003.tar");
    // Base exists: discovery errors and the input itself is used.
    std::fs::write(root.join("logs.tar"), b"").unwrap();
    assert_eq!(
        effective_default_input(&args, &inputs),
        root.join("logs.tar")
    );
}

#[test]
fn regression_mount_in_base_plan_rolling_notice() {
    let a = Path::new("logs.000001.tar");
    assert!(rolling_derivation_notice(a, a, Path::new("logs.000001")).is_none());
    let msg = rolling_derivation_notice(a, Path::new("logs.000002.tar"), Path::new("logs.000001"))
        .unwrap();
    assert!(msg.contains("keeping the mount point logs.000001"), "{msg}");
}

#[test]
fn regression_mount_in_base_plan_bind_sources_are_candidates() {
    let fs = FakeFs::std();
    let args = Args::try_parse_from(["ratarmount", "--bind", "/x=B", "mnt"]).unwrap();
    let plan = plan_mount_point(
        &fs,
        &args,
        Some(PathBuf::from("mnt")),
        &[PathBuf::from("B")],
    )
    .unwrap();
    assert_eq!(plan.candidates, [PathBuf::from("B")]);
    let msg = plan_mount_point(
        &fs,
        &args,
        Some(PathBuf::from("B/mnt")),
        &[PathBuf::from("B")],
    )
    .unwrap_err();
    assert!(msg.contains("inside the folder"), "{msg}");
}

#[test]
fn regression_mount_in_base_plan_cwd_not_needed_for_absolute_paths() {
    let mut fs = FakeFs::std();
    fs.panic_cwd = true;
    let args = Args::try_parse_from(["ratarmount", "/P/B", "/P/C/m"]).unwrap();
    plan_mount_point(
        &fs,
        &args,
        Some(PathBuf::from("/P/C/m")),
        &[PathBuf::from("/P/B")],
    )
    .unwrap();
}

#[test]
fn regression_mount_in_base_default_mountpoint_url_refactor_is_pure() {
    for s in [
        "https://host/a/b.tar.gz",
        "https://host/",
        "s3://bucket/key.tar",
        "x.tar.gz",
        "plain",
        "dir/B.d",
        ".",
        "..",
    ] {
        let expected = match url::Url::parse(s) {
            Ok(url) => url
                .path_segments()
                .and_then(|mut p| p.next_back())
                .filter(|seg| !seg.is_empty())
                .map(|seg| {
                    let stripped = ratarmount_compress::strip_compression_suffix(seg);
                    Path::new(&stripped)
                        .file_stem()
                        .and_then(|x| x.to_str())
                        .unwrap_or(&stripped)
                        .to_string()
                })
                .unwrap_or_else(|| "remote".into()),
            Err(_) => {
                let name = Path::new(s)
                    .file_name()
                    .and_then(|x| x.to_str())
                    .unwrap_or("mount");
                let stripped = ratarmount_compress::strip_compression_suffix(name);
                Path::new(&stripped)
                    .file_stem()
                    .and_then(|x| x.to_str())
                    .unwrap_or(&stripped)
                    .to_string()
            }
        };
        assert_eq!(
            crate::default_mountpoint(Path::new(s)),
            Path::new(&expected),
            "{s}"
        );
    }
}

#[test]
fn regression_mount_in_base_prepare_overlay_dir_creates_only_when_missing() {
    let (_td, root) = real_dir();
    prepare_overlay_dir(&root.join("a/b")).unwrap();
    assert!(root.join("a/b").is_dir());
    std::fs::write(root.join("f"), b"x").unwrap();
    prepare_overlay_dir(&root.join("f")).unwrap();
    assert!(root.join("f").is_file());
}

// ---------------------------------------------------------------------------
// RealFs
// ---------------------------------------------------------------------------

#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[test]
fn regression_mount_in_base_realfs_statx_layout_matches_libc() {
    assert_eq!(std::mem::size_of::<libc::statx>(), 256);
    assert_eq!(std::mem::offset_of!(libc::statx, stx_mnt_id), STX_MNT_ID);
    assert_eq!(std::mem::offset_of!(libc::statx, stx_mask), STX_MASK);
}

#[cfg(target_os = "linux")]
#[test]
fn regression_mount_in_base_realfs_mount_id_present_in_table() {
    let Some(root_id) = mount_id_statx(Path::new("/")) else {
        eprintln!("skip: kernel without STATX_MNT_ID");
        return;
    };
    let td = tempfile::tempdir().unwrap();
    let tmp = td.path().canonicalize().unwrap();
    let table = parse_mountinfo(&RealFs::new().mountinfo_bytes().unwrap_or_default());
    for p in [Path::new("/"), Path::new("/proc"), tmp.as_path()] {
        let Some(id) = mount_id_statx(p) else {
            continue;
        };
        if let Some(e) = table.iter().find(|e| e.id == id) {
            let canon = p.canonicalize().unwrap();
            assert!(
                canon.starts_with(&e.mount_point),
                "{canon:?} vs {:?}",
                e.mount_point
            );
        } else {
            eprintln!("skip: mount id {id} for {p:?} not in mountinfo (chroot?)");
        }
    }
    if let Some(proc_id) = mount_id_statx(Path::new("/proc")) {
        assert_ne!(root_id, proc_id);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn regression_mount_in_base_realfs_handle_mount_id_agrees_where_supported() {
    let td = tempfile::tempdir().unwrap();
    for p in [Path::new("/"), td.path(), Path::new("/proc")] {
        let handle = mount_id_handle(p);
        let statx = mount_id_statx(p);
        if let (Some(h), Some(s)) = (handle, statx) {
            assert_eq!(h, s, "{p:?}");
        }
    }
}

#[test]
fn regression_mount_in_base_realfs_handle_result_mapper() {
    assert_eq!(handle_result(0, 0, 7), Some(7));
    #[cfg(target_os = "linux")]
    assert_eq!(handle_result(-1, libc::EOVERFLOW, 7), Some(7));
    #[cfg(target_os = "linux")]
    assert_eq!(handle_result(-1, libc::EOPNOTSUPP, -1), None);
    assert_eq!(handle_result(-1, 2, -1), None);
    assert_eq!(handle_result(-1, 2, 7), None);
}

#[test]
fn regression_mount_in_base_realfs_lstat_kinds() {
    let (_td, root) = real_dir();
    std::fs::create_dir(root.join("d")).unwrap();
    std::fs::write(root.join("f"), b"").unwrap();
    std::os::unix::fs::symlink("d", root.join("l")).unwrap();
    let fs = RealFs::new();
    assert_eq!(fs.lstat(&root.join("d")).unwrap(), Node::Dir);
    assert_eq!(fs.lstat(&root.join("f")).unwrap(), Node::Other);
    assert_eq!(
        fs.lstat(&root.join("l")).unwrap(),
        Node::Symlink("d".into())
    );
    assert_eq!(
        fs.lstat(&root.join("none")).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
}

#[test]
fn regression_mount_in_base_realfs_dir_id_differs_root_proc() {
    let fs = RealFs::new();
    let a = fs.dir_id(Path::new("/")).unwrap();
    if let Some(b) = fs.dir_id(Path::new("/proc")) {
        assert_ne!(a, b);
    }
    assert!(fs.dir_id(Path::new("/nonexistent-xyz")).is_none());
}

#[cfg(target_os = "linux")]
#[test]
fn regression_mount_in_base_realfs_view_of_is_mount_when_available() {
    let fs = RealFs::new();
    match (mount_id_statx(Path::new("/")), view_of(&fs, Path::new("/"))) {
        (Some(id), v) => assert_eq!(v, Some(View::Mount(id))),
        (None, v) => assert!(matches!(v, Some(View::Dev(_)) | Some(View::Mount(_)))),
    }
}

/// End-to-end on the real filesystem: the refusal needs no mount.
#[test]
fn regression_mount_in_base_realfs_end_to_end_refusal() {
    let (_td, root) = real_dir();
    std::fs::create_dir_all(root.join("B/sub")).unwrap();
    std::os::unix::fs::symlink("B", root.join("L")).unwrap();
    let fs = RealFs::with_cwd(root);
    refused(run(&fs, "L/mnt", &["B"]), &["inside the folder"]);
    run(&fs, "mnt", &["B"]).unwrap();
}

// ---------------------------------------------------------------------------
// Namespace (Linux, try-or-skip): bind mounts through the real kernel.
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[test]
fn regression_mount_in_base_bind_alias_verdicts_in_user_namespace() {
    let ok = std::process::Command::new("unshare")
        .args(["-Urm", "true"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        eprintln!("skip: unshare -Urm unavailable");
        return;
    }
    let td = tempfile::tempdir().unwrap();
    let exe = std::env::current_exe().unwrap();
    let out = std::process::Command::new("unshare")
        .args(["-Urm"])
        .arg(exe)
        .args([
            "--ignored",
            "--exact",
            "mount_guard::tests::helper_bind_alias_verdicts",
            "--nocapture",
        ])
        .env("RATARMOUNT_MIB_NS_DIR", td.path())
        .output()
        .unwrap();
    let text =
        String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "helper failed: {text}");
}

#[cfg(target_os = "linux")]
fn mount_bind(src: &Path, dst: &Path) -> bool {
    use std::ffi::CString;
    let s = CString::new(src.as_os_str().as_bytes()).unwrap();
    let d = CString::new(dst.as_os_str().as_bytes()).unwrap();
    // SAFETY: valid NUL-terminated paths, null fstype/data for MS_BIND.
    unsafe {
        libc::mount(
            s.as_ptr(),
            d.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        ) == 0
    }
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "runs inside `unshare -Urm`; driven by regression_mount_in_base_bind_alias_verdicts_in_user_namespace"]
fn helper_bind_alias_verdicts() {
    let Some(dir) = std::env::var_os("RATARMOUNT_MIB_NS_DIR") else {
        return;
    };
    let root = PathBuf::from(dir).canonicalize().unwrap();
    if mount_id_statx(&root).is_none() {
        eprintln!("skip: no STATX_MNT_ID");
        return;
    }
    let p = root.join("P");
    let (b, sub, c, alias) = (
        p.join("B"),
        p.join("B/sub"),
        root.join("C"),
        root.join("alias"),
    );
    std::fs::create_dir_all(sub.join("deep")).unwrap();
    std::fs::create_dir_all(&c).unwrap();
    std::fs::create_dir_all(&alias).unwrap();
    let fs = RealFs::with_cwd(root.clone());
    let check = |mp: &Path| {
        let bases = bases_now(&fs, std::slice::from_ref(&b), None).unwrap();
        check_mount_point(&fs, mp, &bases, Hint::default())
    };
    // Unrelated bind: accepted.
    if !mount_bind(&c, &alias) {
        eprintln!("skip: MS_BIND not permitted");
        return;
    }
    check(&alias.join("mnt")).unwrap();
    // S1: a subdirectory of the base bound at alias.
    let a2 = root.join("alias2");
    std::fs::create_dir_all(&a2).unwrap();
    assert!(mount_bind(&sub, &a2));
    let msg = check(&a2.join("mnt")).unwrap_err();
    assert!(msg.contains("inside the folder"), "{msg}");
    // C3: P at alias3, C at alias3/B, mount point alias3/B/mnt: accepted (before C2,
    // which adds a view of C inside the base).
    let a3 = root.join("alias3");
    std::fs::create_dir_all(&a3).unwrap();
    assert!(mount_bind(&p, &a3));
    assert!(mount_bind(&c, &a3.join("B")));
    check(&a3.join("B/mnt")).unwrap();
    // C2: C bound inside the base, mount point C/mnt.
    assert!(mount_bind(&c, &sub));
    let msg = check(&c.join("mnt")).unwrap_err();
    assert!(msg.contains(&format!("{}/mnt", sub.display())), "{msg}");
}
