//! Layered supervisor attempts (plan R1b §5.2–§5.5): L3–L8. Layers are real
//! sealed overlays and bundles over a temporary directory base, kept outside
//! the state root; the Fake child captures each lower's metadata, resolving
//! bundles into a cache of its own, and composes nothing.

use super::daemon::{respond, Supervisor};
use super::lowers::MAX_BUNDLE_BYTES;
use super::protocol::{Attempt, BaseOptions, Operation};
use super::requests::Status;
use super::tests::{private_tempdir, Fake, Hook};
use crate::base_identity::fixtures::FixtureOpener;
use crate::overlay_pack::{Limits, PackOptions};
use ratarmount_compositing::{
    compose_stack, overlay_fsck, overlay_seal, BaseDigestRequest, ClassifiedBase, CreateOptions,
    FolderMountSource, Immutability, LowerLayerRecord, OverlayMeta, ServedKind, ServedLocation,
    WriteOverlay, HIDDEN_DB,
};
use ratarmount_core::MountSource;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

const X: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const Y: &str = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
const TREE_X: &str = "3333333333333333333333333333333333333333";
const TREE_Y: &str = "4444444444444444444444444444444444444444";

/// The base identity a fixture layer records.
#[derive(Clone, Copy)]
enum Identity {
    /// A supplied strong digest (`--base-digest`).
    Strong(&'static str),
    /// A Git base with this tree id.
    Git(&'static str),
    /// A directory base's computed weak digest.
    Weak,
    /// `--base-digest none`.
    Nothing,
}

/// The view a layer over `lowers` is written on: `base`, then `lowers`.
fn view(base: &Path, lowers: &[PathBuf]) -> Arc<dyn MountSource> {
    let source: Arc<dyn MountSource> = Arc::new(FolderMountSource::new(base).unwrap());
    let layers: Vec<_> = lowers
        .iter()
        .map(|path| (path.clone(), Immutability::Immutable))
        .collect();
    compose_stack(source, &layers).unwrap()
}

/// A token of the same kind and place at creation and at seal, so seal
/// rewrites no identity row.
fn token(base: &Path, identity: Identity, view: Arc<dyn MountSource>) -> ClassifiedBase {
    let kind = match identity {
        Identity::Git(tree) => ServedKind::Git { tree: tree.into() },
        _ => ServedKind::Folder,
    };
    ClassifiedBase::open(&mut FixtureOpener {
        source: view,
        kind,
        inputs: vec![base.to_string_lossy().into_owned()],
        location: Some(ServedLocation::Local(base.to_path_buf())),
    })
    .unwrap()
}

fn meta(dir: &Path) -> OverlayMeta {
    OverlayMeta::read_no_recovery(dir).unwrap().unwrap()
}

/// What a mount records of the sealed layer `dir`.
fn record(dir: &Path) -> LowerLayerRecord {
    let meta = meta(dir);
    LowerLayerRecord {
        path: dir.canonicalize().unwrap(),
        layer_digest: meta.get("layer_digest").unwrap().into(),
        sealed_at: meta.get("sealed_at").unwrap().into(),
    }
}

fn digest(dir: &Path) -> String {
    meta(dir).get("layer_digest").unwrap().into()
}

fn bundle_digest(bundle: &Path) -> String {
    crate::overlay_pack::bundle_meta(bundle, Limits::resolve(None, None).unwrap()).unwrap()
        ["layer_digest"]
        .clone()
}

fn write_files(dir: &Path, files: &[(&str, &str)]) {
    for (path, content) in files {
        let path = dir.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }
}

fn seal(base: &Path, dir: &Path, lowers: &[PathBuf], identity: Identity) {
    overlay_fsck::fsck(dir, true).unwrap();
    let view = view(base, lowers);
    overlay_seal::seal(dir, &token(base, identity, view.clone()), view).unwrap();
}

/// Unseals `dir`, rewrites `file` and seals it again: a new seal pair.
fn reseal(base: &Path, dir: &Path, lowers: &[PathBuf], identity: Identity, file: &str) {
    overlay_seal::unseal(dir).unwrap();
    fs::write(dir.join(file), "changed after validation\n").unwrap();
    seal(base, dir, lowers, identity);
}

/// Renames a (read-only) layer root; macOS needs its write bit for that.
fn rename_dir(from: &Path, to: &Path) {
    let mode = fs::metadata(from).unwrap().permissions().mode() & 0o7777;
    fs::set_permissions(from, fs::Permissions::from_mode(mode | 0o200)).unwrap();
    fs::rename(from, to).unwrap();
    fs::set_permissions(to, fs::Permissions::from_mode(mode)).unwrap();
}

/// Owner write and search bits on every directory below `path`, so trees of
/// sealed, read-only layers can be removed.
fn writable(path: &Path) {
    let Ok(entry) = fs::symlink_metadata(path) else {
        return;
    };
    if entry.is_dir() {
        let mode = entry.permissions().mode() & 0o7777;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode | 0o700));
        for child in fs::read_dir(path).into_iter().flatten().flatten() {
            writable(&child.path());
        }
    }
}

/// A writable copy of the layer `from` (regular files and directories).
fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir(to).unwrap();
    for child in fs::read_dir(from).unwrap() {
        let child = child.unwrap();
        let target = to.join(child.file_name());
        if child.file_type().unwrap().is_dir() {
            copy_tree(&child.path(), &target);
        } else {
            fs::copy(child.path(), &target).unwrap();
            fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
        }
    }
}

/// Every file below `dir` and its bytes.
fn snapshot(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut files = BTreeMap::new();
    for child in fs::read_dir(dir).unwrap() {
        let path = child.unwrap().path();
        if path.is_dir() {
            files.extend(snapshot(&path));
        } else {
            files.insert(path.clone(), fs::read(&path).unwrap());
        }
    }
    files
}

/// Sealed layers and bundles over one directory base, in their own temporary
/// directory: the place rule refuses anything inside the state root. Owner
/// write bits are restored before the directory is removed.
struct World {
    dir: tempfile::TempDir,
    base: PathBuf,
}

impl Drop for World {
    fn drop(&mut self) {
        writable(self.dir.path());
    }
}

impl World {
    fn new() -> Self {
        let dir = private_tempdir();
        let base = dir.path().join("base");
        fs::create_dir(&base).unwrap();
        fs::write(base.join("base.txt"), "base\n").unwrap();
        Self {
            base: base.canonicalize().unwrap(),
            dir,
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().canonicalize().unwrap().join(name)
    }

    /// An unsealed layer `name` written over `lowers`, holding `files`.
    fn unsealed(
        &self,
        name: &str,
        lowers: &[&Path],
        identity: Identity,
        files: &[(&str, &str)],
    ) -> PathBuf {
        let dir = self.path(name);
        let lowers: Vec<PathBuf> = lowers.iter().map(|path| path.to_path_buf()).collect();
        let view = view(&self.base, &lowers);
        let base_digest = match identity {
            Identity::Strong(digest) => BaseDigestRequest::Supplied(digest.into()),
            Identity::Nothing => BaseDigestRequest::None,
            Identity::Git(_) | Identity::Weak => BaseDigestRequest::Compute,
        };
        let overlay = WriteOverlay::open(
            &token(&self.base, identity, view.clone()),
            view,
            &dir,
            &CreateOptions {
                lower_layers: lowers.iter().map(|lower| record(lower)).collect(),
                base_digest,
                ..Default::default()
            },
        )
        .unwrap();
        drop(overlay);
        write_files(&dir, files);
        dir
    }

    /// A sealed layer `name` written over `lowers`, holding `files`.
    fn layer(
        &self,
        name: &str,
        lowers: &[&Path],
        identity: Identity,
        files: &[(&str, &str)],
    ) -> PathBuf {
        let dir = self.unsealed(name, lowers, identity, files);
        let lowers: Vec<PathBuf> = lowers.iter().map(|path| path.to_path_buf()).collect();
        seal(&self.base, &dir, &lowers, identity);
        dir
    }

    /// The sealed layer `dir`, written over `lowers`, packed into `name`.
    fn bundle(&self, dir: &Path, lowers: &[&Path], name: &str) -> PathBuf {
        let bundle = self.path(name);
        let lowers: Vec<PathBuf> = lowers.iter().map(|path| path.to_path_buf()).collect();
        crate::overlay_pack::pack(
            dir,
            &bundle,
            view(&self.base, &lowers),
            &PackOptions::default(),
        )
        .unwrap();
        bundle
    }
}

/// A supervisor whose base `task` is the world's base, with a Fake child
/// whose bundle cache lives in the world.
struct Setup {
    supervisor: Supervisor<Fake>,
    fake: Fake,
    _state: tempfile::TempDir,
}

fn setup(world: &World) -> Setup {
    // A Fake that extracts bundles needs more than setup()'s 250 ms.
    setup_with(world, Duration::from_secs(10))
}

/// [`setup`] with the supervisor's batch `timeout`.
fn setup_with(world: &World, timeout: Duration) -> Setup {
    let state = private_tempdir();
    let fake = Fake::default();
    let cache = world.path("cache");
    fs::create_dir_all(&cache).unwrap();
    fake.0.lock().unwrap().bundle_cache = Some(cache);
    let mut supervisor = Supervisor::open(state.path(), 8, timeout, fake.clone()).unwrap();
    supervisor
        .handle(Operation::CreateBase {
            name: "task".into(),
            source: world.base.to_str().unwrap().into(),
            options: BaseOptions::default(),
        })
        .unwrap();
    Setup {
        supervisor,
        fake,
        _state: state,
    }
}

fn send(supervisor: &mut Supervisor<Fake>, request: &Value) -> Value {
    serde_json::from_slice(&respond(supervisor, &serde_json::to_vec(request).unwrap())).unwrap()
}

fn layered(count: usize, lowers: &[&Path]) -> Value {
    let lowers: Vec<_> = lowers.iter().map(|path| path.to_str().unwrap()).collect();
    json!({"version": 2, "op": "new", "base": "task", "count": count, "lowers": lowers})
}

/// A refusal before anything exists: `invalid_request` in a v2 envelope whose
/// message names `name`; no attempt directory, spawn or new RAM state.
fn refused(supervisor: &mut Supervisor<Fake>, fake: &Fake, request: &Value, name: &str) -> String {
    let spawns = fake.0.lock().unwrap().spawns;
    let ram = supervisor.root.join("ram-root.json").exists();
    let reply = send(supervisor, request);
    assert_eq!(reply["version"], 2, "{reply}");
    assert_eq!(
        reply["error"]["code"], "invalid_request",
        "{request}: {reply}"
    );
    let message = reply["error"]["message"].as_str().unwrap().to_owned();
    assert!(message.contains(name), "{name}: {message}");
    assert_eq!(fake.0.lock().unwrap().spawns, spawns, "{message}");
    assert_eq!(
        fs::read_dir(supervisor.root.join("attempts"))
            .unwrap()
            .count(),
        0
    );
    assert_eq!(supervisor.root.join("ram-root.json").exists(), ram);
    assert!(supervisor.attempts.is_empty() && supervisor.taken_lowers.is_empty());
    message
}

/// Accepted with `count` 2: each child got the canonical `lowers`, in order,
/// and its re-check recorded what it took (`digests`); then destroyed.
fn accepted(setup: &mut Setup, lowers: &[&Path], digests: &[String]) {
    let reply = send(&mut setup.supervisor, &layered(2, lowers));
    assert_eq!(reply["ok"], true, "{reply}");
    let canonical: Vec<PathBuf> = lowers.iter().map(|p| p.canonicalize().unwrap()).collect();
    let specs = setup.fake.0.lock().unwrap().specs.clone();
    assert!(specs[specs.len() - 2..]
        .iter()
        .all(|spec| spec.lowers == canonical));
    for attempt in reply["result"].as_array().unwrap() {
        let records = setup.supervisor.taken_lowers[attempt["id"].as_str().unwrap()]
            .clone()
            .unwrap();
        let taken: Vec<_> = records.into_iter().map(|r| r.layer_digest).collect();
        assert_eq!(taken, digests);
    }
    setup.supervisor.destroy_all().unwrap();
    assert!(setup.supervisor.taken_lowers.is_empty());
}

/// Leaves `dir`'s overlay database with a hot rollback journal: the database
/// and its `-journal` copied while a writer's spilled transaction is open.
fn hot_journal(dir: &Path) {
    let scratch = tempfile::tempdir().unwrap();
    let source = scratch.path().join("source.sqlite");
    fs::copy(dir.join(HIDDEN_DB), &source).unwrap();
    let conn = rusqlite::Connection::open(&source).unwrap();
    conn.execute_batch(
        "PRAGMA journal_mode=DELETE; CREATE TABLE pad(x BLOB); \
         WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 64) \
         INSERT INTO pad SELECT zeroblob(4096) FROM n;",
    )
    .unwrap();
    // A tiny cache spills the open transaction into the database file.
    conn.execute_batch(
        "PRAGMA cache_size=1; BEGIN; UPDATE pad SET x = zeroblob(4000); \
         INSERT INTO pad SELECT x FROM pad;",
    )
    .unwrap();
    let journal = PathBuf::from(format!("{}-journal", source.display()));
    assert!(fs::metadata(&journal).unwrap().len() > 0, "spilled journal");
    let db = dir.join(HIDDEN_DB);
    fs::copy(&source, &db).unwrap();
    fs::copy(&journal, format!("{}-journal", db.display())).unwrap();
    drop(conn);
}

/// Regression (R1b L3): every lower refusal is `invalid_request` naming the
/// lower, before any attempt directory, child or RAM state exists. The place
/// rule is checked before each component is looked up (a path below the
/// state root is refused, not resolved, also when a later `..` or a symlink
/// would lead out of it again; sweep 1), a FIFO never blocks the daemon, the
/// request's bundles are capped, and a hot journal is refused, never rolled
/// back.
#[test]
fn regression_supervisor_lower_validation_refusals() {
    let world = World::new();
    let a = world.layer("a", &[], Identity::Strong(X), &[("a.txt", "a\n")]);
    let mut setup = setup(&world);
    let Setup {
        supervisor, fake, ..
    } = &mut setup;
    let root = supervisor.root.clone();
    let request = |lowers: &[&Path]| layered(2, lowers);
    let text = |path: &Path| path.to_str().unwrap().to_owned();

    // List rule.
    let raw =
        |lowers: &[&str]| json!({"version": 2, "op": "new", "base": "task", "lowers": lowers});
    let message = refused(
        supervisor,
        fake,
        &raw(&["relative/layer"]),
        "relative/layer",
    );
    assert!(message.contains("absolute"), "{message}");
    refused(supervisor, fake, &raw(&[""]), "empty");
    refused(supervisor, fake, &raw(&["/a\0b"]), "NUL");
    let missing = world.path("missing");
    refused(supervisor, fake, &request(&[&missing]), &text(&missing));
    let many: Vec<&Path> = vec![&a; 33];
    refused(supervisor, fake, &request(&many), "at most 32");

    // Place rule: below the state root as written, before anything there is
    // looked up, so a missing path there is refused as inside, never as
    // missing.
    // Regression (sweep 1, Codex #1): `from/../..` up to `/`, then down to
    // the valid layer `a`. Normalized, it never entered the root, but
    // `canonicalize` looked up every component as written: a missing one
    // made the refusal "missing", an existing one accepted the lower.
    let escape = |from: PathBuf| {
        let mut path = from;
        for _ in 0..root.components().count() + 4 {
            path.push("..");
        }
        path.join(a.strip_prefix("/").unwrap())
    };
    for inside in [
        root.join("attempts/attempt-x/mnt/layer"),
        root.join("indexes"),
        root.join("no-such-layer"),
        root.join("attempts/../indexes/../no-such-layer"),
        escape(root.join("attempts/attempt-x/mnt/uncached")),
        escape(root.join("attempts")),
    ] {
        let message = refused(supervisor, fake, &request(&[&inside]), &text(&inside));
        assert!(
            message.contains("lies inside the supervisor's state directory"),
            "{message}"
        );
    }
    let ancestor = root.parent().unwrap();
    let message = refused(supervisor, fake, &request(&[ancestor]), &text(ancestor));
    assert!(message.contains("inside or above"), "{message}");
    let link = world.path("link");
    std::os::unix::fs::symlink(root.join("attempts"), &link).unwrap();
    let message = refused(supervisor, fake, &request(&[&link]), &text(&link));
    assert!(message.contains("resolves to"), "{message}");
    // Regression (sweep 1, Claude #2): through a symlink to the state root,
    // also when `..` would lead out of it again, nothing inside is looked up.
    let alias = world.path("state-alias");
    std::os::unix::fs::symlink(&root, &alias).unwrap();
    for through in [
        alias.join("attempts/attempt-x/mnt/layer"),
        escape(alias.join("attempts")),
    ] {
        let message = refused(supervisor, fake, &request(&[&through]), &text(&through));
        assert!(
            message.contains(&format!(
                "resolves to {}, inside the supervisor's state directory",
                root.display()
            )),
            "{message}"
        );
    }

    // Type rule: checked before any open, so a FIFO cannot block.
    let fifo = world.path("fifo");
    let name = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    let started = Instant::now();
    let message = refused(supervisor, fake, &request(&[&fifo]), &text(&fifo));
    assert!(message.contains("neither"), "{message}");
    assert!(started.elapsed() < Duration::from_secs(10));

    // Directory lowers: sealed layers with a valid digest only.
    let plain = world.path("plain");
    fs::create_dir(&plain).unwrap();
    refused(supervisor, fake, &request(&[&plain]), &text(&plain));
    let unsealed = world.unsealed("unsealed", &[], Identity::Strong(X), &[("u", "u\n")]);
    let message = refused(supervisor, fake, &request(&[&unsealed]), &text(&unsealed));
    assert!(message.contains("not sealed"), "{message}");
    for (dir, sql, why) in [
        (
            "empty-digest",
            "UPDATE meta SET value = '' WHERE key = 'layer_digest'",
            "invalid layer_digest",
        ),
        (
            "stack-forced",
            "INSERT INTO meta(key, value) VALUES ('stack_mismatch_forced_at', '2026-10-31T00:00:00Z')",
            "stack_mismatch_forced_at",
        ),
        (
            "base-forced",
            "INSERT INTO meta(key, value) VALUES ('base_mismatch_forced_at', '2026-10-31T00:00:00Z')",
            "base_mismatch_forced_at",
        ),
    ] {
        let copy = world.path(dir);
        copy_tree(&a, &copy);
        rusqlite::Connection::open(copy.join(HIDDEN_DB))
            .unwrap()
            .execute_batch(sql)
            .unwrap();
        let message = refused(supervisor, fake, &request(&[&copy]), &text(&copy));
        assert!(message.contains(why), "{message}");
    }
    // Identities that cannot be compared across layers.
    for (name, identity, kind) in [
        ("weak", Identity::Weak, "weak"),
        ("none", Identity::Nothing, "none"),
    ] {
        let layer = world.layer(name, &[], identity, &[("w", "w\n")]);
        assert_eq!(meta(&layer).base_digest_kind(), Some(kind));
        let message = refused(supervisor, fake, &request(&[&layer]), &text(&layer));
        assert!(message.contains(&format!("kind {kind};")), "{message}");
    }

    // Bundle lowers: structural checks only (the child verifies content).
    let file = world.path("file.txt");
    fs::write(&file, "not a bundle\n").unwrap();
    let message = refused(supervisor, fake, &request(&[&file]), &text(&file));
    assert!(message.contains("not a sealed layer bundle"), "{message}");
    let bundle = world.bundle(&a, &[], "a.tar.zst");
    // Regression (sweep 2): `realpath` refuses a file followed by `/` or
    // `/.`, which `Path::components` drops.
    for suffix in ["/", "/."] {
        let slashed = format!("{}{suffix}", text(&bundle));
        let message = refused(supervisor, fake, &raw(&[slashed.as_str()]), &slashed);
        assert!(message.contains("Not a directory"), "{message}");
    }
    let mut unsealed_meta =
        crate::overlay_pack::bundle_meta(&bundle, Limits::resolve(None, None).unwrap()).unwrap();
    unsealed_meta.remove("sealed_at");
    let unsealed_bundle = world.path("unsealed.tar.zst");
    crate::overlay_pack::tests::retar_with(
        &bundle,
        &unsealed_bundle,
        "meta.json",
        &serde_json::to_vec(&unsealed_meta).unwrap(),
    );
    let message = refused(
        supervisor,
        fake,
        &request(&[&unsealed_bundle]),
        &text(&unsealed_bundle),
    );
    assert!(message.contains("unsealed"), "{message}");
    // The request's bundles together may take MAX_BUNDLE_BYTES on disk; the
    // sizes come from metadata, before any bundle is read.
    let big = world.path("big.tar.zst");
    fs::File::create(&big)
        .unwrap()
        .set_len(MAX_BUNDLE_BYTES)
        .unwrap();
    let message = refused(supervisor, fake, &request(&[&bundle, &big]), &text(&big));
    assert!(
        message.contains(&format!("{MAX_BUNDLE_BYTES}-byte cap")),
        "{message}"
    );
    // Exactly at the cap is read, and is no bundle.
    let message = refused(supervisor, fake, &request(&[&big]), &text(&big));
    assert!(message.contains("not a sealed layer bundle"), "{message}");

    // Base rule: lowers only on a local base without binds or recursion.
    for (name, source, options) in [
        (
            "bound",
            world.base.to_str().unwrap().to_owned(),
            BaseOptions {
                binds: vec![format!("/data={}", world.base.display())],
                ..Default::default()
            },
        ),
        (
            "recursive",
            world.base.to_str().unwrap().to_owned(),
            BaseOptions {
                recursive: true,
                ..Default::default()
            },
        ),
        (
            "remote",
            "hf://datasets/org/repo@rev/base.tar".to_owned(),
            BaseOptions::default(),
        ),
    ] {
        supervisor
            .handle(Operation::CreateBase {
                name: name.into(),
                source,
                options,
            })
            .unwrap();
        let request = json!({"version": 2, "op": "new", "base": name, "lowers": [text(&a)]});
        let message = refused(supervisor, fake, &request, &format!("base {name}"));
        assert!(message.contains("lowers"), "{message}");
    }

    // A bad journal glob, with or without lowers, through the child's parser.
    for request in [
        json!({"version": 2, "op": "new", "base": "task", "journal": {"exclude": ["x/../y"]}}),
        json!({"version": 2, "op": "new", "base": "task", "lowers": [text(&a)],
               "journal": {"exclude": ["x/../y"]}}),
    ] {
        refused(supervisor, fake, &request, "without . or .. components");
    }
    // Regression (sweep 2): the parser takes a NUL, which no argv can hold,
    // so it failed only at the spawn, once the attempt existed.
    let nul =
        json!({"version": 2, "op": "new", "base": "task", "journal": {"exclude": ["a\u{0}b"]}});
    refused(supervisor, fake, &nul, "contains NUL");
    // Regression (sweep 3): so did an exclude, valid to the parser, longer
    // than `execve` takes one argument (E2BIG).
    let long = vec!["x/**"; super::process::MAX_ARG_BYTES / 5].join(",");
    let long = json!({"version": 2, "op": "new", "base": "task", "journal": {"exclude": [long]}});
    refused(supervisor, fake, &long, "longer than one argument may be");
    // Regression (sweep 4): so did many short excludes, each spawnable, that
    // together took more of the argv than `execve` takes (E2BIG).
    let per = super::process::excludes_argv_bytes(&["a".to_owned()]);
    assert_eq!(
        per,
        "--journal-exclude=a".len() + 1 + std::mem::size_of::<usize>()
    );
    let fits = super::process::MAX_EXCLUDE_ARGV_BYTES / per;
    let many = |count: usize| json!({"version": 2, "op": "new", "base": "task", "journal": {"exclude": vec!["a"; count]}});
    refused(
        supervisor,
        fake,
        &many(fits + 1),
        "bytes of the child's arguments",
    );
    let reply = send(supervisor, &many(fits));
    assert_eq!(reply["ok"], true, "{reply}");
    supervisor.destroy_all().unwrap();
    // Regression (sweep 4): a derived enum also takes the map form, so
    // `reads: {"first": null}` was `first` and its attempt was created.
    for reads in [json!({"first": null}), json!({"all": null})] {
        let request =
            json!({"version": 2, "op": "new", "base": "task", "journal": {"reads": reads}});
        refused(supervisor, fake, &request, "expected a string");
    }

    // A hot journal OverlayMeta::read would roll back (writable, unsealed)
    // is refused, and the database and journal stay byte for byte.
    let hot = world.unsealed("hot", &[], Identity::Strong(X), &[("h", "h\n")]);
    hot_journal(&hot);
    let db = hot.join(HIDDEN_DB);
    let journal = PathBuf::from(format!("{}-journal", db.display()));
    let before = (fs::read(&db).unwrap(), fs::read(&journal).unwrap());
    refused(supervisor, fake, &request(&[&hot]), &text(&hot));
    assert_eq!(
        (fs::read(&db).unwrap(), fs::read(&journal).unwrap()),
        before
    );
    OverlayMeta::read(&hot).unwrap();
    assert!(
        !journal.exists(),
        "OverlayMeta::read rolls this journal back"
    );

    // Inside the RAM root, once known: refused lexically, so no tmpfs is
    // needed and the RAM directory is never created. `ram-root.json` holds
    // the canonical path `ram_root` writes (on macOS `/tmp` is a symlink to
    // `/private/tmp`), as `resolve` compares canonical prefixes.
    let state = private_tempdir();
    let ram_parent = private_tempdir();
    let ram = fs::canonicalize(ram_parent.path()).unwrap().join(format!(
        "ratarmount-sandbox-{:x}",
        <sha2::Sha256 as sha2::Digest>::digest(
            fs::canonicalize(state.path())
                .unwrap()
                .as_os_str()
                .as_encoded_bytes()
        )
    ));
    fs::write(
        state.path().join("ram-root.json"),
        serde_json::to_vec(&ram).unwrap(),
    )
    .unwrap();
    let ram_fake = Fake::default();
    let mut ram_supervisor =
        Supervisor::open(state.path(), 8, Duration::from_secs(10), ram_fake.clone()).unwrap();
    ram_supervisor
        .handle(Operation::CreateBase {
            name: "task".into(),
            source: world.base.to_str().unwrap().into(),
            options: BaseOptions::default(),
        })
        .unwrap();
    let inside = ram.join("attempt-x");
    let message = refused(
        &mut ram_supervisor,
        &ram_fake,
        &request(&[&inside]),
        &text(&inside),
    );
    assert!(
        message.contains("inside the supervisor's RAM directory"),
        "{message}"
    );
    // The same place reached through a symlink to the RAM root's parent is
    // refused once the link is followed, before `attempt-x` is looked up.
    let link_dir = private_tempdir();
    let link = link_dir.path().join("ram-parent");
    std::os::unix::fs::symlink(ram_parent.path(), &link).unwrap();
    let via_link = link.join(ram.file_name().unwrap()).join("attempt-x");
    let message = refused(
        &mut ram_supervisor,
        &ram_fake,
        &request(&[&via_link]),
        &text(&via_link),
    );
    assert!(
        message.contains("inside the supervisor's RAM directory"),
        "{message}"
    );
    assert!(!ram.exists());
}

/// Regression (R1b L4, old blocker 2): each lower's recorded prefix must be
/// the requested lowers beneath it, by layer digest, for directories and
/// bundles alike, and every lower must record the same strong or Git base.
#[test]
fn regression_supervisor_lower_stack_missing_prefix() {
    let world = World::new();
    let a = world.layer("a", &[], Identity::Strong(X), &[("a.txt", "a\n")]);
    let b = world.layer("b", &[&a], Identity::Strong(X), &[("b.txt", "b\n")]);
    let c = world.layer("c", &[&a, &b], Identity::Strong(X), &[("c.txt", "c\n")]);
    let a2 = world.layer("a2", &[], Identity::Strong(X), &[("a2.txt", "a2\n")]);
    let bundle_a = world.bundle(&a, &[], "a.tar.zst");
    let bundle_b = world.bundle(&b, &[&a], "b.tar.zst");
    let bundle_c = world.bundle(&c, &[&a, &b], "c.tar.zst");
    let a_copy = world.path("a-copy");
    copy_tree(&a, &a_copy);
    let (da, db, dc) = (digest(&a), digest(&b), digest(&c));
    assert_eq!(bundle_digest(&bundle_b), db);
    assert_ne!(digest(&a2), da);
    let mut setup = setup(&world);
    for (lowers, refused_lower) in [
        (vec![&*b], &b),
        (vec![&*bundle_b], &bundle_b),
        (vec![&*a2, &*bundle_b], &bundle_b),
        (vec![&*a, &*c], &c),
        (vec![&*a, &*bundle_c], &bundle_c),
    ] {
        let message = refused(
            &mut setup.supervisor,
            &setup.fake,
            &layered(2, &lowers),
            refused_lower.to_str().unwrap(),
        );
        assert!(message.contains("was sealed over the lowers"), "{message}");
    }
    for (lowers, digests) in [
        (vec![&*a, &*b], vec![da.clone(), db.clone()]),
        (vec![&*a, &*bundle_b], vec![da.clone(), db.clone()]),
        (
            vec![&*a, &*b, &*bundle_c],
            vec![da.clone(), db.clone(), dc.clone()],
        ),
        // Only digests count, never paths.
        (vec![&*bundle_a, &*b], vec![da.clone(), db.clone()]),
        (vec![&*a_copy, &*b], vec![da.clone(), db.clone()]),
    ] {
        accepted(&mut setup, &lowers, &digests);
    }

    // Base agreement, strong: A3 has A's change rows but records Y.
    let a3 = world.layer("a3", &[], Identity::Strong(Y), &[("a.txt", "a\n")]);
    assert_eq!(digest(&a3), da);
    assert_eq!(meta(&a).base_digest_kind(), Some("strong"));
    assert_eq!(meta(&a).base_digest(), Some(X));
    assert_eq!(meta(&a3).base_digest(), Some(Y));
    for lowers in [vec![&*a3, &*b], vec![&*a3, &*bundle_b]] {
        let message = refused(&mut setup.supervisor, &setup.fake, &layered(2, &lowers), Y);
        assert!(
            message.contains("every lower must record the same base"),
            "{message}"
        );
    }
    accepted(&mut setup, &[&a, &b], &[da.clone(), db.clone()]);

    // Base agreement, Git trees X and Y.
    let ga = world.layer("ga", &[], Identity::Git(TREE_X), &[("a.txt", "a\n")]);
    let gb = world.layer("gb", &[&ga], Identity::Git(TREE_X), &[("b.txt", "b\n")]);
    let ga3 = world.layer("ga3", &[], Identity::Git(TREE_Y), &[("a.txt", "a\n")]);
    let bundle_gb = world.bundle(&gb, &[&ga], "gb.tar.zst");
    assert_eq!(meta(&ga).base_digest_kind(), Some("git-tree"));
    assert_eq!(
        meta(&ga).base_digest(),
        Some(format!("git-tree:{TREE_X}").as_str())
    );
    assert_eq!(digest(&ga3), digest(&ga));
    for lowers in [vec![&*ga3, &*gb], vec![&*ga3, &*bundle_gb]] {
        let message = refused(
            &mut setup.supervisor,
            &setup.fake,
            &layered(2, &lowers),
            TREE_Y,
        );
        assert!(
            message.contains("every lower must record the same base"),
            "{message}"
        );
    }
    accepted(&mut setup, &[&ga, &gb], &[digest(&ga), digest(&gb)]);

    // Mixed kinds: a strong lower under a Git-tree lower.
    let mixed = world.layer("mixed", &[&a], Identity::Git(TREE_X), &[("m.txt", "m\n")]);
    let message = refused(
        &mut setup.supervisor,
        &setup.fake,
        &layered(2, &[&a, &mixed]),
        "git-tree",
    );
    assert!(
        message.contains("every lower must record the same base"),
        "{message}"
    );
}

/// Regression (R1b sweep 2, Codex B1): every lower must record a well-formed
/// base digest of its kind. Two lowers whose `base_digest` rows were both
/// missing compared equal, so a stack over two different bases was accepted;
/// one lower alone, or a bundle, was accepted with a missing or malformed one.
#[test]
fn regression_supervisor_lower_base_digest_required() {
    let world = World::new();
    let a = world.layer("a", &[], Identity::Strong(X), &[("a.txt", "a\n")]);
    let b = world.layer("b", &[&a], Identity::Strong(X), &[("b.txt", "b\n")]);
    // A3 has A's change rows, so A's layer digest, but records base Y.
    let a3 = world.layer("a3", &[], Identity::Strong(Y), &[("a.txt", "a\n")]);
    assert_eq!(digest(&a3), digest(&a));
    let ga = world.layer("ga", &[], Identity::Git(TREE_X), &[("a.txt", "a\n")]);
    let mut setup = setup(&world);
    fn refuse(setup: &mut Setup, lowers: &[&Path], name: &Path, why: &str) {
        let request = layered(2, lowers);
        let message = refused(
            &mut setup.supervisor,
            &setup.fake,
            &request,
            name.to_str().unwrap(),
        );
        assert!(message.contains(why), "{message}");
    }
    // The cross-base stack is refused while both digests are recorded, and
    // was accepted once both digest rows were deleted.
    refuse(
        &mut setup,
        &[&a3, &b],
        &b,
        "every lower must record the same base",
    );
    let edit = |from: &Path, name: &str, sql: &str| {
        let copy = world.path(name);
        copy_tree(from, &copy);
        rusqlite::Connection::open(copy.join(HIDDEN_DB))
            .unwrap()
            .execute_batch(sql)
            .unwrap();
        copy
    };
    let missing = "DELETE FROM meta WHERE key = 'base_digest'";
    let (a3_bare, b_bare) = (edit(&a3, "a3-bare", missing), edit(&b, "b-bare", missing));
    refuse(
        &mut setup,
        &[&a3_bare, &b_bare],
        &a3_bare,
        "with no base digest",
    );
    // Alone, a missing, empty or malformed digest of either kind.
    let set = |value: &str| format!("UPDATE meta SET value = '{value}' WHERE key = 'base_digest'");
    for (lower, why) in [
        (b_bare.clone(), "with no base digest"),
        (edit(&a, "empty", &set("")), "with no base digest"),
        (
            edit(&a, "short", &set(&format!("sha256:{}", "1".repeat(63)))),
            "malformed base digest",
        ),
        (
            edit(&a, "upper", &set(&format!("sha256:{}", "A".repeat(64)))),
            "malformed base digest",
        ),
        (
            edit(&a, "tree", &set(&format!("git-tree:{TREE_X}"))),
            "malformed base digest",
        ),
        (edit(&ga, "sha", &set(X)), "malformed base digest"),
    ] {
        refuse(&mut setup, &[&lower], &lower, why);
    }
    // A bundle whose `meta.json` has no digest.
    let bundle = world.bundle(&a, &[], "a.tar.zst");
    let mut meta =
        crate::overlay_pack::bundle_meta(&bundle, Limits::resolve(None, None).unwrap()).unwrap();
    meta.remove("base_digest");
    let bare_bundle = world.path("a-bare.tar.zst");
    crate::overlay_pack::tests::retar_with(
        &bundle,
        &bare_bundle,
        "meta.json",
        &serde_json::to_vec(&meta).unwrap(),
    );
    refuse(
        &mut setup,
        &[&bare_bundle],
        &bare_bundle,
        "with no base digest",
    );
    // Well-formed digests of both kinds are still accepted.
    accepted(&mut setup, &[&a, &b], &[digest(&a), digest(&b)]);
    accepted(&mut setup, &[&bundle, &b], &[digest(&a), digest(&b)]);
    accepted(&mut setup, &[&ga], &[digest(&ga)]);
}

/// Regression (R1b L5): a reordered prefix is refused, also when every count
/// matches and only the order differs.
#[test]
fn regression_supervisor_lower_stack_reordered_prefix() {
    let world = World::new();
    let a = world.layer("a", &[], Identity::Strong(X), &[("a.txt", "a\n")]);
    let b = world.layer("b", &[&a], Identity::Strong(X), &[("b.txt", "b\n")]);
    let c = world.layer("c", &[&a, &b], Identity::Strong(X), &[("c.txt", "c\n")]);
    let bundle_b = world.bundle(&b, &[&a], "b.tar.zst");
    let mut setup = setup(&world);
    for lowers in [vec![&*b, &*a, &*c], vec![&*bundle_b, &*a, &*c]] {
        let message = refused(
            &mut setup.supervisor,
            &setup.fake,
            &layered(2, &lowers),
            "(position 0)",
        );
        assert!(message.contains(lowers[0].to_str().unwrap()), "{message}");
    }
    // Equal counts, order alone differs.
    let a0 = world.layer("a0", &[], Identity::Strong(X), &[("x.txt", "x\n")]);
    let b0 = world.layer("b0", &[], Identity::Strong(X), &[("y.txt", "y\n")]);
    let a1 = world.layer("a1", &[&b0], Identity::Strong(X), &[("x.txt", "x\n")]);
    let b1 = world.layer("b1", &[&a0], Identity::Strong(X), &[("y.txt", "y\n")]);
    let c = world.layer("c2", &[&a0, &b1], Identity::Strong(X), &[("z.txt", "z\n")]);
    let bundle_c = world.bundle(&c, &[&a0, &b1], "c.tar.zst");
    let (da, db) = (digest(&a0), digest(&b0));
    assert_eq!(digest(&a1), da);
    assert_eq!(digest(&b1), db);
    for lowers in [vec![&*b0, &*a1, &*c], vec![&*b0, &*a1, &*bundle_c]] {
        let message = refused(
            &mut setup.supervisor,
            &setup.fake,
            &layered(2, &lowers),
            "(position 2)",
        );
        assert!(
            message.contains(&format!("[{da}, {db}]"))
                && message.contains(&format!("[{db}, {da}]")),
            "{message}"
        );
    }
    accepted(
        &mut setup,
        &[&a0, &b1, &c],
        &[da.clone(), db.clone(), digest(&c)],
    );
}

/// The last `count` paths the Fake cleaned up.
fn cleaned(fake: &Fake, count: usize) -> Vec<PathBuf> {
    let state = fake.0.lock().unwrap();
    state.cleaned[state.cleaned.len().saturating_sub(count)..].to_vec()
}

/// A layered batch of 2 that ends in `code`, rolled back: no attempt, no
/// `taken_lowers` entry, `attempts/` empty and both attempts cleaned up.
fn rolled_back(setup: &mut Setup, request: &Value, code: &str) -> Value {
    let reply = send(&mut setup.supervisor, request);
    assert_eq!(reply["error"]["code"], code, "{reply}");
    assert!(setup.supervisor.attempts.is_empty());
    assert!(setup.supervisor.taken_lowers.is_empty());
    let attempts = setup.supervisor.root.join("attempts");
    assert_eq!(fs::read_dir(&attempts).unwrap().count(), 0);
    let cleaned = cleaned(&setup.fake, 2);
    assert_eq!(cleaned.len(), 2);
    assert_ne!(cleaned[0], cleaned[1]);
    assert!(cleaned.iter().all(|path| path.starts_with(&attempts)));
    reply
}

fn arm(fake: &Fake, hook: fn(&mut super::tests::FakeState) -> &mut Option<Hook>, run: Hook) {
    *hook(&mut fake.0.lock().unwrap()) = Some(run);
}

/// Regression (R1b L6, Keystone #3): the window between validation and the
/// mount is closed by re-checking once every child is ready: what the child
/// reports, and the metadata of what it composed, must equal what was
/// validated, or the batch is rolled back with `lower_changed`.
#[test]
fn regression_supervisor_lower_recheck_after_ready() {
    let world = World::new();
    let mut setup = setup(&world);
    let base = world.base.clone();
    let strong = Identity::Strong(X);

    // (i) Unsealed, edited and resealed before the child's first open.
    let a = world.layer("a-i", &[], strong, &[("a.txt", "a\n")]);
    let (layer, resealed) = (a.clone(), base.clone());
    arm(
        &setup.fake,
        |s| &mut s.before_capture,
        Box::new(move || reseal(&resealed, &layer, &[], strong, "a.txt")),
    );
    let reply = rolled_back(&mut setup, &layered(2, &[&a]), "lower_changed");
    assert!(reply["error"]["message"]
        .as_str()
        .unwrap()
        .contains("lower 0"));

    // (ii) A→B→A: B sits at A's path while the child opens it; A is back,
    // unchanged, by the re-check, so only the child's records refuse it.
    let a = world.layer("a-ii", &[], strong, &[("a.txt", "a\n")]);
    let b = world.layer("b-ii", &[], strong, &[("b.txt", "b\n")]);
    let original = record(&a);
    let aside = world.path("a-ii.aside");
    let (from, to, away) = (b.clone(), a.clone(), aside.clone());
    arm(
        &setup.fake,
        |s| &mut s.before_capture,
        Box::new(move || {
            rename_dir(&to, &away);
            rename_dir(&from, &to);
        }),
    );
    let (from, to, away) = (b.clone(), a.clone(), aside.clone());
    arm(
        &setup.fake,
        |s| &mut s.after_compose,
        Box::new(move || {
            rename_dir(&to, &from);
            rename_dir(&away, &to);
        }),
    );
    let reply = rolled_back(&mut setup, &layered(2, &[&a]), "lower_changed");
    assert!(reply["error"]["message"]
        .as_str()
        .unwrap()
        .contains(&digest(&b)));
    assert_eq!(record(&a), original);

    // (iii) The bundle replaced by a bundle of another layer.
    let a = world.layer("a-iii", &[], strong, &[("a.txt", "a\n")]);
    let b = world.layer("b-iii", &[&a], strong, &[("b.txt", "b\n")]);
    let other = world.layer("other-iii", &[&a], strong, &[("o.txt", "o\n")]);
    let bundle = world.bundle(&b, &[&a], "b-iii.tar.zst");
    let replacement = world.bundle(&other, &[&a], "other-iii.tar.zst");
    let target = bundle.clone();
    arm(
        &setup.fake,
        |s| &mut s.before_capture,
        Box::new(move || {
            fs::copy(&replacement, &target).unwrap();
        }),
    );
    rolled_back(&mut setup, &layered(2, &[&a, &bundle]), "lower_changed");

    // (iv) The same seal pair: a forced pack of B naming another strong base.
    let a = world.layer("a-iv", &[], strong, &[("a.txt", "a\n")]);
    let b = world.layer("b-iv", &[&a], strong, &[("b.txt", "b\n")]);
    let bundle = world.bundle(&b, &[&a], "b-iv.tar.zst");
    let forced = world.path("b-iv-forced.tar.zst");
    let rows = BTreeMap::from([
        ("base_digest".to_owned(), Y.to_owned()),
        ("base_digest_kind".to_owned(), "strong".to_owned()),
        ("base_kind".to_owned(), "directory".to_owned()),
        (
            "base_mismatch_forced_at".to_owned(),
            "2026-10-31T00:00:00Z".to_owned(),
        ),
    ]);
    crate::overlay_pack::pack(
        &b,
        &forced,
        view(&base, std::slice::from_ref(&a)),
        &PackOptions {
            base_rows: Some(rows),
            ..Default::default()
        },
    )
    .unwrap();
    let limits = Limits::resolve(None, None).unwrap();
    let (validated, substitute) = (
        crate::overlay_pack::bundle_meta(&bundle, limits).unwrap(),
        crate::overlay_pack::bundle_meta(&forced, limits).unwrap(),
    );
    for key in ["layer_digest", "sealed_at"] {
        assert_eq!(validated[key], substitute[key], "{key}");
    }
    assert_ne!(validated, substitute);
    let target = bundle.clone();
    arm(
        &setup.fake,
        |s| &mut s.before_capture,
        Box::new(move || {
            fs::copy(&forced, &target).unwrap();
        }),
    );
    let reply = rolled_back(&mut setup, &layered(2, &[&a, &bundle]), "lower_changed");
    assert!(reply["error"]["message"]
        .as_str()
        .unwrap()
        .contains("base_mismatch_forced_at"));

    // (v) Resealed between the child's two opens: its records carry the old
    // seal pair, and the composed directory's metadata differs.
    let a = world.layer("a-v", &[], strong, &[("a.txt", "a\n")]);
    let (layer, resealed) = (a.clone(), base.clone());
    arm(
        &setup.fake,
        |s| &mut s.between_capture_and_compose,
        Box::new(move || reseal(&resealed, &layer, &[], strong, "a.txt")),
    );
    let reply = rolled_back(&mut setup, &layered(2, &[&a]), "lower_changed");
    assert!(reply["error"]["message"]
        .as_str()
        .unwrap()
        .contains("unsealed_at"));

    // (vi) The inspection fails: mount_failed, rolled back.
    let a = world.layer("a-vi", &[], strong, &[("a.txt", "a\n")]);
    setup.fake.0.lock().unwrap().fail_lower_layers = true;
    rolled_back(&mut setup, &layered(2, &[&a]), "mount_failed");
    setup.fake.0.lock().unwrap().fail_lower_layers = false;

    // (vii) Untouched: the records are kept for diff.
    let calls = setup.fake.0.lock().unwrap().lower_layer_calls;
    let reply = send(&mut setup.supervisor, &layered(2, &[&a]));
    assert_eq!(reply["ok"], true, "{reply}");
    for attempt in reply["result"].as_array().unwrap() {
        let id = attempt["id"].as_str().unwrap();
        assert_eq!(setup.supervisor.taken_lowers[id], Some(vec![record(&a)]));
    }
    assert_eq!(setup.fake.0.lock().unwrap().lower_layer_calls, calls + 2);
    setup.supervisor.destroy_all().unwrap();
    // A plain attempt makes no inspection call and has no entry.
    let reply = send(
        &mut setup.supervisor,
        &json!({"version": 2, "op": "new", "base": "task"}),
    );
    assert_eq!(reply["ok"], true, "{reply}");
    assert!(setup.supervisor.taken_lowers.is_empty());
    assert_eq!(setup.fake.0.lock().unwrap().lower_layer_calls, calls + 2);
    setup.supervisor.destroy_all().unwrap();

    // (viii) Under a request_id: a complete rollback is retryable; a kept
    // attempt makes it failed, and diff of it never renders a patch.
    let a = world.layer("a-viii", &[], strong, &[("a.txt", "a\n")]);
    let (layer, resealed) = (a.clone(), base.clone());
    arm(
        &setup.fake,
        |s| &mut s.before_capture,
        Box::new(move || reseal(&resealed, &layer, &[], strong, "a.txt")),
    );
    let mut request = layered(2, &[&a]);
    request["request_id"] = json!("r-retryable");
    rolled_back(&mut setup, &request, "lower_changed");
    assert_eq!(
        setup.supervisor.requests.status("r-retryable"),
        Some(Status::Retryable)
    );
    let a = world.layer("a-viii-kept", &[], strong, &[("a.txt", "a\n")]);
    let (layer, resealed) = (a.clone(), base.clone());
    arm(
        &setup.fake,
        |s| &mut s.before_capture,
        Box::new(move || reseal(&resealed, &layer, &[], strong, "a.txt")),
    );
    setup.fake.0.lock().unwrap().refuse_cleanup = true;
    let mut request = layered(2, &[&a]);
    request["request_id"] = json!("r-failed");
    let reply = send(&mut setup.supervisor, &request);
    assert_eq!(reply["error"]["code"], "lower_changed", "{reply}");
    assert_eq!(
        setup.supervisor.requests.status("r-failed"),
        Some(Status::Failed)
    );
    let kept: Vec<String> = setup.supervisor.attempts.keys().cloned().collect();
    assert_eq!(kept.len(), 2);
    for id in &kept {
        assert_eq!(setup.supervisor.taken_lowers[id], None);
        let diff = send(
            &mut setup.supervisor,
            &json!({"version": 1, "op": "diff", "id": id, "git": true}),
        );
        assert_eq!(diff["error"]["code"], "diff_failed", "{diff}");
        assert!(diff["error"]["message"]
            .as_str()
            .unwrap()
            .contains("never verified"));
    }
    setup.fake.0.lock().unwrap().refuse_cleanup = false;
    setup.supervisor.destroy_all().unwrap();
    assert!(setup.supervisor.taken_lowers.is_empty());

    // (ix) Regression (sweep 4, Claude #2): a byte-identical copy at another
    // path. A symlink to the copy replaces the validated directory before
    // the child's first open, and the child canonicalizes it, so it takes
    // the copy: digest, seal time and every metadata row equal A's, and only
    // the path in its record refuses it.
    let a = world.layer("a-ix", &[], strong, &[("a.txt", "a\n")]);
    let copy = world.path("a-ix.copy");
    copy_tree(&a, &copy);
    assert_eq!(meta(&copy).values(), meta(&a).values());
    let (target, aside, link) = (a.clone(), world.path("a-ix.aside"), copy.clone());
    arm(
        &setup.fake,
        |s| &mut s.before_capture,
        Box::new(move || {
            rename_dir(&target, &aside);
            std::os::unix::fs::symlink(&link, &target).unwrap();
        }),
    );
    let reply = rolled_back(&mut setup, &layered(2, &[&a]), "lower_changed");
    let message = reply["error"]["message"].as_str().unwrap();
    assert!(message.contains("was validated as"), "{message}");
    assert!(
        message.contains(&format!(
            "the mount took {}",
            copy.canonicalize().unwrap().display()
        )),
        "{message}"
    );
}

/// Regression (R1b L7): `diff` of a layered attempt is rendered against
/// base + lowers, never against the bare base, and refuses a lower that
/// changed since the attempt mounted it, without touching it.
#[test]
fn regression_supervisor_lower_diff_composes_stack() {
    let world = World::new();
    let a = world.layer(
        "a",
        &[],
        Identity::Strong(X),
        &[
            ("prepared.txt", "prepared\n"),
            ("base.txt", "edited by a\n"),
            ("untouched.txt", "untouched\n"),
        ],
    );
    let mut setup = setup(&world);
    let mut start = |request: Value| -> (String, PathBuf) {
        let reply = send(&mut setup.supervisor, &request);
        assert_eq!(reply["ok"], true, "{reply}");
        let attempt = &reply["result"][0];
        let top = PathBuf::from(attempt["overlay_dir"].as_str().unwrap());
        fs::write(top.join("prepared.txt"), "attempt\n").unwrap();
        (attempt["id"].as_str().unwrap().to_owned(), top)
    };
    let (layered_id, _) = start(layered(1, &[&a]));
    let (plain_id, _) = start(json!({"version": 1, "op": "new", "base": "task"}));
    let diff = |setup: &mut Setup, version: u32, id: &str| {
        send(
            &mut setup.supervisor,
            &json!({"version": version, "op": "diff", "id": id, "git": true}),
        )
    };
    for version in [1, 2] {
        let reply = diff(&mut setup, version, &layered_id);
        assert_eq!(reply["version"], version);
        let patch = reply["result"]["patch"].as_str().unwrap();
        assert!(patch.contains("-prepared\n+attempt\n"), "{patch}");
        assert_eq!(patch.matches("diff --git").count(), 1, "{patch}");
        assert!(!patch.contains("base.txt") && !patch.contains("untouched.txt"));
        // A plain attempt on the same base renders against the bare base.
        let patch = diff(&mut setup, version, &plain_id)["result"]["patch"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(patch.contains("new file mode") && patch.contains("+attempt\n"));
        assert!(!patch.contains("-prepared"), "{patch}");
    }
    reseal(&world.base, &a, &[], Identity::Strong(X), "prepared.txt");
    let before = snapshot(&a);
    let reply = diff(&mut setup, 2, &layered_id);
    assert_eq!(reply["error"]["code"], "diff_failed", "{reply}");
    let message = reply["error"]["message"].as_str().unwrap();
    assert!(
        message.contains(a.canonicalize().unwrap().to_str().unwrap()),
        "{message}"
    );
    assert_eq!(snapshot(&a), before);
    setup.supervisor.destroy_all().unwrap();
}

/// Regression (R1b L8): the child's inspection socket reports the lower
/// records its overlay recorded (`[]` without lowers), and fails, without
/// hanging, once the overlay is gone.
#[test]
fn regression_supervisor_lower_inspection_reports_records() {
    let dir = private_tempdir();
    let base = dir.path().join("base");
    fs::create_dir(&base).unwrap();
    let root = dir.path().join("attempt");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let attempt = Attempt {
        id: "attempt-1".into(),
        base: "task".into(),
        path: root.join("mnt"),
        overlay_dir: root.join("overlay"),
        status: "ready".into(),
    };
    let source: Arc<dyn MountSource> = Arc::new(FolderMountSource::new(&base).unwrap());
    let records = vec![
        LowerLayerRecord {
            path: "/layers/a".into(),
            layer_digest: format!("sha256:{}", "a".repeat(64)),
            sealed_at: "2026-10-31T00:00:00Z".into(),
        },
        LowerLayerRecord {
            path: "/layers/b".into(),
            layer_digest: format!("sha256:{}", "b".repeat(64)),
            sealed_at: "2026-10-31T00:00:01Z".into(),
        },
    ];
    let socket = super::inspection::socket_path(&attempt);
    let ask = || super::inspection::lower_layers(&attempt, Duration::from_secs(5));
    for (top, lowers) in [("overlay", records.clone()), ("plain", Vec::new())] {
        let overlay = Arc::new(
            crate::base_identity::fixtures::overlay_over(
                source.clone(),
                root.join(top),
                base.to_str().unwrap(),
                lowers.clone(),
            )
            .unwrap(),
        );
        let inspector = super::start_inspection(&socket, &overlay).unwrap();
        assert_eq!(ask().unwrap(), lowers);
        drop(inspector);
    }
    let overlay =
        Arc::new(crate::base_identity::fixtures::new_overlay(source, root.join("gone")).unwrap());
    let inspector = super::start_inspection(&socket, &overlay).unwrap();
    drop(overlay);
    let started = Instant::now();
    assert!(ask().is_err());
    assert!(started.elapsed() < Duration::from_secs(5));
    drop(inspector);
}

/// Regression (R1b sweep 1, Claude N4): `lower_changed` names the differing
/// rows and their values, redacted as `overlay info` redacts them: a layer an
/// older build wrote may still hold a credentialed `base_url`, and the
/// `base_index_path` that embeds it.
#[test]
fn regression_supervisor_lower_changed_message_is_redacted() {
    let world = World::new();
    let a = world.layer("a", &[], Identity::Strong(X), &[("a.txt", "a\n")]);
    let mut validated = meta(&a).values().clone();
    for (key, value) in [
        ("base_url", "https://user:secret@example.com/b.tar"),
        (
            "base_index_path",
            "/cache/https:__user:secret@example.com_b.tar.index.sqlite",
        ),
    ] {
        validated.insert(key.into(), value.into());
    }
    let lower = super::lowers::Lower {
        kind: super::lowers::Kind::Directory,
        path: a.canonicalize().unwrap(),
        meta: validated,
    };
    let error = super::lowers::recheck("attempt-1", &[lower], &[record(&a)]).unwrap_err();
    assert_eq!(error.code, "lower_changed");
    for expected in ["base_url: \"https://", "base_index_path: (redacted)"] {
        assert!(error.message.contains(expected), "{}", error.message);
    }
    assert!(!error.message.contains("secret"), "{}", error.message);
}

/// Regression (R1b sweep 2, Claude N1): a rollback that keeps attempts stores
/// the `lower_changed` message verbatim in a `failed` request line, which R1a
/// bounds (`LINE_BOUND`, sized for messages of a few KiB). Megabyte metadata
/// rows, or a child reporting a megabyte field, made the message as large;
/// each shown key and value is cut, and so is the whole message.
#[test]
fn regression_supervisor_lower_changed_message_is_bounded() {
    use super::lowers::{recheck, Kind, Lower, MESSAGE_BYTES};
    let world = World::new();
    let a = world.layer("a", &[], Identity::Strong(X), &[("a.txt", "a\n")]);
    let huge = "v".repeat(1 << 20);
    let lower = |rows: Vec<(String, String)>| Lower {
        kind: Kind::Directory,
        path: a.canonicalize().unwrap(),
        meta: meta(&a).values().clone().into_iter().chain(rows).collect(),
    };
    // `…` takes three bytes.
    let bounded = |message: &str| message.len() <= MESSAGE_BYTES + 3;
    let rows = (0..8)
        .map(|i| (format!("k{i}-{}", "x".repeat(64 << 10)), huge.clone()))
        .collect();
    let error = recheck("attempt-1", &[lower(rows)], &[record(&a)]).unwrap_err();
    assert_eq!(error.code, "lower_changed");
    assert!(bounded(&error.message), "{}", error.message.len());
    assert!(error.message.contains("k0-xxx"), "{}", error.message);
    // What the child reports.
    let mut reported = record(&a);
    reported.sealed_at = huge.clone();
    reported.layer_digest = huge;
    let error = recheck("attempt-1", &[lower(Vec::new())], &[reported]).unwrap_err();
    assert_eq!(error.code, "lower_changed");
    assert!(bounded(&error.message), "{}", error.message.len());
    assert!(
        error.message.contains("was validated as layer_digest"),
        "{}",
        error.message
    );
}

/// Regression (R1b sweep 4, Claude #5): the stack check quoted a lower's
/// `lower_layers` row whole: its recorded digests in a stack mismatch, or the
/// row itself in serde_json's message for a row of another type. A megabyte
/// row made a megabyte refusal; both are cut to `MESSAGE_BYTES`.
#[test]
fn regression_supervisor_lower_stack_message_is_bounded() {
    use super::lowers::MESSAGE_BYTES;
    let world = World::new();
    let a = world.layer("a", &[], Identity::Strong(X), &[("a.txt", "a\n")]);
    let mut setup = setup(&world);
    let huge = "v".repeat(1 << 20);
    let listed = vec![
        LowerLayerRecord {
            path: "/elsewhere".into(),
            layer_digest: huge.clone(),
            sealed_at: String::new(),
        };
        4
    ];
    for (name, row, why) in [
        (
            "listed",
            serde_json::to_string(&listed).unwrap(),
            "(position 0) was sealed over the lowers [vvv",
        ),
        (
            "string",
            serde_json::to_string(&huge).unwrap(),
            "invalid lower_layers row: invalid type: string \"vvv",
        ),
    ] {
        let copy = world.path(name);
        copy_tree(&a, &copy);
        rusqlite::Connection::open(copy.join(HIDDEN_DB))
            .unwrap()
            .execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES ('lower_layers', ?1)",
                [&row],
            )
            .unwrap();
        let message = refused(
            &mut setup.supervisor,
            &setup.fake,
            &layered(2, &[&copy]),
            copy.to_str().unwrap(),
        );
        assert!(message.contains(why), "{name}: {message}");
        // `…` takes three bytes.
        assert!(
            message.len() <= MESSAGE_BYTES + 3,
            "{name}: {}",
            message.len()
        );
    }
}

/// Regression (R1b sweep 1, Claude #1): the bundles of one request share one
/// budget of decoded bytes, enforced while they are read. The on-disk cap
/// cannot bound decompression: a bundle of a few KiB that decodes past the
/// budget is refused as soon as it does, never decompressed whole in the
/// serve loop; and two bundles that each fit alone are refused together.
#[test]
fn regression_supervisor_lower_bundle_decoded_budget() {
    const BUDGET: u64 = 4 << 20;
    let world = World::new();
    let a = world.layer("a", &[], Identity::Strong(X), &[("a.txt", "a\n")]);
    let bundle = world.bundle(&a, &[], "a.tar.zst");
    let mut setup = setup(&world);
    setup.supervisor.lower_decode_budget = BUDGET;
    let budget = format!("{BUDGET}-byte budget");

    let bomb = world.path("bomb.tar.zst");
    crate::overlay_pack::tests::retar_padded(&bundle, &bomb, 64 << 20);
    assert!(fs::metadata(&bomb).unwrap().len() < 1 << 20);
    crate::overlay_pack::take_decoded_bytes();
    let message = refused(
        &mut setup.supervisor,
        &setup.fake,
        &layered(2, &[&bomb]),
        bomb.to_str().unwrap(),
    );
    let decoded = crate::overlay_pack::take_decoded_bytes();
    assert!(message.contains(&budget), "{message}");
    assert!(
        decoded < 2 * BUDGET,
        "decoded {decoded} bytes before refusing"
    );

    // 3 MiB each: either alone fits, and every request has a budget of its own.
    let (one, two) = (world.path("one.tar.zst"), world.path("two.tar.zst"));
    crate::overlay_pack::tests::retar_padded(&bundle, &one, 3 << 20);
    crate::overlay_pack::tests::retar_padded(&bundle, &two, 3 << 20);
    let message = refused(
        &mut setup.supervisor,
        &setup.fake,
        &layered(2, &[&one, &two]),
        two.to_str().unwrap(),
    );
    assert!(message.contains(&budget), "{message}");
    accepted(&mut setup, &[&one], &[digest(&a)]);
    accepted(&mut setup, &[&two], &[digest(&a)]);
}

/// Regression (R1b sweep 1, Codex #2): the inspection's timeout bounds the
/// whole exchange, not each read. A child that trickles its reply one byte
/// every 50 ms fails at the deadline instead of taking as long as it likes.
#[test]
fn regression_supervisor_lower_inspection_deadline_is_absolute() {
    use std::io::{Read, Write};
    let dir = private_tempdir();
    let root = dir.path().join("attempt");
    fs::create_dir(&root).unwrap();
    let attempt = Attempt {
        id: "attempt-1".into(),
        base: "task".into(),
        path: root.join("mnt"),
        overlay_dir: root.join("overlay"),
        status: "ready".into(),
    };
    let listener =
        std::os::unix::net::UnixListener::bind(super::inspection::socket_path(&attempt)).unwrap();
    // `[]` padded to 41 bytes: about 2 s at one byte per 50 ms.
    let reply = [b"[".as_slice(), &[b' '; 38], b"]\n"].concat();
    let child = std::thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            let mut command = [0u8; 13];
            stream.read_exact(&mut command).unwrap();
            assert_eq!(&command, b"lower_layers\n");
            for byte in &reply {
                if stream.write_all(std::slice::from_ref(byte)).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    });
    let started = Instant::now();
    assert!(super::inspection::lower_layers(&attempt, Duration::from_millis(200)).is_err());
    assert!(
        started.elapsed() < Duration::from_millis(1500),
        "{:?}",
        started.elapsed()
    );
    // Control: the same trickle within a longer deadline is read whole.
    let records = super::inspection::lower_layers(&attempt, Duration::from_secs(30)).unwrap();
    assert!(records.is_empty());
    child.join().unwrap();
}

/// Regression (R1b sweep 1, Codex #2): a re-check that completes after the
/// batch deadline is a `timeout` and the batch is rolled back, as if it had
/// not completed; no inspection is given more than the time left.
#[test]
fn regression_supervisor_lower_recheck_completes_after_deadline() {
    let world = World::new();
    let a = world.layer("a", &[], Identity::Strong(X), &[("a.txt", "a\n")]);
    let timeout = Duration::from_secs(2);
    let mut setup = setup_with(&world, timeout);
    // In time: accepted.
    setup.fake.0.lock().unwrap().lower_layers_delay = Some(Duration::from_millis(100));
    let reply = send(&mut setup.supervisor, &layered(1, &[&a]));
    assert_eq!(reply["ok"], true, "{reply}");
    setup.supervisor.destroy_all().unwrap();
    // The only attempt's answer arrives after the deadline.
    setup.fake.0.lock().unwrap().lower_layers_delay = Some(timeout + Duration::from_secs(1));
    let reply = send(&mut setup.supervisor, &layered(1, &[&a]));
    assert_eq!(reply["error"]["code"], "timeout", "{reply}");
    assert!(
        reply["error"]["message"]
            .as_str()
            .unwrap()
            .contains("lower re-check timed out"),
        "{reply}"
    );
    assert!(setup.supervisor.attempts.is_empty() && setup.supervisor.taken_lowers.is_empty());
    let attempts = setup.supervisor.root.join("attempts");
    assert_eq!(fs::read_dir(&attempts).unwrap().count(), 0);
    let state = setup.fake.0.lock().unwrap();
    assert_eq!(state.lower_layer_calls, 2);
    assert_eq!(state.cleaned.len(), 2);
    assert!(state.cleaned[1].starts_with(&attempts));
    assert!(
        state.lower_layer_timeouts.iter().all(|t| *t <= timeout),
        "{:?}",
        state.lower_layer_timeouts
    );
}
