//! #341: preimage pins of layers sealed over a local directory base.
//!
//! A canonical row carries the layer's side only, so a base file edited to a
//! third value with its size and mtime kept leaves a `modified` row unchanged.
//! The seal records the base side of every changed path; every reuse rehashes
//! those entries (and only those).

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use ratarmount_compositing::overlay_seal::{self, PREIMAGES_UNBOUND, PREIMAGE_DIGEST_KEY};
use ratarmount_compositing::{
    compose_stack, BaseDigestRequest, FolderMountSource, Immutability, LowerLayerRecord,
    OverlayMeta, WriteOverlay, HIDDEN_DB,
};
use ratarmount_core::MountSource;
use ratarmount_core::{ArchiveRead, FileInfo, ListResult};

use super::{pack, unpack, PackOptions};
use crate::base_identity::fixtures;

struct Base {
    tmp: tempfile::TempDir,
    dir: PathBuf,
    source: Arc<dyn MountSource>,
}

impl Base {
    /// A directory base holding `files` (mode 0644, a fixed old mtime).
    fn new(files: &[(&str, &[u8])]) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("base");
        fs::create_dir(&dir).unwrap();
        for (name, bytes) in files {
            let path = dir.join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            set_mtime(&path, 1_000_000);
        }
        let source: Arc<dyn MountSource> = Arc::new(FolderMountSource::new(&dir).unwrap());
        Self { tmp, dir, source }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.tmp.path().join(name)
    }

    /// A sealed layer `name` over this base and the sealed `lowers` beneath
    /// it, made by `edit`, with the given base identity request.
    fn layer_with(
        &self,
        name: &str,
        lowers: &[&Path],
        digest: BaseDigestRequest,
        edit: impl FnOnce(&WriteOverlay, &Path),
    ) -> PathBuf {
        let dir = self.path(name);
        let view = self.view(lowers);
        let records = lowers
            .iter()
            .map(|path| {
                let meta = OverlayMeta::read(path).unwrap().unwrap();
                LowerLayerRecord {
                    path: path.canonicalize().unwrap(),
                    layer_digest: meta.get("layer_digest").unwrap().into(),
                    sealed_at: meta.get("sealed_at").unwrap().into(),
                }
            })
            .collect();
        let overlay = fixtures::overlay_over_with(
            view.clone(),
            &dir,
            self.dir.to_str().unwrap(),
            records,
            digest,
        )
        .unwrap();
        edit(&overlay, &dir);
        drop(overlay);
        fixtures::seal(&dir, view).unwrap();
        dir
    }

    fn layer(
        &self,
        name: &str,
        lowers: &[&Path],
        edit: impl FnOnce(&WriteOverlay, &Path),
    ) -> PathBuf {
        self.layer_with(name, lowers, BaseDigestRequest::Compute, edit)
    }

    /// The base with the sealed `lowers` composed on it.
    fn view(&self, lowers: &[&Path]) -> Arc<dyn MountSource> {
        let layers: Vec<_> = lowers
            .iter()
            .map(|path| (path.to_path_buf(), Immutability::Immutable))
            .collect();
        compose_stack(self.source.clone(), &layers).unwrap()
    }

    /// `MountLowerStack::open_in` over this base, with a private bundle cache.
    fn open(&self, lowers: &[PathBuf]) -> Result<(), String> {
        crate::MountLowerStack::open_in(
            self.source.clone(),
            None,
            lowers,
            false,
            Some(&self.path("cache")),
            &crate::lower_stack_services(),
        )
        .map(|_| ())
    }
}

impl Drop for Base {
    fn drop(&mut self) {
        super::cleanup_dirs(&super::open_root(self.tmp.path()).unwrap());
    }
}

fn set_mtime(path: &Path, secs: u64) {
    File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_times(
            fs::FileTimes::new()
                .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs)),
        )
        .unwrap();
}

/// Rewrite `path` with `bytes`, keeping its mtime (the edit a weak identity
/// cannot see when the size is the same).
fn edit_keeping_mtime(path: &Path, bytes: &[u8]) {
    let mtime = fs::metadata(path).unwrap().modified().unwrap();
    fs::write(path, bytes).unwrap();
    File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(mtime))
        .unwrap();
}

/// Replace `path` in the overlay with `bytes` (mode 0644).
fn replace(overlay: &WriteOverlay, dir: &Path, path: &str, bytes: &[u8]) {
    overlay.unlink(&format!("/{path}")).unwrap();
    let fd = overlay.create_file(&format!("/{path}"), 0o644).unwrap();
    overlay.close_overlay_fd(fd);
    fs::write(dir.join(path), bytes).unwrap();
}

/// The recorded pins, path to content hash.
fn pins(layer: &Path) -> BTreeMap<String, String> {
    let conn = rusqlite::Connection::open_with_flags(
        layer.join(HIDDEN_DB),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let mut stmt = conn
        .prepare("SELECT path,hash FROM seal_preimages")
        .unwrap();
    stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

fn has_pin_table(layer: &Path) -> bool {
    let conn = rusqlite::Connection::open_with_flags(
        layer.join(HIDDEN_DB),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='seal_preimages')",
        [],
        |r| r.get(0),
    )
    .unwrap()
}

/// Run `f` on a writable connection to a sealed layer's database (a casual
/// tamperer: no reseal), restoring the read-only modes afterwards.
fn tamper(layer: &Path, f: impl FnOnce(&rusqlite::Connection)) {
    let db = layer.join(HIDDEN_DB);
    fs::set_permissions(layer, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(&db, fs::Permissions::from_mode(0o644)).unwrap();
    {
        let conn = rusqlite::Connection::open(&db).unwrap();
        f(&conn);
    }
    fs::set_permissions(&db, fs::Permissions::from_mode(0o444)).unwrap();
    fs::set_permissions(layer, fs::Permissions::from_mode(0o555)).unwrap();
}

fn sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("sha256:{:x}", Sha256::digest(bytes))
}

struct ObservedBase {
    inner: Arc<dyn MountSource>,
    opens: AtomicUsize,
    unreadable: bool,
}

impl MountSource for ObservedBase {
    fn list(&self, path: &str) -> Option<ListResult> {
        self.inner.list(path)
    }

    fn lookup(&self, path: &str, version: i32) -> Option<FileInfo> {
        self.inner.lookup(path, version)
    }

    fn open(&self, fi: &FileInfo, buffering: i32) -> io::Result<Box<dyn ArchiveRead>> {
        self.opens.fetch_add(1, Ordering::Relaxed);
        if self.unreadable {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        self.inner.open(fi, buffering)
    }

    fn is_immutable(&self) -> bool {
        self.inner.is_immutable()
    }
}

/// Regression: the ordinary pack bypass was fixed using its existing
/// hashes; forcing a pack must not read the base files two or three times.
#[test]
fn regression_preimage_pin_pack_reads_each_preimage_once() {
    let base = Base::new(&[("f", b"old"), ("untouched", b"do not read")]);
    let layer = base.layer("layer", &[], |ov, dir| replace(ov, dir, "f", b"new"));
    let observed = Arc::new(ObservedBase {
        inner: base.source.clone(),
        opens: AtomicUsize::new(0),
        unreadable: false,
    });
    pack(
        &layer,
        &base.path("bundle.tar.zst"),
        observed.clone(),
        &PackOptions {
            check_change_set: true,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(observed.opens.load(Ordering::Relaxed), 1);
}

/// Regression: verify and pack failed closed on unreadable preimages but
/// omitted the failing path, unlike the lower reuse check.
#[test]
fn regression_preimage_pin_unreadable_base_names_the_path() {
    let base = Base::new(&[("f", b"old")]);
    let layer = base.layer("layer", &[], |ov, dir| replace(ov, dir, "f", b"new"));
    let unreadable: Arc<dyn MountSource> = Arc::new(ObservedBase {
        inner: base.source.clone(),
        opens: AtomicUsize::new(0),
        unreadable: true,
    });
    let mismatched = overlay_seal::check_preimages(&layer, unreadable.clone()).unwrap();
    assert!(mismatched[0].contains("f: cannot read the base entry"));
    for error in [
        overlay_seal::verify(&layer, unreadable.clone()).unwrap_err(),
        pack(
            &layer,
            &base.path("bundle.tar.zst"),
            unreadable,
            &PackOptions::default(),
        )
        .unwrap_err(),
    ] {
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(
            error.to_string().contains("f: cannot read the base entry"),
            "{error}"
        );
    }
    assert!(!base.path("bundle.tar.zst").exists());
}

/// Regression (#341): a sealed directory lower over a weak directory base
/// accepted a base file edited to a third value of the same size with its
/// mtime restored (the `modified` row is unchanged). Now refused at
/// `MountLowerStack` and by `overlay_seal::verify`, naming the path.
#[test]
fn regression_preimage_pin_refuses_same_size_edit_of_modified_file() {
    let base = Base::new(&[("f", b"old"), ("other", b"same")]);
    let layer = base.layer("layer", &[], |ov, dir| replace(ov, dir, "f", b"new"));
    let meta = OverlayMeta::read(&layer).unwrap().unwrap();
    assert_eq!(meta.base_digest_kind(), Some("weak"));
    assert!(meta.get(PREIMAGE_DIGEST_KEY).is_some(), "{meta:?}");
    assert_eq!(pins(&layer), BTreeMap::from([("f".into(), sha256(b"old"))]));
    base.open(std::slice::from_ref(&layer)).unwrap();
    edit_keeping_mtime(&base.dir.join("f"), b"alt");
    let error = base.open(std::slice::from_ref(&layer)).unwrap_err();
    assert!(error.contains("f: content changed"), "{error}");
    assert!(error.contains(&layer.display().to_string()), "{error}");
    assert!(error.contains("--force-base-mismatch"), "{error}");
    let report = overlay_seal::verify(&layer, base.source.clone()).unwrap();
    assert!(!report.ok, "{report:?}");
    // The canonical rows cannot see it; only the pins do.
    assert!(report.mismatched.is_empty(), "{report:?}");
    assert_eq!(report.recorded, report.computed);
    assert_eq!(report.preimages_bound, Some(true));
    assert_eq!(report.preimage_mismatched, ["f: content changed"]);
    // Restored: accepted again.
    edit_keeping_mtime(&base.dir.join("f"), b"old");
    base.open(std::slice::from_ref(&layer)).unwrap();
    assert!(
        overlay_seal::verify(&layer, base.source.clone())
            .unwrap()
            .ok
    );
}

/// Regression (#341): an edit that makes a recorded change disappear (the
/// base now equals the layer) is still refused, by the pins as well.
#[test]
fn regression_preimage_pin_refuses_edit_removing_the_change() {
    let base = Base::new(&[("f", b"old")]);
    let layer = base.layer("layer", &[], |ov, dir| replace(ov, dir, "f", b"new"));
    edit_keeping_mtime(&base.dir.join("f"), b"new");
    let error = base.open(std::slice::from_ref(&layer)).unwrap_err();
    assert!(error.contains("f: content changed"), "{error}");
    let report = overlay_seal::verify(&layer, base.source.clone()).unwrap();
    assert!(!report.ok);
    assert_eq!(report.mismatched, ["f"]);
    assert_eq!(
        report.preimage_mismatched,
        ["f: missing from the base, or no longer changed by the layer"]
    );
}

/// Regression (#341): the preimage of a deleted file, of a rename's source
/// and of a deleted symlink (retargeted to a same-length target) are pinned.
#[test]
fn regression_preimage_pin_refuses_deleted_renamed_and_symlink_edits() {
    let base = Base::new(&[("gone", b"abc"), ("from", b"move me"), ("kept", b"k")]);
    std::os::unix::fs::symlink("target-1", base.dir.join("link")).unwrap();
    let layer = base.layer("layer", &[], |ov, _| {
        ov.unlink("/gone").unwrap();
        ov.rename("/from", "/to").unwrap();
        ov.unlink("/link").unwrap();
    });
    let recorded = pins(&layer);
    assert_eq!(
        recorded.keys().collect::<Vec<_>>(),
        ["from", "gone", "link"],
        "{recorded:?}"
    );
    assert_eq!(recorded["link"], sha256(b"target-1"));
    base.open(std::slice::from_ref(&layer)).unwrap();
    for (name, bytes) in [("gone", &b"xyz"[..]), ("from", b"MOVE ME")] {
        let path = base.dir.join(name);
        let before = fs::read(&path).unwrap();
        edit_keeping_mtime(&path, bytes);
        let error = base.open(std::slice::from_ref(&layer)).unwrap_err();
        assert!(
            error.contains(&format!("{name}: content changed")),
            "{error}"
        );
        let report = overlay_seal::verify(&layer, base.source.clone()).unwrap();
        assert_eq!(
            report.preimage_mismatched,
            [format!("{name}: content changed")]
        );
        edit_keeping_mtime(&path, &before);
        base.open(std::slice::from_ref(&layer)).unwrap();
    }
    fs::remove_file(base.dir.join("link")).unwrap();
    std::os::unix::fs::symlink("target-2", base.dir.join("link")).unwrap();
    let error = base.open(std::slice::from_ref(&layer)).unwrap_err();
    assert!(error.contains("link: content changed"), "{error}");
}

/// Regression: distinct non-UTF-8 symlink targets both became the Unicode
/// replacement character in FileInfo and therefore had identical pins.
#[test]
fn regression_preimage_pin_symlink_targets_use_exact_bytes() {
    use std::os::unix::ffi::OsStrExt;
    let base = Base::new(&[]);
    let link = base.dir.join("link");
    let old = std::ffi::OsStr::from_bytes(b"target-\xff");
    let alt = std::ffi::OsStr::from_bytes(b"target-\xfe");
    std::os::unix::fs::symlink(old, &link).unwrap();
    let layer = base.layer("layer", &[], |ov, _| ov.unlink("/link").unwrap());
    assert_eq!(pins(&layer)["link"], sha256(old.as_bytes()));
    base.open(std::slice::from_ref(&layer)).unwrap();
    fs::remove_file(&link).unwrap();
    std::os::unix::fs::symlink(alt, &link).unwrap();
    assert!(base
        .open(std::slice::from_ref(&layer))
        .unwrap_err()
        .contains("link: content changed"));
    let report = overlay_seal::verify(&layer, base.source.clone()).unwrap();
    assert_eq!(report.preimage_mismatched, ["link: content changed"]);

    // A symlink provided by a lower must retain its bytes through composition.
    let lower = base.layer("lower", &[], |ov, dir| {
        ov.create_symlink("/added-link", "temporary").unwrap();
        fs::remove_file(dir.join("added-link")).unwrap();
        std::os::unix::fs::symlink(old, dir.join("added-link")).unwrap();
    });
    let top = base.layer("top", &[&lower], |ov, _| ov.unlink("/added-link").unwrap());
    assert_eq!(pins(&top)["added-link"], sha256(old.as_bytes()));
    base.open(&[lower, top]).unwrap();
}

/// Regression (#341): no false positives. An unchanged base, an mtime-only
/// touch (pins hash content; the mount's weak manifest check still sees the
/// touch, `MountLowerStack` alone does not) and edits of unpinned files are
/// accepted; a size change or a mode change of a pinned file is named.
#[test]
fn regression_preimage_pin_accepts_unchanged_and_touched_base() {
    let base = Base::new(&[("f", b"old"), ("other", b"same")]);
    let layer = base.layer("layer", &[], |ov, dir| replace(ov, dir, "f", b"new"));
    let paths = [layer.clone()];
    base.open(&paths).unwrap();
    set_mtime(&base.dir.join("f"), 2_000_000);
    base.open(&paths).unwrap();
    assert!(
        overlay_seal::verify(&layer, base.source.clone())
            .unwrap()
            .ok
    );
    fs::write(base.dir.join("other"), b"changed, unpinned").unwrap();
    base.open(&paths).unwrap();
    fs::set_permissions(base.dir.join("f"), fs::Permissions::from_mode(0o755)).unwrap();
    let error = base.open(&paths).unwrap_err();
    assert!(error.contains("f: mode changed"), "{error}");
    fs::set_permissions(base.dir.join("f"), fs::Permissions::from_mode(0o644)).unwrap();
    fs::write(base.dir.join("f"), b"longer").unwrap();
    let error = base.open(&paths).unwrap_err();
    assert!(error.contains("f: size changed"), "{error}");
    fs::remove_file(base.dir.join("f")).unwrap();
    let error = base.open(&paths).unwrap_err();
    assert!(error.contains("f: missing from the base"), "{error}");
}

/// Regression (#341): a layer sealed before #341 (no pin table, no meta row)
/// keeps the old behaviour: a same-size edit with a restored mtime is not
/// seen. Sealing it again (unseal, seal) records pins.
#[test]
fn regression_preimage_pin_old_seal_without_pins_is_unchanged() {
    let base = Base::new(&[("f", b"old")]);
    let layer = base.layer("layer", &[], |ov, dir| replace(ov, dir, "f", b"new"));
    tamper(&layer, |conn| {
        conn.execute_batch(
            "DROP TABLE seal_preimages; DELETE FROM meta WHERE key='base_preimage_digest';",
        )
        .unwrap();
    });
    assert!(!has_pin_table(&layer));
    edit_keeping_mtime(&base.dir.join("f"), b"alt");
    base.open(std::slice::from_ref(&layer)).unwrap();
    let report = overlay_seal::verify(&layer, base.source.clone()).unwrap();
    assert!(report.ok, "{report:?}");
    assert_eq!(report.preimages_bound, None);
    let (output, code) = crate::overlay_cmd::verify(
        &crate::overlay_cmd::VerifyArgs {
            seal: crate::overlay_cmd::SealArgs {
                directory: layer.clone(),
                base: None,
                lower: Vec::new(),
                json: true,
            },
            no_base_check: true,
        },
        &Default::default(),
    )
    .unwrap();
    let json: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(code, 0);
    assert_eq!(json.get("preimages_bound"), Some(&serde_json::Value::Null));
    // Unseal removes pins and their row; sealing again pins the base as it
    // is now, which is then accepted (and its next edit refused).
    overlay_seal::unseal(&layer).unwrap();
    assert!(!has_pin_table(&layer));
    fixtures::seal(&layer, base.source.clone()).unwrap();
    assert_eq!(pins(&layer), BTreeMap::from([("f".into(), sha256(b"alt"))]));
    base.open(std::slice::from_ref(&layer)).unwrap();
    edit_keeping_mtime(&base.dir.join("f"), b"old");
    assert!(base.open(std::slice::from_ref(&layer)).is_err());
}

/// Regression (#341): pins changed in the database after sealing are
/// detected: an edited hash (it no longer matches the base or its binding),
/// a deleted row (binding), and a removed meta row with rows left (binding).
#[test]
fn regression_preimage_pin_tampered_pins_are_detected() {
    let base = Base::new(&[("f", b"old"), ("g", b"two")]);
    let make = |name: &str| {
        base.layer(name, &[], |ov, dir| {
            replace(ov, dir, "f", b"new");
            ov.unlink("/g").unwrap();
        })
    };
    let edited = make("edited");
    tamper(&edited, |conn| {
        conn.execute(
            "UPDATE seal_preimages SET hash=?1 WHERE path='f'",
            [sha256(b"alt")],
        )
        .unwrap();
    });
    let report = overlay_seal::verify(&edited, base.source.clone()).unwrap();
    assert!(!report.ok);
    assert_eq!(report.preimages_bound, Some(false));
    assert_eq!(report.preimage_mismatched, ["f: content changed"]);
    let error = base.open(std::slice::from_ref(&edited)).unwrap_err();
    assert!(error.contains(PREIMAGES_UNBOUND), "{error}");

    let deleted = make("deleted");
    tamper(&deleted, |conn| {
        conn.execute("DELETE FROM seal_preimages WHERE path='g'", [])
            .unwrap();
    });
    let report = overlay_seal::verify(&deleted, base.source.clone()).unwrap();
    assert!(!report.ok);
    assert_eq!(report.preimages_bound, Some(false));
    assert_eq!(report.preimage_mismatched, ["g: not pinned by the seal"]);
    assert!(base
        .open(std::slice::from_ref(&deleted))
        .unwrap_err()
        .contains(PREIMAGES_UNBOUND));

    let unbound = make("unbound");
    tamper(&unbound, |conn| {
        conn.execute("DELETE FROM meta WHERE key=?1", [PREIMAGE_DIGEST_KEY])
            .unwrap();
    });
    let report = overlay_seal::verify(&unbound, base.source.clone()).unwrap();
    assert!(!report.ok);
    assert_eq!(report.preimages_bound, Some(false));
    assert!(base
        .open(std::slice::from_ref(&unbound))
        .unwrap_err()
        .contains(PREIMAGES_UNBOUND));
}

/// Regression: collecting pin rows into a map silently discarded duplicate
/// paths, allowing a rebuilt table to pass its unchanged binding.
#[test]
fn regression_preimage_pin_duplicate_paths_are_refused() {
    let base = Base::new(&[("f", b"old")]);
    let layer = base.layer("layer", &[], |ov, dir| replace(ov, dir, "f", b"new"));
    tamper(&layer, |conn| {
        conn.execute_batch(
            "ALTER TABLE seal_preimages RENAME TO original;
             CREATE TABLE seal_preimages AS SELECT * FROM original;
             INSERT INTO seal_preimages SELECT * FROM original;
             DROP TABLE original;",
        )
        .unwrap();
    });
    let error = base.open(std::slice::from_ref(&layer)).unwrap_err();
    assert!(
        error.contains("duplicate preimage pin") && error.contains('f'),
        "{error}"
    );
    let error = overlay_seal::verify(&layer, base.source.clone()).unwrap_err();
    assert!(
        error.to_string().contains("duplicate preimage pin"),
        "{error}"
    );
}

/// Regression: dropping an empty pin table while keeping its binding was
/// accepted as a valid empty table; only removing BOTH is legacy compatibility.
#[test]
fn regression_preimage_pin_missing_empty_table_is_unbound() {
    let base = Base::new(&[("f", b"old")]);
    let layer = base.layer("layer", &[], |_, dir| {
        fs::write(dir.join("added"), b"new").unwrap();
    });
    assert!(pins(&layer).is_empty());
    tamper(&layer, |conn| {
        conn.execute_batch("DROP TABLE seal_preimages").unwrap();
    });
    let error = base.open(std::slice::from_ref(&layer)).unwrap_err();
    assert!(error.contains(PREIMAGES_UNBOUND), "{error}");
    let report = overlay_seal::verify(&layer, base.source.clone()).unwrap();
    assert!(!report.ok);
    assert_eq!(report.preimages_bound, Some(false));
}

/// Regression: the binding must ignore row order but include the layer
/// digest, even when two different layers have identical preimage rows.
#[test]
fn regression_preimage_pin_binding_is_sorted_and_layer_specific() {
    let base = Base::new(&[("f", b"old"), ("g", b"old")]);
    let make = |name, bytes| {
        base.layer(name, &[], |ov, dir| {
            replace(ov, dir, "f", bytes);
            ov.unlink("/g").unwrap();
        })
    };
    let a = make("a", &b"new"[..]);
    let b = make("b", &b"alt"[..]);
    assert_eq!(pins(&a), pins(&b));
    tamper(&a, |conn| {
        conn.execute_batch(
            "ALTER TABLE seal_preimages RENAME TO original;
            CREATE TABLE seal_preimages AS SELECT * FROM original ORDER BY path DESC;
            DROP TABLE original;",
        )
        .unwrap();
    });
    assert!(overlay_seal::verify(&a, base.source.clone()).unwrap().ok);
    let foreign = OverlayMeta::read(&b).unwrap().unwrap();
    tamper(&a, |conn| {
        OverlayMeta::set(
            conn,
            PREIMAGE_DIGEST_KEY,
            foreign.get(PREIMAGE_DIGEST_KEY).unwrap(),
        )
        .unwrap();
    });
    assert_eq!(
        overlay_seal::verify(&a, base.source.clone())
            .unwrap()
            .preimages_bound,
        Some(false)
    );
    assert!(base.open(&[a]).unwrap_err().contains(PREIMAGES_UNBOUND));
}

/// Regression (#341): a bundle round trip carries the pins (the database and
/// `meta.json`); the bundle `--lower` cache refuses a same-size base edit,
/// and the unpacked layer verifies until the base is edited.
#[test]
fn regression_preimage_pin_bundle_round_trip_carries_pins() {
    let base = Base::new(&[("f", b"old")]);
    let layer = base.layer("layer", &[], |ov, dir| replace(ov, dir, "f", b"new"));
    let bundle = base.path("layer.tar.zst");
    pack(
        &layer,
        &bundle,
        base.source.clone(),
        &PackOptions::default(),
    )
    .unwrap();
    let meta = super::bundle_meta(&bundle, super::Limits::resolve(None, None).unwrap()).unwrap();
    let recorded = OverlayMeta::read(&layer).unwrap().unwrap();
    assert_eq!(
        meta.get(PREIMAGE_DIGEST_KEY).map(String::as_str),
        recorded.get(PREIMAGE_DIGEST_KEY)
    );
    let restored = base.path("restored");
    let outcome = unpack(&bundle, &restored).unwrap();
    assert!(outcome.ok && outcome.verified, "{outcome:?}");
    assert_eq!(pins(&restored), pins(&layer));
    base.open(std::slice::from_ref(&bundle)).unwrap();
    edit_keeping_mtime(&base.dir.join("f"), b"alt");
    let error = base.open(std::slice::from_ref(&bundle)).unwrap_err();
    assert!(error.contains("f: content changed"), "{error}");
    assert!(error.contains(&bundle.display().to_string()), "{error}");
    let report = overlay_seal::verify(&restored, base.source.clone()).unwrap();
    assert_eq!(report.preimage_mismatched, ["f: content changed"]);
    let again = base.path("again");
    let outcome = unpack(&bundle, &again).unwrap();
    assert!(outcome.verified && !outcome.ok, "{outcome:?}");
}

/// Regression (#341): ordinary and moved/forced packs must both refuse a
/// changed preimage, although the canonical change set is unchanged.
#[test]
fn regression_preimage_pin_checked_pack_refuses_changed_preimage() {
    let base = Base::new(&[("f", b"old")]);
    let layer = base.layer("layer", &[], |ov, dir| replace(ov, dir, "f", b"new"));
    let options = PackOptions {
        check_change_set: true,
        ..PackOptions::default()
    };
    pack(
        &layer,
        &base.path("ok.tar.zst"),
        base.source.clone(),
        &options,
    )
    .unwrap();
    edit_keeping_mtime(&base.dir.join("f"), b"alt");
    for options in [PackOptions::default(), options] {
        let error = pack(
            &layer,
            &base.path("no.tar.zst"),
            base.source.clone(),
            &options,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("preimage pins"), "{error}");
        assert!(error.contains("f: content changed"), "{error}");
        assert!(!base.path("no.tar.zst").exists());
    }
}

/// Regression (#341): nested lowers. Lower 1's pins are hashes of what the
/// view beneath it served at seal (base + lower 0): its pin of a path lower 0
/// modified is lower 0's content, and of a path only the base holds is the
/// base's. A base edit under lower 0's change names lower 0; one under lower
/// 1's base-served change names lower 1.
#[test]
fn regression_preimage_pin_nested_lowers_check_their_own_view() {
    let base = Base::new(&[("a", b"base-a"), ("b", b"base-b")]);
    let l0 = base.layer("l0", &[], |ov, dir| replace(ov, dir, "a", b"zero-a"));
    let l1 = base.layer("l1", &[&l0], |ov, dir| {
        replace(ov, dir, "a", b"one-a!");
        replace(ov, dir, "b", b"one-b!");
    });
    assert_eq!(pins(&l0), BTreeMap::from([("a".into(), sha256(b"base-a"))]));
    assert_eq!(
        pins(&l1),
        BTreeMap::from([
            ("a".into(), sha256(b"zero-a")),
            ("b".into(), sha256(b"base-b"))
        ])
    );
    let stack = [l0.clone(), l1.clone()];
    base.open(&stack).unwrap();
    assert!(overlay_seal::verify(&l1, base.view(&[&l0])).unwrap().ok);
    edit_keeping_mtime(&base.dir.join("b"), b"BASE-B");
    let error = base.open(&stack).unwrap_err();
    assert!(
        error.starts_with(&format!("lower {}", l1.display())),
        "{error}"
    );
    assert!(error.contains("b: content changed"), "{error}");
    edit_keeping_mtime(&base.dir.join("b"), b"base-b");
    edit_keeping_mtime(&base.dir.join("a"), b"BASE-A");
    let error = base.open(&stack).unwrap_err();
    assert!(
        error.starts_with(&format!("lower {}", l0.display())),
        "{error}"
    );
    assert!(error.contains("a: content changed"), "{error}");
    // Lower 1's pin of `a` is lower 0's content, unaffected by the base.
    let report = overlay_seal::verify(&l1, base.view(&[&l0])).unwrap();
    assert!(report.ok, "{report:?}");
}

/// Regression: a metadata-only lower can supply a stale user.hash.sha256
/// xattr while the payload still comes from the mutable directory base.
/// Neither sealing nor reuse may mistake that cached claim for a byte read.
#[test]
fn regression_preimage_pin_ignores_mutable_base_hash_xattrs() {
    let base = Base::new(&[("f", b"old")]);
    let metadata = base.layer("metadata", &[], |ov, _| {
        ov.set_xattr("/f", "user.hash.sha256", sha256(b"old").as_bytes(), 0)
            .unwrap();
    });
    assert!(
        !metadata.join("f").exists(),
        "the payload must remain in the base"
    );
    let layer = base.layer("layer", &[&metadata], |ov, dir| {
        replace(ov, dir, "f", b"new")
    });
    base.open(&[metadata.clone(), layer.clone()]).unwrap();
    edit_keeping_mtime(&base.dir.join("f"), b"alt");
    let error = base.open(&[metadata.clone(), layer.clone()]).unwrap_err();
    assert!(error.contains("f: content changed"), "{error}");
    let report = overlay_seal::verify(&layer, base.view(&[&metadata])).unwrap();
    assert_eq!(report.preimage_mismatched, ["f: content changed"]);
    // A fresh seal on the edited base must record its bytes, not the xattr.
    let fresh = base.layer("fresh", &[&metadata], |ov, dir| {
        replace(ov, dir, "f", b"new")
    });
    assert_eq!(pins(&fresh)["f"], sha256(b"alt"));
}

/// Regression: --between and import --lower must check the common lower
/// stack even when neither top itself changes the pinned base path.
#[test]
fn regression_preimage_pin_diff_between_and_import_lower() {
    let base = Base::new(&[("f", b"old")]);
    let lower = base.layer("lower", &[], |ov, dir| replace(ov, dir, "f", b"new"));
    let a = base.layer("a", &[&lower], |_, _| {});
    let b = base.layer("b", &[&lower], |_, _| {});
    let args = crate::diff::DiffArgs {
        directory: a,
        between: Some(b),
        hash: true,
        ..Default::default()
    };
    let context = crate::base_identity::OverlayRunContext::default();
    assert_eq!(crate::diff::run(&args, &context), 0);
    let import = || {
        crate::overlay_import::ImportStack::open_base(
            base.dir.to_str().unwrap(),
            std::slice::from_ref(&lower),
            false,
            &context,
        )
    };
    assert!(import().is_ok());
    edit_keeping_mtime(&base.dir.join("f"), b"alt");
    assert_ne!(crate::diff::run(&args, &context), 0);
    let error = import().err().expect("import must refuse the stale lower");
    assert!(error.contains("f: content changed"), "{error}");
}

/// Regression: type changes and removed subtrees must pin the old file
/// contents; a pinned path replaced by a special file is refused before open.
#[test]
fn regression_preimage_pin_type_changes_and_special_files() {
    let base = Base::new(&[("f", b"old"), ("dir/child", b"old")]);
    let layer = base.layer("layer", &[], |ov, dir| {
        ov.unlink("/f").unwrap();
        ov.mkdir("/f", 0o755).unwrap();
        ov.unlink("/dir/child").unwrap();
        ov.rmdir("/dir").unwrap();
        let fd = ov.create_file("/dir", 0o644).unwrap();
        ov.close_overlay_fd(fd);
        fs::write(dir.join("dir"), b"new").unwrap();
    });
    assert_eq!(
        pins(&layer).keys().cloned().collect::<Vec<_>>(),
        ["dir/child", "f"]
    );
    base.open(std::slice::from_ref(&layer)).unwrap();
    edit_keeping_mtime(&base.dir.join("dir/child"), b"alt");
    assert!(base
        .open(std::slice::from_ref(&layer))
        .unwrap_err()
        .contains("dir/child: content changed"));
    edit_keeping_mtime(&base.dir.join("dir/child"), b"old");
    fs::remove_file(base.dir.join("f")).unwrap();
    rustix::fs::mknodat(
        rustix::fs::CWD,
        base.dir.join("f"),
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        0,
    )
    .unwrap();
    let error = base.open(std::slice::from_ref(&layer)).unwrap_err();
    assert!(error.contains("f: cannot read the base entry"), "{error}");
}

/// Regression (#341): which bases are pinned. A supplied strong digest on a
/// directory is a claim the mount never rehashes, so it is pinned like a
/// weak one; `--base-digest none` asked for no identity and records none; an
/// archive base (its identity covers its bytes) records none.
#[test]
fn regression_preimage_pin_scope_by_recorded_base() {
    let base = Base::new(&[("f", b"old")]);
    let strong = base.layer_with(
        "strong",
        &[],
        BaseDigestRequest::Supplied(format!("sha256:{}", "a".repeat(64))),
        |ov, dir| replace(ov, dir, "f", b"new"),
    );
    let meta = OverlayMeta::read(&strong).unwrap().unwrap();
    assert_eq!(meta.base_digest_kind(), Some("strong"));
    assert!(meta.get(PREIMAGE_DIGEST_KEY).is_some());
    let none = base.layer_with("none", &[], BaseDigestRequest::None, |ov, dir| {
        replace(ov, dir, "f", b"new")
    });
    let meta = OverlayMeta::read(&none).unwrap().unwrap();
    assert!(meta.get(PREIMAGE_DIGEST_KEY).is_none(), "{meta:?}");
    assert!(!has_pin_table(&none));
    edit_keeping_mtime(&base.dir.join("f"), b"alt");
    assert!(base
        .open(std::slice::from_ref(&strong))
        .unwrap_err()
        .contains("f: content changed"));
    base.open(std::slice::from_ref(&none)).unwrap();

    // An archive base.
    let tar = base.path("base.tar");
    {
        let mut builder = tar::Builder::new(File::create(&tar).unwrap());
        let mut header = tar::Header::new_gnu();
        header.set_size(3);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, "f", &b"old"[..]).unwrap();
        builder.finish().unwrap();
    }
    let source = crate::base_identity::fixtures::classify(&tar);
    let view = source.source();
    let dir = base.path("over-tar");
    let overlay =
        fixtures::overlay_over(view.clone(), &dir, tar.to_str().unwrap(), Vec::new()).unwrap();
    replace(&overlay, &dir, "f", b"new");
    drop(overlay);
    ratarmount_compositing::overlay_seal::seal(&dir, &source, view).unwrap();
    let meta = OverlayMeta::read(&dir).unwrap().unwrap();
    assert_eq!(meta.get("base_kind"), Some("archive"));
    assert!(meta.get(PREIMAGE_DIGEST_KEY).is_none(), "{meta:?}");
    assert!(!has_pin_table(&dir));
}

/// Regression (#341): pins hash content, so a byte-identical copy of the base
/// at another path with other mtimes is accepted (offline verbs take copies),
/// but a copy whose pinned file has another mode is refused: pins are
/// stricter than the strong directory digest, which covers contents and
/// symlink targets only.
#[test]
fn regression_preimage_pin_byte_identical_copy_accepted_mode_refused() {
    let base = Base::new(&[("f", b"old"), ("g", b"two")]);
    let layer = base.layer("layer", &[], |ov, dir| replace(ov, dir, "f", b"new"));
    let copy = base.path("copy");
    fs::create_dir(&copy).unwrap();
    for name in ["f", "g"] {
        fs::copy(base.dir.join(name), copy.join(name)).unwrap();
        fs::set_permissions(copy.join(name), fs::Permissions::from_mode(0o644)).unwrap();
        set_mtime(&copy.join(name), 5_000_000);
    }
    let source: Arc<dyn MountSource> = Arc::new(FolderMountSource::new(&copy).unwrap());
    let open = |source: &Arc<dyn MountSource>| {
        crate::MountLowerStack::open_in(
            source.clone(),
            None,
            std::slice::from_ref(&layer),
            false,
            Some(&base.path("cache")),
            &crate::lower_stack_services(),
        )
        .map(|_| ())
    };
    open(&source).unwrap();
    assert!(overlay_seal::verify(&layer, source.clone()).unwrap().ok);
    fs::set_permissions(copy.join("f"), fs::Permissions::from_mode(0o600)).unwrap();
    let error = open(&source).unwrap_err();
    assert!(error.contains("f: mode changed"), "{error}");
}

/// Cost of pins on a layer modifying 1000 files of 64 KiB over a directory
/// base: seal with pins (weak) and without (`none`), the reuse check
/// (`MountLowerStack::open_in`, which rehashes only the pinned files) and a
/// full `verify`. Run with `--release -- --ignored --nocapture`.
#[test]
#[ignore = "timing for #341"]
fn regression_preimage_pin_timing() {
    use std::time::Instant;
    const FILES: usize = 1000;
    let payload = vec![b'x'; 64 << 10];
    let names: Vec<String> = (0..FILES).map(|i| format!("d/f{i:04}")).collect();
    let files: Vec<(&str, &[u8])> = names
        .iter()
        .map(|n| (n.as_str(), payload.as_slice()))
        .collect();
    let base = Base::new(&files);
    let mut timings = Vec::new();
    for (name, request) in [
        ("weak", BaseDigestRequest::Compute),
        ("none", BaseDigestRequest::None),
    ] {
        let dir = base.path(name);
        let overlay = fixtures::overlay_over_with(
            base.source.clone(),
            &dir,
            base.dir.to_str().unwrap(),
            Vec::new(),
            request,
        )
        .unwrap();
        let mut changed = payload.clone();
        changed[0] = b'y';
        for n in &names {
            replace(&overlay, &dir, n, &changed);
        }
        drop(overlay);
        let started = Instant::now();
        fixtures::seal(&dir, base.source.clone()).unwrap();
        timings.push(format!(
            "seal ({name}): {:.3} s",
            started.elapsed().as_secs_f64()
        ));
        let started = Instant::now();
        base.open(std::slice::from_ref(&dir)).unwrap();
        timings.push(format!(
            "MountLowerStack::open_in ({name}): {:.3} s",
            started.elapsed().as_secs_f64()
        ));
        let started = Instant::now();
        assert!(overlay_seal::verify(&dir, base.source.clone()).unwrap().ok);
        timings.push(format!(
            "verify ({name}): {:.3} s",
            started.elapsed().as_secs_f64()
        ));
    }
    assert_eq!(pins(&base.path("weak")).len(), FILES);
    for line in timings {
        eprintln!("{line}");
    }
}
