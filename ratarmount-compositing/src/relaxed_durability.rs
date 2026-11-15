//! Opt-in relaxed durability for a writable mount's overlay database (#328).
//!
//! `--overlay-durability=relaxed` runs the mount's own overlay connection with
//! `PRAGMA synchronous=OFF`: SQLite still writes every committed transaction
//! into the page cache (a killed process loses nothing), but no longer waits
//! for the disk. An OS crash or power loss can then corrupt the database or
//! lose recent rows.
//!
//! The marker row `relaxed_durability` = `<boot_id>:<pid>` is committed with
//! `synchronous=FULL` before the first relaxed write and deleted, again under
//! `FULL` (whose commit fsyncs every earlier unsynced page), when the overlay
//! closes cleanly. A marker left by the current boot means the process died
//! but the kernel kept its writes: safe, and the next writable open clears
//! it. A marker from another boot (or one whose boot is unknown) means the
//! machine went down while the database was relaxed: writable opens, seal,
//! `diff`, offline commits and `overlay fsck` refuse until `overlay fsck
//! --repair` passes `PRAGMA integrity_check` and clears it.
//!
//! The pid is diagnostic only: a daemonized mount enables relaxed mode before
//! it forks, so the recorded pid is the launcher's.

use rusqlite::{params, Connection, OptionalExtension};

use crate::write_overlay::Result;
use crate::{OverlayError, OverlayMeta};

/// The `meta` key holding `<boot_id>:<pid>` while a relaxed mount is open.
pub const RELAXED_DURABILITY_KEY: &str = "relaxed_durability";

/// What a writable mount's overlay connection waits for.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OverlayDurability {
    /// SQLite's `synchronous=FULL` (the default): every commit is on disk.
    #[default]
    Full,
    /// `synchronous=OFF` behind a crash marker (see the module docs).
    Relaxed,
}

impl OverlayDurability {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Relaxed => "relaxed",
        }
    }
}

impl std::str::FromStr for OverlayDurability {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value {
            "full" => Ok(Self::Full),
            "relaxed" => Ok(Self::Relaxed),
            other => Err(format!("expected full or relaxed, got {other:?}")),
        }
    }
}

#[cfg(test)]
thread_local! {
    /// In-crate tests: the boot ID this thread sees (`Some(None)`: unknown).
    static BOOT_ID_OVERRIDE: std::cell::RefCell<Option<Option<String>>> =
        const { std::cell::RefCell::new(None) };
}

/// In-crate tests: run `f` while this thread sees `boot` as the boot ID.
#[cfg(all(test, unix))]
pub(crate) fn with_boot_id<R>(boot: Option<&str>, f: impl FnOnce() -> R) -> R {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            BOOT_ID_OVERRIDE.with(|cell| *cell.borrow_mut() = None);
        }
    }
    BOOT_ID_OVERRIDE.with(|cell| *cell.borrow_mut() = Some(boot.map(str::to_owned)));
    let _reset = Reset;
    f()
}

/// The kernel's ID of the current boot, or `None` when it cannot be read
/// (off Linux, or `/proc` masked): an unknown boot is never "the same boot".
pub fn current_boot_id() -> Option<String> {
    #[cfg(test)]
    if let Some(boot) = BOOT_ID_OVERRIDE.with(|cell| cell.borrow().clone()) {
        return boot;
    }
    // Test seam for the binary's integration tests (absent from release
    // builds; packaging/test-no-test-hooks-in-release.sh).
    #[cfg(any(test, feature = "test-hooks"))]
    if let Some(boot) = std::env::var_os("RATARMOUNT_TEST_BOOT_ID") {
        let boot = boot.to_string_lossy().into_owned();
        return valid_boot_id(&boot).then_some(boot);
    }
    read_boot_id()
}

fn valid_boot_id(boot: &str) -> bool {
    !boot.is_empty() && boot != "unknown" && !boot.contains(':') && !boot.contains('\n')
}

#[cfg(target_os = "linux")]
fn read_boot_id() -> Option<String> {
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-E0148-M01","item":"ratarmount_compositing::relaxed_durability::read_boot_id","disposition":"out-of-family","category":"kernel-or-process-introspection","reason":"/proc or mount-table introspection","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
    )]
    let __inventory_value_0 = std::fs::read_to_string("/proc/sys/kernel/random/boot_id");
    let boot = __inventory_value_0.ok()?.trim().to_owned();
    valid_boot_id(&boot).then_some(boot)
}

#[cfg(not(target_os = "linux"))]
fn read_boot_id() -> Option<String> {
    None
}

/// The marker value this process records: `<boot_id>:<pid>` (`unknown` when
/// the boot ID cannot be read).
pub fn marker_value() -> String {
    format!(
        "{}:{}",
        current_boot_id().as_deref().unwrap_or("unknown"),
        std::process::id()
    )
}

/// What a recorded marker says about the database.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MarkerState {
    /// No relaxed mount left a marker.
    Absent,
    /// A relaxed mount of this boot did not close cleanly (killed, or still
    /// running): its writes reached the kernel, so the database is intact.
    SameBoot(String),
    /// The machine rebooted (or the boot is unknown) while a relaxed mount was
    /// open: the database may be corrupt or missing recent changes.
    Unclean(String),
}

/// Classify a recorded marker value against the current boot.
pub fn classify(value: Option<&str>) -> MarkerState {
    let Some(value) = value else {
        return MarkerState::Absent;
    };
    let recorded = value.rsplit_once(':').map_or(value, |(boot, _)| boot);
    match current_boot_id() {
        Some(boot) if valid_boot_id(recorded) && recorded == boot => {
            MarkerState::SameBoot(value.to_owned())
        }
        _ => MarkerState::Unclean(value.to_owned()),
    }
}

/// [`classify`] of an overlay's metadata.
pub fn marker_state(meta: Option<&OverlayMeta>) -> MarkerState {
    classify(meta.and_then(|meta| meta.get(RELAXED_DURABILITY_KEY)))
}

/// The refusal for an [`MarkerState::Unclean`] marker.
pub fn unclean_message(value: &str) -> String {
    format!(
        "overlay database was written with --overlay-durability=relaxed and was not closed \
         before the machine rebooted (crash or power loss; {RELAXED_DURABILITY_KEY}={value}, \
         current boot {}); it may be corrupt or missing recent changes. Discard the overlay, \
         or run `ratarmount overlay fsck --repair DIR` (PRAGMA integrity_check; clears the \
         marker when it passes)",
        current_boot_id().as_deref().unwrap_or("unknown")
    )
}

/// Refuse an overlay whose relaxed mount did not survive a reboot.
pub fn refuse_unclean(meta: Option<&OverlayMeta>) -> Result<()> {
    match marker_state(meta) {
        MarkerState::Unclean(value) => Err(OverlayError::Msg(unclean_message(&value))),
        MarkerState::Absent | MarkerState::SameBoot(_) => Ok(()),
    }
}

/// The recorded marker read through `conn` (no `meta` table: none).
pub fn read_marker(conn: &Connection) -> Result<Option<String>> {
    let has_meta: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='meta')",
        [],
        |row| row.get(0),
    )?;
    if !has_meta {
        return Ok(None);
    }
    Ok(conn
        .query_row(
            "SELECT value FROM meta WHERE key=?1",
            params![RELAXED_DURABILITY_KEY],
            |row| row.get(0),
        )
        .optional()?)
}

/// Delete the marker through `conn` (and its transaction, if any).
pub fn clear_marker(conn: &Connection) -> Result<()> {
    if read_marker(conn)?.is_some() {
        OverlayMeta::remove(conn, RELAXED_DURABILITY_KEY)?;
    }
    Ok(())
}

/// `PRAGMA integrity_check`: `Ok` only when SQLite answers exactly `ok`.
pub fn integrity_check(conn: &Connection) -> Result<()> {
    let mut statement = conn.prepare("PRAGMA integrity_check")?;
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if rows.len() == 1 && rows[0] == "ok" {
        return Ok(());
    }
    let mut shown = rows.iter().take(5).cloned().collect::<Vec<_>>().join("; ");
    if rows.len() > 5 {
        shown.push_str(&format!("; ... ({} problems)", rows.len()));
    }
    Err(OverlayError::Msg(format!(
        "overlay database failed PRAGMA integrity_check after a relaxed-durability crash \
         ({shown}); discard the overlay"
    )))
}

/// The connection's `PRAGMA synchronous` level (0 OFF, 1 NORMAL, 2 FULL, 3 EXTRA).
pub fn synchronous_level(conn: &Connection) -> Result<i64> {
    Ok(conn.query_row("PRAGMA synchronous", [], |row| row.get(0))?)
}

// The overlay verbs (fsck, seal) these tests drive are Unix-only.
#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// Regression (#328): only a marker of the current, known boot is safe.
    #[test]
    fn regression_relaxed_marker_classification_table() {
        with_boot_id(Some("boot-a"), || {
            assert_eq!(classify(None), MarkerState::Absent);
            assert_eq!(
                classify(Some("boot-a:42")),
                MarkerState::SameBoot("boot-a:42".into())
            );
            for other in ["boot-b:42", "unknown:42", ":42", "boot-a", "garbage"] {
                let expected = if other == "boot-a" {
                    // No pid: the boot still matches.
                    MarkerState::SameBoot(other.into())
                } else {
                    MarkerState::Unclean(other.into())
                };
                assert_eq!(classify(Some(other)), expected, "{other}");
            }
            assert_eq!(marker_value(), format!("boot-a:{}", std::process::id()));
        });
        // Unknown current boot: every marker is unclean, even `unknown:` ones.
        with_boot_id(None, || {
            assert!(matches!(
                classify(Some("unknown:1")),
                MarkerState::Unclean(_)
            ));
            assert_eq!(marker_value(), format!("unknown:{}", std::process::id()));
        });
    }

    use crate::{FolderMountSource, WriteOverlay, HIDDEN_DB};
    use ratarmount_core::MountSource;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    fn fixture() -> (tempfile::TempDir, PathBuf, Arc<FolderMountSource>) {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("base");
        std::fs::create_dir(&base).unwrap();
        std::fs::write(base.join("old"), b"base").unwrap();
        let source = Arc::new(FolderMountSource::new(&base).unwrap());
        let overlay = tmp.path().join("overlay");
        drop(WriteOverlay::new_for_tests(source.clone(), &overlay).unwrap());
        (tmp, overlay, source)
    }

    fn marker(dir: &Path) -> Option<String> {
        crate::OverlayMeta::read(dir)
            .unwrap()
            .unwrap()
            .get(RELAXED_DURABILITY_KEY)
            .map(str::to_owned)
    }

    fn plant(dir: &Path, value: &str) {
        let conn = Connection::open(dir.join(HIDDEN_DB)).unwrap();
        OverlayMeta::set(&conn, RELAXED_DURABILITY_KEY, value).unwrap();
    }

    fn churn(ov: &WriteOverlay) {
        for i in 0..20 {
            let path = format!("/f{i}");
            let fd = ov.create_file(&path, 0o644).unwrap();
            unsafe { libc::close(fd) };
            if i % 2 == 0 {
                ov.unlink(&path).unwrap();
            }
        }
        ov.unlink("/old").unwrap();
    }

    /// Regression (#328): relaxed sets `synchronous=OFF` on the mount's own
    /// connection only, after the marker is committed; a clean close restores
    /// `FULL`, clears the marker and keeps every relaxed change. Full mode
    /// never writes a marker.
    #[test]
    fn regression_relaxed_open_marks_and_clean_close_clears() {
        with_boot_id(Some("boot-a"), || {
            let (_tmp, dir, source) = fixture();
            let ov = WriteOverlay::new_for_tests(source.clone(), &dir).unwrap();
            assert_eq!(ov.synchronous_level_for_test().unwrap(), 2);
            ov.set_durability(OverlayDurability::Full).unwrap();
            churn(&ov);
            assert_eq!(ov.meta_value(RELAXED_DURABILITY_KEY).unwrap(), None);
            drop(ov);
            assert_eq!(marker(&dir), None, "full mode writes no marker");

            let ov = WriteOverlay::new_for_tests(source.clone(), &dir).unwrap();
            ov.set_durability(OverlayDurability::Relaxed).unwrap();
            assert_eq!(ov.durability(), OverlayDurability::Relaxed);
            assert_eq!(ov.synchronous_level_for_test().unwrap(), 0);
            assert_eq!(
                ov.meta_value(RELAXED_DURABILITY_KEY).unwrap(),
                Some(format!("boot-a:{}", std::process::id()))
            );
            // Another overlay's connection in the same process is untouched.
            let (_tmp2, dir2, source2) = fixture();
            let other = WriteOverlay::new_for_tests(source2, &dir2).unwrap();
            assert_eq!(other.synchronous_level_for_test().unwrap(), 2);
            drop(other);
            let fd = ov.create_file("/kept", 0o644).unwrap();
            unsafe { libc::close(fd) };
            ov.unlink("/old").unwrap();
            drop(ov);
            assert_eq!(marker(&dir), None, "clean close clears the marker");
            let ov = WriteOverlay::new_for_tests(source, &dir).unwrap();
            assert_eq!(ov.synchronous_level_for_test().unwrap(), 2);
            assert!(ov.lookup("/kept", 0).is_some());
            assert!(ov.lookup("/old", 0).is_none(), "relaxed tombstone kept");
            // Switching back restores FULL and clears the marker in place.
            ov.set_durability(OverlayDurability::Relaxed).unwrap();
            ov.set_durability(OverlayDurability::Full).unwrap();
            assert_eq!(ov.synchronous_level_for_test().unwrap(), 2);
            assert_eq!(ov.meta_value(RELAXED_DURABILITY_KEY).unwrap(), None);
        });
    }

    /// Regression (#328): a marker of another (or an unknown) boot means the
    /// machine went down while relaxed: the writable open, fsck, seal and the
    /// commit gate refuse naming the cause and `fsck --repair`, which passes
    /// `PRAGMA integrity_check`, clears it and makes the overlay usable again.
    #[test]
    fn regression_relaxed_marker_of_another_boot_refuses_until_repair() {
        with_boot_id(Some("boot-a"), || {
            let (_tmp, dir, source) = fixture();
            let ov = WriteOverlay::new_for_tests(source.clone(), &dir).unwrap();
            churn(&ov);
            drop(ov);
            for planted in ["boot-b:4242", "unknown:4242"] {
                plant(&dir, planted);
                let check = |error: String| {
                    assert!(error.contains("--overlay-durability=relaxed"), "{error}");
                    assert!(error.contains("overlay fsck --repair"), "{error}");
                    assert!(error.contains(planted), "{error}");
                };
                check(
                    WriteOverlay::new_for_tests(source.clone(), &dir)
                        .err()
                        .expect("open refused")
                        .to_string(),
                );
                check(
                    crate::overlay_fsck::fsck(&dir, false)
                        .unwrap_err()
                        .to_string(),
                );
                check(
                    crate::overlay_seal::seal_impl(&dir, None, source.clone())
                        .unwrap_err()
                        .to_string(),
                );
                check(
                    crate::write_overlay::ensure_overlay_unsealed(&dir)
                        .unwrap_err()
                        .to_string(),
                );
                assert_eq!(marker(&dir).as_deref(), Some(planted), "nothing cleared");
                let report = crate::overlay_fsck::fsck(&dir, true).unwrap();
                assert!(report.is_clean(), "{}", report.result());
                assert_eq!(marker(&dir), None);
                crate::overlay_fsck::fsck(&dir, false).unwrap();
                drop(WriteOverlay::new_for_tests(source.clone(), &dir).unwrap());
            }
        });
    }

    /// Regression (#328): a marker of this boot (the relaxed mount was killed;
    /// its writes reached the kernel) is accepted: the next writable open
    /// clears it, seal clears it inside its transaction (a sealed layer never
    /// carries one), and a read-only check accepts it.
    #[test]
    fn regression_relaxed_marker_of_this_boot_is_accepted_and_cleared() {
        with_boot_id(Some("boot-a"), || {
            let (_tmp, dir, source) = fixture();
            plant(&dir, "boot-a:999999999");
            assert!(crate::overlay_fsck::fsck(&dir, false).unwrap().is_clean());
            crate::write_overlay::ensure_overlay_unsealed(&dir).unwrap();
            assert_eq!(marker(&dir).as_deref(), Some("boot-a:999999999"));
            let ov = WriteOverlay::new_for_tests(source.clone(), &dir).unwrap();
            assert_eq!(ov.meta_value(RELAXED_DURABILITY_KEY).unwrap(), None);
            drop(ov);
            assert_eq!(marker(&dir), None);

            plant(&dir, "boot-a:999999999");
            crate::overlay_seal::seal_impl(&dir, None, source.clone()).unwrap();
            let meta = crate::OverlayMeta::read(&dir).unwrap().unwrap();
            assert!(meta.layer_sealed());
            assert_eq!(meta.get(RELAXED_DURABILITY_KEY), None);
        });
    }

    /// Regression (#328): a forced seal must not replace an unclean overlay's
    /// base identity before the seal's later durability check refuses it.
    #[test]
    fn regression_relaxed_forced_base_rows_refuse_unclean_record() {
        let (_tmp, dir, _source) = fixture();
        plant(&dir, "unknown:42");
        let before = std::fs::read(dir.join(HIDDEN_DB)).unwrap();
        let rows = std::collections::BTreeMap::from([
            ("base_kind".into(), "directory".into()),
            ("base_url".into(), "/another/base".into()),
        ]);
        let error = crate::overlay_meta::record_base_rows_offline(&dir, &rows)
            .unwrap_err()
            .to_string();
        assert!(error.contains("fsck --repair"), "{error}");
        assert!(std::fs::read(dir.join(HIDDEN_DB)).unwrap() == before);
    }

    /// Regression (#328): `integrity_check` refuses a damaged database (the
    /// `fsck --repair` gate) and accepts an intact one.
    #[test]
    fn regression_relaxed_integrity_check_refuses_corruption() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("db.sqlite");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "PRAGMA page_size=1024; CREATE TABLE t(k INTEGER PRIMARY KEY, v TEXT);
             CREATE INDEX t_v ON t(v);",
        )
        .unwrap();
        for i in 0..2000 {
            conn.execute(
                "INSERT INTO t(v) VALUES (?1)",
                params![format!("value-{i}")],
            )
            .unwrap();
        }
        integrity_check(&conn).unwrap();
        drop(conn);
        // Flip bytes inside a page in the middle of the file.
        let mut bytes = std::fs::read(&path).unwrap();
        let pages = bytes.len() / 1024;
        assert!(pages > 20);
        let page = (pages / 2) * 1024;
        for byte in &mut bytes[page + 100..page + 900] {
            *byte ^= 0x5a;
        }
        std::fs::write(&path, &bytes).unwrap();
        let conn = Connection::open(&path).unwrap();
        let error = integrity_check(&conn).unwrap_err().to_string();
        assert!(error.contains("integrity_check"), "{error}");
    }

    /// Regression (#328): failed marker persistence must never enable OFF;
    /// failed clean-close deletion must keep the recovery marker under FULL.
    #[test]
    fn regression_relaxed_marker_write_and_clear_failures() {
        with_boot_id(Some("boot-a"), || {
            let (_tmp, dir, source) = fixture();
            let conn = Connection::open(dir.join(HIDDEN_DB)).unwrap();
            conn.execute_batch(
                "CREATE TRIGGER refuse_marker BEFORE INSERT ON meta
                 WHEN NEW.key='relaxed_durability'
                 BEGIN SELECT RAISE(ABORT, 'marker write failed'); END;",
            )
            .unwrap();
            drop(conn);
            let ov = WriteOverlay::new_for_tests(source.clone(), &dir).unwrap();
            assert!(ov.set_durability(OverlayDurability::Relaxed).is_err());
            assert_eq!(ov.durability(), OverlayDurability::Full);
            assert_eq!(ov.synchronous_level_for_test().unwrap(), 2);
            assert_eq!(ov.meta_value(RELAXED_DURABILITY_KEY).unwrap(), None);
            drop(ov);
            let conn = Connection::open(dir.join(HIDDEN_DB)).unwrap();
            conn.execute_batch(
                "DROP TRIGGER refuse_marker;
                 CREATE TRIGGER refuse_clear BEFORE DELETE ON meta
                 WHEN OLD.key='relaxed_durability'
                 BEGIN SELECT RAISE(ABORT, 'marker clear failed'); END;",
            )
            .unwrap();
            drop(conn);
            let ov = WriteOverlay::new_for_tests(source, &dir).unwrap();
            ov.set_durability(OverlayDurability::Relaxed).unwrap();
            churn(&ov);
            let expected = marker_value();
            assert!(ov.set_durability(OverlayDurability::Full).is_err());
            assert_eq!(ov.synchronous_level_for_test().unwrap(), 2);
            assert_eq!(
                ov.meta_value(RELAXED_DURABILITY_KEY).unwrap().as_deref(),
                Some(expected.as_str())
            );
            drop(ov);
            assert_eq!(marker(&dir).as_deref(), Some(expected.as_str()));
        });
    }

    /// Regression (#328): fsck --repair must not clear the marker or repair
    /// host/row inconsistencies when integrity_check finds a damaged index.
    #[test]
    fn regression_relaxed_fsck_corruption_keeps_marker_and_rows() {
        with_boot_id(Some("boot-a"), || {
            let (_tmp, dir, _source) = fixture();
            plant(&dir, "boot-b:42");
            let conn = Connection::open(dir.join(HIDDEN_DB)).unwrap();
            // Make an inconsistency that ordinary fsck would repair. Omit an
            // index update with writable_schema so SQLite stays readable but
            // integrity_check reports the missing index entry.
            conn.execute_batch(
                "CREATE TABLE probe(k INTEGER PRIMARY KEY, v TEXT);
                 CREATE INDEX probe_v ON probe(v);
                 INSERT INTO probe VALUES (1,'one');
                 INSERT INTO files(path,name,mode,deleted) VALUES ('','missing',33188,0);",
            )
            .unwrap();
            let (page, schema): (i64, String) = conn
                .query_row(
                    "SELECT rootpage,sql FROM sqlite_master WHERE name='probe_v'",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap();
            conn.execute_batch("PRAGMA writable_schema=ON; DELETE FROM sqlite_master WHERE name='probe_v'; PRAGMA writable_schema=OFF;").unwrap();
            drop(conn);
            let conn = Connection::open(dir.join(HIDDEN_DB)).unwrap();
            conn.execute("INSERT INTO probe VALUES (2,'two')", [])
                .unwrap();
            conn.execute_batch("PRAGMA writable_schema=ON;").unwrap();
            conn.execute(
                "INSERT INTO sqlite_master(type,name,tbl_name,rootpage,sql)
                 VALUES ('index','probe_v','probe',?1,?2)",
                params![page, schema],
            )
            .unwrap();
            drop(conn);
            let before = std::fs::read(dir.join(HIDDEN_DB)).unwrap();
            let error = crate::overlay_fsck::fsck(&dir, true)
                .unwrap_err()
                .to_string();
            assert!(error.contains("integrity_check"), "{error}");
            assert_eq!(marker(&dir).as_deref(), Some("boot-b:42"));
            assert_eq!(
                std::fs::read(dir.join(HIDDEN_DB)).unwrap(),
                before,
                "the marker, missing-content row and damaged index must remain untouched"
            );
        });
    }

    #[test]
    fn regression_relaxed_durability_parses() {
        assert_eq!("full".parse(), Ok(OverlayDurability::Full));
        assert_eq!("relaxed".parse(), Ok(OverlayDurability::Relaxed));
        assert!("off".parse::<OverlayDurability>().is_err());
        assert_eq!(OverlayDurability::default(), OverlayDurability::Full);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn regression_real_boot_id_is_stable() {
        let Some(first) = read_boot_id() else {
            eprintln!("skip: /proc/sys/kernel/random/boot_id unreadable");
            return;
        };
        assert_eq!(read_boot_id().as_deref(), Some(first.as_str()));
        assert!(valid_boot_id(&first));
    }
}
