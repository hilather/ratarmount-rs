//! The documented base-identity rules that changed behaviour must stay in the
//! docs and the changelog (R6 decisions), so a later edit cannot silently drop
//! them. Whitespace is normalized; the sentences are quoted verbatim.

use std::fs;
use std::path::Path;

fn read(relative: &str) -> String {
    let text = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join(relative),
    )
    .unwrap_or_else(|e| panic!("{relative}: {e}"));
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn require(sentences: &[&str]) {
    for file in ["docs/sandbox.md", "CHANGELOG.md"] {
        let text = read(file);
        for sentence in sentences {
            assert!(text.contains(sentence), "{file} lost: {sentence}");
        }
    }
}

/// Regression: #180 claimed every pack/commit open used database-inode
/// admission, hiding ordinary bundle reads and staging-lock acquisitions.
#[test]
fn regression_docs_db_inode_admission_scope() {
    let module = read("ratarmount-core/src/db_inodes.rs").replace("//! ", "");
    for sentence in [
        "Overlay payload opens, the ZIP and TAR commit readers, the seal and pack sentinels and the pack lock and member reads",
        "opens that never call this module",
        "`overlay pack`/`unpack`'s bundle and lock files",
    ] {
        assert!(module.contains(sentence), "db_inodes module lost: {sentence}");
    }
    assert!(
        !module.contains("Every payload, sentinel, pack and commit open goes through"),
        "db_inodes must not claim universal admission coverage"
    );
    let docs = read("docs/sandbox.md");
    for sentence in [
        "Not every `overlay pack` / `unpack` open is checked either:",
        "reads of a bundle file (`overlay unpack`, a bundle `--lower` and the sandbox supervisor's lower checks)",
        "the `--lower` bundle cache's private copy of it",
        "the `<staging directory>.lock` file",
        "cache fill create (or reuse) beside their staging directory use ordinary opens.",
    ] {
        assert!(docs.contains(sentence), "docs/sandbox.md lost: {sentence}");
    }
}

/// Regression: #180 described unpack finalization as opening only directories,
/// although chmod_entry_at also opens regular-file O_PATH pins on Linux.
#[test]
fn regression_docs_db_inode_unpack_finalization() {
    let docs = read("docs/sandbox.md");
    assert!(
        !docs.contains("unpack finalization opens only directories"),
        "unpack finalization also opens regular-file O_PATH pins on Linux"
    );
    for sentence in [
        "Unpack finalization opens directories for metadata updates; its regular-file mode pass uses the lock-preserving `O_PATH` pins on Linux and no data descriptor elsewhere, as described above (#149).",
        "the unpack stage's mode pass change modes through an `O_PATH` pin on Linux",
        "by name with `AT_SYMLINK_NOFOLLOW` elsewhere, where a swap of the name between the check and the change is not detected",
    ] {
        assert!(docs.contains(sentence), "docs/sandbox.md lost: {sentence}");
    }
}

/// Decision 3: a forced kind change drops to kind-only; `none` accepts copies.
#[test]
fn regression_docs_state_forced_kind_only_and_none_accepts_copies() {
    require(&[
        "A forced base-kind change without a supplied digest drops the overlay to kind-only identity (`base_digest_kind=none`): later runs compare kind, not content, until you supply `--base-digest`.",
        "`--base-digest none` accepts a remote or local copy of the same archive (location is ignored).",
    ]);
}

/// Decision 4: the same-size-same-mtime swap limit, and what a refused commit does.
#[test]
fn regression_docs_state_commit_swap_limit() {
    require(&[
        "A swap of the base with the same size and mtime cannot be caught without hashing; only `overlay verify` with a strong digest catches it (`overlay seal` of an already-strong base compares the stamp and does not rehash).",
    ]);
    let docs = read("docs/sandbox.md");
    assert!(
        docs.contains("A refused commit refuses that commit only: nothing is written, the mount keeps serving, and `--force-base-mismatch` accepts the new base."),
        "docs/sandbox.md lost the refused-commit rule"
    );
    let changelog = read("CHANGELOG.md");
    assert!(
        changelog.contains("A refused commit refuses only that commit (the mount keeps serving; `--force-base-mismatch` accepts the new base)"),
        "CHANGELOG.md lost the refused-commit rule"
    );
}

/// R6-J2: the journal ownership rule (inode only, before every commit) and the
/// roll-forward of a consistent complete journal stay documented.
#[test]
fn regression_docs_state_journal_ownership() {
    let docs = read("docs/sandbox.md");
    for sentence in [
        "A commit journal is applied only to the file it was started for: before EVERY commit, whatever the digest kind (`none` included)",
        "the journal's inode must equal the archive's (the device number is only a hint; it changes across reboots)",
        "one in the `complete` phase that is still on disk rolls FORWARD and re-baselines the recorded stamp",
        "Journals exist on Linux and macOS only; elsewhere there is nothing to check.",
        "A journal touches the overlay's recorded rows only when its target is the recorded base",
        "Mounting applies the same ownership check before any recovery",
        "The Git question is one function (`serves_as_git`) that the mount dispatch and this classifier both call",
        "the roll-forward marks it `pending` (never clears it)",
    ] {
        assert!(docs.contains(sentence), "docs/sandbox.md lost: {sentence}");
    }
}

/// R7-C: how a failed replacement and crash recovery treat a journal stay
/// documented: cleanup under the attempt's own lock, no adoption of another
/// file's journal, a missing complete journal refused (never cleared), the
/// target never inferred from stamps, and the copy guard.
#[test]
fn regression_docs_state_failed_replacement_and_locator_rules() {
    let docs = read("docs/sandbox.md");
    for sentence in [
        "A failed replacement is cleaned up under the archive lock it took, from its own record of what it published, before any other committer can touch the file",
        "it never adopts a journal another file left at the name",
        "a complete locator whose journal cannot be found is refused, never cleared",
        "it is never inferred from matching stamps",
        "A copy fallback (`--commit-overlay-mode auto`) publishes only over the file the commit gate accepted, unchanged since the copy read it, and only while no journal is pending on it.",
    ] {
        assert!(docs.contains(sentence), "docs/sandbox.md lost: {sentence}");
    }
}

/// Regression: R11-S5 (#151, #183): the lock guarantees are scoped to processes that keep
/// the database open (a daemonized mount holds no lock after its fork), the
/// platform table is present, and the swap-back exclusion closed by the
/// checked open is gone.
#[test]
fn regression_docs_scope_lock_claims_and_platform_matrix() {
    let text = read("docs/sandbox.md");
    let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
    // Every "in use" lock claim covers a daemonized mount too, until its
    // serving process exits (#183).
    const SCOPE: &str = "(foreground or daemonized, until the serving process exits; #183)";
    for claim in [
        "A mounted overlay's exclusive database lock is reported as \"in use\"",
        "may fail with “in use” if another mount holds the database",
        "Seal refuses a database held by another mount (“in use by another ratarmount process”)",
        "A database locked by a mount returns “in use”",
        "diff refuses a database locked by a mount",
    ] {
        assert!(
            flat.contains(&format!("{claim} {SCOPE}")),
            "docs/sandbox.md lock claim lost its #183 scope: {claim}"
        );
    }
    for sentence in [
        "two packs are byte-identical only with the same ratarmount build",
        "fails the pack instead of being shipped raw",
    ] {
        assert!(flat.contains(sentence), "docs/sandbox.md lost: {sentence}");
    }
    assert!(
        !text.contains("SQLite (3.45.3)"),
        "docs/sandbox.md names SQLCipher's SQLite version literally"
    );
    let python = read("docs/python.md")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        python.contains("Do not open the same database file (an overlay database, an index sidecar) through both at the same time in one process (#154)"),
        "docs/python.md lost the #154 paragraph"
    );
    for sentence in [
        "so it holds the overlay database's exclusive lock and the index's shared lock for its whole life (#183)",
        "is refused with \"in use\" and changes nothing; a reader can no longer roll back the mount's in-flight journal. Wait for the serving process to exit (or retry on \"in use\") before running them right after an unmount",
        "| Platform / host | Installation | Checked open |",
        "opening one database file through both at once in one process is unsupported (#154",
    ] {
        assert!(flat.contains(sentence), "docs/sandbox.md lost: {sentence}");
    }
    assert!(
        !flat.contains("currently holds no kernel lock"),
        "docs/sandbox.md still says a daemonized mount holds no lock (#183)"
    );
    assert!(
        !text.contains("swapped away and back at its path during its own open"),
        "docs/sandbox.md still lists the swap-back exclusion the checked open closed"
    );
    let changelog = read("CHANGELOG.md");
    assert!(changelog
        .contains("still holds no kernel lock on its overlay database after it forks (#183)"));
    assert!(changelog.contains("now forks before it opens any database"));
}

/// Regression: unmount recipes ran offline verbs before the server released
/// its lock, and a bare BEGIN IMMEDIATE probe could itself hold a reservation.
#[test]
fn regression_docs_daemon_wait() {
    let sandbox = read("docs/sandbox.md");
    for required in [
        "wait \"$attempt_pid\"",
        "BEGIN IMMEDIATE; ROLLBACK;",
        "CLI exit codes alone do not",
        "zero busy timeout",
        "`pgrep -f MOUNTPOINT` is not a",
    ] {
        assert!(
            sandbox.contains(required),
            "missing daemon wait guidance: {required}"
        );
    }
    for path in ["docs/provenance.md", "docs/getting-started.md"] {
        assert!(
            read(path).contains("wait \"$mount_pid\""),
            "{path}: offline access precedes server exit"
        );
    }
    assert!(read("docs/mount-options-parity.md")
        .contains("daemonized mounts detach standard streams while continuing to log"));
}

/// Regression: the pin documentation overstated --no-base-check and omitted
/// which reuse paths and legacy seals do (and do not) check preimages.
#[test]
fn regression_docs_preimage_scope_and_legacy_visibility() {
    let docs = read("docs/sandbox.md");
    for required in [
        "every `overlay pack`",
        "supervisor finalize",
        "supervisor diff after retained restore",
        "including non-UTF-8 target bytes",
        "Duplicate pin paths and a missing table with a remaining binding are refused.",
        "`preimages_bound: null` explicitly means an older, unpinned seal",
        "It still opens the base to recompute changes and check preimage pins.",
    ] {
        assert!(docs.contains(required), "missing pin contract: {required}");
    }
    assert!(read("CHANGELOG.md").contains("ordinary packs, supervisor diff"));
}

/// Regression: required-session wording and offline no-recovery rules survive reconciliation.
#[test]
fn regression_docs_required_record_latch_and_offline_no_recovery() {
    let text = include_str!("../../docs/sandbox.md")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    for expected in [
        "one-way session latch",
        "deleting current or legacy markers never makes it optional again",
        "Offline verbs",
        "never recover:",
    ] {
        assert!(text.contains(expected), "missing {expected}");
    }
}

/// Regression: #239 offline DB and companion symlink refusal must replace the obsolete follow/exit-2 promises.
#[test]
fn regression_docs_state_offline_symlink_refusal() {
    require(&[
        "Offline commit and recovery refuse a symlinked overlay database or any `-wal`, `-journal`, or `-shm` companion with exit 1.",
        "`--force-base-mismatch` cannot bypass this refusal.",
        "Before any write, refusal leaves the archive, symlink targets, database and recovery state unchanged.",
    ]);
    for file in ["docs/sandbox.md", "CHANGELOG.md", "AGENTS.md"] {
        let text = read(file);
        for obsolete in [
            "A symlink to a regular database file keeps working",
            "The offline overlay's database may be a symlink to a regular file",
            "--commit-overlay` with a symlink to a 0-byte database exits 2",
            "regression_offline_recovery_follows_a_symlinked_database",
            "empty or a dangling symlink is a lost record",
            "the offline owner reads through the symlink",
        ] {
            assert!(
                !text.contains(obsolete),
                "{file} retains obsolete rule: {obsolete}"
            );
        }
    }
}

/// Regression: publication docs preserve WAL limitations and the old-pin recovery instructions.
#[test]
fn regression_docs_state_index_wal_and_pin_limits() {
    let formats = read("docs/formats.md");
    for sentence in [
        "A read-only mount can leave an empty `-wal` and a 32 KiB `-shm` beside the index; they hold no data and are harmless.",
        "Side tables written after a publication can stay in the live index's `-wal` until the next writer checkpoints; they are not in the published pin (remaining limitation).",
        "Copying the live `X.index.sqlite` without its `-wal` loses rows; copy the pin or use `--publish-index-to` instead.",
        "`--publish-index-to PATH` refuses an existing `PATH`, except when `PATH` is the index being published itself (the same path under another spelling, or a symlink that resolves to it); a hard link or a bind mount of that index and a `PATH` with a pin name are refused.",
        "ratarmount creates no directory for a publication: the directory of `--publish-index-to PATH` must exist.",
        "ratarmount never opens an index file without a write permission bit for writing, also as root.",
        "Local index publication is Unix-only.",
        "An interrupted publication can leave files named `.ratarmount-index-snap-*.tmp`; they are not part of any published index.",
    ] {assert!(formats.contains(sentence),"docs/formats.md lost {sentence}");}
    let changelog = read("CHANGELOG.md");
    for sentence in [
        "Pins written by earlier releases are hard links of the live index (or of the `--publish-index-to` copy); they may already lack rows or no longer match the id in their name, and they are not migrated.",
        "Re-publish with `ratarmount --no-mount --publish-index ARCHIVE` and use the new `index_id` from `ARCHIVE.index.ptr`.",
        "`--publish-index-to PATH` refuses an existing `PATH`, except when `PATH` is the index being published itself (the same path under another spelling, or a symlink that resolves to it); a hard link or a bind mount of that index and a `PATH` with a pin name are refused.",
    ] {assert!(changelog.contains(sentence),"CHANGELOG.md lost {sentence}");}
    for (name, text) in [("docs/formats.md", formats), ("CHANGELOG.md", changelog)] {
        assert!(
            !text.contains("-links +1"),
            "{name} must not identify invalid pins by link count"
        );
    }
}
