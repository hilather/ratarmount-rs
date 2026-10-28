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
    // Every "in use" lock claim is scoped to a foreground mount (#183).
    const SCOPE: &str = "(a foreground `-f` mount; a daemonized mount holds no lock, #183)";
    for claim in [
        "A mounted overlay's exclusive database lock is reported as \"in use\"",
        "may fail with “in use” if another mount holds the database",
        "Seal refuses a database held by another mount (“in use by another ratarmount process”)",
        "A database locked by a mount returns “in use”",
        "diff refuses a database locked by a mount",
    ] {
        assert!(
            flat.contains(&format!("{claim} {SCOPE}")),
            "docs/sandbox.md lock claim not scoped to #183: {claim}"
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
        "A daemonized ratarmount (the default without `-f`, for a FUSE mount and for an export server alike) currently holds no kernel lock on its overlay database at all",
        "(#183). Until that is fixed, run with `-f` when another process may open the same overlay.",
        "| Platform / host | Installation | Checked open |",
        "opening one database file through both at once in one process is unsupported (#154",
    ] {
        assert!(text.contains(sentence), "docs/sandbox.md lost: {sentence}");
    }
    assert!(
        !text.contains("swapped away and back at its path during its own open"),
        "docs/sandbox.md still lists the swap-back exclusion the checked open closed"
    );
    let changelog = read("CHANGELOG.md");
    assert!(changelog
        .contains("still holds no kernel lock on its overlay database after it forks (#183)"));
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
