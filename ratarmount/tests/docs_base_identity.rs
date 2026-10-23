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
