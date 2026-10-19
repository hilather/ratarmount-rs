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
        "A swap of the base with the same size and mtime cannot be caught without hashing; only `overlay seal` or `overlay verify` with a strong digest catches it.",
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
