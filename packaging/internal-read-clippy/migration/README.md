# Frozen migration evidence

These files are one-time review evidence. The enforcing runner does not read
them and no operation collector or baseline matcher runs in CI.

`baseline-inventory.json` preserves the 553-entry scanner inventory from main
`40d23578` (#220), byte-for-byte from `packaging/internal-read-inventory.json`.
The original PR #201 snapshot at `a147e68e` instead preserved the inventory at
`584311c1`; it differs from this port's baseline in source locations and some
entry metadata. The remaining JSON files retain the original PR's frozen
matching and review evidence; they were not regenerated against the #220
snapshot.

`prior-summary.json`, `prior-inactive-explanations.json` and
`prior-extra-explanations.json` preserve the earlier 540/260/13 result.
The renewed match is 527 native operations, 13 accepted descriptor retypings
and 13 target-inactive rows, with no unexplained misses. `matched.json` and
the per-miss/per-extra explanations retain the original individual identities.
Historical spans/fingerprints are migration evidence, not manifest identity.

`extra-reviews.json` records individual creation/classification review for all
142 extra logical sites. `builder-support-reviews.json` separates preparatory
builder setup from acquisitions while retaining original review provenance.
`inactive-reviews.json` records all 13 native-unobserved marks without inventing
a diagnostic or resolved definition. `cross-target-summary.json` is the frozen
package classification input, not an ongoing cross-build or residual scanner.

The canonical ongoing approval is `../manifest.json`, generated from actual
Clippy DefId events and compiler-selected expectation metadata.
