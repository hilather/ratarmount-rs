# Frozen migration evidence

These files are one-time review evidence. The enforcing runner does not read
them and no operation collector or baseline matcher runs in CI.

`baseline-inventory.json` preserves all 553 original entries at `584311c1`.
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
