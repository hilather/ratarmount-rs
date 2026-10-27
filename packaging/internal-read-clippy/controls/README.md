These compiled controls run before the production inventory migration. Every
fixture first compiles as a production library with `cargo check --lib
--all-features`; foreign declarations are never executed. The driver then applies
Clippy's configured DefIds and the N2–N4 syntax checks.

| Prior skeptic family / variant | Observed rejection |
| --- | --- |
| Substituted transcriber attribute | N3 |
| Extern-crate alias / qualified reexport, invoked macro | Native Clippy `disallowed_methods` |
| Same alias / reexport in dormant exported macro | Accepted gap: no compiled call DefId |
| Qualified reexport under target cfg | N4 |
| Conditional Windows/Linux binding identity | N4; an independent compilation with the fixture file reviewed proves N2 |
| Arbitrary foreign temporary APIs and link_name | N2; no symbol list |
| Creation operation completeness | Seven exact method diagnostics and one OpenOptions type diagnostic |
| Already-inventoried descriptor retyping through From/Into/? | Accepted gap: no new inventory event |

The six requested families and both accepted gaps retain explicit expectations in
`run.py`. `syntax/test_compiled.py` additionally exercises actual compiler-loaded
module/cfg context, raw/nested macro grammar, exact foreign-module authority,
generated foreign blocks, and expectation activation validation. Tests compare
compiler results; no fixture metadata supplies an operation resolver to policy.
