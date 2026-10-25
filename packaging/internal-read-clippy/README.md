# Production internal-read approvals

This lint guards against mistakes in honest repository code. It is not a security
boundary. Runtime enforcement through openat2 handles and the seccomp CI lane is
the boundary. Proc-macro output, build.rs codegen, dlsym tricks and `?`/`From`
retyping of an inventoried descriptor are explicit non-goals. Calls in a
repository-defined proc-macro implementation remain production code. Retyping a
descriptor is not another inventory event.

`clippy.toml` contains resolved disallowed methods, builder types and include
macros. The ordinary root configuration retains its independent journal policy.
There is no textual operation collector, path/reexport resolver, creation flag
table, foreign-symbol policy or cross-target residual scan. Only N2–N4 add
compiler-context syntax checks. Production means Cargo's selected lib/bin
compilations, with all features and the eight selections in `profiles.json`.

Build and check from the repository root:

```sh
python3 -I packaging/internal-read-clippy/compiler/build.py
python3 -I packaging/internal-read-clippy/test_policy.py
python3 -I packaging/internal-read-clippy/controls/run.py --driver "$HOME/.cargo/internal-read-clippy/target/debug/clippy-driver"
python3 -I packaging/internal-read-clippy/witnesses/run.py
python3 -I packaging/internal-read-clippy/policy.py
```

The build recipe pins stock Rust 1.98.0, verifies distributed rustc-dev and Rust
source archive digests, extracts only Clippy sources, and applies the checked-in
Clippy-only adapter. It does not build or fork rustc. `RUSTC_BOOTSTRAP=1` is scoped
to this tool. Cargo always runs with `CARGO_BUILD_JOBS=2` and
`flock /tmp/muse-cargo.lock`. The normal stable fmt, all-targets Clippy and tests
remain separate required gates in the existing CI check job.

`policy.py` dispatches by Cargo metadata's exact source/crate/crate-types tuple;
build scripts and dependency compiler invocations receive ordinary rustc. Strict
and force-warn collection passes use separate target directories and require
complete versioned compiler reports for every selected target, including cached
builds. Clippy emits actual defining identities at its existing resolved DefId
lookups. A visible alias, diagnostic prose or configured path cannot substitute
for the actual definition. The manifest records both identities separately.

Each operation needs the smallest legal handwritten statement/type expectation:

```rust
#[cfg_attr(internal_read_inventory, expect(
    clippy::disallowed_methods,
    reason = r#"internal-read:v1 {"id":"IR-example","item":"example::load","disposition":"managed-read","category":"index-cache","reason":"Read the admitted index cache","creation":{"policy":"none","basis":"Existing input only"}}"#
))]
let bytes = managed_read::read(path)?;
```

The activation cfg is reserved for this exact protocol and registered through
workspace lint inheritance. Ordinary builds leave it off. Reasons contain a
stable unique id, compiler-validated item owner, classification, human reason and
explicit reviewed creation policy/basis. Preserve baseline family/issue/regression
metadata. An approval cannot own a whole function/module or multiple operations;
split chains into local leaves. Independent journal expectations remain
unconditional and never authorize an inventory operation.

`policy.py --collect` writes `target/internal-read-manifest.json` as a review
candidate. Review before copying it to `manifest.json`; CI never refreshes it.
Canonical keys are `(item path, complete literal reason)`, with defining operation
identity, normalized leaf digest, multiplicity and observed profiles as values.
Absolute source spans and line numbers are transient. Source movement alone does
not change approval; rebinding the same configured reexport must change it.
Dependency provenance belongs in the run attestation and cache key rather than
the canonical manifest header.

N2 permits foreign blocks/link_name only in the exact compiler module
`ratarmount_formats_libarchive::ffi`, including a post-expansion HIR check with no
provenance exception. N3 refuses cfg/cfg_attr anywhere in repo macros and
metavariable transcriber attributes, including substituted brackets and attribute
prefixes. Prefix recognition uses matcher fragment kinds and repetition grammar,
independent of the following item, statement, field or variant. Ambiguous `tt`
substitutions beside brackets or a distinct capture are refused; typed indexing
and ordinary macro invocations remain permitted. A repetition that can supply an
unknown attribute prefix before fixed syntax is refused, including `*`, `+` and
`?` forms. Whole-item forwarding, opaque trailing arguments without an active
attribute prefix, and harmless separator-delimited repetitions remain permitted. Literal nested macro definitions
in invocation payloads receive the same grammar audit, with generic matchers and
other payload data preserved.
Every production root must contain an unconditional `forbid` naming the exact
single-segment `unused_macros` lint. N4 refuses target predicates and explicit
`use ... cfg as alias` imports in the 40 reviewed failed-cross-check packages
outside exact reviewed files in `policy.json`. The alias check is a conservative
syntax refusal; it does not resolve macro identity. File exceptions have no
content hash: inactive alternatives still need ordinary code review. The CSI
include exception is limited to its exact reviewed source file and compiler item,
with identity/multiplicity in the manifest.

Intentional gaps include unused exported macros, whole-item forwarding without
forbidden tokens, arbitrary non-target cfg predicates, and target-inactive calls
in reviewed files. Broader dependency acquisitions/read_dir and extending N4 to
the other eight packages are follow-up #209. SQLite/rusqlite pathname opens rely
on runtime checked_open enforcement. The retired collector's transitive helper
proofs and mode inference are not claimed here.

`migration/` is frozen, one-time accounting for the original 553 entries:
527 native matches, 13 accepted descriptor retypings and 13 target-inactive
entries, plus individual explanations for 142 Clippy-only sites. The earlier
540/260/13 evidence remains historical. None of that comparison or its matching
logic runs in enforcement.
