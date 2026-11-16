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
#[expect(
    clippy::disallowed_methods,
    reason = r#"internal-read:v1 {"id":"IR-example","item":"example::load","disposition":"managed-read","category":"index-cache","reason":"Read the admitted index cache","creation":{"policy":"none","basis":"Existing input only"}}"#
)]
let bytes = managed_read::read(path)?;
```

Only a direct `#[expect]` with one disallowed-item lint and one literal review
reason can approve an operation. In restricted packages, `allow`/`warn` for
these lints and any `cfg_attr` wrapping `allow`/`warn`/`expect` are refused at
crate, module and item level, including reviewed files and literal macro
transcribers. Rustc's registered lint groups supply membership for group
suppressions too; there is no handwritten group table. The
`internal_read_inventory` cfg is registered through workspace lint inheritance.
Ordinary builds leave it off and use a root
`cfg_attr(not(internal_read_inventory), allow(unfulfilled_lint_expectations))`
so inventory expectations do not fail against the ordinary journal-only config.
Selected policy compilations and Linux fixture controls enable the cfg and
require fulfillment.
Reasons contain a stable unique id, compiler-validated item owner, classification,
human reason and explicit reviewed creation policy/basis. Preserve baseline
family/issue/regression metadata. An approval cannot own a whole function/module or multiple operations;
split chains into local leaves. Independent journal expectations remain
unconditional and never authorize an inventory operation. Every protected-lint
expectation is checked, including inactive or shadowed source attributes and
reasons without the inventory prefix. Independent journal exemptions need an
explicit `journal_exemption: true` manifest entry for the exact item, literal
reason, lint and resolved/configured rule identity; prose alone grants no
exemption.
Source expectations keep their own compiler item identity. A copied journal
reason cannot select another item's exemption, and conflicting observations
cannot replace or erase an expectation during profile merging.
Exact compiler item spans and enclosing module body spans supply canonical
scope; inactive children append only their declared item names. An inactive
whole impl without a compiler-resolved owner fails closed. Compiler-unloaded
external modules remain outside the selected Linux compilation and require
ordinary review.

`policy.py --collect` writes `target/internal-read-manifest.json` as a review
candidate. Review before copying it to `manifest.json`; CI never refreshes it.
Canonical keys are `(item path, complete literal reason)`, with defining operation
identity, normalized leaf digest, multiplicity and observed profiles as values.
The comparison is bidirectional: every expectation must have an approved entry,
and every approved entry must have a matching expectation. CI fails for either
addition or deletion.
Absolute source spans and line numbers are transient. Source movement alone does
not change approval; rebinding the same configured reexport must change it.
Dependency provenance belongs in the run attestation and cache key rather than
the canonical manifest header.

N2 permits foreign blocks/link_name only in the exact compiler module
`ratarmount_formats_libarchive::ffi`, including a post-expansion HIR check with no
provenance exception. N3 refuses unsupported `macro`/`pub macro` definitions,
including inactive bodies, and every `cfg`/`cfg_attr` attribute in invocation
payloads at any depth. These refusals do not evaluate predicates or model macro
expansion; non-stripping payload attributes remain permitted. N3 also refuses
cfg/cfg_attr anywhere in macro_rules bodies and metavariable transcriber
attributes, including substituted brackets and attribute
prefixes. Prefix recognition uses matcher fragment kinds and repetition grammar,
independent of the following item, statement, field or variant. Ambiguous `tt`
substitutions beside brackets or a distinct capture are refused; typed indexing
and ordinary macro invocations remain permitted. A repetition that can supply an
unknown attribute prefix before fixed syntax is refused, including `*`, `+` and
`?` forms. Whole-item forwarding, opaque trailing arguments without an active
attribute prefix, and harmless separator-delimited repetitions remain permitted.
In restricted crates, every raw token stream is scanned recursively, including
invocation arguments, attributes, matchers and transcribers. The `macro_rules`
identifier is refused except for the head of a directly written definition
whose body receives the ordinary audit; metavariable invocation heads (`$x !`)
are also refused. This fails closed on macro generation without interpreting
generated grammar, even when a macro would discard its input.
CI supplies `-F unused_macros`; the root `forbid` attributes document that rule.
There is no root-attribute source check. N4 refuses target predicates in stripping
`cfg`/`cfg_attr` attributes in the 40 reviewed restricted packages outside exact
reviewed files in `policy.json`, at every nesting level regardless of other
predicates or parent cfg activity. Syntax audits inspect inactive item bodies.
It also refuses unparseable `cfg_attr` predicates and `clippy`/`not(clippy)`
stripping, even in reviewed files. `cfg!` returns a
boolean and keeps both branches type-checked; direct, nested and aliased uses
remain permitted. File exceptions have no content hash: inactive alternatives
still need ordinary code review. Inventory enforcement is Linux-only. The CSI
include exception is limited to its exact reviewed source file and compiler item,
with identity/multiplicity in the manifest.

`native.py --fixtures` supplies Linux stock-Clippy controls with Cargo metadata
dispatch, so `--all-targets` keeps inventory checks on production lib/bin
compilations. Production Clippy uses
`-D clippy::disallowed_methods -F unused_macros -D warnings`; `-D` permits reviewed
expectations, and `-D warnings` makes unfulfilled expectations fail. The Linux
controls prove that a read behind `not(feature)` is diagnosed and a
test/build-script/dependency read does not gain an inventory obligation.
The native macOS/Windows sweeps in `native.py` and `native.json` are deferred
helpers, not CI gates or approval evidence. The pre-existing macOS build/test and
Windows library-check jobs remain independent of this Linux inventory policy.

Intentional gaps include unused exported macros, whole-item forwarding without
forbidden tokens, other non-target cfg predicates, and calls in reviewed files
on inactive macOS/Windows targets. Native inventory coverage is deferred.
Broader dependency acquisitions/read_dir and extending N4 to the other eight
packages are follow-up #209. SQLite/rusqlite pathname opens rely
on runtime checked_open enforcement. The retired collector's transitive helper
proofs and mode inference are not claimed here.

`migration/` is frozen, one-time accounting for the original 553 entries:
527 native matches, 13 accepted descriptor retypings and 13 target-inactive
entries, plus individual explanations for 142 Clippy-only sites. The earlier
540/260/13 evidence remains historical. None of that comparison or its matching
logic runs in enforcement.
