The policy driver uses stock Rust 1.98.0 and the distributed rustc-dev component.
`build.py` verifies the pinned source/component archives, extracts only Clippy
from the Rust source archive and applies `patch.py`. It builds Clippy against
rustc-dev; it does not build or modify rustc. The checked-in Cargo.lock pins the
tool dependencies independently of the application lockfile.

Run `python3 packaging/internal-read-clippy/compiler/build.py` after installing
Rust 1.98.0 with Clippy. The printed path is the driver argument to `policy.py`.
For a disconnected build, seed the two archives with `--source-archive` and
`--component-archive`, then pass `--offline`. Cached files are checked by digest.
The host component is deliberately pinned to x86_64-unknown-linux-gnu, matching
the existing Linux check job; this is not a cross-target enforcement tool.

The patch adds an event hook at the existing Clippy disallowed-method/type
lookup. Events carry the actual resolved definition, separately from the
configured rule path. The canonicalizer traverses defining paths and compiler
impl/type associations; it never resolves imports, reexports, foreign names,
flags or operations from source. Unsupported identities fail compilation. Type, lifetime and const binders use
structural parameter indices, including higher-ranked function signatures.
Handwritten leaf syntax comes from the compiler-selected pre-expansion AST
metadata span, joined to the actual HIR expectation; split HIR imports cannot
shrink the approved source leaf. Generated expectations with no observed source
leaf remain unowned.

For configured macros, the patch also checks completed compiler expansion
records. A fully initialized unused sentinel bounds the dense local expansion
index in the pinned compiler API. This covers empty, item and expression
include expansions that Clippy's ordinary span traversal misses. Normal lint
emission and the resolved disallowed-macros map remain Clippy's. The one CSI
exception is matched by reviewed filename and compiler-validated named owner.

The compiler pre-expansion pass receives the root and every source module
rustc loads. It checks only N2–N4 grammar and the direct expectation protocol.
The original crate AST retains root cfg_attr spelling after Rustc supplies
configured root attributes to the regular callback; both receive the audit.
Registered Rustc lint groups determine which source lint levels can suppress
the protected lint, including literal repo macro transcribers. This is lint
metadata, not a textual operation or path resolver.
Raw N2 findings are deferred to exact compiler HIR module ownership, including
compiler module ranges for inactive syntax in a loaded file; an absent or
ambiguous enclosing module fails. Every local HIR foreign block and link_name
is also checked without provenance filtering. No module is loaded by this tool.

`test_driver.py` exercises the compiled lookup/expansion gates. The sibling
`syntax/test_compiled.py`, `controls/run.py` and `test_manifest.py` exercise
syntax scope, the six initial controls and actual generated manifest changes.
All reports must end with a successful completion record before the runner can
accept them. Strict and force-warn collection use separate production caches.
