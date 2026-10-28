# N1 compiled API witnesses

`python3 -I packaging/internal-read-clippy/witnesses/run.py --output DIR` (after
`compiler/build.py`; `--driver PATH` selects an explicit build)
compiles, but never executes, references/calls to each native external API in the
reviewed policy. Each reference must receive its own exact **method** diagnostic;
a receiver-type diagnostic or another failing expression cannot satisfy it. All
four configured builder types also have direct type witnesses. Clippy's resolved
DefId lookup supplies enforcement. The test's diagnostic assertions are not an
operation collector or manifest input.

The small standalone crate enables the locked optional nix `fs`, `dir`, `mman`,
`mqueue`, `feature` APIs, rustix `shm`, and tokio `fs`/`net`. `availability.json`
covers every configured method, including repository definitions and explicitly
unavailable native paths. A configuration addition fails until that review is
renewed. Dependency/toolchain/feature changes require rerunning the suite and
reviewing availability; `allow-invalid` does not prove coverage.

The source review was performed against Rust 1.98.0, libc 0.2.189, rustix 1.1.5,
tempfile 3.27.0, nix 0.29.0, tokio 1.53.1, git2 0.19.0, and lopdf 0.34.0.
Windows/Apple-only APIs retain isolated compiled platform evidence in the frozen
migration review. Linux cannot claim native observations for those paths.
`rustix::io::fcntl_dupfd` is ESP-IDF-only. The two configured libarchive wide/multi
filename functions and lopdf `load_with_password` have no declarations in the
locked repository/dependency; they are explicitly unavailable, never counted as
successful witnesses. The locked libc also omits Rust definitions for
`mkstemp64`, `mkostemp64`, `mkstemps64`, `mkostemps64` and `fcntl64` on Linux;
compiled E0425 results establish their native unavailability. No cross-workspace cross-target scan is part of this test.

The core `db_inodes` wrapper reexports have a second small fixture using the
actual repository crate as a dependency. Isolated configurations separately
require exact diagnostics for their public spelling and private defining-module
spelling; two names resolving to one DefId cannot hide an invalid policy entry.

The journal fixture also requires all fourteen existing restrictions to emit
their own method diagnostics, including the recovery/death-seam/convenience
helpers without native production callers and the three guarded
replacement/splice APIs added by #239. Together the suites cover 154 external
methods, four core alias spellings, fourteen journal methods and four builder
types. The remaining 17 configured repository wrapper paths are observed in the
selected production passes; 24 native-unavailable method paths have explicit
review dispositions.

`dependency-provenance.json` binds the review to selected API-family versions,
registry sources/checksums, and Cargo normal-dependency declarations and feature
tables of affected workspace members. It also verifies that those API-family
versions in fixture lockfiles match the workspace. The suite rejects drift until
the relevant availability witnesses and review record are renewed. Unrelated
lockfile packages are excluded. `provenance.py --candidate` prints current data
for review without changing the approved record; the five pure provenance
regressions verify relevant drift, unrelated updates and order independence.
