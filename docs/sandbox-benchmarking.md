# Sandbox benchmark validation, schedules and native lifecycle

Linux builds expose the hidden validator:

```sh
ratarmount sandbox bench --manifest tasks.json --validate-only
ratarmount sandbox bench --manifest tasks.json --validate-only --require-pins
```

Exit status: **0** means structurally valid, **1** means an operational or
reporting failure, and **2** means invalid arguments, an invalid manifest, or
unresolved strict pins. Inherited `--socket` is rejected; bench owns its supervisor.
A missing or unreadable manifest is an operational failure (status **1**).
The command is absent on other operating systems.

The selected manifest must be a regular file, at most 1 MiB, opened without
following its final symlink. Validation never opens artifacts, fetches sources,
executes commands, creates directories, mounts FUSE or starts a container.
It checks structure and internal consistency; it establishes no external qualification.

The `rrs-perl-tasks/1` schema rejects duplicate keys and unknown fields at every
object. This complete draft example is also exercised by the CLI regressions:

```json
{
  "schema":"rrs-perl-tasks/1", "catalog_revision":"draft-1",
  "platforms":[{"id":"linux-amd64","os":"linux","architecture":"amd64",
    "image":"unpinned","toolchain_sha256":"unpinned",
    "dependency_lock":{"path":"unpinned","sha256":"unpinned"}}],
  "tasks":[{"id":"mojolicious","role":"Large pure-Perl","distribution":"Mojolicious","version":"unpinned",
    "cpan":{"path":"unpinned","sha256":"unpinned"},
    "git":{"repository":"unpinned","commit":"unpinned","tree":"unpinned"},
    "artifact":{"path":"unpinned","sha256":"unpinned","tar_stream_sha256":"unpinned"},
    "test_inventory":{"state":"unknown","count":null,"sha256":"unpinned"},
    "platforms":[{"platform_id":"linux-amd64","candidate_jobs":[1,2,8],"supported_jobs":[],
      "qualification":{"qualified":false,"reasons":["Pins and offline qualification unresolved"],"evidence":[]}}],
    "backends":["native","fuse"],
    "commands":{"configure":{"argv":["perl","Makefile.PL"],"timeout_seconds":120},
      "build":{"argv":["make","-j{jobs}"],"timeout_seconds":300},
      "test":{"argv":["prove","-b","-r","-j{jobs}","t"],"timeout_seconds":600}},
    "environment":{"PERL_HASH_SEED":"0","PERL_PERTURB_KEYS":"0","TZ":"UTC","LC_ALL":"C"},
    "resources":{"max_load":4.0,"memory_bytes":1073741824,"disk_bytes":2147483648,"cpus":2,"pids":128},
    "placement":{"source":"source","output":"output","scratch":"scratch"},
    "dependency_locations":{"base":["/repo/lib"],"build":["/repo/blib/lib","/repo/blib/arch"]}}]
}
```

IDs and catalog revision are nonempty identifiers; task and platform IDs are
unique. Roles are `Large pure-Perl`, `XS`, and `Moose consumer`; platform OS is
`linux`, architecture is `amd64` or `arm64`. The CLI regression expands this example
with Text-CSV_XS and MooseX-Getopt. There is no candidate-version field.

Only literal `"unpinned"` denotes unresolved identity/version/path fields.
Pinned digests are `sha256:` plus 64 lowercase hex digits; Git commit/tree IDs
are full 40- or 64-digit lowercase hex, with the same length for both. Images use `name@sha256:DIGEST`.
CPAN paths use `authors/id/A/AB/AUTHOR/Distribution-VERSION.tar.gz` (also tgz,
tar.bz2, tar.xz or zip); Git URLs use HTTPS without userinfo, query or fragment.
All-zero digests and Git object IDs are refused; Git hosts must contain a dot.
A pinned CPAN path requires a pinned version, even in non-strict drafts.
Artifact and dependency-lock paths may be absolute or resolve against the manifest directory, without acquisition.
Paths are lexically normal: no empty, `.` or `..` components or trailing slash.
Path fields also refuse whitespace, braces, backslash and the exact values `TODO`, `TBD`, `fake`, `unknown`.
Placement roots are relative to the manifest directory and cannot overlap.

Known `.t` inventories use `state: "known"`, a positive `count` and pinned digest;
unknown inventories explicitly use `state: "unknown"`, `count: null` and `"unpinned"`.
Candidate jobs are unique positive integers. Supported jobs must be candidates
with passing evidence for each selected backend (`native` or `fuse`). Each
evidence object has `jobs`, `backend`, `passed`, `source_sha256`, `image`,
`dependency_lock_sha256`, and `test_inventory_sha256`, matching the row's pins.
`evidence.source_sha256` must equal `artifact.tar_stream_sha256`.
Qualified rows have supported jobs and no refusal reasons; unqualified rows
have reasons. Strict validation requires resolved inputs and qualification.

Commands use nonempty argv and positive timeouts; only `{jobs}` substitution is
accepted in argv/environment. NULs and invalid environment names are refused.
Empty or whitespace-only argv elements and environment values are also refused.
Resource limits must be positive. Dependency locations are absolute container paths,
independent of the manifest location: base strictly below `/repo`, excluding `/repo/blib`,
and build under `/repo/blib`, with the same lexical path rules. Command and resource
fields are validated without execution by `--validate-only` and `--dry-run`.
Draft results remain **not yet run — pins unresolved**; target hosts **need hardware**.

Linux builds also schedule without executing:

```sh
ratarmount sandbox bench --manifest tasks.json --dry-run --jobs 1
ratarmount sandbox bench --manifest tasks.json --dry-run --task mojolicious --backend native,fuse --base-form git,tar.zst-single-frame --jobs 1,2,8 --cache cold,warm --repeats 5 --seed 1 --attempts 1 --allow-oversubscription
```

Exactly one of `--validate-only`, `--dry-run` or `--out DIR` is required. Selection options
work with scheduling or execution; `--require-pins` works with every mode. Validation runs
before admission and preserves the exit statuses above. Inherited `--socket`
is rejected before manifest I/O. Any admission refusal, including oversubscription or a backend, row or job that a selected task does not support, refuses the whole selection with exit **2** and empty stdout;
schedule reporting failures exit **1**.

Only `--task`, `--backend`, `--base-form`, `--jobs` and `--cache` accept comma-separated or repeated values; scalar options take one value. Defaults are all tasks,
each task's declared backends, both base forms, jobs **1**, both cache treatments,
**5** measured repeats per backend, seed **1**, and **1** concurrent attempt.
Repeats must be **1..=100**; attempts accepts only **1**. Unknown tasks/backends,
non-candidate jobs and jobs outside a qualified row's supported set are refused.
For draft rows, candidate jobs remain selectable with their qualification reasons.
Jobs above the task's `resources.cpus` are refused unless
`--allow-oversubscription` is supplied; both the override and whether the cell
actually exceeds that CPU limit are recorded. The override does not admit
unsupported jobs. Dry-run probes no host capacity, runtime or source availability.

Stdout contains one `rrs-perl-bench-schedule/1` JSON object per line. No output
files, work roots or prepared sources are created. Each entry records the cell,
catalog revision, backend, kind, repeat, pairing, seed, repeats, attempts, CPU
limit, admission override and availability. `qualified` describes the validated
manifest claim. `execution_available` and `runnable` are true only for qualified
native/warm/`tar.zst-single-frame` entries. Dry-run `runnable` does not check
execution's `--out` strict pins or its N6 `timeout_seconds` range of **1..=86400**.
Other entries retain an unavailable
reason; executable entries are graded against the native reference when executed.
Stub runtime output is fixture-only. Dry-run entries are plans, not results.

A cell is the canonical JSON tuple `[task, platform, base_form, jobs, cache]`.
Cells sort by the lowercase SHA-256 digest of the JSON tuple
`["rrs-perl-bench/cell-order/1", seed, cell_identity_string]`, then by that
identity string to break ties. Duplicate selection values are collapsed.
The separate `rrs-perl-bench/backend-orientation/1` domain chooses the first
backend order: a leading hex digit **0–7** reverses native/FUSE to FUSE/native.
Each measured repeat contains both backends; successive repeats reverse order,
giving ABBA or BAAB patterns and equal counts even for odd repeats.
Single-backend selections set `paired:false` and make no paired comparison claim.

Within each cell, a native `reference` comes first, followed by one discarded
`warmup` per selected backend for warm cells, then `measured` entries, then one
`empty-top-fuse-probe` if FUSE is selected. Cold cells have no warm-up; native-only
cells have no FUSE probe. References, warm-ups and probes have no measured repeat
number; warm-ups explicitly set `discarded:true`. The probe is a lifecycle
placeholder without suite phases. Scheduling performs no cache treatment,
mounting, source preparation or runtime execution, and produces no benchmark numbers.

Native execution is available with an explicit local Docker-compatible executable:

```sh
ratarmount sandbox bench --manifest tasks.json --backend native --cache warm --base-form tar.zst-single-frame --repeats 5 --out /results/batch-1 --work-root /scratch/bench --runtime /usr/bin/docker --runtime-kind docker
```

`--out` creates a fresh private directory; its parent and `--work-root` must exist.
An explicit `--work-root` requires `--out`; the default `/var/tmp` does not
trigger that requirement, so default dry-run and validate-only remain valid.
Work-root need not be under `--out`: the sibling layout above stays valid.
Execution requires every manifest pin and qualification to be resolved and
selected jobs to be supported. FUSE, Git and cold selections are refused as a
whole before setup. Overlap checks compare the unique scratch leaf minted under
work-root with canonical artifact, source, catalog, runtime, output and placement
roots, resolving host symlinks. Source, output and scratch groups must not overlap.
Work-root itself is refused if it equals the catalog or artifact parent, equals
or is under `placement.source`, or is an ancestor of `--out`, the catalog directory,
the artifact parent, any `placement.source` or `placement.output`, or the resolved
runtime executable. Exactly `/var/tmp` permits the catalog, artifact, output and
placement paths beneath it when the unique scratch leaf does not overlap them;
the runtime executable has no such exception. A catalog directly in `/var/tmp` still
conflicts with its parent. Each refusal exits **2** with a selection reason.
After equality and under-source checks, the six reasons use
`work-root is an ancestor of ...`, checked in order with these suffixes:
`the runtime executable`, `--out`, `the catalog directory`, `the artifact parent`,
`placement.source`, then `placement.output`.
Any selected FUSE entry takes refusal precedence with
`FUSE execution unavailable: lifecycle deferred to B5a1a`.
Artifact final symlinks are refused. Artifact SHA-256 and the exact local image's
RepoDigests, OS and architecture are checked before private roots are created;
there is no fetching, pulling or source substitution.

A checked Linux `getloadavg` reading measures one-minute host load against the
strictest selected `max_load`. Failure, invalid readings and excessive load
refuse execution unless `--allow-high-load` is supplied. Outcomes record the
reading or failure and the override. CPU oversubscription remains a separate
`--allow-oversubscription` admission decision.

Every reference, discarded warm-up and measurement extracts a fresh tree from
the pinned single-frame zstd artifact and verifies the complete tar-stream digest.
Extraction permits regular files and directories. Relative symlink targets are
accepted only when they stay inside the tree lexically and do not pass through
an archive-created symlink, independent of entry order. Final-component confined
symlink chains remain legal. Links are published after tar-stream digest acceptance,
before directory metadata. The exactly-one-zstd-frame check runs after links
are published and directory metadata has been applied. Extraction refuses duplicate
or unsafe paths, extended/special headers and mode bits above 0777. No descent follows archive symlinks.
Bounds are 100000 entries, 128 path components,
4096 path bytes, a 128 MiB decoder window and the smaller of `disk_bytes` or 16 GiB
for each compressed/decoded stream. Directories start at 0700; recorded modes
and mtimes are applied after descendants. Bench private roots stay 0700.
An extraction failure records an `error` terminal and `blocked` terminals for
the remaining entries, and removes the partial tree and private scratch root
before returning exit **1**, without starting a runtime.

The detached runtime uses `run -d --init --pull=never --name NAME`, binds the fresh
tree at `/repo`, sets `/repo` as cwd, disables networking, drops all capabilities,
sets no-new-privileges, limits PIDs and runs as the invoking UID:GID. Every run
uses the same task CPU/memory limits and `IMAGE sleep infinity`. Configure,
build and test are separate `exec` clients with `{jobs}` substitutions and
owned 0600 stdout/stderr logs. Completed log reads keep the final 64 KiB each; phase fields
`stdout_truncated` and `stderr_truncated` are true if the corresponding log
exceeded 64 KiB, false otherwise. Full logs remain available as artifacts.
Execution timeouts must be **1..=86400 seconds** (one day), checked before any
phase or deadline construction; validation-only mode retains the schema's positive-timeout rule.

Timeout/interruption stops and removes the container, reaps outstanding clients,
and repeats stop/removal after a possibly late startup. Stop failure preserves
the tree and recovery record and blocks deletion. Recovery records name the
executable, container and tree; investigate failed stops before manual cleanup.
Execution writes four canonical files with schema `rrs-perl-bench/1`. Every
record includes `schema`, a `record` discriminator and the same `batch_id`.
Schedule and run rows share `run_id` (`<batch_id>-<index>`), which also names
the runtime container. Each schedule sequence matches exactly one terminal index.

- `batch.json` records catalog revision, admitted manifest path and manifest SHA-256; selected platform
  image, OS, architecture, toolchain and dependency-lock pins; task artifact
  paths (given and as opened by admission), compressed/tar-stream digests and test inventories;
  runtime kind/path, consumed native settings, host load and start time.
- `schedule.jsonl` records every planned entry and its sequence/run identity.
- `runs.jsonl` records one terminal per scheduled entry: `passed`, `failed`,
  `blocked`, `interrupted` or `error`. Executed rows retain tree/load/phases,
  execution/stop/cleanup errors and recovery paths. They include exact startup
  and phase argv, substituted environment, CPU/memory/PID/time limits, phase
  `elapsed_ms`, extraction/total lifecycle times, prove summary and reference.
  Blocked rows have `tree:null`, no phases, null summary/lifecycle errors,
  and carry `blocked_by` and `reason` from the triggering terminal.
- `batch-end.json` is written after final scratch cleanup. It records status,
  `interrupt_observed`, lifecycle error, outcome counts, finish time and wall time.
  It is exclusively created as `.batch-end.json.tmp`, written and synced before
  a directory-relative rename publishes it; the output directory is then synced.
  Failed publication removes the temporary file, preserving the primary error.
  Final cleanup failure is reflected in its error/status. A failure writing this
  file returns exit 1 and never prints `passed:`. After a run append fails, no
  further terminals or end marker are written; a missing end marker means incomplete.

Checked `libc::uname` supplies sysname, release, version and machine, without
reading `/proc` or `/etc` for identity. Nodename is omitted. Uname failure is an
explicit lifecycle error before output or scratch creation.

A native reference must have zero phase exits, positive `Files=` and `Tests=`
counts and a terminal `Result: PASS` prove summary. All later runs in that cell
must match both counts exactly. FAIL with exit 0, NOTESTS, bailout, missing or
malformed summaries, unequal counts, nonzero exits (including signals represented
as 128+n), timeout and interruption refuse a pass. Unknown skipped-test counts
remain null. `test_inventory` is recorded, not graded; comparison uses the native
reference. The stub prints `Files=1, Tests=10` for both `test` and `prove` commands.

Execution stops on the first unsuccessful entry and writes exactly one blocked
terminal for each remaining entry. Batch status precedence is `interrupted`,
`error`, `failed`, then `passed`. An interrupt at an entry gives that entry an
`interrupted` terminal and blocks later entries with reason `interrupted`.
An interrupt observed after completed terminals, including a failure break, keeps
the outcome-derived status and failure reason, and records `interrupt_observed:true`.

Exit **0** requires every scheduled run to pass; stub batches also exit 0 but
remain fixtures. Exit **1** covers failed/blocked, interrupted/incomplete and
operational/reporting failures. Exit **2** retains invalid arguments, manifest,
pins and selection refusals. There is no exit 130. Stderr distinguishes:

```text
sandbox bench: passed: N runs graded; batch complete; stub fixture, not publishable
sandbox bench: failed: batch complete with F failed and B blocked runs; see runs.jsonl
sandbox bench: interrupted: batch incomplete; N runs not executed
sandbox bench: interrupted: batch incomplete; lifecycle error: <error>
```

The interrupted count includes every entry without a passed/failed/error terminal,
including the entry whose interrupt arm fired. Status and interrupt observation are
frozen once for the end marker and stderr, including lifecycle errors.
A late interrupt on a completed batch appends `; interrupt observed after completion`.
Records make no throughput or verified-performance claim. `sandbox bench summarize`
is not yet available.

### Runtime kind

Execution requires explicit `--runtime-kind docker|stub`; classification is not
inferred from `--runtime PATH` and is not a manifest field. `podman` is parsed but
refused as **not yet qualified** before runtime canonicalisation, load checks,
artifact opening, inspect, uname or any creation. FUSE and unrunnable selections
retain refusal precedence. `docker` identifies real execution; `stub` records
`fixture:true`, `publishable:false` in batch/run records, and appends
`; stub fixture, not publishable` to successful completion. Docker records use
`fixture:false`, `publishable:true`; that label alone establishes no qualification.
All automated CLI integration uses the stub; it never invokes real Docker/Podman.

The flag is unnecessary for validate-only and dry-run. We choose Clap's
`requires = "out"` for this execution flag: explicitly supplying it with either
mode is refused, just as explicitly supplying `--runtime` is refused.

Scheduling is capped at **100000 total entries**, with exit **2** through
`selection:` before allocating the full entry list or starting execution. A cell
has at most one reference, two warm-ups, `2*repeats` measurements and one FUSE
probe (204 at repeats=100). This cap also applies to dry-run.

Cleanup walks top-down through held directory handles, chmodding pinned directories
to 0700 via `/proc/self/fd` before reopening each O_PATH pin with fd-relative
`openat(pin, ".")` for listing. Only one listing fd per frame survives the reopen.
Symlinks are unlinked without chmodding their targets. Before removing a directory
by name, cleanup checks that its dev/ino still matches the saved O_PATH identity;
a mismatch refuses removal and preserves the replacement. Linux has no unlink-by-fd:
a residual race remains between `fstatat` and `unlinkat`; the check narrows it.
The iterative walk caps depth at 256 frames, counting its root as frame 1; root
plus 255 descendants succeeds, and the 257th directory is refused. Starting at
the scratch leaf leaves 254 directory levels below tree `0`; starting at tree `0`
for `make_removable` or per-entry cleanup leaves 255. Extraction caps paths at
128 components; deeper trees can be runtime-created. Overflow or missing
`/proc` preserves the remaining tree and records `cleanup_error`; an inaccessible
`/proc` magic link also fails closed, with no by-name chmod fallback. Rootless Podman
without keep-id may return EPERM for subuid-owned directories; Podman qualification
remains out of scope. Extraction caches the last parent descriptor rather than
holding one descriptor per archive directory.

An interrupt before extraction records `execution_error: "interrupted"` with
`phases: []`; between entries it prevents the next extract and runtime start.
This interrupt arm cleans up exactly once before writing the row, with
`cleanup_error` null on success or containing the cleanup failure.
An interrupt before runtime spawn records a phase error with empty `stdout_log`
and `stderr_log` strings and creates no phase logs. Kill/rm cleanup still runs.
These outcomes exit **1** with the distinct `interrupted:` presentation and
`batch-end.json` status `interrupted`, including when lifecycle cleanup also fails.
