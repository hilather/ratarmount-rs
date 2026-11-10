# Sandbox benchmark validation and schedules

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
fields are validated now for later execution; this command executes nothing.
Draft results remain **not yet run — pins unresolved**; target hosts **need hardware**.

Linux builds also schedule without executing:

```sh
ratarmount sandbox bench --manifest tasks.json --dry-run --jobs 1
ratarmount sandbox bench --manifest tasks.json --dry-run --task mojolicious --backend native,fuse --base-form git,tar.zst-single-frame --jobs 1,2,8 --cache cold,warm --repeats 5 --seed 1 --attempts 1 --allow-oversubscription
```

Exactly one of `--validate-only` or `--dry-run` is required. Selection options
require `--dry-run`; `--require-pins` works with either mode. Validation runs
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
unsupported jobs. No host capacity, runtime or source availability is probed.

Stdout contains one `rrs-perl-bench-schedule/1` JSON object per line. No output
files, work roots or prepared sources are created. Each entry records the cell,
catalog revision, backend, kind, repeat, pairing, seed, repeats, attempts, CPU
limit, admission override and availability. `qualified` describes the validated
manifest claim; `execution_available` and `runnable` are **false** in this slice,
including for qualified rows. `reasons` retains draft qualification reasons and
explains that execution is unavailable. These are planned entries, not results.
Runtime, output, work-root and high-load options are deferred.

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
