# Plan: ratarmount-side items from "What ratarmount-rs cannot establish on its own" (2026-11-15)

Source: the capability-gap report for SWE and CPAN agent evaluation, written against
commit `c1401e7e`. It compares documented capabilities; it is not a security test.

## What belongs where

The report places most gaps outside ratarmount:

| Gap | Owner | ratarmount action |
|---|---|---|
| Grader isolated from candidate code; hidden inputs and verdict under a separate authority | The verifier/runner (cpanmine) | None in code. Document the boundary. |
| Signed, verifiable record of who graded what | The trusted runner (receipt, then signatures) | Provide stable, documented receipt inputs (layer digest, base digest, policy, journal coverage). |
| Whole-run observation / reliable negative evidence | Split | **This plan: make journal coverage explicit (PR 1).** |
| Per-phase network and leakage policy | Broker, network policy, tool configuration | None in code. Document that `--network` is runtime-level, not an allowlist. |
| Judging whether a task measures the right behaviour | cpanmine | None. |
| Deliberate variation of filesystem behaviour (disorderfs-style) | Diagnostic first | Deferred (PR 3, only if a diagnostic finds real defects). |

The report's one recommended ratarmount-side change: *expose an explicit
observation-coverage and completeness field alongside the receipt, including journal
failures, disabled observation, and a distinction between "observed zero" and
"unknown".*

## PR 1: journal observation coverage (this PR)

### Problem
- A journal has a header but no end record. A clean unmount, a SIGKILLed mount, a
  writer that failed part-way and a mount still running all look the same to a
  reader. `summarize` tolerates a truncated tail silently.
- A writer failure appears only in the daemon log and the live `stats` xattr.
  It is not in the file, so a consumer reading the journal later cannot see it.
- The header does not record the observation settings (`--journal-reads first`,
  `--journal-exclude`), so a later reader cannot tell "no reads under `t/`" from
  "reads under `t/` were excluded".
- `files_read` and friends are positive evidence only. Absence of a path is
  "unknown" whenever coverage is incomplete, and read byte counts are lower bounds
  because page-cache and mmap hits produce no READ callback. Nothing in the
  output says so.

### Design (journal format stays version 1; all additions are additive, and
older readers already ignore unknown records and fields)
1. **Header `observation` object:** `reads` (`all`/`first`), `exclude` (the
   effective globs), `sync`, and a fixed `not_observed` list naming what the
   journal never records: `lookup`, `getattr`, `page_cache_reads`, `mmap_reads`,
   `other_protocols`, `outside_mount`.
2. **End record**, written by the writer thread as the last line on a clean
   finish: `{"op":"end","ts":…,"records":N}`, where `N` counts the records
   written in this segment after the header. It is written only when the writer
   has no error, so its presence proves the segment was flushed completely.
3. **`journal summarize` gains `coverage`:**
   - `segments`: one per mount header, each with `mount`, `t0`, `observation`
     (or `null` for a pre-coverage journal), `ended` (`clean` / `missing_end` /
     `truncated_tail` / `closed_by_mark`), `records_match` and the `excluded` count from `end`.
   - `complete`: true only if every segment overlapping the selected window
     recorded its observation settings and ended `clean` with a matching count,
     or (for a `--until-mark` window) the until-mark itself is present. Marks go
     through the same FIFO writer queue as every other record, so a present
     until-mark proves everything emitted before it was written.
   - **What `complete` means, and what it does not:** the file holds every record
     the daemon emitted for that window. It is never negative evidence of reads:
     page-cache and mmap hits produce no READ callback, so a path missing from
     `files_read` is always `unknown` as a read. The strongest negative the
     output offers is a path absent from `paths` (which includes open-only
     entries) over a complete, unwindowed, unexcluded segment: then no OPEN of
     it reached the mount. `semantics` states this in fixed fields.
   - `reasons`: a small closed set of fixed strings (`missing_end`,
     `truncated_tail`, `record_count_mismatch`, `pre_coverage_journal`).
   - `excluded_globs`, `reads_mode`: unions over segments, so a consumer can
     tell "excluded" from "not touched".
   - Summarize keeps scanning after the `--until-mark` record (it currently
     `break`s) so it can still judge the segment.
4. **Finalize and `sandbox run` reports:** `journal_summary` gains `complete`
   and `reasons` only (no globs: the reports have a size budget, checked by the
   `widest_report` pin and the request-log record bound; update both). The full
   coverage object goes in `journal.summary.json`. Disabled observation is
   already `journal_summary: null`; document that rather than adding a key, so
   unjournaled golden reports stay byte-identical. The journaled golden fixtures
   and the T1 catalog row change deliberately.
5. **`end` also counts `excluded`** (records suppressed by `--journal-exclude`),
   separating "excludes configured, nothing matched" from "something was hidden".
6. **Docs:** the Journal section gains a "Coverage and completeness" subsection;
   the SWE recipe gains a short "What ratarmount does not establish" section
   pointing to the runner-side responsibilities in the table above.

### Tests (`regression_` names)
- Writer: a clean finish writes `end` with the right count; a forced writer
  failure writes no `end`; the header carries `observation` with the effective
  excludes and read mode.
- Summarize table: clean → complete; missing end (killed mount) → `missing_end`;
  truncated tail → `truncated_tail`; count mismatch; a pre-coverage header →
  incomplete with reason; two segments where only one is clean; `--since-mark`
  windows judge only overlapping segments; an `--until-mark` window on a live
  journal (no `end`) is complete once the until-mark is present.
- Existing `{"journal":1}` fixtures in `finalize_tests.rs` and `run.rs` become
  pre-coverage journals; their exact-equality assertions change deliberately.
  `tests/sandbox_run.rs` skips on the dev host (no user namespaces), so its
  report fixtures are edited by hand and CI is their first real check.
- Untouched: the v2 protocol, `op_hash`, and `summarize`'s exit codes.
- FUSE: a real journaled mount, clean unmount → `complete: true`; SIGKILLed mount
  → `complete: false`, `missing_end`.
- Finalize/`sandbox run` reports carry `complete`.

## PR 2: receipt inputs (follow-up, only if cpanmine asks)
`sandbox run` and finalize already report layer digest, base digest and journal
summary. Add the effective read-only/allow policy and the ratarmount version if
the runner needs them in one place. No signing in ratarmount.

## PR 3: reproducible enumeration variation (deferred)
An opt-in `--readdir-order shuffle:SEED` (recorded in the journal header and
overlay metadata, never the default). Only if an external disorderfs run over
real CPAN tasks shows order-dependent defects worth catching.
