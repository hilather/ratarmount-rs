# #328 profile: write-overlay create+unlink cost

Initial profile measured `c1401e7`; the implemented opt-in durability mode and
its follow-up measurements are recorded under B1 below. Plan context:
[`issues-326-329-plan.md`](issues-326-329-plan.md) (#328 section).

## Summary

The issue reproduces: 50 creates plus 50 unlinks take 0.67–0.73 s in a disk
overlay. The reporter saw 0.70 s. In `--overlay-tmpfs` they take 6–20 ms.
**Fsync accounts for nearly all of the time.** Each create and each unlink
is one SQLite transaction, and each transaction costs 4 fsyncs: 3 on the
rollback journal and 1 on the database. The fsyncs cost 6.2–6.7 ms of the
~7 ms per operation. With the overlay connection at `PRAGMA synchronous=OFF`,
the same workload takes 7.8 ms, about 85× faster. That is the same as
`--overlay-tmpfs`. FUSE round trips are minimal: 5 per create
(LOOKUP, CREATE, GETXATTR, WRITE, RELEASE) and 3 per unlink (LOOKUP, UNLINK,
FORGET), with no kernel notifies. Neither `--journal` nor
`--overlay-readonly`/`--overlay-allow` rules cost anything measurable: on
tmpfs the difference is under 0.03 ms per op and within run-to-run noise.

The per-op fsyncs do not make the create durable either. Neither the new
payload file nor its parent directory is fsynced, so after a power loss a
durable `files` row can describe a file that does not exist. The recommended
first fix (A1 below) removes the transaction for overlay-only paths without
weakening any guarantee that holds today.

## Environment

| Item | Value |
|------|-------|
| Host | aarch64, 20 cores, Ubuntu 24.04.5, kernel 7.0.0-1025-nvidia |
| Overlay / bench filesystem | ext4 on NVMe (`/var/tmp`, `/dev/nvme0n1p3`) |
| tmpfs | `/dev/shm`; `--overlay-tmpfs` puts its overlay and its database there |
| Binary | `cargo build --release -p ratarmount` at `c1401e7` (0.2.1 plus 26 commits; no overlay-path changes since v0.2.1 except #280) |
| Mount | `ratarmount -f --passthrough off -w DIR base.tar MNT` (3-member TAR) |
| Tools | `strace` (attached through an exec-into-strace wrapper, see Method); `perf` unusable (`perf_event_paranoid=4`, no sudo); unprivileged user namespaces blocked |

## Numbers

`benchmarks/overlay-create-unlink.sh`, N=50, REPS=3 (medians after one
discarded warm-up round on the same mount). Each create is
`open(O_CREAT|O_TRUNC)` + 32-byte write + close. Each unlink is `unlink(2)`.
The workload runs in `work/`. The rules variants use
`--overlay-readonly '**' --overlay-allow 'work/**'`.

| Variant | create ms/op | unlink ms/op | 50 create+unlink, s |
|---------|-------------:|-------------:|---------:|
| baseline tmpfs dir (no FUSE) | 0.006 | 0.004 | 0.0005 |
| baseline ext4 dir (no FUSE) | 0.008 | 0.007 | 0.0007 |
| `-w` disk | 6.7–7.5 | 6.7–7.3 | 0.67–0.73 |
| `-w` disk `--journal` | 6.7–8.7 | 6.3–7.4 | 0.67–0.80 |
| `-w` disk + rules | 7.7 | 7.7 | 0.76 |
| `--overlay-tmpfs` | 0.07–0.24 | 0.05–0.15 | 0.006–0.019 |
| `--overlay-tmpfs --journal` | 0.24 | 0.14 | 0.019 |
| `--overlay-tmpfs` + rules | 0.25 | 0.16 | 0.021 |

Ranges are separate runs of the script. At N=50 the tmpfs rows vary by about
3× between runs because they are sub-millisecond. Two runs at N=500,
REPS=5 settle them:

| Variant (N=500, REPS=5) | create ms/op | unlink ms/op |
|---------|------:|------:|
| `--overlay-tmpfs` | 0.096 / 0.109 | 0.066 / 0.068 |
| `--overlay-tmpfs --journal` | 0.115 / 0.110 | 0.072 / 0.071 |
| `--overlay-tmpfs` + rules | 0.110 / 0.133 | 0.069 / 0.071 |
| `-w` disk + rules | 7.23 / 7.12 | 6.74 / 6.91 |

The rules are enforced on these mounts: a create at the root or under
`src/` fails with `EROFS`, a create under `work/` succeeds, and
`erofs_denied` counts 2.

The issue's "~1 ms per file on tmpfs" probably includes the cost of its
shell loop. Raw syscalls on tmpfs cost 6 µs.

### Durability share (local experiment, reverted, not committed)

`PRAGMA synchronous=<v>` was set on the overlay connection right after
`LOCKING_MODE = EXCLUSIVE` in `WriteOverlay::open_with_create_info`, chosen
at run time from an environment variable:

| `synchronous` | disk create ms/op | disk unlink ms/op | 50 create+unlink, s | fsyncs per op |
|---------------|------:|------:|------:|---:|
| default (FULL) | 6.74 | 6.73 | 0.667 | 4 (3 journal + 1 db) |
| FULL (explicit) | 7.17 | 6.68 | 0.698 | 4 |
| NORMAL | 5.01 | 4.75 | 0.498 | 3 (2 journal + 1 db) |
| OFF | 0.098 | 0.056 | 0.0078 | 0 |

The same build's `--overlay-tmpfs` stayed at 0.17–0.24 / 0.05–0.15 ms/op for
every setting. Fsync on tmpfs is already nearly free, so a relaxed mode gives
tmpfs nothing.

## Per-operation counts (disk overlay, default FULL)

Daemon syscalls from `strace -f -y -T`, segmented at each workload
`openat(work/fN.txt, O_CREAT)` / `unlinkat(work/fN.txt)`. The warm-up round is
dropped, leaving 100 ops of each kind:

| Per op | create | unlink |
|--------|------:|------:|
| SQLite transactions | 1 (`PendingFilesOp::Present`) | 1 (`PendingFilesOp::Deleted`) |
| fsync of `.ratarmount.overlay.sqlite-journal` | 3.00 (4.7 ms) | 3.01 (5.0 ms) |
| fsync of `.ratarmount.overlay.sqlite` | 1.00 (1.5 ms) | 1.00 (1.7 ms) |
| fsync of the payload file or any directory | 0 | 0 |
| pwrite64 (journal + db pages) | 12 | 19 |
| statx | 11 | 5 |
| openat of the payload | 2 (admitted `O_PATH` + `/proc/self/fd` reopen) | 1 (FUSE #88 park open) |
| journal file open / unlink | 0 | 0 |
| FUSE requests | LOOKUP (ENOENT) + CREATE + GETXATTR + WRITE + RELEASE | LOOKUP + UNLINK + FORGET (no reply) |
| FUSE replies / kernel notifies | 5 / 0 | 2 / 0 |

The FUSE rows come from decoding the opcode of every `read(/dev/fuse)` and
the out-header of every `writev(/dev/fuse)` (`unique == 0` is a notify) in
the daemon trace of a `--overlay-tmpfs` mount. They agree with the root
`user.ratarmount.stats` xattr: `fuse_req.lookup` +1.0 and `lookup_enoent`
+1.0 per create, `lookup` +1.0 per unlink, `getattr` and `readdirplus` +0.
The GETXATTR is the kernel's `security.capability` check before the first
write. No FLUSH reaches the daemon. FORGET arrives either as FORGET (0.78
per unlink) or inside a BATCH_FORGET.

Why there are 3 journal fsyncs: the connection uses `LOCKING_MODE=EXCLUSIVE`
with the default DELETE journal mode. In exclusive mode SQLite keeps the
journal file and zeroes its header at commit, instead of deleting it. Under
FULL it fsyncs the journal body, the header after it writes the record
count, and the zeroed header (the commit point), and then the database.
NORMAL drops the header-count fsync. Other journal modes give the same
count. Measured with a Python `sqlite3` script (system SQLite 3.45.1,
`synchronous=FULL`, one-row transactions after a warm-up, syncs per commit
under strace):

| locking_mode / journal_mode | journal syncs | db syncs | directory syncs | other per commit |
|---|---:|---:|---:|---|
| EXCLUSIVE / DELETE (ratarmount) | 3 | 1 | 0 | |
| EXCLUSIVE / TRUNCATE | 3 | 1 | 0 | 1 ftruncate |
| EXCLUSIVE / PERSIST | 3 | 1 | 0 | |
| NORMAL / DELETE | 2 | 1 | 1 | journal open + unlink |
| NORMAL / TRUNCATE | 3 | 1 | 1 | journal open + ftruncate |
| NORMAL / PERSIST | 3 | 1 | 1 | journal open |

Every row costs 4 syncs per commit. System SQLite uses `fdatasync`;
ratarmount's bundled SQLite issues `fsync`, which has the same count.
Exclusive mode is also needed for the lock model. No journal-mode change
helps, and WAL is out (#239).

Directory fsyncs come only from the publish and COW paths
(`publish_cow_staging`, the marker), not from creating or unlinking new
small files.

There is one unlink pwrite more than for a create. `Deleted` also inserts an
`xattrs(path,'',NULL)` reset row, and that row stays after the path is gone.
A long create/delete loop grows the `xattrs` table by one row per deleted
name, including names that were never in the base.

## CPU profile

`perf record` was not possible on this host: `perf_event_paranoid=4`, no
root, and tracefs is root-only. The `synchronous=OFF` run bounds the non-fsync
cost: 0.06–0.10 ms per op on disk, about 1.5% of the default op time, and
that includes FUSE round trips. A CPU profile cannot change the ranking
below. At N=500 the policy rules and `--journal` add under 0.03 ms per op
on tmpfs, which is within noise. The remaining ~0.1 ms per op of an
`--overlay-tmpfs` mount, against 6 µs for a raw tmpfs directory, is mostly
the 5 or 3 FUSE round trips. Profile on a perf-capable host only if A1 or B1
leave tmpfs-speed mounts as the bottleneck.

## Cold first grep (secondary)

3,000 files × 1 KiB in 30 directories, `grep -rl` for a string in the last
file:

| | first | second | third |
|-|-----:|-----:|-----:|
| extracted ext4 dir | 4.8 ms | 5.0 ms | |
| `-w` mount (new index) | 114 ms | 32 ms | 32 ms |
| remount (index exists) | 114 ms | 37 ms | |

The cold/warm ratio (3.5×) is the same with an index that already exists.
The cold cost is therefore filling the per-mount kernel and daemon caches
(LOOKUP/attr/page cache), not building the index. It is unrelated to the
create/unlink cost. Track it separately as the plan suggests.

## Fix options, ranked

### (a) Overhead fixes with no durability change

**A1. Skip the `files` transaction for overlay-only names (recommended next
fix).** Gain: for names that are neither in the base nor tombstoned (temp
files, build outputs, the issue's workload), create and unlink drop from
about 7 ms to about 0.1 ms per op. That is the `synchronous=OFF` figure or
better, because no SQL runs. The fix:
- `mark_present`: skip `Present` when `!current_base().exists(path)`, no
  `files` row exists for the path (a read on a cached page, no fsync), and
  no `overlay_metadata` row needs deleting. The host file carries the mode
  that `create_file_inner` set.
- `mark_deleted` with `hides_base == false`: skip the transaction when the
  path has no `files`, `overlay_metadata` or `xattrs` rows. Today this
  deletes the row that `Present` wrote and adds a reset `xattrs` row, which
  does nothing for a path with no base xattrs.

A row-less host file is already a legal state. `overlay fsck` counts it as
`unrowed`, which is not an error (the SBX-COW fix and
`regression_cow_fsck_clean_and_repair_preserves_unrowed_content`). Today a
crash between the host `open(O_CREAT)` and the row commit leaves exactly
that state.

Checked by hand for a new name, not only for COW of a base file, with the
same release binary. First case: create `work/added.txt` on a `-w` mount and
`chmod 0751` it, unmount, then delete its `files` and `overlay_metadata`
rows with Python `sqlite3`. Second case: drop a host-only file
`work/hostonly.txt` (mode 0700) straight into the overlay directory.
- On remount, the first file is listed with mode 0751 and reads back its
  content.
- `overlay fsck` reports `result: ok`, `unrowed: 3` (two files plus the
  implicit `work/` directory).
- `ratarmount diff` shows both files as `new file mode 100751` /
  `new file mode 100700`.
- An offline `--commit-overlay` into the recorded base archive writes both
  members, with the host modes (`-rwxr-x--x`, `-rwx------`).

Not yet checked: live and interval commit, seal and pack, and renaming a
row-less file. These are in the list below.

Durability does not change. Today neither the payload nor its parent
directory is fsynced, so power loss can already lose the host file while
the fsynced row survives (fsck then reports `missing_content`), or bring
back an unlinked file. After A1 a crash leaves the host state alone, which
is the state a row-less create already produces.

Before implementing, check these against the regression catalog:
- the #88 rows: `pending_rows` ordering. An elided op must still queue
  behind unsaved rows, so a replay cannot undo it. Only skip when the queue
  is empty, under the same lock;
- SBX-DIFF/SBX-COW: `diff`, the canonical hash, the manifest and
  `--between` must report an unrowed host file that has no base entry as
  Added, with the host mode;
- commit (`--commit-overlay`, live/interval): it must pick up unrowed
  additions. Confirm in `commit_overlay*` / `live_commit*`;
- seal and `pack` agreement (`fuse_cow_agreement`): add a
  create-then-delete case and a create-only case;
- `rename` of a row-less file: `PendingFilesOp::Rename` must still record
  the destination;
- import marker N5 / hot journal R4-I1: not affected (offline, own
  connection).

**Implemented** for regular-file creates and for unlinks/rmdirs of names the
lower view lacks; mkdir and symlinks keep their rows. Analysis, tests and
measurements (disk `full`: 7.1 / 6.6 → 0.12 / 0.07 ms per create / unlink):
[`issue-328-option-a.md`](issue-328-option-a.md).

**A2. Smaller per-op transactions.** The Deleted row keeps an `xattrs` reset
row for names that never had base xattrs (19 vs 12 pwrites, and unbounded
table growth). Write it only when the base entry has xattrs. Gain: a few
pwrites per op and a bounded `xattrs` table. No fsync change.

**A3. FUSE round trips.** Already close to minimal. Each op has one LOOKUP,
which the kernel needs for a name it has not cached, and there are no
notifies or extra GETATTRs. The only optional request is the
`security.capability` GETXATTR before each new file's first write, about
1 of 5 create round trips. Answering it cheaply, or having the kernel skip
it, saves a few µs per create and matters only at tmpfs speed.

Ops that change base-visible state (tombstoning a base member, chmod, a
rename over a base name) still cost 4 fsyncs after A1. Only (b) or batching
helps them.

### (b) Opt-in relaxed durability

**B1. `--overlay-durability=relaxed`: `PRAGMA synchronous=OFF` on the
overlay connection, and skip the COW/publish directory fsyncs.** Gain:
about 85× on disk overlays for every overlay mutation (measured 0.67 s →
0.0078 s). No gain for `--overlay-tmpfs` (measured equal), so making it the
tmpfs default is harmless but buys nothing. The candidates for a default
are the sandbox supervisor's Disk attempt overlays and `sandbox run`, which
throw the overlay away or rebuild it.

Crash semantics: a daemon SIGKILL stays consistent under OFF, because every
write already reached the page cache and the persistent journal still rolls
back a torn transaction. A kernel crash or power loss can corrupt the
database, not just lose recent transactions. The mode must therefore:
- record itself and a dirty flag in overlay `meta` (plus
  `/proc/sys/kernel/random/boot_id`), and clear the flag at clean unmount;
- make `overlay fsck` run `PRAGMA integrity_check` and report when the flag
  is set and the boot id has changed. `--repair` must not "repair" a
  corrupt database into a clean one;
- make `overlay seal` / `pack` / `verify` refuse a dirty relaxed overlay
  after a reboot, and have `seal` itself run at FULL (fsync tree and
  database) before it writes the seal (SBX-SEAL rows);
- keep #126 (COW crash mid-copy): the staging file plus rename still hides
  a partial copy under SIGKILL. Under power loss the dirty flag routes it to
  fsck;
- keep the import marker N5 and hot-journal R4-I1: `overlay import` is
  offline and keeps FULL;
- keep commits (`--commit-overlay`, live/interval/on-exit) at FULL for
  their own transactions and journal (R6/R7 commit-journal rows), since they
  change the base archive.

**B2. `synchronous=NORMAL` only.** Gain: 25% (0.67 → 0.50 s), with SQLite's
small risk of power-loss corruption in rollback mode. B1 has the same kind
of risk for a much larger gain. Not worth a mode of its own.

**Implemented** as `--overlay-durability=relaxed` (synchronous=OFF behind a
boot-ID marker; no COW directory-fsync change; relaxed refuses archive
commits instead of switching them back to FULL). Measured N=200, REPS=3 on
ext4: `-w` 7.04 / 6.55 ms per create / unlink, relaxed 0.155 / 0.078,
`--overlay-tmpfs` 0.111 / 0.065. The combined workload fell from 2.72 s to
0.047 s (about 58×); the earlier 85× figure describes the local experiment,
not this implementation measurement. See docs/sandbox.md, "Relaxed overlay
durability".

### Out of scope

WAL (#239). Group commit across FUSE requests: it conflicts with
reply-after-persist, and the FUSE daemon serializes requests, so there is
little concurrency to batch.

## Method and reproduction

```bash
TMPDIR=/var/tmp CARGO_BUILD_JOBS=2 flock /tmp/muse-cargo.lock cargo build --release -p ratarmount
TMPDIR=/var/tmp bash benchmarks/overlay-create-unlink.sh                 # all variants
TMPDIR=/var/tmp VARIANTS=disk,tmpfs N=200 bash benchmarks/overlay-create-unlink.sh
bash benchmarks/overlay-create-unlink.sh --self-test                    # no binary/FUSE
```

strace: a traced setuid `fusermount3` cannot mount, and Yama
`ptrace_scope=1` allows tracing only descendants. Point `RATARMOUNT` at a
wrapper that starts the daemon untraced and then `exec`s into strace, so the
tracer is the daemon's parent:

```bash
#!/bin/bash
"$REAL" "$@" & pid=$!
mnt="${@: -1}"
until [ -e "$mnt/README" ]; do sleep 0.01; kill -0 $pid 2>/dev/null || exit 1; done
exec strace -f -y -T -p $pid -o "$TRACE_OUT" -e trace=fsync,fdatasync,openat,unlinkat,pwrite64,statx,fcntl
```

The wrapper attaches once the mount is ready, so the first (warm-up) round
can be partly untraced. The analysis therefore drops the first 50 ops of
each kind. For the FUSE request rows use
`-xx -s 24 -e trace=read,writev,openat,unlinkat`: the opcode is bytes 4-7 of
each `read` from `/dev/fuse`, and a `writev` whose out-header `unique` is 0
is a notify.

Run it with `REAL=target/release/ratarmount TRACE_OUT=trace.txt
RATARMOUNT=./wrap.sh VARIANTS=disk REPS=2`. Then attribute each `fsync(fd<path>)`
by its `-y` path and segment the trace at the workload's
`openat(.../work/fN.txt, O_CREAT)` / `unlinkat` calls.

FUSE counters: `os.getxattr(MNT, 'user.ratarmount.stats')` before and after
each phase (`fuse_req.lookup`, `lookup_enoent`, `getattr`, `readdirplus`).
