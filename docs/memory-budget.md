# Memory budget

`ratarmount --memory-budget 512M archive.tar.zst mountpoint/` limits the
process-wide reservations for the buffer and cache pools below. Sizes use binary
suffixes, as for `--readahead`: `512M` is 512 MiB. `0` disables optional buffering.
Library users can call `ratarmount_core::budget::MemoryBudget::install(bytes)`
before opening any sources. Installation is once per process, shared by all
Sessions and mounts; installing after the accountant has been used is an error.

Without the flag, existing caps and read paths are preserved, with one fix:
ZIP's inflate cache now has a 64 MiB byte limit as well as its 256-entry limit.
A count limit alone allowed arbitrarily large retained members. Larger Deflate
members now spill to an anonymous temporary file and remain seekable.

## Pools and fallback paths

Each named pool has a stable share of one eighth of the total budget, capped at
its previous preferred size. All instances of that pool share this allowance;
it is not an allowance per open file. The accountant also checks the process
total atomically. Unused capacity is not redistributed between pool names.
Registration supports a minimum size, but the consumers below use zero: they
can all decline optional caching. No minimum can override the process limit.

| Pool | Preferred cap | On pressure / reservation refusal |
|---|---:|---|
| `http-prefetch` | 256 MiB | Cancel speculative ranges; synchronous reads |
| `fuse-readahead` | 64 MiB | Evict idle windows; exact requested reads |
| `zstd-decode-ahead` | 64 MiB | Cancel queued frames; synchronous decode |
| `zstd-frame` | 64 MiB | Spill a synchronous frame to a temporary file |
| `sevenzip-chunks` | 64 MiB | Evict windows; decode requested range without retaining it |
| `zip-inflate` | 64 MiB | Evict completed slots; stream Deflate into a temporary file |
| `seekable-body` | 256 MiB | Keep decoded body on disk |
| `http-fallback` | 64 MiB | Budgeted Range-ignored HTTP responses stream to disk |
| `hf-fallback` | 64 MiB | Spool a Range-ignored response to disk; existing 64 MiB response limit still applies |
| `rapidgzip` | 64 MiB | Budgeted mode disables optional seek caches and prefetch |
| `sqlite` | 320 MiB | Reserve page-cache capacity (at most its original size or 64 MiB per connection), disable mmap; shrink cache to zero under pressure |

Shrink hooks run in this order: speculative work, retained caches, SQLite.
Hooks use nonblocking locks; an active reader cannot be forcibly evicted.
Workers keep reservations through completion/cancellation and shared buffers keep
them until the last reader releases them. When reclamation cannot immediately
satisfy a request, that request uses its synchronous or disk path.

Rapidgzip's library byte cap permits one oversized window, so budgeted mode
sets both its cache count and bytes to zero and disables read-ahead/prefetch.
7z's progressive LZMA2 decoder also disables its full-folder and contiguous
prefix caches in budgeted mode. This can increase work on backward seeks.
Temporary files follow the platform temporary directory (`TMPDIR` on Unix).
A full or unwritable temporary filesystem can still cause an I/O error.

## Status

Both control-socket `status` and `/.ratarmount-control/status` include:

```text
memory_budget 67108864
memory_reserved 8388608
memory_high_water 12582912
memory_pool zip-inflate reserved=4194304 high_water=8388608 cap=8388608
```

Values are bytes. Pools appear when first used. Without the flag,
`memory_budget` is `unlimited` and reservations are not tracked (zero counters).
A debug-level one-line summary is emitted during unmount cleanup. SQLite and
7z report reserved capacity, which may exceed the number of currently populated
pages/windows. High-water marks persist after readers and caches close.

## Scope

This is a retained-buffer budget, **not an RSS limit**. Kernel page cache is not
counted; `--direct-io` is a separate option. Codec dictionaries and decoder
state, thread stacks, allocator overhead, caller-requested read buffers,
metadata/index structures (including SQLite in-memory databases and compact
indexes), and mandatory synchronous I/O and codec scratch are outside these pools.
Non-progressive 7z codecs, encrypted ZIP members, and ZIP codecs other than
Deflate retain their existing fallback behavior. Some legacy full-decode codec
paths also materialize their output before handing it to the seekable-body pool.
Disk payload/range caches are not charged; no additional RAM member-chunk cache
exists in the compositing layer.

In particular, this option alone cannot guarantee that another process's model
allocation will succeed on unified-memory hardware. Reserve additional headroom
for the listed exclusions and the operating system.

## Validation

The unit suites include accountant release, rejection, priority, concurrency,
consumer fallback, byte-bound, and status regressions. Run the Session stress
case without FUSE:

```sh
cargo test -p ratarmount --test memory_budget
```

It opens eight 4 MiB ZIP members concurrently with the same 64 MiB accountant
used by the CLI, checks every byte, and asserts total and per-pool high-water
marks. The test intentionally does not assert RSS.
