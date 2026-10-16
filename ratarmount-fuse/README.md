# FUSE adapter maintenance

The adapter uses fuser 0.18.0. Passthrough is **not enabled**. The CLI, overlay
cache policy, application readahead, detached inode lifetime, and separate
kernel notification worker retain their existing behavior.

## Migration from fuser 0.15.1

The [upstream changelog](https://github.com/cberner/fuser/blob/v0.18.0/CHANGELOG.md)
documents the 0.16–0.18 API changes. These choices matter for future upgrades:

| Upstream change | Adapter policy |
| --- | --- |
| `libfuse` is no longer a default feature | Enable it explicitly. Linux still prefers libfuse3, falling back to libfuse2; Darwin uses the `fuse` pkg-config package. The pure Rust mount backend is not selected. |
| `abi-7-*` Cargo features were removed | Use runtime negotiation: fuser advertises 7.40 on Linux and 7.19 on macOS. Keep the existing init capabilities; do not request passthrough, writeback cache, parallel directory operations, automatic data invalidation, or READDIRPLUS flags. |
| `FUSE_MAX_PAGES` is now requested when offered; newer ABI init replies include background limits | On Linux, cap requests at the previous 32 pages (128 KiB on 4 KiB-page hosts), including the kernel readahead value used to derive `max_pages`. Keep the old Linux kernel background/congestion defaults of 12/9. Application `--readahead` remains independent. macOS retains the 16 MiB fuser write buffer and its platform init flags; native mount validation remains necessary. |
| Most callbacks take `&self`; filesystems must be `Send + Sync`; optional parallel event loops | Set `n_threads = Some(1)` and `clone_fd = false`. fuser now runs that one event loop on its own thread, while the caller blocks in `run`. Raw overlay/parked-fd lifetimes continue to rely on serial requests. |
| Inodes, handles, flags, errors, and generations are typed; request offsets are unsigned | Convert at the adapter boundary. Keep errno values, KEEP_CACHE, zero create flags, generation zero, TTLs, and the existing signed-offset handling. Internal inode/handle tables remain unchanged. |
| `Config::acl` replaces AllowRoot/AllowOther mount options | Extract those tokens before mounting. Default is Owner; AllowRoot takes precedence when both tokens occur, as in 0.15's `Session::new`. |
| Typed AutoUnmount with Owner is rejected | With the explicitly selected libfuse backend, send `auto_unmount` and `allow_other` as CUSTOM options while retaining `SessionACL::Owner`. This reproduces 0.15's kernel permission option plus userspace owner check, including its `/etc/fuse.conf` requirement. Explicit AllowRoot/AllowOther uses typed AutoUnmount normally. |
| `Session::new` now rejects conflicting mount flags | Reduce opposite flag pairs in their original order, retaining libfuse's last-option-wins behavior. A read-only mount still ignores `rw`; user fsname still replaces the default. Unknown options still reach libfuse. |
| Handshake happens in `Session::new`; `run` consumes and unmounts the session, including on errors | Install the notification worker after the handshake, before any ordinary requests run. After `run`, clear its sender and join it. Kernel notifications remain off the request thread; ENODEV is handled by fuser and ECONNABORTED by the existing adapter. Malformed requests now return an upstream InvalidData error instead of the old successful loop exit. |
| New protocol operations are reachable | Default BATCH_FORGET dispatch calls the same `forget_nlookup` helper. Readdirplus remains implemented with its existing TTL policy; READDIRPLUS negotiation is not newly enabled. Unsupported operations keep the trait's error replies. |
| macOS support changed | fuser automatically selects `macfuse-4-compat` when using Darwin's libfuse mount backend. Do not enable `macos-no-mount` in production: it is a build-only stub. macFUSE/FUSE-T compatibility and unmounting require the native macOS CI/runtime checks. |

The Linux request bounds reflect the pre-MAX_PAGES kernel defaults in
[`fs/fuse/inode.c`](https://github.com/torvalds/linux/blob/master/fs/fuse/inode.c)
and [`fs/fuse/fuse_i.h`](https://github.com/torvalds/linux/blob/master/fs/fuse/fuse_i.h).
The higher ABI itself is intentional; wire negotiation and malformed-request
handling cannot be identical to the old 7.12 session.

## Passthrough (AI-PT)

`--passthrough auto|on|off` and opt-in bounded member copying are implemented.
See [FUSE kernel tuning](../docs/fuse-kernel-tuning.md#linux-fuse-passthrough)
for eligibility, cache placement, privilege requirements, and integration checks.
Writable overlay mounts keep daemon I/O so a later writer can use the overlay
policy funnel. Explicitly read-only overlay mounts can pass whole-file fds.
Passthrough replies omit `FOPEN_KEEP_CACHE` (the kernel rejects that combination);
daemon replies retain their existing flags. Registration failure fixes that
inode's mode to daemon I/O until its last release, avoiding mixed-mode EIO.

On Linux, `Filesystem::init` receives `&mut fuser::KernelConfig`. Check
`kernel_abi()` (at least `fuser::Version(7, 40)`) and
`capabilities().contains(fuser::InitFlags::FUSE_PASSTHROUGH)`. Only when supported,
call `add_capabilities(InitFlags::FUSE_PASSTHROUGH)` and
`set_max_stack_depth(1)` (or 2 if backing files may themselves be on a stacked
filesystem). Handle negotiation and backing-registration failures with the
existing daemon path. Keep macOS on that path.

At open, `ReplyOpen::open_backing(fd)` returns a managed `BackingId`;
`opened_passthrough(FileHandle, FopenFlags, &BackingId)` sends the open reply.
`ReplyCreate` has corresponding `open_backing` and `created_passthrough` methods.
Reuse the same backing registration for concurrent opens of the same inode,
and retain it while those opens need it; dropping the managed ID closes the
kernel registration. Raw registration APIs
exist but are unnecessary for ordinary opens. The backing file starts at byte
zero: archive member ranges need their own prepared files.

## Validation

`cargo test -p ratarmount-fuse --lib fuser_` covers mount configuration and,
on Linux, sends real protocol packets through `Session::from_fd` using a Unix
SEQPACKET socket. This verifies init, ACLs, typed reply encoding, reads, xattrs,
directory cookies, notifications, and detached inode FORGET/BATCH_FORGET without
`/dev/fuse`. It does not prove actual mount/unmount or kernel cache behavior.

Run the full library suite and the CLI integration tests on a FUSE-capable host:

```sh
cargo test -p ratarmount-fuse --lib
cargo test -p ratarmount --test fuse_rename --test fuse_rename_over \
  --test fuse_write_concurrency --test commit_overlay_live \
  --test startup_broken_stdio --test overlay_open_error
```

Cross-checking `aarch64-apple-darwin` requires both the Rust target and a usable
Apple SDK/C compiler plus target native libraries. Installing the Rust target
alone on Linux does not satisfy the C dependencies (including zstd, SQLite,
and libfuse). The native macOS CI job remains the platform gate.
