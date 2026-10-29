#![forbid(unused_macros)]
#![cfg_attr(not(internal_read_inventory), allow(unfulfilled_lint_expectations))]

//! ratarmount CLI (Phases 0–11 + CLI flag parity).

use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use clap::{ArgAction, Parser};
use nix::unistd::{fork, setsid, ForkResult};
pub(crate) use ratarmount_compositing::lower_stack::MountLowerStack;
use ratarmount_compositing::{
    maybe_wrap_payload_cache, CommitOverlayOptions, ControlFolderMountSource, ControlFolderOptions,
    OverlayError, WriteOverlay, HIDDEN_DB,
};
use ratarmount_compress::{
    repack_seekable, strip_compression_suffix, GzipSidecar, RepackAction, RepackOptions,
    RepackReport, DEFAULT_REPACK_FRAME_SIZE,
};
use ratarmount_core::{MountSource, OpenOptions, ParallelizationSpec};
use ratarmount_fuse::{
    clamp_readahead, mount_blocking_with_activity as fuse_mount_blocking, parse_byte_size, unmount,
    PassthroughMode, PassthroughOptions, RECOMMENDED_READAHEAD_BYTES,
};
use ratarmount_index::{
    bind_local_index_id, default_index_folders, fill_content_hashes, parse_index_folders,
    resolve_index_location, SqliteIndex, MEMORY_INDEX,
};
use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicBool, Ordering};

use ratarmount_session::factory;

#[macro_use]
mod quiet_print;

mod base_digest;
mod base_identity;
mod corpus;
mod diff;
mod export_index;
mod find;
mod journal_cmd;
mod mount_guard;
mod overlay_cmd;
mod overlay_commit;
mod overlay_create;
mod overlay_import;
mod overlay_pack;
mod overlay_stats;
mod publish_index;
mod sandbox;
mod shard;
mod snapshot;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser, Debug)]
#[command(
    name = "ratarmount",
    version = VERSION,
    about = "Random Access To Archived Resources (Rust rewrite)",
    long_about = "Mount archives (TAR/ZIP/AR/CPIO/libarchive, compressed) via FUSE.\n\
                  Supports recursive automount (-r), write overlay (-w), remote URLs\n\
                  (http(s)/s3/gs/az/ftp/ssh/oci/ipfs/rclone), and userspace exports\n\
                  (--nfs, --http, --webdav, --smb, --ninep, --sftp, --sftp-subsystem).\n\
                  Optional sugar: ratarmount serve --nfs --http ARCHIVE (requires at\n\
                  least one export; incompatible with --no-mount).\n\
                  Locate: ratarmount find '*.fits' ARCHIVE (no FUSE; TSV path/size/mtime).",
    after_help = "Export sugar: ratarmount serve --nfs --http ARCHIVE\n\
                  Requires at least one of --nfs/--http/--webdav/--smb/--ninep/--sftp/--sftp-subsystem.\n\
                  Incompatible with --no-mount. Boolean flags remain the stable interface.\n\
                  Locate: ratarmount find [--fts] [--hashes] [--offset-order] PATTERN ARCHIVE (no FUSE).\n\
                  Corpus: ratarmount corpus LIST-FILE MOUNTPOINT [--corpus-cache-size N].\n\
                  Sandboxes: ratarmount sandbox daemon|create-base|new|list|diff|stats|destroy|shutdown --socket PATH.\n\
                  Statistics: ratarmount overlay-stats OVERLAY [--json] (no FUSE).\n\
                  Patch: ratarmount diff --base SOURCE OVERLAY [--git] (no FUSE).\n\
                  Datasets: ratarmount shard INPUT -o OUTPUT; ratarmount export-index ARCHIVE --format parquet|jsonl|csv.\n\
                  Snapshots: ratarmount snapshot add DIR --repo REPO [--init]; ratarmount snapshot list --repo REPO."
)]
#[command(group(clap::ArgGroup::new("overlay_target").args(["write_overlay", "overlay_tmpfs", "sandbox"]).multiple(true)))]
struct Args {
    /// Unmount the given mountpoint(s)
    ///
    /// On Linux this runs `fusermount3 -u` and retries about 1 s while the mount is busy
    /// (desktop watchers such as gvfsd-trash probe a new mount).
    #[arg(short = 'u', long = "unmount", action = ArgAction::SetTrue)]
    unmount: bool,

    /// Stay in foreground (default: daemonize after mount is ready)
    ///
    /// SIGINT (Ctrl-C) unmounts with the same ~1 s retry and never detaches lazily; send it
    /// again to retry. SIGTERM retries for about 1 s, then detaches lazily (`fusermount3 -u -z`)
    /// and the process exits once open files close. macOS has no lazy detach.
    #[arg(short = 'f', long = "foreground", action = ArgAction::SetTrue)]
    foreground: bool,

    /// Recreate the index
    #[arg(short = 'c', long = "recreate-index", action = ArgAction::SetTrue)]
    recreate_index: bool,

    /// Use only complete prepared indexes; never rebuild, recover, or modify shared state
    #[arg(long = "no-recreate-index", action = ArgAction::SetTrue)]
    no_recreate_index: bool,

    /// Do not mount; only create/load index
    #[arg(long = "no-mount", action = ArgAction::SetTrue)]
    no_mount: bool,

    /// Recursive mounting of nested archives
    #[arg(short = 'r', long = "recursive", action = ArgAction::SetTrue)]
    recursive: bool,

    /// Lazy recursive mounting: mount nested archives on first access
    #[arg(short = 'l', long = "lazy", action = ArgAction::SetTrue)]
    lazy: bool,

    /// Cap worker threads for eager AutoMount same-dir nested opens (FR-6 / #80).
    /// `0` or `auto` = `available_parallelism` (default); `1` = sequential; `N≥2` = cap at N.
    /// Only applies to eager recursive scan (`-r` without `-l`); lazy mode ignores this.
    #[arg(
        long = "parallel-nested",
        default_value = "0",
        value_name = "N",
        value_parser = parse_parallel_nested
    )]
    parallel_nested: u32,

    /// Mount nested `foo.tar` at `foo/` instead of `foo.tar/`
    #[arg(short = 's', long = "strip-recursive-tar-extension", action = ArgAction::SetTrue)]
    strip_recursive_tar_extension: bool,

    /// Transform nested mount points: `--transform-recursive-mount-point REGEX REPL`
    #[arg(long = "transform-recursive-mount-point", num_args = 2, value_names = ["REGEX", "REPLACEMENT"])]
    transform_recursive_mount_point: Option<Vec<String>>,

    /// Disable `<path>.versions/<n>` virtual folders (enabled by default)
    #[arg(long = "no-file-versions", action = ArgAction::SetTrue)]
    no_file_versions: bool,

    /// Mount content under this prefix path (e.g. `-p data` → `/data/...`)
    #[arg(short = 'p', long = "prefix", default_value = "")]
    prefix: String,

    /// Unix socket for control commands (`status`, `unmount`, `ping`)
    #[arg(long = "control-interface", action = ArgAction::SetTrue)]
    control_interface: bool,

    /// Serve the control socket but not the in-FS `/.ratarmount-control/`
    /// folder (experimental; `sandbox run` uses it so the pid, memory stats
    /// and `unmount` file are not visible in the container).
    #[arg(
        long = "control-socket-only",
        hide = true,
        requires = "control_interface",
        action = ArgAction::SetTrue
    )]
    control_socket_only: bool,

    /// Export the archive as NFS (userspace). Does not require a FUSE mountpoint.
    /// Default protocol is NFSv3. Bind address is `--nfs-bind` (default 127.0.0.1:20490).
    #[arg(long = "nfs", action = ArgAction::SetTrue)]
    nfs: bool,

    /// NFS listen address (`[host:]port`, IPv4 only). Default 127.0.0.1:20490.
    /// Bare port (`20490`) or `:20490` → 127.0.0.1:that port.
    #[arg(
        long = "nfs-bind",
        value_name = "ADDR:PORT",
        default_value = "127.0.0.1:20490"
    )]
    nfs_bind: String,

    /// NFS protocol version. Default 3 (nfsserve). `4` is NFSv4.1 (embednfs;
    /// needs `--features nfsv4`). Required value (`num_args = 1`). Do **not**
    /// use `num_args = 0..=1` — that recreates the `--nfs` archive-steal bug.
    /// `--nfs --nfs-vers testdata.tar.gz` (missing value) consumes the archive
    /// as the version string; clap succeeds, then parse fails (exit 2).
    /// Parsed only when `--nfs` is set; FUSE-only `--nfs-vers 4` is ignored.
    #[arg(
        long = "nfs-vers",
        value_name = "3|4",
        default_value = "3",
        num_args = 1
    )]
    nfs_vers: String,

    /// MOUNT export name without slashes (nfsserve `with_export_name`). Default: `/`.
    /// Ignored on NFSv4.1 (no MOUNT).
    #[arg(long = "nfs-export-name", value_name = "NAME")]
    nfs_export_name: Option<String>,

    /// Export the archive over HTTP GET/HEAD with byte ranges. Default bind
    /// `--http-bind` (`127.0.0.1:20491`). Does not require a FUSE mountpoint.
    #[arg(long = "http", action = ArgAction::SetTrue)]
    http: bool,

    /// HTTP listen address (`[host:]port`, IPv4 only). Default 127.0.0.1:20491.
    #[arg(
        long = "http-bind",
        value_name = "ADDR:PORT",
        default_value = "127.0.0.1:20491",
        num_args = 1
    )]
    http_bind: String,

    /// Export the archive over WebDAV (PROPFIND + GET; writes need `-w`).
    /// Default bind `--webdav-bind` (`127.0.0.1:20492`).
    #[arg(long = "webdav", action = ArgAction::SetTrue)]
    webdav: bool,

    /// WebDAV listen address (`[host:]port`, IPv4 only). Default 127.0.0.1:20492.
    #[arg(
        long = "webdav-bind",
        value_name = "ADDR:PORT",
        default_value = "127.0.0.1:20492",
        num_args = 1
    )]
    webdav_bind: String,

    /// Export the archive as userspace SMB 2.0.2. Default bind `--smb-bind`
    /// (`127.0.0.1:20445`). Share name `--smb-share` (default `ratarmount`).
    #[arg(long = "smb", action = ArgAction::SetTrue)]
    smb: bool,

    /// SMB listen address (`[host:]port`, IPv4 only). Default 127.0.0.1:20445.
    #[arg(
        long = "smb-bind",
        value_name = "ADDR:PORT",
        default_value = "127.0.0.1:20445",
        num_args = 1
    )]
    smb_bind: String,

    /// SMB TREE_CONNECT share name. Default `ratarmount`.
    #[arg(long = "smb-share", value_name = "NAME", default_value = "ratarmount")]
    smb_share: String,

    /// Export the archive as 9P2000.L over TCP. Default bind `--ninep-bind`
    /// (`127.0.0.1:20493`). Canonical flag is `--ninep` (not `--9p`).
    #[arg(long = "ninep", action = ArgAction::SetTrue)]
    ninep: bool,

    /// 9P listen address (`[host:]port`, IPv4 only). Default 127.0.0.1:20493.
    #[arg(
        long = "ninep-bind",
        value_name = "ADDR:PORT",
        default_value = "127.0.0.1:20493",
        num_args = 1
    )]
    ninep_bind: String,

    /// Export the archive as SFTP over TCP. Default bind `--sftp-bind`
    /// (`127.0.0.1:20222`). Needs `--features sftp-russh` (exit 2 otherwise).
    #[arg(long = "sftp", action = ArgAction::SetTrue)]
    sftp: bool,

    /// SFTP listen address (`[host:]port`, IPv4 only). Default 127.0.0.1:20222.
    #[arg(
        long = "sftp-bind",
        value_name = "ADDR:PORT",
        default_value = "127.0.0.1:20222",
        num_args = 1
    )]
    sftp_bind: String,

    /// Authorized-keys file for `--sftp`. Required when the bind is not loopback.
    #[arg(long = "sftp-authorized-keys", value_name = "PATH")]
    sftp_authorized_keys: Option<PathBuf>,

    /// Export SFTP v3 on stdin/stdout (OpenSSH `Subsystem sftp`). No listen.
    /// Exclusive with `--sftp`. Ignores `--sftp-bind` and `--sftp-authorized-keys`.
    /// Needs `--features sftp-russh` (exit 2 otherwise).
    #[arg(long = "sftp-subsystem", action = ArgAction::SetTrue)]
    sftp_subsystem: bool,

    /// Detect GNU incremental archives (heuristic)
    #[arg(long = "detect-gnu-incremental", action = ArgAction::SetTrue)]
    detect_gnu_incremental: bool,

    /// Force GNU incremental path stripping on/off (`true`/`false`)
    #[arg(long = "gnu-incremental", action = ArgAction::SetTrue)]
    gnu_incremental: bool,

    /// Ignore zero-filled TAR blocks (concatenated archives)
    #[arg(short = 'i', long = "ignore-zeros", action = ArgAction::SetTrue)]
    ignore_zeros: bool,

    /// Parallelization matrix for decompressors.
    /// Default: min(available cores, 4). Examples: `1`, `0` (all cores), `4`, `bzip2:4,gzip:2`, `:2,bzip2:4`
    #[arg(
        short = 'P',
        long = "parallelization",
        default_value_t = default_cli_parallelization(),
        value_name = "SPEC"
    )]
    parallelization: String,

    /// Do not keep an on-disk index when the archive has fewer than N indexed files
    /// (0 = always allow writing indexes; harness forces 0). Applies even with --index-file.
    #[arg(long = "index-minimum-file-count", default_value_t = 0)]
    index_minimum_file_count: u64,

    /// Explicit index file path, or `:memory:` for an in-memory index
    #[arg(long = "index-file")]
    index_file: Option<String>,

    /// Bind this mount to an immutable sidecar snapshot. HEX is the sha256 of
    /// the SQLite blob (64 hex). Looks up `{archive}.index.{HEX}.sqlite`, else
    /// the well-known sidecar if its sha256 matches. Unknown id or tarstats
    /// mismatch exits 2 (no silent well-known fallback).
    // Required value (`num_args = 1`); do not use `num_args = 0..=1` (steals ARCHIVE).
    // Resolved here to `opts.index_file_path` (not `OpenOptions::index_id`).
    #[arg(long = "index-id", value_name = "HEX", num_args = 1)]
    index_id: Option<String>,

    /// Comma-separated or JSON list of folders for `.index.sqlite` files.
    /// Empty entry = next to the archive. Default: ,$XDG_CACHE_HOME/ratarmount,~/.ratarmount
    #[arg(long = "index-folders")]
    index_folders: Option<String>,

    /// Publish the validated SQLite index next to the archive (local, hf, s3, gs, az).
    /// With no mountpoint, exit after publication.
    #[arg(long = "publish-index", action = ArgAction::SetTrue)]
    publish_index: bool,

    /// Copy the on-disk SQLite sidecar to PATH. Required value (`num_args = 1`);
    /// do not use `num_args = 0..=1` (that steals the archive). A remote URL names the archive.
    #[arg(long = "publish-index-to", value_name = "PATH_OR_URL", num_args = 1)]
    publish_index_to: Option<PathBuf>,

    /// Hub branch for index publication (archive branch, otherwise main).
    #[arg(long = "publish-revision", value_name = "BRANCH", num_args = 1)]
    publish_revision: Option<String>,

    /// Publish the Hub index or live overlay changes as a pull request.
    #[arg(long = "create-pr", action = ArgAction::SetTrue)]
    create_pr: bool,

    /// Also check archive mtime against the index (stricter reuse)
    #[arg(long = "verify-mtime", action = ArgAction::SetTrue)]
    verify_mtime: bool,

    /// Gzip seek point spacing in MiB (Python `-gs`; converted to bytes internally)
    #[arg(
        short = 'g',
        long = "gzip-seek-point-spacing",
        default_value_t = 16.0,
        visible_alias = "gs"
    )]
    gzip_seek_point_spacing_mib: f64,

    /// Per open-file sequential read window for archive members (`0` = off,
    /// default). On a miss, fill at least BYTES from the request offset so later
    /// sequential FUSE reads hit the window (stop-and-go scanners / compressed
    /// remote images; upstream #180). Accepts `K`/`M`/`G` (1024-based), e.g.
    /// `1M`, `256K`. Capped at 64 MiB per handle.
    ///
    /// When this flag is omitted, the CLI auto-enables the recommended 1 MiB
    /// window if rapidgzip is preferred (`--use-backend rapidgzip` or
    /// `RATARMOUNT_GZIP_BACKEND=rapidgzip`) **or** any mount input looks like a
    /// gzip archive (`.gz` / `.tgz` / `.tar.gz` / `.gzip`). Pass `--readahead 0`
    /// to keep readahead off. Torrent mounts use BYTES for verified HTTP piece
    /// prefetch; the swarm library has a separate fixed 32 MiB lookahead.
    /// For local zstd this flag also bounds speculative decoded bytes; when
    /// omitted zstd uses a separate 16 MiB decode window.
    #[arg(long = "readahead", default_value = "0", value_name = "BYTES")]
    readahead: String,

    /// Process-wide optional buffer/cache budget (e.g. 512M); excludes kernel pages.
    #[arg(long, value_name = "SIZE", value_parser = parse_byte_size)]
    memory_budget: Option<u64>,

    /// Torrent peer discovery (default never: cache and web seeds only; auto falls back to public DHT/trackers; lan uses local peers only; always starts the swarm at mount).
    #[arg(long, default_value = "never", value_name = "never|auto|lan|always")]
    torrent_swarm: ratarmount_core::TorrentSwarmPolicy,

    /// Maximum swarm scratch disk usage per torrent session (web seed reads use the range cache).
    #[arg(long, default_value = "2GiB", value_name = "BYTES", value_parser = parse_byte_size)]
    torrent_scratch_limit: u64,

    /// Local multicast peer discovery; used only while the swarm is active.
    #[arg(long, action = ArgAction::Set, default_value = "on", value_name = "on|off", value_parser = parse_torrent_lsd)]
    torrent_lsd: bool,

    /// Upload verified torrent pieces until unmount (makes a swarm session active).
    #[arg(long)]
    seed: bool,

    /// Maximum torrent upload bytes per second (at least one 16 KiB protocol block).
    #[arg(long, default_value = "1048576", value_name = "BYTES/s", value_parser = clap::value_parser!(u32).range(16384..=1_000_000_000))]
    seed_upload_limit: u32,

    /// Incoming TCP port when --seed is enabled (0 chooses an available port).
    #[arg(long, default_value = "0", value_name = "PORT")]
    torrent_listen_port: u16,

    /// Bypass FUSE's page cache for source members; overlay files keep normal caching.
    /// Disables passthrough and advises eviction of consumed local zstd/TAR pages.
    #[arg(long)]
    direct_io: bool,

    /// Linux >= 6.9 FUSE passthrough: auto requires privileges and eligible sources; on probes support.
    #[arg(long, default_value = "auto", value_name = "auto|on|off")]
    passthrough: PassthroughMode,

    /// Allow copying stored TAR members when reflinking cannot prepare a backing file.
    #[arg(long)]
    passthrough_copy: bool,

    /// Maximum copied member size (bytes or K/M/G suffix); 0 disables copying.
    #[arg(long, default_value = "0", value_name = "BYTES", value_parser = parse_byte_size)]
    passthrough_copy_max: u64,

    /// Total copied bytes held by concurrent passthrough opens (including clone tails).
    #[arg(long, default_value = "1G", value_name = "BYTES", value_parser = parse_byte_size)]
    passthrough_copy_total_max: u64,

    /// Recursion depth for --recursive (0 = deep default when combined with -r)
    #[arg(long = "recursion-depth", default_value_t = 0)]
    recursion_depth: i32,

    /// Comma-separated recursive extension sets (e.g. `/archive,/compressed` or `/all`)
    #[arg(
        long = "recursive-extensions",
        default_value = "/archive,/compressed,/disk,/split"
    )]
    recursive_extensions: String,

    /// Transform all member paths: `--transform REGEX REPLACEMENT`
    #[arg(long = "transform", num_args = 2, value_names = ["REGEX", "REPLACEMENT"])]
    transform: Option<Vec<String>>,

    /// Mount each input under its basename instead of union-mounting
    #[arg(long = "disable-union-mount", action = ArgAction::SetTrue)]
    disable_union_mount: bool,

    /// Prefer a backend (repeatable; last wins). Names match `--print-features` formats.
    #[arg(long = "use-backend", action = ArgAction::Append)]
    use_backend: Vec<String>,

    /// Mount the committed Git tree, including for a normal working directory
    #[arg(long)]
    git: bool,
    /// Git revision to mount (implies --git; invalid revisions are errors)
    #[arg(long, value_name = "REV")]
    git_ref: Option<String>,
    /// Subdirectory of the selected Git tree to mount
    #[arg(long, value_name = "SUBDIR")]
    git_prefix: Option<String>,
    /// Expose a minimal .git with one parentless commit (requires exactly one Git source)
    #[arg(long)]
    git_synthetic_head: bool,

    /// Mount a source at an absolute path before unioning (repeatable; after positional inputs)
    #[arg(long = "bind", value_name = "/MOUNTPATH=SOURCE")]
    source_binds: Vec<ratarmount_compositing::SourceBind>,

    /// Maximum idle repositories retained by a corpus mount
    #[arg(long, default_value_t = 64, value_parser = clap::value_parser!(u32).range(1..))]
    corpus_cache_size: u32,

    #[arg(skip)]
    corpus_list: Option<PathBuf>,

    /// Newline-separated password file for encrypted archives
    #[arg(long = "password-file")]
    password_file: Option<PathBuf>,

    /// Enable file version virtual folders (default on; use `--no-file-versions` to disable)
    #[arg(long = "file-versions", action = ArgAction::SetTrue, overrides_with = "no_file_versions")]
    file_versions: bool,

    /// Force index usage for folders (accepted; folders still bind-mount live)
    #[arg(long = "force-folder-index", action = ArgAction::SetTrue)]
    force_folder_index: bool,

    /// Comma-separated content hashes to store as index xattrs (e.g. `crc32,sha256,sha1`).
    /// Stored under `user.hash.<algo>`. Supported: crc32, md5, sha1, sha256.
    #[arg(long = "hashes", value_name = "ALGO[,ALGO...]")]
    hashes: Option<String>,

    /// Max directory depth for union mount folder cache (Python default 1024)
    #[arg(long = "union-mount-cache-max-depth", default_value_t = 1024)]
    union_mount_cache_max_depth: usize,

    /// Max directory entries to cache for multi-source union (Python default 100000)
    #[arg(long = "union-mount-cache-max-entries", default_value_t = 100_000)]
    union_mount_cache_max_entries: usize,

    /// Seconds allowed to build the union mount folder cache (Python default 60)
    #[arg(long = "union-mount-cache-timeout", default_value_t = 60.0)]
    union_mount_cache_timeout: f64,

    /// Follow winning union symlinks within their source (FR-10 / upstream #160).
    /// Default off: preserve symlink FileInfo. Real directories still beat symlinks (B-4 / #164).
    #[arg(long = "union-resolve-symlinks", action = ArgAction::SetTrue)]
    union_resolve_symlinks: bool,

    /// Force colored log prefixes (overrides NO_COLOR / CLICOLOR)
    #[arg(long = "color", action = ArgAction::SetTrue, overrides_with = "no_color")]
    color: bool,

    /// Disable colored log prefixes (overrides auto / CLICOLOR)
    #[arg(long = "no-color", action = ArgAction::SetTrue)]
    no_color: bool,

    /// Print short OSS attribution list and exit
    #[arg(long = "oss-attributions-short", action = ArgAction::SetTrue)]
    oss_attributions_short: bool,

    /// Print OSS attribution summary and exit
    #[arg(long = "oss-attributions", action = ArgAction::SetTrue)]
    oss_attributions: bool,

    /// Write overlay folder (`:temp:` for a temporary directory). The mountpoint may not
    /// be, lie inside, or contain it (refused, exit 2).
    /// A missing uncompressed `.tar` or `.tar.zst` is created as an empty archive.
    #[arg(short = 'w', long = "write-overlay")]
    write_overlay: Option<PathBuf>,

    /// Read-only overlay layer (repeatable, bottom to top).
    #[arg(long, value_name = "DIR", action = ArgAction::Append)]
    lower: Vec<PathBuf>,

    /// Allow unsealed or legacy lower layers (read-only, without immutable SQLite).
    #[arg(long, requires = "lower")]
    allow_unsealed_lower: bool,

    /// Allow a different lower stack for an existing top and record the override.
    #[arg(long)]
    force_stack_mismatch: bool,

    /// Trust a known sha256:<hex> base digest, or skip hashing with none (warns).
    #[arg(
        long,
        value_name = "sha256:HEX|none",
        conflicts_with = "commit_overlay"
    )]
    base_digest: Option<ratarmount_compositing::BaseDigestRequest>,

    /// Allow a changed base on remount (or `--commit-overlay`) and record the override in overlay metadata.
    #[arg(long, requires = "overlay_target")]
    force_base_mismatch: bool,

    /// Container-friendly ownership, allow_other/noatime, and a throwaway RAM overlay.
    #[arg(long)]
    sandbox: bool,

    /// Private RAM write overlay; optional logical byte cap (use --overlay-tmpfs=2G).
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "", conflicts_with_all = ["write_overlay", "commit_overlay"])]
    overlay_tmpfs: Option<String>,

    /// Explicitly allow a temporary overlay to commit changes into the base archive.
    #[arg(long, requires = "overlay_tmpfs")]
    overlay_tmpfs_allow_commit: bool,

    /// Protect root-relative paths (repeatable, comma-separated; quote globs).
    #[arg(long, value_delimiter = ',', action = ArgAction::Append, requires = "overlay_target", conflicts_with = "commit_overlay")]
    overlay_readonly: Vec<String>,

    /// Writable exceptions to read-only rules; more literal components win (ties allow).
    #[arg(long, value_delimiter = ',', action = ArgAction::Append, requires_all = ["overlay_target", "overlay_readonly"], conflicts_with = "commit_overlay")]
    overlay_allow: Vec<String>,

    /// Maximum logical overlay bytes, including COW (bytes or binary K/M/G/T).
    #[arg(long, value_parser = ratarmount_compositing::parse_overlay_size, requires = "overlay_target", conflicts_with = "commit_overlay")]
    overlay_quota: Option<u64>,

    /// Maximum overlay regular files and symlinks, including COW copies.
    #[arg(long, requires = "overlay_target", conflicts_with = "commit_overlay")]
    overlay_quota_files: Option<u64>,

    #[arg(skip)]
    overlay_stats: Option<overlay_stats::StatsArgs>,

    /// Append filesystem operation records to a JSONL file outside the mount and overlay.
    #[arg(long, conflicts_with_all = ["no_mount", "commit_overlay"])]
    journal: Option<PathBuf>,

    /// Exclude root-relative paths using the overlay-readonly glob syntax (repeatable).
    #[arg(long, action = ArgAction::Append, requires = "journal")]
    journal_exclude: Vec<String>,

    /// Record all coalesced read ranges, or just the first range per handle.
    #[arg(long, value_parser = ["all", "first"], default_value = "all", requires = "journal")]
    journal_reads: String,

    /// Fsync the operation journal at unmount.
    #[arg(long, requires = "journal")]
    journal_sync: bool,

    #[arg(skip)]
    journal_command: Option<journal_cmd::JournalArgs>,

    #[arg(skip)]
    overlay: Option<overlay_cmd::OverlayArgs>,

    #[arg(skip)]
    diff: Option<diff::DiffArgs>,

    #[arg(skip)]
    sandbox_api: Option<sandbox::SandboxArgs>,

    #[arg(long, hide = true, requires_all = ["write_overlay", "foreground"])]
    sandbox_inspection_socket: Option<PathBuf>,

    /// Commit write-overlay changes into a TAR (uncompressed / gzip / bzip2 / xz via GNU tar,
    /// or `.tar.zst` via frame splice) or ZIP (full rebuild). Does not mount; requires
    /// `--write-overlay` and a single archive path.
    /// Create-if-missing for uncompressed `.tar` only; empty `.tar.zst` is live/write-mount only.
    #[arg(long = "commit-overlay", action = ArgAction::SetTrue)]
    commit_overlay: bool,

    /// Archive persistence: copy (default), append (adds-only, mutates the inode),
    /// or auto (append eligible plans only when the archive has one hard link).
    #[arg(long = "commit-overlay-mode", default_value = "copy", value_parser = ["copy", "append", "auto"])]
    commit_overlay_mode: String,

    /// Roll a numbered .tar/.tar.zst series before a commit reaches a new UTC
    /// time bucket or after its active archive reaches SIZE (1d, 6h, 20G, 1d,20G).
    /// Implies --commit-overlay-on-exit; use --commit-overlay-interval for live rolls.
    #[arg(long, value_name = "DURATION|SIZE", value_parser = clap::value_parser!(ratarmount_compositing::RollPolicy), requires = "write_overlay", conflicts_with_all = ["commit_overlay", "repack_seekable", "publish_index", "publish_index_to", "index_id", "disable_union_mount"])]
    roll_every: Option<ratarmount_compositing::RollPolicy>,

    /// Write an atomic <archive>.manifest.jsonl after a successful TAR commit.
    #[arg(long)]
    commit_manifest: bool,

    /// Manifest SHA-256 coverage: new/changed payloads (default), all, or none.
    #[arg(long, default_value = "new", value_parser = ["all", "new", "none"])]
    manifest_hashes: String,

    /// Find-only xattr predicates (repeatable): NAME, NAME=VALUE, NAME!=VALUE.
    #[arg(long = "xattr", action = ArgAction::Append)]
    find_xattrs: Vec<String>,

    /// Skip interactive confirmation for `--commit-overlay` (type "commit" otherwise).
    #[arg(long = "yes", action = ArgAction::SetTrue)]
    yes: bool,

    /// On SIGINT/SIGTERM or NFS/FUSE return, commit `-w` into an uncompressed TAR
    /// or `.tar.zst`. RAM overlays require --overlay-tmpfs-allow-commit.
    /// Rejects disk-backed `:temp:` and gzip/bzip2/xz TAR / ZIP (no silent full rewrite).
    #[arg(long = "commit-overlay-on-exit", action = ArgAction::SetTrue)]
    commit_overlay_on_exit: bool,

    /// Commit `-w` files that have not been modified for DURATION into an
    /// uncompressed TAR or `.tar.zst` while serving (`2s`/`15m`/`1h`).
    /// `0` (default) is off. Recently written files stay in the overlay until
    /// they settle; on-exit still flushes everything. In-process; promptless.
    /// Requires durable `-w` or --overlay-tmpfs-allow-commit for a RAM overlay.
    #[arg(
        long = "commit-overlay-interval",
        value_name = "DURATION",
        default_value = "0"
    )]
    commit_overlay_interval: String,

    /// Producer: rewrite INPUT into a seekable OUTPUT and exit. Does not mount.
    /// Boolean (`SetTrue`). INPUT and OUTPUT are the two positionals.
    /// Do not use `num_args = 0..=1` — that steals the archive path.
    #[arg(long = "repack-seekable", action = ArgAction::SetTrue)]
    repack_seekable: bool,

    /// Uncompressed frame size for a zstd recompress. `num_args = 1` so the next
    /// positional is not stolen. No `default_value`: absence means 8 MiB.
    /// `Option<String>` because clap will not parse `1M` into `u64`.
    /// `1M` = `1024 * 1024`, same as `--readahead`. Only affects recompress.
    #[arg(long = "repack-frame-size", value_name = "BYTES", num_args = 1)]
    repack_frame_size: Option<String>,

    /// Gzip sidecar when OUTPUT is gzip: `rgzi` (default), `gzidx`, or `both`.
    /// `num_args = 1` so the next positional is not stolen.
    #[arg(
        long = "repack-gzip-index",
        value_name = "KIND",
        num_args = 1,
        default_value = "rgzi"
    )]
    repack_gzip_index: String,

    /// Password for encrypted archives (repeatable)
    #[arg(long = "password", action = ArgAction::Append)]
    passwords: Vec<String>,

    /// Input encoding for TAR member names among others (`latin1`, `utf-8`, …)
    #[arg(short = 'e', long = "encoding", default_value = "utf-8")]
    encoding: String,

    /// Debug level: 0=error, 1=warn (default), 2=info, 3=debug
    #[arg(short = 'd', long = "debug", default_value_t = 1)]
    debug: u8,

    /// Redirect log output to this file (after mount setup; useful without -f)
    #[arg(long = "log-file")]
    log_file: Option<PathBuf>,

    /// Comma-separated FUSE options (see `man mount.fuse`)
    #[arg(short = 'o', long = "fuse", default_value = "")]
    fuse: String,

    /// Print version and build feature summary
    #[arg(long = "print-features", action = ArgAction::SetTrue)]
    print_features: bool,

    /// Input archives/folders/URLs and optional mountpoint. A mountpoint may not be, lie
    /// inside, or contain a folder being mounted (refused, exit 2); a folder defaults to
    /// `<folder>.mounted`.
    #[arg(required = false)]
    paths: Vec<PathBuf>,

    /// Set when argv[1] is the `serve` sugar (G-1). Not a clap flag — a
    /// clap `Subcommand` would require `global = true` on every option.
    #[arg(skip)]
    serve: bool,

    /// Set when argv[1] is the `find` sugar (F-3). Same clap trap as `serve`.
    #[arg(skip)]
    find: bool,

    #[arg(skip)]
    shard: Option<shard::ShardArgs>,

    #[arg(skip)]
    snapshot: Option<snapshot::SnapshotArgs>,

    #[arg(skip)]
    export_index: Option<export_index::ExportArgs>,

    /// Find-argv `--fts` (FTS5 MATCH). Not a global mount flag.
    #[arg(skip)]
    find_fts: bool,

    /// Find-argv boolean `--hashes` (include cheap `user.hash.*` TSV columns).
    #[arg(skip)]
    find_hashes: bool,

    /// Find-argv `--offset-order` (re-sort locate hits by `offsetheader`).
    #[arg(skip)]
    find_offset_order: bool,
}

/// `--base-digest` and `--force-stack-mismatch` apply to a write overlay or to a
/// read-only `--lower` stack; clap's `requires` cannot express that OR.
fn base_flag_needs_target_or_lower(args: &Args) -> Result<(), clap::Error> {
    let target = args.write_overlay.is_some() || args.overlay_tmpfs.is_some() || args.sandbox;
    for (given, flag) in [
        (args.base_digest.is_some(), "--base-digest"),
        (args.force_stack_mismatch, "--force-stack-mismatch"),
    ] {
        if given && !target && args.lower.is_empty() {
            return Err(clap::Error::raw(
                clap::error::ErrorKind::MissingRequiredArgument,
                format!("{flag} requires -w/--overlay-tmpfs/--sandbox or --lower"),
            ));
        }
    }
    Ok(())
}

/// Parse `--parallel-nested`: non-negative integer or `auto` (→ 0).
fn parse_parallel_nested(s: &str) -> Result<u32, String> {
    let t = s.trim();
    if t.eq_ignore_ascii_case("auto") {
        return Ok(0);
    }
    t.parse::<u32>()
        .map_err(|_| format!("expected non-negative integer or 'auto', got {s:?}"))
}

fn parse_torrent_lsd(value: &str) -> Result<bool, String> {
    match value {
        "on" => Ok(true),
        "off" => Ok(false),
        _ => Err("expected on or off".into()),
    }
}

/// G-1 `serve` / F-3 `find` sugar: strip argv[1] when it is exactly `serve` or
/// `find`, then parse the existing CLI. A clap `Subcommand` is hostile here:
/// flags after the verb are unknown unless every `Args` field is `global = true`,
/// which would also treat a later positional `serve`/`find` as the subcommand.
fn parse_args_from<I, T>(iter: I) -> Result<Args, clap::Error>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let raw: Vec<OsString> = iter.into_iter().map(Into::into).collect();
    if raw.get(1).is_some_and(|s| s == "sandbox") {
        let command = sandbox::SandboxArgs::try_parse_from(
            std::iter::once(OsString::from("ratarmount sandbox"))
                .chain(raw.iter().skip(2).cloned()),
        )?;
        let mut args = Args::try_parse_from(&raw[..1])?;
        args.sandbox_api = Some(command);
        return Ok(args);
    }
    if raw.get(1).is_some_and(|s| s == "snapshot") {
        let snapshot = snapshot::SnapshotArgs::try_parse_from(
            std::iter::once(OsString::from("ratarmount snapshot"))
                .chain(raw.iter().skip(2).cloned()),
        )?;
        let mut args = Args::try_parse_from(&raw[..1])?;
        args.snapshot = Some(snapshot);
        return Ok(args);
    }
    if raw.get(1).is_some_and(|s| s == "diff") {
        let diff = diff::DiffArgs::try_parse_from(
            std::iter::once(OsString::from("ratarmount diff")).chain(raw.iter().skip(2).cloned()),
        )?;
        let mut args = Args::try_parse_from(&raw[..1])?;
        args.diff = Some(diff);
        return Ok(args);
    }
    if raw
        .get(1)
        .is_some_and(|s| s == "shard" || s == "export-index")
    {
        let mut args = Args::try_parse_from(&raw[..1])?;
        let verb = raw[1].to_string_lossy();
        let argv = std::iter::once(OsString::from(format!("ratarmount {verb}")))
            .chain(raw.iter().skip(2).cloned());
        if verb == "shard" {
            args.shard = Some(shard::ShardArgs::try_parse_from(argv)?);
        } else {
            args.export_index = Some(export_index::ExportArgs::try_parse_from(argv)?);
        }
        return Ok(args);
    }
    if raw.get(1).is_some_and(|s| s == "journal") {
        let journal = journal_cmd::JournalArgs::try_parse_from(
            std::iter::once(OsString::from("ratarmount journal"))
                .chain(raw.iter().skip(2).cloned()),
        )?;
        let mut args = Args::try_parse_from(&raw[..1])?;
        args.journal_command = Some(journal);
        return Ok(args);
    }
    if raw.get(1).is_some_and(|s| s == "overlay") {
        let overlay = overlay_cmd::OverlayArgs::try_parse_from(
            std::iter::once(OsString::from("ratarmount overlay"))
                .chain(raw.iter().skip(2).cloned()),
        )?;
        let mut args = Args::try_parse_from(&raw[..1])?;
        args.overlay = Some(overlay);
        return Ok(args);
    }
    if raw.get(1).is_some_and(|s| s == "overlay-stats") {
        let stats = overlay_stats::StatsArgs::try_parse_from(
            std::iter::once(OsString::from("ratarmount overlay-stats"))
                .chain(raw.iter().skip(2).cloned()),
        )?;
        let mut args = Args::try_parse_from(&raw[..1])?;
        args.overlay_stats = Some(stats);
        return Ok(args);
    }
    if raw.get(1).is_some_and(|s| s == "corpus") {
        let argv = std::iter::once(raw[0].clone()).chain(raw.iter().skip(2).cloned());
        let mut args = Args::try_parse_from(argv)?;
        if args.paths.len() != 2
            || args.no_mount
            || args.write_overlay.is_some()
            || !args.source_binds.is_empty()
            || args.git
            || args.git_ref.is_some()
            || args.git_prefix.is_some()
            || args.git_synthetic_head
            || args.unmount
            || args.commit_overlay
            || args.repack_seekable
            || args.publish_index
            || args.publish_index_to.is_some()
        {
            return Err(clap::Error::raw(clap::error::ErrorKind::ArgumentConflict,
                "corpus requires LIST-FILE MOUNTPOINT; it is read-only and cannot combine with --no-mount, --bind or Git selectors"));
        }
        args.corpus_list = Some(args.paths[0].clone());
        args.lazy = true;
        return Ok(args);
    }
    let find = raw.get(1).is_some_and(|s| s == "find");
    let serve = raw.get(1).is_some_and(|s| s == "serve");
    let stripped: Vec<OsString> = if find || serve {
        raw.into_iter()
            .enumerate()
            .filter_map(|(i, t)| (i != 1).then_some(t))
            .collect()
    } else {
        raw
    };
    let (stripped, find_fts, find_hashes, find_offset_order) = if find {
        strip_find_only_flags(stripped)
    } else {
        (stripped, false, false, false)
    };
    let mut args = Args::try_parse_from(stripped)?;
    if args.seed && args.torrent_swarm == ratarmount_core::TorrentSwarmPolicy::Never {
        return Err(clap::Error::raw(
            clap::error::ErrorKind::ArgumentConflict,
            "--seed conflicts with --torrent-swarm never (the default); pass --torrent-swarm lan, auto or always",
        ));
    }
    if args.seed && !cfg!(feature = "bittorrent") {
        return Err(clap::Error::raw(
            clap::error::ErrorKind::ArgumentConflict,
            "--seed requires a build with --features bittorrent",
        ));
    }
    if args.roll_every.is_some() {
        if find
            || !args.source_binds.is_empty()
            || args.recursive
            || args.recursion_depth != 0
            || !args.prefix.is_empty()
            || args.transform.is_some()
        {
            return Err(clap::Error::raw(clap::error::ErrorKind::ArgumentConflict,
                "--roll-every requires an untransformed archive series without find, --bind, --prefix or recursion"));
        }
        args.commit_overlay_on_exit = true;
    }
    if !args.lower.is_empty()
        && (args.commit_overlay
            || args.commit_overlay_on_exit
            || args.commit_overlay_interval != "0")
    {
        return Err(clap::Error::raw(
            clap::error::ErrorKind::ArgumentConflict,
            "commit of a layered stack is not supported; flatten first",
        ));
    }
    base_flag_needs_target_or_lower(&args)?;
    expand_sandbox(&mut args, caller_ids())
        .map_err(|message| clap::Error::raw(clap::error::ErrorKind::ValueValidation, message))?;
    ratarmount_compositing::ReadOnlyGlobs::new(&args.journal_exclude)
        .map_err(|e| clap::Error::raw(clap::error::ErrorKind::ValueValidation, e.to_string()))?;
    if !args.overlay_readonly.is_empty() {
        ratarmount_compositing::ReadOnlyGlobs::with_allow(
            &args.overlay_readonly,
            &args.overlay_allow,
        )
        .map_err(|e| clap::Error::raw(clap::error::ErrorKind::ValueValidation, e.to_string()))?;
    }
    if !find && !args.find_xattrs.is_empty() {
        return Err(clap::Error::raw(
            clap::error::ErrorKind::ArgumentConflict,
            "--xattr requires find",
        ));
    }
    if find && !args.find_xattrs.is_empty() && args.paths.len() == 1 {
        args.paths.insert(0, PathBuf::from("*"));
    }
    args.serve = serve;
    args.find = find;
    args.find_fts = find_fts;
    args.find_hashes = find_hashes;
    args.find_offset_order = find_offset_order;
    if find {
        args.no_mount = true;
    }
    Ok(args)
}

fn caller_ids() -> (u32, u32) {
    let uid = std::env::var("SUDO_UID")
        .ok()
        .and_then(|id| id.parse().ok())
        .unwrap_or_else(|| unsafe { libc::getuid() });
    let gid = std::env::var("SUDO_GID")
        .ok()
        .and_then(|id| id.parse().ok())
        .unwrap_or_else(|| unsafe { libc::getgid() });
    (uid, gid)
}

fn expand_sandbox(args: &mut Args, (uid, gid): (u32, u32)) -> Result<(), String> {
    let mapping = ratarmount_core::AttributeMapping::parse(&args.fuse)?;
    if args.sandbox {
        let mut defaults = vec!["allow_other".to_owned(), "noatime".to_owned()];
        if mapping.uid.is_none() {
            defaults.push(format!("uid={uid}"));
        }
        if mapping.gid.is_none() {
            defaults.push(format!("gid={gid}"));
        }
        defaults.push(args.fuse.clone());
        args.fuse = defaults.join(",");
        if args.write_overlay.is_none() && args.overlay_tmpfs.is_none() {
            args.overlay_tmpfs = Some(String::new());
        }
    }
    if let Some(size) = &args.overlay_tmpfs {
        if !size.is_empty() {
            let cap = ratarmount_compositing::parse_overlay_size(size)?;
            args.overlay_quota = Some(args.overlay_quota.map_or(cap, |quota| quota.min(cap)));
        }
        if (args.commit_overlay_on_exit
            || overlay_commit::parse_interval(&args.commit_overlay_interval)?.is_some())
            && !args.overlay_tmpfs_allow_commit
        {
            return Err("--overlay-tmpfs is throwaway: committing requires --overlay-tmpfs-allow-commit explicitly".into());
        }
        args.write_overlay = Some(PathBuf::from(":temp:"));
    }
    Ok(())
}

// process::exit skips local destructors. Register cleanup once, and relinquish
// the parent's inherited directory after fork; only the serving child removes it.
static TEMP_OVERLAY: std::sync::Mutex<Option<tempfile::TempDir>> = std::sync::Mutex::new(None);

extern "C" fn cleanup_temp_overlay() {
    if let Ok(mut overlay) = TEMP_OVERLAY.lock() {
        overlay.take();
    }
}

fn relinquish_temp_overlay() {
    if let Some(overlay) = TEMP_OVERLAY.lock().unwrap().take() {
        let _ = overlay.keep();
    }
}

fn has_temp_overlay() -> bool {
    TEMP_OVERLAY.lock().unwrap().is_some()
}

fn register_temp_overlay(overlay: tempfile::TempDir) {
    static REGISTER: std::sync::Once = std::sync::Once::new();
    REGISTER.call_once(|| unsafe {
        libc::atexit(cleanup_temp_overlay);
    });
    *TEMP_OVERLAY.lock().unwrap() = Some(overlay);
}

fn create_tmpfs_overlay() -> std::io::Result<tempfile::TempDir> {
    #[cfg(not(target_os = "linux"))]
    {
        Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "--overlay-tmpfs is supported only on Linux; use -w :temp: for a disk-backed temporary overlay"))
    }
    #[cfg(target_os = "linux")]
    {
        let runtime = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
        create_tmpfs_overlay_in(Path::new("/dev/shm"), runtime.as_deref())
    }
}

#[cfg(target_os = "linux")]
fn create_tmpfs_overlay_in(
    shm: &Path,
    runtime: Option<&Path>,
) -> std::io::Result<tempfile::TempDir> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    let mut last_error = None;
    for parent in std::iter::once(shm).chain(runtime) {
        // XDG_RUNTIME_DIR is normally tmpfs, but refuse a disk-backed override.
        let path = std::ffi::CString::new(parent.as_os_str().as_bytes())?;
        let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statfs(path.as_ptr(), &mut stat) } != 0 {
            last_error = Some(std::io::Error::last_os_error());
            continue;
        }
        if stat.f_type != libc::TMPFS_MAGIC {
            last_error = Some(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!("{} is not tmpfs", parent.display()),
            ));
            continue;
        }
        {
            let __inventory_condition_44740 = {
                #[expect(
                    clippy::disallowed_methods,
                    reason = r###"internal-read:v1 {"id":"IR-B0021-M01","item":"ratarmount::create_tmpfs_overlay_in","disposition":"output-owner","mode_policy":"unchanged-from-e6ca64e","category":"output-owner","reason":"Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"unchanged-from-e6ca64e","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###
                )]
                let __inventory_value_0 = tempfile::Builder::new()
                    .prefix("ratarmount-write-overlay.")
                    .permissions(std::fs::Permissions::from_mode(0o700))
                    .tempdir_in(parent);
                __inventory_value_0
            };
            match __inventory_condition_44740 {
                Ok(directory) => return Ok(directory),
                Err(error) => last_error = Some(error),
            }
        }
    }
    Err(std::io::Error::other(format!(
        "cannot create RAM overlay on /dev/shm or $XDG_RUNTIME_DIR: {}",
        last_error.unwrap()
    )))
}

/// `--fts`, boolean `--hashes`, and `--offset-order` are find-argv only
/// (not global mount flags). `--hashes ALGO[,ALGO...]` is left for the
/// existing clap field (fill then search). `--offset-order` is boolean
/// (copy `--fts`, not value-taking `--hashes`).
fn strip_find_only_flags(raw: Vec<OsString>) -> (Vec<OsString>, bool, bool, bool) {
    let mut out = Vec::with_capacity(raw.len());
    let mut fts = false;
    let mut hashes = false;
    let mut offset_order = false;
    let mut iter = raw.into_iter();
    if let Some(prog) = iter.next() {
        out.push(prog);
    }
    while let Some(tok) = iter.next() {
        if tok == "--fts" {
            fts = true;
            continue;
        }
        if tok == "--offset-order" {
            offset_order = true;
            continue;
        }
        if tok == "--hashes" {
            match iter.next() {
                Some(next) if looks_like_hash_algos(&next) => {
                    out.push(tok);
                    out.push(next);
                }
                Some(next) => {
                    hashes = true;
                    out.push(next);
                }
                None => {
                    hashes = true;
                }
            }
            continue;
        }
        out.push(tok);
    }
    (out, fts, hashes, offset_order)
}

fn looks_like_hash_algos(s: &OsString) -> bool {
    let Some(text) = s.to_str() else {
        return false;
    };
    if text.starts_with('-') {
        return false;
    }
    let mut any = false;
    for p in text.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        any = true;
        if ratarmount_index::normalize_algorithm(p).is_none() {
            return false;
        }
    }
    any
}

fn serve_cli_error(args: &Args) -> Option<&'static str> {
    if !args.serve {
        return None;
    }
    if args.no_mount {
        return Some("serve cannot be combined with --no-mount");
    }
    if !any_export(args) {
        return Some(
            "serve requires at least one export (--nfs, --http, --webdav, --smb, --ninep, --sftp, --sftp-subsystem)",
        );
    }
    None
}

fn find_cli_error(args: &Args) -> Option<&'static str> {
    if !args.find {
        return None;
    }
    if args.paths.len() != 2 {
        return Some("find requires PATTERN ARCHIVE (ratarmount find '*.fits' archive.tar)");
    }
    if args.write_overlay.is_some() {
        return Some("find cannot be combined with -w / --write-overlay");
    }
    if any_export(args) {
        return Some(
            "find cannot be combined with --nfs/--http/--webdav/--smb/--ninep/--sftp/--sftp-subsystem",
        );
    }
    None
}

/// Exit 2 before mount. Interval exclusion uses [`overlay_commit::parse_interval`],
/// not the raw presence of the flag (`"0"` is off).
fn repack_seekable_cli_error(args: &Args) -> Option<String> {
    if !args.repack_seekable {
        return None;
    }
    if args.serve {
        return Some("--repack-seekable cannot be combined with serve".into());
    }
    if args.find {
        return Some("--repack-seekable cannot be combined with find".into());
    }
    if args.commit_overlay {
        return Some("--repack-seekable cannot be combined with --commit-overlay".into());
    }
    if args.commit_overlay_on_exit {
        return Some("--repack-seekable cannot be combined with --commit-overlay-on-exit".into());
    }
    match overlay_commit::parse_interval(&args.commit_overlay_interval) {
        Ok(Some(_)) => {
            return Some(
                "--repack-seekable cannot be combined with --commit-overlay-interval".into(),
            );
        }
        Ok(None) => {}
        Err(e) => return Some(e),
    }
    if any_export(args) {
        return Some(
            "--repack-seekable cannot be combined with --nfs/--http/--webdav/--smb/--ninep/--sftp/--sftp-subsystem"
                .into(),
        );
    }
    if args.write_overlay.is_some() {
        return Some("--repack-seekable cannot be combined with -w / --write-overlay".into());
    }
    match args.paths.len() {
        2 => None,
        n if n > 2 => Some("--repack-seekable does not mount".into()),
        _ => Some("--repack-seekable requires INPUT OUTPUT".into()),
    }
}

fn parse_repack_gzip_index(s: &str) -> Result<GzipSidecar, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "rgzi" => Ok(GzipSidecar::Rgzi),
        "gzidx" => Ok(GzipSidecar::Gzidx),
        "both" => Ok(GzipSidecar::Both),
        _ => Err(format!(
            "--repack-gzip-index must be rgzi, gzidx, or both (got {s:?})"
        )),
    }
}

fn repack_stdout_line(output: &Path, report: &RepackReport) -> String {
    let detail = match report.action {
        RepackAction::Copied => "copied".to_string(),
        RepackAction::SeekTableAppended => "seek table appended".to_string(),
        RepackAction::CopiedWithoutFooter => "copied without footer".to_string(),
        RepackAction::Recompressed { frames } => format!("recompressed, {frames} frames"),
        RepackAction::CopiedWithGzipIndex { format } => {
            let kind = match format {
                GzipSidecar::Rgzi => "rgzi",
                GzipSidecar::Gzidx => "gzidx",
                GzipSidecar::Both => "rgzi+gzidx",
            };
            format!("copied with {kind}")
        }
    };
    format!(
        "Repacked {} ({detail}, {} bytes).",
        output.display(),
        report.output_len
    )
}

fn run_repack_seekable_cli(args: &Args) -> Result<(), (i32, String)> {
    if let Some(msg) = repack_seekable_cli_error(args) {
        return Err((2, msg));
    }
    let frame_size = match args.repack_frame_size.as_deref() {
        Some(s) => {
            parse_byte_size(s).map_err(|e| (2, format!("invalid --repack-frame-size: {e}")))?
        }
        None => DEFAULT_REPACK_FRAME_SIZE,
    };
    let gzip_sidecar = parse_repack_gzip_index(&args.repack_gzip_index).map_err(|e| (2, e))?;
    let output = &args.paths[1];
    let opts = RepackOptions {
        frame_size,
        gzip_sidecar,
        overwrite: args.yes,
        ..RepackOptions::default()
    };
    match repack_seekable(&args.paths[0], output, &opts) {
        Ok(report) => {
            println!("{}", repack_stdout_line(output, &report));
            Ok(())
        }
        Err(e) => {
            let msg = e.to_string();
            let code = if msg.contains("v1 writes") { 2 } else { 1 };
            Err((code, msg))
        }
    }
}

fn prepared_index_cli_error(args: &Args) -> Option<String> {
    if !args.no_recreate_index {
        return None;
    }
    let incompatible = if args.recreate_index {
        Some("-c / --recreate-index")
    } else if args.hashes.is_some() {
        Some("--hashes")
    } else if args.commit_overlay {
        Some("--commit-overlay")
    } else if args.roll_every.is_some() {
        Some("--roll-every")
    } else if args.commit_overlay_on_exit {
        Some("--commit-overlay-on-exit")
    } else if overlay_commit::parse_interval(&args.commit_overlay_interval)
        .map_or(true, |interval| interval.is_some())
    {
        Some("--commit-overlay-interval")
    } else if args.publish_index {
        Some("--publish-index")
    } else if args.publish_index_to.is_some() {
        Some("--publish-index-to")
    } else if args.repack_seekable {
        Some("--repack-seekable")
    } else if args
        .index_file
        .as_deref()
        .is_some_and(|s| s.trim() == MEMORY_INDEX)
    {
        Some("--index-file :memory:")
    } else {
        None
    };
    incompatible.map(|flag| format!("--no-recreate-index cannot be combined with {flag}; stop workers and prepare the base/index separately"))
}

fn index_id_cli_error(args: &Args) -> Option<&'static str> {
    args.index_id.as_ref()?;
    if args.recreate_index {
        return Some("--index-id cannot be combined with -c / --recreate-index");
    }
    if args.hashes.is_some() {
        return Some("--index-id cannot be combined with --hashes");
    }
    None
}

/// Strong identity of the mounted base that may key trusted bundle
/// verifications, obtained without hashing any content: the digest of a single
/// archive base that is already in its index's digest cache. Everything else
/// returns `None` (no markers, every use re-verifies): a directory has no
/// computed strong digest, a union (several inputs) would need every input's
/// identity and its index only covers the first, and a supplied
/// `--base-digest` is just the caller's unchecked claim, so it never keys a
/// marker. Any option that reshapes the mounted view (see
/// [`mounted_view_is_default`]) disables markers (the caller never asks), and
/// the listing options of [`mounted_view_key`] are appended to the digest so a
/// check made under one listing never serves another.
/// Computed only when a `--lower` bundle needs it.
#[cfg(test)]
fn lower_base_key(
    bases: &[PathBuf],
    index: Option<&Path>,
    lowers: &[PathBuf],
    view_key: &str,
) -> Option<String> {
    lower_base_key_for_open(bases, index, lowers, view_key, false)
        .ok()
        .flatten()
}

fn lower_base_key_for_open(
    bases: &[PathBuf],
    index: Option<&Path>,
    lowers: &[PathBuf],
    view_key: &str,
    read_only_index: bool,
) -> Result<Option<String>, String> {
    let [base] = bases else { return Ok(None) };
    if !lowers.iter().any(|p| p.is_file())
        || !base.is_file()
        || (read_only_index && index.is_none())
    {
        return Ok(None);
    }
    let peek = ratarmount_index::peek_archive_digest_for_open(base, index, read_only_index);
    let digest = if read_only_index {
        peek.map_err(|e| e.to_string())?
    } else {
        peek.ok().flatten()
    };
    Ok(digest.map(|digest| format!("{digest}.{view_key}")))
}

/// The verification marker key for this invocation: `None` unless the mount
/// serves the base unchanged (see [`mounted_view_is_default`]) and the base has
/// a computed identity; otherwise the base digest plus [`mounted_view_key`].
fn lower_key_for(
    args: &Args,
    rolling: bool,
    inputs: &[PathBuf],
    index: Option<&Path>,
    read_only_index: bool,
) -> Result<Option<String>, String> {
    if !mounted_view_is_default(args, rolling) {
        return Ok(None);
    }
    lower_base_key_for_open(
        inputs,
        index,
        &args.lower,
        &mounted_view_key(args),
        read_only_index,
    )
}

/// The options that change which members an archive lists or how their paths
/// are synthesized (file-version folders, zero-block handling, GNU incremental
/// stripping, name encoding). They are part of the marker key itself, so a
/// verification made under one listing is never reused under another. A new
/// listing option must be added here.
fn mounted_view_key(args: &Args) -> String {
    format!(
        "fv{}.iz{}.gi{}.dgi{}.enc-{}",
        u8::from(!args.no_file_versions),
        u8::from(args.ignore_zeros),
        u8::from(args.gnu_incremental),
        u8::from(args.detect_gnu_incremental),
        args.encoding
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect::<String>()
    )
}

/// Whether the mount serves the base's paths unchanged, so a bundle verified
/// against the archive's content stays verified. Any option that shapes the
/// mounted tree (prefix, transforms, recursion, binds, corpus, git prefix,
/// rolling series, union disabling) makes this false; a new view option must
/// be added here.
fn mounted_view_is_default(args: &Args, rolling: bool) -> bool {
    !rolling
        && args.prefix.is_empty()
        && args.transform.is_none()
        && args.transform_recursive_mount_point.is_none()
        && !args.recursive
        && args.recursion_depth == 0
        && !args.lazy
        && !args.strip_recursive_tar_extension
        && !args.disable_union_mount
        && args.source_binds.is_empty()
        && args.corpus_list.is_none()
        && args.git_prefix.is_none()
        && args.roll_every.is_none()
}

/// The base a mount actually serves, as far as it can be identified without
/// reading content: what the factory reported (the token) plus what the
/// invocation knows around it.
#[derive(Default)]
struct MountedBase {
    /// What the opener served. `None` only when nothing was classified (no
    /// `--lower` and no `-w`), in which case no lower is compared either.
    classified: Option<ratarmount_compositing::ClassifiedBase>,
    /// A supplied `--base-digest`, reported as the base's identity.
    supplied: Option<String>,
    /// Base-relative paths of this invocation's own overlay, journal and mount
    /// point (and the existing top's recorded set), left out of the walk in
    /// addition to the bottom lower's recorded set so a top or mount point
    /// inside the base does not make the base differ.
    extra_excludes: Vec<PathBuf>,
    /// `--journal` files that already exist inside a directory base. They count
    /// as base content (a read-only mount records no exclusions), so a changed
    /// base is refused naming them.
    existing_journals: Vec<PathBuf>,
}

/// Mount-path policy for comparing the mounted base with the bottom lower's
/// recorded identity. Offline commands use [`MountLowerStack::open`] /
/// [`MountLowerStack::open_in`], which read the recorded digest and do not
/// take this policy.
enum BaseIdentity {
    Enforce { base: MountedBase, force: bool },
}

/// Compare the mounted base with what the bottom lower recorded, using
/// metadata only (a weak directory walk with the lower's own recorded
/// exclusions, an archive's size and mtime, a Git tree id). Returns the
/// mounted base's own identity ("" when it cannot be known without hashing).
fn mounted_base_identity(
    lower: &Path,
    meta: Option<&ratarmount_compositing::OverlayMeta>,
    base: &MountedBase,
    force: bool,
) -> Result<String, String> {
    let Some(classified) = base.classified.as_ref() else {
        return Err("internal error: the mounted base was not classified".into());
    };
    let probe = ratarmount_compositing::overlay_gate::BaseProbe {
        supplied: base.supplied.as_deref(),
        extra_excludes: &base.extra_excludes,
    };
    let comparison =
        ratarmount_compositing::overlay_gate::compare_base_identity(meta, classified, &probe)?;
    let git_tree = classified.actual().git_tree();
    let local_path = matches!(
        classified.actual().location(),
        Some(ratarmount_compositing::overlay_identity::BaseLocation::Local(_))
    );
    let get = |key: &str| meta.and_then(|m| m.get(key));
    let mismatch = comparison.mismatch;
    let identity = comparison.identity;
    if let Some(current) = mismatch {
        if !force {
            let recorded = get("base_digest").unwrap_or("unknown");
            let strong = meta.is_some_and(|m| m.base_digest_kind() == Some("strong"));
            return Err(if strong && git_tree.is_none() && local_path {
                format!(
                    "lower {} was sealed against a strong base digest ({recorded}) and the mounted base's identity could not be confirmed cheaply (size/mtime or the directory manifest differ, and neither a matching --base-digest nor a matching cached SHA-256 in the base's index was found; the mount never hashes the base). Pass --base-digest {recorded} (from `overlay digest-base` on the source) if the mounted base is a copy of it, run `overlay verify {} BASE`, or pass --force-stack-mismatch as a last resort",
                    lower.display(),
                    lower.display()
                )
            } else if git_tree.is_some() || !local_path {
                format!(
                    "lower {} was sealed against base {recorded} but the mounted base is {current}; pass --force-stack-mismatch to override",
                    lower.display()
                )
            } else {
                let journals: String = base
                    .existing_journals
                    .iter()
                    .map(|p| {
                        format!(
                            "; the existing --journal file {} lies inside the base and counts as base content (move it outside the base, or pass --force-stack-mismatch)",
                            p.display()
                        )
                    })
                    .collect();
                format!(
                    "lower {} was sealed against a different base than the mounted one; run `overlay verify {} BASE` to compare digests, or pass --force-stack-mismatch to mount anyway{journals}",
                    lower.display(),
                    lower.display()
                )
            });
        }
    }
    Ok(identity)
}

fn bottom_identity<'a>(
    identity: &'a BaseIdentity,
) -> impl Fn(&Path, Option<&ratarmount_compositing::OverlayMeta>) -> Result<String, String> + 'a {
    let BaseIdentity::Enforce { base, force } = identity;
    let force = *force;
    move |path, meta| mounted_base_identity(path, meta, base, force)
}

fn main() {
    // #93: a desktop launcher can hand us a pipe with no reader as
    // stdout/stderr. println!/eprintln! panic on EPIPE (exit 101) before the
    // mount exists, so point dead stdio at /dev/null first.
    neutralize_dead_stdio();
    let args = parse_args_from(std::env::args_os()).unwrap_or_else(|e| e.exit());

    if let Some(limit) = args.memory_budget {
        ratarmount_core::budget::MemoryBudget::install(limit)
            .expect("budget initialized before sources");
    }

    if let Some(command) = &args.sandbox_api {
        if let Err(error) = sandbox::run(command) {
            eprintln!("sandbox: {error}");
            std::process::exit(sandbox::error_exit_code(command));
        }
        return;
    }

    if let Some(snapshot) = &args.snapshot {
        match snapshot::run_cli(snapshot) {
            Ok(code) => std::process::exit(code),
            Err(error) => {
                eprintln!("snapshot: {error}");
                std::process::exit(1);
            }
        }
    }
    if let Some(diff) = &args.diff {
        std::process::exit(diff::run(
            diff,
            &overlay_run_context(diff.index_folders.as_deref()),
        ));
    }
    if args.shard.is_some() || args.export_index.is_some() {
        let result = export_index::cli_stdout()
            .map_err(Into::into)
            .and_then(|mut stdout| {
                if let Some(shard) = &args.shard {
                    shard::run(shard).map(|_| ())
                } else {
                    export_index::run(
                        args.export_index.as_ref().expect("parsed export-index"),
                        &mut stdout,
                    )
                }
            });
        if let Err(error) = result {
            eprintln!("error: {error}");
            std::process::exit(1);
        }
        return;
    }

    if let Some(journal) = &args.journal_command {
        if let Err(error) = journal_cmd::run(journal) {
            eprintln!("journal: {error}");
            std::process::exit(2);
        }
        return;
    }
    if let Some(overlay) = &args.overlay {
        match overlay_cmd::run(
            overlay,
            &overlay_run_context(overlay.index_folders.as_deref()),
        ) {
            Ok((output, code)) => {
                println!("{}", output.trim_end());
                if code != 0 {
                    std::process::exit(code);
                }
            }
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(
                    if matches!(
                        overlay.command,
                        overlay_cmd::OverlayCommand::Import(_)
                            | overlay_cmd::OverlayCommand::Fsck { .. }
                            | overlay_cmd::OverlayCommand::Seal(_)
                            | overlay_cmd::OverlayCommand::Unseal { .. }
                            | overlay_cmd::OverlayCommand::Verify(_)
                    ) {
                        2
                    } else {
                        1
                    },
                );
            }
        }
        return;
    }
    if let Some(stats) = &args.overlay_stats {
        match overlay_stats::run(stats) {
            Ok(output) => println!("{}", output.trim_end()),
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(1);
            }
        }
        return;
    }

    if args.print_features {
        // Features print does not need a full logger.
        print_features();
        return;
    }
    if args.oss_attributions || args.oss_attributions_short {
        print_oss_attributions(args.oss_attributions);
        return;
    }

    if let Some(msg) = serve_cli_error(&args) {
        eprintln!("error: {msg}");
        std::process::exit(2);
    }
    if let Some(msg) = find_cli_error(&args) {
        eprintln!("error: {msg}");
        std::process::exit(2);
    }
    if let Some(msg) = prepared_index_cli_error(&args) {
        eprintln!("error: {msg}");
        std::process::exit(2);
    }
    if let Some(msg) = index_id_cli_error(&args) {
        eprintln!("error: {msg}");
        std::process::exit(2);
    }
    if let Some(msg) = sftp_export_cli_error(&args) {
        eprintln!("error: {msg}");
        std::process::exit(2);
    }

    let write_style = resolve_color_style(args.color, args.no_color);
    init_logger(args.debug, args.log_file.as_deref(), write_style);
    if args.sandbox {
        log::info!(
            "sandbox: -o {} overlay={} quota={:?} passthrough={:?}",
            args.fuse,
            if args.overlay_tmpfs.is_some() {
                "tmpfs".into()
            } else {
                args.write_overlay
                    .as_ref()
                    .map(|path| path.display().to_string())
                    .unwrap_or_default()
            },
            args.overlay_quota,
            args.passthrough
        );
    }
    if args.overlay_tmpfs.is_some() && args.overlay_quota.is_none() {
        eprintln!("warning: --overlay-tmpfs has no size cap; RAM usage is unbounded (set --overlay-tmpfs=SIZE or --overlay-quota)");
    }

    if args.repack_seekable {
        match run_repack_seekable_cli(&args) {
            Ok(()) => return,
            Err((code, msg)) => {
                eprintln!("error: {msg}");
                std::process::exit(code);
            }
        }
    }

    if args.unmount {
        if args.paths.is_empty() {
            eprintln!("error: -u requires a mountpoint");
            std::process::exit(2);
        }
        for mp in &args.paths {
            if let Err(e) = unmount(mp) {
                eprintln!("error unmounting {}: {e}", mp.display());
                std::process::exit(1);
            }
        }
        return;
    }

    if args.commit_overlay {
        let overlay = args.write_overlay.as_ref().unwrap_or_else(|| {
            eprintln!("error: --commit-overlay requires --write-overlay <folder>");
            std::process::exit(2);
        });
        if overlay.as_os_str() == ":temp:" {
            eprintln!("error: --commit-overlay cannot use --write-overlay :temp:");
            std::process::exit(2);
        }
        // Expect: archive [mountpoint-ignored]
        if args.paths.is_empty() {
            eprintln!("error: --commit-overlay requires <archive.tar|archive.tar.zst|archive.zip>");
            std::process::exit(2);
        }
        let archive = &args.paths[0];
        if args.paths.len() > 2 {
            eprintln!("error: currently only modifications to a single archive may be committed");
            std::process::exit(2);
        }
        if let Some(msg) = overlay_commit::offline_remote_commit_error(archive) {
            eprintln!("error: {msg}");
            std::process::exit(2);
        }
        // A `file://` URL names a local archive: everything below (recovery,
        // the gate, the splice) works on the path it resolves to.
        // Only `file://` is resolved; any other remote scheme is refused
        // before anything could fetch it.
        let typed = archive.to_string_lossy();
        let resolved_archive = match ratarmount_remote::remote_url_scheme(&typed).as_deref() {
            Some("file") => match &ratarmount_remote::resolve_to_local(&typed) {
                Ok(ratarmount_remote::RemoteLocal::Local(path)) => path.clone(),
                _ => archive.clone(),
            },
            _ if ratarmount_remote::is_remote_url(&typed) => {
                eprintln!(
                    "error: offline --commit-overlay takes only a local path or file:// URL, not '{typed}'"
                );
                std::process::exit(2);
            }
            _ => archive.clone(),
        };
        let archive = &resolved_archive;
        // A database overlay recovers a pending commit journal only after its
        // base identity gate (inside the commit): recovery rewrites the archive,
        // and it must not do that to an archive the overlay does not describe.
        // Only a missing entry without a marker is "no database" (R7-E2,
        // R10-B): a dangling symlink, a directory or anything else there takes
        // the database path below; a lost record (marker kept, database gone)
        // or an entry that cannot be classified refuses before any recovery.
        let classify_overlay = || match ratarmount_compositing::overlay_db_entry(overlay) {
            Ok(ratarmount_compositing::DbEntry::Absent) => false,
            Ok(ratarmount_compositing::DbEntry::Present { .. }) => true,
            Ok(ratarmount_compositing::DbEntry::Lost { markers, .. }) => {
                eprintln!(
                    "error: {}",
                    ratarmount_compositing::lost_record_error(overlay, &markers)
                );
                std::process::exit(2);
            }
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(2);
            }
        };
        // Preserve classification's existing usage-error status, then make
        // the authoritative decision again under the operation lock.
        classify_overlay();
        // Cover creation and recovery too: they may write before publication.
        let commit_guard = match ratarmount_compositing::OverlayCommitGuard::acquire(overlay) {
            Ok(guard) => guard,
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        };
        let has_db = classify_overlay();
        if has_db {
            // Refuse sealed layers before creating or initializing a base (#238).
            if let Err(e) = ratarmount_compositing::ensure_overlay_unsealed(overlay) {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
        if !has_db {
            // No recorded base to compare, but a journal started for another
            // file (a copy of the interrupted bytes) must not be rolled in.
            if !args.force_base_mismatch {
                if let Err(msg) = ratarmount_compositing::ensure_journal_is_for_archive(archive) {
                    eprintln!("error: {msg}");
                    std::process::exit(2);
                }
            }
            let owner = if args.force_base_mismatch {
                ratarmount_compositing::Owner::Forced
            } else {
                ratarmount_compositing::Owner::Inode
            };
            // The overlay directory is passed so the guard under the archive
            // lock re-classifies it (R10-B): nothing is restamped while it
            // stays a raw directory.
            let recovered = ratarmount_compositing::recover_journal_at(
                archive,
                Some(&overlay.join(ratarmount_compositing::HIDDEN_DB)),
                owner,
            );
            if let Err(e) = recovered {
                eprintln!("error: commit recovery for {}: {e}", archive.display());
                std::process::exit(2);
            }
        }
        if let Err(e) = overlay_commit::maybe_create_missing_write_base(
            archive,
            overlay_commit::CreateMissingContext::OfflineCommit,
        ) {
            eprintln!("error: {e}");
            std::process::exit(2);
        }
        let opts = CommitOverlayOptions {
            mode: args.commit_overlay_mode.parse().expect("clap commit mode"),
            manifest_hashes: args.commit_manifest.then(|| args.manifest_hashes.clone()),
            yes: args.yes,
            debug: args.debug,
            encoding: args.encoding.clone(),
            ignore_zeros: args.ignore_zeros,
            force_base_mismatch: args.force_base_mismatch,
        };
        // An overlay with a database commits only over the base it recorded:
        // the archive is classified through the factory and gated before the
        // splice. A raw directory of files has no identity to check; it
        // commits through its own entry and says so.
        let result = if has_db {
            base_identity::classify_offline_commit(
                archive,
                &overlay_run_context(args.index_folders.as_deref()),
            )
            .map_err(OverlayError::Msg)
            .and_then(|base| commit_guard.commit(archive, &base, &opts))
        } else {
            commit_guard.commit_raw_dir(archive, &opts).map(|done| {
                if !done.identity_checked {
                    println!(
                        "note: no base identity was checked (overlay directory has no database)"
                    );
                }
                done.committed
            })
        };
        match result {
            Ok(_) => return,
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
    }

    if args.paths.is_empty() && args.source_binds.is_empty() {
        eprintln!("usage: ratarmount [options] <archive|folder|URL>... [mountpoint]");
        eprintln!("       ratarmount -u <mountpoint>");
        eprintln!(
            "       ratarmount --commit-overlay -w <overlay> <archive.tar|archive.tar.zst|archive.zip>"
        );
        eprintln!("       ratarmount --repack-seekable <INPUT> <OUTPUT>");
        eprintln!("       ratarmount -w ov --commit-overlay-interval 2s new.tar.zst mnt");
        eprintln!(
            "       ratarmount serve --nfs|--http|--webdav|--smb|--ninep|--sftp|--sftp-subsystem <archive>..."
        );
        eprintln!("       ratarmount find [--fts] [--hashes] [--offset-order] <pattern> <archive>");
        std::process::exit(2);
    }

    let (source_paths, mountpoint) = split_bound_inputs_mountpoint(&args);
    // Metadata labels also include bound sources; factory gets positional paths
    // separately so every explicit bind is opened exactly once.
    let mut inputs = source_paths.clone();
    inputs.extend(
        args.source_binds
            .iter()
            .map(|bind| PathBuf::from(&bind.source)),
    );
    let publishing = args.publish_index || args.publish_index_to.is_some();
    let live_hf_pr = !publishing
        && overlay_commit::live_hf_create_pr(
            &inputs,
            &args.commit_overlay_interval,
            args.commit_overlay_on_exit,
            args.create_pr,
        );
    if let Err(e) = publish_index::validate_publish_options(
        publishing,
        &inputs,
        args.publish_index_to.as_deref(),
        args.publish_revision.as_deref(),
        args.create_pr && !live_hf_pr,
    ) {
        eprintln!("error: {e}");
        std::process::exit(2);
    }
    if mountpoint.is_some() && !args.no_mount && !args.unmount {
        if let Err(error) = ratarmount_fuse::validate_allow_other(&args.fuse) {
            eprintln!("error: {error}");
            std::process::exit(2);
        }
    }

    // Refuse a mount point equal to, inside, or aliasing a folder the daemon reads by
    // path (the single-threaded daemon deadlocks on its own mount point). Early check:
    // creates nothing, before any fork. See `mount_guard`.
    let guard = if mount_guard::skip_guard(&args, mountpoint.as_deref(), publishing) {
        None
    } else {
        let fs = mount_guard::RealFs::new();
        match mount_guard::plan_mount_point(&fs, &args, mountpoint.clone(), &inputs) {
            Ok(plan) => Some((fs, plan)),
            Err(msg) => {
                eprintln!("error: {msg}");
                std::process::exit(2);
            }
        }
    };

    // Classify every local member's commit journal against the records that
    // vote on it BEFORE any recovery write; members a record does not own wait
    // for the identity gates (recovered below, after the overlay opened).
    let deferred_journals = recover_mount_journals(&args, &inputs);

    if !args.no_recreate_index
        && args.roll_every.is_none()
        && args.write_overlay.is_some()
        && inputs.len() == 1
        && args.source_binds.is_empty()
    {
        if let Err(e) = overlay_commit::maybe_create_missing_write_base(
            &inputs[0],
            overlay_commit::CreateMissingContext::Mount,
        ) {
            eprintln!("error: {e}");
            std::process::exit(2);
        }
    }

    let (index_in_memory, mut index_file_path) = match args.index_file.as_deref() {
        Some(s) if s.trim() == MEMORY_INDEX => (true, None),
        Some(s) => (false, Some(PathBuf::from(s))),
        None => (false, None),
    };

    if let Some(ref hex) = args.index_id {
        if index_in_memory {
            eprintln!("error: --index-id cannot be combined with --index-file :memory:");
            std::process::exit(2);
        }
        let archive = if args.find {
            &args.paths[1]
        } else {
            &inputs[0]
        };
        match bind_local_index_id(archive, hex) {
            Ok(p) => index_file_path = Some(p),
            Err(e) => {
                eprintln!("error: --index-id: {e}");
                std::process::exit(2);
            }
        }
    }

    let index_folders = index_folders_of(&args);

    let mut passwords = args.passwords.clone();
    if let Some(ref pf) = args.password_file {
        {
            let __inventory_condition_87856 = {
                #[expect(
                    clippy::disallowed_methods,
                    reason = r###"internal-read:v1 {"id":"IR-B0022-M01","item":"ratarmount::main","disposition":"out-of-family","category":"configuration-or-credentials","reason":"password file named on the command line","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
                )]
                let __inventory_value_0 = std::fs::read_to_string(pf);
                __inventory_value_0
            };
            match __inventory_condition_87856 {
                Ok(s) => {
                    for line in s.lines() {
                        let line = line.trim_end_matches(['\r', '\n']);
                        if !line.is_empty() {
                            passwords.push(line.to_string());
                        }
                    }
                }
                Err(e) => {
                    eprintln!("error reading --password-file: {e}");
                    std::process::exit(2);
                }
            }
        }
    }

    // Parallelization: Python-style matrix (`4`, `bzip2:4,gzip:2`, `0` = all cores).
    let parallelization = ParallelizationSpec::parse(&args.parallelization).unwrap_or_else(|e| {
        eprintln!("warning: invalid --parallelization: {e}; using default 1");
        ParallelizationSpec::default()
    });

    let gnu_incremental = if args.gnu_incremental {
        Some(true)
    } else if args.detect_gnu_incremental {
        None
    } else {
        Some(false)
    };

    let mut open_opts = OpenOptions {
        recursive: args.recursive,
        ignore_zeros: args.ignore_zeros,
        gnu_incremental,
        parallelization,
        readahead_bytes: parse_byte_size(&args.readahead)
            .map(clamp_readahead)
            .unwrap_or(0),
        torrent_swarm: args.torrent_swarm,
        torrent_scratch_bytes: args.torrent_scratch_limit,
        torrent_lsd: args.torrent_lsd,
        torrent_seed: args.seed,
        torrent_seed_upload_limit: args.seed_upload_limit,
        torrent_listen_port: args.torrent_listen_port,
        direct_io: args.direct_io,
        zstd_readahead_bytes: if readahead_flag_on_argv(std::env::args()) {
            clamp_readahead(parse_byte_size(&args.readahead).unwrap_or_else(|e| {
                eprintln!("error: invalid --readahead: {e}");
                std::process::exit(2);
            }))
        } else {
            16 * 1024 * 1024
        },
        index_minimum_file_count: args.index_minimum_file_count,
        index_file_path,
        index_in_memory,
        index_compact_only: false,
        index_folders,
        clear_index_cache: args.recreate_index && !args.no_recreate_index,
        write_index: !args.no_recreate_index && args.index_id.is_none(),
        read_only_index: args.no_recreate_index || args.index_id.is_some(),
        gzip_seek_point_spacing: (args.gzip_seek_point_spacing_mib * 1024.0 * 1024.0) as u64,
        recursion_depth: if args.recursion_depth == 0 {
            // Python: -r alone means infinite; we map to deep default in automount (32)
            if args.recursive {
                Some(-1)
            } else {
                None
            }
        } else {
            Some(args.recursion_depth)
        },
        passwords,
        encoding: args.encoding.clone(),
        verify_modification_time: args.verify_mtime,
        use_backends: args
            .use_backend
            .iter()
            .flat_map(|s| s.split(','))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        force_folder_index: args.force_folder_index,
        git: args.git,
        git_ref: args.git_ref.clone(),
        git_prefix: args.git_prefix.clone(),
        git_synthetic_head: args.git_synthetic_head,
        hashes: args
            .hashes
            .as_deref()
            .map(|s| {
                s.split(',')
                    .map(|p| p.trim().to_string())
                    .filter(|p| !p.is_empty())
                    .collect()
            })
            .unwrap_or_default(),
        index_build: Default::default(),
        recover_journals: false,
    };

    if args.force_folder_index {
        eprintln!("info: --force-folder-index accepted; folders still bind-mount without SQLite");
    }

    if args.find {
        let pattern = args.paths[0].to_string_lossy();
        let archive = &args.paths[1];
        let include_hashes = args.find_hashes || !open_opts.hashes.is_empty();
        let loc = find::LocateOptions {
            fts: args.find_fts,
            include_hashes,
            fill_hashes: &open_opts.hashes,
            offset_order: args.find_offset_order,
            xattrs: &args.find_xattrs,
        };
        std::process::exit(find::run(archive, &pattern, &open_opts, &loc));
    }

    let rolling = if let Some(policy) = &args.roll_every {
        if inputs.len() != 1
            || !args.source_binds.is_empty()
            || args.corpus_list.is_some()
            || args.find
        {
            eprintln!(
                "error: --roll-every requires one local series base without --bind/corpus/find"
            );
            std::process::exit(2);
        }
        if open_opts.index_file_path.is_some() && !open_opts.index_in_memory {
            eprintln!("error: --roll-every needs per-archive sidecars; use the default index path or :memory:");
            std::process::exit(2);
        }
        match overlay_commit::open_rolling_series(&inputs[0], policy.clone(), &open_opts) {
            Ok(series) => {
                inputs[0] = series.active_path();
                if let Some((_, plan)) = &guard {
                    if let Some(derived) = &plan.derived_rolling_input {
                        if let Some(msg) =
                            mount_guard::rolling_derivation_notice(derived, &inputs[0], &plan.mp)
                        {
                            eprintln!("warning: {msg}");
                        }
                    }
                }
                Some(series)
            }
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(2);
            }
        }
    } else {
        None
    };

    let file_versions = !args.no_file_versions;

    let mut bindings = factory::SourceBindings {
        binds: args.source_binds.clone(),
        ..Default::default()
    };
    if let Some(series) = &rolling {
        // Declared: the series is built here, so this caller names what it is.
        let active = series.active_path();
        bindings.sources.push(factory::DeclaredSource {
            src: series.clone() as Arc<dyn MountSource>,
            kind: ratarmount_compositing::ServedKind::Archive,
            location: Some(ratarmount_compositing::ServedLocation::Local(
                active.clone(),
            )),
            label: active.display().to_string(),
        });
    }
    if let Some(list) = &args.corpus_list {
        match corpus::open(list, args.corpus_cache_size as usize) {
            Ok(source) => bindings.sources.push(factory::DeclaredSource {
                src: source,
                kind: ratarmount_compositing::ServedKind::Folder,
                location: None,
                label: "corpus".to_owned(),
            }),
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(2);
            }
        }
    }
    // A `-w` or `--lower` mount classifies its base: the kind and place the
    // factory actually served are what the overlay records and compares.
    let wants_identity = args.write_overlay.is_some() || !args.lower.is_empty();
    let factory_paths: Vec<PathBuf> = if args.corpus_list.is_some() || rolling.is_some() {
        Vec::new()
    } else {
        source_paths.clone()
    };
    if args.no_mount && !open_opts.read_only_index && !open_opts.index_in_memory {
        for path in factory_paths.iter().cloned().chain(
            args.source_binds
                .iter()
                .map(|bind| PathBuf::from(&bind.source)),
        ) {
            if let Err(error) = factory::validate_worker_preparation(&path) {
                eprintln!("error: {error}");
                std::process::exit(1);
            }
        }
    }
    let factory_comp = factory::CompositingOptions {
        recursive: args.recursive || args.recursion_depth != 0,
        lazy: args.lazy,
        file_versions,
        prefix: if args.prefix.is_empty() {
            None
        } else {
            Some(args.prefix.clone())
        },
        strip_recursive_extension: args.strip_recursive_tar_extension,
        transform_recursive: args.transform_recursive_mount_point.as_ref().and_then(|v| {
            if v.len() == 2 {
                Some((v[0].clone(), v[1].clone()))
            } else {
                None
            }
        }),
        transform: args.transform.as_ref().and_then(|v| {
            if v.len() == 2 {
                Some((v[0].clone(), v[1].clone()))
            } else {
                None
            }
        }),
        disable_union_mount: args.disable_union_mount,
        recursive_extensions: Some(args.recursive_extensions.clone()),
        union_cache: ratarmount_compositing::UnionMountOptions {
            max_cache_depth: args.union_mount_cache_max_depth,
            max_cache_entries: args.union_mount_cache_max_entries,
            max_seconds_to_cache: args.union_mount_cache_timeout,
            resolve_symlinks: args.union_resolve_symlinks,
        },
        parallel_nested_threads: args.parallel_nested,
    };
    let recreate_index = args.recreate_index && !args.no_recreate_index;
    let prepared_artifacts;
    let (mut bundle, classified) = if wants_identity {
        let mut opener = base_identity::FactoryOpener::new(
            inputs
                .iter()
                .map(|p| p.to_string_lossy().into_owned())
                .collect(),
            factory_paths,
            &mut open_opts,
            recreate_index,
            factory_comp,
            bindings,
            args.source_binds.is_empty(),
        );
        match ratarmount_compositing::ClassifiedBase::open(&mut opener) {
            Ok(base) => {
                prepared_artifacts = opener.prepared_artifacts().to_vec();
                (
                    base_identity::MountedSource {
                        source: base.source(),
                        _keep_alive: Box::new(()),
                    },
                    Some(base),
                )
            }
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
    } else {
        match factory::build_mount_source_with_bindings(
            &factory_paths,
            &mut open_opts,
            recreate_index,
            factory_comp,
            bindings,
        ) {
            Ok(built) => {
                prepared_artifacts = built.prepared_artifacts.clone();
                (
                    base_identity::MountedSource {
                        source: built.source.clone(),
                        _keep_alive: built.into_keep_alive(),
                    },
                    None,
                )
            }
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
    };

    // Decisive check: inputs are opened (index folders exist), the `-w` directory is
    // created here exactly as `WriteOverlay::new` did, and nothing has forked, no
    // overlay database, marker or inspection socket exists and nothing is published.
    // Only guard-active runs (a FUSE mount point is coming) take this path; export-only,
    // `--no-mount`, `find` and publish-only keep HEAD's order.
    let mut prepared_overlay_path: Option<PathBuf> = None;
    if let Some((fs, plan)) = &guard {
        if let Some(w) = &args.write_overlay {
            let p = overlay_dir_for(&args, w);
            // The `-w` directory is created before the check so the resolver sees the
            // real directory; no database, marker or socket exists yet.
            if let Err(e) = mount_guard::prepare_overlay_dir(&p) {
                eprintln!("{}", overlay_open_error(&p, &OverlayError::Io(e)));
                std::process::exit(1);
            }
            prepared_overlay_path = Some(p);
        }
        if let Err(msg) = mount_guard::decisive_check(fs, plan, prepared_overlay_path.as_deref()) {
            eprintln!("error: {msg}");
            // A `:temp:` overlay directory is removed by the atexit handler.
            std::process::exit(2);
        }
    }

    // Content-hash xattrs foundation: after a successful mount build, for each
    // path-backed local archive with an on-disk index, open the index writable and
    // fill user.hash.* xattrs. Does not go through factory (TODO: hook during index
    // finalization so compressed/nested sources hash via MountSource::open).
    if !open_opts.hashes.is_empty() {
        if open_opts.index_in_memory {
            log::warn!(
                "--hashes with --index-file :memory: is not applied after mount build; \
                 re-open a path-backed index or hook factory finalization"
            );
        } else {
            for input in &inputs {
                if !input.is_file() {
                    continue;
                }
                // Skip obvious non-local schemes (http(s), sftp, …).
                if let Some(s) = input.to_str() {
                    if s.contains("://") {
                        continue;
                    }
                }
                let explicit = open_opts
                    .index_file_path
                    .as_ref()
                    .map(|p| p.to_string_lossy().into_owned());
                let loc = resolve_index_location(
                    input,
                    explicit.as_deref(),
                    &open_opts.index_folders,
                    false,
                );
                let Some(idx_path) = loc.as_path() else {
                    continue;
                };
                if !idx_path.exists() {
                    log::debug!(
                        "skip --hashes for {}: index {} missing",
                        input.display(),
                        idx_path.display()
                    );
                    continue;
                }
                match SqliteIndex::open_writable(idx_path) {
                    Ok(idx) => {
                        if let Err(e) = fill_content_hashes(&idx, input, &open_opts.hashes) {
                            log::warn!(
                                "failed to fill content hashes for {} (index {}): {e}",
                                input.display(),
                                idx_path.display()
                            );
                        } else {
                            log::info!(
                                "stored content hashes {:?} in {}",
                                open_opts.hashes,
                                idx_path.display()
                            );
                        }
                    }
                    Err(e) => {
                        log::warn!("cannot open index {} for --hashes: {e}", idx_path.display());
                    }
                }
            }
        }
    }

    let index_sidecar = resolved_on_disk_index(&inputs, &open_opts);
    if args.publish_index || args.publish_index_to.is_some() {
        match index_sidecar.as_deref() {
            Some(src) => {
                if let Err(e) = publish_index::publish_validated_index(
                    publish_index::PublishIndexOpts {
                        archive: &inputs[0],
                        sidecar: src,
                        dest: args.publish_index_to.as_deref(),
                        no_recreate_index: args.no_recreate_index,
                    },
                    args.publish_revision.as_deref(),
                    args.create_pr,
                ) {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
            }
            None => {
                eprintln!(
                    "error: --publish-index requires an on-disk SQLite sidecar (not :memory:)"
                );
                std::process::exit(2);
            }
        }
    }

    if publishing && mountpoint.is_none() {
        return;
    }

    let mut overlay_arc: Option<Arc<WriteOverlay>> = None;
    let mut overlay_quota: Option<Arc<ratarmount_compositing::OverlayQuota>> = None;
    let mut journal_rules = None;

    // Under WriteOverlay so overlay files never hit payload-v1.
    bundle.source = maybe_wrap_payload_cache(bundle.source, open_opts.index_in_memory);

    let peek_index = if open_opts.read_only_index {
        classified
            .as_ref()
            .and_then(|base| base.actual().index_for_peek())
    } else {
        index_sidecar.as_deref()
    };
    let lower_key = lower_key_for(
        &args,
        rolling.is_some(),
        &inputs,
        peek_index,
        open_opts.read_only_index,
    )
    .unwrap_or_else(|error| {
        eprintln!("error: prepared lower-key identity: {error}");
        std::process::exit(2);
    });
    let lower_identity = BaseIdentity::Enforce {
        base: MountedBase {
            extra_excludes: lower_extra_excludes(
                inputs.first().map(PathBuf::as_path),
                &args.lower,
                args.write_overlay.as_deref(),
                args.journal.iter().cloned().collect(),
            ),
            existing_journals: existing_journals_inside_base(
                inputs.first().map(PathBuf::as_path),
                &args.lower,
                &args.journal,
            ),
            classified: classified.clone(),
            supplied: match &args.base_digest {
                Some(ratarmount_compositing::BaseDigestRequest::Supplied(digest)) => {
                    Some(digest.clone())
                }
                _ => None,
            },
        },
        force: args.force_stack_mismatch,
    };
    let (lower_stack, lower_view) = MountLowerStack::open_with(
        bundle.source.clone(),
        lower_key.as_deref(),
        &args.lower,
        args.allow_unsealed_lower,
        None,
        &bottom_identity(&lower_identity),
        &lower_stack_services(),
    )
    .unwrap_or_else(|error| {
        eprintln!("error: {error}");
        std::process::exit(1);
    });
    bundle.source = lower_view;

    if let Some(w) = &args.write_overlay {
        let overlay_path = match prepared_overlay_path.take() {
            Some(p) => p,
            None => overlay_dir_for(&args, w),
        };
        lower_stack
            .check_top(&overlay_path, args.force_stack_mismatch)
            .unwrap_or_else(|error| {
                eprintln!("error: {error}");
                std::process::exit(1);
            });
        let create_options = ratarmount_compositing::CreateOptions {
            base_digest: args.base_digest.clone().unwrap_or_default(),
            force_base_mismatch: args.force_base_mismatch,
            lower_layers: lower_stack.records.clone(),
            index_writable: !open_opts.read_only_index,
            // Journal and lower layers inside a directory base stay out of its
            // digest. A mount point inside it is refused by `mount_guard`.
            weak_exclude: args
                .journal
                .iter()
                .cloned()
                .chain(lower_stack.records.iter().map(|r| r.path.clone()))
                .collect(),
            remote_token: None,
        };
        match overlay_create::create_overlay(
            classified.as_ref().expect("a -w mount classified its base"),
            Arc::clone(&bundle.source),
            &overlay_path,
            create_options,
            &inputs,
            !args.source_binds.is_empty(),
        ) {
            Ok(mut ov) => {
                if let Some(series) = &rolling {
                    ov.set_rolling(series.clone());
                }
                ov.set_encoding(&args.encoding);
                ov.set_control_reserved(args.control_interface && !args.control_socket_only);
                if let Ok(Some(marker)) = ov.meta_value("import_in_progress") {
                    eprintln!(
                        "warning: {} holds a partial `overlay import` ({marker}); delete it and import again before sealing",
                        overlay_path.display()
                    );
                }
                ov.set_manifest_hashes(args.commit_manifest.then(|| args.manifest_hashes.clone()));
                ov.set_commit_mode(args.commit_overlay_mode.parse().expect("clap commit mode"));
                if !args.overlay_readonly.is_empty()
                    || args.overlay_quota.is_some()
                    || args.overlay_quota_files.is_some()
                {
                    use ratarmount_compositing::{
                        CompositeOverlayPolicy, OverlayPolicy, OverlayQuota, ReadOnlyGlobs,
                    };
                    let mut quota = match OverlayQuota::new(
                        ov.root(),
                        args.overlay_quota,
                        args.overlay_quota_files,
                    ) {
                        Ok(quota) => quota,
                        Err(e) => {
                            eprintln!("error scanning write overlay: {e}");
                            std::process::exit(1);
                        }
                    };
                    let mut policies: Vec<Arc<dyn OverlayPolicy>> = Vec::new();
                    let rules_json = if args.overlay_readonly.is_empty() {
                        serde_json::json!({"readonly": [], "allow": []})
                    } else {
                        let rules = Arc::new(
                            ReadOnlyGlobs::with_allow(&args.overlay_readonly, &args.overlay_allow)
                                .and_then(|rules| rules.with_overlay_root(ov.root()))
                                .expect("validated read-only globs and overlay root"),
                        );
                        let json = rules.rules_json();
                        quota = quota.with_readonly(rules.clone());
                        journal_rules = Some(rules.clone());
                        policies.push(rules);
                        json
                    };
                    // The rules of the latest -w mount, so `overlay info` shows
                    // what the agent was allowed to change.
                    if let Err(e) = ov.set_meta("readonly_rules", &rules_json.to_string()) {
                        eprintln!("error recording read-only rules in overlay metadata: {e}");
                        std::process::exit(1);
                    }
                    let quota = Arc::new(quota);
                    policies.push(quota.clone());
                    ov.set_policy(Some(Arc::new(CompositeOverlayPolicy(policies))));
                    overlay_quota = Some(quota);
                } else if let Err(e) = ov.set_meta(
                    "readonly_rules",
                    &serde_json::json!({"readonly": [], "allow": []}).to_string(),
                ) {
                    eprintln!("error recording read-only rules in overlay metadata: {e}");
                    std::process::exit(1);
                }
                let ov = Arc::new(ov);
                bundle.source = Arc::clone(&ov) as Arc<dyn MountSource>;
                overlay_arc = Some(ov);
            }
            Err(e) => {
                eprintln!("{}", overlay_open_error(&overlay_path, &e));
                std::process::exit(1);
            }
        }
    }

    // Members whose complete journal waited for the gates: every gate accepted,
    // so each is recovered now (through the overlay's own connection when there
    // is one: it holds its database exclusively).
    for member in &deferred_journals {
        let recovered = match overlay_arc.as_ref() {
            Some(ov) => ov.recover_member_journal(member).map_err(|e| e.to_string()),
            None => ratarmount_compositing::recover_journal_at(
                member,
                None,
                ratarmount_compositing::Owner::Inode,
            )
            .map(|_| ())
            .map_err(|e| e.to_string()),
        };
        if let Err(e) = recovered {
            eprintln!("error: commit recovery for {}: {e}", member.display());
            drop(overlay_arc);
            std::process::exit(1);
        }
    }

    let _sandbox_inspector = args.sandbox_inspection_socket.as_ref().map(|path| {
        sandbox::start_inspection(path, overlay_arc.as_ref().expect("validated write overlay"))
            .unwrap_or_else(|error| {
                eprintln!("sandbox inspection: {error}");
                std::process::exit(1);
            })
    });

    let commit_interval = match overlay_commit::parse_interval(&args.commit_overlay_interval) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(2);
        }
    };
    let live_commit_archive = if args.commit_overlay_on_exit || commit_interval.is_some() {
        match overlay_commit::validate_live_commit_args(
            if args.overlay_tmpfs_allow_commit {
                overlay_arc.as_ref().map(|overlay| overlay.root())
            } else {
                args.write_overlay.as_deref()
            },
            &inputs,
        ) {
            Ok(p) => Some(p),
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(2);
            }
        }
    } else {
        None
    };
    if args.commit_overlay_on_exit || commit_interval.is_some() || has_temp_overlay() {
        overlay_commit::install_term_signal_flag();
    }
    if let (Some(ov), Some(archive)) = (overlay_arc.as_ref(), live_commit_archive.as_ref()) {
        if let Err(error) = overlay_commit::install_object_store_live_commit(
            ov,
            archive,
            &open_opts,
            args.create_pr,
        ) {
            eprintln!("error: {error}");
            std::process::exit(2);
        }
    }

    if args.no_mount {
        if let Some(flag) = export_incompatible_with_no_mount(&args) {
            eprintln!("error: {flag} cannot be combined with --no-mount");
            std::process::exit(2);
        }
        // Only the exclusive preparer finishes publication. Release every
        // source owner before reopening the actual artifacts for checkpointing.
        drop(_sandbox_inspector);
        drop(bundle);
        drop(classified);
        drop(lower_identity);
        drop(overlay_arc);
        drop(rolling);
        drop(lower_stack);
        if !open_opts.read_only_index {
            for path in &prepared_artifacts {
                if let Err(error) = SqliteIndex::finalize_prepared(path) {
                    eprintln!(
                        "error: incomplete preparation for {}: {error}",
                        path.display()
                    );
                    std::process::exit(1);
                }
            }
        }
        return;
    }
    if (args.sftp || args.sftp_subsystem) && !ratarmount_sftp::sftp_russh_compiled() {
        let flag = if args.sftp_subsystem {
            "--sftp-subsystem"
        } else {
            "--sftp"
        };
        eprintln!("error: {flag}: {}", ratarmount_sftp::SFTP_RUSSH_HINT);
        std::process::exit(2);
    }
    if args.sftp_subsystem
        && (args.sftp_authorized_keys.is_some() || args.sftp_bind != "127.0.0.1:20222")
    {
        eprintln!("warning: --sftp-subsystem ignores --sftp-bind and --sftp-authorized-keys");
    }

    let readahead_on_argv = readahead_flag_on_argv(std::env::args());
    #[cfg(feature = "gzip-rapidgzip")]
    let prefer_rapidgzip =
        ratarmount_compress::prefer_rapidgzip_gzip_backend(&open_opts.use_backends);
    #[cfg(not(feature = "gzip-rapidgzip"))]
    let prefer_rapidgzip = false;
    let gzip_input = inputs.iter().any(|p| path_looks_like_gzip_archive(p));
    let readahead = match parse_byte_size(&args.readahead) {
        Ok(n) => {
            let clamped = clamp_readahead(n);
            if clamped < n {
                eprintln!(
                    "warning: --readahead {n} exceeds max {}; using {}",
                    ratarmount_fuse::MAX_READAHEAD_BYTES,
                    clamped
                );
            }
            let effective =
                should_auto_readahead(prefer_rapidgzip, gzip_input, readahead_on_argv, clamped);
            if effective > 0 && clamped == 0 && !readahead_on_argv {
                let reason = if prefer_rapidgzip {
                    "rapidgzip"
                } else {
                    "gzip archive"
                };
                log::info!(
                    "auto-enabling FUSE readahead {effective} bytes for {reason} \
                     (pass --readahead 0 to disable)"
                );
            } else if effective > 0 {
                log::info!("FUSE readahead enabled: {effective} bytes per sequential window");
            }
            effective
        }
        Err(e) => {
            eprintln!("error: invalid --readahead: {e}");
            std::process::exit(2);
        }
    };

    let nfs_bind = if args.nfs {
        match ratarmount_nfs::parse_nfs_bind(&args.nfs_bind) {
            Ok(a) => Some(a),
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(2);
            }
        }
    } else {
        None
    };
    // Same gate as `--nfs-bind`: ignore `--nfs-vers` unless `--nfs` is set
    // (FUSE-only `--nfs-vers 4 archive mnt` must not exit 2).
    let nfs_vers = if args.nfs {
        match ratarmount_nfs::parse_nfs_vers(&args.nfs_vers) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(2);
            }
        }
    } else {
        if args.nfs_vers != "3" {
            log::debug!("ignoring --nfs-vers without --nfs");
        }
        ratarmount_nfs::NfsVers::V3
    };
    #[cfg(feature = "nfsv4")]
    if args.nfs && args.nfs_export_name.is_some() && nfs_vers == ratarmount_nfs::NfsVers::V4 {
        eprintln!("warning: --nfs-export-name is ignored on NFSv4.1 (no MOUNT)");
    }

    // Export-only (NFS/HTTP/…): do not invent a FUSE mountpoint / stem directory.
    let fuse_mp = match &guard {
        // Export-only without a mount point, as on HEAD.
        None => None,
        Some((_, plan)) => {
            // First durable creation of the accepted mount point.
            #[expect(
                clippy::disallowed_methods,
                reason = r###"internal-read:v1 {"id":"IR-E0114-M01","item":"ratarmount::main","disposition":"output-owner","category":"mountpoint-directory","reason":"Create the accepted FUSE mountpoint after the guard has validated the mount plan.","creation":{"policy":"recursive-directory","basis":"Only the explicit guarded FUSE path is created; export-only operation supplies no mountpoint and does not reach this leaf."}}"###
            )]
            std::fs::create_dir_all(&plan.mp).ok();
            Some(plan.mp.clone())
        }
    };
    if args.sftp_subsystem && fuse_mp.is_some() && !args.foreground {
        eprintln!(
            "warning: --sftp-subsystem with a FUSE mountpoint daemonizes and redirects stdin; \
             use -f or omit the mountpoint"
        );
    }

    if any_export(&args) && fuse_mp.is_none() && args.control_interface {
        eprintln!(
            "error: --control-interface requires a FUSE mountpoint (export-only is not supported)"
        );
        std::process::exit(2);
    }

    let journal_options = args.journal.as_ref().map(|path| {
        let Some(mp) = &fuse_mp else {
            eprintln!("error: --journal requires a FUSE mountpoint");
            std::process::exit(2);
        };
        let path = ratarmount_fuse::oplog::validate_path(
            path,
            mp,
            overlay_arc.as_ref().map(|ov| ov.root()),
        )
        .unwrap_or_else(|error| {
            eprintln!("journal: {error}");
            std::process::exit(2)
        });
        ratarmount_fuse::oplog::JournalOptions {
            path,
            exclude: args.journal_exclude.clone(),
            reads: if args.journal_reads == "first" {
                ratarmount_fuse::oplog::Reads::First
            } else {
                ratarmount_fuse::oplog::Reads::All
            },
            sync: args.journal_sync,
        }
    });
    let activity = ratarmount_fuse::oplog::MountActivity {
        journal: journal_options,
        quota: overlay_quota.clone(),
        readonly: journal_rules,
        metadata: if overlay_arc.is_none() {
            lower_stack.read_only_metadata()
        } else {
            Default::default()
        },
    };

    let writable = overlay_arc.is_some();
    let fuse_opts = args.fuse.clone();
    let passthrough = PassthroughOptions {
        mode: args.passthrough,
        copy: args.passthrough_copy,
        copy_max: args.passthrough_copy_max,
        copy_total_max: args.passthrough_copy_total_max,
    };

    // Optional control: Unix socket + in-FS `/.ratarmount-control/` (Python parity).
    let control_stop = Arc::new(AtomicBool::new(false));
    let control = if args.control_interface {
        let mp = fuse_mp.as_ref().expect("control requires FUSE mp");
        let stop = Arc::clone(&control_stop);
        let mp_ctrl = mp.clone();
        let pre_control = Arc::clone(&bundle.source);
        let unmount_in_progress = Arc::new(AtomicBool::new(false));
        let on_search = find::live_search_callback(
            Arc::clone(&pre_control),
            overlay_arc.clone(),
            inputs[0].clone(),
            open_opts.clone(),
        );
        if !args.control_socket_only {
            bundle.source = Arc::new(
                ControlFolderMountSource::new(
                    pre_control,
                    ControlFolderOptions::enabled()
                        .with_label(mp.display().to_string())
                        .with_on_unmount(Arc::new(move || {
                            // The callback fires inside the FUSE request that opens or reads the
                            // control file, so unmounting here would always find the mount busy
                            // (and a retry would stall the request thread). Unmount on a short
                            // thread instead: the opener's request finishes, the opener closes
                            // the file, and the retrying unmount then succeeds. The guard only
                            // blocks a concurrent attempt (open and read both fire); `stop` is
                            // set after success so a failed attempt can be retried by a later read.
                            if unmount_in_progress.swap(true, Ordering::SeqCst) {
                                return;
                            }
                            let stop = Arc::clone(&stop);
                            let mp = mp_ctrl.clone();
                            let in_progress = Arc::clone(&unmount_in_progress);
                            let spawned = thread::Builder::new()
                                .name("ratarmount-control-unmount".into())
                                .spawn(move || match unmount(&mp) {
                                    Ok(()) => stop.store(true, Ordering::SeqCst),
                                    Err(e) => {
                                        log::warn!(
                                            "control file unmount of {} failed: {e}",
                                            mp.display()
                                        );
                                        in_progress.store(false, Ordering::SeqCst);
                                    }
                                });
                            if let Err(e) = spawned {
                                log::warn!("control file unmount: cannot start thread: {e}");
                                unmount_in_progress.store(false, Ordering::SeqCst);
                            }
                        }))
                        .with_on_search(Arc::clone(&on_search)),
                )
                .with_on_status(overlay_quota.clone().map(|quota| {
                    Arc::new(move || quota.usage().status_text())
                        as Arc<dyn Fn() -> String + Send + Sync>
                })),
            ) as Arc<dyn MountSource>;
        }
        bind_control_interface(
            mp,
            Arc::clone(&control_stop),
            Some(on_search),
            overlay_quota.clone(),
        )
    } else {
        None
    };

    let other_exports =
        args.http || args.webdav || args.smb || args.ninep || args.sftp || args.sftp_subsystem;
    if let Some(bind) = nfs_bind {
        if !bind.ip().is_loopback() {
            eprintln!(
                "warning: NFS bound on {} (AUTH_SYS, no allowlist). \
                 Prefer 127.0.0.1 unless you trust the LAN.",
                bind
            );
        }
        let nfs_opts = ratarmount_nfs::NfsOptions {
            attribute_mapping: ratarmount_core::AttributeMapping::parse(&args.fuse)
                .expect("validated attribute mapping"),
            bind,
            export_name: args.nfs_export_name.clone(),
            readahead_bytes: readahead,
            reader_slots: ratarmount_nfs::DEFAULT_READER_SLOTS,
            stop: None,
            overlay: overlay_arc.clone(),
            vers: nfs_vers,
        };
        if !other_exports {
            match fuse_mp {
                None => run_nfs_only(
                    bundle.source,
                    nfs_opts,
                    overlay_arc,
                    live_commit_archive,
                    args.commit_overlay_on_exit,
                    commit_interval,
                    open_opts,
                ),
                Some(mp) => run_fuse_and_nfs(
                    bundle.source,
                    mp,
                    writable,
                    overlay_arc,
                    &fuse_opts,
                    passthrough,
                    activity,
                    readahead,
                    nfs_opts,
                    args.foreground,
                    args.log_file.is_some(),
                    live_commit_archive,
                    args.commit_overlay_on_exit,
                    commit_interval,
                    open_opts,
                    control,
                ),
            }
            return;
        }
        let plan = parse_export_plan(&args, overlay_arc.clone(), readahead, index_sidecar.clone());
        run_exports(
            bundle.source,
            fuse_mp,
            writable,
            overlay_arc,
            &fuse_opts,
            passthrough,
            activity,
            readahead,
            Some(nfs_opts),
            plan,
            args.foreground,
            args.log_file.is_some(),
            live_commit_archive,
            args.commit_overlay_on_exit,
            commit_interval,
            open_opts,
            control,
        );
        return;
    }

    if other_exports {
        let plan = parse_export_plan(&args, overlay_arc.clone(), readahead, index_sidecar.clone());
        run_exports(
            bundle.source,
            fuse_mp,
            writable,
            overlay_arc,
            &fuse_opts,
            passthrough,
            activity,
            readahead,
            None,
            plan,
            args.foreground,
            args.log_file.is_some(),
            live_commit_archive,
            args.commit_overlay_on_exit,
            commit_interval,
            open_opts,
            control,
        );
        return;
    }

    let mp = fuse_mp.expect("FUSE path has a mountpoint");
    run_fuse_only(
        bundle.source,
        mp,
        writable,
        overlay_arc,
        &fuse_opts,
        passthrough,
        activity,
        readahead,
        args.foreground,
        args.log_file.is_some(),
        live_commit_archive,
        args.commit_overlay_on_exit,
        commit_interval,
        open_opts,
        control,
    );
}

/// The overlay directory for `-w`: the path itself, or a fresh temporary directory
/// (disk-backed or tmpfs) for `:temp:`.
fn overlay_dir_for(args: &Args, w: &Path) -> PathBuf {
    if w.as_os_str() == ":temp:" {
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-B0023-M01","item":"ratarmount::overlay_dir_for","disposition":"output-owner","mode_policy":"unchanged-from-e6ca64e","category":"output-owner","reason":"Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"unchanged-from-e6ca64e","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###
        )]
        let td = if args.overlay_tmpfs.is_some() {
            create_tmpfs_overlay()
        } else {
            tempfile::TempDir::with_prefix("ratarmount-write-overlay.")
        }
        .unwrap_or_else(|error| {
            eprintln!("error creating temporary overlay: {error}");
            std::process::exit(1)
        });
        let p = td.path().to_path_buf();
        eprintln!("Created temporary overlay directory: {}", p.display());
        register_temp_overlay(td);
        p
    } else {
        w.to_path_buf()
    }
}

fn any_export(args: &Args) -> bool {
    args.nfs
        || args.http
        || args.webdav
        || args.smb
        || args.ninep
        || args.sftp
        || args.sftp_subsystem
}

fn export_incompatible_with_no_mount(args: &Args) -> Option<&'static str> {
    if args.nfs {
        Some("--nfs")
    } else if args.http {
        Some("--http")
    } else if args.webdav {
        Some("--webdav")
    } else if args.smb {
        Some("--smb")
    } else if args.ninep {
        Some("--ninep")
    } else if args.sftp {
        Some("--sftp")
    } else if args.sftp_subsystem {
        Some("--sftp-subsystem")
    } else {
        None
    }
}

/// `--sftp` (TCP) and `--sftp-subsystem` (stdio) cannot share a process.
fn sftp_export_cli_error(args: &Args) -> Option<&'static str> {
    if args.sftp && args.sftp_subsystem {
        Some("--sftp and --sftp-subsystem are mutually exclusive")
    } else {
        None
    }
}

struct ExportPlan {
    http: Option<ratarmount_http::HttpOptions>,
    webdav: Option<ratarmount_http::WebDavOptions>,
    smb: Option<ratarmount_smb::SmbOptions>,
    ninep: Option<ratarmount_9p::NinepOptions>,
    sftp: Option<ratarmount_sftp::SftpOptions>,
    /// Stdio SFTP v3 (`--sftp-subsystem`). Not a TCP listener.
    sftp_stdio: Option<ratarmount_sftp::SftpOptions>,
}

fn parse_bind_or_exit<E: std::fmt::Display>(
    s: &str,
    parse: impl FnOnce(&str) -> Result<std::net::SocketAddr, E>,
) -> std::net::SocketAddr {
    match parse(s) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(2);
        }
    }
}

fn warn_export_non_loopback(name: &str, bind: std::net::SocketAddr) {
    if !bind.ip().is_loopback() {
        eprintln!(
            "warning: {name} bound on {bind} (no auth). Prefer 127.0.0.1 unless you trust the LAN."
        );
    }
}

/// The index folders the invocation names (`--index-folders`), else the defaults.
fn index_folders_of(args: &Args) -> Vec<PathBuf> {
    parse_folders_or_default(args.index_folders.as_deref())
}

fn parse_folders_or_default(spec: Option<&str>) -> Vec<PathBuf> {
    match spec {
        Some(s) => parse_index_folders(s),
        None => default_index_folders(),
    }
}

/// What the offline verbs need from their invocation: the `--index-folders`
/// they were given (`overlay ... --index-folders`, `diff --index-folders`,
/// `--commit-overlay --index-folders`), else the defaults a mount uses.
fn overlay_run_context(spec: Option<&str>) -> base_identity::OverlayRunContext {
    base_identity::OverlayRunContext {
        index_folders: parse_folders_or_default(spec),
    }
}

fn resolved_on_disk_index(inputs: &[PathBuf], opts: &OpenOptions) -> Option<PathBuf> {
    if opts.index_in_memory {
        return None;
    }
    let archive = inputs.first()?;
    let explicit = opts
        .index_file_path
        .as_ref()
        .map(|p| p.to_string_lossy().into_owned());
    let loc = resolve_index_location(archive, explicit.as_deref(), &opts.index_folders, false);
    let p = loc.as_path()?;
    match std::fs::metadata(p) {
        Ok(m) if m.is_file() && m.len() > 0 => Some(p.to_path_buf()),
        _ => None,
    }
}

fn parse_export_plan(
    args: &Args,
    overlay: Option<Arc<WriteOverlay>>,
    readahead: u64,
    index_sidecar: Option<PathBuf>,
) -> ExportPlan {
    let readahead_usize = usize::try_from(readahead).unwrap_or(usize::MAX);
    let mut plan = ExportPlan {
        http: None,
        webdav: None,
        smb: None,
        ninep: None,
        sftp: None,
        sftp_stdio: None,
    };
    if args.http {
        let bind = parse_bind_or_exit(&args.http_bind, ratarmount_http::parse_http_bind);
        warn_export_non_loopback("HTTP", bind);
        plan.http = Some(ratarmount_http::HttpOptions {
            bind,
            stop: None,
            overlay: overlay.clone(),
            readahead_bytes: readahead,
            webdav: false,
            index_sidecar,
        });
    }
    if args.webdav {
        let bind = parse_bind_or_exit(&args.webdav_bind, ratarmount_http::parse_webdav_bind);
        warn_export_non_loopback("WebDAV", bind);
        plan.webdav = Some(ratarmount_http::WebDavOptions {
            bind,
            stop: None,
            overlay: overlay.clone(),
            readahead_bytes: readahead,
        });
    }
    if args.smb {
        let bind = parse_bind_or_exit(&args.smb_bind, ratarmount_smb::parse_smb_bind);
        warn_export_non_loopback("SMB", bind);
        let (username, password) = ratarmount_smb::smb_credentials_from_env();
        plan.smb = Some(ratarmount_smb::SmbOptions {
            bind,
            stop: None,
            overlay: overlay.clone(),
            readahead_bytes: readahead_usize,
            reader_slots: ratarmount_smb::DEFAULT_READER_SLOTS,
            share_name: args.smb_share.clone(),
            username,
            password,
        });
    }
    if args.ninep {
        let bind = parse_bind_or_exit(&args.ninep_bind, ratarmount_9p::parse_ninep_bind);
        warn_export_non_loopback("9P", bind);
        plan.ninep = Some(ratarmount_9p::NinepOptions {
            attribute_mapping: ratarmount_core::AttributeMapping::parse(&args.fuse)
                .expect("validated attribute mapping"),
            bind,
            stop: None,
            overlay: overlay.clone(),
            readahead_bytes: readahead_usize,
            reader_slots: ratarmount_9p::DEFAULT_READER_SLOTS,
        });
    }
    if args.sftp {
        let bind = parse_bind_or_exit(&args.sftp_bind, ratarmount_sftp::parse_sftp_bind);
        warn_export_non_loopback("SFTP", bind);
        plan.sftp = Some(ratarmount_sftp::SftpOptions {
            attribute_mapping: ratarmount_core::AttributeMapping::parse(&args.fuse)
                .expect("validated attribute mapping"),
            bind,
            stop: None,
            overlay,
            readahead_bytes: readahead_usize,
            reader_slots: ratarmount_sftp::DEFAULT_READER_SLOTS,
            authorized_keys: args.sftp_authorized_keys.clone(),
            host_key: None,
        });
    } else if args.sftp_subsystem {
        // bind / authorized_keys / host_key are ignored by serve_stdio.
        plan.sftp_stdio = Some(ratarmount_sftp::SftpOptions {
            attribute_mapping: ratarmount_core::AttributeMapping::parse(&args.fuse)
                .expect("validated attribute mapping"),
            bind: ratarmount_sftp::DEFAULT_SFTP_BIND,
            stop: None,
            overlay,
            readahead_bytes: readahead_usize,
            reader_slots: ratarmount_sftp::DEFAULT_READER_SLOTS,
            authorized_keys: None,
            host_key: None,
        });
    }
    plan
}

struct ExportHandles {
    nfs: Option<ratarmount_nfs::NfsServerHandle>,
    others: Vec<ratarmount_http::ExportServerHandle>,
}

fn attach_export_stops(
    nfs_opts: &mut Option<ratarmount_nfs::NfsOptions>,
    plan: &mut ExportPlan,
    nfs_stop: &ratarmount_nfs::NfsStop,
    export_stop: &ratarmount_http::ExportStop,
) {
    if let Some(opts) = nfs_opts {
        opts.stop = Some(nfs_stop.clone());
    }
    if let Some(opts) = &mut plan.http {
        opts.stop = Some(export_stop.clone());
    }
    if let Some(opts) = &mut plan.webdav {
        opts.stop = Some(export_stop.clone());
    }
    if let Some(opts) = &mut plan.smb {
        opts.stop = Some(export_stop.clone());
    }
    if let Some(opts) = &mut plan.ninep {
        opts.stop = Some(export_stop.clone());
    }
    if let Some(opts) = &mut plan.sftp {
        opts.stop = Some(export_stop.clone());
    }
}

fn spawn_sftp_stdio_thread(
    source: Arc<dyn MountSource>,
    opts: ratarmount_sftp::SftpOptions,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        if let Err(e) = ratarmount_sftp::serve_stdio(source, opts) {
            eprintln!("error starting SFTP stdio server: {e}");
        }
    })
}

/// Stop flags for listeners that have already bound. Clones of the flags the
/// server threads poll, so [`abandon_started_exports`] can join them.
struct StartedExportStops {
    nfs: Option<ratarmount_nfs::NfsStop>,
    export: Option<ratarmount_http::ExportStop>,
}

/// Stop and join listeners that already bound so they drop their `Arc`s
/// before [`WriteOverlay`] does. A listener with no stop flag is detached;
/// the caller still exits, which ends that thread.
fn abandon_started_exports(handles: ExportHandles, stops: &StartedExportStops) {
    let can_stop_nfs = handles.nfs.is_none() || stops.nfs.is_some();
    let can_stop_export = handles.others.is_empty() || stops.export.is_some();
    if let Some(stop) = &stops.nfs {
        stop.request_stop();
    }
    if let Some(stop) = &stops.export {
        stop.request_stop();
    }
    if can_stop_nfs && can_stop_export {
        join_export_handles(handles);
    }
}

fn remember_export_stop(stops: &mut StartedExportStops, stop: Option<ratarmount_http::ExportStop>) {
    if stops.export.is_none() && stop.is_some() {
        stops.export = stop;
    }
}

/// Same text as the historical `eprintln` before `process::exit(1)`.
fn fail_export_bind(
    handles: ExportHandles,
    stops: &StartedExportStops,
    proto: &str,
    err: impl std::fmt::Display,
) -> String {
    abandon_started_exports(handles, stops);
    format!("error starting {proto} server: {err}")
}

/// Bind every requested export.
///
/// On failure, listeners that already bound are stopped and joined, and the
/// error string is the `error starting … server:` line. The caller prints it
/// and exits through [`exit_on_export_bind_failure`] so the overlay drops.
/// `std::process::exit` here would skip that drop: the interval thread is
/// already running and holds an [`Arc`].
fn spawn_export_threads(
    source: &Arc<dyn MountSource>,
    nfs_opts: Option<ratarmount_nfs::NfsOptions>,
    plan: ExportPlan,
) -> Result<ExportHandles, String> {
    let mut handles = ExportHandles {
        nfs: None,
        others: Vec::new(),
    };
    let mut stops = StartedExportStops {
        nfs: None,
        export: None,
    };
    if let Some(opts) = nfs_opts {
        let stop = opts.stop.clone();
        let ready = opts.clone();
        match spawn_nfs_for_opts(Arc::clone(source), opts) {
            Ok(h) => {
                eprintln!("{}", nfs_ready_line(&ready, h.port));
                stops.nfs = stop;
                handles.nfs = Some(h);
            }
            Err(e) => return Err(fail_export_bind(handles, &stops, "NFS", e)),
        }
    }
    if let Some(opts) = plan.http {
        let bind = opts.bind;
        let stop = opts.stop.clone();
        match ratarmount_http::spawn_http_thread(Arc::clone(source), opts) {
            Ok(h) => {
                eprintln!(
                    "HTTP on {}:{}. curl: curl -r 0-1023 http://{}:{}/member",
                    bind.ip(),
                    h.port,
                    bind.ip(),
                    h.port
                );
                remember_export_stop(&mut stops, stop);
                handles.others.push(h);
            }
            Err(e) => return Err(fail_export_bind(handles, &stops, "HTTP", e)),
        }
    }
    if let Some(opts) = plan.webdav {
        let bind = opts.bind;
        let stop = opts.stop.clone();
        match ratarmount_http::spawn_webdav_thread(Arc::clone(source), opts) {
            Ok(h) => {
                eprintln!(
                    "WebDAV on {}:{}. PROPFIND Depth 0/1; GET/HEAD Range",
                    bind.ip(),
                    h.port
                );
                remember_export_stop(&mut stops, stop);
                handles.others.push(h);
            }
            Err(e) => return Err(fail_export_bind(handles, &stops, "WebDAV", e)),
        }
    }
    if let Some(opts) = plan.smb {
        let bind = opts.bind;
        let share = opts.share_name.clone();
        let stop = opts.stop.clone();
        match ratarmount_smb::spawn_smb_thread(Arc::clone(source), opts) {
            Ok(h) => {
                eprintln!(
                    "SMB2 on {}:{}. smbclient //{}/{share} -p {} -N",
                    bind.ip(),
                    h.port,
                    bind.ip(),
                    h.port
                );
                remember_export_stop(&mut stops, stop);
                handles.others.push(h);
            }
            Err(e) => return Err(fail_export_bind(handles, &stops, "SMB", e)),
        }
    }
    if let Some(opts) = plan.ninep {
        let bind = opts.bind;
        let stop = opts.stop.clone();
        match ratarmount_9p::spawn_ninep_thread(Arc::clone(source), opts) {
            Ok(h) => {
                eprintln!(
                    "9P2000.L on {}:{}. mount -t 9p -o trans=tcp,port={},version=9p2000.L {} <dir>",
                    bind.ip(),
                    h.port,
                    h.port,
                    bind.ip()
                );
                remember_export_stop(&mut stops, stop);
                handles.others.push(h);
            }
            Err(e) => return Err(fail_export_bind(handles, &stops, "9P", e)),
        }
    }
    if let Some(opts) = plan.sftp {
        let bind = opts.bind;
        let stop = opts.stop.clone();
        match ratarmount_sftp::spawn_sftp_thread(Arc::clone(source), opts) {
            Ok(h) => {
                eprintln!(
                    "SFTP on {}:{}. sftp -P {} -o StrictHostKeyChecking=no {}",
                    bind.ip(),
                    h.port,
                    h.port,
                    bind.ip()
                );
                remember_export_stop(&mut stops, stop);
                handles.others.push(h);
            }
            Err(e) => return Err(fail_export_bind(handles, &stops, "SFTP", e)),
        }
    }
    Ok(handles)
}

/// Print `message` (unchanged bind-failure text), drop the overlay, then exit.
///
/// `exit` is [`exit_with_code`] in production. Tests pass a hook that panics
/// so the process stays up and the drop can be observed. The exit code is 1.
/// The hook must not return; `!` is not stable in `FnOnce` bounds.
fn exit_on_export_bind_failure(
    message: &str,
    overlay: Option<Arc<WriteOverlay>>,
    source: Option<Arc<dyn MountSource>>,
    interval: Option<thread::JoinHandle<()>>,
    exit: impl FnOnce(i32, &str),
) -> ! {
    eprintln!("{message}");
    finish_overlay_serve(overlay, source, interval, |_| {});
    exit(1, message);
    unreachable!("bind-failure exit hook returned");
}

fn exit_with_code(code: i32, _message: &str) {
    std::process::exit(code);
}

/// Exports that bound, plus the overlay state the caller still owns.
struct BoundExports {
    handles: ExportHandles,
    source: Arc<dyn MountSource>,
    overlay: Option<Arc<WriteOverlay>>,
    interval: Option<thread::JoinHandle<()>>,
}

/// Bind exports. A bind failure drops the overlay (final pending-row replay)
/// and exits 1 with the same message as a direct `process::exit`.
fn spawn_export_threads_or_exit(
    source: Arc<dyn MountSource>,
    nfs_opts: Option<ratarmount_nfs::NfsOptions>,
    plan: ExportPlan,
    overlay: Option<Arc<WriteOverlay>>,
    interval: Option<thread::JoinHandle<()>>,
    exit: impl FnOnce(i32, &str),
) -> BoundExports {
    match spawn_export_threads(&source, nfs_opts, plan) {
        Ok(handles) => BoundExports {
            handles,
            source,
            overlay,
            interval,
        },
        Err(message) => {
            exit_on_export_bind_failure(&message, overlay, Some(source), interval, exit);
        }
    }
}

/// `false` when a bind fails. The caller drops the overlay before exiting.
/// [`std::process::exit`] here would skip that drop.
fn probe_export_binds(nfs_opts: &Option<ratarmount_nfs::NfsOptions>, plan: &ExportPlan) -> bool {
    let mut addrs = Vec::new();
    if let Some(o) = nfs_opts {
        addrs.push(("NFS", o.bind));
    }
    if let Some(o) = &plan.http {
        addrs.push(("HTTP", o.bind));
    }
    if let Some(o) = &plan.webdav {
        addrs.push(("WebDAV", o.bind));
    }
    if let Some(o) = &plan.smb {
        addrs.push(("SMB", o.bind));
    }
    if let Some(o) = &plan.ninep {
        addrs.push(("9P", o.bind));
    }
    if let Some(o) = &plan.sftp {
        addrs.push(("SFTP", o.bind));
    }
    for (name, bind) in addrs {
        if let Err(e) = std::net::TcpListener::bind(bind) {
            eprintln!("error: cannot bind {name} on {bind}: {e}");
            return false;
        }
    }
    true
}

fn join_export_handles(handles: ExportHandles) {
    if let Some(h) = handles.nfs {
        let _ = h.join();
    }
    for h in handles.others {
        let _ = h.join();
    }
}

/// Spawn the interval thread only in the process that serves the mount.
///
/// A thread started before `fork` is not copied into the child, but its
/// [`Arc`] strong count is. The child then never drops [`WriteOverlay`], and
/// the parent exits and kills the thread. Returns the handle so unmount can
/// join it before the overlay drops.
fn spawn_interval_if(
    overlay: &Option<Arc<WriteOverlay>>,
    live_archive: &Option<PathBuf>,
    commit_interval: Option<Duration>,
    stop: Option<ratarmount_nfs::NfsStop>,
    open_opts: &OpenOptions,
) -> Option<thread::JoinHandle<()>> {
    if !open_opts.read_only_index {
        base_digest::spawn_if_pending(overlay);
    }
    match (overlay, live_archive, commit_interval) {
        (Some(ov), Some(archive), Some(dur)) => Some(overlay_commit::spawn_interval_commits(
            Arc::clone(ov),
            archive.clone(),
            dur,
            stop,
            open_opts.clone(),
        )),
        _ => None,
    }
}

/// Replay queued overlay rows, then drop the overlay, before `process::exit`
/// or a foreground return.
///
/// `std::process::exit` skips destructors, so [`WriteOverlay::drop`] would
/// not run and a failed `files` update would stay unsaved. The interval
/// thread is joined first: it holds an [`Arc`] and only returns after
/// [`overlay_commit::request_shutdown`]. `commit` (on-exit persist) runs
/// while this process still holds the overlay.
///
/// The forked parent must not call this. The child owns the SQLite
/// connection; dropping here would replay into that connection. The parent's
/// `process::exit` skips Drop on purpose.
fn finish_overlay_serve(
    overlay: Option<Arc<WriteOverlay>>,
    source: Option<Arc<dyn MountSource>>,
    interval: Option<thread::JoinHandle<()>>,
    commit: impl FnOnce(Option<&WriteOverlay>),
) {
    overlay_commit::request_shutdown();
    base_digest::join();
    if let Some(handle) = interval {
        let _ = handle.join();
    }
    commit(overlay.as_deref());
    drop(source);
    drop(overlay);
    cleanup_temp_overlay();
    log::debug!(
        "{}",
        ratarmount_core::budget::MemoryBudget::global()
            .status_text()
            .replace('\n', "; ")
    );
}

#[allow(clippy::too_many_arguments)]
fn run_exports(
    source: Arc<dyn MountSource>,
    fuse_mp: Option<PathBuf>,
    writable: bool,
    overlay_arc: Option<Arc<WriteOverlay>>,
    fuse_opts: &str,
    passthrough: PassthroughOptions,
    activity: ratarmount_fuse::oplog::MountActivity,
    readahead: u64,
    mut nfs_opts: Option<ratarmount_nfs::NfsOptions>,
    mut plan: ExportPlan,
    foreground: bool,
    has_log_file: bool,
    live_archive: Option<PathBuf>,
    commit_on_exit: bool,
    commit_interval: Option<Duration>,
    open_opts: OpenOptions,
    control: Option<ControlListener>,
) {
    overlay_commit::install_term_signal_flag();
    let nfs_stop = ratarmount_nfs::NfsStop::new();
    let export_stop = ratarmount_http::ExportStop::new();
    let mut callbacks: Vec<Arc<dyn Fn() + Send + Sync>> = Vec::new();
    {
        let s = nfs_stop.clone();
        callbacks.push(Arc::new(move || s.request_stop()));
    }
    {
        let s = export_stop.clone();
        callbacks.push(Arc::new(move || s.request_stop()));
    }
    overlay_commit::spawn_signal_export_stops(callbacks);
    attach_export_stops(&mut nfs_opts, &mut plan, &nfs_stop, &export_stop);
    let sftp_stdio = plan.sftp_stdio.take();
    let commit_exit = |ov: Option<&WriteOverlay>| {
        overlay_commit::maybe_commit_on_exit(
            ov,
            live_archive.as_deref(),
            commit_on_exit,
            &open_opts,
        );
    };

    match fuse_mp {
        None => {
            let interval = spawn_interval_if(
                &overlay_arc,
                &live_archive,
                commit_interval,
                Some(nfs_stop.clone()),
                &open_opts,
            );
            let BoundExports {
                handles,
                source,
                overlay: overlay_arc,
                interval,
            } = spawn_export_threads_or_exit(
                source,
                nfs_opts,
                plan,
                overlay_arc,
                interval,
                exit_with_code,
            );
            if let Some(opts) = sftp_stdio {
                let serve_err = ratarmount_sftp::serve_stdio(Arc::clone(&source), opts);
                nfs_stop.request_stop();
                export_stop.request_stop();
                join_export_handles(handles);
                finish_overlay_serve(overlay_arc, Some(source), interval, commit_exit);
                if let Err(e) = serve_err {
                    eprintln!("error starting SFTP stdio server: {e}");
                    std::process::exit(1);
                }
                return;
            }
            while !overlay_commit::term_requested()
                && !nfs_stop.is_stopped()
                && !export_stop.is_stopped()
            {
                thread::sleep(Duration::from_millis(50));
            }
            nfs_stop.request_stop();
            export_stop.request_stop();
            join_export_handles(handles);
            finish_overlay_serve(overlay_arc, Some(source), interval, commit_exit);
        }
        Some(mp) => {
            if foreground {
                overlay_commit::spawn_signal_fuse_unmount(mp.clone());
                let control = control.map(ControlListener::serve);
                let interval = spawn_interval_if(
                    &overlay_arc,
                    &live_archive,
                    commit_interval,
                    Some(nfs_stop.clone()),
                    &open_opts,
                );
                eprintln!("FUSE at {}", mp.display());
                let BoundExports {
                    handles,
                    source,
                    overlay: overlay_arc,
                    interval,
                } = spawn_export_threads_or_exit(
                    source,
                    nfs_opts,
                    plan,
                    overlay_arc,
                    interval,
                    exit_with_code,
                );
                // Joined after unmount. `serve_stdio` runs until stdin closes,
                // so this FUSE unmount waits for that client before the overlay
                // drops. Started only after binds succeed: a bind failure exits
                // through `finish_overlay_serve`, and this thread would hold an
                // `Arc` until stdin closed. Dropping the handle would detach it
                // and that `Arc` would outlive the overlay.
                let sftp_thread =
                    sftp_stdio.map(|opts| spawn_sftp_stdio_thread(Arc::clone(&source), opts));
                let mount_err = mount_blocking(
                    Arc::clone(&source),
                    &mp,
                    true,
                    writable,
                    overlay_arc.clone(),
                    fuse_opts,
                    readahead,
                    passthrough,
                    open_opts.direct_io,
                    activity,
                );
                wait_control_reply(&control);
                nfs_stop.request_stop();
                export_stop.request_stop();
                join_export_handles(handles);
                if let Some(handle) = sftp_thread {
                    let _ = handle.join();
                }
                finish_overlay_serve(overlay_arc, Some(source), interval, commit_exit);
                if let Err(e) = mount_err {
                    eprintln!("error mounting at {}: {e}", mp.display());
                    std::process::exit(1);
                }
                return;
            }

            drop(sftp_stdio);
            if !probe_export_binds(&nfs_opts, &plan) {
                finish_overlay_serve(overlay_arc, Some(source), None, |_| {});
                std::process::exit(1);
            }
            match unsafe { fork() } {
                Ok(ForkResult::Parent { child }) => {
                    relinquish_temp_overlay();
                    // The child owns the overlay database. Dropping it here
                    // would replay pending rows into the child's connection.
                    // process::exit skips Drop on purpose. The interval thread
                    // starts in the child, not in this process.
                    if !wait_until_mounted(&mp, Duration::from_secs(30)) {
                        eprintln!(
                            "error: timed out waiting for mount at {} (child pid {child})",
                            mp.display()
                        );
                        let _ = unmount(&mp);
                        std::process::exit(1);
                    }
                    std::process::exit(0);
                }
                Ok(ForkResult::Child) => {
                    let _ = setsid();
                    if !has_log_file {
                        let _ = redirect_stdio_to_null();
                    }
                    overlay_commit::spawn_signal_fuse_unmount(mp.clone());
                    let control = control.map(ControlListener::serve);
                    let interval = spawn_interval_if(
                        &overlay_arc,
                        &live_archive,
                        commit_interval,
                        Some(nfs_stop.clone()),
                        &open_opts,
                    );
                    let BoundExports {
                        handles,
                        source,
                        overlay: overlay_arc,
                        interval,
                    } = spawn_export_threads_or_exit(
                        source,
                        nfs_opts,
                        plan,
                        overlay_arc,
                        interval,
                        exit_with_code,
                    );
                    let mount_err = mount_blocking(
                        source,
                        &mp,
                        true,
                        writable,
                        overlay_arc.clone(),
                        fuse_opts,
                        readahead,
                        passthrough,
                        open_opts.direct_io,
                        activity,
                    );
                    wait_control_reply(&control);
                    nfs_stop.request_stop();
                    export_stop.request_stop();
                    join_export_handles(handles);
                    finish_overlay_serve(overlay_arc, None, interval, commit_exit);
                    if let Err(e) = mount_err {
                        #[expect(
                            clippy::disallowed_methods,
                            reason = r###"internal-read:v1 {"id":"IR-B0024-M01","item":"ratarmount::run_exports","disposition":"output-owner","mode_policy":"unchanged-from-e6ca64e","category":"output-owner","reason":"Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"unchanged-from-e6ca64e","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###
                        )]
                        let _ = std::fs::write(
                            "/tmp/ratarmount-rs-fuse-error.log",
                            format!("mount error: {e}\n"),
                        );
                        std::process::exit(1);
                    }
                    std::process::exit(0);
                }
                Err(e) => {
                    eprintln!("error: fork failed: {e}");
                    finish_overlay_serve(overlay_arc, Some(source), None, |_| {});
                    std::process::exit(1);
                }
            }
        }
    }
}

fn nfs_ready_line(opts: &ratarmount_nfs::NfsOptions, port: u16) -> String {
    let access = if opts.overlay.is_some() {
        "rw overlay"
    } else {
        "ro"
    };
    let ip = opts.bind.ip();
    match opts.vers {
        ratarmount_nfs::NfsVers::V3 => format!(
            "NFSv3 ({access}) on {ip}:{port}. Client: mount -t nfs -o vers=3,tcp,nolock,port={port},mountport={port} {ip}:/ <dir>"
        ),
        #[cfg(feature = "nfsv4")]
        ratarmount_nfs::NfsVers::V4 => format!(
            "NFSv4.1 ({access}) on {ip}:{port}. Client: mount -t nfs -o vers=4.1,tcp,port={port},sec=sys {ip}:/ <dir>"
        ),
    }
}

fn serve_nfs_blocking(
    source: Arc<dyn MountSource>,
    opts: ratarmount_nfs::NfsOptions,
) -> std::io::Result<()> {
    match opts.vers {
        ratarmount_nfs::NfsVers::V3 => ratarmount_nfs::serve_blocking(source, opts),
        #[cfg(feature = "nfsv4")]
        ratarmount_nfs::NfsVers::V4 => ratarmount_nfs::serve_v4_blocking(source, opts),
    }
}

fn spawn_nfs_for_opts(
    source: Arc<dyn MountSource>,
    opts: ratarmount_nfs::NfsOptions,
) -> std::io::Result<ratarmount_nfs::NfsServerHandle> {
    match opts.vers {
        ratarmount_nfs::NfsVers::V3 => ratarmount_nfs::spawn_nfs_thread(source, opts),
        #[cfg(feature = "nfsv4")]
        ratarmount_nfs::NfsVers::V4 => ratarmount_nfs::spawn_nfs4_thread(source, opts),
    }
}

fn run_nfs_only(
    source: Arc<dyn MountSource>,
    mut opts: ratarmount_nfs::NfsOptions,
    overlay: Option<Arc<WriteOverlay>>,
    live_archive: Option<PathBuf>,
    commit_on_exit: bool,
    commit_interval: Option<Duration>,
    open_opts: OpenOptions,
) {
    let stop = ratarmount_nfs::NfsStop::new();
    opts.stop = Some(stop.clone());
    overlay_commit::spawn_signal_nfs_stop(stop.clone());
    let interval = spawn_interval_if(
        &overlay,
        &live_archive,
        commit_interval,
        Some(stop),
        &open_opts,
    );
    eprintln!("{}", nfs_ready_line(&opts, opts.bind.port()));
    let serve_err = serve_nfs_blocking(source, opts);
    finish_overlay_serve(overlay, None, interval, |ov| {
        overlay_commit::maybe_commit_on_exit(
            ov,
            live_archive.as_deref(),
            commit_on_exit,
            &open_opts,
        );
    });
    if let Err(e) = serve_err {
        eprintln!("error starting NFS server: {e}");
        std::process::exit(1);
    }
}

#[allow(clippy::too_many_arguments)]
fn run_fuse_and_nfs(
    source: Arc<dyn MountSource>,
    mp: PathBuf,
    writable: bool,
    overlay_arc: Option<Arc<WriteOverlay>>,
    fuse_opts: &str,
    passthrough: PassthroughOptions,
    activity: ratarmount_fuse::oplog::MountActivity,
    readahead: u64,
    mut nfs_opts: ratarmount_nfs::NfsOptions,
    foreground: bool,
    has_log_file: bool,
    live_archive: Option<PathBuf>,
    commit_on_exit: bool,
    commit_interval: Option<Duration>,
    open_opts: OpenOptions,
    control: Option<ControlListener>,
) {
    let commit_exit = |ov: Option<&WriteOverlay>| {
        overlay_commit::maybe_commit_on_exit(
            ov,
            live_archive.as_deref(),
            commit_on_exit,
            &open_opts,
        );
    };
    if foreground {
        let stop = ratarmount_nfs::NfsStop::new();
        nfs_opts.stop = Some(stop.clone());
        overlay_commit::spawn_signal_nfs_stop(stop.clone());
        overlay_commit::spawn_signal_fuse_unmount(mp.clone());
        let control = control.map(ControlListener::serve);
        let interval = spawn_interval_if(
            &overlay_arc,
            &live_archive,
            commit_interval,
            Some(stop.clone()),
            &open_opts,
        );
        let ready = nfs_opts.clone();
        let handle = match spawn_nfs_for_opts(Arc::clone(&source), nfs_opts) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("error starting NFS server: {e}");
                finish_overlay_serve(overlay_arc, Some(source), interval, |_| {});
                std::process::exit(1);
            }
        };
        eprintln!("{}", nfs_ready_line(&ready, handle.port));
        eprintln!("FUSE at {}", mp.display());
        let mount_err = mount_blocking(
            Arc::clone(&source),
            &mp,
            true,
            writable,
            overlay_arc.clone(),
            fuse_opts,
            readahead,
            passthrough,
            open_opts.direct_io,
            activity,
        );
        wait_control_reply(&control);
        stop.request_stop();
        let _ = handle.join();
        finish_overlay_serve(overlay_arc, Some(source), interval, commit_exit);
        if let Err(e) = mount_err {
            eprintln!("error mounting at {}: {e}", mp.display());
            std::process::exit(1);
        }
        return;
    }

    // Daemonize: probe NFS bind in the parent so a dead port is not silent.
    // No client has been served. Drop the overlay before exit anyway.
    if let Err(e) = std::net::TcpListener::bind(nfs_opts.bind) {
        eprintln!("error: cannot bind NFS on {}: {e}", nfs_opts.bind);
        finish_overlay_serve(overlay_arc, Some(source), None, |_| {});
        std::process::exit(1);
    }
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            relinquish_temp_overlay();
            // The child owns the overlay database. Dropping it here would
            // replay pending rows into the child's connection. process::exit
            // skips Drop on purpose. The interval thread starts in the child.
            if !wait_until_mounted(&mp, Duration::from_secs(30)) {
                eprintln!(
                    "error: timed out waiting for mount at {} (child pid {child})",
                    mp.display()
                );
                let _ = unmount(&mp);
                std::process::exit(1);
            }
            std::process::exit(0);
        }
        Ok(ForkResult::Child) => {
            let _ = setsid();
            if !has_log_file {
                let _ = redirect_stdio_to_null();
            }
            let stop = ratarmount_nfs::NfsStop::new();
            nfs_opts.stop = Some(stop.clone());
            overlay_commit::spawn_signal_nfs_stop(stop.clone());
            overlay_commit::spawn_signal_fuse_unmount(mp.clone());
            let control = control.map(ControlListener::serve);
            let interval = spawn_interval_if(
                &overlay_arc,
                &live_archive,
                commit_interval,
                Some(stop.clone()),
                &open_opts,
            );
            let handle = match spawn_nfs_for_opts(Arc::clone(&source), nfs_opts) {
                Ok(h) => h,
                Err(e) => {
                    #[expect(
                        clippy::disallowed_methods,
                        reason = r###"internal-read:v1 {"id":"IR-B0025-M01","item":"ratarmount::run_fuse_and_nfs","disposition":"output-owner","mode_policy":"unchanged-from-e6ca64e","category":"output-owner","reason":"Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"unchanged-from-e6ca64e","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###
                    )]
                    let _ = std::fs::write(
                        "/tmp/ratarmount-rs-nfs-error.log",
                        format!("NFS bind error: {e}\n"),
                    );
                    finish_overlay_serve(overlay_arc, Some(source), interval, |_| {});
                    std::process::exit(1);
                }
            };
            let mount_err = mount_blocking(
                source,
                &mp,
                true,
                writable,
                overlay_arc.clone(),
                fuse_opts,
                readahead,
                passthrough,
                open_opts.direct_io,
                activity,
            );
            wait_control_reply(&control);
            stop.request_stop();
            let _ = handle.join();
            finish_overlay_serve(overlay_arc, None, interval, commit_exit);
            if let Err(e) = mount_err {
                #[expect(
                    clippy::disallowed_methods,
                    reason = r###"internal-read:v1 {"id":"IR-B0026-M01","item":"ratarmount::run_fuse_and_nfs","disposition":"output-owner","mode_policy":"unchanged-from-e6ca64e","category":"output-owner","reason":"Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"unchanged-from-e6ca64e","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###
                )]
                let _ = std::fs::write(
                    "/tmp/ratarmount-rs-fuse-error.log",
                    format!("mount error: {e}\n"),
                );
                std::process::exit(1);
            }
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("error: fork failed: {e}");
            finish_overlay_serve(overlay_arc, Some(source), None, |_| {});
            std::process::exit(1);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_fuse_only(
    source: Arc<dyn MountSource>,
    mp: PathBuf,
    writable: bool,
    overlay_arc: Option<Arc<WriteOverlay>>,
    fuse_opts: &str,
    passthrough: PassthroughOptions,
    activity: ratarmount_fuse::oplog::MountActivity,
    readahead: u64,
    foreground: bool,
    has_log_file: bool,
    live_archive: Option<PathBuf>,
    commit_on_exit: bool,
    commit_interval: Option<Duration>,
    open_opts: OpenOptions,
    control: Option<ControlListener>,
) {
    let commit_exit = |ov: Option<&WriteOverlay>| {
        overlay_commit::maybe_commit_on_exit(
            ov,
            live_archive.as_deref(),
            commit_on_exit,
            &open_opts,
        );
    };
    if foreground {
        overlay_commit::spawn_signal_fuse_unmount(mp.clone());
        let control = control.map(ControlListener::serve);
        // The interval thread holds an Arc. Join it before the overlay drops,
        // or process exit kills it and the final replay never runs.
        let interval = spawn_interval_if(
            &overlay_arc,
            &live_archive,
            commit_interval,
            None,
            &open_opts,
        );
        let mount_err = mount_blocking(
            source,
            &mp,
            true,
            writable,
            overlay_arc.clone(),
            fuse_opts,
            readahead,
            passthrough,
            open_opts.direct_io,
            activity,
        );
        wait_control_reply(&control);
        finish_overlay_serve(overlay_arc, None, interval, commit_exit);
        if let Err(e) = mount_err {
            eprintln!("error mounting at {}: {e}", mp.display());
            std::process::exit(1);
        }
        return;
    }

    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            relinquish_temp_overlay();
            // The child owns the overlay database. Dropping it here would
            // replay pending rows into the child's connection. process::exit
            // skips Drop on purpose. The interval thread starts in the child.
            if !wait_until_mounted(&mp, Duration::from_secs(30)) {
                eprintln!(
                    "error: timed out waiting for mount at {} (child pid {child})",
                    mp.display()
                );
                let _ = unmount(&mp);
                std::process::exit(1);
            }
            std::process::exit(0);
        }
        Ok(ForkResult::Child) => {
            let _ = setsid();
            if !has_log_file {
                let _ = redirect_stdio_to_null();
            }
            overlay_commit::spawn_signal_fuse_unmount(mp.clone());
            let control = control.map(ControlListener::serve);
            let interval = spawn_interval_if(
                &overlay_arc,
                &live_archive,
                commit_interval,
                None,
                &open_opts,
            );
            let mount_err = mount_blocking(
                source,
                &mp,
                true,
                writable,
                overlay_arc.clone(),
                fuse_opts,
                readahead,
                passthrough,
                open_opts.direct_io,
                activity,
            );
            wait_control_reply(&control);
            finish_overlay_serve(overlay_arc, None, interval, commit_exit);
            if let Err(e) = mount_err {
                #[expect(
                    clippy::disallowed_methods,
                    reason = r###"internal-read:v1 {"id":"IR-B0027-M01","item":"ratarmount::run_fuse_only","disposition":"output-owner","mode_policy":"unchanged-from-e6ca64e","category":"output-owner","reason":"Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"unchanged-from-e6ca64e","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###
                )]
                let _ = std::fs::write(
                    "/tmp/ratarmount-rs-fuse-error.log",
                    format!("mount error: {e}\n"),
                );
                std::process::exit(1);
            }
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("error: fork failed: {e}");
            finish_overlay_serve(overlay_arc, Some(source), None, |_| {});
            std::process::exit(1);
        }
    }
}

/// Resolve log color style from CLI flags and environment.
///
/// Priority: `--no-color` → never; `--color` → always; otherwise auto while
/// honoring `NO_COLOR` (disable), `CLICOLOR=0` (disable), and `CLICOLOR_FORCE`
/// (force on when set and not `"0"`).
fn resolve_color_style(force_color: bool, force_no_color: bool) -> env_logger::WriteStyle {
    if force_no_color {
        return env_logger::WriteStyle::Never;
    }
    if force_color {
        return env_logger::WriteStyle::Always;
    }
    // Auto: respect NO_COLOR (https://no-color.org/) and CLICOLOR / CLICOLOR_FORCE.
    if std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty()) {
        return env_logger::WriteStyle::Never;
    }
    if std::env::var("CLICOLOR")
        .ok()
        .as_deref()
        .is_some_and(|v| v == "0")
    {
        return env_logger::WriteStyle::Never;
    }
    if std::env::var("CLICOLOR_FORCE")
        .ok()
        .as_deref()
        .is_some_and(|v| v != "0")
    {
        return env_logger::WriteStyle::Always;
    }
    env_logger::WriteStyle::Auto
}

fn init_logger(debug: u8, log_file: Option<&Path>, write_style: env_logger::WriteStyle) {
    let rust_log = std::env::var("RUST_LOG").ok();
    let mut builder = logger_filter_builder(debug, rust_log.as_deref());
    builder.write_style(write_style);
    if let Some(path) = log_file {
        {
            let __inventory_condition_172220 = {
                #[expect(
                    clippy::disallowed_types,
                    reason = r###"internal-read:v1 {"id":"IR-B0028-T01","item":"ratarmount::init_logger","disposition":"support","category":"builder-type-support","reason":"Builder type support: logger output or standard descriptor setup","mode_policy":"unchanged-from-e6ca64e","creation":{"policy":"none","basis":"This is a type/import reference; it acquires no file or directory."}}"###
                )]
                #[expect(
                    clippy::disallowed_methods,
                    reason = r###"internal-read:v1 {"id":"IR-B0028-M01","item":"ratarmount::init_logger","disposition":"support","category":"builder-setup","reason":"Prepare the builder for this item's separately reviewed open/create leaf.","mode_policy":"unchanged-from-e6ca64e","creation":{"policy":"none","basis":"Builder construction/setup only; the separate open/create leaf owns pathname acquisition and permissions."},"supports_disposition":"out-of-family","baseline_reason":"logger output or standard descriptor setup"}"###
                )]
                let mut __inventory_value_0 = std::fs::OpenOptions::new();
                #[expect(
                    clippy::disallowed_methods,
                    reason = r###"internal-read:v1 {"id":"IR-E0115-M01","item":"ratarmount::init_logger","disposition":"output-owner","category":"diagnostic-log","reason":"Configure append-or-create logging for the explicit CLI log file.","creation":{"policy":"append-or-create","basis":"The log file is diagnostic output, preserves existing data, and retains default/umask file permissions."}}"###
                )]
                let __inventory_value_1 = __inventory_value_0.create(true);
                #[expect(
                    clippy::disallowed_methods,
                    reason = r###"internal-read:v1 {"id":"IR-B0028-M02","item":"ratarmount::init_logger","disposition":"out-of-family","category":"runtime-resource-or-descriptor-handoff","reason":"logger output or standard descriptor setup","mode_policy":"unchanged-from-e6ca64e","creation":{"policy":"unchanged-from-e6ca64e","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###
                )]
                let __inventory_value_2 = __inventory_value_1.append(true).open(path);
                __inventory_value_2
            };
            match __inventory_condition_172220 {
                Ok(file) => {
                    let file = std::sync::Mutex::new(file);
                    builder.target(env_logger::Target::Pipe(Box::new(WriteAdapter(file))));
                }
                Err(e) => {
                    eprintln!("warning: could not open log file {}: {e}", path.display());
                }
            }
        }
    }
    let _ = builder.try_init();
}

/// Log filters: `-d` sets the global baseline, then a non-empty `RUST_LOG`
/// (global and module directives) overrides it (#138).
fn logger_filter_builder(debug: u8, rust_log: Option<&str>) -> env_logger::Builder {
    let level = match debug {
        0 => log::LevelFilter::Error,
        1 => log::LevelFilter::Warn,
        2 => log::LevelFilter::Info,
        _ => log::LevelFilter::Debug,
    };
    let mut builder = env_logger::Builder::new();
    builder.filter_level(level);
    if let Some(spec) = rust_log.filter(|s| !s.is_empty()) {
        builder.parse_filters(spec);
    }
    configure_http_logging(&mut builder);
    builder
}

fn configure_http_logging(builder: &mut env_logger::Builder) {
    // ureq's request/prelude debug logs contain raw signed URLs. Override even
    // an explicit RUST_LOG=ureq::unit=trace; our HTTP diagnostics redact them.
    builder.filter_module("ureq::unit", log::LevelFilter::Warn);
}

/// Regression: verbose HTTP request traces exposed presigned CDN URL queries.
#[test]
fn regression_http_debug_logging_hides_signed_request_urls() {
    let mut builder = env_logger::Builder::new();
    builder.parse_filters("debug,ureq::unit=trace");
    configure_http_logging(&mut builder);
    let logger = builder.build();
    for level in [log::Level::Debug, log::Level::Trace] {
        let record = log::Record::builder()
            .target("ureq::unit")
            .level(level)
            .args(format_args!(
                "GET https://cdn.example/data?Signature=secret"
            ))
            .build();
        assert!(!logger.matches(&record));
    }
    let record = log::Record::builder()
        .target("ratarmount_remote::http_pool")
        .level(log::Level::Debug)
        .args(format_args!("safe HTTP diagnostic"))
        .build();
    assert!(logger.matches(&record));
}

#[cfg(test)]
fn logger_enabled(debug: u8, rust_log: Option<&str>, target: &str, level: log::Level) -> bool {
    let logger = logger_filter_builder(debug, rust_log).build();
    let record = log::Record::builder()
        .target(target)
        .level(level)
        .args(format_args!("x"))
        .build();
    logger.matches(&record)
}

/// Regression: `RUST_LOG=debug` printed no DEBUG lines because `-d`'s
/// `filter_level` replaced RUST_LOG's global directive (#138).
#[test]
fn regression_rust_log_global_level_wins_over_debug_flag() {
    use log::Level::{Debug, Error, Info, Trace, Warn};
    assert!(logger_enabled(0, Some("debug"), "ratarmount", Debug));
    assert!(logger_enabled(1, Some("debug"), "ratarmount_fuse", Debug));
    // RUST_LOG=error beats -d 3.
    assert!(logger_enabled(3, Some("error"), "ratarmount", Error));
    assert!(!logger_enabled(3, Some("error"), "ratarmount", Warn));
    assert!(!logger_enabled(3, Some("error"), "ratarmount", Debug));
    // Empty RUST_LOG falls back to -d.
    assert!(logger_enabled(3, Some(""), "ratarmount", Debug));
    // Unset: -d applies.
    assert!(logger_enabled(3, None, "ratarmount", Debug));
    assert!(!logger_enabled(2, None, "ratarmount", Debug));
    assert!(logger_enabled(2, None, "ratarmount", Info));
    assert!(!logger_enabled(1, None, "ratarmount", Info));
    // Module-scoped directive keeps working on top of the -d baseline.
    let spec = Some("ratarmount_fuse=debug");
    assert!(logger_enabled(2, spec, "ratarmount_fuse", Debug));
    assert!(logger_enabled(2, spec, "ratarmount_fuse::sub", Debug));
    assert!(!logger_enabled(2, spec, "ratarmount", Debug));
    assert!(logger_enabled(2, spec, "ratarmount", Info));
    // Signed-URL redaction survives a global RUST_LOG.
    let spec = Some("debug,ureq::unit=trace");
    assert!(!logger_enabled(0, spec, "ureq::unit", Debug));
    assert!(!logger_enabled(0, spec, "ureq::unit", Trace));
    assert!(logger_enabled(0, spec, "ureq::unit", Warn));
}

/// Adapter so env_logger can write through a Mutex-guarded File.
struct WriteAdapter(std::sync::Mutex<std::fs::File>);

impl Write for WriteAdapter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("log file mutex").write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.lock().expect("log file mutex").flush()
    }
}

fn print_features() {
    println!("ratarmount {VERSION} (Rust)");
    println!("features:");
    println!("  fuse: fuser (low-level)");
    println!(
        "  nfs: nfsserve NFSv3 (--nfs, default); NFSv4.1 embednfs (--nfs-vers 4; Linux/macOS packages enable nfsv4; source: --features nfsv4, rustc>=1.88)"
    );
    #[cfg(feature = "nfsv4")]
    println!("  nfsv4: compiled");
    #[cfg(not(feature = "nfsv4"))]
    println!("  nfsv4: not compiled");
    println!(
        "  export: HTTP GET/HEAD (--http :20491); WebDAV (--webdav :20492); SMB2 (--smb :20445); 9P2000.L (--ninep :20493); SFTP (--sftp :20222, --sftp-subsystem stdio, --features sftp-russh); optional `serve` sugar"
    );
    #[cfg(feature = "sftp-russh")]
    println!("  sftp-russh: compiled");
    #[cfg(not(feature = "sftp-russh"))]
    println!("  sftp-russh: not compiled");
    #[cfg(feature = "bittorrent")]
    println!("  bittorrent: compiled (magnet/.torrent; web seeds first (LAN mode available); peer discovery off by default (--torrent-swarm never); uploads disabled by default; seeding opt-in)");
    #[cfg(not(feature = "bittorrent"))]
    println!("  bittorrent: not compiled");
    println!(
        "  compress: gzip/bzip2/xz/zstd/lz4/lzip/lzo/Z/lzma/zlib seekable bodies; plain single-file materialize"
    );
    println!(
        "  formats: tar,zip,ar,cpio,iso9660,warc,xar,cab,sevenzip,sqlar,squashfs,ext4,fat,asar,ogg,html,pdf,git,libarchive"
    );
    println!("  compositing: automount,union,folder,write-overlay,file-versions,prefix,transform,oci-overlayfs");
    println!(
        "  remote: http,https,file,s3,gs,az,ftp,ftps,ssh,sftp,webdav,smb,dropbox,oci,docker,ipfs,rclone"
    );
    println!(
        "  index: --index-file, --index-id, --index-folders, :memory:, --publish-index / --publish-index-to"
    );
    println!(
        "  control: --control-interface (unix socket + in-FS search/<pattern>); ratarmount find PATTERN ARCHIVE"
    );
}

fn print_oss_attributions(full: bool) {
    println!("ratarmount {VERSION} (Rust) — open source components (non-exhaustive):");
    // Major direct dependencies used by ratarmount-rs and its workspace crates.
    let short = [
        "fuser — FUSE bindings (MIT)",
        "rusqlite / SQLite — index store (MIT / public domain)",
        "flate2 / miniz_oxide — gzip/zlib (MIT / Zlib)",
        "bzip2 (libbz2) — bzip2 decompression (bzip2-rs + libbz2)",
        "xz2 / liblzma — xz/lzma decompression (MIT)",
        "zstd — zstd decompression (BSD / dual)",
        "lz4_flex — lz4 (MIT)",
        "backhand — SquashFS reader (MIT)",
        "libarchive — multi-format archives via FFI (BSD-2-Clause)",
        "git2 / libgit2 — git repositories (MIT / GPL dual for libgit2)",
        "fatfs — FAT filesystems (MIT)",
        "lopdf — PDF (MIT)",
        "aes / sha2 / md-5 / crc32fast — crypto & hashes",
        "clap — CLI parsing (MIT/Apache-2.0)",
        "env_logger / log — logging (MIT/Apache-2.0)",
        "nix / libc — Unix syscalls (MIT)",
        "regex / thiserror / anyhow / url / tempfile — utilities",
        "ureq / ssh2 / … — remote backends (http/s3/gs/az/ftp/ssh/oci/ipfs/rclone)",
        "nfsserve / tokio — in-process NFSv3 export (--nfs)",
        #[cfg(feature = "bittorrent")]
        "librqbit — torrent metadata and streaming (Apache-2.0; seeding opt-in)",
        #[cfg(feature = "nfsv4")]
        "embednfs — in-process NFSv4.1 export (--nfs-vers 4) (MIT)",
        "httparse — HTTP/WebDAV export (--http / --webdav)",
        "userspace SMB 2.0.2 (--smb) / 9P2000.L (--ninep)",
        #[cfg(feature = "sftp-russh")]
        "russh / russh-sftp — SFTP export (--sftp / --sftp-subsystem)",
        #[cfg(not(feature = "sftp-russh"))]
        "russh / russh-sftp — SFTP export (--sftp / --sftp-subsystem; rebuild with --features sftp-russh)",
    ];
    for s in short {
        println!("  - {s}");
    }
    if full {
        println!();
        println!("Additional transitive crates (serde, parking_lot, memmap2, byteorder,");
        println!("smallvec, once_cell, …) are pulled in via Cargo; see `Cargo.lock`.");
        println!();
        println!(
            "Full license texts ship with the respective crates on crates.io / system packages."
        );
        println!("This binary is MIT-licensed; see LICENSE in the source tree.");
        println!();
        println!("Use --oss-attributions-short for the compact list only.");
    }
}

type SearchFn = Arc<dyn Fn(&str) -> String + Send + Sync>;

/// `<dir>/ratarmount-control-<pid>.sock`.
pub(crate) fn control_socket_path(dir: &Path, pid: u32) -> PathBuf {
    dir.join(format!("ratarmount-control-{pid}.sock"))
}

/// Removes the control socket when dropped. The accept thread only unlinks
/// after its stop flag is set, and `accept()` blocks, so an external
/// `fusermount -u` never reaches that.
struct ControlSocket(PathBuf);

impl Drop for ControlSocket {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// The live control socket, for the serve paths that end in `process::exit`
/// (which skips [`ControlSocket`]'s destructor): see [`mount_blocking`].
static CONTROL_SOCKET: std::sync::Mutex<Option<PathBuf>> = std::sync::Mutex::new(None);

/// [`fuse_mount_blocking`], then unlink the control socket: the mount is over
/// whether it ended by `fusermount -u`, the control `unmount`, or an error, and
/// every caller goes on to `process::exit` or returns into a forked child.
#[allow(clippy::too_many_arguments)]
fn mount_blocking(
    source: Arc<dyn MountSource>,
    mountpoint: impl AsRef<Path>,
    foreground: bool,
    writable: bool,
    overlay: Option<Arc<WriteOverlay>>,
    extra_fuse_opts: &str,
    readahead: u64,
    passthrough: PassthroughOptions,
    direct_io: bool,
    activity: ratarmount_fuse::oplog::MountActivity,
) -> std::io::Result<()> {
    let r = fuse_mount_blocking(
        source,
        mountpoint,
        foreground,
        writable,
        overlay,
        extra_fuse_opts,
        readahead,
        passthrough,
        direct_io,
        activity,
    );
    remove_registered_control_socket();
    r
}

fn remove_registered_control_socket() {
    let path = CONTROL_SOCKET
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take();
    if let Some(path) = path {
        let _ = std::fs::remove_file(path);
    }
}

/// A bound control socket that is not yet served. Binding (and printing the path) happens
/// before any fork so errors reach the user; [`ControlListener::serve`] runs in the process
/// that serves the mount, because a thread started before `fork` does not exist in the child.
struct ControlListener {
    listener: UnixListener,
    sock: PathBuf,
    mountpoint: PathBuf,
    stop: Arc<AtomicBool>,
    on_search: Option<SearchFn>,
    quota: Option<Arc<ratarmount_compositing::OverlayQuota>>,
}

/// Counts control requests being answered. A reply that unmounts is in flight before the
/// unmount starts and stays so until it is written, so the exit path can wait for it.
/// The copy [`ControlListener::serve`] returns also owns the socket file's
/// [`ControlSocket`] guard (the accept thread's copy has none), so the file is
/// removed when the serving path drops it, even after an external `fusermount -u`.
#[derive(Clone, Default)]
struct ControlInflight(
    Arc<std::sync::atomic::AtomicUsize>,
    Option<Arc<ControlSocket>>,
);

/// Marks one control request in flight until dropped (also on panic).
struct ControlInflightGuard(Arc<std::sync::atomic::AtomicUsize>);

impl ControlInflight {
    fn enter(&self) -> ControlInflightGuard {
        self.0.fetch_add(1, Ordering::SeqCst);
        ControlInflightGuard(Arc::clone(&self.0))
    }

    /// Wait up to `bound` for every in-flight request to finish. True when idle.
    fn wait_idle(&self, bound: Duration) -> bool {
        let start = Instant::now();
        while self.0.load(Ordering::SeqCst) != 0 {
            if start.elapsed() >= bound {
                return false;
            }
            thread::sleep(Duration::from_millis(10));
        }
        true
    }
}

impl Drop for ControlInflightGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// How long the exit path waits for a control reply that is still being written.
const CONTROL_REPLY_WAIT: Duration = Duration::from_secs(2);

/// Wait (bounded) for an in-flight control reply before the process exits. No-op without
/// a control socket.
fn wait_control_reply(control: &Option<ControlInflight>) {
    if let Some(inflight) = control {
        if !inflight.wait_idle(CONTROL_REPLY_WAIT) {
            log::warn!("control reply still being written after {CONTROL_REPLY_WAIT:?}; exiting");
        }
    }
}

/// Bind the control socket and print its path.
fn bind_control_interface(
    mountpoint: &Path,
    stop: Arc<AtomicBool>,
    on_search: Option<SearchFn>,
    quota: Option<Arc<ratarmount_compositing::OverlayQuota>>,
) -> Option<ControlListener> {
    let sock = control_socket_path(&std::env::temp_dir(), std::process::id());
    let _ = std::fs::remove_file(&sock);
    let listener = match UnixListener::bind(&sock) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("warning: control interface bind failed: {e}");
            return None;
        }
    };
    eprintln!("control interface: {}", sock.display());
    Some(ControlListener {
        listener,
        sock,
        mountpoint: mountpoint.to_path_buf(),
        stop,
        on_search,
        quota,
    })
}

impl ControlListener {
    /// Start the accept thread. Call in the process that serves the mount.
    fn serve(self) -> ControlInflight {
        let mut inflight = ControlInflight::default();
        // The accept thread's copy carries no socket guard: it blocks in
        // `accept()` and never returns after an external `fusermount -u`.
        let tracker = inflight.clone();
        let ControlListener {
            listener,
            sock,
            mountpoint: mp,
            stop,
            on_search,
            quota,
        } = self;
        *CONTROL_SOCKET.lock().unwrap_or_else(|e| e.into_inner()) = Some(sock.clone());
        inflight.1 = Some(Arc::new(ControlSocket(sock.clone())));
        thread::spawn(move || {
            // Don't block forever if unmount happens
            let _ = listener.set_nonblocking(false);
            while !stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        use std::io::{BufRead, BufReader};
                        let mut reader = BufReader::new(&stream);
                        let mut line = String::new();
                        if reader.read_line(&mut line).is_ok() {
                            // Taken before `control_reply` (which may unmount, after which
                            // `mount_blocking` returns and the process exits) and released only
                            // once the reply is written.
                            let _in_flight = tracker.enter();
                            let reply = control_reply_with_quota(
                                line.trim(),
                                &mp,
                                &stop,
                                on_search.as_ref(),
                                quota.as_deref(),
                                &|p| unmount(p),
                            );
                            let _ = stream.write_all(reply.as_bytes());
                            let _ = stream.flush();
                            let _ = stream.shutdown(std::net::Shutdown::Write);
                        }
                    }
                    Err(_) => {
                        thread::sleep(Duration::from_millis(100));
                    }
                }
            }
            let _ = std::fs::remove_file(&sock);
        });
        inflight
    }
}

fn control_reply_with_quota(
    cmd: &str,
    mp: &Path,
    stop: &AtomicBool,
    on_search: Option<&SearchFn>,
    quota: Option<&ratarmount_compositing::OverlayQuota>,
    unmount_op: &dyn Fn(&Path) -> std::io::Result<()>,
) -> String {
    let mut reply = control_reply(cmd, mp, stop, on_search, unmount_op);
    if cmd == "status" {
        if let Some(quota) = quota {
            reply.push_str(&quota.usage().status_text());
        }
    }
    reply
}

fn control_reply(
    cmd: &str,
    mp: &Path,
    stop: &AtomicBool,
    on_search: Option<&SearchFn>,
    unmount_op: &dyn Fn(&Path) -> std::io::Result<()>,
) -> String {
    match cmd {
        "ping" => "pong\n".to_string(),
        "status" => format!(
            "mounted {}\n{}",
            mp.display(),
            ratarmount_core::budget::MemoryBudget::global().status_text()
        ),
        "unmount" | "quit" | "exit" => {
            // On failure keep the socket up so the client can retry.
            match unmount_op(mp) {
                Ok(()) => {
                    stop.store(true, Ordering::Relaxed);
                    "ok unmounted\n".to_string()
                }
                Err(e) => format!("error: unmount failed: {e}\n"),
            }
        }
        "help" => "commands: ping status unmount search help\n".to_string(),
        "search" => "error: search requires a pattern\n".to_string(),
        other if other.starts_with("search ") => {
            let pattern = other["search ".len()..].trim();
            if pattern.is_empty() {
                return "error: search requires a pattern\n".to_string();
            }
            let Some(cb) = on_search else {
                return "error: search requires an on-disk index\n".to_string();
            };
            let tsv = cb(pattern);
            if tsv.starts_with("error:") {
                if tsv.ends_with('\n') {
                    tsv
                } else {
                    format!("{tsv}\n")
                }
            } else {
                let n = tsv.lines().filter(|l| !l.is_empty()).count();
                let mut out = tsv;
                if !out.is_empty() && !out.ends_with('\n') {
                    out.push('\n');
                }
                out.push_str(&format!("count {n}\n"));
                out
            }
        }
        other => format!("error: unknown command {other:?}\n"),
    }
}

/// Unmount stand-in for control-reply unit tests that never touch a mount.
#[cfg(test)]
fn no_unmount(_: &Path) -> std::io::Result<()> {
    Ok(())
}

fn wait_until_mounted(path: &Path, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if is_fuse_mount(path) {
            return true;
        }
        thread::sleep(Duration::from_millis(50));
    }
    false
}

/// True when `path` appears to be a live FUSE (or FUSE-T) mount.
fn is_fuse_mount(path: &Path) -> bool {
    if mount_table_lists(path) {
        return true;
    }
    // Linux: FUSE superblock magic via statfs (layout is Linux-specific).
    #[cfg(target_os = "linux")]
    {
        if path_is_fuse_superblock(path) {
            return true;
        }
    }
    false
}

/// Check kernel/user mount tables for `path` (Linux mountinfo + portable `mount`).
fn mount_table_lists(path: &Path) -> bool {
    let candidates = path_mount_candidates(path);

    if let Ok(text) = {
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-B0029-M01","item":"ratarmount::mount_table_lists","disposition":"out-of-family","category":"kernel-or-process-introspection","reason":"/proc or mount-table introspection","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
        )]
        let __inventory_value_0 = std::fs::read_to_string("/proc/self/mountinfo");
        __inventory_value_0
    } {
        if text
            .lines()
            .any(|l| candidates.iter().any(|c| l.contains(c.as_str())))
        {
            return true;
        }
    }

    if let Ok(output) = std::process::Command::new("mount").output() {
        if output.status.success() {
            if let Ok(text) = String::from_utf8(output.stdout) {
                if mount_output_lists_path(&text, &candidates) {
                    return true;
                }
            }
        }
    }
    false
}

/// Paths to match in mount tables (as given + canonical when available).
fn path_mount_candidates(path: &Path) -> Vec<String> {
    let mut v = Vec::with_capacity(2);
    let raw = path.to_string_lossy().into_owned();
    v.push(raw);
    if let Ok(c) = path.canonicalize() {
        let s = c.to_string_lossy().into_owned();
        if !v.iter().any(|x| x == &s) {
            v.push(s);
        }
    }
    v
}

/// Parse `mount` command text for a mountpoint.
///
/// Linux: `src on /path type fuse ...`  
/// Darwin: `src on /path (macfuse, local, ...)` or FUSE-T NFS/SMB lines.
fn mount_output_lists_path(mount_text: &str, candidates: &[String]) -> bool {
    for line in mount_text.lines() {
        let Some(idx) = line.find(" on ") else {
            continue;
        };
        let rest = &line[idx + 4..];
        for cand in candidates {
            if !rest.starts_with(cand.as_str()) {
                continue;
            }
            let after = &rest[cand.len()..];
            // Boundary: end, whitespace, or '(' (Darwin options).
            if after.is_empty()
                || after.starts_with(' ')
                || after.starts_with('(')
                || after.starts_with('\t')
            {
                return true;
            }
        }
    }
    false
}

/// Linux-only: `statfs` FUSE_SUPER_MAGIC (`0x65735546`).
#[cfg(target_os = "linux")]
fn path_is_fuse_superblock(path: &Path) -> bool {
    rustix::fs::statfs(path).is_ok_and(|stat| fuse_superblock_type(stat.f_type))
}

#[cfg(target_os = "linux")]
fn fuse_superblock_type(fs_type: rustix::fs::FsWord) -> bool {
    fs_type == 0x6573_5546
}

/// Startup message for a failed `WriteOverlay::new`. Every `Sqlite` error there
/// comes from the overlay database itself (open, exclusive lock, schema,
/// tombstone load, #89). A busy/locked database belongs to another mount, so
/// never suggest moving it aside then; access errors point at permissions.
/// Paths are canonical when the overlay folder exists.
fn overlay_open_error(overlay_path: &Path, e: &OverlayError) -> String {
    let ov = overlay_path
        .canonicalize()
        .unwrap_or_else(|_| overlay_path.to_path_buf());
    let db = ov.join(HIDDEN_DB);
    match e {
        e if e.is_locked() => format!(
            "write overlay {} is in use by another ratarmount process (database is locked); unmount it first",
            ov.display()
        ),
        e if e.is_access_error() => format!(
            "error opening write overlay database {}: {e}; check that it and {} are readable and writable",
            db.display(),
            ov.display()
        ),
        OverlayError::Sqlite(_) => format!(
            "error opening write overlay database {}: {e}; move it aside to start a fresh overlay, or mount without -w",
            db.display()
        ),
        _ => format!("error creating write overlay: {e}"),
    }
}

pub(crate) fn resolve_lower_bundle(
    path: &Path,
    view: Arc<dyn MountSource>,
    marker_key: Option<&str>,
    cache: Option<&Path>,
) -> std::io::Result<PathBuf> {
    match cache {
        Some(cache) => overlay_pack::cached_lower_in(path, cache, view, marker_key),
        None => overlay_pack::cached_lower(path, view, marker_key),
    }
}

pub(crate) fn lower_stack_services(
) -> ratarmount_compositing::lower_stack::LowerStackServices<'static> {
    ratarmount_compositing::lower_stack::LowerStackServices {
        resolve_bundle: &resolve_lower_bundle,
        format_meta_error: &overlay_open_error,
    }
}

/// Point fd 1 and fd 2 at `/dev/null` when they are closed (EBADF) or their
/// reader is gone (`poll` reports POLLERR/POLLHUP, e.g. a pipe whose read end
/// was closed). Working terminals, files and pipes are left alone. Never
/// fails: on any error the fd is left as it was.
fn neutralize_dead_stdio() {
    for target in [libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-E0116-M01","item":"ratarmount::neutralize_dead_stdio","disposition":"out-of-family","category":"standard-descriptor-control","reason":"Determine whether stdin/stdout/stderr is closed before filling vacant standard slots.","creation":{"policy":"none","basis":"F_GETFD queries the standard slot only; no descriptor is opened or duplicated by this operation."}}"###
        )]
        let closed = unsafe { libc::fcntl(target, libc::F_GETFD) } == -1
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::EBADF);
        let dead = !closed && {
            let mut pfd = libc::pollfd {
                fd: target,
                events: libc::POLLOUT,
                revents: 0,
            };
            let n = unsafe { libc::poll(&mut pfd, 1, 0) };
            n > 0 && pfd.revents & (libc::POLLERR | libc::POLLHUP) != 0
        };
        if !(closed || dead) {
            continue;
        }
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-B0030-M01","item":"ratarmount::neutralize_dead_stdio","disposition":"out-of-family","category":"runtime-resource-or-descriptor-handoff","reason":"logger output or standard descriptor setup","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
        )]
        let null = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
        if null < 0 {
            continue;
        }
        unsafe {
            if null != target {
                #[expect(
                    clippy::disallowed_methods,
                    reason = r###"internal-read:v1 {"id":"IR-B0031-M01","item":"ratarmount::neutralize_dead_stdio","disposition":"out-of-family","category":"runtime-resource-or-descriptor-handoff","reason":"standard descriptor handoff: duplicates or redirects a standard stream descriptor; opens no pathname and reads no file content","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
                )]
                libc::dup2(null, target);
            } else {
                // `open` reused the closed target; drop O_CLOEXEC like dup2 would.
                #[expect(
                    clippy::disallowed_methods,
                    reason = r###"internal-read:v1 {"id":"IR-E0117-M01","item":"ratarmount::neutralize_dead_stdio","disposition":"out-of-family","category":"standard-descriptor-control","reason":"Clear descriptor flags when preparing the already-filled standard slot for process handoff.","creation":{"policy":"none","basis":"F_SETFD updates an existing descriptor; /dev/null acquisition and redirection have their own events."}}"###
                )]
                libc::fcntl(target, libc::F_SETFD, 0);
            }
        }
        // `open` may have returned the closed target itself; keep that one.
        if null != libc::STDOUT_FILENO && null != libc::STDERR_FILENO {
            unsafe {
                libc::close(null);
            }
        }
    }
}

fn redirect_stdio_to_null() -> std::io::Result<()> {
    #[expect(
        clippy::disallowed_types,
        reason = r###"internal-read:v1 {"id":"IR-E0118-T01","item":"ratarmount::redirect_stdio_to_null","disposition":"support","category":"builder-type-support","reason":"Builder type support: Import OpenOptions locally for standard-stream redirection to /dev/null.","creation":{"policy":"none","basis":"This is a type/import reference; it acquires no file or directory."}}"###
    )]
    use std::fs::OpenOptions;
    use std::os::unix::io::AsRawFd;
    let devnull = {
        #[expect(
            clippy::disallowed_types,
            reason = r###"internal-read:v1 {"id":"IR-B0032-T01","item":"ratarmount::redirect_stdio_to_null","disposition":"support","category":"builder-type-support","reason":"Builder type support: logger output or standard descriptor setup","mode_policy":"unchanged-from-e6ca64e","creation":{"policy":"none","basis":"This is a type/import reference; it acquires no file or directory."}}"###
        )]
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-B0032-M01","item":"ratarmount::redirect_stdio_to_null","disposition":"support","category":"builder-setup","reason":"Prepare the builder for this item's separately reviewed open/create leaf.","mode_policy":"unchanged-from-e6ca64e","creation":{"policy":"none","basis":"Builder construction/setup only; the separate open/create leaf owns pathname acquisition and permissions."},"supports_disposition":"out-of-family","baseline_reason":"logger output or standard descriptor setup"}"###
        )]
        let mut __inventory_value_0 = OpenOptions::new();
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-B0032-M02","item":"ratarmount::redirect_stdio_to_null","disposition":"out-of-family","category":"runtime-resource-or-descriptor-handoff","reason":"logger output or standard descriptor setup","mode_policy":"unchanged-from-e6ca64e","creation":{"policy":"unchanged-from-e6ca64e","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###
        )]
        let __inventory_value_1 = __inventory_value_0.read(true).write(true).open("/dev/null");
        __inventory_value_1
    }?;
    let fd = devnull.as_raw_fd();
    unsafe {
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-B0033-M01","item":"ratarmount::redirect_stdio_to_null","disposition":"out-of-family","category":"runtime-resource-or-descriptor-handoff","reason":"standard descriptor handoff: duplicates or redirects a standard stream descriptor; opens no pathname and reads no file content","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
        )]
        libc::dup2(fd, 0);
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-B0034-M01","item":"ratarmount::redirect_stdio_to_null","disposition":"out-of-family","category":"runtime-resource-or-descriptor-handoff","reason":"standard descriptor handoff: duplicates or redirects a standard stream descriptor; opens no pathname and reads no file content","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
        )]
        libc::dup2(fd, 1);
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-B0035-M01","item":"ratarmount::redirect_stdio_to_null","disposition":"out-of-family","category":"runtime-resource-or-descriptor-handoff","reason":"standard descriptor handoff: duplicates or redirects a standard stream descriptor; opens no pathname and reads no file content","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
        )]
        libc::dup2(fd, 2);
    }
    Ok(())
}

fn split_bound_inputs_mountpoint(args: &Args) -> (Vec<PathBuf>, Option<PathBuf>) {
    // With binds and one local positional, use that positional as the explicit
    // mountpoint. Export-only commands keep their positional source as before.
    if !args.source_binds.is_empty()
        && args.paths.len() == 1
        && !args.no_mount
        && !any_export(args)
        && !ratarmount_remote::is_remote_url(&args.paths[0].to_string_lossy())
        && !args.paths[0].is_file()
    {
        (Vec::new(), Some(args.paths[0].clone()))
    } else {
        split_inputs_mountpoint(&args.paths, args.no_mount)
    }
}

fn split_inputs_mountpoint(paths: &[PathBuf], no_mount: bool) -> (Vec<PathBuf>, Option<PathBuf>) {
    if no_mount || paths.len() == 1 {
        return (paths.to_vec(), None);
    }
    let last = paths.last().unwrap();
    let last_s = last.to_string_lossy();
    if ratarmount_remote::is_remote_url(&last_s) {
        return (paths.to_vec(), None);
    }
    (paths[..paths.len() - 1].to_vec(), Some(last.clone()))
}

/// Base-relative exclusions for the A2 walk of a directory base: the paths of
/// this invocation (journal, a new `-w` overlay) resolved with the topmost-new
/// rule, plus the set an existing `-w` overlay already recorded.
///
/// An invocation-only path is excluded only if it is not in the base yet or is
/// already in a recorded excluded set (the top's, added below, or the bottom
/// lower's, which the walk applies itself). Anything else is base content, so
/// a change to it is a base change, with or without `-w`.
fn lower_extra_excludes(
    base: Option<&Path>,
    lowers: &[PathBuf],
    overlay: Option<&Path>,
    mut paths: Vec<PathBuf>,
) -> Vec<PathBuf> {
    use ratarmount_compositing::overlay_meta::{resolve_base_excludes, BaseExcludes};
    let Some(base) = base.filter(|b| !lowers.is_empty() && b.is_dir()) else {
        return Vec::new();
    };
    paths.retain(|p| std::fs::symlink_metadata(p).is_err());
    let mut out: Vec<PathBuf> = Vec::new();
    if let Some(overlay) = overlay.filter(|o| o.as_os_str() != ":temp:") {
        paths.push(overlay.to_path_buf());
        if let Some(recorded) = ratarmount_compositing::OverlayMeta::read(overlay)
            .ok()
            .flatten()
            .and_then(|m| m.get("base_weak_excludes").map(str::to_owned))
            .and_then(|text| BaseExcludes::from_json(&text).ok())
        {
            out.extend(recorded.paths().iter().cloned());
        }
    }
    if let Ok((_, resolved)) = resolve_base_excludes(base, &paths) {
        out.extend(resolved.paths().iter().cloned());
    }
    out
}

/// The mount-time journal rule: before any recovery write, compare each
/// member's journal against every readable overlay record (`-w` top, `--lower`
/// directories). A journal every record agrees with (or abstains on) is
/// recovered now and the top's rows restamped; one a record does not own is
/// left untouched until every gate decided. A torn deferred journal is refused
/// (nothing can open on a half-written archive); a complete one is returned for
/// recovery after the gates. The decision is taken again under the archive lock.
fn recover_mount_journals(args: &Args, inputs: &[PathBuf]) -> Vec<PathBuf> {
    use ratarmount_compositing::{
        classify_mount_journal, recover_journal_at, MountJournal, MountRecords,
    };
    let mut members: Vec<PathBuf> = Vec::new();
    for input in inputs {
        let typed = input.to_string_lossy();
        match ratarmount_remote::remote_url_scheme(&typed).as_deref() {
            Some("file") => match &ratarmount_remote::resolve_to_local(&typed) {
                Ok(ratarmount_remote::RemoteLocal::Local(path)) => members.push(path.clone()),
                _ => members.push(input.clone()),
            },
            _ if ratarmount_remote::is_remote_url(&typed) => {}
            _ => members.push(input.clone()),
        }
    }
    if args.roll_every.is_some() && members.len() == 1 {
        if let Ok(name) = ratarmount_compositing::SeriesName::new(&members[0]) {
            if let Ok(found) = name.discover() {
                members = found.into_iter().map(|(_, path)| path).collect();
            }
        }
    }
    for bind in &args.source_binds {
        if !ratarmount_remote::is_remote_url(&bind.source) {
            members.push(PathBuf::from(&bind.source));
        }
    }
    if args.no_recreate_index || args.index_id.is_some() {
        for member in &members {
            if let Err(error) =
                ratarmount_compositing::journal_recovery::check_offline_journal(member)
            {
                eprintln!("error: --no-recreate-index forbids commit recovery for {}: {error}; stop workers and finish preparation first", member.display());
                std::process::exit(2);
            }
        }
        return Vec::new();
    }
    let mut records = MountRecords::default();
    if let Some(top) = args
        .write_overlay
        .as_ref()
        .filter(|w| w.as_os_str() != ":temp:")
    {
        records.top = Some(top.clone());
    }
    for lower in &args.lower {
        if lower.is_dir() {
            records.lowers.push(lower.clone());
        } else {
            records.bundles = true;
        }
    }
    let top_db = records
        .top
        .as_ref()
        .map(|dir| dir.join(ratarmount_compositing::HIDDEN_DB));
    let mut deferred = Vec::new();
    for member in &members {
        match classify_mount_journal(&records, member) {
            Err(e) => {
                eprintln!("error: commit recovery for {}: {e}", member.display());
                std::process::exit(2);
            }
            Ok(MountJournal::None | MountJournal::Own) => {
                let owner = ratarmount_compositing::Owner::Mount {
                    records: &records,
                    member,
                };
                if let Err(e) = recover_journal_at(member, top_db.as_deref(), owner) {
                    eprintln!("error: commit recovery for {}: {e}", member.display());
                    std::process::exit(2);
                }
            }
            Ok(MountJournal::Deferred { complete: true, .. }) => deferred.push(member.clone()),
            Ok(MountJournal::Deferred {
                complete: false,
                why,
                force_flag,
            }) => {
                eprintln!(
                    "error: {} {why}; the replacement did not complete, so it cannot be opened \
                     until recovered. Recover it alone first (`ratarmount --no-mount {}` rolls \
                     the interrupted append back) or restore the recorded base, then retry, \
                     with {force_flag} if it is meant to replace the recorded base.",
                    member.display(),
                    member.display()
                );
                std::process::exit(2);
            }
        }
    }
    deferred
}

/// `--journal` files that exist already and lie inside a directory base under a
/// `--lower` stack (see [`MountedBase::existing_journals`]).
fn existing_journals_inside_base(
    base: Option<&Path>,
    lowers: &[PathBuf],
    journals: &Option<PathBuf>,
) -> Vec<PathBuf> {
    let Some(base) = base.filter(|b| !lowers.is_empty() && b.is_dir()) else {
        return Vec::new();
    };
    journals
        .iter()
        .filter(|p| std::fs::symlink_metadata(p).is_ok())
        .filter(|p| {
            ratarmount_compositing::overlay_meta::resolve_base_excludes(
                base,
                std::slice::from_ref(*p),
            )
            .is_ok_and(|(_, inside)| !inside.paths().is_empty())
        })
        .cloned()
        .collect()
}

/// Default mount point stem for a string `url::Url` can parse (never touches the filesystem).
fn default_mountpoint_url(s: &str) -> Option<PathBuf> {
    let url = url::Url::parse(s).ok()?;
    if let Some(seg) = url.path_segments().and_then(|mut p| p.next_back()) {
        if !seg.is_empty() {
            let stripped = strip_compression_suffix(seg);
            let stem = Path::new(&stripped)
                .file_stem()
                .and_then(|x| x.to_str())
                .unwrap_or(&stripped);
            return Some(PathBuf::from(stem));
        }
    }
    // fall through if URL parse had no usable last segment
    Some(PathBuf::from("remote"))
}

fn default_mountpoint(archive: &Path) -> PathBuf {
    let s = archive.to_string_lossy();
    if let Some(d) = default_mountpoint_url(&s) {
        return d;
    }
    let name = archive
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("mount");
    let stripped = strip_compression_suffix(name);
    let stem = Path::new(&stripped)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(&stripped);
    PathBuf::from(stem)
}

fn default_cli_parallelization() -> String {
    std::thread::available_parallelism()
        .map_or(1, |n| n.get().min(4))
        .to_string()
}

/// True when the user passed `--readahead` / `--readahead=…` on argv.
///
/// Used to distinguish clap's default `"0"` from an explicit `--readahead 0`
/// so auto-enable (rapidgzip prefer or gzip-ish input) only applies when the
/// flag is omitted.
fn readahead_flag_on_argv<I, S>(args: I) -> bool
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    args.into_iter().any(|a| {
        let a = a.as_ref();
        a == "--readahead" || a.starts_with("--readahead=")
    })
}

/// True when `name` (basename, URL segment, or full path) looks like a
/// gzip-compressed archive: `.gz`, `.tgz`, `.tar.gz`, or `.gzip` (case-insensitive).
fn name_looks_like_gzip(name: &str) -> bool {
    // Drop query/fragment if a URL-ish string is passed whole.
    let name = name.split(['?', '#']).next().unwrap_or(name);
    let l = name.to_ascii_lowercase();
    l.ends_with(".tar.gz") || l.ends_with(".tgz") || l.ends_with(".gzip") || l.ends_with(".gz")
}

/// True when a mount input path or URL looks like a gzip-compressed archive.
///
/// Checks the full path string, the file name, and the last URL path segment so
/// nested basenames (`…/inner.tar.gz`) and remote URLs work the same as plain
/// `.gz` / `.tgz` local paths.
fn path_looks_like_gzip_archive(path: &Path) -> bool {
    let s = path.to_string_lossy();
    if name_looks_like_gzip(&s) {
        return true;
    }
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        if name_looks_like_gzip(name) {
            return true;
        }
    }
    if let Ok(url) = url::Url::parse(&s) {
        if let Some(seg) = url.path_segments().and_then(|mut p| p.next_back()) {
            if name_looks_like_gzip(seg) {
                return true;
            }
        }
    }
    false
}

/// Effective FUSE readahead after CLI parse.
///
/// When rapidgzip is preferred **or** any mount input looks like gzip, and the
/// user did **not** pass `--readahead` on argv, a parsed value of `0` (clap
/// default) becomes [`RECOMMENDED_READAHEAD_BYTES`]. Explicit `--readahead 0`
/// stays off; any non-zero parse is left unchanged.
fn should_auto_readahead(
    prefer_rgz: bool,
    gzip_input: bool,
    readahead_flag_on_argv: bool,
    parsed: u64,
) -> u64 {
    if (prefer_rgz || gzip_input) && !readahead_flag_on_argv && parsed == 0 {
        RECOMMENDED_READAHEAD_BYTES
    } else {
        parsed
    }
}

#[cfg(test)]
mod mount_probe_tests {
    use super::{mount_output_lists_path, path_mount_candidates};
    use std::path::Path;

    /// Regression: replacing the handwritten statfs ABI must preserve success/error
    /// handling and distinguish the FUSE superblock from other filesystem types.
    #[cfg(target_os = "linux")]
    #[test]
    fn regression_typed_statfs_fuse_detection() {
        use super::{fuse_superblock_type, path_is_fuse_superblock};
        use std::os::unix::ffi::OsStrExt;

        assert!(fuse_superblock_type(0x6573_5546));
        assert!(!fuse_superblock_type(0));
        assert!(!fuse_superblock_type(0x0102_1994)); // tmpfs
        let dir = tempfile::tempdir().unwrap();
        let stat = rustix::fs::statfs(dir.path()).unwrap();
        assert_eq!(
            path_is_fuse_superblock(dir.path()),
            fuse_superblock_type(stat.f_type)
        );
        assert!(!path_is_fuse_superblock(&dir.path().join("missing")));
        let nul = Path::new(std::ffi::OsStr::from_bytes(b"/tmp/invalid\0path"));
        assert!(!path_is_fuse_superblock(nul));
    }

    #[test]
    fn mount_output_linux_fuse_line() {
        let text = "ratarmount on /tmp/mnt type fuse.ratarmount (rw,nosuid,nodev,relatime,user_id=1000,group_id=1000)\n";
        let cands = path_mount_candidates(Path::new("/tmp/mnt"));
        assert!(mount_output_lists_path(text, &cands));
    }

    #[test]
    fn mount_output_darwin_macfuse_line() {
        let text =
            "ratarmount@macfuse0 on /private/tmp/mnt (macfuse, local, nodev, nosuid, synchronous, mounted by user)\n";
        let cands = vec!["/private/tmp/mnt".to_string()];
        assert!(mount_output_lists_path(text, &cands));
    }

    #[test]
    fn mount_output_prefix_not_matched() {
        // `/tmp/mnt` must not match `/tmp/mnt-extra`
        let text = "x on /tmp/mnt-extra type fuse (rw)\n";
        let cands = vec!["/tmp/mnt".to_string()];
        assert!(!mount_output_lists_path(text, &cands));
    }

    #[test]
    fn path_candidates_include_raw() {
        let c = path_mount_candidates(Path::new("/nonexistent/ratarmount-test-path"));
        assert!(c.iter().any(|s| s.contains("ratarmount-test-path")));
    }
}

#[cfg(test)]
mod readahead_auto_cli_tests {
    /// Regression: direct-I/O is boolean and CLI parallelism is bounded by four CPUs.
    #[test]
    fn regression_direct_io_cli_and_parallelism_default() {
        use clap::Parser;
        let args =
            super::Args::try_parse_from(["ratarmount", "--direct-io", "data.tar.zst", "/mnt"])
                .unwrap();
        assert!(args.direct_io);
        assert_eq!(args.paths.len(), 2);
        let n: usize = args.parallelization.parse().unwrap();
        assert!((1..=4).contains(&n));
        let args =
            super::Args::try_parse_from(["ratarmount", "-P", "1", "data.tar.zst", "/mnt"]).unwrap();
        assert_eq!(args.parallelization, "1");
        assert!(!args.direct_io);
        assert_eq!(
            ratarmount_core::OpenOptions::default().parallelization,
            ratarmount_core::ParallelizationSpec::default()
        );
    }

    use super::{
        name_looks_like_gzip, path_looks_like_gzip_archive, readahead_flag_on_argv,
        should_auto_readahead, RECOMMENDED_READAHEAD_BYTES,
    };
    use std::path::Path;

    /// Regression: auto-enable 1 MiB readahead when rapidgzip preferred and
    /// `--readahead` omitted; explicit `--readahead 0` stays off.
    #[test]
    fn should_auto_readahead_rapidgzip_default_vs_explicit_zero() {
        assert_eq!(
            should_auto_readahead(true, false, false, 0),
            RECOMMENDED_READAHEAD_BYTES,
            "prefer rapidgzip + default 0 → recommended"
        );
        assert_eq!(
            should_auto_readahead(true, false, true, 0),
            0,
            "prefer rapidgzip + explicit --readahead 0 → off"
        );
        assert_eq!(
            should_auto_readahead(false, false, false, 0),
            0,
            "no rapidgzip, no gzip input + default 0 → off"
        );
        assert_eq!(
            should_auto_readahead(true, false, false, 256 * 1024),
            256 * 1024,
            "non-zero parse is never overridden"
        );
        assert_eq!(
            should_auto_readahead(true, false, true, RECOMMENDED_READAHEAD_BYTES),
            RECOMMENDED_READAHEAD_BYTES,
            "explicit non-zero is kept"
        );
    }

    /// Regression: default G3 gzip mounts auto-enable 1 MiB readahead when
    /// `--readahead` is omitted; explicit `--readahead 0` / `--readahead=N` stay overrides.
    #[test]
    fn should_auto_readahead_gzip_path_without_rapidgzip() {
        assert_eq!(
            should_auto_readahead(false, true, false, 0),
            RECOMMENDED_READAHEAD_BYTES,
            "gzip input + default 0 (no rapidgzip) → recommended"
        );
        assert_eq!(
            should_auto_readahead(false, true, true, 0),
            0,
            "gzip input + explicit --readahead 0 → off"
        );
        assert_eq!(
            should_auto_readahead(false, true, false, 512 * 1024),
            512 * 1024,
            "gzip input + non-zero parse is never overridden"
        );
        assert_eq!(
            should_auto_readahead(true, true, false, 0),
            RECOMMENDED_READAHEAD_BYTES,
            "both rapidgzip prefer and gzip input → recommended"
        );
        assert_eq!(
            should_auto_readahead(true, true, true, 0),
            0,
            "both triggers still yield to explicit --readahead 0"
        );
    }

    #[test]
    fn path_looks_like_gzip_archive_suffixes() {
        assert!(path_looks_like_gzip_archive(Path::new("a.tar.gz")));
        assert!(path_looks_like_gzip_archive(Path::new("/data/FOO.TGZ")));
        assert!(path_looks_like_gzip_archive(Path::new("plain.gz")));
        assert!(path_looks_like_gzip_archive(Path::new("x.GZIP")));
        assert!(path_looks_like_gzip_archive(Path::new(
            "/outer/nested/inner.tar.gz"
        )));
        assert!(path_looks_like_gzip_archive(Path::new(
            "https://example.com/pkg/archive.tar.gz"
        )));
        assert!(path_looks_like_gzip_archive(Path::new(
            "https://example.com/pkg/archive.tgz?token=1"
        )));
        assert!(!path_looks_like_gzip_archive(Path::new("a.tar.zst")));
        assert!(!path_looks_like_gzip_archive(Path::new("a.tar.bz2")));
        assert!(!path_looks_like_gzip_archive(Path::new("a.zip")));
        assert!(!path_looks_like_gzip_archive(Path::new("notgz")));
        assert!(!name_looks_like_gzip("archive.tar.gzz"));
    }

    #[test]
    fn readahead_flag_on_argv_forms() {
        assert!(!readahead_flag_on_argv(["ratarmount", "a.tar.gz", "/mnt"]));
        assert!(readahead_flag_on_argv([
            "ratarmount",
            "--readahead",
            "0",
            "a.tar.gz",
            "/mnt"
        ]));
        assert!(readahead_flag_on_argv([
            "ratarmount",
            "--readahead=1M",
            "a.tar.gz",
            "/mnt"
        ]));
        assert!(!readahead_flag_on_argv([
            "ratarmount",
            "--use-backend",
            "rapidgzip",
            "a.tar.gz",
            "/mnt"
        ]));
    }
}

#[cfg(test)]
mod parallel_nested_cli_tests {
    use super::{parse_parallel_nested, Args};
    use clap::Parser;

    /// Regression: FR-6 residual CLI wire — parse `--parallel-nested` values.
    #[test]
    fn parse_parallel_nested_values() {
        assert_eq!(parse_parallel_nested("0").unwrap(), 0);
        assert_eq!(parse_parallel_nested("auto").unwrap(), 0);
        assert_eq!(parse_parallel_nested("AUTO").unwrap(), 0);
        assert_eq!(parse_parallel_nested("  auto  ").unwrap(), 0);
        assert_eq!(parse_parallel_nested("1").unwrap(), 1);
        assert_eq!(parse_parallel_nested("8").unwrap(), 8);
        assert!(parse_parallel_nested("").is_err());
        assert!(parse_parallel_nested("nope").is_err());
        assert!(parse_parallel_nested("-1").is_err());
    }

    /// Default omit → 0 (auto); numeric / auto flag values reach Args.
    #[test]
    fn cli_parallel_nested_flag_defaults_and_sets() {
        let default = Args::try_parse_from(["ratarmount"]).expect("default parse");
        assert_eq!(default.parallel_nested, 0);

        let sequential =
            Args::try_parse_from(["ratarmount", "--parallel-nested", "1"]).expect("seq");
        assert_eq!(sequential.parallel_nested, 1);

        let cap = Args::try_parse_from(["ratarmount", "--parallel-nested", "8"]).expect("cap");
        assert_eq!(cap.parallel_nested, 8);

        let auto = Args::try_parse_from(["ratarmount", "--parallel-nested", "auto"]).expect("auto");
        assert_eq!(auto.parallel_nested, 0);

        let zero = Args::try_parse_from(["ratarmount", "--parallel-nested", "0"]).expect("zero");
        assert_eq!(zero.parallel_nested, 0);
    }

    /// FR-10: `--union-resolve-symlinks` wires into UnionMountOptions.
    #[test]
    fn union_resolve_symlinks_cli_flag() {
        let off = Args::try_parse_from(["ratarmount"]).expect("defaults");
        assert!(!off.union_resolve_symlinks);
        let on = Args::try_parse_from(["ratarmount", "--union-resolve-symlinks"]).expect("flag");
        assert!(on.union_resolve_symlinks);
    }

    /// CompositingOptions path: CLI value is the field that apply_compositing forwards.
    #[test]
    fn compositing_options_receives_parallel_nested() {
        let args = Args::try_parse_from(["ratarmount", "--parallel-nested", "4"]).expect("parse");
        let comp = ratarmount_session::factory::CompositingOptions {
            recursive: true,
            lazy: false,
            file_versions: true,
            prefix: None,
            strip_recursive_extension: false,
            transform_recursive: None,
            transform: None,
            disable_union_mount: false,
            recursive_extensions: None,
            union_cache: ratarmount_compositing::UnionMountOptions::default(),
            parallel_nested_threads: args.parallel_nested,
        };
        assert_eq!(comp.parallel_nested_threads, 4);
        // Default CompositingOptions matches AutoMountOptions auto (0).
        assert_eq!(
            ratarmount_session::factory::CompositingOptions::default().parallel_nested_threads,
            0
        );
    }
}

#[cfg(test)]
mod base_flag_cli_tests {
    use super::parse_args_from;

    fn parse(args: &[&str]) -> Result<super::Args, clap::Error> {
        parse_args_from(std::iter::once("ratarmount").chain(args.iter().copied()))
    }

    /// Regression: clap rejected `--base-digest` / `--force-stack-mismatch` on a
    /// read-only `--lower` mount, where A2 tells the user to pass them.
    #[test]
    fn regression_base_digest_flag_allowed_with_lower_only() {
        let digest = format!("sha256:{}", "a".repeat(64));
        let a = parse(&["--lower", "L", "--base-digest", &digest, "base", "mnt"]).expect("parse");
        assert_eq!(a.paths.len(), 2, "the value must not steal a positional");
        assert!(a.base_digest.is_some());
        assert!(parse(&["--lower", "L", "--base-digest", "none", "base", "mnt"]).is_ok());
        assert!(parse(&["--lower", "L", "--force-stack-mismatch", "base", "mnt"]).is_ok());
        assert!(parse(&[
            "-w",
            "ov",
            "--lower",
            "L",
            "--force-stack-mismatch",
            "base",
            "mnt"
        ])
        .is_ok());
        assert!(parse(&["-w", "ov", "--base-digest", &digest, "base", "mnt"]).is_ok());
        let error = parse(&["--base-digest", &digest, "base", "mnt"])
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("--base-digest requires"), "{error}");
        let error = parse(&["--force-stack-mismatch", "base", "mnt"])
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("--force-stack-mismatch requires"), "{error}");
        // --force-base-mismatch still needs an overlay target.
        assert!(parse(&["--lower", "L", "--force-base-mismatch", "base", "mnt"]).is_err());
    }

    /// Regression: the offline verbs (`overlay seal|pack|verify|import`, `diff`)
    /// dropped the parent invocation's `--index-folders`, so the sidecar a
    /// mount used was not the one they read. Each verb takes the flag, and the
    /// context carries the parsed folders (the defaults when none are given).
    #[test]
    fn regression_index_folders_reaches_offline_verbs() {
        let want = vec![
            std::path::PathBuf::from("/idx/a"),
            std::path::PathBuf::from("/idx/b"),
        ];
        for argv in [
            vec!["overlay", "seal", "ov", "--index-folders", "/idx/a,/idx/b"],
            vec![
                "overlay",
                "pack",
                "ov",
                "out.tar.zst",
                "--index-folders",
                "/idx/a,/idx/b",
            ],
            vec![
                "overlay",
                "verify",
                "ov",
                "--index-folders",
                "/idx/a,/idx/b",
            ],
        ] {
            let args = parse(&argv).unwrap();
            let overlay = args.overlay.expect("overlay verb");
            assert_eq!(
                super::overlay_run_context(overlay.index_folders.as_deref()).index_folders,
                want,
                "{argv:?}"
            );
        }
        let args = parse(&["diff", "ov", "--index-folders", "/idx/a,/idx/b"]).unwrap();
        let diff = args.diff.expect("diff");
        assert_eq!(
            super::overlay_run_context(diff.index_folders.as_deref()).index_folders,
            want
        );
        let args = parse(&[
            "--index-folders",
            "/idx/a,/idx/b",
            "--commit-overlay",
            "-w",
            "ov",
            "a.tar",
        ])
        .unwrap();
        assert_eq!(
            super::overlay_run_context(args.index_folders.as_deref()).index_folders,
            want
        );
        assert_eq!(
            super::overlay_run_context(None).index_folders,
            ratarmount_index::default_index_folders()
        );
    }
}

#[cfg(test)]
mod nfs_cli_tests {
    use super::Args;
    use clap::Parser;
    use std::path::PathBuf;

    /// Regression: boolean `--nfs` must not steal the archive path.
    #[test]
    fn nfs_flag_does_not_steal_archive() {
        let a = Args::try_parse_from(["ratarmount", "--nfs", "testdata.tar.gz"]).expect("parse");
        assert!(a.nfs);
        assert_eq!(a.paths, vec![PathBuf::from("testdata.tar.gz")]);
        assert_eq!(a.nfs_bind, "127.0.0.1:20490");
    }

    #[test]
    fn commit_overlay_on_exit_and_interval_parse() {
        let a = Args::try_parse_from([
            "ratarmount",
            "--nfs",
            "-w",
            "/tmp/ov",
            "--commit-overlay-on-exit",
            "--commit-overlay-interval",
            "2s",
            "a.tar",
        ])
        .expect("parse");
        assert!(a.commit_overlay_on_exit);
        assert_eq!(a.commit_overlay_interval, "2s");
        assert_eq!(
            crate::overlay_commit::parse_interval(&a.commit_overlay_interval).unwrap(),
            Some(std::time::Duration::from_secs(2))
        );
        assert_eq!(a.paths, vec![PathBuf::from("a.tar")]);
    }

    #[test]
    fn commit_overlay_threads_encoding_flag() {
        let a = Args::try_parse_from([
            "ratarmount",
            "--commit-overlay",
            "-w",
            "/tmp/ov",
            "-e",
            "latin1",
            "-i",
            "a.tar.zst",
        ])
        .expect("parse");
        assert!(a.commit_overlay);
        assert_eq!(a.encoding, "latin1");
        assert!(a.ignore_zeros);
        assert_eq!(a.paths, vec![PathBuf::from("a.tar.zst")]);
    }

    /// Regression: commit mode must consume only its value and default to copy.
    #[test]
    fn live_commit_mode_parse_and_default() {
        let args = Args::try_parse_from(["ratarmount", "a.tar", "mnt"]).unwrap();
        assert_eq!(args.commit_overlay_mode, "copy");
        for mode in ["append", "copy", "auto"] {
            let args = Args::try_parse_from([
                "ratarmount",
                "--commit-overlay-mode",
                mode,
                "-w",
                "ov",
                "--commit-overlay-interval",
                "2s",
                "a.tar",
                "mnt",
            ])
            .unwrap();
            assert_eq!(args.commit_overlay_mode, mode);
            assert_eq!(
                args.paths,
                vec![PathBuf::from("a.tar"), PathBuf::from("mnt")]
            );
        }
        assert!(
            Args::try_parse_from(["ratarmount", "--commit-overlay-mode", "unsafe", "a.tar"])
                .is_err()
        );
    }

    #[test]
    fn commit_overlay_interval_default_off() {
        let a = Args::try_parse_from(["ratarmount", "--nfs", "a.tar"]).expect("parse");
        assert!(!a.commit_overlay_on_exit);
        assert_eq!(a.commit_overlay_interval, "0");
        assert_eq!(
            crate::overlay_commit::parse_interval(&a.commit_overlay_interval).unwrap(),
            None
        );
    }

    #[test]
    fn nfs_with_write_overlay_keeps_archive() {
        let a = Args::try_parse_from([
            "ratarmount",
            "--nfs",
            "--write-overlay",
            "/tmp/ov",
            "testdata.tar.gz",
        ])
        .expect("parse");
        assert!(a.nfs);
        assert_eq!(
            a.write_overlay.as_deref(),
            Some(std::path::Path::new("/tmp/ov"))
        );
        assert_eq!(a.paths, vec![PathBuf::from("testdata.tar.gz")]);
    }

    #[test]
    fn nfs_bind_and_mountpoint() {
        let a = Args::try_parse_from([
            "ratarmount",
            "--nfs",
            "--nfs-bind",
            "0.0.0.0:20490",
            "a.tar",
            "mnt",
        ])
        .expect("parse");
        assert!(a.nfs);
        assert_eq!(a.nfs_bind, "0.0.0.0:20490");
        assert_eq!(a.paths, vec![PathBuf::from("a.tar"), PathBuf::from("mnt")]);
    }

    #[test]
    fn nfs_vers_default_is_3() {
        let a = Args::try_parse_from(["ratarmount", "--nfs", "a.tar"]).expect("parse");
        assert!(a.nfs);
        assert_eq!(a.nfs_vers, "3");
        assert_eq!(
            ratarmount_nfs::parse_nfs_vers(&a.nfs_vers).unwrap(),
            ratarmount_nfs::NfsVers::V3
        );
    }

    /// Regression: required-value `--nfs-vers 4` must not steal the archive.
    #[test]
    fn nfs_vers_4_does_not_steal_archive() {
        let a = Args::try_parse_from(["ratarmount", "--nfs", "--nfs-vers", "4", "testdata.tar.gz"])
            .expect("parse");
        assert!(a.nfs);
        assert_eq!(a.nfs_vers, "4");
        assert_eq!(a.paths, vec![PathBuf::from("testdata.tar.gz")]);
    }

    #[test]
    fn nfs_vers_ignored_without_nfs() {
        let a = Args::try_parse_from(["ratarmount", "--nfs-vers", "4", "archive.tar.gz", "mnt"])
            .expect("parse");
        assert!(!a.nfs);
        assert_eq!(a.nfs_vers, "4");
        assert_eq!(
            a.paths,
            vec![PathBuf::from("archive.tar.gz"), PathBuf::from("mnt")]
        );
        // Vers gate is only applied when `nfs` is set (see main).
    }

    /// `--nfs --nfs-vers testdata.tar.gz` treats the archive as the version
    /// string. clap succeeds; `parse_nfs_vers` then fails (exit 2). Acceptable.
    #[test]
    fn nfs_vers_missing_value_exits_2() {
        let a = Args::try_parse_from(["ratarmount", "--nfs", "--nfs-vers", "testdata.tar.gz"])
            .expect("clap treats archive as version value");
        assert_eq!(a.nfs_vers, "testdata.tar.gz");
        assert!(a.paths.is_empty());
        assert!(ratarmount_nfs::parse_nfs_vers(&a.nfs_vers).is_err());
    }

    #[test]
    fn nfs_vers_40_rejected() {
        assert_eq!(
            ratarmount_nfs::parse_nfs_vers("4.0").unwrap_err(),
            ratarmount_nfs::NfsVersError::V40NotSupported
        );
    }

    #[cfg(not(feature = "nfsv4"))]
    #[test]
    fn nfs_vers_4_rejected_without_feature() {
        assert_eq!(
            ratarmount_nfs::parse_nfs_vers("4").unwrap_err(),
            ratarmount_nfs::NfsVersError::FeatureRequired
        );
    }

    #[cfg(feature = "nfsv4")]
    #[test]
    fn nfs_vers_4_accepted() {
        assert_eq!(
            ratarmount_nfs::parse_nfs_vers("4").unwrap(),
            ratarmount_nfs::NfsVers::V4
        );
        assert_eq!(
            ratarmount_nfs::parse_nfs_vers("4.1").unwrap(),
            ratarmount_nfs::NfsVers::V4
        );
    }

    #[test]
    fn nfs_vers_ready_line_v3() {
        let opts = ratarmount_nfs::NfsOptions {
            bind: "127.0.0.1:20490".parse().unwrap(),
            vers: ratarmount_nfs::NfsVers::V3,
            ..ratarmount_nfs::NfsOptions::default()
        };
        let line = super::nfs_ready_line(&opts, 20490);
        assert!(line.contains("NFSv3"), "{line}");
        assert!(
            line.contains("vers=3,tcp,nolock,port=20490,mountport=20490"),
            "{line}"
        );
    }

    #[cfg(feature = "nfsv4")]
    #[test]
    fn nfs_vers_ready_line_v4() {
        let opts = ratarmount_nfs::NfsOptions {
            bind: "127.0.0.1:20490".parse().unwrap(),
            vers: ratarmount_nfs::NfsVers::V4,
            ..ratarmount_nfs::NfsOptions::default()
        };
        let line = super::nfs_ready_line(&opts, 20490);
        assert!(line.contains("NFSv4.1"), "{line}");
        assert!(line.contains("vers=4.1,tcp,port=20490,sec=sys"), "{line}");
        assert!(!line.contains("mountport="), "{line}");
        assert!(!line.contains("nolock"), "{line}");
    }
}

#[cfg(test)]
mod export_cli_tests {
    use super::{export_incompatible_with_no_mount, index_id_cli_error, Args};
    use clap::Parser;
    use std::path::PathBuf;

    fn archive_paths(a: &Args) -> Vec<PathBuf> {
        a.paths.clone()
    }

    /// Regression: boolean `--http` must not steal the archive path.
    #[test]
    fn http_flag_does_not_steal_archive() {
        let a = Args::try_parse_from(["ratarmount", "--http", "testdata.tar.gz"]).expect("parse");
        assert!(a.http);
        assert_eq!(archive_paths(&a), vec![PathBuf::from("testdata.tar.gz")]);
        assert_eq!(a.http_bind, "127.0.0.1:20491");
    }

    #[test]
    fn http_bind_required_value_does_not_steal_archive() {
        let a = Args::try_parse_from([
            "ratarmount",
            "--http",
            "--http-bind",
            "127.0.0.1:20491",
            "a.tar",
        ])
        .expect("parse");
        assert!(a.http);
        assert_eq!(a.http_bind, "127.0.0.1:20491");
        assert_eq!(archive_paths(&a), vec![PathBuf::from("a.tar")]);
    }

    /// Regression: boolean `--publish-index` must not steal the archive path.
    #[test]
    fn publish_index_flag_does_not_steal_archive() {
        let a = Args::try_parse_from(["ratarmount", "--publish-index", "a.tar"]).expect("parse");
        assert!(a.publish_index);
        assert!(a.publish_index_to.is_none());
        assert_eq!(archive_paths(&a), vec![PathBuf::from("a.tar")]);
    }

    /// Regression: Hub publish flags must preserve URL and mountpoint operands.
    #[test]
    fn publish_index_hf_revision_and_create_pr_preserve_operands() {
        let args = Args::try_parse_from([
            "ratarmount",
            "--publish-index",
            "--publish-revision",
            "feature/new",
            "--create-pr",
            "hf://datasets/org/data/a.tar",
        ])
        .unwrap();
        assert!(args.publish_index && args.create_pr);
        assert_eq!(args.publish_revision.as_deref(), Some("feature/new"));
        assert_eq!(
            args.paths,
            vec![PathBuf::from("hf://datasets/org/data/a.tar")]
        );
        let args = Args::try_parse_from([
            "ratarmount",
            "--publish-index-to",
            "s3://bucket/a.tar",
            "a.tar",
        ])
        .unwrap();
        assert_eq!(
            args.publish_index_to.as_deref(),
            Some(std::path::Path::new("s3://bucket/a.tar"))
        );
        assert_eq!(args.paths, vec![PathBuf::from("a.tar")]);
    }

    /// Regression: --create-pr must be accepted for live Hub overlays without stealing either operand.
    #[test]
    fn regression_hf_live_create_pr_cli_preserves_archive_and_mountpoint() {
        let args = Args::try_parse_from([
            "ratarmount",
            "-w",
            "overlay",
            "--commit-overlay-interval",
            "1s",
            "--create-pr",
            "hf://datasets/org/data@main/a.tar.zst",
            "mnt",
        ])
        .unwrap();
        let (inputs, mountpoint) = super::split_bound_inputs_mountpoint(&args);
        assert_eq!(mountpoint, Some(PathBuf::from("mnt")));
        assert_eq!(
            inputs,
            vec![PathBuf::from("hf://datasets/org/data@main/a.tar.zst")]
        );
        let live_pr = crate::overlay_commit::live_hf_create_pr(
            &inputs,
            &args.commit_overlay_interval,
            args.commit_overlay_on_exit,
            args.create_pr,
        );
        assert!(live_pr);
        crate::publish_index::validate_publish_options(
            false,
            &inputs,
            None,
            None,
            args.create_pr && !live_pr,
        )
        .unwrap();
    }

    /// Regression: `--publish-index-to PATH` is `num_args = 1` (not `0..=1`).
    #[test]
    fn publish_index_to_required_value_does_not_steal_archive() {
        let a = Args::try_parse_from([
            "ratarmount",
            "--publish-index-to",
            "/tmp/out.index.sqlite",
            "a.tar",
        ])
        .expect("parse");
        assert_eq!(
            a.publish_index_to.as_deref(),
            Some(std::path::Path::new("/tmp/out.index.sqlite"))
        );
        assert_eq!(archive_paths(&a), vec![PathBuf::from("a.tar")]);
    }

    #[test]
    fn publish_index_to_without_value_is_clap_error() {
        let err = Args::try_parse_from(["ratarmount", "--publish-index-to"]).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("publish-index-to") || msg.contains("required") || msg.contains("value"),
            "{msg}"
        );
    }

    /// Regression: `--index-id HEX` is `num_args = 1` (not `0..=1`).
    #[test]
    fn index_id_required_value_does_not_steal_archive() {
        let hex = "a".repeat(64);
        let a = Args::try_parse_from(["ratarmount", "--index-id", &hex, "a.tar"]).expect("parse");
        assert_eq!(a.index_id.as_deref(), Some(hex.as_str()));
        assert_eq!(archive_paths(&a), vec![PathBuf::from("a.tar")]);
    }

    #[test]
    fn index_id_without_value_is_clap_error() {
        let err = Args::try_parse_from(["ratarmount", "--index-id"]).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("index-id") || msg.contains("required") || msg.contains("value"),
            "{msg}"
        );
    }

    /// Regression: `--index-id HEX ARCHIVE` must not treat HEX as ARCHIVE.
    #[test]
    fn index_id_flag_does_not_steal_archive() {
        let a = Args::try_parse_from([
            "ratarmount",
            "--index-id",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "testdata.tar.gz",
        ])
        .expect("parse");
        assert!(a.index_id.is_some());
        assert_eq!(archive_paths(&a), vec![PathBuf::from("testdata.tar.gz")]);
        assert!(index_id_cli_error(&a).is_none());
    }

    #[test]
    fn index_id_refuses_recreate_index() {
        let hex = "a".repeat(64);
        let a =
            Args::try_parse_from(["ratarmount", "--index-id", &hex, "-c", "a.tar"]).expect("parse");
        assert_eq!(
            index_id_cli_error(&a),
            Some("--index-id cannot be combined with -c / --recreate-index")
        );
    }

    #[test]
    fn index_id_refuses_hashes_fill() {
        let hex = "a".repeat(64);
        let a = Args::try_parse_from([
            "ratarmount",
            "--index-id",
            &hex,
            "--hashes",
            "sha256",
            "a.tar",
        ])
        .expect("parse");
        assert_eq!(
            index_id_cli_error(&a),
            Some("--index-id cannot be combined with --hashes")
        );
    }

    #[test]
    fn http_no_mount_is_incompatible() {
        let a =
            Args::try_parse_from(["ratarmount", "--http", "--no-mount", "a.tar"]).expect("parse");
        assert!(a.http);
        assert!(a.no_mount);
        assert_eq!(export_incompatible_with_no_mount(&a), Some("--http"));
    }

    #[test]
    fn nfs_and_http_same_process_parse() {
        let a = Args::try_parse_from(["ratarmount", "--nfs", "--http", "a.tar"]).expect("parse");
        assert!(a.nfs);
        assert!(a.http);
        assert_eq!(archive_paths(&a), vec![PathBuf::from("a.tar")]);
    }

    #[test]
    fn webdav_flag_does_not_steal_archive() {
        let a = Args::try_parse_from(["ratarmount", "--webdav", "a.tar"]).expect("parse");
        assert!(a.webdav);
        assert_eq!(a.webdav_bind, "127.0.0.1:20492");
        assert_eq!(archive_paths(&a), vec![PathBuf::from("a.tar")]);
    }

    #[test]
    fn smb_flag_does_not_steal_archive() {
        let a = Args::try_parse_from(["ratarmount", "--smb", "a.tar"]).expect("parse");
        assert!(a.smb);
        assert_eq!(a.smb_bind, "127.0.0.1:20445");
        assert_eq!(a.smb_share, "ratarmount");
        assert_eq!(archive_paths(&a), vec![PathBuf::from("a.tar")]);
    }

    #[test]
    fn smb_share_required_value_does_not_steal_archive() {
        let a = Args::try_parse_from(["ratarmount", "--smb", "--smb-share", "data", "a.tar"])
            .expect("parse");
        assert_eq!(a.smb_share, "data");
        assert_eq!(archive_paths(&a), vec![PathBuf::from("a.tar")]);
    }

    /// Regression: boolean `--ninep` must not steal the archive path.
    #[test]
    fn ninep_flag_does_not_steal_archive() {
        let a = Args::try_parse_from(["ratarmount", "--ninep", "a.tar"]).expect("parse");
        assert!(a.ninep);
        assert_eq!(a.ninep_bind, "127.0.0.1:20493");
        assert_eq!(archive_paths(&a), vec![PathBuf::from("a.tar")]);
    }

    #[test]
    fn ninep_bind_and_mountpoint() {
        let a = Args::try_parse_from([
            "ratarmount",
            "--ninep",
            "--ninep-bind",
            "0.0.0.0:20493",
            "a.tar",
            "mnt",
        ])
        .expect("parse");
        assert!(a.ninep);
        assert_eq!(a.ninep_bind, "0.0.0.0:20493");
        assert_eq!(
            archive_paths(&a),
            vec![PathBuf::from("a.tar"), PathBuf::from("mnt")]
        );
    }

    #[test]
    fn sftp_flag_does_not_steal_archive() {
        let a = Args::try_parse_from(["ratarmount", "--sftp", "a.tar"]).expect("parse");
        assert!(a.sftp);
        assert_eq!(a.sftp_bind, "127.0.0.1:20222");
        assert_eq!(archive_paths(&a), vec![PathBuf::from("a.tar")]);
    }

    #[test]
    fn sftp_authorized_keys_does_not_steal_archive() {
        let a = Args::try_parse_from([
            "ratarmount",
            "--sftp",
            "--sftp-authorized-keys",
            "/tmp/keys",
            "a.tar",
        ])
        .expect("parse");
        assert_eq!(
            a.sftp_authorized_keys.as_deref(),
            Some(std::path::Path::new("/tmp/keys"))
        );
        assert_eq!(archive_paths(&a), vec![PathBuf::from("a.tar")]);
    }

    #[cfg(not(feature = "sftp-russh"))]
    #[test]
    fn sftp_without_russh_feature_has_rebuild_hint() {
        assert!(!ratarmount_sftp::sftp_russh_compiled());
        assert!(
            ratarmount_sftp::SFTP_RUSSH_HINT.contains("sftp-russh"),
            "{}",
            ratarmount_sftp::SFTP_RUSSH_HINT
        );
    }

    /// Regression: boolean `--sftp-subsystem` must not steal the archive path.
    #[test]
    fn sftp_subsystem_flag_does_not_steal_archive() {
        let a = Args::try_parse_from(["ratarmount", "--sftp-subsystem", "a.tar"]).expect("parse");
        assert!(a.sftp_subsystem);
        assert!(!a.sftp);
        assert_eq!(archive_paths(&a), vec![PathBuf::from("a.tar")]);
        assert!(super::any_export(&a));
        assert_eq!(
            export_incompatible_with_no_mount(&a),
            Some("--sftp-subsystem")
        );
        assert!(super::sftp_export_cli_error(&a).is_none());
    }

    /// Regression: `--sftp --sftp-subsystem` is exclusive (main exits 2).
    #[test]
    fn sftp_and_sftp_subsystem_are_exclusive() {
        let a = Args::try_parse_from(["ratarmount", "--sftp", "--sftp-subsystem", "a.tar"])
            .expect("parse");
        assert!(a.sftp);
        assert!(a.sftp_subsystem);
        assert_eq!(archive_paths(&a), vec![PathBuf::from("a.tar")]);
        assert_eq!(
            super::sftp_export_cli_error(&a),
            Some("--sftp and --sftp-subsystem are mutually exclusive")
        );
    }

    #[test]
    fn sftp_subsystem_with_bind_does_not_steal_archive() {
        let a = Args::try_parse_from([
            "ratarmount",
            "--sftp-subsystem",
            "--sftp-bind",
            "0.0.0.0:22",
            "--sftp-authorized-keys",
            "/tmp/keys",
            "a.tar",
        ])
        .expect("parse");
        assert!(a.sftp_subsystem);
        assert_eq!(a.sftp_bind, "0.0.0.0:22");
        assert_eq!(
            a.sftp_authorized_keys.as_deref(),
            Some(std::path::Path::new("/tmp/keys"))
        );
        assert_eq!(archive_paths(&a), vec![PathBuf::from("a.tar")]);
    }

    #[test]
    fn sftp_subsystem_with_http_keeps_archive() {
        let a = Args::try_parse_from(["ratarmount", "--sftp-subsystem", "--http", "a.tar"])
            .expect("parse");
        assert!(a.sftp_subsystem);
        assert!(a.http);
        assert_eq!(archive_paths(&a), vec![PathBuf::from("a.tar")]);
        assert!(super::any_export(&a));
    }

    #[test]
    fn sftp_subsystem_no_mount_is_incompatible() {
        let a = Args::try_parse_from(["ratarmount", "--sftp-subsystem", "--no-mount", "a.tar"])
            .expect("parse");
        assert!(a.sftp_subsystem);
        assert!(a.no_mount);
        assert_eq!(
            export_incompatible_with_no_mount(&a),
            Some("--sftp-subsystem")
        );
    }
}

#[cfg(test)]
mod serve_cli_tests {
    use super::{any_export, parse_args_from, serve_cli_error};
    use std::path::PathBuf;

    /// Regression: `serve --http --nfs a.tar` must not steal the archive path.
    #[test]
    fn serve_http_nfs_does_not_steal_archive() {
        let a =
            parse_args_from(["ratarmount", "serve", "--http", "--nfs", "a.tar"]).expect("parse");
        assert!(a.serve);
        assert!(a.http);
        assert!(a.nfs);
        assert_eq!(a.paths, vec![PathBuf::from("a.tar")]);
        assert!(any_export(&a));
        assert!(serve_cli_error(&a).is_none());
    }

    #[test]
    fn serve_http_bind_does_not_steal_archive() {
        let a = parse_args_from([
            "ratarmount",
            "serve",
            "--http",
            "--http-bind",
            "127.0.0.1:20491",
            "a.tar",
        ])
        .expect("parse");
        assert!(a.serve);
        assert!(a.http);
        assert_eq!(a.http_bind, "127.0.0.1:20491");
        assert_eq!(a.paths, vec![PathBuf::from("a.tar")]);
    }

    #[test]
    fn serve_requires_at_least_one_export() {
        let a = parse_args_from(["ratarmount", "serve", "a.tar"]).expect("parse");
        assert!(a.serve);
        assert!(!any_export(&a));
        assert_eq!(a.paths, vec![PathBuf::from("a.tar")]);
        let err = serve_cli_error(&a).expect("error");
        assert!(err.contains("at least one export"), "{err}");
        assert!(err.contains("--sftp-subsystem"), "{err}");
    }

    /// Regression: `serve --sftp-subsystem a.tar` is a valid export-only process.
    #[test]
    fn serve_sftp_subsystem_does_not_steal_archive() {
        let a =
            parse_args_from(["ratarmount", "serve", "--sftp-subsystem", "a.tar"]).expect("parse");
        assert!(a.serve);
        assert!(a.sftp_subsystem);
        assert_eq!(a.paths, vec![PathBuf::from("a.tar")]);
        assert!(any_export(&a));
        assert!(serve_cli_error(&a).is_none());
    }

    #[test]
    fn serve_no_mount_incompatible() {
        let a = parse_args_from(["ratarmount", "serve", "--http", "--no-mount", "a.tar"])
            .expect("parse");
        assert!(a.serve);
        assert!(a.http);
        assert!(a.no_mount);
        let err = serve_cli_error(&a).expect("error");
        assert!(err.contains("--no-mount"), "{err}");
    }

    /// `serve` after flags is an archive name, not the subcommand.
    #[test]
    fn serve_after_flags_is_archive_path() {
        let a = parse_args_from(["ratarmount", "--http", "serve"]).expect("parse");
        assert!(!a.serve);
        assert!(a.http);
        assert_eq!(a.paths, vec![PathBuf::from("serve")]);
        assert!(serve_cli_error(&a).is_none());
    }

    /// Booleans on the mount CLI remain the stable interface (no subcommand required).
    #[test]
    fn boolean_exports_without_serve_still_parse() {
        let a = parse_args_from(["ratarmount", "--nfs", "--http", "a.tar"]).expect("parse");
        assert!(!a.serve);
        assert!(a.nfs && a.http);
        assert_eq!(a.paths, vec![PathBuf::from("a.tar")]);
        assert!(serve_cli_error(&a).is_none());
    }
}

#[cfg(test)]
mod find_cli_tests {
    use super::{control_reply, find_cli_error, no_unmount, parse_args_from, SearchFn};
    use std::path::PathBuf;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    /// Regression: `find '*.fits' a.tar` does not steal the pattern or archive.
    /// Regression: repeatable xattr filters must not steal the archive or path pattern.
    #[test]
    fn regression_provenance_find_cli_flags() {
        let a = parse_args_from([
            "ratarmount",
            "find",
            "--xattr",
            "train_ok=false",
            "--xattr",
            "teacher",
            "trace.tar",
        ])
        .unwrap();
        assert_eq!(a.find_xattrs, ["train_ok=false", "teacher"]);
        assert_eq!(
            a.paths,
            [
                std::path::PathBuf::from("*"),
                std::path::PathBuf::from("trace.tar")
            ]
        );
        assert!(find_cli_error(&a).is_none());
        assert!(parse_args_from(["ratarmount", "--xattr", "teacher", "trace.tar"]).is_err());
        let a = parse_args_from([
            "ratarmount",
            "--commit-manifest",
            "--manifest-hashes",
            "all",
            "--commit-overlay",
            "-w",
            "ov",
            "trace.tar",
        ])
        .unwrap();
        assert!(a.commit_manifest);
        assert_eq!(a.manifest_hashes, "all");
    }

    #[test]
    fn find_flag_does_not_steal_archive() {
        let a = parse_args_from(["ratarmount", "find", "*.fits", "a.tar"]).expect("parse");
        assert!(a.find);
        assert!(a.no_mount);
        assert!(!a.find_fts);
        assert!(!a.find_hashes);
        assert!(!a.find_offset_order);
        assert_eq!(
            a.paths,
            vec![PathBuf::from("*.fits"), PathBuf::from("a.tar")]
        );
        assert!(find_cli_error(&a).is_none());
    }

    /// Regression: find-argv `--fts` must not steal the pattern or archive.
    #[test]
    fn find_flag_fts_does_not_steal_archive() {
        let a = parse_args_from(["ratarmount", "find", "--fts", "*.fits", "a.tar"]).expect("parse");
        assert!(a.find);
        assert!(a.find_fts);
        assert_eq!(
            a.paths,
            vec![PathBuf::from("*.fits"), PathBuf::from("a.tar")]
        );
        assert!(find_cli_error(&a).is_none());
    }

    /// Regression: boolean find `--hashes` must not steal `*.fits` as an algo list.
    #[test]
    fn find_flag_hashes_does_not_steal_pattern() {
        let a =
            parse_args_from(["ratarmount", "find", "--hashes", "*.fits", "a.tar"]).expect("parse");
        assert!(a.find);
        assert!(a.find_hashes);
        assert!(a.hashes.is_none());
        assert_eq!(
            a.paths,
            vec![PathBuf::from("*.fits"), PathBuf::from("a.tar")]
        );
    }

    #[test]
    fn find_flag_hashes_algo_fill_keeps_pattern() {
        let a = parse_args_from([
            "ratarmount",
            "find",
            "--hashes",
            "sha256",
            "*.fits",
            "a.tar",
        ])
        .expect("parse");
        assert!(a.find);
        assert!(!a.find_hashes);
        assert_eq!(a.hashes.as_deref(), Some("sha256"));
        assert_eq!(
            a.paths,
            vec![PathBuf::from("*.fits"), PathBuf::from("a.tar")]
        );
    }

    /// `--fts` is find-argv only, not a global mount flag.
    #[test]
    fn find_flag_fts_is_not_a_mount_flag() {
        let err = parse_args_from(["ratarmount", "--fts", "a.tar", "mnt"]).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("unexpected") || msg.contains("fts") || msg.contains("unrecognized"),
            "{msg}"
        );
    }

    /// `find` after flags is an archive name, not the subcommand.
    #[test]
    fn find_after_flags_is_archive_path() {
        let a = parse_args_from(["ratarmount", "--no-mount", "find"]).expect("parse");
        assert!(!a.find);
        assert_eq!(a.paths, vec![PathBuf::from("find")]);
    }

    #[test]
    fn find_flag_rejects_write_overlay() {
        let a = parse_args_from(["ratarmount", "find", "-w", "/tmp/ov", "*.fits", "a.tar"])
            .expect("parse");
        let err = find_cli_error(&a).expect("error");
        assert!(err.contains("-w") || err.contains("write-overlay"), "{err}");
    }

    #[test]
    fn find_flag_rejects_nfs() {
        let a = parse_args_from(["ratarmount", "find", "--nfs", "*.fits", "a.tar"]).expect("parse");
        let err = find_cli_error(&a).expect("error");
        assert!(err.contains("--nfs"), "{err}");
        assert_eq!(
            a.paths,
            vec![PathBuf::from("*.fits"), PathBuf::from("a.tar")]
        );
    }

    #[test]
    fn find_flag_requires_pattern_and_archive() {
        let a = parse_args_from(["ratarmount", "find", "a.tar"]).expect("parse");
        let err = find_cli_error(&a).expect("error");
        assert!(err.contains("PATTERN"), "{err}");
    }

    /// Regression: find-argv `--offset-order` must not steal PATTERN/ARCHIVE.
    #[test]
    fn find_flag_offset_order_does_not_steal_archive() {
        let a = parse_args_from(["ratarmount", "find", "--offset-order", "*.fits", "a.tar"])
            .expect("parse");
        assert!(a.find);
        assert!(a.find_offset_order);
        assert!(!a.find_fts);
        assert_eq!(
            a.paths,
            vec![PathBuf::from("*.fits"), PathBuf::from("a.tar")]
        );
        assert!(find_cli_error(&a).is_none());
    }

    #[test]
    fn find_flag_fts_offset_order_does_not_steal_archive() {
        let a = parse_args_from([
            "ratarmount",
            "find",
            "--fts",
            "--offset-order",
            "*.fits",
            "a.tar",
        ])
        .expect("parse");
        assert!(a.find_fts);
        assert!(a.find_offset_order);
        assert_eq!(
            a.paths,
            vec![PathBuf::from("*.fits"), PathBuf::from("a.tar")]
        );
        assert!(find_cli_error(&a).is_none());
    }

    #[test]
    fn find_flag_offset_order_still_requires_pattern() {
        let a = parse_args_from(["ratarmount", "find", "--offset-order", "a.tar"]).expect("parse");
        let err = find_cli_error(&a).expect("error");
        assert!(err.contains("PATTERN"), "{err}");
    }

    /// `--offset-order` is find-argv only, not a global mount flag.
    #[test]
    fn find_flag_offset_order_is_not_a_mount_flag() {
        let err = parse_args_from(["ratarmount", "--offset-order", "a.tar", "mnt"]).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("unexpected")
                || msg.contains("offset-order")
                || msg.contains("unrecognized"),
            "{msg}"
        );
    }

    /// Regression: Unix socket `search <pattern>` returns TSV + `count N`.
    #[test]
    fn control_search_socket() {
        let tsv = "/a.fits\t4\t1\n/dir/b.fits\t5\t2\n";
        let cb: SearchFn = Arc::new({
            let tsv = tsv.to_string();
            move |pat: &str| {
                assert_eq!(pat, "*.fits");
                tsv.clone()
            }
        });
        let stop = AtomicBool::new(false);
        let reply = control_reply(
            "search *.fits",
            std::path::Path::new("/mnt"),
            &stop,
            Some(&cb),
            &no_unmount,
        );
        assert!(reply.contains("/a.fits\t4\t1"), "{reply}");
        assert!(reply.contains("/dir/b.fits\t5\t2"), "{reply}");
        assert!(reply.contains("count 2"), "{reply}");

        let missing = control_reply(
            "search *.fits",
            std::path::Path::new("/mnt"),
            &stop,
            None,
            &no_unmount,
        );
        assert!(
            missing.contains("on-disk index"),
            "socket :memory:/missing: {missing}"
        );

        let no_pat = control_reply(
            "search",
            std::path::Path::new("/mnt"),
            &stop,
            Some(&cb),
            &no_unmount,
        );
        assert!(no_pat.contains("pattern"), "{no_pat}");

        let help = control_reply(
            "help",
            std::path::Path::new("/mnt"),
            &stop,
            Some(&cb),
            &no_unmount,
        );
        assert!(help.contains("search"), "{help}");

        let err_cb: SearchFn =
            Arc::new(|_: &str| "error: search requires an on-disk index\n".into());
        let mem = control_reply(
            "search *.fits",
            std::path::Path::new("/mnt"),
            &stop,
            Some(&err_cb),
            &no_unmount,
        );
        assert!(mem.starts_with("error:"), "{mem}");
        assert!(!mem.contains("count "), "{mem}");
    }

    /// Regression: the control socket answered "ok unmounted" and stopped even when the
    /// unmount failed (busy), leaving a mount nobody could reach.
    #[test]
    fn regression_control_reply_unmount_result() {
        let mp = std::path::Path::new("/mnt");
        for cmd in ["unmount", "quit", "exit"] {
            let stop = AtomicBool::new(false);
            assert_eq!(
                control_reply(cmd, mp, &stop, None, &|_| Ok(())),
                "ok unmounted\n"
            );
            assert!(
                stop.load(std::sync::atomic::Ordering::Relaxed),
                "{cmd}: stop after success"
            );

            let stop = AtomicBool::new(false);
            let busy = |_: &std::path::Path| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::ResourceBusy,
                    "still busy",
                ))
            };
            let reply = control_reply(cmd, mp, &stop, None, &busy);
            assert!(reply.starts_with("error:"), "{cmd}: {reply}");
            assert!(reply.contains("still busy"), "{cmd}: {reply}");
            assert!(
                !stop.load(std::sync::atomic::Ordering::Relaxed),
                "{cmd}: stop after failure"
            );
            assert_eq!(control_reply("ping", mp, &stop, None, &busy), "pong\n");
        }
    }
}

#[cfg(test)]
mod create_missing_cli_tests {
    use super::*;
    use crate::overlay_commit::{maybe_create_missing_write_base, CreateMissingContext};
    use ratarmount_compositing::EmptyCreateOutcome;
    use std::fs;
    use std::path::PathBuf;
    use std::process::Command;

    fn ratarmount_bin() -> Option<PathBuf> {
        if let Some(p) = option_env!("CARGO_BIN_EXE_ratarmount") {
            let path = PathBuf::from(p);
            if path.is_file() {
                return Some(path);
            }
        }
        let mut exe = std::env::current_exe().ok()?;
        exe.pop();
        if exe.file_name().and_then(|s| s.to_str()) == Some("deps") {
            exe.pop();
        }
        exe.push(format!("ratarmount{}", std::env::consts::EXE_SUFFIX));
        exe.is_file().then_some(exe)
    }

    fn run_cli(args: &[&str], cwd: &std::path::Path) -> std::process::Output {
        let _processes = ratarmount_index::test_process::spawning();
        let bin = ratarmount_bin().expect("ratarmount binary next to test exe");
        Command::new(bin)
            .args(args)
            .current_dir(cwd)
            .output()
            .expect("spawn ratarmount")
    }

    fn skip_no_bin() -> bool {
        if ratarmount_bin().is_none() {
            eprintln!("skip: ratarmount binary not built next to test exe");
            return true;
        }
        false
    }

    fn skip_no_gnu_tar() -> bool {
        let _processes = ratarmount_index::test_process::spawning();
        let out = Command::new("tar").arg("--version").output();
        match out {
            Ok(o) => !String::from_utf8_lossy(&o.stdout).contains("GNU tar"),
            Err(_) => true,
        }
    }

    fn open_opts() -> OpenOptions {
        OpenOptions {
            index_in_memory: true,
            write_index: false,
            ..Default::default()
        }
    }

    fn write_tiny_targz(dir: &std::path::Path) -> Option<PathBuf> {
        let _processes = ratarmount_index::test_process::spawning();
        let tree = dir.join("gztree");
        fs::create_dir_all(&tree).unwrap();
        fs::write(tree.join("a.txt"), b"gz\n").unwrap();
        let path = dir.join("existing.tar.gz");
        let ok = Command::new("tar")
            .args(["-czf"])
            .arg(&path)
            .arg("-C")
            .arg(&tree)
            .arg("a.txt")
            .status()
            .map(|s| s.success() && path.is_file())
            .unwrap_or(false);
        if ok {
            Some(path)
        } else {
            eprintln!("skip: tar -czf missing or failed");
            None
        }
    }

    fn write_empty_zip(path: &std::path::Path) {
        let mut bytes = vec![0u8; 22];
        bytes[0] = 0x50;
        bytes[1] = 0x4b;
        bytes[2] = 0x05;
        bytes[3] = 0x06;
        fs::write(path, bytes).unwrap();
    }

    #[test]
    fn s3_commit_offline_rejected() {
        let msg = crate::overlay_commit::offline_remote_commit_error(std::path::Path::new(
            "s3://bucket/a.tar",
        ))
        .expect("s3 offline commit is rejected");
        assert!(msg.contains("does not upload"), "{msg}");
        assert!(
            crate::overlay_commit::offline_remote_commit_error(std::path::Path::new("a.tar"))
                .is_none()
        );
        if skip_no_bin() {
            eprintln!("skip: ratarmount binary not next to the test exe");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let ov = dir.path().join("ov");
        fs::create_dir_all(&ov).unwrap();
        let out = run_cli(
            &[
                "--commit-overlay",
                "-w",
                ov.to_str().unwrap(),
                "s3://bucket/a.tar",
            ],
            dir.path(),
        );
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{err}");
        assert!(err.contains("does not upload"), "{err}");
        assert!(!err.to_ascii_lowercase().contains("aws_secret"), "{err}");
    }

    /// Regression: missing archive.tar is not found without -w
    #[test]
    fn create_missing_without_w_does_not_create() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("archive.tar");
        let err = match factory::build_mount_source_ex(
            std::slice::from_ref(&archive),
            &mut open_opts(),
            false,
            factory::CompositingOptions::default(),
        ) {
            Ok(_) => panic!("expected not found without -w"),
            Err(e) => e,
        };
        assert!(err.contains("not found"), "{err}");
        assert!(!archive.exists());

        if skip_no_bin() {
            return;
        }
        let out = run_cli(
            &[
                "--no-mount",
                "--index-file",
                ":memory:",
                archive.to_str().unwrap(),
            ],
            dir.path(),
        );
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{err}");
        assert!(err.contains("not found"), "{err}");
        assert!(!archive.exists());
    }

    /// Regression: missing .tar.gz refused for write create
    #[test]
    fn create_missing_targz_refused() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar.gz");
        let err = maybe_create_missing_write_base(&archive, CreateMissingContext::Mount)
            .expect_err("refuse gzip");
        assert!(
            err.contains("cannot create") || err.contains("gzip"),
            "{err}"
        );
        assert!(!archive.exists());

        if skip_no_bin() {
            return;
        }
        let ov = dir.path().join("ov");
        let out = run_cli(
            &[
                "-w",
                ov.to_str().unwrap(),
                "--no-mount",
                "--index-file",
                ":memory:",
                archive.to_str().unwrap(),
            ],
            dir.path(),
        );
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{err}");
        assert!(
            err.contains("cannot create") || err.contains("gzip"),
            "{err}"
        );
        assert!(!archive.exists());
    }

    /// Regression: existing .tar.gz / .zip still mount under -w
    #[test]
    fn create_missing_existing_targz_zip_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        // K15 helper: dummy / 0-byte .tar.gz must stay Unchanged without `tar`.
        let dummy_gz = dir.path().join("dummy.tar.gz");
        fs::write(&dummy_gz, [0x1f, 0x8b, 0x08, 0x00]).unwrap();
        let dummy_bytes = fs::read(&dummy_gz).unwrap();
        assert_eq!(
            maybe_create_missing_write_base(&dummy_gz, CreateMissingContext::Mount).unwrap(),
            EmptyCreateOutcome::Unchanged
        );
        assert_eq!(fs::read(&dummy_gz).unwrap(), dummy_bytes);
        let zero_gz = dir.path().join("zero.tar.gz");
        fs::write(&zero_gz, b"").unwrap();
        assert_eq!(
            maybe_create_missing_write_base(&zero_gz, CreateMissingContext::Mount).unwrap(),
            EmptyCreateOutcome::Unchanged
        );
        assert_eq!(fs::read(&zero_gz).unwrap(), b"");

        let zip = dir.path().join("a.zip");
        write_empty_zip(&zip);
        let before_zip = fs::read(&zip).unwrap();
        assert_eq!(
            maybe_create_missing_write_base(&zip, CreateMissingContext::Mount).unwrap(),
            EmptyCreateOutcome::Unchanged
        );
        assert_eq!(fs::read(&zip).unwrap(), before_zip);

        if !skip_no_bin() {
            let ov = dir.path().join("ov");
            let out = run_cli(
                &[
                    "-w",
                    ov.to_str().unwrap(),
                    "--no-mount",
                    "--index-file",
                    ":memory:",
                    zip.to_str().unwrap(),
                ],
                dir.path(),
            );
            assert!(
                out.status.success(),
                "existing zip: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            assert_eq!(fs::read(&zip).unwrap(), before_zip);
        }

        let Some(gz) = write_tiny_targz(dir.path()) else {
            return;
        };
        let before_gz = fs::read(&gz).unwrap();
        assert_eq!(
            maybe_create_missing_write_base(&gz, CreateMissingContext::Mount).unwrap(),
            EmptyCreateOutcome::Unchanged
        );
        assert_eq!(fs::read(&gz).unwrap(), before_gz);
        factory::build_mount_source_ex(
            std::slice::from_ref(&gz),
            &mut open_opts(),
            false,
            factory::CompositingOptions::default(),
        )
        .expect("open existing .tar.gz");

        if skip_no_bin() {
            return;
        }
        // This is a different base from the ZIP above; give it its own identity.
        let ov = dir.path().join("ov-gz");
        let out = run_cli(
            &[
                "-w",
                ov.to_str().unwrap(),
                "--no-mount",
                "--index-file",
                ":memory:",
                gz.to_str().unwrap(),
            ],
            dir.path(),
        );
        assert!(
            out.status.success(),
            "existing gzip: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(fs::read(&gz).unwrap(), before_gz);
    }

    /// Regression: missing .iso under -w stays not found
    #[test]
    fn create_missing_iso_stays_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.iso");
        assert_eq!(
            maybe_create_missing_write_base(&archive, CreateMissingContext::Mount).unwrap(),
            EmptyCreateOutcome::Unchanged
        );
        let err = match factory::build_mount_source_ex(
            std::slice::from_ref(&archive),
            &mut open_opts(),
            false,
            factory::CompositingOptions::default(),
        ) {
            Ok(_) => panic!("expected factory not found for missing .iso"),
            Err(e) => e,
        };
        assert!(err.contains("not found"), "{err}");
        assert!(!archive.exists());

        if skip_no_bin() {
            return;
        }
        let ov = dir.path().join("ov");
        let out = run_cli(
            &[
                "-w",
                ov.to_str().unwrap(),
                "--no-mount",
                "--index-file",
                ":memory:",
                archive.to_str().unwrap(),
            ],
            dir.path(),
        );
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{err}");
        assert!(err.contains("not found"), "{err}");
        assert!(!archive.exists());
    }

    /// Regression: remote URL never creates
    #[test]
    fn create_missing_remote_url_never_creates() {
        let dir = tempfile::tempdir().unwrap();
        let url = PathBuf::from("https://example.com/a.tar");
        assert_eq!(
            maybe_create_missing_write_base(&url, CreateMissingContext::Mount).unwrap(),
            EmptyCreateOutcome::Unchanged
        );
        assert!(!dir.path().join("a.tar").exists());

        if skip_no_bin() {
            return;
        }
        let ov = dir.path().join("ov");
        let out = run_cli(
            &[
                "-w",
                ov.to_str().unwrap(),
                "--no-mount",
                "--index-file",
                ":memory:",
                "https://example.com/a.tar",
            ],
            dir.path(),
        );
        assert!(!dir.path().join("a.tar").exists());
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(!err.contains("parent directory does not exist"), "{err}");
        let _ = out;
    }

    /// Regression: offline --commit-overlay remote URL never creates
    #[test]
    fn create_missing_offline_remote_url_never_creates() {
        let dir = tempfile::tempdir().unwrap();
        let ov = dir.path().join("ov");
        fs::create_dir_all(&ov).unwrap();
        assert_eq!(
            maybe_create_missing_write_base(
                Path::new("https://example.com/a.tar"),
                CreateMissingContext::OfflineCommit
            )
            .unwrap(),
            EmptyCreateOutcome::Unchanged
        );

        if skip_no_bin() {
            return;
        }
        let out = run_cli(
            &[
                "--commit-overlay",
                "-w",
                ov.to_str().unwrap(),
                "--yes",
                "https://example.com/a.tar",
            ],
            dir.path(),
        );
        assert!(!dir.path().join("a.tar").exists());
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(!err.contains("parent directory does not exist"), "{err}");
        assert!(!out.status.success(), "{err}");
    }

    /// Regression: missing archive.tar + -w mounts empty root
    #[test]
    fn create_missing_tar_is_1024_zeros() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("new.tar");
        assert_eq!(
            maybe_create_missing_write_base(&archive, CreateMissingContext::Mount).unwrap(),
            EmptyCreateOutcome::Created
        );
        let bytes = fs::read(&archive).unwrap();
        assert_eq!(bytes.len(), 1024);
        assert!(bytes.iter().all(|&b| b == 0));
        factory::build_mount_source_ex(
            std::slice::from_ref(&archive),
            &mut open_opts(),
            false,
            factory::CompositingOptions::default(),
        )
        .expect("open created .tar");

        if skip_no_bin() {
            return;
        }
        let archive2 = dir.path().join("cli.tar");
        let ov = dir.path().join("ov");
        let out = run_cli(
            &[
                "-w",
                ov.to_str().unwrap(),
                "--no-mount",
                "--index-file",
                ":memory:",
                archive2.to_str().unwrap(),
            ],
            dir.path(),
        );
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let bytes = fs::read(&archive2).unwrap();
        assert_eq!(bytes.len(), 1024);
        assert!(bytes.iter().all(|&b| b == 0));
    }

    /// Regression: offline --commit-overlay missing .tar.zst does not create
    #[test]
    fn create_missing_offline_tar_zst_does_not_create() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("new.tar.zst");
        let err = maybe_create_missing_write_base(&archive, CreateMissingContext::OfflineCommit)
            .expect_err("K13");
        assert!(err.contains("on-exit") || err.contains("interval"), "{err}");
        assert!(!archive.exists());

        if skip_no_bin() {
            return;
        }
        let ov = dir.path().join("ov");
        fs::create_dir_all(&ov).unwrap();
        let out = run_cli(
            &[
                "--commit-overlay",
                "-w",
                ov.to_str().unwrap(),
                "--yes",
                archive.to_str().unwrap(),
            ],
            dir.path(),
        );
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{err}");
        assert!(err.contains("on-exit") || err.contains("interval"), "{err}");
        assert!(!archive.exists());
    }

    /// Regression: offline --commit-overlay missing .tar creates then commits
    #[test]
    fn create_missing_offline_tar_creates_then_commits() {
        if skip_no_gnu_tar() {
            eprintln!("skip: GNU tar missing");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("new.tar");
        let ov = dir.path().join("ov");
        fs::create_dir_all(&ov).unwrap();
        let expected = b"offline-create\n";
        fs::write(ov.join("hello.txt"), expected).unwrap();

        if skip_no_bin() {
            return;
        }
        let out = run_cli(
            &[
                "--commit-overlay",
                "-w",
                ov.to_str().unwrap(),
                "--yes",
                archive.to_str().unwrap(),
            ],
            dir.path(),
        );
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(archive.is_file());
        let extract = dir.path().join("ex");
        fs::create_dir_all(&extract).unwrap();
        let _processes = ratarmount_index::test_process::spawning();
        assert!(Command::new("tar")
            .args(["-xf"])
            .arg(&archive)
            .arg("-C")
            .arg(&extract)
            .status()
            .unwrap()
            .success());
        assert_eq!(fs::read(extract.join("hello.txt")).unwrap(), expected);
    }

    /// Refuse existing dir named `*.tar`
    #[test]
    fn create_missing_refuses_dir_named_tar() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("archive.tar");
        fs::create_dir_all(&archive).unwrap();
        let err = maybe_create_missing_write_base(&archive, CreateMissingContext::Mount)
            .expect_err("dir");
        assert!(err.contains("is a directory"), "{err}");
        assert!(archive.is_dir());

        if skip_no_bin() {
            return;
        }
        let ov = dir.path().join("ov");
        let out = run_cli(
            &[
                "-w",
                ov.to_str().unwrap(),
                "--no-mount",
                "--index-file",
                ":memory:",
                archive.to_str().unwrap(),
            ],
            dir.path(),
        );
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{err}");
        assert!(err.contains("is a directory"), "{err}");
        assert!(archive.is_dir());
    }

    /// Existing dir without createable name → folder bind as today
    #[test]
    fn create_missing_folder_bind_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("dest");
        fs::create_dir_all(&dest).unwrap();
        assert_eq!(
            maybe_create_missing_write_base(&dest, CreateMissingContext::Mount).unwrap(),
            EmptyCreateOutcome::Unchanged
        );
        factory::build_mount_source_ex(
            std::slice::from_ref(&dest),
            &mut open_opts(),
            false,
            factory::CompositingOptions::default(),
        )
        .expect("folder bind");

        if skip_no_bin() {
            return;
        }
        let ov = dir.path().join("ov");
        let out = run_cli(
            &[
                "-w",
                ov.to_str().unwrap(),
                "--no-mount",
                "--index-file",
                ":memory:",
                dest.to_str().unwrap(),
            ],
            dir.path(),
        );
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(dest.is_dir());
    }

    /// Refuse clobber: pre-write secret into a.tar
    #[test]
    fn create_missing_refuses_clobber() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        fs::write(&archive, b"secret").unwrap();
        assert_eq!(
            maybe_create_missing_write_base(&archive, CreateMissingContext::Mount).unwrap(),
            EmptyCreateOutcome::Unchanged
        );
        assert_eq!(fs::read(&archive).unwrap(), b"secret");

        if skip_no_bin() {
            return;
        }
        let ov = dir.path().join("ov");
        let _ = run_cli(
            &[
                "-w",
                ov.to_str().unwrap(),
                "--no-mount",
                "--index-file",
                ":memory:",
                archive.to_str().unwrap(),
            ],
            dir.path(),
        );
        assert_eq!(fs::read(&archive).unwrap(), b"secret");
    }

    /// Regression: the SIGINT (retry only) vs SIGTERM (retry, then lazy) asymmetry was
    /// undocumented in `--help`.
    #[test]
    fn regression_help_documents_signal_unmount() {
        use clap::CommandFactory;
        let cmd = Args::command();
        let find = |long: &str| {
            cmd.get_arguments()
                .find(|a| a.get_long() == Some(long))
                .unwrap_or_else(|| panic!("no --{long}"))
                .get_long_help()
                .map(|h| h.to_string())
                .unwrap_or_default()
        };
        let fg = find("foreground");
        for needle in ["SIGINT", "SIGTERM", "-u -z"] {
            assert!(
                fg.contains(needle),
                "--foreground long help lacks {needle}: {fg}"
            );
        }
        let u = find("unmount");
        assert!(u.contains("fusermount3 -u"), "--unmount long help: {u}");
    }

    #[test]
    fn create_missing_clap_help_mentions_empty_archive() {
        use clap::CommandFactory;
        let help = Args::command().render_long_help().to_string();
        assert!(
            help.contains("missing uncompressed") || help.contains("created as an empty archive"),
            "{help}"
        );
        assert!(help.contains(".tar.zst"), "{help}");
        assert!(
            help.contains("uncompressed `.tar` only")
                || help.contains("uncompressed .tar only")
                || help.contains("remains unsupported offline"),
            "{help}"
        );
    }
}

#[cfg(test)]
mod repack_seekable_cli_tests {
    use super::{
        parse_byte_size, parse_repack_gzip_index, repack_seekable_cli_error,
        run_repack_seekable_cli, Args,
    };
    use clap::Parser;
    use std::fs;
    use std::io::Read;
    use std::path::PathBuf;
    use std::process::Command;
    use std::time::Duration;

    /// Regression: `--repack-seekable` is boolean and must not swallow OUTPUT.
    /// A bare flag is not a path named `--repack-seekable`.
    #[test]
    fn repack_seekable_does_not_steal_output_path() {
        let a = Args::try_parse_from([
            "ratarmount",
            "--repack-seekable",
            "in.tar.gz",
            "out.tar.zst",
        ])
        .expect("parse");
        assert!(a.repack_seekable);
        assert_eq!(
            a.paths,
            vec![PathBuf::from("in.tar.gz"), PathBuf::from("out.tar.zst")]
        );
        assert_eq!(a.repack_gzip_index, "rgzi");
        assert!(a.repack_frame_size.is_none());
        assert!(repack_seekable_cli_error(&a).is_none());

        let indexed = Args::try_parse_from([
            "ratarmount",
            "--repack-seekable",
            "--repack-gzip-index",
            "both",
            "in.gz",
            "out.gz",
        ])
        .expect("gzip index does not steal");
        assert_eq!(indexed.repack_gzip_index, "both");
        assert_eq!(
            indexed.paths,
            vec![PathBuf::from("in.gz"), PathBuf::from("out.gz")]
        );
        assert_eq!(
            parse_repack_gzip_index("both").unwrap(),
            ratarmount_compress::GzipSidecar::Both
        );

        let bare = Args::try_parse_from(["ratarmount", "--repack-seekable"]).expect("bare flag");
        assert!(bare.repack_seekable);
        assert!(
            bare.paths.is_empty(),
            "bare flag must not become a path: {:?}",
            bare.paths
        );
        let err = repack_seekable_cli_error(&bare).expect("exit 2 before mount");
        assert!(err.contains("INPUT OUTPUT"), "{err}");

        let third = Args::try_parse_from([
            "ratarmount",
            "--repack-seekable",
            "in.tar.gz",
            "out.tar.zst",
            "mnt",
        ])
        .expect("three paths still parse");
        assert_eq!(
            repack_seekable_cli_error(&third).as_deref(),
            Some("--repack-seekable does not mount")
        );
    }

    /// Regression: `--repack-frame-size 1M` must not steal `archive.tar`.
    #[test]
    fn repack_seekable_frame_size_1m_does_not_steal_archive() {
        let a = Args::try_parse_from(["ratarmount", "--repack-frame-size", "1M", "archive.tar"])
            .expect("parse");
        assert_eq!(a.paths, vec![PathBuf::from("archive.tar")]);
        assert_eq!(a.repack_frame_size.as_deref(), Some("1M"));
        assert_eq!(parse_byte_size("1M").unwrap(), 1024 * 1024);
        assert_eq!(
            parse_byte_size(a.repack_frame_size.as_deref().unwrap()).unwrap(),
            1024 * 1024
        );

        let both = Args::try_parse_from([
            "ratarmount",
            "--repack-seekable",
            "--repack-frame-size",
            "1M",
            "in.tar",
            "out.tar.zst",
        ])
        .expect("frame size does not steal OUTPUT");
        assert_eq!(
            both.paths,
            vec![PathBuf::from("in.tar"), PathBuf::from("out.tar.zst")]
        );
        assert_eq!(
            parse_byte_size(both.repack_frame_size.as_deref().unwrap()).unwrap(),
            1024 * 1024
        );
    }

    /// Mutual exclusion uses the parsed interval: default `"0"` is off.
    #[test]
    fn repack_seekable_mutual_exclusion_uses_parsed_interval() {
        let off =
            Args::try_parse_from(["ratarmount", "--repack-seekable", "in.tar", "out.tar.zst"])
                .expect("default interval");
        assert_eq!(off.commit_overlay_interval, "0");
        assert_eq!(
            crate::overlay_commit::parse_interval(&off.commit_overlay_interval).unwrap(),
            None
        );
        assert!(repack_seekable_cli_error(&off).is_none());

        let explicit_zero = Args::try_parse_from([
            "ratarmount",
            "--repack-seekable",
            "--commit-overlay-interval",
            "0",
            "in.tar",
            "out.tar.zst",
        ])
        .expect("interval 0");
        assert_eq!(
            crate::overlay_commit::parse_interval(&explicit_zero.commit_overlay_interval).unwrap(),
            None
        );
        assert!(repack_seekable_cli_error(&explicit_zero).is_none());

        let interval = Args::try_parse_from([
            "ratarmount",
            "--repack-seekable",
            "--commit-overlay-interval",
            "2s",
            "in.tar",
            "out.tar.zst",
        ])
        .expect("interval 2s");
        assert_eq!(
            crate::overlay_commit::parse_interval(&interval.commit_overlay_interval).unwrap(),
            Some(Duration::from_secs(2))
        );
        let err = repack_seekable_cli_error(&interval).expect("nonzero interval excluded");
        assert!(err.contains("--commit-overlay-interval"), "{err}");

        let commit = Args::try_parse_from([
            "ratarmount",
            "--repack-seekable",
            "--commit-overlay",
            "-w",
            "/tmp/ov",
            "in.tar",
            "out.tar.zst",
        ])
        .expect("commit-overlay parses");
        let err = repack_seekable_cli_error(&commit).expect("commit excluded");
        assert!(err.contains("--commit-overlay"), "{err}");
        assert!(!err.contains("interval"), "{err}");

        let on_exit = Args::try_parse_from([
            "ratarmount",
            "--repack-seekable",
            "--commit-overlay-on-exit",
            "in.tar",
            "out.tar.zst",
        ])
        .expect("on-exit parses");
        let err = repack_seekable_cli_error(&on_exit).expect("on-exit excluded");
        assert!(err.contains("--commit-overlay-on-exit"), "{err}");
    }

    /// Regression (#80): `--repack-seekable` is exclusive with every export flag,
    /// `-w` / `--write-overlay`, and a FUSE mountpoint (exit 2, OUTPUT untouched).
    #[test]
    fn repack_incompatible_with_export() {
        for flag in [
            "--nfs",
            "--http",
            "--webdav",
            "--smb",
            "--ninep",
            "--sftp",
            "--sftp-subsystem",
        ] {
            let a = Args::try_parse_from([
                "ratarmount",
                flag,
                "--repack-seekable",
                "in.tar.gz",
                "out.tar.zst",
            ])
            .expect("export flag parses");
            let err = repack_seekable_cli_error(&a).expect("export excluded");
            assert!(err.contains("cannot be combined"), "{flag}: {err}");
            assert!(err.contains(flag), "{flag}: {err}");
        }
        for overlay in [["-w", "/tmp/ov"], ["--write-overlay", "/tmp/ov"]] {
            let a = Args::try_parse_from([
                "ratarmount",
                "--repack-seekable",
                overlay[0],
                overlay[1],
                "in.tar.gz",
                "out.tar.zst",
            ])
            .expect("write overlay parses");
            let err = repack_seekable_cli_error(&a).expect("write overlay excluded");
            assert!(err.contains("--write-overlay"), "{}: {err}", overlay[0]);
        }
        let mountpoint = Args::try_parse_from([
            "ratarmount",
            "--repack-seekable",
            "in.tar.gz",
            "out.tar.zst",
            "mnt",
        ])
        .expect("mountpoint parses");
        assert_eq!(
            repack_seekable_cli_error(&mountpoint).as_deref(),
            Some("--repack-seekable does not mount")
        );

        // Exit code 2 before any output is written, with a real gzip input.
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("in.gz");
        // gzip of `hi\n`, mtime 0.
        let gz: &[u8] = &[
            0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xcb, 0xc8, 0xe4, 0x02,
            0x00, 0x7a, 0x7a, 0x6f, 0xed, 0x03, 0x00, 0x00, 0x00,
        ];
        fs::write(&input, gz).unwrap();
        let overlay = dir.path().join("ov");
        let output = dir.path().join("out.tar.zst");
        for extra in [
            vec!["--nfs".to_string()],
            vec!["-w".to_string(), overlay.to_str().unwrap().to_string()],
        ] {
            let argv = std::iter::once("ratarmount".to_string())
                .chain(extra.iter().cloned())
                .chain([
                    "--repack-seekable".to_string(),
                    input.to_str().unwrap().to_string(),
                    output.to_str().unwrap().to_string(),
                ]);
            let parsed = Args::try_parse_from(argv).expect("parse");
            let (code, msg) = run_repack_seekable_cli(&parsed).expect_err("exclusive");
            assert_eq!(code, 2, "{extra:?}: {msg}");
            assert!(msg.contains("cannot be combined"), "{extra:?}: {msg}");
            assert!(!output.exists(), "{extra:?}: OUTPUT must not be written");
        }
    }

    /// Temp-dir gzip → `.tar.zst` using the in-tree decoder, not an external `zstd`.
    #[test]
    fn repack_seekable_gzip_round_trip_without_external_zstd() {
        let _processes = ratarmount_index::test_process::spawning();
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("in.gz");
        let output = dir.path().join("out.tar.zst");
        // gzip of `hi\n`, mtime 0. Produced without the `zstd` or `gzip` CLIs.
        let gz: &[u8] = &[
            0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xcb, 0xc8, 0xe4, 0x02,
            0x00, 0x7a, 0x7a, 0x6f, 0xed, 0x03, 0x00, 0x00, 0x00,
        ];
        fs::write(&input, gz).unwrap();

        // Frame size 1 forces a recompress into multiple frames. A one-frame
        // file under the memory cap is full-decoded (`kind` = "zstd") even
        // when a footer is present.
        let args = [
            "--repack-seekable",
            "--repack-frame-size",
            "1",
            input.to_str().unwrap(),
            output.to_str().unwrap(),
        ];
        if let Some(bin) = ratarmount_bin() {
            let out = Command::new(bin)
                .args(args)
                .current_dir(dir.path())
                .output()
                .expect("spawn ratarmount");
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(out.status.success(), "stdout={stdout} stderr={stderr}");
            assert!(stdout.contains("Repacked"), "{stdout}");
            assert!(stdout.contains("recompressed"), "{stdout}");
        } else {
            let parsed =
                Args::try_parse_from(std::iter::once("ratarmount").chain(args)).expect("parse");
            run_repack_seekable_cli(&parsed).expect("in-process repack");
        }

        let map = ratarmount_compress::scan_zstd_frames_path(&output).expect("scan footer");
        assert!(
            map.seek_table.is_some(),
            "recompress writes a seek-table footer"
        );
        assert!(map.frames.len() > 1, "frame size 1 splits hi\\n");
        let body = ratarmount_compress::open_seekable_zstd(&output).expect("open zst");
        assert_eq!(body.kind(), "zstd-seek-table");
        let mut reader = body.open_reader().unwrap();
        let mut got = Vec::new();
        reader.read_to_end(&mut got).unwrap();
        assert_eq!(got, b"hi\n");
        assert_eq!(fs::read(&input).unwrap(), gz);
    }

    fn ratarmount_bin() -> Option<PathBuf> {
        if let Some(p) = option_env!("CARGO_BIN_EXE_ratarmount") {
            let path = PathBuf::from(p);
            if path.is_file() {
                return Some(path);
            }
        }
        let mut exe = std::env::current_exe().ok()?;
        exe.pop();
        if exe.file_name().and_then(|s| s.to_str()) == Some("deps") {
            exe.pop();
        }
        exe.push(format!("ratarmount{}", std::env::consts::EXE_SUFFIX));
        exe.is_file().then_some(exe)
    }
}

#[cfg(test)]
mod overlay_unmount_drop_tests {
    use super::{finish_overlay_serve, spawn_export_threads_or_exit, ExportPlan};
    use ratarmount_compositing::WriteOverlay;
    use ratarmount_core::{FileInfo, ListResult, MountSource, OpenOptions};
    use std::net::{SocketAddr, TcpListener};
    use std::panic::AssertUnwindSafe;
    use std::sync::{Arc, Mutex, MutexGuard};
    use std::thread;
    use std::time::{Duration, Instant};

    fn lock_term_flag() -> MutexGuard<'static, ()> {
        crate::overlay_commit::term_flag_test_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// `body` runs on another thread. The test fails when that thread is still
    /// inside `finish_overlay_serve`'s interval join at `deadline` (the live
    /// interval thread did not exit). On that timeout the term flag is set so
    /// the interval thread can leave, and this waits for it before returning
    /// the panic.
    fn assert_finishes_within(deadline: Duration, body: impl FnOnce() + Send + 'static) {
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let result = std::panic::catch_unwind(AssertUnwindSafe(body));
            let _ = tx.send(result);
        });
        match rx.recv_timeout(deadline) {
            Ok(Ok(())) => {}
            Ok(Err(payload)) => std::panic::resume_unwind(payload),
            Err(_) => {
                crate::overlay_commit::set_term_flag_for_test(true);
                let _ = rx.recv_timeout(Duration::from_secs(2));
                panic!(
                    "did not return within {deadline:?}; live interval thread still running (request_shutdown missing?)"
                );
            }
        }
    }

    struct EmptyBase;

    impl MountSource for EmptyBase {
        fn list(&self, _: &str) -> Option<ListResult> {
            Some(ListResult::Names(Vec::new()))
        }

        fn lookup(&self, _: &str, _: i32) -> Option<FileInfo> {
            None
        }

        fn open(
            &self,
            _: &FileInfo,
            _: i32,
        ) -> std::io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
            Err(std::io::Error::new(std::io::ErrorKind::NotFound, "empty"))
        }

        fn is_immutable(&self) -> bool {
            true
        }
    }

    struct ResetTerm;

    impl Drop for ResetTerm {
        fn drop(&mut self) {
            crate::overlay_commit::set_term_flag_for_test(false);
        }
    }

    /// Regression: unmount drops the overlay even when a background thread
    /// still holds an Arc. `process::exit` would skip that drop (#88).
    #[test]
    fn finish_overlay_serve_drops_before_exit() {
        let _guard = lock_term_flag();
        let _reset = ResetTerm;
        crate::overlay_commit::set_term_flag_for_test(false);
        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("ov");
        let ov = Arc::new(
            crate::base_identity::fixtures::new_overlay(
                Arc::new(EmptyBase) as Arc<dyn MountSource>,
                &overlay,
            )
            .unwrap(),
        );
        let weak = Arc::downgrade(&ov);
        let held = Arc::clone(&ov);
        let interval = thread::spawn(move || {
            let start = Instant::now();
            while !crate::overlay_commit::term_requested() {
                assert!(
                    start.elapsed() < Duration::from_secs(5),
                    "shutdown was not requested"
                );
                thread::sleep(Duration::from_millis(10));
            }
            drop(held);
        });
        let source: Arc<dyn MountSource> = Arc::clone(&ov) as Arc<dyn MountSource>;
        finish_overlay_serve(Some(ov), Some(source), Some(interval), |_| {});
        assert!(
            weak.upgrade().is_none(),
            "overlay Arc still alive after finish"
        );
    }

    /// Regression: reopening a pending overlay must not launch shared-index cache writes.
    #[test]
    fn regression_prepared_index_worker_leaves_pending_digest_cache_untouched() {
        let _guard = lock_term_flag();
        let _reset = ResetTerm;
        crate::overlay_commit::set_term_flag_for_test(false);
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        let index = dir.path().join("index.sqlite");
        std::fs::write(&archive, b"archive bytes").unwrap();
        rusqlite::Connection::open(&index)
            .unwrap()
            .execute_batch("CREATE TABLE files(name TEXT)")
            .unwrap();
        let overlay = dir.path().join("overlay");
        let source = Arc::new(EmptyBase) as Arc<dyn MountSource>;
        let ov = crate::base_identity::fixtures::overlay_over(
            source.clone(),
            &overlay,
            archive.to_str().unwrap(),
            Vec::new(),
        )
        .unwrap();
        ov.set_meta("base_index_path", index.to_str().unwrap())
            .unwrap();
        assert_eq!(
            ov.pending_base().unwrap().unwrap().index.as_deref(),
            Some(index.as_path())
        );
        drop(ov);
        let ov = Arc::new(
            crate::base_identity::fixtures::overlay_over(
                source,
                &overlay,
                archive.to_str().unwrap(),
                Vec::new(),
            )
            .unwrap(),
        );
        let snapshot = || {
            std::fs::read_dir(dir.path())
                .unwrap()
                .filter_map(|e| {
                    let p = e.unwrap().path();
                    p.is_file().then(|| {
                        (
                            p.file_name().unwrap().to_owned(),
                            std::fs::read(&p).unwrap(),
                        )
                    })
                })
                .collect::<std::collections::BTreeMap<_, _>>()
        };
        let before = snapshot();
        let overlay = Some(ov);
        assert!(super::spawn_interval_if(
            &overlay,
            &None,
            None,
            None,
            &OpenOptions {
                read_only_index: true,
                write_index: false,
                ..Default::default()
            }
        )
        .is_none());
        crate::base_digest::join();
        assert!(overlay.as_ref().unwrap().pending_base().unwrap().is_some());
        assert_eq!(snapshot(), before);
        drop(overlay);
        assert_eq!(snapshot(), before);
    }

    /// Regression: the lazy base-digest thread must be joined before the
    /// overlay drops, or `process::exit` strands `WriteOverlay::drop`.
    #[test]
    fn finish_overlay_serve_joins_base_digest_thread() {
        let _guard = lock_term_flag();
        let _reset = ResetTerm;
        crate::overlay_commit::set_term_flag_for_test(false);
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        std::fs::write(&archive, vec![7u8; 1 << 20]).unwrap();
        let overlay = dir.path().join("ov");
        let ov = Arc::new(
            crate::base_identity::fixtures::overlay_over(
                Arc::new(EmptyBase) as Arc<dyn MountSource>,
                &overlay,
                archive.to_str().unwrap(),
                Vec::new(),
            )
            .unwrap(),
        );
        assert!(ov.pending_base().unwrap().is_some());
        let weak = Arc::downgrade(&ov);
        let ov = Some(ov);
        crate::base_digest::spawn_if_pending(&ov);
        finish_overlay_serve(ov, None, None, |_| {});
        assert!(
            weak.upgrade().is_none(),
            "overlay Arc still alive after finish"
        );
    }

    fn live_interval_thread(
        ov: &Arc<WriteOverlay>,
        archive: std::path::PathBuf,
    ) -> thread::JoinHandle<()> {
        let interval = crate::overlay_commit::spawn_interval_commits(
            Arc::clone(ov),
            archive,
            Duration::from_secs(3600),
            None,
            OpenOptions::default(),
        );
        assert_eq!(
            interval.thread().name(),
            Some("ratarmount-overlay-commit"),
            "expected the production interval-commit thread"
        );
        // Past the first flag check. A thread that already saw shutdown would
        // have returned; one still in the poll sleep must not be finished.
        thread::sleep(Duration::from_millis(80));
        assert!(
            !interval.is_finished(),
            "interval thread exited before finish_overlay_serve"
        );
        interval
    }

    /// Regression: `finish_overlay_serve` must `request_shutdown` or the real
    /// interval-commit thread never leaves its poll loop and the join hangs.
    /// A stand-in thread that checks the flag itself does not catch that:
    /// its panic is swallowed by `let _ = handle.join()`.
    #[test]
    fn finish_overlay_serve_joins_live_interval_thread() {
        let _guard = lock_term_flag();
        let _reset = ResetTerm;
        crate::overlay_commit::set_term_flag_for_test(false);
        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("ov");
        let ov = Arc::new(
            crate::base_identity::fixtures::new_overlay(
                Arc::new(EmptyBase) as Arc<dyn MountSource>,
                &overlay,
            )
            .unwrap(),
        );
        let weak = Arc::downgrade(&ov);
        let interval = live_interval_thread(&ov, dir.path().join("archive.tar"));
        let source: Arc<dyn MountSource> = Arc::clone(&ov) as Arc<dyn MountSource>;
        let deadline = Duration::from_secs(2);
        let started = Instant::now();
        assert_finishes_within(deadline, move || {
            finish_overlay_serve(Some(ov), Some(source), Some(interval), |_| {});
        });
        assert!(
            started.elapsed() < deadline,
            "finish_overlay_serve took too long; interval thread did not exit promptly"
        );
        assert!(
            weak.upgrade().is_none(),
            "overlay Arc still alive after the interval thread was joined"
        );
    }

    /// Regression: a bind failure after another listener is up must stop that
    /// listener, join the live interval thread, and drop the overlay (final
    /// pending-row replay) instead of `process::exit` skipping `Drop`.
    /// Exit code stays 1 and the stderr line stays `error starting … server:`.
    #[test]
    fn export_bind_failure_drops_overlay() {
        let _guard = lock_term_flag();
        let _reset = ResetTerm;
        crate::overlay_commit::set_term_flag_for_test(false);
        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("ov");
        let ov = Arc::new(
            crate::base_identity::fixtures::new_overlay(
                Arc::new(EmptyBase) as Arc<dyn MountSource>,
                &overlay,
            )
            .unwrap(),
        );
        let weak = Arc::downgrade(&ov);
        let interval = live_interval_thread(&ov, dir.path().join("archive.tar"));
        let source: Arc<dyn MountSource> = Arc::clone(&ov) as Arc<dyn MountSource>;

        // Hold this port so WebDAV's bind fails after HTTP has already bound.
        let held = TcpListener::bind("127.0.0.1:0").unwrap();
        let occupied = held.local_addr().unwrap();
        let export_stop = ratarmount_http::ExportStop::new();
        let plan = ExportPlan {
            http: Some(ratarmount_http::HttpOptions {
                bind: SocketAddr::from(([127, 0, 0, 1], 0)),
                stop: Some(export_stop.clone()),
                overlay: Some(Arc::clone(&ov)),
                ..ratarmount_http::HttpOptions::default()
            }),
            webdav: Some(ratarmount_http::WebDavOptions {
                bind: occupied,
                stop: Some(export_stop),
                overlay: Some(Arc::clone(&ov)),
                ..ratarmount_http::WebDavOptions::default()
            }),
            smb: None,
            ninep: None,
            sftp: None,
            sftp_stdio: None,
        };

        let seen = Arc::new(Mutex::new(None));
        let seen_hook = Arc::clone(&seen);
        let deadline = Duration::from_secs(2);
        let started = Instant::now();
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let panicked = std::panic::catch_unwind(AssertUnwindSafe(|| {
                spawn_export_threads_or_exit(
                    source,
                    None,
                    plan,
                    Some(ov),
                    Some(interval),
                    move |code, msg| {
                        *seen_hook.lock().unwrap_or_else(|e| e.into_inner()) =
                            Some((code, msg.to_string()));
                        panic!("export bind failure exit");
                    },
                );
            }));
            let _ = tx.send(panicked.is_err());
        });
        let hook_panicked = match rx.recv_timeout(deadline) {
            Ok(panicked) => panicked,
            Err(_) => {
                crate::overlay_commit::set_term_flag_for_test(true);
                let _ = rx.recv_timeout(Duration::from_secs(2));
                panic!(
                    "export bind failure did not return within {deadline:?}; interval or listener thread still running"
                );
            }
        };
        assert!(hook_panicked, "bind failure returned instead of exiting");
        assert!(
            started.elapsed() < deadline,
            "bind-failure cleanup took too long"
        );
        let (code, msg) = seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .expect("exit hook did not run");
        assert_eq!(code, 1, "{msg}");
        assert!(msg.starts_with("error starting WebDAV server:"), "{msg}");
        assert!(msg.contains("in use"), "bind error text changed: {msg}");
        assert!(
            weak.upgrade().is_none(),
            "overlay Arc still alive after bind-failure cleanup (listener or interval thread still holds it)"
        );
        drop(held);
    }

    /// Regression: the control search callback must not keep the overlay alive
    /// after the mount drops its strong refs (#88).
    #[test]
    fn live_search_callback_does_not_pin_overlay() {
        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("ov");
        let ov = Arc::new(
            crate::base_identity::fixtures::new_overlay(
                Arc::new(EmptyBase) as Arc<dyn MountSource>,
                &overlay,
            )
            .unwrap(),
        );
        let weak = Arc::downgrade(&ov);
        let cb = crate::find::live_search_callback(
            Arc::clone(&ov) as Arc<dyn MountSource>,
            Some(Arc::clone(&ov)),
            dir.path().join("archive.tar"),
            OpenOptions::default(),
        );
        let mounted = cb("*");
        assert!(
            !mounted.contains("not mounted"),
            "search while mounted: {mounted}"
        );
        drop(ov);
        assert!(weak.upgrade().is_none(), "callback pinned the overlay");
        let gone = cb("*");
        assert!(
            gone.contains("archive is not mounted"),
            "search after drop: {gone}"
        );
    }
}

#[cfg(test)]
mod git_cli_tests {
    use super::*;

    /// Regression: Git flags must preserve the repository and mountpoint operands.
    #[test]
    fn regression_git_flags_keep_positionals() {
        let args = Args::try_parse_from([
            "ratarmount",
            "--git",
            "--git-ref",
            "HEAD~1",
            "--git-prefix",
            "src",
            "--git-synthetic-head",
            "repo",
            "mnt",
        ])
        .unwrap();
        assert!(args.git);
        assert_eq!(args.git_ref.as_deref(), Some("HEAD~1"));
        assert_eq!(args.git_prefix.as_deref(), Some("src"));
        assert!(args.git_synthetic_head);
        assert_eq!(args.paths, [PathBuf::from("repo"), PathBuf::from("mnt")]);
        let inline = Args::try_parse_from([
            "ratarmount",
            "--git-synthetic-head",
            "repo.git@HEAD~1",
            "mnt",
        ])
        .unwrap();
        assert!(inline.git_synthetic_head);
        assert!(inline.git_ref.is_none());
        assert_eq!(
            inline.paths,
            [PathBuf::from("repo.git@HEAD~1"), PathBuf::from("mnt")]
        );
        assert!(Args::try_parse_from(["ratarmount", "--git-ref"]).is_err());
    }
}

#[cfg(test)]
mod passthrough_cli_tests {
    use super::*;

    /// Regression: merged sandbox, Git and passthrough flags must coexist.
    #[test]
    fn passthrough_flags_coexist_with_sandbox_and_git() {
        let args = parse_args_from([
            "ratarmount",
            "--git",
            "--git-ref",
            "HEAD",
            "--git-prefix",
            "src",
            "--git-synthetic-head",
            "-w",
            "overlay",
            "--overlay-readonly",
            "tests/**",
            "--overlay-quota",
            "2G",
            "--overlay-quota-files",
            "12",
            "--passthrough",
            "off",
            "--passthrough-copy-total-max",
            "0",
            "repo",
            "mnt",
        ])
        .unwrap();
        assert!(args.git && args.git_synthetic_head);
        assert_eq!(args.git_ref.as_deref(), Some("HEAD"));
        assert_eq!(args.git_prefix.as_deref(), Some("src"));
        assert_eq!(args.overlay_readonly, ["tests/**"]);
        assert_eq!(args.overlay_quota, Some(2 << 30));
        assert_eq!(args.overlay_quota_files, Some(12));
        assert_eq!(args.passthrough, PassthroughMode::Off);
        assert_eq!(args.passthrough_copy_total_max, 0);
        assert_eq!(args.paths, [PathBuf::from("repo"), PathBuf::from("mnt")]);
        for invalid in ["nope", "18446744073709551615G"] {
            assert!(Args::try_parse_from([
                "ratarmount",
                "--passthrough-copy-total-max",
                invalid,
                "repo"
            ])
            .is_err());
        }
    }

    /// Regression: passthrough defaults and copy flags must not consume source/mountpoint.
    #[test]
    fn passthrough_flags_preserve_positionals_and_validate_cap() {
        let args = Args::try_parse_from(["ratarmount", "source.tar", "mnt"]).unwrap();
        assert_eq!(args.passthrough, PassthroughMode::Auto);
        assert!(!args.passthrough_copy);
        assert_eq!(args.passthrough_copy_max, 0);
        assert_eq!(args.passthrough_copy_total_max, 1 << 30);
        for mode in ["auto", "on", "off"] {
            let args = Args::try_parse_from([
                "ratarmount",
                "--passthrough",
                mode,
                "--passthrough-copy",
                "--passthrough-copy-max",
                "1M",
                "--passthrough-copy-total-max",
                "8M",
                "source.tar",
                "mnt",
            ])
            .unwrap();
            assert_eq!(
                args.paths,
                vec![PathBuf::from("source.tar"), PathBuf::from("mnt")]
            );
            assert_eq!(args.passthrough, mode.parse().unwrap());
            assert!(args.passthrough_copy);
            assert_eq!(args.passthrough_copy_max, 1024 * 1024);
            assert_eq!(args.passthrough_copy_total_max, 8 << 20);
        }
        assert!(
            Args::try_parse_from(["ratarmount", "--passthrough", "maybe", "source.tar"]).is_err()
        );
        assert!(Args::try_parse_from([
            "ratarmount",
            "--passthrough-copy-max",
            "nope",
            "source.tar"
        ])
        .is_err());
    }
}

#[cfg(test)]
mod sandbox_cli_tests {
    use super::*;

    /// Regression: overlay-stats DIR must use its verb parser, never archive/mountpoint splitting.
    #[test]
    fn regression_overlay_stats_flag_keeps_directory() {
        let args = parse_args_from(["ratarmount", "overlay-stats", "overlay", "--json"]).unwrap();
        assert!(args.paths.is_empty());
        let stats = args.overlay_stats.unwrap();
        assert_eq!(stats.directory, Path::new("overlay"));
        assert!(stats.json);
        assert!(parse_args_from(["ratarmount", "overlay-stats"]).is_err());
        assert!(parse_args_from(["ratarmount", "overlay-stats", "one", "two"]).is_err());
        assert!(parse_args_from(["ratarmount", "overlay-stats", "one", "--nfs"]).is_err());
        let args = parse_args_from(["ratarmount", "--no-mount", "overlay-stats"]).unwrap();
        assert!(args.overlay_stats.is_none());
        assert_eq!(args.paths, [PathBuf::from("overlay-stats")]);
    }

    /// Regression: sandbox flags require -w, preserve positionals and reject invalid rules/sizes.
    #[test]
    fn regression_overlay_policy_flags_require_write_overlay() {
        for flag in [
            "--overlay-readonly",
            "--overlay-allow",
            "--overlay-quota",
            "--overlay-quota-files",
        ] {
            assert!(parse_args_from(["ratarmount", flag, "1", "a.tar", "mnt"]).is_err());
            assert!(parse_args_from([
                "ratarmount",
                "-w",
                "ov",
                "--commit-overlay",
                flag,
                "1",
                "a.tar"
            ])
            .is_err());
        }
        let args = parse_args_from([
            "ratarmount",
            "-w",
            "ov",
            "--overlay-readonly",
            "t/**,tests/**",
            "--overlay-readonly",
            "/src/private",
            "--overlay-quota",
            "2G",
            "--overlay-quota-files",
            "12",
            "a.tar",
            "mnt",
        ])
        .unwrap();
        assert_eq!(args.overlay_readonly, ["t/**", "tests/**", "/src/private"]);
        assert_eq!(args.overlay_quota, Some(2 << 30));
        assert_eq!(args.overlay_quota_files, Some(12));
        assert_eq!(args.paths, [PathBuf::from("a.tar"), PathBuf::from("mnt")]);
        for rule in ["", "../t", "t,,a", "x**y"] {
            assert!(parse_args_from([
                "ratarmount",
                "-w",
                "ov",
                "--overlay-readonly",
                rule,
                "a.tar"
            ])
            .is_err());
        }
        assert!(parse_args_from([
            "ratarmount",
            "-w",
            "ov",
            "--overlay-quota",
            "18446744073709551615G",
            "a.tar"
        ])
        .is_err());
    }
    /// Regression: a single allow value must not consume the archive positional,
    /// and exceptions require read-only rules and a writable overlay target.
    #[test]
    fn regression_overlay_allow_keeps_archive_and_requires_readonly() {
        for target in [vec!["-w", "ov"], vec!["--overlay-tmpfs"], vec!["--sandbox"]] {
            let args = parse_args_from(["ratarmount"].into_iter().chain(target).chain([
                "--overlay-readonly",
                "t/**",
                "--overlay-allow",
                "t/agent/**,t/extra/**",
                "--overlay-allow",
                "t/new/**",
                "a.tar",
                "mnt",
            ]))
            .unwrap();
            assert_eq!(args.overlay_allow, ["t/agent/**", "t/extra/**", "t/new/**"]);
            assert_eq!(args.paths, [PathBuf::from("a.tar"), PathBuf::from("mnt")]);
        }
        assert!(parse_args_from([
            "ratarmount",
            "-w",
            "ov",
            "--overlay-allow",
            "t/agent/**",
            "a.tar"
        ])
        .is_err());
        for bad in ["", "x**y", "../t", "a,,b", "a/./b"] {
            assert!(
                parse_args_from([
                    "ratarmount",
                    "-w",
                    "ov",
                    "--overlay-readonly",
                    "t/**",
                    "--overlay-allow",
                    bad,
                    "a.tar"
                ])
                .is_err(),
                "{bad}"
            );
        }
    }

    /// Regression: the control socket file name format and its Drop unlink.
    #[test]
    fn regression_control_socket_guard_removes_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = control_socket_path(dir.path(), 4242);
        assert_eq!(path, dir.path().join("ratarmount-control-4242.sock"));
        std::fs::write(&path, b"").unwrap();
        let other = control_socket_path(dir.path(), 1);
        std::fs::write(&other, b"").unwrap();
        drop(ControlSocket(path.clone()));
        assert!(!path.exists());
        assert!(other.exists(), "another pid's socket must survive");
        drop(ControlSocket(path));
    }

    /// Regression (I1): the exit path must wait for an unmount reply that is still being written.
    #[test]
    fn regression_control_inflight_idle_returns_immediately() {
        let inflight = ControlInflight::default();
        let t = Instant::now();
        assert!(inflight.wait_idle(Duration::from_secs(5)));
        assert!(t.elapsed() < Duration::from_millis(500));
    }

    #[test]
    fn regression_control_inflight_waits_for_guard_drop() {
        let inflight = ControlInflight::default();
        let guard = inflight.enter();
        let t = Instant::now();
        let h = thread::spawn(move || {
            thread::sleep(Duration::from_millis(150));
            drop(guard);
        });
        assert!(inflight.wait_idle(Duration::from_secs(5)));
        assert!(t.elapsed() >= Duration::from_millis(100));
        h.join().unwrap();
    }

    #[test]
    fn regression_control_inflight_never_dropped_returns_at_bound() {
        let inflight = ControlInflight::default();
        let _guard = inflight.enter();
        let t = Instant::now();
        assert!(!inflight.wait_idle(Duration::from_millis(100)));
        let took = t.elapsed();
        assert!(took >= Duration::from_millis(100), "{took:?}");
        assert!(took < Duration::from_secs(3), "{took:?}");
    }

    /// A panic while answering must not leave the exit path waiting for the full bound.
    #[test]
    fn regression_control_inflight_guard_dropped_on_panic() {
        let inflight = ControlInflight::default();
        let tracker = inflight.clone();
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _g = tracker.enter();
            panic!("handler panic");
        }));
        assert!(r.is_err());
        assert!(inflight.wait_idle(Duration::from_millis(200)));
    }

    /// Regression: socket status includes the same live policy fields as the virtual file.
    #[test]
    fn regression_control_socket_quota_status() {
        let root = tempfile::tempdir().unwrap();
        use ratarmount_compositing::{OverlayMutation, OverlayPolicy, OverlayQuota, ReadOnlyGlobs};
        let rules = Arc::new(ReadOnlyGlobs::with_allow(["t/**"], ["t/agent/**"]).unwrap());
        let quota = OverlayQuota::new(root.path(), Some(1024), None)
            .unwrap()
            .with_readonly(rules.clone());
        let stop = AtomicBool::new(false);
        let reply = control_reply_with_quota(
            "status",
            Path::new("/mnt"),
            &stop,
            None,
            Some(&quota),
            &no_unmount,
        );
        assert!(reply.starts_with("mounted /mnt\nmemory_budget unlimited\n"));
        assert!(reply.ends_with("overlay_bytes 0\noverlay_quota_bytes 1024\noverlay_files 0\noverlay_quota_files unlimited\nerofs_denied 0\n"));
        assert_eq!(
            control_reply_with_quota(
                "ping",
                Path::new("/mnt"),
                &stop,
                None,
                Some(&quota),
                &no_unmount
            ),
            "pong\n"
        );
        assert!(rules
            .check_mutation(OverlayMutation::Create, &["/t/blocked"])
            .is_err());
        let reply = control_reply_with_quota(
            "status",
            Path::new("/mnt"),
            &stop,
            None,
            Some(&quota),
            &no_unmount,
        );
        assert!(reply.ends_with("erofs_denied 1\n"));
        let unlimited = OverlayQuota::new(root.path(), None, None)
            .unwrap()
            .with_readonly(rules);
        let reply = control_reply_with_quota(
            "status",
            Path::new("/mnt"),
            &stop,
            None,
            Some(&unlimited),
            &no_unmount,
        );
        assert!(reply.contains("overlay_quota_bytes unlimited\n"));
        assert!(reply.ends_with("erofs_denied 1\n"));
    }
}

#[cfg(test)]
mod sandbox_preset_tests {
    use super::*;

    /// Regression: sandbox defaults must respect explicit overlay, ownership and passthrough settings.
    #[test]
    fn regression_sandbox_expansion_preserves_explicit_options() {
        let mut args =
            Args::try_parse_from(["ratarmount", "--sandbox", "source.tar", "mnt"]).unwrap();
        expand_sandbox(&mut args, (1001, 1002)).unwrap();
        assert_eq!(args.overlay_tmpfs.as_deref(), Some(""));
        assert_eq!(args.write_overlay.as_deref(), Some(Path::new(":temp:")));
        assert_eq!(args.passthrough, PassthroughMode::Auto);
        let mapping = ratarmount_core::AttributeMapping::parse(&args.fuse).unwrap();
        assert_eq!((mapping.uid, mapping.gid), (Some(1001), Some(1002)));
        assert!(args.fuse.contains("allow_other,noatime"));
        let mut args = Args::try_parse_from([
            "ratarmount",
            "--sandbox",
            "-w",
            "persistent",
            "-o",
            "uid=12345,gid=23456,umask=027",
            "--passthrough",
            "off",
            "source.tar",
            "mnt",
        ])
        .unwrap();
        expand_sandbox(&mut args, (1, 2)).unwrap();
        assert!(args.overlay_tmpfs.is_none());
        assert_eq!(args.write_overlay.as_deref(), Some(Path::new("persistent")));
        let mapping = ratarmount_core::AttributeMapping::parse(&args.fuse).unwrap();
        assert_eq!(
            (mapping.uid, mapping.gid, mapping.umask),
            (Some(12345), Some(23456), 0o027)
        );
        assert_eq!(args.passthrough, PassthroughMode::Off);
    }

    /// Regression: optional tmpfs size must not consume archive/mountpoint or weaken an explicit quota.
    #[test]
    fn regression_overlay_tmpfs_clap_caps_and_conflicts() {
        for (flag, quota) in [
            ("--overlay-tmpfs", None),
            ("--overlay-tmpfs=2G", Some(2 << 30)),
        ] {
            let args = parse_args_from(["ratarmount", flag, "source.tar", "mnt"]).unwrap();
            assert_eq!(
                args.paths,
                [PathBuf::from("source.tar"), PathBuf::from("mnt")]
            );
            assert_eq!(args.overlay_quota, quota);
        }
        let args = parse_args_from([
            "ratarmount",
            "--sandbox",
            "--overlay-quota",
            "1M",
            "source.tar",
        ])
        .unwrap();
        assert_eq!(args.overlay_quota, Some(1 << 20));
        let args = parse_args_from([
            "ratarmount",
            "--overlay-tmpfs=2G",
            "--overlay-quota",
            "1M",
            "source.tar",
        ])
        .unwrap();
        assert_eq!(args.overlay_quota, Some(1 << 20));
        for tail in [
            vec!["-w", "persistent"],
            vec!["--commit-overlay"],
            vec!["--commit-overlay-on-exit"],
            vec!["--commit-overlay-interval", "2s"],
        ] {
            assert!(
                parse_args_from(["ratarmount", "--overlay-tmpfs"].into_iter().chain(tail)).is_err()
            );
        }
        assert!(parse_args_from(["ratarmount", "--overlay-tmpfs=bad"]).is_err());
        assert!(parse_args_from(["ratarmount", "-o", "uid=bad"]).is_err());
        assert!(parse_args_from([
            "ratarmount",
            "--overlay-tmpfs",
            "--overlay-tmpfs-allow-commit",
            "--commit-overlay-on-exit",
            "source.tar",
            "mnt"
        ])
        .is_ok());
    }

    /// Regression: the daemon parent must relinquish cleanup while the serving child retains it.
    #[test]
    fn regression_temp_overlay_daemon_parent_preserves_child_directory() {
        let _processes = ratarmount_index::test_process::spawning();
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("child-owned");
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "sandbox_preset_tests::temp_overlay_daemon_cleanup_child",
                "--nocapture",
            ])
            .env("RATARMOUNT_SB3_CLEANUP_TEST", &marker)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            std::fs::read_to_string(&marker).unwrap(),
            "child retained overlay"
        );
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn temp_overlay_daemon_cleanup_child() {
        let _processes = ratarmount_index::test_process::spawning();
        let Some(marker) = std::env::var_os("RATARMOUNT_SB3_CLEANUP_TEST").map(PathBuf::from)
        else {
            return;
        };
        let directory = tempfile::tempdir_in(marker.parent().unwrap()).unwrap();
        let path = directory.path().to_path_buf();
        register_temp_overlay(directory);
        match unsafe { fork() }.unwrap() {
            ForkResult::Parent { child } => {
                relinquish_temp_overlay();
                let status = nix::sys::wait::waitpid(child, None).unwrap();
                assert_eq!(status, nix::sys::wait::WaitStatus::Exited(child, 0));
                assert!(!path.exists());
            }
            ForkResult::Child => {
                std::thread::sleep(Duration::from_millis(100));
                assert!(path.exists(), "parent removed child's overlay");
                std::fs::write(marker, "child retained overlay").unwrap();
                // The atexit handler must run even though Rust locals don't drop.
                std::process::exit(0);
            }
        }
    }

    /// Regression: RAM overlays must be private, actually on tmpfs, and removed on drop.
    #[cfg(target_os = "linux")]
    #[test]
    fn regression_overlay_tmpfs_private_directory_removed_on_drop() {
        use std::os::unix::fs::PermissionsExt;
        let runtime = tempfile::tempdir().unwrap();
        let directory = match create_tmpfs_overlay_in(Path::new("/dev/shm"), None) {
            Ok(directory) => directory,
            Err(error) => {
                eprintln!("skip: direct /dev/shm creation is unavailable ({error}); checking runtime tmpfs fallback");
                match create_tmpfs_overlay_in(
                    Path::new("/nonexistent-ratarmount-shm"),
                    Some(runtime.path()),
                ) {
                    Ok(directory) => directory,
                    Err(error) => {
                        eprintln!("skip: no writable tmpfs: {error}");
                        return;
                    }
                }
            }
        };
        let path = directory.path().to_path_buf();
        let parent = path.parent().unwrap().to_path_buf();
        assert!(path.starts_with("/dev/shm") || path.starts_with(runtime.path()));
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o700
        );
        drop(directory);
        assert!(!path.exists());
        let fallback =
            create_tmpfs_overlay_in(Path::new("/nonexistent-ratarmount-shm"), Some(&parent))
                .unwrap();
        assert!(fallback.path().starts_with(parent));
        assert!(create_tmpfs_overlay_in(Path::new("/proc"), None).is_err());
    }
}

#[cfg(test)]
mod corpus_cli_tests {
    use super::*;

    /// Regression: --bind consumed the mountpoint or split URL query equals signs.
    #[test]
    fn regression_bind_flag_preserves_positionals() {
        let args = parse_args_from([
            "ratarmount",
            "image.tar",
            "--bind",
            "/repo=repo.git@abc",
            "--bind",
            "/data=https://host/file?x=y",
            "mnt",
        ])
        .unwrap();
        assert_eq!(
            args.paths,
            [PathBuf::from("image.tar"), PathBuf::from("mnt")]
        );
        assert_eq!(args.source_binds.len(), 2);
        assert_eq!(args.source_binds[1].source, "https://host/file?x=y");
        assert!(parse_args_from(["ratarmount", "--bind", "/../escape=repo", "mnt"]).is_err());
        let bound = parse_args_from([
            "ratarmount",
            "--bind",
            "/repo=repo.git@abc",
            "mnt",
            "--git-synthetic-head",
        ])
        .unwrap();
        assert!(bound.git_synthetic_head);
        assert_eq!(bound.paths, [PathBuf::from("mnt")]);
        assert_eq!(
            split_bound_inputs_mountpoint(&bound),
            (vec![], Some(PathBuf::from("mnt")))
        );
        for flag in ["--ninep", "--nfs"] {
            let export = parse_args_from([
                "ratarmount",
                "serve",
                flag,
                "--bind",
                "/repo=repo.git@abc",
                "docker://ubuntu:24.04",
            ])
            .unwrap();
            assert_eq!(
                split_bound_inputs_mountpoint(&export),
                (vec![PathBuf::from("docker://ubuntu:24.04")], None)
            );
        }
    }

    /// Regression: the corpus verb must only match argv[1] and retain both of its positionals.
    #[test]
    fn regression_corpus_verb_does_not_steal_positionals() {
        let args = parse_args_from([
            "ratarmount",
            "corpus",
            "list.txt",
            "mnt",
            "--corpus-cache-size",
            "8",
            "-f",
        ])
        .unwrap();
        assert_eq!(args.corpus_list, Some(PathBuf::from("list.txt")));
        assert_eq!(
            args.paths,
            [PathBuf::from("list.txt"), PathBuf::from("mnt")]
        );
        assert_eq!(args.corpus_cache_size, 8);
        assert!(args.lazy, "corpus recursion must preserve lazy opening");
        let ordinary = parse_args_from(["ratarmount", "--no-mount", "corpus"]).unwrap();
        assert!(ordinary.corpus_list.is_none());
        assert_eq!(ordinary.paths, [PathBuf::from("corpus")]);
        for argv in [
            vec!["ratarmount", "corpus", "list.txt"],
            vec!["ratarmount", "corpus", "list.txt", "mnt", "-w", "overlay"],
            vec![
                "ratarmount",
                "corpus",
                "list.txt",
                "mnt",
                "--git-ref",
                "HEAD",
            ],
            vec![
                "ratarmount",
                "corpus",
                "list.txt",
                "mnt",
                "--corpus-cache-size",
                "0",
            ],
        ] {
            assert!(parse_args_from(argv).is_err());
        }
    }
}

#[cfg(test)]
mod memory_budget_tests {
    use super::*;

    /// Regression: SIZE parsing must not consume the archive or mountpoint.
    #[test]
    fn regression_memory_budget_flag_and_status() {
        let args =
            parse_args_from(["ratarmount", "--memory-budget", "64M", "a.tar", "mnt"]).unwrap();
        assert_eq!(args.memory_budget, Some(64 * 1024 * 1024));
        assert!(parse_args_from(["ratarmount", "--memory-budget", "invalid", "a.tar"]).is_err());
        let _pool = ratarmount_core::budget::MemoryPool::global(
            "socket-test",
            1,
            ratarmount_core::budget::Priority::Cache,
        );
        let reply = control_reply(
            "status",
            Path::new("mnt"),
            &AtomicBool::new(false),
            None,
            &|_| Ok(()),
        );
        assert!(reply.contains("memory_budget unlimited"));
        assert!(reply.contains("memory_pool socket-test"));
    }
}

#[cfg(test)]
mod rolling_cli_tests {
    use super::*;

    /// Regression: --roll-every consumes exactly its policy and preserves both positional paths.
    #[test]
    fn rolling_flag_preserves_paths_and_flushes_on_exit() {
        let args = parse_args_from(
            [
                "ratarmount",
                "-w",
                "overlay",
                "--roll-every",
                "1d,20G",
                "traces.tar.zst",
                "mnt",
            ]
            .map(OsString::from)
            .to_vec(),
        )
        .unwrap();
        assert_eq!(
            args.paths,
            [PathBuf::from("traces.tar.zst"), PathBuf::from("mnt")]
        );
        assert!(args.commit_overlay_on_exit);
        assert!(args.roll_every.is_some());
        for extra in [
            vec!["--recursive"],
            vec!["--prefix", "inner"],
            vec!["--index-id", "abcd"],
        ] {
            let mut argv = vec![
                "ratarmount",
                "-w",
                "overlay",
                "--roll-every",
                "1d",
                "traces.tar",
                "mnt",
            ];
            argv.extend(extra);
            assert!(parse_args_from(argv).is_err());
        }
        assert!(Args::try_parse_from(["ratarmount", "--roll-every", "1d", "traces.tar"]).is_err());
        assert!(Args::try_parse_from([
            "ratarmount",
            "-w",
            "overlay",
            "--roll-every",
            "0B",
            "traces.tar"
        ])
        .is_err());
        assert!(Args::try_parse_from([
            "ratarmount",
            "-w",
            "overlay",
            "--roll-every",
            "1G",
            "--commit-overlay",
            "traces.tar"
        ])
        .is_err());
    }
}

#[cfg(test)]
mod torrent_policy_tests {
    use super::*;
    /// Regression: swarm policy and disk limit silently used defaults or consumed input positionals.
    #[test]
    fn regression_torrent_policy_and_scratch_cli() {
        let defaults = Args::try_parse_from(["ratarmount", "source.tar", "mnt"]).unwrap();
        assert_eq!(
            defaults.torrent_swarm,
            ratarmount_core::TorrentSwarmPolicy::Never
        );
        assert_eq!(defaults.torrent_scratch_limit, 2 * 1024 * 1024 * 1024);
        for policy in ["auto", "always", "lan", "never"] {
            let args = Args::try_parse_from([
                "ratarmount",
                "--torrent-swarm",
                policy,
                "--torrent-scratch-limit",
                "64M",
                "source.tar",
                "mnt",
            ])
            .unwrap();
            assert_eq!(args.torrent_swarm, policy.parse().unwrap());
            assert_eq!(args.torrent_scratch_limit, 64 * 1024 * 1024);
            assert_eq!(args.paths.len(), 2);
        }
        assert!(
            Args::try_parse_from(["ratarmount", "--torrent-swarm", "bad", "source.tar"]).is_err()
        );
    }
    /// Regression: LAN/seeding flags consumed paths, enabled uploads implicitly, or bypassed never.
    #[test]
    fn regression_torrent_lan_seed_flags_and_conflicts() {
        let defaults = Args::try_parse_from(["ratarmount", "file.torrent"]).unwrap();
        assert_eq!(defaults.torrent_listen_port, 0);
        let defaults = Args::try_parse_from(["ratarmount", "source.torrent", "mnt"]).unwrap();
        assert!(defaults.torrent_lsd);
        assert!(!defaults.seed);
        assert_eq!(defaults.seed_upload_limit, 1024 * 1024);
        let args = Args::try_parse_from([
            "ratarmount",
            "--torrent-swarm",
            "lan",
            "--torrent-lsd",
            "off",
            "--seed",
            "--seed-upload-limit",
            "65536",
            "--torrent-listen-port",
            "4241",
            "source.torrent",
            "mnt",
        ])
        .unwrap();
        assert_eq!(args.torrent_swarm, ratarmount_core::TorrentSwarmPolicy::Lan);
        assert!(!args.torrent_lsd);
        assert!(args.seed);
        assert_eq!(args.seed_upload_limit, 65536);
        assert_eq!(args.torrent_listen_port, 4241);
        assert_eq!(args.paths.len(), 2);
        for verb in [None, Some("serve"), Some("find")] {
            let mut argv = vec!["ratarmount"];
            argv.extend(verb);
            argv.extend(["--seed", "--torrent-swarm", "never", "source.torrent"]);
            assert!(parse_args_from(argv)
                .unwrap_err()
                .to_string()
                .contains("conflicts"));
        }
        for rate in ["0", "16383", "1000000001", "4294967296"] {
            assert!(Args::try_parse_from([
                "ratarmount",
                "--seed-upload-limit",
                rate,
                "file.torrent"
            ])
            .is_err());
        }
        assert!(
            Args::try_parse_from(["ratarmount", "--torrent-lsd", "bad", "file.torrent"]).is_err()
        );
        #[cfg(not(feature = "bittorrent"))]
        assert!(parse_args_from([
            "ratarmount",
            "--seed",
            "--torrent-swarm",
            "lan",
            "file.torrent"
        ])
        .unwrap_err()
        .to_string()
        .contains("requires"));
    }

    /// Regression: packaged builds joined the public DHT/tracker swarm unasked
    /// because `--torrent-swarm` defaulted to `auto`.
    #[test]
    fn regression_torrent_swarm_default_never() {
        let defaults = parse_args_from(["ratarmount", "source.torrent", "mnt"]).unwrap();
        assert_eq!(
            defaults.torrent_swarm,
            ratarmount_core::TorrentSwarmPolicy::Never
        );
        assert_eq!(
            defaults.torrent_swarm,
            ratarmount_core::TorrentSwarmPolicy::default()
        );
        // The mount copies `args.torrent_swarm` into `OpenOptions` verbatim.
        assert_eq!(defaults.torrent_swarm, OpenOptions::default().torrent_swarm);
        let auto = parse_args_from([
            "ratarmount",
            "--torrent-swarm",
            "auto",
            "source.torrent",
            "mnt",
        ])
        .unwrap();
        assert_eq!(
            auto.torrent_swarm,
            ratarmount_core::TorrentSwarmPolicy::Auto
        );
    }

    /// Regression: `--seed` without a policy would have to join a swarm the
    /// user never chose; it must name the opt-in instead.
    #[test]
    fn regression_seed_requires_explicit_swarm_policy() {
        for verb in [None, Some("serve"), Some("find")] {
            let mut argv = vec!["ratarmount"];
            argv.extend(verb);
            argv.extend(["--seed", "source.torrent"]);
            let error = parse_args_from(argv).unwrap_err().to_string();
            assert!(error.contains("conflicts"), "{error}");
            assert!(error.contains("--torrent-swarm lan"), "{error}");
        }
        #[cfg(feature = "bittorrent")]
        for policy in ["lan", "auto"] {
            let args = parse_args_from([
                "ratarmount",
                "--seed",
                "--torrent-swarm",
                policy,
                "source.torrent",
                "mnt",
            ])
            .unwrap();
            assert!(args.seed);
            assert_eq!(args.torrent_swarm, policy.parse().unwrap());
        }
    }

    /// Regression: a mountpoint directory named x.torrent was taken as another mount input.
    #[test]
    fn regression_torrent_directory_remains_mountpoint() {
        let temp = tempfile::tempdir().unwrap();
        let mountpoint = temp.path().join("x.torrent");
        std::fs::create_dir(&mountpoint).unwrap();
        let paths = vec![PathBuf::from("source.tar"), mountpoint.clone()];
        let (inputs, mount) = split_inputs_mountpoint(&paths, false);
        assert_eq!(inputs, vec![PathBuf::from("source.tar")]);
        assert_eq!(mount, Some(mountpoint));
    }
}

#[cfg(test)]
mod lower_stack_tests {
    use super::*;
    use ratarmount_compositing::{FolderMountSource, Immutability, OverlayMeta};

    /// Regression: --lower consumes exactly one value and never steals base/mount positionals.
    #[test]
    fn regression_lower_flags_keep_positionals_and_optional_top() {
        let args = parse_args_from([
            "ratarmount",
            "--lower",
            "first",
            "--lower",
            "second",
            "base.tar",
            "mnt",
        ])
        .unwrap();
        assert_eq!(
            args.lower,
            [PathBuf::from("first"), PathBuf::from("second")]
        );
        assert_eq!(
            args.paths,
            [PathBuf::from("base.tar"), PathBuf::from("mnt")]
        );
        assert!(args.write_overlay.is_none());
        for flag in ["--overlay-tmpfs", "--sandbox"] {
            let args = parse_args_from(["ratarmount", flag, "--lower", "first", "base.tar", "mnt"])
                .unwrap();
            assert!(args.overlay_tmpfs.is_some());
        }
        assert!(
            parse_args_from(["ratarmount", "--allow-unsealed-lower", "base.tar", "mnt"]).is_err()
        );
    }

    /// Regression: layered offline/live/interval/rolling commits could overwrite the base.
    #[test]
    fn regression_lower_stack_commit_is_refused() {
        for extra in [
            vec!["--commit-overlay"],
            vec!["--commit-overlay-on-exit"],
            vec!["--commit-overlay-interval", "2s"],
            vec!["--roll-every", "1h"],
        ] {
            let mut argv = vec!["ratarmount", "-w", "top", "--lower", "prepared"];
            argv.extend(extra);
            argv.extend(["base.tar", "mnt"]);
            let error = parse_args_from(argv).unwrap_err().to_string();
            assert!(
                error.contains("commit of a layered stack is not supported; flatten first"),
                "{error}"
            );
        }
    }

    /// Regression: overlay fsck DIR was mistaken for ordinary archive/mount positionals.
    #[test]
    fn regression_lower_fsck_dispatch_keeps_directory() {
        let args = parse_args_from(["ratarmount", "overlay", "fsck", "DIR", "--repair", "--json"])
            .unwrap();
        assert!(args.paths.is_empty());
        assert!(
            matches!(args.overlay.unwrap().command, overlay_cmd::OverlayCommand::Fsck { directory, repair: true, json: true } if directory == Path::new("DIR"))
        );
        assert!(parse_args_from(["ratarmount", "overlay", "fsck"]).is_err());
        assert!(parse_args_from(["ratarmount", "overlay", "fsck", "a", "b"]).is_err());
    }

    /// Regression: unsealed/legacy lowers require opt-in, sealed lowers use immutable SQLite.
    #[test]
    fn regression_lower_unsealed_and_legacy_require_opt_in() {
        let root = tempfile::tempdir().unwrap();
        let base = root.path().join("base");
        std::fs::create_dir(&base).unwrap();
        let dir = root.path().join("lower");
        let view: Arc<dyn ratarmount_core::MountSource> =
            Arc::new(FolderMountSource::new(base).unwrap());
        drop(crate::base_identity::fixtures::new_overlay(view.clone(), &dir).unwrap());
        let paths = [dir.clone()];
        let open = |allow| {
            MountLowerStack::open(view.clone(), None, &paths, allow, &lower_stack_services())
                .map(|r| r.0)
        };
        assert!(open(false).err().unwrap().contains("unsealed"));
        let stack = open(true).unwrap();
        assert_eq!(stack.layers[0].1, Immutability::Shared);
        assert!(stack.records[0].layer_digest.is_empty());
        let conn = rusqlite::Connection::open(dir.join(HIDDEN_DB)).unwrap();
        conn.execute_batch("DROP TABLE meta").unwrap();
        drop(conn);
        assert!(open(false).is_err());
        assert!(open(true).is_ok());
        let conn = rusqlite::Connection::open(dir.join(HIDDEN_DB)).unwrap();
        conn.execute_batch(ratarmount_compositing::overlay_meta::META_SCHEMA)
            .unwrap();
        OverlayMeta::set(&conn, "sealed_at", "2026-10-17T00:00:00Z").unwrap();
        drop(conn);
        assert_eq!(open(false).unwrap().layers[0].1, Immutability::Immutable);
    }

    /// A sealed lower over `base` whose recorded identity is `meta`.
    fn identity_lower(
        root: &Path,
        base: &Path,
        meta: &[(&str, &str)],
    ) -> (Arc<dyn ratarmount_core::MountSource>, PathBuf) {
        let view: Arc<dyn ratarmount_core::MountSource> =
            Arc::new(FolderMountSource::new(base).unwrap());
        let dir = root.join("lower");
        drop(crate::base_identity::fixtures::new_overlay(view.clone(), &dir).unwrap());
        let conn = rusqlite::Connection::open(dir.join(HIDDEN_DB)).unwrap();
        OverlayMeta::set_many(&conn, meta).unwrap();
        // Written by a build that records the base kind (format 2).
        OverlayMeta::set_many(
            &conn,
            &[
                ("format_version", "2"),
                ("sealed_at", "2026-10-17T00:00:00Z"),
                ("layer_digest", "sha256:layer"),
            ],
        )
        .unwrap();
        (view, dir)
    }

    fn enforce(base: &Path, force: bool) -> BaseIdentity {
        BaseIdentity::Enforce {
            base: MountedBase {
                classified: Some(base_identity::fixtures::classify(base)),
                ..Default::default()
            },
            force,
        }
    }

    /// Regression: a read-only `--lower` mount reported the bottom lower's
    /// recorded `base_digest` (here forged) whatever base was mounted.
    #[test]
    fn regression_lower_forged_digest_not_reported() {
        let root = tempfile::tempdir().unwrap();
        let base = root.path().join("base");
        std::fs::create_dir(&base).unwrap();
        std::fs::write(base.join("f"), b"one").unwrap();
        let weak = ratarmount_compositing::overlay_meta::directory_weak_digest(
            &base,
            &ratarmount_compositing::overlay_meta::BaseExcludes::default(),
        )
        .unwrap();
        let (view, lower) = identity_lower(
            root.path(),
            &base,
            &[
                ("base_kind", "directory"),
                ("base_location", &format!("local:{}", base.display())),
                ("base_digest", "sha256:forged"),
                ("base_digest_kind", "strong"),
                ("base_weak_digest", &weak),
                ("base_weak_excludes", "[]"),
            ],
        );
        let paths = [lower];
        let policy = enforce(&base, false);
        let (stack, _) = MountLowerStack::open_with(
            view,
            None,
            &paths,
            false,
            None,
            &bottom_identity(&policy),
            &lower_stack_services(),
        )
        .unwrap();
        let metadata = stack.read_only_metadata();
        assert_eq!(metadata["base_digest"], weak);
        assert_eq!(
            metadata["stack_digest"],
            ratarmount_compositing::stack_digest(&weak, &["sha256:layer"])
        );
    }

    /// Regression: offline commands (`overlay verify`, `seal`, `pack`) must not
    /// refuse a lower over a byte-identical copy of its base; only the mount
    /// path enforces the identity.
    #[test]
    fn regression_verify_stacked_strong_overlay_over_byte_identical_copy_passes() {
        let root = tempfile::tempdir().unwrap();
        let base = root.path().join("base");
        let copy = root.path().join("copy");
        for dir in [&base, &copy] {
            std::fs::create_dir(dir).unwrap();
            std::fs::write(dir.join("f"), b"one").unwrap();
        }
        let file = std::fs::File::options()
            .write(true)
            .open(copy.join("f"))
            .unwrap();
        file.set_modified(std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1))
            .unwrap();
        drop(file);
        let weak = ratarmount_compositing::overlay_meta::directory_weak_digest(
            &base,
            &ratarmount_compositing::overlay_meta::BaseExcludes::default(),
        )
        .unwrap();
        let (_, lower) = identity_lower(
            root.path(),
            &base,
            &[
                ("base_kind", "directory"),
                ("base_location", &format!("local:{}", base.display())),
                ("base_digest", "sha256:strong"),
                ("base_digest_kind", "strong"),
                ("base_weak_digest", &weak),
            ],
        );
        let paths = [lower];
        let view: Arc<dyn ratarmount_core::MountSource> =
            Arc::new(FolderMountSource::new(&copy).unwrap());
        MountLowerStack::open_in(
            view.clone(),
            None,
            &paths,
            false,
            None,
            &lower_stack_services(),
        )
        .unwrap();
        let refuse = enforce(&copy, false);
        let error = MountLowerStack::open_with(
            view.clone(),
            None,
            &paths,
            false,
            None,
            &bottom_identity(&refuse),
            &lower_stack_services(),
        )
        .err()
        .unwrap();
        assert!(error.contains("--force-stack-mismatch"), "{error}");
        let allow = enforce(&copy, true);
        MountLowerStack::open_with(
            view,
            None,
            &paths,
            false,
            None,
            &bottom_identity(&allow),
            &lower_stack_services(),
        )
        .unwrap();
    }

    /// An archive base whose digest is not cached has no identity to report:
    /// empty `base_digest` and `stack_digest`, and no hashing at mount.
    #[test]
    fn regression_lower_uncached_archive_reports_no_identity() {
        let root = tempfile::tempdir().unwrap();
        let archive = root.path().join("base.bin");
        std::fs::write(&archive, b"archive bytes").unwrap();
        let stamp = ratarmount_index::ArchiveDigestStamp::read(&archive).unwrap();
        let folder = root.path().join("folder");
        std::fs::create_dir(&folder).unwrap();
        let (view, lower) = identity_lower(
            root.path(),
            &folder,
            &[
                ("base_kind", "archive"),
                ("base_location", &format!("local:{}", archive.display())),
                ("base_digest", ""),
                ("base_digest_kind", "pending"),
                ("base_size", &stamp.size.to_string()),
                ("base_mtime_ns", &stamp.mtime_ns.to_string()),
            ],
        );
        let paths = [lower];
        let policy = enforce(&archive, false);
        let (stack, _) = MountLowerStack::open_with(
            view,
            None,
            &paths,
            false,
            Some(root.path()),
            &bottom_identity(&policy),
            &lower_stack_services(),
        )
        .unwrap();
        let metadata = stack.read_only_metadata();
        assert_eq!(metadata["base_digest"], "");
        assert_eq!(metadata["stack_digest"], "");
        assert_eq!(metadata["base_digest_state"], "pending");
    }
}

#[cfg(test)]
mod lower_extra_excludes_tests {
    use super::*;

    /// Regression: a read-only `--lower` mount excluded an existing
    /// `B/new.log` named by `--journal`, hiding a change to the base. Only
    /// paths that do not exist yet are excluded without a `-w` overlay.
    #[test]
    fn regression_read_only_lower_excludes_only_new_paths() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("base");
        std::fs::create_dir(&base).unwrap();
        std::fs::write(base.join("new.log"), b"x").unwrap();
        let lowers = [dir.path().join("lower")];
        let out = lower_extra_excludes(
            Some(&base),
            &lowers,
            None,
            vec![base.join("new.log"), base.join("fresh/j.jsonl")],
        );
        assert_eq!(out, vec![PathBuf::from("fresh")]);
    }

    /// Regression: with `-w NEWTOP` the existing-file filter was skipped, so
    /// `--lower L -w NEWTOP --journal B/new.log` hid an ordinary `B/new.log`
    /// added to the base after L was sealed.
    #[test]
    fn regression_writable_top_excludes_only_new_journal_paths() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("base");
        std::fs::create_dir(&base).unwrap();
        std::fs::write(base.join("new.log"), b"x").unwrap();
        let lowers = [dir.path().join("lower")];
        let top = dir.path().join("newtop");
        let out =
            lower_extra_excludes(Some(&base), &lowers, Some(&top), vec![base.join("new.log")]);
        assert!(out.is_empty(), "{out:?}");
    }

    /// A `-w` remount of the same top keeps its journal inside the base: the
    /// top's recorded set (written when the journal did not exist yet) covers it.
    #[test]
    fn regression_writable_remount_uses_recorded_excludes() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("base");
        std::fs::create_dir(&base).unwrap();
        let top = dir.path().join("top");
        let lowers = [dir.path().join("lower")];
        let journal = base.join("j.log");
        let first = lower_extra_excludes(Some(&base), &lowers, Some(&top), vec![journal.clone()]);
        assert_eq!(first, vec![PathBuf::from("j.log")]);
        std::fs::create_dir(&top).unwrap();
        let conn = rusqlite::Connection::open(top.join(ratarmount_compositing::HIDDEN_DB)).unwrap();
        conn.execute_batch("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);")
            .unwrap();
        ratarmount_compositing::OverlayMeta::set(&conn, "base_weak_excludes", r#"["j.log"]"#)
            .unwrap();
        drop(conn);
        std::fs::write(&journal, b"j").unwrap();
        let again = lower_extra_excludes(Some(&base), &lowers, Some(&top), vec![journal]);
        assert!(again.contains(&PathBuf::from("j.log")), "{again:?}");
    }
}

#[cfg(test)]
mod lower_marker_key_tests {
    use super::*;

    /// An archive plus a warm index whose digest cache already holds its digest.
    fn cached_archive(dir: &Path, name: &str, bytes: &[u8]) -> (PathBuf, PathBuf, String) {
        let archive = dir.join(name);
        std::fs::write(&archive, bytes).unwrap();
        let index = dir.join(format!("{name}.index.sqlite"));
        rusqlite::Connection::open(&index)
            .unwrap()
            .execute_batch("CREATE TABLE files (name TEXT);")
            .unwrap();
        let digest = ratarmount_index::cached_archive_digest(&archive, Some(&index)).unwrap();
        (archive, index, digest)
    }

    /// Regression: lower-bundle identity peeks must preserve prepared WAL companions.
    #[test]
    fn regression_prepared_index_lower_key_peek_is_immutable() {
        let dir = tempfile::tempdir().unwrap();
        let (archive, index, digest) = cached_archive(dir.path(), "a.tar", b"archive");
        let bundle = dir.path().join("lower.tar.zst");
        std::fs::write(&bundle, b"bundle").unwrap();
        let db = rusqlite::Connection::open(&index).unwrap();
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_checkpoint(TRUNCATE)")
            .unwrap();
        drop(db);
        let wal = PathBuf::from(format!("{}-wal", index.display()));
        let shm = PathBuf::from(format!("{}-shm", index.display()));
        std::fs::write(&wal, b"").unwrap();
        std::fs::write(&shm, vec![0x5a; 32768]).unwrap();
        let snapshot = || {
            std::fs::read_dir(dir.path())
                .unwrap()
                .map(|e| {
                    let p = e.unwrap().path();
                    (
                        p.file_name().unwrap().to_owned(),
                        std::fs::read(&p).unwrap(),
                    )
                })
                .collect::<std::collections::BTreeMap<_, _>>()
        };
        let before = snapshot();
        let reader = ratarmount_index::open_prepared_connection(&index).unwrap();
        let key = || {
            lower_base_key_for_open(
                std::slice::from_ref(&archive),
                Some(&index),
                std::slice::from_ref(&bundle),
                "view",
                true,
            )
        };
        assert_eq!(key().unwrap(), Some(format!("{digest}.view")));
        assert_eq!(snapshot(), before);
        drop(reader);
        assert_eq!(snapshot(), before);
        std::fs::write(&wal, b"pending WAL").unwrap();
        let bad = snapshot();
        assert!(key().unwrap_err().contains("prepar"));
        assert_eq!(snapshot(), bad);
        assert_eq!(
            lower_base_key_for_open(
                std::slice::from_ref(&archive),
                None,
                std::slice::from_ref(&bundle),
                "view",
                true
            )
            .unwrap(),
            None
        );
        assert_eq!(snapshot(), bad);
        std::fs::remove_file(&wal).unwrap();
        std::fs::remove_file(&shm).unwrap();
        let db = rusqlite::Connection::open(&index).unwrap();
        db.execute_batch("DROP TABLE overlay_base_digests").unwrap();
        drop(db);
        assert_eq!(key().unwrap(), None);
    }

    /// Regression: `A.tar B --lower bundle` keyed the verification marker by A's
    /// cached digest alone, so a bundle that edits `B/f` kept its marker after
    /// `B/f` changed and skipped verification against the changed union.
    #[test]
    fn regression_marker_key_covers_every_base_input() {
        let dir = tempfile::tempdir().unwrap();
        let (a, index, digest) = cached_archive(dir.path(), "a.tar", b"aaaa");
        let b = dir.path().join("b");
        std::fs::create_dir(&b).unwrap();
        std::fs::write(b.join("f"), b"one").unwrap();
        let bundle = dir.path().join("l.tar.zst");
        std::fs::write(&bundle, b"x").unwrap();
        let lowers = [bundle];
        let key = |inputs: &[PathBuf]| lower_base_key(inputs, Some(&index), &lowers, "v");
        // One archive: keyed by its cached digest.
        assert_eq!(key(std::slice::from_ref(&a)), Some(format!("{digest}.v")));
        // A directory beside it has no computed strong identity: no marker, so
        // every use verifies against the union as it is now.
        assert_eq!(key(&[a.clone(), b.clone()]), None);
        // A second archive without its own digest cache is unidentified too.
        let (a2, _, _) = cached_archive(dir.path(), "a2.tar", b"bbbb");
        assert_eq!(key(&[a.clone(), a2]), None);
    }

    /// Nit: a directory base has no computed strong digest, so a supplied
    /// `--base-digest` claim cannot key a marker for it, and an archive without
    /// a cached digest has no key either.
    #[test]
    fn regression_marker_key_needs_a_computed_digest() {
        let dir = tempfile::tempdir().unwrap();
        let bundle = dir.path().join("l.tar.zst");
        std::fs::write(&bundle, b"x").unwrap();
        let lowers = [bundle];
        assert_eq!(
            lower_base_key(&[a_dir(dir.path())], None, &lowers, "v"),
            None
        );
        let bare = dir.path().join("bare.tar");
        std::fs::write(&bare, b"zz").unwrap();
        assert_eq!(lower_base_key(&[bare], None, &lowers, "v"), None);
    }

    /// Regression: a marker cached for the plain view skipped verification when
    /// the same bundle was mounted with `--prefix p` (or any other option that
    /// reshapes the paths), accepting a Modified->Added change.
    #[test]
    fn regression_marker_key_needs_the_default_view() {
        let dir = tempfile::tempdir().unwrap();
        let (a, index, digest) = cached_archive(dir.path(), "a.tar", b"aaaa");
        let bundle = dir.path().join("l.tar.zst");
        std::fs::write(&bundle, b"x").unwrap();
        let lowers = [bundle.clone()];
        let parse = |extra: &[&str]| {
            let mut argv = vec!["ratarmount"];
            argv.extend_from_slice(extra);
            argv.push("a.tar");
            Args::try_parse_from(argv).unwrap()
        };
        let key = |extra: &[&str]| {
            let args = parse(extra);
            mounted_view_is_default(&args, false)
                .then(|| {
                    lower_base_key(
                        std::slice::from_ref(&a),
                        Some(&index),
                        &lowers,
                        &mounted_view_key(&args),
                    )
                })
                .flatten()
        };
        assert_eq!(
            key(&[]),
            Some(format!("{digest}.{}", mounted_view_key(&parse(&[]))))
        );
        for extra in [
            &["--prefix", "p"][..],
            &["--transform", "a", "b"],
            &["--transform-recursive-mount-point", "a", "b"],
            &["-r"],
            &["--lazy"],
            &["--disable-union-mount"],
            &["-s"],
            &["--git-prefix", "x"],
        ] {
            assert_eq!(key(extra), None, "{extra:?}");
        }
        assert!(!mounted_view_is_default(&parse(&[]), true));
    }

    /// Regression: the marker key ignored `--no-file-versions`, `--ignore-zeros`
    /// and the GNU-incremental options, so a bundle verified with
    /// `f.versions/1` hidden was trusted on a normal remount where the base
    /// synthesizes that path. Every listing option must change the key.
    #[test]
    fn regression_marker_key_covers_listing_options() {
        let dir = tempfile::tempdir().unwrap();
        let (a, index, digest) = cached_archive(dir.path(), "a.tar", b"aaaa");
        let bundle = dir.path().join("l.tar.zst");
        std::fs::write(&bundle, b"x").unwrap();
        let lowers = [bundle];
        let key = |extra: &[&str]| {
            let mut argv = vec!["ratarmount"];
            argv.extend_from_slice(extra);
            argv.push("a.tar");
            let args = Args::try_parse_from(argv).unwrap();
            assert!(mounted_view_is_default(&args, false));
            lower_base_key(
                std::slice::from_ref(&a),
                Some(&index),
                &lowers,
                &mounted_view_key(&args),
            )
            .unwrap()
        };
        let plain = key(&[]);
        assert!(plain.starts_with(&digest), "{plain}");
        let mut seen = vec![plain.clone()];
        for extra in [
            &["--no-file-versions"][..],
            &["--ignore-zeros"],
            &["--gnu-incremental"],
            &["--detect-gnu-incremental"],
            &["--encoding", "latin1"],
        ] {
            let k = key(extra);
            assert!(!seen.contains(&k), "{extra:?} reuses a key: {k}");
            seen.push(k);
        }
        // `--file-versions` is the default and keeps the plain key.
        assert_eq!(key(&["--file-versions"]), plain);
    }

    fn a_dir(parent: &Path) -> PathBuf {
        let d = parent.join("adir");
        std::fs::create_dir(&d).unwrap();
        d
    }
}
