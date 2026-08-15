//! ratarmount CLI (Phases 0–11 + CLI flag parity).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use clap::{ArgAction, Parser};
use nix::unistd::{fork, setsid, ForkResult};
use ratarmount_compositing::{
    commit_overlay, CommitOverlayOptions, ControlFolderMountSource, ControlFolderOptions,
    WriteOverlay,
};
use ratarmount_compress::strip_compression_suffix;
use ratarmount_core::{MountSource, OpenOptions, ParallelizationSpec};
use ratarmount_fuse::{
    clamp_readahead, mount_blocking, parse_byte_size, unmount, RECOMMENDED_READAHEAD_BYTES,
};
use ratarmount_index::{
    default_index_folders, fill_content_hashes, parse_index_folders, resolve_index_location,
    SqliteIndex, MEMORY_INDEX,
};
use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicBool, Ordering};

mod factory;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser, Debug)]
#[command(
    name = "ratarmount",
    version = VERSION,
    about = "Random Access To Archived Resources (Rust rewrite)",
    long_about = "Mount archives (TAR/ZIP/AR/CPIO/libarchive, compressed) via FUSE.\n\
                  Supports recursive automount (-r), write overlay (-w), http(s)/file URLs,\n\
                  and userspace NFS (--nfs, NFSv3 default; --nfs-vers 4 for NFSv4.1)."
)]
struct Args {
    /// Unmount the given mountpoint(s)
    #[arg(short = 'u', long = "unmount", action = ArgAction::SetTrue)]
    unmount: bool,

    /// Stay in foreground (default: daemonize after mount is ready)
    #[arg(short = 'f', long = "foreground", action = ArgAction::SetTrue)]
    foreground: bool,

    /// Recreate the index
    #[arg(short = 'c', long = "recreate-index", action = ArgAction::SetTrue)]
    recreate_index: bool,

    /// Never create or modify indexes; only use existing ones
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
    /// Examples: `1` (default), `0` (all cores), `4`, `bzip2:4,gzip:2`, `:2,bzip2:4`
    #[arg(
        short = 'P',
        long = "parallelization",
        default_value = "1",
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

    /// Comma-separated or JSON list of folders for `.index.sqlite` files.
    /// Empty entry = next to the archive. Default: ,$XDG_CACHE_HOME/ratarmount,~/.ratarmount
    #[arg(long = "index-folders")]
    index_folders: Option<String>,

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
    /// to keep readahead off.
    #[arg(long = "readahead", default_value = "0", value_name = "BYTES")]
    readahead: String,

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

    /// Write overlay folder (`:temp:` for a temporary directory)
    #[arg(short = 'w', long = "write-overlay")]
    write_overlay: Option<PathBuf>,

    /// Commit write-overlay changes into a TAR (GNU tar; also gzip/bzip2/xz) or ZIP
    /// (full rebuild). Does not mount; requires `--write-overlay` and a single archive path.
    #[arg(long = "commit-overlay", action = ArgAction::SetTrue)]
    commit_overlay: bool,

    /// Skip interactive confirmation for `--commit-overlay` (type "commit" otherwise).
    #[arg(long = "yes", action = ArgAction::SetTrue)]
    yes: bool,

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

    /// Input archives/folders/URLs and optional mountpoint
    #[arg(required = false)]
    paths: Vec<PathBuf>,
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

fn main() {
    let args = Args::parse();

    if args.print_features {
        // Features print does not need a full logger.
        print_features();
        return;
    }
    if args.oss_attributions || args.oss_attributions_short {
        print_oss_attributions(args.oss_attributions);
        return;
    }

    let write_style = resolve_color_style(args.color, args.no_color);
    init_logger(args.debug, args.log_file.as_deref(), write_style);

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
            eprintln!("error: --commit-overlay requires <archive.tar|archive.zip>");
            std::process::exit(2);
        }
        let archive = &args.paths[0];
        if args.paths.len() > 2 {
            eprintln!("error: currently only modifications to a single archive may be committed");
            std::process::exit(2);
        }
        let opts = CommitOverlayOptions {
            yes: args.yes,
            debug: args.debug,
        };
        match commit_overlay(overlay, archive, &opts) {
            Ok(_) => return,
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
    }

    if args.paths.is_empty() {
        eprintln!("usage: ratarmount [options] <archive|folder|URL>... [mountpoint]");
        eprintln!("       ratarmount -u <mountpoint>");
        eprintln!("       ratarmount --commit-overlay -w <overlay> <archive.tar|archive.zip>");
        std::process::exit(2);
    }

    let (inputs, mountpoint) = split_inputs_mountpoint(&args.paths, args.no_mount);

    let (index_in_memory, index_file_path) = match args.index_file.as_deref() {
        Some(s) if s.trim() == MEMORY_INDEX => (true, None),
        Some(s) => (false, Some(PathBuf::from(s))),
        None => (false, None),
    };

    let index_folders = match &args.index_folders {
        Some(s) => parse_index_folders(s),
        None => default_index_folders(),
    };

    let mut passwords = args.passwords.clone();
    if let Some(ref pf) = args.password_file {
        match std::fs::read_to_string(pf) {
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

    let open_opts = OpenOptions {
        recursive: args.recursive,
        ignore_zeros: args.ignore_zeros,
        gnu_incremental,
        parallelization,
        index_minimum_file_count: args.index_minimum_file_count,
        index_file_path,
        index_in_memory,
        index_compact_only: false,
        index_folders,
        clear_index_cache: args.recreate_index && !args.no_recreate_index,
        write_index: !args.no_recreate_index,
        read_only_index: args.no_recreate_index,
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
    };

    if args.force_folder_index {
        eprintln!("info: --force-folder-index accepted; folders still bind-mount without SQLite");
    }

    let file_versions = !args.no_file_versions;

    let mut bundle = match factory::build_mount_source_ex(
        &inputs,
        &open_opts,
        args.recreate_index && !args.no_recreate_index,
        factory::CompositingOptions {
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
        },
    ) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    };

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

    let mut _temp_overlay: Option<tempfile::TempDir> = None;
    let mut overlay_arc: Option<Arc<WriteOverlay>> = None;

    if let Some(w) = &args.write_overlay {
        let overlay_path = if w.as_os_str() == ":temp:" {
            let td =
                tempfile::TempDir::with_prefix("ratarmount-write-overlay.").expect("temp overlay");
            let p = td.path().to_path_buf();
            eprintln!("Created temporary overlay directory: {}", p.display());
            _temp_overlay = Some(td);
            p
        } else {
            w.clone()
        };
        match WriteOverlay::new(Arc::clone(&bundle.source), &overlay_path) {
            Ok(ov) => {
                let ov = Arc::new(ov);
                bundle.source = Arc::clone(&ov) as Arc<dyn MountSource>;
                overlay_arc = Some(ov);
            }
            Err(e) => {
                eprintln!("error creating write overlay: {e}");
                std::process::exit(1);
            }
        }
    }

    if args.no_mount && args.nfs {
        eprintln!("error: --nfs cannot be combined with --no-mount");
        std::process::exit(2);
    }
    if args.no_mount {
        return;
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

    // NFS-only: do not invent a FUSE mountpoint / stem directory.
    let fuse_mp = if args.nfs && mountpoint.is_none() {
        None
    } else {
        Some(match mountpoint {
            Some(mp) => mp,
            None => {
                let mp = default_mountpoint(&inputs[0]);
                std::fs::create_dir_all(&mp).ok();
                mp
            }
        })
    };
    if let Some(mp) = &fuse_mp {
        std::fs::create_dir_all(mp).ok();
    }

    if args.nfs && fuse_mp.is_none() && args.control_interface {
        eprintln!(
            "error: --control-interface requires a FUSE mountpoint (NFS-only is not supported)"
        );
        std::process::exit(2);
    }

    let writable = overlay_arc.is_some();
    let fuse_opts = args.fuse.clone();

    // Optional control: Unix socket + in-FS `/.ratarmount-control/` (Python parity).
    let control_stop = Arc::new(AtomicBool::new(false));
    let _control_sock = if args.control_interface {
        let mp = fuse_mp.as_ref().expect("control requires FUSE mp");
        let stop = Arc::clone(&control_stop);
        let mp_ctrl = mp.clone();
        bundle.source = Arc::new(ControlFolderMountSource::new(
            Arc::clone(&bundle.source),
            ControlFolderOptions::enabled()
                .with_label(mp.display().to_string())
                .with_on_unmount(Arc::new(move || {
                    stop.store(true, Ordering::SeqCst);
                    let _ = unmount(&mp_ctrl);
                })),
        )) as Arc<dyn MountSource>;
        start_control_interface(mp, Arc::clone(&control_stop))
    } else {
        None
    };

    if let Some(bind) = nfs_bind {
        if !bind.ip().is_loopback() {
            eprintln!(
                "warning: NFS bound on {} (AUTH_SYS, no allowlist). \
                 Prefer 127.0.0.1 unless you trust the LAN.",
                bind
            );
        }
        let nfs_opts = ratarmount_nfs::NfsOptions {
            bind,
            export_name: args.nfs_export_name.clone(),
            readahead_bytes: readahead,
            reader_slots: ratarmount_nfs::DEFAULT_READER_SLOTS,
            stop: None,
            overlay: overlay_arc.clone(),
            vers: nfs_vers,
        };
        match fuse_mp {
            None => run_nfs_only(bundle.source, nfs_opts),
            Some(mp) => run_fuse_and_nfs(
                bundle.source,
                mp,
                writable,
                overlay_arc,
                &fuse_opts,
                readahead,
                nfs_opts,
                args.foreground,
                args.log_file.is_some(),
            ),
        }
        return;
    }

    let mp = fuse_mp.expect("FUSE path has a mountpoint");
    run_fuse_only(
        bundle.source,
        mp,
        writable,
        overlay_arc,
        &fuse_opts,
        readahead,
        args.foreground,
        args.log_file.is_some(),
    );
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

fn run_nfs_only(source: Arc<dyn MountSource>, opts: ratarmount_nfs::NfsOptions) {
    eprintln!("{}", nfs_ready_line(&opts, opts.bind.port()));
    if let Err(e) = serve_nfs_blocking(source, opts) {
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
    readahead: u64,
    mut nfs_opts: ratarmount_nfs::NfsOptions,
    foreground: bool,
    has_log_file: bool,
) {
    if foreground {
        let stop = ratarmount_nfs::NfsStop::new();
        nfs_opts.stop = Some(stop.clone());
        let ready = nfs_opts.clone();
        let handle = match spawn_nfs_for_opts(Arc::clone(&source), nfs_opts) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("error starting NFS server: {e}");
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
            overlay_arc,
            fuse_opts,
            readahead,
        );
        stop.request_stop();
        let _ = handle.join();
        if let Err(e) = mount_err {
            eprintln!("error mounting at {}: {e}", mp.display());
            std::process::exit(1);
        }
        return;
    }

    // Daemonize: probe NFS bind in the parent so a dead port is not silent.
    if let Err(e) = std::net::TcpListener::bind(nfs_opts.bind) {
        eprintln!("error: cannot bind NFS on {}: {e}", nfs_opts.bind);
        std::process::exit(1);
    }
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
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
            if let Err(e) = spawn_nfs_for_opts(Arc::clone(&source), nfs_opts) {
                let _ = std::fs::write(
                    "/tmp/ratarmount-rs-nfs-error.log",
                    format!("NFS bind error: {e}\n"),
                );
                std::process::exit(1);
            }
            if let Err(e) = mount_blocking(
                source,
                &mp,
                true,
                writable,
                overlay_arc,
                fuse_opts,
                readahead,
            ) {
                let _ = std::fs::write(
                    "/tmp/ratarmount-rs-fuse-error.log",
                    format!("mount error: {e}\n"),
                );
                std::process::exit(1);
            }
            stop.request_stop();
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("error: fork failed: {e}");
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
    readahead: u64,
    foreground: bool,
    has_log_file: bool,
) {
    if foreground {
        if let Err(e) = mount_blocking(
            source,
            &mp,
            true,
            writable,
            overlay_arc,
            fuse_opts,
            readahead,
        ) {
            eprintln!("error mounting at {}: {e}", mp.display());
            std::process::exit(1);
        }
        return;
    }

    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
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
            if let Err(e) = mount_blocking(
                source,
                &mp,
                true,
                writable,
                overlay_arc,
                fuse_opts,
                readahead,
            ) {
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
    let level = match debug {
        0 => log::LevelFilter::Error,
        1 => log::LevelFilter::Warn,
        2 => log::LevelFilter::Info,
        _ => log::LevelFilter::Debug,
    };
    // RUST_LOG still wins if set (env_logger convention via filter_or).
    let mut builder =
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(level.as_str()));
    builder.filter_level(level);
    builder.write_style(write_style);
    if let Some(path) = log_file {
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            Ok(file) => {
                let file = std::sync::Mutex::new(file);
                builder.target(env_logger::Target::Pipe(Box::new(WriteAdapter(file))));
            }
            Err(e) => {
                eprintln!("warning: could not open log file {}: {e}", path.display());
            }
        }
    }
    let _ = builder.try_init();
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
        "  nfs: nfsserve NFSv3 (--nfs, default); NFSv4.1 embednfs (--nfs-vers 4, --features nfsv4, rustc>=1.88)"
    );
    #[cfg(feature = "nfsv4")]
    println!("  nfsv4: compiled");
    #[cfg(not(feature = "nfsv4"))]
    println!("  nfsv4: not compiled");
    println!(
        "  compress: gzip/bzip2/xz/zstd/lz4/lzip/lzo/Z/lzma/zlib seekable bodies; plain single-file materialize"
    );
    println!(
        "  formats: tar,zip,ar,cpio,iso9660,warc,xar,cab,sevenzip,sqlar,squashfs,ext4,fat,asar,ogg,html,pdf,git,libarchive"
    );
    println!("  compositing: automount,union,folder,write-overlay,file-versions,prefix,transform");
    println!("  remote: http,https,file,s3,ssh,sftp");
    println!("  index: --index-file, --index-folders, :memory:");
    println!("  control: --control-interface (unix socket)");
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
        "reqwest / ssh2 / … — remote backends (http/s3/ssh)",
        "nfsserve / tokio — in-process NFSv3 export (--nfs)",
        #[cfg(feature = "nfsv4")]
        "embednfs — in-process NFSv4.1 export (--nfs-vers 4) (MIT)",
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

/// Listen for line-based control commands on a Unix socket.
fn start_control_interface(mountpoint: &Path, stop: Arc<AtomicBool>) -> Option<PathBuf> {
    let sock = std::env::temp_dir().join(format!("ratarmount-control-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&sock);
    let listener = match UnixListener::bind(&sock) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("warning: control interface bind failed: {e}");
            return None;
        }
    };
    eprintln!("control interface: {}", sock.display());
    let mp = mountpoint.to_path_buf();
    let sock_path = sock.clone();
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
                        let cmd = line.trim();
                        let reply = match cmd {
                            "ping" => "pong\n".to_string(),
                            "status" => format!("mounted {}\n", mp.display()),
                            "unmount" | "quit" | "exit" => {
                                let _ = unmount(&mp);
                                stop.store(true, Ordering::Relaxed);
                                "ok unmounted\n".to_string()
                            }
                            "help" => "commands: ping status unmount help\n".to_string(),
                            other => format!("error: unknown command {other:?}\n"),
                        };
                        let _ = stream.write_all(reply.as_bytes());
                    }
                }
                Err(_) => {
                    thread::sleep(Duration::from_millis(100));
                }
            }
        }
        let _ = std::fs::remove_file(&sock_path);
    });
    Some(sock)
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

    if let Ok(text) = std::fs::read_to_string("/proc/self/mountinfo") {
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
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    #[repr(C)]
    struct Statfs {
        f_type: i64,
        _pad: [u8; 128],
    }
    const FUSE_SUPER_MAGIC: i64 = 0x6573_5546;
    extern "C" {
        fn statfs(path: *const libc::c_char, buf: *mut Statfs) -> i32;
    }
    let c = match CString::new(path.as_os_str().as_bytes()) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let mut buf = Statfs {
        f_type: 0,
        _pad: [0; 128],
    };
    let r = unsafe { statfs(c.as_ptr(), &mut buf) };
    r == 0 && buf.f_type == FUSE_SUPER_MAGIC
}

fn redirect_stdio_to_null() -> std::io::Result<()> {
    use std::fs::OpenOptions;
    use std::os::unix::io::AsRawFd;
    let devnull = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")?;
    let fd = devnull.as_raw_fd();
    unsafe {
        libc::dup2(fd, 0);
        libc::dup2(fd, 1);
        libc::dup2(fd, 2);
    }
    Ok(())
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

fn default_mountpoint(archive: &Path) -> PathBuf {
    let s = archive.to_string_lossy();
    if let Ok(url) = url::Url::parse(&s) {
        if let Some(seg) = url.path_segments().and_then(|mut p| p.next_back()) {
            if !seg.is_empty() {
                let stripped = strip_compression_suffix(seg);
                let stem = Path::new(&stripped)
                    .file_stem()
                    .and_then(|x| x.to_str())
                    .unwrap_or(&stripped);
                return PathBuf::from(stem);
            }
        }
        // fall through if URL parse had no usable last segment
        return PathBuf::from("remote");
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
        let comp = crate::factory::CompositingOptions {
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
            crate::factory::CompositingOptions::default().parallel_nested_threads,
            0
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
