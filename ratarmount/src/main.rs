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
use ratarmount_fuse::{clamp_readahead, mount_blocking, parse_byte_size, unmount};
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
                  Supports recursive automount (-r), write overlay (-w), and http(s)/file URLs."
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

    if args.no_mount {
        return;
    }

    let mp = match mountpoint {
        Some(mp) => mp,
        None => {
            let mp = default_mountpoint(&inputs[0]);
            std::fs::create_dir_all(&mp).ok();
            mp
        }
    };
    std::fs::create_dir_all(&mp).ok();
    let writable = overlay_arc.is_some();
    let fuse_opts = args.fuse.clone();
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
            if clamped > 0 {
                log::info!("FUSE readahead enabled: {clamped} bytes per sequential window");
            }
            clamped
        }
        Err(e) => {
            eprintln!("error: invalid --readahead: {e}");
            std::process::exit(2);
        }
    };

    // Optional control: Unix socket + in-FS `/.ratarmount-control/` (Python parity).
    let control_stop = Arc::new(AtomicBool::new(false));
    let _control_sock = if args.control_interface {
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
        start_control_interface(&mp, Arc::clone(&control_stop))
    } else {
        None
    };

    if args.foreground {
        if let Err(e) = mount_blocking(
            Arc::clone(&bundle.source),
            &mp,
            true,
            writable,
            overlay_arc,
            &fuse_opts,
            readahead,
        ) {
            eprintln!("error mounting at {}: {e}", mp.display());
            std::process::exit(1);
        }
        drop(bundle);
        return;
    }

    // Daemonize: parent waits for mount readiness, child runs FUSE.
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
            // Parent exits successfully; child continues FUSE session.
            drop(bundle);
            std::process::exit(0);
        }
        Ok(ForkResult::Child) => {
            let _ = setsid();
            // Detach stdio so the terminal is free (logs only if RUST_LOG set via inherited env)
            if args.log_file.is_none() {
                let _ = redirect_stdio_to_null();
            }
            if let Err(e) = mount_blocking(
                Arc::clone(&bundle.source),
                &mp,
                true,
                writable,
                overlay_arc,
                &fuse_opts,
                readahead,
            ) {
                // Best-effort: write to /tmp if possible
                let _ = std::fs::write(
                    "/tmp/ratarmount-rs-fuse-error.log",
                    format!("mount error: {e}\n"),
                );
                std::process::exit(1);
            }
            drop(bundle);
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
