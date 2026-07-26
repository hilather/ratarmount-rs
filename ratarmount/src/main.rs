//! ratarmount CLI (Phases 0–11 + CLI flag parity).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use clap::{ArgAction, Parser};
use nix::unistd::{fork, setsid, ForkResult};
use ratarmount_compress::strip_compression_suffix;
use ratarmount_compositing::{commit_overlay, CommitOverlayOptions, WriteOverlay};
use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicBool, Ordering};
use ratarmount_core::{MountSource, OpenOptions};
use ratarmount_fuse::{mount_blocking, unmount};
use ratarmount_index::{default_index_folders, parse_index_folders, MEMORY_INDEX};

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

    /// Parallelization (reserved for parallel decompressors; backend matrix not fully parsed yet)
    #[arg(short = 'P', long = "parallelization", default_value = "1")]
    parallelization: String,

    /// Minimum file count to create an index (harness forces 0)
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
    #[arg(short = 'g', long = "gzip-seek-point-spacing", default_value_t = 16.0, visible_alias = "gs")]
    gzip_seek_point_spacing_mib: f64,

    /// Recursion depth for --recursive (0 = deep default when combined with -r)
    #[arg(long = "recursion-depth", default_value_t = 0)]
    recursion_depth: i32,

    /// Comma-separated recursive extension sets (e.g. `/archive,/compressed` or `/all`)
    #[arg(long = "recursive-extensions", default_value = "/archive,/compressed,/disk,/split")]
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

    /// Max directory depth for union mount folder cache (Python default 1024)
    #[arg(long = "union-mount-cache-max-depth", default_value_t = 1024)]
    union_mount_cache_max_depth: usize,

    /// Max directory entries to cache for multi-source union (Python default 100000)
    #[arg(long = "union-mount-cache-max-entries", default_value_t = 100_000)]
    union_mount_cache_max_entries: usize,

    /// Seconds allowed to build the union mount folder cache (Python default 60)
    #[arg(long = "union-mount-cache-timeout", default_value_t = 60.0)]
    union_mount_cache_timeout: f64,

    /// Enable/disable colored log prefixes
    #[arg(long = "color", action = ArgAction::SetTrue, overrides_with = "no_color")]
    color: bool,

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

    /// Commit write-overlay changes into an uncompressed TAR (GNU tar required).
    /// Does not mount; requires `--write-overlay` and a single archive path.
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

    let use_color = if args.no_color {
        false
    } else if args.color {
        true
    } else {
        true // default on
    };
    init_logger(args.debug, args.log_file.as_deref(), use_color);

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
            eprintln!("error: --commit-overlay requires <archive.tar>");
            std::process::exit(2);
        }
        let archive = &args.paths[0];
        if args.paths.len() > 2 {
            eprintln!("error: currently only modifications to a single TAR may be committed");
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
        eprintln!("       ratarmount --commit-overlay -w <overlay> <archive.tar>");
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

    // Parallelization: accept Python-style matrix but only use leading integer for now.
    let parallelization = args
        .parallelization
        .split(',')
        .next()
        .and_then(|s| {
            let s = s.trim();
            let s = s.strip_prefix(':').unwrap_or(s);
            s.split(':').next().and_then(|p| p.parse::<u32>().ok())
        })
        .unwrap_or(1);

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
        ..OpenOptions::default()
    };

    if args.force_folder_index {
        eprintln!("info: --force-folder-index accepted; folders still bind-mount without SQLite");
    }

    let file_versions = if args.no_file_versions {
        false
    } else {
        true // default on; --file-versions is explicit enable (same)
    };

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
            },
        },
    ) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    };

    let mut _temp_overlay: Option<tempfile::TempDir> = None;
    let mut overlay_arc: Option<Arc<WriteOverlay>> = None;

    if let Some(w) = &args.write_overlay {
        let overlay_path = if w.as_os_str() == ":temp:" {
            let td = tempfile::TempDir::with_prefix("ratarmount-write-overlay.")
                .expect("temp overlay");
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

    // Optional control Unix socket (status / unmount).
    let control_stop = Arc::new(AtomicBool::new(false));
    let _control_sock = if args.control_interface {
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

fn init_logger(debug: u8, log_file: Option<&Path>, use_color: bool) {
    let level = match debug {
        0 => log::LevelFilter::Error,
        1 => log::LevelFilter::Warn,
        2 => log::LevelFilter::Info,
        _ => log::LevelFilter::Debug,
    };
    // RUST_LOG still wins if set (env_logger convention via filter_or).
    let mut builder = env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(level.as_str()),
    );
    builder.filter_level(level);
    builder.write_style(if use_color {
        env_logger::WriteStyle::Auto
    } else {
        env_logger::WriteStyle::Never
    });
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
    println!(
        "  compositing: automount,union,folder,write-overlay,file-versions,prefix,transform"
    );
    println!("  remote: http,https,file,s3,ssh,sftp");
    println!("  index: --index-file, --index-folders, :memory:");
    println!("  control: --control-interface (unix socket)");
}

fn print_oss_attributions(full: bool) {
    println!("ratarmount {VERSION} (Rust) — open source components (non-exhaustive):");
    let short = [
        "fuser (MIT)",
        "rusqlite / SQLite (MIT / public domain)",
        "flate2 / miniz (MIT/Zlib)",
        "bzip2-rs / libbz2",
        "xz2 / liblzma",
        "zstd",
        "lz4_flex",
        "aes / sha2",
        "fatfs",
        "lopdf",
        "git2 / libgit2",
        "libarchive (via FFI)",
        "clap, regex, thiserror, nix, …",
    ];
    for s in short {
        println!("  - {s}");
    }
    if full {
        println!();
        println!("Full license texts ship with the respective crates on crates.io / system packages.");
        println!("This binary is MIT-licensed; see LICENSE in the source tree.");
    }
}

/// Listen for line-based control commands on a Unix socket.
fn start_control_interface(mountpoint: &Path, stop: Arc<AtomicBool>) -> Option<PathBuf> {
    let sock = std::env::temp_dir().join(format!(
        "ratarmount-control-{}.sock",
        std::process::id()
    ));
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

fn is_fuse_mount(path: &Path) -> bool {
    // Prefer /proc/self/mountinfo when available
    if let Ok(text) = std::fs::read_to_string("/proc/self/mountinfo") {
        let target = path.to_string_lossy();
        if text.lines().any(|l| l.contains(&*target)) {
            return true;
        }
    }
    // Fallback: non-empty readdir often works once FUSE is up
    if let Ok(mut rd) = std::fs::read_dir(path) {
        // Mounted empty archives still allow readdir
        let _ = rd.next();
        // Check mount source type via statfs if possible
        return path_is_fuse(path);
    }
    false
}

fn path_is_fuse(path: &Path) -> bool {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    #[repr(C)]
    struct Statfs {
        f_type: i64,
        _pad: [u8; 128],
    }
    // FUSE_SUPER_MAGIC 0x65735546
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
    let devnull = OpenOptions::new().read(true).write(true).open("/dev/null")?;
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
