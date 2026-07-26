//! ratarmount CLI (Phases 0–11).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use clap::{ArgAction, Parser};
use nix::unistd::{fork, setsid, ForkResult};
use ratarmount_compress::strip_compression_suffix;
use ratarmount_compositing::WriteOverlay;
use ratarmount_core::{MountSource, OpenOptions};
use ratarmount_fuse::{mount_blocking, unmount};

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

    /// Do not mount; only create/load index
    #[arg(long = "no-mount", action = ArgAction::SetTrue)]
    no_mount: bool,

    /// Recursive mounting of nested archives
    #[arg(short = 'r', long = "recursive", action = ArgAction::SetTrue)]
    recursive: bool,

    /// Detect GNU incremental archives
    #[arg(long = "detect-gnu-incremental", action = ArgAction::SetTrue)]
    detect_gnu_incremental: bool,

    /// Ignore zero-filled TAR blocks (concatenated archives)
    #[arg(long = "ignore-zeros", action = ArgAction::SetTrue)]
    ignore_zeros: bool,

    /// Parallelization (reserved for parallel decompressors)
    #[arg(short = 'P', long = "parallelization", default_value_t = 1)]
    parallelization: u32,

    /// Minimum file count to create an index (harness forces 0)
    #[arg(long = "index-minimum-file-count", default_value_t = 0)]
    index_minimum_file_count: u64,

    /// Explicit index file path
    #[arg(long = "index-file")]
    index_file: Option<PathBuf>,

    /// Gzip seek point spacing (CLI parity)
    #[arg(long = "gzip-seek-point-spacing", default_value_t = 16 * 1024 * 1024)]
    gzip_seek_point_spacing: u64,

    /// Recursion depth for --recursive (0 = deep default)
    #[arg(long = "recursion-depth", default_value_t = 0)]
    recursion_depth: i32,

    /// Write overlay folder (`:temp:` for a temporary directory)
    #[arg(short = 'w', long = "write-overlay")]
    write_overlay: Option<PathBuf>,

    /// Password for encrypted archives (repeatable)
    #[arg(long = "password", action = ArgAction::Append)]
    passwords: Vec<String>,

    /// Print version and build feature summary
    #[arg(long = "print-features", action = ArgAction::SetTrue)]
    print_features: bool,

    /// Input archives/folders/URLs and optional mountpoint
    #[arg(required = false)]
    paths: Vec<PathBuf>,
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();
    let args = Args::parse();

    if args.print_features {
        print_features();
        return;
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

    if args.paths.is_empty() {
        eprintln!("usage: ratarmount [options] <archive|folder|URL>... [mountpoint]");
        eprintln!("       ratarmount -u <mountpoint>");
        std::process::exit(2);
    }

    let (inputs, mountpoint) = split_inputs_mountpoint(&args.paths, args.no_mount);

    let open_opts = OpenOptions {
        recursive: args.recursive,
        ignore_zeros: args.ignore_zeros,
        gnu_incremental: if args.detect_gnu_incremental {
            None
        } else {
            Some(false)
        },
        parallelization: args.parallelization,
        index_minimum_file_count: args.index_minimum_file_count,
        index_file_path: args.index_file.clone(),
        clear_index_cache: args.recreate_index,
        gzip_seek_point_spacing: args.gzip_seek_point_spacing,
        recursion_depth: if args.recursion_depth == 0 {
            None
        } else {
            Some(args.recursion_depth)
        },
        write_index: true,
        passwords: args.passwords.clone(),
        ..OpenOptions::default()
    };

    let mut bundle = match factory::build_mount_source(
        &inputs,
        &open_opts,
        args.recreate_index,
        args.recursive,
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

    if args.foreground {
        if let Err(e) = mount_blocking(
            Arc::clone(&bundle.source),
            &mp,
            true,
            writable,
            overlay_arc,
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
            let _ = redirect_stdio_to_null();
            if let Err(e) = mount_blocking(
                Arc::clone(&bundle.source),
                &mp,
                true,
                writable,
                overlay_arc,
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

fn print_features() {
    println!("ratarmount {VERSION} (Rust)");
    println!("features:");
    println!("  fuse: fuser (low-level)");
    println!("  compress: gzip,bzip2,xz,zstd (materialize)");
    println!("  formats: tar,zip,ar,cpio,sevenzip,libarchive");
    println!("  compositing: automount,union,folder,write-overlay");
    println!("  remote: http,https,file,s3,ssh,sftp");
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
