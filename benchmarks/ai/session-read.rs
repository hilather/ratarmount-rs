//! Session baseline with the same 128 KiB caller requests as cat. No FUSE or full-member Vec.
use ratarmount_session::{
    IndexPolicy, OpenRequest, ParallelizationSpec, ReadRequest, Recreate, Session, SourceSpec,
};
use std::fs::File;
use std::io::Read;
use std::time::Instant;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 4 {
        return Err("usage: ai-zstd-read ARCHIVE MEMBER THREADS".into());
    }
    let threads: u32 = args[3].parse()?;
    let session = Session::open(OpenRequest {
        source: SourceSpec::Path(args[1].clone().into()),
        index: IndexPolicy::Sibling,
        explicit_index: None,
        extra_dirs: Vec::new(),
        password: None,
        recursive: false,
        recursion_depth: None,
        parallelization: ParallelizationSpec::new(threads),
        recreate: Recreate::IfInvalid,
    })?;
    let mut archive = File::open(&args[1])?;
    match std::env::var("CACHE").as_deref().unwrap_or("warm") {
        "warm" => {
            std::io::copy(&mut archive, &mut std::io::sink())?;
        }
        "cold" => {
            #[cfg(target_os = "linux")]
            {
                use std::os::fd::AsRawFd;
                // SAFETY: archive owns a live read-only fd; this is advisory.
                unsafe {
                    libc::posix_fadvise(archive.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED);
                }
            }
        }
        _ => return Err("CACHE must be warm or cold".into()),
    }
    let before = ratarmount_compress::zstd_decode_stats();
    let mut reader = session.read_range(ReadRequest {
        path: args[2].clone(),
        offset: 0,
        max_len: u64::MAX,
    })?;
    let mut buffer = vec![0; 128 * 1024];
    let cpu_start = cpu_seconds();
    let start = Instant::now();
    let mut bytes = 0u64;
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        // Keep the copy observable without adding a per-byte checksum bottleneck.
        std::hint::black_box(&buffer[..n]);
        bytes += n as u64;
    }
    let seconds = start.elapsed().as_secs_f64();
    let cpu = cpu_seconds() - cpu_start;
    drop(reader);
    let after = ratarmount_compress::zstd_decode_stats();
    println!("session-read-summary bytes={bytes} seconds={seconds:.6} MB_per_s={:.3} CPU_percent={:.1} prefetched={} ready={} waited={} synchronous={} synchronous_ns={} wait_ns={} reused={}",
        bytes as f64 / seconds / 1e6, 100.0 * cpu / seconds,
        after.prefetched-before.prefetched, after.ready-before.ready, after.waited-before.waited,
        after.synchronous-before.synchronous, after.synchronous_ns-before.synchronous_ns,
        after.wait_ns-before.wait_ns, after.reused-before.reused);
    Ok(())
}

fn cpu_seconds() -> f64 {
    #[cfg(unix)]
    {
        let mut time = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: time points to valid writable storage.
        if unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut time) } == 0 {
            return time.tv_sec as f64 + time.tv_nsec as f64 / 1e9;
        }
    }
    0.0
}
