//! Bounded, process-wide executor. Readers own cancellation and byte reservations.
use std::sync::{mpsc, Arc, Mutex, OnceLock};

type Job = Box<dyn FnOnce() + Send>;

struct Pool {
    pid: u32,
    sender: mpsc::SyncSender<Job>,
    receiver: Arc<Mutex<mpsc::Receiver<Job>>>,
    workers: u32,
}

/// Queue without waiting: saturated executors fall back to synchronous decoding.
/// Rebuild after CLI daemonization; workers do not survive fork.
pub(super) fn submit(threads: u32, job: Job) -> bool {
    static POOL: OnceLock<Mutex<Option<Pool>>> = OnceLock::new();
    let mut slot = POOL.get_or_init(|| Mutex::new(None)).lock().unwrap();
    let pid = std::process::id();
    if slot.as_ref().is_none_or(|pool| pool.pid != pid) {
        let (sender, receiver) = mpsc::sync_channel(256);
        *slot = Some(Pool {
            pid,
            sender,
            receiver: Arc::new(Mutex::new(receiver)),
            workers: 0,
        });
    }
    let pool = slot.as_mut().unwrap();
    while pool.workers < threads {
        let receiver = Arc::clone(&pool.receiver);
        if std::thread::Builder::new()
            .name("zstd-decode-ahead".into())
            .spawn(move || loop {
                let job = receiver.lock().unwrap().recv();
                match job {
                    Ok(job) => job(),
                    Err(_) => break,
                }
            })
            .is_err()
        {
            break;
        }
        pool.workers += 1;
    }
    pool.workers != 0 && pool.sender.try_send(job).is_ok()
}
