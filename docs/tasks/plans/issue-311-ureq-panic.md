# Issue #311: ureq 2.12.1 panics when the server resets after a complete reply

| Field | Value |
|-------|--------|
| **Issue** | #311 — Investigate: ureq 2.12.1 panics at `response.rs:403` when the server resets the connection after replying (follow-up of #297 / PR #302) |
| **Status** | Investigation only. No production change. Any fix plan goes through Keystone. |
| **Base** | `origin/main` 2019fd7 |
| **Platforms affected** | macOS, verified upstream and in our CI (#297). Not Linux: no natively reproducible failure there. Other BSDs and Windows: unknown. |

## TL;DR

- Both panics are `expect()` calls in ureq 2.12.1's `Response::stream_to_reader`, which runs inside
  `call()` / `send_*()`. Each fires when `Stream::reset()` → `TcpStream::set_read_timeout(None)` fails
  while ureq returns the connection to the pool. That happens only for bodies that ureq has
  already fully buffered, or that are empty.
- On macOS, `setsockopt(SO_RCVTIMEO/SO_SNDTIMEO)` returns `EINVAL` once the peer has reset the
  connection. A typical trigger is a server that closes without reading the whole request. On Linux
  the call succeeds on a reset socket. Natively on Linux we got 0 panics in 24 000 rounds. With
  `LD_PRELOAD` fault injection that models the macOS behaviour, the panic reproduces 20/20.
- The panic happens **before the caller sees the response**. Neither the caller's body handling
  (`into_string` / `into_reader`) nor `Connection: close` nor a non-pooled agent avoids it. We
  verified all three under injection.
- Upstream: algesten/ureq#1219 (closed). ureq 3 is fixed in **3.5.1** (PR #1220: on macOS only,
  `InvalidInput` from the timeout setter is tolerated). ureq 2 is **not fixed**: no release after
  2.12.1 on crates.io, and both `expect`s are still present at the head of the `2.12.x-msrv1.71`
  branch.
- Recommendation: fix it by finishing the ureq 3 migration already planned under this issue
  (S3 → S4a → S4b), with a floor of `ureq >= 3.5.1` (3.5.2 is current). Add a macOS-only
  regression test with the S4b flip. An optional interim guard is a `catch_unwind` at the facade
  boundary (option B).

## 1. The panic condition

`~/.cargo/registry/src/index.crates.io-*/ureq-2.12.1/src/response.rs`, in `Response::stream_to_reader`,
called from `Response::do_from_stream` (line 612). That function runs inside `Request::call()` /
`send_bytes()` / `send_string()`, before a `Response` exists:

```rust
// response.rs:363-369
let inner = stream.inner_ref();
let result = inner.set_read_timeout(unit.agent.config.timeout_read);
if let Err(e) = result {
    return Box::new(ErrorReader(e));          // (A) setter failure -> deferred body error, no panic
}
let buffer_len = inner.buffer().len();
...
BodyType::LengthDelimited(len) => {
    match NonZeroUsize::new(len) {
        None => {
            debug!("zero-length body returning stream directly to pool");
            let stream: Stream = stream.into();
            // TODO: This expect can actually panic if we get an error when
            // returning the stream to the pool. We reset the read timeouts
            // when we do that, and since that's a syscall it can fail.
            stream.return_to_pool().expect("returning stream to pool");          // line 389
            Box::new(std::io::empty())
        }
        Some(len) => {
            let mut limited_read = LimitedRead::new(stream, len);
            if len.get() <= buffer_len {
                debug!("Body entirely buffered (length: {})", len);
                let mut buf = vec![0; len.get()];
                // TODO: This expect can actually panic ...
                limited_read
                    .read_exact(&mut buf)
                    .expect("failed to read exact buffer length from stream");  // line 403
                Box::new(Cursor::new(buf))
            } else { Box::new(limited_read) }                                    // streamed
        }
    }
}
```

The call chain at line 403 is as follows. `read_exact` reads through `LimitedRead::read`. The bytes come
from the `BufReader` buffer, and `DeadlineStream::read` (`stream.rs:116-120`) serves those without
a syscall. When `remaining() == 0`, `LimitedRead` calls `return_stream_to_pool()?`
(`response.rs:878-879`), which calls `Stream::return_to_pool` and then `Stream::reset()` (`stream.rs:254-269`):

```rust
pub(crate) fn return_to_pool(mut self) -> io::Result<()> {
    self.reset()?;                                        // runs before the pool returner is consulted
    self.pool_returner.clone().return_to_pool(self);
    Ok(())
}
pub(crate) fn reset(&mut self) -> io::Result<()> {
    if let Some(socket) = self.socket() {                 // plain TCP and rustls (rtls.rs:33) both Some
        socket.set_read_timeout(None)?;
        socket.set_write_timeout(None)?;
    }
    Ok(())
}
```

So the only failure source at 403 is the `setsockopt` inside `reset()`. Line 389 is the same call
without the `LimitedRead`.

**Which responses take these branches:**

- **Line 389:** every `HEAD` response, `204` and `304` (`body_type`, `response.rs:320-329`), and
  `Content-Length: 0`.
- **Line 403:** a `Content-Length` body that arrived in the same reads as the headers. The limit is
  the `BufReader` capacity, which is the std default of 8 KiB (`stream.rs:195`). This includes small
  `Status` error bodies, such as a 403 XML from S3, because `Error::Status` is built from the
  `Response` after `do_from_stream`.
- **No panic, but the same setter failure:** for chunked bodies (`PoolReturnRead`, `pool.rs:283`)
  and streamed `LimitedRead` bodies over the buffer size, `return_to_pool()?` turns the failure into
  an `Err` on the final read of a **complete** body. The caller sees an I/O error and drops a
  response that is complete.

**Why it is a race on macOS:** the setter at line 364 runs first. If the RST has already been
processed by then, that call fails instead and becomes the non-panicking `ErrorReader` (A). The
panic needs the RST to land between line 364 and the reset at 389/403, a window of microseconds.
That fits the rare, flaky failure in #297 (macOS CI, `regression_served_kind_webdav_through_the_real_opener`,
which passed on rerun). It also fits upstream's measured rate of about 0.5% panics with RST on
macOS (10/2000 runs). A request with a deadline (`Request::timeout`, our `Profile::Probe`) also
calls the setter before every socket read (`stream.rs:83-90`). Those requests fail more often, and
earlier, with `Error encountered in a header/the status line: Invalid argument`, but they still panic
sometimes (see §2).

**OS behaviour:**

- **XNU:** our understanding, from memory and not checked offline, is that `sosetopt` rejects
  options with `EINVAL` once the socket is `SS_CANTRCVMORE|SS_CANTSENDMORE`, which an RST produces.
  Upstream #1219 measured the result: after a peer close with unread request data,
  `set_read_timeout` returned `EINVAL` in 300/300 runs while `read()` still returned the full
  response.
- **Linux:** `SO_RCVTIMEO` has no socket-state check. Our native runs confirm that it succeeds on
  a reset socket.

## 2. Reproduction

Standalone crate, outside the tree (scratch, not committed). It pins `ureq = "=2.12.1"` with
`default-features = false`; the plain-HTTP path is the same as with our `tls` feature. The server
reads the request head, writes the whole response in **one** write, optionally sleeps, then sets
`SO_LINGER 0` and closes (RST). In `unread` mode the client instead POSTs 4 KiB that the server
never reads, and a normal `close()` then sends an RST by itself, as in #297.

### 2a. Native Linux (kernel 7.0, x86_64): does not reproduce

Fresh agent per request (`nopool`), 3000 rounds each:

| body | GET + RST | POST, unread body, close |
|------|-----------|--------------------------|
| `Content-Length: 0` | 3000 ok, 0 panic | 3000 ok, 0 panic |
| 5-byte buffered body | 3000 ok, 0 panic | 3000 ok, 0 panic |
| chunked | 3000 ok, 0 panic | 3000 ok, 0 panic |
| 64 KiB streamed | 2999 ok, 1 `ECONNRESET`, 0 panic | 2999 ok, 1 `ECONNRESET`, 0 panic |

A side observation, not part of #311: with a **pooled** agent, about a third to a half of requests
fail with `Connection reset by peer`. ureq reuses the pooled connection that the server already
reset (`GET` + RST: 983/3000 errors for zero-length bodies, 1320/3000 for small bodies). The facade's
pooled-stale contract tests (`contract_pooled_stale_*`) cover ureq's retry rules. This test server
resets every connection, so it is an extreme case.

### 2b. Linux with fault injection that models macOS: reproduces deterministically

`shim.c` is an `LD_PRELOAD` wrapper for `setsockopt`. For `SOL_SOCKET` with `SO_RCVTIMEO` or
`SO_SNDTIMEO`, it returns `EINVAL` when `TCP_INFO` reports `tcpi_state == TCP_CLOSE`, which is the
state after an RST. That models the XNU rule. With `SHIM_SLEEP_MS` set, it also sleeps after every
*successful* timeout set, which widens the window between line 364 and the reset. In the widened
runs below, the server sleeps 20 ms before the RST and the shim sleeps 100 ms.

| Scenario | Result |
|----------|--------|
| `Content-Length: 0`, widened, fresh agent | **20/20 panic** `returning stream to pool: Os { code: 22, kind: InvalidInput, message: "Invalid argument" }` (line 389) |
| 5-byte body, widened, fresh agent | **20/20 panic** `failed to read exact buffer length from stream: Os { code: 22, kind: InvalidInput, message: "Invalid argument" }` (line 403) |
| same, plus `Connection: close` in the response | 20/20 panic (both lines). `set_unpoolable()` does not skip `reset()`. |
| same, shared pooled agent | 20/20 panic (both lines) |
| same, body read with `into_reader().read_to_end` instead of `into_string` | 20/20 panic (both lines). It panics inside `call()`. |
| same, POST with unread body, normal close (#297 shape) | 20/20 panic (both lines) |
| same, with `Request::timeout(5 s)` (deadline) | 20/20 `Err`: `Error encountered in the status line: Invalid argument`. In this widened setup the deadline path fails first. |
| chunked / 64 KiB streamed, widened | 20/20 `Err(Invalid argument)`: complete body lost, no panic |
| no widening (natural race), 2000 rounds, 0-length / small | 183 / 283 panics, 606 / 790 `Err`, the rest OK |
| no widening, unread-body POST, 2000 rounds, 0-length / small | 216 / 440 panics |
| no widening, with deadline, 2000 rounds, 0-length / small | 63 / 116 panics, about 890 `Err` (mostly `Error encountered in a header`) |
| no widening, **shared pooled agent**, 2000 rounds, small / 0-length | 285 / 364 panics interleaved with 860 / 654 OK on the **same agent** (no `PoisonError`, agent keeps serving after each caught panic) |
| control: no shim, with deadline, small, 3000 rounds | 3000 ok |

The panic message and the `os error 22` match #297 / PR #302.

Commands, from the scratch crate:

```sh
cc -shared -fPIC -O2 -o shim.so shim.c -ldl
cargo build --release --offline        # own CARGO_TARGET_DIR
repro311 small 3000 nopool             # native: 0 panics
LD_PRELOAD=$PWD/shim.so SHIM_SLEEP_MS=100 repro311 small 20 nopool delay=20             # 20/20 panic @403
LD_PRELOAD=$PWD/shim.so SHIM_SLEEP_MS=100 repro311 zero  20 nopool delay=20 connclose   # 20/20 panic @389
```

<details><summary><code>shim.c</code></summary>

```c
// LD_PRELOAD fault injection modelling XNU: setsockopt(SOL_SOCKET,
// SO_RCVTIMEO/SO_SNDTIMEO) returns EINVAL once the TCP connection is closed
// in both directions (Linux tcpi_state == TCP_CLOSE after an RST).
// SHIM_SLEEP_MS: sleep after every *successful* timeout set, to widen the
// window between ureq's response.rs:364 set and the later reset.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>

int setsockopt(int fd, int level, int name, const void *val, socklen_t len) {
    static int (*real)(int, int, int, const void *, socklen_t);
    if (!real) real = dlsym(RTLD_NEXT, "setsockopt");
    if (level == SOL_SOCKET && (name == SO_RCVTIMEO || name == SO_SNDTIMEO)) {
        struct tcp_info ti; socklen_t l = sizeof ti;
        if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, &ti, &l) == 0 && ti.tcpi_state == TCP_CLOSE) {
            if (getenv("SHIM_TRACE")) fprintf(stderr, "[shim] fd %d closed -> EINVAL\n", fd);
            errno = EINVAL;
            return -1;
        }
        int r = real(fd, level, name, val, len);
        const char *s = getenv("SHIM_SLEEP_MS");
        if (r == 0 && s) usleep(atoi(s) * 1000);
        return r;
    }
    return real(fd, level, name, val, len);
}
```
</details>

<details><summary><code>Cargo.toml</code> and <code>src/main.rs</code></summary>

```toml
[package]
name = "repro311"
version = "0.0.0"
edition = "2021"
publish = false

[dependencies]
ureq = { version = "=2.12.1", default-features = false }
libc = "0.2"

[workspace]
```

```rust
//! #311 repro: a server sends a complete HTTP response, then resets the
//! connection (SO_LINGER 0 + close -> RST). Usage:
//!   repro311 <zero|small|chunked|big> <rounds> [connclose] [nopool] [unread] [delay=MS] [reader] [deadline]
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::fd::AsRawFd;
use std::time::Duration;

fn set_linger0(s: &std::net::TcpStream) {
    let l = libc::linger { l_onoff: 1, l_linger: 0 };
    let r = unsafe {
        libc::setsockopt(s.as_raw_fd(), libc::SOL_SOCKET, libc::SO_LINGER,
            &l as *const _ as *const libc::c_void, std::mem::size_of::<libc::linger>() as u32)
    };
    assert_eq!(r, 0);
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let kind = a.get(1).cloned().unwrap_or("small".into());
    let rounds: usize = a.get(2).and_then(|s| s.parse().ok()).unwrap_or(100);
    let has = |f: &str| a.iter().any(|x| x == f);
    let connclose = has("connclose");
    let nopool = has("nopool");
    let unread = has("unread"); // client POSTs a body the server never reads; close then RSTs by itself
    let use_reader = has("reader");
    let delay: u64 = a.iter().find_map(|x| x.strip_prefix("delay=").and_then(|v| v.parse().ok())).unwrap_or(0);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/x", listener.local_addr().unwrap());
    let k2 = kind.clone();
    std::thread::spawn(move || {
        for s in listener.incoming() {
            let mut s = match s { Ok(s) => s, Err(_) => continue };
            // read the request head only (body, if any, stays unread when `unread`)
            let mut buf = Vec::new();
            let mut b = [0u8; 1];
            while !buf.ends_with(b"\r\n\r\n") {
                if s.read(&mut b).unwrap_or(0) == 0 { break; }
                buf.push(b[0]);
            }
            let cc = if connclose { "Connection: close\r\n" } else { "" };
            let resp: Vec<u8> = match k2.as_str() {
                "zero" => format!("HTTP/1.1 200 OK\r\n{cc}Content-Length: 0\r\n\r\n").into_bytes(),
                "small" => format!("HTTP/1.1 207 Multi-Status\r\n{cc}Content-Length: 5\r\n\r\nhello").into_bytes(),
                "chunked" => format!("HTTP/1.1 200 OK\r\n{cc}Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n").into_bytes(),
                _ => { // body larger than the 8 KiB BufReader: streamed LimitedRead
                    let mut v = format!("HTTP/1.1 200 OK\r\n{cc}Content-Length: 65536\r\n\r\n").into_bytes();
                    v.extend(std::iter::repeat(b'a').take(65536)); v }
            };
            s.write_all(&resp).unwrap(); // single write: headers + body together
            if delay > 0 { std::thread::sleep(Duration::from_millis(delay)); }
            if !unread { set_linger0(&s); }
            drop(s);
        }
    });

    std::panic::set_hook(Box::new(|_| {})); // count, don't spam
    let mut b = ureq::AgentBuilder::new().timeout_connect(Duration::from_secs(30)).redirects(0);
    if nopool { b = b.max_idle_connections(0); }
    let agent = b.build();
    let (mut ok, mut err, mut panics) = (0, 0, 0);
    let mut errs = std::collections::BTreeMap::<String, usize>::new();
    let mut pmsgs = std::collections::BTreeMap::<String, usize>::new();
    for _ in 0..rounds {
        let agent = if nopool { ureq::AgentBuilder::new().redirects(0).build() } else { agent.clone() };
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut req = agent.request(if unread { "POST" } else { "GET" }, &url);
            if has("deadline") { req = req.timeout(Duration::from_secs(5)); }
            let resp = if unread { req.send_bytes(&[b'x'; 4096]) } else { req.call() };
            match resp {
                Ok(r) => {
                    if use_reader { let mut v = Vec::new(); r.into_reader().read_to_end(&mut v).map(|_| ()) }
                    else { r.into_string().map(|_| ()) }
                }
                Err(e) => Err(std::io::Error::other(e.to_string())),
            }
        }));
        match r {
            Ok(Ok(())) => ok += 1,
            Ok(Err(e)) => { err += 1; *errs.entry(e.to_string()).or_default() += 1; }
            Err(p) => {
                panics += 1;
                let m = p.downcast_ref::<String>().cloned().or(p.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default();
                *pmsgs.entry(m).or_default() += 1;
            }
        }
    }
    println!("{kind} rounds={rounds} connclose={connclose} nopool={nopool} unread={unread} delay={delay} reader={use_reader}: ok={ok} err={err} panic={panics}");
    for (k, v) in errs { println!("  err  x{v}: {k}"); }
    for (k, v) in pmsgs { println!("  panic x{v}: {k}"); }
}
```
</details>

**No `#[ignore]`d test is committed:**

- On Linux it cannot fail natively. The only deterministic form needs a C compiler and an
  `LD_PRELOAD` shim injected into a re-executed test binary, which is test infrastructure for one
  ureq-2 bug that the migration removes.
- On macOS it is a microsecond race, about 0.5% upstream, so it would be flaky.
- The useful regression lands with the fix (see §4).

## 3. Reachability in our code

Every **ureq** user goes through ureq 2.12.1, either via the facade or directly, so every path below
reaches `do_from_stream`. The only other HTTP client in `Cargo.lock` is `reqwest`, pulled in by
`librqbit` under the `bittorrent` feature (trackers, UPnP). That path is not affected by this bug.
`hyper` comes in through `axum` and `tonic`, which are servers. On macOS, a path panics if it can get a HEAD, 204 or 304 response, a
`Content-Length: 0` response, or a small body, and the server resets the connection after
replying. That is likely when a server answers or rejects **before reading the whole request
body**: S3, GCS and Azure answering an upload with 4xx, 413 or a redirect, or a proxy or load
balancer that resets after a response with `Connection: close`.

### Via the facade (`ratarmount_index::http_client`, S1a/S1b/S2)

The facade is `ureq::AgentBuilder` plus `agent.request(..).call()` / `send_*`
(`http_client.rs:425-460`), so it is the same code path as the repro. Its users:

- `ratarmount-remote/src/http_pool.rs`: remote HTTP range reads, HEAD/size probes, redirect hops,
  X-Linked-Etag. Callers: `lib`, `webdav` (PROPFIND, the #297 path), `folder`, `oci`, `ipfs`,
  `dropbox`, `hf`, `hf_commit`, torrent metadata.

### Direct `ureq::` (S3 carry and others)

All of these are production code unless marked otherwise.

- `ratarmount-remote/src/s3.rs`: GET at 306, 612 and 668; GET at 2028 and 2075 (in
  `s3_list_objects_v2_page`); PUT at 326; HEAD at 709 and 762; `request(verb)` at 961 (multipart
  and index-sibling uploads).
- `ratarmount-remote/src/gcs.rs`: GET at 374 and 828; GET at 1508 (`gcs_list_page`) and 1535
  (`gcs_list_page_xml`); POST at 425 (token); HEAD at 857; PUT at 964.
- `ratarmount-remote/src/azure.rs`: GET at 435 and 760; GET at 1708 (`azure_list_page`); PUT at
  1064; HEAD at 1113.
- `ratarmount-index/src/location.rs:1584`: GET in `fetch_index_http_uncached`, the remote sidecar
  fetch. `location.rs:2834` is a HEAD inside the test `link_describedby_archive_head`, so it is not
  production.
- `ratarmount/src/overlay_cmd.rs:834`: an `AgentBuilder` in `remote_base_token`, the remote base
  identity probe for overlay verbs.
- The PR bodies of #318 and #322 name only `s3`, `gcs` and `azure` as the S3 carry. The facade
  header says callers move "in S2/S3". `location.rs:1584` and `overlay_cmd.rs:834` are not named in the PR
  bodies we read, so the plan should state their slice explicitly.

### Response shapes that reach each line

| Line | Responses |
|------|-----------|
| 389 | Every HEAD (size and identity probes in http_pool, s3, gcs, azure, location); 204s (deletes); `Content-Length: 0` replies (redirects, some PUT/POST acknowledgements) |
| 403 | Small range reads (TAR headers, `.index.ptr` pointers, small sidecar or metadata JSON), WebDAV PROPFIND 207s, and any small 4xx/5xx error body |
| Error only, no panic | Large range bodies (> about 8 KiB minus headers) and chunked bodies. A complete body ends in an `Err` on its last read (§1). |

### Blast radius

The panic is ordinary unwinding:

- The workspace `Cargo.toml` has no `[profile]` section with `panic = "abort"`, and there is no
  `.cargo/config`.
- No `-C panic=abort` appears in `packaging/` or `.github/workflows/`. The only `RUSTFLAGS` is CI's
  `-Dwarnings`, so release and package builds unwind too.

The effect therefore depends on the thread:

- **`http-range` prefetch workers** (`http_pool.rs:1065`): contained. `worker.join()` maps the
  panic to `io::Error::other("HTTP range worker panicked")` (`http_pool.rs:1117-1119`). The
  default panic hook still prints to stderr.
- **FUSE request thread:** fuser 0.18 runs even `n_threads = 1` on a spawned `fuser-0` thread
  (`fuser-0.18.0/src/session.rs:290-316`) and has no `catch_unwind`. Remote reads fetch on the calling thread:
  `HttpRangeFile`'s `Read` (`ratarmount-remote/src/lib.rs:1455-1495`) falls back from the
  prefetcher to `read_into_with_pattern` (`http_pool.rs:640-660`), which calls `fetch` or
  `range_reader` and then the facade. When the caller is a FUSE `read` callback, that is the
  `fuser-0` thread. We traced the chain through `ratarmount-remote` only. That `MountSource` reads
  run on the event-loop thread follows from fuser's design, and we did not trace every FUSE
  callback. A panic there ends the event loop. `run()`
  returns `Err("event loop thread panicked")`, `fuse_session_result` passes it through
  (`ratarmount-fuse/src/lib.rs:3995`), and `mount_blocking` returns the error. The **whole mount
  ends** and the process exits with an error. Two consequences are inferred and were not observed
  here: that the session's mount guard unmounts on drop, and that macOS readers then get
  `ENXIO`/`EIO`.
- **Main thread** (mount setup and index build over a remote archive, `--publish-index`, live and
  offline remote commits, `overlay` verbs that probe or fetch): the process exits with status 101
  and a panic message. Offline commits and the journal recovery that follows are not covered by
  this investigation.
- **Export servers** (NFS, 9P, SMB, SFTP, HTTP) serving a remote source: not audited. The
  behaviour depends on each server's thread or task model (a tokio task's panic is contained in
  its `JoinHandle`, but a plain thread loop dies).
- **Python bindings** (pyo3 0.29): a panic that crosses a `#[pyfunction]` boundary becomes
  `pyo3_runtime.PanicException`. Inferred from pyo3's documented behaviour, not tested here.
- **Lock poisoning:** `http_pool` recovers poisoned locks (`unwrap_or_else(|e| e.into_inner())`
  throughout). Inside ureq, `reset()` fails before `pool.add`, so the agent's pool mutex is not held
  while it unwinds. We did not audit other callers for a `Mutex` held across a request.

Practical exposure: macOS builds (portable tarball, Homebrew) using any remote source or remote
publish. The panic is rare per request but fatal for a FUSE mount. On Linux nothing changes, apart
from the pooled-stale behaviour in §2a.

## 4. Upstream status

Checked with `gh api` against GitHub and with the crates.io API, 2026-11-15:

- **algesten/ureq#1219** (opened 2026-10-21, closed 2026-10-22): "macOS: `set_read_timeout`
  fails with EINVAL after the server has closed, so a fully received response is lost (3.x: error;
  2.x: panic on pool return)". It names exactly these two `expect`s and measures 10/2000 panics
  with RST on 2.12.1, macOS. The reporter mentions carrying a local patch for 2.x.
- **ureq 3:** fixed by PR **#1220** (merged 2026-10-22), released in **3.5.1** (crates.io
  2026-11-02). Changelog: "Preserve readable responses after macOS rejects timeout changes on closed
  sockets #1220". At 3.5.1 `src/unversioned/transport/tcp.rs`:
  ```rust
  // macOS can reject timeout changes after the peer closes with unread
  // request data. The response may still be readable: let I/O report the
  // outcome instead. Leave the cache unchanged since the setter failed.
  Err(e) if cfg!(target_os = "macos") && e.kind() == io::ErrorKind::InvalidInput => {}
  ```
  - The tolerance is **macOS only**: FreeBSD and other BSDs still get the error, though not a
    panic.
  - **3.5.0 and 3.4.3 error** on this condition: no panic, but the response is lost.
    `maybe_update_timeout` uses `?` at both tags, as checked through `gh api`. The maintainer's
    "use 3.4.3 until we fix 3.5.0" refers to other 3.5.0 issues; 3.4.3 is not free of this one.
  - The TLS connectors chain over `TcpTransport`, so TLS should share the fix (inferred from the
    source).
  - Current release: 3.5.2 (2026-11-12, `rust-version = 1.85`, below our 1.90 MSRV).
- **ureq 2:** **not fixed**.
  - crates.io: newest 2.x is 2.12.1 (2024-12-04), not yanked.
  - The `2.12.x-msrv1.71` branch head is 59989e10 (2026-07-22, #1186). It still has both
    `expect`s with their TODO comments (`src/response.rs:389`, `:403`).
  - The branch is still maintained (it got a fix in 2026-07), so a 2.12.2 is possible but not
    announced.

## 5. Options for callers (for Keystone)

| Option | What it does | Covers | Trade-offs |
|--------|--------------|--------|------------|
| **A. Avoid the path** (`Connection: close`, a non-pooled agent, reading bodies differently, a deadline) | — | **Nothing** | Shown dead under injection (§2b): `reset()` runs before the pool returner is consulted and before the caller gets the response. A deadline only moves most failures earlier (to a header `Err`) and still panics sometimes. ureq 2 offers no plain-TCP custom transport to intercept the setter. |
| **B. `catch_unwind` at the facade boundary** | Wrap `call` / `send_*` in `catch_unwind(AssertUnwindSafe(..))` and map a panic to a `TransportError` of kind `Io` (for example "connection reset after response (ureq 2)") | Facade users now. Direct callers only after S3 moves them, or with duplicate wrappers. | Small, contained, and removed at S4b. Risks and costs: unwind safety holds in practice. No ureq lock is held at the panic, and §2b's natural-race run shows a shared pooled agent keeps serving after 285 caught panics with no `PoisonError`. The default hook still prints a panic message unless a filtering hook is installed, which is process-global and unattractive. The complete response is lost; idempotent GET and HEAD could retry. It cannot help builds with `panic = "abort"` (none today). It needs a test: the §2b shim, or a test-only seam. |
| **C. Finish the ureq 3 migration** (S3 direct callers → S4a facade-owned redirects → S4b engine flip) | Engine without the panic. On macOS also keeps the response instead of an error. | Everything, once all callers are on the facade | Already planned under #311 (PRs #318 and #322 say "planned for #311"). Must pin `ureq >= 3.5.1`. 3.5.0 and 3.4.3 both propagate the setter error with `?` in `maybe_update_timeout` (checked at both tags), so they give an error, not a panic, and the response is lost. Tolerance is macOS-only upstream. The S1b contract expectations flip at S4b anyway. Largest change, but it is the work already in flight. |
| **D. Pin or patch ureq 2** (`[patch.crates-io]` fork, or vendoring with the two `expect`s replaced by `ErrorReader` / dropping the stream) | Turns the panic into an `Err`, or drops the connection | Everything at once | Small diff, but a fork to maintain for a dependency we are leaving. Precedent: `vendor/librqbit`. It does not fix the non-panic data loss (A path, chunked and streamed). Alternatively, send the two-line fix upstream to `2.12.x-msrv1.71` and adopt a 2.12.2 if one ships. That costs nothing to us but its timing is unknown. |

**Recommendation**

1. Keep the fix in option C, since this issue already anchors the migration.
   - Add an explicit floor `ureq = ">=3.5.1"` (prefer 3.5.2) in the S4b plan.
   - Make the S3 slice list name `location.rs:1584/2834` and `overlay_cmd.rs:834` along with
     `s3`, `gcs` and `azure`.
   - Add a `#[cfg(target_os = "macos")]` contract test at S4b, using upstream #1219's shape: the
     server reads part of a POST, answers `302` with `Content-Length: 0`, and closes. Assert the
     status arrives. Also run a small-body variant to cover line 403's shape.
   - The test passes reliably on a fixed engine, but on a regressed one it fails only
     occasionally. Through ureq, upstream measured 5/5000 to 58/2000 failures on 3.5.0. The 300/300
     figure applies only to the bare setter after a 20 ms sleep.
   - So the test needs many rounds, or a server design that forces the peer close to land before
     ureq's timeout update. One example is a request with a deadline, where the update happens
     before every read. Neither design is tested here.
2. If S4b is more than a few weeks out, land option B as a small interim guard on the facade.
   - It immediately protects the FUSE thread for the http_pool users, the hot path for remote
     mounts, and S3 then moves the direct callers under it.
   - Because of the hook noise, B is a stopgap and should be deleted at S4b.
3. Option D is not recommended unless the migration stalls. Optionally offer the 2.12.x patch
   upstream, since that is cheap.
4. Option A should not be pursued: it does not work.

Open items Keystone may want checked first:

- The macOS-native behaviour of the facade's own WebDAV test after S4b.
- Whether any export server runs remote fetches on a plain thread whose death takes down the
  server.
- Windows and FreeBSD setter semantics on a reset socket (unknown).
