# Issue #311: ureq 2.12.1 panics when the server resets after a complete reply

| Field | Value |
|-------|--------|
| **Issue** | [#311](https://github.com/hilather/ratarmount-rs/issues/311) — investigation following [#297](https://github.com/hilather/ratarmount-rs/issues/297) / [PR #302](https://github.com/hilather/ratarmount-rs/pull/302) |
| **Status** | Investigation only. No production change or approved fix plan. All options and recommendations below are inputs to Keystone architecture review. |
| **Base** | `2019fd7`; workspace line numbers below refer to this revision. |
| **Platforms affected** | macOS: reported upstream and confirmed in #297's CI logs. The reset-triggered setter failure was not reproduced on Linux; this is not a guarantee that a setter can never fail there. Other BSDs and Windows: unknown. |
| **Review** | Primary sources rechecked 2026-11-15: local dependency/workspace sources, GitHub API and crates.io API. Historical experiment counts are distinguished from this review's checks in §2. |

## TL;DR

- Both panics are `expect()` calls in ureq 2.12.1's `Response::stream_to_reader`, inside
  `call()` / `send_*()`. `return_to_pool()` calls `Stream::reset()`, which can fail at either
  `TcpStream::set_read_timeout(None)` or `set_write_timeout(None)`. The panicking branches are
  zero-length bodies and positive `Content-Length` bodies already entirely in ureq's buffer.
- On macOS, `setsockopt(SO_RCVTIMEO/SO_SNDTIMEO)` can return `EINVAL` on the resulting closed
  socket. A reported trigger is a server that closes without reading the whole request. On Linux
  the checked kernel timeout-option implementation has no equivalent closed-state rejection.
  The original investigation reports 0 panics in 24 000 native Linux rounds and 20/20 under
  timed `LD_PRELOAD` injection; those historical counts have no attached logs (§2).
- The panic happens **before the caller sees the response**. Neither the caller's body handling
  (`into_string` / `into_reader`) nor `Connection: close` nor disabling cross-request reuse
  removes the reset call. The source proves that a zero-capacity pool also cannot bypass it;
  the supplied `nopool` experiment actually uses fresh agents with default pool capacity.
- Upstream: algesten/ureq#1219 (closed). ureq 3 is fixed in **3.5.1** (PR #1220: on macOS only,
  `InvalidInput` from the timeout setter is tolerated). ureq 2 is **not fixed**: no release after
  2.12.1 on crates.io, and both `expect`s are still present at the head of the `2.12.x-msrv1.71`
  branch.
- Recommendation **for Keystone review**: prefer finishing the existing ureq 3 migration
  (S3 → S4a → S4b), within 3.x and with a minimum of 3.5.1 (3.5.2 is current at review).
  Require deterministic error-injection coverage and macOS integration coverage with the fix.
  A facade `catch_unwind` guard is an alternative to evaluate, not authorized implementation.

## 1. The panic condition

Checked against `~/.cargo/registry/src/index.crates.io-*/ureq-2.12.1/src/response.rs`,
in `Response::stream_to_reader`,
called from `Response::do_from_stream` (line 612). That function runs inside `Request::call()` /
`send_bytes()` / `send_string()`, before a `Response` exists:

Annotated excerpt (omissions and explanatory comments are not verbatim source):

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
    if let Some(socket) = self.socket() {                 // default TCP/rustls exposes the socket (rtls.rs:33)
        socket.set_read_timeout(None)?;
        socket.set_write_timeout(None)?;
    }
    Ok(())
}
```

For this buffered `read_exact` branch, the I/O error that reaches the `expect` comes from a
timeout setter in `reset()`: reading the already buffered bytes does not issue a socket read.
Line 389 calls the same reset without `LimitedRead`. The error text alone does not identify
which of the read/write setters failed. Source: [response.rs](https://github.com/algesten/ureq/blob/2.12.1/src/response.rs#L353),
[stream.rs](https://github.com/algesten/ureq/blob/2.12.1/src/stream.rs#L254).

**Which responses take these branches:**

- **Line 389:** `HEAD`, `204` and `304` select zero length regardless of their headers
  (`response.rs:321-329`). Other `Content-Length: 0` replies do too, unless the preceding
  transfer-encoding branch selects chunked framing (`response.rs:332-348`).
- **Line 403:** a positive `Content-Length` no greater than the bytes **remaining in the buffer
  after header parsing** (`len <= buffer_len`). Small size alone is insufficient: a fragmented
  small body can be streamed instead. `stream.rs:195` uses `BufReader::new`, whose documented
  current default is 8 KiB; there is no universal “8 KiB minus total headers” cutoff because
  header parsing may refill the buffer. Framing is selected before decompression. A small
  4xx/5xx body can qualify: `Request::do_call` creates `Error::Status` only after response
  construction (`request.rs:160-170`).
- **No panic from these two expects:** a non-buffered length-delimited body propagates a reset
  error on the read that reaches its declared length (`response.rs:876-881`), even if small.
  A chunked body propagates it when the decoder reports EOF (`pool.rs:278-305`); it may already
  have delivered all payload bytes. A caller stopping before that EOF may not observe it.
  Close-delimited bodies do not return to the pool on this path (`response.rs:412-414`).
  Earlier timeout/read errors remain possible for every shape. These are classifications of
  the actual response, not guarantees for a large Range request that receives a small error
  response or a redirect.

**Why it is a race on macOS:** the setter at line 364 runs first. If the RST has already been
processed by then, that call fails instead and becomes the non-panicking `ErrorReader` (A). The
panic needs the close-state change to land between line 364 and the reset at 389/403. This is a
narrow timing window; its duration was not measured here. `ErrorReader` leaves status/headers
available and defers the error until a body read, so it does not always lose the whole response.
The #297 macOS CI logs confirm `regression_served_kind_webdav_through_the_real_opener`
failed at `response.rs:403:34` with `Invalid argument` in
[job 129915183618](https://github.com/hilather/ratarmount-rs/actions/runs/42840807379/job/129915183618)
and passed in [rerun job 129955367006](https://github.com/hilather/ratarmount-rs/actions/runs/42840807379/job/129955367006).
Both job logs were retrieved through `gh api` during review. The mechanism also fits upstream's reported rate of about 0.5% panics with RST on
macOS (10/2000 runs). A request with a deadline (`Request::timeout`, our `Profile::Probe`) also
calls the setters on `DeadlineStream::fill_buf` (`stream.rs:83-90`), even when that call will
find buffered data. The `Read` fast path at 116-120 avoids it when bytes are buffered. This
adds earlier failure opportunities during header parsing; §2 reports both errors and panics
with a deadline. `Profile::Probe` defines such a timeout, but has no production user yet;
`overlay_cmd.rs:835` currently configures its own direct agent timeout.

**OS behaviour:**

- **XNU:** checked `sosetoptlock` in Apple's published source at
  [f6217f89, `bsd/kern/uipc_socket.c:4749`](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/uipc_socket.c#L4749).
  It returns `EINVAL` when both `SS_CANTRCVMORE` and `SS_CANTSENDMORE` are set **and**
  `SOF_NPX_SETOPTSHUT` is absent. This supports the mechanism, but the exact kernel builds in
  #297/#1219 were not matched to this source revision. [Upstream #1219](https://github.com/algesten/ureq/issues/1219)
  reports 300/300 setter failures followed by complete reads in its bare-socket experiment;
  these are the reporter's measurements, not a macOS rerun here.
- **Linux:** [v7.0 `net/core/sock.c`](https://github.com/torvalds/linux/blob/v7.0/net/core/sock.c#L1300)
  routes both timeout options to `sock_set_timeout`, which checks the timeval rather than TCP
  closed state. During this review, each setter with a zero timeval succeeded in 20/20 raw-socket
  RST trials on Linux 7.0.0-1025-nvidia, aarch64; `TCP_INFO` reported `TCP_CLOSE` in every trial.
  This does not prove that every Linux environment or other setter error is harmless.

## 2. Reproduction

**Evidence provenance:** the tables in §2a/§2b are the original investigation's reported
measurements. No logs, scratch lockfile or exact compiler/build identity were attached to
that commit, so their exact counts and original x86_64 environment are **not independently
verified** by this review. They remain useful context, not measured failure probabilities or
proof of deterministic scheduling/unwind safety. The source snippets below are inspectable.

Standalone crate, outside the tree (scratch, not committed). It pins `ureq = "=2.12.1"` with
`default-features = false`; the plain-HTTP path is the same as with our `tls` feature. The server
reads the request head, supplies headers and body together to `write_all` (which may perform
multiple writes), optionally sleeps, then sets
`SO_LINGER 0` and closes (RST). In `unread` mode the client instead POSTs 4 KiB that the server
never reads; a close with unread request data can produce a reset, as reported in #297/#302.
The plain-HTTP harness does not experimentally verify TLS behavior.

**Harness caveat:** `nopool` builds a new default-capacity agent inside each iteration, discarding
the outer agent configured with `max_idle_connections(0)`. It tests absence of cross-request
reuse, not a zero-capacity pool. The source analysis in §1 establishes the latter's exposure.

### 2a. Reported native Linux run (kernel 7.0, x86_64): no panic observed

Fresh agent per request (`nopool`), 3000 rounds each:

| body | GET + RST | POST, unread body, close |
|------|-----------|--------------------------|
| `Content-Length: 0` | 3000 ok, 0 panic | 3000 ok, 0 panic |
| 5-byte buffered body | 3000 ok, 0 panic | 3000 ok, 0 panic |
| chunked | 3000 ok, 0 panic | 3000 ok, 0 panic |
| 64 KiB streamed | 2999 ok, 1 `ECONNRESET`, 0 panic | 2999 ok, 1 `ECONNRESET`, 0 panic |

A side observation, not part of #311: with a **pooled** agent, about a third to a half of requests
fail with `Connection reset by peer` (`GET` + RST: 983/3000 errors for zero-length bodies,
1320/3000 for small bodies). These counts do not show whether a failed connection was reused:
`unit.rs:361-362` also propagates errors from the pre-reuse `server_closed()` probe, and
`stream.rs:223-238` propagates a reset from `peek`. The facade's
`http_client/tests_behaviour.rs:486/500/526` tests (`contract_pooled_stale_*`) exercise stale
connection retry rules, not this reset race. This server resets every connection.

### 2b. Reported Linux fault injection: 20/20 in widened runs

`shim.c` is an `LD_PRELOAD` wrapper for `setsockopt`. For `SOL_SOCKET` with `SO_RCVTIMEO` or
`SO_SNDTIMEO`, it returns `EINVAL` when `TCP_INFO` reports `tcpi_state == TCP_CLOSE`, which is the
state observed after an RST. That approximates the closed-socket failure, not the full XNU
state/flag semantics. With `SHIM_SLEEP_MS` set, it also sleeps after every
*successful* timeout set, which widens the window between line 364 and the reset. In the widened
runs below, the server sleeps 20 ms before the RST and the shim sleeps 100 ms. Sleeps widen a
race; they do not force ordering and are not by themselves a deterministic regression test.

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
. ~/.cargo/env
CARGO_TARGET_DIR=/home/brewerm/git/rr-bl-311/target CARGO_BUILD_JOBS=2 \
  flock /tmp/muse-cargo.lock cargo build --release --offline
# repro311 below denotes /home/brewerm/git/rr-bl-311/target/release/repro311
repro311 small 3000 nopool             # native: 0 panics
LD_PRELOAD=$PWD/shim.so SHIM_SLEEP_MS=100 repro311 small 20 nopool delay=20             # 20/20 panic @403
LD_PRELOAD=$PWD/shim.so SHIM_SLEEP_MS=100 repro311 zero  20 nopool delay=20 connclose   # 20/20 panic @389
```

<details><summary><code>shim.c</code></summary>

```c
// LD_PRELOAD fault injection approximating the observed macOS failure: setsockopt(SOL_SOCKET,
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
            s.write_all(&resp).unwrap(); // headers + body together; may use multiple writes
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

### 2c. Review rerun (2026-11-15, Linux aarch64)

The supplied Rust/C harness was rebuilt outside the repository with Rust **1.100.0
(0ef1bc386)**, Cargo 1.100.0, the **dev** profile and `CARGO_TARGET_DIR` set to this worktree's
`target`. The initial offline build without a lockfile failed dependency resolution; copying
the workspace's `2019fd7` lockfile into the scratch crate before the offline build succeeded.
The resulting scratch lockfile SHA-256 was
`bc07609955c793b5b8932b0f2be4b81af8c6c8d295c70acd778309f02cb05edb`.
These are new observations, not verification of the original x86_64 counts:

| Review trial | Observed result |
|--------------|-----------------|
| Native `zero`, `small`, `chunked`, `big`, each with `nopool`, with/without `unread` | 100/100 successful requests in each of eight cases; no errors or panics |
| Native `small 100 nopool deadline` | 100/100 successful; no errors or panics |
| Injected `zero` and `small`, each with `SHIM_SLEEP_MS=100`, `delay=20`, 20 rounds per configuration | 20/20 panics per configuration, with the respective 389/403 expect messages. Configurations: `nopool`; `nopool connclose`; shared agent; `nopool reader`; `nopool unread`. |
| Injected `zero` / `small` with `nopool deadline`, same delays | 20/20 status-line `Invalid argument` errors each; no panics |
| Injected `chunked` / `big` with `nopool`, same delays | 20/20 `Invalid argument` body-read errors each; no panics |

The `nopool` caveat above still applies. These trials confirm the mechanism and the tested
caller-side non-solutions on this build; they do not establish a deterministic timing test,
real-world failure rate, TLS behavior or native macOS results.

**No production code or test is committed in this investigation.** A native socket race is
unsuitable as the sole regression gate: upstream reports 10/2000 ureq-2 RST panics in each of
two runs, not a universal rate. A future approved fix needs automated coverage in the same
PR, with a controlled timeout-setter failure (a test seam or synchronized injection) and
appropriate platform integration checks (§5). `LD_PRELOAD` is one possible technique, not
the only way to test the policy; #1220 itself contains deterministic injected-error tests.

## 3. Reachability in our code

`Cargo.lock` contains one ureq version, **2.12.1**, used by `ratarmount`, `ratarmount-index` and
`ratarmount-remote`. Workspace searches for `ureq`, `http_client`, `http_pool` and `HttpRangeSource`
confirmed the production entry points below, including calls through stored request/agent
values. Requests that reach HTTP response parsing enter the same `do_from_stream` path.

`reqwest` 0.13.5 is also in the lockfile, used by `librqbit`, `librqbit-tracker-comms` and
`librqbit-upnp` under the optional BitTorrent stack. It does not run the ureq code in question.
`hyper` is a dependency of `reqwest` as well as `axum`/`tonic` and other transport crates;
calling it exclusively a server dependency would be incorrect. This is an inventory of ureq
exposure, not an audit of every HTTP implementation. Torrent **metadata URL fetching** still
uses our ureq facade (§3 table), distinct from librqbit's reqwest traffic.

A macOS caller **can** panic if its actual reply takes one of §1's two branches and a timeout
reset fails in the relevant window. Early upload rejections (including cloud-storage 4xx or
redirects) and resets by proxies are plausible triggers, not production incidents measured
here. `Connection: close` alone does not establish either an RST or a failing setter.

### Via the facade (`ratarmount_index::http_client`, S1a/S1b/S2)

The facade builds agents/requests at `ratarmount-index/src/http_client.rs:425-460` and executes
`call` / `send_bytes` / `send_string` / `send_reader` at **111-137**. Its production caller is
`ratarmount-remote/src/http_pool.rs:81/116`, using `Profile::Pooled`; facade Direct/Probe
profiles are defined but not yet used by production callers. `http_pool` owns the redirect
loop and X-Linked-Etag capture. The following production request-construction sites feed it
(paths relative to `ratarmount-remote/src/`; range reads also use `HttpRangeSource` methods):

| Caller | Verified sites and role |
|--------|-------------------------|
| `lib.rs` | HEAD 774; range-size GET 861; range GET/hash 920/952; capped/full GET 1001/1063/1195; range download 1099; `HttpRangeFile::read` 1437-1495 |
| `webdav.rs` | PROPFIND 139/212/459 (including the #297 route); GET 497 |
| `folder.rs` | HEAD 759 and GET 774 |
| `oci.rs` | GET 415/787/848/1181 (auth, manifests, blobs/ranges) |
| `ipfs.rs` | POST 591 / fallback GET 599; HEAD 770 / fallback GET 777 |
| `dropbox.rs` | POST 448/593/665/802 (listing/metadata/content) |
| `hf.rs` | write-request helper 563; GET 660; range probe 804; range source constructed at 748 |
| `hf_commit.rs` | `write_request` at 197/257/286/382 delegates to `hf.rs`; action request helper 417 covers upload/completion/verification |
| `torrent/metadata.rs` | `HttpRangeSource::request_with_timeout("GET", ...)` at 135; not reqwest |

### Direct `ureq::` (S3 carry and others)

All of these are production code unless marked otherwise.

- `ratarmount-remote/src/s3.rs`: GET at 306 and PUT at 326 are credential/metadata helpers
  (including IMDS token acquisition), not object GET/PUT. Object GETs are 612/668; list GETs
  are 2028/2075 (`s3_list_objects_v2_page`); HEADs are 709/762; `request(verb)` at 961 is
  `S3CallCtx::execute`, used for object/multipart/index-sibling operations.
- `ratarmount-remote/src/gcs.rs`: metadata-token GET 374; token-exchange POST 425; object GET
  828; HEAD 857; PUT 964; listing GETs 1508 (`gcs_list_page`) and 1535 (`gcs_list_page_xml`).
- `ratarmount-remote/src/azure.rs`: metadata-token GET 435; object GET 760; PUT 1064;
  HEAD 1113; listing GET 1708 (`azure_list_page`).
- `ratarmount-index/src/location.rs:1584`: GET in `fetch_index_http_uncached`, the remote sidecar
  fetch. `location.rs:2834` is a HEAD inside the test `link_describedby_archive_head`, so it is not
  production.
- `ratarmount/src/overlay_cmd.rs:834`: an `AgentBuilder` in `remote_base_token`, with **HEAD
  at 838 and `call()` at 845**, a 3-second timeout and redirects disabled. Its production
  caller is `overlay_create.rs:41`; its `s3://` branch uses `head_s3_object` instead.
  `.ok()?` converts errors, not panics.
- **Additional test-only direct caller omitted from the original list:**
  `ratarmount-index/src/http_client.rs:543`, GET in
  `ureq_2_engine_only_error_display_cross_check` (`#[cfg(test)]`). Other direct ureq references
  there construct errors or check types; they do not issue requests.
- No additional production ureq entry point was found in the workspace search.
  [PR #322](https://github.com/hilather/ratarmount-rs/pull/322) explicitly lists `s3`, `gcs` and
  `azure` as S3 carry. [PR #318](https://github.com/hilather/ratarmount-rs/pull/318) discusses
  Direct/Probe profiles, including “like the overlay probe”, but does not provide a complete
  S3 file list. Neither names `location.rs:1584` or `overlay_cmd.rs:834` explicitly. Keystone
  should account for both production callers and separately classify the two test-only sites.

### Response shapes that reach each line

| Line | Responses |
|------|-----------|
| 389, if the initial setter succeeds | HEAD probes through `http_pool`, `s3`, `gcs`, `azure`, **`overlay_cmd`**; 204/304; other zero-length replies when framing selects `LengthDelimited(0)`. `location.rs:2834` is a test-only HEAD; production 1584 is GET. |
| 403, if the initial setter succeeds | Positive length-delimited bodies entirely buffered after headers: possibly small range/pointer/sidecar/JSON bodies, PROPFIND 207s or 4xx/5xx bodies. None qualifies solely by status or small size. |
| No panic at these two expects | Streamed length-delimited or chunked replies propagate a pool-reset error on their completion read (§1), if reached. Close-delimited replies do not use that pool-return path. Any request may first receive a redirect/error response with a different shape. |

### Blast radius

The checked repository configuration uses ordinary unwinding on its desktop targets: no
`panic = "abort"` profile, no repository `.cargo/config` or `.cargo/config.toml`, and no
`-C panic=abort` or panic-profile environment override in `packaging/` or `.github/workflows/`.
CI sets `RUSTFLAGS=-Dwarnings`; other jobs clear it, and the inventory-driver builder sets a
link search path. Thus “the only RUSTFLAGS is -Dwarnings” was too broad. Cargo defaults dev
and release to unwind ([Cargo profiles](https://doc.rust-lang.org/cargo/reference/profiles.html#panic)).
User environment/config overrides and separately distributed binaries were not audited.
The following consequences assume unwinding, not abort, and no further panic in cleanup.

| Execution context | Verified behavior and limits |
|-------------------|------------------------------|
| `http-range` prefetch worker | `http_pool.rs:1065-1075` spawns the synchronous `source.fetch`. On consumption, `worker.join()` maps its panic to `io::Error::other("HTTP range worker panicked")` at 1117-1119. `HttpRangeFile::read` clears the failed prefetch state and returns the error (`lib.rs:1471-1479`); FUSE can reply with EIO rather than lose its event loop. A canceled/detached worker may never be joined, so not every worker panic is delivered to a reader. The default panic hook still runs. |
| FUSE event loop (`fuser-0`) | Ratarmount fixes `config.n_threads = Some(1)` (`ratarmount-fuse/src/lib.rs:3929`). fuser 0.18.0 spawns that thread, dispatches callbacks without `catch_unwind`, and converts a failed join to `io::Error::other("event loop thread panicked")` (`session.rs:293-315`, `:523-540`, `request.rs:238`). A synchronous request panic therefore ends this sole loop and fails the session. |
| Main thread | A panic escaping a CLI operation on main normally ends the process with Rust's panic status 101. Mount preparation/index building, publishing and offline/overlay commands can call the above request sites. This is conditional on the panic reaching main; it must not be applied to all live commits or background reads. Commit recovery after a panic was not audited. |
| Live interval commits | These run on **`ratarmount-overlay-commit`**, not main (`ratarmount/src/overlay_commit.rs:303-346`). The loop invokes remote commit/reopen synchronously through `enqueue_commit` (`ratarmount-compositing/src/write_overlay.rs:4104-4147`) without a panic catch. An unwind stops that worker; whether partial state or poisoned locks subsequently affect serving/recovery remains unverified. |
| Export servers / other background work | The NFS, 9P, SMB, SFTP and HTTP request-task boundaries, other commit entry points, and codec/background-reader behavior have not been exhaustively audited. Their blast radius cannot be inferred solely from “uses tokio” or “uses a thread”; it depends on actual catch/join/supervision and cleanup paths. |
| Python bindings | Lockfile: pyo3 **0.29.2**. Its generated-call trampoline catches Rust unwinds and raises `PanicException` (`src/impl_/trampoline.rs:289-320`). That exception derives from `BaseException`, so ordinary `except Exception` does not catch it. No ratarmount Python integration repro was run; aborts or panics on other threads are not covered by that trampoline. [PyO3 source](https://github.com/PyO3/pyo3/blob/v0.29.2/src/impl_/trampoline.rs#L289), [exception definition](https://github.com/PyO3/pyo3/blob/v0.29.2/src/panic.rs). |

The synchronous FUSE read path was traced in repository code, not inferred from fuser alone:
`Filesystem::read` → `read_handle` → `readahead_fill` → `fill_read_for_fuse` → the source reader
(`ratarmount-fuse/src/lib.rs:3409`, `:1567-1594`, `:278-361`, `:113-120`). `open_source_backend`
also calls `self.source.open` directly at 1457. A concrete source is the remote folder mount:
its `open` delegates to the backend's `open_range` (`ratarmount-remote/src/folder.rs:244-269`),
and the WebDAV backend returns `HttpRangeFile` at 477/479. For that reader, network
I/O can run on this same thread via the direct fallback (`ratarmount-remote/src/lib.rs:1488`),
the synchronous forward window (`http_pool.rs:915`), or a prefetch cache-gap fill (`:1105-1111`).
`read_into_with_pattern` calls `fetch`/`range_reader` at 654/659, ultimately reaching the facade.
Prefetch does not isolate all remote reads. This traces the synchronous reader case; it does
not assert that every format/codec performs network I/O on the event loop.
The direct cloud range readers likewise issue synchronous requests from `Read::read`:
`S3RangeFile` calls `s3_get_object` at `s3.rs:1748`, `GcsRangeFile` calls `gcs_get_object` at
`gcs.rs:1370`, and `AzureRangeFile` calls `azure_get_blob` at `azure.rs:1506`. They do not
automatically gain the `http-range` worker's panic-to-error conversion.

On that FUSE failure, `fuse_session_result` passes the join error through (`lib.rs:3995-4004`),
and `mount_blocking_with_activity` returns it after notifier/journal cleanup (`:4148-4154`).
The FUSE-only CLI handles it with exit **1**, not 101 (`ratarmount/src/main.rs:4224-4226`,
`:4259-4268`). fuser's `UmountOnDrop` **attempts** unmount and logs a failure
(`session.rs:107-120`); successful macOS unmount and exact client errnos (`ENXIO`/`EIO` were
suggested previously) are **not verified**. A worker-contained panic and a synchronous
event-loop panic therefore have different effects on a mount.

**Locks:** the failing reset precedes `PoolReturner::return_to_pool` and `state.pool.add`
(`stream.rs:254-267`, `pool.rs:252-255`), so this error is not raised while the ureq pool
mutex is held. This is not a general unwind-safety proof. `http_pool` recovers poison on its
mutexes, and it holds `target` across initial resolution (`http_pool.rs:537-540`);
the FUSE source-read mutex is also held across I/O (`ratarmount-fuse/src/lib.rs:1568`).
Other caller/codec state and cleanup need review before approving a panic guard.

Practical exposure is macOS operations that reach the ureq callers above, including remote
reads and publishing. This does not include every remote protocol (for example SSH/FTP do
not become ureq callers just by being remote). Incidence in production is unknown; Linux
experiments establish only the narrower observation in §2.

## 4. Upstream status

Rechecked with `gh api` against GitHub and the [crates.io API](https://crates.io/api/v1/crates/ureq)
on 2026-11-15. These are public repository/release observations as of that date, not promises
about future releases or independent reproduction of the reporter's measurements:

- **[algesten/ureq#1219](https://github.com/algesten/ureq/issues/1219)** (opened 2026-10-21, closed 2026-10-22): "macOS: `set_read_timeout`
  fails with EINVAL after the server has closed, so a fully received response is lost (3.x: error;
  2.x: panic on pool return)". It identifies zero-length and buffered branches, explicitly
  quotes the zero-length `expect`, and reports 10/2000 pool-return panics in each of two RST
  runs on macOS with 2.12.1. It does not independently demonstrate both line-specific panics.
  The reporter mentions carrying a local patch for 2.x; that is not evidence of a patch in
  this ratarmount revision.
- **ureq 3:** this timeout-error policy is fixed by [PR **#1220**](https://github.com/algesten/ureq/pull/1220)
  (merged 2026-10-22), released in [**3.5.1**](https://crates.io/crates/ureq/3.5.1) (crates.io
  2026-11-02). Changelog: "Preserve readable responses after macOS rejects timeout changes on closed
  sockets #1220". At [3.5.1 `src/unversioned/transport/tcp.rs:284-288`](https://github.com/algesten/ureq/blob/3.5.1/src/unversioned/transport/tcp.rs#L284):
  ```rust
  // macOS can reject timeout changes after the peer closes with unread
  // request data. The response may still be readable: let I/O report the
  // outcome instead. Leave the cache unchanged since the setter failed.
  Err(e) if cfg!(target_os = "macos") && e.kind() == io::ErrorKind::InvalidInput => {}
  ```
  - The tolerance is **macOS only**. If another OS produces the same setter error, this code
    still propagates it; this does not establish that FreeBSD actually produces that error.
    It tolerates any setter `InvalidInput` on macOS without proving a peer reset, preserves the
    cached timeout on failure, and lets subsequent I/O determine success or failure. It cannot
    guarantee every response survives an RST.
  - [**3.5.0**](https://github.com/algesten/ureq/blob/3.5.0/src/unversioned/transport/tcp.rs#L261)
    and [**3.4.3**](https://github.com/algesten/ureq/blob/3.4.3/src/unversioned/transport/tcp.rs#L228)
    propagate timeout-update errors with `?`. If a setter update is attempted and fails before
    the response is read, they return an error rather than this ureq-2 panic. The maintainer's
    recommendation in #1219 to use 3.4.3 does not explain its rationale; interpreting it as
    referring to other bugs is **unverified**. The checked 3.4.3 source lacks #1220's tolerance.
  - The [default connector chain](https://github.com/algesten/ureq/blob/3.5.1/src/unversioned/transport/mod.rs#L407)
    places rustls/native-tls over the TCP transport. Ordinary direct TLS connections should
    share this policy (source inference); no TLS reproduction or custom/proxy-transport audit
    was performed.
  - #1220 includes injected-error tests for successful/failed cache updates, macOS-only
    `InvalidInput` tolerance and an interrupted-read retry with a rejected timeout update.
    These avoid relying solely on an RST timing race.
  - Latest published version at review: [3.5.2](https://crates.io/crates/ureq/3.5.2),
    2026-11-12, not yanked; `rust-version = "1.85"` is below workspace MSRV 1.90.
    Its `tcp.rs` still has the policy. This verifies metadata/source, not a successful
    ratarmount migration build or the MSRV of all newly resolved dependencies.
- **ureq 2:** the published version and inspected maintenance branch **still contain the bug**.
  - crates.io: newest 2.x is 2.12.1 (2024-12-04), not yanked.
  - The `2.12.x-msrv1.71` branch head is [59989e10](https://github.com/algesten/ureq/commit/59989e10ba060ff4235bda2f068ac636d2b9630a)
    (2026-07-22, #1186). Its [response.rs](https://github.com/algesten/ureq/blob/59989e10ba060ff4235bda2f068ac636d2b9630a/src/response.rs#L389) still has both
    `expect`s with their TODO comments (`src/response.rs:389`, `:403`).
  - This confirms a July backport, not an ongoing maintenance commitment. No commitment to
    a 2.12.2 release was found in #1219/#1220 or the inspected branch/release metadata;
    future 2.x support and release timing remain **unverified**.

## 5. Options for callers (for Keystone)

**Decision boundary:** [#311](https://github.com/hilather/ratarmount-rs/issues/311) explicitly asks
for investigation only and requires architecture review before any fix plan. Nothing in this
section is approved or implemented by this document. Existing migration PRs establish context,
not authorization for the new panic guard, patch, version policy or tests proposed here.

| Option | What it does | Covers | Trade-offs |
|--------|--------------|--------|------------|
| **A. Caller-side avoidance** (`Connection: close`, fresh/zero-capacity agents, different body-reading API, deadline) | Changes pooling or timing, without removing `reset()` | No reliable protection against the two expects | The reset precedes pool eligibility and response delivery (§1). A deadline adds earlier error opportunities; it does not ensure safe completion. Changing caller body handling is too late. No supported plain-TCP transport replacement was found in ureq 2's `AgentBuilder`; a library patch is a separate option. |
| **B. Facade panic guard** | Proposed `catch_unwind(AssertUnwindSafe(..))` around `call` / all `send_*`, mapping to owned `TransportError` kind `Io` | These construction-time panics for callers that actually use the facade, under unwind builds | Direct callers in §3 remain exposed until migrated or separately wrapped. Deferred body I/O errors remain. The guard catches unrelated dependency or upload-reader panics too, so it must not diagnose every payload as a connection reset. The response is lost; retries require a separate replay/idempotency policy. Pool-lock analysis supports this specific failure, but the reported shared-agent run is not a general unwind-safety proof. Audit caller-owned readers/state, test repeated use, and account for panic-hook output; it cannot help abort builds. |
| **C. Complete the ureq 3 migration** (S3 callers → S4a redirects → S4b engine) | Removes these ureq-2 expects; 3.5.1+ tolerates the specified macOS timeout error | All inventoried callers once migrated; the two direct test sites also need disposition | Consistent with #318/#322 and facade S4a/S4b comments. Keep a minimum of 3.5.1 **within major version 3**; 3.4.3/3.5.0 lack the tolerance. Review engine-specific expectations in `http_client/tests_behaviour.rs` at the flip. The policy allows readable data to be consumed; it cannot suppress genuine read/reset errors. Full migration/feature/MSRV validation is future work. |
| **D. Patch/backport ureq 2** | Either replace the two expects with error handling, or discard a connection whose timeout reset fails while preserving the received response | All users resolving to the patched dependency | These are different patches: replacing just the expects does not fix the initial setter's `ErrorReader` or streamed/chunked completion errors. Handling failed reset centrally could also preserve those completion reads; the earlier setter path would still need separate consideration. Scope, error policy and tests require design review. A fork adds maintenance (`vendor/librqbit` is a repository precedent); upstream acceptance and a 2.12.2 release are not guaranteed. |

**Recommendation to Keystone, not an implementation plan**

1. Prefer evaluating C in the existing migration review. Propose a bounded 3.x requirement
   such as `version = "3.5.2"` (Cargo caret, `>=3.5.2, <4.0.0`), or
   `">=3.5.1, <4.0.0"`; an unbounded `">=3.5.1"` would also admit future major versions.
   Explicitly include production `location.rs:1584` and `overlay_cmd.rs:834/838`, plus cloud
   credential/token helpers, in caller coverage. Track `location.rs:2834` and
   `http_client.rs:543` separately as test-only direct callers.
2. An approved fix should include regression tests in the same PR. For C, cover a rejected
   timeout update while a zero-length response or positive buffered body remains readable,
   successful/failed timeout-cache updates, and legitimate I/O errors. #1220's injected tests
   provide a policy model. A new ratarmount test must exercise the intended engine behavior;
   a mock that bypasses the setter does not by itself prove the dependency regression fixed.
   Keep the WebDAV real-opener case and add bounded macOS integration coverage as appropriate.
   An unsynchronized close-after-POST loop is supplementary evidence, not a deterministic gate:
   #1219 reports 5/5000 through 58/2000 setter errors on 3.5.0; its 300/300 number is a different,
   bare-socket experiment after a 20 ms sleep. A deadline or more iterations does not force
   the desired ordering, and RST can cause a real read error even with #1220's policy.
3. If migration timing makes an interim change useful, ask Keystone to compare B and D with
   explicit caller coverage, unwind/error semantics and deterministic tests. No delivery
   deadline or urgency is established by the observed race counts. B could preserve the FUSE
   loop for guarded requests but would leave direct callers and ordinary body errors to
   their existing handling. Do not claim all remote mounts are protected by a facade guard.
4. A is not a dependable fix based on the checked control flow. An upstream 2.x proposal is
   another review decision, not a zero-cost or guaranteed-release alternative.

Open items Keystone may want checked first:

- The macOS-native behaviour of the facade's own WebDAV test after S4b.
- Whether any export server runs remote fetches on a plain thread whose death takes down the
  server.
- Windows and FreeBSD setter semantics on a reset socket (unknown).
- Actual macOS mount teardown/client errnos, TLS/proxy reproduction, and live-commit recovery
  after unwinding; none was tested here.
- Historical §2a/§2b counts without retained logs, and future 2.x maintenance/release intent.
