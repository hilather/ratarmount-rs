#!/usr/bin/env python3
"""poll.py DIR WRITERS CYCLES -> one JSON line.
Writers: write .tmp-<id>-<n>, os.rename onto DIR/final (rename-over).
Poller: loop open+read DIR/final until writers finish; count ENOENT on open
and on read (held fd), and other errors."""
import os, sys, json, threading, errno, time
d, W, C = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
final = os.path.join(d, "final")
with open(final, "w") as f: f.write("seed\n")
done = threading.Event(); werr = []
def writer(i):
    try:
        for n in range(C):
            t = os.path.join(d, f".tmp-{i}-{n}")
            with open(t, "w") as f: f.write(f"w{i} n{n}\n" * 8)
            os.rename(t, final)
    except OSError as e: werr.append(repr(e))
st = dict(opens=0, open_enoent=0, reads=0, read_enoent=0, other=0)
def poller():
    while not done.is_set():
        try:
            fd = os.open(final, os.O_RDONLY); st["opens"] += 1
        except OSError as e:
            st["open_enoent" if e.errno == errno.ENOENT else "other"] += 1; continue
        try:
            os.read(fd, 4096); st["reads"] += 1
        except OSError as e:
            st["read_enoent" if e.errno == errno.ENOENT else "other"] += 1
        finally: os.close(fd)
p = threading.Thread(target=poller); p.start(); t0 = time.time()
ws = [threading.Thread(target=writer, args=(i,)) for i in range(W)]
[w.start() for w in ws]; [w.join() for w in ws]; done.set(); p.join()
att = st["opens"] + st["open_enoent"] + st["other"]
enoent = st["open_enoent"] + st["read_enoent"]
st.update(attempts=att, enoent=enoent, rate=round(enoent / max(att, 1), 4),
          writer_errors=len(werr), secs=round(time.time() - t0, 2),
          leftovers=sum(1 for x in os.listdir(d) if x.startswith(".tmp-")))
print(json.dumps(st)); sys.stdout.flush()
