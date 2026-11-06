#!/usr/bin/env python3
"""H2 feasibility probe D1 items (a),(b),(c),(e). Scratch only; not product code. — Muse"""
import os, sys, time, signal, select, subprocess, ctypes, threading, json, errno
PY = sys.executable; ME = os.path.abspath(__file__)
def starttime(pid):
    s = open(f'/proc/{pid}/stat').read(); return int(s[s.rindex(')')+2:].split()[19])
def nspid(pid='self'):
    for l in open(f'/proc/{pid}/status'):
        if l.startswith('NSpid:'): return [int(x) for x in l.split()[1:]]
def wfile(d, n, v):
    t = os.path.join(d, n + '.tmp'); open(t, 'w').write(json.dumps(v)); os.rename(t, os.path.join(d, n))
def rfile(d, n, timeout=10):
    p = os.path.join(d, n); end = time.time() + timeout
    while not os.path.exists(p):
        if time.time() > end: raise TimeoutError(n)
        time.sleep(0.01)
    return json.load(open(p))
role = sys.argv[1] if len(sys.argv) > 1 else 'main'
if role == 'client':
    d = sys.argv[2]
    o = subprocess.Popen([PY, ME, 'owner', d], start_new_session=True)
    wfile(d, 'R', {'owner': o.pid, 'start': starttime(o.pid)})
    while True: time.sleep(60)
if role == 'owner':
    d = sys.argv[2]; uid, gid = os.getuid(), os.getgid()
    wfile(d, 'owner_threads', len(os.listdir('/proc/self/task')))
    os.unshare(os.CLONE_NEWUSER)
    open('/proc/self/setgroups', 'w').write('deny')
    open('/proc/self/uid_map', 'w').write(f'0 {uid} 1')
    open('/proc/self/gid_map', 'w').write(f'0 {gid} 1')
    os.unshare(os.CLONE_NEWPID)
    p = subprocess.Popen([PY, ME, 'init', d])        # Command::spawn analogue
    wfile(d, 'owner_view', {'child_id': p.pid, 'owner_nspid': nspid()})
    p.wait(); sys.exit(0)
if role == 'init':
    d = sys.argv[2]
    libc = ctypes.CDLL(None, use_errno=True); libc.prctl(1, signal.SIGKILL, 0, 0, 0)  # PR_SET_PDEATHSIG
    subprocess.Popen([PY, ME, 'workload', d, 'workload', '1'])
    wfile(d, 'init_view', {'init_nspid': nspid(), 'getppid': os.getppid()})
    while True:
        try: os.wait()
        except ChildProcessError: time.sleep(1)
if role == 'workload':
    d, name, spawn = sys.argv[2], sys.argv[3], sys.argv[4] == '1'
    if spawn: subprocess.Popen([PY, ME, 'workload', d, 'grandchild', '0'])
    wfile(d, name, nspid())
    while True: time.sleep(60)
# ---- main harness
def alive(fd): return not select.select([fd], [], [], 0)[0]
def tree(d):
    iv = rfile(d, 'init_view'); ov = rfile(d, 'owner_view'); R = rfile(d, 'R')
    wl, gc = rfile(d, 'workload'), rfile(d, 'grandchild'); iv['workload_nspid'] = wl; iv['grandchild_nspid'] = gc
    host = {'owner': R['owner'], 'init': iv['init_nspid'][0], 'workload': wl[0], 'grandchild': gc[0]}
    return iv, ov, R, host, {k: os.pidfd_open(v) for k, v in host.items()}
def run(mode, base):
    d = os.path.join(base, mode); os.makedirs(d, exist_ok=True)
    c = subprocess.Popen([PY, ME, 'client', d])
    try:
        iv, ov, R, host, fds = tree(d)
    except Exception:
        c.kill(); c.wait()  # owner failed (e.g. userns denied): don't leave the client holding stdout
        raise
    res = {'mode': mode, 'host': host, 'owner_threads': rfile(d, 'owner_threads'), 'init_view': iv, 'owner_view': ov}
    res['a_child_id_eq_init_hostpid'] = ov['child_id'] == iv['init_nspid'][0]
    res['a_init_nspid_ends_1'] = iv['init_nspid'][-1] == 1
    res['a_workload_in_ns'] = len(iv['workload_nspid']) == 2 and len(iv['grandchild_nspid']) == 2
    if mode == 'b':
        c.kill(); c.wait(); time.sleep(0.5)
        res['b_after_client_kill_alive'] = {k: alive(f) for k, f in fds.items()}
        # reclaim through R: verify start time via pidfd, then signal owner
        ofd = os.pidfd_open(R['owner']); ok = starttime(R['owner']) == R['start']
        res['b_R_identity_ok'] = ok
        if ok: signal.pidfd_send_signal(ofd, signal.SIGKILL)
    else:
        t0 = time.monotonic(); signal.pidfd_send_signal(fds['owner'], signal.SIGKILL)
    t0 = time.monotonic(); out = {}
    for k in ['init', 'workload', 'grandchild']:
        if k not in fds: continue
        r = select.select([fds[k]], [], [], 5)[0]
        out[k] = {'readable': bool(r), 'ms': round((time.monotonic()-t0)*1000, 2)}
    res[mode + '_reclaim_pidfd_readable'] = out
    if mode == 'c': c.kill(); c.wait()
    return res
def probe_e():
    code = ('import os,threading,time,errno\nthreading.Thread(target=time.sleep,args=(5,),daemon=True).start()\n'
            'try:\n os.unshare(os.CLONE_NEWUSER); print("NO_ERROR")\nexcept OSError as e: print(errno.errorcode[e.errno])')
    one = subprocess.run([PY, '-c', 'import os\nos.unshare(os.CLONE_NEWUSER); print("OK_single_thread")'], capture_output=True, text=True)
    two = subprocess.run([PY, '-c', code], capture_output=True, text=True)
    return {'single_thread': one.stdout.strip() or one.stderr.strip(), 'two_threads': two.stdout.strip() or two.stderr.strip()}
if __name__ == '__main__' and role == 'main':
    base = sys.argv[2] if len(sys.argv) > 2 else '/var/tmp/muse-h2-probe/run'
    out = {'kernel': os.uname().release}
    try:
        out['b'] = run('b', base); out['c'] = run('c', base)
    except Exception as ex:
        out['error'] = f'{type(ex).__name__}: {ex} (owner stderr above names the failing syscall)'
    out['e'] = probe_e()
    print(json.dumps(out, indent=1))
    sys.exit(2 if 'error' in out else 0)
