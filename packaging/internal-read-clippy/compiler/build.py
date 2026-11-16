#!/usr/bin/env python3
"""Reproducibly build the Clippy-only policy patch on distributed rustc-dev.

Downloads are verified before extraction. Only src/tools/clippy is extracted
from rust source. No compiler source is built and no installed toolchain mutates.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tarfile
import time
import urllib.request

HERE=Path(__file__).resolve().parent
PIN=json.loads((HERE/'toolchain.json').read_text())

def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()

def acquire(spec,path,provided):
    if provided:
        source=Path(provided)
        if sha(source)!=spec['sha256']:raise SystemExit('provided archive digest mismatch')
        if source!=path:shutil.copyfile(source,path)
    elif not path.exists():
        with urllib.request.urlopen(spec['url'],timeout=180) as r,path.open('wb') as out:shutil.copyfileobj(r,out)
    if sha(path)!=spec['sha256']:raise SystemExit(f'archive digest mismatch: {path}')

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--cache',type=Path,default=Path(os.environ.get('CARGO_HOME',Path.home()/'.cargo'))/'internal-read-clippy')
    p.add_argument('--source-archive')
    p.add_argument('--component-archive')
    p.add_argument('--offline',action='store_true')
    args=p.parse_args()
    started=time.monotonic()
    cache=args.cache.resolve();cache.mkdir(parents=True,exist_ok=True)
    compiler=subprocess.check_output(['rustc','+1.98.0','-Vv'],text=True)
    if f"commit-hash: {PIN['revision']}" not in compiler or f"host: {PIN['host']}" not in compiler:
        raise SystemExit('policy compiler pin/host mismatch')
    rust=cache/'rust-source.tar.gz';dev=cache/'rustc-dev.tar.xz'
    acquire(PIN['source'],rust,args.source_archive);acquire(PIN['rustc_dev'],dev,args.component_archive)
    source=cache/'clippy-source';component=cache/'rustc-dev'
    patch_inputs=[Path(__file__),HERE/'toolchain.json',HERE/'patch.py',HERE/'internal_read.rs',HERE/'syntax.rs',HERE.parent/'syntax/src/lib.rs',HERE/'Cargo.lock']
    patch_digest=hashlib.sha256(b''.join(path.read_bytes() for path in patch_inputs)).hexdigest()
    stamp=cache/'build.json'
    previous=json.loads(stamp.read_text()) if stamp.exists() else {}
    binary=cache/'target/debug/clippy-driver'
    if previous.get('patch_digest')!=patch_digest or not binary.exists() or previous.get('driver_digest')!=sha(binary):
        if source.exists():shutil.rmtree(source)
        source.mkdir()
        prefix=f"rust-{PIN['revision']}/src/tools/clippy/"
        with tarfile.open(rust) as tar:
            members=[]
            for m in tar:
                if m.name.startswith(prefix):m.name=m.name[len(prefix):];members.append(m)
            tar.extractall(source,members=members,filter='data')
        subprocess.run(['python3',str(HERE/'patch.py'),str(source)],check=True)
        shutil.copyfile(HERE/'Cargo.lock',source/'Cargo.lock')
        if not component.exists():
            component.mkdir()
            prefix=f"rustc-dev-{PIN['toolchain']}-{PIN['host']}/rustc-dev/"
            with tarfile.open(dev) as tar:
                members=[]
                for m in tar:
                    if m.name.startswith(prefix):m.name=m.name[len(prefix):];members.append(m)
                tar.extractall(component,members=members,filter='data')
        sysroot=Path(subprocess.check_output(['rustc','+1.98.0','--print','sysroot'],text=True).strip())
        env=os.environ.copy()
        env.update(CARGO_BUILD_JOBS='2',CARGO_PROFILE_DEV_DEBUG='0',CARGO_INCREMENTAL='0',RUSTC_BOOTSTRAP='1',CARGO_TARGET_DIR=str(cache/'target'),RUSTFLAGS=f'-L {component}/lib/rustlib/{PIN["host"]}/lib',LIBRARY_PATH=str(sysroot/'lib'))
        command=['flock','/tmp/muse-cargo.lock','cargo','+1.98.0','build','--locked','--manifest-path',str(source/'Cargo.toml'),'--bin','clippy-driver']
        if args.offline:command.append('--offline')
        subprocess.run(command,env=env,check=True)
    if hashlib.sha256(b''.join(path.read_bytes() for path in patch_inputs)).hexdigest()!=patch_digest:
        raise SystemExit('policy tool inputs changed during build; rerun build.py')
    result={'schema':1,'driver':str(binary),'patch_digest':patch_digest,'source_digest':PIN['source']['sha256'],'component_digest':PIN['rustc_dev']['sha256'],'compiler_revision':PIN['revision'],'driver_digest':sha(binary),'elapsed_seconds':round(time.monotonic()-started,3)}
    stamp.write_text(json.dumps(result,indent=2)+'\n')
    print(binary)

if __name__=='__main__':main()
