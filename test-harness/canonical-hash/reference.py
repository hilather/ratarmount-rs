#!/usr/bin/env python3
"""Reference implementation of the overlay canonical hash (SHA-256 only).

`ratarmount diff --hash`, `overlay seal`, `overlay verify` and bundles all use
this definition (docs/sandbox.md, "Canonical hash"). External graders can
compare their own implementation against it; `--self-test` checks the golden
fixture pinned by `golden_canonical_hash_fixture` in
ratarmount-compositing/src/overlay_changes.rs.

Rows are sorted by path bytes. Each row is
    path NUL status NUL type NUL mode NUL content-hash NUL
with mode as six octal digits of st_mode and an empty content hash for
directories and deletions. Symlink targets and binary files (a NUL in the
first 8 KiB) always hash exact bytes.
"""
import hashlib
import re
import sys

# Rust's u8::is_ascii_whitespace: no vertical tab.
WHITESPACE = re.compile(rb'[ \t\n\r\x0c]+$')


def normalize(data, mode):
    if mode == 'exact' or b'\0' in data[:8192]:
        return data
    # strict: drop trailing ASCII whitespace per line (this also turns CRLF
    # into LF) and ignore one final newline. loose: also drop blank lines.
    text = b'\n'.join(WHITESPACE.sub(b'', line) for line in data.split(b'\n'))
    if text.endswith(b'\n'):
        text = text[:-1]
    if mode == 'loose':
        text = b'\n'.join(line for line in text.split(b'\n') if line)
    return text


def content_hash(data, mode='exact', symlink=False):
    return 'sha256:' + hashlib.sha256(data if symlink else normalize(data, mode)).hexdigest()


def canonical_hash(rows):
    """rows: iterable of (path bytes, status, type, st_mode int, hash or '')."""
    digest = hashlib.sha256()
    for path, status, kind, mode, content in sorted(rows, key=lambda r: r[0]):
        for field in (path, status.encode(), kind.encode(), b'%06o' % mode, content.encode()):
            digest.update(field + b'\0')
    return 'sha256:' + digest.hexdigest()


def golden(mode):
    return canonical_hash([
        (b'a', 'modified', 'file', 0o100644, content_hash(b'new\n', mode)),
        (b'added.txt', 'added', 'file', 0o100644, content_hash(b'one  \r\ntwo\t\n\n', mode)),
        (b'dir', 'added', 'dir', 0o040755, ''),
        (b'keep/gone.txt', 'deleted', 'file', 0o100644, ''),
        (b'link', 'added', 'symlink', 0o120777, content_hash(b'a', symlink=True)),
        (b'tool', 'modified', 'file', 0o100755, content_hash(b'#!/bin/sh\n', mode)),
    ])


GOLDEN = {
    'exact': 'sha256:d1ff1abce4ef923a02e7c6f4fee513333b8fc4ccaef983a2c6395d3d7fa67026',
    'strict': 'sha256:1fac458db6df916fa9721ef40833e417af99988f90cfa06fbf477a241d46cc37',
    'loose': 'sha256:73a1c14c339962ca7a2960c48972d7935a9cd82a14bf9c0c2cebb779b02d7aa6',
}

if __name__ == '__main__':
    if sys.argv[1:] != ['--self-test']:
        sys.exit('usage: reference.py --self-test')
    assert content_hash(b'x \r\n', 'strict') == content_hash(b'x', 'exact')
    assert content_hash(b'x\x0b\n', 'strict') == content_hash(b'x\x0b', 'exact')
    assert content_hash(b'\0bin \n', 'strict') == content_hash(b'\0bin \n', 'exact')
    for mode, want in GOLDEN.items():
        got = golden(mode)
        assert got == want, f'{mode}: {got} != {want}'
    print('canonical-hash reference self-test: pass')
