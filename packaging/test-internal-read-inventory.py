#!/usr/bin/env python3
"""Internal-read inventory: a reviewed manifest of production file opens (#151, R11-S7).

Every production pathname read, copy source, `OpenOptions` chain, convenience
read/write, temporary-file or directory create, descriptor clone and raw
ownership conversion in the workspace's Rust sources must have an entry in
`packaging/internal-read-inventory.json` with a disposition:

* `managed-read`   a mandatory internal read (index, index pointer, meta-v3
                   metadata cache, index snapshot, internal hash/copy/upload
                   input, SQLAR/materialization/export probe) that goes through
                   `ratarmount_index::managed_read`; the operation must be a
                   managed one and its function may not hold a raw descriptor;
* `sqlite-snapshot` a managed read of bytes an SQLite snapshot produced;
* `output-owner`   an output created or written by this code; creates record
                   a `mode_policy`;
* `residual`       a known non-mandatory read left for #196, with a named
                   family and a specific reason;
* `out-of-family`  a read outside the internal-read families, with a named
                   category and a specific reason.

Each operation is keyed by (file, enclosing function, operation, ordinal of
that operation inside the function). Line numbers are evidence only. A
fingerprint of the normalized statement detects a changed call. The check
fails on new, changed, unclassified and stale entries, on a raw operation at a
managed entry, on a managed function reaching a helper whose reads are not
managed, on a raw descriptor escape from a managed function, and on an
exclusive create without a mode policy.

This is a reviewed change detector, not a dataflow analysis.

Usage:
  test-internal-read-inventory.py            check the workspace (exit 0/1)
  test-internal-read-inventory.py --list     print every scanned operation
  test-internal-read-inventory.py --write    rewrite the manifest: keep the
                                             classification of matching keys,
                                             refresh fingerprints and lines,
                                             add new operations UNCLASSIFIED
  test-internal-read-inventory.py --self-test

Stdlib only; runs on Python 3.9.
"""
import hashlib
import json
import os
import re
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST = os.path.join(ROOT, "packaging", "internal-read-inventory.json")

DISPOSITIONS = (
    "managed-read",
    "sqlite-snapshot",
    "output-owner",
    "residual",
    "out-of-family",
)

OUT_OF_FAMILY = (
    "configuration-or-credentials",
    "kernel-or-process-introspection",
    "structured-control-record",
    "patch-or-bundle-input",
    "runtime-resource-or-descriptor-handoff",
    "directory-handle-or-durability",
)

RESIDUAL_FAMILIES = (
    "generic-folder-reads",
    "payload-admitted-readers",
    "plain-tar-backend",
    "hf-payload-cache",
    "range-cache",
    "payload-cache",
    "http-spool-cache",
    "factory-and-format-readers",
    "foreign-library-or-caller-owned",
    "commit-journal-recovery",
    "sqlite-auxiliary-files",
    # The residual list is open (#196): reads that are no index, index
    # pointer, meta-v3 metadata cache or internal hash input.
    "local-index-v1-cache-header",
    "remote-listing-and-torrent-caches",
    "archive-and-member-io",
)

BASELINE = "e6ca64e"
UNCHANGED = "unchanged-from-" + BASELINE

# Operations that create a file (or directory) and so need a mode policy.
CREATE_OPS = frozenset({
    "File::create",
    "File::create_new",
    "fs::write",
    "fs::copy",
    "OpenOptions",
    "tempfile",
    "tempdir",
    "managed_read::copy_exclusive_new",
    "managed_read::copy_create_or_truncate",
})
MANAGED_OPS = frozenset({
    "ManagedReadCursor::open",
    "managed_read::read",
    "managed_read::read_to_string",
    "managed_read::read_prefix",
    "managed_read::sha256_hex",
    "managed_read::copy_exclusive_new",
    "managed_read::copy_create_or_truncate",
    "managed_read::copy_into",
})
ESCAPES = ("into_raw_fd", "as_raw_fd", "try_clone", "from_raw_fd", "File::from")


# --------------------------------------------------------------------------
# Lexing: blank comments and literal contents, keep offsets and newlines.
# --------------------------------------------------------------------------


def mask(src):
    """Return `src` with comments and string/char literal contents blanked."""
    out = list(src)
    i, n = 0, len(src)

    def blank(a, b):
        for k in range(a, b):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        c = src[i]
        if src.startswith("//", i):
            j = src.find("\n", i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
        elif src.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if src.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif src.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            blank(i, j)
            i = j
        elif re.match(r'(?:b?r#*")', src[i:i + 70]) and (i == 0 or not (src[i - 1].isalnum() or src[i - 1] == "_")):
            m = re.match(r'b?r(#*)"', src[i:])
            close = '"' + m.group(1)
            j = src.find(close, i + m.end())
            j = n if j < 0 else j + len(close)
            blank(i + m.end(), j - len(close))
            i = j
        elif c == '"' or (c == "b" and src.startswith('b"', i) and (i == 0 or not (src[i - 1].isalnum() or src[i - 1] == "_"))):
            j = i + (2 if c == "b" else 1)
            start = j
            while j < n and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            blank(start, min(j, n))
            i = j + 1
        elif c == "'":
            if i + 1 < n and src[i + 1] == "\\":
                j = src.find("'", i + 2)
                j = n if j < 0 else j
                blank(i + 1, j)
                i = j + 1
            elif i + 2 < n and src[i + 2] == "'":
                blank(i + 1, i + 2)
                i += 3
            else:
                i += 1
        else:
            i += 1
    return "".join(out)


def match_brace(text, open_pos):
    depth = 0
    for k in range(open_pos, len(text)):
        if text[k] == "{":
            depth += 1
        elif text[k] == "}":
            depth -= 1
            if depth == 0:
                return k
    return len(text) - 1


TEST_ATTR = re.compile(r"#\[\s*(?:test|tokio::test|cfg\s*\(([^\]]*)\))\s*\]")


def is_test_cfg(attr_body):
    if attr_body is None:
        return True
    body = re.sub(r"\s+", "", attr_body)
    if "not(test)" in body:
        return False
    return re.search(r"(?<![\w\"])test(?![\w\"-])", body) is not None


def test_spans(text, raw=None):
    """Spans of items under `#[test]` / `#[cfg(test ...)]`, and test-only
    `mod name;` declarations (a `#[path = "..."]` file name when given)."""
    spans, test_mods = [], []
    for m in TEST_ATTR.finditer(text):
        if not is_test_cfg(m.group(1)):
            continue
        # The item after the attribute (skip further attributes).
        k = m.end()
        while True:
            nxt = re.match(r"\s*(#!?\[[^\]]*\]\s*)", text[k:])
            if not nxt:
                break
            k += nxt.end()
        semi = text.find(";", k)
        brace = text.find("{", k)
        decl = re.match(r"\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*;", text[k:])
        if decl:
            path = None
            if raw is not None:
                pm = re.search(r'#\[\s*path\s*=\s*"([^"]+)"\s*\]', raw[m.end():k])
                path = pm.group(1) if pm else None
            test_mods.append(("path", path) if path else decl.group(1))
            spans.append((m.start(), k + decl.end()))
            continue
        if brace < 0 or (0 <= semi < brace):
            end = semi if semi >= 0 else len(text)
            spans.append((m.start(), end))
            continue
        spans.append((m.start(), match_brace(text, brace)))
    return spans, test_mods


FN_RE = re.compile(r"\bfn\s+([A-Za-z_]\w*)")
IMPL_RE = re.compile(r"\bimpl\b(?:\s*<[^{;]*?>)?\s+([^{;]*?)\s*(?:where\b[^{;]*)?\{")
TRAIT_RE = re.compile(r"\btrait\s+([A-Za-z_]\w*)[^{;]*\{")


def fn_spans(text):
    """[(start, end, qualified name)] for every fn with a body."""
    impls = []
    for m in IMPL_RE.finditer(text):
        head = m.group(1)
        head = head.split(" for ")[-1]
        head = re.sub(r"<.*", "", head).strip()
        name = head.split("::")[-1].strip() or "impl"
        brace = m.end() - 1
        impls.append((brace, match_brace(text, brace), name))
    for m in TRAIT_RE.finditer(text):
        brace = m.end() - 1
        impls.append((brace, match_brace(text, brace), m.group(1)))
    fns = []
    for m in FN_RE.finditer(text):
        k = m.end()
        depth = 0
        brace = -1
        while k < len(text):
            ch = text[k]
            if ch in "(<[":
                depth += 1
            elif ch in ")>]":
                depth = max(0, depth - 1)
            elif ch == ";" and depth == 0:
                break
            elif ch == "{" and depth == 0:
                brace = k
                break
            k += 1
        if brace < 0:
            continue
        end = match_brace(text, brace)
        owner = None
        for a, b, name in impls:
            if a < m.start() < b and (owner is None or a > owner[0]):
                owner = (a, name)
        qual = m.group(1) if owner is None else owner[1] + "::" + m.group(1)
        fns.append((m.start(), end, qual))
    return fns


def enclosing(fns, pos):
    best = None
    for a, b, name in fns:
        if a <= pos <= b and (best is None or a > best[0]):
            best = (a, name)
    return best[1] if best else "<module>"


# --------------------------------------------------------------------------
# Operations.
# --------------------------------------------------------------------------


def aliases(text):
    """Local names for `std::fs::File` and `std::fs`, and bare fs functions."""
    file_names, fs_names, bare = {"File"}, {"fs"}, set()
    rustix = {"rustix::fs"}
    for m in re.finditer(r"use\s+rustix::fs\s+as\s+(\w+)\s*;", text):
        rustix.add(m.group(1))
    for m in re.finditer(r"use\s+rustix::fs::\{([^}]*)\}", text):
        am = re.search(r"\bself\s+as\s+(\w+)", m.group(1))
        if am:
            rustix.add(am.group(1))
    for m in re.finditer(r"use\s+(?:std|tokio)::fs::File\s+as\s+(\w+)\s*;", text):
        file_names.add(m.group(1))
    for m in re.finditer(r"use\s+(?:std|tokio)::fs\s+as\s+(\w+)\s*;", text):
        fs_names.add(m.group(1))
    for m in re.finditer(r"use\s+std::fs::\{([^}]*)\}", text):
        for part in m.group(1).split(","):
            part = part.strip()
            am = re.match(r"(\w+)(?:\s+as\s+(\w+))?$", part)
            if not am:
                continue
            name, alias = am.group(1), am.group(2) or am.group(1)
            if name == "File":
                file_names.add(alias)
            elif name == "self":
                fs_names.add(alias)
            elif name in ("read", "read_to_string", "copy", "write"):
                bare.add((alias, name))
    return file_names, fs_names, bare, rustix


def op_patterns(text):
    file_names, fs_names, bare, rustix = aliases(text)
    rx = "|".join(sorted(re.escape(n) for n in rustix))
    files = "|".join(sorted(re.escape(n) for n in file_names))
    fss = "|".join(sorted(re.escape(n) for n in fs_names))
    pats = [
        (r"(?<![\w.])(?:(?:std|tokio)::fs::)?(?:%s)::(open|create|create_new)\s*\(" % files, "File::{0}"),
        (r"(?<![\w.])(?:(?:std|tokio)::)?(?:%s)::(read|read_to_string|copy|write)\s*\(" % fss, "fs::{0}"),
        (r"(?<![\w.])(?:(?:std|tokio)::fs::)?OpenOptions::new\s*\(|(?<![\w.])(?:(?:std|tokio)::)?(?:fs::)?(?:%s)::options\s*\(" % files, "OpenOptions"),
        (r"(?<![\w.])(?<!fn )(?:ratarmount_core::db_inodes::)?(open_admitted|openat_admitted)\s*\(", "{0}"),
        (r"\.reopen\s*\(\s*\)", "tempfile::reopen"),
        (r"\.try_clone\s*\(", "try_clone"),
        (r"\b(from_raw_fd|into_raw_fd|from_raw_handle|into_raw_handle)\s*\(", "{0}"),
        (r"(?<![\w.])(?:libc::)(open|openat|open64)\s*\(", "libc::{0}"),
        (r"(?<![\w.:])(?:%s)::(open|openat)\s*\(" % rx, "rustix::{0}"),
        (r"(?<![\w])NamedTempFile::(?:new|new_in)\s*\(|\.tempfile(?:_in)?\s*\(|(?<![\w.])tempfile::tempfile(?:_in)?\s*\(", "tempfile"),
        (r"(?<![\w.])(?:tempfile::)?(?:tempdir|tempdir_in)\s*\(|\.tempdir(?:_in)?\s*\(|(?<![\w.])TempDir::new(?:_in)?\s*\(", "tempdir"),
        (r"(?<![\w.])ManagedReadCursor::open\s*\(", "ManagedReadCursor::open"),
        (r"(?<![\w.])managed_read::(\w+)\s*\(", "managed_read::{0}"),
    ]
    for alias, name in sorted(bare):
        pats.append((r"(?<![\w.:])%s\s*\(" % re.escape(alias), "fs::" + name))
    return [(re.compile(p), label) for p, label in pats]


def statement(text, pos):
    """The normalized statement around `pos` (up to `;`/`{`, at most 6 lines)."""
    start = text.rfind("\n", 0, pos) + 1
    end = pos
    lines = 0
    while end < len(text) and lines < 6:
        ch = text[end]
        if ch == ";":
            break
        if ch == "\n":
            lines += 1
        end += 1
    return re.sub(r"\s+", "", text[start:end])


def fingerprint(stmt):
    return hashlib.sha256(stmt.encode()).hexdigest()[:16]


def is_test_path(rel):
    parts = rel.split("/")
    if parts[0] in ("target", "vendor", "test-harness", "clients", "benchmarks"):
        return True
    if any(p in ("tests", "benches", "examples") for p in parts):
        return True
    return parts[-1] == "build.rs"


def rust_files(root):
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root)
        rel_dir = "" if rel_dir == "." else rel_dir.replace(os.sep, "/")
        dirnames[:] = sorted(d for d in dirnames if not d.startswith(".") and not is_test_path((rel_dir + "/" + d).lstrip("/")))
        for f in sorted(filenames):
            if f.endswith(".rs"):
                rel = (rel_dir + "/" + f).lstrip("/")
                if not is_test_path(rel):
                    out.append(rel)
    return out


def module_file(rel, name, root):
    d = os.path.dirname(rel)
    base = os.path.basename(rel)
    if base not in ("lib.rs", "main.rs", "mod.rs"):
        d = os.path.join(d, base[:-3])
    for cand in (os.path.join(d, name + ".rs"), os.path.join(d, name, "mod.rs")):
        if os.path.exists(os.path.join(root, cand)):
            return cand.replace(os.sep, "/")
    return None


def scan(root):
    """Every production operation: list of dicts (key fields + evidence)."""
    files = rust_files(root)
    texts, raws, test_files = {}, {}, set()
    for rel in files:
        with open(os.path.join(root, rel), encoding="utf-8", errors="replace") as fh:
            raws[rel] = fh.read()
            texts[rel] = mask(raws[rel])
    # Files that are test-only modules (and everything below them).
    changed = True
    while changed:
        changed = False
        for rel in files:
            _, mods = test_spans(texts[rel], raws[rel])
            nested = []
            if rel in test_files:
                nested = re.findall(r"(?:^|\n)\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*;", texts[rel])
            for name in list(mods) + nested:
                if isinstance(name, tuple):
                    mf = os.path.normpath(os.path.join(os.path.dirname(rel), name[1])).replace(os.sep, "/")
                else:
                    mf = module_file(rel, name, root)
                if mf and mf not in test_files:
                    test_files.add(mf)
                    changed = True
    ops, fn_index = [], {}
    for rel in files:
        if rel in test_files:
            continue
        text = texts[rel]
        spans, _ = test_spans(text)
        fns = [f for f in fn_spans(text) if not any(a <= f[0] <= b for a, b in spans)]
        for a, b, name in fns:
            fn_index.setdefault(crate_of(rel), {}).setdefault(name.split("::")[-1], []).append((rel, name))
        found = []
        for pat, label in op_patterns(text):
            for m in pat.finditer(text):
                if any(a <= m.start() <= b for a, b in spans):
                    continue
                op = label.format(*[g for g in m.groups() if g is not None]) if "{0}" in label else label
                found.append((m.start(), op))
        found.sort()
        seen = {}
        for pos, op in found:
            fn = enclosing(fns, pos)
            k = (fn, op)
            seen[k] = seen.get(k, 0) + 1
            stmt = statement(text, pos)
            ops.append({
                "file": rel,
                "function": fn,
                "op": op,
                "ordinal": seen[k],
                "line": text.count("\n", 0, pos) + 1,
                "fingerprint": fingerprint(stmt),
                "creates": op in CREATE_OPS and (op != "OpenOptions" or re.search(r"\.(create|create_new)\(true\)", stmt) is not None)
                or op == "rustix::openat" and "CREATE" in stmt,
                "exclusive": op in ("File::create_new", "tempfile", "tempdir", "managed_read::copy_exclusive_new")
                or (op == "OpenOptions" and ".create_new(true)" in stmt),
            })
    return ops, texts, fns_by_file(texts, files, test_files)


def crate_of(rel):
    return rel.split("/")[0]


def fns_by_file(texts, files, test_files):
    out = {}
    for rel in files:
        if rel in test_files:
            continue
        spans, _ = test_spans(texts[rel])
        out[rel] = [f for f in fn_spans(texts[rel]) if not any(a <= f[0] <= b for a, b in spans)]
    return out


def key(e):
    return (e["file"], e["function"], e["op"], e["ordinal"])


# --------------------------------------------------------------------------
# Check.
# --------------------------------------------------------------------------


def check(root, manifest):
    """Return a list of error strings (empty: clean)."""
    errors = []
    ops, texts, fns = scan(root)
    entries = manifest.get("entries", [])
    by_key = {}
    for e in entries:
        k = key(e)
        if k in by_key:
            errors.append("duplicate manifest entry %s" % (k,))
        by_key[k] = e
    scanned = {key(o): o for o in ops}
    for k, o in scanned.items():
        e = by_key.get(k)
        where = "%s:%d %s %s#%d" % (o["file"], o["line"], o["function"], o["op"], o["ordinal"])
        if e is None:
            errors.append("new operation (classify it in the manifest): " + where)
            continue
        if e.get("fingerprint") != o["fingerprint"]:
            errors.append("changed operation (review and update its entry): " + where)
        errors.extend(entry_errors(e, o, where))
    for k, e in by_key.items():
        if k not in scanned:
            errors.append("stale manifest entry (operation is gone): %s %s %s#%d" % k)
    errors.extend(helper_errors(entries, scanned, texts, fns))
    return errors


def entry_errors(e, o, where):
    errs = []
    d = e.get("disposition")
    if d not in DISPOSITIONS:
        return ["unclassified operation (disposition %r): %s" % (d, where)]
    managed = o["op"] in MANAGED_OPS
    if d in ("managed-read", "sqlite-snapshot"):
        backend = e.get("managed_backend") and o["file"] == "ratarmount-index/src/managed_read.rs"
        if not managed and not backend:
            errs.append("mandatory read uses a raw reader (%s): %s" % (o["op"], where))
        if not e.get("regression"):
            errs.append("mandatory read without a named regression: " + where)
    elif managed and d != "output-owner":
        errs.append("managed operation classified %s: %s" % (d, where))
    if d == "residual":
        if e.get("family") not in RESIDUAL_FAMILIES:
            errs.append("residual without a named family: " + where)
        if not (e.get("reason") or "").strip() or e.get("issue") != "#196":
            errs.append("residual without a specific reason and issue #196: " + where)
    if d == "out-of-family":
        if e.get("category") not in OUT_OF_FAMILY:
            errs.append("out-of-family without a named category: " + where)
        if not (e.get("reason") or "").strip():
            errs.append("out-of-family without a specific reason: " + where)
        if e.get("mandatory_helper"):
            errs.append("mandatory helper classified out-of-family: " + where)
    if o["creates"] or o["exclusive"]:
        policy = (e.get("mode_policy") or "").strip()
        if not policy:
            errs.append("create without a mode policy: " + where)
        elif policy == UNCHANGED and e.get("baseline_fingerprint") != o["fingerprint"]:
            errs.append("%s is valid only for an unchanged baseline create: %s" % (UNCHANGED, where))
    return errs


# Free-function calls only (`helper(..)`, `crate::module::helper(..)`), not
# methods or associated functions.
CALL_RE = re.compile(r"(?<![\w.:])((?:[a-z_]\w*::)*)([a-z_]\w*)\s*\(")


def stem(rel):
    base = os.path.basename(rel)[:-3]
    return os.path.basename(os.path.dirname(rel)) if base in ("mod", "lib", "main") else base


def resolves(rel, text, prefix, callee, target):
    """Whether a call `prefix callee(` in `rel` may name `callee` in `target`:
    the same file for a bare call (or a file whose module the caller imports
    the name from), the named module for a qualified call."""
    segs = [p for p in prefix.split("::") if p]
    if segs and segs[-1] not in ("self", "super", "crate"):
        return stem(target) == segs[-1]
    if target == rel:
        return True
    mod = stem(target)
    return re.search(r"use\s+[\w:]*\b%s::(?:\{[^}]*\b%s\b[^}]*\}|%s\s*;)" % (re.escape(mod), re.escape(callee), re.escape(callee)), text) is not None


def helper_errors(entries, scanned, texts, fns):
    """A function with a managed entry must not reach a same-crate free helper
    whose reads are not managed, and must not hold a raw descriptor except
    around a classified non-managed operation on the same line."""
    errs = []
    by_key = {key(e): e for e in entries}
    managed_fns = {}
    for e in entries:
        if e.get("disposition") in ("managed-read", "sqlite-snapshot"):
            managed_fns.setdefault(e["file"], set()).add(e["function"])
    raw_by_fn, lines_by_fn = {}, {}
    for o in scanned.values():
        lines_by_fn.setdefault((o["file"], o["function"]), set())
        if o["op"] in MANAGED_OPS:
            continue
        lines_by_fn[(o["file"], o["function"])].add(o["line"])
        if "::" not in o["function"]:
            raw_by_fn.setdefault(crate_of(o["file"]), {}).setdefault(o["function"], []).append(o)
    for rel, names in managed_fns.items():
        text = texts.get(rel)
        if text is None:
            continue
        for a, b, qual in fns.get(rel, []):
            if qual not in names:
                continue
            body = text[a:b]
            for esc in ESCAPES:
                for m in re.finditer(r"(?<![\w])%s\s*\(" % re.escape(esc), body):
                    line = text.count("\n", 0, a + m.start()) + 1
                    if line in lines_by_fn.get((rel, qual), set()):
                        continue
                    errs.append("raw descriptor escape %s in managed function %s (%s:%d)" % (esc, qual, rel, line))
            leaf = qual.split("::")[-1]
            for m in CALL_RE.finditer(body):
                prefix, callee = m.group(1), m.group(2)
                if callee == leaf or text[max(0, a + m.start() - 3):a + m.start()].endswith("fn "):
                    continue
                for o in raw_by_fn.get(crate_of(rel), {}).get(callee, []):
                    if not resolves(rel, text, prefix, callee, o["file"]):
                        continue
                    ent = by_key.get(key(o))
                    if ent is None or ent.get("disposition") in ("managed-read", "sqlite-snapshot", "output-owner"):
                        continue
                    if qual in (ent.get("non_mandatory_callers") or []):
                        continue
                    if ent.get("category") == "directory-handle-or-durability":
                        continue  # a directory handle reads no file content
                    errs.append("managed function %s (%s) reaches helper %s with a non-managed read (%s %s#%d)"
                                % (qual, rel, callee, o["file"], o["op"], o["ordinal"]))
    return sorted(set(errs))


# --------------------------------------------------------------------------
# Main.
# --------------------------------------------------------------------------


def load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def write(root, path):
    try:
        manifest = load(path)
    except FileNotFoundError:
        manifest = {"baseline": BASELINE, "entries": []}
    old = {key(e): e for e in manifest["entries"]}
    ops, _, _ = scan(root)
    out = []
    for o in ops:
        e = dict(old.get(key(o)) or {"disposition": "UNCLASSIFIED"})
        for f in ("file", "function", "op", "ordinal", "line", "fingerprint"):
            e[f] = o[f]
        out.append(order(e))
    manifest["entries"] = out
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=1, sort_keys=False)
        fh.write("\n")
    return len(out)


FIELD_ORDER = ("file", "function", "op", "ordinal", "line", "fingerprint", "baseline_fingerprint",
               "disposition", "family", "category", "issue", "reason", "regression",
               "mandatory_helper", "managed_backend", "non_mandatory_callers", "mode_policy")


def order(e):
    return {k: e[k] for k in sorted(e, key=lambda k: (FIELD_ORDER.index(k) if k in FIELD_ORDER else 99, k))}


def main(argv):
    if argv[1:] == ["--self-test"]:
        return self_test()
    if argv[1:] == ["--list"]:
        ops, _, _ = scan(ROOT)
        for o in ops:
            print("%s:%d\t%s\t%s#%d" % (o["file"], o["line"], o["function"], o["op"], o["ordinal"]))
        return 0
    if argv[1:] == ["--write"]:
        print("wrote %d entries" % write(ROOT, MANIFEST))
        return 0
    if len(argv) > 1:
        print(__doc__, file=sys.stderr)
        return 2
    errors = check(ROOT, load(MANIFEST))
    for e in errors:
        print("inventory: " + e)
    if errors:
        print("inventory: %d problem(s); see packaging/test-internal-read-inventory.py" % len(errors))
        return 1
    print("inventory: clean (%d entries)" % len(load(MANIFEST)["entries"]))
    return 0


# --------------------------------------------------------------------------
# Self-tests (each builds a small fake workspace).
# --------------------------------------------------------------------------


def fake(files):
    d = tempfile.mkdtemp(prefix="inventory-selftest-")
    for rel, body in files.items():
        p = os.path.join(d, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(body)
    return d


def classify(root, rules):
    """A manifest for `root`: rules maps (function, op) -> fields."""
    ops, _, _ = scan(root)
    entries = []
    for o in ops:
        e = {f: o[f] for f in ("file", "function", "op", "ordinal", "line", "fingerprint")}
        e.update(rules.get((o["function"], o["op"]), {"disposition": "UNCLASSIFIED"}))
        entries.append(e)
    return {"baseline": BASELINE, "entries": entries}


OOF = {"disposition": "out-of-family", "category": "configuration-or-credentials", "reason": "reads a config file"}
MANAGED = {"disposition": "managed-read", "regression": "regression_x"}


def expect(cond, what):
    if not cond:
        raise AssertionError(what)


def regression_internal_read_inventory_detects_aliased_convenience_reads():
    """Regression: `File as RawFile` / `fs as disk` / bare imports hid reads."""
    root = fake({"c/src/lib.rs": (
        "use std::fs::File as RawFile;\nuse std::fs as disk;\nuse std::fs::{read_to_string as rts};\n"
        "fn a(p: &Path) { let _ = RawFile::open(p); }\n"
        "fn b(p: &Path) { let _ = disk::read(p); }\n"
        "fn c(p: &Path) { let _ = rts(p); let s = String::new(); let _ = s.read_to_string(); }\n"
        "// fn d() { File::open(\"x\") }\n"
        "fn e() { let _ = \"File::open(p)\"; }\n"
        "#[cfg(test)]\nmod tests { fn t() { let _ = std::fs::read(\"x\"); } }\n"
    )})
    ops, _, _ = scan(root)
    got = sorted((o["function"], o["op"]) for o in ops)
    expect(got == [("a", "File::open"), ("b", "fs::read"), ("c", "fs::read_to_string")], got)


def regression_internal_read_inventory_rejects_unclassified_site():
    """Regression: a new pathname read passed without a manifest entry."""
    root = fake({"c/src/lib.rs": "fn a(p: &Path) { let _ = std::fs::read(p); }\n"})
    errs = check(root, {"entries": []})
    expect(any("new operation" in e for e in errs), errs)
    errs = check(root, classify(root, {}))
    expect(any("unclassified" in e for e in errs), errs)
    errs = check(root, classify(root, {("a", "fs::read"): OOF}))
    expect(errs == [], errs)


def regression_internal_read_inventory_rejects_stale_entry():
    """Regression: an entry for a removed read stayed in the manifest; a
    changed call kept its old classification."""
    root = fake({"c/src/lib.rs": "fn a(p: &Path) { let _ = std::fs::read(p); }\n"})
    m = classify(root, {("a", "fs::read"): OOF})
    gone = dict(m["entries"][0], function="b")
    m2 = {"entries": m["entries"] + [gone]}
    expect(any("stale" in e for e in check(root, m2)), check(root, m2))
    with open(os.path.join(root, "c/src/lib.rs"), "w") as fh:
        fh.write("fn a(p: &Path) { let _ = std::fs::read(p.join(\"x\")); }\n")
    expect(any("changed operation" in e for e in check(root, m)), check(root, m))


def regression_internal_read_inventory_rejects_raw_reader_escape():
    """Regression: a managed reader's function also held a raw descriptor."""
    root = fake({"c/src/lib.rs": (
        "fn a(p: &Path) {\n    let c = ManagedReadCursor::open(p)?;\n    let f = std::fs::File::open(p)?;\n    let fd = f.as_raw_fd();\n}\n"
    )})
    m = classify(root, {("a", "ManagedReadCursor::open"): MANAGED, ("a", "File::open"): MANAGED})
    errs = check(root, m)
    expect(any("raw reader" in e for e in errs), errs)
    expect(any("raw descriptor escape as_raw_fd" in e for e in errs), errs)


def regression_internal_read_inventory_requires_transitive_helper():
    """Regression: a mandatory function delegated its read to a new helper
    that opens the file raw."""
    root = fake({"c/src/lib.rs": (
        "fn hash(p: &Path) { let c = ManagedReadCursor::open(p)?; helper(p); }\n"
        "fn helper(p: &Path) { let _ = std::fs::read(p); }\n"
    )})
    m = classify(root, {("hash", "ManagedReadCursor::open"): MANAGED, ("helper", "fs::read"): OOF})
    errs = check(root, m)
    expect(any("reaches helper helper" in e for e in errs), errs)
    m = classify(root, {("hash", "ManagedReadCursor::open"): MANAGED,
                        ("helper", "fs::read"): dict(OOF, non_mandatory_callers=["hash"])})
    expect(check(root, m) == [], check(root, m))


def regression_internal_read_inventory_rejects_out_of_family_mandatory_reader():
    """Regression: a mandatory helper was waved through as configuration."""
    root = fake({"c/src/lib.rs": "fn sha(p: &Path) { let _ = std::fs::read(p); }\n"})
    m = classify(root, {("sha", "fs::read"): dict(OOF, mandatory_helper=True)})
    expect(any("mandatory helper classified out-of-family" in e for e in check(root, m)), check(root, m))
    m = classify(root, {("sha", "fs::read"): {"disposition": "out-of-family", "category": "other", "reason": "x"}})
    expect(any("named category" in e for e in check(root, m)), check(root, m))


def regression_internal_read_inventory_requires_named_residual_reason():
    """Regression: a residual entry had no family, reason or issue."""
    root = fake({"c/src/lib.rs": "fn a(p: &Path) { let _ = std::fs::read(p); }\n"})
    m = classify(root, {("a", "fs::read"): {"disposition": "residual"}})
    errs = check(root, m)
    expect(any("named family" in e for e in errs) and any("issue #196" in e for e in errs), errs)
    m = classify(root, {("a", "fs::read"): {"disposition": "residual", "family": "range-cache",
                                             "reason": "completion owner", "issue": "#196"}})
    expect(check(root, m) == [], check(root, m))


def regression_internal_read_inventory_existing_create_mode_unchanged():
    """Regression: `unchanged-from-<baseline>` was reused for a changed create."""
    root = fake({"c/src/lib.rs": "fn a(p: &Path) { let _ = std::fs::File::create(p); }\n"})
    ops, _, _ = scan(root)
    out = {"disposition": "output-owner", "mode_policy": UNCHANGED, "baseline_fingerprint": ops[0]["fingerprint"]}
    m = classify(root, {("a", "File::create"): out})
    expect(check(root, m) == [], check(root, m))
    with open(os.path.join(root, "c/src/lib.rs"), "w") as fh:
        fh.write("fn a(p: &Path) { let _ = std::fs::File::create(p.join(\"y\")); }\n")
    ops, _, _ = scan(root)
    m["entries"][0]["fingerprint"] = ops[0]["fingerprint"]
    expect(any("valid only for an unchanged baseline" in e for e in check(root, m)), check(root, m))


def regression_exclusive_create_requires_mode_policy():
    """Regression: a new exclusive create landed without a mode policy."""
    root = fake({"c/src/lib.rs": (
        "fn a(p: &Path) { let _ = OpenOptions::new()\n    .write(true)\n    .create_new(true)\n    .open(p); }\n"
    )})
    ops, _, _ = scan(root)
    expect(ops[0]["exclusive"], ops)
    m = classify(root, {("a", "OpenOptions"): {"disposition": "output-owner"}})
    expect(any("mode policy" in e for e in check(root, m)), check(root, m))
    m = classify(root, {("a", "OpenOptions"): {"disposition": "output-owner", "mode_policy": "0666 & !umask"}})
    expect(check(root, m) == [], check(root, m))


def self_test():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("regression_") and callable(v)]
    failed = 0
    for t in tests:
        try:
            t()
            print("ok   " + t.__name__)
        except AssertionError as e:
            failed += 1
            print("FAIL %s: %s" % (t.__name__, e))
    print("%d passed, %d failed" % (len(tests) - failed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
