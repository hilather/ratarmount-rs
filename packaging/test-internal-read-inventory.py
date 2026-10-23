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

This is a reviewed change detector, not a dataflow analysis. It fails closed
on forms it cannot follow: an import from `std::fs`/`tokio::fs` (or a glob,
or an aliased `tempfile` item) it cannot resolve, and an `OpenOptions`
builder bound to a variable that escapes its function or never reaches
`.open(`. Code under `#[cfg(..)]` is skipped only when the predicate is
false without `test` (`feature = "test-hooks"` counts as `test`: release
builds never enable it, packaging/test-no-test-hooks-in-release.sh).
Fingerprints hash the comment-stripped statement with its literal values,
plus every later statement that configures a bound builder. The helper walk
follows same-crate free-function calls transitively.

Known limits: a renamed crate root (`use std as s`), a glob import of a local
module that re-exports an fs function, openers of other crates (`nix`),
method and cross-crate calls in the helper walk.

Usage:
  test-internal-read-inventory.py            check the workspace (exit 0/1)
  test-internal-read-inventory.py --list     print every scanned operation
  test-internal-read-inventory.py --write    rewrite the manifest: keep the
                                             classification of matching keys,
                                             refresh fingerprints and lines,
                                             add new operations UNCLASSIFIED
  test-internal-read-inventory.py --write --baseline DIR
                                             as --write, and refresh the
                                             `baseline_fingerprint` of each
                                             `unchanged-from-<baseline>` create
                                             whose (file, fingerprint) the
                                             baseline checkout DIR has
  test-internal-read-inventory.py --verify-baseline DIR
                                             check every `unchanged-from-<baseline>`
                                             create against a checkout of the
                                             baseline (git archive e6ca64e)
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
# Raw opens whose flags may create (`O_CREAT` / `OFlags::CREATE`).
RAW_OPENS = frozenset({
    "libc::open", "libc::openat", "libc::open64", "rustix::open", "rustix::openat",
    "open_admitted", "openat_admitted",
})
ESCAPES = ("into_raw_fd", "as_raw_fd", "try_clone", "from_raw_fd", "File::from")


# --------------------------------------------------------------------------
# Lexing: blank comments and literal contents, keep offsets and newlines.
# --------------------------------------------------------------------------


def mask(src, strings=True):
    """Return `src` with comments and (unless `strings` is false) string/char
    literal contents blanked. Offsets and newlines are kept."""
    out = list(src)
    keep_strings = not strings
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
            if keep_strings:
                i = j
                continue
            blank(i + m.end(), j - len(close))
            i = j
        elif c == '"' or (c == "b" and src.startswith('b"', i) and (i == 0 or not (src[i - 1].isalnum() or src[i - 1] == "_"))):
            j = i + (2 if c == "b" else 1)
            start = j
            while j < n and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            if keep_strings:
                i = j + 1
                continue
            blank(start, min(j, n))
            i = j + 1
        elif c == "'":
            if i + 1 < n and src[i + 1] == "\\":
                j = src.find("'", i + 2)
                j = n if j < 0 else j
                if not keep_strings:
                    blank(i + 1, j)
                i = j + 1
            elif i + 2 < n and src[i + 2] == "'":
                if not keep_strings:
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


def cfg_test_only(pred):
    """Whether the cfg predicate `pred` is false whenever `test` is false (so
    the item exists only in test builds). `feature = "test-hooks"` counts as
    `test` (release builds never enable it). Other atoms are unknown, so
    `any(test, feature = "x")` is NOT test-only. Kleene logic: `test` is
    test-only, another atom is not; `all(..)` is test-only when any argument
    is; `any(..)` when every argument is (and there is one); `not(..)` never
    (conservative: the item is scanned)."""
    toks = re.findall(r'[A-Za-z_]\w*|"[^"]*"|[(),=]', pred)
    pos = [0]

    def peek():
        return toks[pos[0]] if pos[0] < len(toks) else None

    def take():
        pos[0] += 1
        return toks[pos[0] - 1]

    def expr():
        name = take() if peek() is not None else ""
        if peek() == "(" and name in ("all", "any", "not"):
            take()
            args = []
            while peek() not in (")", None):
                args.append(expr())
                if peek() == ",":
                    take()
            if peek() == ")":
                take()
            if name == "all":
                return any(args)
            if name == "any":
                return bool(args) and all(args)
            return False
        if peek() == "=":
            take()
            value = take() if peek() is not None else ""
            # `test-hooks` is never enabled in a release build
            # (packaging/test-no-test-hooks-in-release.sh).
            return name == "feature" and value == '"test-hooks"'
        return name == "test"

    try:
        return expr()
    except IndexError:
        return False


def is_test_cfg(attr_body):
    if attr_body is None:
        return True
    return cfg_test_only(attr_body)


def test_spans(text, raw=None):
    """Spans of items under `#[test]` / `#[cfg(test ...)]`, and test-only
    `mod name;` declarations (a `#[path = "..."]` file name when given)."""
    spans, test_mods = [], []
    for m in TEST_ATTR.finditer(text):
        body = m.group(1)
        if body is not None and raw is not None:
            body = raw[m.start(1):m.end(1)]  # literal values (`feature = ".."`)
        if not is_test_cfg(body):
            continue
        # The item after the attribute (skip further attributes).
        k = m.end()
        while True:
            nxt = re.match(r"\s*(#!?\[[^\]]*\]\s*)", text[k:])
            if not nxt:
                break
            k += nxt.end()
        item = re.match(
            r"\s*(?:pub(?:\([^)]*\))?\s+)?(?:unsafe\s+|async\s+|const\s+|extern\s+(?:\"[^\"]*\"\s+)?)*"
            r"(fn|mod|impl|struct|enum|trait|union|use|type|static|const|macro_rules!|extern)\b",
            text[k:],
        )
        mac = re.match(r"\s*[\w:]+!\s*([{(\[])", text[k:])
        if not item and mac:
            # A macro item (`thread_local! { .. }`): to its closing bracket.
            open_at = k + mac.end() - 1
            pairs = {"{": "}", "(": ")", "[": "]"}
            depth, j = 0, open_at
            while j < len(text):
                if text[j] == text[open_at]:
                    depth += 1
                elif text[j] == pairs[text[open_at]]:
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            spans.append((m.start(), j))
            continue
        block = re.match(r"\s*(?:if|match|while|for|loop|unsafe)\b|\s*\{", text[k:])
        if not item and block:
            # A block-like expression statement (`#[cfg(test)] if x { .. }`):
            # it ends at the brace closing its first top-level block, or the
            # last one of an `else` chain. It needs no `;`, so the `;` rule
            # below would swallow the statements after it.
            j = k
            while True:
                depth = 0
                while j < len(text):
                    ch = text[j]
                    if ch in "([":
                        depth += 1
                    elif ch in ")]":
                        depth -= 1
                    elif ch == "{" and depth == 0:
                        break
                    j += 1
                j = match_brace(text, j)
                nxt = re.match(r"\s*else\b", text[j + 1:])
                if not nxt:
                    break
                j = j + 1 + nxt.end()
            spans.append((m.start(), j))
            continue
        if not item:
            # A field, statement or expression: it ends at the first `,` or
            # `;` (or the enclosing `}`) outside nested brackets.
            depth, j = 0, k
            while j < len(text):
                ch = text[j]
                if ch in "([{":
                    depth += 1
                elif ch in ")]}":
                    if depth == 0:
                        break
                    depth -= 1
                elif ch in ",;" and depth == 0:
                    break
                j += 1
            spans.append((m.start(), j))
            continue
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


def use_leaves(text):
    """Every `use` declaration flattened to (path segments, local name) with
    its offset; `*` leaves have local name `*`."""
    out = []
    for m in re.finditer(r"(?<![\w:])use\s+([^;]*);", text):
        toks = re.findall(r"::|[A-Za-z_]\w*|[{},*]", m.group(1))
        pos = [0]

        def peek():
            return toks[pos[0]] if pos[0] < len(toks) else None

        def take():
            pos[0] += 1
            return toks[pos[0] - 1]

        def tree(prefix):
            path = list(prefix)
            while True:
                t = peek()
                if t is None:
                    return
                if t == "::":
                    take()
                    continue
                if t == "{":
                    take()
                    while peek() not in ("}", None):
                        tree(path)
                        if peek() == ",":
                            take()
                    if peek() == "}":
                        take()
                    return
                if t == "*":
                    take()
                    out.append((path, "*", m.start()))
                    return
                if t in (",", "}"):
                    return
                take()
                if t == "self":
                    seg_path = path
                else:
                    seg_path = path + [t]
                if peek() == "::":
                    path = seg_path
                    continue
                alias = seg_path[-1] if seg_path else t
                if peek() == "as":
                    take()
                    alias = take() if peek() not in (None, ",", "}") else alias
                out.append((seg_path, alias, m.start()))
                return

        while peek() is not None:
            tree([])
            if peek() == ",":
                take()
            elif peek() is not None:
                take()
    return out


# std::fs / tokio::fs items that open no file by path (anything else imported
# from those modules must be resolved below or is an error).
FS_PASSIVE = frozenset({
    "DirBuilder", "DirEntry", "FileTimes", "FileType", "Metadata", "Permissions", "ReadDir",
    "canonicalize", "create_dir", "create_dir_all", "exists", "hard_link", "metadata",
    "read_dir", "read_link", "remove_dir", "remove_dir_all", "remove_file", "rename",
    "set_permissions", "soft_link", "symlink", "symlink_metadata", "try_exists",
    "symlink_file", "symlink_dir",
})
FS_BARE = ("read", "read_to_string", "copy", "write")
# tempfile items the patterns know by their own name; an alias is an error.
TEMPFILE_ITEMS = frozenset({"NamedTempFile", "TempDir", "Builder", "tempfile", "tempfile_in",
                            "tempdir", "tempdir_in", "TempPath", "PersistError", "SpooledTempFile",
                            "spooled_tempfile", "env"})


def aliases(text):
    """Local names for `std::fs::File`, `std::fs::OpenOptions`, `std::fs`,
    bare fs functions and rustix's fs module, plus every import this scanner
    cannot resolve (`(offset, description)`, reported as an error: it fails
    closed instead of skipping an aliased opener)."""
    file_names, fs_names, bare, oo_names = {"File"}, {"fs"}, set(), {"OpenOptions"}
    rustix, rustix_bare, tempfile_bare, unsupported = {"rustix::fs"}, set(), set(), []
    oo_imported = False
    for path, alias, at in use_leaves(text):
        if len(path) >= 2 and path[0] in ("std", "tokio") and path[1] == "fs":
            rest = path[2:]
            if alias == "*":
                unsupported.append((at, "glob import of %s" % "::".join(path)))
            elif not rest:
                fs_names.add(alias)
            elif len(rest) > 1:
                unsupported.append((at, "import of %s" % "::".join(path)))
            elif rest[0] == "File":
                file_names.add(alias)
            elif rest[0] == "OpenOptions":
                oo_names.add(alias)
                oo_imported = oo_imported or alias == "OpenOptions"
            elif rest[0] in FS_BARE:
                bare.add((alias, rest[0]))
            elif rest[0] not in FS_PASSIVE:
                unsupported.append((at, "import of %s" % "::".join(path)))
        elif len(path) >= 2 and path[0] == "rustix" and path[1] == "fs":
            rest = path[2:]
            if alias == "*":
                unsupported.append((at, "glob import of rustix::fs"))
            elif not rest:
                rustix.add(alias)
            elif rest[0] in ("open", "openat", "openat2"):
                rustix_bare.add((alias, rest[0]))
        elif path and path[0] == "tempfile":
            rest = path[1:]
            if alias == "*":
                unsupported.append((at, "glob import of tempfile"))
            elif not rest:
                if alias != "tempfile":
                    unsupported.append((at, "tempfile imported as %s" % alias))
            elif rest[0] not in TEMPFILE_ITEMS or alias != rest[-1]:
                unsupported.append((at, "import of %s as %s" % ("::".join(path), alias)))
            elif rest[0] in ("tempfile", "tempfile_in"):
                tempfile_bare.add(alias)
    return {"file": file_names, "fs": fs_names, "bare": bare, "oo": oo_names,
            "oo_imported": oo_imported,
            "rustix": rustix, "rustix_bare": rustix_bare, "tempfile_bare": tempfile_bare,
            "unsupported": unsupported}


def builder_factories(text, names):
    """Free functions returning a `std::fs::OpenOptions` builder: each call is
    an `OpenOptions` operation (`open_options_nofollow().create(true).open(p)`)."""
    # A bare `OpenOptions` return type is std's only when imported from it
    # (the session crate has an `OpenOptions` of its own).
    imported = sorted(n for n in names["oo"] if n != "OpenOptions" or names["oo_imported"])
    alts = [r"(?:std|tokio)::fs::OpenOptions", r"fs::OpenOptions"] + [re.escape(n) for n in imported]
    return set(re.findall(r"\bfn\s+([a-z_]\w*)\s*\([^)]*\)\s*->\s*(?:%s)\b" % "|".join(alts), text))


def op_patterns(text, factories=()):
    names = aliases(text)
    rx = "|".join(sorted(re.escape(n) for n in names["rustix"]))
    files = "|".join(sorted(re.escape(n) for n in names["file"]))
    fss = "|".join(sorted(re.escape(n) for n in names["fs"]))
    oos = "|".join(sorted(re.escape(n) for n in names["oo"]))
    pats = [
        (r"(?<![\w.])(?:(?:std|tokio)::fs::)?(?:%s)::(open|create|create_new)\s*\(" % files, "File::{0}"),
        (r"(?<![\w.])(?:(?:std|tokio)::)?(?:%s)::(read|read_to_string|copy|write)\s*\(" % fss, "fs::{0}"),
        (r"(?<![\w.])(?:(?:std|tokio)::fs::|(?:%s)::)?(?:%s)::new\s*\(|(?<![\w.])(?:(?:std|tokio)::)?(?:fs::)?(?:%s)::options\s*\(" % (fss, oos, files), "OpenOptions"),
        (r"(?<![\w.])(?<!fn )(?:ratarmount_core::db_inodes::)?(open_admitted|openat_admitted)\s*\(", "{0}"),
        (r"\.reopen\s*\(\s*\)", "tempfile::reopen"),
        # Private open helpers of the caches: each call is its own entry.
        (r"(?<![\w.:])(?<!fn )open_regular\s*\(", "open_regular"),
        (r"\.try_clone\s*\(", "try_clone"),
        (r"\b(from_raw_fd|into_raw_fd|from_raw_handle|into_raw_handle)\s*\(", "{0}"),
        (r"(?<![\w.])(?:libc::)(open|openat|open64)\s*\(", "libc::{0}"),
        (r"(?<![\w.:])(?:%s)::(open|openat|openat2)\s*\(" % rx, "rustix::{0}"),
        (r"(?<![\w])NamedTempFile::(?:new|new_in)\s*\(|\.tempfile(?:_in)?\s*\(|(?<![\w.])tempfile::tempfile(?:_in)?\s*\(", "tempfile"),
        (r"(?<![\w.])(?:tempfile::)?(?:tempdir|tempdir_in)\s*\(|\.tempdir(?:_in)?\s*\(|(?<![\w.])TempDir::new(?:_in)?\s*\(", "tempdir"),
        (r"(?<![\w.])ManagedReadCursor::open\s*\(", "ManagedReadCursor::open"),
        (r"(?<![\w.])managed_read::(\w+)\s*\(", "managed_read::{0}"),
    ]
    for alias, name in sorted(names["bare"]):
        pats.append((r"(?<![\w.:])(?<!fn )%s\s*\(" % re.escape(alias), "fs::" + name))
    for alias, name in sorted(names["rustix_bare"]):
        pats.append((r"(?<![\w.:])(?<!fn )%s\s*\(" % re.escape(alias), "rustix::" + name))
    for alias in sorted(names["tempfile_bare"]):
        pats.append((r"(?<![\w.:])(?<!fn )%s(?:_in)?\s*\(" % re.escape(alias), "tempfile"))
    for name in sorted(factories):
        pats.append((r"(?<![\w.])(?<!fn )(?:[a-z_]\w*::)*%s\s*\(" % re.escape(name), "OpenOptions"))
    return [(re.compile(p), label) for p, label in pats]


def extent(text, pos):
    """(start, end) of the statement around `pos` in the masked `text`: from
    the start of its line to the first `;` or block `{` outside brackets, or
    the `}` closing the enclosing block (a tail expression), at most 40 lines."""
    start = text.rfind("\n", 0, pos) + 1
    end, lines, depth = pos, 0, 0
    while end < len(text) and lines < 40:
        ch = text[end]
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        elif ch == "{":
            if depth <= 0:
                break
            depth += 1
        elif ch == "}":
            if depth <= 0:
                break
            depth -= 1
        elif ch == ";" and depth <= 0:
            break
        elif ch == "\n":
            lines += 1
        end += 1
    return start, end


def statement(ctext, spans):
    """The normalized text of `spans` in the comment-masked source: literal
    values are kept, so a changed path or mode changes the fingerprint."""
    return "\n".join(re.sub(r"\s+", "", ctext[a:b]) for a, b in spans)


def builder_spans(text, pos, first, fn_end, factory):
    """For `let [mut] NAME = OpenOptions::new()..;` every later statement of
    the function that uses NAME (its configuration and its `.open`), and an
    error string when NAME is used other than by a method call (it escapes)
    or never reaches `.open(` (unless the function returns the builder)."""
    line = text[text.rfind("\n", 0, pos) + 1:pos]
    m = re.search(r"\blet\s+(?:mut\s+)?([a-z_]\w*)\s*(?::[^=]*)?=\s*$", line)
    if not m or m.group(1) == "_" or re.search(r"\.\s*open\s*\(", text[pos:first]):
        return [], None
    name = m.group(1)
    spans, opened, problem = [], False, None
    for u in re.finditer(r"(?<![\w.])%s\b" % re.escape(name), text[first:fn_end]):
        at = first + u.start()
        after = text[at + len(name):at + len(name) + 40]
        sp = extent(text, at)
        if re.match(r"\s*\.", after):
            if re.search(r"\.\s*open\s*\(", text[at:sp[1]]):
                opened = True
        elif not (factory and re.match(r"\s*\}", after)):
            problem = "builder %s escapes its function (used other than by a method call)" % name
        if sp not in spans:
            spans.append(sp)
    if not opened and not factory and problem is None:
        problem = "builder %s never reaches .open( in its function" % name
    return spans, problem


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


def scan(root, problems=None):
    """Every production operation: list of dicts (key fields + evidence).
    Unsupported forms (an unresolvable import, an escaping builder) are
    appended to `problems` when given."""
    problems = [] if problems is None else problems
    files = rust_files(root)
    texts, raws, ctexts, test_files = {}, {}, {}, set()
    for rel in files:
        with open(os.path.join(root, rel), encoding="utf-8", errors="replace") as fh:
            raws[rel] = fh.read()
            texts[rel] = mask(raws[rel])
            ctexts[rel] = mask(raws[rel], strings=False)
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
    factories = {}
    for rel in files:
        if rel not in test_files:
            factories.setdefault(crate_of(rel), set()).update(builder_factories(texts[rel], aliases(texts[rel])))
    ops, fn_index = [], {}
    for rel in files:
        if rel in test_files:
            continue
        text, ctext = texts[rel], ctexts[rel]
        spans, _ = test_spans(text, raws[rel])
        for at, what in aliases(text)["unsupported"]:
            if not any(a <= at <= b for a, b in spans):
                problems.append("unsupported import (resolve it in the scanner or import by a known name): %s:%d %s"
                                % (rel, text.count("\n", 0, at) + 1, what))
        fns = [f for f in fn_spans(text) if not any(a <= f[0] <= b for a, b in spans)]
        for a, b, name in fns:
            fn_index.setdefault(crate_of(rel), {}).setdefault(name.split("::")[-1], []).append((rel, name))
        found = []
        for pat, label in op_patterns(text, factories.get(crate_of(rel), ())):
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
            first = extent(text, pos)
            parts = [first]
            if op == "OpenOptions":
                fn_end = max([b for a, b, n in fns if a <= pos <= b and n == fn] or [len(text)])
                extra, problem = builder_spans(text, pos, first[1], fn_end,
                                               fn.split("::")[-1] in factories.get(crate_of(rel), ()))
                parts += extra
                if problem:
                    problems.append("unsupported OpenOptions builder: %s:%d %s: %s"
                                    % (rel, text.count("\n", 0, pos) + 1, fn, problem))
            stmt = statement(ctext, parts)
            ops.append({
                "file": rel,
                "function": fn,
                "op": op,
                "ordinal": seen[k],
                "line": text.count("\n", 0, pos) + 1,
                "fingerprint": fingerprint(stmt),
                "creates": op in CREATE_OPS and (op != "OpenOptions" or re.search(r"\.(create|create_new)\(true\)", stmt) is not None)
                or (op in RAW_OPENS and re.search(r"O_CREAT|CREATE", stmt) is not None),
                "exclusive": op in ("File::create_new", "tempfile", "tempdir", "managed_read::copy_exclusive_new")
                or (op == "OpenOptions" and ".create_new(true)" in stmt)
                or (op in RAW_OPENS and re.search(r"O_EXCL|EXCL", stmt) is not None),
            })
    return ops, texts, fns_by_file(texts, raws, files, test_files)


def crate_of(rel):
    return rel.split("/")[0]


def fns_by_file(texts, raws, files, test_files):
    out = {}
    for rel in files:
        if rel in test_files:
            continue
        spans, _ = test_spans(texts[rel], raws[rel])
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
    ops, texts, fns = scan(root, errors)
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
    """A function with a managed entry must not reach (directly or through any
    chain of same-crate free functions) a helper whose reads are not managed,
    and must not hold a raw descriptor except around a classified
    non-managed operation on the same line. A helper's entry may excuse a
    caller by listing, in `non_mandatory_callers`, the managed root or the
    function that calls the helper directly. Limits: methods and associated
    functions are not followed, nor calls across crates."""
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
            raw_by_fn.setdefault((crate_of(o["file"]), o["function"]), []).append(o)
    # Free functions by (crate, name): [(file, start, end)].
    free = {}
    for rel, lst in fns.items():
        for a, b, qual in lst:
            if "::" not in qual:
                free.setdefault((crate_of(rel), qual), []).append((rel, a, b))

    def callees(rel, a, b, leaf):
        text = texts[rel]
        body = text[a:b]
        out = []
        for m in CALL_RE.finditer(body):
            prefix, callee = m.group(1), m.group(2)
            if callee == leaf or text[max(0, a + m.start() - 3):a + m.start()].endswith("fn "):
                continue
            for target, ta, tb in free.get((crate_of(rel), callee), []):
                if resolves(rel, text, prefix, callee, target):
                    out.append((callee, target, ta, tb))
        return out

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
            # Breadth-first over the call graph; `via` is the direct caller.
            queue = [(qual, callee, target, ta, tb) for callee, target, ta, tb in callees(rel, a, b, qual.split("::")[-1])]
            visited = set()
            while queue:
                via, callee, target, ta, tb = queue.pop(0)
                if (target, callee) in visited:
                    continue
                visited.add((target, callee))
                for o in raw_by_fn.get((crate_of(rel), callee), []):
                    if o["file"] != target:
                        continue
                    ent = by_key.get(key(o))
                    if ent is None or ent.get("disposition") in ("managed-read", "sqlite-snapshot", "output-owner"):
                        continue
                    excused = ent.get("non_mandatory_callers") or []
                    if qual in excused or via in excused:
                        continue
                    if ent.get("category") == "directory-handle-or-durability":
                        continue  # a directory handle reads no file content
                    chain = "" if via == qual else " via %s" % via
                    errs.append("managed function %s (%s) reaches helper %s%s with a non-managed read (%s %s#%d)"
                                % (qual, rel, callee, chain, o["file"], o["op"], o["ordinal"]))
                for nxt in callees(target, ta, tb, callee):
                    queue.append((callee,) + nxt)
    return sorted(set(errs))


# --------------------------------------------------------------------------
# Main.
# --------------------------------------------------------------------------


def load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def write(root, path, baseline_dir=None):
    """Rewrite the manifest. `baseline_dir` (a checkout of the baseline) is
    the only way a `baseline_fingerprint` is refreshed: an
    `unchanged-from-<baseline>` create gets its current fingerprint as its
    baseline one only when the baseline has the same (file, fingerprint)."""
    at_base = None
    if baseline_dir is not None:
        at_base = {(o["file"], o["fingerprint"]) for o in scan(baseline_dir)[0]}
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
        if at_base is not None and e.get("mode_policy") == UNCHANGED and (o["file"], o["fingerprint"]) in at_base:
            e["baseline_fingerprint"] = o["fingerprint"]
        out.append(order(e))
    manifest["entries"] = out
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=1, sort_keys=False)
        fh.write("\n")
    return len(out)


def verify_baseline(baseline_dir, manifest):
    """The `unchanged-from-<baseline>` entries whose (file,
    baseline_fingerprint) the baseline checkout does not have."""
    at_base = {(o["file"], o["fingerprint"]) for o in scan(baseline_dir)[0]}
    return [e for e in manifest["entries"]
            if e.get("mode_policy") == UNCHANGED
            and (e["file"], e.get("baseline_fingerprint")) not in at_base]


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
    if len(argv) == 3 and argv[1] == "--verify-baseline":
        bad = verify_baseline(argv[2], load(MANIFEST))
        for e in bad:
            print("inventory: not a baseline create: %s:%d %s %s#%d"
                  % (e["file"], e["line"], e["function"], e["op"], e["ordinal"]))
        return 1 if bad else 0
    if argv[1:] == ["--write"]:
        print("wrote %d entries" % write(ROOT, MANIFEST))
        return 0
    if len(argv) == 4 and argv[1:3] == ["--write", "--baseline"]:
        print("wrote %d entries" % write(ROOT, MANIFEST, argv[3]))
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
    """Regression: `File as RawFile` / `fs as disk` / bare imports hid reads;
    a `#[cfg(test)]` field hid the rest of the file."""
    root = fake({"c/src/lib.rs": (
        "struct S {\n    a: u8,\n    #[cfg(test)]\n    t: u8,\n}\n"
        "#[cfg(test)]\nthread_local! {\n    static X: u8 = 0;\n}\n"
        "fn f(p: &Path) { let _ = std::fs::read(p); }\n"
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
    expect(got == [("a", "File::open"), ("b", "fs::read"), ("c", "fs::read_to_string"), ("f", "fs::read")], got)


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
    # Raw exclusive creates (`O_CREAT | O_EXCL`, rustix `CREATE | EXCL`).
    root = fake({"c/src/lib.rs": (
        "fn b(p: &CStr) { let _ = unsafe { libc::open(p.as_ptr(), libc::O_CREAT | libc::O_EXCL, 0o600) }; }\n"
        "fn c(d: &OwnedFd) { let _ = rustix::fs::openat(d, \"x\", OFlags::CREATE | OFlags::EXCL, Mode::empty()); }\n"
    )})
    ops, _, _ = scan(root)
    expect(all(o["exclusive"] for o in ops) and len(ops) == 2, ops)
    m = classify(root, {("b", "libc::open"): {"disposition": "output-owner"},
                        ("c", "rustix::openat"): {"disposition": "output-owner"}})
    expect(sum("mode policy" in e for e in check(root, m)) == 2, check(root, m))


def regression_inventory_cfg_test_block_and_any_test_do_not_hide_code():
    """Regression (R11-S7-FIX1): a `#[cfg(test)] if .. { .. }` statement (no
    `;`) hid every statement after it in the function, so the production
    `libc::open` of `ensure_standard_descriptors` had no entry; and
    `cfg(any(test, feature = "http"))` code, compiled in production with the
    feature, was skipped as test-only."""
    root = fake({"c/src/lib.rs": (
        "fn fill() {\n    #[cfg(test)]\n    if FAIL.with(|f| f.get()) {\n        return;\n    }\n"
        "    loop {\n        let fd = unsafe { libc::open(c\"/dev/null\".as_ptr(), libc::O_RDWR) };\n    }\n}\n"
        "fn chain(p: &Path) {\n    #[cfg(test)]\n    if X { return; } else if Y { return; } else { () }\n"
        "    #[cfg(test)]\n    let _t = std::fs::read(\"t\");\n    let _ = std::fs::read(p);\n}\n"
        "#[cfg(any(test, feature = \"http\"))]\nfn served(p: &Path) { let _ = std::fs::read(p); }\n"
        "#[cfg(all(test, unix))]\nfn only_tests(p: &Path) { let _ = std::fs::read(p); }\n"
        "#[cfg(not(test))]\nfn not_tests(p: &Path) { let _ = std::fs::read(p); }\n"
        "#[cfg(any(test, all(test, unix)))]\nfn also_tests(p: &Path) { let _ = std::fs::read(p); }\n"
        "#[cfg(any(test, feature = \"test-hooks\"))]\nfn hooks(p: &Path) { let _ = std::fs::read(p); }\n"
    )})
    ops, _, _ = scan(root)
    got = sorted((o["function"], o["op"]) for o in ops)
    expect(got == [("chain", "fs::read"), ("fill", "libc::open"), ("not_tests", "fs::read"), ("served", "fs::read")], got)


def regression_inventory_aliased_imports_resolve_or_fail_closed():
    """Regression (R11-S7-FIX1): `use std::fs::read as read_file;`,
    `OpenOptions as FsOpenOptions` and nested `std::{fs::{..}}` imports hid
    their reads and creates; an import the scanner cannot resolve was
    skipped instead of failing."""
    root = fake({"c/src/lib.rs": (
        "use std::fs::read as read_file;\n"
        "use std::fs::{self as stdfs, OpenOptions as FsOpenOptions, Metadata};\n"
        "use std::{fs::{File as F2}, io};\n"
        "use rustix::fs::{self, Mode};\n"
        "fn a(p: &Path) { let _ = read_file(p); }\n"
        "fn b(p: &Path) { let _ = FsOpenOptions::new().write(true).create(true).open(p); }\n"
        "fn c(p: &Path) { let _ = stdfs::read(p); }\n"
        "fn d(p: &Path) { let _ = F2::open(p); }\n"
        "fn e(d: &OwnedFd) { let _ = fs::openat(d, \"x\", OFlags::RDONLY, Mode::empty()); }\n"
    )})
    errs = []
    ops, _, _ = scan(root, errs)
    got = sorted((o["function"], o["op"], o["creates"]) for o in ops)
    expect(got == [("a", "fs::read", False), ("b", "OpenOptions", True), ("c", "fs::read", False),
                   ("d", "File::open", False), ("e", "rustix::openat", False)], got)
    expect(errs == [], errs)
    for bad in ("use std::fs::*;\n", "use std::fs::{open_new_thing};\n", "use tempfile::NamedTempFile as Tmp;\n",
                "use std::fs::File::open;\n", "use tempfile as tf;\n"):
        root = fake({"c/src/lib.rs": bad + "fn a() {}\n"})
        errs = check(root, {"entries": []})
        expect(any("unsupported import" in e for e in errs), (bad, errs))


def regression_inventory_helper_walk_is_transitive():
    """Regression (R11-S7-FIX1): a managed function reaching a raw read
    through two helpers (`hash -> mid -> leaf`, `leaf` in another module) was
    not reported; the check followed one call only."""
    root = fake({
        "c/src/lib.rs": "mod util;\nuse crate::util::leaf;\nfn hash(p: &Path) { let c = ManagedReadCursor::open(p)?; mid(p); }\nfn mid(p: &Path) { leaf(p); }\n",
        "c/src/util.rs": "pub fn leaf(p: &Path) { let _ = std::fs::read(p); }\n",
    })
    m = classify(root, {("hash", "ManagedReadCursor::open"): MANAGED, ("leaf", "fs::read"): OOF})
    errs = check(root, m)
    expect(any("reaches helper leaf via mid" in e for e in errs), errs)
    m = classify(root, {("hash", "ManagedReadCursor::open"): MANAGED,
                        ("leaf", "fs::read"): dict(OOF, non_mandatory_callers=["mid"])})
    expect(check(root, m) == [], check(root, m))


def regression_inventory_fingerprint_keeps_literals_and_builder_configuration():
    """Regression (R11-S7-FIX1): fingerprints hashed literal-masked text, so
    `"config.json"` -> `"index.sqlite"` kept the entry; a builder configured
    in later statements (`let mut o = OpenOptions::new(); o.mode(..);
    o.open(p)`) was neither a create nor fingerprinted past its first
    statement, so `.mode(0o600)` -> `.mode(0o666)` passed."""
    src = "fn a(p: &Path) { let _ = std::fs::read(p.join(\"config.json\")); }\n"
    root = fake({"c/src/lib.rs": src})
    m = classify(root, {("a", "fs::read"): OOF})
    with open(os.path.join(root, "c/src/lib.rs"), "w") as fh:
        fh.write(src.replace("config.json", "index.sqlite"))
    expect(any("changed operation" in e for e in check(root, m)), check(root, m))
    builder = (
        "fn copy(p: &Path) -> io::Result<File> {\n    let mut opts = std::fs::OpenOptions::new();\n"
        "    opts.write(true).create_new(true);\n    #[cfg(unix)]\n    {\n        opts.mode(0o600);\n    }\n"
        "    let f = opts.open(p)?;\n    Ok(f)\n}\n"
    )
    root = fake({"c/src/lib.rs": builder})
    ops, _, _ = scan(root)
    expect(len(ops) == 1 and ops[0]["creates"] and ops[0]["exclusive"], ops)
    m = classify(root, {("copy", "OpenOptions"): {"disposition": "output-owner", "mode_policy": "0600"}})
    expect(check(root, m) == [], check(root, m))
    with open(os.path.join(root, "c/src/lib.rs"), "w") as fh:
        fh.write(builder.replace("0o600", "0o666"))
    expect(any("changed operation" in e for e in check(root, m)), check(root, m))
    # A long chain: the mode on its ninth line is part of the fingerprint.
    chain = "fn l(p: &Path) {\n    let _ = OpenOptions::new()\n" + "        .read(true)\n" * 7 + "        .mode(0o600)\n        .open(p);\n}\n"
    root = fake({"c/src/lib.rs": chain})
    m = classify(root, {("l", "OpenOptions"): OOF})
    with open(os.path.join(root, "c/src/lib.rs"), "w") as fh:
        fh.write(chain.replace("0o600", "0o666"))
    expect(any("changed operation" in e for e in check(root, m)), check(root, m))
    # Builder factories: each call is an operation; an escaping builder fails.
    root = fake({"c/src/lib.rs": (
        "use std::fs::OpenOptions as Fs;\n"
        "fn opts() -> Fs {\n    let mut o = Fs::new();\n    o.read(true);\n    o\n}\n"
        "fn user(p: &Path) { let _ = opts().write(true).create(true).open(p); }\n"
        "fn escapes(p: &Path) { let mut o = Fs::new(); configure(&mut o); let _ = o.open(p); }\n"
        "fn unopened() { let mut o = Fs::new(); o.read(true); }\n"
    )})
    errs = []
    ops, _, _ = scan(root, errs)
    got = sorted((o["function"], o["op"], o["creates"]) for o in ops)
    expect(got == [("escapes", "OpenOptions", False), ("opts", "OpenOptions", False),
                   ("unopened", "OpenOptions", False), ("user", "OpenOptions", True)], got)
    expect(len(errs) == 2 and any("escapes its function" in e for e in errs)
           and any("never reaches .open(" in e for e in errs), errs)


def regression_inventory_baseline_fingerprint_comes_only_from_the_baseline():
    """Regression (R11-S7-FIX1): a new create could claim
    `unchanged-from-<baseline>` by copying its own fingerprint into
    `baseline_fingerprint`; only `--write --baseline DIR` may set it, and
    `--verify-baseline` (now in CI) rejects a copied one."""
    base_src = "fn a(p: &Path) { let _ = std::fs::File::create(p); }\n"
    base = fake({"c/src/lib.rs": base_src})
    cur = fake({"c/src/lib.rs": base_src + "fn b(p: &Path) { let _ = std::fs::File::create(p.join(\"new\")); }\n"})
    path = os.path.join(cur, "manifest.json")
    m = classify(cur, {("a", "File::create"): {"disposition": "output-owner", "mode_policy": UNCHANGED},
                       ("b", "File::create"): {"disposition": "output-owner", "mode_policy": UNCHANGED}})
    with open(path, "w") as fh:
        json.dump(m, fh)
    write(cur, path)
    expect(not any("baseline_fingerprint" in e for e in load(path)["entries"]), "plain --write set one")
    write(cur, path, base)
    m = load(path)
    have = {e["function"]: e.get("baseline_fingerprint") for e in m["entries"]}
    expect(have["a"] and have["b"] is None, have)
    errs = check(cur, m)
    expect(len(errs) == 1 and "valid only for an unchanged baseline" in errs[0] and " b " in errs[0], errs)
    for e in m["entries"]:
        e["baseline_fingerprint"] = e["fingerprint"]  # the self-copy
    expect(check(cur, m) == [], check(cur, m))
    bad = verify_baseline(base, m)
    expect([e["function"] for e in bad] == ["b"], bad)


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
