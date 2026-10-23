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
plus every later statement that configures a bound builder. An
`OpenOptions` `.create(..)` / `.create_new(..)` with any argument but a
literal `false` is a create (it needs a mode policy). A test-only match arm
ends at its block or block-like body (`unsafe`, `loop`, `match`, `if`/`else`).
The helper walk follows same-crate free-function calls transitively, through
`use .. as` renames of a function or a module, `crate::`/`super::`/`self::`
paths (any same-crate definition) and calls of the caller's own name in
another module. Generic argument lists (`::<..>`) are matched balanced; an
unbalanced one is reported. Descriptor duplication and ownership conversion
(`try_clone_to_owned`, `dup`/`dup2`/`dup3`, `F_DUPFD[_CLOEXEC]`, `File::from`)
are operations. A production module whose file lies under `tests`,
`benches` or `examples` (`#[path = "tests/reader.rs"]`) is scanned; the
directory walk still skips those directories, so an integration test no
production module names stays out.
Pathname opens inside foreign libraries (libgit2 `Repository::open`,
libarchive `archive_read_open_filename`, lopdf `Document::load`) are
operations of their own.

Known limits: a renamed crate root (`use std as s`), a glob import of a local
module that re-exports an fs function, a `pub use .. as` re-export called
through its new path, openers of other crates (`nix`) and foreign openers not
listed above, method and cross-crate calls in the helper walk.

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
ESCAPES = ("into_raw_fd", "as_raw_fd", "try_clone", "try_clone_to_owned", "from_raw_fd", "File::from",
           "dup", "dup2", "dup3", "F_DUPFD", "F_DUPFD_CLOEXEC")


# --------------------------------------------------------------------------
# Lexing: blank comments and literal contents, keep offsets and newlines.
# --------------------------------------------------------------------------


def mask(src, strings=True, lit_fill=None):
    """Return `src` with comments and (unless `strings` is false) string/char
    literal contents blanked. Offsets and newlines are kept. With `lit_fill`
    literal contents (newlines included) are filled with that character
    instead, so a caller can tell them from code."""
    out = list(src)
    keep_strings = not strings
    i, n = 0, len(src)

    def blank(a, b, fill=" "):
        for k in range(a, b):
            if fill != " " or out[k] != "\n":
                out[k] = fill

    def blank_lit(a, b):
        blank(a, b, lit_fill or " ")

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
            blank_lit(i + m.end(), j - len(close))
            i = j
        elif c == '"' or (c == "b" and src.startswith('b"', i) and (i == 0 or not (src[i - 1].isalnum() or src[i - 1] == "_"))):
            j = i + (2 if c == "b" else 1)
            start = j
            while j < n and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            if keep_strings:
                i = j + 1
                continue
            blank_lit(start, min(j, n))
            i = j + 1
        elif c == "'":
            if i + 1 < n and src[i + 1] == "\\":
                j = src.find("'", i + 2)
                j = n if j < 0 else j
                if not keep_strings:
                    blank_lit(i + 1, j)
                i = j + 1
            elif i + 2 < n and src[i + 2] == "'":
                if not keep_strings:
                    blank_lit(i + 1, i + 2)
                i += 3
            else:
                i += 1
        else:
            i += 1
    return "".join(out)


def blank_generics(text):
    """`text` with the contents of every explicit generic argument list
    (`::<..>`) blanked, so call patterns see `load::<   >(p)` whatever the
    arguments are (`::<{ 64 * 1024 }>`, `::<Vec<u8>>`, `::<fn() -> T>`).
    Angle brackets nest only outside `()`/`[]`/`{}`; `->` closes nothing.
    Returns (text, [offset of each list that does not close before a `;`
    outside brackets]): an unsupported form the caller reports."""
    out = list(text)
    bad = []
    for m in re.finditer(r"::\s*<", text):
        k = m.end()
        angle, stack = 1, 0
        while k < len(text):
            ch = text[k]
            if ch in "([{":
                stack += 1
            elif ch in ")]}":
                stack -= 1
                if stack < 0:
                    break
            elif stack == 0 and ch == "<":
                angle += 1
            elif stack == 0 and ch == ">" and text[k - 1] != "-":
                angle -= 1
                if angle == 0:
                    break
            elif stack == 0 and ch == ";":
                break
            k += 1
        if k >= len(text) or text[k] != ">" or angle:
            bad.append(m.start())
            continue
        for i in range(m.end(), k):
            if out[i] != "\n":
                out[i] = " "
    return "".join(out), bad


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


def chain_end(text, j):
    """The brace closing the block-like expression from `j`: its first
    top-level `{ .. }` (skipping `(..)` / `[..]`), or the last block of an
    `else` / `else if` chain."""
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
            return j
        j = j + 1 + nxt.end()


# What may follow a top-level block inside one statement or arm: an `else`,
# `as`, a method call, `?`, an operator or the end of the span.
AFTER_BLOCK = re.compile(r"\s*(?:$|else\b|as\b|[^\w\s'#{\"])", re.S)


def unclean_span(span):
    """Why a test-only statement / arm span (from its first token) may hold
    more than one statement or arm: a second top-level `=>`, or code after a
    closed top-level block (`'a: { .. }` then the next statement)."""
    depth, arrows, i = 0, 0, 0
    while i < len(span):
        ch = span[i]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0 and ch == "}" and not AFTER_BLOCK.match(span, i + 1):
                return "code after a closed block"
        elif span.startswith("=>", i) and depth == 0:
            arrows += 1
            if arrows > 1:
                return "a second match arm"
        i += 1
    return None


def test_spans(text, raw=None, problems=None):
    """Spans of items under `#[test]` / `#[cfg(test ...)]`, and test-only
    `mod name;` declarations (a `#[path = "..."]` file name when given).
    A test-only statement or arm whose span may hold more than one statement
    or arm (a form the span rules do not know) is appended to `problems` as
    `(span start, offset, why)`: it fails closed instead of hiding production code."""
    spans, test_mods = [], []

    def check_span(k, j):
        why = unclean_span(text[k:j + 1 if j < len(text) and text[j] == "}" else j])
        if why is not None and problems is not None:
            problems.append((m.start(), k, why))
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
            r"(?:(fn|mod|impl|struct|enum|trait|union|use|type|static|const|extern)\b|macro_rules!)",
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
        block = re.match(r"\s*(?:'\w+\s*:\s*)?(?:(?:if|match|while|for|loop|unsafe)\b|\{)"
                         r"|\s*async\b(?:\s+move\b)?\s*\{", text[k:])
        if not item and block:
            # A block-like expression statement (`#[cfg(test)] if x { .. }`):
            # it ends at the brace closing its first top-level block, or the
            # last one of an `else` chain. It needs no `;`, so the `;` rule
            # below would swallow the statements after it.
            j = chain_end(text, k)
            spans.append((m.start(), j))
            check_span(k, j)
            continue
        if not item:
            # A field, statement, expression or match arm: it ends at the
            # first `,` or `;` (or the enclosing `}`) outside nested
            # brackets, or at the brace closing an arm's block body
            # (`PAT => { .. }` needs no `,`, so the `,` rule would swallow
            # the arms after it).
            depth, j = 0, k
            while j < len(text):
                ch = text[j]
                if ch == "{" and depth == 0 and ARM_BLOCK.search(text[k:j]):
                    # The arm's body is a block-like expression (`{ .. }`,
                    # `unsafe { .. }`, `loop`, `match`, `if`/`else` chain):
                    # it ends at its last block unless a method call or `?`
                    # continues it.
                    j = match_brace(text, j)
                    nxt = re.match(r"\s*else\b", text[j + 1:])
                    if nxt:
                        # The rest of the `else` / `else if` chain: never
                        # re-test `ARM_BLOCK`, whose `if` form cannot cross a
                        # `=>` inside an earlier branch (R11-S7-FIX14).
                        j = chain_end(text, j + 1 + nxt.end())
                    if re.match(r"\s*[.?]", text[j + 1:]):
                        j += 1
                        continue
                    break
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
            check_span(k, j)
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


# The text of a match arm up to the first top-level `{` of a block-like body.
ARM_BLOCK = re.compile(
    r"=>\s*(?:(?:unsafe|async(?:\s+move)?|const|'\w+\s*:|(?:'\w+\s*:\s*)?(?:loop|while|for|match|if)\b(?:(?!=>).)*?))?\s*$",
    re.S)


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


# Modules whose local renames are followed through later imports
# (`use std::fs as disk; use disk::read as read_index;`).
CHAIN_ROOTS = (["std"], ["tokio"], ["std", "fs"], ["tokio", "fs"], ["rustix"], ["rustix", "fs"], ["tempfile"])


def resolve_chained(leaves):
    """`leaves` with each path that starts with a local name of one of
    `CHAIN_ROOTS` rewritten to the full path, to a fixed point: an aliased
    module used as the first segment of a later import names that module."""
    leaves = list(leaves)
    for _ in range(8):
        roots = {}
        for path, alias, _ in leaves:
            if alias != "*" and path in CHAIN_ROOTS and alias != path[0]:
                roots[alias] = path
        changed = False
        out = []
        for path, alias, at in leaves:
            if path and path[0] in roots and len(path) > 1:
                path = roots[path[0]] + path[1:]
                changed = True
            elif path and path[0] in roots and path[0] != alias:
                # `use disk;` is a re-import of the alias itself.
                path = roots[path[0]]
                changed = True
            out.append((path, alias, at))
        leaves = out
        if not changed:
            break
    return leaves


def aliases(text):
    """Local names for `std::fs::File`, `std::fs::OpenOptions`, `std::fs`,
    bare fs functions and rustix's fs module, plus every import this scanner
    cannot resolve (`(offset, description)`, reported as an error: it fails
    closed instead of skipping an aliased opener)."""
    file_names, fs_names, bare, oo_names = {"File"}, {"fs"}, set(), {"OpenOptions"}
    rustix, rustix_bare, tempfile_bare, unsupported = {"rustix::fs"}, set(), set(), []
    oo_imported = False
    for path, alias, at in resolve_chained(use_leaves(text)):
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
    std_oos = "|".join(sorted(re.escape(n) for n in names["oo"] if n != "OpenOptions" or names["oo_imported"])) or "(?!)"
    pats = [
        (r"(?<![\w.])(?:(?:std|tokio)::fs::)?(?:%s)>?::(open|create|create_new)\s*\(" % files, "File::{0}"),
        (r"(?<![\w.])(?:(?:std|tokio)::)?(?:%s)::(read|read_to_string|copy|write)\s*\(" % fss, "fs::{0}"),
        (r"(?<![\w.])(?:(?:std|tokio)::fs::|(?:%s)::)?(?:%s)::new\s*\(|(?<![\w.])(?:(?:std|tokio)::)?(?:fs::)?(?:%s)::options\s*\(" % (fss, oos, files), "OpenOptions"),
        # `OpenOptions::default()` is `OpenOptions::new()` (R11-S7-FIX14); a
        # bare name is std's only when imported from it (`ratarmount_core`
        # has an `OpenOptions` of its own).
        (r"(?<![\w.:])(?:(?:(?:std|tokio)::)?(?:%s)::(?:%s)|%s)::default\s*\(" % (fss, oos, std_oos), "OpenOptions"),
        (r"(?<![\w.])(?<!fn )(?:ratarmount_core::db_inodes::)?(open_admitted|openat_admitted)\s*\(", "{0}"),
        (r"\.reopen\s*\(\s*\)", "tempfile::reopen"),
        # Private open helpers of the caches: each call is its own entry.
        (r"(?<![\w.:])(?<!fn )open_regular\s*\(", "open_regular"),
        (r"\.try_clone\s*\(", "try_clone"),
        (r"\.try_clone_to_owned\s*\(", "try_clone_to_owned"),
        (r"(?<![\w.:])(?:libc::|(?:rustix::)?io::|rustix::)(dup|dup2|dup3)\s*\(", "{0}"),
        (r"(?<![\w])(F_DUPFD(?:_CLOEXEC)?)\b", "{0}"),
        (r"(?<![\w.])(?:(?:std|tokio)::fs::)?(?:%s)>?::from\s*\(" % files, "File::from"),
        (r"\b(from_raw_fd|into_raw_fd|from_raw_handle|into_raw_handle)\s*\(", "{0}"),
        (r"(?<![\w.])(?:libc::)(open|openat|open64)\s*\(", "libc::{0}"),
        (r"(?<![\w.:])(?:%s)::(open|openat|openat2)\s*\(" % rx, "rustix::{0}"),
        (r"(?<![\w])NamedTempFile::(?:new|new_in|with_prefix|with_prefix_in|with_suffix|with_suffix_in)\s*\(|\.tempfile(?:_in)?\s*\(|(?<![\w.])tempfile::tempfile(?:_in)?\s*\(", "tempfile"),
        (r"(?<![\w.])(?:tempfile::)?(?:tempdir|tempdir_in)\s*\(|\.tempdir(?:_in)?\s*\(|(?<![\w.])(?:tempfile::)?TempDir::(?:new|with_prefix|with_suffix)(?:_in)?\s*\(", "tempdir"),
        (r"(?<![\w.])ManagedReadCursor::open\s*\(", "ManagedReadCursor::open"),
        # Foreign libraries that open a pathname themselves (#196 residuals:
        # their descriptors are outside this process's Rust code).
        (r"(?<![\w.])(?:git2::)?Repository::(open|open_bare|open_ext|open_from_env|discover)\s*\(", "git2::Repository::{0}"),
        (r"(?<![\w.])(?<!fn )(?:[a-z_]\w*::)*(archive_read_open_filename(?:_w)?|archive_read_open_filenames)\s*\(", "libarchive::{0}"),
        (r"(?<![\w.])(?:lopdf::)?Document::(load|load_filtered|load_with_password)\s*\(", "lopdf::Document::{0}"),
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
    # A call may carry explicit generic arguments (`std::fs::read::<_>(p)`,
    # `File::open::<&Path>(p)`).
    turbofish = r"\s*(?:::\s*<[^;{}]*?>\s*)?\("
    return [(re.compile(p.replace(r"\s*\(", turbofish)), label) for p, label in pats]


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


def statement(ctext, spans, lits=None):
    """The normalized text of `spans` in the comment-masked source: literal
    values are kept, so a changed path or mode changes the fingerprint.
    Whitespace is dropped outside literals only (`lits`: `ctext` with
    literal contents filled with NUL, from `mask(.., lit_fill="\\0")`), so
    `"cache index.sqlite"` -> `"cacheindex.sqlite"` changes it too."""
    if lits is None:
        return "\n".join(re.sub(r"\s+", "", ctext[a:b]) for a, b in spans)
    return "\n".join("".join(ch for k, ch in enumerate(ctext[a:b], a) if lits[k] == "\0" or not ch.isspace())
                     for a, b in spans)


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


def skipped_module_dir(rel):
    """A `tests` / `benches` / `examples` path component. The directory walk
    does not enter those directories (integration tests, benches, examples).
    A production `mod` whose file is there is still loaded (#197)."""
    return any(p in ("tests", "benches", "examples") for p in rel.split("/"))


def in_workspace(rel):
    """`rel` stays inside the tree after `#[path]` normalization."""
    return rel not in ("", ".") and not rel.startswith("/") and ".." not in rel.split("/")


def is_test_path(rel):
    parts = rel.split("/")
    if parts[0] in ("target", "vendor", "test-harness", "clients", "benchmarks"):
        return True
    if skipped_module_dir(rel):
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


def module_file(rel, name, root, chain=()):
    """File of `mod name;` in `rel`, inside the inline modules `chain`
    (`mod outer { mod name; }` is `outer/name.rs`, R11-S7-FIX16)."""
    d = os.path.dirname(rel)
    base = os.path.basename(rel)
    if base not in ("lib.rs", "main.rs", "mod.rs"):
        d = os.path.join(d, base[:-3])
    d = os.path.join(d, *chain)
    for cand in (os.path.join(d, name + ".rs"), os.path.join(d, name, "mod.rs")):
        if os.path.exists(os.path.join(root, cand)):
            return os.path.normpath(cand).replace(os.sep, "/")
    return None


def mod_decls(text, raw):
    """[(offset, name, chain)] for every `mod name;` declaration; `name` is
    `("path", file)` when a `#[path = ".."]` attribute names its file, and
    `chain` the names of the inline modules around it, outermost first."""
    out = []
    inl = inline_mods(text)
    for m in re.finditer(r"(?:^|\n|;|\}|\{)\s*((?:#\[[^\]]*\]\s*)*)(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*;", text):
        pm = re.search(r'#\[\s*path\s*=\s*"([^"]+)"\s*\]', raw[m.start(1):m.end(1)])
        chain = tuple(n for n, a, b in sorted(inl, key=lambda x: x[1]) if a < m.start(2) <= b)
        out.append((m.start(2), ("path", pm.group(1)) if pm else m.group(2), chain))
    return out


def scan(root, problems=None):
    """Every production operation: list of dicts (key fields + evidence).
    Unsupported forms (an unresolvable import, an escaping builder) are
    appended to `problems` when given."""
    problems = [] if problems is None else problems
    files = rust_files(root)
    texts, raws, ctexts, lits, test_files, generic_errs = {}, {}, {}, {}, set(), {}

    def load_source(rel):
        with open(os.path.join(root, rel), encoding="utf-8", errors="replace") as fh:
            raws[rel] = fh.read()
        texts[rel], generic_errs[rel] = blank_generics(mask(raws[rel]))
        ctexts[rel] = mask(raws[rel], strings=False)
        lits[rel] = mask(raws[rel], lit_fill="\0")

    for rel in files:
        load_source(rel)
    # Files that are test-only modules (and everything below them). A file
    # that a production `mod` declaration also names is production code
    # (`#[cfg(test)] #[path = "util.rs"] mod t; mod util;`, R11-S7-FIX15).
    # Declarations inside inline modules resolve below them (`mod outer {
    # pub mod util; }` is `outer/util.rs`), and a production declaration
    # that resolves to no file fails closed (R11-S7-FIX16). A production
    # target under `tests` / `benches` / `examples` is loaded here: the
    # walk skips those directories before declarations are resolved, so
    # `#[path = "tests/reader.rs"] mod reader;` would otherwise drop out
    # (#197).
    def mod_target(rel, name, chain):
        if isinstance(name, tuple):
            d = os.path.dirname(rel)
            if chain:
                if os.path.basename(rel) not in ("lib.rs", "main.rs", "mod.rs"):
                    d = os.path.join(d, os.path.basename(rel)[:-3])
                d = os.path.join(d, *chain)
            return os.path.normpath(os.path.join(d, name[1])).replace(os.sep, "/")
        return module_file(rel, name, root, chain)
    spans_of = {rel: test_spans(texts[rel], raws[rel])[0] for rel in files}
    decls = {rel: mod_decls(texts[rel], raws[rel]) for rel in files}
    changed = True
    while changed:
        changed = False
        prod = set()
        for rel in files:
            if rel in test_files:
                continue
            for at, name, chain in decls[rel]:
                if any(a <= at <= b for a, b in spans_of[rel]):
                    continue
                mf = mod_target(rel, name, chain)
                prod.add(mf)
                # The walk never opened this file. It is production code
                # because this declaration is, so load it and keep resolving
                # (a `mod` inside it may name another skipped file).
                if (mf and mf not in texts and skipped_module_dir(mf) and in_workspace(mf)
                        and os.path.isfile(os.path.join(root, mf))):
                    load_source(mf)
                    spans_of[mf] = test_spans(texts[mf], raws[mf])[0]
                    decls[mf] = mod_decls(texts[mf], raws[mf])
                    files.append(mf)
                    changed = True
        for rel in files:
            for at, name, chain in decls[rel]:
                if rel in test_files or any(a <= at <= b for a, b in spans_of[rel]):
                    mf = mod_target(rel, name, chain)
                    if mf and mf not in test_files and mf not in prod:
                        test_files.add(mf)
                        changed = True
    for rel in files:
        if rel in test_files:
            continue
        for at, name, chain in decls[rel]:
            mf = mod_target(rel, name, chain)
            if not any(a <= at <= b for a, b in spans_of[rel]) and (mf is None or not os.path.isfile(os.path.join(root, mf))):
                problems.append("unresolved production module (no file for `mod %s;`; the scanner cannot tell "
                                "which file it names): %s:%d"
                                % (name[1] if isinstance(name, tuple) else name, rel, texts[rel].count("\n", 0, at) + 1))
    factories = {}
    for rel in files:
        if rel not in test_files:
            factories.setdefault(crate_of(rel), set()).update(builder_factories(texts[rel], aliases(texts[rel])))
    ops, fn_index = [], {}
    for rel in files:
        if rel in test_files:
            continue
        text, ctext = texts[rel], ctexts[rel]
        forms = []
        spans, _ = test_spans(text, raws[rel], forms)
        for own, at, why in forms:
            # Inside another test-only span (a statement in `mod tests`) it hides nothing.
            if not any(a <= at <= b and a != own for a, b in spans):
                problems.append("unsupported test-only form (%s; end it with `,` / `;` or move it into a "
                                "test function): %s:%d" % (why, rel, text.count("\n", 0, at) + 1))
        for at, what in aliases(text)["unsupported"]:
            if not any(a <= at <= b for a, b in spans):
                problems.append("unsupported import (resolve it in the scanner or import by a known name): %s:%d %s"
                                % (rel, text.count("\n", 0, at) + 1, what))
        for at in generic_errs[rel]:
            if not any(a <= at <= b for a, b in spans):
                problems.append("unsupported generic arguments (unbalanced ::<..>): %s:%d"
                                % (rel, text.count("\n", 0, at) + 1))
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
            stmt = statement(ctext, parts, lits[rel])
            ops.append({
                "file": rel,
                "function": fn,
                "op": op,
                "ordinal": seen[k],
                "line": text.count("\n", 0, pos) + 1,
                "fingerprint": fingerprint(stmt),
                # Any `.create(..)` / `.create_new(..)` but a literal `false`
                # may create (`{ true }`, a variable).
                "creates": op in CREATE_OPS and (op != "OpenOptions" or re.search(r"\.(create|create_new)\((?!false\))", stmt) is not None)
                or (op in RAW_OPENS and re.search(r"O_CREAT|CREATE", stmt) is not None),
                "exclusive": op in ("File::create_new", "tempfile", "tempdir", "managed_read::copy_exclusive_new")
                or (op == "OpenOptions" and re.search(r"\.create_new\((?!false\))", stmt) is not None)
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
# methods or associated functions; explicit generic arguments
# (`helper::<T>(..)`, `m::helper::<Vec<u8>>(..)`) are calls too.
CALL_RE = re.compile(r"(?<![\w.:])((?:[a-z_]\w*::)*)([a-z_]\w*)\s*(?:::\s*<[^;{}]*?>\s*)?\(")


def stem(rel):
    base = os.path.basename(rel)[:-3]
    return os.path.basename(os.path.dirname(rel)) if base in ("mod", "lib", "main") else base


def renamed_imports(text, crate, free):
    """`use .. as` renames in one file: `{alias: (name, module or None)}` for
    an imported same-crate free function (`use crate::m::read_index as
    legacy_read`), and `{alias: module}` for a renamed module
    (`use crate::util as u`)."""
    fns, mods = {}, {}
    for path, alias, _ in use_leaves(text):
        if alias == "*" or not path or alias == path[-1]:
            continue
        hint = path[-2] if len(path) >= 2 and path[-2] not in ("crate", "self", "super") else None
        if (crate, path[-1]) in free:
            fns[alias] = (path[-1], hint)
        if path[-1] not in ("crate", "self", "super"):
            mods[alias] = path[-1]
    return fns, mods


def inline_mods(text):
    """[(name, open brace, close brace)] of every inline `mod name { .. }`."""
    return [(m.group(1), m.end() - 1, match_brace(text, m.end() - 1))
            for m in re.finditer(r"\bmod\s+([A-Za-z_]\w*)\s*\{", text)]


def resolves(rel, text, prefix, callee, target, hint=None, mods=None, owners=()):
    """Whether a call `prefix callee(` in `rel` may name `callee` in `target`:
    the same file for a bare call (or a file whose module the caller imports
    the name from), the named module for a qualified call (through a renamed
    module import too); `hint` is the module a renamed function import names.
    `owners` are the inline modules (`mod util { .. }`) around the definition:
    each is a module name of it as well as the file's (R11-S7-FIX14)."""
    names = {stem(target)} | set(owners)
    segs = [p for p in prefix.split("::") if p]
    if segs and segs[-1] not in ("self", "super", "crate"):
        return (mods or {}).get(segs[-1], segs[-1]) in names
    if segs:
        # `crate::helper(p)`, `super::helper(p)`, `self::helper(p)`: no module
        # is named, so any same-crate definition (over-reporting is safe).
        return True
    if hint is not None:
        return hint == "" or hint in names
    if target == rel:
        return True
    # Any import form: `use crate::m::leaf;`, nested braces
    # (`use crate::{m::leaf, ..}`), or a glob of the module (`use crate::m::*;`).
    for path, alias, _ in use_leaves(text):
        if alias == "*" and path and path[-1] in names:
            return True
        if len(path) >= 2 and path[-1] == callee and path[-2] in names:
            return True
    return False


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
    free, owners = {}, {}
    for rel, lst in fns.items():
        inl = inline_mods(texts[rel]) if rel in texts else []
        for a, b, qual in lst:
            if "::" not in qual:
                free.setdefault((crate_of(rel), qual), []).append((rel, a, b))
                owners[(rel, a)] = tuple(n for n, o, c in inl if o < a < c)

    renames = {}

    def callees(rel, a, b):
        text = texts[rel]
        body = text[a:b]
        if rel not in renames:
            renames[rel] = renamed_imports(text, crate_of(rel), free)
        fn_alias, mod_alias = renames[rel]
        out = []
        for m in CALL_RE.finditer(body):
            prefix, callee = m.group(1), m.group(2)
            hint = None
            if not prefix and callee in fn_alias:
                # `use crate::m::read_index as legacy_read; legacy_read(p)`.
                # A `crate::`/`self::`/`super::` path names no module: any
                # same-crate definition (over-reporting is safe).
                callee, hint = fn_alias[callee]
                hint = hint or ""
            if text[max(0, a + m.start() - 3):a + m.start()].endswith("fn "):
                continue
            for target, ta, tb in free.get((crate_of(rel), callee), []):
                # A call of the same name is followed unless it is the caller
                # itself (`other::read_index(p)` from `read_index`).
                if (target, ta) == (rel, a):
                    continue
                if resolves(rel, text, prefix, callee, target, hint, mod_alias, owners[(target, ta)]):
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
                tail = r"\b" if esc.startswith("F_") else r"\s*\("
                for m in re.finditer(r"(?<![\w])%s%s" % (re.escape(esc), tail), body):
                    line = text.count("\n", 0, a + m.start()) + 1
                    if line in lines_by_fn.get((rel, qual), set()):
                        continue
                    errs.append("raw descriptor escape %s in managed function %s (%s:%d)" % (esc, qual, rel, line))
            # Breadth-first over the call graph; `via` is the direct caller.
            queue = [(qual, callee, target, ta, tb) for callee, target, ta, tb in callees(rel, a, b)]
            visited = set()
            while queue:
                via, callee, target, ta, tb = queue.pop(0)
                # A definition is its file and offset: two `bridge`s in one
                # file (`first::bridge`, `second::bridge`) are both walked
                # (R11-S7-FIX15).
                if (target, ta) in visited:
                    continue
                visited.add((target, ta))
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
                for nxt in callees(target, ta, tb):
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
    baseline one only when the baseline has an unclaimed operation with the
    same file, function, operation and fingerprint."""
    avail = None
    if baseline_dir is not None:
        avail = baseline_ops(baseline_dir)
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
        if avail is not None:
            # Refreshed from the baseline only: each baseline operation backs
            # at most one entry with the same identity (a second copy of a
            # baseline create in the same function gets none).
            e.pop("baseline_fingerprint", None)
            ident = base_ident(o, o["fingerprint"])
            if e.get("mode_policy") == UNCHANGED and avail.get(ident, 0) > 0:
                avail[ident] -= 1
                e["baseline_fingerprint"] = o["fingerprint"]
        out.append(order(e))
    manifest["entries"] = out
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=1, sort_keys=False)
        fh.write("\n")
    return len(out)


def verify_baseline(baseline_dir, manifest):
    """The `unchanged-from-<baseline>` entries whose (file,
    baseline_fingerprint) the baseline checkout does not have, matched by
    operation identity and multiplicity (see `baseline_claims`)."""
    avail = baseline_ops(baseline_dir)
    bad = []
    for e in manifest["entries"]:
        if e.get("mode_policy") != UNCHANGED:
            continue
        ident = base_ident(e, e.get("baseline_fingerprint"))
        if avail.get(ident, 0) > 0:
            avail[ident] -= 1
        else:
            bad.append(e)
    return bad


def base_ident(o, fingerprint):
    """A create's identity across the baseline: file, function, operation and
    fingerprint (not the ordinal, which shifts when another operation is
    added before it). A copy of a baseline statement into another function
    is a different operation."""
    return (o["file"], o["function"], o["op"], fingerprint)


def baseline_ops(baseline_dir):
    """How many operations of each identity the baseline checkout has."""
    avail = {}
    for o in scan(baseline_dir)[0]:
        ident = base_ident(o, o["fingerprint"])
        avail[ident] = avail.get(ident, 0) + 1
    return avail


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


def regression_inventory_test_only_match_arm_block_does_not_hide_arms():
    """Regression (R11-S7-FIX5): a `#[cfg(test)]` match arm whose body is a
    block (`0 => { .. }`, no trailing comma) hid every arm after it."""
    root = fake({"c/src/lib.rs": (
        "fn m(p: &Path, x: u8) {\n    match x {\n        #[cfg(test)]\n"
        "        0 => {\n            let _ = std::fs::read(\"t\");\n        }\n"
        "        1 => {\n            let _ = std::fs::read(p);\n        }\n"
        "        #[cfg(test)]\n        2 => if x > 1 { () } else { () },\n"
        "        _ => { let _ = std::fs::read_to_string(p); }\n    }\n}\n"
    )})
    ops, _, _ = scan(root)
    got = sorted((o["function"], o["op"]) for o in ops)
    expect(got == [("m", "fs::read"), ("m", "fs::read_to_string")], got)


def regression_inventory_helper_walk_follows_renamed_imports():
    """Regression (R11-S7-FIX5): a managed function reaching a raw helper
    through `use crate::util::read_index as legacy_read` (or a renamed
    module, `use crate::util as u; u::read_index(p)`) was not reported: the
    walk looked the callee up by its local spelling."""
    leaf = "pub fn read_index(p: &Path) { let _ = std::fs::read(p); }\n"
    for caller in ("use crate::util::read_index as legacy_read;\nfn hash(p: &Path) { let c = ManagedReadCursor::open(p)?; legacy_read(p); }\n",
                   "use crate::util::{read_index as legacy_read};\nfn hash(p: &Path) { let c = ManagedReadCursor::open(p)?; legacy_read(p); }\n",
                   "use crate::util as u;\nfn hash(p: &Path) { let c = ManagedReadCursor::open(p)?; u::read_index(p); }\n"):
        root = fake({"c/src/lib.rs": "mod util;\n" + caller, "c/src/util.rs": leaf})
        m = classify(root, {("hash", "ManagedReadCursor::open"): MANAGED, ("read_index", "fs::read"): OOF})
        errs = check(root, m)
        expect(any("reaches helper read_index" in e for e in errs), (caller, errs))
        m = classify(root, {("hash", "ManagedReadCursor::open"): MANAGED,
                            ("read_index", "fs::read"): dict(OOF, non_mandatory_callers=["hash"])})
        expect(check(root, m) == [], (caller, check(root, m)))
    # A rename of a function in another module than the one called.
    root = fake({"c/src/lib.rs": "mod util;\nmod other;\nuse crate::other::read_index as legacy_read;\n"
                                 "fn hash(p: &Path) { let c = ManagedReadCursor::open(p)?; legacy_read(p); }\n",
                 "c/src/util.rs": leaf, "c/src/other.rs": "pub fn read_index(p: &Path) {}\n"})
    m = classify(root, {("hash", "ManagedReadCursor::open"): MANAGED, ("read_index", "fs::read"): OOF})
    expect(check(root, m) == [], check(root, m))


def regression_inventory_non_literal_create_flags_are_creates():
    """Regression (R11-S7-FIX5): only a literal `.create(true)` /
    `.create_new(true)` counted, so `.create_new({ true })` or
    `.create_new(flag)` landed without a mode policy; anything but a literal
    `false` is a (possible) create now."""
    for flag, exclusive in (("create_new({ true })", True), ("create_new(flag)", True),
                            ("create(flag)", False), ("create( true )", False)):
        root = fake({"c/src/lib.rs": "fn a(p: &Path, flag: bool) { let _ = OpenOptions::new().write(true).%s.open(p); }\n" % flag})
        ops, _, _ = scan(root)
        expect(ops[0]["creates"] and ops[0]["exclusive"] == exclusive, (flag, ops))
        m = classify(root, {("a", "OpenOptions"): {"disposition": "output-owner"}})
        expect(any("mode policy" in e for e in check(root, m)), (flag, check(root, m)))
    root = fake({"c/src/lib.rs": "fn a(p: &Path) { let _ = OpenOptions::new().write(true).create(false).create_new(false).open(p); }\n"})
    ops, _, _ = scan(root)
    expect(not ops[0]["creates"] and not ops[0]["exclusive"], ops)


def regression_inventory_records_foreign_library_openers():
    """Regression (R11-S7-FIX5): pathname opens inside foreign libraries
    (libgit2 `Repository::open`, libarchive `archive_read_open_filename`,
    lopdf `Document::load`) had no manifest entry."""
    root = fake({"c/src/lib.rs": (
        "extern \"C\" {\n    pub fn archive_read_open_filename(a: *mut A, p: *const c_char, n: usize) -> c_int;\n}\n"
        "fn g(p: &Path) { let _ = Repository::open(p); let _ = git2::Repository::discover(p); }\n"
        "fn l(a: *mut A, p: &CStr) { let _ = unsafe { archive_read_open_filename(a, p.as_ptr(), 10240) }; }\n"
        "fn d(p: &Path) { let _ = Document::load(p); let _ = Document::load_mem(&[]); }\n"
    )})
    ops, _, _ = scan(root)
    got = sorted((o["function"], o["op"]) for o in ops)
    expect(got == [("d", "lopdf::Document::load"), ("g", "git2::Repository::discover"), ("g", "git2::Repository::open"),
                   ("l", "libarchive::archive_read_open_filename")], got)
    errs = check(root, classify(root, {}))
    expect(sum("unclassified" in e for e in errs) == 4, errs)


def regression_inventory_chained_aliases_resolve():
    """Regression (R11-S7-FIX9): `use std::fs as disk; use disk::read as
    read_index;` (an import through an aliased module) hid `read_index(p)`:
    zero operations, an empty manifest passed."""
    root = fake({"c/src/lib.rs": (
        "use std::fs as disk;\nuse disk::read as read_index;\nuse disk::{File as Raw};\n"
        "use std as s;\nuse s::fs::read_to_string as rts;\n"
        "fn a(p: &Path) { let _ = read_index(p); }\n"
        "fn b(p: &Path) { let _ = Raw::open(p); }\n"
        "fn c(p: &Path) { let _ = rts(p); }\n"
    )})
    errs = []
    ops, _, _ = scan(root, errs)
    got = sorted((o["function"], o["op"]) for o in ops)
    expect(got == [("a", "fs::read"), ("b", "File::open"), ("c", "fs::read_to_string")], got)
    expect(errs == [], errs)
    errs = check(root, {"entries": []})
    expect(sum("new operation" in e for e in errs) == 3, errs)
    root = fake({"c/src/lib.rs": "use std::fs as disk;\nuse disk::*;\nfn a() {}\n"})
    expect(any("unsupported import" in e for e in check(root, {"entries": []})), "glob through an alias")


def regression_inventory_generic_arguments_are_calls():
    """Regression (R11-S7-FIX9): explicit generic arguments
    (`std::fs::read::<_>(p)`, `File::open::<_>(p)`) and the qualified form
    `<File>::open(p)` hid the call."""
    root = fake({"c/src/lib.rs": (
        "fn a(p: &Path) { let _ = std::fs::read::<_>(p); }\n"
        "fn b(p: &Path) { let _ = File::open::<&Path>(p); }\n"
        "fn c(p: &Path) { let _ = <std::fs::File>::open(p); let _ = <File>::create(p); }\n"
        "fn d(p: &Path) { let _ = fs::read_to_string::<Vec<u8>>(p); }\n"
    )})
    ops, _, _ = scan(root)
    got = sorted((o["function"], o["op"]) for o in ops)
    expect(got == [("a", "fs::read"), ("b", "File::open"), ("c", "File::create"), ("c", "File::open"),
                   ("d", "fs::read_to_string")], got)


def regression_inventory_fingerprint_keeps_literal_whitespace():
    """Regression (R11-S7-FIX9): fingerprints dropped whitespace inside
    string literals, so `"cache index.sqlite"` -> `"cacheindex.sqlite"` kept
    the entry; whitespace outside literals (rustfmt) still does not count."""
    src = "fn a(p: &Path) { let _ = std::fs::read(p.join(\"cache index.sqlite\")); }\n"
    root = fake({"c/src/lib.rs": src})
    m = classify(root, {("a", "fs::read"): OOF})
    for changed in (src.replace("cache index", "cacheindex"), src.replace("cache index", "cache\tindex")):
        with open(os.path.join(root, "c/src/lib.rs"), "w") as fh:
            fh.write(changed)
        expect(any("changed operation" in e for e in check(root, m)), changed)
    with open(os.path.join(root, "c/src/lib.rs"), "w") as fh:
        fh.write(src.replace("read(p.join(", "read(  p.join( "))
    expect(check(root, m) == [], check(root, m))


def regression_inventory_helper_walk_follows_braced_and_glob_imports():
    """Regression (R11-S7-FIX9): a managed function reaching a raw helper
    imported through nested braces (`use crate::{util::leaf, ..}`) or a glob
    (`use crate::util::*;`) was not reported."""
    for imp in ("use crate::{util::leaf, other};\n", "use crate::util::*;\n", "use crate::{util::{leaf}};\n"):
        root = fake({
            "c/src/lib.rs": "mod util;\n" + imp + "fn hash(p: &Path) { let c = ManagedReadCursor::open(p)?; leaf(p); }\n",
            "c/src/util.rs": "pub fn leaf(p: &Path) { let _ = std::fs::read(p); }\n",
        })
        m = classify(root, {("hash", "ManagedReadCursor::open"): MANAGED, ("leaf", "fs::read"): OOF})
        errs = check(root, m)
        expect(any("reaches helper leaf" in e for e in errs), (imp, errs))


def regression_inventory_tempdir_builders_are_creates():
    """Regression (R11-S7-FIX9): `TempDir::with_prefix(..)` (and the
    `NamedTempFile`/`TempDir` `with_prefix`/`with_suffix` constructors) had no
    inventory entry."""
    root = fake({"c/src/lib.rs": (
        "fn a() { let _ = tempfile::TempDir::with_prefix(\"x\"); let _ = TempDir::with_prefix_in(\"x\", \"/d\"); }\n"
        "fn b() { let _ = NamedTempFile::with_prefix(\"y\"); let _ = NamedTempFile::with_suffix_in(\"y\", \"/d\"); }\n"
    )})
    ops, _, _ = scan(root)
    got = sorted((o["function"], o["op"], o["creates"], o["exclusive"]) for o in ops)
    expect(got == [("a", "tempdir", True, True)] * 2 + [("b", "tempfile", True, True)] * 2, got)


def regression_inventory_generic_helper_calls_are_followed():
    """Regression (R11-S7-FIX10): the helper walk missed a call with explicit
    generic arguments (`load::<Config>(p)`, `util::load::<Vec<u8>>(p)`), so a
    managed function reaching a raw-reading helper that way passed with an
    unchanged manifest while the non-generic call failed."""
    for call in ("load::<Config>(p)", "util::load::<Vec<u8>>(p)", "load :: < Config > (p)"):
        root = fake({
            "c/src/lib.rs": ("mod util;\nuse crate::util::load;\n"
                             "fn hash(p: &Path) { let c = ManagedReadCursor::open(p)?; let _ = %s; }\n" % call),
            "c/src/util.rs": "pub fn load<T>(p: &Path) -> T { let _ = std::fs::read(p); todo!() }\n",
        })
        m = classify(root, {("hash", "ManagedReadCursor::open"): MANAGED, ("load", "fs::read"): OOF})
        errs = check(root, m)
        expect(any("reaches helper load" in e for e in errs), (call, errs))


def regression_inventory_baseline_claims_match_identity_and_multiplicity():
    """Regression (R11-S7-FIX10): `unchanged-from-<baseline>` was matched on
    (file, fingerprint) only, so an identical create copied into a new
    function (or a second copy in the same function) inherited the baseline
    exemption from `--write --baseline` and passed `--verify-baseline`."""
    stmt = "let _ = std::fs::File::create(p);"
    base = fake({"c/src/lib.rs": "fn a(p: &Path) {\n    %s\n}\n" % stmt})
    cur = fake({"c/src/lib.rs": "fn a(p: &Path) {\n    %s\n    %s\n}\nfn b(p: &Path) {\n    %s\n}\n"
                                % (stmt, stmt, stmt)})
    path = os.path.join(cur, "manifest.json")
    unchanged = {"disposition": "output-owner", "mode_policy": UNCHANGED}
    m = classify(cur, {("a", "File::create"): unchanged, ("b", "File::create"): unchanged})
    expect(len({e["fingerprint"] for e in m["entries"]}) == 1 and len(m["entries"]) == 3, m["entries"])
    with open(path, "w") as fh:
        json.dump(m, fh)
    write(cur, path, base)
    m = load(path)
    have = sorted((e["function"], e["ordinal"], e.get("baseline_fingerprint") is not None) for e in m["entries"])
    expect(have == [("a", 1, True), ("a", 2, False), ("b", 1, False)], have)
    errs = check(cur, m)
    expect(len(errs) == 2 and all("valid only for an unchanged baseline" in e for e in errs), errs)
    # A hand-copied claim on every entry: `--verify-baseline` rejects the
    # copies beyond the baseline's one operation.
    for e in m["entries"]:
        e["baseline_fingerprint"] = e["fingerprint"]
    bad = sorted((e["function"], e["ordinal"]) for e in verify_baseline(base, m))
    expect(bad == [("a", 2), ("b", 1)], bad)
    # The baseline's own operation still verifies.
    m["entries"] = [e for e in m["entries"] if (e["function"], e["ordinal"]) == ("a", 1)]
    expect(verify_baseline(base, m) == [], verify_baseline(base, m))


def regression_inventory_helper_walk_follows_crate_super_and_same_name_calls():
    """Regression (R11-S7-FIX12): the helper walk did not follow
    `crate::helper(p)` or `super::helper(p)` to a helper in another file
    (no import names its module), and skipped every call whose name equals
    the caller's (`util::read_index(p)` from `read_index`), so a managed
    function reached a raw-reading helper with an unchanged manifest."""
    cases = [
        ("helper", {
            "c/src/lib.rs": "mod a;\npub fn helper(p: &Path) { let _ = std::fs::read(p); }\n",
            "c/src/a.rs": "fn hash(p: &Path) { let c = ManagedReadCursor::open(p)?; crate::helper(p); }\n",
        }),
        ("helper", {
            "c/src/lib.rs": "mod a;\n",
            "c/src/a.rs": "mod b;\npub fn helper(p: &Path) { let _ = std::fs::read(p); }\n",
            "c/src/a/b.rs": "fn hash(p: &Path) { let c = ManagedReadCursor::open(p)?; super::helper(p); }\n",
        }),
        ("read_index", {
            "c/src/lib.rs": ("mod util;\nfn read_index(p: &Path) { let c = ManagedReadCursor::open(p)?;"
                             " util::read_index(p); }\n"),
            "c/src/util.rs": "pub fn read_index(p: &Path) { let _ = std::fs::read(p); }\n",
        }),
    ]
    for name, files in cases:
        root = fake(files)
        managed = "read_index" if name == "read_index" else "hash"
        m = classify(root, {(managed, "ManagedReadCursor::open"): MANAGED, (name, "fs::read"): OOF})
        errs = check(root, m)
        expect(any("reaches helper %s" % name in e for e in errs), (files, errs))
    # A function's call of itself is not a helper.
    root = fake({"c/src/lib.rs": "fn walk(p: &Path) { let c = ManagedReadCursor::open(p)?; walk(p); }\n"})
    m = classify(root, {("walk", "ManagedReadCursor::open"): MANAGED})
    expect(check(root, m) == [], check(root, m))


def regression_inventory_test_only_block_like_match_arms_do_not_hide_arms():
    """Regression (R11-S7-FIX12): a `#[cfg(test)]` match arm whose body is a
    block-like expression other than a bare block (`unsafe { .. }`, `loop`,
    `match`, an `if`/`else` chain) needs no trailing comma, and the scanner
    hid the production arm after it."""
    for body in ("unsafe { t() }", "loop { break }", "match x { _ => () }",
                 "if x > 1 { () } else { () }", "if x > 1 { () } else if x > 2 { () } else { () }",
                 "'outer: loop { break 'outer }", "unsafe { t() }.min(1),"):
        root = fake({"c/src/lib.rs": (
            "fn m(p: &Path, x: u8) {\n    match x {\n        #[cfg(test)]\n"
            "        0 => %s\n"
            "        1 => {\n            let _ = std::fs::read(p);\n        }\n"
            "        _ => (),\n    }\n}\n" % body
        )})
        ops, _, _ = scan(root)
        got = [(o["function"], o["op"]) for o in ops]
        expect(got == [("m", "fs::read")], (body, got))


def regression_inventory_descriptor_duplication_and_conversion_are_operations():
    """Regression (R11-S7-FIX12): `try_clone_to_owned`, `libc::dup`/`dup2`,
    `fcntl(.., F_DUPFD[_CLOEXEC], ..)` and `File::from(OwnedFd)` duplicate or
    take ownership of a descriptor (its close releases this process's locks
    on the file) but were no operations, so three production sites were
    missing from the inventory."""
    root = fake({"c/src/lib.rs": (
        "fn d(fd: i32) {\n"
        "    let o = unsafe { BorrowedFd::borrow_raw(fd) }.try_clone_to_owned()?;\n"
        "    let f = std::fs::File::from(o);\n"
        "    let a = unsafe { libc::dup(1) };\n"
        "    unsafe { libc::dup2(a, 1) };\n"
        "    let b = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };\n"
        "    let c = unsafe { libc::fcntl(fd, libc::F_DUPFD, 0) };\n"
        "    let g = File::from(c);\n}\n"
    )})
    ops, _, _ = scan(root)
    got = sorted((o["op"], o["ordinal"]) for o in ops)
    want = sorted([("try_clone_to_owned", 1), ("File::from", 1), ("File::from", 2), ("dup", 1),
                   ("dup2", 1), ("F_DUPFD_CLOEXEC", 1), ("F_DUPFD", 1)])
    expect(got == want, got)
    m = classify(root, {})
    errs = check(root, m)
    expect(sum("unclassified operation" in e for e in errs) == len(want), errs)


def regression_inventory_const_generic_helper_calls_are_followed():
    """Regression (R11-S7-FIX12): the generic-argument pattern excluded
    braces, so `load::<{ 64 * 1024 }>(p)` reached a raw-reading helper with
    an unchanged manifest while `load::<65536>(p)` failed. Generic argument
    lists are matched balanced (`{ N > 3 }`, `fn() -> T`); an unbalanced one
    is reported."""
    for call in ("load::<{ 64 * 1024 }>(p)", "load::<{ N > 3 }, Vec<u8>>(p)",
                 "util::load::<fn() -> u8>(p)", "load::<65536>(p)"):
        root = fake({
            "c/src/lib.rs": ("mod util;\nuse crate::util::load;\n"
                             "fn hash(p: &Path) { let c = ManagedReadCursor::open(p)?; let _ = %s; }\n" % call),
            "c/src/util.rs": "pub fn load<const N: usize>(p: &Path) { let _ = std::fs::read(p); }\n",
        })
        m = classify(root, {("hash", "ManagedReadCursor::open"): MANAGED, ("load", "fs::read"): OOF})
        errs = check(root, m)
        expect(any("reaches helper load" in e for e in errs), (call, errs))
    root = fake({"c/src/lib.rs": "fn f(p: &Path) { let _ = std::fs::read::<{ 1 }>(p); }\n"})
    ops, _, _ = scan(root)
    expect([o["op"] for o in ops] == ["fs::read"], ops)
    root = fake({"c/src/lib.rs": "fn f(p: &Path) { let _ = load::<Vec<u8>(p); }\n"})
    errs = check(root, classify(root, {}))
    expect(any("unsupported generic arguments" in e for e in errs), errs)



def regression_inventory_test_only_if_else_arm_with_nested_arrow_does_not_hide_arms():
    """Regression (R11-S7-FIX14): after the `else` of a test-only `if` arm
    the scanner re-tested its arm-body pattern, whose `if` form cannot cross
    a `=>`, so a `match` inside an earlier branch made the production arm
    after the chain part of the test-only span. Labeled bare blocks,
    `const { .. }` and `async { .. }` bodies (statements too) end where they
    close."""
    for body in ("if x > 1 { match x { _ => () } } else { () }",
                 "if x > 1 { match x { _ => () } } else if x > 2 { () } else { () }",
                 "if x > 1 { () } else if x > 2 { match x { _ => () } } else { () }",
                 "if x > 1 { () } else { match x { _ => () } }",
                 "'a: { () }", "const { 1 }", "async move { () }"):
        root = fake({"c/src/lib.rs": (
            "fn m(p: &Path, x: u8) {\n    match x {\n        #[cfg(test)]\n"
            "        0 => %s\n"
            "        1 => {\n            let _ = std::fs::read(p);\n        }\n"
            "        _ => (),\n    }\n}\n" % body
        )})
        ops, _, _ = scan(root)
        got = [(o["function"], o["op"]) for o in ops]
        expect(got == [("m", "fs::read")], (body, got))
        errs = check(root, classify(root, {("m", "fs::read"): OOF}))
        expect(errs == [], (body, errs))
    for stmt in ("'l: loop { break 'l }", "'a: { t() }", "async { t() }"):
        root = fake({"c/src/lib.rs": (
            "fn s(p: &Path) {\n    #[cfg(test)]\n    %s\n    let _ = std::fs::read(p);\n}\n" % stmt)})
        ops, _, _ = scan(root)
        expect([o["op"] for o in ops] == ["fs::read"], (stmt, ops))


def regression_inventory_unknown_test_only_form_fails_closed():
    """Regression (R11-S7-FIX14): a test-only statement or arm in a form the
    span rules do not know swallowed the code after it silently; a span
    holding a second top-level `=>`, or code after a closed top-level block,
    is reported instead. A `#[cfg(test)] macro_rules!` is an item (it hid
    the `#[cfg(not(test))]` definition after it)."""
    arm = ("fn m(p: &Path, x: u8) {\n    match x {\n        #[cfg(test)]\n"
           "        0 => try { t() }\n        1 => { let _ = std::fs::read(p); }\n        _ => (),\n    }\n}\n")
    stmt = "fn s(p: &Path) {\n    #[cfg(test)]\n    try { t() }\n    let _ = std::fs::read(p);\n}\n"
    arms = ("fn m(p: &Path, x: u8) {\n    match x {\n        #[cfg(test)]\n"
            "        0 => t()\n        1 => { let _ = std::fs::read(p); }\n        _ => (),\n    }\n}\n")
    for src, why in ((arm, "code after a closed block"), (arms, "a second match arm"),
                     (stmt, "code after a closed block")):
        root = fake({"c/src/lib.rs": src})
        errs = check(root, classify(root, {}))
        expect(any("unsupported test-only form (%s" % why in e for e in errs), (src, errs))
    # Inside a test module it hides nothing.
    root = fake({"c/src/lib.rs": "#[cfg(test)]\nmod tests {\n    fn t() {\n" + stmt.split("\n", 1)[1] + "}\n"})
    expect(check(root, classify(root, {})) == [], check(root, classify(root, {})))
    root = fake({"c/src/lib.rs": (
        "#[cfg(test)]\nmacro_rules! st {\n    ($s:expr) => {\n        $s.t()\n    };\n}\n"
        "#[cfg(not(test))]\nmacro_rules! st {\n    ($s:expr) => {\n        std::fs::read($s)\n    };\n}\n")})
    ops, _, _ = scan(root)
    expect([o["op"] for o in ops] == ["fs::read"], ops)


def regression_inventory_open_options_default_is_a_builder():
    """Regression (R11-S7-FIX14): `OpenOptions::default()` built a std
    builder the scanner did not recognize, so a read or an exclusive create
    through it was no operation at all. A bare `OpenOptions` is std's only
    when imported from it (`ratarmount_core::OpenOptions::default()` is a
    mount option set)."""
    for src, exclusive in (
            ("fn a(p: &Path) { let _ = std::fs::OpenOptions::default().read(true).open(p); }\n", False),
            ("fn a(p: &Path) { let _ = std::fs::OpenOptions::default().write(true).create_new(true).open(p); }\n", True),
            ("use std::fs::OpenOptions;\nfn a(p: &Path) { let _ = OpenOptions::default().read(true).open(p); }\n", False),
            ("use std::fs;\nfn a(p: &Path) { let _ = fs::OpenOptions::default().write(true).create_new(true).open(p); }\n", True)):
        root = fake({"c/src/lib.rs": src})
        ops, _, _ = scan(root)
        expect([(o["op"], o["exclusive"]) for o in ops] == [("OpenOptions", exclusive)], (src, ops))
        errs = check(root, classify(root, {}))
        expect(any("unclassified" in e for e in errs), (src, errs))
        if exclusive:
            errs = check(root, classify(root, {("a", "OpenOptions"): OOF}))
            expect(any("create without a mode policy" in e for e in errs), (src, errs))
    root = fake({"c/src/lib.rs": ("use ratarmount_core::OpenOptions;\n"
                                  "fn a() -> OpenOptions { OpenOptions { x: 1, ..OpenOptions::default() } }\n"
                                  "fn b() { let _ = f(&OpenOptions::default()); }\n"
                                  "fn c() { let _ = ratarmount_core::OpenOptions::default(); }\n")})
    ops, _, _ = scan(root)
    expect(ops == [], ops)


def regression_inventory_helper_walk_follows_inline_modules():
    """Regression (R11-S7-FIX14): a qualified call resolved only against the
    defining file's module name, so `util::load(p)` from a managed function
    reached a raw-reading helper in an inline `mod util { .. }` with an
    unchanged manifest (an unqualified `load(p)` was reported)."""
    leaf = "mod util {\n    pub fn load(p: &Path) { let _ = std::fs::read(p); }\n}\n"
    nested = "mod a {\n    pub mod util {\n        pub fn load(p: &Path) { let _ = std::fs::read(p); }\n    }\n}\n"
    for files in (
            {"c/src/lib.rs": leaf + "fn hash(p: &Path) { let c = ManagedReadCursor::open(p)?; util::load(p); }\n"},
            {"c/src/lib.rs": leaf + "use self::util as u;\nfn hash(p: &Path) { let c = ManagedReadCursor::open(p)?; u::load(p); }\n"},
            {"c/src/lib.rs": leaf + "use crate::util::load;\nfn hash(p: &Path) { let c = ManagedReadCursor::open(p)?; load(p); }\n"},
            {"c/src/lib.rs": "mod h;\n" + nested, "c/src/h.rs": "fn hash(p: &Path) { let c = ManagedReadCursor::open(p)?; crate::a::util::load(p); }\n"},
            {"c/src/lib.rs": "mod h;\n" + nested, "c/src/h.rs": "use crate::a::util::load;\nfn hash(p: &Path) { let c = ManagedReadCursor::open(p)?; load(p); }\n"},
            # Control: an unqualified call in the same file.
            {"c/src/lib.rs": leaf + "fn hash(p: &Path) { let c = ManagedReadCursor::open(p)?; load(p); }\n"}):
        root = fake(files)
        m = classify(root, {("hash", "ManagedReadCursor::open"): MANAGED, ("load", "fs::read"): OOF})
        errs = check(root, m)
        expect(any("reaches helper load" in e for e in errs), (files, errs))
        m = classify(root, {("hash", "ManagedReadCursor::open"): MANAGED,
                            ("load", "fs::read"): dict(OOF, non_mandatory_callers=["hash"])})
        expect(check(root, m) == [], (files, check(root, m)))
    # Another module's function of the same name is not this helper.
    root = fake({"c/src/lib.rs": leaf + "mod other;\nfn hash(p: &Path) { let c = ManagedReadCursor::open(p)?; other::load(p); }\n",
                 "c/src/other.rs": "pub fn load(p: &Path) {}\n"})
    m = classify(root, {("hash", "ManagedReadCursor::open"): MANAGED, ("load", "fs::read"): OOF})
    expect(check(root, m) == [], check(root, m))

def regression_inventory_production_module_shared_with_test_module_is_scanned():
    """Regression (R11-S7-FIX15): every file a test-only `mod` declaration
    names was excluded, so `#[cfg(test)] #[path = "util.rs"] mod test_util;
    mod util;` hid the production reads in `util.rs` (zero operations, an
    empty manifest passed)."""
    util = {"c/src/util.rs": "pub fn load(p: &Path) { let _ = std::fs::read(p); }\n"}
    for lib in ('#[cfg(test)]\n#[path = "util.rs"]\nmod test_util;\nmod util;\n',
                'mod util;\n#[cfg(test)]\n#[path = "util.rs"]\nmod test_util;\n',
                '#[cfg(test)]\nmod util;\n#[path = "util.rs"]\nmod prod_util;\n'):
        root = fake(dict(util, **{"c/src/lib.rs": lib}))
        ops, _, _ = scan(root)
        expect([(o["file"], o["function"]) for o in ops] == [("c/src/util.rs", "load")], (lib, ops))
        expect(check(root, {"baseline": BASELINE, "entries": []}) != [], lib)
    # Control: a file named only by test-only declarations stays excluded.
    root = fake(dict(util, **{"c/src/lib.rs": '#[cfg(test)]\n#[path = "util.rs"]\nmod test_util;\n'}))
    expect(scan(root)[0] == [], scan(root)[0])


def regression_inventory_modules_inside_inline_modules_resolve_below_them():
    """Regression (R11-S7-FIX16): a `mod util;` inside `mod outer { .. }`
    resolved as if it were at the top of its file, so a test-only alias
    `#[path = "outer/util.rs"]` excluded the production file `outer/util.rs`
    (zero operations, an empty manifest passed). A production declaration
    that names no file now fails closed."""
    read = "pub fn load(p: &Path) { let _ = std::fs::read(p); }\n"
    alias = '#[cfg(test)]\n#[path = "outer/util.rs"]\nmod test_util;\n'
    for files, util in (
            ({"c/src/lib.rs": "mod outer {\n    pub mod util;\n}\n" + alias}, "c/src/outer/util.rs"),
            ({"c/src/lib.rs": "mod outer {\n    pub mod util;\n}\n" + alias.replace("outer/util.rs", "outer/util/mod.rs")},
             "c/src/outer/util/mod.rs"),
            ({"c/src/lib.rs": "mod a;\n", "c/src/a.rs": "mod outer {\n    mod inner {\n        pub mod util;\n    }\n}\n"
              + alias.replace("outer/util.rs", "a/outer/inner/util.rs")}, "c/src/a/outer/inner/util.rs"),
            ({"c/src/lib.rs": 'mod outer {\n    #[path = "x.rs"]\n    pub mod util;\n}\n'
              + alias.replace("outer/util.rs", "outer/x.rs")}, "c/src/outer/x.rs")):
        root = fake(dict(files, **{util: read}))
        problems = []
        ops, _, _ = scan(root, problems)
        expect([(o["file"], o["function"]) for o in ops] == [(util, "load")], (files, ops, problems))
        expect(problems == [], (files, problems))
        expect(check(root, {"baseline": BASELINE, "entries": []}) != [], files)
    # Control: a test-only declaration inside an inline module stays excluded.
    root = fake({"c/src/lib.rs": "mod outer {\n    #[cfg(test)]\n    mod t;\n}\n", "c/src/outer/t.rs": read})
    expect(scan(root)[0] == [], scan(root)[0])
    # A production declaration the scanner cannot resolve fails closed.
    root = fake({"c/src/lib.rs": "mod outer {\n    pub mod util;\n}\n" + alias, "c/src/util.rs": read})
    errs = check(root, classify(root, {}))
    expect(any("unresolved production module (no file for `mod util;`" in e for e in errs), errs)


def regression_inventory_production_module_under_skipped_dir_is_scanned():
    """Regression (#197): the walk skipped `tests` / `benches` / `examples`
    before resolving module targets, so a production
    `#[path = "tests/reader.rs"] mod reader;` that contains `std::fs::read`
    dropped out (zero operations, an empty manifest passed). The resolved
    file is scanned, including a module it declares and a `#[path]` inside
    an inline module. A test-only declaration, a file nobody declares, and
    a test-only child stay out; a missing file still fails closed."""
    read = "pub fn load(p: &Path) { let _ = std::fs::read(p); }\n"
    hidden = ("#[cfg(test)]\nmod tests {\n    fn t(p: &Path) { let _ = std::fs::read(p); }\n}\n")
    for dirname in ("tests", "benches", "examples"):
        rel = "c/src/%s/reader.rs" % dirname
        root = fake({
            "c/src/lib.rs": '#[path = "%s/reader.rs"]\nmod reader;\n' % dirname,
            rel: read + hidden,
        })
        problems = []
        ops, _, _ = scan(root, problems)
        expect([(o["file"], o["function"], o["op"]) for o in ops] == [(rel, "load", "fs::read")],
               (dirname, ops, problems))
        expect(problems == [], (dirname, problems))
        expect(check(root, {"baseline": BASELINE, "entries": []}) != [], dirname)
    # A module declared from the skipped file, and `mod.rs`.
    root = fake({
        "c/src/lib.rs": '#[path = "tests/reader/mod.rs"]\nmod reader;\n',
        "c/src/tests/reader/mod.rs": "mod helper;\n" + hidden,
        "c/src/tests/reader/helper.rs": read,
    })
    problems = []
    ops, _, _ = scan(root, problems)
    expect([(o["file"], o["function"]) for o in ops] == [("c/src/tests/reader/helper.rs", "load")],
           (ops, problems))
    expect(problems == [], problems)
    expect(check(root, {"entries": []}) != [], ops)
    # `#[path]` inside an inline module, and a path that leaves `src/`.
    for files, util in (
            ({"c/src/lib.rs": 'mod outer {\n    #[path = "tests/reader.rs"]\n    pub mod reader;\n}\n',
              "c/src/outer/tests/reader.rs": read}, "c/src/outer/tests/reader.rs"),
            ({"c/src/lib.rs": '#[path = "../benches/reader.rs"]\nmod reader;\n',
              "c/benches/reader.rs": read}, "c/benches/reader.rs"),
            ({"c/src/lib.rs": ('#[cfg(test)]\n#[path = "examples/reader.rs"]\nmod test_reader;\n'
                               '#[path = "examples/reader.rs"]\nmod reader;\n'),
              "c/src/examples/reader.rs": read}, "c/src/examples/reader.rs")):
        root = fake(files)
        problems = []
        ops, _, _ = scan(root, problems)
        expect([(o["file"], o["function"]) for o in ops] == [(util, "load")], (files, ops, problems))
        expect(problems == [], (files, problems))
        expect(check(root, {"entries": []}) != [], files)
    # A test-only child file under the skipped directory is not scanned.
    root = fake({
        "c/src/lib.rs": '#[path = "tests/reader.rs"]\nmod reader;\n',
        "c/src/tests/reader.rs": "#[cfg(test)]\nmod helper;\n" + read,
        "c/src/tests/reader/helper.rs": "pub fn extra(p: &Path) { let _ = std::fs::read(p); }\n",
    })
    ops, _, _ = scan(root)
    expect([(o["file"], o["function"]) for o in ops] == [("c/src/tests/reader.rs", "load")], ops)
    # Controls: test-only `#[path]`, an undeclared file, a missing file.
    root = fake({"c/src/lib.rs": '#[cfg(test)]\n#[path = "tests/reader.rs"]\nmod reader;\n',
                 "c/src/tests/reader.rs": read})
    problems = []
    ops, _, _ = scan(root, problems)
    expect(ops == [] and problems == [], (ops, problems))
    expect(check(root, {"entries": []}) == [], check(root, {"entries": []}))
    root = fake({"c/src/lib.rs": "fn a() {}\n", "c/src/tests/reader.rs": read,
                 "c/benches/other.rs": read, "c/examples/other.rs": read})
    expect(scan(root)[0] == [], scan(root)[0])
    root = fake({"c/src/lib.rs": '#[path = "tests/missing.rs"]\nmod reader;\n'})
    errs = check(root, {"entries": []})
    expect(any("unresolved production module (no file for `mod tests/missing.rs;`" in e for e in errs), errs)


def regression_inventory_helper_walk_visits_same_named_helpers_by_definition():
    """Regression (R11-S7-FIX15): the helper walk marked a function visited by
    file and name, so visiting an empty `first::bridge` skipped
    `second::bridge` in the same file, which reaches a raw-reading helper."""
    root = fake({"c/src/lib.rs": (
        "mod first {\n    pub fn bridge(p: &Path) {}\n}\n"
        "mod second {\n    pub fn bridge(p: &Path) { crate::leaf(p); }\n}\n"
        "pub fn leaf(p: &Path) { let _ = std::fs::read(p); }\n"
        "fn hash(p: &Path) { let c = ManagedReadCursor::open(p)?; first::bridge(p); second::bridge(p); }\n")})
    m = classify(root, {("hash", "ManagedReadCursor::open"): MANAGED, ("leaf", "fs::read"): OOF})
    errs = check(root, m)
    expect(any("reaches helper leaf via bridge" in e for e in errs), errs)
    m = classify(root, {("hash", "ManagedReadCursor::open"): MANAGED,
                        ("leaf", "fs::read"): dict(OOF, non_mandatory_callers=["bridge"])})
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
