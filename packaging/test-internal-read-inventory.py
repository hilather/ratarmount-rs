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
`use .. as` renames of a function or a module, including a chain
(`use crate::util as u; use u::load as read_index`), `crate::`/`super::`/`self::`
paths (any same-crate definition) and calls of the caller's own name in
another module. Main's helper resolver runs unchanged; a separate alias-chain
pass adds reports, and their union preserves every report from main. In the
extra pass, only the first segment of a relative path expands through aliases;
rooted paths keep their roots. Cycles, unknown targets, and ambiguous or
unsupported scoped bindings fail closed. Every production `pub use` (including
restricted visibility) must be reviewed in
`packaging/internal-read-reexport-allowlist.json`; a tokenized use-tree and its
repo-relative file identify each entry. Cfg exclusion uses comment-stripped
tokens, retaining literal values. Any `use` inside a macro invocation payload
or macro_rules body requires the same allowlist review, regardless of visibility;
the gate does not expand macros. Missing, stale and duplicate entries fail
closed, even when the extra pass could resolve the re-export.
Generic argument lists (`::<..>`) are matched balanced; an unbalanced one is
reported. Descriptor duplication and ownership conversion
(`try_clone_to_owned`, `dup`/`dup2`/`dup3`, `F_DUPFD[_CLOEXEC]`, `File::from`)
are operations.
Pathname opens inside foreign libraries (libgit2 `Repository::open`,
libarchive `archive_read_open_filename`, lopdf `Document::load`) are
operations of their own.

Known limits: a renamed crate root (`use std as s`), helper paths through
allowlisted re-exports, openers of other crates (`nix`) and
foreign openers not listed above, method and cross-crate calls in the helper walk.

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
REEXPORT_ALLOWLIST = "packaging/internal-read-reexport-allowlist.json"

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
    for rel in files:
        with open(os.path.join(root, rel), encoding="utf-8", errors="replace") as fh:
            raws[rel] = fh.read()
            texts[rel], generic_errs[rel] = blank_generics(mask(raws[rel]))
            ctexts[rel] = mask(raws[rel], strings=False)
            lits[rel] = mask(raws[rel], lit_fill="\0")
    # Files that are test-only modules (and everything below them). A file
    # that a production `mod` declaration also names is production code
    # (`#[cfg(test)] #[path = "util.rs"] mod t; mod util;`, R11-S7-FIX15).
    # Declarations inside inline modules resolve below them (`mod outer {
    # pub mod util; }` is `outer/util.rs`), and a production declaration
    # that resolves to no file fails closed (R11-S7-FIX16).
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
                if not any(a <= at <= b for a, b in spans_of[rel]):
                    prod.add(mod_target(rel, name, chain))
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
    errors.extend(reexport_errors(root))
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
    errors.extend(union_helper_errors(entries, scanned, texts, fns))
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


# Separate #198 pass. Main resolution above is intentionally kept verbatim.


def chain_use_leaves(text, preserve_roots=False):
    """Every `use` declaration flattened to (path segments, local name) with
    its offset; `*` leaves have local name `*`. Helper resolution preserves
    initial `self` and an empty segment for leading `::` when requested."""
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
                    if preserve_roots and not path:
                        path = [""]
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
                if t == "self" and (path or not preserve_roots):
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


PATH_ROOTS = ("", "crate", "self", "super")


class ChainBindings(dict):
    """Extra-pass aliases only. Never change main's resolver or its reports.

    The chain pass cannot model Rust lexical visibility. Refuse
    an attempted expansion if its binding is ambiguous or outside file scope;
    keep test-only bindings as ambiguity evidence, rather than letting them
    redirect a production call. Failures are collected even for excused reads.
    """

    def __init__(self, text, crate, free):
        super().__init__()
        self.bad = []
        leaves = chain_use_leaves(text, preserve_roots=True)
        declarations = [(m.group(1), m.start()) for m in
                        re.finditer(r"\bmod\s+([A-Za-z_]\w*)\s*[;{]", text)]
        self.known = {stem(rel) for (c, _), defs in free.items() if c == crate
                      for rel, _, _ in defs}
        self.known.update(name for c, name in free if c == crate)
        self.known.update(name for name, _ in declarations)
        # A scope is its stack of opening braces; import-tree braces are
        # harmless because the `use` offset precedes them.
        positions = sorted({at for _, _, at in leaves} | {at for _, at in declarations}, reverse=True)
        scopes, stack = {}, []
        for m in re.finditer(r"[{}]", text):
            while positions and positions[-1] < m.start():
                scopes[positions.pop()] = tuple(stack)
            if m.group() == "{":
                stack.append(m.start())
            elif stack:
                stack.pop()
        for at in positions:
            scopes[at] = tuple(stack)
        # Cfg-distinct imports may share braces. A test-only item is still a
        # separate binding context, and no binding may silently win by order.
        test_ranges, _ = test_spans(text, text)
        for at in scopes:
            if any(a <= at <= b for a, b in test_ranges):
                scopes[at] += ("test-only",)
        self.scopes = {}
        self.targets = {}
        for name, at in declarations + [(alias, at) for _, alias, at in leaves if alias != "*"]:
            self.scopes.setdefault(name, set()).add(scopes[at])
        for path, alias, _ in leaves:
            self.targets.setdefault(alias, set()).add(tuple(path))
            if path and alias not in ("*", "_", path[-1]):
                self[alias] = path

    def refuse(self, name, reason):
        self.bad.append((name, reason))
        return None

    def resolve(self, path):
        seen = set()
        while path and path[0] not in PATH_ROOTS and path[0] in self:
            name = path[0]
            scopes = self.scopes[name]
            if len(scopes) > 1:
                return self.refuse(name, "alias name is bound in more than one scope")
            if len(self.targets[name]) > 1:
                return self.refuse(name, "alias name has more than one target")
            if next(iter(scopes)):
                return self.refuse(name, "scoped alias visibility cannot be resolved")
            if name in seen:
                return self.refuse(name, "cycle")
            seen.add(name)
            target = self[name]
            # Validate the alias target before adding a call/import suffix:
            # u -> missing must fail for u::load as well as for `use u as v`.
            if len(target) == 1 and target[0] not in PATH_ROOTS and target[0] not in self and target[0] not in self.known:
                return self.refuse(name, "unknown target `%s`" % target[0])
            path = target + path[1:]
        return path


def chain_renamed_imports(text, crate, free):
    """Resolve relative first-segment alias chains in a separate extra pass."""
    bindings = ChainBindings(text, crate, free)
    fns = {}
    for original, alias, at in chain_use_leaves(text, preserve_roots=True):
        if not original or alias in ("*", "_", original[-1]):
            continue
        path = bindings.resolve(original)
        if path and (crate, path[-1]) in free:
            hint = path[-2] if len(path) >= 2 and path[-2] not in PATH_ROOTS else None
            fns[alias] = (path[-1], hint)
    return fns, bindings, bindings.bad


def chain_resolves(rel, text, prefix, callee, target, hint=None, mods=None, owners=()):
    """Whether a call `prefix callee(` in `rel` may name `callee` in `target`:
    the same file for a bare call (or a file whose module the caller imports
    the name from, through an alias chain: `use u::load` where `u` is
    `util`), the named module for a qualified call (through a renamed
    module import too, `use u as v; v::load`); `hint` is the module a
    renamed function import names, after that chain is resolved.
    `owners` are the inline modules (`mod util { .. }`) around the definition:
    each is a module name of it as well as the file's (R11-S7-FIX14)."""
    names = {stem(target)} | set(owners)
    mods = mods if mods is not None else ChainBindings(text, "", {})
    segs = mods.resolve(prefix.split("::")[:-1] if prefix else [])
    if segs is None:
        return False  # aliases_of reports the unresolved chain.
    if segs and segs[-1] not in PATH_ROOTS:
        return segs[-1] in names
    if segs:
        # `crate::helper(p)`, `super::helper(p)`, `self::helper(p)`: no module
        # is named, so any same-crate definition (over-reporting is safe).
        return True
    if hint is not None:
        return hint == "" or hint in names
    if target == rel:
        return True
    # Any import form: `use crate::m::leaf;`, nested braces
    # (`use crate::{m::leaf, ..}`), or a glob of the module (`use crate::m::*;`),
    # including one whose module is itself an alias (`use u::load;`, `use u::*;`).
    for original, alias, at in chain_use_leaves(text, preserve_roots=True):
        path = mods.resolve(original)
        if not path:
            continue
        if alias == "*":
            if path[-1] in names or (path != original and path[-1] in PATH_ROOTS):
                return True
        elif len(path) >= 2 and path[-1] == callee:
            if path[-2] in names or (path != original and path[-2] in PATH_ROOTS):
                return True
    return False


def chain_helper_errors(entries, scanned, texts, fns):
    """Walk the extra #198 call graph independently of main's helper pass.

    Keep the same managed roots, helper exemptions and report format; add
    chain resolution and explicit refusals for unsupported alias paths.
    """
    errs = []
    by_key = {key(e): e for e in entries}
    managed_fns = {}
    for e in entries:
        if e.get("disposition") in ("managed-read", "sqlite-snapshot"):
            managed_fns.setdefault(e["file"], set()).add(e["function"])
    raw_by_fn = {}
    for o in scanned.values():
        if o["op"] in MANAGED_OPS:
            continue
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
    def aliases_of(rel):
        if rel not in renames:
            fn_alias, mod_alias, _ = chain_renamed_imports(texts[rel], crate_of(rel), free)
            renames[rel] = (fn_alias, mod_alias)
        return renames[rel]

    def callees(rel, a, b):
        text = texts[rel]
        body = text[a:b]
        fn_alias, mod_alias = aliases_of(rel)
        out = []
        for m in CALL_RE.finditer(body):
            prefix, callee = m.group(1), m.group(2)
            hint = None
            if not prefix and callee in fn_alias:
                # `use crate::m::read_index as legacy_read; legacy_read(p)`.
                # A `crate::`/`self::`/`super::` path names no module: any
                # same-crate definition (over-reporting is safe).
                if mod_alias.resolve([callee]) is None:
                    continue
                callee, hint = fn_alias[callee]
                hint = hint or ""
            if text[max(0, a + m.start() - 3):a + m.start()].endswith("fn "):
                continue
            if prefix:
                path = mod_alias.resolve(prefix.split("::")[:-1] + [callee])
                if path is None:
                    continue
            for target, ta, tb in free.get((crate_of(rel), callee), []):
                # A call of the same name is followed unless it is the caller
                # itself (`other::read_index(p)` from `read_index`).
                if (target, ta) == (rel, a):
                    continue
                if chain_resolves(rel, text, prefix, callee, target, hint, mod_alias, owners[(target, ta)]):
                    out.append((callee, target, ta, tb))
        return out

    for rel, names in managed_fns.items():
        text = texts.get(rel)
        if text is None:
            continue
        for a, b, qual in fns.get(rel, []):
            if qual not in names:
                continue
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
    for rel, (_, bindings) in renames.items():
        for alias, reason in bindings.bad:
            errs.append("unresolved use-alias chain (fail closed): %s `%s`: %s" % (rel, alias, reason))
    return sorted(set(errs))


def union_helper_errors(entries, scanned, texts, fns):
    """Union main's unchanged helper walk with the independent chain pass."""
    return sorted(set(helper_errors(entries, scanned, texts, fns)) |
                  set(chain_helper_errors(entries, scanned, texts, fns)))


def rust_tokens(src, literals=False):
    """Rust tokens and offsets, omitting comments and complete literals.

    Re-export detection uses tokens from the original source, independently of
    the helper resolvers. Nested comments, escaped strings, byte/C strings,
    raw strings (any hash count), chars and raw identifiers cannot introduce
    fake `pub use` tokens. Lifetimes retain their identifier tokens. The cfg
    gate can retain each literal as one opaque token, never its contents.
    """
    raw_re = re.compile(r'(?:br|cr|r)(#*)"')
    quoted_re = re.compile(r'(?:b|c)?"')
    char_re = re.compile(r"b?'(?:\\(?:u\{[0-9a-fA-F_]+\}|x[0-9a-fA-F]{2}|.)|[^'\\\n])'")
    token_re = re.compile(r"r#\w+|[^\W\d]\w*|::|[^\s]")
    i, n = 0, len(src)
    while i < n:
        if src[i].isspace():
            i += 1
            continue
        if src.startswith("//", i):
            end = src.find("\n", i + 2)
            i = n if end < 0 else end
            continue
        if src.startswith("/*", i):
            depth, i = 1, i + 2
            while i < n and depth:
                if src.startswith("/*", i):
                    depth, i = depth + 1, i + 2
                elif src.startswith("*/", i):
                    depth, i = depth - 1, i + 2
                else:
                    i += 1
            continue
        raw = raw_re.match(src, i)
        if raw:
            close = '"' + raw.group(1)
            end = src.find(close, raw.end())
            stop = n if end < 0 else end + len(close)
            if literals:
                yield src[i:stop], i
            i = stop
            continue
        quoted = quoted_re.match(src, i)
        if quoted:
            start = i
            i = quoted.end()
            while i < n:
                if src[i] == "\\":
                    i += 2
                elif src[i] == '"':
                    i += 1
                    break
                else:
                    i += 1
            if literals:
                yield src[start:i], start
            continue
        char = char_re.match(src, i)
        if char:
            if literals:
                yield char.group(), i
            i = char.end()
            continue
        token = token_re.match(src, i)
        yield token.group(), i
        i = token.end()


def macro_payload_indices(tokens):
    """Indices inside invocation/definition payloads, before parsing visibility.

    Macro tokens are arbitrary syntax: even a private `use` may expand to a
    public import. Include macro_rules bodies and all nested delimiter kinds.
    """
    closes, stack = {}, []
    pairs = {"(": ")", "[": "]", "{": "}"}
    for i, (token, _) in enumerate(tokens):
        if token in pairs:
            stack.append(i)
        elif stack and token == pairs[tokens[stack[-1]][0]]:
            closes[stack.pop()] = i
    payload = set()
    for i, (token, _) in enumerate(tokens):
        if token != "!" or not i or not re.fullmatch(r"(?:r#)?[^\W\d]\w*", tokens[i - 1][0]):
            continue
        j = i + 1
        if tokens[i - 1][0] == "macro_rules":
            j += 1  # macro_rules! name { ... }
        if j in closes:
            payload.update(range(j + 1, closes[j]))
    return payload


def macro_use_trees(tokens, payload):
    """Review every `use` in opaque macro payloads, without visibility parsing."""
    out = []
    for i in sorted(payload):
        if tokens[i][0] != "use":
            continue
        tree, j = [], i + 1
        while j in payload and tokens[j][0] != ";":
            tree.append(tokens[j][0])
            j += 1
        out.append((" ".join(tree), tokens[i][1]))
    return out


def public_use_trees(src, tokens=None, payload=None):
    """(normalized use-tree, pub offset) for every visibility-qualified use.

    Consume visibility forwards, including balanced multiline `pub(in ..)`;
    never infer visibility from text before a use or its imported names.
    """
    tokens = list(rust_tokens(src)) if tokens is None else tokens
    payload = macro_payload_indices(tokens) if payload is None else payload
    out = []
    i = 0
    while i < len(tokens):
        token, at = tokens[i]
        i += 1
        if token != "pub" or i - 1 in payload:
            continue
        if i < len(tokens) and tokens[i][0] == "(":
            depth = 1
            i += 1
            while i < len(tokens) and depth:
                if tokens[i][0] == "(":
                    depth += 1
                elif tokens[i][0] == ")":
                    depth -= 1
                i += 1
        if i >= len(tokens) or tokens[i][0] != "use":
            continue
        i += 1
        tree = []
        while i < len(tokens) and tokens[i][0] != ";":
            tree.append(tokens[i][0])
            i += 1
        out.append((" ".join(tree), at))
    return out


def reexport_cfg_test_only(tokens):
    """Conservative test-only cfg policy, evaluated solely on Rust tokens.

    Comments have already gone and literals are opaque tokens. In particular,
    a comment saying `test` cannot become an all()/any() predicate argument.
    Unknown or unsupported predicates remain production source.
    """
    pos = 0

    def take():
        nonlocal pos
        token = tokens[pos]
        pos += 1
        return token

    def expr():
        name = take()
        if not re.fullmatch(r"[^\W\d]\w*", name):
            raise ValueError("unsupported cfg atom")
        if pos < len(tokens) and tokens[pos] == "(":
            take()
            args = []
            while tokens[pos] != ")":
                args.append(expr())
                if tokens[pos] != ",":
                    break
                take()
            if take() != ")" or name not in ("all", "any", "not"):
                raise ValueError("unsupported cfg predicate")
            if name == "all":
                return any(args)
            if name == "any":
                return bool(args) and all(args)
            return False
        if pos < len(tokens) and tokens[pos] == "=":
            take()
            return take() == '"test-hooks"' and name == "feature"
        return name == "test"

    try:
        result = expr()
        return result and pos == len(tokens)
    except (IndexError, ValueError):
        return False


def reexport_token_views(src, tokens, payload):
    """Offset-preserving syntax and literal views made only from Rust tokens.

    Decide cfg exclusion here. Normalize attributes to #[test] or #[] before
    reusing main's span-boundary helper, so it never reinterprets raw cfg text.
    Literal values are retained separately only for module #[path] extraction.
    Attributes inside macro payloads are opaque and cannot exclude a use.
    """
    code = ["\n" if ch == "\n" else " " for ch in src]
    literal_code = code.copy()
    literal_tokens = list(rust_tokens(src, literals=True))
    for token, at in literal_tokens:
        literal_code[at:at + len(token)] = token
    for token, at in tokens:
        code[at:at + len(token)] = token
    macro_offsets = {tokens[i][1] for i in payload}
    i = 0
    while i + 1 < len(literal_tokens):
        token, at = literal_tokens[i]
        if token != "#" or literal_tokens[i + 1][0] != "[":
            i += 1
            continue
        j, depth = i + 2, 1
        while j < len(literal_tokens) and depth:
            if literal_tokens[j][0] == "[":
                depth += 1
            elif literal_tokens[j][0] == "]":
                depth -= 1
            j += 1
        if depth:
            break  # Unsupported syntax stays visible; it cannot exclude code.
        body = [t for t, _ in literal_tokens[i + 2:j - 1]]
        test_only = body in (["test"], ["tokio", "::", "test"])
        if len(body) >= 3 and body[:2] == ["cfg", "("] and body[-1] == ")":
            test_only = reexport_cfg_test_only(body[2:-1])
        if at in macro_offsets:
            test_only = False
        end = literal_tokens[j - 1][1] + 1
        for k in range(at, end):
            if code[k] != "\n":
                code[k] = " "
        replacement = "#[test]" if test_only else "#[]"
        code[at:at + len(replacement)] = replacement
        i = j
    # Span/module helpers accept conventional visibility spelling. Never
    # interpret visibility inside an arbitrary macro token payload.
    for i, (token, at) in enumerate(tokens):
        if token != "pub" or i in payload:
            continue
        j, depth = i + 1, 0
        if j < len(tokens) and tokens[j][0] == "(":
            while j < len(tokens):
                if tokens[j][0] == "(":
                    depth += 1
                elif tokens[j][0] == ")":
                    depth -= 1
                    if not depth:
                        j += 1
                        break
                j += 1
        for k in range(at, tokens[j][1] if j < len(tokens) else len(src)):
            if code[k] != "\n":
                code[k] = " "
    return "".join(code), "".join(literal_code)


def reexport_sources(root):
    """Tokenized sources outside test-only modules, independent of scan().

    Literal text cannot fabricate a cfg/module declaration that excludes a
    production file. Evaluate cfg predicates on the comment-stripped tokens;
    a file shared by production and test declarations remains production.
    """
    sources, decls = {}, {}
    for rel in rust_files(root):
        with open(os.path.join(root, rel), encoding="utf-8", errors="replace") as fh:
            src = fh.read()
        tokens = list(rust_tokens(src))
        payload = macro_payload_indices(tokens)
        text, literal_text = reexport_token_views(src, tokens, payload)
        spans, _ = test_spans(text)
        decls[rel] = mod_decls(text, literal_text)
        sources[rel] = (src, tokens, spans)

    def target(rel, name, chain):
        if not isinstance(name, tuple):
            return module_file(rel, name, root, chain)
        directory = os.path.dirname(rel)
        if chain and os.path.basename(rel) not in ("lib.rs", "main.rs", "mod.rs"):
            directory = os.path.join(directory, os.path.basename(rel)[:-3])
        return os.path.normpath(os.path.join(directory, *chain, name[1])).replace(os.sep, "/")

    test_files = set()
    while True:
        production, test_targets = set(), set()
        for rel, (_, _, spans) in sources.items():
            for at, name, chain in decls[rel]:
                targets = (test_targets if rel in test_files or any(a <= at <= b for a, b in spans)
                           else production)
                targets.add(target(rel, name, chain))
        added = (test_targets - production) - test_files
        if not added:
            break
        test_files.update(added)
    return {rel: source for rel, source in sources.items() if rel not in test_files}


def reexport_errors(root):
    """Require review for every production public import and macro-payload use.

    An allowlisted use is permitted without claiming the chain pass follows
    its exported names. No visibility, owner or name-matching exemptions apply.
    """
    errors, present = [], {}
    for rel, (src, tokens, spans) in reexport_sources(root).items():
        payload = macro_payload_indices(tokens)
        uses = public_use_trees(src, tokens, payload) + macro_use_trees(tokens, payload)
        for tree, at in uses:
            if not any(a <= at <= b for a, b in spans):
                present[(rel, tree)] = src.count("\n", 0, at) + 1
    try:
        allowlist = load(os.path.join(root, REEXPORT_ALLOWLIST))
    except FileNotFoundError:
        allowlist = {"version": 1, "entries": []}
    except (ValueError, OSError) as e:
        return ["re-export allowlist (fail closed): cannot read %s: %s" % (REEXPORT_ALLOWLIST, e)]
    if (not isinstance(allowlist, dict) or allowlist.get("version") != 1
            or not isinstance(allowlist.get("entries"), list)):
        return ["re-export allowlist (fail closed): expected version 1 and entries list"]
    allowed = set()
    for entry in allowlist["entries"]:
        if (not isinstance(entry, dict) or not isinstance(entry.get("file"), str)
                or not isinstance(entry.get("use"), str)):
            errors.append("re-export allowlist (fail closed): entry needs file and use strings")
            continue
        tree = " ".join(t for t, _ in rust_tokens(entry["use"]))
        ident = (entry["file"], tree)
        if ident in allowed:
            errors.append("re-export allowlist (fail closed): duplicate entry %s %s" % ident)
        allowed.add(ident)
        if not tree or tree != entry["use"]:
            errors.append("re-export allowlist (fail closed): use-tree must be token whitespace normalized: %s %s" % ident)
        if not isinstance(entry.get("reason"), str) or not entry["reason"].strip():
            errors.append("re-export allowlist (fail closed): entry needs a reason: %s %s" % ident)
        if ident not in present:
            errors.append("re-export allowlist (fail closed): stale entry %s %s" % ident)
    for (rel, tree), line in sorted(present.items()):
        if (rel, tree) not in allowed:
            errors.append("re-export allowlist (fail closed): unreviewed pub use or macro use: %s:%d use %s;"
                          % (rel, line, tree))
    return errors


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
        errors = reexport_errors(ROOT)
        for error in errors:
            print("inventory: " + error)
        return 1 if bad or errors else 0
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
    """Regression: (R11-S7-FIX1): a `#[cfg(test)] if .. { .. }` statement (no
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
    """Regression: (R11-S7-FIX1): `use std::fs::read as read_file;`,
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
    """Regression: (R11-S7-FIX1): a managed function reaching a raw read
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
    """Regression: (R11-S7-FIX1): fingerprints hashed literal-masked text, so
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
    """Regression: (R11-S7-FIX1): a new create could claim
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
    """Regression: (R11-S7-FIX5): a `#[cfg(test)]` match arm whose body is a
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
    """Regression: (R11-S7-FIX5): a managed function reaching a raw helper
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
    """Regression: (R11-S7-FIX5): only a literal `.create(true)` /
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
    """Regression: (R11-S7-FIX5): pathname opens inside foreign libraries
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
    """Regression: (R11-S7-FIX9): `use std::fs as disk; use disk::read as
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
    """Regression: (R11-S7-FIX9): explicit generic arguments
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
    """Regression: (R11-S7-FIX9): fingerprints dropped whitespace inside
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
    """Regression: (R11-S7-FIX9): a managed function reaching a raw helper
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
    """Regression: (R11-S7-FIX9): `TempDir::with_prefix(..)` (and the
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
    """Regression: (R11-S7-FIX10): the helper walk missed a call with explicit
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
    """Regression: (R11-S7-FIX10): `unchanged-from-<baseline>` was matched on
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
    """Regression: (R11-S7-FIX12): the helper walk did not follow
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
    """Regression: (R11-S7-FIX12): a `#[cfg(test)]` match arm whose body is a
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
    """Regression: (R11-S7-FIX12): `try_clone_to_owned`, `libc::dup`/`dup2`,
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
    """Regression: (R11-S7-FIX12): the generic-argument pattern excluded
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
    """Regression: (R11-S7-FIX14): after the `else` of a test-only `if` arm
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
    """Regression: (R11-S7-FIX14): a test-only statement or arm in a form the
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
    """Regression: (R11-S7-FIX14): `OpenOptions::default()` built a std
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
    """Regression: (R11-S7-FIX14): a qualified call resolved only against the
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
    """Regression: (R11-S7-FIX15): every file a test-only `mod` declaration
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
    """Regression: (R11-S7-FIX16): a `mod util;` inside `mod outer { .. }`
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


def regression_inventory_helper_walk_visits_same_named_helpers_by_definition():
    """Regression: (R11-S7-FIX15): the helper walk marked a function visited by
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


def regression_inventory_helper_walk_resolves_chained_use_aliases():
    """Regression: (#198): a raw helper reached only through a chain of `use`
    aliases (`use crate::util as u; use u::load as read_index`, call
    `read_index(p)`) was not a callee, so the mandatory-helper check passed.
    An alias cycle is reported instead of skipped."""
    leaf = "pub fn load(p: &Path) { let _ = std::fs::read(p); }\n"
    body = "fn hash(p: &Path) { let c = ManagedReadCursor::open(p)?; %s; }\n"
    cases = (
        ("mod util;\nuse crate::util as u;\nuse u::load as read_index;\n", "read_index(p)", True),
        ("mod util;\nuse crate::util as u;\nuse u::{load as read_index};\n", "read_index(p)", True),
        ("mod util;\nuse crate::util as u;\nuse u as v;\nuse v::load as read_index;\n", "read_index(p)", True),
        ("mod util;\nuse crate::util as u;\nuse u::load;\n", "load(p)", True),
        ("mod util;\nuse crate::util as u;\nuse u::*;\n", "load(p)", True),
        ("mod util;\nuse crate::util as u;\nuse u as v;\n", "v::load(p)", True),
        # A rooted path uses the actual module name, without alias expansion.
        ("mod util;\nuse crate::util as u;\nuse self::util::load as read_index;\n", "read_index(p)", True),
        ("mod util {\n    pub fn load(p: &Path) { let _ = std::fs::read(p); }\n}\n"
         "use self::util as u;\nuse u::load as read_index;\n", "read_index(p)", False),
        ("pub fn load(p: &Path) { let _ = std::fs::read(p); }\nuse self as s;\nuse s::load as read_index;\n",
         "read_index(p)", False),
        ("pub fn load(p: &Path) { let _ = std::fs::read(p); }\nuse self as s;\n", "s::load(p)", False),
    )
    for imp, call, separate in cases:
        files = {"c/src/lib.rs": imp + body % call}
        if separate:
            files["c/src/util.rs"] = leaf
        root = fake(files)
        m = classify(root, {("hash", "ManagedReadCursor::open"): MANAGED, ("load", "fs::read"): OOF})
        errs = check(root, m)
        expect(any("reaches helper load" in e for e in errs), (imp, call, errs))
        m = classify(root, {("hash", "ManagedReadCursor::open"): MANAGED,
                            ("load", "fs::read"): dict(OOF, non_mandatory_callers=["hash"])})
        expect(check(root, m) == [], (imp, call, check(root, m)))
    # A chain that names another module is not this helper.
    root = fake({"c/src/lib.rs": "mod util;\nmod other;\nuse crate::other as o;\nuse o::load as read_index;\n"
                                 + body % "read_index(p)",
                 "c/src/util.rs": leaf, "c/src/other.rs": "pub fn load(p: &Path) {}\n"})
    m = classify(root, {("hash", "ManagedReadCursor::open"): MANAGED, ("load", "fs::read"): OOF})
    expect(check(root, m) == [], check(root, m))
    # A cycle never names a module. The previous scanner reported nothing.
    root = fake({"c/src/lib.rs": "mod util;\nuse a as b;\nuse b as a;\n" + body % "b::load(p)",
                 "c/src/util.rs": leaf})
    errs = check(root, classify(root, {("hash", "ManagedReadCursor::open"): MANAGED, ("load", "fs::read"): OOF}))
    expect(any("unresolved use-alias chain" in e for e in errs), errs)


def regression_inventory_helper_walk_rejects_unknown_alias_target():
    """Regression: an ungrounded alias chain guessed a module name and
    silently skipped the raw helper instead of refusing fail-closed."""
    for imports in ("use missing as u;\nuse u::load as read_index;\n",
                    "use missing as u;\nuse u as v;\nuse v::load as read_index;\n"):
        root = fake({"c/src/lib.rs": (
            "mod util;\n" + imports
            + "fn hash(p: &Path) { let c = ManagedReadCursor::open(p)?; read_index(p); }\n"),
            "c/src/util.rs": "pub fn load(p: &Path) { let _ = std::fs::read(p); }\n"})
        errs = check(root, classify(root, {("hash", "ManagedReadCursor::open"): MANAGED,
                                           ("load", "fs::read"): OOF}))
        expect(any("unresolved use-alias chain" in e and "unknown target `missing`" in e for e in errs), errs)


def regression_inventory_helper_walk_rewrites_only_first_relative_segment():
    """Regression: rooted calls or a later path segment were rewritten
    through an unrelated local alias and selected a decoy module."""
    text = "use crate::util as a;\n"
    free = {("c", "load"): [("c/src/a.rs", 0, 1), ("c/src/util.rs", 0, 1)]}
    _, mods, bad = chain_renamed_imports(text, "c", free)
    expect(bad == [], bad)
    for prefix in ("crate::a::", "super::a::", "self::a::", "::a::", "outer::a::"):
        expect(chain_resolves("c/src/caller.rs", text, prefix, "load", "c/src/a.rs", mods=mods), prefix)
        expect(not chain_resolves("c/src/caller.rs", text, prefix, "load", "c/src/util.rs", mods=mods), prefix)
    for prefix in ("crate::a", "super::a", "self::a", "::a", "outer::a"):
        for leaf, call in (("load as read_index", "read_index"), ("load", "load"), ("*", "load")):
            imports = text + "use %s::%s;\n" % (prefix, leaf)
            fns, mods, bad = chain_renamed_imports(imports, "c", free)
            expect(bad == [], (imports, bad))
            callee, hint = fns.get(call, (call, None))
            expect(chain_resolves("c/src/caller.rs", imports, "", callee, "c/src/a.rs", hint, mods), imports)
            expect(not chain_resolves("c/src/caller.rs", imports, "", callee, "c/src/util.rs", hint, mods), imports)


def check_compiled_alias_fixture(modules, imports, call, raw_module, test_cfg=False):
    """Type-check a real Rust fixture, then check its exact raw-helper report."""
    import subprocess

    files = {
        "c/src/lib.rs": (
            "#![allow(dead_code, unused_imports, unused_variables)]\n"
            "pub struct ManagedReadCursor;\n"
            "impl ManagedReadCursor {\n"
            "    pub fn open(_: &std::path::Path) -> Self { Self }\n"
            "}\n"
            "mod caller;\n" + "".join("mod %s;\n" % name for name in modules)),
        "c/src/caller.rs": (
            "use std::path::Path;\nuse crate::ManagedReadCursor;\n" + imports
            + "fn hash(p: &Path) { let _c = ManagedReadCursor::open(p); %s; }\n" % call),
    }
    for name, body in modules.items():
        files["c/src/%s.rs" % name] = "use std::path::Path;\n" + body
    root = fake(files)
    cmd = ["rustc", "--crate-name", "inventory_alias_fixture", "--crate-type", "lib",
           "--edition=2021", "--emit=metadata", "--out-dir", root, "c/src/lib.rs"]
    for cfg in ([], ["--cfg", "test"]) if test_cfg else ([],):
        try:
            compiled = subprocess.run(cmd + cfg, cwd=root, capture_output=True, text=True, timeout=30)
        except OSError as e:
            raise AssertionError("rustc is required for the alias fixture: %s" % e) from e
        expect(compiled.returncode == 0, (imports, call, compiled.stderr))
    rules = {("hash", "ManagedReadCursor::open"): MANAGED, ("load", "fs::read"): OOF}
    errors = check(root, classify(root, rules))
    expected = ("managed function hash (c/src/caller.rs) reaches helper load "
                "with a non-managed read (c/src/%s.rs fs::read#1)" % raw_module)
    expect(errors == [expected], (imports, call, errors))
    rules[("load", "fs::read")] = dict(OOF, non_mandatory_callers=["hash"])
    expect(check(root, classify(root, rules)) == [], (imports, call, check(root, classify(root, rules))))


def regression_inventory_helper_walk_keeps_rooted_renamed_import():
    """Regression: a local module alias rewrote `crate::a::load as read_index`
    to an empty decoy instead of reporting a::load's raw std::fs::read."""
    check_compiled_alias_fixture(
        {"a": "pub fn load(p: &Path) { let _ = std::fs::read(p); }\n",
         "util": "pub fn load(_: &Path) {}\n"},
        "use crate::util as a;\nuse crate::a::load as read_index;\n",
        "read_index(p)", "a")


def regression_inventory_helper_walk_keeps_rooted_bare_import():
    """Regression: a local module alias rewrote the parent of `use crate::a::load`
    and hid the raw helper behind an empty decoy."""
    check_compiled_alias_fixture(
        {"a": "pub fn load(p: &Path) { let _ = std::fs::read(p); }\n",
         "util": "pub fn load(_: &Path) {}\n"},
        "use crate::util as a;\nuse crate::a::load;\n", "load(p)", "a")


def regression_inventory_helper_walk_keeps_rooted_glob_import():
    """Regression: a local module alias rewrote `use crate::a::*` to an empty
    decoy and hid the raw std::fs::read reached through load(p)."""
    check_compiled_alias_fixture(
        {"a": "pub fn load(p: &Path) { let _ = std::fs::read(p); }\n",
         "util": "pub fn load(_: &Path) {}\n"},
        "use crate::util as a;\nuse crate::a::*;\n", "load(p)", "a")


def regression_inventory_helper_walk_test_alias_does_not_rewrite_rooted_import():
    """Regression: an alias inside #[cfg(test)] mod tests poisoned the
    production import `use crate::a::load as read_index`."""
    check_compiled_alias_fixture(
        {"a": "pub fn load(p: &Path) { let _ = std::fs::read(p); }\n",
         "util": "pub fn load(_: &Path) {}\n"},
        "use crate::a::load as read_index;\n"
        "#[cfg(test)] mod tests { use crate::util as a; }\n",
        "read_index(p)", "a", test_cfg=True)


def regression_inventory_helper_walk_qualified_alias_stops_at_rooted_target():
    """Regression: o::load followed o -> util -> outer across two absolute
    imports and selected an empty decoy instead of util::load's raw read."""
    check_compiled_alias_fixture(
        {"util": "pub fn load(p: &Path) { let _ = std::fs::read(p); }\n",
         "outer": "pub fn load(_: &Path) {}\n"},
        "use crate::util as o;\nuse crate::outer as util;\n", "o::load(p)", "util")


def regression_inventory_helper_walk_absolute_alias_name_swap_is_not_cycle():
    """Regression: absolute foo/bar name-swapped imports were falsely
    reported as a cycle instead of following bar::load to foo::load."""
    check_compiled_alias_fixture(
        {"foo": "pub fn load(p: &Path) { let _ = std::fs::read(p); }\n",
         "bar": "pub fn load(_: &Path) {}\n"},
        "use crate::foo as bar;\nuse crate::bar as foo;\n", "bar::load(p)", "foo")


SCOPE_IMPORTS = (
    ("use a::load;\n", "load(p)"),
    ("use a::load as read_index;\n", "read_index(p)"),
    ("use a::*;\n", "load(p)"),
    ("use a::{load};\n", "load(p)"),
    ("use a::{load as read_index};\n", "read_index(p)"),
)
SCOPE_ALIASES = {
    "nested": "mod nested { use crate::util as a; }\n",
    "test": "#[cfg(test)] mod tests { use crate::util as a; }\n",
    "function": "fn other() { use crate::util as a; }\n",
}
UTIL_IMPORTS = (
    ("use util::load;\n", "load(p)"),
    ("use util::load as read_index;\n", "read_index(p)"),
    ("use util::*;\n", "load(p)"),
)


def check_compiled_scope_fixture(imports, call, raw_file, local_a=False, test_cfg=False,
                                 refusal_reason=None):
    """Compile a scope collision, then require main's raw report or refusal."""
    import subprocess

    files = {
        "c/src/lib.rs": (
            "#![allow(dead_code, unused_imports, unused_variables)]\n"
            "pub struct ManagedReadCursor;\n"
            "impl ManagedReadCursor {\n"
            "    pub fn open(_: &std::path::Path) -> Self { Self }\n"
            "}\n"
            "mod caller;\npub mod util;\nmod decoy;\n"),
        "c/src/caller.rs": (
            "use std::path::Path;\nuse crate::ManagedReadCursor;\n"
            + ("mod a;\n" if local_a else "use crate::util;\n") + imports
            + "fn hash(p: &Path) { let _c = ManagedReadCursor::open(p); %s; }\n" % call),
        "c/src/util.rs": "use std::path::Path;\npub fn load(p: &Path) { %s }\n" % (
            "let _ = std::fs::read(p);" if raw_file == "c/src/util.rs" else ""),
        "c/src/decoy.rs": "pub fn load(_: &std::path::Path) {}\n",
    }
    if local_a:
        files["c/src/caller/a.rs"] = (
            "pub fn load(p: &std::path::Path) { let _ = std::fs::read(p); }\n")
    root = fake(files)
    cmd = ["rustc", "--crate-name", "inventory_scope_fixture", "--crate-type", "lib",
           "--edition=2021", "--emit=metadata", "--out-dir", root, "c/src/lib.rs"]
    for cfg in ([], ["--cfg", "test"]) if test_cfg else ([],):
        try:
            compiled = subprocess.run(cmd + cfg, cwd=root, capture_output=True, text=True, timeout=30)
        except OSError as e:
            raise AssertionError("rustc is required for the scope fixture: %s" % e) from e
        expect(compiled.returncode == 0, (imports, call, compiled.stderr))
    rules = {("hash", "ManagedReadCursor::open"): MANAGED, ("load", "fs::read"): OOF}
    errors = check(root, classify(root, rules))
    expected = ("managed function hash (c/src/caller.rs) reaches helper load "
                "with a non-managed read (%s fs::read#1)" % raw_file)
    refusal = [e for e in errors if "unresolved use-alias chain (fail closed)" in e
               or "re-export allowlist (fail closed)" in e]
    expect(expected in errors or refusal, (imports, call, errors))
    expect(all(e == expected or e in refusal for e in errors), (imports, call, errors))
    if refusal_reason:
        expect(any(refusal_reason in e for e in refusal), (imports, call, errors))
    # Exempting the actual helper may remove its report, but cannot excuse
    # an unsupported alias: refusal must still be explicit.
    rules[("load", "fs::read")] = dict(OOF, non_mandatory_callers=["hash"])
    excused = check(root, classify(root, rules))
    expect(all("unresolved use-alias chain (fail closed)" in e
               or "re-export allowlist (fail closed)" in e for e in excused), excused)
    if refusal_reason:
        expect(any(refusal_reason in e for e in excused), excused)


def regression_inventory_helper_walk_nested_alias_does_not_hide_relative_imports():
    """Regression: a sibling module's alias hid five forms of a::load import."""
    for imports, call in SCOPE_IMPORTS:
        check_compiled_scope_fixture(SCOPE_ALIASES["nested"] + imports, call,
                                     "c/src/caller/a.rs", local_a=True,
                                     refusal_reason="bound in more than one scope")


def regression_inventory_helper_walk_test_alias_does_not_hide_relative_imports():
    """Regression: a test module's alias hid five production a::load imports."""
    for imports, call in SCOPE_IMPORTS:
        check_compiled_scope_fixture(SCOPE_ALIASES["test"] + imports, call,
                                     "c/src/caller/a.rs", local_a=True, test_cfg=True,
                                     refusal_reason="bound in more than one scope")


def regression_inventory_helper_walk_function_alias_does_not_hide_relative_imports():
    """Regression: an unrelated function's alias hid five a::load imports."""
    for imports, call in SCOPE_IMPORTS:
        check_compiled_scope_fixture(SCOPE_ALIASES["function"] + imports, call,
                                     "c/src/caller/a.rs", local_a=True,
                                     refusal_reason="bound in more than one scope")


def regression_inventory_helper_walk_test_alias_does_not_hide_util_imports():
    """Regression: test-only util -> decoy hid a production util::load read."""
    alias = "#[cfg(test)] mod tests { use crate::decoy as util; }\n"
    for imports, call in UTIL_IMPORTS:
        check_compiled_scope_fixture(alias + imports, call, "c/src/util.rs", test_cfg=True,
                                     refusal_reason="bound in more than one scope")


def regression_inventory_helper_walk_function_alias_does_not_hide_util_imports():
    """Regression: a function-local util -> decoy hid a production raw helper."""
    alias = "fn other() { use crate::decoy as util; }\n"
    for imports, call in UTIL_IMPORTS:
        check_compiled_scope_fixture(alias + imports, call, "c/src/util.rs",
                                     refusal_reason="bound in more than one scope")


def regression_inventory_helper_walk_reexport_reports_raw_helper_or_refuses():
    """Regression: outer::a::load silently lost the raw pub-use target."""
    check_compiled_scope_fixture("mod outer { pub use crate::util as a; }\n",
                                 "outer::a::load(p)", "c/src/util.rs",
                                 refusal_reason="re-export allowlist")


def regression_inventory_helper_walk_pub_function_reexport_refuses():
    """Regression: outer::load skipped an unsupported pub-use function binding."""
    check_compiled_scope_fixture("mod outer { pub use crate::util::load; }\n",
                                 "outer::load(p)", "c/src/util.rs",
                                 refusal_reason="re-export allowlist")


def regression_inventory_helper_walk_pub_glob_reexport_refuses():
    """Regression: outer::load skipped an unsupported pub-use glob binding."""
    check_compiled_scope_fixture("mod outer { pub use crate::util::*; }\n",
                                 "outer::load(p)", "c/src/util.rs",
                                 refusal_reason="re-export allowlist")



def regression_inventory_helper_walk_rooted_reexport_owners_refuse():
    """Regression: self/super re-export owners silently lost a renamed helper."""
    import subprocess

    for exported, scope, call in (
        ("pub use util::load as l;\n", "", "self::l(p)"),
        ("", "mod outer { pub use crate::util::load as l; %s }\n", "self::l(p)"),
        ("pub use util::load as l;\n", "mod outer { use super::*; %s }\n", "super::l(p)"),
    ):
        body = ("fn hash(p: &std::path::Path) { let _ = crate::ManagedReadCursor::open(p); %s; }\n" % call)
        files = {
            "c/src/lib.rs": (
                "#![allow(dead_code, unused_imports)]\n"
                "pub struct ManagedReadCursor;\n"
                "impl ManagedReadCursor { pub fn open(_: &std::path::Path) -> Self { Self } }\n"
                "pub mod util;\n" + exported + (scope % body if scope else body)),
            "c/src/util.rs": "pub fn load(p: &std::path::Path) { let _ = std::fs::read(p); }\n",
        }
        root = fake(files)
        compiled = subprocess.run(
            ["rustc", "--crate-name", "inventory_rooted_reexport", "--crate-type", "lib",
             "--edition=2021", "--emit=metadata", "--out-dir", root, "c/src/lib.rs"],
            cwd=root, capture_output=True, text=True, timeout=30)
        expect(compiled.returncode == 0, compiled.stderr)
        errs = check(root, classify(root, {("hash", "ManagedReadCursor::open"): MANAGED,
                                           ("load", "fs::read"): OOF}))
        expect(any("re-export allowlist (fail closed)" in e for e in errs), (exported, scope, call, errs))



def write_reexport_fixture_allowlist(root, entries):
    path = os.path.join(root, REEXPORT_ALLOWLIST)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"version": 1, "entries": entries}, fh)


def regression_inventory_reexport_allowlist_tokenizes_visibility_and_trees():
    """Regression: comments, literals and multiline visibility hid public uses."""
    # Literal contents, nested comments and raw identifiers are not keywords.
    # Include more raw-string hashes than mask()'s lookahead, and lifetimes.
    hashes = "#" * 100
    literals = ('const S: &str = "pub use decoy::string;";\n'
                'const B: &[u8] = b"pub use decoy::bytes;";\n'
                'const C: &std::ffi::CStr = c"pub use decoy::c;";\n'
                'const R: &str = r' + hashes + '"pub use decoy::raw;"' + hashes + ';\n'
                'const ATTR: &str = r' + hashes + '"x" #[cfg(test)] mod hidden { "y"' + hashes + ';\n'
                'const BR: &[u8] = br##"pub use decoy::raw_bytes;"##;\n'
                'const CR: &std::ffi::CStr = cr#"pub use decoy::raw_c;"#;\n'
                "const CH: char = '\\'';\nconst BC: u8 = b'\\x70';\n"
                "fn lifetime<'a>(p: &'a str) -> &'a str { p }\n"
                "fn r#pub() {}\n// pub use decoy::line;\n"
                "/* outer /* pub use decoy::nested; */ pub use decoy::block; */\n")
    trees = ("util :: load", "util :: { load as read_index , other , }", "util :: *")
    uses = ("pub\nuse util::load;\n",
            "pub(\ncrate\n)\nuse util::{load as read_index, /* split */ other,};\n",
            "pub ( super ) use util::*;\n")
    for declaration, tree in zip(uses, trees):
        src = literals + declaration
        root = fake({"c/src/lib.rs": src})
        errors = check(root, {"entries": []})
        expect(len(errors) == 1 and "re-export allowlist" in errors[0], errors)
        expect("use %s;" % tree in errors[0], errors)
        write_reexport_fixture_allowlist(root, [{"file": "c/src/lib.rs", "use": tree,
                                                "reason": "Fixture public API."}])
        expect(check(root, {"entries": []}) == [], check(root, {"entries": []}))


def regression_inventory_reexport_allowlist_cannot_exempt_resolved_or_unused_use():
    """Regression: resolvable or unused re-exports bypassed the refusal gate."""
    root = fake({"c/src/lib.rs": "mod util { pub fn load() {} }\npub use util::load as l;\n"})
    errors = check(root, {"entries": []})
    expect(any("re-export allowlist" in e for e in errors), errors)


def regression_inventory_reexport_allowlist_skips_only_test_source():
    """Regression: test-only exports required review or hid production ones."""
    root = fake({
        "c/src/lib.rs": ('#[cfg(test)] mod tests;\n'
                         '#[cfg(test)] pub use decoy::load;\n'
                         '#[cfg(test)] mod inline { pub use decoy::load; }\n'),
        "c/src/tests.rs": "pub use decoy::load;\n",
    })
    expect(check(root, {"entries": []}) == [], check(root, {"entries": []}))
    with open(os.path.join(root, "c/src/lib.rs"), "a", encoding="utf-8") as fh:
        fh.write('#[cfg(any(test, feature = "production"))]\npub use util::load;\n')
    errors = check(root, {"entries": []})
    expect(len(errors) == 1 and "re-export allowlist" in errors[0], errors)


def regression_inventory_reexport_allowlist_stale_entry_refuses():
    """Regression: an obsolete allowlist entry silently authorized old code."""
    root = fake({"c/src/lib.rs": ""})
    write_reexport_fixture_allowlist(root, [{"file": "c/src/lib.rs", "use": "util :: load",
                                            "reason": "Removed fixture API."}])
    errors = check(root, {"entries": []})
    expect(any("re-export allowlist" in e and "stale entry" in e for e in errors), errors)


def regression_inventory_reexport_allowlist_duplicate_entry_refuses():
    """Regression: duplicate review keys obscured the authoritative reason."""
    root = fake({"c/src/lib.rs": "pub use util::load;\n"})
    entry = {"file": "c/src/lib.rs", "use": "util :: load", "reason": "Fixture API."}
    # Normalize before checking duplicates, including differently spaced keys.
    for duplicate in (entry, dict(entry, use="util::load")):
        write_reexport_fixture_allowlist(root, [entry, duplicate])
        errors = check(root, {"entries": []})
        expect(any("re-export allowlist" in e and "duplicate entry" in e for e in errors), errors)


def regression_inventory_reexport_allowlist_requires_reason_and_schema():
    """Regression: malformed or reasonless allowlists permitted public imports."""
    root = fake({"c/src/lib.rs": "pub use util::load;\n"})
    path = os.path.join(root, REEXPORT_ALLOWLIST)
    for entry in ({"file": "c/src/lib.rs", "use": "util :: load"},
                  {"file": "c/src/lib.rs", "use": "util :: load", "reason": " "},
                  {"file": "c/src/lib.rs", "use": "util :: load", "reason": 42},
                  {"file": "c/src/lib.rs"}):
        write_reexport_fixture_allowlist(root, [entry])
        errors = check(root, {"entries": []})
        expect(any("re-export allowlist" in e for e in errors), errors)
    for contents in ('{', '[]', '{"entries": []}', '{"version": 1, "entries": {}}'):
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(contents)
        errors = check(root, {"entries": []})
        expect(any("re-export allowlist" in e for e in errors), errors)


def compiled_reexport_fixture(files, test_cfg=False, extra_cfg=()):
    """Build a real Rust fixture and return its classified inventory errors."""
    import subprocess

    bootstrap = (
        "#![allow(dead_code, unused_imports, unused_variables)]\n"
        "pub struct ManagedReadCursor;\n"
        "impl ManagedReadCursor { pub fn open(_: &std::path::Path) -> Self { Self } }\n")
    files = dict(files)
    files["c/src/lib.rs"] = bootstrap + files["c/src/lib.rs"]
    root = fake(files)
    cmd = ["rustc", "--crate-name", "inventory_reexport_fixture", "--crate-type", "lib",
           "--edition=2021", "--emit=metadata", "--out-dir", root, "c/src/lib.rs"]
    for value in extra_cfg:
        cmd.extend(["--cfg", value])
    for cfg in ([], ["--cfg", "test"]) if test_cfg else ([],):
        try:
            compiled = subprocess.run(cmd + cfg, cwd=root, capture_output=True, text=True, timeout=30)
        except OSError as e:
            raise AssertionError("rustc is required for the re-export fixture: %s" % e) from e
        expect(compiled.returncode == 0, (files, compiled.stderr))
    manifest = classify(root, {("hash", "ManagedReadCursor::open"): MANAGED,
                               ("load", "fs::read"): OOF})
    return check(root, manifest)


REEXPORT_RAW = "pub fn load(p: &std::path::Path) { let _ = std::fs::read(p); }\n"
REEXPORT_HASH = ("fn hash(p: &std::path::Path) { "
                 "let _c = crate::ManagedReadCursor::open(p); %s; }\n")


def regression_inventory_reexport_allowlist_raw_string_cannot_hide_module():
    """Regression: a cfg/mod decoy in a raw string excluded a production file."""
    hashes = "#" * 100
    for declaration in ("mod a;\n", '#[path = "a.rs"] pub ( crate ) mod a;\n'):
        errors = compiled_reexport_fixture({
            "c/src/lib.rs": ('const S: &str = r' + hashes
                             + '"x"\n#[cfg(test)] mod a;\n"' + hashes + ';\n'
                             + declaration),
            "c/src/a.rs": "pub use std::fs::read;\n",
        })
        expect(any("re-export allowlist" in e and "c/src/a.rs" in e for e in errors), errors)


def regression_inventory_reexport_allowlist_root_imports_refuse():
    """Regression: root pub-use load imports bypassed the re-export heuristic."""
    for imports in ("use crate::load;\n", "use crate::{load};\n", "use super::load;\n"):
        errors = compiled_reexport_fixture({
            "c/src/lib.rs": "pub mod util;\npub use util::load;\nmod caller;\n",
            "c/src/util.rs": REEXPORT_RAW,
            "c/src/caller.rs": imports + REEXPORT_HASH % "load(p)",
        })
        expect(any("re-export allowlist" in e for e in errors), (imports, errors))


def regression_inventory_reexport_allowlist_path_module_refuses():
    """Regression: #[path] and globs of its module bypassed file-stem owners."""
    for imports, call in (
        ("", "crate::helpers::load(p)"),
        ("use crate::helpers::load;\n", "load(p)"),
        ("use crate::helpers::*;\n", "load(p)"),
        ("use helpers::a as b;\nuse crate::helpers;\n", "b::load(p)"),
    ):
        exported = ("pub use crate::util as a;\n" if "b::" in call
                    else "pub use crate::util::load;\n")
        errors = compiled_reexport_fixture({
            "c/src/lib.rs": 'pub mod util;\n#[path = "bridge.rs"]\nmod helpers;\nmod caller;\n',
            "c/src/util.rs": REEXPORT_RAW,
            "c/src/bridge.rs": exported,
            "c/src/caller.rs": imports + REEXPORT_HASH % call,
        })
        expect(any("re-export allowlist" in e for e in errors), (imports, call, errors))


def regression_inventory_reexport_allowlist_unrenamed_and_glob_refuse():
    """Regression: unrenamed and glob imports skipped re-export validation."""
    for exported, imports, call in (
        ("pub use crate::util as a;\n", "use crate::outer::a;\n", "a::load(p)"),
        ("pub use crate::util as a;\n", "use crate::outer::*;\n", "a::load(p)"),
        ("pub use crate::util::load as read_index;\n", "use crate::outer::read_index;\n", "read_index(p)"),
        ("pub use crate::util::load as read_index;\n", "use crate::outer::*;\n", "read_index(p)"),
        ("pub use crate::util::load;\n", "use crate::outer::load;\n", "load(p)"),
        ("pub use crate::util::load;\n", "use crate::outer::*;\n", "load(p)"),
    ):
        errors = compiled_reexport_fixture({
            "c/src/lib.rs": "pub mod util;\nmod outer;\nmod caller;\n",
            "c/src/util.rs": REEXPORT_RAW,
            "c/src/outer.rs": exported,
            "c/src/caller.rs": imports + REEXPORT_HASH % call,
        })
        expect(any("re-export allowlist" in e for e in errors), (exported, imports, errors))


def regression_inventory_reexport_allowlist_long_visibility_refuses():
    """Regression: a long pub(in path) visibility escaped the look-behind."""
    ancestor = "ancestor_" + "long_" * 20 + "scope"
    body = ("pub mod %s {\nmod outer {\n" % ancestor
            + "pub(in crate::%s)\nuse crate::util::load as l;\n" % ancestor
            + REEXPORT_HASH % "self::l(p)" + "}\n}\n")
    errors = compiled_reexport_fixture({"c/src/lib.rs": "pub mod util;\n" + body,
                                        "c/src/util.rs": REEXPORT_RAW})
    expect(any("re-export allowlist" in e for e in errors), errors)


def regression_inventory_reexport_allowlist_decoy_name_refuses():
    """Regression: a same-name decoy function exempted the real re-export."""
    errors = compiled_reexport_fixture({
        "c/src/lib.rs": ("pub mod util;\npub use util::load as read_index;\n"
                          "mod decoy { pub fn read_index(_: &std::path::Path) {} }\n"
                          + REEXPORT_HASH % "crate::read_index(p)"),
        "c/src/util.rs": REEXPORT_RAW,
    })
    expect(any("re-export allowlist" in e for e in errors), errors)


def regression_inventory_helper_walk_cfg_distinct_alias_bindings_refuse():
    """Regression: a test-only same-scope alias overwrote the production target."""
    for imports, call in (
        ("", "u::load(p)"),
        ("use u::load as read_index;\n", "read_index(p)"),
        ("use u::load;\n", "load(p)"),
        ("use u::*;\n", "load(p)"),
    ):
        errors = compiled_reexport_fixture({
            "c/src/lib.rs": "pub mod util;\nmod decoy;\nmod caller;\n",
            "c/src/util.rs": REEXPORT_RAW,
            "c/src/decoy.rs": "pub fn load(_: &std::path::Path) {}\n",
            "c/src/caller.rs": (
                "#[cfg(not(test))]\nuse crate::util as u;\n"
                "#[cfg(test)]\nuse crate::decoy as u;\n" + imports
                + REEXPORT_HASH % call),
        }, test_cfg=True)
        expect(any("unresolved use-alias chain (fail closed)" in e for e in errors), (imports, call, errors))


def regression_inventory_reexport_allowlist_cfg_comments_cannot_hide_production():
    """Regression: a comment's `test` hid production exports and modules."""
    attr = '#[cfg(all(feature = "production", /* test */))]\n'
    cases = (
        {"c/src/lib.rs": attr + "pub use std::fs::read;\n"},
        {"c/src/lib.rs": attr + "mod a { pub use std::fs::read; }\n"},
        {"c/src/lib.rs": attr + "mod a;\n",
         "c/src/a.rs": "pub use std::fs::read;\n"},
        {"c/src/lib.rs": attr + '#[path = "exports.rs"] mod a;\n',
         "c/src/exports.rs": "pub use std::fs::read;\n"},
    )
    for files in cases:
        errors = compiled_reexport_fixture(files, extra_cfg=('feature="production"',))
        expect(any("re-export allowlist (fail closed)" in e for e in errors), (files, errors))


def regression_inventory_reexport_allowlist_macro_payloads_cannot_hide_use():
    """Regression: macro visibility tokens hid a public use inside the payload."""
    unwrap = ('macro_rules! unwrap_pub {\n'
              '    (pub($($item:item)*)) => {$($item)*}\n'
              '}\n')
    invocations = (
        "unwrap_pub! { pub(pub use std::fs::read;) }\n",
        "unwrap_pub!(pub(pub use std::fs::read;));\n",
        "unwrap_pub![pub(pub use std::fs::read;)];\n",
        ('macro_rules! nested { ($($t:tt)*) => { unwrap_pub! { $($t)* } } }\n'
         'nested! { pub(pub use std::fs::read;) }\n'),
    )
    for invocation in invocations:
        errors = compiled_reexport_fixture({"c/src/lib.rs": unwrap + invocation})
        expect(any("re-export allowlist (fail closed)" in e for e in errors), (invocation, errors))


def regression_inventory_reexport_allowlist_macro_private_use_refuses():
    """Regression: non-public use in a macro payload bypassed public-use checks."""
    item_macro = 'macro_rules! items { ($($item:item)*) => {$($item)*} }\n'
    invocations = (
        "items! { use std::fs::read as read_index; }\n",
        "items!(use std::fs::read as read_index;);\n",
        "items![use std::fs::read as read_index;];\n",
    )
    for invocation in invocations:
        errors = compiled_reexport_fixture({"c/src/lib.rs": item_macro + invocation})
        expect(any("re-export allowlist (fail closed)" in e for e in errors), (invocation, errors))


def regression_inventory_reexport_allowlist_macro_definition_use_refuses():
    """Regression: a macro definition could introduce an unchecked import."""
    source = ('macro_rules! read_macro {\n'
              '    () => {{ use std::fs::read as read_index; }}\n'
              '}\n'
              'fn invoke() { read_macro!(); }\n')
    errors = compiled_reexport_fixture({"c/src/lib.rs": source})
    expect(any("re-export allowlist (fail closed)" in e for e in errors), errors)


def regression_inventory_reexport_allowlist_macro_use_requires_review():
    """Regression: macro imports need the same reviewed key as public imports."""
    source = ('macro_rules! read_macro {\n'
              '    () => {{ use std::fs::read as read_index; }}\n'
              '}\n')
    root = fake({"c/src/lib.rs": source})
    errors = check(root, {"entries": []})
    expect(any("re-export allowlist (fail closed)" in e for e in errors), errors)
    write_reexport_fixture_allowlist(root, [{
        "file": "c/src/lib.rs", "use": "std :: fs :: read as read_index",
        "reason": "Fixture macro imports the file reader.",
    }])
    expect(check(root, {"entries": []}) == [], check(root, {"entries": []}))


def self_test():
    global check, fake

    tests = [v for k, v in sorted(globals().items()) if k.startswith("regression_") and callable(v)]
    failed = 0
    checked = [0]
    checked_roots, fixture_roots = set(), set()
    scan_only = 0
    corpus_errors = []
    original_check = check
    original_fake = fake

    def compare_helper_passes(root, entries, ops, texts, fns):
        scanned = {key(o): o for o in ops}
        main_errors = set(helper_errors(entries, scanned, texts, fns))
        union_errors = set(union_helper_errors(entries, scanned, texts, fns))
        if not main_errors <= union_errors:
            corpus_errors.append((root, "union dropped main reports", sorted(main_errors - union_errors)))

    def capture_fixture(files):
        root = original_fake(files)
        fixture_roots.add(root)
        return root

    def regression_inventory_helper_walk_union_preserves_main_corpus(root, manifest):
        """Regression: the chain pass must never remove a main-pass report.

        Check every fixture invocation, including loop variants and exemptions,
        with identical scanned inputs for main alone and the two-pass union;
        scan-only fixture roots are checked after the corpus finishes.
        """
        ops, texts, fns = scan(root)
        compare_helper_passes(root, manifest.get("entries", []), ops, texts, fns)
        checked[0] += 1
        checked_roots.add(root)
        return original_check(root, manifest)

    check = regression_inventory_helper_walk_union_preserves_main_corpus
    fake = capture_fixture
    try:
        for t in tests:
            try:
                t()
                print("ok   " + t.__name__)
            except AssertionError as e:
                failed += 1
                print("FAIL %s: %s" % (t.__name__, e))
        for root in sorted(fixture_roots - checked_roots):
            ops, texts, fns = scan(root)
            entries = [dict(o, **(MANAGED if o["op"] in MANAGED_OPS else OOF)) for o in ops]
            compare_helper_passes(root, entries, ops, texts, fns)
            scan_only += 1
    finally:
        check = original_check
        fake = original_fake
    try:
        expect(checked[0] > 0, "no fixtures checked")
        expect(not corpus_errors, corpus_errors)
        print("ok   regression_inventory_helper_walk_union_preserves_main_corpus "
              "(%d fixture checks + %d scan-only roots)" % (checked[0], scan_only))
    except AssertionError as e:
        failed += 1
        print("FAIL regression_inventory_helper_walk_union_preserves_main_corpus: %s" % e)
    print("%d passed, %d failed" % (len(tests) + 1 - failed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
