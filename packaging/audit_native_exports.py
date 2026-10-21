#!/usr/bin/env python3
"""Audit the dynamic exports of the Python extension module (#151).

The `_native` module installs ratarmount's SQLite system-call wrappers into
its bundled SQLite through a private-instance initializer whose safety rests
on that SQLite being private to the module: no `sqlite3_*` symbol may be
exported, so nothing outside the module can reach the instance before the
module is published. This script checks the final artifact (a repaired wheel
or an installed `_native` shared object):

* the `_native` extension module may export only the symbols in ALLOWED;
* no shared object in the wheel (grafted libraries included) may export a
  `sqlite3*` symbol.

Linux: `nm -D --defined-only`. macOS: `nm -gU`, with the leading underscore
removed. Exit status: 0 clean, 1 offending exports (each is printed),
2 usage or tool errors (a self-test whose C compiler fails included; `CC`
may carry arguments).

Usage:
  audit_native_exports.py FILE...   (FILE: a .whl or a shared object)
  audit_native_exports.py --self-test

Stdlib only; runs on Python 3.9.
"""
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import zipfile

# Every export the extension module may have. A new one fails the audit until
# it is reviewed and listed here with where it comes from.
ALLOWED = frozenset({
    # The CPython module entry point.
    "PyInit__native",
    # bzip2-sys: `#[no_mangle]` callback the bundled libbz2 calls.
    "bz_internal_error",
    # rust-lzo: `#[no_mangle] pub extern "C"` functions.
    "lzo1x_1_compress",
    "lzo1x_decompress_safe",
})


class AuditError(Exception):
    """A tool or input problem (exit status 2)."""


def is_sqlite(name):
    return name.lower().startswith("sqlite3")


def is_native_module(member):
    base = member.rsplit("/", 1)[-1]
    return base.startswith("_native.") and base.endswith((".so", ".dylib", ".pyd"))


def is_shared_object(member):
    base = member.rsplit("/", 1)[-1]
    return base.endswith((".so", ".dylib")) or ".so." in base


def verdict(names, allowed):
    """Offending exports among `names` (already normalized). `allowed` is the
    allowlist for the extension module, or None for another shared object,
    where only SQLite exports offend."""
    offenders = []
    for name in sorted(set(names)):
        if is_sqlite(name):
            offenders.append("exports SQLite symbol " + name)
        elif allowed is not None and name not in allowed:
            offenders.append("exports unexpected symbol " + name)
    return offenders


def parse_nm(output, macho):
    """Defined external symbol names from `nm` output."""
    names = []
    for line in output.splitlines():
        fields = line.split()
        # A header line: "FILE:" or, for a universal (fat) Mach-O,
        # "FILE (for architecture arm64):".
        if len(fields) < 2 or line.rstrip().endswith(":"):
            continue
        name = fields[-1].split("@", 1)[0]
        if macho and name.startswith("_"):
            name = name[1:]
        if name:
            names.append(name)
    return names


def is_macho(path):
    with open(path, "rb") as f:
        magic = f.read(4)
    return magic in (
        b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce",
        b"\xca\xfe\xba\xbe",
    )


def exports(path):
    nm = shutil.which("nm")
    if nm is None:
        raise AuditError("nm is not installed")
    macho = is_macho(path)
    command = [nm, "-gU", path] if macho else [nm, "-D", "--defined-only", path]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            universal_newlines=True)
    if result.returncode != 0:
        raise AuditError("{}: {}".format(" ".join(command), result.stderr.strip()))
    return parse_nm(result.stdout, macho)


def audit_object(path, allowed):
    return verdict(exports(path), allowed)


def audit_wheel(path):
    """(member, offender) pairs of every shared object in the wheel."""
    found = []
    saw_native = False
    with tempfile.TemporaryDirectory() as tmp, zipfile.ZipFile(path) as wheel:
        for member in wheel.namelist():
            if not is_shared_object(member) and not is_native_module(member):
                continue
            native = is_native_module(member)
            saw_native = saw_native or native
            extracted = wheel.extract(member, tmp)
            for offender in audit_object(extracted, ALLOWED if native else None):
                found.append((member, offender))
    if not saw_native:
        raise AuditError("{}: no _native extension module in the wheel".format(path))
    return found


def audit(path):
    if path.endswith(".whl"):
        return audit_wheel(path)
    return [(os.path.basename(path), o) for o in audit_object(path, ALLOWED)]


def compiler_command(value):
    """The compiler command line from `CC` (which may carry arguments)."""
    return shlex.split(value) or ["cc"]


def build(cc, tmp, name, symbols):
    """A real shared object exporting exactly `symbols`. The export list is
    explicit (an ELF version script or a Mach-O exported-symbols list), as a
    cdylib's is, so linker-defined symbols (`_init`, `_end`, ...) that some
    toolchains leave exported cannot fail the clean rows. A compiler failure
    is an AuditError (exit status 2)."""
    source = os.path.join(tmp, name + ".c")
    with open(source, "w") as f:
        for symbol in symbols:
            f.write("int {}(void) {{ return 0; }}\n".format(symbol))
    exports_file = os.path.join(tmp, name + ".exports")
    with open(exports_file, "w") as f:
        if sys.platform == "darwin":
            f.write("".join("_{}\n".format(symbol) for symbol in symbols))
        else:
            f.write("{{ global: {} local: *; }};\n".format(
                "".join("{}; ".format(symbol) for symbol in symbols)))
    flag = ("-Wl,-exported_symbols_list," if sys.platform == "darwin"
            else "-Wl,--version-script=") + exports_file
    out = os.path.join(tmp, name)
    command = cc + ["-shared", "-fPIC", flag, "-o", out, source]
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                universal_newlines=True)
    except OSError as error:
        raise AuditError("{}: {}".format(" ".join(command), error))
    if result.returncode != 0:
        raise AuditError("{}: exit {}: {}".format(
            " ".join(command), result.returncode, result.stderr.strip()))
    return out


def self_test():
    """Verdict rows, then (with a C compiler) real shared objects and wheels.
    Returns a list of failure descriptions."""
    failures = []

    def check(label, got, want):
        if got != want:
            failures.append("{}: got {!r}, want {!r}".format(label, got, want))

    check("clean", verdict(sorted(ALLOWED), ALLOWED), [])
    check("sqlite", verdict(["PyInit__native", "sqlite3_vfs_find"], ALLOWED),
          ["exports SQLite symbol sqlite3_vfs_find"])
    check("unexpected", verdict(["PyInit__native", "ratarmount_extra"], ALLOWED),
          ["exports unexpected symbol ratarmount_extra"])
    check("grafted", verdict(["archive_read_new", "sqlite3_open_v2"], None),
          ["exports SQLite symbol sqlite3_open_v2"])
    check("nm elf", parse_nm("0000 T PyInit__native\n0001 T foo@@V_1\n", False),
          ["PyInit__native", "foo"])
    check("nm macho", parse_nm("0000 T _PyInit__native\n0001 T _sqlite3_malloc\n", True),
          ["PyInit__native", "sqlite3_malloc"])
    check("nm fat", parse_nm(
        "\n/x/_native.so (for architecture arm64):\n0000 T _PyInit__native\n"
        "\n/x/_native.so (for architecture x86_64):\n0000 T _PyInit__native\n", True),
        ["PyInit__native", "PyInit__native"])
    check("cc words", compiler_command("gcc -m64"), ["gcc", "-m64"])
    check("cc default", compiler_command(""), ["cc"])
    try:
        build([sys.executable, "-c", "import sys; sys.exit(1)"], tempfile.gettempdir(),
              "_native.never.so", ["PyInit__native"])
        failures.append("failing compiler: no AuditError")
    except AuditError:
        pass

    cc = compiler_command(os.environ.get("CC", ""))
    if shutil.which(cc[0]) is None or shutil.which("nm") is None:
        print("skip: no C compiler or nm; real-object rows not run")
        return failures

    def wheel(tmp, name, members):
        path = os.path.join(tmp, name)
        with zipfile.ZipFile(path, "w") as z:
            for arcname, source in members:
                z.write(source, arcname)
        return path

    with tempfile.TemporaryDirectory() as tmp:
        clean = build(cc, tmp, "_native.clean.so", ["PyInit__native", "bz_internal_error"])
        # A non-`libversion` SQLite export: the runtime own-handle probe looks
        # only for sqlite3_libversion, so this is what the audit adds.
        leaky = build(cc, tmp, "_native.leaky.so", ["PyInit__native", "sqlite3_vfs_find"])
        extra = build(cc, tmp, "_native.extra.so", ["PyInit__native", "ratarmount_extra"])
        grafted = build(cc, tmp, "libarchive.so.13", ["archive_read_new"])
        grafted_sqlite = build(cc, tmp, "libsqlite3.so.0", ["sqlite3_open_v2"])
        check("object clean", audit(clean), [])
        check("object leaky", audit(leaky),
              [("_native.leaky.so", "exports SQLite symbol sqlite3_vfs_find")])
        check("object extra", audit(extra),
              [("_native.extra.so", "exports unexpected symbol ratarmount_extra")])
        native = "ratarmount_rs/_native.abi3.so"
        check("wheel clean", audit(wheel(tmp, "clean.whl", [
            (native, clean), ("ratarmount_rs.libs/libarchive.so.13", grafted)])), [])
        check("wheel leaky", audit(wheel(tmp, "leaky.whl", [(native, leaky)])),
              [(native, "exports SQLite symbol sqlite3_vfs_find")])
        check("wheel grafted sqlite", audit(wheel(tmp, "grafted.whl", [
            (native, clean), ("ratarmount_rs.libs/libsqlite3.so.0", grafted_sqlite)])),
              [("ratarmount_rs.libs/libsqlite3.so.0", "exports SQLite symbol sqlite3_open_v2")])
        try:
            audit(wheel(tmp, "empty.whl", [("ratarmount_rs.libs/libarchive.so.13", grafted)]))
            failures.append("wheel without _native: no error")
        except AuditError:
            pass
    return failures


def main(argv):
    if argv == ["--self-test"]:
        try:
            failures = self_test()
        except (AuditError, OSError, zipfile.BadZipFile) as error:
            print("audit_native_exports self-test: tool error: {}".format(error),
                  file=sys.stderr)
            return 2
        for failure in failures:
            print("audit_native_exports self-test: " + failure, file=sys.stderr)
        if not failures:
            print("audit_native_exports self-test: ok")
        return 1 if failures else 0
    if not argv or any(a.startswith("-") for a in argv):
        print(__doc__, file=sys.stderr)
        return 2
    status = 0
    for path in argv:
        try:
            found = audit(path)
        except (AuditError, OSError, zipfile.BadZipFile) as error:
            print("audit_native_exports: {}: {}".format(path, error), file=sys.stderr)
            return 2
        for member, offender in found:
            print("audit_native_exports: {}: {}: {}".format(path, member, offender),
                  file=sys.stderr)
            status = 1
        if not found:
            print("audit_native_exports: {}: ok".format(path))
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
