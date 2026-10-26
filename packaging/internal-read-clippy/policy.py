#!/usr/bin/env python3
"""Production Clippy dispatcher and manifest compiler.

Operation identity comes only from the patched Clippy lookup events. This module
does not parse Rust, resolve paths or classify open flags/foreign symbols.
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import tomllib

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SCHEMA = 1
TOOLCHAIN = "1.98.0"
PREFIX = "internal-read:v1 "
LINTS = ("clippy::disallowed_methods", "clippy::disallowed_types", "clippy::disallowed_macros")


class PolicyError(Exception):
    pass


def source_leaf(row):
    primary = row.get("span", {})
    leaf = row.get("source_leaf_span", {})
    file = primary.get("file")
    normalized = Path(os.path.normpath(file)) if isinstance(file, str) else None
    if (row.get("source_leaf_observed") is not True or not isinstance(file, str)
            or normalized.is_absolute() or (normalized.parts and normalized.parts[0] == "..")
            or file != leaf.get("file")):
        raise PolicyError("unowned inventory primary span outside its compiler-observed source leaf")
    if not all(isinstance(s.get(k), int) for s in (primary, leaf) for k in ("lo", "hi")):
        raise PolicyError("malformed compiler source-leaf span")
    if not (leaf["lo"] <= primary["lo"] <= primary["hi"] <= leaf["hi"]):
        raise PolicyError("inventory primary span is not contained in its reviewed source leaf")


def canonical(value):
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def json_lines(path):
    """Reject partial/truncated reports, including a missing final newline."""
    data = Path(path).read_text()
    if not data or not data.endswith("\n"):
        raise PolicyError(f"missing or truncated report: {path}")
    try:
        rows = [json.loads(line) for line in data.splitlines()]
    except (ValueError, TypeError) as error:
        raise PolicyError(f"malformed report {path}: {error}") from error
    if any(not isinstance(row, dict) for row in rows):
        raise PolicyError(f"non-object report row: {path}")
    return rows


def cargo(arguments, *, cwd=ROOT, env=None, **kwargs):
    effective = os.environ.copy() if env is None else env.copy()
    effective["CARGO_BUILD_JOBS"] = "2"
    return subprocess.run(
        ["flock", "/tmp/muse-cargo.lock", "cargo", *arguments],
        cwd=cwd, env=effective, check=True, **kwargs,
    )


def targets(metadata, arguments):
    packages = {p["id"]: p for p in metadata["packages"]}
    names = None
    if "-p" in arguments:
        names = {arguments[arguments.index("-p") + 1]}
    result = []
    for member in metadata["workspace_members"]:
        package = packages[member]
        if names is not None and package["name"] not in names:
            continue
        for target in package["targets"]:
            kinds = set(target["kind"])
            is_lib = bool(kinds & {"lib", "rlib", "cdylib", "staticlib", "dylib", "proc-macro"})
            is_bin = kinds == {"bin"}
            if not ((is_lib and "--lib" in arguments) or (is_bin and "--bins" in arguments)):
                continue
            row = {
                "package": package["name"],
                "crate": target["name"].replace("-", "_"),
                "source": str(Path(target["src_path"]).resolve()),
                "crate_types": sorted(target["crate_types"]),
            }
            row["key"] = digest(canonical(row).encode())[:20]
            result.append(row)
    if not result or len({r["key"] for r in result}) != len(result):
        raise PolicyError("empty or ambiguous production target selection")
    return sorted(result, key=lambda r: r["key"])


def rust_argument(arguments, flag):
    values = []
    for i, argument in enumerate(arguments):
        if argument == flag:
            if i + 1 == len(arguments):
                raise PolicyError(f"missing compiler argument after {flag}")
            values.append(arguments[i + 1])
        elif argument.startswith(flag + "="):
            values.append(argument[len(flag) + 1:])
    return values


def nonproduction_targets(metadata):
    return [{"source": str(Path(target["src_path"]).resolve()),
             "crate": target["name"].replace("-", "_"),
             "crate_types": sorted(target["crate_types"])}
            for package in metadata["packages"] if package["id"] in metadata["workspace_members"]
            for target in package["targets"]
            if set(target["kind"]) & {"custom-build", "test", "example", "bench"}]


def dispatch(arguments):
    """RUSTC_WRAPPER: inject policy only into exact Cargo production tuples."""
    settings = json.loads(Path(os.environ["INTERNAL_READ_DISPATCH"]).read_text())
    if not arguments:
        raise PolicyError("empty rustc wrapper invocation")
    # cargo-clippy normally supplies clippy-driver, rustc, rustc arguments.
    clippy = Path(arguments[0]).name.startswith("clippy-driver")
    rustc = arguments[1] if clippy else arguments[0]
    rustargs = arguments[2:] if clippy else arguments[1:]
    sources = [str(Path(a).resolve()) for a in rustargs if a.endswith(".rs")]
    crate = rust_argument(rustargs, "--crate-name")
    crate_types = sorted(t for a in rust_argument(rustargs, "--crate-type") for t in a.split(","))
    selected = [r for r in settings["targets"] if sources == [r["source"]]
                and crate == [r["crate"]] and crate_types == r["crate_types"]
                and "--test" not in rustargs]
    if len(selected) > 1:
        raise PolicyError("ambiguous compiler target")
    known_nonproduction = "--test" in rustargs or any(
        sources == [r["source"]] and crate == [r["crate"]] and crate_types == r["crate_types"]
        for r in settings.get("nonproduction_targets", []))
    if any(r["source"] in sources for r in settings["targets"]) and not selected and not known_nonproduction:
        raise PolicyError(f"unexpected selected compiler tuple: {sources}, {crate}, {crate_types}")
    env = os.environ.copy()
    upstream_clippy_args = env.get("CLIPPY_ARGS")
    for variable in ("CLIPPY_ARGS", "CLIPPY_CONF_DIR", "INTERNAL_READ_REPORT", "INTERNAL_READ_CONFIG"):
        env.pop(variable, None)
    if selected:
        row = selected[0]
        suffixes = [a.split("=", 1)[1] for a in rust_argument(rustargs, "-C")
                    if a.startswith("extra-filename=")]
        if len(suffixes) != 1:
            raise PolicyError("selected compiler target has no unique artifact suffix")
        env.update(
            CLIPPY_CONF_DIR=settings["config_dir"],
            INTERNAL_READ_ROOT=settings["root"],
            INTERNAL_READ_CONFIG=settings["config"],
            INTERNAL_READ_REPORT=str(Path(settings["reports"]) / (row["key"] + suffixes[0] + ".jsonl")),
            RUSTC_BOOTSTRAP="1",
        )
        if upstream_clippy_args is not None:
            env["CLIPPY_ARGS"] = upstream_clippy_args
        env["LD_LIBRARY_PATH"] = settings["compiler_libraries"] + os.pathsep + env.get("LD_LIBRARY_PATH", "")
        flags = ["--cfg", "internal_read_inventory", "--check-cfg=cfg(internal_read_inventory)",
                 "-D", "warnings", "-D", "unfulfilled_lint_expectations",
                 "-F", "unused_macros"]
        for lint in LINTS:
            flags.extend(["--force-warn" if settings["mode"] == "collection" else "-D", lint])
        command = [settings["driver"], rustc, *rustargs, *flags]
    else:
        command = [rustc, *rustargs]
    os.execvpe(command[0], command, env)


def metadata_reason(reason):
    if not isinstance(reason, str) or not reason.startswith(PREFIX):
        raise PolicyError("inventory event has no literal internal-read:v1 reason")
    try:
        value = json.loads(reason[len(PREFIX):])
    except ValueError as error:
        raise PolicyError(f"invalid expectation JSON: {error}") from error
    for field in ("id", "item", "disposition", "category", "reason"):
        if not isinstance(value.get(field), str) or not value[field].strip():
            raise PolicyError(f"missing expectation metadata: {field}")
    creation = value.get("creation")
    if not isinstance(creation, dict) or any(not isinstance(creation.get(k), str)
                                            or not creation[k].strip() for k in ("policy", "basis")):
        raise PolicyError("creation requires reviewed policy and basis")
    return value


def validate_report(path):
    rows = json_lines(path)
    if any(r.get("schema") != SCHEMA for r in rows):
        raise PolicyError(f"unsupported compiler report schema: {path}")
    if (rows[-1].get("kind") != "complete" or not rows[-1].get("success")
            or not all(rows[-1].get(k) for k in ("syntax_complete", "expanded_complete", "hir_complete"))):
        raise PolicyError(f"missing successful compiler completion: {path}")
    if any(r.get("kind") == "violation" for r in rows):
        raise PolicyError(f"compiler syntax policy violation: {path}")
    if (not any(r.get("kind") == "syntax_loaded" and r.get("scope") == "crate" for r in rows)
            or sum(r.get("kind") == "expansion_complete" for r in rows) != 1
            or sum(r.get("kind") == "hir_complete" for r in rows) != 1):
        raise PolicyError(f"missing compiler phase report: {path}")
    return rows


def validate_config(metadata):
    config = json.loads((HERE / "policy.json").read_text())
    if config.get("allowed_extern_module") != "ratarmount_formats_libarchive::ffi":
        raise PolicyError("N2 requires exactly the one reviewed compiler module")
    members = {p["name"] for p in metadata["packages"] if p["id"] in metadata["workspace_members"]}
    if sorted(members) != sorted(config["classified_packages"]):
        raise PolicyError("workspace package matrix changed; review N4 classification")
    if len(config["restricted_packages"]) != 40 or not set(config["restricted_packages"]) <= members:
        raise PolicyError("invalid reviewed N4 package set")
    files = config["reviewed_target_files"]
    if len({r["file"] for r in files}) != len(files):
        raise PolicyError("duplicate N4 file exception")
    for row in files:
        path = Path(row["file"])
        if path.is_absolute() or ".." in path.parts or any(not row.get(k) for k in ("reviewer", "provenance", "reason")):
            raise PolicyError("N4 exceptions require exact relative files and review metadata")
        if not (ROOT / path).is_file():
            raise PolicyError(f"stale N4 reviewed file: {path}")
    exceptions = config["include_exceptions"]
    if len(exceptions) != 1 or exceptions[0]["file"] != "ratarmount-csi/src/lib.rs" or exceptions[0]["item"] != "ratarmount_csi::csi" or not exceptions[0].get("reason"):
        raise PolicyError("include requires the exact reviewed CSI source-file/item exception")


def manifest(reports, header, journal_exemptions=()):
    """Canonical identities never contain compiler byte positions or file paths."""
    entries = {}
    ids = {}
    journal_rules = {(r["path"], r["reason"]) for r in
                     tomllib.loads((ROOT / "clippy.toml").read_text())["disallowed-methods"]
                     if not r["reason"].startswith("inventory-op:")}
    journal = {}
    reason_owners = {}
    for approval in journal_exemptions:
        if approval.get("journal_exemption") is not True:
            raise PolicyError("journal exemption requires an explicit manifest flag")
        fields = ("item", "reason", "lint", "resolved", "configured_path", "rule_reason")
        if any(not isinstance(approval.get(field), str) or not approval[field] for field in fields):
            raise PolicyError("journal exemption requires an item, reason and exact resolved lookup fields")
        if (approval["configured_path"], approval["rule_reason"]) not in journal_rules:
            raise PolicyError("journal exemption is not an independent root Clippy rule")
        if approval["lint"] != "clippy::disallowed_methods":
            raise PolicyError("journal exemption requires the exact disallowed-methods lint")
        key = (approval["item"], approval["reason"])
        if key in journal:
            raise PolicyError("duplicate journal exemption item/reason")
        if approval["reason"] in reason_owners and reason_owners[approval["reason"]] != approval["item"]:
            raise PolicyError("duplicate expectation reason on different items")
        reason_owners[approval["reason"]] = approval["item"]
        journal[key] = approval
    active_marks = set()
    observed_marks = set()
    for profile, report in reports:
        seen_source = set()
        seen_operations = set()
        rows = validate_report(report)
        owner_bindings = {}
        for row in rows:
            if row["kind"] != "source_owner":
                continue
            span = row.get("span", {})
            span_key = (span.get("file"), span.get("lo"), span.get("hi"))
            if not isinstance(row.get("owner"), str) or not row["owner"]:
                raise PolicyError("source item has no compiler owner")
            if span_key in owner_bindings and owner_bindings[span_key] != row["owner"]:
                raise PolicyError("conflicting compiler source item owners")
            owner_bindings[span_key] = row["owner"]
        for row in rows:
            if row["kind"] not in {"operation", "expectation", "include_exception"}:
                continue
            source_mark = row["kind"] == "expectation" and (
                row.get("source") is True or "native_active" in row)
            if source_mark:
                # Every pre-pruning source expectation needs approval, including
                # active marks which HIR may shadow with another lint level.
                # HIR and resolved operations still supply active ownership.
                owner_span = row.get("owner_span", {})
                owner_key = (owner_span.get("file"), owner_span.get("lo"), owner_span.get("hi"))
                owner = owner_bindings.get(owner_key, row.get("owner"))
                if not isinstance(owner, str) or not owner:
                    raise PolicyError("source expectation has no compiler item owner")
                if "<unresolved-impl>" in owner:
                    raise PolicyError("source expectation requires a resolved compiler impl owner")
                row = dict(row, active=False, owner=owner,
                           leaf_digest=digest(row["leaf"]["tokens"].encode()))
            if row["kind"] == "operation":
                source_leaf(row)
            if row["kind"] == "include_exception":
                reason = row["reason"]
                owner = row["owner"]
                key = (owner, reason)
                value = {"item": owner, "reason": reason, "kind": "include-exception",
                         "resolved": row["resolved"], "configured_path": row["configured_path"],
                         "multiplicity": 1, "profiles": []}
            else:
                reason = row.get("reason")
                owner = row["owner"]
                key = (owner, reason)
                if reason in reason_owners and reason_owners[reason] != owner:
                    raise PolicyError(f"duplicate expectation reason on different items: {owner}")
                reason_owners[reason] = owner
                approval = journal.get(key)
                if row.get("broad", False):
                    raise PolicyError(f"broad inventory expectation: {owner}: {reason}")
                if approval is not None:
                    if row.get("lint") != approval["lint"]:
                        raise PolicyError(f"journal expectation lint differs from manifest: {key}")
                    if row["kind"] == "operation":
                        if row.get("rule_reason", "").startswith("inventory-op:"):
                            raise PolicyError(f"journal exemption cannot approve an inventory rule: {key}")
                        for field in ("lint", "resolved", "configured_path", "rule_reason"):
                            if row.get(field) != approval[field]:
                                raise PolicyError(f"journal lookup differs from manifest field {field}: {key}")
                    value = {"item": owner, "reason": reason, "journal_exemption": True,
                             "native_observed": row["kind"] == "operation", "profiles": [],
                             "leaf_digest": row["leaf_digest"]}
                    for field in ("lint", "resolved", "configured_path", "rule_reason"):
                        value[field] = approval[field]
                else:
                    if (row["kind"] == "operation"
                            and not row.get("rule_reason", "").startswith("inventory-op:")):
                        raise PolicyError(f"unknown Clippy rule namespace or missing explicit journal exemption: {row.get('rule_reason')}: {key}")
                    review = metadata_reason(reason)
                    if owner != review["item"]:
                        raise PolicyError(f"declared owner differs from compiler owner: {review['id']}: {owner}")
                    if review["id"] in ids and ids[review["id"]] != key:
                        raise PolicyError(f"duplicate expectation id: {review['id']}")
                    ids[review["id"]] = key
                    value = {"item": owner, "reason": reason, "metadata": review,
                             "lint": row.get("lint"),
                             "native_observed": row["kind"] == "operation", "profiles": [],
                             "leaf_digest": row["leaf_digest"]}
                    if row["kind"] == "operation":
                        for field in ("lint", "resolved", "configured_path", "rule_reason"):
                            if not row.get(field):
                                raise PolicyError(f"missing resolved lookup field {field}: {review['id']}")
                            value[field] = row[field]
                if row["kind"] == "expectation" and row.get("active", True):
                    active_marks.add(key)
                    continue  # Every active protected expectation needs a lookup.
                if row["kind"] == "operation":
                    observed_marks.add(key)
                    value["multiplicity"] = 1
            seen = seen_source if source_mark else seen_operations
            if key in seen:
                raise PolicyError(f"multiple operations/marks under one expectation: {key[0]}")
            seen.add(key)
            if key in entries:
                previous = {k: v for k, v in entries[key].items() if k != "profiles"}
                current = {k: v for k, v in value.items() if k != "profiles"}
                # A source mark and its native lookup may reconcile only after
                # every shared identity/leaf field agrees. Never replace or
                # drop a conflicting source observation merely because the
                # other row has a native operation.
                if any(previous[k] != current[k] for k in previous.keys() & current.keys()
                       if k != "native_observed"):
                    raise PolicyError(f"conflicting compiler observations for {key[0]}")
                if previous.get("native_observed") is True and current.get("native_observed") is False:
                    continue  # Identity and leaf equality were checked above.
                profiles = (entries[key]["profiles"] if previous.get("native_observed") == current.get("native_observed")
                            else [])
                merged = dict(previous, **current)
                if "native_observed" in previous or "native_observed" in current:
                    merged["native_observed"] = (previous.get("native_observed", False)
                                                 or current.get("native_observed", False))
                merged["profiles"] = profiles
                entries[key] = merged
            else:
                entries[key] = value
            entries[key]["profiles"].append(profile)
    if active_marks - observed_marks:
        raise PolicyError(f"active expectation has no inventory lookup: {sorted(active_marks - observed_marks)}")
    for value in entries.values():
        value["profiles"] = sorted(set(value["profiles"]))
    return {"schema": SCHEMA, "policy": header, "entries": [entries[k] for k in sorted(entries)]}


def check_diff(candidate, approved):
    actual = canonical(candidate)
    expected = Path(approved).read_text()
    if actual != expected:
        sys.stderr.writelines(difflib.unified_diff(expected.splitlines(True), actual.splitlines(True),
                                                fromfile=str(approved), tofile="generated manifest"))
        raise PolicyError("internal-read manifest changed; review the candidate")


def run(args):
    started = time.monotonic()
    profiles = json.loads((HERE / "profiles.json").read_text())
    output = cargo([f"+{TOOLCHAIN}", "metadata", "--no-deps", "--format-version=1"],
                   capture_output=True, text=True)
    metadata = json.loads(output.stdout)
    validate_config(metadata)
    driver = Path(args.driver).resolve()
    if not driver.is_file():
        raise PolicyError(f"missing pinned Clippy driver: {driver}; run compiler/build.py")
    build = json.loads((driver.parents[2] / "build.json").read_text())
    toolchain = {k: build[k] for k in ("schema", "patch_digest", "source_digest", "component_digest", "compiler_revision")}
    sysroot = subprocess.run(["rustc", f"+{TOOLCHAIN}", "--print", "sysroot"],
                             check=True, capture_output=True, text=True).stdout.strip()
    policy_files = [HERE / "clippy.toml", HERE / "profiles.json", HERE / "policy.json", HERE / "diagnostics.py",
                    Path(__file__), HERE / "dispatch.py"]
    policy_digest = digest(b"".join(p.read_bytes() for p in policy_files))
    header = {"toolchain": toolchain, "configuration": policy_digest,
              "profiles": digest((HERE / "profiles.json").read_bytes())}
    cache_key = digest(canonical(header).encode() + (ROOT / "Cargo.lock").read_bytes())[:20]
    cache = Path(args.target_dir).resolve() / cache_key
    runs = []
    reports = []
    for mode in ("strict", "collection"):
        for label, arguments in profiles:
            directory = cache / mode / label
            directory.mkdir(parents=True, exist_ok=True)
            report_dir = cache / mode / "reports"
            report_dir.mkdir(parents=True, exist_ok=True)
            expected = targets(metadata, arguments)
            settings = {"targets": expected, "mode": mode, "driver": str(driver),
                        "nonproduction_targets": nonproduction_targets(metadata),
                        "root": str(ROOT), "config": str(HERE / "policy.json"),
                        "config_dir": str(HERE), "reports": str(report_dir),
                        "compiler_libraries": str(Path(sysroot) / "lib")}
            dispatch_file = directory / "dispatch.json"
            text = canonical(settings)
            if not dispatch_file.exists() or dispatch_file.read_text() != text:
                dispatch_file.write_text(text)
            env = os.environ.copy()
            env.update(CARGO_TARGET_DIR=str(cache / mode / "target"),
                       CARGO_PROFILE_DEV_DEBUG="0", CARGO_INCREMENTAL="0",
                       CLIPPY_CONF_DIR=str(HERE),
                       RUSTC_WRAPPER=str(HERE / "dispatch.py"),
                       INTERNAL_READ_DISPATCH=str(dispatch_file))
            before = time.monotonic()
            with (directory / "cargo.jsonl").open("w") as stdout, (directory / "cargo.stderr").open("w") as stderr:
                result = cargo([f"+{TOOLCHAIN}", "clippy", *arguments, "--message-format=json"],
                               env=env, stdout=stdout, stderr=stderr)
            messages = json_lines(directory / "cargo.jsonl")
            if not messages or messages[-1].get("reason") != "build-finished" or not messages[-1].get("success"):
                raise PolicyError(f"missing Cargo build-finished success: {mode}/{label}")
            for target in expected:
                artifacts = [m for m in messages if m.get("reason") == "compiler-artifact"
                             and str(Path(m["target"]["src_path"]).resolve()) == target["source"]
                             and m["target"]["name"].replace("-", "_") == target["crate"]
                             and sorted(m["target"]["crate_types"]) == target["crate_types"]]
                if len(artifacts) != 1:
                    raise PolicyError(f"missing/ambiguous production artifact: {mode}/{label}/{target['source']}")
                filenames = artifacts[0]["filenames"]
                metadata_files = [f for f in filenames if Path(f).suffix == ".rmeta"]
                if not metadata_files and "proc-macro" in target["crate_types"]:
                    metadata_files = [f for f in filenames if Path(f).suffix == ".so"]
                stems = {Path(f).stem.removeprefix("lib" + target["crate"])
                         for f in metadata_files}
                if len(stems) != 1 or not next(iter(stems)).startswith("-"):
                    raise PolicyError(f"unsupported production artifact shape: {artifacts[0]['filenames']}")
                report = report_dir / (target["key"] + next(iter(stems)) + ".jsonl")
                rows = validate_report(report)
                if mode == "collection":
                    spec = importlib.util.spec_from_file_location("internal_read_diagnostics", HERE / "diagnostics.py")
                    diagnostics = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(diagnostics)
                    diagnostics.validate_diagnostics(messages, target, rows, root=ROOT)
                    snapshot = directory / (target["key"] + ".jsonl")
                    shutil.copyfile(report, snapshot)
                    reports.append((label, snapshot))
            elapsed = time.monotonic() - before
            runs.append({"mode": mode, "profile": label, "seconds": elapsed,
                         "targets": len(expected), "exit": result.returncode})
            print(f"{mode}/{label}: {len(expected)} production targets, {elapsed:.2f}s", flush=True)
    approved = json.loads(Path(args.manifest).read_text())
    exemptions = [row for row in approved["entries"] if row.get("journal_exemption") is True]
    candidate = manifest(reports, header, journal_exemptions=exemptions)
    Path(args.candidate).write_text(canonical(candidate))
    attestation = {"schema": SCHEMA, "runs": runs, "seconds": time.monotonic() - started,
                   "cargo_lock": digest((ROOT / "Cargo.lock").read_bytes()),
                   "cache_key": cache_key, "candidate": str(Path(args.candidate).resolve())}
    Path(args.attestation).write_text(canonical(attestation))
    if not args.collect:
        check_diff(candidate, args.manifest)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--driver", default=Path.home() / ".cargo/internal-read-clippy/target/debug/clippy-driver")
    parser.add_argument("--target-dir", default=ROOT / "target/internal-read-policy")
    parser.add_argument("--manifest", default=HERE / "manifest.json")
    parser.add_argument("--candidate", default=ROOT / "target/internal-read-manifest.json")
    parser.add_argument("--attestation", default=ROOT / "target/internal-read-run.json")
    parser.add_argument("--collect", action="store_true", help="write a review candidate without accepting it")
    args = parser.parse_args()
    try:
        run(args)
    except (PolicyError, OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"internal-read policy: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
