#!/usr/bin/env python3
"""A1 native evidence, not an absent-name support claim.

check consumes combined, uncaptured Cargo/libtest output AND its exit code.
mutations proves attribution refusals on that same real local partial log.
root-controls runs isolated expected-failure probes; it never provisions mounts.
Strict manifests are fixed here. There is deliberately no manifest override.
"""

import argparse
from collections import Counter
import copy
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import stat
import subprocess
import sys
import tempfile
import tomllib
import uuid


PREFIX = "regression_235_part2_a1_"
CORE_MODULE = "native_fs::tests::"
INDEX_MODULE = "checked_open::native_fs::tests::"
LINUX_MODULE = INDEX_MODULE + "linux_tests::"
MACOS_MODULE = "checked_open::native_fs::macos_tests::"
WINDOWS_MODULE = "checked_open::native_fs::windows_tests::"

CORE = {
    CORE_MODULE + PREFIX + "identity_domains": ("core.identity_domains",),
    CORE_MODULE + PREFIX + "absent_capability_pending": ("core.absent_pending",),
}
SHARED = {
    INDEX_MODULE + PREFIX + "component_validation": ("shared.component_validation",),
    INDEX_MODULE + PREFIX + "existing_and_missing": ("shared.existing_and_missing",),
    INDEX_MODULE + PREFIX + "macos_objid_link_ids": ("seam.macos_objid_link_ids",),
    INDEX_MODULE + PREFIX + "macos_objid_low32_collision": ("seam.macos_objid_low32_collision",),
    INDEX_MODULE + PREFIX + "query_drift": ("seam.query_drift",),
}
LOCK_PARENT = INDEX_MODULE + PREFIX + "unix_queries_preserve_locks"
UNIX = {
    INDEX_MODULE + PREFIX + "parent_and_leaf_links": ("unix.parent_and_leaf_links",),
    LOCK_PARENT: ("unix.lock_parent",),
}
LOCK_ROLES = (
    "initial_locked", "during_queries_locked", "after_drop_locked",
    "after_rollback_released", "restarted_locked", "raw_alias_close_released",
)
LINUX = {
    LINUX_MODULE + PREFIX + "linux_tmpfs": ("linux.tmpfs_identity", "linux.tmpfs_names"),
    LINUX_MODULE + PREFIX + "linux_ext4": (
        "linux.ext4_sensitive_identity", "linux.ext4_sensitive_flags",
    ),
    LINUX_MODULE + PREFIX + "linux_ext4_casefold": (
        "linux.ext4_casefold_identity", "linux.ext4_casefold_flags", "linux.ext4_casefold_names",
        "linux.ext4_casefold_refusal",
    ),
    LINUX_MODULE + PREFIX + "linux_classification_errors": ("linux.classification_errors",),
    LINUX_MODULE + PREFIX + "linux_pending_after_experiment": ("linux.pending_experiments",),
    LINUX_MODULE + PREFIX + "linux_rule_table": (
        "seam.linux_rule_table", "seam.rule_abi_gate", "seam.rule_failures_unavailable",
        "seam.ext_frozen_errors", "seam.tmpfs_casefold_refusal", "seam.btrfs_casefold_refusal",
    ),
    INDEX_MODULE + PREFIX + "family_equivalence": ("seam.family_equivalence",),
    INDEX_MODULE + PREFIX + "family_reserved_suffix": ("seam.family_reserved_suffix",),
    INDEX_MODULE + PREFIX + "family_name_length": ("seam.family_name_length",),
    **{LINUX_MODULE + PREFIX + test: tuple(f"linux.{prefix}_{part}" for part in parts)
       for test, prefix, parts in (
           ("linux_tmpfs_rule", "tmpfs_rule", ("flags", "existing", "absent", "family", "length")),
           ("linux_ext4_rule", "ext4_rule", ("flags", "existing", "absent", "family", "length")),
           ("linux_btrfs", "btrfs", ("identity", "rule_flags", "rule_existing", "rule_absent",
                                     "rule_family", "rule_length")),
       )},
}
MACOS = {
    MACOS_MODULE + PREFIX + "macos_apfs_identity": ("macos.apfs_identity",),
    MACOS_MODULE + PREFIX + "macos_apfs_modes": ("macos.apfs_insensitive", "macos.apfs_sensitive"),
    MACOS_MODULE + PREFIX + "macos_attribute_errors": ("macos.attribute_errors",),
    MACOS_MODULE + PREFIX + "macos_forced_objid_fallback": (
        "macos.objid_observation", "macos.objid_undecided",
    ),
    MACOS_MODULE + PREFIX + "macos_pending_after_experiment": ("macos.pending_experiments",),
}
WINDOWS = {
    WINDOWS_MODULE + PREFIX + "windows_identity_and_reparse": (
        "windows.ntfs_identity", "windows.leaf_reparse", "windows.parent_junction",
    ),
    WINDOWS_MODULE + PREFIX + "windows_case_modes": ("windows.case_ordinary", "windows.case_sensitive"),
    WINDOWS_MODULE + PREFIX + "windows_existing_short_aliases": (
        "windows.allocated_8dot3", "windows.empty_alternate",
    ),
    WINDOWS_MODULE + PREFIX + "windows_alias_companions": ("windows.alias_companions",),
    WINDOWS_MODULE + PREFIX + "windows_native_errors": ("windows.native_errors",),
    WINDOWS_MODULE + PREFIX + "windows_pending_after_experiment": ("windows.pending_experiments",),
}
MANIFESTS = {
    "strict-linux": {**CORE, **SHARED, **UNIX, **LINUX},
    "strict-macos": {**CORE, **SHARED, **UNIX, **MACOS},
    "strict-windows": {**CORE, **SHARED, **WINDOWS},
    "local-linux-partial": {**CORE, **SHARED, **UNIX, **LINUX},
}
OPTIONAL_SUBGROUPS = {
    "strict-macos": {"macos_acl_denial": MACOS_MODULE + PREFIX + "macos_attribute_errors"},
    "strict-windows": {
        "windows_acl_denial": WINDOWS_MODULE + PREFIX + "windows_native_errors",
        "windows_list_denial": WINDOWS_MODULE + PREFIX + "windows_native_errors",
    },
}
OPTIONAL_SKIP_CAUSES = {
    "macos_acl_denial": "root bypasses permission denial",
    "windows_acl_denial": "owned icacls fixture could not be installed",
    "windows_list_denial": "owned icacls fixture could not be installed",
}
LOCAL_FIXTURES = {
    "linux.ext4_sensitive": LINUX_MODULE + PREFIX + "linux_ext4",
    "linux.ext4_casefold": LINUX_MODULE + PREFIX + "linux_ext4_casefold",
    "linux.ext4_rule": LINUX_MODULE + PREFIX + "linux_ext4_rule",
    "linux.btrfs": LINUX_MODULE + PREFIX + "linux_btrfs",
}
FIXTURES = {
    **LOCAL_FIXTURES,
    "linux.tmpfs": LINUX_MODULE + PREFIX + "linux_tmpfs",
    "linux.tmpfs_rule": LINUX_MODULE + PREFIX + "linux_tmpfs_rule",
    "linux.pending_experiments": LINUX_MODULE + PREFIX + "linux_pending_after_experiment",
    "macos.apfs_identity": MACOS_MODULE + PREFIX + "macos_apfs_identity",
    "macos.apfs_insensitive": MACOS_MODULE + PREFIX + "macos_apfs_modes",
    "macos.apfs_sensitive": MACOS_MODULE + PREFIX + "macos_apfs_modes",
    "macos.objid_fallback": MACOS_MODULE + PREFIX + "macos_forced_objid_fallback",
    "macos.pending_experiments": MACOS_MODULE + PREFIX + "macos_pending_after_experiment",
    "windows.identity_and_reparse": WINDOWS_MODULE + PREFIX + "windows_identity_and_reparse",
    "windows.leaf_reparse": WINDOWS_MODULE + PREFIX + "windows_identity_and_reparse",
    "windows.parent_junction": WINDOWS_MODULE + PREFIX + "windows_identity_and_reparse",
    "windows.case_ordinary": WINDOWS_MODULE + PREFIX + "windows_case_modes",
    "windows.case_sensitive": WINDOWS_MODULE + PREFIX + "windows_case_modes",
    "windows.allocated_8dot3": WINDOWS_MODULE + PREFIX + "windows_existing_short_aliases",
    "windows.alias_companions": WINDOWS_MODULE + PREFIX + "windows_alias_companions",
    "windows.native_errors": WINDOWS_MODULE + PREFIX + "windows_native_errors",
    "windows.pending_experiments": WINDOWS_MODULE + PREFIX + "windows_pending_after_experiment",
}
FIXTURE_ROOTS = {
    LINUX_MODULE + PREFIX + "linux_tmpfs": ("linux.tmpfs",),
    LINUX_MODULE + PREFIX + "linux_ext4": ("linux.ext4_sensitive",),
    LINUX_MODULE + PREFIX + "linux_ext4_casefold": ("linux.ext4_casefold",),
    LINUX_MODULE + PREFIX + "linux_pending_after_experiment": ("linux.pending_experiments",),
    LINUX_MODULE + PREFIX + "linux_tmpfs_rule": ("linux.tmpfs_rule",),
    LINUX_MODULE + PREFIX + "linux_ext4_rule": ("linux.ext4_rule",),
    LINUX_MODULE + PREFIX + "linux_btrfs": ("linux.btrfs",),
    MACOS_MODULE + PREFIX + "macos_apfs_identity": ("macos.apfs_identity",),
    MACOS_MODULE + PREFIX + "macos_apfs_modes": ("macos.apfs_insensitive", "macos.apfs_sensitive"),
    MACOS_MODULE + PREFIX + "macos_forced_objid_fallback": ("macos.objid_fallback",),
    MACOS_MODULE + PREFIX + "macos_pending_after_experiment": ("macos.pending_experiments",),
    WINDOWS_MODULE + PREFIX + "windows_identity_and_reparse": ("windows.identity_and_reparse",),
    WINDOWS_MODULE + PREFIX + "windows_case_modes": ("windows.case_ordinary", "windows.case_sensitive"),
    WINDOWS_MODULE + PREFIX + "windows_existing_short_aliases": ("windows.allocated_8dot3",),
    WINDOWS_MODULE + PREFIX + "windows_alias_companions": ("windows.alias_companions",),
    WINDOWS_MODULE + PREFIX + "windows_native_errors": ("windows.native_errors",),
    WINDOWS_MODULE + PREFIX + "windows_pending_after_experiment": ("windows.pending_experiments",),
}
FIXTURE_VARIABLES = ("RRS_A1_TMPFS_ROOT", "RRS_A1_EXT4_ROOT", "RRS_A1_BTRFS_ROOT")
# Explicit: an unmapped Linux fixture group fails at import instead of falling back.
LINUX_ROOT_VARIABLES = {
    **dict.fromkeys(("linux.tmpfs", "linux.pending_experiments", "linux.tmpfs_rule"), FIXTURE_VARIABLES[0]),
    **dict.fromkeys(("linux.ext4_sensitive", "linux.ext4_casefold", "linux.ext4_rule"), FIXTURE_VARIABLES[1]),
    "linux.btrfs": FIXTURE_VARIABLES[2],
}
ROOT_VARIABLES = {
    group: (LINUX_ROOT_VARIABLES[group] if group.startswith("linux.")
            else "RRS_A1_APFS_SENSITIVE_ROOT" if group == "macos.apfs_sensitive"
            else "RRS_A1_APFS_ROOT" if group.startswith("macos.") else "RRS_A1_NTFS_ROOT")
    for roots in FIXTURE_ROOTS.values() for group in roots
}

# libtest writes a test prefix before entering the body. Its final `ok` can
# follow six complete nested harnesses. Do not parse a transcript line by line
# as if each line represented a completed parent test.
EVENT = re.compile(
    r"(?P<running>\brunning (?P<count>\d+) tests?(?=\r?(?:\n|$)))"
    r"|(?P<test>\btest (?P<name>[A-Za-z0-9_:]+) \.\.\. )"
    r"|(?P<summary>test result: (?P<result>ok|FAILED)\. "
    r"(?P<passed>\d+) passed; (?P<failed>\d+) failed; (?P<ignored>\d+) ignored; "
    r"(?P<measured>\d+) measured; (?P<filtered>\d+) filtered out; finished in [^\r\n]+)"
    r"|(?P<marker>\bA1_[A-Z_]+)(?: (?P<args>[^\r\n]*))?"
    r"|(?P<status>(?:(?m:^)|(?<= \.\.\. ))(?:ok|FAILED|ignored)(?=\r?(?:\n|$)))"
)


class EvidenceError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


class Harness:
    def __init__(self, count, family, child=False):
        self.count = count
        self.family = family
        self.child = child
        self.pending = None
        self.finished = []
        self.role_begin = None
        self.role_complete = None


def check(transcript, profile, exit_code):
    require(profile in MANIFESTS, "unknown profile")
    require(exit_code == 0, f"command failed: exit code {exit_code}")
    require(transcript.strip(), "empty transcript")
    transcript = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", transcript)
    require(not re.search(r"FAILED|panicked\b|\bpanic:|\bfailures:|\berror:|A1_REQUIRED_FIXTURE_FAILURE", transcript),
            "failed or panicked harness")
    for line in transcript.splitlines():
        if re.search(r"\bskip(?:ped|ping|s)?\b", line, re.IGNORECASE):
            require("A1_OPTIONAL_FIXTURE_SKIP " in line or "A1_OPTIONAL_SUBGROUP_SKIP " in line,
                    f"unrecognized skip text: {line}")

    manifest = MANIFESTS[profile]
    owners = Counter(group for groups in manifest.values() for group in groups)
    duplicates = sorted(group for group, count in owners.items() if count > 1)
    require(not duplicates, f"duplicate group owner: {', '.join(duplicates)}")
    group_owner = {group: name for name, groups in manifest.items() for group in groups}
    fixture_owned = {group for group, name in group_owner.items() if name in FIXTURE_ROOTS}
    require(fixture_owned.isdisjoint(set(group_owner) - fixture_owned), "fixture/non-fixture group overlap")
    optional = OPTIONAL_SUBGROUPS.get(profile, {})
    stack = []
    families = []
    parents = Counter()
    completions = Counter()
    groups = Counter()
    optional_seen = Counter()
    fixture_skips = {}
    roots_seen = set()
    optional_root_modes = set()
    lock_started = False
    children = []

    for event in EVENT.finditer(transcript):
        kind = event.lastgroup
        # lastgroup can be an inner named capture, so inspect the outer tokens.
        if event.group("running") is not None:
            count = int(event.group("count"))
            require(count > 0, "zero tests in harness")
            if stack:
                require(len(stack) == 1 and stack[0].pending == LOCK_PARENT and lock_started,
                        "nested harness outside lock parent")
                require(LOCK_PARENT in manifest and count == 1 and len(children) < 6,
                        "unexpected child harness/count")
                stack.append(Harness(count, "index", child=True))
            else:
                family = "core" if count == 2 else "index"
                expected_count = 2 if family == "core" else len(manifest) - 2
                require(count == expected_count and family not in families,
                        f"unexpected parent harness/count: {family}/{count}")
                families.append(family)
                stack.append(Harness(count, family))
        elif event.group("test") is not None:
            require(stack, "test status outside harness")
            harness = stack[-1]
            name = event.group("name")
            require(harness.pending is None, "test prefix before preceding status")
            if harness.child:
                require(name == LOCK_PARENT, f"unknown child test: {name}")
            else:
                require(name in manifest, f"unknown parent test: {name}")
                require((name in CORE) == (harness.family == "core"), "test in wrong parent harness")
                parents[name] += 1
                require(parents[name] == 1, f"duplicate parent test: {name}")
            harness.pending = name
        elif event.group("summary") is not None:
            require(stack, "orphan libtest summary")
            harness = stack[-1]
            require(harness.pending is None, "truncated test status before summary")
            require(event.group("result") == "ok"
                    and int(event.group("passed")) == harness.count
                    and all(int(event.group(field)) == 0 for field in ("failed", "ignored", "measured"))
                    and len(harness.finished) == harness.count,
                    "libtest summary/count mismatch")
            if harness.child:
                require(harness.role_complete == LOCK_ROLES[len(children)], "missing child role completion")
                children.append(harness.role_complete)
            stack.pop()
        elif event.group("marker") is not None:
            require(stack and stack[-1].pending is not None, "marker outside active test")
            harness = stack[-1]
            marker = event.group("marker")
            args = (event.group("args") or "").strip()
            if marker in ("A1_LOCK_CHILD_BEGIN", "A1_LOCK_CHILD_COMPLETE"):
                require(harness.child and harness.pending == LOCK_PARENT, "child marker outside child harness")
                require(args == LOCK_ROLES[len(children)], "wrong child role/sequence")
                if marker == "A1_LOCK_CHILD_BEGIN":
                    require(harness.role_begin is None, "duplicate child begin")
                    harness.role_begin = args
                else:
                    require(harness.role_begin == args and harness.role_complete is None,
                            "missing/duplicate child role begin/completion")
                    harness.role_complete = args
                continue
            require(not harness.child, "child attribution cannot mint parent success")
            name = harness.pending
            if marker == "A1_LOCK_PARENT_BEGIN":
                require(name == LOCK_PARENT and not lock_started and not args, "invalid lock parent begin")
                lock_started = True
            elif marker == "A1_GROUP_COMPLETE":
                require(args in group_owner, f"unknown required group: {args}")
                require(group_owner[args] == name, f"group attributed to wrong parent: {args}")
                require(not completions[name], "group after parent completion")
                require(name not in fixture_skips.values(), "group completion after fixture skip")
                groups[args] += 1
                require(groups[args] == 1, f"duplicate group completion: {args}")
            elif marker == "A1_TEST_COMPLETE":
                require(args == name and args in manifest, "parent completion attributed to wrong test")
                require(name not in fixture_skips.values(), "parent completion after fixture skip")
                missing = set(manifest[name]) - groups.keys()
                require(not missing, f"missing required group: {', '.join(sorted(missing))}")
                if name == LOCK_PARENT:
                    require(lock_started and tuple(children) == LOCK_ROLES, "missing six child outcomes/negative control")
                completions[name] += 1
                require(completions[name] == 1, f"duplicate parent completion: {name}")
            elif marker in ("A1_OPTIONAL_SUBGROUP_SKIP", "A1_OPTIONAL_SUBGROUP_COMPLETE"):
                fields = args.split(maxsplit=1)
                group = fields[0] if fields else ""
                require(group in optional and optional[group] == name, f"forbidden optional subgroup: {group}")
                require(not completions[name], "optional subgroup after parent completion")
                if marker.endswith("SKIP"):
                    require(len(fields) == 2 and fields[1] == OPTIONAL_SKIP_CAUSES[group],
                            f"forbidden optional subgroup cause: {group}")
                else:
                    require(len(fields) == 1, "malformed optional subgroup completion")
                optional_seen[group] += 1
                require(optional_seen[group] == 1, f"duplicate optional subgroup: {group}")
            elif marker == "A1_OPTIONAL_FIXTURE_SKIP":
                fields = args.split(maxsplit=1)
                group = fields[0] if fields else ""
                require(group in FIXTURES and FIXTURES[group] == name and len(fields) == 2,
                        f"unknown fixture skip/attribution: {group}")
                require(group not in fixture_skips and not completions[name], "duplicate/late fixture skip")
                require(not any(groups[g] for g in manifest[name]), "fixture skip after required completion")
                fixture_skips[group] = name
            elif marker == "A1_FIXTURE_ROOT":
                fields = args.split(maxsplit=3)
                require(len(fields) == 4 and fields[0] in FIXTURE_ROOTS.get(name, ())
                        and fields[1] == ROOT_VARIABLES[fields[0]],
                        "fixture observation attributed to wrong test")
                require(fields[2] in ("mode=required", "mode=optional"), "missing fixture mode observation")
                if profile != "local-linux-partial" and fields[2] != "mode=required":
                    optional_root_modes.add(fields[0])
                roots_seen.add((name, fields[0]))
                # An observation is deliberately not credited as completion.
            else:
                raise EvidenceError(f"unknown evidence marker: {marker}")
        elif event.group("status") is not None:
            require(stack and stack[-1].pending is not None, "orphan libtest status")
            harness = stack[-1]
            require(event.group("status") == "ok", "failed/ignored test status")
            if harness.child:
                require(harness.role_complete is not None, "missing child role completion")
            harness.finished.append(harness.pending)
            harness.pending = None
        else:
            raise EvidenceError(f"unhandled transcript event: {kind}")

    require(not stack, "truncated transcript: unfinished harness/summary")
    require(set(families) == {"core", "index"}, "missing parent harness")
    require(set(parents) == set(manifest),
            f"missing parent tests: {', '.join(sorted(set(manifest) - parents.keys()))}")
    forbidden = set(fixture_skips) - (set(LOCAL_FIXTURES) if profile == "local-linux-partial" else set())
    require(not forbidden, f"required fixture skipped: {', '.join(sorted(forbidden))}")
    require(not optional_root_modes,
            f"strict profile requires required fixture mode: {', '.join(sorted(optional_root_modes))}")
    skipped_parents = set(fixture_skips.values())
    expected_completions = set(manifest) - skipped_parents
    require(set(completions) == expected_completions,
            f"missing parent completion: {', '.join(sorted(expected_completions - completions.keys()))}")
    expected_groups = {group for name in expected_completions for group in manifest[name]}
    require(set(groups) == expected_groups and expected_groups, "missing required groups/count")
    expected_roots = {(name, group) for name in expected_completions for group in FIXTURE_ROOTS.get(name, ())}
    require(expected_roots <= roots_seen, "missing fixture root/mode observation")
    require(set(optional_seen) == set(optional), "missing optional subgroup outcome")
    require(tuple(children) == (LOCK_ROLES if LOCK_PARENT in manifest else ()), "missing six child outcomes")
    # Credit follows fixture ownership and an observed root line, never a group prefix.
    native = sorted(group for group in groups if group in fixture_owned
                    and all((group_owner[group], root) in roots_seen for root in FIXTURE_ROOTS[group_owner[group]]))
    require(set(native) == fixture_owned & set(groups), "native group without root observation")
    return {
        "result": "LOCAL_PARTIAL_EVIDENCE" if profile == "local-linux-partial" else "NATIVE_EVIDENCE_COMPLETE",
        "profile": profile, "parent_statuses": len(parents), "parent_completions": len(completions),
        "required_groups_completed": len(groups), "required_groups_total": len(group_owner),
        "lock_children": len(children), "optional_fixture_skips": sorted(fixture_skips),
        "optional_subgroups": sorted(optional_seen),
        "native_groups": native, "non_native_groups": sorted(set(groups) - fixture_owned),
    }


def remove_marker(transcript, marker, value):
    pattern = re.compile(r"\b" + re.escape(marker + " " + value) + r"(?=\r?(?:\n|$))")
    result, count = pattern.subn("", transcript)
    require(count == 1, f"mutation expected one {marker} {value}, got {count}")
    return result


def real_mutations(transcript):
    """Keep all six child outcomes intact in the parent-removal controls."""
    no_lock = remove_marker(transcript, "A1_TEST_COMPLETE", LOCK_PARENT)
    child_only = no_lock
    depth = 0
    spans = []
    for event in EVENT.finditer(child_only):
        if event.group("running") is not None:
            depth += 1
        elif event.group("summary") is not None:
            depth -= 1
        elif event.group("test") is not None and depth == 1 and event.group("name") == LOCK_PARENT:
            spans.append(event.span())
    require(len(spans) == 1, "mutation cannot locate real lock parent prefix")
    start, end = spans[0]
    child_only = child_only[:start] + child_only[end:]
    child_only = child_only.replace("A1_LOCK_PARENT_BEGIN", "", 1)
    child_only = remove_marker(child_only, "A1_GROUP_COMPLETE", "unix.lock_parent")
    summaries = list(re.finditer(r"test result: ok\.", transcript))
    require(summaries, "mutation cannot locate final summary")
    required_skip = transcript
    tmpfs = LINUX_MODULE + PREFIX + "linux_tmpfs"
    for group in LINUX[tmpfs]:
        required_skip = remove_marker(required_skip, "A1_GROUP_COMPLETE", group)
    required_skip = required_skip.replace(
        "A1_TEST_COMPLETE " + tmpfs,
        "A1_OPTIONAL_FIXTURE_SKIP linux.tmpfs RRS_A1_TMPFS_ROOT cause=required facility missing", 1,
    )
    return {
        "missing-lock-parent": (no_lock, "missing parent completion: " + LOCK_PARENT),
        "child-only-parent-claim": (child_only, "nested harness outside lock parent"),
        "child-forged-parent": (no_lock.replace(
            "A1_LOCK_CHILD_COMPLETE " + LOCK_ROLES[0],
            "A1_LOCK_CHILD_COMPLETE " + LOCK_ROLES[0] + "\nA1_TEST_COMPLETE " + LOCK_PARENT, 1),
            "child attribution cannot mint parent success"),
        "truncated": (transcript[:summaries[-1].start()], "truncated transcript"),
        "missing-group": (remove_marker(transcript, "A1_GROUP_COMPLETE", "linux.tmpfs_names"),
                          "missing required group: linux.tmpfs_names"),
        "missing-parent": (remove_marker(transcript, "A1_TEST_COMPLETE", CORE_MODULE + PREFIX + "identity_domains"),
                           "missing parent completion: " + CORE_MODULE + PREFIX + "identity_domains"),
        "required-skip": (required_skip, "required fixture skipped: linux.tmpfs"),
        "failure": (transcript + "\ntest result: FAILED\n", "failed or panicked harness"),
        "panic": (transcript + "\nthread 'mutation' panicked at required assertion\n", "failed or panicked harness"),
    }


def validate_mutations(transcript, exit_code, output):
    baseline = check(transcript, "local-linux-partial", exit_code)
    output.mkdir(parents=True, exist_ok=False)
    report = {"baseline": baseline, "baseline_sha256": hashlib.sha256(transcript.encode()).hexdigest(), "mutations": {}}
    for name, (mutated, diagnostic) in real_mutations(transcript).items():
        (output / (name + ".log")).write_bytes(mutated.encode("utf-8"))
        try:
            check(mutated, "local-linux-partial", exit_code)
        except EvidenceError as error:
            require(diagnostic in str(error), f"{name}: wrong diagnostic: {error}; expected {diagnostic}")
            report["mutations"][name] = {"rejected": True, "diagnostic": str(error),
                                          "sha256": hashlib.sha256(mutated.encode()).hexdigest()}
        else:
            raise EvidenceError(f"{name}: mutation was accepted")
    (output / "results.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def linux_mount_type(path):
    def decode(field):
        return re.sub(r"\\(040|011|012|134)", lambda m: chr(int(m[1], 8)), field)
    entries = []
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        before, after = line.split(" - ", 1)
        mount = Path(decode(before.split()[4]))
        if path == mount or mount in path.parents:
            entries.append((len(mount.parts), after.split()[0]))
    require(entries, "root control cannot corroborate filesystem")
    depth = max(item[0] for item in entries)
    deepest = [kind for size, kind in entries if size == depth]
    require(len(deepest) == 1, "root control ambiguous mountinfo")
    return deepest[0]


def validate_root_control(transcript, code, variable, group, test, root, required, cause=None):
    require(re.search(r"\brunning 1 test\b", transcript), "root control did not execute one test")
    require(len(re.findall(re.escape("test " + test + " ... "), transcript)) == 1,
            "root control did not execute exact target test")
    require("A1_TEST_COMPLETE" not in transcript and "A1_GROUP_COMPLETE" not in transcript,
            "root control substituted successful fixture")
    events = list(EVENT.finditer(transcript))
    require([event["name"] for event in events if event["test"]] == [test]
            and [event["count"] for event in events if event["running"]] == ["1"]
            and len([event for event in events if event["summary"]]) == 1,
            "root control must contain exactly one named test/harness")
    outcome = next(event for event in events if event["summary"])
    require(outcome["result"] == ("FAILED" if required else "ok")
            and outcome["passed"] == ("0" if required else "1")
            and outcome["failed"] == ("1" if required else "0")
            and outcome["ignored"] == outcome["measured"] == "0"
            and [event["status"] for event in events if event["status"]] == ["FAILED" if required else "ok"],
            "root control target outcome/count mismatch")
    if required:
        marker = f"A1_REQUIRED_FIXTURE_FAILURE {group} {variable} root="
        require(code != 0 and marker in transcript and "test result: FAILED. 0 passed; 1 failed;" in transcript,
                "required root control failed for an unrelated reason or used fallback")
    else:
        marker = f"A1_OPTIONAL_FIXTURE_SKIP {group} {variable} root="
        require(code == 0 and marker in transcript and "test result: ok. 1 passed; 0 failed;" in transcript,
                "optional root control did not produce an honest skip")
    require((str(root) in transcript if root is not None else "root=None" in transcript),
            "root control did not name configured root/unset cause")
    if cause is not None:
        require(cause in transcript, f"root control failed for wrong cause; expected {cause}")
    return {"exit_code": code, "marker": marker, "required": required}


REPOSITORY = Path(__file__).resolve().parents[1]
PACKAGES = ("ratarmount-core", "ratarmount-index", "ratarmount-formats-sqlar")
ENGINES = ("stock", "sqlcipher")
SQLAR_GROUPS = (
    "tests::sqlcipher_enabled_matches_cfg",
    "tests::regression_sqlar_header_probes_keep_sqlar_lock",
    "tests::regression_macos_sqlar_connections_keep_auto_vfs",
)
A1_RUN_ARGS = [PREFIX, "--nocapture", "--test-threads=1"]
RECORDED_ENV = (
    "TMPDIR", "CARGO_BUILD_JOBS", "CARGO_TARGET_DIR", "CARGO_TERM_COLOR",
    "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "MACOSX_DEPLOYMENT_TARGET",
    "RATARMOUNT_TEST_SQLITE_BACKEND", "RRS_A1_STRICT_ENGINE", "RRS_A1_ENGINE_EXE",
    "RRS_A1_REQUIRE_FIXTURES", *FIXTURE_VARIABLES,
    "RRS_A1_LOCK_CHILD", "RRS_A1_LOCK_ROLE",
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def save_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def capture(command, env, output, name, *, merged=False, timeout=600):
    """One creation-time stream policy, shared by native runs and refusal controls."""
    process = subprocess.Popen(command, cwd=REPOSITORY, env=env, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT if merged else subprocess.PIPE,
                               start_new_session=True)
    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            stdout, stderr = process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            stdout, stderr = process.communicate()
    stderr = stderr or b""
    # Preserve bytes before decoding; decoding/timeout failures cannot qualify.
    (output / (name + ".stdout")).write_bytes(stdout)
    (output / (name + ".stderr")).write_bytes(stderr)
    record = {"argv": command, "cwd": str(REPOSITORY), "status": process.returncode,
              "merged": merged, "timed_out": timed_out,
              "env": {key: env[key] for key in RECORDED_ENV if key in env},
              "stdout": stdout.decode("utf-8"), "stderr": stderr.decode("utf-8"),
              "stdout_sha256": digest(stdout), "stderr_sha256": digest(stderr)}
    save_json(output / (name + ".json"), record)
    return record


def verify_record(record, command, *, merged=False, status=0):
    require(record["argv"] == command, "command/package/feature mismatch")
    require(record["cwd"] == str(REPOSITORY), "command source directory mismatch")
    require(not record["timed_out"], "command timed out")
    require(record["merged"] == merged and (not merged or not record["stderr"]),
            "capture must merge stderr at process creation")
    for stream in ("stdout", "stderr"):
        require(digest(record[stream].encode("utf-8")) == record[stream + "_sha256"],
                "raw stream hash mismatch")
    if status is not None:
        require(record["status"] == status, f"command failed: exit code {record['status']}")


def source_identity():
    names = subprocess.check_output(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                                    cwd=REPOSITORY).split(b"\0")
    source = hashlib.sha256()
    for name in sorted(set(names) - {b""}):
        path = REPOSITORY / os.fsdecode(name)
        contents = os.fsencode(os.readlink(path)) if path.is_symlink() else path.read_bytes()
        source.update(name + b"\0" + digest(contents).encode() + b"\n")
    lock = (REPOSITORY / "Cargo.lock").read_bytes()
    return {"source_sha256": source.hexdigest(), "lock_sha256": digest(lock),
            "lock_packages": tomllib.loads(lock.decode())["package"],
            "head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPOSITORY).decode().strip(),
            "head_tree": subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=REPOSITORY).decode().strip()}


def native_target(rustc):
    require(sys.platform == "linux" and platform.machine() in ("x86_64", "aarch64"),
            "S1 engine execution requires native Linux x86_64/aarch64")
    target = platform.machine() + "-unknown-linux-gnu"
    require(re.search(r"(?m)^host: " + re.escape(target) + r"$", rustc), "nonnative toolchain target/ABI")
    return target


def cargo_command(engine, phase, target):
    require(engine in ENGINES, "invalid expected engine")
    selected = [item for package in PACKAGES for item in ("-p", package)]
    features = ["--features", "ratarmount-formats-sqlar/sqlcipher"] if engine == "sqlcipher" else []
    if phase == "metadata":
        arguments = ["metadata", "--locked", "--format-version=1", "--filter-platform", target] + features
    elif phase == "build":
        arguments = ["test", "--locked", "--no-run", "--message-format=json", "--lib"] + selected + features + ["--target", target]
    elif phase == "graph":
        arguments = ["tree", "--locked", "-e", "features", "-i", "libsqlite3-sys"] + selected + features + ["--target", target, "--no-dedupe"]
    else:
        raise EvidenceError("unknown Cargo phase")
    return ["flock", "/tmp/muse-cargo.lock", "cargo"] + arguments


def cell_environment(cell, *, executable=None, qualified=True):
    env = os.environ.copy()
    for key in RECORDED_ENV:
        if key.startswith("RRS_A1_") or key == "RATARMOUNT_TEST_SQLITE_BACKEND":
            env.pop(key, None)
    # Fixture paths are passed explicitly by the approved fixture owner.
    for key in FIXTURE_VARIABLES:
        if key in os.environ:
            env[key] = os.environ[key]
    env.update(TMPDIR="/var/tmp", CARGO_BUILD_JOBS="2", CARGO_TERM_COLOR="never",
               CARGO_TARGET_DIR=cell["target_dir"], RRS_A1_REQUIRE_FIXTURES="1")
    if qualified:
        env.update(RRS_A1_STRICT_ENGINE="1", RATARMOUNT_TEST_SQLITE_BACKEND=cell["engine"])
    if executable is not None:
        env["RRS_A1_ENGINE_EXE"] = executable
    return env


def verify_cell_env(record, cell, *, executable=None, qualified=True):
    expected = cell_environment(cell, executable=executable, qualified=qualified)
    for key in ("TMPDIR", "CARGO_BUILD_JOBS", "CARGO_TARGET_DIR", "CARGO_TERM_COLOR"):
        require(record["env"].get(key) == expected[key], "target/build environment mismatch")
    if qualified:
        require(record["env"].get("RRS_A1_STRICT_ENGINE") == "1"
                and record["env"].get("RATARMOUNT_TEST_SQLITE_BACKEND") == cell["engine"],
                "strict engine/backend environment missing or invalid")
    if executable is not None:
        require(record["env"].get("RRS_A1_ENGINE_EXE") == executable, "executable environment binding mismatch")


def selected_metadata(metadata):
    require(metadata["workspace_root"] == str(REPOSITORY), "foreign metadata workspace")
    selected = {}
    for name in PACKAGES:
        packages = [package for package in metadata["packages"] if package["name"] == name]
        require(len(packages) == 1, "missing/ambiguous metadata package: " + name)
        package = packages[0]
        require(package["source"] is None
                and package["manifest_path"] == str(REPOSITORY / name / "Cargo.toml")
                and package["id"] in metadata["workspace_members"], "foreign same-name metadata package")
        targets = [target for target in package["targets"] if target["kind"] == ["lib"]]
        require(len(targets) == 1 and targets[0]["name"] == name.replace("-", "_")
                and targets[0]["src_path"] == str(REPOSITORY / name / "src/lib.rs"),
                "metadata library source target mismatch")
        selected[name] = package
    return selected


def verify_graph(cell, metadata, events):
    selected = selected_metadata(metadata)
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    require(len(nodes) == len(metadata["resolve"]["nodes"]), "duplicate resolved packageID")
    packages = {package["id"]: package for package in metadata["packages"]}
    for family in ("libsqlite3-sys", "rusqlite"):
        members = [package for package in packages.values() if package["name"] == family]
        locked = [package for package in cell["source"]["lock_packages"] if package["name"] == family]
        require(len(members) == len(locked) == 1, "ambiguous locked SQLite engine family")
        package, lock = members[0], locked[0]
        require((package["version"], package["source"]) == (lock["version"], lock["source"]),
                "lock/packageID engine mismatch")
        require(package["id"] == package["source"] + "#" + family + "@" + package["version"],
                "resolved engine packageID mismatch")
        artifacts = [event for event in events if event.get("reason") == "compiler-artifact"
                     and event["package_id"] == package["id"]]
        require(artifacts, "missing compiled engine feature evidence")
        features = set(nodes[package["id"]]["features"])
        cipher_features = {"bundled-sqlcipher", "bundled-sqlcipher-vendored-openssl"}
        for observed in [features] + [set(event["features"]) for event in artifacts]:
            require("bundled" in observed, "engine must use locked bundled SQLite")
            require(cipher_features <= observed if cell["engine"] == "sqlcipher"
                    else not any("sqlcipher" in feature for feature in observed),
                    "missing/unexpected SQLCipher dependency feature")
    sqlar = selected[PACKAGES[2]]
    require(("sqlcipher" in nodes[sqlar["id"]]["features"]) == (cell["engine"] == "sqlcipher"),
            "SQLAR resolved feature mismatch")
    sqlite = next(package["id"] for package in packages.values() if package["name"] == "libsqlite3-sys")
    for name in PACKAGES[1:]:
        pending, reached = [selected[name]["id"]], set()
        while pending:
            package_id = pending.pop()
            if package_id not in reached:
                reached.add(package_id)
                pending.extend(nodes[package_id]["dependencies"])
        require(sqlite in reached, "selected package graph loses SQLite dependency")
    tree = cell["commands"]["graph"]["stdout"]
    version = packages[sqlite]["version"]
    require(tree.splitlines() and tree.splitlines()[0].startswith("libsqlite3-sys v" + version),
            "missing matching rooted engine feature graph")
    require(set(re.findall(r"libsqlite3-sys v([0-9.]+)", tree)) == {version}, "ambiguous tree engine versions")
    for name in PACKAGES[1:]:
        package = selected[name]
        require(name + " v" + package["version"] in tree, "feature tree loses selected root " + name)
    if cell["engine"] == "sqlcipher":
        for token in ('ratarmount-formats-sqlar feature "sqlcipher"',
                      'rusqlite feature "bundled-sqlcipher-vendored-openssl"',
                      'libsqlite3-sys feature "bundled-sqlcipher-vendored-openssl"'):
            require(token in tree, "missing SQLCipher feature graph path")
    else:
        require("sqlcipher" not in tree.lower(), "stock graph unexpectedly has cipher")


def executable_identity(path, cell):
    target = Path(cell["target_dir"])
    require(target.is_absolute() and target.resolve(strict=True) == target
            and target.stat().st_uid == os.geteuid() and target.stat().st_mode & 0o077 == 0,
            "target is not canonical/private/owned")
    require(path.is_absolute() and path.parent == target / cell["native_target"] / "debug/deps",
            "artifact outside exact cell target")
    try:
        require(path.resolve(strict=True) == path, "aliased executable artifact")
    except OSError as error:
        raise EvidenceError("missing executable artifact") from error
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and os.access(path, os.X_OK),
            "artifact is not owned regular executable")
    data = path.read_bytes()
    machine = 62 if cell["native_target"].startswith("x86_64-") else 183
    require(len(data) >= 64 and data[:7] == b"\x7fELF\x02\x01\x01"
            and int.from_bytes(data[16:18], "little") in (2, 3)
            and int.from_bytes(data[18:20], "little") == machine, "nonnative executable artifact")
    return {"path": str(path), "sha256": digest(data), "device": info.st_dev, "inode": info.st_ino,
            "size": info.st_size, "cell_id": cell["id"], "source_sha256": cell["source"]["source_sha256"],
            "lock_sha256": cell["source"]["lock_sha256"]}


def enumerate_artifacts(cell):
    require(set(cell["commands"]) == {"rustc", "metadata", "build", "graph"},
            "extra/missing Cargo invocation could change feature unification")
    verify_record(cell["commands"]["rustc"], ["rustc", "-vV"])
    require(native_target(cell["commands"]["rustc"]["stdout"]) == cell["native_target"], "native cell target changed")
    require(cell["runner"] == {"uid": os.geteuid(), "gid": os.getegid()}
            and os.geteuid() != 0 and os.getegid() != 0, "engine runner identity changed or privileged")
    require(cell["profile"] == "strict-linux" and cell["deployment"] == "native"
            and cell["manifest"] == json.loads(json.dumps(MANIFESTS["strict-linux"])), "cell profile/manifest mismatch")
    for phase in ("metadata", "build", "graph"):
        record = cell["commands"][phase]
        verify_record(record, cargo_command(cell["engine"], phase, cell["native_target"]))
        verify_cell_env(record, cell)
    try:
        metadata = json.loads(cell["commands"]["metadata"]["stdout"])
        events = [json.loads(line) for line in cell["commands"]["build"]["stdout"].splitlines()]
    except (ValueError, TypeError) as error:
        raise EvidenceError("malformed build/metadata JSON") from error
    require(events and all(isinstance(event, dict) for event in events), "malformed build event")
    finished = [event for event in events if event.get("reason") == "build-finished"]
    require(finished == [{"reason": "build-finished", "success": True}]
            and events[-1] == finished[0], "missing/unfinished build-finished success")
    selected = selected_metadata(metadata)
    require(cell["package_ids"] == {name: package["id"] for name, package in selected.items()},
            "frozen metadata packageID identity changed")
    verify_graph(cell, metadata, events)
    by_id = {package["id"]: name for name, package in selected.items()}
    artifacts = {}
    for event in events:
        if event.get("reason") != "compiler-artifact" or not event["profile"]["test"]:
            continue
        require(event["package_id"] in by_id, "unexpected test artifact packageID")
        name = by_id[event["package_id"]]
        require(name not in artifacts, "duplicate test artifact")
        target = next(target for target in selected[name]["targets"] if target["kind"] == ["lib"])
        require(all(event["target"][key] == target[key] for key in ("kind", "crate_types", "name", "src_path"))
                and event["profile"]["opt_level"] == "0" and event["profile"]["debug_assertions"]
                and event["executable"] is not None, "test artifact source/target/profile mismatch")
        require(event["filenames"] == [event["executable"]]
                and re.fullmatch(re.escape(target["name"]) + r"-[0-9a-f]{16}", Path(event["executable"]).name),
                "unknown same-name executable artifact")
        if name == PACKAGES[2]:
            require(("sqlcipher" in event["features"]) == (cell["engine"] == "sqlcipher"),
                    "SQLAR artifact missing/unexpected sqlcipher feature")
        artifacts[name] = executable_identity(Path(event["executable"]), cell)
        artifacts[name]["package_id"] = event["package_id"]
        artifacts[name]["features"] = event["features"]
    require(set(artifacts) == set(PACKAGES), "missing required core/index/SQLAR artifact")
    require(len({artifact["path"] for artifact in artifacts.values()}) == 3, "ambiguous executable artifacts")
    return artifacts


def verify_artifacts(cell):
    require(cell["source"] == source_identity(), "changed source/lock identity")
    artifacts = enumerate_artifacts(cell)
    require(artifacts == cell["artifacts"], "artifact replaced after enumeration or stale source/lock binding")
    return artifacts


def build_cell(output, engine):
    require(os.geteuid() != 0 and os.getegid() != 0, "no Cargo as root/privileged group")
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    target_dir = output / "target"
    target_dir.mkdir(mode=0o700)
    cell = {"id": uuid.uuid4().hex, "engine": engine, "profile": "strict-linux", "deployment": "native",
            "runner": {"uid": os.geteuid(), "gid": os.getegid()},
            "target_dir": str(target_dir.resolve()), "source": source_identity(),
            "manifest": json.loads(json.dumps(MANIFESTS["strict-linux"])), "commands": {}}
    env = cell_environment(cell)
    record = capture(["rustc", "-vV"], env, output, "rustc")
    cell["commands"]["rustc"] = record
    verify_record(record, ["rustc", "-vV"])
    cell["native_target"] = native_target(record["stdout"])
    for phase in ("metadata", "build", "graph"):
        command = cargo_command(engine, phase, cell["native_target"])
        cell["commands"][phase] = capture(command, env, output, phase, timeout=1800)
        save_json(output / "cell.json", cell)
        verify_record(cell["commands"][phase], command)
        if phase == "metadata":
            selected = selected_metadata(json.loads(cell["commands"][phase]["stdout"]))
            cell["package_ids"] = {name: package["id"] for name, package in selected.items()}
        require(source_identity() == cell["source"], "changed source/lock during build")
    cell["artifacts"] = enumerate_artifacts(cell)
    save_json(output / "cell.json", cell)
    return cell


def run_binary(cell, package, arguments, output, label, *, overrides=None):
    artifact = verify_artifacts(cell)[package]
    env = cell_environment(cell, executable=artifact["path"])
    for key, value in (overrides or {}).items():
        if value is None:
            env.pop(key, None)
        else:
            env[key] = value
    record = capture([artifact["path"]] + arguments, env, output, label, merged=True)
    record["binary_before"] = artifact
    record["binary_after"] = verify_artifacts(cell)[package]
    save_json(output / (label + ".json"), record)
    return record


def verify_binary_record(record, cell, package, arguments, *, status=0, qualified=True):
    artifact = cell["artifacts"][package]
    verify_record(record, [artifact["path"]] + arguments, merged=True, status=status)
    verify_cell_env(record, cell, executable=artifact["path"], qualified=qualified)
    require(record["binary_before"] == artifact == record["binary_after"], "binary changed during execution")


def list_inventory(record, expected):
    lines = [line for line in record["stdout"].splitlines() if line]
    require(lines and re.fullmatch(r"\d+ tests?, 0 benchmarks?", lines[-1]), "unfinished test enumeration")
    names = []
    for line in lines[:-1]:
        match = re.fullmatch(r"([A-Za-z0-9_:]+): test", line)
        require(match, "unexpected listing/ancillary test")
        names.append(match[1])
    require(len(names) == len(set(names)), "duplicate listed test")
    require(set(names) == set(expected) and len(names) == int(lines[-1].split()[0]),
            "missing/extra required listed test")
    return names


CANONICAL_OK = re.compile(
    r"test result: ok\. [1-9][0-9]* passed; 0 failed; 0 ignored; 0 measured; "
    r"[0-9]+ filtered out; finished in [0-9]+\.[0-9]{2}s"
)


def reject_unsuccessful(text, message):
    """Exempt whole canonical zero-failure lines with a positive ASCII passed count."""
    for line in text.split("\n"):
        line = line.removesuffix("\r")
        if not CANONICAL_OK.fullmatch(line):
            require(not re.search(r"FAILED|panicked|\bpanic:|\bfailures:|\berror:|\bskip", line, re.I), message)


def verify_single_test(transcript, name):
    reject_unsuccessful(transcript, "mandatory behavior failed/ignored/skipped")
    events = list(EVENT.finditer(transcript))
    require([event["name"] for event in events if event["test"]] == [name], "mandatory behavior test identity/count")
    require([int(event["count"]) for event in events if event["running"]] == [1], "mandatory behavior harness/count")
    summaries = [event for event in events if event["summary"]]
    require(len(summaries) == 1 and summaries[0]["result"] == "ok" and summaries[0]["passed"] == "1"
            and all(summaries[0][field] == "0" for field in ("failed", "ignored", "measured"))
            and [event["status"] for event in events if event["status"]] == ["ok"],
            "mandatory behavior did not pass exactly one test")


def verify_engine_observations(transcript, cell, *, qualified=True):
    records = []
    for match in re.finditer(r"\bENGINE_OBSERVATION ([^\r\n]+)", transcript):
        try:
            records.append(json.loads(match[1]))
        except ValueError as error:
            raise EvidenceError("malformed runtime engine observation") from error
    roles = [record.get("role") for record in records]
    require(len(roles) == len(set(roles)), "duplicate runtime engine role")
    require(roles == ["parent", *LOCK_ROLES], "missing/unrecognized runtime engine role")
    artifact = cell["artifacts"][PACKAGES[1]]
    pids = set()
    for record in records:
        require(all(isinstance(record.get(key), str) and record[key].strip() for key in ("version", "source_id")),
                "missing/empty runtime SQLite version/sourceID")
        cipher = record.get("cipher_version")
        require(cipher is None if cell["engine"] == "stock" else isinstance(cipher, str) and bool(cipher.strip()),
                "runtime engine differs from expected backend")
        require(record.get("engine") == cell["engine"], "runtime engine label differs from observed backend")
        require(record.get("strict") is qualified
                and record.get("expected") == (cell["engine"] if qualified else None),
                "runtime strict/backend environment absent or invalid")
        require(record.get("executable") == artifact["path"] and record.get("sha256") == artifact["sha256"],
                "runtime child/parent executable binding mismatch")
        require(type(record.get("pid")) is int and record["pid"] > 0 and record["pid"] not in pids,
                "runtime child/parent process identity mismatch")
        pids.add(record["pid"])
    require(len({(record["version"], record["source_id"], record["cipher_version"]) for record in records}) == 1,
            "runtime child engine facts differ from parent")
    return records


def environment_cases(cell, child_path):
    cases = {"ordinary": ({"RRS_A1_STRICT_ENGINE": None, "RATARMOUNT_TEST_SQLITE_BACKEND": None}, None)}
    for role in ("parent", "child"):
        child = {"RRS_A1_LOCK_CHILD": child_path, "RRS_A1_LOCK_ROLE": "raw_alias_close_released"} if role == "child" else {}
        for name, backend, diagnostic in (
            ("missing", None, "strict engine requires RATARMOUNT_TEST_SQLITE_BACKEND"),
            ("invalid", "unrecognized", "invalid RATARMOUNT_TEST_SQLITE_BACKEND"),
            ("mismatch", "sqlcipher" if cell["engine"] == "stock" else "stock", "SQLite engine differs from requested backend"),
        ):
            cases[role + "-" + name] = ({**child, "RATARMOUNT_TEST_SQLITE_BACKEND": backend}, diagnostic)
    return cases


def verify_environment_controls(cell):
    controls = cell["environment_controls"]
    cases = environment_cases(cell, cell["environment_child_path"])
    require(set(controls) == set(cases), "missing parent/child ordinary/strict environment control")
    arguments = [LOCK_PARENT, "--exact", "--nocapture", "--test-threads=1"]
    for name, (overrides, diagnostic) in cases.items():
        record = controls[name]
        verify_binary_record(record, cell, PACKAGES[1], arguments, status=None, qualified=False)
        expected_env = cell_environment(cell, executable=cell["artifacts"][PACKAGES[1]]["path"])
        for key, value in overrides.items():
            if value is None:
                expected_env.pop(key, None)
            else:
                expected_env[key] = value
        for key in ("RRS_A1_STRICT_ENGINE", "RATARMOUNT_TEST_SQLITE_BACKEND", "RRS_A1_LOCK_CHILD", "RRS_A1_LOCK_ROLE"):
            require(record["env"].get(key) == expected_env.get(key), "environment control did not exercise requested branch")
        text = record["stdout"]
        if diagnostic is None:
            require(record["status"] == 0, "ordinary/no-env lock control failed")
            reject_unsuccessful(text, "ordinary/no-env lock control failed")
            verify_engine_observations(text, cell, qualified=False)
            require(text.count("A1_TEST_COMPLETE " + LOCK_PARENT) == 1
                    and text.count("A1_GROUP_COMPLETE unix.lock_parent") == 1
                    and re.findall(r"A1_LOCK_CHILD_COMPLETE ([^\r\n]+)", text) == list(LOCK_ROLES),
                    "ordinary/no-env control lost parent/child lock assertions")
            summaries = [event for event in EVENT.finditer(text) if event["summary"]]
            require(len(summaries) == 7 and all(event["result"] == "ok" and event["passed"] == "1"
                    and all(event[key] == "0" for key in ("failed", "ignored", "measured")) for event in summaries),
                    "ordinary/no-env parent/child status mismatch")
            events = list(EVENT.finditer(text))
            require([event["name"] for event in events if event["test"]] == [LOCK_PARENT] * 7
                    and [int(event["count"]) for event in events if event["running"]] == [1] * 7
                    and [event["status"] for event in events if event["status"]] == ["ok"] * 7,
                    "ordinary/no-env parent/child identity/running/status mismatch")
        else:
            require(record["status"] != 0 and diagnostic in text
                    and text.count("test " + LOCK_PARENT + " ... ") == 1
                    and "running 1 test\n" in text
                    and "test result: FAILED. 0 passed; 1 failed;" in text
                    and "A1_TEST_COMPLETE" not in text and "A1_GROUP_COMPLETE" not in text,
                    "strict environment negative failed for unrelated cause")


def run_environment_controls(cell, output):
    # Empty owned file, opened as a real SQLite connection by the child itself.
    # No system-Python SQLite engine contributes to observations.
    with tempfile.TemporaryDirectory(prefix="engine-env-", dir=output) as directory:
        path = Path(directory) / "child.db"
        path.touch(mode=0o600)
        cell["environment_child_path"] = str(path)
        cell["environment_controls"] = {}
        for name, (overrides, _) in environment_cases(cell, str(path)).items():
            cell["environment_controls"][name] = run_binary(
                cell, PACKAGES[1], [LOCK_PARENT, "--exact", "--nocapture", "--test-threads=1"],
                output, "env-" + name, overrides=overrides)
    verify_environment_controls(cell)


def verify_run_cell(cell):
    verify_artifacts(cell)
    require(set(cell["lists"]) == set(PACKAGES) and set(cell["runs"]) == set(PACKAGES[:2]),
            "missing/extra required harness or ancillary artifact")
    for package in PACKAGES:
        record = cell["lists"][package]
        verify_binary_record(record, cell, package, [PREFIX, "--list"])
        expected = CORE if package == PACKAGES[0] else {} if package == PACKAGES[2] else {
            name: groups for name, groups in MANIFESTS[cell["profile"]].items() if name not in CORE}
        list_inventory(record, expected)
    require(cell["ancillary"] == "ancillary_sqlar_no_A1_group", "SQLAR ancillary relabeled required")
    require(set(cell["sqlar_groups"]) == set(SQLAR_GROUPS), "missing mandatory SQLAR behavior group")
    for name in SQLAR_GROUPS:
        group = cell["sqlar_groups"][name]
        verify_binary_record(group["list"], cell, PACKAGES[2], [name, "--exact", "--list"])
        list_inventory(group["list"], [name])
        verify_binary_record(group["run"], cell, PACKAGES[2], [name, "--exact", "--nocapture", "--test-threads=1"])
        verify_single_test(group["run"]["stdout"], name)
    raw = []
    for package in PACKAGES[:2]:
        record = cell["runs"][package]
        verify_binary_record(record, cell, package, A1_RUN_ARGS, status=None)
        require(record["env"].get("RRS_A1_REQUIRE_FIXTURES") == "1"
                and all(record["env"].get(variable) and record["env"][variable] == cell["fixture_roots"][variable]
                        for variable in FIXTURE_VARIABLES),
                "strict fixtures environment missing")
        raw.append(record["stdout"])
    combined = "".join(raw)  # Whole raw required transcripts, never SQLAR's zero-test inventory.
    require(cell["combined_sha256"] == digest(combined.encode()), "combined raw transcript hash mismatch")
    actual_status = next((cell["runs"][name]["status"] for name in PACKAGES[:2] if cell["runs"][name]["status"] != 0), 0)
    result = check(combined, cell["profile"], actual_status)
    verify_engine_observations(cell["runs"][PACKAGES[1]]["stdout"], cell)
    verify_environment_controls(cell)
    return result


def run_cell(cell, output):
    verify_artifacts(cell)
    cell["fixture_roots"] = {key: os.environ.get(key) for key in FIXTURE_VARIABLES}
    cell["lists"], cell["runs"], cell["sqlar_groups"] = {}, {}, {}
    for package in PACKAGES:
        record = run_binary(cell, package, [PREFIX, "--list"], output, package + "-list")
        cell["lists"][package] = record
        verify_binary_record(record, cell, package, [PREFIX, "--list"])
        expected = CORE if package == PACKAGES[0] else {} if package == PACKAGES[2] else {
            name: groups for name, groups in MANIFESTS[cell["profile"]].items() if name not in CORE}
        list_inventory(record, expected)
    cell["ancillary"] = "ancillary_sqlar_no_A1_group"
    run_environment_controls(cell, output)
    for package in PACKAGES[:2]:
        cell["runs"][package] = run_binary(cell, package, A1_RUN_ARGS, output, package + "-A1")
        save_json(output / "cell.json", cell)
    combined = "".join(cell["runs"][name]["stdout"] for name in PACKAGES[:2])
    (output / "required-A1.log").write_bytes(combined.encode())
    cell["combined_sha256"] = digest(combined.encode())
    for number, name in enumerate(SQLAR_GROUPS):
        group = cell["sqlar_groups"][name] = {}
        for phase, arguments in (("list", [name, "--exact", "--list"]),
                                 ("run", [name, "--exact", "--nocapture", "--test-threads=1"])):
            group[phase] = run_binary(cell, PACKAGES[2], arguments, output, f"sqlar-{number}-{phase}")
            save_json(output / "cell.json", cell)
    result = verify_run_cell(cell)
    save_json(output / "cell.json", cell)
    save_json(output / "checker.json", result)
    return result


def verify_matrix(cells, *, executed=False):
    require(len(cells) == 2 and [cell["engine"] for cell in cells] == list(ENGINES), "missing required engine/platform/deployment cell")
    require(len({cell["id"] for cell in cells}) == 2, "reused cell identity")
    targets = [Path(cell["target_dir"]).resolve(strict=True) for cell in cells]
    require(targets[0] != targets[1] and not any(a in b.parents for a, b in (targets, targets[::-1])),
            "shared canonical engine target")
    require(cells[0]["source"] == cells[1]["source"]
            and cells[0]["native_target"] == cells[1]["native_target"], "engine cells have different source/lock/native identities")
    for cell in cells:
        verify_run_cell(cell) if executed else verify_artifacts(cell)
    return {"engines": list(ENGINES), "profile": "strict-linux", "executed": executed}


def build_engines(output):
    require(not output.resolve().is_relative_to(REPOSITORY), "evidence/target output must be outside source tree")
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    cells = [build_cell(output / engine, engine) for engine in ENGINES]
    result = verify_matrix(cells)
    save_json(output / "matrix.json", result)
    return result


def load_engines(output):
    require(json.loads((output / "matrix.json").read_text())["engines"] == list(ENGINES), "missing required engine matrix")
    cells = [json.loads((output / engine / "cell.json").read_text()) for engine in ENGINES]
    verify_matrix(cells)
    return cells


def run_engines(output):
    cells = load_engines(output)
    for cell in cells:
        run_cell(cell, output / cell["engine"])
    result = verify_matrix(cells, executed=True)
    save_json(output / "matrix.json", result)
    return result


def old_root_control(output, root):
    stock = load_engines(output)[0]
    require(os.geteuid() != 0, "old-root control requires unprivileged runner")
    root = root.resolve(strict=True)
    info = root.stat()
    require(info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700 and root.is_dir(),
            "old-root negative requires original root-owned mode0700 fixture")
    test = LINUX_MODULE + PREFIX + "linux_tmpfs"
    record = run_binary(stock, PACKAGES[1], [test, "--exact", "--nocapture", "--test-threads=1"],
                        output / "stock", "old-root-negative", overrides={"RRS_A1_TMPFS_ROOT": str(root)})
    verify_binary_record(record, stock, PACKAGES[1], [test, "--exact", "--nocapture", "--test-threads=1"], status=None)
    return validate_root_control(record["stdout"], record["status"], "RRS_A1_TMPFS_ROOT", "linux.tmpfs", test,
                                 root, True, "cause=root must be owned by this uid and private")


def engine_mutations(cells, output):
    """Offline mutations of a complete real bundle; originals remain immutable."""
    baseline = verify_matrix(cells, executed=True)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    result = {"baseline": baseline, "mutations": {}}
    for name, diagnostic in (("wrong-engine", "runtime engine differs"),
                             ("missing-feature", "command/package/feature mismatch"),
                             ("missing-group", "missing required group")):
        mutated = copy.deepcopy(cells)
        cell = mutated[1]
        if name == "missing-feature":
            arguments = cell["commands"]["build"]["argv"]
            start = arguments.index("--features")
            del arguments[start:start + 2]
        else:
            record = cell["runs"][PACKAGES[1]]
            if name == "wrong-engine":
                record["stdout"] = re.sub(r'"cipher_version"\s*:\s*"[^"\r\n]+"', '"cipher_version":null', record["stdout"], count=1)
            else:
                record["stdout"] = remove_marker(record["stdout"], "A1_GROUP_COMPLETE", "linux.tmpfs_names")
            record["stdout_sha256"] = digest(record["stdout"].encode())
            cell["combined_sha256"] = digest("".join(cell["runs"][package]["stdout"] for package in PACKAGES[:2]).encode())
        save_json(output / (name + ".json"), mutated)
        try:
            verify_matrix(mutated, executed=True)
        except EvidenceError as error:
            require(diagnostic in str(error), "offline mutation rejected for wrong cause: " + str(error))
            result["mutations"][name] = str(error)
        else:
            raise EvidenceError("offline engine mutation was accepted: " + name)
    save_json(output / "results.json", result)
    return result


def verify_linux_fixture(root, mount, source, kind):
    require(os.geteuid() != 0 and os.getegid() != 0, "fixture requires unprivileged UID/GID")
    require(kind in ("tmpfs", "ext4", "btrfs") and root.is_absolute() and mount.is_absolute()
            and root.resolve(strict=True) == root and mount.resolve(strict=True) == mount
            and root.is_relative_to(mount), "fixture root/mount must be exact canonical paths")
    info = root.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and info.st_gid == os.getegid()
            and stat.S_IMODE(info.st_mode) == 0o700, "fixture UID/GID/mode0700 differs from runner")
    matches = []
    def decode(field):
        return re.sub(r"\\(040|011|012|134)", lambda match: chr(int(match[1], 8)), field)
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        before, after = line.split(" - ", 1)
        fields, device = before.split(), after.split()
        if decode(fields[4]) == str(mount):
            matches.append((device[0], decode(device[1]), fields[2]))
    stat_device = f"{os.major(info.st_dev)}:{os.minor(info.st_dev)}"
    if kind == "btrfs":
        # mountinfo prints sb->s_dev; btrfs stat reports the subvolume's anonymous
        # device. Require the root's subvolume to be the mount target's, not equality.
        same = len(matches) == 1 and matches[0][:2] == (kind, source) and mount.stat().st_dev == info.st_dev
    else:
        same = matches == [(kind, source, stat_device)]
    require(same and linux_mount_type(root) == kind, "fixture mount source/fs/device mismatch or stacked mount")
    # Traversal and actual create/read/reopen/unlink happen as this runner.
    with tempfile.TemporaryDirectory(prefix="a1-owner-", dir=root) as directory:
        child = Path(directory)
        require(child.stat().st_uid == os.geteuid() and child.stat().st_gid == os.getegid()
                and stat.S_IMODE(child.stat().st_mode) == 0o700, "fixture child ownership mismatch")
        probe = child / "probe"
        probe.write_bytes(b"owned native fixture\n")
        require(probe.read_bytes() == b"owned native fixture\n", "fixture create/use probe failed")
        probe.unlink()
    return {"root": str(root), "mount": str(mount), "source": source, "kind": kind,
            "uid": info.st_uid, "gid": info.st_gid, "mode": "0700", "create_use": True,
            "kernel_release": platform.release(), "machine": platform.machine(),
            "mountinfo_device": matches[0][2], "stat_device": stat_device}


def root_controls(tmpfs_root, scratch_root, output, engines):
    stock = load_engines(engines)[0]
    require(sys.platform == "linux", "root-controls is Linux-only; no provisioning is performed")
    tmpfs_root, scratch_root = tmpfs_root.resolve(strict=True), scratch_root.resolve(strict=True)
    for root in (tmpfs_root, scratch_root):
        stat = root.stat()
        require(root.is_dir() and stat.st_uid == os.geteuid() and stat.st_mode & 0o077 == 0,
                f"root control needs explicit private owned directory: {root}")
    require(linux_mount_type(tmpfs_root) == "tmpfs", "configured control tmpfs is not tmpfs")
    require(linux_mount_type(scratch_root) != "tmpfs", "wrong-type control requires a non-tmpfs scratch root")
    require(Path("/dev/shm").is_dir(), "missing-root substitution control requires /dev/shm to exist")
    require(os.geteuid() != 0, "unwritable-root control requires an unprivileged uid; root can bypass mode denial")
    output.mkdir(parents=True, exist_ok=False)
    results = {}
    with tempfile.TemporaryDirectory(prefix="a1-roots-", dir=scratch_root) as temporary, \
            tempfile.TemporaryDirectory(prefix="a1-unwritable-", dir=tmpfs_root) as denied:
        owned = Path(temporary)
        unwritable = Path(denied)
        regular = owned / "not-a-directory"
        regular.write_text("root refusal control\n")
        probes = (
            ("required-tmpfs-missing", "RRS_A1_TMPFS_ROOT", "linux.tmpfs", "linux_tmpfs", owned / "missing-tmpfs", True, "cause=root metadata:"),
            ("optional-tmpfs-missing", "RRS_A1_TMPFS_ROOT", "linux.tmpfs", "linux_tmpfs", owned / "missing-tmpfs", False, "cause=root metadata:"),
            ("required-ext4-missing", "RRS_A1_EXT4_ROOT", "linux.ext4_sensitive", "linux_ext4", owned / "missing-ext4", True, "cause=root metadata:"),
            ("optional-ext4-missing", "RRS_A1_EXT4_ROOT", "linux.ext4_sensitive", "linux_ext4", owned / "missing-ext4", False, "cause=root metadata:"),
            ("required-tmpfs-unset", "RRS_A1_TMPFS_ROOT", "linux.tmpfs", "linux_tmpfs", None, True, "cause=root is unset"),
            ("required-ext4-unset", "RRS_A1_EXT4_ROOT", "linux.ext4_sensitive", "linux_ext4", None, True, "cause=root is unset"),
            ("required-tmpfs-wrong-type", "RRS_A1_TMPFS_ROOT", "linux.tmpfs", "linux_tmpfs", scratch_root, True, "cause=wrong filesystem:"),
            ("required-ext4-wrong-type", "RRS_A1_EXT4_ROOT", "linux.ext4_sensitive", "linux_ext4", tmpfs_root, True, "cause=wrong filesystem:"),
            ("required-tmpfs-not-directory", "RRS_A1_TMPFS_ROOT", "linux.tmpfs", "linux_tmpfs", regular, True, "cause=root is not a directory"),
            ("required-tmpfs-relative", "RRS_A1_TMPFS_ROOT", "linux.tmpfs", "linux_tmpfs", Path("relative-a1-root"), True, "cause=root must be an explicit absolute"),
            ("required-tmpfs-unwritable", "RRS_A1_TMPFS_ROOT", "linux.tmpfs", "linux_tmpfs", unwritable, True, "cause=root not writable:"),
            ("optional-tmpfs-unwritable", "RRS_A1_TMPFS_ROOT", "linux.tmpfs", "linux_tmpfs", unwritable, False, "cause=root not writable:"),
            ("required-btrfs-missing", "RRS_A1_BTRFS_ROOT", "linux.btrfs", "linux_btrfs", owned / "missing-btrfs", True, "cause=root metadata:"),
            ("optional-btrfs-missing", "RRS_A1_BTRFS_ROOT", "linux.btrfs", "linux_btrfs", owned / "missing-btrfs", False, "cause=root metadata:"),
            ("required-btrfs-unset", "RRS_A1_BTRFS_ROOT", "linux.btrfs", "linux_btrfs", None, True, "cause=root is unset"),
            ("required-btrfs-wrong-type", "RRS_A1_BTRFS_ROOT", "linux.btrfs", "linux_btrfs", tmpfs_root, True, "cause=wrong filesystem:"),
        )
        for name, variable, group, suffix, root, required, cause in probes:
            overrides = {**dict.fromkeys(FIXTURE_VARIABLES), "RRS_A1_REQUIRE_FIXTURES": "1" if required else "0"}
            if root is not None:
                overrides[variable] = str(root)
            test = LINUX_MODULE + PREFIX + suffix
            arguments = [test, "--exact", "--nocapture", "--test-threads=1"]
            try:
                if root == unwritable:
                    unwritable.chmod(0o500)
                record = run_binary(stock, PACKAGES[1], arguments, output, name, overrides=overrides)
                verify_binary_record(record, stock, PACKAGES[1], arguments, status=None)
            finally:
                unwritable.chmod(0o700)
            (output / (name + ".log")).write_bytes(record["stdout"].encode())
            results[name] = validate_root_control(record["stdout"], record["status"], variable, group,
                                                  test, root, required, cause)
            results[name]["command"] = record["argv"]
    (output / "results.json").write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    return results


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("check", "manifest"):
        command = commands.add_parser(name)
        command.add_argument("--profile", choices=MANIFESTS, required=True)
        if name == "check":
            command.add_argument("--log", type=Path, required=True)
            command.add_argument("--exit-code", type=int, required=True)
    mutations = commands.add_parser("mutations")
    mutations.add_argument("--profile", choices=("local-linux-partial",), required=True)
    mutations.add_argument("--log", type=Path, required=True)
    mutations.add_argument("--exit-code", type=int, required=True)
    mutations.add_argument("--output-dir", type=Path, required=True)
    roots = commands.add_parser("root-controls")
    roots.add_argument("--tmpfs-root", type=Path, required=True)
    roots.add_argument("--scratch-root", type=Path, required=True)
    roots.add_argument("--output-dir", type=Path, required=True)
    roots.add_argument("--engines", type=Path, required=True)
    for name in ("build-engines", "run-engines", "verify-engines", "engine-mutations", "old-root-control"):
        command = commands.add_parser(name)
        command.add_argument("--output-dir", type=Path, required=True)
        if name == "old-root-control":
            command.add_argument("--root", type=Path, required=True)
        if name == "engine-mutations":
            command.add_argument("--mutations-dir", type=Path, required=True)
    fixture_command = commands.add_parser("linux-fixture")
    fixture_command.add_argument("--root", type=Path, required=True)
    fixture_command.add_argument("--mount", type=Path, required=True)
    fixture_command.add_argument("--source", required=True)
    fixture_command.add_argument("--kind", choices=("tmpfs", "ext4", "btrfs"), required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "check":
            result = check(args.log.read_bytes().decode("utf-8"), args.profile, args.exit_code)
        elif args.command == "mutations":
            result = validate_mutations(args.log.read_bytes().decode("utf-8"), args.exit_code, args.output_dir)
        elif args.command == "root-controls":
            result = root_controls(args.tmpfs_root, args.scratch_root, args.output_dir, args.engines)
        elif args.command == "build-engines":
            result = build_engines(args.output_dir)
        elif args.command == "run-engines":
            result = run_engines(args.output_dir)
        elif args.command == "verify-engines":
            result = verify_matrix(load_engines(args.output_dir), executed=True)
        elif args.command == "engine-mutations":
            result = engine_mutations(load_engines(args.output_dir), args.mutations_dir)
        elif args.command == "old-root-control":
            result = old_root_control(args.output_dir, args.root)
        elif args.command == "linux-fixture":
            result = verify_linux_fixture(args.root, args.mount, args.source, args.kind)
        else:
            manifest = MANIFESTS[args.profile]
            result = {"profile": args.profile, "tests": manifest, "parent_count": len(manifest),
                      "group_count": sum(map(len, manifest.values())),
                      "optional_subgroups": OPTIONAL_SUBGROUPS.get(args.profile, {}),
                      "fixture_roots": {name: FIXTURE_ROOTS[name] for name in manifest if name in FIXTURE_ROOTS},
                      "optional_fixtures": LOCAL_FIXTURES if args.profile == "local-linux-partial" else {}}
        print(json.dumps(result, sort_keys=True, indent=2))
    except (ValueError, KeyError, TypeError, OSError, UnicodeError, subprocess.SubprocessError) as error:
        print(f"A1_EVIDENCE_REJECTED: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
